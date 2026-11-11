#!/usr/bin/env bash
# Run a command in the toolchain image against a COPY of the checkout.
#
#   usage: scripts/in-toolchain-image.sh <image> <command...>
#   e.g.   scripts/in-toolchain-image.sh go-trusted-platform-toolchain:abc make build
#
# How CI runs a stage in the devcontainer image (handbook ci-standard.md §2). A
# CI runner reaches its Docker daemon through a socket, so a bind mount would
# resolve on the daemon's host, where the checkout does not exist. This
# creates the container, streams the checkout into it (`.git` included: the
# Makefile reads the tag and hash for LDFLAGS) owned by the image's non-root
# user, then starts it and returns the command's exit status. It works the
# same against a local daemon; on a workstation `make docker-run CMD=...`
# (bind mount) is the shorter path.
#
# The container is hardened where a copy-in allows it: every capability
# dropped, no-new-privileges, bounded ulimits and pids, a non-root user, no
# network. The root filesystem is writable only because `docker cp` cannot
# write into a read-only one.
#
# The pids bound counts threads (cgroup v2). 4096 was too low on the 80-thread
# CI hosts: gosec's package loading forks `go` processes whose threads passed
# it, and the fork failed with "resource temporarily unavailable" (runs on
# ci-node-2-c and ci-node-1-b, 2026-10-24). 16384 keeps it bounded.
#
# IN_IMAGE_NETWORK=bridge gives the container a network, for the stages that
# must reach one: `make deps-check` asks the module proxy for the newest
# releases, and `make security` fetches the vulnerability databases. Only then
# are GOPROXY reopened, a writable module cache used under /gocache, and the
# forge credentials passed through, by NAME from this environment (the four
# variables dependency-resolution.md §6 has the runner inject), so no token
# ever appears on a command line.
#
# IN_IMAGE_MEMORY bounds the container's memory (default 8g), and
# --memory-swap is set to the same size, so the container gets no swap: a
# stage that outgrows it is OOM-killed and fails, instead of swapping the
# shared runner host. Unbounded, `make test test-sdk-go` reached 24.2 GB and
# `make security` 17.0 GB on ci-node-2, which then swapped (#1178). The
# /tmp tmpfs is charged to the same limit. Each ci.yml step sets its own
# size. IN_IMAGE_GOMAXPROCS (default 16) caps Go's parallelism in the
# container: GOMAXPROCS is the default of `go build -p` and `go test -p`, so
# it bounds how many packages compile, link and test at once, which on an
# 80-thread host is otherwise 80. It changes no package set and no test.
# IN_IMAGE_GOMEMLIMIT (default unset) sets GOMEMLIMIT in the container, so the
# Go GC works hard before the cgroup limit kills a large process; govulncheck's
# symbol scan reached 16.7 GB under 16g (#1425).
# CI_CGROUP_PARENT (default ci.slice) is the container's --cgroup-parent, so
# the runner host's ci.slice bounds every CI container together; without it a
# container runs in system.slice, outside that bound (#1178). Set it empty to
# pass no --cgroup-parent (a developer host with no ci.slice).
#
# IN_IMAGE_COPY=<host file>:<container path> copies one more file, outside the
# checkout, into the container before it starts, owned by the run's user: the
# trivy image step's `docker save` archive (#1272), which is kept out of the
# checkout so no other step streams it. The container path's directory must
# exist once the checkout is in (e.g. /src), and must not be under /tmp, whose
# tmpfs hides what is copied before start. Unset, nothing more is copied.
#
# The container is named go-trusted-platform-ci-tc-<pid>-<random>, under the
# prefix scripts/reap-stale-ci-stacks.sh reaps, and is removed on every exit.
# v4 (ci-template v1.29.4 and v1.29.5, Company Agent rulings 261(c) and
# 262(a)): Go's build and link scratch
# (TMPDIR, GOTMPDIR) is an anonymous volume on the image's /var/tmp
# (IN_IMAGE_SCRATCH overrides), on the daemon's data disk, not the 3 GB /tmp
# tmpfs, and removed with the container. A scratch directory that is missing or not writable fails
# the stage by name. A bridge stage's GOPROXY puts DEVCACHE_GOPROXY (Athens)
# first when the runner sets it: <DEVCACHE_GOPROXY>|https://proxy.golang.org,
# so any error falls through to the public proxy.
# v5 (ci-template v1.34.1): no `direct` entry in that chain
# (dependency-resolution.md, "No direct fetch, anywhere"); a private path is
# fetched by GOPRIVATE/GONOPROXY, never through GOPROXY.
#
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <image> <command...>" >&2
  exit 2
fi
image=$1
shift
network=${IN_IMAGE_NETWORK:-none}
case $network in
  none | bridge) ;;
  *) echo "IN_IMAGE_NETWORK must be none or bridge: $network" >&2; exit 2 ;;
esac
memory=${IN_IMAGE_MEMORY:-8g}
if ! [[ $memory =~ ^[1-9][0-9]*[mg]$ ]]; then
  echo "IN_IMAGE_MEMORY must be a size in m or g, e.g. 16g: $memory" >&2
  exit 2
fi
scratch=${IN_IMAGE_SCRATCH:-/var/tmp}
case $scratch in
  /*) ;;
  *) echo "IN_IMAGE_SCRATCH must be an absolute path: $scratch" >&2; exit 2 ;;
esac
gomaxprocs=${IN_IMAGE_GOMAXPROCS:-16}
if ! [[ $gomaxprocs =~ ^[1-9][0-9]*$ ]]; then
  echo "IN_IMAGE_GOMAXPROCS must be a positive integer: $gomaxprocs" >&2
  exit 2
fi
gomemlimit=${IN_IMAGE_GOMEMLIMIT:-}
if [ -n "$gomemlimit" ] && ! [[ $gomemlimit =~ ^[1-9][0-9]*(B|KiB|MiB|GiB|TiB)$ ]]; then
  echo "IN_IMAGE_GOMEMLIMIT must be a Go memory limit such as 18GiB, or empty: $gomemlimit" >&2
  exit 2
fi
cgroup_parent=${CI_CGROUP_PARENT-ci.slice}
if [ -n "$cgroup_parent" ] && ! [[ $cgroup_parent =~ ^[A-Za-z0-9][A-Za-z0-9_.@:/-]*$ ]]; then
  echo "CI_CGROUP_PARENT must be a cgroup name such as ci.slice, or empty: $cgroup_parent" >&2
  exit 2
fi
copy=${IN_IMAGE_COPY:-}
copy_src=
copy_dest=
if [ -n "$copy" ]; then
  copy_src=${copy%%:*}
  copy_dest=${copy#*:}
  if [ "$copy_src" = "$copy" ] || [ ! -f "$copy_src" ] ||
    ! [[ $copy_dest =~ ^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]] || [[ $copy_dest == /tmp/* ]]; then
    echo "IN_IMAGE_COPY must be <host file>:<absolute container path outside /tmp>: $copy" >&2
    exit 2
  fi
fi

uid=10001
name="go-trusted-platform-ci-tc-$$-${RANDOM}"
args=(
  --name "$name"
  --init
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --pids-limit 16384
  --memory "$memory"
  --memory-swap "$memory"
  --ulimit memlock=67108864:67108864
  --ulimit core=1048576:1048576
  --ulimit nofile=65536:65536
  --tmpfs "/tmp:rw,exec,nosuid,nodev,size=3g,mode=1777"
  # Go's build and link scratch on disk, not the tmpfs (v4, above).
  -v "$scratch"
  --env TMPDIR="$scratch"
  --env GOTMPDIR="$scratch"
  --network "$network"
  --user "$uid:$uid"
  --workdir /src
  --env HOME=/tmp
  --env CI="${CI:-}"
  --env GOMAXPROCS="$gomaxprocs"
)
[ -n "$gomemlimit" ] && args+=(--env GOMEMLIMIT="$gomemlimit")
if [ -n "$cgroup_parent" ]; then
  args+=(--cgroup-parent "$cgroup_parent")
fi
if [ "$network" = bridge ]; then
  # The baked module cache is read-only to the run's user and holds only the
  # build lists of the modules the image downloaded; the stages that walk
  # further fetch more. The writable one starts empty, so a stage downloads
  # its whole graph (gigabytes): it goes beside the build cache on disk, not
  # in the 3g /tmp tmpfs, where it left no room for trivy's DB (#933).
  args+=(--env "GOPROXY=${DEVCACHE_GOPROXY:+$DEVCACHE_GOPROXY|}https://proxy.golang.org" --env GOMODCACHE=/gocache/mod)
  for v in GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
    if [ -n "${!v:-}" ]; then args+=(--env "$v"); fi
  done
fi

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The scratch directory is checked in the container first (v4), so a missing
# or unwritable one fails the stage here by name, not later as ENOSPC or EACCES.
# shellcheck disable=SC2016 # expands in the container, not here
guard='[ -d "$TMPDIR" ] && [ -w "$TMPDIR" ] || { echo "in-toolchain-image: scratch directory $TMPDIR is missing or not writable" >&2; exit 2; }'
docker create "${args[@]}" "$image" sh -c "$guard; $*" >/dev/null
tar -C "$PWD" --owner="$uid" --group="$uid" --numeric-owner -cf - . |
  docker cp -a - "$name:/src"
if [ -n "$copy_src" ]; then
  tar -C "$(dirname "$copy_src")" --owner="$uid" --group="$uid" --numeric-owner \
    --transform "s|.*|$(basename "$copy_dest")|" -cf - "$(basename "$copy_src")" |
    docker cp -a - "$name:$(dirname "$copy_dest")"
fi
docker start -a "$name"

#!/usr/bin/env bash
# Run a command in the toolchain image against a copy of the checkout.
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
  # ci-template v1.36: the Trivy database repositories the runner sets (the
  # dev-cache ghcr mirror on the LAN first, the public ones after) travel
  # with the stage, so `make security` and `trivy image` fetch the vulnerability
  # and Java databases from the LAN instead of the internet.
  for v in GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
    TRIVY_DB_REPOSITORY TRIVY_JAVA_DB_REPOSITORY TRIVY_INSECURE; do
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

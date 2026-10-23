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
# IN_IMAGE_NETWORK=bridge gives the container a network, for the stages that
# must reach one: `make deps-check` asks the module proxy for the newest
# releases, and `make security` fetches the vulnerability databases. Only then
# are GOPROXY reopened, a writable module cache used under /gocache, and the
# forge credentials passed through, by NAME from this environment (the four
# variables dependency-resolution.md §6 has the runner inject), so no token
# ever appears on a command line.
#
# The container is named go-trusted-platform-ci-tc-<pid>-<random>, under the
# prefix scripts/reap-stale-ci-stacks.sh reaps, and is removed on every exit.
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

uid=10001
name="go-trusted-platform-ci-tc-$$-${RANDOM}"
args=(
  --name "$name"
  --init
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --pids-limit 4096
  --ulimit memlock=67108864:67108864
  --ulimit core=1048576:1048576
  --ulimit nofile=65536:65536
  --tmpfs "/tmp:rw,exec,nosuid,nodev,size=3g,mode=1777"
  --network "$network"
  --user "$uid:$uid"
  --workdir /src
  --env HOME=/tmp
  --env CI="${CI:-}"
)
if [ "$network" = bridge ]; then
  # The baked module cache is read-only to the run's user and holds only the
  # build lists of the modules the image downloaded; the stages that walk
  # further fetch more. The writable one starts empty, so a stage downloads
  # its whole graph (gigabytes): it goes beside the build cache on disk, not
  # in the 3g /tmp tmpfs, where it left no room for trivy's DB (#933).
  args+=(--env "GOPROXY=https://proxy.golang.org,direct" --env GOMODCACHE=/gocache/mod)
  for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
    if [ -n "${!v:-}" ]; then args+=(--env "$v"); fi
  done
fi

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker create "${args[@]}" "$image" sh -c "$*" >/dev/null
tar -C "$PWD" --owner="$uid" --group="$uid" --numeric-owner -cf - . |
  docker cp -a - "$name:/src"
docker start -a "$name"

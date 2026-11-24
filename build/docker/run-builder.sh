#!/usr/bin/env bash
# Runs a builder container without a single host bind mount.
set -euo pipefail

docker="${DOCKER:-docker}"
ins=()
outs=()

usage() {
    echo "usage: ${0##*/} [-i HOST:CTR]... [-o CTR:HOST]... -- <docker create args>" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -i) [ $# -ge 2 ] || usage; ins+=("$2"); shift 2 ;;
        -o) [ $# -ge 2 ] || usage; outs+=("$2"); shift 2 ;;
        --) shift; break ;;
        *) usage ;;
    esac
done
[ $# -gt 0 ] || usage

name="builder-$$-${RANDOM}"
"$docker" create --name "$name" "$@" >/dev/null
trap '"$docker" rm -f -v "$name" >/dev/null 2>&1 || true' EXIT

# Copying a directory's contents ("src/.") merges it into the destination,
# which is created when absent; a file is copied to the destination path.
for spec in ${ins[@]+"${ins[@]}"}; do
    host="${spec%%:*}"
    ctr="${spec#*:}"
    if [ -d "$host" ]; then
        "$docker" cp "${host%/}/." "$name:$ctr"
    elif [ -f "$host" ]; then
        # docker cp needs the destination's parent to exist; extracting a
        # tree rooted at / creates it.
        stage="$(mktemp -d)"
        mkdir -p "$stage/$(dirname "${ctr#/}")"
        cp -p "$host" "$stage/${ctr#/}"
        "$docker" cp "$stage/." "$name:/"
        rm -rf "$stage"
    else
        echo "run-builder: input $host does not exist" >&2
        exit 2
    fi
done

# `start -a` streams the build log and exits with the container's status.
"$docker" start -a "$name"

for spec in ${outs[@]+"${outs[@]}"}; do
    ctr="${spec%%:*}"
    host="${spec#*:}"
    mkdir -p "$host"
    "$docker" cp "$name:${ctr%/}/." "$host"
done

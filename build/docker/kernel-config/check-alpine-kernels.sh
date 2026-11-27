#!/bin/sh
# check-alpine-kernels.sh: check Alpine kernel packages against the platform-required options.
set -eu

[ $# -ge 1 ] || { echo "usage: check-alpine-kernels.sh PACKAGE..." >&2; exit 2; }

apk update -q >/dev/null
apk add -q bash >/dev/null

work=$(mktemp -d)
status=0
for pkg in "$@"; do
    (cd "$work" && apk fetch -q "$pkg" >/dev/null) || { echo "cannot fetch $pkg" >&2; exit 2; }
    apkfile=$(ls "$work/$pkg"-[0-9]*.apk)
    mkdir -p "$work/$pkg"
    # An apk is concatenated gzip tar streams; tar reads through them and
    # warns about the signature and control segments, which are not wanted.
    tar -xzf "$apkfile" -C "$work/$pkg" boot 2>/dev/null || true
    config=$(ls "$work/$pkg"/boot/config-* 2>/dev/null) || { echo "$pkg: no boot/config-* in $apkfile" >&2; exit 2; }
    echo "=== $(cat /etc/alpine-release) $(apk --print-arch) $(basename "$apkfile") ($(basename "$config"))"
    if bash /kc/require-config.sh --enabled "$config" /kc/platform-required.config; then
        echo "$pkg: carries every platform-required option"
    else
        rc=$?
        [ "$rc" -eq 3 ] || exit "$rc"
        status=3
    fi
done
exit "$status"

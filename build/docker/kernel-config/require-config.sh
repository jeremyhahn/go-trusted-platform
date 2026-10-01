#!/bin/bash
# require-config.sh - fail when a kernel .config does not carry a fragment.
#
#   require-config.sh [--enabled] CONFIG FRAGMENT...
#
# Every requirement line of every FRAGMENT is checked against CONFIG (a
# kernel .config):
#
#   CONFIG_X=<value>          CONFIG must contain exactly that line. After
#                             merge_config.sh + olddefconfig, a missing or
#                             changed line means Kconfig dropped or demoted
#                             the option, almost always an unmet dependency.
#   # CONFIG_X is not set     CONFIG must not enable CONFIG_X.
#
# Any other line starting with '#', and blank lines, are comments.
#
# --enabled relaxes CONFIG_X=y and CONFIG_X=m to "enabled, built in or as a
# module". It is for kernels the platform ships but does not build (Alpine's
# linux-lts and linux-rpi), where module-versus-built-in is the distribution's
# choice and only presence matters. Other values stay exact.
#
# Every miss is reported, one line each, before the script exits 3; a usage
# error or an unreadable file exits 2; a CONFIG meeting every requirement
# exits 0. The builders call it after `make olddefconfig`
# (build/docker/{fips,virt}-kernel-builder), so the exit code is the build's.
set -euo pipefail

usage() {
    echo "usage: require-config.sh [--enabled] CONFIG FRAGMENT..." >&2
    exit 2
}

enabled_mode=0
if [ "${1:-}" = "--enabled" ]; then
    enabled_mode=1
    shift
fi
[ $# -ge 2 ] || usage
config="$1"
shift
[ -r "$config" ] || { echo "require-config: cannot read $config" >&2; exit 2; }
for fragment in "$@"; do
    [ -r "$fragment" ] || { echo "require-config: cannot read $fragment" >&2; exit 2; }
done

not_set_re='^# (CONFIG_[A-Za-z0-9_]+) is not set$'
value_re='^(CONFIG_[A-Za-z0-9_]+)=(.*)$'

missing=0
for fragment in "$@"; do
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ $line =~ $not_set_re ]]; then
            symbol="${BASH_REMATCH[1]}"
            if grep -q "^${symbol}=" "$config"; then
                echo "$fragment: $line is violated: $(grep "^${symbol}=" "$config")" >&2
                missing=$((missing + 1))
            fi
            continue
        fi
        case "$line" in
            ''|'#'*) continue ;;
        esac
        if ! [[ $line =~ $value_re ]]; then
            echo "require-config: $fragment: not a Kconfig line: $line" >&2
            exit 2
        fi
        symbol="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        if [ "$enabled_mode" -eq 1 ] && { [ "$value" = y ] || [ "$value" = m ]; }; then
            if ! grep -qE "^${symbol}=[ym]$" "$config"; then
                echo "$fragment: $symbol is not enabled in $config" >&2
                missing=$((missing + 1))
            fi
            continue
        fi
        if ! grep -qxF "$line" "$config"; then
            echo "$fragment: $line was dropped by Kconfig (unmet dependency?)" >&2
            missing=$((missing + 1))
        fi
    done < "$fragment"
done

if [ "$missing" -ne 0 ]; then
    echo "require-config: $config misses $missing required option(s)" >&2
    exit 3
fi

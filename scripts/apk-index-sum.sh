#!/usr/bin/env bash
# apk-index-sum: v1 (ci-template v1.29, Company Agent ruling 220(5),
# 2026-10-27) — one checksum of the Alpine package indexes the devcontainer
# build resolves against.
#
# Each ci.yml job that names the integration image puts the printed value in
# APK_INDEX_SUM, which the integration image's content tag hashes (`make -s
# it-image`, ci-standard.md §9) and which its build takes as a build argument
# (devcontainer.md §6). A
# new Alpine package release, a CVE fix among them, changes an index, so it
# changes the tag, and the next run rebuilds the image instead of reusing the
# cached one: before v1.29 a tree whose files had not changed kept its image,
# and `trivy image` went red on a fixed CVE until some unrelated file moved
# (go-enclave main fd83b79ce, CVE-2026-92392, libcurl 8.23.0-r0).
#
# Usage: scripts/apk-index-sum.sh [Dockerfile]
#   The Dockerfile defaults to APK_DOCKERFILE, else
#   build/docker/devcontainer/Dockerfile. Each external base image its FROM
#   lines name (a global ARG default is substituted; `scratch` and earlier
#   stages are skipped) is run once, as root with every capability dropped
#   but the ones apk needs, to read its /etc/apk/repositories and fetch their
#   APKINDEX files with `apk update`. APK_BASE_IMAGES, space separated,
#   replaces the FROM parse for a Dockerfile it cannot read.
#
# Prints a sha256 over each base image's name, repository list and index
# checksums, or `none` when no base image has apk. Exits 1 when a base image
# cannot be resolved, run or updated: a missing index is never a pass, since
# the image build then cannot resolve its packages either.
set -euo pipefail

dockerfile=${1:-${APK_DOCKERFILE:-build/docker/devcontainer/Dockerfile}}

fail() {
  echo "::error::apk-index-sum: $*" >&2
  exit 1
}

bases=()
if [ -n "${APK_BASE_IMAGES:-}" ]; then
  read -r -a bases <<< "$APK_BASE_IMAGES"
else
  [ -f "$dockerfile" ] || fail "no Dockerfile at $dockerfile"
  declare -A arg=() stage=() seen=()
  # shellcheck disable=SC2016 # a regex, not an expansion
  ref='\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)'
  from=0
  # Join continuation lines, drop comments, then read one instruction a line.
  while read -r kw rest; do
    case ${kw^^} in
      ARG)
        # Only a global ARG (before the first FROM) can name a base image.
        [ "$from" = 0 ] || continue
        read -r -a kvs <<< "$rest"
        for kv in "${kvs[@]}"; do
          case $kv in
            *=*) v=${kv#*=}; v=${v#\"}; v=${v%\"}; arg[${kv%%=*}]=$v ;;
          esac
        done
        ;;
      FROM)
        from=1
        read -r -a w <<< "$rest"
        i=0
        while [ "$i" -lt "${#w[@]}" ] && [ "${w[$i]#--}" != "${w[$i]}" ]; do i=$((i + 1)); done
        img=${w[$i]:-}
        [ -n "$img" ] || fail "a FROM line in $dockerfile names no image"
        # ${NAME}, ${NAME:-default} and $NAME from the global ARG defaults.
        while [[ $img =~ $ref ]]; do
          n=${BASH_REMATCH[1]:-${BASH_REMATCH[4]}}
          v=${arg[$n]:-${BASH_REMATCH[3]}}
          [ -n "$v" ] || fail "FROM $img in $dockerfile names \$$n, which has no global ARG default; set APK_BASE_IMAGES"
          img=${img/"${BASH_REMATCH[0]}"/$v}
        done
        if [ "${w[$((i + 1))]:-}" != "" ] && [ "${w[$((i + 1))],,}" = as ]; then
          stage[${w[$((i + 2))],,}]=1
        fi
        [ "${img,,}" = scratch ] && continue
        [ -n "${stage[${img,,}]:-}" ] && continue
        [ -n "${seen[$img]:-}" ] && continue
        seen[$img]=1
        bases+=("$img")
        ;;
    esac
  done < <(sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' -e 's/^[[:space:]]*#.*//' "$dockerfile")
fi

[ "${#bases[@]}" -gt 0 ] || fail "no base image found in $dockerfile"

# Runs in the base image. A base without apk contributes `none`.
# shellcheck disable=SC2016 # expanded by the container's shell
probe='command -v apk >/dev/null 2>&1 || { echo none; exit 0; }
apk update --quiet >/dev/null || exit 3
set -- /var/cache/apk/APKINDEX.*.tar.gz
[ -f "$1" ] || exit 4
sed "s/[[:space:]]*$//" /etc/apk/repositories | grep -v "^#" | grep . | sort
sha256sum "$@" | sed "s|  .*/| |" | sort'

sum_input=
alpine=0
for img in "${bases[@]}"; do
  out=$(docker run --rm --pull missing --network bridge --user 0 \
          --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
          --security-opt no-new-privileges --entrypoint /bin/sh "$img" -c "$probe") ||
    fail "reading the Alpine package index of $img failed (exit $?)"
  [ "$out" = none ] || alpine=1
  echo "apk-index-sum: $img: $(printf '%s\n' "$out" | grep -c 'APKINDEX' || true) index file(s)" >&2
  sum_input+="$img"$'\n'"$out"$'\n'
done

if [ "$alpine" = 0 ]; then
  echo none
else
  printf '%s' "$sum_input" | sha256sum | cut -d' ' -f1
fi

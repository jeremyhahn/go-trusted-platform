#!/usr/bin/env bash
# scripts/touched-packages.sh: the unit-test packages a range of commits
# touches (handbook testing-guidelines.md section 4, ruling 1171): every
# changed Go package of the root module that still exists at <tip>, and its
# direct importers in the module, printed as ./<dir>, sorted, one per line,
# ready for `make test-pkg PKG=./<dir>/`.
#
# Only the root module counts: sdk/go/, build/tools-src/, testdata/ paths and
# any directory with its own go.mod are skipped. A go.mod or go.sum change,
# or a failure to list the packages (fail closed), prints `./...`. A range
# with no Go change prints nothing.
#
# Run it from a checkout of <tip>.
#
#   usage: scripts/touched-packages.sh <base> <tip>
set -euo pipefail

[ "$#" = 2 ] || {
	echo "usage: $0 <base> <tip>" >&2
	exit 2
}
base=$1 tip=$2

everything() {
	echo ./...
	exit 0
}

# own_module DIR: DIR or a parent below the root has its own go.mod at <tip>.
own_module() {
	local d=$1
	while [ "$d" != . ] && [ -n "$d" ]; do
		git cat-file -e "$tip:$d/go.mod" 2>/dev/null && return 0
		case $d in */*) d=${d%/*} ;; *) d=. ;; esac
	done
	return 1
}

declare -A changed=()
while IFS= read -r path; do
	case $path in
	go.mod | go.sum) everything ;;
	sdk/go/* | build/tools-src/* | testdata/* | */testdata/*) continue ;;
	*.go) ;;
	*) continue ;;
	esac
	case $path in */*) d=${path%/*} ;; *) d=. ;; esac
	own_module "$d" && continue
	changed[$d]=1
done < <(git diff --name-only "$base" "$tip")
[ "${#changed[@]}" -gt 0 ] || exit 0

root=$(git rev-parse --show-toplevel)
cd "$root"
tags=$(make -s print-build-tags) || everything
listing=$(go list -e -tags "$tags" \
	-f '{{.Dir}}|{{.ImportPath}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' \
	./...) || everything

reldir() {
	if [ "$1" = "$root" ]; then echo .; else echo "${1#"$root"/}"; fi
}

declare -A pathof=() importers=() exists=()
while IFS='|' read -r dir ip imports; do
	[ -n "$dir" ] || continue
	pathof[$ip]=$(reldir "$dir")
done <<<"$listing"
while IFS='|' read -r dir ip imports; do
	[ -n "$dir" ] || continue
	rel=$(reldir "$dir")
	exists[$rel]=1
	for imp in $imports; do
		[ -n "${pathof[$imp]:-}" ] || continue
		importers[${pathof[$imp]}]+=" $rel"
	done
done <<<"$listing"

declare -A out=()
for d in "${!changed[@]}"; do
	[ -n "${exists[$d]:-}" ] || continue # gone at <tip>
	out[$d]=1
	for imp in ${importers[$d]:-}; do
		out[$imp]=1
	done
done
[ "${#out[@]}" -gt 0 ] || exit 0
for d in "${!out[@]}"; do
	echo "./$d"
done | LC_ALL=C sort

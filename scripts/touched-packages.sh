#!/usr/bin/env bash
# scripts/touched-packages.sh: the unit-test packages a range of commits
# touches (handbook testing-guidelines.md section 4, ruling 1171): every
# changed Go package of the root module that still exists at <tip>, and its
# direct importers in the module, printed as ./<dir>, sorted, one per line,
# ready for `make test-pkg PKG=./<dir>/`.
#
# Only the root module counts: sdk/go/, build/tools-src/ paths and any
# directory with its own go.mod are skipped. A changed non-Go file selects the
# package that embeds it (go list EmbedFiles), else the nearest package
# directory above it (testdata, fixtures); one with no owning package (the
# Makefile, scripts, workflows, web/) prints `./...`. A go.mod or go.sum
# change, or a failure to read the diff or list the packages (fail closed),
# prints `./...`. A docs-only range (*.md, docs/) prints nothing.
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

# The diff is read into a variable first: a failed git diff (an unknown
# <base>) is a failure to list the changes, which fails closed.
diff=$(git diff --name-only "$base" "$tip") || everything

# changed: directories with a changed .go file. others: every other changed
# input of a package (an embedded file, testdata, a fixture), mapped to its
# owning package below once the packages are listed.
declare -A changed=() others=()
while IFS= read -r path; do
	[ -n "$path" ] || continue
	case $path in
	go.mod | go.sum) everything ;;
	*.md | docs/*) continue ;;
	sdk/go/* | build/tools-src/*) continue ;;
	esac
	case $path in */*) d=${path%/*} ;; *) d=. ;; esac
	own_module "$d" && continue
	case $path in
	testdata/* | */testdata/*) others[$path]=1 ;;
	*.go) changed[$d]=1 ;;
	*) others[$path]=1 ;;
	esac
done <<<"$diff"
[ "$((${#changed[@]} + ${#others[@]}))" -gt 0 ] || exit 0

root=$(git rev-parse --show-toplevel)
cd "$root"
tags=$(make -s print-build-tags) || everything
listing=$(go list -e -tags "$tags" \
	-f '{{.Dir}}|{{.ImportPath}}|{{join .EmbedFiles " "}} {{join .TestEmbedFiles " "}} {{join .XTestEmbedFiles " "}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' \
	./...) || everything

reldir() {
	if [ "$1" = "$root" ]; then echo .; else echo "${1#"$root"/}"; fi
}

declare -A pathof=() importers=() exists=() embedded=()
while IFS='|' read -r dir ip embeds imports; do
	[ -n "$dir" ] || continue
	pathof[$ip]=$(reldir "$dir")
done <<<"$listing"
while IFS='|' read -r dir ip embeds imports; do
	[ -n "$dir" ] || continue
	rel=$(reldir "$dir")
	exists[$rel]=1
	for e in $embeds; do
		if [ "$rel" = . ]; then embedded[$e]=$rel; else embedded[$rel/$e]=$rel; fi
	done
	for imp in $imports; do
		[ -n "${pathof[$imp]:-}" ] || continue
		importers[${pathof[$imp]}]+=" $rel"
	done
done <<<"$listing"

# A non-Go input belongs to the package that embeds it, else to the nearest
# package directory above it (testdata, fixtures read by its tests). One with
# no owning package (the Makefile, scripts, workflows, the web console) may be
# read by any test: every package runs.
for path in "${!others[@]}"; do
	owner=${embedded[$path]:-}
	d=$path
	while [ -z "$owner" ] && [ "$d" != . ]; do
		case $d in */*) d=${d%/*} ;; *) d=. ;; esac
		[ -n "${exists[$d]:-}" ] && owner=$d
	done
	[ -n "$owner" ] || everything
	changed[$owner]=1
done

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

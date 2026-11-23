#!/usr/bin/env bash
# scripts/touched-features.sh: the integration features a range of commits
# touches (handbook testing-guidelines.md section 4, ruling 1171). Features
# come from the project's one mapping table, TARGET_PACKAGES in
# build/docker/devcontainer/run-integration-tests.sh, read at <tip>; there is
# no other list of features.
#
# Every suite drives the one platformd built from the whole module, so the
# table maps only test/integration paths and any non-docs change outside
# test/integration is shared. The script prints:
#
#   - nothing when only docs changed (*.md anywhere, anything under docs/);
#   - ALL for a shared change, a test directory in no feature, a failure to
#     read the table or the packages (fail closed), or when every feature is
#     touched: run `make integration-test`. ALL is followed by the table's
#     features outside the runner's ALL_TARGETS, sorted: run
#     `make integration-test-<feature>` for each of those too;
#   - otherwise the touched features, sorted, one per line: the features
#     whose pattern covers a changed directory or one of its direct
#     importers inside test/integration. Run `make integration-test-<feature>`
#     for each.
#
# Run it from a checkout of <tip>.
#
#   usage: scripts/touched-features.sh <base> <tip>
set -euo pipefail

[ "$#" = 2 ] || {
	echo "usage: $0 <base> <tip>" >&2
	exit 2
}
base=$1 tip=$2
runner=build/docker/devcontainer/run-integration-tests.sh

# all: run everything. `make integration-test` runs the runner's `all`, which
# is ALL_TARGETS and compute; the table's other features (their own make
# targets only) follow ALL, so a shared change never runs less than a change
# to one of them alone. Before the table is read, ALL alone.
declare -A table=() in_all=()
all() {
	echo ALL
	local key
	for key in "${!table[@]}"; do
		[ -n "${in_all[$key]:-}" ] || echo "$key"
	done | LC_ALL=C sort
	exit 0
}

# The table: the rows between `declare -A TARGET_PACKAGES=(` and the next `)`.
script=$(git show "$tip:$runner") || all
in=0
row='^[[:space:]]*\[([A-Za-z0-9_.-]+)\]="([^"]*)"'
while IFS= read -r line; do
	if [ "$in" = 0 ]; then
		[ "$line" = 'declare -A TARGET_PACKAGES=(' ] && in=1
		continue
	fi
	[ "$line" = ')' ] && break
	if [[ $line =~ $row ]]; then
		[ "${BASH_REMATCH[1]}" = all ] && continue # the runner's keyword for everything
		table[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
	fi
done <<<"$script"
[ "${#table[@]}" -gt 0 ] || all

# The suites `all` runs: the words between `ALL_TARGETS=(` and the next `)`,
# and compute (the runner's `all` adds it). An unreadable list leaves in_all
# empty, so ALL is followed by every feature (fail closed).
in=0
while IFS= read -r line; do
	if [ "$in" = 0 ]; then
		[ "$line" = 'ALL_TARGETS=(' ] && in=1
		continue
	fi
	line=${line%%#*}
	[ "${line//[[:space:]]/}" = ')' ] && break
	for word in $line; do
		in_all[$word]=1
	done
done <<<"$script"
[ "${#in_all[@]}" -eq 0 ] || in_all[compute]=1

# covers PATTERN DIR: a pattern ending /... covers its directory and
# everything under it; any other pattern is that one package.
covers() {
	local p=${1#./} d=$2
	case $p in
	*/...)
		p=${p%/...}
		[ "$d" = "$p" ] || [ "${d#"$p"/}" != "$d" ]
		;;
	*) [ "$d" = "${p%/}" ] ;;
	esac
}

declare -A touched=()
# mark DIR: add every feature covering DIR; fail when none does.
mark() {
	local key p hit=1
	for key in "${!table[@]}"; do
		for p in ${table[$key]}; do
			if covers "$p" "$1"; then
				touched[$key]=1
				hit=0
			fi
		done
	done
	return "$hit"
}

# The diff is read into a variable first: a failed git diff (an unknown
# <base>) is a failure to read the changes, which fails closed.
diff=$(git diff --name-only "$base" "$tip") || all
declare -A dirs=()
while IFS= read -r path; do
	[ -n "$path" ] || continue
	case $path in
	*.md | docs/*) continue ;;
	test/integration/*) ;;
	*) all ;;
	esac
	d=${path%/*}
	if [ "$d" = test/integration ]; then
		case $path in *.go) ;; *) all ;; esac
	fi
	d=${d%%/testdata/*}
	d=${d%/testdata}
	dirs[$d]=1
done <<<"$diff"
[ "${#dirs[@]}" -gt 0 ] || exit 0

# The direct importers of each test/integration package, by directory.
root=$(git rev-parse --show-toplevel)
cd "$root"
module=
while read -r word rest; do
	if [ "$word" = module ]; then
		module=${rest%% *}
		break
	fi
done <go.mod
[ -n "$module" ] || all
tags=$(make -s print-build-tags) || all
listing=$(go list -e -tags "integration $tags" \
	-f '{{.Dir}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' \
	./test/integration/...) || all
declare -A importers=()
while IFS='|' read -r dir imports; do
	[ -n "$dir" ] || continue
	rel=${dir#"$root"/}
	for ip in $imports; do
		case $ip in "$module"/*) importers[${ip#"$module"/}]+=" $rel" ;; esac
	done
done <<<"$listing"

for d in "${!dirs[@]}"; do
	mark "$d" || all
	for imp in ${importers[$d]:-}; do
		mark "$imp" || true # an importer in no feature holds no test
	done
done

[ "${#touched[@]}" -lt "${#table[@]}" ] || all
printf '%s\n' "${!touched[@]}" | LC_ALL=C sort

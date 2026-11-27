#!/bin/sh
# Prints the cache key of the devcontainer's apt layer: a sha256 over the amd64 and arm64 package index digests of the image's apt suites.
set -eu
set -f

# The suites of the golang bookworm image's /etc/apt/sources.list.d/debian.sources.
DEFAULT_SUITES="https://deb.debian.org/debian/dists/bookworm
https://deb.debian.org/debian/dists/bookworm-updates
https://deb.debian.org/debian-security/dists/bookworm-security"
SUITES=${APT_SUITES:-$DEFAULT_SUITES}

# index_lines URL: the "sha256 size path" entries of the SHA256: section of the
# InRelease file at URL whose path is main/binary-amd64/Packages* or
# main/binary-arm64/Packages*; nothing if the file cannot be fetched.
index_lines() {
	body=$(curl -fsS --max-time 30 "$1/InRelease" 2>/dev/null) || return 0
	printf '%s\n' "$body" | {
		in=0
		while IFS= read -r line; do
			case "$line" in
			"SHA256:")
				in=1
				continue
				;;
			" "*) ;;
			*)
				in=0
				continue
				;;
			esac
			[ "$in" = 1 ] || continue
			# shellcheck disable=SC2086 # split the entry into its fields
			set -- $line
			[ "$#" -ge 3 ] || continue
			case "$3" in
			main/binary-amd64/Packages* | main/binary-arm64/Packages*)
				printf '%s %s %s\n' "$1" "$2" "$3"
				;;
			esac
		done
	}
}

all=""
for suite in $SUITES; do
	lines=$(index_lines "$suite")
	if [ -z "$lines" ]; then
		fallback=$(date -u +%Y-%m-%dT%HZ)
		echo "warning: apt-refresh-key: no Packages index sums from $suite/InRelease; APT_REFRESH falls back to $fallback" >&2
		echo "$fallback"
		exit 0
	fi
	all="$all$lines
"
done

printf '%s' "$all" | LC_ALL=C sort | sha256sum | cut -d' ' -f1

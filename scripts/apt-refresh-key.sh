#!/bin/sh
# Prints the cache key of the devcontainer's apt layer (APT_REFRESH in
# build/docker/devcontainer/Dockerfile): the newest Date: field of the
# InRelease files of the suites the image's apt sources name, as a UTC
# timestamp. The key changes when Debian publishes to any of those suites, so
# a fix published mid-day rebuilds the layer and reaches `trivy image` on the
# next build.
#
# If a suite cannot be fetched or parsed, the key falls back to the UTC date
# and hour and a warning goes to stderr; the build goes on.
set -eu

# The suites of the golang bookworm image's /etc/apt/sources.list.d/debian.sources.
SUITES="https://deb.debian.org/debian/dists/bookworm
https://deb.debian.org/debian/dists/bookworm-updates
https://deb.debian.org/debian-security/dists/bookworm-security"

# release_epoch URL: the Date: field of the InRelease file at URL, in epoch
# seconds; nothing if the file cannot be fetched or has no Date: field. The
# fields come before the signed index, so the first 4 KiB carry the Date: line.
release_epoch() {
	curl -fsS --max-time 10 --range 0-4095 "$1/InRelease" 2>/dev/null |
		while IFS= read -r line; do
			case "$line" in
			"Date: "*)
				date -u -d "${line#Date: }" +%s 2>/dev/null
				exit 0
				;;
			esac
		done
}

newest=0
for suite in $SUITES; do
	epoch=$(release_epoch "$suite") || epoch=""
	case "$epoch" in
	"" | *[!0-9]*)
		fallback=$(date -u +%Y-%m-%dT%HZ)
		echo "warning: apt-refresh-key: no Date: from $suite/InRelease; APT_REFRESH falls back to $fallback" >&2
		echo "$fallback"
		exit 0
		;;
	esac
	if [ "$epoch" -gt "$newest" ]; then
		newest=$epoch
	fi
done

date -u -d "@$newest" +%Y-%m-%dT%H:%M:%SZ

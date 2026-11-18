#!/usr/bin/env bash
# scripts/ci-go-integrity.sh: the module-integrity gate of Go on a
# self-hosted pool (Tenant Agent ruling 869, pending InfoSec's review of
# M-8). The pools fetch modules through the LAN proxy first, then
# proxy.golang.org; integrity then rests on the checksum database, which
# verifies every module whichever proxy serves it. Every pool step that runs
# Go calls this first, so the step fails before any Go runs unless:
#
#   - GOSUMDB is sum.golang.org;
#   - nothing exempts a module from it or from the proxy: GONOSUMDB,
#     GOPRIVATE, GONOPROXY and GOINSECURE are empty, GONOSUMCHECK is unset,
#     GOFLAGS carries no -insecure;
#   - GOFLAGS sets -mod=readonly and no other -mod, so go.mod and go.sum are
#     never rewritten;
#   - GOPROXY never falls back to direct.
#
# It reads `go env`, so a value from the pool, the job or a `go env -w`
# file is checked alike. On a GitHub-hosted runner (RUNNER_ENVIRONMENT is
# github-hosted, exactly) it does not apply and exits 0; any other value,
# unset included, is checked.
#
#   usage: scripts/ci-go-integrity.sh
set -euo pipefail

if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
	echo "ci-go-integrity: a GitHub-hosted runner, not a pool: the gate does not apply"
	exit 0
fi

fail=0
bad() {
	echo "::error::ci-go-integrity: $*" >&2
	fail=1
}

sumdb=$(go env GOSUMDB)
[ "$sumdb" = sum.golang.org ] ||
	bad "GOSUMDB is '$sumdb', not sum.golang.org: every module is checked against the checksum database"
for v in GONOSUMDB GOPRIVATE GONOPROXY GOINSECURE; do
	val=$(go env "$v")
	[ -z "$val" ] || bad "$v is '$val': it exempts modules from the checksum database or the proxy"
done
[ -z "${GONOSUMCHECK+set}" ] || bad "GONOSUMCHECK is set ('${GONOSUMCHECK}')"

flags=$(go env GOFLAGS)
readonly_set=0
for f in $flags; do
	case $f in
	-mod=readonly) readonly_set=1 ;;
	-mod | -mod=*) bad "GOFLAGS ('$flags') sets $f: only -mod=readonly is allowed" ;;
	-insecure | -insecure=*) bad "GOFLAGS ('$flags') carries $f" ;;
	esac
done
[ "$readonly_set" = 1 ] || bad "GOFLAGS ('$flags') lacks -mod=readonly"

proxy=$(go env GOPROXY)
IFS='|,' read -ra entries <<<"$proxy"
for e in "${entries[@]}"; do
	[ "$e" != direct ] || bad "GOPROXY ('$proxy') falls back to direct"
done

[ "$fail" = 0 ] || exit 1
echo "ci-go-integrity: GOSUMDB=$sumdb, no checksum or proxy exemptions, GOFLAGS=$flags, GOPROXY=$proxy"

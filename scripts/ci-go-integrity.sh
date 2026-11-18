#!/usr/bin/env bash
# scripts/ci-go-integrity.sh: the module-integrity gate of a Go job on a
# self-hosted pool (Tenant Agent ruling 869, pending InfoSec's review of
# M-8). The pools fetch modules through the LAN proxy first, then
# proxy.golang.org; integrity then rests on the checksum database, which
# verifies every module whichever proxy serves it. So the job fails unless:
#
#   - GOSUMDB is sum.golang.org;
#   - nothing exempts a module from it: GONOSUMDB, GOPRIVATE and GOINSECURE
#     are empty, GONOSUMCHECK is unset, GOFLAGS carries no -insecure;
#   - GOFLAGS carries -mod=readonly, so go.mod and go.sum are never rewritten;
#   - GOPROXY never falls back to direct.
#
# It reads `go env`, so a value from the pool, the job or a `go env -w`
# file is checked alike.
#
#   usage: scripts/ci-go-integrity.sh
set -euo pipefail

fail=0
bad() {
	echo "::error::ci-go-integrity: $*" >&2
	fail=1
}

sumdb=$(go env GOSUMDB)
[ "$sumdb" = sum.golang.org ] ||
	bad "GOSUMDB is '$sumdb', not sum.golang.org: every module is checked against the checksum database"
for v in GONOSUMDB GOPRIVATE GOINSECURE; do
	val=$(go env "$v")
	[ -z "$val" ] || bad "$v is '$val': it exempts modules from the checksum database"
done
[ -z "${GONOSUMCHECK+set}" ] || bad "GONOSUMCHECK is set ('${GONOSUMCHECK}')"

flags=$(go env GOFLAGS)
case " $flags " in
*" -insecure "* | *" -insecure="*) bad "GOFLAGS ('$flags') carries -insecure" ;;
esac
case " $flags " in
*" -mod=readonly "*) ;;
*) bad "GOFLAGS ('$flags') lacks -mod=readonly" ;;
esac

proxy=$(go env GOPROXY)
IFS='|,' read -ra entries <<<"$proxy"
for e in "${entries[@]}"; do
	[ "$e" != direct ] || bad "GOPROXY ('$proxy') falls back to direct"
done

[ "$fail" = 0 ] || exit 1
echo "ci-go-integrity: GOSUMDB=$sumdb, no checksum exemptions, GOFLAGS=$flags, GOPROXY=$proxy"

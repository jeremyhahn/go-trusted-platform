#!/usr/bin/env bash
# ci-go-integrity.sh: the module-integrity gate of Go on a self-hosted pool.
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
case $flags in
*\'* | *\"* | *\\*) bad "GOFLAGS ('$flags') holds quoting or escapes, which go parses differently: set plain -flag=value entries" ;;
esac
readonly_set=0
for f in $flags; do
	case $f in --*) f=${f#-} ;; esac # --flag is -flag to go
	case $f in
	-mod=readonly) readonly_set=1 ;;
	-mod | -mod=*) bad "GOFLAGS ('$flags') sets $f: only -mod=readonly is allowed" ;;
	-insecure | -insecure=*) bad "GOFLAGS ('$flags') carries $f" ;;
	esac
done
[ "$readonly_set" = 1 ] || bad "GOFLAGS ('$flags') lacks -mod=readonly"

proxy=$(go env GOPROXY)
IFS='|,' read -ra entries <<<"$(printf '%s' "$proxy" | tr '\n' ',')"
for e in "${entries[@]}"; do
	e=$(printf '%s' "$e" | tr -d '[:space:]')
	[ "$e" != direct ] || bad "GOPROXY ('$proxy') falls back to direct"
done

[ "$fail" = 0 ] || exit 1
echo "ci-go-integrity: GOSUMDB=$sumdb, no checksum or proxy exemptions, GOFLAGS=$flags, GOPROXY=$proxy"

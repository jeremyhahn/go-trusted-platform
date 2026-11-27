#!/bin/bash
# sdk-consumer-check.sh: build sdk/go the way a module consumer does.
set -euo pipefail

root_module="github.com/jeremyhahn/go-trusted-platform"
sdk_module="$root_module/sdk/go"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -R "$repo_root/sdk/go" "$work/sdk"
mkdir "$work/consumer"
cd "$work/consumer"

export GOWORK=off
export GOFLAGS=-mod=mod

go mod init example.com/sdk-consumer 2>/dev/null
go mod edit -require="$sdk_module@v0.0.0" -replace="$sdk_module=../sdk"
cp ../sdk/go.sum go.sum

if ! packages="$(go list "$sdk_module/...")"; then
    echo "sdk-consumer-check: FAIL: cannot list the sdk/go packages from a consumer module" >&2
    exit 1
fi

# shellcheck disable=SC2086 # one argument per package path
if ! go build $packages; then
    echo "sdk-consumer-check: FAIL: sdk/go does not build from a consumer module" >&2
    exit 1
fi

# shellcheck disable=SC2086 # one argument per package path
deps="$(go list -deps $packages)"
leaks="$(printf '%s\n' "$deps" | grep "^$root_module/" | grep -v -e "^$sdk_module\$" -e "^$sdk_module/" || true)"
if [ -n "$leaks" ]; then
    echo "sdk-consumer-check: FAIL: sdk/go depends on the root module:" >&2
    printf '%s\n' "$leaks" >&2
    exit 1
fi

echo "sdk-consumer-check: OK: $(printf '%s\n' "$packages" | wc -l) sdk/go packages build without the root module"

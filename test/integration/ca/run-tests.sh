#!/bin/bash
# CA QuicBaaS Adapters Integration Tests
#
# This script runs the CA QuicBaaS adapter integration tests.
#
# Usage:
#   ./run-tests.sh           # Run tests (default)

set -e

WORKSPACE="${WORKSPACE:-/workspace}"

# The tags come from the Makefile, never a hand-written list.
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$WORKSPACE" print-build-tags)}"

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    echo "=== Running CA QuicBaaS Adapter Integration Tests ==="
    cd "$WORKSPACE"

    export CGO_ENABLED=0

    go test -v -tags "$BUILD_TAGS" -count=1 -parallel 1 -timeout 10m ./test/integration/ca/...

    echo "=== CA QuicBaaS Adapter Integration Tests Complete ==="
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    test|run)
        run_tests
        ;;
    *)
        echo "Usage: $0 {test}"
        exit 1
        ;;
esac

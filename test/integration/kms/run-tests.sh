#!/bin/bash
# KMS Integration Tests
#
# This script runs the KMS integration tests for QuicBaaS.
# Tests cover key generation, rotation, encrypt/decrypt,
# DEK management, and secrets store/retrieve.
#
# Usage:
#   ./run-tests.sh           # Run tests (default)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    echo "=== Running KMS Integration Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=0

    go test -v -tags integration -count=1 -parallel 1 -timeout 10m ./test/integration/kms/...

    echo "=== KMS Integration Tests Complete ==="
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

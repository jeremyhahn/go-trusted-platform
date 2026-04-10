#!/bin/bash
# iPXE/PXE Integration Tests
#
# This script runs the iPXE/PXE integration tests covering DHCP, TFTP,
# HTTP boot scripts, and multi-protocol server functionality.
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh dhcp      # Run DHCP protocol tests
#   ./run-tests.sh tftp      # Run TFTP protocol tests
#   ./run-tests.sh http      # Run HTTP boot script tests
#   ./run-tests.sh multi     # Run multi-protocol integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# Test Functions
# =============================================================================

run_all_tests() {
    log_info "=== Running iPXE Integration Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    go test -v -count=1 -parallel 1 -timeout 5m -tags=integration \
        ./test/integration/ipxe/...

    log_info "=== iPXE Integration Tests Complete ==="
}

run_dhcp_tests() {
    log_info "=== Running DHCP Protocol Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    go test -v -count=1 -parallel 1 -timeout 5m -tags=integration \
        -run "TestDHCP" ./test/integration/ipxe/...

    log_info "=== DHCP Protocol Tests Complete ==="
}

run_tftp_tests() {
    log_info "=== Running TFTP Protocol Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    go test -v -count=1 -parallel 1 -timeout 5m -tags=integration \
        -run "TestTFTP" ./test/integration/ipxe/...

    log_info "=== TFTP Protocol Tests Complete ==="
}

run_http_tests() {
    log_info "=== Running HTTP Boot Script Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    go test -v -count=1 -parallel 1 -timeout 5m -tags=integration \
        -run "TestHTTP" ./test/integration/ipxe/...

    log_info "=== HTTP Boot Script Tests Complete ==="
}

run_multi_tests() {
    log_info "=== Running Multi-Protocol Integration Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    go test -v -count=1 -parallel 1 -timeout 10m -tags=integration \
        -run "TestMultiProtocol|TestPXE" ./test/integration/ipxe/...

    log_info "=== Multi-Protocol Integration Tests Complete ==="
}

# =============================================================================
# Main
# =============================================================================

case "${1:-all}" in
    all|test|run)
        run_all_tests
        ;;
    dhcp)
        run_dhcp_tests
        ;;
    tftp)
        run_tftp_tests
        ;;
    http)
        run_http_tests
        ;;
    multi)
        run_multi_tests
        ;;
    *)
        echo "Usage: $0 {all|dhcp|tftp|http|multi}"
        echo ""
        echo "Commands:"
        echo "  all   - Run all iPXE integration tests (default)"
        echo "  dhcp  - Run DHCP protocol tests only"
        echo "  tftp  - Run TFTP protocol tests only"
        echo "  http  - Run HTTP boot script tests only"
        echo "  multi - Run multi-protocol integration tests"
        exit 1
        ;;
esac

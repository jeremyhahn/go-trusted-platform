#!/bin/bash
# CLI Multi-Protocol Integration Tests
#
# This script runs the root-level CLI multi-protocol integration tests.
# Tests commands: version, status, health, config, context, service, completion
# Tests all protocols: CLI, REST, gRPC, QUIC, MCP, Unix Socket
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh version   # Run version command tests only
#   ./run-tests.sh status    # Run status command tests only
#   ./run-tests.sh health    # Run health command tests only
#   ./run-tests.sh config    # Run config command tests only
#   ./run-tests.sh context   # Run context command tests only
#   ./run-tests.sh service   # Run service command tests only
#   ./run-tests.sh completion # Run completion command tests only
#   ./run-tests.sh edge      # Run edge case tests only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"

# Build tags for CGO and PKCS11 support
BUILD_TAGS="integration pkcs11 objstore"

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    local filter="${1:-}"
    echo "=== Running CLI Multi-Protocol Integration Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    if [ -n "$filter" ]; then
        echo "Filter: $filter"
        go test -tags "$BUILD_TAGS" -v -count=1 -parallel 1 -timeout 10m -run "$filter" ./test/integration/cli/...
    else
        go test -tags "$BUILD_TAGS" -v -count=1 -parallel 1 -timeout 10m ./test/integration/cli/...
    fi

    echo "=== CLI Multi-Protocol Integration Tests Complete ==="
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    test|run|all)
        run_tests
        ;;
    version)
        run_tests "testVersionCommands"
        ;;
    status)
        run_tests "testStatusCommands"
        ;;
    health)
        run_tests "testHealthCommands"
        ;;
    config)
        run_tests "testConfigCommands"
        ;;
    context)
        run_tests "testContextCommands"
        ;;
    service)
        run_tests "testServiceCommands"
        ;;
    completion)
        run_tests "testCompletionCommands"
        ;;
    edge)
        run_tests "TestCLIEdgeCases"
        ;;
    multi|multiprotocol)
        run_tests "TestCLIMultiProtocol"
        ;;
    *)
        echo "Usage: $0 {test|version|status|health|config|context|service|completion|edge|multiprotocol}"
        echo ""
        echo "Commands:"
        echo "  test, run, all  - Run all CLI integration tests"
        echo "  version         - Run version command tests"
        echo "  status          - Run status command tests"
        echo "  health          - Run health command tests"
        echo "  config          - Run config command tests"
        echo "  context         - Run context command tests"
        echo "  service         - Run service command tests"
        echo "  completion      - Run completion command tests"
        echo "  edge            - Run edge case tests"
        echo "  multiprotocol   - Run full multi-protocol test suite"
        exit 1
        ;;
esac

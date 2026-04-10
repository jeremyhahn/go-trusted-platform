#!/bin/bash
# Daemon Multi-Protocol Integration Tests
#
# This script runs the daemon multi-protocol integration tests.
# Tests all protocols: REST, gRPC, QUIC, MCP, Unix Socket
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh rest      # Run REST tests only
#   ./run-tests.sh grpc      # Run gRPC tests only
#   ./run-tests.sh quic      # Run QUIC tests only
#   ./run-tests.sh mcp       # Run MCP tests only
#   ./run-tests.sh unix      # Run Unix socket tests only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-/workspace}"

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    local filter="${1:-}"
    echo "=== Running Daemon Multi-Protocol Integration Tests ==="
    cd "$WORKSPACE"

    export INTEGRATION_TEST=1
    export CGO_ENABLED=1

    if [ -n "$filter" ]; then
        echo "Filter: $filter"
        go test -v -tags integration -count=1 -parallel 1 -timeout 10m -run "$filter" ./test/integration/daemon/...
    else
        go test -v -tags integration -count=1 -parallel 1 -timeout 10m ./test/integration/daemon/...
    fi

    echo "=== Daemon Multi-Protocol Integration Tests Complete ==="
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    test|run)
        run_tests
        ;;
    rest)
        run_tests "TestDaemonREST"
        ;;
    grpc)
        run_tests "TestDaemonGRPC"
        ;;
    quic)
        run_tests "TestDaemonQUIC"
        ;;
    mcp)
        run_tests "TestDaemonMCP"
        ;;
    unix)
        run_tests "TestDaemonUnix"
        ;;
    cli)
        run_tests "TestDaemonCLI"
        ;;
    *)
        echo "Usage: $0 {test|rest|grpc|quic|mcp|unix|cli}"
        exit 1
        ;;
esac

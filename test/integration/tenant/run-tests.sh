#!/bin/bash
# Tenant Multi-Protocol Integration Tests
#
# This script runs the tenant multi-protocol integration tests.
# Tests all protocols: CLI, REST, gRPC, QUIC, MCP, Unix Socket
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh cli       # Run CLI tests only
#   ./run-tests.sh rest      # Run REST tests only
#   ./run-tests.sh grpc      # Run gRPC tests only
#   ./run-tests.sh quic      # Run QUIC tests only
#   ./run-tests.sh mcp       # Run MCP tests only
#   ./run-tests.sh unix      # Run Unix socket tests only

set -e

WORKSPACE="${WORKSPACE:-/workspace}"

# The tags come from the Makefile, never a hand-written list.
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$WORKSPACE" print-build-tags)}"

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    local filter="${1:-}"
    echo "=== Running Tenant Multi-Protocol Integration Tests ==="
    cd "$WORKSPACE"

    export CGO_ENABLED=1

    if [ -n "$filter" ]; then
        echo "Filter: $filter"
        go test -tags "$BUILD_TAGS" -v -count=1 -parallel 1 -timeout 10m -run "$filter" ./test/integration/tenant/...
    else
        go test -tags "$BUILD_TAGS" -v -count=1 -parallel 1 -timeout 10m ./test/integration/tenant/...
    fi

    echo "=== Tenant Multi-Protocol Integration Tests Complete ==="
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    test|run)
        run_tests
        ;;
    cli)
        run_tests "TestTenant.*CLI"
        ;;
    rest)
        run_tests "TestTenant.*REST"
        ;;
    grpc)
        run_tests "TestTenant.*gRPC"
        ;;
    quic)
        run_tests "TestTenant.*QUIC"
        ;;
    mcp)
        run_tests "TestTenant.*MCP"
        ;;
    unix)
        run_tests "TestTenant.*Unix"
        ;;
    crud)
        run_tests "TestTenant.*CRUD"
        ;;
    lifecycle)
        run_tests "TestTenant.*Lifecycle"
        ;;
    quotas)
        run_tests "TestTenant.*Quotas"
        ;;
    network)
        run_tests "TestTenant.*Network"
        ;;
    sync)
        run_tests "TestTenant.*Sync"
        ;;
    *)
        echo "Usage: $0 {test|cli|rest|grpc|quic|mcp|unix|crud|lifecycle|quotas|network|sync}"
        exit 1
        ;;
esac

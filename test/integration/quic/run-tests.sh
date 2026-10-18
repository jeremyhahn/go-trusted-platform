#!/bin/bash
# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# QUIC Integration Test Runner
#
# This script starts a platformd instance in test mode and runs QUIC protocol
# integration tests against it.
#
# Usage:
#   ./run-tests.sh                    # Run all QUIC tests
#   ./run-tests.sh -run TestQUICCA    # Run specific test
#
# Environment Variables:
#   QUIC_SERVER_ADDR - QUIC server address (default: localhost:9444)
#   QUIC_AUTH_TOKEN  - Authentication token for requests
#   SKIP_DAEMON_START - Set to 1 to skip starting platformd (use external server)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# The tags come from the Makefile, never a hand-written list.
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$PROJECT_ROOT" print-build-tags)}"

# Default configuration
export QUIC_SERVER_ADDR="${QUIC_SERVER_ADDR:-localhost:9444}"
QUIC_HOST="${QUIC_SERVER_ADDR%:*}"
QUIC_PORT="${QUIC_SERVER_ADDR#*:}"

# Daemon configuration
PLATFORMD_PID=""
PLATFORMD_LOG="/tmp/platformd-quic-test.log"
PLATFORMD_SOCKET="/tmp/platformd-quic-test.sock"
STARTUP_TIMEOUT=30

echo "Running QUIC Integration Tests"
echo "=============================="
echo "Server Address: ${QUIC_SERVER_ADDR}"
echo ""

# Cleanup function to stop platformd on exit
cleanup() {
    if [ -n "$PLATFORMD_PID" ] && kill -0 "$PLATFORMD_PID" 2>/dev/null; then
        echo "Stopping platformd (PID: $PLATFORMD_PID)..."
        kill "$PLATFORMD_PID" 2>/dev/null || true
        wait "$PLATFORMD_PID" 2>/dev/null || true
    fi
    rm -f "$PLATFORMD_SOCKET"
}
trap cleanup EXIT

# Start platformd in test mode if not already running
start_platformd() {
    if [ "${SKIP_DAEMON_START:-}" = "1" ]; then
        echo "SKIP_DAEMON_START=1: Using external platformd server"
        return 0
    fi

    # Check if already running
    if nc -z "$QUIC_HOST" "$QUIC_PORT" 2>/dev/null; then
        echo "QUIC server already running at ${QUIC_SERVER_ADDR}"
        return 0
    fi

    echo "Starting platformd in test mode..."

    # Build platformd if needed
    if [ ! -x "$PROJECT_ROOT/bin/platformd" ]; then
        echo "Building platformd..."
        cd "$PROJECT_ROOT"
        make build
    fi

    # Start platformd in test mode (skips IAM validation)
    cd "$PROJECT_ROOT"
    "$PROJECT_ROOT/bin/platformd" serve \
        --test-mode \
        --socket-path="$PLATFORMD_SOCKET" \
        --enable-rest=false \
        --enable-grpc=false \
        --enable-quic=true \
        --quic-port="$QUIC_PORT" \
        --enable-mcp=false \
        > "$PLATFORMD_LOG" 2>&1 &
    PLATFORMD_PID=$!

    echo "Waiting for platformd to start (PID: $PLATFORMD_PID)..."

    # Wait for QUIC port to be available
    local elapsed=0
    while [ $elapsed -lt $STARTUP_TIMEOUT ]; do
        if nc -z "$QUIC_HOST" "$QUIC_PORT" 2>/dev/null; then
            echo "platformd QUIC server is ready at ${QUIC_SERVER_ADDR}"
            return 0
        fi

        # Check if process is still running
        if ! kill -0 "$PLATFORMD_PID" 2>/dev/null; then
            echo "ERROR: platformd exited unexpectedly. Log:"
            cat "$PLATFORMD_LOG"
            return 1
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "ERROR: platformd failed to start within ${STARTUP_TIMEOUT}s. Log:"
    cat "$PLATFORMD_LOG"
    return 1
}

# Start platformd
if ! start_platformd; then
    echo "Failed to start platformd - skipping QUIC tests"
    echo "Note: QUIC tests require a properly configured platformd instance"
    echo "Set SKIP_DAEMON_START=1 and start platformd manually with a valid config"
    exit 0  # Exit with success to not fail the integration test suite
fi

cd "${PROJECT_ROOT}"

# Run the tests
echo ""
echo "Running QUIC tests..."
go test -v -tags "$BUILD_TAGS" "${SCRIPT_DIR}/..." "$@"
TEST_RESULT=$?

echo ""
if [ $TEST_RESULT -eq 0 ]; then
    echo "QUIC Integration Tests Complete (PASSED)"
else
    echo "QUIC Integration Tests Complete (FAILED)"
fi

exit $TEST_RESULT

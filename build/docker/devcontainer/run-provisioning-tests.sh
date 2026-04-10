#!/bin/bash
# Provisioning integration test runner for go-trusted-platform devcontainer.
#
# This script sets up the test environment (swtpm, platformd) and runs
# only the provisioning integration test package.
#
# Usage:
#   run-provisioning-tests.sh [BUILD_TAGS]
#
# Arguments:
#   BUILD_TAGS - Space-separated list of build tags
#                (default: "integration codec_msgpack codec_json codec_cbor")

set -uo pipefail

BUILD_TAGS="${1:-integration codec_msgpack codec_json codec_cbor}"
BUILD_TAGS_ARG="-tags ${BUILD_TAGS}"

PLATFORMD_PID=""
CLEANUP_DONE=false

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    if [ "$CLEANUP_DONE" = true ]; then
        return
    fi
    CLEANUP_DONE=true

    echo ""
    echo "=== Cleaning up provisioning test environment ==="

    if [ -n "$PLATFORMD_PID" ] && kill -0 "$PLATFORMD_PID" 2>/dev/null; then
        echo "Stopping platformd (PID: $PLATFORMD_PID)..."
        kill "$PLATFORMD_PID" 2>/dev/null || true
        wait "$PLATFORMD_PID" 2>/dev/null || true
    fi

    pkill -9 -f 'swtpm socket' 2>/dev/null || true

    echo "=== Cleanup complete ==="
}

trap cleanup EXIT

# =============================================================================
# swtpm Setup
# =============================================================================

start_swtpm() {
    echo "=== Starting Software TPM (swtpm) ==="

    pkill -9 -f 'swtpm socket' 2>/dev/null || true
    sleep 1

    rm -rf /tmp/swtpm
    mkdir -p /tmp/swtpm

    if command -v swtpm_setup > /dev/null 2>&1; then
        swtpm_setup --tpm2 --tpmstate /tmp/swtpm --overwrite --pcr-banks sha256
    fi

    if command -v swtpm > /dev/null 2>&1; then
        swtpm socket --tpm2 \
            --tpmstate dir=/tmp/swtpm \
            --server type=unixio,path=/tmp/swtpm/swtpm.sock \
            --ctrl type=unixio,path=/tmp/swtpm/swtpm.sock.ctrl \
            --flags startup-clear,not-need-init \
            --log level=1,file=/tmp/swtpm/swtpm.log &
        sleep 2

        if [ -S /tmp/swtpm/swtpm.sock ]; then
            echo "swtpm started successfully"
        else
            echo "WARNING: swtpm socket not found"
        fi
    else
        echo "WARNING: swtpm not installed, vTPM features may be unavailable"
    fi

    echo "=== swtpm setup complete ==="
}

# =============================================================================
# Build & Start platformd
# =============================================================================

build_binaries() {
    echo "=== Building platformd and platformctl ==="

    cd /workspace

    echo "Downloading module dependencies..."
    if ! go mod download -x 2>&1 | tail -5; then
        echo "WARNING: go mod download had errors (continuing anyway)"
    fi
    echo "Module dependencies downloaded"

    echo "Pre-compiling test packages..."
    if ! go test -tags "${BUILD_TAGS}" -count=0 ./test/integration/provisioning/... 2>&1 | tail -5; then
        echo "WARNING: test packages failed to pre-compile (continuing anyway)"
    fi
    echo "Test packages pre-compiled"

    LDFLAGS="-X github.com/jeremyhahn/go-trusted-platform/pkg/app.Version=0.0.0-test -X github.com/jeremyhahn/go-trusted-platform/pkg/app.Name=trusted-platform"

    echo "Building platformd..."
    if ! go build -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/platformd ./cmd/platformd/; then
        echo "FATAL: platformd build failed"
        exit 1
    fi
    echo "platformd built successfully"

    echo "Building platformctl..."
    if ! go build -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/platformctl ./cmd/platformctl/; then
        echo "FATAL: platformctl build failed"
        exit 1
    fi
    echo "platformctl built successfully"

    export PATH="/tmp:${PATH}"

    echo "=== Binaries built ==="
}

start_platformd() {
    echo "=== Starting platformd ==="

    rm -rf /tmp/platformd-integration
    mkdir -p /run /tmp/platformd-integration/log /tmp/platformd-integration/ca /tmp/platformd-integration/vtpm /tmp/platformd-integration/quicbaas

    /tmp/platformd serve \
        --config /workspace/test/integration/config.yaml \
        --enable-mtls \
        --skip-iam-validation \
        --socket-path=/run/platformd.sock \
        --rest-port=8443 \
        --grpc-port=10443 \
        --quic-port=9444 \
        --mcp-port=9445 \
        --raw-so-pin="123456" \
        --raw-pin="123456" \
        --debug \
        > /var/log/platformd.log 2>&1 &

    PLATFORMD_PID=$!
    echo "platformd starting (PID: $PLATFORMD_PID)..."

    for i in $(seq 1 30); do
        if [ -S /run/platformd.sock ]; then
            echo "platformd started successfully"

            for j in $(seq 1 10); do
                if [ -f /tmp/platformd-integration/tls/client-bundle.pem ] && \
                   [ -f /tmp/platformd-integration/tls/ca-bundle.crt ]; then
                    echo "mTLS certificates ready"
                    break
                fi
                sleep 1
            done

            echo "=== platformd ready ==="
            return 0
        fi
        sleep 1
    done

    echo "WARNING: platformd socket not ready after 30 seconds"
    echo "platformd logs:"
    tail -50 /var/log/platformd.log 2>/dev/null || true
    echo "=== platformd may not be fully operational ==="
    return 1
}

setup_env_vars() {
    echo "=== Setting environment variables ==="

    export INTEGRATION_TEST="1"
    export DEVCONTAINER="1"

    export PLATFORMD_SOCKET="/run/platformd.sock"
    export PLATFORM_SOCKET_PATH="/run/platformd.sock"

    export PLATFORM_CLIENT_CERT="/tmp/platformd-integration/tls/client-bundle.pem"
    export PLATFORM_CLIENT_KEY="/tmp/platformd-integration/tls/client-bundle.pem"
    export PLATFORM_CA_CERT="/tmp/platformd-integration/tls/ca-bundle.crt"

    export PLATFORM_API_ENDPOINT="https://localhost:8443"
    export PLATFORM_REST_ENDPOINT="https://localhost:8443"
    export PLATFORM_REST_URL="https://localhost:8443"

    export PLATFORM_GRPC_ENDPOINT="localhost:10443"
    export PLATFORM_GRPC_PORT="10443"

    export PLATFORM_QUIC_ENDPOINT="localhost:9444"
    export PLATFORM_MCP_ENDPOINT="localhost:9445"

    export PLATFORMCTL_BINARY="/tmp/platformctl"
    export PLATFORMCTL_PATH="/tmp/platformctl"

    echo "  PLATFORM_REST_URL=$PLATFORM_REST_URL"
    echo "  PLATFORM_CLIENT_CERT=$PLATFORM_CLIENT_CERT"
    echo "  PLATFORM_CA_CERT=$PLATFORM_CA_CERT"
    echo "=== Environment variables set ==="
}

# =============================================================================
# Main
# =============================================================================

echo "============================================="
echo "  Provisioning Integration Tests"
echo "============================================="
echo "Build tags: ${BUILD_TAGS}"
echo ""

build_binaries

start_swtpm || echo "WARNING: swtpm setup failed"

start_platformd || echo "WARNING: platformd setup failed"

setup_env_vars

echo ""
echo "============================================="
echo "  Running Provisioning Tests"
echo "============================================="
echo ""

RESULT=0

if go test -v -tags "${BUILD_TAGS}" -count=1 -parallel 1 -timeout 10m ./test/integration/provisioning/...; then
    echo "--- PASS: provisioning ---"
else
    echo "--- FAIL: provisioning ---"
    RESULT=1
fi

echo ""
echo "=== platformd stderr log (post-test) ==="
cat /var/log/platformd.log 2>/dev/null || echo "(empty or missing)"
echo "=== platformd app log (post-test) ==="
cat /tmp/platformd-integration/log/trusted-platform.log 2>/dev/null || echo "(empty or missing)"

echo ""
echo "============================================="
if [ $RESULT -eq 0 ]; then
    echo "  PROVISIONING TESTS PASSED"
else
    echo "  PROVISIONING TESTS FAILED"
fi
echo "============================================="

exit $RESULT

#!/bin/bash
# Integration test runner for go-trusted-platform devcontainer.
#
# This script sets up the complete test environment (OVS, swtpm, platformd)
# and runs integration test packages.
#
# Usage:
#   run-integration-tests.sh [TARGET] [BUILD_TAGS]
#
# Arguments:
#   TARGET     - Optional target keyword selecting which package(s) to run.
#                Known targets: all, bmc, ceremony, piv, luks, fido2, device.
#                If the first argument is not a known target, it is treated
#                as BUILD_TAGS (backward-compatible with the prior 1-arg form).
#                Default: all
#   BUILD_TAGS - Space-separated list of build tags
#                (default: "integration codec_msgpack codec_json codec_cbor")
#
# Examples:
#   run-integration-tests.sh
#   run-integration-tests.sh all
#   run-integration-tests.sh ceremony
#   run-integration-tests.sh luks "integration codec_msgpack codec_json codec_cbor"
#   run-integration-tests.sh "integration codec_msgpack"      # legacy form

set -uo pipefail

# Known target keywords mapped to their Go test package paths. A single-word
# first argument matching a key here selects that target; anything else is
# treated as the legacy BUILD_TAGS argument.
declare -A TARGET_PACKAGES=(
    [all]=""
    [bmc]="./test/integration/bmc/..."
    [bootstrap]="./test/integration/bootstrap/..."
    [ca]="./test/integration/ca/..."
    [ceremony]="./test/integration/ceremony/..."
    [piv]="./test/integration/piv/..."
    [luks]="./test/integration/luks/..."
    [fido2]="./test/integration/fido2/..."
    [device]="./test/integration/device/..."
    [tpm]="./test/integration/tpm/..."
    [cold-start]="./test/integration/cold_start/..."
    [barrier-gate]="./test/integration/barrier_gate/..."
    [restroutes]="./test/integration/restroutes/..."
)

RUN_TARGET="all"
ARG1="${1:-}"
ARG2="${2:-}"

if [ -n "$ARG1" ] && [ -n "${TARGET_PACKAGES[$ARG1]+set}" ]; then
    RUN_TARGET="$ARG1"
    BUILD_TAGS="${ARG2:-integration codec_msgpack codec_json codec_cbor}"
else
    # Legacy single-arg form: treat ARG1 as BUILD_TAGS.
    BUILD_TAGS="${ARG1:-integration codec_msgpack codec_json codec_cbor}"
fi

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
    echo "=== Cleaning up integration test environment ==="

    # Stop platformd
    if [ -n "$PLATFORMD_PID" ] && kill -0 "$PLATFORMD_PID" 2>/dev/null; then
        echo "Stopping platformd (PID: $PLATFORMD_PID)..."
        kill "$PLATFORMD_PID" 2>/dev/null || true
        wait "$PLATFORMD_PID" 2>/dev/null || true
    fi

    # Stop swtpm
    pkill -9 -f 'swtpm socket' 2>/dev/null || true

    # Stop OVS
    if [ -f /var/run/openvswitch/ovs-vswitchd.pid ]; then
        kill "$(cat /var/run/openvswitch/ovs-vswitchd.pid)" 2>/dev/null || true
    fi
    if [ -f /var/run/openvswitch/ovsdb-server.pid ]; then
        kill "$(cat /var/run/openvswitch/ovsdb-server.pid)" 2>/dev/null || true
    fi

    echo "=== Cleanup complete ==="
}

trap cleanup EXIT

# =============================================================================
# Device Setup
# =============================================================================

setup_devices() {
    echo "=== Setting up devices and kernel modules ==="

    # TUN/TAP permissions
    if [ -e /dev/net/tun ]; then
        chmod 666 /dev/net/tun
    fi

    # KVM permissions
    if [ -e /dev/kvm ]; then
        chmod 666 /dev/kvm
    fi

    # Load kernel modules (best effort)
    modprobe tun 2>/dev/null || true
    modprobe openvswitch 2>/dev/null || true

    echo "=== Device setup complete ==="
}

# =============================================================================
# OVS Setup
# =============================================================================

start_ovs() {
    echo "=== Starting Open vSwitch ==="

    mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch

    # Initialize OVS database if needed
    if [ ! -f /etc/openvswitch/conf.db ]; then
        echo "Initializing OVSDB..."
        ovsdb-tool create /etc/openvswitch/conf.db \
            /usr/share/openvswitch/vswitch.ovsschema
    fi

    # Start ovsdb-server
    if ! pgrep -x ovsdb-server > /dev/null; then
        echo "Starting ovsdb-server..."
        ovsdb-server \
            --remote=punix:/var/run/openvswitch/db.sock \
            --remote=ptcp:6640:127.0.0.1 \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log \
            /etc/openvswitch/conf.db
        sleep 2
        ovs-vsctl --no-wait init || true
    fi

    # Start ovs-vswitchd
    if ! pgrep -x ovs-vswitchd > /dev/null; then
        echo "Starting ovs-vswitchd..."
        ovs-vswitchd \
            --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log
        sleep 2
    fi

    # Verify
    if ovs-vsctl show > /dev/null 2>&1; then
        echo "OVS started successfully"
    else
        echo "WARNING: OVS may not be fully operational"
    fi

    echo "=== OVS started ==="
}

# =============================================================================
# swtpm Setup
# =============================================================================

start_swtpm() {
    echo "=== Starting Software TPM (swtpm) ==="

    # Kill any existing swtpm
    pkill -9 -f 'swtpm socket' 2>/dev/null || true
    sleep 1

    rm -rf /tmp/swtpm
    mkdir -p /tmp/swtpm

    # Initialize TPM state
    if command -v swtpm_setup > /dev/null 2>&1; then
        swtpm_setup --tpm2 --tpmstate /tmp/swtpm --overwrite --pcr-banks sha256
    fi

    # Start swtpm daemon
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
        echo "WARNING: swtpm not installed, vTPM tests may be skipped"
    fi

    echo "=== swtpm setup complete ==="
}

# =============================================================================
# platformd Setup
# =============================================================================

build_binaries() {
    echo "=== Building platformd and platformctl ==="

    # Detect a Go workspace setup: when /home/jhahn/sources/go.work exists
    # the host has mounted a multi-repo go workspace into the container, and
    # the build must run from the in-workspace path of go-trusted-platform
    # so the `use ./go-trusted-platform` directive resolves. Otherwise fall
    # back to the legacy /workspace cwd. This keeps the legacy single-mount
    # path working unchanged while supporting the barrier-gate / cold-start
    # targets that need local source replaces for go-xkms, go-quicbaas etc.
    local build_dir="/workspace"
    if [ -f /home/jhahn/sources/go.work ] && [ -d /home/jhahn/sources/go-trusted-platform ]; then
        build_dir="/home/jhahn/sources/go-trusted-platform"
        export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
        echo "Detected go workspace; building from $build_dir (GOTOOLCHAIN=$GOTOOLCHAIN)"
    fi
    cd "$build_dir"

    # Pre-download ALL module dependencies before building or testing.
    # This prevents stalls during 'go test' when large deps (libovsdb,
    # coredhcp) are fetched on-demand with a test timeout running.
    echo "Downloading module dependencies..."
    if ! go mod download -x 2>&1 | tail -5; then
        echo "WARNING: go mod download had errors (continuing anyway)"
    fi
    echo "Module dependencies downloaded"

    # Pre-compile all test packages to cache build artifacts.
    # This prevents 'go test' from spending its timeout on compilation.
    echo "Pre-compiling test packages..."
    if ! go test -tags "${BUILD_TAGS}" -count=0 ./test/integration/... 2>&1 | tail -5; then
        echo "WARNING: some test packages failed to pre-compile (continuing anyway)"
    fi
    echo "Test packages pre-compiled"

    # ldflags to inject version and name into binaries
    LDFLAGS="-X github.com/jeremyhahn/go-trusted-platform/pkg/app.Version=0.0.0-test -X github.com/jeremyhahn/go-trusted-platform/pkg/app.Name=trusted-platform"

    # Build platformd. -buildvcs=false because the bind-mounted /workspace
    # has a .git directory the container's git can read but with permission
    # quirks that fail VCS stamping; the test build doesn't need VCS info.
    echo "Building platformd..."
    if ! go build -buildvcs=false -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/platformd ./cmd/platformd/; then
        echo "FATAL: platformd build failed"
        exit 1
    fi
    echo "platformd built successfully"

    # Build platformctl
    echo "Building platformctl..."
    if ! go build -buildvcs=false -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/platformctl ./cmd/platformctl/; then
        echo "FATAL: platformctl build failed"
        exit 1
    fi
    echo "platformctl built successfully"

    # Add binaries to PATH so adapters can find them
    export PATH="/tmp:${PATH}"

    echo "=== Binaries built ==="
}

start_platformd() {
    echo "=== Starting platformd ==="

    # Clean stale data from previous runs to avoid key/cert mismatches
    rm -rf /tmp/platformd-integration
    mkdir -p /run /tmp/platformd-integration/log /tmp/platformd-integration/ca /tmp/platformd-integration/vtpm /tmp/platformd-integration/quicbaas

    # Start platformd with mTLS authentication (all protocols)
    # --skip-iam-validation disables token-based auth on MCP since integration
    # tests don't set up an IAM/token infrastructure
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

    # Wait for socket to be ready
    for i in $(seq 1 30); do
        if [ -S /run/platformd.sock ]; then
            echo "platformd started successfully"
            echo "=== platformd startup log (stdout/stderr) ==="
            cat /var/log/platformd.log 2>/dev/null || true
            echo "=== platformd app log ==="
            cat /tmp/platformd-integration/log/trusted-platform.log 2>/dev/null || true

            # Wait for mTLS certificates to be generated
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
    echo "=== Setting environment variables for adapters ==="

    # Integration test flags (many tests check these at runtime)
    export INTEGRATION_TEST="1"
    export DEVCONTAINER="1"

    # Enable Raft cluster simulation tests
    export RAFT_CLUSTER_TEST="1"

    # Socket path for Unix adapters (daemon, sdn, vtpm, overlay, and the new
    # ceremony/piv/luks/fido2 suites that share the adapter pattern).
    export PLATFORMD_SOCKET="/run/platformd.sock"
    export PLATFORM_SOCKET_PATH="/run/platformd.sock"
    export PLATFORM_UNIX_SOCKET="/run/platformd.sock"
    export VTPM_SOCKET_PATH="/run/platformd.sock"

    # mTLS client certificate paths for test adapters
    # Client bundle contains both cert and key PEM blocks;
    # tls.LoadX509KeyPair extracts each block type from the same file.
    export PLATFORM_CLIENT_CERT="/tmp/platformd-integration/tls/client-bundle.pem"
    export PLATFORM_CLIENT_KEY="/tmp/platformd-integration/tls/client-bundle.pem"
    export PLATFORM_CA_CERT="/tmp/platformd-integration/tls/ca-bundle.crt"

    # REST endpoint (mTLS requires HTTPS)
    export PLATFORM_API_ENDPOINT="https://localhost:8443"
    export PLATFORM_REST_ENDPOINT="https://localhost:8443"
    export PLATFORM_REST_URL="https://localhost:8443"
    export VTPM_REST_ENDPOINT="https://localhost:8443"

    # gRPC endpoint (mTLS over TCP)
    export PLATFORM_GRPC_ENDPOINT="localhost:10443"
    export PLATFORMD_GRPC_ENDPOINT="localhost:10443"
    export PLATFORM_GRPC_PORT="10443"
    export VTPM_GRPC_ENDPOINT="localhost:10443"

    # QUIC endpoint
    export PLATFORM_QUIC_ENDPOINT="localhost:9444"
    export QUIC_SERVER_ADDR="localhost:9444"
    export VTPM_QUIC_ENDPOINT="localhost:9444"

    # MCP endpoint. The daemon adapter uses plain HTTP (see MCP adapter docs in
    # CLAUDE.md); vtpm/sdn-style adapters may use stdio. Ceremony/PIV/LUKS/FIDO2
    # adapters consume the HTTP form, so expose both.
    export PLATFORM_MCP_ENDPOINT="http://localhost:9445"
    export VTPM_MCP_ENDPOINT="http://localhost:9445"
    export PLATFORM_MCP_PATH="/tmp/platformd"

    # CLI binary path
    export PLATFORMCTL_BINARY="/tmp/platformctl"
    export PLATFORMCTL_PATH="/tmp/platformctl"

    # SDN/OVS socket path for SDN service initialization
    if [ -S /var/run/openvswitch/db.sock ]; then
        export SDN_OVS_SOCKET="/var/run/openvswitch/db.sock"
        export SDN_SERVICE_AVAILABLE="1"
    else
        export SDN_SERVICE_AVAILABLE="0"
    fi

    echo "  PLATFORMD_SOCKET=$PLATFORMD_SOCKET"
    echo "  PLATFORM_UNIX_SOCKET=$PLATFORM_UNIX_SOCKET"
    echo "  PLATFORM_CLIENT_CERT=$PLATFORM_CLIENT_CERT (bundle)"
    echo "  PLATFORM_CLIENT_KEY=$PLATFORM_CLIENT_KEY (bundle)"
    echo "  PLATFORM_CA_CERT=$PLATFORM_CA_CERT"
    echo "  PLATFORM_REST_ENDPOINT=$PLATFORM_REST_ENDPOINT"
    echo "  PLATFORM_GRPC_ENDPOINT=$PLATFORM_GRPC_ENDPOINT"
    echo "  PLATFORM_QUIC_ENDPOINT=$PLATFORM_QUIC_ENDPOINT"
    echo "  PLATFORM_MCP_ENDPOINT=$PLATFORM_MCP_ENDPOINT"
    echo "  PLATFORMCTL_PATH=$PLATFORMCTL_PATH"
    echo "  RAFT_CLUSTER_TEST=$RAFT_CLUSTER_TEST"
    echo "=== Environment variables set ==="
}

# =============================================================================
# Main
# =============================================================================

echo "============================================="
echo "  go-trusted-platform Integration Tests"
echo "============================================="
echo "Target:     ${RUN_TARGET}"
echo "Build tags: ${BUILD_TAGS}"
echo ""

# Phase 1: Build binaries
build_binaries

# Phase 2: Setup infrastructure
setup_devices

# OVS is required for SDN/network tests (non-fatal if unavailable)
start_ovs || echo "WARNING: OVS setup failed, SDN/network tests may skip"

# swtpm is required for vTPM tests (non-fatal if unavailable)
start_swtpm || echo "WARNING: swtpm setup failed, vTPM tests may skip"

# Cold-start and barrier-gate scenarios manage their own platformd
# lifecycle; the shared auto-unsealed daemon must NOT be running when
# the harness boots a fresh init-only daemon. Skip the shared start and
# seed the per-scenario env vars instead.
if [ "$RUN_TARGET" = "cold-start" ]; then
    echo "=== cold-start target: skipping shared platformd ==="
    rm -rf /tmp/platformd-cold-start
    mkdir -p /tmp/platformd-cold-start
    export PLATFORM_COLD_START_DIR="/tmp/platformd-cold-start"
    export PLATFORM_COLD_START_BIN="/tmp/platformd"
elif [ "$RUN_TARGET" = "barrier-gate" ]; then
    echo "=== barrier-gate target: skipping shared platformd ==="
    rm -rf /tmp/platformd-barrier-gate
    mkdir -p /tmp/platformd-barrier-gate
    export PLATFORM_BARRIER_GATE_DIR="/tmp/platformd-barrier-gate"
    export PLATFORM_BARRIER_GATE_BIN="/tmp/platformd"
    export PLATFORM_BARRIER_GATE_CONFIG="/workspace/test/integration/barrier_gate/config.yaml"
else
    # platformd is required for standalone protocol tests (non-fatal if unavailable)
    start_platformd || echo "WARNING: platformd setup failed, some protocol tests may skip"
fi

# Phase 3: Configure environment for test adapters
setup_env_vars

echo ""
echo "============================================="
echo "  Running Integration Tests"
echo "============================================="
echo ""

# Track overall result
RESULT=0

# Run each test package, collecting results
# Standalone packages first (no daemon needed), then daemon-dependent packages
run_test() {
    local pkg="$1"
    echo ""
    echo "--- Testing $pkg ---"
    if go test -v -tags "${BUILD_TAGS}" -count=1 -parallel 1 -timeout 10m "$pkg"; then
        echo "--- PASS: $pkg ---"
    else
        echo "--- FAIL: $pkg ---"
        RESULT=1
    fi
}

if [ "$RUN_TARGET" = "all" ]; then
    # Standalone packages (no daemon needed)
    run_test ./test/integration/datastore/...
    run_test ./test/integration/cluster/...

    # All daemon-dependent packages (use the single shared platformd instance)
    run_test ./test/integration/daemon/...
    run_test ./test/integration/ca/...
    run_test ./test/integration/vtpm/...
    run_test ./test/integration/provisioning/...
    # TODO: device integration tests need CRUD routes wired into platformd
    # run_test ./test/integration/device/...
    run_test ./test/integration/sdn/...
    run_test ./test/integration/network/...
    run_test ./test/integration/quic/...
else
    # Single-target run: dispatch via the TARGET_PACKAGES map.
    pkg="${TARGET_PACKAGES[$RUN_TARGET]}"
    if [ -z "$pkg" ]; then
        echo "FATAL: unknown target '$RUN_TARGET'"
        exit 2
    fi
    run_test "$pkg"
fi

echo ""
echo "=== platformd stderr log (post-test) ==="
cat /var/log/platformd.log 2>/dev/null || echo "(empty or missing)"
echo "=== platformd app log (post-test) ==="
cat /tmp/platformd-integration/log/trusted-platform.log 2>/dev/null || echo "(empty or missing)"
echo "=== platformd log dir listing ==="
ls -la /tmp/platformd-integration/log/ 2>/dev/null || echo "(missing)"
echo "=== platformd CA dir listing ==="
ls -laR /tmp/platformd-integration/ca/ 2>/dev/null || echo "(missing)"
echo "=== barrier-gate platformd stderr (post-test) ==="
cat /tmp/platformd-barrier-gate/platformd.log 2>/dev/null || echo "(empty or missing)"
echo "=== barrier-gate platformd app log (post-test) ==="
cat /tmp/platformd-barrier-gate/log/trusted-platform.log 2>/dev/null || echo "(empty or missing)"
echo "=== barrier-gate data dir listing ==="
ls -laR /tmp/platformd-barrier-gate/ 2>/dev/null | head -60 || echo "(missing)"
echo "=== end platformd diagnostics ==="

echo ""
echo "============================================="
if [ $RESULT -eq 0 ]; then
    echo "  ALL INTEGRATION TESTS PASSED"
else
    echo "  SOME INTEGRATION TESTS FAILED"
fi
echo "============================================="

exit $RESULT

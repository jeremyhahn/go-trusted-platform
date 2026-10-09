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
#                Known targets: the keys of TARGET_PACKAGES below — all, bmc,
#                bootstrap, ca, ceremony, piv, luks, fido2, provision,
#                secureboot, device, tpm, cold-start, barrier-gate,
#                restroutes, sdn, proxy, ntp, tenant, iam, attestation, lb,
#                nat64, diskimage, netboot, ipsec.
#                If the first argument is not a known target, it is treated
#                as BUILD_TAGS (backward-compatible with the prior 1-arg form).
#                Default: all
#   BUILD_TAGS - Space-separated list of build tags
#                (default: "integration codec_msgpack codec_json codec_cbor")
#
# Environment:
#   HOST_UID / HOST_GID - the invoking user on the host. Anything the run
#                creates in the bind-mounted source tree is handed back to them
#                on exit; see restore_workspace_ownership. Optional: the mount
#                point's own ownership is used when they are unset.
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
    [provision]="./test/integration/provision/..."
    [secureboot]="./test/integration/secureboot/..."
    [device]="./test/integration/device/..."
    [tpm]="./test/integration/tpm/..."
    [cold-start]="./test/integration/cold_start/..."
    [barrier-gate]="./test/integration/barrier_gate/..."
    [restroutes]="./test/integration/restroutes/..."
    [sdn]="./test/integration/sdn/..."
    [proxy]="./test/integration/proxy/..."
    [ntp]="./test/integration/ntp/..."
    [tenant]="./test/integration/tenant/..."
    [iam]="./test/integration/iam/..."
    [attestation]="./test/integration/attestation/..."
    [diskimage]="./test/integration/diskimage"
    [netboot]="./test/integration/netboot"
    [lb]="./test/integration/sdn/"
    [nat64]="./test/integration/nat64"
    [ipsec]="./test/integration/ipsec"
)

# Per-target -run filter, for a target that is one test of a larger
# package. lb is the load balancer datapath test: real OVS, conntrack and
# network namespaces, and nothing from the shared platformd.
declare -A TARGET_RUN=(
    [lb]='^TestGroupLoadBalancer$'
)

# Per-target go test timeout. The default fits a daemon-backed suite; the
# diskimage suite boots an aarch64 guest under TCG emulation, where a first
# boot through firstboot provisioning takes tens of minutes.
declare -A TARGET_TIMEOUTS=(
    [diskimage]="90m"
    [netboot]="40m"
    [nat64]="15m"
    [ipsec]="40m"
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
VBMC_PID=""
CLEANUP_DONE=false

# Build directory — set by build_binaries(), used by start_platformd() for the
# config path. Defaults to the legacy /workspace Docker mount path; overridden
# to the actual source tree when a Go workspace is detected on the host.
PLATFORM_BUILD_DIR="/workspace"

# Platformd startup log — written to /tmp so the script works on the host
# (where /var/log is root-owned) as well as inside the devcontainer.
PLATFORMD_STARTUP_LOG="/tmp/platformd-integration/platformd-startup.log"

# Platformd Unix socket path — /tmp is always writable; /run requires root on
# the host. The path is exported for use by setup_env_vars() and test adapters.
PLATFORMD_SOCK_PATH="/tmp/platformd-integration/platformd.sock"

# OVS bridge name used by the integration test config (sdn.ovs.bridge).
# Platformd reads this from test/integration/config.yaml; the bridge is
# pre-created here so the App.initSDN path finds it immediately and avoids
# the 120-retry wait loop in initOVSBridge.
OVS_INT_BRIDGE="br-platform-int"

# =============================================================================
# Cleanup
# =============================================================================

# restore_workspace_ownership gives back anything the run created in the
# bind-mounted source tree.
#
# The container runs as root, so files it writes into the mount come back owned
# by root. Two costs, both paid by whoever ran the suite: `git status` starts
# reporting "could not open directory ... Permission denied" on every
# invocation, and `git worktree remove` fails on the root-owned path, which
# makes cleaning up a finished branch look like it needs sudo. It does not, but
# each person has to discover that.
#
# The owning uid/gid come from HOST_UID/HOST_GID when the caller passes them,
# and otherwise from the mount point itself: a bind mount preserves the host
# directory's ownership, so stat on the workspace root is the invoking user by
# construction. The fallback matters because not every target passes the
# variables.
#
# Never fails the run. A chown problem is not a test result, and this function
# is called from the EXIT trap, where a non-zero return would be noise.
restore_workspace_ownership() {
    local dir="${PLATFORM_BUILD_DIR:-/workspace}"

    if [ ! -d "$dir" ]; then
        return 0
    fi

    # Only root can hand files to another owner; a rootless container has
    # nothing to fix, because it never created root-owned files.
    if [ "$(id -u)" != "0" ]; then
        return 0
    fi

    local uid="${HOST_UID:-}"
    local gid="${HOST_GID:-}"
    if [ -z "$uid" ] || [ -z "$gid" ]; then
        uid="$(stat -c %u "$dir" 2>/dev/null || echo "")"
        gid="$(stat -c %g "$dir" 2>/dev/null || echo "")"
    fi

    # Nothing to do when the workspace is genuinely owned by root on the host.
    if [ -z "$uid" ] || [ -z "$gid" ] || [ "$uid" = "0" ]; then
        return 0
    fi

    # Touch only what is wrong, so a clean tree costs a walk and no writes.
    local count
    count=$(find "$dir" \( ! -uid "$uid" -o ! -gid "$gid" \) -print 2>/dev/null | wc -l)
    if [ "$count" = "0" ]; then
        return 0
    fi

    echo "Restoring ownership of ${count} path(s) under ${dir} to ${uid}:${gid}..."
    find "$dir" \( ! -uid "$uid" -o ! -gid "$gid" \) -print0 2>/dev/null \
        | xargs -0 --no-run-if-empty chown -h "${uid}:${gid}" 2>/dev/null \
        || echo "WARNING: could not restore ownership under ${dir}"
}

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

    # Stop vBMC
    if [ -n "$VBMC_PID" ] && kill -0 "$VBMC_PID" 2>/dev/null; then
        echo "Stopping vBMC (PID: $VBMC_PID)..."
        kill "$VBMC_PID" 2>/dev/null || true
        wait "$VBMC_PID" 2>/dev/null || true
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

    restore_workspace_ownership

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

    # Verify OVS is operational
    if ovs-vsctl show > /dev/null 2>&1; then
        echo "OVS started successfully"
    else
        echo "WARNING: OVS may not be fully operational"
    fi

    # Create the integration test bridge that config.yaml references under
    # sdn.ovs.bridge. Pre-creating it here means App.initSDN finds the bridge
    # immediately and skips the 120-retry wait loop in initOVSBridge. The
    # add-br command is idempotent — it silently succeeds when the bridge already
    # exists (e.g., on a second run without a full OVS reset).
    if ovs-vsctl show > /dev/null 2>&1; then
        echo "Creating integration test OVS bridge: ${OVS_INT_BRIDGE}"
        ovs-vsctl --may-exist add-br "${OVS_INT_BRIDGE}" || \
            echo "WARNING: failed to create ${OVS_INT_BRIDGE} (overlay tests may degrade)"
        echo "OVS bridge ${OVS_INT_BRIDGE} ready"
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
    PLATFORM_BUILD_DIR="/workspace"
    if [ -f /home/jhahn/sources/go.work ] && [ -d /home/jhahn/sources/go-trusted-platform ]; then
        PLATFORM_BUILD_DIR="/home/jhahn/sources/go-trusted-platform"
        export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
        echo "Detected go workspace; building from $PLATFORM_BUILD_DIR (GOTOOLCHAIN=$GOTOOLCHAIN)"
    fi
    cd "$PLATFORM_BUILD_DIR"

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
    #
    # `go vet`, not `go test -count=0`: -count=0 still runs every TestMain,
    # and test/integration/bmc's TestMain fails hard when INTEGRATION_TEST=1
    # is set before the mTLS trio is (which is exactly this point of the
    # run), so the old step printed a bare FAIL through `tail -5` and
    # "continued anyway". vet type-checks and compiles the test packages
    # under the same tags without executing anything, so a failure here is a
    # real compile error and stops the run with the file:line on screen.
    echo "Pre-compiling test packages..."
    if ! go vet -tags "${BUILD_TAGS}" ./test/integration/...; then
        echo "ERROR: integration test packages do not compile (see above)"
        exit 1
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

# =============================================================================
# vBMC Setup (bmc integration target only)
# =============================================================================

# start_vbmc builds and starts the virtual BMC responder, exports the harness
# environment variables, downloads the vBMC CA cert for daemon trust injection,
# and generates a modified platformd config that trusts the vBMC HTTPS cert.
# Must be called before start_platformd for the bmc target so the daemon starts
# with the correct trust configuration.
#
# Port layout (TCP/UDP can share the same port number):
#   TCP 6230 — vBMC HTTPS/TLS (peerCertificate, GetWebCertificate)
#   UDP 6230 — vBMC IPMI RMCP+ (power/boot/sensors/sysinfo)
#   TCP 8645 — vBMC plain HTTP CA cert endpoint (bootstrap trust)
start_vbmc() {
    if [ "$RUN_TARGET" != "bmc" ]; then
        return 0
    fi

    echo "=== Building and starting vBMC ==="

    # Build the vBMC binary from source.
    if ! go build -buildvcs=false -o /tmp/vbmc "${PLATFORM_BUILD_DIR}/test/integration/bmc/vbmc/"; then
        echo "FATAL: vBMC build failed"
        exit 1
    fi
    echo "vBMC built: /tmp/vbmc"

    # Start vBMC. TCP:6230 serves TLS (HTTPS for GetWebCertificate / Redfish).
    # UDP:6230 serves IPMI RMCP+. OS-level TCP vs UDP separation means both
    # can bind the same port number without conflict.
    VBMC_HTTPS_ADDR=127.0.0.1:6230 \
    VBMC_CA_ADDR=127.0.0.1:8645 \
    VBMC_IPMI_ADDR=127.0.0.1:6230 \
    VBMC_IPMI_USER=ADMIN \
    VBMC_IPMI_PASSWORD=ADMIN \
    VBMC_VENDOR=Dell \
    VBMC_LOG_LEVEL=debug \
    /tmp/vbmc > /tmp/vbmc.log 2>&1 &
    VBMC_PID=$!
    echo "vBMC starting (PID: $VBMC_PID)..."

    # Wait for the plain-HTTP CA endpoint to be ready (TCP 8645).
    # That server starts before the HTTPS and IPMI listeners, so it is the
    # safest readiness proxy. Poll via /dev/tcp — no external tool needed.
    for i in $(seq 1 20); do
        if kill -0 "$VBMC_PID" 2>/dev/null; then
            if (exec 3<>/dev/tcp/127.0.0.1/8645) 2>/dev/null; then
                exec 3>&-
                echo "vBMC CA endpoint ready (attempt $i)"
                break
            fi
        else
            echo "FATAL: vBMC process died on startup"
            cat /tmp/vbmc.log 2>/dev/null || true
            exit 1
        fi
        sleep 1
        if [ "$i" = "20" ]; then
            echo "WARNING: vBMC CA endpoint not ready after 20s — continuing"
            cat /tmp/vbmc.log 2>/dev/null || true
        fi
    done

    # Download the vBMC self-signed CA cert from the plain-HTTP endpoint.
    # This cert is used to configure the daemon's BMC trust resolver so
    # GetWebCertificate can verify the TLS handshake against the vBMC.
    if curl -sf http://127.0.0.1:8645/tls/ca -o /tmp/vbmc-ca.pem 2>/dev/null; then
        echo "vBMC CA cert downloaded to /tmp/vbmc-ca.pem"
    else
        # Fallback: wget (in case curl is absent)
        wget -q -O /tmp/vbmc-ca.pem http://127.0.0.1:8645/tls/ca 2>/dev/null || true
        if [ -s /tmp/vbmc-ca.pem ]; then
            echo "vBMC CA cert downloaded to /tmp/vbmc-ca.pem (via wget)"
        else
            echo "WARNING: could not download vBMC CA cert; GetWebCertificate tests may fail"
        fi
    fi

    # Generate a modified platformd config that adds trust.bmc so the daemon
    # trusts the vBMC's self-signed cert when calling GetWebCertificate.
    # The config is a copy of the standard integration config with a trust
    # section appended. YAML append is safe here because the base config has
    # no trust: key.
    VBMC_PLATFORMD_CONFIG="/tmp/platformd-bmc-config.yaml"
    cp "${PLATFORM_BUILD_DIR}/test/integration/config.yaml" "${VBMC_PLATFORMD_CONFIG}"
    cat >> "${VBMC_PLATFORMD_CONFIG}" << 'TRUSTEOF'

# vBMC trust configuration injected by run-integration-tests.sh for the
# bmc target. Trusts the vBMC self-signed cert via ca-file strategy so
# GetWebCertificate can verify the TLS handshake without InsecureSkipVerify.
trust:
  bmc:
    strategies:
      - ca-file
    ca-file: /tmp/vbmc-ca.pem
TRUSTEOF
    echo "vBMC platformd config written: ${VBMC_PLATFORMD_CONFIG}"

    # Export harness env vars so the test adapters can address the vBMC.
    # The vBMC advertises vendor=Dell so the platform's AutoCertManager vendor
    # probe resolves the standards-based Redfish backend (Supermicro ATEN CGI is
    # the gated X10 fallback, validated on real hardware). Endpoint()/IPMIEndpoint()
    # read the VBMC_DELL_* keys for the matching flavor.
    # VBMC_DELL_ADDR  — HTTPS endpoint (Endpoint() / WaitForReady)
    # VBMC_DELL_IPMI_ADDR — IPMI UDP endpoint (IPMIEndpoint())
    export VBMC_DELL_ADDR=127.0.0.1:6230
    export VBMC_DELL_IPMI_ADDR=127.0.0.1:6230
    export VBMC_IPMI_USER=ADMIN
    export VBMC_IPMI_PASSWORD=ADMIN

    echo "=== vBMC started ==="
}

start_platformd() {
    local config_file="${1:-${PLATFORM_BUILD_DIR}/test/integration/config.yaml}"
    echo "=== Starting platformd (config: ${config_file}) ==="

    # Clean stale data from previous runs to avoid key/cert mismatches
    rm -rf /tmp/platformd-integration
    mkdir -p /tmp/platformd-integration/log \
             /tmp/platformd-integration/ca \
             /tmp/platformd-integration/vtpm \
             /tmp/platformd-integration/quicbaas

    # Start platformd with mTLS authentication, as production runs it.
    #
    # No --skip-iam-validation. That testing-only opt-out stopped doing what
    # this harness wanted from it: since #440 an MCP server without an
    # authorization backend refuses every tool that needs a permission, so it
    # bought MCP nothing -- and it still switched off IAM, which is where the
    # daemon registers platform.v1.TenantService and PlatformIAMService. The
    # tenant suite therefore met "unknown service platform.v1.TenantService"
    # on every transport (#730). With IAM on, the daemon builds the same
    # services, and the same MCP authorization backend, that production does.
    # Log goes to /tmp (writable on both host and devcontainer without root).
    # Socket path is /tmp/platformd-integration/platformd.sock for the same reason.
    /tmp/platformd serve \
        --config "${config_file}" \
        --enable-mtls \
        --socket-path="${PLATFORMD_SOCK_PATH}" \
        --rest-port=8443 \
        --grpc-port=10443 \
        --quic-port=9444 \
        --mcp-port=9445 \
        --raw-so-pin="123456" \
        --raw-pin="123456" \
        --debug \
        > "${PLATFORMD_STARTUP_LOG}" 2>&1 &

    PLATFORMD_PID=$!
    echo "platformd starting (PID: $PLATFORMD_PID)..."

    # Wait for socket to be ready. A daemon that has already exited will never
    # create the socket, so stop waiting the moment the process is gone rather
    # than burning the full 30 seconds on a config error.
    for i in $(seq 1 30); do
        if ! kill -0 "$PLATFORMD_PID" 2>/dev/null; then
            echo "FATAL: platformd exited during startup (after ${i}s)"
            break
        fi
        if [ -S "${PLATFORMD_SOCK_PATH}" ]; then
            echo "platformd started successfully"
            echo "=== platformd startup log (stdout/stderr) ==="
            cat "${PLATFORMD_STARTUP_LOG}" 2>/dev/null || true
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

    echo "FATAL: platformd never created its socket at ${PLATFORMD_SOCK_PATH}"
    echo "platformd logs:"
    tail -50 "${PLATFORMD_STARTUP_LOG}" 2>/dev/null || true
    return 1
}

# abort_no_daemon ends the run when platformd did not come up.
#
# Every daemon-dependent suite dials the endpoints platformd serves. Continuing
# past a dead daemon hands those suites nothing to talk to, and their adapters
# then report a transport that never dialled exactly as they report one that
# passed (issue #523). A bring-up failure is a failed run, not a warning.
abort_no_daemon() {
    echo ""
    echo "============================================="
    echo "  FATAL: platformd did not start"
    echo "============================================="
    echo "Target '${RUN_TARGET}' needs a live platform daemon. Aborting rather"
    echo "than running suites against endpoints nothing is listening on — that"
    echo "produces adapter failures that look like product defects."
    echo ""
    echo "--- platformd startup log (stdout/stderr) ---"
    tail -100 "${PLATFORMD_STARTUP_LOG}" 2>/dev/null || echo "(empty or missing)"
    echo "--- platformd app log ---"
    tail -100 /tmp/platformd-integration/log/trusted-platform.log 2>/dev/null || echo "(empty or missing)"
    exit 1
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
    export PLATFORMD_SOCKET="${PLATFORMD_SOCK_PATH}"
    export PLATFORM_SOCKET_PATH="${PLATFORMD_SOCK_PATH}"
    export PLATFORM_UNIX_SOCKET="${PLATFORMD_SOCK_PATH}"
    export VTPM_SOCKET_PATH="${PLATFORMD_SOCK_PATH}"

    # The tenant suite reads its own TENANT_* namespace
    # (test/integration/tenant/helpers.go). Its defaults are production paths --
    # notably /run/platformd.sock, which this harness never creates -- so
    # without these exports the suite dials somewhere the daemon is not, and
    # reports a socket that does not exist rather than whatever the daemon
    # actually did. Same aliasing the VTPM_* exports above do.
    export TENANT_SOCKET_PATH="${PLATFORMD_SOCK_PATH}"

    # The IAM suite has the same private namespace, with the same production
    # defaults (test/integration/iam/helpers.go).
    export IAM_SOCKET_PATH="${PLATFORMD_SOCK_PATH}"

    # The attestation suite has the same private namespace, with the same
    # production defaults (test/integration/attestation/helpers.go).
    export ATTESTATION_SOCKET_PATH="${PLATFORMD_SOCK_PATH}"

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
    export TENANT_REST_ENDPOINT="https://localhost:8443"
    export IAM_REST_ENDPOINT="https://localhost:8443"
    export ATTESTATION_REST_ENDPOINT="https://localhost:8443"

    # gRPC endpoint (mTLS over TCP)
    export PLATFORM_GRPC_ENDPOINT="localhost:10443"
    export PLATFORMD_GRPC_ENDPOINT="localhost:10443"
    export PLATFORM_GRPC_PORT="10443"
    export VTPM_GRPC_ENDPOINT="localhost:10443"
    export TENANT_GRPC_ENDPOINT="localhost:10443"
    export IAM_GRPC_ENDPOINT="localhost:10443"
    export ATTESTATION_GRPC_ENDPOINT="localhost:10443"

    # QUIC endpoint
    export PLATFORM_QUIC_ENDPOINT="localhost:9444"
    export QUIC_SERVER_ADDR="localhost:9444"
    export VTPM_QUIC_ENDPOINT="localhost:9444"
    export TENANT_QUIC_ENDPOINT="localhost:9444"
    export IAM_QUIC_ENDPOINT="localhost:9444"
    export ATTESTATION_QUIC_ENDPOINT="localhost:9444"

    # MCP endpoint. The daemon adapter uses plain HTTP (see MCP adapter docs in
    # CLAUDE.md); vtpm/sdn-style adapters may use stdio. Ceremony/PIV/LUKS/FIDO2
    # adapters consume the HTTP form, so expose both.
    export PLATFORM_MCP_ENDPOINT="http://localhost:9445"
    export VTPM_MCP_ENDPOINT="http://localhost:9445"
    export TENANT_MCP_ENDPOINT="http://localhost:9445"
    export IAM_MCP_ENDPOINT="http://localhost:9445"
    export ATTESTATION_MCP_ENDPOINT="http://localhost:9445"
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
    echo "  TENANT_SOCKET_PATH=$TENANT_SOCKET_PATH"
    echo "  IAM_SOCKET_PATH=$IAM_SOCKET_PATH"
    echo "  ATTESTATION_SOCKET_PATH=$ATTESTATION_SOCKET_PATH"
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
    export PLATFORM_BARRIER_GATE_CONFIG="${PLATFORM_BUILD_DIR}/test/integration/barrier_gate/config.yaml"
elif [ "$RUN_TARGET" = "bmc" ]; then
    # BMC target: start vBMC first (generates /tmp/vbmc-ca.pem and the
    # modified config that trusts it), then start platformd with that config.
    start_vbmc || echo "WARNING: vBMC setup failed, BMC tests may fail"
    start_platformd "${VBMC_PLATFORMD_CONFIG}" || abort_no_daemon
elif [ "$RUN_TARGET" = "lb" ]; then
    # The load balancer test drives OVS directly and needs no daemon.
    echo "=== lb target: skipping shared platformd ==="
elif [ "$RUN_TARGET" = "diskimage" ]; then
    # The factory-image suite boots the image itself: the guest is a
    # single-node platform and is its own control plane, so no shared
    # platformd is started. The image, its Raspberry Pi sibling and the
    # U-Boot binary come from the host build (make integration-test-diskimage)
    # through DISKIMAGE_IMAGE, DISKIMAGE_RPI_IMAGE and DISKIMAGE_UBOOT; the
    # suite fails, not skips, when they are unset.
    echo "=== diskimage target: skipping shared platformd ==="
    export DISKIMAGE_WORK_DIR="${DISKIMAGE_WORK_DIR:-/tmp/diskimage-integration}"
    rm -rf "${DISKIMAGE_WORK_DIR}"
    mkdir -p "${DISKIMAGE_WORK_DIR}"
    echo "image:     ${DISKIMAGE_IMAGE:-<unset>}"
    echo "rpi image: ${DISKIMAGE_RPI_IMAGE:-<unset>}"
    echo "u-boot:    ${DISKIMAGE_UBOOT:-<unset>}"
    echo "work dir:  ${DISKIMAGE_WORK_DIR}"
elif [ "$RUN_TARGET" = "nat64" ]; then
    # The NAT64 suite boots its own Alpine VM (the translator is a kernel
    # module the devcontainer cannot load into the host) and runs the
    # guest suite there; no shared platformd. Inputs come from the host
    # build (make integration-test-nat64).
    echo "=== nat64 target: skipping shared platformd ==="
    echo "kernel: ${NAT64_VM_KERNEL:-<unset>}"
    echo "rootfs: ${NAT64_VM_ROOTFS:-<unset>}"
    echo "suite:  ${NAT64_VM_SUITE:-<unset>}"
    echo "run:    ${NAT64_VM_RUN:-<unset>}"
elif [ "$RUN_TARGET" = "netboot" ]; then
    # The netboot suite drives `platformctl iso test pxe`, which runs its
    # own PXE server on an isolated bridge and boots the aarch64 guest from
    # U-Boot; no shared platformd. Inputs come from the host build
    # (make integration-test-netboot): the qemu_arm64 U-Boot, the Secure
    # Boot key set it was preseeded with, and the Alpine netboot files.
    echo "=== netboot target: skipping shared platformd ==="
    export NETBOOT_WORK_DIR="${NETBOOT_WORK_DIR:-/tmp/netboot-integration}"
    rm -rf "${NETBOOT_WORK_DIR}"
    mkdir -p "${NETBOOT_WORK_DIR}"
    echo "u-boot:    ${NETBOOT_UBOOT:-<unset>}"
    echo "ipxe:      ${NETBOOT_IPXE:-<unset>}"
    echo "keys:      ${NETBOOT_KEYS_DIR:-<unset>}"
    echo "kernel:    ${NETBOOT_KERNEL:-<unset>}"
    echo "initrd:    ${NETBOOT_INITRD:-<unset>}"
    echo "modloop:   ${NETBOOT_MODLOOP:-<unset>}"
    echo "repo:      ${NETBOOT_ALPINE_REPO:-<unset>}"
    echo "u-boot dir:${NETBOOT_UBOOT_DIR:-<unset>}"
    echo "rpi apks:  ${NETBOOT_RPI_APK_DIR:-<unset>}"
    echo "work dir:  ${NETBOOT_WORK_DIR}"
elif [ "$RUN_TARGET" = "ipsec" ]; then
    # The IPsec suite runs strongSwan peers in their own network namespaces
    # and needs no platform daemon. Its inputs -- per arch the peer root
    # filesystems (which carry the glibc module host), plus the aarch64 VM and
    # the arm64 test binary -- come from the host build (make integration-test-ipsec)
    # through IPSEC_*; the suite fails, not skips, when they are unset.
    echo "=== ipsec target: skipping shared platformd ==="
    export IPSEC_WORK_DIR="${IPSEC_WORK_DIR:-/tmp/ipsec-integration}"
    rm -rf "${IPSEC_WORK_DIR}"
    mkdir -p "${IPSEC_WORK_DIR}"
    for v in IPSEC_ROOTFS_AMD64 IPSEC_ROOTFS_ARM64 \
        IPSEC_VM_KERNEL IPSEC_VM_INITRD IPSEC_TEST_ARM64; do
        echo "${v}: ${!v:-<unset>}"
    done
else
    # platformd is required for every daemon-dependent suite. A failed bring-up
    # ends the run; see abort_no_daemon.
    start_platformd || abort_no_daemon
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
    local timeout="${TARGET_TIMEOUTS[$RUN_TARGET]:-10m}"
    local run_args=()
    if [ -n "${TARGET_RUN[$RUN_TARGET]:-}" ]; then
        run_args=(-run "${TARGET_RUN[$RUN_TARGET]}")
    fi
    if go test -v -tags "${BUILD_TAGS}" -count=1 -parallel 1 -timeout "$timeout" "${run_args[@]}" "$pkg"; then
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
    run_test ./test/integration/provision/...
    run_test ./test/integration/device/...
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
echo "=== platformd startup log (post-test) ==="
cat "${PLATFORMD_STARTUP_LOG}" 2>/dev/null || echo "(empty or missing)"
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

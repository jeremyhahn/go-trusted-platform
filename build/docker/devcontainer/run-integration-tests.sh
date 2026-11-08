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
#                Known targets: the keys of TARGET_PACKAGES below. `all`
#                runs the suites in ALL_TARGETS on one shared platformd; every
#                other key runs one suite. `leg-<n>` runs leg n of
#                INTEGRATION_LEGS the way `all` runs everything, and `legs`
#                prints the legs and exits.
#                If the first argument is not a known target, it is treated
#                as BUILD_TAGS (backward-compatible with the prior 1-arg form).
#                Default: all
#   BUILD_TAGS - Space-separated list of build tags. make passes its derived
#                list; when absent the script derives it the same way
#                (`make -s print-build-tags` plus integration)
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
#   run-integration-tests.sh leg-2
#   run-integration-tests.sh legs
#   run-integration-tests.sh ceremony
#   run-integration-tests.sh luks "integration $(make -s print-build-tags)"
#   run-integration-tests.sh "integration $(make -s print-build-tags)"  # legacy form

set -uo pipefail

# shellcheck source=build/docker/devcontainer/swtpm-provision.sh
source "$(dirname "${BASH_SOURCE[0]}")/swtpm-provision.sh"
# shellcheck source=build/docker/devcontainer/wait-for.sh
source "$(dirname "${BASH_SOURCE[0]}")/wait-for.sh"

# Known target keywords mapped to their Go test package paths, one or more
# separated by spaces. A single-word first argument matching a key here
# selects that target; anything else is treated as the legacy BUILD_TAGS
# argument. sdn names its packages one by one to leave out sdn/stress: the
# stress generators keep every CPU busy for over four minutes, and run beside
# the sdn package (go test runs packages in parallel) they starved
# ovs-vswitchd, platformd and platformctl until the sdn package ran out of
# its 5 minutes (#973). sdn-stress runs them on their own.
declare -A TARGET_PACKAGES=(
    [all]=""
    [bmc]="./test/integration/bmc/..."
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
    [sdn]="./test/integration/sdn/ ./test/integration/sdn/mock_bgp/..."
    [sdn-stress]="./test/integration/sdn/stress/..."
    [proxy]="./test/integration/proxy/..."
    [ntp]="./test/integration/ntp/..."
    [orchestrator]="./test/integration/orchestrator/..."
    [objectstorage]="./test/integration/objectstorage/..."
    [vpn]="./test/integration/vpn/..."
    [tenant]="./test/integration/tenant/..."
    [iam]="./test/integration/iam/..."
    [attestation]="./test/integration/attestation/..."
    [diskimage]="./test/integration/diskimage"
    [netboot]="./test/integration/netboot"
    [lb]="./test/integration/sdn/"
    [nat64]="./test/integration/nat64"
    [ipsec]="./test/integration/ipsec"
    [installer]="./test/integration/installer"
    [root]="./test/integration"
    [testenv-enrollment]="./test/integration"
    [acme]="./test/integration/acme/..."
    [authenticode]="./test/integration/authenticode/..."
    [cli]="./test/integration/cli/..."
    [compute]="./test/integration/compute/..."
    [container]="./test/integration/container/..."
    [daemon]="./test/integration/daemon/..."
    [dns]="./test/integration/dns/..."
    [e2e]="./test/integration/e2e/..."
    [helpers]="./test/integration/helpers/..."
    [ipxe]="./test/integration/ipxe/..."
    [ipxe-dhcp]="./test/integration/ipxe/..."
    [iso]="./test/integration/iso/..."
    [kms]="./test/integration/kms/..."
    [pxe]="./test/integration/pxe/..."
    [registry]="./test/integration/registry/..."
    [secrets]="./test/integration/secrets/..."
    [vtpm]="./test/integration/vtpm/..."
)

# Per-target -run filter, for a target that is one test of a larger
# package. lb is the load balancer datapath test: real OVS, conntrack and
# network namespaces, and nothing from the shared platformd.
# testenv-enrollment is the two-VM ACME enrollment test of the root package;
# it runs its full mode when INTEGRATION_TEST_SERVER_ISO and
# INTEGRATION_TEST_CLIENT_ISO name pre-built ISOs. ipxe-dhcp is the DHCP
# slice of the ipxe suite; it starts a DHCP server for
# TestIPXEDHCPToHTTPChain.
declare -A TARGET_RUN=(
    [lb]='^TestGroupLoadBalancer$'
    [testenv-enrollment]='^TestEnrollmentIntegration$'
    [ipxe-dhcp]='.*DHCP.*'
)

# Per-target environment, NAME=value words passed to `env` before go test.
# IPXE_DHCP_ENABLED=1 makes the ipxe suite's TestMain start its DHCP server
# (loopback, a free high port); the DHCP tests fail without it, so every
# target that selects them sets it.
declare -A TARGET_ENV=(
    [ipxe]='IPXE_DHCP_ENABLED=1'
    [ipxe-dhcp]='IPXE_DHCP_ENABLED=1'
)

# Per-target go test timeout. The default fits a daemon-backed suite; the
# diskimage suite boots an aarch64 guest under TCG emulation, where a first
# boot through firstboot provisioning takes tens of minutes. The root package
# and testenv-enrollment carry the enrollment test's own 30-minute context;
# e2e carries a 45-minute one. sdn gets 15 minutes. Its tests run one at a
# time (-parallel 1), in file order, and passing they take more than 5: on
# #983 (job 267894) the files up to nat_dual_uplink_test.go used all 300 s
# with no test hung, and on main (run 62224) TestSDNMultiProtocol alone ran
# over 2m24s, about 27 s per transport, after 2m36s of earlier files. The
# files from network_provisioning_test.go on (openflow, overlay
# multi-protocol, overlay ND, perf, policy, state transition, tap, the
# tunnel netns suites, zone) were never reached; their estimate, from their
# waits and transport count, is another 5 to 6 minutes, so about 11 in all.
# A hang still fails fast: every ovs-vsctl and ovs-ofctl call has a
# 30-second deadline (test/integration/helpers/boundedexec) and every
# transport adapter a client timeout and a context deadline.
# iso gets 35 minutes: the 20-minute install budget (vmInstallTimeout) plus the
# ISO build and customize steps; a guest stuck at its GRUB menu fails in 2.
# sdn-stress gets the 30 minutes `make stress-sdn` gives the same package.
declare -A TARGET_TIMEOUTS=(
    [sdn]="15m"
    [sdn-stress]="30m"
    [iso]="35m"
    [diskimage]="90m"
    [netboot]="40m"
    [nat64]="15m"
    [ipsec]="40m"
    [root]="40m"
    [testenv-enrollment]="40m"
    [e2e]="50m"
    [compute]="30m"
)

# Targets that run without the shared platformd. Each suite needs no daemon:
# lb drives OVS directly; installer runs a real dnsmasq against a stub
# upstream it starts; the ipxe suites start their own iPXE server on
# 127.0.0.1; testenv-enrollment and e2e boot their own QEMU guests;
# helpers tests the shared harness library in-process. The
# targets that do more than skip the daemon -- cold-start, barrier-gate, bmc
# and the host-built-input suites -- have their own branch in Main.
declare -A TARGET_NO_DAEMON=(
    [lb]=1
    [installer]=1
    [testenv-enrollment]=1
    [e2e]=1
    [helpers]=1
    [ipxe]=1
    [ipxe-dhcp]=1
)

# The suites `all` runs on the one shared platformd: the daemon-free suites
# first, all at once (run_concurrent), then every daemon-backed one, one at a
# time in list order. Left out, each for
# a reason the suite itself sets: cold-start and barrier-gate need the shared
# daemon NOT running; bmc needs platformd started against the vBMC config;
# diskimage, netboot, nat64 and ipsec need inputs only their make targets
# build on the host; lb, testenv-enrollment and ipxe-* are slices of
# packages already listed (sdn, root, ipxe). pxe stays runnable by name but
# is out of the default set: platformd builds its PXE service with no
# backend, so every PXE call answers SERVICE_NOT_CONFIGURED.
# secureboot stays runnable by name but is out of the default set as well: its
# FIPS-kernel test needs a prebuilt kernel, modules and signing key that only
# the caller supplies (FIPS_KERNEL_IMAGE, FIPS_MODULES_TAR,
# FIPS_MODULE_SIGNING_KEY).
# tpm runs last: its Clear case issues TPM2_Clear on the shared daemon's
# swtpm (docs/tpm/security.md), which flushes the owner-hierarchy SRKs that
# seal the daemon's platform-policy key passwords. After it the daemon can
# no longer sign a TLS handshake, so every gRPC, QUIC and MCP dial a later
# suite makes ends in "tls: internal error" (vtpm, #949).
# compute is not in the list: it drives VMs, and the shared daemon serves the
# container orchestrator the container suite needs (one orchestrator serves
# both), so it answers every VM spec "not supported" (#949). `all` ends with
# it, after tpm, on a fresh swtpm and a platformd started on the local QEMU
# provider, as the compute target does.
# sdn-stress needs no daemon but is not in TARGET_NO_DAEMON: the daemon-free
# suites run all at once, and its generators would starve them the way they
# starved sdn. In the daemon-backed list it runs alone, after sdn.
ALL_TARGETS=(
    helpers ipxe installer e2e
    root acme attestation authenticode ca ceremony cli
    container daemon device dns fido2 iam iso kms luks
    ntp objectstorage orchestrator piv provision proxy registry sdn
    sdn-stress secrets tenant vpn vtpm tpm
)

# The legs CI runs as parallel jobs, one container and one shared platformd
# each (#1119): every ALL_TARGETS entry, and compute, is in exactly one leg
# (pkg/arch/integration_legs_test.go). `leg-<n>` runs leg n the way `all` runs
# everything: its daemon-free suites at once, then its daemon-backed ones in
# ALL_TARGETS order, so tpm stays last on its daemon, and compute after them on
# a restarted one. The legs are balanced by CI's measured job times
# (docs/test/integration.md, "Legs"); iso and sdn, the two longest, are apart.
INTEGRATION_LEGS=(
    "acme authenticode ca iso"
    "ceremony cli container sdn"
    "daemon device dns sdn-stress"
    "helpers ipxe installer e2e root attestation fido2 iam kms luks ntp objectstorage orchestrator"
    "piv provision proxy registry secrets tenant vpn vtpm tpm compute"
)

RUN_TARGET="all"
ARG1="${1:-}"
ARG2="${2:-}"

# `legs` prints ALL_TARGETS and then each leg, one per line, and exits before
# anything starts: the partition check and the docs read the legs from here.
if [ "$ARG1" = "legs" ]; then
    echo "all ${ALL_TARGETS[*]} compute"
    for i in "${!INTEGRATION_LEGS[@]}"; do
        echo "leg-$((i + 1)) ${INTEGRATION_LEGS[$i]}"
    done
    exit 0
fi

# The suites this run takes: every ALL_TARGETS entry and compute for `all`,
# one leg's share of them for `leg-<n>`.
SELECTED_TARGETS=("${ALL_TARGETS[@]}")
RUN_COMPUTE=true
RUN_LEG=""
if [[ "$ARG1" =~ ^leg-([0-9]+)$ ]]; then
    RUN_LEG="${BASH_REMATCH[1]}"
    if [ "$RUN_LEG" -lt 1 ] || [ "$RUN_LEG" -gt "${#INTEGRATION_LEGS[@]}" ]; then
        echo "FATAL: no integration leg ${RUN_LEG}; the legs are 1 to ${#INTEGRATION_LEGS[@]}" >&2
        exit 2
    fi
    declare -A LEG_MEMBERS=()
    for target in ${INTEGRATION_LEGS[$((RUN_LEG - 1))]}; do
        LEG_MEMBERS[$target]=1
    done
    SELECTED_TARGETS=()
    for target in "${ALL_TARGETS[@]}"; do
        if [ -n "${LEG_MEMBERS[$target]:-}" ]; then
            SELECTED_TARGETS+=("$target")
        fi
    done
    if [ -z "${LEG_MEMBERS[compute]:-}" ]; then
        RUN_COMPUTE=false
    fi
    ARG1="all"
fi

# derive_build_tags prints the tag set when the caller passed none: the
# Makefile's derived list plus integration, never a hand-written copy of it.
derive_build_tags() {
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
    echo "integration $(make -s -C "${repo_root}" print-build-tags)"
}

if [ -n "$ARG1" ] && [ -n "${TARGET_PACKAGES[$ARG1]+set}" ]; then
    RUN_TARGET="$ARG1"
    BUILD_TAGS="${ARG2:-$(derive_build_tags)}"
elif [ "$ARG1" = "warm" ]; then
    # `warm <build-tags> [<cache-dir>]`: see warm_build_cache.
    RUN_TARGET="warm"
    BUILD_TAGS="${ARG2:-$(derive_build_tags)}"
    WARM_CACHE_DIR="${3:-}"
else
    # Legacy single-arg form: treat ARG1 as BUILD_TAGS.
    BUILD_TAGS="${ARG1:-$(derive_build_tags)}"
fi

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

# Platformd listener ports. Each one is written exactly once: start_platformd()
# passes it to `platformd serve` and setup_env_vars() builds every exported
# endpoint from it, so the daemon and the suites cannot disagree (#502).
# test/integration/helpers/endpoints_test.go asserts that shape.
#
# The ports are ephemeral, chosen by choose_platformd_ports() after
# build_binaries, never fixed numbers: every act_runner job container runs
# with `network: host`, so two Integration jobs on one host share one network
# namespace, and with a fixed 8443 the second job's suites talked to the first
# job's daemon (jobs 301360 and 301211, #997). The OVSDB manager's TCP port
# (OVSDB_TCP_PORT, read by test/integration/sdn through OVSDB_ADDRESS) is
# chosen in the same call for the same reason.
PLATFORMD_REST_PORT=""
PLATFORMD_GRPC_PORT=""
PLATFORMD_QUIC_PORT=""
PLATFORMD_MCP_PORT=""
OVSDB_TCP_PORT=""

# The REST port test/integration/config.yaml carries: its webservice tls-port
# and its WebAuthn relying-party origin. With a webservice configured the
# daemon opens no REST listener of its own (leaveRESTToWebservice,
# pkg/daemon/commands/serve.go), so --rest-port alone does not move REST:
# start_platformd rewrites this port to PLATFORMD_REST_PORT in the copy of the
# config it starts platformd on. pkg/app/integration_config_test.go asserts
# the config carries this port and that the rewrite is made. It names no
# listener, so it sits outside the PLATFORMD_*_PORT set that
# test/integration/helpers/endpoints_test.go keeps free of fixed numbers.
HARNESS_CONFIG_REST_PORT="8443"

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

# chronyd paths (start_chronyd): the Debian chrony package's defaults, which
# pkg/ntp DefaultPaths also renders and drives.
CHRONYD_CONF="/etc/chrony/chrony.conf"
CHRONYD_RUN_DIR="/run/chrony"
CHRONYD_SOCK="${CHRONYD_RUN_DIR}/chronyd.sock"
CHRONYD_PID_FILE="${CHRONYD_RUN_DIR}/chronyd.pid"
# The reference chronyd (start_ntp_reference) that serves the config's
# loopback upstream. Its files sit beside the daemon chronyd's under their
# own names. A config under /run/chrony-reference/ failed with "Could not
# open ... Permission denied" although root wrote it and the container is
# privileged: only a mandatory access control profile refuses root there,
# and the chrony package's AppArmor profile for /usr/sbin/chronyd (loaded on
# the CI host, so it confines chronyd in this container too) allows reads
# of /etc/chrony/ and writes to /run/chrony/ only. That left the daemon's
# chronyd with no source and the ntp component degraded (#949).
NTP_REFERENCE_CONF="/etc/chrony/reference.conf"
NTP_REFERENCE_PID_FILE="${CHRONYD_RUN_DIR}/reference.pid"

# stop_platformd stops platformd and the chronyd pair start_platformd starts
# with it (the daemon's chronyd and its loopback reference).
stop_platformd() {
    if [ -n "$PLATFORMD_PID" ] && kill -0 "$PLATFORMD_PID" 2>/dev/null; then
        echo "Stopping platformd (PID: $PLATFORMD_PID)..."
        kill "$PLATFORMD_PID" 2>/dev/null || true
        wait "$PLATFORMD_PID" 2>/dev/null || true
    fi
    PLATFORMD_PID=""

    if [ -f "${CHRONYD_PID_FILE}" ]; then
        kill "$(cat "${CHRONYD_PID_FILE}")" 2>/dev/null || true
    fi
    if [ -f "${NTP_REFERENCE_PID_FILE}" ]; then
        kill "$(cat "${NTP_REFERENCE_PID_FILE}")" 2>/dev/null || true
    fi
}

cleanup() {
    if [ "$CLEANUP_DONE" = true ]; then
        return
    fi
    CLEANUP_DONE=true

    echo ""
    echo "=== Cleaning up integration test environment ==="

    # Stop platformd and its chronyd
    stop_platformd

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

    # KVM permissions. Without /dev/kvm every QEMU guest runs TCG (pkg/qemu
    # logs "KVM requested but unusable, running TCG"), and the iso install
    # suite does not finish inside its 20-minute bound: say which it is.
    if [ -e /dev/kvm ]; then
        chmod 666 /dev/kvm
        echo "/dev/kvm: available (QEMU guests run KVM)"
    else
        echo "WARNING: /dev/kvm NOT AVAILABLE: QEMU guests run TCG; the iso install suite will exceed its bound"
    fi

    # Load kernel modules (best effort)
    modprobe tun 2>/dev/null || true
    modprobe openvswitch 2>/dev/null || true

    echo "=== Device setup complete ==="
}

# =============================================================================
# OVS Setup
# =============================================================================

# ovsdb_listen_tcp makes the running ovsdb-server listen on the OVSDB_TCP_PORT
# chosen for this run, the port OVSDB_ADDRESS names. It is added at runtime so
# an ovsdb-server that was already running gets it too: the devcontainer
# entrypoint (AUTO_START_OVS=true) starts one listening on 6640 only, and
# without the new remote the SDN suite would dial an unbound port (#997).
# Adding a remote the server already has is a no-op.
ovsdb_listen_tcp() {
    ovs-appctl -t ovsdb-server ovsdb-server/add-remote "ptcp:${OVSDB_TCP_PORT}:127.0.0.1"
}

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
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log \
            /etc/openvswitch/conf.db
        wait_for 10 "ovsdb-server on db.sock" ovs-vsctl --no-wait --timeout=1 show || true
        ovs-vsctl --no-wait init || true
    else
        echo "ovsdb-server already running; reusing it"
    fi
    ovsdb_listen_tcp || return 1
    echo "OVSDB listening on ${OVSDB_ADDRESS}"

    # Start ovs-vswitchd
    if ! pgrep -x ovs-vswitchd > /dev/null; then
        echo "Starting ovs-vswitchd..."
        ovs-vswitchd \
            --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log
        wait_for 10 "ovs-vswitchd control socket" ovs-appctl -t ovs-vswitchd version || true
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
    wait_for 5 "the old swtpm to exit" no_process_matching 'swtpm socket' || exit 1

    rm -rf /tmp/swtpm
    mkdir -p /tmp/swtpm

    # Provision it like shipped hardware, with an EK and an EK certificate.
    # A TPM without an EK sends platformd down its recovery path, which no
    # real node takes, so the run stops here rather than test that.
    if ! provision_swtpm_state /tmp/swtpm; then
        echo "FATAL: the harness swtpm has no EK and EK certificate; platformd cannot run on it"
        exit 1
    fi

    # Start swtpm daemon
    if command -v swtpm > /dev/null 2>&1; then
        swtpm socket --tpm2 \
            --tpmstate dir=/tmp/swtpm \
            --server type=unixio,path=/tmp/swtpm/swtpm.sock \
            --ctrl type=unixio,path=/tmp/swtpm/swtpm.sock.ctrl \
            --flags startup-clear,not-need-init \
            --log level=1,file=/tmp/swtpm/swtpm.log &

        if wait_for 10 "swtpm socket /tmp/swtpm/swtpm.sock" test -S /tmp/swtpm/swtpm.sock; then
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

# choose_platformd_ports sets platformd's four listener ports and the OVSDB
# manager's TCP port from one call to test/integration/helpers/freeport, which
# binds 127.0.0.1:0 for each and holds them all until every one is bound, so
# the five are distinct (#997). It runs from PLATFORM_BUILD_DIR, which
# build_binaries has entered.
choose_platformd_ports() {
    echo "=== Choosing platformd's loopback ports ==="
    if ! go build -buildvcs=false -o /tmp/freeport ./test/integration/helpers/freeport/; then
        echo "FATAL: freeport build failed"
        exit 1
    fi
    local ports
    # REST, gRPC, QUIC (UDP), MCP, OVSDB manager.
    if ! ports="$(/tmp/freeport tcp tcp udp tcp tcp)"; then
        echo "FATAL: freeport could not bind loopback ports"
        exit 1
    fi
    local -a port_list
    mapfile -t port_list <<< "$ports"
    PLATFORMD_REST_PORT="${port_list[0]}"
    PLATFORMD_GRPC_PORT="${port_list[1]}"
    PLATFORMD_QUIC_PORT="${port_list[2]}"
    PLATFORMD_MCP_PORT="${port_list[3]}"
    OVSDB_TCP_PORT="${port_list[4]}"
    export OVSDB_ADDRESS="tcp:127.0.0.1:${OVSDB_TCP_PORT}"
    echo "platformd ports: REST ${PLATFORMD_REST_PORT}, gRPC ${PLATFORMD_GRPC_PORT}, QUIC ${PLATFORMD_QUIC_PORT}/udp, MCP ${PLATFORMD_MCP_PORT}; OVSDB ${OVSDB_TCP_PORT}"
}

build_binaries() {
    echo "=== Building platformd and platformctl ==="

    # Detect a Go workspace setup: when /sources/go.work exists
    # the host has mounted a multi-repo go workspace into the container, and
    # the build must run from the in-workspace path of go-trusted-platform
    # so the `use ./go-trusted-platform` directive resolves. Otherwise fall
    # back to the legacy /workspace cwd. This keeps the legacy single-mount
    # path working unchanged while supporting the barrier-gate / cold-start
    # targets that need local source replaces for go-xkms, go-quicbaas etc.
    PLATFORM_BUILD_DIR="/workspace"
    if [ -f /sources/go.work ] && [ -d /sources/go-trusted-platform ]; then
        PLATFORM_BUILD_DIR="/sources/go-trusted-platform"
        export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
        echo "Detected go workspace; building from $PLATFORM_BUILD_DIR (GOTOOLCHAIN=$GOTOOLCHAIN)"
    fi
    cd "$PLATFORM_BUILD_DIR" || exit 1

    # Pre-download ALL module dependencies before building or testing.
    # This prevents stalls during 'go test' when large deps (libovsdb,
    # coredhcp) are fetched on-demand with a test timeout running.
    echo "Downloading module dependencies..."
    if ! go mod download -x 2>&1 | tail -5; then
        echo "WARNING: go mod download had errors (continuing anyway)"
    fi
    echo "Module dependencies downloaded"

    # No whole-tree pre-compile of ./test/integration/... here: compile_check
    # vets each selected target's package on its own (CA m639).

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

# compile_check type-checks and compiles one target's package under the run's
# tags without executing anything, so a compile error stops that target with
# the file:line on screen. `go vet`, not `go test -count=0`: -count=0 still
# runs every TestMain, and test/integration/bmc's TestMain fails hard before
# the mTLS trio is set. vet compiles the package's dependencies into the same
# build cache the target's `go test` then reuses, and it links nothing, so the
# check adds only the analysis. It replaces a whole-tree vet of
# ./test/integration/... that compiled every package, selected or not, before
# the first test (CA m639).
compile_check() {
    local target="$1"
    local pkg="${TARGET_PACKAGES[$target]}"
    local pkgs=()
    read -r -a pkgs <<< "$pkg"
    if ! go vet -tags "${BUILD_TAGS}" "${pkgs[@]}"; then
        echo "ERROR: $pkg ($target) does not compile (see above)"
        return 1
    fi
}

# =============================================================================
# vBMC Setup (bmc integration target only)
# =============================================================================

# build_gatewayd builds gatewayd into /tmp beside platformd, once per run.
build_gatewayd() {
    if [ -x /tmp/gatewayd ] && [ -n "${GATEWAYD_PATH:-}" ]; then
        return 0
    fi
    if ! go build -buildvcs=false -tags "${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/gatewayd ./cmd/gatewayd/; then
        echo "FATAL: gatewayd build failed"
        exit 1
    fi
    export GATEWAYD_PATH=/tmp/gatewayd
    echo "gatewayd built: ${GATEWAYD_PATH}"
}

# prepare_iso_customize builds what `platformctl iso customize` stages from
# beside platformd and fails without (pkg/iso/customize.go StageMedia):
# platform-initrd, which dracut calls at boot to unlock the root, and gatewayd,
# which the gateway-role single-node template the iso suite bakes in needs
# (pkg/iso/gatewayd.go), and platformctl-static, the media's installer.
# /tmp/platformctl is a CGO build, and customize refuses a dynamically linked
# installer (pkg/iso DynamicBinaryError), so platformctl-static is the same
# CLI built CGO_ENABLED=0 with the tags `make build` adds to the derived set.
# The suite hands it to customize as --platformctl-static-binary from
# PLATFORMCTL_STATIC_PATH: with platformctl named on the command line,
# customize never looks beside it.
# platform-initrd comes from its own make target, which owns its build tags;
# GOFLAGS=-buildvcs=false for the reason build_binaries gives.
prepare_iso_customize() {
    echo "=== Preparing iso customize binaries ==="
    if ! GOFLAGS="${GOFLAGS:+${GOFLAGS} }-buildvcs=false" make -s -C "${PLATFORM_BUILD_DIR}" \
        platform-initrd PLATFORM_INITRD=/tmp/platform-initrd; then
        echo "FATAL: platform-initrd build failed"
        exit 1
    fi
    echo "platform-initrd built: /tmp/platform-initrd"
    echo "Building platformctl-static..."
    if ! CGO_ENABLED=0 go build -buildvcs=false -tags "osusergo netgo ${BUILD_TAGS}" \
        -ldflags "${LDFLAGS}" \
        -o /tmp/platformctl-static ./cmd/platformctl/; then
        echo "FATAL: platformctl-static build failed"
        exit 1
    fi
    export PLATFORMCTL_STATIC_PATH=/tmp/platformctl-static
    echo "platformctl-static built: ${PLATFORMCTL_STATIC_PATH}"
    build_gatewayd
}

# prepare_gatewayd_supervision readies the proxy suite's supervised-process
# tests (#557): it builds gatewayd, which those tests run as a real
# `gatewayd serve` with the `process:` section on, and delegates the memory
# and cpu controllers from the container's cgroup root so gatewayd can give
# each child a leaf with memory.max and cpu.max. cgroup v2 refuses to enable a
# controller for the children of a cgroup that itself holds processes, and the
# container's root holds all of them, so they move to a sibling leaf first —
# the step docker-in-docker takes for the same reason.
prepare_gatewayd_supervision() {
    echo "=== Preparing gatewayd supervision ==="
    build_gatewayd

    local root=/sys/fs/cgroup
    if [ ! -f "${root}/cgroup.controllers" ]; then
        echo "FATAL: ${root} is not a cgroup v2 mount"
        exit 1
    fi
    mkdir -p "${root}/init"
    # A process forked while the list is moved lands back in the root, so
    # the move repeats until enabling the controllers stops failing.
    for _ in 1 2 3 4 5; do
        local pid
        while read -r pid; do
            echo "${pid}" > "${root}/init/cgroup.procs" 2>/dev/null || true
        done < "${root}/cgroup.procs"
        if echo "+memory +cpu" > "${root}/cgroup.subtree_control" 2>/dev/null; then
            echo "cgroup controllers delegated: $(cat "${root}/cgroup.subtree_control")"
            return 0
        fi
    done
    echo "FATAL: cannot enable memory and cpu in ${root}/cgroup.subtree_control"
    exit 1
}

# warm_build_cache compiles into the build cache everything a run compiles:
# platformd, platformctl, gatewayd, platform-initrd, and the vet check and test
# binary of every package of every ALL_TARGETS key and compute. It starts
# nothing. The integration-legs stage of the devcontainer Dockerfile runs it
# (#1119), so a leg links and runs against a warm /gocache instead of compiling
# the tree from an empty one.
#
# With WARM_CACHE_DIR (the stage's BuildKit cache mount, which keeps the last
# build's cache) the build runs against that directory, so it compiles only what
# changed since, and then copies what it used into the image's GOCACHE. The go
# command refreshes the mtime of an entry it uses once that mtime is an hour old
# (cmd/go/internal/cache), so every entry is first dated two hours back: after
# the build, the entries newer than a stamp are exactly this build's. The rest
# are deleted, which keeps the mount to one build's cache.
#
# A test package that does not compile is reported and left out: its suite
# fails with the file:line in the leg that runs it, as it would without the warm
# cache.
warm_build_cache() {
    local image_cache="${GOCACHE:-$(go env GOCACHE)}"
    local stamp=""
    if [ -n "${WARM_CACHE_DIR}" ]; then
        mkdir -p "${WARM_CACHE_DIR}"
        find "${WARM_CACHE_DIR}" -mindepth 2 -type f -exec touch -m -d '2 hours ago' {} +
        stamp="$(mktemp)"
        export GOCACHE="${WARM_CACHE_DIR}"
    fi
    echo "=== Warming the build cache (${GOCACHE}) ==="
    build_binaries
    prepare_iso_customize

    local test_bin target pkg pkgs=()
    test_bin="$(mktemp -u)"
    for target in "${ALL_TARGETS[@]}" compute; do
        compile_check "$target" || continue
        read -r -a pkgs <<< "${TARGET_PACKAGES[$target]}"
        for pkg in $(go list -tags "${BUILD_TAGS}" "${pkgs[@]}"); do
            if ! go test -c -tags "${BUILD_TAGS}" -o "${test_bin}" "$pkg"; then
                echo "WARNING: the test binary of $pkg ($target) does not compile"
            fi
            rm -f "${test_bin}"
        done
    done
    # The binaries are rebuilt from the cache by each run, into its own /tmp.
    rm -f /tmp/platformd /tmp/platformctl /tmp/gatewayd /tmp/platform-initrd

    if [ -n "${stamp}" ]; then
        find "${WARM_CACHE_DIR}" -mindepth 2 -type f ! -newer "${stamp}" -delete
        rm -f "${stamp}"
        mkdir -p "${image_cache}"
        cp -a "${WARM_CACHE_DIR}/." "${image_cache}/"
    fi
    echo "=== Build cache warm: $(du -sh "${image_cache}" | cut -f1) in ${image_cache} ==="
}

# target_selected reports whether this run takes the suite KEY: every key for
# `all`, the leg's own for `leg-<n>`.
target_selected() {
    local key="$1" target
    for target in "${SELECTED_TARGETS[@]}"; do
        if [ "$target" = "$key" ]; then
            return 0
        fi
    done
    return 1
}

# prepare_compute_config writes the platformd config for the compute target:
# the standard integration config with the local QEMU provider selected. With
# no compute: section the daemon serves the container orchestrator, and the
# compute suite drives VMs (#260).
prepare_compute_config() {
    COMPUTE_PLATFORMD_CONFIG="/tmp/platformd-compute-config.yaml"
    cp "${PLATFORM_BUILD_DIR}/test/integration/config.yaml" "${COMPUTE_PLATFORMD_CONFIG}"
    cat >> "${COMPUTE_PLATFORMD_CONFIG}" << 'COMPUTEEOF'

# Compute configuration injected by run-integration-tests.sh for the
# compute target: the VM orchestrator the compute suite drives.
compute:
  provider: local-qemu
COMPUTEEOF
    echo "Compute platformd config: ${COMPUTE_PLATFORMD_CONFIG}"
}

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
        echo "WARNING: could not download vBMC CA cert; GetWebCertificate tests may fail"
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

# chronyd backs the ntp suite. platformd renders /etc/chrony/chrony.conf from
# the config's ntp: section and enables chronyd through OpenRC, which this
# Debian container does not have, so the runner starts chronyd on the rendered
# file. -x keeps chronyd off the system clock: the container shares the CI
# host's kernel clock, and no suite may move it. A config without an ntp:
# section renders nothing, and chronyd is not started. The paths are set
# beside cleanup(), which stops chronyd.
#
# The daemon's chronyd consumes 127.0.0.1, which start_ntp_reference serves,
# and the runner waits for it to synchronise: an unsynchronised clock is the
# documented degraded `ntp` health component (docs/health/api.md), and a
# degraded component makes the aggregate health answer of every transport
# not-healthy, so every suite that asserts a healthy platform would fail.
start_chronyd() {
    if [ ! -f "${CHRONYD_CONF}" ]; then
        echo "WARNING: platformd rendered no ${CHRONYD_CONF}; the ntp suite has no chronyd"
        return 0
    fi
    # chronyd drops to _chrony and opens its command socket only when the
    # socket's directory is owned by that user and closed to others; a
    # root-owned 0755 directory leaves it running with "Disabled command
    # socket", so every chronyc poll platformd makes fails (#949).
    # The reference chronyd keeps its pid file in the same directory.
    install -d -m 0750 -o _chrony -g _chrony "${CHRONYD_RUN_DIR}"
    start_ntp_reference
    echo "=== Starting chronyd (config: ${CHRONYD_CONF}, clock control off) ==="
    if ! chronyd -x -f "${CHRONYD_CONF}"; then
        echo "WARNING: chronyd failed to start; the ntp suite has no chronyd"
        return 0
    fi
    for _ in $(seq 1 10); do
        if chronyc -n -h "${CHRONYD_SOCK}" tracking >/dev/null 2>&1; then
            echo "chronyd ready"
            # waitsync <tries> <max-correction> <max-skew> <interval>: 30
            # one-second polls; 0 leaves the correction and skew unbounded.
            if chronyc -n -h "${CHRONYD_SOCK}" waitsync 30 0 0 1 >/dev/null 2>&1; then
                echo "chronyd synchronised to the reference"
            else
                echo "WARNING: chronyd did not synchronise to the reference within 30s; the ntp health component stays degraded"
            fi
            return 0
        fi
        sleep 1
    done
    echo "WARNING: chronyd never answered on ${CHRONYD_SOCK}"
}

# start_ntp_reference runs a second chronyd as the harness's time source: it
# serves its own clock on 127.0.0.1:123 as a local stratum-8 reference, which
# the daemon's consume-mode chronyd (rendered with `port 0`, so the two never
# share a port) synchronises to. Like the daemon's chronyd it runs with -x and
# never moves the clock the container shares with the CI host, and it has no
# command socket (`cmdport 0`, `bindcmdaddress /`), so every chronyc call the
# daemon makes still reaches the daemon's chronyd.
start_ntp_reference() {
    echo "=== Starting the reference chronyd on 127.0.0.1:123 ==="
    cat > "${NTP_REFERENCE_CONF}" << NTPREFEOF
bindaddress 127.0.0.1
allow 127.0.0.1
local stratum 8
cmdport 0
bindcmdaddress /
pidfile ${NTP_REFERENCE_PID_FILE}
NTPREFEOF
    # Without the reference the daemon's chronyd never synchronises, the ntp
    # component stays degraded and every transport's aggregate health is
    # not-healthy, so the suites would fail far from this cause.
    if ! chronyd -x -f "${NTP_REFERENCE_CONF}"; then
        echo "FATAL: the reference chronyd failed to start on ${NTP_REFERENCE_CONF}; the daemon's chronyd has no source"
        exit 1
    fi
}

# platformd_socket_or_gone ends start_platformd's wait: the daemon has created
# its socket, or it has exited and never will.
platformd_socket_or_gone() {
    [ -S "${PLATFORMD_SOCK_PATH}" ] || process_gone "${PLATFORMD_PID}"
}

# platformd_tls_ready reports whether platformd has written the admin client
# bundle and the CA bundle the suites dial with.
platformd_tls_ready() {
    [ -f /tmp/platformd-integration/tls/client-bundle.pem ] &&
        [ -f /tmp/platformd-integration/tls/ca-bundle.crt ]
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

    # Serve REST on this job's port: the webservice tls-port and the
    # relying-party origin move from HARNESS_CONFIG_REST_PORT to
    # PLATFORMD_REST_PORT, where PLATFORM_REST_ENDPOINT points.
    local run_config="/tmp/platformd-integration/platformd-config.yaml"
    sed -e "s|^\( *tls-port: \)${HARNESS_CONFIG_REST_PORT}\$|\1${PLATFORMD_REST_PORT}|" \
        -e "s|https://localhost:${HARNESS_CONFIG_REST_PORT}\$|https://localhost:${PLATFORMD_REST_PORT}|" \
        "${config_file}" > "${run_config}" || return 1
    if grep -Eq "(tls-port: |https://localhost:)${HARNESS_CONFIG_REST_PORT}\$" "${run_config}"; then
        echo "FATAL: ${run_config} still serves REST on ${HARNESS_CONFIG_REST_PORT}, not ${PLATFORMD_REST_PORT}"
        return 1
    fi
    config_file="${run_config}"
    echo "platformd REST webservice on ${PLATFORMD_REST_PORT} (config: ${config_file})"

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
        --rest-port="${PLATFORMD_REST_PORT}" \
        --grpc-port="${PLATFORMD_GRPC_PORT}" \
        --quic-port="${PLATFORMD_QUIC_PORT}" \
        --mcp-port="${PLATFORMD_MCP_PORT}" \
        --raw-so-pin="123456" \
        --raw-pin="123456" \
        --debug \
        > "${PLATFORMD_STARTUP_LOG}" 2>&1 &

    PLATFORMD_PID=$!
    echo "platformd starting (PID: $PLATFORMD_PID)..."

    # Wait for the socket. A daemon that has already exited never creates it,
    # so the wait ends the moment the process is gone rather than burning the
    # full 30 seconds on a config error.
    if ! wait_for 30 "platformd socket ${PLATFORMD_SOCK_PATH}" platformd_socket_or_gone; then
        echo "FATAL: platformd never created its socket at ${PLATFORMD_SOCK_PATH}"
        report_platformd_startup_failure
        return 1
    fi
    if [ -S "${PLATFORMD_SOCK_PATH}" ]; then
        echo "platformd started successfully"
        echo "=== platformd startup log (stdout/stderr) ==="
        cat "${PLATFORMD_STARTUP_LOG}" 2>/dev/null || true
        echo "=== platformd app log ==="
        cat /tmp/platformd-integration/log/trusted-platform.log 2>/dev/null || true

        # Wait for mTLS certificates to be generated. They land in
        # <platform-dir>/tls (platform-dir comes from the config). The
        # admin client-bundle.pem exists only because /tmp/platformd is
        # built with the integration tag
        # (pkg/daemon/commands/harness_admin_bundle_integration.go); a
        # production platformd mints no admin key, and this harness has
        # no barrier, so it has no /init step to take one from.
        if wait_for 10 "platformd mTLS certificates" platformd_tls_ready; then
            echo "mTLS certificates ready"
        fi

        start_chronyd

        echo "=== platformd ready ==="
        return 0
    fi

    echo "FATAL: platformd exited during startup"
    report_platformd_startup_failure
    return 1
}

# report_platformd_startup_failure says why platformd is not serving: its exit
# status (or that it is still running), appended to PLATFORMD_STARTUP_LOG so
# the log carries it, then the tail of the startup and application logs. A
# missing log is reported as missing rather than printed as nothing.
report_platformd_startup_failure() {
    local app_log="/tmp/platformd-integration/log/trusted-platform.log"
    local status_line
    if kill -0 "$PLATFORMD_PID" 2>/dev/null; then
        status_line="platformd (PID ${PLATFORMD_PID}) is still running without its socket"
    else
        wait "$PLATFORMD_PID"
        status_line="platformd (PID ${PLATFORMD_PID}) exited with status $?"
    fi
    echo "${status_line}"
    echo "${status_line}" >> "${PLATFORMD_STARTUP_LOG}"

    echo "=== platformd startup log (${PLATFORMD_STARTUP_LOG}, stdout/stderr) ==="
    tail -50 "${PLATFORMD_STARTUP_LOG}"
    echo "=== platformd app log (${app_log}) ==="
    if [ -f "${app_log}" ]; then
        tail -50 "${app_log}"
    else
        echo "(missing)"
    fi
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
    # The same issuer's bundle for the fixed non-system tenant
    # harness-tenant, written before client-bundle.pem: the suites that
    # assert what a tenant outside the system tenant is refused use it.
    export PLATFORM_TENANT_CLIENT_CERT="/tmp/platformd-integration/tls/tenant-client-bundle.pem"
    export PLATFORM_TENANT_CLIENT_KEY="/tmp/platformd-integration/tls/tenant-client-bundle.pem"

    # Admin console session (docs/test/integration.md, "Admin session"). The
    # REST adapters claim the platform console once with the firstboot admin
    # bundle the embedded quicbaas server writes under <quicbaas data-dir>/admin
    # (quicbaas.data-dir in test/integration/config.yaml), and cache the
    # bearer the claim mints in the session file for every later test binary.
    export PLATFORM_ADMIN_BUNDLE_DIR="/tmp/platformd-integration/quicbaas/admin"
    export PLATFORM_ADMIN_SESSION_FILE="/tmp/platformd-integration/admin-session.json"

    # REST endpoint (mTLS requires HTTPS)
    export PLATFORM_API_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"
    export PLATFORM_REST_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"
    export VTPM_REST_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"
    export TENANT_REST_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"
    export IAM_REST_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"
    export ATTESTATION_REST_ENDPOINT="https://localhost:${PLATFORMD_REST_PORT}"

    # gRPC endpoint (mTLS over TCP)
    export PLATFORM_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"
    export PLATFORMD_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"
    export VTPM_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"
    export TENANT_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"
    export IAM_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"
    export ATTESTATION_GRPC_ENDPOINT="localhost:${PLATFORMD_GRPC_PORT}"

    # QUIC endpoint
    export PLATFORM_QUIC_ENDPOINT="localhost:${PLATFORMD_QUIC_PORT}"
    export QUIC_SERVER_ADDR="localhost:${PLATFORMD_QUIC_PORT}"
    export VTPM_QUIC_ENDPOINT="localhost:${PLATFORMD_QUIC_PORT}"
    export TENANT_QUIC_ENDPOINT="localhost:${PLATFORMD_QUIC_PORT}"
    export IAM_QUIC_ENDPOINT="localhost:${PLATFORMD_QUIC_PORT}"
    export ATTESTATION_QUIC_ENDPOINT="localhost:${PLATFORMD_QUIC_PORT}"

    # MCP endpoint. The daemon serves MCP over TLS 1.3 only, with the same
    # certificate and client-CA pool as REST and gRPC (#844); there is no
    # plaintext listener. Adapters dial https:// with the mTLS trio below.
    export PLATFORM_MCP_ENDPOINT="https://localhost:${PLATFORMD_MCP_PORT}"
    export VTPM_MCP_ENDPOINT="https://localhost:${PLATFORMD_MCP_PORT}"
    export TENANT_MCP_ENDPOINT="https://localhost:${PLATFORMD_MCP_PORT}"
    export IAM_MCP_ENDPOINT="https://localhost:${PLATFORMD_MCP_PORT}"
    export ATTESTATION_MCP_ENDPOINT="https://localhost:${PLATFORMD_MCP_PORT}"
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
    echo "  PLATFORM_TENANT_CLIENT_CERT=$PLATFORM_TENANT_CLIENT_CERT (bundle)"
    echo "  PLATFORM_TENANT_CLIENT_KEY=$PLATFORM_TENANT_CLIENT_KEY (bundle)"
    echo "  PLATFORM_ADMIN_BUNDLE_DIR=$PLATFORM_ADMIN_BUNDLE_DIR"
    echo "  PLATFORM_ADMIN_SESSION_FILE=$PLATFORM_ADMIN_SESSION_FILE"
    echo "  PLATFORM_REST_ENDPOINT=$PLATFORM_REST_ENDPOINT"
    echo "  PLATFORM_GRPC_ENDPOINT=$PLATFORM_GRPC_ENDPOINT"
    echo "  PLATFORM_QUIC_ENDPOINT=$PLATFORM_QUIC_ENDPOINT"
    echo "  PLATFORM_MCP_ENDPOINT=$PLATFORM_MCP_ENDPOINT"
    echo "  PLATFORMCTL_PATH=$PLATFORMCTL_PATH"
    echo "  TENANT_SOCKET_PATH=$TENANT_SOCKET_PATH"
    echo "  IAM_SOCKET_PATH=$IAM_SOCKET_PATH"
    echo "  ATTESTATION_SOCKET_PATH=$ATTESTATION_SOCKET_PATH"
    echo "=== Environment variables set ==="
}

# =============================================================================
# Main
# =============================================================================

echo "============================================="
echo "  go-trusted-platform Integration Tests"
echo "============================================="
echo "Target:     ${RUN_TARGET}${RUN_LEG:+ (leg ${RUN_LEG} of ${#INTEGRATION_LEGS[@]})}"
echo "Build tags: ${BUILD_TAGS}"
echo ""

# `warm` only compiles; there is nothing for the EXIT trap to stop.
if [ "$RUN_TARGET" = "warm" ]; then
    trap - EXIT
    warm_build_cache
    exit 0
fi

# Phase 1: Build binaries
build_binaries
choose_platformd_ports

# A single target's package is checked here, before OVS, swtpm or platformd
# start, so a compile error ends the run with the file:line first. `all`
# checks each package just before its own run (run_test).
if [ "$RUN_TARGET" != "all" ] && ! compile_check "$RUN_TARGET"; then
    exit 1
fi

# Phase 2: Setup infrastructure
setup_devices

# OVS backs the SDN, lb, compute and e2e suites.
start_ovs || echo "WARNING: OVS setup failed; the suites that need OVS have none"

# swtpm backs the shared platformd's TPM and every vTPM suite. The vtpm
# target has nothing to test without it, so there a failure ends the run.
if ! start_swtpm; then
    if [ "$RUN_TARGET" = "vtpm" ]; then
        echo "FATAL: swtpm did not start; the vtpm target cannot run without it"
        exit 1
    fi
    echo "WARNING: swtpm setup failed; the suites that need a TPM have none"
fi

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
elif [ "$RUN_TARGET" = "compute" ]; then
    # Compute target: platformd with the local QEMU provider, so the VM
    # tools and RPCs reach a VM orchestrator.
    prepare_compute_config
    start_platformd "${COMPUTE_PLATFORMD_CONFIG}" || abort_no_daemon
elif [ "$RUN_TARGET" = "proxy" ]; then
    # The proxy suite talks to the shared platformd and also runs gatewayd
    # itself, supervised, to kill its children under load.
    start_platformd || abort_no_daemon
    prepare_gatewayd_supervision
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
elif [ -n "${TARGET_NO_DAEMON[$RUN_TARGET]:-}" ]; then
    echo "=== ${RUN_TARGET} target: skipping shared platformd ==="
else
    # platformd is required for every daemon-dependent suite. A failed bring-up
    # ends the run; see abort_no_daemon.
    start_platformd || abort_no_daemon
    # The proxy suite's supervised-process tests need gatewayd built and the
    # cgroup controllers delegated; a leg without proxy skips both.
    if [ "$RUN_TARGET" = "all" ] && target_selected proxy; then
        prepare_gatewayd_supervision
    fi
fi

# The iso suite's customize step stages platform-initrd and gatewayd from
# beside /tmp/platformd, and platformctl-static from PLATFORMCTL_STATIC_PATH.
if [ "$RUN_TARGET" = "iso" ] || { [ "$RUN_TARGET" = "all" ] && target_selected iso; }; then
    prepare_iso_customize
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

# Per-target outcome (PASS or FAIL) and the targets in run order, for the
# summary.
declare -A TARGET_RESULT=()
RAN_TARGETS=()

# record_result notes one target's outcome for the summary and folds a
# failure into RESULT.
record_result() {
    local target="$1"
    local rc="$2"
    RAN_TARGETS+=("$target")
    if [ "$rc" -eq 0 ]; then
        TARGET_RESULT[$target]="PASS"
    else
        TARGET_RESULT[$target]="FAIL"
        RESULT=1
    fi
}

# run_test runs one target's package with that target's timeout and -run
# filter, and returns non-zero when it fails.
run_test() {
    local target="$1"
    local pkg="${TARGET_PACKAGES[$target]}"
    echo ""
    echo "--- Testing $pkg ($target) ---"
    # A single target was checked before any daemon started (Main).
    if [ "$RUN_TARGET" = "all" ] && ! compile_check "$target"; then
        echo "--- FAIL: $pkg ---"
        return 1
    fi
    local timeout="${TARGET_TIMEOUTS[$target]:-10m}"
    local pkgs=()
    read -r -a pkgs <<< "$pkg"
    local run_args=()
    if [ -n "${TARGET_RUN[$target]:-}" ]; then
        run_args=(-run "${TARGET_RUN[$target]}")
    fi
    local target_env=()
    if [ -n "${TARGET_ENV[$target]:-}" ]; then
        read -r -a target_env <<< "${TARGET_ENV[$target]}"
    fi
    if env "${target_env[@]}" go test -v -tags "${BUILD_TAGS}" -count=1 -parallel 1 -timeout "$timeout" "${run_args[@]}" "${pkgs[@]}"; then
        echo "--- PASS: $pkg ---"
    else
        echo "--- FAIL: $pkg ---"
        return 1
    fi
}

# run_concurrent runs the given targets at once. Each writes its own log,
# printed whole as soon as that target ends, so the suites' -v output never
# interleaves.
run_concurrent() {
    local log_dir="/tmp/integration-logs"
    rm -rf "$log_dir"
    mkdir -p "$log_dir"
    local -A pid_target=()
    local target pid rc
    for target in "$@"; do
        run_test "$target" > "$log_dir/$target.log" 2>&1 &
        pid_target[$!]="$target"
    done
    while [ "${#pid_target[@]}" -gt 0 ]; do
        pid=""
        wait -n -p pid "${!pid_target[@]}"
        rc=$?
        # wait returns without a pid only when a signal interrupts it.
        if [ -z "$pid" ]; then
            continue
        fi
        target="${pid_target[$pid]}"
        unset "pid_target[$pid]"
        echo ""
        echo "=== ${target} log ==="
        cat "$log_dir/$target.log"
        record_result "$target" "$rc"
    done
}

if [ "$RUN_TARGET" = "all" ]; then
    # The daemon-free suites of SELECTED_TARGETS (TARGET_NO_DAEMON) run at
    # once: none shares state with another or with platformd. Every
    # daemon-backed suite then runs alone on the one shared platformd, in list
    # order.
    DAEMON_FREE_TARGETS=()
    DAEMON_TARGETS=()
    for target in "${SELECTED_TARGETS[@]}"; do
        if [ -n "${TARGET_NO_DAEMON[$target]:-}" ]; then
            DAEMON_FREE_TARGETS+=("$target")
        else
            DAEMON_TARGETS+=("$target")
        fi
    done
    if [ "${#DAEMON_FREE_TARGETS[@]}" -gt 0 ]; then
        run_concurrent "${DAEMON_FREE_TARGETS[@]}"
    fi
    for target in "${DAEMON_TARGETS[@]}"; do
        run_test "$target"
        record_result "$target" "$?"
    done

    # compute last, on its own daemon: a fresh swtpm (tpm cleared the shared
    # one) and platformd on the local QEMU provider.
    if [ "$RUN_COMPUTE" = true ]; then
        echo "=== compute: restarting platformd on the local QEMU provider ==="
        stop_platformd
        if start_swtpm && prepare_compute_config && start_platformd "${COMPUTE_PLATFORMD_CONFIG}"; then
            run_test compute
            record_result compute "$?"
        else
            echo "--- FAIL: compute (platformd did not start on the local QEMU provider) ---"
            record_result compute 1
        fi
    fi
else
    run_test "$RUN_TARGET"
    record_result "$RUN_TARGET" "$?"
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
for target in "${RAN_TARGETS[@]}"; do
    echo "  ${TARGET_RESULT[$target]}  ${target}"
done
echo "---------------------------------------------"
if [ $RESULT -eq 0 ]; then
    echo "  ALL INTEGRATION TESTS PASSED"
else
    echo "  SOME INTEGRATION TESTS FAILED"
fi
echo "============================================="

exit $RESULT

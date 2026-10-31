#!/bin/bash
# SDN/OVS Integration Tests
#
# This script sets up Open vSwitch and runs comprehensive SDN integration tests
# covering network provisioning flows, policy engine integration, and OpenFlow rules.
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh setup     # Just setup OVS
#   ./run-tests.sh teardown  # Just teardown OVS
#   ./run-tests.sh provision # Run network provisioning tests
#   ./run-tests.sh policy    # Run policy engine tests
#   ./run-tests.sh bridge    # Run bridge/port management tests
#   ./run-tests.sh flows     # Run OpenFlow rules tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Bounded readiness polls (#964): the image copy, else the repository's.
WAIT_FOR_SH=/usr/local/lib/devcontainer/wait-for.sh
if [ ! -f "$WAIT_FOR_SH" ]; then
    WAIT_FOR_SH="$SCRIPT_DIR/../../../build/docker/devcontainer/wait-for.sh"
fi
# shellcheck source=build/docker/devcontainer/wait-for.sh
source "$WAIT_FOR_SH"

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
# OVS Setup/Teardown
# =============================================================================

setup_ovs() {
    log_info "Setting up Open vSwitch environment..."

    # Create necessary directories
    sudo mkdir -p /var/run/openvswitch
    sudo mkdir -p /var/log/openvswitch
    sudo mkdir -p /etc/openvswitch

    # Initialize OVS database if it doesn't exist
    if [ ! -f /etc/openvswitch/conf.db ]; then
        log_info "Initializing OVSDB..."
        sudo ovsdb-tool create /etc/openvswitch/conf.db \
            /usr/share/openvswitch/vswitch.ovsschema
    fi

    # Check if ovsdb-server is already running
    if pgrep ovsdb-server > /dev/null; then
        log_warn "ovsdb-server is already running"
    else
        # Start ovsdb-server
        log_info "Starting ovsdb-server..."
        sudo ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
            --remote=ptcp:6640:127.0.0.1 \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log

        wait_for 10 "ovsdb-server on db.sock" sudo ovs-vsctl --no-wait --timeout=1 show || return 1
    fi

    # Initialize OVS
    log_info "Initializing Open vSwitch..."
    sudo ovs-vsctl --no-wait init || true

    # Check if ovs-vswitchd is already running
    if pgrep ovs-vswitchd > /dev/null; then
        log_warn "ovs-vswitchd is already running"
    else
        # Start ovs-vswitchd
        log_info "Starting ovs-vswitchd..."
        sudo ovs-vswitchd --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log

        wait_for 10 "ovs-vswitchd control socket" sudo ovs-appctl -t ovs-vswitchd version || return 1
    fi

    # Verify OVS is running
    log_info "Verifying OVS status..."
    if sudo ovs-vsctl show > /dev/null 2>&1; then
        log_info "OVS is running successfully"
    else
        log_error "OVS failed to start properly"
        return 1
    fi

    # Enable kernel module for tap devices
    sudo modprobe tun 2>/dev/null || log_warn "TUN module already loaded or not available"

    # Set permissions for test access
    sudo chmod 666 /var/run/openvswitch/db.sock

    log_info "OVS setup complete!"
}

teardown_ovs() {
    log_info "Stopping Open vSwitch..."

    # Clean up any test bridges
    log_info "Cleaning up test bridges..."
    for bridge in $(sudo ovs-vsctl list-br 2>/dev/null | grep -E '^br-'); do
        log_info "Deleting bridge: $bridge"
        sudo ovs-vsctl del-br "$bridge" 2>/dev/null || true
    done

    # Stop processes. A process still running at its deadline is left to the
    # force kill below.
    local pid
    if [ -f /var/run/openvswitch/ovs-vswitchd.pid ]; then
        pid=$(cat /var/run/openvswitch/ovs-vswitchd.pid)
        sudo kill "$pid" 2>/dev/null || true
        wait_for 5 "ovs-vswitchd (PID $pid) to exit after SIGTERM" process_gone "$pid" || true
    fi

    if [ -f /var/run/openvswitch/ovsdb-server.pid ]; then
        pid=$(cat /var/run/openvswitch/ovsdb-server.pid)
        sudo kill "$pid" 2>/dev/null || true
        wait_for 5 "ovsdb-server (PID $pid) to exit after SIGTERM" process_gone "$pid" || true
    fi

    # Force kill if still running
    sudo pkill -9 ovs-vswitchd 2>/dev/null || true
    sudo pkill -9 ovsdb-server 2>/dev/null || true

    log_info "OVS stopped"
}

cleanup_test_bridges() {
    log_info "Cleaning up any leftover test bridges..."
    for bridge in $(sudo ovs-vsctl list-br 2>/dev/null | grep -E 'test|prov|prod'); do
        log_info "Deleting test bridge: $bridge"
        sudo ovs-vsctl del-br "$bridge" 2>/dev/null || true
    done
}

# =============================================================================
# Test Functions
# =============================================================================

run_all_tests() {
    log_info "=== Running All SDN Integration Tests ==="
    setup_ovs

    cleanup_test_bridges

    # SDN tests have their own go.mod
    cd "$SCRIPT_DIR"

    # Ensure dependencies are resolved
    log_info "Resolving dependencies..."
    go mod tidy

    log_info "Running all integration tests..."
    go test -v -timeout 15m ./... -count=1

    cleanup_test_bridges

    log_info "=== All SDN Integration Tests Complete ==="
}

run_network_provisioning_tests() {
    log_info "=== Running Network Provisioning Tests ==="
    setup_ovs
    cleanup_test_bridges

    cd "$SCRIPT_DIR"
    log_info "Running network provisioning flow tests..."
    go test -v -timeout 10m -run TestNetworkProvisioning ./... -count=1

    cleanup_test_bridges
    log_info "=== Network Provisioning Tests Complete ==="
}

run_policy_engine_tests() {
    log_info "=== Running Policy Engine Integration Tests ==="
    setup_ovs
    cleanup_test_bridges

    cd "$SCRIPT_DIR"
    log_info "Running policy engine tests..."
    go test -v -timeout 10m -run TestPolicyEngine ./... -count=1

    cleanup_test_bridges
    log_info "=== Policy Engine Tests Complete ==="
}

run_bridge_port_tests() {
    log_info "=== Running Bridge and Port Management Tests ==="
    setup_ovs
    cleanup_test_bridges

    cd "$SCRIPT_DIR"
    log_info "Running bridge and port tests..."
    go test -v -timeout 10m -run "TestBridge|TestPort|TestVLAN" ./... -count=1

    cleanup_test_bridges
    log_info "=== Bridge and Port Tests Complete ==="
}

run_openflow_tests() {
    log_info "=== Running OpenFlow Rules Tests ==="
    setup_ovs
    cleanup_test_bridges

    cd "$SCRIPT_DIR"
    log_info "Running OpenFlow rules tests..."
    go test -v -timeout 10m -run "TestOpenFlow|TestACL|TestFlow" ./... -count=1

    cleanup_test_bridges
    log_info "=== OpenFlow Tests Complete ==="
}

show_test_status() {
    log_info "=== Test Environment Status ==="

    if pgrep ovsdb-server > /dev/null; then
        log_info "ovsdb-server: ${GREEN}Running${NC}"
    else
        log_warn "ovsdb-server: ${RED}Not Running${NC}"
    fi

    if pgrep ovs-vswitchd > /dev/null; then
        log_info "ovs-vswitchd: ${GREEN}Running${NC}"
    else
        log_warn "ovs-vswitchd: ${RED}Not Running${NC}"
    fi

    if sudo ovs-vsctl show > /dev/null 2>&1; then
        log_info "OVS Bridges:"
        sudo ovs-vsctl list-br 2>/dev/null | while read bridge; do
            log_info "  - $bridge"
        done
    fi
}

show_help() {
    cat << EOF
SDN/OVS Integration Test Runner

Usage: $0 [command]

Commands:
    test, run        Run all integration tests (default)
    setup            Setup OVS environment
    teardown         Teardown OVS environment
    cleanup          Clean up test bridges only
    status           Show test environment status

    # Individual test suites:
    provision        Run network provisioning tests
    policy           Run policy engine tests
    bridge           Run bridge/port management tests
    flows            Run OpenFlow rules tests

    help             Show this help message

Examples:
    $0                      # Run all tests
    $0 setup                # Setup OVS
    $0 provision            # Run provisioning tests only
    $0 cleanup && $0 test   # Clean and run all tests

EOF
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    setup)
        setup_ovs
        show_test_status
        ;;
    teardown)
        teardown_ovs
        ;;
    cleanup)
        cleanup_test_bridges
        ;;
    status)
        show_test_status
        ;;
    test|run|all)
        run_all_tests
        ;;
    provision)
        run_network_provisioning_tests
        ;;
    policy)
        run_policy_engine_tests
        ;;
    bridge|port)
        run_bridge_port_tests
        ;;
    flows|openflow|acl)
        run_openflow_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac

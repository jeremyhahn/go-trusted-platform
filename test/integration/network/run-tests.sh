#!/bin/bash
# Network Authentication Integration Tests
#
# This script runs the network authentication service integration tests.
# Tests verify the NetworkAuthService works correctly with mocked or real OVS/OPA.
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh setup     # Just setup environment
#   ./run-tests.sh teardown  # Just teardown environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Bounded readiness polls (wait_for, process_gone): the image installs the
# helper; outside the image it comes from the repository.
if [ -f /usr/local/lib/devcontainer/wait-for.sh ]; then
    # shellcheck source=build/docker/devcontainer/wait-for.sh
    source /usr/local/lib/devcontainer/wait-for.sh
else
    # shellcheck source=build/docker/devcontainer/wait-for.sh
    source "$$WORKSPACE_DIR/build/docker/devcontainer/wait-for.sh"
fi

# The tags come from the Makefile, never a hand-written list.
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$WORKSPACE_DIR" print-build-tags)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# =============================================================================
# Environment Setup/Teardown
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

        wait_for 10 "ovsdb-server on db.sock" sudo ovs-vsctl --no-wait --timeout=1 show ||
            log_warn "ovsdb-server is not answering on db.sock"
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

        wait_for 10 "ovs-vswitchd control socket" sudo ovs-appctl -t ovs-vswitchd version ||
            log_warn "ovs-vswitchd is not answering on its control socket"
    fi

    # Verify OVS is running
    log_info "Verifying OVS status..."
    if sudo ovs-vsctl show > /dev/null 2>&1; then
        log_info "OVS is running successfully"
    else
        log_warn "OVS not available - some tests will be skipped"
    fi

    # Enable kernel module for tap devices
    sudo modprobe tun 2>/dev/null || log_warn "TUN module already loaded or not available"

    # Set permissions for test access
    if [ -e /var/run/openvswitch/db.sock ]; then
        sudo chmod 666 /var/run/openvswitch/db.sock
    fi

    log_info "OVS setup complete!"
}

teardown_ovs() {
    log_info "Cleaning up OVS test bridges..."

    # Clean up any test bridges
    for bridge in $(sudo ovs-vsctl list-br 2>/dev/null | grep -E 'test|network-auth'); do
        log_info "Deleting bridge: $bridge"
        sudo ovs-vsctl del-br "$bridge" 2>/dev/null || true
    done

    log_info "OVS cleanup complete"
}

setup_environment() {
    log_step "Setting up test environment..."
    setup_ovs
    log_info "Environment setup complete!"
}

teardown_environment() {
    log_step "Tearing down test environment..."
    teardown_ovs
    log_info "Environment teardown complete!"
}

# =============================================================================
# Test Functions
# =============================================================================

run_tests() {
    log_step "=== Running Network Authentication Integration Tests ==="
    setup_environment

    cd "$WORKSPACE_DIR"

    log_info "Running network authentication integration tests..."
    go test -v -timeout 10m \
        -tags "$BUILD_TAGS" \
        ./test/integration/network/... \
        -count=1

    teardown_environment

    log_step "=== Network Authentication Tests Complete ==="
}

show_test_status() {
    log_step "=== Test Environment Status ==="

    echo ""
    echo "OVS Status:"
    if pgrep ovsdb-server > /dev/null; then
        echo -e "  ovsdb-server: ${GREEN}Running${NC}"
    else
        echo -e "  ovsdb-server: ${RED}Not Running${NC}"
    fi

    if pgrep ovs-vswitchd > /dev/null; then
        echo -e "  ovs-vswitchd: ${GREEN}Running${NC}"
    else
        echo -e "  ovs-vswitchd: ${RED}Not Running${NC}"
    fi

    echo ""
    if sudo ovs-vsctl show > /dev/null 2>&1; then
        echo "OVS Bridges:"
        bridges=$(sudo ovs-vsctl list-br 2>/dev/null)
        if [ -z "$bridges" ]; then
            echo "  (none)"
        else
            echo "$bridges" | while read bridge; do
                echo "  - $bridge"
            done
        fi
    fi
}

show_help() {
    cat << EOF
Network Authentication Integration Test Runner

Usage: $0 [command]

Commands:
    test, run, all   Run all integration tests (default)
    setup            Setup test environment (OVS)
    teardown         Teardown test environment
    status           Show test environment status
    help             Show this help message

Examples:
    $0                      # Run all tests
    $0 setup                # Setup environment
    $0 teardown             # Teardown environment

EOF
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    setup)
        setup_environment
        show_test_status
        ;;
    teardown)
        teardown_environment
        ;;
    status)
        show_test_status
        ;;
    test|run|all)
        run_tests
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

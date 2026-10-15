#!/bin/bash
# Compute/QEMU Integration Tests
#
# This script sets up the environment and runs comprehensive compute integration tests
# covering QEMU VM lifecycle, OVS network attachment, and swtpm TPM emulation.
#
# Usage:
#   ./run-tests.sh           # Run all tests (default)
#   ./run-tests.sh setup     # Just setup environment
#   ./run-tests.sh teardown  # Just teardown environment
#   ./run-tests.sh lifecycle # Run VM lifecycle tests
#   ./run-tests.sh network   # Run network attachment tests
#   ./run-tests.sh e2e       # Run end-to-end tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# The tags come from the Makefile, never a hand-written list.
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$REPO_ROOT" print-build-tags)}"

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
        log_info "Starting ovsdb-server..."
        sudo ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
            --remote=ptcp:6640:127.0.0.1 \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log

        sleep 2
    fi

    # Initialize OVS
    log_info "Initializing Open vSwitch..."
    sudo ovs-vsctl --no-wait init || true

    # Check if ovs-vswitchd is already running
    if pgrep ovs-vswitchd > /dev/null; then
        log_warn "ovs-vswitchd is already running"
    else
        log_info "Starting ovs-vswitchd..."
        sudo ovs-vswitchd --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log

        sleep 2
    fi

    # Verify OVS is running
    log_info "Verifying OVS status..."
    if sudo ovs-vsctl show > /dev/null 2>&1; then
        log_info "OVS is running successfully"
    else
        log_error "OVS failed to start properly"
        return 1
    fi

    # Enable kernel modules
    sudo modprobe tun 2>/dev/null || log_warn "TUN module already loaded or not available"
    sudo modprobe kvm 2>/dev/null || log_warn "KVM module not available (will use software emulation)"
    sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || log_warn "KVM CPU module not available"

    # Set permissions
    sudo chmod 666 /var/run/openvswitch/db.sock

    log_info "OVS setup complete!"
}

setup_qemu() {
    log_info "Verifying QEMU environment..."

    # Check QEMU binary
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        log_error "qemu-system-x86_64 not found"
        return 1
    fi

    # Check OVMF firmware
    if [ ! -f /usr/share/OVMF/OVMF_CODE_4M.fd ]; then
        log_error "OVMF firmware not found at /usr/share/OVMF/OVMF_CODE_4M.fd"
        return 1
    fi

    # Check KVM availability
    if [ -e /dev/kvm ]; then
        log_info "KVM acceleration available"
        sudo chmod 666 /dev/kvm 2>/dev/null || true
    else
        log_warn "KVM not available, QEMU will use software emulation (slower)"
    fi

    log_info "QEMU environment verified!"
}

setup_swtpm() {
    log_info "Verifying swtpm environment..."

    # Check swtpm binary
    if ! command -v swtpm &> /dev/null; then
        log_error "swtpm not found"
        return 1
    fi

    # Create swtpm directories
    sudo mkdir -p /var/lib/swtpm
    sudo chmod 755 /var/lib/swtpm

    log_info "swtpm environment verified!"
}

setup_all() {
    log_info "=== Setting up Compute Integration Test Environment ==="
    setup_ovs
    setup_qemu
    setup_swtpm
    log_info "=== Environment setup complete ==="
}

teardown_ovs() {
    log_info "Stopping Open vSwitch..."

    # Clean up test bridges
    log_info "Cleaning up test bridges..."
    for bridge in $(sudo ovs-vsctl list-br 2>/dev/null | grep -E 'test|compute'); do
        log_info "Deleting bridge: $bridge"
        sudo ovs-vsctl del-br "$bridge" 2>/dev/null || true
    done

    # Stop processes
    if [ -f /var/run/openvswitch/ovs-vswitchd.pid ]; then
        sudo kill "$(cat /var/run/openvswitch/ovs-vswitchd.pid)" 2>/dev/null || true
        sleep 1
    fi

    if [ -f /var/run/openvswitch/ovsdb-server.pid ]; then
        sudo kill "$(cat /var/run/openvswitch/ovsdb-server.pid)" 2>/dev/null || true
        sleep 1
    fi

    log_info "OVS stopped"
}

cleanup_test_resources() {
    log_info "Cleaning up test resources..."

    # Kill any stray QEMU processes from tests
    sudo pkill -f "qemu-system.*test-" 2>/dev/null || true

    # Kill any stray swtpm processes from tests
    sudo pkill -f "swtpm.*test-" 2>/dev/null || true

    # Clean up test bridges
    for bridge in $(sudo ovs-vsctl list-br 2>/dev/null | grep -E 'test-compute'); do
        log_info "Deleting test bridge: $bridge"
        sudo ovs-vsctl --if-exists del-br "$bridge" 2>/dev/null || true
    done

    log_info "Test resources cleaned up"
}

# =============================================================================
# Test Functions
# =============================================================================

run_all_tests() {
    log_info "=== Running All Compute Integration Tests ==="
    setup_all

    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running all integration tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 30m ./... -count=1

    cleanup_test_resources

    log_info "=== All Compute Integration Tests Complete ==="
}

run_lifecycle_tests() {
    log_info "=== Running VM Lifecycle Tests ==="
    setup_all
    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running VM lifecycle tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 20m -run "TestQEMUOrchestratorStart|TestQEMUOrchestratorStop" ./... -count=1

    cleanup_test_resources
    log_info "=== VM Lifecycle Tests Complete ==="
}

run_network_tests() {
    log_info "=== Running Network Attachment Tests ==="
    setup_all
    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running network attachment tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 20m -run "TestQEMUOrchestratorAttachNetwork|TestQEMUOrchestratorDetachNetwork" ./... -count=1

    cleanup_test_resources
    log_info "=== Network Attachment Tests Complete ==="
}

run_e2e_tests() {
    log_info "=== Running End-to-End Tests ==="
    setup_all
    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running end-to-end tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 30m -run "TestQEMUOrchestratorE2ELifecycle" ./... -count=1

    cleanup_test_resources
    log_info "=== End-to-End Tests Complete ==="
}

run_tpm_tests() {
    log_info "=== Running TPM Tests ==="
    setup_all
    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running TPM tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 20m -run "TestQEMUOrchestratorWithTPM" ./... -count=1

    cleanup_test_resources
    log_info "=== TPM Tests Complete ==="
}

run_multi_instance_tests() {
    log_info "=== Running Multiple Instance Tests ==="
    setup_all
    cleanup_test_resources

    cd "$SCRIPT_DIR"

    log_info "Running multiple instance tests..."
    go test -v -tags "$BUILD_TAGS" -timeout 30m -run "TestQEMUOrchestratorMultipleInstances" ./... -count=1

    cleanup_test_resources
    log_info "=== Multiple Instance Tests Complete ==="
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

    if [ -e /dev/kvm ]; then
        log_info "KVM: ${GREEN}Available${NC}"
    else
        log_warn "KVM: ${YELLOW}Not Available${NC}"
    fi

    if command -v qemu-system-x86_64 &> /dev/null; then
        log_info "QEMU: ${GREEN}Available${NC}"
    else
        log_warn "QEMU: ${RED}Not Available${NC}"
    fi

    if command -v swtpm &> /dev/null; then
        log_info "swtpm: ${GREEN}Available${NC}"
    else
        log_warn "swtpm: ${RED}Not Available${NC}"
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
Compute/QEMU Integration Test Runner

Usage: $0 [command]

Commands:
    test, run        Run all integration tests (default)
    setup            Setup test environment
    teardown         Teardown test environment
    cleanup          Clean up test resources only
    status           Show test environment status

    # Individual test suites:
    lifecycle        Run VM lifecycle tests (Start/Stop)
    network          Run network attachment tests
    e2e              Run end-to-end lifecycle tests
    tpm              Run TPM-enabled VM tests
    multi            Run multiple instance tests

    help             Show this help message

Examples:
    $0                      # Run all tests
    $0 setup                # Setup environment
    $0 e2e                  # Run E2E tests only
    $0 cleanup && $0 test   # Clean and run all tests

EOF
}

# =============================================================================
# Main
# =============================================================================

case "${1:-test}" in
    setup)
        setup_all
        show_test_status
        ;;
    teardown)
        teardown_ovs
        ;;
    cleanup)
        cleanup_test_resources
        ;;
    status)
        show_test_status
        ;;
    test|run|all)
        run_all_tests
        ;;
    lifecycle)
        run_lifecycle_tests
        ;;
    network)
        run_network_tests
        ;;
    e2e)
        run_e2e_tests
        ;;
    tpm)
        run_tpm_tests
        ;;
    multi)
        run_multi_instance_tests
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

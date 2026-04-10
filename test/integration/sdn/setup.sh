#!/bin/bash
set -e

# =============================================================================
# SDN Integration Test Environment Setup Script
# =============================================================================
#
# This script handles setup for SDN integration tests, including:
# - OVS (Open vSwitch) initialization
# - Topology management for multi-node tests
# - Environment verification
#
# Usage:
#   ./setup.sh                    - Initialize OVS and run default command
#   ./setup.sh topology start     - Start a test topology
#   ./setup.sh topology stop      - Stop a running topology
#   ./setup.sh topology list      - List available topologies
#   ./setup.sh topology status    - Show topology status
#   ./setup.sh topology destroy   - Destroy a topology
#   ./setup.sh verify             - Verify environment is ready
#
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPOLOGY_WORK_DIR="${TOPOLOGY_WORK_DIR:-/tmp/sdn-topology}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-sdn-test}"

# =============================================================================
# Color output helpers
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# OVS Setup Functions
# =============================================================================

setup_ovs() {
    info "Starting OVS integration test environment..."

    # Create necessary directories
    mkdir -p /var/run/openvswitch
    mkdir -p /var/log/openvswitch
    mkdir -p /etc/openvswitch

    # Initialize OVS database if it doesn't exist
    if [ ! -f /etc/openvswitch/conf.db ]; then
        info "Initializing OVSDB..."
        ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
    fi

    # Check if ovsdb-server is already running
    if ! pgrep -x ovsdb-server > /dev/null; then
        info "Starting ovsdb-server..."
        ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
            --remote=ptcp:6640:127.0.0.1 \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log
        sleep 2
    else
        info "ovsdb-server already running"
    fi

    # Initialize OVS
    info "Initializing Open vSwitch..."
    ovs-vsctl --no-wait init || true

    # Check if ovs-vswitchd is already running
    if ! pgrep -x ovs-vswitchd > /dev/null; then
        info "Starting ovs-vswitchd..."
        ovs-vswitchd --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log
        sleep 2
    else
        info "ovs-vswitchd already running"
    fi

    # Verify OVS is running
    info "Verifying OVS status..."
    ovs-vsctl show

    # Enable kernel module for tap devices
    modprobe tun 2>/dev/null || warn "TUN module already loaded or not available"

    success "OVS setup complete!"
    info "OVSDB listening on tcp:127.0.0.1:6640"
}

# =============================================================================
# Topology Management Functions
# =============================================================================

# Available preset topologies
PRESET_TOPOLOGIES=("single-node" "three-node" "multi-gateway" "bgp-transit" "edge" "minimal")

topology_usage() {
    cat << EOF
Usage: $0 topology <command> [options]

Commands:
    start <preset>      Start a preset topology
    stop <name>         Stop a running topology
    destroy <name>      Destroy a topology and cleanup resources
    status [name]       Show status of topology (all if no name given)
    list                List available preset topologies
    logs <name> [node]  Capture logs from topology

Preset Topologies:
    single-node     Single gateway with all modes
    three-node      Gateway + 2 compute nodes with VXLAN
    multi-gateway   2 gateways + 3 compute for HA testing
    bgp-transit     Gateway + mock ISP for transit testing
    edge            Edge gateway with IoT clients
    minimal         Minimal topology for smoke tests

Examples:
    $0 topology list
    $0 topology start three-node
    $0 topology status three-node
    $0 topology logs three-node gateway-1
    $0 topology destroy three-node

Environment Variables:
    TOPOLOGY_WORK_DIR   Working directory for topology files (default: /tmp/sdn-topology)
    COMPOSE_PROJECT     Docker Compose project name prefix (default: sdn-test)
EOF
}

topology_list() {
    info "Available preset topologies:"
    for preset in "${PRESET_TOPOLOGIES[@]}"; do
        case "$preset" in
            single-node)
                echo "  - single-node     : Single gateway with all modes"
                ;;
            three-node)
                echo "  - three-node      : Gateway + 2 compute nodes with VXLAN"
                ;;
            multi-gateway)
                echo "  - multi-gateway   : 2 gateways + 3 compute for HA testing"
                ;;
            bgp-transit)
                echo "  - bgp-transit     : Gateway + mock ISP for transit testing"
                ;;
            edge)
                echo "  - edge            : Edge gateway with IoT clients"
                ;;
            minimal)
                echo "  - minimal         : Minimal topology for smoke tests"
                ;;
        esac
    done
}

topology_start() {
    local preset="$1"

    if [ -z "$preset" ]; then
        error "Preset name required"
        topology_usage
        exit 1
    fi

    # Check if preset exists
    local valid=false
    for p in "${PRESET_TOPOLOGIES[@]}"; do
        if [ "$p" = "$preset" ]; then
            valid=true
            break
        fi
    done

    if [ "$valid" = false ]; then
        error "Unknown preset: $preset"
        topology_list
        exit 1
    fi

    local work_dir="${TOPOLOGY_WORK_DIR}/${preset}"
    local compose_file="${work_dir}/docker-compose.yml"

    info "Starting topology: $preset"

    # Create working directory
    mkdir -p "$work_dir"

    # Generate Docker Compose file if it doesn't exist
    if [ ! -f "$compose_file" ]; then
        info "Generating docker-compose file for $preset..."
        generate_compose_file "$preset" "$compose_file"
    fi

    # Start with Docker Compose
    info "Starting containers..."
    docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${preset}" up -d

    success "Topology $preset started"

    # Show status
    topology_status "$preset"
}

topology_stop() {
    local name="$1"

    if [ -z "$name" ]; then
        error "Topology name required"
        exit 1
    fi

    local work_dir="${TOPOLOGY_WORK_DIR}/${name}"
    local compose_file="${work_dir}/docker-compose.yml"

    if [ ! -f "$compose_file" ]; then
        error "Topology $name not found"
        exit 1
    fi

    info "Stopping topology: $name"
    docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${name}" stop

    success "Topology $name stopped"
}

topology_destroy() {
    local name="$1"

    if [ -z "$name" ]; then
        error "Topology name required"
        exit 1
    fi

    local work_dir="${TOPOLOGY_WORK_DIR}/${name}"
    local compose_file="${work_dir}/docker-compose.yml"

    if [ ! -f "$compose_file" ]; then
        warn "Topology $name not found, cleaning up anyway..."
    fi

    info "Destroying topology: $name"

    if [ -f "$compose_file" ]; then
        docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${name}" down -v --remove-orphans || true
    fi

    # Remove working directory
    rm -rf "$work_dir"

    success "Topology $name destroyed"
}

topology_status() {
    local name="$1"

    if [ -z "$name" ]; then
        # Show all topologies
        info "Running topologies:"
        for dir in "${TOPOLOGY_WORK_DIR}"/*/; do
            if [ -d "$dir" ]; then
                local topo_name=$(basename "$dir")
                local compose_file="${dir}/docker-compose.yml"
                if [ -f "$compose_file" ]; then
                    echo ""
                    info "Topology: $topo_name"
                    docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${topo_name}" ps 2>/dev/null || warn "Failed to get status"
                fi
            fi
        done
    else
        local work_dir="${TOPOLOGY_WORK_DIR}/${name}"
        local compose_file="${work_dir}/docker-compose.yml"

        if [ ! -f "$compose_file" ]; then
            error "Topology $name not found"
            exit 1
        fi

        info "Status for topology: $name"
        docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${name}" ps
    fi
}

topology_logs() {
    local name="$1"
    local node="$2"

    if [ -z "$name" ]; then
        error "Topology name required"
        exit 1
    fi

    local work_dir="${TOPOLOGY_WORK_DIR}/${name}"
    local compose_file="${work_dir}/docker-compose.yml"

    if [ ! -f "$compose_file" ]; then
        error "Topology $name not found"
        exit 1
    fi

    if [ -z "$node" ]; then
        info "Capturing logs for all nodes in topology: $name"
        docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${name}" logs
    else
        info "Capturing logs for node: $node in topology: $name"
        docker-compose -f "$compose_file" -p "${COMPOSE_PROJECT}-${name}" logs "$node"
    fi
}

# Generate a Docker Compose file for a preset
generate_compose_file() {
    local preset="$1"
    local output_file="$2"

    cat > "$output_file" << 'COMPOSE_HEADER'
# Auto-generated Docker Compose file for SDN test topology
version: '3.8'

COMPOSE_HEADER

    case "$preset" in
        minimal)
            generate_minimal_compose >> "$output_file"
            ;;
        single-node)
            generate_single_node_compose >> "$output_file"
            ;;
        three-node)
            generate_three_node_compose >> "$output_file"
            ;;
        multi-gateway)
            generate_multi_gateway_compose >> "$output_file"
            ;;
        bgp-transit)
            generate_bgp_transit_compose >> "$output_file"
            ;;
        edge)
            generate_edge_compose >> "$output_file"
            ;;
        *)
            error "Unknown preset: $preset"
            exit 1
            ;;
    esac
}

generate_minimal_compose() {
    cat << 'EOF'
networks:
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1

services:
  gateway-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-minimal-gateway-1
    hostname: gateway-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    networks:
      - underlay
    environment:
      - NODE_TYPE=gateway
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3
EOF
}

generate_single_node_compose() {
    cat << 'EOF'
networks:
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1
  management:
    driver: bridge
    ipam:
      config:
        - subnet: 10.200.0.0/24
          gateway: 10.200.0.1

services:
  gateway-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-single-gateway-1
    hostname: gateway-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay,edge,transit
      - BGP_ASN=64512
      - EVPN_ENABLED=true
    volumes:
      - /var/run/openvswitch:/var/run/openvswitch
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3
EOF
}

generate_three_node_compose() {
    cat << 'EOF'
networks:
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1
  management:
    driver: bridge
    ipam:
      config:
        - subnet: 10.200.0.0/24
          gateway: 10.200.0.1

services:
  gateway-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-three-gateway-1
    hostname: gateway-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay
      - BGP_ASN=64512
      - EVPN_ENABLED=true
      - NODE_IP=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-three-compute-1
    hostname: compute-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.11
      - GATEWAY_IP=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-2:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-three-compute-2
    hostname: compute-2
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.12
      - GATEWAY_IP=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3
EOF
}

generate_multi_gateway_compose() {
    cat << 'EOF'
networks:
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1
  management:
    driver: bridge
    ipam:
      config:
        - subnet: 10.200.0.0/24
          gateway: 10.200.0.1

services:
  gateway-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-multi-gateway-1
    hostname: gateway-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay
      - BGP_ASN=64512
      - EVPN_ENABLED=true
      - NODE_IP=10.100.0.10
      - HA_ROLE=primary
      - PEER_GATEWAY=10.100.0.11
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  gateway-2:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-multi-gateway-2
    hostname: gateway-2
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay
      - BGP_ASN=64512
      - EVPN_ENABLED=true
      - NODE_IP=10.100.0.11
      - HA_ROLE=secondary
      - PEER_GATEWAY=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-multi-compute-1
    hostname: compute-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
      - gateway-2
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.20
      - GATEWAY_IPS=10.100.0.10,10.100.0.11
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-2:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-multi-compute-2
    hostname: compute-2
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
      - gateway-2
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.21
      - GATEWAY_IPS=10.100.0.10,10.100.0.11
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-3:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-multi-compute-3
    hostname: compute-3
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
      - gateway-2
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.22
      - GATEWAY_IPS=10.100.0.10,10.100.0.11
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3
EOF
}

generate_bgp_transit_compose() {
    cat << 'EOF'
networks:
  transit:
    driver: bridge
    ipam:
      config:
        - subnet: 10.254.0.0/24
          gateway: 10.254.0.1
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1
  management:
    driver: bridge
    ipam:
      config:
        - subnet: 10.200.0.0/24
          gateway: 10.200.0.1

services:
  gateway-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-bgp-gateway-1
    hostname: gateway-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - transit
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay,transit
      - BGP_ASN=64512
      - EVPN_ENABLED=true
      - TRANSIT_ENABLED=true
      - NODE_IP=10.100.0.10
      - TRANSIT_IP=10.254.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  mock-isp:
    image: frrouting/frr:latest
    container_name: sdn-bgp-mock-isp
    hostname: mock-isp
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    networks:
      - transit
      - management
    environment:
      - BGP_ASN=64496
      - ROUTER_ID=10.254.0.100
      - NEIGHBOR_IP=10.254.0.10
      - NEIGHBOR_ASN=64512
    healthcheck:
      test: ["CMD", "vtysh", "-c", "show bgp summary"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  compute-1:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-bgp-compute-1
    hostname: compute-1
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    depends_on:
      - gateway-1
    environment:
      - NODE_TYPE=compute
      - VTEP_IP=10.100.0.11
      - GATEWAY_IP=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3
EOF
}

generate_edge_compose() {
    cat << 'EOF'
networks:
  edge-lan:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
  underlay:
    driver: bridge
    ipam:
      config:
        - subnet: 10.100.0.0/24
          gateway: 10.100.0.1
  management:
    driver: bridge
    ipam:
      config:
        - subnet: 10.200.0.0/24
          gateway: 10.200.0.1

services:
  gateway-core:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-edge-gateway-core
    hostname: gateway-core
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - underlay
      - management
    environment:
      - NODE_TYPE=gateway
      - GATEWAY_MODES=overlay
      - BGP_ASN=64512
      - EVPN_ENABLED=true
      - NODE_IP=10.100.0.10
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  gateway-edge:
    image: go-trusted-platform-sdn:latest
    container_name: sdn-edge-gateway-edge
    hostname: gateway-edge
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - NET_RAW
    networks:
      - edge-lan
      - underlay
      - management
    depends_on:
      - gateway-core
    environment:
      - NODE_TYPE=edge
      - GATEWAY_MODES=edge
      - EDGE_LAN_IP=192.168.1.1
      - CORE_GATEWAY=10.100.0.10
      - DHCP_ENABLED=true
    healthcheck:
      test: ["CMD", "ovs-vsctl", "show"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 3

  client-1:
    image: alpine:latest
    container_name: sdn-edge-client-1
    hostname: client-1
    networks:
      - edge-lan
    depends_on:
      - gateway-edge
    environment:
      - DHCP_CLIENT=true
    command: sleep infinity

  client-2:
    image: alpine:latest
    container_name: sdn-edge-client-2
    hostname: client-2
    networks:
      - edge-lan
    depends_on:
      - gateway-edge
    environment:
      - DHCP_CLIENT=true
    command: sleep infinity
EOF
}

# =============================================================================
# Environment Verification
# =============================================================================

verify_environment() {
    info "Verifying SDN test environment..."

    local errors=0

    # Check Docker
    if command -v docker &> /dev/null; then
        success "Docker is installed"
    else
        error "Docker is not installed"
        ((errors++))
    fi

    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        success "Docker Compose is installed"
    else
        error "Docker Compose is not installed"
        ((errors++))
    fi

    # Check OVS tools
    if command -v ovs-vsctl &> /dev/null; then
        success "OVS tools are installed"
    else
        warn "OVS tools not found (may be in container)"
    fi

    # Check if OVS is running (if installed)
    if command -v ovs-vsctl &> /dev/null; then
        if ovs-vsctl show &> /dev/null; then
            success "OVS is running"
        else
            warn "OVS is installed but not running"
        fi
    fi

    # Check for required kernel modules
    if lsmod | grep -q "^tun "; then
        success "TUN kernel module is loaded"
    else
        warn "TUN kernel module not loaded (may need: modprobe tun)"
    fi

    if lsmod | grep -q "^vxlan "; then
        success "VXLAN kernel module is loaded"
    else
        warn "VXLAN kernel module not loaded (may need: modprobe vxlan)"
    fi

    # Check working directory
    if [ -d "$TOPOLOGY_WORK_DIR" ]; then
        success "Topology work directory exists: $TOPOLOGY_WORK_DIR"
    else
        info "Topology work directory does not exist (will be created)"
    fi

    echo ""
    if [ $errors -gt 0 ]; then
        error "Environment verification failed with $errors error(s)"
        return 1
    else
        success "Environment verification passed"
        return 0
    fi
}

# =============================================================================
# Main Entry Point
# =============================================================================

main() {
    case "${1:-}" in
        topology)
            shift
            case "${1:-}" in
                start)
                    shift
                    topology_start "$@"
                    ;;
                stop)
                    shift
                    topology_stop "$@"
                    ;;
                destroy)
                    shift
                    topology_destroy "$@"
                    ;;
                status)
                    shift
                    topology_status "$@"
                    ;;
                list)
                    topology_list
                    ;;
                logs)
                    shift
                    topology_logs "$@"
                    ;;
                *)
                    topology_usage
                    exit 1
                    ;;
            esac
            ;;
        verify)
            verify_environment
            ;;
        help|--help|-h)
            cat << EOF
SDN Integration Test Setup Script

Usage: $0 [command] [options]

Commands:
    (none)          Initialize OVS and run default command
    topology        Manage test topologies (see: $0 topology help)
    verify          Verify environment is ready for testing
    help            Show this help message

OVS Setup:
    Running without arguments initializes OVS and executes any additional
    arguments as a command. This is useful for container entrypoints.

Examples:
    $0                              # Initialize OVS only
    $0 verify                       # Check environment
    $0 topology start three-node    # Start a test topology
    $0 go test -v ./...             # Initialize OVS and run tests
EOF
            ;;
        *)
            # Default: setup OVS and execute remaining args
            setup_ovs
            if [ $# -gt 0 ]; then
                exec "$@"
            fi
            ;;
    esac
}

main "$@"

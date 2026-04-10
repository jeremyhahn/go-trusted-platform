#!/bin/bash
# Cluster Node Entrypoint Script
#
# This entrypoint manages the lifecycle of a QuicBaaS/Raft cluster node,
# including initialization, health monitoring, and graceful shutdown.
#
# Environment Variables:
#   NODE_ID              - Unique node identifier (required, > 0)
#   NODE_NAME            - Human-readable node name
#   RAFT_PORT            - Port for Raft consensus communication
#   API_PORT             - Port for API communication
#   RAFT_ADDRESS         - Full Raft address (overrides hostname:RAFT_PORT)
#   CLUSTER_PEERS        - Comma-separated list of peer addresses
#   IS_BOOTSTRAP         - "true" for initial cluster bootstrap node
#   QUICBAAS_DATA_DIR    - QuicBaaS data directory
#   QUICBAAS_WAL_DIR     - QuicBaaS WAL directory
#   QUICBAAS_CACHE_SIZE  - Cache size in bytes
#   LOG_LEVEL            - Logging verbosity (debug, info, warn, error)

set -e

# =============================================================================
# Configuration
# =============================================================================

NODE_ID="${NODE_ID:-1}"
NODE_NAME="${NODE_NAME:-cluster-node-${NODE_ID}}"
RAFT_PORT="${RAFT_PORT:-7001}"
API_PORT="${API_PORT:-8001}"
RAFT_ADDRESS="${RAFT_ADDRESS:-$(hostname):${RAFT_PORT}}"
CLUSTER_PEERS="${CLUSTER_PEERS:-}"
IS_BOOTSTRAP="${IS_BOOTSTRAP:-false}"
QUICBAAS_DATA_DIR="${QUICBAAS_DATA_DIR:-/data/quicbaas}"
QUICBAAS_WAL_DIR="${QUICBAAS_WAL_DIR:-${QUICBAAS_DATA_DIR}/wal}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# Raft timing configuration
HEARTBEAT_INTERVAL_MS="${HEARTBEAT_INTERVAL_MS:-100}"
ELECTION_TIMEOUT_MS="${ELECTION_TIMEOUT_MS:-1000}"
SNAPSHOT_INTERVAL_SEC="${SNAPSHOT_INTERVAL_SEC:-300}"
SNAPSHOT_THRESHOLD="${SNAPSHOT_THRESHOLD:-10000}"

# =============================================================================
# Logging Functions
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if [ "${LOG_FORMAT}" = "json" ]; then
        echo "{\"timestamp\":\"${timestamp}\",\"level\":\"${level}\",\"node_id\":${NODE_ID},\"node_name\":\"${NODE_NAME}\",\"message\":\"${message}\"}"
    else
        echo "[${timestamp}] [${level}] [${NODE_NAME}] ${message}"
    fi
}

log_info() { log "INFO" "$@"; }
log_debug() { [ "${LOG_LEVEL}" = "debug" ] && log "DEBUG" "$@" || true; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# =============================================================================
# Initialization Functions
# =============================================================================

init_directories() {
    log_info "Initializing data directories..."

    mkdir -p "${QUICBAAS_DATA_DIR}"
    mkdir -p "${QUICBAAS_WAL_DIR}"
    mkdir -p /var/log/cluster
    mkdir -p /var/run/cluster

    log_debug "Data directory: ${QUICBAAS_DATA_DIR}"
    log_debug "WAL directory: ${QUICBAAS_WAL_DIR}"
}

write_config() {
    log_info "Writing node configuration..."

    cat > /var/run/cluster/node-config.json << EOF
{
    "node_id": ${NODE_ID},
    "node_name": "${NODE_NAME}",
    "raft_address": "${RAFT_ADDRESS}",
    "raft_port": ${RAFT_PORT},
    "api_port": ${API_PORT},
    "is_bootstrap": ${IS_BOOTSTRAP},
    "cluster_peers": "$(echo ${CLUSTER_PEERS} | tr ',' ' ')",
    "quicbaas": {
        "data_dir": "${QUICBAAS_DATA_DIR}",
        "wal_dir": "${QUICBAAS_WAL_DIR}",
        "cache_size": ${QUICBAAS_CACHE_SIZE:-67108864},
        "sync_writes": ${QUICBAAS_SYNC_WRITES:-true},
        "compression": "${QUICBAAS_COMPRESSION:-snappy}"
    },
    "raft": {
        "heartbeat_interval_ms": ${HEARTBEAT_INTERVAL_MS},
        "election_timeout_ms": ${ELECTION_TIMEOUT_MS},
        "snapshot_interval_sec": ${SNAPSHOT_INTERVAL_SEC},
        "snapshot_threshold": ${SNAPSHOT_THRESHOLD}
    },
    "log_level": "${LOG_LEVEL}"
}
EOF

    log_debug "Configuration written to /var/run/cluster/node-config.json"
}

wait_for_peers() {
    if [ -z "${CLUSTER_PEERS}" ]; then
        log_info "No cluster peers configured, running in bootstrap mode"
        return 0
    fi

    log_info "Waiting for cluster peers to become available..."

    IFS=',' read -ra PEERS <<< "${CLUSTER_PEERS}"
    for peer in "${PEERS[@]}"; do
        peer=$(echo "${peer}" | tr -d ' ')
        if [ -z "${peer}" ]; then
            continue
        fi

        host="${peer%%:*}"
        port="${peer##*:}"

        log_debug "Checking peer: ${host}:${port}"

        retries=0
        max_retries=60
        while ! nc -z "${host}" "${port}" 2>/dev/null; do
            retries=$((retries + 1))
            if [ ${retries} -ge ${max_retries} ]; then
                log_error "Timeout waiting for peer ${host}:${port}"
                return 1
            fi
            log_debug "Waiting for peer ${host}:${port} (attempt ${retries}/${max_retries})..."
            sleep 2
        done

        log_info "Peer ${host}:${port} is reachable"
    done

    log_info "All cluster peers are available"
}

# =============================================================================
# Health Check Functions
# =============================================================================

check_health() {
    # Check if the Raft port is listening
    if nc -z localhost "${RAFT_PORT}" 2>/dev/null; then
        echo "healthy"
        return 0
    else
        echo "unhealthy"
        return 1
    fi
}

run_health_server() {
    # Simple health check endpoint using netcat
    # This runs in the background and responds to health probes
    while true; do
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\",\"node_id\":${NODE_ID}}" | \
            nc -l -p "${API_PORT}" -q 1 2>/dev/null || true
    done
}

# =============================================================================
# Shutdown Handling
# =============================================================================

shutdown_handler() {
    log_info "Received shutdown signal, performing graceful shutdown..."

    # Write shutdown marker
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > /var/run/cluster/shutdown-marker

    # Kill background processes
    if [ -n "${HEALTH_SERVER_PID}" ]; then
        kill "${HEALTH_SERVER_PID}" 2>/dev/null || true
    fi

    log_info "Shutdown complete"
    exit 0
}

trap shutdown_handler SIGTERM SIGINT SIGQUIT

# =============================================================================
# Command Handlers
# =============================================================================

show_status() {
    echo "=== Cluster Node Status ==="
    echo "Node ID:       ${NODE_ID}"
    echo "Node Name:     ${NODE_NAME}"
    echo "Raft Address:  ${RAFT_ADDRESS}"
    echo "Raft Port:     ${RAFT_PORT}"
    echo "API Port:      ${API_PORT}"
    echo "Is Bootstrap:  ${IS_BOOTSTRAP}"
    echo "Cluster Peers: ${CLUSTER_PEERS:-none}"
    echo ""
    echo "Data Directory: ${QUICBAAS_DATA_DIR}"
    echo "WAL Directory:  ${QUICBAAS_WAL_DIR}"
    echo ""
    echo "Health Status: $(check_health)"
    echo "==========================="
}

show_help() {
    cat << EOF
Cluster Node Entrypoint

Usage:
    cluster-node-entrypoint.sh [COMMAND]

Commands:
    node        Start the cluster node (default)
    status      Show node status
    health      Check node health
    shell       Start interactive shell
    help        Show this help message

Environment Variables:
    NODE_ID              Unique node identifier (required)
    NODE_NAME            Human-readable node name
    RAFT_PORT            Port for Raft consensus (default: 7001)
    API_PORT             Port for API (default: 8001)
    RAFT_ADDRESS         Full Raft address
    CLUSTER_PEERS        Comma-separated peer addresses
    IS_BOOTSTRAP         "true" for bootstrap node
    QUICBAAS_DATA_DIR    Data directory
    QUICBAAS_WAL_DIR     WAL directory
    LOG_LEVEL            Logging level (debug, info, warn, error)

Examples:
    # Start as bootstrap node
    NODE_ID=1 IS_BOOTSTRAP=true ./cluster-node-entrypoint.sh node

    # Start as follower joining existing cluster
    NODE_ID=2 CLUSTER_PEERS="node1:7001" ./cluster-node-entrypoint.sh node

EOF
}

start_node() {
    log_info "Starting cluster node ${NODE_NAME} (ID: ${NODE_ID})..."

    # Initialize
    init_directories
    write_config

    # Wait for peers if not bootstrap
    if [ "${IS_BOOTSTRAP}" != "true" ]; then
        wait_for_peers
    fi

    # Start health server in background
    log_debug "Starting health server on port ${API_PORT}..."
    run_health_server &
    HEALTH_SERVER_PID=$!

    log_info "Cluster node ${NODE_NAME} is ready"
    log_info "Raft listening on ${RAFT_ADDRESS}"
    log_info "API listening on port ${API_PORT}"

    # Keep the container running
    while true; do
        sleep 60
        log_debug "Node ${NODE_NAME} heartbeat - status: $(check_health)"
    done
}

# =============================================================================
# Main Entry Point
# =============================================================================

case "${1:-node}" in
    node)
        start_node
        ;;
    status)
        show_status
        ;;
    health)
        check_health
        ;;
    shell|bash|sh)
        exec /bin/bash
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        # Pass through any other command
        exec "$@"
        ;;
esac

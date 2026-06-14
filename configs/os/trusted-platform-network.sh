#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Trusted Platform :: Device Network Configuration Service
#
# This script handles client-side network setup for device profile activation.
# It fetches the device profile from the platform API using mTLS (IDevID certificate),
# parses network configuration, generates systemd-networkd config files,
# and triggers VLAN transition.
#
# Zone identity:
#   TP_NETWORK_ZONE is exported after extracting the zone field from the
#   trusted network phase config.  The baked /etc/platformd/network/network.env
#   (written by platformctl iso create) is sourced first as a fallback so the
#   zone is always available even when the API fetch fails.

set -euo pipefail

# Configuration
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/trusted-platform/network-setup.log"
readonly PID_FILE="/run/trusted-platform/network-setup.pid"
readonly LOCK_FILE="/run/trusted-platform/network-setup.lock"

# Timeout values (in seconds)
readonly API_TIMEOUT=30
readonly NETWORK_RESTART_TIMEOUT=60

# API configuration
readonly API_ENDPOINT="${PLATFORM_API_ENDPOINT:-https://platform-api.local:8443}"
readonly API_PROFILE_PATH="/api/v1/device/profile"
readonly API_ACTIVATE_PATH="/api/v1/device/activate"

# Certificate paths (set during installation)
readonly IDEVID_CERT="${PLATFORM_IDEVID_CERT:-/etc/trusted-platform/certs/idevid.crt}"
readonly IDEVID_KEY="${PLATFORM_IDEVID_KEY:-/etc/trusted-platform/certs/idevid.key}"
readonly CA_CERT="${PLATFORM_CA_CERT:-/etc/trusted-platform/certs/ca.crt}"

# System configuration
readonly NETWORKD_CONFIG_DIR="/etc/systemd/network"
readonly BACKUP_DIR="/var/backups/trusted-platform/network"
readonly STATE_FILE="/var/lib/trusted-platform/network-state.json"

# Baked network env file written by platformctl iso create.
# Provides TP_NETWORK_ZONE as a fallback when the API is unreachable.
readonly BAKED_NETWORK_ENV="/etc/platformd/network/network.env"

# Temporary file for JSON response
readonly TEMP_PROFILE="/tmp/device-profile-$$.json"
trap "rm -f '$TEMP_PROFILE'" EXIT

# Error types
declare -r ERR_CERT_MISSING=10
declare -r ERR_API_UNAVAILABLE=11
declare -r ERR_INVALID_PROFILE=12
declare -r ERR_NETWORK_CONFIG_FAILED=13
declare -r ERR_LOCK_FAILED=14
declare -r ERR_ACTIVATE_FAILED=15

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        log "DEBUG" "$@"
    fi
}

# Utility functions
check_prerequisites() {
    log_info "Checking prerequisites"

    # Check required commands
    local required_cmds=("curl" "jq" "systemctl" "ip" "mkdir" "sed")
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            return 1
        fi
    done

    # Check certificate files exist
    if [[ ! -f "$IDEVID_CERT" ]]; then
        log_error "IDevID certificate not found: $IDEVID_CERT"
        return "$ERR_CERT_MISSING"
    fi

    if [[ ! -f "$IDEVID_KEY" ]]; then
        log_error "IDevID key not found: $IDEVID_KEY"
        return "$ERR_CERT_MISSING"
    fi

    if [[ ! -f "$CA_CERT" ]]; then
        log_error "CA certificate not found: $CA_CERT"
        return "$ERR_CERT_MISSING"
    fi

    log_info "Prerequisites check passed"
    return 0
}

# Acquire exclusive lock to prevent concurrent runs
acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_error "Failed to acquire lock (another instance running?)"
        return "$ERR_LOCK_FAILED"
    fi
    echo $$ > "$PID_FILE"
}

# Release lock
release_lock() {
    rm -f "$PID_FILE"
    exec 200>&-
}

# Fetch device profile from API using mTLS
fetch_device_profile() {
    log_info "Fetching device profile from API: $API_ENDPOINT$API_PROFILE_PATH"

    local response
    local http_code

    response=$(mktemp)
    trap "rm -f '$response'" RETURN

    http_code=$(curl \
        --silent \
        --show-error \
        --max-time "$API_TIMEOUT" \
        --cacert "$CA_CERT" \
        --cert "$IDEVID_CERT" \
        --key "$IDEVID_KEY" \
        --write-out "%{http_code}" \
        --output "$response" \
        "$API_ENDPOINT$API_PROFILE_PATH" 2>&1) || true

    # Extract HTTP code from output (last 3 characters)
    http_code="${http_code: -3}"

    if [[ "$http_code" != "200" ]]; then
        log_error "API request failed with HTTP $http_code"
        if [[ -f "$response" ]]; then
            log_error "Response: $(cat "$response")"
        fi
        return "$ERR_API_UNAVAILABLE"
    fi

    # Validate JSON response
    if ! jq empty "$response" 2>/dev/null; then
        log_error "Invalid JSON response from API"
        return "$ERR_INVALID_PROFILE"
    fi

    cp "$response" "$TEMP_PROFILE"
    log_debug "Device profile fetched successfully"
    return 0
}

# Validate device profile structure
validate_profile() {
    log_info "Validating device profile structure"

    if [[ ! -f "$TEMP_PROFILE" ]]; then
        log_error "Profile file not found"
        return "$ERR_INVALID_PROFILE"
    fi

    # Check required fields
    local required_fields=("id" "name" "role")
    for field in "${required_fields[@]}"; do
        if ! jq -e ".$field" "$TEMP_PROFILE" > /dev/null 2>&1; then
            log_error "Required field missing in profile: $field"
            return "$ERR_INVALID_PROFILE"
        fi
    done

    log_debug "Profile validation passed"
    return 0
}

# Extract network configuration for given phase
extract_network_config() {
    local phase="$1"  # "provisioning", "trusted", or "quarantine"

    log_debug "Extracting $phase network configuration"

    local config_key="${phase}Network"

    # Check if phase network config exists
    if ! jq -e ".${config_key}" "$TEMP_PROFILE" > /dev/null 2>&1; then
        log_debug "No $phase network configuration found"
        return 0
    fi

    jq ".${config_key}" "$TEMP_PROFILE"
}

# Generate systemd-networkd configuration for a network interface
generate_networkd_config() {
    local iface="$1"
    local vlan="$2"
    local static_ip="$3"
    local gateway="$4"
    local dns_servers="$5"  # space-separated list

    log_info "Generating networkd config for interface: $iface (VLAN: $vlan)"

    # Create networkd config directory if needed
    mkdir -p "$NETWORKD_CONFIG_DIR"

    # Backup existing config
    local config_file="$NETWORKD_CONFIG_DIR/10-$iface.network"
    if [[ -f "$config_file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$config_file" "$BACKUP_DIR/10-$iface.network.$(date +%s)"
        log_info "Backed up existing config: $config_file"
    fi

    # Generate network configuration file
    cat > "$config_file.tmp" << EOF
# Generated by trusted-platform-network.sh
# DO NOT EDIT MANUALLY

[Match]
Name=$iface
VLAN=$vlan

[Network]
DHCP=no
EOF

    # Add DNS if provided
    if [[ -n "$dns_servers" ]]; then
        echo "DNS=$dns_servers" >> "$config_file.tmp"
    fi

    # Add IP configuration
    if [[ -n "$static_ip" ]]; then
        # Validate IP format (basic check)
        if [[ ! "$static_ip" =~ ^[0-9.]+/[0-9]+$ ]]; then
            log_warn "Invalid static IP format: $static_ip (skipping)"
        else
            echo "Address=$static_ip" >> "$config_file.tmp"
        fi
    fi

    # Add gateway if provided
    if [[ -n "$gateway" ]]; then
        # Validate gateway format (basic check)
        if [[ ! "$gateway" =~ ^[0-9.]+$ ]]; then
            log_warn "Invalid gateway format: $gateway (skipping)"
        else
            echo "Gateway=$gateway" >> "$config_file.tmp"
        fi
    fi

    # Atomically move config into place
    if ! mv "$config_file.tmp" "$config_file"; then
        log_error "Failed to write network config: $config_file"
        rm -f "$config_file.tmp"
        return "$ERR_NETWORK_CONFIG_FAILED"
    fi

    # Set restrictive permissions
    chmod 0644 "$config_file"
    log_debug "Network config written: $config_file"
    return 0
}

# Apply network configuration for trusted phase.
# Exports TP_NETWORK_ZONE to the environment after resolving the zone name
# from the trusted network phase config.  Falls back to the baked
# /etc/platformd/network/network.env when the zone field is absent from the
# live API response.
apply_trusted_network_config() {
    log_info "Applying trusted network configuration"

    local net_config
    net_config=$(extract_network_config "trusted")

    if [[ -z "$net_config" || "$net_config" == "null" ]]; then
        log_warn "No trusted network configuration found in profile"
        return 0
    fi

    # Extract network parameters
    local vlan static_ip gateway dns_servers zone
    vlan=$(echo "$net_config" | jq -r '.vlan // empty')
    static_ip=$(echo "$net_config" | jq -r '.static_ip // empty')
    gateway=$(echo "$net_config" | jq -r '.gateway // empty')
    dns_servers=$(echo "$net_config" | jq -r '.dns[]? // empty' | tr '\n' ' ' | sed 's/[[:space:]]*$//')
    zone=$(echo "$net_config" | jq -r '.zone // empty')

    if [[ -z "$vlan" ]]; then
        log_error "VLAN ID not specified in trusted network config"
        return "$ERR_INVALID_PROFILE"
    fi

    # Export zone.  When the API response carries no zone field, fall back to
    # the value baked by platformctl iso create into network.env.
    if [[ -n "$zone" ]]; then
        export TP_NETWORK_ZONE="$zone"
        log_info "Network zone from API: $TP_NETWORK_ZONE"
    else
        # Attempt to source the baked env file written at ISO build time.
        if [[ -f "$BAKED_NETWORK_ENV" ]]; then
            # shellcheck source=/dev/null
            . "$BAKED_NETWORK_ENV"
            log_info "Network zone from baked env: ${TP_NETWORK_ZONE:-<unset>}"
        else
            log_warn "No zone in API response and baked env not found: $BAKED_NETWORK_ENV"
        fi
    fi

    # Get primary network interface (typically eth0)
    local primary_iface
    primary_iface=$(ip -4 route show | grep '^default' | awk '{print $5}' | head -1)

    if [[ -z "$primary_iface" ]]; then
        log_error "Could not determine primary network interface"
        return "$ERR_NETWORK_CONFIG_FAILED"
    fi

    log_info "Using primary interface: $primary_iface"

    # Generate networkd configuration
    if ! generate_networkd_config "$primary_iface" "$vlan" "$static_ip" "$gateway" "$dns_servers"; then
        return "$ERR_NETWORK_CONFIG_FAILED"
    fi

    return 0
}

# Reload systemd-networkd configuration
reload_network_config() {
    log_info "Reloading systemd-networkd configuration"

    if ! systemctl daemon-reload; then
        log_error "Failed to reload systemd daemon"
        return "$ERR_NETWORK_CONFIG_FAILED"
    fi

    if ! systemctl restart systemd-networkd; then
        log_error "Failed to restart systemd-networkd"
        return "$ERR_NETWORK_CONFIG_FAILED"
    fi

    log_info "Network configuration reloaded successfully"
    return 0
}

# Verify network connectivity
verify_network_connectivity() {
    log_info "Verifying network connectivity"

    local max_attempts=5
    local attempt=0

    while (( attempt < max_attempts )); do
        ((attempt++))

        # Try to reach the API endpoint
        if curl \
            --silent \
            --max-time 5 \
            --cacert "$CA_CERT" \
            --cert "$IDEVID_CERT" \
            --key "$IDEVID_KEY" \
            "$API_ENDPOINT/health" \
            -o /dev/null 2>/dev/null; then
            log_info "Network connectivity verified"
            return 0
        fi

        log_debug "Connectivity check attempt $attempt/$max_attempts failed, retrying..."
        sleep 2
    done

    log_warn "Network connectivity verification failed (continuing anyway)"
    return 0
}

# Call device activation endpoint
activate_device() {
    log_info "Activating device on platform API"

    local response
    local http_code

    response=$(mktemp)
    trap "rm -f '$response'" RETURN

    http_code=$(curl \
        --silent \
        --show-error \
        --max-time "$API_TIMEOUT" \
        --cacert "$CA_CERT" \
        --cert "$IDEVID_CERT" \
        --key "$IDEVID_KEY" \
        --request POST \
        --header "Content-Type: application/json" \
        --write-out "%{http_code}" \
        --output "$response" \
        "$API_ENDPOINT$API_ACTIVATE_PATH" 2>&1) || true

    # Extract HTTP code
    http_code="${http_code: -3}"

    if [[ "$http_code" != "200" && "$http_code" != "201" && "$http_code" != "204" ]]; then
        log_error "Device activation failed with HTTP $http_code"
        if [[ -f "$response" ]]; then
            log_error "Response: $(cat "$response")"
        fi
        return "$ERR_ACTIVATE_FAILED"
    fi

    log_info "Device activated successfully"
    return 0
}

# Save state for future reference
save_state() {
    log_debug "Saving network state"

    mkdir -p "$(dirname "$STATE_FILE")"

    local state_data
    state_data=$(jq -n \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg profile_id "$(jq -r '.id // "unknown"' "$TEMP_PROFILE")" \
        --arg device_name "$(hostname)" \
        --arg zone "${TP_NETWORK_ZONE:-}" \
        '{timestamp: $timestamp, profile_id: $profile_id, device_name: $device_name, zone: $zone}')

    echo "$state_data" > "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
    log_debug "State saved to: $STATE_FILE"
}

# Main execution flow
main() {
    log_info "Starting device network configuration"

    # Create log directory if needed
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")" "$(dirname "$LOCK_FILE")"

    # Source the baked network env as an early default so TP_NETWORK_ZONE is
    # available even if the API fetch later fails.
    if [[ -f "$BAKED_NETWORK_ENV" ]]; then
        # shellcheck source=/dev/null
        . "$BAKED_NETWORK_ENV"
        log_info "Loaded baked network env: ${TP_NETWORK_ZONE:-<unset>}"
    fi

    # Check prerequisites
    if ! check_prerequisites; then
        return $?
    fi

    # Acquire lock
    if ! acquire_lock; then
        return $?
    fi

    # Main execution
    local exit_code=0

    {
        # Fetch device profile
        if ! fetch_device_profile; then
            exit_code=$?
            log_error "Failed to fetch device profile"
            return $exit_code
        fi

        # Validate profile
        if ! validate_profile; then
            exit_code=$?
            log_error "Device profile validation failed"
            return $exit_code
        fi

        # Apply trusted network configuration (also resolves TP_NETWORK_ZONE)
        if ! apply_trusted_network_config; then
            exit_code=$?
            log_error "Failed to apply network configuration"
            return $exit_code
        fi

        # Reload network configuration
        if ! reload_network_config; then
            exit_code=$?
            log_error "Failed to reload network configuration"
            return $exit_code
        fi

        # Verify connectivity
        if ! verify_network_connectivity; then
            exit_code=$?
            log_warn "Network verification failed"
            # Don't return here, continue to activation
        fi

        # Activate device
        if ! activate_device; then
            exit_code=$?
            log_error "Failed to activate device"
            return $exit_code
        fi

        # Save state
        save_state

        log_info "Device network configuration completed successfully"
    } || {
        exit_code=$?
    }

    release_lock
    return $exit_code
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

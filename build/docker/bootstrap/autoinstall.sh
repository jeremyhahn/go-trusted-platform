#!/bin/sh
# ============================================================================
#  ⚠️  REFERENCE / DEAD FILE — NOT THE SCRIPT THE ISO ACTUALLY RUNS ⚠️
# ============================================================================
# The autoinstall.sh that gets baked into the ISO is BUILT INLINE inside
# pkg/iso/customize.go's `buildAutoinstallScript()` function (around
# line 1967). That string is what runs on the target during install.
#
# This standalone .sh file is a historical reference only. Edits made here
# do NOT propagate to the ISO. Make all changes in customize.go.
#
# DO NOT delete this file without grepping for it first — it may still be
# referenced by docs or test fixtures, but it is NOT on the live install
# code path.
# ============================================================================
# Automated installation script with platformd integration
#
# Config resolution priority:
#   1. Kernel param platform_config=<server_url> (trust-bootstrapped HTTPS fetch)
#   2. USB/removable media (/platform/config.yaml)
#   3. Embedded in ISO (/media/cdrom/configs/config.yaml or installer.yaml)
#   4. Interactive QR code provisioning
#   5. Fatal error
#
# Debug mode (kernel cmdline `platform_debug=1`):
#   - `set -x` enables shell command tracing
#   - The installer is invoked with --debug for slog Debug level + dracut -v
#   - Every step is captured to /tmp/install.log via tee
#
# Forensic upload (kernel cmdline `platform_debug_sink=<host>:<port>`):
#   - On EVERY exit (success OR failure), /tmp/install.log is PUT to
#     http://<host>:<port>/installs/$(hostname)/install.log
#   - Default sink: the DHCP server IP discovered from the dhclient lease
#   - Files are size-capped at 16 MiB by the receiver
#   - We never lose post-mortem data even when the install env reboots
set -e
# pipefail propagates exit codes through `cmd | tee` pipelines. Without it,
# `eval "$INSTALL_CMD" 2>&1 | tee /tmp/install.log` would silently mask any
# non-zero install exit code (because `tee` always succeeds), and the script
# would happily report "Installation completed successfully" while the ESP
# is empty. This was the actual bug in the previous version. busybox sh
# supports pipefail in modern Alpine; older shells silently ignore it.
set -o pipefail 2>/dev/null || true

log() {
    echo "[autoinstall] $1"
    sync
}

error() {
    echo "[autoinstall] ERROR: $1" >&2
    sync
    exit 1
}

# Mirror EVERYTHING (stdout AND stderr from this script onward) to
# /tmp/install.log so the forensic uploader has a complete transcript.
# Done before debug-mode detection so the log captures the cmdline parse too.
exec > >(tee -a /tmp/install.log) 2>&1
log "=== autoinstall.sh started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
log "Kernel cmdline: $(cat /proc/cmdline)"

# Detect debug mode from kernel cmdline. When set, enable shell tracing for
# the rest of the script. The installer Go binary picks up the same flag
# from the cmdline directly via cmdline_param("platform_debug").
PLATFORM_DEBUG=$(cat /proc/cmdline | tr ' ' '\n' | grep '^platform_debug=' | cut -d= -f2- | tail -1)
if [ "$PLATFORM_DEBUG" = "1" ] || [ "$PLATFORM_DEBUG" = "true" ]; then
    log "platform_debug=1 — enabling shell tracing (set -x)"
    set -x
    PLATFORM_DEBUG=1
else
    PLATFORM_DEBUG=0
fi
export PLATFORM_DEBUG

# Forensic-sink uploader. Called on EVERY exit path (trap below).
# Best-effort: failure to upload must NEVER block the install or its cleanup.
upload_install_log() {
    EXIT_CODE=$?
    set +e

    # Resolve the upload sink:
    #   1. Explicit kernel cmdline override `platform_debug_sink=host:port`
    #   2. The DHCP server IP from the dhclient lease (the bootstrap container
    #      IS the DHCP server, so this is always reachable for the install env)
    #   3. The DHCP gateway as a last resort
    SINK=$(cat /proc/cmdline | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep '^dhcp-server-identifier' /var/lib/dhcp/dhclient.leases 2>/dev/null | tail -1 | sed 's/.*identifier //; s/;.*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        if [ -n "$DHCP_SERVER" ]; then
            SINK="${DHCP_SERVER}:8080"
        fi
    fi

    if [ -z "$SINK" ]; then
        echo "[autoinstall] no upload sink resolved — install.log will NOT be uploaded" >&2
        return
    fi

    HOSTNAME_LC=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9.-' '-')
    [ -z "$HOSTNAME_LC" ] && HOSTNAME_LC="unknown"

    URL="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    echo "[autoinstall] uploading install.log to ${URL} (exit_code=${EXIT_CODE})" >&2

    # Append a final manifest with exit code, dmesg tail, and lsblk so the
    # postmortem reader has hardware context without needing a separate file.
    {
        echo ""
        echo "=== POSTMORTEM MANIFEST ==="
        echo "exit_code: ${EXIT_CODE}"
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "hostname: ${HOSTNAME_LC}"
        echo ""
        echo "--- lsblk ---"
        lsblk 2>&1 || true
        echo ""
        echo "--- ip addr ---"
        ip addr 2>&1 || true
        echo ""
        echo "--- mount ---"
        mount 2>&1 || true
        echo ""
        echo "--- dmesg tail (last 200 lines) ---"
        dmesg 2>&1 | tail -200 || true
        echo ""
        echo "=== END POSTMORTEM ==="
    } >> /tmp/install.log

    # PUT the log. busybox wget supports --post-file with --header but not PUT,
    # so use curl if available, otherwise fall back to constructing an HTTP
    # request via netcat (which the install env's busybox provides as `nc`).
    if command -v curl >/dev/null 2>&1; then
        curl --silent --show-error --max-time 30 \
             --request PUT --upload-file /tmp/install.log "${URL}" >&2 || \
            echo "[autoinstall] curl PUT failed (continuing)" >&2
    else
        # Pure-busybox PUT via raw HTTP. Build a minimal request body and
        # pipe it through nc. Connection-close to avoid timeouts.
        BODY_LEN=$(wc -c < /tmp/install.log)
        HOST_PART="${SINK%:*}"
        PORT_PART="${SINK##*:}"
        {
            printf 'PUT /installs/%s/install.log HTTP/1.1\r\n' "${HOSTNAME_LC}"
            printf 'Host: %s\r\n' "${SINK}"
            printf 'Content-Length: %s\r\n' "${BODY_LEN}"
            printf 'Connection: close\r\n'
            printf 'Content-Type: text/plain\r\n'
            printf '\r\n'
            cat /tmp/install.log
        } | nc -w 30 "${HOST_PART}" "${PORT_PART}" >&2 || \
            echo "[autoinstall] nc PUT failed (continuing)" >&2
    fi

    echo "[autoinstall] upload attempt complete" >&2
    return $EXIT_CODE
}

# Always upload the log on exit, regardless of success or failure path.
trap upload_install_log EXIT INT TERM

# Extract a kernel command line parameter value
cmdline_param() {
    PARAM_NAME="$1"
    DEFAULT_VALUE="$2"
    VALUE=$(cat /proc/cmdline | tr ' ' '\n' | grep "^${PARAM_NAME}=" | cut -d= -f2- | tail -1)
    if [ -n "$VALUE" ]; then
        echo "$VALUE"
    else
        echo "$DEFAULT_VALUE"
    fi
}

# Find the platformctl-static binary
find_platformctl() {
    if [ -x /media/cdrom/platformd-bin/platformctl ]; then
        echo "/media/cdrom/platformd-bin/platformctl"
    elif [ -x /usr/bin/platformctl ]; then
        echo "/usr/bin/platformctl"
    elif [ -x /media/cdrom/platformd-bin/platformctl-static ]; then
        echo "/media/cdrom/platformd-bin/platformctl-static"
    elif [ -x /usr/bin/platformctl-static ]; then
        echo "/usr/bin/platformctl-static"
    else
        echo ""
    fi
}

# Fetch config from the control plane using the embedded CA bundle.
# The CA bundle is included in the ISO at /media/cdrom/configs/ca-bundle.pem
# and provides TLS verification without needing DANE/Noise/SPKI trust bootstrap.
# The server URL is the config delivery endpoint; the device MAC address is
# appended as a query parameter so the CP can match the device profile.
fetch_config_from_server() {
    SERVER_URL="$1"

    # Discover device MAC address for profile matching
    MAC_ADDR=$(ip link show eth0 2>/dev/null | grep ether | awk '{print $2}' || echo "")
    if [ -z "$MAC_ADDR" ]; then
        # Try other interfaces
        for iface in eth1 eth2 eth3 eno1 eno2 enp0s25; do
            MAC_ADDR=$(ip link show "$iface" 2>/dev/null | grep ether | awk '{print $2}' || echo "")
            [ -n "$MAC_ADDR" ] && break
        done
    fi
    log "Device MAC: $MAC_ADDR"

    # Build config URL with MAC query parameter
    CONFIG_URL="${SERVER_URL}?mac=${MAC_ADDR}"
    log "Fetching config from: $CONFIG_URL"

    # Use the CA bundle embedded in the ISO for TLS verification.
    # This avoids the need for DANE/Noise/SPKI trust bootstrap.
    CA_BUNDLE="/media/cdrom/configs/ca-bundle.pem"
    if [ ! -f "$CA_BUNDLE" ]; then
        log "WARNING: CA bundle not found at $CA_BUNDLE, trying without TLS verification"
        CA_BUNDLE=""
    fi

    # Bring up network with DHCP for config fetch (install hasn't run yet)
    if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
        log "Bringing up eth0 with DHCP for config fetch..."
        ip link set eth0 up 2>/dev/null
        udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null
    fi

    # Fetch config via HTTPS using curl with the CA bundle
    FETCH_OPTS=""
    if [ -n "$CA_BUNDLE" ]; then
        FETCH_OPTS="--cacert $CA_BUNDLE"
    fi

    curl -sf $FETCH_OPTS -o /tmp/platform-config.yaml "$CONFIG_URL" 2>&1
    CURL_RESULT=$?

    if [ "$CURL_RESULT" -ne 0 ]; then
        log "Config fetch failed (curl exit $CURL_RESULT), trying platformctl fallback..."

        # Fallback: try platformctl if available
        PLATFORMCTL=$(find_platformctl)
        if [ -z "$PLATFORMCTL" ]; then
            log "platformctl not found, cannot use fallback"
            return 1
        fi

        # Gather device identity for platformctl
        EK_SERIAL=$("$PLATFORMCTL" tpm ek-serial 2>/dev/null || echo "")
        EAB_KID=$(cmdline_param "eab_kid" "")
        EAB_HMAC=$(cmdline_param "eab_hmac" "")
        log "Device identity: EK=$EK_SERIAL MAC=$MAC_ADDR"

        "$PLATFORMCTL" provision fetch-config \
            --server-url "$SERVER_URL" \
        --output /tmp/platform-config.yaml \
        ${EK_SERIAL:+--ek-serial "$EK_SERIAL"} \
        ${MAC_ADDR:+--mac "$MAC_ADDR"} \
        ${EAB_KID:+--eab-kid "$EAB_KID"} \
        ${EAB_HMAC:+--eab-hmac "$EAB_HMAC"} \
        2>&1
    FETCH_EXIT=$?

    if [ "$FETCH_EXIT" -eq 0 ]; then
        INSTALLER_CONFIG="/tmp/platform-config.yaml"
        log "Config fetched from server: $INSTALLER_CONFIG"
        return 0
    fi

    # Exit code 2 means "pending" — try interactive mode
    if [ "$FETCH_EXIT" -eq 2 ]; then
        log "No matching config on server, trying interactive mode..."
        return 2
    fi

    log "Config fetch failed (exit $FETCH_EXIT)"
    return 1
}

# Interactive QR code provisioning
interactive_provision() {
    SERVER_URL="$1"
    PLATFORMCTL=$(find_platformctl)

    if [ -z "$PLATFORMCTL" ]; then
        log "platformctl-static not found, cannot use interactive mode"
        return 1
    fi

    EK_SERIAL=$("$PLATFORMCTL" tpm ek-serial 2>/dev/null || echo "")
    MAC_ADDR=$(ip link show eth0 2>/dev/null | grep ether | awk '{print $2}' || echo "")
    EAB_KID=$(cmdline_param "eab_kid" "")
    EAB_HMAC=$(cmdline_param "eab_hmac" "")

    "$PLATFORMCTL" provision interactive \
        --server-url "$SERVER_URL" \
        --output /tmp/platform-config.yaml \
        --timeout 600 \
        ${EK_SERIAL:+--ek-serial "$EK_SERIAL"} \
        ${MAC_ADDR:+--mac "$MAC_ADDR"} \
        ${EAB_KID:+--eab-kid "$EAB_KID"} \
        ${EAB_HMAC:+--eab-hmac "$EAB_HMAC"} \
        2>&1

    if [ $? -eq 0 ] && [ -f /tmp/platform-config.yaml ]; then
        INSTALLER_CONFIG="/tmp/platform-config.yaml"
        log "Config received via interactive provisioning: $INSTALLER_CONFIG"
        return 0
    fi

    log "Interactive provisioning failed or timed out"
    return 1
}

# Scan USB/removable media for config
scan_usb_config() {
    log "Scanning USB/removable media for config..."
    mkdir -p /mnt/usb

    for dev in /dev/sd[b-z]1 /dev/sd[b-z]; do
        [ -b "$dev" ] || continue
        if mount "$dev" /mnt/usb 2>/dev/null; then
            if [ -f /mnt/usb/platform/config.yaml ]; then
                log "Config found on USB: $dev"
                cp /mnt/usb/platform/config.yaml /tmp/platform-config.yaml
                umount /mnt/usb
                INSTALLER_CONFIG="/tmp/platform-config.yaml"
                return 0
            fi
            umount /mnt/usb 2>/dev/null
        fi
    done

    log "No config found on USB media"
    return 1
}

# Fetch per-MAC installer.yaml from the bootstrap HTTP sink (pxeboot
# container). The orchestrator stages merged per-node config at
#   /config/mac/<MAC>/installer.yaml
# for every boot method; virtual-media boot has no way to set kernel
# cmdline params, so use platform_debug_sink (always set for debug
# installs) as the implicit config URL. Returns 0 on success, 1 on
# failure (caller proceeds to next priority).
fetch_config_from_bootstrap_sink() {
    SINK=$(cmdline_param "platform_debug_sink" "")
    if [ -z "$SINK" ]; then
        return 1
    fi

    # Bring up eth0 with DHCP if no IP yet. The kernel modules for
    # onboard NICs have already been loaded above; this just leases.
    if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
        log "Bringing up eth0 with DHCP to reach bootstrap sink $SINK..."
        ip link set eth0 up 2>/dev/null
        udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null
    fi

    # Resolve the active MAC. Match fetch_config_from_server.
    MAC_ADDR=$(ip link show eth0 2>/dev/null | grep ether | awk '{print $2}' || echo "")
    if [ -z "$MAC_ADDR" ]; then
        for iface in eth1 eth2 eth3 eno1 eno2 enp0s25; do
            MAC_ADDR=$(ip link show "$iface" 2>/dev/null | grep ether | awk '{print $2}' || echo "")
            [ -n "$MAC_ADDR" ] && break
        done
    fi
    if [ -z "$MAC_ADDR" ]; then
        log "fetch_config_from_bootstrap_sink: no MAC found, skipping"
        return 1
    fi

    # Normalize MAC to dash-separated lowercase (matches orchestrator
    # sanitizeMACForPath in pkg/bootstrap/virtual_media.go).
    MAC_PATH=$(echo "$MAC_ADDR" | tr ':' '-' | tr '[:upper:]' '[:lower:]')
    URL="http://${SINK}/config/mac/${MAC_PATH}/installer.yaml"
    log "Fetching per-MAC installer config: $URL"

    # Plain HTTP on the bootstrap network — the pxeboot container runs
    # on the deployer host on-LAN. No CA bundle needed.
    if command -v curl >/dev/null 2>&1; then
        curl --silent --show-error --max-time 10 --fail -o /tmp/platform-config.yaml "$URL" 2>&1
        RESULT=$?
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --timeout=10 -O /tmp/platform-config.yaml "$URL" 2>&1
        RESULT=$?
    else
        log "fetch_config_from_bootstrap_sink: neither curl nor wget available"
        return 1
    fi

    if [ "$RESULT" -ne 0 ] || [ ! -s /tmp/platform-config.yaml ]; then
        log "Per-MAC config fetch failed or empty (exit=$RESULT); falling through"
        rm -f /tmp/platform-config.yaml
        return 1
    fi

    log "Config source: bootstrap sink (http://${SINK}/config/mac/${MAC_PATH}/installer.yaml)"
    INSTALLER_CONFIG="/tmp/platform-config.yaml"
    return 0
}

# Main config resolution function
resolve_config() {
    INSTALLER_CONFIG=""

    # Priority 1: Kernel param platform_config=<server_url>
    PLATFORM_CONFIG_URL=$(cmdline_param "platform_config" "")
    if [ -n "$PLATFORM_CONFIG_URL" ]; then
        log "Config source: kernel param platform_config=$PLATFORM_CONFIG_URL"
        fetch_config_from_server "$PLATFORM_CONFIG_URL"
        FETCH_RESULT=$?
        if [ "$FETCH_RESULT" -eq 0 ]; then
            return 0
        fi
        # If fetch returned "pending" (exit 2), try interactive after USB check
        if [ "$FETCH_RESULT" -eq 2 ]; then
            # Try USB first before going interactive
            if scan_usb_config; then
                return 0
            fi
            # Try interactive QR provisioning
            if interactive_provision "$PLATFORM_CONFIG_URL"; then
                return 0
            fi
        fi
    fi

    # Priority 2: Per-MAC installer.yaml on the bootstrap HTTP sink.
    # The orchestrator's virtual-media path stages merged per-node config at
    #   http://${platform_debug_sink}/config/mac/<MAC>/installer.yaml
    # Virtual-media boot cannot inject kernel cmdline, so rely on the
    # debug sink address (always set for debug installs) to locate the
    # pxeboot HTTP server and fetch the per-device config before falling
    # back to the stub baked into the ISO.
    if fetch_config_from_bootstrap_sink; then
        return 0
    fi

    # Priority 3: USB/removable media
    if scan_usb_config; then
        return 0
    fi

    # Priority 4: Embedded in ISO (check both new and legacy config names)
    if [ -f /media/cdrom/configs/config.yaml ]; then
        log "Config source: embedded ISO (config.yaml)"
        INSTALLER_CONFIG="/media/cdrom/configs/config.yaml"
        return 0
    fi
    if [ -f /media/cdrom/configs/installer.yaml ]; then
        log "Config source: embedded ISO (installer.yaml, legacy)"
        INSTALLER_CONFIG="/media/cdrom/configs/installer.yaml"
        return 0
    fi

    # Priority 5: Interactive QR (if server URL available but no auto-match)
    PLATFORM_SERVER=$(cmdline_param "platform_server" "")
    if [ -n "$PLATFORM_SERVER" ]; then
        log "Config source: interactive provisioning via $PLATFORM_SERVER"
        if interactive_provision "$PLATFORM_SERVER"; then
            return 0
        fi
    fi

    # Priority 5: Fatal error
    error "No installer configuration found.

Tried the following sources:
  1. Kernel param platform_config=${PLATFORM_CONFIG_URL:-<not set>}
  2. USB/removable media (/platform/config.yaml)
  3. Embedded ISO (/media/cdrom/configs/config.yaml)
  4. Interactive provisioning (platform_server=${PLATFORM_SERVER:-<not set>})

To fix this, either:
  - Build the ISO with an embedded config: platformctl iso create --config platform.yaml
  - Set kernel param: platform_config=https://your-server:8443
  - Place config on USB drive at /platform/config.yaml"
}

log "Starting platformd system installation..."

# Load common bare metal NIC drivers that may not be auto-loaded
# These are essential for networking during installation on physical servers
log "Loading kernel modules for bare metal NICs..."
for mod in igb ixgbe e1000e i40e ice mlx5_core bnxt_en; do
    modprobe "$mod" 2>/dev/null && log "  Loaded: $mod" || true
done

# Also load modules from the installer config if specified
if [ -f /media/cdrom/configs/installer.yaml ]; then
    CONFIG_MODULES=$(grep -A20 "kernel-modules:" /media/cdrom/configs/installer.yaml 2>/dev/null | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "')
    for mod in $CONFIG_MODULES; do
        modprobe "$mod" 2>/dev/null && log "  Loaded from config: $mod" || true
    done
fi

# Wait for NICs to come up after module loading
sleep 2

# Configure minimal networking for config resolution
log "Configuring network..."

# Check if there's a config in the ISO that has network settings
INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
NETWORK_CONFIG="/media/cdrom/configs/config.yaml"
if [ -f "$NETWORK_CONFIG" ]; then
    INSTALLER_YAML="$NETWORK_CONFIG"
fi
if [ -f "$INSTALLER_YAML" ]; then
    log "Reading network configuration from installer.yaml..."

    # Extract network interface configuration using grep/sed
    # Check if static IP is configured
    IFACE_TYPE=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "type:" | head -1 | sed 's/.*type:\s*//' | tr -d ' "')

    if [ "$IFACE_TYPE" = "static" ]; then
        log "Static IP configuration detected"

        # Extract network settings
        IFACE_NAME=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "name:" | head -1 | sed 's/.*name:\s*//' | tr -d ' "')
        IPV4_ADDR=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-address:" | head -1 | sed 's/.*ipv4-address:\s*//' | tr -d ' "')
        IPV4_MASK=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-netmask:" | head -1 | sed 's/.*ipv4-netmask:\s*//' | tr -d ' "')
        IPV4_GW=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-gateway:" | head -1 | sed 's/.*ipv4-gateway:\s*//' | tr -d ' "')

        # Extract DNS servers
        DNS_SERVERS=$(grep -A5 "dns:" "$INSTALLER_YAML" | grep -A3 "nameservers:" | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "' | tr '\n' ' ')

        # Default interface name if not specified
        [ -z "$IFACE_NAME" ] && IFACE_NAME="eth0"

        if [ -n "$IPV4_ADDR" ] && [ -n "$IPV4_GW" ]; then
            log "Configuring $IFACE_NAME with IP: $IPV4_ADDR, Gateway: $IPV4_GW"

            # Bring up interface
            ip link set "$IFACE_NAME" up 2>/dev/null || true

            # Calculate CIDR prefix from netmask
            # Common netmasks: 255.255.255.0 = /24, 255.255.255.240 = /28
            case "$IPV4_MASK" in
                255.255.255.0)   CIDR="24" ;;
                255.255.255.128) CIDR="25" ;;
                255.255.255.192) CIDR="26" ;;
                255.255.255.224) CIDR="27" ;;
                255.255.255.240) CIDR="28" ;;
                255.255.255.248) CIDR="29" ;;
                255.255.255.252) CIDR="30" ;;
                255.255.254.0)   CIDR="23" ;;
                255.255.252.0)   CIDR="22" ;;
                255.255.248.0)   CIDR="21" ;;
                255.255.240.0)   CIDR="20" ;;
                255.255.0.0)     CIDR="16" ;;
                255.0.0.0)       CIDR="8" ;;
                *)               CIDR="24" ;;  # Default to /24
            esac

            # Configure IP address
            ip addr add "${IPV4_ADDR}/${CIDR}" dev "$IFACE_NAME" 2>/dev/null || true

            # Add default route
            ip route add default via "$IPV4_GW" 2>/dev/null || true

            # Configure DNS
            if [ -n "$DNS_SERVERS" ]; then
                log "Configuring DNS: $DNS_SERVERS"
                : > /etc/resolv.conf
                for dns in $DNS_SERVERS; do
                    echo "nameserver $dns" >> /etc/resolv.conf
                done
            fi

            log "Static network configuration complete"
            ip addr show "$IFACE_NAME"
            ip route show
        else
            log "Incomplete static config, falling back to DHCP"
            setup-interfaces -a 2>&1 || true
            rc-service networking start 2>&1 || true
        fi
    else
        log "DHCP or no network type specified, using auto-configuration"
        setup-interfaces -a 2>&1 || true
        rc-service networking start 2>&1 || true
    fi
else
    log "No installer.yaml found, using DHCP"
    setup-interfaces -a 2>&1 || true
    rc-service networking start 2>&1 || true
fi
sleep 2

# Setup repositories
log "Setting up repositories..."
cat > /etc/apk/repositories << 'REPOEOF'
http://dl-cdn.alpinelinux.org/alpine/v3.22/main
http://dl-cdn.alpinelinux.org/alpine/v3.22/community
REPOEOF

# Update package index
log "Updating package index..."
apk update || error "Failed to update package index"

# Install required packages
log "Installing disk management tools..."
apk add --no-cache \
    parted \
    e2fsprogs \
    e2fsprogs-extra \
    lvm2 \
    device-mapper \
    dosfstools \
    util-linux \
    kmod \
    eudev || error "Failed to install required packages"

# Install glibc compatibility layer for platformd binary
log "Installing glibc compatibility layer..."
apk add --no-cache gcompat libc6-compat || log "Warning: glibc compatibility packages may not be fully available"

# Install OpenSSL libraries needed by platformd
log "Installing OpenSSL libraries..."
apk add --no-cache openssl-dev || log "Warning: OpenSSL dev package not available"

# Install SoftHSM if the platform config references it
if grep -q "libsofthsm" /media/cdrom/configs/*.yaml 2>/dev/null; then
    log "Platform config references SoftHSM, installing softhsm package..."
    apk add --no-cache softhsm || log "Warning: SoftHSM package not available"
else
    log "SoftHSM not referenced in config, skipping installation"
fi

log "Required packages installed successfully"
sync
sleep 1

# Find platformd binary (single binary for all operations)
PLATFORM_BIN=""
if [ -x /usr/bin/platformd ]; then
    PLATFORM_BIN="/usr/bin/platformd"
    log "Found platformd in /usr/bin"
elif [ -x /media/cdrom/platformd-bin/platformd ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformd"
    log "Found platformd on CD-ROM"
else
    error "platformd binary not found"
fi

# Resolve installer configuration using priority chain
resolve_config
log "Using installer configuration: $INSTALLER_CONFIG"

# Detect target installation disk
# Check for disk specified in config or kernel cmdline first
INSTALL_DISK=$(cmdline_param "install_disk" "")

if [ -z "$INSTALL_DISK" ] && [ -n "$INSTALLER_CONFIG" ]; then
    # Try to read disk device from config
    CFG_DISK=$(grep "device:" "$INSTALLER_CONFIG" 2>/dev/null | head -1 | sed 's/.*device:\s*//' | tr -d ' "')
    if [ -n "$CFG_DISK" ] && [ -b "$CFG_DISK" ]; then
        INSTALL_DISK="$CFG_DISK"
    fi
fi

# Auto-detect if not specified
if [ -z "$INSTALL_DISK" ]; then
    log "Auto-detecting installation disk..."
    # List all available block devices for debugging
    log "Available block devices:"
    lsblk -d -o NAME,SIZE,TYPE,TRAN,RO,RM,MODEL 2>/dev/null | while read line; do log "  $line"; done

    # Find a suitable installation disk:
    # - Must be a disk (not partition, cdrom, or loop)
    # - Must NOT be removable (RM=0) to skip BMC virtual media
    # - Must NOT be read-only (RO=0)
    # - Must be larger than 8GB (skip small USB drives and virtual CDs)
    # - Prefer SATA/NVMe over virtio
    for disk in /dev/sda /dev/sdb /dev/sdc /dev/nvme0n1 /dev/vda; do
        if [ ! -b "$disk" ]; then
            continue
        fi

        # Skip removable devices (BMC virtual CD-ROM appears as removable SCSI disk)
        REMOVABLE=$(cat /sys/block/$(basename $disk)/removable 2>/dev/null || echo "1")
        if [ "$REMOVABLE" = "1" ]; then
            log "  Skipping $disk (removable device - likely virtual CD)"
            continue
        fi

        # Skip read-only devices
        READONLY=$(cat /sys/block/$(basename $disk)/ro 2>/dev/null || echo "1")
        if [ "$READONLY" = "1" ]; then
            log "  Skipping $disk (read-only device)"
            continue
        fi

        # Skip small devices (< 8GB) to avoid installing on USB or virtual media
        SIZE_BYTES=$(cat /sys/block/$(basename $disk)/size 2>/dev/null || echo "0")
        SIZE_GB=$((SIZE_BYTES * 512 / 1024 / 1024 / 1024))
        if [ "$SIZE_GB" -lt 8 ]; then
            log "  Skipping $disk (${SIZE_GB}GB - too small, minimum 8GB)"
            continue
        fi

        INSTALL_DISK="$disk"
        log "Found installation target: $INSTALL_DISK (${SIZE_GB}GB, non-removable)"
        break
    done
fi

if [ -z "$INSTALL_DISK" ]; then
    error "No installation disk found. Available devices: $(ls /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null | tr '\n' ' ')"
fi

log "Installing Alpine Linux with TPM-based disk encryption"
log "Target disk: $INSTALL_DISK"

# Build installation command (using consolidated platformd binary)
# If installer config exists, use it; otherwise use command-line flags
# In debug mode, ask the installer for slog.LevelDebug + dracut -v output.
# The Go installer reads --debug and passes -v to dracut and other subcommands.
DEBUG_FLAG=""
if [ "$PLATFORM_DEBUG" = "1" ]; then
    DEBUG_FLAG="--debug"
    log "Debug mode active — installer will use --debug flag"
fi

# CRITICAL: the install command lives on `platformctl`, NOT `platformd`.
# The previous version of this script called `$PLATFORM_BIN initrd
# system-install` which is a non-existent cobra command — cobra silently
# treated the args as positional, ran the bare `platformd` (which prints
# help and exits 0), and reported "Installation completed successfully"
# while NOTHING was actually installed. This is what was leaving the ESP
# empty on every install. Use platformctl install system instead.
INSTALL_BIN=""
if [ -x /media/cdrom/platformd-bin/platformctl-static ]; then
    INSTALL_BIN="/media/cdrom/platformd-bin/platformctl-static"
elif [ -x /media/cdrom/platformd-bin/platformctl ]; then
    INSTALL_BIN="/media/cdrom/platformd-bin/platformctl"
elif [ -x /usr/bin/platformctl ]; then
    INSTALL_BIN="/usr/bin/platformctl"
else
    error "platformctl binary not found — cannot run install. Searched: \
/media/cdrom/platformd-bin/platformctl-static, \
/media/cdrom/platformd-bin/platformctl, \
/usr/bin/platformctl"
fi
log "Using install binary: $INSTALL_BIN"
$INSTALL_BIN install system --help >/dev/null 2>&1 || \
    error "platformctl install system command not registered in this build — \
the binary at $INSTALL_BIN is missing the install subcommand."

if [ -n "$INSTALLER_CONFIG" ]; then
    log "Using installer configuration file: $INSTALLER_CONFIG"
    sleep 1
    log "Building installation command..."
    # Config file provides defaults, but password must be provided via flag for automated mode
    INSTALL_CMD="$INSTALL_BIN install system \
        --config \"$INSTALLER_CONFIG\" \
        --disk \"$INSTALL_DISK\" \
        --password \"password\" \
        --root-password \"password\" \
        --verbose $DEBUG_FLAG"
    log "Installation command built successfully"
else
    INSTALL_CMD="$INSTALL_BIN install system \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --password \"password\" \
        --root-password \"password\" \
        --hostname \"trusted-platform\" \
        --verbose $DEBUG_FLAG"

fi

# Add additional flags if not using config file
if [ -z "$INSTALLER_CONFIG" ]; then
fi

# Execute the installation command
log "About to execute installation command..."
sleep 1
log "Command: $INSTALL_CMD"
sleep 1
log "Starting installation now..."
eval "$INSTALL_CMD" 2>&1 | tee /tmp/install.log

INSTALL_RESULT=$?
log "Installation command exited with code: $INSTALL_RESULT"
sleep 1

if [ $INSTALL_RESULT -eq 0 ]; then
    log "Installation completed successfully"

    # Write loaded kernel modules to installed system's /etc/modules
    # so NICs and other hardware drivers load on boot
    # The Go installer unmounts /mnt and closes LUKS before returning,
    # so we must re-open LUKS, activate LVM, and mount.
    # Disable set -e for this block since mount/crypto commands may fail
    set +e
    log "Persisting kernel modules to installed system..."
    LVM_DEV="/dev/mapper/vg0-root"
    MOUNTED=false

    # Try to re-open LUKS and activate LVM
    if [ -n "$INSTALL_DISK" ]; then
        # The root partition is partition 2 on GPT (partition 1 is EFI)
        LUKS_PART="${INSTALL_DISK}2"
        # For NVMe, partition names use p2 not just 2
        if echo "$INSTALL_DISK" | grep -q "nvme"; then
            LUKS_PART="${INSTALL_DISK}p2"
        fi

        log "  Re-opening LUKS on $LUKS_PART..."
        echo -n "password" | cryptsetup luksOpen "$LUKS_PART" cryptroot --key-file=- 2>/dev/null
        if [ $? -eq 0 ]; then
            log "  LUKS opened"
            vgchange -ay vg0 2>/dev/null
            sleep 1
            if [ -b "$LVM_DEV" ]; then
                mount "$LVM_DEV" /mnt 2>/dev/null
                if [ -d /mnt/etc ]; then
                    MOUNTED=true
                    log "  Rootfs mounted at /mnt"
                fi
            fi
        else
            log "  Could not open LUKS (may already be closed)"
        fi
    fi

    if [ "$MOUNTED" = "true" ]; then
        # Append all modules we loaded during install (skip built-in modules)
        for mod in igb ixgbe e1000e i40e ice mlx5_core bnxt_en; do
            if lsmod 2>/dev/null | grep -q "^${mod} "; then
                if ! grep -q "^${mod}$" /mnt/etc/modules 2>/dev/null; then
                    echo "$mod" >> /mnt/etc/modules
                    log "  Added module: $mod"
                fi
            fi
        done
        # Also add any modules from the installer config
        if [ -n "$INSTALLER_CONFIG" ]; then
            CONFIG_MODULES=$(grep -A20 "kernel-modules:" "$INSTALLER_CONFIG" 2>/dev/null | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "')
            for mod in $CONFIG_MODULES; do
                if ! grep -q "^${mod}$" /mnt/etc/modules 2>/dev/null; then
                    echo "$mod" >> /mnt/etc/modules
                    log "  Added module from config: $mod"
                fi
            done
        fi
        log "Modules written to /mnt/etc/modules:"
        cat /mnt/etc/modules 2>/dev/null | while read line; do log "  $line"; done

        # Unmount and close LUKS after writing modules
        sync
        umount /mnt 2>/dev/null || true
        vgchange -an vg0 2>/dev/null || true
        cryptsetup luksClose cryptroot 2>/dev/null || true
        log "Rootfs unmounted after module persistence"
    else
        log "WARNING: Could not mount rootfs to persist kernel modules"
        log "  Kernel modules may need to be loaded manually on first boot"
    fi
    set -e

    # After-install action. Managed nodes (a BMC/board controller drives the
    # post-install disk boot) use "poweroff" — the orchestrator unmounts media,
    # sets disk boot, and powers the node back on. Unmanaged nodes (Raspberry
    # Pi, USB/self-boot, PXE with no BMC) MUST use "reboot" so the node boots
    # the freshly-installed OS on its own — nothing else can power it on.
    # Selected via the platform_after_install kernel cmdline param; defaults to
    # poweroff to preserve managed behaviour.
    AFTER_INSTALL=$(cmdline_param "platform_after_install" "poweroff")
    if [ "$AFTER_INSTALL" != "reboot" ] && [ "$AFTER_INSTALL" != "poweroff" ]; then
        log "WARNING: invalid platform_after_install='$AFTER_INSTALL', defaulting to poweroff"
        AFTER_INSTALL="poweroff"
    fi
    log "System will $AFTER_INSTALL after install (platform_after_install=$AFTER_INSTALL)..."
    # CRITICAL: Properly unmount filesystems and sync before the final action
    # to ensure all data (especially installer.luks on EFI) is written to disk
    log "Syncing filesystems before unmount..."
    sync

    # DEBUG: Verify LUKS header exists before unmount
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes before unmount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID before unmount"
        else
            log "DEBUG: LUKS header MISSING before unmount!"
        fi
    else
        log "DEBUG: installer.luks NOT FOUND before unmount!"
    fi

    log "Unmounting EFI partition..."
    umount /mnt/boot/efi 2>/dev/null || true
    sync

    # DEBUG: Remount and verify again to ensure write went through
    mount ${INSTALL_DISK}1 /mnt/boot/efi 2>/dev/null || true
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes after remount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID after remount - data persisted!"
        else
            log "DEBUG: LUKS header MISSING after remount! Write did NOT persist!"
        fi
    fi
    umount /mnt/boot/efi 2>/dev/null || true

    log "Unmounting remaining filesystems..."
    umount /mnt/proc 2>/dev/null || true
    umount /mnt/sys 2>/dev/null || true
    umount /mnt/dev 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    sync
    sleep 3
    if [ "$AFTER_INSTALL" = "reboot" ]; then
        log "Rebooting in 60 seconds into the installed OS (check console for errors)..."
        sleep 60
        reboot
    else
        log "Powering off in 60 seconds (check console for errors)..."
        sleep 60
        poweroff
    fi
else
    log "INSTALLATION FAILED - check /tmp/install.log for details"
    log "Install log contents:"
    tail -50 /tmp/install.log 2>/dev/null
    log "Dropping to shell for debugging. Type 'poweroff' to shut down."
    /bin/sh
fi

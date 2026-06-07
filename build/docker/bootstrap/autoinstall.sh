#!/bin/sh
# Automated installation script with platformd integration
set -e

INSTALL_LOG="/tmp/autoinstall-debug.log"
log() {
    echo "[autoinstall] $1"
    echo "[autoinstall] $1" >> "$INSTALL_LOG" 2>/dev/null || true
    echo "[autoinstall] $1" > /dev/kmsg 2>/dev/null || true
    sync
}

# Log kernel cmdline immediately for debugging
echo "=== KERNEL CMDLINE ===" >> "$INSTALL_LOG"
cat /proc/cmdline >> "$INSTALL_LOG" 2>/dev/null
echo "=== NETWORK STATE ===" >> "$INSTALL_LOG"
ip addr >> "$INSTALL_LOG" 2>/dev/null
echo "=== ISO BUILD TIMESTAMP ===" >> "$INSTALL_LOG"
date >> "$INSTALL_LOG" 2>/dev/null

error() {
    echo "[autoinstall] ERROR: $1" >&2
    echo "[autoinstall] ERROR: $1" > /dev/kmsg 2>/dev/null || true
    sync
    exit 1
}

# resolve_platform_hostname extracts os.hostname from the embedded
# platformd config file. The config is the single source of truth for
# every node-specific field; the installer reads it from the ISO at
# /etc/platformd/config.yaml (copied in by the iso customizer) or from
# the fetch cache in dynamic-config mode (/etc/platformd/config.yaml
# written by the dynamic-config fetcher before autoinstall runs).
#
# Returns the hostname string on stdout, empty string if not set.
# Falls back to the Alpine live env's hostname command only when the
# config file is missing entirely — which only happens in development
# or misconfigured builds.
#
# Shell-native YAML scan: looks for the first indented "hostname:" key
# inside the top-level "os:" block. Handles quoted and unquoted values.
# Avoids python/yq dependencies because the live installer environment
# has neither.
resolve_platform_hostname() {
    # Priority -1: per-MAC hostname published by the orchestrator to the
    # pxeboot HTTP server at /config/mac/<mac>/hostname. Overrides the
    # shared-ISO baked-in value because a single ISO is used for all
    # nodes in a deployment. The orchestrator knows each node's target
    # hostname from bootstrap.yaml and publishes it under every MAC the
    # BMC enumerated, so this hit succeeds regardless of which NIC eth0
    # maps to in the live ISO. Best-effort with short timeouts: if the
    # sink is unreachable we fall through to the cmdline/YAML paths
    # and the node gets the generic baked hostname.
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -n "$SINK" ]; then
        # Iterate EVERY local eth*/en* interface and try each MAC against
        # the orchestrator's per-MAC hostname endpoint. Multi-NIC hosts
        # (common: Supermicro X10 has up to 4 onboard + add-in cards)
        # may have a primary NIC whose MAC differs from whatever was
        # hand-entered in bootstrap.yaml. The orchestrator stages the
        # hostname under every MAC it knows, so the first MAC that
        # matches wins. Without this loop a node with a different
        # primary-NIC MAC than the YAML-configured MAC never finds its
        # per-node hostname and falls back to the generic baked value.
        for iface in /sys/class/net/eth* /sys/class/net/en*; do
            [ -e "$iface" ] || continue
            MAC_RAW=$(cat "$iface/address" 2>/dev/null)
            [ -n "$MAC_RAW" ] || continue
            MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
            [ ${#MAC_LC} -eq 12 ] || continue
            MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
            if command -v curl >/dev/null 2>&1; then
                HN_MAC=$(curl --silent --max-time 5 "http://${SINK}/config/mac/${MAC_PATH}/hostname" 2>/dev/null)
            else
                HN_MAC=$(wget -qO- -T 5 "http://${SINK}/config/mac/${MAC_PATH}/hostname" 2>/dev/null)
            fi
            HN_MAC=$(echo "$HN_MAC" | tr -d '[:space:]')
            if [ -n "$HN_MAC" ] && [ "${HN_MAC:0:1}" != "<" ]; then
                echo "[autoinstall] resolved hostname from orchestrator config: ${HN_MAC} (mac=${MAC_PATH})" > /dev/kmsg 2>/dev/null || true
                echo "$HN_MAC"
                return 0
            fi
        done
    fi

    # Priority 0: kernel cmdline platform_hostname=<value>. Baked into
    # the GRUB cmdline at ISO-build time from the merged platformd
    # config's os.hostname field. /proc/cmdline is always readable, no
    # filesystem mounts or YAML parsing needed — the most robust path.
    for param in $(cat /proc/cmdline 2>/dev/null); do
        case "$param" in
            platform_hostname=*)
                HN_CMDLINE="${param#platform_hostname=}"
                if [ -n "$HN_CMDLINE" ]; then
                    echo "$HN_CMDLINE"
                    return 0
                fi
                ;;
        esac
    done

    # Fallback candidate YAML paths, in preference order:
    # 1. The installer.Config yaml in the overlay — populated by
    #    buildInstallerConfig with hostname sourced from the merged
    #    platformd config. This is the canonical runtime path under
    #    the live Alpine environment.
    # 2. The merged platformd config on the CD mount (legacy/fallback).
    CFG="/etc/platformd/install.yaml"
    [ ! -f "$CFG" ] && CFG="/etc/platformd/config.yaml"
    [ ! -f "$CFG" ] && CFG="/media/cdrom/configs/installer.yaml"
    [ ! -f "$CFG" ] && CFG="/mnt/cdrom/configs/installer.yaml"
    if [ -f "$CFG" ]; then
        # awk scan: track when we enter the "os:" block at indent 0,
        # then emit the first indented "hostname:" value we see before
        # we hit another top-level key.
        HN=$(awk '
            /^os:[[:space:]]*$/ { inos = 1; next }
            /^[a-zA-Z]/        { if (inos) { inos = 0 } }
            inos && /^[[:space:]]+hostname:/ {
                sub(/^[[:space:]]+hostname:[[:space:]]*/, "")
                gsub(/["'"'"']/, "")
                sub(/[[:space:]]+$/, "")
                print
                exit
            }
        ' "$CFG" 2>/dev/null)
        if [ -n "$HN" ]; then
            echo "$HN"
            return 0
        fi
    fi
    # Final fallback: Alpine live env hostname command. Usually returns
    # (none) or localhost; the caller normalizes those to "unknown".
    hostname 2>/dev/null
}

# fetch_orchestrator_ca_bundle pulls the control-plane CA bundle from the
# orchestrator's per-MAC config endpoint and saves it to
# /tmp/cp-ca-bundle.pem. Called BEFORE the installer runs so the
# post-install chroot can install it into the system trust store.
#
# The orchestrator stages the bundle at /config/mac/<MAC>/ca-bundle.pem
# for every non-CP node it provisions. Without this delivery, GW and
# compute nodes boot with no trust anchor for the CP's local CA, which
# makes their first ACME enrollment attempt fail with
# "x509: certificate signed by unknown authority" — they then fall
# back to issuing their own local CA and never enroll with the cluster.
#
# Mirrors resolve_platform_hostname's MAC iteration loop so multi-NIC
# hosts (Supermicro X10 onboard quad NIC + add-in cards) find their
# orchestrator-staged value regardless of which interface enumerates
# as eth0. Best-effort: failure here logs a warning and the install
# continues — the runtime BootstrapTrust path can still recover via
# DANE/Noise/SPKI when configured.
fetch_orchestrator_ca_bundle() {
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -z "$SINK" ]; then
        echo "[autoinstall] no orchestrator sink resolved - CA bundle delivery skipped" > /dev/kmsg 2>/dev/null || true
        return 1
    fi

    # Iterate every local NIC's MAC and try the orchestrator-staged
    # bundle path. First successful fetch wins.
    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] || continue
        MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#MAC_LC} -eq 12 ] || continue
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        URL="http://${SINK}/config/mac/${MAC_PATH}/ca-bundle.pem"
        if command -v curl >/dev/null 2>&1; then
            curl --silent --show-error --max-time 10 --fail -o /tmp/cp-ca-bundle.pem.tmp "$URL" 2>/dev/null
            RC=$?
        elif command -v wget >/dev/null 2>&1; then
            wget --quiet --timeout=10 -O /tmp/cp-ca-bundle.pem.tmp "$URL" 2>/dev/null
            RC=$?
        else
            return 1
        fi
        if [ "$RC" -eq 0 ] && [ -s /tmp/cp-ca-bundle.pem.tmp ]; then
            # Sanity check — must contain a PEM CERTIFICATE block, not
            # an HTML 404 page from a misconfigured pxeboot endpoint.
            if grep -q "BEGIN CERTIFICATE" /tmp/cp-ca-bundle.pem.tmp; then
                mv /tmp/cp-ca-bundle.pem.tmp /tmp/cp-ca-bundle.pem
                echo "[autoinstall] fetched orchestrator CA bundle from ${URL} ($(wc -c < /tmp/cp-ca-bundle.pem) bytes)" > /dev/kmsg 2>/dev/null || true
                return 0
            fi
        fi
        rm -f /tmp/cp-ca-bundle.pem.tmp
    done
    echo "[autoinstall] no orchestrator CA bundle staged for any local MAC - skipped" > /dev/kmsg 2>/dev/null || true
    return 1
}

# fetch_orchestrator_spki_pin pulls the orchestrator-staged SPKI pin
# (base64-std SHA-256 of the CP CA's SPKI) from the per-MAC config
# endpoint and saves it to /tmp/cp-spki-pin. The post-install mount
# block writes it into /etc/trusted-platform/bootstrap-spki-pin so the
# platform's BootstrapTrust SPKI strategy has a value to pin against.
#
# This is the parallel "trust anchor" delivery path to ca-bundle.pem.
# The bundle path is preferred when it succeeds (no per-request DNS
# round-trip on every TLS handshake), but the pin path survives in
# scenarios where the orchestrator HTTP endpoint can serve TXT-style
# values but not large binary bundles (rare but historically real on
# embedded CGI stacks). They are independent and either is sufficient.
fetch_orchestrator_spki_pin() {
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    [ -z "$SINK" ] && return 1

    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] || continue
        MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#MAC_LC} -eq 12 ] || continue
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        URL="http://${SINK}/config/mac/${MAC_PATH}/bootstrap-spki-pin"
        if command -v curl >/dev/null 2>&1; then
            PIN=$(curl --silent --show-error --max-time 5 --fail "$URL" 2>/dev/null)
        elif command -v wget >/dev/null 2>&1; then
            PIN=$(wget --quiet --timeout=5 -O- "$URL" 2>/dev/null)
        else
            return 1
        fi
        PIN=$(echo "$PIN" | tr -d '[:space:]')
        # Sanity check: base64-encoded SHA-256 is exactly 44 chars and
        # matches [A-Za-z0-9+/]{43}=. Reject anything else (HTML 404,
        # garbage, empty body) so we never persist a malformed pin.
        case "$PIN" in
            ?????????????????????????????????????????????) ;;
            *) continue ;;
        esac
        echo "$PIN" > /tmp/cp-spki-pin
        echo "[autoinstall] fetched orchestrator SPKI pin from ${URL} (${#PIN} chars)" > /dev/kmsg 2>/dev/null || true
        return 0
    done
    echo "[autoinstall] no orchestrator SPKI pin staged for any local MAC - skipped" > /dev/kmsg 2>/dev/null || true
    return 1
}

# upload_install_log uploads /tmp/install.log to the bootstrap container's
# HTTP forensic sink. Resolves the sink in this order:
#   1. Kernel cmdline platform_debug_sink=host:port
#   2. The DHCP server IP from the dhclient lease (the bootstrap container
#      IS the DHCP server in our deployment, so this is always reachable)
#   3. The default gateway as a last resort
# Best-effort: a failed upload logs a warning and returns 0 so the
# surrounding cleanup continues unchanged.
upload_install_log() {
    upload_install_log_with_code "$?"
}

# upload_install_log_with_code is the implementation. The trap calls this
# directly with the exit code captured BEFORE upload_checkpoint runs, so we
# don't lose the original install exit code in the postmortem.
upload_install_log_with_code() {
    INSTALL_EXIT_CODE="$1"
    [ -z "$INSTALL_EXIT_CODE" ] && INSTALL_EXIT_CODE=0
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        if [ -n "$DHCP_SERVER" ]; then
            SINK="${DHCP_SERVER}:8080"
        fi
    fi

    if [ -z "$SINK" ]; then
        echo "[autoinstall] no upload sink resolved - install.log will NOT be uploaded" > /dev/kmsg 2>/dev/null || true
        set -e
        return $INSTALL_EXIT_CODE
    fi

    # Identifier for the upload path. Primary: MAC of the first usable
    # ethernet interface (stable, always-known, survives the generic
    # "server" hostname baked into shared ISOs). Fallback: resolved
    # platform hostname. MAC beats hostname because the orchestrator
    # side knows each node's MAC from bootstrap.yaml but has no way to
    # know which generic hostname a shared ISO baked in.
    MAC_RAW=""
    for iface in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$iface" ] || continue
        MAC_RAW=$(cat "$iface/address" 2>/dev/null)
        [ -n "$MAC_RAW" ] && break
    done
    MAC_LC=$(echo "$MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
    # Format as aa-bb-cc-dd-ee-ff when we have exactly 12 hex chars.
    MAC_PATH=""
    if [ ${#MAC_LC} -eq 12 ]; then
        MAC_PATH=$(echo "$MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
    fi

    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    # Primary upload URL (MAC-keyed when we have one) and fallback
    # (hostname-keyed). Both are attempted — the MAC path is what the
    # orchestrator polls; the hostname path is kept for human
    # debugging and backward compat.
    if [ -n "$MAC_PATH" ]; then
        URL="http://${SINK}/installs/mac/${MAC_PATH}/install.log"
    else
        URL="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    fi
    URL_FALLBACK="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    echo "[autoinstall] uploading install.log to ${URL} (exit=${INSTALL_EXIT_CODE})" > /dev/kmsg 2>/dev/null || true

    # Append a postmortem manifest with hardware/system context. Invaluable
    # for diagnosing install failures after the live env is gone.
    {
        echo ""
        echo "=== POSTMORTEM MANIFEST ==="
        echo "exit_code: ${INSTALL_EXIT_CODE}"
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        echo "hostname: ${HOSTNAME_LC}"
        echo "kernel_cmdline: $(cat /proc/cmdline 2>/dev/null)"
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
        echo "--- dmesg tail ---"
        dmesg 2>&1 | tail -200 || true
        echo ""
        echo "=== END POSTMORTEM ==="
    } >> /tmp/install.log 2>/dev/null || true

    # Upload to primary URL (MAC-keyed) and, when that differs from the
    # hostname-keyed URL, ALSO upload to the fallback path. The pxeboot
    # HTTP sink accepts both; the orchestrator will find whichever
    # matches its poll path first.
    _upload_one_url() {
        _U="$1"
        if command -v curl >/dev/null 2>&1; then
            curl --silent --show-error --max-time 30 \
                 --request PUT --upload-file /tmp/install.log "${_U}" \
                 > /dev/kmsg 2>&1 || \
                echo "[autoinstall] curl PUT to ${_U} failed (continuing)" > /dev/kmsg 2>/dev/null || true
        else
            BODY_LEN=$(wc -c < /tmp/install.log 2>/dev/null || echo 0)
            HOST_PART="${SINK%:*}"
            PORT_PART="${SINK##*:}"
            # Extract path from URL: strip scheme://host:port prefix.
            _PATH=$(echo "$_U" | sed 's|^[^/]*//[^/]*||')
            {
                printf 'PUT %s HTTP/1.1\r\n' "${_PATH}"
                printf 'Host: %s\r\n' "${SINK}"
                printf 'Content-Length: %s\r\n' "${BODY_LEN}"
                printf 'Connection: close\r\n'
                printf 'Content-Type: text/plain\r\n'
                printf '\r\n'
                cat /tmp/install.log 2>/dev/null
            } | nc -w 30 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
                echo "[autoinstall] nc PUT to ${_U} failed (continuing)" > /dev/kmsg 2>/dev/null || true
        fi
    }

    _upload_one_url "${URL}"
    if [ -n "${URL_FALLBACK}" ] && [ "${URL_FALLBACK}" != "${URL}" ]; then
        _upload_one_url "${URL_FALLBACK}"
    fi

    echo "[autoinstall] upload attempt complete" > /dev/kmsg 2>/dev/null || true
    set -e
    return $INSTALL_EXIT_CODE
}

# upload_checkpoint uploads a tiny heartbeat file to mark that the script
# reached this stage. Used at multiple points (script-start, pre-install,
# post-install, success, failure) so we can pinpoint which stage the install
# is dying at when the full install.log doesn't make it off the box.
upload_checkpoint() {
    CHECKPOINT_NAME="$1"
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        [ -z "$DHCP_SERVER" ] && DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -z "$SINK" ]; then
        echo "[checkpoint:$CHECKPOINT_NAME] no sink resolved" > /dev/kmsg 2>/dev/null || true
        set -e
        return
    fi

    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    PAYLOAD="checkpoint=$CHECKPOINT_NAME timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date) sink=$SINK"
    URL="http://${SINK}/installs/${HOSTNAME_LC}/checkpoint-${CHECKPOINT_NAME}.txt"
    echo "[checkpoint:$CHECKPOINT_NAME] PUT $URL" > /dev/kmsg 2>/dev/null || true

    if command -v curl >/dev/null 2>&1; then
        printf '%s\n' "$PAYLOAD" | curl --silent --show-error --max-time 10 \
             --request PUT --data-binary @- "${URL}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] curl failed" > /dev/kmsg 2>/dev/null || true
    else
        BODY_LEN=$(printf '%s\n' "$PAYLOAD" | wc -c)
        HOST_PART="${SINK%:*}"
        PORT_PART="${SINK##*:}"
        {
            printf 'PUT /installs/%s/checkpoint-%s.txt HTTP/1.1\r\n' "${HOSTNAME_LC}" "${CHECKPOINT_NAME}"
            printf 'Host: %s\r\n' "${SINK}"
            printf 'Content-Length: %s\r\n' "${BODY_LEN}"
            printf 'Connection: close\r\n'
            printf '\r\n'
            printf '%s\n' "$PAYLOAD"
        } | nc -w 10 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] nc failed" > /dev/kmsg 2>/dev/null || true
    fi
    set -e
}

# Trap upload + log exit on EVERY exit path. CRITICAL: capture $? FIRST
# and pass it explicitly to upload_install_log, otherwise running
# upload_checkpoint first clobbers $? to its own success exit code (0)
# and the postmortem reports exit_code:0 even when the install actually
# failed. This is exactly the bug that masked the original UKI build
# failure as "successful install" — every checkpoint says success because
# the original install error was overwritten before the trap reached the
# upload step.
trap 'TRAP_RC=$?; upload_checkpoint exit-trap; upload_install_log_with_code "$TRAP_RC"; echo "[autoinstall] script exiting with status $TRAP_RC" > /dev/kmsg 2>/dev/null' EXIT INT TERM

# CHECKPOINT 1: script started. If this never lands on the bootstrap host,
# the autoinstall.sh isn't running at all (init/inittab problem).
upload_checkpoint script-start

log "Starting platformd system installation..."

# Load common bare metal NIC drivers before configuring network
log "Loading kernel modules for bare metal NICs..."
for mod in igb ixgbe e1000e i40e ice; do
    modprobe "$mod" 2>/dev/null && log "  Loaded: $mod" || true
done
sleep 2

# Configure networking from installer.yaml if available
log "Configuring network..."
INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
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

            # Configure DNS for install-time. The post-install platformd
            # commonly points at 127.0.0.1 (local dnsmasq), but the live
            # install environment has no resolver — apk update would fail
            # against external mirrors. Drop loopback during install AND
            # always append the IPv4 gateway as a working fallback so apk
            # can resolve the mirror. The post-install OS gets the original
            # /etc/resolv.conf written from the YAML in a later step.
            if [ -n "$DNS_SERVERS" ] || [ -n "$IPV4_GW" ]; then
                log "Configuring install-time DNS"
                : > /etc/resolv.conf
                for dns in $DNS_SERVERS; do
                    case "$dns" in
                        127.*|::1)
                            log "  skipping loopback DNS $dns (no resolver in live env)"
                            ;;
                        *)
                            echo "nameserver $dns" >> /etc/resolv.conf
                            log "  nameserver $dns"
                            ;;
                    esac
                done
                if [ -n "$IPV4_GW" ]; then
                    echo "nameserver $IPV4_GW" >> /etc/resolv.conf
                    log "  nameserver $IPV4_GW (gateway fallback)"
                fi
                # If still empty (no DNS, no gateway), fall back to public.
                if [ ! -s /etc/resolv.conf ]; then
                    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
                    log "  nameserver 8.8.8.8 (last-resort fallback)"
                fi
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

# Mount the ISO/CD-ROM if not already mounted
log "Mounting boot media..."
mkdir -p /media/cdrom
if ! mountpoint -q /media/cdrom 2>/dev/null; then
    mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
    mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || \
    log "Warning: Could not mount CD-ROM, packages may not be available offline"
fi

# Setup repositories — local ISO packages only. The ISO ships with a
# complete pre-fetched repository at /apks-prefetch including every
# package the installer needs (parted, lvm2, util-linux, eudev, kmod,
# device-mapper, dosfstools). Network mirrors are intentionally NOT
# configured here because:
#   1. Many install-time networks (bootstrap VLAN, isolated provisioning)
#      cannot reach external mirrors.
#   2. apk update fails fast when ANY configured repo is unreachable, so
#      a network mirror present-but-unreachable poisons the entire flow.
# The original /etc/apk/repositories from the Alpine live env may be
# preserved in /etc/apk/repositories.original for diagnostic reference.
log "Setting up repositories (local-only, offline install)..."
[ -f /etc/apk/repositories ] && cp /etc/apk/repositories /etc/apk/repositories.original 2>/dev/null || true
cat > /etc/apk/repositories << 'REPOEOF'
/media/cdrom/apks
/media/cdrom/apks-prefetch
REPOEOF
log "Updating local package index..."
apk update --allow-untrusted 2>&1 | tail -5 | while IFS= read -r line; do log "  $line"; done || \
    log "Warning: apk update returned non-zero (continuing with cached index)"

# Install required packages from the local pre-fetched repository.
# Capture full apk stderr so failures are debuggable from SOL output.
# Disable set -e around the capture so we can record the exit code and
# stderr instead of letting the script abort silently.
log "Installing disk management tools..."
set +e
APK_OUT=$(apk add --no-cache --allow-untrusted \
    parted \
    e2fsprogs \
    e2fsprogs-extra \
    lvm2 \
    lvm2-libs \
    dosfstools \
    util-linux \
    kmod \
    kmod-libs \
    device-mapper \
    device-mapper-libs \
    device-mapper-event-libs \
    eudev \
    libaio \
    xz-libs \
    zstd-libs \
    readline \
    ncurses-libs 2>&1)
APK_RC=$?
set -e
if [ $APK_RC -ne 0 ]; then
    log "apk add failed with exit code $APK_RC. Output:"
    printf '%s\n' "$APK_OUT" | while IFS= read -r line; do log "  apk> $line"; done
    log "Repositories configured:"
    cat /etc/apk/repositories | while IFS= read -r line; do log "  repo> $line"; done
    log "Available repos on /media/cdrom:"
    ls -la /media/cdrom/apks/x86_64/ 2>&1 | head -3 | while IFS= read -r line; do log "  apks> $line"; done
    ls -la /media/cdrom/apks-prefetch/x86_64/ 2>&1 | head -3 | while IFS= read -r line; do log "  prefetch> $line"; done
    error "Failed to install required packages (apk exit=$APK_RC)"
fi
log "$(printf '%s' "$APK_OUT" | tail -3)"

# Decompression/compression tooling for the initramfs rebuild step. dracut
# can produce gzip, xz, or zstd initramfs depending on kernel CONFIG_RD_*
# and dracut.conf. The Go installer auto-detects the format from magic
# bytes (pkg/installer/installer.go:detectInitramfsDecompressor) and
# shells out to the matching streaming tool. The full set must be
# available in the live env, otherwise the install dies in the UKI
# extract-modify-repack pipeline with an obscure "command not found".
log "Installing initramfs codec tools (gzip/xz/zstd/lz4/lzop)..."
apk add --no-cache --allow-untrusted \
    gzip \
    xz \
    zstd \
    lz4 \
    lzop \
    bzip2 || log "Warning: some initramfs codecs may not be available; install will fail if dracut uses them"

# cpio binary in busybox accepts only short options. The Go installer's
# inject step uses cpio -idm (short form), which IS busybox-compatible.
# Future maintainers: do NOT reintroduce GNU long options like
# --no-absolute-filenames which silently break in busybox.

# Install glibc compatibility layer for platformd binary
log "Installing glibc compatibility layer..."
apk add --no-cache --allow-untrusted gcompat libc6-compat || log "Warning: glibc compatibility packages may not be fully available"

# Install OpenSSL libraries needed by platformd
log "Installing OpenSSL libraries..."
apk add --no-cache --allow-untrusted openssl-dev || log "Warning: OpenSSL dev package not available"

# Install SoftHSM if the platform config references it
if grep -q "libsofthsm" /media/cdrom/configs/*.yaml 2>/dev/null; then
    log "Platform config references SoftHSM, installing softhsm package..."
    apk add --no-cache --allow-untrusted softhsm || log "Warning: SoftHSM package not available"
else
    log "SoftHSM not referenced in config, skipping installation"
fi

log "Required packages installed successfully"
sync
sleep 1

# Load required kernel modules for device-mapper and LUKS
log "Loading kernel modules..."
modprobe dm_mod 2>/dev/null || log "Warning: dm_mod may already be loaded"
modprobe dm_crypt 2>/dev/null || log "Warning: dm_crypt may already be loaded"
modprobe loop 2>/dev/null || log "Warning: loop may already be loaded"

# Trigger udev to create device nodes (including /dev/mapper/control)
log "Triggering udev to create device nodes..."
if command -v udevadm >/dev/null 2>&1; then
    udevadm trigger --type=devices 2>/dev/null || true
    udevadm settle --timeout=10 2>/dev/null || true
fi

# Verify /dev/mapper/control exists
if [ -e /dev/mapper/control ]; then
    log "Device-mapper control node ready: /dev/mapper/control"
else
    # Manually create dm control node if udev didn't
    log "Creating device-mapper control node manually..."
    mkdir -p /dev/mapper
    if [ ! -e /dev/mapper/control ]; then
        # Get dm control major/minor from /proc/misc
        DM_MINOR=$(grep -w "device-mapper" /proc/misc 2>/dev/null | awk '{print $1}')
        if [ -n "$DM_MINOR" ]; then
            mknod /dev/mapper/control c 10 "$DM_MINOR" 2>/dev/null || log "Warning: Could not create control node"
        fi
    fi
fi

# Verify device-mapper is working
if [ -e /dev/mapper/control ]; then
    log "Device-mapper ready"
else
    error "Device-mapper control node not available - LUKS will fail"
fi

# Find platformctl binary (CLI binary for installation operations)
# Prefer static binary for Alpine/musl compatibility
PLATFORM_BIN=""
if [ -x /usr/bin/platformctl-static ]; then
    PLATFORM_BIN="/usr/bin/platformctl-static"
    log "Found platformctl-static in /usr/bin"
elif [ -x /usr/bin/platformctl ]; then
    PLATFORM_BIN="/usr/bin/platformctl"
    log "Found platformctl in /usr/bin"
elif [ -x /media/cdrom/platformd-bin/platformctl-static ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl-static"
    log "Found platformctl-static on CD-ROM"
elif [ -x /media/cdrom/platformd-bin/platformctl ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl"
    log "Found platformctl on CD-ROM"
else
    error "platformctl binary not found"
fi

# Copy the installer binary (platformctl) AND the bundled platformd (which
# the installer re-exec's into the target rootfs) off the virtual CD into
# tmpfs BEFORE invoking the install. The ATEN virtual CD on Supermicro
# X10 regularly glitches partway through a multi-minute install — we see
# kernel messages like:
#   sr0: rw=0, sector=80, nr_sectors = 4 limit=0
#   bio_check_eod: attempt to access beyond end of device
# When the glitch happens while the Go runtime is paging in code from
# mmap'd text sections that live on the CD, the file-backed pages become
# invalid and the next instruction fetch hits a nonexistent physical
# address, raising SIGBUS (bus error code=0x2). Copying to tmpfs
# eliminates all mmap backing from removable media so the process has
# nothing to lose when the CD hiccups.
TMPFS_BIN_DIR=/run/platformd-bin
mkdir -p "$TMPFS_BIN_DIR"
# Re-mount /run as tmpfs only if it isn't already one. On the Alpine
# live ISO /run is typically already tmpfs; on some minimal setups it
# isn't mounted at all.
if ! mountpoint -q /run 2>/dev/null; then
    mount -t tmpfs -o size=128m tmpfs /run 2>/dev/null || true
fi
log "Copying installer binary to tmpfs to isolate from virtual CD glitches"
if cp -f "$PLATFORM_BIN" "$TMPFS_BIN_DIR/platformctl" 2>&1; then
    chmod +x "$TMPFS_BIN_DIR/platformctl"
    PLATFORM_BIN="$TMPFS_BIN_DIR/platformctl"
    log "Installer binary copied: $PLATFORM_BIN"
else
    log "WARNING: tmpfs copy failed, falling back to CD-ROM binary path"
fi
# Same treatment for the platformd binary that the installer embeds
# into the target UKI. The installer reads this at install time so a
# mid-install CD glitch here also crashes the process.
if [ -f /media/cdrom/platformd-bin/platformd ]; then
    if cp -f /media/cdrom/platformd-bin/platformd "$TMPFS_BIN_DIR/platformd" 2>&1; then
        chmod +x "$TMPFS_BIN_DIR/platformd"
        log "platformd binary copied to tmpfs: $TMPFS_BIN_DIR/platformd"
    fi
fi

# Find installer configuration file
# Priority 1: Fetch from control plane via platform_config= kernel param
# Priority 2: Embedded in ISO at /media/cdrom/configs/installer.yaml
INSTALLER_CONFIG=""

# Read platform_config URL from kernel cmdline
PLATFORM_CONFIG_URL=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        platform_config=*) PLATFORM_CONFIG_URL="${param#platform_config=}" ;;
    esac
done

if [ -n "$PLATFORM_CONFIG_URL" ]; then
    log "Config source: kernel param platform_config=$PLATFORM_CONFIG_URL"

    # Bring up network with DHCP if not already up. Do this BEFORE MAC
    # enumeration so interfaces that are plumbed but not yet up still
    # get their MAC returned by ip link.
    if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
        log "Bringing up eth0 with DHCP for config fetch..."
        ip link set eth0 up 2>/dev/null
        udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null || true
    fi

    # Build the list of candidate MACs from all local NICs. The
    # bootstrap orchestrator publishes each node's merged config under
    # EVERY MAC it knows about (YAML + BMC-discovered), so we try each
    # local MAC against the config server and the first 2xx wins.
    #
    # See docs/bootstrap/config-delivery.md §3 for the URL shape and
    # docs/architecture/bootstrap-flow.md §6 for the per-MAC keying
    # rationale.
    CA_BUNDLE="/media/cdrom/configs/ca-bundle.pem"
    WGET_OPTS="--no-check-certificate"
    if [ -f "$CA_BUNDLE" ]; then
        WGET_OPTS="--ca-certificate=$CA_BUNDLE"
        log "Using CA bundle: $CA_BUNDLE"
    fi

    # Normalize the base URL — strip any trailing slash.
    PLATFORM_CONFIG_BASE="${PLATFORM_CONFIG_URL%/}"

    # Detect URL shape. Path-style (e.g. .../config/mac) expects
    #   <base>/<mac-dashed>/installer.yaml
    # Legacy query-style expects
    #   <base>?mac=<mac-colons>
    # Default to path-style since that is the orchestrator's served
    # endpoint (pkg/ipxe/http_server.go).
    for _iface_path in /sys/class/net/eth* /sys/class/net/en*; do
        [ -e "$_iface_path" ] || continue
        _MAC_RAW=$(cat "$_iface_path/address" 2>/dev/null)
        [ -n "$_MAC_RAW" ] || continue
        _MAC_LC=$(echo "$_MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
        [ ${#_MAC_LC} -eq 12 ] || continue
        _MAC_DASHED=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')
        _MAC_COLONS=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1:\2:\3:\4:\5:\6/')

        # Try path-style (orchestrator convention) first.
        _URL_PATH="${PLATFORM_CONFIG_BASE}/${_MAC_DASHED}/installer.yaml"
        log "Trying config fetch: ${_URL_PATH}"
        if wget -q $WGET_OPTS -O /tmp/platform-config.yaml "$_URL_PATH" 2>&1; then
            if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                INSTALLER_CONFIG="/tmp/platform-config.yaml"
                log "Config fetched from ${_URL_PATH} ($(wc -c < /tmp/platform-config.yaml) bytes)"

                # Also fetch the CP's CA bundle from the same path.
                # Orchestrator publishes it alongside installer.yaml for
                # non-CP nodes so the installer can add the private CA
                # to the OS trust store before first-boot ACME enrollment.
                # 404 is not an error — CP-role nodes don't need it.
                _URL_CA="${PLATFORM_CONFIG_BASE}/${_MAC_DASHED}/ca-bundle.pem"
                if wget -q $WGET_OPTS -O /tmp/ca-bundle.pem "$_URL_CA" 2>&1; then
                    if [ -s /tmp/ca-bundle.pem ] && head -1 /tmp/ca-bundle.pem | grep -q 'BEGIN CERTIFICATE'; then
                        log "CA bundle fetched from ${_URL_CA} ($(wc -c < /tmp/ca-bundle.pem) bytes)"
                    else
                        rm -f /tmp/ca-bundle.pem
                    fi
                fi
                break
            fi
        fi

        # Fall back to legacy query-style for production config-delivery
        # servers that expect ?mac=<colon-mac> (see
        # docs/provisioning/config-delivery.md).
        _URL_QUERY="${PLATFORM_CONFIG_BASE}?mac=${_MAC_COLONS}"
        log "Trying config fetch (legacy): ${_URL_QUERY}"
        if wget -q $WGET_OPTS -O /tmp/platform-config.yaml "$_URL_QUERY" 2>&1; then
            if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                INSTALLER_CONFIG="/tmp/platform-config.yaml"
                log "Config fetched from ${_URL_QUERY} ($(wc -c < /tmp/platform-config.yaml) bytes)"
                break
            fi
        fi
    done

    if [ -z "$INSTALLER_CONFIG" ]; then
        log "WARNING: Dynamic config fetch failed for all local MACs, falling back to embedded config"
    fi
fi

# Priority 1b: Implicit per-MAC config via platform_debug_sink.
# Virtual-media boot has no way to set kernel cmdline params, so the
# orchestrator's per-MAC installer.yaml at the pxeboot HTTP sink
# cannot be reached via platform_config=. When platform_debug_sink is
# set (always true for debug installs) derive the config URL from it
# and retry the per-MAC fetch before falling back to the ISO-baked stub.
if [ -z "$INSTALLER_CONFIG" ]; then
    PLATFORM_DEBUG_SINK=""
    for param in $(cat /proc/cmdline); do
        case "$param" in
            platform_debug_sink=*) PLATFORM_DEBUG_SINK="${param#platform_debug_sink=}" ;;
        esac
    done

    if [ -n "$PLATFORM_DEBUG_SINK" ]; then
        log "Trying per-MAC config via debug sink: http://${PLATFORM_DEBUG_SINK}/config/mac"

        # Reuse the same DHCP bootstrap as Priority 1.
        if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
            log "Bringing up eth0 with DHCP to reach debug sink..."
            ip link set eth0 up 2>/dev/null
            udhcpc -i eth0 -t 10 -T 3 -n 2>/dev/null || true
        fi

        SINK_BASE="http://${PLATFORM_DEBUG_SINK}/config/mac"
        for _iface_path in /sys/class/net/eth* /sys/class/net/en*; do
            [ -e "$_iface_path" ] || continue
            _MAC_RAW=$(cat "$_iface_path/address" 2>/dev/null)
            [ -n "$_MAC_RAW" ] || continue
            _MAC_LC=$(echo "$_MAC_RAW" | tr '[:upper:]' '[:lower:]' | sed 's/[^0-9a-f]//g')
            [ ${#_MAC_LC} -eq 12 ] || continue
            _MAC_DASHED=$(echo "$_MAC_LC" | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3-\4-\5-\6/')

            _URL_PATH="${SINK_BASE}/${_MAC_DASHED}/installer.yaml"
            log "Trying config fetch (debug sink): ${_URL_PATH}"
            if wget -q -O /tmp/platform-config.yaml "$_URL_PATH" 2>&1; then
                if [ -s /tmp/platform-config.yaml ] && ! head -1 /tmp/platform-config.yaml | grep -qE '^<'; then
                    INSTALLER_CONFIG="/tmp/platform-config.yaml"
                    log "Config fetched from ${_URL_PATH} ($(wc -c < /tmp/platform-config.yaml) bytes)"

                    # Also fetch matching CA bundle (best-effort).
                    _URL_CA="${SINK_BASE}/${_MAC_DASHED}/ca-bundle.pem"
                    if wget -q -O /tmp/ca-bundle.pem "$_URL_CA" 2>&1; then
                        if [ -s /tmp/ca-bundle.pem ] && head -1 /tmp/ca-bundle.pem | grep -q 'BEGIN CERTIFICATE'; then
                            log "CA bundle fetched from ${_URL_CA} ($(wc -c < /tmp/ca-bundle.pem) bytes)"
                        else
                            rm -f /tmp/ca-bundle.pem
                        fi
                    fi
                    break
                fi
            fi
        done

        if [ -z "$INSTALLER_CONFIG" ]; then
            log "WARNING: Debug sink per-MAC fetch failed for all local MACs, falling back to embedded config"
        fi
    fi
fi

# Priority 2: Embedded config in ISO
if [ -z "$INSTALLER_CONFIG" ] && [ -f /media/cdrom/configs/installer.yaml ]; then
    INSTALLER_CONFIG="/media/cdrom/configs/installer.yaml"
    log "Found installer configuration: $INSTALLER_CONFIG"
fi

if [ -z "$INSTALLER_CONFIG" ]; then
    log "No installer configuration found, using defaults"
fi

# Detect target installation disk
# Skip removable devices (BMC virtual CD-ROM) and small devices (< 8GB)
INSTALL_DISK=""
log "Auto-detecting installation disk..."
lsblk -d -o NAME,SIZE,TYPE,TRAN,RO,RM 2>/dev/null | while read line; do log "  $line"; done

for disk in /dev/sda /dev/sdb /dev/sdc /dev/nvme0n1 /dev/vda; do
    [ -b "$disk" ] || continue
    DEVNAME=$(basename $disk)
    REMOVABLE=$(cat /sys/block/$DEVNAME/removable 2>/dev/null || echo "1")
    if [ "$REMOVABLE" = "1" ]; then
        log "  Skipping $disk (removable - likely virtual CD)"
        continue
    fi
    READONLY=$(cat /sys/block/$DEVNAME/ro 2>/dev/null || echo "1")
    if [ "$READONLY" = "1" ]; then
        log "  Skipping $disk (read-only)"
        continue
    fi
    SIZE_SECTORS=$(cat /sys/block/$DEVNAME/size 2>/dev/null || echo "0")
    SIZE_GB=$((SIZE_SECTORS * 512 / 1024 / 1024 / 1024))
    if [ "$SIZE_GB" -lt 8 ]; then
        log "  Skipping $disk (${SIZE_GB}GB - too small)"
        continue
    fi
    INSTALL_DISK="$disk"
    log "Found installation target: $INSTALL_DISK (${SIZE_GB}GB)"
    break
done

if [ -z "$INSTALL_DISK" ]; then
    error "No suitable installation disk found (need non-removable disk >= 8GB)"
fi

log "Installing Alpine Linux with TPM-based disk encryption"
log "Target disk: $INSTALL_DISK"

# Resolve hostname from embedded platform config (same function used for
# install log upload path). Falls back to "trusted-platform" if unset.
PLATFORM_HOSTNAME=$(resolve_platform_hostname)
PLATFORM_HOSTNAME=$(echo "$PLATFORM_HOSTNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
case "$PLATFORM_HOSTNAME" in
    ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux"|"unknown") PLATFORM_HOSTNAME="trusted-platform" ;;
esac
log "Resolved platform hostname: $PLATFORM_HOSTNAME"

# Fetch the control-plane CA bundle from the orchestrator (best-effort).
# Saved to /tmp/cp-ca-bundle.pem; the post-install mount block installs
# it into the chroot's system trust store. Without this, GW and compute
# nodes can't validate the CP's TLS cert on first-boot ACME enrollment.
fetch_orchestrator_ca_bundle || true
# Capture the SPKI pin too (parallel trust-anchor path). Saved to
# /tmp/cp-spki-pin; post-install writes to
# /etc/trusted-platform/bootstrap-spki-pin so platformd's SPKI
# bootstrap strategy can pin against it when bundle delivery fails.
fetch_orchestrator_spki_pin || true

# Build installation command (using platformctl CLI binary)
# If installer config exists, use it; otherwise use command-line flags.
# When --config is provided, the config file is the single source of
# truth for hostname, root-password, and encryption password. CLI
# flags are only used to override when absolutely needed. The install
# command only applies flag overrides when the flag is explicitly
# provided (cobra Changed check), so omitting them lets the config
# file values take effect.
if [ -n "$INSTALLER_CONFIG" ]; then
    log "Using installer configuration file: $INSTALLER_CONFIG"
    sleep 1
    log "Building installation command..."
    # Config file provides hostname, root-password, encryption settings.
    # Only pass --password in debug mode as a known dev passphrase;
    # in production the config's encryption settings are authoritative.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --config \"$INSTALLER_CONFIG\" \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --automated \
        --verbose \
        --debug"
    # Per-node hostname override. The config file baked into the shared
    # ISO carries a generic hostname ("server"); PLATFORM_HOSTNAME
    # resolution above picked up the per-MAC value published by the
    # orchestrator. Always pass --hostname so the installed system
    # takes the orchestrator-assigned name rather than the shared
    # default. Cobra's Changed-check means the installer only applies
    # this flag when explicitly provided, which is exactly what we
    # want.
    INSTALL_CMD="$INSTALL_CMD --hostname \"$PLATFORM_HOSTNAME\""
    # In debug mode, force a known LUKS passphrase for dev convenience
    if grep -q 'platform_debug=1' /proc/cmdline 2>/dev/null; then
        INSTALL_CMD="$INSTALL_CMD --password \"password\""
        log "Debug mode: using known LUKS passphrase"
    fi
    log "Installation command built successfully (hostname=$PLATFORM_HOSTNAME)"
else
    # No config file — fallback to CLI flags with defaults.
    # This is the degraded/test path.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --password \"password\" \
        --root-password \"password\" \
        --hostname \"$PLATFORM_HOSTNAME\" \
        --automated \
        --verbose \
        --debug"

fi

# Add additional flags if not using config file
if [ -z "$INSTALLER_CONFIG" ]; then
    INSTALL_CMD="$INSTALL_CMD --tpm-auto-upgrade-seal"
    log "TPM auto-upgrade seal: enabled"
fi

# Add platformd binary if it exists on the ISO
# Prefer the tmpfs copy (isolates from virtual-CD glitches — see the
# platformctl binary copy block above for rationale). Falls back to the
# CD-ROM path if the copy did not succeed.
PLATFORMD_PATH="/run/platformd-bin/platformd"
if [ ! -f "$PLATFORMD_PATH" ]; then
    PLATFORMD_PATH="/media/cdrom/platformd-bin/platformd"
fi
if [ -f "$PLATFORMD_PATH" ]; then
    INSTALL_CMD="$INSTALL_CMD --platformd-binary \"$PLATFORMD_PATH\""
    log "Platformd binary: $PLATFORMD_PATH"
fi

# Execute the installation command
log "About to execute installation command..."
sleep 1
log "Command: $INSTALL_CMD"
sleep 1
log "Starting installation now..."
set +e
eval "$INSTALL_CMD" > /tmp/install.log 2>&1
INSTALL_RESULT=$?
set -e
# Log the install output to kernel log for serial capture
while IFS= read -r line; do
    echo "[autoinstall] install: $line" > /dev/kmsg 2>/dev/null
done < /tmp/install.log
log "Installation command exited with code: $INSTALL_RESULT"
sleep 1

if [ $INSTALL_RESULT -eq 0 ]; then
    log "Installation completed successfully"

    # Persist kernel modules to installed system's /etc/modules
    # The Go installer unmounts /mnt before returning, so we re-open LUKS/LVM
    set +e
    log "Persisting kernel modules to installed system..."
    LVM_DEV="/dev/mapper/vg0-root"
    MODULES_WRITTEN=false

    if [ -n "$INSTALL_DISK" ]; then
        LUKS_PART="${INSTALL_DISK}2"
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
                    log "  Rootfs mounted at /mnt"

                    # Add detected NIC modules
                    for mod in igb ixgbe e1000e i40e ice; do
                        if lsmod 2>/dev/null | grep -q "^${mod} "; then
                            if ! grep -q "^${mod}$" /mnt/etc/modules 2>/dev/null; then
                                echo "$mod" >> /mnt/etc/modules
                                log "  Added module: $mod"
                                MODULES_WRITTEN=true
                            fi
                        fi
                    done

                    if [ "$MODULES_WRITTEN" = "true" ]; then
                        log "  Modules persisted to /mnt/etc/modules"
                    else
                        log "  No additional modules needed"
                    fi

                    # Install the orchestrator-staged CA bundle into the
                    # system trust store so the FIRST platformd boot can
                    # validate the control plane's TLS cert during ACME
                    # enrollment. Without this step the new node's
                    # ACME client hits "x509: certificate signed by
                    # unknown authority" and falls back to issuing its
                    # own local CA — exactly the failure mode that left
                    # GW/compute unenrolled in the 2026-04-29 deploy.
                    #
                    # Best-effort: missing bundle / missing host tooling
                    # logs and continues. The runtime BootstrapTrust
                    # path can still recover via SPKI/Noise when wired.
                    if [ -s /tmp/cp-ca-bundle.pem ] && [ -d /mnt/usr ]; then
                        log "  Installing orchestrator CA bundle to system trust store..."
                        mkdir -p /mnt/usr/local/share/ca-certificates
                        cp /tmp/cp-ca-bundle.pem /mnt/usr/local/share/ca-certificates/cp-ca-bundle.crt
                        chmod 0644 /mnt/usr/local/share/ca-certificates/cp-ca-bundle.crt
                        # Also stage at /etc/ssl/certs/ for tools that read
                        # there directly without consulting ca-certificates.
                        mkdir -p /mnt/etc/ssl/certs
                        cp /tmp/cp-ca-bundle.pem /mnt/etc/ssl/certs/cp-ca-bundle.pem
                        chmod 0644 /mnt/etc/ssl/certs/cp-ca-bundle.pem
                        # Run update-ca-certificates inside the chroot so
                        # the OpenSSL bundle (/etc/ssl/certs/ca-certificates.crt)
                        # picks up the new anchor. Bind-mount /proc /sys /dev
                        # so the chroot tool can resolve its prerequisites.
                        for sub in proc sys dev; do
                            if [ ! -d /mnt/$sub ]; then mkdir -p /mnt/$sub; fi
                            mount --bind /$sub /mnt/$sub 2>/dev/null || true
                        done
                        if chroot /mnt /usr/sbin/update-ca-certificates >/dev/null 2>&1; then
                            log "  CA bundle installed and trust store refreshed"
                        else
                            log "  WARNING: update-ca-certificates failed inside chroot - bundle is staged but not yet hashed"
                        fi
                        for sub in dev sys proc; do
                            umount /mnt/$sub 2>/dev/null || true
                        done
                    else
                        if [ -s /tmp/cp-ca-bundle.pem ]; then
                            log "  /mnt/usr not present - cannot install CA bundle"
                        else
                            log "  No orchestrator CA bundle staged - relying on runtime trust bootstrap"
                        fi
                    fi

                    # Persist the orchestrator-staged SPKI pin so the
                    # platform's BootstrapTrust SPKI strategy has a
                    # value to pin against. The platform reads from
                    # /etc/trusted-platform/bootstrap-spki-pin via the
                    # bootstrap-client.spki.pin-file config key.
                    if [ -s /tmp/cp-spki-pin ] && [ -d /mnt/etc ]; then
                        mkdir -p /mnt/etc/trusted-platform
                        cp /tmp/cp-spki-pin /mnt/etc/trusted-platform/bootstrap-spki-pin
                        chmod 0644 /mnt/etc/trusted-platform/bootstrap-spki-pin
                        log "  SPKI pin persisted to /etc/trusted-platform/bootstrap-spki-pin"
                    fi

                    sync
                    umount /mnt 2>/dev/null || true
                fi
            fi
            vgchange -an vg0 2>/dev/null || true
            cryptsetup luksClose cryptroot 2>/dev/null || true
            log "  LUKS closed after module persistence"
        else
            log "  WARNING: Could not re-open LUKS for module persistence"
        fi
    fi
    set -e
    log "System will poweroff..."
    # CRITICAL: Properly unmount filesystems and sync before poweroff
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

    # DEBUG: Verify main LUKS partition header (${INSTALL_DISK}2)
    if [ -b ${INSTALL_DISK}2 ]; then
        VDAMAG=$(head -c 6 ${INSTALL_DISK}2 | xxd -p)
        log "DEBUG: ${INSTALL_DISK}2 LUKS header magic bytes: $VDAMAG"
        if [ "$VDAMAG" = "4c554b53babe" ]; then
            log "DEBUG: ${INSTALL_DISK}2 LUKS header VALID!"
        else
            log "DEBUG: ${INSTALL_DISK}2 LUKS header CORRUPTED! Expected 4c554b53babe, got $VDAMAG"
        fi
    else
        log "DEBUG: ${INSTALL_DISK}2 does not exist as block device!"
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

    # Upload the install.log BEFORE poweroff. The EXIT trap will not fire
    # because poweroff halts the system before the script reaches its
    # natural exit point. Calling upload_install_log_with_code explicitly
    # here with the captured $INSTALL_RESULT is the only way to guarantee
    # the postmortem makes it off the box on the success path.
    log "Uploading install.log forensic capture before poweroff..."
    upload_checkpoint pre-poweroff || true
    upload_install_log_with_code "$INSTALL_RESULT" || true

    log "Powering off..."
    poweroff
else
    log "INSTALLATION FAILED — install.log dump follows"
    cat /tmp/install.log 2>&1 || true
    log "Uploading install.log forensic capture after install failure (exit_code=$INSTALL_RESULT)..."
    upload_checkpoint install-failed || true
    upload_install_log_with_code "$INSTALL_RESULT" || true
    error "Installation failed"
fi

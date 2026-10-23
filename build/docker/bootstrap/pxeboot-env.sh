# Defaults for the BOOTSTRAP_* env vars and the optional pxeboot flags,
# sourced by entrypoint.sh (variables documented there). It only sets
# variables, so a unit test can source it and read BOOTSTRAP_PXEBOOT_ARGS.
# An invalid setting exits 2.

: "${BOOTSTRAP_INTERFACE:=eth0}"
: "${BOOTSTRAP_HTTP_PORT:=8080}"
: "${BOOTSTRAP_SERVER_IP:=192.0.2.1}"
: "${BOOTSTRAP_DHCP_START:=192.0.2.100}"
: "${BOOTSTRAP_DHCP_END:=192.0.2.200}"
: "${BOOTSTRAP_DNS:=192.0.2.1}"
# PXE nodes have no /media/cdrom, so the kernel cmdline must carry a working
# APK repository. Default to the public Alpine mirror so internet-connected
# installs work out of the box; operators override via BOOTSTRAP_APK_MIRROR.
# Non-empty defaults are REQUIRED: supervisord's %(ENV_*)s expansion would
# otherwise emit a bare flag and the next flag would be parsed as its value.
: "${BOOTSTRAP_APK_MIRROR:=https://dl-cdn.alpinelinux.org/alpine}"
: "${BOOTSTRAP_ALPINE_VERSION:=3.22.2}"
# Derived from the HTTP port rather than a flat 8081 so moving one port
# carries the other with it, matching the offset pxeboot applies when the
# flag is unset. Set BOOTSTRAP_DEVICE_SCRIPT_PORT to move it independently
# when something else on the deployer already owns the derived port.
: "${BOOTSTRAP_DEVICE_SCRIPT_PORT:=$((BOOTSTRAP_HTTP_PORT + 1))}"

# The optional pxeboot flags are assembled here, not in supervisord.conf:
# an unset %(ENV_*)s there would leave a bare flag that swallows the next
# flag as its value. This one variable closes the command, so empty is
# nothing.
BOOTSTRAP_PXEBOOT_ARGS=""
if [ -n "${BOOTSTRAP_BIND_HOST:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --bind-host $BOOTSTRAP_BIND_HOST"
fi
if [ -n "${BOOTSTRAP_TFTP_DIR:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --tftp-dir $BOOTSTRAP_TFTP_DIR"
fi
if [ -n "${BOOTSTRAP_ARM64_IPXE:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --firmware-override snponly-aarch64.efi=$BOOTSTRAP_ARM64_IPXE"
fi
# BOOTSTRAP_NO_ROUTER=true advertises no gateway: DHCP sends no router
# option, for an isolated VLAN whose boot server does not route. Off, an
# unset gateway takes the default as it always has.
case "${BOOTSTRAP_NO_ROUTER:-false}" in
    true)
        if [ -n "${BOOTSTRAP_GATEWAY:-}" ]; then
            echo "BOOTSTRAP_NO_ROUTER=true and BOOTSTRAP_GATEWAY=$BOOTSTRAP_GATEWAY contradict each other: set one" >&2
            exit 2
        fi
        ;;
    false)
        : "${BOOTSTRAP_GATEWAY:=192.0.2.1}"
        BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --dhcp-gateway $BOOTSTRAP_GATEWAY"
        ;;
    *) echo "BOOTSTRAP_NO_ROUTER must be true or false, got $BOOTSTRAP_NO_ROUTER" >&2; exit 2 ;;
esac
case "${BOOTSTRAP_PROXY_DHCP:-false}" in
    true) BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --dhcp-proxy" ;;
    false) ;;
    *) echo "BOOTSTRAP_PROXY_DHCP must be true or false, got $BOOTSTRAP_PROXY_DHCP" >&2; exit 2 ;;
esac
if [ -n "${BOOTSTRAP_NBD_LISTEN:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-listen $BOOTSTRAP_NBD_LISTEN"
fi
if [ -n "${BOOTSTRAP_NBD_VOLUME_DIR:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-volume-dir $BOOTSTRAP_NBD_VOLUME_DIR"
fi
if [ -n "${BOOTSTRAP_NBD_VOLUME_SIZE:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-volume-size $BOOTSTRAP_NBD_VOLUME_SIZE"
fi
if [ -n "${BOOTSTRAP_NBD_CA_FILE:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-ca-file $BOOTSTRAP_NBD_CA_FILE"
fi
if [ -n "${BOOTSTRAP_NBD_CERT:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-cert $BOOTSTRAP_NBD_CERT"
fi
if [ -n "${BOOTSTRAP_NBD_KEY:-}" ]; then
    BOOTSTRAP_PXEBOOT_ARGS="$BOOTSTRAP_PXEBOOT_ARGS --nbd-key $BOOTSTRAP_NBD_KEY"
fi

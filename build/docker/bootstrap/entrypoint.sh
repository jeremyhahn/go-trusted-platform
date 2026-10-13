#!/bin/sh
# Trusted Platform bootstrap container entrypoint.
#
# Sets sane defaults for the BOOTSTRAP_* env vars consumed by pxeboot,
# prepares samba state directories, then execs supervisord which
# coordinates pxeboot + smbd + nmbd under PID 1.
#
# Required env vars (passed via `docker run -e`):
#   BOOTSTRAP_INTERFACE   network interface to bind (e.g. eth0)
#   BOOTSTRAP_BIND_HOST   address the HTTP and TFTP servers bind (optional;
#                         unset binds every interface, DHCP always does)
#   BOOTSTRAP_HTTP_PORT   HTTP port (default 8080)
#   BOOTSTRAP_SERVER_IP   server IP advertised by DHCP
#   BOOTSTRAP_DHCP_START  DHCP range start
#   BOOTSTRAP_DHCP_END    DHCP range end
#   BOOTSTRAP_GATEWAY     gateway advertised by DHCP
#   BOOTSTRAP_DNS         DNS server(s) advertised by DHCP
#   BOOTSTRAP_APK_MIRROR  install-time APK mirror base (default: public mirror)
#   BOOTSTRAP_ALPINE_VERSION  Alpine version of the staged kernel/initramfs
#   BOOTSTRAP_TFTP_DIR    Raspberry Pi boot tree to serve over TFTP (optional)
#   BOOTSTRAP_ARM64_IPXE  db-signed arm64 iPXE served as snponly-aarch64.efi (optional)
#   BOOTSTRAP_PROXY_DHCP  "true": proxy DHCP, the segment's own server leases (optional)
#
# NBD export server, read only when the manifest has a diskless-nbd node:
#   BOOTSTRAP_NBD_LISTEN       listen address (default BOOTSTRAP_SERVER_IP:10809)
#   BOOTSTRAP_NBD_VOLUME_DIR   per-node root volumes (default <data dir>/nbd)
#   BOOTSTRAP_NBD_VOLUME_SIZE  bytes of a new root volume, a multiple of 512
#   BOOTSTRAP_NBD_CA_FILE      platform CA bundle that verifies client IDevIDs
#   BOOTSTRAP_NBD_CERT         server TLS certificate
#   BOOTSTRAP_NBD_KEY          server TLS private key

set -eu

: "${BOOTSTRAP_INTERFACE:=eth0}"
: "${BOOTSTRAP_HTTP_PORT:=8080}"
: "${BOOTSTRAP_SERVER_IP:=192.0.2.1}"
: "${BOOTSTRAP_DHCP_START:=192.0.2.100}"
: "${BOOTSTRAP_DHCP_END:=192.0.2.200}"
: "${BOOTSTRAP_GATEWAY:=192.0.2.1}"
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

export BOOTSTRAP_INTERFACE BOOTSTRAP_HTTP_PORT BOOTSTRAP_SERVER_IP \
       BOOTSTRAP_DHCP_START BOOTSTRAP_DHCP_END BOOTSTRAP_GATEWAY BOOTSTRAP_DNS \
       BOOTSTRAP_APK_MIRROR BOOTSTRAP_ALPINE_VERSION BOOTSTRAP_DEVICE_SCRIPT_PORT \
       BOOTSTRAP_PXEBOOT_ARGS

# Samba state dirs the alpine package doesn't pre-create
mkdir -p /var/lib/samba/private /var/log/samba /run/samba

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

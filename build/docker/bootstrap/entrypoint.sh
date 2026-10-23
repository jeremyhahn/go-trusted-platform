#!/bin/sh
# Trusted Platform bootstrap container entrypoint.
#
# Sets sane defaults for the BOOTSTRAP_* env vars consumed by pxeboot
# (pxeboot-env.sh), prepares samba state directories, then execs supervisord which
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
#   BOOTSTRAP_GATEWAY     gateway advertised by DHCP (default 192.0.2.1)
#   BOOTSTRAP_NO_ROUTER   "true": advertise no gateway, excludes BOOTSTRAP_GATEWAY (optional)
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

. /usr/local/bin/pxeboot-env.sh

export BOOTSTRAP_INTERFACE BOOTSTRAP_HTTP_PORT BOOTSTRAP_SERVER_IP \
       BOOTSTRAP_DHCP_START BOOTSTRAP_DHCP_END BOOTSTRAP_DNS \
       BOOTSTRAP_APK_MIRROR BOOTSTRAP_ALPINE_VERSION BOOTSTRAP_DEVICE_SCRIPT_PORT \
       BOOTSTRAP_PXEBOOT_ARGS

# Samba state dirs the alpine package doesn't pre-create
mkdir -p /var/lib/samba/private /var/log/samba /run/samba

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

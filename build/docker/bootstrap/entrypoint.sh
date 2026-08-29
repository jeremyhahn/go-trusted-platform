#!/bin/sh
# Trusted Platform bootstrap container entrypoint.
#
# Sets sane defaults for the BOOTSTRAP_* env vars consumed by pxeboot,
# prepares samba state directories, then execs supervisord which
# coordinates pxeboot + smbd + nmbd under PID 1.
#
# Required env vars (passed via `docker run -e`):
#   BOOTSTRAP_INTERFACE   network interface to bind (e.g. eth0)
#   BOOTSTRAP_HTTP_PORT   HTTP port (default 8080)
#   BOOTSTRAP_SERVER_IP   server IP advertised by DHCP
#   BOOTSTRAP_DHCP_START  DHCP range start
#   BOOTSTRAP_DHCP_END    DHCP range end
#   BOOTSTRAP_GATEWAY     gateway advertised by DHCP
#   BOOTSTRAP_DNS         DNS server(s) advertised by DHCP
#   BOOTSTRAP_APK_MIRROR  install-time APK mirror base (default: public mirror)
#   BOOTSTRAP_ALPINE_VERSION  Alpine version of the staged kernel/initramfs

set -eu

: "${BOOTSTRAP_INTERFACE:=eth0}"
: "${BOOTSTRAP_HTTP_PORT:=8080}"
: "${BOOTSTRAP_SERVER_IP:=172.16.201.1}"
: "${BOOTSTRAP_DHCP_START:=172.16.201.100}"
: "${BOOTSTRAP_DHCP_END:=172.16.201.200}"
: "${BOOTSTRAP_GATEWAY:=172.16.201.1}"
: "${BOOTSTRAP_DNS:=172.16.201.1}"
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

export BOOTSTRAP_INTERFACE BOOTSTRAP_HTTP_PORT BOOTSTRAP_SERVER_IP \
       BOOTSTRAP_DHCP_START BOOTSTRAP_DHCP_END BOOTSTRAP_GATEWAY BOOTSTRAP_DNS \
       BOOTSTRAP_APK_MIRROR BOOTSTRAP_ALPINE_VERSION BOOTSTRAP_DEVICE_SCRIPT_PORT

# Samba state dirs the alpine package doesn't pre-create
mkdir -p /var/lib/samba/private /var/log/samba /run/samba

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

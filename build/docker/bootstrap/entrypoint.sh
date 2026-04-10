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

set -eu

: "${BOOTSTRAP_INTERFACE:=eth0}"
: "${BOOTSTRAP_HTTP_PORT:=8080}"
: "${BOOTSTRAP_SERVER_IP:=172.16.201.1}"
: "${BOOTSTRAP_DHCP_START:=172.16.201.100}"
: "${BOOTSTRAP_DHCP_END:=172.16.201.200}"
: "${BOOTSTRAP_GATEWAY:=172.16.201.1}"
: "${BOOTSTRAP_DNS:=172.16.201.1}"

export BOOTSTRAP_INTERFACE BOOTSTRAP_HTTP_PORT BOOTSTRAP_SERVER_IP \
       BOOTSTRAP_DHCP_START BOOTSTRAP_DHCP_END BOOTSTRAP_GATEWAY BOOTSTRAP_DNS

# Samba state dirs the alpine package doesn't pre-create
mkdir -p /var/lib/samba/private /var/log/samba /run/samba

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

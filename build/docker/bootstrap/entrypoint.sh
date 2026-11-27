#!/bin/sh
# Trusted Platform bootstrap container entrypoint.

set -eu

. /usr/local/bin/pxeboot-env.sh

export BOOTSTRAP_INTERFACE BOOTSTRAP_HTTP_PORT BOOTSTRAP_SERVER_IP \
       BOOTSTRAP_DHCP_START BOOTSTRAP_DHCP_END BOOTSTRAP_DNS \
       BOOTSTRAP_APK_MIRROR BOOTSTRAP_ALPINE_VERSION BOOTSTRAP_DEVICE_SCRIPT_PORT \
       BOOTSTRAP_PXEBOOT_ARGS

# Samba state dirs the alpine package doesn't pre-create
mkdir -p /var/lib/samba/private /var/log/samba /run/samba

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

# Trusted Platform PXE Boot Container
#
# Self-contained network bootstrap server.
# Contains:
#   - pxeboot binary (DHCP + TFTP + HTTP for PXE)
#   - kernel + initramfs extracted from the platform ISO
#   - autoinstall script
#   - Samba (smbd + nmbd) serving /data over SMB so BMC virtual media
#     can mount the platform ISO without requiring vendor-specific
#     licensed Redfish endpoints (e.g. Supermicro DCMS)
#   - supervisord coordinating all services under one PID 1
#
# Build with: make pxeboot-container
# The ISO must be built first (make iso) to provide kernel/initramfs.
#
# Usage:
#   docker run --net=host \
#     -v /path/to/data:/data \
#     -v /path/to/iso:/data/boot.iso:ro \
#     platform-pxeboot:latest
#
# The /data directory is exposed as the [boot] SMB share. Drop any
# ISO into /data and it becomes available at smb://<host>/boot/<name>.

FROM alpine:3.22

# Samba server + supervisor for multi-process container.
# samba-common-tools provides smbpasswd / testparm / etc.
RUN apk add --no-cache samba-server samba-common-tools supervisor

# PXE boot server binary
COPY pxeboot /usr/local/bin/pxeboot

# Entrypoint: validates env vars, prepares samba state dirs, execs supervisord
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Samba: anonymous read-only [boot] share over /data
COPY smb.conf /etc/samba/smb.conf

# supervisord: pxeboot + smbd + nmbd under one PID 1
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Kernel and initramfs extracted from the platform ISO
COPY vmlinuz /data/vmlinuz
COPY initramfs /data/initramfs

# Autoinstall script
COPY autoinstall.sh /data/autoinstall.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/pxeboot

# Ports:
#   67/udp   DHCP server
#   69/udp   TFTP server (iPXE firmware)
#   137/udp  NetBIOS name service (helps older BMCs locate the share)
#   138/udp  NetBIOS datagram service
#   139/tcp  SMB over NetBIOS
#   445/tcp  SMB direct (microsoft-ds) — primary BMC virtual media transport
#   8080/tcp HTTP (kernel, initramfs, boot scripts)
EXPOSE 67/udp 69/udp 137/udp 138/udp 139/tcp 445/tcp 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

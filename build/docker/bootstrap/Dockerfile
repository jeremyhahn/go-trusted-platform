# Trusted Platform PXE Boot Container
#
# Self-contained network bootstrap server.
# Contains:
#   - pxeboot binary (DHCP + TFTP + HTTP for PXE)
#   - Samba (smbd + nmbd) serving /data over SMB so BMC virtual media
#     can mount the platform ISO without requiring vendor-specific
#     licensed Redfish endpoints (e.g. Supermicro DCMS)
#   - supervisord coordinating all services under one PID 1
#
# No installer media is baked in: every media set the container serves —
# x86_64 included — comes from a netboot media build (`make netboot-media`)
# the deployer stages under /data/media (bootstrap.yaml
# deployer.netboot_media_dir).
#
# Build with: make pxeboot-container
#
# Usage:
#   docker run --net=host \
#     -v /path/to/data:/data \
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

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/pxeboot

# Ports:
#   67/udp   DHCP server
#   69/udp   TFTP server (iPXE firmware)
#   137/udp  NetBIOS name service (helps older BMCs locate the share)
#   138/udp  NetBIOS datagram service
#   139/tcp  SMB over NetBIOS
#   445/tcp  SMB direct (microsoft-ds) — primary BMC virtual media transport
#   8080/tcp HTTP (media sets, boot scripts, per-MAC config)
EXPOSE 67/udp 69/udp 137/udp 138/udp 139/tcp 445/tcp 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

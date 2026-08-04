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
# Alpine kernel-modules squashfs. The PXE boot.ipxe cmdline fetches
# modloop=http://<host>/data/modloop-lts; without it Alpine init cannot
# load kernel modules and hangs right after the autoinstall/inittab setup.
COPY modloop-lts /data/modloop-lts

# Autoinstall script
COPY autoinstall.sh /data/autoinstall.sh

# Installer binaries extracted from the platform ISO. PXE-booted nodes have
# no CD to read /media/cdrom/platformd-bin/ from, so the autoinstall fetches
# these over HTTP via platform_bin_url=http://<host>/data. platformctl is the
# install CLI; platformd is embedded into the target UKI at install time.
COPY platformctl /data/platformctl
COPY platformd /data/platformd
# platform-initrd: boot-time LUKS/TPM unlock binary embedded into the target
# UKI by the installer. dracut-platformd.tar.gz: the 90platformd dracut module
# the installer copies into the target so dracut can build the UKI. PXE nodes
# fetch both over HTTP into /media/cdrom (no CD to read them from).
COPY platform-initrd /data/platform-initrd
COPY dracut-platformd.tar.gz /data/dracut-platformd.tar.gz

# Alpine minirootfs extracted from the platform ISO (prefetch builder output).
# The OS installer prefers a locally-cached minirootfs; PXE nodes fetch this
# over HTTP into /media/cdrom so the install does not need to reach the public
# Alpine mirror for the base rootfs.
COPY alpine-minirootfs.tar.gz /data/alpine-minirootfs.tar.gz

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

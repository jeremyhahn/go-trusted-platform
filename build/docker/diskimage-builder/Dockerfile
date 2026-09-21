# Assemble container for the Trusted Platform factory disk images.
#
# `platformctl diskimage create` runs the installer's Phase A inside this
# image, under the target architecture (binfmt on an x86-64 build host),
# against a loop-mounted image: partition table, LUKS2 root, Alpine root
# filesystem from the pre-fetched packages on /media/cdrom, dracut and the
# UKI in the target chroot, the U-Boot boot files on the EFI partition, and
# installer.luks for the device's first boot. It is started with
# --privileged because losetup, device-mapper and the chroot mounts need it,
# but with its own private /dev: the host's /dev is never bind-mounted, since
# the installer's `mdev -s` resets the mode of every device node it walks.
# It never receives private keys (the Secure Boot DB key travels on the
# media exactly as it does on the ISO).
#
# The platform binaries are not in this image: the media carries the
# target-architecture platformctl-static, which is what runs here.
FROM alpine:3.22

RUN apk add --no-cache \
    apk-tools \
    bash \
    coreutils \
    cpio \
    dosfstools \
    e2fsprogs \
    e2fsprogs-extra \
    file \
    findutils \
    gawk \
    gzip \
    kmod \
    lvm2 \
    parted \
    tar \
    util-linux \
    xz

WORKDIR /work

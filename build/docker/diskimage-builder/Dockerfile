# Assemble container for the Trusted Platform factory disk images.
FROM alpine:3.22

RUN apk add --no-cache \
    apk-tools \
    bash \
    coreutils \
    cpio \
    cryptsetup \
    dosfstools \
    e2fsprogs \
    e2fsprogs-extra \
    file \
    findutils \
    gawk \
    gzip \
    kmod \
    lvm2 \
    mkinitfs \
    parted \
    tar \
    squashfs-tools \
    util-linux \
    xz

WORKDIR /work

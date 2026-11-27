# The NAT64 integration VM: linux-lts with the jool translator, Open vSwitch and iproute2 in one initramfs.
ARG ALPINE_VERSION=3.22
FROM alpine:${ALPINE_VERSION} AS rootfs
RUN apk add --no-cache linux-lts jool-modules-lts jool-tools openvswitch iproute2 iputils \
 && rm -rf /lib/firmware /boot/initramfs-lts /var/cache/apk/*
# Keep only the module trees the VM loads.
RUN set -e; kver=$(ls /lib/modules); m=/lib/modules/$kver; \
    find $m/kernel -mindepth 1 -maxdepth 1 ! -name net ! -name lib ! -name crypto ! -name drivers -exec rm -rf {} +; \
    find $m/kernel/drivers -mindepth 1 -maxdepth 1 ! -name net ! -name virtio ! -name block -exec rm -rf {} +; \
    depmod "$kver"
COPY init /init
RUN chmod 0755 /init

FROM alpine:${ALPINE_VERSION} AS pack
RUN apk add --no-cache cpio gzip
COPY --from=rootfs / /rootfs
RUN set -e; mkdir /out; cp /rootfs/boot/vmlinuz-lts /out/vmlinuz; rm -rf /rootfs/boot; \
    cd /rootfs && find . -xdev | cpio -o -H newc --quiet | gzip -1 > /out/rootfs.cpio.gz

FROM scratch
COPY --from=pack /out/ /

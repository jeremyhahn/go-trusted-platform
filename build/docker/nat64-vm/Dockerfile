# The NAT64 integration VM (#601): Alpine's linux-lts kernel with the
# jool-modules-lts translator built for exactly that kernel, Open vSwitch
# and iproute2, packed as one initramfs. The kernel and the module come from
# the same repository snapshot in the same apk transaction, which is the
# only way the module loads -- Alpine's netboot kernel lags the package
# repository, and a host kernel is whatever the host runs. It is the fleet's
# own pairing (Alpine LTS + jool-modules-lts, ruling R6).
ARG ALPINE_VERSION=3.22
FROM alpine:${ALPINE_VERSION} AS rootfs
RUN apk add --no-cache linux-lts jool-modules-lts jool-tools openvswitch iproute2 iputils \
 && rm -rf /lib/firmware /boot/initramfs-lts /var/cache/apk/*
# Keep the module trees the VM loads (net, virtio, the translator) and drop
# the rest, so the initramfs stays small enough to boot in seconds.
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

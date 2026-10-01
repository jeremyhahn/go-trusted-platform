# check=skip=FromPlatformFlagConstDisallowed
# (The root stage is aarch64 whatever the build host is: that constant
# platform is the point of this file.)
# The ipsec suite's aarch64 VM: a kernel and an initramfs that run the suite's
# tests on a real aarch64 kernel under qemu-system-aarch64 (TCG).
#
# Why a VM and not qemu-user: qemu's linux-user mode refuses NETLINK_XFRM
# sockets (EPROTONOSUPPORT, measured with qemu 7.2 and 10.2.3), and charon
# aborts at start-up without its kernel IPsec interface.
#
# Built by `make ipsec-arm64-vm` with `--output type=local`: the result is
# Image (the raw arm64 kernel) and initrd.gz.

# Alpine's linux-virt kernel (XFRM, ESP, veth, netns, 9p all available as
# modules) with iproute2 for `ip netns`, and the init that runs the suite.
FROM --platform=linux/arm64 alpine:3.22 AS root
RUN apk add --no-cache linux-virt iproute2
COPY init /init
RUN chmod 755 /init

# Packed on the build host's own architecture.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS pack
RUN apk add --no-cache cpio
COPY --from=root / /vmroot
# vmlinuz-virt is an EFI zboot image, which qemu's -kernel (7.2 in the
# devcontainer) cannot load: the raw Image is the gzip payload whose offset
# and size the zboot header holds at bytes 8 and 12, after the "zimg" magic
# at byte 4 and the codec name at byte 24.
RUN set -eu; \
    z=/vmroot/boot/vmlinuz-virt; \
    [ "$(dd if=$z bs=1 skip=4 count=4 2>/dev/null)" = zimg ] || { echo "$z is not a zboot image" >&2; exit 1; }; \
    [ "$(dd if=$z bs=1 skip=24 count=4 2>/dev/null)" = gzip ] || { echo "$z payload is not gzip" >&2; exit 1; }; \
    off=$(od -An -tu4 -j8 -N4 $z | tr -d ' '); \
    size=$(od -An -tu4 -j12 -N4 $z | tr -d ' '); \
    tail -c +$((off + 1)) $z | head -c $size | gunzip > /Image; \
    [ "$(dd if=/Image bs=1 skip=56 count=4 2>/dev/null)" = ARMd ] || { echo "extracted kernel is not an arm64 Image" >&2; exit 1; }; \
    cd /vmroot && rm -rf boot && find . | cpio -o -H newc 2>/dev/null | gzip -1 > /initrd.gz

FROM scratch
COPY --from=pack /Image /initrd.gz /

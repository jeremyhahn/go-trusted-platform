# check=skip=FromPlatformFlagConstDisallowed
# The ipsec suite's aarch64 VM: a kernel and an initramfs that run the suite under qemu-system-aarch64 (TCG).

# linux-virt with iproute2 and the suite's init.
FROM --platform=linux/arm64 alpine:3.22 AS root
RUN apk add --no-cache linux-virt iproute2
COPY init /init
RUN chmod 755 /init

# Packed on the build host's own architecture.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS pack
RUN apk add --no-cache cpio
COPY --from=root / /vmroot
# qemu's -kernel cannot load the EFI zboot vmlinuz-virt, so extract the raw Image from its gzip payload.
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

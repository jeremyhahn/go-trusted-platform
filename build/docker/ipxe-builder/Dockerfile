# iPXE builder for the Trusted Platform network boot.
#
# Builds the arm64 EFI iPXE the PXE server hands to a Raspberry Pi (and to
# the QEMU virt stand-in) after U-Boot's DHCP/TFTP stage. Upstream's binary
# cannot be used: iPXE's EFI nap is WFI, and U-Boot's EFI implementation is
# polled — it never raises the interrupt that would wake the CPU — so
# upstream's arm64 iPXE halts for good at its own "Press Ctrl-B" banner
# (ipxe/ipxe discussion #605). This build selects NAP_NULL
# (configs/nap.h) and is otherwise upstream's snponly configuration.
#
# alpine-first per the company devops convention; iPXE is freestanding, so
# the same bare-metal aarch64 toolchain the U-Boot builder uses is enough.
FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    build-base \
    coreutils \
    gcc-aarch64-none-elf \
    linux-headers \
    perl \
    tar \
    wget \
    xz

WORKDIR /build

COPY build-ipxe.sh /build/
RUN chmod +x /build/build-ipxe.sh

ENTRYPOINT ["/build/build-ipxe.sh"]

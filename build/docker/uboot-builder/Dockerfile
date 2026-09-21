# U-Boot builder for the Trusted Platform Raspberry Pi image.
#
# Builds two U-Boot binaries from one pinned upstream release:
#   rpi_arm64  - loaded by the Raspberry Pi firmware as kernel8.img; talks to
#                the Infineon SLB9670 over GPIO bit-banged SPI (mainline
#                U-Boot has no BCM2835 SPI controller driver), measures the
#                boot into the TPM through EFI_TCG2_PROTOCOL and enforces
#                EFI Secure Boot with PK/KEK/db preseeded into the binary.
#   qemu_arm64 - the same EFI/TCG2/Secure Boot configuration for the QEMU
#                virt machine (tpm-tis-device / swtpm), used by the
#                emulated end-to-end tests.
#
# alpine-first per the company devops convention; the aarch64 bare-metal
# toolchain is enough because U-Boot is freestanding.
FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    bc \
    bison \
    build-base \
    coreutils \
    findutils \
    dtc \
    flex \
    gcc-aarch64-none-elf \
    gnutls-dev \
    linux-headers \
    ncurses-dev \
    openssl \
    openssl-dev \
    perl \
    py3-openssl \
    py3-elftools \
    py3-setuptools \
    python3 \
    python3-dev \
    swig \
    tar \
    util-linux-dev \
    wget \
    xz

WORKDIR /build

COPY build-uboot.sh mkesl.py /build/
RUN chmod +x /build/build-uboot.sh

ENV CROSS_COMPILE=aarch64-none-elf-
ENTRYPOINT ["/build/build-uboot.sh"]

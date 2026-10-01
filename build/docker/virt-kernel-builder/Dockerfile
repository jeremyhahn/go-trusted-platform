# Cross-builds the aarch64 Linux kernel the QEMU virt stand-in of the
# Raspberry Pi factory image boots (docs/factory-image/).
#
# Why a platform-built kernel: Alpine's aarch64 kernels ship no memory-mapped
# TIS driver (CONFIG_TCG_TIS is unset in linux-lts and linux-rpi; linux-virt
# has no TPM support at all), and the only TPM QEMU can attach to the virt
# machine is the memory-mapped tpm-tis-device. The Raspberry Pi itself uses
# the SPI transport those kernels do have. This kernel is Alpine's version
# with the TIS driver, signed modules and the same lockdown LSM, so the
# emulated first boot exercises the platform exactly as the Pi does.
#
# alpine-first per the company devops convention; the aarch64 bare-metal
# toolchain builds the kernel the same way it builds U-Boot.
FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    bc \
    binutils-aarch64-none-elf \
    bison \
    build-base \
    coreutils \
    diffutils \
    elfutils-dev \
    findutils \
    flex \
    gcc-aarch64-none-elf \
    linux-headers \
    openssl \
    openssl-dev \
    perl \
    python3 \
    rsync \
    tar \
    wget \
    xz

WORKDIR /build

COPY build-virt-kernel.sh /build/
RUN chmod +x /build/build-virt-kernel.sh

# The options every platform kernel carries and the check that enforces them,
# shared with the fips kernel builder. "kernelconfig" is a named build context
# (docker build --build-context kernelconfig=../kernel-config), so the one
# copy in build/docker/kernel-config is what both images bake in.
COPY --from=kernelconfig platform-required.config require-config.sh /build/kernel-config/

ENV ARCH=arm64
ENV CROSS_COMPILE=aarch64-none-elf-
ENTRYPOINT ["/build/build-virt-kernel.sh"]

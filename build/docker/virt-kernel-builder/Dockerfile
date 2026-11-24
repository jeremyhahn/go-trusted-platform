# Cross-builds the aarch64 kernel the QEMU virt stand-in of the Raspberry Pi factory image boots.
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

# Baked in, not bind-mounted: the daemon cannot see a CI job container's checkout.
COPY configs/virt.config /configs/virt.config

# The options every platform kernel carries and the check that enforces them.
COPY --from=kernelconfig platform-required.config require-config.sh /build/kernel-config/

ENV ARCH=arm64
ENV CROSS_COMPILE=aarch64-none-elf-
ENTRYPOINT ["/build/build-virt-kernel.sh"]

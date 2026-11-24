# U-Boot builder for the Trusted Platform Raspberry Pi image.
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

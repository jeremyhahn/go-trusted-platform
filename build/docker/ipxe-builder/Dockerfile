# iPXE builder for the Trusted Platform network boot.
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

# strongSwan builder for the Trusted Platform overlay.
FROM alpine:3.22

# makedepends and checkdepends of aport/APKBUILD (abuild runs with -d).
RUN apk add --no-cache \
    abuild \
    bash \
    build-base \
    gnupg \
    libcap-dev \
    linux-headers \
    openssl-dev \
    tzdata \
    wget

# abuild refuses to run as root; the build script hands it to this user.
RUN adduser -D builder && addgroup builder abuild

# The package's users and groups, created as root, since abuild's setuid helpers fail under qemu-user.
RUN addgroup -S strongswan && adduser -S -D -H -h /var/empty -s /sbin/nologin -G strongswan strongswan \
    && addgroup -S xkms-p11 && adduser -S -D -H -h /var/empty -s /sbin/nologin -G xkms-p11 xkms-p11

WORKDIR /build

# The strongSwan release signing key, pinned in the repository.
COPY strongswan-release-key.asc /build/
RUN gpg --dearmor < /build/strongswan-release-key.asc > /build/strongswan-release-key.gpg

COPY build-strongswan.sh /build/
COPY aport/ /build/aport/
COPY aport-p11-host/ /build/aport-p11-host/
COPY socket-takeover /build/
RUN chmod +x /build/build-strongswan.sh

ENTRYPOINT ["/build/build-strongswan.sh"]

# strongSwan builder for the Trusted Platform overlay.
#
# Builds charon + swanctl (IKEv2, OpenSSL, PKCS#11, VICI) from a pinned,
# signature-verified upstream release and packages them as a signed apk with
# an OpenRC service, and packages the PKCS#11 module host (a glibc root
# filesystem it is given) with its OpenRC service as a second apk. Built once
# per architecture: --platform linux/amd64
# natively, --platform linux/arm64 under binfmt/qemu-user.
#
# alpine-first per the company devops convention: the platform's nodes run
# Alpine 3.22 (musl), so the package is built against the same release.
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

# The package's pkgusers/pkggroups, created here as root: abuild otherwise
# creates them through its setuid abuild-addgroup/abuild-adduser helpers, and
# under qemu-user (the arm64 build) a binfmt handler without the C flag runs
# setuid binaries without their privilege, so that step fails.
RUN addgroup -S strongswan && adduser -S -D -H -h /var/empty -s /sbin/nologin -G strongswan strongswan \
    && addgroup -S xkms-p11 && adduser -S -D -H -h /var/empty -s /sbin/nologin -G xkms-p11 xkms-p11

WORKDIR /build

# The strongSwan release signing key, pinned in the repository. The build
# script also checks the signer's fingerprint, so a key added here later
# cannot silently widen what is accepted.
COPY strongswan-release-key.asc /build/
RUN gpg --dearmor < /build/strongswan-release-key.asc > /build/strongswan-release-key.gpg

COPY build-strongswan.sh /build/
COPY aport/ /build/aport/
COPY aport-p11-host/ /build/aport-p11-host/
COPY socket-takeover /build/
RUN chmod +x /build/build-strongswan.sh

ENTRYPOINT ["/build/build-strongswan.sh"]

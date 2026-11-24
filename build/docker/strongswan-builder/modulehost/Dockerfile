# The module host: a glibc root filesystem whose p11-kit server hosts the go-xkms PKCS#11 module for one node.
FROM ubuntu:26.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends p11-kit opensc util-linux \
    && rm -rf /var/lib/apt/lists/* /usr/share/man /usr/share/info \
    && test -x /usr/bin/setpriv \
    && test -x /usr/bin/pkcs11-tool

RUN version="$(dpkg-query -W -f='${Version}' p11-kit)" \
    && dpkg --compare-versions "${version}" ge 0.26 \
    && mkdir -p /usr/share/xkms \
    && printf '%s\n' "${version}" > /usr/share/xkms/p11-kit.version

COPY --from=module libxkms_pkcs11.so /usr/lib/xkms/libxkms_pkcs11.so

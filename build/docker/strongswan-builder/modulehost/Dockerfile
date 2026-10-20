# The module host: a glibc root filesystem whose p11-kit server hosts the
# go-xkms PKCS#11 module for one node. It is packaged as the
# trusted-platform-p11-host apk (../aport-p11-host) and run, chrooted, by that
# apk's OpenRC service.
#
# Why a separate glibc host: a Go c-shared library cannot be loaded by a musl
# process (golang/go#13492), so neither charon nor a musl p11-kit server can
# dlopen the module; charon loads p11-kit-client.so instead and reaches the
# module through this server (docs/sdn/engineering.md, "PKCS#11 on musl").
#
# Why Ubuntu 26.04: p11-kit's RPC changed in 0.26, and a 0.26 client against
# a 0.24/0.25 server silently corrupts byte-array attributes (CKA_ID 01
# arrives as 01000000, labels vanish). Alpine 3.22's client is 0.26.2;
# Ubuntu 26.04 LTS carries the same 0.26.2, while the devcontainer's Debian
# bookworm has 0.24.1 and trixie 0.25.5. The build fails if the installed
# server is older, and records the version beside the module so the apk
# build and the service check it again (../aport-p11-host/p11-kit-pin-check).
#
# The service runs the server as its own unprivileged user, dropping to it
# with util-linux's setpriv inside the chroot, and labels the token once, as
# root, with OpenSC's pkcs11-tool loading the module directly. The build fails
# if either is missing.
#
# Built by `make ipsec-module-host` with the module (built against glibc by
# ipsec-pkcs11-module) as the named build context "module", then exported to
# a tarball the apk build takes as its input.
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

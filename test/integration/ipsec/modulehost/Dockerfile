# The module host of the ipsec integration suite: a glibc root filesystem
# whose p11-kit server hosts the go-xkms PKCS#11 module for one peer.
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
# bookworm has 0.24.1 and trixie 0.25.5.
#
# Built by `make ipsec-test-inputs` with the module (built against glibc by
# ipsec-pkcs11-module) as the named build context "module", then exported to
# a tarball the suite unpacks per peer.
FROM ubuntu:26.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends p11-kit \
    && rm -rf /var/lib/apt/lists/*

COPY --from=module libxkms_pkcs11.so /usr/lib/xkms/libxkms_pkcs11.so

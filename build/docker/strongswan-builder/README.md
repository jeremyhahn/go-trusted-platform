# strongSwan builder

Builds `trusted-platform-strongswan` for the overlay's IPsec transport
(`docs/sdn/engineering.md`, §9). It contains charon (IKEv2 only) and swanctl,
built for Alpine 3.22 (musl) on amd64 and arm64 from a pinned strongSwan 6.0.x
release and packaged as signed apks with an OpenRC service.

```
make build                                    # both arches, ephemeral dev signing key
make build APK_SIGNING_KEY=~/.trusted-platform/apk/<name>.rsa
make verify                                   # checksums, signatures, plugin set, source
make clean
```

From the repository root the same targets are `make strongswan-build`,
`make strongswan-verify` and `make strongswan-clean`.

## What is pinned

| Pin | Value | Enforced by |
|---|---|---|
| Release | `STRONGSWAN_VERSION` (6.0.7) | `build-strongswan.sh` |
| Tarball hash | `STRONGSWAN_SHA256` | `sha256sum -c`, fail-closed |
| Signer | `STRONGSWAN_SIGNER`, the primary-key fingerprint of the strongSwan release key (`strongswan-release-key.asc`) | `gpgv`, plus a comparison of the `VALIDSIG` primary key with the pin, because gpgv accepts any key in its keyring |
| Plugins | `STRONGSWAN_PLUGINS` | `--disable-defaults` + `--enable-<each>`; `package()` fails if the installed set differs in any way |

The plugins are `openssl pkcs11 vici counters nonce kernel-netlink
socket-default pem revocation constraints updown`:

- **Crypto and control:** `openssl` is the only crypto provider, `pkcs11` loads keys held outside the daemon, and `vici` is the control API.
- **Infrastructure charon cannot run without:**
  - `nonce`
  - `kernel-netlink` (XFRM)
  - `socket-default` (UDP 500/4500)
  - `pem`
  - `revocation` (CRLs)
  - `constraints` (name constraints)
  - `updown` (the per-SA hook)
- **`counters`:** configure turns it on whenever VICI is enabled.

**There is no `x509` plugin, on purpose.** The openssl plugin decodes X.509
certificates and CRLs itself (`openssl_plugin.c`: `CERT_DECODE` for
`CERT_X509` and `CERT_X509_CRL`), and `pem` unwraps PEM for it. The ipsec
suite asserts that both certificates load and that charon reports no
X.509/CRL decoder missing. What the openssl plugin does not decode is OCSP
and attribute certificates; the platform revokes by pushing CRLs, so it uses
neither.

There is no in-tree crypto, no EAP, no XAuth, no IKEv1 and no stroke. PSK
authentication is part of charon's core and cannot be compiled out; the
platform's connections use `auth = pubkey` only.

## Runtime shape

- **User:** charon starts as root, binds 500/4500, opens the kernel interface, then switches to the `strongswan` user (`--with-user/--with-group`, libcap). It keeps `CAP_NET_ADMIN` and nothing else; the ipsec suite measures `CapEff=0x1000`.
- **VICI socket:** `/run/charon.vici`, owned `strongswan:strongswan`, mode 0660.
- **OpenRC service:** `/etc/init.d/charon` runs charon under `supervise-daemon`, which restarts it. Environment for the PKCS#11 provider goes in `/etc/conf.d/charon`.

## Signing key

`APK_SIGNING_KEY` is an abuild RSA private key with `<name>.rsa.pub` beside it.
Nodes trust the `.pub` from `/etc/apk/keys`. The key is mounted read-only and
never enters an image. Without it, every build generates an ephemeral key
under `output/.ephemeral-key/`; that is for dev builds only, since nothing
outside the build trusts it.

## Output

```
output/x86_64/   trusted-platform-strongswan{,-doc,-openrc}-<ver>-r0.apk APKINDEX.tar.gz manifest.json SHA256SUMS
output/aarch64/  (same)
output/keys/     <key>.rsa.pub
```

Each `<arch>` directory is an apk repository (`apk add --repository
output/<repo-root>`). The suite's peer image installs the apks this way, with
signature checks on.

## arm64

The arm64 apk is built natively under binfmt/qemu-user. That needs the
qemu-user that `make binfmt` registers (qemu 10.2.3). Under the qemu 7.2 that
`multiarch/qemu-user-static` registered, gcc 14 segfaulted at random. abuild's
setuid helpers do not run elevated under emulation either, so the image
creates the package's user itself.

The upstream test suite (`make check`) runs on both arches. On a musl system
it needs `tzdata`, because one libstrongswan test formats times in
Europe/Zurich.

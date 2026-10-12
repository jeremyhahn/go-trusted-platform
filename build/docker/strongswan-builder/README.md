# strongSwan builder

Builds the packages the overlay's IPsec transport runs on
(`docs/sdn/engineering.md`, §9), for Alpine 3.22 (musl) on amd64 and arm64, as
signed apks with OpenRC services, in one repository per architecture:

- `trusted-platform-strongswan` (+ `-openrc`): charon (IKEv2 only) and swanctl
  from a pinned strongSwan 6.0.x release, the `strongswan.d` settings and the
  `charon` service.
- `trusted-platform-p11-host` (+ `-openrc`): the glibc module host, a root
  filesystem with a p11-kit server that hosts the go-xkms PKCS#11 module, and
  the `xkms-p11-kit` service. charon cannot load the Go module itself on musl.

```
make build XKMS_VERSION=v0.48.0-alpha MODULE_HOST_DIR=<dir>
make build XKMS_VERSION=... MODULE_HOST_DIR=... APK_SIGNING_KEY=~/.trusted-platform/apk/<name>.rsa
make verify XKMS_VERSION=...                  # checksums, signatures, plugin set, source, the four apks
make clean
```

`XKMS_VERSION` is the go-xkms release the module is built from; it becomes the
module-host apk's version. `MODULE_HOST_DIR` holds `modulehost-<arch>.tar`, the
module-host root filesystem that `make ipsec-module-host` exports from
`modulehost/Dockerfile`. From the repository root, `make strongswan-build`
builds that first and passes both; `make strongswan-verify` and
`make strongswan-clean` are the other two targets.

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
- **Settings:** `/etc/strongswan.d/trusted-platform.conf` sets `make_before_break = yes`, `cookie_threshold`, `init_limit_half_open`, loads only the plugin set above (templated from `STRONGSWAN_PLUGINS`) and fixes the VICI socket path. `strongswan.d/charon/pkcs11.conf` points the pkcs11 plugin at `/usr/lib/pkcs11/p11-kit-client.so`.
- **VICI socket:** `/run/charon.vici`. The vici plugin creates it as `strongswan`; `socket-takeover` hands it to the account platformd runs as, `root:root` by default (`CHARON_VICI_USER`, `CHARON_VICI_GROUP`), at mode 0600 on every (re)start. platformd runs as root on installer-built nodes and refuses a socket its uid does not own, so change the owner only together with platformd's account. The service refuses to start if that user or group is missing.
- **`socket-takeover`:** both services run their daemon through it. It removes a stale socket, `exec`s the daemon (so `supervise-daemon` signals and reaps the daemon itself) and leaves a detached watcher that, once the daemon's own user owns the socket, sets the mode and then the owner. A daemon that does not serve the socket within `CHARON_TAKEOVER_TRIES` / `XKMS_P11_TAKEOVER_TRIES` tenths of a second, or whose socket cannot be handed over, is stopped and respawned.
- **`charon` service:** `/etc/init.d/charon` runs charon under `supervise-daemon`, which restarts it, and `need`s `xkms-p11-kit`. `P11_KIT_SERVER_ADDRESS` (`unix:path=/run/p11-kit/xkms.sock`) is in `/etc/conf.d/charon`.
- **`xkms-p11-kit` service:** unpacks the module-host root filesystem under `/var/lib/xkms-p11-host`, bind-mounts `/proc`, `/dev`, `/run/p11-kit` and `/var/lib/xkms` into it and runs `p11-kit server` in a chroot hosting `libxkms_pkcs11.so` on `/run/p11-kit/xkms.sock`; `socket-takeover` sets it to mode 0660, `xkms-p11:strongswan`, on every (re)start. The server runs as `xkms-p11` (created by the apk; it owns `/var/lib/xkms`), dropped to with `setpriv` inside the chroot, and exports only `pkcs11:token=trusted-platform-ipsec`. `rc-service xkms-p11-kit init_token` labels that token as root, with the service stopped, from the SO PIN in the root-only `/run/xkms-p11-kit.so-pin`. Its module environment (`XKMS_PKCS11_*`) is in `/etc/conf.d/xkms-p11-kit`.
- **p11-kit pin:** 0.26 or newer, on both ends. A 0.26 client against an older server corrupts CKA_ID and labels without an error. Both apks depend on `p11-kit-server>=0.26`; `modulehost/Dockerfile`, the module-host `APKBUILD` and the service start each run the check on the host's recorded version (`aport-p11-host/p11-kit-pin-check`). It is not configurable.

## Signing key

`APK_SIGNING_KEY` is an abuild RSA private key with `<name>.rsa.pub` beside it.
Nodes trust the `.pub` from `/etc/apk/keys`. The key is mounted read-only and
never enters an image. Without it, every build generates an ephemeral key
under `output/.ephemeral-key/`; that is for dev builds only, since nothing
outside the build trusts it.

## Output

```
output/x86_64/   trusted-platform-strongswan{,-doc,-openrc}-<ver>-r0.apk
                trusted-platform-p11-host{,-openrc}-<ver>-r0.apk
                APKINDEX.tar.gz manifest.json SHA256SUMS
output/aarch64/  (same)
output/keys/     <key>.rsa.pub
```

Each `<arch>` directory is an apk repository (`apk add --repository
output/<repo-root>`). The suite's peer image installs the apks this way, with
signature checks on. The install media take the same directory:
`platformctl iso create --platform-apk-dir output` (and `diskimage create`)
copies the four platform apks, plus `p11-kit-server` from the Alpine mirror, into
the offline repository (`docs/installer/cli.md`). The names are checked against
`pkg/iso` by `TestPlatformPackages_MatchTheBuilder`.

## arm64

The arm64 apk is built natively under binfmt/qemu-user. That needs the
qemu-user that `make binfmt` registers (qemu 10.2.3). Under the qemu 7.2 that
`multiarch/qemu-user-static` registered, gcc 14 segfaulted at random. abuild's
setuid helpers do not run elevated under emulation either, so the image
creates the package's user itself.

The upstream test suite (`make check`) runs on both arches. On a musl system
it needs `tzdata`, because one libstrongswan test formats times in
Europe/Zurich.

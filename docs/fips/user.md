# FIPS Mode — User Guide

> **Status: NORMATIVE** · Scope: building, installing and running in FIPS mode · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

FIPS mode is three separate settings:

- a **build** setting, which removes non-approved algorithms from the binaries;
- a **runtime** setting, which makes Go's cryptographic module refuse them;
- the **kernel's** FIPS mode, which restricts disk-encryption keyslots.

A FIPS deployment needs all three. [architecture.md](architecture.md) explains
why they are separate.

## 1. Prerequisites

- x86_64. A FIPS ISO cannot be built for aarch64.
- Docker, to build the FIPS kernel and the OpenSSL FIPS provider during ISO
  creation.

## 2. Build FIPS binaries

```sh
GOFIPS140=latest make build WITH_FIPS=1
```

- `WITH_FIPS=1` selects the FIPS implementations.
- `GOFIPS140=latest` links in Go's FIPS 140-3 module. `make` does not set it for
  you.
- Never pass the tag through `BUILD_TAGS=` on the command line. That drops every
  other tag. Use `WITH_FIPS=1`.

## 3. Build and install a FIPS system

```sh
platformctl iso create --fips --output platform-fips.iso
```

The ISO boots a FIPS kernel with `fips=1` and installs with `--fips`. To install
onto an existing system, run `platformctl install system --fips --disk /dev/sda`,
or select the `fips` installer profile.

On the installed system:

- `/proc/sys/crypto/fips_enabled` reads `1`;
- new disk-encryption keyslots use PBKDF2-SHA256, not Argon2id;
- existing Argon2id keyslots still open.

## 4. Run the daemons in FIPS mode

Set `GODEBUG=fips140=only` in the environment of every platform daemon. Nothing
sets it for you yet, even when the kernel is in FIPS mode. Automatic activation
is **Planned**.

Use `only`, not `on`: `on` still permits non-approved algorithms.

## 5. Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| A tunnel or VPN configuration naming `wireguard` is refused | WireGuard is not in FIPS builds | Use the `ipsec` tunnel transport; VPN clients use MASQUE |
| DNS refuses to start with `nsec-mode: nsec3` | NSEC3 is SHA-1 only | Use `nsec-mode: nsec` (this permits zone enumeration), or run that node outside FIPS mode. See [dnssec.md](../dns/dnssec.md) |
| An IPMI session fails: "FIPS 140-3 requires at least 14 …" | The BMC password or KG key is under 14 bytes | Set a password of 14 bytes or more, or manage the controller over Redfish |
| An IPMI controller is refused for an unapproved algorithm | It offers only MD5 or SHA-1 for RMCP+ | Manage it over Redfish |
| A BGP peer with `auth-type: md5` is refused | TCP-MD5 is not in FIPS builds | Use `tcp-ao`. See [BGP configuration](../sdn/bgp/configuration.md) |
| ISO creation fails while prefetching packages | A FIPS-built `platformctl` cannot verify the Alpine package index (its checksums are SHA-1) | Build the ISO with a default `platformctl`; `--fips` still makes a FIPS ISO |
| Adding a disk keyslot with Argon2id, `pbkdf2-sha1` or a SHA-1 hash is refused | The kernel is in FIPS mode | Use PBKDF2 with SHA-256 or SHA-512 |
| The Noise bootstrap listener does not start in a FIPS build | Its only suite uses Curve25519 | Bootstrap another way; the approved P-256 suite is **Planned (#518)** |
| Passwords are still hashed with Argon2id | Not yet switched under FIPS mode | **Planned (#26)** |

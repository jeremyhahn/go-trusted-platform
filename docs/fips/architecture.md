# FIPS Mode — Architecture

> **Status: NORMATIVE** · Scope: the `fips` build tag, `GODEBUG=fips140=only`, `pkg/fips/` · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

FIPS 140-3 permits only approved algorithms. Several protocols the platform
speaks have **no** approved form: WireGuard (Curve25519, ChaCha20-Poly1305,
BLAKE2s), DNSSEC NSEC3 (SHA-1 only, RFC 5155), IPMI RMCP+ with MD5/SHA-1, BGP
TCP-MD5, and the Alpine `APKINDEX` checksum (SHA-1). A FIPS deployment must
refuse each of these with an error that names the mode as the cause. It must not
crash, and it must not quietly fall back to an unapproved algorithm.

## 2. The shape: three independent switches

FIPS mode is not one setting. Three switches exist on `main`, each read by
different code:

| Switch | When it acts | What it does | Read by |
|---|---|---|---|
| `fips` build tag (`make WITH_FIPS=1`) | compile time | Swaps in the FIPS implementation file; MD5, SHA-1 and WireGuard are not linked in | every `//go:build fips` file ([engineering.md §2](engineering.md)); selected at `Makefile:293-295` |
| `GODEBUG=fips140=only` (binary built with `GOFIPS140=latest`) | process start | Go's cryptographic module refuses non-approved algorithms, often by panicking; platform code checks `crypto/fips140.Enabled()` so that it refuses first, with a typed error | `pkg/bmc/rmcp_fips_keys.go:43`, `pkg/dns/config.go:362`; the daemon's LUKS backends also pick PBKDF2 for a keyslot whose KDF is unset (`pkg/app/backends/luks_fips.go:65-70`) |
| Kernel indicator `/proc/sys/crypto/fips_enabled` | each call | Restricts LUKS2 keyslots to PBKDF2 and refuses SHA-1 | `pkg/fips/detect.go:63`, `:71-83`; installer `--fips` also activates it (`pkg/installer/luks_algorithms.go:36`) |

What `main` does and does not do today:

- **The switches are not linked.** Nothing sets `GODEBUG=fips140=only` from the
  kernel indicator. No init script, unit or Go code sets `GODEBUG`. One
  path reads both: the daemon's LUKS backends (`pkg/app/backends`,
  `resolveLUKSKeyslotPolicy`) select PBKDF2 for an unset KDF when
  `fips140.Enabled()` is true, because the Go module refuses Argon2 and the
  enrolment would otherwise fail, and then apply the kernel-indicator policy.
  So a daemon under `GODEBUG=fips140=only` (or `on`) creates PBKDF2 keyslots
  there even on a kernel without the indicator; an explicit KDF or hash is
  still judged by the kernel indicator alone.
- **Only the FIPS test job builds with the tag.** That job is
  `make test-fips` (`Makefile:1366-1402`). Release binaries carry neither the
  `fips` tag nor `GOFIPS140`.
- A FIPS OS image is a separate path (§4). It boots a FIPS kernel with
  `fips=1`, which turns on the kernel indicator. It does not turn on the Go
  module.

**Planned — no issue filed yet:** activating `fips140=only` automatically when
the kernel indicator is on. The security model's FIPS ruling 1 requires it (one
artifact for both markets; activation by configuration or by the kernel's FIPS
mode). Until it is built, an operator sets `GODEBUG` by hand
([user.md](user.md)).

## 3. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| Gate every check on the build tag | A binary built without the tag can still run under `fips140=only`. A tag-only check would then let `crypto/hmac` or `crypto/sha1` panic mid-handshake. Checks on a Go runtime refusal therefore read `fips140.Enabled()` (`pkg/bmc/rmcp_fips_keys.go:32-36`, `pkg/dns/config.go:391`) |
| `make BUILD_TAGS="... fips"` | A command-line `BUILD_TAGS` replaces the Makefile's whole tag list. The run then tests a build with no codecs, raft or frost, and the resulting codec errors look like FIPS findings (`Makefile:286-292`) |
| `GODEBUG=fips140=on` in the test job | `on` loads the module but still permits non-approved algorithms, so the suite would pass while a regulated path used prohibited cryptography (`Makefile:1376-1378`) |
| Silently rewrite every unapproved LUKS choice | Only the documented case is substituted: an Argon2 KDF becomes PBKDF2. An explicit `pbkdf2-sha1` or SHA-1 hash is refused with a typed error, because `--fips` never promised to rewrite them (`pkg/installer/luks_algorithms.go:45-60`, `:64-70`) |
| Treat an unreadable kernel indicator as "not FIPS" | That fails open. `IsEnabled` assumes activation on any read error (`pkg/fips/detect.go:71-83`) |

## 4. Boundaries

- **`pkg/fips/`** owns two things:
  - the kernel-indicator policy: detection, KDF and hash rules for LUKS2 keyslots;
  - the registry for the OS-level FIPS installer (`pkg/fips/interface.go`).

  It owns no cryptography.
- **Each feature owns its own refusal**, in its own package (BMC, DNS, BGP,
  tunnel, VPN, IMA, ISO, Secure Boot, attestation). [engineering.md](engineering.md)
  lists every one.
- **The upstream stack owns the cryptography.** That is Go's module and the
  go-xkms primitives reached through the go-quicbaas SDK re-exports.
  - The Noise bootstrap listener refuses to start in a FIPS build because the
    upstream key generation refuses Curve25519. The platform adds no check of
    its own (`pkg/api/noise/server_fips_test.go:29-44`).
- **The FIPS OS image** is built by the installer and ISO builder:
  - a FIPS kernel and the OpenSSL FIPS provider, from builder containers;
  - `fips=1` on the kernel command line;
  - installer code in `pkg/installer/alpine/fips.go`, `pkg/installer/installer.go:309-322`, `:395-406`, `:1217-1220`.

  It changes the kernel indicator, not the Go binaries.

## 5. Trust boundaries

- The indicator path is a package variable that nothing outside the package
  sets (tests replace it), and it is not overridable from the environment
  (`pkg/fips/detect.go:63`). A hostile environment cannot switch the keyslot
  policy off.
- An indicator that is unreadable, or holds anything other than `0` or `1`,
  produces a typed error. `IsEnabled` treats that as active
  (`pkg/fips/detect.go:92-108`).

## 6. What FIPS mode does not do

- It does not certify anything. It selects and enforces approved algorithms.
- It offers no approved substitute for a protocol that has none: WireGuard,
  NSEC3, BGP TCP-MD5, APK `Q1` checksums. Each of these is refused.
- It builds no FIPS ISO for aarch64 (`pkg/iso/types.go:323-326`).
- It does not yet hash passwords with PBKDF2 under FIPS activation.
  `pkg/crypto/argon2` is Argon2id whatever the mode. **Planned (#26).**
- It does not yet offer an approved suite for the Noise bootstrap listener. A
  FIPS build refuses the only suite it has. **Planned (#518).**

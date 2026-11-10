# LUKS Key-Slot Management — Architecture

> **Status: NORMATIVE** · Scope: runtime LUKS2 key-slot management on a running host · Last verified: 2026-10-30
> Conflicts with this document are defects. Fix them here first.

---

## 1. Problem

A provisioned host keeps its root filesystem on a LUKS2 volume. After first
boot an operator still has to change who and what can open that volume: add a
passphrase, bind a FIDO2 authenticator or the TPM, cut a recovery key, retire a
slot, rotate a passphrase. Doing that with `cryptsetup` on the host bypasses the
platform's transports, its authorization and its FIPS keyslot policy.

This feature exposes those key-slot operations as one platformd service on every
transport, and as `platformctl luks`.

It is the **runtime** half. Unlocking the volume at boot is the initramfs's job
and is documented in
[`docs/installer/engineering.md` §5](../installer/engineering.md); the
keyslots enrolled here are the ones those strategies consume.

---

## 2. What it does not do

- It does not unlock, open or mount a volume. `test-unlock` checks a slot; it
  maps nothing.
- It does not format a volume. Formatting happens in the installer
  ([`docs/installer/`](../installer/)).
- It does not implement LUKS2. All header and keyslot I/O is
  `github.com/jeremyhahn/go-luks2`.
- It does not implement FIDO2 or TPM sealing. Those come from the go-xkms
  re-exports under `quicbaas/sdk/go/xkms/*`.
- It does not store passphrases, recovery keys or FIDO2 secrets. A recovery key
  is returned once and then cleared from memory.

---

## 3. Boundaries and data flow

```
platformctl luks <verb>                     REST / gRPC / Unix / QUIC / MCP caller
        │                                                │
        ▼                                                ▼
sdk/go/services/luks  (Service)          pkg/api/daemon transport adapters
                                          luks_rest.go · luks_grpc_service.go
                                          phase35_quic.go · mcp_phase35.go
                                                         │
                                                         ▼
                                          pkg/api/daemon/luks_service.go
                                          (LUKSService: validation, root gate)
                                                         │  LUKSBackend
                                                         ▼
                                          pkg/app/backends/luks.go
                                          (go-luks2 + FIDO2 / TPM handlers)
                                                         │
                                                         ▼
                                                 /dev/<device> LUKS2 header
```

- **Transport adapters** decode, call `LUKSService`, and map its typed errors to
  the transport's status codes. They hold no LUKS logic.
- **`LUKSService`** validates required fields, enforces the root gate on
  mutating operations, and delegates to a `LUKSBackend`. It is constructed with
  no backend and no root checker; both are injected through setters.
- **`LUKSBackend`** (`pkg/app/backends`) performs the header I/O with go-luks2
  and applies the platform FIPS keyslot policy. FIDO2 and TPM enrollment go
  through pluggable handlers built on the go-xkms re-exports.

**The initrd FIDO2 strategy** (`pkg/initrd/strategy_fido2.go`) keys its slot
with the key the SDK FIDO2 handler returns from `UnlockWithKey` for the
credential ID and a 32-byte salt: the SDK's 64-byte derivation of the
authenticator's hmac-secret (`GenerateDerivedKey`), not the raw secret.
Enrolment takes a second touch, as `systemd-cryptenroll` does. The key is
never stored. The credential ID, salt and relying party ID are kept in a LUKS2
header token bound to the keyslot (base64 `fido2-credential` and
`fido2-salt`, `fido2-rp`). The installer's enrolment (`pkg/installer/fido2_enroll.go`) uses the same SDK
calls and writes a type `fido2` (`luks.TokenTypeFIDO2`) token
([installer engineering](../installer/engineering.md)); the runtime
`DeriveEnroll` (`pkg/app/backends/luks_fido2_handler.go`) writes type
`fido2-manual`. If the token cannot be written, the slot is killed again.
When the installer's enrolment is cancelled after its keyslot is written and
before the token is (the context is checked again after the token-slot
lookup, which reads the header without one), it kills the slot again too, so boot is not left with a
slot it cannot unlock and a retry can reuse the target slot. If that fails,
the error joins `FIDO2CanceledError` and `FIDO2RollbackError`.
The installer's unlock (`FIDO2Unlock`) checks its context before it asks for a
touch and again before it maps the volume; an expired deadline counts as a
cancellation. A cancelled unlock or enrolment never waits on the authenticator:
the SDK call it abandons runs on in a drain that zeroes the late key, closes the
handler and only then admits the next FIDO2 operation, so a retry cannot race
it for the touch ([installer engineering](../installer/engineering.md)). The
`fido2-assert` of a `fido2-manual` unlock is one of those operations: it waits
for the slot (a cancelled wait never launches it) and holds it until the tool
exits. The initrd strategy does the same at boot: one gate for the process
admits one authenticator operation at a time, an unlock or the whole of an
enrolment. A call abandoned by a cancelled unlock keeps the gate until it has
ended and its late key is zeroed. A retry waits for the gate, honours its own
context while it waits, and never asks the authenticator when that context ends
first.

At boot the strategy takes its slots from the header, not from the volume
config: every token that carries a credential and a salt names its slots in
`keyslots`, and the lowest token ID wins a slot. The configured
`FallbackMethods` index (2 by default) plays no part, so the installer's
default slot 3 opens. Each slot is handled by its token type:

| Type | Written by | Read as |
|---|---|---|
| `fido2` | installer | base64 credential and salt, relying party `fido2-rp` (default `luks-root`), no user verification |
| `fido2-manual` | runtime `DeriveEnroll`, earlier installers | credential in hex or any base64 alphabet, `fido2-rp` (default the SDK's), `fido2-up-required` as user verification |
| `systemd-fido2`, any other | `systemd-cryptenroll` | refused: `FIDO2RawSecretTokenError`, authenticator not asked |

An `fido2-manual` token does not say which key its slot holds: the runtime
keys it with the SDK derivation, earlier installers with the raw hmac-secret.
The strategy derives once and lets LUKS check the key. If the slot rejects
it, the error is `FIDO2RawSecretTokenError` (naming go-xkms #1769: the pinned
SDK cannot return the raw secret) and the authenticator is not asked again.
The initrd cannot open such a slot, so it has to be re-enrolled.

The installer's `FIDO2Unlock` (`pkg/installer/fido2_unlock.go`) reads the same
token types and picks the unlock path the same way, with one difference for
`fido2-manual`:

| Type | Unlock path |
|---|---|
| `fido2` | SDK `UnlockWithKey`; `fido2-assert` is never run |
| `fido2-manual` | the raw hmac-secret first, from `fido2-token -L` and `fido2-assert -G -h` (run with `exec.CommandContext`), which is how earlier installers keyed the slot; if that fails or the keyslot rejects it, SDK `UnlockWithKey` |
| `systemd-fido2`, any other | refused: `FIDO2RawSecretTokenError` |

Only the type `fido2` token marks the SDK derivation. Earlier installers wrote
`fido2-manual` with `fido2-up-required=true` meaning user presence, which is
what `fido2-assert` asks for by default. The runtime writes the same field
meaning user verification, and the SDK fallback reads it that way, because the
authenticator's hmac-secret differs with and without verification. Trying the
raw hmac-secret first means a legacy slot never depends on an SDK assertion
that asks for verification an authenticator without built-in UV refuses. A
token that fails to decode is refused before the authenticator is asked. When
both paths fail, the error joins the raw-secret failure and the SDK failure.

Raw-secret failures are typed: `FIDO2AssertError` names the failed step and
wraps `FIDO2NoDeviceError`, `FIDO2SecretLengthError` or the tool's error. A raw
secret the slot also rejects gives `FIDO2KeyRejectedError`.

At boot, `commands.CreateManager` (`pkg/boot/commands/manager.go`) opens the SDK
FIDO2 handler (`fido2.NewHandler` on the default HID enumerator) and sets it as
`Platform.FIDO2`, so the manager registers the FIDO2 strategy when
`FallbackMethods` names it. If the handler cannot be opened, a warning is
logged and the manager is built without FIDO2; the TPM and password strategies
still run.

No explicit derivation marker (`"derivation"`) is written: the go-luks2
`v0.2.0-alpha` `Token` has no field for it and drops unknown JSON fields on
import and read, so the token type is the only signal that survives.

**As shipped, the chain is not connected at the server end** (see
[engineering.md](engineering.md) §6): the platformd startup path injects
neither the go-luks2 backend nor a root checker, so every server transport
answers *backend not configured* or *root required*. `platformctl luks` builds
the SDK's `GRPCClient` from `platform.Client.LUKS()` and reaches that refusal
over whichever transport is active.

---

## 4. Trust boundaries

| Boundary | Rule |
|---|---|
| Caller → platformd | The transport's authentication applies (mTLS for REST, a platform token for gRPC TCP, QUIC and MCP). See [`docs/daemon/api.md`](../daemon/api.md) §5. |
| Service → header | Mutating operations require that platformd runs as root (`LUKSService` root gate). Read-only operations and `test-unlock` do not check root. |
| Secrets in requests | Existing, old and new passphrases travel in the request body. On the CLI they are command-line flags and are therefore visible in the process table of the CLI host. |
| Recovery key out | The recovery key crosses the transport once in the response and is written by the CLI to a `0600` file. The backend clears its copy after formatting it. |
| FIPS | When the host is in FIPS mode, new keyslots use PBKDF2 with an approved PRF instead of the go-luks2 default (argon2id). Outside FIPS mode the library defaults apply. |

---

## 5. Rejected alternatives

- **Shelling out to `cryptsetup`.** Rejected: it parses text output, needs the
  binary on every image, and puts the keyslot policy outside the platform.
  go-luks2 reads and writes the header directly.
- **Leaving these verbs under `platformctl fido2`.** Rejected: most of them
  have nothing to do with FIDO2. The LUKS-specific `fido2` verbs were removed
  without a compatibility shim; [cli.md](cli.md) §2 maps old to new.
- **A platformd-local, Unix-socket-only service.** Rejected by the
  multi-protocol rule: the service is registered on every daemon transport.

---

## 6. Expected change

The platform pins go-luks2 `v0.2.0-alpha`. A move to go-luks2
`v1.0.0-rc.4` is expected (held in `go.mod`: it lifts go-enclave under the
SDK stack); it changes the library API this backend calls and
will land together with an update to this folder. Everything here describes
`v0.2.0-alpha`.

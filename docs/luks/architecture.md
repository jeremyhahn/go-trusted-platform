# LUKS Key-Slot Management — Architecture

> **Status: NORMATIVE** · Scope: runtime LUKS2 key-slot management on a running host · Last verified: 2026-10-11
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
[`docs/installer/UNLOCK_STRATEGIES.md`](../installer/UNLOCK_STRATEGIES.md); the
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

**As shipped, the chain is not connected at either end** (see
[engineering.md](engineering.md) §6):

- the platformd startup path injects neither the go-luks2 backend nor a root
  checker, so every server transport answers *backend not configured* or
  *root required*;
- `platformctl luks` uses the SDK's default `Client`, a stub that returns
  `not yet wired` for every operation.

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
`v1.0.0-rc.2` is expected; it changes the library API this backend calls and
will land together with an update to this folder. Everything here describes
`v0.2.0-alpha`.

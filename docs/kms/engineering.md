# Key Management (re-export frontage) — Engineering Contract

> **Status: NORMATIVE** · Scope: the platform's KMS surface (`pkg/api/daemon/kms_*`, `pkg/webservice/v1/rest/kms/`, `pkg/cli/commands/kms/`) · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. There is no `pkg/kms` in this repository

Verified 2026-08-18: `pkg/kms` does not exist. Key management belongs to the
stack — go-xkms for hardware and cloud crypto, exported through
`go-quicbaas/sdk/go` — and this repository re-exports it as the platform
product's KMS surface (docs/00 L5).

What is local is service and transport code:

| Location | Role |
|---|---|
| `pkg/api/daemon/kms_service.go`, `kms_service_extended.go` | The service the transports call |
| `pkg/api/daemon/kms_platform_service.go`, `kms_platform_rest.go` | Platform-scoped KMS service and its REST wiring |
| `pkg/api/daemon/quic_kms.go`, `quic_kms_extended.go` | QUIC handlers |
| `pkg/api/daemon/mcp_service_kms_lifecycle.go` | MCP key-lifecycle tools |
| `pkg/webservice/v1/rest/kms/` | REST routes |
| `pkg/api/grpc/kms_service.go`, `kms_types.go` | gRPC service |
| `pkg/cli/commands/kms/` | The CLI |

`pkg/crypto/` holds two primitives used elsewhere in the platform (`aesgcm`,
`argon2`) and is **not** the KMS.

`aesgcm.Seal`/`Open` changed shape in #209 to survive `GODEBUG=fips140=only`,
which refuses `cipher.NewGCM` outright: they now use
`cipher.NewGCMWithRandomNonce` and exchange a single self-framing blob —
`nonce || ciphertext || tag` — instead of returning and accepting a separate
nonce. There is no nonce parameter to pair wrongly any more. `GenerateKey` is
unchanged for callers, though it now honours the entropy reader passed to
`NewAESGCM`, which it had silently ignored.

**`aesgcm` is the platform's one AES-GCM implementation** (#248). `pkg/registry`
seals layer content and wraps data-encryption keys through `Seal`/`Open`
rather than building its own cipher, so the nonce handling and the FIPS-only
construction live in one place. `pkg/app` uses `GenerateKey` for its random
PINs. Do not construct a GCM cipher anywhere else in the platform; if a caller
needs something `aesgcm` lacks, add it to the package.

`Open` refuses a blob shorter than a nonce plus a tag with the typed
`ErrCiphertextTooShort`. The package exports only errors it can actually
return: the nonce-length, message-size and buffer-overlap sentinels, and the
panic guard in `Open` with its `MessageError`, were removed in #248 — with no
nonce parameter and a nil destination, neither of `crypto/cipher`'s panic
conditions can arise. `aesgcm` is a platform-internal primitive, not consumer
API, so it is not re-exported under `sdk/go`.

**Never add key-management logic here.** A missing capability is missing in
go-xkms or in the quicbaas SDK (docs/00 L8).

## 2. A large part of the CLI is deliberately unimplemented

This is the most important thing to know about this feature, and it is stated
in the code rather than hidden: **eight non-test files in
`pkg/cli/commands/kms/` carry "not yet implemented"**, backed by eight distinct
typed errors:

```go
ErrSecretsNotImplemented        ErrKeyExportNotImplemented
ErrKeyImportNotImplemented      ErrKeyVersionsNotImplemented
ErrKeyStatusNotImplemented      ErrKeyUnwrapNotImplemented
ErrDEKNotImplemented            ErrBackendTestNotImplemented
```

Affected areas, by file:

| File | Unimplemented surface |
|---|---|
| `secrets.go` | The **entire** `kms secrets` subtree — store, get, list, delete, rotate, version, versions, rollback, status, policy get/set, prefix list, watch |
| `dek.go` | Data-encryption-key operations |
| `key_export.go`, `key_import.go` | Key export and import |
| `key_versions.go` | Key version listing |
| `key_status.go` | Key status |
| `key_unwrap.go` | Key unwrap |
| `key_test_backend.go` | Backend test |

`ErrSecretsNotImplemented.Error()` reads *"secrets management is not yet
implemented in the platform KMS service"*, and the command's long help offers a
workaround: use `kms crypto encrypt` / `decrypt` to manage encrypted secrets
yourself.

**These are commands that exist, parse flags, and then refuse.** They are typed
errors, not panics or silent no-ops, which is the right shape — but a caller
must not read "the verb exists" as "the capability exists".

**The REST surface does not have this gap.** `/api/v1/kms/secrets/...` routes
are registered and functional ([api.md](api.md) §4). The CLI is behind the API,
not the other way round.

## 3. Exported surface

There is no KMS type exported from this repository. The surface is:

- **gRPC** `KeyManagementService` — 23 RPCs
  (`pkg/api/grpc/proto/kms.proto`).
- **REST** — `/api/v1/kms`, the largest REST route set in the platform after
  IAM.
- **QUIC** — key management `0xC0`–`0xCF`, crypto `0xD0`–`0xDA`, plus a
  **KMS extended category opcode `0xCD`** whose subs `0x08`–`0x0D` are the DEK
  calls. The `OpDEK*` bytes `0xF0`–`0xF5` are reserved and unserved.
- **MCP** — 29 `kms_*` tools, 11 `secret_*` tools and 6 `dek_*` tools.
- **SDK** — `sdk/go/services/kms`.

## 4. Invariants

1. **Private key material never crosses into this repository in the clear.** The
   platform layer calls the stack; it does not hold keys. `ExportKey` exists on
   the gRPC service and its CLI counterpart is unimplemented — which is the
   conservative side to be wrong on.
2. **`Rewrap` re-encrypts to the latest key version; it does not re-encrypt
   plaintext.** That is what makes rotation cheap.
3. **A DEK is generated by the KMS, not by the caller.** `GenerateDataKey` and
   `GenerateWrappedDataKey` return the key; a caller that generates its own has
   left the trust model.
4. **Batch operations are not a different security context.** `BatchEncrypt` and
   `BatchDecrypt` apply the same key policy per item.
5. **Hash and HMAC are distinct.** `Hash` is unkeyed; `HMAC` and `VerifyHMAC`
   are keyed by a KMS key. Using `Hash` where an HMAC is required is a real
   defect, not a style choice.
6. **AEAD safety limits are a correctness control.** They exist because
   AES-GCM has a bound on the number of invocations per key before nonce reuse
   becomes probable. Exceeding it is a break, not a slowdown.

## 5. AEAD safety limits — no surface at all

`pkg/cli/commands/kms/key_safety.go` declares `kms key safety set|get|clear|check|report`
behind the `key_safety` build tag. The shipped tag set omits it, and under it
the file does not compile (no `SetKeySafety` / `GetKeySafety` on the SDK
client); [cli.md](cli.md) §10. There is **no gRPC RPC, REST route, QUIC opcode
or MCP tool** either.

Given that the limits guard against nonce reuse under a single key, "there is no
programmatic way to check whether a fleet's keys are approaching their limit" is
a real operational gap. Recorded in [api.md](api.md) §5.

## 6. Configuration

The KMS backend is configured in the stack, not here. `BackendStatus` /
`kms_backend_status` reports which backend is live — that is the platform-side
question worth asking, and the answer determines whether keys are in hardware,
in a cloud KMS, or in software.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/api/daemon/kms_*_test.go`, `pkg/cli/commands/kms/*_test.go` | Service behaviour, lifecycle, CLI flag handling, and the not-implemented errors |
| Integration | `test/integration/kms/`, `test/integration/secrets/` | Against a running daemon and a real backend |

The unimplemented verbs have their own tests
(`key_export_test.go`, `key_import_test.go`, `key_versions_test.go`,
`secrets_versions_test.go`, `key_unwrap_test.go`,
`key_test_backend_test.go`) — they assert the refusal, which is the right thing
to test for a stub and means the stubs will not silently start half-working.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. For KMS it would be
actively misleading if satisfied naively, since many verbs are stubs
([cli.md](cli.md) §8).

## 8. Observability

`BackendStatus` is the health signal. There is no AEAD safety report on any
surface (§5).

**Never log key material, plaintext passed to `Encrypt`, or the output of
`Decrypt`, `GenerateDataKey` or `Unseal`-style operations.** This repository sits
above Layer 3, so it uses the stack's owned key abstractions rather than raw
byte slices — that is the portfolio's layered protected-memory rule, and it is
what keeps key bytes out of this layer entirely.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/ca/`](../ca/) — the other half of the stack re-export frontage; CA keys
  live in this KMS
- [`docs/tenant/`](../tenant/) — per-tenant DEKs
- [`docs/registry/`](../registry/) — per-layer DEKs for image encryption
- [`docs/secrets/`](../secrets/) — the secrets surface

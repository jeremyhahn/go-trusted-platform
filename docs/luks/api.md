# LUKS Key-Slot Management — API

> **Status: NORMATIVE** · Scope: LUKS routes on every transport · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

The six transports, the QUIC category-opcode scheme and the platform-wide
authorization model are defined once in [`docs/daemon/api.md`](../daemon/api.md);
this page lists only what is specific to LUKS. **Unix is gRPC over a Unix
domain socket**, so gRPC and Unix share a column.

Every server transport is registered, but the service behind it has no backend
or root checker injected, so each capability answers *backend not configured*
or *root required* today ([engineering.md](engineering.md) §6).

---

## 1. Surfaces

- **gRPC:** `platform.v1.LUKSService`, 10 RPCs (`pkg/api/grpc/proto/luks.proto`),
  registered on the TCP and Unix gRPC servers.
- **REST:** base path `/api/v1/luks` (`pkg/api/daemon/luks_rest.go`).
- **QUIC:** category opcode `0x9C` (`OpLUKSCategory`), sub-opcodes `0x01`–`0x0A`
  (`sdk/go/wire/quicwire/phase35_opcodes.go`), dispatched by `pkg/api/daemon/phase35_quic.go`.
- **MCP:** 10 `platform_luks_*` tools (`pkg/api/mcp/phase35_tools.go`).
- **Embedded:** no LUKS entry in the SDK service registry.

---

## 2. Capabilities

| Capability | REST | gRPC / Unix | QUIC `0x9C` | MCP | Embedded |
|---|---|---|---|---|---|
| Volume status | `GET /api/v1/luks/status?device=` | `Status` | `0x01` | `platform_luks_status` | `MISSING — docs/13 G7` |
| List keyslots | `GET /api/v1/luks/slots?device=` | `ListSlots` | `0x02` | `platform_luks_list_slots` | `MISSING — docs/13 G7` |
| Header info | `GET /api/v1/luks/info?device=` | `Info` | `0x03` | `platform_luks_info` | `MISSING — docs/13 G7` |
| Enroll passphrase | `POST /api/v1/luks/enroll/passphrase` | `EnrollPassphrase` | `0x04` | `platform_luks_enroll_passphrase` | `MISSING — docs/13 G7` |
| Enroll FIDO2 | `POST /api/v1/luks/enroll/fido2` | `EnrollFIDO2` | `0x05` | `platform_luks_enroll_fido2` | `MISSING — docs/13 G7` |
| Enroll TPM | `POST /api/v1/luks/enroll/tpm` | `EnrollTPM` | `0x06` | `platform_luks_enroll_tpm` | `MISSING — docs/13 G7` |
| Enroll recovery key | `POST /api/v1/luks/enroll/recovery` | `EnrollRecovery` | `0x07` | `platform_luks_enroll_recovery` | `MISSING — docs/13 G7` |
| Remove keyslot | `POST /api/v1/luks/keys/remove` | `RemoveKey` | `0x08` | `platform_luks_remove_key` | `MISSING — docs/13 G7` |
| Test keyslot | `POST /api/v1/luks/keys/test-unlock` | `TestUnlock` | `0x09` | `platform_luks_test_unlock` (refused, §5) | `MISSING — docs/13 G7` |
| Change passphrase | `POST /api/v1/luks/passphrase/change` | `ChangePassphrase` | `0x0A` | `platform_luks_change_passphrase` | `MISSING — docs/13 G7` |

### SDK client paths

- `sdk/go/services/luks.GRPCClient` is the SDK LUKS client on every transport:
  it wraps the active transport's `LUKSServiceClient`. `platformctl luks`
  builds it from `platform.Client.LUKS()` (`pkg/cli/commands/luks/luks.go`).
- The SDK REST transport maps all ten operations to the REST routes above.
  Status, ListSlots and Info are the GETs with `?device=`
  (`sdk/go/transport/rest/luks.go`); the seven POSTs are in
  `sdk/go/transport/rest/adapter.go`. The server registrations
  (`pkg/api/daemon/luks_rest.go`) are authoritative.

---

## 3. Schema

Field names per transport:

- **gRPC:** `LUKS<Op>Request` / `LUKS<Op>Response` messages in `luks.proto`.
- **QUIC:** `quicwire.LUKS<Op>Req` / `LUKS<Op>Resp`
  (`sdk/go/wire/quicwire/phase35_types.go`), snake_case codec keys.
- **MCP:** snake_case arguments.
- **REST:** request bodies use the same snake_case keys as QUIC and MCP (the
  JSON tags on the daemon request structs). The status, list, info and enroll
  responses are the daemon result structs, which carry no JSON tags, so their
  keys are the **Go field names** (`IsLUKS`, `ActiveSlots`, `TokenID`,
  `RecoveryKey`, …); the SDK decodes them with the `sdk/go/services/luks` wire
  decoders it shares with MCP. The three REST responses that are not structs
  are `{"removed":true}`, `{"unlocked":<bool>}` and `{"changed":true}`.

| Operation | Request (QUIC / MCP name) | Required | Response |
|---|---|---|---|
| Status | `device` | `device` | `device`, `is_luks`, `version`, `uuid`, `label`, `cipher`, `active_slots` |
| ListSlots | `device` | `device` | `device`, `slots[]` (`slot`, `type`, `key_size`, `priority`) |
| Info | `device` | `device` | `device`, `uuid`, `label`, `version`, `cipher`, `key_size`, `sector_size`, `slots[]`, `metadata_json` |
| EnrollPassphrase | `device`, `existing_passphrase`, `new_passphrase` | all | `slot` |
| EnrollFIDO2 | `device`, `existing_passphrase`, `credential_id`, `require_pin`, `require_uv` | first three | `slot`, `token_id` |
| EnrollTPM | `device`, `existing_passphrase`, `pcrs` (int list), `handle` | first two | `slot`, `token_id` |
| EnrollRecovery | `device`, `existing_passphrase` | both | `slot`, `recovery_key` |
| RemoveKey | `device`, `slot` | both | `removed` |
| TestUnlock | `device`, `slot` | both | `unlocked` |
| ChangePassphrase | `device`, `slot`, `old_passphrase`, `new_passphrase` | all | `changed` |

The server does not range-check `slot`. On REST and QUIC an omitted `slot`
decodes as `0`.

---

## 4. Error mapping

| Service error | REST | gRPC | QUIC |
|---|---|---|---|
| `ErrLUKSNotConfigured` | 503 | `Unavailable` | `StatusUnavailable` |
| `ErrLUKSRootRequired` | 403 | `PermissionDenied` | `StatusPermissionDenied` |
| `ErrLUKS{Device,Passphrase,NewPassphrase,CredentialID,Slot}Required` | 400 | `InvalidArgument` | `StatusInvalidArgument` |
| any other error | 500 | `Internal` | `StatusInternalError` |
| `ErrLUKSMalformedBody` (REST body that is not valid JSON) | 400 | — | — |
| `ErrLUKSTestUnlockUnverified` (MCP test-unlock only) | — | `Unimplemented` | — |

REST errors are `{"error":"<message>"}`. A malformed REST body answers the fixed
message `luks: malformed request body`, never the JSON decoder's error, which
can quote a passphrase.

MCP returns the service error message with the gRPC code of the same error, so
an MCP caller reads the class a gRPC caller reads. The provider wraps every
service error in `ErrLUKSOperation` (`pkg/api/daemon/luks_grpc_service.go`),
which `errors.Is` still unwraps to the sentinel; the MCP server maps the code
to its wire class.

On every SDK transport a refusal reaches the caller as the operation's typed
error (`sdk/go/services/luks/errors.go`, for example `*ErrStatusFailed`) whose
cause is a gRPC status carrying the code in the table and the bare service
message. The SDK REST transport takes that message from the `error` key.

---

## 5. Authorization

| Transport | Requirement |
|---|---|
| REST | mTLS client certificate, which the daemon REST handshake requires. The LUKS routes are outside the scope guard: they take no `Bearer` token and check no scope. |
| gRPC TCP | a platform token carrying the method's `luks:*` scope (`pkg/api/grpc/method_permissions.go`). |
| QUIC | a platform token carrying the sub-opcode's `luks:*` scope (`pkg/api/quic/opcode_permissions.go`). |
| MCP | a platform token carrying the tool's `luks:*` scope (`toolPermissionCatalog`, `pkg/api/mcp/authz.go`). `platform_luks_test_unlock` is **refused**: it is unclassified, so `AuthorizeTool` denies it, and the provider itself refuses with `ErrLUKSTestUnlockUnverified`. |
| Unix | gRPC over the local socket; see [`docs/daemon/api.md`](../daemon/api.md). |

| Operation | gRPC, QUIC and MCP scope |
|---|---|
| Status, ListSlots, Info | `luks:read` |
| TestUnlock | `luks:read` on gRPC and QUIC; unclassified on MCP |
| EnrollPassphrase, EnrollFIDO2, EnrollTPM, EnrollRecovery, ChangePassphrase | `luks:write` |
| RemoveKey | `luks:delete` |

Test-unlock is refused over MCP because it proves nothing: the request carries
no key, and the backend only checks that the keyslot exists
(`pkg/app/backends/luks.go`), so `unlocked: true` would claim a key works
without trying one. gRPC, REST and QUIC still answer it that way.

LUKS has no tenancy. A request names only a device path, and neither
`LUKSService` nor its transports read a tenant.

Beyond transport authorization, mutating operations require platformd to run as
root ([architecture.md](architecture.md) §4).

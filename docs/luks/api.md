# LUKS Key-Slot Management — API

> **Status: NORMATIVE** · Scope: LUKS routes on every transport · Last verified: 2026-10-11
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
  (`pkg/api/quic/phase35_opcodes.go`), dispatched by `pkg/api/daemon/phase35_quic.go`.
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
| Test keyslot | `POST /api/v1/luks/keys/test-unlock` | `TestUnlock` | `0x09` | `platform_luks_test_unlock` | `MISSING — docs/13 G7` |
| Change passphrase | `POST /api/v1/luks/passphrase/change` | `ChangePassphrase` | `0x0A` | `platform_luks_change_passphrase` | `MISSING — docs/13 G7` |

### SDK client paths

- `sdk/go/services/luks.GRPCClient` reaches the gRPC and Unix transports.
- The SDK's default `Client` is a stub (every method returns `not yet wired`);
  it is what `platformctl luks` uses.
- The SDK REST adapter (`sdk/go/transport/rest/adapter.go`) maps status, list,
  info and the four enroll operations to the routes above, but maps the other
  three to routes the server does not register:

  | Operation | SDK REST adapter | Server |
  |---|---|---|
  | RemoveKey | `DELETE /api/v1/luks/slots` | `POST /api/v1/luks/keys/remove` |
  | TestUnlock | `POST /api/v1/luks/test-unlock` | `POST /api/v1/luks/keys/test-unlock` |
  | ChangePassphrase | `PUT /api/v1/luks/passphrase` | `POST /api/v1/luks/passphrase/change` |

  The server column is authoritative.

---

## 3. Schema

Field names per transport:

- **gRPC:** `LUKS<Op>Request` / `LUKS<Op>Response` messages in `luks.proto`.
- **QUIC:** `quic.LUKS<Op>Req` / `LUKS<Op>Resp` (`pkg/api/quic/phase35_types.go`),
  snake_case codec keys.
- **MCP:** snake_case arguments.
- **REST:** the daemon request and result structs carry no JSON tags, so REST
  bodies use the **Go field names** (`Device`, `ExistingPassphrase`, `Slot`, …).
  The three REST responses that are not structs are `{"removed":true}`,
  `{"unlocked":<bool>}` and `{"changed":true}`.

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
| malformed REST body | 400 | — | — |

REST errors are `{"error":"<message>"}`. MCP returns the service error message to
the caller.

---

## 5. Authorization

| Transport | Requirement |
|---|---|
| REST | mTLS client certificate (the daemon REST server authenticates by mTLS only). No per-route scope. |
| gRPC TCP | a platform token. `LUKSService` is not in the gRPC method-permission catalog, so no `scp` scope is required beyond a valid token. |
| QUIC | a platform token. `0x9C` has no opcode permission entry, so no `scp` scope is required beyond a valid token. |
| MCP | **refused.** The `platform_luks_*` tools have no permission mapping and are listed as unclassified, so `AuthorizeTool` denies every call. |
| Unix | gRPC over the local socket; see [`docs/daemon/api.md`](../daemon/api.md). |

Beyond transport authorization, mutating operations require platformd to run as
root ([architecture.md](architecture.md) §4). No `luks:*` scope is defined;
mutating operations that can wipe a keyslot are gated only by authentication and
the root check.

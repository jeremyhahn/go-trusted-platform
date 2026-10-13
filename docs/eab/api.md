# ACME External Account Binding — API

> **Status: NORMATIVE** · Scope: `pkg/eab/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

The platform's transport model, the QUIC frame format and the platform-wide
authorization picture are defined once in
[`docs/daemon/api.md`](../daemon/api.md). This file does not repeat them.

For EAB specifically:

| Transport | Entry point |
|---|---|
| Embedded | `ServiceRegistry.EAB` (`sdk/go/transport/embedded/adapter.go`), dispatched by gRPC full-method string |
| Unix | `platform.v1.EABService` over the platformd Unix socket — **the same gRPC service set** |
| gRPC | `platform.v1.EABService`, 11 RPCs (`pkg/api/grpc/proto/eab.proto`) |
| REST | `/api/v1/eab/credentials` (`pkg/webservice/v1/rest/eab/router.go`) |
| QUIC | `OpProvisioningCategory` (`0xCF`), sub-opcodes `0x10`–`0x1A` (`sdk/go/wire/quicwire/eab_opcodes.go`) |
| MCP | `platform_eab_*`, 11 tools (`pkg/api/mcp/eab_tools.go`) |

**One implementation backs all six.** `EABGRPCService`
(`pkg/api/daemon/eab_grpc_service.go`) wraps the canonical `eab.Service`; the
REST router, the QUIC dispatcher and the MCP provider all delegate to it, so
semantics and error mapping are identical everywhere.

Sub-opcode allocation under `0xCF`:

```
0x01-0x07  config delivery (provisioning_opcodes.go)
0x08-0x0F  reserved for config delivery growth
0x10-0x1A  EAB credential management (eab_opcodes.go)
```

---

## 2. Capabilities

Eleven capabilities, complete on all five reachable transports. The CLI column
is not one of the six transports and is shown separately in [cli.md](cli.md);
there is no `platformctl eab` group.

| Capability | Embedded (Go) | Unix | gRPC | REST | QUIC | MCP |
|---|---|---|---|---|---|---|
| Create credential | `EABService_CreateCredential_FullMethodName` → `svc.CreateCredential` | `CreateCredential` | `CreateCredential` | `POST /api/v1/eab/credentials` | `EABSubCreateCredential` (`0x10`) | `platform_eab_create_credential` |
| Get credential by ID | `EABService_GetCredential_FullMethodName` | `GetCredential` | `GetCredential` | `GET /api/v1/eab/credentials/{id:[0-9]+}` | `EABSubGetCredential` (`0x11`) | `platform_eab_get_credential` |
| Get credential by KeyID | `EABService_GetCredentialByKeyID_FullMethodName` | `GetCredentialByKeyID` | `GetCredentialByKeyID` | `GET /api/v1/eab/credentials/key/{key}` | `EABSubGetCredentialByKeyID` (`0x12`) | `platform_eab_get_credential_by_key_id` |
| List credentials | `EABService_ListCredentials_FullMethodName` | `ListCredentials` | `ListCredentials` | `GET /api/v1/eab/credentials` | `EABSubListCredentials` (`0x13`) | `platform_eab_list_credentials` |
| Revoke credential | `EABService_RevokeCredential_FullMethodName` | `RevokeCredential` | `RevokeCredential` | `POST /api/v1/eab/credentials/{id}/revoke` | `EABSubRevokeCredential` (`0x14`) | `platform_eab_revoke_credential` |
| Validate credential | `EABService_ValidateCredential_FullMethodName` | `ValidateCredential` | `ValidateCredential` | `POST /api/v1/eab/credentials/validate` | `EABSubValidateCredential` (`0x15`) | `platform_eab_validate_credential` |
| Delete credential | `EABService_DeleteCredential_FullMethodName` | `DeleteCredential` | `DeleteCredential` | `DELETE /api/v1/eab/credentials/{id}` | `EABSubDeleteCredential` (`0x16`) | `platform_eab_delete_credential` |
| Render QR code | `EABService_GetCredentialQRCode_FullMethodName` | `GetCredentialQRCode` | `GetCredentialQRCode` | `GET /api/v1/eab/credentials/{id}/qrcode` | `EABSubGetCredentialQRCode` (`0x17`) | `platform_eab_get_credential_qr_code` |
| Render enrollment URL | `EABService_GetEnrollmentURL_FullMethodName` | `GetEnrollmentURL` | `GetEnrollmentURL` | `GET /api/v1/eab/credentials/{id}/url` | `EABSubGetEnrollmentURL` (`0x18`) | `platform_eab_get_enrollment_url` |
| Mark credential used | `EABService_MarkCredentialUsed_FullMethodName` | `MarkCredentialUsed` | `MarkCredentialUsed` | `POST /api/v1/eab/credentials/{id}/used` | `EABSubMarkCredentialUsed` (`0x19`) | `platform_eab_mark_credential_used` |
| Cleanup expired | `EABService_CleanupExpiredCredentials_FullMethodName` | `CleanupExpiredCredentials` | `CleanupExpiredCredentials` | `POST /api/v1/eab/credentials/cleanup` | `EABSubCleanupExpiredCredentials` (`0x1A`) | `platform_eab_cleanup_expired_credentials` |

REST route ordering matters and is handled: `/credentials/cleanup`,
`/credentials/validate` and `/credentials/key/{key}` are registered **before**
`/credentials/{id:[0-9]+}`, and the `{id}` pattern is digits-only, so no literal
path segment is swallowed as an id.

An ergonomic Go wrapper over the same eleven is
`sdk/go/services/eab.Client` — note two names differ from the RPC:
`GetQRCode` (not `GetCredentialQRCode`) and `GetEnrollmentURL` returns a bare
`string`.

---

## 3. Request and response schemas

Messages are defined in `pkg/api/grpc/proto/eab.proto`. The REST bodies are the
protobuf JSON projections of the same messages.

### `EABCredential`

| Field | Type | Notes |
|---|---|---|
| `id` | `uint64` | Decimal string in JSON surfaces |
| `key_id` | `string` | `base64url`, no padding |
| `hmac_key` | `string` | `base64url`, no padding — **populated only in the create response** |
| `profile_id` | `uint64` | Device profile |
| `tenant_id` | `string` | |
| `status` | `EABCredentialStatus` | `UNSPECIFIED`/`ACTIVE`/`REVOKED`/`EXPIRED`/`USED` |
| `expires_at` | `Timestamp` | Absent when the credential does not expire |
| `created_at` | `Timestamp` | |
| `used_at` | `Timestamp` | Present once marked used |

### Create

`CreateEABCredentialRequest`: `profile_id` (required, non-zero), `tenant_id`
(required, non-empty), `expires_in_seconds` (`int64`, 0 = no expiry),
`hmac_key_length` (`int32`, 0 = 32, minimum 32).
`CreateEABCredentialResponse`: `credential` (with `hmac_key`), `timestamp`.
REST returns **201 Created**.

### List

`ListEABCredentialsRequest`: `tenant_id` (declared *required* in the proto
comment), `profile_id` (optional filter), `pagination` (`PaginationRequest`),
`status_filter` (`EABCredentialStatus`), `active_only` (`bool`).
`ListEABCredentialsResponse`: `credentials` (no `hmac_key`), `pagination`,
`total`, `timestamp`.

Pagination is the shared `PaginationRequest`/`PaginationResponse` from
`common.proto`. On the MCP surface, `page` and `page_size` of `0` mean "return
the full set"; the service walks the store in pages of `eabPageCollectSize`
(100) to assemble an unfiltered list.

### Validate

`ValidateEABCredentialRequest`: `key_id`, `hmac_key` (both required,
`base64url`).
`ValidateEABCredentialResponse`: `valid` (`bool`), `credential` (only when
valid, no `hmac_key`), `error_message`, `timestamp`.

**A failed validation is a successful call.** `valid=false` with an
`error_message` comes back as `StatusOK`/200, not as a transport error. Clients
must check `valid`, not just the status.

### Revoke

`RevokeEABCredentialRequest`: `credential_id`, `revoker_id` (`uint64`, "ID of
the user performing the revocation" — for the audit trail). The MCP tool marks
only `credential_id` as required; a missing `revoker_id` becomes `0`.

### QR code

`GetEABCredentialQRCodeRequest`: `credential_id`, `size` (`int32`, default 256).
`GetEABCredentialQRCodeResponse`: `qr_code` (`bytes`, PNG), `content_type`
(always `image/png`), `timestamp`. On MCP the PNG is base64-encoded in the tool
result.

### Enrollment URL

`GetEABEnrollmentURLRequest`: `credential_id`, `path` (optional override).
`GetEABEnrollmentURLResponse`: `url`, `timestamp`.

The URL is built from the configured base
(`https://<platform FQDN>:<REST port>`) with query parameters `kid`, `hmac` and
— when `path` is empty — `profile`. `ToURLWithPath` sets the path and omits
`profile`.

### Cleanup

`CleanupExpiredEABCredentialsRequest`: `tenant_id` (optional; empty = all
tenants). `CleanupExpiredEABCredentialsResponse`: `deleted_count` (`int32`),
`status`, `timestamp`.

---

## 4. Status and error mapping

| QUIC byte | Name | gRPC | REST | EAB cause |
|---|---|---|---|---|
| `0x00` | `StatusOK` | `OK` | 200 / 201 | — |
| `0x01` | `StatusInvalidRequest` | `InvalidArgument` | 400 | Malformed payload |
| `0x02` | `StatusNotFound` | `NotFound` | 404 | `ErrCredentialNotFound` |
| `0x03` | `StatusUnauthorized` | `Unauthenticated` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | `Internal` | 500 | `ErrKeyGenerationFailed`, `ErrQRCodeGenerationFailed`, `ErrFileExportFailed`, any unmatched error |
| `0x07` | `StatusPermissionDenied` | `PermissionDenied` | 403 | See §5 — no scope is currently required |
| `0x09` | `StatusInvalidArgument` | `InvalidArgument` | 400 | `ErrInvalidCredential`, `ErrInvalidProfileID`, `ErrInvalidTenantID`, `ErrInvalidExpiresAt`, `ErrCredentialExpired`, `ErrCredentialRevoked`, `ErrCredentialAlreadyUsed` (the last three as `FailedPrecondition`) |
| `0x0A` | `StatusUnavailable` | `Unavailable` | 503 | `ErrEABNotConfigured`, `ErrEABDeliveryNotConfigured` |

**503 on every EAB call means the platform is not QuicBaaS-backed** — the
service registry returned no `eab.Service`, so `requireService` refuses. It is
never `Unimplemented` and never a panic.

**503 on QR code or enrollment URL only** means the delivery handler is
unconfigured (`requireDelivery`) while the credential service is fine.

---

## 5. Authorization

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`EABService` is fully scoped on gRPC** (`pkg/api/grpc/method_permissions.go`):

| Permission | RPCs |
|---|---|
| `eab:read` | `GetCredential`, `GetCredentialByKeyID`, `GetCredentialQRCode`, `GetEnrollmentURL`, `ListCredentials`, `ValidateCredential` |
| `eab:write` | `CreateCredential`, `MarkCredentialUsed`, `RevokeCredential`, `CleanupExpiredCredentials` |
| `eab:delete` | `DeleteCredential` |

**QUIC requires the `eab` scopes (#767).** The EAB sub-opcodes of
`OpProvisioningCategory` (`0xCF`) are classified in
`pkg/api/quic/opcode_permissions.go`:

| Scope | Sub-opcodes |
|---|---|
| `eab:read` | `EABSubGetCredential`, `EABSubGetCredentialByKeyID`, `EABSubListCredentials`, `EABSubValidateCredential`, `EABSubGetCredentialQRCode`, `EABSubGetEnrollmentURL` |
| `eab:write` | `EABSubCreateCredential`, `EABSubRevokeCredential`, `EABSubMarkCredentialUsed` |
| `eab:delete` | `EABSubDeleteCredential`, `EABSubCleanupExpiredCredentials` |

**Every `platform_eab_*` MCP tool is refused.** None is in the MCP permission
map (`pkg/api/mcp/authz.go`), so `AuthorizeTool` answers
`AuthErrorToolNotClassified` for every caller until they are classified.

The `hmac_key` suppression on read paths is a separate control from the scope
check, so an `eab:read` holder still never sees an existing credential's secret.
It holds: `eabCredentialToPb(..., false)` on every path but create.

### REST is gated on the `admin` role (#165)

`/api/v1/eab/**` requires an authenticated caller holding `admin`. An EAB
credential is a bearer secret that authorises certificate issuance, so create,
revoke, delete and the credential listing are all credential-bearing — before
#165 they answered a caller with no token at all.

This changes the REST position only. The gRPC, Unix, QUIC, MCP and embedded
positions described above are unchanged. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 6. Pagination

`ListCredentials` is the only unbounded result set. It takes
`PaginationRequest` and returns `PaginationResponse` plus `total`. A request
with no pagination walks the whole store in pages of 100
(`eabPageCollectSize`) and returns everything — acceptable for fleet-sized
credential counts, not for unbounded ones.

`ListByProfile` and `ListByTenant` on the Go `Service` interface are
**unpaginated** and return a full slice. They are backed by full store scans
([engineering.md](engineering.md) §6).

---

## 7. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion` `0x01`
with EAB sub-opcodes `0x10`–`0x1A` under category `0xCF`. Nothing in this
feature is deprecated. No route has been renamed.

---

## 8. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC categories, the authorization catalogs
- [`docs/ca/`](../ca/) — the ACME surface
- [`docs/provisioning/`](../provisioning/) — the flow that consumes a credential

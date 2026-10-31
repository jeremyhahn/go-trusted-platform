# EAB gRPC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `platform.v1.EABService` RPCs and the typed-error to gRPC code mapping.

| Property | Value |
|----------|-------|
| Service | `platform.v1.EABService` |
| Proto | `pkg/api/grpc/proto/eab.proto` |
| Endpoints | gRPC TCP `:10443` and gRPC UDS `/run/platformd.sock` |
| Implementation | `pkg/api/daemon/eab_grpc_service.go` |

## RPCs

| RPC | Semantics |
|-----|-----------|
| `CreateCredential` | Generates a credential; the response is the **only** place the HMAC key (base64url, no padding) is ever returned. `expires_in_seconds` 0 = no expiry; negative is `InvalidArgument`. |
| `GetCredential` / `GetCredentialByKeyID` | Lookup by id / KeyID; HMAC key never included. |
| `ListCredentials` | Filter cascade: `profile_id` (with `tenant_id` refining), else `tenant_id`, else the full store. `status_filter` / `active_only` refine; pagination applies last so totals reflect the filtered set. `sort_by` supports `id` (default) and `created_at` with the `ascending` flag; unknown fields are `InvalidArgument`. |
| `RevokeCredential` | Marks revoked; `revoker_id` is only written to the daemon log, not stored with the credential. |
| `ValidateCredential` | Constant-time `(key_id, hmac_key)` check. Validation failures return `valid=false` + `error_message` in-band (not an RPC error); malformed base64 is `InvalidArgument`. |
| `DeleteCredential` | Permanent removal. |
| `GetCredentialQRCode` | PNG QR at the requested pixel `size` (0 = configured default, negative = `InvalidArgument`). |
| `GetEnrollmentURL` | Enrollment URL with credentials as query params; optional `path` override. |
| `MarkCredentialUsed` | Post-enrollment consumption. |
| `CleanupExpiredCredentials` | `tenant_id` set → deletes only that tenant's expired credentials; empty → store-wide cleanup. |

## Error mapping

Typed `pkg/eab` errors map through an ordered matcher table
(`eabErrorMatchers`):

| Domain error | gRPC code |
|--------------|-----------|
| `ErrCredentialNotFound` | `NotFound` |
| `ErrInvalidProfileID`, `ErrInvalidTenantID`, `ErrInvalidExpiresAt`, `ErrInvalidCredential` | `InvalidArgument` |
| `ErrCredentialExpired`, `ErrCredentialRevoked`, `ErrCredentialAlreadyUsed` | `FailedPrecondition` |
| `ErrKeyGenerationFailed`, `ErrQRCodeGenerationFailed` | `Internal` |
| unknown | `Internal` |

An unconfigured backing service or delivery handler returns
`Unavailable` via the `requireService` / `requireDelivery` guards.

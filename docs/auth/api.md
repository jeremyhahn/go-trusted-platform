# Platform Authentication — API

> **Status: NORMATIVE** · Scope: `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. `pkg/auth` has no API surface

There is no `AuthService` on gRPC, no `/api/v1/auth/*` route group, no QUIC
opcode category, and no `platform_auth_*` MCP tool. `pkg/auth` is a library
consumed in-process by interceptors and by `pkg/proxy`. Verified 2026-08-18.

What this folder's API surface *is*, is two disjoint things:

- **§3 — session and credential capabilities** the platform exposes (REST
  login, refresh, WebAuthn) or explicitly does not (N-factor management, which
  is served by go-quicbaas).
- **§4 — the per-transport authentication mechanisms.** These are not
  capabilities *on* transports; they are what each transport does to every
  request. They are tabulated separately because forcing them into a
  six-transport matrix would say something false.

The transport model itself, the QUIC frame format, the status-byte vocabulary
and the platform-wide authorization catalogs are defined once in
[`docs/daemon/api.md`](../daemon/api.md). This file does not repeat them.

---

## 2. What is documented elsewhere

| Looking for | Go to |
|---|---|
| Users, groups, roles, policies, applications, tokens | [`docs/iam/api.md`](../iam/api.md) |
| Invitations | [`docs/iam/api-reference-invitations.md`](../iam/api-reference-invitations.md) |
| Certificate issuance, revocation, CRL | [`docs/ca/`](../ca/) |
| Transport model, opcodes, status bytes, scope catalogs | [`docs/daemon/api.md`](../daemon/api.md) |
| Edge-gateway authorization chain | [`docs/proxy/`](../proxy/) |

---

## 3. Session and credential capabilities

| Capability | Embedded (Go) | Unix | gRPC | REST | QUIC | MCP |
|---|---|---|---|---|---|---|
| Issue session token (JWT) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/login` (`GenerateToken`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Refresh session token | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/login/refresh` (`RefreshToken`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| WebAuthn: begin registration | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/webauthn/registration/begin` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| WebAuthn: finish registration | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/webauthn/registration/finish` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| WebAuthn: registration status | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `GET /api/v1/webauthn/registration/status` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| WebAuthn: begin login | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/webauthn/login/begin` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| WebAuthn: finish login | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/webauthn/login/finish` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| OAuth 2.1 protected-resource metadata (RFC 9728) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `GET\|HEAD /.well-known/oauth-protected-resource` |
| Factor login (mTLS / FIDO2 / PIV) | not this repo | not this repo | not this repo | not this repo | not this repo | not this repo |
| Factor list / add / remove / rotate / relabel | not this repo | not this repo | not this repo | not this repo | not this repo | not this repo |
| Credential submit / list / rotate | `MISSING` (CLI stub) | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Certificate → identity (mTLS authentication) | `auth.MTLSAdapter.Authenticate` | see §4 | see §4 | see §4 | see §4 | see §4 |

**"not this repo"** means the capability is served by
`go-quicbaas/sdk/go`'s `Security().Auth().Factors()` (M10, over go-qrdb's M14
User N-AuthFactor service), reached through the thin wrapper
`sdk/go/services/auth`. The platform exposes no route for it on any of its six
transports, by design — it is not a gap on the platform's side.

**"`MISSING` (CLI stub)"** on the credential row means the verbs exist in the
CLI tree and return `PendingCredentialBackendError`; no transport carries them.
The locked CLI surface defines seven credential verbs
([cli.md](cli.md) §6).

### The `docs/13 G7` rows are large and real

Every session capability the platform *does* serve is **REST-only**. There is no
way to obtain or refresh a platform JWT over gRPC, Unix, QUIC or MCP. A gRPC or
QUIC client must have been given a token by some other means — the CLI's
go-quicbaas login, or an operator.

---

## 4. Per-transport authentication mechanisms

This is what each transport does to every request, not a capability you call.

| Transport | Mechanism | Implementation | Failure |
|---|---|---|---|
| Embedded | **None.** In-process calls are trusted; there is no wire to authenticate. | `sdk/go/transport/embedded/` | — |
| Unix | `SO_PEERCRED` — kernel-verified PID/UID/GID. No token, no certificate. | `pkg/api/grpc/unix_credentials.go` | `ErrUnixCredentialsUnavailable`, `ErrNotUnixConnection`, `ErrPeerNotAvailable` |
| gRPC (TCP) | mTLS client certificate → `auth.Authenticator` → `*auth.Identity` on the context | `pkg/api/daemon/mtls_interceptor.go` | `codes.Unauthenticated` |
| gRPC (TCP) | Bearer platform token in the `authorization` metadata header; claims path projects `scp` → RBAC and `tenant_id` → RLS | `pkg/api/grpc/oidc_interceptor.go` | `codes.Unauthenticated`; scope denial → `codes.PermissionDenied` |
| REST | JWT middleware; `/login` and `/login/refresh` are its own endpoints | `pkg/webservice/v1/middleware`, `router/authentication.go` | 401 |
| QUIC | Bearer token in the request frame's token field (`MaxTokenSize` 8 KiB), then per-opcode scope | `pkg/api/quic/auth.go` | `StatusUnauthorized` (`0x03`), `StatusPermissionDenied` (`0x07`), `StatusUnavailable` (`0x0A`) |
| MCP | OAuth 2.1 bearer token, RFC 9728 metadata, per-tool permission map | `pkg/api/mcp/authz.go`, `oauth_metadata.go` | JSON-RPC error codes, §6 |

### Unix is the strongest and the least expressive

`SO_PEERCRED` cannot be forged — the kernel fills it in. It also carries **no
tenant and no roles**: `RequireRoot`, `RequireUID`, `RequireGID` and
`RequireUIDOrRoot` are the entire vocabulary. A local root process is
authenticated as root, not as a tenant principal.

### mTLS and token authentication are independent

The gRPC TCP server installs *either* the mTLS interceptors (when
`EnableMTLS && CAService != nil`) *or* the token interceptors, depending on how
the daemon was assembled. They are not layered by default; do not assume a
request that passed one also passed the other.

---

## 5. OAuth 2.1 protected-resource metadata

```
GET  /.well-known/oauth-protected-resource
HEAD /.well-known/oauth-protected-resource
```

Mounted on the MCP server's HTTP mux (`pkg/api/mcp/server.go`). Any other
method returns **405** with `Allow: GET, HEAD`. Responses carry
`Cache-Control: public, max-age=3600`.

Response body (`OAuthProtectedResourceMetadata`, RFC 9728):

| Field | JSON | Notes |
|---|---|---|
| `Resource` | `resource` | Required; this MCP server's identifier URL |
| `AuthorizationServers` | `authorization_servers` | Required |
| `ScopesSupported` | `scopes_supported` | See below |
| `BearerMethodsSupported` | `bearer_methods_supported` | Always `["header"]` |
| `ResourceDocumentation` | `resource_documentation` | Optional |
| `ResourceSigningAlgValuesSupported` | `resource_signing_alg_values_supported` | Optional; not populated |
| `ResourceEncryptionAlgValuesSupported` | `resource_encryption_alg_values_supported` | Optional; not populated |
| `ResourceEncryptionEncValuesSupported` | `resource_encryption_enc_values_supported` | Optional; not populated |

`getSupportedScopes` returns a **hard-coded** list, verified 2026-08-18:

```
mcp:tools, mcp:resources,
vtpm:read|write|delete, device:read|write|delete, dns:read|write|delete,
sdn:read|write|delete, ca:read|write|delete, kms:read|write|delete,
iam:read|write|delete, container:read|write|delete,
attestation:read|write, tenant:read|write|delete,
platform:admin
```

**This list is advertised, not enforced.** It is broader than the MCP
authorization map (`initToolPermissions` covers only the vtpm, dns, device,
profile, gateway-lb, gateway-perf, sdn, proxy and ntp families) and narrower
than the tool set (449 declared tool names). A client that requests `ca:write`
because the metadata offers it will find no `ca_*` tool checks it.

`Validate()` requires a non-empty `Resource` and at least one authorization
server, returning `OAuthMetadataError` with `OAuthMetadataErrorMissingResource`
or `OAuthMetadataErrorMissingAuthServer`. `DefaultOAuthMetadataConfig` returns
empty values, so **an unconfigured handler serves metadata that fails its own
`Validate`** — nothing calls `Validate` on the serving path.

### WWW-Authenticate challenge (RFC 6750)

`WWWAuthenticateChallenge(realm, scope, errorCode, errorDescription)` builds:

```
Bearer realm="Trusted Platform MCP", scope="vtpm:write", error="invalid_token", error_description="..."
```

`realm` defaults to `BearerRealm` = `"Trusted Platform MCP"` when empty. Empty
`scope`, `errorCode` and `errorDescription` are omitted.

---

## 6. Error mapping

### MCP authorization errors

| `AuthorizationError.Type` | Raised when |
|---|---|
| `AuthErrorMissingToken` | Tool requires a permission and no token was presented |
| `AuthErrorInvalidToken` | Token validation or liveness failed |
| `AuthErrorPermissionDenied` | `platformtoken.ScopeDeniedError`, or the PEP said no |

### `pkg/auth` errors at a transport boundary

| `pkg/auth` error | gRPC | REST | QUIC |
|---|---|---|---|
| `ErrNilCertificate`, `ErrMTLSNoCertificates` | `Unauthenticated` | 401 | `0x03` |
| `ErrCertificateExpired`, `ErrCertificateInvalid` | `Unauthenticated` | 401 | `0x03` |
| `ErrChainValidationFailed` | `Unauthenticated` | 401 | `0x03` |
| `ErrCertificateRevoked` | `Unauthenticated` | 401 | `0x03` |
| `ErrIdentityNotFound`, `ErrTenantNotFound` | `Unauthenticated` | 401 | `0x03` |
| `ErrTPMAttestationFailed` | context-dependent — see [`docs/attestation/`](../attestation/) | | |

The mTLS interceptor wraps every one of them as
`status.Errorf(codes.Unauthenticated, "mtls: %v", err)`, so the specific cause
reaches the client as a message, not as a distinguishable code.

---

## 7. Authorization

Authentication is enforced on every transport. **Authorization is enforced only
where a scope-catalog entry exists**, and both catalogs default to allow:

| Catalog | Coverage | Default for an unlisted entry |
|---|---|---|
| gRPC `pkg/api/grpc/method_permissions.go` | 185 of 461 RPCs, 11 of 31 services | Allowed once the token validates |
| MCP `pkg/api/mcp/authz.go` | 71 of 449 declared tool names | `AuthorizeTool` returns no error |

Detail, service lists and the standing owner question are in
[`docs/daemon/api.md`](../daemon/api.md) §5. They are not restated here.

Three MCP tools are explicitly public (empty required permission):
`platform_health`, `platform_liveness`, `platform_readiness`.
On QUIC, `OpHealth`, `OpLiveness` and `OpReadiness` map to `nil` in
`DefaultOpcodePermissions`.

---

## 8. Versioning and deprecation

REST under `/api/v1`; the metadata endpoint is at the HTTP root per RFC 9728 and
is not versioned by the platform.

Deprecated and **removed**, per the legacy `docs/auth/README.md` security
principles and confirmed absent from the code: **API-key authentication** and
**password authentication** on the platform API. Authentication is
certificate-based (mTLS, IDevID), WebAuthn/FIDO2/PIV, or bearer token.

---

## 9. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, status bytes, authorization catalogs
- [`docs/iam/api.md`](../iam/api.md) — identity and RBAC
- [`docs/ca/`](../ca/) — certificates

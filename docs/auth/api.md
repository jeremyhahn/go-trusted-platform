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
consumed in-process by interceptors and by `pkg/proxy`.

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
| Invitations | [`docs/tenant/architecture.md`](../tenant/architecture.md) |
| Certificate issuance, revocation, CRL | [`docs/ca/`](../ca/) |
| Transport model, opcodes, status bytes, scope catalogs | [`docs/daemon/api.md`](../daemon/api.md) |
| Edge-gateway authorization chain | [`docs/proxy/`](../proxy/) |

---

## 2b. Admin claim ceremony (REST)

> Code: `pkg/webservice/v1/adminclaim/` · Architecture:
> [architecture.md §6b](architecture.md).

The one-time flow that binds an operator's authenticator to the first-boot
system admin. **REST only.** These routes exist to run before any session
does; adding them to a transport whose only client is an already-authenticated
one would be surface without a purpose. When the deployment cannot support the
ceremony (no SDK ceremony client, no factor client, no trust anchor, no
operating tenant) they are **not registered at all** — a 404, never an
unguarded endpoint.

The same 404 applies when `JWT.PlatformToken.Enabled` is set. The ceremony's
finish step returns a platform-local JWT, and that configuration makes the
broker platform-token validator the inbound seam, which accepts only
broker-issued bearers — so a completed claim would return a bearer every
protected route rejects. Converging the two token types is
#202; until it lands, the flow is offered only where its
session works.

Every route is pre-auth. What protects them is the certificate proof, the
single-use short-lived secrets, and the fact that the flow is closed while an
authenticator is enrolled (removing the last factor re-opens it — the
recovery path for a lost key; see
[architecture.md §6b.5](architecture.md)).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/admin/claim/status` | Is this node's admin identity claimed? |
| `POST` | `/api/v1/admin/claim/challenge` | Issue a possession nonce |
| `POST` | `/api/v1/admin/claim/verify` | Exchange a proof for a claim token |
| `POST` | `/api/v1/admin/claim/passkey/begin` | Start WebAuthn registration |
| `POST` | `/api/v1/admin/claim/passkey/finish` | Complete it; returns a console bearer |

### `GET /api/v1/admin/claim/status`

```json
{ "claimed": false, "username": "admin", "tenant_id": "system" }
```

Discloses no secret — only whether the one-time flow is still open, so the
console can route a fresh node to its setup page. **Fails closed:** an SDK
error answers `500`, never `claimed: false`.

### `POST /api/v1/admin/claim/challenge`

No body. Returns a single-use nonce valid for two minutes:

```json
{ "challenge": "8Kx...", "expires_at": "2026-09-01T18:04:00Z" }
```

`429` when too many nonces are outstanding — the store refuses rather than
evicting, so an attacker cannot flush the operator's live challenge.

### `POST /api/v1/admin/claim/verify`

```json
{
  "challenge": "8Kx...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "signature": "<base64 DER signature over the challenge string>"
}
```

ECDSA and RSA sign the SHA-256 digest of the challenge (ASN.1 / PKCS#1 v1.5);
Ed25519 signs it unhashed. When the TLS handshake already presented the admin
certificate the body may be **entirely absent** — the handshake is the proof,
and the peer certificate is checked before the request body is consulted at
all. Only an absent body is tolerated: a truncated or malformed one is still
`400`, whether or not a certificate was presented, because quietly ignoring
it would hide a client bug.

Returns a single-use claim token valid for ten minutes:

```json
{ "claim_token": "u7Q...", "expires_at": "2026-09-01T18:12:00Z" }
```

### `POST /api/v1/admin/claim/passkey/{begin,finish}`

Both carry the claim token in the **`X-Admin-Claim`** header — a header, not a
bearer, so it can never be mistaken for or replayed as a session token.
`begin` returns the browser's `CredentialCreation` object with the SDK
`session_id` alongside; `finish` takes the raw
`navigator.credentials.create()` body and echoes the session id back in
`X-Session-Id`, matching the WebAuthn handler's convention.

`begin` checks the claim token but does not spend it — `finish` still needs
it. `finish` spends it **whatever the ceremony's outcome**, so a failed
attestation cannot be retried against the same proof. On success it returns
the console bearer for the now-claimed system admin:

```json
{ "token": "<platform JWT>", "tenant_id": "system" }
```

On a deployment running several `platformd` instances against one store, the
four mutating routes answer **`501`** with `ErrMultiInstanceUnsupported` —
the ceremony's one-time state is process-local, so it is not served there
(#170). `status` still answers `200`: it mutates nothing, and the console has
to be able to tell a clustered node from a broken one.

### Error mapping

| Condition | Status | Body |
|---|---|---|
| Any proof rejection — unknown/spent challenge, bad chain, wrong identity, bad signature, bad claim token | `403` | `adminclaim: admin credential proof rejected` |
| Already claimed | `403` | `adminclaim: the system admin identity has already been claimed` |
| Attestation reported unverified by the SDK | `400` | `adminclaim: the SDK rejected the authenticator attestation` |
| Malformed body | `400` | decode error |
| Too many outstanding secrets | `429` | capacity error |
| SDK unreachable | `500` | wrapped SDK error |

Every proof rejection returns the **same** generic reason. Distinguishing them
would let a caller probe the trust anchor, the identity rule and the challenge
store independently of one another.

---

## 3. Session and credential capabilities

| Capability | Embedded (Go) | Unix | gRPC | REST | QUIC | MCP |
|---|---|---|---|---|---|---|
| Issue session (mTLS factor) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/login` (`GenerateToken`) — **declined 403**, see below | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Refresh session token | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `/api/v1/login/refresh` (`RefreshToken`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Revoke session (logout) | `MISSING — #213` | `MISSING — #213` | `MISSING — #213` | `MISSING — #213` (no route; see below) | `MISSING — #213` (`OpAuthLogout` reserved) | `MISSING — #213` |
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

### Platform session token claims

`jwt.Service` signs the platform session bearer (RS256 with the web
service's key) with these claims (`jwt.TokenClaims`):

| Claim | JSON type | Meaning |
|---|---|---|
| `sub` | string | Session principal (same value as `user_id`) |
| `user_id` | string | Session principal: the platform user id in a platform-issued token, the backbone subject in a backbone-issued session |
| `uid` | string, decimal | The platform user-store key. Omitted in a backbone-issued session |
| `email` | string | Principal's email |
| `tenant_id` | string | Tenant the session is scoped to. A browser login's is the principal's own workspace, never the operating tenant ([architecture](architecture.md#which-tenant-a-login-lands-in)) |
| `is_tenant_owner` | bool | Tenant owner flag. Always `false` in a backbone-issued session: the SDK identity carries no ownership attribute |
| `roles` | string array | RBAC roles. A browser login's are the principal's roles in its workspace, never the operating tenant's |
| `svcs` | number array | Service references. No issuer sets it, so it is always `null` today; it must become a string array before it carries an id |
| `iss`, `aud`, `iat`, `nbf`, `exp` | registered claims | Issuer, audience, validity window |

User ids are xxhash64 values, almost all above 2^53, so `uid` is a decimal
**string**, never a JSON number. A number reaches every schemaless decoder
(`jwt.MapClaims`, a browser's `JSON.parse`) as a float64 that names a different
user (#642). Read it with `TokenClaims.PlatformUserID()` or
`strconv.ParseUint(uid, 10, 64)`. A missing or non-decimal `uid` is refused:
`/api/v1/login/refresh` answers 401, session creation answers 400, and the
tenant middleware answers 401 (`ErrMissingUserClaim`). A backbone-issued
session carries no `uid`, so it is refused the same way and renews by logging
in again ([every such site](architecture.md#why-the-platform-still-mints-the-bearer)
is listed in the architecture).

### Registration model — iam.self_service_registration

Whether an uninvited user may register is governed by the canonical
stack-wide flag (docs/08-bootstrap-auth-contract.md §Registration model).
Platform YAML carrier:
`quicbaas.self-service-registration.enabled` — **default false,
invite-only**; the value also passes through to the embedded server's
`iam.self_service_registration`. When disabled,
`POST /api/v1/webauthn/registration/begin` WITHOUT an `invitation_token`
returns 403 with the typed public-registration-disabled error; invited
registrations are unaffected. When enabled, self-registration creates a
new tenant with the registrant as its tenant admin (see the tenant
onboarding issues #157–#159 for the full model).

### WebAuthn REST browser contract

The four ceremony endpoints speak the browser's native shapes; all
ceremony state (challenge / session) lives in the quicbaas SDK and the
platform persists none of it:

- **`registration/begin` takes `{"email", "invitation_token"?}` and
  validates the address before anything else is derived from it.** The
  address becomes the user id, the tenant owner label and the mirrored IAM
  identity, so an address the IAM identity store would reject
  (`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`) is answered 400
  (`service.ErrInvalidEmail`) at begin. No ceremony is opened, no
  registration session is stored and no user or tenant is created (#643).
  Invitations apply the same rule (`service.ValidateEmail`). The SDK does
  not export IAM's validator, so the platform holds the one copy.
- **Registration lands in the user's workspace, never the operating
  tenant (#662).** An invitation into the operating tenant is answered 403
  at `registration/begin`, and `registration/finish` answers 403 instead of
  issuing a session when the registered user resolves to no tenant or to
  the operating tenant (docs/auth/architecture.md, "Which tenant a login
  lands in").
- **Begin** (`registration/begin`, `login/begin`) returns the parsed
  WebAuthn options object: `publicKey` at the top level, plus
  `session_id` — the ceremony session the client must echo back.
  Registration passes the SDK user handle through in `publicKey.user.id`
  untouched.
- **`login/begin` takes no request body and returns no user identifier.**
  The login ceremony is usernameless: it sends no hint to the backbone,
  which drives the discoverable-credential flow, so the authenticator
  selects the credential and the backbone resolves the principal from the
  credential id in the assertion. There is consequently no `user_id` field
  and no `X-User-ID` response header on `login/begin`, and no username to
  supply. That is what makes an account on a public email domain an
  ordinary case rather than a lookup problem.
- **Finish** (`registration/finish`, `login/finish`) accepts the raw
  `PublicKeyCredential` JSON produced by the browser as the request body.
  `login/finish` needs one header, `X-Session-Id` (the `session_id` from
  begin); registration additionally needs `X-User-Id`, the base64url SDK
  user handle from `publicKey.user.id`. A finish without `X-Session-Id`
  fails closed with HTTP 400 ("restart the ceremony"); the credential is
  validated against that session's challenge, so a forged or stale
  session id fails verification.
- `login/finish` returns the **session the login issued** in the envelope
  payload — `bearer` and `expiresAt`. The ceremony runs entirely on the
  backbone, which verifies the assertion and resolves the principal; the
  `bearer` is then minted by the platform's JWT signer from that identity,
  because the seam every protected route runs (`Router.authMiddleware`)
  validates platform-signed tokens and the SDK has no working inbound
  validator for the backbone's own OIDC bearer — `sdk/go/client/auth`'s
  `ValidateToken` asserts `*service.TokenClaims` while the embedded
  transport answers with `*service.ValidateTokenResponse`
  (jeremyhahn/go-quicbaas#955). Forwarding the backbone bearer instead
  would hand every client a token this same server rejects.

  The mint is a projection of the backbone's verdict, not an
  authentication: it happens only after the ceremony succeeded, only from
  the identity the ceremony resolved, and a bearer with no identity is
  refused 401 rather than turned into an anonymous credential. It is
  confined to one seam, `login.SessionIssuer`, and disappears when the
  inbound validator lands (#202, phases 3 and 4 of #644).

  **No renewal credential is returned.** The backbone mints one with its
  own bearer, but that credential renews the BACKBONE's session and the
  client is not holding the backbone's bearer. Forwarding it would hand
  over a credential no route on this server can redeem. The pair returns
  together in the same change that makes the backbone bearer the session.

  **The session lands in the principal's workspace.** Its `tenant_id` is
  the tenant registration created for the user or an invitation joined them
  to, not the operating tenant the ceremony ran in. A principal with no
  workspace — no platform user, no tenant, a deleted tenant, or one that is
  the operating tenant — is refused **403** (`login.NoWorkspaceError`) after
  a good assertion, and no bearer is issued (#662). Its `roles` are the
  principal's roles in that workspace, read from the workspace's IAM user,
  never the operating tenant's; a principal the workspace does not hold has
  none, and a failed lookup is a **500** with no bearer
  ([architecture](architecture.md#which-tenant-a-login-lands-in)).

**`/api/v1/login` answers 403.** The route exists and its mTLS factor is
deliberately closed: the platform cannot bind the caller's peer certificate to
the ceremony through `sdk/go` (jeremyhahn/go-quicbaas#857), and opening one
anyway would let a **remote** transport resolve the identity of *platformd's*
own client certificate for an unauthenticated caller. The refusal is in the
binder, before the backbone is reached, on both ceremony verbs. Rationale and
failure mode: `docs/auth/architecture.md` §The mTLS factor is declined. WebAuthn
login is unaffected — it is a different factor on the same driver.

**There is no server-side logout, and the SDK cannot provide one yet (#213).**
The console's session is the platform JWT that `login.SessionIssuer` mints
(`jwt.Service.IssueSession`), not the backbone's bearer. The backbone never
issued it and never sees it: `jwt.Service` verifies it by signature, audience
and expiry and checks no session state, and it carries no `jti`. The SDK's revocation verb,
`sdk/go/client/auth` `Logout(ctx, accessToken)`, reaches the backbone's
`OIDCProvider.RevokeSessionToken`, which revokes only bearers the backbone itself
issued through `IssueSessionToken`. So passing the platform JWT to it cannot make
a replay fail. A platform-local deny-list would be a local reimplementation of
session revocation, which this repository does not build. Logout becomes possible
when the backbone's bearer *is* the session (#202, phases 3 and 4 of #644). That
needs an inbound SDK validator, and `ValidateToken` is still broken on the
embedded transport in `sdk/go` v0.14.0-alpha (jeremyhahn/go-quicbaas#955).
Until then, the console's sign-out only clears the browser's copy, and the token
stays valid until it expires.

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
| Embedded | **None on the wire** — there is none. The embedder attaches the caller's identity through `ServiceRegistry.CallerContext`; platformctl's embedded host (GUI standalone mode and CLI `embedded` contexts) attaches its own process's PID/UID/GID (`peercred.ContextWithProcessCredentials`), so its calls hold what a Unix socket peer of that uid holds. No hook, no identity. | `sdk/go/transport/embedded/`, `pkg/api/daemon/embedded_host.go` | Whatever the service refuses an unidentified caller, e.g. sign-csr → `codes.PermissionDenied` (`docs/ca/api.md`) |
| Unix | `SO_PEERCRED` — kernel-verified PID/UID/GID. No token, no certificate. | `pkg/util/peercred/peercred.go` | `ErrUnixCredentialsUnavailable`, `ErrNotUnixConnection`, `ErrPeerNotAvailable` |
| gRPC (TCP) | mTLS client certificate → `auth.Authenticator` → `*auth.Identity` on the context | `pkg/api/daemon/mtls_interceptor.go` | `codes.Unauthenticated` |
| gRPC (TCP) | Bearer platform token in the `authorization` metadata header; claims path projects `scp` → RBAC and `tenant_id` → RLS | `pkg/api/grpc/oidc_interceptor.go` | `codes.Unauthenticated`; scope denial → `codes.PermissionDenied` |
| REST | JWT middleware; `/login` and `/login/refresh` are its own endpoints. `/login` authenticates nothing itself — it drives the unified login ceremony (`pkg/webservice/v1/login`) with the mTLS factor and issues the session credential from the identity that ceremony resolved | `pkg/webservice/v1/middleware`, `router/authentication.go` | 401 |
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

`scopes_supported` is **derived, not maintained** (#315): `getSupportedScopes`
returns every distinct scope the MCP tool permission catalog
(`toolPermissionCatalog`, `pkg/api/mcp/authz.go`) requires, sorted. The
authorization checker enforces the same catalog, so the advertised list is
exactly the enforced vocabulary — a scope cannot be required by a tool without
being advertised, or advertised without a tool requiring it. Open tools (empty
permission) contribute nothing. The set the catalog derives today:

```
attestation:read|write,
bmc:read|write|power|media|admin,
ca:read|write|sign-csr,
ceremony:read|write,
device:read|write|delete, dns:read|write|delete,
fido2:read|write,
iam:read,
invitation:read|write|delete,
ntp:read|write,
piv:read|write,
proxy:read|write|delete,
sdn:read|write|delete,
vtpm:read|write|delete
```

Scopes no MCP tool consults — `mcp:tools`, `mcp:resources`, `platform:admin`,
the `kms:*`, `container:*` and `tenant:*` families, `iam:write`, `iam:delete`
and `ca:delete` — are no longer advertised. `iam:read` is advertised since
`iam_verify_token` requires it (#304). A tool family added to the catalog is advertised by
the same change; `TestOAuthMetadataHandler_getSupportedScopes` fails if the two
ever disagree, or if a catalog permission is not a well-formed
`resource:action` scope.

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

Authentication is enforced on every transport. All three scope catalogs are
**default-deny** ([architecture.md](architecture.md)): an operation with no
catalog entry is refused, not allowed.

| Catalog | Coverage | Default for an unlisted entry |
|---|---|---|
| gRPC `pkg/api/grpc/method_permissions.go` | Every registered RPC; a contract test keeps it that way | Refused with `PermissionDenied` (`ErrMethodNotClassified`) before the token is read, unless the method is on the documented pre-auth list |
| MCP `pkg/api/mcp/authz.go` | All 487 registered tools (475 scoped, 12 open); a contract test keeps it that way | `AuthorizeTool` refuses it with `AuthErrorToolNotClassified` |
| QUIC `pkg/api/quic/opcode_permissions.go` | every routable opcode and sub-opcode | Denied (`StatusPermissionDenied`, #767) |

Detail, the pre-auth list and the open MCP tools are in
[`docs/daemon/api.md`](../daemon/api.md) §5. They are not restated here.

Eleven MCP tools are explicitly public (empty required permission):
`platform_health`, `platform_liveness`, `platform_readiness`,
`platform_invitation_get_by_token`, `platform_invitation_accept`,
`device_boot_certificate`, `device_boot_delivery`, `provision_get_nonce`,
`provision_fetch_config`, `provision_sign_digest` and `provision_poll_session`.
The two boot tools are open because a diskless node holds no token; the boot
service authenticates the caller itself and refuses on MCP, which carries no
TLS state. The four provisioning tools are pre-auth on gRPC too; the config
delivery service checks the nonce, EAB HMAC and EK binding itself, and a poll
needs the random session ID ([`docs/provisioning/api.md`](../provisioning/api.md) §6).
On QUIC, `OpHealth`, `OpLiveness`, `OpReadiness` and `OpIAMAuthenticate`
are the pre-auth list of the operation catalog
(`pkg/api/quic/opcode_permissions.go`), and `preAuthSubOpcodes` opens the
boot and pre-enrollment provisioning sub-opcodes and the invitee pair under
`OpIAMCategory`, `InvitationSubGetByToken` and `InvitationSubAccept` (#704).
Every other QUIC operation is classified there or refused (#767).

---

## 8. Versioning and deprecation

REST under `/api/v1`; the metadata endpoint is at the HTTP root per RFC 9728 and
is not versioned by the platform.

Deprecated and **removed**, per the deleted legacy `docs/auth/README.md` security
principles and confirmed absent from the code: **API-key authentication** and
**password authentication** on the platform API. Authentication is
certificate-based (mTLS, IDevID), WebAuthn/FIDO2/PIV, or bearer token.

---

## 9. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, status bytes, authorization catalogs
- [`docs/iam/api.md`](../iam/api.md) — identity and RBAC
- [`docs/ca/`](../ca/) — certificates

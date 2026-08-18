# Platform Authentication — Architecture

> **Status: NORMATIVE** · Scope: `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Read this first: what `pkg/auth` actually is

**`pkg/auth` is a certificate-to-identity extractor. That is the whole
package.** Five non-test Go files, no storage, no network calls of its own, no
tokens, no sessions, no roles, no policy.

Given an `*x509.Certificate` it will: check validity dates, verify the chain
against a configured root pool, optionally ask a CA whether the certificate is
revoked, optionally check TCG IDevID/IAK markers, and project the certificate
into an `auth.Identity` struct — an ID, a tenant, an email, a fingerprint, a
serial, and a small attribute map.

**It is not IAM.** It does not know what a user is, it does not decide what
anyone may do, and it never talks to an identity store.

| Question | Answered by | Documented in |
|---|---|---|
| "Is this X.509 certificate one of ours, and whose is it?" | `pkg/auth` | **this folder** |
| "Who is this principal, what roles do they hold, may they do X?" | go-qrdb's identity model and its single RBAC decision point, composed by go-quicbaas, re-exported here | [`docs/iam/`](../iam/) |
| "Is this bearer token valid, and does it carry the scope this call needs?" | The per-transport interceptors, against a broker-issued platform token | [`docs/daemon/api.md`](../daemon/api.md) §5 |

`docs/iam/architecture.md` states the same boundary from the other side:
*"`pkg/auth/` is **not** IAM. It is transport-level authentication — mTLS and
token validation."* This folder is the mTLS half of that sentence; the token
half lives in the transport packages and is catalogued in
[`docs/daemon/api.md`](../daemon/api.md).

**This document does not duplicate [`docs/iam/`](../iam/).** Where a question
is about identities, groups, roles, policies, applications or invitations, go
there.

## 2. The problem

A platform that provisions bare metal has principals that predate any user
account: a machine holding a TPM-issued IDevID, an installer holding an
enrollment credential, a `gatewayd` process holding a platform-issued client
certificate. Those principals authenticate with a certificate, on a transport,
before anything resembling a session exists.

Meanwhile human and service principals authenticate with factors — mTLS, FIDO2,
PIV — and receive a token. Both paths have to arrive at the same notion of "who
is this" so downstream authorization has one input.

## 3. The shape chosen

**Two layers, deliberately separate.**

1. **Certificate → `auth.Identity`** (`pkg/auth`). A pure function of a
   certificate plus a configured trust anchor. Reusable by any transport, any
   binary, with no daemon and no database.

2. **Transport → authenticated context.** Each transport owns its own
   interceptor/middleware, all of which either wrap layer 1 (mTLS) or validate a
   broker-issued platform token:

   | Transport | Mechanism | Where |
   |---|---|---|
   | gRPC (TCP) | mTLS interceptor → `auth.Authenticator` | `pkg/api/daemon/mtls_interceptor.go` |
   | gRPC (TCP) | OIDC / platform-token interceptor | `pkg/api/grpc/oidc_interceptor.go` |
   | Unix socket | `SO_PEERCRED`, kernel-verified PID/UID/GID | `pkg/api/grpc/unix_credentials.go` |
   | QUIC | `AuthMiddleware` over the frame's token field | `pkg/api/quic/auth.go` |
   | MCP | OAuth 2.1 bearer + `AuthorizationChecker` | `pkg/api/mcp/authz.go`, `oauth_metadata.go` |
   | REST | JWT middleware; `/login`, `/login/refresh`, WebAuthn | `pkg/webservice/v1/router/` |
   | Edge proxy | `pkg/proxy` auth chain, seamed to `auth.MTLSAdapter` | `pkg/proxy/authchain.go` |

3. **Session issuance is not in this repo.** `platformctl auth login` and the
   whole N-factor enrolment surface delegate to
   `go-quicbaas/sdk/go`'s `Security().Auth().Factors()` through the thin wrapper
   `sdk/go/services/auth`. The platform issues no factors and stores no
   enrolments.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Put identity extraction inside each transport's interceptor** | Five copies of "which certificate field is the tenant" is five places for them to diverge. `pkg/auth` is one small library that gRPC, the proxy, `gatewayd` and the IAM middleware all call. |
| **Make `pkg/auth` own users, roles and sessions** | go-qrdb owns the identity model and the single RBAC decision point (docs/00 L2). A second one here would drift, and the drift would only surface when two authorization decisions disagreed. The absence of a `pkg/iam` in this repository is the enforcement. |
| **A single fixed identity field (always CN)** | Certificates in this fleet are issued for different purposes: IDevIDs carry TPM serials, human certificates carry emails, service certificates carry DNS names. `MTLSConfig.IdentityField` selects; `extractFallbackIdentity` tries email → CN → subject serial → first DNS SAN when the selected field is empty. |
| **Require a CA for every `MTLSAdapter`** | `gatewayd` validates platform-issued client certificates without hosting the CA in-process; it sources roots through `pkg/trust`. `NewMTLSAdapterFromRoots` exists for exactly that. |
| **Silently skip revocation when no CA is available** | That is fail-open on the one check whose whole point is catching a stolen certificate. `NewMTLSAdapterFromRoots` rejects `WithRequireRevocation` at construction time with `ErrRevocationRequiresCA` — the failure happens at assembly, not at request time. |
| **Treat a failed IDevID check as an authentication failure** | Not every client certificate is an IDevID. `Authenticate` logs the failure at debug and continues. This is a **fail-open** decision with a real cost, called out in §6.3. Callers that need a device certificate call `auth.ValidateIDevID` / `auth.ValidateIAK` directly and act on the error. |
| **Implement the platform's own token issuer** | The platform is a broker-token **validator**, not a token authorization decision point. Tokens are minted elsewhere and enforced here by offline `scp` claim checks. |
| **Password authentication on the platform API** | Removed. Authentication is certificate-based (mTLS, IDevID), WebAuthn/FIDO2/PIV, or bearer token. |

## 4. Component boundaries

| Piece | Location | Owner |
|---|---|---|
| Certificate → `Identity` projection | `pkg/auth/mtls.go`, `interface.go` | this repo |
| X.509 / TCG validators (`ValidateCertificate`, `ValidateIDevID`, `ValidateIAK`, key-usage helpers) | `pkg/auth/validator.go` | this repo |
| Typed authentication errors | `pkg/auth/errors.go` | this repo |
| gRPC mTLS interceptors | `pkg/api/daemon/mtls_interceptor.go` | this repo |
| gRPC platform-token / OIDC interceptors | `pkg/api/grpc/oidc_interceptor.go` | this repo |
| Unix `SO_PEERCRED` credentials and interceptors | `pkg/api/grpc/unix_credentials.go` | this repo |
| QUIC auth middleware and opcode→permission map | `pkg/api/quic/auth.go` | this repo |
| MCP OAuth 2.1 metadata and tool authorization | `pkg/api/mcp/oauth_metadata.go`, `authz.go` | this repo |
| REST login / refresh / WebAuthn routers | `pkg/webservice/v1/router/authentication.go`, `webauthn.go` | this repo |
| IDevID/IAK attestation middleware | `pkg/webservice/v1/middleware/iam/attestation.go` | this repo |
| Edge-proxy auth chain | `pkg/proxy/authchain.go` | this repo — [`docs/proxy/`](../proxy/) |
| `platformctl auth` / `platformctl credential` | `pkg/cli/commands/canonical_auth.go` | this repo |
| Auth SDK wrapper | `sdk/go/services/auth` | this repo |
| **Certificate issuance and revocation state** | go-xkms `TrustedCA`, reached through `go-quicbaas/sdk/go/xkms/ca` | **not this repo** — [`docs/ca/`](../ca/) |
| **Identity model, users, groups, roles, policies, the single RBAC PDP** | go-qrdb, composed by go-quicbaas | **not this repo** — [`docs/iam/`](../iam/) |
| **N-factor enrolment and login** | go-quicbaas `Security().Auth().Factors()` (M10) over go-qrdb's User N-AuthFactor service (M14) | **not this repo** |
| **Platform token minting** | The broker | **not this repo** |
| **Invitations** | `InvitationService` — [`docs/iam/api-reference-invitations.md`](../iam/api-reference-invitations.md) | this repo, **different feature** |

The §R capability row is part of *"Re-export frontage of the composed stack (CA,
KMS, IAM, FIDO2/PIV, barrier, ceremony, LUKS, auth, data services)"*, Tier 1 —
the `auth` entry — reached through `sdk/go/services/auth`.

## 5. Data flow

### A machine authenticating with a client certificate (gRPC/TCP)

1. TLS handshake completes with `RequireAndVerifyClientCert`; Go populates
   `tls.ConnectionState.VerifiedChains`.
2. `MTLSUnaryInterceptor` skips the method if it is in `SkipMethods`;
   otherwise `authenticateFromPeer` pulls `credentials.TLSInfo` off the gRPC
   peer.
3. `extractClientCerts` prefers `VerifiedChains[0]`, falling back to
   `PeerCertificates`.
4. `auth.MTLSAdapter.Authenticate(ctx, leaf)`:
   dates → chain verify against `TrustedRoots` with `ExtKeyUsageClientAuth` →
   optional revocation check via the CA → optional IDevID check (advisory) →
   `ExtractIdentity` → `ExtractTenant` (or `DefaultTenant`).
5. The `*auth.Identity` is stored on the context under `ContextKeyIdentity`;
   handlers read it with `daemon.IdentityFromContext`.

Nothing is persisted. Nothing crosses a host boundary except the TLS handshake
itself and, when revocation checking is on, the call to the CA.

### A human authenticating and receiving a token

1. `platformctl auth login [--method mtls|fido2|piv]` resolves a go-quicbaas
   address from `PLATFORMCTL_QUICBAAS_ADDR`, else the active CLI context.
2. `sdk/go/services/auth.Client.Login` performs the factor exchange against
   go-quicbaas.
3. A session token comes back; `--save-token` writes it `0600` under
   `$HOME/.platformctl/session.token` (or `--token-path`).
4. Subsequent platform calls present it as a bearer token, validated per
   transport and enforced against the `scp` claim.

**The platform never sees the factor.** It sees the resulting token.

### A browser authenticating with WebAuthn

`/api/v1/webauthn/registration/begin` → `finish` →
`/api/v1/webauthn/login/begin` → `finish`, terminating at the REST layer, which
mints a JWT. `/api/v1/login` and `/api/v1/login/refresh` are the JWT
middleware's own endpoints.

### A local CLI over the Unix socket

No token, no certificate. `NewUnixTransportCredentials` performs `SO_PEERCRED`
during the server handshake and the kernel-verified `UnixCredentials{PID, UID,
GID}` land on the context. `RequireRoot` / `RequireUID` / `RequireGID` /
`RequireUIDOrRoot` are the assertions built on it.

## 6. Trust boundaries

1. **Trust anchor.** Everything `pkg/auth` concludes depends on
   `MTLSConfig.TrustedRoots`. `NewMTLSAdapter` fills it from
   `ca.CABundleCertPool()` when the caller supplied none — and on failure
   **logs a warning and continues with a nil pool**.
   **A nil `TrustedRoots` means `Authenticate` skips chain verification
   entirely** (`if m.config.TrustedRoots != nil { ... }`). Dates, revocation,
   IDevID and identity extraction still run; the *chain* does not. This is the
   single most important fail-open path in the package. Callers that must not
   accept an unchained certificate should construct with explicit
   `WithTrustedRoots` (or use `NewMTLSAdapterFromRoots`, which requires a
   non-nil pool and returns `ErrMissingTrustedRoots` otherwise).

2. **Revocation.** Off by default. `WithRequireRevocation(endpoint)` turns it
   on, and `NewMTLSAdapterFromRoots` refuses that combination outright
   (`ErrRevocationRequiresCA`) because revocation state lives in the CA and
   skipping the check silently would be fail-open. When it is on,
   `checkRevocation` calls `ca.Verify(cert, nil)` and maps an error containing
   the substring `"revoked"` to `ErrCertificateRevoked`. **Any other
   verification error is logged at debug and treated as not-revoked** — a
   deliberate narrowing, and a second fail-open path.

3. **IDevID/IAK checks are advisory inside `Authenticate`.** With
   `WithIDevIDValidation(true)`, a failing `ValidateIDevID` is logged at debug
   and authentication continues, on the reasoning that not every client
   certificate is a device certificate. **Attestation-gated paths must call
   `auth.ValidateIDevID` / `auth.ValidateIAK` themselves and act on the error**
   — which is exactly what `pkg/webservice/v1/middleware/iam/attestation.go` and
   `pkg/proxy/authchain.go` do.

4. **Identity extraction is not authorization.** `Identity.ID` and
   `Identity.TenantID` are whatever the certificate asserted, within the bounds
   of what the CA was willing to issue. **A CA that will issue a certificate
   with an arbitrary Organization is a CA that will issue arbitrary tenants**,
   because `TenantField` defaults to `IdentityFieldOrganization`.

5. **`DefaultTenant` weakens tenant binding.** When set, a certificate with no
   extractable tenant is assigned it instead of failing with
   `ErrTenantNotFound`. `gatewayd` sets `WithDefaultTenant("default")`. That is
   fine for a single-tenant edge and wrong for a multi-tenant one.

6. **`SkipMethods` is an authentication bypass by design.** Health and
   reflection endpoints are the intended contents. Anything else added there is
   unauthenticated.

7. **Token validation is per transport, and the scope catalogs default to
   allow.** gRPC covers 185 of 461 RPCs; MCP covers 71 of 449 tools; an entry
   absent from either catalog is permitted once the token validates
   ([`docs/daemon/api.md`](../daemon/api.md) §5). Authentication is enforced;
   *authorization* is only enforced where a catalog entry exists.

8. **QUIC `AuthMiddleware` fails closed when `requireAuth` is set and no
   validator is configured** (`StatusUnavailable`), and **fails open when
   `requireAuth` is false** — no validator means no check.
   `AuthorizationChecker.AuthorizeTool` on MCP likewise returns success when
   both `authService` and `authManager` are nil, which is the test-mode
   (`SkipIAMValidation`) and standalone path.

9. **Unix socket credentials are kernel-verified and unforgeable** — the
   strongest authentication in the platform — **and carry no tenant.** A local
   root process is authenticated as root, not as a tenant principal.

10. **Session tokens on disk.** `--save-token` writes the token to
    `$HOME/.platformctl/session.token`, mode `0600`, directory `0700`. It is a
    bearer credential in a file.

11. **PINs and certificates via environment.** `PLATFORMCTL_USER_PIN`,
    `PLATFORMCTL_CLIENT_CERT`, `PLATFORMCTL_TOKEN_PATH` are read by
    `auth login` when the corresponding flag is absent. Environment variables
    are visible to the process's children.

## 7. What this feature deliberately does not do

- **It does not store identities.** No users, no groups, no roles, no
  enrolments. [`docs/iam/`](../iam/).
- **It does not make authorization decisions.** There is exactly one RBAC
  decision point in the portfolio and it is not here.
- **It does not issue or revoke certificates.** [`docs/ca/`](../ca/).
- **It does not mint tokens.** The platform validates broker-issued tokens
  offline against the `scp` claim.
- **It does not implement WebAuthn, FIDO2 or PIV.** It consumes them through
  the stack.
- **It does not manage invitations** despite invitations being an
  authentication-adjacent flow — see
  [`docs/iam/api-reference-invitations.md`](../iam/api-reference-invitations.md).
  The legacy `docs/auth/invitation-flow.md` in this folder predates the IAM
  conversion and is superseded by it.
- **It does not enforce IDevID inside `Authenticate`.** See §6.3.
- **It has no API surface of its own.** `pkg/auth` is a library; there is no
  `AuthService` on any transport. [api.md](api.md).

## 8. Corrections against the code

Recorded per `conventions/feature-docs.md` §7 — the code wins.

| Stale statement | Where | Reality (2026-08-18) |
|---|---|---|
| *"designed to work with the go-trusted-ca `CertificateAuthority` interface"* | `pkg/auth/doc.go` | `NewMTLSAdapter` takes `quicbaasca.CACertificateAuthority` from `go-quicbaas/sdk/go/xkms/ca`. `go-trusted-ca` was decommissioned; its CA rolled into go-xkms. |
| *"IAM Module (`pkg/iam/`)"* with a tenant manager, identity store, WebAuthn and an ABAC engine | legacy `docs/auth/README.md` diagram (and `docs/iam/architecture.md`, which already flags it) | **There is no `pkg/iam` in this repository.** Those components live in go-qrdb / go-quicbaas. |
| *"QuicBaaS IAM — ABAC for all permission decisions"* as this repo's design | legacy `docs/auth/README.md` | Correct as a *statement about the stack*; it is not a description of `pkg/auth`, which makes no permission decisions. |
| Port table (`8443/9443`, `10443`, `11443`, `8000`) presented as configuration | legacy `docs/auth/README.md` | Those are defaults in deployment examples, not constants in `pkg/auth`. Ports are configured per deployment; do not treat the table as normative. |

## 9. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/iam/`](../iam/) — identity, RBAC, policies, invitations (**the other half of this story**)
- [`docs/daemon/api.md`](../daemon/api.md) — transports and the authorization catalogs
- [`docs/ca/`](../ca/) — certificate issuance and revocation
- [`docs/proxy/`](../proxy/) — the edge auth chain
- [`docs/attestation/`](../attestation/) — what IDevID/IAK evidence is used for

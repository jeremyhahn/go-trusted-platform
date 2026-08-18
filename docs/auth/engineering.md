# Platform Authentication — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Package layout

`pkg/auth/` — five non-test files. There is nothing else in the package.

| File | Holds |
|---|---|
| `doc.go` | Package documentation (partly stale — [architecture.md](architecture.md) §8) |
| `interface.go` | `IdentityField`, `Identity`, `Authenticator`, `MTLSConfig`, `MTLSOption`, the seven options, `DefaultMTLSConfig` |
| `mtls.go` | `MTLSAdapter` and its two constructors |
| `validator.go` | Free-function X.509 and TCG validators |
| `errors.go` | Sixteen typed errors |

Everything else described in this folder lives outside `pkg/auth` and is
inventoried in [architecture.md](architecture.md) §4.

## 2. Exported surface — `pkg/auth`

### Identity fields

```go
type IdentityField int

const (
    IdentityFieldEmail IdentityField = iota  // "email"
    IdentityFieldCN                          // "cn"
    IdentityFieldSerialNumber                // "serial_number"
    IdentityFieldSubjectDN                   // "subject_dn"
    IdentityFieldOrganization                // "organization"
)

func (f IdentityField) String() string // unlisted values render as "unknown"
```

`extractFromField` maps them to, respectively: first email SAN,
`Subject.CommonName`, `Subject.SerialNumber`, `Subject.String()`, first
`Subject.Organization`.

### Identity

```go
type Identity struct {
    ID              string
    TenantID        string
    UserID          string  // empty until IAM resolution; pkg/auth never sets it
    Email           string
    Name            string  // Subject.CommonName
    CertFingerprint string  // lowercase hex SHA-256 of cert.Raw
    CertExpiry      time.Time
    IssuedAt        time.Time // cert.NotBefore
    Issuer          string    // Issuer.CommonName
    SerialNumber    string    // cert.SerialNumber.Text(16)
    Attributes      map[string]string
}

func (i *Identity) IsExpired() bool
func (i *Identity) TimeUntilExpiry() time.Duration
```

`Attributes` is populated, when present, with `subject_serial`, `organization`,
`organizational_unit`, and `dns_names` (comma-joined).

**`CertFingerprint` is plain lowercase hex, not colon-separated.** An unexported
`formatFingerprint` produces the uppercase colon form and is not reachable from
outside the package.

### The interface

```go
type Authenticator interface {
    Authenticate(ctx context.Context, clientCert *x509.Certificate) (*Identity, error)
    ValidateChain(ctx context.Context, certs []*x509.Certificate) error
    ExtractIdentity(cert *x509.Certificate) (*Identity, error)
    ExtractTenant(cert *x509.Certificate) (string, error)
}
```

`*MTLSAdapter` is the only implementation in this repository.
`pkg/proxy.MTLSAuthenticator` is a narrower one-method seam over the same type
(`var _ MTLSAuthenticator = (*auth.MTLSAdapter)(nil)`).

### Configuration and options

```go
type MTLSConfig struct {
    TrustedRoots       *x509.CertPool
    RequireRevocation  bool
    RevocationEndpoint string
    IdentityField      IdentityField
    TenantField        IdentityField
    DefaultTenant      string
    ValidateIDevID     bool
    RequireClientAuth  bool
}

type MTLSOption func(*MTLSConfig)

func WithTrustedRoots(roots *x509.CertPool) MTLSOption
func WithRequireRevocation(endpoint string) MTLSOption   // sets RequireRevocation = true
func WithIdentityField(field IdentityField) MTLSOption
func WithTenantField(field IdentityField) MTLSOption
func WithDefaultTenant(tenant string) MTLSOption
func WithIDevIDValidation(enabled bool) MTLSOption
func WithRequireClientAuth(required bool) MTLSOption

func DefaultMTLSConfig() *MTLSConfig
```

`DefaultMTLSConfig` returns `IdentityField: IdentityFieldEmail`,
`TenantField: IdentityFieldOrganization`, `RequireClientAuth: true`, and zero
values for everything else — **notably `TrustedRoots: nil` and
`RequireRevocation: false`**.

`MTLSConfig.RequireClientAuth` and `MTLSConfig.RevocationEndpoint` are stored
and never read inside `pkg/auth`. `RequireClientAuth` is advisory for the caller
building its `tls.Config`; `RevocationEndpoint` is recorded but the revocation
check goes through the CA, not that URL. Verified 2026-08-18.

### The adapter

```go
type MTLSAdapter struct { /* logger, ca, config */ }

func NewMTLSAdapter(
    logger *logging.Logger,
    ca quicbaasca.CACertificateAuthority,
    opts ...MTLSOption,
) (*MTLSAdapter, error)

func NewMTLSAdapterFromRoots(
    logger *logging.Logger,
    roots *x509.CertPool,
    opts ...MTLSOption,
) (*MTLSAdapter, error)

func (m *MTLSAdapter) Authenticate(ctx context.Context, cert *x509.Certificate) (*Identity, error)
func (m *MTLSAdapter) ValidateChain(ctx context.Context, certs []*x509.Certificate) error
func (m *MTLSAdapter) ExtractIdentity(cert *x509.Certificate) (*Identity, error)
func (m *MTLSAdapter) ExtractTenant(cert *x509.Certificate) (string, error)
func (m *MTLSAdapter) Config() *MTLSConfig
func (m *MTLSAdapter) SetTrustedRoots(roots *x509.CertPool)
func (m *MTLSAdapter) String() string
```

`quicbaasca` is `github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca`.

- `NewMTLSAdapter` requires a non-nil logger (`ErrNilLogger`) **and** a non-nil
  CA (`ErrNilCA`). When no `WithTrustedRoots` was supplied it calls
  `ca.CABundleCertPool()`; **on error it logs a warning and leaves the pool
  nil** — it does not fail.
- `NewMTLSAdapterFromRoots` requires a non-nil logger and a non-nil pool
  (`ErrMissingTrustedRoots`), sets `TrustedRoots` **after** applying options
  (so `WithTrustedRoots` is overridden), leaves `ca` nil, and rejects
  `RequireRevocation` with `ErrRevocationRequiresCA`.
- `SetTrustedRoots` mutates the shared `*MTLSConfig` **without a lock**. Do not
  call it while requests are in flight.
- `Config()` returns the live pointer, not a copy. Mutating it mutates the
  adapter.

### Free-function validators (`validator.go`)

```go
func ValidateCertificate(ctx context.Context, cert *x509.Certificate, roots *x509.CertPool) error
func ValidateIDevID(ctx context.Context, cert *x509.Certificate) error
func ValidateIAK(ctx context.Context, cert *x509.Certificate) error

func HasKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool
func HasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool
func HasAnyExtKeyUsage(cert *x509.Certificate, usages ...x509.ExtKeyUsage) bool
func RequireExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) error

func IsClientAuthCertificate(cert *x509.Certificate) bool  // ClientAuth or Any
func IsServerAuthCertificate(cert *x509.Certificate) bool  // ServerAuth or Any
func IsCACertificate(cert *x509.Certificate) bool
func IsExpired(cert *x509.Certificate) bool                // nil ⇒ true
func IsNotYetValid(cert *x509.Certificate) bool            // nil ⇒ true
func ValidityRemaining(cert *x509.Certificate) time.Duration // nil ⇒ 0
```

The TCG OIDs are unexported package variables:

| Name | OID | Meaning |
|---|---|---|
| `oidTCGIDevID` | `2.23.133.5.4.2` | TPM 2.0 IDevID certificate |
| `oidTCGIAK` | `2.23.133.5.4.1` | TPM 2.0 IAK certificate |
| `oidTCGManufacturer` | `2.23.133.2.1` | TPM manufacturer |
| `oidTCGModel` | `2.23.133.2.2` | TPM model |
| `oidTCGVersion` | `2.23.133.2.3` | TPM version |

`ValidateIDevID` requires `KeyUsageDigitalSignature`, then accepts either the
IDevID OID **or**, as a fallback, any of manufacturer/model/version. `ValidateIAK`
requires `KeyUsageDigitalSignature`, then the IAK OID **or**, as a fallback,
manufacturer alone. Both fallbacks are looser than the TCG profile; a caller
needing the strict form must inspect `cert.Extensions` itself.

## 3. Invariants

1. **`Authenticate` order is fixed**: nil check → `NotBefore` → `NotAfter` →
   chain (only if `TrustedRoots != nil`) → revocation (only if
   `RequireRevocation`) → IDevID (advisory) → identity → tenant. Reordering
   changes which error a caller sees for a doubly-invalid certificate.
2. **Chain verification requires `ExtKeyUsageClientAuth`.** Both
   `validateCertificate` and `ValidateChain` set
   `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}`. A
   server-auth-only certificate fails with `ErrChainValidationFailed` even
   though its chain is sound.
3. **`ValidateChain` treats `certs[0]` as the leaf** and every later element as
   an intermediate. It does **not** check dates itself beyond
   `CurrentTime: time.Now()` inside `Verify`.
4. **`ExtractIdentity` never returns a nil identity with a nil error.** If the
   configured field is empty it falls back (email → CN → `Subject.SerialNumber`
   → first DNS SAN) and returns `ErrIdentityNotFound` when all are empty.
5. **`ExtractTenant` falls back to `Subject.Organization[0]`** regardless of
   `TenantField`, then returns `ErrTenantNotFound`.
6. **`Authenticate` sets `Identity.TenantID`; `ExtractIdentity` does not.**
   Calling `ExtractIdentity` directly yields an identity with an empty tenant.
7. **`Identity.UserID` is never populated by this package.** It exists for the
   IAM resolution step that happens elsewhere.
8. **`MTLSAdapter` is safe for concurrent reads** — `Authenticate`,
   `ValidateChain`, `ExtractIdentity`, `ExtractTenant` do not mutate. It is
   **not** safe against a concurrent `SetTrustedRoots`.
9. **The adapter performs no I/O except the optional CA call** in
   `checkRevocation`.

## 4. Error semantics

All sixteen are typed structs in `pkg/auth/errors.go` with **value receivers**;
match with `errors.As` on the value type.

| Error | Fields | Returned when |
|---|---|---|
| `ErrAuthenticationFailed` | `Reason` | Declared; not returned anywhere inside `pkg/auth` |
| `ErrCertificateInvalid` | `Reason` | `"certificate not yet valid"`; `"empty certificate chain"` |
| `ErrCertificateExpired` | — | `now.After(cert.NotAfter)` |
| `ErrCertificateRevoked` | — | CA verify error containing `"revoked"` |
| `ErrChainValidationFailed` | `Cause` (unwraps) | `cert.Verify` / `leaf.Verify` failed |
| `ErrIdentityNotFound` | — | No identity field and no fallback yielded a value |
| `ErrTenantNotFound` | — | No tenant field and no Organization |
| `ErrTPMAttestationFailed` | `Reason` | Certificate carries neither IDevID/IAK nor TPM OIDs |
| `ErrNilCertificate` | — | nil `*x509.Certificate` |
| `ErrNilLogger` | — | nil logger at construction |
| `ErrNilCA` | — | nil CA in `NewMTLSAdapter` |
| `ErrMissingTrustedRoots` | — | nil pool in `NewMTLSAdapterFromRoots` / `ValidateCertificate` |
| `ErrRevocationCheckFailed` | `Reason` | Declared; not returned anywhere inside `pkg/auth` |
| `ErrInvalidKeyUsage` | `Expected`, `Actual` | Missing `DigitalSignature` on IDevID/IAK |
| `ErrInvalidExtKeyUsage` | `Expected` | `RequireExtKeyUsage` failed |
| `ErrRevocationRequiresCA` | — | `WithRequireRevocation` on `NewMTLSAdapterFromRoots` |

**`ErrAuthenticationFailed` and `ErrRevocationCheckFailed` are declared and
unused** inside the package (grepped 2026-08-18). They are part of the exported
vocabulary for callers; do not assume `Authenticate` produces them.

### Fail-closed paths

- Nil certificate → `ErrNilCertificate`, always.
- Expired or not-yet-valid → refused before anything else.
- Chain verification failure → refused (**when a root pool is configured**).
- Revocation detected → refused.
- No extractable identity → refused.
- No extractable tenant **and** no `DefaultTenant` → refused.
- `NewMTLSAdapterFromRoots` + `WithRequireRevocation` → refused **at
  construction**, so a misconfiguration cannot degrade into an unchecked
  request path.
- gRPC mTLS interceptor: no peer, no TLS info, or no client certificates →
  `codes.Unauthenticated`.

### Fail-open paths — know these

1. **Nil `TrustedRoots` skips chain verification.** `Authenticate` guards the
   chain check with `if m.config.TrustedRoots != nil`. `NewMTLSAdapter` can
   produce exactly that state when `ca.CABundleCertPool()` fails, because it
   logs a warning and proceeds.
2. **Non-revocation CA errors are ignored.** `checkRevocation` maps only errors
   whose text contains `"revoked"`; everything else is logged at debug and the
   certificate is treated as good.
3. **`checkRevocation` returns nil immediately when `m.ca == nil`.** Reachable
   only via `NewMTLSAdapterFromRoots`, which already rejects
   `RequireRevocation` — so this is defence in depth rather than a live hole.
4. **`ValidateIDevID` failure inside `Authenticate` does not fail
   authentication.** Deliberate (not every client certificate is a device
   certificate) and consequential: enforce it yourself where it matters.
5. **`ParseStatus`-style permissiveness elsewhere in the transport layer**: an
   RPC or MCP tool absent from its scope catalog is allowed once the token
   validates ([`docs/daemon/api.md`](../daemon/api.md) §5).

## 5. Transport-layer contracts

Not `pkg/auth`, but the code that consumes it. Signatures verified 2026-08-18.

### gRPC mTLS (`pkg/api/daemon/mtls_interceptor.go`)

```go
type MTLSInterceptorConfig struct {
    Authenticator auth.Authenticator
    Logger        *logging.Logger
    SkipMethods   []string
}

func MTLSUnaryInterceptor(cfg *MTLSInterceptorConfig) grpc.UnaryServerInterceptor
func MTLSStreamInterceptor(cfg *MTLSInterceptorConfig) grpc.StreamServerInterceptor
func IdentityFromContext(ctx context.Context) *auth.Identity

const ContextKeyIdentity contextKey = "mtls-identity"

type ErrMTLSNoPeerInfo struct{}
type ErrMTLSNoTLSInfo struct{}
type ErrMTLSNoCertificates struct{}
```

Wired in `pkg/api/daemon/daemon.go` when `config.EnableMTLS && config.CAService
!= nil`, with `WithTrustedRoots(config.MTLSClientCAPool)` when that pool is set.

### gRPC platform token (`pkg/api/grpc/oidc_interceptor.go`)

```go
type TokenValidator interface { /* ValidateToken */ }
type AuthorizationChecker interface { /* CheckPermission */ }

func OIDCUnaryInterceptor(opts ...OIDCInterceptorOption) grpc.UnaryServerInterceptor
func OIDCStreamInterceptor(opts ...OIDCInterceptorOption) grpc.StreamServerInterceptor

func WithTokenValidator(v TokenValidator) OIDCInterceptorOption
func WithSkipMethods(methods ...string) OIDCInterceptorOption
func WithRequireAuth(require bool) OIDCInterceptorOption

func ContextWithToken(ctx context.Context, token string) context.Context
func TokenFromContext(ctx context.Context) (string, bool)
func AddBearerToken(ctx context.Context, token string) context.Context
```

Errors: `ErrTokenValidatorNotConfigured`, `ErrMissingAuthorizationHeader`,
`ErrInvalidAuthorizationHeader`, `ErrTokenValidationFailed`, `ErrScopeDenied`.

### Unix `SO_PEERCRED` (`pkg/api/grpc/unix_credentials.go`)

```go
type UnixCredentials struct { /* PID, UID, GID */ }
func (c UnixCredentials) IsRoot() bool

func NewUnixTransportCredentials(opts ...UnixTransportOption) credentials.TransportCredentials
func WithRequireCredentials(require bool) UnixTransportOption

func UnixCredentialsUnaryInterceptor() grpc.UnaryServerInterceptor
func UnixCredentialsUnaryInterceptorRequired() grpc.UnaryServerInterceptor
func UnixCredentialsStreamInterceptor() grpc.StreamServerInterceptor
func UnixCredentialsStreamInterceptorRequired() grpc.StreamServerInterceptor

func ExtractUnixCredentials(conn net.Conn) (UnixCredentials, error)
func ContextWithUnixCredentials(ctx context.Context, creds UnixCredentials) context.Context
func UnixCredentialsFromContext(ctx context.Context) (UnixCredentials, bool)
func MustUnixCredentialsFromContext(ctx context.Context) UnixCredentials

func RequireRoot(ctx context.Context) error
func RequireUID(ctx context.Context, uid uint32) error
func RequireGID(ctx context.Context, gid uint32) error
func RequireUIDOrRoot(ctx context.Context, uid uint32) error
```

Errors: `ErrUnixCredentialsUnavailable`, `ErrNilConnection`,
`ErrNotUnixConnection`, `ErrPeerNotAvailable`, `ErrCredentialsNotInContext`,
`ErrSyscallFailed`.

### QUIC (`pkg/api/quic/auth.go`)

```go
type AuthMiddleware struct { /* ... */ }
func NewAuthMiddleware(opts ...AuthMiddlewareOption) *AuthMiddleware

func WithQUICTokenValidator(v TokenValidator) AuthMiddlewareOption
func WithQUICAuthorizationChecker(c AuthorizationChecker) AuthMiddlewareOption
func WithQUICSkipOpcodes(opcodes ...byte) AuthMiddlewareOption
func WithQUICRequireAuth(require bool) AuthMiddlewareOption

func (m *AuthMiddleware) AuthenticateRequest(ctx context.Context, req *Request) (context.Context, *Response)
func (m *AuthMiddleware) AuthorizeRequest(ctx context.Context, req *Request, resource, action string) *Response

type OpcodePermission struct { Resource, Action string }
func DefaultOpcodePermissions() map[byte]*OpcodePermission
```

`AuthenticateRequest` prefers the claims path when the validator implements
`ClaimsTokenValidator` — `AuthorizeToken(ctx, token, "", "", "", "")` — and
stashes the resulting `AuthorizedContext`. `AuthorizeRequest` then enforces
`authCtx.RequireScope(scopeForOperation(resource, action))`. **QUIC carries no
DPoP frame**, so proof / htm / htu are always empty: every QUIC token is a
bearer token.

`DefaultOpcodePermissions` maps `OpHealth`, `OpLiveness` and `OpReadiness` to
`nil` (no permission).

### MCP (`pkg/api/mcp/`)

```go
type AuthorizationChecker struct { /* authService, authManager, toolPermissions */ }
func NewAuthorizationChecker(authService AuthorizationService, authManager AuthManager) *AuthorizationChecker
func (c *AuthorizationChecker) AuthorizeTool(ctx context.Context, toolName, token string) (context.Context, *AuthorizationError)
func (c *AuthorizationChecker) CheckToolAuthorization(ctx context.Context, toolName, token string) *AuthorizationError

type OAuthProtectedResourceMetadata struct { /* RFC 9728 */ }
type OAuthMetadataConfig struct { ResourceURL string; AuthorizationServerURLs []string; DocumentationURL string }
func NewOAuthMetadataHandler(config *OAuthMetadataConfig) *OAuthMetadataHandler
func (h *OAuthMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)
func (h *OAuthMetadataHandler) Validate() error

const WWWAuthenticateHeader = "WWW-Authenticate"
const BearerRealm = "Trusted Platform MCP"
func WWWAuthenticateChallenge(realm, scope, errorCode, errorDescription string) string
func SetWWWAuthenticateHeader(w http.ResponseWriter, scope, errorCode, errorDescription string)
```

`AuthorizeTool` short-circuits with success when **both** `authService` and
`authManager` are nil (test mode / standalone), when the tool is absent from
`toolPermissions`, and when its mapped permission is the empty string
(`platform_health`, `platform_liveness`, `platform_readiness`).

## 6. Configuration

`pkg/auth` reads **no** configuration file and **no** environment variable. Its
entire configuration is the `MTLSOption` set passed at construction.

The CLI's auth surface reads:

| Variable | Read by | Effect |
|---|---|---|
| `PLATFORMCTL_QUICBAAS_ADDR` | `resolveQuicBaaSAddress` | Overrides the go-quicbaas address; highest precedence |
| `PLATFORMCTL_USER_PIN` | `resolveAuthLoginEnv` | Fills `--pin` when the flag is absent |
| `PLATFORMCTL_CLIENT_CERT` | `resolveAuthLoginEnv` | Fills `--client-cert` when the flag is absent |
| `PLATFORMCTL_TOKEN_PATH` | `resolveAuthLoginEnv` | Fills `--token-path` when the flag is absent |

Address precedence when no env var is set: local context →
`/run/quicbaas.sock` (Unix); remote context → the context's configured server
(REST for `http(s)://`, gRPC otherwise); **embedded context is an error** —
`"auth: embedded context cannot dial quicbaas (set PLATFORMCTL_QUICBAAS_ADDR)"`.

## 7. Persistence

`pkg/auth` persists nothing.

The only thing this feature writes to disk is the session token from
`platformctl auth login --save-token`: `$HOME/.platformctl/session.token` by
default, file mode `0600`, directory mode `0700`, contents `<token>\n`.
`ErrTokenWrite` (from `sdk/go/services/auth`) wraps failures.

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/auth/{interface,errors,mtls,validator}_test.go` | Field extraction and fallbacks, chain verification, revocation mapping, IDevID/IAK OID handling, every error's message, both constructors |
| Interceptor | `pkg/api/daemon/mtls_interceptor_test.go` | Peer extraction, skip methods, context propagation, stream wrapping |
| Proxy chain | `pkg/proxy/authchain_test.go` | The `MTLSAuthenticator` seam and IDevID enforcement at the edge |
| CLI | `pkg/cli/commands/canonical_auth_login_test.go`, `canonical_surface_test.go` | Flag binding, env resolution, factory substitution via `SetAuthClientFactory` |

Fault-injection seams:
- `auth.Authenticator` — substitute a failing authenticator in any interceptor.
- `pkg/proxy.MTLSAuthenticator` — one method, trivial to fake.
- `commands.SetAuthClientFactory(f)` returns a restorer; use it with `defer` to
  swap in an in-process auth service.
- `TokenValidator` / `AuthorizationChecker` on gRPC and QUIC.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, including for the `auth`
and `credential` verbs in [cli.md](cli.md).

## 9. Observability

`pkg/auth` logs at **debug only**, through `*logging.Logger`:

| Event | Level | Message shape |
|---|---|---|
| CA bundle pool fetch failed at construction | warn | `auth: failed to get CA bundle cert pool: %v` |
| IDevID validation failed (non-fatal) | debug | `auth: IDevID validation failed: %v` |
| Certificate verification during revocation check | debug | `auth: certificate verification during revocation check: %v` |
| Successful authentication | debug | `auth: authenticated %s for tenant %s` |

The mTLS interceptor logs the same class of events at debug when a logger is
configured (`mtls: no peer info in context`, `mtls: peer auth info is not TLS`,
`mtls: no client certificates in TLS state`, `mtls: authentication failed`,
`mtls: authenticated %s (tenant: %s)`).

**There are no metrics and no audit records for authentication outcomes** in
`pkg/auth` or the mTLS interceptor. Repeated failed client-certificate
authentication is visible only at debug log level. That is a gap worth knowing
about before an incident, not after.

**Never log**: a bearer token, a session token, a PIN, or a private key. The
certificate fingerprint (`Identity.CertFingerprint`) is the correct thing to log
to identify a client.

## 10. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/iam/engineering.md`](../iam/engineering.md) — the identity/RBAC half
- [`docs/daemon/api.md`](../daemon/api.md) — transports and authorization catalogs
- [`docs/proxy/`](../proxy/) — the edge auth chain

# Trusted Reverse Proxy — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/proxy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> This is the file an implementing agent works from. Every identifier below was
> grepped in this repository on 2026-08-18.

---

## 1. Package layout

`pkg/proxy/` — the engine and its seams:

| File | Holds |
|---|---|
| `proxy.go` | `Engine`, `New`, `Reload`, `Status`, `compile`, `mergeAuthDefaults` |
| `config.go` | `Config`, `ListenerConfig`, `RouteConfig`, `AuthRequirements`, `AuthDefaults`, `BackendPoolConfig`, `BackendConfig`, `BackendTLSConfig`, `Validate` |
| `deps.go` | `Deps`, `AuthChain`, `AuthDecision`, `ClientIdentity`, `ChainCapabilities`, `CapabilityReporter`, `TrustResolver`, `AuditSink`, `checkFailClosed`, `checkRouteCapabilities` |
| `authchain.go` | `Chain`, `NewAuthChain`, `AuthChainConfig`, `MTLSAuthenticator`, `ZoneExtractor`, `MatrixProvider`, `PolicyZoneExtractor`, the `Reason*` constants |
| `tokenauth.go` | `TokenAuthenticator`, `TokenAuthRequest`, `TokenPrincipal`, `bearerToken`, `requestHTU` |
| `attestation.go` | `AttestationGate`, `DefaultAttestationMaxAge`, `checkAttestation` |
| `policy.go` | `PolicyEvaluator`, `checkPolicy`, `policyInput` |
| `router.go` | `CompiledRoute`, `routeTable`, `buildRouteTable`, `matchPrefix`, `normalizeHost` |
| `transport.go` | `compiledPool`, `compilePools`, `buildTransport`, `poolConfigHash` |
| `balancer.go` | `Balancer`, `BalancerRoundRobin`, `balancerRegistry`, `newBalancer` |
| `handler.go` | `Engine.ServeHTTP`, `newReverseProxy`, `stripIdentityHeaders`, `stripRequestPrefix`, `writeJSONError` |
| `identity.go` | `injectIdentity`, `buildXFCC`, the `X-TP-*` header constants |
| `listener.go` | `Engine.Start`, `Engine.Stop`, `ListenerStatus`, `serverProtocols` |
| `audit.go` | `AuditEvent`, `AuditSink`, `Decision*` constants, `noopSink` |
| `metrics.go` | `Engine.Metrics`, `MetricsSnapshot`, `RouteMetrics` |
| `errors.go` | every sentinel and typed error in §5 |

`pkg/sdn/gateway/proxysvc/` — the gatewayd assembly (see §8):
`config.go`, `service.go`, `controlplane.go`, `attestation.go`, `tokenauth.go`,
`opa.go`, `audit.go`, `errors.go`.

`pkg/api/daemon/proxy_store.go`, `pkg/api/grpc/proxy_service.go` and the four
transport adapters — the platformd side ([api.md](api.md)).

## 2. Exported surface

### 2.1 Engine

```go
func New(cfg Config, deps Deps) (*Engine, error)

func (e *Engine) Reload(cfg Config) error
func (e *Engine) Start() error
func (e *Engine) Stop(ctx context.Context) error
func (e *Engine) Status() *Status
func (e *Engine) Metrics() MetricsSnapshot
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

`Engine` implements `http.Handler` — it is the single shared handler across
every listener. There are no functional options; construction is
`New(cfg, deps)`.

### 2.2 Injected collaborators

```go
type Deps struct {
    Auth      AuthChain
    Trust     TrustResolver
    Audit     AuditSink
    ServerTLS *tls.Config
    Logger    *slog.Logger
}

type AuthChain interface {
    Authenticate(ctx context.Context, r *http.Request, route *CompiledRoute) (*AuthDecision, error)
}
type CapabilityReporter interface{ Capabilities() ChainCapabilities }
type TrustResolver interface {
    ClientTLSConfig(ctx context.Context, trustClass, endpoint string) (*tls.Config, error)
}
type AuditSink interface{ Record(ctx context.Context, ev AuditEvent) }
```

`Deps.withDefaults` replaces a nil `Audit` with `noopSink{}` and a nil `Logger`
with `slog.Default()`. Nothing else is defaulted.

**A chain that does not implement `CapabilityReporter` is assumed fully
capable** (`chainCapabilities` returns all-true) — the injector vouches for it.
`*Chain` does implement it.

### 2.3 The auth chain

```go
func NewAuthChain(cfg AuthChainConfig) (*Chain, error)

type AuthChainConfig struct {
    MTLS          MTLSAuthenticator   // required
    ZoneExtractor ZoneExtractor       // with Matrix, or neither
    Matrix        MatrixProvider      // func() zone.Matrix
    Logger        *slog.Logger
    Token         TokenAuthenticator  // optional -> Token capability
    Attestation   AttestationGate     // optional -> Attestation capability
    Policy        PolicyEvaluator     // optional -> OPA capability
}
```

Four seams, each one method:

```go
type MTLSAuthenticator interface {
    Authenticate(ctx context.Context, clientCert *x509.Certificate) (*auth.Identity, error)
}
type TokenAuthenticator interface {
    Authorize(ctx context.Context, req *TokenAuthRequest) (*TokenPrincipal, error)
}
type AttestationGate interface {
    Fresh(ctx context.Context, deviceID string, maxAge time.Duration) error
}
type PolicyEvaluator interface {
    Evaluate(ctx context.Context, policy string, input map[string]any) (allowed bool, violations []string, err error)
}
type ZoneExtractor interface{ ExtractZone(cert *x509.Certificate) (string, error) }
type MatrixProvider func() zone.Matrix
```

`NewPolicyZoneExtractor() *PolicyZoneExtractor` is the production
`ZoneExtractor`. It reads the canonical `OIDTPNetworkZone` extension
(`1.3.6.1.4.1.29377.101.21`) with the quicbaas SDK parser
(`quicbaasca.ParseNetworkZoneExtension`) rather than adapting
`pkg/sdn/policy.X509PolicyExtractor` — importing `pkg/sdn/policy` would drag
the SDN runtime (OVS, device DAO, datastore) into the proxy.

### 2.4 Identity and decisions

```go
type AuthDecision struct{ Allowed bool; Reason string; Identity *ClientIdentity }

type ClientIdentity struct {
    ID, DeviceID, Zone, AuthMethod, CertFingerprint string
    Attested bool
    Roles    []string
    // subjectDN, uriSAN — unexported
}
```

`subjectDN` and `uriSAN` are **deliberately unexported**: only the in-package
chain, which validated the certificate, can set them. An external `AuthChain`
implementation therefore produces an `X-Forwarded-Client-Cert` with a `Hash=`
element and no `Subject=` / `URI=` elements.

### 2.5 Constants worth naming

| Constant | Value |
|---|---|
| `AuthModePublic`, `AuthModeMTLS`, `AuthModeToken`, `AuthModeMTLSOrToken` | `public`, `mtls`, `token`, `mtls-or-token` |
| `ProtocolH1`, `ProtocolH2` | `h1`, `h2` |
| `WildcardHost` | `*` |
| `BalancerRoundRobin` | `round-robin` |
| `DefaultAttestationMaxAge` | 24h — matches the platform verifier's manifest freshness policy |
| `defaultReadHeaderTimeout` | 30s (unexported) |
| `defaultMaxIdleConnsPerHost` / `defaultIdleConnTimeout` | 128 / 90s (unexported) |
| `defaultDialTimeout` / `defaultKeepAlive` / `defaultTLSHandshakeTimeout` / `defaultExpectContinue` | 30s / 30s / 10s / 1s (unexported) |
| `DecisionAllow`, `DecisionDeny`, `DecisionError`, `DecisionNoRoute` | `allow`, `deny`, `error`, `no-route` |

## 3. Invariants

1. **The request hot path takes no lock.** Compiled state lives behind
   `atomic.Pointer[compiledState]`; `Engine.mu` guards only control-plane
   operations (`Start` / `Stop` / `Reload` / listener bookkeeping).
2. **Compiled state is immutable.** `CompiledRoute` instances are shared across
   requests and never mutated after `compile`.
3. **Reload is atomic and all-or-nothing.** Validation and compilation happen
   before the swap; on any error the running state is untouched.
4. **Pool transports carry over across a reload** when a pool's ID *and*
   configuration hash (`poolConfigHash`, xxhash over `%#v`) are unchanged —
   warm connections survive. Transports of changed or removed pools have
   `CloseIdleConnections()` called **after** the swap.
5. **Route counters survive a reload** for route IDs present in both states
   (`prevMetrics[rc.ID]`).
6. **Listener changes take effect on the next `Start`.** `Reload` does not
   rebind; running listeners are not restarted.
7. **`Start` is once.** `started.CompareAndSwap(false, true)`; a second call
   returns `ErrEngineStarted`. Listeners bind **synchronously**, so
   `Status().Listeners[i].BoundAddress` is valid as soon as `Start` returns
   (this is how `:0` ports are resolved).
8. **`Stop` is idempotent and never leaks a server.** It is a no-op when not
   started; if graceful `Shutdown` fails (context expired) it force-`Close`s and
   joins both errors.
9. **Route matching is deterministic.** Exact host before wildcard; within a
   host, descending path-prefix length with a **stable** sort;
   segment-boundary prefix match. Hosts are lowercased at validation *and* at
   table build; the request Host has its port stripped.
10. **`Hosts: nil` means wildcard.** An empty list compiles into the wildcard
    bucket, identical to `["*"]`.
11. **Inbound identity headers are stripped before routing**, unconditionally —
    not after a deny, not only on authenticated routes.
12. **`X-TP-Attested` is always set on an allow**, `"true"` or `"false"`, so a
    backend never has to distinguish absent from false. Every other `X-TP-*`
    header is omitted when its field is empty.
13. **The engine never calls the chain for a public route.** `Chain.Authenticate`
    still allows `AuthModePublic` defensively.
14. **Auth is per request.** No session, no affinity — see
    [architecture.md](architecture.md) §6.3.

## 4. Fail-closed paths

**Composition time** (`New` / `Reload`, via `checkFailClosed` →
`checkRouteCapabilities`). Any non-public route requires `Deps.Auth` and
`Deps.ServerTLS`; any pool with a trust class requires `Deps.Trust`; and each
route's **defaults-merged** requirements must be within the chain's reported
capabilities:

| Route asks for | Missing capability | Error |
|---|---|---|
| any non-public mode | `Deps.Auth == nil` | `ErrAuthChainRequired` |
| any non-public mode | `Deps.ServerTLS == nil` | `ErrTLSRequiredForAuth` |
| `mtls` / `mtls-or-token` | `caps.MTLS` | `ErrMTLSAuthNotConfigured` |
| `token` / `mtls-or-token` | `caps.Token` | `ErrTokenAuthNotConfigured` |
| `require-attestation` | `caps.Attestation` | `ErrAttestationGateNotConfigured` |
| `opa-policy` | `caps.OPA` | `ErrOPANotConfigured` |
| `allowed-zones` or `backend-zone` | `caps.Zones` | `ErrZoneEnforcementNotConfigured` |
| pool `tls.trust-class` | `Deps.Trust == nil` | `ErrTrustResolverRequired` |

All but the first three are wrapped in a `*ConfigError{Kind: "route", ID: …}`.

**Request time.** Every check denies rather than skipping. Notably:

- A chain error (not a deny) is a **500** with an `error` audit event — reserved
  for nil request / nil route, i.e. programming mistakes.
- `decision == nil` is treated as a deny with reason `"denied"`.
- Defensive denies exist even where composition already rejected the shape:
  `c.policy == nil` on an OPA route → `opa_error`; `c.attestation == nil` →
  `attestation_unavailable`; `c.zones == nil` with zone requirements →
  `zone_missing`; `c.matrix == nil` on the token path → `zone_matrix_denied`;
  `c.token == nil` on the token path → `token_auth_not_configured`.
- **`ErrTCPPassthroughUnsupported`** — a passthrough route is rejected, never
  silently forwarded around the chain.

**The one deliberate fail-open** is the audit sink: `proxysvc.SDKAuditSink`
logs and drops on a dial failure, and a construction error in
`buildAuditSink` leaves `Deps.Audit` nil, which `New` replaces with the no-op
sink. The proxy always serves regardless of the audit plane's health.

## 5. Error semantics

### 5.1 Configuration sentinels (`Validate`, wrapped in `*ConfigError`)

| Error | Raised when |
|---|---|
| `ErrNoListeners` | zero listeners — returned bare, not wrapped |
| `ErrListenerIDRequired` / `ErrListenerAddressRequired` / `ErrDuplicateListenerID` | listener shape |
| `ErrUnknownProtocol` | protocol other than `h1` / `h2` |
| `ErrRouteIDRequired` / `ErrDuplicateRouteID` | route shape |
| `ErrInvalidPathPrefix` | prefix does not start with `/` |
| `ErrTCPPassthroughUnsupported` | `PassthroughTCP` set |
| `ErrRouteAuthModeRequired` | `Auth.Mode` empty — **there is no default mode** |
| `ErrInvalidAuthMode` | mode outside the four |
| `ErrRoutePoolRequired` / `ErrUnknownPoolID` | pool reference |
| `ErrTokenModeRequired` | `token-zone` or `required-scopes` on a route with no token path |
| `ErrIDevIDRequiresMTLS` | `require-idevid` on a pure `token` route |
| `ErrPoolIDRequired` / `ErrDuplicatePoolID` / `ErrNoBackends` | pool shape |
| `ErrInvalidBackendURL` / `ErrInvalidBackendScheme` / `ErrInvalidBackendWeight` | backend shape; scheme must be `http` or `https`, weight non-negative |
| `ErrUnknownBalancer` | balancer name not in `balancerRegistry` |

`ErrTokenModeRequired` and `ErrIDevIDRequiresMTLS` exist because both
misconfigurations are silent otherwise: scopes that are never enforced, and a
route that could never admit anyone.

### 5.2 Chain-construction and runtime sentinels

`ErrMTLSAuthenticatorRequired`, `ErrZoneConfigIncomplete` (exactly one of
extractor/matrix set), `ErrNilRequest`, `ErrNilRoute`, `ErrNilLeafCertificate`,
`ErrZoneExtensionMissing`, `ErrEngineStarted`.

### 5.3 Classification sentinels — the two that adapters must wrap

| Sentinel | Wrapped by | Chain maps it to |
|---|---|---|
| `ErrAttestationStale` | `proxysvc.ErrDeviceNotAttested` (via `Unwrap`) | `attestation_stale` |
| `ErrTokenScopeDenied` | `proxysvc.ErrScopeDenied` (via `Unwrap`) | `token_scope_denied` |

**Any other error from a gate or authenticator is the indeterminate case** —
`attestation_unavailable` and `token_invalid` respectively. Both deny. An
adapter that forgets to wrap turns a definitive verdict into an indeterminate
one; it still denies, but the operator sees the wrong reason.

### 5.4 Typed error structs

`*ConfigError{Kind, ID, Err}` (kinds: `listener`, `route`, `pool`),
`*ListenerError{ID, Err}`, `*TrustResolveError{PoolID, TrustClass, Err}`. All
implement `Unwrap`.

### 5.5 Deny reasons — the stable client-facing vocabulary

Every deny is **403** with body `{"error":"forbidden","reason":"<reason>"}` and
one audit event. Audit consumers and tests match these strings exactly:

| Reason | Meaning |
|---|---|
| `client_cert_required` | mTLS route, no peer certificate |
| `mtls_authentication_failed` | adapter rejected the certificate (chain, validity) |
| `idevid_required` | `require-idevid` and `auth.ValidateIDevID` failed — or an `mtls-or-token` route reached over the token path |
| `zone_missing` | zone-scoped route, certificate carries no readable zone |
| `zone_not_allowed` | client zone not in `allowed-zones` |
| `zone_matrix_denied` | no allowed path from client zone to `backend-zone` |
| `role_required` | identity lacks a `required-roles` entry |
| `token_auth_not_configured` | token path on a chain with no `TokenAuthenticator` |
| `token_missing` | token path, no `Authorization: Bearer` |
| `token_invalid` | signature / `iss` / `aud` / `exp` / DPoP / liveness failure |
| `token_scope_denied` | token valid, a `required-scopes` entry not granted |
| `zone_requires_mtls` | token principal on a zone-enforcing route with no `auth.token-zone` |
| `attestation_stale` | no manifest, manifest older than the accepted age, or platformd rejected verification |
| `attestation_unavailable` | attestation state could not be established — no device identity, or platformd unreachable |
| `opa_denied` | policy returned not-allowed |
| `opa_error` | policy evaluation failed |

Non-deny outcomes: **404** `{"error":"no route"}` with a `no-route` audit
event; **500** `{"error":"authentication error"}` on a chain error; **502**
`{"error":"bad gateway"}` from the reverse-proxy `ErrorHandler`.

**OPA violation messages never reach the client.** They are logged and audited
server-side; the client sees the bare `opa_denied`.

## 6. The OPA input document

`policyInput` (`policy.go`) builds exactly this, and it is part of the proxy's
policy contract:

```json
{
  "client":  {"id", "zone", "device_id", "attested", "auth_method", "roles"},
  "route":   {"id", "hosts", "path_prefix", "backend_zone"},
  "request": {"method", "path", "host"}
}
```

`client.attested` reflects the attestation gate's outcome, which is why the
gate runs before the policy.

**Known mismatch with the embedded policy.** `pkg/policy/opa/policies/proxy_authz.rego`
documents its input as `route: {id, allowed_methods}` and contains a rule
keyed on `input.route.allowed_methods`. **`policyInput` never emits
`allowed_methods`**, so in Rego that rule body is undefined and the
method-allowlist violation can never fire. What `proxy_authz` actually enforces
today is: default deny, deny when `client.zone == "quarantine"`, and require a
non-empty `client.zone` and a non-empty `route.id` to allow. Recorded here, not
resolved — closing it means either extending the input document or removing the
dead rule, and that is a behavior change.

Note the consequence: because `proxy_authz` requires a non-empty
`client.zone`, a token principal on a route with no `auth.token-zone` cannot
pass it even on a route that does not otherwise enforce zones.

## 7. Header contract

Stripped from every inbound request, case-insensitively, before routing:
`X-Forwarded-Client-Cert` and every header beginning `X-TP-`.

Deleted before forwarding on an **authenticated** route: `Authorization`.

Set toward the backend after an allow:

| Header | Source |
|---|---|
| `X-TP-Client-ID` | `ClientIdentity.ID` — mTLS adapter identity, or the token `sub` |
| `X-TP-Device-ID` | `auth.Identity.SerialNumber`; empty for token principals |
| `X-TP-Client-Zone` | certificate zone, or the operator-assigned `token-zone` |
| `X-TP-Auth-Method` | `mtls` or `token` |
| `X-TP-Attested` | `"true"` / `"false"` — always present |
| `X-TP-Cert-Fingerprint` | lowercase SHA-256 hex of the raw leaf |
| `X-Forwarded-Client-Cert` | Envoy-compatible `Hash=…;Subject="…";URI=…`, present elements only |

`X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host` are set by
`ProxyRequest.SetXForwarded()` from the connection, not copied from the client.

## 8. Configuration

The engine's `proxy.Config` is built in Go. The **file** schema is
`proxysvc.Config` — the `proxy:` section of the gatewayd configuration
(`<install-dir>/config.yaml` or the path given to `gatewayd serve`), kebab-case
keys, parsed by viper (`LoadServeConfig`).

| Key | Type | Default | Notes |
|---|---|---|---|
| `proxy.enabled` | bool | `false` | Disabled sections are not validated |
| `proxy.tls.cert-file` / `key-file` | path | — | Must be set together (`ErrConfigInvalid`); required when any route is non-public (`ErrServerTLSRequired`) |
| `proxy.tls.client-ca-file` | path | — | Wins over the trust resolver; absent, the `internal`-class CA pool is used. Neither available with authenticated routes → `ErrClientCARequired` |
| `proxy.listeners[].id` / `.address` / `.protocols` | string / string / list | protocols empty ⇒ h1+h2 | **Never synced from platformd** |
| `proxy.routes[]` | list | — | Static base layer; see the route keys below |
| `proxy.pools[]` | list | — | Static base layer |
| `proxy.defaults.attestation-max-age` | duration | — | Applied when a route sets `require-attestation` with no max age |
| `proxy.defaults.backend-zone` | string | — | Applied when a route leaves `backend-zone` empty |
| `proxy.sync.enabled` | bool | `false` | Off ⇒ static configuration only |
| `proxy.sync.interval` | duration | `15s` (`DefaultSyncInterval`) | Zero normalises to the default |
| `proxy.platformd.protocol` | `unix` \| `grpc` | `unix` | Anything else → `ErrConfigInvalid` |
| `proxy.platformd.socket` | path | `/run/platformd.sock` (`DefaultPlatformdSocket`) | `unix` protocol |
| `proxy.platformd.grpc-addr` | host:port | — | **Required** for `grpc`; also requires a `trust:` section (`ErrTrustRequiredForGRPC`) |
| `proxy.attestation.enabled` | bool | `false` | Enables the gate |
| `proxy.attestation.cache-ttl` | duration | `60s` | Per-device verdict reuse |
| `proxy.attestation.negative-cache-ttl` | duration | `5s` | Failed-query reuse — the deny window |
| `proxy.token-auth.enabled` | bool | `false` | Enables the token path |
| `proxy.token-auth.issuer` | URL | — | **Required** when enabled |
| `proxy.token-auth.jwks-url` | URL | — | **Required** when enabled |
| `proxy.token-auth.audience` | string | `DefaultTokenAudience` | Token `aud` must contain it |
| `proxy.token-auth.cache-ttl` | duration | 1h | JWKS key cache |
| `proxy.token-auth.authz-mode` | `offline` \| `online` \| `hybrid` | `hybrid` | Anything else → `ErrTokenAuthConfig` |
| `proxy.token-auth.introspection-url` | URL | — | **Required** for `online` and `hybrid`; a liveness-requiring mode without it is a startup error, never a downgrade |
| `proxy.token-auth.introspection-client-id` / `-client-secret` | string | — | RFC 7662 HTTP Basic |
| `proxy.token-auth.introspection-bearer-token` | string | — | Bearer instead of Basic |
| `proxy.token-auth.allow-bearer` | bool | `false` | `false` ⇒ a DPoP proof on every token request (`ErrBearerNotAllowed`) |
| `proxy.token-auth.liveness-cache-ttl` | duration | `DefaultTokenLivenessCacheTTL` | Positive hybrid liveness cache |
| `proxy.opa.enabled` | bool | `false` | Enables `opa-policy` routes |
| `proxy.opa.policy-dir` | path | — | Overlays the embedded policies; same-name wins. Loaded once at startup |
| `proxy.audit.enabled` | bool | `false` | Emits onto the quicbaasd audit chain |
| `proxy.audit.quicbaas-addr` | address | — | **Required** when audit is enabled (`ErrAuditConfig`) |
| `proxy.audit.quicbaas-transport` | `unix`\|`rest`\|`quic`\|`mcp` | auto-detect | Empty (or grpc) lets the SDK detect from the address |
| `proxy.audit.service` | string | `gatewayd-proxy` (`DefaultAuditService`) | Tags `AuditContext.Service` |

Per-route keys, all under `proxy.routes[].auth`:
`mode` (**required**), `require-idevid`, `allowed-zones`, `backend-zone`,
`require-attestation`, `attestation-max-age`, `required-roles`,
`required-scopes`, `opa-policy`, `token-zone`.
Route-level: `id`, `hosts`, `path-prefix`, `pool`, `strip-prefix`,
`preserve-host`.

Per-pool keys: `id`, `backends[].url`, `backends[].weight`, `balancer`,
`tls.trust-class`, `tls.mtls-client-cert`, `max-idle-conns-per-host`,
`idle-conn-timeout`.

**There are no environment variables for the proxy section.** Configuration is
file-and-API only. Precedence is: static file (base) → platformd runtime
config (wins per ID) → `AuthDefaults` merged into unset route fields at compile
time.

**Correction against the pre-migration `configuration.md`:** that document
omits the whole `proxy.audit` section, which exists in `proxysvc.AuditConfig`
and is validated by `Config.Validate`.

## 9. gatewayd assembly

`commands.BuildGateway` → `commands.BuildProxyHandler` (`assembly.go`):

1. Reject a disabled section (`ErrProxyDisabled`); `Config.Validate()`, which
   delegates route/pool/listener rules to `proxy.Config.Validate` — the single
   source of truth.
2. Build the `pkg/trust` resolver from `trust:` when present.
3. Resolve the client CA pool (`client-ca-file`, else `trust.ClassInternal`,
   bounded by a 30s `trustResolveTimeout`).
4. Build server TLS: `tls.VersionTLS13` minimum, `ClientAuth:
   VerifyClientCertIfGiven` when a pool exists.
5. Build the audit sink (never fatal), the zone-matrix provider (only when sync
   is enabled), and the enabled collaborators.
6. `proxy.New(staticCfg, deps)` — the fail-closed gate.
7. `proxysvc.NewLazyControlPlaneClient` + `NewConfigSyncer` when sync is
   enabled.
8. `proxysvc.NewHandler` and `Gateway.RegisterServiceHandler` under service
   name `proxy` (`proxysvc.ServiceName`, matching `gateway.ServiceProxy`).

`configNeedsAuth` inspects **static** routes only; a runtime-synced route that
adds an auth requirement is caught by `Reload`'s fail-closed checks instead.

`proxysvc.Handler` implements the gateway service-handler contract: `Name`,
`Start`, `Stop`, `IsActive`, `Health`, plus `HealthSnapshot() HealthSnapshot`
which is where a failed sync surfaces.

`ConfigSyncer.Run(ctx)` tickers; `SyncOnce(ctx)` is the unit under test;
`Status() SyncStatus` reports the loop.

## 10. Persistence

**`pkg/proxy` persists nothing.** The engine is configured in memory.

**`ProxyStore` (`pkg/api/daemon/proxy_store.go`) persists nothing either** — it
is `map[string]proxy.RouteConfig` plus `map[string]proxy.BackendPoolConfig`
under an `sync.RWMutex`, with a monotonic `version` and an `updatedAt`. It is
created empty on every daemon start. There is no schema, no key layout and no
migration rule, because there is no store on disk.

Store semantics that do matter:

- Every mutation validates the **whole** candidate configuration through
  `proxy.Config.Validate`, injecting a synthetic `validationListener`
  (`store-validation` on `127.0.0.1:0`) because the engine requires at least one
  listener and listeners are gatewayd-local.
- `DeletePool` refuses while any route references the pool
  (`ErrPoolInUse{ID, Routes}`).
- `Reload` bumps the version without changing state, which is how an operator
  forces every gatewayd to re-fetch.

## 11. Observability

**Log events** (slog, through the injected logger):

| Level | Event |
|---|---|
| Warn | `proxy: mtls authentication failed` (route, subject, error) |
| Warn | `proxy: idevid validation failed` |
| Warn | `proxy: zone extraction failed` |
| Debug | `proxy: zone extraction failed on zone-free route` |
| Warn | `proxy: token authentication failed` (route, error) |
| Warn | `proxy: attestation gate denied` (route, device, max_age, error) |
| Warn | `proxy: attestation required but caller has no device identity` |
| Warn | `proxy: opa policy denied request` (route, policy, client, violations) |
| Error | `proxy: opa evaluation failed` |
| Error | `proxy: backend error` (route, error) |
| Error | `proxy: listener terminated` / `proxy: closing listener` |
| Debug | `proxy: failed to write error response` |

**Never logged**: token values, DPoP proofs, introspection credentials. The
chain logs the certificate *subject*, never the certificate.

**Audit** — one `AuditEvent` per decision, delivered to `Deps.Audit`:

```go
type AuditEvent struct {
    Time                              time.Time
    RouteID, ClientID, DeviceID, Zone string
    Decision, Reason, AuthMethod      string
    RemoteAddr, Method, Path          string
}
```

`Decision` is one of `allow` / `deny` / `error` / `no-route`. `Reason` is empty
on allow and one of §5.5 on deny. In production `proxysvc.SDKAuditSink` maps it
onto a quicbaas `iamsdk.AuditEvent` and calls `RecordAsync` with a
`DefaultAuditTimeout` (5s) detached context.

**Metrics** — `Engine.Metrics()` returns a consistent snapshot:
`MetricsSnapshot{NotFound uint64, Routes map[string]RouteMetrics}` where
`RouteMetrics` is `{Requests, Denied, Errors, BytesOut}`. These are lock-free
`atomic.Uint64` counters incremented on the hot path; `BytesOut` is counted by
`countingResponseWriter`, which implements `Unwrap` so
`http.ResponseController` still reaches `Flush`/`Hijack`. There is **no
Prometheus exporter in `pkg/proxy`** — the snapshot is the interface.

## 12. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/proxy/*_test.go` | `config_test.go` (validation matrix), `authchain_test.go` + `authchain_phase3_test.go` (chain order, deny reasons), `capabilities_test.go` (fail-closed composition), `deps_test.go`, `router_test.go` (host/prefix matching), `balancer_test.go`, `transport_test.go` (carryover), `handler_test.go` + `handler_injection_test.go` (strip/inject), `listener_test.go`, `lifecycle_test.go`, `audit_test.go`, `metrics_test.go`, `errors_test.go`, `identity_test.go`, `proxy_test.go`; `benchmark_test.go` for the hot path; `helpers_test.go` for fixtures |
| Unit | `pkg/sdn/gateway/proxysvc/*_test.go` | Config validation, merge semantics, sync loop, attestation gate caching, token authenticator, OPA evaluator, audit sink |
| Unit | `pkg/api/daemon/proxy_store_test.go`, `proxy_grpc_service_test.go`, `proxy_mcp_test.go` | Store semantics and error mapping |
| Unit | `pkg/api/rest/proxy_handlers_test.go`, `pkg/api/quic/proxy_handlers_test.go`, `pkg/api/grpc/proxy_service_test.go` | Per-transport adapters |
| Unit | `pkg/policy/opa/proxy_authz_test.go` | The embedded `proxy_authz` policy |
| Integration | `test/integration/proxy/` (`//go:build integration`) | `gatewayd_test.go` — real `BuildProxyHandler` assembly; `multiprotocol_test.go` — the parity suite |

**Fault-injection seams**: the four one-method interfaces, plus
`proxysvc.DialFunc` / `AttestationDialFunc` / `AuditDialFunc` for connection
failures, and `MatrixProvider` for zone changes.

**Parity.** `test/integration/proxy/commands.go` declares `ProxyCommands` — the
transport-agnostic interface implemented by the CLI adapter (`cli_adapter.go`)
and the five SDK transport adapters (`sdk_adapters.go`), so
`multiprotocol_test.go` runs one body against each. It covers 13 of the 14
capabilities: route CRUD+list, pool CRUD+list, `Status`, `Reload`,
`ZoneMatrix`. **`GetProxyConfig` is absent from `ProxyCommands`** and has no
CLI verb, so it is the one capability with no parity coverage —
[cli.md](cli.md) §7.

Note this repository defines **no `CommandDefinition` type** (grepped
2026-08-18); `ProxyCommands` is what the parity requirement of
`conventions/feature-docs.md` §4 resolves to here.

## 13. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/gateway/engineering.md`](../gateway/engineering.md) — the node that hosts this service
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC frames, status bytes
- [`docs/sdn/`](../sdn/) — `zone.Matrix`
- [`docs/attestation/`](../attestation/) — manifests and verification

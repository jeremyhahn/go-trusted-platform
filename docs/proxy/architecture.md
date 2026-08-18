# Trusted Reverse Proxy — Architecture

> **Status: NORMATIVE** · Scope: `pkg/proxy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, exported surface, error set, auth-chain
> order, deny reasons, config keys, CLI flags, routes and the transport matrix
> were read out of the code on 2026-08-18. Corrections against the pre-migration
> documents are called out inline.

---

## 1. The problem

A platform that attests hardware still has to put *something* in front of an
application that cannot attest anything — a legacy admin console, a vendor
appliance UI, a service that speaks nothing but HTTP and a bearer token. The
usual answer is a general-purpose reverse proxy with an auth module bolted on.
That proxy knows about users and tokens. It does not know that the caller's
machine has a TPM, which network zone its certificate places it in, or whether
its last attestation manifest is stale.

The result is two authorization systems that disagree: the platform's, which is
hardware-rooted and zone-aware, and the proxy's, which is neither. Every route
then has to be configured twice, and the two configurations drift.

## 2. The shape chosen

**A reverse-proxy engine whose authentication is an injected chain of
platform-native mechanisms, not a module.**

`pkg/proxy` is a self-contained HTTP engine: lock-free routing over an atomic
pointer, one pooled transport per backend pool, one shared
`httputil.ReverseProxy` per route, hot reload with transport carryover. It
knows nothing about TPMs, tokens or zones. Everything trusted-computing enters
through four small interfaces:

| Seam | Interface | Production implementation |
|---|---|---|
| Certificate identity | `proxy.MTLSAuthenticator` | `*auth.MTLSAdapter` (`pkg/auth`) |
| Bearer tokens | `proxy.TokenAuthenticator` | `proxysvc.PlatformTokenAuthenticator` |
| Device attestation | `proxy.AttestationGate` | `proxysvc.SDKAttestationGate` |
| Policy | `proxy.PolicyEvaluator` | `proxysvc.OPAEvaluator` over `pkg/policy/opa` |

`proxy.Chain` (`authchain.go`) composes them. The engine is **fail-closed at
composition time**: `proxy.New` and `proxy.Reload` reject any configuration
whose routes demand a capability the injected chain does not report through
`ChainCapabilities`. A route asking for attestation on a chain with no gate is
a startup error, not a runtime deny.

The assembly — reading `proxy:`, `trust:` and the collaborators' config
sections, dialling platformd, wiring the sync loop — lives one layer up in
`pkg/sdn/gateway/proxysvc` and `pkg/sdn/gateway/commands`. That is deliberate:
`pkg/proxy` composes against behavior, never against the quicbaas SDK's
dependency graph.

### 2.1 Where the gateway ends and this feature begins

`gatewayd` is the edge node ([`docs/gateway/`](../gateway/)). Eleven
independently enabled service sections; `ServiceProxy` (`"proxy"`) is one of
them. The split:

| Concern | Owner |
|---|---|
| The node, its eleven service sections, its lifecycle, BGP/IPAM/LB/firewall/NAT/overlay | [`docs/gateway/`](../gateway/) |
| The reverse-proxy engine, its auth chain, routes, pools, listeners | **this folder** |
| The platformd-side route/pool store and its five-transport API | **this folder** ([api.md](api.md)) |
| The `gatewayd` binary and its `serve` command | [`docs/gateway/cli.md`](../gateway/cli.md) |
| `platformctl proxy` verbs | **this folder** ([cli.md](cli.md)) |

`docs/gateway/architecture.md` declares `pkg/proxy/` in its scope line. That is
the gateway's view of the proxy **as a hosted service**; the engine's own
design contract is this document, and where the two disagree this one wins for
anything inside `pkg/proxy`.

## 3. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **An off-the-shelf reverse proxy (nginx/Envoy/Traefik) with an auth plugin** | It authenticates a user or a token. It cannot evaluate a TCG IDevID, an `OIDTPNetworkZone` certificate extension, or an attestation manifest's freshness. Route reachability would be configured in the proxy *and* in the SDN zone matrix, and the two would drift. |
| **Putting the auth chain inside the engine package** | `pkg/proxy` would link the quicbaas platformtoken SDK validator, the OPA runtime and the attestation client. The engine that terminates untrusted traffic would carry the whole platform dependency tree. The four interfaces cost one indirection and buy an import closure small enough to guard (`pkg/arch/gatewayguard_test.go`). |
| **Running the engine inside `platformd`** | Untrusted HTTP termination would share a process with the control plane. `platformd` owns the *configuration*; `gatewayd` owns the *data path*. |
| **Letting gatewayd author its own routes** | Then every gateway is a separate source of truth and a fleet has no single answer to "what is reachable". platformd owns routes and pools; gatewayd polls. Listeners are the deliberate exception — a listen address is a property of the host, and platformd never sets one. |
| **Deriving the token principal's zone from a header** | Token clients present no certificate and therefore no zone extension. Trusting a header would let the caller pick its own zone. `auth.token-zone` is an **operator** assignment per route; absent it, zone-enforcing routes deny token principals with `zone_requires_mtls`. |
| **Warn-and-serve on a capability mismatch** | A route that demands attestation on a chain with no gate would deny every request at runtime and look like an outage. `checkRouteCapabilities` rejects it at `New`/`Reload` with a typed error, so the misconfiguration is visible before traffic arrives. |
| **Honouring inbound `X-Forwarded-Proto` / `X-Forwarded-Host` when rebuilding the DPoP `htu`** | The proxy *is* the front door, so those headers arrive unauthenticated from the client. Honouring them would let a caller replay a DPoP proof bound to a different origin. `requestHTU` rebuilds the URI from the proxy's own TLS state and `Host`. |
| **Forwarding the caller's `Authorization` header to the backend** | A backend could replay the caller's platform token. On every authenticated route the header is deleted before forwarding; the backend reads identity from the trusted `X-TP-*` headers and authenticates the *proxy* by its mTLS platform identity. |
| **TCP passthrough routes** | Declared in `RouteConfig.PassthroughTCP` and rejected by `Validate` with `ErrTCPPassthroughUnsupported`. The auth chain is HTTP-shaped — it needs headers, a method and a path. A passthrough route would silently bypass every control in this document. |
| **A weighted or least-connections balancer** | `BackendConfig.Weight` is parsed and validated (non-negative) and **the round-robin balancer ignores it**. One registered balancer, `round-robin`, is what exists; more can register into `balancerRegistry` when a deployment needs one. Documenting an unimplemented policy would be worse than the gap. |
| **Blocking the request path on the audit plane** | `SDKAuditSink` fails **open**: a dial failure logs and drops the event. An audit outage must not become a traffic outage. The authorization decisions themselves fail closed — the asymmetry is intentional and stated in §7. |

## 4. Component boundaries

| Piece | Package / file | Owner |
|---|---|---|
| Engine, compile, hot reload | `pkg/proxy/proxy.go` | this repo |
| Configuration schema and validation | `pkg/proxy/config.go` | this repo |
| Fail-closed composition, injected deps | `pkg/proxy/deps.go` | this repo |
| Auth chain, deny reasons, zone extraction | `pkg/proxy/authchain.go` | this repo |
| Bearer-token path, DPoP `htu` reconstruction | `pkg/proxy/tokenauth.go` | this repo |
| Attestation gate seam | `pkg/proxy/attestation.go` | this repo |
| OPA seam and the policy input document | `pkg/proxy/policy.go` | this repo |
| Routing table, host/prefix match | `pkg/proxy/router.go` | this repo |
| Backend pools, pooled transports | `pkg/proxy/transport.go`, `balancer.go` | this repo |
| Request handling, header strip/inject | `pkg/proxy/handler.go`, `identity.go` | this repo |
| Listeners, TLS, graceful stop | `pkg/proxy/listener.go` | this repo |
| Audit events, counters | `pkg/proxy/audit.go`, `metrics.go` | this repo |
| Typed errors | `pkg/proxy/errors.go` | this repo |
| gatewayd assembly, sync loop, adapters | `pkg/sdn/gateway/proxysvc/` | this repo — [`docs/gateway/`](../gateway/) hosts it |
| `BuildProxyHandler` / `BuildGateway` | `pkg/sdn/gateway/commands/assembly.go` | this repo |
| platformd route/pool store | `pkg/api/daemon/proxy_store.go` | this repo |
| Shared service behind all transports | `pkg/api/grpc/proxy_service.go` (`ProxyGRPCService`) | this repo |
| REST / QUIC / MCP adapters | `pkg/api/rest/proxy_handlers.go`, `pkg/api/quic/proxy_handlers.go`, `pkg/api/mcp/proxy_tools.go` | this repo |
| `platformctl proxy` | `pkg/cli/commands/proxy/` | this repo |
| **mTLS identity adapter** | `pkg/auth` (`MTLSAdapter`, `ValidateIDevID`) | this repo, separate feature |
| **Zone matrix** (`zone.Matrix`, `Allowed`) | `pkg/sdn/zone` — [`docs/sdn/`](../sdn/) | this repo, separate feature |
| **Trust classes** (`default` / `bmc` / `internal`) | `pkg/trust` | this repo, separate feature |
| **OPA engine and embedded policies** | `pkg/policy/opa` | this repo, separate feature |
| **Attestation manifests and verification** | `pkg/attestation` — [`docs/attestation/`](../attestation/) | this repo, separate feature |
| **`OIDTPNetworkZone` OID and its parser** | `go-quicbaas/sdk/go/xkms/ca` | **not this repo** |
| **Platform-token validation pipeline** | quicbaas `platformtoken` SDK | **not this repo** |
| **Broker that mints tokens; the audit chain of record** | quicbaasd | **not this repo** |

The §R capability row is *"Edge gateway and trusted reverse proxy (routes,
pools, zones)"*, Tier 1, reached through `services/proxy` alongside
`services/gateway`. The lower layer is consumed through `go-quicbaas/sdk/go`
only — the zone-extension parser, the token validator and the audit client all
arrive that way.

## 5. Data flow

### 5.1 Configuration — platformd decides, gatewayd polls

```
platformctl proxy route add ──▶ ProxyService (any of 5 transports)
                                     │
                                     ▼
                              ProxyStore (in-process, version++)
                                     │  GetProxyConfig / GetZoneMatrix
                                     ▼   (gRPC over the platformd UDS by default)
                              proxysvc.ConfigSyncer  ── every proxy.sync.interval
                                     │
                    ┌────────────────┴─────────────────┐
                    ▼                                  ▼
        Engine.Reload(MergeConfig(...))     ZoneMatrixProvider.Update  (atomic swap)
```

- **Every mutation re-validates the whole configuration** through
  `proxy.Config.Validate` and bumps a monotonic version. A poller detects
  change with one integer comparison.
- **The zone matrix refreshes on every tick**, independent of the config
  version — zones change without a proxy mutation.
- **Route and pool config applies only when the version moved.** A failed
  `Reload` leaves the running configuration serving, surfaces in
  `Handler.HealthSnapshot()`, and retries next tick without advancing the
  version.
- **Merge is by ID and platformd wins** (`proxysvc.MergeConfig`): a runtime
  entry whose ID matches a static one replaces it entirely. Listeners and
  `defaults` always come from the static file.
- **platformd being down at boot is not fatal.** The client is lazily dialled;
  gatewayd serves its static configuration and the sync loop keeps retrying.

**Correction against the pre-migration documents.** `ProxyStore` is an
in-process, mutex-guarded map created **empty at daemon start**
(`NewProxyGRPCService` → `NewProxyStore()`, `pkg/api/daemon/daemon.go:501`).
Routes and pools are **not persisted**: restarting `platformd` returns the
store to version 0 with no routes and no pools, and every syncing gatewayd then
converges on its static file configuration alone. Nothing in the code writes
the store to disk or to qrdb. Treat platformd-side proxy configuration as
runtime state, not durable state.

### 5.2 A request arriving at the edge

1. **TLS terminates on the proxy listener** (`listener.go` → `http.Server`,
   `Deps.ServerTLS`). TLS 1.3 minimum; client certificates are requested and,
   when presented, verified against the client CA pool with
   `tls.VerifyClientCertIfGiven` (`assembly.go: buildServerTLS`).
2. **Inbound identity headers are stripped** — `X-Forwarded-Client-Cert` and
   every `X-TP-*`, case-insensitively, **before routing and regardless of the
   auth outcome** (`stripIdentityHeaders`).
3. **Route match** — exact host first, then wildcard; longest path prefix wins;
   the match is on a path-segment boundary, so `/api` matches `/api/v1` and not
   `/apiary`. No match: 404 plus a `no-route` audit event.
4. **Public route?** The chain is never called; the request forwards.
5. **Credential selection.** `mtls` requires a certificate; `token` requires a
   bearer token; `mtls-or-token` takes the **mTLS path whenever a certificate
   is present** — when both credentials arrive the certificate wins and the
   bearer token is ignored and never forwarded.
6. **mTLS path** — adapter authentication (chain, validity), then IDevID
   validation on `require-idevid` routes, then zone extraction and enforcement,
   then roles.
7. **Token path** — bearer extraction, then the platformtoken SDK pipeline
   (JWKS-by-`kid`, `iss`/`aud`/`exp`, RFC 9068 `typ: at+jwt`, DPoP proof for
   `cnf.jkt`-bound tokens, scope enforcement, per-mode liveness), then the
   operator-assigned token zone, then roles.
8. **Attestation gate** (`require-attestation` routes), then **OPA policy**
   (`opa-policy` routes) — both shared by the two paths, in that order, so the
   policy input sees the attestation outcome.
9. **Identity injection** — the caller's `Authorization` header is deleted and
   the trusted `X-TP-*` headers plus an Envoy-compatible
   `X-Forwarded-Client-Cert` are set.
10. **Forward** through the pool's shared transport; the balancer picks a
    backend per request. Decision audited, counters incremented.

Steps 5–8 fail closed; the first failing check returns **403** with a stable
machine-readable reason and no detail beyond it.

## 6. Trust boundaries

### 6.1 Where TLS terminates

**On the proxy listener, in `gatewayd`.** There is exactly one termination
point for client traffic and it is inside this feature. `Deps.ServerTLS` is
required whenever any route is non-public (`ErrTLSRequiredForAuth`) — a plain
HTTP listener is permitted only when every route is `public`.

Two further TLS legs, both outbound and both anchored by `pkg/trust`:

- **Proxy → backend.** Per pool, when `tls.trust-class` is set. Unknown class
  is a typed error (`ErrUnknownTrustClass`), never default trust. Resolution
  uses the pool's **first** backend host as the representative endpoint, so a
  pool must be homogeneous in trust terms.
- **gatewayd → platformd.** Unix socket by default; `platformd.protocol: grpc`
  requires a `trust:` section (`ErrTrustRequiredForGRPC`). Verification is
  never skipped.

### 6.2 Where token validation happens — and what it is not

**Offline `scp` enforcement, inside `PlatformTokenAuthenticator`, using the
quicbaas platformtoken SDK.**

This platform is a **broker-token validator, not a token-authorization decision
point.** It does not mint tokens, does not run an authorization engine over
them, and does not decide what a subject may do. The broker (quicbaasd) minted
the `scp` claim from the subject's resolved permissions; the proxy verifies the
signature and enforces the claim it finds. `authz-mode: online` / `hybrid` add
RFC 7662 introspection for **liveness and revocation** — still asking the
broker a question, still not deciding authorization locally.

**Embedded OPA is a different thing and it is legitimately here.** The platform
runs OPA (`pkg/policy/opa`) for workload admission, attestation-evidence
evaluation and — through `proxy.PolicyEvaluator` — **per-route proxy-authz**.
`pkg/proxy` reaches it only through that one-method interface; `proxysvc`
supplies `OPAEvaluator`, and the engine's default action is `deny`, so an
undefined policy result never admits. The distinction that matters: OPA decides
**whether this authenticated caller may take this route**, using the identity
the chain already established. It never decides whether a token is valid.

`policy.go` and `GetZoneMatrix` are the other half of that join: a route's
reachability derives from the SDN zone matrix — the same deny-by-default table
that programs OVS flow rules — instead of being configured a second time here.

### 6.3 Session handling

**There is none, by design.** The proxy is stateless per request: no cookie, no
session store, no sticky backend affinity. Every request re-runs the full auth
chain. Three caches exist and none of them is a session:

| Cache | Where | TTL | What it holds |
|---|---|---|---|
| Attestation verdict, per **device** | `SDKAttestationGate` | `attestation.cache-ttl`, default 60s | manifest timestamp + verification result — **not** a per-route decision |
| Negative attestation result | `SDKAttestationGate` | `attestation.negative-cache-ttl`, default 5s | a failed platformd query |
| JWKS keys by `kid` | platformtoken SDK | `token-auth.cache-ttl`, default 1h | broker signing keys |

Hybrid mode additionally caches a *positive* liveness result for
`liveness-cache-ttl` (default 15s). The verdict cache is refreshed through
singleflight, so one platformd round trip serves concurrent routes with
different `attestation-max-age` values, and the shortest-lived deny window
belongs to the negative cache.

### 6.4 The rest

1. **Internet / IoT → proxy.** Everything inbound is untrusted, including every
   `X-TP-*` and `X-Forwarded-Client-Cert` header — stripped before routing.
2. **Proxy → backend.** Crossed only after an allow decision. The backend trusts
   the `X-TP-*` values *because* the proxy stripped them on the way in; that
   strip is the whole basis of the trust and it happens unconditionally.
3. **Attestation identity.** Manifests are keyed by the **IDevID CN**
   (`HostManifest.HostID`), so the chain passes the mTLS leaf's Common Name.
   Token principals have no device identity and are denied
   `attestation_unavailable` on attestation-gated routes — never admitted as
   "unknown".
4. **Zone as a certificate claim.** The client zone comes from the canonical
   `OIDTPNetworkZone` X.509 extension, parsed by the quicbaas SDK. A
   certificate without it is denied `zone_missing` on a zone-scoped route, never
   defaulted. Unknown zones fail closed in the matrix.
5. **The zero-state matrix denies everything.** Before the first successful
   sync, `ZoneMatrixProvider` holds a deny-all matrix. A gatewayd that has never
   reached platformd cannot pass a `backend-zone` check.
6. **The audit plane is outside the trust boundary of the data path.** It fails
   open (§3). A deny that was not recorded still denied.

## 7. What this feature deliberately does not do

- **It does not decide token authorization.** It validates broker tokens and
  enforces the `scp` claim offline. §6.2.
- **It does not mint or forward credentials toward backends.** No token
  exchange, no impersonation header, no service-account injection. The caller's
  `Authorization` header is deleted on every authenticated route.
- **It does not terminate TCP or non-HTTP protocols.** `PassthroughTCP` is
  rejected at validation.
- **It does not own listen addresses in the control plane.** Listeners are
  gatewayd-local and never synced.
- **It does not persist route or pool configuration.** §5.1.
- **It does not do health checking, circuit breaking, retries or outlier
  ejection.** The balancer hands out backends in order; a dead backend produces
  502 until it is removed from the pool.
- **It does not do rate limiting, WAF, request body inspection, or response
  rewriting.** Path-prefix stripping and Host preservation are the only request
  mutations.
- **It does not program the datapath.** VIP and anycast exposure are L3
  concerns owned by the gateway's OVS/BGP services; the engine binds the address
  it is given ([`docs/gateway/`](../gateway/)).
- **It does not terminate HTTP/3.** Listener protocols are `h1` and `h2` only;
  `ListenerConfig.Protocols` documents `h3` as a later phase and
  `ErrUnknownProtocol` rejects it today. (The *other* web server —
  `pkg/webservice` — does serve HTTP/3; see [`docs/web/`](../web/).)
- **It does not weight backends.** §3.
- **It does not run inside `platformd`'s request path.** platformd hosts the
  configuration API for this feature and nothing else of it.

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — the node that hosts the proxy service
- [`docs/daemon/api.md`](../daemon/api.md) — the six transports, the QUIC frame
  and opcode vocabulary, and the platform-wide authorization picture
- [`docs/sdn/`](../sdn/) — network zones and the matrix
- [`docs/attestation/`](../attestation/) — what the attestation gate queries
- [`docs/web/`](../web/) — the platform's *other* HTTP server, which also has a
  virtual-host reverse proxy and is not this one

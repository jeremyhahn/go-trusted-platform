# Proxy Configuration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [engineering.md](engineering.md) §8. The schema below omits the `proxy.audit` section (`proxysvc.AuditConfig`).

Two `proxy:` sections exist, one per daemon (#570, ruling R4):

- **platformd** (`/etc/trusted-platform/config.yaml`, schema
  `proxy.ControlPlaneConfig`): `routes`, `pools` and `defaults` the control plane
  owns. Seeded into the platform proxy store at startup as the base layer — an ID
  the store already holds (authored over the API) is kept as stored — and handed
  to every gateway through the sync loop. No listeners. Route, pool and auth keys
  are exactly the ones below (the gatewayd schema aliases the same
  `pkg/proxy` types).
- **gatewayd** (`/etc/gatewayd/config.yaml`, schema `pkg/sdn/gateway/proxysvc.Config`):
  the full section below — listeners (gatewayd-local, never synced), TLS, the static
  routes/pools base layer, sync, attestation, token-auth, OPA, audit.

The shipped templates put the routes in the control plane's section
(`configs/platform/templates/dedicated/*/control-plane.yaml`); the gateway
templates' webservice virtual hosts no longer proxy anything.

## gatewayd full schema

## Full schema

```yaml
proxy:
  enabled: true

  tls:
    cert-file: /etc/gatewayd/tls/server.pem       # front-door server cert (PEM, leaf + chain)
    key-file: /etc/gatewayd/tls/server-key.pem    # server key (PEM)
    client-ca-file: /etc/gatewayd/tls/ca.pem      # optional; default = the platform anchor (platform-ca-file:)

  listeners:                # gatewayd-local; NEVER synced from platformd
    - id: https
      address: :8443
      protocols: [h1, h2]   # empty enables both

  routes:                   # static base layer
    - id: legacy-app
      hosts: [app.example.com]      # empty matches any host
      path-prefix: /
      pool: legacy
      strip-prefix: false
      preserve-host: false
      auth:
        mode: mtls                  # public | mtls | token | mtls-or-token
        require-idevid: false       # rejected on mode: token (no certificate to carry an IDevID)
        allowed-zones: [control-plane]
        backend-zone: services
        require-attestation: false  # requires the attestation: section
        attestation-max-age: 5m
        required-roles: [admin]
        required-scopes: []         # token-path only; rejected on mode: public/mtls
        opa-policy: ""              # e.g. proxy_authz; requires the opa: section
        token-zone: ""              # operator-assigned zone for token principals (token modes only)

  pools:
    - id: legacy
      balancer: round-robin
      max-idle-conns-per-host: 32
      idle-conn-timeout: 90s
      tls:
        trust-class: platform       # platform (platform anchor) | bmc (trust: bmc: class)
        mtls-client-cert: false
      backends:
        - url: http://10.0.10.20:8080
          weight: 1

  defaults:
    attestation-max-age: 5m
    backend-zone: ""

  attestation:              # platformd-backed attestation gate (require-attestation routes)
    enabled: false
    cache-ttl: 60s          # per-device verdict reuse
    negative-cache-ttl: 5s  # failed platformd query reuse (deny window)
    # accepted age = route auth.attestation-max-age / defaults.attestation-max-age
    # (deliberately no third max-age knob here)

  token-auth:               # platform-token (DPoP) path for token / mtls-or-token routes
    enabled: false
    issuer: https://broker.example.gov      # REQUIRED: QuicBaaS identity broker issuer (iss)
    jwks-url: https://broker.example.gov/.well-known/jwks.json  # REQUIRED: broker JWKS
    audience: api://platform-proxy          # default api://platform-proxy
    cache-ttl: 1h                           # JWKS key cache
    authz-mode: hybrid                      # offline | online | hybrid (default hybrid)
    introspection-url: https://broker.example.gov/oauth2/introspect  # REQUIRED for online/hybrid
    introspection-client-id: ""             # RFC 7662 Basic credentials (optional)
    introspection-client-secret: ""
    introspection-bearer-token: ""          # alternative Bearer credential
    allow-bearer: false                     # false (default) requires a DPoP proof on every request
    liveness-cache-ttl: 15s                 # hybrid-mode positive liveness cache

  opa:                      # per-route OPA policy evaluation (opa-policy routes)
    enabled: false
    policy-dir: ""          # optional overlay over the embedded policies (same-name wins)

  sync:
    enabled: true
    interval: 15s           # default 15s

  platformd:
    protocol: unix          # unix (default) | grpc
    socket: /run/platformd.sock
    grpc-addr: cp.example.com:10443   # grpc protocol; TLS anchored by platform-ca-file: (the platform anchor)
    cert-file: /etc/gatewayd/platformd-client.pem      # grpc: client identity for an mTLS platformd
    key-file: /etc/gatewayd/platformd-client-key.pem
    token-file: ""                    # grpc: platform bearer token for a token platformd (re-read on every dial)
```

Two gatewayd-wide trust sources back the proxy. The top-level
`platform-ca-file:` is the platform anchor: it supplies the client CA pool
(unless `client-ca-file` overrides it), `trust-class: platform` backend
TLS, and the TLS anchor for the `grpc` platformd protocol. The `trust:`
section (`pkg/trust` resolver) supplies `trust-class: bmc` backend TLS.

The broker `issuer` / `jwks-url` are deployment-specific and therefore
required config (typed validation error when missing) — there is no
discoverable default. `authz-mode` mirrors the platformd platform-token
validator: `hybrid` (default) and `online` require `introspection-url`
and fail closed at startup without it; only an explicit
`authz-mode: offline` skips liveness.

`token-zone` design: token clients present no certificate and therefore
no `OIDTPNetworkZone` extension, so on routes that enforce
`allowed-zones` / `backend-zone` their zone cannot be derived — it is an
operator trust decision. `auth.token-zone` assigns that zone per route;
it passes exactly the same `allowed-zones` and zone-matrix checks a
certificate zone would (unknown zones are denied by the deny-by-default
matrix), and without it token principals are denied with
`zone_requires_mtls`. The field is carried end-to-end (config file,
platformd `ProxyService` proto `token_zone`, sync loop), and is rejected
on routes without a token path.

## Static / runtime merge semantics

The engine configuration served at any moment is
`MergeConfig(static, platformdRoutes, platformdPools)`:

1. **Listeners and defaults** — always from the static file. platformd
   never owns gatewayd listen addresses.
2. **Routes and pools merge by ID; platformd wins.** A platformd
   route/pool whose ID matches a static one replaces it entirely (full
   replace, not a patch). Platformd entries with new IDs are appended.
3. **Static entries platformd does not know keep serving.** Removing a
   static entry requires a file change + restart; removing a runtime
   entry requires a platformd delete (applied on the next sync tick).
4. Ordering is deterministic: static entries in file order (with
   overrides applied in place), then new platformd entries in ID order.

A merged configuration that fails validation (or demands a capability
the chain lacks) is rejected atomically: the previous configuration
keeps serving, the error appears in the handler health snapshot, and the
sync loop retries on the next tick.

## Failure behavior at startup

- `proxy.enabled: true` with authenticated routes and no TLS material →
  typed startup error (`ErrServerTLSRequired` / `ErrClientCARequired`).
- platformd unreachable → gatewayd starts on the static configuration
  and logs a warn per failed sync attempt; no crash loop.
- `platformd.protocol: grpc` without `platform-ca-file:` → typed startup
  error (`ErrPlatformAnchorRequiredForGRPC`); TLS verification is never
  skipped.
- `platformd.protocol: grpc` without `cert-file`/`key-file` or
  `token-file` → typed startup error (`ErrConfigInvalid`): platformd's gRPC
  listener refuses unauthenticated callers. A certificate that does not
  load, or an empty token file, is `ErrPlatformdIdentityLoadFailed`.

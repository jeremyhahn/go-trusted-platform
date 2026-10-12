# Web Console and Web Server — Architecture

> **Status: NORMATIVE** · Scope: `pkg/webserver/`, `pkg/webservice/`, `web/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, server construction, static-serving
> behavior, embedding mechanism, config keys, route registration, frontend tree
> and build targets were read out of the code on 2026-08-18. The pre-migration
> documents had drifted substantially; each correction is called out inline.

---

## 1. The problem

The platform's control surface is a REST API. Somebody has to serve a browser
UI for it, and the two obvious ways to do that are both wrong for this product:

- **Ship the UI as a separate service.** Now an air-gapped install needs two
  artifacts, two TLS identities, two lifecycles, and a CORS relationship
  between them. An appliance you install from an ISO cannot have half of itself
  on a CDN.
- **Server-render it.** A Node runtime inside the trusted control plane is an
  additional attack surface and an additional supply chain, sitting next to the
  TPM and the CA.

What the product needs is a UI that is *bytes* — no runtime, no second service
— served by the same process, over the same TLS identity, out of the same
binary when you want a single artifact and off disk when you want to update it
without one.

## 2. The shape chosen

**A statically exported Next.js application, served by the platform's own HTTP
server, optionally compiled into the binary.**

Three pieces:

| Piece | What it is |
|---|---|
| `web/` | Next.js 16 / React 19 control panel. `output: 'export'` — no server runtime, no SSR at runtime. Consumes the platform through `sdk/javascript` (`trusted-platform-sdk`) |
| `pkg/webserver/embed/` | A two-file build-tag switch that either embeds `dist/` into the binary or leaves the FS nil |
| `pkg/webservice/` | `WebServerV1` — HTTP/1.1 + HTTP/2 + HTTP/3 server, virtual hosts, static and SPA serving, CORS, the `/api/v1` mount and the OCI `/v2` mount |

**One server, one certificate, one port pair.** The console and the REST API
are the same listener: `/api/v1/...` goes to the API router, everything else
falls through to static serving. There is no CORS problem to solve in
production because there is no cross origin.

### 2.1 Static export means the URL space is a directory tree

`trailingSlash: true` turns `/devices` into `devices/index.html`. That is why
the server's fallback logic is more than "serve index.html": a static export of
a dynamic route like `/devices/[id]` pre-renders exactly one literal segment,
`__placeholder__`, and no directory exists for a real ID at runtime.

Both serving paths therefore walk the requested path from the deepest segment
up, looking for a sibling `__placeholder__/index.html`
(`findPlaceholderFallback` for the embedded FS, `findPlaceholderFallbackFS` for
disk), and serve that so the client component can hydrate and read the real ID
out of the URL. `web/src/utils/dynamic-route.ts: resolveDynamicId` is the
client half of the same contract — it trusts `useParams()` unless the value is
missing or literally `__placeholder__`, and then reads the pathname.

Without this, a click on a detail row misses on disk, is not a non-SPA path,
falls through to `/index.html`, and the browser lands back on the dashboard.
That failure was real and the fallback exists because of it.

### 2.2 The SPA fallback has an exclusion list

`nonSPAPathPrefixes` — `/api/`, `/_next/`, `/static/` — never fall back to the
SPA shell. A miss under `/api/` returns a **JSON** 404
(`{"error","path","message"}`); a miss under the other two returns a plain 404.
Without this the frontend would answer REST calls with HTML, and every client
error would surface as a JSON parse failure instead of a 404.

## 3. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **A separately deployed frontend service** | Two artifacts, two TLS identities, a real CORS boundary, and an install path that cannot be a single ISO. |
| **Server-side rendering / `next start`** | A Node runtime inside the control plane: a second supply chain and a second attack surface beside the TPM and CA. `output: 'export'` removes the runtime entirely. |
| **Embedding always** | Every UI change would need a Go rebuild and a binary redeploy. `WITH_WEB` is **off by default** for development speed, and the ISO path installs `public_html` to disk instead — you can rsync a UI fix without rebuilding the platform. |
| **Embedding never** | An air-gapped or immutable-root deployment wants exactly one artifact. `WITH_WEB=1` gives it. Both modes exist because both deployments exist. |
| **Serving the SPA shell for every miss** | REST clients would receive HTML for a mistyped endpoint. §2.2. |
| **Serving `/index.html` for unmatched dynamic routes** | Users landed back on the dashboard instead of the detail page. §2.1. |
| **Hand-written `fetch` wrappers per page** | The frontend consumes `trusted-platform-sdk` and its React hooks (`useDevice`, `useCA`, `useKMS`, …) so the API contract lives in one generated place. **Correction:** the pre-migration `control-panel.md` describes a `src/lib/api/` client layer and `api-integration.md` an `apiRequest` helper. Neither exists — `src/lib/` contains only `utils.ts`, and the hooks barrel `src/hooks/index.ts` re-exports 25 SDK hooks. |
| **Mounting the OCI distribution API under `/api/v1`** | The distribution specification mandates `/v2/` at the host root; under `/api/v1` a `docker pull` against the registry fails. It is registered on the root router before the API subrouter. |
| **Turbopack for the default dev and build scripts** | The linked local SDK (`file:../sdk/javascript`) resolves more reliably under webpack. `dev` and `build` are `next dev --webpack` / `next build --webpack`; `dev:turbopack` remains available. **Correction:** the pre-migration `configuration.md` and `README.md` document `next dev --turbopack` as the default. |

## 4. Component boundaries

| Piece | Package / path | Owner |
|---|---|---|
| HTTP/S server, virtual hosts, static + SPA serving | `pkg/webservice/webserver_v1.go` | this repo |
| Web service configuration schema | `pkg/webservice/v1/config.go` | this repo |
| Built-in defaults (`DefaultConfig`, RSA/ECDSA/Ed25519 variants) | `pkg/webservice/types.go` | this repo |
| Virtual-host round-robin | `pkg/webservice/loadbalancer.go` | this repo |
| mTLS client / signer helpers | `pkg/webservice/mtls_client.go`, `mtls_signer.go` | this repo |
| `/api/v1` route registration | `pkg/webservice/v1/router.go`, `pkg/webservice/v1/router/` | this repo |
| Service registry and its status endpoint | `pkg/webservice/v1/service_registry.go` | this repo |
| CORS, mTLS, IAM and tenant middleware | `pkg/webservice/v1/middleware/` | this repo |
| Browser JWT issue / refresh | `pkg/webservice/v1/jwt/` | this repo |
| Response envelope | `sdk/go/wire/restwire/` (type), `pkg/webservice/v1/response/` (writer) | this repo |
| Embed switch | `pkg/webserver/embed/embed.go`, `embed_web.go` | this repo |
| Control-panel frontend | `web/src/` | this repo |
| JavaScript/TypeScript SDK | `sdk/javascript` (`trusted-platform-sdk`) | this repo, separate feature |
| **Certificate issuance and TLS config for the listener** | the CA, through `go-quicbaas/sdk/go/xkms/acme` | **not this repo** |
| **Certificate hot reload** | `pkg/bootstrap.CertReloader` | this repo, separate feature |
| **WebAuthn service** | `pkg/webservice/v1/...` registry-wired; the credential model is IAM's — [`docs/iam/`](../iam/) | this repo, separate feature |
| **Everything under `/api/v1/<service>`** | each service's own feature folder | this repo, separate features |
| **The OCI `/v2` surface** | `pkg/webservice/v1/rest/registry` — [`docs/registry/`](../registry/) | this repo, separate feature |
| **The ISO installer that lays down `public_html`** | `pkg/installer/` | this repo, separate feature |

**This folder documents the server and the console, not the API it serves.**
Route inventories for individual services belong to those services' folders;
the transport model belongs to [`docs/daemon/api.md`](../daemon/api.md).

### 4.1 This is not the trusted reverse proxy

`WebServerV1` contains its own reverse proxy: a virtual host with
`proxy.backends` set gets `httputil.NewSingleHostReverseProxy` behind
`RoundRobinBalancer()` (`webserver_v1.go: reverseProxyHandler`). It is
**unauthenticated** — it applies no auth chain, no zone check, no attestation
gate, and no identity header injection. It is a convenience for fronting a
sibling service on a virtual host, and it is a different thing from
[`docs/proxy/`](../proxy/), which is the authenticating trusted proxy that runs
in `gatewayd`.

Do not reach for the virtual-host proxy when the requirement is
authentication. It cannot do it.

The *top-level* `webservices[].proxy` key that used to sit beside
`virtual-hosts` parsed and was never read; it was removed in #571. Only
`virtual-hosts[].proxy` exists. Under ruling R4 (epic #553) the shipping
edge proxy becomes `pkg/proxy`; until that lands, an `edge` surface fronts
these virtual-host proxies.

## 5. Data flow

### 5.1 Build and delivery

```
web/src ──npm run build──▶ web/out/            (static export)
                             │
              ┌──────────────┼─────────────────────────┐
              ▼              ▼                         ▼
   pkg/webserver/embed/dist   public_html/     public_html.tar.gz
   (WITH_WEB=1, tag           (make web-build,  (ISO payload,
    platform_web)              make build-       platformctl iso
                               public-html)      create --webui)
              │                    │                    │
              ▼                    ▼                    ▼
   compiled into the binary   served from disk   installed to
   (embed.WebFS)              (webservices[].home) <install-dir>/public_html
```

`make build-public-html` additionally generates the Swagger/OpenAPI document
and vendors Swagger UI into `public_html/swagger/`; the embed path
(`_web-embed-prepare`) does not.

### 5.2 A request arriving at the web server

1. **Listener.** Plain HTTP on `port` (a redirect to the TLS port, #535);
   when `tls-port > 0`, additionally HTTPS on TCP **and HTTP/3 on UDP at the
   same port number**. ALPN is `["h3", "h2", "http/1.1"]`; every response
   carries `Alt-Svc: h3=":443"; ma=86400`. Each TCP listener is capped at
   `max-connections` when set (always on an edge surface). **Residual risk:**
   the cap counts TCP connections only; QUIC connections over UDP are not
   counted (quic-go exposes no server-side connection cap), so an edge
   surface bounds each HTTP/3 connection to 100 streams instead, and the
   per-source rate limit still applies to every request.
2. **Rate limit**, when configured (always on an edge surface): a per-source
   token bucket (`pkg/security/ratelimit`) answers `429` before any handler.
3. **CORS** middleware, when `cors:` is configured — globally, and/or per
   virtual host.
4. **Virtual hosts** — registered **before every path route** (#571), each
   matched by an allowlist of its configured names (exact, or a `*.suffix`
   wildcard by one label; `hostSetMatcher`), each either the static handler
   for its directory or the unauthenticated proxy. A virtual host owns its
   Host entirely: a request for it never falls through to this server's own
   API or console, on either surface.
5. **The surface** (`surface: full`, the default):
   - `/v2/...` — the OCI distribution surface, on the root router, only when
     the handler registry supplies a backend; every route behind the v1
     router's caller gate and admin chain (`RegisterRootRoutes`, #549). A
     mount that cannot be gated is a startup failure, not a degraded node.
   - `/v1/ca/bootstrap` — the canonical trust-bootstrap bundle.
   - `/api/v1/...` — the API subrouter; ~25 route groups registered in a
     fixed order, each degrading to a recorded "unconfigured" state rather
     than vanishing.
   - Everything else — the global static handler for `home` / `index`.

   **`surface: edge`** (#571) mounts none of that. A public edge listener
   carries the virtual hosts above, the ACME group under `/api/v1/acme`
   **only when this node has an ACME server** (the control plane does; a
   gateway node does not, and its edge is a pure reverse-proxy listener), and
   the plaintext redirect. Its catch-all answers `404` for a path it does not
   mount on a host it serves, and `421 Misdirected Request` for any other
   host — never the SPA. An edge with neither an ACME server nor a virtual
   host would mount nothing and refuses to start (`ErrEdgeSurfaceEmpty`); an
   unknown `surface` value refuses to start (`ErrUnknownSurface`).

Static serving resolves in this order: rewrite rules → exact file → directory
index → non-SPA exclusion (JSON or plain 404) → `__placeholder__` fallback →
SPA index → 404.

### 5.3 A browser session

1. The console loads. `/` client-side `replace`s to `/auth/webauthn` — a
   deliberate client-side redirect, because Next's server `redirect()` is a
   no-op in a static export and previously produced a blank `index.html`.
2. WebAuthn registration or login runs against
   `/api/v1/webauthn/{registration,login}/{begin,finish}` using
   `@simplewebauthn/browser`.
3. On success the **page JavaScript** writes the returned JWT into a `jwt`
   cookie: `secure`, `SameSite=Strict`, `expires` **7 days**.
4. `AuthProvider` (`src/contexts/AuthContext.tsx`) reads that cookie, decodes
   the JWT **without verifying the signature**, and exposes
   `{id, email, tenantId, isTenantOwner, roles}` plus `isAuthenticated`,
   `isLoading`, `login`, `logout`. It is the console's only auth
   implementation: `@/hooks` re-exports `useAuth` and `AuthProvider` from it, so
   every import path reaches the same React context.
5. `AuthGuard` renders nothing and `replace`s to `/auth/webauthn` whenever the
   decode yields no user.
6. Every API call goes through `PlatformProvider` with `baseUrl: "/api"` and
   `credentials: "include"` — same origin, so the cookie rides along.

## 6. Trust boundaries

### 6.1 Where TLS terminates

**On `WebServerV1`'s HTTPS/H3 listeners, in the platform process.** The
`tls.Config` comes from the CA — `ServerTLSConfig`, or `TLSConfigWithXSigner`
when `certificate.acme.cross-sign` is configured — not from files on disk.
When a certificate is present, `bootstrap.CertReloader` is installed as
`GetCertificate`, so rotation happens without a restart.

**The plain-HTTP listener on `port` is a redirect to `tls-port`** and mounts
nothing else (#535): a request for the console or the API in the clear is
answered with a permanent redirect and never a page, a route or a 401 inviting
a credential. Without a TLS port the plaintext listener may carry the router
only when `bind-host` is loopback; an exposed plaintext-only webservice refuses
to construct (`ErrPlaintextExposure`). `port: 0` opens no plaintext listener.

**`webservices[].certificate` and `webservices[].key`** select the identity and
its storage; the defaults put the key in the TPM
(`StoreType: StoreTPM2`, `PlatformPolicy: true`) for the RSA and ECDSA
profiles, and in software for Ed25519.

### 6.2 Where token validation happens

**In middleware, on the `/api/v1` router, per protected route.** The precedence
is fixed (`systemRoutes`):

1. **Broker platform-token validator** when `jwt.platform-token.enabled` — the
   pure-validator inbound path. Verifies the signature against the broker JWKS
   by `kid`, checks `iss`/`aud`/`exp`, optionally binds a presented DPoP proof
   to the token's `cnf.jkt`, and maps `scp` → RBAC and `tenant_id` → row-level
   security.
2. **WebAuthn handler** when configured.
3. **Legacy locally minted JWT handler** otherwise.

Same statement as the rest of the platform: **this is a broker-token validator,
not a token-authorization decision point.** It enforces the `scp` claim
offline; `authz-mode: online` / `hybrid` add RFC 7662 introspection for
liveness and revocation, which is still asking the broker rather than deciding
locally. Embedded OPA (`pkg/policy/opa`) is used elsewhere in the platform —
workload admission, attestation evidence, proxy authz
([`docs/proxy/`](../proxy/)) — and **is not in this server's request path**.

The locally minted JWT path (`/api/v1/login`) is the legacy alternative and
exists for deployments with no broker.

### 6.3 Session handling

**A JWT in a cookie, written and read by JavaScript. There is no server-side
session.**

Consequences, all deliberate or all observable, and worth stating plainly:

| Property | Value | Why it matters |
|---|---|---|
| Cookie name | `jwt` | Also `uid` after WebAuthn registration |
| `HttpOnly` | **No** — it cannot be, the page sets it | The token is readable by any script on the origin. The mitigation is that the origin serves only the platform's own static bundle |
| `Secure` | Yes | |
| `SameSite` | `Strict` | |
| Cookie lifetime | **7 days**, hard-coded in the page | |
| **Token** lifetime | `webservices[].jwt.expiration` **minutes**, default **60** | |
| Signature verification | **Client-side: none.** `decodeJWT` splits and base64-decodes. The server verifies on every request | |

**The cookie outlives the token by design of neither.** After the token
expires the console still believes it is authenticated — `AuthGuard` only
checks that the JWT decodes and carries `sub`/`email`, not `exp` — until an API
call returns 401. Users experience this as a UI that looks logged in and
answers 401. Recorded here rather than resolved; changing either lifetime is a
behavior change.

**Correction:** the pre-migration `README.md` states a "7-day token lifetime
with server-side validation". Seven days is the *cookie*; the token default is
60 minutes (`jwt.Expiration` is multiplied by `time.Minute` in
`pkg/webservice/v1/jwt/service.go`).

### 6.4 The rest

1. **Browser → server.** Everything from the browser is untrusted. Multi-tenancy
   is enforced **server-side** from the token's `tenant_id`; the console's
   tenant state is display only, and hiding a button hides nothing.
2. **Virtual-host proxy → backend.** Unauthenticated and unauthorised. §4.1.
3. **Host header.** `validateHostHeader` accepts a domain (with optional port)
   or a literal IP. Virtual-host dispatch is by `Host`, so a misconfigured host
   list is a routing question, not an authorization one.
4. **Filesystem serving.** Request paths are `filepath.Clean`ed and joined onto
   the configured root; on the embedded path the FS is a `fs.Sub` of the
   compiled `dist/`. Directories outside the root are not reachable through
   either path.
5. **The embedded bundle is part of the measured binary.** With `WITH_WEB=1`
   the UI is inside the artifact the platform attests. Serving from
   `public_html` on disk moves the UI outside that boundary — a real
   deployment-time trade-off, not a detail.
6. **Default index generation.** `ensureDirectoryExists` creates a missing
   virtual-host directory and writes a templated placeholder `index.html`. A
   typo in `home` produces a working "Welcome to …" page rather than an error.

## 7. What this feature deliberately does not do

- **It does not render on the server.** No SSR, no ISR, no Node runtime in the
  platform.
- **It does not verify JWT signatures in the browser.** Client-side decoding is
  for display; the server is the authority.
- **It does not enforce tenancy in the frontend.** The UI hides what a role
  cannot use; the API refuses it.
- **It does not authenticate the virtual-host reverse proxy.** §4.1.
- **It does not serve anything but the HTTPS redirect on the plain port** when
  a TLS port exists; `port: 0` disables the plain listener entirely.
- **It does not hot-reload the frontend.** Embedded assets change with the
  binary; disk assets change when you copy files.
- **It does not own the API it serves.** Route groups belong to their features.
- **It does not offer a CLI of its own.** [cli.md](cli.md).
- **It does not expose any of its own behavior on gRPC, QUIC, Unix, MCP or the
  embedded transport.** [api.md](api.md) records the whole surface as
  REST-and-browser-only.

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — the six transports and the
  authorization picture; this server is the REST one
- [`docs/iam/`](../iam/) — WebAuthn credentials, users, roles
- [`docs/registry/`](../registry/) — the OCI `/v2` surface this server mounts
- [`docs/proxy/`](../proxy/) — the *authenticating* reverse proxy, which this is
  not

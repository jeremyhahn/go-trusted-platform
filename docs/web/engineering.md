# Web Console and Web Server — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/webserver/`, `pkg/webservice/`, `web/` · Last verified: 2026-10-27
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier, config key, file path and script name below was grepped in
> this repository on 2026-08-18.

---

## 1. Package layout

### 1.1 `pkg/webserver/embed/` — three files, one decision

| File | Build tag | Contents |
|---|---|---|
| `embed.go` | `!platform_web` | `var WebFS fs.FS` = nil; `IsEmbedded() bool` = false |
| `embed_web.go` | `platform_web` | `//go:embed all:dist`; `init()` sets `WebFS = fs.Sub(webDist, "dist")`; `IsEmbedded()` = true only when `dist` holds an entry other than `.gitkeep` (#323) |
| `embed_test.go`, `embed_stub_test.go`, `embed_web_test.go` | —, `!platform_web`, `platform_web` | |

`init()` **panics** if `fs.Sub` fails. That is correct: a binary built with the
tag and a broken `dist/` must not start.

**Correction against the pre-migration `embedding.md`:** that document shows
`//go:embed public_html/*` in an unnamed package. The real directive is
`//go:embed all:dist` inside `pkg/webserver/embed`, gated on the `platform_web`
tag and fed from `pkg/webserver/embed/dist` by the Makefile.

### 1.2 `pkg/webservice/` — the server

| File | Holds |
|---|---|
| `webserver_v1.go` | `WebServerV1`, `NewWebServerV1`, `Run`, `Shutdown`, `buildRoutes`, `serveStaticFiles`, `serveEmbeddedFiles`, `serveFilesystemFiles`, `serveEmbeddedFile`, `findPlaceholderFallback`, `findPlaceholderFallbackFS`, `reverseProxyHandler`, `startHTTP`, `startHTTPS`, `plaintextHandler`, `redirectToTLS`, `servedHosts`, `debugRoutes`, `CertReloader`, `ensureDirectoryExists`, `createDefaultIndexFile`, `addAltSvcHeader` |
| `types.go` | `DefaultConfig`, `DefaultConfigRSA`, `DefaultConfigECDSA`, `DefaultConfigEd25519` |
| `edge.go` | Surface and listener limits (#571): `resolveSurface`, `resolveLimits`, `ListenerLimits`, the `Edge*` defaults, the rate limiter, `misdirectedUnlessServed`; `ErrUnknownSurface`, `ErrEdgeSurfaceEmpty`, `ErrProvisioningSurfaceEmpty` |
| `provisioning.go` | `ValidateProvisioningSurface` and its typed refusals (#177) |
| `cert_reload_errors.go` | Typed errors for certificate hot-reload |
| `loadbalancer.go` | `LoadBalancerFunc`, `RoundRobinBalancer` |
| `mtls_client.go`, `mtls_signer.go` | mTLS client and signer helpers |
| `util.go`, `errors.go` | helpers; `WrappedError` |

`pkg/webservice/v1/` — configuration, routing and middleware:
`config.go`, `types.go`, `errors.go`, `authz.go`, `router.go`, `registry.go`,
`service_registry.go`, `keycache.go`, `attestation_capture.go`,
`router/` (per-group routers), `middleware/` (`cors.go`, `mtls.go`, `iam/`,
`tenant/`), `jwt/`, `response/`, `rest/<service>/`, `device/`, `bmc/`,
`invitation/`, `login/`, `webauthn/`, `adminclaim/`, `system/`.

### 1.3 `web/` — the console

```
web/
├── src/
│   ├── app/
│   │   ├── layout.tsx, page.tsx, providers.tsx, globals.css, fonts/
│   │   ├── auth/webauthn/, auth/login/, logout/, protected/
│   │   ├── admin/tenant/, admin/invitations/
│   │   ├── (auth)/                 # route group: layout.tsx only, no pages
│   │   └── (dashboard)/            # route group: layout + AuthGuard
│   │       ├── dashboard/ account/security/
│   │       ├── iam/ tenant/ ca/ kms/ devices/ attestation/ tpm/
│   │       ├── compute/ networking/ storage/ provisioning/ platform/
│   ├── components/{ui,layout,features,security,brand}/, theme-*.tsx
│   ├── contexts/AuthContext.tsx    # the only auth implementation
│   ├── hooks/{index.ts,use-toast.ts,...}   # index.ts re-exports AuthContext
│   ├── lib/{utils.ts,number-field.ts,device-*.ts,compute-state.ts,sdn-wire.ts,...}
│   ├── test/control-plane-fetch.tsx    # shared vitest helper
│   ├── types/*.ts
│   └── utils/{cookie.ts,jwt.ts,session.ts,errors.ts,getBaseUrl.ts,dynamic-route.ts,auth-factors-api.ts,...}
├── e2e/                            # Playwright E2E (mocked backend)
├── next.config.mjs, tailwind.config.ts, playwright.config.ts,
│   playwright.integration.config.ts, vitest.config.ts, package.json, Makefile
```

~225 `.tsx` files across roughly 90 pages. **Correction:** the pre-migration
`architecture.md` describes six pages under a flat `src/app/` and an
`(auth)` route group holding the auth pages. `(auth)` holds only a
`layout.tsx`; the authenticated surface is the `(dashboard)` group and the
legacy `admin/`, `protected/`, `logout/`, `auth/webauthn/`, `auth/login/` pages
sit outside both. `control-panel.md`'s `src/lib/api/` layer does not exist
either — `src/lib/` holds pure helpers (`utils.ts`, `number-field.ts`, the
device, compute and SDN wire mappers) with their vitest files, and no API
client.

## 2. Exported surface

```go
// pkg/webserver/embed
var  WebFS fs.FS
func IsEmbedded() bool

// pkg/webservice
func NewWebServerV1(
    ctx context.Context, debug bool, logger *logging.Logger,
    _ca trustedca.CACertificateAuthority, caConfig *trustedca.CAConfig,
    config *v1.Config, restServiceRegistry v1.RestHandlerRegistry,
    keyAttributes *xkmssdk.KeyAttributes) *WebServerV1

func (server *WebServerV1) Run()
func (server *WebServerV1) Shutdown()
func (server *WebServerV1) CertReloader() *bootstrap.CertReloader

type LoadBalancerFunc func(backends []string) string
func RoundRobinBalancer() LoadBalancerFunc

var ErrLoadTlsCerts, ErrBindPort error
```

**`NewWebServerV1` calls `logger.FatalError` when `_ca` is nil.** Construction
without a CA terminates the process; there is no error return.

**`Run()` blocks** until `Shutdown()` sends on `closeChan`. `Shutdown` allows
one 5-second context for the plaintext and TLS `http.Server.Shutdown` calls
and the HTTP/3 server. `startHTTPS` keeps the HTTP/3 server, its UDP socket and
a `done` channel in `server.h3`; `shutdownHTTP3` drains it with
`http3.Server.Shutdown(ctx)` (GOAWAY, then wait for in-flight requests), falls
back to `Close` (which aborts them) when the drain fails or the context
expires, waits on `done` for `Serve` to return, then closes the UDP socket so
the port is released. A failed step is an `ErrHTTP3Shutdown` (`drain`,
`close`, `socket`) that `Shutdown` logs.

Server timeouts (`webserver_v1.go`):
`HTTP_CLIENT_TIMEOUT` 10s, `HTTP_SERVER_READ_TIMEOUT` 5s,
`HTTP_SERVER_WRITE_TIMEOUT` 30s, `HTTP_SERVER_IDLE_TIMEOUT` 120s. The three
server values are the defaults `resolveLimits` (`edge.go`) applies when the
entry's `read-timeout`, `write-timeout` or `idle-timeout` is unset (§6).

**The write timeout applies to every response on the listener**, including any
streaming endpoint mounted under `/api/v1`. A stream that needs to run longer
than the default 30s needs a larger `write-timeout` on that entry.

`Shutdown` drains the plaintext and TLS servers and closes the rate limiter.

## 3. Invariants

1. **`buildRoutes()` builds a fresh `mux.Router` and swaps it under
   `routerMutex`**, then re-wraps it in `addAltSvcHeader`. It is called once by
   `Run()`, and is written to be safe to call again at runtime.
2. **On the `full` surface, `/v2` is registered on the root router before the `/api/v1` subrouter**,
   because the OCI distribution specification mandates the host root. It goes
   through the same `v1.Router` (`RegisterRootRoutes`) so it shares the API's
   gates; the root router is walked by its own authorization audit
   (`TestRegisterRootRoutes_EveryRouteDeniesWithoutCredential`).
3. **`/api/v1` route groups register in a fixed order**
   (`Router.RegisterRoutes`), and `/platform/service-registry` is mounted
   **last** so it observes every group's outcome.
4. **A group whose dependency is nil records itself unconfigured rather than
   disappearing.** `serviceRegistry.requireService` / `markUnconfigured` mount a
   503 stub and record the reason, so a dark surface is visible in the console
   instead of a bare 404. `/platform/service-registry` is deliberately exempt —
   it would otherwise be masked by its own stub.
5. **`isNonSPAPath` is checked before any SPA fallback**, on both the embedded
   and the filesystem path. It is `apiPathPrefixes` (`/api/`, `/v1/`, `/v2/`,
   `/.well-known/`) plus `staticAssetPathPrefixes` (`/_next/`, `/static/`).
6. **`isAPIPath` decides 404 shape**: an `apiPathPrefixes` path gets JSON,
   everything else gets `http.NotFound`.
7. **The placeholder walk goes deepest-segment-first** and stops at the first
   `__placeholder__/index` that exists. Its client-side counterpart is
   `resolveDynamicId`, which trusts `useParams()` unless the value is missing or
   equals `__placeholder__`.
8. **Rewrite rules are first-match-wins and then stop.** An invalid
   `regexp` pattern is logged and skipped, never fatal. On the embedded path
   the pattern is matched against `"/"+requestPath`; on the filesystem path
   against the cleaned path.
9. **Embedded serving wins whenever it is available.** `serveStaticFiles`
   checks `embed.IsEmbedded() && embed.WebFS != nil` first, so in a
   `platform_web` binary the configured `home` directory is **never read**.
   `IsEmbedded()` is false for a `platform_web` build whose `dist` holds only the
   tracked `.gitkeep` (a `go build -tags platform_web` that skipped
   `_web-embed-prepare`, #323), so such a binary serves from `home` like a
   `!platform_web` one rather than claiming a console it does not have.
10. **The plaintext port carries a redirect, or nothing (#535).** With
    `tls-port > 0` the listener on `port` answers every request with a
    permanent redirect to the same path and query on the TLS port
    (`301` for GET/HEAD, `308` otherwise) and mounts no route — no API, no
    console, so no credential is ever asked for in the clear. The Location
    host is the configured spelling from `servedHosts()` — the certificate
    subject and SANs, virtual hosts, WebAuthn id and origins, CORS origins,
    the bind host and loopback — never the request's `Host` header; an
    unknown host is answered `421 Misdirected Request`, so a forged `Host`
    cannot make the redirect an open redirect. A wildcard virtual host
    (`*.apps.example.com`) matches exactly one extra label and redirects to
    that label on the configured suffix. The plaintext listener is its own
    `http.Server` (`plainServer`) and `Shutdown` drains it alongside the TLS
    server. With no TLS
    port the plaintext listener is the only listener and is allowed to carry
    the router only when `bind-host` is loopback (`127/8`, `::1`,
    `localhost`); anything else is `ErrPlaintextExposure` at construction
    and the daemon does not start. `port: 0` opens no plaintext listener.
    HTTPS is conditional on `tls-port > 0`; both bind `bind-host`
    (`WebServerV1.listener`, #552).
11. **HTTP/3 shares the handler and the `tls.Config` with HTTPS** and binds the
    same port number over UDP.
12. **Virtual-host subrouters are registered before the global catch-all**, so
    a `Host()`-matched route wins.
13. **A virtual host with `proxy.backends` is a proxy and never serves files** —
    the two are mutually exclusive per host.
14. **`ensureDirectoryExists` runs before every virtual host is wired** and
    creates the directory plus a templated `index.html` when missing. A failure
    logs and `continue`s to the next virtual host rather than aborting startup.

## 4. Fail-closed and fail-fast paths

This server's posture is **fail-fast at startup, fail-open at request time for
presentation**:

| Situation | Behavior |
|---|---|
| `_ca == nil` at construction | `logger.FatalError` — process exits |
| Unknown `surface` value | `logger.FatalError(ErrUnknownSurface)` at construction |
| Plaintext-only listener off loopback | `logger.FatalError(ErrPlaintextExposure)` at construction |
| `edge` surface with no ACME server and no virtual hosts | `logger.FatalError(ErrEdgeSurfaceEmpty)` in `buildRoutes` |
| `provisioning` surface whose route cannot mount | `logger.FatalError(ErrProvisioningSurfaceEmpty)` in `buildRoutes` |
| TLS config or cert-reloader construction fails | `logger.FatalError` |
| `certificate.acme.cross-sign.directory` is not a parseable FQDN | `logger.FatalError` |
| HTTP or HTTPS listener cannot bind | `logger.Fatalf` |
| HTTP/3 UDP listener cannot bind | `logger.Fatalf` |
| Embedded `dist/` unusable | `panic` in `init()` |
| A service dependency is nil | 503 stub + registry entry, server starts |
| Virtual-host directory cannot be created | logged, that host skipped, server starts |
| Static file missing | placeholder fallback, then SPA index, then 404 |
| Rewrite pattern invalid | logged, rule skipped |

**Authentication itself fails closed**, but not here — it is the middleware's
contract ([`docs/iam/`](../iam/)), applied per route group. This server's own
code contains no authorization decision.

**The plain-HTTP listener is a redirect.** `port: 0` disables it; with a TLS
port it serves only the HTTP→HTTPS redirect; without one it must be loopback
(§3 item 10, #535). It is no longer a firewall question.

## 5. Error semantics

`pkg/webservice` declares two package-level sentinels, `ErrLoadTlsCerts` and
`ErrBindPort`, and `WrappedError{Msg, Err}` with `Unwrap`. In practice the
startup paths call `logger.Fatalf` / `logger.FatalError` directly rather than
returning these — they are available to callers, not load-bearing in `Run()`.

Request-time error shapes produced by this server (as distinct from the
services it hosts):

| Condition | Status | Body |
|---|---|---|
| Miss under `/api/`, `/v1/`, `/v2/` or `/.well-known/` | 404 | `{"error":"not found","path":"…","message":"the requested API endpoint does not exist"}` |
| Miss under `/_next/` or `/static/` | 404 | `http.NotFound` plain text |
| Miss elsewhere, no SPA index on disk | 404 | plain text |
| Embedded file stat failure | 500 | `Internal Server Error` plain text |
| Virtual-host proxy with no backends | 500 | `No backend servers configured` |
| Virtual-host proxy backend URL unparseable | 500 | `Invalid backend URL` |
| Virtual-host proxy backend unreachable | 502 | `Proxy error` |
| Service registry with no response writer | 500 | `registry: response writer not configured` |

Everything under `/api/v1` uses the `WebServiceResponse` envelope
(`sdk/go/wire/restwire`, written by `pkg/webservice/v1/response`); that
contract belongs to the services, not to this document.

## 6. Configuration

The schema is `pkg/webservice/v1.Config`. It is bound to **two** platform keys
(`pkg/app/app.go`):

| Platform key | Field | Note |
|---|---|---|
| `webservices` | `App.WebServices []*v1.Config` | The plural form. Multiple named servers |
| `webservice` | `App.WebServiceConfig *v1.Config` | Singular fallback; copied into `WebServices` when the plural list is empty |

`App.PrimaryWebService()` prefers the singular and falls back to
`WebServices[0]`.

| Key (per entry) | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | — | Identifies the entry |
| `home` | path | `public_html` | Static root. **Ignored entirely when the binary embeds the UI** |
| `index` | string | **empty** | Index filename. Every shipped config sets `index.html`; the built-in `DefaultConfig` does not |
| `bind-host` | string | **empty** (every interface) | Address the HTTP, HTTPS and HTTP/3 listeners bind (#552). An IP literal pins the address family (`tcp4`/`tcp6`, `udp4`/`udp6`); a hostname or empty leaves it to the resolver. Empty is deliberate: the webservice is the platform's intended external surface |
| `port` | int | `8080` | Plain HTTP: a redirect to `tls-port` when one is set, the router only on a loopback `bind-host` otherwise, `0` for none (#535); follows `bind-host` |
| `tls-port` | int | `8443` | `0` disables HTTPS and HTTP/3; follows `bind-host` |
| `certificate` | `common.Identity` | `www.example.com`, 365 days, SANs `www.example.com` / `localhost` / `localhost.localdomain` / `127.0.0.1` | Server identity |
| `certificate.acme.cross-sign.directory` | URL | — | Enables `TLSConfigWithXSigner`; must parse as an FQDN |
| `key` | `common.KeyConfig` | per profile | `DefaultConfigRSA`: RSA-2048, SHA-256, PSS, `StoreTPM2`, platform policy. `DefaultConfigECDSA`: P-256, SHA-256, `StoreTPM2`. `DefaultConfigEd25519`: Ed25519, **software store**. A YAML entry without `key` gets none, and startup refuses it with `app.ErrWebServiceKeyRequired` unless its certificate CN equals `tpm.idevid.cn` and the TPM IDevID is provisioned |
| `jwt.expiration` | int | `60` | **Minutes** (`time.Minute * Duration(Expiration)`) |
| `jwt.issuer` | string | — | |
| `jwt.platform-token.enabled` | bool | `false` | Broker platform-token validator |
| `jwt.platform-token.issuer` / `.jwks-url` | URL | — | Broker identity |
| `jwt.platform-token.audience` | string | `api://platform` | |
| `jwt.platform-token.allow-bearer` | bool | `false` | `false` ⇒ DPoP proof required |
| `jwt.platform-token.clock-skew-seconds` | int64 | `60` | DPoP `iat` tolerance |
| `jwt.platform-token.cache-ttl-seconds` | int64 | `3600` | JWKS cache |
| `jwt.platform-token.authz-mode` | `offline`\|`online`\|`hybrid` | `hybrid` | |
| `jwt.platform-token.introspection-url` | URL | — | Required for `online` / `hybrid` |
| `jwt.platform-token.introspection-client-id` / `-client-secret` / `-bearer-token` | string | — | RFC 7662 credentials |
| `jwt.platform-token.liveness-cache-ttl-seconds` | int | `15` | Hybrid positive cache |
| `webauthn.display-name` / `.id` / `.origins` | string / string / list | — | Relying-party parameters |
| `acme.enabled` / `.directory` / `.terms-of-service` / `.challenges` / `.external-account-required` | — | — | Per-webservice ACME server |
| `cors.allowed-origins` / `.allowed-methods` / `.allowed-headers` / `.allow-credentials` | lists / bool | — | Global CORS |
| `rewrite[].pattern` / `.target` | regexp / path | — | First match wins |
| `surface` | `full` \| `edge` \| `provisioning` | `full` | What the listener mounts (#571). `edge`: virtual hosts, ACME when an ACME server exists, the TLS redirect; nothing else; unknown Host is 421. `provisioning` (#177): `GET /api/v1/devices/config` and the TLS redirect; nothing else, and no other surface mounts that route. Startup (`webservice.ValidateProvisioningSurface`, wrapped in `app.ErrWebServiceValidation`) refuses it unless `bind-host` is an IP literal inside the provisioning zone of the node's network plan, `tls-port` is set and `virtual-hosts` is empty. Any other value refuses to start |
| `max-header-bytes` | int | Go default (1 MiB); `65536` on `edge` and `provisioning` | Request header cap on both listeners |
| `read-timeout` / `write-timeout` / `idle-timeout` | duration | `5s` / `30s` / `120s` | Per-listener `http.Server` timeouts |
| `max-connections` | int | unlimited; `4096` on `edge` and `provisioning` | Concurrent TCP connections per listener (`netutil.LimitListener`; HTTP/3 over UDP is not counted) |
| `rate-limit.requests-per-second` / `.burst` | float / int | none; `50` / `100` on `edge` and `provisioning` | Per-source token bucket (`pkg/security/ratelimit`, idle buckets evicted after 5 min); `0` disables |
| `virtual-hosts[].hosts` | list | — | `Host` names this virtual host owns: exact, or `*.suffix` matching exactly one extra label. Virtual hosts match before every path route (#571) |
| `virtual-hosts[].home` | path | — | Joined onto the top-level `home` |
| `virtual-hosts[].index` | string | falls back to top-level `index` | |
| `virtual-hosts[].certificate` / `.key` | — | — | Per-host identity |
| `virtual-hosts[].cors` | `CORSConfig` | — | Per-host CORS middleware |
| `virtual-hosts[].proxy.backends` | list | — | Turns the host into an **unauthenticated** reverse proxy |
| `virtual-hosts[].rewrite` | list | — | Per-host rewrite rules |

**There are no environment variables on the Go side of this feature.**
Configuration is the YAML file. The frontend's `getBaseUrl()` reads
`VERCEL_URL`, `NODE_ENV`, `HOSTNAME` and `PORT` on the server side of Next —
which never executes in a static export, so those are effectively dead. In the
browser it returns `window.location`'s origin, and `providers.tsx` uses the
fixed relative base `"/api"`.

**`index` has no built-in default.** `DefaultConfig` sets `Home`, `Port`,
`TLSPort`, `JWT.Expiration` and `Certificate`, and leaves `Index` empty. Set it
explicitly; every shipped configuration does.

## 7. Persistence

**None in this feature.** The server holds no state beyond its compiled router
and the certificate reloader. Static assets are read-only, from either the
embedded FS or disk.

The one thing it *writes*: `createDefaultIndexFile` renders
`defaultIndexTemplate` (`<h1>Welcome to {{.VirtualHost}}</h1>`) into a missing
virtual-host directory. It never overwrites an existing file.

Deployment layout the ISO installer produces:
`<install-dir>/public_html/` with `dir_perms` 755, `file_perms` 644, owned by
root. `<install-dir>` is `/var/lib/trusted-platform` in the shipped installer.

## 8. Build

### 8.1 Embedded (single artifact)

```bash
make build WITH_WEB=1
```

`WITH_WEB=1` adds the `platform_web` build tag (`Makefile:277`) and triggers
`_web-embed-prepare`, which runs `npm install && npm run build` in
`sdk/javascript` and then in `web/`, and copies `web/out/*` into
`pkg/webserver/embed/dist` (`WEB_EMBED_DIR`). **`WITH_WEB` defaults to `0`** —
the fallback path copies `public_html.tar.gz` into the ISO instead.

### 8.2 On disk

| Target | Does |
|---|---|
| `make web-build` | Builds the SDK, `npm run build` in `web/`, copies `web/out/*` to `public_html/`, tars `public_html.tar.gz` |
| `make build-public-html` | The devcontainer path: Swagger generation + Swagger UI vendoring + `npm ci`/`npm install` + `npm run build` + copy + tar |
| `make build-public-html-host` | The host equivalent, marked legacy in the Makefile |
| `make web-deps` | `npm ci` + `npm run build` in `sdk/javascript`, then `npm ci` in `web/` — the reproducible install CI uses; the SDK `dist/` must exist before `tsc` or it reports hundreds of missing-module errors (#396) |
| `make web-lint` | `npm run lint` (eslint only; typecheck split out in #396 so CI gates them independently) |
| `make web-typecheck` | `npm run typecheck` (`tsc --noEmit`) |
| `make web-build-check` | `npm run build` only — no copy into the tracked `public_html/` |
| `make web-test-unit` | `npm run test:unit` — vitest over `web/src/**/*.test.ts(x)` in jsdom; the unit runner beside Playwright, mirroring `sdk/javascript` |
| `make web-clean` | Removes `web/.next`, `web/out`, `web/node_modules`, `$(WEB_EMBED_DIR)/*` |

Variables: `WEB_SRC=web`, `WEB_PUBLIC_HTML=public_html`,
`WEB_EMBED_DIR=pkg/webserver/embed/dist`, `WEB_PACKAGE=trusted-platform-web`.

**The package manager is npm.** Every Makefile path uses `npm`.
**Correction:** the pre-migration `README.md`, `configuration.md`, `testing.md`
and `embedding.md` all show `yarn install` / `yarn dev` / `yarn build`.

### 8.3 Frontend scripts (`web/package.json`)

| Script | Command |
|---|---|
| `dev` | `next dev --webpack` |
| `dev:webpack` | `next dev --webpack` |
| `dev:turbopack` | `next dev --turbopack` |
| `build` | `next build --webpack` |
| `start` | `next start` — unused; there is no server runtime |
| `lint` | `eslint src` |
| `typecheck` | `tsc --noEmit` |
| `test:unit` | `vitest run` |
| `test` / `test:e2e` | `playwright test` |
| `test:e2e:ui` / `:headed` / `:debug` | `playwright test --ui` / `--headed` / `--debug` |

**Webpack, not Turbopack, is the default** for `dev` and `build`, because the
linked local SDK (`"trusted-platform-sdk": "file:../sdk/javascript"`) resolves
more reliably under it; `next.config.mjs` carries a webpack `resolve.alias` for
the SDK's subpath exports and `transpilePackages: ["trusted-platform-sdk"]`.
`playwright.config.ts` explicitly starts `npm run dev:webpack` for the same
reason. `vitest.config.ts` does the test-side equivalent: it inlines
`trusted-platform-sdk` and dedupes `react`/`react-dom`, because the linked SDK
carries its own dev copy of React and an externalized SDK hook (`useApi`)
otherwise fails with "Invalid hook call".

Console pages load server data through the SDK's `useApi`, never through a
local `useState` + `useEffect` pair. The account security page
(`account/security/page.tsx`) reads factors this way: `toApiResponse`
(`src/utils/auth-factors-api.ts`) adapts the factor client's result to the
SDK's `ApiResponse`, and local edits go through `useApi`'s `mutate` (#435).

Form schemas declare numeric fields as `z.number()`, never `z.coerce.number()`:
coercion makes the schema's input type `unknown`, which no longer matches the
form values and forces an `as any` on `zodResolver`. A number field binds to
`<Input type="number">` through `numberFieldProps(field)`
(`src/lib/number-field.ts`), which reads the input's `valueAsNumber` and turns
a blank into `undefined` (#451).

## 9. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Go unit | `pkg/webserver/embed/embed_test.go` | The build-tag switch (100% of statements per the coverage log) |
| Go unit | `pkg/webservice/*_test.go` | `types_test.go`, `util_test.go`, `loadbalancer_test.go`, `mtls_client_test.go`, `mtls_signer_test.go`, `placeholder_fallback_test.go` (the `__placeholder__` walk), `mock_ca_test.go` |
| Go unit | `pkg/webservice/v1/*_test.go` | `config_test.go`, `router_test.go`, `router_registry_test.go`, `registry_test.go`, `handler_registry_test.go`, `hooks_test.go`, `keycache_test.go` |
| Go unit | `pkg/webservice/v1/middleware/**` | CORS, mTLS, IAM auth/authz/session/JWT/platform-token, tenant context |
| Go unit | `pkg/webservice/v1/jwt/*_test.go` | Token issue, refresh, signing method, expiry |
| Frontend E2E | `web/e2e/*.spec.ts` (22 files) | `auth`, `webauthn-flow`, `dashboard`, `iam`, `tenant`, `tenant-isolation`, `tenant-management`, `invitations`, `ca`, `kms`, `devices`, `compute`, `networking`, `storage`, `platform`, `tpm-attestation`, `api-routes-regression`. Backend **mocked** — `e2e/fixtures/{api-mock,dashboard-api-mocks,webauthn-mock,auth-setup}.ts` |
| Frontend integration | `test/integration/web/*.spec.ts` (13 files) | The same surfaces against a **real** backend, driven by `web/playwright.integration.config.ts` |

**The two Playwright configurations differ in ways that matter:**

| | `playwright.config.ts` | `playwright.integration.config.ts` |
|---|---|---|
| `testDir` | `./e2e` | `../test/integration/web` |
| Backend | Mocked | Real (`make start-backend` in a devcontainer) |
| Projects | chromium locally; five browsers in CI | **chromium only** — the WebAuthn virtual authenticator needs CDP |
| Workers | `1` always | 1 in CI, 2 locally |
| `ignoreHTTPSErrors` | not set | `true` — the backend uses a platform-issued certificate |
| Web server | `npm run dev:webpack` | `npm run dev`, skipped when `FRONTEND_URL` is remote or `NO_WEB_SERVER=1` |
| Reporter | github (CI) / html | github/line + **json to `web/playwright.log`** + html |

`web/Makefile` drives both: `test-e2e*` for the mocked suite,
`test-integration*` for the real one, plus per-file shortcuts (`test-auth`,
`test-dashboard`, `test-iam`, `test-tenant`, `test-ca-kms`, `test-devices`,
`test-compute`, `test-api`) and `test-webauthn` with a `FRONTEND_URL` override.

**Correction:** the pre-migration `configuration.md` reproduces a
`playwright.config.ts` with `workers: process.env.CI ? 1 : undefined`,
`timeout: 30000`, `expect.timeout: 5000` and five unconditional browser
projects. The real file uses `workers: 1`, `timeout: 60000`,
`expect.timeout: 10000`, `navigationTimeout: 60000`, and gates the extra
browsers on `CI`.

**Known defect:** `web/Makefile`'s `help` target advertises
`make dev-standalone` and the `.PHONY` line declares it, but **no such rule
exists**. Running it fails.

## 10. Observability

Server logs, through `pkg/logging`:

| Level | Event |
|---|---|
| Info | `Serving web frontend from embedded filesystem` / `... from filesystem` (with `rootDir`) |
| Info | `Listening for incoming HTTP (HTTP/1.1, HTTP/2) connections` (tcp) |
| Info | `Listening for incoming HTTPS (HTTP/1.1, HTTP/2) connections` (tcp) |
| Info | `Listening for incoming HTTP/3 connections` (udp) |
| Info | `Virtual host %s configured as reverse proxy` / `... mapped to directory %s with index %s` |
| Info | `Created default index file` |
| Info | `Proxy REST routes registered` |
| Warn | `Non-SPA resource not found` / `... (embedded)` |
| Warn | `File not found`, `Embedded file not found`, `Index file already exists` |
| Warn | `Platform router is nil - /platform routes not registered ...` |
| Debug | `Incoming request` / `... (embedded)` — remote address, method, path |
| Debug | `Serving static file`, `Serving directory index file`, `Serving embedded file`, `Rewrite applied`, `Fallback to SPA index file`, `Serving Next dynamic-route placeholder` |
| Error | `invalid rewrite pattern`, `failed to stat embedded file`, `Proxy error: …` |

**Per-request Debug logging includes the full path** — enable `debug` only
where that is acceptable.

`debugRoutes()` (behind the `debug` flag) walks the router and logs each
route's path template, path regexp, query templates and methods.

**There are no metrics and no audit records in this feature.** The wiring
snapshot (`GET /api/v1/platform/service-registry`) is the introspection surface;
it is unauthenticated deliberately, so the console's Services tab can show dark
surfaces without a token, and because it reports wire state only, never
configuration values. The route inventory (`GET /endpoints`) was removed in
#551; `debugRoutes()` logs it under the `debug` flag.

## 11. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/iam/`](../iam/) — WebAuthn, users, the middleware this server applies
- [`docs/registry/`](../registry/) — the `/v2` surface mounted at the root
- [`docs/daemon/api.md`](../daemon/api.md) — where the other five transports live
- [`docs/proxy/`](../proxy/) — the authenticating reverse proxy, not this one

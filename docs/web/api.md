# Web Console and Web Server — API

> **Status: NORMATIVE** · Scope: routes owned by `pkg/webservice` itself, on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written explicitly, never omitted.

---

## 1. Scope of this file

**This documents what the web server *is*, not what it *serves*.**

`WebServerV1` mounts the whole `/api/v1` REST surface — roughly 25 route groups
belonging to CA, KMS, IAM, device, attestation, compute, SDN, DNS, tenant,
registry and the rest. Those routes belong to **their own** feature folders,
and this file does not repeat them. It covers the handful of capabilities the
web server owns itself: asset delivery, the route inventory, the wiring
snapshot, and the browser sign-in path.

For the transport model, the QUIC frame and opcode vocabulary, and the
platform-wide authorization picture, see
[`docs/daemon/api.md`](../daemon/api.md). This server **is** that document's
REST transport.

## 2. The six transports, and why five of them are empty here

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`.

**Every capability in this feature is HTTP-shaped and REST-only.** There is no
`WebService` in `ServiceRegistry` (`sdk/go/transport/embedded/adapter.go`'s 22
fields do not include one), no `.proto` for it, no QUIC opcode range, and no
`web_*` MCP tool. Grepped 2026-08-18.

Two different markers appear in the tables below, and the difference is
deliberate:

- **`n/a — HTTP-only by design`** — serving an HTML file over gRPC is not a
  capability anybody wants; the absence is the architecture, not a debt. These
  rows are recorded so the next reader does not go looking.
- **`MISSING — docs/13 G7`** — a capability that a non-browser client could
  reasonably need and cannot reach. Tracked debt with an owner.

## 3. Asset delivery

Served by the catch-all handler; there is no method restriction beyond what
`http.ServeFile` / `http.ServeFileFS` / `http.ServeContent` impose.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Serve the console shell | `GET /` → `index` | n/a — HTTP-only by design | n/a | n/a | n/a |
| Serve a static asset | `GET /<path>` | n/a — HTTP-only by design | n/a | n/a | n/a |
| Serve a directory index | `GET /<dir>/` → `<dir>/<index>` | n/a — HTTP-only by design | n/a | n/a | n/a |
| SPA fallback | any unmatched non-excluded path → `index` | n/a — HTTP-only by design | n/a | n/a | n/a |
| Next dynamic-route fallback | unmatched path → nearest `…/__placeholder__/<index>` | n/a — HTTP-only by design | n/a | n/a | n/a |
| Path rewrite | first matching `rewrite[]` rule rewrites the path | n/a — HTTP-only by design | n/a | n/a | n/a |
| Virtual-host static serving | `GET /<path>` with a matching `Host` | n/a — HTTP-only by design | n/a | n/a | n/a |
| Virtual-host reverse proxy | any method, matching `Host` with `proxy.backends` | n/a — HTTP-only by design | n/a | n/a | n/a |

**Ordering matters and is not configurable**: rewrite → exact file → directory
index → non-SPA exclusion → `__placeholder__` walk → SPA index → 404.

**The non-SPA exclusion list is `/api/`, `/_next/`, `/static/`.** A miss under
`/api/` returns a JSON 404; the other two return plain-text 404. Everything
else falls back to the SPA shell with **status 200** — a client that treats
"200 with HTML" as success will not notice a bad URL.

**The virtual-host reverse proxy is unauthenticated.** No auth chain, no zone
check, no attestation, no identity headers. The authenticating proxy is a
different feature ([`docs/proxy/`](../proxy/)).

`Alt-Svc: h3=":443"; ma=86400` is set on **every** response by
`addAltSvcHeader`, including plain-HTTP ones. The value is hard-coded and does
not follow `tls-port`.

## 4. Introspection

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Service wiring snapshot | `GET /api/v1/platform/service-registry` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | **none** |

**There is no route inventory route.** `GET /endpoints` used to walk the mux and
return every registered path template — gated paths included — to any caller
with no credential, an oracle that amplified every other exposure. It was
removed in #551. Operators who need the inventory run the daemon with the
`debug` flag, whose `debugRoutes()` logs it locally.

**`/api/v1/platform/service-registry`** returns
`{"services": [...], "total": N, "configured": M}` — one entry per service the
daemon knows about and whether its routes were wired. It is deliberately
unauthenticated: the console's Services tab must be able to show dark surfaces
without a token, and the endpoint reports **wire state only, never
configuration values**. It is mounted last, after every route group, so it
observes all of them; and it is exempt from the "unconfigured service gets a
503 stub" rule, because the stub would otherwise mask the endpoint that
reports the stubs.

Every dark surface answers the same body shape — `{code, error, success,
service, reason}` — where `reason` is the stable discriminator
`SERVICE_NOT_CONFIGURED` (`ReasonServiceNotConfigured` in
`pkg/webservice/v1/response/service_availability.go`). The console decides
"this node does not host the service" from **status 503 plus that
discriminator**; the `error` text is operator-facing prose and is not a
contract. The TypeScript SDK lifts `reason`/`service` into `ApiError.details`
and ships the predicate as `isServiceNotConfigured(err)`.

**Two producers, one contract.** A service the daemon never wired is caught by
the registry's catch-all stub above. A service whose *router* is registered but
whose *backend* is absent on this node — PXE and the local gateway service on a
control plane, where both run on the gateway role — never reaches that stub, so
its gRPC handler answers `codes.Unavailable` carrying a `google.rpc.ErrorInfo`
detail (`reason` `SERVICE_NOT_CONFIGURED`, domain `go-trusted-platform`,
metadata `service`). `protorest.WriteError` lifts that detail into the identical
REST body, so a client has one rule regardless of which producer answered — and
because the detail rides the gRPC status rather than a Go type, gRPC, QUIC and
MCP callers read the same discriminator.

The discriminator is deliberately **absent** from a 503 raised by a service this
node *does* host — "gateway is not running", a transient backend outage. Those
are operator-actionable failures on a node with the role, and the console must
keep surfacing them as errors rather than reporting the role away.

Both are candidates for the other transports — an operator on gRPC cannot ask
"which services are wired?" — hence `MISSING` rather than `n/a`.

## 5. Browser sign-in

REST base `/api/v1`. These are the routes the console itself calls; the
credential model and the user store are IAM's ([`docs/iam/`](../iam/)).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Issue a JWT from credentials | `POST /api/v1/login` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none (this *is* the auth) |
| Refresh a JWT | `GET /api/v1/login/refresh` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | JWT |
| Begin WebAuthn registration | `/api/v1/webauthn/registration/begin` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none |
| Finish WebAuthn registration | `/api/v1/webauthn/registration/finish` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none |
| Begin WebAuthn login | `/api/v1/webauthn/login/begin` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none |
| Finish WebAuthn login | `/api/v1/webauthn/login/finish` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none |
| WebAuthn registration status | `GET /api/v1/webauthn/registration/status` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | none |

**Only `registration/status` restricts its method.** The other four WebAuthn
routes are registered with a bare `HandleFunc` and therefore answer **any**
HTTP method; the handler is what enforces the ceremony's shape. Likewise
`/login` and `/login/refresh` carry no `.Methods(...)` restriction — the
Swagger annotations say `[post]` and `[get]` but the router does not enforce
it.

**`FIDO2Service` on gRPC is not this.** It covers local FIDO2 device
enumeration and ceremony-role binding, not the browser relying-party flow. A
headless client wanting to complete a WebAuthn ceremony against the platform
has only REST.

**The registration and login routes are unauthenticated by necessity** — they
are how you become authenticated. The rate-limiting and lockout story belongs
to IAM.

## 6. What the token buys

`POST /api/v1/login` returns a locally minted JWT whose lifetime is
`webservices[].jwt.expiration` **minutes** (default 60). The console writes it
into a `jwt` cookie with a **7-day** expiry, `Secure`, `SameSite=Strict`, and
**not** `HttpOnly` (page JavaScript sets it). The mismatch and its consequences
are in [architecture.md](architecture.md) §6.3.

When `jwt.platform-token.enabled` is true, protected routes are validated
against the **broker's** tokens instead — JWKS by `kid`, `iss`/`aud`/`exp`,
optional DPoP binding to `cnf.jkt`, `scp` → RBAC, `tenant_id` → row-level
security. Precedence for protected system routes is platform-token → WebAuthn
handler → legacy JWT. This is offline `scp` enforcement, not a local
authorization decision ([architecture.md](architecture.md) §6.2).

Per-route `scp` requirements are not this feature's to state: they belong to
each service's folder and to the platform-wide catalogs in
[`docs/daemon/api.md`](../daemon/api.md) §5.

## 6a. Surfaces

A webservice's route table depends on its `surface` (#571). `full` (default)
mounts everything in §7 plus the console. `edge` mounts only the virtual
hosts, `/api/v1/acme/**` when the node has an ACME server, and the
plaintext→TLS redirect; every other path is `404` on a served host and `421`
on an unknown host. `TestEdgeSurface_RouteSetIsAWhitelist` pins the edge
route set, so a route added to the platform later cannot appear on a public
listener without failing the build.

## 7. Mounted, not owned

| Surface | Where | Documented in |
|---|---|---|
| `/api/v1/...` — every platform service | `pkg/webservice/v1/router.go` and `rest/<service>/` | that service's feature folder |
| `/v2/...` — OCI distribution | mounted on the **root** router by `Router.RegisterRootRoutes`, only when `OCIDistBackend()` is non-nil, behind the caller gate and admin chain (#549) | [`docs/registry/`](../registry/) |
| `/swagger/...` | static files, present only when built by `make build-public-html` | [engineering.md](engineering.md) §8 |

`/v2` is at the host root because the distribution specification requires it —
under `/api/v1` a `docker pull` against the platform registry fails.

## 8. Status and error mapping

Errors this server produces itself (as opposed to the services it hosts):

| Condition | Status | Body |
|---|---|---|
| Miss under `/api/` | 404 | `{"error":"not found","path":"…","message":"the requested API endpoint does not exist"}` |
| Miss under `/_next/` or `/static/` | 404 | plain text |
| Miss elsewhere with no SPA index available | 404 | plain text |
| SPA fallback served | **200** | the shell `index` |
| Embedded file stat failure | 500 | `Internal Server Error` |
| Virtual-host proxy: no backends configured | 500 | `No backend servers configured` |
| Virtual-host proxy: backend URL unparseable | 500 | `Invalid backend URL` |
| Virtual-host proxy: backend unreachable | 502 | `Proxy error` |
| Service registry with no response writer | 500 | `registry: response writer not configured` |
| An unconfigured service's routes | 503 | the registry stub, with a reason |

`/api/v1` responses use the `WebServiceResponse` envelope
(`sdk/go/wire/restwire`), written by `pkg/webservice/v1/response`
(`Success200` and friends); that contract belongs to the services.

## 9. Pagination

**None.** The service-registry returns every service; the result set is
bounded by the daemon's own wiring and is small.

## 10. Versioning

REST under `/api/v1`; the Swagger annotations in `webserver_v1.go` declare
`@BasePath /api/v1` and schemes `http, https, ws, wss`. The OCI `/v2` routes
carry the **distribution specification's** version, not the platform's
([`docs/registry/api.md`](../registry/api.md)).

**Nothing in this feature is deprecated.** The one shape to be aware of is the
dual configuration key: `webservices:` (plural, a list) and `webservice:`
(singular, one entry) both parse, and the singular is copied into the plural
when the plural is empty ([engineering.md](engineering.md) §6).

## 11. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — the six transports and the
  authorization picture
- [`docs/iam/`](../iam/) — WebAuthn credentials, users, roles, the middleware
- [`docs/registry/api.md`](../registry/api.md) — the `/v2` surface
- [`docs/proxy/api.md`](../proxy/api.md) — the authenticating proxy's API

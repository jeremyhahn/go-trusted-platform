# Web Console — Using It

> **Status: REFERENCE** · Scope: `pkg/webserver/`, `pkg/webservice/`, `web/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Task-oriented, in the order you do things. Internals are in
> [engineering.md](engineering.md).

---

## What this is

The browser console for the platform, plus the HTTP server that delivers it.

The console is a static site — no server-side rendering, no Node runtime — that
talks to the platform's REST API from the browser. It is served by the platform
itself, on the same address and the same certificate as the API, so there is no
second service to deploy and no cross-origin setup to get right.

You get it one of two ways:

| | **Embedded** | **On disk** |
|---|---|---|
| Built with | `make build WITH_WEB=1` | `make web-build` or `make build-public-html` |
| Lives in | the platform binary | `<install-dir>/public_html` |
| Updating the UI | rebuild and redeploy the binary | copy files; no restart |
| Best for | air-gapped, immutable, single-artifact installs | development, and fixing a UI bug without a platform release |

**Embedded wins when both are present.** A binary built with the web tag never
reads the `home` directory.

---

## Prerequisites

1. **A `webservices:` (or `webservice:`) section** in the platform
   configuration. Without it, no web server starts.
2. **`index` set** — every shipped configuration uses `index.html`; the
   built-in default leaves it empty. Set it explicitly.
3. **`home` pointing at the asset directory**, if you are not using an embedded
   build. The installer places it at `<install-dir>/public_html`.
4. **`tls-port` set** if you want HTTPS and HTTP/3. `0` disables both.
5. **WebAuthn configured** — `webservices[].webauthn.id` (the relying-party ID,
   i.e. the domain) and `.origins`. Get these wrong and the browser refuses the
   ceremony with an opaque error.
6. **A CA-issued identity for the listener.** The certificate comes from the
   platform CA, not from files you supply.

Minimal shape:

```yaml
webservices:
  - name: console
    home: <install-dir>/public_html
    index: index.html
    port: 8080
    tls-port: 8443
    webauthn:
      display-name: Trusted Platform
      id: console.example.com
      origins:
        - https://console.example.com:8443
    jwt:
      expiration: 60        # minutes
      issuer: https://console.example.com
```

---

## First run

Start `platformd`. The log tells you what bound:

```
Listening for incoming HTTP (HTTP/1.1, HTTP/2) connections   tcp=:8080
Listening for incoming HTTPS (HTTP/1.1, HTTP/2) connections  tcp=:8443
Listening for incoming HTTP/3 connections                    udp=:8443
Serving web frontend from embedded filesystem
```

That last line is the one to read: `embedded filesystem` or
`Serving web frontend from filesystem` with the `rootDir` it chose. If it says
filesystem and the directory is wrong, you get a "Welcome to …" placeholder
page rather than the console.

Then open `https://console.example.com:8443/`.

**The plain HTTP port only redirects.** `http://console.example.com:8080/…`
answers with a permanent redirect to the TLS port and nothing else; set
`port: 0` to open no plaintext port at all. A webservice with a plaintext port
and no `tls-port` starts only when `bind-host` is a loopback address, so a
credential can never be asked for over the network in the clear (#535).
WebAuthn origins and CORS allowed-origins should list only `https://` origins —
a browser will not run a WebAuthn ceremony from an `http://` page anyway.

---

## Signing in

`/` redirects to `/auth/webauthn`. Enter a username and either register a
passkey or log in with one.

- **Registration** creates the credential and drops you at `/dashboard`.
- **Login** authenticates an existing passkey.
- **Invitations** arrive as `/auth/webauthn?invitation=<token>` and put the
  page straight into registration mode. `?tenant_name=` is displayed if present.
- **If a `jwt` cookie already exists**, the page skips straight to
  `/dashboard`.

Common messages and what they actually mean:

| You see | It means |
|---|---|
| "Account not found…" | 404 — no such username |
| "An account with this username already exists. Please log in instead." | 409 on register |
| "Please enter your passkey to log in." | 409 on login |
| "Too many attempts. Please wait a moment and try again." | 429 |
| "Something went wrong on our end." | 5xx |

Raw errors are never shown; the mapping is deliberate.

---

## What is in the console

The authenticated surface is one dashboard with a sidebar. Roughly seventy
pages across:

| Area | Covers |
|---|---|
| Dashboard | Overview |
| IAM | Users, groups, roles, permissions, policies, tokens, OAuth apps |
| Tenant | Workspace, members, quotas, invitations |
| CA | Certificates, requests, CRL, trust bundle |
| KMS | Keys, encrypt/decrypt |
| Devices | Device registry with each device's attestation verdict beside its age (fresh / stale / never collected), whether an attestation certificate is enrolled, and a "Refresh attestation" action that enqueues a collection; device detail with the full report (which check failed, cryptographic vs could-not-run, baseline source and age) and the address of the last heartbeat; profiles (with each profile's PCR baseline: source, age, registers, seeding device), templates, IDevID, vTPM |
| Attestation | Manifests, quotes, event logs, verification. Per-device verdicts live on the Devices pages (above) |
| TPM | Status, PCRs, quote, seal, NV RAM, keys, event log, lockout |
| Compute | VMs, containers, images, snapshots. On a node without the compute service (e.g. a control plane), the VM/container/snapshot pages show an informational "not available on this node" state; Images stays live (registry-backed) |
| Networking | SDN, zones, VLANs, DNS, IPAM, overlays, gateway, ports, flows, PXE. PXE and gatewayd run on the gateway role, so on a control plane the PXE and Gateway pages show an informational "not available on this node" state in place of the local-service cards, and the fleet telemetry from `/api/v1/gateway/state` (reporting gateways, their PXE status and boots served) stays the primary content |
| Storage | Objects, KV, time series, vector, backup |
| Provisioning | Sessions |
| Platform | Health, services, config, logs, events, metrics |
| Account | Security factors |

Dark and light themes follow the system setting by default.

**Some pages are stubs.** A few QuicBaaS-backed surfaces (storage objects, KV,
time series, vector, backups) are served by placeholder handlers that return
empty collections and echo back what you submit, so the page renders its empty
state instead of a 404 banner. They look like they work; the data is not
persisted anywhere. The **Platform → Services** page is the honest view — it
reports which service surfaces are actually wired.

---

## Updating the console

**On disk**, no restart needed:

```bash
make web-build
rsync -a public_html/ <user>@console.example.com:<install-dir>/public_html/
```

**Embedded**, a full redeploy:

```bash
make build WITH_WEB=1
# ship and restart the binary
```

**In an ISO**:

```bash
make web-build
platformctl iso create --config iso.yaml --webui ./public_html.tar.gz
```

If you leave `--webui` off, the builder looks for `public_html.tar.gz` then
`public_html/` in the working directory, and failing both runs
`make build-public-html` itself. If it still finds nothing it builds an ISO
**with no console** and only says so in the log.

---

## Developing on it

```bash
cd web
make dev        # backend in a container, frontend on the host at :3000
make status     # what is running
make stop-all   # tear it down
```

The frontend runs on `http://localhost:3000` and the backend on
`https://localhost:8443` inside the container.

```bash
make web-deps        # npm ci in sdk/javascript + web/, builds the SDK dist/ (once, from the repo root)
make web-lint        # eslint
make web-typecheck   # tsc --noEmit — needs the SDK dist/ from web-deps
```

Two test suites, and they are not interchangeable:

```bash
cd web
make test-e2e          # ./e2e — backend fully mocked, fast
make test-integration  # ../test/integration/web — real backend, chromium only
make test-webauthn FRONTEND_URL=https://console.example.com:8443
```

Integration runs are chromium-only because the WebAuthn virtual authenticator
needs Chrome DevTools Protocol, and they write a JSON result log to
`web/playwright.log` (`make test-log`, `make test-failures`).

Two things that catch people:

- **Use `npm`, not `yarn`.** Every Makefile path does.
- **`dev` and `build` use webpack, not Turbopack.** The linked local SDK
  resolves more reliably under it. `npm run dev:turbopack` exists if you want
  it.
- **`make dev-standalone` is advertised in `web/Makefile`'s help and does not
  exist.** It will fail.

---

## Troubleshooting

**A blank page at `/`.** The static export cannot use Next's server-side
`redirect()`, so `/` does a client-side replace to `/auth/webauthn`. If you get
a blank page instead of the login screen, the bundle is stale or partially
copied — rebuild and recopy.

**A "Welcome to …" page.** The server created a placeholder index because the
configured directory was missing. Check `home` (and `virtual-hosts[].home`) and
the `Serving web frontend from filesystem  rootDir=…` log line.

**Clicking a row in a table sends you back to the dashboard.** The
`__placeholder__` fallback did not find a candidate — usually a partially
copied bundle. Confirm the deployed tree still contains its `__placeholder__`
directories; the export needs them.

**API calls return HTML.** Something is serving the SPA shell for `/api/`
paths. That should be impossible — `/api/`, `/_next/` and `/static/` are
excluded from the SPA fallback and get a real 404 — so check whether an
intermediary in front of the platform is rewriting.

**A page shows "the requested API endpoint does not exist".** That is the
server's JSON 404 for an `/api/` path. The service is not wired: open
**Platform → Services** to see which surfaces are dark and why.

**Logged in, but everything returns 401.** The cookie lives for **7 days**; the
token lives for `jwt.expiration` **minutes** (default 60). The console only
checks that the JWT decodes, not that it is still valid, so an expired session
looks logged-in and answers 401. Sign out and back in. If this bites you often,
raise `jwt.expiration`.

**WebAuthn refuses to start.** `webauthn.id` must be the exact domain and
`webauthn.origins` must contain the exact origin including scheme and port. A
mismatch is rejected by the browser, not by the platform, and the message is
unhelpful.

**HTTP/3 is not being used.** `Alt-Svc: h3=":443"` is sent on every response
regardless of your actual `tls-port` — the value is hard-coded. On a
non-standard port, clients will not upgrade. Everything still works over
HTTP/1.1 and HTTP/2.

**A long-running request is cut off around 30 seconds.** The server's write
timeout is 30s and applies to every response on this listener.

**The UI changed and the browser did not.** Static assets are cached
aggressively by Next's content hashes; a hard reload usually settles it. If you
are on an embedded build, confirm you actually redeployed the binary — the
`home` directory is ignored there.

---

## Things worth knowing before you design around them

- **The JWT cookie is readable by JavaScript.** It cannot be `HttpOnly`,
  because the page sets it. The mitigation is that the origin serves only the
  platform's own bundle — do not host third-party scripts on it.
- **The console enforces nothing.** Hidden buttons are cosmetic; the API
  refuses what a role may not do.
- **`/api/v1/platform/service-registry` is unauthenticated** and reports wire
  state only.
- **Virtual hosts can reverse-proxy, and that proxy authenticates nothing.**
  When you need authentication in front of an application, use the trusted
  proxy in `gatewayd` ([`docs/proxy/`](../proxy/)), not this.

---

## Where to go next

- [cli.md](cli.md) — `platformctl iso create --webui` and the build targets
- [api.md](api.md) — what this server owns, on every transport
- [architecture.md](architecture.md) — the design and its scope fence
- [`docs/iam/`](../iam/) — users, roles and WebAuthn credentials
- [`docs/proxy/`](../proxy/) — the authenticating reverse proxy

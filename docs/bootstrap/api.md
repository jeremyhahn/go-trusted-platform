# Bootstrap — API

> **Status: NORMATIVE** · Scope: bootstrap, first-boot and pre-unseal barrier routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column throughout — any
RPC named below is available on both under the same name. The transport model,
the canonical QUIC opcode table, the status-byte vocabulary and the platform-wide
authorization picture live in [`docs/daemon/api.md`](../daemon/api.md); this file
does not repeat them.

**Bootstrap is the feature with the least API surface in the repository, and that
is deliberate for half of it and a gap for the other half.** Read §5 before
concluding anything is missing by accident.

Two surfaces in this feature are **not** among the six, and a client that needs
them cannot reach them through the SDK:

| Out-of-band surface | Where | Why it exists |
|---|---|---|
| The pre-unseal HTTP mux — `/healthz`, `/init`, `/unseal` | `pkg/api/rest/init_handlers.go`, bound on a bare `http.ServeMux` with no `/api/v1` prefix | It has to answer *before* the barrier is unsealed, when no other transport is bound |
| The Noise_NK bundle listener | `pkg/api/noise`, default `:9999` | It has to work when TLS cannot be verified at all |
| The bootstrap container's HTTP server — `/installs/…`, `/config/mac/…`, `/boot.ipxe`, `/health` | `pkg/ipxe/http_server.go`, `:8080` on the deployer host | It serves machines that have no identity yet; see [`docs/ipxe/architecture.md`](../ipxe/architecture.md) |

---

## 2. Trust bootstrap

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Fetch the CA bundle **unauthenticated**, for trust bootstrap | `GET /v1/ca/bootstrap` and `GET /api/v1/ca/bootstrap` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `bootstrap.CABundleAdapter.CABundle()` ¹ |
| Fetch the CA bundle (authenticated) | `GET /api/v1/ca/bundle` | `GetCABundle` | `OpCABundle` (`0xA8`) | `ca_bundle` | ✅ |
| Fetch the CA bundle over Noise_NK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — ² |
| Publish DANE TLSA records for a certificate | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `DANEPublisher.PublishForCertificate` ³ |
| Pre-publish a DANE-EE rollover record | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `DANEPublisher.PrePublishRollover` |
| Remove TLSA records for a host | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `DANEPublisher.RemoveForHostname` |
| Install a fetched bundle into the system trust store | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `trust.InstallToSystemTrust` ⁴ |
| Hot-swap the server's TLS certificate | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `CertReloader.Reload` ⁵ |

¹ An in-process Go call, but **not** an SDK route: `CABundleAdapter` is not a
field of `ServiceRegistry`, so `--transport embedded` does not reach it. It exists
to feed the Noise listener. The row is not `—` because the call is real.

² Noise is a protocol of its own on its own listener. Nothing about it is
reachable through the six.

³ Constructed in production and shared between the platform's own certificate
flow and the SDK-registered publisher adapter, so there is one DNS-write path.

⁴ Reached from the CLI (`bootstrap trust --install-to-system-trust`), not from a
service.

⁵ Constructed in production and wired into `tls.Config.GetCertificate`, but
**no production code calls `Reload`** ([engineering.md](engineering.md) §7.3).

### `GET /v1/ca/bootstrap` and `GET /api/v1/ca/bootstrap`

Unauthenticated by design — the caller has no trust anchor yet, which is the
whole point.

**Two paths, one handler.** `/v1/ca/bootstrap` is the *canonical* path: it is
the go-xkms trust fetcher's `DefaultBundlePath`, so it is what
`xkey trust import-platform <host:port>` and anything else built on that
fetcher requests. It is anchored at the host root because a client making
first contact has no way to discover this platform's API prefix. Registered by
`CARouter.RegisterCanonicalRoutes` on the root router (`webserver_v1.go`
`registerCanonicalRoutes`), alongside the OCI `/v2` surface.

`/api/v1/ca/bootstrap` is the platform-prefixed path, registered by
`CARouter.registerBootstrapRoutes` under `RegisterPublicRoutes`. It is what the
installer, the ISO test client and `platformctl bootstrap trust` use. Both
paths serve the identical bundle and the identical query parameters; neither
supersedes the other.

| Query parameter | Type | Default | Meaning |
|---|---|---|---|
| `store_type` | string | all | Filter by keystore |
| `algorithm` | string | all | Filter by key algorithm |

Response `200` with `Content-Type` of PEM and a body of concatenated PEM
certificates. Errors:

| Status | Cause |
|---|---|
| `400` | `algorithm` did not parse |
| `404` | `ErrBundleNotFound` — the bundle is empty |
| `500` | `ErrBootstrapBundleFailed` |
| `503` | `ErrCANotInitialized` — the CA is not up yet |

**Do not fetch this endpoint with certificate verification disabled.** The
endpoint being unauthenticated does not make the response unauthenticated: DANE,
SPKI and Noise are how the *bundle* is verified. `platformctl bootstrap trust`
does that for you.

### Unclaimed paths under an API namespace return 404, not the console

The web console is served by a catch-all that hydrates the SPA for any path it
does not recognise. It **declines** `/api/`, `/v1/`, `/v2/` and `/.well-known/`
(`webserver_v1.go` `apiPathPrefixes`): a path under one of those namespaces
that no route claims returns a JSON `404`, not `200 text/html`. Returning the
console shell to an API client turns a missing route into a parse error further
downstream that names neither the route nor the cause — which is how the
canonical bootstrap path presented before it was served: `trust/fetcher:
invalid PEM data`.

---

## 3. Barrier — the pre-unseal surface

Before the barrier is unsealed, the daemon binds **only** the three routes below.
No gRPC TCP, no business REST, no QUIC, no MCP.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Report platform state / readiness | `GET /healthz` ⁶ | `BarrierService.GetStatus` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `barrier.Manager.IsSealed` / `IsInitialized` / `SyncStatus` |
| Initialize the barrier (ceremony bootstrap) | `POST /init` ⁶ | `BarrierService.Init` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Manager.Initialize`, `Manager.InitializeShamir` |
| Submit a secret or share toward unseal | `POST /unseal` ⁶ | `BarrierService.Unseal` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Manager.Unseal`, `Manager.UnsealWithShare` |
| Seal, rekey, ceremony claim-cert / claim-share | see [`docs/cli/barrier.md`](../cli/barrier.md) | `BarrierService.Seal`, `.Rekey`; `CeremonyService` | `OpCeremonyCategory` (`0x9A`) | `MISSING — docs/13 G7` | `Manager.Seal`, `.Rekey`, `.CeremonyInitialize`, `.BeginClaimCert`, `.CompleteClaimCert`, `.BeginClaimShare`, `.CompleteClaimShare` |

⁶ On the **pre-unseal mux**, not under `/api/v1`. These three paths are bound by
`InitHandlers.Register` on a bare `http.ServeMux`.

**`OpTenantBarrierCategory` (`0x9E`) and the MCP tools
`platform_tenant_barrier_init` / `platform_tenant_barrier_unseal` are a different
capability**: they operate on *per-tenant* barriers, not on the platform barrier
that gates daemon startup. Do not reach for them expecting to unseal the
platform.

### Request and response schemas

`POST /init` accepts `so_pin`, `user_pin`, `barrier_strategy`, `shares`,
`threshold`, `hostname`, `sans`, `credential_seal_strategy` — all optional in the
JSON, with the effective requirements decided by the ceremony backend. It returns
`ceremony_id`, `state`, `initialized_at`, `spki_pin`, `admin_cert_pem`,
`admin_key_pem`.

**The `/init` response is the only time the admin key is available.** Capture it,
along with `spki_pin`, before doing anything else.

`POST /unseal` accepts exactly one of `secret` (software strategy) or `share`
(Shamir) and returns `state`, `shares_provided`, `required`, `sealed` — so a
multi-share workflow can iterate until `sealed` is false.

`GET /healthz` returns `state` and `ready`. `state` is one of `uninitialized`,
`sealed`, `unsealing`, `unsealed`; `ready` is true only for `unsealed`.

### Status mapping

| Status | When |
|---|---|
| `200` | Success, and always for `/healthz` |
| `405` | Wrong method |
| `409` | `ErrInitNotPermitted` (not `uninitialized`) or `ErrUnsealNotPermitted` (not `sealed`) |
| `503` | The init or unseal backend is not wired |

Request bodies are capped at 64 KiB by default (`InitHandlersConfig.MaxBodyBytes`).

---

## 4. Day-zero orchestration

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Discover node MACs and system info | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `bootstrap.DiscoverNodes`, `Orchestrator.Discover` |
| Validate config and plan a run (dry run) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Orchestrator.DryRun` |
| Run the full bootstrap | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Orchestrator.Run` |
| Deploy the bootstrap container | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `bootstrap.NewLinuxDeployerAdapter` → `Deployer.Deploy` |
| Tear down the bootstrap container | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Deployer.Teardown` |
| Fetch and cache the control-plane CA pool | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `Orchestrator.ControlPlaneCAPool`, paired with `Orchestrator.ControlPlaneTLSName` (the `ServerName` the pool verifies) and `Orchestrator.ControlPlaneAddresses` (where to dial) |
| First-boot seal | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `firstboot.Executor.Run`, `FirstbootSealStrategy.Unlock` |

**Not one day-zero capability is on any remote transport.** Unlike the gaps
elsewhere in the platform, most of this is a decision rather than an omission —
see §5 — but it is recorded as `MISSING` because the rule is that a gap is
written down, and because "the design says no" and "nobody has built it" look
identical from the outside once the rows are omitted.

---

## 5. Why there is no bootstrap service, and where the line is

The orchestrator holds BMC credentials, powers hardware on and off, mounts media,
and drives an SSH session to the host that serves every node's install. Exposing
that as a network service would make "provision the fleet" a remote call
authorised by whatever authorises the rest of the platform — including the
platform it is provisioning. It runs from an operator's CLI, against a file the
operator wrote, on a machine the operator controls.

That reasoning covers `run`, `deploy`, `teardown` and first boot. It does **not**
obviously cover `discover`, `DryRun` or `status`, which only read. A read-only
bootstrap query surface is a legitimate future capability and its absence today
is closer to an omission than a decision — which is exactly why the rows above
say `MISSING` rather than being left out.

---

## 6. Seeding and config delivery

The orchestrator is a *client* of these routes; the control plane serves them.
They are the only part of bootstrap that crosses a network boundary as an API.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Upload a device template (seeder shape) | `POST /api/v1/devices/templates` | `MISSING — docs/13 G7` ⁷ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ via the template service |
| Create a profile from a template (seeder shape) | `POST /api/v1/devices/templates/{id}/create-profile` → `201` envelope, `payload.id` string (below) | `DeviceService.CreateProfileFromTemplate` | `MISSING — docs/13 G7` ⁸ | `MISSING — docs/13 G7` | ✅ |
| Fetch a device's config by identity | `GET /api/v1/devices/config` | `DeviceService.FindConfigForDevice` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Enroll a node's BMC | `POST /api/v1/bmc/{profileID}/enroll` | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) |

⁷ Device-template CRUD was **removed** from `device.proto` — the comment in place
records that the `Template` RPCs collided with the vTPM messages of the same
name, were never generated, and were referenced by nothing. Template CRUD is
REST-only until someone defines it with `DeviceTemplate…` message prefixes.

⁸ `OpDeviceCreateProfile` (`0x38`) creates a profile directly; it is **not** the
create-from-template path. The MCP `profile_create` tool is likewise the direct
path.

### Request and response shapes

Template upload takes `{"role": <string>, "template": <object>}` and returns the
new template's `id` inside the standard `{code, success, payload}` envelope.
The template is sent as **JSON**, converted from the role YAML, because YAML
comments are not valid JSON. `role` is one of the node roles of
[`config-reference.md`](config-reference.md) — `control-plane`, `gateway`,
`worker` — and is stored verbatim as the template's `name` **and** `role`, so
`GET /api/v1/devices/templates` lists the three seeded roles by name. The
template id is `util.NewID(role)`, so re-seeding a role is idempotent. A role
outside the device vocabulary ([`docs/device/api.md`](../device/api.md) §4.2)
is a `400`; it is never stored as `unknown`. The seeder router is the only
owner of this method and path — the device CRUD handler creates templates on
singular `POST /api/v1/device/templates` (§4.1 there).

Profile creation takes `{"mac", "hostname", "role", "config", "ek_cert"}` where
`config` is the fully merged device configuration. The control plane stores
`config` on the profile **verbatim** (it is authoritative — the handler does
not merge it onto the template again, so keys the seeder replaced stay
replaced) and delivers it unchanged from `GET /api/v1/devices/config`. A
`config` that is not a JSON object (an explicit `null` included) is a `400`.
**`ek_cert` is refused with `400` on this route**: the route carries no caller
credential (see *Authorization — an open question* below), so accepting a
certificate here would let anyone reaching the port prestage hardware identity
for a hostname-derived profile id. EK binding stays on the authenticated
`POST /api/v1/device/profiles/{id}/assign`; a node whose bootstrap config sets
`ek_cert` fails seeding loudly rather than having the certificate dropped. The
call answers `201` with the created profile inside the standard envelope:

```json
{"code": 201, "success": true, "payload": {
  "id": "7416956686233238300", "name": "lab-node-2", "role": "control-plane",
  "match_rules": {"mac_prefix": "00:25:90:5e:02:aa"}, "assigned": false}}
```

`payload.id` is the deterministic profile id (`util.NewID(hostname)`, so
re-seeding the same host is idempotent) **as a JSON string** — a `uint64`
exceeds the precision of a double. The payload fields are the subset of the
`GET /api/v1/devices/profiles` item shape the seeder consumes; see
[`docs/device/api.md`](../device/api.md) §4. The seeder reads `payload.id` and
also accepts a bare `{"id": "<string>"}` body.
`TestSeederContract_*` in `pkg/bootstrap` drives the real seeder client through
the real handler so the two shapes cannot drift apart again.

### Authorization — an open question

The main device router is constructed with the mTLS middleware. The **seeder**
router registered alongside it is constructed without any middleware, no
router-wide authentication middleware is applied to `/api/v1` (only CORS, and
rate limiting on the ACME subtree), and the seeder's own HTTP client presents no
bearer token and no client certificate — it verifies the *server*, not itself.

The practical consequence is that template upload and profile creation appear to
be reachable on the control plane's HTTPS port without a credential. That is
plausible as a deliberate day-zero affordance — the seeder runs before any
credential exists — and it is also exactly the shape of an accidental gap. **It
is raised here as an owner question and is not decided by this document.** If it
is deliberate, it belongs in [architecture.md](architecture.md)'s trust
boundaries with the reasoning attached; if it is not, it is a defect.

The same question does not arise for `GET /api/v1/ca/bootstrap`, which is
unauthenticated by an explicit and documented decision, or for `/healthz`,
`/init` and `/unseal`, which are guarded by barrier state rather than by a
credential.

---

## 7. Status and error mapping

The canonical status-byte table is in
[`docs/daemon/api.md`](../daemon/api.md) §4. Bootstrap-specific mappings:

| REST | Feature cause |
|---|---|
| `400` | Unparseable `algorithm` on the bootstrap bundle |
| `404` | `ErrBundleNotFound` |
| `405` | Wrong method on the pre-unseal mux |
| `409` | `ErrInitNotPermitted`, `ErrUnsealNotPermitted` |
| `500` | `ErrBootstrapBundleFailed` |
| `503` | `ErrCANotInitialized`; unwired init or unseal backend |

The orchestrator maps *inbound* statuses rather than emitting them. Anything
outside 2xx from a seeding call becomes `ErrTemplateUploadFailed{StatusCode}` or
`ErrProfileCreateFailed{StatusCode}` and aborts the seed phase; anything outside
2xx from a BMC enrollment becomes `ErrBMCEnrollFailed` and is recorded without
aborting.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion` `0x01`.
The three pre-unseal paths (`/healthz`, `/init`, `/unseal`) are **deliberately
unversioned** — they are bound before the versioned surface exists and are the
one contract an orchestrator can rely on across releases. Nothing in this feature
is deprecated.

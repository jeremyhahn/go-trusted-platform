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

Three surfaces in this feature are **not** among the six. Only the pre-unseal
mux has an SDK client — `sdk/go/services/gate`, a separate package because it
speaks plain HTTP to a local endpoint rather than any of the six transports:

| Out-of-band surface | Where | Why it exists |
|---|---|---|
| The pre-unseal HTTP mux — `/healthz`, `/init`, `/unseal` | `pkg/api/rest/init_handlers.go`, bound on a bare `http.ServeMux` with no `/api/v1` prefix, on the Unix socket and `127.0.0.1:9446` only | It has to answer *before* the barrier is unsealed, when no other transport is bound ([`docs/daemon/api.md`](../daemon/api.md) §1) |
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

Before the barrier is unsealed, `platformd` binds only the barrier gate
(`/healthz`, `/init`, `/unseal`). The gate routes, their schemas and status
codes, and the platform barrier capability rows (init, status, unseal, seal,
rekey, recovery) are in [`docs/barrier/api.md`](../barrier/api.md). The
operator walk-through of first init and unseal is
[`docs/barrier/user.md`](../barrier/user.md#first-start-on-a-new-node).

What bootstrap adds on top is the officer ceremony:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Ceremony status, claim-cert, claim-share | `MISSING — docs/13 G7` | `CeremonyService` | `OpCeremonyCategory` (`0x9A`) | `platform_ceremony_*` ([`docs/cli/ceremony.md`](../cli/ceremony.md)) | `ServiceRegistry.Ceremony`; `Manager.CeremonyInitialize`, `.CeremonyStatus`, `.BeginClaimCert`, `.CompleteClaimCert`, `.BeginClaimShare`, `.CompleteClaimShare` |

**`OpTenantBarrierCategory` (`0x9E`) and the `platform_tenant_barrier_*` MCP
tools are a different capability**: they operate on per-tenant barriers, not on
the platform barrier that gates daemon start-up. Do not reach for them expecting
to unseal the platform.

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
| Fetch a device's config at boot (`?mac=` / `?serial=`) | `GET /api/v1/devices/config`, **provisioning listener only** (#177) | REST-only ⁹ | REST-only ⁹ | REST-only ⁹ | REST-only ⁹ |
| Enroll a node's BMC | `POST /api/v1/bmc/{profileID}/enroll` | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) | see [`docs/bmc/`](../bmc/) |

⁷ The seeder's `{"role", "template"}` upload has no equivalent on the other
transports. Storing a template in the CRUD shape does: `DeviceService.CreateTemplate`
on gRPC/Unix, QUIC sub-op `0x23` under `0xCF`, the MCP tool
`device_template_create` and embedded (#497) — see
[`docs/device/api.md`](../device/api.md) §4.

⁸ `OpDeviceCreateProfile` (`0x38`) creates a profile directly; it is **not** the
create-from-template path. The MCP `profile_create` tool is likewise the direct
path. Building a profile from a template in the CRUD shape (`overrides` only, no
seeder `mac`/`hostname`/`config`) is QUIC sub-op `0x24` under `0xCF` and the MCP
tool `profile_create_from_template` (#497).

⁹ The boot fetch is REST-only by design. Its caller is a machine still booting,
with no credential, so it is served only by a webservice with
`surface: provisioning` bound inside the provisioning zone. Every other listener
answers it with the unknown-route `404` (#177; see *Authorization* below).
`DeviceService.FindConfigForDevice` on gRPC, Unix, QUIC, MCP and embedded is a
different operation: the scope-gated `device:read` operator query, whose REST
equivalent is `GET /api/v1/device/profiles/find-config`
([`docs/device/api.md`](../device/api.md) §3).

### Request and response shapes

Template upload takes `{"role": <string>, "template": <object>}` and returns the
new template's `id` inside the standard `{code, success, payload}` envelope.
The template is sent as **JSON**, converted from the role YAML, because YAML
comments are not valid JSON. `role` is one of the node roles of
[`engineering.md`](engineering.md) — `control-plane`, `gateway`,
`worker` — and is stored verbatim as the template's `name` **and** `role`, so
`GET /api/v1/device/templates` lists the three seeded roles by name. The
template id is `util.NewID(role)`, so re-seeding a role is idempotent. A role
outside the device vocabulary ([`docs/device/api.md`](../device/api.md) §4.2)
is a `400`; it is never stored as `unknown`. The seeder router is the only
owner of this method and path — the device CRUD handler creates templates on
singular `POST /api/v1/device/templates` (§4.1 there).

Profile creation takes `{"mac", "hostname", "role", "config", "ek_cert"}` where
`config` is the fully merged device configuration. The control plane stores
`config` on the profile **verbatim** (it is authoritative — the handler does
not merge it onto the template again, so keys the seeder replaced stay
replaced) and delivers it unchanged from `GET /api/v1/devices/config` on the
provisioning listener. A
`config` that is not a JSON object (an explicit `null` included) is a `400`.
**`ek_cert` is refused with `400` on this route**: the route carries no caller
credential today (see *Authorization — pending an upstream capability*
below), so accepting a
certificate here would let anyone reaching the port prestage hardware identity
for a hostname-derived profile id. EK binding stays on the authenticated
`POST /api/v1/device/profiles/{id}/assign`; a node whose bootstrap config sets
`ek_cert` fails seeding loudly rather than having the certificate dropped. The
call answers `201` with the created profile inside the standard envelope:

```json
{"code": 201, "success": true, "payload": {
  "id": "7416956686233238300", "name": "node-02", "role": "control-plane",
  "match_rules": {"mac_prefix": "00:25:90:00:02:aa"}, "assigned": false}}
```

`payload.id` is the deterministic profile id (`util.NewID(hostname)`, so
re-seeding the same host is idempotent) **as a JSON string** — a `uint64`
exceeds the precision of a double. The payload fields are the subset of the
`GET /api/v1/device/profiles` item shape the seeder consumes; see
[`docs/device/api.md`](../device/api.md) §4. The seeder reads `payload.id` and
also accepts a bare `{"id": "<string>"}` body.
`TestSeederContract_*` in `pkg/bootstrap` drives the real seeder client through
the real handler so the two shapes cannot drift apart again.

### Authorization — pending an upstream capability

The main device router is constructed with the mTLS middleware. The **seeder**
router registered alongside it is constructed without any middleware, no
router-wide authentication middleware is applied to `/api/v1` (only CORS, and
rate limiting on the ACME subtree), and the seeder's own HTTP client presents no
bearer token and no client certificate — it verifies the *server*, not itself.

**The two POST routes are reachable without a credential on every running
platformd.** The chain is:

1. `pkg/app/app.go` constructs the profile and template services
   unconditionally, failing fatally if either cannot be built. So the
   `templateService != nil && profileService != nil` guard at
   `pkg/webservice/v1/router.go` that gates seeder-router registration is
   always satisfied in a running daemon — it is not a feature switch, and a
   test fixture that supplies neither service will not see these routes at
   all.
2. The seeder router registers directly on the `/api/v1` subrouter, while the
   main device router is constructed with `MTLSMiddleware()`.
3. `pkg/webservice/webserver_v1.go` mounts that `/api/v1` subrouter with only
   the CORS middleware. There is no router-wide authentication seam behind it.

Until #177, `GET /api/v1/devices/config` sat on the same subrouter and returned
any node's full merged configuration as YAML to an unauthenticated caller on
every listener. It no longer does (below). The write is the more serious
exposure: `POST /api/v1/devices/templates/{id}/create-profile` derives the
profile id as `util.NewID(hostname)` and saves over whatever is there, so an
unauthenticated caller who knows or guesses a hostname can **replace that node's
profile, including the `config` the control plane delivers to it on first
boot**.

The routes stay registered for the daemon's entire life, not only during
seeding, so they are a defect, not a day-zero affordance.

**The seeder authenticates as `admin@system` over mTLS, using the firstboot
admin bundle.** The parent record is issue #121; the two POST routes are #176
and `GET /api/v1/devices/config` is #177, which cannot take the same treatment:
its caller is a machine that is still booting and holds no credential, so
locking it to admin mTLS would break PXE provisioning.

**The config fetch (#177) is served only on the isolated provisioning VLAN.** Only a webservice with
`surface: provisioning` mounts it, and that listener mounts nothing else.
Startup refuses the listener unless its `bind-host` is an IP literal inside
the provisioning zone of the node's network plan
(`webservice.ValidateProvisioningSurface`). Every full and edge listener
answers the route with the unknown-route `404`. The route stays
unauthenticated by design, so the boundary is the address plus the
provisioning zone's flows: a candidate on that VLAN reaches it, and nothing
else does. Binding an address alone is not isolation, because Linux accepts a
packet for any local address on any interface. An EK-bound challenge, so that
only the machine a profile names can read its config, is the planned
follow-up ([`docs/provisioning/engineering.md`](../provisioning/engineering.md)).
The trust boundary is in [`docs/device/architecture.md`](../device/architecture.md)
§4.2.

The rest of this section concerns the two POST routes.

Admin mTLS on these routes is not implemented yet, and the obvious partial fix
is not it. `MTLSMiddleware()` already exists
and is already applied to the main device router constructed alongside the
seeder router, so wiring it here looks like a one-line change. It is not
sufficient: that middleware accepts **any** certificate chaining to the platform
trust roots, so applying it alone would move the exposure from *anyone who can
reach the port* to *any enrolled device* — a real reduction, and still not the
required outcome. Authorizing specifically `admin@system` needs an
identity-from-client-certificate lookup that the SDK does not yet expose,
tracked upstream as `go-quicbaas#376`.

Until then these routes are unauthenticated, and the compensating control is
network reachability of the control plane port during the seeding window.

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

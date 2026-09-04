# Device Identity, Profiles and Inventory — API

> **Status: NORMATIVE** · Scope: device, device-profile and device-template routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

The transport model, the QUIC frame format and category-opcode table, the
status-byte vocabulary and the two authorization catalogs are documented once
in [`docs/daemon/api.md`](../daemon/api.md). Only what is specific to devices
appears here.

- **Unix is gRPC over a Unix domain socket**, so gRPC and Unix share a column.
- **Embedded** is `ServiceRegistry.Device`
  (`sdk/go/transport/embedded/adapter.go:37`), dispatched by gRPC method string
  through `registerDeviceHandlers` (`sdk/go/transport/embedded/dispatch.go:336`).
- gRPC: `DeviceService`, **21 RPCs** (`pkg/api/grpc/proto/device.proto`).
- REST: `/api/v1/devices/*`, `/api/v1/device/*`
  (`pkg/webservice/v1/router/device.go`, `pkg/webservice/v1/rest/device/router.go`).
- QUIC: top-level opcodes **`0x30`–`0x3E`**, dispatched by
  `req.Opcode >= OpDeviceRegister && req.Opcode <= OpDeviceGetMetrics`
  (`pkg/api/daemon/quic_service.go:489`). No category indirection.
- MCP: two device tool families plus one profile family — see §6.
- Go SDK: `sdk/go/services/device` — `NewClient(transport.Adapter)` or
  `NewClientFromGRPC(platformv1.DeviceServiceClient)`.

**Four DeviceService RPCs have no embedded route.**
`CreateProfileFromTemplate`, `FindConfigForDevice`, `AssignProfileToDevice` and
`UnassignProfileFromDevice` are absent from `registerDeviceHandlers`
(grepped 2026-08-18), so `--transport embedded` cannot reach them even though
gRPC, Unix and REST can. They are marked in the tables below.

---

## 2. Devices

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create device | `POST /api/v1/devices` | `CreateDevice` | `OpDeviceRegister` (`0x30`) | `device_register` | ✅ |
| Get device | `GET /api/v1/devices/{id}` | `GetDevice` | `OpDeviceGet` (`0x32`) | `device_get` | ✅ |
| Update device | `PUT /api/v1/devices/{id}` | `UpdateDevice` | `OpDeviceUpdate` (`0x34`) | `device_update` | ✅ |
| Delete device | `DELETE /api/v1/devices/{id}` | `DeleteDevice` | `OpDeviceUnregister` (`0x31`) | `device_delete` | ✅ |
| List devices | `GET /api/v1/devices` | `ListDevices` | `OpDeviceList` (`0x33`) | `device_list` | ✅ |
| Count devices | `GET /api/v1/devices/count` | `CountDevices` | `OpDeviceList` (`0x33`) — total in the list reply's pagination | `MISSING — docs/13 G7` | ✅ |
| Find device by serial | `GET /api/v1/devices/serial/{serial}` | `FindDeviceBySerial` | `OpDeviceGet` (`0x32`) — union on `Serial` | `MISSING — docs/13 G7` | ✅ |
| Find device by hostname (IDevID CN) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `(*device.Service).FindByHostname` — no adapter route |
| Activate device (mTLS, serial from client cert) | `POST /api/v1/device/activate` | `ActivateDevice` | `OpDeviceActivate` (`0x3B`) | `MISSING — docs/13 G7` | ✅ |
| Activate device (JSON body) | `POST /api/v1/device/activate-json` | `ActivateDevice` | `OpDeviceActivate` (`0x3B`) | `MISSING — docs/13 G7` | ✅ |
| Device heartbeat (mTLS, identity from client cert) | `POST /api/v1/device/heartbeat` | machine-facing REST only — see note | machine-facing REST only | machine-facing REST only | in-process Go only: `(*device.Service).RecordHeartbeat` |
| Get device lifecycle state | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceGetState` (`0x3D`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Attest device | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceAttest` (`0x3A`) — **returns `StatusNotImplemented`** | `device_attest` | `MISSING — docs/13 G7` |
| Deactivate device | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceDeactivate` (`0x3C`) — **returns `StatusNotImplemented`** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Device metrics | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceGetMetrics` (`0x3E`) — **returns `StatusNotImplemented`** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Provision device with a profile | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `device_provision` | `MISSING — docs/13 G7` |

**Three QUIC opcodes are allocated, named and dispatched to an explicit
`StatusNotImplemented`**: `OpDeviceAttest`, `OpDeviceDeactivate` and
`OpDeviceGetMetrics`, each with `ErrDeviceOperationNotImplemented{Operation:…}`
(`pkg/api/daemon/quic_device_handlers.go:145-152`). A fourth,
`OpDeviceAttributes` (`0x6D`), is *also* routed by the device handler to
`StatusNotImplemented` — but the same opcode is separately handled by the
IDevID/TPM2 path in `pkg/api/daemon/quic_idevid.go:315`, where it does real
work. `0x6D` falls outside the `0x30`–`0x3E` device range, so the device
handler's case for it is unreachable from `quic_service.go` dispatch. Treat
`OpDeviceAttributes` as the IDevID feature's, not this one's.

**Two QUIC opcodes are multiplexed.** `OpDeviceGet` serves both `GetDevice`
(when `Id != 0`) and `FindDeviceBySerial` (otherwise), because *"both response
messages carry the device under the same Device field."* `OpDeviceList` serves
both `ListDevices` and `CountDevices` — *"the response pagination carries the
total device count so the SDK can derive CountDevicesResponse from the list
reply."*

**REST device ids are numerically constrained.** `/devices/{id:[0-9]+}` — a
non-numeric id 404s before reaching a handler. `/devices/count` and
`/devices/serial/{serial}` are registered before `/devices/{id}` so they are
not swallowed.

---

## 3. Device profiles

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create profile | `POST /api/v1/device/profiles`, `POST /api/v1/devices/profiles` | `CreateProfile` | `OpDeviceCreateProfile` (`0x38`) | `profile_create` | ✅ |
| Get profile | `GET /api/v1/device/profiles/{id}`, `GET /api/v1/devices/profiles/{id}` | `GetProfile` | `OpDeviceGetProfile` (`0x35`) | `profile_get_by_id` | ✅ |
| Update profile (full replace) | `PUT /api/v1/device/profiles/{id}`, `PUT /api/v1/devices/profiles/{id}` | `UpdateProfile` | `OpDeviceSetProfile` (`0x36`) | `profile_update_by_id` (partial merge) | ✅ |
| Delete profile | `DELETE /api/v1/device/profiles/{id}`, `DELETE /api/v1/devices/profiles/{id}` | `DeleteProfile` | `OpDeviceDeleteProfile` (`0x39`) | `profile_delete_by_id` | ✅ |
| List profiles | `GET /api/v1/device/profiles`, `GET /api/v1/devices/profiles` | `ListProfiles` | `OpDeviceListProfiles` (`0x37`) | `profile_list_all` | ✅ |
| Count profiles | `GET /api/v1/device/profiles/count` | `CountProfiles` | `OpDeviceListProfiles` (`0x37`) — total in the list reply | `MISSING — docs/13 G7` | ✅ |
| Find profile by MAC | `GET /api/v1/device/profiles/mac/{mac}` | `FindProfileByMACAddress` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find profile by serial | `GET /api/v1/device/profiles/serial/{serial}` | `FindProfileBySerial` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find matching profile | `POST /api/v1/device/profiles/match` | `FindMatchingProfile` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find config for a device (EK serial / MAC) | `GET /api/v1/device/profiles/find-config` | `FindConfigForDevice` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Assign profile to a device identity | `POST /api/v1/device/profiles/{id}/assign` | `AssignProfileToDevice` | `MISSING — docs/13 G7` | `profile_assign_to_device` | `MISSING — docs/13 G7` |
| Unassign profile | `POST /api/v1/device/profiles/{id}/unassign` | `UnassignProfileFromDevice` | `MISSING — docs/13 G7` | `profile_unassign_from_device` | `MISSING — docs/13 G7` |
| Get profile over mTLS (device self-service) | `GET /api/v1/device/profile` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

### 3.1 The singular / plural REST aliasing

`/api/v1/device/profiles` and `/api/v1/devices/profiles` dispatch to the **same
handlers**. The source states why: *"the dashboard hits
`/api/v1/devices/profiles` while the platform originally exposed singular
`/api/v1/device/profiles`. Both forms must dispatch to the same handler so REST
and SDK callers agree."* The same applies to `/device/templates` versus
`/devices/templates` for `GET`, and for `GET`/`PUT`/`DELETE` on `{id}` — but
**not** for `POST /devices/templates`, which is the bootstrap seeder's route
(§4.1); CRUD creation is singular only.

**The aliasing is not complete.** Only these exist on the plural form:
`POST` and `GET /devices/profiles`, and `GET`/`PUT`/`DELETE
/devices/profiles/{id}`. `count`, `match`, `serial/{serial}`, `mac/{mac}`,
`find-config`, `assign` and `unassign` are **singular-only**. Write new clients
against the singular form.

`GET /api/v1/devices/config` was listed beside `find-config` in the table above
until #265. **It has never been registered** — `grep -rn '"/devices/config"'`
over `pkg/` returns nothing — so it was a claimed route with no handler, in the
one document a client author would consult to find the right one. Removed.

The quoted justification for the aliasing is also worth reading with care: the
dashboard does **not** call `/api/v1/devices/profiles`. Every `/devices/...`
string under `web/src` is a single-page-app route — `app-sidebar.tsx:123-124`
`href:` entries and `${templateId}/edit` paths — not an API call. See #266.

### 3.2 `GET /api/v1/device/profile` is a different shape

The mTLS device-self-service route does **not** return a `DeviceProfile`. It
returns `ProfileResponse` (`pkg/webservice/v1/device/handler.go`):

```json
{
  "serialNumber": "SRV-2024-001",
  "trustedNetwork": { "vlan": 200, "useDHCP": false,
                      "staticIP": "203.0.113.50", "gateway": "203.0.113.1",
                      "dns": ["203.0.113.1"] },
  "acls":      [{ "name": "…", "priority": 100, "match": {}, "action": "allow" }],
  "rateLimit": { "ingressMbps": 100, "egressMbps": 100 }
}
```

The primary field is **`trustedNetwork`**, with an optional
**`provisioningNetwork`** sibling carrying the enrollment-phase network
(used server-side as the fail-closed revert target for the physical switch
move during activation). There is no snake_case `production_network`,
`provisioning_network` or `quarantine_network` in this response, and no such
fields exist on `entities.DeviceProfile` either. The legacy
`docs/device/network-setup.md` documents `production_network`; the code wins
and the correction is recorded here.

### Device heartbeat

`POST /api/v1/device/heartbeat` records the calling node's liveness. It
is a **machine-facing mTLS route** exactly like the gatewayd telemetry
ingest (`docs/gateway/api.md`): the device identity comes exclusively
from the verified client certificate (CN first, DNS SAN, then subject
serialNumber — the mTLS middleware's extraction chain), never from the
body, and the body is ignored entirely. The identity is matched against
the device serial first and the enrollment hostname (IDevID CN) second.
The response is raw JSON (no operator envelope):
`{"device_id":…,"serial":"…","received_at":"…"}`. Only
`last_heartbeat_at` and `updated_at` change — a heartbeat never moves
the lifecycle state machine.

Like the gateway control-plane routes, this deliberately has no
gRPC/QUIC/MCP variants: it is not an operator API; the reporting client
is platformd itself (`heartbeat:` config section, `pkg/app/heartbeat.go`)
using the node's TPM-backed IDevID identity — the same identity and
client (`pkg/provisioning`) that performs post-enrollment activation.

The section optionally takes `cert-file` / `key-file` (and `ca-file`) to
select a file-based mTLS identity instead, mirroring the gatewayd
control-plane reporter. This exists because a **restricted** IDevID
signing key cannot produce a TLS `CertificateVerify` signature — the TPM
ticket-hashes the digest before signing — so fleets whose IDevID keys
are restricted enroll a dedicated client certificate (CN = the device
serial) from the control plane CA. Server verification is anchored to
`ca-file` when set, else the platform CA store, else the OS trust store
(where the installer bakes the control-plane root); it is never skipped.

Device list/get responses carry `state`, `created_at`, `updated_at` and
`last_heartbeat_at`; the WebUI drives its Online/Offline/Unknown badge
off `last_heartbeat_at` freshness (five-minute threshold).

`POST /api/v1/device/activate` returns
`{"status":"activated","vlan":200,"transitionedAt":"…"}` (`ActivateResponse`).
Both routes take the device serial from the **verified mTLS client
certificate**, never from the request.

### 3.3 Partial versus full update

**`PUT /api/v1/devices/{id}` is a partial merge, and the merge happens in the
service, not the handler.** The handler builds its entity from the request
alone, so a field the caller omits arrives zero; `device.Service.Update` then
restores it from the stored record. Sending a partial device is the normal,
supported shape for a dashboard edit.

Two consequences worth knowing before writing a client:

- **Omitting a field does not clear it.** Server-owned fields — lifecycle state
  and the identity/enrollment set (`TenantID`, `EKCert`, `AttestPub`,
  `SigningPub`, `EventLog`, `HashAlgoId`, `Model`, `Serial`) — are restored, so
  a partial `PUT` cannot erase a device's TPM identity. Before #252 it could,
  silently.
- **`TenantID` cannot be set through this route at all.** `DeviceRequest` has
  no tenant field, so a device's tenant binding is not editable over REST; it
  is established at enrollment.

`UpdateProfile` (gRPC/REST/QUIC) is a **full replace**. `profile_update_by_id`
(MCP) is a **partial merge**: it fetches the profile and applies only the
supplied non-zero fields, with `assigned` and `assigned_at` as tri-state
pointers so "not sent" and "set to zero" are distinguishable. A client that
switches transports and keeps the same payload will get different semantics.

### 3.4 uint64 ids on the wire

MCP profile results emit `id` as a **decimal string**, not a JSON number —
`formatUint64ID` — because JSON numbers lose precision past 2^53. The CLI does
the same in `--output json`. Numbers are decoded with `json.Number` on the way
back so nothing round-trips through `float64`.

---

## 4. Device templates

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create template | `POST /api/v1/device/templates` (singular only — the plural `POST` is the seeder's, §4.1) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Get template | `GET /api/v1/device/templates/{id}`, `GET /api/v1/devices/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Update template | `PUT /api/v1/device/templates/{id}`, `PUT /api/v1/devices/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Delete template | `DELETE /api/v1/device/templates/{id}`, `DELETE /api/v1/devices/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| List templates | `GET /api/v1/device/templates`, `GET /api/v1/devices/templates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Find template by name | `GET /api/v1/device/templates/name/{name}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Create profile from template | `POST /api/v1/device/templates/{id}/create-profile`, `POST /api/v1/devices/templates/{id}/create-profile` → `201` envelope, `payload.id` string (§4.3) | `CreateProfileFromTemplate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

**Device templates are REST-only, and that is deliberate — with a stated
reason.** `device.proto` carries a comment where the RPCs used to be:

> *"Device-template CRUD lives on the REST surface only … The
> Create/Get/Update/Delete/List/FindByName Template RPCs that used to be
> declared here collided with vtpm.proto's identically-named messages, never
> got generated into device.pb.go, and were not referenced from any Go code.
> They have been removed; if a gRPC device-template service is needed in the
> future, define it with `DeviceTemplate…` message prefixes so the names cannot
> collide with vtpm."*

This is the one row set in this document where `MISSING` is a recorded design
decision rather than an untracked hole. The prefix requirement is binding on
whoever adds it back.

### 4.1 `POST /api/v1/devices/templates` belongs to the bootstrap seeder

Two routers register device-template routes on the same `mux.Router`:
`registerProfileCRUD` (`pkg/webservice/v1/router/device.go`) and the
bootstrap-seeder router (`pkg/webservice/v1/rest/device/router.go`). Until
#123 both registered `POST /devices/templates`; gorilla/mux matches in
registration order, the CRUD router is registered first, and so the seeder's
`{"role", "template"}` body was decoded as the CRUD envelope — seeded
templates listed as `name=""`, `role="unknown"` with no config (#114).

**Resolved by route ownership, not by inspecting the body.** The plural
`POST` is registered only by the seeder router →
`DeviceTemplateHandlers.HandleUploadTemplate`, whose contract is
[`docs/bootstrap/api.md`](../bootstrap/api.md) §6. The CRUD create
(`TemplateCRUDHandler.CreateTemplate`, flat or `{template: {...}}` envelope)
is singular `POST /api/v1/device/templates` only; the JS SDK's
`createTemplate` posts there. `GET /devices/templates` and the
`GET`/`PUT`/`DELETE /devices/templates/{id}` plural aliases remain CRUD
because they do not collide. One handler per route — a request is never
interpreted by guessing its shape; `pkg/webservice/v1/router/device_templates_test.go`
pins which handler answers the plural `POST`.

The seeder's other two routes do not collide: `GET /api/v1/devices/config` is
unique to it, and `POST /api/v1/devices/templates/{id}/create-profile` is not
registered by the CRUD alias block (which only aliases `GET`/`PUT`/`DELETE` on
`{id}`).

### 4.2 Role vocabulary

`role` on templates and profiles is `entities.DeviceRole`. The canonical values
are `control-plane`, `gateway`, `worker`, `server`, `client`, `workstation`,
`edge`, `iot`, `load-balancer` and `unknown`; `loadbalancer` is accepted as an
alias of `load-balancer`, and matching is case-insensitive. The first three are
the bootstrap configuration's node roles
([`docs/bootstrap/config-reference.md`](../bootstrap/config-reference.md)) and
round-trip verbatim. Every REST create/update path resolves the string through
`entities.ParseDeviceRole`: an omitted `role` is `unknown`; any other string
outside the vocabulary is a **`400`** carrying `device: unknown role "<value>"`
(`entities.ErrUnknownDeviceRole`) and nothing is stored. The platform.v1
`DeviceRole` enum carries every canonical value (`DEVICE_ROLE_CONTROL_PLANE =
9`, `DEVICE_ROLE_WORKER = 10` were added with #114), and
`pkg/api/grpc.EntityRoleToProto` / `ProtoRoleToEntity` is the one mapping the
gRPC and Unix services use, so a role written over REST reads back identically
over every transport. `platformctl device profile --role` accepts the same
list.

### 4.3 `create-profile` request and response (seeder shape)

`POST /api/v1/devices/templates/{id}/create-profile` takes
`{"mac", "hostname", "role", "config", "ek_cert", "overrides"}`. `overrides`
is deep-merged onto the template config; `config`, when present, is the
caller's fully merged configuration and is stored on the profile verbatim,
winning over the template-derived config (a non-object, including `null`, is
a `400`); `ek_cert` is **refused** with `400` because this route is
unauthenticated — EK binding belongs to the authenticated
`POST /api/v1/device/profiles/{id}/assign`. It answers `201` with the
created profile in the standard `{code, success, payload}` envelope. The
payload is the subset of the `GET /api/v1/devices/profiles` item shape the
seeder consumes — `id` (**JSON string**, deterministic from the hostname),
`name`, `role`, `mac_address`, `match_rules` and `assigned` — with identical
field names and encoding, so a client that lists profiles parses this payload
unchanged. An empty body is a contract violation: the bootstrap seeder reads
`payload.id` (`pkg/bootstrap`, `parseProfileIDFromResponse`), and
`TestSeederContract_*` pins the real handler to the real client. Request and
example response: [`docs/bootstrap/api.md`](../bootstrap/api.md) §6.

---

## 5. Adjacent routes on the same router

`pkg/webservice/v1/router/device.go` also registers the config-delivery
provisioning surface. **These belong to a different feature** and are listed
only so an operator reading firewall or proxy rules recognises them:

| Method | Path |
|---|---|
| POST | `/api/v1/provisioning/config` |
| GET | `/api/v1/provisioning/config/nonce` |
| POST | `/api/v1/provisioning/sign` |
| GET | `/api/v1/provisioning/sessions` |
| GET | `/api/v1/provisioning/sessions/{sessionID}` |
| GET | `/api/v1/provisioning/sessions/{sessionID}/poll` |
| POST | `/api/v1/provisioning/sessions/{sessionID}/fulfill` |

They are registered **without mTLS**, with the source comment *"These routes
are UNPROTECTED (no mTLS) since devices at boot have no client cert"* — they
authenticate at the application layer via EAB and EK binding instead.

---

## 6. The MCP surface is triplicated, and one third is dead

Three families of device-related MCP tools exist.

| Family | Registered by | Executor | In the authorization map |
|---|---|---|---|
| `device_register`, `device_get`, `device_list`, `device_delete`, `device_update`, `device_attest`, `device_provision` | `registerDeviceTools` (`tools.go:554`) | yes (`tools.go:1287`) | **yes** — `device:write` / `device:read` / `device:delete` |
| `device_create`, `device_get_by_id`, `device_get_by_serial`, `device_list_all`, `device_update_by_id`, `device_delete_by_id`, `device_get_status` | `registerDeviceToolsV2` (`device_tools.go:82`) | **no** | **no** |
| `profile_create`, `profile_get_by_id`, `profile_list_all`, `profile_update_by_id`, `profile_delete_by_id`, `profile_assign_to_device`, `profile_unassign_from_device` | `registerDeviceToolsV2` | yes (`deviceProfileToolDispatch`) | **yes** — all seven mapped to `device:*` |

Both registration functions run (`tools.go:63` and `:66`), so all 21 tool names
are advertised by `tools/list`.

**The seven V2 `device_*` tools have no executor.** `ExecuteTool` has no case
for them and no `default:` dispatcher claims them (grepped 2026-08-18), so a
call returns `unknown tool: device_create`. They are advertised and
non-functional. Use the older family.

This is the same duplicated-family pattern recorded for DNS
([`docs/dns/api.md`](../dns/api.md) §3) and vTPM
([`docs/vtpm/api.md`](../vtpm/api.md) §5), with one difference that works in
this feature's favour: here the **unmapped** family is also the **dead** one,
so `AuthorizeTool`'s default-allow behaviour for unlisted tools does not open a
live path. The seven `profile_*` tools are both live and scope-checked.

---

## 7. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form. Enforcement is per operation: gRPC
`RequireScope`, QUIC `AuthorizeRequest`, MCP `AuthorizeTool`. The catalogs and
their default-allow behaviour are described in
[`docs/daemon/api.md`](../daemon/api.md) §5.

**`DeviceService` is in the gRPC scope catalog, and its coverage is complete**
— all 21 RPCs are mapped in `pkg/api/grpc/method_permissions.go:147-167`,
resource `device`:

| Action | RPCs |
|---|---|
| `device:read` | `GetDevice`, `ListDevices`, `CountDevices`, `FindDeviceBySerial`, `GetProfile`, `ListProfiles`, `CountProfiles`, `FindMatchingProfile`, `FindProfileByMACAddress`, `FindProfileBySerial`, `FindConfigForDevice` |
| `device:write` | `CreateDevice`, `UpdateDevice`, `ActivateDevice`, `AssignProfileToDevice`, `UnassignProfileFromDevice`, `CreateProfile`, `CreateProfileFromTemplate`, `UpdateProfile` |
| `device:delete` | `DeleteDevice`, `DeleteProfile` |

`DeviceService` is one of only eleven services in that catalog. Device
templates, being REST-only, have no scope-catalog entry at all.

On MCP, 14 of the 21 device-related tool names carry a permission — see §6.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | Device cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Payload failed to decode (`ErrQUICDecodingFailed`) |
| `0x02` | `StatusNotFound` | 404 | Unknown device, profile or template; `ErrNoMatchingConfig`; `ErrProfileNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid; missing or unverified mTLS client certificate |
| `0x04` | `StatusInternalError` | 500 | Storage failure (`*WrappedError`); `ErrARPLookupFailed`; `ErrPortTransitionFailed`; switch VLAN transition failure |
| `0x06` | `StatusAlreadyExists` | 409 | **No device path produces this today.** `ErrDuplicateTemplateName` is declared in `pkg/device/errors.go` and never returned; no handler under `pkg/webservice/v1/device/` emits 409 (grepped 2026-08-18). Creating a second template with an existing name succeeds. |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `device:*` scope |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidDeviceID`, `ErrInvalidProfileID`, `ErrInvalidTemplateID`, `ErrDeviceIdentityRequired`, `ErrEKCertNotPEM`, `ErrEKCertInvalid`, `ErrInvalidTransition`, `ErrMissingSerial`, `ErrQUICMissingField{Field:"id"}`, `ErrProfileVLANsNotDistinct` |
| `0x0A` | `StatusUnavailable` | 503 | `ErrDeviceProfileServiceNotAvailable` — the profile service is not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | `ErrDeviceOperationNotImplemented` on `attest`, `deactivate`, `get_metrics` |

`ErrProfileVLANsNotDistinct` is mapped **by type** on every transport, with
`errors.As` so a wrapped instance maps identically: gRPC
(`pkg/api/grpc` `mapProfileError`, `pkg/api/daemon` `toGRPCError`), REST
(`pkg/api/rest` `DeviceHandlers.writeProfileError` and
`TemplateHandlers.writeProfileError`, `pkg/webservice/v1/device`
`handleServiceError` and `handleServiceErr`, `pkg/webservice/v1/rest/device`
`HandleCreateProfile`), and QUIC (`profileErrorResponse`). MCP returns the
typed error unchanged. Before #133 five of those eight reported it as a
server error — 500 / `codes.Internal` — and QUIC matched it only because the
message happens to contain the word "invalid". Do not add a profile error
mapping that classifies by substring.

**A 503 on a profile operation means the daemon has no profile service**, not
that the profile is missing. `handleDeviceActivate`, `handleDeviceGetProfile`
and `handleDeviceListProfiles` each check `h.profileService == nil` first.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB). A device profile carries
a full platform config; a very large config will hit that ceiling on QUIC
before it does on REST.

---

## 9. Pagination

`ListDevices` and `ListProfiles` take `common.ListOptions` with
`common.NewPagination(page, pageSize)`; the reply carries a `PageResult` whose
`TotalItems` is also how `CountDevices`/`CountProfiles` are satisfied over QUIC.
The CLI defaults are `--page 1 --page-size 20`; the MCP `profile_list_all`
default is `page 1, page_size 50`. Both result sets are unbounded in principle —
always paginate.

---

## 10. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. Nothing in the device surface is marked deprecated as of 2026-08-18.
The singular/plural REST duplication (§3.1) and the triplicated MCP families
(§6) are **not** a versioning scheme — they are drift, and the newer spelling
is not automatically the better one.

---

## 11. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/api.md`](../sdn/api.md) · [`docs/switch/api.md`](../switch/api.md)

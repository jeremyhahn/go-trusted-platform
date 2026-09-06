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

## 1a. How `id` is encoded, on the way out and the way in

Every `id` on the device REST surface is a `device.ID`
(`pkg/webservice/v1/device/id.go`). One type, two asymmetric rules:

| direction | encoding |
|---|---|
| **responses** | always a JSON **string** — `{"id":"9007199254740993"}` |
| **requests** | a JSON **string or a JSON number** — both accepted |

**Why responses are strings.** The platform mints ids above 2^53. A JSON number
at that magnitude loses precision in any JavaScript client: the console
truncates the value and can then no longer navigate to the record it just
listed.

**Why requests accept both.** Before this was a type, responses carried
`json:"id,string"` and requests a bare `uint64`, so a client that read an object
and wrote it back had no correct move above 2^53:

- echo the string it was given → **HTTP 400**, the body fails to unmarshal
  before any handler runs;
- convert it to a JavaScript number first → **precision is lost**, and the
  server accepts a *different* id without complaint.

The second is the worse of the two: an update applied to the wrong record, or a
404 nobody can explain.

The obvious repair — adding `,string` to the request types — does not work.
`encoding/json`'s `,string` accepts a quoted value and **rejects a bare number**
outright, so it would have broken every client sending numeric ids, which is all
of them. Accepting both encodings while emitting one widens the contract
instead: nothing that works today stops working, and a client that echoes what
it received starts working.

**Rejected inputs.** A value that is not an unsigned integer — text, a negative,
a float, an exponent — fails with `ErrInvalidID` and leaves the id at zero. It
does not round, and it does not land on a neighbouring record.

**Absent ids.** `null` and `""` both decode to zero, the same value an omitted
field leaves in place. On fields tagged `omitempty`, a zero id is still elided
from the output.

## 2. Devices

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create device (the server assigns the id — see below) | `POST /api/v1/devices` | `CreateDevice` | `OpDeviceRegister` (`0x30`) | `device_register` | ✅ |
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
| Attest device (verify submitted quote evidence) | `POST /api/v1/devices/{id}/attest` | `AttestDevice` | `OpDeviceAttest` (`0x3A`) | `device_attest` | ✅ |
| Deactivate device | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceDeactivate` (`0x3C`) — **returns `StatusNotImplemented`** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Device metrics | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceGetMetrics` (`0x3E`) — **returns `StatusNotImplemented`** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Provision device with a profile | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `device_provision` | `MISSING — docs/13 G7` |

**Create assigns the device id; a caller does not have to supply one.** Every
create verb in the table above reaches `DeviceService.Create`, which mints the
id through `device.NewID()` when the request carries none. A request that does
carry a non-zero id is honoured, so create behaves as an upsert on that path —
it does not assert the id is unused. Responses always carry the assigned id
(encoded per §1a), and the device is readable under it immediately.

Until #525 the create verbs called `DeviceService.Save`, which requires a
non-zero id because it doubles as the update primitive, so a caller creating a
device — who by definition has no id — was refused with `InvalidArgument:
invalid device ID` on every transport. Fleet enrollment was never affected: it
goes through `device.Register`, which assigns the id before saving.

**The device carries two attestation-key fields, and only one is a trust
anchor.** `attest_pub` is the bare attestation public key from the TCG CSR.
`attest_cert` is the PEM IAK/AK certificate the platform CA issued for that key
at enrollment (#404); it is what the quote verifier chains and checks for
`tcg-cap-verifiedTPMRestricted` (§4.4). Both travel on every transport that
carries a device — REST (flat and `{device: {...}}` envelope), gRPC / Unix /
QUIC (`Device.attest_cert = 14`), the MCP `device_create` /
`device_update_by_id` schemas, `platformctl device get`, and the JS SDK `Device`
type — and both are server-owned on update (§3.3). Neither is validated on the
way in: a caller may register a device with any string in `attest_cert`, and
the device is then denied at attest time when that string does not chain.
Nothing is trusted because it was stored.

**Two QUIC opcodes are allocated, named and dispatched to an explicit
`StatusNotImplemented`**: `OpDeviceDeactivate` and `OpDeviceGetMetrics`, each
with `ErrDeviceOperationNotImplemented{Operation:…}`
(`pkg/api/daemon/quic_device_handlers.go`). A third,
`OpDeviceAttributes` (`0x6D`), is *also* routed by the device handler to
`StatusNotImplemented` — but the same opcode is separately handled by the
IDevID/TPM2 path in `pkg/api/daemon/quic_idevid.go:315`, where it does real
work. `0x6D` falls outside the `0x30`–`0x3E` device range, so the device
handler's case for it is unreachable from `quic_service.go` dispatch. Treat
`OpDeviceAttributes` as the IDevID feature's, not this one's.

`OpDeviceAttest` was a third until #226. It answered `StatusNotImplemented`
on the live dispatcher while a `handleAttest` sat in
`pkg/api/quic/device_handlers.go` — a package whose `NewDeviceHandler` has no
non-test caller (#291). So the operation read as implemented in one package
and was a stub in the one actually served, which is the failure mode
CLAUDE.md names when it says a "wire this up later" stub on a multi-protocol
service is a bug rather than a transitional state. It now delegates to the
shared `DeviceService` gRPC implementation like every other device opcode.

### 2.1 The two transports that verified nothing

That `pkg/api/quic` handler was not merely unreached — it was **not a
verifier**. Its `verifyTPMAttestation` logged the nonce, quote and signature
lengths and returned `true`, under a comment listing the six checks it did
not perform. The same function, verbatim, sat in
`pkg/api/rest/device_handlers.go`, and that copy was **live**: the daemon
mounts those handlers on its own REST listener
(`daemon.go` → `RESTServer.SetDeviceHandlers`), so
`POST /api/v1/devices/{id}/attest` answered `200 {"attested": true,
"message": "device attestation verified"}` for any body carrying a non-empty
nonce, quote and signature, and moved the device to `attested` (#403).

Both now bind their transport and delegate to the in-process `DeviceService`
implementation, which owns the one `DeviceQuoteVerifier` (§4.4). Neither
package contains verification logic any more. Two structural consequences,
both deliberate:

- **REST registers the attest route only when the verifier is wired**, and
  QUIC answers `StatusUnavailable` without one. An unverified attest route
  must not exist; an absent capability must not look like a broken one.
- **No transport mutates device state on the way through.** The REST and
  QUIC copies used to set `DeviceStateAttested` themselves, which is how an
  unverified quote marked a device attested. The verdict belongs to the
  verifier.

`pkg/api/daemon/device_attest_transport_parity_test.go` pins the property
the single verifier exists for: the same evidence answers identically on
gRPC, REST and QUIC, including a quote signed by a key the device never
enrolled.

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

### 2.2 `POST /api/v1/devices` has two handlers, and they take different bodies

Two packages register a handler for this method and path. Which one answers
depends on which server is listening, and their request contracts are not the
same. Read this before assuming what a body does.

| Server | Handler | Body it accepts |
|---|---|---|
| Webservice (`baseURI` `/api/v1`, `pkg/webservice/webserver_v1.go:203`) | `device.CRUDHandler.CreateDevice` (`pkg/webservice/v1/device/rest_handlers.go:91`) | `DeviceRequest` — flat fields **and** the nested `{device: {…}}` envelope, plus UI-only keys |
| Daemon REST (`pkg/api/daemon/rest_service.go:365`) | `restapi.DeviceHandlers.handleRegisterDevice` (`pkg/api/rest/device_handlers.go:538`) | `DeviceRegisterRequest` — **flat only**, no envelope, and an empty `serial` is a `400` |

**The console reaches the webservice handler.** Its SDK `baseUrl` is `/api`
(`web/src/app/providers.tsx:27`), same-origin with the server that serves the
console, and `DeviceService` appends `/v1/devices`.

**The webservice handler accepts either shape, envelope wins.** `DeviceRequest`
carries the flat fields and a `device` object; `requestToDevice` starts from the
flat fields and overlays any non-zero field from the envelope. So the proto and
SDK shape (`CreateDeviceRequest { Device device = 1; }`, mirrored by the JS
SDK's `{device: Partial<Device>}`) and the flat REST shape both work, and a
client sending both gets the envelope's values.

**It also accepts UI-only keys, and almost all of them go nowhere.** `name`,
`type`, `device_type`, `description`, `manufacturer`, `version`,
`tpm_manufacturer`, `tpm_version` and `tpm_firmware_version` decode into
`DeviceRequest`, but `entities.Device` has fields for none of them. Exactly one
has any effect: `manufacturer` becomes the `Model` when no `model` is supplied.

**`name` is deliberately not mapped to anything.** `requestToDevice` used to
reuse it as the **`Serial`** when no serial was supplied, at either nesting
level. The console's serial field is optional and its name is required, so the
ordinary registration wrote a display string into the serial number: a row that
can never match a TPM serial at enrollment, and that `RecordHeartbeat` cannot
resolve, because it matches the mTLS identity against `Serial` or `Hostname`
(`pkg/device/service.go:322`).

On `PUT` it was worse. `UpdateDevice` shares `requestToDevice` and has no
synthesis fallback, and the service layer preserves an existing serial only when
the incoming one is empty (`pkg/device/service.go:214`). The coercion made it
non-empty, so a `PUT` carrying just a name **overwrote a real TPM serial with
the display name** — the identity-erasure class of #252.

A name-only `POST` now falls through to the synthesis below, and a name-only
`PUT` leaves the serial empty so the service layer restores the existing one.
Pinned by `TestCreateDeviceDoesNotStoreTheNameAsTheSerial`,
`TestCreateDeviceDoesNotStoreTheFlatNameAsTheSerial` and
`TestUpdateDeviceDoesNotOverwriteASerialWithAName`.

**A device has no name.** The proto `Device` (`device.proto:82`) and
`entities.Device` have no name field, so no transport persists one. The
console's `web/src/types/device.ts` declares its own `Device` and
`RegisterDeviceInput` that *do* carry `name`, `type`, `description`, `tags` and
`tpmInfo`; those are console-local types describing no server state. Whether a
device should gain a first-class display name is open on #455.

**An empty body is accepted.** `CreateDevice` allocates an id when none is
given and falls back to a synthesised `dev-<id>` serial, so `{}` yields a `201`
and a saved device. The daemon REST handler rejects the same body with `400`.

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
| Assign profile to a device identity (explicit `ek_serial`/`mac_address`, or `device_id` of a registered device — the server derives the EK serial from its stored EK certificate, #463) | `POST /api/v1/device/profiles/{id}/assign` | `AssignProfileToDevice` | `OpProvisioningCategory` (`0xCF`) sub `0x20` — see §3.7 | `profile_assign_to_device` | `MISSING — docs/13 G7` |
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

The JavaScript SDK models this body as `DeviceSelfServiceProfile`
(`sdk/javascript/src/types/device-self-service.ts`, read via
`DeviceService.getDeviceProfile()`), a type deliberately separate from
`DeviceProfile`; `pkg/webservice/v1/device/self_service_wire_parity_test.go`
pins it to `ProfileResponse`'s tags field-for-field in both directions (#402).

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

Since #226 the record also carries **`last_heartbeat_addr`**: the transport
peer address (host:port) the most recent heartbeat arrived from, recorded from
the mTLS-verified connection and never from the body. The attestation
collector uses it as a dial candidate after the platform DNS record. Only an
IP literal is recorded; anything else leaves the previous value in place.
The live REST device response carries it read-only as `last_heartbeat_addr`
(the request contract has no such field), and the console's device detail
page shows it as "Last heartbeat from" (#428).

A device **profile** may set `tls-server-name` (`tls_server_name` in JSON and
on the pb `DeviceProfile`): the certificate name the collector verifies a node
of that profile against when it dials, for fleets whose node webservice
certificates carry a role name (the shipped templates issue
`compute.<domain>.internal` to every worker). Empty means the device's own
FQDN, and a device with no hostname on a profile with no name fails closed
(`device has no hostname and its profile sets no tls-server-name`). Since #448
the field is on every transport that carries a profile — live REST
`ProfileRequest`/`ProfileFullResponse`, the pb `DeviceProfile` (gRPC, Unix,
live QUIC), the dark REST/QUIC profile structs, and the MCP `profile_create`
/ `profile_update_by_id` tools — and the operator path is the CLI:

```bash
platformctl device profile update <profile-id> --tls-server-name compute.trusted-platform.internal
```

An update that omits the name keeps the stored one (§3.3), so a console edit
cannot silently disarm the collector.

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
  `AttestCert`, `SigningPub`, `EventLog`, `HashAlgoId`, `Model`, `Serial`) — are
  restored, so
  a partial `PUT` cannot erase a device's TPM identity. Before #252 it could,
  silently.
- **`TenantID` cannot be set through this route at all.** `DeviceRequest` has
  no tenant field, so a device's tenant binding is not editable over REST; it
  is established at enrollment.

`UpdateProfile` (gRPC/REST/QUIC) is a **full replace**, with two fields
`ProfileService.Update` restores from the stored record when the incoming
entity carries none: the read-only `pcr_baseline` (§3.6) and
`tls_server_name` (§3.2) — both are state the attestation collector depends
on, and neither can be erased by omission on any transport. Every other
field is replaced. `profile_update_by_id` (MCP), the dark REST/QUIC update
handlers and `platformctl device profile update` are **partial merges**: they
fetch the profile and apply only the supplied non-zero fields, with
`assigned` and `assigned_at` as tri-state pointers where the wire allows so
"not sent" and "set to zero" are distinguishable. A client that switches
transports and keeps the same payload will get different semantics.

### 3.4 uint64 ids on the wire

MCP profile results emit `id` as a **decimal string**, not a JSON number —
`formatUint64ID` — because JSON numbers lose precision past 2^53. The CLI does
the same in `--output json`. Numbers are decoded with `json.Number` on the way
back so nothing round-trips through `float64`.

### 3.5 Profile networks: one open-keyed map plus three selectors

`ProfileFullResponse` — every item of `GET /device/profiles`, the body of
`GET /device/profiles/{id}`, and the create/update replies — carries a
profile's networks as:

```json
{
  "networks": {
    "provisioning": { "vlan": 998, "dhcp": true },
    "trusted":      { "vlan": 200, "static_ip": "203.0.113.50" },
    "lab-dmz":      { "vlan": 42 }
  },
  "enrollment_network": "provisioning",
  "post_enrollment_network": "lab-dmz",
  "failure_network": "quarantine"
}
```

- **`networks` is open-keyed.** `provisioning`, `trusted` and `quarantine` are
  the keys the selectors fall back to when unset (`entities.Default*Network`),
  not an enumeration; `lab-dmz` above is as valid as any of them.
- **The three selectors are strings naming a key**, and each is `omitempty`.
  Absent on the wire means the default applies — it never means "no network".
  Resolve before reading (the JavaScript SDK's `networkPhaseSelectors`).
- **No `provisioning_network` / `production_network` / `quarantine_network`
  field exists on this surface** in either case convention. The console
  declared exactly those until #378, so it rendered every profile as having no
  networks and posted its static-IP override under a key the server discards
  with a `2xx`.
- **The template route honours the same override fields as the CRUD route.**
  `POST /device/templates/{id}/create-profile` takes `overrides` as a full
  `ProfileRequest` and maps it through the one mapper both routes share
  (`pkg/webservice/v1/device/profile_mapping.go`); its `201` — and the
  `find-config`, `assign` and `unassign` replies from the same handler — is the
  full shape above. The template merge (`pkg/device`
  `ToProfileWithConfigOverrides`) then applies `name`, `model`, `role`, `zone`,
  `networks` (per key, over the template's), the three selectors,
  `platformd_config`, `match_rules`, `ek_serial` and `mac_address`. It does
  **not** apply `ek_cert`, `config`, `event_log`, `assigned` or `assigned_at`
  from overrides: `config` is the template's, and EK binding belongs to
  `POST /device/profiles/{id}/assign`. Until #378 the template handler mapped
  only `name`/`model`/`role` and its `201` omitted networks, so a network
  override on that route was discarded with a `2xx`; the daemon-only REST stack
  (`pkg/api/rest/template_handlers.go`) still maps only those three, on a path
  shipped configurations do not reach.

---

### 3.6 The profile's PCR baseline is read-only

Every read of a profile returns `pcr_baseline` when one is recorded, and no
write accepts it. The baseline is written by the verifier on the first fully
verified quote or by a signed manifest, never by a caller — a caller-supplied
expected state is the defect #373 removed from the attest path, and it does
not come back through any profile route (#448):

- **Live REST** (`ProfileFullResponse`) and the **dark REST/QUIC** profile
  responses: `values` (hex digest per PCR, keyed by the register index as a
  string), `source` (`signed` | `tofu`), `recorded_at`, and
  `recorded_from_device_id` (live REST: a JSON string, §3.4; dark REST/QUIC:
  a number; present only for a TOFU baseline). None of the request structs
  has the field, so a body that names `pcr_baseline` reaches the entity with
  none.
- **gRPC / Unix / live QUIC** (`DeviceProfile.pcr_baseline`, message
  `PCRBaseline`: `map<uint32, bytes> values`, `source`,
  `google.protobuf.Timestamp recorded_at`, `uint64 recorded_from_device_id`):
  `GetProfile`/`ListProfiles` populate it; `CreateProfile`/`UpdateProfile`
  ignore it — the pb→entity conversions in `pkg/api/daemon` and
  `pkg/api/grpc` never map it, pinned by tests that fail if they do.
- **MCP**: the result of every `profile_*` tool is the domain JSON and so
  carries `pcr_baseline`; the `profile_create` / `profile_update_by_id`
  argument decode has no such field, so an argument naming it is dropped.
- **CLI**: `platformctl device profile create|update` print it (`PCR
  Baseline` in the table; a `pcr_baseline` object in `--output json`) and
  have no flag to set it.

The update route is otherwise a full replace, but the baseline is
server-owned: `ProfileService.Update` restores `PCRBaseline` (and
`Assigned` / `AssignedAt`, which only the assign/unassign flows may change,
and `tls_server_name`, §3.2) from the stored record when the incoming entity
carries none, the same way `device.Service.Update` restores a device's
enrollment material (§3.3). A `PUT` that edits a profile's name or networks
cannot erase the baseline the verifier captured (#446), and a pb
`UpdateProfile` that supplies a different baseline does not replace the
recorded one.

### 3.7 Profile assignment travels as a QUIC sub-opcode, not a top-level one

`AssignProfileToDevice` and `UnassignProfileFromDevice` are served on QUIC,
but not by an opcode of their own: the single-byte opcode space is fully
allocated, so both travel under `OpProvisioningCategory` (`0xCF`) with the
sub-opcode in `payload[0]` — `DeviceProfileSubAssign` (`0x20`) and
`DeviceProfileSubUnassign` (`0x21`), routed by
`handleDeviceProfileCategorySub` in `pkg/api/daemon/quic_device_handlers.go`.
The dispatcher reports "not mine" for any other sub-opcode so the request
falls through to the config-delivery handler, the same multiplexing precedent
the EAB sub-range uses.

`DeviceSubRecordAttestCert` (`0x22`) shares that same sub-range and the same
dispatcher; §2's attestation-certificate section records it. The device
integration suite's QUIC adapter reaches all three through the category
opcode rather than a top-level one.

The transport table above read `MISSING` for this row until #480, while
[`api-reference-quic.md`](api-reference-quic.md) had documented the sub-opcode
table all along — the two documents disagreed about the same capability. A
capability that is served but recorded as absent is the more expensive
direction of a stale doc: it stops anyone from calling a route that works, and
it made the device integration suite's assignment coverage look like an
accepted gap rather than an untested one.


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

### 4.4 Device attestation is the VERIFIER half only

`POST /api/v1/devices/{id}/attest` verifies TPM quote evidence **the caller
supplies**. It does not ask a device for a fresh quote: nothing in the
platform does that yet, and the collector that will is #226. Do not read this
route as "attest this device now" — it answers "does this evidence attest
this device".

**One verifier behind all five transports.** REST, gRPC, Unix, QUIC and MCP
all reach `DeviceQuoteVerifier` in `pkg/api/daemon`. REST delegates to the
in-process `DeviceService` gRPC implementation through the handler registry;
QUIC's `OpDeviceAttest` dispatches to the same `DeviceGRPCService`; MCP's
`device_attest` tool builds the verifier over the same services (until #373
it accepted caller-supplied `attest_pub` / `ek_cert` and **overwrote the
device's enrolled material** while reporting success — that path is gone).
Extracting the verifier to a service package is **#175**'s scope. A second
implementation per transport is how two protocols come to disagree about a
security verdict: until #403 the `pkg/api/rest` and `pkg/api/quic` device
handlers each carried a `verifyTPMAttestation` that returned `true` for any
input, and the REST one was mounted on the daemon's own listener. Both now
delegate here (§2.1).

**A failed verification is a `200` with a negative verdict, not an error.**
The caller asked whether the device attests; "no" is a successful answer.
Error statuses are reserved for requests that could not be evaluated at all —
unusable evidence, an unknown device, or a missing dependency.

Request body — `evidence` is the JSON-encoded `DeviceQuoteEvidence`
(base64 in JSON), identical on every transport so the wire contract does not
fork. `pcrs` are the values the device **read** for the quoted selection; the
verifier proves they hash to the digest the TPM signed and only then treats
them as evidence. The attester never supplies the expected state (#373):

```json
{"evidence": "<base64 of {\"quote\":…,\"signature\":…,\"nonce\":…,\"pcrs\":{\"0\":…,\"7\":…}}>"}
```

The checks, in order, and what each one means:

| check | passes when | fails as |
|---|---|---|
| `ak_certificate_verified` | the device's **enrolled `attest_cert`** chains to the platform CA and carries `tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3), the MUST of TCG DevID v1 r12 §8.2 | no certificate / no CA → *absence*; wrong CA or attribute missing → *cryptographic* |
| `signature_valid` | the certified key signed the quote | cryptographic |
| `nonce_valid` | the quote's `extraData` is the caller's nonce | cryptographic |
| `pcrs_valid` | the reported values hash to the signed digest **and** equal the PCR baseline on the device's profile | digest mismatch or baseline mismatch → cryptographic; no matching profile → absence |

A bare `attest_pub` is **not** a trust anchor: without the certificate the
Restricted attribute cannot be checked, so a device enrolled before
certificates were recorded is denied service (`verified:false`,
`ak_certificate_verified:false`) — never quarantined.

**Where `attest_cert` comes from (#404).** The go-xkms ACME finalize for a
TCG-CSR-IDEVID order issues the IAK certificate in the same call that issues
the IDevID (`SignTCGCSRIDevID`, profile `tcg-iak`) and hands it to every
order-finalize hook as `TCGData.IAKCertificateDER`. The platform's device
registration hook (`pkg/webservice/v1/registry.go`,
`NewDeviceRegistrationHook`) PEM-encodes that DER into `Device.AttestCert`
beside the hex `AttestPub`, on first enrollment and on re-enrollment; a
finalize that carries no IAK certificate leaves a previously recorded one in
place and never fabricates one. Whether the recorded certificate then passes
`ak_certificate_verified` depends on the CA that issued it: the `tcg-iak`
profile stamps `tcg-cap-verifiedTPMRestricted` from go-xkms v0.9.3-alpha; the
go-xkms the platform reaches through its current quicbaas pin (v0.7.7-alpha)
stamps residency and fixed only, so a device enrolled against that CA is
recorded correctly and still denied (cryptographic class, attribute missing)
until the pin moves. Recording and verifying are deliberately separate
facts.

**PCR baseline.** The expected state lives on the `DeviceProfile`
(`pcr_baseline`: `values`, `source`, `recorded_at`, `recorded_from_device_id`),
never in the request. A profile with no baseline captures one from the
**first fully verified quote** — trust on first use, `source: "tofu"`, logged as
a `pcr_baseline_captured` attestation event because every later device on that
profile is measured against it. A forged, replayed or digest-inconsistent quote
never seeds a baseline. A `signed` baseline (from a signed manifest) is compared
the same way; `pcr_baseline_source` and `pcr_baseline_recorded_at` in the
response tell the operator which kind and how old.

**Verdict classes.** Every result is handed to the attestation service as a
`verdict.DeviceVerdict` and logged (`device_quote_verified` /
`device_quote_rejected`). A **cryptographic** failure — bad signature, wrong
nonce, PCR mismatch, untrusted or unrestricted certificate — is evidence of a
compromised or impersonated device: it is denied service **and** reported to
the quarantine observers (SDN quarantine zone, #226 ruling). An **absence of
evidence** — no certificate, no CA, no profile — is denied service but never
quarantined: absence of evidence is not evidence of compromise.

Response reports each check separately, so a console can say **which** check
failed rather than only that one did:

```json
{"device_id": "42", "serial": "SN-42", "verified": false,
 "ak_certificate_verified": true,
 "signature_valid": false, "nonce_valid": true, "pcrs_valid": false,
 "pcr_baseline_source": "", "pcr_baseline_captured": false,
 "attestation_status": "failed", "message": "…", "attested_at": "…"}
```

**Gating.** The REST route is on the admin gate — it reads a device's
enrolled key and reports a security verdict about that machine, so it is
operator work, not machine-facing. It registers only when a
`DeviceServiceServer` is wired; when it is absent the route does not exist at
all rather than answering 503.

---

### 4.5 Recording the attestation certificate without re-enrolling (#473)

`POST /api/v1/devices/{id}/attest-cert/record` (admin gate) records — or
re-records — the device's attestation (IAK/AK) certificate on its platform
record. It exists for the device enrolled **before** the control plane
recorded certificates at enrollment (#447): such a device has
`attest_cert == ""`, and §4.4's verifier denies its quotes in the *absence*
class until a certificate is recorded.

**The verb fails closed, and there is no override.** The recorded certificate
is the trust anchor every later quote is verified against, so a candidate is
written only if it (a) parses, (b) chains to the platform CA, (c) carries
`tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3) and (d) certifies the
device's **enrolled attestation public key** (`att_pub`, the TPMT_PUBLIC
recorded at enrollment). (a)–(c) run through the very `VerifyAKCertificate`
the verifier uses, so the verb and the verifier agree by construction; (d)
exists because a certificate over any other key would fail every quote
signature and quarantine the device. A certificate that chains but lacks the
attribute — which is what the fleet's CA issued at enrollment before go-xkms
stamped `.3` — is refused, because recording it would move the device from
*absence* (denied) to *cryptographic failure* (quarantined) on its next
quote. Nothing is written on refusal.

Candidates, in order; the first to pass is recorded:

1. the certificate already on the record (re-verified; `changed: false`);
2. the platform CA's certificate store under the device's identity names —
   the IDevID CN (`hostname`), the TCG subject `<model>-<serial>`, and
   `iak-<model>-<serial>`;
3. **only with `{"reissue": true}`** — a certificate the CA issues over the
   enrolled attestation public key. This does not involve the device: the
   enrollment already proved the key TPM-resident, and the control plane
   re-checks the recorded public area (restricted, fixedTPM, fixedParent,
   sensitiveDataOrigin, sign, not decrypt) before asking the CA. Whether the
   CA stamps `.3` is the CA's profile; a re-issued certificate without it is
   refused like any other. The CA has still issued and stored it, so the
   recorder **revokes** the refused certificate by serial (RFC 5280 reason
   `superseded`) in the same call; a revocation failure is its own typed
   error (`ErrAttestCertReissuedRevokeFailed`, `INTERNAL`) that names the
   serial and subject to revoke by hand. The CA's profile cannot be probed
   first: the quicbaas SDK's CA surface exposes neither the profile
   registry nor a dry issuance, so the post-issue check is the gate — which
   is why re-issuance is opt-in.

A finding that shapes this: the CA does **not** hold the IAK certificate it
issued at enrollment. go-xkms's `SignTCGCSRIDevID` stores the IAK and the
IDevID under the same CN, and the IDevID overwrites the IAK (go-xkms#371).
Until that lands, candidate 2 finds an IDevID under the device CN — refused
by (d) — and re-issuance is the path for a pre-#447 device. The fix
(go-xkms PR #383) issues the IAK under `iak-<model>-<serial>` and adds an
`IAKCertificate(ctx, model, serial)` read. The recorder already consumes
that shape through the optional `device.IAKCertificateReader` interface,
tried first among the CA candidates when the CA handle implements it; once
the go-quicbaas re-export lands, the hookup is an alias swap with no
platform change. On this fleet today the CA handle does not implement it
and the CN lookups return not-found.

Request body is optional: `{"reissue": <bool>}`. The response mirrors
`RecordAttestationCertificateResponse` with proto field names:

```json
{"device_id":"42","serial":"SN0042","model":"SuperMicro X10","changed":true,
 "source":"reissued","source_detail":"iak-SuperMicro X10-SN0042","reissued":true,
 "subject":"CN=iak-SuperMicro X10-SN0042,O=…","certificate_serial":"…",
 "not_after":"9999-12-31T23:59:59Z","attest_cert":"-----BEGIN CERTIFICATE-----…"}
```

`source` is `device`, `ca` or `reissued`. A refusal is `FAILED_PRECONDITION`
on gRPC/Unix/MCP, QUIC status `0x01`, and `400` on REST, with a message that
names **every** candidate and why it was refused (`ca[lab-node-3]: … does not
carry tcg-cap-verifiedTPMRestricted`). `UNAVAILABLE` means no CA is
configured. Every attempt is audited as an attestation store event —
`device_attest_cert_recorded` or `device_attest_cert_refused` — and never
reaches the quarantine observers: recording is not a verdict; the collector's
next sweep (§4.4, [attestation/user.md](../attestation/user.md)) produces
that.

**One recorder behind all transports**, like the verifier: gRPC and Unix
serve `DeviceService.RecordAttestationCertificate`; QUIC multiplexes it as
sub-opcode `0x22` under `OpProvisioningCategory` (0xCF), the device
sub-range the profile-assignment verbs use; MCP's `device_record_attest_cert`
(`device:write`) and REST delegate to the same in-process gRPC service; the
Go SDK exposes `device.Client.RecordAttestationCertificate`; the CLI is
`platformctl device attest-cert record <id> [--reissue]`.

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
| `0x0B` | `StatusNotImplemented` | 501 | `ErrDeviceOperationNotImplemented` on `deactivate`, `get_metrics`, `attributes`. `attest` was on this list until #226 wired the live QUIC dispatcher to the shared verifier |

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

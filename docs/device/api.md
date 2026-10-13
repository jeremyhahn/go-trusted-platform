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
  through `registerDeviceHandlers` (`sdk/go/transport/embedded/dispatch.go:340`).
- gRPC: `DeviceService`, **28 RPCs** (`pkg/api/grpc/proto/device.proto`).
- REST: `/api/v1/devices/*`, `/api/v1/device/*`
  (`pkg/webservice/v1/router/device.go`, `pkg/webservice/v1/rest/device/router.go`).
- QUIC: top-level opcodes **`0x30`–`0x3E`**, dispatched by
  `req.Opcode >= OpDeviceRegister && req.Opcode <= OpDeviceGetMetrics`
  (`pkg/api/daemon/quic_service.go:489`). No category indirection.
- MCP: one device tool family, one profile family and two template tools —
  see §6.
- Go SDK: `sdk/go/services/device` — `NewClient(transport.Adapter)` or
  `NewClientFromGRPC(platformv1.DeviceServiceClient)`. Over REST the SDK sends
  every RPC to the exact route in §2, verb and id constraint included (#321).
  `ActivateDevice` targets the admin `/device/activate-json`, not the mTLS
  `/device/activate`. `TestDeviceServiceRoutes_MatchTheServerRouter`
  (`sdk/go/transport/rest`) and
  `TestSDKRouteClaims_DeviceServiceDispatchesToItsHandler`
  (`pkg/webservice/v1`) fail on any drift. The body it sends and the reply it
  decodes are the handlers' own shapes, not the gRPC messages — see §1b.

**Every DeviceService RPC has an embedded route** (#250), except the two
channel-bound diskless boot RPCs (§4.6), which need a TLS connection the
embedded transport does not have. The embedded
transport hands the call to the same `DeviceServiceServer` gRPC and Unix
serve, so a server-side refusal (including its own `Unimplemented`) reaches
the caller unchanged. `TestDispatch_DeviceAttestationAndProfileAssignment`
(`sdk/go/transport/embedded`) drives the attestation, template and
profile-assignment RPCs through the generated client over the embedded conn.

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

## 1b. REST wire shapes the SDK translates

The REST handlers do not speak the gRPC messages. They decode their own request
types (`pkg/webservice/v1/device/types.go`) and answer through the webservice
response writer, so every body arrives in the envelope
`{"code", "success", "payload"}` with the resource **bare** in `payload` and its
`id` a string (§1a). The Go SDK's REST transport translates in both directions
(`sdk/go/transport/rest/device.go`, mappings in
`sdk/go/wire/restwire/device_profile.go`). `TestDeviceSDKREST_*`
(`pkg/webservice/v1/router/device_sdk_rest_test.go`) drives the profile writes,
the template create and device register and read through the real router and
handlers.

| RPC | request body sent | reply decoded |
|---|---|---|
| `CreateProfile`, `UpdateProfile` | the profile **flat** — the `ProfileRequest` fields at the top level, never `{"profile": {...}}` | bare `ProfileFullResponse` → `reply.profile` |
| `CreateProfileFromTemplate` | `{"overrides": {...}}`, the overrides as a flat `ProfileRequest`; `{}` when there are none | bare `ProfileFullResponse` → `reply.profile` |
| `CreateDevice`, `GetDevice`, `UpdateDevice`, `FindDeviceBySerial` | unchanged | bare `DeviceResponse` → `reply.device` |
| the other single-profile RPCs (find, match, assign, config) | unchanged | bare `ProfileFullResponse` → `reply.profile` |
| `ListDevices`, `ListProfiles` | unchanged | `pagination.total` → `pagination.total_items` |
| `ActivateDevice` | unchanged | `status` → `activation_status` |

Field mapping on profiles, both directions:

- `role` and a network's `auth_method` are the handler's strings
  (`load-balancer`, `802.1x`), not the proto enum names;
- `config` is inline JSON, not base64 — a non-JSON `config` is refused before
  the request is sent (`ErrProfileConfigNotJSON`);
- the digests in a reply's `pcr_baseline.values` are hex, not base64
  (`ErrPCRDigestNotHex` on a bad one);
- a zero `assigned_at` in a reply (`0001-01-01T00:00:00Z`) is dropped rather
  than decoded as a timestamp.

REST does not carry `tenant_id` or `bmc` on a profile, nor `pcr_baseline` on a
write, so those fields are lost on a round trip over REST and survive one over
gRPC, Unix, QUIC and embedded.

## 2. Devices

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create device (the server assigns the id — see below) | `POST /api/v1/devices` | `CreateDevice` | `OpDeviceRegister` (`0x30`) | `device_register` | ✅ |
| Get device | `GET /api/v1/devices/{id}` | `GetDevice` | `OpDeviceGet` (`0x32`) | `device_get` | ✅ |
| Update device | `PUT /api/v1/devices/{id}` | `UpdateDevice` | `OpDeviceUpdate` (`0x34`) | `device_update` | ✅ |
| Delete device | `DELETE /api/v1/devices/{id}` | `DeleteDevice` | `OpDeviceUnregister` (`0x31`) | `device_delete` | ✅ |
| List devices | `GET /api/v1/devices` | `ListDevices` | `OpDeviceList` (`0x33`) | `device_list` | ✅ |
| Count devices | `GET /api/v1/devices/count` | `CountDevices` | `OpDeviceList` (`0x33`) — total in the list reply's pagination | `MISSING — docs/13 G7` | ✅ |
| Find device by serial | `GET /api/v1/devices/serial/{serial}` | `FindDeviceBySerial` | `OpDeviceGet` (`0x32`) — union on `Serial` | `device_find_by_serial` | ✅ |
| Find device by hostname (IDevID CN) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `(*device.Service).FindByHostname` — no adapter route |
| Activate device (mTLS, serial from client cert) | `POST /api/v1/device/activate` | `ActivateDevice` | `OpDeviceActivate` (`0x3B`) | `MISSING — docs/13 G7` | ✅ |
| Activate device (JSON body) | `POST /api/v1/device/activate-json` | `ActivateDevice` | `OpDeviceActivate` (`0x3B`) | `MISSING — docs/13 G7` | ✅ |
| Device heartbeat (mTLS, identity from client cert) | `POST /api/v1/device/heartbeat` | machine-facing REST only — see note | machine-facing REST only | machine-facing REST only | in-process Go only: `(*device.Service).RecordHeartbeat` |
| Get device lifecycle state | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDeviceGetState` (`0x3D`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Attest device (verify submitted quote evidence) | `POST /api/v1/devices/{id}/attest` | `AttestDevice` | `OpDeviceAttest` (`0x3A`) | `device_attest` | ✅ |
| Disable device (block its port, record `suspended`) | `POST /api/v1/devices/{id}/disable` | `DisableDevice` | `OpProvisioningCategory` (`0xCF`) sub `DeviceSubDisable` (`0x25`) | `device_disable` | ✅ |
| Enable device (re-admit to quarantine, request re-attestation) | `POST /api/v1/devices/{id}/enable` | `EnableDevice` | `OpProvisioningCategory` (`0xCF`) sub `DeviceSubEnable` (`0x26`) | `device_enable` | ✅ |
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
QUIC (`Device.attest_cert = 14`), the MCP `device_register` schema and every
MCP device result, `platformctl device get`, and the JS SDK `Device`
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
| Create profile | `POST /api/v1/device/profiles` | `CreateProfile` | `OpDeviceCreateProfile` (`0x38`) | `profile_create` | ✅ |
| Get profile | `GET /api/v1/device/profiles/{id}` | `GetProfile` | `OpDeviceGetProfile` (`0x35`) | `profile_get_by_id` | ✅ |
| Update profile (full replace) | `PUT /api/v1/device/profiles/{id}` | `UpdateProfile` | `OpDeviceSetProfile` (`0x36`) | `profile_update_by_id` (partial merge) | ✅ |
| Delete profile | `DELETE /api/v1/device/profiles/{id}` | `DeleteProfile` | `OpDeviceDeleteProfile` (`0x39`) | `profile_delete_by_id` | ✅ |
| List profiles | `GET /api/v1/device/profiles` | `ListProfiles` | `OpDeviceListProfiles` (`0x37`) | `profile_list_all` | ✅ |
| Count profiles | `GET /api/v1/device/profiles/count` | `CountProfiles` | `OpDeviceListProfiles` (`0x37`) — total in the list reply | `MISSING — docs/13 G7` | ✅ |
| Find profile by MAC | `GET /api/v1/device/profiles/mac/{mac}` | `FindProfileByMACAddress` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find profile by serial | `GET /api/v1/device/profiles/serial/{serial}` | `FindProfileBySerial` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find matching profile | `POST /api/v1/device/profiles/match` | `FindMatchingProfile` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Find config for a device (EK serial / MAC) | `GET /api/v1/device/profiles/find-config` | `FindConfigForDevice` — no identity `InvalidArgument`, unknown identity `NotFound` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Assign profile to a device identity (explicit `ek_serial`/`mac_address`, or `device_id` of a registered device — the server derives the EK serial from its stored EK certificate, #463) | `POST /api/v1/device/profiles/{id}/assign` | `AssignProfileToDevice` | `OpProvisioningCategory` (`0xCF`) sub `0x20` — see §3.7 | `profile_assign_to_device` | ✅ |
| Unassign profile | `POST /api/v1/device/profiles/{id}/unassign` | `UnassignProfileFromDevice` | `MISSING — docs/13 G7` | `profile_unassign_from_device` | ✅ |
| Get profile over mTLS (device self-service) | `GET /api/v1/device/profile` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

### 3.1 One name per resource

Device **records** live under the plural `/api/v1/devices`. Their **profiles
and templates** live under the singular `/api/v1/device`. No path is served
under both (#266). Until #266 the router also answered a partial set of plural
aliases: `POST`/`GET /devices/profiles`, `GET`/`PUT`/`DELETE
/devices/profiles/{id}`, `GET /devices/templates` and `GET`/`PUT`/`DELETE
/devices/templates/{id}`. They stopped short of `count`, `match`,
`serial/{serial}`, `mac/{mac}`, `find-config`, `assign` and `unassign`, so a
client had to know which name each operation used. The aliases were deleted,
and the plural sub-resources were not renamed. A plural profile or template
request now gets `404`.

`TestDeviceRoutesHaveOneName` (`pkg/webservice/v1/device_route_names_test.go`)
walks the router platformd builds and fails if any path below one prefix is
also registered below the other. The bootstrap seeder's three plural routes are
the only exemption. They are `GET /devices/config`, `POST /devices/templates`
and `POST /devices/templates/{id}/create-profile` (§4.1, §4.3), and the
exemption is keyed by method and path, so a CRUD alias on one of those paths is
still caught.

The justification once quoted for the aliases did not hold: the dashboard
never called `/api/v1/devices/profiles`. Every `/devices/...` string under
`web/src` is a single-page-app route, such as the `app-sidebar.tsx` `href:`
entries and the `${templateId}/edit` paths, not an API call.

The JS SDK's `DeviceService` calls device records under `/v1/devices` and
profiles, templates and `activate-json` under `/v1/device` (#228). The route
table in `sdk/javascript/src/services/__tests__/device-service.test.ts` pins the
verb and the path of every method. Before #228 it called eight routes the server
has never registered: `devices/by-serial`, `devices/activate`,
`devices/profiles/by-mac`, `devices/profiles/by-serial`, the plural `match`,
`count` and `assign`, and `devices/templates/{id}/profiles` for create-from-template.

### 3.2 `GET /api/v1/device/profile` is a different shape

The mTLS device-self-service route does **not** return a `DeviceProfile`. It
returns `ProfileResponse` (`pkg/webservice/v1/device/handler.go`):

```json
{
  "serialNumber": "SRV-2024-001",
  "admittedNetwork": { "vlan": 200, "useDHCP": false,
                      "staticIP": "203.0.113.50", "gateway": "203.0.113.1",
                      "dns": ["203.0.113.1"] },
  "acls":      [{ "name": "…", "priority": 100, "match": {}, "action": "allow" }],
  "rateLimit": { "ingressMbps": 100, "egressMbps": 100 }
}
```

The primary field is **`admittedNetwork`**, with an optional
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
platformctl device profile update <profile-id> --tls-server-name compute.example.internal
```

An update that omits the name keeps the stored one (§3.3), so a console edit
cannot silently disarm the collector. Clearing it is a deliberate act (#462),
spelled per transport:

| Transport | Clear | Keep |
|-----------|-------|------|
| Live REST `PUT /device/profiles/{id}`, dark REST/QUIC update, MCP `profile_update_by_id` | `"tls_server_name": ""` | omit the field, or send `null` |
| pb `UpdateProfileRequest` (gRPC, Unix, live QUIC) | `clear_tls_server_name: true` | leave the flag unset; an empty `profile.tls_server_name` keeps the name, because proto3 cannot tell unset from empty |
| CLI | `platformctl device profile update <id> --clear-tls-server-name` | omit both flags |

A pb request that sets `clear_tls_server_name` together with a non-empty
`profile.tls_server_name` is `InvalidArgument`
(`device.ErrTLSServerNameClearConflict`), and the CLI rejects
`--clear-tls-server-name` with `--tls-server-name`. The service learns about
the clear through the `device.ClearTLSServerName` option on
`ProfileService.Update`; the entity alone cannot say it.

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
on, and neither can be erased by omission on any transport; only the explicit
clear in §3.2 blanks `tls_server_name`. Every other field is replaced. `profile_update_by_id` (MCP), the dark REST/QUIC update
handlers and `platformctl device profile update` are **partial merges**: they
fetch the profile and apply only the supplied non-zero fields, with
`assigned`, `assigned_at` and `tls_server_name` as tri-state pointers where
the wire allows so "not sent" and "set to zero" are distinguishable. A client that switches
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
    "admitted":     { "vlan": 406, "static_ip": "203.0.113.50" },
    "lab":          { "vlan": 409 }
  },
  "enrollment_network": "provisioning",
  "post_enrollment_network": "lab",
  "failure_network": "quarantine"
}
```

- **`networks` is open-keyed.** `provisioning`, `admitted` and `quarantine` are
  the keys the selectors fall back to when unset (`entities.Default*Network`),
  not an enumeration; `lab` above (an owner-defined zone) is as valid as any of
  them.
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
  full shape above. Like the CRUD route, it mints the profile `id` server-side
  when `overrides` names none. The template merge (`pkg/device`
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
and `tls_server_name` unless the update carries the explicit clear, §3.2)
from the stored record when the incoming entity carries none, the same way `device.Service.Update` restores a device's
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
dispatcher; §4.5 records it. So do `DeviceSubBootCertificate` (`0x23`) and
`DeviceSubBootDelivery` (`0x24`), the diskless boot requests of §4.6,
`DeviceSubDisable` (`0x25`) and `DeviceSubEnable` (`0x26`), the operator
lifecycle transitions of §4.7, and `DeviceSubTemplateCreate` (`0x27`) and
`DeviceSubProfileFromTemplate` (`0x28`), which carry `CreateTemplate` and
`CreateProfileFromTemplate` (§4). The device integration suite's QUIC adapter
reaches the profile, attestation-certificate, lifecycle and template
sub-opcodes through the category opcode rather than a top-level one.

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
| Create template | `POST /api/v1/device/templates` (the plural `POST` is the seeder's, §4.1) → `201` envelope, `payload.id` string | `CreateTemplate` | `OpProvisioningCategory` (`0xCF`) sub-op `DeviceSubTemplateCreate` (`0x27`) | `device_template_create` | ✅ |
| Get template | `GET /api/v1/device/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Update template | `PUT /api/v1/device/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Delete template | `DELETE /api/v1/device/templates/{id}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| List templates | `GET /api/v1/device/templates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Find template by name | `GET /api/v1/device/templates/name/{name}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Create profile from template | `POST /api/v1/device/templates/{id}/create-profile`; the seeder's own `POST /api/v1/devices/templates/{id}/create-profile` → `201` envelope, `payload.id` string (§4.3) | `CreateProfileFromTemplate` — unset override fields (an unspecified role included) keep the template's value; unknown template `NotFound`, a daemon without a template or profile service `Unavailable` | `OpProvisioningCategory` (`0xCF`) sub-op `DeviceSubProfileFromTemplate` (`0x28`) | `profile_create_from_template` | ✅ |

**Creating a template, and building a profile from one, is served on every
transport (#497).** Every column of those two rows reaches the same code: the
gRPC and Unix `DeviceService.CreateTemplate` / `CreateProfileFromTemplate`
(`pkg/api/daemon/device_grpc_template.go`) store through the template service
the REST handlers use, and QUIC, MCP and embedded call those two methods rather
than a copy of them. REST and gRPC build the profile through the one
`device.CreateProfileFromTemplate` (`pkg/device/template_service.go`). A zero
template id is assigned by the server, as on REST. A daemon started without the
template or the profile service answers `Unavailable` on every transport (REST
`503`).

| Operation | REST | gRPC / Unix | QUIC | MCP | Embedded | Go SDK |
|---|---|---|---|---|---|---|
| CreateTemplate | yes | yes | yes | yes | yes | `device.Client.CreateTemplate` |
| CreateProfileFromTemplate | yes | yes | yes | yes | yes | `device.Client.CreateProfileFromTemplate` |

The messages carry the `DeviceTemplate…` prefix (`DeviceTemplate`,
`DeviceTemplateCreateRequest`, `DeviceTemplateCreateResponse`) that the
removal note in `device.proto` required, so they cannot collide with
`vtpm.proto`'s `CreateTemplateRequest`. A vTPM template
(`VTPMService.CreateTemplate`, the `vtpm_*` tools) is a different object.
Get, update, delete, list and find-by-name remain REST-only; those rows are
untracked gaps.

**Wire shapes.**

- **QUIC**: `payload[0]` is the sub-opcode; the rest is
  `DeviceTemplateCreateRequest` or `CreateProfileFromTemplateRequest` in the
  build's payload codec (`quicwire.EncodePayload`); the reply is the matching
  response message. Sub-opcodes `0x23` and `0x24` share
  the §3.7 sub-range and dispatcher.
- **MCP**: `device_template_create` takes `tenant_id`, `name` (required),
  `description`, `role` (the §4.2 string), `config` (YAML **text**) and
  `match_rules`; `profile_create_from_template` takes `template_id` (required)
  and `overrides`, using the `profile_create` argument names. Both return the
  domain JSON with `id` as a string; a template's `config` comes back as text.
- **REST**: `config` is bytes, so it is **base64** in both directions. The
  `create-profile` body is `{"overrides": ProfileRequest}` with the template id
  in the path only. A body that does not decode is a **`400`**
  (`ErrInvalidRequestBody`) and nothing is stored; an empty body means "no
  overrides".

**Fields the REST and MCP SDK paths refuse.** The Go SDK translates the pb
messages into the domain JSON those two transports take. Three pb fields have
no place in that shape, and the SDK refuses them before anything is sent
(`provision.ErrFieldNotSupported`; MCP reports it as
`mcp.ErrFieldNotSupported`, REST as `InvalidArgument`) rather than dropping
them with a `2xx`:

| Field | Why |
|---|---|
| template `bmc` | the REST and MCP template shapes carry no BMC block |
| `overrides.tenant_id` | the profile takes the template's tenant |
| `overrides.networks`, `overrides.platformd_config` | not part of the MCP override arguments; refused on both paths so they agree |

gRPC, Unix, QUIC and embedded carry the pb message directly and are not
limited this way.

**The template routes always have a handler (#320).** `router.NewDeviceRouter`
(`pkg/webservice/v1/router/device.go`) requires the device CRUD handler and the
template handler, and returns `ErrDeviceHandlerRequired{Handler}` when either is
nil. That is because `RegisterRoutes` mounts the device, profile and template
routes, and `find-config` / `assign` / `unassign`, with no nil check. Before
#320 every use of the template handler carried its own `if handler != nil`.
The plural aliases #266 removed even had a second check nested inside the
CRUD group. So the guarantee lasted only as long as each new route
remembered its check, and a route that forgot one would dereference nil on
its first request. The remaining handlers
are optional, and each one gates a whole capability: the mTLS device handler,
config delivery, and the attestation verifier. If `deviceRoutes`
(`pkg/webservice/v1/router.go`) gets the constructor error, it logs at Error
and registers no device routes at all. It does not serve a broken half.
`TestNewDeviceRouter_RequiresTheHandlersRegisterRoutesDereferences` and
`TestRegisterRoutes_MountsTheTemplateRoutes` pin both halves of this.

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
`createTemplate` posts there. Every other template operation is singular
only (§3.1). One handler per route — a request is never
interpreted by guessing its shape; `pkg/webservice/v1/router/device_templates_test.go`
pins which handler answers the plural `POST`.

The seeder's other two routes do not collide either. `GET /api/v1/devices/config`
is unique to it. Its `POST /api/v1/devices/templates/{id}/create-profile` sits
beside the singular CRUD `create-profile` under the other prefix, with a
different body (§4.3).

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

The JavaScript SDK's `DeviceRole` (`sdk/javascript/src/types/device.ts`) is
exactly these ten REST strings, with no index signature, so a role the server
adds fails the web console's typecheck wherever it keeps an exhaustive
`Record<DeviceRole, …>`. The console reads, labels and submits roles through
`web/src/lib/device-role.ts`; it never sends the gRPC enum spelling (#119).

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
payload is the subset of the `GET /api/v1/device/profiles` item shape the
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
quote. Nothing is written on refusal unless the caller asks for the clear
below.

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

**Clearing a refused certificate (#516).** A device that already holds a
non-compliant certificate (one enrolled before go-xkms stamped `.3`) is
quarantined by every quote, and no candidate can replace it while the CA
cannot issue a compliant one. `{"clear_on_refusal": true}` is the way out:
when every candidate is refused, the recorder clears the certificate on the
record, so the next quote is an *absence* (denied, not quarantined) until a
compliant certificate is recorded. The flag is never on by default, and it
clears only on that outcome: a compliant certificate is recorded as usual, and
a device with no stored certificate, no enrolled attestation key, an
unreachable CA or a failed revocation of a re-issued certificate keeps the
error unchanged. The clear is a compare-and-clear: if the record changed while
the call ran, nothing is written and the call fails with `ABORTED` (REST
`409`, QUIC status `0x06`). The clear itself is audited as its own event,
`device_attest_cert_cleared`, carrying the refusal that caused it, after the
`device_attest_cert_refused` event for the attempt.

Request body is optional: `{"reissue": <bool>, "clear_on_refusal": <bool>}`.
The response mirrors
`RecordAttestationCertificateResponse` with proto field names:

```json
{"device_id":"42","serial":"SN0042","model":"SuperMicro X10","changed":true,
 "source":"reissued","source_detail":"iak-SuperMicro X10-SN0042","reissued":true,
 "subject":"CN=iak-SuperMicro X10-SN0042,O=…","certificate_serial":"…",
 "not_after":"9999-12-31T23:59:59Z","attest_cert":"-----BEGIN CERTIFICATE-----…"}
```

After a clear the response has `"cleared": true`, `"refusal"` names every
refused candidate, `source` and `attest_cert` are empty, and `subject`,
`certificate_serial` and `not_after` describe the certificate that was
removed.

`source` is `device`, `ca` or `reissued`. A refusal is `FAILED_PRECONDITION`
on gRPC/Unix/MCP, QUIC status `0x01`, and `400` on REST, with a message that
names **every** candidate and why it was refused (`ca[node-03]: … does not
carry tcg-cap-verifiedTPMRestricted`). `UNAVAILABLE` means no CA is
configured. Every attempt is audited as an attestation store event —
`device_attest_cert_recorded`, `device_attest_cert_refused` or
`device_attest_cert_cleared` — and never
reaches the quarantine observers: recording is not a verdict; the collector's
next sweep (§4.4, [attestation/user.md](../attestation/user.md)) produces
that.

**One recorder behind all transports**, like the verifier: gRPC and Unix
serve `DeviceService.RecordAttestationCertificate`; QUIC multiplexes it as
sub-opcode `0x22` under `OpProvisioningCategory` (0xCF), the device
sub-range the profile-assignment verbs use; MCP's `device_record_attest_cert`
(`device:write`), REST and the embedded transport delegate to the same
in-process gRPC service; the
Go SDK exposes `device.Client.RecordAttestationCertificate`; the CLI is
`platformctl device attest-cert record <id> [--reissue] [--clear-on-refusal]`.
The JavaScript SDK exposes `DeviceService.recordAttestCert(id, {reissue})` over
the REST route, returning a refusal's message verbatim in `error.message`
(`error.status` 400). The web console's device detail page carries it as
**Record certificate** on the Attestation Certificate card (#491): re-issuance
is an unchecked option in the confirm dialog, and a refusal is shown verbatim
in that dialog. There is no override in either, because none exists here.
Neither carries `clear_on_refusal` yet; clear a refused certificate through
the CLI or any other surface above.

### 4.6 Diskless boot delivery (#690)

A provisioned diskless node keeps its keys in the TPM and nothing else across
a reboot. Each boot, platformd fetches its identity certificates back
(`pkg/app/tpm_diskless_boot.go`; the node side is
[docs/tpm/architecture.md](../tpm/architecture.md) §4d). Two machine-facing
REST routes serve it, through one service (`BootService`,
`pkg/webservice/v1/device/boot_service.go`):

| Method | Path | Auth | Returns |
|---|---|---|---|
| POST | `/api/v1/device/boot/certificate` | proof of the IDevID key (no client certificate) | `{"identity":"…","idevidChain":"<PEM>"}` — the IDevID chain recorded at enrollment |
| POST | `/api/v1/device/boot` | mTLS (the node's IDevID) | `BootDeliveryResponse`, below |

The certificate route takes no client certificate because the node needs the
chain before it can present it. It authenticates in the body instead,
`{"identity":"<name>","signature":"<base64>"}`: the signature is made with the
TPM-resident IDevID key over SHA-256 of
`go-trusted-platform diskless boot certificate v1 ‖ 0x00 ‖ identity ‖ 0x00 ‖ nonce`,
where the nonce is the same connection channel value the delivery quotes over
(below). It is RSASSA-PSS with a salt as long as the hash, or ASN.1 ECDSA
(`provisioning.SignBootCertificateProof`). The control plane looks the identity
up by serial, then by enrollment hostname, and verifies the signature against
the recorded IDevID leaf. It returns the chain only to the node that holds that
key, on the connection the proof was made for.

The recorded chain is the IDevID leaf first, then the CA certificates of its
issuing chain; the IAK certificate is not in it (it is recorded on its own, as
the attestation certificate). The enrollment hook builds it that way rather than
storing the finalize PEM as delivered: an enroll-01 finalize delivers the IAK,
then the IDevID, then the issuing chain, and a chain led by the IAK would make
every proof above fail against the IAK's key. A finalize chain that does not
parse fails the enrollment instead of being recorded.

An unknown name, a device enrolled before its chain was recorded, and a proof
that does not verify all get the same `403` body,
`device: boot certificate refused`. The route therefore cannot be used to learn
which names are enrolled.

A diskless node's identity is its EK-derived name, `ek-<32 hex>`
([docs/tpm/architecture.md](../tpm/architecture.md) §4d step 5). It enrolls
under that serial and Common Name, and registration refuses either unless it is
the identity of the enrollment's proven EK certificate. The delivery route takes the identity from the
verified client certificate, like the heartbeat, and its body is
`{"evidence":"<base64 vm.QuoteEvidence JSON>"}` — the evidence shape
`POST /api/v1/device/attest` takes. The control plane serves it only when all
of these hold:

1. the presented leaf is byte-for-byte the recorded IDevID, and it chains to
   the platform CA bundle with the client-auth usage;
2. the quote's nonce is the connection's channel value — the TLS 1.3 exporter
   with label `EXPORTER-go-trusted-platform-diskless-boot`, 32 bytes
   (`provisioning.BootChannelNonce`). There is no nonce endpoint: a quote is
   valid only on the connection that produced it, and a TLS 1.2 connection
   cannot be bound and is refused;
3. the device quote verifier (§4.4) returns a verified verdict for that
   device; and
4. the device is not `revoked` or `suspended`. A `quarantined` device may
   boot, because quarantine is enforced on its port and remediation needs it
   up.

```json
{"serial":"SN0042","idevidChain":"-----BEGIN CERTIFICATE-----…",
 "attestCert":"-----BEGIN CERTIFICATE-----…","caBundle":"-----BEGIN CERTIFICATE-----…",
 "profile":{"serialNumber":"SN0042","admittedNetwork":{"vlan":200,…}},
 "pcrBaselineSource":"tofu","pcrBaselineCaptured":true}
```

`profile` is the §3.2 `ProfileResponse`. `pcrBaselineSource` is `signed` or
`tofu` — what the quote was compared against — and the node logs it: a `tofu`
boot proved freshness and IAK possession, not the expected boot state.

| Status | Cause |
|---|---|
| 400 | no identity, a body that is not the JSON above, or a connection with no TLS 1.3 exporter to bind to (`ErrBootChannelRequired`) |
| 403 | certificate: any request that does not prove the recorded IDevID key, one body for all of them. Delivery: wrong or unchained certificate, a quote nonce that is not this connection's, failed or unevaluable attestation, revoked or suspended device |
| 404 | delivery: identity unknown, or no profile bound to the device |
| 500 | recorded chain unparseable, CA bundle, storage or verifier fault |

#### Transports

Both operations are `DeviceService.BootCertificate` and
`DeviceService.BootDelivery` on every transport. They are not an operator API:
the client is a diskless node's platformd before it has started. Every
transport reaches the same `BootService`, which holds all enforcement — the
proof of possession, the leaf-to-CA and recorded-IDevID check, the channel
binding and the attestation verdict — so a transport only peels off its framing
and maps the typed outcome. No transport can serve a node the others refuse.

| Transport | BootCertificate | BootDelivery |
|---|---|---|
| REST | `POST /api/v1/device/boot/certificate` | `POST /api/v1/device/boot` (mTLS) |
| gRPC | `platform.v1.DeviceService/BootCertificate` | `platform.v1.DeviceService/BootDelivery` |
| QUIC | `OpProvisioningCategory` (0xCF), sub-opcode `0x23` | `OpProvisioningCategory` (0xCF), sub-opcode `0x24` |
| MCP | tool `device_boot_certificate` | tool `device_boot_delivery` |
| Unix socket | gRPC over the socket | gRPC over the socket |

The gRPC messages mirror the REST bodies (`BootCertificateRequest{identity,
signature}`, `BootDeliveryRequest{evidence}`, and the `BootDeliveryResponse`
with its `BootProfile`). gRPC statuses map the REST statuses: `InvalidArgument`
(400), `PermissionDenied` (403), `NotFound` (404), `Unavailable` and `Internal`
(500). QUIC carries the same messages in the codec payload after the sub-opcode
byte, with the matching QUIC status.

**Authentication.** A diskless node holds no token, so these methods are exempt
from the transport's token check: the gRPC interceptor skip list, the QUIC
`AuthMiddleware` sub-opcode skip, and an explicitly open (`""`) MCP tool
permission. The exemption is safe only because the boot service authenticates
every request itself. On gRPC and QUIC the connection's TLS state reaches the
service — the gRPC peer's `TLSInfo`, the QUIC connection state carried in the
request context — and the delivery identity is the verified client
certificate, never a request field.

**Where a transport cannot serve a node.** The channel nonce is a TLS 1.3
exporter, so a transport with no TLS connection has none. The transport
refuses the request itself, with the typed `ErrBootChannelRequired` naming
it, before the boot service runs — an empty nonce never reaches it:

| Transport | Refusal for a connection with no channel |
|---|---|
| REST | `400` |
| gRPC, Unix socket | `FailedPrecondition` |
| QUIC | `StatusInvalidRequest` |
| MCP | `-32007` (`FailedPrecondition`): tool error `ErrBootChannelRequired` (Transport `MCP`), from both MCP service providers |

- The Unix socket and MCP (plain HTTP or stdio) carry no TLS connection; both
  operations are refused there, by the SDK before anything is sent (below)
  and by the daemon for any other client. A proof made for another
  connection is refused on REST, gRPC and QUIC with `403` /
  `PermissionDenied`, the same as any proof that does not verify.
- The gRPC TCP and QUIC listeners with mutual TLS enabled (`EnableMTLS`)
  verify a client certificate **if one is given** (`tls.VerifyClientCertIfGiven`,
  set by `grpcTCPServerTLS` and `quicServerMTLS` in
  `pkg/api/daemon/client_cert_gate.go`) and require one per request: `BootCertificate` may arrive without one (the
  node has none yet); `BootDelivery` and every other RPC or QUIC opcode are
  refused (`Unauthenticated` / `StatusUnauthorized`) without a verified
  certificate. A certificate that does not chain to the client CA fails the
  handshake. On QUIC the handshake and the request authenticator verify
  against one client CA pool, read once when the daemon is constructed.
  Both boot calls therefore share one listener.
- A TLS-terminating proxy or load balancer in front of the control plane breaks
  diskless boot: the channel nonce and the client certificate belong to the
  proxy's connection, not the node's, so the proof fails closed. Pass TLS
  through (layer 4) to the control plane.
- A gRPC or QUIC listener that never requests a client certificate cannot serve
  `BootDelivery`: there is no leaf to verify, so it fails closed.

**Client.** The proof and the evidence are bound to the connection that
carries them, and that connection's exporter exists only once it is open, so
the Go SDK takes a callback rather than proof bytes:

```go
type BootProofFunc func(ctx context.Context, binding []byte) ([]byte, error)

resp, err := client.BootCertificate(ctx, identity, sign)  // sign returns the IDevID proof over binding
resp, err := client.BootDelivery(ctx, quote)              // quote returns vm.QuoteEvidence JSON whose nonce is binding
```

The transport calls the function after it has connected, with that
connection's `provisioning.BootChannelNonce`, and sends the request on the
same connection ([architecture.md §4.5](architecture.md#45-diskless-boot-a-proof-is-made-on-the-connection-that-carries-it-690)).
Every failure is the typed `ErrBootCertificateFailed` /
`ErrBootDeliveryFailed` wrapping its cause: the control plane's status, the
callback's own error, `ErrBootProofMissing` for a nil callback, or — on a
transport with no TLS connection (Unix, MCP, embedded) —
`*transport.ErrChannelBindingUnavailable{Transport, Reason}`, returned
without calling the function or sending anything. The CLI is
`platformctl device boot certificate --identity <name> --key <PEM>` and
`platformctl device boot delivery --quote-command <program>`
([cli.md §2.7](cli.md#27-device-boot-certificate-and-device-boot-delivery)).

### 4.7 Operator Disable and Enable (#250)

`POST /api/v1/devices/{id}/disable` and `POST /api/v1/devices/{id}/enable`
(admin gate) are the operator's lifecycle transitions. They are dedicated
verbs, not a `PUT` of the `state` field: each programs the device's switch port
through the SDN policy engine **before** it records the state, so a recorded
state is always an enforced one
([architecture.md §4.6](architecture.md#46-operator-disable-and-enable-250)).

- **Disable** blocks the port and records `suspended` with
  `state_reason` `operator: <reason>` (`operator: disabled` without one).
  Request body is optional: `{"reason": "<text>"}`, at most 256 bytes.
- **Enable** takes no body. It moves a `suspended` device to `quarantined`,
  re-admits its port to the zone carrying lifecycle role `quarantine` and asks
  the attestation collector to quote the device now. Only a passing verdict
  restores the state and placement it had before the disable.

Both answer in the standard envelope with the `DeviceLifecycleResponse`
fields under proto names:

```json
{"device_id":"42","state":"quarantined","previous_state":"suspended",
 "state_reason":"","reattestation_requested":true}
```

`reattestation_requested` is `false` on Disable, and on Enable when no
collector took the request; the device then waits for the next scheduled
attestation cycle.

**The transitions fail closed.** Every refusal leaves the record and the port
as they were:

| Cause | Error | gRPC / Unix / MCP | QUIC | REST |
|---|---|---|---|---|
| The daemon has no SDN policy engine (not SDN-OVS, or no attestation quarantine observer) | `ErrLifecycleUnenforced` | `FAILED_PRECONDITION` | `0x01` | 400 |
| The device has no `network_port_id` | `ErrDeviceNotOnFabric` | `FAILED_PRECONDITION` | `0x01` | 400 |
| Disable from `suspended` or `revoked` | `entities.ErrInvalidTransition` | `FAILED_PRECONDITION` | `0x01` | 400 |
| Enable from anything but `suspended`; no zone with lifecycle role `quarantine`; the engine knows no port for the device | `policy.ErrDeviceNotSuspended`, `ErrNoQuarantineZone`, `ErrUnknownDevicePort` | `FAILED_PRECONDITION` | `0x01` | 400 |
| `reason` longer than 256 bytes; id missing or `0` | `ErrLifecycleReasonTooLong`; `ErrInvalidDeviceID` | `INVALID_ARGUMENT` | `0x09` | 400 |
| Unknown device | — | `NOT_FOUND` | `0x02` | 404 |

**One service behind all transports.** gRPC and Unix serve
`DeviceService.DisableDevice` / `EnableDevice`; QUIC multiplexes them as
sub-opcodes `0x25` / `0x26` under `OpProvisioningCategory` (§3.7); MCP's
`device_disable` / `device_enable` (`device:write`) and REST delegate to the
same in-process gRPC service; the Go SDK exposes `device.Client.Disable` /
`Enable`, the JS SDK `DeviceService.disableDevice` / `enableDevice`,
and the CLI `platformctl device disable <id> [--reason]` /
`device enable <id>` ([cli.md §2.8](cli.md)).

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

## 6. The MCP surface: one device family, one profile family, two template tools

Two families of device-related MCP tools exist, plus the two template tools,
and every tool in them is dispatched and scope-checked.

| Family | Registered by | Executor | In the authorization map |
|---|---|---|---|
| `device_register`, `device_get`, `device_find_by_serial`, `device_list`, `device_delete`, `device_update`, `device_attest`, `device_record_attest_cert`, `device_provision`, `device_disable`, `device_enable` | `registerDeviceTools` (`tools.go:557`) | `ExecuteTool` (`tools.go:1325`) | **yes** — `device:write` / `device:read` / `device:delete` |
| `profile_create`, `profile_get_by_id`, `profile_list_all`, `profile_update_by_id`, `profile_delete_by_id`, `profile_assign_to_device`, `profile_unassign_from_device` | `registerDeviceToolsV2` (`device_tools.go:99`) | `deviceProfileToolDispatch` | **yes** — all seven mapped to `device:*` |
| `device_template_create`, `profile_create_from_template` (§4) | `registerDeviceTemplateTools` (`device_template_tools.go:157`) | `deviceProfileToolDispatch` | **yes** — both `device:write` |

The two template tools are not the `vtpm_*_template_*` tools, which create
vTPM templates. A template tool called on a daemon without the template or
profile service answers a typed JSON-RPC error, as every MCP device tool does.


**Arguments are named after the device fields.** `device_register` takes
`serial` (required), `model`, `ek_cert`, `attest_pub`, `attest_cert`,
`signing_pub` and `hash_algo_id`, and stores each under its own name; the
result is the created device with its assigned `id`. `device_update` takes
`device_id` (required) plus `model` and `serial` — the attestation fields are
server-owned (§3.3) and ignored — and returns the stored device after the
update. `device_find_by_serial` takes `serial` and returns the device.

Until #533 a third family — `device_create`, `device_get_by_id`,
`device_get_by_serial`, `device_list_all`, `device_update_by_id`,
`device_delete_by_id`, `device_get_status` — was advertised by `tools/list`
with no executor behind it, so every call answered `unknown tool:
device_create`. It was removed rather than wired: it duplicated the family
above verb for verb. `device_register` also read `name` / `device_type` and
stored them as model and serial, so the serial a caller sent was dropped; it
now maps every argument by name.

`AuthorizeTool` denies any tool with no entry in the permission map, and
`TestExecuteTool_EveryAdvertisedToolDispatches` fails when a tool is advertised
without an executor, so an advertised-but-dead tool cannot return unnoticed.

---

## 7. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form. Enforcement is per operation: gRPC
`RequireScope`, QUIC `AuthorizeRequest`, MCP `AuthorizeTool`, webservice
REST `RequireScope` on the routes noted below. The gRPC, QUIC and MCP catalogs
and their default-deny behaviour are described in
[`docs/daemon/api.md`](../daemon/api.md) §5.

**QUIC enforces two catalogs.** `opcodePermissions` maps every top-level
device opcode (`0x30`–`0x3E`) and `categoryPermissions` maps the device
sub-opcodes under `OpProvisioningCategory` (`0xCF`, keyed by `payload[0]`):
`0x20`/`0x21` assign and unassign, `0x22` record attestation certificate,
`0x25`/`0x26` disable and enable, `0x27` create template, `0x28` create profile
from template — all `device:write`. The diskless boot sub-opcodes `0x23`/`0x24`
are pre-auth (§4.6). Both catalogs are in `pkg/api/quic/opcode_permissions.go`;
an operation absent from them is refused, so a new sub-opcode without an entry
fails closed. `pkg/api/daemon/quic_device_authz_test.go` sends every device
write through the daemon's QUIC handler with a read-only, a write and a missing
token. The other `0xCF` sub-ranges are unscoped by design: config delivery
(`0x01`–`0x07`) is machine bootstrap without a platform token, and EAB
(`0x10`–`0x1A`) is unscoped on gRPC and MCP too
([`docs/eab/api.md`](../eab/api.md) §5). Under mTLS-only QUIC or skipped IAM
validation no token middleware is installed and nothing is enforced. The
opcode tables are in [`api-reference-quic.md`](api-reference-quic.md).

**`DeviceService` is in the gRPC scope catalog, and its coverage is complete**
— all 28 RPCs but the two token-exempt boot RPCs (§4.6) are mapped in
`pkg/api/grpc/method_permissions.go`, resource `device`:

| Action | RPCs |
|---|---|
| `device:read` | `GetDevice`, `ListDevices`, `CountDevices`, `FindDeviceBySerial`, `GetProfile`, `ListProfiles`, `CountProfiles`, `FindMatchingProfile`, `FindProfileByMACAddress`, `FindProfileBySerial`, `FindConfigForDevice` |
| `device:write` | `CreateDevice`, `UpdateDevice`, `ActivateDevice`, `AssignProfileToDevice`, `UnassignProfileFromDevice`, `CreateProfile`, `CreateProfileFromTemplate`, `CreateTemplate`, `UpdateProfile`, `AttestDevice`, `RecordAttestationCertificate`, `DisableDevice`, `EnableDevice` |
| `device:delete` | `DeleteDevice`, `DeleteProfile` |

The catalog is default-deny, so every `DeviceService` RPC is in it:
`TestGRPCMethodCatalog_CoversEveryRegisteredMethod` fails on any registered RPC
with neither a scope nor a pre-auth entry, and
`TestScopeForMethod_EveryDeviceServiceMethodIsScoped` walks
`DeviceService_ServiceDesc`, keeps `BootCertificate` and `BootDelivery`
unscoped and pins the write methods above. Until #250 the catalog stopped at
21: `AttestDevice` and `RecordAttestationCertificate` were unscoped on gRPC
while QUIC and MCP checked them, because an unlisted method was then allowed
for any validated token.

**Attestation is a write.** `AttestDevice` persists: the first fully verified
quote seeds the profile's PCR baseline (§4.4), and a cryptographic failure
quarantines the device. `RecordAttestationCertificate` stores a certificate on
the device. Both require `device:write` on every scoped transport — gRPC, QUIC
`OpDeviceAttest` (`0x3A`) and sub-opcode `0x22`, MCP `device_attest` /
`device_record_attest_cert`, and the webservice REST routes
`POST /api/v1/devices/{id}/attest` and
`POST /api/v1/devices/{id}/attest-cert/record` — so a `device:read` token can
look at devices but cannot change their trust state. The lifecycle routes
`POST /api/v1/devices/{id}/disable` and `POST /api/v1/devices/{id}/enable`
require `device:write` the same way. On the webservice the scope check applies
behind the platform-token middleware; under the legacy JWT handler, which
carries no scopes, the routes keep only their admin role gate. The daemon REST
server (`pkg/api/rest`) is mTLS-only and has no scope check.

The two template operations require `device:write` on MCP as well
(`device_template_create`, `profile_create_from_template` in
`pkg/api/mcp/authz.go`). Template create requires it on the webservice REST
route `POST /api/v1/device/templates` too, behind the platform-token middleware
like the attestation routes: before #770 that route kept only its admin role
gate, so a `device:read` token could create a template over REST that every
other transport refused. The create-profile route and the other template routes
(get, update, delete, list) still keep only the role gate; get, update, delete
and list are REST-only and have no gRPC catalog entry.

On MCP, all 20 device-related tool names carry a permission — see §6.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | Device cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Payload failed to decode (`ErrQUICDecodingFailed`); a refused operator Disable/Enable (`FAILED_PRECONDITION`, §4.7) |
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
Over REST the count is `pagination.total`; the SDK renames it to `total_items`
(§1b). The CLI defaults are `--page 1 --page-size 20`; the MCP `profile_list_all`
default is `page 1, page_size 50`. Both result sets are unbounded in principle —
always paginate.

---

## 10. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. Nothing in the device surface is marked deprecated as of 2026-08-18.
The singular/plural REST duplication was drift, not a versioning scheme, and
#266 removed it (§3.1). The dead third MCP device family (§6) was the same kind
of drift, and #533 removed it: the newer spelling is not automatically the
better one.

---

## 11. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/api.md`](../sdn/api.md) · [`docs/switch/api.md`](../switch/api.md)

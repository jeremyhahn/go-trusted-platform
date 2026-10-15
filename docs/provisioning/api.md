# Zero-Touch Provisioning — API

> **Status: NORMATIVE** · Scope: provisioning, PXE and config-delivery routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.PXE` and `ServiceRegistry.ConfigDelivery` carry both services
in-process — the latter with its own comment noting it *"backs the pre-enrollment
provisioning verbs (nonce issuance, config fetch, remote Secure Boot digest
signing, provisioning session management)."*

Three gRPC services are in scope:

| Service | RPCs | File |
|---|---|---|
| `PXEService` | 15 | `pkg/api/grpc/proto/pxe.proto` |
| `ConfigDeliveryService` | 7 | `pkg/api/grpc/proto/configdelivery.proto` |
| `ProvisioningGateway` | 4 | `pkg/api/grpc/proto/provisioning.proto` |

QUIC uses a **provisioning category opcode `0xCF`**
(`sdk/go/wire/quicwire/provisioning_opcodes.go`, which notes it follows "the same
pattern as OpSwitchCategory (0xCC)"), plus PXE extended opcodes `0xFC`–`0xFF`.

---

## 2. PXE device lifecycle

REST base path `/api/v1/pxe` (`pkg/webservice/v1/rest/pxe/router.go`).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Register device | `POST /api/v1/pxe/devices` | `RegisterDevice` | `0xFC`–`0xFF` | `pxe_register_device` | ✅ |
| List devices | `GET /api/v1/pxe/devices` | `ListDevices` | as above | `pxe_list_devices` | ✅ |
| Get device | `GET /api/v1/pxe/devices/{id}` | `GetDevice` | as above | `pxe_get_device` | ✅ |
| Get device by MAC | `GET /api/v1/pxe/devices/mac/{mac}` | `GetDeviceByMAC` | as above | `pxe_get_device_by_mac` | ✅ |
| Remove device | `DELETE /api/v1/pxe/devices/{id}` | `RemoveDevice` | as above | `pxe_remove_device` | ✅ |
| Update state | `PUT /api/v1/pxe/devices/{id}/state` | `UpdateState` | as above | `pxe_update_state` | ✅ |
| Set enrolled | `POST /api/v1/pxe/devices/{id}/enrolled` | `SetDeviceEnrolled` | as above | `pxe_set_device_enrolled` | ✅ |
| **Authorize** | `POST /api/v1/pxe/devices/{id}/authorize` | `Authorize` | as above | `pxe_authorize_device` | ✅ |
| **Quarantine** | `POST /api/v1/pxe/devices/{id}/quarantine` | `Quarantine` | as above | `pxe_quarantine_device` | ✅ |
| Retry | `POST /api/v1/pxe/devices/{id}/retry` | `Retry` | as above | `pxe_retry_device` | ✅ |
| Device events | `GET /api/v1/pxe/devices/{id}/events` | `GetEvents` | as above | `pxe_get_device_events` | ✅ |
| Service status | `GET /api/v1/pxe/status` | `GetStatus` | as above | `pxe_service_status` | ✅ |
| Start service | `POST /api/v1/pxe/start` | `StartService` | as above | `pxe_start_service` | ✅ |
| Stop service | `POST /api/v1/pxe/stop` | `StopService` | as above | `pxe_stop_service` | ✅ |
| Install-complete webhook | `POST /api/v1/pxe/webhook/complete` | `WebhookComplete` | as above | `pxe_webhook_complete` | ✅ |

**This is the most complete capability set in the platform** — fifteen
capabilities, all fifteen on five transports.

`Authorize` and `Quarantine` are separate operations, and the presence of
`Quarantine` is the design point: a device that fails a check goes to an
isolated state rather than being left in an ambiguous one. `Retry` is how it
comes back.

**`WebhookComplete` is an input, not a truth.** It is the machine reporting that
installation finished; the state machine decides what that means. Its REST route
is registered only when `pxe.ServiceConfig.WebhookEnabled` is true (default
false), and is then unauthenticated — see [`docs/ipxe/api.md`](../ipxe/api.md)
§4 and #238.

---

## 3. Config delivery — pre-enrollment

The routes a machine with no identity uses.

| Capability | REST | gRPC / Unix | QUIC (under `0xCF`) | MCP | Embedded |
|---|---|---|---|---|---|
| Get nonce | `GET /api/v1/provisioning/config/nonce` | `GetNonce` | ✅ | `provision_get_nonce` | ✅ |
| Fetch config | `POST /api/v1/provisioning/config` | `FetchConfig` | ✅ | `provision_fetch_config` | ✅ |
| **Sign digest** (remote Secure Boot signing) | `POST /api/v1/provisioning/sign` | `SignDigest` | ✅ | `provision_sign_digest` | ✅ |
| Poll session | `GET /api/v1/provisioning/sessions/{sessionID}/poll` | `PollSession` | ✅ | `provision_poll_session` | ✅ |
| **Fulfil session** | `POST /api/v1/provisioning/sessions/{sessionID}/fulfill` | `FulfillSession` | ✅ | `provision_fulfill_session` | ✅ |
| List sessions | `GET /api/v1/provisioning/sessions` | `ListSessions` | ✅ | `provision_list_sessions` | ✅ |
| Get session | `GET /api/v1/provisioning/sessions/{sessionID}` | `GetSession` | ✅ | `provision_get_session` | ✅ |

**Config delivery is on REST** (`pkg/webservice/v1/router/device.go`,
`registerProvisioningDeviceRoutes` and `registerProvisioningOperatorRoutes`).
An earlier revision of this table said it had no REST surface at all; the
routes were registered and the web console was calling them, so the table
was corrected against the router (#418). The four device-facing routes carry
no role gate — a machine at boot has no certificate or session — and
authenticate by EAB (SignDigest also by the EK); the three operator routes
sit behind the gated router and take the gRPC scopes (§6).

`FulfillSession` is the **authorisation step**: a provisioning session stays
pending until something with authority links a device profile to it. There is no
self-service path.

**Session body (`pkg/provisioning/configdelivery/types.go`, `Session`)** —
returned by *Get session* and, as an array, by *List sessions*:
`{"id", "ek_serial", "mac_address", "tenant_id", "profile_id", "profile",
"fulfilled", "created_at", "expires_at"}`, snake_case throughout. `profile_id`
is the platform's wire id type and is **emitted as a JSON string** (#375's
response half, applied here by #425), so a JavaScript client reads it exactly
above 2^53; `profile` is the linked `DeviceProfile` once fulfilled. The
JavaScript SDK's `ProvisioningSession` declares exactly these names, pinned by
`session_wire_parity_test.go`; before #425 it declared camelCase for every one
of them, so the console's session pages read `undefined` for values the server
had sent.

**Fulfil body (`pkg/provisioning/configdelivery/types.go`, `FulfillRequest`):**
`{"session_id": "…", "profile_id": "…"}`. `session_id` is optional when the
path carries it. `profile_id` is the platform's wire id type
(`pkg/webservice/v1/device.ID`, the #375 rule): it **decodes from a JSON string
or a JSON number** and rejects anything else with `400` and
`device: id must be a JSON string or number holding an unsigned integer`. Send
it as a string — ids are minted above 2^53 and a JSON number at that magnitude
is rounded by every JavaScript client. Before #418 the field was a plain
`uint64` and the JavaScript SDK posted it under `profileId`, a key the server
does not read, so every console fulfil ran with profile id 0 and answered
`404 profile not found`. The `Session` body's `profile_id` is still emitted as a
JSON number; that row is #425.

A missing or zero `profile_id` names no profile. `configdelivery.Service`
refuses it with `ErrProfileIDRequired`
(`configdelivery: profile_id is required and must be non-zero`) before it looks
the session up, so every transport answers it the same way: REST `400`, gRPC and
Unix `InvalidArgument`, QUIC `StatusInvalidArgument`, MCP `InvalidParams` (#304).

`SignDigest` signs a Secure Boot digest **on the platform**, so the signing key
never travels to the machine being provisioned.

---

## 4. Provisioning gateway

`ProvisioningGateway` (`pkg/api/grpc/proto/provisioning.proto`) is the
gateway-side view — four RPCs:

| RPC | Purpose |
|---|---|
| `RegisterPXEDevice` | Register a device seen by the gateway |
| `GetBootConfig` | Deliver a boot configuration |
| `ReportDeviceState` | Report state upward |
| `NotifyInstallComplete` | Report completion upward |

These are consumed by gatewayd in its `pxe` service section
([`docs/gateway/`](../gateway/)).

Over REST (#452) the device's MAC is the path segment and the rest of the
request is the body. The webservice routes
(`pkg/webservice/v1/rest/pxe/gateway.go`) translate each report onto the
`PXEService` the gRPC server runs:

| RPC | REST route | Credential | Served by |
|---|---|---|---|
| `RegisterPXEDevice` | `POST /api/v1/provisioning/devices/{mac}/register` | admin role + `provisioning:write` | `PXEService.RegisterDevice`; a known MAC answers `200` with its ID and `already_registered`, a new one `201` |
| `ReportDeviceState` | `POST /api/v1/provisioning/devices/{mac}/state` | admin role + `provisioning:write` | `PXEService.GetDeviceByMAC`, then `UpdateState`; `state` is a `ProvisioningState` name without its prefix (`booting`) |
| `NotifyInstallComplete` | `POST /api/v1/provisioning/devices/{mac}/install-complete` | admin role + `provisioning:write` | `PXEService.WebhookComplete`; `status` is `success` or `failure` |
| `GetBootConfig` | none | — | no per-MAC boot configuration exists in platformd to answer it from; the SDK's `GET /api/v1/provisioning/devices/{mac}/boot-config` claim stays in the route ledger |

An unknown MAC answers `404`, a bad `state` or `status` `400`, and a token
without `provisioning:write` `403`. Under the legacy JWT handler the role gate
alone applies.

`NotifyInstallComplete` is the same operation as the booting node's
`POST /api/v1/pxe/webhook/complete`. That webhook presents no credential
(#238). The gateway route is not a second open path: it takes the admin gate
and the scope. The EAB check was not used, because it authenticates a device
on its own first contact, not a gateway reporting on a device.

**Note the near-duplicate naming.** `ProvisioningGateway.RegisterPXEDevice` and
`PXEService.RegisterDevice` are different RPCs on different services with
different request messages (`RegisterProvisioningDeviceRequest` versus
`RegisterPXEDeviceRequest`). They are not interchangeable.

---

## 5. BMC — transport shape only

`BMCService` (`pkg/api/grpc/proto/bmc.proto`) carries 23 RPCs — power control,
boot device, virtual media, sensors, system info, provisioning, web certificate
management, enrollment, factory restore and user management. QUIC reaches every
RPC through the **BMC category opcode `0x9F`**, one sub-opcode per RPC; there
are 23 `platform_bmc_*` MCP tools, one per RPC; and the embedded transport
carries all 23 through `ServiceRegistry.BMC`.

**BMC internals are not documented in this pass** — see
[engineering.md](engineering.md) §1. The transport shape is recorded here so the
matrix is not silently incomplete; `docs/bmc/` remains unconverted.

---

## 6. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)). Every RPC of the four
services is classified in the gRPC catalog (`pkg/api/grpc/method_permissions.go`):

| Service | Requirement |
|---|---|
| `PXEService` | `pxe:read` for the five reads; `pxe:write` for `Authorize`, `Quarantine` and the other mutators; `pxe:delete` for `RemoveDevice` ([`docs/ipxe/api.md`](../ipxe/api.md) §5) |
| `ConfigDeliveryService` | `ListSessions` and `GetSession` need `provisioning:read`; `FulfillSession` needs `provisioning:write`. `GetNonce`, `FetchConfig`, `SignDigest` and `PollSession` are **pre-auth**: the machine authenticates inside the request (single-use nonce, EAB HMAC, EK-certificate binding) before it holds any platform credential |
| `ProvisioningGateway` | `GetBootConfig` needs `provisioning:read`; `RegisterPXEDevice`, `ReportDeviceState` and `NotifyInstallComplete` need `provisioning:write` |
| `BMCService` | `bmc:read` / `bmc:write` / `bmc:power` / `bmc:media` / `bmc:admin` ([`docs/bmc/api.md`](../bmc/api.md) §8) |

**QUIC requires per-operation scopes (#767)**
(`pkg/api/quic/opcode_permissions.go`):

| Scope | QUIC operations |
|---|---|
| `pxe:read` | `OpPXEListDevices`, `OpPXEGetDevice` |
| `pxe:write` | `OpPXERegisterDevice`, `OpPXEUpdateState`, `OpPXEAuthorize`, `OpPXEQuarantine`, `OpPXERetry` |
| `pxe:delete` | `OpPXERemoveDevice` |
| `provisioning:read` | `OpProvisioningCategory` (`0xCF`) subs `ListSessions`, `GetSession` |
| `provisioning:write` | sub `FulfillSession` |
| open (pre-auth) | subs `GetNonce`, `FetchConfig`, `SignDigest`, `PollSession`, as on gRPC (#317) |
| `device:write` | subs `DeviceProfileSubAssign`, `DeviceProfileSubUnassign`, `DeviceSubRecordAttestCert`, `DeviceSubDisable`, `DeviceSubEnable` |

The EAB sub-opcodes of the same category carry the `eab` scopes
([`docs/eab/api.md`](../eab/api.md) §5); BMC enrollment carries `bmc:admin`
([`docs/bmc/api.md`](../bmc/api.md) §8).

`FulfillSession` is the authorisation gate for bringing a new machine onto the
platform, so `provisioning:write` is the grant to guard.

**The webservice REST operator routes take the same scopes (#484).** Behind the
platform-token middleware, `GET /api/v1/provisioning/sessions` and
`GET /api/v1/provisioning/sessions/{sessionID}` require `provisioning:read`
and `POST /api/v1/provisioning/sessions/{sessionID}/fulfill` requires
`provisioning:write`, on top of the admin role gate; a token without the scope
gets `403`. Under the legacy JWT handler the role gate alone applies. The
device-facing routes take no scope (§3). The gateway's device reports under
`/api/v1/provisioning/devices/{mac}` require `provisioning:write` the same way
(§4).

On MCP, the 23 BMC tools are mapped ([`docs/bmc/api.md`](../bmc/api.md) §8).
The `provision_*` tools take the scopes of their gRPC twin (#304):
`provision_list_sessions` and `provision_get_session` need `provisioning:read`,
`provision_fulfill_session` needs `provisioning:write`, and
`provision_get_nonce`, `provision_fetch_config`, `provision_sign_digest` and
`provision_poll_session` are open, as the gRPC methods are pre-auth. The open
tools reach the same `configdelivery.Service`, which checks the nonce, EAB HMAC
and EK binding before it answers. QUIC serves the same four open, through
its pre-auth sub-opcode list (#317); before #317 it required
`provisioning:read` or `provisioning:write` for them, so a device without a
token could not provision over QUIC. No transport binds a caller to a
session's tenant, so `provisioning:read` lists every tenant's sessions.

Note that the config-delivery path is *separately* protected: a device presents
an EAB credential and a nonce, and `RateLimitConfig` bounds the endpoint. That
protects against unidentified machines; the operator half is the scoped
`ListSessions` / `GetSession` / `FulfillSession` above.

---

## 7. Status and error mapping

| QUIC byte | Name | REST | Provisioning cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed MAC, EK serial or device record |
| `0x02` | `StatusNotFound` | 404 | Unknown device or session |
| `0x03` | `StatusUnauthorized` | 401 | EAB credential rejected; nonce stale |
| `0x04` | `StatusInternalError` | 500 | Installer or boot-config failure |
| `0x06` | `StatusAlreadyExists` | 409 | Device already registered |
| `0x07` | `StatusPermissionDenied` | 403 | Device quarantined or not authorised |
| `0x08` | `StatusResourceExhausted` | 429 | Provisioning endpoint rate limit |
| `0x0A` | `StatusUnavailable` | 503 | PXE service stopped or not wired in |

**429 here is expected under a mass provisioning event.** The endpoint is
reachable by machines with no identity, so it is rate-limited by design
(`RateLimitConfig`).

**503 from `/api/v1/pxe/*` may mean the PXE service is simply stopped** —
`StartService` and `StopService` exist, so "not running" is a state, not a
fault.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
`ProvisioningGateway` / `PXEService` naming overlap in §4 is a duplication
hazard rather than a deprecation.

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
installation finished; the state machine decides what that means.

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
sit behind the gated router.

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
([`docs/gateway/`](../gateway/)) and are gRPC-only.

**Note the near-duplicate naming.** `ProvisioningGateway.RegisterPXEDevice` and
`PXEService.RegisterDevice` are different RPCs on different services with
different request messages (`RegisterProvisioningDeviceRequest` versus
`RegisterPXEDeviceRequest`). They are not interchangeable.

---

## 5. BMC — transport shape only

`BMCService` (`pkg/api/grpc/proto/bmc.proto`) carries 23 RPCs — power control,
boot device, virtual media, sensors, system info, provisioning, web certificate
management, enrollment, factory restore and user management. QUIC reaches BMC
enrollment through the **BMC category opcode `0x9F`**, and there are 16
`platform_bmc_*` MCP tools.

**BMC internals are not documented in this pass** — see
[engineering.md](engineering.md) §1. The transport shape is recorded here so the
matrix is not silently incomplete; `docs/bmc/` remains unconverted.

---

## 6. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

**None of `PXEService`, `ConfigDeliveryService`, `ProvisioningGateway` or
`BMCService` is in the gRPC scope catalog.** `pkg/api/grpc/method_permissions.go`
maps 185 methods across eleven services; none of these four is among them, and a
method absent from the map carries no required scope.

**No provisioning MCP tool is in the MCP authorization map either** — 71 of 449
tool names carry a permission, and neither the 22 `pxe_*`/`provision_*` tools
nor the 16 BMC tools are among them.

So **any validated token can authorize a PXE device, quarantine one, fulfil a
provisioning session, or ask the platform to sign a Secure Boot digest.**
`FulfillSession` is the authorisation gate for bringing a new machine onto the
platform, and `SignDigest` produces a Secure Boot signature. Raised as an owner
question in the migration report.

Note that the config-delivery path is *separately* protected: a device presents
an EAB credential and a nonce, and `RateLimitConfig` bounds the endpoint. That
protects against unidentified machines; it does not scope an operator's token.

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

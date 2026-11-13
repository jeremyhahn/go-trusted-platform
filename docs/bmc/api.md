# BMC — API

> **Status: NORMATIVE** · Scope: BMC routes on every transport · Last verified: 2026-10-15
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G<n>`, never omitted.

---

## 1. The six transports, and where BMC lives on each

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. The canonical
description of all six — the frame format, the status bytes, the QUIC category
opcode table, the platform authorization model — is
[`docs/daemon/api.md`](../daemon/api.md). It is not repeated here.

| Transport | BMC surface | Defined in |
|---|---|---|
| **gRPC** | `platform.v1.BMCService`, **23 RPCs** | `pkg/api/grpc/proto/bmc.proto`; registered in `pkg/api/daemon/daemon.go` |
| **Unix** | **The same 23 RPCs.** Unix is gRPC over a UDS; `BMCService` is registered on both `grpcServer` and `grpcUDSServer` | same |
| **REST** | base path `/api/v1/bmc/{profileID}`, **20 route registrations over 13 paths** | `pkg/api/daemon/rest_service.go`; handlers in `pkg/webservice/v1/bmc/` |
| **QUIC** | `OpBMCCategory` = `0x9F`, **23 sub-opcodes** `0x01`–`0x17`, one per gRPC RPC | `sdk/go/wire/quicwire/phase35_opcodes.go`; handler `pkg/api/daemon/quic_bmc.go` |
| **MCP** | **23 tools**, all named `platform_bmc_*`, one per gRPC RPC | `pkg/api/mcp/bmc_tools.go`; servicer wired in `pkg/api/daemon/daemon.go` |
| **Embedded** | **The same 23 RPCs**, through `ServiceRegistry.BMC` | `sdk/go/transport/embedded/dispatch.go`; registry built in `pkg/api/daemon/embedded_host.go` |

Each QUIC sub-opcode, each MCP tool and each embedded handler calls the same
`BMCService` servicer gRPC registers, so a call on any of them returns the
reply and the refusal its gRPC RPC gives.

An MCP tool's arguments are the RPC's request message and its result is the
RPC's response message, both in protobuf JSON under the proto field names:
enums by name (`BMC_BOOT_DEVICE_PXE`), 64-bit integers as strings, `bytes`
fields base64. An argument the request message does not declare is refused as
`InvalidArgument` before the servicer runs. A tool therefore succeeds and
refuses with the gRPC status its RPC gives the same caller.

A backend the node does not have — no BMC service, no profile store, no
enroller, no restorer, no baremetal orchestrator — is *service not
configured*, answered as `Unavailable` everywhere: gRPC `Unavailable` with the
`SERVICE_NOT_CONFIGURED` reason (`bmcNotConfigured`,
`pkg/api/daemon/bmc_grpc_service.go`), REST `503`, QUIC `StatusUnavailable`,
and MCP `ErrBMCNotConfigured` or the servicer's `Unavailable`.

## 2. The embedded transport

`ServiceRegistry` (`sdk/go/transport/embedded/adapter.go`) is the complete
reach of the embedded transport, and its `BMC` field carries the
`BMCService` servicer. `Daemon.embeddedServices`
(`pkg/api/daemon/embedded_host.go`) sets it whenever the daemon wires a BMC
service, and `registerBMCHandlers` (`sdk/go/transport/embedded/dispatch.go`)
binds all 23 `platform.v1.BMCService` methods to it. An SDK client on
`ProtocolEmbedded` therefore reaches every RPC gRPC carries.

A daemon with no BMC service leaves the field `nil`; every BMC method is then
unregistered and the embedded call is refused `Unimplemented`
(`embedded: method ... not registered`).

The embedded transport runs **no scope check**. Its caller is the daemon's
own process, so the §8 scopes do not apply to it.

Standalone mode (`--bmc-host`) is the only daemonless path, and it is a
different thing: direct hardware access with no audit log and no persistence.

The "Embedded Go call" column below is the `pkg/bmc` in-process API, distinct
from the "Embedded transport" column. A capability that is reachable in-process
and absent from every transport is implemented but unexported — which is
exactly the shape of debt `docs/13` exists to track.

---

## 3. Power

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Power on | `Service.PowerOn(ctx, profileID)` | `PowerOn` | `PowerOn` | `POST /api/v1/bmc/{profileID}/power` `{"action":"on"}` | `PowerOn` | `0x9F` / `BMCSubPowerOn` `0x03` | `platform_bmc_power_on` |
| Power off | `Service.PowerOff` | `PowerOff` | `PowerOff` | `POST .../power` `{"action":"off"}` | `PowerOff` | `0x9F` / `BMCSubPowerOff` `0x04` | `platform_bmc_power_off` |
| Power reset | `Service.PowerReset` | `PowerReset` | `PowerReset` | `POST .../power` `{"action":"reset"}` | `PowerReset` | `0x9F` / `BMCSubPowerReset` `0x05` | `platform_bmc_power_reset` |
| Power cycle | `Service.PowerCycle` | `PowerCycle` | `PowerCycle` | `POST .../power` `{"action":"cycle"}` | `PowerCycle` | `0x9F` / `BMCSubPowerCycle` `0x06` | `platform_bmc_power_cycle` |
| Power status | `Service.PowerStatus` | `PowerStatus` | `PowerStatus` | `GET .../power` | `PowerStatus` | `0x9F` / `BMCSubPowerStatus` `0x07` | `platform_bmc_power_status` |

**All four power mutators share one REST path and method.** The action comes
from the body, so a REST client cannot be constrained to "may reset, may not
power off" by path-based authorization. Missing or unrecognized `action` is
`400` (`ErrMissingAction`, `ErrInvalidAction`).

Request/response shapes: gRPC `BMCPowerRequest{profile_id}` →
`BMCPowerResponse` (the SDK's `PowerResponse` exposes `PreviousState` and
`CurrentState`); `BMCPowerStatusRequest` → `BMCPowerStatusResponse{state}`.
`PowerState` on the wire is `ON` / `OFF` / `UNKNOWN` / `UNSPECIFIED`; in
`pkg/bmc` it is `"on"` / `"off"` / `"unknown"`. MCP arguments: `profile_id`;
the MCP result is the gRPC response, e.g.
`{"previous_state":"BMC_POWER_STATE_OFF","current_state":"BMC_POWER_STATE_ON"}`.

---

## 4. Boot device and virtual media

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Set boot device | `Service.SetBootDevice(ctx, id, device, persistent)` | `SetBootDevice` | `SetBootDevice` | `POST /api/v1/bmc/{profileID}/boot-device` | `SetBootDevice` | `0x9F` / `BMCSubSetBootDevice` `0x08` | `platform_bmc_set_boot_device` |
| Get boot device | `Service.GetBootDevice` | `GetBootDevice` | `GetBootDevice` | `GET .../boot-device` | `GetBootDevice` | `0x9F` / `BMCSubGetBootDevice` `0x09` | `platform_bmc_get_boot_device` |
| Mount ISO | `Service.MountISO(ctx, id, isoURL)` | `MountISO` | `MountISO` | `POST .../virtual-media` | `MountISO` | `0x9F` / `BMCSubMountISO` `0x0A` | `platform_bmc_mount_iso` |
| Unmount ISO | `Service.UnmountISO` | `UnmountISO` | `UnmountISO` | `DELETE .../virtual-media` | `UnmountISO` | `0x9F` / `BMCSubUnmountISO` `0x0B` | `platform_bmc_unmount_iso` |
| Virtual media status | `Service.VirtualMediaStatus` | `VirtualMediaStatus` | `VirtualMediaStatus` | `GET .../virtual-media` | `VirtualMediaStatus` | `0x9F` / `BMCSubVirtualMediaStatus` `0x0C` | `platform_bmc_virtual_media_status` |
| **Mount arbitrary media (`MediaSpec`)** | `Client.MountVirtualMedia(ctx, *MediaSpec)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Unmount arbitrary media** | `Client.UnmountVirtualMedia(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Clear UEFI boot entries** | `Client.ClearUEFIBootEntries(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

`BMCSetBootDeviceRequest{profile_id, device, persistent}`; REST body
`{"device": "...", "persistent": bool}`. Missing device is `400`
(`ErrMissingBootDevice`); unrecognized device is `400`
(`ErrInvalidBootDevice`).

`BootDevice` on the wire is `PXE` / `DISK` / `CDROM` / `VIRTUAL_MEDIA` / `NONE`
/ `UNSPECIFIED`; in `pkg/bmc` it is `pxe` / `disk` / `cdrom` / `virtual_media` /
`none`. **The CLI accepts a third, different set** — see [cli.md](cli.md) §4.

**Three `Client` methods have no transport at all.** `MountVirtualMedia`,
`UnmountVirtualMedia` and `ClearUEFIBootEntries` exist on the interface and are
implemented on both clients, and nothing outside the process can call them.
`ClearUEFIBootEntries` is the documented remedy for the X10 reflash trap — the
one operation an operator most wants remotely when a node keeps booting the
wrong thing — and it is in-process only.

Mount body `{"iso_url": "..."}`; missing URL is `400` (`ErrMissingISOURL`).
Virtual media is Redfish-only; on an IPMI client the call is delegated to a
lazily-created Redfish sub-client on port 443.

---

## 5. Sensors, inventory, provisioning

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Get sensors | `Service.GetSensors` | `GetSensors` | `GetSensors` | `GET /api/v1/bmc/{profileID}/sensors` | `GetSensors` | `0x9F` / `BMCSubGetSensors` `0x0D` | `platform_bmc_get_sensors` |
| Get system info | `Service.GetSystemInfo` | `GetSystemInfo` | `GetSystemInfo` | `GET .../system-info` | `GetSystemInfo` | `0x9F` / `BMCSubGetSystemInfo` `0x0E` | `platform_bmc_get_system_info` |
| **Hardware identity (quirk-matching)** | `bmc.Client.HardwareIdentity` | in-process only | in-process only | in-process only | in-process only | in-process only | in-process only |
| Provision | — (`baremetal` service) | `Provision` | `Provision` | `POST .../provision` | `Provision` | `0x9F` / `BMCSubProvision` `0x0F` | `platform_bmc_provision` |
| Provision status | — (`baremetal` service) | `ProvisionStatus` | `ProvisionStatus` | `GET .../provision` | `ProvisionStatus` | `0x9F` / `BMCSubProvisionStatus` `0x10` | `platform_bmc_provision_status` |
| **Host MAC discovery** | `bmc.DiscoverMAC` / `bmc.DiscoverMACs` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Protocol detection** | `bmc.DetectProtocol` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Vendor probe** | `VendorProbe.Detect` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

`HardwareIdentity` is deliberately in-process only rather than `MISSING`:
it exists so the bootstrap orchestrator can hand the installer the identity
the BMC client itself resolves quirks from, and that consumer runs in the
same process. It is not `SystemInfo` under another name — the two read
different fields, so an identity rebuilt from `SystemInfo` selects a
different registry entry (see
[`architecture.md`](architecture.md) and
[`../architecture/vendor-quirks.md`](../architecture/vendor-quirks.md)).
Exposing it on a transport would mean a `SystemInfo.PartNumber` change
across all six plus the proto and `sdk/go`; that is a separate decision and
is not made here.

**Provision and ProvisionStatus are registered and non-functional on a stock
daemon.** `pkg/api/daemon/daemon.go` passes `nil` for the baremetal
orchestrator, so both RPCs answer `Unavailable` (service not configured) until
one is wired via `SetBaremetalService`. On REST the equivalent is `503`
(`ErrBaremetalServiceNotAvailable`). Provisioning error mapping when the
orchestrator *is* wired: `409` `ErrProvisionInProgress`, `400`
`ErrInvalidProvisionRequest` and `ErrProfileNoBMC`, `404`
`ErrProvisionNotFound`.

**MAC discovery is remote-reachable only through the CLI's standalone path.**
`platformctl bmc mac` and `platformctl bootstrap discover` both call
`DiscoverMACs` in process. There is no route, on any transport.

---

## 6. Certificates, users, and the two ceremonies

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Get web certificate | `Service.GetWebCertificate` | `GetWebCertificate` | `GetWebCertificate` | `GET /api/v1/bmc/{profileID}/cert` | `GetWebCertificate` | `0x9F` / `BMCSubGetWebCertificate` `0x11` | `platform_bmc_get_web_certificate` |
| Replace web certificate | `Service.ReplaceWebCertificate` | `ReplaceWebCertificate` | `ReplaceWebCertificate` | `PUT .../cert` | `ReplaceWebCertificate` | `0x9F` / `BMCSubReplaceWebCertificate` `0x12` | `platform_bmc_replace_web_certificate` |
| List users | `Service.ListUsers` | `ListUsers` | `ListUsers` | `GET .../users` | `ListUsers` | `0x9F` / `BMCSubListUsers` `0x13` | `platform_bmc_list_users` |
| Create user | `Service.CreateUser` | `CreateUser` | `CreateUser` | `POST .../users` | `CreateUser` | `0x9F` / `BMCSubCreateUser` `0x14` | `platform_bmc_create_user` |
| Delete user | `Service.DeleteUser` | `DeleteUser` | `DeleteUser` | `DELETE .../users/{slot}` | `DeleteUser` | `0x9F` / `BMCSubDeleteUser` `0x15` | `platform_bmc_delete_user` |
| Set user password | `Service.SetUserPassword` | `SetUserPassword` | `SetUserPassword` | `PUT .../users/{slot}/password` | `SetUserPassword` | `0x9F` / `BMCSubSetUserPassword` `0x16` | `platform_bmc_set_user_password` |
| Set user privilege | `Service.SetUserPrivilege` | `SetUserPrivilege` | `SetUserPrivilege` | `PUT .../users/{slot}/privilege` | `SetUserPrivilege` | `0x9F` / `BMCSubSetUserPrivilege` `0x17` | `platform_bmc_set_user_privilege` |
| **Enrollment ceremony** | `App.EnrollBMC(ctx, deviceID, cfg, opts)` | `EnrollBMC` | `EnrollBMC` | `POST .../enroll` | `EnrollBMC` | `0x9F` / `BMCSubEnroll` `0x01` | `platform_bmc_enroll` |
| **Factory-cert restore** | `App.RestoreBMC(ctx, deviceID, cfg)` | `RestoreFactoryCert` | `RestoreFactoryCert` | `POST .../cert/restore` | `RestoreFactoryCert` | `0x9F` / `BMCSubRestore` `0x02` | `platform_bmc_cert_restore` |
| **Password rotation** | `RotationEngine.RotateOnce` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Credential store CRUD** | `CredentialStore` (`Get`/`Put`/`Delete`/`List`/`History`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

QUIC, MCP and the embedded transport carry every certificate, user and
ceremony operation gRPC carries; only REST's SDK client falls short (§9).

MCP carries every certificate and user operation gRPC carries, under the same
`bmc:admin` scope (§8). Their arguments hold secrets exactly as the gRPC
requests do: `platform_bmc_replace_web_certificate` takes `cert_pem` and
`key_pem` (base64 of the PEM bytes), and `platform_bmc_create_user` and
`platform_bmc_set_user_password` take `password` in clear. `create_user` takes
`user` as a `BMCUser` object (`slot`, `username`, `enabled`, `privilege`,
`channel`); privileges are `BMC_USER_PRIVILEGE_*` names.

REST request/response detail:

- `PUT .../cert` body carries `cert_pem` and `key_pem`; missing either is `400`
  (`ErrMissingCertPEM`, `ErrMissingKeyPEM`).
- `POST .../users` requires `username`, `password` and `privilege`; each missing
  field is its own `400` (`ErrMissingUsername`, `ErrMissingPassword`,
  `ErrMissingPrivilege`).
- `POST .../enroll` body is `EnrollRequest` — four **optional** booleans
  `replace_certificate`, `rotate_password`, `dns_register`, `dane_publish`. An
  absent field keeps the profile's stored default; `{}` is a valid body. The
  response is `EnrollResponse`, whose `steps[]` is `{name, ok, detail}` per
  step. `503` `ErrBMCEnrollerNotAvailable` when the enroller is not wired;
  `400` `ErrInvalidRequestBody` on malformed JSON.
- `POST .../cert/restore` needs no body; `503` `ErrBMCRestorerNotAvailable`
  when the restorer is not wired.

QUIC payload shapes (`pkg/api/daemon/quic_bmc.go`): a request under
`OpBMCCategory` is the sub-opcode byte followed by the RPC's request message
(`BMCEnrollRequest`, `BMCPowerRequest`, ...), MessagePack-encoded; the response
payload is the RPC's response message, encoded the same way. The daemon looks
the sub-opcode up in `bmcQUICHandlers` and calls the gRPC servicer, so the
enrollment ceremony's optional booleans keep their gRPC meaning: an absent
field keeps the profile's stored default.

A servicer refusal comes back as the QUIC status its gRPC code maps to
(`grpcDelegateCodeToQUICStatus` in `pkg/api/daemon/quic_grpc_delegates.go`):
`InvalidArgument` is `StatusInvalidArgument`, `NotFound` is `StatusNotFound`,
`PermissionDenied` is `StatusPermissionDenied`, `FailedPrecondition` is
`StatusInvalidRequest`, `Unavailable` is `StatusUnavailable`. The handler
refuses three cases itself: a daemon with no BMC service is
`StatusUnavailable` (`ErrQUICServiceUnavailable{Service: "bmc"}`), an empty
payload (no sub-opcode) is `StatusInvalidRequest`, and an unknown sub-opcode
is `StatusNotImplemented`.

**The `EnrollBMC` response carries the factory certificate PEM over the
wire,** on every transport. That is the ceremony's identity evidence, and it is
a certificate, not a key.

---

## 7. Status and error mapping

Status bytes and their REST equivalents are the platform-wide table in
[`docs/daemon/api.md`](../daemon/api.md) §4. BMC-specific causes:

| REST | QUIC | BMC cause |
|---|---|---|
| 200 | `StatusOK` | — |
| 400 | `StatusInvalidRequest` / `StatusInvalidArgument` | `ErrMissingAction`, `ErrInvalidAction`, `ErrMissingBootDevice`, `ErrInvalidBootDevice`, `ErrMissingISOURL`, `ErrMissingCertPEM`, `ErrMissingKeyPEM`, `ErrMissingUsername`, `ErrMissingPassword`, `ErrMissingPrivilege`, `ErrInvalidRequestBody`, `bmc.ErrInvalidConfig`, `baremetal.ErrInvalidProvisionRequest`, `baremetal.ErrProfileNoBMC` |
| 404 | `StatusNotFound` | `bmc.ErrProfileNotFound` (profile absent, **or has no BMC block, or no `ProfileStore` is wired** — all three are indistinguishable), `baremetal.ErrProvisionNotFound` |
| 409 | `StatusAlreadyExists` | `baremetal.ErrProvisionInProgress` |
| 500 | `StatusInternalError` | `ErrServiceError{Operation, Cause}` wrapping any `pkg/bmc` failure — `ErrConnectionFailed`, `ErrPowerOperation`, `ErrBootDevice`, `ErrVirtualMedia`, `ErrSensorRead`, `ErrInventory`, `ErrAutoCert*`, `ErrRotation*` |
| 503 | `StatusUnavailable` | service not configured: no BMC service (QUIC, MCP, gRPC), no profile store, enroller, restorer or baremetal orchestrator (`ErrBMCEnrollerNotAvailable`, `ErrBMCRestorerNotAvailable`, `ErrBaremetalServiceNotAvailable` on REST) |
| 501 | `StatusNotImplemented` | QUIC only: unknown sub-opcode under `0x9F` |

REST bodies are the platform envelope:

```json
{"code": 400, "success": false, "error": "bmc: invalid action: destroy", "payload": null}
```

**`writeBMCError` collapses everything that is not `ErrProfileNotFound` into a
`500`.** A BMC that is powered off, unreachable, or refusing the credential all
surface identically as "internal error" with the cause in the message string.
Clients cannot distinguish "the platform broke" from "the BMC is not answering"
by status code; read the `error` string.

---

## 8. Authorization

The gRPC, MCP and QUIC catalogs are **default-deny** ([`docs/auth/architecture.md`](../auth/architecture.md)),
and every BMC entry point on them carries a required scope. One vocabulary
serves all three:

| Permission | Meaning | gRPC `BMCService` RPCs | MCP `platform_bmc_*` tools |
|---|---|---|---|
| `bmc:read` | observation | `PowerStatus`, `GetBootDevice`, `VirtualMediaStatus`, `GetSensors`, `GetSystemInfo`, `ListUsers`, `GetWebCertificate`, `ProvisionStatus` | `power_status`, `get_boot_device`, `virtual_media_status`, `get_sensors`, `get_system_info`, `list_users`, `get_web_certificate`, `provision_status` |
| `bmc:write` | recoverable state change | `PowerOn`, `SetBootDevice` | `power_on`, `set_boot_device` |
| `bmc:power` | interrupts a running node | `PowerOff`, `PowerReset`, `PowerCycle` | `power_off`, `power_reset`, `power_cycle` |
| `bmc:media` | chooses what the machine boots | `MountISO`, `UnmountISO` | `mount_iso`, `unmount_iso` |
| `bmc:admin` | changes which credentials the BMC trusts | `EnrollBMC`, `RestoreFactoryCert`, `ReplaceWebCertificate`, `CreateUser`, `DeleteUser`, `SetUserPassword`, `SetUserPrivilege`, `Provision` | `enroll`, `cert_restore`, `replace_web_certificate`, `create_user`, `delete_user`, `set_user_password`, `set_user_privilege`, `provision` |

Each MCP tool's scope is held on its `bmcTools` entry in
`pkg/api/mcp/bmc_tools.go`, and a unit test holds it equal to its RPC's scope
in `pkg/api/grpc/method_permissions.go`.

Each QUIC sub-opcode under `OpBMCCategory` (`0x9F`) requires the scope of its
RPC, held in `pkg/api/quic/opcode_permissions.go`;
`pkg/api/daemon/bmc_quic_sdk_test.go` calls every sub-opcode holding only its
RPC's gRPC scope. A sub-opcode the table does not classify is refused (#767). The
embedded transport checks no scope (§2).

`Provision` takes `bmc:admin` because it composes boot device, virtual media and
power in one call: neither `bmc:media` nor `bmc:power` alone may confer the
whole sequence. A caller without the scope is refused with `PermissionDenied`
(gRPC) or `AuthErrorPermissionDenied` (MCP).

The daemon REST listener takes the same scopes from the gRPC catalog (#997
s12). Every `/api/v1/bmc/{profileID}/...` route is mounted behind the REST scope
guard: a request without a credential gets 401, and one without the scope of
the route's RPC gets 403. Each route's RPC is its `catalogRouteRPCs` entry in
`pkg/api/daemon/rest_scope.go`, and the scope is
`grpcapi.ScopeForMethod(rpc)`, so REST cannot drift from gRPC.

`POST .../power` serves all four power RPCs, and its body's `action` picks
which. The guard reads the body (at most 1 KiB), decodes only `action`, maps
`on`, `off`, `reset`, `cycle` to `PowerOn`, `PowerOff`, `PowerReset`,
`PowerCycle`, requires that RPC's scope, and hands the handler the same
bytes. So `on` needs `bmc:write`, and the other three need `bmc:power`. A
body over the limit, a body that is not JSON, or a missing or unknown action
gets 403 (`ErrBMCPowerActionUnscoped`) before the handler runs. The guard
never falls back to `bmc:write`.

[`docs/daemon/api.md`](../daemon/api.md) §5 records the platform-wide picture
and the catalog totals.

## 9. SDK mapping: every transport but REST reaches all 23 methods

The `sdk/go` BMC client (`services/bmc`) issues gRPC method strings; each
transport adapter maps them onto its own wire:

| Transport | SDK mapping | Methods mapped |
|---|---|---|
| gRPC, Unix | the generated `BMCServiceClient` | 23 of 23 |
| QUIC | `sdk/go/transport/quic/aab_bmc.go` (`bmcSubOpcodes`): method → `0x9F` sub-opcode | 23 of 23 |
| MCP | `sdk/go/transport/mcp/bmc.go`: method → `platform_bmc_*` tool | 23 of 23 |
| Embedded | `sdk/go/transport/embedded/dispatch.go` (`registerBMCHandlers`): method → `ServiceRegistry.BMC` | 23 of 23 |
| REST | `sdk/go/transport/rest/adapter.go`: method → route template | **14 of 23** |

A client on QUIC, MCP or embedded gets the reply and the refusal code its
gRPC call gives.

`sdk/go/transport/rest/adapter.go` templates gRPC method strings onto REST
routes. It defines **14 of the 23 `platform.v1.BMCService` methods**: the five
power RPCs, both boot-device RPCs, three virtual-media RPCs, sensors, system
info, and both provisioning RPCs.

Not mapped: `GetWebCertificate`, `ReplaceWebCertificate`, `ListUsers`,
`CreateUser`, `DeleteUser`, `SetUserPassword`, `SetUserPrivilege`, `EnrollBMC`,
`RestoreFactoryCert`.

So an SDK client on `--transport rest` cannot reach certificate management,
user management or either ceremony — **even though `platformd` serves all of
those routes**. This is a client-side gap, distinct from the transport gaps in
§3–§6, and it is why the `platformctl bmc cert` / `enroll` / `user` verbs use
the gRPC path rather than the raw-HTTP path the other verbs use.



## 10. Two REST route registries, and they disagree

BMC routes are registered in two places:

| Registrar | Routes | Includes enroll / cert-restore? |
|---|---|---|
| `pkg/api/daemon/rest_service.go` | 20 registrations, 13 paths | **Yes** |
| `pkg/webservice/v1/router/bmc.go` (`BMCRouter`) | 18 registrations | **No** |

`BMCRouter` covers power, boot device, virtual media, sensors, system info,
provision, cert get/replace and the five user routes — and omits
`POST /bmc/{profileID}/enroll` and `POST /bmc/{profileID}/cert/restore`,
even though `bmc.RestHandler` declares `EnrollBMC` and the handler implements
it. A deployment served by `BMCRouter` rather than the daemon REST service has
no enrollment endpoint. The bootstrap orchestrator hardcodes
`"/api/v1/bmc/%d/enroll"`, so it depends on the daemon registrar.

## 11. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. Nothing in the BMC surface is deprecated.

`OpBMCCategory` is `0x9F`. Sub-opcodes `0x01`–`0x17` are the whole namespace
today, one per `BMCService` RPC. Adding one for a new RPC is a constant in
`sdk/go/wire/quicwire/phase35_opcodes.go`, an entry in `bmcQUICHandlers`
(`pkg/api/daemon/quic_bmc.go`), an entry in the SDK's `bmcSubOpcodes`
(`sdk/go/transport/quic/aab_bmc.go`), and its scope in
`pkg/api/quic/opcode_permissions.go`.
Remember that sub-opcode values are only unique **within** the `0x9F`
category — `0x01` at top level is `OpLiveness`. The rule and the full opcode
table are in [`docs/daemon/api.md`](../daemon/api.md) §4.

## 12. Summary of tracked gaps

| Gap | Rows affected |
|---|---|
| `MountVirtualMedia`, `UnmountVirtualMedia`, `ClearUEFIBootEntries` have no transport | 3 |
| MAC discovery, protocol detection, vendor probe have no transport | 3 |
| Password rotation and credential-store CRUD have no transport | 2 |
| SDK REST adapter maps 14 of 23 RPCs | 9 |
| `BMCRouter` omits enroll and cert-restore | 2 |

All are recorded as `docs/13 G7` debt, not as design.

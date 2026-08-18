# BMC — API

> **Status: NORMATIVE** · Scope: BMC routes on every transport · Last verified: 2026-08-18
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
| **REST** | base path `/api/v1/bmc/{profileID}`, **20 route registrations over 17 paths** | `pkg/api/daemon/rest_service.go`; handlers in `pkg/webservice/v1/bmc/` |
| **QUIC** | `OpBMCCategory` = `0x9F`, sub-opcodes `BMCSubEnroll` `0x01` and `BMCSubRestore` `0x02` — **two operations, nothing else** | `pkg/api/quic/phase35_opcodes.go`; handler `pkg/api/daemon/quic_bmc.go` |
| **MCP** | **16 tools**, all named `platform_bmc_*` | `pkg/api/mcp/bmc_tools.go` |
| **Embedded** | **None** | see §2 |

## 2. Embedded has no BMC route at all

`ServiceRegistry` (`sdk/go/transport/embedded/adapter.go`) is the complete
reach of the embedded transport. Its fields are Daemon, CA, TPM, VTPM, Device,
IAM, KMS, SDN, Compute, IDevID, Attestation, Tenant, PXE, DNS, Gateway, Proxy,
Overlay, Registry, Cluster, EAB, Invitation, ConfigDelivery.

**There is no `BMC` field.** Every embedded cell in the tables below is
therefore `MISSING — docs/13 G7`, for every capability, without exception.

This matters more than the usual gap: BMC is a **Tier 1** capability in the
ownership register — *"Zero-touch provisioning — BMC (Redfish/IPMI), iPXE/network
boot, installer"*, SDK surface `services/bmc` — and Tier 1 requires all six
transports. `platformctl --transport embedded bmc ...` cannot
work. Standalone mode (`--bmc-host`) is the only daemonless path, and it is a
different thing: direct hardware access with no audit log and no persistence.

There is a second, subtler embedded-adjacent gap: **the "embedded Go call"
column below is the `pkg/bmc` in-process API**, which is fully populated. A
capability that is reachable in-process and absent from `ServiceRegistry` is
implemented but unexported — which is exactly the shape of debt `docs/13`
exists to track.

---

## 3. Power

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Power on | `Service.PowerOn(ctx, profileID)` | `MISSING — docs/13 G7` | `PowerOn` | `POST /api/v1/bmc/{profileID}/power` `{"action":"on"}` | `PowerOn` | `MISSING — docs/13 G7` | `platform_bmc_power_on` |
| Power off | `Service.PowerOff` | `MISSING — docs/13 G7` | `PowerOff` | `POST .../power` `{"action":"off"}` | `PowerOff` | `MISSING — docs/13 G7` | `platform_bmc_power_off` |
| Power reset | `Service.PowerReset` | `MISSING — docs/13 G7` | `PowerReset` | `POST .../power` `{"action":"reset"}` | `PowerReset` | `MISSING — docs/13 G7` | `platform_bmc_power_reset` |
| Power cycle | `Service.PowerCycle` | `MISSING — docs/13 G7` | `PowerCycle` | `POST .../power` `{"action":"cycle"}` | `PowerCycle` | `MISSING — docs/13 G7` | `platform_bmc_power_cycle` |
| Power status | `Service.PowerStatus` | `MISSING — docs/13 G7` | `PowerStatus` | `GET .../power` | `PowerStatus` | `MISSING — docs/13 G7` | `platform_bmc_power_status` |

**All four power mutators share one REST path and method.** The action comes
from the body, so a REST client cannot be constrained to "may reset, may not
power off" by path-based authorization. Missing or unrecognized `action` is
`400` (`ErrMissingAction`, `ErrInvalidAction`).

Request/response shapes: gRPC `BMCPowerRequest{profile_id}` →
`BMCPowerResponse` (the SDK's `PowerResponse` exposes `PreviousState` and
`CurrentState`); `BMCPowerStatusRequest` → `BMCPowerStatusResponse{state}`.
`PowerState` on the wire is `ON` / `OFF` / `UNKNOWN` / `UNSPECIFIED`; in
`pkg/bmc` it is `"on"` / `"off"` / `"unknown"`. MCP arguments: `profile_id`.

---

## 4. Boot device and virtual media

| Capability | Embedded Go call | Embedded transport | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|---|
| Set boot device | `Service.SetBootDevice(ctx, id, device, persistent)` | `MISSING — docs/13 G7` | `SetBootDevice` | `POST /api/v1/bmc/{profileID}/boot-device` | `SetBootDevice` | `MISSING — docs/13 G7` | `platform_bmc_set_boot_device` |
| Get boot device | `Service.GetBootDevice` | `MISSING — docs/13 G7` | `GetBootDevice` | `GET .../boot-device` | `GetBootDevice` | `MISSING — docs/13 G7` | `platform_bmc_get_boot_device` |
| Mount ISO | `Service.MountISO(ctx, id, isoURL)` | `MISSING — docs/13 G7` | `MountISO` | `POST .../virtual-media` | `MountISO` | `MISSING — docs/13 G7` | `platform_bmc_mount_iso` |
| Unmount ISO | `Service.UnmountISO` | `MISSING — docs/13 G7` | `UnmountISO` | `DELETE .../virtual-media` | `UnmountISO` | `MISSING — docs/13 G7` | `platform_bmc_unmount_iso` |
| Virtual media status | `Service.VirtualMediaStatus` | `MISSING — docs/13 G7` | `VirtualMediaStatus` | `GET .../virtual-media` | `VirtualMediaStatus` | `MISSING — docs/13 G7` | `platform_bmc_virtual_media_status` |
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
| Get sensors | `Service.GetSensors` | `MISSING — docs/13 G7` | `GetSensors` | `GET /api/v1/bmc/{profileID}/sensors` | `GetSensors` | `MISSING — docs/13 G7` | `platform_bmc_get_sensors` |
| Get system info | `Service.GetSystemInfo` | `MISSING — docs/13 G7` | `GetSystemInfo` | `GET .../system-info` | `GetSystemInfo` | `MISSING — docs/13 G7` | `platform_bmc_get_system_info` |
| Provision | — (`baremetal` service) | `MISSING — docs/13 G7` | `Provision` | `POST .../provision` | `Provision` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Provision status | — (`baremetal` service) | `MISSING — docs/13 G7` | `ProvisionStatus` | `GET .../provision` | `ProvisionStatus` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Host MAC discovery** | `bmc.DiscoverMAC` / `bmc.DiscoverMACs` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Protocol detection** | `bmc.DetectProtocol` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Vendor probe** | `VendorProbe.Detect` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

**Provision and ProvisionStatus are registered and non-functional on a stock
daemon.** `pkg/api/daemon/daemon.go` passes `nil` for the baremetal
orchestrator, and the code comment states that both RPCs "return
FailedPrecondition until a baremetal orchestrator is wired via
`SetBaremetalService`". On REST the equivalent is `500`
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
| Get web certificate | `Service.GetWebCertificate` | `MISSING — docs/13 G7` | `GetWebCertificate` | `GET /api/v1/bmc/{profileID}/cert` | `GetWebCertificate` | `MISSING — docs/13 G7` | `platform_bmc_get_web_certificate` |
| Replace web certificate | `Service.ReplaceWebCertificate` | `MISSING — docs/13 G7` | `ReplaceWebCertificate` | `PUT .../cert` | `ReplaceWebCertificate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| List users | `Service.ListUsers` | `MISSING — docs/13 G7` | `ListUsers` | `GET .../users` | `ListUsers` | `MISSING — docs/13 G7` | `platform_bmc_list_users` |
| Create user | `Service.CreateUser` | `MISSING — docs/13 G7` | `CreateUser` | `POST .../users` | `CreateUser` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Delete user | `Service.DeleteUser` | `MISSING — docs/13 G7` | `DeleteUser` | `DELETE .../users/{slot}` | `DeleteUser` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Set user password | `Service.SetUserPassword` | `MISSING — docs/13 G7` | `SetUserPassword` | `PUT .../users/{slot}/password` | `SetUserPassword` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Set user privilege | `Service.SetUserPrivilege` | `MISSING — docs/13 G7` | `SetUserPrivilege` | `PUT .../users/{slot}/privilege` | `SetUserPrivilege` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Enrollment ceremony** | `App.EnrollBMC(ctx, deviceID, cfg, opts)` | `MISSING — docs/13 G7` | `EnrollBMC` | `POST .../enroll` | `EnrollBMC` | `OpBMCCategory` `0x9F` / `BMCSubEnroll` `0x01` | `platform_bmc_enroll` |
| **Factory-cert restore** | `App.RestoreBMC(ctx, deviceID, cfg)` | `MISSING — docs/13 G7` | `RestoreFactoryCert` | `POST .../cert/restore` | `RestoreFactoryCert` | `OpBMCCategory` `0x9F` / `BMCSubRestore` `0x02` | `platform_bmc_cert_restore` |
| **Password rotation** | `RotationEngine.RotateOnce` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Credential store CRUD** | `CredentialStore` (`Get`/`Put`/`Delete`/`List`/`History`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

The two ceremonies are the **only** BMC capabilities on QUIC, and the only ones
present on five of the six transports.

**Four of five user-management operations are MCP-invisible.** An MCP client can
enumerate BMC accounts but cannot create, delete, re-password or re-privilege
one. Given §8, that is the safer half of the asymmetry — but it is an asymmetry,
not a decision recorded anywhere in code.

**`platform_bmc_cert_restore` is on MCP and `platform_bmc_replace_web_certificate`
is not.** An MCP client can strip a BMC's platform-issued identity and cannot
give it one back. Restore is the destructive direction.

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
  step. `500` `ErrBMCEnrollerNotAvailable` when the enroller is not wired;
  `400` `ErrInvalidRequestBody` on malformed JSON.
- `POST .../cert/restore` needs no body.

QUIC payload shapes (`pkg/api/daemon/quic_bmc.go`, MessagePack):
`QUICBMCEnrollRequest{profile_id, replace_certificate?, rotate_password?,
dns_register?, dane_publish?}` — the optional fields are `*bool` precisely so
omission preserves profile defaults —
`QUICBMCEnrollResponse{device_id, endpoint, hostname, dns_name?,
pin_spki_sha256, factory_cert_pem?, factory_cert_meta, new_cert_pem?,
ca_cert_pem?, steps[], timestamp}`, with
`QUICBMCFactoryCertMetaResponse{subject, issuer, serial_number, not_before,
not_after, spki_sha256, sha256, captured_at}`.

`profile_id == 0` on QUIC is `StatusInvalidArgument`; a profile that will not
load is `StatusNotFound`; an unwired enroller or restorer is
`StatusUnavailable` (`bmc-enroll` / `bmc-restore`); an unknown sub-opcode is
`StatusNotImplemented`.

**`QUICBMCEnrollResponse` carries the factory certificate PEM over the wire.**
That is the ceremony's identity evidence, and it is a certificate, not a key —
but it is the reason the QUIC response is the largest BMC payload on any
transport.

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
| 500 | `StatusInternalError` | `ErrServiceError{Operation, Cause}` wrapping any `pkg/bmc` failure — `ErrConnectionFailed`, `ErrPowerOperation`, `ErrBootDevice`, `ErrVirtualMedia`, `ErrSensorRead`, `ErrInventory`, `ErrAutoCert*`, `ErrRotation*`; plus `ErrBMCEnrollerNotAvailable`, `ErrBaremetalServiceNotAvailable` |
| 503 | `StatusUnavailable` | QUIC only: the enroller or restorer is not wired |
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

BMC is **not enforced on either catalog**, and both catalogs are default-allow.

| Catalog | BMC coverage | Effect |
|---|---|---|
| gRPC (`pkg/api/grpc/method_permissions.go`) | **`BMCService` is absent entirely.** Zero of 23 RPCs carry a required scope | The interceptor allows every BMC RPC once the token validates |
| MCP (`pkg/api/mcp/authz.go`) | **No `bmc` entries.** Zero of 16 tools carry a permission | `AuthorizeTool` returns no error for unlisted tools |

Consequences, stated plainly because they are not obvious from the code:

- **Any principal with a valid platform token can power off any node**, set its
  boot device, mount an installer ISO, replace or restore its BMC certificate,
  and create a BMC administrator account. No `scp` claim is checked on any of
  it.
- Because all four power mutators share `POST .../power` with the verb in the
  body, even a path-based gateway policy in front of REST cannot separate
  "status" from "power off" beyond method.
- The QUIC handlers pass `req.Token` into the sub-request and dispatch; there is
  no BMC-specific scope check on that path either.

[`docs/daemon/api.md`](../daemon/api.md) §5 records the platform-wide picture:
185 of 461 gRPC RPCs across 11 of 31 services carry scopes, and 71 of 449 MCP
tools do. `BMCService` is named there among the services not in the catalog.
**Whether both catalogs should default to deny is an open owner question**, not
settled by this document.

## 9. The SDK's REST transport reaches only part of the surface

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
| `pkg/api/daemon/rest_service.go` | 20 registrations, 17 paths | **Yes** |
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

`OpBMCCategory` is `0x9F`. Sub-opcodes `0x01` and `0x02` are the whole
namespace today; adding a third is a data change in
`pkg/api/quic/phase35_opcodes.go` plus a case in `handleBMCCategory`.
Remember that sub-opcode values are only unique **within** the `0x9F`
category — `0x01` at top level is `OpLiveness`. The rule and the full opcode
table are in [`docs/daemon/api.md`](../daemon/api.md) §4.

## 12. Summary of tracked gaps

| Gap | Rows affected |
|---|---|
| No BMC in the embedded `ServiceRegistry` | **every** capability |
| QUIC carries only the two ceremonies | 21 of 23 RPC-backed capabilities |
| MCP omits provision, provision-status, replace-cert, and four user verbs | 7 |
| `MountVirtualMedia`, `UnmountVirtualMedia`, `ClearUEFIBootEntries` have no transport | 3 |
| MAC discovery, protocol detection, vendor probe have no transport | 3 |
| Password rotation and credential-store CRUD have no transport | 2 |
| SDK REST adapter maps 14 of 23 RPCs | 9 |
| `BMCRouter` omits enroll and cert-restore | 2 |
| Neither authorization catalog covers BMC | all 23 RPCs, all 16 tools |

All are recorded as `docs/13 G7` debt, not as design.

# Managed Switch Provisioning — API

> **Status: NORMATIVE** · Scope: physical-switch routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

The transport model, the QUIC frame format and category-opcode table, the
status-byte vocabulary and the two authorization catalogs are documented once
in [`docs/daemon/api.md`](../daemon/api.md). Only what is specific to switches
appears here.

- **Unix is gRPC over a Unix domain socket**, so gRPC and Unix share a column.
  `platformv1.RegisterSwitchServiceServer` is called for **both** the TCP gRPC
  server and the UDS server (`pkg/api/daemon/daemon.go:1031,1034`).
- gRPC: `SwitchService`, **5 RPCs** (`pkg/api/grpc/proto/switch.proto`).
- REST: base path `/api/v1/switches`
  (`pkg/webservice/v1/rest/switch/router.go`).
- QUIC: **category opcode `OpSwitchCategory` (`0xCC`)** with five sub-opcodes
  (`sdk/go/wire/quicwire/switch_opcodes.go`). `switchQUICHandlers` in
  `pkg/api/daemon/quic_switch.go` routes each sub-opcode, through the
  `appQUICCategories` table, to the same `SwitchGRPCService` servicer gRPC
  serves, so QUIC has no second implementation either (#704).
- MCP: five tools (`pkg/api/mcp/switch_tools.go`), one per RPC. Each decodes
  its arguments into the gRPC request and calls the daemon's
  `SwitchGRPCService` — the servicer gRPC serves — so MCP has no second
  implementation (#704).
- Embedded: `ServiceRegistry.Switch` (`sdk/go/transport/embedded/adapter.go`),
  dispatched by `registerSwitchHandlers` in
  `sdk/go/transport/embedded/dispatch.go`. The daemon's embedded host fills it
  from the same `SwitchGRPCService` (`pkg/api/daemon/embedded_host.go`).
- SDK: `Client.Switch()` (`sdk/go/client.go`) returns the generated
  `platformv1.SwitchServiceClient` and rides every transport adapter — gRPC,
  Unix, REST, QUIC, MCP and embedded. Each adapter's mapping is listed in
  [`docs/sdk/api.md`](../sdk/api.md) §1; the MCP adapter's is
  `sdk/go/transport/mcp/switch.go`.
- `sdk/go/services/switch` is the older **REST-only** client,
  `NewClient(baseURL string, httpClient *http.Client)`; it speaks HTTP
  directly and cannot be pointed at another transport. `platformctl switch`
  uses it.

## 2. The embedded transport

The in-process caller reaches the five port operations through
`ServiceRegistry.Switch`. The embedded transport runs no scope interceptor:
the caller is the daemon's own process. A host whose registry has no switch
servicer leaves the methods out of the dispatch map, so each answers
`Unimplemented` rather than dereferencing a nil servicer.

---

## 3. Port operations

REST path parameters are `{switch}` and `{port}`. The subrouter calls
`UseEncodedPath()` because **port names contain slashes** — `Eth1/3` must be
sent as `Eth1%2F3` — and the handlers `url.PathUnescape` them before use. A
client that sends a raw slash will match a different route or none.

| Capability | REST | gRPC / Unix | QUIC (under `0xCC`) | MCP | Embedded |
|---|---|---|---|---|---|
| List ports | `GET /api/v1/switches/{switch}/ports` | `ListPorts` | `SwitchSubListPorts` (`0x01`) | `switch_list_ports` | `ServiceRegistry.Switch` |
| Get port status | `GET /api/v1/switches/{switch}/ports/{port}` | `GetPortStatus` | `SwitchSubGetPortStatus` (`0x02`) | `switch_port_status` | `ServiceRegistry.Switch` |
| Set port VLAN | `POST /api/v1/switches/{switch}/ports/{port}/vlan` | `SetPortVLAN` | `SwitchSubSetPortVLAN` (`0x03`) | `switch_set_vlan` | `ServiceRegistry.Switch` |
| Enable port | `POST /api/v1/switches/{switch}/ports/{port}/enable` | `EnablePort` | `SwitchSubEnablePort` (`0x04`) | `switch_enable_port` | `ServiceRegistry.Switch` |
| Disable port | `POST /api/v1/switches/{switch}/ports/{port}/disable` | `DisablePort` | `SwitchSubDisablePort` (`0x05`) | `switch_disable_port` | `ServiceRegistry.Switch` |
| Get port VLAN only | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `Manager.GetPortVLAN` |

`Manager.GetPortVLAN` is part of the `Manager` interface, implemented by the
SSH driver, and exposed on **no transport at all**. Its information is a strict
subset of `GetPortStatus`, which is presumably why — but it is a real interface
method with no route, so it is a row here rather than an omission.

The other five capabilities are **complete on all six transports**, which
makes this one of the more uniform surfaces in the platform. The uniformity
holds only while the service is wired — see §9.

---

## 4. Switch configuration (bootstrap)

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Configure VLANs | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `Configurator.ConfigureVLANs` |
| Configure ports | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `Configurator.ConfigurePorts` |
| Configure switch (VLANs + ports) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `Configurator.Configure` |
| Verify switch against config | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in-process Go only: `Configurator.Verify` |

**Unlike §3, this is a decision rather than a gap.** `Service` deliberately
exposes only `Manager`; the source states *"The Service layer doesn't execute
ConfigureVLANs/ConfigurePorts (no Configurator exposed)."* The `Configurator`
is reached exactly once, from `pkg/bootstrap/orchestrator.go::configureSwitch`,
because VLAN creation writes `copy running-config startup-config` and is not
something a runtime API should offer ([architecture.md](architecture.md) §2.1).

Exposing these later would need a decision about NVRAM persistence first, not
just a route.

---

## 5. Wire contract

### 5.1 REST

`SetPortVLAN` body:

```json
{ "vlan_id": 200 }
```

`vlan_id` is `uint16`. `0` ⇒ 400 `ErrMissingVLANID`; `> 4094` ⇒ 400
`ErrInvalidVLANID`. `EnablePort` and `DisablePort` take **no body**.

The SDK REST transport claims exactly these routes
(`sdk/go/transport/rest/switches.go`, #452): `switch_name` and `port_name`
travel only in the path, escaped, and only `vlan_id` travels in the body. A
request missing either name is refused with `InvalidArgument` before it is
sent.

Responses are wrapped in the platform `WebServiceResponse` envelope
(`{success, payload, error}`). The SDK unwraps it and builds the gRPC reply
from the payload: `PortStatus` becomes `SwitchPortStatus`, and an
acknowledgement whose `status` is `"ok"` becomes the same `Status` the gRPC
service returns. Any other `status` is an error
(`ErrSwitchActionNotAcknowledged`). Success payloads:

| Route | Payload |
|---|---|
| `GET .../ports` | `[]*switchwire.PortStatus` |
| `GET .../ports/{port}` | `*switchwire.PortStatus` |
| `POST .../vlan` | `{"switch":…,"port":…,"vlan_id":…,"status":"ok"}` |
| `POST .../enable` \| `.../disable` | `{"switch":…,"port":…,"action":"enable"\|"disable","status":"ok"}` |

`PortStatus` (`sdk/go/wire/switchwire/port.go`) JSON: `port`, `mode` (`"access"` \| `"trunk"`), `access_vlan`,
`trunk_vlans` (omitted when empty), `native_vlan` (omitted when none), `enabled`, `link_up`, `description`
(omitted when empty).

### 5.2 QUIC

The category opcode is a **single byte followed by a sub-opcode byte**: the
daemon reads `req.Payload[0]` as the sub-opcode and treats `req.Payload[1:]` as
the sub-request. **The sub-request is the generated `platform.v1` protobuf
message**, MessagePack-encoded — the same message gRPC uses. The source is
explicit:

> *"The SDK QUIC transport adapter routes every SwitchService method to
> OpSwitchCategory … and encodes the generated platform.v1 protobuf request
> struct directly under the category sub-opcode. The daemon therefore decodes
> the payload into the SAME platform.v1 message the SDK sent … the protobuf
> messages ARE the wire contract (identical to the device surface)."*

An empty payload is `StatusInvalidRequest` with
`ErrQUICMissingField{Field:"sub_opcode"}`.

**Do not send `SwitchSub*` values at top level.** They use the `SwitchSub`
prefix rather than `Op` precisely because they are not top-level opcodes —
`0x01` at top level is `OpLiveness`. The constants are declared in
`sdk/go/wire/quicwire/switch_opcodes.go`, and `pkg/api/daemon/quic_switch.go`
keys its handler table on them directly, so there is one copy.

Every sub-opcode calls the `SwitchGRPCService` method of the same name. A
refusal is the servicer's gRPC error, wrapped in `ErrQUICOperationFailed`
and sent with the QUIC status `grpcDelegateCodeToQUICStatus` maps its code
to, so QUIC answers every case the way gRPC does (§8).

`uint16` becomes `uint32` on the wire: `SwitchPortStatus.access_vlan`,
`trunk_vlans` and `native_vlan` (field 8) are `uint32` in proto and converted by
`portStatusToProto`, which every transport shares.

### 5.3 gRPC

Five request/response pairs, all unary, all carrying `switch_name` and (except
`ListPorts`) `port_name`. Mutating responses carry a `Status{success, message}`
with fixed strings: `"port VLAN updated successfully"`,
`"port enabled successfully"`, `"port disabled successfully"`.

### 5.4 MCP

| Tool | Required arguments |
|---|---|
| `switch_list_ports` | `switch_name` |
| `switch_port_status` | `switch_name`, `port_name` |
| `switch_set_vlan` | `switch_name`, `port_name`, `vlan_id` |
| `switch_enable_port` | `switch_name`, `port_name` |
| `switch_disable_port` | `switch_name`, `port_name` |

The arguments are the gRPC request's fields under their proto names; an
argument the request does not declare is refused as `InvalidArgument` before
the servicer runs. The result is the gRPC response in the proto3 JSON mapping
with proto field names: `switch_list_ports` returns `{"ports": [...]}`,
`switch_port_status` returns `{"port": {...}}`, and the three mutators return
`{"status": {"success": ..., "message": ...}}`. A servicer error reaches the
caller with its gRPC code's MCP class, so every code in §8 is the gRPC code.

---

## 6. Pagination

None. `ListPorts` returns every port on the switch in one response, on every
transport. A high-density chassis returns a large single payload; on QUIC that
is bounded by `MaxPayloadSize` (16 MiB), which is not a practical limit for
port lists.

---

## 7. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`. Enforcement is
per operation: gRPC `RequireScope`, QUIC `AuthMiddleware.GuardRequest`, MCP
`AuthorizeTool`. All three catalogs are **default-deny** for entries they do not
list ([`docs/daemon/api.md`](../daemon/api.md) §5).

**`SwitchService` is fully scoped on gRPC**
(`pkg/api/grpc/method_permissions.go`): `GetPortStatus` and `ListPorts` need
`switch:read`; `EnablePort`, `DisablePort` and `SetPortVLAN` need
`switch:write`. Disabling a physical uplink therefore needs the same class of
grant as the virtual-datapath `SDNService.SetPortState` (`sdn:write`), under its
own resource.

**MCP requires the same `switch` scopes (#304).** `switch_list_ports` and
`switch_port_status` need `switch:read`; `switch_enable_port`,
`switch_disable_port` and `switch_set_vlan` need `switch:write`
(`pkg/api/mcp/authz.go`). A caller without the scope gets `PermissionDenied`
(`-32003`) and the tool never runs. Switch ports are platform-level: no
transport scopes them to a tenant.

The daemon's MCP provider serves the tools from its `SwitchGRPCService`
(`MCPServiceProvider.SetSwitchServer`). A provider with no switch servicer
answers `ErrSwitchNotConfigured`, class `Unavailable`, the class every
unconfigured service answers with. The daemon always wires one, so a
classified caller there gets the servicer's answer — `Unavailable` with reason
`SERVICE_NOT_CONFIGURED` while the backend is dark (§9).

**QUIC requires the `switch` scopes (#767).** Under `OpSwitchCategory`
(`0xCC`), `SwitchSubListPorts` and `SwitchSubGetPortStatus` need
`switch:read`; `SwitchSubSetPortVLAN`, `SwitchSubEnablePort` and
`SwitchSubDisablePort` need `switch:write`
(`pkg/api/quic/opcode_permissions.go`).

REST is not covered by either catalog; its protection is whatever middleware
the daemon mounts in front of `/api/v1`.

### REST is gated on the `admin` role (#165)

`/api/v1/switches/**` requires an authenticated caller holding `admin` — port
listing and status, VLAN assignment, and port enable/disable.

Moving a port between VLANs moves a physical machine between network zones,
which is why the read is gated with the writes: the port-to-VLAN map is the
fabric's segmentation.

The REST gate is role-based; the gRPC and MCP positions are the scope catalogs
above. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | gRPC | Switch cause |
|---|---|---|---|---|
| `0x00` | `StatusOK` | 200 | OK | — |
| `0x01` | `StatusInvalidRequest` | 400 | — | Payload decode failure; empty QUIC payload (missing sub-opcode) |
| `0x02` | `StatusNotFound` | 404 | `NotFound` | `ErrManagerNotFound` → `ErrSwitchNotFound` (REST) / `NotFound` on gRPC, QUIC, MCP and embedded; `ErrPortNotFound` → `NotFound` from `GetPortStatus` only — `SetPortVLAN`, `EnablePort` and `DisablePort` answer `Internal` for it on gRPC, QUIC, MCP and embedded alike (**REST/gRPC mapping exists but the SSH driver never produces it** — [engineering.md](engineering.md) §8) |
| `0x03` | `StatusUnauthorized` | 401 | `Unauthenticated` | Token invalid |
| `0x04` | `StatusInternalError` | 500 | `Internal` | `ErrSSHConnectionFailed`, `ErrSSHCommandFailed`, `ErrSSHParseOutputFailed`, `ErrPortVLANSetFailed` |
| `0x09` | `StatusInvalidArgument` | 400 | `InvalidArgument` | Missing `switch_name` / `port_name`; `vlan_id` zero or > 4094 |
| `0x0A` | `StatusUnavailable` | 503 | `Unavailable` | Switch service not wired into the daemon — §9 |
| `0x0B` | `StatusNotImplemented` | 501 | — | Unknown sub-opcode under `0xCC` |

"Service not wired" is `Unavailable` on every transport, and gRPC, QUIC, MCP
and embedded carry the `SERVICE_NOT_CONFIGURED` reason with `service: switch`
(`switchNotConfigured`, `pkg/api/daemon/switch_grpc_service.go`).

A `StatusInternalError` / 500 from these routes almost always means the SSH
session failed or the switch's output did not parse — the `ErrSSHParseOutputFailed`
error carries the raw switch output, which is the first thing to look at.

---

## 9. The whole surface is dark by default

Three separate wiring seams exist and **none of them is used**, anywhere in the
repository:

| Seam | Callers |
|---|---|
| `switchmgmt.NewService(configs, logger)` | none outside tests |
| `HandlerRegistryParams.SwitchService` (REST) | never populated |
| `(*SwitchGRPCService).SetSwitchService` | **none at all** |

The gRPC service is registered on both the TCP and UDS servers with an
**explicit nil** backend, and the source says why:

> *"Create the Switch gRPC service. It has no switch backend yet, so every
> method answers Unavailable (not configured); the QUIC opcodes, the MCP
> tools and the embedded transport call this same servicer."*
> — `pkg/api/daemon/daemon.go:1026`

Until that is wired:

| Transport | What a caller gets |
|---|---|
| REST | **503** from the `requireService` catch-all under `/api/v1/switches/`, body `{"code":503,"error":"switch service not configured by daemon — REST surface is dark","success":false,"service":"switch","reason":"SERVICE_NOT_CONFIGURED"}`; clients branch on `reason`, never on the prose; the daemon logs a startup warning |
| gRPC / Unix | `codes.Unavailable`, reason `SERVICE_NOT_CONFIGURED` — `"switch service is not configured on this node"` |
| QUIC | `StatusUnavailable` — the gRPC servicer's answer in `ErrQUICOperationFailed`; a handler with no servicer set answers `ErrQUICServiceUnavailable{Service:"switch"}`, also `StatusUnavailable` |
| MCP | `codes.Unavailable` — the gRPC servicer's answer, passed through |
| Embedded | `codes.Unavailable` — the gRPC servicer's answer, passed through |

`GET /api/v1/platform/service-registry` reports the `switch` entry with
`Configured: false` and the reason string. **Check that before debugging
anything else.**

The `switches:` config block is parsed into `app.App.SwitchConfigs`
(`pkg/app/app.go:334`) and nothing constructs a `Service` from it. The
bootstrap `Configurator` path is separate and does run.

---

## 10. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. Nothing in the switch surface is deprecated.

---

## 11. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/api.md`](../sdn/api.md) — the virtual datapath surface, §7 and §9
- [`docs/device/api.md`](../device/api.md) — the activation path that drives `SetPortVLAN`

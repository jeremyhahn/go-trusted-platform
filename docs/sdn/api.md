# SDN — API

> **Status: NORMATIVE** · Scope: SDN, overlay and switch routes on every transport · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.SDN` and `ServiceRegistry.Overlay`
(`sdk/go/transport/embedded/adapter.go`) carry the services in-process.

Three gRPC services are in scope here: `SDNService` (30 RPCs, `sdn.proto`),
`OverlayService` (10 RPCs, `overlay.proto`) and `SwitchService` (5 RPCs,
`switch.proto`). The edge gateway's `GatewayService` and `ProxyService` are a
separate feature — [`docs/gateway/`](../gateway/).

---

## 2. Bridges, ports and flows

REST base path `/api/v1/sdn` (`pkg/webservice/v1/rest/sdn/router.go`).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create bridge | `POST /api/v1/sdn/bridges` | `CreateBridge` | `OpSDNCreateBridge` (`0xB0`) | `sdn_create_bridge` | ✅ |
| List bridges | `GET /api/v1/sdn/bridges` | `ListBridges` | `OpSDNListBridges` (`0x4B`) | `sdn_list_bridges` | ✅ |
| Get bridge | `GET /api/v1/sdn/bridges/{name}` | `GetBridge` | `OpSDNGetBridge` (`0x4A`) | `sdn_list_bridges`, filtered by the SDK on the bridge's UUID or name | ✅ |
| Delete bridge | `DELETE /api/v1/sdn/bridges/{name}` | `DeleteBridge` | `OpSDNDeleteBridge` (`0xB1`) | `sdn_delete_bridge` | ✅ |
| Add port | `POST /api/v1/sdn/bridges/{name}/ports` | `AddPort` | `OpSDNCreatePort` (`0xB2`) | `sdn_add_port` | ✅ |
| List ports | `GET /api/v1/sdn/bridges/{name}/ports` | `ListPorts` | `OpSDNListPorts` (`0x42`) | `MISSING — docs/13 G7` | ✅ |
| Get port | `MISSING — docs/13 G7` | `GetPort` | `OpSDNGetPort` (`0x4F`) | `sdn_get_port_state` | ✅ |
| Delete port | `DELETE /api/v1/sdn/bridges/{name}/ports/{port}` | `DeletePort` | `OpSDNDeletePort` (`0xB3`) | `sdn_delete_port` | ✅ |
| Get port state | `GET /api/v1/sdn/bridges/{name}/ports/{port}/state` | (via `GetPort`) | `OpSDNGetPortState` (`0x40`) | `sdn_get_port_state` | ✅ |
| Set port state | `PUT /api/v1/sdn/bridges/{name}/ports/{port}/state` | `SetPortState` | `OpSDNSetPortState` (`0x41`) | `sdn_set_port_state` | ✅ |
| Port statistics | `GET /api/v1/sdn/bridges/{name}/ports/{port}/stats` | `GetPortStats` | `MISSING — docs/13 G7` | `sdn_get_port_stats` | ✅ |
| Add flow | `POST /api/v1/sdn/flows`, `POST /api/v1/sdn/bridges/{name}/flows` | `AddFlow` | `OpSDNAddFlow` (`0x44`) | `sdn_add_flow` | ✅ |
| List flows | `GET /api/v1/sdn/flows`, `GET /api/v1/sdn/bridges/{name}/flows` | `ListFlows` | `OpSDNListFlows` (`0x46`) | `sdn_list_flows` | ✅ |
| Delete flow | `DELETE /api/v1/sdn/flows` | `DeleteFlow` | `OpSDNDeleteFlow` (`0x45`) | `sdn_delete_flow` | ✅ |
| Get flow | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpSDNGetFlow` (`0x43`) | `MISSING — docs/13 G7` | — |
| Flush flows | `MISSING — docs/13 G7` | `FlushFlows` | `MISSING — docs/13 G7` | `sdn_flush_flows` | ✅ |
| Flow statistics | `MISSING — docs/13 G7` | `GetFlowStats` | `MISSING — docs/13 G7` | `sdn_get_flow_stats` | ✅ |
| Stream flow logs | `MISSING — docs/13 G7` | `StreamFlowLogs` (server stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| SDN metrics | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpSDNGetMetrics` (`0x4C`) | `MISSING — docs/13 G7` | — |

Bridge-scoped and global flow routes both exist in REST
(`/sdn/flows` and `/sdn/bridges/{name}/flows`) — the global form operates across
bridges. `DELETE /api/v1/sdn/flows` takes its selector in the body, which is why
it is not a path-parameter route.

**A flow's ID is its cookie, on every transport.** Adding a flow stamps it with
a fresh cookie under the `0xA9F1` owner prefix (or the cookie the request names)
and returns `flow-0x<cookie>`; listing reports the same ID; delete and flow
stats act on exactly the flow carrying that cookie (`ovs.ParseFlowID`,
`ovs.FlowID`). Anything else is refused as an invalid flow ID (`400` /
`InvalidArgument`). Until #614 the ID was handed to Open vSwitch as a match
string, which the flow encoder emptied, so "delete this flow" removed every
flow on the bridge.

**Set port state applies ingress policing and egress shaping, on every
transport.** `ingress_rate`
(bps) and `ingress_burst` (bits) set the interface's Open vSwitch ingress
policing (`ovs.Client.SetIngressPolicing`); a zero rate leaves it unchanged.
Each must be 0 or a whole multiple of 1000 and a burst needs a rate, otherwise
the request is refused before anything changes (`400` / `InvalidArgument`,
`ovs.ErrInvalidPolicing`). REST validates and applies through the OVS client;
gRPC, Unix, QUIC and MCP go through `SDNService.SetPortState`, and the CLI's
`--ingress-rate`/`--ingress-burst` call that RPC. Until #730 every transport
accepted `ingress_rate` and dropped it, MCP handed `up`/`down` to the 802.1X
engine (which refused both), and `platformctl sdn port set-state` changed
nothing.

`egress_rate` (bps) and `egress_burst` (bits) set the port's egress shaping
(`ovs.Client.SetEgressShaping`): a `linux-htb` QoS whose queue 0 carries the
rate and burst. A zero rate leaves it unchanged; a burst without a rate is
refused before anything changes (`400` / `InvalidArgument`,
`ovs.ErrInvalidShaping`). Every transport takes the same path as ingress
policing, and the CLI's `--egress-rate`/`--egress-burst` call the same RPC.
Until #730 every transport accepted `egress_rate` and dropped it.

**Every SDN call the CLI makes reaches MCP.** The SDK's MCP transport
(`sdk/go/transport/mcp/sdn.go`, `sdn_policy.go`, `sdn_zone.go`) maps each of
the 23 `SDNService` methods behind `platformctl sdn` to the tool in the
tables above and builds the tool's own arguments: `bridge_name`, `port_name`
and `state` for the port tools, the four rates as decimal strings,
`port_type` as the short type name (`internal`, `tap`, …), the REST policy
document for the policy tools and the zone fields for the zone tools.
`sdn_set_port_state` answers with the refreshed port, and `sdn_add_port`
refuses a `port_type` it does not know instead of adding an unspecified port.
A request field the tool cannot carry is refused before the call
(`InvalidArgument`, `ErrFieldNotSupported` naming the field), never dropped:
on MCP, `AddFlow` takes no flow body, `CreateBridge` only the name and type
`ovs`, `DeleteBridge` no `force`, `AddPort` no VLAN, trunk, MAC,
MTU, promiscuous flag, options or zone, `CreateVLAN` no ports, `FlushFlows`
no table, and the list calls no selector or pagination. Labels pass,
since the daemon ignores them on every transport. Until #730 the SDK
mapped six of these methods, sent the gRPC field names the tools do not
read, and `platformctl sdn port set-state` over MCP failed `Unimplemented`.

---

## 3. VLANs

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create VLAN | `POST /api/v1/sdn/vlans`, `POST /api/v1/sdn/bridges/{bridge_id}/vlans` | `CreateVLAN` | `OpSDNSetVLAN` (`0x4D`) | `sdn_create_vlan` | ✅ |
| List VLANs | `GET /api/v1/sdn/vlans`, `GET /api/v1/sdn/bridges/{bridge_id}/vlans` | `ListVLANs` | `OpSDNGetVLAN` (`0x4E`) | `sdn_list_vlans` | ✅ |
| Delete VLAN | `DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id=` (daemon REST only) | `DeleteVLAN` | `MISSING — docs/13 G7` | `sdn_delete_vlan` | ✅ |

**The daemon's REST VLAN routes are the gRPC operations.** The daemon's
standalone REST server (`pkg/api/rest/sdn_handlers.go`) hands `POST`, `GET` and
`DELETE` on `/api/v1/sdn/vlans` to the same `SDNService` instance the gRPC
transport serves (`pkg/api/daemon/rest_sdn.go`), so a VLAN created on one
transport is listed and deleted on the other, and both enforce the same rules:
`vlan_id` 1–4095 and `bridge_id` required (`400`), unknown bridge or VLAN
(`404`), a VLAN ID already on the bridge (`409`), a port that refuses the tag
(`500`). The gRPC status maps to HTTP through the table in
`pkg/api/rest/proxy_handlers.go`; with no SDN service wired the routes answer
`503`. Until #730 these routes echoed the request, listed nothing and reported
every delete as done without touching any state. The webservice still has no
VLAN delete route.

Note the path-parameter inconsistency: bridge-scoped port and flow routes use
`{name}`, bridge-scoped VLAN routes use `{bridge_id}`. Same identifier, two
spellings.

---

## 4. Port authentication and policy

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Authenticate port | `POST /api/v1/sdn/bridges/{name}/ports/{port}/auth` (webservice only) | `AuthenticatePort` | `MISSING — docs/13 G7` | `sdn_authenticate_port` | ✅ |
| Revoke port auth | `DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth` (webservice only) | `RevokePortAuth` | `MISSING — docs/13 G7` | `sdn_revoke_port_auth` | ✅ |
| Apply policy | `POST /api/v1/sdn/policies` | `ApplyPolicy` | `OpSDNApplyPolicy` (`0x47`) | `sdn_apply_policy` | ✅ |
| List policies | `GET /api/v1/sdn/policies` | `ListPolicies` | `OpSDNListPolicies` (`0x49`) | `sdn_list_policies` | ✅ |
| Get policy | `GET /api/v1/sdn/policies/{id}` | `GetPolicy` | `OpSDNGetPolicy` (`0x48`) | `sdn_get_policy` | ✅ |
| Delete policy | `DELETE /api/v1/sdn/policies/{id}` (daemon REST only) | `DeletePolicy` | `OpSDNDeletePolicy` (`0xB4`) | `sdn_delete_policy` | ✅ |

**The daemon's REST policy routes are the gRPC operations.** Like the VLAN
routes (§3), the daemon's standalone REST server hands the four policy routes to
the shared `SDNService`, so a policy applied on one transport is read, listed
and deleted on the other under the same rules: a name is required (`400`), an
unknown `type`, rule `action` or target `type` is refused (`400`), a second
policy with the same name conflicts (`409`), and get or delete of an unknown ID
or name is `404`. Until #730 these routes kept their own in-process map that no
other transport saw. The REST policy object no longer carries `labels` — the
gRPC `Policy` has no such field. The webservice still has no policy delete
route.

The webservice's apply route takes the same body, calls the same
`ApplyPolicy` and answers `201` with the same policy object; it reports a
duplicate name as `400`, not `409`. The SDK's REST client sends `ApplyPolicy`
there in this form, through the policy codec its MCP client uses
(`sdk/go/services/sdn/policy_wire.go`). Until #452 it posted the gRPC request
to `/api/v1/sdn/policies/apply`, which no server serves, and the webservice
route answered a made-up policy without calling the service.

**The MCP policy tools are the same operations.** `sdn_apply_policy`,
`sdn_get_policy`, `sdn_list_policies` and `sdn_delete_policy` call the same
`SDNService` on both MCP providers and speak the REST policy document, so a
policy created over MCP is seen over REST and gRPC and the other way round.
Until #730 the MCP tools kept their own policy-engine path and their own
argument shape.

**Port authentication is on the webservice REST router, not on QUIC or the
daemon's standalone REST server.** `POST` and `DELETE` on
`/api/v1/sdn/bridges/{name}/ports/{port}/auth` call `SDNService.AuthenticatePort`
and `RevokePortAuth` behind the webservice's admin gate. Authenticate takes
`{"certificate": <base64 PEM or DER>, "format": "DER"}` (`format` defaults to
PEM) and answers the port's authentication state; a missing bridge, port or
certificate, or a certificate that does not parse or is not valid now, is `400`; an unknown bridge or port, or a
revoke on a port that is not authenticated, is `404`. Given that port
authentication is the SDN feature's security core — see
[engineering.md](engineering.md) §2 — the missing QUIC route is the most
consequential hole left in the matrix.

**The SDK's REST transport puts every bridge and port ID in the path.**
`DeleteBridge`, `AddPort`, `DeletePort`, `AuthenticatePort` and
`RevokePortAuth` call the templated routes in the tables above
(`sdk/go/transport/rest/sdn.go`); the body carries only the remaining fields,
and an empty bridge or port ID is refused before the call (`InvalidArgument`).
`AddPort` sends the REST port document (`type` as the short type name) and
refuses a port type it does not know. Until #452 these five calls went to flat
routes no server registers. `ApplyPolicy` still claims
`POST /api/v1/sdn/policies/apply`, which no server registers.

**This is IDevID-certificate authentication, not EAP/RADIUS.** `AuthenticatePort`
validates a device certificate; there is no RADIUS exchange behind it.

---

## 5. Network zones

The zone operations manage the **underlay zones** of the
[reference network](../architecture/reference-network.md): the nine built-in
zones at offsets x00–x08 (policy tunable, numbering fixed) and owner-defined
zones at offsets 9–99. Overlays (`platform`, `tenant`, `public`) are not zones
and cannot be created here.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create owner-defined zone | `POST /api/v1/sdn/zones` | `CreateNetworkZone` | gateway category (`0x2F`), sub-opcode `0x11` | `gateway_zone_create` | ✅ |
| Tune / replace zone | `PUT /api/v1/sdn/zones/{name}` | `UpdateNetworkZone` | sub-opcode `0x12` | `gateway_zone_update` | ✅ |
| Delete zone (omit optional built-in) | `DELETE /api/v1/sdn/zones/{name}` | `DeleteNetworkZone` | sub-opcode `0x13` | `gateway_zone_delete` | ✅ |
| List zones with numbering | `GET /api/v1/sdn/zones` (`?lifecycle_role=`) | `ListNetworkZones` | sub-opcode `0x10` | `gateway_zone_list` | ✅ |

Every zone record carries `name`, `offset`, `port_classes`,
`internet_ingress`, `isolate_from`, `allow_to` (`{zone, services}`),
`services`, `isolate`, `oob`, `lifecycle_role`, `privileged_access`
(`{reason, approved_by}`), `restart_required` and the timestamps. When the
node has an `sdn.environment`, it also carries the zone's derived
`numbering` (`vlan`, `subnet4`, `subnet6`, `gateway`).

Every mutation re-resolves the zone set onto the built-ins and re-runs zone
and numbering validation; a refused mutation changes nothing. The rules a
mutation must satisfy:

- a built-in keeps its offset, port classes, lifecycle role and OOB flag;
- an owner-defined zone takes a unique offset in 9–99 and joins the
  `gateway` and/or `hypervisor` port class;
- `platform`, `tenant`, `public` and `trusted` are reserved names;
- an `allow_to` path into `control-plane` or `management` beyond the
  reference defaults needs `privileged_access` with `reason` and
  `approved_by`; the service writes an audit record (`audit=true`,
  compliance `AU-2,AC-4`) for it;
- `fabric`, `provisioning`, `quarantine` and `control-plane` cannot be
  deleted; deleting another built-in omits it.

Every accepted mutation returns `restart_required: true`: the network plan
and the flow matrix are derived at daemon startup.

**There is no "assign a network to a zone" operation.** Networks are zones:
netplan derives exactly one network per zone. The former
`AssignNetworkZone` RPC, the `PUT /api/v1/sdn/networks/{network}/zone`
route, QUIC sub-opcode `0x14` (retired, never reused) and the
`gateway_zone_assign` tool were removed with #708.

The zone REST routes are served by the webservice
(`pkg/webservice/v1/rest/sdn/zones.go`, delegating to the in-process
`SDNServiceServer`) and wrap the zone objects in the standard platform
response envelope (`{code, error, success, payload}`). The daemon's
standalone REST stack (`pkg/api/rest/sdn_handlers.go`) serves the same paths
and the same object shape (`pkg/sdn/gateway.ZoneView`) bare, without the
envelope, when `EnableREST` is set. The QUIC zone operations are
sub-opcodes multiplexed under the **gateway category opcode `0x2F`**, not
first-class opcodes — see §8.

The MCP zone tools hold the offset in a byte and take no `omit`, so the
SDK refuses an offset above 255 (`ErrValueOutOfRange`) and an omit
(`ErrFieldNotSupported`) with `InvalidArgument` instead of sending them.

---

## 6. VXLAN/EVPN overlay

REST base path `/api/v1/overlay` (`pkg/webservice/v1/rest/overlay/router.go`);
gRPC `OverlayService`. QUIC overlay operations are sub-opcodes under the
**overlay category opcode `0x2E`**.

| Capability | REST | gRPC / Unix | QUIC (under `0x2E`) | MCP | Embedded |
|---|---|---|---|---|---|
| Overlay status | `GET /api/v1/overlay/status` | `GetOverlayStatus` | `OpOverlayStatus` (`0x01`) | `overlay_status` | ✅ |
| List VTEPs | `GET /api/v1/overlay/vteps` | `ListVTEPs` | `OpOverlayListVTEPs` (`0x02`) | `overlay_vtep_list` | ✅ |
| Get VTEP | `GET /api/v1/overlay/vteps/{nodeId}` | `GetVTEP` | `OpOverlayGetVTEP` (`0x03`) | `overlay_vtep_get` | ✅ |
| List VNIs | `GET /api/v1/overlay/vnis` | `ListVNIs` | `OpOverlayListVNIs` (`0x04`) | `overlay_vni_list` | ✅ |
| Create VNI | `POST /api/v1/overlay/vnis` | `CreateVNI` | `OpOverlayCreateVNI` (`0x05`) | `overlay_vni_create` | ✅ |
| Delete VNI | `DELETE /api/v1/overlay/vnis/{vni}` | `DeleteVNI` | `OpOverlayDeleteVNI` (`0x06`) | `overlay_vni_delete` | ✅ |
| List tunnels | `GET /api/v1/overlay/tunnels` | `ListTunnels` | `OpOverlayListTunns` (`0x07`) | `overlay_tunnel_list` | ✅ |
| Tunnel statistics | `GET /api/v1/overlay/tunnels/stats` | `GetTunnelStats` | `OpOverlayTunnelStats` (`0x0A`) | `overlay_tunnel_stats` | ✅ |
| List remote MACs | `GET /api/v1/overlay/macs` | `ListRemoteMACs` | `OpOverlayListMACs` (`0x08`) | `overlay_mac_list` | ✅ |
| Forget MAC | `DELETE /api/v1/overlay/macs?mac=<mac>&vni=<vni>` | `ForgetMAC` | `OpOverlayForgetMAC` (`0x09`) | `overlay_mac_forget` | ✅ |

The overlay is served on every transport: every capability is present on all
six, each answering from the one overlay controller.

`{vni:[0-9]+}` is numerically constrained in the route; a non-numeric VNI 404s
rather than reaching the handler.

Forget MAC reads the MAC and VNI from the query only; a `DELETE` body is
ignored. A missing MAC, a zero VNI or a malformed MAC is refused with 400 and
the same reason gRPC returns.

---

## 7. Physical switches

REST base path `/api/v1/switches`
(`pkg/webservice/v1/rest/switch/handlers.go`); gRPC `SwitchService`.

QUIC reaches the switch service through the **switch category opcode `0xCC`**,
whose five sub-opcodes are declared in `sdk/go/wire/quicwire/switch_opcodes.go` and
dispatched by `pkg/api/daemon/quic_switch.go::handleSwitchCategory`.

| Capability | REST | gRPC / Unix | QUIC (under `0xCC`) | MCP | Embedded |
|---|---|---|---|---|---|
| List switch ports | `GET /api/v1/switches/{switch}/ports` | `ListPorts` | `SwitchSubListPorts` (`0x01`) | `switch_list_ports` | `MISSING` — no `Switch` field in `ServiceRegistry` |
| Get port status | `GET /api/v1/switches/{switch}/ports/{port}` | `GetPortStatus` | `SwitchSubGetPortStatus` (`0x02`) | `switch_port_status` | `MISSING` |
| Set port VLAN | `POST /api/v1/switches/{switch}/ports/{port}/vlan` | `SetPortVLAN` | `SwitchSubSetPortVLAN` (`0x03`) | `switch_set_vlan` | `MISSING` |
| Enable port | `POST /api/v1/switches/{switch}/ports/{port}/enable` | `EnablePort` | `SwitchSubEnablePort` (`0x04`) | `switch_enable_port` | `MISSING` |
| Disable port | `POST /api/v1/switches/{switch}/ports/{port}/disable` | `DisablePort` | `SwitchSubDisablePort` (`0x05`) | `switch_disable_port` | `MISSING` |

Sub-opcode names use the `SwitchSub*` prefix rather than `Op*`, because they are
not top-level opcodes. Do not send them at top level — `0x01` at top level is
`OpLiveness`.

`ServiceRegistry` (`sdk/go/transport/embedded/adapter.go:32`) has 25 fields and
**`Switch` is not one of them**, so the embedded transport cannot reach physical
switch management. That is a genuine embedded-mode hole, distinct from the REST
and QUIC gaps above.

---

## 8. QUIC category opcodes — read before writing a QUIC client

The QUIC protocol is a **flat byte opcode with a two-level extension**: certain
opcodes are *category* opcodes whose sub-opcode comes from the payload, and the
daemon routes them to a dedicated handler
(`pkg/api/daemon/quic_service.go`).

| Category opcode | Routes to |
|---|---|
| `0x2E` | Overlay handler |
| `0x2F` | Gateway handler; sub-opcodes `0x20`–`0x2D` are further routed to the **proxy** handler |
| `0x3F` | IPAM handler |
| `0x99` | Physical TPM2 handler |
| `0x9A`–`0x9D` | Ceremony, PIV, LUKS, FIDO2 |
| `0x9E` | Per-tenant barrier |
| `0x9F` | BMC enrollment |

**This is why opcode values collide.** `OpOverlayStatus`, `OpGatewayStatus` and
`OpLiveness` are all `0x01`, but the first two are *sub*-opcodes inside their
category and the third is a top-level opcode. A client that sends `0x01` at top
level gets a liveness check, not overlay status. The comments on the gateway and
overlay opcode blocks claim they were "defined here to avoid conflicts with
existing protocol.go allocations", which reads as if the values were chosen to
be distinct — they were not; the categories are what keeps them apart.

`0x40`–`0x4F` and `0xB0`–`0xB4` are top-level SDN opcodes with no category
indirection.

---

## 9. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`. The gRPC scope
catalog (`pkg/api/grpc/method_permissions.go`) is **default-deny**: a method
absent from it is refused with `PermissionDenied`.

**`SDNService` and `OverlayService` are fully scoped** under resource `sdn`,
actions `read`, `write`, `delete`. `SwitchService` is scoped under its own
resource, `switch` ([`docs/switch/api.md`](../switch/api.md) §7). On MCP, the bridge, port-state and policy
`sdn_*` tools carry `sdn:*` permissions. The flow, VLAN, port-stats and
port-auth `sdn_*` tools, and every `overlay_*` and `switch_*` tool, are not
classified, so `AuthorizeTool` refuses them for every caller. QUIC classifies
every operation (#767) in `pkg/api/quic/opcode_permissions.go`: overlay
sub-opcodes need `sdn:*` and switch sub-opcodes `switch:read` / `switch:write`.

### REST is gated on the `admin` role (#165)

`/api/v1/sdn/**` requires an authenticated caller holding `admin` — bridge,
port, flow and VLAN mutation, and the corresponding reads.

Flow rules **are** the network policy this platform enforces. An anonymous
caller able to add one can route around every other control on the node, which
makes this one of the higher-consequence rows in #165's table despite not
holding any credential material itself.

This changes the REST position only. The gRPC, Unix, MCP and embedded
positions described above are unchanged. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 10. Status and error mapping

| QUIC byte | Name | REST | SDN cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed bridge, port, flow or VLAN spec |
| `0x02` | `StatusNotFound` | 404 | Unknown bridge, port, VLAN, zone or policy (`ErrGatewayZoneNotFound`) |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | OVS/OVSDB or netlink failure |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrDuplicatePoolName`; a zone that exists (`ErrGatewayZoneAlreadyExists`) |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `sdn:*` scope; port not authorised |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidPoolCIDR`; a zone mutation that fails zone or numbering validation (`ErrGatewayZoneInvalid`) |
| `0x0A` | `StatusUnavailable` | 503 | SDN subsystem not wired into the daemon |

Configuration errors (`ErrInvalidTCPolicy`, `ErrDPDKRequiresNetdev`,
`ErrIPAMBackendUnknown`, …) are raised at **load**, not per request — a
misconfigured SDN subsystem does not start.

---

## 11. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing in the SDN, overlay
or switch surface is deprecated as of 2026-08-18.

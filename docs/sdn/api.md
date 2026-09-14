# SDN — API

> **Status: NORMATIVE** · Scope: SDN, overlay and switch routes on every transport · Last verified: 2026-08-18
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
| Get bridge | `GET /api/v1/sdn/bridges/{name}` | `GetBridge` | `OpSDNGetBridge` (`0x4A`) | `MISSING — docs/13 G7` | ✅ |
| Delete bridge | `DELETE /api/v1/sdn/bridges/{name}` | `DeleteBridge` | `OpSDNDeleteBridge` (`0xB1`) | `sdn_delete_bridge` | ✅ |
| Add port | `POST /api/v1/sdn/bridges/{name}/ports` | `AddPort` | `OpSDNCreatePort` (`0xB2`) | `sdn_add_port` | ✅ |
| List ports | `GET /api/v1/sdn/bridges/{name}/ports` | `ListPorts` | `OpSDNListPorts` (`0x42`) | `MISSING — docs/13 G7` | ✅ |
| Get port | `MISSING — docs/13 G7` | `GetPort` | `OpSDNGetPort` (`0x4F`) | `MISSING — docs/13 G7` | ✅ |
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

---

## 3. VLANs

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create VLAN | `POST /api/v1/sdn/vlans`, `POST /api/v1/sdn/bridges/{bridge_id}/vlans` | `CreateVLAN` | `OpSDNSetVLAN` (`0x4D`) | `sdn_create_vlan` | ✅ |
| List VLANs | `GET /api/v1/sdn/vlans`, `GET /api/v1/sdn/bridges/{bridge_id}/vlans` | `ListVLANs` | `OpSDNGetVLAN` (`0x4E`) | `sdn_list_vlans` | ✅ |
| Delete VLAN | `MISSING — docs/13 G7` | `DeleteVLAN` | `MISSING — docs/13 G7` | `sdn_delete_vlan` | ✅ |

**VLAN delete has no REST route.** A VLAN can be created over REST and not
removed over REST — an asymmetry worth closing.

Note the path-parameter inconsistency: bridge-scoped port and flow routes use
`{name}`, bridge-scoped VLAN routes use `{bridge_id}`. Same identifier, two
spellings.

---

## 4. Port authentication and policy

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Authenticate port | `MISSING — docs/13 G7` | `AuthenticatePort` | `MISSING — docs/13 G7` | `sdn_authenticate_port` | ✅ |
| Revoke port auth | `MISSING — docs/13 G7` | `RevokePortAuth` | `MISSING — docs/13 G7` | `sdn_revoke_port_auth` | ✅ |
| Apply policy | `POST /api/v1/sdn/policies` | `ApplyPolicy` | `OpSDNApplyPolicy` (`0x47`) | `sdn_apply_policy` | ✅ |
| List policies | `GET /api/v1/sdn/policies` | `ListPolicies` | `OpSDNListPolicies` (`0x49`) | `sdn_list_policies` | ✅ |
| Get policy | `GET /api/v1/sdn/policies/{id}` | `GetPolicy` | `OpSDNGetPolicy` (`0x48`) | `sdn_get_policy` | ✅ |
| Delete policy | `MISSING — docs/13 G7` | `DeletePolicy` | `OpSDNDeletePolicy` (`0xB4`) | `MISSING — docs/13 G7` | ✅ |

**Port authentication has no REST and no QUIC route.** It is reachable over
gRPC, Unix, MCP and embedded only. Given that port authentication is the SDN
feature's security core — see [engineering.md](engineering.md) §2 — this is the
most consequential hole in the matrix.

**This is IDevID-certificate authentication, not EAP/RADIUS.** `AuthenticatePort`
validates a device certificate; there is no RADIUS exchange behind it.

---

## 5. Network zones

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create zone | `POST /api/v1/sdn/zones` | `CreateNetworkZone` | via gateway category (`0x2F`), sub-opcodes `0x10`–`0x14` | `gateway_zone_create` | ✅ |
| Update zone | `PUT /api/v1/sdn/zones/{name}` | `UpdateNetworkZone` | as above | `gateway_zone_update` | ✅ |
| Delete zone | `DELETE /api/v1/sdn/zones/{name}` | `DeleteNetworkZone` | as above | `gateway_zone_delete` | ✅ |
| List zones | `GET /api/v1/sdn/zones` (`?lifecycle_role=`) | `ListNetworkZones` | as above | `gateway_zone_list` | ✅ |
| Assign zone | `PUT /api/v1/sdn/networks/{network}/zone` | `AssignNetworkZone` | as above | `gateway_zone_assign` | ✅ |

The zone REST routes are served by the webservice
(`pkg/webservice/v1/rest/sdn/zones.go`, delegating to the in-process
`SDNServiceServer`) and wrap the documented snake_case zone objects in the
standard platform response envelope (`{code, error, success, payload}`).
The daemon's standalone REST stack (`pkg/api/rest/sdn_handlers.go`) serves
the same paths bare, without the envelope, when `EnableREST` is set. The
MCP zone tools (`pkg/api/mcp/gateway_tools.go`) close what this table
previously recorded as a G7 gap, so zones now reach every transport. The
QUIC zone operations are
sub-opcodes multiplexed under the **gateway category opcode `0x2F`**, not
first-class opcodes — see §8.

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
| Tunnel statistics | `GET /api/v1/overlay/tunnels/stats` | `GetTunnelStats` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| List remote MACs | `GET /api/v1/overlay/macs` | `ListRemoteMACs` | `OpOverlayListMACs` (`0x08`) | `overlay_mac_list` | ✅ |
| Forget MAC | `DELETE /api/v1/overlay/macs` | `ForgetMAC` | `OpOverlayForgetMAC` (`0x09`) | `overlay_mac_forget` | ✅ |

The overlay is the most complete surface in this feature: only tunnel statistics
is missing on QUIC and MCP, and everything else is present on five transports.

`{vni:[0-9]+}` is numerically constrained in the route; a non-numeric VNI 404s
rather than reaching the handler.

---

## 7. Physical switches

REST base path `/api/v1/switches`
(`pkg/webservice/v1/rest/switch/handlers.go`); gRPC `SwitchService`.

QUIC reaches the switch service through the **switch category opcode `0xCC`**,
whose five sub-opcodes are declared in `pkg/api/quic/switch_opcodes.go` and
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

`ServiceRegistry` (`sdk/go/transport/embedded/adapter.go:32`) has 22 fields and
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

Platform tokens carry an `scp` claim as `"<resource>:<action>"`. **`SDNService`
is one of the eleven services in the gRPC scope catalog**
(`pkg/api/grpc/method_permissions.go`), with 25 of its methods mapped —
resource `sdn`, actions `read`, `write`, `delete`. QUIC projects the same
mapping through `DefaultOpcodePermissions`; MCP through `AuthorizeTool`.

`OverlayService` and `SwitchService` are **not** in the catalog, and the
catalog's doc comment states that a method absent from the map carries no
required scope. So overlay and switch operations require only a validated
token, while the equivalent SDN operations require `sdn:write`. That asymmetry
is raised as an owner question in the migration report.

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
| `0x02` | `StatusNotFound` | 404 | Unknown bridge, port, VLAN, zone or policy |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | OVS/OVSDB or netlink failure |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrDuplicatePoolName`, `ErrDuplicateNetworkVLAN`, `ErrDuplicateNetworkName`, `ErrDuplicateNetworkSubnet` |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `sdn:*` scope; port not authorised |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidNetworkVLAN`, `ErrInvalidPoolCIDR`, `ErrSubnetPoolMismatch`, `ErrUnknownNetworkZone` |
| `0x0A` | `StatusUnavailable` | 503 | SDN subsystem not wired into the daemon |

Configuration errors (`ErrInvalidTCPolicy`, `ErrDPDKRequiresNetdev`,
`ErrIPAMBackendUnknown`, …) are raised at **load**, not per request — a
misconfigured SDN subsystem does not start.

---

## 11. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing in the SDN, overlay
or switch surface is deprecated as of 2026-08-18.

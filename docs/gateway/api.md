# Edge Gateway — API

> **Status: NORMATIVE** · Scope: gateway and proxy routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Gateway` and `ServiceRegistry.Proxy` carry both services
in-process.

Two gRPC services: `GatewayService` (24 RPCs, `gateway.proto`) and
`ProxyService` (14 RPCs, `proxy.proto`).

**QUIC reaches both through the gateway category opcode `0x2F`.** Sub-opcodes
`0x20`–`0x2D` under that category are routed to the **proxy** handler; the rest
go to the gateway handler (`pkg/api/daemon/quic_service.go`). IPAM additionally
has its own category opcode `0x3F`. Sub-opcode values collide with top-level
opcodes by design — `0x01` under `0x2F` is `OpGatewayStatus`, while `0x01` at
top level is `OpLiveness`.

---

## 2. Gateway status and mode

REST base path `/api/v1/gateway` (`pkg/webservice/v1/rest/gateway/router.go`).

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| Gateway status | `GET /api/v1/gateway/status` | `GetGatewayStatus` | `OpGatewayStatus` (`0x01`) | `gateway_status` | ✅ |
| Set gateway mode | `POST /api/v1/gateway/mode` | `SetGatewayMode` | `OpGatewaySetMode` (`0x02`) | `gateway_mode_set` | ✅ |

**`SetGatewayMode` is the deprecated compatibility surface.** `GatewayMode`
carries a deprecation notice in `pkg/sdn/gateway/compat.go` and maps only three
of the eleven service sections. It is documented here because it exists and is
callable, not because it is the way to configure a gateway — see
[architecture.md](architecture.md).

---

## 3. BGP

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| BGP status | `GET /api/v1/gateway/bgp/status` | `GetBGPStatus` | `OpGatewayBGPStatus` (`0x03`) | `gateway_bgp_status` | ✅ |
| List peers | `GET /api/v1/gateway/bgp/peers` | `ListBGPPeers` | `OpGatewayBGPPeers` (`0x04`) | `gateway_bgp_peers` | ✅ |
| List announced prefixes | `GET /api/v1/gateway/bgp/prefixes` | `ListAnnouncedPrefixes` | `OpGatewayListPrefixes` (`0x07`) | `gateway_bgp_prefixes` | ✅ |
| Announce prefix | `POST /api/v1/gateway/bgp/prefixes` | `AnnouncePrefix` | `OpGatewayAnnouncePrefix` (`0x05`) | `gateway_bgp_announce` | ✅ |
| Withdraw prefix | `DELETE /api/v1/gateway/bgp/prefixes` | `WithdrawPrefix` | `OpGatewayWithdrawPrefix` (`0x06`) | `gateway_bgp_withdraw` | ✅ |

BGP is complete on all five reachable transports. Announce and withdraw share
the `/bgp/prefixes` path and are distinguished by method; the prefix travels in
the body, which is why withdraw is a `DELETE` with a payload rather than a path
parameter.

---

## 4. IPAM

REST exposes a reduced set under `/api/v1/gateway/ipam`; gRPC and MCP carry full
pool CRUD. QUIC has both the gateway-category sub-opcodes and a dedicated **IPAM
category opcode `0x3F`**.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List pools | `GET /api/v1/gateway/ipam/pools` | `ListIPAMPools` | `OpGatewayListIPAMPools` (`0x08`) | `gateway_ipam_pools` | ✅ |
| Create pool | `MISSING — docs/13 G7` | `CreateIPAMPool` | `OpGatewayCreateIPAMPool` (`0x0C`) | `gateway_ipam_pool_create` | ✅ |
| Get pool | `MISSING — docs/13 G7` | `GetIPAMPool` | `OpGatewayGetIPAMPool` (`0x0E`) | `gateway_ipam_pool_get` | ✅ |
| Update pool | `MISSING — docs/13 G7` | `UpdateIPAMPool` | `OpGatewayUpdateIPAMPool` (`0x0F`) | `gateway_ipam_pool_update` | ✅ |
| Delete pool | `MISSING — docs/13 G7` | `DeleteIPAMPool` | `OpGatewayDeleteIPAMPool` (`0x0D`) | `gateway_ipam_pool_delete` | ✅ |
| List allocations | `GET /api/v1/gateway/ipam/allocations` | `ListAllocations` | `OpGatewayListAllocations` (`0x0B`) | `gateway_ipam_allocations` | ✅ |
| Allocate IP | `POST /api/v1/gateway/ipam/allocations` | `AllocateIP` | `OpGatewayAllocateIP` (`0x09`) | `gateway_ipam_allocate` | ✅ |
| Release IP | `DELETE /api/v1/gateway/ipam/allocations` | `ReleaseIP` | `OpGatewayReleaseIP` (`0x0A`) | `gateway_ipam_release` | ✅ |

**Pool CRUD is missing from REST entirely** — four of the eight IPAM
capabilities. REST can list pools and manage allocations but cannot create,
read, update or delete a pool. That is the largest single hole in this feature.

---

## 5. Load balancer

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| LB status | `MISSING — docs/13 G7` | `GetLBStatus` | sub-opcode range (`pkg/api/daemon/gateway_lb_quic.go`) | `gateway_lb_status` | ✅ |
| Add VIP | `MISSING — docs/13 G7` | `AddVIP` | as above | `gateway_lb_vip_add` | ✅ |
| Get VIP | `MISSING — docs/13 G7` | `GetVIP` | as above | `gateway_lb_vip_get` | ✅ |
| List VIPs | `MISSING — docs/13 G7` | `ListVIPs` | as above | `gateway_lb_vip_list` | ✅ |
| Remove VIP | `MISSING — docs/13 G7` | `RemoveVIP` | as above | `gateway_lb_vip_remove` | ✅ |
| Set VIP backends | `MISSING — docs/13 G7` | `SetVIPBackends` | as above | `gateway_lb_vip_set_backends` | ✅ |

**The load balancer has no REST surface at all.** Six capabilities on gRPC,
Unix, QUIC, MCP and embedded; zero on REST. A REST-only client cannot see or
manage a VIP.

---

## 6. Performance and datapath statistics

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`, `0x36`–`0x38`) | MCP | Embedded |
|---|---|---|---|---|---|
| Flow statistics | `MISSING — docs/13 G7` | `GetPerfFlows` | ✅ | `gateway_perf_flows` | ✅ |
| Datapath statistics | `MISSING — docs/13 G7` | `GetPerfDatapath` | ✅ | `gateway_perf_datapath` | ✅ |
| Conntrack statistics | `MISSING — docs/13 G7` | `GetPerfConntrack` | ✅ | `gateway_perf_conntrack` | ✅ |

The perf sub-opcodes `0x36`–`0x38` are served by the same shared perf service
as the other transports; when the perf backend is not wired, they return
`StatusUnavailable` rather than failing as unknown opcodes.

---

## 7. Network zones at the gateway

Zone CRUD is `SDNService`'s (`CreateNetworkZone` and friends —
[`docs/sdn/api.md`](../sdn/api.md) §5), but the **QUIC** path and the **MCP**
tools are gateway-scoped:

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`, `0x10`–`0x14`) | MCP | Embedded |
|---|---|---|---|---|---|
| List zones | `MISSING — docs/13 G7` | `SDNService.ListNetworkZones` | `OpGatewayListNetworkZones` (`0x10`) | `gateway_zone_list` | ✅ |
| Create zone | `MISSING — docs/13 G7` | `SDNService.CreateNetworkZone` | `OpGatewayCreateNetworkZone` (`0x11`) | `gateway_zone_create` | ✅ |
| Update zone | `MISSING — docs/13 G7` | `SDNService.UpdateNetworkZone` | `0x12`–`0x14` range | `gateway_zone_update` | ✅ |
| Delete zone | `MISSING — docs/13 G7` | `SDNService.DeleteNetworkZone` | as above | `gateway_zone_delete` | ✅ |
| Assign zone | `MISSING — docs/13 G7` | `SDNService.AssignNetworkZone` | as above | `gateway_zone_assign` | ✅ |

Zones are split across two gRPC services and two MCP prefixes. That is worth
knowing before searching for `sdn_zone_*` tools, which do not exist.

---

## 8. Control-plane liaison

A second REST router under the same `/api/v1/gateway` prefix
(`pkg/webservice/v1/rest/gateway/control_plane.go`) carries the gateway ⇄
control-plane conversation. These routes are served by the **control plane**,
consumed by gateways:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/gateway/state` | List reported gateway state |
| GET | `/api/v1/gateway/state/{id}` | One gateway's state |
| DELETE | `/api/v1/gateway/state/{id}` | Forget a gateway's state |
| POST | `/api/v1/gateway/telemetry` | Gateway pushes telemetry |
| GET | `/api/v1/gateway/desired-config/{id}` | Gateway fetches its desired configuration |

`desired-config` is the direction of authority made explicit: the control plane
decides, the gateway fetches. A gateway does not author its own configuration.

---

## 9. Trusted reverse proxy

REST is served through `pkg/api/daemon/proxy_rest.go`; QUIC through sub-opcodes
`0x20`–`0x2D` **multiplexed under the gateway category `0x2F`**.

| Capability | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|
| Create route | `CreateRoute` | ✅ | `proxy_route_create` | ✅ |
| Get route | `GetRoute` | ✅ | `proxy_route_get` | ✅ |
| Update route | `UpdateRoute` | ✅ | `proxy_route_update` | ✅ |
| Delete route | `DeleteRoute` | ✅ | `proxy_route_delete` | ✅ |
| List routes | `ListRoutes` | ✅ | `proxy_route_list` | ✅ |
| Create pool | `CreatePool` | ✅ | `proxy_pool_create` | ✅ |
| Get pool | `GetPool` | ✅ | `proxy_pool_get` | ✅ |
| Update pool | `UpdatePool` | ✅ | `proxy_pool_update` | ✅ |
| Delete pool | `DeletePool` | ✅ | `proxy_pool_delete` | ✅ |
| List pools | `ListPools` | ✅ | `proxy_pool_list` | ✅ |
| Get proxy config | `GetProxyConfig` | ✅ | `proxy_config` | ✅ |
| Get proxy status | `GetProxyStatus` | ✅ | `proxy_status` | ✅ |
| Reload proxy config | `ReloadProxyConfig` | ✅ | `proxy_config_reload` | ✅ |
| Get zone matrix | `GetZoneMatrix` | ✅ | `proxy_zone_matrix` | ✅ |

`GetZoneMatrix` is the join between proxy routing and SDN zoning: it reports
which zones may reach which, so a route's reachability is derived rather than
configured twice.

---

## 10. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.
**`GatewayService` (9 methods) and `ProxyService` (14 methods) are both in the
gRPC scope catalog** (`pkg/api/grpc/method_permissions.go`), so gateway and
proxy operations do require a scope — unlike registry, attestation, overlay and
switch, which are absent from the catalog and therefore require only a validated
token.

Nine of `GatewayService`'s 24 RPCs are mapped. The unmapped fifteen — which
include the IPAM pool CRUD and the LB VIP operations — carry no required scope,
because a method absent from the map is allowed once the token validates. That
asymmetry within a single service is raised as an owner question in the
migration report.

---

## 11. Status and error mapping

| QUIC byte | Name | REST | Gateway cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed prefix, pool, VIP or route |
| `0x02` | `StatusNotFound` | 404 | Unknown pool, VIP, route or gateway ID |
| `0x03` | `StatusUnauthorized` | 401 | Proxy auth chain rejected the request |
| `0x04` | `StatusInternalError` | 500 | BGP speaker or datapath failure |
| `0x06` | `StatusAlreadyExists` | 409 | Duplicate pool, VIP or route |
| `0x07` | `StatusPermissionDenied` | 403 | Missing scope; proxy policy denied |
| `0x08` | `StatusResourceExhausted` | 429 | IPAM pool exhausted |
| `0x0A` | `StatusUnavailable` | 503 | A service section not enabled or its backend not wired |

**`StatusUnavailable` is the normal answer for a disabled service section.** A
gateway with `bgp` off answers BGP calls with 503, not 404 — the capability
exists and is switched off, which is a different thing from not existing.

---

## 12. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. The one deprecated element is
`GatewayMode` and its `SetGatewayMode` RPC / `gateway_mode_set` tool /
`POST /api/v1/gateway/mode` route — retained for compatibility during the
migration to config-driven service sections.

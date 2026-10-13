# Gateway REST API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). Covers only status, mode, snapshots, admitted VTEPs and BGP; IPAM, load balancer, NAT64, perf statistics and network zones are missing here.

Base paths are `/api/v1/gateway` for gateway state and `/api/v1/sdn/gateway`
for SDN-scoped gateway operations.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/gateway/status` | Gateway node status. |
| `POST` | `/api/v1/gateway/mode` | Deprecated compatibility mode setter. |
| `GET` | `/api/v1/gateway/state` | List reported gateway snapshots. |
| `GET` | `/api/v1/gateway/state/{gateway_id}` | Read one gateway snapshot. |
| `GET` | `/api/v1/sdn/gateway/overlay/vteps` | List admitted overlay VTEPs. Optional `gateway_id` query selects a reported gateway. |
| `GET` | `/api/v1/sdn/gateway/overlay/vteps/{vtep}` | Read one admitted overlay VTEP. Optional `gateway_id` query selects a reported gateway. |
| `GET` | `/api/v1/sdn/gateway/bgp/status` | BGP speaker status. |
| `GET` | `/api/v1/sdn/gateway/bgp/peers` | List BGP peers. |
| `GET` | `/api/v1/sdn/gateway/bgp/prefixes` | List announced prefixes. |
| `POST` | `/api/v1/sdn/gateway/bgp/prefixes` | Announce `prefix` with `next_hop`. |
| `DELETE` | `/api/v1/sdn/gateway/bgp/prefixes/{prefix}` | Withdraw a prefix. `{prefix}` is the CIDR as written, `/` included. |
| `GET` | `/api/v1/gateway/bgp/status` | Web service form of the status read. |
| `GET` | `/api/v1/gateway/bgp/peers` | Web service form of the peer list. |
| `GET` | `/api/v1/gateway/bgp/prefixes` | Web service form of the prefix list. |
| `POST` | `/api/v1/gateway/bgp/prefixes` | Web service form of announce. |
| `DELETE` | `/api/v1/gateway/bgp/prefixes` | Web service form of withdraw; the prefix is the `prefix` query parameter. |

The snapshot response includes `overlay` when the overlay service is running.
That object carries the local VTEP, table ids, admitted VTEPs and ND counters:
`punted`, `answered`, `meter_dropped`, `queue_dropped`, and `fell_through`.

An admitted-VTEP read returns not found when the address is not currently
admitted.

The BGP reads require `sdn:read` and announce/withdraw `sdn:write`. With no
BGP speaker every BGP route answers `503 Service Unavailable` ([api.md](api.md)
§3); a malformed prefix or next hop answers `400`.

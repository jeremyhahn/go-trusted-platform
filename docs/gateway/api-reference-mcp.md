# Gateway MCP API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). Covers only status, mode, snapshots, admitted VTEPs and BGP; IPAM, load balancer, NAT64, perf statistics and network zones are missing here.

Gateway MCP tools expose the same service-layer operations as the other
transports.

| Tool | Description |
|---|---|
| `gateway_status` | Gateway node status. |
| `gateway_mode_set` | Deprecated compatibility mode setter. |
| `gateway_snapshot` | Read one gateway snapshot. |
| `gateway_snapshots` | List reported gateway snapshots. |
| `gateway_admitted_vtep` | Read one admitted overlay VTEP by IP address. |
| `gateway_admitted_vteps` | List admitted overlay VTEPs. |
| `gateway_bgp_status` | BGP speaker status. Requires `sdn:read`. |
| `gateway_bgp_peers` | List BGP peers. Requires `sdn:read`. |
| `gateway_bgp_prefixes` | List announced prefixes. Requires `sdn:read`. |
| `gateway_bgp_announce` | Announce `prefix` with `next_hop`. Requires `sdn:write`. |
| `gateway_bgp_withdraw` | Withdraw `prefix`. Requires `sdn:write`. |

The overlay snapshot object carries admitted VTEPs and ND counters. The direct
admitted-VTEP tools return the same VTEP shape as the snapshot overlay list.
Like `gateway_snapshot`, both admitted-VTEP tools require `sdn:read`.

`gateway_bgp_status` returns the status object itself; `gateway_bgp_peers` and
`gateway_bgp_prefixes` return `{"peers": [...]}` and `{"prefixes": [...]}`;
announce and withdraw return `{"success": true}`. With no BGP speaker every
BGP tool answers the typed "not configured" error ([api.md](api.md) §3).

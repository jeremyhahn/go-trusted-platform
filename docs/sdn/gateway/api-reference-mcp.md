# Gateway MCP API Reference

Transport: MCP (stdio / HTTP, port 9445).

Tool definitions: `pkg/api/mcp/gateway_tools.go` (plus the LB and perf
tools registered alongside). OAuth scopes (`sdn:read` / `sdn:write` /
`sdn:delete`) are mapped in `pkg/api/mcp/authz.go`.

## Tools

### Status and Mode

| Tool | Description |
|------|-------------|
| `gateway_status` | Gateway status: modes, tier, reputation, health |
| `gateway_mode_set` | Set the active gateway modes (overlay, edge, transit) |

### BGP

| Tool | Description |
|------|-------------|
| `gateway_bgp_status` | BGP speaker status (ASN, router ID, peers, prefixes) |
| `gateway_bgp_peers` | List configured BGP peers |
| `gateway_bgp_announce` | Announce a prefix (args: prefix, next_hop) |
| `gateway_bgp_withdraw` | Withdraw an announced prefix (args: prefix) |
| `gateway_bgp_prefixes` | List announced prefixes |

### IPAM

| Tool | Description |
|------|-------------|
| `gateway_ipam_pools` | List IPAM pools |
| `gateway_ipam_pool_get` | Get a pool by ID |
| `gateway_ipam_pool_create` | Create a pool (name, cidr, gateway, zone, ...) |
| `gateway_ipam_pool_update` | Update a pool |
| `gateway_ipam_pool_delete` | Delete a pool |
| `gateway_ipam_allocate` | Allocate an IP (pool_id, device_id, hostname) |
| `gateway_ipam_release` | Release an allocated IP |
| `gateway_ipam_allocations` | List allocations |

### Network Zones

| Tool | Description |
|------|-------------|
| `gateway_zone_list` | List network trust zones |
| `gateway_zone_create` | Create a zone |
| `gateway_zone_update` | Update zone policy settings |
| `gateway_zone_delete` | Delete a zone |
| `gateway_zone_assign` | Assign a network segment to a zone |

### Load Balancer

| Tool | Description |
|------|-------------|
| `gateway_lb_status` | Load balancer health (VIPs, backend counts) |
| `gateway_lb_vip_add` | Add a VIP with backends |
| `gateway_lb_vip_remove` | Remove a VIP |
| `gateway_lb_vip_get` | Get one VIP with per-backend health |
| `gateway_lb_vip_list` | List all VIPs |
| `gateway_lb_vip_set_backends` | Replace a VIP's backend set |

### Performance

| Tool | Description |
|------|-------------|
| `gateway_perf_flows` | Timed flow install (MUTATES bridge; sdn:write) |
| `gateway_perf_datapath` | Live datapath counters (sdn:read) |
| `gateway_perf_conntrack` | Conntrack table summary (sdn:read) |

## Input Schemas

Each tool declares a JSON schema for its arguments in
`pkg/api/mcp/gateway_tools.go`; argument names mirror the CLI flags.

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [Operations Guide](operations.md)

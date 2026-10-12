# IPAM MCP API Reference

IPAM operations are exposed as gateway MCP tools
(`pkg/api/mcp/gateway_tools.go`), served via MCP (stdio / HTTPS, port
9445).

## Tools

| Tool | Description |
|------|-------------|
| `gateway_ipam_pools` | List IPAM pools |
| `gateway_ipam_pool_get` | Get a pool by ID |
| `gateway_ipam_pool_create` | Create a pool (name, cidr, gateway, zone, description, lease, reserved, range_start, range_end) |
| `gateway_ipam_pool_update` | Update pool metadata; `reserved`, `range_start`, `range_end` replace the window fields present (`[]`/`""` clear) |
| `gateway_ipam_pool_delete` | Delete a pool |
| `gateway_ipam_allocate` | Allocate an IP (pool_id, device_id, optional hostname) |
| `gateway_ipam_release` | Release an allocated IP |
| `gateway_ipam_allocations` | List allocations (optional pool filter) |

Input schemas are declared per tool in
`pkg/api/mcp/gateway_tools.go`; argument names mirror the CLI flags.

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway MCP API Reference](../../gateway/api.md)

# IPAM MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> IPAM as gateway MCP tools.

IPAM operations are exposed as gateway MCP tools
(`pkg/api/mcp/gateway_tools.go`), served via MCP (stdio / HTTPS, port
9445). A tool's result is a `CallToolResult` whose text block holds the tool's
JSON output ([daemon api.md](../../daemon/api.md) §1 "MCP tool results").

## Tools

| Tool | Description |
|------|-------------|
| `gateway_ipam_pools` | List IPAM pools |
| `gateway_ipam_pool_get` | Get a pool by ID (`pool_id`) |
| `gateway_ipam_pool_create` | Create a pool (`name`, `cidr`, `gateway`, `zone`, `description`, `lease_duration_seconds`, `reserved`, `range_start`, `range_end`); there is no `id` argument, so the ID is generated |
| `gateway_ipam_pool_update` | Update a pool (`pool_id` plus the create fields other than `cidr`); `reserved`, `range_start`, `range_end` replace the window fields present (`[]`/`""` clear) |
| `gateway_ipam_pool_delete` | Delete a pool (`pool_id`) |
| `gateway_ipam_allocate` | Allocate an IP (`pool_id`, `device_id`, optional `hostname`); no requested address |
| `gateway_ipam_release` | Release an allocated IP (`ip`) |
| `gateway_ipam_allocations` | List allocations (optional `pool_id`) |

Input schemas are declared per tool in `pkg/api/mcp/gateway_tools.go`
(from line 314). Arguments are the CLI flags in snake case (`--pool-id` is
`pool_id`); `lease_duration_seconds` has no CLI flag. `gateway_ipam_pools`
takes an optional `zone`.

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway MCP API Reference](../../gateway/api.md)

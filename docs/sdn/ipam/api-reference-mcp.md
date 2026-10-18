# IPAM MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-18
> IPAM as gateway MCP tools.

IPAM operations are exposed as gateway MCP tools
(`pkg/api/mcp/gateway_tools.go`), served via MCP (stdio / HTTPS, port
9445).

## Tools

| Tool | Description |
|------|-------------|
| `gateway_ipam_pools` | List IPAM pools |
| `gateway_ipam_pool_get` | Get a pool by ID (`pool_id`) |
| `gateway_ipam_pool_create` | Create a pool (`name`, `cidr`, `gateway`, `zone`, `description`, `lease_duration_seconds`, `reserved`, `range_start`, `range_end`); there is no `id` argument, so the ID is generated |
| `gateway_ipam_pool_update` | Update a pool (`pool_id` plus the create fields other than `cidr`); `reserved`, `range_start`, `range_end` replace the window fields present (`[]`/`""` clear) |
| `gateway_ipam_pool_delete` | Delete a pool (`pool_id`) |
| `gateway_ipam_allocate` | Allocate an IP (`pool_id`, `device_id`, optional `hostname`); no requested address |
| `gateway_ipam_release` | Release an allocated IP (`ip`); an address with no allocation is not found |
| `gateway_ipam_allocations` | List the active and reserved allocations of `pool_id`, or of every pool when `pool_id` is omitted; a released address is not listed, and an unknown `pool_id` is not found |

`gateway_ipam_release` and `gateway_ipam_allocations` answer as gRPC
`ReleaseIP` and `ListAllocations` do: the same allocations, and an unknown
pool or address is the not-found class, not an internal error.

## Errors

Every tool answers the class the gRPC method it mirrors answers for the
same error (`ipamErrToGRPC`, `pkg/api/daemon/gateway_grpc_service.go`); the
JSON-RPC code is that class (`mcpwire.CodeForClass`,
`sdk/go/wire/mcpwire/errorcodes.go`) and the message is the error text.

| Code | Class | Raised by |
|------|-------|-----------|
| `-32602` | `InvalidArgument` | A malformed `cidr`, `gateway` or `ip`; a `reserved` entry that is not a prefix, or a `range_start`/`range_end` outside the pool or set alone |
| `-32004` | `Unavailable` | IPAM is not configured, or its backend is unavailable |
| `-32005` | `NotFound` | An unknown `pool_id` (get, update, delete, allocate, allocations); an `ip` with no allocation (release) |
| `-32006` | `AlreadyExists` | A pool whose name or CIDR clashes with an existing pool (create) |
| `-32007` | `FailedPrecondition` | Deleting a pool that still holds allocations |
| `-32603` | `ResourceExhausted` | Allocating from a pool with no free address: `mcpwire` maps no code to this class, so MCP answers the internal code with the message `pool exhausted` |
| `-32603` | `Internal` | Any other failure |

Input schemas are declared per tool in `pkg/api/mcp/gateway_tools.go`
(from line 314). Arguments are the CLI flags in snake case (`--pool-id` is
`pool_id`); `lease_duration_seconds` has no CLI flag. `gateway_ipam_pools`
takes an optional `zone`.

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway MCP API Reference](../../gateway/api.md)

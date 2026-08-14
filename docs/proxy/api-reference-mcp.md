# Proxy MCP API Reference

MCP (Model Context Protocol) tools for the reverse-proxy configuration
service.

| Property | Value |
|----------|-------|
| Port | 9445 (HTTP) or stdio |
| Tools | `pkg/api/mcp/proxy_tools.go` |
| Provider | daemon `MCPServiceProvider` (`pkg/api/daemon/proxy_mcp.go`) |

Tool arguments and results use the protobuf JSON shapes of the
`platform.v1` request/response messages (snake_case field names), so
AI/LLM clients and the SDK MCP transport share one contract.

## Tools

| Tool | Scope | Arguments |
|------|-------|-----------|
| `proxy_route_create` | `proxy:write` | `route` (ProxyRoute JSON) |
| `proxy_route_get` | `proxy:read` | `id` |
| `proxy_route_update` | `proxy:write` | `id` (optional), `route` |
| `proxy_route_delete` | `proxy:delete` | `id` |
| `proxy_route_list` | `proxy:read` | — |
| `proxy_pool_create` | `proxy:write` | `pool` (ProxyPool JSON) |
| `proxy_pool_get` | `proxy:read` | `id` |
| `proxy_pool_update` | `proxy:write` | `id` (optional), `pool` |
| `proxy_pool_delete` | `proxy:delete` | `id` |
| `proxy_pool_list` | `proxy:read` | — |
| `proxy_config` | `proxy:read` | — |
| `proxy_status` | `proxy:read` | — |
| `proxy_config_reload` | `proxy:write` | — |
| `proxy_zone_matrix` | `proxy:read` | — |

## Examples

Create a route:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "proxy_route_create",
    "arguments": {
      "route": {
        "id": "web",
        "path_prefix": "/",
        "pool_id": "web-pool",
        "auth": {"mode": "public"}
      }
    }
  }
}
```

Create a pool:

```json
{
  "name": "proxy_pool_create",
  "arguments": {
    "pool": {
      "id": "web-pool",
      "backends": [{"url": "https://10.0.0.10:8443", "weight": 2}],
      "tls": {"trust_class": "internal", "mtls_client_cert": true}
    }
  }
}
```

Results carry the protobuf response JSON, e.g. `proxy_status`:

```json
{"version": 4, "route_count": 2, "pool_count": 1, "updated_at": 1754800000}
```

## Errors

A daemon started without the proxy store wired returns
`proxy: configuration service not configured`. Missing required
arguments return `proxy: id is required` / `proxy: route is required` /
`proxy: pool is required`. Backend failures surface the shared service
error text (not-found, already-exists, pool-in-use, validation).

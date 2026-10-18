# Object Storage MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The `objectstorage_*` MCP tools, their arguments, scopes and wire conventions.

| Property | Value |
|----------|-------|
| Endpoint | `https://host:9445` |
| Tools | `objectstorage_*` (`appServiceTools`, `pkg/api/mcp/app_service_tools.go`) |
| Backend | the same `ObjectStorageGRPCService` the other transports call |
| SDK mapping | `sdk/go/transport/mcp/app_services.go` |

## Tools

| Tool | RPC | Scope | Required arguments |
|------|-----|-------|--------------------|
| `objectstorage_put` | `PutObject` | `objectstorage:write` | `key`, `target_backend` |
| `objectstorage_get` | `GetObject` | `objectstorage:read` | `key` |
| `objectstorage_delete` | `DeleteObject` | `objectstorage:delete` | `key` |
| `objectstorage_head` | `HeadObject` | `objectstorage:read` | `key` |
| `objectstorage_list` | `ListObjects` | `objectstorage:read` | none |
| `objectstorage_copy` | `CopyObject` | `objectstorage:write` | `source_key`, `destination_key`, `target_backend` |
| `objectstorage_list_by_tag` | `ListObjectsByTag` | `objectstorage:read` | `tag_name` |
| `objectstorage_list_tenant` | `ListTenantObjects` | `objectstorage:read` | `tenant_id` |

A tool's input schema lists every field of its request. A caller without the
tool's scope is refused before the tool runs.

## Wire conventions

- Arguments are the RPC request and results the RPC response, in the proto3
  JSON mapping under the proto field names: `value` and `checksum` are
  base64, 64-bit integers (`object_id`, `version`, `size`, the `*_unix_ms`
  times) are strings, and `tags` is a JSON object.
- An argument the request does not have is refused as invalid.
- A gRPC status becomes the JSON-RPC error code of its class
  (`sdk/go/wire/mcpwire`), and the SDK maps it back. A daemon whose MCP
  provider has no object storage server answers `UNAVAILABLE`
  (`ErrAppServiceNotConfigured`).

```json
{"name": "objectstorage_put",
 "arguments": {"key": "docs:a.txt", "value": "aGk=", "target_backend": "default",
               "tags": {"env": "prod"}}}
```

# Object Storage REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The `/api/v1/object-storage` routes, their parameters and HTTP status mapping.

| Property | Value |
|----------|-------|
| Base path | `/api/v1/object-storage` |
| Routes | `appRESTRoutes` (`pkg/api/rest/app_service_handlers.go`) |
| Listeners | daemon REST (`restapi.ScopeGuard`) and the platformd HTTPS listener in webservice mode (`appServiceRoutes`, `pkg/webservice/v1/router.go`, behind the admin role gate) |
| Encoding | protojson; responses use the JSON field names (`objectId`, `createdAtUnixMs`), emit unset fields, and render 64-bit integers as strings and bytes as base64 |

## Routes

An object key contains `:` and `/`, so item routes take it from the query
string rather than the path.

| Method and path | RPC | Scope | Success |
|-----------------|-----|-------|---------|
| `POST /objects` | `PutObject` | `objectstorage:write` | `201` |
| `GET /objects?prefix=&tenant_id=&limit=&cursor=&include_tags=` | `ListObjects` | `objectstorage:read` | `200` |
| `POST /objects/copy` | `CopyObject` | `objectstorage:write` | `201` |
| `GET /objects/by-tag?tag_name=&tag_value=&tenant_id=&limit=&cursor=` | `ListObjectsByTag` | `objectstorage:read` | `200` |
| `GET /object?key=&tenant_id=&include_metadata=` | `GetObject` | `objectstorage:read` | `200` |
| `DELETE /object?key=&tenant_id=` | `DeleteObject` | `objectstorage:delete` | `200` |
| `GET /object/metadata?key=&tenant_id=` | `HeadObject` | `objectstorage:read` | `200` |
| `GET /tenants/{tenant_id}/objects?limit=&cursor=&include_tags=` | `ListTenantObjects` | `objectstorage:read` | `200` |

`POST` routes take the whole request as a protojson body, under either the
proto or the JSON field names; `value` is base64. `GET` and `DELETE` routes
take only the query parameters listed. A query value that does not parse as
its field's type is `400`.

```http
POST /api/v1/object-storage/objects
Content-Type: application/json

{"key": "docs:reports/a.txt", "value": "aGk=", "content_type": "text/plain",
 "tags": {"env": "prod"}, "target_backend": "default"}
```

## Status mapping

| gRPC status | HTTP |
|-------------|------|
| `INVALID_ARGUMENT`, undecodable body or query | `400` |
| `UNAUTHENTICATED` | `401` |
| `PERMISSION_DENIED` | `403` |
| `NOT_FOUND` | `404` |
| `ALREADY_EXISTS`, `ABORTED`, `FAILED_PRECONDITION` | `409` |
| `UNAVAILABLE` (service not configured) | `503` |
| `DEADLINE_EXCEEDED` | `504` |
| `UNIMPLEMENTED` | `501` |
| anything unmapped | `500` |

The table is `protorestHTTPStatus` (`pkg/api/rest/ntp_handlers.go`).

Errors use the `{error, code, timestamp}` envelope. The daemon REST listener
always mounts the routes and always constructs the object storage server, so a
node without the SDK answers `503` through the `UNAVAILABLE` row above. The
webservice listener mounts none of the application service routes (`404`)
only when all four of its cache, scheduler, messaging and object storage
servers are nil; with any one of them present, a nil object storage server
answers `503` (`appRESTMethod`).

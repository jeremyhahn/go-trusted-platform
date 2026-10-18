# Object Storage gRPC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The `platform.v1.ObjectStorageService` methods, messages and status codes.

| Property | Value |
|----------|-------|
| Endpoint | `host:10443` (TCP, TLS 1.3); the same service on `/run/platformd.sock` |
| Service | `platform.v1.ObjectStorageService` (`pkg/api/grpc/proto/objectstorage.proto`) |
| Server | `ObjectStorageGRPCService` (`pkg/api/daemon/objectstorage_grpc_service.go`) |
| Scopes | `pkg/api/grpc/method_permissions.go` |

## Methods

| Method | Request / response | Scope |
|--------|--------------------|-------|
| `PutObject` | `PutObjectRequest` / `PutObjectResponse` | `objectstorage:write` |
| `GetObject` | `GetObjectRequest` / `GetObjectResponse` | `objectstorage:read` |
| `DeleteObject` | `DeleteObjectRequest` / `DeleteObjectResponse` | `objectstorage:delete` |
| `HeadObject` | `HeadObjectRequest` / `HeadObjectResponse` | `objectstorage:read` |
| `ListObjects` | `ListObjectsRequest` / `ListObjectsResponse` | `objectstorage:read` |
| `CopyObject` | `CopyObjectRequest` / `CopyObjectResponse` | `objectstorage:write` |
| `ListObjectsByTag` | `ListObjectsByTagRequest` / `ListObjectsResponse` | `objectstorage:read` |
| `ListTenantObjects` | `ListTenantObjectsRequest` / `ListObjectsResponse` | `objectstorage:read` |

## Messages

- `PutObjectRequest` carries `key`, `value`, `content_type`, `tenant_id`,
  `shard_id`, `tags`, the optional `replication_policy`, `archive_policy` and
  `retention_policy`, `target_backend` and an optional `checksum` of `value`
  that the store verifies. A policy left unset sends none, so the store
  defaults apply.
- `GetObjectRequest.include_metadata` asks the store to include the object
  metadata in the reply; `value` is always returned.
- `HeadObjectResponse` adds `status`, `last_access_at_unix_ms` and
  `replica_count` to the object metadata.
- `CopyObjectRequest.tenant_id` empty keeps the source tenant;
  `overwrite_existing` replaces an existing destination.
- `ObjectSummary`, the list entry, carries `key`, `size`, `content_type`,
  `version`, `status`, `created_at_unix_ms`, `modified_at_unix_ms`, and `tags`
  when the list asked for them.

Times are Unix milliseconds. `PutObjectResponse.checksum` is the SHA-256 of
the stored data.

## Status codes

The service maps each error through `appServiceStatus`
(`pkg/api/daemon/app_services.go`); the table is in
[api-reference.md](api-reference.md#errors). A `PutObject` or `CopyObject`
without `target_backend` is `INVALID_ARGUMENT` naming the field
([api-reference.md](api-reference.md#limits-of-the-pinned-sdk)).

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolGRPC),
    platform.WithGRPCAddr("localhost:10443"),
    platform.WithTLSConfig(tlsConfig)))
put, err := client.ObjectStorage().PutObject(ctx, &platformv1.PutObjectRequest{
    Key: "docs:reports/a.txt", Value: data, TargetBackend: "default",
})
```

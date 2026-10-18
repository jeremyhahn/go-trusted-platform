# Object Storage Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The object storage gRPC service on the local Unix socket.

| Property | Value |
|----------|-------|
| Socket | `/run/platformd.sock` |
| Protocol | gRPC over UDS (`platform.v1.ObjectStorageService`) |
| Auth | `SO_PEERCRED` (no TLS on the local socket) |

The Unix transport is the same `ObjectStorageGRPCService` instance registered
on the gRPC UDS server, so every method, error mapping and limit documented in
[api-reference-grpc.md](api-reference-grpc.md) applies unchanged.
`platformctl objectstorage` uses this socket in a local context.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock")))
list, err := client.ObjectStorage().ListObjects(ctx, &platformv1.ListObjectsRequest{
    Prefix: "docs:", IncludeTags: true,
})
```

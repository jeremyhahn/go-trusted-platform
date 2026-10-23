# Object Storage QUIC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The object storage sub-opcodes under `0x60`, the wire format and the QUIC status bytes.

| Property | Value |
|----------|-------|
| Endpoint | `host:9444` (UDP, QUIC + TLS 1.3) |
| Category opcode | `0x60` (`OpObjectStorageCategory`, `sdk/go/wire/quicwire/appservice_opcodes.go`) |
| Sub-opcode range | `0x01`-`0x08` (`ObjectStorageSub*`) |
| Message format | sub-opcode byte + MessagePack-encoded `platform.v1` request |
| Handler | `objectStorageQUICHandlers` (`pkg/api/daemon/quic_app_services.go`) |
| Scopes | `pkg/api/quic/opcode_permissions.go` |

`payload[0]` selects the sub-operation and `payload[1:]` is the request.
Every request carries a body, even an empty message. The handler calls the
same `ObjectStorageGRPCService` instance the other transports call.

## Sub-Opcodes

| Sub-opcode | Operation | Request / response messages | Scope |
|-----------|-----------|------------------------------|-------|
| `0x01` | PutObject | `PutObjectRequest` / `PutObjectResponse` | `objectstorage:write` |
| `0x02` | GetObject | `GetObjectRequest` / `GetObjectResponse` | `objectstorage:read` |
| `0x03` | DeleteObject | `DeleteObjectRequest` / `DeleteObjectResponse` | `objectstorage:delete` |
| `0x04` | HeadObject | `HeadObjectRequest` / `HeadObjectResponse` | `objectstorage:read` |
| `0x05` | ListObjects | `ListObjectsRequest` / `ListObjectsResponse` | `objectstorage:read` |
| `0x06` | CopyObject | `CopyObjectRequest` / `CopyObjectResponse` | `objectstorage:write` |
| `0x07` | ListObjectsByTag | `ListObjectsByTagRequest` / `ListObjectsResponse` | `objectstorage:read` |
| `0x08` | ListTenantObjects | `ListTenantObjectsRequest` / `ListObjectsResponse` | `objectstorage:read` |

## Wire Format

The `platform.v1` object storage messages are oneof-free, so the generated pb
structs encode and decode directly through the payload codec. The SDK QUIC
adapter (`sdk/go/transport/quic`) maps each gRPC method to its category and
sub-opcode, encodes the pb request, prepends the sub-opcode, and decodes the
response payload into the pb reply.

## Status Bytes

The gRPC code of a failed call becomes a status byte
(`grpcDelegateCodeToQUICStatus`, `pkg/api/daemon/quic_grpc_delegates.go`):

| gRPC status | QUIC status |
|-------------|-------------|
| `INVALID_ARGUMENT` | `StatusInvalidArgument` |
| `NOT_FOUND` | `StatusNotFound` |
| `ALREADY_EXISTS` | `StatusAlreadyExists` |
| `PERMISSION_DENIED` | `StatusPermissionDenied` |
| `FAILED_PRECONDITION` | `StatusInvalidRequest` |
| `UNAVAILABLE` | `StatusUnavailable` |
| `DEADLINE_EXCEEDED` | `StatusTimeout` |
| anything else | `StatusInternalError` |

An undecodable body is `StatusInvalidRequest`, and a daemon with no object
storage server answers `StatusUnavailable` naming the service. An unknown
sub-opcode is refused `StatusPermissionDenied` by the authorization guard,
which has no scope for it.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithTLSConfig(tlsConfig)))
head, err := client.ObjectStorage().HeadObject(ctx, &platformv1.HeadObjectRequest{
    Key: "docs:reports/a.txt",
})
```

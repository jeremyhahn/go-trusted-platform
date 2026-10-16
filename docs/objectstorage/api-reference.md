# Object Storage API Reference

> **Status: REFERENCE** · Last verified: 2026-10-16
> The object storage transport map, validation, errors and the limits of the pinned SDK.

platformd serves `platform.v1.ObjectStorageService`
(`pkg/api/grpc/proto/objectstorage.proto`) over the object store of the
composed go-quicbaas data plane. Object keys take the form `namespace:path`.
It is one of the four application services on platformd
([../sdk/api.md §3.5](../sdk/api.md#35-application-services-on-platformd)).

One implementation backs every transport: `ObjectStorageGRPCService`
(`pkg/api/daemon/objectstorage_grpc_service.go`) calls the service layer
`appservices.ObjectStorageService` (`pkg/appservices/objectstorage.go`), and
the service layer is the only code that calls the SDK's
`ObjectStorage()` client. Validation and error mapping are therefore the same
on every transport.

| Transport | Reference | Entry point |
|-----------|-----------|-------------|
| REST | [api-reference-rest.md](api-reference-rest.md) | `/api/v1/object-storage/*` |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | `platform.v1.ObjectStorageService` (TCP `:10443`) |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | `0x60` sub-opcodes `0x01`-`0x08` |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | `objectstorage_*` tools |
| Unix | [api-reference-unix.md](api-reference-unix.md) | `platform.v1.ObjectStorageService` over `/run/platformd.sock` |

The Go SDK reaches the service with `platform.Client.ObjectStorage()` on any
transport, and `platformctl objectstorage` wraps it
([../sdk/cli.md](../sdk/cli.md)).

## RPCs and scopes

| RPC | Scope | Required fields |
|-----|-------|-----------------|
| `PutObject` | `objectstorage:write` | `key`, `target_backend` |
| `GetObject` | `objectstorage:read` | `key` |
| `DeleteObject` | `objectstorage:delete` | `key` |
| `HeadObject` | `objectstorage:read` | `key` |
| `ListObjects` | `objectstorage:read` | none |
| `CopyObject` | `objectstorage:write` | `source_key`, `destination_key`, `target_backend` |
| `ListObjectsByTag` | `objectstorage:read` | `tag_name` |
| `ListTenantObjects` | `objectstorage:read` | `tenant_id` |

The three list RPCs answer `ListObjectsResponse`: `objects`, `next_cursor`,
`has_more`, `total_count`. A negative `limit` is refused; `0` lets the store
choose. A `PutObject` `replication_policy.mode` is empty, `sync`, `async` or
`quorum`.

## Errors

| Cause | gRPC status |
|-------|-------------|
| The node's DAO factory has no SDK, or the SDK does not serve the group | `UNAVAILABLE`, `ErrorInfo` reason `SERVICE_NOT_CONFIGURED`, metadata `service` = `objectstorage` |
| A required field is empty, a `limit` is negative, or a replication mode is unknown | `INVALID_ARGUMENT`, naming the field |
| The SDK answers with a typed error (`QBError`) | its code's gRPC twin (`barrier.SDKCode`): `NotFound` `NOT_FOUND`, `AlreadyExists` `ALREADY_EXISTS`, ... |
| The SDK answers with a gRPC status | that status code |
| Any other SDK failure | `INTERNAL` |

Each transport carries these codes in its own form: an HTTP status on REST, a
status byte on QUIC, a JSON-RPC error class on MCP.

## Limits of the pinned SDK

These come from go-quicbaas `sdk/go v0.12.0-alpha` and its server. Each is
reported upstream as an SDK seam; platformd does not work around them.

- **`target_backend` is required.** The go-quicbaas server builds its object
  store from `config.DefaultObjectStoreDefaults()`, which names no primary
  backend, and the store fails an empty backend name instead of choosing one.
  platformd refuses a `PutObject` or `CopyObject` without `target_backend` with
  `INVALID_ARGUMENT` whose reason names this gap, before the call reaches the
  SDK.
- **Not found is `INTERNAL` on the embedded SDK.** The embedded transport
  returns the data plane's own error type rather than the SDK's `QBError`, so
  `barrier.SDKCode` cannot classify it and a missing object surfaces as
  `INTERNAL`. A `QBError` or gRPC status keeps its code.
- **Objects group only.** The SDK client has no bucket or multipart-upload
  calls. Its other groups (replicate, migrate, archive, restore, verify,
  object policy, backends, tenant usage and quotas, batch, streaming) are not
  served by platformd yet.

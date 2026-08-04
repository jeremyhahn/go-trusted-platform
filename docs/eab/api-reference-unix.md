# EAB Unix Socket API Reference

| Property | Value |
|----------|-------|
| Socket | `/run/platformd.sock` |
| Protocol | gRPC over UDS (`platform.v1.EABService`) |
| Auth | `SO_PEERCRED` (no TLS on the local socket) |

The Unix transport is the same `EABGRPCService` instance registered on
the gRPC UDS server in `pkg/api/daemon/daemon.go`, so every RPC,
error-mapping and security property documented in
[api-reference-grpc.md](api-reference-grpc.md) applies unchanged.

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock"))
eabClient, err := eab.NewClient(client.Transport())
```

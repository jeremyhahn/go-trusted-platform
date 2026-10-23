# EAB Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The EAB gRPC service on the local Unix socket.

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
opts := platform.NewOptions(platform.WithUnixSocket("/run/platformd.sock"))
conn, err := unix.Connect(ctx, opts) // sdk/go/transport/unix
eabClient, err := eab.NewClient(conn)
```

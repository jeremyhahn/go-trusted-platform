# Orchestrator Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-22
> The orchestrator gRPC service on the local Unix socket.

| Property | Value |
|----------|-------|
| Socket | `/run/platformd.sock` |
| Protocol | gRPC over UDS (`platform.v1.OrchestratorService`) |
| Auth | `SO_PEERCRED` (no TLS on the local socket) |

The Unix transport is the same `OrchestratorGRPCService` instance registered
on the gRPC UDS server, so every method, message and status code documented
in [api-reference-grpc.md](api-reference-grpc.md) applies unchanged.
`platformctl orchestrator` uses this socket in a local context.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock")))
sessions, err := client.Orchestrator().ListSessions(ctx, &platformv1.ListOrchestratorSessionsRequest{
    Status: "active",
})
```

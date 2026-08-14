# NTP Unix Socket API Reference

| Property | Value |
|----------|-------|
| Socket | `/run/platformd.sock` |
| Protocol | gRPC over UDS (`platform.v1.NTPService`) |
| Auth | `SO_PEERCRED` (no TLS on the local socket) |

The Unix transport is the same `NTPGRPCService` instance registered on
the gRPC UDS server in `pkg/api/daemon/daemon.go`, so every RPC, status
code and security property documented in
[api-reference-grpc.md](api-reference-grpc.md) applies unchanged.

This is the default transport for `platformctl`, which makes it the
path an operator uses when recovering a node whose clock is wrong and
whose TLS certificates therefore may not validate — the local socket
needs no certificate validity window to be correct.

## CLI

```sh
platformctl ntp status
platformctl ntp status -o json
platformctl ntp sources
platformctl ntp step
```

Add `--protocol {rest,grpc,quic,mcp,unix}` to exercise another
transport; the command surface is identical on all of them.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock")))

ntpClient := ntp.NewClientFromGRPC(client.NTP())
status, err := ntpClient.Status(ctx)
```

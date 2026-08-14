# Proxy Unix Socket API Reference

Unix domain socket access to the reverse-proxy configuration service.

| Property | Value |
|----------|-------|
| Socket | `/run/platformd.sock` |
| Protocol | gRPC over Unix domain socket |
| Service | `platform.v1.ProxyService` |

The Unix transport serves the identical `ProxyService` gRPC surface as
TCP (the daemon registers the same `ProxyGRPCService` on both servers),
so all RPCs, scopes and error codes in
[api-reference-grpc.md](api-reference-grpc.md) apply unchanged.

## CLI Usage

`platformctl` prefers the Unix socket automatically when running on the
platform host:

```bash
platformctl proxy status
platformctl proxy route list
platformctl proxy pool add --id web-pool --backend https://10.0.0.10:8443
```

Force the Unix transport explicitly:

```bash
platformctl --protocol unix proxy status
```

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock"))
if err != nil {
    return err
}
proxy := proxysvc.NewClientFromGRPC(client.Proxy())
status, err := proxy.Status(ctx)
```

Local IPC over the socket avoids TCP/TLS overhead and relies on
filesystem permissions plus peer-credential checks for access control.

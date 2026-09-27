# BGP Unix Socket API Reference

Socket: `/run/platformd.sock`

The Unix transport is **gRPC over a Unix domain socket** — BGP
operations are served by the same `platform.v1.GatewayService` as TCP
port 10443 (see [BGP gRPC API Reference](api-reference-grpc.md)). The
server authenticates callers with Unix peer credentials (SO_PEERCRED);
socket file permissions gate access.

## CLI Usage

```bash
# Force the unix transport explicitly (or PLATFORMCTL_TRANSPORT=unix)
platformctl --transport unix sdn gateway bgp status
platformctl --transport unix sdn gateway bgp peers
platformctl --transport unix sdn gateway bgp routes
platformctl --transport unix sdn gateway bgp announce --prefix 2001:db8::/36
platformctl --transport unix sdn gateway bgp withdraw --prefix 2001:db8::/36
```

## See Also

- [BGP gRPC API Reference](api-reference-grpc.md)
- [Gateway Unix API Reference](../gateway/api-reference-unix.md)
- [CLI Usage](cli-usage.md)

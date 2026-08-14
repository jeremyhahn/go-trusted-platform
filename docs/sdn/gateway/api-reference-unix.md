# Gateway Unix Socket API Reference

Socket: `/run/platformd.sock`

The Unix transport is **gRPC over a Unix domain socket** — it serves
the same `platform.v1.GatewayService` as TCP port 10443 (see
[gRPC API Reference](api-reference-grpc.md)). The server authenticates
callers with Unix peer credentials (SO_PEERCRED); socket file
permissions gate which users/groups may connect.

## CLI Usage

```bash
# Force the unix transport explicitly (or PLATFORMCTL_TRANSPORT=unix)
platformctl --transport unix sdn gateway status
platformctl --transport unix sdn gateway mode set --modes overlay,edge
platformctl --transport unix sdn gateway bgp status
platformctl --transport unix sdn gateway bgp peers
platformctl --transport unix sdn gateway lb status
platformctl --transport unix sdn gateway lb vip list
platformctl --transport unix sdn gateway perf datapath
platformctl --transport unix sdn ipam pool list
platformctl --transport unix sdn ipam allocations
```

## Go Client

Use the platform Go SDK (`sdk/go`), which dials the Unix socket with
the platform's Unix transport credentials — the same path the CLI uses.

## See Also

- [gRPC API Reference](api-reference-grpc.md) — Full service definition
- [Operations Guide](operations.md)

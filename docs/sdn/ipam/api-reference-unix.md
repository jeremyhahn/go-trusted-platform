# IPAM Unix Socket API Reference

> **Status: REFERENCE**
> How to reach IPAM over the local socket.

Socket: `/run/platformd.sock`

The Unix transport is **gRPC over a Unix domain socket** — IPAM
operations are served by the same `platform.v1.GatewayService` as TCP
port 10443 (see [IPAM gRPC API Reference](api-reference-grpc.md)). The
server authenticates callers with Unix peer credentials (SO_PEERCRED);
socket file permissions gate access.

## CLI Usage

```bash
# Force the unix transport explicitly (or PLATFORMCTL_TRANSPORT=unix)
platformctl --transport unix sdn ipam pool list
platformctl --transport unix sdn ipam pool create --name prod-v4 --cidr 10.0.0.0/24
platformctl --transport unix sdn ipam allocate --pool-id prod-v4 --device-id vm-001
platformctl --transport unix sdn ipam release --ip 10.0.0.50
platformctl --transport unix sdn ipam allocations
```

## See Also

- [IPAM gRPC API Reference](api-reference-grpc.md)
- [Gateway Unix API Reference](../../gateway/api.md)

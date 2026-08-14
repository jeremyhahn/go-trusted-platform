# IPAM API Reference

## Overview

IPAM (pools + allocations) is exposed through the **gateway service**
on every platform protocol. There is no standalone `IPAMService`; the
wire surface is the IPAM subset of `platform.v1.GatewayService`.

## Protocol-Specific Documentation

| Protocol | Documentation | Port | Use Case |
|----------|---------------|------|----------|
| REST | [api-reference-rest.md](api-reference-rest.md) | 8443 | Web clients, external systems |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | 10443 | High-performance service-to-service |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | 9444 | Low-latency, mobile clients |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | 9445 | AI/LLM integration |
| Unix Socket | [api-reference-unix.md](api-reference-unix.md) | /run/platformd.sock | Local IPC, CLI |

## Service Operations

### Pool Management

| Operation | Description |
|-----------|-------------|
| CreateIPAMPool | Create a pool (name, CIDR, gateway, zone, description, lease) |
| GetIPAMPool | Get a pool by ID |
| UpdateIPAMPool | Update pool metadata (CIDR is immutable) |
| DeleteIPAMPool | Delete a pool |
| ListIPAMPools | List pools (optional zone filter) |

### Allocations

| Operation | Description |
|-----------|-------------|
| AllocateIP | Allocate an IP from a pool to a device (optional hostname) |
| ReleaseIP | Release an allocated IP back to its pool |
| ListAllocations | List allocations (optionally per pool) |

## CLI Reference

```bash
platformctl sdn ipam pool list [--zone trusted]
platformctl sdn ipam pool get --id pool1
platformctl sdn ipam pool create --name prod-v4 --cidr 10.0.0.0/24 --gateway 10.0.0.1
platformctl sdn ipam pool update --id pool1 --description "production"
platformctl sdn ipam pool delete --id pool1

platformctl sdn ipam allocate --pool-id pool1 --device-id vm-123 --hostname webserver
platformctl sdn ipam release --ip 10.0.0.5
platformctl sdn ipam allocations [--pool-id pool1]
```

## Authentication

All protocols require mTLS; REST additionally accepts platform JWTs.
The Unix socket authenticates with peer credentials and socket file
permissions.

## See Also

- [README](README.md) — IPAM overview
- [Architecture](architecture.md) — Allocator design
- [Configuration](configuration.md) — `sdn.ipam` YAML reference
- [Gateway API Reference](../gateway/api-reference-grpc.md)

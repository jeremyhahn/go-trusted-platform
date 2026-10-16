# IPAM API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> Index of IPAM's transports.

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
| CreateIPAMPool | Create a pool (name, CIDR, gateway, zone, description, lease, allocation window) |
| GetIPAMPool | Get a pool by ID |
| UpdateIPAMPool | Update pool metadata and, optionally, its allocation window (CIDR is immutable) |
| DeleteIPAMPool | Delete a pool |
| ListIPAMPools | List pools (optional zone filter) |

### Allocation Window

Every pool returns, and create and update accept, its allocation window on
all six transports:

| Field | Meaning |
|-------|---------|
| `reserved` | Prefixes (CIDR) that are never allocatable. The gateway is always reserved as well. |
| `range_start`, `range_end` | The dynamic window `AllocateIP` draws from; set both or neither (neither = the whole CIDR). |

`total` counts what can ever be allocated (usable addresses less reserved
ones). A reserved prefix or a range that does not fit the CIDR is refused
(gRPC `InvalidArgument`, REST 400, QUIC `StatusInvalidArgument`, MCP error).
Only QUIC's allocate takes a requested address (`ip_address`); gRPC, REST,
MCP and the CLI always draw from the window. A requested address that is
reserved is refused with `StatusInvalidArgument`. Updates replace
the window only when asked: gRPC and QUIC set `update_window`; REST, MCP and
the WebUI replace the fields present in the request and keep the rest.

### Allocations

| Operation | Description |
|-----------|-------------|
| AllocateIP | Allocate an IP from a pool to a device (optional hostname) |
| ReleaseIP | Release an allocated IP back to its pool |
| ListAllocations | List allocations (optionally per pool) |

## CLI Reference

```bash
platformctl sdn ipam pool list [--zone storage]
platformctl sdn ipam pool get --id lab
platformctl sdn ipam pool create --id lab --name lab --cidr 10.4.9.0/24 --gateway 10.4.9.1 \
    --reserved 10.4.9.1/32 --range-start 10.4.9.50 --range-end 10.4.9.254
platformctl sdn ipam pool update --id lab --description "lab VMs"
platformctl sdn ipam pool update --id lab --range-start 10.4.9.100 --range-end 10.4.9.254
platformctl sdn ipam pool delete --id lab

platformctl sdn ipam allocate --pool-id lab --device-id vm-123 --hostname webserver
platformctl sdn ipam release --ip 10.4.9.50
platformctl sdn ipam allocations [--pool-id lab]
```

## Authentication

All protocols require mTLS; REST additionally accepts platform JWTs.
The Unix socket authenticates with peer credentials and socket file
permissions.

## See Also

- [README](README.md) — IPAM overview
- [Architecture](architecture.md) — Allocator design
- [Configuration](configuration.md) — `sdn.ipam` YAML reference
- [Gateway API Reference](../../gateway/api.md)

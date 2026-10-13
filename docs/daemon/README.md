# Trusted Platform Daemon

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [user.md](user.md) and [configuration.md](configuration.md). The gRPC TCP port is 10443, not the 9443 shown below.

Multi-protocol system daemon providing unified access to platform services.

## Overview

The `platformd` daemon is the core system service for the Trusted Platform, exposing all platform capabilities through five concurrent network protocols. This enables maximum interoperability across web clients, high-performance services, mobile applications, AI/LLM integrations, and local command-line tools.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Protocol** | Simultaneous REST, gRPC, QUIC, MCP, and Unix Socket support |
| **Service Management** | Lifecycle control for platform subsystems |
| **Health Monitoring** | Unified health checks across all protocols |
| **TLS Support** | TLS for REST and gRPC; MCP over HTTP is TLS 1.3 only |
| **Graceful Shutdown** | Coordinated shutdown with configurable timeout |
| **Auto-Start Services** | Configurable automatic service startup |

## Supported Protocols

| Protocol | Transport | Default Port | Use Case |
|----------|-----------|--------------|----------|
| REST | HTTP/HTTPS | 8443 | Web clients, external integrations |
| gRPC | TCP | 9443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTPS | 9445 | AI/LLM tool integration |
| Unix Socket | Unix | /run/platformd.sock | Local IPC, CLI tools |

## Quick Start

### Start the Daemon

```bash
# Start with default configuration
platformd

# Start with custom config
platformd --config /etc/trusted-platform/config.yaml
```

### Check Daemon Status

```bash
# Via CLI (Unix socket)
platformctl status

# Via REST API
curl -k https://localhost:8443/api/v1/status

# Via gRPC (needs a token holding platform:read)
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem \
  -H "authorization: Bearer $TOKEN" localhost:9443 \
  platform.v1.PlatformDaemon/GetHealth
```

### Manage Services

```bash
# List all services
platformctl service list

# Start a service
platformctl service start tpm

# Stop a service
platformctl service stop dns
```

## Architecture Overview

```
                         +------------------+
                         |    platformd     |
                         |  (Main Daemon)   |
                         +--------+---------+
                                  |
        +------------+------------+------------+------------+
        |            |            |            |            |
+-------v------+ +---v----+ +----v---+ +------v-----+ +----v-----+
|    REST      | |  gRPC  | |  QUIC  | |    MCP     | |  Unix    |
| HTTP/HTTPS   | |  TCP   | |  UDP   | | HTTPS/stdio| |  Socket  |
| Port 8443    | | Port   | | Port   | | Port 9445  | | /run/    |
|              | | 9443   | | 9444   | |            | | platformd|
+--------------+ +--------+ +--------+ +------------+ | .sock    |
                                                      +----------+
                                  |
                                  v
                    +-------------+-------------+
                    |     Service Layer         |
                    | (CA, vTPM, Device, SDN,   |
                    |  KMS, DNS, Attestation)   |
                    +---------------------------+
```

## Managed Services

The daemon manages the following platform services:

| Service | Description | Auto-Start |
|---------|-------------|------------|
| `tpm` | TPM operations and management | Yes |
| `vtpm` | Virtual TPM bundles | Yes |
| `ca` | Certificate Authority | Yes |
| `kms` | Key Management Service | Yes |
| `sdn` | Software-Defined Networking | No |
| `dns` | DNS server operations | No |
| `attestation` | Remote attestation | No |
| `compute` | Compute workloads | No |
| `acme` | ACME certificate automation | No |
| `webservice` | Web service endpoints | No |
| `mcp` | MCP server operations | Yes |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Multi-protocol architecture and design |
| [Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | Protocol-specific API documentation |

## Example Configuration

```yaml
daemon:
  # Bind hosts and ports are the only daemon keys (#552, #565); loopback is
  # the default — name an interface to expose a transport.
  rest: {bind-host: 127.0.0.1, port: 8443}
  grpc: {bind-host: 0.0.0.0, port: 10443}
  quic: {bind-host: 127.0.0.1, port: 9444}
  mcp:  {bind-host: 127.0.0.1, port: 9445}
```

The socket path, which transports run and mTLS are `platformd serve` flags
(`--socket-path`, `--enable-<transport>`, `--enable-mtls`); TLS material comes
from the platform CA. See [Configuration](configuration.md).

## Health Checking

All protocols expose health check endpoints:

```bash
# REST
curl https://localhost:8443/api/v1/health

# gRPC: the standard health protocol is the only anonymous RPC;
# PlatformDaemon/GetHealth needs a token holding platform:read
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem localhost:9443 \
  grpc.health.v1.Health/Check

# QUIC
# Uses OpHealth (0x00) opcode

# MCP
# Uses health tool
```

## See Also

- [CLI Reference](cli.md)
- [CA Documentation](../ca/README.md)
- [TPM Documentation](../tpm/README.md)
- [SDN Documentation](../sdn/README.md)
- [DNS Documentation](../dns/README.md)

# Platform API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](daemon/api.md) and each feature's `api.md`.

Multi-protocol API documentation for the Trusted Platform.

## Protocol Overview

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTPS | 8443 | Web clients, external systems |
| gRPC | TCP | 9443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTPS | 9445 | AI/LLM integration |
| Unix Socket | Unix | /run/platformd.sock | Local IPC, CLI |

## Service Parity Matrix

All services are exposed via all 5 protocols with 100% feature parity.

| Service | REST | gRPC | QUIC | MCP | Unix |
|---------|------|------|------|-----|------|
| KMS | [Y] | [Y] | [Y] | [Y] | [Y] |
| CA | [Y] | [Y] | [Y] | [Y] | [Y] |
| IAM | [Y] | [Y] | [Y] | [Y] | [Y] |
| vTPM | [Y] | [Y] | [Y] | [Y] | [Y] |
| Device | [Y] | [Y] | [Y] | [Y] | [Y] |
| Container | [Y] | [Y] | [Y] | [Y] | [Y] |
| Attestation | [Y] | [Y] | [Y] | [Y] | [Y] |
| VM/Compute | [Y] | [Y] | [Y] | [Y] | [Y] |
| DNS | [Y] | [Y] | [Y] | [Y] | [Y] |
| SDN | [Y] | [Y] | [Y] | [Y] | [Y] |
| Health | [Y] | [Y] | [Y] | [Y] | [Y] |
| IDevID | [Y] | [Y] | [Y] | [Y] | [Y] |

**Legend:** [Y] = Fully Implemented

## Service Documentation

### Core Services

| Service | Description | API Reference |
|---------|-------------|---------------|
| [KMS](kms/api-reference.md) | Key management, encryption, secrets | REST/gRPC/CLI |
| [CA](ca/api-reference.md) | Certificate Authority, ACME, PKI | REST/ACME |
| [IAM](iam/api-reference.md) | Identity, access control, OIDC | Multi-protocol |

### Infrastructure Services

| Service | Description | API Reference |
|---------|-------------|---------------|
| [vTPM](vtpm/api-reference.md) | Virtual TPM bundles and templates | Multi-protocol |
| [Device](device/api-reference.md) | Device profiles and registration | Multi-protocol |
| [DNS](dns/api-reference.md) | DNS zones, records, DNSSEC | Multi-protocol |
| [SDN](sdn/api-reference.md) | OVS bridges, flows, VLANs | Multi-protocol |

### Compute Services

| Service | Description | API Reference |
|---------|-------------|---------------|
| [Compute/VM](compute/api-reference.md) | Virtual machine lifecycle | Multi-protocol |
| Container | Container orchestration | Multi-protocol |
| [Attestation](attestation/api-reference.md) | TPM quotes, manifests, policies | Multi-protocol |

### Identity Services

| Service | Description | API Reference |
|---------|-------------|---------------|
| IDevID | IEEE 802.1AR device identity | Multi-protocol |
| Health | Service health checks | Multi-protocol |

## Implementation Details

### REST API

Base path: `/api/v1`

Implementation files:
- `pkg/api/rest/*_handlers.go` - Handler implementations
- `pkg/api/daemon/rest_service.go` - REST service router
- `pkg/api/daemon/rest_idevid.go` - IDevID REST handlers

### gRPC API

Connection: `localhost:9443` (mTLS required)

Implementation files:
- `pkg/api/daemon/*_grpc_service.go` - Service implementations
- `pkg/api/grpc/proto/*.proto` - Protocol buffer definitions
- `sdk/go/gen/*.pb.go` - Generated Go code

gRPC Services:
| Proto File | Service |
|------------|---------|
| attestation.proto | AttestationService |
| ca.proto | CAService |
| compute.proto | ComputeService |
| device.proto | DeviceService |
| dns.proto | DNSService |
| health.proto | HealthService |
| iam.proto | IAMService |
| idevid.proto | IDevIDService |
| kms.proto | KMSService |
| sdn.proto | SDNService |
| vtpm.proto | VTPMService |

### QUIC API

Connection: `localhost:9444` (TLS 1.3 required)

Implementation files:
- `pkg/api/quic/*_handlers.go` - Handler implementations
- `pkg/api/daemon/quic_*.go` - Daemon QUIC integration
- `sdk/go/wire/quicwire/protocol.go` - Protocol definitions

QUIC Handlers:
| File | Service |
|------|---------|
| attestation_handlers.go | Attestation operations |
| ca_handlers.go | CA operations |
| container_handlers.go | Container lifecycle |
| device_handlers.go | Device management |
| dns_handlers.go | DNS operations |
| iam_handlers.go | IAM operations |
| kms_handlers.go | KMS operations |
| sdn_handlers.go | SDN operations |
| vm_handlers.go | VM lifecycle |
| vtpm_handlers.go | vTPM management |

### MCP API

Transport: stdio or HTTPS (port 9445)

Implementation files:
- `pkg/api/mcp/*_tools.go` - Tool implementations
- `pkg/api/mcp/server.go` - MCP server
- `pkg/api/daemon/mcp_*.go` - Daemon MCP integration

MCP Tools:
| File | Tools |
|------|-------|
| attestation_tools.go | Attestation tools |
| ca_tools.go | CA/certificate tools |
| container_tools.go | Container tools |
| device_tools.go | Device tools |
| dns_tools.go | DNS tools |
| iam_tools.go | IAM tools |
| idevid_tools.go | 18 IDevID tools |
| kms_tools.go | KMS tools |
| sdn_tools.go | SDN tools |
| vm_tools.go | VM tools |
| vtpm_tools.go | vTPM tools |

### Unix Socket API

Socket path: `/run/platformd.sock`

Implementation files:
- `pkg/api/unix/*_handlers.go` - Handler implementations
- `pkg/api/unix/server.go` - Unix socket server
- `pkg/api/unix/protocol.go` - Protocol definitions

Unix Handlers:
| File | Service |
|------|---------|
| attestation_handlers.go | Attestation operations |
| ca_handlers.go | CA operations |
| container_handlers.go | Container lifecycle |
| device_handlers.go | Device management |
| dns_handlers.go | DNS operations |
| health_handlers.go | Health checks |
| iam_handlers.go | IAM operations |
| idevid_handlers.go | IDevID operations |
| kms_handlers.go | KMS operations |
| sdn_handlers.go | SDN operations |
| vm_handlers.go | VM lifecycle |
| vtpm_handlers.go | vTPM management |

## Authentication

All protocols require authentication via one of:

**mTLS Client Certificate:**
```
TLS client certificate issued by the platform CA
```

**Bearer Token:**
```
Authorization: Bearer <access_token>
```

## Error Handling

All protocols return consistent error codes. See individual service documentation for protocol-specific error formats.

| Code | Description |
|------|-------------|
| `not_found` | Resource does not exist |
| `already_exists` | Resource already exists |
| `invalid_argument` | Request validation failed |
| `unauthorized` | Authentication required |
| `forbidden` | Permission denied |
| `internal_error` | Internal server error |

## Related Documentation

- [Architecture](api/README.md) - API architecture overview
- [gRPC Design](api/grpc-design.md) - gRPC API design principles
- [REST Reference](api/rest-reference.md) - REST endpoint details
- [gRPC Reference](api/grpc-reference.md) - gRPC service details

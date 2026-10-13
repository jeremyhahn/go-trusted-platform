# Deployment Modes

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [../cluster/user.md](../cluster/user.md) and [../daemon/user.md](../daemon/user.md). The platform config (`pkg/app/app.go`) has no top-level `backends:` or `services:` keys, so the Mixed and Dedicated Cluster modes below do not exist.

This document describes the deployment modes supported by go-trusted-platform, including architecture diagrams and configuration examples.

## Overview

go-trusted-platform supports four primary deployment modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| Standalone | Single node with embedded PebbleDB | Development, edge devices, small deployments |
| Clustered | Multi-node with Raft consensus | Production, high availability |
| Mixed | Some services embedded, some remote | Hybrid deployments, gradual migration |
| Dedicated Clusters | Separate clusters for KMS, IAM, CA | Enterprise, security isolation |

## Standalone Mode

Single-node deployment with all services embedded in-process using PebbleDB for storage.

### Architecture

```
┌──────────────────────────────────────────────────────┐
│                    platformd                          │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │              Multi-Protocol APIs                 │ │
│  │  REST (8443) │ gRPC (10443) │ QUIC (9444)       │ │
│  │  MCP (9445)  │ Unix (/run/platformd.sock)       │ │
│  └─────────────────────────────────────────────────┘ │
│                         │                             │
│  ┌─────────────────────────────────────────────────┐ │
│  │           Embedded Services                      │ │
│  │  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐       │ │
│  │  │  KMS  │ │  IAM  │ │  CA   │ │  DNS  │       │ │
│  │  └───────┘ └───────┘ └───────┘ └───────┘       │ │
│  │  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐       │ │
│  │  │ vTPM  │ │Device │ │ SDN   │ │Secrets│       │ │
│  │  └───────┘ └───────┘ └───────┘ └───────┘       │ │
│  └─────────────────────────────────────────────────┘ │
│                         │                             │
│  ┌─────────────────────────────────────────────────┐ │
│  │         QuicBaaS (PebbleDB Storage)              │ │
│  │                                                   │ │
│  │  /var/lib/trusted-platform/quicbaas/             │ │
│  └─────────────────────────────────────────────────┘ │
│                         │                             │
│  ┌─────────────────────────────────────────────────┐ │
│  │                TPM 2.0                           │ │
│  │          /dev/tpmrm0 or Simulator                │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

### Configuration

```yaml
# Standalone configuration (config.standalone.yaml)
debug: false
platform-dir: /var/lib/trusted-platform
config-dir: /etc/trusted-platform
log-dir: /var/log/trusted-platform
domain: server.example.com

# Single-node PebbleDB storage
quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  cache-size: 67108864
  consistency-level: linearizable

# Real TPM (or simulator for dev)
tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true

# Embedded CA
certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true
  identity:
    - keystores:
        tpm2:
          srk-handle: 0x81000003
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          store: tpm2
      subject:
        cn: ca.server.example.com

# Single webservice
webservice:
  port: 8080
  tls-port: 8443
```

### When to Use

- Development and testing
- Edge devices with limited resources
- Small deployments (single server)
- Proof of concept installations
- IoT gateways

## Clustered Mode

Multi-node deployment with Raft consensus for high availability.

### Architecture

```
                           ┌─────────────────┐
                           │  Load Balancer  │
                           │   VIP: 10.0.0.1 │
                           └────────┬────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
     ┌──────▼──────┐         ┌──────▼──────┐         ┌──────▼──────┐
     │   server1   │         │   server2   │         │   server3   │
     │  10.0.1.1   │         │  10.0.1.2   │         │  10.0.1.3   │
     │   (Leader)  │◄───────►│ (Follower)  │◄───────►│ (Follower)  │
     └──────┬──────┘         └──────┬──────┘         └──────┬──────┘
            │ Raft :63000           │ Raft :63000           │ Raft :63000
            │                       │                       │
     ┌──────▼──────┐         ┌──────▼──────┐         ┌──────▼──────┐
     │  QuicBaaS   │         │  QuicBaaS   │         │  QuicBaaS   │
     │    (Raft)   │◄───────►│    (Raft)   │◄───────►│    (Raft)   │
     └─────────────┘         └─────────────┘         └─────────────┘
```

### Network Layout

| Component | Network | IP Addresses |
|-----------|---------|--------------|
| Gateways | gateway-net (10.0.0.0/24) | 10.0.0.10, 10.0.0.11 (VIP: 10.0.0.1) |
| Servers | server-net (10.0.1.0/24) | 10.0.1.1, 10.0.1.2, 10.0.1.3 |
| Clients | client-net (10.0.2.0/24) | 10.0.2.1, 10.0.2.2, 10.0.2.3 |
| Internal | internal-net (10.0.100.0/24) | Cross-tier communication |

### Configuration (Bootstrap Node)

```yaml
# Server 1 (Raft Bootstrap) - server1.example.com.yaml
debug: true
platform-dir: /var/lib/trusted-platform
domain: server1.example.com

# Raft cluster configuration
quicbaas:
  data-dir: /var/lib/trusted-platform/quicbaas
  storage-backend: raft
  node-id: 1
  raft-address: "10.0.1.1:63000"
  join-addresses: []  # Empty for bootstrap node
  cache-size: 67108864
  consistency-level: linearizable

# DNS with Raft storage
dns:
  quicbaas:
    data-dir: /var/lib/trusted-platform/quicbaas/dns
    storage-backend: raft
    node-id: 1
    raft-address: "10.0.1.1:63000"
    join-addresses: []

tpm:
  device: /dev/tpmrm0
  simulator: false

certificate-authority:
  platform-ca: 1
  identity:
    - keystores:
        tpm2:
          srk-handle: 0x81000003
      keys:
        - algorithm: ECDSA
          store: tpm2
      subject:
        cn: ca.server1.example.com
```

### Configuration (Follower Nodes)

```yaml
# Server 2 (Raft Follower) - server2.example.com.yaml
debug: true
platform-dir: /var/lib/trusted-platform
domain: server2.example.com

quicbaas:
  data-dir: /var/lib/trusted-platform/quicbaas
  storage-backend: raft
  node-id: 2
  raft-address: "10.0.1.2:63000"
  join-addresses:
    - "10.0.1.1:63000"  # Bootstrap node
  cache-size: 67108864
  consistency-level: linearizable
```

### Deployment Order

1. **server1** (Raft bootstrap) - Start first, initializes cluster
2. **server2, server3** - Join Raft cluster
3. **gateway1, gateway2** - Stateless, any order
4. **client1, client2, client3** - Application servers, any order

### Docker Compose

```bash
# Start entire cluster
docker compose -f configs/platform/cluster/docker-compose.yaml up -d

# Start server cluster only
docker compose up -d server1 server2 server3

# Follow logs
docker compose logs -f server1

# Stop all services
docker compose down
```

### When to Use

- Production deployments requiring high availability
- Multi-region deployments
- Enterprise installations
- Compliance requirements (data redundancy)

## Mixed Mode

Hybrid deployment with some services embedded and others connecting to remote clusters.

### Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                             Application Node                            │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                         platformd                                  │ │
│  │                                                                    │ │
│  │  ┌─────────────────────────────────────────────────────────────┐  │ │
│  │  │               Embedded Services (Local)                      │  │ │
│  │  │  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐                    │  │ │
│  │  │  │Vector │ │ Data  │ │ vTPM  │ │Device │                    │  │ │
│  │  │  └───────┘ └───────┘ └───────┘ └───────┘                    │  │ │
│  │  └─────────────────────────────────────────────────────────────┘  │ │
│  │                              │                                     │ │
│  │  ┌─────────────────────────────────────────────────────────────┐  │ │
│  │  │            Remote Service Clients (gRPC/REST)                │  │ │
│  │  │  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐                    │  │ │
│  │  │  │  KMS  │ │Secrets│ │  IAM  │ │  CA   │                    │  │ │
│  │  │  └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘                    │  │ │
│  │  └──────┼─────────┼─────────┼─────────┼────────────────────────┘  │ │
│  └─────────┼─────────┼─────────┼─────────┼────────────────────────────┘ │
└────────────┼─────────┼─────────┼─────────┼────────────────────────────────┘
             │         │         │         │
             │         │         │         │
    ┌────────▼─────────▼───┐     │    ┌────▼────────┐
    │    KMS Cluster       │     │    │  CA Cluster │
    │   (Dedicated HSM)    │     │    │  (Separate) │
    └──────────────────────┘     │    └─────────────┘
                                 │
                        ┌────────▼────────┐
                        │   IAM Cluster   │
                        │   (Dedicated)   │
                        └─────────────────┘
```

### Configuration

```yaml
# Mixed-mode configuration
platform-dir: /var/lib/trusted-platform
domain: app.example.com

# Define remote backends
backends:
  kms-cluster:
    address: "kms.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/kms/ca
      client_cert: kms://platform/backends/kms/cert
      client_key: kms://platform/backends/kms/key

  iam-cluster:
    address: "iam.internal:10443"
    transport: grpc

  ca-cluster:
    address: "ca.internal:8443"
    transport: rest

# Service configuration - mode inferred from backend
services:
  # Remote services (backend specified)
  kms:     { backend: kms-cluster }
  secrets: { backend: kms-cluster }
  iam:     { backend: iam-cluster }
  ca:      { backend: ca-cluster }

  # Embedded services (no backend = embedded)
  vector:     { index_type: hnsw }
  data:       { wal_enabled: true }
  timeseries: { retention: 90d }

# Local PebbleDB for embedded services
quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas

tpm:
  device: /dev/tpmrm0
```

### When to Use

- Gradual migration from standalone to clustered
- Security isolation (sensitive services on dedicated clusters)
- Performance optimization (local caching with remote persistence)
- Regulatory compliance (separate KMS/IAM clusters)

## Dedicated Cluster Mode

Enterprise deployment with separate clusters for each critical service.

### Architecture

```
                                ┌─────────────────────────────────────┐
                                │          Application Tier            │
                                │                                      │
                                │  ┌────────┐ ┌────────┐ ┌────────┐   │
                                │  │ App 1  │ │ App 2  │ │ App 3  │   │
                                │  └────┬───┘ └────┬───┘ └────┬───┘   │
                                └───────┼──────────┼──────────┼───────┘
                                        │          │          │
        ┌───────────────────────────────┼──────────┼──────────┼───────┐
        │                               │          │          │       │
┌───────▼───────┐               ┌───────▼──────────▼──────────▼─────┐ │
│  KMS Cluster  │               │           IAM Cluster             │ │
│               │               │                                    │ │
│ ┌───┐ ┌───┐ ┌───┐            │    ┌───┐    ┌───┐    ┌───┐        │ │
│ │ 1 │ │ 2 │ │ 3 │            │    │ 1 │    │ 2 │    │ 3 │        │ │
│ └───┘ └───┘ └───┘            │    └───┘    └───┘    └───┘        │ │
│   HSM-backed                 │         RBAC/ABAC                  │ │
└───────────────┘               └────────────────────────────────────┘ │
        │                                       │                      │
        │               ┌───────────────────────┼────────────────┐     │
        │               │                       │                │     │
┌───────▼───────┐ ┌─────▼─────┐        ┌───────▼────────┐       │     │
│  CA Cluster   │ │  Secrets  │        │  Data Cluster  │       │     │
│               │ │  Cluster  │        │                │       │     │
│ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐       │ ┌───┐ ┌───┐ ┌───┐     │     │
│ │ 1 │ │ 2 │ │ 3 │ │ 1 │ │ 2 │ │ 3 │  │ │ 1 │ │ 2 │ │ 3 │     │     │
│ └───┘ └───┘ └───┘ └───┘ └───┘ └───┘  │ └───┘ └───┘ └───┘     │     │
│    ACME, PKI                Vault    │    Vector, KV         │     │
└───────────────┘ └───────────┘        └────────────────────────┘     │
                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### Configuration

```yaml
# Enterprise dedicated clusters configuration
platform-dir: /var/lib/trusted-platform
domain: enterprise.example.com

backends:
  # Dedicated KMS cluster (HSM-backed)
  kms:
    address: "kms.enterprise.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/kms/ca
      client_cert: kms://platform/backends/kms/cert
      client_key: kms://platform/backends/kms/key

  # Dedicated Secrets cluster (Vault integration)
  secrets:
    address: "secrets.enterprise.internal:10443"
    transport: grpc

  # Dedicated IAM cluster
  iam:
    address: "iam.enterprise.internal:10443"
    transport: grpc

  # Dedicated CA cluster
  ca:
    address: "ca.enterprise.internal:8443"
    transport: rest

  # Dedicated Data cluster (Vector, KV, TimeSeries)
  data:
    address: "data.enterprise.internal:10443"
    transport: grpc

services:
  kms:        { backend: kms }
  secrets:    { backend: secrets }
  iam:        { backend: iam }
  ca:         { backend: ca }
  vector:     { backend: data }
  kv:         { backend: data }
  timeseries: { backend: data }

tpm:
  device: /dev/tpmrm0
  encrypt-sessions: true
```

### When to Use

- Large enterprise deployments
- Strict security isolation requirements
- Regulatory compliance (PCI-DSS, HIPAA, SOC2)
- Multi-tenant platforms
- Geographic distribution requirements

## Comparison Matrix

| Feature | Standalone | Clustered | Mixed | Dedicated |
|---------|------------|-----------|-------|-----------|
| High Availability | No | Yes | Partial | Yes |
| Scalability | Limited | High | Medium | Very High |
| Complexity | Low | Medium | Medium | High |
| Resource Usage | Low | Medium | Medium | High |
| Security Isolation | Basic | Good | Good | Excellent |
| Recovery Time | N/A | Fast | Medium | Fast |
| Data Redundancy | None | Raft | Partial | Full |

## Related Documentation

- [Build Tags Reference](../configuration/build-tags.md) - Control feature compilation
- [Service Endpoints](../configuration/service-endpoints.md) - Configure service connections
- [SDK Integration](../architecture/sdk-integration.md) - Multi-transport architecture
- [Cluster Configuration](../../configs/platform/cluster/docker-compose.yaml) - Docker Compose reference

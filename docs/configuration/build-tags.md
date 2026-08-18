# Build Tags Reference

This document describes all build tags used in go-trusted-platform for conditional compilation and feature selection.

## Overview

go-trusted-platform uses build tags to control which features are included in the compiled binary. This allows:

- Optimizing binary size by excluding unused features
- Building for specific deployment scenarios (edge, cloud, enterprise)
- Controlling protocol support (REST, QUIC, MCP)
- Including optional integrations (cloud providers, HSM, post-quantum crypto)

**Important**: Native go-trusted-platform services (TPM, vTPM, attestation, device, SDN, DNS, etc.) have NO build tags. They are CORE features and are ALWAYS compiled into every build.

## Protocol Tags

Protocol tags control which communication protocols are included. These tags are shared with go-quicbaas for unified builds.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_REST` | 1 | Include REST API (HTTP/HTTPS endpoints) |
| `WITH_QUIC` | 1 | Include QUIC transport (low-latency UDP) |
| `WITH_MCP` | 1 | Include MCP (Model Context Protocol for AI/LLM) |

**Note**: Building with `WITH_MCP=0` excludes MCP code from BOTH go-trusted-platform AND go-quicbaas.

## Feature Tags

Feature tags control which go-quicbaas services are included. A
quicbaas feature that rides on a qrdb engine also enables the matching
qrdb tag (qrdb's own tag names), so the engine is compiled in rather
than qrdb's feature-disabled stub: `WITH_TIMESERIES` adds
`timeseries qrdb_ts`, `WITH_VECTOR` adds `vector qrdb_vector`, and
`WITH_RAG` adds `rag qrdb_vector`.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_RAFT` | 1 | Include Raft consensus for clustering |
| `WITH_IAM` | 1 | Include IAM service (always core, tag for embedded DB) |
| `WITH_VECTOR` | 1 | Include Vector database service (`vector` + `qrdb_vector`) |
| `WITH_TIMESERIES` | 1 | Include TimeSeries service (`timeseries` + `qrdb_ts`) |
| `WITH_RAG` | 1 | Include RAG service (`rag` + `qrdb_vector`; requires `WITH_VECTOR=1`) |

## qrdb Optional Feature Tags

qrdb's optional engines and protocol frontends, OFF by default for the
platform (lean build — the default platform binary contains no SQL
engine, no MySQL/PostgreSQL/etcd wire frontends). The MySQL and
PostgreSQL frontends are engines over qrdb's SQL layer, so enabling
either implies `qrdb_sql`. SQL builds stay CGO-free via the always-on
`gms_pure_go` tag.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_QRDB_SQL` | 0 | qrdb SQL query engine (`qrdb_sql`; pkg/sql over go-mysql-server) |
| `WITH_QRDB_MYSQL` | 0 | MySQL wire frontend (`qrdb_mysql`, implies `qrdb_sql`) |
| `WITH_QRDB_PGSQL` | 0 | PostgreSQL wire frontend (`qrdb_pgsql`, implies `qrdb_sql`) |
| `WITH_QRDB_ETCD` | 0 | etcd v3 gRPC frontend (`qrdb_etcd`) |

## Cloud Provider Tags

Cloud provider tags enable integration with external cloud services. Disabled by default to minimize dependencies.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_AWS` | 0 | Include AWS integrations (S3, KMS, Secrets Manager) |
| `WITH_GCP` | 0 | Include GCP integrations (Cloud KMS, Secret Manager) |
| `WITH_AZURE` | 0 | Include Azure integrations (Key Vault, Blob Storage) |
| `WITH_VAULT` | 0 | Include HashiCorp Vault integration |

## Security/Crypto Tags

Security tags enable advanced cryptographic features.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_PKCS11` | 0 | Include PKCS#11 HSM support |
| `WITH_QUANTUM` | 0 | Include post-quantum cryptography algorithms |

## Messaging Protocol Tags

Messaging tags control which message broker protocols are included.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_MQTT` | 1 | Include MQTT messaging support |
| `WITH_AMQP` | 1 | Include AMQP messaging support |
| `WITH_STOMP` | 1 | Include STOMP messaging support |

## Service Embedding Tags

Embedding tags control whether services run in-process or connect to remote endpoints.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_QUICBAAS_EMBEDDED` | 1 | Embed QuicBaaS services in-process |
| `WITH_XKMS_EMBEDDED` | 1 | Embed go-xkms services (including CA/ACME) in-process |

## Codec Tags

Codec tags control which serialization formats are included.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_CODEC_JSON` | 1 | JSON codec |
| `WITH_CODEC_YAML` | 1 | YAML codec |
| `WITH_CODEC_TOML` | 1 | TOML codec |
| `WITH_CODEC_MSGPACK` | 1 | MessagePack codec |
| `WITH_CODEC_BSON` | 1 | BSON codec |
| `WITH_CODEC_CBOR` | 1 | CBOR codec |
| `WITH_CODEC_PROTOBUF` | 1 | Protocol Buffers codec |

## Cache Tags

Cache tags control additional caching layers.

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_L2_REDIS` | 0 | Include Redis L2 cache |

## Platform-Specific Tags

Platform-specific build tags used by the Makefile.

| Build Tag | Usage | Effect |
|-----------|-------|--------|
| `platform_web` | `WITH_WEB=1` | Embed web frontend into binary |
| `platform_p2p` | `WITH_P2P=1` | Include P2P/libp2p networking support |

## Build Examples

### Full Feature Build (Development)

Build with all features enabled for development and testing:

```bash
make build
# Or explicitly:
go build -tags "iam codec_msgpack codec_cbor codec_json local objstore raft timeseries" ./cmd/platformd
```

### Minimal Build

Build without optional protocols or features for minimal binary size:

```bash
go build -tags "WITH_RAFT=0,WITH_TIMESERIES=0,WITH_VECTOR=0,WITH_RAG=0,WITH_REST=0,WITH_QUIC=0,WITH_MCP=0" ./cmd/platformd
```

### Cloud Deployment (AWS Backend)

Build for AWS deployment with remote QuicBaaS services:

```bash
go build -tags "WITH_AWS=1,WITH_QUICBAAS_EMBEDDED=0" ./cmd/platformd
```

### Enterprise Build

Build with all enterprise features including cloud providers and HSM support:

```bash
go build -tags "WITH_AWS=1,WITH_GCP=1,WITH_AZURE=1,WITH_VAULT=1,WITH_PKCS11=1,WITH_QUANTUM=1,WITH_L2_REDIS=1" ./cmd/platformd
```

### Without MCP (Non-AI Deployments)

Build without Model Context Protocol for deployments not using AI/LLM features:

```bash
go build -tags "WITH_MCP=0" ./cmd/platformd
```

### With Embedded Web Frontend

Build with the web dashboard embedded in the binary:

```bash
WITH_WEB=1 make build
```

### With P2P Support

Build the gateway daemon with P2P/libp2p networking:

```bash
make build-gatewayd WITH_P2P=1
```

## Docker Build Arguments

When building Docker images, build tags can be controlled via build arguments:

```dockerfile
ARG WITH_WEB=false
```

Usage:

```bash
docker build --build-arg WITH_WEB=true -t trusted-platform:latest .
```

## Related Documentation

- [Service Endpoints Configuration](service-endpoints.md) - Configure service connections
- [Deployment Modes](../operations/deployment-modes.md) - Standalone, cluster, and mixed deployments
- [SDK Integration](../architecture/sdk-integration.md) - Multi-transport support

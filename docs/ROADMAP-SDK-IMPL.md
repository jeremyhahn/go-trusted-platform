# Unified SDK Integration Roadmap for go-trusted-platform

> **Claude Plan Reference**: `~/.claude/plans/happy-coalescing-rivest.md`
>
> To continue this plan in a future Claude session, reference the plan file above.

---

## Executive Summary

Refactor go-trusted-platform to use a **clean unified API** where go-trusted-platform is the ONLY entry point for all services. All external dependencies (go-quicbaas, go-xkms) will be accessed exclusively through their SDKs with proper abstraction layers. Note: go-trusted-ca has been decommissioned; its CA and ACME functionality are now part of go-xkms.

### Goals
1. **Single Entry Point**: go-trusted-platform SDK is the only consumer-facing API
2. **SDK-Only Access**: No direct access to internal packages of dependencies
3. **Full Feature Parity**: Go and JavaScript SDKs expose ALL features uniformly
4. **Abstraction Layers**: Allow changing implementations without breaking SDK interface
5. **Scalable Deployment**: Support embedded OR remote service endpoints per-service via build tags and config

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Consumer Applications                         │
│              (platformctl, web dashboard, third-party)              │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                    go-trusted-platform SDKs                         │
│                                                                      │
│  sdk/go/                             sdk/javascript/                 │
│  ├── Client interface                ├── PlatformClient              │
│  ├── All services unified            ├── Full TypeScript types       │
│  └── Multi-transport support         └── REST/WebSocket support      │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                    Multi-Protocol API Layer                          │
│                      pkg/api/daemon/                                 │
│                                                                      │
│  Embedded   │ REST (8443) │ gRPC (10443) │ QUIC (9444) │ MCP (9445) │
│  (in-proc)  │             │              │             │ Unix (/run)│
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                    Platform Service Registry                         │
│                       pkg/platform/registry.go                       │
└─────────────┬─────────────────────────────────────┬─────────────────┘
              │                                     │
┌─────────────▼─────────────┐       ┌──────────────▼──────────────────┐
│  NATIVE SERVICES (pkg/)   │       │  SDK-WRAPPED SERVICES (internal/)│
│  ALWAYS EMBEDDED          │       │  EMBEDDED or REMOTE              │
│  NO BUILD TAGS            │       │  BUILD TAGS OPTIONAL             │
│  ─────────────────────    │       │  ────────────────────────────    │
│  pkg/tpm/                 │       │  internal/quicbaas/              │
│  pkg/vtpm/                │       │    ├── kms/                      │
│  pkg/idevid/              │       │    ├── secrets/                  │
│  pkg/attestation/         │       │    ├── iam/                      │
│  pkg/device/              │       │    ├── crypto/                   │
│  pkg/sdn/                 │       │    ├── vector/                   │
│  pkg/dns/                 │       │    ├── scheduler/                │
│  pkg/compute/             │       │    ├── messaging/                │
│  pkg/pxe/                 │       │    └── ... (28 services)         │
│  pkg/overlay/             │       │                                  │
│  pkg/gateway/             │       │  internal/ca/                    │
│  pkg/tenant/              │       │    ├── certificate/              │
│                           │       │    └── acme/                     │
│                           │       │                                  │
│                           │       │  internal/xkms/              │
│                           │       │    ├── tpm/                      │
│                           │       │    ├── software/                 │
│                           │       │    └── pkcs11/                   │
└───────────────────────────┘       └─────────────────────────────────┘
                                                   │
┌──────────────────────────────────────────────────▼──────────────────┐
│               External SDKs (SDK Access ONLY - No pkg/ imports)      │
│                                                                      │
│  go-quicbaas/sdk/go      go-xkms/sdk/go (includes CA/ACME)        │
│  ─────────────────       ─────────────────────────────────         │
│  quicbaas.Client         xkms.SDK                               │
│  - KV(), KMS()           - TPM2, Software, PKCS#11              │
│  - Secrets(), IAM()      - CA/ACME (pkg/ca + pkg/acme)          │
│  - Vector(), etc.        - Certificate operations                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Build Tags & Remote Service Configuration

### Embedded vs. Remote Services

Each SDK-wrapped service supports **two deployment modes** controlled by build tags:

1. **Embedded Mode**: Service runs in-process (default for development/single-node)
2. **Remote Mode**: Service connects to dedicated cluster endpoint (production/scale-out)

### Build Tags (Aligned with go-quicbaas)

**go-trusted-platform and go-quicbaas use unified build tags. Building with `WITH_MCP=0` excludes MCP code from BOTH projects.**

#### Core Feature Tags (from go-quicbaas)
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_RAFT` | 1 | Include Raft consensus for clustering |
| `WITH_IAM` | 1 | Include IAM service |
| `WITH_TIMESERIES` | 1 | Include TimeSeries service |
| `WITH_VECTOR` | 1 | Include Vector database service |
| `WITH_RAG` | 1 | Include RAG (requires WITH_VECTOR=1) |

#### Protocol Tags (shared across projects)
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_REST` | 1 | Include REST API |
| `WITH_QUIC` | 1 | Include QUIC transport |
| `WITH_MCP` | 1 | Include MCP (Model Context Protocol) |

#### Messaging Protocol Tags
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_MQTT` | 1 | Include MQTT messaging |
| `WITH_AMQP` | 1 | Include AMQP messaging |
| `WITH_STOMP` | 1 | Include STOMP messaging |

#### Cloud Provider Tags
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_AWS` | 0 | Include AWS integrations (S3, KMS, etc.) |
| `WITH_GCP` | 0 | Include GCP integrations |
| `WITH_AZURE` | 0 | Include Azure integrations |
| `WITH_VAULT` | 0 | Include HashiCorp Vault integration |

#### Security/Crypto Tags
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_PKCS11` | 0 | Include PKCS#11 HSM support |
| `WITH_QUANTUM` | 0 | Include post-quantum cryptography |

#### Cache Tags
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_L2_REDIS` | 0 | Include Redis L2 cache |

#### Codec Tags
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_CODEC_JSON` | 1 | JSON codec |
| `WITH_CODEC_YAML` | 1 | YAML codec |
| `WITH_CODEC_TOML` | 1 | TOML codec |
| `WITH_CODEC_MSGPACK` | 1 | MessagePack codec |
| `WITH_CODEC_BSON` | 1 | BSON codec |
| `WITH_CODEC_CBOR` | 1 | CBOR codec |
| `WITH_CODEC_AVRO` | 1 | Avro codec |
| `WITH_CODEC_PROTOBUF` | 1 | Protocol Buffers codec |

#### Service Embedding Tags (SDK-wrapped services only)
| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_QUICBAAS_EMBEDDED` | 1 | Embed QuicBaaS services in-process |
| `WITH_XKMS_EMBEDDED` | 1 | Embed go-xkms services (including CA/ACME) in-process |

**IMPORTANT**: Native go-trusted-platform services (TPM, vTPM, attestation, device, SDN, DNS, etc.) have NO build tags. They are CORE features of the trusted platform and are ALWAYS compiled into every build.

**Makefile Targets:**
```makefile
# Build with full features (development)
build-full:
	go build -tags "WITH_RAFT=1,WITH_IAM=1,WITH_VECTOR=1,WITH_RAG=1,WITH_REST=1,WITH_QUIC=1,WITH_MCP=1,WITH_QUICBAAS_EMBEDDED=1" ./...

# Build minimal (no optional protocols or features)
build-minimal:
	go build -tags "WITH_RAFT=0,WITH_TIMESERIES=0,WITH_VECTOR=0,WITH_RAG=0,WITH_REST=0,WITH_QUIC=0,WITH_MCP=0" ./...

# Build for cloud deployment (AWS backend)
build-cloud-aws:
	go build -tags "WITH_AWS=1,WITH_QUICBAAS_EMBEDDED=0" ./...

# Build enterprise (all features + cloud + HSM)
build-enterprise:
	go build -tags "WITH_AWS=1,WITH_GCP=1,WITH_AZURE=1,WITH_VAULT=1,WITH_PKCS11=1,WITH_QUANTUM=1,WITH_L2_REDIS=1" ./...

# Build without MCP (for non-AI deployments)
build-no-mcp:
	go build -tags "WITH_MCP=0" ./...
```

### Configuration Schema

**Key Principle**: Mode is INFERRED from configuration - no explicit `mode:` field required.
- If `backend:` is specified → **remote mode**
- If `backend:` is NOT specified → **embedded mode** (default)

**Secrets**: Never store secrets in config files. Use go-quicbaas's secrets resolution:
- `kms://path/to/secret` - Local KMS lookup
- `remote-kms://host:port/path` - Remote KMS lookup
- `auto` - Auto-generate on first boot

```yaml
# Device Profile / Platform Config

# Define backends once (reusable)
backends:
  kms-cluster:
    address: "kms.cluster.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/kms/ca
      client_cert: kms://platform/backends/kms/cert
      client_key: kms://platform/backends/kms/key

  quicbaas-primary:
    address: "quicbaas.internal:10443"
    transport: grpc

  ca-cluster:
    address: "ca.internal:8443"
    transport: rest

# Service configuration - mode inferred from backend presence
services:
  # Remote services (backend specified)
  kms:     { backend: kms-cluster }
  secrets: { backend: quicbaas-primary }
  iam:     { backend: quicbaas-primary }
  ca:      { backend: ca-cluster }

  # Embedded services (no backend = embedded)
  vector:  { index_type: hnsw, dimensions: 1536 }
  data:    { wal_enabled: true }
```

---

## Implementation Phases

### Phase 1: SDK Adapter Layer (Foundation)

Create clean adapter layer wrapping external SDKs in `internal/` directories.

**Files to Create:**

1. `internal/quicbaas/adapter.go`
```go
// Adapter wraps go-quicbaas SDK providing unified access to all 28 services
type Adapter struct {
    client quicbaassdk.Client
    config *Config
}

func NewAdapter(cfg *Config) (*Adapter, error)
func (a *Adapter) KMS() quicbaassdk.KMSClient
func (a *Adapter) Secrets() quicbaassdk.SecretsClient
func (a *Adapter) IAM() quicbaassdk.IAMClient
// ... all 28 services
```

2. `internal/ca/adapter.go`
3. `internal/xkms/adapter.go`

### Phase 2: Refactor Internal Services

Fix all files that directly import internal packages.

**Files to Refactor:**

| File | Changes Required |
|------|------------------|
| `pkg/storage/quicbaas/client.go` | Use SDK embedded transport |
| `pkg/api/daemon/iam_service.go` | Use SDK adapter |
| `pkg/api/daemon/kms_service.go` | Use SDK adapter |
| `pkg/dns/dnssec_keystore.go` | Use XKMS adapter |
| `pkg/app/secrets.go` | Return SDK client |
| `pkg/app/app.go` | Initialize adapters |

### Phase 3: Platform Service Layer

Create unified service layer that wraps SDK adapters.

**Directory Structure:**
```
internal/
├── quicbaas/                    # All go-quicbaas SDK service wrappers
│   ├── adapter.go               # QuicBaaS SDK adapter (all 28 services)
│   ├── kv/
│   ├── kms/
│   ├── secrets/
│   ├── iam/
│   ├── crypto/
│   ├── vector/
│   └── ... (all 28 services)
│
└── xkms/                    # go-xkms SDK service wrappers (including CA/ACME)
    ├── adapter.go
    ├── tpm/
    ├── software/
    ├── pkcs11/
    ├── ca/
    └── acme/

pkg/
├── platform/
│   └── registry.go              # Service registry exposing internal services
│
├── tpm/                         # Native go-trusted-platform services (ALWAYS enabled)
├── vtpm/
├── attestation/
├── device/
├── idevid/
├── sdn/
├── dns/
├── compute/
├── pxe/
├── overlay/
├── gateway/
└── tenant/
```

### Phase 4: Update Go SDK

Update `sdk/go/` to expose unified platform services.

### Phase 5: Update JavaScript SDK

Ensure full feature parity with Go SDK.

### Phase 6: Multi-Protocol API Updates

Ensure all services are exposed through all protocols (REST, gRPC, QUIC, MCP, Unix).

---

## Service Mapping

### go-quicbaas SDK Services (28 services)

| Platform Service | SDK Method | Description |
|-----------------|------------|-------------|
| `KVService` | `client.KV()` | Key-value storage |
| `BatchService` | `client.Batch()` | Batch operations |
| `TransactionService` | `client.Transaction()` | ACID transactions |
| `QueryService` | `client.Query()` | Query operations |
| `ClusterService` | `client.Cluster()` | Cluster management |
| `HealthService` | `client.Health()` | Health checks |
| `OperationsService` | `client.Operations()` | Cluster operations |
| `CacheService` | `client.Cache()` | Cache management |
| `AuthService` | `client.Auth()` | Authentication |
| `SealService` | `client.Seal()` | Seal/unseal operations |
| `KMSService` | `client.KMS()` | Key management |
| `SecretsService` | `client.Secrets()` | Secrets management |
| `CryptoService` | `client.Crypto()` | Cryptographic operations |
| `RBACService` | `client.RBAC()` | Role-based access control |
| `DynamicSecretsService` | `client.DynamicSecrets()` | Dynamic credentials |
| `CertificateService` | `client.Certificate()` | Certificate management |
| `ClusterDEKService` | `client.ClusterDEK()` | Cluster DEK management |
| `IAMService` | `client.IAM()` | Full IAM |
| `VectorService` | `client.Vector()` | Vector database |
| `TimeSeriesService` | `client.TimeSeries()` | Time-series data |
| `BackupService` | `client.Backup()` | Backup/restore |
| `ObjectStorageService` | `client.ObjectStorage()` | Object storage |
| `ObjectStorageAdminService` | `client.ObjectStorageAdmin()` | Object storage admin |
| `ObjectTransferService` | `client.ObjectTransfer()` | Object transfers |
| `ParameterStoreService` | `client.ParameterStore()` | Parameter store |
| `SchedulerService` | `client.Scheduler()` | Job scheduling |
| `MessagingService` | `client.Messaging()` | Pub/sub messaging |
| `EmbeddingService` | `client.Embedding()` | Embedding generation |
| `OllamaService` | `client.Ollama()` | Ollama LLM operations |

### go-xkms SDK Services (including absorbed CA/ACME functionality)

| Platform Service | SDK Interface | Description |
|-----------------|---------------|-------------|
| `XKMSService` | `xkms.Backend` | Key storage (TPM, Software, PKCS#11) |
| `CAService` | `xkms.TrustedCA` | Certificate authority (pkg/ca, formerly go-trusted-ca) |
| `ACMEService` | `xkms.ACME` | ACME protocol server (pkg/acme, formerly go-trusted-ca) |

---

## Success Criteria

1. **No Direct Internal Imports**: Zero `go-quicbaas/pkg/*` imports (except SDK)
2. **Unified SDK Interface**: All 31 services accessible via `platform.Client`
3. **Protocol Parity**: All services work through all 6 transports (Embedded, REST, gRPC, QUIC, MCP, Unix)
4. **SDK Parity**: Go and JavaScript SDKs have identical feature sets
5. **Build Tag Alignment**: go-trusted-platform and go-quicbaas share unified build tags
6. **Remote Endpoint Config**: Device profile supports per-service remote endpoint configuration
7. **Mixed Mode Deployment**: Platform runs with any combination of embedded/remote services
8. **Test Coverage**: 90%+ coverage on adapter and service layers (both embedded and remote paths)
9. **Documentation Complete**: All docs listed in Documentation Updates section delivered
10. **All 28 QuicBaaS Services**: Complete integration of all go-quicbaas SDK services
11. **Inferred Configuration**: Service mode inferred from `backend:` presence (no explicit `mode:` field)
12. **No Secrets in Config**: All sensitive values use go-quicbaas secrets resolution (`kms://`, `remote-kms://`, `auto`)
13. **No Enabled Flags**: Presence in config = configured. Omission = use defaults. No `enabled: true/false`
14. **Native Services Always Compiled**: TPM, attestation, device, SDN, DNS, etc. have NO build tags - always part of every build
15. **Clean Separation**: SDK wrappers in `internal/quicbaas/`, `internal/ca/`, `internal/xkms/`. Native services in `pkg/`

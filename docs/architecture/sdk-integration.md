# Unified SDK Integration Architecture

This document describes the unified SDK integration architecture for go-trusted-platform, which provides a single entry point for all services through clean abstraction layers.

## Overview

go-trusted-platform uses a **unified SDK integration pattern** where:

1. **go-trusted-platform is the ONLY entry point** for consumer applications
2. **External dependencies** (go-quicbaas, go-trusted-ca, go-xkms) are accessed **exclusively through SDKs**
3. **Abstraction layers** allow changing implementations without breaking the SDK interface
4. **Multi-transport support** enables embedded OR remote service endpoints per-service

## Architecture Diagram

```
                        Consumer Applications
                   (platformctl, web dashboard, third-party)
                                   |
                                   v
+--------------------------------------------------------------------------+
|                      go-trusted-platform SDKs                             |
|                                                                           |
|  sdk/go/platform/                    sdk/javascript/                      |
|  +-------------------------+         +---------------------------+        |
|  | Client interface        |         | PlatformClient            |        |
|  | - 16 Platform services  |         | - 16 Platform services    |        |
|  | - QuicBaaS() accessor   |         | - 28 QuicBaaS services    |        |
|  | - Multi-transport       |         | - REST/WebSocket support  |        |
|  +-------------------------+         +---------------------------+        |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|                      Multi-Protocol API Layer                             |
|                        pkg/api/daemon/                                    |
|                                                                           |
|  Embedded   | REST (8443) | gRPC (10443) | QUIC (9444) | MCP (9445)       |
|  (in-proc)  |             |              |             | Unix (/run)      |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|                    Platform Service Registry                              |
|                      pkg/platform/registry.go                             |
|                                                                           |
|  Provides unified access to:                                              |
|  - SDK Adapters (QuicBaaS, CA, XKMS)                                  |
|  - Native Services (Device, DNS, TPM, vTPM, etc.)                         |
|  - QuicBaaS convenience accessors (KV, KMS, Secrets, IAM, etc.)           |
+--------------------------------------------------------------------------+
              |                                     |
              v                                     v
+----------------------------+        +--------------------------------+
| NATIVE SERVICES (pkg/)     |        | SDK-WRAPPED SERVICES (internal/)|
| ALWAYS EMBEDDED            |        | EMBEDDED or REMOTE              |
| NO BUILD TAGS              |        | BUILD TAGS OPTIONAL             |
|                            |        |                                  |
| pkg/tpm/                   |        | internal/quicbaas/               |
| pkg/vtpm/                  |        |   - adapter.go (all 28 services) |
| pkg/idevid/                |        |                                  |
| pkg/attestation/           |        | internal/ca/                     |
| pkg/device/                |        |   - adapter.go                   |
| pkg/sdn/                   |        |                                  |
| pkg/dns/                   |        | internal/xkms/               |
| pkg/compute/               |        |   - adapter.go                   |
| pkg/pxe/                   |        |                                  |
| pkg/overlay/               |        +--------------------------------+
| pkg/gateway/               |                        |
| pkg/tenant/                |                        v
+----------------------------+        +--------------------------------+
                                      | External SDKs (SDK Access ONLY) |
                                      |                                  |
                                      | go-quicbaas/sdk/go               |
                                      |   - KV(), KMS(), Secrets(), etc. |
                                      |   - 28 service clients           |
                                      |                                  |
                                      | go-trusted-ca (interfaces)       |
                                      |   - CertificateAuthority         |
                                      |                                  |
                                      | go-xkms                      |
                                      |   - XKMSServicer             |
                                      +----------------------------------+
```

## Key Components

### Platform Service Registry (`pkg/platform/registry.go`)

The registry is the central access point for all platform services. It:

- **Manages SDK adapter lifecycle** (create, start, stop)
- **Provides unified accessors** for all services
- **Supports thread-safe access** via atomic operations and RWMutex
- **Handles graceful shutdown** with cleanup of all adapters

```go
type Registry struct {
    // SDK Adapters (SDK-wrapped services)
    quicBaaSAdapter *quicbaas.Adapter
    caAdapter       *ca.Adapter
    xkmsAdapter *xkms.Adapter

    // Native Services (always embedded)
    deviceService *device.Service
    dnsService    *dns.Service

    // State management
    started atomic.Bool
    closed  atomic.Bool
    mu      sync.RWMutex
}
```

#### Registry Configuration

```go
type RegistryConfig struct {
    Logger *logging.Logger

    // SDK Adapter Configurations (nil = not configured)
    QuicBaaSConfig *quicbaas.Config
    CAConfig       *ca.Config
    XKMSConfig *xkms.Config

    // Native Service References
    DeviceService *device.Service
    DNSService    *dns.Service
}
```

#### Start Parameters

For embedded mode, pass service implementations to the Start method:

```go
type StartParams struct {
    QuicBaaSService dbservice.QuicBaaS      // Embedded QuicBaaS service
    CAService       ca.CertificateAuthority // Embedded CA service
    XKMSService xkms.XKMSServicer // Embedded XKMS service
}
```

### SDK Adapters (`internal/`)

Each SDK adapter wraps an external SDK providing:

- **Thread-safe access** with atomic started/closed state
- **Multi-transport support** (embedded, gRPC, REST, QUIC, Unix)
- **Consistent lifecycle** (NewAdapter, Start, Stop, IsStarted, IsClosed)

#### QuicBaaS Adapter (`internal/quicbaas/adapter.go`)

Wraps go-quicbaas SDK providing access to all 28 services:

| Category | Services |
|----------|----------|
| Core Data | KV, Batch, Transaction, Query, TimeSeries, Backup |
| AI/ML | Vector, Embedding, Ollama |
| Security | Auth, KMS, Secrets, Crypto, DynamicSecrets, Certificate, Seal, RBAC, ClusterDEK |
| Infrastructure | Cluster, Health, Operations, Cache, ParameterStore, Scheduler, ObjectStorage, ObjectStorageAdmin, ObjectTransfer |
| Identity | IAM (with 11 sub-clients) |
| Messaging | Messaging (pub/sub, push notifications, delta sync) |

#### CA Adapter (`internal/ca/adapter.go`)

Wraps go-trusted-ca for certificate authority operations:

- Certificate issuance and revocation
- ACME protocol support
- Cross-signing and certificate chains

#### XKMS Adapter (`internal/xkms/adapter.go`)

Wraps go-xkms for key management:

- TPM-backed key storage
- Software keystore
- PKCS#11 HSM integration

## Multi-Transport Support

### Transport Modes

| Transport | Port | Use Case |
|-----------|------|----------|
| Embedded | - | Default, in-process (single-node) |
| Unix Socket | /run/platformd.sock | Local IPC, CLI tools |
| gRPC | 10443 | High-performance remote |
| REST | 8443 | Web clients, external systems |
| QUIC | 9444 | Low-latency, mobile clients |
| MCP | 9445 | AI/LLM integration |

### Mode Inference from Configuration

Service mode is **inferred from configuration** - no explicit `mode:` field required:

- If `backend:` is specified → **remote mode**
- If `backend:` is NOT specified → **embedded mode** (default)

```yaml
backends:
  quicbaas-cluster:
    address: "quicbaas.internal:10443"
    transport: grpc

services:
  # Remote services (backend specified)
  kms:     { backend: quicbaas-cluster }
  secrets: { backend: quicbaas-cluster }

  # Embedded services (no backend = embedded)
  vector:  { index_type: hnsw }
  data:    { wal_enabled: true }
```

## Build Tags

go-trusted-platform supports optional build tags for feature inclusion/exclusion:

### Protocol Tags (shared with go-quicbaas)

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_REST` | 1 | Include REST API |
| `WITH_QUIC` | 1 | Include QUIC transport |
| `WITH_MCP` | 1 | Include MCP (Model Context Protocol) |

### Feature Tags (from go-quicbaas)

| Build Tag | Default | Effect |
|-----------|---------|--------|
| `WITH_RAFT` | 1 | Include Raft consensus |
| `WITH_VECTOR` | 1 | Include Vector database |
| `WITH_TIMESERIES` | 1 | Include TimeSeries service |

### Important Notes

- **Native services have NO build tags** - TPM, attestation, device, SDN, DNS are CORE features compiled into every build
- Building with `WITH_MCP=0` excludes MCP from BOTH go-trusted-platform AND go-quicbaas

## Usage Examples

### Creating and Starting the Registry

```go
cfg := &platform.RegistryConfig{
    Logger: logger,
    QuicBaaSConfig: &quicbaas.Config{
        Transport: quicbaas.TransportEmbedded,
        DataDir:   "/var/lib/platform/quicbaas",
    },
}

registry, err := platform.NewRegistry(cfg)
if err != nil {
    return err
}

// Start with embedded services
err = registry.Start(ctx, &platform.StartParams{
    QuicBaaSService: embeddedQuicBaaS,
})
```

### Accessing Services

```go
// Access QuicBaaS services via convenience accessors
kv := registry.KV()           // Key-value client
kms := registry.KMS()         // KMS client
secrets := registry.Secrets() // Secrets client

// Or access the full adapter
if adapter := registry.QuicBaaS(); adapter != nil {
    vector := adapter.Vector()
    embedding := adapter.Embedding()
}

// Access native services
deviceSvc := registry.DeviceService()
dnsSvc := registry.DNSService()
```

### SDK Client Usage

```go
// Connect to platform daemon
client, err := platform.Connect(ctx, platform.NewOptions())
if err != nil {
    return err
}
defer client.Close()

// Use platform services
resp, err := client.TPM().GetEK(ctx, &req)

// Use QuicBaaS services
kvClient := client.QuicBaaS().KV()
_, err = kvClient.Put(ctx, &quicbaas.PutRequest{Key: "foo", Value: []byte("bar")})
```

## Error Handling

The registry uses typed errors for precise error handling:

```go
// Registry state errors
type ErrRegistryClosed struct{}
type ErrRegistryNotStarted struct{}

// Adapter errors
type ErrAdapterCreationFailed struct {
    Adapter string
    Cause   error
}

type ErrAdapterStartFailed struct {
    Adapter string
    Cause   error
}

type ErrAdapterNotConfigured struct {
    Adapter string
}

type ErrServiceUnavailable struct {
    Service string
    Reason  string
}
```

## Related Documentation

- [SDK Overview](../api/sdk-overview.md) - Complete SDK documentation
- [QuicBaaS Integration](quicbaas-integration.md) - QuicBaaS service details
- [Go SDK](../api/sdk-go.md) - Go SDK reference
- [JavaScript SDK](../api/sdk-javascript.md) - JavaScript SDK reference

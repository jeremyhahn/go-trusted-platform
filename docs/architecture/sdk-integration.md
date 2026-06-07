# Unified SDK Integration Architecture

This document describes the SDK integration architecture for
go-trusted-platform after the Phase 6 / Phase 7 / Phase 8 refactors that
established quicbaas as the **only** consumer-facing surface for the
underlying crypto / KV / IAM / trust stack.

## Overview

go-trusted-platform consumes the stack through a single SDK:

1. **go-quicbaas SDK is the ONLY runtime path** to crypto, KV, IAM,
   barrier, ceremony, trust-bootstrap, ACME, and identity capabilities.
2. **No direct imports** of `go-qrdb`, `go-xkms`, `go-quicraft`, or
   `go-truststrap` from application runtime code. The single documented
   exception is the initramfs build-time carve-out (see
   [SDK Consumption Invariant](../../CLAUDE.md#sdk-consumption-invariant)).
3. **Multi-transport support** — the quicbaas SDK auto-selects between
   embedded, Unix socket, gRPC, REST, QUIC, and MCP transports.
4. **`Security().*` grouping** — all crypto/auth/trust verbs are reachable
   from `quicbaas.SDK().Security()`; there are no flat shortcuts
   (`Client.Barrier()` etc. were removed in Phase 8a).

## Architecture Diagram

```
                          Consumer Applications
                  (platformctl, web dashboard, third-party)
                                   |
                                   v
+--------------------------------------------------------------------------+
|                       go-trusted-platform SDK                            |
|                                                                          |
|  sdk/go/platform/                    sdk/javascript/                     |
|  +-------------------------+         +---------------------------+       |
|  | Client interface        |         | PlatformClient            |       |
|  | - Platform-native verbs |         | - Platform-native verbs   |       |
|  |   (TPM, IDevID, SDN,    |         |   (TPM, IDevID, SDN,      |       |
|  |    BMC, attestation)    |         |    BMC, attestation)      |       |
|  | - QuicBaaS() accessor   |         | - QuicBaaS() accessor     |       |
|  +-------------------------+         +---------------------------+       |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|              Multi-Protocol Transport Layer (platformd)                  |
|                                                                          |
|  Embedded   | REST (8443) | gRPC (10443) | QUIC (9444) | MCP (9445)      |
|  (in-proc)  |             |              |             | Unix (/run)     |
|                                                                          |
|  M6 INIT-ONLY GATE: before barrier unseal, only Unix + 127.0.0.1:9446    |
|  (/healthz + /init + /unseal) are bound. Remote transports gate.         |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|       Platform-Native Services (always embedded in platformd)            |
|                                                                          |
|  pkg/tpm/         pkg/vtpm/        pkg/idevid/      pkg/attestation/     |
|  pkg/device/      pkg/sdn/         pkg/dns/         pkg/compute/         |
|  pkg/bmc/         pkg/initrd/      pkg/iso/         pkg/ipxe/            |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|             go-quicbaas SDK  (the only path to the stack below)          |
|                                                                          |
|  Imported as: github.com/jeremyhahn/go-quicbaas/sdk/go                   |
|  Composed in: pkg/storage/quicbaas/sdk_embedded_qrdb.go                  |
|                                                                          |
|  Security().Auth().{WebAuthn,FIDO2,PIV,Factors}()                        |
|  Security().{Barrier,Ceremony,Credentials}()                             |
|  Security().Trust().Bootstrap()      Security().ACME()                   |
|  Security().{KMS,Secrets,Crypto,Certificate,CertificateExt}()            |
|  KV() / Batch() / Transaction() / Query() / Vector() / TimeSeries() ...  |
+--------------------------------------------------------------------------+
                                   |
                                   v
+--------------------------------------------------------------------------+
|               Upstream stack (NOT directly imported by platform)         |
|                                                                          |
|  go-qrdb              go-xkms                    go-quicraft / go-truststrap
|  (Raft KV +           (TPM2 + PKCS#11 + cloud    (Raft consensus +
|   software seal +      KMS + FIDO2 CTAP2 +        truststrap dispatch
|   PINBackend +         WebAuthn RP + PIV +        — composed inside xkms
|   ceremony +           TrustedCA + ACME +         and quicbaas)
|   credentials)         pkg/trust/bootstrap)                              |
+--------------------------------------------------------------------------+
```

### What the diagram replaces

The pre-Phase-6 architecture had per-dependency adapters under
`internal/quicbaas/`, `internal/ca/`, and `internal/xkms/`. Those were
removed when the quicbaas SDK absorbed the trusted-ca and xkms surfaces
into `Security().*`. The platform repo now imports exactly one SDK module
(`go-quicbaas/sdk/go`) for everything that used to be three.

## Key Components

### Platform Service Registry (`pkg/platform/registry.go`)

The registry is the central access point for all platform services. It:

- **Manages a single SDK client lifecycle** (create, start, stop)
- **Provides unified accessors** for native services and SDK verbs
- **Supports thread-safe access** via atomic operations and RWMutex
- **Handles graceful shutdown** with cleanup of the SDK client

```go
type Registry struct {
    // Single SDK client — composes qrdb (KV/seal/ceremony/credentials)
    // and xkms (TPM/PKCS#11/cloud KMS/FIDO2/WebAuthn/PIV/TrustedCA/
    // ACME/trust-bootstrap) behind quicbaas.SDK().Security().*.
    quicBaaSClient quicbaassdk.Client

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

    // Single quicbaas SDK configuration. Trusted-CA and xkms inputs
    // are folded into the SDK's Security().ACME() / Security().Trust()
    // / Security().{KMS,Certificate,...} surfaces, so the platform
    // registry no longer carries CAConfig / XKMSConfig fields.
    QuicBaaSConfig *quicbaas.Config

    // Native Service References
    DeviceService *device.Service
    DNSService    *dns.Service
}
```

#### Start Parameters

For embedded mode, pass the in-process quicbaas SDK client to the Start
method. After the Phase 6 / Phase 7 / Phase 8 refactors there is **one**
SDK client; the previous trusted-ca and xkms adapter inputs were folded
into the quicbaas SDK's `Security().ACME()` / `Security().Trust()` /
`Security().{KMS,Certificate,...}` surfaces.

```go
type StartParams struct {
    QuicBaaSClient quicbaassdk.Client // Embedded quicbaas SDK client
    DeviceService  *device.Service
    DNSService     *dns.Service
}
```

### Embedded composition

When the platform daemon runs `serve --embedded` (the default for
single-node deployments) it composes the quicbaas SDK in-process via
`pkg/storage/quicbaas/sdk_embedded_qrdb.go`. The embedded SDK is wired
against the local qrdb sharded client so application code reaches the
same in-memory KV state that backs the QuicBaaS facade, with no transport
hop. See `embeddedQRDBOption` in that file for the canonical wiring.

The composition uses the canonical `WithEmbeddedQRDB` option exported by
`go-quicbaas/sdk/go` — it accepts a `QRDBEmbeddedServicers` struct that
bundles the KV, Admin, Barrier, Ceremony, Credential, and CeremonyCA
servicers the SDK needs.

### Capability map (per quicbaas SDK)

| Category | SDK accessor |
|----------|--------------|
| Core Data | `Client.KV()`, `Batch()`, `Transaction()`, `Query()`, `TimeSeries()`, `Backup()` |
| AI/ML | `Client.Vector()`, `Embedding()`, `Ollama()`, `RAG()` |
| Security (auth) | `Security().Auth().{WebAuthn,FIDO2,PIV,Factors}()` plus the embedded `AuthClient` |
| Security (barrier/ceremony) | `Security().Barrier()`, `Security().Ceremony()`, `Security().Credentials()` |
| Security (keys/secrets) | `Security().{KMS,Secrets,Crypto,Certificate,CertificateExt,Seal,RBAC,ClusterDEK,DEK,DynamicSecrets,SealStore}()` |
| Security (trust) | `Security().Trust().Bootstrap()`, `Security().Trust().{DANE,Pools,AIA}()` |
| Security (ACME) | `Security().ACME()` |
| Infrastructure | `Cluster()`, `Health()`, `Operations()`, `Cache()`, `ParameterStore()`, `Scheduler()`, `ObjectStorage()`, `ObjectStorageAdmin()`, `ObjectTransfer()` |
| Identity | `IAM()` (with sub-clients) |
| Messaging | `Messaging()` (pub/sub, push notifications, delta sync) |
| Tenant | `Tenant()` |

The complete interface set lives in `quicbaas/sdk/go/services.go`. There
are **no flat shortcuts** for capabilities grouped under `Security()` —
the Phase 8a refactor removed the deprecated `Client.Barrier()` /
`Client.BarrierCeremony()` accessors.

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

// Start with the embedded quicbaas SDK client. The platform's
// pkg/storage/quicbaas/sdk_embedded_qrdb.go wires the canonical
// WithEmbeddedQRDB option so the SDK shares the in-memory qrdb
// state with platformd.
err = registry.Start(ctx, &platform.StartParams{
    QuicBaaSClient: embeddedQuicBaaSClient,
})
```

### Accessing Services

```go
// Convenience accessors on the registry.
kv := registry.KV()           // Key-value client
kms := registry.KMS()         // KMS client
secrets := registry.Secrets() // Secrets client

// Or reach the full SDK surface.
sdk := registry.QuicBaaS()
vec := sdk.Vector()
emb := sdk.Embedding()
auth := sdk.Security().Auth()      // WebAuthn/FIDO2/PIV/Factors
trust := sdk.Security().Trust()    // DANE/Bootstrap/Pools/AIA

// Native services are unchanged.
deviceSvc := registry.DeviceService()
dnsSvc := registry.DNSService()
```

### SDK Client Usage

```go
// Connect to platform daemon over the configured transport.
client, err := platform.Connect(ctx, platform.NewOptions())
if err != nil {
    return err
}
defer client.Close()

// Platform-native verbs (TPM, IDevID, attestation, SDN, BMC).
resp, err := client.TPM().GetEK(ctx, &req)

// Stack capabilities (everything else).
sdk := client.QuicBaaS()

// Core data
_, err = sdk.KV().Put(ctx, &quicbaas.PutRequest{Key: "foo", Value: []byte("bar")})

// Barrier / ceremony
barrier, err := sdk.Security().Barrier()
ceremony, err := sdk.Security().Ceremony()

// Auth (WebAuthn / FIDO2 / PIV / factors)
opts, err := sdk.Security().Auth().WebAuthn().BeginRegistration(ctx, user)

// Trust bootstrap
trust := sdk.Security().Trust()
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

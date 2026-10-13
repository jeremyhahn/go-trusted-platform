# Trusted Registry

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [cli.md](cli.md), [api.md](api.md) and [user.md](user.md). There is no `registry.NewClient`, `registry.ClientConfig` or `handlers.go`; config keys are snake_case (`listen_addr`, `quicbaas_addr`); `../quicbaas/` does not exist.

Attestation-gated container registry with hardware-backed encryption.

## Overview

The Trusted Registry is a container registry that only allows access from verified/attested hosts, fully integrated with the trusted computing environment. It provides:

- **Attestation-Gated Access**: TPM quote required before image pull/push
- **Image Encryption**: All images encrypted with keys managed by QuicBaaS
- **QuicBaaS Storage**: Single storage backend leveraging QuicBaaS's internal flexibility

## Key Features

| Feature | Description |
|---------|-------------|
| **TPM Attestation** | Clients must present valid TPM quote with PCR values |
| **OPA Policy Evaluation** | Customizable access policies via OPA |
| **Image Layer Encryption** | AES-256-GCM encryption per layer |
| **Key Wrapping** | Per-layer DEKs wrapped with QuicBaaS-managed keys |
| **OCI Compliance** | Standard OCI registry API for tool compatibility |
| **Audit Logging** | All access attempts logged with attestation details |

## Architecture Decision

**QuicBaaS-Only Storage** - The Trusted Registry uses QuicBaaS exclusively for blob storage.

| Aspect | Decision |
|--------|----------|
| Storage | QuicBaaS (no S3/filesystem abstraction) |
| Keys | QuicBaaS key management namespace |
| Encryption | Always-on image layer encryption |
| Authentication | TPM attestation (no username/password) |

**Rationale:**
- QuicBaaS already supports multiple backends internally
- Single integration point reduces complexity
- Unified key and data management
- Hardware-backed security throughout

## Quick Start

### Registry Configuration

```yaml
# config.yaml
registry:
  enabled: true
  listen-addr: ":5000"

  tls:
    cert-file: /etc/platformd/certs/registry.crt
    key-file: /etc/platformd/certs/registry.key

  attestation:
    require-attestation: true
    required-pcrs: [0, 1, 2, 7, 14]
    attestation-policy: "registry.access"

  encryption:
    quicbaas-addr: "localhost:9000"
    key-namespace: "container-images"
    algorithm: "AES-256-GCM"
    encrypt-by-default: true

  storage:
    addr: "localhost:9000"
    namespace: "registry-blobs"
    encrypted: true
```

### Pulling Images

Clients must provide attestation evidence with each request:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/registry"

// Create registry client with attestation
client, err := registry.NewClient(registry.ClientConfig{
    RegistryAddr: "registry.platform.local:5000",
    TPM:          tpm,  // TPM handle for quotes
    AIK:          aik,  // Attestation Identity Key
})

// Pull image (attestation happens automatically)
image, err := client.Pull(ctx, "myapp:v1.0")
```

### Device Profile Integration

```yaml
device_profile:
  name: "secure-compute-node"

  registry:
    trusted_registry: "registry.platform.local:5000"
    attestation:
      enabled: true
      required_pcrs: [0, 1, 2, 7, 14]
    encryption:
      enabled: true
      quicbaas_addr: "quicbaas.platform.local:9000"
      key_namespace: "container-images"
      encrypt_by_default: true

  containers:
    - name: "secure-app"
      image: "registry.platform.local:5000/secure-app:v1"
```

## Components

```
pkg/registry/
├── registry.go       # TrustedRegistry implementation
├── config.go         # Registry configuration
├── auth.go           # Attestation-based authentication
├── encryption.go     # Image encryption with QuicBaaS keys
├── storage.go        # QuicBaaS storage backend
├── handlers.go       # HTTP handlers for OCI registry API
├── errors.go         # Typed error definitions
└── *_test.go         # Unit tests (90%+ coverage)
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Registry architecture and design |
| [Configuration](configuration.md) | Configuration reference |

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **TPM** | Quote generation and verification for attestation |
| **QuicBaaS** | Key management and blob storage |
| **OPA** | Policy evaluation for access control |
| **Container Orchestrator** | Image pull/push for containers |
| **Platform CA** | TLS certificates for registry endpoint |

## Security Model

### Attestation Flow

1. Client generates TPM quote over required PCRs
2. Client sends request with quote and AIK
3. Registry verifies quote signature
4. Registry evaluates OPA access policy
5. On success, registry decrypts and serves image

### Encryption Model

- Each image layer has unique Data Encryption Key (DEK)
- DEKs are wrapped with QuicBaaS-managed Key Encryption Key (KEK)
- KEK never leaves QuicBaaS
- Images are encrypted at rest and decrypted on-demand

### Access Control

- No username/password authentication
- TPM attestation is the only authentication method
- PCR values must match expected golden values
- OPA policies can enforce additional constraints

## See Also

- [Container Orchestrator](../compute/container-orchestrator.md)
- [TPM Documentation](../tpm/README.md)
- [QuicBaaS Documentation](../quicbaas/README.md)
- [Attestation Architecture](../attestation/architecture.md)

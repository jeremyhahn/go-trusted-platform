# QuicBaaS Integration

This document describes how go-trusted-platform integrates with go-quicbaas for distributed database services and Backend-as-a-Service features such as KMS, Secrets, IAM, and storage.

## Overview

go-trusted-platform uses QuicBaaS as its service layer for:

- **KMS**: Key management with multi-backend support
- **IAM**: Identity and access management with ABAC
- **Secrets**: Vault-style secrets management
- **KV Store**: Distributed key-value storage
- **Vector Search**: AI/ML vector similarity search
- **Embeddings**: Multi-provider embedding generation
- **Raft**: Strong consistency via Raft log replication

## SDK Integration

The platform SDKs wrap the go-quicbaas SDK to expose all 28 QuicBaaS services:

| Category | Services | Count |
|----------|----------|-------|
| Core Data | KV, Batch, Transaction, Query, TimeSeries, Backup | 6 |
| AI/ML | Vector, Embedding, Ollama | 3 |
| Security | Auth, KMS, Secrets, Crypto, DynamicSecrets, Certificate, Seal, RBAC, ClusterDEK | 9 |
| Infrastructure | Cluster, Health, Operations, Cache, ParameterStore, Scheduler, ObjectStorage, ObjectStorageAdmin, ObjectTransfer | 9 |
| Identity | IAM (with 11 sub-clients) | 1 |

### Multi-Transport Support

The SDK supports 5 transport options for connecting to QuicBaaS:

| Transport | Address Format | Use Case |
|-----------|---------------|----------|
| **Embedded** | `WithEmbedded(service)` | Default - current behavior |
| **Unix Socket** | `/var/run/quicbaas.sock` | Local IPC, CLI tools |
| **gRPC** | `localhost:10443` | High-performance remote |
| **REST** | `http://localhost:8443` | Web clients, external |
| **QUIC** | `localhost:9444` | Low-latency, mobile |

### Configuration Example

```yaml
# config.yaml
quicbaas:
  # Transport: embedded (default), unix, grpc, rest, quic
  transport: embedded

  # Address for remote transports
  address: "localhost:10443"

  # Unix socket path (for unix transport)
  unix_socket: "/var/run/quicbaas.sock"

  # Embedded mode settings (existing)
  storage_backend: pebble
  data_dir: /var/lib/platform/quicbaas
  cache_size: 134217728  # 128MB
  sync_writes: true
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          go-trusted-platform                             │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │     SDN     │  │   Compute   │  │   CA/ACME   │  │      CLI        │  │
│  │  Controller │  │ Orchestrator│  │   Server    │  │   platformctl   │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                │                  │           │
│         └────────────────┴────────────────┴──────────────────┘           │
│                                  │                                       │
│                                  ▼                                       │
└──────────────────────────────────┼───────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                     go-quicbaas (Service Layer)                          │
│                                                                          │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌────────────┐ │
│  │               │  │               │  │               │  │            │ │
│  │      KMS      │  │      IAM      │  │    Secrets    │  │  KV Store  │ │
│  │    Manager    │  │    Manager    │  │    Manager    │  │ (PebbleDB) │ │
│  │               │  │               │  │               │  │            │ │
│  │ Methods:      │  │ Methods:      │  │ Methods:      │  │ Methods:   │ │
│  │ • GenerateKey │  │ • Authenticate│  │ • Set         │  │ • Get      │ │
│  │ • GetKey      │  │ • Authorize   │  │ • Get         │  │ • Put      │ │
│  │ • DeleteKey   │  │ • CreateUser  │  │ • Delete      │  │ • Delete   │ │
│  │ • Encrypt     │  │ • CreateGroup │  │ • List        │  │ • List     │ │
│  │ • Decrypt     │  │ • CreateRole  │  │ • Rotate      │  │ • Watch    │ │
│  │ • Sign        │  │ • CreatePolicy│  │               │  │            │ │
│  │ • Verify      │  │ • Evaluate    │  │               │  │            │ │
│  │ • RotateKey   │  │               │  │               │  │            │ │
│  └───────┬───────┘  └───────────────┘  └───────────────┘  └─────┬──────┘ │
│          │                                                      │        │
│          │ (uses internally for                                 │        │
│          │  backend operations)                                 │        │
│          ▼                                                      ▼        │
│  ┌───────┴──────────────────────────────────────────────────┬───┴───┐    │
│  │                 go-xkms (Backend Library)            │  Raft │    │
│  │                                                          │Cluster│    │
│  │  ┌──────────┐  ┌────────┐  ┌─────────┐  ┌──────────────┐ │       │    │
│  │  │ Software │  │  TPM2  │  │ PKCS#11 │  │  Cloud KMS   │ │       │    │
│  │  │  (dev)   │  │(native)│  │  (HSM)  │  │ AWS/Azure/GCP│ │       │    │
│  │  └──────────┘  └────────┘  └─────────┘  └──────────────┘ │       │    │
│  └──────────────────────────────────────────────────────────┴───────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Direct go-xkms Usage

go-trusted-platform uses go-xkms directly **only** for native hardware operations that cannot go through QuicBaaS:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Direct go-xkms Usage (Native Hardware ONLY)                         │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 1. FIDO2 LUKS Enrollment                                          │  │
│  │    • Hardware passkey operations                                  │  │
│  │    • Must interact with physical device                           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 2. TPM2 Direct Operations                                         │  │
│  │    • Attestation quotes (Quote, VerifyQuote)                      │  │
│  │    • Sealing to PCRs (Seal, Unseal)                               │  │
│  │    • Reading PCR values                                           │  │
│  │    • Reading event log                                            │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 3. KeyAttributes Type Definitions                                 │  │
│  │    • Shared types between go-xkms and QuicBaaS                │  │
│  │    • Algorithm definitions, key attributes                        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ All other key operations go through QuicBaaS for:                       │
│   • Raft replication (cluster-wide consistency)                         │
│   • Backend abstraction (software/TPM/HSM/cloud)                        │
│   • Audit logging                                                       │
│   • Access control                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

## KMS Integration

### Configuration

> The gRPC API exposes KeyManagement, SecretsManagement, Crypto, and DEKManagement services. REST API and CLI are pending. See [kms/ROADMAP.md](../kms/ROADMAP.md) for details.

Key management is configured through the `certificate-authority` section's identity keys:

```yaml
# Current implementation: Keys are configured per CA identity
certificate-authority:
  identity:
    - name: root-ca
      keys:
        - algorithm: RSA
          size: 4096
          store: tpm2          # software, tpm2, or pkcs11
          pin: ${TPM_PIN}
        - algorithm: ECDSA
          curve: P-384
          store: pkcs11
          pin: ${PKCS11_PIN}
```

**QuicBaaS KMS Configuration:**

```yaml
# KMS configuration (handled by QuicBaaS)
kms:
  enabled: true
  backend: software  # software, tpm2, pkcs11, awskms, azurekv, gcpkms

  quicbaas:
    data_dir: /var/lib/platform/quicbaas
    raft:
      enabled: true
      bind: 10.0.0.1:7000
      peers:
        - 10.0.0.2:7000
        - 10.0.0.3:7000
```

### Usage Example

```go
import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
    "github.com/jeremyhahn/go-quicbaas/sdk/go/types"
)

// Initialize QuicBaaS with KMS
server, err := quicbaassdk.NewServer(quicbaassdk.Config{
    DataDir: "/var/lib/platform/quicbaas",
    KMS: quicbaassdk.KMSConfig{
        Backend: "software",
    },
})
if err != nil {
    return err
}

// Get KMS manager
kms := server.KMS()

// Generate a key
key, err := kms.GenerateKey(ctx, types.KeyAttributes{
    Path:      "/tenants/tenant-1/keys/my-key",
    Algorithm: types.AlgorithmAES256GCM,
    Purpose:   types.PurposeEncryption,
})
if err != nil {
    return err
}

// Encrypt data
ciphertext, err := kms.Encrypt(ctx, key.Path, plaintext)
if err != nil {
    return err
}

// Decrypt data
plaintext, err := kms.Decrypt(ctx, key.Path, ciphertext)
if err != nil {
    return err
}

// Rotate key (zero-downtime)
newKey, err := kms.RotateKey(ctx, key.Path)
if err != nil {
    return err
}
// Old ciphertext still decryptable with versioned key
```

### Key Hierarchy

```
┌──────────────────────────────────────────────────────────┐
│                      Key Hierarchy                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Root Key (per backend)                                  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Software: Derived from master password              │ │
│  │ TPM2: Storage Root Key (SRK)                        │ │
│  │ PKCS#11: HSM master key                             │ │
│  │ Cloud: AWS/Azure/GCP CMK                            │ │
│  └─────────────────────────────────────────────────────┘ │
│                          │                               │
│                          ▼                               │
│  Master Key (platform-wide)                              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Encrypted by root key                               │ │
│  │ Used to encrypt tenant master keys                  │ │
│  └─────────────────────────────────────────────────────┘ │
│                          │                               │
│           ┌──────────────┼──────────────┐                │
│           │              │              │                │
│           ▼              ▼              ▼                │
│  Tenant Keys         Tenant Keys    Tenant Keys          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ tenant-1    │  │ tenant-2    │  │ tenant-n    │       │
│  └──────┬──────┘  └─────────────┘  └─────────────┘       │
│         │                                                │
│    ┌────┼────┐                                           │
│    │    │    │                                           │
│    ▼    ▼    ▼                                           │
│  ┌───┐ ┌───┐ ┌───┐                                       │
│  │DEK│ │DEK│ │DEK│  Data Encryption Keys                 │
│  └───┘ └───┘ └───┘                                       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## IAM Integration

### Configuration

> **Note:** IAM integration with QuicBaaS is a planned feature. The configuration shown below is a proposed format and is not yet implemented.

Currently, authentication is configured through the `webservices` section:

```yaml
# Current implementation: Auth configured per webservice
webservices:
  - name: api-server
    port: 8443

    # JWT configuration
    jwt:
      algorithm: SHA256-RSA
      expiration: 3600
      issuer: https://platform.example.com

    # mTLS configuration
    mtls:
      enabled: true
      client-ca: /etc/platform/certs/client-ca.crt
```

**PROPOSED - QuicBaaS IAM Integration (Not Yet Implemented):**

```yaml
# Proposed future configuration
iam:
  enabled: true

  authentication:
    methods:
      - mtls      # Client certificate
      - jwt       # Bearer token

    jwt:
      issuer: https://platform.example.com
      audience: platformd
      signing_key: /etc/platform/keys/jwt.key

  authorization:
    default_policy: deny
    policies_path: /etc/platform/policies/
```

### Usage Example

```go
import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// Get IAM manager
iam := server.IAM()

// Authenticate from certificate
identity, err := iam.AuthenticateFromCert(ctx, clientCert)
if err != nil {
    return err
}

// Authorize action
decision, err := iam.Authorize(ctx, quicbaassdk.AuthzRequest{
    Principal: identity,
    Action:    "create",
    Resource:  "/api/v1/vms",
})
if err != nil {
    return err
}

if !decision.Allowed {
    return fmt.Errorf("access denied: %s", decision.Reason)
}

// Create user
user, err := iam.CreateUser(ctx, quicbaassdk.User{
    Username:  "admin",
    TenantID:  "tenant-1",
    Roles:     []string{"admin"},
})

// Create policy
policy, err := iam.CreatePolicy(ctx, quicbaassdk.Policy{
    Name: "admin-policy",
    Subjects: []quicbaassdk.Subject{
        {Attributes: map[string]string{"role": "admin"}},
    },
    Resources: []quicbaassdk.Resource{
        {Pattern: "/api/v1/**"},
    },
    Actions: []string{"*"},
    Effect:  "allow",
})
```

## Storage Backends

QuicBaaS supports multiple storage backends for different use cases:

| Backend | Persistence | Speed | Use Case |
|---------|-------------|-------|----------|
| `memory` | None | Fastest | Unit tests, ephemeral data |
| `file` | Yes (files) | Slowest | Debugging, human-readable data |
| `pebble` | Yes (LSM) | Fast | Single-node production (default) |
| `raft` | Yes (distributed) | Slower | Multi-node production with consensus |

### Single-Node Mode (Development/Production)

Use `pebble` backend for high-performance single-node deployments:

```yaml
quicbaas:
  storage-backend: pebble  # High-performance local storage
  data-dir: /var/lib/platform/quicbaas
  wal-dir: /var/lib/platform/quicbaas/wal
  cache-size: 67108864     # 64MB
  log-level: warn
  consistency-level: linearizable
```

```
┌──────────────────┐
│   Single Node    │
│                  │
│ platformd        │
│   │              │
│   └─▶ QuicBaaS   │
│       (PebbleDB) │
└──────────────────┘
```

### Memory Mode (Testing)

Use `memory` backend for fast unit tests:

```yaml
quicbaas:
  storage-backend: memory  # No persistence, fastest
  cache-size: 4194304      # 4MB
  log-level: error
```

### File Mode (Debugging)

Use `file` backend when you need to inspect data:

```yaml
quicbaas:
  storage-backend: file    # Human-readable files
  data-dir: /tmp/quicbaas-debug
  log-level: debug
```

### Clustered Mode (Production HA)

Use `raft` backend for distributed consensus:

```yaml
quicbaas:
  storage-backend: raft    # Distributed consensus
  data-dir: /var/lib/platform/quicbaas
  wal-dir: /var/lib/platform/quicbaas/wal
  raft-address: 10.0.0.1:63000
  node-id: 1
  join-addresses:
    - 10.0.0.2:63000
    - 10.0.0.3:63000
  cache-size: 67108864
  log-level: warn
    consistency-level: linearizable
```

```
┌────────────┐    ┌────────────┐    ┌────────────┐
│   Node 1   │    │   Node 2   │    │   Node 3   │
│  (Leader)  │    │ (Follower) │    │ (Follower) │
│            │    │            │    │            │
│ platformd  │    │ platformd  │    │ platformd  │
│     │      │    │     │      │    │     │      │
│     ▼      │    │     ▼      │    │     ▼      │
│ QuicBaaS   │◀──▶│ QuicBaaS   │◀──▶│ QuicBaaS   │
│   (Raft)   │    │   (Raft)   │    │   (Raft)   │
└────────────┘    └────────────┘    └────────────┘
       │               │                  │
       └───────────────┴──────────────────┘
                  Raft Consensus
```

## Data Flow

### Key Generation (Clustered)

```
Client              Node 1 (Leader)         Node 2         Node 3
   │                     │                    │               │
   │ GenerateKey         │                    │               │
   │────────────────────▶│                    │               │
   │                     │                    │               │
   │                     │ 1. Generate key    │               │
   │                     │    material        │               │
   │                     │                    │               │
   │                     │ 2. Raft Propose    │               │
   │                     │───────────────────▶│               │
   │                     │                    │               │
   │                     │◀───────────────────│               │
   │                     │    Raft Commit     │               │
   │                     │                    │               │
   │                     │ 3. Apply to state  │               │
   │                     │    machine         │               │
   │                     │                    │               │
   │◀────────────────────│                    │               │
   │    Key created      │                    │               │
```

### Secret Retrieval (Any Node)

```
Client              Node 2 (Follower)       Node 1 (Leader)
   │                     │                        │
   │ GetSecret           │                        │
   │────────────────────▶│                        │
   │                     │                        │
   │                     │ 1. Check local state   │
   │                     │    (may be stale)      │
   │                     │                        │
   │                     │ 2. Read from Raft      │
   │                     │    (consistent read)   │
   │                     │───────────────────────▶│
   │                     │◀───────────────────────│
   │                     │                        │
   │◀────────────────────│                        │
   │    Secret value     │                        │
```

## Service Interface

```go
// QuicBaaS provides the main service interface
type QuicBaaS interface {
    // Service managers
    KMS() KMSManager
    IAM() IAMManager
    Secrets() SecretsManager
    KV() KVStore

    // Cluster operations
    Cluster() ClusterManager

    // Lifecycle
    Close() error
}

// KMSManager provides key management operations
type KMSManager interface {
    GenerateKey(ctx context.Context, attrs types.KeyAttributes) (*Key, error)
    GetKey(ctx context.Context, path string) (*Key, error)
    DeleteKey(ctx context.Context, path string) error
    ListKeys(ctx context.Context, prefix string) ([]*Key, error)

    Encrypt(ctx context.Context, keyPath string, plaintext []byte) ([]byte, error)
    Decrypt(ctx context.Context, keyPath string, ciphertext []byte) ([]byte, error)

    Sign(ctx context.Context, keyPath string, digest []byte) ([]byte, error)
    Verify(ctx context.Context, keyPath string, digest, sig []byte) (bool, error)

    RotateKey(ctx context.Context, path string) (*Key, error)
}

// IAMManager provides identity and access management
type IAMManager interface {
    // Authentication
    AuthenticateFromCert(ctx context.Context, cert *x509.Certificate) (*Identity, error)
    AuthenticateFromToken(ctx context.Context, token string) (*Identity, error)

    // Authorization
    Authorize(ctx context.Context, req AuthzRequest) (*AuthzDecision, error)

    // User management
    CreateUser(ctx context.Context, user User) (*User, error)
    GetUser(ctx context.Context, id string) (*User, error)
    UpdateUser(ctx context.Context, user User) (*User, error)
    DeleteUser(ctx context.Context, id string) error

    // Group management
    CreateGroup(ctx context.Context, group Group) (*Group, error)
    AddUserToGroup(ctx context.Context, userID, groupID string) error
    RemoveUserFromGroup(ctx context.Context, userID, groupID string) error

    // Role management
    CreateRole(ctx context.Context, role Role) (*Role, error)
    AssignRole(ctx context.Context, principalID, roleID string) error

    // Policy management
    CreatePolicy(ctx context.Context, policy Policy) (*Policy, error)
    UpdatePolicy(ctx context.Context, policy Policy) (*Policy, error)
    DeletePolicy(ctx context.Context, id string) error
}
```

## Scheduler Clustering

Platformd embeds go-quicbaas's scheduler engine on PlatformShardID=1.
In a Raft cluster the storage is replicated across every node, so
every node's engine observes every due job.

Dispatch gating (from go-quicbaas `NewWithClustering`):

| Scenario | Rule |
|---|---|
| `Job.NodeAffinity == ""` (cluster-wide) | Execute only on the Raft leader |
| `Job.NodeAffinity == <nodeID>` (node-affine) | Execute only on the matching node, regardless of leadership |

Platformd uses node-affine jobs for cert renewal (one job per node,
named `platform.cert-renewal.<nodeID>`), so each node renews only
its own certs and leader churn doesn't cause duplicate firings.

Leadership for the gate is supplied via a `LeaderChecker` — a small
interface the platform implements against the existing raft accessor
(`server.IsLeader(PlatformShardID)`).

Wire-up: the quicbaas `SchedulerEngine()` accessor exposes the raw
engine to platformd; `App.CertManagementScheduler()` returns it as
the narrow `SchedulerService` interface the cert-renewal handler
consumes.

See `../bmc-tls.md` for the cert lifecycle that rides on top of this
pattern, and `../../docs/bmc/testing.md` + `../operations/cert-lifecycle.md`
for integration test + operator guides. Upstream detail lives in
`/home/jhahn/sources/go-quicbaas/docs/scheduler-clustering.md`.

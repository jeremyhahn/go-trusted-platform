# KMS Architecture

## Overview

The Trusted Platform KMS provides distributed key management through direct QuicBaaS integration. The architecture leverages QuicBaaS's native KMS service with go-xkms backends for hardware security support including TPM 2.0 and PKCS#11 HSMs.

**Implementation Status:**
- gRPC API: 100% complete
- REST API: 100% complete (99.9% test coverage)
- CLI Commands: 100% complete
- Integration Tests: Framework complete, adapters implemented

## Component Architecture

```
+-----------------------------------------------------------------------+
|                          Trusted Platform KMS                          |
+-----------------------------------------------------------------------+
|                                                                        |
|  +------------------------------------------------------------------+  |
|  |                     platformctl (CLI)                            |  |
|  |         pkg/cli/commands/kms/*.go                                |  |
|  |         key, dek, secrets, crypto, status commands               |  |
|  +-----------------------------+------------------------------------+  |
|                                | gRPC (Unix socket)                    |
|                                v                                       |
|  +------------------------------------------------------------------+  |
|  |                     REST API Layer                               |  |
|  |         pkg/webservice/v1/rest/kms/                              |  |
|  |         handlers.go, router.go, types.go                         |  |
|  +-----------------------------+------------------------------------+  |
|                                | HTTP/HTTPS                            |
|                                v                                       |
|  +------------------------------------------------------------------+  |
|  |                     platformd (daemon)                           |  |
|  |               Listens on Unix socket for gRPC requests           |  |
|  +-----------------------------+------------------------------------+  |
|                                |                                       |
|                                v                                       |
|  +------------------------------------------------------------------+  |
|  |                     KMSService                                   |  |
|  |                (pkg/api/daemon/kms_service.go)                   |  |
|  |   Wraps QuicBaaS KMS gRPC services:                              |  |
|  |   - KeyManagement: Key lifecycle operations                      |  |
|  |   - SecretsManagement: Secret storage/retrieval                  |  |
|  |   - Crypto: Encryption/decryption operations                     |  |
|  |   - DEKManagement: Data encryption key management                |  |
|  +-----------------------------+------------------------------------+  |
|                                |                                       |
|                                v                                       |
|  +------------------------------------------------------------------+  |
|  |                  QuicBaaS KMS Service                            |  |
|  |                (from go-quicbaas)                                |  |
|  |   - Key generation and storage                                   |  |
|  |   - Secret management                                            |  |
|  |   - Cryptographic operations                                     |  |
|  +-----------------------------+------------------------------------+  |
|                                |                                       |
|                                v                                       |
|  +------------------------------------------------------------------+  |
|  |                     go-xkms Backends                         |  |
|  +-------------------+-------------------+---------------------------+  |
|  |   Software        |      TPM 2.0      |         PKCS#11          |  |
|  |   Backend         |      Backend      |         Backend          |  |
|  +-------------------+-------------------+---------------------------+  |
|                                                                        |
+------------------------------------------------------------------------+
```

## Layer Details

### CLI Layer (`pkg/cli/commands/kms/`)

The CLI provides user-facing commands through `platformctl`:

| File | Description |
|------|-------------|
| `kms.go` | Root KMS command |
| `key.go` | Key management commands |
| `dek.go` | DEK management commands |
| `secrets.go` | Secrets management commands |
| `crypto.go` | Cryptographic operations |
| `status.go` | Backend status command |
| `crypto_encrypt.go` | Encrypt command |
| `crypto_decrypt.go` | Decrypt command |
| `crypto_sign.go` | Sign command |
| `crypto_verify.go` | Verify command |
| `crypto_hash.go` | Hash command |
| `crypto_hmac.go` | HMAC command |
| `crypto_random.go` | Random bytes command |
| `crypto_rewrap.go` | Rewrap command |
| `crypto_batch.go` | Batch operations |
| `crypto_datakey.go` | Data key generation |
| `key_import.go` | Key import |
| `key_export.go` | Key export |
| `key_versions.go` | Version management |
| `key_revoke.go` | Key revocation |
| `key_status.go` | Enable/disable |
| `key_metadata.go` | Metadata operations |
| `key_policy.go` | Policy management |
| `key_algorithms.go` | List algorithms |
| `key_safety.go` | Safety limits |
| `key_test_backend.go` | Backend testing |
| `dek_safety.go` | DEK safety limits |
| `secrets_version.go` | Get version |
| `secrets_versions.go` | List versions |
| `secrets_rollback.go` | Rollback |
| `secrets_status.go` | Status management |
| `secrets_policy.go` | Rotation policy |
| `secrets_prefix.go` | Prefix operations |
| `secrets_watch.go` | Watch for changes |

### REST API Layer (`pkg/webservice/v1/rest/kms/`)

The REST layer provides HTTP endpoints:

| File | Description |
|------|-------------|
| `router.go` | Route registration |
| `handlers.go` | Request handlers |
| `types.go` | Request/response types |
| `errors.go` | Error types |

**Route Groups:**

| Prefix | Handler Group |
|--------|---------------|
| `/api/v1/kms/keys` | Key management |
| `/api/v1/kms/encrypt`, `/decrypt`, etc. | Crypto operations |
| `/api/v1/kms/deks` | DEK management |
| `/api/v1/kms/secrets` | Secrets management |
| `/api/v1/kms/backend` | Backend operations |

### gRPC Service Layer (`pkg/api/daemon/kms_service.go`)

The KMSService wraps QuicBaaS's KMS gRPC services:

```go
type KMSService struct {
    app       *app.App
    logger    *slog.Logger
    kmsServer *dbgrpc.KMSServer
    running   atomic.Bool
}
```

**Registered Services:**

| Service | Description |
|---------|-------------|
| `KeyManagement` | Key lifecycle: generate, rotate, import, export, delete |
| `SecretsManagement` | Secret storage and retrieval |
| `Crypto` | Encryption and decryption operations |
| `DEKManagement` | Data encryption key management |

## Request Flow

### CLI Request Flow

```
platformctl kms key generate --algorithm AES-256-GCM my-key
    |
    | Parse flags, create gRPC request
    v
cli.NewBaseCommand() -> base.Client().KMS()
    |
    | gRPC (Unix socket)
    v
platformd daemon
    |
    | app.KMS() accessor
    v
KMSService (daemon service wrapper)
    |
    | dbgrpc.KMSServer
    v
QuicBaaS KMS Service
    |
    | go-xkms types
    v
go-xkms Backend (software/tpm2/pkcs11)
```

### REST Request Flow

```
POST /api/v1/kms/keys
    |
    | HTTP request
    v
KMSRouter.RegisterRoutes() -> handlers.GenerateKey()
    |
    | Decode JSON, validate
    v
keyMgmtClient.GenerateKey() (gRPC client)
    |
    | gRPC call
    v
QuicBaaS KMS Service
    |
    v
go-xkms Backend
```

## Key Hierarchy

```
+---------------------------------------------------+
|        Root Key (TPM/HSM Primary Key)             |
|        Hardware-bound, never exported             |
+-------------------------+-------------------------+
                          | seals
                          v
+---------------------------------------------------+
|        Storage Root Key (SRK)                     |
|        TPM persistent handle 0x81000001           |
+-------------------------+-------------------------+
                          | derives/wraps
                          v
+---------------------------------------------------+
|        Master Key (Per Backend)                   |
|        Seals/unseals Data Encryption Keys         |
+-------------------------+-------------------------+
                          | seals
                          v
+---------------------------------------------------+
|        Data Encryption Key (DEK)                  |
|        Encrypts user keys and application data    |
|        Replicated via QuicBaaS                    |
+-------------------------+-------------------------+
                          | encrypts
                          v
+---------------------------------------------------+
|        User Keys                                  |
|        Application-specific encryption keys       |
+-------------------------+-------------------------+
                          | encrypts
                          v
+---------------------------------------------------+
|        Application Data                           |
|        Secrets, credentials, sensitive data       |
+---------------------------------------------------+
```

## Backend Selection

go-xkms supports multiple backends with automatic routing:

```
+-----------------------------------------------------------------------+
|                        Backend Selection                               |
+-----------------------------------------------------------------------+
|                                                                        |
|   1. Check explicit location in key attributes                         |
|      - KeyLocationSoftware -> Software backend                         |
|      - KeyLocationTPM -> TPM 2.0 backend (if available)                |
|      - KeyLocationHSM -> PKCS#11 backend (if configured)               |
|                                                                        |
|   2. Check algorithm compatibility                                     |
|      - Ed25519, Ed448 -> Software only (TPM doesn't support)           |
|      - AES-GCM, ECDSA, RSA -> TPM or Software                          |
|                                                                        |
|   3. Use default location from configuration                           |
|                                                                        |
|   4. Fallback logic                                                    |
|      - If TPM requested but unavailable -> Fall back to software       |
|      - Log warning for fallback                                        |
|                                                                        |
+-----------------------------------------------------------------------+
```

## go-xkms Backends

```
+-----------------------------------------------------------------------+
|                   go-xkms Backend Architecture                     |
+-----------------------------------------------------------------------+
|                                                                        |
|   +-------------------------+   +-------------------------+            |
|   |    Software Backend     |   |      TPM 2.0 Backend    |            |
|   |    (Default)            |   |    (Hardware Keys)      |            |
|   +------------+------------+   +------------+------------+            |
|                |                             |                         |
|                v                             v                         |
|   +-------------------------+   +-------------------------+            |
|   |    QuicBaaS Storage     |   |     TPM 2.0 Device      |            |
|   |    - Key metadata       |   |   - Sealed key handles  |            |
|   |    - Encrypted keys     |   |   - PCR policies        |            |
|   |    - Usage tracking     |   |   - Platform binding    |            |
|   +-------------------------+   +-------------------------+            |
|                                                                        |
|   +-------------------------+                                          |
|   |    PKCS#11 Backend      |                                          |
|   |    (HSM Support)        |                                          |
|   +------------+------------+                                          |
|                |                                                       |
|                v                                                       |
|   +-------------------------+                                          |
|   |    Hardware Security    |                                          |
|   |    Module (HSM)         |                                          |
|   +-------------------------+                                          |
|                                                                        |
+-----------------------------------------------------------------------+
```

## Key Status State Machine

```
                      +----------------+
                      |    Created     |
                      +-------+--------+
                              |
                              v
+-----------+         +----------------+         +------------+
|  Disabled |<------->|    Enabled     |-------->|  Rotating  |
+-----------+         +-------+--------+         +-----+------+
      |                       |                        |
      |                       |                        |
      |                       v                        |
      |               +----------------+               |
      +-------------->|    Revoked     |<--------------+
                      +-------+--------+
                              |
                              v
                      +----------------+
                      | PendingDeletion|
                      +-------+--------+
                              |
                              v
                      +----------------+
                      |    Deleted     |
                      +----------------+
```

## Security Model

### Key Protection

| Layer | Protection Method |
|-------|-------------------|
| At Rest (Software) | Encrypted with DEK in QuicBaaS |
| At Rest (TPM) | Sealed to TPM hierarchy, PCR-bound |
| In Transit | TLS 1.3, mTLS for internal communication |
| In Memory | Secure zeroing after use, optional caching |

### Access Control

```
+-----------------------------------------------------------------------+
|                         Access Control                                 |
+-----------------------------------------------------------------------+
|                                                                        |
|   Key Policy:                                                          |
|   - AllowedOperations: [encrypt, decrypt, sign, verify]                |
|   - AllowedPrincipals: [user-1, service-2]                             |
|   - DeniedPrincipals: [banned-user]                                    |
|   - RequireMFA: true                                                   |
|   - MaxUsageCount: 1000000                                             |
|   - ExpiresAt: 2025-12-31T23:59:59Z                                    |
|                                                                        |
+-----------------------------------------------------------------------+
```

### Audit Logging

All key operations are logged:

| Operation | Log Level | Details |
|-----------|-----------|---------|
| GenerateKey | INFO | Key ID, algorithm, location |
| GetKey | DEBUG | Key ID, requester |
| DeleteKey | WARN | Key ID, force flag, requester |
| RotateKey | INFO | Key ID, old version, new version |
| RevokeKey | WARN | Key ID, reason, requester |
| Policy Change | INFO | Key ID, policy changes |

## Multi-Backend Deployment

Each deployment can use different backends per key:

```
+-----------------------------------------------------------------------+
|                     Multi-Backend Deployment                           |
+-----------------------------------------------------------------------+
|                                                                        |
|   Production Keys:                                                     |
|   +-------------------+                                                |
|   | Location: TPM     |  Hardware-bound, cannot be extracted           |
|   | Algorithm: ECDSA  |  Used for signing, authentication              |
|   +-------------------+                                                |
|                                                                        |
|   Bulk Encryption Keys:                                                |
|   +-------------------+                                                |
|   | Location: Software|  High throughput for data encryption           |
|   | Algorithm: AES-GCM|  Backed by QuicBaaS storage                    |
|   +-------------------+                                                |
|                                                                        |
|   FIPS Compliance Keys:                                                |
|   +-------------------+                                                |
|   | Location: HSM     |  PKCS#11 HSM for regulatory compliance         |
|   | Algorithm: RSA    |  Audit trail, tamper evidence                  |
|   +-------------------+                                                |
|                                                                        |
+-----------------------------------------------------------------------+
```

## CA Integration

The KMS provides signing key access for the go-xkms CA component (pkg/ca, consumed via go-quicbaas SDK) through the QuicBaaSKMSAdapter (`pkg/ca/quicbaas/kms_adapter.go`).

### Integration Flow

```
go-xkms CA (pkg/ca)          go-trusted-platform              go-quicbaas
     |                               |                              |
     | GetSigningKey(tenant,purpose) |                              |
     |------------------------------>|                              |
     |                               | kms.GetKey(keyID)            |
     |                               |---------------------------->|
     |                               |<----------------------------|
     |                               |                              |
     |                               | xkms.SignerByID(keyID)   |
     |                               |---------------------------->|
     |                               |<----------------------------|
     |<------------------------------| crypto.Signer                |
```

### KMSAdapter Methods

| Method | Description |
|--------|-------------|
| `CreateSigningKey` | Creates a new signing key for a tenant/purpose |
| `GetSigningKey` | Returns crypto.Signer via xkms.SignerByID |
| `ListSigningKeys` | Lists all signing keys for a tenant |
| `DeleteSigningKey` | Permanently deletes a key |
| `EnableSigningKey` | Enables a disabled key |
| `DisableSigningKey` | Disables a key without deletion |

## Recovery and Backup

### Software Keys

- Backed up via QuicBaaS snapshots
- Can be exported with key wrapping
- Replicated across cluster nodes

### TPM Keys

- Platform-bound, cannot be backed up directly
- Use key escrow with authorized recovery
- Multi-platform deployments use separate keys

### HSM Keys

- HSM-specific backup procedures
- Key cloning to backup HSM
- Recovery procedures per HSM vendor

# Unified Architecture: Dependency Stack

This document describes the dependency chain across the go-trusted-platform ecosystem, detailing which capabilities originate from which layer and how barrier, ceremony, and algorithm operations flow through the stack.

## Dependency Chain

```
go-qrdb          (foundation: embedded database, system utilities)
    |
go-xkms          (key management: keystores, cert stores, TPM2)
    |
go-quicbaas      (service layer: barrier, auth, QUIC transport, SDK)
    |
go-trusted-platform  (platform: CA, attestation, device management)
```

### go-qrdb

Foundation layer providing embedded database and system-level utilities.

**Capabilities provided:**
- Embedded key-value storage engine (Pebble-backed)
- WAL (write-ahead log) for crash recovery
- Barrier storage encryption (encrypt-at-rest for all data)
- Shamir secret sharing implementation
- OpenSSL configuration parsing (`pkg/system`)
- Transport abstractions: gRPC, QUIC, REST, MCP, embedded

**Key interfaces:**
- `transport.BarrierClient` -- barrier lifecycle operations (init, seal, unseal, rekey)
- `transport.Client` -- unified database client across all transports

### go-xkms

Key Management Services layer implementing secure key and certificate storage.

**Capabilities provided:**
- Software cryptographic backend (asymmetric + symmetric operations)
- TPM 2.0 backend for hardware-bound key operations
- PKCS#11 backend for HSM integration
- Certificate store with pluggable storage backends
- Key generation, signing, verification, encryption
- Platform password management for TPM sealing

**Key interfaces:**
- `xkms.Backend` -- unified keystore operations
- `store.KeyBackend` -- TPM key persistence
- `certstore.CertStore` -- certificate CRUD

### go-quicbaas

Backend-as-a-Service layer providing service orchestration and SDK.

**Capabilities provided:**
- QuicBaaS SDK client (`sdk/go/Client`) wrapping go-qrdb transports
- Barrier lifecycle management via SDK
- IAM / authentication / token validation
- Object storage service
- QUIC transport with TLS 1.3
- MCP (Model Context Protocol) integration
- Service discovery and health checks

**Key interfaces:**
- `quicbaassdk.Client` -- SDK entry point; barrier lifecycle is reached via `Security().Barrier()`
- `service.ServiceInterface` -- platform service abstraction
- `client/objectstorage` -- object storage client

### go-trusted-platform

Top-level platform consuming all lower layers.

**Capabilities provided:**
- ACME RFC-8555 certificate authority (CA/ACME engine from go-xkms, consumed via the go-quicbaas SDK `Security().ACME()` / `Security().Certificate()`)
- TPM attestation and device identity (IDevID/LDevID)
- Barrier gRPC service exposing barrier operations to platform clients
- Multi-protocol API: gRPC, REST, QUIC, MCP, Unix socket
- Device provisioning and lifecycle management
- SDN overlay networking
- Cluster management
- vTPM management for virtual machines

## Barrier Flow

The barrier protects all sensitive data at rest using encryption. The flow from gRPC client to storage:

```
platformctl CLI / gRPC client
    |
    v
BarrierGRPCService (pkg/api/daemon)      -- protobuf <-> SDK type mapping
    |
    v
barrier.Manager (pkg/barrier)            -- local state tracking, validation
    |
    v
quicbaas SDK Security().Barrier()        -- barrier service client
    |
    v
qrdbtransport.BarrierClient             -- transport-agnostic interface
    |
    v
go-qrdb barrier engine                  -- Shamir splitting, AES-GCM encryption
    |
    v
Pebble storage                          -- encrypted data at rest
```

### Initialization

1. `BarrierGRPCService.Init()` receives the gRPC request
2. If `threshold >= 2`, delegates to `barrier.Manager.InitializeShamir()`
3. Manager calls the SDK barrier client's `BarrierInitializeShamir()` (reached via `Security().Barrier()`)
4. go-qrdb generates Shamir shares and encrypts the barrier key
5. Shares are returned through the stack to the gRPC client

### Unseal

1. `BarrierGRPCService.Unseal()` checks `barrier.Config.IsShamir()`
2. Shamir mode: calls `Manager.UnsealWithShare()` for each share
3. Single-key mode: calls `Manager.Unseal()` with the master secret
4. Manager delegates to the SDK barrier client
5. go-qrdb reconstructs the encryption key and unlocks storage

### Seal

1. `BarrierGRPCService.Seal()` delegates to `Manager.Seal()`
2. Manager calls the SDK barrier client's `BarrierSeal()` (reached via `Security().Barrier()`)
3. go-qrdb discards the in-memory encryption key
4. All data access is blocked until next unseal

## Algorithm Flow

Cryptographic operations flow through go-xkms backends:

```
Platform CA / attestation code
    |
    v
go-xkms Backend (software / tpm2 / pkcs11)
    |
    +-- Software: Go stdlib crypto (RSA, ECDSA, Ed25519, AES-GCM)
    |
    +-- TPM2: go-tpm library -> hardware TPM
    |
    +-- PKCS11: PKCS#11 C bindings -> HSM hardware
```

The platform selects backends at startup based on configuration. Multiple backends can coexist (e.g., software for general operations, TPM2 for attestation keys).

## Storage Architecture

All storage goes through go-objstore for portability:

| Data Type | Storage Layer | Backend Options |
|-----------|--------------|-----------------|
| Keys | go-xkms | File, Memory, TPM NVRAM |
| Certificates | go-xkms certstore | File, Memory, go-objstore |
| Barrier data | go-qrdb (Pebble) | Local embedded DB |
| Objects | go-objstore | Local FS, S3, Azure Blob, GCS |
| Configuration | go-quicbaas | Embedded or remote QRDB |

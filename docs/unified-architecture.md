# Unified Architecture: Dependency Stack

This document describes the dependency chain across the go-trusted-platform ecosystem, detailing which capabilities originate from which layer and how barrier, ceremony, and algorithm operations flow through the stack.

## Dependency Chain

The capability stack — who owns which primitive — is four layers deep:

```
go-qrdb          (foundation: embedded database, system utilities)
    |
go-xkms          (key management: keystores, cert stores, TPM2)
    |
go-quicbaas      (service layer: barrier, auth, QUIC transport, SDK)
    |
go-trusted-platform  (platform: CA, attestation, device management)
```

That chain describes where capabilities *originate*, not what the platform is allowed to import. The platform reaches every crypto, key, auth, ceremony, and trust-bootstrap capability through the go-quicbaas SDK alone. Importing `go-xkms`, `go-qrdb`, `go-quicraft`, or `go-truststrap` directly is forbidden everywhere in the repo, including in `_test.go` files, and the rule is machine-enforced by `pkg/arch/layerguard_test.go`, which parses every `.go` file in the module and fails with a `file:line` report naming the sanctioned SDK replacement. See [../CLAUDE.md](../CLAUDE.md) for the full layer-ownership table and the canonical `Security().*` entry point for each capability.

### The real go.mod dependency set

The four-layer chain understates what the module actually declares. The full set of `jeremyhahn` dependencies:

| Module | In go.mod as | Reached how |
|--------|--------------|-------------|
| `go-quicbaas/sdk/go` | direct | Imported directly; the single sanctioned runtime path (~570 import sites) |
| `go-quicbaas/api/proto` | direct | Imported directly for protobuf types in the daemon services |
| `go-codec` | direct | Imported directly (`pkg/api/daemon/daemon.go` and the QUIC/REST services) |
| `go-luks2` | direct | Imported directly (`pkg/firstboot`, `pkg/boot/commands`, `pkg/installer`, `pkg/app/backends`) |
| `go-xkms`, `go-xkms/sdk/go` | direct | **Never imported.** Present because the `quicbaas/sdk/go/xkms/*` type-alias re-exports resolve into them |
| `go-qrdb`, `go-qrdb/sdk/go` | indirect / direct | **Never imported.** Reached only through the SDK |
| `go-quicraft` | indirect | **Never imported.** Consensus is reached through the SDK |
| `go-truststrap` | direct | **Never imported.** Trust bootstrap goes through `quicbaas/sdk/go/xkms/trust/bootstrap`; the module is a leftover `require` |
| `go-objstore` | direct | **Never imported.** Object storage is reached through the quicbaas SDK object-storage client; the module is a leftover `require` |
| `go-frost` | indirect | Pulled in transitively; no platform import site |
| `go-auth` | indirect | Pulled in transitively; no platform import site |

The distinction matters when reading this document's later sections: where the text below says a capability comes from go-xkms or go-qrdb, that describes the implementation's home, and the platform still calls it through `quicbaas.SDK().Security().*`.

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

Object storage is portable behind a single interface shape, but the platform never imports go-objstore to get there. `pkg/store/object/objstore_adapter.go` wraps the SDK's `quicbaas/sdk/go/client/objectstorage` client and presents it as the `ObjectStorage` interface re-exported from `quicbaas/sdk/go/xkms`, which is the interface the CA expects:

| Data Type | Owning Layer | Platform reaches it via | Backend Options |
|-----------|--------------|-------------------------|-----------------|
| Keys | go-xkms | `Security().KMS()` | File, Memory, TPM NVRAM |
| Certificates | go-xkms certstore | `Security().Certificate()` | File, Memory, object storage |
| Barrier data | go-qrdb (Pebble) | `Security().Barrier()` | Local embedded DB |
| Objects | go-objstore interface shape | `pkg/store/object` adapter over the SDK objectstorage client | Local FS, S3, Azure Blob, GCS |
| Configuration | go-quicbaas | SDK | Embedded or remote QRDB |

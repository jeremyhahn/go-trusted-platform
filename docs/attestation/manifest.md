# Host Manifest

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `pkg/attestation/manifest` builder, signer and verifier API; [architecture.md](architecture.md) is normative.

The host manifest aggregates attestations from a host's physical TPM, VMs, and containers into a single signed document. A Merkle tree provides efficient integrity verification of all components.

## Overview

A host manifest captures the complete attestation state of a host at a point in time. It includes the physical TPM quote, vTPM quotes from all VMs, and PCR 14 chain entries from all containers. The manifest is signed by the host's Attestation Key (AK) and includes a Merkle root for integrity verification.

Package: `pkg/attestation/manifest/`

## Key Types

### HostManifest

The primary structure representing a complete host attestation.

```go
type HostManifest struct {
    ID                 string                 // Unique manifest identifier
    HostID             string                 // Host identifier from IDevID
    Timestamp          time.Time              // When manifest was generated
    Nonce              []byte                 // Anti-replay nonce
    Host               *HostAttestation       // Physical TPM attestation
    VMs                []VMAttestation        // All VM attestations
    Containers         []ContainerAttestation // All container attestations
    MerkleRoot         []byte                 // Root hash of Merkle tree
    Signature          []byte                 // AK signature over manifest
    SignatureAlgorithm string                 // Signature algorithm used
    Version            string                 // Manifest format version
    Metadata           map[string]string      // Additional metadata
}
```

### HostAttestation

Represents the physical TPM attestation from the host.

```go
type HostAttestation struct {
    QuoteData          []byte        // Raw TPM quote (TPMS_ATTEST)
    Signature          []byte        // AK signature over quote
    SignatureAlgorithm string        // Signature algorithm
    PCRs               []PCRValue    // PCR values in quote
    PCRDigest          []byte        // Hash of PCR values
    Nonce              []byte        // Anti-replay nonce
    Timestamp          time.Time     // When quote was generated
    AKPublicKey        []byte        // AK public key
    IDevIDCertificate  []byte        // Host IDevID certificate
    HashAlgorithm      HashAlgorithm // Hash algorithm used
    FirmwareVersion    string        // TPM firmware version
}
```

### VMAttestation

Represents a vTPM attestation from a VM (in manifest context).

```go
type VMAttestation struct {
    VMID               string            // VM unique identifier
    HostID             string            // Host running this VM
    QuoteData          []byte            // Raw TPM quote
    Signature          []byte            // AIK/AK signature
    SignatureAlgorithm string            // Signature algorithm
    PCRs               []PCRValue        // PCR values
    PCRDigest          []byte            // Hash of PCR values
    Nonce              []byte            // Anti-replay nonce
    Timestamp          time.Time         // When quote was generated
    AIKPublicKey       []byte            // AIK/AK public key
    EKCertificate      []byte            // vTPM EK certificate
    WorkloadPCR        []byte            // PCR 14 value
    HashAlgorithm      HashAlgorithm     // Hash algorithm
    Metadata           map[string]string // VM-specific metadata
}
```

### ContainerAttestation

Represents the PCR 14 chain attestation for a container.

```go
type ContainerAttestation struct {
    ContainerID string            // Container unique identifier
    ImageID     string            // Container image ID
    ImageDigest string            // Container image digest
    Digest      []byte            // Measurement hash
    PCRValue    []byte            // PCR 14 after extension
    Timestamp   time.Time         // When measured
    Metadata    map[string]string // Container-specific metadata
}
```

### VerificationResult

Represents the outcome of manifest verification.

```go
type VerificationResult struct {
    Status                     VerificationStatus // Overall status
    SignatureValid             bool               // Manifest signature valid
    MerkleRootValid            bool               // Merkle root matches
    NonceValid                 bool               // Nonce matches expected
    TimestampValid             bool               // Manifest not expired
    HostAttestationValid       bool               // Host attestation valid
    VMAttestationsValid        bool               // All VMs valid
    ContainerAttestationsValid bool               // All containers valid
    VerifiedAt                 time.Time          // When verified
    Errors                     []string           // Error messages
    VMErrors                   map[string]string  // Per-VM errors
    ContainerErrors            map[string]string  // Per-container errors
}
```

## Interfaces

### ManifestBuilder

Constructs host manifests from attestation components.

```go
type ManifestBuilder interface {
    // Initialize sets up the builder.
    Initialize(ctx context.Context, config *BuilderConfig) error

    // SetHostAttestation sets the host attestation.
    SetHostAttestation(ctx context.Context, attestation *HostAttestation) error

    // AddVMAttestation adds a VM attestation.
    AddVMAttestation(ctx context.Context, attestation *VMAttestation) error

    // AddContainerAttestation adds a container attestation.
    AddContainerAttestation(ctx context.Context, attestation *ContainerAttestation) error

    // Build constructs the manifest with a fresh nonce.
    Build(ctx context.Context) (*HostManifest, error)

    // BuildWithNonce constructs the manifest with a provided nonce.
    BuildWithNonce(ctx context.Context, nonce []byte) (*HostManifest, error)

    // Reset clears all attestations for a fresh build.
    Reset()

    // GetVMCount returns the number of VM attestations.
    GetVMCount() int

    // GetContainerCount returns the number of container attestations.
    GetContainerCount() int

    // Close releases resources.
    Close() error
}
```

### ManifestSigner

Signs host manifests using the TPM's AK.

```go
type ManifestSigner interface {
    // Initialize sets up the signer.
    Initialize(ctx context.Context, config *SignerConfig) error

    // Sign signs a manifest using the TPM's AK.
    Sign(ctx context.Context, manifest *HostManifest) error

    // SignWithKey signs a manifest with a provided key (for testing).
    SignWithKey(ctx context.Context, manifest *HostManifest, key crypto.Signer) error

    // VerifySignature verifies a manifest's signature.
    VerifySignature(ctx context.Context, manifest *HostManifest,
        publicKey crypto.PublicKey) (bool, error)

    // Close releases resources.
    Close() error
}
```

### ManifestVerifier

Verifies host manifests including signature and Merkle root.

```go
type ManifestVerifier interface {
    // Initialize sets up the verifier.
    Initialize(ctx context.Context, config *VerifierConfig) error

    // Verify performs complete manifest verification.
    Verify(ctx context.Context, manifest *HostManifest,
        publicKey crypto.PublicKey, expectedNonce []byte) (*VerificationResult, error)

    // VerifySignature verifies only the signature.
    VerifySignature(ctx context.Context, manifest *HostManifest,
        publicKey crypto.PublicKey) (bool, error)

    // VerifyMerkleRoot verifies the Merkle root integrity.
    VerifyMerkleRoot(ctx context.Context, manifest *HostManifest) (bool, error)

    // VerifyNonce verifies the nonce matches expected.
    VerifyNonce(manifest *HostManifest, expectedNonce []byte) bool

    // VerifyFreshness verifies the manifest has not expired.
    VerifyFreshness(manifest *HostManifest) (bool, error)

    // VerifyHostAttestation verifies the host attestation.
    VerifyHostAttestation(ctx context.Context, manifest *HostManifest,
        expectedPCRs map[int][]byte) (bool, error)

    // Close releases resources.
    Close() error
}
```

## Usage

### Building a Manifest

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"

// Create builder
builder := manifest.NewManifestBuilder(
    manifest.WithTPMDevice(tpmDevice),
    manifest.WithBuilderLogger(logger),
)

// Initialize
cfg := &manifest.BuilderConfig{
    HostID:        "host-001",
    HashAlgorithm: manifest.HashAlgorithmSHA256,
    PCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7, 14},
    NonceSize:     32,
    Version:       "1.0",
}
if err := builder.Initialize(ctx, cfg); err != nil {
    log.Fatal(err)
}
defer builder.Close()

// Set host attestation
hostAttestation := &manifest.HostAttestation{
    QuoteData:     quoteData,
    Signature:     signature,
    PCRs:          pcrValues,
    PCRDigest:     pcrDigest,
    Nonce:         nonce,
    Timestamp:     time.Now(),
    AKPublicKey:   akPubKey,
    HashAlgorithm: manifest.HashAlgorithmSHA256,
}
if err := builder.SetHostAttestation(ctx, hostAttestation); err != nil {
    log.Fatal(err)
}

// Add VM attestations
for _, vm := range vmAttestations {
    if err := builder.AddVMAttestation(ctx, vm); err != nil {
        log.Fatal(err)
    }
}

// Add container attestations
for _, container := range containerAttestations {
    if err := builder.AddContainerAttestation(ctx, container); err != nil {
        log.Fatal(err)
    }
}

// Build manifest
manifest, err := builder.Build(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Manifest ID: %s, VMs: %d, Containers: %d\n",
    manifest.ID, len(manifest.VMs), len(manifest.Containers))
```

### Signing a Manifest

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"

// Create signer
signer := manifest.NewManifestSigner(
    manifest.WithSignerTPMDevice(tpmDevice),
    manifest.WithSignerLogger(logger),
)

// Initialize
cfg := &manifest.SignerConfig{
    TPMDevicePath: "/dev/tpmrm0",
    AKHandle:      0x81010002,
    HashAlgorithm: manifest.HashAlgorithmSHA256,
}
if err := signer.Initialize(ctx, cfg); err != nil {
    log.Fatal(err)
}
defer signer.Close()

// Sign manifest
if err := signer.Sign(ctx, manifest); err != nil {
    log.Fatal(err)
}

fmt.Printf("Signed with algorithm: %s\n", manifest.SignatureAlgorithm)
```

### Verifying a Manifest

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"

// Create verifier
verifier := manifest.NewManifestVerifier(
    manifest.WithVerifierLogger(logger),
)

// Initialize
cfg := &manifest.VerifierConfig{
    PlatformCACert:         platformCACert,
    MaxManifestAge:         300, // 5 minutes
    RequireHostAttestation: true,
    VerifyMerkleRoot:       true,
    HashAlgorithm:          manifest.HashAlgorithmSHA256,
}
if err := verifier.Initialize(ctx, cfg); err != nil {
    log.Fatal(err)
}
defer verifier.Close()

// Verify manifest
result, err := verifier.Verify(ctx, manifest, akPublicKey, expectedNonce)
if err != nil {
    log.Fatal(err)
}

if result.Status == manifest.VerificationStatusVerified {
    fmt.Println("Manifest verified successfully")
} else {
    fmt.Println("Verification failed:")
    for _, e := range result.Errors {
        fmt.Printf("  - %s\n", e)
    }
}
```

### Quick Verification

```go
// Perform quick verification without full initialization
valid, err := manifest.QuickVerify(mfst, publicKey, expectedNonce, manifest.HashAlgorithmSHA256)
if err != nil {
    log.Fatal(err)
}
if valid {
    fmt.Println("Quick verification passed")
}
```

## Merkle Tree Structure

The Merkle tree provides integrity verification with O(log n) proof size:

```
                    Merkle Root
                   /           \
              Hash(L0+L1)    Hash(L2+L3)
             /         \          |
         Host         VM1        Container1
         Hash         Hash         Hash
```

Leaf construction:
- Host: `SHA256(QuoteData || PCRDigest)`
- VM: `SHA256(QuoteData || PCRDigest)`
- Container: `SHA256(Digest || PCRValue)`

Utility functions for Merkle operations:

```go
// Compute Merkle root from leaves
root := manifest.ComputeMerkleRoot(leaves, manifest.HashAlgorithmSHA256)

// Recompute and validate Merkle root
valid, err := manifest.ValidateMerkleRoot(mfst, manifest.HashAlgorithmSHA256)
```

## Signature Algorithms

| Algorithm | Hash | Description |
|-----------|------|-------------|
| RSASSA-PKCS1-v1_5-SHA256 | SHA-256 | Default for TPM 2.0 |
| RSASSA-PKCS1-v1_5-SHA384 | SHA-384 | Stronger hash |
| RSASSA-PKCS1-v1_5-SHA512 | SHA-512 | Maximum security |

## Configuration

### BuilderConfig

```go
type BuilderConfig struct {
    HostID        string        // Host identifier
    HashAlgorithm HashAlgorithm // Hash algorithm for Merkle tree
    PCRIndices    []int         // PCRs to include in host attestation
    NonceSize     int           // Size of generated nonces (min 16)
    Version       string        // Manifest format version
}
```

### SignerConfig

```go
type SignerConfig struct {
    TPMDevicePath string        // Path to TPM device
    AKHandle      uint32        // TPM handle for AK
    HashAlgorithm HashAlgorithm // Hash algorithm for signing
}
```

### VerifierConfig

```go
type VerifierConfig struct {
    PlatformCACert         *x509.Certificate   // Platform CA certificate
    TrustedRoots           []*x509.Certificate // Additional trusted roots
    MaxManifestAge         int64               // Max age in seconds (0 = no limit)
    RequireHostAttestation bool                // Require valid host attestation
    VerifyMerkleRoot       bool                // Verify Merkle root
    HashAlgorithm          HashAlgorithm       // Hash algorithm
}
```

### Default Configuration

```go
cfg := manifest.DefaultManifestConfig()
// Returns:
// - DefaultHashAlgorithm: sha256
// - DefaultPCRIndices: [0, 1, 2, 3, 4, 5, 6, 7, 14]
// - MaxManifestAge: 300 (5 minutes)
// - NonceSize: 32
// - IncludeWorkloadPCR: true
// - Version: "1.0"
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrBuilderNotInitialized` | Builder not initialized |
| `ErrSignerNotInitialized` | Signer not initialized |
| `ErrVerifierNotInitialized` | Verifier not initialized |
| `ErrInvalidManifest` | Manifest validation failed |
| `ErrInvalidConfig` | Configuration validation failed |
| `ErrHostNotAttested` | Host attestation not set |
| `ErrEmptyManifest` | No attestations in manifest |
| `ErrManifestBuildFailed` | Failed to build manifest |
| `ErrManifestSignFailed` | Failed to sign manifest |
| `ErrManifestVerifyFailed` | Verification failed |
| `ErrManifestExpired` | Manifest has expired |
| `ErrMerkleRootMismatch` | Merkle root does not match |
| `ErrNonceMismatch` | Nonce does not match |
| `ErrSignatureInvalid` | Signature verification failed |
| `ErrTPMNotAvailable` | TPM device not accessible |
| `ErrAKNotFound` | AK not found in TPM |
| `ErrContextCanceled` | Operation canceled |

## Related Documentation

- [Workload Attestation](workload-attestation.md) - PCR 14 container chain
- [VM Attestation](vm-attestation.md) - vTPM quote generation
- [Push](push.md) - Distributing manifests
- [API Reference](api.md) - REST/gRPC APIs

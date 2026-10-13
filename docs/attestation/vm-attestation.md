# VM Attestation

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `pkg/attestation/vm` attestor and verifier API; [architecture.md](architecture.md) is normative.

VM attestation extends the platform's hardware root of trust into virtual machines using vTPM (virtual TPM) technology. Each VM receives a vTPM with an EK certificate that cryptographically binds it to its host.

## Overview

The VM attestation system enables virtual machines to generate TPM quotes that can be verified by remote parties. The vTPM EK certificate contains the VM-to-host binding in its subject Common Name, enabling verification that a VM is running on an authorized host.

Package: `pkg/attestation/vm/`

## Key Types

### HashAlgorithm

Represents cryptographic hash algorithms used for TPM operations.

```go
type HashAlgorithm string

const (
    HashAlgorithmSHA1   HashAlgorithm = "sha1"
    HashAlgorithmSHA256 HashAlgorithm = "sha256"
    HashAlgorithmSHA384 HashAlgorithm = "sha384"
    HashAlgorithmSHA512 HashAlgorithm = "sha512"
)
```

### VMIdentity

Represents the identity of a VM, linking it to its host.

```go
type VMIdentity struct {
    VMID               string              // Unique identifier for the VM
    HostID             string              // Host identifier running the VM
    EKCertificate      *x509.Certificate   // vTPM EK certificate
    EKCertificateChain []*x509.Certificate // Intermediate certificates
}
```

The identity is encoded in the EK certificate subject CN with format: `vm:<vmID>@host:<hostID>`

### VMQuote

Represents a TPM quote from a VM's vTPM.

```go
type VMQuote struct {
    QuoteData          []byte        // Raw TPM quote structure (TPMS_ATTEST)
    Signature          []byte        // AIK/AK signature over quote data
    SignatureAlgorithm string        // Algorithm used for signing
    PCRs               []PCRValue    // PCR values included in quote
    PCRDigest          []byte        // Hash of PCR values
    Nonce              []byte        // Anti-replay nonce
    Timestamp          time.Time     // When quote was generated
    AIKPublicKey       []byte        // Public key of AIK/AK
    HashAlgorithm      HashAlgorithm // Hash algorithm used
}
```

### VMAttestation

Represents the full attestation result for a VM.

```go
type VMAttestation struct {
    Identity           *VMIdentity         // VM identity information
    Quote              *VMQuote            // TPM quote from vTPM
    VerificationResult *VerificationResult // Verification outcome
    Timestamp          time.Time           // When attestation was performed
    AttestationID      string              // Unique identifier
    WorkloadPCR        []byte              // WorkloadPCR value (workload chain, default: PCR 14)
    Metadata           map[string]string   // Additional metadata
}
```

### VerificationResult

Represents the outcome of quote verification.

```go
type VerificationResult struct {
    Status                VerificationStatus  // Overall status
    SignatureValid        bool                // Quote signature validity
    CertificateChainValid bool                // EK certificate chain validity
    PCRsValid             bool                // PCR values match expected
    NonceValid            bool                // Nonce matches expected
    HostBindingValid      bool                // VM-to-host binding valid
    TimestampValid        bool                // Quote timestamp within range
    VerifiedAt            time.Time           // When verification performed
    Errors                []string            // Errors encountered
    PCRMismatches         []PCRMismatchDetail // PCR mismatch details
}
```

## Interfaces

### VMAttestor

Generates TPM quotes and attestations using the vTPM.

```go
type VMAttestor interface {
    // Initialize sets up the attestor with configuration.
    Initialize(ctx context.Context, config *AttestorConfig) error

    // GenerateQuote generates a TPM quote using the vTPM's AIK/AK.
    GenerateQuote(ctx context.Context, request *QuoteRequest) (*VMQuote, error)

    // GetIdentity returns the VM identity from the vTPM EK certificate.
    GetIdentity(ctx context.Context) (*VMIdentity, error)

    // GetAttestation generates a full attestation including quote and identity.
    GetAttestation(ctx context.Context, request *QuoteRequest) (*VMAttestation, error)

    // ReadPCR reads a single PCR value from the vTPM.
    ReadPCR(ctx context.Context, index int, algorithm HashAlgorithm) (*PCRValue, error)

    // Close releases resources.
    Close() error
}
```

### VMVerifier

Verifies TPM quotes from VMs.

```go
type VMVerifier interface {
    // Initialize sets up the verifier with configuration.
    Initialize(ctx context.Context, config *VerifierConfig) error

    // VerifyQuote verifies a TPM quote and returns the result.
    VerifyQuote(ctx context.Context, request *VerifyRequest) (*VerificationResult, error)

    // VerifyAttestation verifies a complete VM attestation.
    VerifyAttestation(ctx context.Context, attestation *VMAttestation,
        expectedPCRs map[int][]byte, expectedNonce []byte) (*VerificationResult, error)

    // VerifyEKCertificate verifies the EK certificate chain.
    VerifyEKCertificate(ctx context.Context, identity *VMIdentity) error

    // Close releases resources.
    Close() error
}
```

## Usage

### Generating Attestations

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"

// Create attestor with vTPM device
attestor := vm.NewVMAttestor(
    vm.WithVTPMDevice(vtpmDevice),
    vm.WithAttestorLogger(logger),
)

// Initialize
cfg := &vm.AttestorConfig{
    VTPMDevicePath:       "/dev/tpmrm0",
    DefaultHashAlgorithm: vm.HashAlgorithmSHA256,
    DefaultPCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7},
    IncludeWorkloadPCR:   true,
}
if err := attestor.Initialize(ctx, cfg); err != nil {
    log.Fatal(err)
}
defer attestor.Close()

// Generate quote request
request := &vm.QuoteRequest{
    Nonce:         nonce,
    PCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7, 14},
    HashAlgorithm: vm.HashAlgorithmSHA256,
}

// Get full attestation
attestation, err := attestor.GetAttestation(ctx, request)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("VM: %s on Host: %s\n", attestation.Identity.VMID, attestation.Identity.HostID)
```

### Verifying Attestations

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"

// Create verifier
verifier := vm.NewVMVerifier(
    vm.WithVerifierLogger(logger),
)

// Initialize with Platform CA
cfg := &vm.VerifierConfig{
    PlatformCACert:     platformCACert,
    MaxQuoteAge:        300, // 5 minutes
    RequireHostBinding: true,
    AllowedHostIDs:     []string{"host-1", "host-2"},
}
if err := verifier.Initialize(ctx, cfg); err != nil {
    log.Fatal(err)
}
defer verifier.Close()

// Verify attestation
expectedPCRs := map[int][]byte{
    0: goldenPCR0,
    7: goldenPCR7,
}
result, err := verifier.VerifyAttestation(ctx, attestation, expectedPCRs, originalNonce)
if err != nil {
    log.Fatal(err)
}

if result.Status == vm.VerificationStatusVerified {
    fmt.Println("Attestation verified successfully")
} else {
    fmt.Println("Verification failed:", result.Errors)
}
```

### Parsing VM Identity

```go
// Parse identity from certificate CN
cn := "vm:vm-123@host:host-456"
identity, err := vm.ParseCN(cn)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("VMID: %s, HostID: %s\n", identity.VMID, identity.HostID)

// Format identity as CN
formatted := identity.FormatCN()
// Returns: "vm:vm-123@host:host-456"
```

## EK Certificate Chain

The vTPM EK certificate chain enables verification of VM identity:

```
Platform CA (Root)
    |
    +-- Host EK Certificate (bound to physical TPM)
        |
        +-- vTPM EK Certificate (bound to VM and host)
```

The vTPM EK certificate contains:
- Subject CN: `vm:<vmID>@host:<hostID>`
- Issuer: Platform CA or intermediate
- Extensions: TPM-specific OIDs

## Verification Checks

| Check | Description |
|-------|-------------|
| Signature | AIK/AK signature over quote data is valid |
| Certificate Chain | EK certificate chains to Platform CA |
| Nonce | Anti-replay nonce matches expected value |
| PCRs | PCR values match expected golden values |
| Host Binding | VM is running on an authorized host |
| Timestamp | Quote is within acceptable age |

## Configuration

### AttestorConfig

```go
type AttestorConfig struct {
    VTPMDevicePath       string        // Path to vTPM device
    AIKHandle            uint32        // TPM handle for AIK/AK
    DefaultHashAlgorithm HashAlgorithm // Default hash algorithm
    DefaultPCRIndices    []int         // Default PCRs to include
    IncludeWorkloadPCR   bool          // Include WorkloadPCR (default: 14)
}
```

### VerifierConfig

```go
type VerifierConfig struct {
    PlatformCACert     *x509.Certificate   // Platform CA certificate
    TrustedRoots       []*x509.Certificate // Additional trusted roots
    MaxQuoteAge        int64               // Maximum quote age in seconds
    RequireHostBinding bool                // Require host binding validation
    AllowedHostIDs     []string            // Allowed host IDs (empty = all)
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrVTPMNotAvailable` | vTPM device not accessible |
| `ErrAIKNotFound` | AIK/AK not found in vTPM |
| `ErrAttestorNotInitialized` | Attestor not initialized |
| `ErrVerifierNotInitialized` | Verifier not initialized |
| `ErrQuoteGenerationFailed` | Failed to generate TPM quote |
| `ErrQuoteVerificationFailed` | Quote verification failed |
| `ErrEKCertificateInvalid` | EK certificate is invalid |
| `ErrCertificateChainInvalid` | Certificate chain validation failed |
| `ErrSignatureInvalid` | Quote signature is invalid |
| `ErrHostBindingInvalid` | Host binding check failed |
| `ErrInvalidVMIdentity` | Invalid VM identity format |
| `ErrPCRReadFailed` | Failed to read PCR value |
| `ErrContextCanceled` | Operation canceled via context |

## Related Documentation

- [Workload Attestation](workload-attestation.md) - WorkloadPCR workload chain
- [Manifest](manifest.md) - Aggregating attestations
- [API Reference](api-reference.md) - REST/gRPC APIs

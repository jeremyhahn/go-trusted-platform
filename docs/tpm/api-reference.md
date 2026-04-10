# TPM API Reference

The TPM service exposes physical Trusted Platform Module operations via multiple protocols for maximum interoperability.

## Supported Protocols

| Protocol | Transport | Port/Path | Use Case |
|----------|-----------|-----------|----------|
| [REST](api-reference-rest.md) | HTTPS | 8443 | Web clients, external systems |
| [gRPC](api-reference-grpc.md) | TCP | 9443 | High-performance service-to-service |
| [QUIC](api-reference-quic.md) | UDP | 9444 | Low-latency, mobile clients |
| [MCP](api-reference-mcp.md) | stdio/HTTP | 9445 | AI/LLM integration |
| [Unix Socket](api-reference-unix.md) | Unix | /run/platformd.sock | Local IPC, CLI |

## Service Interface

```go
type TPMService interface {
    // Device information
    Info(ctx context.Context) (*TPMInfo, error)

    // Provisioning
    Provision(ctx context.Context, ownerPassword string) error
    Clear(ctx context.Context, ownerPassword string) error

    // Endorsement Key operations
    GetEK(ctx context.Context) (*TPMKey, error)
    CreateEK(ctx context.Context, opts *KeyAttributes) (*TPMKey, error)
    DeleteEK(ctx context.Context) error
    GetEKCertificate(ctx context.Context) ([]byte, error)
    ImportEKCertificate(ctx context.Context, cert []byte) error

    // Storage Root Key operations
    GetSRK(ctx context.Context) (*TPMKey, error)
    CreateSRK(ctx context.Context, opts *KeyAttributes) (*TPMKey, error)
    DeleteSRK(ctx context.Context) error

    // Initial Attestation Key operations
    GetIAK(ctx context.Context) (*TPMKey, error)
    CreateIAK(ctx context.Context, opts *KeyAttributes) (*TPMKey, error)
    DeleteIAK(ctx context.Context) error
    GetIDevID(ctx context.Context) ([]byte, error)

    // Attestation operations
    Quote(ctx context.Context, opts *QuoteOptions) (*Quote, error)
    VerifyQuote(ctx context.Context, quote *Quote) (bool, error)
    Certify(ctx context.Context, handle uint32, nonce []byte) (*CertifyResponse, error)
    GetEventLog(ctx context.Context, format string) ([]byte, error)

    // PCR operations
    ReadPCRs(ctx context.Context, indices []uint32) ([]*PCRValue, error)
    ExtendPCR(ctx context.Context, index uint32, data []byte) error

    // Seal/Unseal operations
    Seal(ctx context.Context, opts *SealOptions) (*SealResponse, error)
    Unseal(ctx context.Context, opts *UnsealOptions) ([]byte, error)

    // NVRAM operations
    DefineNVRAM(ctx context.Context, index uint32, size uint32) error
    WriteNVRAM(ctx context.Context, index uint32, data []byte) error
    ReadNVRAM(ctx context.Context, index uint32, size uint32) ([]byte, error)
    UndefineNVRAM(ctx context.Context, index uint32) error

    // Random number generation
    GetRandom(ctx context.Context, numBytes uint32) ([]byte, error)

    // Key and certificate generation
    CreateIDevIDCSR(ctx context.Context) ([]byte, error)
    CreateLDevIDCSR(ctx context.Context) ([]byte, error)

    // Platform attributes
    GetPlatformAttributes(ctx context.Context) (map[string]string, error)
}
```

## Operations Summary

| Operation | Description |
|-----------|-------------|
| Info | Get TPM device information and capabilities |
| Provision | Initialize TPM with owner authorization |
| Clear | Clear TPM state and reset owner authorization |
| GetEK | Retrieve Endorsement Key |
| CreateEK | Create a new Endorsement Key |
| DeleteEK | Flush Endorsement Key handle |
| GetEKCertificate | Retrieve manufacturer or CA-issued EK certificate |
| ImportEKCertificate | Import EK certificate into TPM NV storage |
| GetSRK | Retrieve Storage Root Key |
| CreateSRK | Create Storage Root Key hierarchy |
| DeleteSRK | Flush Storage Root Key handle |
| GetIAK | Retrieve Initial Attestation Key |
| CreateIAK | Create Initial Attestation Key |
| DeleteIAK | Flush Attestation Key handle |
| GetIDevID | Get Initial Device Identifier certificate |
| Quote | Generate attestation quote over PCRs |
| VerifyQuote | Verify attestation quote signature |
| Certify | Certify key or object |
| GetEventLog | Retrieve TPM event log |
| ReadPCRs | Read Platform Configuration Register values |
| ExtendPCR | Extend PCR with measurement data |
| Seal | Seal data with optional PCR policy |
| Unseal | Unseal TPM-sealed data |
| DefineNVRAM | Create NVRAM index |
| WriteNVRAM | Write data to NVRAM |
| ReadNVRAM | Read data from NVRAM |
| UndefineNVRAM | Delete NVRAM index |
| GetRandom | Get random bytes from TPM RNG |
| CreateIDevIDCSR | Generate Initial DevID Certificate Signing Request |
| CreateLDevIDCSR | Generate Local DevID Certificate Signing Request |
| GetPlatformAttributes | Retrieve platform attributes |

## Data Types

### TPMInfo

```go
type TPMInfo struct {
    Version              string
    Manufacturer         *TPMManufacturer
    Capabilities         []TPMCapability
    PCRBanks             []string
    MaxNVRAMSize         uint32
    IsSimulator          bool
    FIPSMode             bool
    Properties           map[string]string
}
```

### TPMManufacturer

```go
type TPMManufacturer struct {
    Name             string
    ID               uint32
    Model            string
    FirmwareVersion  string
}
```

### KeyAlgorithm

```go
type KeyAlgorithm string

const (
    KeyAlgorithmRSA2048    KeyAlgorithm = "RSA_2048"
    KeyAlgorithmRSA3072    KeyAlgorithm = "RSA_3072"
    KeyAlgorithmRSA4096    KeyAlgorithm = "RSA_4096"
    KeyAlgorithmECDSAP256  KeyAlgorithm = "ECDSA_P256"
    KeyAlgorithmECDSAP384  KeyAlgorithm = "ECDSA_P384"
    KeyAlgorithmECDSAP521  KeyAlgorithm = "ECDSA_P521"
    KeyAlgorithmEd25519    KeyAlgorithm = "ED25519"
)
```

### TPMKey

```go
type TPMKey struct {
    Handle    uint32
    PublicKey []byte        // TPM2B_PUBLIC marshaled
    Algorithm KeyAlgorithm
}
```

### PCRBank

```go
type PCRBank string

const (
    PCRBankSHA1    PCRBank = "SHA1"
    PCRBankSHA256  PCRBank = "SHA256"
    PCRBankSHA384  PCRBank = "SHA384"
    PCRBankSHA512  PCRBank = "SHA512"
)
```

### Quote

```go
type Quote struct {
    Attestation []byte    // TPMS_ATTEST structure
    Signature   []byte    // Signature over attestation
    PCRValues   []*PCRValue
    EventLog    []byte
}
```

### PCRValue

```go
type PCRValue struct {
    Index uint32
    Bank  PCRBank
    Value []byte
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrTPMServiceUnavailable` | TPM service not configured or unavailable |
| `ErrNotFound` | Key or object not found |
| `ErrAlreadyExists` | Object already exists |
| `ErrInvalidArgument` | Invalid parameter |
| `ErrPermissionDenied` | Authorization failed |
| `ErrFailedPrecondition` | PCR mismatch or TPM not ready |
| `ErrInternal` | TPM internal error |

## Service Initialization

The TPM service is integrated into the platform daemon. Access it through any of the supported protocols.

### Unix Socket (Local IPC)

```go
import "google.golang.org/grpc"

conn, err := grpc.Dial(
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewTPMServiceClient(conn)
```

### gRPC (TCP)

```go
import "google.golang.org/grpc/credentials"

creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
if err != nil {
    return err
}

conn, err := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewTPMServiceClient(conn)
```

### REST (HTTPS)

```bash
curl -X GET https://localhost:8443/api/v1/tpm/info
```

### QUIC (UDP)

```go
import "github.com/quic-go/quic-go"

// Load platform CA certificate for TLS verification
caCert, _ := os.ReadFile("/path/to/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    RootCAs:    caCertPool,
}

conn, err := quic.DialAddr(ctx, "localhost:9444", tlsConfig, nil)
if err != nil {
    return err
}
defer conn.CloseWithError(0, "done")
```

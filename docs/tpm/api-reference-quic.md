# TPM QUIC API Reference

Port: `9444` (UDP)
Protocol: QUIC with TLS 1.3

## Protocol Overview

The QUIC protocol uses a binary frame format with MessagePack encoding for low-latency TPM operations.

### Frame Format

**Request:**
```
+--------+------------+-------------+---------+
| Opcode | Token Len  | Token       | Payload |
| 1 byte | 2 bytes    | variable    | variable|
+--------+------------+-------------+---------+
```

**Response:**
```
+--------+-------------+---------+
| Status | Payload Len | Payload |
| 1 byte | 4 bytes     | variable|
+--------+-------------+---------+
```

## Category Opcode (0x27 - TPM2Category)

TPM operations use a category opcode (0x27) with a sub-opcode in the first byte of the payload.

## Sub-Operation Codes

### Device Information and Management

| SubOp | Name | Description |
|-------|------|-------------|
| `0x01` | Info | Get TPM device information |
| `0x02` | Provision | Provision TPM with owner auth |
| `0x03` | Clear | Clear TPM state |
| `0x17` | Capabilities | Get TPM capabilities |

### Endorsement Key Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x04` | GetEK | Retrieve Endorsement Key |
| `0x05` | CreateEK | Create Endorsement Key |
| `0x06` | DeleteEK | Delete Endorsement Key |
| `0x07` | GetEKCert | Get EK certificate |
| `0x08` | ImportEKCert | Import EK certificate |

### Storage Root Key Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x09` | GetSRK | Retrieve Storage Root Key |
| `0x0A` | CreateSRK | Create Storage Root Key |
| `0x0B` | DeleteSRK | Delete Storage Root Key |

### Initial Attestation Key Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x0C` | GetIAK | Retrieve Initial Attestation Key |
| `0x0D` | CreateIAK | Create Initial Attestation Key |
| `0x0E` | DeleteIAK | Delete Initial Attestation Key |
| `0x1F` | GetIDevID | Get Initial Device ID |

### Attestation Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x0F` | Quote | Generate quote over PCRs |
| `0x10` | VerifyQuote | Verify quote signature |
| `0x13` | EventLog | Get TPM event log |

### PCR Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x11` | ReadPCRs | Read PCR values |
| `0x12` | ExtendPCR | Extend PCR with data |

### Seal/Unseal Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x15` | Seal | Seal data to TPM |
| `0x16` | Unseal | Unseal TPM-sealed data |

### NVRAM Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x18` | NVRead | Read NVRAM index |
| `0x19` | NVWrite | Write NVRAM index |
| `0x1A` | NVDelete | Delete NVRAM index |
| `0x1B` | NVList | List NVRAM indices |

### Device Identifier Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x1C` | IDevIDCSR | Create Initial DevID CSR |
| `0x1D` | LDevIDCSR | Create Local DevID CSR |

### Platform Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x1E` | PlatformAttrs | Get platform attributes |

## Status Codes

| Code | Name | Description |
|------|------|-------------|
| `0x00` | OK | Success |
| `0x01` | InvalidRequest | Invalid request format |
| `0x02` | NotFound | Resource not found |
| `0x04` | InternalError | Server error |

## Payload Encoding

All payloads use MessagePack encoding with `codec` struct tags.

### Info (0x01)

**Request Payload:**
```messagepack
{}
```

**Response Payload:**
```go
type TPM2InfoResponse struct {
    Info         string            `codec:"info"`
    Version      string            `codec:"version"`
    Manufacturer string            `codec:"manufacturer"`
    Model        string            `codec:"model"`
    FWVersion    string            `codec:"fw_version"`
    IsSimulator  bool              `codec:"is_simulator"`
    FIPSMode     bool              `codec:"fips_mode"`
    MaxNVRAMSize uint32            `codec:"max_nvram_size"`
    Properties   map[string]string `codec:"properties"`
    Timestamp    int64             `codec:"timestamp"`
}
```

### Provision (0x02)

**Request Payload:**
```go
type TPM2ProvisionRequest struct {
    OwnerPassword string `codec:"owner_password"`
}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### Clear (0x03)

**Request Payload:**
```go
type TPM2ClearRequest struct {
    OwnerPassword string `codec:"owner_password"`
}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### GetEK (0x04)

**Request Payload:**
```messagepack
{}
```

**Response Payload:**
```go
type TPM2KeyResponse struct {
    Handle    uint32 `codec:"handle"`
    PublicKey []byte `codec:"public_key"`
    Algorithm string `codec:"algorithm"`
    Timestamp int64  `codec:"timestamp"`
}
```

### CreateEK (0x05)

**Request Payload:**
```messagepack
{}
```

**Response Payload:**
```go
type TPM2KeyResponse struct {
    Handle    uint32 `codec:"handle"`
    PublicKey []byte `codec:"public_key"`
    Algorithm string `codec:"algorithm"`
    Timestamp int64  `codec:"timestamp"`
}
```

### DeleteEK (0x06)

**Request Payload:**
```messagepack
{}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### GetEKCert (0x07)

**Request Payload:**
```messagepack
{}
```

**Response Payload:**
```go
type TPM2CertificateResponse struct {
    Certificate []byte `codec:"certificate"`
    Timestamp   int64  `codec:"timestamp"`
}
```

### ImportEKCert (0x08)

**Request Payload:**
```go
type TPM2ImportEKCertRequest struct {
    Certificate []byte `codec:"certificate"`
}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### Quote (0x0F)

**Request Payload:**
```go
type TPM2QuoteRequest struct {
    PCRIndices []uint32 `codec:"pcr_indices"`
    Nonce      []byte   `codec:"nonce"`
}
```

**Response Payload:**
```go
type TPM2QuoteResponse struct {
    Quote              []byte `codec:"quote"`
    Signature          []byte `codec:"signature"`
    SignatureAlgorithm string `codec:"signature_algorithm"`
    EventLog           []byte `codec:"event_log"`
    Timestamp          int64  `codec:"timestamp"`
}
```

`TPM2VerifyQuoteRequest` (0x10) carries `signature_algorithm` back; the
signature is checked under it and fails without it.

### ReadPCRs (0x11)

**Request Payload:**
```go
type TPM2ReadPCRsRequest struct {
    Indices []uint32 `codec:"indices"`
}
```

**Response Payload:**
```go
type TPM2ReadPCRsResponse struct {
    PCRValues []map[string]interface{} `codec:"pcr_values"`
    Timestamp int64                    `codec:"timestamp"`
}
```

### ExtendPCR (0x12)

**Request Payload:**
```go
type TPM2ExtendPCRRequest struct {
    Index  uint32 `codec:"index"`
    Data   []byte `codec:"data"`
    HashAlg string `codec:"hash_alg"`
}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### Seal (0x15)

**Request Payload:**
```go
type TPM2SealRequest struct {
    Data    []byte   `codec:"data"`
    CN      string   `codec:"cn"`
    Password string  `codec:"password"`
    PCRs    []uint32 `codec:"pcr_indices"`
}
```

**Response Payload:**
```go
type TPM2SealResponse struct {
    SealedData []byte `codec:"sealed_data"`
    PublicKey  []byte `codec:"public_key"`
    PrivateKey []byte `codec:"private_key"`
    Timestamp  int64  `codec:"timestamp"`
}
```

### Unseal (0x16)

**Request Payload:**
```go
type TPM2UnsealRequest struct {
    CN       string `codec:"cn"`
    Password string `codec:"password"`
}
```

**Response Payload:**
```go
type TPM2UnsealResponse struct {
    Data      []byte `codec:"data"`
    Timestamp int64  `codec:"timestamp"`
}
```

### NVRead (0x18)

**Request Payload:**
```go
type TPM2NVReadRequest struct {
    Index    uint32 `codec:"index"`
    DataSize uint16 `codec:"data_size"`
}
```

**Response Payload:**
```go
type TPM2NVReadResponse struct {
    Data      []byte `codec:"data"`
    Timestamp int64  `codec:"timestamp"`
}
```

### NVWrite (0x19)

**Request Payload:**
```go
type TPM2NVWriteRequest struct {
    Index    uint32 `codec:"index"`
    Data     []byte `codec:"data"`
    Password string `codec:"password"`
    Offset   uint32 `codec:"offset"`
}
```

**Response Payload:**
```go
type TPM2StatusResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

## Connection Example

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

// Load platform CA certificate for TLS verification
caCert, _ := os.ReadFile("/path/to/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    RootCAs:    caCertPool,
    NextProtos: []string{"tpm-quic"},
}

quicConfig := &quic.Config{
    MaxIdleTimeout: 60 * time.Second,
}

conn, err := quic.DialAddr(ctx, "localhost:9444", tlsConfig, quicConfig)
if err != nil {
    return err
}
defer conn.CloseWithError(0, "done")

stream, err := conn.OpenStreamSync(ctx)
if err != nil {
    return err
}
defer stream.Close()

// Send TPM Info request (category 0x27, sub-opcode 0x01)
opcode := byte(0x27)
subOpcode := byte(0x01)
payload := []byte{subOpcode}
request := append([]byte{opcode, 0, 0}, payload...)

stream.Write(request)

// Read response
status := make([]byte, 1)
stream.Read(status)

lenBuf := make([]byte, 4)
stream.Read(lenBuf)

respLen := binary.BigEndian.Uint32(lenBuf)
respPayload := make([]byte, respLen)
stream.Read(respPayload)
```

## Protocol Constants

```go
const (
    // Max payload size: 16MB
    MaxQUICPayloadSizeTPM uint32 = 16 * 1024 * 1024

    // Max token size: 8KB
    MaxQUICTokenSizeTPM uint16 = 8 * 1024

    // Default timeout
    DefaultQUICTimeoutTPM = 30 * time.Second

    // Category opcode for TPM2
    OpTPM2Category byte = 0x27
)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TPM_QUIC_ENDPOINT` | QUIC server address | `localhost:9444` |

## Notes

- All timestamps are Unix epoch in milliseconds
- Binary data is encoded as byte arrays in MessagePack
- Codec struct tags are required for proper serialization/deserialization
- MessagePack encoding uses the latest protocol version

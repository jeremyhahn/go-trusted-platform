# TPM QUIC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The TPM opcodes of the platform QUIC protocol. The cross-transport contract
> is [api.md](api.md).

Port: `9444` (UDP)
Protocol: QUIC with TLS 1.3

## Protocol Overview

The QUIC protocol uses a binary frame format with MessagePack encoding for low-latency TPM operations.

### Frame Format

**Request:**
```
+--------+-----------+----------+-------------+---------+
| Opcode | Token Len | Token    | Payload Len | Payload |
| 1 byte | 2 bytes   | variable | 4 bytes     | variable|
+--------+-----------+----------+-------------+---------+
```

Lengths are big-endian (`quicwire.WriteRequest`, `ReadResponse`). An error
response carries the error text as its payload.

**Response:**
```
+--------+-------------+---------+
| Status | Payload Len | Payload |
| 1 byte | 4 bytes     | variable|
+--------+-------------+---------+
```

## Category Opcode (0x99 - TPM2Category)

TPM operations use a category opcode (`OpTPM2Category`, 0x99) with a sub-opcode
in the first byte of the payload (`sdk/go/wire/quicwire/tpm_opcodes.go`). An
unknown sub-opcode is `0x0B` NotImplemented; a daemon without a TPM answers
`0x0A` Unavailable.

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
| `0x09` | GetSRK | Retrieve a Storage Root Key: optional `handle`, the SSRK by default or the PlatformSRK |
| `0x0A` | CreateSRK | Create Storage Root Key |
| `0x0B` | DeleteSRK | Delete Storage Root Key |

### Initial Attestation Key Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x0C` | GetIAK | Retrieve Initial Attestation Key |
| `0x0D` | CreateIAK | Create Initial Attestation Key |
| `0x0E` | DeleteIAK | Refused with `StatusFailedPrecondition` (`0x0C`), as `OpIAKDelete` (`0x5E`): the IAK is not deleted ([api.md](api.md) §8) |
| `0x1F` | GetIDevID | Get Initial Device ID |

### Attestation Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x0F` | Quote | Generate quote over PCRs |
| `0x10` | VerifyQuote | Verify quote signature |
| `0x13` | EventLog | Get TPM event log |
| `0x20` | MakeCred | Create a TPM2_MakeCredential challenge |
| `0x21` | ActivateCred | Activate a challenge and recover the wrapped secret |
| `0x22` | Certify | IAK certifies a persistent key (`TPM2CertifyRequest` → `TPM2CertifyResponse`) |

### PCR Operations

| SubOp | Name | Description |
|-------|------|-------------|
| `0x11` | ReadPCRs | Read PCR values |
| `0x12` | ExtendPCR | Extend PCR with data |

### Random

| SubOp | Name | Description |
|-------|------|-------------|
| `0x14` | Random | Random bytes from the TPM (`num_bytes`) |

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

## Device Identity Key Delete

The IDevID service has top-level opcodes of its own. Two of them are refused
until the owner rules on eviction:

| Opcode | Name | Answer |
|--------|------|--------|
| `0x58` | IDevIDDelete | `0x0C` FailedPrecondition; nothing is changed |
| `0x5E` | IAKDelete | `0x0C` FailedPrecondition; nothing is changed |

The key is TPM-resident and is not evicted; the refusal deletes no key, no
certificate and no state, as on every other transport (#304). The
certificates have their own opcodes, `0x7A` IDevIDDeleteCert and `0x7B`
IAKDeleteCert, which do delete and answer in gRPC's classes (#704): no TPM is
`0x0C` FailedPrecondition, a missing certificate NotFound, and no IDevID
service wired `Unavailable` (api.md §8).

## Status Codes

| Code | Name | Description |
|------|------|-------------|
| `0x00` | OK | Success |
| `0x01` | InvalidRequest | Invalid request format |
| `0x02` | NotFound | Resource not found |
| `0x03` | Unauthorized | Missing or rejected token |
| `0x04` | InternalError | Server error |
| `0x05` | Timeout | Request timed out |
| `0x06` | AlreadyExists | Resource already exists |
| `0x07` | PermissionDenied | Scope missing |
| `0x08` | ResourceExhausted | Limit reached |
| `0x09` | InvalidArgument | Invalid request field |
| `0x0A` | Unavailable | The daemon has no TPM |
| `0x0B` | NotImplemented | Unknown sub-opcode |
| `0x0C` | FailedPrecondition | The gRPC class `FailedPrecondition`: the operation is refused in the current state |

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
    PCRBanks     []string          `codec:"pcr_banks"` // "sha1", "sha256", ...; empty when the PCR read fails
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

`owner_password` is passed to the TPM as the lockout authorization.

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

The EK is created from the configured EK attributes and persisted at the
configured EK handle. An occupied EK handle is refused with
`StatusAlreadyExists` (0x06); EK attributes that carry no creation template
are refused with `StatusInvalidRequest` (0x01, gRPC `FailedPrecondition`).

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

The configured EK handle is flushed.

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
    ChannelBinding     []byte `codec:"channel_binding"`
    Timestamp          int64  `codec:"timestamp"`
}
```

The TPM quotes SHA-256(nonce || channel_binding), where `channel_binding` is
the TLS exporter of the connection (#482). The types are in
`sdk/go/wire/quicwire/tpm_quote.go`.

`TPM2VerifyQuoteRequest` (0x10) carries `quote`, `signature`, `nonce`,
`ak_public` (empty: the node's IAK), `channel_binding` and
`signature_algorithm`; the signature is checked under `signature_algorithm`
and fails without it.

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
    PCRValues []*TPM2PCRValue `codec:"pcr_values"`
    Timestamp int64           `codec:"timestamp"`
}

type TPM2PCRValue struct {
    Index     uint32 `codec:"index"`
    Bank      string `codec:"bank"`
    Value     []byte `codec:"value"`
    Timestamp int64  `codec:"timestamp"`
}
```

An empty `indices` reads PCRs 0-23.

### ExtendPCR (0x12)

**Request Payload:**
```go
type TPM2ExtendPCRRequest struct {
    PCRIndex int    `codec:"pcr_index"` // 0-23
    HashAlg  string `codec:"hash_alg"`  // default sha256
    Data     []byte `codec:"data"`      // required
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
    Data []byte `codec:"data"` // required
}
```

**Response Payload:**
```go
type TPM2SealResponse struct {
    SealedData []byte `codec:"sealed_data"`
    Timestamp  int64  `codec:"timestamp"`
}
```

The QUIC request carries no name, password or PCR selection.

### Unseal (0x16)

**Request Payload:**
```go
type TPM2UnsealRequest struct {
    CN string `codec:"cn"` // required
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
    Size     uint16 `codec:"size"`     // 0 reads the whole index
    Offset   uint16 `codec:"offset"`
    Password string `codec:"password"`
}
```

**Response Payload:**
```go
type TPM2NVReadResponse struct {
    Index     uint32 `codec:"index"`
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
    Offset   uint16 `codec:"offset"`
    Password string `codec:"password"`
}
```

**Response Payload:** `TPM2StatusResponse`.

### NVDelete (0x1A)

**Request Payload:**
```go
type TPM2NVDeleteRequest struct {
    Index          uint32 `codec:"index"`
    ParentPassword string `codec:"parent_password"` // owner hierarchy
}
```

**Response Payload:** `TPM2StatusResponse`.

### NVList (0x1B)

No request payload.

**Response Payload:**
```go
type TPM2NVListResponse struct {
    Indexes   []*TPM2NVIndex `codec:"indexes"`
    Timestamp int64          `codec:"timestamp"`
}

type TPM2NVIndex struct {
    Handle    uint32 `codec:"handle"`
    Type      string `codec:"type"`
    Size      uint32 `codec:"size"`
    AuthRead  bool   `codec:"auth_read"`
    AuthWrite bool   `codec:"auth_write"`
}
```

Index 0, empty write data and a PCR index outside 0–23 are refused with
`InvalidArgument` before the TPM is touched. The NV checks are shared with
gRPC, REST and MCP (`pkg/api/tpmnv`), the PCR checks with MCP
(`pkg/api/tpmpcr`).

## Connection Example

```go
import (
    "crypto/tls"
    "crypto/x509"
    "os"
    "time"

    "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
    "github.com/quic-go/quic-go"
)

// Load platform CA certificate for TLS verification
caCert, _ := os.ReadFile("/path/to/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    RootCAs:    caCertPool,
    NextProtos: []string{quicwire.ALPNProtocol}, // "platform-quic"
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

// Send TPM Info request (category 0x99, sub-opcode 0x01)
err = quicwire.WriteRequest(stream, &quicwire.Request{
    Opcode:  quicwire.OpTPM2Category,
    Token:   token,
    Payload: []byte{quicwire.SubOpTPM2Info},
})
if err != nil {
    return err
}

resp, err := quicwire.ReadResponse(stream)
if err != nil {
    return err
}
// resp.Status is a status code; resp.Payload is the MessagePack response
```

## Protocol Constants

From `sdk/go/wire/quicwire`:

```go
const (
    // Max payload size: 16MB
    MaxPayloadSize uint32 = 16 * 1024 * 1024

    // Max token size: 8KB
    MaxTokenSize uint16 = 8 * 1024

    // Category opcode for TPM2
    OpTPM2Category byte = 0x99

    // TLS ALPN
    ALPNProtocol = "platform-quic"
)
```

The port default is `DefaultQUICPort` (`pkg/config/daemon.go`).

## Notes

- All timestamps are Unix epoch in seconds
- Binary data is encoded as byte arrays in MessagePack
- Codec struct tags are required for proper serialization/deserialization
- MessagePack is the default payload codec (`quicwire.DecodePayload`)

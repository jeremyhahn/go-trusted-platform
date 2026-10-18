# TPM gRPC API Reference

Package: `platform.v1`
Service: `TPMService`
Port: `9443`

## Service Definition

```protobuf
service TPMService {
  // Info returns TPM capabilities and information
  rpc Info(TPMInfoRequest) returns (TPMInfoResponse);

  // Provision initializes the TPM with required keys
  rpc Provision(TPMProvisionRequest) returns (TPMProvisionResponse);

  // Clear clears the TPM (requires owner authorization)
  rpc Clear(TPMClearRequest) returns (TPMClearResponse);

  // EK operations
  rpc CreateEK(CreateEKRequest) returns (CreateEKResponse);
  rpc GetEK(GetEKRequest) returns (GetEKResponse);
  rpc GetEKCertificate(GetEKCertificateRequest) returns (GetEKCertificateResponse);
  rpc ImportEKCertificate(ImportEKCertificateRequest) returns (ImportEKCertificateResponse);
  rpc DeleteEK(DeleteEKRequest) returns (DeleteEKResponse);

  // SRK operations
  rpc CreateSRK(CreateSRKRequest) returns (CreateSRKResponse);
  rpc GetSRK(GetSRKRequest) returns (GetSRKResponse);
  rpc DeleteSRK(DeleteSRKRequest) returns (DeleteSRKResponse);

  // AK/IAK operations
  rpc CreateAK(CreateAKRequest) returns (CreateAKResponse);
  rpc GetAK(GetAKRequest) returns (GetAKResponse);
  rpc DeleteAK(DeleteAKRequest) returns (DeleteAKResponse);

  // Seal/Unseal operations
  rpc Seal(SealRequest) returns (SealResponse);
  rpc Unseal(UnsealRequest) returns (UnsealResponse);

  // Attestation operations
  rpc Quote(QuoteRequest) returns (QuoteResponse);
  rpc VerifyQuote(VerifyQuoteRequest) returns (VerifyQuoteResponse);
  rpc Certify(CertifyRequest) returns (CertifyResponse);
  rpc GetEventLog(GetEventLogRequest) returns (GetEventLogResponse);
  rpc GetPCRs(GetPCRsRequest) returns (GetPCRsResponse);

  // NVRAM operations
  rpc DefineNVRAM(DefineNVRAMRequest) returns (DefineNVRAMResponse);
  rpc WriteNVRAM(WriteNVRAMRequest) returns (WriteNVRAMResponse);
  rpc ReadNVRAM(ReadNVRAMRequest) returns (ReadNVRAMResponse);
  rpc UndefineNVRAM(UndefineNVRAMRequest) returns (UndefineNVRAMResponse);

  // Random number generation
  rpc GetRandom(GetRandomRequest) returns (GetRandomResponse);
}
```

## Enums

```protobuf
enum KeyAlgorithm {
  KEY_ALGORITHM_UNSPECIFIED = 0;
  KEY_ALGORITHM_RSA_2048 = 1;
  KEY_ALGORITHM_RSA_3072 = 2;
  KEY_ALGORITHM_RSA_4096 = 3;
  KEY_ALGORITHM_ECDSA_P256 = 4;
  KEY_ALGORITHM_ECDSA_P384 = 5;
  KEY_ALGORITHM_ECDSA_P521 = 6;
  KEY_ALGORITHM_ED25519 = 7;
}

enum PCRBank {
  PCR_BANK_UNSPECIFIED = 0;
  PCR_BANK_SHA1 = 1;
  PCR_BANK_SHA256 = 2;
  PCR_BANK_SHA384 = 3;
  PCR_BANK_SHA512 = 4;
}
```

## TPM Information

### Info

Returns TPM device information and capabilities.

**Request:**
```protobuf
message TPMInfoRequest {}
```

**Response:**
```protobuf
message TPMInfoResponse {
  TPMVersion version = 1;
  TPMManufacturer manufacturer = 2;
  repeated TPMCapability capabilities = 3;
  repeated PCRBank pcr_banks = 4;
  uint32 max_nvram_size = 5;
  bool is_simulator = 6;
  bool fips_mode = 7;
  map<string, string> properties = 8;
}
```

**Go Example:**
```go
response, err := client.Info(ctx, &platformv1.TPMInfoRequest{})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Manufacturer: %s\n", response.Manufacturer.Name)
fmt.Printf("Version: %v\n", response.Version)
fmt.Printf("FIPS Mode: %v\n", response.FipsMode)
```

## Endorsement Key Operations

### GetEK

Retrieves the Endorsement Key public portion.

**Request:**
```protobuf
message GetEKRequest {
  KeyAlgorithm algorithm = 1;
  uint32 handle = 2;
}
```

**Response:**
```protobuf
message GetEKResponse {
  bytes public_key = 1;
  uint32 handle = 2;
  KeyAlgorithm algorithm = 3;
}
```

### GetEKCertificate

Retrieves the EK certificate.

**Request:**
```protobuf
message GetEKCertificateRequest {
  KeyAlgorithm algorithm = 1;
  uint32 handle = 2;
}
```

**Response:**
```protobuf
message GetEKCertificateResponse {
  bytes certificate = 1;
  string format = 2;
}
```

### CreateEK

Creates a new Endorsement Key.

**Request:**
```protobuf
message CreateEKRequest {
  KeyAttributes attributes = 1;
  bool persistent = 2;
}
```

**Response:**
```protobuf
message CreateEKResponse {
  Status status = 1;
  bytes public_key = 2;
  uint32 handle = 3;
}
```

### ImportEKCertificate

Imports an EK certificate.

**Request:**
```protobuf
message ImportEKCertificateRequest {
  bytes certificate = 1;
}
```

**Response:**
```protobuf
message ImportEKCertificateResponse {
  Status status = 1;
}
```

### DeleteEK

Flushes the EK handle from the TPM.

**Request:**
```protobuf
message DeleteEKRequest {}
```

**Response:**
```protobuf
message DeleteEKResponse {
  Status status = 1;
}
```

## Storage Root Key Operations

### GetSRK

Retrieves the Storage Root Key.

**Request:**
```protobuf
message GetSRKRequest {
  KeyAlgorithm algorithm = 1;
  uint32 handle = 2;
}
```

**Response:**
```protobuf
message GetSRKResponse {
  bytes public_key = 1;
  uint32 handle = 2;
  KeyAlgorithm algorithm = 3;
}
```

### CreateSRK

Creates a new Storage Root Key under the EK.

**Request:**
```protobuf
message CreateSRKRequest {
  KeyAttributes attributes = 1;
  bool persistent = 2;
  uint32 parent_handle = 3;
  string parent_password = 4;
}
```

**Response:**
```protobuf
message CreateSRKResponse {
  Status status = 1;
  bytes public_key = 2;
  uint32 handle = 3;
}
```

### DeleteSRK

Flushes the SRK handle from the TPM.

**Request:**
```protobuf
message DeleteSRKRequest {}
```

**Response:**
```protobuf
message DeleteSRKResponse {
  Status status = 1;
}
```

## Attestation Key Operations

### GetAK

Retrieves the Attestation Key.

**Request:**
```protobuf
message GetAKRequest {
  KeyAlgorithm algorithm = 1;
  uint32 handle = 2;
}
```

**Response:**
```protobuf
message GetAKResponse {
  bytes public_key = 1;
  uint32 handle = 2;
  KeyAlgorithm algorithm = 3;
}
```

### CreateAK

Creates a new Attestation Key.

**Request:**
```protobuf
message CreateAKRequest {
  KeyAttributes attributes = 1;
  bool persistent = 2;
  uint32 parent_handle = 3;
  string parent_password = 4;
}
```

**Response:**
```protobuf
message CreateAKResponse {
  Status status = 1;
  bytes public_key = 2;
  uint32 handle = 3;
  bytes credential_blob = 4;
}
```

### DeleteAK

Flushes the AK handle from the TPM.

**Request:**
```protobuf
message DeleteAKRequest {}
```

**Response:**
```protobuf
message DeleteAKResponse {
  Status status = 1;
}
```

## Seal and Unseal Operations

### Seal

Seals data to the TPM as an object protected by `password`.

**PCR-bound sealing is unavailable.** A request that sets `pcr_indices` fails
with `FAILED_PRECONDITION`, and the message names go-quicbaas #1171. Binding the
object to PCRs needs the TPM PolicyPCR primitives, which go-quicbaas does not
re-export yet. Without them the object would be sealed in a way the PCRs do not
protect, so the server refuses it. `pcr_indices` and `pcr_bank` stay in the
message for the day the re-export lands.


**Request:**
```protobuf
message SealRequest {
  bytes data = 1;
  string cn = 2;
  uint32 parent_handle = 3;
  string parent_password = 4;
  string password = 5;
  repeated uint32 pcr_indices = 6;
  PCRBank pcr_bank = 7;
  bool overwrite = 8;
}
```

**Response:**
```protobuf
message SealResponse {
  Status status = 1;
  bytes sealed_data = 2;
  bytes public_key = 3;
  bytes private_key = 4;
}
```

**Example:**
```go
response, err := client.Seal(ctx, &platformv1.SealRequest{
    Data:         []byte("my-secret-data"),
    Cn:           "app-secret",
    ParentHandle: 0x81000002,
    Password:     sealPassword,
})
```

### Unseal

Unseals data from the TPM.

**Request:**
```protobuf
message UnsealRequest {
  string cn = 1;
  uint32 parent_handle = 2;
  string parent_password = 3;
  string password = 4;
  repeated uint32 pcr_indices = 5;
  PCRBank pcr_bank = 6;
}
```

**Response:**
```protobuf
message UnsealResponse {
  Status status = 1;
  bytes data = 2;
}
```

## Attestation Operations

### Quote

Generates a TPM quote over selected PCRs.

**Request:**
```protobuf
message QuoteRequest {
  uint32 ak_handle = 1;
  string ak_password = 2;
  repeated uint32 pcr_indices = 3;
  PCRBank pcr_bank = 4;
  bytes nonce = 5;
}
```

**Response:**
```protobuf
message QuoteResponse {
  Status status = 1;
  bytes quote = 2;
  bytes signature = 3;
  repeated PCRValue pcr_values = 4;
  bytes event_log = 5;
  // The IAK's signature scheme, e.g. "SHA256-RSAPSS".
  string signature_algorithm = 7;
}
```

**Example:**
```go
nonce := make([]byte, 32)
rand.Read(nonce)

response, err := client.Quote(ctx, &platformv1.QuoteRequest{
    AkHandle:   0x81010002,
    PcrIndices: []uint32{0, 1, 2, 3, 7, 8, 9},
    PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
    Nonce:      nonce,
})
```

### VerifyQuote

Verifies a TPM quote.

**Request:**
```protobuf
message VerifyQuoteRequest {
  bytes quote = 1;
  bytes signature = 2;
  bytes ak_public = 3;
  bytes nonce = 4;
  repeated PCRValue expected_pcrs = 5;
  // The scheme QuoteResponse declared; required, the signature is checked
  // under it.
  string signature_algorithm = 7;
}
```

**Response:**
```protobuf
message VerifyQuoteResponse {
  Status status = 1;
  bool verified = 2;
  string message = 3;
  repeated PCRValue actual_pcrs = 4;
}
```

### Certify

The IAK certifies that the key at a persistent handle is resident in this TPM
(TPM2_Certify). Scope `tpm:read`. A zero or non-persistent handle, or a nonce
over 64 bytes, is `InvalidArgument`; a handle the TPM does not hold is
`NotFound` ([api.md](api.md) §5).

**Request:**
```protobuf
message CertifyRequest {
  uint32 key_handle = 1;
  string key_password = 2;  // the key's authValue; empty when it has none
  bytes nonce = 3;          // echoed in certify_info's extraData; at most 64 bytes
}
```

**Response:**
```protobuf
message CertifyResponse {
  Status status = 1;
  bytes certify_info = 2;              // the TPMS_ATTEST the IAK signed
  bytes signature = 3;                 // RSA bytes or ASN.1 DER ECDSA (r, s)
  string signature_algorithm = 4;      // x509.SignatureAlgorithm name
  bytes certify_info_signature = 5;    // marshalled TPMT_SIGNATURE
  bytes attesting_key_public = 6;      // IAK, PKIX DER
  bytes attested_key_public = 7;       // certified key, PKIX DER
  bytes attesting_key_public_area = 8; // IAK TPMT_PUBLIC
  bytes attested_key_public_area = 9;  // certified key TPMT_PUBLIC
  bytes nonce = 10;
}
```

## PCR Operations

### GetPCRs

Reads PCR values.

**Request:**
```protobuf
message GetPCRsRequest {
  repeated uint32 indices = 1;
  PCRBank bank = 2;
}
```

**Response:**
```protobuf
message GetPCRsResponse {
  repeated PCRValue pcr_values = 1;
}

message PCRValue {
  uint32 index = 1;
  PCRBank bank = 2;
  bytes value = 3;
}
```

## Event Log

### GetEventLog

Retrieves the TPM event log.

**Request:**
```protobuf
message GetEventLogRequest {
  string format = 1;  // json, binary, text
}
```

**Response:**
```protobuf
message GetEventLogResponse {
  bytes event_log = 1;
  string format = 2;
  uint64 event_count = 3;
}
```

## NVRAM Operations

### DefineNVRAM

Defines an NVRAM index.

**Request:**
```protobuf
message DefineNVRAMRequest {
  uint32 index = 1;
  uint32 size = 2;
  string password = 3;
  repeated string attributes = 4;
}
```

### WriteNVRAM

Writes data to NVRAM.

**Request:**
```protobuf
message WriteNVRAMRequest {
  uint32 index = 1;
  bytes data = 2;
  string password = 3;
  uint32 offset = 4;
}
```

### ReadNVRAM

Reads data from NVRAM.

**Request:**
```protobuf
message ReadNVRAMRequest {
  uint32 index = 1;
  string password = 2;
  uint32 offset = 3;
  uint32 size = 4;
}
```

**Response:**
```protobuf
message ReadNVRAMResponse {
  bytes data = 1;
}
```

### UndefineNVRAM

Deletes an NVRAM index.

**Request:**
```protobuf
message UndefineNVRAMRequest {
  uint32 index = 1;
}
```

## Random Number Generation

### GetRandom

Gets random bytes from TPM hardware RNG.

**Request:**
```protobuf
message GetRandomRequest {
  uint32 num_bytes = 1;
}
```

**Response:**
```protobuf
message GetRandomResponse {
  bytes random_bytes = 1;
}
```

**Example:**
```go
response, err := client.GetRandom(ctx, &platformv1.GetRandomRequest{
    NumBytes: 32,
})
```

## Common Types

### KeyAttributes

```protobuf
message KeyAttributes {
  string cn = 1;
  KeyAlgorithm algorithm = 2;
  HashAlgorithm hash = 3;
  uint32 handle = 4;
  bool persistent = 5;
  string password = 6;
  map<string, string> metadata = 7;
}
```

### Status

```protobuf
message Status {
  bool success = 1;
  string message = 2;
  ErrorDetail error = 3;
}
```

## Error Handling

gRPC status codes:

| Code | Description |
|------|-------------|
| `NOT_FOUND` | Key or object not found |
| `ALREADY_EXISTS` | Object already exists |
| `INVALID_ARGUMENT` | Invalid request parameters |
| `PERMISSION_DENIED` | Authorization failed |
| `FAILED_PRECONDITION` | PCR mismatch, TPM not ready, or a `Seal` naming PCRs (refused until go-quicbaas #1171); `IDevIDService.DeleteIDevID` and `DeleteIAK`, always |
| `INTERNAL` | Server error |

`IDevIDService.DeleteIDevID` and `DeleteIAK` are refused until the owner rules
on eviction: the key is TPM-resident and is not evicted, and the refusal
changes nothing — no key, no certificate, no state (#304). The certificates
are deleted with `DeleteIDevIDCertificate` and `DeleteIAKCertificate`. Every
transport answers the same; see [api.md](api.md) §8.

```go
resp, err := client.GetEK(ctx, &platformv1.GetEKRequest{})
if err != nil {
    if st, ok := status.FromError(err); ok {
        if st.Code() == codes.NotFound {
            // Handle not found
        }
    }
    return err
}
```

## Connection Example

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TLS connection
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

// Unix socket connection
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

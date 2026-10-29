# TPM gRPC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> `platform.v1.TPMService` messages over gRPC. The cross-transport contract is
> [api.md](api.md).

Package: `platform.v1`
Service: `TPMService`
Port: `10443`

## Service Definition

```protobuf
service TPMService {
  // Info returns TPM capabilities and information
  rpc Info(TPMInfoRequest) returns (TPMInfoResponse);

  // GetCapabilities returns the algorithms, commands and ECC curves the TPM implements
  rpc GetCapabilities(TPMCapabilitiesRequest) returns (TPMCapabilitiesResponse);

  // GetPlatformAttributes describes the TPM device and its provisioned identity keys
  rpc GetPlatformAttributes(TPMPlatformAttributesRequest) returns (TPMPlatformAttributesResponse);

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
  rpc ExtendPCR(ExtendPCRRequest) returns (ExtendPCRResponse);

  // Credential activation
  rpc MakeCredential(MakeCredentialRequest) returns (MakeCredentialResponse);
  rpc ActivateCredential(TPMActivateCredentialRequest) returns (TPMActivateCredentialResponse);

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
  KEY_ALGORITHM_DILITHIUM2 = 8;
  KEY_ALGORITHM_DILITHIUM3 = 9;
  KEY_ALGORITHM_DILITHIUM5 = 10;
}

enum PCRBank {
  PCR_BANK_UNSPECIFIED = 0;
  PCR_BANK_SHA1 = 1;
  PCR_BANK_SHA256 = 2;
  PCR_BANK_SHA384 = 3;
  PCR_BANK_SHA512 = 4;
  PCR_BANK_SM3_256 = 5;
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
  repeated NVIndex nv_indexes = 9;
}

message NVIndex {
  uint32 handle = 1;
  string type = 2;   // ordinary | counter | extend | bits | pin_pass | pin_fail
  uint32 size = 3;
  bool auth_read = 4;
  bool auth_write = 5;
}
```

`properties["info"]` carries the TPM's text summary. `manufacturer`,
`capabilities`, `max_nvram_size`, `fips_mode` and `nv_indexes` come from the
TPM fixed properties; when that read fails they are left empty.

**Go Example:**
```go
response, err := client.Info(ctx, &platformv1.TPMInfoRequest{})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Manufacturer: %s\n", response.GetManufacturer().GetName())
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
  string format = 2;      // PEM or DER
  uint32 nvram_index = 3;
}
```

Only `certificate` is read; an empty one is `InvalidArgument`.

**Response:**
```protobuf
message ImportEKCertificateResponse {
  Status status = 1;
}
```

### DeleteEK

Evicts the EK that `tpm.ek` configures from its persistent handle
(`TPM2_EvictControl`, TPM 2.0 Library Part 3 §28.5), authorised by the
`tpm.ek` hierarchy auth it was persisted with, so a following `CreateEK`
at the same handle succeeds. The status message is `EK evicted`. An empty
handle (`TPM_RC_HANDLE`) is `NotFound`; a `tpm.ek` without a handle is
`FailedPrecondition`. `handle` must name the configured `tpm.ek` handle: any
other handle, or none, is `InvalidArgument` and evicts nothing. `algorithm`
and `password` are not read.

**Request:**
```protobuf
message DeleteEKRequest {
  uint32 handle = 1;
  KeyAlgorithm algorithm = 2;
  string password = 3;
}
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

Creates the Shared SRK that `tpm.ssrk` configures and persists it at its
handle (`0x81000001` by default). The key is built from the configuration, not
read back from the handle, so it works on a cleared TPM. With
`encrypt-sessions` on, the EK salts the session. An occupied handle is
`AlreadyExists`; a `tpm.ssrk` without a handle is `FailedPrecondition`.

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

Evicts the Shared SRK that `tpm.ssrk` configures from its persistent handle
(`TPM2_EvictControl`, TPM 2.0 Library Part 3 §28.5), authorised by the
`tpm.ssrk` hierarchy auth it was persisted with, so a following `CreateSRK`
at the same handle succeeds. The status message is `SRK evicted`. An empty
handle (`TPM_RC_HANDLE`) is `NotFound`; a `tpm.ssrk` without a handle is
`FailedPrecondition`. `handle` must name the configured `tpm.ssrk` handle:
any other handle, or none, is `InvalidArgument` and evicts nothing.
`algorithm` and `password` are not read.

**Request:**
```protobuf
message DeleteSRKRequest {
  uint32 handle = 1;
  KeyAlgorithm algorithm = 2;
  string password = 3;
}
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

Refused with `FAILED_PRECONDITION` (`ErrDeviceIdentityKeyNotDeletable`),
whatever the request: the AK this service names is the IAK, which is not
evicted, so it answers as `IDevIDService.DeleteIAK` and the TPM is not touched
(#704).

**Request:**
```protobuf
message DeleteAKRequest {
  uint32 handle = 1;
  KeyAlgorithm algorithm = 2;
  string password = 3;
}
```

**Response:**
```protobuf
message DeleteAKResponse {
  Status status = 1;
}
```

## Seal and Unseal Operations

### Seal

Seals data to the TPM with optional PCR policy.

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
    Data:       []byte("my-secret-data"),
    Cn:         "app-secret",
    PcrIndices: []uint32{7, 8, 9},
    PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
})
```

The daemon always seals under the SSRK: `parent_handle`, `parent_password` and
`overwrite` are not read, and only `sealed_data` is returned. Unseal reads only
`cn` and `password`. See [Sealing](sealing.md).

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
  // TLS exporter of the request's connection; the TPM quoted
  // SHA-256(nonce || channel_binding) (#482).
  bytes channel_binding = 6;
  // The IAK's signature scheme, e.g. "SHA256-RSAPSS".
  string signature_algorithm = 7;
}
```

**Example:**
```go
nonce := make([]byte, 32)
rand.Read(nonce)

response, err := client.Quote(ctx, &platformv1.QuoteRequest{
    PcrIndices: []uint32{0, 1, 2, 3, 7, 8, 9},
    Nonce:      nonce,
})
```

Only `pcr_indices` and `nonce` are read; the quote is signed by the IAK.
`pcr_values` is not filled. A request that did not arrive over TLS is refused.
See [Attestation](attestation.md#quote-request-example).

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
  // When set, the quote must carry SHA-256(nonce || channel_binding).
  bytes channel_binding = 6;
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

An empty `ak_public` verifies against the node's own IAK. `expected_pcrs` is
not compared and `actual_pcrs` is not filled; see
[Attestation](attestation.md#verification-example).

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

### ExtendPCR

Extends PCR `index` (0-23) in the `hash_alg` bank (`sha1`, `sha256`, `sha384`
or `sha512`; `sha256` when empty) with `data`. Scope `tpm:write`. An index past
23 or empty `data` is `InvalidArgument` and the TPM is not called; a bank the
TPM does not have is the TPM's refusal; QUIC `0x12` and MCP `platform_tpm_pcr_extend` run the same validator
(`pkg/api/tpmpcr`). A successful extend returns `status` with `success: true`
and the message `PCR <index> extended`, the pair QUIC and MCP return.

```protobuf
message ExtendPCRRequest {
  uint32 index = 1;
  string hash_alg = 2;
  bytes data = 3;
}

message ExtendPCRResponse {
  Status status = 1;
}
```

## Capabilities and Platform Attributes

### GetCapabilities

Returns TPM2_GetCapability's algorithm, command and ECC-curve names. Scope
`tpm:read`. A list the TPM refuses is `FailedPrecondition` naming the list.

```protobuf
message TPMCapabilitiesRequest {}

message TPMCapabilitiesResponse {
  repeated string algorithms = 1;
  repeated string commands = 2;
  repeated string ecc_curves = 3;
}
```

### GetPlatformAttributes

Describes the TPM device and its provisioned EK, SRK and IAK. Scope
`tpm:read`. An attribute the TPM cannot report is false or empty; a key that is
not provisioned is absent.

```protobuf
message TPMPlatformAttributesRequest {}

message TPMPlatformAttributesResponse {
  string device = 1;
  bool is_fips = 2;
  bool pcr_extended = 3;
  bool can_seal = 4;
  bool is_simulator = 5;
  string manufacturer = 6;
  TPMKeyRef ek = 7;
  TPMKeyRef srk = 8;
  TPMKeyRef iak = 9;
}

message TPMKeyRef {
  uint32 handle = 1;
  string algorithm = 2;
}
```

QUIC `0x17` / `0x1E` and MCP `platform_tpm_capabilities` /
`platform_tpm_platform` read the same values through `pkg/api/tpmattrs`.

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
  repeated EventLogEntry entries = 4;
}

message EventLogEntry {
  uint32 event_num = 1;
  uint32 pcr_index = 2;
  string event_type = 3;
  uint32 digest_count = 4;
  repeated EventDigest digests = 5;
  uint32 event_size = 6;
  string event_string = 7;
}

message EventDigest {
  string algorithm_id = 1;
  string digest = 2;
}
```

The request's `format` is not read: `event_log` is the raw log and `format` is
always `tcg2`. When the log cannot be parsed, `entries` is empty.

## NVRAM Operations

### DefineNVRAM

Defines an NVRAM index.

**Request:**
```protobuf
message DefineNVRAMRequest {
  uint32 index = 1;
  uint32 size = 2;
  string password = 3;
  repeated string attributes = 4;  // AUTHWRITE, AUTHREAD, ...
  string parent_password = 5;      // owner hierarchy auth, when set
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
  string parent_password = 10;  // owner hierarchy auth, when set
  string password = 2;
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
| `UNAVAILABLE` | The daemon has no TPM |
| `PERMISSION_DENIED` | Authorization failed |
| `FAILED_PRECONDITION` | PCR mismatch or TPM not ready; `IDevIDService.DeleteIDevID` and `DeleteIAK` and `TPMService.DeleteAK`, always |
| `INTERNAL` | Server error |

`IDevIDService.DeleteIDevID` and `DeleteIAK` are refused until the owner rules
on eviction: the key is TPM-resident and is not evicted, and the refusal
changes nothing — no key, no certificate, no state (#304). The certificates
are deleted with `DeleteIDevIDCertificate` and `DeleteIAKCertificate`. Every
transport answers the same; see [api.md](api.md) §8. `TPMService.DeleteAK`
names the same IAK and gives the same refusal, even with no TPM attached.

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
    "google.golang.org/grpc/credentials/insecure"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TLS connection
creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
if err != nil {
    return err
}

conn, err := grpc.Dial("localhost:10443", grpc.WithTransportCredentials(creds))
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

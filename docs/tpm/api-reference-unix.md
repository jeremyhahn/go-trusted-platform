# TPM Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> How to reach the TPM service over the local socket. The cross-transport
> contract is [api.md](api.md).

Socket Path: `/run/platformd.sock`
Protocol: gRPC over Unix domain socket

## Overview

The Unix socket interface provides local IPC for CLI tools and local services.
It serves the same gRPC services as the TCP interface, over a Unix domain
socket and without TLS. The path is `platformd serve --socket-path` (default
`/run/platformd.sock`).

## Connection

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

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

## Available Methods

All methods from the [gRPC API](api-reference-grpc.md) are available via Unix socket:

### Device Information and Management

| Method | Description |
|--------|-------------|
| `Info` | Get TPM device information |
| `GetCapabilities` | List the algorithms, commands and ECC curves the TPM implements |
| `GetPlatformAttributes` | Describe the TPM device and its provisioned EK, SRK and IAK |
| `Provision` | Provision TPM with owner authorization |
| `Clear` | Clear TPM and reset authorization |

### Endorsement Key Operations

| Method | Description |
|--------|-------------|
| `GetEK` | Get Endorsement Key |
| `CreateEK` | Create Endorsement Key |
| `DeleteEK` | Delete Endorsement Key |
| `GetEKCertificate` | Get EK certificate |
| `ImportEKCertificate` | Import EK certificate |

### Storage Root Key Operations

| Method | Description |
|--------|-------------|
| `GetSRK` | Get Storage Root Key |
| `CreateSRK` | Create Storage Root Key |
| `DeleteSRK` | Delete Storage Root Key |

### Attestation Key Operations

| Method | Description |
|--------|-------------|
| `GetAK` | Get Attestation Key |
| `CreateAK` | Create Attestation Key |
| `DeleteAK` | Refused with `FailedPrecondition`: the AK is the IAK, which is not deleted |

### Attestation Operations

| Method | Description |
|--------|-------------|
| `Quote` | Generate attestation quote over PCRs |
| `VerifyQuote` | Verify quote signature |
| `Certify` | IAK certifies a persistent key (TPM2_Certify) |
| `GetEventLog` | Get TPM event log |
| `GetPCRs` | Read PCR values |
| `ExtendPCR` | Extend a PCR with data (`tpm:write`) |
| `MakeCredential` | Create a TPM2_MakeCredential challenge |
| `ActivateCredential` | Activate a challenge and recover the wrapped secret |

### Seal and Unseal Operations

| Method | Description |
|--------|-------------|
| `Seal` | Seal data under a password (PCR binding refused until go-quicbaas #1171) |
| `Unseal` | Unseal TPM-sealed data |

### NVRAM Operations

| Method | Description |
|--------|-------------|
| `DefineNVRAM` | Define NVRAM index |
| `WriteNVRAM` | Write NVRAM data |
| `ReadNVRAM` | Read NVRAM data |
| `UndefineNVRAM` | Delete NVRAM index |

### Random Number Generation

| Method | Description |
|--------|-------------|
| `GetRandom` | Get random bytes from TPM |

## Usage Examples

### Get TPM Info

```go
resp, err := client.Info(ctx, &platformv1.TPMInfoRequest{})
if err != nil {
    return err
}

fmt.Printf("Manufacturer: %s\n", resp.GetManufacturer().GetName())
fmt.Printf("FIPS Mode: %v\n", resp.FipsMode)
```

### Provision TPM

```go
resp, err := client.Provision(ctx, &platformv1.TPMProvisionRequest{
    OwnerPassword: "secure-password",
})
if err != nil {
    return err
}

fmt.Printf("Status: %v\n", resp.Status.Success)
```

### Get Endorsement Key

```go
resp, err := client.GetEK(ctx, &platformv1.GetEKRequest{})
if err != nil {
    return err
}

fmt.Printf("Handle: %d\n", resp.Handle)
fmt.Printf("Algorithm: %v\n", resp.Algorithm)
```

### Quote PCRs

```go
nonce := make([]byte, 32)
rand.Read(nonce)

resp, err := client.Quote(ctx, &platformv1.QuoteRequest{
    PcrIndices: []uint32{0, 1, 2, 3, 7, 8, 9},
    Nonce:      nonce,
})
if err != nil {
    return err
}

fmt.Printf("Quote length: %d bytes\n", len(resp.Quote))
fmt.Printf("Signature length: %d bytes\n", len(resp.Signature))
```

A request that did not arrive over TLS is refused (the quote is bound to the
TLS connection, #482), so over the Unix socket `Quote` fails; quote over gRPC
TCP. See [Attestation](attestation.md#quote-request-example).

### Read PCRs

```go
resp, err := client.GetPCRs(ctx, &platformv1.GetPCRsRequest{
    Indices: []uint32{0, 1, 2, 3, 7},
    Bank:    platformv1.PCRBank_PCR_BANK_SHA256,
})
if err != nil {
    return err
}

for _, pcr := range resp.PcrValues {
    fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Value)
}
```

### Seal Data

```go
resp, err := client.Seal(ctx, &platformv1.SealRequest{
    Data:     []byte("my-secret-data"),
    Cn:       "app-secret",
    Password: sealPassword,
})
if err != nil {
    return err
}

fmt.Printf("Sealed data length: %d bytes\n", len(resp.SealedData))
```

Setting `PcrIndices` fails with `FailedPrecondition`. PCR-bound sealing is
unavailable until go-quicbaas re-exports the TPM PolicyPCR primitives
(go-quicbaas #1171).

### Unseal Data

```go
resp, err := client.Unseal(ctx, &platformv1.UnsealRequest{
    Cn:       "app-secret",
    Password: sealPassword,
})
if err != nil {
    return err
}

fmt.Printf("Unsealed data: %s\n", string(resp.Data))
```

The daemon seals under the SSRK; Unseal reads only `cn` and `password`. See
[Sealing](sealing.md).

### Get Random Bytes

```go
resp, err := client.GetRandom(ctx, &platformv1.GetRandomRequest{
    NumBytes: 32,
})
if err != nil {
    return err
}

fmt.Printf("Random bytes: %x\n", resp.RandomBytes)
```

### NVRAM Operations

```go
// Define NV index
_, err := client.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{
    Index:    0x01C00100,
    Size:     256,
    Password: "nv-password",
})
if err != nil {
    return err
}

// Write NVRAM
_, err = client.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{
    Index:    0x01C00100,
    Data:     []byte("test data"),
    Password: "nv-password",
})
if err != nil {
    return err
}

// Read NVRAM
resp, err := client.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{
    Index:    0x01C00100,
    Password: "nv-password",
    Size:     256,
})
if err != nil {
    return err
}

fmt.Printf("NVRAM data: %s\n", string(resp.Data))

// Delete NVRAM
_, err = client.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{
    Index: 0x01C00100,
})
if err != nil {
    return err
}
```

## CLI Usage

The `platformctl` CLI uses the Unix socket by default: its default context
`local` names `/run/platformd.sock` (`pkg/cli/config.go`).

```bash
# Get TPM info
platformctl tpm info

# Provision TPM
platformctl tpm provision --owner-password secure-password

# Endorsement Key
platformctl tpm ek info

# Seal data (--pcrs is refused until go-quicbaas #1171)
platformctl tpm seal --cn app-secret --data "plaintext-data" --password "$PW"

# Unseal data
platformctl tpm unseal --cn app-secret --password "$PW"
```

`platformctl tpm` has no PCR read, quote or random command; see
[CLI Usage](cli-usage.md).

### Unix Socket Configuration

```bash
# Use a custom socket path: name it in a local context, then select it
platformctl context add custom --socket-path /path/to/custom.sock
platformctl --context custom tpm info

# Or select the context via environment variable
export PLATFORMCTL_CONTEXT=custom
platformctl tpm info
```

## Permissions

The daemon creates the socket with mode `0660` (`SocketMode`,
`pkg/api/daemon/config.go`). It sets no group: the socket keeps the owner and
group of the `platformd` process, so a client must run as that user or in that
group.

```bash
ls -la /run/platformd.sock
```

## Security Considerations

1. **Local Only**: Unix sockets only accept local connections
2. **File Permissions**: Socket access is controlled by the socket's mode
3. **No TLS**: The socket serves plain gRPC; TLS-bound calls such as `Quote`
   are refused
4. **SO_PEERCRED**: The server reads the caller's kernel-verified UID/GID/PID
   and puts them in the request context (`pkg/util/peercred`)
5. **No Network Exposure**: Cannot be accessed remotely

## Performance Benefits

- No TLS handshake overhead
- No TCP/IP stack
- Suitable for high-frequency local operations

## Error Handling

All errors follow standard gRPC status codes.

The socket serves the same `IDevIDService` as gRPC, so `DeleteIDevID` and
`DeleteIAK` are refused with `FailedPrecondition` until the owner rules on
eviction: the key stays in the TPM and nothing is changed — no key, no
certificate, no state (#304). `TPMService.DeleteAK` names the same IAK and
is refused the same way (#704). `DeleteIDevIDCertificate` and
`DeleteIAKCertificate` delete the certificates.

```go
resp, err := client.Info(ctx, &platformv1.TPMInfoRequest{})
if err != nil {
    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.Unavailable:
            fmt.Println("TPM service not available")
        case codes.Internal:
            fmt.Println("TPM error:", st.Message())
        default:
            fmt.Println("Error:", st.Message())
        }
    }
    return err
}
```

## Connection Pooling

For applications making many concurrent requests, consider reusing the connection:

```go
// Single connection, reused for all operations
conn, err := grpc.Dial(
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewTPMServiceClient(conn)

// All calls use the same connection
for i := 0; i < 100; i++ {
    resp, _ := client.Info(ctx, &platformv1.TPMInfoRequest{})
    // ...
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORMCTL_CONTEXT` | platformctl context to use; a local context names the socket | the config's current context (`/run/platformd.sock`) |
| `GRPC_GO_LOG_VERBOSITY_LEVEL` | grpc-go log verbosity (0-99) | 0 |
| `GRPC_GO_LOG_SEVERITY_LEVEL` | grpc-go log severity (info, warning, error) | error |

## Debugging

Enable gRPC debug logging:

```bash
export GRPC_GO_LOG_VERBOSITY_LEVEL=99
export GRPC_GO_LOG_SEVERITY_LEVEL=info
platformctl tpm info
```

Check socket availability:

```bash
# Verify socket exists
stat /run/platformd.sock

# Test connection with nc
nc -U /run/platformd.sock

# Test with grpcurl (the daemon registers no reflection service)
grpcurl -plaintext -unix \
  -import-path pkg/api/grpc/proto -proto tpm.proto \
  /run/platformd.sock platform.v1.TPMService.Info
```

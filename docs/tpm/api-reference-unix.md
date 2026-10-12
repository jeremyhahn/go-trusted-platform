# TPM Unix Socket API Reference

Socket Path: `/run/platformd.sock`
Protocol: gRPC over Unix domain socket

## Overview

The Unix socket interface provides local IPC for CLI tools and local services. It uses the same gRPC protocol as the TCP interface but over a Unix domain socket for secure local communication without TLS overhead.

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
| `DeleteAK` | Delete Attestation Key |

### Attestation Operations

| Method | Description |
|--------|-------------|
| `Quote` | Generate attestation quote over PCRs |
| `VerifyQuote` | Verify quote signature |
| `GetEventLog` | Get TPM event log |
| `GetPCRs` | Read PCR values |

### Seal and Unseal Operations

| Method | Description |
|--------|-------------|
| `Seal` | Seal data with optional PCR policy |
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

fmt.Printf("Manufacturer: %s\n", resp.Manufacturer.Name)
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
    AkHandle:   0x81010002,
    PcrIndices: []uint32{0, 1, 2, 3, 7, 8, 9},
    PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
    Nonce:      nonce,
})
if err != nil {
    return err
}

fmt.Printf("Quote length: %d bytes\n", len(resp.Quote))
fmt.Printf("Signature length: %d bytes\n", len(resp.Signature))
```

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
    Data:         []byte("my-secret-data"),
    Cn:           "app-secret",
    ParentHandle: 0x81000002,
    PcrIndices:   []uint32{7, 8, 9},
    PcrBank:      platformv1.PCRBank_PCR_BANK_SHA256,
})
if err != nil {
    return err
}

fmt.Printf("Sealed data length: %d bytes\n", len(resp.SealedData))
```

### Unseal Data

```go
resp, err := client.Unseal(ctx, &platformv1.UnsealRequest{
    Cn:           "app-secret",
    ParentHandle: 0x81000002,
    PcrIndices:   []uint32{7, 8, 9},
    PcrBank:      platformv1.PCRBank_PCR_BANK_SHA256,
})
if err != nil {
    return err
}

fmt.Printf("Unsealed data: %s\n", string(resp.Data))
```

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

The `platformctl` CLI uses the Unix socket by default:

```bash
# Get TPM info
platformctl tpm info

# Provision TPM
platformctl tpm provision --owner-password secure-password

# Get Endorsement Key
platformctl tpm ek get

# Read PCRs
platformctl tpm pcr read --indices 0,1,2,3,7,8,9 --bank SHA256

# Generate quote
platformctl tpm quote \
  --nonce dGVzdG5vbmNl \
  --pcr-indices 0,1,2,3,7,8,9

# Get random bytes
platformctl tpm random --num-bytes 32

# Seal data
platformctl tpm seal --data "plaintext-data" --pcr-indices 7,8,9

# Unseal data
platformctl tpm unseal --cn app-secret --pcr-indices 7,8,9
```

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

The Unix socket requires appropriate permissions:

```bash
# Default socket location
/run/platformd.sock

# Typical permissions
srw-rw---- 1 root platform 0 Jan 15 10:00 /run/platformd.sock
```

Users must be in the `platform` group to access the socket:

```bash
sudo usermod -aG platform $USER
```

Verify permissions:
```bash
ls -la /run/platformd.sock
getent group platform
```

## Security Considerations

1. **Local Only**: Unix sockets only accept local connections
2. **File Permissions**: Socket access controlled by filesystem permissions
3. **No TLS Required**: Secure by virtue of local-only access
4. **Audit Logging**: All operations logged with caller UID/GID
5. **SO_PEERCRED**: Server validates caller identity via SO_PEERCRED
6. **No Network Exposure**: Cannot be accessed remotely

## Performance Benefits

- No TLS handshake overhead
- No network framing overhead
- Direct kernel-to-kernel communication
- Lower latency than TCP/gRPC
- Suitable for high-frequency operations

## Error Handling

All errors follow standard gRPC status codes:

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
| `GRPC_GO_LOG_VERBOSITY_LEVEL` | gRPC log level (0-99) | 0 |
| `GRPC_GO_LOG_SEVERITY_LEVEL` | gRPC log level (info, warning, error) | info |

## Debugging

Enable gRPC debug logging:

```bash
export GRPC_GO_LOG_VERBOSITY_LEVEL=99
export GRPC_GO_LOG_SEVERITY_LEVEL=debug
platformctl tpm info
```

Check socket availability:

```bash
# Verify socket exists
stat /run/platformd.sock

# Test connection with nc
nc -U /run/platformd.sock

# Test with grpcurl
grpcurl -plaintext -unix /run/platformd.sock \
  platform.v1.TPMService.Info
```

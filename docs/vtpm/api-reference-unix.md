# vTPM Unix Socket API Reference

Socket Path: `/run/platformd.sock`
Protocol: gRPC over Unix domain socket

## Overview

The Unix socket interface provides local IPC for CLI tools and local services. It uses the same gRPC protocol as the TCP interface but over a Unix domain socket for secure local communication.

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

client := platformv1.NewVTPMServiceClient(conn)
```

## Available Methods

All methods from the [gRPC API](api-reference-grpc.md) are available:

### Bundle Operations

| Method | Description |
|--------|-------------|
| `CreateBundle` | Create new vTPM bundle |
| `GetBundle` | Get bundle by ID |
| `DeleteBundle` | Delete bundle |
| `ListBundles` | List bundles with filtering |

### Template Operations

| Method | Description |
|--------|-------------|
| `CreateTemplate` | Create new template |
| `GetTemplate` | Get template by ID |
| `DeleteTemplate` | Delete template |
| `ListTemplates` | List templates |
| `CloneTemplate` | Clone template to bundle |

### Export/Import

| Method | Description |
|--------|-------------|
| `ExportBundle` | Stream export bundle as tar.gz |
| `ImportBundle` | Stream import bundle from tar.gz |

### Utilities

| Method | Description |
|--------|-------------|
| `ValidateBundle` | Validate bundle integrity |
| `GetBundlePath` | Get bundle filesystem path |
| `GetTPMSocketPath` | Get TPM socket path |
| `GetNVRAMPath` | Get NVRAM path |

## Usage Examples

### Create Bundle

```go
resp, err := client.CreateBundle(ctx, &platformv1.CreateBundleRequest{
    Options: &platformv1.CreateBundleOptions{
        Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
        Hostname:          "vm001.example.com",
        EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
        SecureBootEnabled: true,
    },
})
if err != nil {
    return err
}
fmt.Printf("Created bundle: %s\n", resp.Bundle.Id)
```

### List Bundles

```go
resp, err := client.ListBundles(ctx, &platformv1.ListBundlesRequest{
    Options: &platformv1.ListBundleOptions{
        Mode:  platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
        Limit: 50,
    },
})
if err != nil {
    return err
}
for _, bundle := range resp.Bundles {
    fmt.Printf("%s: %s\n", bundle.Id, bundle.Manifest.Hostname)
}
```

### Get TPM Socket Path

```go
resp, err := client.GetTPMSocketPath(ctx, &platformv1.GetTPMSocketPathRequest{
    Id: bundleID,
})
if err != nil {
    return err
}
fmt.Printf("TPM socket: %s\n", resp.Path)
```

### Export Bundle

```go
stream, err := client.ExportBundle(ctx, &platformv1.ExportBundleRequest{
    Id: bundleID,
})
if err != nil {
    return err
}

file, _ := os.Create("bundle.tar.gz")
defer file.Close()

for {
    chunk, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }
    file.Write(chunk.Data)
}
```

## CLI Usage

The `platformctl` CLI uses the Unix socket by default:

```bash
# Create bundle
platformctl vtpm bundle create \
  --mode pre-assigned \
  --hostname vm001.example.com

# List bundles
platformctl vtpm bundle list

# Get TPM socket path
platformctl vtpm bundle socket-path --id <bundle-id>

# Export bundle
platformctl vtpm bundle export --id <bundle-id> --output bundle.tar.gz
```

### Unix Socket Configuration

```bash
# Use custom socket path
platformctl --socket /path/to/custom.sock vtpm bundle list

# Or via environment variable
export PLATFORMD_SOCKET=/path/to/custom.sock
platformctl vtpm bundle list
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

## Security Considerations

1. **Local Only**: Unix sockets only accept local connections
2. **File Permissions**: Socket access controlled by filesystem permissions
3. **No TLS Required**: Secure by virtue of local-only access
4. **Audit Logging**: All operations logged with caller UID/GID

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORMD_SOCKET` | Socket path | `/run/platformd.sock` |

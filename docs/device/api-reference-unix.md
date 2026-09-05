# Device Unix Socket API Reference

Socket Path: `/run/platformd.sock`

## Overview

The Device API is exposed via Unix domain socket for local IPC and CLI communication. This transport provides lowest latency for local operations and secure communication without network exposure.

## Connection

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

conn, _ := grpc.DialContext(ctx,
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
defer conn.Close()

client := pb.NewDeviceServiceClient(conn)
```

## CLI Usage

The `platformctl` CLI uses the Unix socket by default for local operations.

### Device Operations

```bash
# Register device
platformctl device register \
  --serial SRV-2024-001 \
  --model TrustedServer-v2 \
  --ek-cert /path/to/ek.crt \
  --attest-pub /path/to/attest.pub \
  --attest-cert /path/to/attest.crt

# Get device
platformctl device get --id 1234567890

# Get device by serial
platformctl device get --serial SRV-2024-001

# Update device
platformctl device update --id 1234567890 --model TrustedServer-v3

# Delete device
platformctl device delete --id 1234567890

# List devices
platformctl device list --page 1 --page-size 10

# Attest device
platformctl device attest --id 1234567890 --nonce-file /path/to/nonce
```

### Profile Operations

```bash
# Create profile
platformctl profile create \
  --name "IoT Sensor Profile" \
  --model IoT-Sensor-v1 \
  --role iot \
  --mac-prefix "52:54:00" \
  --serial-prefix "IOT-"

# Get profile
platformctl profile get --id 1

# Update profile
platformctl profile update --id 1 --name "IoT Sensor Profile v2"

# Delete profile
platformctl profile delete --id 1

# List profiles
platformctl profile list

# Find matching profile
platformctl profile match \
  --mac 52:54:00:aa:bb:cc \
  --serial IOT-001 \
  --model IoT-Sensor-v1

# Find by MAC prefix
platformctl profile find-mac --prefix "52:54:00"

# Find by serial prefix
platformctl profile find-serial --prefix "IOT-"
```

### Output Formats

```bash
# JSON output (default)
platformctl device list --output json

# Table output
platformctl device list --output table

# YAML output
platformctl device list --output yaml

# Quiet (IDs only)
platformctl device list --output quiet
```

## Protocol

The Unix socket uses gRPC over Unix domain socket with the same protobuf messages as the TCP gRPC endpoint.

### Request Flow

```
Client -> Unix Socket -> gRPC Server -> Device Service -> Response
```

### Message Format

Standard gRPC over HTTP/2 framing:

```
Length-Prefixed Message:
+----------------+------------------+
| Length (4B)    | Protobuf Payload |
+----------------+------------------+
```

## Go Client Example

```go
package main

import (
    "context"
    "fmt"

    pb "github.com/jeremyhahn/go-trusted-platform/api/v1/device"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    conn, err := grpc.DialContext(context.Background(),
        "unix:///run/platformd.sock",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    client := pb.NewDeviceServiceClient(conn)

    // List devices
    resp, err := client.ListDevices(context.Background(), &pb.ListDevicesRequest{
        Page:     1,
        PageSize: 10,
    })
    if err != nil {
        panic(err)
    }

    for _, device := range resp.Devices {
        fmt.Printf("Device: %d - %s (%s)\n", device.Id, device.Serial, device.Model)
    }
}
```

## Unix Socket Permissions

The socket is created with restricted permissions:

| Permission | Value | Description |
|------------|-------|-------------|
| Owner | root | Socket owner |
| Group | platformd | Service group |
| Mode | 0660 | Owner/group read-write |

Access requires membership in the `platformd` group:

```bash
# Add user to platformd group
sudo usermod -aG platformd $USER

# Verify access
ls -la /run/platformd.sock
srw-rw---- 1 root platformd 0 Jan 15 10:00 /run/platformd.sock
```

## Security Considerations

1. **No network exposure**: Unix socket is local only
2. **File permissions**: Restricted to platformd group
3. **No TLS required**: Communication is local and protected by filesystem permissions
4. **Audit logging**: All operations logged with caller UID/GID

## Error Handling

Unix socket-specific errors:

| Error | Description |
|-------|-------------|
| ENOENT | Socket file not found |
| EACCES | Permission denied |
| ECONNREFUSED | Service not running |

Application errors follow gRPC status codes. See [api-reference.md](api-reference.md) for complete error code mapping.

## Systemd Integration

The socket is managed by systemd socket activation:

```ini
# /etc/systemd/system/platformd.socket
[Unit]
Description=Platform Daemon Socket

[Socket]
ListenStream=/run/platformd.sock
SocketMode=0660
SocketUser=root
SocketGroup=platformd

[Install]
WantedBy=sockets.target
```

```bash
# Enable socket activation
sudo systemctl enable platformd.socket
sudo systemctl start platformd.socket

# Check socket status
sudo systemctl status platformd.socket
```

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

The socket serves the whole `DeviceService`, including `CreateTemplate`
and `CreateProfileFromTemplate` ([api-reference-grpc.md](api-reference-grpc.md#device-templates)).
`platformctl` has no device template verb, so reach those two through the
Go SDK (`device.Client.CreateTemplate`,
`device.Client.CreateProfileFromTemplate`) or a gRPC client on this socket.

## CLI Usage

The `platformctl` CLI uses the Unix socket by default for local operations.

### Device Operations

```bash
# Register device
platformctl device register \
  --serial SRV-2024-001 \
  --model TrustedServer-v2 \
  --ek-cert /path/to/ek.crt \
  --hash-algo 11

# Get device
platformctl device get 1234567890

# Get device by serial
platformctl device find-serial SRV-2024-001

# Delete device
platformctl device delete 1234567890

# List devices
platformctl device list --page 1 --page-size 10

# Record the device's attestation certificate without re-enrolling it
# (fail-closed; add --reissue to let the CA issue a fresh one)
platformctl device attest-cert record 1234567890

# Clear a refused (non-compliant) certificate so the device is denied
# rather than quarantined until a compliant one is recorded
platformctl device attest-cert record 1234567890 --clear-on-refusal

# Disable a device: block its switch port, record it suspended
platformctl device disable 1234567890 --reason "decommissioning rack 3"

# Re-admit it to quarantine; it is restored only once it re-attests
platformctl device enable 1234567890
```

`platformctl` has **no `device attest` verb** — `pkg/cli/commands/device`
registers `list`, `get`, `find-serial`, `register`, `delete`, `disable`,
`enable`, `profile` and `attest-cert` only. Device attestation is reached over gRPC / Unix
(`AttestDevice`), REST (`POST /api/v1/devices/{id}/attest`), QUIC (`0x3A`)
and MCP (`device_attest`); see [`api.md`](api.md) §2.

### Profile Operations

```bash
# Create profile (create, update, assign and unassign live under device profile)
platformctl device profile create \
  --name "IoT Sensor Profile" \
  --model IoT-Sensor-v1 \
  --role iot

# Get, list and delete a profile (platformctl profile runs the same verbs)
platformctl profile get 1
platformctl profile list
platformctl profile delete 1

# Update profile
platformctl device profile update 1 --name "IoT Sensor Profile v2"

# Find the matching profile; MAC and serial match by prefix, model exactly.
# No match exits non-zero with "no profile matches ..." (gRPC NOT_FOUND).
platformctl profile match \
  --mac 52:54:00:aa:bb:cc \
  --serial IOT-001 \
  --model IoT-Sensor-v1

# Name the certificate the attestation collector verifies nodes of a
# profile against (the pb DeviceProfile tls_server_name; docs/device/cli.md §3),
# then confirm it over the same socket
platformctl device profile list
platformctl device profile update 123 --tls-server-name compute.example.internal
platformctl device profile get 123 --output json

# Clear it again (sets UpdateProfileRequest.clear_tls_server_name)
platformctl device profile update 123 --clear-tls-server-name
```

Profile reads over the socket carry the read-only `pcr_baseline` and
`tls_server_name` like gRPC (`api-reference-grpc.md`); `platformctl device
profile` prints both. An update clears `tls_server_name` only through
`clear_tls_server_name`, exactly as gRPC does (`docs/device/api.md` §3.2).

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
5. **Boot requests are refused**: `BootCertificate` and `BootDelivery`
   ([api.md §4.6](api.md#46-diskless-boot-delivery-690)) are served on the
   socket through the same service as every other transport, but they bind
   the proof and the evidence to a TLS channel nonce. The socket has no TLS
   connection, so the SDK refuses before sending
   (`*transport.ErrChannelBindingUnavailable`, Transport `unix`) and the
   daemon answers any other client `FailedPrecondition`
   (`ErrBootChannelRequired`) before the boot service runs.
   A diskless node reaches them over REST, gRPC or QUIC.

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

# Unix Socket API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md), the canonical six-transport reference and QUIC category-opcode table.

Unix socket API documentation for local IPC with the Trusted Platform daemon.

## Socket Path

```
/run/platformd.sock
```

## Protocol

The Unix socket exposes a gRPC server. All gRPC services available on the TCP port are also available via the Unix socket.

## Connection

### Go

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func connectUnix() (*grpc.ClientConn, error) {
    dialer := func(ctx context.Context, addr string) (net.Conn, error) {
        return net.Dial("unix", "/run/platformd.sock")
    }

    return grpc.Dial(
        "unix:///run/platformd.sock",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithContextDialer(dialer),
    )
}

func main() {
    conn, err := connectUnix()
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    client := platformv1.NewPlatformDaemonClient(conn)

    // Use client...
}
```

### Python

```python
import grpc
import platform_pb2
import platform_pb2_grpc

# Connect via Unix socket
channel = grpc.insecure_channel('unix:///run/platformd.sock')
stub = platform_pb2_grpc.PlatformDaemonStub(channel)

# Health check
response = stub.GetHealth(platform_pb2.GetHealthRequest())
print(f"Health: {response.status}")
```

### grpcurl

```bash
# Health check
grpcurl -plaintext -unix /run/platformd.sock \
  platform.v1.PlatformDaemon/GetHealth

# List services
grpcurl -plaintext -unix /run/platformd.sock \
  platform.v1.PlatformDaemon/ListServices

# Get status
grpcurl -plaintext -unix /run/platformd.sock \
  platform.v1.PlatformDaemon/GetStatus

# Start service
grpcurl -plaintext -unix /run/platformd.sock \
  -d '{"service": "SERVICE_TYPE_DNS"}' \
  platform.v1.PlatformDaemon/StartService

# Stop service
grpcurl -plaintext -unix /run/platformd.sock \
  -d '{"service": "SERVICE_TYPE_DNS"}' \
  platform.v1.PlatformDaemon/StopService
```

## Available Services

The Unix socket exposes all registered gRPC services:

### PlatformDaemon Service

Core daemon management operations.

| Method | Description |
|--------|-------------|
| GetHealth | System health check |
| GetStatus | Daemon status |
| ListServices | List managed services |
| StartService | Start a service |
| StopService | Stop a service |
| Shutdown | Shutdown daemon |

### VTPMService (when enabled)

Virtual TPM bundle management.

| Method | Description |
|--------|-------------|
| CreateBundle | Create vTPM bundle |
| GetBundle | Get bundle by ID |
| ListBundles | List all bundles |
| DeleteBundle | Delete bundle |

### DeviceService (when enabled)

Device management operations.

| Method | Description |
|--------|-------------|
| RegisterDevice | Register new device |
| GetDevice | Get device by ID |
| ListDevices | List devices |
| DeleteDevice | Delete device |
| UpdateDevice | Update device |

### CAService (when enabled)

Certificate Authority operations.

| Method | Description |
|--------|-------------|
| GetCAInfo | CA information |
| IssueCertificate | Issue certificate |
| GetCertificate | Get certificate |
| ListCertificates | List certificates |
| RevokeCertificate | Revoke certificate |
| RenewCertificate | Renew certificate |
| VerifyCertificate | Verify certificate |
| GetCRL | Get CRL |
| GetCABundle | Get CA bundle |

### KMSService (when enabled)

Key Management Service operations.

Refer to go-quicbaas KMS documentation for available methods.

## Socket Permissions

The daemon creates the socket at `--socket-path` (default
`/run/platformd.sock`) with mode `0660`. Neither the mode nor the group is
configurable, and platformd does not change the socket's group: it is the
group of the platformd process.

### Access Control

A client must own the socket or be a member of its group to connect:

```bash
# Add user to group
sudo usermod -aG trusted-platform myuser

# Verify group membership
groups myuser
```

## CLI Integration

The `platformctl` CLI uses the Unix socket by default:

```bash
# These commands use /run/platformd.sock
platformctl status
platformctl service list
platformctl service start dns
platformctl service stop dns
platformctl health
```

Override socket path. platformctl has no `--socket` flag; name the socket in a
local context and select it with `--context` (or `PLATFORMCTL_CONTEXT`):

```bash
platformctl context add custom --socket-path /tmp/platformd.sock
platformctl --context custom status
```

## Socket Management

### Check Socket Status

```bash
# Verify socket exists
ls -la /run/platformd.sock

# Check socket type
file /run/platformd.sock

# Test connectivity
nc -U /run/platformd.sock
```

### Cleanup Stale Socket

The daemon automatically cleans up stale sockets on startup when configured:

```go
unix.WithCleanupOldSocket(true)
```

Manual cleanup:

```bash
sudo rm /run/platformd.sock
```

## Security Considerations

### Process Credentials

The Unix socket server can verify client credentials:

- UID/GID of connecting process
- PID for audit logging
- Supplementary groups

### No Network Exposure

Unix sockets are not accessible over the network, providing:

- Local-only access
- No network attack surface
- Faster than TCP loopback
- Kernel-enforced security

### Recommended Practices

1. Use restrictive socket permissions (`0660` or `0600`)
2. Create dedicated group for daemon access
3. Avoid world-readable/writable sockets
4. Monitor socket access via audit logs

## Performance

Unix sockets offer better performance than TCP for local communication:

| Aspect | Unix Socket | TCP Loopback |
|--------|-------------|--------------|
| Latency | Lower | Higher |
| Overhead | Minimal | TCP/IP stack |
| Context switches | Fewer | More |
| Security | Kernel-enforced | Application-level |

## Examples

### Health Check Script

```bash
#!/bin/bash

SOCKET="/run/platformd.sock"

if [ ! -S "$SOCKET" ]; then
    echo "Socket not found"
    exit 1
fi

health=$(grpcurl -plaintext -unix "$SOCKET" \
  platform.v1.PlatformDaemon/GetHealth 2>/dev/null)

if echo "$health" | grep -q "HEALTH_STATUS_HEALTHY"; then
    echo "Platform is healthy"
    exit 0
else
    echo "Platform is unhealthy"
    exit 1
fi
```

### Service Management Script

```bash
#!/bin/bash

SOCKET="/run/platformd.sock"
SERVICE="$1"
ACTION="$2"

case "$ACTION" in
    start)
        grpcurl -plaintext -unix "$SOCKET" \
          -d "{\"service\": \"SERVICE_TYPE_${SERVICE^^}\"}" \
          platform.v1.PlatformDaemon/StartService
        ;;
    stop)
        grpcurl -plaintext -unix "$SOCKET" \
          -d "{\"service\": \"SERVICE_TYPE_${SERVICE^^}\"}" \
          platform.v1.PlatformDaemon/StopService
        ;;
    *)
        echo "Usage: $0 <service> <start|stop>"
        exit 1
        ;;
esac
```

### Systemd Integration

```ini
[Unit]
Description=Trusted Platform Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/platformd
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RuntimeDirectory=trusted-platform

[Install]
WantedBy=multi-user.target
```

Health check via systemd:

```ini
[Service]
ExecStartPost=/usr/local/bin/platformctl health
```

## See Also

- [API Reference](api-reference.md)
- [gRPC API Reference](api-reference-grpc.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)

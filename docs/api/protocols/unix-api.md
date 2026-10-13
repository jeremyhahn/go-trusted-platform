# Unix Socket API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](../../daemon/api.md) and each feature's `api.md`.

The Unix Socket API provides the fastest possible access to platform services through gRPC over Unix Domain Sockets, designed for local CLI tools and system services.

## Connection Configuration

### Socket Path

Default path: `/run/platformd.sock`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORMCTL_CONTEXT` | platformctl context to use; a local context names the socket | the config's current context (`/run/platformd.sock`) |

### Requirements

- **Root privileges required**: Unix socket connections require root (uid 0)
- **Local host only**: Cannot be used for remote connections
- **Kernel security**: Access controlled by file system permissions

### Go SDK Configuration

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"

client, err := platform.NewClient(ctx,
    platform.WithUnixSocket("/run/platformd.sock"),
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithTimeout(5*time.Second),
    platform.WithMaxMessageSize(8*1024*1024),
)
```

### Direct gRPC Connection

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

// Connect to Unix socket
conn, err := grpc.DialContext(ctx, "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
    grpc.WithDefaultCallOptions(
        grpc.MaxCallRecvMsgSize(4*1024*1024),
        grpc.MaxCallSendMsgSize(4*1024*1024),
    ),
)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Create service clients
daemonClient := platformv1.NewPlatformDaemonClient(conn)
caClient := platformv1.NewCAServiceClient(conn)
```

## Socket Permissions

### Default Permissions

```bash
$ ls -la /run/platformd.sock
srw-rw---- 1 root platform 0 Jan 20 10:00 /run/platformd.sock
```

### Access Control

| User/Group | Access | Use Case |
|------------|--------|----------|
| root | Full | System administration |
| platform group | Full | Platform services |
| Other | None | Blocked by default |

### Allowing Non-Root Access

Add users to the `platform` group:

```bash
# Add user to platform group
sudo usermod -aG platform username

# Verify membership
groups username
```

Or configure socket permissions in platform daemon config:

```yaml
# /etc/platformd/config.yaml
socket:
  path: /run/platformd.sock
  mode: 0660
  group: platform
```

## Performance Characteristics

### Latency Comparison

```
+--------------------+----------+
| Protocol           | Latency  |
+--------------------+----------+
| Unix Socket        | ~0.1ms   |
| gRPC (localhost)   | ~0.5ms   |
| gRPC (remote)      | ~1-5ms   |
| REST (localhost)   | ~1ms     |
| REST (remote)      | ~5-20ms  |
+--------------------+----------+
```

### Throughput

```
+--------------------+------------------+
| Protocol           | Requests/Second  |
+--------------------+------------------+
| Unix Socket        | ~50,000          |
| gRPC (localhost)   | ~30,000          |
| REST (localhost)   | ~10,000          |
+--------------------+------------------+
```

### Why Unix Socket is Fastest

1. **No network stack**: Bypasses TCP/IP entirely
2. **No TLS overhead**: Security provided by kernel (file permissions)
3. **Zero-copy potential**: Kernel can optimize buffer handling
4. **No serialization of addresses**: No IP/port parsing

## Local CLI Usage

### platformctl Examples

```bash
# Use Unix socket by default (when running as root)
sudo platformctl ca info

# Another socket path: name it in a local context, then select it
sudo platformctl context add custom --socket-path /path/to/custom.sock
sudo platformctl --context custom ca info

# Issue certificate
sudo platformctl ca issue \
    --common-name server.example.com \
    --valid-days 365

# List devices
sudo platformctl device list

# Get TPM info
sudo platformctl tpm info

# Create vTPM
sudo platformctl vtpm create --name vm-001-vtpm

# Attestation quote
sudo platformctl attestation quote --pcrs 0,1,7
```

### Shell Script Integration

```bash
#!/bin/bash
set -e

SOCKET="/run/platformd.sock"

# Check socket exists
if [ ! -S "$SOCKET" ]; then
    echo "Platform daemon not running"
    exit 1
fi

# Get platform version
VERSION=$(platformctl version)
echo "Platform version: $VERSION"

# Issue certificate for this host
HOSTNAME=$(hostname -f)
platformctl ca issue \
    --common-name "$HOSTNAME" \
    --dns-names "$HOSTNAME,localhost" \
    --output /etc/ssl/certs/server.crt

echo "Certificate issued for $HOSTNAME"
```

## Service Integration

### Systemd Service Example

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Application
After=platformd.service
Requires=platformd.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/myapp
Environment=PLATFORM_SOCKET=/run/platformd.sock

[Install]
WantedBy=multi-user.target
```

### Go Service Integration

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        cancel()
    }()

    // Connect via Unix socket
    socketPath := os.Getenv("PLATFORM_SOCKET")
    if socketPath == "" {
        socketPath = "/run/platformd.sock"
    }

    client, err := platform.NewClient(ctx,
        platform.WithUnixSocket(socketPath),
        platform.WithOnlyProtocol(platform.ProtocolUnix),
    )
    if err != nil {
        log.Fatalf("Failed to connect to platform daemon: %v", err)
    }
    defer client.Close()

    // Verify connection
    if err := client.Ping(ctx); err != nil {
        log.Fatalf("Platform daemon not responding: %v", err)
    }

    log.Println("Connected to platform daemon")

    // Your application logic here
    runApplication(ctx, client)
}

func runApplication(ctx context.Context, client platform.Client) {
    // Example: Monitor device attestation
    for {
        select {
        case <-ctx.Done():
            return
        default:
            // Periodic attestation check
            devices, err := client.Device().List(ctx, &platformv1.ListDevicesRequest{})
            if err != nil {
                log.Printf("Error listing devices: %v", err)
                continue
            }

            for _, device := range devices.Devices {
                _, err := client.Device().Attest(ctx, &platformv1.AttestDeviceRequest{
                    DeviceId: device.Id,
                })
                if err != nil {
                    log.Printf("Device %s attestation failed: %v", device.Id, err)
                }
            }
        }
    }
}
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `socket not found` | Daemon not running | Start platformd service |
| `permission denied` | Not root/platform group | Run as root or add to group |
| `connection refused` | Daemon crashed | Check daemon logs |
| `socket busy` | Too many connections | Implement connection pooling |

### Error Handling Example

```go
import (
    "errors"
    "os"
    "syscall"
)

client, err := platform.NewClient(ctx,
    platform.WithUnixSocket("/run/platformd.sock"),
    platform.WithOnlyProtocol(platform.ProtocolUnix),
)
if err != nil {
    var connErr platform.ErrConnectionFailed
    if errors.As(err, &connErr) {
        // Check underlying error
        if os.IsNotExist(connErr.Err) {
            log.Fatal("Platform daemon is not running. Start with: systemctl start platformd")
        }
        if os.IsPermission(connErr.Err) {
            log.Fatal("Permission denied. Run as root or add user to 'platform' group")
        }
        if errors.Is(connErr.Err, syscall.ECONNREFUSED) {
            log.Fatal("Connection refused. Platform daemon may have crashed")
        }
    }
    log.Fatalf("Failed to connect: %v", err)
}
```

## Security Considerations

### No TLS Required

Unix sockets rely on kernel-level security:

- **File permissions**: Control who can connect
- **Credential passing**: Kernel provides peer credentials (uid/gid/pid)
- **No network exposure**: Cannot be accessed remotely

### Peer Credential Verification

The server can verify client identity:

```go
// Server-side peer credential check
import "golang.org/x/sys/unix"

func getPeerCredentials(conn net.Conn) (*unix.Ucred, error) {
    unixConn, ok := conn.(*net.UnixConn)
    if !ok {
        return nil, errors.New("not a unix connection")
    }

    file, err := unixConn.File()
    if err != nil {
        return nil, err
    }
    defer file.Close()

    return unix.GetsockoptUcred(int(file.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
}

// Usage
cred, _ := getPeerCredentials(conn)
log.Printf("Client: uid=%d, gid=%d, pid=%d", cred.Uid, cred.Gid, cred.Pid)
```

### Best Practices

1. **Run daemon as dedicated user**: `platformd:platform`
2. **Restrict socket permissions**: `0660` or `0600`
3. **Use group-based access**: Add trusted users to `platform` group
4. **Monitor socket access**: Log all connections with peer credentials
5. **Avoid world-readable sockets**: Never use `0666` permissions

## Complete Example

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

func main() {
    // Check if running as root
    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root")
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Connect via Unix socket
    client, err := platform.NewClient(ctx,
        platform.WithUnixSocket("/run/platformd.sock"),
        platform.WithOnlyProtocol(platform.ProtocolUnix),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.Close()

    log.Printf("Connected via %s", client.Protocol())

    // Get platform version
    version, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    log.Printf("Platform version: %s", version.Version)

    // Get CA info
    caInfo, err := client.CA().GetInfo(ctx, &platformv1.GetCAInfoRequest{})
    if err != nil {
        log.Fatalf("Failed to get CA info: %v", err)
    }
    log.Printf("CA: %s, Valid until: %s", caInfo.Subject, caInfo.NotAfter)

    // Get TPM info
    tpmInfo, err := client.TPM().GetInfo(ctx, &platformv1.GetTPMInfoRequest{})
    if err != nil {
        log.Fatalf("Failed to get TPM info: %v", err)
    }
    log.Printf("TPM: %s, Firmware: %s", tpmInfo.Manufacturer, tpmInfo.FirmwareVersion)

    // Issue a certificate
    cert, err := client.CA().Issue(ctx, &platformv1.IssueCertificateRequest{
        CommonName: "local-service.example.com",
        DnsNames:   []string{"localhost"},
        ValidDays:  30,
    })
    if err != nil {
        log.Fatalf("Failed to issue certificate: %v", err)
    }
    log.Printf("Issued certificate: serial=%s", cert.Serial)
}
```

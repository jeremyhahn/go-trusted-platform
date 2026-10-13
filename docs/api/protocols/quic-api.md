# QUIC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](../../daemon/api.md) and each feature's `api.md`.

The QUIC API provides low-latency, connection-resilient access to platform services over UDP with mandatory TLS 1.3 encryption.

## Connection Configuration

### Server Address

```
{host}:{port}
```

Default port: **9444**

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_QUIC_ADDR` | Full address | `localhost:9444` |
| `PLATFORM_QUIC_PORT` | Port number | `9444` |

### Go SDK Configuration

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"

client, err := platform.NewClient(ctx,
    platform.WithQUICAddr("platform.example.com:9444"),
    platform.WithTLSConfig(&tls.Config{
        MinVersion: tls.VersionTLS13,
        NextProtos: []string{"platform-quic"},
    }),
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithTimeout(10*time.Second),
)
```

### Direct QUIC Connection

```go
// The QUIC wire contract (frames, opcodes, status codes, client) is the
// SDK package sdk/go/wire/quicwire; the daemon imports the same package.
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"

clientConfig := &quicwire.ClientConfig{
    ServerAddr:         "platform.example.com:9444",
    TLSConfig:          tlsConfig,
    Timeout:            10 * time.Second,
    MaxIdleTimeout:     30 * time.Second,
    NextProtos:         []string{"platform-quic"},
}

client, err := quicwire.NewClient(clientConfig)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## Authentication

### Token-Based

```go
// Set token on QUIC adapter
adapter := client.(*quicAdapter)
adapter.SetToken(jwtToken)

// Or use with direct client
quicClient.SetToken(jwtToken)
```

### mTLS Authentication

```go
// Load client certificate
cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")

// Configure mTLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
    MinVersion:   tls.VersionTLS13,
    NextProtos:   []string{"platform-quic"},
}

client, err := platform.NewClient(ctx,
    platform.WithQUICAddr("platform.example.com:9444"),
    platform.WithTLSConfig(tlsConfig),
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
)
```

## Opcode-Based Routing

QUIC uses a binary protocol with opcode-based routing for efficient dispatch. Each operation is identified by a single-byte opcode.

### Protocol Frame Format

```
+--------+--------+--------+--------+--------+--------+
| Opcode |  Flags | Payload Length  |     Payload     |
|  (1B)  |  (1B)  |      (2B)       |    (variable)   |
+--------+--------+--------+--------+--------+--------+
```

### Health Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x01` | `OpHealth` | Health check |
| `0x02` | `OpLiveness` | Liveness probe |
| `0x03` | `OpReadiness` | Readiness probe |

### CA Service Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x10` | `OpCAInfo` | Get CA information |
| `0x11` | `OpCAIssue` | Issue certificate |
| `0x12` | `OpCAGet` | Get certificate |
| `0x13` | `OpCAList` | List certificates |
| `0x14` | `OpCARevoke` | Revoke certificate |
| `0x15` | `OpCARenew` | Renew certificate |
| `0x16` | `OpCAVerify` | Verify certificate |
| `0x17` | `OpCACRL` | Get CRL |
| `0x18` | `OpCABundle` | Get CA bundle |

### IAM Service Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x20` | `OpIAMUserCreate` | Create user |
| `0x21` | `OpIAMUserDelete` | Delete user |
| `0x22` | `OpIAMUserGet` | Get user |
| `0x23` | `OpIAMUserList` | List users |
| `0x24` | `OpIAMRoleCreate` | Create role |
| `0x25` | `OpIAMRoleDelete` | Delete role |
| `0x26` | `OpIAMRoleGet` | Get role |
| `0x27` | `OpIAMRoleList` | List roles |
| `0x28` | `OpIAMRoleAssign` | Assign role |
| `0x29` | `OpIAMRoleRevoke` | Revoke role |
| `0x2A` | `OpIAMAuthenticate` | Authenticate |
| `0x2B` | `OpIAMCheckPermission` | Check permission |
| `0x2C` | `OpIAMTokenCreate` | Create token |
| `0x2D` | `OpIAMTokenRevoke` | Revoke token |
| `0x2E` | `OpIAMTokenVerify` | Verify token |

### KMS Service Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x30` | `OpKMSGenerateKey` | Create key |
| `0x31` | `OpKMSImportKey` | Import key |
| `0x32` | `OpKMSGetKey` | Get key |
| `0x33` | `OpKMSListKeys` | List keys |
| `0x34` | `OpKMSDeleteKey` | Delete key |
| `0x35` | `OpKMSRotateKey` | Rotate key |
| `0x36` | `OpKMSEncrypt` | Encrypt data |
| `0x37` | `OpKMSDecrypt` | Decrypt data |
| `0x38` | `OpKMSSign` | Sign data |
| `0x39` | `OpKMSVerify` | Verify signature |
| `0x3A` | `OpKMSGenerateRandom` | Generate random |
| `0x3B` | `OpKMSGenerateDataKey` | Generate data key |

### vTPM Service Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x40` | `OpVTPMCreate` | Create vTPM |
| `0x41` | `OpVTPMDelete` | Delete vTPM |
| `0x42` | `OpVTPMStart` | Start vTPM |
| `0x43` | `OpVTPMStop` | Stop vTPM |
| `0x44` | `OpVTPMList` | List vTPMs |
| `0x45` | `OpVTPMGetState` | Get state |
| `0x46` | `OpVTPMQuote` | Get quote |
| `0x47` | `OpVTPMSeal` | Seal data |
| `0x48` | `OpVTPMUnseal` | Unseal data |
| `0x49` | `OpVTPMExtendPCR` | Extend PCR |
| `0x4A` | `OpVTPMReadPCR` | Read PCR |

### Attestation Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x50` | `OpAttestQuote` | Get quote |
| `0x51` | `OpAttestVerify` | Verify quote |
| `0x52` | `OpAttestGetEK` | Get EK |
| `0x53` | `OpAttestGetAK` | Get AK |
| `0x54` | `OpAttestChallenge` | Create challenge |
| `0x55` | `OpAttestResponse` | Verify challenge |

### Device Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x60` | `OpDeviceRegister` | Register device |
| `0x61` | `OpDeviceUnregister` | Delete device |
| `0x62` | `OpDeviceGet` | Get device |
| `0x63` | `OpDeviceList` | List devices |
| `0x64` | `OpDeviceUpdate` | Update device |
| `0x65` | `OpDeviceAttest` | Attest device |

## Performance Benefits

### Comparison with TCP-based protocols

```
                    Connection Time
+------------------------------------------------+
| Protocol    | Initial     | Resumed            |
+------------------------------------------------+
| gRPC (TCP)  | 3 RTT       | 1 RTT              |
| REST (TCP)  | 3 RTT       | 1 RTT              |
| QUIC        | 1 RTT       | 0 RTT              |
+------------------------------------------------+

                    Latency Profile
+------------------------------------------------+
| Scenario                | gRPC    | QUIC       |
+------------------------------------------------+
| First request           | 50ms    | 20ms       |
| Subsequent (same conn)  | 5ms     | 4ms        |
| After network change    | 50ms    | 5ms        |
| Packet loss recovery    | 15ms    | 3ms        |
+------------------------------------------------+
```

### Key Advantages

1. **Faster Connection Establishment**
   - 1-RTT for new connections
   - 0-RTT for resumed connections

2. **Connection Migration**
   - Seamless network changes (WiFi to cellular)
   - No reconnection required

3. **Head-of-Line Blocking Prevention**
   - Multiplexed streams
   - Independent packet delivery

4. **Built-in Encryption**
   - TLS 1.3 mandatory
   - Encrypted headers

## When to Use QUIC

### Ideal Use Cases

- **Mobile Applications**: Connection migration handles network changes
- **High-Latency Networks**: 0-RTT resumption reduces perceived latency
- **Unreliable Networks**: Better packet loss handling
- **Real-time Operations**: Lower latency for attestation flows

### Not Recommended For

- **High-Throughput Bulk Transfers**: TCP still better for sustained throughput
- **Firewall-Restricted Environments**: UDP may be blocked
- **Legacy Systems**: May not support QUIC

## Error Handling

### Status Codes

| Status | Value | Description |
|--------|-------|-------------|
| `StatusOK` | `0x00` | Success |
| `StatusInvalidRequest` | `0x01` | Invalid request |
| `StatusNotFound` | `0x02` | Not found |
| `StatusUnauthorized` | `0x03` | Unauthorized |
| `StatusInternalError` | `0x04` | Internal error |
| `StatusTimeout` | `0x05` | Timeout |
| `StatusAlreadyExists` | `0x06` | Already exists |
| `StatusPermissionDenied` | `0x07` | Permission denied |
| `StatusResourceExhausted` | `0x08` | Rate limited |
| `StatusInvalidArgument` | `0x09` | Invalid argument |
| `StatusUnavailable` | `0x0A` | Unavailable |
| `StatusNotImplemented` | `0x0B` | Not implemented |

### Error Handling Example

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"

err := quicClient.Send(ctx, quicwire.OpCAIssue, request, response)
if err != nil {
    // Check for protocol errors
    var protoErr *quicwire.ErrProtocol
    if errors.As(err, &protoErr) {
        switch protoErr.Status {
        case quicwire.StatusInvalidRequest:
            log.Printf("Invalid request: %s", protoErr.Message)
        case quicwire.StatusUnauthorized:
            log.Printf("Unauthorized: %s", protoErr.Message)
        case quicwire.StatusTimeout:
            log.Printf("Request timed out")
        default:
            log.Printf("Error: %s", protoErr.Message)
        }
        return
    }

    // Check for connection errors
    if errors.Is(err, quicwire.ErrClientClosed) {
        log.Printf("Connection closed")
        return
    }

    if errors.Is(err, quicwire.ErrStreamFailed) {
        log.Printf("Stream failed, retrying...")
        return
    }

    log.Printf("Unknown error: %v", err)
}
```

## Connection Management

### Configuration Options

```go
clientConfig := &quicwire.ClientConfig{
    // Server address
    ServerAddr: "platform.example.com:9444",

    // TLS configuration
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS13,
        NextProtos: []string{"platform-quic"},
    },

    // Timeouts
    Timeout:        10 * time.Second,  // Request timeout
    MaxIdleTimeout: 30 * time.Second,  // Connection idle timeout

    // ALPN protocols
    NextProtos: []string{"platform-quic"},
}
```

### Connection Pooling

```go
// QUIC multiplexes streams over a single connection
// No explicit pooling needed - one connection handles all requests
client, err := quicwire.NewClient(config)
if err != nil {
    log.Fatal(err)
}

// All operations use the same underlying connection
go func() { client.Send(ctx, opcode1, req1, resp1) }()
go func() { client.Send(ctx, opcode2, req2, resp2) }()
go func() { client.Send(ctx, opcode3, req3, resp3) }()
```

### Connection Recovery

```go
// QUIC handles connection migration automatically
// If the network changes, the connection continues

// Example: Mobile app switching from WiFi to cellular
// The client continues working without reconnection

// For explicit reconnection after errors:
if !client.IsConnected() {
    client.Close()
    client, err = quicwire.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
}
```

## Complete Example

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    "time"

    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Create QUIC client via SDK
    client, err := platform.NewClient(ctx,
        platform.WithQUICAddr("platform.example.com:9444"),
        platform.WithTLSConfig(&tls.Config{
            MinVersion: tls.VersionTLS13,
            NextProtos: []string{"platform-quic"},
        }),
        platform.WithOnlyProtocol(platform.ProtocolQUIC),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.Close()

    log.Printf("Connected via QUIC to %s", client.Protocol())

    // Use services as normal - protocol is abstracted
    version, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    log.Printf("Platform version: %s", version.Version)

    // Issue certificate over QUIC
    cert, err := client.CA().Issue(ctx, &platformv1.IssueCertificateRequest{
        CommonName: "mobile-app.example.com",
        ValidDays:  30,
    })
    if err != nil {
        log.Fatalf("Failed to issue certificate: %v", err)
    }
    log.Printf("Certificate issued: %s", cert.Serial)
}
```

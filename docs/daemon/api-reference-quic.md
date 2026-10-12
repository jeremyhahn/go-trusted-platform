# QUIC API Reference

QUIC protocol API documentation for the Trusted Platform daemon.

## Connection

```
UDP localhost:9444
```

QUIC always uses TLS encryption.

## Protocol Format

### Request

```
+--------+--------+--------+---------+
| Token  | Opcode | Length | Payload |
| 4 byte | 1 byte | 2 byte | N bytes |
+--------+--------+--------+---------+
```

### Response

```
+--------+--------+---------+
| Status | Length | Payload |
| 1 byte | 2 byte | N bytes |
+--------+--------+---------+
```

## Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | StatusOK | Success |
| 0x01 | StatusInvalidRequest | Malformed request |
| 0x02 | StatusInvalidArgument | Invalid argument |
| 0x03 | StatusUnauthorized | Authentication required |
| 0x04 | StatusNotFound | Resource not found |
| 0x05 | StatusInternalError | Server error |
| 0x06 | StatusUnavailable | Service unavailable |
| 0x07 | StatusNotImplemented | Not implemented |

## Operations

### Health Operations (0x00-0x02)

#### OpHealth (0x00)

System health check.

**Request:**
```
Opcode: 0x00
Payload: HealthCheckRequest (optional)
```

```go
type HealthCheckRequest struct {
    Component string `codec:"component"` // Optional: specific component
}
```

**Response:**
```go
type HealthCheckResponse struct {
    Healthy    bool              `codec:"healthy"`
    Status     string            `codec:"status"`
    Components map[string]string `codec:"components"`
    Timestamp  int64             `codec:"timestamp"`
}
```

---

#### OpLiveness (0x01)

Simple liveness probe.

**Request:**
```
Opcode: 0x01
Payload: (empty)
```

**Response:**
```go
type LivenessResponse struct {
    Alive     bool  `codec:"alive"`
    Timestamp int64 `codec:"timestamp"`
}
```

---

#### OpReadiness (0x02)

Service readiness check.

**Request:**
```
Opcode: 0x02
Payload: (empty)
```

**Response:**
```go
type ReadinessResponse struct {
    Ready     bool              `codec:"ready"`
    Services  map[string]string `codec:"services"`
    Timestamp int64             `codec:"timestamp"`
}
```

### vTPM Operations (0x10-0x1F)

#### OpVTPMCreate (0x10)

Create a vTPM bundle.

**Request:**
```go
type VTPMCreateRequest struct {
    Hostname          string            `codec:"hostname"`
    EKAlgorithm       string            `codec:"ek_algorithm"` // RSA, ECC
    SecureBootEnabled bool              `codec:"secure_boot_enabled"`
    Labels            map[string]string `codec:"labels"`
    TemplateID        string            `codec:"template_id"`
}
```

**Response:**
```go
type VTPMCreateResponse struct {
    ID        string `codec:"id"`
    Hostname  string `codec:"hostname"`
    CreatedAt int64  `codec:"created_at"`
    Timestamp int64  `codec:"timestamp"`
}
```

---

#### OpVTPMDelete (0x11)

Delete a vTPM bundle.

**Request:**
```go
type VTPMDeleteRequest struct {
    ID string `codec:"id"`
}
```

**Response:**
```go
type VTPMDeleteResponse struct {
    ID        string `codec:"id"`
    Deleted   bool   `codec:"deleted"`
    Timestamp int64  `codec:"timestamp"`
}
```

---

#### OpVTPMList (0x12)

List vTPM bundles.

**Request:**
```go
type VTPMListRequest struct {
    Mode   string            `codec:"mode"`   // template, pre-assigned
    Labels map[string]string `codec:"labels"`
    Limit  int               `codec:"limit"`
    Offset int               `codec:"offset"`
}
```

**Response:**
```go
type VTPMListResponse struct {
    Bundles   []*VTPMBundleSummary `codec:"bundles"`
    Total     int                  `codec:"total"`
    Timestamp int64                `codec:"timestamp"`
}

type VTPMBundleSummary struct {
    ID        string `codec:"id"`
    Hostname  string `codec:"hostname"`
    Mode      string `codec:"mode"`
    CreatedAt int64  `codec:"created_at"`
}
```

---

#### OpVTPMGetState (0x13)

Get vTPM state.

**Request:**
```go
type VTPMGetStateRequest struct {
    ID string `codec:"id"`
}
```

**Response:**
```go
type VTPMGetStateResponse struct {
    ID                string `codec:"id"`
    Hostname          string `codec:"hostname"`
    Mode              string `codec:"mode"`
    EKAlgorithm       string `codec:"ek_algorithm"`
    SecureBootEnabled bool   `codec:"secure_boot_enabled"`
    CreatedAt         int64  `codec:"created_at"`
    Timestamp         int64  `codec:"timestamp"`
}
```

### Certificate Operations (0x80-0x8F)

Certificate operations are mapped to CA operations:

| Opcode | Operation | Maps To |
|--------|-----------|---------|
| 0x80 | OpCertIssue | OpCAIssue |
| 0x81 | OpCertRevoke | OpCARevoke |
| 0x82 | OpCertRenew | OpCARenew |
| 0x83 | OpCertGet | OpCAGet |
| 0x84 | OpCertList | OpCAList |
| 0x85 | OpCertVerify | OpCAVerify |
| 0x86 | OpCertGetChain | OpCABundle |
| 0x87 | OpCertGetCRL | OpCACRL |

### CA Operations (0xA0-0xAF)

#### OpCAInfo (0xA0)

Get CA information.

#### OpCAIssue (0xA1)

Issue a new certificate.

#### OpCAGet (0xA2)

Get certificate by serial.

#### OpCAList (0xA3)

List certificates.

#### OpCARevoke (0xA4)

Revoke a certificate.

#### OpCARenew (0xA5)

Renew a certificate.

#### OpCAVerify (0xA6)

Verify a certificate.

#### OpCACRL (0xA7)

Get Certificate Revocation List.

#### OpCABundle (0xA8)

Get CA certificate bundle.

### DNS Operations (0x20-0x2F)

DNS operations are currently not implemented via QUIC.

### Device Operations (0x30-0x3F)

Device operations are currently not implemented via QUIC.

## Encoding

All payloads use MessagePack encoding via the `codec` package.

### Encoding Example (Go)

The wire contract — frames, opcodes, status codes, codecs and the client — is
the SDK package `sdk/go/wire/quicwire`; the daemon's handlers import the same
package.

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Encode request
req := &VTPMCreateRequest{
    Hostname:    "myhost",
    EKAlgorithm: "RSA",
}
payload, err := quicwire.EncodePayload(req)
if err != nil {
    return err
}

// Decode response
var resp VTPMCreateResponse
if err := quicwire.DecodePayload(responsePayload, &resp); err != nil {
    return err
}
```

## Examples

### Go Client

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func main() {
    // Create client (TLS 1.3, ALPN "platform-quic", system roots)
    client, err := quicwire.NewClient(quicwire.DefaultClientConfig("localhost:9444"))
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Health check
    if err := client.Health(context.Background()); err != nil {
        log.Fatal(err)
    }
    log.Print("healthy")
}
```

### Create vTPM Bundle

`Send` encodes the request, sends it under the opcode and decodes the response
payload. A non-OK status byte comes back as `*quicwire.ErrProtocol`.

```go
req := &VTPMCreateRequest{
    Hostname:          "device-001",
    EKAlgorithm:       "RSA",
    SecureBootEnabled: true,
    Labels: map[string]string{
        "environment": "production",
    },
}

var result VTPMCreateResponse
if err := client.Send(ctx, quicwire.OpVTPMCreate, req, &result); err != nil {
    log.Fatal(err)
}
log.Printf("Created vTPM: %s", result.ID)
```

### List vTPM Bundles

```go
req := &VTPMListRequest{
    Mode:   "pre-assigned",
    Limit:  100,
    Offset: 0,
}

var result VTPMListResponse
if err := client.Send(ctx, quicwire.OpVTPMList, req, &result); err != nil {
    log.Fatal(err)
}
log.Printf("Found %d bundles", result.Total)
```

## Error Handling

```go
var state VTPMGetStateResponse
err := client.Send(ctx, quicwire.OpVTPMGetState, req, &state)

var protoErr *quicwire.ErrProtocol
if errors.As(err, &protoErr) {
    log.Printf("Error (status 0x%02X): %s", protoErr.Status, protoErr.Message)
    return
}
if err != nil {
    log.Fatal(err)
}
```

## Connection Management

```go
// Create with a custom config; TLSConfig carries the client certificate
// and the CA pool for mTLS.
client, err := quicwire.NewClient(&quicwire.ClientConfig{
    ServerAddr:     "localhost:9444",
    TLSConfig:      tlsConfig,
    Timeout:        10 * time.Second,
    MaxIdleTimeout: 30 * time.Second,
}, quicwire.WithToken(token))
```

Each request opens a new stream on the one QUIC connection; `Close` ends it.

## See Also

- [API Reference](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)

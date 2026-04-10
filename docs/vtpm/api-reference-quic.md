# vTPM QUIC API Reference

Port: `9444` (UDP)
Protocol: QUIC with TLS 1.3

## Protocol Overview

The QUIC protocol uses a binary frame format for low-latency vTPM operations.

### Frame Format

**Request:**
```
+--------+------------+-------------+---------+
| Opcode | Token Len  | Token       | Payload |
| 1 byte | 2 bytes    | variable    | variable|
+--------+------------+-------------+---------+
```

**Response:**
```
+--------+-------------+---------+
| Status | Payload Len | Payload |
| 1 byte | 4 bytes     | variable|
+--------+-------------+---------+
```

## Operation Codes (0x20-0x2E)

### Bundle Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x20` | BundleCreate | Create new bundle |
| `0x21` | BundleGet | Get bundle by ID |
| `0x22` | BundleDelete | Delete bundle |
| `0x23` | BundleList | List bundles |
| `0x24` | BundleValidate | Validate bundle integrity |

### Template Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x25` | TemplateCreate | Create new template |
| `0x26` | TemplateGet | Get template by ID |
| `0x27` | TemplateDelete | Delete template |
| `0x28` | TemplateList | List templates |
| `0x29` | TemplateClone | Clone template to bundle |

### Export/Import Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x2A` | BundleExport | Export bundle as tar.gz |
| `0x2B` | BundleImport | Import bundle from tar.gz |

### Path Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x2C` | GetBundlePath | Get bundle filesystem path |
| `0x2D` | GetTPMSocketPath | Get TPM socket path |
| `0x2E` | GetNVRAMPath | Get NVRAM path |

## Status Codes

| Code | Name | Description |
|------|------|-------------|
| `0x00` | OK | Success |
| `0x01` | InvalidRequest | Invalid request format |
| `0x02` | NotFound | Resource not found |
| `0x04` | InternalError | Server error |

## Payload Encoding

All payloads use JSON encoding.

### CreateBundle (0x20)

**Request Payload:**
```json
{
  "mode": "pre-assigned",
  "hostname": "vm001.example.com",
  "ek_algorithm": "RSA",
  "secure_boot_enabled": true,
  "labels": {"env": "prod"}
}
```

**Response Payload:**
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mode": "pre-assigned",
  "manifest": {...}
}
```

### GetBundle (0x21)

**Request Payload:**
```json
{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
```

**Response Payload:**
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mode": "pre-assigned",
  "manifest": {...}
}
```

### DeleteBundle (0x22)

**Request Payload:**
```json
{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
```

**Response Payload:**
```json
{"success": true}
```

### ListBundles (0x23)

**Request Payload:**
```json
{
  "mode": "pre-assigned",
  "limit": 50,
  "offset": 0
}
```

**Response Payload:**
```json
{
  "bundles": [...],
  "total": 10
}
```

### CloneTemplate (0x29)

**Request Payload:**
```json
{
  "template_id": "base-server",
  "hostname": "vm002.example.com",
  "labels": {"cloned": "true"}
}
```

### ValidateBundle (0x24)

**Response Payload:**
```json
{
  "valid": true,
  "errors": []
}
```

### Path Getters (0x2C-0x2E)

**Request Payload:**
```json
{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
```

**Response Payload:**
```json
{"path": "/var/lib/trusted-platform/vtpm/bundles/..."}
```

## Connection Example

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

// Load platform CA certificate for TLS verification
caCert, _ := os.ReadFile("/path/to/ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    RootCAs:    caCertPool,
    NextProtos: []string{"vtpm-quic"},
}

quicConfig := &quic.Config{
    MaxIdleTimeout: 60 * time.Second,
}

conn, err := quic.DialAddr(ctx, "localhost:9444", tlsConfig, quicConfig)
if err != nil {
    return err
}
defer conn.CloseWithError(0, "done")

stream, err := conn.OpenStreamSync(ctx)
if err != nil {
    return err
}
defer stream.Close()

// Send request
writeRequest(stream, OpQUICVTPMBundleGet, payload)

// Read response
status, respPayload, err := readResponse(stream)
```

## Protocol Constants

```go
const (
    // Max payload size: 16MB
    MaxQUICPayloadSizeVTPM uint32 = 16 * 1024 * 1024

    // Max token size: 8KB
    MaxQUICTokenSizeVTPM uint16 = 8 * 1024

    // Default timeout
    DefaultQUICTimeoutVTPM = 30 * time.Second
)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VTPM_QUIC_ENDPOINT` | QUIC server address | `localhost:9444` |

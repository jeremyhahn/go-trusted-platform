# DNS QUIC API Reference

QUIC protocol usage for the DNS service.

| Property | Value |
|----------|-------|
| Port | 9444 |
| Transport | UDP with QUIC |
| Protocol | HTTP/3 or raw QUIC streams |

## Overview

QUIC provides low-latency DNS operations over UDP with TLS 1.3 encryption. Ideal for:

- Mobile clients with changing networks
- High-frequency DNS updates
- Low-latency resolution requirements

## Connection Setup

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/http3"
)

func NewQUICClient(addr string, tlsConfig *tls.Config) (*http3.RoundTripper, error) {
    return &http3.RoundTripper{
        TLSClientConfig: tlsConfig,
        QuicConfig: &quic.Config{
            MaxIdleTimeout:  30 * time.Second,
            KeepAlivePeriod: 10 * time.Second,
        },
    }, nil
}
```

## HTTP/3 API

QUIC exposes the same REST API over HTTP/3:

### Zone Operations

```go
// Create zone
req, _ := http.NewRequest("POST", "https://platform.example.com:9444/api/v1/dns/zones", body)
resp, err := client.Do(req)

// Get zone
req, _ := http.NewRequest("GET", "https://platform.example.com:9444/api/v1/dns/zones/example.internal.", nil)
resp, err := client.Do(req)

// List zones
req, _ := http.NewRequest("GET", "https://platform.example.com:9444/api/v1/dns/zones", nil)
resp, err := client.Do(req)

// Delete zone
req, _ := http.NewRequest("DELETE", "https://platform.example.com:9444/api/v1/dns/zones/example.internal.", nil)
resp, err := client.Do(req)
```

### Record Operations

```go
// Add record
body := bytes.NewBuffer([]byte(`{"type":"A","name":"server01","value":"192.168.1.100","ttl":3600}`))
req, _ := http.NewRequest("POST", "https://platform.example.com:9444/api/v1/dns/zones/example.internal./records", body)
req.Header.Set("Content-Type", "application/json")
resp, err := client.Do(req)

// Get record
req, _ := http.NewRequest("GET", "https://platform.example.com:9444/api/v1/dns/zones/example.internal./records/A/server01", nil)
resp, err := client.Do(req)

// Delete record
req, _ := http.NewRequest("DELETE", "https://platform.example.com:9444/api/v1/dns/zones/example.internal./records/A/server01", nil)
resp, err := client.Do(req)
```

### TLSA/DANE

```go
body := bytes.NewBuffer([]byte(`{
    "type": "TLSA",
    "name": "_443._tcp.www",
    "usage": 3,
    "selector": 1,
    "matching_type": 1,
    "certificate": "base64-data",
    "ttl": 3600
}`))
req, _ := http.NewRequest("POST", "https://platform.example.com:9444/api/v1/dns/zones/example.com./records", body)
```

### Resolution

```go
req, _ := http.NewRequest("GET", "https://platform.example.com:9444/api/v1/dns/resolve?name=ns1.example.internal.&type=A", nil)
resp, err := client.Do(req)
```

## Stream-Based API

For high-performance scenarios, use raw QUIC streams:

```go
func StreamResolve(conn quic.Connection, queries []ResolveRequest) ([]ResolveResponse, error) {
    stream, err := conn.OpenStreamSync(ctx)
    if err != nil {
        return nil, err
    }
    defer stream.Close()

    // Write queries
    encoder := json.NewEncoder(stream)
    for _, q := range queries {
        if err := encoder.Encode(q); err != nil {
            return nil, err
        }
    }
    stream.Close() // Signal end of writes

    // Read responses
    var responses []ResolveResponse
    decoder := json.NewDecoder(stream)
    for {
        var resp ResolveResponse
        if err := decoder.Decode(&resp); err == io.EOF {
            break
        } else if err != nil {
            return nil, err
        }
        responses = append(responses, resp)
    }
    return responses, nil
}
```

## Request/Response Format

Same JSON format as REST API:

**Create Zone Request:**
```json
{
  "name": "myzone.internal.",
  "ttl": 3600,
  "internal": true,
  "records": {
    "soa": {
      "name": "myzone.internal.",
      "mname": "ns1.myzone.internal.",
      "rname": "hostmaster.myzone.internal.",
      "serial": 1
    }
  }
}
```

**Add Record Request:**
```json
{
  "type": "A",
  "name": "server01",
  "value": "192.168.1.100",
  "ttl": 3600
}
```

**Resolve Request:**
```json
{
  "name": "ns1.example.internal.",
  "type": "A"
}
```

**Resolve Response:**
```json
{
  "name": "ns1.example.internal.",
  "type": "A",
  "ttl": 3600,
  "answers": [
    {"value": "192.168.1.10"}
  ]
}
```

## Connection Management

```go
type QUICDNSClient struct {
    conn      quic.Connection
    tlsConfig *tls.Config
    addr      string
}

func (c *QUICDNSClient) Connect(ctx context.Context) error {
    conn, err := quic.DialAddr(ctx, c.addr, c.tlsConfig, &quic.Config{
        MaxIdleTimeout:       30 * time.Second,
        KeepAlivePeriod:      10 * time.Second,
        EnableDatagrams:      true,
    })
    if err != nil {
        return err
    }
    c.conn = conn
    return nil
}

func (c *QUICDNSClient) Close() error {
    return c.conn.CloseWithError(0, "client closed")
}
```

## Error Handling

QUIC errors map to application errors:

| QUIC Error | Meaning |
|------------|---------|
| `NO_ERROR` | Success |
| `APPLICATION_ERROR` | Check JSON error response |
| `CONNECTION_REFUSED` | Service unavailable |

```go
resp, err := client.Do(req)
if err != nil {
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        // Handle QUIC application error
    }
    return err
}

if resp.StatusCode >= 400 {
    var apiErr APIError
    json.NewDecoder(resp.Body).Decode(&apiErr)
    // Handle API error
}
```

## Performance Considerations

- 0-RTT connection resumption for repeat connections
- Multiplexed streams for concurrent operations
- No head-of-line blocking
- Connection migration for mobile clients

```go
// Enable 0-RTT
quicConfig := &quic.Config{
    Allow0RTT: true,
}

// Store session for resumption
sessionCache := tls.NewLRUClientSessionCache(100)
tlsConfig := &tls.Config{
    ClientSessionCache: sessionCache,
}
```

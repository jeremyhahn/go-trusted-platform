# DNS Unix Socket API Reference

Unix socket usage for the DNS service.

| Property | Value |
|----------|-------|
| Socket Path | `/run/platformd.sock` |
| Transport | Unix domain socket |
| Protocol | HTTP/1.1 over Unix socket |

## Overview

Unix sockets provide local IPC for CLI tools and local services. Benefits:

- No network overhead
- Filesystem-based permissions
- Faster than TCP for local calls

## Connection

### Go Client

```go
import (
    "context"
    "net"
    "net/http"
)

func NewUnixSocketClient(socketPath string) *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                return net.Dial("unix", socketPath)
            },
        },
    }
}

// Usage
client := NewUnixSocketClient("/run/platformd.sock")
resp, err := client.Get("http://localhost/api/v1/dns/zones")
```

### curl

```bash
curl --unix-socket /run/platformd.sock http://localhost/api/v1/dns/zones
```

## Zone Operations

### ListZones

```bash
curl --unix-socket /run/platformd.sock \
  http://localhost/api/v1/dns/zones
```

### GetZone

```bash
curl --unix-socket /run/platformd.sock \
  http://localhost/api/v1/dns/zones/example.internal.
```

### CreateZone

```bash
curl --unix-socket /run/platformd.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myzone.internal.",
    "ttl": 3600,
    "internal": true,
    "records": {
      "soa": {
        "name": "myzone.internal.",
        "mname": "ns1.myzone.internal.",
        "rname": "hostmaster.myzone.internal.",
        "serial": 1,
        "refresh": 86400,
        "retry": 7200,
        "expire": 86400,
        "min_ttl": 3600,
        "ttl": 3600
      },
      "ns": [
        {"name": "myzone.internal.", "value": "ns1.myzone.internal.", "ttl": 3600}
      ]
    }
  }' \
  http://localhost/api/v1/dns/zones
```

### UpdateZone

```bash
curl --unix-socket /run/platformd.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"ttl": 7200}' \
  http://localhost/api/v1/dns/zones/myzone.internal.
```

### DeleteZone

```bash
curl --unix-socket /run/platformd.sock \
  -X DELETE \
  http://localhost/api/v1/dns/zones/myzone.internal.
```

## Record Operations

### ListRecords

```bash
curl --unix-socket /run/platformd.sock \
  http://localhost/api/v1/dns/zones/example.internal./records

# Filter by type
curl --unix-socket /run/platformd.sock \
  "http://localhost/api/v1/dns/zones/example.internal./records?type=A"
```

### GetRecord

```bash
curl --unix-socket /run/platformd.sock \
  http://localhost/api/v1/dns/zones/example.internal./records/A/ns1
```

### AddRecord

```bash
# A record
curl --unix-socket /run/platformd.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"type":"A","name":"server01","value":"192.0.2.100","ttl":3600}' \
  http://localhost/api/v1/dns/zones/example.internal./records

# MX record
curl --unix-socket /run/platformd.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"type":"MX","name":"@","value":"mail.example.internal.","priority":10,"ttl":3600}' \
  http://localhost/api/v1/dns/zones/example.internal./records
```

### UpdateRecord

```bash
curl --unix-socket /run/platformd.sock \
  -X PUT \
  -H "Content-Type: application/json" \
  -d '{"value":"192.0.2.101","ttl":7200}' \
  http://localhost/api/v1/dns/zones/example.internal./records/A/server01
```

### DeleteRecord

```bash
curl --unix-socket /run/platformd.sock \
  -X DELETE \
  http://localhost/api/v1/dns/zones/example.internal./records/A/server01
```

## TLSA/DANE

### AddTLSARecord

```bash
curl --unix-socket /run/platformd.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "type": "TLSA",
    "name": "_443._tcp.www",
    "usage": 3,
    "selector": 1,
    "matching_type": 1,
    "certificate": "base64-encoded-cert-data",
    "ttl": 3600
  }' \
  http://localhost/api/v1/dns/zones/example.com./records
```

## Resolution

### Resolve

```bash
curl --unix-socket /run/platformd.sock \
  "http://localhost/api/v1/dns/resolve?fqdn=ns1.example.internal.&type=A"
```

## Go Client Examples

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
)

const socketPath = "/run/platformd.sock"

type DNSClient struct {
    client *http.Client
}

func NewDNSClient() *DNSClient {
    return &DNSClient{
        client: &http.Client{
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                    return net.Dial("unix", socketPath)
                },
            },
        },
    }
}

func (c *DNSClient) ListZones() ([]Zone, error) {
    resp, err := c.client.Get("http://localhost/api/v1/dns/zones")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Zones []Zone `json:"zones"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    return result.Zones, nil
}

func (c *DNSClient) AddRecord(zoneName string, record Record) error {
    body, _ := json.Marshal(record)
    url := fmt.Sprintf("http://localhost/api/v1/dns/zones/%s/records", zoneName)
    resp, err := c.client.Post(url, "application/json", bytes.NewReader(body))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        var apiErr APIError
        json.NewDecoder(resp.Body).Decode(&apiErr)
        return fmt.Errorf("%s: %s", apiErr.Error, apiErr.Message)
    }
    return nil
}

func (c *DNSClient) Resolve(name, recordType string) ([]string, error) {
    url := fmt.Sprintf("http://localhost/api/v1/dns/resolve?fqdn=%s&type=%s", name, recordType)
    resp, err := c.client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result ResolveResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    // Only the records name owns, from its longest managed zone; see
    // resolution.md#api-resolve.
    var values []string
    for _, r := range result.Records {
        if r.A != nil {
            values = append(values, r.A.Value)
        }
    }
    return values, nil
}
```

## Authentication

For local Unix socket connections, authentication uses:

1. **Unix credentials** - Peer UID/GID verification
2. **Bearer token** - Same as REST API

```bash
# With bearer token
curl --unix-socket /run/platformd.sock \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost/api/v1/dns/zones
```

## Permissions

Socket file permissions control access:

```bash
# Default permissions
srw-rw---- 1 root platform 0 Jan  1 00:00 /run/platformd.sock

# Users in 'platform' group can access
sudo usermod -aG platform myuser
```

## Error Handling

Same JSON error format as REST API:

```json
{
  "error": "zone_not_found",
  "message": "Zone 'nonexistent.internal.' not found"
}
```

Check HTTP status codes:

```bash
curl --unix-socket /run/platformd.sock \
  -w "%{http_code}" \
  http://localhost/api/v1/dns/zones/nonexistent.
# Returns: 404
```

The gRPC `DNSService` on the socket is the same servicer as the TCP gRPC
listener, so it reaches the same DNS backend. With no `dns:` section it
answers `UNAVAILABLE` with an `ErrorInfo` reason `SERVICE_NOT_CONFIGURED`,
metadata `service=dns`, as described in
[api-reference-grpc.md](api-reference-grpc.md#error-handling).

## CLI Integration

The `platformctl` CLI uses Unix socket by default:

```bash
# These commands use /run/platformd.sock internally
platformctl dns zones list
platformctl dns zones create --name myzone.internal. --ttl 3600 --internal
platformctl dns records add --zone myzone.internal. --type A --name server01 --value 192.0.2.100
platformctl dns resolve ns1.example.internal. A
```

Override with remote endpoint:

```bash
platformctl --endpoint https://platform.example.com:8443 dns zones list
```

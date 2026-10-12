# REST API Reference

HTTP/HTTPS REST API for the Trusted Platform daemon.

## Base URL

```
https://localhost:8443/api/v1
```

## Authentication

```
Authorization: Bearer <access_token>
```

Or via mTLS client certificate.

## Endpoints

### Health Check

```
GET /api/v1/health
```

Returns system health status with component details.

**Response:**
```json
{
  "status": "healthy",
  "components": [
    {
      "name": "ca",
      "status": "healthy",
      "message": "",
      "last_check": "2025-01-05T12:00:00Z"
    }
  ],
  "timestamp": "2025-01-05T12:00:00Z"
}
```

**Status Codes:**
| Code | Description |
|------|-------------|
| 200 | System healthy |
| 503 | System unhealthy |

---

### Daemon Status

```
GET /api/v1/status
```

Returns detailed daemon status including system information.

**Response:**
```json
{
  "status": "ready",
  "version": "1.0.0",
  "build_time": "2025-01-01T00:00:00Z",
  "git_commit": "abc1234",
  "go_version": "go1.22.0",
  "system": {
    "os": "linux",
    "arch": "amd64",
    "num_cpus": 8,
    "total_memory_mb": 16384,
    "available_memory_mb": 8192,
    "uptime": "24h30m15s"
  },
  "timestamp": "2025-01-05T12:00:00Z"
}
```

---

### Version

```
GET /api/v1/version
```

Returns version information.

**Response:**
```json
{
  "version": "1.0.0",
  "build_time": "2025-01-01T00:00:00Z",
  "git_commit": "abc1234",
  "go_version": "go1.22.0"
}
```

---

### List Services

```
GET /api/v1/services
```

Returns all managed services with their status.

**Response:**
```json
{
  "services": [
    {
      "name": "ca",
      "status": "running",
      "started_at": "2025-01-05T00:00:00Z",
      "uptime": "12h30m15s",
      "start_count": 1,
      "stop_count": 0,
      "last_error": ""
    },
    {
      "name": "dns",
      "status": "stopped",
      "started_at": null,
      "uptime": "",
      "start_count": 0,
      "stop_count": 0,
      "last_error": ""
    }
  ],
  "count": 2,
  "timestamp": "2025-01-05T12:00:00Z"
}
```

---

### Get Service

```
GET /api/v1/services/{service}
```

Returns details for a specific service.

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| service | path | string | Service name |

**Response:**
```json
{
  "name": "ca",
  "status": "running",
  "started_at": "2025-01-05T00:00:00Z",
  "uptime": "12h30m15s",
  "start_count": 1,
  "stop_count": 0,
  "last_error": ""
}
```

**Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Success |
| 404 | Service not found |

---

### Start Service

```
POST /api/v1/services/{service}/start
```

Starts a stopped service.

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| service | path | string | Service name |

**Response:**
```json
{
  "service": "dns",
  "action": "start",
  "success": true,
  "message": "service started successfully"
}
```

**Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Service started |
| 404 | Service not found |
| 409 | Service already running |
| 500 | Start failed |

---

### Stop Service

```
POST /api/v1/services/{service}/stop
```

Stops a running service.

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| service | path | string | Service name |

**Response:**
```json
{
  "service": "dns",
  "action": "stop",
  "success": true,
  "message": "service stopped successfully"
}
```

**Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Service stopped |
| 404 | Service not found |
| 409 | Service not running |
| 500 | Stop failed |

---

### Restart Service

```
POST /api/v1/services/{service}/restart
```

Restarts a service (stop then start).

**Parameters:**
| Name | In | Type | Description |
|------|-----|------|-------------|
| service | path | string | Service name |

**Response:**
```json
{
  "service": "dns",
  "action": "restart",
  "success": true,
  "message": "service restarted successfully"
}
```

**Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Service restarted |
| 404 | Service not found |
| 500 | Restart failed |

---

### List Protocols

```
GET /api/v1/protocols
```

Returns status of all protocol endpoints.

**Response:**
```json
{
  "protocols": [
    {
      "name": "REST",
      "enabled": true,
      "address": "0.0.0.0:8443",
      "port": 8443,
      "status": "running",
      "tls": true
    },
    {
      "name": "gRPC",
      "enabled": true,
      "address": "0.0.0.0:9443",
      "port": 9443,
      "status": "unknown",
      "tls": true
    },
    {
      "name": "Unix Socket",
      "enabled": true,
      "address": "/run/platformd.sock",
      "port": 0,
      "status": "running",
      "tls": false
    },
    {
      "name": "QUIC",
      "enabled": true,
      "address": "0.0.0.0:9444",
      "port": 9444,
      "status": "running",
      "tls": true
    },
    {
      "name": "MCP",
      "enabled": true,
      "address": "127.0.0.1:9445",
      "port": 9445,
      "status": "running",
      "tls": true
    }
  ],
  "timestamp": "2025-01-05T12:00:00Z"
}
```

## Error Responses

All errors return a consistent format:

```json
{
  "error": "service not found: unknown",
  "code": 404,
  "timestamp": "2025-01-05T12:00:00Z"
}
```

## Headers

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes* | Bearer token |
| `Content-Type` | No | `application/json` |
| `Accept` | No | `application/json` |
| `Accept-Encoding` | No | `gzip` for compression |
| `X-Request-ID` | No | Custom request ID |

*Required unless mTLS is configured.

### Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `Content-Encoding` | `gzip` when compressed |
| `X-Request-ID` | Request tracking ID |

## Examples

### curl

```bash
# Health check
curl -k https://localhost:8443/api/v1/health

# Get status
curl -k https://localhost:8443/api/v1/status

# List services
curl -k https://localhost:8443/api/v1/services

# Start a service
curl -k -X POST https://localhost:8443/api/v1/services/dns/start

# Stop a service
curl -k -X POST https://localhost:8443/api/v1/services/dns/stop

# With authentication
curl -k -H "Authorization: Bearer mytoken" \
  https://localhost:8443/api/v1/services

# With custom request ID
curl -k -H "X-Request-ID: my-trace-id" \
  https://localhost:8443/api/v1/health
```

### HTTPie

```bash
# Health check
https --verify=no GET localhost:8443/api/v1/health

# Start service
https --verify=no POST localhost:8443/api/v1/services/dns/start
```

### Python

```python
import requests

BASE_URL = "https://localhost:8443/api/v1"

# Health check
response = requests.get(f"{BASE_URL}/health", verify=False)
health = response.json()

# List services
response = requests.get(f"{BASE_URL}/services", verify=False)
services = response.json()

# Start service
response = requests.post(f"{BASE_URL}/services/dns/start", verify=False)
result = response.json()
```

### Go

```go
package main

import (
    "crypto/tls"
    "encoding/json"
    "net/http"
)

func main() {
    // Load platform CA certificate for TLS verification
    caCert, _ := os.ReadFile("/path/to/ca.crt")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS13,
                RootCAs:    caCertPool,
            },
        },
    }

    // Health check
    resp, _ := client.Get("https://localhost:8443/api/v1/health")
    defer resp.Body.Close()

    var health map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&health)
}
```

## CORS

When CORS is enabled, the server responds to preflight requests:

```
OPTIONS /api/v1/services HTTP/1.1
Origin: http://localhost:3000

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Accept, Authorization, Content-Type, X-Request-ID
Access-Control-Max-Age: 86400
```

## Rate Limiting

When enabled, rate limiting applies to all endpoints:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

Configure rate limiting in the daemon configuration:

```yaml
rest:
  rate_limit_requests: 100  # requests per second
  rate_limit_burst: 200     # burst allowance
```

## See Also

- [API Reference](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)

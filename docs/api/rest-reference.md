# REST API Reference

Base URL: `https://<host>:8443/api/v1`

## Authentication

| Method | Header | Description |
|--------|--------|-------------|
| TLS | - | Server certificate validation |
| mTLS | - | Client certificate authentication |
| Bearer | `Authorization: Bearer <token>` | JWT token |

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Simple health check |
| GET | /api/v1/status | Platform status |
| GET | /api/v1/health | Detailed health |
| GET | /api/v1/version | Version info |
| GET | /api/v1/services | List services |
| GET | /api/v1/services/{name} | Service status |
| POST | /api/v1/services/{name}/start | Start service |
| POST | /api/v1/services/{name}/stop | Stop service |
| POST | /api/v1/services/{name}/restart | Restart service |

---

## Health Check

### GET /health

Simple health check endpoint. No authentication required.

**Response:**

```json
{
  "healthy": true,
  "status": "ok",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

## System Endpoints

### GET /api/v1/status

Returns platform status and information.

**Response:**

```json
{
  "status": "SYSTEM_STATUS_READY",
  "timestamp": "2025-01-15T10:30:00Z",
  "data": {
    "hostname": "platform-host",
    "platform_id": "abc123",
    "version": "1.0.0",
    "uptime_seconds": 3600
  }
}
```

### GET /api/v1/health

Returns detailed health information for all components.

**Response (healthy):**

```json
{
  "healthy": true,
  "status": "HEALTH_STATUS_HEALTHY",
  "checks": {
    "tpm": true,
    "sdn": true,
    "compute": true
  },
  "timestamp": "2025-01-15T10:30:00Z",
  "details": {
    "tpm": {
      "healthy": true,
      "status": "HEALTH_STATUS_HEALTHY",
      "message": "TPM operational"
    },
    "sdn": {
      "healthy": true,
      "status": "HEALTH_STATUS_HEALTHY",
      "message": "SDN controller connected"
    }
  }
}
```

**Response (unhealthy):** Returns HTTP 503 with same format.

### GET /api/v1/version

Returns version information.

**Response:**

```json
{
  "version": "1.0.0",
  "git_hash": "abc123def",
  "build_date": "2025-01-15T00:00:00Z",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

## Service Management

### GET /api/v1/services

Lists all platform services.

**Response:**

```json
{
  "services": [
    {
      "name": "TPM Service",
      "type": "SERVICE_TYPE_TPM",
      "status": "SERVICE_STATUS_RUNNING",
      "enabled": true,
      "timestamp": "2025-01-15T10:30:00Z",
      "details": {
        "health": "HEALTH_STATUS_HEALTHY",
        "version": "2.0",
        "uptime_seconds": 3600,
        "metadata": {}
      }
    },
    {
      "name": "SDN Service",
      "type": "SERVICE_TYPE_SDN",
      "status": "SERVICE_STATUS_RUNNING",
      "enabled": true,
      "timestamp": "2025-01-15T10:30:00Z",
      "details": {
        "health": "HEALTH_STATUS_HEALTHY",
        "version": "1.0",
        "uptime_seconds": 3500
      }
    }
  ],
  "count": 2,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### GET /api/v1/services/{name}

Returns status of a specific service.

**Path Parameters:**
- `name` - Service name: `tpm`, `sdn`, `compute`, `dns`, `acme`, `webservice`, `attestation`

**Response:**

```json
{
  "name": "TPM Service",
  "type": "SERVICE_TYPE_TPM",
  "status": "SERVICE_STATUS_RUNNING",
  "enabled": true,
  "timestamp": "2025-01-15T10:30:00Z",
  "details": {
    "health": "HEALTH_STATUS_HEALTHY",
    "version": "2.0",
    "uptime_seconds": 3600
  }
}
```

**Errors:**
- 400 - Invalid service name
- 404 - Service not found

### POST /api/v1/services/{name}/start

Starts a service.

**Path Parameters:**
- `name` - Service name

**Request Body (optional):**

```json
{
  "service_name": "tpm"
}
```

**Response:**

```json
{
  "success": true,
  "message": "Service started",
  "service": "tpm",
  "action": "start",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### POST /api/v1/services/{name}/stop

Stops a service.

**Path Parameters:**
- `name` - Service name

**Request Body (optional):**

```json
{
  "force": false,
  "timeout": 30
}
```

| Field | Type | Description |
|-------|------|-------------|
| `force` | bool | Force stop without waiting |
| `timeout` | int | Stop timeout in seconds |

**Response:**

```json
{
  "success": true,
  "message": "Service stopped",
  "service": "tpm",
  "action": "stop",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### POST /api/v1/services/{name}/restart

Restarts a service.

**Path Parameters:**
- `name` - Service name

**Request Body (optional):**

```json
{
  "timeout": 30
}
```

**Response:**

```json
{
  "success": true,
  "message": "Service restarted",
  "service": "tpm",
  "action": "restart",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

## Error Responses

All errors return a consistent format:

```json
{
  "error": "Error type",
  "message": "Detailed description",
  "code": 500,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request - Invalid input |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Permission denied |
| 404 | Not found - Resource does not exist |
| 500 | Internal server error |
| 503 | Service unavailable - Backend unavailable |

---

## Response Types

### StatusResponse

```json
{
  "status": "string",
  "message": "string (optional)",
  "timestamp": "ISO8601",
  "data": {}
}
```

### HealthResponse

```json
{
  "healthy": true,
  "status": "string",
  "checks": {"component": true},
  "timestamp": "ISO8601",
  "details": {}
}
```

### VersionResponse

```json
{
  "version": "string",
  "git_hash": "string",
  "git_branch": "string",
  "build_date": "string",
  "timestamp": "ISO8601"
}
```

### ServiceResponse

```json
{
  "name": "string",
  "type": "string",
  "status": "string",
  "enabled": true,
  "timestamp": "ISO8601",
  "details": {}
}
```

### ServiceActionResponse

```json
{
  "success": true,
  "message": "string",
  "service": "string",
  "action": "string",
  "timestamp": "ISO8601"
}
```

### ErrorResponse

```json
{
  "error": "string",
  "message": "string",
  "code": 0,
  "timestamp": "ISO8601",
  "request_id": "string"
}
```

---

## Service Types

| Name | API Value | Description |
|------|-----------|-------------|
| tpm | SERVICE_TYPE_TPM | TPM service |
| sdn | SERVICE_TYPE_SDN | SDN controller |
| compute | SERVICE_TYPE_COMPUTE | VM/container service |
| dns | SERVICE_TYPE_DNS | DNS service |
| acme | SERVICE_TYPE_ACME | ACME certificate service |
| webservice | SERVICE_TYPE_WEBSERVICE | Web service |
| attestation | SERVICE_TYPE_ATTESTATION | Attestation service |

---

## Examples

### cURL

```bash
# Health check
curl -k https://localhost:8443/health

# Get status
curl -k https://localhost:8443/api/v1/status

# Get detailed health
curl -k https://localhost:8443/api/v1/health

# Get version
curl -k https://localhost:8443/api/v1/version

# List services
curl -k https://localhost:8443/api/v1/services

# Get TPM service status
curl -k https://localhost:8443/api/v1/services/tpm

# Start TPM service
curl -k -X POST https://localhost:8443/api/v1/services/tpm/start

# Stop TPM service with timeout
curl -k -X POST https://localhost:8443/api/v1/services/tpm/stop \
  -H "Content-Type: application/json" \
  -d '{"timeout": 30}'

# Restart SDN service
curl -k -X POST https://localhost:8443/api/v1/services/sdn/restart
```

### Go Client

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
)

type StatusResponse struct {
    Status    string                 `json:"status"`
    Timestamp string                 `json:"timestamp"`
    Data      map[string]interface{} `json:"data"`
}

func main() {
    client := &http.Client{}

    resp, err := client.Get("https://localhost:8443/api/v1/status")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var status StatusResponse
    json.NewDecoder(resp.Body).Decode(&status)

    fmt.Printf("Status: %s\n", status.Status)
    fmt.Printf("Hostname: %s\n", status.Data["hostname"])
}
```

### Python Client

```python
import requests

# Disable SSL verification for self-signed certs
base_url = "https://localhost:8443/api/v1"

# Get status
resp = requests.get(f"{base_url}/status", verify=False)
status = resp.json()
print(f"Status: {status['status']}")

# List services
resp = requests.get(f"{base_url}/services", verify=False)
services = resp.json()
for svc in services['services']:
    print(f"{svc['name']}: {svc['status']}")

# Start service
resp = requests.post(f"{base_url}/services/tpm/start", verify=False)
result = resp.json()
print(f"Success: {result['success']}")
```

---

## TLS Configuration

The REST API server supports TLS and mTLS.

### TLS (Server Certificate)

```bash
curl --cacert /path/to/ca.crt https://localhost:8443/health
```

### mTLS (Client Certificate)

```bash
curl --cacert /path/to/ca.crt \
     --cert /path/to/client.crt \
     --key /path/to/client.key \
     https://localhost:8443/api/v1/status
```

### Configuration

```yaml
rest_api:
  tls_enabled: true
  tls_cert_file: "/etc/platform/certs/server.crt"
  tls_key_file: "/etc/platform/certs/server.key"
  tls_ca_file: "/etc/platform/certs/ca.crt"
  tls_min_version: "1.3"
  mtls_enabled: true
  mtls_verify_client: true
```

# Daemon API Reference

Multi-protocol API documentation for the Trusted Platform daemon.

## Supported Protocols

| Protocol | Transport | Port | Documentation |
|----------|-----------|------|---------------|
| REST | HTTPS | 8443 | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | TCP | 9443 | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | UDP | 9444 | [api-reference-quic.md](api-reference-quic.md) |
| MCP | stdio/HTTPS | 9445 | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix Socket | Unix | /run/platformd.sock | [api-reference-unix.md](api-reference-unix.md) |

## Protocol Selection Guide

| Use Case | Recommended Protocol |
|----------|---------------------|
| Web applications | REST |
| Service-to-service | gRPC |
| Mobile/low-latency | QUIC |
| AI/LLM integration | MCP |
| Local CLI/scripts | Unix Socket |
| High throughput | gRPC or QUIC |
| Browser clients | REST |
| Streaming data | gRPC |

## Common Operations

### Health and Status

| Operation | Description |
|-----------|-------------|
| Health | Overall system health check |
| Liveness | Simple alive check |
| Readiness | Service availability check |
| Status | Detailed daemon status |
| Version | Version information |

### Service Management

| Operation | Description |
|-----------|-------------|
| ListServices | List all managed services |
| GetService | Get service details |
| StartService | Start a stopped service |
| StopService | Stop a running service |
| RestartService | Restart a service |

### Protocol Status

| Operation | Description |
|-----------|-------------|
| ListProtocols | List enabled protocols and status |

## Authentication

All protocols support authentication via:

**Bearer Token:**
```
Authorization: Bearer <access_token>
```

**mTLS Client Certificate:**
```
TLS client certificate issued by the platform CA
```

**Unix Socket:**
```
Process UID/GID verification via socket credentials
```

## Error Handling

All protocols return consistent error information:

| Field | Description |
|-------|-------------|
| `error` | Error message |
| `code` | HTTP status code equivalent |
| `timestamp` | Error occurrence time |

### Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad request / validation error |
| 401 | Authentication required |
| 403 | Permission denied |
| 404 | Resource not found |
| 409 | Conflict (e.g., service already running) |
| 500 | Internal server error |
| 503 | Service unavailable |

### Protocol-Specific Errors

**REST:**
```json
{
  "error": "service not found: unknown",
  "code": 404,
  "timestamp": "2025-01-05T12:00:00Z"
}
```

**gRPC:**
```
Status: NOT_FOUND
Message: service not found: unknown
```

**QUIC:**
```
Status: 0x04 (StatusNotFound)
Payload: "service not found: unknown"
```

## Request ID Tracking

All protocols support request ID tracking for distributed tracing:

**REST:**
```
X-Request-ID: 20250105120000-1234
```

**gRPC:**
```
grpc-request-id: 20250105120000-1234
```

Request IDs are auto-generated if not provided by the client.

## Rate Limiting

When enabled (REST only), rate limiting returns:

```
HTTP 429 Too Many Requests
Retry-After: 1
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704456001
```

## Response Formats

### Health Response

```json
{
  "status": "healthy",
  "components": [
    {
      "name": "ca",
      "status": "healthy",
      "message": "",
      "last_check": "2025-01-05T12:00:00Z"
    },
    {
      "name": "kms",
      "status": "healthy",
      "message": "",
      "last_check": "2025-01-05T12:00:00Z"
    }
  ],
  "timestamp": "2025-01-05T12:00:00Z"
}
```

### Status Response

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

### Services List Response

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

### Protocols Response

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
      "status": "running",
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

## Service Status Values

| Status | Description |
|--------|-------------|
| `stopped` | Service is not running |
| `starting` | Service is starting up |
| `running` | Service is operational |
| `stopping` | Service is shutting down |
| `error` | Service encountered an error |

## Protocol Feature Matrix

| Feature | REST | gRPC | QUIC | MCP | Unix |
|---------|------|------|------|-----|------|
| Health Check | Yes | Yes | Yes | Yes | Yes |
| Service Management | Yes | Yes | No | Yes | Yes |
| Protocol Status | Yes | Yes | No | No | Yes |
| Streaming | No | Yes | No | No | Yes |
| TLS Support | Yes | Yes | Required | No | N/A |
| Binary Encoding | No | Yes | Yes | No | Yes |
| Human Readable | Yes | No | No | Yes | No |

## See Also

- [README](README.md)
- [Architecture](architecture.md)
- [Configuration](configuration.md)

# Platform API Overview

The Trusted Platform exposes APIs through multiple protocols with 100% feature parity.

## SDKs

For client applications, use the official SDKs which provide type-safe, multi-protocol access to all platform services:

| SDK | Installation | Documentation |
|-----|--------------|---------------|
| **Go SDK** | `go get github.com/jeremyhahn/go-trusted-platform/sdk/go` | [docs/sdk/](../sdk/user.md) |
| **JavaScript SDK** | `npm install trusted-platform-sdk` | [sdk-javascript.md](sdk-javascript.md) |

See [Go SDK architecture](../sdk/architecture.md) for architecture details.

## Protocols

| Protocol | Transport | Address | Use Case |
|----------|-----------|---------|----------|
| REST | HTTPS | :8443 (public), :9443 (internal) | Web clients, external systems |
| gRPC | TCP | :10443 | High-performance service-to-service |
| gRPC | Unix Socket | /run/platformd.sock | Local IPC, CLI (SO_PEERCRED auth) |
| QUIC | UDP | :9444 | Low-latency, mobile clients |
| MCP | HTTP | :9445 | AI/LLM integration (OAuth 2.1) |

Note: Unix socket uses gRPC protocol with SO_PEERCRED for kernel-verified authentication.

For the complete multi-protocol API reference and service parity matrix, see [API Reference](../api-reference.md).

## Architecture

```
┌───────────────────┐      ┌───────────────────┐      ┌─────────────────┐
│  External Client  │ ───▶ │  REST API Server  │ ───▶ │    platformd    │
│  (HTTP/JSON)      │      │  (port 8443)      │      │                 │
└───────────────────┘      └───────────────────┘      └─────────────────┘
                                                              ▲
┌───────────────────┐      ┌───────────────────┐              │
│  gRPC Client      │ ───▶ │  gRPC Server      │──────────────┤
│  (Protobuf/TCP)   │      │  (port 10443)     │              │
└───────────────────┘      └───────────────────┘              │
                                                              │
┌───────────────────┐      ┌───────────────────┐              │
│  gRPC Client      │ ───▶ │  gRPC Server      │──────────────┤
│  (Unix/SO_PEERCRED)      │  (Unix socket)    │              │
└───────────────────┘      └───────────────────┘              │
                                                              │
┌───────────────────┐      ┌───────────────────┐              │
│  QUIC Client      │ ───▶ │  QUIC Server      │──────────────┤
│  (Binary)         │      │  (port 9444)      │              │
└───────────────────┘      └───────────────────┘              │
                                                              │
┌───────────────────┐      ┌───────────────────┐              │
│  MCP Client       │ ───▶ │  MCP Server       │──────────────┘
│  (AI/LLM OAuth2.1)│      │  (port 9445)      │
└───────────────────┘      └───────────────────┘
```

## REST API

The REST API provides an HTTP gateway to platformd for external clients.

**Base URL:** `https://<host>:8443/api/v1`

**Features:**
- TLS 1.3 by default
- Optional mTLS for client authentication
- CORS support
- JSON request/response format

See [REST API Reference](rest-reference.md) for endpoint details.

## gRPC API

The gRPC API provides high-performance communication over TCP and Unix socket transports.

**TCP Address:** `:10443` (service-to-service, external clients)
**Unix Socket:** `/run/platformd.sock` (local IPC, CLI with SO_PEERCRED auth)

**Services:**
- `PlatformDaemon` - System and service management
- `TPMService` - TPM operations
- `ComputeService` - VM and container lifecycle
- `SDNService` - Software-defined networking

See [gRPC API Reference](grpc-reference.md) for service details.

## Authentication

All protocols (except health endpoints) require authentication. See [Authentication Architecture](../auth/README.md) for complete details.

| Protocol | Auth Method | Token Source | Documentation |
|----------|-------------|--------------|---------------|
| REST | mTLS + JWT | Authorization header | [auth/README.md](../auth/README.md) |
| gRPC (TCP) | mTLS + JWT | gRPC metadata | [auth/README.md](../auth/README.md) |
| gRPC (UDS) | SO_PEERCRED | Kernel credentials | [auth/README.md](../auth/README.md) |
| QUIC | TLS + JWT | QUIC metadata | [auth/README.md](../auth/README.md) |
| MCP | OAuth 2.1 | Authorization header | [auth/oauth2-architecture.md](../auth/oauth2-architecture.md) |

### REST API

| Method | Description |
|--------|-------------|
| TLS | Server certificate validation (default) |
| mTLS | Client certificate authentication |
| Bearer Token | JWT token in Authorization header |

### gRPC API

**TCP Transport:**
- Per-RPC credentials with OIDC interceptor
- Channel credentials via TLS
- Token validated via platform OIDC provider

**Unix Socket Transport:**
- SO_PEERCRED provides kernel-verified UID/GID/PID
- Socket permissions (0660) restrict access to `platform` group
- No tokens required - authentication is automatic

### MCP API (OAuth 2.1)

The MCP server implements OAuth 2.1 per RFC 9728:

- **Metadata Endpoint**: `/.well-known/oauth-protected-resource`
- **Token Validation**: Via platform OIDC provider
- **Permission Checks**: Via platform Policy Enforcement Point (PEP)

See [MCP OAuth 2.1 Architecture](../auth/oauth2-architecture.md) for implementation details.

## Error Handling

### REST API Errors

```json
{
  "error": "Service not found",
  "message": "Detailed error description",
  "code": 404,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### gRPC Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 1 | NOT_FOUND | Resource not found |
| 2 | ALREADY_EXISTS | Resource already exists |
| 3 | INVALID_ARGUMENT | Invalid input |
| 4 | PERMISSION_DENIED | Access denied |
| 10 | INTERNAL | Internal error |
| 11 | UNAVAILABLE | Service unavailable |

## Quick Start

### REST API

```bash
# Health check
curl -k https://localhost:8443/health

# Get platform status
curl -k https://localhost:8443/api/v1/status

# List services
curl -k https://localhost:8443/api/v1/services
```

### gRPC over Unix Socket (Go)

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Connect via Unix socket
conn, err := grpc.NewClient(
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Create service client
daemon := platformv1.NewPlatformDaemonClient(conn)

// Make request (SO_PEERCRED authentication is automatic)
resp, err := daemon.GetStatus(ctx, &platformv1.GetStatusRequest{})
```

### gRPC over TCP (Go)

```go
// Connect via TCP with TLS
conn, err := grpc.NewClient(
    "localhost:10443",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
)
```

## Configuration

### REST Server Config

```yaml
rest_api:
  host: "0.0.0.0"
  port: 8443
  socket_path: "/run/platformd/platformd.sock"
  tls_enabled: true
  tls_cert_file: "/etc/platform/certs/server.crt"
  tls_key_file: "/etc/platform/certs/server.key"
  mtls_enabled: false
  api_base_path: "/api/v1"
  enable_cors: false
```

| Field | Default | Description |
|-------|---------|-------------|
| `host` | 0.0.0.0 | Listen address |
| `port` | 8443 | Listen port |
| `socket_path` | /run/platformd/platformd.sock | platformd socket |
| `tls_enabled` | true | Enable HTTPS |
| `tls_min_version` | 1.3 | Minimum TLS version |
| `mtls_enabled` | false | Require client certs |
| `read_timeout` | 5s | HTTP read timeout |
| `write_timeout` | 30s | HTTP write timeout |
| `api_base_path` | /api/v1 | API URL prefix |

## Related Documentation

### SDKs
- [Go SDK](../sdk/architecture.md) - SDK architecture, usage and examples for Go
- [JavaScript SDK Guide](sdk-javascript.md) - Installation, React hooks, and examples

### Protocol References
- [Protocol Overview](protocols/overview.md) - Multi-protocol architecture comparison
- [REST API](protocols/rest-api.md) - REST endpoint reference
- [gRPC API](protocols/grpc-api.md) - gRPC service reference
- [QUIC API](protocols/quic-api.md) - QUIC protocol reference
- [MCP API](protocols/mcp-api.md) - Model Context Protocol reference
- [Unix Socket API](protocols/unix-api.md) - Unix socket reference

### Process Flows
- [Authentication](process-flows/authentication.md) - Authentication flow diagrams
- [Request Lifecycle](process-flows/request-lifecycle.md) - Request/response lifecycle
- [Protocol Selection](process-flows/protocol-selection.md) - Protocol selection guide

### Legacy References
- [API Reference](../api-reference.md) - Complete multi-protocol API reference and parity matrix
- [gRPC Design](grpc-design.md) - Comprehensive gRPC API architecture and design
- [gRPC Reference](grpc-reference.md) - gRPC service endpoints reference
- [REST Reference](rest-reference.md) - REST API endpoints reference
- [REST Routers](rest-routers.md) - Internal layout of `pkg/webservice/v1/rest/*` and how to add a new router
- [Architecture](../architecture/README.md)

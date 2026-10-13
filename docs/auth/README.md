# Authentication Architecture

This document provides an overview of the authentication and authorization architecture for go-trusted-platform.

## Overview

go-trusted-platform implements a secure authentication architecture based on:

- **MCP OAuth 2.1** - Per RFC 9728 (Protected Resource Metadata) for AI/LLM integration
- **QuicBaaS IAM** - ABAC (Attribute-Based Access Control) for all permission decisions
- **OIDC** - OpenID Connect as the sole authentication mechanism

## Protocol Authentication

| Protocol | Auth Method | Token Source | Validation |
|----------|-------------|--------------|------------|
| REST | mTLS + JWT | Authorization header | QuicBaaS OIDC |
| gRPC (TCP) | mTLS + JWT | gRPC metadata | QuicBaaS OIDC |
| gRPC (UDS) | SO_PEERCRED | Process credentials | Kernel (no token needed) |
| QUIC | TLS + JWT | QUIC metadata | QuicBaaS OIDC |
| MCP | OAuth 2.1 | Authorization header | QuicBaaS OIDC |

## Port Configuration

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTP/HTTPS | 8443/9443 | Web clients (public/internal) |
| gRPC | TCP | 10443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | HTTP | 8000 | AI/LLM integration (OAuth 2.1) |
| Unix | gRPC UDS | /run/platformd.sock | Local IPC, CLI (SO_PEERCRED) |

## Key Components

### MCP OAuth 2.1

The MCP server implements OAuth 2.1 Protected Resource Metadata per RFC 9728:

- **Metadata Endpoint**: `/.well-known/oauth-protected-resource`
- **Token Validation**: Via QuicBaaS OIDC provider
- **Permission Checks**: Via QuicBaaS PEP (Policy Enforcement Point)

See [oauth2-architecture.md](oauth2-architecture.md) for implementation details.

### QuicBaaS IAM Integration

All authorization decisions are made via QuicBaaS's IAM services:

- **OIDC Provider**: Token validation and claims extraction
- **PEP (Policy Enforcement Point)**: ABAC policy evaluation
- **Support for Embedded and Remote Modes**: Works with local QuicBaaS instance or remote SDK

See [quicbaas-iam.md](quicbaas-iam.md) for integration details.

### gRPC OIDC Interceptor

The gRPC server uses interceptors for JWT token validation:

- **Location**: `pkg/api/grpc/oidc_interceptor.go`
- **Unary Interceptor**: `OIDCUnaryInterceptor()` for regular RPC calls
- **Stream Interceptor**: `OIDCStreamInterceptor()` for streaming RPCs
- **Token Source**: Authorization header in gRPC metadata (`Bearer <token>`)
- **Skip Methods**: Health checks and reflection can skip authentication

```go
server := grpc.NewServer(
    grpc.UnaryInterceptor(grpc.OIDCUnaryInterceptor(
        grpc.WithTokenValidator(myValidator),
        grpc.WithSkipMethods("/grpc.health.v1.Health/Check"),
    )),
)
```

### QUIC Auth Middleware

The QUIC server uses middleware for authentication and authorization:

- **Location**: `pkg/api/quic/auth.go`
- **AuthMiddleware**: Handles both token validation and permission checks
- **Token Source**: Token field in QUIC request protocol
- **Permission Mapping**: `LookupOperationPermission` (`opcode_permissions.go`) maps every opcode and category sub-opcode to a resource/action pair; unclassified operations are denied

```go
m := quic.NewAuthMiddleware(
    quic.WithQUICTokenValidator(myValidator),
    quic.WithQUICAuthorizationChecker(myChecker),
)
```

### Unix Socket Authentication (SO_PEERCRED)

Local IPC via Unix domain sockets uses kernel-verified credentials:

- **Location**: `pkg/util/peercred/peercred.go` (leaf package shared with the gatewayd supervisor IPC, #557)
- **Transport Credentials**: `NewUnixTransportCredentials()`
- **Interceptors**: `UnixCredentialsUnaryInterceptor()`, `UnixCredentialsStreamInterceptor()`
- **No Token Required**: Kernel verifies PID/UID/GID automatically

## Security Principles

1. **No Anonymous Access**: All protected endpoints require valid authentication
2. **No API Keys**: Removed in favor of JWT/OIDC tokens
3. **No Password Authentication**: Removed in favor of certificate-based and token-based auth
4. **Mandatory Authorization**: No "allow all" fallbacks when auth services are unavailable
5. **Default Deny**: When no validator is configured and auth is required, requests are rejected

## Implementation Files

| File | Description |
|------|-------------|
| `pkg/api/mcp/oauth_metadata.go` | MCP Protected Resource Metadata endpoint |
| `pkg/api/mcp/authz.go` | MCP authorization checker |
| `pkg/api/mcp/quicbaas_auth.go` | MCP QuicBaaS adapter |
| `pkg/api/grpc/oidc_interceptor.go` | gRPC OIDC token validation interceptors |
| `pkg/util/peercred/peercred.go` | Unix socket SO_PEERCRED authentication |
| `pkg/api/quic/auth.go` | QUIC authentication middleware |

## Related Documentation

- [MCP API Reference](../api/mcp/)
- [QuicBaaS Integration](../datastore/)
- [Platform Daemon](../daemon/)
- [OAuth 2.1 Architecture](oauth2-architecture.md)
- [QuicBaaS IAM Integration](quicbaas-iam.md)

# MCP OAuth 2.1 Architecture

This document details the OAuth 2.1 implementation for the MCP (Model Context Protocol) server in go-trusted-platform.

## Overview

The MCP server implements OAuth 2.1 for Protected Resources per RFC 9728, enabling secure AI/LLM integration with the platform.

## Protected Resource Metadata (RFC 9728)

### Endpoint

```
GET /.well-known/oauth-protected-resource
```

### Response

```json
{
  "resource": "https://platformd.example.com:8000",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": [
    "mcp:tools",
    "mcp:resources",
    "vtpm:read",
    "vtpm:write",
    "device:read",
    "device:write",
    "dns:read",
    "dns:write",
    "sdn:read",
    "sdn:write"
  ],
  "bearer_methods_supported": ["header"]
}
```

## Authentication Flow

```
1. Client requests MCP tool/resource
2. Server checks for Authorization header
3. If missing: 401 with WWW-Authenticate header
4. If present: Validate token via QuicBaaS OIDC provider
5. Extract claims (subject, roles, groups, tenant)
6. Check permission via QuicBaaS PEP
7. Allow or deny access
```

## Token Requirements

- **Type**: Bearer token (JWT)
- **Header**: `Authorization: Bearer <token>`
- **PKCE**: S256 challenge method required for authorization code flow
- **Validation**: Via QuicBaaS OIDC provider

## WWW-Authenticate Response (RFC 6750)

When authentication fails, the server returns:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="platformd", error="invalid_token", error_description="Token validation failed"
```

## Scope Mapping

MCP tools are mapped to platform scopes:

| Tool Category | Required Scope |
|---------------|----------------|
| vtpm_* tools | vtpm:read or vtpm:write |
| dns_* tools | dns:read, dns:write, or dns:delete |
| device_* tools | device:read, device:write, or device:delete |
| sdn_* tools | sdn:read, sdn:write, or sdn:delete |
| platform_health | No scope required (public) |

## Implementation Files

- `pkg/api/mcp/oauth_metadata.go` - Protected Resource Metadata endpoint
- `pkg/api/mcp/authz.go` - Authorization checker
- `pkg/api/mcp/quicbaas_auth.go` - QuicBaaS integration adapter
- `pkg/api/mcp/types.go` - Auth error types

## Configuration

```yaml
mcp:
  address: ":8000"
  oauth:
    authorization_server: "https://auth.example.com"
    required: true
```

## Error Codes

| Code | Description |
|------|-------------|
| -32001 | Authentication required |
| -32002 | Invalid token |
| -32003 | Permission denied |
| -32004 | Authorization service unavailable |

## Security Considerations

1. **HTTPS Required**: MCP server should run over HTTPS in production
2. **Token Expiration**: Short-lived tokens (configurable TTL)
3. **Scope Validation**: Strict scope checking per tool
4. **No Fallback**: If auth services unavailable, protected operations fail

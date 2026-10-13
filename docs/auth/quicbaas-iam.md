# QuicBaaS IAM Integration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [api.md](api.md).

This document details how go-trusted-platform integrates with QuicBaaS's IAM (Identity and Access Management) services for authentication and authorization.

## Overview

QuicBaaS provides OIDC (OpenID Connect) and ABAC (Attribute-Based Access Control) services that go-trusted-platform uses for all authentication and authorization decisions.

## Architecture

```
+-------------------+     +-----------------+     +------------------+
|  Protocol Layer   |---->|  Auth Adapter   |---->|   QuicBaaS IAM   |
| (MCP/REST/gRPC)   |     | (TokenValidator)|     | (OIDC + PEP)     |
+-------------------+     +-----------------+     +------------------+
```

## QuicBaaS Modes

### Embedded Mode

When QuicBaaS runs in the same process as platformd:

```go
// Access via server.Service()
srv := server.New(config)
srv.StartAsync()

svc := srv.Service()  // Returns service.QuicBaaS
oidcProvider, _ := svc.GetOIDCProvider(ctx)
```

### Remote Mode

When QuicBaaS runs as a separate service:

```go
// Access via SDK client
client, _ := quicbaas.NewClient("localhost:10443")  // gRPC
iamClient := client.IAM()
pepClient := iamClient.PEP()
```

## Token Validation

### TokenValidator Interface

```go
type TokenValidator interface {
    ValidateToken(ctx context.Context, token string) (bool, error)
}
```

### QuicBaaS Implementation

```go
type QuicBaaSTokenValidator struct {
    service QuicBaaSService
}

func (v *QuicBaaSTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
    resp, err := v.service.ValidateToken(ctx, &ValidateTokenRequest{
        AccessToken: token,
    })
    if err != nil {
        return false, err
    }
    return resp.Valid, nil
}
```

## Policy Evaluation

### PEP (Policy Enforcement Point)

The PEP evaluates authorization decisions based on:
- **Subject**: User/service identity from token claims
- **Action**: Operation being performed (read, write, delete)
- **Resource**: Target resource (vtpm, dns, device, sdn)

### Permission Mapping

```go
var toolPermissions = map[string]string{
    "vtpm_create":  "vtpm:write",
    "vtpm_delete":  "vtpm:delete",
    "vtpm_list":    "vtpm:read",
    "dns_add_record": "dns:write",
    // ...
}
```

### Check Request

```go
resp, err := pepClient.Check(ctx, &iampb.CheckRequest{
    Subject: &iampb.Subject{
        Id:       userID,
        TenantId: tenantID,
        Roles:    roles,
        Groups:   groups,
    },
    Action:   "write",
    Resource: "vtpm",
})
```

## QuicBaaS Auth Adapter

The `QuicBaaSAuthAdapter` bridges MCP authorization with QuicBaaS IAM:

```go
type QuicBaaSAuthAdapter struct {
    tokenValidator  TokenValidator
    pepClient       iampb.PEPServiceClient
    defaultTenantID string
}

// Implements both AuthManager and AuthorizationService interfaces
func (a *QuicBaaSAuthAdapter) ValidateToken(ctx context.Context, token string) (bool, error)
func (a *QuicBaaSAuthAdapter) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error)
```

## Local PEP Adapter

For embedded mode without gRPC, `LocalPEPAdapter` wraps a local `PolicyEvaluator`:

```go
type LocalPEPAdapter struct {
    evaluator PolicyEvaluator
}

func (a *LocalPEPAdapter) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
    // Convert protobuf request to local request
    // Evaluate using local PolicyEvaluator
    // Convert response back to protobuf
}
```

## Configuration

```yaml
quicbaas:
  mode: embedded  # embedded | remote

  # Remote settings (when mode=remote)
  remote:
    address: "quicbaas.example.com:10443"
    protocol: grpc  # grpc | rest | quic | unix
```

## Error Handling

| Error Type | Description |
|------------|-------------|
| `AuthErrorMissingToken` | No token provided |
| `AuthErrorInvalidToken` | Token validation failed |
| `AuthErrorPermissionDenied` | Insufficient permissions |
| `AuthErrorServiceUnavailable` | QuicBaaS IAM not configured |

## Implementation Files

- `pkg/api/mcp/dragondb_auth.go` - Auth adapter implementation and QuicBaaS service interfaces
- `pkg/api/daemon/daemon.go` - Wiring QuicBaaS auth into MCP server
- `pkg/storage/quicbaas/interfaces.go` - Client and factory interfaces

## Security Considerations

1. **No Fallback**: If QuicBaaS IAM is unavailable, protected operations fail
2. **Token Caching**: Consider caching validated tokens for performance
3. **Tenant Isolation**: All requests scoped to tenant ID
4. **Audit Logging**: Log all authorization decisions

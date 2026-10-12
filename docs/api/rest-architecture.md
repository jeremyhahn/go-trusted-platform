# REST API Architecture

This document describes the REST API architecture and design principles for go-trusted-platform.

## Overview

The go-trusted-platform REST API follows a resource-oriented design pattern using standard HTTP methods and JSON payloads. All endpoints are versioned and organized by service domain.

### Design Principles

- **Resource-Oriented**: URLs represent resources with standard CRUD operations
- **Versioned**: API versioning via URL path (`/api/v1/`)
- **Consistent**: Uniform response structure across all endpoints
- **Secure**: mTLS, JWT, and API key authentication supported
- **Stateless**: Each request contains all necessary information

### Base URL

```
https://{host}:8443/api/v1
```

Default port: **8443** (HTTPS)

## Service Endpoints

### Certificate Authority (`/api/v1/ca`)

Manages PKI certificates, CRLs, and CA bundles.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/info` | Get CA information |
| POST | `/certificates` | Issue certificate |
| GET | `/certificates` | List certificates |
| GET | `/certificates/{serial}` | Get certificate by serial |
| DELETE | `/certificates/{serial}` | Revoke certificate |
| GET | `/bundle` | Get CA bundle |
| GET | `/crl` | Get Certificate Revocation List |

**Source**: `pkg/webservice/v1/rest/ca/router.go`

### DNS Management (`/api/v1/dns`)

Manages DNS zones, records, and DNSSEC.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/zones` | Create zone |
| GET | `/zones` | List zones |
| GET | `/zones/{zone}` | Get zone |
| PUT | `/zones/{zone}` | Update zone |
| DELETE | `/zones/{zone}` | Delete zone |
| POST | `/zones/{zone}/records` | Add record |
| GET | `/zones/{zone}/records` | List records |
| DELETE | `/zones/{zone}/records/{type}/{name}` | Delete record |
| POST | `/zones/{zone}/sign` | Sign zone with DNSSEC |
| GET | `/zones/{zone}/dnssec` | Get DNSSEC status |
| POST | `/register` | Register FQDN with IP |

**Source**: `pkg/webservice/v1/rest/dns/router.go`

### Identity and Access Management (`/api/v1/iam`)

Manages tenants, users, groups, roles, policies, and applications.

#### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants` | Create tenant |
| GET | `/tenants` | List tenants |
| GET | `/tenants/{tenant}` | Get tenant |
| PUT | `/tenants/{tenant}` | Update tenant |
| DELETE | `/tenants/{tenant}` | Delete tenant |

#### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{tenant}/users` | Create user |
| GET | `/tenants/{tenant}/users` | List users |
| GET | `/tenants/{tenant}/users/{id}` | Get user |
| PUT | `/tenants/{tenant}/users/{id}` | Update user |
| DELETE | `/tenants/{tenant}/users/{id}` | Delete user |
| POST | `/tenants/{tenant}/users/{id}/roles/{role}` | Assign role |
| DELETE | `/tenants/{tenant}/users/{id}/roles/{role}` | Remove role |

#### Group Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{tenant}/groups` | Create group |
| GET | `/tenants/{tenant}/groups` | List groups |
| GET | `/tenants/{tenant}/groups/{id}` | Get group |
| PUT | `/tenants/{tenant}/groups/{id}` | Update group |
| DELETE | `/tenants/{tenant}/groups/{id}` | Delete group |
| POST | `/tenants/{tenant}/groups/{id}/members/{user}` | Add member |
| DELETE | `/tenants/{tenant}/groups/{id}/members/{user}` | Remove member |

#### Role Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{tenant}/roles` | Create role |
| GET | `/tenants/{tenant}/roles` | List roles |
| GET | `/tenants/{tenant}/roles/{id}` | Get role |
| PUT | `/tenants/{tenant}/roles/{id}` | Update role |
| DELETE | `/tenants/{tenant}/roles/{id}` | Delete role |

#### Policy Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{tenant}/policies` | Create policy |
| GET | `/tenants/{tenant}/policies` | List policies |
| GET | `/tenants/{tenant}/policies/{id}` | Get policy |
| PUT | `/tenants/{tenant}/policies/{id}` | Update policy |
| DELETE | `/tenants/{tenant}/policies/{id}` | Delete policy |
| POST | `/tenants/{tenant}/policies/validate` | Validate policy |
| POST | `/tenants/{tenant}/policies/test` | Test policy |

#### Application Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/tenants/{tenant}/apps` | Register application |
| GET | `/tenants/{tenant}/apps` | List applications |
| GET | `/tenants/{tenant}/apps/{id}` | Get application |
| PUT | `/tenants/{tenant}/apps/{id}` | Update application |
| DELETE | `/tenants/{tenant}/apps/{id}` | Delete application |
| POST | `/tenants/{tenant}/apps/{id}/rotate` | Rotate app secret |

**Source**: `pkg/webservice/v1/rest/iam/router.go`

### Key Management Service (`/api/v1/kms`)

Manages cryptographic keys, secrets, and crypto operations.

#### Key Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/keys` | Generate key |
| POST | `/keys/import` | Import key |
| GET | `/keys` | List keys |
| GET | `/keys/{name}` | Get key |
| DELETE | `/keys/{name}` | Delete key |
| POST | `/keys/{name}/rotate` | Rotate key |
| PUT | `/keys/{name}/status` | Update key status |
| GET | `/keys/{name}/versions` | List key versions |

#### Cryptographic Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/encrypt/{name}` | Encrypt data |
| POST | `/decrypt/{name}` | Decrypt data |
| POST | `/sign/{name}` | Sign data |
| POST | `/verify/{name}` | Verify signature |
| POST | `/hmac/{name}` | Generate HMAC |
| POST | `/hmac/{name}/verify` | Verify HMAC |
| POST | `/hash` | Compute hash |
| POST | `/random` | Generate random bytes |

#### DEK Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/deks` | Create DEK |
| GET | `/deks` | List DEKs |
| GET | `/deks/{path}` | Get DEK |
| DELETE | `/deks/{path}` | Delete DEK |
| POST | `/deks/{path}/rotate` | Rotate DEK |
| GET | `/deks/{path}/status` | Get DEK status |

#### Secrets Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/secrets` | Store secret |
| GET | `/secrets` | List secrets |
| GET | `/secrets/{name}` | Get secret |
| DELETE | `/secrets/{name}` | Delete secret |
| POST | `/secrets/{name}/rotate` | Rotate secret |
| POST | `/secrets/{name}/rollback` | Rollback secret |
| PUT | `/secrets/{name}/status` | Update secret status |
| PUT | `/secrets/{name}/policy` | Set rotation policy |
| GET | `/secrets/{name}/policy` | Get rotation policy |
| GET | `/secrets/{name}/versions` | List secret versions |
| GET | `/secrets/{name}/versions/{version}` | Get secret version |

#### Backend Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/backend/status` | Backend status |
| POST | `/backend/test` | Backend test |

**Source**: `pkg/webservice/v1/rest/kms/router.go`

### Software Defined Networking (`/api/v1/sdn`)

Manages network bridges, ports, flows, policies, and VLANs.

#### Bridge Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/bridges` | Create bridge |
| GET | `/bridges` | List bridges |
| GET | `/bridges/{name}` | Get bridge |
| DELETE | `/bridges/{name}` | Delete bridge |

#### Port Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/bridges/{name}/ports` | Add port |
| DELETE | `/bridges/{name}/ports/{port}` | Delete port |
| GET | `/bridges/{name}/ports/{port}/state` | Get port state |
| PUT | `/bridges/{name}/ports/{port}/state` | Set port state |
| GET | `/bridges/{name}/ports/{port}/stats` | Get port statistics |

#### Flow Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/flows` | Add flow |
| DELETE | `/flows` | Delete flow |
| GET | `/flows` | List flows |

#### Policy and VLAN Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/policies` | Apply policy |
| GET | `/policies` | List policies |
| GET | `/policies/{id}` | Get policy |
| POST | `/vlans` | Create VLAN |
| GET | `/vlans` | List VLANs |

**Source**: `pkg/webservice/v1/rest/sdn/router.go`

### Virtual TPM (`/api/v1/vtpm`)

Manages vTPM bundles and templates.

#### Bundle Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/bundles` | Create bundle |
| GET | `/bundles` | List bundles |
| GET | `/bundles/{id}` | Get bundle |
| DELETE | `/bundles/{id}` | Delete bundle |
| GET | `/bundles/{id}/export` | Export bundle as tar.gz |
| POST | `/bundles/import` | Import bundle from tar.gz |
| POST | `/bundles/{id}/validate` | Validate bundle integrity |
| GET | `/bundles/{id}/path` | Get bundle filesystem path |
| GET | `/bundles/{id}/tpm-socket` | Get TPM socket path |
| GET | `/bundles/{id}/nvram` | Get NVRAM path |

#### Template Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/templates` | Create template |
| GET | `/templates` | List templates |
| GET | `/templates/{id}` | Get template |
| DELETE | `/templates/{id}` | Delete template |
| POST | `/templates/{id}/clone` | Clone template to create bundle |

**Source**: `pkg/webservice/v1/rest/vtpm/router.go`

### Platform Management (`/api/v1/platform`)

Manages platform health, status, services, and protocols.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Get platform health status |
| GET | `/status` | Get platform status |
| GET | `/version` | Get platform version |
| GET | `/services` | List all services |
| GET | `/services/{service}` | Get service status |
| POST | `/services/{service}/start` | Start a service |
| POST | `/services/{service}/stop` | Stop a service |
| POST | `/services/{service}/restart` | Restart a service |
| GET | `/protocols` | Get protocol status |

**Source**: `pkg/webservice/v1/rest/platform/router.go`

### Attestation (`/api/v1/attestation`)

Manages attestation manifests and TPM quotes.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/manifest` | Get current host manifest |
| POST | `/manifest/build` | Generate fresh manifest |
| POST | `/verify` | Verify a manifest |
| GET | `/quote` | Get TPM quote |
| POST | `/quote/verify` | Verify a quote |

**Source**: `pkg/webservice/v1/rest/attestation/router.go`

## Authentication

The REST API supports three authentication methods:

### mTLS (Mutual TLS)

Client certificate authentication for service-to-service communication.

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    MinVersion:   tls.VersionTLS13,
}
```

### JWT Bearer Token

Include the token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key

Include the API key in a custom header:

```http
X-API-Key: pk_live_abc123...
```

## Request/Response Format

### Content Types

The API supports both JSON and YAML formats based on the `Accept` header:

| Accept Header | Content-Type |
|---------------|--------------|
| `application/json` | `application/json` |
| `text/json` | `application/json` |
| `application/yaml` | `application/yaml` |
| `text/yaml` | `application/yaml` |

Default: `application/json`

### Standard Response Envelope

All responses use a consistent envelope structure:

```json
{
  "code": 200,
  "success": true,
  "error": "",
  "payload": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `code` | int | HTTP status code |
| `success` | bool | Operation success indicator |
| `error` | string | Error message (empty on success) |
| `payload` | object | Response data |

### Success Response Example

```json
{
  "code": 200,
  "success": true,
  "error": "",
  "payload": {
    "certificate": {
      "serial": "01:23:45:67:89:AB:CD:EF",
      "subject": {
        "common_name": "server.example.com"
      },
      "not_before": 1705708800,
      "not_after": 1737244800
    },
    "timestamp": 1705708800
  }
}
```

### Error Response Example

```json
{
  "code": 400,
  "success": false,
  "error": "common_name is required",
  "payload": null
}
```

### HTTP Status Codes

| Status | Code | Description |
|--------|------|-------------|
| 200 | OK | Success |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Missing/invalid authentication |
| 403 | Forbidden | Permission denied |
| 404 | Not Found | Resource not found |
| 500 | Internal Server Error | Server error |

## Pagination

List endpoints support cursor-based pagination.

### Request Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int32 | Maximum items to return |
| `cursor` | string | Cursor from previous response |

### Paginated Response

```json
{
  "code": 200,
  "success": true,
  "payload": {
    "certificates": [ ... ],
    "next_cursor": "eyJzZXJpYWwiOiIxMjM0In0=",
    "has_more": true,
    "total_count": 150,
    "timestamp": 1705708800
  }
}
```

### Example Paginated Request

```bash
# First page
curl "https://platform:8443/api/v1/ca/certificates?limit=20"

# Next page
curl "https://platform:8443/api/v1/ca/certificates?limit=20&cursor=eyJzZXJpYWwiOiIxMjM0In0="
```

## Versioning

### URL-Based Versioning

API versions are specified in the URL path:

```
/api/v1/...   # Version 1 (current)
/api/v2/...   # Version 2 (future)
```

### Version Lifecycle

| Version | Status | Support |
|---------|--------|---------|
| v1 | Current | Full support |
| v2 | Planned | Future release |

### Deprecation Policy

- Minimum 6-month notice before deprecation
- Deprecated endpoints return `X-Deprecated: true` header
- Migration guides provided for version upgrades

## Request Headers

### Required Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Content-Type` | `application/json` | Request body format |

### Optional Headers

| Header | Description |
|--------|-------------|
| `Accept` | Response format preference |
| `Authorization` | Bearer token authentication |
| `X-API-Key` | API key authentication |
| `X-Request-ID` | Correlation ID for tracing |
| `X-Tenant-ID` | Multi-tenant requests |

## Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | Response body format |
| `X-Request-ID` | Correlation ID (echoed or generated) |
| `X-Deprecated` | Indicates deprecated endpoint |

## Examples

### Issue Certificate

```bash
curl -X POST https://platform:8443/api/v1/ca/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "common_name": "server.example.com",
      "organization": "Example Corp"
    },
    "sans": {
      "dns": ["server.example.com", "localhost"],
      "ips": ["192.168.1.100"]
    },
    "valid_days": 365,
    "key_algorithm": "ECDSA-P256"
  }'
```

### Create User

```bash
curl -X POST https://platform:8443/api/v1/iam/tenants/default/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "name": "New User"
  }'
```

### Encrypt Data

```bash
curl -X POST https://platform:8443/api/v1/kms/encrypt/my-key \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "aGVsbG8gd29ybGQ="
  }'
```

### Create DNS Zone

```bash
curl -X POST https://platform:8443/api/v1/dns/zones \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com",
    "type": "primary"
  }'
```

## Router Implementation

Each service implements a router that registers routes with the Gorilla Mux router:

```go
type ServiceRouter struct {
    handlers *ServiceHandlers
}

func (r *ServiceRouter) RegisterRoutes(router *mux.Router) {
    subrouter := router.PathPrefix(basePath).Subrouter()
    subrouter.HandleFunc("/resource", r.handlers.Create).Methods("POST")
    subrouter.HandleFunc("/resource", r.handlers.List).Methods("GET")
    subrouter.HandleFunc("/resource/{id}", r.handlers.Get).Methods("GET")
    subrouter.HandleFunc("/resource/{id}", r.handlers.Update).Methods("PUT")
    subrouter.HandleFunc("/resource/{id}", r.handlers.Delete).Methods("DELETE")
}
```

## Related Documentation

- [REST API Reference](protocols/rest-api.md) - Detailed endpoint reference
- [Authentication Flows](process-flows/authentication.md) - Authentication details
- [Protocol Overview](protocols/overview.md) - Multi-protocol support
- [Go SDK](../sdk/user.md) - Go client library
- [JavaScript SDK](sdk-javascript.md) - JavaScript client library

# REST API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](../../daemon/api.md) and each feature's `api.md`.

The REST API provides HTTP/HTTPS access to all platform services, designed for web clients and external integrations.

## Connection Configuration

### Base URL

```
https://{host}:{port}/api/v1
```

Default port: **8443**

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_REST_URL` | Full base URL | `https://localhost:8443` |
| `PLATFORM_REST_PORT` | Port number | `8443` |
| `PLATFORM_REST_TLS` | Enable TLS | `true` |

### Go SDK Configuration

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"

client, err := platform.NewClient(ctx,
    platform.WithRESTAddr("platform.example.com:8443"),
    platform.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}),
    platform.WithOnlyProtocol(platform.ProtocolREST),
)
```

### JavaScript SDK Configuration

```typescript
const client = new PlatformClient({
  baseUrl: 'https://platform.example.com:8443',
  credentials: 'include',
  headers: {
    'X-Custom-Header': 'value',
  },
});
```

## Authentication

### Bearer Token

```http
GET /api/v1/ca/info HTTP/1.1
Host: platform.example.com:8443
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

### Cookie-Based

```http
GET /api/v1/ca/info HTTP/1.1
Host: platform.example.com:8443
Cookie: platform_session=abc123...
Content-Type: application/json
```

### API Key

```http
GET /api/v1/ca/info HTTP/1.1
Host: platform.example.com:8443
X-API-Key: pk_live_abc123...
Content-Type: application/json
```

## Endpoint Patterns

All endpoints follow a consistent pattern:

```
{method} /api/v1/{service}/{resource}[/{id}][/{action}]
```

### Examples

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List certificates | GET | `/api/v1/ca/certificates` |
| Get certificate | GET | `/api/v1/ca/certificates/{serial}` |
| Issue certificate | POST | `/api/v1/ca/certificates` |
| Revoke certificate | POST | `/api/v1/ca/certificates/revoke` |
| Renew certificate | POST | `/api/v1/ca/certificates/renew` |

## Request/Response Formats

### Request Format

```json
{
  "fieldName": "value",
  "nestedObject": {
    "innerField": "value"
  },
  "arrayField": ["item1", "item2"]
}
```

### Success Response

```json
{
  "data": {
    "id": "12345",
    "status": "active",
    "createdAt": "2025-01-20T10:30:00Z"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "commonName is required",
    "details": {
      "field": "commonName",
      "constraint": "required"
    }
  }
}
```

### List Response

```json
{
  "data": {
    "items": [...],
    "total": 150,
    "page": 1,
    "pageSize": 20,
    "hasMore": true
  }
}
```

## Common Headers

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `Accept` | No | `application/json` |
| `Authorization` | Conditional | `Bearer {token}` |
| `X-API-Key` | Conditional | API key authentication |
| `X-Request-ID` | No | Correlation ID for tracing |
| `X-Tenant-ID` | Conditional | Multi-tenant requests |

### Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-Request-ID` | Echo of request ID or generated |
| `X-RateLimit-Limit` | Requests per minute allowed |
| `X-RateLimit-Remaining` | Requests remaining |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

## Error Codes

### HTTP Status Codes

| Status | Code | Description |
|--------|------|-------------|
| 200 | OK | Success |
| 201 | Created | Resource created |
| 204 | No Content | Success, no body |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Missing/invalid auth |
| 403 | Forbidden | Permission denied |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 429 | Too Many Requests | Rate limited |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service down |

### Error Code Mapping

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `INVALID_ARGUMENT` | 400 | Invalid request parameters |
| `UNAUTHENTICATED` | 401 | Authentication required |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `ALREADY_EXISTS` | 409 | Resource already exists |
| `RESOURCE_EXHAUSTED` | 429 | Rate limit exceeded |
| `INTERNAL` | 500 | Internal server error |
| `UNAVAILABLE` | 503 | Service unavailable |

## Service Endpoints

### Platform Daemon

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/version` | Get platform version |
| GET | `/api/v1/status` | Get platform status |
| GET | `/health` | Health check |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |

### Certificate Authority

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ca/info` | Get CA information |
| POST | `/api/v1/ca/certificates` | Issue certificate |
| GET | `/api/v1/ca/certificates` | List certificates |
| GET | `/api/v1/ca/certificates/{serial}` | Get certificate |
| POST | `/api/v1/ca/certificates/revoke` | Revoke certificate |
| POST | `/api/v1/ca/certificates/renew` | Renew certificate |
| POST | `/api/v1/ca/certificates/verify` | Verify certificate |
| GET | `/api/v1/ca/crl` | Get CRL |
| GET | `/api/v1/ca/bundle` | Get CA bundle |
| GET | `/api/v1/ca/trust-root` | Get trust root |

### IAM Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/iam/authenticate` | Authenticate user |
| POST | `/api/v1/iam/users` | Create user |
| GET | `/api/v1/iam/users` | List users |
| GET | `/api/v1/iam/users/{id}` | Get user |
| DELETE | `/api/v1/iam/users/{id}` | Delete user |
| GET | `/api/v1/iam/users/current` | Get current user |
| POST | `/api/v1/iam/users/password` | Change password |
| POST | `/api/v1/iam/roles` | Create role |
| GET | `/api/v1/iam/roles` | List roles |
| POST | `/api/v1/iam/roles/assign` | Assign role |
| POST | `/api/v1/iam/roles/revoke` | Revoke role |
| POST | `/api/v1/iam/tokens` | Create token |
| POST | `/api/v1/iam/tokens/verify` | Verify token |
| POST | `/api/v1/iam/tokens/refresh` | Refresh token |
| POST | `/api/v1/iam/tokens/revoke` | Revoke token |
| POST | `/api/v1/iam/permissions/check` | Check permission |

### KMS Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/kms/keys` | Create key |
| GET | `/api/v1/kms/keys` | List keys |
| GET | `/api/v1/kms/keys/{id}` | Get key |
| DELETE | `/api/v1/kms/keys/{id}` | Delete key |
| POST | `/api/v1/kms/keys/rotate` | Rotate key |
| POST | `/api/v1/kms/encrypt` | Encrypt data |
| POST | `/api/v1/kms/decrypt` | Decrypt data |
| POST | `/api/v1/kms/sign` | Sign data |
| POST | `/api/v1/kms/verify` | Verify signature |
| POST | `/api/v1/kms/random` | Generate random bytes |
| POST | `/api/v1/kms/data-keys` | Generate data key |

### vTPM Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/vtpm/instances` | Create vTPM |
| GET | `/api/v1/vtpm/instances` | List vTPMs |
| DELETE | `/api/v1/vtpm/instances/{id}` | Delete vTPM |
| POST | `/api/v1/vtpm/instances/start` | Start vTPM |
| POST | `/api/v1/vtpm/instances/stop` | Stop vTPM |
| GET | `/api/v1/vtpm/instances/state` | Get vTPM state |
| POST | `/api/v1/vtpm/quote` | Get quote |
| POST | `/api/v1/vtpm/seal` | Seal data |
| POST | `/api/v1/vtpm/unseal` | Unseal data |
| POST | `/api/v1/vtpm/pcrs/extend` | Extend PCR |
| GET | `/api/v1/vtpm/pcrs` | Read PCR |

### Device Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/devices` | Register device |
| GET | `/api/v1/devices` | List devices |
| GET | `/api/v1/devices/{id}` | Get device |
| PUT | `/api/v1/devices/{id}` | Update device |
| DELETE | `/api/v1/devices/{id}` | Delete device |
| POST | `/api/v1/devices/attest` | Attest device |

### Attestation Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/attestation/quote` | Get attestation quote |
| POST | `/api/v1/attestation/verify` | Verify quote |
| GET | `/api/v1/attestation/ek` | Get endorsement key |
| GET | `/api/v1/attestation/ak` | Get attestation key |
| POST | `/api/v1/attestation/ak` | Create attestation key |
| POST | `/api/v1/attestation/challenge` | Create challenge |
| POST | `/api/v1/attestation/challenge/verify` | Verify challenge |

## Example Requests

### Issue Certificate

```bash
curl -X POST https://platform.example.com:8443/api/v1/ca/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "commonName": "server.example.com",
    "organization": ["Example Corp"],
    "dnsNames": ["server.example.com", "localhost"],
    "validDays": 365
  }'
```

**Response:**

```json
{
  "data": {
    "serial": "01:23:45:67:89:AB:CD:EF",
    "subject": "CN=server.example.com,O=Example Corp",
    "issuer": "CN=Platform CA",
    "notBefore": "2025-01-20T00:00:00Z",
    "notAfter": "2026-01-20T00:00:00Z",
    "certificate": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

### Create User

```bash
curl -X POST https://platform.example.com:8443/api/v1/iam/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "name": "New User",
    "tenantId": "default",
    "roles": ["operator"]
  }'
```

### Encrypt Data

```bash
curl -X POST https://platform.example.com:8443/api/v1/kms/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId": "my-key",
    "plaintext": "aGVsbG8gd29ybGQ="
  }'
```

## Rate Limiting

Default rate limits per client:

| Endpoint Category | Requests/Minute |
|------------------|-----------------|
| Health checks | Unlimited |
| Read operations | 1000 |
| Write operations | 100 |
| Authentication | 30 |
| Certificate issuance | 10 |

**Rate limit response:**

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705752000
Retry-After: 60

{
  "error": {
    "code": "RESOURCE_EXHAUSTED",
    "message": "Rate limit exceeded",
    "details": {
      "retryAfter": 60
    }
  }
}
```

## Pagination

### Request Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-indexed) |
| `pageSize` | integer | 20 | Items per page (max 100) |
| `sortBy` | string | varies | Sort field |
| `sortOrder` | string | `asc` | Sort order (`asc`/`desc`) |

### Example

```bash
curl "https://platform.example.com:8443/api/v1/ca/certificates?page=2&pageSize=50&sortBy=notAfter&sortOrder=desc" \
  -H "Authorization: Bearer $TOKEN"
```

### Response

```json
{
  "data": {
    "items": [...],
    "total": 150,
    "page": 2,
    "pageSize": 50,
    "hasMore": true
  }
}
```

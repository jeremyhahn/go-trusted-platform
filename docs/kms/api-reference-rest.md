# KMS REST API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). REST KMS routes also require the admin role, not only mTLS or a bearer token.

REST API endpoints for the KMS service via HTTPS.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/kms` |
| Port | 8443 (HTTPS) |
| Content-Type | `application/json` |
| Auth | mTLS + Bearer Token |

## Key Lifecycle Operations

### Revoke Key

Mark a key as revoked, preventing all future cryptographic operations.

```http
POST /api/v1/kms/keys/{key_id}/revoke
Content-Type: application/json

{
  "reason": "Key compromised during update deployment"
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key_id` | string | Yes | Key identifier to revoke |
| `reason` | string | No | Audit trail reason for revocation |

**Response (200 OK):**

```json
{
  "key_id": "my-encryption-key",
  "status": "REVOKED",
  "timestamp": 1705416600
}
```

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 404 | NotFound | Key does not exist |
| 409 | AlreadyRevoked | Key is already revoked |
| 503 | ServiceUnavailable | KMS backend offline |

---

### Get Key Metadata

Retrieve key metadata (name, description, tags, timestamps) without exposing key material.

```http
GET /api/v1/kms/keys/{key_id}/metadata
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key_id` | string | Yes | Key identifier |

**Response (200 OK):**

```json
{
  "metadata": {
    "key_id": "my-encryption-key",
    "name": "My Encryption Key",
    "description": "Production encryption key",
    "algorithm": "AES-256-GCM",
    "status": "ENABLED",
    "usage": ["ENCRYPT", "DECRYPT"],
    "exportable": false,
    "deletion_protection": true,
    "tags": {
      "team": "security",
      "environment": "production"
    },
    "created_at": 1704067200,
    "updated_at": 1705416600
  },
  "timestamp": 1705416600
}
```

**Query Parameters:**

None; use GET with key ID in path.

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 404 | NotFound | Key does not exist |
| 503 | ServiceUnavailable | KMS backend offline |

---

### Update Key Metadata

Update mutable key metadata fields (name, description, tags).

```http
PUT /api/v1/kms/keys/{key_id}/metadata
Content-Type: application/json

{
  "name": "Updated Key Name",
  "description": "Updated description",
  "tags": {
    "team": "security",
    "status": "active"
  },
  "remove_tags": ["deprecated", "old-owner"]
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key_id` | string | Yes | Key identifier |
| `name` | string | No | New display name |
| `description` | string | No | New description |
| `tags` | object | No | Tags to add/update as key-value pairs |
| `remove_tags` | array | No | Tag keys to remove |

**Response (200 OK):**

```json
{
  "metadata": {
    "key_id": "my-encryption-key",
    "name": "Updated Key Name",
    "description": "Updated description",
    "algorithm": "AES-256-GCM",
    "status": "ENABLED",
    "tags": {
      "team": "security",
      "status": "active"
    },
    "created_at": 1704067200,
    "updated_at": 1705416600
  },
  "timestamp": 1705416600
}
```

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | BadRequest | Invalid metadata format |
| 404 | NotFound | Key does not exist |
| 503 | ServiceUnavailable | KMS backend offline |

---

### Get Key Policy

Retrieve the access control policy for a key.

```http
GET /api/v1/kms/keys/{key_id}/policy
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key_id` | string | Yes | Key identifier |

**Response (200 OK):**

```json
{
  "policy": {
    "key_id": "my-encryption-key",
    "version": 2,
    "allowed_operations": ["ENCRYPT", "DECRYPT", "WRAP_KEY"],
    "allowed_principals": ["user:alice", "service:app-api"],
    "denied_principals": ["user:bob"],
    "expires_at": 1735689600,
    "rotation_required": false,
    "max_usage_count": 1000000,
    "require_mfa": false,
    "updated_at": 1705416600
  },
  "timestamp": 1705416600
}
```

**Field Descriptions:**

| Field | Description |
|-------|-------------|
| `version` | Policy version number (incremented on updates) |
| `allowed_operations` | List of permitted operations (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, DERIVE_KEY) |
| `allowed_principals` | List of authorized identities (format: type:name, e.g., user:alice, service:app-api, role:admin) |
| `denied_principals` | List of explicitly denied identities (deny list takes precedence) |
| `expires_at` | Unix timestamp when policy expires (0 = never expires) |
| `rotation_required` | If true, key rotation required before further use |
| `max_usage_count` | Maximum cryptographic operations allowed (0 = unlimited) |
| `require_mfa` | If true, MFA required for all operations |

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 404 | NotFound | Key or policy does not exist |
| 503 | ServiceUnavailable | KMS backend offline |

---

### Set Key Policy

Set or update the access control policy for a key.

```http
PUT /api/v1/kms/keys/{key_id}/policy
Content-Type: application/json

{
  "allowed_operations": ["ENCRYPT", "DECRYPT"],
  "allowed_principals": ["user:alice", "service:app-api"],
  "denied_principals": ["user:bob"],
  "expires_at": 1735689600,
  "rotation_required": false,
  "max_usage_count": 1000000,
  "require_mfa": false
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `key_id` | string | Yes | Key identifier |
| `allowed_operations` | array | No | Permitted operations (ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY) |
| `allowed_principals` | array | No | Authorized users/services/roles |
| `denied_principals` | array | No | Explicitly denied principals (overrides allow list) |
| `expires_at` | number | No | Unix timestamp when policy expires |
| `rotation_required` | boolean | No | Require rotation before use |
| `max_usage_count` | number | No | Max operations (0 = unlimited) |
| `require_mfa` | boolean | No | Require MFA for key operations |

**Response (200 OK):**

```json
{
  "key_id": "my-encryption-key",
  "policy_version": 3,
  "timestamp": 1705416600
}
```

**Policy Enforcement:**

- If `allowed_principals` is empty, all authenticated users are allowed
- `denied_principals` is checked before `allowed_principals` (deny wins)
- Policy version increments on each update
- Expired policies continue to enforce restrictions until explicitly removed
- Operations exceeding `max_usage_count` are rejected

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 400 | BadRequest | Invalid policy format or conflicting settings |
| 404 | NotFound | Key does not exist |
| 409 | Conflict | Policy version mismatch |
| 503 | ServiceUnavailable | KMS backend offline |

---

## Metadata & Capabilities

### List Supported Algorithms

List all cryptographic algorithms supported by the KMS backend.

```http
GET /api/v1/kms/algorithms
```

**Response (200 OK):**

```json
{
  "algorithms": [
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
    "ECDSA-P256",
    "ECDSA-P384",
    "ECDSA-P521",
    "ED25519",
    "ED448",
    "HMAC-SHA256",
    "HMAC-SHA384",
    "HMAC-SHA512"
  ],
  "timestamp": 1705416600
}
```

---

### Backend Status

Get health and capability information about the KMS backend.

```http
GET /api/v1/kms/backend/status
```

**Response (200 OK):**

```json
{
  "healthy": true,
  "backend_type": "hybrid",
  "capabilities": {
    "encrypt": true,
    "decrypt": true,
    "sign": true,
    "verify": true,
    "wrap_key": true,
    "derive_key": true,
    "generate_mac": true,
    "verify_mac": true
  },
  "device": "/dev/tpmrm0",
  "region": "us-east-1",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "timestamp": 1705416600
}
```

**Backend Types:**

| Type | Description |
|------|-------------|
| `software` | Software-only key storage (QuicBaaS) |
| `tpm2` | TPM 2.0 hardware-protected keys |
| `hybrid` | Software + TPM with automatic routing |
| `hsm` | PKCS#11 HSM integration |
| `cloud` | AWS KMS / Azure Key Vault / GCP Cloud KMS |

**Error Responses:**

| Status | Error | Description |
|--------|-------|-------------|
| 503 | ServiceUnavailable | KMS backend offline or unhealthy |

---

## Secrets Operations

### Store Secret

Store a secret with optional metadata and automatic encryption.

```http
POST /api/v1/kms/secrets
Content-Type: application/json

{
  "secret_id": "api-key",
  "data": "c2stMTIzNDU2Nzg5MA==",
  "metadata": {
    "source": "github",
    "purpose": "ci-deployment"
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret_id` | string | Yes | Secret identifier / path |
| `data` | string | Yes | Base64-encoded secret data |
| `metadata` | object | No | Version-specific metadata key-value pairs |

**Response (201 Created):**

```json
{
  "secret_id": "api-key",
  "version": 1,
  "created_at": 1705416600,
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### Get Secret

Retrieve a secret by ID, optionally at a specific version.

```http
GET /api/v1/kms/secrets/{secret_id}?version=1
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | number | Specific version (0 or omitted = latest) |

**Response (200 OK):**

```json
{
  "secret_id": "api-key",
  "version": 1,
  "data": "c2stMTIzNDU2Nzg5MA==",
  "metadata": {
    "source": "github",
    "purpose": "ci-deployment"
  },
  "created_at": 1705416600,
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### List Secrets

List secrets (identifiers and metadata only, no secret data).

```http
GET /api/v1/kms/secrets?limit=50&cursor=next
```

**Query Parameters:**

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `limit` | number | Max secrets to return | 50 |
| `cursor` | string | Pagination cursor | |

**Response (200 OK):**

```json
{
  "secrets": [
    {
      "secret_id": "api-key",
      "version": 1,
      "created_at": 1705416600,
      "updated_at": 1705416600
    },
    {
      "secret_id": "db-password",
      "version": 2,
      "created_at": 1705416500,
      "updated_at": 1705416600
    }
  ],
  "next_cursor": "cursor-123",
  "timestamp": 1705416600
}
```

---

### Delete Secret

Delete a secret (optionally cascade delete all versions).

```http
DELETE /api/v1/kms/secrets/{secret_id}
```

**Response (204 No Content):**

```
(empty body)
```

---

### Set Secret Rotation Policy

Set automatic rotation policy for a secret.

```http
PUT /api/v1/kms/secrets/{secret_id}/rotation-policy
Content-Type: application/json

{
  "enabled": true,
  "interval_seconds": 7776000,
  "retain_versions": 3
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret_id` | string | Yes | Secret identifier |
| `enabled` | boolean | Yes | Enable automatic rotation |
| `interval_seconds` | number | Yes | Rotation interval in seconds (90 days = 7776000) |
| `retain_versions` | number | No | Number of old versions to retain (default: 3) |

**Response (200 OK):**

```json
{
  "secret_id": "api-key",
  "rotation_enabled": true,
  "interval_seconds": 7776000,
  "retain_versions": 3,
  "next_rotation_at": 1713192600,
  "timestamp": 1705416600
}
```

---

### Get Secret Rotation Policy

Retrieve the rotation policy for a secret.

```http
GET /api/v1/kms/secrets/{secret_id}/rotation-policy
```

**Response (200 OK):**

```json
{
  "secret_id": "api-key",
  "rotation_enabled": true,
  "interval_seconds": 7776000,
  "retain_versions": 3,
  "last_rotation_at": 1697640600,
  "next_rotation_at": 1713192600,
  "timestamp": 1705416600
}
```

---

## Integration Examples

### Curl Examples

```bash
# Revoke a key
curl -X POST https://localhost:8443/api/v1/kms/keys/my-key/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "Key compromise suspected"}'

# Get key metadata
curl https://localhost:8443/api/v1/kms/keys/my-key/metadata

# Update key metadata
curl -X PUT https://localhost:8443/api/v1/kms/keys/my-key/metadata \
  -H "Content-Type: application/json" \
  -d '{"name": "New Name", "tags": {"env": "prod"}}'

# Set key policy
curl -X PUT https://localhost:8443/api/v1/kms/keys/my-key/policy \
  -H "Content-Type: application/json" \
  -d '{
    "allowed_operations": ["ENCRYPT", "DECRYPT"],
    "allowed_principals": ["user:alice"],
    "require_mfa": true
  }'

# List supported algorithms
curl https://localhost:8443/api/v1/kms/algorithms

# Get backend status
curl https://localhost:8443/api/v1/kms/backend/status

# Store secret
curl -X POST https://localhost:8443/api/v1/kms/secrets \
  -H "Content-Type: application/json" \
  -d '{"secret_id": "api-key", "data": "c2stMTIzNDU2Nzg5MA=="}'

# Get secret
curl https://localhost:8443/api/v1/kms/secrets/api-key

# Set secret rotation policy
curl -X PUT https://localhost:8443/api/v1/kms/secrets/api-key/rotation-policy \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "interval_seconds": 7776000, "retain_versions": 3}'
```

### JavaScript/Fetch Examples

```javascript
// Get key metadata
const metadata = await fetch('https://localhost:8443/api/v1/kms/keys/my-key/metadata', {
  method: 'GET',
  headers: { 'Authorization': 'Bearer token' }
});

// Revoke a key
const revoke = await fetch('https://localhost:8443/api/v1/kms/keys/my-key/revoke', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token'
  },
  body: JSON.stringify({ reason: 'Compromise suspected' })
});

// Store a secret
const secret = await fetch('https://localhost:8443/api/v1/kms/secrets', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token'
  },
  body: JSON.stringify({
    secret_id: 'api-key',
    data: 'c2stMTIzNDU2Nzg5MA==',
    metadata: { source: 'github' }
  })
});
```

---

## Status Codes

| Code | Description |
|------|-------------|
| 200 | Success (GET, PUT) |
| 201 | Created (POST) |
| 204 | No Content (DELETE) |
| 400 | Bad Request (invalid input) |
| 401 | Unauthorized (authentication failed) |
| 403 | Forbidden (policy denied or key disabled) |
| 404 | Not Found (key/secret doesn't exist) |
| 409 | Conflict (state conflict, e.g., already revoked) |
| 503 | Service Unavailable (KMS backend offline) |

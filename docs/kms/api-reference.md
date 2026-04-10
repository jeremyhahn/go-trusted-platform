# KMS API Reference

## Overview

The KMS API provides cryptographic key management, secrets storage, and cryptographic operations. The API is available via REST, gRPC, and CLI interfaces with 100% feature parity.

**Implementation Status:**
- gRPC API: 100% complete
- REST API: 100% complete (99.9% test coverage)
- CLI Commands: 100% complete

Base path: `/api/v1/kms`

## REST API Endpoints

### Key Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/keys` | Generate a new key |
| POST | `/keys/import` | Import an external key |
| GET | `/keys` | List all keys |
| GET | `/keys/{name}` | Get key by ID |
| DELETE | `/keys/{name}` | Delete a key |
| POST | `/keys/{name}/rotate` | Rotate a key |
| PUT | `/keys/{name}/status` | Update key status |
| GET | `/keys/{name}/versions` | List key versions |

#### Generate Key

```http
POST /api/v1/kms/keys
Content-Type: application/json

{
  "key_spec": {
    "algorithm": "AES-256-GCM",
    "usage": ["ENCRYPT", "DECRYPT"],
    "exportable": false,
    "deletion_protection": true
  },
  "name": "my-encryption-key",
  "description": "Production encryption key",
  "tags": {"team": "security"},
  "owner": "user-123"
}
```

**Response:**
```json
{
  "key": {
    "key_id": "my-encryption-key",
    "version": 1,
    "algorithm": "AES-256-GCM",
    "status": "ENABLED",
    "created_at": 1704067200
  },
  "metadata": {
    "key_id": "my-encryption-key",
    "name": "my-encryption-key",
    "algorithm": "AES-256-GCM",
    "status": "ENABLED",
    "usage": ["ENCRYPT", "DECRYPT"],
    "exportable": false,
    "deletion_protection": true
  },
  "timestamp": 1704067200
}
```

#### Import Key

```http
POST /api/v1/kms/keys/import
Content-Type: application/json

{
  "key_material": "<base64-encoded-key>",
  "wrapping_key_id": "transport-key",
  "key_spec": {
    "algorithm": "AES-256-GCM",
    "usage": ["ENCRYPT", "DECRYPT"]
  },
  "name": "imported-key"
}
```

#### Get Key

```http
GET /api/v1/kms/keys/{name}?version=2
```

#### List Keys

```http
GET /api/v1/kms/keys?limit=50&cursor=next-page-token&algorithm=AES-256-GCM&status=ENABLED
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `limit` | Max results (default: 50, max: 1000) |
| `cursor` | Pagination cursor |
| `algorithm` | Filter by algorithm |
| `status` | Filter by status |

#### Rotate Key

```http
POST /api/v1/kms/keys/{name}/rotate
Content-Type: application/json

{
  "retain_old_version": true
}
```

**Response:**
```json
{
  "key_id": "my-key",
  "old_version": 1,
  "new_version": 2,
  "timestamp": 1704067200
}
```

#### Delete Key

```http
DELETE /api/v1/kms/keys/{name}?pending_window_days=7&force=false
```

#### Update Key Status

```http
PUT /api/v1/kms/keys/{name}/status
Content-Type: application/json

{
  "status": "DISABLED",
  "version": 0
}
```

#### List Key Versions

```http
GET /api/v1/kms/keys/{name}/versions?limit=50&cursor=token
```

### Cryptographic Operations

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

#### Encrypt

```http
POST /api/v1/kms/encrypt/{name}
Content-Type: application/json

{
  "plaintext": "<base64-encoded-data>",
  "context": "<optional-aad>",
  "nonce": "<optional-nonce>"
}
```

**Response:**
```json
{
  "key_id": "my-key",
  "key_version": 1,
  "ciphertext": "<base64-encoded>",
  "nonce": "<base64-encoded>",
  "timestamp": 1704067200
}
```

#### Decrypt

```http
POST /api/v1/kms/decrypt/{name}
Content-Type: application/json

{
  "ciphertext": "<base64-encoded>",
  "context": "<optional-aad>",
  "nonce": "<base64-encoded>",
  "key_version": 1
}
```

#### Sign

```http
POST /api/v1/kms/sign/{name}
Content-Type: application/json

{
  "message": "<base64-encoded>",
  "hash_algorithm": "SHA256"
}
```

**Response:**
```json
{
  "key_id": "signing-key",
  "key_version": 1,
  "signature": "<base64-encoded>",
  "hash_algorithm": "SHA256",
  "timestamp": 1704067200
}
```

#### Verify

```http
POST /api/v1/kms/verify/{name}
Content-Type: application/json

{
  "message": "<base64-encoded>",
  "signature": "<base64-encoded>",
  "hash_algorithm": "SHA256",
  "key_version": 1
}
```

**Response:**
```json
{
  "key_id": "signing-key",
  "key_version": 1,
  "valid": true,
  "timestamp": 1704067200
}
```

#### Hash

```http
POST /api/v1/kms/hash
Content-Type: application/json

{
  "data": "<base64-encoded>",
  "algorithm": "SHA256"
}
```

**Supported Hash Algorithms:** SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512, BLAKE2B-256, BLAKE2B-512

#### HMAC

```http
POST /api/v1/kms/hmac/{name}
Content-Type: application/json

{
  "message": "<base64-encoded>",
  "hash_algorithm": "SHA256"
}
```

#### Generate Random

```http
POST /api/v1/kms/random
Content-Type: application/json

{
  "num_bytes": 32
}
```

**Response:**
```json
{
  "random_bytes": "<base64-encoded>",
  "timestamp": 1704067200
}
```

### DEK Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/deks` | Create DEK |
| GET | `/deks` | List DEKs |
| GET | `/deks/{path}` | Get DEK |
| POST | `/deks/{path}/rotate` | Rotate DEK |
| DELETE | `/deks/{path}` | Delete DEK |
| GET | `/deks/{path}/status` | Get DEK status |

#### Create DEK

```http
POST /api/v1/kms/deks
Content-Type: application/json

{
  "path": "/tenant/myapp/default",
  "algorithm": "AES-256-GCM",
  "description": "Application data encryption",
  "max_operations": 1000000,
  "max_bytes": 10737418240,
  "warning_percent": 80
}
```

#### List DEKs

```http
GET /api/v1/kms/deks?prefix=/tenant/myapp&recursive=true&limit=100
```

#### Get DEK

```http
GET /api/v1/kms/deks/tenant/myapp/default
```

#### Rotate DEK

```http
POST /api/v1/kms/deks/tenant/myapp/default/rotate
Content-Type: application/json

{
  "background": true
}
```

#### Delete DEK

```http
DELETE /api/v1/kms/deks/tenant/myapp/old?force=true&migrate_to=/tenant/myapp/new
```

#### Get DEK Status

```http
GET /api/v1/kms/deks/tenant/myapp/default/status
```

**Response:**
```json
{
  "dek": {
    "path": "/tenant/myapp/default",
    "algorithm": "AES-256-GCM",
    "version": 2,
    "status": "ENABLED",
    "is_default": true,
    "usage_count": 15000,
    "bytes_used": 1048576000
  },
  "reencryption_progress": {
    "in_progress": false,
    "total_keys": 0,
    "processed_keys": 0
  },
  "timestamp": 1704067200
}
```

### Secrets Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/secrets` | Store secret |
| GET | `/secrets` | List secrets |
| GET | `/secrets?prefix=...` | Get secrets by prefix |
| GET | `/secrets/{name}` | Get secret |
| DELETE | `/secrets/{name}` | Delete secret |
| POST | `/secrets/{name}/rotate` | Rotate secret |
| GET | `/secrets/{name}/versions` | List versions |
| GET | `/secrets/{name}/versions/{version}` | Get version |
| POST | `/secrets/{name}/rollback` | Rollback to version |
| PUT | `/secrets/{name}/status` | Update status |
| PUT | `/secrets/{name}/policy` | Set rotation policy |
| GET | `/secrets/{name}/policy` | Get rotation policy |

#### Store Secret

```http
POST /api/v1/kms/secrets
Content-Type: application/json

{
  "secret_id": "api-key",
  "name": "api-key",
  "description": "Production API key",
  "data": "<base64-encoded-secret>",
  "metadata": {"environment": "production"},
  "tags": {"team": "platform"},
  "tenant_id": "tenant-123",
  "key_id": "my-encryption-key",
  "algorithm": "AES-256-GCM"
}
```

**Response:**
```json
{
  "secret_id": "api-key",
  "version": 1,
  "timestamp": 1704067200
}
```

#### Get Secret

```http
GET /api/v1/kms/secrets/{name}?version=2
```

**Response:**
```json
{
  "secret_id": "api-key",
  "version": 2,
  "data": "<base64-encoded>",
  "metadata": {"environment": "production"},
  "algorithm": "AES-256-GCM",
  "key_identifier": "/tenant/default/dek",
  "created_at": 1704067200,
  "timestamp": 1704067200
}
```

#### List Secrets

```http
GET /api/v1/kms/secrets?limit=100&cursor=token
```

#### Rotate Secret

```http
POST /api/v1/kms/secrets/{name}/rotate
Content-Type: application/json

{
  "new_data": "<base64-encoded>",
  "metadata": {"rotated_by": "admin"},
  "tenant_id": "tenant-123"
}
```

#### Rollback Secret

```http
POST /api/v1/kms/secrets/{name}/rollback
Content-Type: application/json

{
  "target_version": 1
}
```

#### Set Rotation Policy

```http
PUT /api/v1/kms/secrets/{name}/policy
Content-Type: application/json

{
  "policy": {
    "enabled": true,
    "interval_seconds": 7776000,
    "retain_versions": 5,
    "rotation_lambda": "arn:aws:lambda:..."
  }
}
```

### Backend Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/backend/status` | Get backend status |
| POST | `/backend/test` | Test backend connectivity |

#### Backend Status

```http
GET /api/v1/kms/backend/status
```

**Response:**
```json
{
  "backend_type": "hybrid",
  "status": "healthy",
  "device": "/dev/tpmrm0",
  "region": "us-east-1",
  "pcr_banks": ["SHA256", "SHA384"],
  "pcr_registers": [0, 1, 7],
  "capabilities": {
    "encrypt": true,
    "decrypt": true,
    "sign": true,
    "verify": true,
    "wrap_key": true,
    "derive_key": true
  },
  "timestamp": 1704067200
}
```

#### Backend Test

```http
POST /api/v1/kms/backend/test
```

**Response:**
```json
{
  "success": true,
  "duration_ms": 45,
  "message": "All backend operations completed successfully",
  "timestamp": 1704067200
}
```

## Error Codes

| Error Type | HTTP Code | Description |
|------------|-----------|-------------|
| `ErrKeyNotFound` | 404 | Key does not exist |
| `ErrKeyAlreadyExists` | 400 | Key ID already in use |
| `ErrKeyDisabled` | 403 | Key is disabled |
| `ErrKeyCompromised` | 403 | Key is revoked/compromised |
| `ErrVersionNotFound` | 404 | Key version does not exist |
| `ErrInvalidInput` | 400 | Invalid parameter |
| `ErrDeletionProtected` | 403 | Key has deletion protection |
| `ErrStorageUnavailable` | 503 | Backend unavailable |
| `ErrUnsupportedAlgorithm` | 400 | Algorithm not supported |
| `ErrPolicyViolation` | 403 | Policy check failed |
| `ErrUnauthorized` | 401 | Unauthorized operation |

## Supported Algorithms

### Symmetric Encryption

| Algorithm | Description |
|-----------|-------------|
| `AES-128-GCM` | AES-128 in GCM mode |
| `AES-192-GCM` | AES-192 in GCM mode |
| `AES-256-GCM` | AES-256 in GCM mode (default) |
| `CHACHA20-POLY1305` | ChaCha20 with Poly1305 |
| `XCHACHA20-POLY1305` | XChaCha20 with Poly1305 |

### Asymmetric Keys

| Algorithm | Description |
|-----------|-------------|
| `RSA-2048` | RSA 2048-bit |
| `RSA-3072` | RSA 3072-bit |
| `RSA-4096` | RSA 4096-bit |
| `ECDSA-P256` | NIST P-256 curve |
| `ECDSA-P384` | NIST P-384 curve |
| `ECDSA-P521` | NIST P-521 curve |
| `ED25519` | Edwards curve 25519 |
| `ED448` | Edwards curve 448 |

### Key Exchange

| Algorithm | Description |
|-----------|-------------|
| `X25519` | Curve25519 ECDH |
| `X448` | Curve448 ECDH |

### HMAC

| Algorithm | Description |
|-----------|-------------|
| `HMAC-SHA256` | HMAC with SHA-256 |
| `HMAC-SHA384` | HMAC with SHA-384 |
| `HMAC-SHA512` | HMAC with SHA-512 |

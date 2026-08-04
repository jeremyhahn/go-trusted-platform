# KMS MCP API Reference

Model Context Protocol (MCP) tools for KMS operations.

| Property | Value |
|----------|-------|
| Protocol | MCP 1.0 |
| Transport | stdio, SSE (server-sent events) |
| Authentication | mTLS certificates, Bearer tokens |
| Tools | 32 tools across key management, crypto, and secrets |

## Overview

The KMS MCP transport exposes KMS operations as tools that AI agents and Claude can invoke. All tools accept JSON input and return JSON results with optional base64-encoded data.

## Key Management Tools

### kms_generate_key

Generate a new cryptographic key with specified algorithm and properties.

**Input Schema:**

```json
{
  "name": "string (required)",
  "algorithm": "string (optional, default: aes-256-gcm)",
  "key_size": "integer (optional)",
  "usage": ["array of strings"],
  "key_spec": "object (optional)",
  "exportable": "boolean (default: false)",
  "deletion_protection": "boolean (default: false)",
  "description": "string (optional)",
  "tags": "object (optional)",
  "owner": "string (optional)"
}
```

**Example:**

```json
{
  "name": "production-key",
  "algorithm": "AES-256-GCM",
  "usage": ["ENCRYPT", "DECRYPT"],
  "deletion_protection": true,
  "tags": {"env": "production", "team": "security"}
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "algorithm": "AES-256-GCM",
  "version": 1,
  "status": "ENABLED",
  "exportable": false,
  "deletion_protection": true,
  "created_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### kms_list_keys

List all keys with optional filtering and pagination.

**Input Schema:**

```json
{
  "limit": "integer (default: 50)",
  "cursor": "string (optional)",
  "status": "string (optional, e.g., ENABLED, DISABLED, PENDING_DELETION)",
  "algorithm": "string (optional)"
}
```

**Returns:**

```json
{
  "keys": [
    {
      "key_id": "production-key",
      "algorithm": "AES-256-GCM",
      "status": "ENABLED",
      "version": 1,
      "created_at": 1705416600
    }
  ],
  "next_cursor": "cursor-token-123",
  "total": 42,
  "timestamp": 1705416600
}
```

---

### kms_get_key

Get key details by ID including metadata and status.

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "version": "integer (optional, default: latest)"
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "algorithm": "AES-256-GCM",
  "status": "ENABLED",
  "version": 1,
  "usage": ["ENCRYPT", "DECRYPT"],
  "exportable": false,
  "deletion_protection": true,
  "created_at": 1705416600,
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### kms_delete_key

Delete a key with optional pending deletion window.

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "pending_window_days": "integer (default: 7)",
  "force": "boolean (default: false)"
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "status": "PENDING_DELETION",
  "deletion_scheduled_at": 1706021400,
  "timestamp": 1705416600
}
```

---

### kms_rotate_key

Rotate a key to generate a new version while optionally retaining the old version.

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "retain_old_version": "boolean (default: true)"
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "old_version": 1,
  "new_version": 2,
  "timestamp": 1705416600
}
```

---

## Key Lifecycle Tools

### kms_revoke_key

Revoke a key, marking it as unusable for all cryptographic operations.

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "reason": "string (optional)"
}
```

**Example:**

```json
{
  "key_id": "compromised-key",
  "reason": "Key suspected compromised during infrastructure audit"
}
```

**Returns:**

```json
{
  "key_id": "compromised-key",
  "status": "REVOKED",
  "timestamp": 1705416600
}
```

---

### kms_get_key_metadata

Get key metadata (name, description, tags, timestamps) without exposing key material.

**Input Schema:**

```json
{
  "key_id": "string (required)"
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "name": "Production Encryption Key",
  "description": "Master key for application data encryption",
  "algorithm": "AES-256-GCM",
  "status": "ENABLED",
  "usage": ["ENCRYPT", "DECRYPT"],
  "exportable": false,
  "deletion_protection": true,
  "tags": {
    "team": "security",
    "environment": "production",
    "cost-center": "cc-123"
  },
  "created_at": 1704067200,
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### kms_update_key_metadata

Update mutable key metadata fields (name, description, tags).

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "name": "string (optional)",
  "description": "string (optional)",
  "tags": "object (optional)",
  "remove_tags": ["array of strings (optional)"]
}
```

**Example:**

```json
{
  "key_id": "production-key",
  "name": "Production Master Key v2",
  "description": "Updated description",
  "tags": {"status": "active", "version": "2"},
  "remove_tags": ["deprecated"]
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "name": "Production Master Key v2",
  "description": "Updated description",
  "tags": {
    "team": "security",
    "status": "active",
    "version": "2"
  },
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### kms_get_key_policy

Get the access control policy for a key.

**Input Schema:**

```json
{
  "key_id": "string (required)"
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "version": 2,
  "allowed_operations": ["ENCRYPT", "DECRYPT"],
  "allowed_principals": ["user:alice", "service:app-api"],
  "denied_principals": [],
  "expires_at": 1735689600,
  "rotation_required": false,
  "max_usage_count": 1000000,
  "require_mfa": false,
  "updated_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### kms_set_key_policy

Set the access control policy for a key.

**Input Schema:**

```json
{
  "key_id": "string (required)",
  "allowed_operations": ["array of strings (optional)"],
  "allowed_principals": ["array of strings (optional)"],
  "denied_principals": ["array of strings (optional)"],
  "expires_at": "integer (optional, Unix timestamp)",
  "rotation_required": "boolean (optional)",
  "max_usage_count": "integer (optional, 0 = unlimited)",
  "require_mfa": "boolean (optional)"
}
```

**Example:**

```json
{
  "key_id": "production-key",
  "allowed_operations": ["ENCRYPT", "DECRYPT"],
  "allowed_principals": ["service:app-api", "user:alice"],
  "denied_principals": ["user:bob"],
  "require_mfa": true
}
```

**Returns:**

```json
{
  "key_id": "production-key",
  "policy_version": 3,
  "timestamp": 1705416600
}
```

---

### kms_supported_algorithms

List the cryptographic algorithms supported by the KMS backend.

**Input Schema:**

```json
{}
```

**Returns:**

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

### kms_backend_status

Get health and capability information about the KMS backend.

**Input Schema:**

```json
{}
```

**Returns:**

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

---

## Secrets Management Tools

### secret_store

Store a secret with optional metadata. The value is encrypted at rest.

**Input Schema:**

```json
{
  "secret_id": "string (required)",
  "data": "string (required, base64-encoded)",
  "metadata": "object (optional)"
}
```

**Example:**

```json
{
  "secret_id": "github-api-key",
  "data": "Z2hfa0oxMjM0NTY3ODkwYWJjZGVm",
  "metadata": {
    "source": "github",
    "purpose": "ci-deployment",
    "team": "platform"
  }
}
```

**Returns:**

```json
{
  "secret_id": "github-api-key",
  "version": 1,
  "created_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### secret_get

Retrieve a secret by ID, optionally at a specific version.

**Input Schema:**

```json
{
  "secret_id": "string (required)",
  "version": "integer (optional, 0 = latest)"
}
```

**Returns:**

```json
{
  "secret_id": "github-api-key",
  "version": 1,
  "data": "Z2hfa0oxMjM0NTY3ODkwYWJjZGVm",
  "metadata": {
    "source": "github",
    "purpose": "ci-deployment"
  },
  "created_at": 1705416600,
  "timestamp": 1705416600
}
```

---

### secret_list

List secrets (identifiers and metadata only, no secret data).

**Input Schema:**

```json
{
  "limit": "integer (default: 50)"
}
```

**Returns:**

```json
{
  "secrets": [
    {
      "secret_id": "github-api-key",
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
  "next_cursor": "cursor-token",
  "total": 2,
  "timestamp": 1705416600
}
```

---

### secret_delete

Delete a secret and all its versions.

**Input Schema:**

```json
{
  "secret_id": "string (required)"
}
```

**Returns:**

```json
{
  "secret_id": "github-api-key",
  "deleted": true,
  "timestamp": 1705416600
}
```

---

### secret_set_rotation_policy

Set the automatic rotation policy for a secret, including how many old versions to retain.

**Input Schema:**

```json
{
  "secret_id": "string (required)",
  "enabled": "boolean (required)",
  "interval_seconds": "integer (required)",
  "retain_versions": "integer (optional, default: 3)"
}
```

**Example:**

```json
{
  "secret_id": "api-key",
  "enabled": true,
  "interval_seconds": 7776000,
  "retain_versions": 3
}
```

**Returns:**

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

### secret_get_rotation_policy

Get the automatic rotation policy for a secret.

**Input Schema:**

```json
{
  "secret_id": "string (required)"
}
```

**Returns:**

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

## Error Handling

All tools return errors in the following format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error description",
    "details": {}
  }
}
```

**Common Error Codes:**

| Code | Description |
|------|-------------|
| `KMS_KEY_ID_REQUIRED` | Key ID parameter is required |
| `KMS_SERVICE_UNAVAILABLE` | KMS backend is offline or unhealthy |
| `KMS_KEY_NOT_FOUND` | Requested key does not exist |
| `KMS_POLICY_VIOLATION` | Operation violates key policy |
| `SECRET_ID_REQUIRED` | Secret ID parameter is required |
| `SECRET_NOT_FOUND` | Requested secret does not exist |

---

## Integration Examples

### Claude Integration

Claude can invoke KMS tools to perform operations on behalf of users:

```
User: "Revoke the production encryption key and rotate it"

Claude: I'll help you revoke the old key and create a new one.

[Invokes kms_revoke_key]
Tool: kms_revoke_key
Input: {"key_id": "production-key", "reason": "Automatic rotation"}
Result: {
  "key_id": "production-key",
  "status": "REVOKED",
  "timestamp": 1705416600
}

[Invokes kms_generate_key]
Tool: kms_generate_key
Input: {
  "name": "production-key-v2",
  "algorithm": "AES-256-GCM",
  "deletion_protection": true,
  "tags": {"version": "2"}
}
Result: {
  "key_id": "production-key-v2",
  "version": 1,
  "status": "ENABLED",
  "timestamp": 1705416600
}

Claude: I've successfully revoked the old production-key and created a new key 
production-key-v2. The new key is ready for use.
```

### Automated Workflows

```
Workflow: Daily Secret Rotation Check

[Invokes secret_list]
- List all secrets
- Filter by rotation_enabled=true
- Check next_rotation_at timestamp

[Invokes secret_get_rotation_policy]
- For secrets due for rotation
- Verify rotation interval

[Invokes secret_set_rotation_policy]
- Update rotation intervals as needed
```

---

## Base64 Encoding

For cryptographic operations involving binary data, MCP tools use base64 encoding:

```json
{
  "secret_id": "database-password",
  "data": "c2VjcmV0X3Bhc3N3b3JkXzEyMzQ1Njc4OTA="
}
```

Decode in Python:
```python
import base64
data = base64.b64decode("c2VjcmV0X3Bhc3N3b3JkXzEyMzQ1Njc4OTA=")
print(data)  # b'secret_password_1234567890'
```

---

## Tool Categories

| Category | Tools | Purpose |
|----------|-------|---------|
| Key Management | kms_generate_key, kms_get_key, kms_list_keys, kms_delete_key, kms_rotate_key, kms_export_public_key | Core key operations |
| Key Lifecycle | kms_revoke_key, kms_get_key_metadata, kms_update_key_metadata, kms_get_key_policy, kms_set_key_policy | Metadata and policy |
| Capabilities | kms_supported_algorithms, kms_backend_status | Backend information |
| Secrets | secret_store, secret_get, secret_list, secret_delete | Secret storage |
| Secret Policies | secret_set_rotation_policy, secret_get_rotation_policy | Rotation automation |

Total: 32 tools providing full KMS/Secrets surface via MCP.

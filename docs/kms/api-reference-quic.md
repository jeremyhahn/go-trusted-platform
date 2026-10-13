# KMS QUIC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). The status bytes below are wrong: InvalidRequest `0x01`, NotFound `0x02`, Unauthorized `0x03`, InternalError `0x04`, AlreadyExists `0x06`, PermissionDenied `0x07`, Unavailable `0x0A`, NotImplemented `0x0B`. The `0xCD` table also omits SignCSR `0x07`.

Low-latency QUIC transport for KMS operations.

| Property | Value |
|----------|-------|
| Endpoint | `localhost:9444` (UDP) |
| Protocol | QUIC + TLS 1.3 |
| Message Format | Length-prefixed CBOR payload |
| NextProtos | `quic-api`, `trusted-platform` |

## Overview

The KMS QUIC transport provides two new category opcodes with multiplexed sub-operations for key lifecycle management and secrets operations. The single-byte opcode space in the 0xC0-0xCF range was exhausted by existing KMS operations, so new verbs multiplex under category opcodes following the Phase 3.5 pattern.

### Category Opcodes

| Opcode | Name | Purpose |
|--------|------|---------|
| `0xCD` | OpKMSExtendedCategory | Key lifecycle verbs (revoke, metadata, policy, algorithms) |
| `0xCE` | OpSecretsCategory | Secrets management (store, get, list, delete, rotation policy) |

## KMS Extended Category (0xCD)

Key lifecycle operations for key metadata, policy, and revocation.

### Request/Response Structure

```
Request:
+--------+-------+
| OpCode | Sub   | Payload
| (0xCD) | Op    | (CBOR-encoded)
+--------+-------+

Response:
+--------+--------+
| Status | Payload|
| (1B)   | (CBOR) |
+--------+--------+
```

### Sub-operations

#### Revoke Key (0x01)

Revoke a key, marking it unusable for all cryptographic operations.

**Request:**

```protobuf
message KMSRevokeKeyRequest {
  string key_id = 1;           // Key identifier to revoke
  string reason = 2;           // Audit trail reason (optional)
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSRevokeKeyResponse {
  string key_id = 1;           // Key ID
  string status = 2;           // "REVOKED"
  int64 timestamp = 3;         // Operation timestamp (Unix seconds)
}
```

**Wire Format (CBOR):**

```
Request:  {key_id: "my-key", reason: "compromised"}
Response: {key_id: "my-key", status: "REVOKED", timestamp: 1705416600}
```

**Errors:**

- `StatusNotFound` (404) - Key does not exist
- `StatusInvalidArgument` (400) - Missing key_id
- `StatusInternalError` (500) - Backend failure

---

#### Get Key Metadata (0x02)

Retrieve key metadata without exposing key material.

**Request:**

```protobuf
message KMSGetKeyMetadataRequest {
  string key_id = 1;           // Key identifier
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSGetKeyMetadataResponse {
  KMSKeyMetadataResponse metadata = 1;  // Key metadata
  int64 timestamp = 2;                  // Operation timestamp
}

message KMSKeyMetadataResponse {
  string key_id = 1;
  string name = 2;
  string description = 3;
  string algorithm = 4;
  string status = 5;                    // "ENABLED", "DISABLED", "REVOKED"
  repeated string usage = 6;            // ["ENCRYPT", "DECRYPT", ...]
  bool exportable = 7;
  bool deletion_protection = 8;
  map<string, string> tags = 9;
  int64 created_at = 10;
  int64 updated_at = 11;
}
```

**Errors:**

- `StatusNotFound` (404) - Key does not exist
- `StatusInvalidArgument` (400) - Missing key_id

---

#### Update Key Metadata (0x03)

Update mutable key metadata fields (name, description, tags).

**Request:**

```protobuf
message KMSUpdateKeyMetadataRequest {
  string key_id = 1;                    // Key identifier
  string name = 2;                      // New name (optional)
  string description = 3;               // New description (optional)
  map<string, string> tags = 4;         // Tags to add/update
  repeated string remove_tags = 5;      // Tag keys to remove
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSUpdateKeyMetadataResponse {
  KMSKeyMetadataResponse metadata = 1;  // Updated metadata
  int64 timestamp = 2;                  // Operation timestamp
}
```

**Errors:**

- `StatusNotFound` (404) - Key does not exist
- `StatusInvalidArgument` (400) - Missing key_id
- `StatusInternalError` (500) - Update failed

---

#### Set Key Policy (0x04)

Set or update the access control policy for a key.

**Request:**

```protobuf
message KMSSetKeyPolicyRequest {
  string key_id = 1;                    // Key identifier
  KMSKeyPolicyPayload policy = 2;       // Policy to set
}

message KMSKeyPolicyPayload {
  string key_id = 1;
  uint64 version = 2;                   // Policy version (0 = auto)
  repeated string allowed_operations = 3;  // ["ENCRYPT", "DECRYPT", ...]
  repeated string allowed_principals = 4;  // ["user:alice", "service:api", ...]
  repeated string denied_principals = 5;   // Deny list
  int64 expires_at = 6;                 // Unix timestamp (0 = never)
  bool rotation_required = 7;
  uint64 max_usage_count = 8;           // 0 = unlimited
  bool require_mfa = 9;
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSSetKeyPolicyResponse {
  string key_id = 1;
  uint64 policy_version = 2;
  int64 timestamp = 3;
}
```

**Errors:**

- `StatusNotFound` (404) - Key does not exist
- `StatusInvalidArgument` (400) - Missing key_id or policy
- `StatusInternalError` (500) - Policy update failed

---

#### Get Key Policy (0x05)

Retrieve the access control policy for a key.

**Request:**

```protobuf
message KMSGetKeyPolicyRequest {
  string key_id = 1;                    // Key identifier
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSGetKeyPolicyResponse {
  KMSKeyPolicyPayload policy = 1;       // Key policy
  int64 timestamp = 2;                  // Operation timestamp
}
```

**Errors:**

- `StatusNotFound` (404) - Key or policy does not exist
- `StatusInvalidArgument` (400) - Missing key_id

---

#### Get Supported Algorithms (0x06)

List all cryptographic algorithms supported by the KMS backend.

**Request:**

```protobuf
message GetSupportedAlgorithmsRequest {
  // No parameters required
}
```

**Response (Status: 0x00 OK):**

```protobuf
message KMSGetSupportedAlgorithmsResponse {
  repeated string algorithms = 1;       // ["AES-256-GCM", "ECDSA-P256", ...]
  int64 timestamp = 2;                  // Operation timestamp
}
```

**Algorithms Returned:**

- Symmetric: AES-128-GCM, AES-192-GCM, AES-256-GCM, CHACHA20-POLY1305
- Asymmetric: RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, ECDSA-P521, ED25519, ED448
- MAC: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

**Errors:**

- `StatusInternalError` (500) - Backend query failed

---

## Secrets Category (0xCE)

Secrets management operations for storing and retrieving encrypted secrets.

### Sub-operations

#### Store Secret (0x01)

Store a secret with optional metadata. Secret is encrypted at rest.

**Request:**

```protobuf
message SecretsStoreRequest {
  string secret_id = 1;                 // Secret identifier / path
  bytes data = 2;                       // Secret data (raw or base64)
  map<string, string> metadata = 3;     // Version-specific metadata (optional)
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsStoreResponse {
  string secret_id = 1;
  uint32 version = 2;                   // Stored version number
  int64 created_at = 3;                 // Creation timestamp
  int64 timestamp = 4;                  // Operation timestamp
}
```

**Errors:**

- `StatusInvalidArgument` (400) - Missing secret_id or data
- `StatusInternalError` (500) - Storage failed

---

#### Get Secret (0x02)

Retrieve a secret by ID, optionally at a specific version.

**Request:**

```protobuf
message SecretsGetRequest {
  string secret_id = 1;                 // Secret identifier
  uint32 version = 2;                   // Version (0 = latest)
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsGetResponse {
  string secret_id = 1;
  uint32 version = 2;
  bytes data = 3;                       // Secret data
  map<string, string> metadata = 4;     // Version metadata
  int64 created_at = 5;
  int64 timestamp = 6;
}
```

**Errors:**

- `StatusNotFound` (404) - Secret does not exist
- `StatusInvalidArgument` (400) - Missing secret_id

---

#### List Secrets (0x03)

List secrets (identifiers and metadata only, no secret data).

**Request:**

```protobuf
message SecretsListRequest {
  uint32 limit = 1;                     // Max results (default 50)
  string cursor = 2;                    // Pagination cursor
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsListResponse {
  repeated SecretSummary secrets = 1;
  string next_cursor = 2;               // For pagination
  int64 timestamp = 3;
}

message SecretSummary {
  string secret_id = 1;
  uint32 version = 2;
  int64 created_at = 3;
  int64 updated_at = 4;
}
```

**Errors:**

- `StatusInternalError` (500) - List operation failed

---

#### Delete Secret (0x04)

Delete a secret and all its versions.

**Request:**

```protobuf
message SecretsDeleteRequest {
  string secret_id = 1;                 // Secret identifier
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsDeleteResponse {
  string secret_id = 1;
  int64 timestamp = 2;
}
```

**Errors:**

- `StatusNotFound` (404) - Secret does not exist
- `StatusInvalidArgument` (400) - Missing secret_id

---

#### Set Rotation Policy (0x05)

Set the automatic rotation policy for a secret.

**Request:**

```protobuf
message SecretsSetRotationPolicyRequest {
  string secret_id = 1;
  bool enabled = 2;                     // Enable automatic rotation
  uint32 interval_seconds = 3;          // Rotation interval in seconds
  uint32 retain_versions = 4;           // Old versions to retain (optional, default 3)
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsRotationPolicyResponse {
  string secret_id = 1;
  bool enabled = 2;
  uint32 interval_seconds = 3;
  uint32 retain_versions = 4;
  int64 next_rotation_at = 5;           // Unix timestamp
  int64 timestamp = 6;
}
```

**Errors:**

- `StatusNotFound` (404) - Secret does not exist
- `StatusInvalidArgument` (400) - Invalid interval or retention setting

---

#### Get Rotation Policy (0x06)

Retrieve the automatic rotation policy for a secret.

**Request:**

```protobuf
message SecretsGetRotationPolicyRequest {
  string secret_id = 1;                 // Secret identifier
}
```

**Response (Status: 0x00 OK):**

```protobuf
message SecretsRotationPolicyResponse {
  string secret_id = 1;
  bool enabled = 2;
  uint32 interval_seconds = 3;
  uint32 retain_versions = 4;
  int64 last_rotation_at = 5;
  int64 next_rotation_at = 6;
  int64 timestamp = 7;
}
```

**Errors:**

- `StatusNotFound` (404) - Secret or policy does not exist

---

## Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | StatusOK | Success |
| 0x01 | StatusBadRequest | Invalid request format |
| 0x02 | StatusUnauthorized | Authentication failed |
| 0x03 | StatusForbidden | Authorization denied (policy) |
| 0x04 | StatusNotFound | Resource not found |
| 0x05 | StatusConflict | State conflict |
| 0x06 | StatusUnavailable | Service unavailable |
| 0x07 | StatusInternalError | Server error |

---

## Connection Example

```go
import (
    "context"
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

// Establish connection
tlsConf := &tls.Config{
    RootCAs:    caCertPool,
    NextProtos: []string{"quic-api"},
}

conn, _ := quic.DialAddr(context.Background(), "localhost:9444", tlsConf, nil)
stream, _ := conn.OpenStreamSync(context.Background())

// Send KMS Extended request (Revoke)
request := KMSRevokeKeyRequest{
    KeyID:  "my-key",
    Reason: "Compromise suspected",
}
payload := encodePayload(request)
message := append([]byte{0xCD, 0x01}, payload...)

// Send and receive response
stream.Write(message)
response := make([]byte, 1024)
n, _ := stream.Read(response)
```

---

## Multiplexing Pattern

Both OpKMSExtendedCategory and OpSecretsCategory follow the Phase 3.5 multiplexing pattern:

1. **Opcode byte** (0xCD or 0xCE) identifies the category
2. **Sub-opcode byte** (0x01-0x06) selects the specific operation
3. **Payload** contains the operation-specific request/response

This pattern is consistent with ceremony, PIV, LUKS, and FIDO2 categories already deployed in the QUIC API.

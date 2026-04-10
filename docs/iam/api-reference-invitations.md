# Invitation API Reference

Complete API reference for invitation management in go-trusted-platform. The Invitation API enables tenant owners to invite new users to join their tenant with pre-assigned roles.

## Protocol Overview

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTP/HTTPS | 8443 | Web clients, external systems |
| gRPC | TCP | 9443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTP | 9445 | AI/LLM integration |
| Unix | Unix Socket | /run/platformd.sock | Local IPC, CLI |

## Operations Summary

| # | Operation | Description | Authorization |
|---|-----------|-------------|---------------|
| 1 | CreateInvitation | Create invitation for new user | Tenant owner |
| 2 | ListInvitations | List all tenant invitations | Tenant member |
| 3 | GetInvitation | Get invitation by ID | Tenant member |
| 4 | GetInvitationByToken | Validate invitation token | Public |
| 5 | RevokeInvitation | Revoke pending invitation | Tenant owner |

## Invitation Status Lifecycle

```
    +----------+
    | Pending  |
    +----+-----+
         |
    +----+----+----+----+
    |         |         |
    v         v         v
+--------+ +-------+ +-------+
|Accepted| |Expired| |Revoked|
+--------+ +-------+ +-------+
```

| Status | Description | Terminal |
|--------|-------------|----------|
| `pending` | Awaiting user registration | No |
| `accepted` | User completed registration | Yes |
| `expired` | Expiration time passed | Yes |
| `revoked` | Manually cancelled by owner | Yes |

---

## REST API

Base URL: `https://host:8443/api/v1/invitations`

### 1. CreateInvitation

Creates a new invitation for a user to join the tenant.

**Endpoint:** `POST /api/v1/invitations`

**Authorization:** Bearer token (tenant owner only)

**Request:**
```http
POST /api/v1/invitations
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "role": "member",
  "expires_in": 604800000000000
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Invitee email address |
| `role` | string | Yes | Role to assign (admin, member, viewer) |
| `expires_in` | int64 | No | Expiration in nanoseconds (default: 7 days) |

**Valid Roles:**

| Role | Description |
|------|-------------|
| `admin` | Full tenant management access |
| `member` | Standard user access |
| `viewer` | Read-only access |

**Response (201 Created):**
```json
{
  "id": 12345678901234567890,
  "tenant_id": "tenant-550e8400-e29b-41d4",
  "email": "newuser@example.com",
  "role": "member",
  "status": "pending",
  "token": "aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3VyZS10b2tlbg==",
  "invite_url": "https://platform.example.com/invite/aGVsbG8t...",
  "expires_at": "2025-01-22T00:00:00Z",
  "created_at": "2025-01-15T12:00:00Z"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | uint64 | Unique invitation identifier |
| `tenant_id` | string | Target tenant UUID |
| `email` | string | Invitee email address |
| `role` | string | Role to assign upon registration |
| `status` | string | Current invitation status |
| `token` | string | Secure token (only on create) |
| `invite_url` | string | Full invitation URL (only on create) |
| `expires_at` | string | Expiration timestamp (RFC 3339) |
| `created_at` | string | Creation timestamp (RFC 3339) |

**Error Responses:**

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `missing_email` | Email address not provided |
| 400 | `invalid_email` | Email format is invalid |
| 400 | `missing_role` | Role not provided |
| 400 | `invalid_role` | Role is not valid |
| 401 | `unauthorized` | Missing or invalid token |
| 403 | `not_tenant_owner` | Only tenant owners can create invitations |
| 409 | `email_already_registered` | Email already exists in tenant |
| 409 | `duplicate_invitation` | Pending invitation exists for email |

---

### 2. ListInvitations

Lists all invitations for the current tenant.

**Endpoint:** `GET /api/v1/invitations`

**Authorization:** Bearer token (tenant member)

**Request:**
```http
GET /api/v1/invitations
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "invitations": [
    {
      "id": 12345678901234567890,
      "tenant_id": "tenant-550e8400-e29b-41d4",
      "email": "newuser@example.com",
      "role": "member",
      "status": "pending",
      "expires_at": "2025-01-22T00:00:00Z",
      "created_at": "2025-01-15T12:00:00Z"
    },
    {
      "id": 98765432109876543210,
      "tenant_id": "tenant-550e8400-e29b-41d4",
      "email": "another@example.com",
      "role": "viewer",
      "status": "accepted",
      "expires_at": "2025-01-20T00:00:00Z",
      "created_at": "2025-01-13T10:00:00Z"
    }
  ],
  "total": 2
}
```

**Note:** Token and invite_url are not included in list responses for security.

---

### 3. GetInvitation

Retrieves an invitation by its ID.

**Endpoint:** `GET /api/v1/invitations/{id}`

**Authorization:** Bearer token (tenant member)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | uint64 | Invitation ID |

**Request:**
```http
GET /api/v1/invitations/12345678901234567890
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "id": 12345678901234567890,
  "tenant_id": "tenant-550e8400-e29b-41d4",
  "email": "newuser@example.com",
  "role": "member",
  "status": "pending",
  "expires_at": "2025-01-22T00:00:00Z",
  "created_at": "2025-01-15T12:00:00Z"
}
```

**Error Responses:**

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `missing_invitation_id` | ID not provided |
| 400 | `invalid_invitation_id` | ID format is invalid |
| 401 | `unauthorized` | Missing or invalid token |
| 404 | `invitation_not_found` | Invitation does not exist or belongs to different tenant |

---

### 4. GetInvitationByToken

Validates an invitation token and returns invitation details. This is a public endpoint used during registration.

**Endpoint:** `GET /api/v1/invitations/token/{token}`

**Authorization:** None (public endpoint)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `token` | string | Base64URL-encoded invitation token |

**Request:**
```http
GET /api/v1/invitations/token/aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3VyZS10b2tlbg==
```

**Response (200 OK - Valid):**
```json
{
  "id": 12345678901234567890,
  "tenant_id": "tenant-550e8400-e29b-41d4",
  "email": "newuser@example.com",
  "role": "member",
  "status": "pending",
  "expires_at": "2025-01-22T00:00:00Z",
  "created_at": "2025-01-15T12:00:00Z"
}
```

**Error Responses:**

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `missing_token` | Token not provided |
| 400 | `invitation_expired` | Token has expired |
| 400 | `invitation_revoked` | Token was revoked |
| 400 | `invitation_already_accepted` | Token already used |
| 404 | `invitation_not_found` | Token does not exist |

---

### 5. RevokeInvitation

Revokes a pending invitation.

**Endpoint:** `DELETE /api/v1/invitations/{id}`

**Authorization:** Bearer token (tenant owner only)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | uint64 | Invitation ID |

**Request:**
```http
DELETE /api/v1/invitations/12345678901234567890
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "status": "revoked",
  "message": "invitation has been revoked"
}
```

**Error Responses:**

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `missing_invitation_id` | ID not provided |
| 400 | `invalid_invitation_id` | ID format is invalid |
| 401 | `unauthorized` | Missing or invalid token |
| 403 | `not_tenant_owner` | Only tenant owners can revoke invitations |
| 404 | `invitation_not_found` | Invitation does not exist or belongs to different tenant |
| 409 | `invitation_already_revoked` | Invitation already revoked |
| 409 | `invitation_already_accepted` | Cannot revoke accepted invitation |

---

## gRPC API

Service: `InvitationService` on port 9443

### Service Definition

```protobuf
service InvitationService {
  rpc CreateInvitation(CreateInvitationRequest) returns (InvitationResponse);
  rpc GetInvitation(GetInvitationRequest) returns (InvitationResponse);
  rpc GetInvitationByToken(GetInvitationByTokenRequest) returns (InvitationResponse);
  rpc ListInvitations(ListInvitationsRequest) returns (ListInvitationsResponse);
  rpc RevokeInvitation(RevokeInvitationRequest) returns (RevokeInvitationResponse);
}
```

### Message Types

**CreateInvitationRequest:**
```protobuf
message CreateInvitationRequest {
  string email = 1;           // Required: Invitee email
  string role = 2;            // Required: Role to assign
  int64 expires_in_ns = 3;    // Optional: Expiration in nanoseconds
}
```

**GetInvitationRequest:**
```protobuf
message GetInvitationRequest {
  uint64 id = 1;              // Required: Invitation ID
}
```

**GetInvitationByTokenRequest:**
```protobuf
message GetInvitationByTokenRequest {
  string token = 1;           // Required: Invitation token
}
```

**ListInvitationsRequest:**
```protobuf
message ListInvitationsRequest {
  int32 limit = 1;            // Optional: Max results
  int32 offset = 2;           // Optional: Pagination offset
  string status = 3;          // Optional: Filter by status
}
```

**RevokeInvitationRequest:**
```protobuf
message RevokeInvitationRequest {
  uint64 id = 1;              // Required: Invitation ID
}
```

**InvitationResponse:**
```protobuf
message InvitationResponse {
  uint64 id = 1;
  string tenant_id = 2;
  string email = 3;
  string role = 4;
  string status = 5;
  string token = 6;           // Only on create
  string invite_url = 7;      // Only on create
  google.protobuf.Timestamp expires_at = 8;
  google.protobuf.Timestamp created_at = 9;
}
```

### gRPC Error Codes

| Error Type | gRPC Code | Description |
|------------|-----------|-------------|
| ErrInvitationNotFound | NOT_FOUND | Invitation does not exist |
| ErrInvalidEmail | INVALID_ARGUMENT | Email format invalid |
| ErrInvalidRole | INVALID_ARGUMENT | Role not valid |
| ErrNotTenantOwner | PERMISSION_DENIED | User is not tenant owner |
| ErrInvitationExpired | FAILED_PRECONDITION | Invitation has expired |
| ErrInvitationRevoked | FAILED_PRECONDITION | Invitation was revoked |
| ErrEmailAlreadyRegistered | ALREADY_EXISTS | Email exists in tenant |

---

## QUIC API

Binary protocol on UDP port 9444.

### Opcodes

| Opcode | Hex | Operation |
|--------|-----|-----------|
| OpInvitationCreate | 0xC0 | Create invitation |
| OpInvitationGet | 0xC1 | Get invitation by ID |
| OpInvitationGetByToken | 0xC2 | Get invitation by token |
| OpInvitationList | 0xC3 | List invitations |
| OpInvitationRevoke | 0xC4 | Revoke invitation |

### Request Payloads (MessagePack)

**OpInvitationCreate (0xC0):**
```json
{
  "email": "newuser@example.com",
  "role": "member",
  "expires_in_ns": 604800000000000
}
```

**OpInvitationGet (0xC1):**
```json
{
  "id": 12345678901234567890
}
```

**OpInvitationGetByToken (0xC2):**
```json
{
  "token": "aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3VyZS10b2tlbg=="
}
```

**OpInvitationList (0xC3):**
```json
{
  "limit": 50,
  "offset": 0,
  "status": "pending"
}
```

**OpInvitationRevoke (0xC4):**
```json
{
  "id": 12345678901234567890
}
```

---

## MCP API (Model Context Protocol)

AI/LLM integration via stdio or HTTP on port 9445.

### Tools

| Tool Name | Description |
|-----------|-------------|
| invitation_create | Create new invitation |
| invitation_get | Get invitation by ID |
| invitation_get_by_token | Validate invitation token |
| invitation_list | List tenant invitations |
| invitation_revoke | Revoke pending invitation |

### Tool Schema: invitation_create

```json
{
  "name": "invitation_create",
  "description": "Create a new invitation for a user to join the tenant",
  "inputSchema": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "description": "Email address of the user to invite"
      },
      "role": {
        "type": "string",
        "enum": ["admin", "member", "viewer"],
        "description": "Role to assign upon registration"
      },
      "expires_in_days": {
        "type": "integer",
        "description": "Days until invitation expires (default: 7)",
        "default": 7
      }
    },
    "required": ["email", "role"]
  }
}
```

### Example MCP Invocation

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "invitation_create",
    "arguments": {
      "email": "newuser@example.com",
      "role": "member",
      "expires_in_days": 7
    }
  }
}
```

---

## Unix Socket API

Local IPC via `/run/platformd.sock`.

### CLI Commands

```bash
# Create invitation
platformctl invitation create \
  --email newuser@example.com \
  --role member \
  --expires-in 7d

# List invitations
platformctl invitation list

# Get invitation by ID
platformctl invitation get --id 12345678901234567890

# Validate invitation token
platformctl invitation validate --token aGVsbG8t...

# Revoke invitation
platformctl invitation revoke --id 12345678901234567890
```

### Wire Protocol

Uses the same opcodes as QUIC (0xC0-0xC4) over Unix domain socket with MessagePack encoding.

---

## Token Security

### Token Generation

Invitation tokens are cryptographically secure:

| Property | Value |
|----------|-------|
| Entropy | 256 bits (32 bytes) |
| Encoding | Base64URL (URL-safe) |
| Storage | Hashed in secondary index |
| Transmission | HTTPS only |
| Lifetime | Default 7 days (configurable) |

### Security Best Practices

1. **Never log tokens** - Treat tokens as secrets
2. **Single use** - Each token can only be accepted once
3. **Rate limiting** - Token validation is rate-limited per IP
4. **Secure delivery** - Use encrypted email or secure channels
5. **Audit logging** - All invitation operations are logged

---

## Error Codes Reference

| Error Code | HTTP | gRPC | Description |
|------------|------|------|-------------|
| `missing_email` | 400 | INVALID_ARGUMENT | Email not provided |
| `invalid_email` | 400 | INVALID_ARGUMENT | Email format invalid |
| `missing_role` | 400 | INVALID_ARGUMENT | Role not provided |
| `invalid_role` | 400 | INVALID_ARGUMENT | Role not valid |
| `missing_token` | 400 | INVALID_ARGUMENT | Token not provided |
| `missing_invitation_id` | 400 | INVALID_ARGUMENT | ID not provided |
| `invalid_invitation_id` | 400 | INVALID_ARGUMENT | ID format invalid |
| `unauthorized` | 401 | UNAUTHENTICATED | Authentication required |
| `not_tenant_owner` | 403 | PERMISSION_DENIED | Owner permission required |
| `invitation_not_found` | 404 | NOT_FOUND | Invitation not found |
| `invitation_expired` | 400 | FAILED_PRECONDITION | Token expired |
| `invitation_revoked` | 400 | FAILED_PRECONDITION | Token revoked |
| `invitation_already_accepted` | 409 | ALREADY_EXISTS | Token already used |
| `invitation_already_revoked` | 409 | FAILED_PRECONDITION | Already revoked |
| `email_already_registered` | 409 | ALREADY_EXISTS | Email in use |
| `duplicate_invitation` | 409 | ALREADY_EXISTS | Pending invitation exists |

---

## Related Documentation

- [Invitation Flow](../auth/invitation-flow.md) - Complete invitation lifecycle
- [User Registration](user-registration.md) - WebAuthn registration process
- [User-Tenant Relationship](../tenant/user-relationship.md) - Multi-tenancy model
- [IAM API Reference](api-reference.md) - Complete IAM API documentation

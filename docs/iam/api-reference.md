# IAM API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). gRPC is 10443, not 9443.

## Overview

The go-trusted-platform IAM (Identity and Access Management) system provides comprehensive multi-protocol API support for managing tenants, users, groups, roles, policies, and applications. All IAM operations are exposed via five protocols to ensure maximum interoperability.

## Protocol Support Matrix

| Protocol | Transport | Port | Use Case | Status |
|----------|-----------|------|----------|--------|
| REST | HTTP/HTTPS | 8443 | Web clients, external systems | Full Support |
| gRPC | TCP | 9443 | High-performance service-to-service | Full Support |
| QUIC | UDP | 9444 | Low-latency, mobile clients | Full Support |
| MCP | stdio/HTTPS | 9445 | AI/LLM integration | Partial (no update/policy ops) |
| Unix Socket | Unix Socket | /run/platformd.sock | Local IPC, CLI | Full Support |

## Table of Contents

- [REST API](#rest-api)
  - [Tenants](#tenants)
  - [Users](#users)
  - [Groups](#groups)
  - [Roles](#roles)
  - [Policies](#policies)
  - [Applications](#applications-oauth-clients)
- [gRPC API](#grpc-api)
- [QUIC API](#quic-api)
- [MCP API](#mcp-api)
- [Unix Socket API](#unix-socket-api)
- [Authentication](#authentication)
- [OIDC Endpoints](#oidc-endpoints)
- [Error Handling](#error-responses)

---

## REST API

Base path: `/api/v1/iam`

All REST endpoints require authentication via Bearer token or mTLS. Responses are JSON-formatted.

### Common Query Parameters

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | int32 | 50 | 1000 | Maximum number of results to return |
| `offset` | int32 | 0 | - | Number of results to skip for pagination |

### Common Response Headers

| Header | Description |
|--------|-------------|
| `X-Request-ID` | Unique request identifier for tracing |
| `X-RateLimit-Remaining` | Remaining requests in current window |

---

### Tenants

Tenants are the top-level organizational unit for IAM resources. All users, groups, roles, and policies belong to a tenant.

#### Create Tenant

Creates a new tenant.

```http
POST /api/v1/iam/tenants
Authorization: Bearer <admin_token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique tenant identifier (alphanumeric, hyphens allowed) |
| `name` | string | No | Human-readable display name |
| `settings` | object | No | Tenant configuration settings |
| `settings.max_users` | int32 | No | Maximum number of users allowed |
| `settings.mfa_required` | bool | No | Require MFA for all users (default: false) |

**Example:**

```json
{
  "id": "acme-corp",
  "name": "Acme Corporation",
  "settings": {
    "max_users": 1000,
    "mfa_required": true
  }
}
```

**Response (200 OK):**

```json
{
  "id": "acme-corp",
  "name": "Acme Corporation",
  "settings": {
    "max_users": 1000,
    "mfa_required": true
  },
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

#### List Tenants

Returns a paginated list of tenants.

```http
GET /api/v1/iam/tenants?limit=50&offset=0
Authorization: Bearer <admin_token>
```

**Response (200 OK):**

```json
{
  "total": 5,
  "limit": 50,
  "offset": 0,
  "tenants": [
    {
      "id": "acme-corp",
      "name": "Acme Corporation",
      "settings": {
        "max_users": 1000,
        "mfa_required": true
      },
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

#### Get Tenant

Retrieves a tenant by ID.

```http
GET /api/v1/iam/tenants/{tenant}
Authorization: Bearer <token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant` | string | Tenant ID |

**Response (200 OK):**

```json
{
  "id": "acme-corp",
  "name": "Acme Corporation",
  "settings": {
    "max_users": 1000,
    "mfa_required": true
  },
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

#### Update Tenant

Updates an existing tenant.

```http
PUT /api/v1/iam/tenants/{tenant}
Authorization: Bearer <admin_token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Acme Corp Updated",
  "settings": {
    "max_users": 2000,
    "mfa_required": true
  }
}
```

**Response (200 OK):** Returns the updated tenant object.

#### Delete Tenant

Deletes a tenant and all associated resources.

```http
DELETE /api/v1/iam/tenants/{tenant}
Authorization: Bearer <admin_token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "tenant deleted successfully"
}
```

---

### Users

Users represent individual identities within a tenant.

#### Create User

Creates a new user in a tenant.

```http
POST /api/v1/iam/tenants/{tenant}/users
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email address (must be unique within tenant) |
| `name` | string | No | User display name |
| `roles` | []string | No | Initial role IDs to assign |
| `groups` | []string | No | Initial group IDs to add user to |
| `attributes` | map[string]string | No | Custom key-value attributes |

**Example:**

```json
{
  "email": "alice@acme.com",
  "name": "Alice Smith",
  "roles": ["developer"],
  "groups": ["engineering"],
  "attributes": {
    "department": "engineering",
    "team_id": "team-west"
  }
}
```

**Response (200 OK):**

```json
{
  "id": "user_abc123",
  "tenant_id": "acme-corp",
  "email": "alice@acme.com",
  "name": "Alice Smith",
  "roles": ["developer"],
  "groups": ["engineering"],
  "attributes": {
    "department": "engineering",
    "team_id": "team-west"
  },
  "mfa_verified": false,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

#### List Users

Returns a paginated list of users in a tenant.

```http
GET /api/v1/iam/tenants/{tenant}/users
Authorization: Bearer <token>
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int32 | Max results (default: 50, max: 1000) |
| `offset` | int32 | Pagination offset |
| `email` | string | Filter by email (exact or prefix match) |
| `role` | string | Filter by role ID |
| `group` | string | Filter by group ID |

**Response (200 OK):**

```json
{
  "total": 42,
  "limit": 50,
  "offset": 0,
  "users": [
    {
      "id": "user_abc123",
      "tenant_id": "acme-corp",
      "email": "alice@acme.com",
      "name": "Alice Smith",
      "roles": ["developer"],
      "groups": ["engineering"],
      "mfa_verified": true,
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

#### Get User

Retrieves a user by ID.

```http
GET /api/v1/iam/tenants/{tenant}/users/{id}
Authorization: Bearer <token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant` | string | Tenant ID |
| `id` | string | User ID |

#### Update User

Updates an existing user.

```http
PUT /api/v1/iam/tenants/{tenant}/users/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Alice M. Smith",
  "email": "alice.smith@acme.com",
  "roles": ["developer", "team-lead"],
  "groups": ["engineering", "platform"],
  "attributes": {
    "department": "engineering",
    "team_id": "team-west",
    "level": "senior"
  }
}
```

#### Delete User

Deletes a user from a tenant.

```http
DELETE /api/v1/iam/tenants/{tenant}/users/{id}
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "user deleted successfully"
}
```

#### Assign Role to User

Assigns a role to a user.

```http
POST /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}
Authorization: Bearer <token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant` | string | Tenant ID |
| `id` | string | User ID |
| `role` | string | Role ID to assign |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "role assigned successfully"
}
```

#### Revoke Role from User

Removes a role from a user.

```http
DELETE /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "success": true,
  "message": "role revoked successfully"
}
```

---

### Groups

Groups are collections of users that can be referenced in policies.

#### Create Group

Creates a new group.

```http
POST /api/v1/iam/tenants/{tenant}/groups
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique group identifier |
| `name` | string | No | Group display name |
| `description` | string | No | Group description |

**Example:**

```json
{
  "id": "engineering",
  "name": "Engineering Team",
  "description": "All engineering staff"
}
```

**Response (200 OK):**

```json
{
  "id": "engineering",
  "tenant_id": "acme-corp",
  "name": "Engineering Team",
  "description": "All engineering staff",
  "members": [],
  "created_at": "2025-01-15T10:30:00Z"
}
```

#### List Groups

Returns a paginated list of groups.

```http
GET /api/v1/iam/tenants/{tenant}/groups?limit=50&offset=0
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "total": 10,
  "limit": 50,
  "offset": 0,
  "groups": [
    {
      "id": "engineering",
      "tenant_id": "acme-corp",
      "name": "Engineering Team",
      "description": "All engineering staff",
      "members": ["user_abc123", "user_def456"],
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

#### Get Group

Retrieves a group by ID.

```http
GET /api/v1/iam/tenants/{tenant}/groups/{id}
Authorization: Bearer <token>
```

#### Update Group

Updates an existing group.

```http
PUT /api/v1/iam/tenants/{tenant}/groups/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Engineering Department",
  "description": "All engineering and DevOps staff"
}
```

#### Delete Group

Deletes a group.

```http
DELETE /api/v1/iam/tenants/{tenant}/groups/{id}
Authorization: Bearer <token>
```

#### Add Member to Group

Adds a user to a group.

```http
POST /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}
Authorization: Bearer <token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant` | string | Tenant ID |
| `id` | string | Group ID |
| `user` | string | User ID to add |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "member added successfully"
}
```

#### Remove Member from Group

Removes a user from a group.

```http
DELETE /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}
Authorization: Bearer <token>
```

---

### Roles

Roles define sets of permissions that can be assigned to users.

#### Create Role

Creates a new role.

```http
POST /api/v1/iam/tenants/{tenant}/roles
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique role identifier |
| `name` | string | No | Role display name |
| `description` | string | No | Role description |
| `permissions` | []string | No | List of permission strings |

**Example:**

```json
{
  "id": "team-lead",
  "name": "Team Lead",
  "description": "Can manage team resources",
  "permissions": ["read:users", "write:users", "read:groups"]
}
```

**Response (200 OK):**

```json
{
  "id": "team-lead",
  "tenant_id": "acme-corp",
  "name": "Team Lead",
  "description": "Can manage team resources",
  "permissions": ["read:users", "write:users", "read:groups"],
  "created_at": "2025-01-15T10:30:00Z"
}
```

#### List Roles

Returns a paginated list of roles.

```http
GET /api/v1/iam/tenants/{tenant}/roles?limit=50&offset=0
Authorization: Bearer <token>
```

#### Get Role

Retrieves a role by ID.

```http
GET /api/v1/iam/tenants/{tenant}/roles/{id}
Authorization: Bearer <token>
```

#### Update Role

Updates an existing role.

```http
PUT /api/v1/iam/tenants/{tenant}/roles/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Senior Team Lead",
  "description": "Can manage team resources and budgets",
  "permissions": ["read:users", "write:users", "read:groups", "write:budgets"]
}
```

#### Delete Role

Deletes a role.

```http
DELETE /api/v1/iam/tenants/{tenant}/roles/{id}
Authorization: Bearer <token>
```

---

### Policies

Policies define fine-grained access control rules using ABAC (Attribute-Based Access Control).

#### Create Policy

Creates a new policy.

```http
POST /api/v1/iam/tenants/{tenant}/policies
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique policy name |
| `description` | string | No | Policy description |
| `priority` | int32 | No | Evaluation priority (lower = higher priority) |
| `spec_yaml` | string | Yes | Policy specification in YAML format |
| `labels` | map[string]string | No | Metadata labels for organization |

**Example:**

```json
{
  "name": "developer-access",
  "description": "Allow developers to access their own resources",
  "priority": 100,
  "spec_yaml": "apiVersion: abac.trustedplatform.io/v1\nkind: Policy\nmetadata:\n  name: developer-access\nspec:\n  rules:\n    - name: read-own-keys\n      effect: allow\n      actions: [read]\n      resources:\n        - keys/users/${subject.id}/**\n      subjects:\n        roles: [developer]",
  "labels": {
    "environment": "production",
    "team": "platform"
  }
}
```

**Response (200 OK):**

```json
{
  "name": "developer-access",
  "tenant_id": "acme-corp",
  "description": "Allow developers to access their own resources",
  "priority": 100,
  "spec_yaml": "apiVersion: abac.trustedplatform.io/v1\n...",
  "labels": {
    "environment": "production",
    "team": "platform"
  },
  "created_at": "2025-01-15T10:30:00Z"
}
```

#### List Policies

Returns a paginated list of policies.

```http
GET /api/v1/iam/tenants/{tenant}/policies?limit=50&offset=0
Authorization: Bearer <token>
```

#### Get Policy

Retrieves a policy by name.

```http
GET /api/v1/iam/tenants/{tenant}/policies/{id}
Authorization: Bearer <token>
```

#### Update Policy

Updates an existing policy.

```http
PUT /api/v1/iam/tenants/{tenant}/policies/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "description": "Updated policy description",
  "priority": 50,
  "spec_yaml": "apiVersion: abac.trustedplatform.io/v1\n...",
  "labels": {
    "environment": "production"
  }
}
```

#### Delete Policy

Deletes a policy.

```http
DELETE /api/v1/iam/tenants/{tenant}/policies/{id}
Authorization: Bearer <token>
```

#### Validate Policy

Validates a policy specification without creating it.

```http
POST /api/v1/iam/tenants/{tenant}/policies/validate
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "spec_yaml": "apiVersion: abac.trustedplatform.io/v1\n..."
}
```

**Response (200 OK):**

```json
{
  "valid": true,
  "errors": []
}
```

**Response (200 OK - Invalid):**

```json
{
  "valid": false,
  "errors": [
    "invalid rule syntax at line 10",
    "unknown action 'execute' - valid actions are: read, write, delete, admin"
  ]
}
```

#### Test Policy

Tests policy evaluation against a simulated request.

```http
POST /api/v1/iam/tenants/{tenant}/policies/test
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject_id` | string | Yes | Subject/user ID to test |
| `action` | string | Yes | Action to test (read, write, delete, admin) |
| `resource` | string | Yes | Resource path to test |
| `roles` | []string | No | Roles to assume for the test |
| `groups` | []string | No | Groups to assume for the test |
| `attributes` | map[string]string | No | Subject attributes |
| `context` | map[string]string | No | Request context (IP, time, etc.) |

**Example:**

```json
{
  "subject_id": "user_abc123",
  "action": "read",
  "resource": "keys/data/my-key",
  "roles": ["developer"],
  "groups": ["engineering"],
  "attributes": {
    "department": "engineering"
  },
  "context": {
    "ip": "192.168.1.100",
    "user_agent": "platformctl/1.0"
  }
}
```

**Response (200 OK):**

```json
{
  "allowed": true,
  "matched_policy": "developer-access",
  "matched_rule": "read-own-keys",
  "evaluation_time_ns": 3250
}
```

---

### Applications (OAuth Clients)

Applications are OAuth2/OIDC clients that can authenticate users.

#### Register Application

Registers a new OAuth2 application.

```http
POST /api/v1/iam/tenants/{tenant}/apps
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Application name |
| `redirect_uris` | []string | No | Allowed OAuth redirect URIs |
| `grant_types` | []string | No | Allowed grant types |
| `response_types` | []string | No | Allowed response types |
| `resource_prefix` | string | No | Resource prefix for scoping |

**Supported Grant Types:**
- `authorization_code` - Standard OAuth2 authorization code flow
- `refresh_token` - Refresh token support
- `client_credentials` - Machine-to-machine authentication

**Supported Response Types:**
- `code` - Authorization code response

**Example:**

```json
{
  "name": "my-web-app",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "resource_prefix": "myapp"
}
```

**Response (200 OK):**

```json
{
  "client_id": "app_abc123xyz",
  "client_secret": "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "tenant_id": "acme-corp",
  "name": "my-web-app",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "resource_prefix": "myapp",
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Note:** The `client_secret` is only returned on creation and rotation. Store it securely.

#### List Applications

Returns a paginated list of applications.

```http
GET /api/v1/iam/tenants/{tenant}/apps?limit=50&offset=0
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "total": 3,
  "limit": 50,
  "offset": 0,
  "apps": [
    {
      "client_id": "app_abc123xyz",
      "tenant_id": "acme-corp",
      "name": "my-web-app",
      "redirect_uris": ["https://myapp.com/callback"],
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

#### Get Application

Retrieves an application by client ID.

```http
GET /api/v1/iam/tenants/{tenant}/apps/{id}
Authorization: Bearer <token>
```

**Note:** The `client_secret` is not returned in GET responses.

#### Update Application

Updates an existing application.

```http
PUT /api/v1/iam/tenants/{tenant}/apps/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "my-web-app-v2",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/oauth/callback",
    "https://staging.myapp.com/callback"
  ]
}
```

#### Delete Application

Deletes an application.

```http
DELETE /api/v1/iam/tenants/{tenant}/apps/{id}
Authorization: Bearer <token>
```

#### Rotate Client Secret

Rotates the client secret for an application.

```http
POST /api/v1/iam/tenants/{tenant}/apps/{id}/rotate
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "client_id": "app_abc123xyz",
  "name": "my-web-app",
  "client_secret": "sk_live_yyyyyyyyyyyyyyyyyyyyyyyyyyy"
}
```

**Warning:** The old client secret is immediately invalidated. Update your application configuration promptly.

---

## gRPC API

The IAM gRPC service provides high-performance access to all IAM operations.

**Connection:** `localhost:9443` (mTLS required)

**Proto Package:** `platform.v1`

**Service:** `PlatformIAMService`

### Service Definition

```protobuf
service PlatformIAMService {
  // Tenant Operations
  rpc CreateTenant(CreateIAMTenantRequest) returns (IAMTenantResponse);
  rpc GetTenant(GetIAMTenantRequest) returns (IAMTenantResponse);
  rpc ListTenants(ListIAMTenantsRequest) returns (ListIAMTenantsResponse);
  rpc UpdateTenant(UpdateIAMTenantRequest) returns (IAMTenantResponse);
  rpc DeleteTenant(DeleteIAMTenantRequest) returns (DeleteIAMTenantResponse);

  // User Operations
  rpc CreateUser(CreateIAMUserRequest) returns (IAMUserResponse);
  rpc GetUser(GetIAMUserRequest) returns (IAMUserResponse);
  rpc ListUsers(ListIAMUsersRequest) returns (ListIAMUsersResponse);
  rpc UpdateUser(UpdateIAMUserRequest) returns (IAMUserResponse);
  rpc DeleteUser(DeleteIAMUserRequest) returns (DeleteIAMUserResponse);

  // Role Operations
  rpc CreateRole(CreateIAMRoleRequest) returns (IAMRoleResponse);
  rpc GetRole(GetIAMRoleRequest) returns (IAMRoleResponse);
  rpc ListRoles(ListIAMRolesRequest) returns (ListIAMRolesResponse);
  rpc UpdateRole(UpdateIAMRoleRequest) returns (IAMRoleResponse);
  rpc DeleteRole(DeleteIAMRoleRequest) returns (DeleteIAMRoleResponse);
  rpc AssignRole(AssignIAMRoleRequest) returns (AssignIAMRoleResponse);
  rpc RevokeRole(RevokeIAMRoleRequest) returns (RevokeIAMRoleResponse);

  // Group Operations
  rpc CreateGroup(CreateIAMGroupRequest) returns (IAMGroupResponse);
  rpc GetGroup(GetIAMGroupRequest) returns (IAMGroupResponse);
  rpc ListGroups(ListIAMGroupsRequest) returns (ListIAMGroupsResponse);
  rpc UpdateGroup(UpdateIAMGroupRequest) returns (IAMGroupResponse);
  rpc DeleteGroup(DeleteIAMGroupRequest) returns (DeleteIAMGroupResponse);
  rpc AddGroupMember(AddGroupMemberRequest) returns (AddGroupMemberResponse);
  rpc RemoveGroupMember(RemoveGroupMemberRequest) returns (RemoveGroupMemberResponse);

  // Policy Operations
  rpc CreatePolicy(CreateIAMPolicyRequest) returns (IAMPolicyResponse);
  rpc GetPolicy(GetIAMPolicyRequest) returns (IAMPolicyResponse);
  rpc ListPolicies(ListIAMPoliciesRequest) returns (ListIAMPoliciesResponse);
  rpc UpdatePolicy(UpdateIAMPolicyRequest) returns (IAMPolicyResponse);
  rpc DeletePolicy(DeleteIAMPolicyRequest) returns (DeleteIAMPolicyResponse);
  rpc ValidatePolicy(ValidateIAMPolicyRequest) returns (ValidateIAMPolicyResponse);
  rpc TestPolicy(TestIAMPolicyRequest) returns (TestIAMPolicyResponse);

  // Application Operations
  rpc RegisterApp(RegisterIAMAppRequest) returns (IAMAppResponse);
  rpc GetApp(GetIAMAppRequest) returns (IAMAppResponse);
  rpc ListApps(ListIAMAppsRequest) returns (ListIAMAppsResponse);
  rpc UpdateApp(UpdateIAMAppRequest) returns (IAMAppResponse);
  rpc DeleteApp(DeleteIAMAppRequest) returns (DeleteIAMAppResponse);
  rpc RotateAppSecret(RotateIAMAppSecretRequest) returns (RotateIAMAppSecretResponse);

  // Authorization
  rpc CheckPermission(CheckIAMPermissionRequest) returns (CheckIAMPermissionResponse);

  // Authentication (OIDC-based, limited direct support)
  rpc Authenticate(AuthenticateIAMRequest) returns (AuthenticateIAMResponse);
  rpc CreateToken(CreateIAMTokenRequest) returns (CreateIAMTokenResponse);
  rpc RevokeToken(RevokeIAMTokenRequest) returns (RevokeIAMTokenResponse);
  rpc VerifyToken(VerifyIAMTokenRequest) returns (VerifyIAMTokenResponse);
}
```

### Message Types

**CreateIAMUserRequest:**

```protobuf
message CreateIAMUserRequest {
  string tenant_id = 1;       // Required: Tenant ID
  string email = 2;           // Required: User email
  string name = 3;            // Optional: Display name
  repeated string roles = 4;  // Optional: Initial roles
  repeated string groups = 5; // Optional: Initial groups
  map<string, string> attributes = 6; // Optional: Custom attributes
}
```

**IAMUser:**

```protobuf
message IAMUser {
  string id = 1;
  string tenant_id = 2;
  string email = 3;
  string name = 4;
  repeated string roles = 5;
  repeated string groups = 6;
  map<string, string> attributes = 7;
  bool mfa_verified = 8;
  google.protobuf.Timestamp created_at = 9;
  google.protobuf.Timestamp updated_at = 10;
  google.protobuf.Timestamp last_auth = 11;
}
```

**CheckIAMPermissionRequest:**

```protobuf
message CheckIAMPermissionRequest {
  string tenant_id = 1;       // Required: Tenant ID
  string subject_id = 2;      // Required: Subject/User ID
  string action = 3;          // Required: Action to check
  string resource = 4;        // Required: Resource path
  repeated string roles = 5;  // Optional: Roles to assume
  repeated string groups = 6; // Optional: Groups to assume
  map<string, string> attributes = 7; // Optional: Subject attributes
  map<string, string> context = 8;    // Optional: Request context
}
```

**CheckIAMPermissionResponse:**

```protobuf
message CheckIAMPermissionResponse {
  bool allowed = 1;
  string matched_policy = 2;
  string matched_rule = 3;
  int64 evaluation_time_ns = 4;
  google.protobuf.Timestamp timestamp = 5;
}
```

### Example Usage (Go)

```go
package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "log"
    "os"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Load mTLS credentials
    cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
    if err != nil {
        log.Fatal(err)
    }

    caCert, err := os.ReadFile("ca.crt")
    if err != nil {
        log.Fatal(err)
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    creds := credentials.NewTLS(&tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    })

    // Connect to gRPC service
    conn, err := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := platformv1.NewPlatformIAMServiceClient(conn)

    // Create a user
    resp, err := client.CreateUser(context.Background(), &platformv1.CreateIAMUserRequest{
        TenantId: "acme-corp",
        Email:    "alice@acme.com",
        Name:     "Alice Smith",
        Roles:    []string{"developer"},
        Groups:   []string{"engineering"},
        Attributes: map[string]string{
            "department": "engineering",
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created user: %s", resp.User.Id)

    // Check permission
    permResp, err := client.CheckPermission(context.Background(), &platformv1.CheckIAMPermissionRequest{
        TenantId:  "acme-corp",
        SubjectId: resp.User.Id,
        Action:    "read",
        Resource:  "keys/data/shared-key",
        Roles:     []string{"developer"},
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Permission allowed: %v (policy: %s)", permResp.Allowed, permResp.MatchedPolicy)
}
```

---

## QUIC API

The QUIC API provides low-latency IAM operations using a binary protocol over UDP.

**Connection:** `localhost:9444` (QUIC with TLS 1.3)

### Operation Codes (OpCodes)

| Category | OpCode | Hex | Operation |
|----------|--------|-----|-----------|
| **User** | OpIAMUserCreate | 0xA9 | Create user |
| | OpIAMUserDelete | 0xAA | Delete user |
| | OpIAMUserGet | 0xAB | Get user |
| | OpIAMUserList | 0xAC | List users |
| | OpIAMUserUpdate | 0xAD | Update user |
| **Role** | OpIAMRoleCreate | 0xB5 | Create role |
| | OpIAMRoleDelete | 0xB6 | Delete role |
| | OpIAMRoleGet | 0xB7 | Get role |
| | OpIAMRoleList | 0xB8 | List roles |
| | OpIAMRoleAssign | 0xB9 | Assign role to user |
| | OpIAMRoleRevoke | 0xBA | Revoke role from user |
| **Group** | OpIAMGroupCreate | 0xBB | Create group |
| | OpIAMGroupDelete | 0xBC | Delete group |
| | OpIAMGroupGet | 0xBD | Get group |
| | OpIAMGroupList | 0xBE | List groups |
| | OpIAMGroupAddMember | 0xBF | Add member to group |
| | OpIAMGroupRemoveMember | 0xF6 | Remove member from group |
| **Auth** | OpIAMCheckPermission | 0xF7 | Check permission |
| | OpIAMAuthenticate | 0xF8 | Authenticate user |
| | OpIAMTokenCreate | 0xF9 | Create token |
| | OpIAMTokenRevoke | 0xFA | Revoke token |
| | OpIAMTokenVerify | 0xFB | Verify token |

### Message Format

QUIC messages use MessagePack (CBOR) encoding:

```
+--------+--------+----------------+
| OpCode | Length | Payload        |
| 1 byte | 4 bytes| variable       |
+--------+--------+----------------+
```

### Request/Response Types

**CreateUserRequest:**

```go
type CreateUserRequest struct {
    TenantID   string            `codec:"tenant_id"`
    UserID     string            `codec:"user_id"`
    Email      string            `codec:"email"`
    Username   string            `codec:"username"`
    Name       string            `codec:"name"`
    Enabled    bool              `codec:"enabled"`
    Attributes map[string]string `codec:"attributes"`
}
```

**IAMUserResponse:**

```go
type IAMUserResponse struct {
    ID         string            `codec:"id"`
    TenantID   string            `codec:"tenant_id"`
    Email      string            `codec:"email"`
    Username   string            `codec:"username"`
    Name       string            `codec:"name"`
    Enabled    bool              `codec:"enabled"`
    Roles      []string          `codec:"roles"`
    Groups     []string          `codec:"groups"`
    Attributes map[string]string `codec:"attributes"`
    CreatedAt  int64             `codec:"created_at"`
    UpdatedAt  int64             `codec:"updated_at"`
    Timestamp  int64             `codec:"timestamp"`
}
```

**CheckPermissionRequest:**

```go
type CheckPermissionRequest struct {
    TenantID  string            `codec:"tenant_id"`
    SubjectID string            `codec:"subject_id"`
    Resource  string            `codec:"resource"`
    Action    string            `codec:"action"`
    Context   map[string]string `codec:"context"`
}
```

**CheckPermissionResponse:**

```go
type CheckPermissionResponse struct {
    Allowed   bool   `codec:"allowed"`
    Reason    string `codec:"reason"`
    Timestamp int64  `codec:"timestamp"`
}
```

**GenericIAMResponse:**

```go
type GenericIAMResponse struct {
    Success   bool   `codec:"success"`
    Message   string `codec:"message"`
    Timestamp int64  `codec:"timestamp"`
}
```

### Example Usage (Go)

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func main() {
    ctx := context.Background()

    // Connect to QUIC service; tlsConfig carries the mTLS client identity
    config := quicwire.DefaultClientConfig("localhost:9444")
    config.TLSConfig = tlsConfig
    client, err := quicwire.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create a user
    createReq := &CreateUserRequest{
        TenantID: "acme-corp",
        Email:    "alice@acme.com",
        Name:     "Alice Smith",
    }

    var user IAMUserResponse
    if err := client.Send(ctx, quicwire.OpIAMUserCreate, createReq, &user); err != nil {
        log.Fatal(err)
    }

    log.Printf("Created user: %s", user.ID)

    // Check permission
    checkReq := &CheckPermissionRequest{
        TenantID:  "acme-corp",
        SubjectID: user.ID,
        Resource:  "keys/data/my-key",
        Action:    "read",
    }

    var permResult CheckPermissionResponse
    if err := client.Send(ctx, quicwire.OpIAMCheckPermission, checkReq, &permResult); err != nil {
        log.Fatal(err)
    }
    log.Printf("Permission allowed: %v", permResult.Allowed)
}
```

---

## MCP API

The Model Context Protocol (MCP) API provides AI/LLM integration for IAM operations.

**Transport:** stdio or HTTPS (port 9445)

**Note:** MCP tools currently support CRUD operations but do not include update operations or policy management. Use REST or gRPC for full functionality.

### Available Tools

#### User Management

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_create_user` | Create a new IAM user | `tenant_id`, `email` |
| `iam_delete_user` | Delete an IAM user | `tenant_id`, `user_id` |
| `iam_get_user` | Get user details | `tenant_id`, `user_id` |
| `iam_list_users` | List users with pagination | `tenant_id` |

**iam_create_user Schema:**

```json
{
  "type": "object",
  "properties": {
    "tenant_id": {
      "type": "string",
      "description": "Tenant ID for the user"
    },
    "email": {
      "type": "string",
      "description": "User email address"
    },
    "name": {
      "type": "string",
      "description": "User display name"
    },
    "roles": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Initial roles to assign to the user"
    },
    "groups": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Initial groups to add the user to"
    },
    "attributes": {
      "type": "object",
      "description": "Custom user attributes as key-value pairs"
    }
  },
  "required": ["tenant_id", "email"]
}
```

#### Role Management

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_create_role` | Create a new role | `tenant_id`, `id` |
| `iam_delete_role` | Delete a role | `tenant_id`, `role_id` |
| `iam_get_role` | Get role details | `tenant_id`, `role_id` |
| `iam_list_roles` | List roles with pagination | `tenant_id` |
| `iam_assign_role` | Assign role to user | `tenant_id`, `user_id`, `role` |
| `iam_revoke_role` | Revoke role from user | `tenant_id`, `user_id`, `role` |

**iam_create_role Schema:**

```json
{
  "type": "object",
  "properties": {
    "tenant_id": {
      "type": "string",
      "description": "Tenant ID for the role"
    },
    "id": {
      "type": "string",
      "description": "Unique role identifier"
    },
    "name": {
      "type": "string",
      "description": "Role display name"
    },
    "description": {
      "type": "string",
      "description": "Role description"
    },
    "permissions": {
      "type": "array",
      "items": {"type": "string"},
      "description": "List of permissions granted by this role"
    }
  },
  "required": ["tenant_id", "id"]
}
```

#### Group Management

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_create_group` | Create a new group | `tenant_id`, `id` |
| `iam_delete_group` | Delete a group | `tenant_id`, `group_id` |
| `iam_get_group` | Get group details | `tenant_id`, `group_id` |
| `iam_list_groups` | List groups with pagination | `tenant_id` |
| `iam_add_group_member` | Add user to group | `tenant_id`, `group_id`, `user_id` |
| `iam_remove_group_member` | Remove user from group | `tenant_id`, `group_id`, `user_id` |

#### Tenant Management

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_create_tenant` | Create a new tenant | `id` |
| `iam_delete_tenant` | Delete a tenant | `tenant_id` |
| `iam_get_tenant` | Get tenant details | `tenant_id` |
| `iam_list_tenants` | List all tenants | (none) |

**iam_create_tenant Schema:**

```json
{
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "description": "Unique tenant identifier"
    },
    "name": {
      "type": "string",
      "description": "Tenant display name"
    },
    "max_users": {
      "type": "integer",
      "description": "Maximum number of users allowed in the tenant"
    },
    "mfa_required": {
      "type": "boolean",
      "description": "Whether MFA is required for all users in the tenant",
      "default": false
    }
  },
  "required": ["id"]
}
```

#### Authorization

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_check_permission` | Check user permission | `tenant_id`, `user_id`, `resource`, `action` |
| `iam_authenticate` | Authenticate user | `tenant_id`, `email` |

**iam_check_permission Schema:**

```json
{
  "type": "object",
  "properties": {
    "tenant_id": {
      "type": "string",
      "description": "Tenant ID"
    },
    "user_id": {
      "type": "string",
      "description": "User ID to check permissions for"
    },
    "resource": {
      "type": "string",
      "description": "Resource identifier (e.g., 'iam:users', 'ca:certificates')"
    },
    "action": {
      "type": "string",
      "description": "Action to check (read, write, delete, admin)"
    }
  },
  "required": ["tenant_id", "user_id", "resource", "action"]
}
```

#### Token Management

| Tool | Description | Required Parameters |
|------|-------------|---------------------|
| `iam_create_token` | Create auth token | `tenant_id`, `user_id` |
| `iam_revoke_token` | Revoke a token | `token_id` |
| `iam_verify_token` | Verify and decode token | `token` |

**iam_create_token Schema:**

```json
{
  "type": "object",
  "properties": {
    "tenant_id": {
      "type": "string",
      "description": "Tenant ID"
    },
    "user_id": {
      "type": "string",
      "description": "User ID to create the token for"
    },
    "scopes": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Scopes to grant to the token"
    },
    "expires_in": {
      "type": "integer",
      "description": "Token expiration time in seconds",
      "default": 3600
    },
    "description": {
      "type": "string",
      "description": "Optional description for the token"
    }
  },
  "required": ["tenant_id", "user_id"]
}
```

### Example MCP Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "iam_create_user",
    "arguments": {
      "tenant_id": "acme-corp",
      "email": "alice@acme.com",
      "name": "Alice Smith",
      "roles": ["developer"],
      "groups": ["engineering"]
    }
  }
}
```

### Example MCP Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"id\":\"user_abc123\",\"tenant_id\":\"acme-corp\",\"email\":\"alice@acme.com\",\"name\":\"Alice Smith\",\"roles\":[\"developer\"],\"groups\":[\"engineering\"]}"
      }
    ]
  }
}
```

---

## Unix Socket API

The Unix socket API provides local IPC access to IAM operations.

**Socket Path:** `/run/platformd.sock`

The Unix socket serves HTTP requests with the same REST API as the TCP listener.

### Usage with platformctl CLI

platformctl's default local context dials `/run/platformd.sock`; for another
path, see `docs/daemon/api-reference-unix.md`.

```bash
# User Operations
platformctl iam user create \
  --tenant acme-corp \
  --email alice@acme.com \
  --name "Alice Smith" \
  --roles developer \
  --groups engineering

platformctl iam user list \
  --tenant acme-corp \
  --limit 100

platformctl iam user get \
  --tenant acme-corp \
  --user user_abc123

platformctl iam user delete \
  --tenant acme-corp \
  --user user_abc123

# Role Operations
platformctl iam role create \
  --tenant acme-corp \
  --id team-lead \
  --name "Team Lead" \
  --permissions "read:users,write:users"

platformctl iam role assign \
  --tenant acme-corp \
  --user user_abc123 \
  --role developer

platformctl iam role revoke \
  --tenant acme-corp \
  --user user_abc123 \
  --role developer

# Group Operations
platformctl iam group create \
  --tenant acme-corp \
  --id engineering \
  --name "Engineering Team"

platformctl iam group add-member \
  --tenant acme-corp \
  --group engineering \
  --user user_abc123

# Policy Operations
platformctl iam policy create \
  --tenant acme-corp \
  --name developer-access \
  --spec-file policy.yaml

platformctl iam policy test \
  --tenant acme-corp \
  --subject user_abc123 \
  --action read \
  --resource keys/data/my-key
```

### Usage with curl

```bash
# Create user
curl --unix-socket /run/platformd.sock \
  -X POST http://localhost/api/v1/iam/tenants/acme-corp/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@acme.com",
    "name": "Alice Smith",
    "roles": ["developer"]
  }'

# List users
curl --unix-socket /run/platformd.sock \
  "http://localhost/api/v1/iam/tenants/acme-corp/users?limit=50"

# Get user
curl --unix-socket /run/platformd.sock \
  http://localhost/api/v1/iam/tenants/acme-corp/users/user_abc123

# Delete user
curl --unix-socket /run/platformd.sock \
  -X DELETE http://localhost/api/v1/iam/tenants/acme-corp/users/user_abc123

# Test policy
curl --unix-socket /run/platformd.sock \
  -X POST http://localhost/api/v1/iam/tenants/acme-corp/policies/test \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "user_abc123",
    "action": "read",
    "resource": "keys/data/my-key",
    "roles": ["developer"]
  }'
```

### Usage with Go

```go
package main

import (
    "context"
    "encoding/json"
    "io"
    "net"
    "net/http"
)

func main() {
    // Create HTTP client with Unix socket transport
    client := &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                return net.Dial("unix", "/run/platformd.sock")
            },
        },
    }

    // List users
    resp, err := client.Get("http://localhost/api/v1/iam/tenants/acme-corp/users")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    var result map[string]interface{}
    json.Unmarshal(body, &result)

    // Process result...
}
```

---

## Authentication

### mTLS (All Protocols)

All protocols support mutual TLS (mTLS) authentication for machine-to-machine communication.

```bash
# REST with mTLS
curl --cert client.crt --key client.key --cacert ca.crt \
  https://platform.example.com:8443/api/v1/iam/tenants

# gRPC with mTLS (via grpcurl)
grpcurl -cert client.crt -key client.key -cacert ca.crt \
  platform.example.com:9443 \
  platform.v1.PlatformIAMService/ListTenants
```

**Go mTLS Configuration:**

```go
cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")
caCert, _ := os.ReadFile("ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      caCertPool,
}

// For gRPC
creds := credentials.NewTLS(tlsConfig)
conn, _ := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))

// For HTTP
client := &http.Client{
    Transport: &http.Transport{TLSClientConfig: tlsConfig},
}
```

### Bearer Tokens (REST, gRPC)

Bearer tokens can be obtained via OAuth2/OIDC flows.

```http
GET /api/v1/iam/tenants/acme-corp/users
Authorization: Bearer <access_token>
```

**Go Bearer Token:**

```go
// REST
req.Header.Set("Authorization", "Bearer "+accessToken)

// gRPC
ctx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
```

### OAuth2/OIDC Flows

For user authentication, use the OAuth2/OIDC endpoints. See [OIDC Endpoints](#oidc-endpoints) section below.

---

## OIDC Endpoints

The platform provides OpenID Connect (OIDC) compliant endpoints for user authentication.

### Discovery Document

```http
GET /.well-known/openid-configuration
```

**Response:**

```json
{
  "issuer": "https://platform.example.com",
  "authorization_endpoint": "https://platform.example.com/oauth2/authorize",
  "token_endpoint": "https://platform.example.com/oauth2/token",
  "userinfo_endpoint": "https://platform.example.com/oauth2/userinfo",
  "jwks_uri": "https://platform.example.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

### Authorization Endpoint

```http
GET /oauth2/authorize
```

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | Application client ID |
| `redirect_uri` | Yes | Registered callback URL |
| `response_type` | Yes | `code` for authorization code flow |
| `scope` | Yes | Space-separated scopes (must include `openid`) |
| `state` | Recommended | CSRF protection token |
| `code_challenge` | PKCE | Base64url-encoded SHA256 hash of verifier |
| `code_challenge_method` | PKCE | `S256` |
| `nonce` | Optional | Replay attack prevention |

**Example:**

```
GET /oauth2/authorize?
  client_id=app_abc123xyz
  &redirect_uri=https://myapp.com/callback
  &response_type=code
  &scope=openid%20profile%20email
  &state=xyz123
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

### Token Endpoint

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
```

**Authorization Code Grant:**

```
grant_type=authorization_code
&code=<auth_code>
&redirect_uri=<callback_url>
&client_id=<client_id>
&client_secret=<client_secret>
&code_verifier=<pkce_verifier>
```

**Refresh Token Grant:**

```
grant_type=refresh_token
&refresh_token=<refresh_token>
&client_id=<client_id>
&client_secret=<client_secret>
```

**Client Credentials Grant:**

```
grant_type=client_credentials
&client_id=<client_id>
&client_secret=<client_secret>
&scope=<scopes>
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJl...",
  "id_token": "eyJhbGciOiJFUzI1NiIs...",
  "scope": "openid profile email"
}
```

### UserInfo Endpoint

```http
GET /oauth2/userinfo
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "sub": "user_abc123",
  "email": "alice@acme.com",
  "email_verified": true,
  "name": "Alice Smith",
  "preferred_username": "alice",
  "groups": ["engineering"],
  "roles": ["developer"],
  "tenant_id": "acme-corp"
}
```

### JWKS Endpoint

```http
GET /.well-known/jwks.json
```

**Response:**

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "key-1",
      "x": "...",
      "y": "..."
    }
  ]
}
```

---

## Error Responses

### Error Format

All errors follow a consistent JSON format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error message",
  "error_uri": "https://docs.trustedplatform.io/iam/errors#error_code"
}
```

### HTTP Status Codes

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `bad_request` | Invalid request body or parameters |
| 400 | `invalid_request` | Missing or invalid OAuth parameter |
| 400 | `invalid_grant` | Invalid authorization code or refresh token |
| 401 | `unauthorized` | Missing or invalid authentication |
| 401 | `invalid_client` | Client authentication failed |
| 403 | `forbidden` | Insufficient permissions |
| 403 | `unauthorized_client` | Client not authorized for grant type |
| 404 | `not_found` | Resource not found |
| 409 | `conflict` | Resource already exists |
| 429 | `rate_limited` | Too many requests |
| 500 | `internal_error` | Internal server error |
| 503 | `service_unavailable` | IAM service not available |

### gRPC Error Codes

| Code | Description |
|------|-------------|
| `FAILED_PRECONDITION` | IAM service not available |
| `INVALID_ARGUMENT` | Missing or invalid required parameter |
| `NOT_FOUND` | Resource not found |
| `ALREADY_EXISTS` | Resource already exists |
| `PERMISSION_DENIED` | Insufficient permissions |
| `UNAUTHENTICATED` | Missing or invalid authentication |
| `INTERNAL` | Internal server error |

### QUIC Status Codes

| Status | Value | Description |
|--------|-------|-------------|
| StatusOK | 0x00 | Success |
| StatusInvalidRequest | 0x01 | Invalid request format |
| StatusInvalidArgument | 0x02 | Missing or invalid parameter |
| StatusNotFound | 0x03 | Resource not found |
| StatusUnauthorized | 0x04 | Authentication required |
| StatusInternalError | 0x05 | Internal server error |
| StatusNotImplemented | 0x06 | Operation not supported |
| StatusUnavailable | 0x07 | Service unavailable |

### Error Handling Example (Go)

```go
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func handleError(err error) {
    st, ok := status.FromError(err)
    if !ok {
        // Not a gRPC error
        log.Printf("Unknown error: %v", err)
        return
    }

    switch st.Code() {
    case codes.NotFound:
        log.Printf("Resource not found: %s", st.Message())
    case codes.InvalidArgument:
        log.Printf("Invalid argument: %s", st.Message())
    case codes.PermissionDenied:
        log.Printf("Permission denied: %s", st.Message())
    case codes.FailedPrecondition:
        log.Printf("Service unavailable: %s", st.Message())
    default:
        log.Printf("Error [%s]: %s", st.Code(), st.Message())
    }
}
```

---

## Rate Limiting

All API endpoints are subject to rate limiting:

| Endpoint Category | Rate Limit | Window |
|-------------------|------------|--------|
| Authentication | 10 req/min | Per IP |
| Read Operations | 1000 req/min | Per tenant |
| Write Operations | 100 req/min | Per tenant |
| Policy Evaluation | 10000 req/min | Per tenant |

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705312800
```

When rate limited, a `429 Too Many Requests` response is returned:

```json
{
  "error": "rate_limited",
  "error_description": "Too many requests, please retry after 60 seconds",
  "retry_after": 60
}
```

---

## Best Practices

### Security

1. **Always use mTLS** for service-to-service communication
2. **Rotate client secrets** regularly using the `/rotate` endpoint
3. **Use PKCE** for all OAuth2 authorization code flows
4. **Validate tokens** on every request using the JWKS endpoint
5. **Use short-lived tokens** and refresh tokens for long sessions

### Performance

1. **Use gRPC or QUIC** for high-throughput operations
2. **Batch operations** where possible using list endpoints with filters
3. **Cache policy decisions** client-side when appropriate
4. **Use pagination** for large result sets (always specify `limit`)

### Reliability

1. **Implement retry logic** with exponential backoff for transient errors
2. **Handle rate limiting** by respecting `Retry-After` headers
3. **Monitor error rates** using the `X-Request-ID` header for correlation
4. **Use Unix socket** for local operations to avoid network overhead

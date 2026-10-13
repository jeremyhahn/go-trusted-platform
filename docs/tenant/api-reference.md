# Tenant API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). The gRPC TCP port is 10443, not 9443.

Complete API reference for tenant management in go-trusted-platform. The Tenant API provides 15 operations for multi-tenant lifecycle management: quota enforcement, DEK management and state synchronization, plus the per-tenant barrier operations.

> Subordinate to [api.md](api.md), which is normative. The per-tenant VLAN range and OVS bridge were retired by #708, and with them the `ValidateVLAN` and `GetBridgeName` operations on every transport.

## Protocol Overview

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTP/HTTPS | 8443 | Web clients, external systems |
| gRPC | TCP | 9443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTPS | 9445 | AI/LLM integration |
| Unix | Unix Socket | /run/platformd.sock | Local IPC, CLI |

## Multi-Tenancy Architecture

Each tenant receives:

- **Resource Quotas**: Compute, network, and storage limits
- **DEK (Data Encryption Key)**: TPM-backed tenant-specific encryption
- **State Management**: Lifecycle state machine with transitions

### Tenant State Machine

```
    +----------+
    | Created  |
    +----+-----+
         |
         v
    +----+-----+     +-----------+
    |  Active  +<--->+ Suspended |
    +----+-----+     +-----+-----+
         |                 |
         v                 v
    +----+-----+     +-----+-----+
    | Deleting +---->+  Deleted  |
    +----------+     +-----------+
```

**State Transitions:**
- `created` -> `active`: Tenant activated after setup
- `created` -> `deleting`: Cancel before activation
- `active` -> `suspended`: Block traffic, pause operations
- `active` -> `deleting`: Begin deletion process
- `suspended` -> `active`: Resume operations
- `suspended` -> `deleting`: Delete suspended tenant
- `deleting` -> `deleted`: Deletion complete (terminal)

## Operations Summary

| # | Operation | Description |
|---|-----------|-------------|
| 1 | ListTenants | List all tenants with pagination |
| 2 | GetTenant | Get tenant by ID |
| 3 | GetTenantByName | Get tenant by name |
| 4 | CreateTenant | Create tenant with quotas and DEK |
| 5 | UpdateTenant | Update display name, labels, annotations |
| 6 | DeleteTenant | Delete tenant and cleanup resources |
| 7 | SuspendTenant | Suspend tenant |
| 8 | ResumeTenant | Resume suspended tenant |
| 9 | GetQuotas | Get compute, network, storage quotas |
| 10 | UpdateQuotas | Update tenant quotas |
| 11 | GetUsage | Get current resource usage |
| 12 | CheckQuota | Check quota availability |
| 13 | Sync | Synchronize tenant state |
| 14 | RotateTenantDEK | Rotate tenant Data Encryption Key |
| 15 | GetTenantDEKStatus | Get DEK status and usage metrics |

---

## REST API

Base URL: `https://host:8443/api/v1/tenants`

### 1. ListTenants

List all tenants with pagination support.

**Request:**
```http
GET /api/v1/tenants?limit=100&offset=0
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | int | 100 | Maximum tenants to return |
| offset | int | 0 | Number to skip for pagination |

**Response (200 OK):**
```json
{
  "tenants": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "engineering",
      "display_name": "Engineering Team",
      "state": "active",
      "compute_quota": {
        "max_vms": 50,
        "max_containers": 200,
        "max_vcpus": 400,
        "max_memory_mb": 524288,
        "max_disk_gb": 5000
      },
      "network_quota": {
        "max_bridges": 5,
        "max_ports": 500,
        "max_bandwidth_mbps": 10000
      },
      "storage_quota": {
        "max_volumes_gb": 10000,
        "max_snapshots": 100
      },
      "labels": { "env": "prod" },
      "created_at": "2025-12-26T10:30:00Z",
      "updated_at": "2025-12-26T14:45:00Z"
    }
  ],
  "total": 45,
  "limit": 100,
  "offset": 0,
  "timestamp": "2025-12-26T15:00:00Z"
}
```

### 2. GetTenant

Get tenant details by ID.

**Request:**
```http
GET /api/v1/tenants/{id}
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "engineering",
  "display_name": "Engineering Team",
  "state": "active",
  "compute_quota": { ... },
  "network_quota": { ... },
  "storage_quota": { ... },
  "labels": { "env": "prod" },
  "annotations": { "owner": "platform-team" },
  "created_at": "2025-12-26T10:30:00Z",
  "updated_at": "2025-12-26T14:45:00Z"
}
```

### 3. GetTenantByName

Get tenant by unique name.

**Request:**
```http
GET /api/v1/tenants/name/{name}
```

**Response:** Same as GetTenant.

### 4. CreateTenant

Create a new tenant with its quotas, DEK and per-tenant barrier.

**Request:**
```http
POST /api/v1/tenants
Content-Type: application/json

{
  "name": "engineering",
  "display_name": "Engineering Team",
  "labels": { "env": "prod", "cost_center": "CC-1234" },
  "annotations": { "owner": "platform-team" }
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Unique tenant identifier |
| display_name | string | No | Human-readable name |
| labels | object | No | Key-value labels |
| annotations | object | No | Key-value annotations |

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "engineering",
  "display_name": "Engineering Team",
  "state": "created",
  "compute_quota": {
    "max_vms": 10,
    "max_containers": 50,
    "max_vcpus": 100,
    "max_memory_mb": 131072,
    "max_disk_gb": 1000
  },
  "network_quota": {
    "max_bridges": 1,
    "max_ports": 100,
    "max_bandwidth_mbps": 1000
  },
  "storage_quota": {
    "max_volumes_gb": 1000,
    "max_snapshots": 10
  },
  "labels": { "env": "prod", "cost_center": "CC-1234" },
  "annotations": { "owner": "platform-team" },
  "created_at": "2025-12-26T10:30:00Z",
  "updated_at": "2025-12-26T10:30:00Z"
}
```

### 5. UpdateTenant

Update tenant metadata (display name, labels, annotations).

**Request:**
```http
PUT /api/v1/tenants/{id}
Content-Type: application/json

{
  "display_name": "Engineering Team (Updated)",
  "labels": { "env": "prod", "tier": "premium" },
  "annotations": { "owner": "platform-team", "updated-by": "admin" }
}
```

**Response (200 OK):** Updated tenant object.

### 6. DeleteTenant

Delete tenant and clean up its resources (DEK, barrier, quotas).

**Request:**
```http
DELETE /api/v1/tenants/{id}
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "delete",
  "success": true,
  "message": "tenant deleted successfully"
}
```

### 7. SuspendTenant

Suspend tenant. Suspension blocks resource operations; it is a state change only, since a tenant has no network enforcement until tenant VRFs.

**Request:**
```http
POST /api/v1/tenants/{id}/suspend
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "suspend",
  "success": true,
  "message": "tenant suspended successfully"
}
```

### 8. ResumeTenant

Resume suspended tenant, restoring network traffic.

**Request:**
```http
POST /api/v1/tenants/{id}/resume
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "resume",
  "success": true,
  "message": "tenant resumed successfully"
}
```

### 9. GetQuotas

Get tenant compute, network, and storage quotas.

**Request:**
```http
GET /api/v1/tenants/{id}/quotas
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "compute": {
    "max_vms": 50,
    "max_containers": 200,
    "max_vcpus": 400,
    "max_memory_mb": 524288,
    "max_disk_gb": 5000
  },
  "network": {
    "max_bridges": 5,
    "max_ports": 500,
    "max_bandwidth_mbps": 10000
  },
  "storage": {
    "max_volumes_gb": 10000,
    "max_snapshots": 100
  },
  "timestamp": "2025-12-26T15:00:00Z"
}
```

### 10. UpdateQuotas

Update tenant quota limits.

**Request:**
```http
PUT /api/v1/tenants/{id}/quotas
Content-Type: application/json

{
  "compute": {
    "max_vms": 100,
    "max_containers": 500,
    "max_vcpus": 1000,
    "max_memory_mb": 1048576,
    "max_disk_gb": 10000
  },
  "network": {
    "max_bridges": 10,
    "max_ports": 1000,
    "max_bandwidth_mbps": 20000
  },
  "storage": {
    "max_volumes_gb": 20000,
    "max_snapshots": 200
  }
}
```

**Response (200 OK):** Updated quotas object.

### 11. GetUsage

Get current resource usage for a tenant.

**Request:**
```http
GET /api/v1/tenants/{id}/usage
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "vms": 25,
  "containers": 100,
  "vcpus": 200,
  "memory_mb": 262144,
  "disk_gb": 2500,
  "bridges": 2,
  "ports": 250,
  "bandwidth_mbps": 5000,
  "volumes": 5000,
  "snapshots": 50,
  "timestamp": "2025-12-26T15:00:00Z"
}
```

### 12. CheckQuota

Check if a resource request can be fulfilled within quota limits.

**Request:**
```http
POST /api/v1/tenants/{id}/check-quota
Content-Type: application/json

{
  "resource": "vms",
  "amount": 10
}
```

**Resource Types:**

| Category | Resources |
|----------|-----------|
| Compute | `vms`, `containers`, `vcpus`, `memory`, `disk` |
| Network | `bridges`, `ports`, `bandwidth` |
| Storage | `volumes`, `snapshots` |

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "resource": "vms",
  "amount": 10,
  "allowed": true,
  "message": "quota available",
  "timestamp": "2025-12-26T15:00:00Z"
}
```

### 13. Sync

Synchronize tenant manager state with external systems (usage tracker, quota reservations).

**Request:**
```http
POST /api/v1/tenants/sync
```

**Response (200 OK):**
```json
{
  "action": "sync",
  "success": true,
  "message": "tenant manager synchronized successfully"
}
```

### 14. RotateTenantDEK

Rotate the Data Encryption Key for a tenant. Supports background re-encryption.

**Request:**
```http
POST /api/v1/tenants/{id}/dek/rotate
Content-Type: application/json

{
  "background": true
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| background | bool | No | Run re-encryption in background (default: false) |

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "old_version": 1,
  "new_version": 2,
  "timestamp": "2025-12-26T15:00:00Z"
}
```

### 15. GetTenantDEKStatus

Get DEK status including usage metrics and rotation progress.

**Request:**
```http
GET /api/v1/tenants/{id}/dek/status
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "/tenant/550e8400-e29b-41d4-a716-446655440000/default",
  "algorithm": "aes-256-gcm",
  "status": "active",
  "version": 2,
  "is_default": true,
  "created_at": "2025-12-26T10:30:00Z",
  "rotated_at": "2025-12-26T15:00:00Z",
  "usage_count": 15000,
  "bytes_used": 1073741824,
  "max_usage_count": 1000000,
  "max_bytes_used": 0,
  "warning_percent": 80,
  "usage_percent": 1.5,
  "needs_rotation": false,
  "reencrypt_progress": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| path | string | KMS DEK path (/tenant/{id}/default) |
| algorithm | string | Encryption algorithm (aes-256-gcm) |
| status | string | DEK status (active, rotating, etc.) |
| version | uint64 | Current DEK version |
| is_default | bool | Whether this is the default DEK |
| usage_count | uint64 | Number of encrypt/decrypt operations |
| bytes_used | uint64 | Total bytes processed |
| max_usage_count | uint64 | Maximum operations before rotation (0=unlimited) |
| max_bytes_used | uint64 | Maximum bytes before rotation (0=unlimited) |
| warning_percent | int32 | Percentage threshold for rotation warning |
| usage_percent | float64 | Current usage as percentage of limit |
| needs_rotation | bool | Whether rotation is recommended |
| reencrypt_progress | object | Background re-encryption progress (if active) |

---

## gRPC API

Service: `TenantGRPCService` on port 9443

### Service Methods

```protobuf
service TenantService {
  rpc ListTenants(ListTenantsRequest) returns (ListTenantsResponse);
  rpc GetTenant(GetTenantRequest) returns (TenantResponse);
  rpc GetTenantByName(GetTenantByNameRequest) returns (TenantResponse);
  rpc CreateTenant(CreateTenantRequest) returns (TenantResponse);
  rpc UpdateTenant(UpdateTenantRequest) returns (TenantResponse);
  rpc DeleteTenant(DeleteTenantRequest) returns (OperationStatusResponse);
  rpc SuspendTenant(SuspendTenantRequest) returns (OperationStatusResponse);
  rpc ResumeTenant(ResumeTenantRequest) returns (OperationStatusResponse);
  rpc GetQuotas(GetQuotasRequest) returns (QuotasResponse);
  rpc UpdateQuotas(UpdateQuotasRequest) returns (OperationStatusResponse);
  rpc GetUsage(GetUsageRequest) returns (UsageResponse);
  rpc CheckQuota(CheckQuotaRequest) returns (CheckQuotaResponse);
  rpc Sync(SyncRequest) returns (SyncResponse);
  rpc RotateTenantDEK(RotateTenantDEKRequest) returns (RotateTenantDEKResponse);
  rpc GetTenantDEKStatus(GetTenantDEKStatusRequest) returns (TenantDEKStatusResponse);
}
```

### Request/Response Types

**ListTenantsRequest:**
```json
{ "limit": 100, "offset": 0 }
```

**GetTenantRequest:**
```json
{ "tenant_id": "550e8400-e29b-41d4-a716-446655440000" }
```

**GetTenantByNameRequest:**
```json
{ "name": "engineering" }
```

**CreateTenantRequest:**
```json
{
  "name": "engineering",
  "display_name": "Engineering Team",
  "labels": { "env": "prod" },
  "annotations": {},
  "compute_quota": { "max_vms": 50, "max_containers": 200, "max_vcpus": 400, "max_memory_mb": 524288 },
  "network_quota": { "max_bridges": 5, "max_ports": 500, "max_bandwidth_mbps": 10000 },
  "storage_quota": { "max_volumes_gb": 10000, "max_snapshots": 100 }
}
```

**UpdateTenantRequest:**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "display_name": "Engineering Team (Updated)",
  "labels": { "env": "prod" },
  "annotations": {}
}
```

**CheckQuotaRequest:**
```json
{ "tenant_id": "...", "resource": "vms", "amount": 10 }
```

### gRPC Error Codes

| Error Type | gRPC Code | Description |
|------------|-----------|-------------|
| ErrTenantNotFound | NOT_FOUND | Tenant does not exist |
| ErrTenantExists | ALREADY_EXISTS | Tenant name already used |
| ErrInvalidRequest | INVALID_ARGUMENT | Bad request parameters |
| ErrInvalidState | FAILED_PRECONDITION | Invalid tenant state |
| ErrInvalidTransition | FAILED_PRECONDITION | Illegal state transition |
| ErrQuotaExceeded | RESOURCE_EXHAUSTED | Quota limit reached |
| ErrStorageFailed | INTERNAL | Storage operation failed |
| ErrDEKOperationFailed | INTERNAL | TPM key operation failed |

### Go Client Example

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    conn, err := grpc.Dial("localhost:9443",
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    svc := daemon.NewTenantGRPCService()

    // Create tenant
    resp, err := svc.CreateTenant(context.Background(), &daemon.CreateTenantRequest{
        Name:           "engineering",
        DisplayName:    "Engineering Team",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created tenant: %s", resp.Tenant.ID)
}
```

---

## QUIC API

Binary protocol on UDP port 9444.

### Opcodes (0x10-0x1E, 0xEA-0xEB)

| Opcode | Hex | Operation |
|--------|-----|-----------|
| OpTenantList | 0x10 | List all tenants |
| OpTenantGet | 0x11 | Get tenant by ID |
| OpTenantGetByName | 0x12 | Get tenant by name |
| OpTenantCreate | 0x13 | Create new tenant |
| OpTenantUpdate | 0x14 | Update tenant |
| OpTenantDelete | 0x15 | Delete tenant |
| OpTenantSuspend | 0x16 | Suspend tenant |
| OpTenantResume | 0x17 | Resume tenant |
| OpTenantGetQuotas | 0x18 | Get quotas |
| OpTenantUpdateQuotas | 0x19 | Update quotas |
| OpTenantGetUsage | 0x1A | Get usage stats |
| OpTenantCheckQuota | 0x1B | Check quota availability |
| OpTenantSync | 0x1E | Synchronize state |
| OpTenantRotateDEK | 0xEA | Rotate tenant DEK |
| OpTenantGetDEKStatus | 0xEB | Get DEK status |

### Frame Format

```
+--------+--------+--------+--------+--------+--------+
| OpCode | Flags  |    Payload Length (4 bytes)      |
+--------+--------+--------+--------+--------+--------+
|                    Payload (MessagePack)           |
+--------+--------+--------+--------+--------+--------+
```

### Request Payloads (MessagePack)

**OpTenantList (0x10):**
```json
{ "limit": 100, "offset": 0 }
```

**OpTenantGet (0x11):**
```json
{ "tenant_id": "550e8400-e29b-41d4-a716-446655440000" }
```

**OpTenantGetByName (0x12):**
```json
{ "name": "engineering" }
```

**OpTenantCreate (0x13):**
```json
{
  "name": "engineering",
  "display_name": "Engineering Team",
  "labels": { "env": "prod" },
  "annotations": {}
}
```

**OpTenantUpdate (0x14):**
```json
{
  "tenant_id": "...",
  "display_name": "New Name",
  "labels": {},
  "annotations": {}
}
```

**OpTenantDelete (0x15):**
```json
{ "tenant_id": "..." }
```

**OpTenantSuspend (0x16) / OpTenantResume (0x17):**
```json
{ "tenant_id": "..." }
```

**OpTenantGetQuotas (0x18) / OpTenantGetUsage (0x1A):**
```json
{ "tenant_id": "..." }
```

**OpTenantUpdateQuotas (0x19):**
```json
{
  "tenant_id": "...",
  "quotas": {
    "compute": { "max_vms": 100, ... },
    "network": { ... },
    "storage": { ... }
  }
}
```

**OpTenantCheckQuota (0x1B):**
```json
{ "tenant_id": "...", "resource": "vms", "amount": 10 }
```

**OpTenantSync (0x1E):**
```json
{}
```

---

## MCP API (Model Context Protocol)

AI/LLM integration via stdio or HTTPS on port 9445.

### Tools

| Tool Name | Description |
|-----------|-------------|
| tenant_list | List all tenants with pagination |
| tenant_get | Get tenant by ID |
| tenant_get_by_name | Get tenant by name |
| tenant_create | Create new tenant |
| tenant_update | Update tenant metadata |
| tenant_delete | Delete tenant |
| tenant_suspend | Suspend tenant |
| tenant_resume | Resume tenant |
| tenant_get_quotas | Get tenant quotas |
| tenant_update_quotas | Update quotas |
| tenant_get_usage | Get resource usage |
| tenant_check_quota | Check quota availability |
| tenant_sync | Synchronize state |
| tenant_rotate_dek | Rotate tenant DEK |
| tenant_get_dek_status | Get DEK status and usage |

### Tool Schemas

**tenant_list:**
```json
{
  "name": "tenant_list",
  "description": "List all tenants with pagination support",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": { "type": "integer", "description": "Max tenants to return", "default": 100 },
      "offset": { "type": "integer", "description": "Skip for pagination", "default": 0 }
    }
  }
}
```

**tenant_create:**
```json
{
  "name": "tenant_create",
  "description": "Create a new tenant with optional quotas",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": { "type": "string", "description": "Unique tenant name" },
      "display_name": { "type": "string", "description": "Human-readable name" },
      "labels": { "type": "object", "description": "Key-value labels" },
      "annotations": { "type": "object", "description": "Key-value annotations" },
      "max_vms": { "type": "integer", "description": "Max VMs (compute)" },
      "max_containers": { "type": "integer", "description": "Max containers" },
      "max_vcpus": { "type": "integer", "description": "Max vCPUs" },
      "max_memory_mb": { "type": "integer", "description": "Max memory (MB)" },
      "max_disk_gb": { "type": "integer", "description": "Max disk (GB)" },
      "max_bridges": { "type": "integer", "description": "Max bridges" },
      "max_ports": { "type": "integer", "description": "Max ports" },
      "max_bandwidth_mbps": { "type": "integer", "description": "Max bandwidth (Mbps)" },
      "max_volumes_gb": { "type": "integer", "description": "Max volume storage (GB)" },
      "max_snapshots": { "type": "integer", "description": "Max snapshots" }
    },
    "required": ["name"]
  }
}
```

**tenant_check_quota:**
```json
{
  "name": "tenant_check_quota",
  "description": "Check if tenant has sufficient quota for a resource request",
  "inputSchema": {
    "type": "object",
    "properties": {
      "tenant_id": { "type": "string", "description": "Tenant ID" },
      "resource_type": {
        "type": "string",
        "description": "Resource type (vms, containers, vcpus, memory, disk, bridges, ports, bandwidth, volumes, snapshots)"
      },
      "amount": { "type": "integer", "description": "Amount to request" }
    },
    "required": ["tenant_id", "resource_type", "amount"]
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
    "name": "tenant_create",
    "arguments": {
      "name": "engineering",
      "display_name": "Engineering Team",
      "max_vms": 50,
      "max_containers": 200
    }
  }
}
```

### Response Format

```json
{
  "success": true,
  "tenant": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "engineering",
    "display_name": "Engineering Team",
    "state": "created",
    "compute_quota": { ... },
    "network_quota": { ... },
    "storage_quota": { ... },
    "created_at": "2025-12-26T10:30:00Z",
    "updated_at": "2025-12-26T10:30:00Z"
  },
  "message": "tenant 'engineering' created successfully"
}
```

---

## Unix Socket API

Local IPC via `/run/platformd.sock`.

### Commands

| Command | Description |
|---------|-------------|
| tenant.list | List all tenants |
| tenant.get | Get tenant by ID |
| tenant.getByName | Get tenant by name |
| tenant.create | Create new tenant |
| tenant.update | Update tenant |
| tenant.delete | Delete tenant |
| tenant.suspend | Suspend tenant |
| tenant.resume | Resume tenant |
| tenant.getQuotas | Get quotas |
| tenant.updateQuotas | Update quotas |
| tenant.getUsage | Get usage |
| tenant.checkQuota | Check quota |
| tenant.sync | Synchronize state |
| tenant.rotateDEK | Rotate tenant DEK |
| tenant.getDEKStatus | Get DEK status |

### Wire Protocol

Uses the same opcodes as QUIC (0x10-0x1E) over Unix domain socket with MessagePack encoding.

### Request Types

**TenantListRequest:**
```go
type TenantListRequest struct {
    Limit  int `codec:"limit,omitempty" json:"limit,omitempty"`
    Offset int `codec:"offset,omitempty" json:"offset,omitempty"`
}
```

**TenantGetRequest:**
```go
type TenantGetRequest struct {
    TenantID string `codec:"tenant_id" json:"tenant_id"`
}
```

**TenantGetByNameRequest:**
```go
type TenantGetByNameRequest struct {
    Name string `codec:"name" json:"name"`
}
```

**TenantCreateRequest:**
```go
type TenantCreateRequest struct {
    Name        string            `codec:"name" json:"name"`
    DisplayName string            `codec:"display_name,omitempty" json:"display_name,omitempty"`
    Labels      map[string]string `codec:"labels,omitempty" json:"labels,omitempty"`
    Annotations map[string]string `codec:"annotations,omitempty" json:"annotations,omitempty"`
}
```

**TenantUpdateRequest:**
```go
type TenantUpdateRequest struct {
    TenantID    string            `codec:"tenant_id" json:"tenant_id"`
    DisplayName *string           `codec:"display_name,omitempty" json:"display_name,omitempty"`
    Labels      map[string]string `codec:"labels,omitempty" json:"labels,omitempty"`
    Annotations map[string]string `codec:"annotations,omitempty" json:"annotations,omitempty"`
}
```

**TenantCheckQuotaRequest:**
```go
type TenantCheckQuotaRequest struct {
    TenantID string `codec:"tenant_id" json:"tenant_id"`
    Resource string `codec:"resource" json:"resource"`
    Amount   int64  `codec:"amount" json:"amount"`
}
```

### CLI Usage

```bash
# List tenants
platformctl tenant list

# Get tenant
platformctl tenant get --id 550e8400-e29b-41d4-a716-446655440000
platformctl tenant get --name engineering

# Create tenant
platformctl tenant create \
  --name engineering \
  --display-name "Engineering Team" \

# Update tenant
platformctl tenant update \
  --id 550e8400-e29b-41d4-a716-446655440000 \
  --display-name "Engineering (Updated)"

# Delete tenant
platformctl tenant delete --id 550e8400-e29b-41d4-a716-446655440000

# Suspend/Resume
platformctl tenant suspend --id 550e8400-e29b-41d4-a716-446655440000
platformctl tenant resume --id 550e8400-e29b-41d4-a716-446655440000

# Quota operations
platformctl tenant quotas get --id 550e8400-e29b-41d4-a716-446655440000
platformctl tenant quotas update --id ... --max-vms 100 --max-containers 500
platformctl tenant usage --id 550e8400-e29b-41d4-a716-446655440000


# DEK operations
platformctl tenant dek rotate --id 550e8400-e29b-41d4-a716-446655440000
platformctl tenant dek rotate --id ... --background
platformctl tenant dek status --id 550e8400-e29b-41d4-a716-446655440000

# Sync
platformctl tenant sync
```

---

## Quota Types

### Compute Quotas

| Field | Type | Description |
|-------|------|-------------|
| max_vms | int64 | Maximum virtual machines |
| max_containers | int64 | Maximum containers |
| max_vcpus | int64 | Maximum vCPUs across all instances |
| max_memory_mb | int64 | Maximum memory in megabytes |
| max_disk_gb | int64 | Maximum disk space in gigabytes |

### Network Quotas

| Field | Type | Description |
|-------|------|-------------|
| max_bridges | int64 | Maximum OVS bridges |
| max_ports | int64 | Maximum network ports |
| max_bandwidth_mbps | int64 | Maximum bandwidth in Mbps |

### Storage Quotas

| Field | Type | Description |
|-------|------|-------------|
| max_volumes_gb | int64 | Maximum total volume storage in GB |
| max_snapshots | int64 | Maximum snapshots |

---

## Error Codes

| Error | HTTP | gRPC | Description |
|-------|------|------|-------------|
| ErrTenantNotFound | 404 | NOT_FOUND | Tenant does not exist |
| ErrTenantExists | 409 | ALREADY_EXISTS | Tenant name in use |
| ErrInvalidRequest | 400 | INVALID_ARGUMENT | Bad parameters |
| ErrInvalidState | 400 | FAILED_PRECONDITION | Invalid tenant state |
| ErrInvalidTransition | 409 | FAILED_PRECONDITION | Illegal state change |
| ErrQuotaExceeded | 403 | RESOURCE_EXHAUSTED | Quota limit reached |
| ErrResourceLimitReached | 403 | RESOURCE_EXHAUSTED | Resource limit hit |
| ErrDEKOperationFailed | 500 | INTERNAL | TPM DEK error |
| ErrStorageFailed | 500 | INTERNAL | Storage error |
| ErrBarrierNotSupported | 501 | UNIMPLEMENTED | Barrier client not configured (no SDK wired) |
| ErrNilBarrierStatus | 500 | INTERNAL | SDK returned nil status without error |

---

## Per-Tenant Barrier Lifecycle (2026-04-28)

Each tenant has an independent cryptographic barrier whose lifecycle is
exposed through `Manager` and routes to all five QRDB transports
(REST/gRPC/QUIC/MCP/Unix). Barriers auto-initialize on `CreateTenant` and
auto-seal on `DeleteTenant`.

### `Manager` API

| Method | Behavior |
|--------|----------|
| `Manager.InitTenantBarrier(ctx, tenantID)` | Initialize the per-tenant barrier (called automatically by `CreateTenant`; available for explicit re-init). |
| `Manager.UnsealTenantBarrier(ctx, tenantID, key)` | Unseal with the supplied key bytes. Empty key falls back to the deterministic init credential. |
| `Manager.SealTenantBarrier(ctx, tenantID)` | Seal the barrier. Subsequent reads/writes against the tenant namespace fail until unsealed. |
| `Manager.TenantBarrierStatus(ctx, tenantID)` | Returns `*TenantBarrierState{TenantID, Sealed, Initialized, Strategy, HardwareBacked}`. Uninitialized barriers report `Sealed=true, Initialized=false` rather than erroring. |

The wire path is `Manager → quicbaassdk.QRDBTenantClient → qrdb transport
(REST/gRPC/QUIC/MCP/Unix) → qrdb pkg/tenant.TenantService → BarrierRegistry`.
Empty `tenantID` returns `ErrInvalidRequest`; nil SDK client returns
`ErrBarrierNotSupported`; transport failures wrap into `ErrStorageFailed`.

### Platform multi-protocol surface

The platform exposes the same lifecycle through every protocol it ships:

| Protocol | Surface |
|----------|---------|
| **gRPC** | `platform.v1.TenantService/{InitTenantBarrier,UnsealTenantBarrier,SealTenantBarrier,GetTenantBarrierStatus}` |
| **REST** | `POST /api/v1/tenants/{id}/barrier/{init,unseal,seal}`, `GET /api/v1/tenants/{id}/barrier/status` |
| **QUIC** | Category opcode `OpTenantBarrierCategory` (`0x9E`) with sub-opcodes `Init=0x01`, `Unseal=0x02`, `Seal=0x03`, `Status=0x04` |
| **MCP** | Tools `platform_tenant_barrier_{init,unseal,seal,status}` |
| **Unix** | gRPC-over-UDS reuses `platform.v1.TenantService` |

### Platform SDK

`sdk/go/services/tenant/Client` exposes:

```go
InitTenantBarrier(ctx, tenantID, threshold, shares int32) error
UnsealTenantBarrier(ctx, tenantID string, key []byte) error
SealTenantBarrier(ctx, tenantID string) error
GetTenantBarrierStatus(ctx, tenantID string) (*platformv1.TenantBarrierStatus, error)
```

Errors returned: `ErrInitTenantBarrierFailed`, `ErrUnsealTenantBarrierFailed`, `ErrSealTenantBarrierFailed`, `ErrGetTenantBarrierStatusFailed` (all `Unwrap()`-able).

### CLI

```bash
# Explicit init (auto-init runs on CreateTenant; this is for re-init/Shamir)
platformctl tenant barrier init <tenant-name> [--threshold N --shares N]

# Unseal with a hex or base64 key (or empty for deterministic credential)
platformctl tenant barrier unseal <tenant-name> [--key-hex HEX | --key-base64 B64]

# Seal a previously initialized barrier
platformctl tenant barrier seal <tenant-name>

# Inspect status (also accepts -o json)
platformctl tenant barrier status <tenant-name>
```

All four subcommands route through the configured `--context` protocol — the same CLI binary works against REST/gRPC/QUIC/MCP/Unix/embedded modes.

### Daemon wiring

To make the REST + gRPC tenant surfaces reachable in production, set
`daemon.Config.PlatformTenantManager` to a `*tenant.Manager` when constructing
the daemon. `daemon.New()` automatically wires that instance into:

- `RESTServer.SetTenantHandlers(...)` — registers `/api/v1/tenants/*` routes
- `TenantGRPCServer.SetManager(...)` — fulfills the gRPC `TenantService`
  methods that require the platform manager (otherwise return
  `FailedPrecondition`)

A single `*tenant.Manager` instance is shared across REST, gRPC, QUIC, MCP,
and Unix-socket transports so per-tenant state (CRUD, quotas, DEK, barrier
lifecycle) is identical regardless of which transport
the caller chose.

`platformd serve` sets it in **both** modes, with and without webservices,
through `platformTenantManager` (`pkg/daemon/commands/serve_tenant.go`). It
builds the manager from the QuicBaaS SDK IAM tenant client. The manager is
IAM-only: DEK isolation and the VLAN, quota and bridge subsystems are off
until startup constructs them too (#721). Before #730, only the webservices
path set the manager. A daemon-only node then registered `TenantService` but
answered `FailedPrecondition` on every call.

The daemon registers **one** `TenantGRPCServer` on both the TCP and the
Unix-socket gRPC servers, so the manager `SetManager` installs serves both
listeners. Before #730, each registration built its own `TenantGRPCServer`.
The TCP listener then kept one that never received the manager.

IAM must be on for any of this to exist. `--skip-iam-validation` (testing
only) skips IAM, so it also skips `TenantService` registration.

---

## Related Documentation

- [Architecture](architecture.md) - Multi-tenancy design
- [Configuration](configuration.md) - Tenant configuration
- [CLI Usage](cli-usage.md) - Command-line interface
- [Isolation](isolation.md) - Network and data isolation

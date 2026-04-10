# IPAM REST API Reference

REST API endpoints for the IPAM service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/ipam` |
| Port | 8443 |
| Content-Type | `application/json` |

## Pool Endpoints

### ListPools

```http
GET /api/v1/sdn/ipam/pools
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tag` | string | Filter by tag |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "pools": [
    {
      "id": "prod-v4",
      "name": "Production IPv4",
      "cidr": "10.0.0.0/24",
      "gateway": "10.0.0.1",
      "description": "Internal production workloads",
      "tags": ["production", "internal"],
      "total_ips": 254,
      "allocated_ips": 50,
      "available_ips": 204,
      "default_lease_duration": "24h0m0s",
      "inactivity_timeout": "720h0m0s",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-19T10:00:00Z"
    },
    {
      "id": "prod-v6",
      "name": "Production IPv6",
      "cidr": "2602:F5BB:1234::/64",
      "gateway": "2602:F5BB:1234::1",
      "tags": ["production", "public"],
      "total_ips": 18446744073709551614,
      "allocated_ips": 100,
      "available_ips": 18446744073709551514,
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-19T10:00:00Z"
    }
  ],
  "total": 2,
  "limit": 100,
  "offset": 0
}
```

### GetPool

```http
GET /api/v1/sdn/ipam/pools/{pool_id}
```

**Response:**
```json
{
  "id": "prod-v4",
  "name": "Production IPv4",
  "cidr": "10.0.0.0/24",
  "gateway": "10.0.0.1",
  "description": "Internal production workloads",
  "tags": ["production", "internal"],
  "total_ips": 254,
  "allocated_ips": 50,
  "available_ips": 204,
  "default_lease_duration": "24h0m0s",
  "inactivity_timeout": "720h0m0s",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-19T10:00:00Z"
}
```

### GetPoolByName

```http
GET /api/v1/sdn/ipam/pools/by-name/{name}
```

**Response:** Same as GetPool

### GetPoolByCIDR

```http
GET /api/v1/sdn/ipam/pools/by-cidr
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cidr` | string | Yes | CIDR prefix (URL encoded) |

**Example:**
```http
GET /api/v1/sdn/ipam/pools/by-cidr?cidr=10.0.0.0%2F24
```

**Response:** Same as GetPool

### CreatePool

```http
POST /api/v1/sdn/ipam/pools
Content-Type: application/json
```

**Request:**
```json
{
  "id": "dev-v4",
  "name": "Development IPv4",
  "cidr": "192.168.100.0/24",
  "gateway": "192.168.100.1",
  "description": "Development environment",
  "tags": ["development"],
  "default_lease_duration": "1h",
  "inactivity_timeout": "24h"
}
```

**Response (201):**
```json
{
  "id": "dev-v4",
  "name": "Development IPv4",
  "cidr": "192.168.100.0/24",
  "gateway": "192.168.100.1",
  "description": "Development environment",
  "tags": ["development"],
  "total_ips": 254,
  "allocated_ips": 0,
  "available_ips": 254,
  "default_lease_duration": "1h0m0s",
  "inactivity_timeout": "24h0m0s",
  "created_at": "2026-01-19T10:30:00Z",
  "updated_at": "2026-01-19T10:30:00Z"
}
```

### UpdatePool

```http
PUT /api/v1/sdn/ipam/pools/{pool_id}
Content-Type: application/json
```

**Request:**
```json
{
  "name": "Development IPv4 (Updated)",
  "description": "Updated development environment",
  "tags": ["development", "updated"],
  "default_lease_duration": "2h",
  "inactivity_timeout": "48h"
}
```

**Note:** CIDR cannot be changed after pool creation.

**Response:** Same as GetPool

### DeletePool

```http
DELETE /api/v1/sdn/ipam/pools/{pool_id}
```

**Response:**
```json
{
  "deleted": true,
  "pool_id": "dev-v4"
}
```

**Error (409 - has allocations):**
```json
{
  "error": "pool_has_allocations",
  "message": "Pool has 5 active allocations and cannot be deleted",
  "details": {
    "pool_id": "dev-v4",
    "active_allocations": 5
  }
}
```

### GetPoolStats

```http
GET /api/v1/sdn/ipam/pools/{pool_id}/stats
```

**Response:**
```json
{
  "pool_id": "prod-v4",
  "total_ips": 254,
  "allocated_ips": 50,
  "available_ips": 200,
  "expired_ips": 2,
  "reserved_ips": 2,
  "utilization_pct": 19.69
}
```

## Allocation Endpoints

### Allocate

```http
POST /api/v1/sdn/ipam/allocate
Content-Type: application/json
```

**Request:**
```json
{
  "pool_id": "prod-v4",
  "device_id": "vm-001",
  "hostname": "webserver",
  "description": "Primary web server",
  "tags": ["web", "frontend"],
  "metadata": {
    "environment": "production",
    "owner": "platform-team"
  },
  "lease_duration": "48h"
}
```

**Response (201):**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "pool_id": "prod-v4",
  "ip": "10.0.0.2",
  "device_id": "vm-001",
  "hostname": "webserver",
  "description": "Primary web server",
  "tags": ["web", "frontend"],
  "metadata": {
    "environment": "production",
    "owner": "platform-team"
  },
  "status": "active",
  "allocated_at": "2026-01-19T10:30:00Z",
  "last_seen": "2026-01-19T10:30:00Z",
  "expires_at": "2026-01-21T10:30:00Z"
}
```

### AllocateSpecific

```http
POST /api/v1/sdn/ipam/allocate/specific
Content-Type: application/json
```

**Request:**
```json
{
  "pool_id": "prod-v4",
  "device_id": "db-001",
  "hostname": "database",
  "requested_ip": "10.0.0.100",
  "description": "Primary database server"
}
```

**Response (201):** Same as Allocate

**Error (409 - already allocated):**
```json
{
  "error": "ip_already_allocated",
  "message": "IP 10.0.0.100 is already allocated to device vm-002",
  "details": {
    "ip": "10.0.0.100",
    "current_device_id": "vm-002",
    "current_hostname": "other-server"
  }
}
```

### Release

```http
POST /api/v1/sdn/ipam/release
Content-Type: application/json
```

**Request:**
```json
{
  "ip": "10.0.0.50"
}
```

**Response:**
```json
{
  "released": true,
  "ip": "10.0.0.50",
  "pool_id": "prod-v4",
  "device_id": "vm-001"
}
```

### ReleaseByDeviceID

```http
POST /api/v1/sdn/ipam/release/device/{device_id}
```

**Response:**
```json
{
  "device_id": "vm-001",
  "released_count": 3,
  "released_ips": [
    "10.0.0.50",
    "10.0.0.51",
    "192.168.100.10"
  ]
}
```

### GetAllocation

```http
GET /api/v1/sdn/ipam/allocations/{ip}
```

**Example:**
```http
GET /api/v1/sdn/ipam/allocations/10.0.0.50
```

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "pool_id": "prod-v4",
  "ip": "10.0.0.50",
  "device_id": "vm-001",
  "hostname": "webserver",
  "description": "Primary web server",
  "tags": ["web", "frontend"],
  "metadata": {
    "environment": "production"
  },
  "status": "active",
  "allocated_at": "2026-01-19T10:30:00Z",
  "last_seen": "2026-01-19T10:45:00Z",
  "expires_at": "2026-01-21T10:30:00Z"
}
```

### ListAllocationsByPool

```http
GET /api/v1/sdn/ipam/pools/{pool_id}/allocations
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status (active, expired, released, reserved) |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "allocations": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "pool_id": "prod-v4",
      "ip": "10.0.0.50",
      "device_id": "vm-001",
      "hostname": "webserver",
      "status": "active",
      "allocated_at": "2026-01-19T10:30:00Z",
      "last_seen": "2026-01-19T10:45:00Z",
      "expires_at": "2026-01-21T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### ListAllocationsByDevice

```http
GET /api/v1/sdn/ipam/devices/{device_id}/allocations
```

**Response:** Same format as ListAllocationsByPool

## Lease Endpoints

### Renew

```http
POST /api/v1/sdn/ipam/renew
Content-Type: application/json
```

**Request:**
```json
{
  "ip": "10.0.0.50"
}
```

**Response:**
```json
{
  "ip": "10.0.0.50",
  "renewed": true,
  "last_seen": "2026-01-19T11:00:00Z",
  "expires_at": "2026-01-21T11:00:00Z"
}
```

### ExpireInactive

```http
POST /api/v1/sdn/ipam/pools/{pool_id}/expire-inactive
```

**Response:**
```json
{
  "pool_id": "prod-v4",
  "expired_count": 2,
  "expired_allocations": [
    {
      "ip": "10.0.0.60",
      "device_id": "vm-old-001",
      "last_seen": "2025-12-01T00:00:00Z"
    },
    {
      "ip": "10.0.0.61",
      "device_id": "vm-old-002",
      "last_seen": "2025-12-15T00:00:00Z"
    }
  ]
}
```

## Reservation Endpoints

### Reserve

```http
POST /api/v1/sdn/ipam/reserve
Content-Type: application/json
```

**Request:**
```json
{
  "pool_id": "prod-v4",
  "ip": "10.0.0.200",
  "description": "Reserved for future load balancer"
}
```

**Response (201):**
```json
{
  "id": "b2c3d4e5-f678-9012-bcde-f12345678901",
  "pool_id": "prod-v4",
  "ip": "10.0.0.200",
  "device_id": "reserved",
  "description": "Reserved for future load balancer",
  "status": "reserved",
  "allocated_at": "2026-01-19T11:00:00Z"
}
```

### Unreserve

```http
POST /api/v1/sdn/ipam/unreserve
Content-Type: application/json
```

**Request:**
```json
{
  "ip": "10.0.0.200"
}
```

**Response:**
```json
{
  "ip": "10.0.0.200",
  "unreserved": true,
  "pool_id": "prod-v4"
}
```

### ListReservations

```http
GET /api/v1/sdn/ipam/pools/{pool_id}/reservations
```

**Response:**
```json
{
  "reservations": [
    {
      "id": "b2c3d4e5-f678-9012-bcde-f12345678901",
      "pool_id": "prod-v4",
      "ip": "10.0.0.200",
      "description": "Reserved for future load balancer",
      "status": "reserved",
      "allocated_at": "2026-01-19T11:00:00Z"
    }
  ],
  "total": 1
}
```

## Batch Endpoints

### AllocateBatch

```http
POST /api/v1/sdn/ipam/allocate/batch
Content-Type: application/json
```

**Request:**
```json
{
  "requests": [
    {
      "pool_id": "prod-v4",
      "device_id": "vm-001",
      "hostname": "web-001"
    },
    {
      "pool_id": "prod-v4",
      "device_id": "vm-002",
      "hostname": "web-002"
    },
    {
      "pool_id": "prod-v4",
      "device_id": "vm-003",
      "hostname": "web-003"
    }
  ]
}
```

**Response (201):**
```json
{
  "allocations": [
    {
      "id": "...",
      "ip": "10.0.0.2",
      "device_id": "vm-001",
      "status": "active"
    },
    {
      "id": "...",
      "ip": "10.0.0.3",
      "device_id": "vm-002",
      "status": "active"
    },
    {
      "id": "...",
      "ip": "10.0.0.4",
      "device_id": "vm-003",
      "status": "active"
    }
  ],
  "total_requested": 3,
  "total_allocated": 3
}
```

### ReleaseBatch

```http
POST /api/v1/sdn/ipam/release/batch
Content-Type: application/json
```

**Request:**
```json
{
  "ips": [
    "10.0.0.2",
    "10.0.0.3",
    "10.0.0.4"
  ]
}
```

**Response:**
```json
{
  "total_requested": 3,
  "total_released": 3,
  "released_ips": [
    "10.0.0.2",
    "10.0.0.3",
    "10.0.0.4"
  ],
  "failed_ips": []
}
```

## Error Responses

### Standard Error Format

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {
    "field": "value"
  }
}
```

### HTTP Status Codes

| Status | Description |
|--------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 409 | Conflict (already exists, in use) |
| 410 | Gone (expired) |
| 429 | Rate limited |
| 500 | Server error |
| 503 | Backend unavailable |
| 507 | Pool exhausted |

## Rate Limiting

| Endpoint Type | Requests/Min |
|---------------|--------------|
| Pool read | 200 |
| Pool write | 30 |
| Allocation read | 500 |
| Allocation write | 100 |
| Batch operations | 10 |

Headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## curl Examples

```bash
# List pools
curl -X GET https://platform.example.com/api/v1/sdn/ipam/pools \
  --cert client.crt --key client.key --cacert ca.crt

# Create pool
curl -X POST https://platform.example.com/api/v1/sdn/ipam/pools \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-pool",
    "name": "Test Pool",
    "cidr": "203.0.113.0/24",
    "gateway": "203.0.113.1"
  }'

# Allocate IP
curl -X POST https://platform.example.com/api/v1/sdn/ipam/allocate \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "pool_id": "prod-v4",
    "device_id": "my-device",
    "hostname": "myserver"
  }'

# Get allocation
curl -X GET https://platform.example.com/api/v1/sdn/ipam/allocations/10.0.0.50 \
  --cert client.crt --key client.key --cacert ca.crt

# Release IP
curl -X POST https://platform.example.com/api/v1/sdn/ipam/release \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.50"}'

# Renew lease
curl -X POST https://platform.example.com/api/v1/sdn/ipam/renew \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.50"}'

# Get pool stats
curl -X GET https://platform.example.com/api/v1/sdn/ipam/pools/prod-v4/stats \
  --cert client.crt --key client.key --cacert ca.crt

# Reserve IP
curl -X POST https://platform.example.com/api/v1/sdn/ipam/reserve \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "pool_id": "prod-v4",
    "ip": "10.0.0.200",
    "description": "Reserved for load balancer"
  }'

# List allocations by device
curl -X GET https://platform.example.com/api/v1/sdn/ipam/devices/vm-001/allocations \
  --cert client.crt --key client.key --cacert ca.crt
```

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [API Overview](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)

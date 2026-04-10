# IPAM API Reference

## Overview

The IPAM service exposes APIs via multiple protocols for maximum interoperability. All protocols provide feature parity for core IPAM operations.

## Supported Protocols

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTPS | 8443 | Web clients, external integrations |
| gRPC | TCP | 10443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTP | 9445 | AI/LLM integration |
| Unix | Unix Socket | /run/platformd.sock | Local IPC, CLI |

## API Categories

### Pool Management

Operations for managing IP address pools:

| Operation | Description |
|-----------|-------------|
| CreatePool | Create a new IP pool |
| GetPool | Get pool by ID |
| GetPoolByName | Get pool by name |
| GetPoolByCIDR | Get pool by CIDR |
| ListPools | List all pools |
| UpdatePool | Update pool configuration |
| DeletePool | Delete a pool |
| GetPoolStats | Get pool statistics |

### Allocation Operations

Operations for IP address allocation:

| Operation | Description |
|-----------|-------------|
| Allocate | Allocate next available IP |
| AllocateSpecific | Allocate a specific IP |
| Release | Release an allocation |
| ReleaseByDeviceID | Release all allocations for a device |

### Lease Management

Operations for managing allocation leases:

| Operation | Description |
|-----------|-------------|
| Renew | Renew an allocation lease |
| GetAllocation | Get allocation by IP |
| GetAllocationsByDevice | Get all allocations for a device |
| GetAllocationsByPool | Get all allocations in a pool |
| ExpireInactive | Expire inactive allocations |

### Reservation Operations

Operations for IP reservations (where supported):

| Operation | Description |
|-----------|-------------|
| Reserve | Reserve an IP address |
| Unreserve | Remove a reservation |
| ListReservations | List pool reservations |

### Batch Operations

Bulk operations (where supported):

| Operation | Description |
|-----------|-------------|
| AllocateBatch | Allocate multiple IPs |
| ReleaseBatch | Release multiple IPs |

## Protocol-Specific Documentation

### REST API

RESTful HTTP/HTTPS API for web clients and external systems.

- **Base Path**: `/api/v1/sdn/ipam`
- **Port**: 8443 (HTTPS)
- **Content-Type**: `application/json`
- **Authentication**: mTLS client certificates

[REST API Reference](api-reference-rest.md)

### gRPC API

High-performance RPC for service-to-service communication.

- **Package**: `platform.sdn.ipam.v1`
- **Port**: 10443
- **Protocol**: HTTP/2 + Protobuf
- **Authentication**: mTLS

[gRPC API Reference](api-reference-grpc.md)

### QUIC API

Low-latency API for mobile and IoT clients.

- **Port**: 9444 (UDP)
- **Protocol**: QUIC + Protobuf
- **Authentication**: mTLS

### MCP API

Model Context Protocol for AI/LLM integration.

- **Port**: 9445
- **Protocol**: JSON-RPC 2.0
- **Transport**: stdio or HTTP

### Unix Socket API

Local IPC for CLI and same-host services.

- **Path**: `/run/platformd.sock`
- **Protocol**: HTTP/1.1 + JSON

## Common Data Types

### Pool

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
  "default_lease_duration": "24h",
  "inactivity_timeout": "720h",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-19T10:00:00Z"
}
```

### Allocation

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
    "environment": "production",
    "owner": "platform-team"
  },
  "status": "active",
  "allocated_at": "2026-01-19T10:00:00Z",
  "last_seen": "2026-01-19T10:30:00Z",
  "expires_at": "2026-01-20T10:00:00Z"
}
```

### AllocationRequest

```json
{
  "pool_id": "prod-v4",
  "device_id": "vm-001",
  "hostname": "webserver",
  "description": "Primary web server",
  "tags": ["web", "frontend"],
  "metadata": {
    "environment": "production"
  },
  "requested_ip": "10.0.0.100",
  "lease_duration": "48h"
}
```

### PoolStats

```json
{
  "pool_id": "prod-v4",
  "total_ips": 254,
  "allocated_ips": 50,
  "available_ips": 200,
  "expired_ips": 2,
  "reserved_ips": 2,
  "utilization_pct": 19.7
}
```

### AllocationStatus

| Status | Description |
|--------|-------------|
| `active` | Currently in use |
| `expired` | Lease expired or inactive too long |
| `released` | Explicitly released by device |
| `reserved` | Reserved, cannot be auto-allocated |

## Error Codes

### Common Errors

| Error | HTTP | Description |
|-------|------|-------------|
| `pool_not_found` | 404 | Pool does not exist |
| `pool_already_exists` | 409 | Pool ID or name conflict |
| `pool_exhausted` | 507 | No available IPs in pool |
| `pool_cidr_overlaps` | 409 | CIDR overlaps existing pool |
| `pool_has_allocations` | 409 | Cannot delete pool with active allocations |
| `allocation_not_found` | 404 | Allocation does not exist |
| `ip_already_allocated` | 409 | IP is already allocated |
| `ip_not_in_pool` | 400 | IP is not within pool CIDR |
| `invalid_cidr` | 400 | Invalid CIDR format |
| `invalid_ip` | 400 | Invalid IP address |
| `invalid_pool_id` | 400 | Empty or invalid pool ID |
| `device_id_required` | 400 | Device ID not provided |
| `allocation_expired` | 410 | Allocation has expired |
| `backend_unavailable` | 503 | Storage backend unavailable |

### Error Response Format

```json
{
  "error": "ip_already_allocated",
  "message": "IP 10.0.0.50 is already allocated to device vm-002",
  "details": {
    "ip": "10.0.0.50",
    "current_device_id": "vm-002",
    "current_hostname": "database"
  }
}
```

## Authentication

All API protocols require mTLS authentication with platform-issued client certificates.

### Certificate Requirements

| Field | Requirement |
|-------|-------------|
| Subject CN | Device or service identity |
| Key Usage | Digital Signature, Client Auth |
| Extended Key Usage | TLS Client Authentication |
| Issuer | Platform CA |

### Authorization

Operations are authorized based on certificate attributes:

| Attribute | Use |
|-----------|-----|
| `O` (Organization) | Tenant identification |
| `OU` (Organizational Unit) | Role/permission scoping |
| `CN` (Common Name) | Device identity |
| SAN extensions | Additional identities |

## Rate Limiting

| Operation Type | Requests/Min |
|----------------|--------------|
| Pool read | 200 |
| Pool write | 30 |
| Allocation read | 500 |
| Allocation write | 100 |
| Batch operations | 10 |

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Reset timestamp

## Pagination

List operations support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Maximum results |
| `offset` | int | 0 | Skip count |
| `page_token` | string | - | Cursor token (gRPC) |

Response includes:
- `total`: Total matching items
- `limit`: Applied limit
- `offset`: Applied offset
- `next_page_token`: Token for next page (gRPC)

## Versioning

APIs are versioned using URL path (REST) or package name (gRPC):

- REST: `/api/v1/sdn/ipam/...`
- gRPC: `platform.sdn.ipam.v1`

Version deprecation follows semantic versioning with minimum 6-month deprecation notice.

## See Also

- [REST API Reference](api-reference-rest.md) - REST endpoint details
- [gRPC API Reference](api-reference-grpc.md) - gRPC service methods
- [Configuration](configuration.md) - IPAM configuration
- [Architecture](architecture.md) - Technical architecture

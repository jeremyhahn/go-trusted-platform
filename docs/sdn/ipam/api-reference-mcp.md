# IPAM MCP API Reference

Model Context Protocol (MCP) interface for AI/LLM integration with the IPAM service.

| Property | Value |
|----------|-------|
| Service | `ipam` |
| Transport | stdio or HTTP |
| Port (HTTP) | 9445 |
| Protocol | MCP v1.0 |

## Overview

The MCP interface enables AI assistants and LLMs to interact with IPAM through:

- **Tools** - Actions to manage pools, allocations, and reservations
- **Resources** - Data about IP address usage and availability

## Connection Setup

### stdio Transport

```json
{
  "mcpServers": {
    "ipam": {
      "command": "platformctl",
      "args": ["mcp", "ipam", "serve"],
      "env": {
        "PLATFORM_CONFIG": "/etc/platform/config.yaml"
      }
    }
  }
}
```

### HTTP Transport

```json
{
  "mcpServers": {
    "ipam": {
      "url": "https://platform.example.com:9445/mcp/ipam",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  }
}
```

## Available Tools

### Pool Management Tools

#### ipam_pool_list

List all IP address pools.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| tag | string | No | Filter by tag |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "ipam_pool_list",
  "arguments": {
    "tag": "production"
  }
}
```

**Response:**
```json
{
  "pools": [
    {
      "id": "prod-v4",
      "name": "Production IPv4",
      "cidr": "10.0.0.0/24",
      "gateway": "10.0.0.1",
      "total_ips": 254,
      "allocated_ips": 50,
      "available_ips": 204
    }
  ],
  "total": 1
}
```

#### ipam_pool_get

Get pool details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

#### ipam_pool_create

Create a new IP address pool.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Pool identifier |
| name | string | Yes | Pool name |
| cidr | string | Yes | CIDR notation |
| gateway | string | No | Gateway address |
| description | string | No | Pool description |
| tags | array | No | Pool tags |
| default_lease_duration | string | No | Default lease (e.g., "24h") |

**Example:**
```json
{
  "name": "ipam_pool_create",
  "arguments": {
    "id": "dev-v4",
    "name": "Development IPv4",
    "cidr": "192.168.100.0/24",
    "gateway": "192.168.100.1",
    "tags": ["development"],
    "default_lease_duration": "1h"
  }
}
```

#### ipam_pool_delete

Delete a pool.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

#### ipam_pool_stats

Get pool statistics.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

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

### Allocation Tools

#### ipam_allocate

Allocate an IP address from a pool.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |
| device_id | string | Yes | Device identifier |
| hostname | string | No | Hostname |
| description | string | No | Description |
| tags | array | No | Tags |
| lease_duration | string | No | Lease duration |

**Example:**
```json
{
  "name": "ipam_allocate",
  "arguments": {
    "pool_id": "prod-v4",
    "device_id": "vm-001",
    "hostname": "webserver",
    "lease_duration": "48h"
  }
}
```

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "pool_id": "prod-v4",
  "ip": "10.0.0.2",
  "device_id": "vm-001",
  "hostname": "webserver",
  "status": "active",
  "expires_at": "2026-01-21T10:30:00Z"
}
```

#### ipam_allocate_specific

Allocate a specific IP address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |
| device_id | string | Yes | Device identifier |
| ip | string | Yes | Specific IP to allocate |
| hostname | string | No | Hostname |

**Example:**
```json
{
  "name": "ipam_allocate_specific",
  "arguments": {
    "pool_id": "prod-v4",
    "device_id": "db-001",
    "ip": "10.0.0.100",
    "hostname": "database"
  }
}
```

#### ipam_release

Release an IP allocation.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IP address to release |

#### ipam_release_device

Release all IPs for a device.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device identifier |

#### ipam_allocation_get

Get allocation details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IP address |

#### ipam_allocations_list

List allocations.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | No | Filter by pool |
| device_id | string | No | Filter by device |
| status | string | No | Filter by status |
| limit | integer | No | Maximum results |

### Lease Tools

#### ipam_renew

Renew an IP lease.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IP address |

**Response:**
```json
{
  "ip": "10.0.0.50",
  "renewed": true,
  "last_seen": "2026-01-19T11:00:00Z",
  "expires_at": "2026-01-21T11:00:00Z"
}
```

#### ipam_expire_inactive

Expire inactive allocations.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

### Reservation Tools

#### ipam_reserve

Reserve an IP address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |
| ip | string | Yes | IP to reserve |
| description | string | No | Reservation description |

**Example:**
```json
{
  "name": "ipam_reserve",
  "arguments": {
    "pool_id": "prod-v4",
    "ip": "10.0.0.200",
    "description": "Reserved for future load balancer"
  }
}
```

#### ipam_unreserve

Remove a reservation.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IP address |

#### ipam_reservations_list

List reservations.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

### Batch Tools

#### ipam_allocate_batch

Allocate multiple IPs.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| requests | array | Yes | Array of allocation requests |

**Example:**
```json
{
  "name": "ipam_allocate_batch",
  "arguments": {
    "requests": [
      {"pool_id": "prod-v4", "device_id": "vm-001", "hostname": "web-001"},
      {"pool_id": "prod-v4", "device_id": "vm-002", "hostname": "web-002"},
      {"pool_id": "prod-v4", "device_id": "vm-003", "hostname": "web-003"}
    ]
  }
}
```

#### ipam_release_batch

Release multiple IPs.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ips | array | Yes | Array of IP addresses |

## Available Resources

### ipam://pools

List of all pools.

**URI:** `ipam://pools`

### ipam://pools/{pool_id}

Pool details.

**URI:** `ipam://pools/prod-v4`

### ipam://pools/{pool_id}/stats

Pool statistics.

**URI:** `ipam://pools/prod-v4/stats`

### ipam://pools/{pool_id}/allocations

Pool allocations.

**URI:** `ipam://pools/prod-v4/allocations`

### ipam://pools/{pool_id}/reservations

Pool reservations.

**URI:** `ipam://pools/prod-v4/reservations`

### ipam://allocations/{ip}

Allocation details.

**URI:** `ipam://allocations/10.0.0.50`

### ipam://devices/{device_id}/allocations

Device allocations.

**URI:** `ipam://devices/vm-001/allocations`

### ipam://status

IPAM service status.

**URI:** `ipam://status`

## Example AI Interactions

### Capacity Planning

```
User: "How much IP space do we have left in production?"

AI reads:
1. ipam://pools (filter by production tag)
2. ipam://pools/prod-v4/stats

AI Response: "Production IP capacity:
- prod-v4 (10.0.0.0/24): 19.7% used (50/254)
- prod-v6 (2602:F5BB:1234::/64): <0.01% used (100/18 quintillion)

You have 204 IPv4 addresses available. At current growth rate
of 5 allocations per day, IPv4 will be exhausted in ~41 days.
Consider planning for additional IPv4 space or migrating
workloads to IPv6."
```

### IP Conflict Investigation

```
User: "Device vm-005 reports IP conflict on 10.0.0.50"

AI uses:
1. ipam_allocation_get(ip="10.0.0.50")
2. ipam_allocations_list(pool_id="prod-v4")

AI Response: "IP 10.0.0.50 is allocated to device vm-002 (hostname:
appserver) since 2026-01-15. The lease is active and was last
renewed 2 hours ago.

Device vm-005 should not have this IP. Possible causes:
1. Static IP configuration outside IPAM
2. DHCP misconfiguration
3. Stale ARP cache

Recommend removing static configuration from vm-005 and using
IPAM allocation."
```

### Bulk Provisioning

```
User: "I need 10 IPs for new web cluster"

AI uses:
1. ipam_pool_stats(pool_id="prod-v4") - Check availability
2. ipam_allocate_batch with 10 requests

AI Response: "Allocated 10 IPs for web cluster:
- 10.0.0.51 -> web-cluster-001
- 10.0.0.52 -> web-cluster-002
- 10.0.0.53 -> web-cluster-003
- 10.0.0.54 -> web-cluster-004
- 10.0.0.55 -> web-cluster-005
- 10.0.0.56 -> web-cluster-006
- 10.0.0.57 -> web-cluster-007
- 10.0.0.58 -> web-cluster-008
- 10.0.0.59 -> web-cluster-009
- 10.0.0.60 -> web-cluster-010

All leases set to 48 hours. Pool utilization now at 23.6%."
```

### Cleanup Stale Allocations

```
User: "Clean up expired leases in the dev pool"

AI uses:
1. ipam_pool_stats(pool_id="dev-v4")
2. ipam_expire_inactive(pool_id="dev-v4")

AI Response: "Expired 15 inactive allocations from dev-v4:
- 192.168.100.10 (test-vm-001) - inactive 45 days
- 192.168.100.11 (test-vm-002) - inactive 32 days
- 192.168.100.12 (demo-server) - inactive 28 days
... (12 more)

Recovered 15 IP addresses. Pool now has 239 available IPs
(94.1% available)."
```

## Error Handling

```json
{
  "error": {
    "code": "pool_exhausted",
    "message": "Pool 'prod-v4' has no available IP addresses",
    "details": {
      "pool_id": "prod-v4",
      "total": 254,
      "allocated": 254
    }
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `pool_not_found` | Pool does not exist |
| `allocation_not_found` | Allocation not found |
| `ip_already_allocated` | IP is already in use |
| `pool_exhausted` | No available IPs in pool |
| `pool_has_allocations` | Cannot delete pool with active allocations |
| `invalid_cidr` | Invalid CIDR notation |
| `ip_outside_pool` | Requested IP is not in pool range |
| `lease_expired` | Lease has expired |

## Security

- All operations require authentication
- Pool creation/deletion may require admin privileges
- Operations are logged for audit
- Rate limiting applies

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)


## Gateway Pool CRUD Tools (Z5b)

| Tool | Arguments | Description |
|------|-----------|-------------|
| `gateway_ipam_pool_create` | `name` (req), `cidr` (req), `id`?, `gateway`?, `zone`?, `description`?, `lease_duration_seconds`? | Create a new pool |
| `gateway_ipam_pool_get` | `pool_id` (req) | Retrieve a pool by ID |
| `gateway_ipam_pool_update` | `pool_id` (req), `name`?, `gateway`?, `zone`?, `description`?, `lease_duration_seconds`? | Update mutable pool fields |
| `gateway_ipam_pool_delete` | `pool_id` (req) | Delete a pool (fails if active allocations exist) |
| `gateway_ipam_pools` | `zone`? | List pools, optional zone filter |

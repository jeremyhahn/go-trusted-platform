# Gateway REST API Reference

REST API endpoints for the gateway service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/gateway` |
| Port | 8443 |
| Content-Type | `application/json` |

## Gateway Registration Endpoints

### ListGateways

```http
GET /api/v1/sdn/gateway/gateways
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | string | Filter by mode (active, standby, maintenance) |
| `region` | string | Filter by region |
| `healthy` | bool | Filter by health status |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "gateways": [
    {
      "id": "gw-001",
      "node_id": "node-001",
      "region": "us-east-1",
      "mode": "active",
      "ipv6_prefix": "2602:F5BB:0001::/48",
      "ipv4_address": "23.143.36.1",
      "vtep_ip": "10.0.0.1",
      "healthy": true,
      "last_heartbeat": "2026-01-18T10:30:00Z",
      "uptime_seconds": 86400,
      "connections": {
        "active": 1500,
        "total": 50000
      },
      "capabilities": ["ipv6", "ipv4", "nat64", "load_balancer"]
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetGateway

```http
GET /api/v1/sdn/gateway/gateways/{id}
```

**Response:**
```json
{
  "id": "gw-001",
  "node_id": "node-001",
  "region": "us-east-1",
  "mode": "active",
  "ipv6_prefix": "2602:F5BB:0001::/48",
  "ipv4_address": "23.143.36.1",
  "vtep_ip": "10.0.0.1",
  "healthy": true,
  "last_heartbeat": "2026-01-18T10:30:00Z",
  "uptime_seconds": 86400,
  "connections": {
    "active": 1500,
    "total": 50000
  },
  "capabilities": ["ipv6", "ipv4", "nat64", "load_balancer"],
  "config": {
    "max_connections": 10000,
    "connection_timeout_seconds": 300,
    "nat64_enabled": true,
    "nat64_prefix": "64:ff9b::/96"
  },
  "statistics": {
    "bytes_in": 1073741824,
    "bytes_out": 2147483648,
    "packets_in": 10000000,
    "packets_out": 15000000,
    "errors": 50
  }
}
```

### RegisterGateway

```http
POST /api/v1/sdn/gateway/gateways
Content-Type: application/json
```

**Request:**
```json
{
  "region": "us-east-1",
  "ipv6_prefix": "2602:F5BB:0001::/48",
  "ipv4_address": "23.143.36.1",
  "vtep_ip": "10.0.0.1",
  "capabilities": ["ipv6", "ipv4", "nat64", "load_balancer"],
  "config": {
    "max_connections": 10000,
    "connection_timeout_seconds": 300,
    "nat64_enabled": true
  }
}
```

**Response (201):**
```json
{
  "id": "gw-001",
  "node_id": "node-001",
  "region": "us-east-1",
  "mode": "standby",
  "ipv6_prefix": "2602:F5BB:0001::/48",
  "ipv4_address": "23.143.36.1",
  "vtep_ip": "10.0.0.1",
  "healthy": true,
  "last_heartbeat": "2026-01-18T10:30:00Z"
}
```

### DeregisterGateway

```http
DELETE /api/v1/sdn/gateway/gateways/{id}
```

**Response:**
```json
{
  "deleted": true,
  "gateway_id": "gw-001"
}
```

### UpdateGateway

```http
PUT /api/v1/sdn/gateway/gateways/{id}
Content-Type: application/json
```

**Request:**
```json
{
  "config": {
    "max_connections": 20000
  }
}
```

## Gateway Mode Endpoints

### SetGatewayMode

```http
POST /api/v1/sdn/gateway/gateways/{id}/mode
Content-Type: application/json
```

**Request:**
```json
{
  "mode": "active"
}
```

**Response:**
```json
{
  "id": "gw-001",
  "previous_mode": "standby",
  "mode": "active",
  "transition_time": "2026-01-18T10:30:00Z"
}
```

### PromoteGateway

```http
POST /api/v1/sdn/gateway/gateways/{id}/promote
```

Promotes a standby gateway to active mode.

**Response:**
```json
{
  "id": "gw-001",
  "mode": "active",
  "promoted_at": "2026-01-18T10:30:00Z",
  "demoted_gateway": "gw-002"
}
```

### DemoteGateway

```http
POST /api/v1/sdn/gateway/gateways/{id}/demote
```

Demotes an active gateway to standby mode.

**Response:**
```json
{
  "id": "gw-001",
  "mode": "standby",
  "demoted_at": "2026-01-18T10:30:00Z"
}
```

## Health Endpoints

### GetGatewayHealth

```http
GET /api/v1/sdn/gateway/gateways/{id}/health
```

**Response:**
```json
{
  "id": "gw-001",
  "healthy": true,
  "checks": [
    {
      "name": "bgp_session",
      "status": "healthy",
      "message": "All BGP peers established",
      "last_check": "2026-01-18T10:29:55Z"
    },
    {
      "name": "vtep_connectivity",
      "status": "healthy",
      "message": "VTEP reachable",
      "last_check": "2026-01-18T10:29:55Z"
    },
    {
      "name": "ipv6_routing",
      "status": "healthy",
      "message": "IPv6 routes announced",
      "last_check": "2026-01-18T10:29:55Z"
    },
    {
      "name": "load_balancer",
      "status": "healthy",
      "message": "All backends healthy",
      "last_check": "2026-01-18T10:29:55Z"
    }
  ],
  "uptime_seconds": 86400,
  "last_failure": null
}
```

### Heartbeat

```http
POST /api/v1/sdn/gateway/gateways/{id}/heartbeat
```

**Response:**
```json
{
  "id": "gw-001",
  "acknowledged": true,
  "timestamp": "2026-01-18T10:30:00Z"
}
```

## IPv6 Allocation Endpoints

### AllocateIPv6

```http
POST /api/v1/sdn/gateway/ipv6/allocate
Content-Type: application/json
```

**Request:**
```json
{
  "device_id": "device-001",
  "prefix_length": 128,
  "vni": 1000100,
  "metadata": {
    "owner": "tenant-a",
    "purpose": "vm-network"
  }
}
```

**Response (201):**
```json
{
  "address": "2602:F5BB:0001:0100::1",
  "prefix_length": 128,
  "device_id": "device-001",
  "gateway_id": "gw-001",
  "vni": 1000100,
  "allocated_at": "2026-01-18T10:30:00Z",
  "expires_at": null
}
```

### ReleaseIPv6

```http
DELETE /api/v1/sdn/gateway/ipv6/{address}
```

**Response:**
```json
{
  "released": true,
  "address": "2602:F5BB:0001:0100::1"
}
```

### ListIPv6Allocations

```http
GET /api/v1/sdn/gateway/ipv6/allocations
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `device_id` | string | Filter by device |
| `vni` | int | Filter by VNI |
| `gateway_id` | string | Filter by gateway |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "allocations": [
    {
      "address": "2602:F5BB:0001:0100::1",
      "prefix_length": 128,
      "device_id": "device-001",
      "gateway_id": "gw-001",
      "vni": 1000100,
      "allocated_at": "2026-01-18T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetIPv6Pools

```http
GET /api/v1/sdn/gateway/ipv6/pools
```

**Response:**
```json
{
  "pools": [
    {
      "prefix": "2602:F5BB:0001::/48",
      "gateway_id": "gw-001",
      "total_addresses": 65536,
      "allocated": 1500,
      "available": 64036,
      "utilization_percent": 2.3
    }
  ]
}
```

## Device Onboarding Endpoints

### OnboardDevice

```http
POST /api/v1/sdn/gateway/devices/onboard
Content-Type: application/json
```

**Request:**
```json
{
  "device_id": "device-001",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "vlan_id": 100,
  "profile": "standard-workstation",
  "certificate_cn": "device-001.example.internal"
}
```

**Response (201):**
```json
{
  "device_id": "device-001",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "vlan_id": 100,
  "vni": 1000100,
  "ipv6_address": "2602:F5BB:0001:0100::10",
  "gateway_id": "gw-001",
  "onboarded_at": "2026-01-18T10:30:00Z",
  "state": "provisioned"
}
```

### OffboardDevice

```http
POST /api/v1/sdn/gateway/devices/{device_id}/offboard
```

**Response:**
```json
{
  "device_id": "device-001",
  "offboarded": true,
  "resources_released": {
    "ipv6_address": "2602:F5BB:0001:0100::10",
    "vni": 1000100
  }
}
```

### GetDeviceStatus

```http
GET /api/v1/sdn/gateway/devices/{device_id}/status
```

**Response:**
```json
{
  "device_id": "device-001",
  "state": "active",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "vlan_id": 100,
  "vni": 1000100,
  "ipv6_address": "2602:F5BB:0001:0100::10",
  "gateway_id": "gw-001",
  "connected_vtep": "10.0.0.1",
  "last_activity": "2026-01-18T10:29:55Z",
  "traffic": {
    "bytes_in": 1048576,
    "bytes_out": 2097152,
    "packets_in": 10000,
    "packets_out": 15000
  }
}
```

## Load Balancer Endpoints

### ListLoadBalancers

```http
GET /api/v1/sdn/gateway/loadbalancers
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `gateway_id` | string | Filter by gateway |
| `state` | string | Filter by state (active, draining, disabled) |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "loadbalancers": [
    {
      "id": "lb-001",
      "name": "web-frontend",
      "gateway_id": "gw-001",
      "vip": "2602:F5BB:0001:0100::80",
      "port": 443,
      "protocol": "tcp",
      "algorithm": "round_robin",
      "state": "active",
      "backends": [
        {
          "address": "2602:F5BB:0001:0100::10",
          "port": 8443,
          "weight": 100,
          "state": "healthy"
        },
        {
          "address": "2602:F5BB:0001:0100::11",
          "port": 8443,
          "weight": 100,
          "state": "healthy"
        }
      ],
      "health_check": {
        "protocol": "https",
        "path": "/health",
        "interval_seconds": 10,
        "timeout_seconds": 5,
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      },
      "statistics": {
        "active_connections": 500,
        "total_connections": 100000,
        "bytes_in": 10737418240,
        "bytes_out": 21474836480
      }
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetLoadBalancer

```http
GET /api/v1/sdn/gateway/loadbalancers/{id}
```

**Response:**
```json
{
  "id": "lb-001",
  "name": "web-frontend",
  "gateway_id": "gw-001",
  "vip": "2602:F5BB:0001:0100::80",
  "port": 443,
  "protocol": "tcp",
  "algorithm": "round_robin",
  "state": "active",
  "backends": [
    {
      "address": "2602:F5BB:0001:0100::10",
      "port": 8443,
      "weight": 100,
      "state": "healthy",
      "statistics": {
        "active_connections": 250,
        "total_connections": 50000
      }
    }
  ],
  "health_check": {
    "protocol": "https",
    "path": "/health",
    "interval_seconds": 10,
    "timeout_seconds": 5,
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  }
}
```

### CreateLoadBalancer

```http
POST /api/v1/sdn/gateway/loadbalancers
Content-Type: application/json
```

**Request:**
```json
{
  "name": "web-frontend",
  "vip": "2602:F5BB:0001:0100::80",
  "port": 443,
  "protocol": "tcp",
  "algorithm": "round_robin",
  "backends": [
    {
      "address": "2602:F5BB:0001:0100::10",
      "port": 8443,
      "weight": 100
    },
    {
      "address": "2602:F5BB:0001:0100::11",
      "port": 8443,
      "weight": 100
    }
  ],
  "health_check": {
    "protocol": "https",
    "path": "/health",
    "interval_seconds": 10,
    "timeout_seconds": 5,
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  }
}
```

**Response (201):**
```json
{
  "id": "lb-001",
  "name": "web-frontend",
  "gateway_id": "gw-001",
  "vip": "2602:F5BB:0001:0100::80",
  "port": 443,
  "state": "active"
}
```

### UpdateLoadBalancer

```http
PUT /api/v1/sdn/gateway/loadbalancers/{id}
Content-Type: application/json
```

**Request:**
```json
{
  "algorithm": "least_connections",
  "backends": [
    {
      "address": "2602:F5BB:0001:0100::10",
      "port": 8443,
      "weight": 100
    },
    {
      "address": "2602:F5BB:0001:0100::11",
      "port": 8443,
      "weight": 50
    },
    {
      "address": "2602:F5BB:0001:0100::12",
      "port": 8443,
      "weight": 100
    }
  ]
}
```

### DeleteLoadBalancer

```http
DELETE /api/v1/sdn/gateway/loadbalancers/{id}
```

**Response:**
```json
{
  "deleted": true,
  "loadbalancer_id": "lb-001"
}
```

### AddBackend

```http
POST /api/v1/sdn/gateway/loadbalancers/{id}/backends
Content-Type: application/json
```

**Request:**
```json
{
  "address": "2602:F5BB:0001:0100::12",
  "port": 8443,
  "weight": 100
}
```

### RemoveBackend

```http
DELETE /api/v1/sdn/gateway/loadbalancers/{id}/backends/{address}
```

### DrainBackend

```http
POST /api/v1/sdn/gateway/loadbalancers/{id}/backends/{address}/drain
```

**Response:**
```json
{
  "address": "2602:F5BB:0001:0100::10",
  "state": "draining",
  "active_connections": 50,
  "drain_started": "2026-01-18T10:30:00Z"
}
```

## Error Responses

```json
{
  "error": "gateway_not_found",
  "message": "Gateway 'gw-999' not found",
  "details": {
    "gateway_id": "gw-999"
  }
}
```

**HTTP Status Codes:**

| Status | Description |
|--------|-------------|
| 400 | Invalid request (bad IP, invalid config) |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found (gateway, device, loadbalancer) |
| 409 | Conflict (gateway exists, IP allocated) |
| 429 | Rate limited |
| 500 | Server error |
| 503 | Gateway unhealthy |

## Rate Limiting

| Endpoint Type | Requests/Min |
|---------------|--------------|
| Gateway read | 200 |
| Gateway write | 30 |
| IPv6 allocation | 100 |
| Device operations | 60 |
| Load balancer read | 200 |
| Load balancer write | 30 |

Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## curl Examples

```bash
# List gateways
curl -X GET https://platform.example.com/api/v1/sdn/gateway/gateways \
  --cert client.crt --key client.key --cacert ca.crt

# Register gateway
curl -X POST https://platform.example.com/api/v1/sdn/gateway/gateways \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "region": "us-east-1",
    "ipv6_prefix": "2602:F5BB:0001::/48",
    "vtep_ip": "10.0.0.1",
    "capabilities": ["ipv6", "ipv4", "nat64", "load_balancer"]
  }'

# Promote gateway to active
curl -X POST https://platform.example.com/api/v1/sdn/gateway/gateways/gw-001/promote \
  --cert client.crt --key client.key --cacert ca.crt

# Allocate IPv6 address
curl -X POST https://platform.example.com/api/v1/sdn/gateway/ipv6/allocate \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "device-001",
    "prefix_length": 128,
    "vni": 1000100
  }'

# Onboard device
curl -X POST https://platform.example.com/api/v1/sdn/gateway/devices/onboard \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "device-001",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "vlan_id": 100,
    "profile": "standard-workstation"
  }'

# Create load balancer
curl -X POST https://platform.example.com/api/v1/sdn/gateway/loadbalancers \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web-frontend",
    "vip": "2602:F5BB:0001:0100::80",
    "port": 443,
    "protocol": "tcp",
    "algorithm": "round_robin",
    "backends": [
      {"address": "2602:F5BB:0001:0100::10", "port": 8443, "weight": 100}
    ]
  }'

# Check gateway health
curl -X GET https://platform.example.com/api/v1/sdn/gateway/gateways/gw-001/health \
  --cert client.crt --key client.key --cacert ca.crt
```

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [SDN Architecture](../architecture.md)
- [BGP Transit](../bgp/transit.md)
- [Overlay Configuration](../overlay/configuration.md)

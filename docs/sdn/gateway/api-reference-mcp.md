# Gateway MCP API Reference

Model Context Protocol (MCP) interface for AI/LLM integration with the gateway service.

| Property | Value |
|----------|-------|
| Service | `gateway` |
| Transport | stdio or HTTP |
| Port (HTTP) | 9445 |
| Protocol | MCP v1.0 |

## Overview

The MCP interface enables AI assistants and LLMs to interact with gateways through:

- **Tools** - Actions to manage gateways, devices, IPv6, and load balancers
- **Resources** - Data about gateway state, device inventory, and traffic

## Connection Setup

### stdio Transport

```json
{
  "mcpServers": {
    "gateway": {
      "command": "platformctl",
      "args": ["mcp", "gateway", "serve"],
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
    "gateway": {
      "url": "https://platform.example.com:9445/mcp/gateway",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  }
}
```

## Available Tools

### Gateway Management Tools

#### gateway_list

List all gateways.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| mode | string | No | Filter by mode (active, standby, maintenance) |
| region | string | No | Filter by region |
| healthy_only | boolean | No | Show only healthy gateways |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "gateway_list",
  "arguments": {
    "mode": "active",
    "healthy_only": true
  }
}
```

**Response:**
```json
{
  "gateways": [
    {
      "id": "gw-001",
      "region": "us-east-1",
      "mode": "active",
      "ipv6_prefix": "2602:F5BB:0001::/48",
      "healthy": true,
      "connections": {
        "active": 1500,
        "total": 50000
      }
    }
  ],
  "total": 1
}
```

#### gateway_get

Get detailed gateway information.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Gateway ID |

#### gateway_register

Register a new gateway.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| region | string | Yes | Geographic region |
| ipv6_prefix | string | Yes | IPv6 prefix to serve |
| ipv4_address | string | No | Public IPv4 address |
| vtep_ip | string | Yes | VTEP IP for overlay |
| capabilities | array | No | Gateway capabilities |

**Example:**
```json
{
  "name": "gateway_register",
  "arguments": {
    "region": "us-east-1",
    "ipv6_prefix": "2602:F5BB:0001::/48",
    "vtep_ip": "10.0.0.1",
    "capabilities": ["ipv6", "ipv4", "nat64", "load_balancer"]
  }
}
```

#### gateway_deregister

Remove a gateway.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Gateway ID |

#### gateway_promote

Promote gateway to active mode.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Gateway ID |

#### gateway_demote

Demote gateway to standby mode.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Gateway ID |

#### gateway_health

Get gateway health status.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Gateway ID |

**Response:**
```json
{
  "id": "gw-001",
  "healthy": true,
  "checks": [
    {
      "name": "bgp_session",
      "status": "healthy",
      "message": "All BGP peers established"
    },
    {
      "name": "vtep_connectivity",
      "status": "healthy",
      "message": "VTEP reachable"
    }
  ],
  "uptime_seconds": 86400
}
```

### IPv6 Allocation Tools

#### gateway_ipv6_allocate

Allocate an IPv6 address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device identifier |
| prefix_length | integer | No | Prefix length (default: 128) |
| vni | integer | Yes | VNI for the allocation |
| metadata | object | No | Additional metadata |

**Example:**
```json
{
  "name": "gateway_ipv6_allocate",
  "arguments": {
    "device_id": "device-001",
    "vni": 1000100,
    "metadata": {
      "owner": "tenant-a",
      "purpose": "vm-network"
    }
  }
}
```

**Response:**
```json
{
  "address": "2602:F5BB:0001:0100::1",
  "prefix_length": 128,
  "device_id": "device-001",
  "gateway_id": "gw-001",
  "vni": 1000100
}
```

#### gateway_ipv6_release

Release an IPv6 address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | Yes | IPv6 address to release |

#### gateway_ipv6_list

List IPv6 allocations.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | No | Filter by device |
| vni | integer | No | Filter by VNI |
| gateway_id | string | No | Filter by gateway |
| limit | integer | No | Maximum results |

#### gateway_ipv6_pools

Get IPv6 pool statistics.

**Parameters:** None

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

### Device Onboarding Tools

#### gateway_device_onboard

Onboard a new device.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device identifier |
| mac_address | string | Yes | MAC address |
| vlan_id | integer | Yes | VLAN ID |
| profile | string | No | Device profile |
| certificate_cn | string | No | Certificate common name |

**Example:**
```json
{
  "name": "gateway_device_onboard",
  "arguments": {
    "device_id": "device-001",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "vlan_id": 100,
    "profile": "standard-workstation"
  }
}
```

**Response:**
```json
{
  "device_id": "device-001",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "vlan_id": 100,
  "vni": 1000100,
  "ipv6_address": "2602:F5BB:0001:0100::10",
  "gateway_id": "gw-001",
  "state": "provisioned"
}
```

#### gateway_device_offboard

Offboard a device.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device identifier |

#### gateway_device_status

Get device status.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device identifier |

**Response:**
```json
{
  "device_id": "device-001",
  "state": "active",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ipv6_address": "2602:F5BB:0001:0100::10",
  "connected_vtep": "10.0.0.1",
  "last_activity": "2026-01-18T10:29:55Z",
  "traffic": {
    "bytes_in": 1048576,
    "bytes_out": 2097152
  }
}
```

### Load Balancer Tools

#### gateway_lb_list

List load balancers.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| gateway_id | string | No | Filter by gateway |
| state | string | No | Filter by state |
| limit | integer | No | Maximum results |

**Response:**
```json
{
  "loadbalancers": [
    {
      "id": "lb-001",
      "name": "web-frontend",
      "vip": "2602:F5BB:0001:0100::80",
      "port": 443,
      "state": "active",
      "backends": [
        {
          "address": "2602:F5BB:0001:0100::10",
          "port": 8443,
          "state": "healthy"
        }
      ]
    }
  ]
}
```

#### gateway_lb_get

Get load balancer details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Load balancer ID |

#### gateway_lb_create

Create a load balancer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Load balancer name |
| vip | string | Yes | Virtual IP address |
| port | integer | Yes | Listen port |
| protocol | string | Yes | Protocol (tcp, udp, http, https) |
| algorithm | string | No | Algorithm (round_robin, least_connections) |
| backends | array | Yes | Backend configurations |

**Example:**
```json
{
  "name": "gateway_lb_create",
  "arguments": {
    "name": "web-frontend",
    "vip": "2602:F5BB:0001:0100::80",
    "port": 443,
    "protocol": "tcp",
    "algorithm": "round_robin",
    "backends": [
      {"address": "2602:F5BB:0001:0100::10", "port": 8443, "weight": 100},
      {"address": "2602:F5BB:0001:0100::11", "port": 8443, "weight": 100}
    ]
  }
}
```

#### gateway_lb_delete

Delete a load balancer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | string | Yes | Load balancer ID |

#### gateway_lb_add_backend

Add a backend to load balancer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| loadbalancer_id | string | Yes | Load balancer ID |
| address | string | Yes | Backend address |
| port | integer | Yes | Backend port |
| weight | integer | No | Backend weight |

#### gateway_lb_remove_backend

Remove a backend from load balancer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| loadbalancer_id | string | Yes | Load balancer ID |
| address | string | Yes | Backend address |

#### gateway_lb_drain_backend

Drain a backend.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| loadbalancer_id | string | Yes | Load balancer ID |
| address | string | Yes | Backend address |

## Available Resources

### gateway://gateways

List of all gateways.

**URI:** `gateway://gateways`

### gateway://gateways/{id}

Detailed gateway information.

**URI:** `gateway://gateways/gw-001`

### gateway://gateways/{id}/health

Gateway health status.

**URI:** `gateway://gateways/gw-001/health`

### gateway://ipv6/allocations

IPv6 allocations.

**URI:** `gateway://ipv6/allocations`

### gateway://ipv6/pools

IPv6 pool statistics.

**URI:** `gateway://ipv6/pools`

### gateway://devices

Device inventory.

**URI:** `gateway://devices`

### gateway://devices/{device_id}

Device details.

**URI:** `gateway://devices/device-001`

### gateway://loadbalancers

Load balancer list.

**URI:** `gateway://loadbalancers`

### gateway://loadbalancers/{id}

Load balancer details.

**URI:** `gateway://loadbalancers/lb-001`

### gateway://status

Overall gateway service status.

**URI:** `gateway://status`

## Example AI Interactions

### Device Onboarding Workflow

```
User: "Onboard device aa:bb:cc:dd:ee:ff to VLAN 100"

AI uses:
1. gateway_device_onboard(device_id="device-001", mac_address="aa:bb:cc:dd:ee:ff", vlan_id=100)

AI Response: "Device onboarded successfully:
- Device ID: device-001
- IPv6 Address: 2602:F5BB:0001:0100::10
- VNI: 1000100
- Gateway: gw-001
The device is now provisioned and ready for network access."
```

### Capacity Planning

```
User: "How much IPv6 capacity do we have left?"

AI reads:
1. gateway://ipv6/pools
2. gateway://devices

AI Response: "Current IPv6 capacity:
- Pool 2602:F5BB:0001::/48: 2.3% used (1,500/65,536)
- 64,036 addresses available
- 1,500 devices currently onboarded

At current growth rate (50 devices/day), the pool will last
approximately 3.5 years."
```

### Load Balancer Troubleshooting

```
User: "Web frontend load balancer has unhealthy backends"

AI uses:
1. gateway_lb_get(id="lb-001")
2. gateway://loadbalancers/lb-001

AI Response: "Load balancer lb-001 (web-frontend) status:
- VIP: 2602:F5BB:0001:0100::80:443
- 2 backends configured, 1 healthy

Unhealthy backend: 2602:F5BB:0001:0100::11:8443
- Last health check failed: Connection refused
- Failed 3 consecutive checks

Recommend checking if the application is running on that backend."
```

### Gateway Failover

```
User: "Promote gw-002 to active and demote gw-001"

AI uses:
1. gateway_health(id="gw-002") - Verify gw-002 is healthy
2. gateway_promote(id="gw-002")

AI Response: "Gateway failover completed:
- gw-002 promoted to active
- gw-001 automatically demoted to standby
- 1,500 active connections migrated
- Failover completed in 2.3 seconds"
```

## Error Handling

```json
{
  "error": {
    "code": "gateway_not_found",
    "message": "Gateway 'gw-999' not found",
    "details": {
      "gateway_id": "gw-999"
    }
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `gateway_not_found` | Gateway does not exist |
| `device_not_found` | Device not found |
| `loadbalancer_not_found` | Load balancer not found |
| `ip_already_allocated` | IPv6 address already in use |
| `pool_exhausted` | No available IPv6 addresses |
| `device_already_onboarded` | Device already exists |
| `gateway_unhealthy` | Gateway health check failed |
| `invalid_ipv6` | Invalid IPv6 address format |
| `invalid_vni` | Invalid VNI |

## Security

- All operations require authentication
- Device onboarding may require certificate validation
- Gateway promotion may require approval
- Operations are logged for audit

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [Unix Socket API Reference](api-reference-unix.md)

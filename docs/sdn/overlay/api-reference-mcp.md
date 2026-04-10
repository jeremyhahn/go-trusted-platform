# VXLAN Overlay MCP API Reference

Model Context Protocol (MCP) interface for AI/LLM integration with the VXLAN overlay service.

| Property | Value |
|----------|-------|
| Service | `overlay` |
| Transport | stdio or HTTP |
| Port (HTTP) | 9445 |
| Protocol | MCP v1.0 |

## Overview

The MCP interface enables AI assistants and LLMs to interact with the overlay service through:

- **Tools** - Actions the AI can invoke to manage overlay resources
- **Resources** - Data the AI can read to understand overlay state

## Connection Setup

### stdio Transport

For local AI integrations running on the same host.

```json
{
  "mcpServers": {
    "overlay": {
      "command": "platformctl",
      "args": ["mcp", "overlay", "serve"],
      "env": {
        "PLATFORM_CONFIG": "/etc/platform/config.yaml"
      }
    }
  }
}
```

### HTTP Transport

For remote AI integrations.

```json
{
  "mcpServers": {
    "overlay": {
      "url": "https://platform.example.com:9445/mcp/overlay",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  }
}
```

## Available Tools

### VTEP Management Tools

#### overlay_vtep_list

List all VTEPs in the overlay network.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| healthy_only | boolean | No | Filter to only healthy VTEPs |
| limit | integer | No | Maximum number of results (default: 100) |

**Example:**
```json
{
  "name": "overlay_vtep_list",
  "arguments": {
    "healthy_only": true,
    "limit": 50
  }
}
```

**Response:**
```json
{
  "vteps": [
    {
      "ip": "10.0.0.1",
      "node_id": "node-001",
      "underlay_iface": "eth0",
      "healthy": true,
      "active_vnis": [1000100, 1000200]
    }
  ],
  "total": 1
}
```

#### overlay_vtep_get

Get details for a specific VTEP.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | VTEP IP address |

**Example:**
```json
{
  "name": "overlay_vtep_get",
  "arguments": {
    "ip": "10.0.0.1"
  }
}
```

#### overlay_vtep_register

Register a new VTEP.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | VTEP IP address |
| underlay_iface | string | Yes | Underlay network interface |
| underlay_mtu | integer | No | MTU size (default: 1500) |
| vxlan_port | integer | No | VXLAN UDP port (default: 4789) |

**Example:**
```json
{
  "name": "overlay_vtep_register",
  "arguments": {
    "ip": "10.0.0.1",
    "underlay_iface": "eth0",
    "underlay_mtu": 9000,
    "vxlan_port": 4789
  }
}
```

#### overlay_vtep_deregister

Remove a VTEP from the overlay network.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | VTEP IP address |

#### overlay_vtep_health

Check VTEP health status.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | VTEP IP address |

**Response:**
```json
{
  "ip": "10.0.0.1",
  "healthy": true,
  "latency_ms": 2,
  "tunnel_count": 3,
  "uptime_seconds": 86400
}
```

### VNI Management Tools

#### overlay_vni_list

List all VNIs.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vlan_id | integer | No | Filter by VLAN ID |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "overlay_vni_list",
  "arguments": {
    "limit": 100
  }
}
```

#### overlay_vni_get

Get VNI details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | integer | Yes | VNI ID |

#### overlay_vni_create

Create a new VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | integer | Yes | VNI ID (1-16777215) |
| vlan_id | integer | No | Associated VLAN ID |
| multicast_group | string | No | Multicast group for BUM traffic |

**Example:**
```json
{
  "name": "overlay_vni_create",
  "arguments": {
    "id": 1000100,
    "vlan_id": 100,
    "multicast_group": "239.1.1.100"
  }
}
```

#### overlay_vni_delete

Delete a VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | integer | Yes | VNI ID |

#### overlay_vni_join

Join the local VTEP to a VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni_id | integer | Yes | VNI ID to join |

#### overlay_vni_leave

Leave a VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni_id | integer | Yes | VNI ID to leave |

#### overlay_vni_members

List VNI members.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni_id | integer | Yes | VNI ID |

### Tunnel Management Tools

#### overlay_tunnel_list

List all VXLAN tunnels.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| state | string | No | Filter by state (active, unhealthy, failed) |
| limit | integer | No | Maximum results |

#### overlay_tunnel_get

Get tunnel details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| remote_vtep | string | Yes | Remote VTEP IP address |

**Response:**
```json
{
  "id": "tunnel-10.0.0.1-10.0.0.2",
  "local_vtep": "10.0.0.1",
  "remote_vtep": "10.0.0.2",
  "vnis": [1000100, 1000200],
  "state": "active",
  "rtt": "1.5ms"
}
```

#### overlay_tunnel_create

Create a tunnel to a remote VTEP.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| remote_vtep | string | Yes | Remote VTEP IP address |
| vnis | array | Yes | VNI IDs to include |

**Example:**
```json
{
  "name": "overlay_tunnel_create",
  "arguments": {
    "remote_vtep": "10.0.0.2",
    "vnis": [1000100, 1000200]
  }
}
```

#### overlay_tunnel_delete

Delete a tunnel.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| remote_vtep | string | Yes | Remote VTEP IP address |

#### overlay_tunnel_stats

Get tunnel statistics.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| remote_vtep | string | Yes | Remote VTEP IP address |

**Response:**
```json
{
  "remote_vtep": "10.0.0.2",
  "stats": {
    "tx_packets": 150000,
    "rx_packets": 148500,
    "tx_bytes": 15360000,
    "rx_bytes": 15180000,
    "tx_errors": 0,
    "rx_errors": 0
  }
}
```

### MAC Table Tools

#### overlay_mac_list

List MAC addresses for a VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni | integer | Yes | VNI ID |
| type | string | No | Filter by type (local, remote, static) |
| limit | integer | No | Maximum results |

#### overlay_mac_get

Get MAC address details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni | integer | Yes | VNI ID |
| mac | string | Yes | MAC address |

#### overlay_mac_learn

Add a MAC address entry.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni | integer | Yes | VNI ID |
| mac | string | Yes | MAC address |
| vtep_ip | string | Yes | VTEP IP where MAC resides |
| type | string | No | Entry type (default: static) |

#### overlay_mac_delete

Delete a MAC address entry.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni | integer | Yes | VNI ID |
| mac | string | Yes | MAC address |

#### overlay_mac_flush

Flush MAC addresses for a VNI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| vni | integer | Yes | VNI ID |
| type | string | No | Type to flush (all, remote, local) |

## Available Resources

### overlay://vteps

List of all VTEPs with current status.

**URI:** `overlay://vteps`

**Contents:**
```json
{
  "vteps": [
    {
      "ip": "10.0.0.1",
      "node_id": "node-001",
      "healthy": true,
      "active_vnis": [1000100, 1000200],
      "last_heartbeat": "2026-01-18T10:30:00Z"
    }
  ]
}
```

### overlay://vteps/{ip}

Detailed information about a specific VTEP.

**URI:** `overlay://vteps/10.0.0.1`

### overlay://vnis

List of all VNIs.

**URI:** `overlay://vnis`

**Contents:**
```json
{
  "vnis": [
    {
      "id": 1000100,
      "vlan_id": 100,
      "member_vteps": ["10.0.0.1", "10.0.0.2"],
      "mac_count": 25
    }
  ]
}
```

### overlay://vnis/{id}

Detailed VNI information.

**URI:** `overlay://vnis/1000100`

### overlay://vnis/{id}/members

VNI membership information.

**URI:** `overlay://vnis/1000100/members`

### overlay://tunnels

List of all tunnels.

**URI:** `overlay://tunnels`

### overlay://tunnels/{remote_vtep}

Detailed tunnel information.

**URI:** `overlay://tunnels/10.0.0.2`

### overlay://tunnels/{remote_vtep}/stats

Tunnel statistics.

**URI:** `overlay://tunnels/10.0.0.2/stats`

### overlay://macs/{vni}

MAC table for a VNI.

**URI:** `overlay://macs/1000100`

### overlay://status

Overall overlay status.

**URI:** `overlay://status`

**Contents:**
```json
{
  "vtep_count": 5,
  "healthy_vteps": 5,
  "vni_count": 10,
  "tunnel_count": 20,
  "active_tunnels": 19,
  "total_macs": 500
}
```

## Example AI Interactions

### Troubleshooting Unhealthy VTEP

AI can diagnose overlay issues.

```
User: "VTEP 10.0.0.2 seems to be having issues"

AI uses:
1. overlay_vtep_health(ip="10.0.0.2") - Check health
2. overlay_tunnel_list(state="unhealthy") - Check affected tunnels
3. overlay_mac_list(vni=1000100, type="remote") - Check MAC learning

AI Response: "VTEP 10.0.0.2 is unhealthy with 3 failed tunnels.
The underlay interface eth0 shows high packet loss. This is
affecting MAC learning for VNI 1000100. Recommend checking
physical connectivity."
```

### Creating New Overlay Segment

```
User: "Create a new overlay segment for VLAN 200"

AI uses:
1. overlay_vni_create(id=1000200, vlan_id=200)
2. overlay_vni_join(vni_id=1000200)
3. overlay_tunnel_create(remote_vtep="10.0.0.2", vnis=[1000200])

AI Response: "Created VNI 1000200 mapped to VLAN 200. Joined local
VTEP and established tunnel to 10.0.0.2. The overlay segment is
ready for use."
```

### Capacity Analysis

```
User: "How many more VMs can we add to VNI 1000100?"

AI reads:
1. overlay://vnis/1000100
2. overlay://macs/1000100
3. overlay://status

AI Response: "VNI 1000100 currently has 25 MACs learned across
2 VTEPs. Based on your MAC table limit of 10,000 entries per VNI,
you can add approximately 9,975 more endpoints. Current VTEP
memory utilization is at 15%."
```

## Error Handling

Tools return errors in a structured format.

```json
{
  "error": {
    "code": "vtep_not_found",
    "message": "VTEP '10.0.0.99' not found",
    "details": {
      "vtep_ip": "10.0.0.99"
    }
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `vtep_not_found` | VTEP does not exist |
| `vni_not_found` | VNI does not exist |
| `tunnel_not_found` | Tunnel does not exist |
| `mac_not_found` | MAC entry not found |
| `vtep_already_exists` | VTEP already registered |
| `vni_already_exists` | VNI already exists |
| `invalid_vni_range` | VNI outside valid range |
| `invalid_vtep_ip` | Invalid IP address format |
| `underlay_unreachable` | Cannot reach underlay network |

## Security

MCP access requires authentication and authorization.

- stdio transport: Uses process-level authentication
- HTTP transport: Requires valid bearer token or mTLS
- All operations are logged for audit
- Rate limiting applies per-client

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)

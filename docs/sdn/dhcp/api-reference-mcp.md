# DHCP MCP API Reference

Model Context Protocol (MCP) interface for AI/LLM integration with the DHCP service.

| Property | Value |
|----------|-------|
| Service | `dhcp` |
| Transport | stdio or HTTP |
| Port (HTTP) | 9445 |
| Protocol | MCP v1.0 |

## Overview

The MCP interface enables AI assistants and LLMs to interact with DHCP through:

- **Tools** - Actions to manage leases and interface options
- **Resources** - Data about lease state, statistics, and configuration

## Connection Setup

### stdio Transport

```json
{
  "mcpServers": {
    "dhcp": {
      "command": "platformctl",
      "args": ["mcp", "dhcp", "serve"],
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
    "dhcp": {
      "url": "https://platform.example.com:9445/mcp/dhcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  }
}
```

## Available Tools

### Status Tools

#### dhcp_status

Get DHCP server status.

**Parameters:** None

**Response:**
```json
{
  "running": true,
  "interfaces": [
    {
      "name": "eth0",
      "address": "192.168.1.1",
      "pool_id": "internal-pool",
      "network": "private"
    }
  ],
  "ipam_backend": "memory",
  "uptime_seconds": 86400
}
```

#### dhcp_stats

Get server statistics.

**Parameters:** None

**Response:**
```json
{
  "started_at": "2026-01-18T00:00:00Z",
  "packets_received": 15000,
  "packets_sent": 14500,
  "discover_count": 5000,
  "offer_count": 5000,
  "request_count": 5000,
  "ack_count": 4900,
  "nak_count": 100,
  "active_leases": 245
}
```

### Lease Tools

#### dhcp_lease_list

List DHCP leases.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | No | Filter by pool |
| interface | string | No | Filter by interface |
| state | string | No | Filter by state (active, expired, released) |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "dhcp_lease_list",
  "arguments": {
    "pool_id": "internal-pool",
    "state": "active",
    "limit": 100
  }
}
```

**Response:**
```json
{
  "leases": [
    {
      "ip": "192.168.1.100",
      "mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "workstation-001",
      "pool_id": "internal-pool",
      "state": "active",
      "leased_at": "2026-01-18T10:00:00Z",
      "expires_at": "2026-01-19T10:00:00Z",
      "time_remaining_seconds": 43200
    }
  ],
  "total": 1
}
```

#### dhcp_lease_get_by_mac

Get lease by MAC address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| mac | string | Yes | MAC address |

**Example:**
```json
{
  "name": "dhcp_lease_get_by_mac",
  "arguments": {
    "mac": "aa:bb:cc:dd:ee:ff"
  }
}
```

#### dhcp_lease_get_by_ip

Get lease by IP address.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IP address |

#### dhcp_lease_release

Release a DHCP lease.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| mac | string | Yes | MAC address |

**Example:**
```json
{
  "name": "dhcp_lease_release",
  "arguments": {
    "mac": "aa:bb:cc:dd:ee:ff"
  }
}
```

**Response:**
```json
{
  "released": true,
  "mac": "aa:bb:cc:dd:ee:ff",
  "ip": "192.168.1.100"
}
```

#### dhcp_lease_expire

Manually expire old leases.

**Parameters:** None

**Response:**
```json
{
  "expired_count": 5,
  "active_leases": 240
}
```

### Interface Tools

#### dhcp_interface_list

List DHCP interfaces.

**Parameters:** None

**Response:**
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "network": "private",
      "address": "192.168.1.1",
      "pool_id": "internal-pool",
      "active_leases": 200,
      "options": {
        "subnet_mask": "255.255.255.0",
        "router": "192.168.1.1",
        "dns": ["8.8.8.8", "8.8.4.4"],
        "lease_time_seconds": 86400
      }
    }
  ]
}
```

#### dhcp_interface_get

Get interface details.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Interface name |

#### dhcp_interface_update_options

Update DHCP options for an interface.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Interface name |
| dns | array | No | DNS servers |
| domain_name | string | No | Domain name |
| lease_time_seconds | integer | No | Lease time |
| ntp_servers | array | No | NTP servers |
| mtu | integer | No | MTU size |

**Example:**
```json
{
  "name": "dhcp_interface_update_options",
  "arguments": {
    "name": "eth0",
    "dns": ["1.1.1.1", "8.8.8.8"],
    "domain_name": "newdomain.local",
    "lease_time_seconds": 43200
  }
}
```

### Pool Tools

#### dhcp_pool_stats

Get pool statistics.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pool_id | string | Yes | Pool identifier |

**Response:**
```json
{
  "pool_id": "internal-pool",
  "total_addresses": 254,
  "allocated": 200,
  "available": 54,
  "utilization_percent": 78.74,
  "leases_by_state": {
    "active": 195,
    "expired": 3,
    "released": 2
  }
}
```

## Available Resources

### dhcp://status

Server status.

**URI:** `dhcp://status`

### dhcp://stats

Server statistics.

**URI:** `dhcp://stats`

### dhcp://leases

All active leases.

**URI:** `dhcp://leases`

### dhcp://leases/mac/{mac}

Lease by MAC address.

**URI:** `dhcp://leases/mac/aa:bb:cc:dd:ee:ff`

### dhcp://leases/ip/{ip}

Lease by IP address.

**URI:** `dhcp://leases/ip/192.168.1.100`

### dhcp://interfaces

Interface list.

**URI:** `dhcp://interfaces`

### dhcp://interfaces/{name}

Interface details.

**URI:** `dhcp://interfaces/eth0`

### dhcp://pools/{pool_id}/stats

Pool statistics.

**URI:** `dhcp://pools/internal-pool/stats`

## Example AI Interactions

### Troubleshooting Client Connection

```
User: "Device aa:bb:cc:dd:ee:ff can't get an IP address"

AI uses:
1. dhcp_lease_get_by_mac(mac="aa:bb:cc:dd:ee:ff")
2. dhcp_stats()
3. dhcp_pool_stats(pool_id="internal-pool")

AI Response: "Device aa:bb:cc:dd:ee:ff does not have an active lease.

DHCP Statistics show 100 NAK responses recently, which suggests
configuration issues or pool exhaustion.

Pool 'internal-pool' is at 78.7% utilization (200/254).
Pool has 54 available addresses.

Possible causes:
1. Device may be on wrong VLAN
2. MAC filtering may be blocking the device
3. Device's previous lease may have been declined

Recommend checking network connectivity and MAC filter policies."
```

### Capacity Analysis

```
User: "Is the DHCP pool running low?"

AI reads:
1. dhcp://pools/internal-pool/stats
2. dhcp://leases

AI Response: "DHCP pool analysis for 'internal-pool':
- Total: 254 addresses
- Allocated: 200 (78.7%)
- Available: 54

Lease state breakdown:
- Active: 195
- Expired: 3
- Released: 2

At current utilization, the pool will be exhausted in
approximately 10 days if growth continues at 5 leases/day.

Recommend either expanding the pool or cleaning up stale
leases by running dhcp_lease_expire()."
```

### Interface Configuration

```
User: "Change DNS servers on eth0 to Cloudflare"

AI uses:
1. dhcp_interface_update_options(name="eth0", dns=["1.1.1.1", "1.0.0.1"])

AI Response: "Updated DHCP options on interface eth0:
- DNS servers changed to: 1.1.1.1, 1.0.0.1

New clients will receive Cloudflare DNS servers. Existing
clients will get the new settings on lease renewal. To
force immediate update, clients can release and renew
their DHCP leases."
```

### Lease Cleanup

```
User: "Clean up all expired DHCP leases"

AI uses:
1. dhcp_stats() - Get current state
2. dhcp_lease_expire() - Expire old leases

AI Response: "DHCP lease cleanup completed:
- Before: 248 total leases (245 active, 3 expired)
- Expired: 3 leases
- After: 245 active leases

Recovered 3 IP addresses back to the available pool.
Pool utilization dropped from 78.7% to 77.5%."
```

## Error Handling

```json
{
  "error": {
    "code": "lease_not_found",
    "message": "No lease found for MAC aa:bb:cc:dd:ee:ff",
    "details": {
      "mac": "aa:bb:cc:dd:ee:ff"
    }
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `lease_not_found` | No lease for specified MAC/IP |
| `invalid_mac` | Invalid MAC address format |
| `invalid_ip` | Invalid IP address format |
| `server_not_running` | DHCP server is stopped |
| `pool_exhausted` | No available IPs in pool |
| `lease_expired` | Lease has already expired |
| `interface_not_found` | Network interface not found |
| `pool_not_found` | IPAM pool not found |

## Security

- Read operations available to authenticated users
- Write operations (release, update) require elevated privileges
- All operations are logged for audit
- Rate limiting applies

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)

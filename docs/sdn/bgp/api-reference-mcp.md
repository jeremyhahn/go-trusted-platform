# BGP MCP API Reference

Model Context Protocol (MCP) interface for AI/LLM integration with the BGP service.

| Property | Value |
|----------|-------|
| Service | `bgp` |
| Transport | stdio or HTTP |
| Port (HTTP) | 9445 |
| Protocol | MCP v1.0 |

## Overview

The MCP interface enables AI assistants and LLMs to interact with BGP through:

- **Tools** - Actions to manage peers, routes, and transit
- **Resources** - Data about BGP state, peers, and routing tables

## Connection Setup

### stdio Transport

```json
{
  "mcpServers": {
    "bgp": {
      "command": "platformctl",
      "args": ["mcp", "bgp", "serve"],
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
    "bgp": {
      "url": "https://platform.example.com:9445/mcp/bgp",
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

#### bgp_status

Get BGP speaker status.

**Parameters:** None

**Response:**
```json
{
  "asn": 65001,
  "router_id": "23.143.36.1",
  "role": "backbone",
  "state": "running",
  "peer_count": 5,
  "established_peers": 5,
  "route_count": {
    "ipv4_unicast": 850000,
    "ipv6_unicast": 180000,
    "l2vpn_evpn": 2500
  }
}
```

#### bgp_speaker_info

Get detailed speaker information.

**Parameters:** None

### Peer Management Tools

#### bgp_peer_list

List all BGP peers.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| state | string | No | Filter by state (established, idle, active) |
| type | string | No | Filter by type (ebgp, ibgp) |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "bgp_peer_list",
  "arguments": {
    "state": "established",
    "limit": 50
  }
}
```

**Response:**
```json
{
  "peers": [
    {
      "address": "198.51.100.1",
      "remote_asn": 64500,
      "type": "ebgp",
      "state": "established",
      "uptime_seconds": 86400,
      "prefixes_received": 850000,
      "description": "ISP-Primary"
    }
  ],
  "total": 1
}
```

#### bgp_peer_get

Get detailed peer information.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | Yes | Peer IP address |

#### bgp_peer_add

Add a new BGP peer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | Yes | Peer IP address |
| remote_asn | integer | Yes | Remote AS number |
| type | string | Yes | Peer type (ebgp, ibgp) |
| description | string | No | Peer description |
| hold_time | integer | No | Hold time in seconds |
| md5_secret | string | No | MD5 authentication key |
| bfd_enabled | boolean | No | Enable BFD |
| families | array | No | Address families |

**Example:**
```json
{
  "name": "bgp_peer_add",
  "arguments": {
    "address": "198.51.100.1",
    "remote_asn": 64500,
    "type": "ebgp",
    "description": "ISP-Primary",
    "bfd_enabled": true,
    "families": ["ipv4-unicast", "ipv6-unicast"]
  }
}
```

#### bgp_peer_delete

Remove a BGP peer.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | Yes | Peer IP address |

#### bgp_peer_reset

Reset a BGP session.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | Yes | Peer IP address |
| soft | boolean | No | Soft reset (route refresh) |

### Route Tools

#### bgp_route_list

List BGP routes.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| family | string | No | Address family (ipv4, ipv6, evpn) |
| prefix | string | No | Filter by prefix |
| neighbor | string | No | Filter by neighbor |
| best_only | boolean | No | Show only best routes |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "bgp_route_list",
  "arguments": {
    "family": "ipv6",
    "best_only": true,
    "limit": 100
  }
}
```

**Response:**
```json
{
  "routes": [
    {
      "prefix": "2602:F5BB::/36",
      "next_hop": "2602:F5BB::1",
      "as_path": [65001],
      "origin": "igp",
      "local_pref": 100,
      "best": true,
      "rpki_status": "valid"
    }
  ]
}
```

#### bgp_route_get

Get route details with all paths.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| family | string | Yes | Address family |
| prefix | string | Yes | Route prefix |

### EVPN Tools

#### bgp_evpn_list

List EVPN routes.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| type | integer | No | Route type (2, 3, 5) |
| vni | integer | No | Filter by VNI |
| limit | integer | No | Maximum results |

**Example:**
```json
{
  "name": "bgp_evpn_list",
  "arguments": {
    "type": 2,
    "vni": 1000100
  }
}
```

**Response:**
```json
{
  "routes": [
    {
      "type": 2,
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.100.10",
      "vni": 1000100,
      "next_hop": "10.0.0.2"
    }
  ]
}
```

#### bgp_evpn_advertise_mac

Advertise EVPN Type-2 route.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| mac | string | Yes | MAC address |
| ip | string | No | IP address |
| vni | integer | Yes | VNI |

#### bgp_evpn_withdraw_mac

Withdraw EVPN Type-2 route.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| mac | string | Yes | MAC address |
| vni | integer | Yes | VNI |

#### bgp_evpn_advertise_prefix

Advertise EVPN Type-5 route.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| prefix | string | Yes | IP prefix |
| l3_vni | integer | Yes | L3 VNI |
| gateway_ip | string | No | Gateway IP |

### Transit Tools

#### bgp_transit_list

List transit prefixes.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| announced_only | boolean | No | Show only announced prefixes |
| family | string | No | Filter by family |

**Response:**
```json
{
  "prefixes": [
    {
      "prefix": "2602:F5BB::/36",
      "family": "ipv6",
      "announced": true,
      "signed": true,
      "rpki_status": "valid"
    }
  ]
}
```

#### bgp_transit_announce

Announce a transit prefix.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| prefix | string | Yes | Prefix to announce |
| next_hop | string | No | Next hop address |
| communities | array | No | BGP communities |
| require_signing | boolean | No | Require multi-sig |

**Example:**
```json
{
  "name": "bgp_transit_announce",
  "arguments": {
    "prefix": "2602:F5BB:0001::/48",
    "communities": ["65001:300"],
    "require_signing": true
  }
}
```

#### bgp_transit_withdraw

Withdraw a transit prefix.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| prefix | string | Yes | Prefix to withdraw |

#### bgp_transit_blackhole

Blackhole a prefix (DDoS mitigation).

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| prefix | string | Yes | Prefix to blackhole |
| reason | string | No | Reason for blackhole |

### RPKI Tools

#### bgp_rpki_status

Get RPKI validator status.

**Parameters:** None

**Response:**
```json
{
  "enabled": true,
  "servers": [
    {
      "address": "rpki-validator:8323",
      "state": "connected",
      "records": 450000
    }
  ],
  "statistics": {
    "valid_routes": 800000,
    "invalid_routes": 150,
    "not_found_routes": 49850
  }
}
```

#### bgp_rpki_validate

Validate a prefix against RPKI.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| prefix | string | Yes | Prefix to validate |
| asn | integer | Yes | Origin ASN |

**Response:**
```json
{
  "prefix": "2602:F5BB::/36",
  "asn": 65001,
  "status": "valid",
  "roas": [
    {
      "prefix": "2602:F5BB::/36",
      "max_length": 48,
      "asn": 65001
    }
  ]
}
```

### Dampening Tools

#### bgp_dampening_status

Get route dampening status.

**Parameters:** None

#### bgp_dampening_suppressed

List suppressed routes.

**Parameters:** None

## Available Resources

### bgp://status

Overall BGP status.

**URI:** `bgp://status`

### bgp://speaker

Speaker configuration.

**URI:** `bgp://speaker`

### bgp://peers

List of all peers.

**URI:** `bgp://peers`

### bgp://peers/{address}

Detailed peer information.

**URI:** `bgp://peers/198.51.100.1`

### bgp://routes/{family}

Routes by address family.

**URI:** `bgp://routes/ipv6`

### bgp://routes/{family}/{prefix}

Specific route details.

**URI:** `bgp://routes/ipv6/2602:F5BB::/36`

### bgp://evpn

EVPN routes.

**URI:** `bgp://evpn`

### bgp://evpn/type2/{vni}

Type-2 routes for a VNI.

**URI:** `bgp://evpn/type2/1000100`

### bgp://transit

Transit prefixes.

**URI:** `bgp://transit`

### bgp://rpki

RPKI status and statistics.

**URI:** `bgp://rpki`

### bgp://dampening

Route dampening status.

**URI:** `bgp://dampening`

## Example AI Interactions

### Troubleshooting Peer Issues

```
User: "Peer 198.51.100.1 keeps flapping"

AI uses:
1. bgp_peer_get(address="198.51.100.1") - Get peer details
2. bgp_dampening_suppressed() - Check suppressed routes
3. bgp://peers/198.51.100.1 - Read full peer state

AI Response: "Peer 198.51.100.1 has flapped 5 times in the last
hour. The last error was 'Hold Timer Expired'. This typically
indicates network reachability issues or CPU overload on the
peer. BFD is enabled and detecting failures in 300ms.
Recommend checking underlay connectivity."
```

### Transit Operations

```
User: "Announce our new /48 prefix with DDoS protection"

AI uses:
1. bgp_rpki_validate(prefix="2602:F5BB:0001::/48", asn=65001)
2. bgp_transit_announce(prefix="2602:F5BB:0001::/48", require_signing=true)

AI Response: "RPKI validation passed for 2602:F5BB:0001::/48.
Prefix has been announced with multi-signature requirement.
3 signatures collected. The prefix is now visible to all
upstream peers."
```

### EVPN Analysis

```
User: "Show me MAC mobility on VNI 1000100"

AI uses:
1. bgp_evpn_list(type=2, vni=1000100)
2. bgp://evpn/type2/1000100

AI Response: "VNI 1000100 has 25 MAC/IP bindings. MAC
aa:bb:cc:dd:ee:ff has moved 3 times in the last hour
between VTEP 10.0.0.1 and 10.0.0.2. This may indicate
a misconfiguration or a VM migration in progress."
```

### Capacity Planning

```
User: "How many more routes can we accept from ISP peers?"

AI reads:
1. bgp://status
2. bgp://peers

AI Response: "Current RIB has 850K IPv4 and 180K IPv6 routes.
With 2GB RIB memory configured, you can accept approximately
150K more IPv4 routes or 50K more IPv6 routes. ISP-Primary
is sending 850K prefixes. Consider implementing more
aggressive filtering or upgrading memory."
```

## Error Handling

```json
{
  "error": {
    "code": "peer_not_found",
    "message": "BGP peer '198.51.100.99' not found",
    "details": {
      "peer_address": "198.51.100.99"
    }
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `peer_not_found` | BGP peer does not exist |
| `peer_not_established` | Peer exists but not in Established state |
| `route_not_found` | Route not in RIB |
| `invalid_prefix` | Invalid prefix format |
| `invalid_asn` | Invalid AS number |
| `rpki_validation_failed` | RPKI validation failed |
| `speaker_not_running` | BGP speaker not active |

## Security

- All operations require authentication
- Transit announcements may require multi-signature approval
- RPKI validation is performed automatically
- Operations are logged for audit

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)

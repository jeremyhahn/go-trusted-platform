# BGP REST API Reference

REST API endpoints for the BGP service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/bgp` |
| Port | 8443 |
| Content-Type | `application/json` |

## Status Endpoints

### GetStatus

```http
GET /api/v1/sdn/bgp/status
```

**Response:**
```json
{
  "asn": 65001,
  "router_id": "23.143.36.1",
  "role": "backbone",
  "state": "running",
  "uptime_seconds": 86400,
  "peer_count": 5,
  "established_peers": 5,
  "route_count": {
    "ipv4_unicast": 850000,
    "ipv6_unicast": 180000,
    "l2vpn_evpn": 2500
  },
  "speaker_mode": "active"
}
```

### GetSpeakerInfo

```http
GET /api/v1/sdn/bgp/speaker
```

**Response:**
```json
{
  "id": "speaker-001",
  "asn": 65001,
  "router_id": "23.143.36.1",
  "role": "backbone",
  "listen_port": 179,
  "vtep_ip": "10.0.0.1",
  "families": [
    {"afi": "ipv4", "safi": "unicast"},
    {"afi": "ipv6", "safi": "unicast"},
    {"afi": "l2vpn", "safi": "evpn"}
  ],
  "config": {
    "hold_time": 90,
    "keepalive_interval": 30,
    "graceful_restart": true,
    "graceful_restart_time": 120
  }
}
```

## Peer Endpoints

### ListPeers

```http
GET /api/v1/sdn/bgp/peers
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `state` | string | Filter by state (established, idle, connect, active) |
| `type` | string | Filter by type (ebgp, ibgp) |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

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
      "messages_received": 150000,
      "messages_sent": 145000,
      "prefixes_received": 850000,
      "prefixes_sent": 2,
      "last_error": null,
      "description": "ISP-Primary"
    },
    {
      "address": "10.0.0.2",
      "remote_asn": 65001,
      "type": "ibgp",
      "state": "established",
      "uptime_seconds": 172800,
      "messages_received": 50000,
      "messages_sent": 48000,
      "prefixes_received": 180000,
      "prefixes_sent": 180000,
      "last_error": null,
      "description": "DC-Speaker-2"
    }
  ],
  "total": 2,
  "limit": 100,
  "offset": 0
}
```

### GetPeer

```http
GET /api/v1/sdn/bgp/peers/{address}
```

**Response:**
```json
{
  "address": "198.51.100.1",
  "remote_asn": 64500,
  "type": "ebgp",
  "state": "established",
  "uptime_seconds": 86400,
  "description": "ISP-Primary",
  "config": {
    "hold_time": 90,
    "keepalive_interval": 30,
    "md5_enabled": true,
    "bfd_enabled": true,
    "graceful_restart": true,
    "multihop": false,
    "multihop_ttl": 1
  },
  "families": [
    {"afi": "ipv4", "safi": "unicast", "enabled": true},
    {"afi": "ipv6", "safi": "unicast", "enabled": true}
  ],
  "statistics": {
    "messages_received": 150000,
    "messages_sent": 145000,
    "updates_received": 100000,
    "updates_sent": 50,
    "opens_received": 1,
    "opens_sent": 1,
    "keepalives_received": 50000,
    "keepalives_sent": 48000,
    "notifications_received": 0,
    "notifications_sent": 0
  },
  "timers": {
    "negotiated_hold_time": 90,
    "uptime": "1d 0h 0m",
    "last_read": "2026-01-18T10:29:55Z",
    "last_write": "2026-01-18T10:29:50Z"
  }
}
```

### AddPeer

```http
POST /api/v1/sdn/bgp/peers
Content-Type: application/json
```

**Request:**
```json
{
  "address": "198.51.100.1",
  "remote_asn": 64500,
  "type": "ebgp",
  "description": "ISP-Primary",
  "config": {
    "hold_time": 90,
    "keepalive_interval": 30,
    "md5_secret": "bgp_secret_key",
    "bfd_enabled": true,
    "graceful_restart": true
  },
  "families": [
    {"afi": "ipv4", "safi": "unicast"},
    {"afi": "ipv6", "safi": "unicast"}
  ],
  "policies": {
    "import_policy": "import-from-isp",
    "export_policy": "export-to-isp"
  }
}
```

**Response (201):**
```json
{
  "address": "198.51.100.1",
  "remote_asn": 64500,
  "type": "ebgp",
  "state": "idle",
  "description": "ISP-Primary"
}
```

### UpdatePeer

```http
PUT /api/v1/sdn/bgp/peers/{address}
Content-Type: application/json
```

**Request:**
```json
{
  "description": "ISP-Primary-Updated",
  "config": {
    "hold_time": 120
  }
}
```

### DeletePeer

```http
DELETE /api/v1/sdn/bgp/peers/{address}
```

**Response:**
```json
{
  "deleted": true,
  "peer_address": "198.51.100.1"
}
```

### ResetPeer

```http
POST /api/v1/sdn/bgp/peers/{address}/reset
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `soft` | bool | Soft reset (route refresh) |

**Response:**
```json
{
  "address": "198.51.100.1",
  "reset": true,
  "type": "hard"
}
```

## Route Endpoints

### ListRoutes

```http
GET /api/v1/sdn/bgp/routes
GET /api/v1/sdn/bgp/routes/{family}
```

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `family` | Address family: `ipv4`, `ipv6`, `evpn` |

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `prefix` | string | Filter by prefix |
| `neighbor` | string | Filter by neighbor |
| `origin` | string | Filter by origin (igp, egp, incomplete) |
| `best` | bool | Show only best routes |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response (IPv4/IPv6):**
```json
{
  "family": "ipv6",
  "routes": [
    {
      "prefix": "2602:F5BB::/36",
      "next_hop": "2602:F5BB::1",
      "origin": "igp",
      "as_path": [65001],
      "local_pref": 100,
      "med": 0,
      "communities": ["65001:100"],
      "best": true,
      "source": "local",
      "age_seconds": 86400,
      "rpki_status": "valid"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetRoute

```http
GET /api/v1/sdn/bgp/routes/{family}/{prefix}
```

**Example:**
```http
GET /api/v1/sdn/bgp/routes/ipv6/2602:F5BB::/36
```

**Response:**
```json
{
  "prefix": "2602:F5BB::/36",
  "paths": [
    {
      "next_hop": "2602:F5BB::1",
      "origin": "igp",
      "as_path": [65001],
      "local_pref": 100,
      "med": 0,
      "communities": ["65001:100"],
      "best": true,
      "source": "local",
      "age_seconds": 86400,
      "rpki_status": "valid"
    }
  ]
}
```

## EVPN Route Endpoints

### ListEVPNRoutes

```http
GET /api/v1/sdn/bgp/evpn/routes
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | int | Route type (2, 3, 5) |
| `vni` | int | Filter by VNI |
| `rd` | string | Filter by Route Distinguisher |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "routes": [
    {
      "type": 2,
      "rd": "65001:1000100",
      "ethernet_tag": 0,
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.100.10",
      "vni": 1000100,
      "next_hop": "10.0.0.2",
      "rt": ["65001:1000100"],
      "source": "10.0.0.2",
      "age_seconds": 3600
    },
    {
      "type": 3,
      "rd": "65001:1000100",
      "ethernet_tag": 0,
      "originator_ip": "10.0.0.1",
      "vni": 1000100,
      "pmsi_tunnel": {
        "type": "ingress_replication",
        "label": 1000100,
        "tunnel_id": "10.0.0.1"
      },
      "rt": ["65001:1000100"],
      "source": "local",
      "age_seconds": 86400
    },
    {
      "type": 5,
      "rd": "65001:10000",
      "ethernet_tag": 0,
      "prefix": "192.168.1.0/24",
      "gateway_ip": "10.0.0.1",
      "vni": 10000,
      "next_hop": "10.0.0.1",
      "rt": ["65001:10000"],
      "source": "local",
      "age_seconds": 86400
    }
  ],
  "total": 3,
  "limit": 100,
  "offset": 0
}
```

### GetEVPNType2

```http
GET /api/v1/sdn/bgp/evpn/type2/{vni}/{mac}
```

**Response:**
```json
{
  "type": 2,
  "rd": "65001:1000100",
  "ethernet_tag": 0,
  "mac": "aa:bb:cc:dd:ee:ff",
  "ip": "192.168.100.10",
  "vni": 1000100,
  "next_hop": "10.0.0.2",
  "rt": ["65001:1000100"],
  "source": "10.0.0.2",
  "age_seconds": 3600,
  "seq_num": 0
}
```

## Transit Route Endpoints

### ListTransitPrefixes

```http
GET /api/v1/sdn/bgp/transit/prefixes
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `announced` | bool | Filter by announcement status |
| `family` | string | Filter by family (ipv4, ipv6) |

**Response:**
```json
{
  "prefixes": [
    {
      "prefix": "2602:F5BB::/36",
      "family": "ipv6",
      "announced": true,
      "signed": true,
      "signature_count": 3,
      "rpki_status": "valid",
      "communities": ["65001:100"],
      "last_announced": "2026-01-18T00:00:00Z"
    },
    {
      "prefix": "23.143.36.0/24",
      "family": "ipv4",
      "announced": true,
      "signed": true,
      "signature_count": 3,
      "rpki_status": "valid",
      "communities": ["65001:100"],
      "last_announced": "2026-01-18T00:00:00Z"
    }
  ],
  "total": 2
}
```

### AnnouncePrefix

```http
POST /api/v1/sdn/bgp/transit/announce
Content-Type: application/json
```

**Request:**
```json
{
  "prefix": "2602:F5BB:0001::/48",
  "next_hop": "2602:F5BB:0001::1",
  "communities": ["65001:300"],
  "require_signing": true
}
```

**Response (201):**
```json
{
  "prefix": "2602:F5BB:0001::/48",
  "announced": true,
  "signed": true,
  "signature_count": 3,
  "rpki_status": "valid"
}
```

### WithdrawPrefix

```http
POST /api/v1/sdn/bgp/transit/withdraw
Content-Type: application/json
```

**Request:**
```json
{
  "prefix": "2602:F5BB:0001::/48"
}
```

**Response:**
```json
{
  "prefix": "2602:F5BB:0001::/48",
  "withdrawn": true
}
```

### BlackholePrefix

```http
POST /api/v1/sdn/bgp/transit/blackhole
Content-Type: application/json
```

**Request:**
```json
{
  "prefix": "2602:F5BB:0001:1000::/64",
  "reason": "DDoS mitigation"
}
```

**Response:**
```json
{
  "prefix": "2602:F5BB:0001:1000::/64",
  "blackholed": true,
  "community": "65001:666"
}
```

## RPKI Endpoints

### GetRPKIStatus

```http
GET /api/v1/sdn/bgp/rpki/status
```

**Response:**
```json
{
  "enabled": true,
  "servers": [
    {
      "address": "rpki-validator.example.com:8323",
      "state": "connected",
      "serial": 12345,
      "records": 450000,
      "last_sync": "2026-01-18T10:00:00Z"
    }
  ],
  "policy": {
    "valid_action": "accept",
    "invalid_action": "reject",
    "not_found_action": "accept"
  },
  "statistics": {
    "valid_routes": 800000,
    "invalid_routes": 150,
    "not_found_routes": 49850
  }
}
```

### ValidatePrefix

```http
GET /api/v1/sdn/bgp/rpki/validate
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `prefix` | string | Prefix to validate |
| `asn` | int | Origin ASN |

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
      "asn": 65001,
      "source": "arin"
    }
  ]
}
```

## Dampening Endpoints

### GetDampeningStatus

```http
GET /api/v1/sdn/bgp/dampening/status
```

**Response:**
```json
{
  "enabled": true,
  "config": {
    "half_life_seconds": 900,
    "suppress_threshold": 2000,
    "reuse_threshold": 750,
    "max_suppress_seconds": 3600
  },
  "suppressed_routes": 5,
  "history_paths": 150
}
```

### ListSuppressedRoutes

```http
GET /api/v1/sdn/bgp/dampening/suppressed
```

**Response:**
```json
{
  "routes": [
    {
      "prefix": "203.0.113.0/24",
      "penalty": 2500,
      "flap_count": 8,
      "suppressed_since": "2026-01-18T10:15:00Z",
      "reuse_time": "2026-01-18T10:45:00Z"
    }
  ],
  "total": 1
}
```

## Error Responses

```json
{
  "error": "peer_not_found",
  "message": "BGP peer '198.51.100.99' not found",
  "details": {
    "peer_address": "198.51.100.99"
  }
}
```

**HTTP Status Codes:**

| Status | Description |
|--------|-------------|
| 400 | Invalid request (bad prefix, invalid ASN) |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found (peer, route, prefix) |
| 409 | Conflict (peer exists) |
| 429 | Rate limited |
| 500 | Server error |

## Rate Limiting

| Endpoint Type | Requests/Min |
|---------------|--------------|
| Status read | 200 |
| Peer read | 200 |
| Peer write | 30 |
| Route read | 500 |
| Route write | 30 |
| RPKI read | 100 |

Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## curl Examples

```bash
# Get BGP status
curl -X GET https://platform.example.com/api/v1/sdn/bgp/status \
  --cert client.crt --key client.key --cacert ca.crt

# List peers
curl -X GET https://platform.example.com/api/v1/sdn/bgp/peers \
  --cert client.crt --key client.key --cacert ca.crt

# Add eBGP peer
curl -X POST https://platform.example.com/api/v1/sdn/bgp/peers \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "address": "198.51.100.1",
    "remote_asn": 64500,
    "type": "ebgp",
    "description": "ISP-Primary",
    "config": {
      "md5_secret": "secret123",
      "bfd_enabled": true
    }
  }'

# List IPv6 routes
curl -X GET "https://platform.example.com/api/v1/sdn/bgp/routes/ipv6?best=true&limit=10" \
  --cert client.crt --key client.key --cacert ca.crt

# List EVPN Type-2 routes
curl -X GET "https://platform.example.com/api/v1/sdn/bgp/evpn/routes?type=2&vni=1000100" \
  --cert client.crt --key client.key --cacert ca.crt

# Announce transit prefix
curl -X POST https://platform.example.com/api/v1/sdn/bgp/transit/announce \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "2602:F5BB:0001::/48",
    "next_hop": "2602:F5BB:0001::1",
    "require_signing": true
  }'

# Validate RPKI
curl -X GET "https://platform.example.com/api/v1/sdn/bgp/rpki/validate?prefix=2602:F5BB::/36&asn=65001" \
  --cert client.crt --key client.key --cacert ca.crt

# Reset peer (soft)
curl -X POST "https://platform.example.com/api/v1/sdn/bgp/peers/198.51.100.1/reset?soft=true" \
  --cert client.crt --key client.key --cacert ca.crt
```

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [Architecture](architecture.md)
- [EVPN](evpn.md)
- [Transit](transit.md)
- [Configuration](configuration.md)

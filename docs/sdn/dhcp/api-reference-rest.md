# DHCP REST API Reference

REST API endpoints for the DHCP service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/dhcp` |
| Port | 8443 |
| Content-Type | `application/json` |

## Status Endpoints

### GetStatus

```http
GET /api/v1/sdn/dhcp/status
```

Returns the current DHCP server status.

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
    },
    {
      "name": "eth1",
      "address": "10.0.0.1",
      "pool_id": "public-pool",
      "network": "public"
    }
  ],
  "ipam_backend": "memory",
  "uptime_seconds": 86400
}
```

### GetStats

```http
GET /api/v1/sdn/dhcp/stats
```

Returns server statistics.

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
  "release_count": 500,
  "decline_count": 5,
  "inform_count": 95,
  "error_count": 10,
  "active_leases": 245
}
```

## Lease Endpoints

### ListLeases

```http
GET /api/v1/sdn/dhcp/leases
```

Lists all active DHCP leases.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pool_id` | string | Filter by pool ID |
| `interface` | string | Filter by interface |
| `state` | string | Filter by state (active, expired, released, declined) |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "leases": [
    {
      "ip": "192.168.1.100",
      "mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "workstation-001",
      "pool_id": "internal-pool",
      "interface": "eth0",
      "client_id": "01:aa:bb:cc:dd:ee:ff",
      "vendor_class": "",
      "user_class": "",
      "leased_at": "2026-01-18T10:00:00Z",
      "expires_at": "2026-01-19T10:00:00Z",
      "renewed_at": "2026-01-18T22:00:00Z",
      "state": "active",
      "time_remaining_seconds": 43200
    },
    {
      "ip": "192.168.1.101",
      "mac": "11:22:33:44:55:66",
      "hostname": "laptop-002",
      "pool_id": "internal-pool",
      "interface": "eth0",
      "client_id": "",
      "vendor_class": "MSFT 5.0",
      "user_class": "",
      "leased_at": "2026-01-18T08:00:00Z",
      "expires_at": "2026-01-19T08:00:00Z",
      "renewed_at": "2026-01-18T08:00:00Z",
      "state": "active",
      "time_remaining_seconds": 36000
    }
  ],
  "total": 245,
  "limit": 100,
  "offset": 0
}
```

### GetLeaseByMAC

```http
GET /api/v1/sdn/dhcp/leases/mac/{mac}
```

Retrieves a lease by MAC address.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `mac` | MAC address (colon-separated) |

**Example:**
```http
GET /api/v1/sdn/dhcp/leases/mac/aa:bb:cc:dd:ee:ff
```

**Response:**
```json
{
  "ip": "192.168.1.100",
  "mac": "aa:bb:cc:dd:ee:ff",
  "hostname": "workstation-001",
  "pool_id": "internal-pool",
  "interface": "eth0",
  "client_id": "01:aa:bb:cc:dd:ee:ff",
  "vendor_class": "",
  "user_class": "",
  "leased_at": "2026-01-18T10:00:00Z",
  "expires_at": "2026-01-19T10:00:00Z",
  "renewed_at": "2026-01-18T22:00:00Z",
  "state": "active",
  "time_remaining_seconds": 43200
}
```

**Error Response (404):**
```json
{
  "error": "lease_not_found",
  "message": "No lease found for MAC aa:bb:cc:dd:ee:ff",
  "details": {
    "mac": "aa:bb:cc:dd:ee:ff"
  }
}
```

### GetLeaseByIP

```http
GET /api/v1/sdn/dhcp/leases/ip/{ip}
```

Retrieves a lease by IP address.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `ip` | IP address |

**Example:**
```http
GET /api/v1/sdn/dhcp/leases/ip/192.168.1.100
```

**Response:**
```json
{
  "ip": "192.168.1.100",
  "mac": "aa:bb:cc:dd:ee:ff",
  "hostname": "workstation-001",
  "pool_id": "internal-pool",
  "interface": "eth0",
  "client_id": "01:aa:bb:cc:dd:ee:ff",
  "leased_at": "2026-01-18T10:00:00Z",
  "expires_at": "2026-01-19T10:00:00Z",
  "renewed_at": "2026-01-18T22:00:00Z",
  "state": "active",
  "time_remaining_seconds": 43200
}
```

### ReleaseLease

```http
DELETE /api/v1/sdn/dhcp/leases/mac/{mac}
```

Releases a lease by MAC address.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `mac` | MAC address to release |

**Example:**
```http
DELETE /api/v1/sdn/dhcp/leases/mac/aa:bb:cc:dd:ee:ff
```

**Response:**
```json
{
  "released": true,
  "mac": "aa:bb:cc:dd:ee:ff",
  "ip": "192.168.1.100"
}
```

**Error Response (404):**
```json
{
  "error": "lease_not_found",
  "message": "No lease found for MAC aa:bb:cc:dd:ee:ff"
}
```

### ExpireLeases

```http
POST /api/v1/sdn/dhcp/leases/expire
```

Manually triggers expiration of old leases.

**Response:**
```json
{
  "expired_count": 5,
  "active_leases": 240
}
```

## Interface Endpoints

### ListInterfaces

```http
GET /api/v1/sdn/dhcp/interfaces
```

Lists configured DHCP interfaces.

**Response:**
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "network": "private",
      "address": "192.168.1.1",
      "pool_id": "internal-pool",
      "options": {
        "subnet_mask": "255.255.255.0",
        "router": "192.168.1.1",
        "dns": ["8.8.8.8", "8.8.4.4"],
        "domain_name": "example.local",
        "lease_time_seconds": 86400,
        "renewal_time_seconds": 43200,
        "rebind_time_seconds": 75600,
        "mtu": 1500
      },
      "active_leases": 200
    },
    {
      "name": "eth1",
      "network": "public",
      "address": "10.0.0.1",
      "pool_id": "public-pool",
      "options": {
        "subnet_mask": "255.255.255.0",
        "router": "10.0.0.1",
        "dns": ["1.1.1.1"],
        "lease_time_seconds": 28800
      },
      "active_leases": 45
    }
  ]
}
```

### GetInterface

```http
GET /api/v1/sdn/dhcp/interfaces/{name}
```

Gets configuration for a specific interface.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Interface name |

**Response:**
```json
{
  "name": "eth0",
  "network": "private",
  "address": "192.168.1.1",
  "pool_id": "internal-pool",
  "options": {
    "subnet_mask": "255.255.255.0",
    "router": "192.168.1.1",
    "dns": ["8.8.8.8", "8.8.4.4"],
    "domain_name": "example.local",
    "lease_time_seconds": 86400,
    "renewal_time_seconds": 43200,
    "rebind_time_seconds": 75600,
    "ntp_servers": ["pool.ntp.org"],
    "mtu": 1500
  },
  "active_leases": 200
}
```

### UpdateInterfaceOptions

```http
PUT /api/v1/sdn/dhcp/interfaces/{name}/options
Content-Type: application/json
```

Updates DHCP options for an interface.

**Request:**
```json
{
  "dns": ["1.1.1.1", "8.8.8.8"],
  "domain_name": "newdomain.local",
  "lease_time_seconds": 43200
}
```

**Response:**
```json
{
  "name": "eth0",
  "options": {
    "subnet_mask": "255.255.255.0",
    "router": "192.168.1.1",
    "dns": ["1.1.1.1", "8.8.8.8"],
    "domain_name": "newdomain.local",
    "lease_time_seconds": 43200,
    "renewal_time_seconds": 21600,
    "rebind_time_seconds": 37800
  },
  "updated": true
}
```

## Pool Endpoints

### GetPoolStats

```http
GET /api/v1/sdn/dhcp/pools/{pool_id}/stats
```

Gets statistics for an IPAM pool.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `pool_id` | IPAM pool ID |

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
    "released": 2,
    "declined": 0
  }
}
```

## Error Responses

### Error Format

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
| 400 | Invalid request (bad MAC, invalid IP) |
| 401 | Unauthorized (missing/invalid certificate) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found (lease, interface, pool) |
| 409 | Conflict (lease already exists) |
| 429 | Rate limited |
| 500 | Server error |
| 503 | Service unavailable (server not running) |

### Error Codes

| Code | Description |
|------|-------------|
| `lease_not_found` | No lease for specified MAC/IP |
| `invalid_mac` | Invalid MAC address format |
| `invalid_ip` | Invalid IP address format |
| `server_not_running` | DHCP server is stopped |
| `pool_exhausted` | No available IPs in pool |
| `lease_expired` | Lease has expired |
| `interface_not_found` | Network interface not found |
| `pool_not_found` | IPAM pool not found |
| `validation_error` | Request validation failed |

## Rate Limiting

| Endpoint Type | Requests/Min |
|---------------|--------------|
| Status read | 200 |
| Lease list | 200 |
| Lease get | 200 |
| Lease release | 60 |
| Interface read | 200 |
| Interface write | 30 |
| Pool read | 100 |

Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## curl Examples

```bash
# Get DHCP server status
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/status \
  --cert client.crt --key client.key --cacert ca.crt

# Get server statistics
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/stats \
  --cert client.crt --key client.key --cacert ca.crt

# List all leases
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/leases \
  --cert client.crt --key client.key --cacert ca.crt

# List leases for a pool
curl -X GET "https://platform.example.com/api/v1/sdn/dhcp/leases?pool_id=internal-pool&limit=50" \
  --cert client.crt --key client.key --cacert ca.crt

# Get lease by MAC
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/leases/mac/aa:bb:cc:dd:ee:ff \
  --cert client.crt --key client.key --cacert ca.crt

# Get lease by IP
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/leases/ip/192.168.1.100 \
  --cert client.crt --key client.key --cacert ca.crt

# Release a lease
curl -X DELETE https://platform.example.com/api/v1/sdn/dhcp/leases/mac/aa:bb:cc:dd:ee:ff \
  --cert client.crt --key client.key --cacert ca.crt

# Expire old leases
curl -X POST https://platform.example.com/api/v1/sdn/dhcp/leases/expire \
  --cert client.crt --key client.key --cacert ca.crt

# List interfaces
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/interfaces \
  --cert client.crt --key client.key --cacert ca.crt

# Get interface details
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/interfaces/eth0 \
  --cert client.crt --key client.key --cacert ca.crt

# Update interface options
curl -X PUT https://platform.example.com/api/v1/sdn/dhcp/interfaces/eth0/options \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "dns": ["1.1.1.1"],
    "lease_time_seconds": 43200
  }'

# Get pool statistics
curl -X GET https://platform.example.com/api/v1/sdn/dhcp/pools/internal-pool/stats \
  --cert client.crt --key client.key --cacert ca.crt
```

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [API Overview](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)

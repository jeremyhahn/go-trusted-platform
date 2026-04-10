# VXLAN Overlay REST API Reference

REST API endpoints for the VXLAN overlay service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/overlay` |
| Port | 8443 |
| Content-Type | `application/json` |

## VTEP Endpoints

### ListVTEPs

```http
GET /api/v1/sdn/overlay/vteps
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `healthy` | bool | Filter by health status |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "vteps": [
    {
      "ip": "10.0.0.1",
      "node_id": "node-001",
      "underlay_iface": "eth0",
      "underlay_mtu": 9000,
      "vxlan_port": 4789,
      "active_vnis": [1000100, 1000200],
      "healthy": true,
      "last_heartbeat": "2026-01-18T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetVTEP

```http
GET /api/v1/sdn/overlay/vteps/{ip}
```

**Response:**
```json
{
  "ip": "10.0.0.1",
  "node_id": "node-001",
  "underlay_iface": "eth0",
  "underlay_mtu": 9000,
  "vxlan_port": 4789,
  "active_vnis": [1000100, 1000200],
  "healthy": true,
  "last_heartbeat": "2026-01-18T10:30:00Z"
}
```

### RegisterVTEP

```http
POST /api/v1/sdn/overlay/vteps
Content-Type: application/json
```

**Request:**
```json
{
  "ip": "10.0.0.1",
  "underlay_iface": "eth0",
  "underlay_mtu": 9000,
  "vxlan_port": 4789
}
```

**Response (201):**
```json
{
  "ip": "10.0.0.1",
  "node_id": "node-001",
  "underlay_iface": "eth0",
  "underlay_mtu": 9000,
  "vxlan_port": 4789,
  "active_vnis": [],
  "healthy": true,
  "last_heartbeat": "2026-01-18T10:30:00Z"
}
```

### DeregisterVTEP

```http
DELETE /api/v1/sdn/overlay/vteps/{ip}
```

**Response:**
```json
{
  "deleted": true,
  "vtep_ip": "10.0.0.1"
}
```

### HealthCheckVTEP

```http
GET /api/v1/sdn/overlay/vteps/{ip}/health
```

**Response:**
```json
{
  "ip": "10.0.0.1",
  "healthy": true,
  "latency_ms": 2,
  "last_check": "2026-01-18T10:30:00Z",
  "uptime_seconds": 86400,
  "tunnel_count": 3,
  "error": null
}
```

## VNI Endpoints

### ListVNIs

```http
GET /api/v1/sdn/overlay/vnis
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `vlan_id` | int | Filter by VLAN ID |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "vnis": [
    {
      "id": 1000100,
      "vlan_id": 100,
      "member_vteps": ["10.0.0.1", "10.0.0.2"],
      "multicast_group": "239.1.1.100",
      "local_ports": ["veth-vm1", "veth-vm2"],
      "mac_count": 25
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetVNI

```http
GET /api/v1/sdn/overlay/vnis/{id}
```

**Response:**
```json
{
  "id": 1000100,
  "vlan_id": 100,
  "member_vteps": ["10.0.0.1", "10.0.0.2"],
  "multicast_group": "239.1.1.100",
  "local_ports": ["veth-vm1", "veth-vm2"],
  "mac_count": 25
}
```

### CreateVNI

```http
POST /api/v1/sdn/overlay/vnis
Content-Type: application/json
```

**Request:**
```json
{
  "id": 1000100,
  "vlan_id": 100,
  "multicast_group": "239.1.1.100"
}
```

**Response (201):**
```json
{
  "id": 1000100,
  "vlan_id": 100,
  "member_vteps": [],
  "multicast_group": "239.1.1.100",
  "local_ports": [],
  "mac_count": 0
}
```

### DeleteVNI

```http
DELETE /api/v1/sdn/overlay/vnis/{id}
```

**Response:**
```json
{
  "deleted": true,
  "vni_id": 1000100
}
```

### ListVNIMembers

```http
GET /api/v1/sdn/overlay/vnis/{id}/members
```

**Response:**
```json
{
  "vni_id": 1000100,
  "members": [
    {
      "vtep_ip": "10.0.0.1",
      "node_id": "node-001",
      "joined_at": "2026-01-18T08:00:00Z"
    },
    {
      "vtep_ip": "10.0.0.2",
      "node_id": "node-002",
      "joined_at": "2026-01-18T08:15:00Z"
    }
  ]
}
```

### JoinVNI

```http
POST /api/v1/sdn/overlay/vnis/{id}/join
```

**Response:**
```json
{
  "vni_id": 1000100,
  "vtep_ip": "10.0.0.1",
  "joined": true
}
```

### LeaveVNI

```http
POST /api/v1/sdn/overlay/vnis/{id}/leave
```

**Response:**
```json
{
  "vni_id": 1000100,
  "vtep_ip": "10.0.0.1",
  "left": true
}
```

## Tunnel Endpoints

### ListTunnels

```http
GET /api/v1/sdn/overlay/tunnels
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `state` | string | Filter by state (active, unhealthy, failed) |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "tunnels": [
    {
      "id": "tunnel-10.0.0.1-10.0.0.2",
      "local_vtep": "10.0.0.1",
      "remote_vtep": "10.0.0.2",
      "vnis": [1000100, 1000200],
      "ovs_port": "vxlan-10.0.0.2",
      "of_port": 10,
      "state": "active",
      "last_check": "2026-01-18T10:29:55Z",
      "rtt": "1.5ms"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetTunnel

```http
GET /api/v1/sdn/overlay/tunnels/{remote_vtep}
```

**Response:**
```json
{
  "id": "tunnel-10.0.0.1-10.0.0.2",
  "local_vtep": "10.0.0.1",
  "remote_vtep": "10.0.0.2",
  "vnis": [1000100, 1000200],
  "ovs_port": "vxlan-10.0.0.2",
  "of_port": 10,
  "state": "active",
  "last_check": "2026-01-18T10:29:55Z",
  "rtt": "1.5ms",
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

### CreateTunnel

```http
POST /api/v1/sdn/overlay/tunnels
Content-Type: application/json
```

**Request:**
```json
{
  "remote_vtep": "10.0.0.2",
  "vnis": [1000100, 1000200]
}
```

**Response (201):**
```json
{
  "id": "tunnel-10.0.0.1-10.0.0.2",
  "local_vtep": "10.0.0.1",
  "remote_vtep": "10.0.0.2",
  "vnis": [1000100, 1000200],
  "ovs_port": "vxlan-10.0.0.2",
  "of_port": 10,
  "state": "active",
  "last_check": "2026-01-18T10:30:00Z",
  "rtt": "1.2ms"
}
```

### DeleteTunnel

```http
DELETE /api/v1/sdn/overlay/tunnels/{remote_vtep}
```

**Response:**
```json
{
  "deleted": true,
  "remote_vtep": "10.0.0.2"
}
```

### GetTunnelStats

```http
GET /api/v1/sdn/overlay/tunnels/{remote_vtep}/stats
```

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
    "rx_errors": 0,
    "tx_drops": 0,
    "rx_drops": 5
  },
  "collected_at": "2026-01-18T10:30:00Z"
}
```

## MAC Table Endpoints

### ListMACs

```http
GET /api/v1/sdn/overlay/macs
GET /api/v1/sdn/overlay/macs/{vni}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by type (local, remote, static) |
| `limit` | int | Max results (default 1000) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "vni": 1000100,
  "macs": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "vni": 1000100,
      "vtep_ip": "10.0.0.2",
      "port_id": "",
      "type": "remote",
      "learned_at": "2026-01-18T09:00:00Z",
      "expires_at": "2026-01-18T09:05:00Z"
    },
    {
      "mac": "11:22:33:44:55:66",
      "vni": 1000100,
      "vtep_ip": "10.0.0.1",
      "port_id": "veth-vm1",
      "type": "local",
      "learned_at": "2026-01-18T08:00:00Z",
      "expires_at": "2026-01-18T08:05:00Z"
    }
  ],
  "total": 2,
  "limit": 1000,
  "offset": 0
}
```

### GetMAC

```http
GET /api/v1/sdn/overlay/macs/{vni}/{mac}
```

**Response:**
```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "vni": 1000100,
  "vtep_ip": "10.0.0.2",
  "port_id": "",
  "type": "remote",
  "learned_at": "2026-01-18T09:00:00Z",
  "expires_at": "2026-01-18T09:05:00Z"
}
```

### LearnMAC

```http
POST /api/v1/sdn/overlay/macs/{vni}
Content-Type: application/json
```

**Request:**
```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "vtep_ip": "10.0.0.2",
  "type": "static"
}
```

**Response (201):**
```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "vni": 1000100,
  "vtep_ip": "10.0.0.2",
  "type": "static",
  "learned_at": "2026-01-18T10:30:00Z"
}
```

### DeleteMAC

```http
DELETE /api/v1/sdn/overlay/macs/{vni}/{mac}
```

**Response:**
```json
{
  "deleted": true,
  "vni": 1000100,
  "mac": "aa:bb:cc:dd:ee:ff"
}
```

### FlushMACs

```http
DELETE /api/v1/sdn/overlay/macs/{vni}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by type (all, remote, local) |

**Response:**
```json
{
  "flushed": true,
  "vni": 1000100,
  "count": 25
}
```

## Error Responses

```json
{
  "error": "vtep_not_found",
  "message": "VTEP '10.0.0.99' not found",
  "details": {
    "vtep_ip": "10.0.0.99"
  }
}
```

**HTTP Status Codes:**

| Status | Description |
|--------|-------------|
| 400 | Invalid request (bad VNI range, invalid IP) |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found (VTEP, VNI, tunnel, MAC) |
| 409 | Conflict (VTEP exists, VNI exists) |
| 429 | Rate limited |
| 500 | Server error |
| 503 | Underlay unreachable |

## Rate Limiting

| Endpoint Type | Requests/Min |
|---------------|--------------|
| VTEP read | 200 |
| VTEP write | 30 |
| VNI read | 200 |
| VNI write | 60 |
| Tunnel read | 200 |
| Tunnel write | 30 |
| MAC read | 1000 |
| MAC write | 100 |

Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## curl Examples

```bash
# List VTEPs
curl -X GET https://platform.example.com/api/v1/sdn/overlay/vteps \
  --cert client.crt --key client.key --cacert ca.crt

# Register VTEP
curl -X POST https://platform.example.com/api/v1/sdn/overlay/vteps \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.1","underlay_iface":"eth0","underlay_mtu":9000,"vxlan_port":4789}'

# Create VNI
curl -X POST https://platform.example.com/api/v1/sdn/overlay/vnis \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"id":1000100,"vlan_id":100}'

# Join VNI
curl -X POST https://platform.example.com/api/v1/sdn/overlay/vnis/1000100/join \
  --cert client.crt --key client.key --cacert ca.crt

# Create tunnel
curl -X POST https://platform.example.com/api/v1/sdn/overlay/tunnels \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"remote_vtep":"10.0.0.2","vnis":[1000100,1000200]}'

# Get tunnel stats
curl -X GET https://platform.example.com/api/v1/sdn/overlay/tunnels/10.0.0.2/stats \
  --cert client.crt --key client.key --cacert ca.crt

# List MACs for VNI
curl -X GET https://platform.example.com/api/v1/sdn/overlay/macs/1000100 \
  --cert client.crt --key client.key --cacert ca.crt

# Add static MAC
curl -X POST https://platform.example.com/api/v1/sdn/overlay/macs/1000100 \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{"mac":"aa:bb:cc:dd:ee:ff","vtep_ip":"10.0.0.2","type":"static"}'

# Flush VNI MACs
curl -X DELETE https://platform.example.com/api/v1/sdn/overlay/macs/1000100?type=remote \
  --cert client.crt --key client.key --cacert ca.crt
```

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [Architecture](architecture.md)
- [Configuration](configuration.md)

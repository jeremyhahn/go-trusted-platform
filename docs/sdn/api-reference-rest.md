# SDN REST API Reference

Base URL: `https://localhost:8443/api/v1/sdn`

All endpoints require mTLS authentication.

## Bridge Operations

### Create Bridge

```http
POST /bridges
Content-Type: application/json

{
  "name": "br0"
}
```

Response (201):
```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "br0"
}
```

### Get Bridge

```http
GET /bridges/{name}
```

Response (200):
```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "br0"
}
```

### Delete Bridge

```http
DELETE /bridges/{name}
```

Response (204): No content

### List Bridges

```http
GET /bridges
```

Response (200):
```json
{
  "bridges": [
    {"uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "br0"},
    {"uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "name": "br1"}
  ]
}
```

## Port Operations

### Add Port

```http
POST /bridges/{bridge}/ports
Content-Type: application/json

{
  "name": "eth0"
}
```

Response (201):
```json
{
  "uuid": "c3d4e5f6-a7b8-9012-cdef-234567890123",
  "name": "eth0",
  "interfaces": ["eth0"]
}
```

### Delete Port

```http
DELETE /bridges/{bridge}/ports/{port}
```

Response (204): No content

### Get Port State

```http
GET /ports/{port}/state
```

Response (200):
```json
{
  "port": "eth0",
  "state": "up",
  "of_port": 1
}
```

### Set Port State

```http
PUT /ports/{port}/state
Content-Type: application/json

{
  "state": "down"
}
```

Response (200):
```json
{
  "port": "eth0",
  "state": "down"
}
```

### Get Port Stats

```http
GET /ports/{port}/stats
```

Response (200):
```json
{
  "port": "eth0",
  "rx_packets": 1000,
  "tx_packets": 950,
  "rx_bytes": 102400,
  "tx_bytes": 97280,
  "rx_errors": 0,
  "tx_errors": 0
}
```

## Flow Operations

### Add Flow

```http
POST /bridges/{bridge}/flows
Content-Type: application/json

{
  "priority": 100,
  "match": {
    "in_port": 1,
    "eth_type": 2048,
    "ipv4_dst": "10.0.0.0/24"
  },
  "actions": [
    {"type": "output", "port": 2}
  ],
  "idle_timeout": 0,
  "hard_timeout": 0
}
```

Response (201):
```json
{
  "cookie": 12345678901234567890,
  "priority": 100
}
```

### Delete Flow

```http
DELETE /bridges/{bridge}/flows
Content-Type: application/json

{
  "match": {
    "in_port": 1,
    "eth_type": 2048
  }
}
```

Response (204): No content

### List Flows

```http
GET /bridges/{bridge}/flows
```

Response (200):
```json
{
  "flows": [
    {
      "priority": 100,
      "match": {"in_port": 1},
      "actions": [{"type": "output", "port": 2}],
      "packet_count": 1000,
      "byte_count": 102400
    }
  ]
}
```

## VLAN Operations

### Create VLAN

```http
POST /vlans
Content-Type: application/json

{
  "vlan_id": 100,
  "name": "tenant-a"
}
```

Response (201):
```json
{
  "vlan_id": 100,
  "name": "tenant-a"
}
```

### Delete VLAN

```http
DELETE /vlans/{vlan_id}
```

Response (204): No content

### List VLANs

```http
GET /vlans
```

Response (200):
```json
{
  "vlans": [
    {"vlan_id": 100, "name": "tenant-a"},
    {"vlan_id": 200, "name": "tenant-b"}
  ]
}
```

## Policy Operations

### Apply Policy

```http
POST /ports/{port}/policy
Content-Type: application/json

{
  "tenant_id": "tenant-a",
  "vlan": 100,
  "acls": [
    {
      "priority": 100,
      "match": {"ipv4_dst": "0.0.0.0/0"},
      "action": {"type": "allow"}
    }
  ]
}
```

Response (200):
```json
{
  "port": "eth0",
  "tenant_id": "tenant-a",
  "vlan": 100
}
```

### Get Policy

```http
GET /ports/{port}/policy
```

Response (200):
```json
{
  "tenant_id": "tenant-a",
  "vlan": 100,
  "acls": [
    {
      "priority": 100,
      "match": {"ipv4_dst": "0.0.0.0/0"},
      "action": {"type": "allow"}
    }
  ],
  "expires_at": "2026-12-31T23:59:59Z"
}
```

### List Policies

```http
GET /policies
```

Response (200):
```json
{
  "policies": [
    {"port": "eth0", "tenant_id": "tenant-a", "vlan": 100},
    {"port": "eth1", "tenant_id": "tenant-b", "vlan": 200}
  ]
}
```

## Error Responses

All errors return:
```json
{
  "error": {
    "code": "BRIDGE_NOT_FOUND",
    "message": "Bridge br0 not found"
  }
}
```

HTTP status codes:
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 409: Conflict (e.g., bridge exists)
- 500: Internal Server Error

## Network Zone API

Base path: `/api/v1/sdn/zones`

### POST /api/v1/sdn/zones

Create a new network trust zone.

**Request body:**
```json
{
  "name": "dmz",
  "internet_ingress": true,
  "isolate": false,
  "isolate_per_tenant": false,
  "oob": false,
  "lifecycle_role": ""
}
```

**Response 201:**
```json
{
  "name": "dmz",
  "internet_ingress": true,
  "restart_required": false,
  "created_at": "2026-06-12T00:00:00Z",
  "updated_at": "2026-06-12T00:00:00Z"
}
```

### GET /api/v1/sdn/zones

List all network trust zones. Optional `lifecycle_role` query parameter filters results.

**Query parameters:**
- `lifecycle_role` — `provisioning` or `quarantine` (empty returns all)

**Response 200:**
```json
{
  "zones": [
    {
      "name": "trusted",
      "isolate": false,
      "created_at": "2026-06-12T00:00:00Z",
      "updated_at": "2026-06-12T00:00:00Z"
    }
  ],
  "count": 1,
  "timestamp": "2026-06-12T00:00:00Z"
}
```

### PUT /api/v1/sdn/zones/{name}

Update policy settings of an existing zone.

**Request body:** same fields as create (except `name`).

**Response 200:** zone object with `restart_required` set when flow matrix
must be rebuilt.

### DELETE /api/v1/sdn/zones/{name}

Delete a zone by name. Fails when the zone is the sole holder of a required
lifecycle role.

**Response 200:**
```json
{"deleted": true, "restart_required": false}
```

### PUT /api/v1/sdn/networks/{network}/zone

Assign a network segment to a trust zone.

**Request body:**
```json
{"zone": "trusted"}
```

**Response 200:**
```json
{"success": true, "restart_required": true}
```

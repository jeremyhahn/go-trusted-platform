# DNS REST API Reference

REST API endpoints for the DNS service.

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/dns` |
| Port | 8443 |
| Content-Type | `application/json` |

## Zone Endpoints

### ListZones

```http
GET /api/v1/dns/zones
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `internal` | bool | Filter by internal/public |
| `limit` | int | Max results (default 100) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "zones": [
    {
      "id": 1234567890,
      "name": "example.internal.",
      "ttl": 3600,
      "internal": true
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### GetZone

```http
GET /api/v1/dns/zones/{zoneName}
```

**Response:**
```json
{
  "id": 1234567890,
  "name": "example.internal.",
  "ttl": 3600,
  "description": "Internal zone",
  "internal": true,
  "records": {
    "soa": {...},
    "a": [...],
    "ns": [...]
  }
}
```

### CreateZone

```http
POST /api/v1/dns/zones
Content-Type: application/json
```

**Request:**
```json
{
  "name": "myzone.internal.",
  "ttl": 3600,
  "description": "My zone",
  "internal": true,
  "records": {
    "soa": {
      "name": "myzone.internal.",
      "mname": "ns1.myzone.internal.",
      "rname": "hostmaster.myzone.internal.",
      "serial": 1,
      "refresh": 86400,
      "retry": 7200,
      "expire": 86400,
      "min_ttl": 3600,
      "ttl": 3600
    },
    "ns": [
      {"name": "myzone.internal.", "value": "ns1.myzone.internal.", "ttl": 3600}
    ]
  }
}
```

### UpdateZone

```http
PUT /api/v1/dns/zones/{zoneName}
Content-Type: application/json
```

**Request:**
```json
{
  "ttl": 7200,
  "description": "Updated description"
}
```

### DeleteZone

```http
DELETE /api/v1/dns/zones/{zoneName}
```

**Response:**
```json
{
  "deleted": true,
  "zone_name": "myzone.internal."
}
```

## Record Endpoints

### ListRecords

```http
GET /api/v1/dns/zones/{zoneName}/records
GET /api/v1/dns/zones/{zoneName}/records?type=A
```

**Response:**
```json
{
  "zone_name": "example.internal.",
  "records": {
    "a": [{"name": "ns1", "value": "192.168.1.10", "ttl": 3600}],
    "cname": [{"name": "www", "value": "example.internal.", "ttl": 3600}]
  }
}
```

### GetRecord

```http
GET /api/v1/dns/zones/{zoneName}/records/{type}/{name}
```

**Example:**
```http
GET /api/v1/dns/zones/example.internal./records/A/ns1
```

**Response:**
```json
{
  "type": "A",
  "name": "ns1",
  "value": "192.168.1.10",
  "ttl": 3600
}
```

### AddRecord

```http
POST /api/v1/dns/zones/{zoneName}/records
Content-Type: application/json
```

**A Record:**
```json
{
  "type": "A",
  "name": "server01",
  "value": "192.168.1.100",
  "ttl": 3600
}
```

**MX Record:**
```json
{
  "type": "MX",
  "name": "@",
  "value": "mail.example.internal.",
  "priority": 10,
  "ttl": 3600
}
```

**SRV Record:**
```json
{
  "type": "SRV",
  "name": "_ldap._tcp",
  "target": "ldap.example.internal.",
  "port": 389,
  "priority": 10,
  "weight": 100,
  "ttl": 3600
}
```

### UpdateRecord

```http
PUT /api/v1/dns/zones/{zoneName}/records/{type}/{name}
Content-Type: application/json
```

**Request:**
```json
{
  "value": "192.168.1.101",
  "ttl": 7200
}
```

### DeleteRecord

```http
DELETE /api/v1/dns/zones/{zoneName}/records/{type}/{name}
```

## TLSA/DANE Endpoint

### AddTLSARecord

```http
POST /api/v1/dns/zones/{zoneName}/records
Content-Type: application/json
```

**Request:**
```json
{
  "type": "TLSA",
  "name": "_443._tcp.www",
  "usage": 3,
  "selector": 1,
  "matching_type": 1,
  "certificate": "base64-encoded-cert-data",
  "ttl": 3600
}
```

## Resolution Endpoint

### Resolve

```http
GET /api/v1/dns/resolve?name={fqdn}&type={type}
```

**Example:**
```http
GET /api/v1/dns/resolve?name=ns1.example.internal.&type=A
```

**Response:**
```json
{
  "name": "ns1.example.internal.",
  "type": "A",
  "ttl": 3600,
  "answers": [
    {"value": "192.168.1.10"}
  ]
}
```

## Error Responses

```json
{
  "error": "zone_not_found",
  "message": "Zone 'nonexistent.internal.' not found",
  "details": {
    "zone_name": "nonexistent.internal."
  }
}
```

**HTTP Status Codes:**

| Status | Description |
|--------|-------------|
| 400 | Invalid request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 409 | Conflict |
| 429 | Rate limited |
| 500 | Server error |

## Rate Limiting

| Endpoint | Requests/Min |
|----------|--------------|
| Zone read | 100 |
| Zone write | 30 |
| Record read | 200 |
| Record write | 60 |

Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## curl Examples

```bash
# List zones
curl -X GET https://platform.example.com/api/v1/dns/zones \
  -H "Authorization: Bearer $TOKEN"

# Create zone
curl -X POST https://platform.example.com/api/v1/dns/zones \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"myzone.internal.","ttl":3600,"internal":true,...}'

# Add record
curl -X POST https://platform.example.com/api/v1/dns/zones/myzone.internal./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"A","name":"server01","value":"192.168.1.100","ttl":3600}'

# Resolve
curl -X GET "https://platform.example.com/api/v1/dns/resolve?name=ns1.example.internal.&type=A" \
  -H "Authorization: Bearer $TOKEN"
```

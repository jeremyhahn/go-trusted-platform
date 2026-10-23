# DNS REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `/api/v1/dns` routes as served by `pkg/webservice/v1/rest/dns/`. The
> cross-transport matrix and authorization are [api.md](api.md).

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/dns` |
| Port | 8443 |
| Content-Type | `application/json` |
| Authorization | authenticated caller holding the `admin` role, on every route |

Every response is the platform envelope; the bodies below are its `payload`:

```json
{"code": 200, "error": "", "success": true, "payload": { ... }}
```

## Routes

| Method | Path | Handler |
|--------|------|---------|
| `POST` | `/zones` | CreateZone |
| `GET` | `/zones` | ListZones |
| `GET` | `/zones/{zone}` | GetZone |
| `PUT` | `/zones/{zone}` | UpdateZone |
| `DELETE` | `/zones/{zone}` | DeleteZone |
| `POST` | `/zones/{zone}/records` | AddRecord |
| `GET` | `/zones/{zone}/records` | ListRecords |
| `GET` | `/zones/{zone}/records/{type}/{name}` | GetRecord |
| `DELETE` | `/zones/{zone}/records/{type}/{name}` | DeleteRecord |
| `GET` | `/resolve` | Resolve |
| `POST` | `/zones/{zone}/sign` | SignZone |
| `GET` | `/zones/{zone}/dnssec` | GetDNSSECStatus |
| `POST` | `/register` | Register |

There is no update-record route ([api.md](api.md) §2): delete the record and
add it again.

## Zones

### CreateZone

```http
POST /api/v1/dns/zones
```

```json
{
  "name": "myzone.internal.",
  "ttl": 3600,
  "description": "My zone",
  "internal": true,
  "soa": {
    "name": "myzone.internal.",
    "mname": "ns1.myzone.internal.",
    "rname": "hostmaster.myzone.internal.",
    "serial": 1,
    "refresh": 86400,
    "retry": 7200,
    "expire": 86400,
    "minimum_ttl": 3600,
    "ttl": 3600
  },
  "ns_records": [
    {"name": "myzone.internal.", "value": "ns1.myzone.internal.", "ttl": 3600}
  ]
}
```

Only `name` is required. The response is the zone. There is no conflict
check: creating a name that already exists saves over it.

### ListZones

```http
GET /api/v1/dns/zones?internal=true
```

`internal=true` keeps internal zones, `public=true` keeps public ones.

```json
{
  "total": 1,
  "limit": 50,
  "offset": 0,
  "zones": [
    {"id": 1234567890, "name": "example.internal.", "ttl": 3600, "internal": true, "records": { ... }}
  ]
}
```

`limit` (default 50, at most 1000) and `offset` page the matching zones and
are echoed back; `total` counts every matching zone, not the page.

### GetZone, UpdateZone, DeleteZone

`GET /api/v1/dns/zones/{zone}` returns the zone: `id`, `name`, `ttl`,
`description`, `internal`, `created_at`, `updated_at` and `records`, which
holds `soa` plus one list per type (`a`, `aaaa`, `cname`, `mx`, `ns`, `txt`,
`srv`, `caa`, `tlsa`, `dnskey`, `ds`).

`PUT /api/v1/dns/zones/{zone}` takes `{"ttl": 7200, "description": "..."}`
and returns the zone.

`DELETE /api/v1/dns/zones/{zone}` returns
`{"success": true, "message": "zone deleted successfully"}`.

## Records

### AddRecord

```http
POST /api/v1/dns/zones/{zone}/records
```

The body names the type and carries the record under that type's key:

```json
{"type": "A", "a": {"name": "server01", "value": "192.0.2.100", "ttl": 3600}}
```

```json
{"type": "MX", "mx": {"name": "@", "value": "mail.example.internal.", "priority": 10, "ttl": 3600}}
```

```json
{"type": "SRV", "srv": {"name": "_ldap._tcp", "target": "ldap.example.internal.", "port": 389, "priority": 10, "weight": 100, "ttl": 3600}}
```

```json
{"type": "TLSA", "tlsa": {"name": "_443._tcp.www", "usage": 3, "selector": 1, "matching_type": 1, "data": "<hex digest>", "ttl": 3600}}
```

Accepted types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SRV`, `CAA`, `TLSA`.
The response is the updated zone.

### ListRecords, GetRecord, DeleteRecord

`GET /api/v1/dns/zones/{zone}/records` returns `{"records": [ ... ]}`, each
entry in the AddRecord shape; `?type=A` filters.

`GET /api/v1/dns/zones/{zone}/records/{type}/{name}` returns that one record,
or 404 when the zone holds no record of that type and name.

`DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}` removes it and returns
the updated zone.

## Resolution

```http
GET /api/v1/dns/resolve?fqdn={fqdn}&type={type}
```

`fqdn` is required (400 without it); `type` is optional and filters. The
longest managed zone suffix of `fqdn` answers with only the records `fqdn`
owns ([resolution.md](resolution.md#api-resolve)). `records` is `[]` when
nothing matches: `authoritative` is then `true` inside a managed zone and
`false` outside every one. A `type` resolution does not serve is a 400.

```json
{
  "records": [
    {"type": "A", "a": {"name": "ns1", "value": "192.0.2.10", "ttl": 3600}}
  ],
  "authoritative": true
}
```

## DNSSEC

`POST /api/v1/dns/zones/{zone}/sign` signs the zone and returns it.
`GET /api/v1/dns/zones/{zone}/dnssec` returns `enabled`, `zone_signed`, `keys`
and `ds_records`.

## Registration

```http
POST /api/v1/dns/register
```

```json
{"fqdn": "newhost.example.internal", "ip": "192.0.2.50"}
```

Returns `{"success": true, "message": "registration successful", "zone": { ... }}`.
Registration checks only that the zone name is free ([api.md](api.md) §6).

## Errors

On failure the envelope carries `success: false`, `code` set to the HTTP
status and `error` set to the message.

| Status | Cause |
|--------|-------|
| 400 | Malformed body, missing zone name, record type, record name, `fqdn` or `ip`, or an unsupported record type |
| 401 | Not authenticated |
| 403 | Caller lacks the `admin` role |
| 404 | Unknown zone or record |
| 500 | Store, signing or registration failure |
| 503 | No DNS backend: the daemon has no `dns:` section (code `SERVICE_NOT_CONFIGURED`) |

## curl Examples

```bash
# List zones
curl https://platform.example.com:8443/api/v1/dns/zones \
  -H "Authorization: Bearer $TOKEN"

# Add a record
curl -X POST https://platform.example.com:8443/api/v1/dns/zones/myzone.internal./records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"A","a":{"name":"server01","value":"192.0.2.100","ttl":3600}}'

# Resolve
curl "https://platform.example.com:8443/api/v1/dns/resolve?fqdn=ns1.example.internal.&type=A" \
  -H "Authorization: Bearer $TOKEN"
```

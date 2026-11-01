# DNS REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-26
> The `/api/v1/dns` routes as served by `pkg/webservice/v1/rest/dns/`. The
> cross-transport matrix and authorization are [api.md](api.md).

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/dns` |
| Port | 8443 |
| Content-Type | `application/json` |
| Authorization | webservice: authenticated caller holding the `admin` role, on every route; daemon REST listener: the `dns:read`, `dns:write` or `dns:delete` scope the gRPC catalog gives the rpc ([daemon api.md](../daemon/api.md)) |

Every route serves the `DNSService` proto messages
(`pkg/api/grpc/proto/platform_dns.proto`) in protojson, the shape gRPC and the
SDK carry: the handlers decode the RPC's request message and call the same
`DNSServiceServer` gRPC does (`Daemon.DNSGRPCServiceServer`). Field names are
lowerCamelCase (`zoneName`, `aRecords`); the proto names (`zone_name`) are
accepted on input. Enums are their names (`RECORD_TYPE_A`). Unknown fields are
ignored. Every field is emitted, so an empty list is `[]`, never absent.

Every response is the platform envelope; the bodies below are its `payload`:

```json
{"code": 200, "error": "", "success": true, "payload": { ... }}
```

## Routes

| Method | Path | RPC | Request from the path and query |
|--------|------|-----|------|
| `POST` | `/zones` | `CreateZone` | — |
| `GET` | `/zones` | `ListZones` | `internal`, `public`, `page`, `page_size` |
| `GET` | `/zones/{zone}` | `GetZone` | `name` |
| `PUT` | `/zones/{zone}` | `UpdateZone` | `name` |
| `DELETE` | `/zones/{zone}` | `DeleteZone` | `name` |
| `POST` | `/zones/{zone}/records` | `AddRecord` | `zoneName` |
| `PUT` | `/zones/{zone}/records` | `UpdateRecord` | `zoneName` |
| `GET` | `/zones/{zone}/records` | `ListRecords` | `zoneName`, `type`, `page`, `page_size` |
| `GET` | `/zones/{zone}/records/{type}/{name}` | — (one `Record`, from `ListRecords`) | |
| `DELETE` | `/zones/{zone}/records/{type}/{name}` | `DeleteRecord` | `zoneName`, `type`, `name` |
| `GET` | `/resolve` | `Resolve` | `fqdn`, `type` |
| `POST` | `/zones/{zone}/sign` | `SignZone` | `zoneName` |
| `GET` | `/zones/{zone}/dnssec` | `GetDNSSECStatus` | `zoneName` |
| `POST` | `/register` | `Register` | — |

The path and query values overwrite the body's. A `type` in the path or query
is a mnemonic (`A`, `AAAA`, `MX`) or an enum name (`RECORD_TYPE_A`), in any
case; any other value is a 400.

## Zones

### CreateZone

```http
POST /api/v1/dns/zones
```

`CreateZoneRequest`:

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
    "minimumTtl": 3600,
    "ttl": 3600
  },
  "nsRecords": [
    {"name": "myzone.internal.", "value": "ns1.myzone.internal.", "ttl": 3600}
  ]
}
```

Only `name` is required. The response is `CreateZoneResponse`,
`{"status": {"success": true, "message": "..."}, "zone": { ... }}`. There is
no conflict check: creating a name that already exists saves over it.

A `Zone` is `id`, `name`, `ttl`, `description`, `internal` and `records`, a
`RecordSet`: `soa` plus one list per type (`aRecords`, `aaaaRecords`,
`cnameRecords`, `mxRecords`, `nsRecords`, `txtRecords`, `srvRecords`,
`caaRecords`, `tlsaRecords`, `dnskeyRecords`, `dsRecords`, `rrsigRecords`,
`nsecRecords`, `nsec3Records`, `nsec3paramRecords`). An unset message field
(`records`, `soa`) is `null`. The zone carries no timestamps.

The web console reads these messages typed as the SDK's `Zone`,
`ListZonesResponse` and `GetZoneResponse` (`web/src/lib/dns-wire.ts`); until
#445 it read them untyped, accepting both the lowercase per-type keys the old
REST document used (`a`, `mx`, `soa`) and the camelCase ones.

### ListZones

```http
GET /api/v1/dns/zones?internal=true&page=1&page_size=50
```

`internal=true` sets `internalOnly`, `public=true` sets `publicOnly`.
`page` (from 1) and `page_size` page the matching zones; without a
`page_size` every zone comes back as one page.

```json
{
  "zones": [
    {"id": "1234567890", "name": "example.internal.", "ttl": 3600, "description": "", "internal": true, "records": { ... }}
  ],
  "pagination": {"page": 1, "pageSize": 50, "totalPages": 1, "totalItems": "1"}
}
```

`id` and `totalItems` are 64-bit, so protojson writes them as strings.

### GetZone, UpdateZone, DeleteZone

`GET /api/v1/dns/zones/{zone}` returns `GetZoneResponse`, `{"zone": { ... }}`.

`PUT /api/v1/dns/zones/{zone}` takes `UpdateZoneRequest`,
`{"ttl": 7200, "description": "..."}`, and returns `{"status", "zone"}`.

`DELETE /api/v1/dns/zones/{zone}` returns
`{"status": {"success": true, "message": "zone deleted successfully"}}`.

## Records

A `Record` names its type and carries the record under that type's key:

```json
{"type": "RECORD_TYPE_A", "a": {"name": "server01", "value": "192.0.2.100", "ttl": 3600}}
```

```json
{"type": "RECORD_TYPE_MX", "mx": {"name": "@", "value": "mail.example.internal.", "priority": 10, "ttl": 3600}}
```

```json
{"type": "RECORD_TYPE_SRV", "srv": {"name": "_ldap._tcp", "target": "ldap.example.internal.", "port": 389, "priority": 10, "weight": 100, "ttl": 3600}}
```

```json
{"type": "RECORD_TYPE_TLSA", "tlsa": {"name": "_443._tcp.www", "usage": 3, "selector": 1, "matchingType": 1, "data": "<hex digest>", "ttl": 3600}}
```

The keys are `a`, `aaaa`, `cname`, `mx`, `ns`, `txt`, `srv`, `caa` and `tlsa`.

### AddRecord, UpdateRecord

`POST /api/v1/dns/zones/{zone}/records` takes `AddRecordRequest`,
`{"record": { ... }}`. `PUT /api/v1/dns/zones/{zone}/records` takes
`UpdateRecordRequest`, `{"oldRecord": { ... }, "newRecord": { ... }}`: the old
record is matched by type and name and replaced. Both return
`{"status", "zone"}` with the updated zone.

### ListRecords, GetRecord, DeleteRecord

`GET /api/v1/dns/zones/{zone}/records` returns `ListRecordsResponse`,
`{"records": [ ... ], "pagination": { ... }}`; `?type=A` filters and `page`
and `page_size` page as for ListZones.

`GET /api/v1/dns/zones/{zone}/records/{type}/{name}` returns that one
`Record`, or 404 when the zone holds no record of that type and name.
`DNSService` has no `GetRecord` rpc, so this route reads `ListRecords`.

`DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}` removes it and returns
`{"status", "zone"}` with the updated zone.

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
    {"type": "RECORD_TYPE_A", "a": {"name": "ns1", "value": "192.0.2.10", "ttl": 3600}}
  ],
  "authoritative": true
}
```

## DNSSEC

`POST /api/v1/dns/zones/{zone}/sign` signs the zone and returns
`{"status", "zone"}`. `GET /api/v1/dns/zones/{zone}/dnssec` returns
`{"status": {"enabled", "zoneSigned", "keys", "dsRecords", "algorithm", "keySize"}}`.

## Registration

```http
POST /api/v1/dns/register
```

```json
{"fqdn": "newhost.example.internal", "ip": "192.0.2.50"}
```

Returns `{"status": {"success": true, "message": "registration successful"}, "zone": { ... }}`.
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
  -d '{"record":{"type":"RECORD_TYPE_A","a":{"name":"server01","value":"192.0.2.100","ttl":3600}}}'

# Resolve
curl "https://platform.example.com:8443/api/v1/dns/resolve?fqdn=ns1.example.internal.&type=A" \
  -H "Authorization: Bearer $TOKEN"
```

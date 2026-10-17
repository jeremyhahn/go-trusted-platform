# DNS QUIC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The DNS opcodes of the platform QUIC protocol, as handled by
> `pkg/api/daemon/quic_dns.go` and `quic_dns_delegate.go`. Frame constants and
> status bytes are [daemon/api.md](../daemon/api.md) §4; the cross-transport
> matrix is [api.md](api.md).

| Property | Value |
|----------|-------|
| Port | 9444 (UDP, QUIC with TLS 1.3) |
| Opcodes | `0x20`–`0x2C`, top level, no category byte |
| Payload | the platform codec (`quicwire.EncodePayload`), not HTTP/3 |

QUIC does not carry the REST routes. Each request is one opcode and one
encoded payload; each response is one status byte and one encoded payload.

## Opcodes

| Opcode | Name | Request | Response |
|--------|------|---------|----------|
| `0x20` | `OpDNSAddRecord` | `ZoneName`, `Record` | `AddRecordResponse` |
| `0x21` | `OpDNSDeleteRecord` | `DeleteRecordRequest` | `DeleteRecordResponse` |
| `0x22` | `OpDNSUpdateRecord` | `zone`, `name`, `record_type`, `value`, `ttl`, `priority` | `success`, `zone`, `name`, `timestamp` |
| `0x23` | `OpDNSGetRecord` | `zone`, `name`, `record_type` | `record`, `zone`, `timestamp` |
| `0x24` | `OpDNSListRecords` | `ListRecordsRequest` (`Limit`, `Offset` page it as on gRPC) | `Records`, `Total`, `Limit`, `Offset` |
| `0x25` | `OpDNSAddZone` | `CreateZoneRequest` | `CreateZoneResponse` |
| `0x26` | `OpDNSDeleteZone` | `DeleteZoneRequest` | `DeleteZoneResponse` |
| `0x27` | `OpDNSGetZone` | `zone` | `zone` (`id`, `name`, `ttl`, `description`, `internal`, `record_count`), `timestamp` |
| `0x28` | `OpDNSListZones` | `ListZonesRequest`, or empty | `ListZonesResponse` |
| `0x29` | `OpDNSResolve` | `ResolveRequest` | `Records`, `Authoritative` |
| `0x2A` | `OpDNSGetConfig` | empty | `config` (`internal_domain`, `public_domain`, `dnssec_enabled`, `allow_registration`), `timestamp` |
| `0x2C` | `OpDNSGetMetrics` | empty | `metrics` (`zone_count`, `total_records`, `queries_total`, `cache_hits`, `cache_misses`, `dnssec_validated`, `forwarded_queries`), `timestamp` |

`0x2B` and `0x2D` are retired and refused ([api.md](api.md) §2). There is no
QUIC opcode for update zone, sign zone, DNSSEC status or register.

### Two payload shapes

- **Delegated opcodes** (`0x20`, `0x21`, `0x24`–`0x26`, `0x28`, `0x29`) carry
  the gRPC request message under its Go field names (`ZoneName`, `Fqdn`,
  `Type`) and call the same `DNSService` servicer as gRPC
  ([api-reference-grpc.md](api-reference-grpc.md)). A record is `Type` (the
  `RecordType` number) plus `Record` holding one of `A`, `Aaaa`, `Cname`,
  `Mx`, `Ns`, `Txt`, `Srv`, `Caa`, `Tlsa`:

  ```json
  {"ZoneName": "example.internal.",
   "Record": {"Type": 1, "Record": {"A": {"Name": "www", "Value": "192.0.2.10", "Ttl": 300}}}}
  ```

- **Daemon-native opcodes** (`0x22`, `0x23`, `0x27`, `0x2A`, `0x2C`) carry the
  flat snake_case fields in the table. `0x22` builds the old and new record
  from `name` and `record_type` (one of A, AAAA, CNAME, MX, NS, TXT; MX takes
  `priority`) and calls the servicer's `UpdateRecord`, so the new `value` is
  checked first and a record the zone does not hold is `NotFound`; `ttl`
  defaults to 3600.

## Status bytes

| Status | DNS cause |
|--------|-----------|
| `0x00` OK | — |
| `0x01` InvalidRequest | payload does not decode |
| `0x09` InvalidArgument | a required field (`zone_name`, `record`, `name`, `fqdn`, `zone`, `record_type`, `value`) is empty |
| `0x02` NotFound | unknown zone or record |
| `0x04` InternalError | store failure |
| `0x07` PermissionDenied | missing `dns:*` scope |
| `0x0A` Unavailable | no `dns:` section: no DNS backend |

Delegated opcodes map the servicer's gRPC status as [api.md](api.md) §5 gives
it.

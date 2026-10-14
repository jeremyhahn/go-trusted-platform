# DNS — API

> **Status: NORMATIVE** · Scope: DNS routes on every transport · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.DNS` carries the service in-process.

gRPC: `DNSService`, 13 RPCs (`pkg/api/grpc/proto/platform_dns.proto`).
REST: base path `/api/v1/dns` (`pkg/webservice/v1/rest/dns/router.go`).
QUIC: top-level opcodes `0x20`–`0x2C` — no category indirection. `0x2B` and
`0x2D` are retired (#317) — see §2.
MCP: **two parallel tool families** — see §3.

---

## 2. Capability matrix

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create zone | `POST /api/v1/dns/zones` | `CreateZone` | `OpDNSAddZone` (`0x25`) | `dns_create_zone`, `dns_zone_create` | ✅ |
| List zones | `GET /api/v1/dns/zones` | `ListZones` | `OpDNSListZones` (`0x28`) | `dns_list_zones`, `dns_zone_list` | ✅ |
| Get zone | `GET /api/v1/dns/zones/{zone}` | `GetZone` | `OpDNSGetZone` (`0x27`) | `dns_zone_get` | ✅ |
| Update zone | `PUT /api/v1/dns/zones/{zone}` | `UpdateZone` | `MISSING — docs/13 G7` | `dns_zone_update` | ✅ |
| Delete zone | `DELETE /api/v1/dns/zones/{zone}` | `DeleteZone` | `OpDNSDeleteZone` (`0x26`) | `dns_delete_zone`, `dns_zone_delete` | ✅ |
| Add record | `POST /api/v1/dns/zones/{zone}/records` | `AddRecord` | `OpDNSAddRecord` (`0x20`) | `dns_add_record`, `dns_record_create` | ✅ |
| List records | `GET /api/v1/dns/zones/{zone}/records` | `ListRecords` | `OpDNSListRecords` (`0x24`) | `dns_list_records`, `dns_record_list` | ✅ |
| Get record | `GET /api/v1/dns/zones/{zone}/records/{type}/{name}` | `MISSING — docs/13 G7` | `OpDNSGetRecord` (`0x23`) | `dns_get_record`, `dns_record_get` | — |
| Update record | `MISSING — docs/13 G7` | `UpdateRecord` | `OpDNSUpdateRecord` (`0x22`) | `dns_record_update` | ✅ |
| Delete record | `DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}` | `DeleteRecord` | `OpDNSDeleteRecord` (`0x21`) | `dns_delete_record`, `dns_record_delete` | ✅ |
| Sign zone | `POST /api/v1/dns/zones/{zone}/sign` | `SignZone` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| DNSSEC status | `GET /api/v1/dns/zones/{zone}/dnssec` | `GetDNSSECStatus` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Resolve | `GET /api/v1/dns/resolve?fqdn={fqdn}&type={type}` | `Resolve` | `OpDNSResolve` (`0x29`) | `dns_resolve`, `dns_lookup` | ✅ |
| Reverse lookup | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `dns_reverse_lookup` | — |
| Register | `POST /api/v1/dns/register` | `Register` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Get DNS config | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDNSGetConfig` (`0x2A`) | `MISSING — docs/13 G7` | — |
| DNS metrics | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpDNSGetMetrics` (`0x2C`) | `MISSING — docs/13 G7` | — |

Two shapes stand out:

- **DNSSEC — signing and status — exists only on REST, gRPC and embedded.** No
  QUIC, no MCP. Signing a zone is the operation that matters most and is
  reachable on the fewest transports.
- **Two operational reads are QUIC-only**: get config and metrics. An operator
  on REST cannot read DNS metrics.
- **There is no update-config or flush-cache verb on any transport.**
  `OpDNSUpdateConfig` (`0x2B`) and `OpDNSFlushCache` (`0x2D`) only ever
  answered `StatusNotImplemented`: `DNSService` has no runtime config setter,
  and the platform's DNS server keeps no cache. The only cache is the dnsmasq
  local forwarder's (`cache-size`, `pkg/dns/resolver.go`), which no platform
  API controls. #317 retired both bytes; the wire refuses them as unclassified
  (`StatusPermissionDenied`). Do not reuse them. A flush verb needs a dnsmasq
  control path in the DNS service layer, served on every transport.

`DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}` keys a record by type
and name in the path, so a record with the same name in two types is deleted
independently — that is the intended granularity. `GET` on the same path
returns that one record (404 when the zone holds no record of that type and
name); `GET /api/v1/dns/zones/{zone}/records` lists the zone, optionally
filtered by `?type=`. The two are distinct routes with distinct answers.

The SDK REST client (`sdk/go/transport/rest/dns.go`) calls these routes with
the zone, record type and record name in the path, never in the body; the type
travels as its mnemonic (`A`, `AAAA`, `MX`), and a record call without a type
is refused before it is sent. Get record is served on REST, and on MCP by
`dns_record_get` from `ListRecords` (§3). The SDK cannot call it, because
`DNSService` declares no `GetRecord` rpc (docs/13 G7).

`GET /api/v1/dns/resolve` answers from managed zones only, exactly as gRPC
`Resolve` does — both call `dns.ResolveName`: `fqdn` is required (400 without
it) and the longest managed zone suffix answers with only the records the name
owns, filtered by `type`. A name with no managed zone is a 200 with no records
and `authoritative: false`; a name inside one with no such records is a 200
with no records and `authoritative: true`. A `type` resolution does not serve
is a 400 (gRPC `InvalidArgument`). See
[resolution.md](resolution.md#api-resolve).

---

## 3. The MCP surface is duplicated

**Read this before writing an MCP client.**

Twenty DNS tool names exist for roughly ten capabilities, in two families:

| Older family (`pkg/api/mcp/tools.go`) | Newer family (`pkg/api/mcp/dns_tools.go`) |
|---|---|
| `dns_create_zone` | `dns_zone_create` |
| `dns_list_zones` | `dns_zone_list` |
| `dns_delete_zone` | `dns_zone_delete` |
| — | `dns_zone_get`, `dns_zone_update` |
| `dns_add_record` | `dns_record_create` |
| `dns_list_records` | `dns_record_list` |
| `dns_get_record` | `dns_record_get` |
| `dns_delete_record` | `dns_record_delete` |
| — | `dns_record_update` |
| `dns_resolve` | `dns_lookup`, `dns_reverse_lookup` |

**Both families are in the authorization map, under `dns:*` scopes.** The older
family's permissions are listed in `pkg/api/mcp/authz.go` (`dns_add_record` →
`dns:write`, `dns_create_zone` → `dns:write`, `dns_delete_zone` →
`dns:delete`, `dns_resolve` → `dns:read`, and four more).

The newer family is bound to the gRPC `DNSService` servicer (#304). Each tool
decodes its arguments into the RPC's request message and calls the RPC over the
daemon's DNS service. It returns the response with proto field names and
requires the RPC's scope (`dnsTools`, `pkg/api/mcp/dns_tools.go`). The tool
therefore answers and fails as gRPC does: the gRPC status passes through, so
`NotFound` and `InvalidArgument` keep their class on the wire.

- **Arguments.** The arguments are the request message in its JSON form.
  `dns_record_create` takes `zone_name` and a `record` such as
  `{"type": "RECORD_TYPE_A", "a": {"name": "www", "value": "10.0.0.1", "ttl": 300}}`.
  An argument the request does not have is `InvalidArgument`.
- **`dns_record_get` has no RPC**, because `DNSService` declares no `GetRecord`.
  It lists the zone's records of `type` and returns the one named `name`, as
  REST's `GET …/records/{type}/{name}` does. When none matches it returns
  `NotFound` (`ErrDNSRecordNotFound`). It requires `dns:read`, the scope of
  `ListRecords`.
- **`dns_reverse_lookup` has no backend.** No transport serves a reverse lookup,
  and the record set has no PTR type. It is left out of the map and refused with
  `AuthErrorToolNotClassified`.
- **No DNS service.** When none is wired into the daemon, every tool returns
  `Unavailable`.

`dns_create_zone` and `dns_zone_create` now need the same scope.

Which family is canonical, and whether the other is removed or aliased, is
still open.

---

## 4. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`. Both catalogs
are **default-deny** ([`docs/auth/architecture.md`](../auth/architecture.md)).

**`DNSService` is fully scoped on gRPC** with 13 methods mapped, resource
`dns`, actions `read`/`write`/`delete`.

On MCP, the eight older-family tools in §3 carry a permission. So do eleven of
the twelve newer-family tools, each with its gRPC method's scope;
`dns_reverse_lookup` is refused.

The tenant is the DNS service's own. `DNSService` carries no caller tenant on
gRPC: it acts in the tenant the daemon configured the DNS service with, and a
zone of another tenant is `NotFound`. The MCP tools call the same servicer, so
they behave identically and add no tenant binding of their own. Platform-wide
catalog totals are in
[`docs/daemon/api.md`](../daemon/api.md) §5.

### REST is gated on the `admin` role (#165)

`/api/v1/dns/**` requires an authenticated caller holding `admin` — zone and
record CRUD and DNSSEC signing. Reads are gated with the writes: a zone's
contents are the platform's internal name map, and enumerating it is
reconnaissance even when nothing is changed.

This changes the REST position only. The gRPC, Unix, MCP and embedded
positions described above are unchanged. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 5. Status and error mapping

| QUIC byte | Name | REST | DNS cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed zone or record |
| `0x02` | `StatusNotFound` | 404 | Unknown zone or record |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | Resolver or key-store failure |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrZoneAlreadyExists` |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `dns:*` scope |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrRecordTypeNotSupported`, `ErrInvalidResolverAddress`, `ErrInvalidResolverPort` |
| `0x0A` | `StatusUnavailable` | 503 | DNS service not wired into the daemon |

`ErrNoResolverServers`, `ErrZoneSubdomainsNoInternalServer` and
`ErrZoneSubdomainsNoNetworkZones` are **load-time** errors — the service does not
start rather than answering requests badly.

---

## 6. Zone registration has no ownership check

`Register` (`POST /api/v1/dns/register`, `DNSService.Register`) creates a zone
after checking only that the name is not taken. Domain ownership verification is
explicitly deferred in the code (`pkg/dns/service.go:477`, blocked on the IAM
domain-ownership model).

**Before enabling `allow-external-registration`, read
[engineering.md](engineering.md) §3.2.** On an externally reachable authoritative
server, this route lets a caller claim any unclaimed zone name.

---

## 7. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing is formally
deprecated, but the older MCP DNS tool family in §3 is the de-facto legacy half
of a duplicated surface awaiting an owner ruling.

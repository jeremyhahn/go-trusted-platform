# DNS MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The DNS tools of the platform MCP server (`pkg/api/mcp/`). Why there are two
> tool families, and which transports carry what, is [api.md](api.md) §2–3.

| Property | Value |
|----------|-------|
| Protocol | JSON-RPC 2.0, `tools/call` |
| HTTP transport | `POST https://<host>:9445/mcp` (TLS only, no plaintext mode) |
| stdio transport | JSON-RPC over stdin/stdout |
| Result | `CallToolResult`; the output below is its text block ([daemon api.md](../daemon/api.md) §1 "MCP tool results") |
| Authorization | each tool requires a `dns:read`, `dns:write` or `dns:delete` scope |

There are no DNS resources (`resources/read`); everything is a tool.

## Newer family (bound to `DNSService`)

Each tool decodes its arguments into the gRPC request message, in its proto
JSON form, and calls the RPC ([api-reference-grpc.md](api-reference-grpc.md)).
The response carries proto field names; gRPC status codes pass through.

| Tool | RPC | Scope | Required arguments |
|------|-----|-------|--------------------|
| `dns_zone_create` | `CreateZone` | `dns:write` | `name` |
| `dns_zone_get` | `GetZone` | `dns:read` | `name` |
| `dns_zone_list` | `ListZones` | `dns:read` | — |
| `dns_zone_update` | `UpdateZone` | `dns:write` | `name` |
| `dns_zone_delete` | `DeleteZone` | `dns:delete` | `name` |
| `dns_record_create` | `AddRecord` | `dns:write` | `zone_name`, `record` |
| `dns_record_get` | `ListRecords`, filtered | `dns:read` | `zone_name`, `type`, `name` |
| `dns_record_list` | `ListRecords` | `dns:read` | `zone_name` |
| `dns_record_update` | `UpdateRecord` | `dns:write` | `zone_name`, `old_record`, `new_record` |
| `dns_record_delete` | `DeleteRecord` | `dns:delete` | `zone_name`, `name` |
| `dns_lookup` | `Resolve` | `dns:read` | `fqdn` |
| `dns_zone_sign` | `SignZone` | `dns:write` | `zone_name` |
| `dns_zone_dnssec_status` | `GetDNSSECStatus` | `dns:read` | `zone_name` |
| `dns_register` | `Register` | `dns:write` | `fqdn`, `ip` |

An argument the request message does not have is `InvalidArgument`.
`dns_record_get` has no RPC of its own: it lists the zone's records of `type`
and returns the one named `name`, or `NotFound`.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "dns_record_create",
    "arguments": {
      "zone_name": "example.internal.",
      "record": {"type": "RECORD_TYPE_A", "a": {"name": "www", "value": "192.0.2.10", "ttl": 300}}
    }
  }
}
```

## Older family

| Tool | Scope | Arguments |
|------|-------|-----------|
| `dns_create_zone` | `dns:write` | `zone` (required) |
| `dns_delete_zone` | `dns:delete` | `zone` (required) |
| `dns_list_zones` | `dns:read` | none |
| `dns_add_record` | `dns:write` | `name` (FQDN), `record_type`, `value` (required); `ttl` (default 300) |
| `dns_get_record` | `dns:read` | `name` (FQDN), `record_type` (required) |
| `dns_delete_record` | `dns:delete` | `name` (FQDN), `record_type` (required) |
| `dns_list_records` | `dns:read` | `zone` (required) |
| `dns_resolve` | `dns:read` | `name` (required); `record_type` (default `A`) |

The older tools take a record's FQDN, not a zone and a relative name.
`record_type` is one of A, AAAA, CNAME, MX, NS, TXT, SRV, CAA and TLSA, in any
case; any other type is `ErrRecordTypeNotSupported`. The `value` of A, AAAA,
CNAME, MX (the exchange), NS and TXT is stored as given. SRV, CAA and TLSA take
the RDATA in zone-file form (`10 5 5060 sip.example.com.`,
`0 issue "letsencrypt.org"`, `3 1 1 <hex>`). A value that does not parse is
`ErrInvalidRecordValue`. `dns_resolve` answers in the same forms
(`Service.AddRecord`, `pkg/dns/record_kinds.go`).
`dns_add_record` returns `{"success": true}`; `dns_resolve` returns
`{"results": [...]}`; `dns_list_zones` returns `{"zones": [...]}`.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "dns_resolve",
    "arguments": {"name": "www.example.internal.", "record_type": "A"}
  }
}
```

## Errors

Tool failures map as [api.md](api.md) §5 gives them. With no `dns:` section,
every tool in both families returns `Unavailable`.

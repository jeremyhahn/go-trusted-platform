# DNS API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> Index of the DNS service's per-protocol references. The capability matrix,
> authorization and error mapping are normative in [api.md](api.md).

## Supported Protocols

| Protocol | Transport | Port | Documentation |
|----------|-----------|------|---------------|
| REST | HTTPS | 8443 | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | TCP | 10443 | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | UDP | 9444 | [api-reference-quic.md](api-reference-quic.md) |
| MCP | stdio/HTTPS | 9445 | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix Socket | Unix | /run/platformd.sock | [api-reference-unix.md](api-reference-unix.md) |

## Authentication

Callers authenticate with a bearer token (`Authorization: Bearer <access_token>`)
or a TLS client certificate issued by the platform CA. REST additionally
requires the `admin` role on every `/api/v1/dns/**` route; gRPC and MCP check
`dns:read`, `dns:write` and `dns:delete` scopes ([api.md](api.md) §4).

## Operations

The gRPC `DNSService` declares 13 RPCs: `CreateZone`, `GetZone`, `UpdateZone`,
`DeleteZone`, `ListZones`, `AddRecord`, `DeleteRecord`, `UpdateRecord`,
`ListRecords`, `SignZone`, `GetDNSSECStatus`, `Resolve` and `Register`.

The transports do not carry the same set. Get record exists on REST, QUIC and
MCP but not gRPC. Update record exists on REST, gRPC and MCP; the daemon serves
it on QUIC too, but the SDK QUIC adapter does not map it. Signing and DNSSEC
status exist on REST, gRPC, MCP (`dns_zone_sign`, `dns_zone_dnssec_status`) and
embedded, not QUIC. The full per-transport matrix is [api.md](api.md) §2.

TLSA records are added through add record with type `TLSA`. The platform's
own DANE publishing calls `dns.Service.AddTLSARecord` in-process
([dane.md](dane.md)); no transport has a separate TLSA operation.

## Tenancy

The DNS service acts in the tenant the daemon configured it with. A zone of
another tenant answers not found ([api.md](api.md) §4).

## Error Handling

There are no DNS-specific error strings. REST answers the platform response
envelope (`code` is the HTTP status, `error` the message, `success: false`);
gRPC, QUIC and MCP answer their native status codes. The mapping between them
is [api.md](api.md) §5.

### One backend, and the answer without one

Every transport reaches the one DNS service a `dns:` section starts. gRPC,
the Unix socket, the embedded SDK transport, the REST handlers
(`pkg/webservice/v1/rest/dns/handlers.go`), the SDK-mapped QUIC operations and
MCP's newer tools (`dns_zone_*`, `dns_record_*`, `dns_register`,
`dns_lookup`) all go through a `DNSServiceServer`
(`pkg/api/daemon/dns_grpc_service.go`). QUIC's flat-wire operations
(`pkg/api/daemon/quic_dns.go`) and MCP's older tool family call the same
`*dns.Service` directly.

With no `dns:` section there is no backend, and every DNS call answers the
not-configured error before it reads its input:

| Transport | Answer |
|-----------|--------|
| gRPC, Unix, embedded | `UNAVAILABLE`, `ErrorInfo` reason `SERVICE_NOT_CONFIGURED`, metadata `service=dns` |
| REST | `503`, code `SERVICE_NOT_CONFIGURED` |
| QUIC | `StatusUnavailable` (`0x0A`) |
| MCP | `Unavailable`, both tool families |

## See Also

- [DNS Overview](README.md)
- [Zones](zones.md)
- [Records](records.md)
- [DNSSEC](dnssec.md)

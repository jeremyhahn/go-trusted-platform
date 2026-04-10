# DNS Resolution

Query handling and resolution in the Trusted Platform DNS subsystem.

## Overview

DNS resolution is handled by the custom `TrustedPlatformPlugin` which integrates with CoreDNS. The plugin intercepts incoming queries, validates them against RFC 1035, performs zone lookups against the platform datastore, and returns parsed records. Queries for unknown zones are forwarded to configured upstream DNS servers.

## Query Flow

1. **Query Reception**: CoreDNS receives the DNS query and routes it to `TrustedPlatformPlugin.ServeDNS()`
2. **Port Detection**: The plugin extracts the listening port from `w.LocalAddr()` to determine server type (internal vs public)
3. **Query Normalization**: The qname is normalized using `dns.Fqdn()` to ensure a trailing dot
4. **Validation**: The query is validated via `validateQuery()` for RFC 1035 compliance
5. **Zone Lookup**: Two-phase lookup attempts to locate the zone:
   - Direct lookup using the full qname as zone ID
   - If not found, parse qname via `ParseDomainName()` and construct zone name from subdomains + root domain
6. **Security Check**: If query arrives on public port for an internal zone, silently drop and log security event
7. **Record Parsing**: `parseQueriedRecord()` dispatches to the appropriate parser function based on query type
8. **Response**: Matching records are assembled into a DNS response message and sent to the client

```
Query: myhost.trusted-platform.internal A
           │
           ▼
┌──────────────────────┐
│ Validate RFC 1035    │
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Zone Lookup (qname)  │─────▶ Not found
└──────────────────────┘            │
           │                        ▼
           │               ┌──────────────────────┐
           │               │ Parse subdomain/zone │
           │               │ Retry lookup         │
           │               └──────────────────────┘
           │                        │
           ▼                        ▼
┌──────────────────────┐
│ Check internal flag  │
│ vs server port       │
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ parseQueriedRecord() │
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Return DNS response  │
└──────────────────────┘
```

## Supported Record Types

| Query Type | DNS Type | Parser Function | Record Source |
|------------|----------|-----------------|---------------|
| A | `dns.TypeA` | `recordParserFuncs[dns.TypeA]` | `zone.RecordSet.ARecords` |
| AAAA | `dns.TypeAAAA` | `recordParserFuncs[dns.TypeAAAA]` | `zone.RecordSet.AAAARecords` |
| MX | `dns.TypeMX` | `recordParserFuncs[dns.TypeMX]` | `zone.RecordSet.MXRecords` |
| CNAME | `dns.TypeCNAME` | `recordParserFuncs[dns.TypeCNAME]` | `zone.RecordSet.CNAMERecords` |
| NS | `dns.TypeNS` | `recordParserFuncs[dns.TypeNS]` | `zone.RecordSet.NSRecords` |
| SOA | `dns.TypeSOA` | `recordParserFuncs[dns.TypeSOA]` | `zone.RecordSet.SOARecord` |
| TXT | `dns.TypeTXT` | `recordParserFuncs[dns.TypeTXT]` | `zone.RecordSet.TXTRecords` |
| SRV | `dns.TypeSRV` | `recordParserFuncs[dns.TypeSRV]` | `zone.RecordSet.SRVRecords` |

Parser functions are registered in `parser.go` via the `recordParserFuncs` map. Each function extracts the hostname from the qname, matches it against records in the zone, and constructs the appropriate `dns.RR` response.

## Internal vs Public Resolution

The platform runs two separate DNS server instances differentiated by port:

| Server | Default Port | Purpose |
|--------|--------------|---------|
| Internal | 9053 | Serves internal zones, can resolve public zones |
| Public | 8053 | Serves public zones only |

### Security Enforcement

When a query arrives on the public server port for a zone marked `Internal: true`:

1. The query is silently dropped (no response sent)
2. A security log entry is recorded with severity `HIGH`
3. The offender's address is captured for audit
4. `ErrInternalZoneQueryViolation` is logged

```go
// Security check in ServeDNS
if port == strconv.Itoa(Configuration.PublicServer.Port) && zone.Internal {
    // Log violation and drop query silently
    Configuration.Logger.Security(logging.SecurityLogEntry{
        Category:        logging.CategoryNetworkSecurity,
        Description:     "Ignoring public query for internal zone",
        Details:         qname,
        OffenderAddress: w.RemoteAddr().String(),
        Source:          logging.SourceDNS,
        Severity:        logging.SeverityHigh,
    })
    return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
}
```

No error response is returned to prevent attackers from enumerating internal zone names.

## Query Validation

All queries pass through `validateQuery()` which enforces RFC 1035 compliance:

| Check | Limit | Error |
|-------|-------|-------|
| Domain length | 253 characters max | "DNS query exceeds maximum domain length" |
| Label length | 63 characters max | "DNS query contains a label exceeding 63 characters" |
| Empty labels | Not allowed | "DNS query contains an empty label" |
| Label format | `^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$` | "DNS query contains an invalid label" |
| IP addresses | Rejected | "DNS query must not be an IP address" |

These checks protect against DNS injection attacks and malformed inputs. Queries failing validation are passed to the next plugin in the chain.

## Forwarding

When a zone is not found in the datastore, queries are forwarded to upstream DNS servers via the CoreDNS `forward` plugin.

### Corefile Generation

Corefiles are dynamically generated based on configuration:

```go
// With forwarders configured
.:{port} {
    trustedPlatform
    log
    chaos
    forward . {forwarders}
}
```

### Default Forwarders

| Server Type | Default Forwarders |
|-------------|-------------------|
| Internal | `192.168.1.1`, `192.168.2.1`, `192.168.3.1` |
| Public | `4.4.4.4`, `8.8.8.8` |

Forwarders are configurable per server in the platform configuration:

```yaml
dns:
  internal:
    port: 9053
    forwarders:
      - "192.168.1.1"
  public:
    port: 8053
    forwarders:
      - "8.8.8.8"
      - "4.4.4.4"
```

## Custom Resolver

The DNS service provides a `net.Resolver` instance for programmatic DNS lookups using the internal server:

```go
// Get the resolver
resolver := dnsService.Resolver()

// Use for lookups
addrs, err := resolver.LookupHost(ctx, "myhost.trusted-platform.internal")
```

The resolver is configured to:
- Use Go's native DNS implementation (`PreferGo: true`)
- Connect to the internal DNS server on the configured port
- Allow resolution of both internal and public zones
- Forward unknown queries to configured upstream servers

## Future: DNSSEC Validation

Planned DNSSEC support will add cryptographic validation to DNS responses:

| Feature | Description |
|---------|-------------|
| DO Flag Handling | Detect DNSSEC OK flag in queries |
| RRSIG Responses | Include resource record signatures in responses |
| NSEC/NSEC3 | Authenticated denial of existence |
| Key Management | TPM-backed DNSSEC signing keys via KMS |

DNSSEC record types are already defined in the zone entity structure (`DNSKEYRecord`, `DSRecord`, `RRSIGRecord`) but signing and validation logic is not yet implemented.

## See Also

- [Architecture](architecture.md) - DNS subsystem design
- [Zones](zones.md) - Zone management
- [Records](records.md) - Record types and management
- [Security](security.md) - Security model

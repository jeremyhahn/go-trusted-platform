# DNS Resolution

> **Status: REFERENCE** · Last verified: 2026-10-15
> How the DNS wire plugin and the resolve API answer queries, as built in
> `pkg/dns/plugin.go`, `parser.go` and `resolve.go`.

## Overview

DNS resolution is handled by the custom `TrustedPlatformPlugin` which integrates with CoreDNS. The plugin intercepts incoming queries, validates them against RFC 1035, performs zone lookups against the platform datastore, and returns parsed records. Queries for unknown zones are forwarded to configured upstream DNS servers.

## Query Flow

1. **Query Reception**: CoreDNS receives the DNS query and routes it to `TrustedPlatformPlugin.ServeDNS()`
2. **Port Detection**: The plugin extracts the listening port from `w.LocalAddr()` to determine server type (internal vs public)
3. **Query Normalization**: The qname is normalized using `dns.Fqdn()` to ensure a trailing dot
4. **Validation**: The query is validated via `validateQuery()` for RFC 1035 compliance; a query that fails goes to the next plugin
5. **NAT64 discovery**: `ipv4only.arpa` (RFC 7050 prefix discovery) is answered before the zone lookup
6. **Zone Lookup**: `findZoneForQuery()` tries each suffix of the qname, longest first, and the first stored zone is authoritative; no zone sends the query to the next plugin
7. **Security Check**: If the query arrives on the public port for an internal zone, the plugin logs a security event and passes the query on without answering from the zone
8. **Zone transfer**: AXFR and IXFR go to the transfer responder ([zone-transfer.md](zone-transfer.md))
9. **Record Parsing**: `parseQueriedRecord()` dispatches to the appropriate parser function based on query type, which selects the records whose owner name IS the queried name (see [Name matching](#name-matching))
10. **Response**: `buildResponse()` assembles the reply — matching records as an authoritative answer, or a negative answer distinguishing NXDOMAIN from NODATA (see [Negative answers](#negative-answers))

```
Query: myhost.example.internal A
           │
           ▼
┌──────────────────────┐
│ Validate RFC 1035    │─────▶ invalid: next plugin
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Zone lookup, longest │─────▶ no zone: next plugin (forward)
│ suffix first         │
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Check internal flag  │─────▶ internal zone on public port: next plugin
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
| CAA | `dns.TypeCAA` | `recordParserFuncs[dns.TypeCAA]` | `zone.RecordSet.CAARecords` |
| TLSA | `dns.TypeTLSA` | `recordParserFuncs[dns.TypeTLSA]` | `zone.RecordSet.TLSARecords` |
| DNSKEY | `dns.TypeDNSKEY` | `recordParserFuncs[dns.TypeDNSKEY]` | `zone.RecordSet.DNSKEYRecords` |
| DS | `dns.TypeDS` | `recordParserFuncs[dns.TypeDS]` | `zone.RecordSet.DSRecords` |
| RRSIG | `dns.TypeRRSIG` | `recordParserFuncs[dns.TypeRRSIG]` | `zone.RecordSet.RRSIGRecords` |
| NSEC | `dns.TypeNSEC` | `recordParserFuncs[dns.TypeNSEC]` | `zone.RecordSet.NSECRecords` |
| NSEC3 | `dns.TypeNSEC3` | `recordParserFuncs[dns.TypeNSEC3]` | `zone.RecordSet.NSEC3Records` |
| NSEC3PARAM | `dns.TypeNSEC3PARAM` | `recordParserFuncs[dns.TypeNSEC3PARAM]` | `zone.RecordSet.NSEC3PARAMRecords` |

Parser functions are registered in `parser.go` via the `recordParserFuncs` map. Each function selects the records the queried name owns and constructs the appropriate `dns.RR` response, whose header name echoes the query name.

## Name matching

A record answers a query only when its owner name IS the queried name. Owners are
stored in any of three forms, all of which resolve to the same fully qualified
name before comparison (`recordOwnerFQDN`, `pkg/dns/owner.go`):

| Stored `name` | Zone | Owner |
|---|---|---|
| `www` | `example.com.` | `www.example.com.` |
| `@` or empty | `example.com.` | `example.com.` |
| `www.example.com.` | `example.com.` | `www.example.com.` |

Comparison is case-insensitive and trailing-dot insensitive (RFC 4343 §3), so a
0x20-case-randomised query matches, and the answer echoes the query's own
spelling.

The SOA is owned by the zone apex and answers nowhere else: a zone has exactly
one SOA and it sits at the apex (RFC 1034 §4.2). The SOA entity's `name` field
is not used for matching.

An RRSIG answers at the owner of the RRset it signs. The signer records that
owner in `RRSIGRecord.name`, so `RRSIG www.example.com.` returns the signatures
over the `www` RRsets and `RRSIG example.com.` returns only the apex ones. A
signature persisted before the owner was recorded has no `name`, which resolves
to the apex like any other record. Re-signing the zone, which every zone save
does while DNSSEC is enabled, records the real owners.

**Wildcards are not supported.** A record named `*` is matched literally, as the
name `*.example.com.`; there is no RFC 4592 synthesis. Nothing in the zone model,
the AXFR responder or the DNSSEC signer models wildcards, and a signed zone
cannot synthesise wildcard answers without the wildcard RRSIG handling of RFC
4035 §3.1.3.

> **Changed 2026-09-02 (#182).** A records — and, less visibly, every other type
> in the table — used to match on the query's FIRST LABEL alone, or on no name at
> all. A zone holding `www` answered `www.anything.example.com` and every deeper
> name; MX, CNAME, NS, CAA, TLSA, SRV and the DNSSEC types returned their whole
> record set for any name in the zone. Zones whose apex records were stored under
> a non-apex owner (`name: cp.example.com.` in an `example.com.` zone) relied on
> that looseness and must move those records to `@` — including zones ALREADY
> PERSISTED in the datastore, which `processZone` does not re-seed from the
> configuration file. See
> [troubleshooting.md](troubleshooting.md#owner-names-after-the-exact-matching-change).

> **Changed 2026-10-12 (#219).** `RRSIGRecord` now persists its owner (`name`).
> Before, the signer dropped it: every signature answered at the apex only, and
> AXFR sent each one under the apex owner, so a secondary received mis-owned
> signatures for every non-apex RRset. The signer also stored the signature
> base64-encoded twice, so no served or transferred RRSIG verified. Zones signed
> before this change keep both defects until they are next saved.

## Negative answers

A query that matches no record is answered authoritatively, and RFC 2308 §2
distinguishes two cases (`buildResponse`, `pkg/dns/plugin.go`):

| Case | Rcode | When |
|---|---|---|
| NXDOMAIN | `RcodeNameError` (3) | The queried name exists nowhere in the zone |
| NODATA | `RcodeSuccess` (0), empty answer | The name exists but owns no record of the queried type |

A name exists when it owns a record — including a DNSSEC record such as a DS at a
delegation point, so a signed zone never denies a name it also answers NSEC3 or
DS for — when it is the zone apex, or when it is an
empty non-terminal — an interior node with no records of its own but with records
beneath it, such as `host.example.com.` in a zone defining
`deep.host.example.com.` (RFC 1034 §4.3.2). An empty non-terminal is NODATA and
never NXDOMAIN.

Both kinds of negative answer carry the zone SOA in the authority section so a
resolver can cache the denial. Its TTL is the lesser of the SOA record's own TTL
and its MINIMUM field (RFC 2308 §3, §5). A zone with no SOA configured sends an
empty authority section: there is nothing authoritative to cite.

### Aliases

A name that owns a CNAME owns nothing else (RFC 1034 §3.6.2), so a query for
any other type is answered with the alias and then restarted at its target
(§4.3.2 step 3(a)):

| Chain ends | Answer | Authority |
|---|---|---|
| At a name in this zone holding the queried type | CNAME(s) + the target's records | — |
| At a name in this zone holding no such record | CNAME(s) | zone SOA (NODATA at the end of the chain) |
| Outside this zone | CNAME(s) | — (the resolver continues from the target) |

Chains are followed at most eight hops and never revisit a name, so alias data
that points at itself or around a cycle still terminates. A `CNAME` query is
answered by the record itself and is never chased.

An exact match wins over an alias: a name carrying both a CNAME and an address
record — invalid zone data (RFC 2181 §10.5.1) that the shipped templates
contain — is answered from the address record.

### Referrals

A name at or below a **delegation** — an NS RRset owned by a name other than
the zone apex — is neither answered nor denied here, and the cut is found
BEFORE any data at or below it (RFC 1034 §4.3.2 walks down to the name and
stops there). Whatever the parent stores under a cut is glue for the additional
section, never an answer: `NS child.example.com.` and `A ns1.child.example.com.`
are both referrals. The parent holds the
child's NS records but is not authoritative for the names beneath them, so
RFC 1034 §4.3.2 step 3(b) calls for a referral: NOERROR, an empty answer, the
child's NS RRset in the authority section, and the **AA bit clear**. The
closest enclosing delegation wins, since that is the zone actually holding the
name. The apex NS RRset names this server and delegates nothing, so it never
produces a referral.

**Parent-side types at the cut are the exception.** `DS` (RFC 4035 §3.1.4.1)
and `NSEC` are stored on the parent side of the delegation, so a query for one
of them AT the delegation point is answered authoritatively — including the
`DS` NODATA that tells a validator the delegation is insecure. Below the cut
nothing is parent-side, so the same query for a name inside the child zone is
referred like anything else.

An alias whose target falls at or below a delegation ends the chain there: what
the parent holds inside the child is glue, not an answer, and the parent may
not deny the child's names either.

A referral carries **glue** in the additional section: the A and AAAA records
this zone holds for the child's nameservers, but only for in-bailiwick targets
— names at or below the delegation point. A nameserver named inside the zone it
serves cannot be resolved without them, and an address for any other name is
not this zone's to give.

Two things disqualify an NS RRset from being a delegation:

| Not a delegation | Why |
|---|---|
| An owner outside the zone (`name: com.` in an `example.com.` zone) | Nothing constrains the stored owner today; honouring it would refer every name in the zone away |
| An owner that also holds ordinary data — an address, alias, MX, TXT, SRV, CAA or TLSA record | Authoritative data and a cut cannot share an owner (RFC 2181 §6.1). This shape is a zone's own NS RRset stored under a hostname instead of the apex; zones seeded from older templates carry it, and referring that name would stop a control plane answering its own hostname. |

### Other response flags

Answers and negative answers set the AA bit, since the platform is
authoritative for the zones it serves; referrals clear it. Query types outside `recordParserFuncs` are still forwarded to the next
plugin rather than answered negatively — that is `ErrRecordTypeNotSupported`
behaviour, unchanged.

## API resolve

The resolve API (`GET /api/v1/dns/resolve`, gRPC `Resolve`, and the QUIC, MCP
and Unix tools) answers from the managed zones without going over the DNS wire.
Every transport calls one function, `dns.ResolveName` (`pkg/dns/resolve.go`):

1. **Zone.** The managed zone with the longest suffix of the queried name
   answers, so `host.sub.example.com.` is answered by `sub.example.com.` when
   both it and `example.com.` are managed. Each suffix is looked up lower-cased,
   then as written.
2. **Owner.** Only records whose owner IS the queried name come back, matched
   as in [Name matching](#name-matching). One extra stored form is accepted
   here: an absolute owner without its trailing dot (`www.example.com` in
   `example.com.`), which is the shape a record added through the API can
   carry. The DNS wire plugin reads that form as relative.
3. **Type.** `type` filters by mnemonic, in any case; without it every type
   below is returned.
4. **Names** compare case-insensitively, and the trailing dot is optional.

| Case | Answer |
|---|---|
| Name under no managed zone | No records, `authoritative: false` |
| Name inside a zone, with records of the type | Those records, `authoritative: true` |
| Name inside a zone, with no such records | No records, `authoritative: true` — the zone is authoritative for the name and holds nothing for it |
| Longest zone is one the caller may not read | No records, `authoritative: false`; a shorter zone the caller does own does not answer instead |
| `type` outside A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, TLSA | Refused: REST 400, gRPC `InvalidArgument` (`ErrRecordTypeNotSupported`) |

The API answer is the zone's stored data. It does not chase CNAMEs, refer at
delegations or synthesise SOA authority the way the wire plugin does.

`Service.Resolve`, the value-list form that the MCP `dns_resolve` tool and the
`pkg/api/quic` and `pkg/api/rest` handlers call (the daemon's QUIC and Unix
resolve go through gRPC `Resolve`), returns the record values and serves A, AAAA,
CNAME, MX, NS, TXT, SRV, CAA and TLSA. SRV, CAA and TLSA values are their RDATA in zone-file form, the form
`Service.AddRecord` takes. An empty answer is an error there (`ErrRecordNotFound`).

> **Changed 2026-10-14 (#452).** The resolve API used to look up the queried
> name as a zone and return every record of the type in it, whatever its
> owner: `www.example.com.` found no zone and returned nothing, and
> `example.com.` returned the `www` records with the apex ones. An unserved
> `type` used to be an empty answer.

## Internal vs Public Resolution

The platform runs two separate DNS server instances differentiated by port:

| Server | Default Port | Purpose |
|--------|--------------|---------|
| Internal | 9053 | Serves internal zones, can resolve public zones |
| Public | 8053 | Serves public zones only |

### Security Enforcement

When a query arrives on the public server port for a zone marked `Internal: true`:

1. `ErrInternalZoneQueryViolation` is logged
2. A security log entry is recorded with severity `HIGH` and the offender's address
3. The query goes to the next plugin unanswered by the zone, so with forwarders
   configured it is forwarded upstream like a name the platform does not serve

```go
// Security check in ServeDNS
if port == strconv.Itoa(Configuration.PublicServer.Port) && zone.Internal {
    // Log violation and drop query silently
    Configuration.Logger.Error(ErrInternalZoneQueryViolation)
    Configuration.Logger.Security(ctx, logging.SecurityLogEntry{
        Category:        logging.CategoryNetworkSecurity,
        Description:     "Ignoring public query for internal zone",
        Details:         qname,
        OffenderAddress: w.RemoteAddr().String(),
        Source:          logging.SourceDNS,
        Severity:        logging.SeverityHigh,
        Timestamp:       time.Now(),
    })
    return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
}
```

The platform returns no error of its own, so the public server does not reveal which internal zones exist.

## Query Validation

All queries pass through `validateQuery()` which enforces RFC 1035 compliance:

| Check | Limit | Error |
|-------|-------|-------|
| Empty query | Not allowed | "DNS query is empty" |
| Domain length | 253 characters max | "DNS query exceeds maximum domain length (253 characters)" |
| Label length | 63 characters max | "DNS query contains a label exceeding 63 characters" |
| Empty labels | Not allowed | "DNS query contains an empty label" |
| Label format | `^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$` (underscores allowed for `_acme-challenge`, SRV and TLSA owners) | "DNS query contains an invalid label" |
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
    {dns64 stanza, when DNS64 serves this listener}
    forward . {forwarders}
}
```

`NewCorefileForServer` (`pkg/dns/corefile.go`) writes one block per listener;
the `forward` line is omitted when the listener has no forwarders.

### Default Forwarders

| Server Type | Default Forwarders |
|-------------|-------------------|
| Internal | three RFC 1918 gateway addresses (`DefaultConfig`, `pkg/dns/config.go`); set your own |
| Public | `4.4.4.4`, `8.8.8.8` |

Forwarders are configurable per server in the platform configuration:

```yaml
dns:
  internal:
    port: 9053
    forwarders:
      - "192.0.2.1"
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
addrs, err := resolver.LookupHost(ctx, "myhost.example.internal")
```

The resolver is configured to:
- Use Go's native DNS implementation (`PreferGo: true`)
- Connect to the internal DNS server on the configured port
- Allow resolution of both internal and public zones
- Forward unknown queries to configured upstream servers

## DNSSEC

Zone signing is implemented ([dnssec.md](dnssec.md)): a signed zone's DNSKEY,
DS, RRSIG, NSEC, NSEC3 and NSEC3PARAM records are served when queried by type,
as in the table above. Two things are not implemented:

| Feature | State |
|---------|-------|
| DO-bit handling | The plugin does not read the DNSSEC OK flag; RRSIGs are not added to answers for other types |
| Validation | Answers forwarded upstream are not validated |

## See Also

- [Architecture](architecture.md) - DNS subsystem design
- [Zones](zones.md) - Zone management
- [Records](records.md) - Record types and management
- [Security](security.md) - Security model

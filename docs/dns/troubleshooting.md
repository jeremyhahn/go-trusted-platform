# DNS Troubleshooting Guide

> **Status: REFERENCE** · Last verified: 2026-10-18
> Symptoms of the platform's DNS server (`pkg/dns`) and what causes them in the code. There is no `platformctl dns` group (#954): checks use `dig` and the [DNS API](api.md).

## Quick checks

The public listener defaults to port 8053 and the internal one to 9053
([operations.md](operations.md#what-runs)).

```bash
dig @127.0.0.1 -p 8053 example.com. SOA            # public zone
dig @127.0.0.1 -p 9053 example.internal. SOA       # internal zone
dig @127.0.0.1 -p 8053 example.com. DNSKEY +dnssec # signed?
delv @127.0.0.1 -p 8053 example.com. A             # validates?
```

## Symptoms

| Symptom | Cause in the code | Fix |
|---------|-------------------|-----|
| A name in an internal zone does not resolve on 8053 | The public listener passes internal-zone queries to the next plugin (`pkg/dns/plugin.go:116-134`) | Query port 9053 |
| A name in no platform zone gets an upstream answer or SERVFAIL | No zone found: the query goes to `forward` if forwarders are set (`pkg/dns/plugin.go:112`) | Expected; add the zone if it should be local |
| A malformed name is not answered from a zone | `validateQuery` (`pkg/dns/parser.go:518`) failed; logged as `Invalid query` | Fix the query name |
| Editing a zone in the configuration file changes nothing | `processZone` (`pkg/dns/plugin.go:581`) saves a configured zone only when it is not already stored | Change the stored zone through the API |
| AXFR or IXFR gets REFUSED | Transfer disabled, or no matching TSIG key ([zone-transfer.md](zone-transfer.md)) | Read the `Refusing zone transfer` reason |
| Validating resolvers return SERVFAIL after about 30 days | RRSIGs expired; nothing re-signs on a schedule | Re-sign the zone ([operations.md](operations.md#routine-task-re-sign-before-signatures-expire)) |
| Validating resolvers return SERVFAIL after keys changed | The parent's DS no longer matches the KSK ([dnssec-rollover.md](dnssec-rollover.md)) | Replace the DS at the parent |
| `nsupdate` has no effect | DNS UPDATE is not implemented ([dynamic-dns.md](dynamic-dns.md)) | Change records through the API |
| A DNS API call answers Unavailable or 503 | The daemon has no `dns:` section ([api.md](api.md#5-status-and-error-mapping)) | Configure `dns:` |
| A REST DNS call answers 403 | `/api/v1/dns/**` needs the `admin` role ([api.md](api.md#4-authorization)) | Use an admin token |
| A zone call fails with `ErrUnauthorizedZoneAccess` | The zone's tenant is not the DNS service's ([security.md](security.md#tenant-check)) | Use the owning tenant's daemon |

### Owner names after the exact-matching change

Before exact matching, the resolver matched A records on the query's first label and
matched most other types on no name at all, so a record answered names it did
not own. Records now answer their own name only
([resolution.md](resolution.md#name-matching)), which surfaces two shapes of
pre-existing misconfiguration in **zones already persisted in the datastore**.
`processZone` seeds a zone once and then leaves it alone, so editing the
configuration file does not repair a zone that is already stored.

| Stored shape | Symptom after upgrade | Repair |
|---|---|---|
| An apex record stored under a non-apex owner — `ns:` with `name: cp.example.com.` in an `example.com.` zone | `NS example.com.` answers nothing | Set the owner to `@` |
| A non-apex NS record whose owner holds NOTHING else in the zone | The name and everything below it is referred to the child nameservers with `AA=0` instead of answered | Set the owner to `@` if it was meant as the zone's own NS; keep it only if a real child zone is delegated there |

A non-apex NS owner that also holds an address, alias, MX, TXT, SRV, CAA or
TLSA record in the same zone is NOT read as a delegation (RFC 2181 §6.1: a cut
carries no other data at its owner), so the shipped templates' old
`cp.example.com.` shape keeps answering after an upgrade. The apex NS answer is
the part that needs the repair below.

Check what a zone actually stores rather than what its configuration file says:

```bash
dig @127.0.0.1 -p 8053 example.com. NS +norecurse
dig @127.0.0.1 -p 8053 cp.example.com. A +norecurse
```

An `AA=0` reply with NS records in the authority section is a referral, not an
answer. The shipped templates were corrected in the same change; a deployment
that predates it needs the stored zone updated too.

## Log messages

DNS logs go to the daemon's logger. `platformd --debug`
(`pkg/daemon/commands/root.go:118`) adds the debug-level lines.

| Message | Level | Code |
|---------|-------|------|
| `Inbound DNS query` | Info | `pkg/dns/plugin.go:84` |
| `Query response` | Info | `pkg/dns/plugin.go:161` |
| `Invalid query` | Warn | `pkg/dns/plugin.go:95` |
| `no zone found for query` | Debug | `pkg/dns/plugin.go:112` |
| `received public query for internal zone`, plus a high-severity security event | Error | `pkg/dns/plugin.go:51`, `:122` |
| `Served zone transfer` | Info | `pkg/dns/axfr.go:133` |
| `Refusing zone transfer`, plus a medium-severity security event | Warn | `pkg/dns/axfr.go:157` |
| `unauthorized zone access` | Warn | `pkg/dns/service.go:171` |
| `SetDNSSECKeyStore returned an error on startup` | Warn | `pkg/dns/service.go:149` |

There are no DNS-specific logging keys and no separate DNS log file.

## Not available

No `platformctl dns` commands, zone export or import, cache to flush,
signature-expiry monitor, emergency key rollover or key revocation, rate
limits, or performance keys exist.

## See also

- [Operations](operations.md) · [Security](security.md) · [Resolution](resolution.md) · [Zone transfer](zone-transfer.md) · [API](api.md)

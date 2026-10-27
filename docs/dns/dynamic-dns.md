# Dynamic DNS (DDNS)

> **Status: REFERENCE** · Last verified: 2026-10-19
> RFC 2136 DNS UPDATE is **not implemented**, as a server or as a client. This page states how records change today and what is missing.

## How records change today

| Path | Code | Notes |
|------|------|-------|
| Record and zone API on every transport | [api.md](api.md#2-capability-matrix) | Add, update and delete records; create, update, delete and sign zones |
| `Register` route | `pkg/dns/service.go:366` | Gated by `allow-registration` and the per-zone-kind switches ([configuration.md](configuration.md#top-level-keys)) |
| Platform-internal writers | `pkg/app`, `pkg/bootstrap` | Each webservice's A/AAAA record ([configuration.md](configuration.md#top-level-keys)), TLSA records ([dane.md](dane.md)), the BMC certificate's dns-01 TXT record ([acme-integration.md](acme-integration.md)) |

Every write goes through the DNS service, which re-signs the zone when DNSSEC
is enabled ([dnssec.md](dnssec.md)).

## What the DNS wire protocol does

The CoreDNS plugin (`TrustedPlatformPlugin.ServeDNS`, `pkg/dns/plugin.go:82`)
answers queries and serves AXFR/IXFR to TSIG-authenticated secondaries
([zone-transfer.md](zone-transfer.md)). Any opcode other than QUERY (an
UPDATE, a NOTIFY) gets NOTIMP (RFC 1035 §4.1.1 RCODE 4): the plugin returns
that rcode and the CoreDNS server writes the reply, so an UPDATE is never
applied and never answered as a query. A query with no question gets FORMERR
(RCODE 1) the same way.

TSIG keys exist only for zone transfer (`dns.transfer.tsig-keys`,
`TSIGKey` in `pkg/dns/config.go:321`). Nothing signs or verifies an UPDATE
with them.

## Attestation-gated updates

`pkg/dns/attestation` holds a `Guard` (`NewGuard`, `VerifyForUpdate`,
`VerifyForQuery`) that checks a per-zone attestation policy. Only its own
tests call it: no route, plugin or service uses it, and the `dns.attestation`
keys have no effect ([configuration.md](configuration.md#attestation)).

## Not implemented

- RFC 2136 UPDATE processing on the platform's DNS server, including
  prerequisites (an UPDATE is refused with NOTIMP today).
- A DDNS client that sends UPDATE to another server, so DS records are never
  pushed to a parent zone ([dnssec-rollover.md](dnssec-rollover.md)).
- TSIG (RFC 8945) or SIG(0) authentication of updates.

## See also

- [API](api.md) · [Records](records.md) · [Zones](zones.md) · [Zone transfer](zone-transfer.md)

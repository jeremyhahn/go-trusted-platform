# DNS Operations Guide

> **Status: REFERENCE** · Last verified: 2026-10-18
> What an operator can observe and maintain in the platform's DNS server (`pkg/dns`) today. Every task below goes through `platformctl dns` ([cli.md](cli.md)), the [DNS API](api.md) or `dig`.

## What runs

Each listener is one CoreDNS server block built by `corefileBlock`
(`pkg/dns/corefile.go:29`). It loads only these plugins:

| Plugin | Effect |
|--------|--------|
| `trustedPlatform` | Answers from the platform's zones and serves AXFR/IXFR ([resolution.md](resolution.md), [zone-transfer.md](zone-transfer.md)) |
| `log` | One stdout line per query |
| `chaos` | Answers CHAOS-class `version.bind`-style queries |
| `dns64` | Only when `dns64` is configured ([configuration.md](configuration.md#dns64)) |
| `forward` | Only when forwarders are set |

The public listener defaults to port 8053 and the internal one to 9053
(`DefaultPublicPort`, `DefaultInternalPort`, `pkg/dns/config.go:30-35`).

## Monitoring

There is no DNS health endpoint and no Prometheus metric: neither the
`health` nor the `prometheus` CoreDNS plugin is loaded, and no `dns:` key
configures one.

| Check | How |
|-------|-----|
| Listener answers | `dig @<host> -p 8053 <zone> SOA` (internal zones: `-p 9053`) |
| Zone is signed | `dig @<host> -p 8053 <zone> DNSKEY +dnssec`, or the DNSSEC status call ([api.md](api.md#2-capability-matrix)) |
| Zone and record counts | QUIC `OpDNSGetMetrics` (`handleDNSGetMetrics`, `pkg/api/daemon/quic_dns.go:358`) |

`OpDNSGetMetrics` sets only `zone_count` and `total_records`. Its other
fields (`queries_total`, `cache_hits`, `cache_misses`, `dnssec_validated`,
`forwarded_queries`) are always zero.

## Logging

DNS logs go to the daemon's logger (`Configuration.Logger`); there is no
DNS-specific logging key.

- `ServeDNS` (`pkg/dns/plugin.go:74`) logs every query and every answer at
  info level, the answer with its records, on top of the `log` plugin's line.
- A public-listener query for an internal zone is logged as a high-severity
  security event and passed to the next plugin instead of answered from the
  zone.

## Routine task: re-sign before signatures expire

RRSIGs are valid for `dnssec.signature-expiry` (default 30 days). A zone is
signed when it is saved and, when the key store is set at startup, only if it
has no signatures (`SignUnsignedZones` and `needsDNSSECSigning`,
`pkg/dns/plugin.go:720` and `:638`). Nothing re-signs on a
schedule, so a zone untouched for that long becomes bogus. Re-sign each
signed zone well inside the window with the sign call
([api.md](api.md#2-capability-matrix), [dnssec.md](dnssec.md)).

## Backup and recovery

Zones are stored through go-quicbaas (`dns.quicbaas`,
[configuration.md](configuration.md#top-level-keys)), and DNSSEC private keys in the
go-quicbaas KMS ([dnssec.md](dnssec.md)). They are backed up with that
storage; the DNS service has no export, import or backup verb.

Two ways to copy a zone's contents:

- Read it through the API (get zone, list records) and re-create it with
  create zone and add record.
- Pull it over AXFR to a TSIG-authenticated secondary
  ([zone-transfer.md](zone-transfer.md)).

A zone restored without its keys is signed with new keys, so its DS at the
parent must be replaced ([dnssec-rollover.md](dnssec-rollover.md)).

## Not available

Maintenance mode, a DNS cache to size or flush, performance keys
(`dns.performance`, `dns.cache`), scheduled backups, and DNS cluster
commands do not exist.

## See also

- [Troubleshooting](troubleshooting.md) · [Security](security.md) · [Configuration](configuration.md)

# DANE/TLSA Records

> **Status: REFERENCE** · Last verified: 2026-10-18
> TLSA records the platform publishes for its own certificates (RFC 6698, RFC 7671), and the `dns.dane` keys that drive them.

## Overview

A TLSA record at `_<port>._tcp.<hostname>.` binds a TLS certificate to a name
(RFC 6698 §2). A client trusts it only if the zone is DNSSEC-signed and it
validates the chain, so DANE needs [DNSSEC](dnssec.md) on the zone.

```
_443._tcp.www.example.com. IN TLSA <usage> <selector> <matching-type> <data>
```

| Field | Values (RFC 6698 §2.1) |
|-------|------------------------|
| Usage | 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE |
| Selector | 0 full certificate, 1 SubjectPublicKeyInfo |
| Matching type | 0 exact, 1 SHA-256, 2 SHA-512 |

The record's YAML fields are in [records.md](records.md#tlsa-record).

## Configuration

```yaml
dns:
  dane:
    enabled: true
    auto-generate: true
    default-port: 443
    ttl: 3600
    default-usage: 3
    default-selector: 1
    default-matching-type: 1
    publish-dane-ee: false
    rollover-ttl: 0          # 0 = 2 x ttl
```

Every key and its type is in [configuration.md](configuration.md#dane).
`key-reuse` is parsed but has no effect: the only reader is
`RolloverManager` (`pkg/bootstrap/rollover.go`), which nothing constructs.

## What publishes TLSA records

An operator can add a TLSA record through the API (`Service.AddRecord` takes the
RDATA `usage selector matching-type data`, RFC 6698 §2.2). An operator adds
one with `platformctl dns record add --type tlsa` ([cli.md](cli.md)). The platform's own TLSA
records come from a zone's configured `tlsa:` list or from one of these paths,
all gated on `dane.enabled`:

| Trigger | Code | Records |
|---------|------|---------|
| Webservice certificate issued, with `auto-generate` | `publishDANETLSA`, `pkg/app/app.go:4286` | DANE-TA (usage 2) from the platform intermediate CA, or the root when there is no intermediate; plus DANE-EE (usage 3) from the leaf when `publish-dane-ee` is set |
| Certificate issued by the platform ACME server, with `auto-generate` | `NewTLSAGenerationHook`, `pkg/webservice/v1/registry.go:678` | One record from the configured usage/selector/matching type |
| BMC enrolled | `pkg/app/bmc_enroll.go:356` | As for a webservice certificate |
| BMC certificate renewed | `buildBMCRenewalHooks`, `pkg/app/bmc_cert_init.go:387` | On issue: a DANE-EE record for the new certificate at `rollover-ttl` (pre-publish); once deployed: the DANE-TA (and optional DANE-EE) set, port 443, internal zone |
| BMC removed | `pkg/app/bmc_restore.go:140` | The host's TLSA records deleted |
| go-quicbaas SDK publisher | `pkg/storage/quicbaas/dane_publisher_adapter.go` | Records the SDK asks to publish, written through the same publisher |

The `DANEPublisher` paths (`pkg/bootstrap/dane_publisher.go`) name the record
`_<port>._tcp.<hostname>.` with the port from `default-port` (443 when 0) and
the hostname from the certificate CN. For webservice certificates the zone is
the configured internal or public zone the hostname falls under, else the
hostname's parent when such a zone exists (`resolveDANEZone`,
`pkg/app/app.go:4370`); BMC paths use the internal zone. Selector and matching
type come from `default-selector` and `default-matching-type`. They write
through `Service.AddTLSARecord`, then re-sign the zone with `SaveAndSign`. Their TTL is `ttl` as configured, so `ttl: 0` publishes records
with TTL 0.

The ACME hook differs: it writes to the internal zone (the public zone when
there is none) whatever the hostname, falls back to the first DNS SAN when the
CN is empty, defaults `ttl` to 3600, does not re-sign, and never fails
issuance — an error is logged and the certificate is still returned.

## Rollover

With DANE-TA (usage 2), renewing a leaf under the same CA leaves the record
valid; only a CA change needs a new record. For DANE-EE, the BMC renewal path
pre-publishes the new record before the certificate is deployed, so both
records are served for one `rollover-ttl` (RFC 7671 §8.1). Other paths have no
pre-publish step.

## Checking a record

```bash
# The record and its signature
dig TLSA _443._tcp.www.example.com @127.0.0.1 -p 8053 +dnssec

# SHA-256 of the certificate's SPKI (selector 1, matching type 1)
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | openssl sha256

# End to end against a DANE-capable client
openssl s_client -connect www.example.com:443 -dane_tlsa_domain www.example.com
```

The zone's TLSA records are also listed by
`GET /api/v1/dns/zones/{zone}/records?type=TLSA` ([api.md](api.md)).

## Related Documentation

- [DNSSEC](dnssec.md) — the signatures DANE depends on
- [Configuration](configuration.md#dane) — the `dns.dane` keys
- [Records](records.md#tlsa-record) — TLSA record fields
- [BMC user guide](../bmc/user.md) — BMC certificates
- [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) · [RFC 7671](https://datatracker.ietf.org/doc/html/rfc7671)

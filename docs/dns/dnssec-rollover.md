# DNSSEC Key Rollover

> **Status: REFERENCE** · Last verified: 2026-10-19
> DNSSEC key rollover is **not implemented**. This page states what `pkg/dns` does with zone keys today and what a rollover would need.

## What the code does

Each signed zone has exactly one KSK and one ZSK, held in the go-quicbaas KMS
and scoped by tenant and zone ([dnssec.md](dnssec.md)).

| Step | Code | Behaviour |
|------|------|-----------|
| First sign | `DNSSECService.SignZone`, `pkg/dns/dnssec.go:296` | `LoadKeys` fails, so `generateKeysXKMS` creates a KSK and a ZSK |
| Every later sign | same | Loads the two keys, clears every DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM and DS record, then publishes the two DNSKEYs and re-signs |
| DS record | `GenerateDS` | One DS for the current KSK, added to the zone itself; nothing sends it to a parent |
| Key replacement | `DNSSECService.PrepareKeyRollover`, `pkg/dns/dnssec.go:1210` | Deletes the KSK or ZSK, then generates a new one: the key store holds one key per tenant, zone and type, so the new key cannot be generated beside the old one. A failed delete is returned and the current key kept; a failed generation after the delete returns `ErrRolloverKeyDeleted`, since the zone then has no key of that type. Only tests call it; no API route, CLI verb or scheduler reaches it |

`dnssec.ksk.lifetime` and `dnssec.zsk.lifetime` are validated at startup
(`ErrInvalidKeyLifetime` unless a positive duration) but nothing schedules a
rollover from them.

## Why replacing a key breaks validation

Because the signer rebuilds the DNSKEY set from the one current KSK and ZSK,
an old key cannot stay published next to the new one. A replaced key
therefore takes effect at once:

- **ZSK**: resolvers that cached signatures from the old ZSK fail to validate
  them until the cached records expire.
- **KSK**: the DS at the parent no longer matches, so the zone is bogus for
  validating resolvers until the parent's DS is replaced by hand.

There is no supported procedure for changing a zone's keys today.

## Not implemented

| Piece | Standard |
|-------|----------|
| ZSK pre-publication rollover | RFC 7583 |
| KSK double-DS rollover | RFC 7583 |
| Key timing states and scheduling from `lifetime` | RFC 7583 |
| CDS/CDNSKEY publication for the parent | RFC 7344 |
| DS update at the parent over DNS UPDATE | RFC 2136 (no UPDATE support, see [dynamic-dns.md](dynamic-dns.md)) |
| Rollover CLI or API | none (there is no `platformctl dns` group) |

## See also

- [DNSSEC](dnssec.md) · [Configuration](configuration.md#dnssec) · [DANE rollover](dane.md#rollover)

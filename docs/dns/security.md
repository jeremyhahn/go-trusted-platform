# DNS Security

> **Status: REFERENCE** · Last verified: 2026-10-18
> The controls `pkg/dns` applies today, and the ones it does not have. There is no `platformctl dns` group (#954).

## Controls in the code

| Control | Code | What it does |
|---------|------|--------------|
| API authorization | [api.md](api.md#4-authorization) | gRPC and MCP calls need a `dns` scope (`read`, `write`, `delete`); REST `/api/v1/dns/**` needs the `admin` role |
| Zone tenant check | `Service.authorizeZoneAccess`, `pkg/dns/service.go:166` | `Save`, `SaveAndSign`, `SignZone`, `Delete` and `Zone` refuse a zone whose `TenantID` differs from the service's own |
| Internal zones off the public listener | `ServeDNS`, `pkg/dns/plugin.go:116-134` | A public-port query for a zone marked `internal` is not answered from the zone |
| Zone transfer | [zone-transfer.md](zone-transfer.md) | Off by default; AXFR/IXFR only to TSIG-authenticated secondaries, others get REFUSED |
| DNSSEC signing | [dnssec.md](dnssec.md) | Zones are signed with keys held in the go-quicbaas KMS; NSEC or NSEC3 by `dnssec.nsec-mode` |

### Tenant check

The tenant compared is the DNS service's own (`Params.TenantID`, set from the
platform tenant at `pkg/app/app.go:1200`), not the caller's. A zone saved with
no tenant takes the service's (`ensureZoneTenantID`, `pkg/dns/service.go:183`).
An unset service tenant fails with `ErrMissingTenantContext`; a mismatch fails
with `ErrUnauthorizedZoneAccess` and a warning naming both tenants, the zone
and the action. `Register` checks only that the name is free
([api.md](api.md#6-zone-registration-has-no-ownership-check)).

### Internal and public listeners

| Listener | Default port | Serves |
|----------|--------------|--------|
| Internal | 9053 | Every zone |
| Public | 8053 | Zones not marked `internal` |

`dns.internal` and `dns.public` take only `port`, `forwarders` and `zone`
(`pkg/dns/config.go:359-369`); there is no bind-address key, so which
networks reach each port is up to the host firewall.

A public-port query for an internal zone is logged as an error and a
high-severity security event, then passed to the next plugin. No answer from
the zone reveals that it exists.

### DNSSEC keys

The KSK and ZSK are created in the go-quicbaas KMS software store
(`xkmssdk.StoreSoftware`, `pkg/dns/dnssec_keystore_sdk.go:202`), not in a TPM,
and the `store:` field of a key configuration is not read. Key IDs are
`dnssec_<tenant>_<zone with dots as hyphens>_<ksk|zsk>` (`makeKeyID`,
`pkg/dns/dnssec_keystore.go:108`). Algorithms are listed in
[dnssec.md](dnssec.md#supported-algorithms).

## Security events

These go to the daemon logger's security channel (`Logger.Security`):

| Event | Severity | Code |
|-------|----------|------|
| Public-port query for an internal zone | High | `pkg/dns/plugin.go:122` |
| Refused zone transfer | Medium | `pkg/dns/axfr.go:162` |

A refused tenant check is a plain warning (`pkg/dns/service.go:171`), not a
security event. Zone and record changes have no DNS-specific audit log.

## Not implemented

| Control | State |
|---------|-------|
| TPM-held or PCR-sealed DNSSEC keys | Keys are in the KMS software store |
| Query rate limiting, response rate limiting, connection limits | No plugin is loaded and no `dns:` key configures one ([operations.md](operations.md#what-runs)) |
| Signed DNS UPDATE (TSIG, SIG(0)) | No UPDATE support ([dynamic-dns.md](dynamic-dns.md)) |
| Attestation-gated updates | `pkg/dns/attestation` is not wired ([configuration.md](configuration.md#attestation)) |
| DNS over TLS or HTTPS | Planned design ([dot-doh.md](dot-doh.md)) |
| Key rollover and scheduled re-signing | [dnssec-rollover.md](dnssec-rollover.md), [operations.md](operations.md#routine-task-re-sign-before-signatures-expire) |

The keys `dns.rate-limit`, `dns.ddns` and `dnssec.signatures` do not exist.

## See also

- [DNSSEC](dnssec.md) · [Zone transfer](zone-transfer.md) · [API](api.md) · [Configuration](configuration.md) · [Auth architecture](../auth/architecture.md)

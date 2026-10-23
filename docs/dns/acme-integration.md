# ACME DNS Integration

> **Status: REFERENCE** · Last verified: 2026-10-18
> dns-01 ACME challenges answered from the platform's DNS zones (`pkg/dns/`, `pkg/app/bmc_cert.go`).

## Overview

The DNS subsystem takes part in ACME `dns-01` (RFC 8555 §8.4) in two places:

| Role | Who | Code |
|------|-----|------|
| **Client side**: publish the challenge TXT record | BMC certificate issuance | `pkg/app/bmc_cert.go` |
| **Server side**: verify a client's TXT record | the platform ACME server, when `dns-01` is in its `challenges` list | `buildChallengeMap`, `pkg/daemon/commands/serve.go:248` |

There is no general-purpose dns-01 client, no ACME scheduler and no
`platformctl cert` command. Platform certificates other than BMC certificates
are issued by the platform CA ([docs/ca/](../ca/)).

## Publishing a challenge (BMC certificates)

A BMC certificate request is built with `ChallengeType: "dns-01"`
(`pkg/app/bmc_cert.go:279`). BMCs sit on isolated management VLANs, so
`dns-01` is the only challenge the BMC config accepts; see
[docs/bmc/user.md](../bmc/user.md).

| Step | What happens |
|------|--------------|
| Setup | `dns01.ComputeChallengeValue(keyAuth)` gives the TXT value (base64url SHA-256 of the key authorization, RFC 8555 §8.4). The record `_acme-challenge.<authz-value>` is added through the DNS service's `AddRecord` with type `TXT`. |
| TTL | The request's TTL, or `60` seconds when it is unset or not positive. |
| Authz value | `certificate.acme.authz-value`, falling back to the certificate subject CN. |
| Cleanup | `DeleteRecord(name, "TXT")` after the challenge, best effort: a failure is logged at info level and does not fail issuance. |

`Service.AddRecord` (`pkg/dns/service.go:1151`) files the record in the
longest stored zone whose name is a suffix of the record name (`zoneForName`,
`pkg/dns/service.go:1317`), so `_acme-challenge.bmc.internal.example.com.`
lands in `internal.example.com.` when that zone exists. It then adds the
record and saves the zone. With `dns.dnssec.enabled`, every zone save re-signs
the zone ([dnssec.md](dnssec.md#zone-signing-process)), so the TXT record is
served with an RRSIG.

## Verifying a challenge (platform ACME server)

The ACME server on a webservice is configured under its `acme:` block
(`ACMEConfig`, `pkg/webservice/v1/config.go:94`):

```yaml
acme:
  enabled: true
  directory: https://server.example.com/api/v1/acme/directory
  challenges:
    - dns-01
```

`buildChallengeMap` maps `http-01`, `dns-01`, `enroll-01` and `endorse-01` to
verifiers; any other name in the list is ignored. `dns-01` calls the SDK's
`ACMEVerifyDNS01` with the `*net.Resolver` the SDK ACME server passes in.
The ACME server itself is documented in [docs/ca/acme.md](../ca/acme.md).

## Wildcards

RFC 8555 §8.4: a wildcard name validates at the base domain, so `*.example.com`
uses `_acme-challenge.example.com`.

## Debugging

```bash
# The challenge record on the public server (default port 8053)
dig TXT _acme-challenge.example.com @127.0.0.1 -p 8053

# With its signature, when DNSSEC is enabled
dig TXT _acme-challenge.example.com @127.0.0.1 -p 8053 +dnssec
```

The zone's records are also readable over the API:
`GET /api/v1/dns/zones/{zone}/records?type=TXT` ([api.md](api.md)).

## CAA

A zone can carry CAA records (`caa:` in the zone's `records`,
[configuration.md](configuration.md#zones)) to restrict which CAs may issue for
it. CAA is a zone record like any other; nothing in the ACME path reads it.

## Related Documentation

- [DNSSEC](dnssec.md) — signing on save
- [Configuration](configuration.md) — the `dns:` section
- [API](api.md) — zone and record routes on every transport
- [BMC user guide](../bmc/user.md) — BMC certificate configuration
- [ACME server](../ca/acme.md)

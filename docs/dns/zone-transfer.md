# DNS Zone Transfers (AXFR)

> **Status: Outbound AXFR implemented (platform as PRIMARY).**
>
> The Trusted Platform DNS server acts as a **primary (master) nameserver**.
> It serves full zone transfers (AXFR, RFC 5936) over DNS TCP to explicitly
> configured, **TSIG-authenticated** secondary nameservers. Inbound/secondary
> mode, IXFR, and NOTIFY are **not** implemented — see
> [Not Yet Implemented](#not-yet-implemented).

## Overview

A zone transfer lets a downstream secondary nameserver obtain a complete copy
of an authoritative zone from the platform. The platform is always the primary
in this relationship: secondaries **pull** the zone from the platform; the
platform never pulls a zone from an upstream primary.

| Benefit | Description |
|---------|-------------|
| **Redundancy** | Secondaries keep answering queries if the platform is unreachable |
| **Load Distribution** | Query load is spread across the platform + secondaries |
| **Geographic Distribution** | Place secondaries closer to clients for lower latency |

### What "primary" means here

- The platform holds the authoritative zone data in its own store (the same
  zone/record store used by the DNS CRUD APIs and WebUI).
- A secondary sends an `AXFR` query for a zone over **TCP**, signed with a
  configured **TSIG** key.
- The platform validates the TSIG, then streams the full zone — the apex SOA,
  every record in the zone (including any DNSSEC records), and a closing apex
  SOA, in RFC 5936 order — signing the response with the same key.
- Any request that is not TCP, not TSIG-signed, or signed with an
  unconfigured/unauthorized key is **refused** and security-logged. The
  responder is **fail-closed**: with no configured keys, every transfer
  request is refused.

## Where the AXFR responder lives (transport)

AXFR is a **DNS-protocol operation on TCP/53**, not one of the platform's five
API protocols (REST/gRPC/QUIC/MCP/Unix). The wire responder therefore lives in
the authoritative DNS server itself — the CoreDNS `trustedPlatform` plugin —
which is where secondaries connect. It is **not** exposed through the API
protocols, because a secondary nameserver speaks DNS, not the platform SDK.

The DNS server validates the request TSIG (the configured keys are installed
into the server's TSIG secret table at startup) and signs the AXFR response.
The zone content emitted on the wire is produced by `dns.BuildZoneTransfer`,
the single projection function that both the wire responder and the REST
export surface share, so they never drift.

### REST/management surface

`POST /api/v1/dns/transfer` is a **management / export** surface, not a wire
transfer. It returns exactly the records a secondary would receive (RFC 5936
order, rendered as presentation-format strings) plus the configured secondary
key names, so an operator can preview a zone export or audit which secondaries
are authorized. It never performs a wire transfer and never discloses a TSIG
secret.

```jsonc
// POST /api/v1/dns/transfer  { "zone_name": "example.com." }
{
  "zone_name": "example.com.",
  "model": "primary",
  "records": [
    "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 2026080401 86400 7200 3600000 3600",
    "example.com.\t3600\tIN\tNS\tns1.example.com.",
    "www.example.com.\t300\tIN\tA\t192.0.2.10",
    "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 2026080401 86400 7200 3600000 3600"
  ],
  "record_count": 4,
  "secondaries": ["secondary1."],
  "message": "authoritative AXFR is served over DNS TCP to TSIG-authenticated secondaries; this is the zone-export preview",
  "timestamp": "2026-08-04T00:00:00Z"
}
```

## Configuration

Zone transfers are configured under `dns.transfer`. Transfers are **off by
default**; they are served only when `enabled: true` and at least one TSIG key
is configured (explicit-config, fail-closed).

```yaml
dns:
  transfer:
    enabled: true
    tsig-keys:
      - name: "secondary1."          # TSIG key name (canonicalized to lowercase FQDN)
        algorithm: "hmac-sha256"      # optional; defaults to hmac-sha256
        secret: "${ZONE_TRANSFER_KEY}" # base64-encoded shared HMAC secret
```

### `dns.transfer` options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for the outbound AXFR responder |
| `tsig-keys` | list | `[]` | Shared TSIG keys authorized to pull zone transfers |

### `tsig-keys[]` options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | TSIG key name; canonicalized to a lowercase FQDN (e.g. `secondary1.`) |
| `algorithm` | string | No | HMAC algorithm; one of `hmac-sha256` (default), `hmac-sha512`, `hmac-sha1` |
| `secret` | string | Yes | Base64-encoded shared HMAC secret. Provide via environment/secret reference — never hardcode |

A key with an empty `name` or `secret` is ignored. If no valid key remains,
the responder stays fail-closed.

## Secondary (BIND) configuration example

A downstream BIND secondary pulling from the platform (primary at
`192.0.2.1`):

```
key "secondary1." {
    algorithm hmac-sha256;
    secret "<same base64 secret as dns.transfer.tsig-keys[].secret>";
};

server 192.0.2.1 {
    keys { "secondary1."; };
};

zone "example.com." {
    type secondary;
    primaries { 192.0.2.1 key "secondary1."; };
    file "db.example.com.";
};
```

## Security

| Control | Implementation |
|---------|----------------|
| TSIG authentication | Mandatory. Requests without a TSIG, or with an unconfigured key, are refused |
| TSIG verification | The DNS server verifies the request MAC before the handler runs (`TsigStatus`) |
| TCP-only | AXFR over UDP is refused (RFC 5936 §4.2) |
| Fail-closed | No configured keys ⇒ every transfer refused |
| No data leak | Refused transfers reply `REFUSED` with an empty answer section |
| Audit logging | Every refusal is written to the security log with the offender address and reason |
| Response signing | The AXFR response is signed with the requesting key so the secondary can authenticate it |

**Best practices**

- Use a distinct TSIG key per secondary (or per trust domain) to limit blast
  radius and simplify rotation.
- Prefer `hmac-sha256` or `hmac-sha512`.
- Supply secrets through environment variables / secret references, never
  literals in checked-in config.
- Rotate TSIG keys on a regular cadence.

## Not Yet Implemented

The following were part of an earlier design sketch and are **not** in the
current build. They are documented here only to set expectations; the code
does not read any of this configuration:

| Feature | Status |
|---------|--------|
| **IXFR** (incremental, RFC 1995) | Not implemented — an `IXFR` query is served as a full `AXFR` |
| **NOTIFY** (RFC 1996) | Not implemented — secondaries poll on their SOA refresh timer |
| **Secondary/slave mode** | Not implemented — the platform is primary-only and never pulls a zone |
| **IP-based `allow-transfer` ACLs** | Not implemented — authorization is by TSIG key, not source IP |
| **Per-zone key scoping / rate limiting** | Not implemented — a configured key may transfer any served zone |
| **`platformctl dns transfer …` CLI** | Not implemented — use the REST export surface for previews |

When any of these lands, this document and the `dns.transfer` schema must be
updated in the same change.

## Related Documentation

| Document | Description |
|----------|-------------|
| [Security](security.md) | DNS security model and TPM integration |
| [Zones](zones.md) | Zone management and configuration |
| [DNSSEC](dnssec.md) | DNSSEC signing and validation |
| [Architecture](architecture.md) | DNS system architecture |
| [Configuration](configuration.md) | Full DNS configuration reference |

## See Also

- [RFC 5936 - DNS Zone Transfer Protocol (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936)
- [RFC 8945 - Secret Key Transaction Authentication for DNS (TSIG)](https://datatracker.ietf.org/doc/html/rfc8945)
- [RFC 1995 - Incremental Zone Transfer in DNS (IXFR)](https://datatracker.ietf.org/doc/html/rfc1995)
- [RFC 1996 - DNS NOTIFY](https://datatracker.ietf.org/doc/html/rfc1996)

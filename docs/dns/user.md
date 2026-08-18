# DNS — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Task-oriented guide for operators running the platform's authoritative DNS.
> Internals are in [engineering.md](engineering.md).

---

## What this is

The platform runs its own authoritative DNS: zones, records, DNSSEC signing,
DANE/TLSA publication, and a resolver with forwarders. It is authoritative for
platform names, so the CoreDNS configuration is **generated** from platform
state rather than hand-maintained.

---

## Before anything else: there is no `platformctl dns`

Every task below is an API call. The CLI group does not exist
([cli.md](cli.md)), and a document in this folder
([cli-reference.md](cli-reference.md)) describes one that was never built — it is
fenced with an archive banner. Use REST or gRPC.

---

## Two things to settle before you deploy

### 1. Zone registration does not verify ownership

The `Register` route creates a zone after checking only that the name is not
already taken. Ownership verification is deferred in the code, blocked on the
IAM domain-ownership model.

That is fine on an internal-only server. On anything reachable from outside,
with `allow-external-registration` on, **a caller can claim any zone name that
is not already taken.** Decide deliberately:

| Key | Set it to |
|---|---|
| `allow-registration` | The master switch. Off unless you need dynamic registration. |
| `allow-internal-registration` | Reasonable on a trusted segment. |
| `allow-external-registration` | Not without an ownership check, or a compensating control in front of it. |

### 2. Which DNSSEC key store you are using

Three backends exist. The **quicbaas KMS key store generates a local placeholder
key pair** rather than fetching the key from the KMS — the code says so at
`pkg/dns/dnssec_keystore_quicbaas.go:597`.

Zones signed with such a key validate normally, which is exactly the problem:
nothing looks wrong, and the key is not actually under KMS management, rotation
or audit. If DNSSEC key custody matters to you, use the xkms-backed key store
and confirm which backend is configured before signing anything.

---

## Zones and records

```bash
# List zones
curl -s https://platform.example.com/api/v1/dns/zones

# Create a zone
curl -s -X POST https://platform.example.com/api/v1/dns/zones \
     -d '{"name":"apps.example.com"}'

# Add a record
curl -s -X POST https://platform.example.com/api/v1/dns/zones/apps.example.com/records \
     -d '{"type":"A","name":"web","value":"203.0.113.10","ttl":300}'

# List records
curl -s https://platform.example.com/api/v1/dns/zones/apps.example.com/records

# Delete a record — keyed by type AND name
curl -s -X DELETE \
     https://platform.example.com/api/v1/dns/zones/apps.example.com/records/A/web
```

Deleting a record takes both the type and the name in the path, so `A web` and
`AAAA web` are removed independently.

Supported record types are a closed set: A, AAAA, CNAME, MX, NS, SOA, SRV, TXT,
CAA, TLSA, DNSKEY, DS, RRSIG. Anything else is rejected as an unsupported record
type.

Creating a zone that exists is an error, not an update.

---

## Signing a zone

```bash
curl -s -X POST https://platform.example.com/api/v1/dns/zones/apps.example.com/sign
curl -s https://platform.example.com/api/v1/dns/zones/apps.example.com/dnssec
```

Signing and status are separate operations: a zone is not "signed" because
signing was requested, only because status says so.

**DNSSEC is reachable on REST, gRPC and in-process only.** There is no QUIC or
MCP route for signing or status.

---

## Operational verbs are QUIC-only

Four things an operator regularly wants have **no REST and no gRPC route**:

| Task | QUIC opcode |
|---|---|
| Flush the DNS cache | `OpDNSFlushCache` (`0x2D`) |
| Read DNS metrics | `OpDNSGetMetrics` (`0x2C`) |
| Read DNS config | `OpDNSGetConfig` (`0x2A`) |
| Update DNS config | `OpDNSUpdateConfig` (`0x2B`) |

If you do not have a QUIC client, you cannot flush the cache. That is a real
constraint on day-to-day operation, recorded as a gap in [api.md](api.md).

---

## If you are driving DNS from an AI/MCP client

There are **two parallel tool families** for the same operations —
`dns_create_zone` and `dns_zone_create` both create a zone — and **only the
older family requires a permission.** `dns_create_zone` needs `dns:write`;
`dns_zone_create` needs nothing beyond a valid token.

Until that is resolved, prefer the older names (`dns_create_zone`,
`dns_add_record`, `dns_list_zones`, `dns_delete_zone`, `dns_delete_record`,
`dns_get_record`, `dns_list_records`, `dns_resolve`) so calls are actually
scope-checked. [api.md](api.md) §3 has the full mapping.

---

## Troubleshooting

**The DNS service will not start, and the error mentions resolver servers.**
`ErrNoResolverServers` — no forwarders or resolver addresses configured. Also
check `ErrInvalidResolverAddress` and `ErrInvalidResolverPort` for a malformed
entry.

**The service will not start, and the error mentions zone subdomains.**
Subdomain expansion needs **both** an internal server and declared network
zones. Configuring one without the other is refused at load rather than
producing zones that resolve to nothing.

**A record will not save and the type is rejected.**
It is outside the thirteen supported types.

**Creating a zone returns "already exists" for a zone you cannot see.**
The name is taken. With registration open, it may have been taken by somebody
else — see "zone registration does not verify ownership" above.

**Everything returns 503.**
The DNS service is not wired into the daemon. Configuration, not a crash.

**Hand edits to the CoreDNS Corefile keep disappearing.**
The Corefile is generated from platform state. Change the platform's zones and
forwarder configuration instead.

---

## Where to go next

- [api.md](api.md) — every capability on every transport, and the gaps
- [engineering.md](engineering.md) — the two known defects, in detail
- [architecture.md](architecture.md) — how zones, DNSSEC and the resolver compose
- [dnssec.md](dnssec.md), [dnssec-rollover.md](dnssec-rollover.md),
  [dane.md](dane.md), [dot-doh.md](dot-doh.md) — deep dives (not re-verified in
  the 2026-08-18 pass)

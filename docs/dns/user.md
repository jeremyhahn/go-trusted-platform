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
([cli.md](cli.md)), and a deleted document
(cli-reference.md) described one that was never built. Use REST or gRPC.

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

Three backends exist. Each keeps the private key in its KMS and publishes the
matching public key as the zone's DNSKEY; confirm which backend is configured
before signing anything.

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

## Operational reads are QUIC-only

Two things an operator regularly wants have **no REST and no gRPC route**:

| Task | QUIC opcode |
|---|---|
| Read DNS metrics | `OpDNSGetMetrics` (`0x2C`) |
| Read DNS config | `OpDNSGetConfig` (`0x2A`) |

There is no way to change DNS config at runtime or to flush a cache on any
transport: change the configuration and restart. The two QUIC opcodes that
claimed those verbs never did anything and were retired (#317); see
[api.md](api.md) §2.

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

## Serving IPv6-only clients (DNS64)

An IPv6-only client cannot reach a name that has only an A record. DNS64
answers it with an AAAA built from a NAT64 translator's prefix, and the
translator turns the flow back into IPv4. **You need both halves.** This is the
DNS half; the translator is the gateway's `nat64:` service, and turning this on
without one produces answers that route nowhere.

Add a `dns64:` section to the DNS configuration:

```yaml
dns:
  dns64:
    enabled: true
    prefix: "64:ff9b::/96"   # must match the translator's prefix
    servers: [internal]      # default; add "public" only if you mean it
```

Everything is optional but `enabled`. The prefix defaults to the RFC 6052
Well-Known Prefix, `64:ff9b::/96`, and the section applies to the internal
listener only.

**What the settings do**

| Key | Effect |
|---|---|
| `prefix` | The translator's prefix. Must be /32, /40, /48, /56, /64 or /96, and the Well-Known Prefix only at /96. Anything else is refused at startup. |
| `servers` | Which listeners synthesise: `internal`, `public`, or both. |
| `translate-all` | Synthesise even for names that already have AAAA. Only for a network with no route to native IPv6 at all. |
| `allow-ipv4` | Synthesise for queries arriving over IPv4. Off by default, because a client that asked over IPv4 can usually reach the IPv4 address itself. |

**Three things to know before you turn it on**

1. **Do not point a validating resolver at a synthesising listener.** A
   synthesised AAAA has no signature — the resolver invented it. The upstream
   plugin synthesises regardless of whether the client asked for DNSSEC, so a
   validating stub behind it will fail to validate the answer. It never claims
   authentication it does not have (the AD bit stays clear), but validation
   will fail.
2. **Leave `servers` at the default unless you have a reason.** Synthesising on
   the public authoritative server hands the Well-Known Prefix to resolvers on
   the internet that have no route to your translator.
3. **The prefix has to match the translator's, and nothing checks that for
   you.** The two daemons are configured separately. A mismatch synthesises
   addresses that reach no translator, which looks like a routing fault rather
   than a DNS one.

**Checking it works.** Query the discovery name from an IPv6 client:

```
dig @<internal-server> AAAA ipv4only.arpa
```

The answer should be two AAAA records inside your prefix. `ipv4only.arpa` has A
records and deliberately no AAAA, so it is the one name whose answer is always
synthesised — RFC 7050 uses exactly that to let a client discover the prefix.
An empty answer means synthesis is not on for that listener.

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

**Everything returns 503 (gRPC `UNAVAILABLE`, reason `SERVICE_NOT_CONFIGURED`).**
The daemon configuration has no `dns:` section, so no DNS service started.
Configuration, not a crash.

**Hand edits to the CoreDNS Corefile keep disappearing.**
The Corefile is generated from platform state. Change the platform's zones and
forwarder configuration instead.

---

## Where to go next

- [api.md](api.md) — every capability on every transport, and the gaps
- [engineering.md](engineering.md) — the two known defects, in detail
- [architecture.md](architecture.md) — how zones, DNSSEC and the resolver compose
- [dnssec.md](dnssec.md), [dnssec-rollover.md](dnssec-rollover.md),
  [dane.md](dane.md), [dot-doh.md](dot-doh.md) — deep dives

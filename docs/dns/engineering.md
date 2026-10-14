# DNS — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/dns/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

| File / dir | Holds |
|---|---|
| `service.go`, `types.go`, `config.go` | The service façade, types, configuration |
| `resolver.go`, `resolver_errors.go` | Resolution and forwarding |
| `dnssec.go`, `dnssec_errors.go` | Zone signing and DNSSEC status |
| `dnssec_keystore.go`, `dnssec_keystore_sdk.go`, `dnssec_keystore_quicbaas.go` | DNSSEC key storage, three backends |
| `datastore.go`, `dao/`, `entities/` | Persistence — DAO/entity, not raw KV |
| `corefile.go`, `plugin.go`, `parser.go` | CoreDNS integration |
| `axfr.go` | Zone transfer |
| `zonesubdomains.go`, `tld.go`, `macros.go` | Zone naming and expansion |
| `attestation/` | Attestation-aware DNS records |
| `mocks/` | Test doubles |

## 2. Exported surface

### Record constructors

One per record type, all in `entities`-facing form:
`NewARecord`, `NewAAAARecord`, `NewCNAMERecord`, `NewMXRecord`, `NewNSRecord`,
`NewSOARecord`, `NewSRVRecord`, `NewTXTRecord`, `NewCAARecord`,
`NewTLSARecord`, `NewDNSKEYRecord`, `NewDSRecord`, `NewRRSIGRecord`.

`ErrRecordTypeNotSupported` is a sentinel (`errors.New`) returned for anything
outside that set. Adding a record type means adding a constructor **and** a
parser case; adding only one produces a type that can be stored and not read, or
read and not stored.

### Service

```go
func NewService(params *Params) (*Service, error)
func NewDatastore(storage quicbaas.Storage, logger *logging.Logger) *Datastore
```

`NewService` takes a `*Params` struct rather than functional options — the one
place in this feature that diverges from the portfolio option pattern.

### DNSSEC key stores — four constructors, three backends

```go
NewDNSSECServiceWithKeyStore(config *DNSSECConfig, logger *logging.Logger, keyStore DNSSECKeyStore) (*DNSSECService, error)
NewDNSSECServiceWithXKMS(config *DNSSECConfig, logger *logging.Logger, adapter *xkmsadapter.Adapter) (*DNSSECService, error)
NewDNSSECServiceWithXKMSAndBackend(config *DNSSECConfig, logger *logging.Logger, adapter *xkmsadapter.Adapter, backend string) (*DNSSECService, error)
```

Key stores: `NewXKMSKeyStore`, `NewXKMSKeyStoreWithBackend`,
`NewQuicBaaSKMSKeyStore`, `NewSDKKeyStore`, `NewSDKKeyStoreWithBackend`, plus
`NewMockKeyStore` for tests.

### CoreDNS

```go
func NewCorefile(port int) string
func NewCorefileWithForwarders(port int, forwarders []string) string
func NewCorefileForServer(server string, port int, forwarders []string, dns64 *DNS64Config) string
```

These generate a Corefile; they do not read one. The platform is the authority
for zone content, and the Corefile is derived.

All three render through one unexported `corefileBlock`, so a directive added
for one listener cannot go missing on the other. `NewCorefileForServer` is what
`dns.Run` calls; the first two remain for callers that have no DNS64 section.

An empty forwarder list now renders no `forward` directive. It used to render
`forward .` with no upstream, which is a CoreDNS setup error — a latent defect
that never fired because every caller checked the length first.

## 3. Two known defects — read before trusting DNSSEC

Both are in the code today and both are security-relevant. They are recorded
here rather than left as comments an implementer will not find.

### 3.1 The quicbaas DNSSEC key store generates a local placeholder key pair

`pkg/dns/dnssec_keystore_quicbaas.go:597` carries the comment:

> *"Note: This generates a local placeholder key pair. The actual public key
> should come from the QuicBaaS KMS."*

The function generates a key locally (RSA or Ed25519 by algorithm) and encodes
it to PEM. A paired failure path at `:138` wraps *"failed to generate local
public key placeholder"*.

**A DNSSEC signing key that is generated locally rather than fetched from the
KMS is not managed by the KMS**: it is not rotated by it, not audited by it, and
not protected by it. Zones signed with such a key validate — that is the
hazard — while the operator believes the key lives somewhere it does not.

The other key store backends (`XKMSKeyStore`, `SDKKeyStore`) do not have this
comment. **Whether the quicbaas backend should be blocked until this is fixed
is an owner decision**, raised in the migration report and not made here.

### 3.2 Domain ownership verification is not implemented

`pkg/dns/service.go:477`:

> *"DEFERRED: Domain ownership verification not yet implemented. Blocked by: IAM
> domain ownership model."*

Zone registration currently checks only that the zone does not already exist
(`ErrZoneAlreadyExists`). Nothing verifies that the requester is entitled to the
name. Combined with `allow-registration`, `allow-internal-registration` and
`allow-external-registration` in the configuration, this means **enabling
external registration on an authoritative server lets a caller claim any zone
name that is not already taken.**

The blocker is real — it needs the IAM domain-ownership model — but the gap is
live now and belongs in the deployment decision, not only in the backlog.

## 4. Configuration

`pkg/dns/config.go`. YAML keys use hyphens.

**Built-in zones (`DefaultConfig`) are placeholders.** The public zone is
`example.com.` and the internal zone `example.internal.` (RFC 2606 names; the
internal zone takes a `.internal` name because `Register` refuses a public TLD in
the internal zone with `ErrInvalidPrivateTLD`). Neither is a usable deployment
value, and the build carries no default domain either (the Makefile's `DOMAIN`
is unset): a deployment names its own zones.

**Registration gates — the three that decide exposure:**

| Key | Meaning |
|---|---|
| `allow-registration` | Master switch for dynamic registration |
| `allow-internal-registration` | Registration from internal zones |
| `allow-external-registration` | Registration from outside |

Read §3.2 before setting `allow-external-registration`.

**Resolution:** `forwarders`, `default-port`, `port`, `default-ttl`, `internal`,
`fallback`, `any`, `public`.

**Addressing:** `private-ipv4`, `private-ipv6`, `public-ipv4`, `public-ipv6`.

**DNS64 (`dns64:`)**: `enabled`, `prefix`, `translate-all`, `allow-ipv4`,
`servers`. See §6a.

**DNSSEC (`dnssec:`)**: `enabled`, `algorithm`, `auto-generate`, `key-reuse`,
`ksk`, `lifetime`, `max-age`, `nsec-mode`, `nsec3-iterations`, `nsec3-salt`.

`DNSSECConfig.Validate()` is called from `dns.Run` before the server starts, and
again from each `NewDNSSECService*` constructor for a config that reaches the
service by another route. It refuses `nsec-mode: nsec3` under FIPS activation
with `ErrFIPSNSEC3Unsupported` — RFC 5155 defines only a SHA-1 NSEC3 hash, which
`crypto/sha1` refuses by panicking under `fips140=only`. The check is a runtime
one, not build-tagged ([FIPS mode](../fips/architecture.md)). `validateForMode`
takes the mode as a parameter so both states are testable from one binary —
GODEBUG is fixed before `main`. See [dnssec.md](dnssec.md) for the operator-facing
consequence.

`TestSignZone_NSEC3Mode` lives in `dnssec_nsec3_test.go` behind `//go:build
!fips`: NSEC3 signing cannot be exercised in a FIPS build, so the test is
excluded there rather than weakened to run in both.

**DANE (`dane:`)**: `default-usage`, `default-selector`,
`default-matching-type`, `publish-dane-ee`.

**Attestation (`attestation:`)**: `default-pcr-policy`, `pcr-policies`, `pcrs`,
`expected`, `index`. DNS records can carry attestation policy — see
`pkg/dns/attestation/`.

### Configuration errors

`ErrNoResolverServers`, `ErrInvalidResolverPort`, `ErrInvalidResolverAddress`,
`ErrZoneSubdomainsNoInternalServer`, `ErrZoneSubdomainsNoNetworkZones`,
`ErrInvalidDNS64Prefix`, `ErrInvalidDNS64Server`, `ErrDNS64ServerNotConfigured`.

The last two are the ones that surprise people: zone subdomain expansion needs
both an internal server and declared network zones. Configure subdomain
expansion without either and it is refused at load rather than producing zones
that resolve to nothing.

## 5. Invariants

1. **The platform is authoritative for its zones; the Corefile is derived.**
   `NewCorefile` and `NewCorefileWithForwarders` generate configuration from
   platform state. Hand-editing a generated Corefile is overwritten.
2. **A zone must be signed before DNSSEC status reports it as signed.**
   `SignZone` and `GetDNSSECStatus` are separate operations for that reason.
3. **Record types are a closed set.** Anything outside the thirteen constructors
   is `ErrRecordTypeNotSupported`.
4. **A DNS64 prefix the daemon accepts is one a translator can reverse.**
   `DNS64Config.Validate` runs from `dns.Run` before anything is registered.
   It is stricter than the CoreDNS plugin's own parser on purpose: the plugin
   accepts every multiple of eight from /32 to /96, which admits /72, /80 and
   /88 — lengths RFC 6052 §2.2 never defined and no translator can undo. An
   address synthesised into one of those resolves to nothing and reads as a
   network fault, so it is refused at load instead.
5. **A listener selected for synthesis is a listener that exists.**
   `servers: [public]` with no public server configured is
   `ErrDNS64ServerNotConfigured`, not a section that quietly synthesises
   nowhere.

## 6a. DNS64

`pkg/dns/dns64.go`. Synthesis itself is the upstream CoreDNS `dns64` plugin
(`github.com/coredns/coredns/plugin/dns64`, linked for its side-effect
registration). This package owns the configuration contract, the plugin's
position in the chain, and RFC 7050 discovery.

**Plugin order.** `dnsserver.Directives` is `dns64, trustedPlatform, log,
chaos, forward`. `dns64` is ahead of `trustedPlatform`, not behind it: the
plugin works by letting the rest of the chain answer an AAAA question and
synthesising only when that answer carried no AAAA, so it has to wrap the
authoritative plugin. Behind it, it would have nothing to intercept for the
platform's own zones. Anything that is not an AAAA question in class IN
arriving over IPv6 passes straight through, so the ordering costs nothing
when synthesis is off — and when the section is absent the plugin is never
instantiated at all.

**Scope is per listener, not per zone.** `servers` selects `internal`,
`public`, or both, defaulting to internal. A CoreDNS server block is a zone
list and both of this daemon's blocks are `.`, so a per-zone stanza is not
expressible without splitting blocks — but the decision is not per-zone
anyway. DNS64 is a property of the resolver a client population is pointed
at: the same name must synthesise for an IPv6-only client and stay untouched
for a dual-stack one, and the listener is what separates them. Synthesising
on the public authoritative server would hand the Well-Known Prefix to
resolvers with no route to this translator, which is why it is off there by
default.

**RFC 7050 discovery is ours, not the plugin's.** The upstream plugin has no
`ipv4only.arpa` handling. `serveRFC7050` in `pkg/dns/dns64.go`, called from
`TrustedPlatformPlugin.ServeDNS` before the zone lookup, answers A with
192.0.0.170 and 192.0.0.171 and answers every other type — AAAA included —
with an authoritative NODATA. That absence is the mechanism: the client asks
for AAAA, `dns64` finds no AAAA, looks up A, and synthesises an address the
client reads the prefix out of. Both halves have to be local for the chain to
close, which is the other reason `dns64` is ordered ahead of
`trustedPlatform`.

**DNSSEC.** A synthesised AAAA cannot validate — there is no signature over a
record the resolver invented. RFC 6147 §5.5 describes a DNS64 that declines to
synthesise when the client sets DO and CD; **the upstream plugin implements
neither check**. It synthesises regardless of the DO bit. It does leave AD
clear (`Synthesize` builds its reply with `SetReply`), so it never claims
authentication it does not have, but a validating stub resolver behind it will
fail to validate the synthesised answer. Do not point a validating resolver at
a synthesising listener. This is upstream behaviour, recorded here rather than
worked around locally.

**Prefix agreement.** The prefix must match the NAT64 translator's. On a node
running both, that is the gateway's `nat64.prefix`; nothing enforces the
agreement across the two daemons yet, and a mismatch synthesises addresses
that route to no translator.
4. **Persistence goes through DAO/entity, not raw KV** (`dao/`, `entities/`),
   per the portfolio data-access convention.
5. **Zone creation is not idempotent.** A second create is `ErrZoneAlreadyExists`,
   not a no-op update.
6. **A record answers the name it owns, and no other.** `ownerMatchesQuery`
   (`owner.go`) compares the WHOLE query name against the record's owner,
   resolved from the relative or fully qualified stored form, case- and
   trailing-dot insensitively (RFC 4343 §3). There is no wildcard synthesis:
   a `*` owner matches the literal name `*.<zone>`. The SOA answers at the
   zone apex only; an RRSIG answers at, and transfers under, the owner it
   signs (`RRSIGRecord.Name`, set by `rrsigToEntity`). Restoring first-label matching re-opens #182, where a zone
   holding `www` answered `www.anything.example.com`.
7. **A query with no matching record gets the right KIND of negative answer.**
   `buildResponse` (`plugin.go`) sends NXDOMAIN when `zoneHasName` reports the
   name exists nowhere in the zone and NODATA when it exists without records of
   the queried type, including for empty non-terminals (RFC 1034 §4.3.2,
   RFC 2308 §2). Both carry the zone SOA in the authority section at the
   negative-caching TTL: the lesser of the SOA TTL and its MINIMUM.
8. **Owner-name resolution has one implementation.** `recordOwnerFQDN` serves
   the resolver, the AXFR responder (`transferHeader`) and the DNSSEC signer
   (`resolveName`, `collectOwnerNames`). Three copies of this rule previously
   drifted; a fourth must not appear.
9. **The SOA's effective TTL has one definition.** `soaTTL` (the record's own
   TTL, else the zone default) serves the resolver, the negative answer, the
   AXFR responder and the DNSSEC signer. Signing at a different TTL than the
   one served leaves the RRSIG's original TTL disagreeing with its RRset.
10. **An alias is chased, never denied.** `cnameChain` (`plugin.go`) answers a
    non-CNAME query at a CNAME owner with the alias and the target's records
    (RFC 1034 §4.3.2 step 3a), bounded at `maxCNAMEDepth` hops with a visited
    set. A negative answer there would have resolvers cache "no address" for a
    name that has one.
11. **A delegated subtree is referred, never denied.** `delegationFor`
   (`plugin.go`) finds the closest non-apex NS owner enclosing the query;
   `buildResponse` then answers a referral with the AA bit clear rather than
   NXDOMAIN, which would let resolvers cache a false non-existence for a zone
   this server does not hold (RFC 1034 §4.3.2 step 3b). The check precedes the
   answer: data the parent holds at or below a cut is glue, not an answer. A `DS` query AT the cut
   and `NSEC` AT the cut are the exception and stay authoritative
   (`parentSideTypesAtCut`; RFC 4035 §3.1.4.1) — they are parent-side data, and
   referring them would leave every insecure delegation unvalidatable and put
   an RRset the zone stores out of reach. `cnameChain` applies the same cut
   check to every target it follows. Referrals carry
   in-bailiwick glue from the parent's own A/AAAA records (`glueFor`). An NS
   RRset is a cut only when its owner is below the apex AND holds no other data
   in the zone (RFC 2181 §6.1) — the second condition is what keeps a zone
   seeded from a pre-2026-09-02 template answering its own hostname.
12. **The DNSSEC type bitmap says SOA at the apex only.** `getTypeBitMapForName`
   reads the apex, never `SOARecord.Name` — shipped templates set that field to
   a non-apex name, and a bitmap bit for an RRset the resolver never serves
   points a validator at a hole. `collectRRsets` likewise skips a zone with no
   SOA rather than signing a nil one.
13. **Two owner-name SETS, and they are not interchangeable.**
   `zoneOwnerNames` is every owner in the zone and answers "does this name
   exist" for negative answers — a DS-only or NSEC3-only owner is a name the
   zone defines. `zoneDataOwnerNames` excludes DNSSEC meta-records and is what
   the signer chains NSEC/NSEC3 over; feeding it the full set would chain the
   signer over its own output, growing the chain on every re-signing.

## 6. Persistence

`Datastore` wraps the stack's storage through `NewDatastore(storage
quicbaas.Storage, ...)`. Zones and records are entities with DAOs; DNSSEC keys
live in whichever key store backend is configured — which is exactly why §3.1
matters.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/dns/*_test.go` | Record construction, parser, config validation, Corefile generation |
| Integration | `test/integration/dns/` | Resolution, zone transfer, DNSSEC signing against a running service |

`pkg/dns/mocks/` and `NewMockKeyStore()` are the fixtures. `pkg/dns` is one of
the package trees `make test` excludes on the grounds that it is covered by
`make integration-test`.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. For DNS it is moot in
practice — there is no DNS CLI at all ([cli.md](cli.md)).

## 8. Observability

`OpDNSGetMetrics` (`0x2C`) exposes DNS metrics over QUIC; there is no REST or
gRPC equivalent. `OpDNSFlushCache` (`0x2D`) is likewise QUIC-only. Both are
operational verbs that an operator on REST cannot reach.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- Deep dives carried over and not re-verified in this pass:
  [dnssec.md](dnssec.md), [dnssec-rollover.md](dnssec-rollover.md),
  [dane.md](dane.md), [dot-doh.md](dot-doh.md),
  [dynamic-dns.md](dynamic-dns.md), [acme-integration.md](acme-integration.md),
  [operations.md](operations.md), [configuration.md](configuration.md)

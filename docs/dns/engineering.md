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
```

These generate a Corefile; they do not read one. The platform is the authority
for zone content, and the Corefile is derived.

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

**DNSSEC (`dnssec:`)**: `enabled`, `algorithm`, `auto-generate`, `key-reuse`,
`ksk`, `lifetime`, `max-age`, `nsec-mode`, `nsec3-iterations`, `nsec3-salt`.

**DANE (`dane:`)**: `default-usage`, `default-selector`,
`default-matching-type`, `publish-dane-ee`.

**Attestation (`attestation:`)**: `default-pcr-policy`, `pcr-policies`, `pcrs`,
`expected`, `index`. DNS records can carry attestation policy — see
`pkg/dns/attestation/`.

### Configuration errors

`ErrNoResolverServers`, `ErrInvalidResolverPort`, `ErrInvalidResolverAddress`,
`ErrZoneSubdomainsNoInternalServer`, `ErrZoneSubdomainsNoNetworkZones`.

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
4. **Persistence goes through DAO/entity, not raw KV** (`dao/`, `entities/`),
   per the portfolio data-access convention.
5. **Zone creation is not idempotent.** A second create is `ErrZoneAlreadyExists`,
   not a no-op update.

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

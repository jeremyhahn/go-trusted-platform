# DNS Architecture

> **Status: NORMATIVE** · Scope: `pkg/dns/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package boundaries, configuration keys, record types,
> transport matrix and the two known defects were checked against code on
> 2026-08-18. The diagrams and narrative below predate the feature-folder
> migration and were carried over rather than re-derived.

## The problem

A platform that issues its own certificates, runs its own network zones and
attests its own workloads cannot outsource name resolution for those things. The
names have to be authoritative somewhere the platform controls, they have to be
signed, and — for DANE and for ACME DNS-01 — the certificate story depends on
being able to publish records on demand.

## The shape chosen

Authoritative DNS **inside the platform**, with CoreDNS as the serving engine and
the platform as the source of truth. The Corefile is **generated**
(`NewCorefile`, `NewCorefileWithForwarders`) from platform state; nothing reads a
hand-maintained one.

DNSSEC signing keys live in a pluggable key store with three backends (xkms,
quicbaas KMS, SDK), so key custody follows the deployment rather than being
fixed in the DNS code.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Delegate to an external DNS provider** | ACME DNS-01 and DANE both need records published on demand, under platform control, at platform speed. An external provider puts a third party and an API rate limit in the path of certificate issuance. |
| **Hand-maintained zone files** | Zone content is derived from platform state — device registrations, network zones, service endpoints. A hand-maintained file drifts from the state it is supposed to describe, silently. |
| **Writing a DNS server from scratch** | CoreDNS already handles the protocol correctly. What the platform adds is authority over content and key custody, not wire-format parsing. |
| **A single fixed DNSSEC key store** | Key custody is a deployment decision — hardware KMS in one environment, software in another. The key store is an interface with three implementations for that reason. (One of them has a defect: [engineering.md](engineering.md) §3.1.) |
| **An open record-type set** | Records are constructed by type-specific constructors and parsed by type-specific cases. An open set means a type that can be written and not read. Thirteen types, closed, with `ErrRecordTypeNotSupported` for the rest. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Service façade, zones, records | `pkg/dns/service.go`, `dao/`, `entities/` | this repo |
| Resolver and forwarding | `pkg/dns/resolver.go` | this repo |
| DNSSEC signing and status | `pkg/dns/dnssec.go` | this repo |
| DNSSEC key stores | `pkg/dns/dnssec_keystore*.go` | this repo — **backed by the stack's KMS** |
| CoreDNS integration | `pkg/dns/corefile.go`, `plugin.go`, `parser.go` | this repo |
| Zone transfer | `pkg/dns/axfr.go` | this repo |
| Attestation-aware records | `pkg/dns/attestation/` | this repo |
| **Key management** | consumed through the quicbaas SDK / xkms adapter | **not this repo** |
| **Storage** | consumed through the quicbaas SDK | **not this repo** |
| **ACME issuance** | reached through the stack — [`docs/ca/`](../ca/) | **not this repo** |

The §R capability row is *"Authoritative DNS / DNSSEC"*, Tier 1, reached through
`services/dns`.

## Trust boundaries

1. **Registrant → DNS service.** Crossed by a zone registration request.
   **This boundary currently has no ownership check** — see
   [engineering.md](engineering.md) §3.2. That makes
   `allow-external-registration` a trust decision, not a convenience toggle.
2. **DNS service → key store → KMS.** DNSSEC private keys should never
   materialise in the DNS service. One backend does not honour that today
   ([engineering.md](engineering.md) §3.1).
3. **Resolver → forwarders.** Forwarded queries leave the platform. Forwarder
   choice is a privacy and integrity decision.
4. **Zone transfer (AXFR).** A zone transfer discloses the full zone. Who may
   perform one is configuration.

## What this feature deliberately does not do

- **It does not manage keys.** Key material comes from the stack.
- **It does not issue certificates.** It publishes the records ACME and DANE
  need; issuance is [`docs/ca/`](../ca/).
- **It does not serve a recursive resolver to arbitrary clients.** It is
  authoritative for platform zones with forwarders for the rest.
- **It does not translate packets.** DNS64 synthesises the AAAA answers that
  send an IPv6-only client at a NAT64 translator; the translator itself is the
  gateway's, and this half is useless without it.
- **It has no CLI.** That is a gap ([cli.md](cli.md)), and a document in this
  folder describing one is fenced as never-implemented.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Trusted Platform                              │
│                    (Single Binary, Modular Features)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                       DNS Module (pkg/dns/)                       │  │
│  │                        [Enabled via config]                       │  │
│  │                                                                   │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │  │
│  │  │    DNS      │  │  Trusted    │  │    Zone     │  │   Query   │ │  │
│  │  │   Service   │  │  Platform   │  │     DAO     │  │   Parser  │ │  │
│  │  │             │  │   Plugin    │  │             │  │           │ │  │
│  │  │ - Register  │  │ - ServeDNS  │  │ - kvstore   │  │ - Validate│ │  │
│  │  │ - Zones     │  │ - Security  │  │ - objstore  │  │ - Parse RR│ │  │
│  │  │ - Resolver  │  │ - Logging   │  │ - CRUD      │  │ - RFC 1035│ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    CoreDNS Integration                      │  │  │
│  │  │                                                             │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │  │  │
│  │  │  │ Corefile │─▶│ Plugin   │─▶│ Forward  │─▶│   Query     │  │  │  │
│  │  │  │ (Dynamic)│  │ Chain    │  │ (Ext)    │  │ Resolution  │  │  │  │
│  │  │  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    │ uses                               │
│                                    ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Dual-Server Architecture                      │  │
│  │                                                                   │  │
│  │  ┌──────────────────────────┐   ┌──────────────────────────┐      │  │
│  │  │    Internal Server       │   │    Public Server         │      │  │
│  │  │    (Port 9053)           │   │    (Port 8053)           │      │  │
│  │  │                          │   │                          │      │  │
│  │  │ - Private zones          │   │ - Public zones           │      │  │
│  │  │ - Private TLDs           │   │ - IANA TLDs              │      │  │
│  │  │ - Internal forwarders    │   │ - External forwarders    │      │  │
│  │  │ - LAN resolution         │   │ - Internet resolution    │      │  │
│  │  └──────────────────────────┘   └──────────────────────────┘      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    │ stores                             │
│                                    ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     Datastore (dns/zones)                         │  │
│  │                                                                   │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │  │
│  │  │   kvstore   │  │  objstore   │  │    JSON     │  │  Memory   │ │  │
│  │  │   (LOCAL)   │  │  (Objects)  │  │  Serializer │  │  Backend  │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### DNS Service

The DNS Service (`pkg/dns/service.go`) provides the core zone and record management operations:

- Zone CRUD operations (Save, Delete, Zone)
- Host and device registration
- Internal/external zone separation
- Custom net.Resolver for platform DNS lookups
- Domain name parsing and validation

### TrustedPlatformPlugin

The TrustedPlatformPlugin (`pkg/dns/plugin.go`) integrates with CoreDNS as a custom plugin:

- Implements `plugin.Handler` interface
- Handles incoming DNS queries via `ServeDNS`
- Zone lookup by query name
- Security enforcement for internal/public zone separation
- RFC 1035 compliant query validation
- Security logging for policy violations

### Zone DAO

Zone Data Access Object provides persistence abstraction:

| Backend | Package | Storage Type |
|---------|---------|--------------|
| kvstore | `pkg/dns/dao/kvstore` | Key-value storage |
| objstore | `pkg/dns/dao/objstore` | Object storage |

Both backends support:
- Generic CRUD operations via `datastore.GenericDAO`
- Zone lookup by name via `GetByName`
- Pagination support

### Parser

The Parser (`pkg/dns/parser.go`) handles DNS record parsing and validation:

- Record type parsing (A, AAAA, MX, CNAME, NS, SOA, TXT, SRV)
- Owner-name matching against the query name (`pkg/dns/owner.go`): a record
  answers only the name it owns, resolved from either the relative (`www`, `@`)
  or fully qualified (`www.example.com.`) stored form. There is no wildcard
  synthesis, and the SOA answers at the zone apex only. An RRSIG answers at
  the owner of the RRset it signs.
- Query validation per RFC 1035
- Domain name parsing via publicsuffix
- Hostname, subdomain, and TLD extraction

Negative answers are built by `buildResponse` (`pkg/dns/plugin.go`), which
separates NXDOMAIN from NODATA per RFC 2308 §2 and cites the zone SOA in the
authority section. See [resolution.md](resolution.md) for the rules.

### Configuration

Configuration (`pkg/dns/config.go`) defines the DNS module settings:

- Dual-server configuration (internal/public)
- Zone definitions embedded in config
- Forwarder lists for upstream DNS
- Registration policy settings
- IP address configuration (IPv4/IPv6)

## Data Model

### Zone Entity

```go
type Zone struct {
    ID          uint64    // Unique zone identifier
    Name        string    // Zone name (e.g., "example.com.")
    TenantID    string    // Tenant that owns this zone (multi-tenant isolation)
    TTL         uint32    // Default TTL for records
    RecordSet   RecordSet // All DNS records
    Description string    // Zone description
    Internal    bool      // Internal vs public zone flag
}

// IsOwnedBy checks if the zone belongs to the specified tenant
func (z *Zone) IsOwnedBy(tenantID string) bool {
    return z.TenantID == tenantID
}
```

### Multi-Tenant Zone Isolation

The DNS service implements tenant-based zone isolation to support multi-tenant deployments:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-Tenant DNS Architecture                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                   DNS Service Layer                     │   │
│   │                                                         │   │
│   │   TenantID: "platform"                                  │   │
│   │   ┌──────────────────────────────────────────────────┐  │   │
│   │   │  authorizeZoneAccess(zone, action)               │  │   │
│   │   │  • Verify caller TenantID matches zone TenantID  │  │   │
│   │   │  • Log unauthorized access attempts              │  │   │
│   │   │  • Return ErrUnauthorizedZoneAccess if denied    │  │   │
│   │   └──────────────────────────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│              ┌───────────────┼───────────────┐                   │
│              ▼               ▼               ▼                   │
│   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│   │ Zone: example.  │ │ Zone: internal. │ │ Zone: tenant-b. │   │
│   │ TenantID:       │ │ TenantID:       │ │ TenantID:       │   │
│   │ "platform"      │ │ "platform"      │ │ "tenant-b"      │   │
│   │                 │ │                 │ │                 │   │
│   │ ✓ Accessible    │ │ ✓ Accessible    │ │ ✗ Denied        │   │
│   └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key Features:**

| Feature | Description |
|---------|-------------|
| Automatic TenantID Assignment | New zones inherit TenantID from the DNS service |
| Ownership Verification | All zone operations check tenant ownership |
| DNSSEC Key Isolation | Keys stored in tenant-scoped paths: `dnssec/{tenant}/{zone}/{key}` |
| Audit Logging | Unauthorized access attempts logged with full context |

### RecordSet

```go
type RecordSet struct {
    ARecords      []*ARecord      // IPv4 address records
    AAAARecords   []*AAAARecord   // IPv6 address records
    CNAMERecords  []*CNAMERecord  // Canonical name records
    DNSKEYRecords []*DNSKEYRecord // DNSSEC public keys
    DSRecords     []*DSRecord     // Delegation signer records
    MXRecords     []*MXRecord     // Mail exchange records
    NSRecords     []*NSRecord     // Name server records
    RRSIGRecords  []*RRSIGRecord  // Resource record signatures
    SOARecord     SOARecord       // Start of authority
    SRVRecords    []*SRVRecord    // Service records
    TXTRecords    []*TXTRecord    // Text records
}
```

### DNSSEC Records

| Record Type | Purpose |
|-------------|---------|
| DNSKEY | Zone signing public key |
| DS | Delegation signer for chain of trust |
| RRSIG | Signature over resource record sets |

### Datastore Partition

All DNS zone data is stored under the partition:
```
dns/zones
```

Zone IDs are generated using `util.NewID([]byte(zoneName))` for consistent, deterministic identification.

## CoreDNS Integration

### Dynamic Corefile Generation

The platform dynamically generates CoreDNS Corefiles at runtime:

```go
// Basic Corefile
.:{port} {
    trustedPlatform
    log
    chaos
}

// With forwarders
.:{port} {
    trustedPlatform
    log
    chaos
    forward . {forwarder1} {forwarder2}
}

// With DNS64 synthesis on this listener
.:{port} {
    trustedPlatform
    log
    chaos
    dns64 {
        prefix 64:ff9b::/96
    }
    forward . {forwarder1} {forwarder2}
}
```

An empty forwarder list renders no `forward` directive rather than a `forward .`
with no upstream, which CoreDNS refuses at setup.

### Plugin Registration

The TrustedPlatformPlugin registers with CoreDNS during initialization:

```go
dnsserver.Directives = []string{
    "dns64",
    "trustedPlatform",
    "log",
    "chaos",
    "forward",
}
```

`dns64` is ordered **ahead of** `trustedPlatform`. The plugin lets the rest of
the chain answer an AAAA question and synthesises only when that answer carried
no AAAA, so it must wrap the authoritative plugin rather than sit behind it.
Behind it there would be nothing to intercept for the platform's own zones, and
RFC 7050 prefix discovery would not work at all — the `ipv4only.arpa` answer the
plugin synthesises from is served by `trustedPlatform`. Questions that are not
AAAA in class IN over IPv6 pass straight through, and with no `dns64:` section
the plugin is never instantiated. See
[engineering.md §6a](engineering.md) for the full contract, including the
DNSSEC caveat: the upstream plugin synthesises regardless of the DO bit, so a
validating resolver must not be pointed at a synthesising listener.

### Query Handling Flow

```
Client                  CoreDNS                TrustedPlatformPlugin        ZoneDAO
   |                       |                          |                        |
   | 1. DNS Query          |                          |                        |
   |---------------------->|                          |                        |
   |                       |                          |                        |
   |                       | 2. Route to plugin       |                        |
   |                       |------------------------->|                        |
   |                       |                          |                        |
   |                       |                          | 3. Validate query      |
   |                       |                          | (RFC 1035)             |
   |                       |                          |                        |
   |                       |                          | 4. Get zone            |
   |                       |                          |----------------------->|
   |                       |                          |                        |
   |                       |                          | 5. Zone data           |
   |                       |                          |<-----------------------|
   |                       |                          |                        |
   |                       |                          | 6. Security check      |
   |                       |                          | (internal/public)      |
   |                       |                          |                        |
   |                       |                          | 7. Parse records       |
   |                       |                          |                        |
   |                       | 8. DNS Response          |                        |
   |<----------------------|<-------------------------|                        |
```

## DNSSEC Architecture (Planned)

### DNSSECService

Future DNSSEC implementation will provide:

- Zone signing with KSK and ZSK
- NSEC/NSEC3 authenticated denial of existence
- Key rollover support
- Signature expiration management

### ZoneSigner

```
┌───────────────────────────────────────────────────────────────────────┐
│                         DNSSEC Zone Signing                           │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   Step 1: Key Generation                                              │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  KMS Service ─▶ KeyGenerator ─▶ DNSKEY Records                  │ │
│   │  • KSK (Key Signing Key): flags=257, algorithm=13 (ECDSAP256)   │ │
│   │  • ZSK (Zone Signing Key): flags=256, algorithm=13              │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│   Step 2: Record Signing                                              │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  For each RRset:                                                │ │
│   │  • Canonical ordering                                           │ │
│   │  • RRSIG generation using ZSK                                   │ │
│   │  • Signature validity period                                    │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│   Step 3: Chain Generation                                            │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  NSEC/NSEC3:                                                    │ │
│   │  • Sorted zone records                                          │ │
│   │  • Next secure record chain                                     │ │
│   │  • Type bitmaps                                                 │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│   Step 4: DS Record                                                   │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  DS = Digest(DNSKEY)                                            │ │
│   │  • Submitted to parent zone                                     │ │
│   │  • Establishes chain of trust                                   │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### KeyGenerator with go-quicbaas

DNSSEC keys will be managed through the platform's KMS:

- TPM-backed key storage
- Hardware security module support
- Key lifecycle management
- Automated rotation policies

## Key Management Integration

### go-quicbaas KMSService

The DNS module integrates with the platform's key management:

| Feature | Description |
|---------|-------------|
| Multi-backend | TPM, HSM, Software |
| TPM Protection | Hardware-bound keys |
| Key Hierarchy | KSK/ZSK separation |
| Rotation | Automated key rollover |

### TPM Key Protection

For high-security deployments:

- DNSSEC keys sealed to TPM
- Platform attestation binding
- Non-exportable key storage
- Hardware random generation

## Security Architecture

### Query Validation

All DNS queries undergo RFC 1035 validation:

- Maximum domain length (253 characters)
- Label length validation (1-63 characters)
- Character set validation (alphanumeric, hyphen)
- IP address rejection (forward lookups only)
- Injection prevention

### Internal vs Public Zone Separation

```
┌───────────────────────────────────────────────────────────────────────┐
│                       Zone Separation Security                        │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   Public Server (Port 8053)                                           │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  • Serves only public zones (Internal=false)                    │ │
│   │  • Rejects queries for internal zones                           │ │
│   │  • Logs security violations                                     │ │
│   │  • No error response revealing internal structure               │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│   Internal Server (Port 9053)                                         │
│   ┌─────────────────────────────────────────────────────────────────┐ │
│   │  • Serves both internal and public zones                        │ │
│   │  • Internal network access only                                 │ │
│   │  • Full resolution capabilities                                 │ │
│   │  • Forwards unknown queries to configured forwarders            │ │
│   └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Security Logging

Violations are logged with structured security entries:

```go
SecurityLogEntry{
    Category:        CategoryNetworkSecurity,
    Description:     "Ignoring public query for internal zone",
    Details:         qname,
    OffenderAddress: remoteAddr,
    Source:          SourceDNS,
    Severity:        SeverityHigh,
    Timestamp:       time.Now(),
}
```

### ABAC Integration

Future authorization integration:

- Policy-based zone access control
- Tenant-scoped DNS zones
- Fine-grained record permissions
- Audit logging for all operations

## Configuration Reference

### Registration Policies

| Setting | Description |
|---------|-------------|
| `AllowRegistration` | Enable/disable device registration |
| `AllowExternalRegistration` | Allow external domain registration |
| `AllowInternalRegistration` | Allow internal domain registration |

### Server Configuration

```yaml
dns:
  internal:
    port: 9053
    forwarders:
      - 203.0.113.1
    zone:
      name: "example.internal."
      internal: true
  public:
    port: 8053
    forwarders:
      - 8.8.8.8
      - 4.4.4.4
    zone:
      name: "example.com."
      internal: false
```

### Macro Expansion

Configuration supports macro variables:

| Macro | Description |
|-------|-------------|
| `${PUBLIC_IPv4}` | Public IPv4 address |
| `${PUBLIC_IPv6}` | Public IPv6 address |
| `${PRIVATE_IPv4}` | Private IPv4 address |
| `${PRIVATE_IPv6}` | Private IPv6 address |
| `${HOSTNAME}` | Local hostname |
| `${PUBLIC_DOMAIN}` | Public zone name |
| `${PRIVATE_DOMAIN}` | Private zone name |
| `${PUBLIC_FQDN}` | Full public FQDN |
| `${PRIVATE_FQDN}` | Full private FQDN |

## TLD Validation

The DNS module validates TLDs against the IANA registry:

- Fetches official TLD list from data.iana.org
- Caches TLDs in memory for fast lookup
- Distinguishes public TLDs from private extensions
- Prevents registration of reserved domains

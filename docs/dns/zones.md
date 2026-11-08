# DNS Zone Management

> **Status: REFERENCE** · Last verified: 2026-10-15
> The zone model and zone management.

## Overview

The Trusted Platform DNS service provides authoritative DNS for internal and public zones. Zones define the namespace boundaries and contain all DNS records for a domain. The platform supports running separate internal and public DNS servers, each with their own zone configuration, forwarders, and security policies.

## Zone Types

### Internal Zones

Internal zones use private TLDs that are not registered with IANA. These zones are only resolvable within your private network.

An internal zone's TLD must not appear in the IANA root list (`IsTLD`,
`pkg/dns/tld.go`). `.home.arpa` does not qualify: its TLD, `arpa`, is in that list.

| TLD | Use Case |
|-----|----------|
| `.internal` | Recommended private TLD (ICANN reserved, 2024) |
| `.local` | mDNS/Bonjour (may conflict with multicast DNS) |
| `.lan` | Common private network TLD |
| `.corp` | Corporate internal networks |

**Security characteristics:**
- Only accepts registrations from private IP addresses
- Isolated from public DNS queries
- No external delegation

### Public Zones

Public zones use IANA-registered TLDs and are resolvable from the public internet.

| Validation | Requirement |
|------------|-------------|
| TLD | Must be a valid IANA TLD |
| IP Address | Must be a public (non-private) IP |
| Ownership | Domain must be delegated to your nameservers |

**Security characteristics:**
- Validates TLD against IANA registry
- Rejects private IP addresses
- Supports DNSSEC signing

### Zone Isolation

| Property | Internal Zone | Public Zone |
|----------|---------------|-------------|
| Server Port | Configurable (default 9053) | Configurable (default 8053) |
| Forwarders | Private DNS servers | Public DNS (8.8.8.8, 4.4.4.4) |
| IP Validation | Private subnets only | Public IPs only |
| TLD Validation | Non-IANA TLDs | IANA TLDs |
| Query Scope | Internal network | Public internet |

## Zone Structure

### Zone Entity Fields

```go
type Zone struct {
    ID          uint64    // Unique zone identifier (hash of zone name)
    Name        string    // Zone name with trailing dot (e.g., "example.internal.")
    TenantID    string    // Tenant that owns this zone (multi-tenant isolation)
    TTL         uint32    // Default TTL for records in seconds
    KSK         *common.KeyConfig // Per-zone key-signing key override (optional)
    ZSK         *common.KeyConfig // Per-zone zone-signing key override (optional)
    RecordSet   RecordSet // All DNS records in the zone
    Description string    // Human-readable zone description
    Internal    bool      // True for internal zones, false for public
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier generated from zone name hash | Auto |
| `name` | FQDN with trailing dot | Yes |
| `tenant_id` | Tenant identifier for multi-tenant isolation | Yes |
| `ttl` | Default TTL in seconds | Yes |
| `ksk`, `zsk` | Per-zone DNSSEC key overrides; absent means the `dnssec:` defaults (`pkg/dns/entities/zone.go:30`) | No |
| `records` | SOA, NS, A, AAAA, CAA, CNAME, MX, TXT, SRV, TLSA, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM | Yes |
| `description` | Zone description | No |
| `internal` | Internal zone flag | Yes |

### Zone Ownership

Each zone is owned by a specific tenant. The `TenantID` field provides multi-tenant isolation:

```go
// IsOwnedBy checks if the zone belongs to the specified tenant
func (z *Zone) IsOwnedBy(tenantID string) bool {
    return z.TenantID == tenantID
}
```

- Zones are assigned the DNS service's own TenantID on creation (the tenant the
  daemon configured it with; the caller's tenant is not consulted)
- Zone reads and modifications refuse a zone another tenant owns
  (`pkg/dns/service.go:174`)
- DNSSEC key IDs are tenant-scoped: `dnssec_{tenantID}_{zoneName}_{keyType}`

### SOA Record Requirements

Every zone must have exactly one SOA (Start of Authority) record.

```yaml
soa:
  name: "example.internal."
  mname: "ns1.example.internal."      # Primary nameserver
  rname: "hostmaster.example.internal." # Admin email (@ replaced with .)
  serial: 1                            # Zone serial number
  refresh: 86400                       # Seconds before refresh
  retry: 7200                          # Seconds before retry
  expire: 86400                        # Seconds before expiration
  min_ttl: 3600                        # Minimum TTL for negative caching
  ttl: 3600                            # SOA record TTL
```

The config loader reads `min_ttl`, the field's `mapstructure` tag
(`pkg/dns/entities/records.go:115`); a `min-ttl:` key is silently ignored.

### NS Record Configuration

NS records delegate authority for the zone:

```yaml
ns:
  - name: "example.internal."
    value: "ns1.example.internal."
    ttl: 3600
  - name: "example.internal."
    value: "ns2.example.internal."
    ttl: 3600
```

## Zone Operations

### Creating Zones Programmatically

```go
import (
    "context"
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
    "github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// Create zone entity
zone := &entities.Zone{
    ID:          util.NewID([]byte("myzone.internal.")),
    Name:        "myzone.internal.",
    TTL:         3600,
    Internal:    true,
    Description: "My internal zone",
    RecordSet: entities.RecordSet{
        SOARecord: entities.SOARecord{
            Name:       "myzone.internal.",
            MName:      "ns1.myzone.internal.",
            RName:      "hostmaster.myzone.internal.",
            Serial:     1,
            Refresh:    86400,
            Retry:      7200,
            Expire:     86400,
            MinimumTTL: 3600,
            TTL:        3600,
        },
        NSRecords: []*entities.NSRecord{
            {Name: "myzone.internal.", Value: "ns1.myzone.internal.", TTL: 3600},
        },
        ARecords: []*entities.ARecord{
            {Name: "ns1", Value: "192.0.2.10", TTL: 3600},
        },
    },
}

// Save via service
err := dnsService.Save(ctx, zone)
```

### Loading Default Zones from Config

Zones are automatically loaded from the platform configuration at startup:

```yaml
dns:
  internal:
    zone:
      # Zone configuration loaded at startup
  public:
    zone:
      # Zone configuration loaded at startup
```

### Zone Registration Flow

The `Register` function handles zone and record creation:

1. **Validate registration is allowed** - `allow-registration` must be true
2. **Validate the IP** - `ErrInvalidIPAddress` if it does not parse
3. **Parse FQDN** - Extract hostname, subdomains, root domain, TLD
4. **Configured zones first** - an FQDN under the `internal` zone needs a private
   IP and a non-IANA TLD; one under the `public` zone needs a public IP and an
   IANA TLD. A match registers the record in that zone.
5. **Otherwise a new zone** - `allow-external-registration` (IANA TLD) or
   `allow-internal-registration` (other TLD) must be true, and the root domain
   must not already be a zone (`ErrZoneAlreadyExists`)
6. **Persist** - the zone is saved to the datastore

```go
// Register creates zone or adds record based on FQDN
zone, err := dnsService.Register(ctx, "myhost.example.internal", "192.0.2.100")
```

### Zone Persistence

Zones are persisted to the configured datastore:

| Storage | Key Format |
|---------|------------|
| Partition | `dns/zones` |
| Key | Zone ID (hash of zone name) |
| Serialization | JSON or configured serializer |

## Configuration Examples

### Internal Zone YAML

```yaml
dns:
  allow-registration: true
  allow-internal-registration: true

  internal:
    port: 9053
    forwarders:
      - "192.0.2.1"
      - "198.51.100.1"
    zone:
      id: 2
      name: "example.internal."
      ttl: 3600
      description: "Internal zone for example.internal"
      internal: true
      records:
        soa:
          name: "example.internal."
          mname: "ns1.example.internal."
          rname: "hostmaster.example.internal."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min_ttl: 3600
          ttl: 3600
        ns:
          - name: "example.internal."
            value: "ns1.example.internal."
            ttl: 3600
          - name: "example.internal."
            value: "ns2.example.internal."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${PRIVATE_IPv4}"
            ttl: 3600
          - name: "ns2"
            value: "198.51.100.1"
            ttl: 3600
          - name: "${HOSTNAME}"
            value: "${PRIVATE_IPv4}"
            ttl: 3600
        cname:
          - name: "www"
            value: "example.internal."
            ttl: 3600
```

### Public Zone YAML

```yaml
dns:
  allow-registration: true
  allow-external-registration: true

  public:
    port: 8053
    forwarders:
      - "4.4.4.4"
      - "8.8.8.8"
    zone:
      id: 1
      name: "example.com."
      ttl: 3600
      description: "Public zone for example.com"
      internal: false
      records:
        soa:
          name: "example.com."
          mname: "ns1.example.com."
          rname: "hostmaster.example.com."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min_ttl: 3600
          ttl: 3600
        ns:
          - name: "example.com."
            value: "ns1.example.com."
            ttl: 3600
          - name: "example.com."
            value: "ns2.example.com."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${PUBLIC_IPv4}"
            ttl: 3600
          - name: "ns2"
            value: "${PUBLIC_IPv4}"
            ttl: 3600
          - name: "www"
            value: "${PUBLIC_IPv4}"
            ttl: 3600
        cname:
          - name: "www"
            value: "example.com."
            ttl: 3600
        mx:
          - name: "example.com."
            value: "mail.example.com."
            priority: 10
            ttl: 3600
        txt:
          - name: "example.com."
            value: "v=spf1 include:_spf.google.com ~all"
            ttl: 3600
```

### Macro Expansion

Configuration values support macro expansion (`pkg/dns/macros.go`):

| Macro | Description | Example |
|-------|-------------|---------|
| `${PUBLIC_IPv4}`, `${PUBLIC_IPv6}` | Public address | `203.0.113.10` |
| `${PRIVATE_IPv4}`, `${PRIVATE_IPv6}` | Private address | `192.0.2.10` |
| `${HOSTNAME}` | System hostname | `server01` |
| `${PUBLIC_DOMAIN}`, `${PRIVATE_DOMAIN}`, `${PUBLIC_FQDN}`, `${PRIVATE_FQDN}` | Domain names | `example.com` |

The domain and FQDN macros are set only when that server (`dns.public`,
`dns.internal`) is configured. If the local hostname cannot be read, DNS
startup fails with `ErrHostnameLookup`.

```yaml
a:
  - name: "ns1"
    value: "${PUBLIC_IPv4}"  # Expanded at runtime
    ttl: 3600
  - name: "${HOSTNAME}"      # Creates record for this host
    value: "${PRIVATE_IPv4}"
    ttl: 3600
```

## Zone Operations Without a CLI

`platformctl dns zone` and `platformctl dns record` ([cli.md](cli.md)) manage
zones and records. The same CRUD is available through REST `/api/v1/dns/zones` or gRPC `DNSService`; host registration
is `POST /api/v1/dns/register`. [api-reference-rest.md](api-reference-rest.md)
has the request bodies.

## Error Handling

| Error | Description |
|-------|-------------|
| `ErrZoneAlreadyExists` | Zone with this name already exists |
| `ErrZoneNotFound` | Requested zone does not exist |
| `ErrParsingDomainName` | Failed to parse FQDN |
| `ErrInvalidIPAddress` | IP address format is invalid |
| `ErrInvalidPrivateIP` | Private IP required for internal zone |
| `ErrInvalidPublicIP` | Public IP required for public zone |
| `ErrInvalidPrivateTLD` | Cannot use IANA TLD for internal zone |
| `ErrInvalidPublicTLD` | Must use IANA TLD for public zone |
| `ErrRegistrationDisabled` | Zone registration is disabled |
| `ErrExternalRegistrationDisabled` | External zone registration disabled |
| `ErrInternalRegistrationDisabled` | Internal zone registration disabled |

## See Also

- [DNS Records](records.md) - Record type reference
- [Platform Configuration](configuration.md) - Full configuration reference
- [KMS Documentation](../kms/architecture.md) - Key management integration

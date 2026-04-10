# DNS Zone Management

## Overview

The Trusted Platform DNS service provides authoritative DNS for internal and public zones. Zones define the namespace boundaries and contain all DNS records for a domain. The platform supports running separate internal and public DNS servers, each with their own zone configuration, forwarders, and security policies.

## Zone Types

### Internal Zones

Internal zones use private TLDs that are not registered with IANA. These zones are only resolvable within your private network.

| TLD | Use Case |
|-----|----------|
| `.internal` | RFC 8375 recommended private TLD |
| `.local` | mDNS/Bonjour (may conflict with multicast DNS) |
| `.home.arpa` | RFC 8375 home network reserved |
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
    RecordSet   RecordSet // All DNS records in the zone
    Description string    // Human-readable zone description
    Internal    bool      // True for internal zones, false for public
}
```

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier generated from zone name hash | Auto |
| `name` | FQDN with trailing dot | Yes |
| `tenant_id` | Tenant identifier for multi-tenant isolation | Yes |
| `ttl` | Default TTL in seconds | Yes |
| `records` | SOA, NS, A, AAAA, CNAME, MX, TXT, SRV, DNSKEY, DS, RRSIG | Yes |
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

- Zones are automatically assigned the caller's TenantID on creation
- Authorization checks verify tenant ownership before zone modifications
- DNSSEC keys are stored in tenant-scoped KMS paths

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
  min-ttl: 3600                        # Minimum TTL for negative caching
  ttl: 3600                            # SOA record TTL
```

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
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// Create zone entity
zone := &entities.Zone{
    ID:          dns.NewID([]byte("myzone.internal.")),
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
            {Name: "ns1", Value: "192.168.1.10", TTL: 3600},
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

1. **Validate registration is allowed** - Check `allow-registration` config
2. **Parse FQDN** - Extract hostname, subdomains, root domain, TLD
3. **Determine zone type** - Internal vs public based on IP and TLD
4. **Check zone existence** - Add record to existing zone or create new
5. **Validate IP/TLD pairing** - Private IPs for internal, public IPs for public
6. **Create zone or record** - Persist to datastore

```go
// Register creates zone or adds record based on FQDN
zone, err := dnsService.Register(ctx, "myhost.example.internal", "192.168.1.100")
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
      - "192.168.1.1"
      - "192.168.2.1"
    zone:
      id: 2
      name: "trusted-platform.internal."
      ttl: 3600
      description: "Internal zone for trusted-platform.internal"
      internal: true
      records:
        soa:
          name: "trusted-platform.internal."
          mname: "ns1.trusted-platform.internal."
          rname: "hostmaster.trusted-platform.internal."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min-ttl: 3600
          ttl: 3600
        ns:
          - name: "trusted-platform.internal."
            value: "ns1.trusted-platform.internal."
            ttl: 3600
          - name: "trusted-platform.internal."
            value: "ns2.trusted-platform.internal."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${LOCAL_IPv4}"
            ttl: 3600
          - name: "ns2"
            value: "192.168.2.1"
            ttl: 3600
          - name: "${HOSTNAME}"
            value: "${LOCAL_IPv4}"
            ttl: 3600
        cname:
          - name: "www"
            value: "trusted-platform.internal."
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
      name: "trusted-platform.io."
      ttl: 3600
      description: "Public zone for trusted-platform.io"
      internal: false
      records:
        soa:
          name: "trusted-platform.io."
          mname: "ns1.trusted-platform.io."
          rname: "hostmaster.trusted-platform.io."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min-ttl: 3600
          ttl: 3600
        ns:
          - name: "trusted-platform.io."
            value: "ns1.trusted-platform.io."
            ttl: 3600
          - name: "trusted-platform.io."
            value: "ns2.trusted-platform.io."
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
            value: "trusted-platform.io."
            ttl: 3600
        mx:
          - name: "trusted-platform.io."
            value: "mail.trusted-platform.io."
            priority: 10
            ttl: 3600
        txt:
          - name: "trusted-platform.io."
            value: "v=spf1 include:_spf.google.com ~all"
            ttl: 3600
```

### Macro Expansion

Configuration values support macro expansion for dynamic IP addresses:

| Macro | Description | Example |
|-------|-------------|---------|
| `${PUBLIC_IPv4}` | Public IPv4 address | `203.0.113.10` |
| `${LOCAL_IPv4}` | Private IPv4 address | `192.168.1.10` |
| `${HOSTNAME}` | System hostname | `server01` |

```yaml
a:
  - name: "ns1"
    value: "${PUBLIC_IPv4}"  # Expanded at runtime
    ttl: 3600
  - name: "${HOSTNAME}"      # Creates record for this host
    value: "${LOCAL_IPv4}"
    ttl: 3600
```

## CLI Commands

### Zone Management

**List zones:**
```bash
platformctl dns zone list
```

**Get zone details:**
```bash
platformctl dns zone get trusted-platform.internal
```

**Create zone:**
```bash
platformctl dns zone create \
  --name "myzone.internal." \
  --ttl 3600 \
  --internal \
  --description "My internal zone"
```

**Delete zone:**
```bash
platformctl dns zone delete trusted-platform.internal
```

### Zone Registration

**Register host in internal zone:**
```bash
platformctl dns register \
  --fqdn "myhost.trusted-platform.internal" \
  --ip "192.168.1.100"
```

**Register host in public zone:**
```bash
platformctl dns register \
  --fqdn "www.trusted-platform.io" \
  --ip "203.0.113.10"
```

### Configuration Options

| Flag | Description | Default |
|------|-------------|---------|
| `--name` | Zone FQDN with trailing dot | Required |
| `--ttl` | Default TTL in seconds | `3600` |
| `--internal` | Mark as internal zone | `false` |
| `--description` | Zone description | Empty |
| `--fqdn` | Full qualified domain name | Required |
| `--ip` | IP address for registration | Required |

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
- [Platform Configuration](../configuration.md) - Full configuration reference
- [KMS Documentation](../kms/README.md) - Key management integration

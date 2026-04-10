# DNS Configuration Reference

Complete configuration reference for the Trusted Platform DNS subsystem.

## Overview

The DNS subsystem is configured through the platform configuration file. This document covers all available configuration options, environment variable overrides, and configuration macros.

### Configuration File Location

The DNS configuration is part of the main platform configuration:

| Location | Description |
|----------|-------------|
| `config.yaml` | Primary configuration file |
| `config.local.yaml` | Local overrides (not committed to version control) |
| `/etc/trusted-platform/config.yaml` | System-wide configuration |
| `~/.trusted-platform/config.yaml` | User-specific configuration |

Configuration files are loaded in order with later files overriding earlier values.

### Configuration Hierarchy

```
Platform Config
    |
    +-- dns:                         # DNS subsystem root
         |
         +-- allow-registration      # Global registration control
         +-- allow-external-registration
         +-- allow-internal-registration
         +-- default-ttl
         +-- private-ipv4/ipv6
         +-- public-ipv4/ipv6
         |
         +-- quicbaas:               # Zone persistence (QuicBaaS)
         |    +-- storage-backend
         |    +-- data-dir
         |    +-- wal-dir
         |    +-- node-id
         |    +-- cache-size
         |    +-- log-level
         |    +-- consistency-level
         |
         +-- shard-id                # Service-specific shard ID
         +-- partition               # Partition name for disk isolation
         |
         +-- public:                 # Public DNS server
         |    +-- port
         |    +-- forwarders
         |    +-- zone:
         |         +-- name, ttl, records...
         |
         +-- internal:               # Internal DNS server
         |    +-- port
         |    +-- forwarders
         |    +-- zone:
         |         +-- name, ttl, records...
         |
         +-- dnssec:                 # DNSSEC configuration
         |    +-- enabled
         |    +-- algorithm
         |    +-- ksk, zsk
         |    +-- denial
         |    +-- signing
         |    +-- rollover
         |
         +-- ddns:                   # Dynamic DNS client
         |    +-- enabled
         |    +-- servers
         |    +-- tsig
         |
         +-- scheduler:              # Automated tasks
              +-- enabled
              +-- check-interval
              +-- jobs
```

## Root Configuration

```yaml
dns:
  # Enable dynamic record registration
  allow-registration: true

  # Allow registration in public zones (use with caution)
  allow-external-registration: false

  # Allow registration in internal zones
  allow-internal-registration: true

  # Default TTL for dynamically created records (seconds)
  default-ttl: 3600

  # Private/internal IP addresses for macro expansion
  private-ipv4: "192.168.1.100"
  private-ipv6: "fd00::1"

  # Public IP addresses for macro expansion
  public-ipv4: "203.0.113.50"
  public-ipv6: "2001:db8::1"

  # QuicBaaS storage configuration (inherited from platform)
  # Service-specific overrides
  shard-id: 2
  partition: dns

  # Public DNS server configuration
  public: {}

  # Internal DNS server configuration
  internal: {}

  # DNSSEC configuration
  dnssec: {}

  # Dynamic DNS client configuration
  ddns: {}

  # Scheduler configuration
  scheduler: {}
```

### Root Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allow-registration` | bool | `false` | Master switch for dynamic registration |
| `allow-external-registration` | bool | `false` | Allow registration in public zones |
| `allow-internal-registration` | bool | `true` | Allow registration in internal zones |
| `default-ttl` | int | `3600` | Default TTL for dynamic records (seconds) |
| `private-ipv4` | string | - | Private IPv4 address for `${PRIVATE_IPv4}` macro |
| `private-ipv6` | string | - | Private IPv6 address for `${PRIVATE_IPv6}` macro |
| `public-ipv4` | string | - | Public IPv4 address for `${PUBLIC_IPv4}` macro |
| `public-ipv6` | string | - | Public IPv6 address for `${PUBLIC_IPv6}` macro |

## QuicBaaS Configuration

The QuicBaaS configuration controls how zone data is persisted.

```yaml
quicbaas:
  # Storage backend: memory, file, pebble, raft
  storage-backend: pebble

  # Data directory for QuicBaaS files
  data-dir: /var/lib/trusted-platform/quicbaas

  # Write-ahead log directory
  wal-dir: /var/lib/trusted-platform/quicbaas/wal

  # Node ID (required for raft backend)
  node-id: 1

  # In-memory cache size in bytes (64MB default)
  cache-size: 67108864

  # Logging level: debug, info, warn, error
  log-level: warn

  # Consistency level: linearizable, strong, eventual
  consistency-level: linearizable

dns:
  # Shard ID for DNS zone data
  shard-id: 2

  # Partition for disk isolation
  partition: dns
```

### QuicBaaS Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage-backend` | string | `pebble` | Storage backend (memory, file, pebble, raft) |
| `data-dir` | string | `trusted-data/quicbaas` | Data file directory |
| `wal-dir` | string | `trusted-data/quicbaas/wal` | Write-ahead log directory |
| `node-id` | uint64 | `1` | Unique node identifier in cluster |
| `cache-size` | int64 | `67108864` (64MB) | In-memory cache size in bytes |
| `log-level` | string | `warn` | Logging verbosity: debug, info, warn, error |
| `consistency-level` | string | `linearizable` | Read consistency: linearizable, strong, eventual |
| `raft-address` | string | - | Raft cluster address (raft backend only) |

### DNS Service Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `shard-id` | uint64 | `0` | QuicBaaS shard ID for DNS zone data |
| `partition` | string | `dns` | Partition name for disk isolation |

## Public Server Configuration

The public DNS server handles queries for public zones.

```yaml
public:
  # UDP/TCP port for DNS queries
  port: 8053

  # Upstream forwarders for recursive queries
  forwarders:
    - "8.8.8.8"
    - "8.8.4.4"
    - "1.1.1.1"

  # Zone configuration
  zone:
    # Zone identifier (auto-generated if not specified)
    id: 1

    # Fully qualified zone name (must end with dot)
    name: "example.com."

    # Default TTL for records in this zone
    ttl: 3600

    # Human-readable description
    description: "Public zone for example.com"

    # Zone type (false for public zones)
    internal: false

    # DNS records
    records:
      soa:
        name: "example.com."
        mname: "ns1.example.com."
        rname: "hostmaster.example.com."
        serial: 1
        refresh: 86400
        retry: 7200
        expire: 86400
        minimum_ttl: 3600
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
        - name: "www"
          value: "${PUBLIC_IPv4}"
          ttl: 3600

      aaaa:
        - name: "ns1"
          value: "${PUBLIC_IPv6}"
          ttl: 3600

      cname:
        - name: "mail"
          value: "www.example.com."
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

      srv:
        - name: "_ldap._tcp.example.com."
          target: "ldap.example.com."
          port: 389
          priority: 10
          weight: 100
          ttl: 3600
```

### Server Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | int | `8053` | DNS server port (public) |
| `forwarders` | []string | - | Upstream DNS servers for recursion |
| `zone` | Zone | - | Zone configuration |

## Internal Server Configuration

The internal DNS server handles queries for internal zones with enhanced security.

```yaml
internal:
  # UDP/TCP port for DNS queries
  port: 9053

  # Upstream forwarders (typically internal DNS infrastructure)
  forwarders:
    - "192.168.1.1"
    - "192.168.1.2"

  # Zone configuration
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
        minimum_ttl: 3600
        ttl: 3600

      ns:
        - name: "example.internal."
          value: "ns1.example.internal."
          ttl: 3600

      a:
        - name: "ns1"
          value: "${PRIVATE_IPv4}"
          ttl: 3600
        - name: "${HOSTNAME}"
          value: "${PRIVATE_IPv4}"
          ttl: 3600
```

### Internal Server Security

| Feature | Description |
|---------|-------------|
| Zone Isolation | Internal zones are only accessible via the internal server |
| Query Filtering | Public server queries for internal zones are silently dropped |
| IP Validation | Registration requires private IP addresses for internal zones |
| Audit Logging | All access attempts are logged for security analysis |

## Zone Configuration

Zones contain DNS records organized into record sets.

```yaml
zone:
  # Unique zone identifier
  id: 1

  # Fully qualified domain name (must end with dot)
  name: "example.com."

  # Default TTL for records
  ttl: 3600

  # Zone description
  description: "Production zone"

  # Internal zone flag (true = internal, false = public)
  internal: false

  # Record sets
  records:
    soa: {}      # SOA record (required)
    ns: []       # NS records (required)
    a: []        # A records
    aaaa: []     # AAAA records
    cname: []    # CNAME records
    mx: []       # MX records
    txt: []      # TXT records
    srv: []      # SRV records
    key: []      # DNSKEY records (DNSSEC)
    ds: []       # DS records (DNSSEC)
    rrsig: []    # RRSIG records (DNSSEC)
```

### Record Type Reference

#### SOA Record

```yaml
soa:
  name: "example.com."           # Zone apex
  mname: "ns1.example.com."      # Primary nameserver
  rname: "hostmaster.example.com."  # Admin email (@ replaced with .)
  serial: 2024010101             # Zone serial number
  refresh: 86400                 # Secondary refresh interval (seconds)
  retry: 7200                    # Retry interval after failed refresh
  expire: 604800                 # Secondary expiration time
  minimum_ttl: 3600              # Minimum TTL for negative caching
  ttl: 3600                      # SOA record TTL
```

#### NS Record

```yaml
ns:
  - name: "example.com."         # Zone or delegation point
    value: "ns1.example.com."    # Nameserver hostname
    ttl: 3600
```

#### A Record

```yaml
a:
  - name: "www"                  # Host name (relative to zone)
    value: "192.0.2.1"           # IPv4 address
    ttl: 3600
  - name: "@"                    # Zone apex
    value: "${PUBLIC_IPv4}"      # Macro expansion
    ttl: 3600
```

#### AAAA Record

```yaml
aaaa:
  - name: "www"
    value: "2001:db8::1"         # IPv6 address
    ttl: 3600
```

#### CNAME Record

```yaml
cname:
  - name: "mail"                 # Alias name
    value: "www.example.com."    # Canonical name (FQDN)
    ttl: 3600
```

#### MX Record

```yaml
mx:
  - name: "example.com."         # Domain accepting mail
    value: "mail.example.com."   # Mail server hostname
    priority: 10                 # Lower = higher priority
    ttl: 3600
```

#### TXT Record

```yaml
txt:
  - name: "example.com."
    value: "v=spf1 include:_spf.google.com ~all"
    ttl: 3600
  - name: "_dmarc.example.com."
    value: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    ttl: 3600
```

#### SRV Record

```yaml
srv:
  - name: "_ldap._tcp.example.com."  # Service name
    target: "ldap.example.com."      # Target server
    port: 389                        # Service port
    priority: 10                     # Lower = higher priority
    weight: 100                      # Load balancing weight
    ttl: 3600
```

#### DNSKEY Record (DNSSEC)

```yaml
key:
  - id: 12345                    # Key tag
    name: "example.com."
    flags: 257                   # 256=ZSK, 257=KSK
    protocol: 3                  # Always 3 for DNSSEC
    algorithm: 13                # ECDSAP256SHA256
    key: "BASE64_PUBLIC_KEY"
    ttl: 86400
```

#### DS Record (DNSSEC)

```yaml
ds:
  - id: 12345
    name: "child.example.com."
    key-tag: 12345               # Key tag of child KSK
    algorithm: 13                # DNSSEC algorithm
    digest_type: 2               # SHA-256
    digest: "ABC123..."          # Base16 digest
    ttl: 86400
```

#### CAA Record

Certificate Authority Authorization records specify which CAs can issue certificates for a domain.

```yaml
caa:
  - name: "example.com."         # Domain name
    flags: 0                     # 0 = non-critical, 128 = critical
    tag: "issue"                 # Tag: issue, issuewild, iodef
    value: "letsencrypt.org"     # CA domain or mailto: URI
    ttl: 3600
  - name: "example.com."
    flags: 0
    tag: "issuewild"
    value: "letsencrypt.org"
    ttl: 3600
  - name: "example.com."
    flags: 0
    tag: "iodef"
    value: "mailto:security@example.com"
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Domain name (FQDN) |
| `flags` | int | 0 = non-critical, 128 = critical (must be understood) |
| `tag` | string | `issue` (single), `issuewild` (wildcard), `iodef` (violation reports) |
| `value` | string | CA domain or `mailto:` URI for iodef |
| `ttl` | int | Record TTL |

#### TLSA Record

TLSA records enable DANE (DNS-Based Authentication of Named Entities) for certificate pinning.

```yaml
tlsa:
  - name: "_443._tcp.www.example.com."  # _port._proto.hostname
    usage: 3                    # Certificate usage (0-3)
    selector: 1                 # Selector (0-1)
    matching-type: 1            # Matching type (0-2)
    data: "sha256-hash-here"    # Certificate/public key hash
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | `_port._proto.hostname.` format |
| `usage` | int | 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE |
| `selector` | int | 0=Full certificate, 1=SubjectPublicKeyInfo |
| `matching-type` | int | 0=Full, 1=SHA-256, 2=SHA-512 |
| `data` | string | Hex-encoded hash or certificate data |
| `ttl` | int | Record TTL |

For detailed DANE/TLSA configuration and usage, see [dane.md](dane.md).

## DNSSEC Configuration

The DNSSEC configuration uses the platform's standard KeyConfig pattern for algorithm specification, providing human-readable configuration that's consistent with the rest of the platform.

```yaml
dnssec:
  # Enable DNSSEC signing
  enabled: true

  # Default key configuration (used if KSK/ZSK don't specify their own)
  # Uses standard platform KeyConfig pattern for algorithm specification
  default-key:
    algorithm: ECDSA           # RSA, ECDSA, or Ed25519
    ecc:
      curve: P-256             # P-256 or P-384 for ECDSA
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2                # software, tpm2, pkcs11, aws-kms, azure-kv, gcp-kms, vault

  # Key Signing Key (KSK) configuration
  ksk:
    # Optional: Override default-key with different key config
    # key:
    #   algorithm: ECDSA
    #   ecc:
    #     curve: P-384
    #   signature-algorithm: ECDSA-SHA384
    #   hash: SHA-384
    #   store: tpm2

    # Key lifetime before rollover
    lifetime: "365d"

    # DNSKEY record TTL
    ttl: 86400

  # Zone Signing Key (ZSK) configuration
  zsk:
    # Optional: Override default-key with different key config
    # key:
    #   algorithm: ECDSA
    #   ecc:
    #     curve: P-256
    #   signature-algorithm: ECDSA-SHA256
    #   hash: SHA-256
    #   store: software

    lifetime: "30d"
    ttl: 3600

  # Signature expiry configuration
  signature-expiry: "30d"

  # Denial of existence configuration
  nsec-mode: "nsec3"           # nsec or nsec3
  nsec3-iterations: 1          # 0-1 recommended per RFC 9276
  nsec3-salt: ""               # Empty for random salt
```

### DNSSEC Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DNSSEC signing |
| `default-key` | KeyConfig | ECDSA P-256 | Default key configuration for all DNSSEC keys |
| `signature-expiry` | duration | `30d` | Signature validity period |
| `nsec-mode` | string | `nsec3` | Denial of existence mode: nsec or nsec3 |
| `nsec3-iterations` | int | `1` | NSEC3 hash iterations (0-1 recommended) |
| `nsec3-salt` | string | `""` | NSEC3 salt (empty = random) |

### Default Key Options (KeyConfig)

The `default-key` uses the platform's standard KeyConfig structure:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algorithm` | string | `ECDSA` | Key algorithm: RSA, ECDSA, or Ed25519 |
| `ecc.curve` | string | `P-256` | ECC curve: P-256, P-384 |
| `rsa.size` | int | `2048` | RSA key size (if algorithm is RSA) |
| `signature-algorithm` | string | `ECDSA-SHA256` | Signature algorithm |
| `hash` | string | `SHA-256` | Hash algorithm |
| `store` | string | `software` | Key storage backend |

### Algorithm Mapping

The KeyConfig is automatically mapped to DNSSEC algorithm IDs:

| KeyConfig | DNSSEC Algorithm | ID |
|-----------|------------------|-----|
| `algorithm: ECDSA`, `ecc.curve: P-256` | ECDSAP256SHA256 | 13 |
| `algorithm: ECDSA`, `ecc.curve: P-384` | ECDSAP384SHA384 | 14 |
| `algorithm: RSA`, `signature-algorithm: SHA256-RSA` | RSASHA256 | 8 |
| `algorithm: RSA`, `signature-algorithm: SHA512-RSA` | RSASHA512 | 10 |
| `algorithm: Ed25519` | ED25519 | 15 |

### KSK/ZSK Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `key` | KeyConfig | inherits default-key | Optional per-key override |
| `lifetime` | duration | `365d`/`30d` | Key validity period |
| `ttl` | int | `86400`/`3600` | DNSKEY record TTL |

### Key Storage Backends

| Backend | Description | Security Level |
|---------|-------------|----------------|
| `software` | File-based key storage | Low (development only) |
| `tpm2` | TPM 2.0 hardware-backed | High (recommended) |
| `pkcs11` | HSM via PKCS#11 | High |
| `aws-kms` | AWS Key Management Service | High |
| `azure-kv` | Azure Key Vault | High |
| `gcp-kms` | Google Cloud KMS | High |
| `vault` | HashiCorp Vault | High |

### Per-Key Override Example

You can override the default key configuration at the KSK or ZSK level:

```yaml
dnssec:
  enabled: true

  # Default: ECDSA P-256 for most keys
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2

  ksk:
    # Override: Use P-384 for stronger KSK
    key:
      algorithm: ECDSA
      ecc:
        curve: P-384
      signature-algorithm: ECDSA-SHA384
      hash: SHA-384
      store: tpm2
    lifetime: 365d
    ttl: 86400

  zsk:
    # Inherits default-key (ECDSA P-256)
    lifetime: 30d
    ttl: 3600
```

This pattern allows multi-tenant configurations where different zones can have different key configurations while sharing common defaults.

## DANE Configuration

DANE (DNS-Based Authentication of Named Entities) enables certificate pinning via TLSA records.

```yaml
dns:
  dane:
    # Enable DANE support
    enabled: true

    # Default TLSA record parameters
    default-usage: 3            # 3 = DANE-EE (end entity)
    default-selector: 1         # 1 = SubjectPublicKeyInfo
    default-matching-type: 1    # 1 = SHA-256

    # Auto-generate TLSA records for platform certificates
    auto-generate: true

    # Certificate sources for auto-generation
    certificate-sources:
      - type: "platform-ca"
        zones:
          - "example.com."
      - type: "file"
        path: "/etc/ssl/certs/server.pem"
        zones:
          - "secure.example.com."

    # TLSA record TTL
    ttl: 3600
```

### DANE Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DANE support |
| `default-usage` | int | `3` | Default certificate usage (DANE-EE) |
| `default-selector` | int | `1` | Default selector (SPKI) |
| `default-matching-type` | int | `1` | Default matching type (SHA-256) |
| `auto-generate` | bool | `false` | Auto-generate TLSA for platform certs |
| `ttl` | int | `3600` | TLSA record TTL |

### Certificate Usage Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | PKIX-TA | CA constraint with PKIX validation |
| 1 | PKIX-EE | Service certificate with PKIX validation |
| 2 | DANE-TA | Trust anchor without PKIX |
| 3 | DANE-EE | Service certificate without PKIX (recommended) |

For detailed DANE configuration and usage patterns, see [dane.md](dane.md).

## Attestation Configuration

TPM attestation can be required for dynamic DNS updates to ensure only trusted devices can modify records.

```yaml
dns:
  zones:
    - name: "secure.example.com."
      attestation:
        # Require TPM attestation for updates
        required: true

        # Maximum age for attestation evidence
        max-age: 5m

        # PCR policy for attestation validation
        pcr-policy: "standard-boot"

        # Allowed signing algorithms
        algorithms:
          - "RSA-2048"
          - "ECC-P256"
```

### Attestation Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `required` | bool | `false` | Require attestation for updates |
| `max-age` | duration | `5m` | Maximum attestation evidence age |
| `pcr-policy` | string | `standard-boot` | PCR validation policy name |
| `algorithms` | []string | all | Allowed attestation key algorithms |

### PCR Policy Names

| Policy | PCRs | Description |
|--------|------|-------------|
| `standard-boot` | 0,1,2,3,7 | Firmware and boot loader measurements |
| `secure-boot` | 0,1,2,3,7,8,9 | Secure boot with kernel measurements |
| `full` | 0-15 | All standard PCRs |
| `custom` | configurable | Custom PCR selection |

For detailed attestation configuration, see [dynamic-dns.md](dynamic-dns.md).

## DoT/DoH Configuration (Planned)

DNS over TLS (DoT) and DNS over HTTPS (DoH) provide encrypted DNS transport.

```yaml
dns:
  # DNS over TLS (port 853)
  dot:
    enabled: false              # Planned feature
    port: 853
    certificate: "/etc/ssl/certs/dns.pem"
    key: "/etc/ssl/private/dns.key"

  # DNS over HTTPS (port 443)
  doh:
    enabled: false              # Planned feature
    port: 443
    path: "/dns-query"
    certificate: "/etc/ssl/certs/dns.pem"
    key: "/etc/ssl/private/dns.key"
```

For planned DoT/DoH features and specifications, see [dot-doh.md](dot-doh.md).

## Dynamic DNS Configuration

```yaml
ddns:
  # Enable DDNS client
  enabled: true

  # Number of retry attempts
  retry-count: 3

  # Initial delay between retries (exponential backoff)
  retry-delay: "30s"

  # Timeout for each update request
  timeout: "10s"

  # Target DNS servers
  servers:
    - name: "parent-ns1"
      address: "ns1.parent.com:53"
      zone: "parent.com."
      tsig:
        name: "ddns-key"
        algorithm: "hmac-sha256"
        secret: "BASE64_ENCODED_SECRET"

    - name: "parent-ns2"
      address: "ns2.parent.com:53"
      zone: "parent.com."
      tsig:
        name: "ddns-key"
        algorithm: "hmac-sha256"
        secret: "BASE64_ENCODED_SECRET"
```

### DDNS Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DDNS client |
| `retry-count` | int | `3` | Number of retry attempts |
| `retry-delay` | duration | `30s` | Initial retry delay |
| `timeout` | duration | `10s` | Request timeout |
| `servers` | []Server | - | Target DNS servers |

### Server Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | Friendly server name |
| `address` | string | Yes | Server address (host:port) |
| `zone` | string | Yes | Zone this server is authoritative for |
| `tsig.name` | string | Yes | TSIG key name |
| `tsig.algorithm` | string | Yes | HMAC algorithm |
| `tsig.secret` | string | Yes | Base64-encoded shared secret |

### TSIG Algorithms

| Algorithm | Security | Recommendation |
|-----------|----------|----------------|
| `hmac-sha256` | High | Recommended |
| `hmac-sha384` | Very High | Alternative |
| `hmac-sha512` | Very High | High security environments |
| `hmac-md5` | Low | Legacy only, not recommended |

## Scheduler Configuration

```yaml
scheduler:
  # Enable scheduler
  enabled: true

  # Default check interval
  check-interval: "1h"

  # Scheduled jobs
  jobs:
    # ACME certificate renewal
    acme-renewal:
      enabled: true
      threshold: "30d"

    # DNSSEC ZSK rotation
    dnssec-zsk-rotation:
      enabled: true
      threshold: "30d"

    # DNSSEC KSK rotation
    dnssec-ksk-rotation:
      enabled: true
      threshold: "60d"

    # DNSSEC RRSIG refresh
    dnssec-rrsig-refresh:
      enabled: true
      threshold: "7d"
      interval: "6h"
```

### Scheduler Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable task scheduler |
| `check-interval` | duration | `1h` | Default check interval |

### Job Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable this job |
| `threshold` | duration | varies | Time before expiry to trigger |
| `interval` | duration | - | Override check interval |

### Scheduled Jobs

| Job | Description | Default Threshold |
|-----|-------------|-------------------|
| `acme-renewal` | Renew ACME certificates | 30 days |
| `dnssec-zsk-rotation` | Rotate Zone Signing Keys | 30 days |
| `dnssec-ksk-rotation` | Rotate Key Signing Keys | 60 days |
| `dnssec-rrsig-refresh` | Refresh RRSIG signatures | 7 days |

## Environment Variables

Environment variables can override configuration values:

| Variable | Config Path | Default | Description |
|----------|-------------|---------|-------------|
| `DNS_ENABLED` | `dns` | - | Enable DNS subsystem |
| `DNS_ALLOW_REGISTRATION` | `dns.allow-registration` | `false` | Allow dynamic registration |
| `DNS_ALLOW_EXTERNAL_REGISTRATION` | `dns.allow-external-registration` | `false` | Allow public zone registration |
| `DNS_ALLOW_INTERNAL_REGISTRATION` | `dns.allow-internal-registration` | `true` | Allow internal zone registration |
| `DNS_DEFAULT_TTL` | `dns.default-ttl` | `3600` | Default record TTL |
| `DNS_PRIVATE_IPV4` | `dns.private-ipv4` | - | Private IPv4 address |
| `DNS_PRIVATE_IPV6` | `dns.private-ipv6` | - | Private IPv6 address |
| `DNS_PUBLIC_IPV4` | `dns.public-ipv4` | - | Public IPv4 address |
| `DNS_PUBLIC_IPV6` | `dns.public-ipv6` | - | Public IPv6 address |
| `DNS_PUBLIC_PORT` | `dns.public.port` | `8053` | Public server port |
| `DNS_INTERNAL_PORT` | `dns.internal.port` | `9053` | Internal server port |
| `DNS_SHARD_ID` | `dns.shard-id` | `0` | QuicBaaS shard ID |
| `DNS_PARTITION` | `dns.partition` | `dns` | Partition name for disk isolation |
| `DNSSEC_ENABLED` | `dns.dnssec.enabled` | `false` | Enable DNSSEC |
| `DNSSEC_ALGORITHM` | `dns.dnssec.algorithm` | `ECDSAP256SHA256` | Signing algorithm |
| `DNSSEC_ROLLOVER_ENABLED` | `dns.dnssec.rollover.enabled` | `true` | Enable automatic rollovers |
| `DNSSEC_ZSK_LIFETIME` | `dns.dnssec.zsk.lifetime` | `30d` | ZSK validity period |
| `DNSSEC_KSK_LIFETIME` | `dns.dnssec.ksk.lifetime` | `365d` | KSK validity period |
| `DNSSEC_TPM_PCR_POLICY` | `dns.dnssec.*.tpm.pcr-policy` | `0,7,8,9` | PCR indices for TPM policy |
| `DDNS_ENABLED` | `dns.ddns.enabled` | `false` | Enable DDNS client |
| `DDNS_RETRY_COUNT` | `dns.ddns.retry-count` | `3` | Retry attempts |
| `DDNS_TIMEOUT` | `dns.ddns.timeout` | `10s` | Request timeout |

### Environment Variable Syntax

Configuration values can reference environment variables using `${VAR}` syntax:

```yaml
dns:
  public-ipv4: "${MY_PUBLIC_IP}"
  ddns:
    servers:
      - tsig:
          secret: "${DDNS_TSIG_SECRET}"
```

## Configuration Macros

Macros provide dynamic value expansion in zone configurations:

| Macro | Description | Source |
|-------|-------------|--------|
| `${PUBLIC_IPv4}` | Public IPv4 address | `dns.public-ipv4` config |
| `${PUBLIC_IPv6}` | Public IPv6 address | `dns.public-ipv6` config |
| `${PRIVATE_IPv4}` | Private IPv4 address | `dns.private-ipv4` config |
| `${PRIVATE_IPv6}` | Private IPv6 address | `dns.private-ipv6` config |
| `${HOSTNAME}` | Local system hostname | `os.Hostname()` |
| `${PUBLIC_DOMAIN}` | Public zone name | `dns.public.zone.name` |
| `${PRIVATE_DOMAIN}` | Private zone name | `dns.internal.zone.name` |
| `${PUBLIC_FQDN}` | Hostname + public domain | Computed |
| `${PRIVATE_FQDN}` | Hostname + private domain | Computed |
| `${PREFERRED_IP}` | System preferred IPv4 | Network detection |

### Macro Usage

```yaml
dns:
  public-ipv4: "203.0.113.50"
  private-ipv4: "192.168.1.100"

  public:
    zone:
      records:
        a:
          # Expands to: value: "203.0.113.50"
          - name: "ns1"
            value: "${PUBLIC_IPv4}"
            ttl: 3600

  internal:
    zone:
      records:
        a:
          # Expands to: name: "<hostname>", value: "192.168.1.100"
          - name: "${HOSTNAME}"
            value: "${PRIVATE_IPv4}"
            ttl: 3600
```

## Complete Configuration Example

```yaml
# Complete DNS configuration example
dns:
  # Registration settings
  allow-registration: true
  allow-external-registration: false
  allow-internal-registration: true
  default-ttl: 3600

  # IP addresses for macro expansion
  private-ipv4: "192.168.1.100"
  private-ipv6: "fd00::100"
  public-ipv4: "203.0.113.50"
  public-ipv6: "2001:db8::50"

  # QuicBaaS storage (inherited from platform quicbaas: config)
  # Service-specific overrides
  shard-id: 2
  partition: dns

  # Public DNS server
  public:
    port: 8053
    forwarders:
      - "8.8.8.8"
      - "8.8.4.4"
    zone:
      name: "example.com."
      ttl: 3600
      description: "Public zone for example.com"
      internal: false
      records:
        soa:
          name: "example.com."
          mname: "ns1.example.com."
          rname: "hostmaster.example.com."
          serial: 2024010101
          refresh: 86400
          retry: 7200
          expire: 86400
          minimum_ttl: 3600
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
        aaaa:
          - name: "ns1"
            value: "${PUBLIC_IPv6}"
            ttl: 3600
          - name: "www"
            value: "${PUBLIC_IPv6}"
            ttl: 3600
        cname:
          - name: "mail"
            value: "www.example.com."
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

  # Internal DNS server
  internal:
    port: 9053
    forwarders:
      - "192.168.1.1"
    zone:
      name: "example.internal."
      ttl: 3600
      description: "Internal zone for example.internal"
      internal: true
      records:
        soa:
          name: "example.internal."
          mname: "ns1.example.internal."
          rname: "hostmaster.example.internal."
          serial: 2024010101
          refresh: 86400
          retry: 7200
          expire: 86400
          minimum_ttl: 3600
          ttl: 3600
        ns:
          - name: "example.internal."
            value: "ns1.example.internal."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${PRIVATE_IPv4}"
            ttl: 3600
          - name: "${HOSTNAME}"
            value: "${PRIVATE_IPv4}"
            ttl: 3600

  # DNSSEC configuration
  dnssec:
    enabled: true
    default-key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: tpm2
    signature-expiry: 30d
    nsec-mode: nsec3
    nsec3-iterations: 1
    nsec3-salt: ""
    ksk:
      lifetime: 365d
      ttl: 86400
    zsk:
      lifetime: 30d
      ttl: 3600

  # Dynamic DNS client
  ddns:
    enabled: true
    retry-count: 3
    retry-delay: "30s"
    timeout: "10s"
    servers:
      - name: "parent-ns1"
        address: "ns1.parent.example.com:53"
        zone: "parent.example.com."
        tsig:
          name: "ddns-key"
          algorithm: "hmac-sha256"
          secret: "${DDNS_TSIG_SECRET}"

  # Scheduler
  scheduler:
    enabled: true
    check-interval: "1h"
    jobs:
      acme-renewal:
        enabled: true
        threshold: "30d"
      dnssec-zsk-rotation:
        enabled: true
        threshold: "30d"
      dnssec-ksk-rotation:
        enabled: true
        threshold: "60d"
      dnssec-rrsig-refresh:
        enabled: true
        threshold: "7d"
        interval: "6h"
```

## Validation

Configuration is validated at startup. Common validation errors:

### Zone Validation

| Field | Validation | Error |
|-------|------------|-------|
| `name` | Must end with `.` | `zone name must be fully qualified (end with dot)` |
| `name` | Max 253 characters | `zone name exceeds maximum length` |
| `ttl` | Must be positive | `TTL must be positive` |
| `records.soa` | Required | `SOA record is required` |
| `records.ns` | At least one required | `at least one NS record is required` |

### Record Validation

| Record | Validation | Error |
|--------|------------|-------|
| A | Valid IPv4 | `invalid IPv4 address` |
| AAAA | Valid IPv6 | `invalid IPv6 address` |
| CNAME | FQDN format | `CNAME value must be fully qualified` |
| MX | Priority 0-65535 | `MX priority out of range` |
| SRV | Port 0-65535 | `SRV port out of range` |
| Label | Max 63 chars | `label exceeds maximum length (63)` |

### DNSSEC Validation

| Field | Validation | Error |
|-------|------------|-------|
| `default-key.algorithm` | RSA, ECDSA, or Ed25519 | `unsupported key algorithm` |
| `default-key.ecc.curve` | P-256 or P-384 | `unsupported ECC curve` |
| `default-key.store` | Valid backend | `invalid key storage backend` |
| `nsec3-iterations` | 0-150 | `NSEC3 iterations must be 0-150` |
| `signature-expiry` | Positive duration | `signature expiry must be positive` |

### DDNS Validation

| Field | Validation | Error |
|-------|------------|-------|
| `servers[].address` | Valid host:port | `invalid server address format` |
| `servers[].zone` | FQDN | `zone must be fully qualified` |
| `servers[].tsig.algorithm` | Supported | `unsupported TSIG algorithm` |
| `servers[].tsig.secret` | Valid Base64 | `invalid Base64 encoding for TSIG secret` |

## See Also

- [Architecture](architecture.md) - DNS system architecture
- [Zones](zones.md) - Zone management
- [Records](records.md) - DNS record types
- [DNSSEC](dnssec.md) - DNSSEC signing and validation
- [DNSSEC Rollover](dnssec-rollover.md) - Key rollover procedures
- [DANE/TLSA](dane.md) - Certificate pinning configuration
- [Dynamic DNS](dynamic-dns.md) - RFC 2136 dynamic updates with attestation
- [DoT/DoH](dot-doh.md) - DNS over TLS/HTTPS (planned)
- [Zone Transfer](zone-transfer.md) - AXFR/IXFR zone transfer (planned)
- [Operations](operations.md) - Monitoring and maintenance
- [Security](security.md) - Security model and best practices

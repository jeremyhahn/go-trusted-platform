# DNS CLI Reference

Command-line interface for DNS zone and record management with the Trusted Platform.

## Overview

The `platformctl dns` command provides comprehensive DNS management capabilities including zone operations, record management, DNSSEC configuration, dynamic DNS updates, and server administration.

### Command Structure

```
platformctl dns <subcommand> [options]
```

### Subcommand Categories

| Category | Description |
|----------|-------------|
| `zone` | Zone management operations |
| `record` | DNS record operations |
| `dnssec` | DNSSEC signing and key management |
| `dane` | DANE/TLSA certificate pinning |
| `update` | Dynamic DNS record updates |
| `delete` | Dynamic DNS record deletion |
| `server` | DNS server administration |

---

## Zone Management

### List Zones

List all configured DNS zones.

```bash
platformctl dns zone list [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--internal` | bool | false | Show only internal zones |
| `--public` | bool | false | Show only public zones |
| `--format` | string | table | Output format: `table`, `json`, `yaml` |
| `--verbose` | bool | false | Include additional zone details |

**Output Fields:**

| Field | Description |
|-------|-------------|
| `NAME` | Zone name (FQDN) |
| `TYPE` | Zone type (internal/public) |
| `RECORDS` | Total record count |
| `DNSSEC` | DNSSEC status (enabled/disabled) |
| `SERIAL` | SOA serial number |

**Examples:**

```bash
# List all zones
platformctl dns zone list

# List only internal zones
platformctl dns zone list --internal

# List zones in JSON format
platformctl dns zone list --format json

# Verbose listing with details
platformctl dns zone list --verbose
```

**Example Output:**

```
NAME                          TYPE      RECORDS  DNSSEC    SERIAL
trusted-platform.internal.    internal  45       disabled  2024011501
trusted-platform.io.          public    23       enabled   2024011502
example.com.                  public    67       enabled   2024011503
```

---

### Create Zone

Create a new DNS zone.

```bash
platformctl dns zone create <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name (must be FQDN with trailing dot) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--internal` | bool | false | Create as internal zone |
| `--description` | string | - | Zone description |
| `--ttl` | int | 3600 | Default TTL for records |
| `--refresh` | int | 86400 | SOA refresh interval |
| `--retry` | int | 7200 | SOA retry interval |
| `--expire` | int | 86400 | SOA expire time |
| `--min-ttl` | int | 3600 | SOA minimum TTL |
| `--mname` | string | auto | Primary nameserver (SOA MNAME) |
| `--rname` | string | auto | Hostmaster email (SOA RNAME) |

**Examples:**

```bash
# Create a public zone
platformctl dns zone create example.com.

# Create an internal zone with description
platformctl dns zone create corp.internal. --internal --description "Corporate internal zone"

# Create zone with custom SOA values
platformctl dns zone create example.com. \
  --ttl 7200 \
  --refresh 43200 \
  --retry 3600 \
  --mname ns1.example.com. \
  --rname hostmaster.example.com.
```

---

### Delete Zone

Delete a DNS zone and all its records.

```bash
platformctl dns zone delete <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name to delete |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--force` | bool | false | Skip confirmation prompt |
| `--preserve-keys` | bool | false | Keep DNSSEC keys after deletion |

**Examples:**

```bash
# Delete zone with confirmation
platformctl dns zone delete example.com.

# Force delete without confirmation
platformctl dns zone delete example.com. --force

# Delete zone but preserve DNSSEC keys
platformctl dns zone delete example.com. --force --preserve-keys
```

---

### Show Zone

Display detailed information about a zone.

```bash
platformctl dns zone show <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name to display |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format` | string | table | Output format: `table`, `json`, `yaml` |
| `--include-records` | bool | false | Include all zone records |
| `--include-dnssec` | bool | false | Include DNSSEC status and keys |

**Examples:**

```bash
# Show zone details
platformctl dns zone show example.com.

# Show zone in JSON format
platformctl dns zone show example.com. --format json

# Show zone with all records
platformctl dns zone show example.com. --include-records

# Show zone with DNSSEC information
platformctl dns zone show example.com. --include-dnssec
```

**Example Output:**

```
Zone: example.com.
Type: public
Description: Production domain
Created: 2024-01-15T10:30:00Z
Modified: 2024-01-20T14:22:00Z

SOA Record:
  Primary NS: ns1.example.com.
  Hostmaster: hostmaster.example.com.
  Serial: 2024012001
  Refresh: 86400
  Retry: 7200
  Expire: 86400
  Minimum TTL: 3600

Statistics:
  Total Records: 67
  A Records: 25
  AAAA Records: 10
  CNAME Records: 15
  MX Records: 3
  TXT Records: 14

DNSSEC:
  Status: enabled
  Algorithm: ECDSAP256SHA256
  KSK Key Tag: 12345
  ZSK Key Tag: 54321
```

---

### Import Zone

Import a zone from a zone file.

```bash
platformctl dns zone import <zone> <file> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name for imported data |
| `<file>` | Yes | Path to zone file (BIND format) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--internal` | bool | false | Import as internal zone |
| `--overwrite` | bool | false | Overwrite existing zone |
| `--dry-run` | bool | false | Show what would be imported |
| `--validate` | bool | true | Validate records before import |

**Examples:**

```bash
# Import zone from file
platformctl dns zone import example.com. /path/to/example.com.zone

# Import with overwrite
platformctl dns zone import example.com. /path/to/example.com.zone --overwrite

# Dry run to validate
platformctl dns zone import example.com. /path/to/example.com.zone --dry-run
```

---

### Export Zone

Export a zone to a file.

```bash
platformctl dns zone export <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name to export |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--file` | string | stdout | Output file path |
| `--format` | string | bind | Export format: `bind`, `json`, `yaml` |
| `--include-dnssec` | bool | false | Include DNSSEC records (DNSKEY, RRSIG, NSEC) |

**Examples:**

```bash
# Export to stdout in BIND format
platformctl dns zone export example.com.

# Export to file
platformctl dns zone export example.com. --file /path/to/output.zone

# Export in JSON format
platformctl dns zone export example.com. --format json --file zone.json

# Export with DNSSEC records
platformctl dns zone export example.com. --include-dnssec --file signed.zone
```

---

### Sign Zone

Sign a zone with DNSSEC.

```bash
platformctl dns zone sign <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name to sign |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algorithm` | string | ECDSAP256SHA256 | Signing algorithm |
| `--force` | bool | false | Force complete re-sign |
| `--refresh` | bool | false | Refresh signature timestamps only |

**Examples:**

```bash
# Sign zone with default algorithm
platformctl dns zone sign example.com.

# Sign with specific algorithm
platformctl dns zone sign example.com. --algorithm ECDSAP384SHA384

# Force complete re-sign
platformctl dns zone sign example.com. --force
```

---

### Resign Zone

Refresh zone signatures without full re-signing.

```bash
platformctl dns zone resign <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name to resign |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--validity` | duration | 14d | Signature validity period |
| `--force` | bool | false | Force resign all records |

**Examples:**

```bash
# Resign zone with default validity
platformctl dns zone resign example.com.

# Resign with custom validity period
platformctl dns zone resign example.com. --validity 30d
```

---

## Record Management

### List Records

List records in a zone.

```bash
platformctl dns record list <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--type` | string | all | Filter by record type: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `SRV`, `TXT`, `PTR` |
| `--name` | string | - | Filter by record name |
| `--format` | string | table | Output format: `table`, `json`, `yaml` |
| `--include-dnssec` | bool | false | Include DNSSEC records |

**Examples:**

```bash
# List all records
platformctl dns record list example.com.

# List only A records
platformctl dns record list example.com. --type A

# List records matching name pattern
platformctl dns record list example.com. --name "www"

# List MX records in JSON
platformctl dns record list example.com. --type MX --format json
```

**Example Output:**

```
NAME                    TYPE   TTL    VALUE
@                       A      3600   203.0.113.50
@                       AAAA   3600   2001:db8::1
@                       MX     3600   10 mail.example.com.
@                       TXT    3600   "v=spf1 include:_spf.example.com ~all"
www                     A      3600   203.0.113.50
www                     AAAA   3600   2001:db8::1
mail                    A      3600   203.0.113.51
api                     CNAME  3600   www.example.com.
```

---

### Add Record

Add a new record to a zone.

```bash
platformctl dns record add <zone> <type> <name> <value> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |
| `<type>` | Yes | Record type |
| `<name>` | Yes | Record name (use `@` for zone apex) |
| `<value>` | Yes | Record value |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--ttl` | int | 3600 | Record TTL in seconds |
| `--priority` | int | - | Priority (MX, SRV records) |
| `--weight` | int | - | Weight (SRV records) |
| `--port` | int | - | Port (SRV records) |

**Record Type Examples:**

```bash
# A record (IPv4)
platformctl dns record add example.com. A www 203.0.113.50

# AAAA record (IPv6)
platformctl dns record add example.com. AAAA www 2001:db8::1

# CNAME record
platformctl dns record add example.com. CNAME api www.example.com.

# MX record with priority
platformctl dns record add example.com. MX @ mail.example.com. --priority 10

# TXT record (quote values with spaces)
platformctl dns record add example.com. TXT @ "v=spf1 include:_spf.example.com ~all"

# SRV record
platformctl dns record add example.com. SRV _ldap._tcp ldap.example.com. \
  --priority 10 --weight 5 --port 389

# NS record
platformctl dns record add example.com. NS @ ns1.example.com.

# PTR record (for reverse DNS)
platformctl dns record add 113.0.203.in-addr.arpa. PTR 50 www.example.com.
```

**Advanced Examples:**

```bash
# Add record with custom TTL
platformctl dns record add example.com. A www 203.0.113.50 --ttl 7200

# Add DKIM record
platformctl dns record add example.com. TXT selector1._domainkey \
  "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

#### CAA Records

Add Certificate Authority Authorization records to control which CAs can issue certificates.

```bash
platformctl dns record add <zone> --type CAA --name <name> --flags <flags> --tag <tag> --value <value> [options]
```

**CAA-Specific Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--flags` | int | 0 | CAA flags (0=non-critical, 128=critical) |
| `--tag` | string | required | CAA tag: `issue`, `issuewild`, `iodef` |

**CAA Examples:**

```bash
# Allow Let's Encrypt to issue certificates
platformctl dns record add example.com. --type CAA --name @ \
  --flags 0 --tag issue --value "letsencrypt.org"

# Allow wildcard certificates from DigiCert
platformctl dns record add example.com. --type CAA --name @ \
  --flags 0 --tag issuewild --value "digicert.com"

# Set incident reporting email
platformctl dns record add example.com. --type CAA --name @ \
  --flags 0 --tag iodef --value "mailto:security@example.com"

# Critical flag - CA must understand this tag
platformctl dns record add example.com. --type CAA --name @ \
  --flags 128 --tag issue --value ";"  # Prohibit all issuance
```

---

### Delete Record

Delete a record from a zone.

```bash
platformctl dns record delete <zone> <type> <name> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |
| `<type>` | Yes | Record type |
| `<name>` | Yes | Record name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--value` | string | - | Delete only record with matching value |
| `--force` | bool | false | Skip confirmation prompt |
| `--all` | bool | false | Delete all records of this type/name |

**Examples:**

```bash
# Delete A record
platformctl dns record delete example.com. A www

# Delete specific record by value
platformctl dns record delete example.com. A www --value 203.0.113.50

# Delete all A records for a name
platformctl dns record delete example.com. A www --all

# Force delete without confirmation
platformctl dns record delete example.com. A www --force
```

---

### Update Record

Update an existing record.

```bash
platformctl dns record update <zone> <type> <name> <value> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |
| `<type>` | Yes | Record type |
| `<name>` | Yes | Record name |
| `<value>` | Yes | New record value |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--old-value` | string | - | Match specific old value |
| `--ttl` | int | - | Update TTL |
| `--priority` | int | - | Update priority (MX, SRV) |

**Examples:**

```bash
# Update A record
platformctl dns record update example.com. A www 203.0.113.51

# Update specific record by old value
platformctl dns record update example.com. A www 203.0.113.51 --old-value 203.0.113.50

# Update record and TTL
platformctl dns record update example.com. A www 203.0.113.51 --ttl 7200

# Update MX priority
platformctl dns record update example.com. MX @ mail.example.com. --priority 5
```

---

## DNSSEC Operations

### Status

Show DNSSEC status for a zone.

```bash
platformctl dns dnssec status <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format` | string | table | Output format: `table`, `json`, `yaml` |
| `--verbose` | bool | false | Include extended key information |

**Examples:**

```bash
# Show DNSSEC status
platformctl dns dnssec status example.com.

# Show status in JSON
platformctl dns dnssec status example.com. --format json

# Verbose status with key details
platformctl dns dnssec status example.com. --verbose
```

**Example Output:**

```
Zone: example.com.
Status: SIGNED
Algorithm: ECDSAP256SHA256 (13)

Key Signing Key (KSK):
  Key Tag: 12345
  Algorithm: ECDSAP256SHA256
  Flags: 257 (SEP)
  Created: 2024-01-15T00:00:00Z
  Expires: 2025-01-15T00:00:00Z
  Store: tpm2

Zone Signing Key (ZSK):
  Key Tag: 54321
  Algorithm: ECDSAP256SHA256
  Flags: 256
  Created: 2024-06-01T00:00:00Z
  Expires: 2024-07-01T00:00:00Z
  Store: tpm2

Signatures:
  Valid Until: 2024-06-15T00:00:00Z
  Next Refresh: 2024-06-08T00:00:00Z
  Signature Count: 127

Denial of Existence:
  Mode: NSEC3
  Iterations: 1
  Salt Length: 8 bytes
```

---

### Enable DNSSEC

Enable DNSSEC signing for a zone.

```bash
platformctl dns dnssec enable <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algorithm` | string | ECDSAP256SHA256 | Signing algorithm |
| `--ksk-store` | string | tpm2 | KSK storage backend |
| `--zsk-store` | string | tpm2 | ZSK storage backend |
| `--nsec3` | bool | true | Use NSEC3 for denial of existence |
| `--nsec3-iterations` | int | 1 | NSEC3 hash iterations |
| `--nsec3-salt-length` | int | 8 | NSEC3 salt length in bytes |

**Supported Algorithms:**

| Algorithm | ID | Notes |
|-----------|-----|-------|
| ECDSAP256SHA256 | 13 | Recommended, default |
| ECDSAP384SHA384 | 14 | Higher security |
| ED25519 | 15 | Modern, compact |
| ED448 | 16 | Highest security |
| RSASHA256 | 8 | Legacy compatibility |
| RSASHA512 | 10 | Legacy compatibility |

**Examples:**

```bash
# Enable with defaults
platformctl dns dnssec enable example.com.

# Enable with specific algorithm
platformctl dns dnssec enable example.com. --algorithm ECDSAP384SHA384

# Enable with software key storage (development)
platformctl dns dnssec enable example.com. --ksk-store software --zsk-store software

# Enable with NSEC (instead of NSEC3)
platformctl dns dnssec enable example.com. --nsec3=false
```

---

### Disable DNSSEC

Disable DNSSEC signing for a zone.

```bash
platformctl dns dnssec disable <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--remove-keys` | bool | false | Delete DNSSEC keys |
| `--force` | bool | false | Skip confirmation prompt |

**Examples:**

```bash
# Disable DNSSEC (keeps keys)
platformctl dns dnssec disable example.com.

# Disable and remove keys
platformctl dns dnssec disable example.com. --remove-keys

# Force disable without confirmation
platformctl dns dnssec disable example.com. --force
```

---

### Generate KSK

Generate a new Key Signing Key.

```bash
platformctl dns dnssec generate-ksk <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algorithm` | string | ECDSAP256SHA256 | Key algorithm |
| `--store` | string | tpm2 | Key storage backend |
| `--lifetime` | duration | 365d | Key lifetime |
| `--publish` | bool | true | Publish key immediately |

**Storage Backends:**

| Backend | Description | Use Case |
|---------|-------------|----------|
| `software` | Software key storage | Development/testing |
| `tpm2` | TPM 2.0 hardware | Production (recommended) |
| `pkcs11` | PKCS#11 HSM | Enterprise HSMs |
| `aws-kms` | AWS Key Management Service | AWS deployments |
| `azure-kv` | Azure Key Vault | Azure deployments |
| `gcp-kms` | GCP Cloud KMS | GCP deployments |
| `vault` | HashiCorp Vault | Multi-cloud |

**Examples:**

```bash
# Generate KSK with defaults
platformctl dns dnssec generate-ksk example.com.

# Generate with specific algorithm
platformctl dns dnssec generate-ksk example.com. --algorithm ED25519

# Generate with TPM storage
platformctl dns dnssec generate-ksk example.com. --store tpm2

# Generate with custom lifetime
platformctl dns dnssec generate-ksk example.com. --lifetime 730d
```

---

### Generate ZSK

Generate a new Zone Signing Key.

```bash
platformctl dns dnssec generate-zsk <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--algorithm` | string | from KSK | Key algorithm |
| `--store` | string | tpm2 | Key storage backend |
| `--lifetime` | duration | 30d | Key lifetime |
| `--publish` | bool | true | Publish key immediately |

**Examples:**

```bash
# Generate ZSK with defaults
platformctl dns dnssec generate-zsk example.com.

# Generate with custom lifetime
platformctl dns dnssec generate-zsk example.com. --lifetime 60d

# Generate with software storage (development)
platformctl dns dnssec generate-zsk example.com. --store software
```

---

### Rotate KSK

Initiate Key Signing Key rollover.

```bash
platformctl dns dnssec rotate-ksk <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--method` | string | double-sign | Rollover method: `double-sign`, `double-ds` |
| `--wait` | bool | false | Wait for rollover completion |
| `--submit-ds` | bool | false | Auto-submit DS to parent via DDNS |

**Examples:**

```bash
# Initiate KSK rollover
platformctl dns dnssec rotate-ksk example.com.

# Rollover with auto-DS submission
platformctl dns dnssec rotate-ksk example.com. --submit-ds

# Rollover and wait for completion
platformctl dns dnssec rotate-ksk example.com. --wait
```

---

### Rotate ZSK

Initiate Zone Signing Key rollover.

```bash
platformctl dns dnssec rotate-zsk <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--method` | string | pre-publish | Rollover method: `pre-publish`, `double-sign` |
| `--wait` | bool | false | Wait for rollover completion |

**Examples:**

```bash
# Initiate ZSK rollover
platformctl dns dnssec rotate-zsk example.com.

# Rollover with double-sign method
platformctl dns dnssec rotate-zsk example.com. --method double-sign

# Rollover and wait for completion
platformctl dns dnssec rotate-zsk example.com. --wait
```

---

### Show DS Record

Display DS record for submission to parent zone.

```bash
platformctl dns dnssec show-ds <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format` | string | bind | Output format: `bind`, `generic`, `json` |
| `--digest-type` | int | 2 | Digest type: `1` (SHA-1), `2` (SHA-256), `4` (SHA-384) |
| `--key-tag` | int | - | Specific key tag (default: current KSK) |

**Examples:**

```bash
# Show DS record in BIND format
platformctl dns dnssec show-ds example.com.

# Show DS record with SHA-384 digest
platformctl dns dnssec show-ds example.com. --digest-type 4

# Show DS record in generic format
platformctl dns dnssec show-ds example.com. --format generic

# Show DS for specific key
platformctl dns dnssec show-ds example.com. --key-tag 12345
```

**Example Output:**

```
; DS record for example.com.
; Submit this record to your registrar or parent zone operator

example.com. IN DS 12345 13 2 (
    A1B2C3D4E5F6789012345678901234567890ABCD
    EF1234567890ABCDEF1234567890ABCDEF123456 )

; Key Tag: 12345
; Algorithm: ECDSAP256SHA256 (13)
; Digest Type: SHA-256 (2)
```

---

### Verify DNSSEC

Verify DNSSEC configuration and chain of trust.

```bash
platformctl dns dnssec verify <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<zone>` | Yes | Zone name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--full` | bool | false | Full chain of trust verification |
| `--from-root` | bool | false | Trace chain from root zone |
| `--format` | string | table | Output format: `table`, `json`, `yaml` |

**Examples:**

```bash
# Basic DNSSEC verification
platformctl dns dnssec verify example.com.

# Full verification with chain of trust
platformctl dns dnssec verify example.com. --full

# Trace from root
platformctl dns dnssec verify example.com. --from-root
```

**Example Output:**

```
Zone: example.com.
DNSSEC Status: VALID

Verification Results:
  DNSKEY RRset: VALID (signed by KSK 12345)
  A records: VALID (signed by ZSK 54321)
  MX records: VALID (signed by ZSK 54321)
  NSEC3 chain: COMPLETE

Chain of Trust:
  . -> com. -> example.com.
  Root DS: VALID
  com. DS: VALID
  example.com. DS: VALID

All checks passed.
```

---

## DANE/TLSA Operations

### Generate TLSA

Generate a TLSA record from a certificate file.

```bash
platformctl dns dane generate-tlsa --domain <domain> --port <port> --cert <path> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--domain` | Yes | Target domain (e.g., www.example.com) |
| `--port` | Yes | Service port (e.g., 443) |
| `--cert` | Yes | Path to certificate PEM file |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--protocol` | string | tcp | Protocol: `tcp`, `udp`, `sctp` |
| `--usage` | int | 3 | Certificate usage (0-3) |
| `--selector` | int | 1 | Selector (0=cert, 1=SPKI) |
| `--matching-type` | int | 1 | Matching type (0=full, 1=SHA-256, 2=SHA-512) |
| `--ttl` | int | 3600 | Record TTL |
| `--add` | bool | false | Add record to zone automatically |
| `--zone` | string | auto | Target zone for `--add` |

**Examples:**

```bash
# Generate TLSA record for HTTPS service
platformctl dns dane generate-tlsa \
  --domain www.example.com \
  --port 443 \
  --cert /etc/ssl/certs/www.pem

# Generate and add to zone
platformctl dns dane generate-tlsa \
  --domain www.example.com \
  --port 443 \
  --cert /etc/ssl/certs/www.pem \
  --add --zone example.com.

# Use SHA-512 matching
platformctl dns dane generate-tlsa \
  --domain www.example.com \
  --port 443 \
  --cert /etc/ssl/certs/www.pem \
  --matching-type 2

# DANE-TA usage (trust anchor)
platformctl dns dane generate-tlsa \
  --domain www.example.com \
  --port 443 \
  --cert /etc/ssl/certs/ca.pem \
  --usage 2
```

**Example Output:**

```
TLSA Record:
  Name: _443._tcp.www.example.com.
  Usage: 3 (DANE-EE)
  Selector: 1 (SPKI)
  Matching Type: 1 (SHA-256)
  Data: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

BIND Format:
_443._tcp.www.example.com. 3600 IN TLSA 3 1 1 a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

---

### Auto-Generate TLSA

Automatically generate TLSA records for all certificates in a zone.

```bash
platformctl dns dane auto-generate --zone <zone> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--zone` | Yes | Zone name (FQDN) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--source` | string | platform-ca | Certificate source: `platform-ca`, `file`, `acme` |
| `--ports` | []int | 443 | Service ports to generate TLSA for |
| `--dry-run` | bool | false | Show what would be generated |
| `--update` | bool | false | Update existing TLSA records |

**Examples:**

```bash
# Auto-generate from platform CA
platformctl dns dane auto-generate --zone example.com.

# Generate for multiple ports
platformctl dns dane auto-generate --zone example.com. --ports 443,8443,993

# Dry run to preview
platformctl dns dane auto-generate --zone example.com. --dry-run

# Update existing records
platformctl dns dane auto-generate --zone example.com. --update
```

---

### Verify DANE

Verify DANE/TLSA configuration for a domain.

```bash
platformctl dns dane verify --domain <domain> --port <port> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--domain` | Yes | Target domain to verify |
| `--port` | Yes | Service port |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--protocol` | string | tcp | Protocol: `tcp`, `udp` |
| `--connect` | bool | true | Connect to service and verify certificate |
| `--verbose` | bool | false | Show detailed verification output |
| `--format` | string | table | Output format: `table`, `json`, `yaml` |

**Examples:**

```bash
# Verify HTTPS DANE configuration
platformctl dns dane verify --domain www.example.com --port 443

# Verify without connecting to service
platformctl dns dane verify --domain www.example.com --port 443 --connect=false

# Verbose output
platformctl dns dane verify --domain www.example.com --port 443 --verbose
```

**Example Output:**

```
DANE Verification: www.example.com:443
=======================================

TLSA Record:
  Name: _443._tcp.www.example.com.
  Usage: DANE-EE (3)
  Selector: SPKI (1)
  Matching Type: SHA-256 (1)
  Status: FOUND

Certificate Chain:
  Subject: CN=www.example.com
  Issuer: CN=Example CA
  Valid: 2024-01-01 to 2025-01-01

Verification:
  TLSA Match: PASS
  Certificate Valid: PASS
  Chain Complete: PASS

Result: DANE VERIFIED
```

---

## Dynamic DNS

### Update

Add or update a DNS record dynamically using RFC 2136.

```bash
platformctl dns update <fqdn> <ip> [options]
platformctl dns update <fqdn> --auto [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<fqdn>` | Yes | Fully qualified domain name |
| `<ip>` | No | IP address (not required with `--auto`) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--auto` | bool | false | Auto-detect local IP address |
| `--type` | string | A | Record type: `A`, `AAAA`, `TXT`, `PTR` |
| `--ttl` | int | 3600 | Record TTL in seconds |
| `--server` | string | config | Override target DNS server |
| `--zone` | string | auto | Specify zone for update |
| `--dry-run` | bool | false | Show what would be done |
| `--verbose` | bool | false | Enable verbose output |
| `--attest` | bool | false | Include TPM attestation evidence |
| `--attestation-service` | string | config | Attestation service URL |

**Attestation Options:**

When `--attest` is enabled, the client includes TPM attestation evidence with the update request. This is required for zones with attestation enforcement enabled.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--attest` | bool | false | Include TPM attestation with update |
| `--attestation-service` | string | from config | Override attestation service URL |
| `--ak-handle` | hex | auto | TPM Attestation Key handle |
| `--pcr-selection` | string | 0,1,2,3,7 | PCR indices to include in quote |

**Examples:**

```bash
# Update A record with specific IP
platformctl dns update myhost.trusted-platform.internal 192.168.1.100

# Auto-detect IP and update
platformctl dns update myhost.trusted-platform.internal --auto

# Update with custom TTL
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 --ttl 7200

# Update IPv6 record
platformctl dns update myhost.trusted-platform.internal 2001:db8::1 --type AAAA

# Update using specific server
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 \
  --server ns1.trusted-platform.internal:53

# Dry run to preview
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 --dry-run

# Update with TPM attestation (for attested zones)
platformctl dns update myhost.secure.example.com 192.168.1.100 --attest

# Update with attestation using specific service
platformctl dns update myhost.secure.example.com 192.168.1.100 \
  --attest --attestation-service https://attestation.example.com:8443

# Update with custom PCR selection
platformctl dns update myhost.secure.example.com 192.168.1.100 \
  --attest --pcr-selection 0,1,2,3,7,8,9
```

For detailed attestation configuration and workflows, see [dynamic-dns.md](dynamic-dns.md).

---

### Delete

Remove a DNS record dynamically using RFC 2136.

```bash
platformctl dns delete <fqdn> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `<fqdn>` | Yes | Fully qualified domain name |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--type` | string | A | Record type to delete |
| `--all` | bool | false | Delete all records for the name |
| `--server` | string | config | Override target DNS server |
| `--zone` | string | auto | Specify zone for update |
| `--dry-run` | bool | false | Show what would be done |
| `--verbose` | bool | false | Enable verbose output |

**Examples:**

```bash
# Delete A record
platformctl dns delete myhost.trusted-platform.internal

# Delete AAAA record
platformctl dns delete myhost.trusted-platform.internal --type AAAA

# Delete all records for a name
platformctl dns delete myhost.trusted-platform.internal --all

# Dry run
platformctl dns delete myhost.trusted-platform.internal --dry-run
```

---

## Server Administration

### Start

Start the DNS server.

```bash
platformctl dns server start [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--foreground` | bool | false | Run in foreground |
| `--internal-only` | bool | false | Start only internal server |
| `--public-only` | bool | false | Start only public server |

**Examples:**

```bash
# Start DNS server
platformctl dns server start

# Start in foreground
platformctl dns server start --foreground

# Start only internal DNS server
platformctl dns server start --internal-only
```

---

### Stop

Stop the DNS server.

```bash
platformctl dns server stop [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--force` | bool | false | Force immediate stop |
| `--timeout` | duration | 30s | Graceful shutdown timeout |

**Examples:**

```bash
# Stop DNS server gracefully
platformctl dns server stop

# Force stop
platformctl dns server stop --force

# Stop with custom timeout
platformctl dns server stop --timeout 60s
```

---

### Status

Display DNS server status.

```bash
platformctl dns server status [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format` | string | table | Output format: `table`, `json`, `yaml` |
| `--verbose` | bool | false | Include detailed statistics |

**Examples:**

```bash
# Show server status
platformctl dns server status

# Verbose status with statistics
platformctl dns server status --verbose

# Status in JSON format
platformctl dns server status --format json
```

**Example Output:**

```
DNS Server Status
=================

Internal Server:
  Status: running
  Address: 0.0.0.0:9053
  Uptime: 5d 12h 30m
  Zones: 3
  Queries (24h): 125,432

Public Server:
  Status: running
  Address: 0.0.0.0:8053
  Uptime: 5d 12h 30m
  Zones: 2
  Queries (24h): 45,678

DNSSEC Status:
  Signed Zones: 2
  Next Key Rollover: 2024-02-15 (ZSK)
```

---

### Reload

Reload DNS server configuration and zones.

```bash
platformctl dns server reload [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--zones` | bool | true | Reload zone data |
| `--config` | bool | false | Reload configuration |

**Examples:**

```bash
# Reload zones
platformctl dns server reload

# Reload configuration and zones
platformctl dns server reload --config

# Reload only configuration
platformctl dns server reload --config --zones=false
```

---

## Global Options

These options apply to all `platformctl dns` commands.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--config` | string | /etc/trustedplatform/config.yaml | Configuration file path |
| `--format` | string | table | Default output format: `table`, `json`, `yaml` |
| `--verbose` | bool | false | Enable verbose output |
| `--quiet` | bool | false | Suppress non-essential output |
| `--no-color` | bool | false | Disable colored output |
| `--log-level` | string | info | Log level: `debug`, `info`, `warn`, `error` |

**Examples:**

```bash
# Use custom config file
platformctl dns zone list --config /path/to/config.yaml

# JSON output for all commands
platformctl dns zone list --format json

# Quiet mode
platformctl dns record add example.com. A www 203.0.113.50 --quiet

# Debug logging
platformctl dns server status --log-level debug
```

---

## Exit Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | SUCCESS | Command completed successfully |
| 1 | ERROR | General error |
| 2 | USAGE | Invalid command usage |
| 3 | NOT_FOUND | Resource not found (zone, record, key) |
| 4 | ALREADY_EXISTS | Resource already exists |
| 5 | PERMISSION_DENIED | Authorization failed |
| 6 | VALIDATION_ERROR | Input validation failed |
| 7 | DNSSEC_ERROR | DNSSEC operation failed |
| 8 | SERVER_ERROR | DNS server error |
| 9 | NETWORK_ERROR | Network communication error |
| 10 | TIMEOUT | Operation timed out |

---

## Examples

### Complete Zone Setup

```bash
# Create a new public zone
platformctl dns zone create example.com.

# Add basic records
platformctl dns record add example.com. A @ 203.0.113.50
platformctl dns record add example.com. A www 203.0.113.50
platformctl dns record add example.com. AAAA @ 2001:db8::1
platformctl dns record add example.com. AAAA www 2001:db8::1
platformctl dns record add example.com. MX @ mail.example.com. --priority 10
platformctl dns record add example.com. TXT @ "v=spf1 include:_spf.example.com ~all"

# Enable DNSSEC
platformctl dns dnssec enable example.com.

# Get DS record for registrar
platformctl dns dnssec show-ds example.com.

# Verify DNSSEC setup
platformctl dns dnssec verify example.com.
```

### Device Registration Workflow

```bash
# Register device with auto-detected IP
platformctl dns update mydevice.trusted-platform.internal --auto

# Verify registration
dig @localhost -p 9053 mydevice.trusted-platform.internal A

# Update when IP changes
platformctl dns update mydevice.trusted-platform.internal 192.168.1.200

# Deregister device
platformctl dns delete mydevice.trusted-platform.internal
```

### DNSSEC Key Rollover

```bash
# Check current status
platformctl dns dnssec status example.com.

# Initiate ZSK rollover
platformctl dns dnssec rotate-zsk example.com.

# Monitor rollover progress
platformctl dns dnssec status example.com. --verbose

# For KSK rollover (requires DS update at registrar)
platformctl dns dnssec rotate-ksk example.com.

# Get new DS record
platformctl dns dnssec show-ds example.com.

# Submit DS to registrar, then verify
platformctl dns dnssec verify example.com. --full
```

### Zone Migration

```bash
# Export existing zone
platformctl dns zone export old-zone.com. --file old-zone.zone --include-dnssec

# Import to new zone
platformctl dns zone import new-zone.com. old-zone.zone --dry-run

# Execute import
platformctl dns zone import new-zone.com. old-zone.zone --overwrite

# Verify import
platformctl dns zone show new-zone.com. --include-records
```

### Troubleshooting

```bash
# Check server status
platformctl dns server status --verbose

# List all zones
platformctl dns zone list --verbose

# Verify zone configuration
platformctl dns zone show example.com. --include-records --include-dnssec

# Test DNSSEC chain
platformctl dns dnssec verify example.com. --from-root

# Check specific record
dig @localhost -p 8053 +dnssec example.com A
```

---

## See Also

| Document | Description |
|----------|-------------|
| [README](README.md) | DNS subsystem overview |
| [Architecture](architecture.md) | System architecture |
| [Zones](zones.md) | Zone management details |
| [Records](records.md) | DNS record types |
| [DNSSEC](dnssec.md) | DNSSEC signing guide |
| [DNSSEC Rollover](dnssec-rollover.md) | Key rollover procedures |
| [DANE/TLSA](dane.md) | Certificate pinning guide |
| [Dynamic DNS](dynamic-dns.md) | RFC 2136 dynamic updates with attestation |
| [DoT/DoH](dot-doh.md) | DNS over TLS/HTTPS (planned) |
| [Zone Transfer](zone-transfer.md) | Outbound AXFR zone transfer (primary; TSIG) |
| [Configuration](configuration.md) | Configuration reference |
| [Operations](operations.md) | Monitoring and maintenance |
| [API Reference](api-reference.md) | REST and gRPC APIs |
| [Troubleshooting](troubleshooting.md) | Common issues |

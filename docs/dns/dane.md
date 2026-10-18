# DANE/TLSA Records

> **Status: REFERENCE**
> DNS-based Authentication of Named Entities (DANE) enables certificate pinning via DNS.

## Overview

DANE (RFC 6698, 7671, 7672, 7673) uses TLSA records in DNS to associate TLS certificates with domain names, providing an alternative trust path independent of traditional Certificate Authorities.

### Benefits

| Benefit | Description |
|---------|-------------|
| **CA Independence** | Trust established through DNSSEC chain, not CA hierarchy |
| **Certificate Pinning** | Bind specific certificates to services via DNS |
| **MITM Protection** | Cryptographic proof of expected certificate |
| **Reduced CA Trust** | Limit reliance on third-party CA infrastructure |
| **Self-Signed Support** | Enable trusted self-signed certificates with DNSSEC |

### How DANE Works

```
1. Client initiates TLS connection to server
2. Client queries DNS for TLSA record at _port._protocol.hostname
3. DNSSEC validates TLSA record authenticity
4. Client compares server certificate against TLSA data
5. Connection proceeds only if certificate matches TLSA
```

## TLSA Record Structure

TLSA records contain four fields that specify how to match certificates:

```
_443._tcp.www.example.com. IN TLSA <usage> <selector> <matching-type> <certificate-data>
```

### Record Fields

| Field | Size | Description |
|-------|------|-------------|
| **Usage** | 1 byte | How to use the certificate data |
| **Selector** | 1 byte | Which part of certificate to match |
| **Matching Type** | 1 byte | How to match the selected data |
| **Certificate Data** | Variable | The actual certificate or hash data |

### Record Name Format

TLSA records are named using the service port and protocol:

| Service | Record Name |
|---------|-------------|
| HTTPS (443) | `_443._tcp.example.com.` |
| SMTP (25) | `_25._tcp.mail.example.com.` |
| SMTP Submission (587) | `_587._tcp.mail.example.com.` |
| IMAPS (993) | `_993._tcp.mail.example.com.` |
| Custom Port | `_<port>._tcp.<hostname>.` |

## Certificate Usage Types

The usage field determines how the TLSA data relates to the certificate chain.

| Value | Name | Description | Use Case |
|-------|------|-------------|----------|
| 0 | PKIX-TA | CA constraint - certificate must chain to specified CA | Restrict which CAs can issue |
| 1 | PKIX-EE | End entity constraint with PKIX validation | Pin end certificate, require CA validation |
| 2 | DANE-TA | Trust anchor assertion | Specify CA without PKIX chain |
| 3 | DANE-EE | End entity assertion | Pin end certificate directly |

### Usage Recommendations

| Usage | Recommendation | Rationale |
|-------|----------------|-----------|
| **3 (DANE-EE)** | Recommended | Simplest, most direct pinning |
| 2 (DANE-TA) | Supported | Pin CA for multiple services |
| 1 (PKIX-EE) | Situational | Hybrid with traditional PKIX |
| 0 (PKIX-TA) | Situational | Restrict CA issuers |

**DANE-EE (3) is preferred because:**
- No chain validation required
- Self-signed certificates work natively
- Simplest validation logic
- Fastest verification

## Selector Types

The selector field specifies which certificate data to match.

| Value | Name | Description | Size |
|-------|------|-------------|------|
| 0 | Full Certificate | Match entire certificate (DER encoded) | ~1-2 KB |
| 1 | SubjectPublicKeyInfo | Match only the SPKI (public key + algorithm) | ~270-500 bytes |

### Selector Recommendations

| Selector | Recommendation | Rationale |
|----------|----------------|-----------|
| **1 (SPKI)** | Recommended | Key survives re-issuance, smaller records |
| 0 (Cert) | Supported | Includes validity period, issuer info |

**SPKI (1) is preferred because:**
- Record survives certificate renewal (if key unchanged)
- Smaller DNS response size
- Faster DNS lookup and validation
- Reduces TLSA rotation frequency

## Matching Types

The matching type specifies how the certificate data is represented.

| Value | Name | Description | Data Size |
|-------|------|-------------|-----------|
| 0 | Full | Exact match of selected data | Variable |
| 1 | SHA-256 | SHA-256 hash of selected data | 32 bytes |
| 2 | SHA-512 | SHA-512 hash of selected data | 64 bytes |

### Matching Type Recommendations

| Type | Recommendation | Rationale |
|------|----------------|-----------|
| **1 (SHA-256)** | Recommended | Good balance of security and size |
| 2 (SHA-512) | Supported | Higher security margin |
| 0 (Full) | Avoid | Large DNS responses, fragmentation issues |

**SHA-256 (1) is preferred because:**
- 256-bit security is sufficient for certificate binding
- 32-byte hash fits efficiently in DNS
- Avoids UDP fragmentation
- Wide implementation support

## Recommended Configuration

The optimal TLSA record uses:

| Field | Value | Name |
|-------|-------|------|
| Usage | 3 | DANE-EE |
| Selector | 1 | SPKI |
| Matching Type | 1 | SHA-256 |

This combination (3 1 1) provides:
- Direct certificate pinning without CA dependency
- Record survives certificate renewal
- Compact DNS response
- Fast validation

## Configuration

### Basic DANE Configuration

```yaml
dns:
  dane:
    enabled: true
    default-usage: 3
    default-selector: 1
    default-matching-type: 1
    auto-generate: true
```

### Full Configuration Reference

```yaml
dns:
  dane:
    # Enable DANE/TLSA support
    enabled: true

    # Default TLSA record parameters
    default-usage: 3           # DANE-EE
    default-selector: 1        # SPKI
    default-matching-type: 1   # SHA-256

    # Automatic TLSA generation for platform certificates
    auto-generate: true

    # TTL for TLSA records (seconds)
    ttl: 3600

    # Services to auto-generate TLSA for
    services:
      - port: 443
        protocol: tcp
        name: "HTTPS"
      - port: 8443
        protocol: tcp
        name: "Platform API"
      - port: 25
        protocol: tcp
        name: "SMTP"
      - port: 587
        protocol: tcp
        name: "SMTP Submission"
      - port: 993
        protocol: tcp
        name: "IMAPS"

    # Pre-publish period for rollover (seconds)
    prepublish-period: 86400   # 24 hours

    # Certificate sources for auto-generation
    certificate-sources:
      - type: platform-ca
        path: /etc/trusted-platform/certs
      - type: acme
        domains:
          - "*.example.com"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DANE/TLSA support |
| `default-usage` | int | `3` | Default usage field value |
| `default-selector` | int | `1` | Default selector field value |
| `default-matching-type` | int | `1` | Default matching type value |
| `auto-generate` | bool | `false` | Auto-generate TLSA for platform certs |
| `ttl` | int | `3600` | TLSA record TTL |
| `prepublish-period` | int | `86400` | Pre-publish period for rollovers |

## Zone-Level Configuration

Control DANE behavior per zone with opt-in domains and exclusions.

### Enable DANE for Specific Domains

```yaml
dns:
  public:
    zone:
      name: example.com.
      dane:
        enabled: true
        domains:
          - www.example.com
          - api.example.com
          - mail.example.com
```

### Exclude Domains from Auto-Generation

```yaml
dns:
  public:
    zone:
      name: example.com.
      dane:
        enabled: true
        auto-generate: true
        exclusions:
          - legacy.example.com
          - test.example.com
```

### Per-Service Override

```yaml
dns:
  public:
    zone:
      name: example.com.
      dane:
        enabled: true
        services:
          - hostname: mail.example.com
            port: 25
            usage: 2        # DANE-TA for mail
            selector: 0     # Full certificate
            matching-type: 1
```

## Automatic TLSA Generation Workflow

When auto-generation is enabled, TLSA records are created automatically during certificate lifecycle events.

### Workflow Diagram

```
Certificate Issuance/Renewal
            |
            v
+---------------------------+
| CA Issues Certificate     |
| (Platform CA or ACME)     |
+---------------------------+
            |
            v
+---------------------------+
| Extract SPKI from Cert    |
| SHA-256(SubjectPublicKey) |
+---------------------------+
            |
            v
+---------------------------+
| Generate TLSA Record      |
| Usage=3, Selector=1,      |
| Matching=1                |
+---------------------------+
            |
            v
+---------------------------+
| Add TLSA to DNS Zone      |
| _443._tcp.hostname        |
+---------------------------+
            |
            v
+---------------------------+
| DNSSEC Sign Zone          |
| Generate RRSIG for TLSA   |
+---------------------------+
            |
            v
+---------------------------+
| Zone Published            |
| TLSA Available via DNS    |
+---------------------------+
```

### Certificate Lifecycle Integration

TLSA records are automatically managed throughout the certificate lifecycle:

| Event | TLSA Action |
|-------|-------------|
| Certificate Issued | Generate and publish TLSA record |
| Certificate Renewed (same key) | No change required |
| Certificate Renewed (new key) | Pre-publish new TLSA, then transition |
| Certificate Revoked | Remove TLSA record |

### Rollover Timing

The pre-publish strategy ensures seamless certificate transitions:

```
Time
  |
  |  Old TLSA active
  |
  |  +--- Pre-publish period starts (default 24h before cert change)
  |  |    Both old and new TLSA records published
  |  |
  |  +--- Certificate updated
  |  |    New TLSA matches new certificate
  |  |    Old TLSA still valid for cached responses
  |  |
  |  +--- TTL expiration
  |       Remove old TLSA record
  |       Only new TLSA active
  v
```

### Pre-Publish Configuration

```yaml
dns:
  dane:
    enabled: true
    auto-generate: true

    rollover:
      # Start publishing new TLSA before cert change
      prepublish-period: 86400      # 24 hours

      # Keep old TLSA after cert change
      post-publish-period: 86400    # 24 hours (> 2x TTL)

      # TLSA record TTL during rollover
      rollover-ttl: 3600            # 1 hour (shorter during transition)
```

## CLI Commands

### Generate TLSA Record

Generate a TLSA record from a certificate file:

```bash
# Generate TLSA from certificate file
platformctl dns dane generate-tlsa \
  --cert /path/to/cert.pem \
  --hostname www.example.com \
  --port 443

# Output:
# _443._tcp.www.example.com. 3600 IN TLSA 3 1 1 (
#     2B4A7C8F9D0E1A3B5C7D9E0F1A2B3C4D
#     5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B )
```

### Generate with Options

```bash
# Specify TLSA parameters
platformctl dns dane generate-tlsa \
  --cert /path/to/cert.pem \
  --hostname www.example.com \
  --port 443 \
  --usage 3 \
  --selector 1 \
  --matching-type 1 \
  --ttl 7200

# Generate from key file (SPKI only)
platformctl dns dane generate-tlsa \
  --key /path/to/key.pem \
  --hostname www.example.com \
  --port 443
```

### Auto-Generate for Zone

Generate TLSA records for all certificates in a zone:

```bash
# Auto-generate TLSA for all zone services
platformctl dns dane auto-generate --zone example.com.

# Auto-generate for specific services
platformctl dns dane auto-generate \
  --zone example.com. \
  --services 443,25,587

# Dry run to preview
platformctl dns dane auto-generate --zone example.com. --dry-run
```

### Verify TLSA Records

Verify TLSA record matches certificate:

```bash
# Verify TLSA for a hostname
platformctl dns dane verify --hostname www.example.com --port 443

# Verify against specific certificate
platformctl dns dane verify \
  --hostname www.example.com \
  --port 443 \
  --cert /path/to/cert.pem

# Verify with DNSSEC validation
platformctl dns dane verify \
  --hostname www.example.com \
  --port 443 \
  --dnssec
```

### List TLSA Records

```bash
# List all TLSA records in a zone
platformctl dns dane list --zone example.com.

# Output:
# HOSTNAME                    PORT  USAGE  SELECTOR  MATCHING  STATUS
# www.example.com            443   3      1         1         Valid
# api.example.com            443   3      1         1         Valid
# mail.example.com           25    2      1         1         Valid
# mail.example.com           587   2      1         1         Valid
```

### Add TLSA Record Manually

```bash
# Add TLSA record with hash
platformctl dns record add example.com. TLSA _443._tcp.www \
  "3 1 1 2B4A7C8F9D0E1A3B5C7D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B"

# Add TLSA from certificate
platformctl dns dane add \
  --zone example.com. \
  --hostname www \
  --port 443 \
  --cert /path/to/cert.pem
```

### Remove TLSA Record

```bash
# Remove specific TLSA record
platformctl dns dane remove \
  --zone example.com. \
  --hostname www \
  --port 443

# Remove all TLSA for a hostname
platformctl dns dane remove \
  --zone example.com. \
  --hostname www \
  --all-ports
```

## Security Considerations

### DNSSEC Required

DANE security depends entirely on DNSSEC. Without DNSSEC, TLSA records can be spoofed.

| Aspect | Requirement |
|--------|-------------|
| **Zone Signing** | Zone must be DNSSEC signed |
| **Chain of Trust** | DS record must exist at parent |
| **Validation** | Clients must validate DNSSEC |

**Enable DNSSEC before deploying DANE:**

```bash
# Enable DNSSEC for zone
platformctl dns dnssec enable example.com.

# Verify DNSSEC chain
platformctl dns dnssec verify example.com. --from-root
```

### TTL Selection

TLSA record TTL affects rollover timing and recovery from errors:

| TTL | Advantages | Disadvantages |
|-----|------------|---------------|
| Short (300-1800) | Fast rollover, quick recovery | More DNS queries |
| Medium (3600-7200) | Balanced | Standard caching |
| Long (86400+) | Reduced DNS load | Slow rollover |

**Recommended:** 3600 seconds (1 hour) for production, shorter during rollovers.

### Monitoring

Monitor DANE deployment health:

```yaml
dns:
  dane:
    monitoring:
      enabled: true
      alerts:
        # Alert when TLSA doesn't match certificate
        mismatch: true
        # Alert on certificate expiration
        expiration-threshold: 30d
        # Alert on DNSSEC validation failures
        dnssec-failures: true
```

**Monitoring Commands:**

```bash
# Check DANE health for zone
platformctl dns dane health --zone example.com.

# Monitor certificate/TLSA sync
platformctl dns dane monitor --zone example.com. --interval 1h
```

### Rollback Procedure

If TLSA deployment causes issues:

```bash
# Emergency: Remove all TLSA records for a hostname
platformctl dns dane remove \
  --zone example.com. \
  --hostname www \
  --all-ports \
  --force

# Re-sign zone
platformctl dns zone sign example.com. --force
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| TLSA mismatch | Certificate renewed with new key | Regenerate TLSA record |
| DNSSEC validation fails | DS record missing/wrong | Verify DNSSEC chain |
| Record not found | Wrong port/protocol | Check record name format |
| Connection fails | Client doesn't support DANE | Ensure TLSA is optional |

### Verification Commands

```bash
# Query TLSA record
dig TLSA _443._tcp.www.example.com @localhost -p 8053

# Query with DNSSEC validation
dig TLSA _443._tcp.www.example.com +dnssec +multi

# Verify DANE end-to-end
openssl s_client -connect www.example.com:443 -dane_tlsa_domain www.example.com

# Check certificate SPKI hash
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl sha256
```

## Related Documentation

| Document | Description |
|----------|-------------|
| [DNSSEC](dnssec.md) | DNSSEC signing and validation |
| [DNSSEC Rollover](dnssec-rollover.md) | Key rollover procedures |
| [Security](security.md) | DNS security model |
| [Configuration](configuration.md) | Complete configuration reference |
| [Records](records.md) | DNS record types |
| [CA Documentation](../ca/architecture.md) | Certificate Authority overview |

## See Also

- [RFC 6698 - DANE TLSA](https://datatracker.ietf.org/doc/html/rfc6698)
- [RFC 7671 - DANE Updates](https://datatracker.ietf.org/doc/html/rfc7671)
- [RFC 7672 - DANE for SMTP](https://datatracker.ietf.org/doc/html/rfc7672)
- [RFC 7673 - DANE for SRV](https://datatracker.ietf.org/doc/html/rfc7673)
- [RFC 8162 - DANE for S/MIME](https://datatracker.ietf.org/doc/html/rfc8162)

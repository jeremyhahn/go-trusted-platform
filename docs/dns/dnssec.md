# DNSSEC Signing

Hardware-backed DNSSEC signing integrated with the Trusted Platform.

## Overview

DNSSEC (Domain Name System Security Extensions) provides cryptographic authentication for DNS data, protecting against cache poisoning, man-in-the-middle attacks, and DNS spoofing. The Trusted Platform integrates DNSSEC signing with hardware-backed key storage via TPM, HSMs, and cloud key management services through go-quicbaas.

### Why DNSSEC Matters

| Threat | Protection |
|--------|------------|
| **Cache Poisoning** | Cryptographic signatures verify authenticity |
| **DNS Spoofing** | Clients can validate responses came from authoritative source |
| **Man-in-the-Middle** | Tampered responses fail signature verification |
| **Zone Enumeration** | NSEC3 hashes prevent walking the zone |

### Trusted Computing Integration

The Trusted Platform provides hardware-backed DNSSEC keys using TPM 2.0:

- **Key Protection** - Private keys never leave the TPM
- **Attestation** - Prove keys were generated and stored in hardware
- **Audit Trail** - All signing operations logged with TPM-signed timestamps
- **Key Hierarchy** - DNSSEC keys derived from platform primary keys

## Key Types

### KSK (Key Signing Key)

The Key Signing Key signs the DNSKEY RRset and establishes the chain of trust.

| Property | Value |
|----------|-------|
| **Purpose** | Signs the DNSKEY RRset |
| **Flags** | 257 (SEP bit set) |
| **Lifetime** | 365 days (configurable) |
| **TPM Handle** | 0x81010010 |
| **Key Usage** | Critical - requires parent DS record update on rollover |

The KSK is published to the parent zone as a DS (Delegation Signer) record.

### ZSK (Zone Signing Key)

The Zone Signing Key signs all resource records in the zone.

| Property | Value |
|----------|-------|
| **Purpose** | Signs all other RRsets |
| **Flags** | 256 |
| **Lifetime** | 30 days (configurable) |
| **TPM Handle** | 0x81010011 |
| **Key Usage** | Frequent rotation - transparent to parent zone |

The ZSK can be rotated frequently without updating the parent zone.

## Supported Algorithms

The following algorithms are supported via go-quicbaas key management:

| Algorithm | ID | Status | Notes |
|-----------|-----|--------|-------|
| ECDSAP256SHA256 | 13 | Recommended | Default algorithm, good balance of security and performance |
| ECDSAP384SHA384 | 14 | Supported | Higher security for sensitive zones |
| RSASHA256 | 8 | Supported | Legacy compatibility, larger signatures |
| RSASHA512 | 10 | Supported | Legacy compatibility, larger key sizes |
| ED25519 | 15 | Supported | Modern, compact signatures |
| ED448 | 16 | Supported | Highest security, larger signatures |

### Algorithm Selection

The DNSSEC configuration uses the platform's standard KeyConfig pattern:

```yaml
# Recommended for most deployments (ECDSAP256SHA256)
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2

# High security environments (ECDSAP384SHA384)
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-384
    signature-algorithm: ECDSA-SHA384
    hash: SHA-384
    store: tpm2

# Modern deployments (ED25519)
dnssec:
  enabled: true
  default-key:
    algorithm: Ed25519
    signature-algorithm: Ed25519
    hash: SHA-256
    store: tpm2
```

## Key Storage Backends

Keys can be stored in various backends based on security requirements:

| Backend | Use Case | Security Level |
|---------|----------|----------------|
| **Software** | Development, testing | Low |
| **TPM 2.0** | Production (recommended) | High |
| **PKCS#11** | HSMs, smart cards | High |
| **AWS KMS** | AWS deployments | High |
| **Azure Key Vault** | Azure deployments | High |
| **GCP Cloud KMS** | GCP deployments | High |
| **HashiCorp Vault** | Multi-cloud, on-premises | High |

### Tenant-Scoped Key Paths

DNSSEC keys are stored in tenant-scoped paths within the KMS to provide multi-tenant isolation:

```
dnssec/{tenant_id}/{zone_name}/{key_type}
```

| Component | Description | Example |
|-----------|-------------|---------|
| `tenant_id` | Platform or user tenant identifier | `platform`, `tenant-abc123` |
| `zone_name` | Zone name with dots replaced by hyphens | `example-com` |
| `key_type` | Key type identifier | `ksk`, `zsk` |

**Example key paths:**
- `dnssec/platform/example-com/ksk` - KSK for platform's example.com zone
- `dnssec/tenant-abc/internal-local/zsk` - ZSK for tenant-abc's internal.local zone

This ensures:
- **Isolation**: Each tenant's DNSSEC keys are stored separately
- **Authorization**: Only the owning tenant can access their zone's keys
- **Audit**: Key operations are logged with tenant context

### Backend Configuration

```yaml
dnssec:
  enabled: true
  # Default key uses TPM2
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2

  ksk:
    # Inherits default-key, or override with different store
    lifetime: 365d
    ttl: 86400

  zsk:
    # Override: Use PKCS#11 for ZSK
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: pkcs11
    lifetime: 30d
    ttl: 3600
```

## Zone Signing Process

The zone signing process follows these steps:

```
1. Generate/Retrieve Keys     2. Create DNSKEY Records
   ┌────────────────┐            ┌──────────────────┐
   │ KSK from       │            │ DNSKEY (257)     │
   │ go-quicbaas    │            │ DNSKEY (256)     │
   ├────────────────┤            └──────────────────┘
   │ ZSK from       │                     │
   │ go-quicbaas    │                     ▼
   └────────────────┘         3. Sign DNSKEY RRset
                                 ┌──────────────────┐
                                 │ RRSIG (DNSKEY)   │
                                 │ signed with KSK  │
                                 └──────────────────┘
                                          │
                                          ▼
                              4. Sign All Other RRsets
                                 ┌──────────────────┐
                                 │ RRSIG (A)        │
                                 │ RRSIG (AAAA)     │
                                 │ RRSIG (MX)       │
                                 │ signed with ZSK  │
                                 └──────────────────┘
                                          │
                                          ▼
                              5. Generate NSEC/NSEC3 Chain
                                 ┌──────────────────┐
                                 │ NSEC3 records    │
                                 │ RRSIG (NSEC3)    │
                                 └──────────────────┘
                                          │
                                          ▼
                              6. Store Signed Zone
                                 ┌──────────────────┐
                                 │ Complete zone    │
                                 │ with all RRSIG   │
                                 └──────────────────┘
```

### Signing Example

```bash
# Sign a zone
platformctl dns zone sign example.com

# Force re-sign with new signatures
platformctl dns zone sign example.com --force

# Sign with specific algorithm
platformctl dns zone sign example.com --algorithm ECDSAP384SHA384
```

## Denial of Existence

DNSSEC provides cryptographic proof that a domain name does not exist.

### NSEC

NSEC records create a sorted chain of all names in the zone:

| Property | Description |
|----------|-------------|
| **Ordering** | Canonical DNS name ordering |
| **Type Bitmap** | Lists all record types at each name |
| **Chain** | Last record points to first (circular) |
| **Proof** | Proves name falls between two existing names |

```
; NSEC chain example
alpha.example.com.  NSEC beta.example.com. A AAAA RRSIG NSEC
beta.example.com.   NSEC gamma.example.com. A MX RRSIG NSEC
gamma.example.com.  NSEC alpha.example.com. A RRSIG NSEC
```

**Limitation:** NSEC allows zone enumeration by walking the chain.

### NSEC3

NSEC3 uses hashed names to prevent zone enumeration:

| Property | Description |
|----------|-------------|
| **Hash Algorithm** | SHA-1 (mandatory per RFC 5155) |
| **Iterations** | Additional hash rounds (recommend 0-1) |
| **Salt** | Random value to prevent rainbow tables |
| **Opt-Out** | Skip unsigned delegations (large zones) |
| **FIPS** | **Unavailable.** A FIPS-activated node refuses to start — see below |

#### NSEC3 is unavailable under FIPS activation

**Plan for this before designing a zone, not after.** A node started with
`GODEBUG=fips140=only` and `nsec-mode: nsec3` **fails to start**, with
`ErrFIPSNSEC3Unsupported`. The kernel's FIPS mode alone does not set
`GODEBUG` ([FIPS mode](../fips/architecture.md)), so it does not trigger this.

This is a property of the protocol, not a gap in this implementation. RFC 5155
registers exactly one NSEC3 hash algorithm — 1, SHA-1 — so there is nothing
approved to select, and nothing can be added without a new RFC. Go's
cryptographic module refuses SHA-1 by panicking under `fips140=only`, so a FIPS
build cannot produce an NSEC3 chain at all.

Startup is where it is caught, deliberately. The alternative — a daemon that
comes up and quietly stops signing — is a state that persists unnoticed. The
error names the **mode** as the constraint: the zone is intact and the
configuration is otherwise valid.

Options for a FIPS deployment, both with real costs:

| Option | Consequence |
|---|---|
| `nsec-mode: nsec` | Signed zones work. **NSEC permits zone enumeration** — walking the chain reveals every name, which is the exact exposure NSEC3 exists to prevent. A deliberate security trade, which is why it is not applied automatically. |
| Do not activate FIPS on that node | NSEC3 works as documented; the node is outside the FIPS boundary. |

Only NSEC3 is refused. A FIPS node with `nsec-mode: nsec`, or with DNSSEC
disabled, starts normally.

```yaml
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2
  nsec-mode: nsec3
  nsec3-iterations: 1
  nsec3-salt: ""          # Empty for random salt
```

### NSEC3 vs NSEC

| Aspect | NSEC | NSEC3 |
|--------|------|-------|
| Zone Enumeration | Possible | Prevented |
| Response Size | Smaller | Larger |
| CPU Usage | Lower | Higher |
| Complexity | Simple | Complex |
| Recommendation | Internal zones | Public zones |

## DS Record Generation

The DS (Delegation Signer) record links the child zone to the parent.

### Digest Types

| Digest Type | Algorithm | Status |
|-------------|-----------|--------|
| 1 | SHA-1 | Deprecated |
| 2 | SHA-256 | Recommended |
| 4 | SHA-384 | Supported |

### Generating DS Records

```bash
# Generate DS record for submission to parent
platformctl dns dnssec show-ds example.com

# Output example:
# example.com. IN DS 12345 13 2 (
#     A1B2C3D4E5F6...  ; SHA-256 digest
# )
```

### Parent Zone Submission

1. Generate DS record using `platformctl dns dnssec show-ds`
2. Submit DS record to registrar or parent zone operator
3. Wait for propagation (check with `dig DS example.com @parent-ns`)
4. Verify chain of trust with `dig +dnssec example.com`

## Configuration

### Complete Configuration Reference

```yaml
dnssec:
  # Enable DNSSEC signing
  enabled: true

  # Default key configuration (used if KSK/ZSK don't specify their own)
  # Uses platform's standard KeyConfig pattern for algorithm specification
  default-key:
    algorithm: ECDSA           # RSA, ECDSA, or Ed25519
    ecc:
      curve: P-256             # P-256 or P-384 for ECDSA
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2                # software, tpm2, pkcs11, aws-kms, azure-kv, gcp-kms, vault

  # Signature expiry configuration
  signature-expiry: 30d

  # Denial of existence configuration
  nsec-mode: nsec3             # nsec or nsec3
  nsec3-iterations: 1          # 0-1 recommended per RFC 9276
  nsec3-salt: ""               # Empty for random salt

  # Key Signing Key configuration
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
    lifetime: 365d

    # DNSKEY record TTL
    ttl: 86400

  # Zone Signing Key configuration
  zsk:
    # Optional: Override default-key
    # key:
    #   algorithm: ECDSA
    #   ecc:
    #     curve: P-256
    #   signature-algorithm: ECDSA-SHA256
    #   hash: SHA-256
    #   store: software

    lifetime: 30d
    ttl: 3600
```

### Minimal Configuration

```yaml
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
  ksk:
    lifetime: 365d
    ttl: 86400
  zsk:
    lifetime: 30d
    ttl: 3600
```

### Per-Key Override Example

You can use different key configurations for KSK and ZSK:

```yaml
dnssec:
  enabled: true
  # Default for all keys
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2

  ksk:
    # Override: Use stronger P-384 curve for KSK
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
    # Inherits default-key (P-256)
    lifetime: 30d
    ttl: 3600
```

## CLI Commands

### Enable DNSSEC

```bash
# Enable DNSSEC for a zone
platformctl dns dnssec enable example.com

# Enable with specific algorithm
platformctl dns dnssec enable example.com --algorithm ECDSAP384SHA384
```

### Check DNSSEC Status

```bash
# Show DNSSEC status for a zone
platformctl dns dnssec status example.com

# Example output:
# Zone: example.com
# Status: SIGNED
# Algorithm: ECDSAP256SHA256 (13)
# KSK:
#   Key Tag: 12345
#   Created: 2024-01-15T00:00:00Z
#   Expires: 2025-01-15T00:00:00Z
#   Store: tpm2
# ZSK:
#   Key Tag: 54321
#   Created: 2024-06-01T00:00:00Z
#   Expires: 2024-07-01T00:00:00Z
#   Store: tpm2
# Signatures:
#   Valid Until: 2024-06-15T00:00:00Z
#   Next Refresh: 2024-06-08T00:00:00Z
```

### Key Management

```bash
# Generate new KSK
platformctl dns dnssec generate-ksk example.com

# Generate new ZSK
platformctl dns dnssec generate-zsk example.com

# List all DNSSEC keys
platformctl dns dnssec keys example.com

# Export public key (DNSKEY record)
platformctl dns dnssec export-key example.com --key-tag 12345
```

### DS Record

```bash
# Show DS record for parent zone submission
platformctl dns dnssec show-ds example.com

# Show DS record with specific digest type
platformctl dns dnssec show-ds example.com --digest-type 2
```

### Zone Signing

```bash
# Sign zone (or re-sign if already signed)
platformctl dns zone sign example.com

# Force complete re-sign
platformctl dns zone sign example.com --force

# Sign with fresh timestamps
platformctl dns zone sign example.com --refresh
```

### Disable DNSSEC

```bash
# Disable DNSSEC (removes signatures, keeps keys)
platformctl dns dnssec disable example.com

# Disable and remove keys
platformctl dns dnssec disable example.com --remove-keys
```

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **KMS** | Key storage, rotation policies |
| **TPM** | Hardware-backed key protection |
| **CA** | DANE/TLSA record generation |
| **IAM** | Access control for zone signing |
| **Audit** | Signing operation logging |

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Chain of trust broken | DS record missing/wrong | Re-submit DS to parent |
| Signatures expired | Auto-sign failed | Check logs, manual re-sign |
| SERVFAIL responses | Invalid signatures | Verify zone is properly signed |
| Key not found | TPM handle mismatch | Check handle configuration |

### Verification Commands

```bash
# Verify DNSSEC chain from root
dig +dnssec +trace example.com

# Check specific DNSKEY
dig DNSKEY example.com @ns1.example.com

# Verify DS record at parent
dig DS example.com @parent-ns.tld

# Test with DNSSEC validator
delv @ns1.example.com example.com
```

## Related Documentation

| Document | Description |
|----------|-------------|
| [Key Rollover](dnssec-rollover.md) | KSK and ZSK rollover procedures |
| [Security](security.md) | DNS security model |
| [Configuration](configuration.md) | Complete configuration reference |
| [Architecture](architecture.md) | DNS system architecture |
| [Zones](zones.md) | Zone management |

## See Also

- [RFC 4033 - DNS Security Introduction](https://datatracker.ietf.org/doc/html/rfc4033)
- [RFC 4034 - Resource Records for DNSSEC](https://datatracker.ietf.org/doc/html/rfc4034)
- [RFC 4035 - Protocol Modifications for DNSSEC](https://datatracker.ietf.org/doc/html/rfc4035)
- [RFC 5155 - NSEC3](https://datatracker.ietf.org/doc/html/rfc5155)
- [RFC 9276 - NSEC3 Guidance](https://datatracker.ietf.org/doc/html/rfc9276)
- [KMS Documentation](../kms/architecture.md)
- [TPM Documentation](../tpm/README.md)

# DNSSEC Signing

> **Status: REFERENCE** · Last verified: 2026-10-15
> DNSSEC zone signing in `pkg/dns`, with keys held in the go-quicbaas KMS.

## Overview

DNSSEC (Domain Name System Security Extensions) provides cryptographic authentication for DNS data, protecting against cache poisoning, man-in-the-middle attacks, and DNS spoofing. The Trusted Platform signs zones in `pkg/dns`; the private keys are generated and held by the go-quicbaas KMS (`dns.NewQuicBaaSKMSKeyStore`, wired at `pkg/app/app.go:1179`).

### Why DNSSEC Matters

| Threat | Protection |
|--------|------------|
| **Cache Poisoning** | Cryptographic signatures verify authenticity |
| **DNS Spoofing** | Clients can validate responses came from authoritative source |
| **Man-in-the-Middle** | Tampered responses fail signature verification |
| **Zone Enumeration** | NSEC3 hashes prevent walking the zone |

### Key Custody

- **Generation and storage** - the KSK and ZSK are generated through the go-quicbaas SDK KMS on the first signing of a zone, then loaded from it
- **Store** - the SDK keystore creates DNSSEC keys in the software store (`xkmssdk.StoreSoftware`, `pkg/dns/dnssec_keystore_sdk.go:202`); `pkg/dns` does not read the `store:` field of a key configuration
- **Tenant scope** - every key ID carries the zone's tenant (see [Tenant-Scoped Key IDs](#tenant-scoped-key-ids))

## Key Types

### KSK (Key Signing Key)

The Key Signing Key signs the DNSKEY RRset and establishes the chain of trust.

| Property | Value |
|----------|-------|
| **Purpose** | Signs the DNSKEY RRset |
| **Flags** | 257 (SEP bit set) |
| **Lifetime** | `ksk.lifetime` must be a positive duration (`365d`, `720h`), else startup fails with `ErrInvalidKeyLifetime`; nothing acts on it: there is no automatic rollover |
| **Key Usage** | Critical - requires parent DS record update on rollover |

The KSK is published to the parent zone as a DS (Delegation Signer) record.

### ZSK (Zone Signing Key)

The Zone Signing Key signs all resource records in the zone.

| Property | Value |
|----------|-------|
| **Purpose** | Signs all other RRsets |
| **Flags** | 256 |
| **Lifetime** | `zsk.lifetime` must be a positive duration (`365d`, `720h`), else startup fails with `ErrInvalidKeyLifetime`; nothing acts on it: there is no automatic rollover |
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
| ED448 | 16 | Not supported | An unrecognised algorithm falls back to ECDSAP256SHA256 |

### Algorithm Selection

The DNSSEC configuration uses the platform's standard KeyConfig pattern. The
algorithm number is derived from it (`keyConfigToDNSSECAlgorithm`,
`pkg/dns/dnssec.go:883`):

| KeyConfig | DNSSEC algorithm |
|-----------|------------------|
| `RSA`, `signature-algorithm` containing SHA512 | RSASHA512 (10) |
| `RSA`, any other `signature-algorithm` | RSASHA256 (8) |
| `ECDSA`, curve P-384 | ECDSAP384SHA384 (14) |
| `ECDSA`, any other curve | ECDSAP256SHA256 (13) |
| `Ed25519` | ED25519 (15) |
| anything else, or no key configured | ECDSAP256SHA256 (13) |


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

# High security environments (ECDSAP384SHA384)
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-384
    signature-algorithm: ECDSA-SHA384
    hash: SHA-384

# Modern deployments (ED25519)
dnssec:
  enabled: true
  default-key:
    algorithm: Ed25519
    signature-algorithm: Ed25519
    hash: SHA-256
```

## Key Storage

DNSSEC keys are created through the go-quicbaas SDK KMS in its software
store (see [Key Custody](#key-custody)). The backend is not selectable from
the `dnssec:` configuration.

### Tenant-Scoped Key IDs

DNSSEC keys are stored under tenant-scoped IDs within the KMS to provide multi-tenant isolation (`pkg/dns/dnssec_keystore.go:108`):

```
dnssec_{tenant_id}_{zone_name}_{key_type}
```

| Component | Description | Example |
|-----------|-------------|---------|
| `tenant_id` | Platform or user tenant identifier | `platform`, `tenant-abc123` |
| `zone_name` | Zone name, trailing dot trimmed, dots replaced by hyphens | `example-com` |
| `key_type` | Key type identifier | `ksk`, `zsk` |

**Example key IDs:**
- `dnssec_platform_example-com_ksk` - KSK for platform's example.com zone
- `dnssec_tenant-abc_internal-local_zsk` - ZSK for tenant-abc's internal.local zone

This ensures:
- **Isolation**: Each tenant's DNSSEC keys are stored separately
- **Authorization**: Only the owning tenant can access their zone's keys
- **Audit**: Key operations are logged with tenant context

### Key Configuration

```yaml
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256

  ksk:
    ttl: 86400      # DNSKEY TTL

  zsk:
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
                              6. Generate DS (SHA-256)
                                 ┌──────────────────┐
                                 │ DS for the KSK,  │
                                 │ stored in zone   │
                                 └──────────────────┘
```

Each run clears the zone's DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM and DS
records and regenerates them (`DNSSECService.SignZone`, `pkg/dns/dnssec.go:294`).
Keys are generated on first use and reused afterwards. With `dnssec.enabled`,
every zone save signs the zone (`Service.Save`, `pkg/dns/service.go:195`).

### Signing Example

There is no `platformctl dns` command group ([CLI](cli.md)). Sign through the
REST or gRPC API:

```bash
# Sign a zone and save it; the response is the signed zone
curl -X POST https://<host>:8443/api/v1/dns/zones/example.com/sign
```

The gRPC equivalent is `DNSService.SignZone`. Signing with DNSSEC disabled
fails with `ErrDNSSECNotEnabled`.

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
| **Salt** | The `nsec3-salt` value as configured; empty means no salt (`pkg/dns/dnssec.go:712`) |
| **Opt-Out** | Not used: the NSEC3 flags are 0, so every name is covered |
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
  nsec-mode: nsec3
  nsec3-iterations: 1
  nsec3-salt: ""          # Empty means no salt
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

### Digest Type

Each signing run generates one DS record for the KSK with digest type 2,
SHA-256 (`GenerateDS`, `pkg/dns/dnssec.go:426`), and stores it in the zone.

### Reading DS Records

```bash
# The ds_records field holds the DS record(s) for submission to the parent
curl https://<host>:8443/api/v1/dns/zones/example.com/dnssec
```

The response carries `enabled`, `zone_signed`, `keys` (DNSKEY) and
`ds_records`. The gRPC equivalent is `DNSService.GetDNSSECStatus`.

### Parent Zone Submission

1. Read the DS record from `GET /api/v1/dns/zones/{zone}/dnssec`
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

  # Signature expiry configuration
  signature-expiry: 30d

  # Denial of existence configuration
  nsec-mode: nsec3             # nsec or nsec3
  nsec3-iterations: 1          # 0-1 recommended per RFC 9276
  nsec3-salt: ""               # Empty means no salt

  # Key Signing Key configuration
  ksk:
    # Optional: Override default-key with different key config
    # key:
    #   algorithm: ECDSA
    #   ecc:
    #     curve: P-384
    #   signature-algorithm: ECDSA-SHA384
    #   hash: SHA-384

    # Parsed but not read: there is no automatic rollover
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
  signature-expiry: 30d
  nsec-mode: nsec3
  nsec3-iterations: 1
```

### Algorithm Precedence

A zone uses one algorithm for both keys. It is taken from the first of: the
zone's own KSK key config, its ZSK key config, the global `ksk.key`, the
global `zsk.key`, then `default-key` (`getAlgorithmForZone`,
`pkg/dns/dnssec.go:961`). Setting `ksk.key` to P-384, as below, makes **both**
keys ECDSAP384SHA384:

```yaml
dnssec:
  enabled: true
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256

  ksk:
    key:
      algorithm: ECDSA
      ecc:
        curve: P-384
      signature-algorithm: ECDSA-SHA384
      hash: SHA-384
    ttl: 86400

  zsk:
    ttl: 3600
```

## Signing and Status Without a CLI

DNSSEC is switched on for the whole server by `dnssec.enabled`; there is no
per-zone enable or disable. The API surface is:

| Operation | REST | gRPC |
|-----------|------|------|
| Sign a zone | `POST /api/v1/dns/zones/{zone}/sign` | `DNSService.SignZone` |
| DNSSEC status, DNSKEY and DS records | `GET /api/v1/dns/zones/{zone}/dnssec` | `DNSService.GetDNSSECStatus` |

See [api-reference-rest.md](api-reference-rest.md).

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **KMS** | Key generation and storage through the go-quicbaas SDK |
| **CA** | DANE/TLSA record generation |
| **IAM** | Access control for zone signing |
| **Logging** | Signing logged with tenant and zone |

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Chain of trust broken | DS record missing/wrong | Re-submit DS to parent |
| Signatures expired | Zone not re-signed within `signature-expiry` (default 30d) | Save the zone or `POST .../sign` |
| SERVFAIL responses | Invalid signatures | Verify zone is properly signed |
| `KSK validation failed (stale keys from previous install? ...)` | Keys left from an earlier install | Clean the data directory and retry |

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

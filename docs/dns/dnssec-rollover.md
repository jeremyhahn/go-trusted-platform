# DNSSEC Key Rollover

## Overview

DNSSEC key rollover is the process of replacing cryptographic keys used to sign DNS zones while maintaining the chain of trust. Proper key rollover is essential for:

- **Key Hygiene**: Regular rotation limits exposure from key compromise
- **Algorithm Agility**: Enables migration to stronger algorithms
- **Compliance**: Meets security policy requirements for key lifetimes
- **Operational Resilience**: Ensures continuity if keys become unavailable

### Hybrid Approach: TPM Attestation + RFC 2136 DNS UPDATE

Trusted Platform implements a hybrid rollover architecture that combines:

| Component | Purpose |
|-----------|---------|
| **TPM Attestation** | Proves platform integrity before authorizing key operations |
| **RFC 2136 DNS UPDATE** | Standard protocol for dynamic zone updates to parent nameservers |
| **Platform Coordinator** | Validates attestation evidence and issues time-limited credentials |
| **Hardware-Bound Keys** | DNSSEC keys never leave the TPM, preventing exfiltration |

This approach ensures that key rollovers only occur on platforms with verified secure boot state and measured integrity.

## Key State Machine

DNSSEC keys transition through well-defined states during their lifecycle:

```
generated --> pending_introduction --> published --> active --> retiring --> hidden --> deleted
```

### State Definitions

| State | Description | Zone Presence |
|-------|-------------|---------------|
| `generated` | Key material created in TPM, not yet used | Not in zone |
| `pending_introduction` | Awaiting propagation delay before publication | Not in zone |
| `published` | DNSKEY record published, not signing | In DNSKEY RRset |
| `active` | Key is actively signing records | In DNSKEY RRset, creating RRSIGs |
| `retiring` | Old key still published, new key signing | In DNSKEY RRset, not signing |
| `hidden` | DNSKEY removed, signatures may still exist | Not in zone |
| `deleted` | Key material destroyed | Not in zone |

### State Transitions

```
                                               ┌─────────┐
                                               │ deleted │
                                               └─────────┘
                                                    ▲
                                                    │
┌───────────┐    ┌──────────────────────┐    ┌───────────┐    ┌────────┐    ┌──────────┐
│ generated │───▶│ pending_introduction │───▶│ published │───▶│ active │───▶│ retiring │
└───────────┘    └──────────────────────┘    └───────────┘    └────────┘    └──────────┘
                                                                                 │
                                                                                 ▼
                                                                           ┌────────┐
                                                                           │ hidden │
                                                                           └────────┘
```

## ZSK Rollover (Pre-Publication Method)

Zone Signing Keys (ZSK) are rotated using the pre-publication method, which minimizes zone size increase by publishing the new key before it becomes active.

### Timeline

| Phase | Time | Old Key State | New Key State | Zone Change |
|-------|------|---------------|---------------|-------------|
| T0 | 30d before expiry | active | generated | Generate new ZSK in TPM |
| T1 | T0 + propagation | active | published | Publish new DNSKEY |
| T2 | T1 + propagation | retiring | active | New ZSK signs all RRsets |
| T3 | T2 + signature lifetime | hidden | active | Remove old DNSKEY |
| T4 | T3 + cleanup | deleted | active | Delete old key material |

### Timing Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Key generation lead time | 30 days | How early to generate the new key |
| Propagation delay | 1 hour | Minimum time between zone changes |
| Signature validity | 14 days | RRSIG validity period |
| Total rollover duration | ~48 hours | End-to-end process time |

### Pre-Publication Process

```
Phase T0: Generate New ZSK
┌───────────────────┐     ┌───────────────────┐
│  Old ZSK (256)    │     │  New ZSK (256)    │
│  State: active    │     │  State: generated │
│  Signing: YES     │     │  Signing: NO      │
└───────────────────┘     └───────────────────┘

Phase T1: Publish New DNSKEY
┌───────────────────┐     ┌───────────────────┐
│  Old ZSK (256)    │     │  New ZSK (256)    │
│  State: active    │     │  State: published │
│  Signing: YES     │     │  Signing: NO      │
└───────────────────┘     └───────────────────┘
Zone DNSKEY RRset: [Old ZSK, New ZSK, KSK]

Phase T2: Activate New ZSK
┌───────────────────┐     ┌───────────────────┐
│  Old ZSK (256)    │     │  New ZSK (256)    │
│  State: retiring  │     │  State: active    │
│  Signing: NO      │     │  Signing: YES     │
└───────────────────┘     └───────────────────┘
Zone DNSKEY RRset: [Old ZSK, New ZSK, KSK]

Phase T3: Remove Old DNSKEY
┌───────────────────┐     ┌───────────────────┐
│  Old ZSK (256)    │     │  New ZSK (256)    │
│  State: hidden    │     │  State: active    │
│  Signing: NO      │     │  Signing: YES     │
└───────────────────┘     └───────────────────┘
Zone DNSKEY RRset: [New ZSK, KSK]

Phase T4: Delete Old Key Material
                          ┌───────────────────┐
                          │  New ZSK (256)    │
                          │  State: active    │
                          │  Signing: YES     │
                          └───────────────────┘
```

## KSK Rollover (Double-DS Method)

Key Signing Keys (KSK) require coordination with the parent zone. Trusted Platform uses the Double-DS method for maximum safety.

### Process

1. **Generate new KSK**: Create new key material in TPM
2. **Request TPM attestation**: Prove platform integrity to coordinator
3. **Submit new DS to parent**: Send DS record via RFC 2136 UPDATE with TSIG authentication
4. **Wait for DS propagation**: Verify new DS is visible via DNS queries
5. **Publish new DNSKEY**: Add new KSK to zone, sign DNSKEY RRset with both keys
6. **Remove old DS from parent**: Send DELETE for old DS record
7. **Remove old DNSKEY**: Remove old KSK from zone
8. **Delete old key material**: Destroy old key in TPM

### Timeline

| Phase | Time | Action | Parent Zone | Local Zone |
|-------|------|--------|-------------|------------|
| K0 | 60d before expiry | Generate new KSK | - | New key in TPM |
| K1 | K0 + attestation | Submit new DS | DS(new) added | No change |
| K2 | K1 + TTL | Verify DS propagation | DS(old), DS(new) | No change |
| K3 | K2 + propagation | Publish new DNSKEY | DS(old), DS(new) | DNSKEY(new) added |
| K4 | K3 + TTL | Sign with new KSK | DS(old), DS(new) | New KSK signs |
| K5 | K4 + propagation | Remove old DS | DS(new) only | No change |
| K6 | K5 + TTL | Remove old DNSKEY | DS(new) only | DNSKEY(old) removed |
| K7 | K6 + cleanup | Delete old key | DS(new) only | Key material deleted |

### Timing Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Key generation lead time | 60 days | How early to generate the new key |
| DS propagation check interval | 5 minutes | How often to verify DS visibility |
| DS propagation timeout | 1 hour | Maximum wait for DS propagation |
| Total rollover duration | 24-48 hours | End-to-end process time |

### Double-DS State Diagram

```
Parent Zone DS Records                    Child Zone DNSKEY
┌────────────────────────┐                ┌────────────────────────┐
│ Phase K1-K2            │                │ Phase K1-K2            │
│  DS(old_KSK)           │                │  DNSKEY(old_KSK)       │
│  DS(new_KSK)           │                │                        │
└────────────────────────┘                └────────────────────────┘
            │                                         │
            ▼                                         ▼
┌────────────────────────┐                ┌────────────────────────┐
│ Phase K3-K4            │                │ Phase K3-K4            │
│  DS(old_KSK)           │                │  DNSKEY(old_KSK)       │
│  DS(new_KSK)           │                │  DNSKEY(new_KSK)       │
└────────────────────────┘                └────────────────────────┘
            │                                         │
            ▼                                         ▼
┌────────────────────────┐                ┌────────────────────────┐
│ Phase K5-K6            │                │ Phase K5-K6            │
│  DS(new_KSK)           │                │  DNSKEY(old_KSK)       │
│                        │                │  DNSKEY(new_KSK)       │
└────────────────────────┘                └────────────────────────┘
            │                                         │
            ▼                                         ▼
┌────────────────────────┐                ┌────────────────────────┐
│ Phase K7 (Complete)    │                │ Phase K7 (Complete)    │
│  DS(new_KSK)           │                │  DNSKEY(new_KSK)       │
└────────────────────────┘                └────────────────────────┘
```

## TPM-Attested Rollover Protocol

The attestation protocol ensures key operations only occur on verified platforms.

### Flow Diagram

```
Platform Node              Coordinator              Parent NS
     |                          |                       |
     | 1. POST /dnssec/rollover |                       |
     |------------------------->|                       |
     |                          |                       |
     | 2. Challenge (nonce)     |                       |
     |<-------------------------|                       |
     |                          |                       |
     | 3. TPM Quote + pubkey    |                       |
     |------------------------->|                       |
     |                          |                       |
     |            4. Verify quote, PCRs, EK             |
     |                          |                       |
     | 5. Credential blob       |                       |
     |<-------------------------|                       |
     |                          |                       |
     | 6. TPM ActivateCredential|                       |
     |------------------------->|                       |
     |                          |                       |
     | 7. Time-limited TSIG     |                       |
     |<-------------------------|                       |
     |                          |                       |
     | 8. DNS UPDATE + TSIG     |                       |
     |----------------------------------------------->  |
     |                          |     9. Verify, apply  |
     |                          |                       |
     | 10. RCODE: NOERROR       |                       |
     |<-----------------------------------------------|
```

### Protocol Steps

| Step | Actor | Action | Security Property |
|------|-------|--------|-------------------|
| 1 | Platform | Initiate rollover request | Authenticated via mTLS |
| 2 | Coordinator | Issue fresh nonce | Replay prevention |
| 3 | Platform | Generate TPM quote over PCRs | Platform identity proof |
| 4 | Coordinator | Verify EK, quote signature, PCR values | Attestation validation |
| 5 | Coordinator | Create MakeCredential blob | TPM binding |
| 6 | Platform | Decrypt via ActivateCredential | Proves TPM possession |
| 7 | Coordinator | Issue TSIG key with 10-minute validity | Time-bounded authorization |
| 8 | Platform | Send RFC 2136 UPDATE with TSIG | Authenticated zone update |
| 9 | Parent NS | Verify TSIG, apply update | Standard DNS security |
| 10 | Parent NS | Return success/failure | Operation confirmation |

### TPM Key Protection

| Key | TPM Handle | PCR Policy | Purpose |
|-----|------------|------------|---------|
| KSK | 0x81010010 | 0,7,8,9 | Sign DNSKEY RRset |
| ZSK | 0x81010011 | 0,7,8,9 | Sign other RRsets |
| TSIG | Sealed blob | 0,7,8,9 | DNS UPDATE authentication |

### PCR Policy Meaning

| PCR | Measurement | Security Guarantee |
|-----|-------------|-------------------|
| PCR 0 | BIOS/UEFI code | Firmware integrity |
| PCR 7 | Secure Boot policy | Boot chain validation |
| PCR 8 | Kernel command line | Boot parameters unchanged |
| PCR 9 | initrd measurements | Initial ramdisk integrity |

### Credential Activation Flow

```
Coordinator                                  Platform TPM
     │                                            │
     │ MakeCredential(EK_pub, nonce, secret)      │
     │───────────────────────────────────────────▶│
     │                                            │
     │           Credential blob                  │
     │◀───────────────────────────────────────────│
     │                                            │
     │           Send blob to platform            │
     │───────────────────────────────────────────▶│
     │                                            │
     │         ActivateCredential(AK, EK, blob)   │
     │                                    ┌───────────────┐
     │                                    │ Decrypt only  │
     │                                    │ if PCR policy │
     │                                    │ satisfied     │
     │                                    └───────────────┘
     │                                            │
     │           Return secret (TSIG key)         │
     │◀───────────────────────────────────────────│
```

## Security Benefits

| Benefit | Description |
|---------|-------------|
| **Platform Integrity** | TPM quote proves secure boot and measured launch |
| **Key Protection** | DNSSEC keys are TPM-resident, never exposed in memory |
| **Time-Limited Auth** | TSIG credentials valid 5-15 minutes, limiting replay window |
| **Audit Trail** | All attestation evidence logged for forensic analysis |
| **Graceful Fallback** | Cached signatures remain valid if TPM temporarily unavailable |
| **Non-Exportable Keys** | TPM keys cannot be extracted, even with root access |
| **Hardware Binding** | Keys tied to specific platform via EK |

### Threat Model Coverage

| Threat | Mitigation |
|--------|------------|
| Key exfiltration | Keys never leave TPM |
| Unauthorized rollover | Requires valid attestation |
| Replay attack | Fresh nonce in each attestation |
| Compromised platform | PCR policy detects tampering |
| TSIG theft | Short validity window |
| Man-in-the-middle | mTLS for coordinator communication |

## Configuration

### Full Configuration Reference

```yaml
dnssec:
  enabled: true

  # Default key configuration (uses platform KeyConfig pattern)
  default-key:
    algorithm: ECDSA           # RSA, ECDSA, or Ed25519
    ecc:
      curve: P-256             # P-256 or P-384 for ECDSA
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2

  signature-expiry: 30d
  nsec-mode: nsec3
  nsec3-iterations: 1
  nsec3-salt: ""

  ksk:
    # Optional: Override default-key for KSK
    # key:
    #   algorithm: ECDSA
    #   ecc:
    #     curve: P-384
    #   signature-algorithm: ECDSA-SHA384
    #   hash: SHA-384
    #   store: tpm2
    lifetime: 365d
    ttl: 86400

  zsk:
    # Inherits default-key
    lifetime: 30d
    ttl: 3600
```

### Minimal Configuration

```yaml
dnssec:
  rollover:
    enabled: true
    check-interval: 1h
    propagation-delay: 1h
    zsk-lifetime: 30d
    ksk-lifetime: 365d
    tpm:
      pcr-policy: [0, 7, 8, 9]
      tsig-validity: 10m
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DNSSEC_ROLLOVER_ENABLED` | Enable automatic rollover | `true` |
| `DNSSEC_ZSK_LIFETIME` | ZSK validity period | `30d` |
| `DNSSEC_KSK_LIFETIME` | KSK validity period | `365d` |
| `DNSSEC_TPM_PCR_POLICY` | PCR indices for policy | `0,7,8,9` |

## Scheduler Integration

The rollover scheduler integrates with the platform's unified task scheduler.

### Scheduler Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                     Unified Platform Scheduler                        │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐  │
│   │ ACME Renewals   │    │ DNSSEC Rollovers │    │ CA Operations   │  │
│   │ • Cert expiry   │    │ • ZSK rotation   │    │ • CRL refresh   │  │
│   │ • Challenge     │    │ • KSK rotation   │    │ • OCSP update   │  │
│   └─────────────────┘    └──────────────────┘    └─────────────────┘  │
│                                                                       │
│   Scheduler Tasks:                                                    │
│   • Daily key expiry check (midnight UTC)                             │
│   • Hourly propagation monitoring during rollover                     │
│   • On-demand emergency rollover support                              │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Scheduled Tasks

| Task | Schedule | Description |
|------|----------|-------------|
| Key expiry check | Daily at 00:00 UTC | Scan all zones for expiring keys |
| ZSK rollover initiation | As needed | Start ZSK rotation 30d before expiry |
| KSK rollover initiation | As needed | Start KSK rotation 60d before expiry |
| Propagation check | Every 5 minutes during rollover | Verify DS/DNSKEY propagation |
| Signature refresh | Daily | Re-sign RRsets approaching expiry |

### Task State Persistence

Rollover state is persisted to survive restarts:

```
__dnssec:zone:{zone_id}:rollover:state       -> Current rollover state
__dnssec:zone:{zone_id}:rollover:started     -> Rollover start timestamp
__dnssec:zone:{zone_id}:rollover:phase       -> Current phase (T0-T4 or K0-K7)
__dnssec:zone:{zone_id}:key:{key_id}:state   -> Individual key state
```

## CLI Commands

### Key Status

```bash
# Show DNSSEC key status for a zone
platformctl dns dnssec status example.com.

# Output:
# Zone: example.com.
# DNSSEC: enabled
# Algorithm: ECDSAP256SHA256
#
# Keys:
#   KSK (key-tag: 12345)
#     State: active
#     Created: 2024-01-15T00:00:00Z
#     Expires: 2025-01-15T00:00:00Z
#     TPM Handle: 0x81010010
#
#   ZSK (key-tag: 54321)
#     State: active
#     Created: 2024-11-01T00:00:00Z
#     Expires: 2024-12-01T00:00:00Z
#     TPM Handle: 0x81010011
#
# Next scheduled rollover:
#   ZSK: 2024-11-15T00:00:00Z (in 14 days)
```

### Manual Rollover

```bash
# Initiate KSK rollover
platformctl dns dnssec rotate-ksk example.com.

# Initiate ZSK rollover
platformctl dns dnssec rotate-zsk example.com.

# Options:
#   --force         Skip confirmation prompt
#   --emergency     Immediate rollover (skip propagation delays)
#   --dry-run       Show what would happen without executing
```

### Rollover Monitoring

```bash
# Monitor ongoing rollover
platformctl dns dnssec rollover-status example.com.

# Output:
# Zone: example.com.
# Rollover: ZSK (in progress)
# Phase: T2 (activating new key)
# Started: 2024-11-15T00:00:00Z
# Progress: 60%
#
# Timeline:
#   [DONE] T0: Generated new ZSK (key-tag: 98765)
#   [DONE] T1: Published new DNSKEY
#   [NOW]  T2: Switching to new ZSK
#   [ ]    T3: Remove old DNSKEY
#   [ ]    T4: Delete old key material
```

### Emergency Operations

```bash
# Emergency key revocation
platformctl dns dnssec revoke-key example.com. --key-tag 12345

# Cancel in-progress rollover
platformctl dns dnssec cancel-rollover example.com.

# Force re-sign zone
platformctl dns dnssec resign example.com.
```

## Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Attestation failure | PCR mismatch | Verify secure boot, check PCR values |
| DS propagation timeout | Parent NS not updating | Check RFC 2136 connectivity, TSIG key |
| TPM key unavailable | PCR policy failure | Platform integrity compromised, investigate |
| RRSIG validation failure | Clock skew | Synchronize NTP, check signature validity |

### Diagnostic Commands

```bash
# Check TPM key availability
platformctl tpm key status 0x81010010

# Verify PCR values
platformctl tpm pcr read 0 7 8 9

# Test attestation
platformctl tpm quote --pcrs 0,7,8,9

# Validate DNSSEC chain
dig +dnssec +cd example.com. DNSKEY
dig +dnssec example.com. DS @parent-ns.
```

### Log Analysis

Key rollover events are logged with structured fields:

```json
{
  "level": "info",
  "component": "dnssec-rollover",
  "zone": "example.com.",
  "key_type": "ZSK",
  "key_tag": 54321,
  "phase": "T2",
  "action": "activate_new_key",
  "timestamp": "2024-11-15T12:00:00Z"
}
```

## See Also

- [DNSSEC Overview](dnssec.md) - DNSSEC signing and validation
- [Dynamic DNS](dynamic-dns.md) - RFC 2136 dynamic updates
- [Architecture](architecture.md) - DNS system architecture
- [TPM Documentation](../tpm/README.md) - TPM integration details
- [KMS Documentation](../kms/README.md) - Key management service

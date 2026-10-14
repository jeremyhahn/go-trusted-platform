# DNS Security

## Overview

The Trusted Platform DNS module implements a security-first design with defense in depth, leveraging trusted computing capabilities for hardware-backed protection of cryptographic keys and operations.

### Security Principles

| Principle | Implementation |
|-----------|----------------|
| **Defense in Depth** | Multiple security layers from network to cryptographic |
| **Zero Trust** | All queries validated, no implicit trust |
| **Hardware Root of Trust** | TPM-backed key protection |
| **Least Privilege** | Fine-grained access control per zone/operation |
| **Audit Everything** | Comprehensive security event logging |

### Threat Landscape

DNS is a critical infrastructure component targeted by various attack vectors:

- Cache poisoning and DNS spoofing
- Zone enumeration and reconnaissance
- Unauthorized zone modifications
- Key compromise and signature forgery
- Denial of service attacks
- Man-in-the-middle attacks

## TPM Integration

The Trusted Platform integrates TPM 2.0 for hardware-backed security of DNSSEC keys and TSIG secrets.

### Key Protection

All DNSSEC keys are stored within the TPM with the following protections:

| Protection | Description |
|------------|-------------|
| **Hardware Isolation** | Private keys never leave TPM in plaintext |
| **Non-Exportable** | Keys bound to specific TPM instance |
| **PCR Sealing** | Access requires correct platform state |
| **Attestation** | Cryptographic proof of key properties |

### TPM Key Handles

| Key | Handle | Purpose |
|-----|--------|---------|
| KSK | 0x81010010 | Signs DNSKEY RRset, establishes chain of trust |
| ZSK | 0x81010011 | Signs all other RRsets in the zone |
| TSIG | Sealed blob | DDNS authentication secrets |

### PCR Policy

Keys are sealed to Platform Configuration Registers (PCRs) to ensure they are only accessible when the system is in a known-good state:

| PCR | Measurement | Purpose |
|-----|-------------|---------|
| 0 | BIOS/UEFI firmware | Boot integrity verification |
| 7 | Secure Boot policy | Boot configuration state |
| 8 | Kernel command line | Boot parameters validation |
| 9 | initrd hash | Initial ramdisk integrity |

**Policy Configuration:**

```yaml
dnssec:
  ksk:
    store: tpm2
    tpm:
      handle: 0x81010010
      hierarchy: owner
      pcrs: [0, 7, 8, 9]
  zsk:
    store: tpm2
    tpm:
      handle: 0x81010011
      hierarchy: owner
      pcrs: [0, 7, 8, 9]
```

### TPM Attestation

The platform uses TPM attestation for enhanced security:

| Feature | Description |
|---------|-------------|
| **Quote Verification** | Verify platform state before key operations |
| **Credential Activation** | Authenticate DDNS update requests |
| **Time-Limited TSIG** | Generate short-lived TSIG tokens for updates |

**Attestation Workflow:**

```
Device                      Attestation Service                TPM
   │                               │                            │
   │ 1. Request TSIG token         │                            │
   │──────────────────────────────▶│                            │
   │                               │                            │
   │                               │ 2. Generate nonce          │
   │                               │───────────────────────────▶│
   │                               │                            │
   │                               │ 3. Quote (PCRs + nonce)    │
   │                               │◀───────────────────────────│
   │                               │                            │
   │                               │ 4. Verify quote against    │
   │                               │    expected PCR values     │
   │                               │                            │
   │                               │ 5. Unseal TSIG secret      │
   │                               │───────────────────────────▶│
   │                               │                            │
   │                               │ 6. Generate time-limited   │
   │                               │    TSIG token (1h validity)│
   │                               │                            │
   │ 7. TSIG token                 │                            │
   │◀──────────────────────────────│                            │
```

## Attestation-Gated DNS Updates

For high-security zones, the platform supports TPM attestation-gated DNS updates that require devices to prove platform integrity before modifications are accepted.

| Security Feature | Description |
|------------------|-------------|
| **Per-zone attestation policy** | Enable attestation requirements on individual zones |
| **PCR validation** | Verify device boot state matches expected configuration before accepting updates |
| **Time-limited tokens** | Short-lived attestation tokens prevent replay attacks |
| **Device binding** | EK fingerprint ties updates to specific authorized devices |

This provides defense-in-depth beyond TSIG authentication by cryptographically proving the requesting device is in a known-good state.

See [Dynamic DNS - Attestation-Gated Updates](dynamic-dns.md#attestation-gated-updates) for complete configuration details.

## Access Control

### Zone-Level Permissions

DNS operations are controlled through fine-grained permissions:

| Permission | Description |
|------------|-------------|
| `dns:zone:read` | View zone configuration and records |
| `dns:zone:write` | Create and modify zones |
| `dns:zone:delete` | Remove zones |
| `dns:record:read` | View DNS records |
| `dns:record:write` | Create and modify records |
| `dns:record:delete` | Remove records |
| `dns:dnssec:sign` | Sign zones with DNSSEC |
| `dns:dnssec:manage` | Manage DNSSEC keys and configuration |

### IAM Integration

DNS access is managed through the platform's IAM system:

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: dns-admin
  tenant: acme-corp
  description: Full DNS administrative access

spec:
  subjects:
    roles: [dns-admin]

  rules:
    - name: full-dns-access
      effect: allow
      actions:
        - dns:zone:*
        - dns:record:*
        - dns:dnssec:*
      resources:
        - dns/zones/tenant/${subject.tenant}/**
      when:
        - subject.mfa_verified exists
```

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: dns-operator
  tenant: acme-corp
  description: DNS operator with limited access

spec:
  subjects:
    roles: [dns-operator]

  rules:
    - name: read-zones
      effect: allow
      actions:
        - dns:zone:read
      resources:
        - dns/zones/tenant/${subject.tenant}/**

    - name: manage-records
      effect: allow
      actions:
        - dns:record:*
      resources:
        - dns/zones/tenant/${subject.tenant}/**
```

### ABAC Policies

Attribute-based access control enables context-aware authorization:

**Time-Based Access:**

```yaml
rules:
  - name: business-hours-only
    effect: allow
    actions: [dns:zone:write, dns:record:write]
    resources:
      - dns/zones/tenant/${subject.tenant}/**
    when:
      - time.hour between 9..17
      - time.weekday in [mon, tue, wed, thu, fri]
```

**Network-Based Restrictions:**

```yaml
rules:
  - name: internal-network-only
    effect: deny
    actions: [dns:dnssec:manage]
    resources:
      - dns/zones/**
    unless:
      - request.ip in 10.0.0.0/8
      - request.ip in 192.168.0.0/16
```

### Multi-Tenant Zone Authorization

The DNS service implements tenant-based authorization to ensure zone isolation in multi-tenant deployments. Each zone is owned by a specific tenant, and all zone operations verify ownership before proceeding.

**Zone Ownership Model:**

| Field | Description | Example |
|-------|-------------|---------|
| `TenantID` | Unique identifier of the owning tenant | `platform`, `tenant-abc123` |
| `IsOwnedBy()` | Method to check tenant ownership | `zone.IsOwnedBy("platform")` |

**Authorization Flow:**

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│   Caller    │────▶│  DNS Service        │────▶│   Zone      │
│  (Tenant A) │     │  authorizeZoneAccess│     │  (Tenant A) │
└─────────────┘     └─────────────────────┘     └─────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │ Compare TenantIDs   │
                    │ A == A? ✓ Allow     │
                    └─────────────────────┘
```

**Protected Operations:**

| Operation | Authorization Check | Error on Failure |
|-----------|---------------------|------------------|
| `Save()` | Zone must be owned by caller | `ErrUnauthorizedZoneAccess` |
| `SaveAndSign()` | Zone must be owned by caller | `ErrUnauthorizedZoneAccess` |
| `Delete()` | Zone must be owned by caller | `ErrUnauthorizedZoneAccess` |
| `SignZone()` | Zone must be owned by caller | `ErrUnauthorizedZoneAccess` |
| `CreateZone()` | TenantID set from service | N/A (auto-assigned) |

**Service Layer Authorization:**

```go
// authorizeZoneAccess checks if the caller's tenant owns the zone
func (s *Service) authorizeZoneAccess(zone *entities.Zone, action string) error {
    if s.params.TenantID == "" {
        return ErrMissingTenantContext
    }
    if !zone.IsOwnedBy(s.params.TenantID) {
        s.params.Config.Logger.Warn("unauthorized zone access",
            slog.String("caller_tenant", s.params.TenantID),
            slog.String("zone_tenant", zone.TenantID),
            slog.String("zone", zone.Name),
            slog.String("action", action))
        return ErrUnauthorizedZoneAccess
    }
    return nil
}
```

**Tenant Isolation Guarantees:**

- Zones are automatically assigned the caller's TenantID on creation
- All zone modifications require matching TenantID
- DNSSEC keys are stored in tenant-scoped KMS paths: `dnssec/{tenant_id}/{zone_name}/{key_type}`
- Unauthorized access attempts are logged with full context for audit

## Network Security

### Internal vs Public Separation

The dual-server architecture provides network-level security:

| Server | Port | Purpose | Access |
|--------|------|---------|--------|
| Internal | 9053 | Private zones, full resolution | LAN only |
| Public | 8053 | Public zones only | Internet-facing |

**Security Controls:**

```
┌──────────────────────────────────────────────────────────────────┐
│                     Network Security Model                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   External Network (Untrusted)                                   │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │                                                            │ │
│   │   Firewall / Load Balancer                                 │ │
│   │   • Rate limiting                                          │ │
│   │   • DDoS protection                                        │ │
│   │   • Only port 8053 exposed                                 │ │
│   │                                                            │ │
│   └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │   Public DNS Server (Port 8053)                            │ │
│   │   • Only serves public zones                               │ │
│   │   • Rejects internal zone queries                          │ │
│   │   • Logs all security violations                           │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Internal Network (Trusted)                                     │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │   Internal DNS Server (Port 9053)                          │ │
│   │   • Serves all zones (internal + public)                   │ │
│   │   • Full resolution capabilities                           │ │
│   │   • DDNS updates accepted                                  │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Zone Isolation:**

```go
// Public server rejects internal zone queries
if zone.Internal && isPublicServer {
    logSecurityEvent(SecurityLogEntry{
        Category:    CategoryNetworkSecurity,
        Description: "Rejecting public query for internal zone",
        Severity:    SeverityHigh,
    })
    return dns.RcodeRefused
}
```

### Query Validation

All DNS queries undergo strict RFC 1035 validation:

| Check | Limit | Purpose |
|-------|-------|---------|
| Domain length | 253 characters | Prevent buffer overflow |
| Label length | 1-63 characters | RFC compliance |
| Character set | Alphanumeric, hyphen | Prevent injection |
| Query type | Whitelist | Limit attack surface |

**Injection Prevention:**

- No special characters in domain names
- IP addresses rejected in forward lookups
- Query names sanitized before processing
- Response size limits enforced

### Rate Limiting

Protection against abuse and denial of service:

| Limit Type | Default | Description |
|------------|---------|-------------|
| Query rate | 1000/min | Per-client query limit |
| Update rate | 60/min | DDNS update limit |
| Connection limit | 100 | Concurrent connections |
| Response size | 4096 bytes | Maximum response size |

**Configuration:**

```yaml
dns:
  rate-limit:
    queries-per-minute: 1000
    updates-per-minute: 60
    max-connections: 100
    burst: 50
```

### DoS Protection

| Protection | Description |
|------------|-------------|
| **Connection limits** | Maximum concurrent connections per client |
| **Query rate limiting** | Throttle excessive query rates |
| **Response rate limiting** | Limit responses to prevent amplification |
| **TCP fallback** | Require TCP for large responses |
| **EDNS0 validation** | Validate extended DNS options |

## DNSSEC Security

### Algorithm Selection

| Algorithm | ID | Security Level | Recommendation |
|-----------|-----|----------------|----------------|
| ECDSAP256SHA256 | 13 | High | Recommended for most deployments |
| ECDSAP384SHA384 | 14 | Very High | High security environments |
| ED25519 | 15 | High | Modern deployments (check resolver support) |
| ED448 | 16 | Very High | Maximum security |
| RSASHA256 | 8 | Medium | Legacy compatibility only |
| RSASHA512 | 10 | Medium | Legacy compatibility only |

**Avoid:**

| Algorithm | Reason |
|-----------|--------|
| RSA-1024 | Insufficient key size |
| DSA | Weak, deprecated |
| RSASHA1 | SHA-1 vulnerabilities |

### Key Lifecycle

| Phase | Duration | Action |
|-------|----------|--------|
| Generation | N/A | Secure random generation in TPM |
| Active | KSK: 365d, ZSK: 30d | Sign zone data |
| Pre-publish | ZSK: 7d | Publish new key before activation |
| Post-publish | ZSK: 7d | Keep old key for cache expiration |
| Revocation | Immediate | Emergency key compromise response |
| Destruction | Post-revocation | Secure key deletion |

**Secure Key Generation:**

```go
// Keys generated within TPM using hardware RNG
key, err := tpm.GenerateKey(tpm.KeyConfig{
    Algorithm:     tpm.ECDSA_P256,
    Handle:        0x81010011,
    NonExportable: true,
    PCRs:          []int{0, 7, 8, 9},
})
```

### Signature Validity

| Parameter | Default | Recommendation |
|-----------|---------|----------------|
| Validity period | 14 days | Short validity reduces exposure |
| Refresh interval | 7 days | Re-sign before expiration |
| Inception offset | 1 hour | Handle clock skew |
| Jitter | 10% | Prevent predictable re-signing |

**Configuration:**

```yaml
dnssec:
  signatures:
    validity: 14d
    refresh: 7d
    inception-offset: 1h
    jitter: 10%
```

## Audit Logging

### Security Events

All security-relevant events are logged:

| Category | Events |
|----------|--------|
| Zone modifications | Create, update, delete zones |
| Record changes | Add, modify, remove records |
| Key operations | Generate, rotate, revoke keys |
| Signing operations | Zone signing, re-signing |
| Query violations | Blocked queries, rate limit hits |
| Access violations | Unauthorized access attempts |
| Authentication | TSIG success/failure |

### Log Format

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event": "dns.security.violation",
  "severity": "HIGH",
  "category": "network_security",
  "source": "dns",
  "description": "Public query for internal zone rejected",
  "details": {
    "query_name": "db.example.internal.",
    "query_type": "A",
    "zone": "example.internal.",
    "zone_internal": true,
    "server": "public"
  },
  "offender_address": "203.0.113.50",
  "request_id": "req-abc123"
}
```

### Log Levels

| Severity | Events |
|----------|--------|
| CRITICAL | Key compromise, system breach |
| HIGH | Access violations, authentication failures |
| MEDIUM | Rate limiting, configuration changes |
| LOW | Normal operations, successful queries |

### Log Retention

| Log Type | Retention | Storage |
|----------|-----------|---------|
| Security events | 1 year | Encrypted, immutable |
| Audit trail | 7 years | Compliance storage |
| Operational | 30 days | Standard storage |

## Threat Model

### Threats Mitigated

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| DNS spoofing | Forged responses | DNSSEC signatures |
| Cache poisoning | Malicious records | DNSSEC validation |
| Zone enumeration | NSEC walking | NSEC3 hashed names |
| Key compromise | Key theft | TPM hardware protection |
| Unauthorized updates | Forged DDNS | TSIG + attestation |
| Man-in-the-middle | Intercepted queries | DNSSEC + DoT/DoH |
| Zone transfer | Unauthorized AXFR | Access control lists |
| Amplification | DNS reflection | Response rate limiting |

### Residual Risks

| Risk | Likelihood | Impact | Mitigation Strategy |
|------|------------|--------|---------------------|
| DDoS attacks | Medium | High | External DDoS protection, rate limiting |
| Protocol vulnerabilities | Low | High | Regular patching, security monitoring |
| Zero-day exploits | Low | Critical | Defense in depth, monitoring |
| Insider threats | Low | High | Access controls, audit logging |
| Supply chain | Low | Critical | Code signing, dependency auditing |

### Security Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│                     Security Boundary Model                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Trust Boundary 1: Network Perimeter                            │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ External queries ─▶ Firewall ─▶ Public DNS only            │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│   Trust Boundary 2: Zone Separation                              │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ Internal zones isolated from public queries                │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│   Trust Boundary 3: Cryptographic                                │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ DNSSEC keys protected in TPM                               │ │
│   │ TSIG secrets sealed to platform state                      │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│   Trust Boundary 4: Access Control                               │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ IAM policies enforce least privilege                       │ │
│   │ All operations authenticated and authorized                │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Best Practices

### Deployment

1. **Enable DNSSEC for all zones** - Sign all authoritative zones
2. **Use TPM for key storage** - Never store keys in software
3. **Enable NSEC3** - Prevent zone enumeration (not plain NSEC)
4. **Regular key rotation** - ZSK: 30 days, KSK: 365 days
5. **Monitor security logs** - Automated alerting on violations
6. **Restrict zone transfers** - Explicit ACLs only

### Configuration

```yaml
dns:
  # Network security
  internal:
    port: 9053
    bind: 127.0.0.1  # Localhost only
  public:
    port: 8053
    bind: 0.0.0.0

  # Rate limiting
  rate-limit:
    queries-per-minute: 1000
    updates-per-minute: 60

  # DDNS security
  ddns:
    require-tsig: true
    allowed-update-types: [A, AAAA, TXT, PTR]

  # Zone transfer (outbound AXFR, platform as primary — see zone-transfer.md).
  # Off by default; served only to TSIG-authenticated secondaries.
  transfer:
    enabled: false
    tsig-keys: []

dnssec:
  enabled: true

  # Default key config using platform KeyConfig pattern
  default-key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2                # TPM-backed for hardware protection

  signature-expiry: 30d
  nsec-mode: nsec3             # NSEC3 for zone enumeration protection
  nsec3-iterations: 1
  nsec3-salt: ""

  ksk:
    lifetime: 365d
    ttl: 86400

  zsk:
    lifetime: 30d
    ttl: 3600
```

### Operational

| Practice | Frequency | Description |
|----------|-----------|-------------|
| Key rotation | ZSK: monthly, KSK: yearly | Automated rotation |
| Security audit | Quarterly | Review logs and access |
| Penetration testing | Annually | External security assessment |
| Backup verification | Monthly | Ensure key recovery works |
| Incident response drill | Semi-annually | Test response procedures |

## Compliance

### Standards Alignment

| Standard | Requirement | Implementation |
|----------|-------------|----------------|
| NIST SP 800-81 | DNSSEC deployment | Full DNSSEC support |
| NIST SP 800-53 | Access control | IAM/ABAC integration |
| RFC 6781 | DNSSEC operational practices | Key rollover procedures |
| RFC 9276 | NSEC3 guidance | Low iteration count |

### Regulatory Considerations

| Regulation | DNS Requirements | Platform Support |
|------------|------------------|------------------|
| PCI-DSS | Secure DNS resolution | DNSSEC, access controls |
| HIPAA | Data integrity | Audit logging, encryption |
| SOC 2 | Security controls | Comprehensive logging |
| FedRAMP | DNSSEC required | Full compliance |

### Audit Support

The platform provides audit-ready documentation:

- Complete audit trail of all DNS operations
- Cryptographic proof of key operations
- Access control policy export
- Configuration change history
- Security event reports

## Related Documentation

| Document | Description |
|----------|-------------|
| [DNSSEC Signing](dnssec.md) | DNSSEC configuration and signing |
| [Key Rollover](dnssec-rollover.md) | KSK and ZSK rollover procedures |
| [Dynamic DNS](dynamic-dns.md) | DDNS and TSIG authentication |
| [Architecture](architecture.md) | DNS system architecture |
| [IAM Authorization](../iam/architecture.md#authorization-flow) | Access control policies |
| [TPM Documentation](../tpm/README.md) | TPM integration details |

## See Also

- [RFC 4033 - DNS Security Introduction](https://datatracker.ietf.org/doc/html/rfc4033)
- [RFC 4034 - Resource Records for DNSSEC](https://datatracker.ietf.org/doc/html/rfc4034)
- [RFC 4035 - Protocol Modifications for DNSSEC](https://datatracker.ietf.org/doc/html/rfc4035)
- [RFC 5155 - NSEC3](https://datatracker.ietf.org/doc/html/rfc5155)
- [RFC 2845 - TSIG](https://datatracker.ietf.org/doc/html/rfc2845)
- [NIST SP 800-81 - Secure DNS Deployment Guide](https://csrc.nist.gov/publications/detail/sp/800-81/2/final)

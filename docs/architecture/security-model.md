# Zero-Trust Security Architecture

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [../security/architecture.md](../security/architecture.md) and [../trust/architecture.md](../trust/architecture.md).

This document describes the zero-trust security architecture for go-trusted-platform, explaining how cryptographic identity and layered verification provide stronger security than traditional perimeter-based models.

> **Status.** This document describes the target security model. Where the
> code differs, this note is authoritative:
>
> - The `security:` configuration in §4 is a design sketch, not a shipped
>   configuration section; no loader decodes it.
> - **Layer 3 (trust level, reputation)** and **Layer 6 (rate limiting,
>   adaptive proof-of-work)** belong to the P2P trusted-computing network,
>   which is planned ([`docs/dht/`](../dht/), `Status: PLANNED`) and not
>   implemented.
> - **Layer 4 (attestation)**: quote freshness is nonce-based; there is no
>   ±100 ms time window. Golden PCR baselines are learned from the first
>   matching device of a profile (trust on first use) until signed baselines
>   land in this release's attestation work, so a modified-firmware device
>   that enrolls first defines the baseline.
> - The network layer this model rests on — zones, port classes, host
>   addressing by role — is the [reference network](reference-network.md),
>   implemented in #708; the overlay's admission and IPsec are #709.

## 1. Overview

### Zero-Trust + Trusted Computing Model

go-trusted-platform implements a **zero-trust security model** built on **trusted computing principles**. This represents a fundamental departure from traditional perimeter-based security.

| Aspect | Traditional Model | go-trusted-platform |
|--------|-------------------|---------------------|
| Trust Anchor | Network perimeter (firewall) | Cryptographic identity (TPM) |
| Authentication | Network location + credentials | Hardware-bound certificates |
| Authorization | Implicit (inside = trusted) | Explicit per-request verification |
| Verification | Once at perimeter | Every request, every layer |
| Compromise Impact | Full access if inside | Limited to compromised identity |

### Why Network Exposure Does Not Weaken Security

In traditional security models, exposing services to the network is dangerous because network location implies trust. Once an attacker penetrates the perimeter, they have trusted access.

In go-trusted-platform, **network exposure does not weaken security** because:

1. **Trust is cryptographic, not locational** - Being on the network grants nothing; only valid TPM-backed credentials enable access
2. **Identity cannot be stolen** - Private keys never leave the TPM; possession of network access is worthless without the physical hardware
3. **Every request is verified** - No implicit trust exists; each request must prove identity and pass authorization
4. **Attestation proves integrity** - Even valid identities must prove their platform has not been compromised
5. **Defense in depth** - Multiple independent layers must all pass; compromising one layer does not bypass others

## 2. Traditional vs Zero-Trust Comparison

### Traditional Perimeter-Based Security

```
                    UNTRUSTED                        TRUSTED
                    (Internet)                       (Internal)
                         │                               │
                         │                               │
    ┌────────────────────┼───────────────────────────────┼────────────────────────┐
    │                    │                               │                        │
    │   Attackers        │     ╔═══════════════╗         │   Internal Resources   │
    │   ┌─────┐          │     ║               ║         │                        │
    │   │ ? ? │ ─────────┼────▶║   FIREWALL    ║─────────┼──▶  ┌─────────────┐    │
    │   │ ? ? │          │     ║               ║         │     │ Database    │    │
    │   └─────┘          │     ║ (Trust        ║         │     │ Servers     │    │
    │                    │     ║  Boundary)    ║         │     │ Services    │    │
    │   Blocked by       │     ╚═══════════════╝         │     └─────────────┘    │
    │   firewall rules   │                               │                        │
    │                    │                               │   Implicitly trusted   │
    │                    │                               │   once inside          │
    └────────────────────┴───────────────────────────────┴────────────────────────┘

    PROBLEMS:
    • Once inside, everything is trusted
    • Stolen credentials = full access
    • Lateral movement is easy
    • VPN = "trusted" even from compromised device
    • No verification of device integrity
```

### go-trusted-platform Zero-Trust Model

```
                        EVERY CONNECTION VERIFIED
                        (Network location irrelevant)

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                                                                             │
    │   ┌─────────────┐         ┌─────────────────────────────────────────────┐   │
    │   │ Device A    │         │              platformd                      │   │
    │   │ ┌─────────┐ │         │                                             │   │
    │   │ │   TPM   │ │ mTLS    │  ┌─────────┐  ┌─────────┐  ┌─────────┐     │   │
    │   │ │ IDevID  │─┼────────▶│  │ Layer 1 │─▶│ Layer 2 │─▶│ Layer N │─────│──▶│
    │   │ └─────────┘ │         │  │ Identity│  │ Enrolled│  │   ...   │     │   │
    │   └─────────────┘         │  └─────────┘  └─────────┘  └─────────┘     │   │
    │                           │                                             │   │
    │   ┌─────────────┐         │  Every request must pass ALL layers:        │   │
    │   │ Device B    │         │  • Valid IDevID certificate                 │   │
    │   │ ┌─────────┐ │         │  • Device enrolled                          │   │
    │   │ │   TPM   │ │ mTLS    │  • Trust level sufficient                   │   │
    │   │ │ IDevID  │─┼────────▶│  • TPM attestation valid (if required)      │   │
    │   │ └─────────┘ │         │  • ABAC policy allows action                │   │
    │   └─────────────┘         │  • Rate limits not exceeded                 │   │
    │                           │                                             │   │
    │   ┌─────────────┐         └─────────────────────────────────────────────┘   │
    │   │ Attacker    │                                                           │
    │   │ (No TPM/    │ ────X   BLOCKED: Cannot present valid IDevID              │
    │   │  No IDevID) │                                                           │
    │   └─────────────┘                                                           │
    │                                                                             │
    │   SECURITY PROPERTIES:                                                      │
    │   • Network access grants nothing                                           │
    │   • Every request verified independently                                    │
    │   • Stolen credentials useless without TPM hardware                         │
    │   • Compromised device detectable via attestation                           │
    │   • Lateral movement blocked by per-request verification                    │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘
```

## 3. Security Layers

go-trusted-platform implements six security layers. Each layer provides independent protection, and requests must pass ALL applicable layers.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          go-trusted-platform Security Layers                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  REQUEST ──▶ ┌───────────────────────────────────────────────────────────────┐  │
│              │ LAYER 1: Identity Verification [MANDATORY]                    │  │
│              │ Valid IDevID certificate + mTLS                               │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│              ┌───────────────────────────▼───────────────────────────────────┐  │
│              │ LAYER 2: Enrollment Verification [CONFIGURABLE]               │  │
│              │ Device enrolled / Trusted CA only                             │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│              ┌───────────────────────────▼───────────────────────────────────┐  │
│              │ LAYER 3: Trust Level Verification [CONFIGURABLE]              │  │
│              │ Hardware TPM / Minimum reputation / Age                       │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│              ┌───────────────────────────▼───────────────────────────────────┐  │
│              │ LAYER 4: TPM Attestation [CONFIGURABLE PER OPERATION]         │  │
│              │ Fresh quote / PCR verification                                │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│              ┌───────────────────────────▼───────────────────────────────────┐  │
│              │ LAYER 5: ABAC Policy Enforcement [MANDATORY]                  │  │
│              │ Attribute-based access control                                │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│              ┌───────────────────────────▼───────────────────────────────────┐  │
│              │ LAYER 6: Rate Limiting & DDoS Protection [MANDATORY]          │  │
│              │ Per-node limits / Reputation quotas / Adaptive PoW            │  │
│              └───────────────────────────┬───────────────────────────────────┘  │
│                                          │                                      │
│                                          ▼                                      │
│                                      ALLOWED                                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Layer 1: Identity Verification (Mandatory)

**What it does:**
- Requires a valid IDevID (Initial Device Identifier) certificate for every connection
- Enforces mutual TLS (mTLS) authentication - both client and server verify each other
- Validates certificate chain back to trusted CA
- Checks certificate revocation status

**What attackers it blocks:**
- Random internet attackers without valid certificates
- Attackers with self-signed or invalid certificates
- Attackers attempting man-in-the-middle attacks
- Connections from devices not enrolled with the platform CA

**Why TPM binding matters:**
The IDevID private key is generated inside the TPM and **never leaves the hardware**. This means:
- Cannot be stolen via malware
- Cannot be copied to another machine
- Cannot be extracted even with physical access (TPM is tamper-resistant)
- The only way to use the identity is to possess the original hardware

### Layer 2: Enrollment Verification (Configurable)

**What it does:**
- Verifies the connecting device is enrolled in the platform
- Can restrict to only IDevIDs issued by specific trusted CAs
- Supports different connection policies based on deployment mode

**Connection Policy Modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `enrolled_only` | Only accept enrolled devices | Enterprise/private deployments |
| `trusted_ca_only` | Accept any IDevID from trusted CAs | Multi-organization federation |
| `p2p_network` | Accept valid P2P network participants | Distributed deployments |

**What attackers it blocks:**
- Devices with valid certificates but not enrolled in this deployment
- Devices from other organizations (when in enrolled_only mode)
- Revoked or suspended devices

### Layer 3: Trust Level Verification (Configurable)

**What it does:**
- Enforces minimum trust level requirements
- Distinguishes between hardware TPM and software TPM (swtpm)
- Checks device reputation score
- Enforces minimum device age (anti-Sybil protection)

**Trust Levels:**

| Level | TPM Type | Description |
|-------|----------|-------------|
| `untrusted` | None | No TPM (rejected in production) |
| `software` | swtpm | Software TPM (development/testing) |
| `trusted` | Hardware | Hardware TPM 2.0 |
| `attested` | Hardware + Quote | Hardware TPM with fresh attestation |

**What attackers it blocks:**
- Attackers using software-emulated TPMs to fake hardware trust
- Newly created identities attempting Sybil attacks
- Nodes with degraded reputation due to past misbehavior
- Development/test devices attempting production access

### Layer 4: TPM Attestation (Configurable Per Operation)

**What it does:**
- Requests a fresh TPM quote for sensitive operations
- Verifies PCR (Platform Configuration Register) values match expected golden state
- Ensures the quote is recent (within configurable freshness window)
- Validates the attestation signature chain

**What attackers it blocks:**
- Compromised devices with modified firmware/software
- Devices with rootkits or bootkits that altered the boot chain
- Replay attacks using old attestation quotes
- Devices that pass identity checks but have been tampered with

**Configurable Operations:**
- `certificate_request` - Require attestation for certificate issuance
- `admin_operations` - Require attestation for administrative actions
- `key_operations` - Require attestation for cryptographic operations
- `sensitive_data` - Require attestation for sensitive data access

### Layer 5: ABAC Policy Enforcement (Mandatory)

**What it does:**
- Implements Attribute-Based Access Control
- Evaluates policies based on subject, action, resource, and environment attributes
- Supports fine-grained access control at the API operation level
- Enables role-based restrictions within the attribute framework

**Example Policy Attributes:**

| Category | Attributes |
|----------|------------|
| Subject | role, tenant_id, device_id, trust_level, reputation |
| Action | method (GET/POST/...), operation_type |
| Resource | path, resource_type, owner |
| Environment | time, source_ip, request_rate |

**What attackers it blocks:**
- Valid identities attempting unauthorized actions
- Privilege escalation attempts
- Cross-tenant access attempts
- Actions outside permitted time windows or contexts

### Layer 6: Rate Limiting and DDoS Protection (Mandatory)

**What it does:**
- Enforces per-node request rate limits
- Applies reputation-based quotas
- Implements adaptive Proof-of-Work for unknown/untrusted requesters
- Protects against resource exhaustion attacks

**Rate Limit Tiers:**

| Tier | RPM | Burst | Notes |
|------|-----|-------|-------|
| Enrolled devices | 1000 | 100 | Full-speed access |
| P2P nodes | 10 | 5 | Reduced for cross-network |
| Unknown | 1 | 1 | Requires PoW |

**What attackers it blocks:**
- DDoS attacks from compromised or fake identities
- Resource exhaustion attacks
- Abuse by low-reputation nodes
- Rapid enumeration or brute-force attempts

## 4. Security Policy Configuration

The following YAML example shows a comprehensive security configuration with all six layers:

```yaml
security:
  # Layer 1: Identity Verification (mandatory - always enabled)
  require_idevid: true
  mtls:
    enabled: true
    verify_client: true
    verify_revocation: true
    trusted_cas:
      - /etc/platform/ca/root-ca.pem
      - /etc/platform/ca/issuing-ca.pem

  # Layer 2: Enrollment Verification
  connection_policy:
    mode: enrolled_only  # Options: enrolled_only, trusted_ca_only, p2p_network
    enrolled_only:
      database: quicbaas://enrolled_devices
    trusted_ca_only:
      allowed_cas:
        - "CN=Acme Corp Root CA,O=Acme Corp"
        - "CN=Partner Org CA,O=Partner Org"

  # Layer 3: Trust Level Verification
  trust_requirements:
    min_trust_level: trusted  # Options: software, trusted, attested
    require_hardware_tpm: true
    reject_swtpm: true
    min_reputation: 0.0       # 0.0 to 1.0 (0 = accept all, 0.8 = high-trust only)
    min_age_days: 0           # Minimum device age for anti-Sybil protection

  # Layer 4: TPM Attestation
  attestation:
    require_quote_for:
      - certificate_request
      - admin_operations
      - key_operations
      - sensitive_data
    pcr_policy:
      # Expected PCR values for known-good platform state
      pcr0: "sha256:abc123..."   # BIOS/UEFI firmware
      pcr1: "sha256:def456..."   # Platform configuration
      pcr7: "sha256:ghi789..."   # Secure boot state
      pcr14: "sha256:jkl012..."  # Workload chain
    max_quote_age: 100ms         # design only: freshness is nonce-based today
    nonce_size: 32               # Nonce size in bytes

  # Layer 5: ABAC Policy Enforcement
  abac:
    default_effect: deny
    policies:
      - name: admin-full-access
        subjects:
          - attributes:
              role: admin
              trust_level: attested
        resources:
          - pattern: "/api/v1/**"
        actions:
          - "*"
        effect: allow

      - name: device-self-management
        subjects:
          - attributes:
              device_id: ${subject.device_id}
        resources:
          - pattern: "/api/v1/devices/${subject.device_id}/**"
        actions:
          - GET
          - PUT
        effect: allow

      - name: read-only-for-low-reputation
        subjects:
          - attributes:
              reputation: { lt: 0.5 }
        resources:
          - pattern: "/api/v1/**"
        actions:
          - POST
          - PUT
          - DELETE
        effect: deny

  # Layer 6: Rate Limiting and DDoS Protection
  rate_limits:
    enrolled_devices:
      requests_per_minute: 1000
      burst: 100
      require_pow: false
    p2p_nodes:
      requests_per_minute: 10
      burst: 5
      require_pow: false
    unknown:
      requests_per_minute: 1
      burst: 1
      require_pow: true
      pow_difficulty: 24  # 2^24 work factor

    # Per-operation limits (override tier defaults)
    operation_limits:
      certificate_request:
        requests_per_hour: 10
      key_generation:
        requests_per_hour: 5

    # DDoS protection
    ddos:
      enabled: true
      auto_pow_threshold: 10000  # RPM before enabling PoW for all
      block_threshold: 100000    # RPM before blocking
```

## 5. Attack Scenarios and Defenses

The following table compares how traditional perimeter security and go-trusted-platform handle common attack scenarios:

| Attack Scenario | Traditional Model | go-trusted-platform |
|-----------------|-------------------|---------------------|
| **Random internet attacker** | Blocked at firewall | Blocked at Layer 1: No valid IDevID certificate |
| **Stolen credentials** | Full access once inside network | Blocked: Credentials useless without TPM hardware containing private key |
| **Cloned VM** | Full access if on trusted network | Blocked at Layer 3: swtpm rejected; Layer 4: PCR mismatch detected |
| **Compromised leaf node** | Lateral movement to other systems | Limited: Can only access resources allowed by ABAC policy for that identity |
| **Malicious P2P node** | N/A (perimeter model) | Planned: the P2P network and its Layers 3 and 6 are not implemented (`docs/dht/`) |
| **DDoS attack** | Overwhelms firewall/services | Planned: Layer 6 per-node limits and adaptive PoW are not implemented |
| **Insider threat (valid employee)** | Full trusted access | Limited: ABAC policies restrict to job function; attestation detects tampering |
| **Replay attack (old quote)** | N/A (no attestation) | Blocked at Layer 4: each quote is bound to a fresh verifier nonce |
| **Sybil attack (many fake identities)** | Can create unlimited accounts | Blocked at Layer 3: Hardware TPM required, minimum age enforced |
| **Supply chain attack (modified firmware)** | Undetected | Detected at Layer 4 once a profile's golden PCRs are set: values mismatch. Baselines are trust-on-first-use until signed baselines land, so a device modified before its profile's first enrollment is not detected |
| **Physical device theft** | Credentials extracted, device cloned | Limited: TPM keys non-exportable; new enrollment triggers alerts |

### Attack Scenario Details

**Stolen Credentials:**
In traditional systems, stolen username/password or even stolen client certificates grant full access. In go-trusted-platform, the private key exists only inside the TPM. An attacker would need to:
1. Physically steal the device
2. Keep it powered and connected
3. Use it directly (cannot extract keys)

Even then, the theft would be detected when the legitimate device comes online (certificate conflict) or through physical inventory.

**Cloned VM Attack:**
An attacker who copies a VM (including its software TPM) to another host will fail because:
1. If `reject_swtpm: true`, swtpm is rejected entirely
2. Even with swtpm allowed, the PCR values will differ from the original hardware platform
3. The cloned VM's attestation quote will show unexpected PCR values

**Compromised Leaf Node:**
Even if an attacker fully compromises one device:
1. They can only access resources that device's identity is authorized for
2. They cannot impersonate other devices (no access to their TPM keys)
3. Attestation will eventually detect the compromise (modified PCRs)
4. ABAC policies limit blast radius to that device's permissions

## 6. Key Protection

go-trusted-platform implements a tiered key protection strategy based on key criticality:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Key Protection Hierarchy                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ TIER 1: Critical Keys                                                   │    │
│  │ Storage: HSM (Hardware Security Module) or Offline TPM                  │    │
│  │                                                                         │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐   │    │
│  │  │   CA Root Key     │  │   DNSSEC KSK      │  │   IAM Signing     │   │    │
│  │  │   (Offline HSM)   │  │   (HSM or TPM)    │  │   (TPM-bound)     │   │    │
│  │  │                   │  │                   │  │                   │   │    │
│  │  │ • Never online    │  │ • Annual rotation │  │ • Hardware-bound  │   │    │
│  │  │ • Air-gapped      │  │ • Multi-person    │  │ • Non-exportable  │   │    │
│  │  │ • Ceremony-based  │  │   ceremony        │  │ • Quote-attested  │   │    │
│  │  └───────────────────┘  └───────────────────┘  └───────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                      │
│                                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ TIER 2: Operational Keys                                                │    │
│  │ Storage: TPM-sealed (released only in known-good state)                 │    │
│  │                                                                         │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐   │    │
│  │  │  CA Issuing Key   │  │   DNSSEC ZSK      │  │    TLS Keys       │   │    │
│  │  │  (TPM-sealed)     │  │   (TPM-sealed)    │  │   (TPM-sealed)    │   │    │
│  │  │                   │  │                   │  │                   │   │    │
│  │  │ • Online signing  │  │ • Quarterly       │  │ • Auto-rotated    │   │    │
│  │  │ • PCR-bound       │  │   rotation        │  │ • Per-service     │   │    │
│  │  │ • Auto-unseal     │  │ • PCR-bound       │  │ • ACME-managed    │   │    │
│  │  └───────────────────┘  └───────────────────┘  └───────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                      │
│                                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ TIER 3: Data Encryption Keys                                            │    │
│  │ Storage: TPM-sealed DEKs (Data Encryption Keys)                         │    │
│  │                                                                         │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐   │    │
│  │  │  QuicBaaS DEK     │  │   Secrets DEK     │  │   Backup DEK      │   │    │
│  │  │  (TPM-sealed)     │  │   (TPM-sealed)    │  │   (TPM-sealed)    │   │    │
│  │  │                   │  │                   │  │                   │   │    │
│  │  │ • Database        │  │ • Vault-style     │  │ • Backup          │   │    │
│  │  │   encryption      │  │   secrets store   │  │   encryption      │   │    │
│  │  │ • At-rest only    │  │ • PCR-bound       │  │ • Offline copy    │   │    │
│  │  └───────────────────┘  └───────────────────┘  └───────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  TPM Sealing Properties:                                                        │
│  • Keys sealed to specific PCR values                                           │
│  • Only released when platform is in known-good state                           │
│  • Modified firmware/OS = keys remain sealed (inaccessible)                     │
│  • Physical TPM extraction = keys destroyed (tamper-resistant)                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Tier Details

**Tier 1: Critical Keys**

| Key | Storage | Protection | Rotation |
|-----|---------|------------|----------|
| CA Root Key | Offline HSM | Air-gapped, multi-person ceremony | 10+ years |
| DNSSEC KSK | HSM or TPM | Key signing ceremonies | Annual |
| IAM Signing Key | TPM-bound | Hardware non-exportable | As needed |

**Tier 2: Operational Keys**

| Key | Storage | Protection | Rotation |
|-----|---------|------------|----------|
| CA Issuing Key | TPM-sealed | PCR-bound, auto-unseal | 1-2 years |
| DNSSEC ZSK | TPM-sealed | PCR-bound, auto-unseal | Quarterly |
| TLS Server Keys | TPM-sealed | ACME-managed | 90 days |

**Tier 3: Data Encryption Keys**

| Key | Storage | Protection | Rotation |
|-----|---------|------------|----------|
| QuicBaaS DEK | TPM-sealed | Encrypts database at rest | On compromise |
| Secrets DEK | TPM-sealed | Encrypts secrets store | On compromise |
| Backup DEK | TPM-sealed | Encrypts backups | Per backup set |

### TPM Sealing Behavior

When a key is "TPM-sealed":
1. The key is encrypted by the TPM using the Storage Root Key (SRK)
2. The sealed blob includes PCR values that must match for unsealing
3. On boot, if PCRs match expected values, TPM releases the key
4. If firmware/OS is modified, PCRs differ, and key remains sealed

This means:
- **Rootkit installed?** PCRs change, keys stay sealed, attacker gets nothing
- **Firmware modified?** PCRs change, keys stay sealed, system won't operate
- **TPM physically removed?** Keys are destroyed (tamper-resistant hardware)
- **VM cloned?** No hardware TPM, cannot unseal (swtpm has different SRK)

## 7. Why This Architecture Is Inherently Secure

### Summary of Security Properties

| Property | Implementation | Benefit |
|----------|----------------|---------|
| **Cryptographic Identity** | TPM-bound IDevID keys | Identity cannot be stolen, cloned, or transferred |
| **Zero Implicit Trust** | Every request verified through 6 layers | No free pass for network location or past authentication |
| **Defense in Depth** | Independent security layers | Compromising one layer does not bypass others |
| **Operator Control** | Configurable policies per layer | Adapt security posture to deployment requirements |
| **Tamper Detection** | TPM attestation with PCR verification | Compromised platforms detected before damage |
| **Blast Radius Limitation** | ABAC policies per identity | Compromise of one device does not grant access to others |

### The Fundamental Difference

In traditional security:
```
Network Access + Credentials = Trust
```

In go-trusted-platform:
```
TPM Hardware + Valid Certificate + Enrollment + Trust Level + Attestation + ABAC + Rate Limits = Trust
```

Each element is independently verified. Removing any one:
- No TPM hardware = Cannot generate valid IDevID
- Invalid certificate = Rejected at Layer 1
- Not enrolled = Rejected at Layer 2
- Wrong trust level = Rejected at Layer 3
- Failed attestation = Rejected at Layer 4
- ABAC policy violation = Rejected at Layer 5
- Rate limit exceeded = Rejected at Layer 6

**This is why exposing go-trusted-platform to the network is safe** - network access provides no privilege. Only possession of enrolled hardware with valid attestation and appropriate permissions grants access.

## 8. Related Documentation

- [Platform Modes](platform-modes.md) - Local, P2P, and Hosted deployment modes
- [IAM Architecture](../iam/architecture.md) - Identity and access management details
- [Attestation Architecture](../attestation/architecture.md) - TPM attestation implementation
- [DHT Security and Trust](../dht/03-security-trust.md) - P2P network security model
- [ABAC Policies](../iam/abac-policies.md) - Policy configuration reference

---

**Document Version:** 1.0
**Last Updated:** 2026-01-10

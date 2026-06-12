# Security Architecture

Comprehensive security design for go-trusted-platform, covering cryptographic trust, threat models, and operational security.

## Executive Summary

go-trusted-platform provides **cryptographic assurance** of platform security through:

1. **Hardware-backed identity** via TPM 2.0 (trust anchor)
2. **TLS 1.3 everywhere** with no downgrade possible (transport security)
3. **Zero-trust authorization** via cryptographic certificates (never implicit trust)
4. **Cryptographic sealing** with Shamir shares (barrier/seal system)
5. **Platform attestation** proving integrity (remote verification)

Trust is **never** granted by network location or implicit assumptions — only by cryptographic proof.

## 1. Trust Bootstrapping

### Cold Start Problem

When platform starts for the first time, it faces the chicken-and-egg
problem: it has no identity, but needs one to communicate securely.
go-trusted-platform solves this by dispatching through the canonical
`xkms/pkg/trust/bootstrap` library (reached from the platform trust
resolver in `pkg/trust` via the type-alias re-export
`github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap`). That
library composes [go-truststrap](https://github.com/jeremyhahn/go-truststrap)
internally — the platform repo does NOT import `go-truststrap` directly
from application code. Four bootstrap modes are supported:

#### Method 1: DANE/TLSA DNS Records

**For:** Organizations with existing DNSSEC

```
_8443._tcp.example.test.  TLSA  3 1 1 DEADBEEF...
```

**Process:**
1. Platform generates self-signed cert on first boot
2. Admin publishes TLSA record with cert fingerprint in DNS
3. Subsequent connections validate cert against TLSA record
4. DNSSEC proves record authenticity
5. Trust established without certificate authority

**Security:** Requires DNSSEC and DNS admin access

```bash
# Generate TLSA record
openssl x509 -in /var/lib/trusted-platform/ca/cert.pem \
    -noout -fingerprint -sha256 | \
    awk -F'=' '{print "3 1 1 " tolower($2) | "tr -d :'"}' > tlsa.txt

# Publish in DNS
# _8443._tcp.example.test. TLSA <content of tlsa.txt>
```

#### Method 2: Noise Protocol (NK)

**For:** Organizations without DNSSEC

```
Device connects via Noise_NK pattern to known public key
```

**Process:**
1. Admin shares platform public key via out-of-band (email, QR code)
2. Device verifies public key matches (NK = Known Public Key)
3. Authenticated encryption established
4. Platform identity proven without certificate authority

**Security:** Requires secure key distribution channel

```bash
# Get platform public key
platformctl ca info --public-key

# Device connects with known public key
# Noise_NK(remote_public_key: platform_public_key)
```

#### Method 3: SPKI Hash

**For:** Enterprise with certificate pinning

```
Pin: sha256/DEADBEEF...
```

**Process:**
1. Admin pins platform public key via SPKI hash
2. All clients verify cert against pinned key
3. Cert rotation updates pin
4. Prevents man-in-the-middle via rogue certificates

**Security:** Requires key rotation management

```bash
# Get SPKI hash
echo | openssl s_client -connect localhost:8443 2>/dev/null | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    base64
```

#### Method 4: HTTPS with Self-Signed

**For:** Development and testing

```
Trust cert permanently (one-time)
```

**Process:**
1. Admin connects to HTTPS endpoint
2. Browser warns self-signed cert
3. Admin explicitly trusts cert (one-time)
4. Subsequent connections succeed
5. No certificate authority needed

**Security:** Vulnerable to MITM on first connection

```bash
# One-time trust on Linux
curl -k https://localhost:8443 | tee /tmp/data
sudo cp /var/lib/trusted-platform/ca/cert.pem \
    /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates
curl https://localhost:8443 | tee /tmp/data-verified
```

### Trust Store

Platform maintains trust anchors:

```
/var/lib/trusted-platform/
├── ca/
│   ├── certificate.pem          # Self-signed or issuing CA
│   ├── signing-key.enc          # Private key (encrypted in barrier)
│   └── chain.pem                # CA chain if issuing
├── trust/
│   ├── roots.pem                # Trusted root CAs
│   ├── intermediates.pem         # Trusted intermediate CAs
│   └── pinned.pem               # Pinned public keys
└── barrier/
    ├── status                    # Sealed/unsealed
    └── shares/                   # Shamir shares (threshold-crypto)
```

## 2. Transport Security: TLS 1.3

### TLS 1.3 Enforcement

**Critical design principle:** TLS 1.3 enforced everywhere with **no downgrade possible**.

```go
// TLS configuration is immutable
const (
    minTLSVersion = tls.VersionTLS13
    maxTLSVersion = tls.VersionTLS13
)

// Downgrades impossible — Go runtime rejects older versions
// No SSLv3, TLS 1.0, 1.1, 1.2 possible
```

### Cipher Suites

Only modern, NIST-approved suites:

```go
// All AEAD (authenticated encryption + anti-tampering)
// All have forward secrecy (ephemeral keys)

var cipherSuites = []uint16{
    tls.TLS_AES_256_GCM_SHA384,         // 256-bit keys, SHA-384
    tls.TLS_CHACHA20_POLY1305_SHA256,   // ChaCha20-Poly1305
    tls.TLS_AES_128_GCM_SHA256,         // 128-bit keys (weakest acceptable)
}
```

All suites are:
- **Authenticated encryption** — tampering impossible
- **Forward secret** — session key loss doesn't reveal past
- **AEAD** — no separate MAC, prevents oracle attacks
- **NIST-approved** — cryptographically proven secure

### Certificate Requirements

All TLS certificates must:

```
✓ Be issued by platform CA (verified in Transport layer)
✓ Have valid SubjectAltName (no CN-only certs)
✓ Use RSA-PSS or ECDSA (no RSA-PKCS1v1.5)
✓ Be non-self-signed for clients (self-signed only for platform CA)
✓ Include Extended Key Usage (serverAuth, clientAuth)
✓ Have reasonable TTL (90 days max for rotation)
```

**Certificate Path Validation:**

```
TLS Connection
    ↓
Extract peer certificate chain
    ↓
Verify signature: each cert signed by next in chain
    ↓
Verify chain root: last cert matches trust store
    ↓
Verify SubjectAltName matches hostname
    ↓
Verify Extended Key Usage (serverAuth/clientAuth)
    ↓
Verify not expired and not revoked (OCSP/CRL)
    ↓
Connection accepted
```

### Session Security

**Session Resumption Disabled** (by default):

```go
// Prevent session ticket replay
tlsConfig.SessionTicketsDisabled = true
```

Rationale: Session tickets cache credentials. If ticket is stolen, attacker can hijack session. Disabling prevents this attack (trades performance for security).

**Optional Session Resumption:**

For high-performance scenarios, enable with safeguards:

```yaml
tls:
  session-resumption: true
  session-timeout: 300       # 5 minutes max
  session-ticket-rotation: true  # Rotate every request
```

## 3. Zero-Trust Authorization

### Authentication vs Authorization

| Layer | Mechanism | Granularity |
|-------|-----------|-------------|
| Transport | TLS certificates (mTLS) | Per-connection |
| Application | JWT tokens with claims | Per-request |
| Resource | RBAC/ABAC policies | Per-resource |

### Transport Layer (mTLS)

All service-to-service communication uses mutual TLS:

```
Service A                           Service B
├─ Certificate                      ├─ Certificate
│  ├─ CN=svc-a.platform             │  ├─ CN=svc-b.platform
│  └─ Key (in TPM)                  └─ Key (in TPM)
│
TLS Handshake:
1. Server (B) sends cert
2. A verifies cert signed by platform CA
3. A sends its cert
4. B verifies cert signed by platform CA
5. Both verify SubjectAltName = CN
6. Encrypted channel established
7. Both authenticate each other
```

### Application Layer (OAuth2/JWT)

```
Authenticated client sends:
POST /api/endpoint
Authorization: Bearer <JWT>

JWT contains:
{
  "sub": "device-serial-123",       # Subject (device identity)
  "aud": ["platform-api"],          # Audience
  "scope": ["ca:read", "dns:write"], # Requested permissions
  "iat": 1711779000,                # Issued at
  "exp": 1711782600,                # Expires
  "device-attestation": {...}       # Platform attestation
}

Server verifies:
✓ Signature (public key from platform CA)
✓ Expiration (time is valid)
✓ Audience (token for this service)
✓ Claims match request (scope includes requested operation)
✓ Device attestation proves platform not compromised
```

### Resource Layer (RBAC/ABAC)

After authentication and token verification:

```go
// Example: User wants to revoke certificate

// RBAC check
if user.Role == "admin" {
    // Allow
} else {
    // Deny
}

// ABAC check (attribute-based)
if user.HasAttribute("certificate-revoke") &&
   cert.Owner == user.ID {
    // Allow (user owns cert)
} else {
    // Deny
}
```

### Policy Engine

Platform uses [OPA (Open Policy Agent)](https://www.openpolicyagent.dev/) for flexible policies:

```rego
# Example policy: Only admins or resource owner can delete

package platform.policies

allow_delete {
    user.role == "admin"
}

allow_delete {
    input.resource.owner == user.id
}

# Usage
allowed := data.platform.policies.allow_delete
```

## 4. Barrier and Seal System

The **barrier** is cryptographic storage protection for sensitive data at rest (keys, certificates, secrets).

### Shamir Secret Sharing

Uses [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) to split barrier unlock key into shares:

```
Master Key (barrier unlock key)
    ↓
Split into 5 shares using Shamir
    ↓
Threshold 3: any 3 of 5 can reconstruct
    ↓
Share 1 → Vault A
Share 2 → Vault B
Share 3 → Person C (offline)
Share 4 → Cloud storage (encrypted)
Share 5 → Off-site backup
```

**Security Properties:**

1. **Individual shares worthless** — One or two shares reveal nothing
2. **Quorum required** — Always need threshold number
3. **Distributed trust** — No single point of failure
4. **Recombination only in memory** — Key never reconstructed to disk
5. **Non-deterministic** — Same data + shares ≠ same key (uses randomness)

### Seal Strategies

Platform supports three barrier sealing strategies:

#### Software Strategy (Development)

```
┌──────────────────┐
│  Barrier Sealed  │
└────────┬─────────┘
         │
    User unseal
         │
    Enter shares
    (CLI prompts)
         │
┌────────▼─────────┐
│ Barrier Unsealed │
└──────────────────┘
```

**Security:** User must enter shares (no automation)

**Use case:** Development, testing

```bash
# Initialize
sudo platformctl barrier init --strategy software --shares 5 --threshold 3

# Unseal
sudo platformctl barrier unseal --share share-1.enc --share share-2.enc --share share-3.enc
```

#### TPM Strategy (Production)

```
Barrier unlock key encrypted in TPM
    ↓
TPM seals key to PCR values
    ↓
Only unseal if system integrity valid
    (PCRs match expected measurement)
```

**Process:**

```
1. Generate random barrier unlock key
2. Seal to TPM with PCR 0,1,7 (firmware + bootloader + kernel)
3. On startup, platform unseals from TPM
4. If PCRs don't match (tampering detected), unseal fails
5. Manual unseal with shares required
```

**Security:** Requires hardware security module (TPM) and verified boot

**Use case:** Production servers with fixed configuration

```yaml
# Configuration
barrier:
  seal-strategy: tpm2
  tpm:
    key-handle: 0x81000003
    pcrs: [0, 1, 7]
```

#### PKCS#11 Strategy (HSM)

```
Barrier unlock key stored in Hardware Security Module
    ↓
HSM unseals on platform authentication
    ↓
User supplies PIN to HSM
```

**Security:** HSM-grade security, PIN-protected

**Use case:** Enterprise with HSMs

```yaml
barrier:
  seal-strategy: pkcs11
  pkcs11:
    hsm-module: /usr/lib/softhsm/libsofthsm2.so
    token: "SoftHSM v2"
    pin: ${BARRIER_PIN}
```

### Barrier State Machine

```
┌─────────────┐
│   Sealed    │◄────────────────────────────┐
└──────┬──────┘                             │
       │                                    │
  unseal cmd                           seal cmd
  (shares or HSM)                      (explicit)
       │                                    │
       ▼                                    │
┌─────────────┐                            │
│  Unsealing  │                            │
└──────┬──────┘                            │
       │                                    │
  (reconstruct key)                        │
       │                                    │
       ▼                                    │
┌─────────────┐                            │
│ Unsealed    │────────────────────────────┘
└─────────────┘
   (ready to use)
```

### Barrier Operations

```bash
# Initialize barrier (first boot)
sudo platformctl barrier init --strategy tpm2 --shares 5 --threshold 3

# Check status
platformctl barrier status
# Output: sealed / unsealing / unsealed

# Unseal (manual)
sudo platformctl barrier unseal --share share-1.enc --share share-2.enc --share share-3.enc

# Unseal (automatic TPM)
sudo platformctl barrier unseal

# Seal (explicit)
sudo platformctl barrier seal

# Generate new shares (recovery)
sudo platformctl barrier shares generate --count 5
```

## 5. Platform Attestation

Remote systems can **verify platform integrity** via attestation:

### Local Attestation

Device proves to local service that platform is not compromised:

```
┌──────────────────────────────────────────┐
│ Trusted Platform                         │
├────────────────────────────────────────┤
│ 1. TPM extends measurement to PCR 10    │
│ 2. Request quote from TPM               │
│ 3. Sign quote with attestation key      │
│ 4. Return quote + signature             │
├────────────────────────────────────────┤
│ Verifier checks:                        │
│ ✓ Quote signature (TPM key)             │
│ ✓ PCR 10 value (known good state)       │
│ ✓ Timestamp (recent)                    │
└──────────────────────────────────────────┘
```

**Quote contains:**

```
{
  "pcr-10": "DEADBEEF...",              # IMA measurement
  "pcr-0": "ABCD1234...",               # Firmware
  "pcr-1": "5678EFGH...",               # Bootloader
  "pcr-7": "IJKL9012...",               # Secure boot config
  "timestamp": 1711779000,
  "nonce": "random-challenge-from-verifier"
}
```

### Remote Attestation

External system verifies platform integrity:

```
Remote System                        Platform
    │                                   │
    ├──── verify request + nonce ─────►│
    │                                   │
    │                                   │ Get quote from TPM
    │                                   │ Sign with AK (Attestation Key)
    │                                   │
    │◄──── signed quote + AK cert ─────┤
    │                                   │
Verify quote:
✓ Check AK cert (issued by platform CA)
✓ Check signature (AK key)
✓ Check PCR values (known good)
✓ Check timestamp (recent)
✓ Check nonce (matches request)
    │
Decision: trusted or untrusted
```

## 6. Cryptographic Key Management

### Key Storage

Platform key management is reached via `quicbaas.SDK().Security().KMS()`
(and `Security().Crypto()` / `Security().Certificate()`). The KMS
implementation behind those interfaces is provided by
[go-xkms](https://github.com/jeremyhahn/go-xkms) — the canonical home
for hardware-backed crypto in the stack — but the platform repo never
imports `go-xkms` directly from runtime code (see the SDK Consumption
Invariant in `CLAUDE.md`). The supported key storage tiers are:

| Key Type | Storage | Use |
|----------|---------|-----|
| Platform CA signing key | Barrier (encrypted) | Sign certificates |
| TPM SRK (Storage Root Key) | TPM hardware | Seal other keys |
| Device IDevID | TPM hardware | Device identity |
| Attestation Key (AK) | TPM hardware | Quote signing |
| Session keys | Memory only | TLS session |
| Database encryption | Barrier | Encrypt-at-rest |

### Key Hierarchy

```
                 TPM SRK
                    │
            ┌───────┼────────┐
            │       │        │
        IDevID    IAK      AEK
            │       │        │
        Identity  Quotes   Data Encryption
            │       │        │
        Platform  Remote  Encrypted
        Certs   Attestation Storage
```

### Key Rotation

Platform automatically rotates long-lived keys:

```bash
# View key versions
platformctl kms key versions --name platform-ca-signing

# Rotate (generates new, old retained for grace period)
sudo platformctl ca rotate

# View rotation history
platformctl kms key rotations --name platform-ca-signing
```

**Rotation process:**

1. Generate new key
2. Create new certificate signed by old key
3. Cross-sign (new key signs cert containing old key)
4. Transition period (accept both old and new)
5. Revoke old after grace period

## 7. Threat Model

### Assets Protected

| Asset | Threat | Mitigation |
|-------|--------|-----------|
| CA keys | Theft, misuse | TPM-sealed, barrier, access control |
| Device identity | Cloning, impersonation | TPM-bound IDevID, attestation |
| User credentials | Theft, replay | Bcrypt + salt, short-lived tokens |
| API keys | Theft, misuse | Hardware tokens, rotation |
| Secrets (passwords) | Plaintext disclosure | Encrypted-at-rest in barrier |
| TLS certs | Rogue issuance | Platform CA only, no external CAs |
| Audit logs | Tampering | Append-only, signed entries |
| Configuration | Unauthorized modification | File permissions, immutability checks |

### Attack Scenarios

#### Scenario 1: Network Attacker

**Attack:** Eavesdrop on network traffic

**Mitigation:** TLS 1.3 encryption
- All traffic encrypted
- Forward secrecy (session key loss doesn't reveal past)
- No plaintext ever transmitted

**Result:** Network attacker sees only encrypted bytes, learns nothing

#### Scenario 2: Stolen Credentials

**Attack:** Obtain user password or API key

**Mitigation:**
- Short-lived tokens (1 hour max)
- No password stored in plaintext
- Per-request authorization verification
- Credential revocation possible

**Result:** Stolen credential expires, attacker loses access

#### Scenario 3: Compromised Service (e.g., DNS)

**Attack:** Attacker gains shell on DNS service

**Mitigation:**
- Service runs in unprivileged container
- CA keys in barrier (not accessible)
- API keys rotated frequently
- Barrier locked (unseal required for CA ops)

**Result:** Attacker can't access CA keys, can't issue rogue certs

#### Scenario 4: TPM Firmware Bug

**Attack:** TPM implementation is buggy, allows key extraction

**Mitigation:**
- Shamir shares (threshold-crypto) for barrier
- Multi-strategy support (not TPM-only)
- Defense in depth (even if one layer fails, others remain)

**Result:** Even if TPM is compromised, barrier shares required to unseal

#### Scenario 5: Rubber Hose Attack

**Attack:** Coerce operator to reveal barrier shares

**Mitigation:**
- Distributed shares (quorum required)
- No single person has threshold
- Audit logging (all unseal attempts logged)
- Offline backups (hard to access)

**Result:** Requires collusion of multiple people, attempts logged

#### Scenario 6: Data Center Breach

**Attack:** Physical access to servers, hardware theft

**Mitigation:**
- Encrypted backups (AES-256-GCM)
- Encryption key separate from data
- Shamir shares split geographically
- Hardware security modules (TPM)

**Result:** Stolen hardware/data is worthless without keys

### Non-Goals

Platform does **NOT** protect against:

1. **Threats to user's local device** — If user's workstation is compromised, attacker can use that workstation's credentials
2. **Quantum computing** — Cryptography is vulnerable to large quantum computers (not yet practical)
3. **Threats to physical TPM** — If TPM hardware is replaced, physical security necessary
4. **Social engineering** — If user is tricked into revealing credentials, security reduced
5. **Threats from authorized insiders** — If someone with barrier shares and credentials goes rogue, they can attack system

## 8. Operational Security

### Access Control

Role-based access control (RBAC):

```
Admin
├─ Create users/roles
├─ Manage cluster
├─ Unseal barrier
└─ Rotate keys

Operator
├─ Start/stop services
├─ View logs/metrics
├─ Create backups
└─ View system status (no modifications)

User
├─ Request certificates
├─ Manage own DNS records
├─ View own secrets
└─ No privileged operations
```

### Audit Logging

All sensitive operations logged:

```json
{
  "timestamp": "2026-03-29T15:30:00Z",
  "action": "barrier_unseal",
  "actor": "root",
  "result": "success",
  "shares_used": 3,
  "system_state_before": "sealed",
  "system_state_after": "unsealed"
}
```

Logged operations:
- All authentication events
- Barrier unseal/seal
- Key generation/rotation
- Certificate issuance/revocation
- Configuration changes
- Admin operations

### Compliance

Platform supports compliance frameworks:

- **FIPS 140-3:** Cryptographic module validation
- **PCI-DSS:** Payment card security
- **HIPAA:** Healthcare data protection
- **SOC2:** Security auditing
- **ISO 27001:** Information security management

## 9. Cryptographic Algorithms

### Approved Algorithms

**Asymmetric (Signing):**
- RSA-PSS with SHA-256/384/512
- ECDSA with P-256/P-384/P-521
- EdDSA (Curve25519)

**Asymmetric (Encryption):**
- RSAES-OAEP with SHA-256
- ECDH with P-256/P-384/P-521

**Symmetric (Encryption):**
- AES-GCM-256 (preferred)
- ChaCha20-Poly1305
- AES-GCM-128 (minimum)

**Hashing:**
- SHA-256 (minimum for security)
- SHA-384
- SHA-512
- BLAKE2b (when available)

**Key Derivation:**
- PBKDF2
- Argon2id (preferred for passwords)
- HKDF

### Deprecated (Never Use)

- **RC4, DES, 3DES** — Cryptographically broken
- **MD5, SHA-1** — Collision attacks practical
- **RSA with PKCS#1 v1.5 padding** — Padding oracle attacks
- **ECB mode** — No semantic security
- **Stream ciphers without authentication** — No integrity verification
- **Static key material** — No forward secrecy

## Related Documentation

- [Binary Separation](binary-separation.md) - Process isolation and privilege separation
- [Security Model](security-model.md) - Zero-trust architecture
- [Deployment Guide](../operations/deployment-guide.md) - Secure configuration
- [Operational Runbook](../operations/operational-runbook.md) - Day-to-day operations
- [Backup & Recovery](../operations/backup-recovery.md) - Data protection

# Platformd P2P Mode

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

## Overview

Platformd P2P mode enables nodes to participate in the trusted DHT network for decentralized coordination, service discovery, and content distribution. The `--p2p` flag is a **modifier** that can be combined with any existing operating mode (standalone, raft, node) to add P2P network capabilities.

**Key Principle:** P2P is not a separate mode but an enhancement layer that enables DHT participation while preserving the underlying cluster architecture.

> **Cross-References:**
> - Network architecture: [02-network-architecture.md](02-network-architecture.md)
> - Security and trust model: [03-security-trust.md](03-security-trust.md)
> - Certificate authority: [05-certificate-authority.md](05-certificate-authority.md)
> - Consensus coordination: [06-consensus-coordination.md](06-consensus-coordination.md)

---

## Operating Modes with P2P

### Mode Combinations

| Base Mode | Command | Description |
|-----------|---------|-------------|
| `standalone` | `platformd --p2p` | Single node on P2P network |
| `raft` | `platformd --mode=raft --p2p` | Single-node Raft cluster on P2P network |
| `node` | `platformd --mode=node --p2p` | Multi-node Raft cluster on P2P network |

### Standalone + P2P

Single node participating directly in the P2P network without Raft consensus.

```
+------------------------------------------+
|           STANDALONE + P2P               |
|                                          |
|  +------------------------------------+  |
|  |         Platformd Node             |  |
|  |                                    |  |
|  |  +------------+  +-------------+   |  |
|  |  |   Local    |  |    P2P      |   |  |
|  |  |  Storage   |  |  Interface  |   |  |
|  |  +------------+  +------+------+   |  |
|  +-------------------------|----------+  |
|                            |             |
+----------------------------|-------------+
                             |
                             v
                    +------------------+
                    |   DHT Network    |
                    | (Kademlia Mesh)  |
                    +------------------+
```

**Use Cases:**
- Development and testing
- Edge devices with intermittent connectivity
- Observer nodes that consume but don't coordinate

**Characteristics:**
- No consensus overhead
- Direct DHT participation
- Single point of failure for local state

### Raft + P2P (Single-Node Cluster)

Single-node Raft cluster with P2P network participation. Useful for bootstrapping or solo deployments.

```
+------------------------------------------+
|            RAFT + P2P (Single)           |
|                                          |
|  +------------------------------------+  |
|  |     Raft Cluster (1 Node)          |  |
|  |                                    |  |
|  |  +------------+  +-------------+   |  |
|  |  |   Raft     |  |    P2P      |   |  |
|  |  |   Leader   |  |  Interface  |   |  |
|  |  | (Self)     |  +------+------+   |  |
|  |  +------------+         |          |  |
|  +-------------------------|----------+  |
|                            |             |
+----------------------------|-------------+
                             |
                             v
                    +------------------+
                    |   DHT Network    |
                    | (Kademlia Mesh)  |
                    +------------------+
```

**Use Cases:**
- Single-server deployments requiring Raft journal
- Bootstrap node for future cluster expansion
- High-availability prep without multi-node overhead

**Characteristics:**
- Raft journal for state durability
- Always leader (no consensus latency)
- Can expand to multi-node later

### Node + P2P (Multi-Node Cluster)

Multi-node Raft cluster where **only the leader communicates on the P2P network**.

```
+-----------------------------------------------------------------------+
|                     RAFT CLUSTER + P2P (Multi-Node)                   |
|                                                                       |
|  +-------------------+  +-------------------+  +-------------------+  |
|  |    Node 1         |  |    Node 2         |  |    Node 3         |  |
|  |    (Leader)       |  |    (Follower)     |  |    (Follower)     |  |
|  |                   |  |                   |  |                   |  |
|  |  +-------------+  |  |  +-------------+  |  |  +-------------+  |  |
|  |  | P2P Active  |  |  |  | P2P Standby |  |  |  | P2P Standby |  |  |
|  |  +------+------+  |  |  +-------------+  |  |  +-------------+  |  |
|  |         |         |  |                   |  |                   |  |
|  +---------|---------+  +-------------------+  +-------------------+  |
|            |                    ^                      ^              |
|            |         Raft Replication                  |              |
|            |<------------------------------------------+              |
|            |                                                          |
+------------|----------------------------------------------------------+
             |
             v
    +------------------+
    |   DHT Network    |
    | (Kademlia Mesh)  |
    +------------------+
```

**Critical Design Decision:** Only the Raft **leader** actively participates in P2P communication.

**Rationale:**
- Avoids duplicate DHT registrations from the same logical service
- Prevents conflicting announcements to the network
- Ensures consistent state representation
- Simplifies failover semantics

**Characteristics:**
- Leader handles all P2P traffic
- Followers maintain P2P state via Raft replication
- Automatic P2P state transfer on leader change

---

## IDevID/EK Enrollment Flow

Before joining the P2P network, nodes must obtain cryptographic identity credentials through a multi-stage enrollment process.

### Enrollment Decision Tree

```
+------------------+
|  Node Startup    |
|  with --p2p      |
+--------+---------+
         |
         v
+------------------+
| Check TPM for EK |
+--------+---------+
         |
    +----+----+
    |         |
    v         v
  [No EK]   [Has EK]
    |         |
    v         |
+------------------+     |
| ACME endorse-01  |     |
| (Requires EAB)   |     |
+--------+---------+     |
         |               |
         v               |
    [EK Endorsed]        |
         |               |
         +-------+-------+
                 |
                 v
        +------------------+
        | Check for valid  |
        |     IDevID       |
        +--------+---------+
                 |
            +----+----+
            |         |
            v         v
       [No IDevID] [Has Valid IDevID]
            |              |
            v              |
   +------------------+    |
   | ACME enroll-01   |    |
   | to Privacy CA    |    |
   +--------+---------+    |
            |              |
            v              |
       [IDevID Issued]     |
            |              |
            +------+-------+
                   |
                   v
          +------------------+
          | Present IDevID   |
          | for P2P Join     |
          +--------+---------+
                   |
                   v
          +------------------+
          | TPM Quote proves |
          | cert binding     |
          +--------+---------+
                   |
                   v
          +------------------+
          | Peer verifies    |
          | quote + chain    |
          +--------+---------+
                   |
                   v
          +------------------+
          | Assigned to DHT  |
          | routing table    |
          +------------------+
```

### Complete Enrollment Sequence

```
Node                          Privacy CA (FROST Pool)         Peer Node
 |                                    |                           |
 | 1. Check TPM for EK Certificate    |                           |
 |                                    |                           |
 |--- [If no EK] ------------------------------------------>|     |
 |    ACME endorse-01 Challenge       |                           |
 |    (with EAB credentials)          |                           |
 |<--- EK Endorsement Certificate ----|                           |
 |                                    |                           |
 | 2. Generate IDevID key in TPM      |                           |
 |                                    |                           |
 |--- ACME enroll-01 Challenge ------>|                           |
 |    - CSR with IDevID public key    |                           |
 |    - TPM Quote (PCRs 0,2,7)        |                           |
 |    - EK Certificate                |                           |
 |    - Nonce (freshness)             |                           |
 |                                    |                           |
 |<--- IDevID Certificate ------------|                           |
 |     (FROST threshold signed)       |                           |
 |                                    |                           |
 | 3. Initiate P2P Join               |                           |
 |                                    |                           |
 |--- Present IDevID + TPM Quote ------------------------------------>|
 |                                    |                           |
 |                                    |    4. Verify:             |
 |                                    |    - Quote signature      |
 |                                    |    - Nonce freshness      |
 |                                    |    - Certificate chain    |
 |                                    |    - Trust level          |
 |                                    |                           |
 |<--- P2P Join Accepted + DHT Assignment ---------------------------|
 |                                    |                           |
```

---

## ACME endorse-01 Challenge

### Purpose

The `endorse-01` challenge provides EK (Endorsement Key) endorsement for TPMs without manufacturer certificates. This is required when:

- TPM lacks a manufacturer-issued EK certificate
- EK certificate chain is incomplete or untrusted
- TPM is from an unknown manufacturer

### EAB Requirements

External Account Binding (EAB) credentials are **required** for endorse-01:

| Field | Description |
|-------|-------------|
| `eab_kid` | Key Identifier from CA administrator |
| `eab_hmac` | HMAC key for binding proof |

**Why EAB?** Prevents abuse by requiring pre-authorization. Without EAB, attackers could flood the CA with endorsement requests.

### EAB Credential Rotation

EAB credentials require periodic rotation to limit exposure window from potential compromise. The platform implements a **90-day rotation schedule** with grace periods for in-flight requests.

**Rotation Schedule:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Rotation Interval | 90 days | Balance between security and operational overhead |
| Grace Period | 24 hours | Allows in-flight requests to complete |
| Maximum Age | 120 days | Absolute limit regardless of rotation success |
| Usage Limit | 10,000 | Force rotation after heavy use even before 90 days |

**Solution**: Implement automatic EAB credential rotation with secure lifecycle management.

```go
// EABCredentialManager handles secure EAB credential lifecycle
type EABCredentialManager struct {
    mu              sync.RWMutex
    currentCreds    *EABCredentials
    previousCreds   *EABCredentials  // Allow grace period for in-flight requests
    rotationConfig  EABRotationConfig
    storage         SecureCredentialStorage
    caClient        CAAdminClient
}

// EABCredentials represents a set of EAB credentials
type EABCredentials struct {
    KID           string    // Key Identifier
    HMAC          []byte    // HMAC secret (sensitive - never log)
    IssuedAt      time.Time // When credentials were issued
    ExpiresAt     time.Time // Expiration time
    RotationID    [32]byte  // Unique identifier for this rotation
    UsageCount    atomic.Uint64  // Number of times used
    MaxUsage      uint64    // Maximum allowed uses (0 = unlimited)
}

// EABRotationConfig defines rotation policy
type EABRotationConfig struct {
    RotationInterval   time.Duration  // How often to rotate
    GracePeriod        time.Duration  // How long to accept old credentials
    MaxCredentialAge   time.Duration  // Maximum age before forced rotation
    MaxUsagePerCred    uint64         // Max uses before forced rotation (0 = unlimited)
    RotateOnCompromise bool           // Immediate rotation on suspected compromise
}

const (
    DefaultEABRotationInterval = 90 * 24 * time.Hour // 90 days
    DefaultEABGracePeriod      = 24 * time.Hour      // 24 hour overlap for in-flight requests
    DefaultEABMaxAge           = 120 * 24 * time.Hour // 120 days absolute max
    DefaultEABMaxUsage         = 10000               // Max 10,000 endorsements per credential
)

// NewEABCredentialManager creates a manager with default rotation config
func NewEABCredentialManager(storage SecureCredentialStorage, caClient CAAdminClient) *EABCredentialManager {
    return &EABCredentialManager{
        rotationConfig: EABRotationConfig{
            RotationInterval:   DefaultEABRotationInterval,
            GracePeriod:        DefaultEABGracePeriod,
            MaxCredentialAge:   DefaultEABMaxAge,
            MaxUsagePerCred:    DefaultEABMaxUsage,
            RotateOnCompromise: true,
        },
        storage:  storage,
        caClient: caClient,
    }
}

// Start begins the rotation management loop
func (m *EABCredentialManager) Start(ctx context.Context) error {
    // Load existing credentials
    creds, err := m.storage.LoadEABCredentials()
    if err != nil {
        return fmt.Errorf("failed to load EAB credentials: %w", err)
    }

    m.mu.Lock()
    m.currentCreds = creds
    m.mu.Unlock()

    // Start rotation ticker
    go m.rotationLoop(ctx)

    return nil
}

// rotationLoop periodically checks and rotates credentials
func (m *EABCredentialManager) rotationLoop(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Hour) // Check every hour
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if m.shouldRotate() {
                if err := m.rotateCredentials(ctx); err != nil {
                    // Log error but don't crash - will retry next tick
                    log.Printf("EAB rotation failed: %v", err)
                }
            }
        }
    }
}

// shouldRotate checks if credentials need rotation
func (m *EABCredentialManager) shouldRotate() bool {
    m.mu.RLock()
    creds := m.currentCreds
    m.mu.RUnlock()

    if creds == nil {
        return true // No credentials - need to obtain
    }

    now := time.Now()

    // Check age-based rotation
    if creds.IssuedAt.Add(m.rotationConfig.RotationInterval).Before(now) {
        return true
    }

    // Check absolute expiry
    if creds.ExpiresAt.Before(now) {
        return true
    }

    // Check usage-based rotation
    if m.rotationConfig.MaxUsagePerCred > 0 &&
       creds.UsageCount.Load() >= m.rotationConfig.MaxUsagePerCred {
        return true
    }

    return false
}

// rotateCredentials performs the credential rotation
func (m *EABCredentialManager) rotateCredentials(ctx context.Context) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Request new credentials from CA admin API
    newCreds, err := m.caClient.RequestNewEABCredentials(ctx, m.buildRotationRequest())
    if err != nil {
        return fmt.Errorf("failed to request new EAB credentials: %w", err)
    }

    // Move current to previous (for grace period)
    m.previousCreds = m.currentCreds

    // Set new as current
    m.currentCreds = &EABCredentials{
        KID:        newCreds.KID,
        HMAC:       newCreds.HMAC,
        IssuedAt:   time.Now(),
        ExpiresAt:  time.Now().Add(m.rotationConfig.MaxCredentialAge),
        RotationID: sha256.Sum256(append([]byte(newCreds.KID), newCreds.HMAC...)),
        MaxUsage:   m.rotationConfig.MaxUsagePerCred,
    }

    // Persist new credentials securely
    if err := m.storage.SaveEABCredentials(m.currentCreds); err != nil {
        return fmt.Errorf("failed to save new EAB credentials: %w", err)
    }

    // Schedule revocation of old credentials after grace period
    if m.previousCreds != nil {
        go m.scheduleRevocation(m.previousCreds, m.rotationConfig.GracePeriod)
    }

    log.Printf("EAB credentials rotated successfully. New KID: %s", m.currentCreds.KID)
    return nil
}

// GetCredentials returns current valid credentials
func (m *EABCredentialManager) GetCredentials() (*EABCredentials, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    if m.currentCreds == nil {
        return nil, ErrNoEABCredentials
    }

    if m.currentCreds.ExpiresAt.Before(time.Now()) {
        return nil, ErrEABCredentialsExpired
    }

    // Increment usage counter
    m.currentCreds.UsageCount.Add(1)

    return m.currentCreds, nil
}

// ValidateCredentials checks if the provided KID/HMAC are valid
// Returns true if credentials match current OR previous (within grace period)
func (m *EABCredentialManager) ValidateCredentials(kid string, hmac []byte) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()

    // Check current credentials
    if m.currentCreds != nil &&
       m.currentCreds.KID == kid &&
       hmac.Equal(m.currentCreds.HMAC, hmac) {
        return true
    }

    // Check previous credentials (within grace period)
    if m.previousCreds != nil &&
       m.previousCreds.KID == kid &&
       hmac.Equal(m.previousCreds.HMAC, hmac) &&
       m.previousCreds.IssuedAt.Add(m.rotationConfig.RotationInterval).Add(m.rotationConfig.GracePeriod).After(time.Now()) {
        return true
    }

    return false
}

// ForceRotation triggers immediate credential rotation (e.g., on suspected compromise)
func (m *EABCredentialManager) ForceRotation(ctx context.Context, reason string) error {
    log.Printf("SECURITY: Forced EAB rotation triggered. Reason: %s", reason)

    if err := m.rotateCredentials(ctx); err != nil {
        return fmt.Errorf("forced rotation failed: %w", err)
    }

    // Immediately revoke old credentials (no grace period)
    m.mu.Lock()
    m.previousCreds = nil
    m.mu.Unlock()

    return nil
}

// scheduleRevocation revokes old credentials after grace period expires
// This ensures in-flight requests using old credentials can complete while
// preventing indefinite use of rotated credentials
func (m *EABCredentialManager) scheduleRevocation(creds *EABCredentials, delay time.Duration) {
    // Create a timer for the grace period
    timer := time.NewTimer(delay)
    defer timer.Stop()

    select {
    case <-timer.C:
        // Grace period expired - revoke the old credentials
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()

        if err := m.caClient.RevokeEABCredentials(ctx, creds.KID); err != nil {
            log.Printf("SECURITY: Failed to revoke old EAB credentials %s after grace period: %v", creds.KID, err)
            // Schedule retry with exponential backoff
            go m.retryRevocation(creds, 1)
        } else {
            log.Printf("EAB credentials revoked after grace period: KID=%s, age=%v",
                creds.KID, time.Since(creds.IssuedAt))
        }
    }
}

// retryRevocation attempts credential revocation with exponential backoff
func (m *EABCredentialManager) retryRevocation(creds *EABCredentials, attempt int) {
    maxAttempts := 5
    if attempt > maxAttempts {
        log.Printf("CRITICAL: Failed to revoke EAB credentials %s after %d attempts", creds.KID, maxAttempts)
        return
    }

    backoff := time.Duration(1<<uint(attempt)) * time.Minute // 2, 4, 8, 16, 32 minutes
    time.Sleep(backoff)

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := m.caClient.RevokeEABCredentials(ctx, creds.KID); err != nil {
        log.Printf("Revocation retry %d failed for %s: %v", attempt, creds.KID, err)
        go m.retryRevocation(creds, attempt+1)
    } else {
        log.Printf("EAB credentials revoked on retry %d: %s", attempt, creds.KID)
    }
}

// buildRotationRequest creates the request for new credentials
func (m *EABCredentialManager) buildRotationRequest() *EABRotationRequest {
    return &EABRotationRequest{
        PreviousKID:     m.currentCreds.KID,
        PreviousRotationID: m.currentCreds.RotationID,
        RequestTime:     time.Now(),
        Reason:          "scheduled_rotation",
    }
}

// EABRotationRequest is sent to CA admin to request new credentials
type EABRotationRequest struct {
    PreviousKID        string
    PreviousRotationID [32]byte
    RequestTime        time.Time
    Reason             string  // scheduled_rotation, usage_exceeded, forced, compromise
}

// SecureCredentialStorage interface for secure credential persistence
type SecureCredentialStorage interface {
    LoadEABCredentials() (*EABCredentials, error)
    SaveEABCredentials(*EABCredentials) error
}

// CAAdminClient interface for CA administrative operations
type CAAdminClient interface {
    RequestNewEABCredentials(ctx context.Context, req *EABRotationRequest) (*EABCredentials, error)
    RevokeEABCredentials(ctx context.Context, kid string) error
}

// EAB credential errors
var (
    ErrNoEABCredentials     = errors.New("no EAB credentials available")
    ErrEABCredentialsExpired = errors.New("EAB credentials expired")
    ErrEABRotationFailed    = errors.New("EAB credential rotation failed")
)
```

### EAB Security Best Practices

1. **Never log HMAC secrets** - Only log KID for debugging
2. **Use secure storage** - Store credentials in TPM-sealed storage when possible
3. **Monitor usage** - Alert on unusual usage patterns
4. **Rotate on compromise** - Immediately rotate if any breach suspected
5. **Grace periods** - Allow overlap to prevent in-flight request failures
6. **Audit trail** - Log all rotation events with timestamps

### TCG_CSR_IDEVID Structure

```go
// TCGCSRIDevID represents the CSR structure for ACME endorse-01
type TCGCSRIDevID struct {
    // EK public key to be endorsed
    EKPublic []byte `asn1:"tag:0"`

    // TPM2_Certify proof binding EK to TPM
    CertifyInfo []byte `asn1:"tag:1"`

    // Signature over CertifyInfo using AK
    CertifySignature []byte `asn1:"tag:2"`

    // Attestation Key certificate (if available)
    AKCertificate []byte `asn1:"tag:3,optional"`

    // TPM manufacturer info
    TPMInfo TPMManufacturerInfo `asn1:"tag:4"`
}

// TPMManufacturerInfo contains TPM identification
type TPMManufacturerInfo struct {
    Manufacturer string // e.g., "Infineon", "STMicroelectronics"
    Model        string // TPM model identifier
    Firmware     string // Firmware version
    VendorID     uint32 // TCG Vendor ID
}
```

### endorse-01 Implementation

```go
// EndorseChallenge performs ACME endorse-01 for EK endorsement
func (c *ACMEClient) EndorseChallenge(ctx context.Context, tpm TPMInterface, eabKID, eabHMAC string) (*x509.Certificate, error) {
    // Validate EAB credentials are provided
    if eabKID == "" || eabHMAC == "" {
        return nil, ErrEABRequired
    }

    // Get EK public key from TPM
    ekPub, err := tpm.GetEKPublic(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get EK public: %w", err)
    }

    // Create Attestation Key for signing
    akHandle, err := tpm.CreateAK(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create AK: %w", err)
    }
    defer tpm.FlushContext(ctx, akHandle)

    // Generate TPM2_Certify proof binding EK to this TPM
    certifyInfo, certifySig, err := tpm.Certify(ctx, akHandle, ekPub)
    if err != nil {
        return nil, fmt.Errorf("failed to certify EK: %w", err)
    }

    // Get TPM info
    tpmInfo, err := tpm.GetManufacturerInfo(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get TPM info: %w", err)
    }

    // Build TCG_CSR_IDEVID
    csr := &TCGCSRIDevID{
        EKPublic:         ekPub,
        CertifyInfo:      certifyInfo,
        CertifySignature: certifySig,
        TPMInfo: TPMManufacturerInfo{
            Manufacturer: tpmInfo.Manufacturer,
            Model:        tpmInfo.Model,
            Firmware:     tpmInfo.FirmwareVersion,
            VendorID:     tpmInfo.VendorID,
        },
    }

    // Create ACME order with EAB binding
    order, err := c.newOrderWithEAB(ctx, "endorse-01", eabKID, eabHMAC)
    if err != nil {
        return nil, fmt.Errorf("failed to create order: %w", err)
    }

    // Submit CSR
    csrDER, err := asn1.Marshal(csr)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal CSR: %w", err)
    }

    // Finalize order and get EK endorsement certificate
    return c.finalizeOrder(ctx, order, csrDER)
}

// newOrderWithEAB creates an ACME order with External Account Binding
func (c *ACMEClient) newOrderWithEAB(ctx context.Context, challengeType, kid, hmacKey string) (*Order, error) {
    // Decode HMAC key
    hmacBytes, err := base64.RawURLEncoding.DecodeString(hmacKey)
    if err != nil {
        return nil, ErrInvalidEABHMAC
    }

    // Create EAB signature
    eabPayload := c.accountKey.Public()
    mac := hmac.New(sha256.New, hmacBytes)
    mac.Write(eabPayload)
    eabSignature := mac.Sum(nil)

    // Build order request with EAB
    req := &OrderRequest{
        Identifiers: []Identifier{{Type: challengeType, Value: "ek-endorsement"}},
        ExternalAccountBinding: &EAB{
            KID:       kid,
            Algorithm: "HS256",
            Signature: base64.RawURLEncoding.EncodeToString(eabSignature),
        },
    }

    return c.submitOrder(ctx, req)
}
```

### CA Verification Process

```go
// VerifyEndorseChallenge validates an endorse-01 CSR
func (ca *PrivacyCA) VerifyEndorseChallenge(csr *TCGCSRIDevID, eab *EAB) (*x509.Certificate, error) {
    // Step 1: Verify EAB credentials
    if !ca.validateEAB(eab) {
        return nil, ErrInvalidEAB
    }

    // Step 2: Verify TPM2_Certify signature
    if err := ca.verifyCertifySignature(csr); err != nil {
        return nil, fmt.Errorf("certify verification failed: %w", err)
    }

    // Step 3: Verify EK is bound to legitimate TPM
    if err := ca.verifyTPMBinding(csr); err != nil {
        return nil, fmt.Errorf("TPM binding verification failed: %w", err)
    }

    // Step 4: Check TPM against known vulnerabilities
    cveStatus := ca.checkCVEStatus(csr.TPMInfo)
    if cveStatus == "blocked" {
        return nil, ErrTPMBlocked{Reason: "known vulnerability"}
    }

    // Step 5: Issue EK endorsement certificate
    return ca.issueEKEndorsement(csr)
}
```

---

## ACME enroll-01 Challenge

### Purpose

The `enroll-01` challenge obtains an IDevID (Initial Device Identifier) certificate from the Privacy CA. This is the primary identity certificate used for P2P network participation.

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| Valid EK Certificate | Either manufacturer-issued or via endorse-01 |
| TPM 2.0 | Hardware TPM required for trusted status |
| Network Access | Connectivity to Privacy CA |

### enroll-01 Implementation

```go
// EnrollChallenge performs ACME enroll-01 for IDevID certificate
func (c *ACMEClient) EnrollChallenge(ctx context.Context, tpm TPMInterface) (*x509.Certificate, error) {
    // Generate IDevID key pair in TPM
    iakHandle, iakPub, err := tpm.CreateIDevIDKey(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create IDevID key: %w", err)
    }

    // Get EK certificate (required)
    ekCert, err := tpm.GetEKCertificate(ctx)
    if err != nil {
        return nil, fmt.Errorf("EK certificate required: %w", err)
    }

    // Generate fresh nonce for quote
    nonce := make([]byte, 32)
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }

    // Create TPM Quote over PCRs 0, 2, 7
    quote, err := tpm.Quote(ctx, iakHandle, nonce, []int{0, 2, 7})
    if err != nil {
        return nil, fmt.Errorf("failed to create quote: %w", err)
    }

    // Build TCG_CSR_IDEVID for enroll-01
    csr := &TCGCSRIDevIDEnroll{
        // IDevID key information
        IDevIDPublic: iakPub,

        // IAK attestation proving key is TPM-bound
        IAKAttestation: quote.Attestation,
        IAKSignature:   quote.Signature,

        // TPM Quote for platform state
        Quote:      quote.QuoteData,
        QuoteSig:   quote.QuoteSignature,
        PCRDigest:  quote.PCRDigest,
        PCRValues:  quote.PCRValues,
        Nonce:      nonce,

        // EK certificate chain
        EKCertificate: ekCert.Raw,

        // Timestamp for freshness
        Timestamp: time.Now().Unix(),
    }

    // Create ACME order
    order, err := c.newOrder(ctx, "enroll-01")
    if err != nil {
        return nil, fmt.Errorf("failed to create order: %w", err)
    }

    // Submit CSR and get IDevID certificate
    csrDER, err := asn1.Marshal(csr)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal CSR: %w", err)
    }

    return c.finalizeOrder(ctx, order, csrDER)
}

// TCGCSRIDevIDEnroll represents the enroll-01 CSR structure
type TCGCSRIDevIDEnroll struct {
    // IDevID key to be certified
    IDevIDPublic []byte `asn1:"tag:0"`

    // IAK attestation proving IDevID key is TPM-bound
    IAKAttestation []byte `asn1:"tag:1"`
    IAKSignature   []byte `asn1:"tag:2"`

    // TPM Quote proving platform state
    Quote     []byte `asn1:"tag:3"`
    QuoteSig  []byte `asn1:"tag:4"`
    PCRDigest []byte `asn1:"tag:5"`
    PCRValues []byte `asn1:"tag:6"`
    Nonce     []byte `asn1:"tag:7"`

    // EK certificate for trust chain
    EKCertificate []byte `asn1:"tag:8"`

    // Timestamp for freshness verification
    Timestamp int64 `asn1:"tag:9"`
}
```

### Privacy CA Verification

```go
// VerifyEnrollChallenge validates an enroll-01 CSR and issues IDevID
func (ca *PrivacyCA) VerifyEnrollChallenge(csr *TCGCSRIDevIDEnroll) (*x509.Certificate, error) {
    // Step 1: Verify nonce freshness (+/- 100ms)
    requestTime := time.Unix(csr.Timestamp, 0)
    if time.Since(requestTime).Abs() > 100*time.Millisecond {
        return nil, ErrNonceExpired
    }

    // Step 2: Parse and verify EK certificate
    ekCert, err := x509.ParseCertificate(csr.EKCertificate)
    if err != nil {
        return nil, fmt.Errorf("invalid EK certificate: %w", err)
    }

    // Step 3: Verify EK certificate chain to trusted root
    if err := ca.verifyEKChain(ekCert); err != nil {
        return nil, fmt.Errorf("EK chain verification failed: %w", err)
    }

    // Step 4: Verify TPM Quote signature
    if err := ca.verifyQuoteSignature(csr); err != nil {
        return nil, fmt.Errorf("quote signature invalid: %w", err)
    }

    // Step 5: Verify nonce is embedded in quote
    if !bytes.Contains(csr.Quote, csr.Nonce) {
        return nil, ErrNonceMismatch
    }

    // Step 6: Verify IAK attestation (IDevID key is TPM-bound)
    if err := ca.verifyIAKAttestation(csr); err != nil {
        return nil, fmt.Errorf("IAK attestation failed: %w", err)
    }

    // Step 7: Determine trust level
    trustLevel := ca.determineTrustLevel(ekCert)

    // Step 8: Issue IDevID certificate via FROST threshold signing
    return ca.issueIDevID(csr.IDevIDPublic, trustLevel, ekCert)
}

// determineTrustLevel evaluates EK to assign trust level
func (ca *PrivacyCA) determineTrustLevel(ekCert *x509.Certificate) TrustLevel {
    // Check if hardware TPM
    if ca.isSimulatorEK(ekCert) {
        return TrustLevelUntrusted
    }

    // Check manufacturer whitelist
    manufacturer := ca.extractManufacturer(ekCert)
    if !ca.isWhitelistedManufacturer(manufacturer) {
        return TrustLevelUntrusted
    }

    // Check for known CVEs
    cveStatus := ca.checkManufacturerCVE(ekCert)
    if cveStatus == "blocked" || cveStatus == "critical" {
        return TrustLevelUntrusted
    }

    return TrustLevelTrusted
}
```

---

## Trust Level Assignment

### Binary Trust Model (CA-Based)

The DHT uses a **binary trust model** - nodes are either **Trusted** or **Untrusted**. Trust is determined **purely** by EK certificate chain validation against configured Manufacturer CAs.

**Key Principle**: Trust is NOT hardcoded based on TPM type. It is determined entirely by whether the EK certificate validates to a **configured** Manufacturer CA in the Privacy CA's trust store.

```go
type TrustLevel uint8

const (
    TrustLevelUntrusted TrustLevel = 0 // EK doesn't chain to configured CA
    TrustLevelTrusted   TrustLevel = 1 // EK chains to configured CA
)
```

### Trust Determination (CA-Based)

| EK Certificate Chain | Trust Level |
|---------------------|-------------|
| Validates to configured Manufacturer CA | **TRUSTED** |
| Does NOT validate to any configured CA | **UNTRUSTED** |

**Examples** (assuming Intel and AMD CAs are configured):

| TPM Type | Manufacturer | EK Chain Validates To | Trust Level |
|----------|--------------|----------------------|-------------|
| Intel fTPM (PTT) | Intel | Intel CA (configured) | **TRUSTED** |
| AMD fTPM | AMD | AMD CA (configured) | **TRUSTED** |
| Infineon dTPM | Infineon | Infineon CA (if configured) | **TRUSTED** |
| swtpm | Self-signed | No CA (self-signed) | **UNTRUSTED** |
| Unknown vendor | Unknown | No configured CA | **UNTRUSTED** |

### Privacy CA Configuration

The Privacy CA dynamically loads trusted Manufacturer CA certificates via the go-xkms CA API (consumed through go-quicbaas SDK). No code changes needed to add/remove trusted manufacturers:

```go
// Dynamic import of manufacturer EK CA certificates
err := privacyCA.ImportEndorsementKeyCertificate(manufacturerCACert)

// Recursive import from certificate AIA extensions
err := privacyCA.ImportIssuingCAs(ekCert)
```

**Certificate Storage**: Imported certificates are stored in the filesystem:
```
/app/data/ca/certs/
├── intel-tpm-ek-ca.pem        # Intel fTPM + dTPM
├── amd-tpm-ek-ca.pem          # AMD fTPM + dTPM
├── infineon-tpm-ek-ca.pem     # Infineon dTPM
├── stmicro-tpm-ek-ca.pem      # STMicroelectronics
├── nuvoton-tpm-ek-ca.pem      # Nuvoton
└── ...                        # Additional manufacturers
```

### Trust Level Capabilities

| Capability | Trusted | Untrusted |
|------------|---------|-----------|
| Join P2P network | Yes | Yes |
| Route DHT messages | Yes | Yes |
| Observe network state | Yes | Yes |
| **Earn reputation** | Yes | **No** |
| **Assume roles** | All roles | **Observer only** |
| **FROST participation** | Yes | **No** |
| **CA pool membership** | Yes | **No** |

### Untrusted Node DDoS Work Requirement

Untrusted nodes must complete proof-of-work challenges to prevent Sybil attacks:

```go
// DDoSWorkConfig defines PoW requirements for untrusted nodes
type DDoSWorkConfig struct {
    // Difficulty: Number of leading zero bits required
    Difficulty uint8 // Default: 20 (approx 1 second on modern CPU)

    // Challenge validity period
    ChallengeValidity time.Duration // Default: 1 hour

    // Rate limiting for untrusted nodes
    MaxRequestsPerMinute int // Default: 10
}

// VerifyDDoSWork checks proof-of-work for untrusted node request
func VerifyDDoSWork(challenge []byte, solution []byte, difficulty uint8) bool {
    hash := sha256.Sum256(append(challenge, solution...))
    leadingZeros := countLeadingZeroBits(hash[:])
    return leadingZeros >= int(difficulty)
}

### Adaptive PoW Difficulty

Static PoW difficulty creates two problems: too easy during attacks (ineffective protection) and too hard during normal operation (poor user experience). The platform implements an **adaptive difficulty controller** that adjusts based on network load.

**Adaptive Behavior:**

| Network State | Load Factor | Difficulty | Approx. Time |
|---------------|-------------|------------|--------------|
| Idle | 0-25% | 16 bits | ~65K hashes |
| Normal | 25-50% | 18-20 bits | ~260K-1M hashes |
| Busy | 50-70% | 20-22 bits | ~1M-4M hashes |
| Heavy | 70-85% | 22-24 bits | ~4M-16M hashes |
| Attack/Overload | 85-100% | 24-28 bits | ~16M-268M hashes |

**Key Properties:**
- Difficulty adjusts every 10 seconds based on rolling load average
- Higher difficulty during suspected attacks throttles malicious requests
- Lower difficulty during normal operation preserves user experience
- Thread-safe atomic operations for concurrent access

```go
// AdaptiveDifficultyController manages dynamic PoW difficulty
type AdaptiveDifficultyController struct {
    baseDifficulty     uint8
    currentDifficulty  uint32           // Atomic for thread safety
    loadSamples        []float64        // Rolling window of load samples
    sampleWindow       int              // Number of samples to keep
    adjustmentInterval time.Duration    // How often to recalculate
    lastAdjustment     int64            // Unix nano, atomic
    mu                 sync.RWMutex
}

// DifficultyThresholds define load-based difficulty levels
var DifficultyThresholds = []struct {
    LoadFactor float64
    Difficulty uint8
}{
    {0.00, 16},  // Minimal load: easy PoW (~65K hashes)
    {0.25, 18},  // Light load
    {0.50, 20},  // Moderate load: default
    {0.70, 22},  // Heavy load
    {0.85, 24},  // Very heavy load
    {0.95, 26},  // Near capacity: hard PoW
    {1.00, 28},  // At capacity: maximum difficulty
}

// NewAdaptiveDifficultyController creates an adaptive controller
func NewAdaptiveDifficultyController() *AdaptiveDifficultyController {
    return &AdaptiveDifficultyController{
        baseDifficulty:     20,
        loadSamples:        make([]float64, 0, 60), // 60 samples
        sampleWindow:       60,
        adjustmentInterval: 10 * time.Second,
    }
}

// GetCurrentDifficulty returns the current adaptive difficulty
func (c *AdaptiveDifficultyController) GetCurrentDifficulty() uint8 {
    return uint8(atomic.LoadUint32(&c.currentDifficulty))
}

// RecordLoadSample adds a new load measurement
func (c *AdaptiveDifficultyController) RecordLoadSample(load float64) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if load < 0 {
        load = 0
    }
    if load > 1 {
        load = 1
    }

    c.loadSamples = append(c.loadSamples, load)
    if len(c.loadSamples) > c.sampleWindow {
        c.loadSamples = c.loadSamples[1:]
    }
}

// AdjustDifficulty recalculates difficulty based on recent load
func (c *AdaptiveDifficultyController) AdjustDifficulty() {
    // Rate limit adjustments
    now := time.Now().UnixNano()
    lastAdj := atomic.LoadInt64(&c.lastAdjustment)
    if time.Duration(now-lastAdj) < c.adjustmentInterval {
        return
    }

    c.mu.RLock()
    samples := make([]float64, len(c.loadSamples))
    copy(samples, c.loadSamples)
    c.mu.RUnlock()

    if len(samples) == 0 {
        return
    }

    // Calculate average load
    var sum float64
    for _, s := range samples {
        sum += s
    }
    avgLoad := sum / float64(len(samples))

    // Find appropriate difficulty
    newDifficulty := DifficultyThresholds[0].Difficulty
    for _, threshold := range DifficultyThresholds {
        if avgLoad >= threshold.LoadFactor {
            newDifficulty = threshold.Difficulty
        }
    }

    old := atomic.SwapUint32(&c.currentDifficulty, uint32(newDifficulty))
    atomic.StoreInt64(&c.lastAdjustment, now)

    if uint32(newDifficulty) != old {
        log.Info("adaptive difficulty adjusted",
            "previous", old,
            "new", newDifficulty,
            "avgLoad", avgLoad)
    }
}
```

> **Cross-Reference:** See [03-security-trust.md](03-security-trust.md) for complete TPM trust policy.

---

## Cluster-P2P Integration

### Leader-Only P2P Communication

In multi-node Raft clusters, **only the leader communicates on the P2P network**:

```
+-----------------------------------------------------------------------+
|                    CLUSTER-P2P STATE FLOW                             |
|                                                                       |
|   +-----------------+                                                 |
|   |  Leader Node    |                                                 |
|   |                 |                                                 |
|   | +-------------+ |     +------------------+                        |
|   | | P2P Manager |------>| DHT Network      |                        |
|   | | (ACTIVE)    | |     | - Routing table  |                        |
|   | +------+------+ |     | - Service disco  |                        |
|   |        |        |     | - Content store  |                        |
|   +--------|--------+     +------------------+                        |
|            |                                                          |
|            | Raft Replication                                         |
|            | (P2P state included)                                     |
|            |                                                          |
|   +--------v--------+     +-----------------+                         |
|   |  Follower 1     |     |  Follower 2     |                         |
|   |                 |     |                 |                         |
|   | +-------------+ |     | +-------------+ |                         |
|   | | P2P Manager | |     | | P2P Manager | |                         |
|   | | (STANDBY)   | |     | | (STANDBY)   | |                         |
|   | +-------------+ |     | +-------------+ |                         |
|   +-----------------+     +-----------------+                         |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Why Leader-Only?

1. **No Duplicate DHT Registrations:** Each cluster service appears once in DHT
2. **No Conflicting Announcements:** Single source of truth for service state
3. **Consistent State:** Leader's view is authoritative
4. **Simplified Failover:** Clear handoff semantics

### P2P State Replication

P2P state is replicated via Raft to all followers:

```go
// P2PState contains state replicated via Raft
type P2PState struct {
    // DHT routing table snapshot
    RoutingTable *RoutingTableSnapshot

    // Registered services
    RegisteredServices []ServiceRegistration

    // Active connections
    PeerConnections []PeerConnection

    // Content announcements
    ContentAnnouncements []ContentAnnouncement

    // Last DHT refresh timestamp
    LastRefresh time.Time
}

// P2PStateUpdate is a Raft log entry for P2P state changes
type P2PStateUpdate struct {
    Type      P2PUpdateType
    Timestamp time.Time
    Payload   []byte
}

type P2PUpdateType uint8

const (
    P2PUpdateRoutingTable P2PUpdateType = iota
    P2PUpdateServiceRegister
    P2PUpdateServiceDeregister
    P2PUpdatePeerConnect
    P2PUpdatePeerDisconnect
    P2PUpdateContentAnnounce
    P2PUpdateContentWithdraw
)
```

### Leader Change Protocol

When leadership changes, the new leader inherits P2P state:

```
Old Leader              Raft Cluster            New Leader           DHT Network
    |                        |                       |                    |
    | 1. Leadership lost     |                       |                    |
    |----------------------->|                       |                    |
    |                        |                       |                    |
    | 2. Deactivate P2P      |                       |                    |
    |    (stop announcements)|                       |                    |
    |                        |                       |                    |
    |                        | 3. Leader election    |                    |
    |                        |---------------------->|                    |
    |                        |                       |                    |
    |                        |                       | 4. Activate P2P    |
    |                        |                       |    from replicated |
    |                        |                       |    state           |
    |                        |                       |                    |
    |                        |                       | 5. Re-announce to  |
    |                        |                       |    DHT             |
    |                        |                       |------------------->|
    |                        |                       |                    |
    |                        |                       | 6. Resume normal   |
    |                        |                       |    P2P operations  |
    |                        |                       |                    |
```

### Leader Change Implementation

```go
// P2PManager handles P2P network participation
type P2PManager struct {
    raftNode    *RaftNode
    dht         *DHT
    state       *P2PState
    active      atomic.Bool
    mu          sync.RWMutex
}

// OnBecomeLeader activates P2P participation
func (pm *P2PManager) OnBecomeLeader(ctx context.Context) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    // Load replicated state
    state, err := pm.raftNode.GetP2PState()
    if err != nil {
        return fmt.Errorf("failed to load P2P state: %w", err)
    }
    pm.state = state

    // Activate P2P interface
    pm.active.Store(true)

    // Re-announce all services to DHT
    for _, svc := range state.RegisteredServices {
        if err := pm.dht.Announce(ctx, svc); err != nil {
            log.Warn("failed to re-announce service", "service", svc.Name, "error", err)
        }
    }

    // Re-announce content
    for _, content := range state.ContentAnnouncements {
        if err := pm.dht.AnnounceContent(ctx, content); err != nil {
            log.Warn("failed to re-announce content", "key", content.Key, "error", err)
        }
    }

    // Restore routing table
    if err := pm.dht.RestoreRoutingTable(state.RoutingTable); err != nil {
        log.Warn("failed to restore routing table", "error", err)
    }

    log.Info("P2P activated as leader")
    return nil
}

// OnBecomeFollower deactivates P2P participation
// SECURITY FIX (P4-H4): MUST actively withdraw announcements to prevent split-brain
// Previous version relied on TTL expiry which can take hours - during that time,
// DHT clients would route to the old leader which is no longer authoritative.
func (pm *P2PManager) OnBecomeFollower(ctx context.Context) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    // Deactivate P2P interface FIRST to stop new operations
    pm.active.Store(false)

    // CRITICAL (P4-H4): Actively withdraw ALL announcements
    // This prevents split-brain where DHT thinks old leader is still valid
    // TTL-based expiry is NOT acceptable - can take hours
    var withdrawErrors []error

    // Withdraw services
    for _, svc := range pm.state.RegisteredServices {
        if err := pm.dht.Withdraw(ctx, svc); err != nil {
            withdrawErrors = append(withdrawErrors, fmt.Errorf("service %s: %w", svc.Name, err))
            // Continue withdrawing others even if one fails
        }
    }

    // Withdraw content announcements
    for _, content := range pm.state.ContentAnnouncements {
        if err := pm.dht.WithdrawContent(ctx, content); err != nil {
            withdrawErrors = append(withdrawErrors, fmt.Errorf("content %s: %w", content.Key, err))
        }
    }

    // Clear local routing table to prevent stale routes
    pm.dht.ClearRoutingTable()

    // Log completion status
    if len(withdrawErrors) > 0 {
        log.Warn("P2P deactivated with withdrawal errors",
            "errors", len(withdrawErrors),
            "first_error", withdrawErrors[0])
    } else {
        log.Info("P2P deactivated as follower - all announcements withdrawn")
    }

    return nil
}

// IMPORTANT: DHT interface must support withdrawal
// These methods MUST be implemented:
//   dht.Withdraw(ctx, service) - Remove service announcement
//   dht.WithdrawContent(ctx, content) - Remove content announcement
//   dht.ClearRoutingTable() - Clear local routing state

// ProposeP2PUpdate proposes a P2P state change via Raft
func (pm *P2PManager) ProposeP2PUpdate(ctx context.Context, update *P2PStateUpdate) error {
    if !pm.active.Load() {
        return ErrNotLeader
    }

    // Propose update through Raft consensus
    return pm.raftNode.Propose(ctx, update)
}
```

---

## Configuration Schema

### Full YAML Configuration

```yaml
# /etc/platformd/config.yaml

# Cluster configuration
cluster:
  # Operating mode: standalone, raft, node
  mode: node

  # Unique node identifier within cluster
  node_id: node-1

  # Raft configuration (for raft/node modes)
  raft:
    # Data directory for Raft journal
    data_dir: /var/lib/platformd/raft

    # Cluster peer addresses
    peers:
      - node-1:7001
      - node-2:7001
      - node-3:7001

    # Raft timing
    election_timeout: 1000ms
    heartbeat_interval: 100ms

    # Snapshot configuration
    snapshot_threshold: 10000
    snapshot_retention: 3

# P2P network configuration
p2p:
  # Enable P2P mode
  enabled: true

  # Bootstrap peers for initial network join
  bootstrap_peers:
    - /ip4/192.0.2.10/tcp/9999/p2p/QmNodeID1
    - /ip4/192.0.2.11/tcp/9999/p2p/QmNodeID2
    - /dns4/bootstrap.example.com/tcp/9999/p2p/QmBootstrapID

  # Listen addresses for P2P connections
  listen_addresses:
    - /ip4/0.0.0.0/tcp/9999
    - /ip6/::/tcp/9999
    - /ip4/0.0.0.0/udp/9999/quic

  # Public address announcement (auto-detected if empty)
  announce_addresses: []

  # Enrollment configuration
  enrollment:
    # Privacy CA endpoint
    privacy_ca_url: https://ca.example.com/acme

    # EAB credentials for endorse-01 (if needed)
    eab:
      kid: ""      # Set via --eab-kid flag
      hmac: ""     # Set via --eab-hmac flag

    # Certificate storage
    cert_path: /var/lib/platformd/certs/idevid.pem
    key_path: /var/lib/platformd/certs/idevid.key

    # Re-enrollment settings
    renew_before_expiry: 168h  # 7 days

  # DHT configuration
  dht:
    # DHT operation mode
    mode: server  # server (full), client (queries only)

    # Routing table settings
    bucket_size: 20
    replication_factor: 3

    # Refresh intervals
    routing_table_refresh: 1h
    provider_refresh: 12h

    # Storage limits
    max_record_size: 1MB
    max_records: 100000

  # DDoS work configuration (for untrusted nodes)
  ddos_work:
    # PoW difficulty (leading zero bits)
    difficulty: 20

    # Challenge validity period
    challenge_validity: 1h

    # Rate limits for untrusted nodes
    max_requests_per_minute: 10

  # Cluster-P2P integration
  cluster_integration:
    # Only leader participates in P2P (for cluster modes)
    leader_only: true

    # State replication interval
    state_sync_interval: 5s

    # Re-announcement delay after leader change
    leader_change_delay: 1s

# TPM configuration
tpm:
  # TPM device path
  device: /dev/tpmrm0

  # PCRs to include in quotes
  quote_pcrs: [0, 2, 7]

  # Key storage
  ek_cert_path: /var/lib/platformd/tpm/ek.crt
  idevid_handle: 0x81000001
```

### Environment Variable Overrides

```bash
# Cluster configuration
PLATFORMD_CLUSTER_MODE=node
PLATFORMD_CLUSTER_NODE_ID=node-1

# P2P configuration
PLATFORMD_P2P_ENABLED=true
PLATFORMD_P2P_BOOTSTRAP_PEERS=/ip4/192.0.2.10/tcp/9999/p2p/QmNodeID1

# EAB credentials (sensitive - prefer flags)
PLATFORMD_P2P_EAB_KID=your-kid
PLATFORMD_P2P_EAB_HMAC=your-hmac-key
```

---

## CLI Flags

### P2P Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--p2p` | Enable P2P mode | `false` |
| `--p2p-bootstrap` | Bootstrap peer address (repeatable) | `[]` |
| `--p2p-listen` | Custom listen address | `/ip4/0.0.0.0/tcp/9999` |
| `--p2p-announce` | Custom announce address | Auto-detected |

### EAB Flags (for endorse-01)

| Flag | Description | Default |
|------|-------------|---------|
| `--eab-kid` | EAB Key Identifier | `""` |
| `--eab-hmac` | EAB HMAC Key | `""` |

### Example Commands

**Standalone with P2P:**
```bash
platformd --p2p \
  --p2p-bootstrap=/ip4/192.0.2.10/tcp/9999/p2p/QmNodeID1
```

**Single-node Raft with P2P:**
```bash
platformd --mode=raft --p2p \
  --p2p-bootstrap=/ip4/192.0.2.10/tcp/9999/p2p/QmNodeID1 \
  --raft-data-dir=/var/lib/platformd/raft
```

**Multi-node Raft cluster with P2P:**
```bash
# Node 1 (initial leader)
platformd --mode=node --p2p \
  --node-id=node-1 \
  --raft-peers=node-1:7001,node-2:7001,node-3:7001 \
  --p2p-bootstrap=/ip4/10.0.0.50/tcp/9999/p2p/QmBootstrap

# Node 2
platformd --mode=node --p2p \
  --node-id=node-2 \
  --raft-peers=node-1:7001,node-2:7001,node-3:7001 \
  --p2p-bootstrap=/ip4/10.0.0.50/tcp/9999/p2p/QmBootstrap

# Node 3
platformd --mode=node --p2p \
  --node-id=node-3 \
  --raft-peers=node-1:7001,node-2:7001,node-3:7001 \
  --p2p-bootstrap=/ip4/10.0.0.50/tcp/9999/p2p/QmBootstrap
```

**First enrollment (new TPM without EK certificate):**
```bash
platformd --p2p \
  --eab-kid=your-key-id \
  --eab-hmac=your-hmac-key \
  --p2p-bootstrap=/ip4/192.0.2.10/tcp/9999/p2p/QmNodeID1
```

---

## P2P Join Protocol

### Peer Verification Flow

```
Joining Node                                    Existing Peer
     |                                               |
     | 1. P2P Connection Request                     |
     |---------------------------------------------->|
     |                                               |
     |             2. Request IDevID + Fresh Quote   |
     |<----------------------------------------------|
     |                                               |
     | 3. Send:                                      |
     |    - IDevID Certificate                       |
     |    - TPM Quote with peer's nonce              |
     |    - PCR values                               |
     |---------------------------------------------->|
     |                                               |
     |                          4. Verify:           |
     |                          - Quote signature    |
     |                          - Nonce freshness    |
     |                          - Cert chain to CA   |
     |                          - PCR policy         |
     |                          - Trust level        |
     |                                               |
     |             5. Accept/Reject + DHT Assignment |
     |<----------------------------------------------|
     |                                               |
     | 6. DHT Routing Table Exchange                 |
     |<--------------------------------------------->|
     |                                               |
```

### Peer Verification Implementation

```go
// VerifyPeerJoin validates a joining node's credentials
func (p *Peer) VerifyPeerJoin(ctx context.Context, req *JoinRequest) (*JoinResponse, error) {
    // Step 1: Verify IDevID certificate chain to Privacy CA
    idevid, err := x509.ParseCertificate(req.IDevIDCertificate)
    if err != nil {
        return nil, ErrInvalidCertificate
    }

    if err := p.verifyIDevIDChain(idevid); err != nil {
        return nil, fmt.Errorf("IDevID certificate chain invalid: %w", err)
    }

    // Step 2: Retrieve and DELETE nonce IMMEDIATELY after retrieval
    // CRITICAL: Nonce deletion prevents replay attacks where an attacker
    // captures a valid join request and replays it later
    p.nonceMu.Lock()
    expectedNonce, exists := p.pendingNonces[req.NodeID]
    nonceTimestamp, timestampExists := p.nonceTimestamps[req.NodeID]

    // DELETE NONCE IMMEDIATELY - before any validation
    // The nonce is consumed regardless of whether verification succeeds
    // This prevents replay attacks even if an attacker times out the connection
    delete(p.pendingNonces, req.NodeID)
    delete(p.nonceTimestamps, req.NodeID)
    p.nonceMu.Unlock()

    // Now validate the nonce (after deletion ensures one-time use)
    if !exists || !timestampExists {
        return nil, ErrNonceNotFound
    }
    if !bytes.Equal(req.Quote.Nonce, expectedNonce) {
        return nil, ErrNonceMismatch
    }
    if time.Since(nonceTimestamp) > 100*time.Millisecond {
        return nil, ErrNonceExpired
    }

    // Step 3: Parse EK certificate for trust determination
    ekCert, err := x509.ParseCertificate(req.EKCertificate)
    if err != nil {
        return nil, ErrInvalidEKCertificate
    }

    // Step 4: Verify EK certificate chain against manufacturer CAs
    // Trust level is determined ENTIRELY by EK chain validation
    trustLevel, err := p.verifyEKAgainstManufacturerCAs(ekCert)
    if err != nil {
        return nil, fmt.Errorf("EK trust determination failed: %w", err)
    }

    // Step 5: Verify TPM quote signature
    if err := p.verifyQuote(req.Quote, idevid.PublicKey); err != nil {
        return nil, fmt.Errorf("quote verification failed: %w", err)
    }

    // Step 6: Verify PCR policy
    if err := p.verifyPCRPolicy(req.Quote.PCRValues); err != nil {
        return nil, fmt.Errorf("PCR policy violation: %w", err)
    }

    // Step 7: Apply trust-level-specific requirements
    if trustLevel == TrustLevelUntrusted {
        // Require DDoS work for untrusted nodes
        // Use adaptive difficulty based on current network load
        currentDifficulty := p.difficultyController.GetCurrentDifficulty()
        if !VerifyDDoSWork(req.DDoSChallenge, req.DDoSSolution, currentDifficulty) {
            return nil, ErrDDoSWorkRequired
        }
    }

    // Step 8: Assign to DHT routing table
    nodeID := DeriveNodeID(idevid)
    p.routingTable.Add(&Contact{
        NodeID:      nodeID,
        Address:     req.Address,
        TrustLevel:  trustLevel,
        Certificate: idevid,
        EKCert:      ekCert,
    })

    return &JoinResponse{
        Accepted:     true,
        AssignedID:   nodeID,
        TrustLevel:   trustLevel,
        RoutingTable: p.routingTable.GetSnapshot(),
    }, nil
}

// verifyEKAgainstManufacturerCAs validates EK certificate chain against configured manufacturer CAs
// This is the SOLE determinant of trust level - trust comes FROM the EK validation result
//
// Trust Determination Logic:
//   1. Build x509.VerifyOptions with configured manufacturer CA roots
//   2. Attempt certificate chain verification
//   3. If chain validates to ANY configured CA root → TRUSTED
//   4. If chain does NOT validate → UNTRUSTED
//
// This approach ensures:
//   - swtpm (self-signed EK) → UNTRUSTED (no chain to CA)
//   - Unknown manufacturer TPM → UNTRUSTED (no configured CA)
//   - Intel/AMD fTPM with valid EK → TRUSTED (chains to Intel/AMD CA)
//   - Infineon dTPM with valid EK → TRUSTED (if Infineon CA configured)
func (p *Peer) verifyEKAgainstManufacturerCAs(ekCert *x509.Certificate) (TrustLevel, error) {
    // Build certificate pool from configured manufacturer CA roots
    roots := x509.NewCertPool()
    for _, ca := range p.config.TrustedManufacturerCAs {
        roots.AddCert(ca)
    }

    // Add any intermediate CAs for chain building
    intermediates := x509.NewCertPool()
    for _, ca := range p.config.IntermediateCAs {
        intermediates.AddCert(ca)
    }

    // Configure verification options
    opts := x509.VerifyOptions{
        Roots:         roots,
        Intermediates: intermediates,
        KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
        // CurrentTime can be set for testing; defaults to time.Now()
    }

    // Attempt to build and verify certificate chain
    chains, err := ekCert.Verify(opts)

    if err != nil || len(chains) == 0 {
        // EK certificate does NOT chain to any configured manufacturer CA
        // Possible causes:
        //   - Self-signed EK (swtpm, software TPM)
        //   - Unknown TPM manufacturer (CA not configured)
        //   - Expired EK certificate
        //   - Revoked intermediate CA
        //   - Malformed certificate chain
        return TrustLevelUntrusted, nil
    }

    // Chain validated successfully - now check for known vulnerabilities
    // (e.g., ROCA CVE-2017-15361 for certain Infineon TPM firmware versions)
    if p.isEKVulnerable(ekCert) {
        return TrustLevelUntrusted, nil
    }

    // EK chains to a trusted manufacturer CA and is not vulnerable
    return TrustLevelTrusted, nil
}

// isEKVulnerable checks if the EK is known to have security vulnerabilities
// (e.g., ROCA vulnerability CVE-2017-15361 for certain Infineon TPMs)
func (p *Peer) isEKVulnerable(ekCert *x509.Certificate) bool {
    // Check against known vulnerable EK public key patterns
    for _, vuln := range p.vulnerableEKPatterns {
        if vuln.Matches(ekCert.PublicKey) {
            return true
        }
    }
    return false
}

var (
    ErrInvalidEKCertificate = errors.New("invalid EK certificate")
    ErrNonceNotFound        = errors.New("nonce not found - may have been used or expired")
)
```

---

## Security Considerations

### Critical Security Design Decisions

This section documents four critical security mechanisms that protect the P2P network from common attacks.

#### 1. Nonce Deletion After Verification

**Threat:** Replay attacks where an attacker captures a valid TPM quote and replays it to impersonate a legitimate node.

**Design:** Nonces are deleted from the `pendingNonces` map **immediately after retrieval**, before any validation occurs.

```
Attacker captures: NodeID + Quote + Nonce
Attacker replays: Same request 50ms later

Timeline:
  T+0ms:   Legitimate request arrives, nonce retrieved and DELETED
  T+10ms:  Nonce validation proceeds (nonce already gone from map)
  T+50ms:  Replay arrives, nonce lookup returns ErrNonceNotFound
```

**Key Property:** Even if an attacker times out the connection or causes validation to fail, the nonce is consumed and cannot be reused.

#### 2. EK Certificate Chain Validation

**Threat:** Nodes with software TPMs (swtpm) or unknown manufacturers gaining TRUSTED status.

**Design:** Trust level is determined **solely** by whether the EK certificate chains to a configured Manufacturer CA root. No hardcoding of TPM types.

```
EK Certificate → Intermediate CA → Manufacturer Root CA
                                         ↓
                            Configured in TrustedManufacturerCAs?
                                    ↓           ↓
                                  Yes          No
                                    ↓           ↓
                               TRUSTED    UNTRUSTED
```

**Key Property:** Adding or removing trusted manufacturers requires only CA certificate changes, not code changes.

#### 3. EAB Credential Rotation

**Threat:** Long-lived EAB credentials increase exposure window for credential theft or brute force attacks.

**Design:** 90-day rotation schedule with 24-hour grace period for in-flight requests.

| Phase | Action |
|-------|--------|
| Day 0 | New EAB credentials issued |
| Day 1-89 | Current credentials active |
| Day 90 | Rotation triggered, new credentials issued |
| Day 90-91 | Grace period - both old and new accepted |
| Day 91+ | Old credentials revoked via `scheduleRevocation()` |

**Key Property:** Revocation occurs automatically with exponential backoff retry on failure.

#### 4. Adaptive PoW Difficulty

**Threat:** Static PoW difficulty is either too easy (ineffective during attacks) or too hard (poor UX during normal operation).

**Design:** Difficulty adjusts every 10 seconds based on rolling average network load.

```
Load 0-25%  → Difficulty 16 (easy, ~65K hashes)
Load 50%    → Difficulty 20 (moderate, ~1M hashes)
Load 85%+   → Difficulty 26+ (hard, ~67M hashes)
```

**Key Property:** During DDoS attacks, legitimate users experience delays but service remains available; attackers face exponentially increasing costs.

### Enrollment Security

| Threat | Mitigation |
|--------|------------|
| EK spoofing | TPM2_Certify proof verifies EK is TPM-bound |
| Quote replay | Fresh nonce with 100ms validity window + immediate nonce deletion after retrieval |
| Nonce replay attack | Nonces deleted from pendingNonces map before verification completes - cannot be reused |
| Trust level bypass | EK certificate chain validated against manufacturer CAs via `verifyEKAgainstManufacturerCAs()` |
| Fake TPM | Manufacturer CA whitelist + CVE checking (ROCA, etc.) |
| Certificate forgery | FROST threshold signatures from distributed CA |
| Man-in-the-middle | TLS with certificate pinning |
| Credential theft | 90-day EAB rotation with automatic revocation |
| DDoS attacks | Adaptive PoW difficulty scales with network load |

### Cluster-P2P Security

| Threat | Mitigation |
|--------|------------|
| Follower impersonation | Only leader holds active P2P credentials |
| Split-brain P2P | Raft consensus prevents dual leaders |
| State desync | All P2P state replicated via Raft |
| Leader hijacking | Raft election requires quorum |

### DDoS Protection

| Trust Level | Protection |
|-------------|------------|
| Trusted | Full rate limits, no PoW required |
| Untrusted | Reduced rate limits, PoW required |

---

## Monitoring and Observability

### P2P Metrics

```go
// P2P metrics exported via Prometheus
var (
    p2pPeersConnected = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "platformd_p2p_peers_connected",
        Help: "Number of connected P2P peers",
    })

    p2pDHTRecords = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "platformd_p2p_dht_records",
        Help: "Number of records in local DHT storage",
    })

    p2pMessagesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "platformd_p2p_messages_total",
        Help: "Total P2P messages by type",
    }, []string{"type", "direction"})

    p2pEnrollmentDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "platformd_p2p_enrollment_duration_seconds",
        Help:    "Time taken for P2P enrollment",
        Buckets: prometheus.DefBuckets,
    })

    p2pLeaderChanges = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "platformd_p2p_leader_changes_total",
        Help: "Total P2P leader changes in cluster mode",
    })
)
```

### Health Checks

```bash
# Check P2P status
platformctl p2p status

# Output:
# P2P Status: ACTIVE
# Mode: node (leader)
# Trust Level: TRUSTED
# Peers Connected: 47
# DHT Records: 1,234
# IDevID Expires: 2026-04-07T12:00:00Z
# Last Quote: 2026-01-08T10:30:00Z
```

---

## Related Documents

- [02-network-architecture.md](02-network-architecture.md) - DHT network topology and routing
- [03-security-trust.md](03-security-trust.md) - TPM trust policy and security constants
- [05-certificate-authority.md](05-certificate-authority.md) - FROST CA and IDevID enrollment
- [06-consensus-coordination.md](06-consensus-coordination.md) - Coordinator election and PBFT
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system and Sybil defense

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-08 | 1.0 | Initial documentation for Platformd P2P mode |
| 2026-01-10 | 1.1 | Added Critical Security Design Decisions section documenting: (1) Nonce deletion after retrieval to prevent replay attacks, (2) EK certificate chain validation via `verifyEKAgainstManufacturerCAs()` for trust determination, (3) 90-day EAB credential rotation with `scheduleRevocation()` implementation, (4) Adaptive PoW difficulty controller for DDoS protection |

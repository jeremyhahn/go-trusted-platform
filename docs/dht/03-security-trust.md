# Security and Trust Architecture

This document consolidates security properties, threat models, cryptographic requirements, TPM trust policies, and incident response procedures for the go-trusted-platform network.

---

## 1. Security Properties and Design Principles

### Core Security Properties

| Property | Guarantee | Implementation |
|----------|-----------|----------------|
| **Confidentiality** | Key shares never exposed | TPM sealed storage, encrypted P2P |
| **Integrity** | Certificates unforgeable with <33% compromise | FROST threshold signatures |
| **Availability** | 99.9999% uptime | 4 CA pools, failover, geographic distribution |
| **Non-repudiation** | All signatures traceable | CT log with Merkle proofs |

### Design Philosophy: Security Through Determinism

Core network parameters are **non-configurable** to ensure deterministic, secure operation:

```
NO user configuration of:
  - DHT parameters (k, alpha, replication)
  - CA parameters (rotation, threshold, pool size)
  - Security parameters (reputation thresholds, TPM requirements)
  - Cryptographic algorithms (FROST only, no alternatives)

WHY this prevents:
  - Weakening security through misconfiguration
  - Network fragmentation (inconsistent parameters)
  - Attack surface expansion (exploiting misconfigurations)
  - Compatibility issues (nodes with different configs)
```

---

## 2. STRIDE Threat Model

| Threat | Component | Attack Vector | Mitigation |
|--------|-----------|---------------|------------|
| **Spoofing** | TPM Attestation | Replay old quote | Nonce + +/-100ms freshness |
| **Spoofing** | Node Identity | Forge NodeID | TPM-backed identity keys |
| **Tampering** | FROST Shares | Modify share during DKG | Commitment verification + VSS |
| **Tampering** | DHT Data | Modify stored data | Signatures on all entries |
| **Repudiation** | CA Signatures | Deny signing certificate | CT log with inclusion proofs |
| **Information Disclosure** | Key Material | Extract from memory | TPM sealed storage, secure deletion |
| **Information Disclosure** | Network Traffic | Eavesdrop P2P | TLS 1.3 / Noise Protocol |
| **Denial of Service** | DHT/CA | Flood with requests | PoW 2^24, rate limiting, reputation |
| **Denial of Service** | DKG | Refuse to participate | Timeout + exclusion + restart |
| **Elevation of Privilege** | Coordinators | Abuse coordinator role | Multi-sig, 67% quorum, VRF selection |

---

## 3. Security Constants (CANONICAL)

All security-critical parameters are compile-time constants. This section is the single source of truth.

### DHT Parameters

```go
// pkg/config/constants.go - NON-CONFIGURABLE

const (
    // Kademlia Parameters
    KademliaK              = 20                     // Bucket size
    KademliaAlpha          = 3                      // Parallel lookups
    KademliaKeySize        = 160                    // Node ID size in bits
    KademliaBucketRefresh  = 1 * time.Hour
    KademliaReplication    = 3                      // Replication factor

    // Regional DHT
    RegionalKeySize        = 128                    // Regional node IDs
    MaxRegions             = 65536                  // 2^16 regions (/48 subnets)

    // DHT Storage
    MaxValueSize           = 1 * 1024 * 1024        // 1MB max value size
    DefaultTTL             = 24 * time.Hour

    // DHT Performance
    LookupTimeout          = 10 * time.Second
    StoreTimeout           = 5 * time.Second
    MaxConcurrentLookups   = 100
)
```

### Certificate Authority Parameters

```go
const (
    // Rotation Schedule
    CARotationInterval     = 1 * time.Hour          // FIXED: 1 hour
    CARotationOffset       = 30 * time.Minute       // 30-minute stagger

    // Threshold Signature
    CAThreshold            = 0.33                   // FIXED: 33% threshold
    CAPoolSizeMin          = 100
    CAPoolSizeMax          = 10_000_000
    CAPoolSizePercent      = 0.001                  // 0.1% of network

    // Certificate Validity
    CertificateValidity    = 90 * 24 * time.Hour    // 90 days

    // Algorithms (FIXED)
    CAAlgorithm1           = "FROST(Ed25519, SHA-512)"
    CAAlgorithm2           = "FROST(P-256, SHA-256)"
)
```

### DKG (Distributed Key Generation) Parameters

These parameters govern the FROST threshold key generation protocol. See `04-cryptographic-protocols.md` for detailed implementation.

```go
// pkg/config/dkg_constants.go - NON-CONFIGURABLE

const (
    // === Session Timing ===
    // DKG uses a phase-overlapping design for efficiency:
    //   - Fast Path (with overlap): 10 minutes target
    //   - Slow Path (no overlap): 13 minutes maximum
    //
    // Phase overlapping allows Share Distribution (3min) and Verification (3min)
    // to begin processing early arrivals while waiting for stragglers.
    DKGDuration            = 10 * time.Minute       // Target duration with fast-path overlap
    DKGSlowPathMax         = 13 * time.Minute       // Maximum duration without overlap
    DKGFastPath            = 5 * time.Minute        // Emergency DKG (reduced participants)
    DKGPreStart            = 15 * time.Minute       // Pre-rotation buffer before CA rotation
    DKGProgressTimeout     = 15 * time.Minute       // Hard deadline that aborts session
    DKGCheckpointInterval  = 30 * time.Second       // Coordinator state persistence interval

    // === Phase Timeouts ===
    // Each phase has individual timeout. Phases advance when:
    //   1. All participants respond (fast path), OR
    //   2. Timeout fires with sufficient responses (slow path)
    //
    // Phase Breakdown (10 min fast path with overlap):
    //   Share Generation:  2 min
    //   Share Distribution: 3 min (overlaps with verification)
    //   Verification:       3 min (overlaps with distribution)
    //   Commitment:         2 min
    //   Finalization:       2 min (includes buffer)
    //   Buffer:             1 min (absorbed into finalization)
    DKGPhaseShareGenTimeout      = 2 * time.Minute  // Phase 1: Share generation
    DKGPhaseShareDistTimeout     = 3 * time.Minute  // Phase 2: Share distribution (overlaps)
    DKGPhaseVerificationTimeout  = 3 * time.Minute  // Phase 3: Verification (overlaps)
    DKGPhaseCommitmentTimeout    = 2 * time.Minute  // Phase 4: Commitment broadcast
    DKGPhaseFinalizeTimeout      = 2 * time.Minute  // Phase 5: Finalization + buffer

    // Legacy phase names (for compatibility)
    DKGPhaseSetupTimeout         = DKGPhaseShareGenTimeout
    DKGPhaseShareTimeout         = DKGPhaseShareDistTimeout
    DKGPhaseComplaintTimeout     = 2 * time.Minute  // Complaint resolution (within verification)

    // Per-participant timeout within each phase
    DKGParticipantTimeout  = 60 * time.Second       // Timeout per participant response

    // === Retry and Recovery ===
    MaxDKGAttempts         = 5                      // Maximum retry attempts per session
    DKGMaxRetries          = 2                      // Retries within single attempt
    AbortExclusionPeriod   = 1 * time.Hour          // Aborter exclusion after 3+ aborts
    CooldownPeriod         = 10 * time.Minute       // Exclusion after first abort

    // === Rate Limiting ===
    MaxConcurrentDKGSessions     = 3                // Max simultaneous DKG sessions network-wide
    MinDKGSessionInterval        = 5 * time.Minute  // Minimum time between session starts
    MaxDKGSessionsPerHour        = 10               // Maximum sessions per hour globally
    MaxDKGSessionsPerDay         = 50               // Maximum sessions per day globally

    // Per-node rate limits (anti-griefing)
    MaxNodeDKGInitiationsPerHour = 2                // Max DKG initiations per node per hour
    MaxNodeDKGInitiationsPerDay  = 5                // Max DKG initiations per node per day
    NodeDKGCooldownAfterFailure  = 30 * time.Minute // Cooldown after failed initiation

    // === Staking (anti-griefing) ===
    DKGInitiationStake     = 100                    // Coins locked during DKG initiation
    DKGStakeSlashPercent   = 10                     // Percent slashed on abort/griefing

    // === Coordinator Recovery ===
    // CANONICAL: See 06-consensus-coordination.md Section "Canonical Coordinator Failure Detection Constants"
    // for authoritative heartbeat and failure detection values.
    CoordinatorHeartbeatInterval = 2 * time.Second  // DKG coordinator heartbeat (matches consensus protocol)
    CoordinatorFailoverTimeout   = 10 * time.Second // Time to declare coordinator failed (8s detection + 2s buffer)
    MaxCoordinatorFailovers      = 2                // Max failovers per DKG session
    // SECURITY FIX (P5-M3): Extended from 1h to 2h to prevent checkpoint expiration
    // during slow DKG sessions (especially under high load or network latency)
    DKGCheckpointTTL             = 2 * time.Hour    // Checkpoint storage TTL in DHT
)
```

#### DKG Phase Timing Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DKG SESSION TIMELINE                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CARotationInterval = 1 hour                                            │
│  ├───────────────────────────────────────────────────────────────┤     │
│                                                                         │
│  │←── DKGPreStart ──→│←────────── DKGDuration ───────────→│            │
│  │     15 min        │              10 min                 │            │
│                                                                         │
│  DKG starts 15 min before rotation to ensure new keys ready             │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│  TIMING CLARIFICATION                                                   │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  Stated Duration: 10 minutes (fast path with phase overlap)             │
│  Slow Path (no overlap): 13 minutes maximum                             │
│                                                                         │
│  PHASE BREAKDOWN:                                                       │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ Phase              │ Duration │ Notes                             │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ Share Generation   │   2 min  │ Participants generate shares      │ │
│  │ Share Distribution │   3 min  │ OVERLAPS with verification        │ │
│  │ Verification       │   3 min  │ OVERLAPS with distribution        │ │
│  │ Commitment         │   2 min  │ Final commitment broadcast        │ │
│  │ Finalization       │   2 min  │ Key derivation                    │ │
│  │ Buffer             │   1 min  │ Absorbed into finalization        │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  FAST PATH (10 min with overlap):                                       │
│                                                                         │
│    Time: 0───────2───────4───────6───────8───────10 min                │
│          │       │       │       │       │       │                     │
│          │ Share │       │       │       │       │                     │
│          │  Gen  │ Share Distribution    │       │                     │
│          │       │       │ Verification  │       │                     │
│          │       │       │       │ Commit│ Final │                     │
│          │       │       │       │       │       │                     │
│                     ↑                                                   │
│              Overlap: Distribution and Verification                     │
│              run concurrently, processing early arrivals                │
│                                                                         │
│  SLOW PATH (13 min without overlap):                                    │
│                                                                         │
│    Time: 0───2───5───8───10──12──13 min                                │
│          │   │   │   │   │   │   │                                     │
│          │Gen│Dist │Vrfy │Cmt│Fin│                                     │
│          │ 2m│ 3m  │ 3m  │2m │2m │1m buffer                            │
│          │   │     │     │   │   │                                     │
│                                                                         │
│  WHY TWO PATHS:                                                         │
│  • Fast path: Phases advance as messages arrive                         │
│  • Slow path: Phases wait for full timeout (network issues/Byzantine)   │
│  • DKGProgressTimeout (15 min): Hard abort if exceeded                  │
│                                                                         │
│  INVARIANTS:                                                            │
│  • DKGDuration (10m) < DKGSlowPathMax (13m) < DKGProgressTimeout (15m)  │
│  • If DKG exceeds 13 min, it MUST abort (byzantine or network failure)  │
│                                                                         │
│  If DKG fails:                                                          │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │ Attempt 1 │ Attempt 2 │ Attempt 3 │ Attempt 4 │ Attempt 5 │ FAIL │  │
│  │   10min   │   10min   │   10min   │   10min   │   10min   │      │  │
│  └───────────┴───────────┴───────────┴───────────┴───────────┴──────┘  │
│                                                                         │
│  Total maximum: 5 attempts × 10 min = 50 min                            │
│  DKGProgressTimeout = 15 min is overall deadline (session aborts)       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### DKG Rate Limiting Rationale

| Limit | Value | Rationale |
|-------|-------|-----------|
| `MaxConcurrentDKGSessions` | 3 | Prevent resource exhaustion; 4 CA pools can have 1 active each |
| `MinDKGSessionInterval` | 5 min | Allow previous session cleanup before next starts |
| `MaxNodeDKGInitiationsPerHour` | 2 | Prevent single node from monopolizing DKG resources |
| `DKGInitiationStake` | 100 coins | Economic cost for frivolous DKG initiations |
| `DKGStakeSlashPercent` | 10% | 10 coins penalty for abort/griefing per offense |

#### Cross-Reference

- **Full DKG Protocol**: See `04-cryptographic-protocols.md § Distributed Key Generation (DKG)`
- **DKG Coordinator Slashing**: See `04-cryptographic-protocols.md § DKG Coordinator Slashing`
- **DKG Recovery Protocol**: See `04-cryptographic-protocols.md § DKG Recovery Protocol`
- **Genesis Trustee Recovery**: See `04-cryptographic-protocols.md § Genesis Trustee Recovery`

### TPM Parameters

```go
const (
    TPMRequired            = true                   // ALWAYS required
    TPMVersion             = "2.0"                  // Minimum version
    TPMQuoteFreshness      = 100 * time.Millisecond // +/-100ms
    TPMNonceSize           = 32                     // bytes (256 bits)
)
```

### Clock Synchronization Parameters

Accurate time synchronization is critical for TPM attestation security. All nodes must maintain clock synchronization with authoritative time sources.

```go
const (
    // NTP Synchronization Requirements
    NTPSyncRequired        = true                   // Mandatory NTP synchronization
    NTPMaxDrift            = 100 * time.Millisecond // Maximum acceptable drift from NTP
    NTPCheckInterval       = 1 * time.Minute        // Frequency of NTP sync verification
    NTPGracePeriod         = 5 * time.Minute        // Grace period before rejection

    // Reputation Penalties
    ClockDriftPenalty      = -0.10                  // Penalty for excessive clock drift

    // TPM Clock Integration
    TPMClockDriftTolerance = 5 * time.Second        // Tolerance for TPM internal clock drift
)
```

**NTP Synchronization Requirements:**

| Requirement | Value | Enforcement |
|-------------|-------|-------------|
| NTP Sync Mandatory | Yes | Node rejected if unsynchronized |
| Maximum Acceptable Drift | 100ms from NTP | Measured via NTP offset |
| Check Interval | 1 minute | Continuous monitoring |
| Grace Period | 5 minutes | Time to resync before rejection |
| Reputation Penalty | -0.10 | Applied for sustained drift |

**Clock Drift Validation in TPM Quote Verification:**

```go
// ClockSyncValidator validates node clock synchronization
type ClockSyncValidator struct {
    ntpServers     []string
    maxDrift       time.Duration
    checkInterval  time.Duration
    gracePeriod    time.Duration
    driftPenalty   float64
}

// ValidateClockSync checks if node clock is within acceptable NTP drift
func (v *ClockSyncValidator) ValidateClockSync(nodeTime time.Time) (*ClockSyncResult, error) {
    ntpTime, err := v.queryNTPTime()
    if err != nil {
        return nil, ErrNTPQueryFailed
    }

    drift := nodeTime.Sub(ntpTime)
    if drift < 0 {
        drift = -drift
    }

    result := &ClockSyncResult{
        NodeTime:      nodeTime,
        NTPTime:       ntpTime,
        Drift:         drift,
        WithinTolerance: drift <= v.maxDrift,
    }

    if !result.WithinTolerance {
        result.ReputationPenalty = v.driftPenalty
    }

    return result, nil
}

// IntegrateWithTPMQuoteVerification validates clock sync during TPM attestation
func (v *ClockSyncValidator) IntegrateWithTPMQuoteVerification(
    quote *TPMQuote,
    nodeID NodeID,
) error {
    // Validate node's system clock against NTP
    syncResult, err := v.ValidateClockSync(quote.SystemTime)
    if err != nil {
        return err
    }

    if !syncResult.WithinTolerance {
        // Check if still in grace period
        if v.isInGracePeriod(nodeID) {
            // Log warning but allow
            v.metrics.RecordClockDriftWarning(nodeID, syncResult.Drift)
            return nil
        }
        return &ClockDriftError{
            NodeID:    nodeID,
            Drift:     syncResult.Drift,
            MaxDrift:  v.maxDrift,
            Penalty:   syncResult.ReputationPenalty,
        }
    }

    return nil
}
```

**Recommended NTP Configuration:**

- Use multiple stratum-1 NTP servers for redundancy
- Configure NTP daemon with `iburst` for fast initial synchronization
- Enable NTP authentication where available
- Monitor NTP offset via system metrics

### Reputation and Role Thresholds

```go
const (
    // Reputation Thresholds
    MinReputationLeaf      = 0.00                   // Any node can be leaf
    MinReputationHub       = 0.80                   // Hub promotion
    MinReputationCoord     = 0.95                   // Coordinator promotion
    MinReputationCA        = 0.90                   // CA signing eligible
    MinReputationGateway   = 0.85                   // Gateway promotion
    ReputationDecayRate    = 0.001                  // 0.1% per day

    // Uptime Requirements (ONGOING after probation)
    // NOTE: Probation periods have STRICTER uptime requirements.
    // See 09-defense-reputation.md for probation-specific thresholds:
    //   - Hub probation: 99% (vs 95% ongoing)
    //   - Gateway probation: 99.5% (vs 95% ongoing)
    MinUptimeHub           = 0.95                   // 95% ongoing (99% during probation)
    MinUptimeCoord         = 0.99                   // 99% (always)
    MinUptimeCA            = 0.95                   // 95% for CA

    // Age Requirements (Hard Minimums)
    // NOTE: Effective minimums may be longer due to reputation earning time.
    // See 09-defense-reputation.md for full eligibility calculations.
    MinAgeHub              = 30 * 24 * time.Hour    // 30 days
    MinAgeCoord            = 180 * 24 * time.Hour   // 6 months hard minimum
    // ^ Effective minimum is 185 days: 95 days to earn 0.95 reputation
    //   (at 0.01/day) + 90 days probation period. The hard minimum of
    //   180 days is subsumed by these requirements.
    MinAgeGateway          = 90 * 24 * time.Hour    // 3 months (CRITICAL)
    MinAgeForCA            = 90 * 24 * time.Hour    // 90 days

    // Bandwidth Requirements (bps)
    MinBandwidthLeaf       = 10_000_000             // 10 Mbps
    MinBandwidthHub        = 100_000_000            // 100 Mbps
    MinBandwidthCoord      = 1_000_000_000          // 1 Gbps
    MinBandwidthCA         = 10_000_000             // 10 Mbps
    MinBandwidthGateway    = 100_000_000            // 100 Mbps

    // Demotion Criteria
    DemotionReputationDrop = 0.10                   // 10% drop = demote
    DemotionOfflineTime    = 7 * 24 * time.Hour     // 7 days offline = demote
)
```

### DDoS Protection Parameters

```go
const (
    // Rate Limiting
    MaxConnectionsPerIP    = 10                     // Concurrent per IP
    MaxRequestsPerSecond   = 100                    // Requests per second per IP
    MaxNewConnsPerMinute   = 20                     // New connections per minute

    // Proof-of-Work
    PoWDifficulty          = 20                     // 2^20 hashes (~1 second)
    PoWCacheDuration       = 1 * time.Hour

    // IP Reputation
    MinIPReputation        = 0.20                   // Block if below
    IPReputationDecay      = 0.01                   // Per bad request
    IPReputationRestore    = 0.001                  // Per good request

    // Threat Intelligence
    ThreatIntelExpiry      = 24 * time.Hour
    ThreatIntelMinReports  = 3                      // Reports to blacklist
)
```

### Network Parameters

```go
const (
    // Ports
    DefaultP2PPort         = 9999
    DefaultHTTPPort        = 8080
    DefaultGRPCPort        = 9090

    // IPv6 Addressing
    IPv6PoolPrefix         = "2602:F5BB::"          // Allocation prefix
    IPv6PrefixLength       = 36                     // /36
    IPv6RegionSize         = 48                     // /48 per region
    IPv6SubnetSize         = 64                     // /64 per subnet

    // Connectivity
    MaxPeersPerNode        = 50
    PeerRefreshInterval    = 5 * time.Minute
    ConnectionTimeout      = 30 * time.Second

    // Health Monitoring
    HealthCheckInterval    = 60 * time.Second
    HealthCheckRetries     = 3
)
```

### Compile-Time Validation

```go
func init() {
    if !TPMRequired {
        panic("SECURITY VIOLATION: TPM must always be required")
    }
    if CAThreshold < 0.33 || CAThreshold > 0.67 {
        panic("SECURITY VIOLATION: CA threshold must be between 33% and 67%")
    }
    if MinReputationGateway < 0.80 {
        panic("SECURITY VIOLATION: Gateway minimum reputation must be >= 0.80")
    }
    if MinAgeGateway < 90*24*time.Hour {
        panic("SECURITY VIOLATION: Gateway minimum age must be >= 90 days")
    }
}
```

---

## 4. Cryptographic Requirements

### Random Number Generation

The DHT uses go-xkms's pluggable RNG system with automatic hardware detection.

| Requirement | Specification |
|-------------|---------------|
| **Primary RNG** | TPM 2.0 hardware RNG (highest priority) |
| **Secondary RNG** | PKCS#11 HSM (SoftHSM, YubiKey, NitroKey) |
| **Fallback RNG** | `crypto/rand` (software, last resort) |
| **Selection** | Automatic via `RNGModeAuto` |
| **Entropy** | >=256 bits for all key generation |
| **Validation** | Test RNG availability on startup |

```go
import quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

// Hardware RNG with automatic backend selection
// Priority: TPM2 > PKCS#11 > Software (fallback)
func generateRandomBytes(n int) ([]byte, error) {
    return xkms.Rand(n)
}

// io.Reader for standard crypto operations (x509, ECDSA, etc.)
func secureReader() io.Reader {
    return xkms.Reader()
}

// Generate random big.Int for certificate serials, etc.
func generateRandomInt(max *big.Int) (*big.Int, error) {
    return xkms.RandInt(max)
}
```

**RNG Modes:**
- `xkms.RNGModeAuto` - Auto-detect best available (recommended)
- `xkms.RNGModeTPM2` - Force TPM 2.0 hardware RNG
- `xkms.RNGModePKCS11` - Force PKCS#11 HSM
- `xkms.RNGModeSoftware` - Force software fallback (testing only)

### FROST Implementation

| Requirement | Specification |
|-------------|---------------|
| **Protocol** | RFC 9591 compliant |
| **VSS** | Verifiable Secret Sharing mandatory |
| **Commitment Length** | MUST validate len(C_i) == t |
| **Proof of Knowledge** | Schnorr proof for a_0 required |
| **Nonce Handling** | One-time use, delete after signing |
| **Commitment Expiry** | 24 hours |
| **Signing Timeout** | 5 seconds |

### TPM Attestation

| Requirement | Specification |
|-------------|---------------|
| **Quote Freshness** | +/-100 milliseconds |
| **Nonce** | 256-bit random, verified in quote |
| **PCR Policy** | Bind to PCR 0, 2, 7 |
| **Manufacturer** | Whitelist known-good TPMs |
| **CVE Checking** | Block TPMs with known vulnerabilities |

### TPM Quote Timing Security

The default +/-100ms freshness window provides basic replay protection but may be vulnerable to timing attacks in certain network conditions. This section defines stricter timing controls with network-aware freshness windows and comprehensive nonce management.

#### Network-Aware Freshness Windows

| Network Type | Freshness Window | Use Case |
|--------------|------------------|----------|
| Local | +/-50ms | Same datacenter/rack |
| Regional | +/-100ms | Same geographic region |
| Global | +/-200ms | Cross-region |
| **Nonce TTL** | **30 seconds** | Maximum nonce validity |

#### Implementation

```go
// pkg/tpm/timing_security.go

// TPMTimingSecurity hardens against timing-based attestation attacks
type TPMTimingSecurity struct {
    // Tighter freshness windows based on network conditions
    LocalNetworkFreshness   time.Duration  // Same datacenter: 50ms
    RegionalNetworkFreshness time.Duration  // Same region: 100ms
    GlobalNetworkFreshness   time.Duration  // Cross-region: 200ms
    
    // Nonce requirements
    NonceMinEntropy       int            // Minimum bits of entropy (256)
    NonceExpirationWindow time.Duration  // Nonces expire after 30 seconds
    PreventNonceReuse     bool           // Block replay of nonces
    
    // Monotonic counter requirements
    RequireMonotonicCounter bool          // Require TPM clock monotonic
    MaxClockDrift          time.Duration  // Maximum allowed clock drift
}

const (
    DefaultLocalFreshness   = 50 * time.Millisecond
    DefaultRegionalFreshness = 100 * time.Millisecond
    DefaultGlobalFreshness  = 200 * time.Millisecond
    DefaultNonceExpiration  = 30 * time.Second
    
    // DefaultMaxClockDrift: Maximum allowed TPM clock drift for attestation validity.
    // 
    // RATIONALE FOR 5-SECOND WINDOW:
    // This value is intentionally higher than TPM quote freshness (+/-100ms) because
    // clock drift detection serves a different security purpose:
    //
    // 1. QUOTE FRESHNESS (+/-100ms): Validates that the TPM quote was generated
    //    within the challenge-response window, preventing replay attacks. This uses
    //    the nonce mechanism and is enforced at DefaultLocalFreshness/DefaultRegionalFreshness.
    //
    // 2. CLOCK DRIFT (5s): Detects nodes with significantly misconfigured system
    //    clocks that could indicate tampering or unstable infrastructure. The 5s
    //    window accommodates:
    //    - NTP sync delays across geographic regions (typical jitter: 50-200ms)
    //    - Transient network partitions during NTP updates
    //    - TPM clock info reporting granularity (1s resolution on some TPMs)
    //    - Container/VM clock synchronization delays
    //
    // SECURITY CONSTRAINT: TPM quote validation ALWAYS uses the stricter +/-100ms
    // freshness check on the nonce. Clock drift detection is a secondary check
    // that identifies infrastructure issues, not a replacement for nonce freshness.
    //
    // If tighter clock synchronization is required, configure NTP servers with
    // stratum-1 sources and reduce this value accordingly.
    DefaultMaxClockDrift    = 5 * time.Second
)
```

#### TPM Clock Drift Tolerance Analysis (CANONICAL)

The 5-second TPM clock drift tolerance represents a carefully balanced security parameter that addresses both security requirements and operational realities.

**Security vs. Operational Balance:**

| Factor | Consideration | 5-Second Tolerance Impact |
|--------|---------------|---------------------------|
| TPM Hardware Drift | Typical drift <1 second/day | Well within tolerance |
| Network Partitions | Brief partitions during NTP sync | Prevents false positives |
| Geographic Distribution | Cross-region latency variations | Accommodates global network |
| Container/VM Overhead | Clock sync delays in virtualized environments | Allows containerized nodes |

**TPM Hardware Clock Characteristics:**

TPM internal clocks drift over time due to hardware oscillator variations:

```
Typical TPM Clock Drift Rates:
┌─────────────────────┬─────────────────┬────────────────────┐
│ TPM Type            │ Typical Drift   │ Maximum Drift      │
├─────────────────────┼─────────────────┼────────────────────┤
│ Discrete TPM (dTPM) │ <0.5 sec/day    │ 1 sec/day          │
│ Firmware TPM (fTPM) │ <0.5 sec/day    │ 2 sec/day          │
│ Virtual TPM (vTPM)  │ <1 sec/day      │ 5 sec/day          │
└─────────────────────┴─────────────────┴────────────────────┘

At 1 second/day drift:
- After 5 days without sync: 5 second drift (at tolerance limit)
- After 1 day without sync: 1 second drift (well within tolerance)
```

**Attack Scenario Analysis:**

The following attack scenarios were analyzed to determine the 5-second tolerance:

```go
// AttackScenario documents a timing manipulation attack and its mitigation
type AttackScenario struct {
    Name           string
    Description    string
    AttackVector   string
    Impact         string
    Mitigation     string
    RiskWithDrift  string
}

var TimingAttackScenarios = []AttackScenario{
    {
        Name:        "Quote Replay with Clock Manipulation",
        Description: "Attacker captures valid quote and replays with manipulated clock",
        AttackVector: "Set system clock to past timestamp to replay old quote",
        Impact:      "Could reuse attestation without current TPM state",
        Mitigation:  "Nonce mechanism (+/-100ms) prevents this - quote must include fresh nonce",
        RiskWithDrift: "NONE - nonce check is independent of clock drift tolerance",
    },
    {
        Name:        "TPM Clock Rollback Attack",
        Description: "Attacker rolls back TPM clock to evade freshness checks",
        AttackVector: "Manipulate TPM clock info to appear fresh",
        Impact:      "Stale attestation accepted as fresh",
        Mitigation:  "TPM monotonic counter prevents clock rollback; quote timestamp verified",
        RiskWithDrift: "NONE - TPM hardware prevents clock rollback",
    },
    {
        Name:        "Network Delay Exploitation",
        Description: "Attacker delays quote delivery to extend validity window",
        AttackVector: "Hold quote during network transit, deliver just before expiry",
        Impact:      "Quote reflects stale TPM state",
        Mitigation:  "Nonce expiration (30s) limits delay window; 5s drift does not extend this",
        RiskWithDrift: "LOW - nonce expiration is the primary control",
    },
    {
        Name:        "Infrastructure Instability Masking",
        Description: "Compromised node hides instability behind clock drift allowance",
        AttackVector: "Intentionally desync clock to obscure suspicious behavior",
        Impact:      "Anomalous timing patterns not detected",
        Mitigation:  "NTP sync validation catches deliberate desync; reputation penalty (-0.10) applies",
        RiskWithDrift: "LOW - separate NTP validation catches this",
    },
    {
        Name:        "Split-Second Timing Attack",
        Description: "Attacker exploits millisecond-level timing differences",
        AttackVector: "Use precise timing to win race conditions",
        Impact:      "Could influence FROST signing order or DKG participation",
        Mitigation:  "5s drift tolerance is irrelevant - these attacks target sub-ms precision",
        RiskWithDrift: "NONE - wrong order of magnitude for this attack class",
    },
}
```

**Why Not Stricter (e.g., 1 second)?**

A 1-second tolerance would cause operational issues:

| Issue | Frequency with 1s Tolerance | Frequency with 5s Tolerance |
|-------|-----------------------------|-----------------------------|
| False positives during NTP resync | ~5% of nodes | <0.1% of nodes |
| Container restart clock issues | ~10% of restarts | <1% of restarts |
| Cross-region attestation failures | ~2% of requests | <0.01% of requests |
| Legitimate node rejections | Significant | Negligible |

**Why Not Looser (e.g., 30 seconds)?**

A 30-second tolerance would create security risks:

| Risk | Impact |
|------|--------|
| Extended replay window | Larger window for captured quote reuse (mitigated by nonce) |
| Reduced anomaly detection | Harder to identify infrastructure issues |
| Delayed compromise detection | More time for attacker to operate undetected |

**Relationship to Other Timing Parameters:**

```
┌────────────────────────────────────────────────────────────────┐
│                    TIMING PARAMETER HIERARCHY                   │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Quote Freshness (50-200ms)                                    │
│  ├── Primary replay prevention                                 │
│  └── Enforced via nonce mechanism                              │
│                                                                │
│  Nonce Expiration (30s)                                        │
│  ├── Maximum quote delivery window                             │
│  └── Limits network delay exploitation                         │
│                                                                │
│  TPM Clock Drift (5s)        ←── THIS PARAMETER                │
│  ├── Infrastructure health indicator                           │
│  ├── NOT a security-critical window                            │
│  └── Triggers reputation penalty if exceeded                   │
│                                                                │
│  NTP Check Interval (1 min)                                    │
│  ├── Continuous clock sync monitoring                          │
│  └── Catches deliberate desync attempts                        │
│                                                                │
│  NTP Grace Period (5 min)                                      │
│  ├── Recovery window for sync issues                           │
│  └── Prevents spurious rejections                              │
│                                                                │
└────────────────────────────────────────────────────────────────┘

INVARIANT: Quote Freshness << Nonce Expiration < TPM Clock Drift
           (50-200ms)        (30s)              (5s)

Note: TPM Clock Drift is NOT in the critical path for quote validation.
      It is a secondary health check that identifies infrastructure issues.
```

```go
// NonceManager prevents nonce replay attacks
type NonceManager struct {
    usedNonces    map[[32]byte]time.Time
    expirationTTL time.Duration
    mu            sync.RWMutex
}

func NewNonceManager(ttl time.Duration) *NonceManager {
    nm := &NonceManager{
        usedNonces:    make(map[[32]byte]time.Time),
        expirationTTL: ttl,
    }
    go nm.cleanupLoop()
    return nm
}

// GenerateNonce creates a fresh, cryptographically secure nonce
func (nm *NonceManager) GenerateNonce() ([32]byte, error) {
    var nonce [32]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        return nonce, ErrNonceGenerationFailed
    }
    
    nm.mu.Lock()
    nm.usedNonces[nonce] = time.Now()
    nm.mu.Unlock()
    
    return nonce, nil
}

// ValidateNonce checks if nonce is fresh and unused
func (nm *NonceManager) ValidateNonce(nonce [32]byte, quoteTime time.Time) error {
    nm.mu.RLock()
    issued, exists := nm.usedNonces[nonce]
    nm.mu.RUnlock()
    
    // Nonce must have been issued by us
    if !exists {
        return ErrNonceNotIssued
    }
    
    // Check nonce hasn't expired
    if time.Since(issued) > nm.expirationTTL {
        return ErrNonceExpired
    }
    
    // Verify quote time is within freshness window of nonce issuance
    timeDelta := quoteTime.Sub(issued)
    if timeDelta < 0 {
        return ErrQuoteTimeBeforeNonce
    }
    if timeDelta > nm.expirationTTL {
        return ErrQuoteTimeTooLate
    }
    
    // Mark nonce as consumed (one-time use)
    nm.mu.Lock()
    delete(nm.usedNonces, nonce)
    nm.mu.Unlock()
    
    return nil
}

#### Nonce Storage Bounds (CANONICAL)

The NonceManager implements bounded storage with deterministic cleanup to prevent memory exhaustion attacks.

**Storage Constants:**

```go
const (
    // MaxNonceCacheSize is the maximum number of active nonces in memory
    // Rationale: 100,000 nonces * 40 bytes (32-byte nonce + 8-byte timestamp) = 4MB max memory
    // This supports approximately 3,300 attestations per second with 30-second TTL
    MaxNonceCacheSize = 100_000

    // NonceCleanupInterval defines how frequently expired nonces are purged
    // Set to 1/6 of TTL to ensure timely cleanup without excessive CPU overhead
    NonceCleanupInterval = 5 * time.Second

    // NonceEvictionBatchSize is the number of entries to evict when cache is full
    // Evicts oldest 10% to avoid thrashing
    NonceEvictionBatchSize = 10_000
)
```

**Eviction Policy:**

When the nonce cache reaches `MaxNonceCacheSize`, the following eviction policy applies:

| Condition | Action | Priority |
|-----------|--------|----------|
| Cache full | Evict oldest 10% by issuance time | Immediate |
| Nonce expired (>30s) | Delete during cleanup cycle | Normal |
| Nonce validated | Delete after validation | Immediate |

```go
// cleanupLoop runs periodic cleanup of expired nonces
func (nm *NonceManager) cleanupLoop() {
    ticker := time.NewTicker(NonceCleanupInterval)
    defer ticker.Stop()

    for range ticker.C {
        nm.cleanup()
    }
}

// cleanup removes expired nonces and enforces cache size limits
func (nm *NonceManager) cleanup() {
    nm.mu.Lock()
    defer nm.mu.Unlock()

    now := time.Now()
    expiredCount := 0

    // Phase 1: Remove all expired nonces
    for nonce, issued := range nm.usedNonces {
        if now.Sub(issued) > nm.expirationTTL {
            delete(nm.usedNonces, nonce)
            expiredCount++
        }
    }

    // Phase 2: If still over limit, evict oldest entries
    if len(nm.usedNonces) > MaxNonceCacheSize {
        nm.evictOldest(NonceEvictionBatchSize)
    }

    // Record metrics for monitoring
    nm.metrics.RecordCleanup(expiredCount, len(nm.usedNonces))
}

// evictOldest removes the N oldest nonces by issuance time
func (nm *NonceManager) evictOldest(count int) {
    // Build sorted list of nonces by age
    type nonceAge struct {
        nonce  [32]byte
        issued time.Time
    }

    nonces := make([]nonceAge, 0, len(nm.usedNonces))
    for nonce, issued := range nm.usedNonces {
        nonces = append(nonces, nonceAge{nonce: nonce, issued: issued})
    }

    // Sort by issued time (oldest first)
    sort.Slice(nonces, func(i, j int) bool {
        return nonces[i].issued.Before(nonces[j].issued)
    })

    // Evict oldest entries
    evicted := 0
    for _, na := range nonces {
        if evicted >= count {
            break
        }
        delete(nm.usedNonces, na.nonce)
        evicted++
    }

    nm.metrics.RecordEviction(evicted, "cache_full")
}

// GenerateNonce creates a fresh nonce with cache overflow protection
func (nm *NonceManager) GenerateNonce() ([32]byte, error) {
    var nonce [32]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        return nonce, ErrNonceGenerationFailed
    }

    nm.mu.Lock()
    defer nm.mu.Unlock()

    // Check cache capacity before inserting
    if len(nm.usedNonces) >= MaxNonceCacheSize {
        // Trigger emergency eviction
        nm.evictOldest(NonceEvictionBatchSize)
    }

    nm.usedNonces[nonce] = time.Now()
    return nonce, nil
}
```

**Security Considerations:**

1. **Memory Exhaustion Prevention**: Hard cap prevents attackers from exhausting memory by requesting excessive nonces without completing attestation.

2. **Oldest-First Eviction**: LRU-style eviction ensures legitimate recent nonces are preserved while stale entries are cleaned.

3. **Cleanup Frequency**: 5-second cleanup interval (1/6 of 30s TTL) balances memory efficiency against CPU overhead. At maximum load (3,300 attestations/sec), approximately 16,500 nonces are issued between cleanups.

4. **Atomic Operations**: All cache modifications hold the mutex to prevent race conditions during concurrent attestation requests.

5. **Metrics Integration**: All eviction and cleanup events are recorded for security monitoring and capacity planning.

#### Nonce Management Parameters (CANONICAL)

Enhanced nonce management with structured format and per-node tracking provides defense-in-depth against replay and timing attacks.

**Core Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| Nonce Maximum Age | 30 seconds | Maximum validity period for any nonce |
| Replay Detection Window | 60 seconds | Window for detecting replayed nonces |
| Cleanup Batch Size | 10,000 | Entries removed per cleanup cycle |
| Per-Node Tracking | Enabled | Track nonce usage per originating node |

```go
const (
    // Nonce Timing
    NonceMaxAge            = 30 * time.Second   // Maximum nonce validity
    ReplayDetectionWindow  = 60 * time.Second   // Window for replay detection
    NonceCleanupBatchSize  = 10_000             // Batch size for cleanup operations

    // Structured Nonce Format
    NonceTimestampBytes    = 8                  // Bytes for embedded timestamp
    NonceRandomBytes       = 20                 // Bytes for random component
    NonceNodeIDBytes       = 4                  // Bytes for node identifier
    NonceTotalBytes        = 32                 // Total nonce size (256 bits)
)
```

**Structured Nonce Format:**

The nonce format embeds metadata to enable efficient validation and per-node tracking:

```
┌─────────────────────────────────────────────────────────────────┐
│                    32-Byte Structured Nonce                      │
├──────────────┬──────────────┬──────────────────────────────────┤
│  Timestamp   │   Node ID    │        Random Component           │
│   (8 bytes)  │  (4 bytes)   │          (20 bytes)               │
├──────────────┼──────────────┼──────────────────────────────────┤
│ Unix nano    │ Hash(NodeID) │   crypto/rand                     │
│ truncated    │ truncated    │   160 bits entropy                │
└──────────────┴──────────────┴──────────────────────────────────┘
```

```go
// StructuredNonce contains embedded timestamp and node tracking
type StructuredNonce struct {
    Timestamp  time.Time    // Embedded timestamp for age validation
    NodeIDHash [4]byte      // Truncated hash of originating node
    Random     [20]byte     // Cryptographic random component
}

// GenerateStructuredNonce creates a nonce with embedded metadata
func GenerateStructuredNonce(nodeID NodeID) (*StructuredNonce, error) {
    nonce := &StructuredNonce{
        Timestamp: time.Now(),
    }

    // Embed truncated node ID hash for per-node tracking
    nodeHash := sha256.Sum256(nodeID[:])
    copy(nonce.NodeIDHash[:], nodeHash[:4])

    // Generate random component
    if _, err := rand.Read(nonce.Random[:]); err != nil {
        return nil, ErrNonceGenerationFailed
    }

    return nonce, nil
}

// Bytes serializes the structured nonce to 32 bytes
func (sn *StructuredNonce) Bytes() [32]byte {
    var result [32]byte
    binary.BigEndian.PutUint64(result[0:8], uint64(sn.Timestamp.UnixNano()))
    copy(result[8:12], sn.NodeIDHash[:])
    copy(result[12:32], sn.Random[:])
    return result
}

// ParseStructuredNonce deserializes a 32-byte nonce
func ParseStructuredNonce(data [32]byte) *StructuredNonce {
    return &StructuredNonce{
        Timestamp:  time.Unix(0, int64(binary.BigEndian.Uint64(data[0:8]))),
        NodeIDHash: [4]byte(data[8:12]),
        Random:     [20]byte(data[12:32]),
    }
}
```

**Per-Node Nonce Tracking:**

Track nonce usage per node to detect anomalous request patterns:

```go
// PerNodeNonceTracker monitors nonce requests per node
type PerNodeNonceTracker struct {
    nodeNonces map[NodeID]*nodeNonceState
    mu         sync.RWMutex
}

type nodeNonceState struct {
    activeNonces  map[[32]byte]time.Time  // Currently active nonces
    recentNonces  map[[32]byte]time.Time  // Recently used (replay detection)
    requestCount  uint64                   // Total requests
    lastRequest   time.Time                // Last nonce request
}

// ValidateNonceForNode performs per-node nonce validation
func (t *PerNodeNonceTracker) ValidateNonceForNode(
    nodeID NodeID,
    nonce [32]byte,
) error {
    t.mu.RLock()
    state, exists := t.nodeNonces[nodeID]
    t.mu.RUnlock()

    if !exists {
        return ErrNonceNotIssued
    }

    // Check if nonce was recently used (replay detection)
    if _, replayed := state.recentNonces[nonce]; replayed {
        t.recordReplayAttempt(nodeID, nonce)
        return ErrNonceReplayDetected
    }

    // Parse structured nonce for age validation
    structured := ParseStructuredNonce(nonce)
    if time.Since(structured.Timestamp) > NonceMaxAge {
        return ErrNonceExpired
    }

    // Verify node ID hash matches
    nodeHash := sha256.Sum256(nodeID[:])
    if !bytes.Equal(structured.NodeIDHash[:], nodeHash[:4]) {
        return ErrNonceNodeMismatch
    }

    return nil
}

// Error types for enhanced nonce management
var (
    ErrNonceReplayDetected = errors.New("nonce replay attack detected")
    ErrNonceNodeMismatch   = errors.New("nonce node ID does not match requester")
)
```

**Replay Detection Window:**

The 60-second replay detection window (2x the nonce maximum age) ensures that even if an attacker captures a valid nonce, they cannot replay it after it has been consumed:

| Time | Nonce State | Action |
|------|-------------|--------|
| T+0s | Generated | Active, awaiting validation |
| T+30s | Expired | No longer valid for new attestations |
| T+60s | Purged | Removed from replay detection tracking |


// ValidateQuoteFreshness verifies TPM quote timing with network-aware windows
func ValidateQuoteFreshness(
    quote *TPMQuote,
    nonce [32]byte,
    issueTime time.Time,
    networkType NetworkType,
) error {
    // Get appropriate freshness window
    var window time.Duration
    switch networkType {
    case NetworkLocal:
        window = DefaultLocalFreshness
    case NetworkRegional:
        window = DefaultRegionalFreshness
    case NetworkGlobal:
        window = DefaultGlobalFreshness
    default:
        window = DefaultLocalFreshness // Most restrictive as default
    }
    
    // Verify quote timestamp
    quoteAge := time.Since(quote.Timestamp)
    if quoteAge < -window || quoteAge > window {
        return &QuoteFreshnessError{
            ExpectedWindow: window,
            ActualAge:      quoteAge,
            NetworkType:    networkType,
        }
    }
    
    // Verify nonce matches
    if !bytes.Equal(quote.Nonce[:], nonce[:]) {
        return ErrNonceMismatch
    }
    
    // Verify TPM clock is monotonic (if available)
    if quote.TPMClockInfo.Safe {
        // TPM clock has been verified as monotonic
        // Check for clock drift
        drift := time.Duration(quote.TPMClockInfo.ClockValue) - time.Since(quote.TPMClockInfo.ResetCount)
        if drift > DefaultMaxClockDrift || drift < -DefaultMaxClockDrift {
            return &ClockDriftError{Drift: drift, MaxAllowed: DefaultMaxClockDrift}
        }
    }
    
    return nil
}

// Error types
var (
    ErrNonceGenerationFailed = errors.New("failed to generate cryptographic nonce")
    ErrNonceNotIssued        = errors.New("nonce was not issued by this verifier")
    ErrNonceExpired          = errors.New("nonce has expired")
    ErrQuoteTimeBeforeNonce  = errors.New("quote timestamp is before nonce issuance")
    ErrQuoteTimeTooLate      = errors.New("quote timestamp is too late after nonce issuance")
    ErrNonceMismatch         = errors.New("quote nonce does not match challenge")
)
```

#### Security Considerations

1. **Local Network (+/-50ms)**: Use for same-datacenter attestation where network latency is minimal and timing attacks are most feasible.

2. **Regional Network (+/-100ms)**: Appropriate for nodes within the same geographic region where network conditions are predictable.

3. **Global Network (+/-200ms)**: Required for cross-region attestation to account for network latency variations.

4. **Nonce One-Time Use**: Each nonce is consumed after validation to prevent replay attacks.

5. **Monotonic Counter Verification**: When available, the TPM clock monotonic property provides additional assurance against time manipulation.

6. **Clock Drift Detection**: Maximum 5-second drift tolerance prevents clock skew attacks while accommodating legitimate drift.

---

## 5. Non-Configurable Parameters

### User-Configurable (Node-Specific Only)

```go
type NodeConfig struct {
    // Node Identity (auto-generated)
    NodeID         NodeID
    PrivateKeyPath string

    // Resource Limits (user declares capabilities)
    MaxStorageGB    int
    MaxUploadMbps   int
    MaxDownloadMbps int

    // Network (auto-detected or specified)
    ListenAddr  string  // "0.0.0.0:9999"
    PublicIP    string  // "auto" or specify
    IPv6Address string  // "auto" or specify

    // Gateway Settings
    GatewayType    string  // "residential", "business", "datacenter"
    CanAnnounceBGP bool
    ASN            uint32

    // Paths
    DataDir string
    LogDir  string
}

func (nc *NodeConfig) Validate() error {
    if nc.MaxStorageGB < 1 {
        return errors.New("must contribute at least 1GB storage")
    }
    if nc.MaxUploadMbps < MinBandwidthLeaf/1_000_000 {
        return errors.New("must contribute at least 10 Mbps upload")
    }
    // User CANNOT set tier, reputation, etc. - those are calculated
    return nil
}
```

---

## 6. TPM Trust Policy (CANONICAL)

### Binary Trust Model (CANONICAL)

The DHT uses a **binary trust model** - nodes are either **Trusted** or **Untrusted**. There is no middle ground.

| Trust Level | EK Certificate Requirement | Can Earn Reputation | Role Access |
|-------------|---------------------------|---------------------|-------------|
| **Trusted** | EK chains to configured Manufacturer CA | **Yes** | All roles (Leaf -> Coordinator) |
| **Untrusted** | EK does NOT chain to any configured CA | **No** | DDoS work required |

**Trust Determination (CA-Based):**
- Trust is determined **purely** by EK certificate chain validation
- Privacy CA is configured with a set of trusted TPM Manufacturer CA certificates
- EK certificate is validated against configured Manufacturer CAs
- Trust status is embedded in the IDevID certificate
- **NO hardcoding** of TPM types (fTPM, swtpm, etc.) - trust is entirely configuration-driven

### Privacy CA Manufacturer Configuration

The Privacy CA dynamically loads trusted TPM Manufacturer CA certificates via the go-xkms CA API (consumed through go-quicbaas SDK). This is the **ONLY** mechanism for trust determination:

```go
// Dynamic import of manufacturer EK CA certificates
err := privacyCA.ImportEndorsementKeyCertificate(manufacturerCACert)

// Recursive import from AIA extensions
err := privacyCA.ImportIssuingCAs(ekCert)
```

**Certificate Storage**: Imported CA certificates are stored in the filesystem:
```
/app/data/ca/certs/
├── intel-tpm-ek-ca.pem        # Intel (fTPM + dTPM)
├── amd-tpm-ek-ca.pem          # AMD (fTPM + dTPM)
├── infineon-tpm-ek-ca.pem     # Infineon dTPM
├── stmicro-tpm-ek-ca.pem      # STMicroelectronics
├── nuvoton-tpm-ek-ca.pem      # Nuvoton
└── ...                        # Additional manufacturers as needed
```

### Common TPM Manufacturers

Example manufacturers whose CA certificates can be configured:

| Manufacturer | TPM Types | Typical Configuration |
|--------------|-----------|----------------------|
| Intel | fTPM (PTT) + discrete | Trusted if Intel CA configured |
| AMD | fTPM + discrete | Trusted if AMD CA configured |
| Infineon Technologies | Discrete TPM | Trusted if Infineon CA configured |
| STMicroelectronics | Discrete TPM | Trusted if ST CA configured |
| Nuvoton Technology | Discrete TPM | Trusted if Nuvoton CA configured |

### Trust Determination Examples

| TPM Type | Manufacturer | EK Chain Validates To | Trust Level |
|----------|--------------|----------------------|-------------|
| Intel fTPM (PTT) | Intel | Intel CA (if configured) | **TRUSTED** |
| AMD fTPM | AMD | AMD CA (if configured) | **TRUSTED** |
| Infineon dTPM | Infineon | Infineon CA (if configured) | **TRUSTED** |
| swtpm | Self-signed | No chain (self-signed) | **UNTRUSTED** |
| Unknown vendor | Unknown | No configured CA | **UNTRUSTED** |

### Untrusted Node Capabilities

Untrusted nodes can still participate in the network, but with restrictions:

| Operation | Allowed | Notes |
|-----------|---------|-------|
| Join network | Yes | Receives IDevID marked as "untrusted" |
| Route DHT messages | Yes | Can forward messages |
| Observe network state | Yes | Can read DHT data |
| **Earn reputation** | **No** | Permanently capped at 0.0 |
| **Assume any role** | **No** | Cannot be Leaf, Hub, Gateway, Coordinator, or CA |
| **Participate in FROST** | **No** | Cannot hold key shares |
| **Sign certificates** | **No** | Cannot participate in CA pool |

**Use Cases for Untrusted Nodes:**
- Development and testing without hardware TPM
- Monitoring and observation
- Low-trust client access
- Temporary participation

```go
type TrustLevel uint8

const (
    TrustLevelUntrusted TrustLevel = iota  // swtpm, fTPM, unknown EK
    TrustLevelTrusted                       // Hardware TPM with whitelisted EK
)

type TPMVerificationResult struct {
    TrustLevel         TrustLevel
    Manufacturer       string
    Model              string
    FirmwareVersion    string
    EKFingerprint      string
    IsHardwareTPM      bool
    IsWhitelistedEK    bool
    CVEStatus          string  // "clean", "quarantine", "blocked"
}

func DetermineTrustLevel(result *TPMVerificationResult) TrustLevel {
    // Must be hardware TPM with whitelisted EK to be trusted
    if result.IsHardwareTPM && result.IsWhitelistedEK && result.CVEStatus == "clean" {
        return TrustLevelTrusted
    }
    return TrustLevelUntrusted
}
```

### TPM Tier Classification (CANONICAL)

Beyond the binary Trusted/Untrusted distinction, the platform classifies TPMs into tiers based on their implementation type. This classification determines eligibility for specific roles, particularly CA pool participation.

| Tier | Constant | Description | Implementation |
|------|----------|-------------|----------------|
| 1 | `TPMTierHardware` | Discrete TPM chips from approved manufacturers | Physical chip on motherboard or add-in card |
| 2 | `TPMTierFirmware` | Firmware TPM (fTPM) | Runs in CPU secure enclave (Intel PTT, AMD fTPM) |
| 3 | `TPMTierCloud` | Virtual TPM (vTPM) | Cloud provider attestation (AWS Nitro, Azure vTPM, GCP vTPM) |
| 4 | `TPMTierPlatform` | Platform-minted EK | Foundation backbone nodes only |

```go
// TPMTier classifies the implementation type of a TPM
type TPMTier uint8

const (
    TPMTierHardware  TPMTier = 1 // Discrete hardware TPM from approved manufacturer
    TPMTierFirmware  TPMTier = 2 // Firmware TPM (Intel PTT, AMD fTPM)
    TPMTierCloud     TPMTier = 3 // Virtual TPM (AWS Nitro, Azure vTPM, GCP vTPM)
    TPMTierPlatform  TPMTier = 4 // Platform-minted EK for foundation backbone
)

// TPMTierName returns human-readable tier name
func TPMTierName(tier TPMTier) string {
    switch tier {
    case TPMTierHardware:
        return "Hardware"
    case TPMTierFirmware:
        return "Firmware"
    case TPMTierCloud:
        return "Cloud"
    case TPMTierPlatform:
        return "Platform"
    default:
        return "Unknown"
    }
}
```

**Tier Determination:**
- **TPMTierHardware**: EK certificate chains to an approved discrete TPM manufacturer CA (Infineon, STMicroelectronics, Nuvoton, Microchip/Atmel, Nations Technologies)
- **TPMTierFirmware**: EK certificate chains to Intel PTT or AMD fTPM manufacturer CA
- **TPMTierCloud**: EK certificate chains to cloud provider vTPM CA (AWS, Azure, GCP)
- **TPMTierPlatform**: EK certificate issued by the platform's own Privacy CA with platform-minted marker

### Manufacturer CA Whitelist (CANONICAL)

The following manufacturers are approved for hardware TPM tier classification. Only TPMs with EK certificates chaining to these manufacturer CAs qualify for `TPMTierHardware`.

| Manufacturer | Headquarters | Products | Notes |
|--------------|--------------|----------|-------|
| Infineon Technologies | Germany | SLB 9665, SLB 9670, OPTIGA TPM | Largest TPM market share |
| STMicroelectronics | Switzerland | ST33TPHF2x series | Common in enterprise systems |
| Nuvoton Technology | Taiwan | NPCT7xx series | Widely used in consumer devices |
| Microchip/Atmel | USA | ATECC608, AT97SC3204 | Acquired Atmel TPM line |
| Nations Technologies | China | Z32H330TC | Regional availability |

**Adding New Manufacturers:**
- New manufacturers may be added via governance proposal
- Requires security audit of manufacturing practices
- 2/3 supermajority vote in treasury governance
- See "Manufacturer Whitelist Governance" section below for full process

### TPM Tier Eligibility Matrix (CANONICAL)

| TPM Tier | CA Pool Eligible | Infrastructure Eligible | Notes |
|----------|-----------------|------------------------|-------|
| Hardware (1) | **YES** | YES | Only tier eligible for CA pool participation |
| Firmware (2) | NO | YES | General network participation, not CA pool |
| Cloud (3) | NO | YES | VPS/cloud hosted nodes |
| Platform (4) | NO | YES | Foundation backbone infrastructure only |

**CA Pool Restriction Rationale:**
- Hardware TPMs provide the highest assurance of key protection
- Firmware TPMs run in CPU secure enclaves which may have larger attack surface
- Cloud TPMs depend on cloud provider security guarantees
- Platform TPMs are controlled by the foundation and would create centralization risk

```go
// CanJoinCAPool determines if a node's TPM tier allows CA pool participation
func CanJoinCAPool(tier TPMTier) bool {
    return tier == TPMTierHardware
}

// CanJoinInfrastructure determines if a node can participate in network infrastructure
func CanJoinInfrastructure(tier TPMTier) bool {
    // All tiers can participate in infrastructure with valid trust status
    return tier >= TPMTierHardware && tier <= TPMTierPlatform
}
```

> **Note on OrganizationID:** For CA pool constraints (e.g., the 10% single-organization limit), the network uses `OrganizationID` derived from verified domain or economic stake rather than per-TPM `OwnerID`. This ensures diversity constraints apply to real-world entities. See [docs/dht/26-organization-identity.md](26-organization-identity.md) for the complete Organization Identity specification.

### Manufacturer Whitelist Governance

**Adding Manufacturers:**
- Proposal submitted to treasury with details
- Community review period (minimum 7 days)
- 2/3 supermajority vote required
- Security audit required before approval

**Removing Manufacturers:**
- Emergency removal: Immediate action by Foundation for active compromise
- Standard removal: 2/3 supermajority vote required
- All affected nodes immediately become Untrusted
- No grace period - trust is binary

**Evaluation Criteria:**
1. Security track record (CVEs, response time, patch quality)
2. Manufacturing standards (FIPS 140-2/3, Common Criteria EAL4+)
3. Key management practices
4. Incident response capability
5. Market presence and stability

### CVE Response Protocol

**Quarantine Model:** Affected nodes enter quarantine (limited participation) rather than full blocking.

**Trust Status Levels:**

| Status | Description | Operations |
|--------|-------------|------------|
| **Trusted** | No known issues | All operations |
| **Quarantine** | Known CVE | Routing and validation only |
| **Blocked** | Manufacturer compromise or critical CVE | No participation |

**Quarantine Restrictions:**

| Operation | Allowed | Notes |
|-----------|---------|-------|
| DHT Query Routing | Yes | Reduced weight |
| Transaction Confirmation | Yes | Limited voting |
| Reputation Earning | No | Frozen |
| CA Signing Operations | No | Revoked |
| Hub Role | No | Demoted |
| Gateway Role | No | Demoted |
| Coordinator Role | No | Removed |

**CVE Response Steps:**

1. **Verification** - Assess severity, exploitability, patch availability
2. **Quarantine Activation** - Broadcast to network, apply restrictions
3. **Remediation** - Firmware update, TPM replacement, or hardware replacement
4. **Re-Attestation** - Fresh attestation with updated TPM, quarantine lifted

```go
type CVEQuarantineRule struct {
    CVEID           string
    ManufacturerID  string
    AffectedModels  []string
    AffectedFirmware struct {
        MinVersion string
        MaxVersion string
    }
    Severity       string  // "critical", "high", "medium", "low"
    ActivationDate time.Time
    PatchAvailable bool
    GracePeriod    time.Duration
}
```

### Manufacturer Compromise Response

**Triggers:**
1. Root key compromise
2. Malicious firmware distribution
3. Systematic counterfeiting
4. Regulatory action on facilities
5. Repeated gross security negligence

**Immediate Actions (T+0):**
- Emergency blocklist activation (no quarantine)
- Network alert broadcast
- Certificate revocation for all affected nodes
- Remove from routing tables

**Medium-Term (T+24h):**
- Detailed incident report published
- Treasury vote (2/3 supermajority to ratify; if fails, blocklist lifted after 7 days)

**Long-Term (T+7d):**
- Node operators replace TPM hardware
- Fresh attestation required to rejoin
- Post-incident review

### Certificate Transparency for TPM EK Certificates

Certificate Transparency (CT) provides an additional layer of security by logging all TPM Endorsement Key certificates, enabling detection of anomalous issuance patterns and compromised manufacturer CAs.

**CT Requirements:**

| Requirement | Value | Purpose |
|-------------|-------|---------|
| CT Log Submission | Mandatory | All EK certificates logged |
| Inclusion Proof | Required | Verify certificate in CT log |
| Anomaly Detection | Enabled | Detect issuance rate spikes |
| Batch Record Cross-Reference | Enabled | Validate against manufacturing data |

```go
const (
    // CT Log Configuration
    CTLogSubmissionRequired = true                    // Mandatory CT logging
    CTLogMaxLatency         = 24 * time.Hour          // Maximum merge delay
    CTInclusionProofTimeout = 5 * time.Minute         // Timeout for proof retrieval

    // Anomaly Detection Thresholds
    EKIssuanceRateThreshold = 1000                    // EKs per manufacturer per hour
    EKIssuanceSpikeFactor   = 5.0                     // 5x normal triggers alert
    EKBatchSizeThreshold    = 10000                   // Maximum batch size per submission
)
```

**CT Log Integration:**

```go
// EKCertificateCTMonitor monitors Certificate Transparency for EK certificates
type EKCertificateCTMonitor struct {
    ctLogs          []CTLogClient
    manufacturerCAs map[string]*x509.Certificate
    issuanceRates   map[string]*issuanceRateTracker
    batchRecords    map[string]*manufacturingBatchRecord
    mu              sync.RWMutex
}

// SubmitEKCertificate logs an EK certificate to CT logs
func (m *EKCertificateCTMonitor) SubmitEKCertificate(
    ekCert *x509.Certificate,
) (*CTSubmissionResult, error) {
    // Submit to multiple CT logs for redundancy
    var scts []*SignedCertificateTimestamp
    for _, ctLog := range m.ctLogs {
        sct, err := ctLog.SubmitCertificate(ekCert)
        if err != nil {
            m.metrics.RecordCTSubmissionFailure(ctLog.URL, err)
            continue
        }
        scts = append(scts, sct)
    }

    if len(scts) == 0 {
        return nil, ErrCTSubmissionFailed
    }

    return &CTSubmissionResult{
        Certificate: ekCert,
        SCTs:        scts,
        SubmittedAt: time.Now(),
    }, nil
}

// VerifyInclusionProof validates that an EK certificate is in the CT log
func (m *EKCertificateCTMonitor) VerifyInclusionProof(
    ekCert *x509.Certificate,
    sct *SignedCertificateTimestamp,
) error {
    ctLog := m.getLogByID(sct.LogID)
    if ctLog == nil {
        return ErrUnknownCTLog
    }

    proof, err := ctLog.GetInclusionProof(sct.Timestamp, ekCert)
    if err != nil {
        return ErrInclusionProofFailed
    }

    if !proof.Verify() {
        return ErrInclusionProofInvalid
    }

    return nil
}
```

**Anomaly Detection for EK Issuance:**

Detect unusual patterns in EK certificate issuance that may indicate compromise:

```go
// issuanceRateTracker monitors EK issuance rates per manufacturer
type issuanceRateTracker struct {
    manufacturerID string
    hourlyRates    []int                  // Rolling 24-hour window
    currentHour    int                    // Current hour's count
    lastReset      time.Time              // Last hourly reset
    baselineRate   float64                // Normal issuance rate
}

// DetectIssuanceAnomaly checks for abnormal EK issuance patterns
func (m *EKCertificateCTMonitor) DetectIssuanceAnomaly(
    manufacturerID string,
) (*IssuanceAnomalyResult, error) {
    m.mu.RLock()
    tracker, exists := m.issuanceRates[manufacturerID]
    m.mu.RUnlock()

    if !exists {
        return nil, ErrUnknownManufacturer
    }

    currentRate := float64(tracker.currentHour)
    if currentRate > tracker.baselineRate*EKIssuanceSpikeFactor {
        return &IssuanceAnomalyResult{
            ManufacturerID:  manufacturerID,
            CurrentRate:     currentRate,
            BaselineRate:    tracker.baselineRate,
            SpikeFactor:     currentRate / tracker.baselineRate,
            Severity:        calculateSeverity(currentRate, tracker.baselineRate),
            RecommendedAction: RecommendedActionQuarantine,
        }, nil
    }

    return nil, nil // No anomaly detected
}
```

**Manufacturing Batch Record Cross-Reference:**

Validate EK certificates against known manufacturing batch records:

```go
// manufacturingBatchRecord contains expected TPM production data
type manufacturingBatchRecord struct {
    ManufacturerID   string
    BatchID          string
    ProductionDate   time.Time
    ExpectedCount    int
    SerialRangeStart string
    SerialRangeEnd   string
    ValidityPeriod   time.Duration
}

// CrossReferenceBatchRecord validates EK against manufacturing data
func (m *EKCertificateCTMonitor) CrossReferenceBatchRecord(
    ekCert *x509.Certificate,
) (*BatchValidationResult, error) {
    // Extract manufacturer and batch info from EK certificate
    manufacturerID := extractManufacturerID(ekCert)
    batchID := extractBatchID(ekCert)

    m.mu.RLock()
    record, exists := m.batchRecords[batchID]
    m.mu.RUnlock()

    if !exists {
        // Unknown batch - flag for review
        return &BatchValidationResult{
            Valid:             false,
            Reason:            "Unknown manufacturing batch",
            RecommendedAction: RecommendedActionReview,
        }, nil
    }

    // Validate certificate against batch record
    if record.ManufacturerID != manufacturerID {
        return &BatchValidationResult{
            Valid:  false,
            Reason: "Manufacturer mismatch for batch",
            RecommendedAction: RecommendedActionReject,
        }, nil
    }

    // Check serial number is within expected range
    if !isSerialInRange(ekCert.SerialNumber, record.SerialRangeStart, record.SerialRangeEnd) {
        return &BatchValidationResult{
            Valid:  false,
            Reason: "Serial number outside batch range",
            RecommendedAction: RecommendedActionReject,
        }, nil
    }

    return &BatchValidationResult{
        Valid:    true,
        BatchID:  batchID,
        Verified: time.Now(),
    }, nil
}
```

**Compromised Manufacturer CA Detection:**

Monitor for signs of manufacturer CA compromise through CT log analysis:

```go
// CompromisedCAIndicator defines signs of CA compromise
type CompromisedCAIndicator struct {
    IndicatorType    string
    Severity         string
    Description      string
    DetectedAt       time.Time
    AffectedCerts    int
}

// DetectCompromisedManufacturerCA analyzes CT logs for compromise indicators
func (m *EKCertificateCTMonitor) DetectCompromisedManufacturerCA(
    manufacturerID string,
) ([]CompromisedCAIndicator, error) {
    var indicators []CompromisedCAIndicator

    // Check 1: Sudden issuance rate spike
    anomaly, err := m.DetectIssuanceAnomaly(manufacturerID)
    if err == nil && anomaly != nil {
        indicators = append(indicators, CompromisedCAIndicator{
            IndicatorType: "issuance_spike",
            Severity:      string(anomaly.Severity),
            Description:   fmt.Sprintf("%.1fx normal issuance rate", anomaly.SpikeFactor),
            DetectedAt:    time.Now(),
        })
    }

    // Check 2: Certificates with invalid batch records
    invalidBatchCount := m.countInvalidBatchCerts(manufacturerID)
    if invalidBatchCount > 10 {
        indicators = append(indicators, CompromisedCAIndicator{
            IndicatorType: "invalid_batches",
            Severity:      "high",
            Description:   fmt.Sprintf("%d certificates with invalid batch records", invalidBatchCount),
            DetectedAt:    time.Now(),
            AffectedCerts: invalidBatchCount,
        })
    }

    // Check 3: Duplicate serial numbers
    duplicates := m.findDuplicateSerials(manufacturerID)
    if len(duplicates) > 0 {
        indicators = append(indicators, CompromisedCAIndicator{
            IndicatorType: "duplicate_serials",
            Severity:      "critical",
            Description:   fmt.Sprintf("%d duplicate serial numbers detected", len(duplicates)),
            DetectedAt:    time.Now(),
            AffectedCerts: len(duplicates),
        })
    }

    // Check 4: Certificates issued after revocation
    postRevocationCerts := m.findPostRevocationCerts(manufacturerID)
    if len(postRevocationCerts) > 0 {
        indicators = append(indicators, CompromisedCAIndicator{
            IndicatorType: "post_revocation_issuance",
            Severity:      "critical",
            Description:   "Certificates issued after CA revocation",
            DetectedAt:    time.Now(),
            AffectedCerts: len(postRevocationCerts),
        })
    }

    return indicators, nil
}
```

**CT Error Types:**

```go
var (
    ErrCTSubmissionFailed    = errors.New("failed to submit certificate to CT logs")
    ErrUnknownCTLog          = errors.New("unknown CT log identifier")
    ErrInclusionProofFailed  = errors.New("failed to retrieve inclusion proof")
    ErrInclusionProofInvalid = errors.New("inclusion proof verification failed")
    ErrUnknownManufacturer   = errors.New("unknown TPM manufacturer")
)
```

---

## 7. Node Scrutiny System

### Scrutiny Levels (CANONICAL)

Trust-based monitoring and rate limiting applied to all nodes based on their trust status:

| Level | Target | Rate Multiplier | PoW Required | Work Required | Monitoring Interval |
|-------|--------|-----------------|--------------|---------------|---------------------|
| **Minimal** | Trusted nodes (EK chains to configured CA) | 100% | No | None | 5 minutes |
| **Standard** | Probationary trusted nodes (< 90 days) | 80% | No | None | 1 minute |
| **Elevated** | Untrusted nodes (EK doesn't chain to CA) | 50% | Yes | 4 hours/day | 30 seconds |
| **Maximum** | Flagged/suspicious nodes | 10% | Yes | 8 hours/day | 10 seconds |

```go
type ScrutinyLevel int

const (
    ScrutinyMinimal    ScrutinyLevel = 0  // Trusted nodes
    ScrutinyStandard   ScrutinyLevel = 1  // Probationary trusted
    ScrutinyElevated   ScrutinyLevel = 2  // Untrusted nodes
    ScrutinyMaximum    ScrutinyLevel = 3  // Flagged/suspicious
)
```

### Scrutiny Constraints

```go
var ScrutinyConstraints = map[ScrutinyLevel]Constraints{
    ScrutinyMinimal: {
        RateMultiplier:     1.0,
        PoWRequired:        false,
        WorkContribution:   0,
        MonitoringInterval: 5*time.Minute,
        QuarantineOnFlag:   false,
    },
    ScrutinyElevated: {
        RateMultiplier:     0.5,
        PoWRequired:        true,
        WorkContribution:   4,  // hours/day
        MonitoringInterval: 30*time.Second,
        QuarantineOnFlag:   true,
    },
}
```

### Misbehavior Types

| Type | Description | First Offense | Third Offense |
|------|-------------|---------------|---------------|
| Rate Limit Violation | Exceeding allocated rate limits | 1 hour ban | Permanent ban |
| Malformed Requests | Sending invalid protocol messages | Warning | 24 hour ban |
| Replay Attack | Reusing authentication tokens | 24 hour ban | Permanent ban |
| Protocol Violation | Breaking DHT protocol rules | 1 hour ban | Permanent ban |
| Sybil Pattern | Multiple identities detected | Permanent ban | N/A |
| DDoS Participation | Participating in attacks | Permanent ban | N/A |
| Work Refusal | Refusing assigned DDoS work | Scrutiny escalation | Permanent ban |
| False Reporting | Filing false accusations | 1 hour ban | Permanent ban |

See [17-untrusted-nodes.md](17-untrusted-nodes.md) for complete untrusted node work assignment system.

---

## 8. Attack Scenarios and Mitigations

### Threshold Signature Attack

**Threat:** Attacker compromises 33% of CA pool to forge certificates.

**Analysis:**
- With 1M node network: 330K nodes needed
- Cost estimate: $1000/node x 330K = $330M

**Mitigations:**
- TPM attestation (cannot fake compromise)
- Geographic distribution
- Reputation requirements (90+ days, 0.8+ score)
- Anomaly detection on certificate patterns
- Consider lowering threshold to 25%

### DKG Polynomial Degree Attack (CVE-2024)

**Threat:** Malicious participant uses degree T > t polynomial, silently raising threshold.

**Impact:** Key becomes unusable if T >= n.

**Mitigation (MANDATORY):**
```go
if len(commitment.Coefficients) != threshold {
    return ErrInvalidCoefficientCount
}
```

### Sybil Attack

**Threat:** Attacker creates many nodes to gain influence.

**Current Defenses:**
- 90-day probation
- 100 successful CA signatures required
- TPM attestation

**Enhanced Defenses:**
- Geographic diversity check (GeoIP)
- Monthly bandwidth re-verification
- Reputation decay (0.1%/day without activity)
- Logarithmic penalty for same subnet

### Eclipse Attack Mitigation (CANONICAL)

**Threat:** Attacker isolates target by controlling DHT neighbors, enabling partition attacks, censorship, and traffic manipulation.

**Attack Vectors:**
1. Node ID manipulation to target specific buckets
2. Gradual neighbor replacement through strategic joins
3. Coordinated Sybil nodes surrounding the target
4. Exploitation of geographic or network proximity

#### DHT Neighbor Diversity Requirements

**CRITICAL SECURITY REQUIREMENT**: Every node MUST maintain diverse neighbors across multiple dimensions to prevent isolation attacks.

**Diversity Dimensions:**

| Dimension | Minimum Diversity | Enforcement |
|-----------|------------------|-------------|
| **Geographic (Region)** | >= 3 distinct regions | Protocol-level |
| **Autonomous System (ASN)** | >= 3 distinct ASNs | Protocol-level |
| **Organization** | >= 2 distinct organizations | Best-effort |
| **Network Prefix (/24)** | >= 5 distinct prefixes | Protocol-level |
| **Trust Status** | 100% Trusted peers | Hard requirement |

```go
// DiversityRequirements defines minimum neighbor diversity thresholds
type DiversityRequirements struct {
    MinDistinctRegions       int  // Minimum geographic regions (>=3)
    MinDistinctASNs          int  // Minimum autonomous systems (>=3)
    MinDistinctOrganizations int  // Minimum organizations (>=2)
    MinDistinctNetworkPrefixes int // Minimum /24 prefixes (>=5)
    MaxSameRegionPercent     float64 // Maximum peers from same region (<=40%)
    MaxSameASNPercent        float64 // Maximum peers from same ASN (<=30%)
    MaxSamePrefixPercent     float64 // Maximum peers from same /24 (<=10%)
}

var DefaultDiversityRequirements = DiversityRequirements{
    MinDistinctRegions:        3,
    MinDistinctASNs:           3,
    MinDistinctOrganizations:  2,
    MinDistinctNetworkPrefixes: 5,
    MaxSameRegionPercent:      0.40,
    MaxSameASNPercent:         0.30,
    MaxSamePrefixPercent:      0.10,
}

// ===== PER-BUCKET DIVERSITY THRESHOLDS (CANONICAL) =====
//
// These thresholds define the MAXIMUM concentration allowed from any single
// diversity group within a Kademlia bucket. Violations trigger peer rejection.
//
// | Metric                    | Threshold | Description                              |
// |---------------------------|-----------|------------------------------------------|
// | MaxBucketSameSubnet       | 50%       | No more than half from same /24 subnet   |
// | MaxBucketSameASN          | 33%       | No more than 1/3 from same ASN           |
// | MaxBucketSameOrganization | 25%       | No more than 1/4 from same organization  |
// | MinEffectiveDiversity     | 3 groups  | Minimum entropy: 3 effective groups      |
//
// Effective diversity is computed using Shannon entropy:
//   H = -sum(p_i * log2(p_i)) where p_i is the fraction from group i
//   MinEffectiveDiversity = 2^H >= 3 (equivalent to 1.58 bits of entropy)

const (
    // Per-bucket concentration limits
    MaxBucketSameSubnetPercent = 0.50       // <=50% of bucket from same /24 subnet
    MaxBucketSameASNPercent    = 0.33       // <=33% of bucket from same ASN  
    MaxBucketSameOrgPercent    = 0.25       // <=25% of bucket from same organization
    
    // Minimum entropy requirement (effective diversity groups)
    MinEffectiveDiversityGroups = 3         // Minimum 3 effective diversity groups
    MinDiversityEntropyBits     = 1.58      // log2(3) = 1.58 bits minimum entropy
)

// BucketDiversityThresholds defines per-bucket concentration limits
type BucketDiversityThresholds struct {
    MaxSameSubnetPercent float64  // Maximum peers from same /24 subnet
    MaxSameASNPercent    float64  // Maximum peers from same ASN
    MaxSameOrgPercent    float64  // Maximum peers from same organization
    MinEffectiveGroups   int      // Minimum effective diversity groups (entropy-based)
}

var DefaultBucketThresholds = BucketDiversityThresholds{
    MaxSameSubnetPercent: MaxBucketSameSubnetPercent,  // 50%
    MaxSameASNPercent:    MaxBucketSameASNPercent,     // 33%
    MaxSameOrgPercent:    MaxBucketSameOrgPercent,     // 25%
    MinEffectiveGroups:   MinEffectiveDiversityGroups, // 3
}

// CalculateEffectiveDiversity computes the effective number of diversity groups
// using Shannon entropy. Returns 2^H where H is the entropy in bits.
func CalculateEffectiveDiversity(groupCounts map[string]int, totalPeers int) float64 {
    if totalPeers == 0 {
        return 0
    }
    
    entropy := 0.0
    for _, count := range groupCounts {
        if count > 0 {
            p := float64(count) / float64(totalPeers)
            entropy -= p * math.Log2(p)
        }
    }
    
    // Effective diversity = 2^H
    return math.Pow(2, entropy)
}

// ValidateBucketDiversity checks if a bucket meets diversity requirements
func (v *PeerDiversityValidator) ValidateBucketDiversity(bucket *KademliaBucket) error {
    peers := bucket.GetPeers()
    totalPeers := len(peers)
    
    if totalPeers == 0 {
        return nil // Empty bucket is valid
    }
    
    // Count peers per diversity group
    subnetCounts := make(map[string]int)
    asnCounts := make(map[uint32]int)
    orgCounts := make(map[string]int)
    
    for _, peer := range peers {
        subnetCounts[peer.NetworkPrefix]++
        asnCounts[peer.ASN]++
        orgCounts[peer.Organization]++
    }
    
    // Check subnet concentration
    for subnet, count := range subnetCounts {
        if float64(count)/float64(totalPeers) > DefaultBucketThresholds.MaxSameSubnetPercent {
            return &BucketDiversityError{
                BucketIndex: bucket.Index,
                Code:        "SUBNET_CONCENTRATION",
                Reason:      fmt.Sprintf("%.0f%% peers from subnet %s exceeds 50%% limit",
                    float64(count)/float64(totalPeers)*100, subnet),
            }
        }
    }
    
    // Check ASN concentration
    for asn, count := range asnCounts {
        if float64(count)/float64(totalPeers) > DefaultBucketThresholds.MaxSameASNPercent {
            return &BucketDiversityError{
                BucketIndex: bucket.Index,
                Code:        "ASN_CONCENTRATION",
                Reason:      fmt.Sprintf("%.0f%% peers from ASN %d exceeds 33%% limit",
                    float64(count)/float64(totalPeers)*100, asn),
            }
        }
    }
    
    // Check organization concentration
    for org, count := range orgCounts {
        if float64(count)/float64(totalPeers) > DefaultBucketThresholds.MaxSameOrgPercent {
            return &BucketDiversityError{
                BucketIndex: bucket.Index,
                Code:        "ORG_CONCENTRATION",
                Reason:      fmt.Sprintf("%.0f%% peers from org %s exceeds 25%% limit",
                    float64(count)/float64(totalPeers)*100, org),
            }
        }
    }
    
    // Check effective diversity (entropy-based)
    // Convert asnCounts to string map for entropy calculation
    asnStringCounts := make(map[string]int)
    for asn, count := range asnCounts {
        asnStringCounts[fmt.Sprintf("%d", asn)] = count
    }
    
    effectiveDiversity := CalculateEffectiveDiversity(asnStringCounts, totalPeers)
    if effectiveDiversity < float64(DefaultBucketThresholds.MinEffectiveGroups) {
        return &BucketDiversityError{
            BucketIndex: bucket.Index,
            Code:        "LOW_ENTROPY",
            Reason:      fmt.Sprintf("effective diversity %.2f below minimum %d groups",
                effectiveDiversity, DefaultBucketThresholds.MinEffectiveGroups),
        }
    }
    
    return nil
}

const (
    // EclipseDetectionCheckInterval is how often to verify neighbor diversity
    EclipseDetectionCheckInterval = 5 * time.Minute

    // EclipseAlertThreshold triggers alert when diversity drops below this percent of requirements
    EclipseAlertThreshold = 0.75  // 75% of minimum diversity

    // EclipseQuarantineThreshold triggers quarantine when critically low
    EclipseQuarantineThreshold = 0.50  // 50% of minimum diversity

    // NeighborRefreshOnEclipseDetection forces neighbor refresh when eclipse suspected
    NeighborRefreshOnEclipseDetection = true
)
```

#### Peer Diversity Validation Protocol

Every routing table modification MUST pass diversity validation:

```go
// PeerDiversityValidator enforces neighbor diversity requirements
type PeerDiversityValidator struct {
    geoIP           GeoIPDatabase
    asnDatabase     ASNDatabase
    orgDatabase     OrganizationDatabase
    requirements    DiversityRequirements
    routingTable    *RoutingTable
    alertManager    AlertManager
    metrics         DiversityMetrics
}

// PeerDiversityInfo contains diversity metadata for a peer
type PeerDiversityInfo struct {
    NodeID          [32]byte
    IPAddress       net.IP
    Region          string    // ISO 3166-1 region code
    ASN             uint32    // Autonomous System Number
    Organization    string    // Organization name from WHOIS
    NetworkPrefix   string    // /24 prefix
    TrustLevel      TrustLevel
    AddedAt         time.Time
}

// ValidatePeerAddition checks if adding a peer maintains diversity requirements
func (v *PeerDiversityValidator) ValidatePeerAddition(newPeer *PeerDiversityInfo) error {
    // Rule 1: Must be trusted
    if newPeer.TrustLevel != TrustLevelTrusted {
        return &DiversityError{
            Code:   "UNTRUSTED_PEER",
            Reason: "only trusted peers may be added to routing table",
        }
    }

    // Get current peer distribution
    currentPeers := v.routingTable.GetAllPeers()
    stats := v.calculateDiversityStats(currentPeers)

    // Rule 2: Check region concentration
    if stats.RegionCounts[newPeer.Region]+1 > int(float64(len(currentPeers)+1)*v.requirements.MaxSameRegionPercent) {
        if stats.DistinctRegions < v.requirements.MinDistinctRegions {
            return &DiversityError{
                Code:   "REGION_CONCENTRATION",
                Reason: fmt.Sprintf("adding peer would exceed %d%% from region %s with only %d distinct regions",
                    int(v.requirements.MaxSameRegionPercent*100), newPeer.Region, stats.DistinctRegions),
            }
        }
    }

    // Rule 3: Check ASN concentration
    if stats.ASNCounts[newPeer.ASN]+1 > int(float64(len(currentPeers)+1)*v.requirements.MaxSameASNPercent) {
        if stats.DistinctASNs < v.requirements.MinDistinctASNs {
            return &DiversityError{
                Code:   "ASN_CONCENTRATION",
                Reason: fmt.Sprintf("adding peer would exceed %d%% from ASN %d with only %d distinct ASNs",
                    int(v.requirements.MaxSameASNPercent*100), newPeer.ASN, stats.DistinctASNs),
            }
        }
    }

    // Rule 4: Check /24 prefix concentration
    if stats.PrefixCounts[newPeer.NetworkPrefix]+1 > int(float64(len(currentPeers)+1)*v.requirements.MaxSamePrefixPercent) {
        return &DiversityError{
            Code:   "PREFIX_CONCENTRATION",
            Reason: fmt.Sprintf("adding peer would exceed %d%% from prefix %s",
                int(v.requirements.MaxSamePrefixPercent*100), newPeer.NetworkPrefix),
        }
    }

    return nil
}

// DiversityStats contains current routing table diversity metrics
type DiversityStats struct {
    TotalPeers        int
    DistinctRegions   int
    DistinctASNs      int
    DistinctOrgs      int
    DistinctPrefixes  int
    RegionCounts      map[string]int
    ASNCounts         map[uint32]int
    OrgCounts         map[string]int
    PrefixCounts      map[string]int
    DiversityScore    float64  // 0.0-1.0 overall diversity health
}

// calculateDiversityStats computes current diversity metrics
func (v *PeerDiversityValidator) calculateDiversityStats(peers []*PeerDiversityInfo) *DiversityStats {
    stats := &DiversityStats{
        TotalPeers:   len(peers),
        RegionCounts: make(map[string]int),
        ASNCounts:    make(map[uint32]int),
        OrgCounts:    make(map[string]int),
        PrefixCounts: make(map[string]int),
    }

    for _, peer := range peers {
        stats.RegionCounts[peer.Region]++
        stats.ASNCounts[peer.ASN]++
        stats.OrgCounts[peer.Organization]++
        stats.PrefixCounts[peer.NetworkPrefix]++
    }

    stats.DistinctRegions = len(stats.RegionCounts)
    stats.DistinctASNs = len(stats.ASNCounts)
    stats.DistinctOrgs = len(stats.OrgCounts)
    stats.DistinctPrefixes = len(stats.PrefixCounts)

    // Calculate overall diversity score
    stats.DiversityScore = v.calculateDiversityScore(stats)

    return stats
}
```

#### Eclipse Attack Detection Mechanisms

```go
// EclipseDetector identifies potential eclipse attacks in progress
type EclipseDetector struct {
    validator      *PeerDiversityValidator
    routingTable   *RoutingTable
    alertManager   AlertManager
    auditLog       AuditLogger
    checkInterval  time.Duration
}

// EclipseIndicator represents a detected eclipse attack indicator
type EclipseIndicator struct {
    Type        EclipseIndicatorType
    Severity    Severity
    Description string
    Evidence    []byte
    DetectedAt  time.Time
    AffectedBuckets []int
}

type EclipseIndicatorType string

const (
    EclipseIndicatorLowDiversity       EclipseIndicatorType = "LOW_DIVERSITY"
    EclipseIndicatorRapidChurn         EclipseIndicatorType = "RAPID_PEER_CHURN"
    EclipseIndicatorCoordinatedJoins   EclipseIndicatorType = "COORDINATED_JOINS"
    EclipseIndicatorBucketTargeting    EclipseIndicatorType = "BUCKET_TARGETING"
    EclipseIndicatorRouteManipulation  EclipseIndicatorType = "ROUTE_MANIPULATION"
)

// DetectEclipseAttempt analyzes current state for eclipse attack indicators
func (d *EclipseDetector) DetectEclipseAttempt(ctx context.Context) []EclipseIndicator {
    var indicators []EclipseIndicator

    // Check 1: Overall diversity score
    stats := d.validator.calculateDiversityStats(d.routingTable.GetAllPeers())
    if stats.DiversityScore < EclipseAlertThreshold {
        indicators = append(indicators, EclipseIndicator{
            Type:        EclipseIndicatorLowDiversity,
            Severity:    SeverityHigh,
            Description: fmt.Sprintf("diversity score %.2f below threshold %.2f", 
                stats.DiversityScore, EclipseAlertThreshold),
            DetectedAt:  time.Now(),
        })
    }

    // Check 2: Rapid peer churn (>50% replacement in 1 hour)
    churnRate := d.calculatePeerChurnRate(1 * time.Hour)
    if churnRate > 0.50 {
        indicators = append(indicators, EclipseIndicator{
            Type:        EclipseIndicatorRapidChurn,
            Severity:    SeverityMedium,
            Description: fmt.Sprintf("%.0f%% peer churn in last hour", churnRate*100),
            DetectedAt:  time.Now(),
        })
    }

    // Check 3: Coordinated joins from same ASN/region
    coordinated := d.detectCoordinatedJoins(15 * time.Minute)
    if len(coordinated) > 0 {
        indicators = append(indicators, EclipseIndicator{
            Type:        EclipseIndicatorCoordinatedJoins,
            Severity:    SeverityHigh,
            Description: fmt.Sprintf("%d coordinated join patterns detected", len(coordinated)),
            Evidence:    d.serializePatterns(coordinated),
            DetectedAt:  time.Now(),
        })
    }

    // Record and alert
    for _, indicator := range indicators {
        d.auditLog.RecordEclipseIndicator(indicator)
        if indicator.Severity >= SeverityHigh {
            d.alertManager.Fire(AlertEclipseDetected{Indicator: indicator})
        }
    }

    return indicators
}
```

#### Eclipse Attack Response Protocol

```go
// EclipseResponseManager handles detected eclipse attacks
type EclipseResponseManager struct {
    detector       *EclipseDetector
    routingTable   *RoutingTable
    bootstrapNodes []string
    alertManager   AlertManager
}

// RespondToEclipse executes defensive measures when eclipse detected
func (m *EclipseResponseManager) RespondToEclipse(ctx context.Context, indicators []EclipseIndicator) error {
    // Classify severity
    maxSeverity := SeverityLow
    for _, ind := range indicators {
        if ind.Severity > maxSeverity {
            maxSeverity = ind.Severity
        }
    }

    switch maxSeverity {
    case SeverityCritical:
        return m.respondCritical(ctx, indicators)
    case SeverityHigh:
        return m.respondHigh(ctx, indicators)
    default:
        return m.respondMedium(ctx, indicators)
    }
}

// respondCritical handles critical eclipse situations
func (m *EclipseResponseManager) respondCritical(ctx context.Context, indicators []EclipseIndicator) error {
    // Step 1: Enter defensive mode (reject new connections temporarily)
    m.routingTable.EnterDefensiveMode(5 * time.Minute)

    // Step 2: Purge suspicious peers (low diversity contributors)
    purged := m.purgeLowDiversityPeers()

    // Step 3: Force refresh from bootstrap nodes
    for _, bootstrap := range m.bootstrapNodes {
        if err := m.routingTable.RefreshFromBootstrap(ctx, bootstrap); err != nil {
            continue // Try next bootstrap
        }
    }

    // Step 4: Initiate out-of-band connectivity verification
    m.verifyConnectivityOutOfBand(ctx)

    // Step 5: Alert operators
    m.alertManager.Fire(AlertCriticalEclipse{
        Indicators:   indicators,
        PeersPurged:  purged,
        ResponseTime: time.Now(),
    })

    return nil
}
```

#### Network-Wide Eclipse Claim Validation (CANONICAL)

Eclipse detection at a single node is insufficient for network-wide response. To prevent false positives and coordinated manipulation, eclipse claims MUST be validated across multiple independent nodes before triggering network-wide alerts.

**Validation Requirements:**

| Requirement | Threshold | Rationale |
|-------------|-----------|-----------|
| Independent Detections | >= 3 nodes | Prevents single-node false positive |
| ASN Diversity | 3 different ASNs | Prevents colluding ISP customers |
| Time Window | Within 5 minutes | Ensures temporal correlation |
| Evidence Required | Merkle proof of indicators | Prevents fabricated claims |

**False Eclipse Detection Penalty:**

Filing a false eclipse claim (not corroborated by network) incurs reputation penalty:

| Offense | Penalty | Cooldown |
|---------|---------|----------|
| First false claim | -0.05 reputation | 24 hours |
| Second false claim | -0.10 reputation | 7 days |
| Third+ false claim | -0.20 reputation | 30 days |

```go
// NetworkEclipseValidator coordinates network-wide eclipse claim validation
type NetworkEclipseValidator struct {
    localDetector    *EclipseDetector
    p2pNetwork       P2PNetwork
    claimRegistry    *EclipseClaimRegistry
    reputationMgr    ReputationManager
}

// EclipseClaim represents a node's claim of being under eclipse attack
type EclipseClaim struct {
    ClaimantNodeID   [32]byte
    ClaimantASN      uint32
    Indicators       []EclipseIndicator
    EvidenceRoot     [32]byte              // Merkle root of evidence
    EvidenceProof    [][]byte              // Merkle proof
    Timestamp        time.Time
    Signature        []byte                // Node signature over claim
}

// EclipseClaimValidation tracks validation state across the network
type EclipseClaimValidation struct {
    OriginalClaim    *EclipseClaim
    Confirmations    []*EclipseConfirmation
    RequiredConf     int                   // Minimum confirmations (3)
    UniqueASNs       map[uint32]bool       // Track ASN diversity
    ValidationStart  time.Time
    ValidationWindow time.Duration         // 5 minutes
    Status           EclipseClaimStatus
}

type EclipseClaimStatus string

const (
    EclipseClaimPending    EclipseClaimStatus = "PENDING"
    EclipseClaimValidated  EclipseClaimStatus = "VALIDATED"
    EclipseClaimRejected   EclipseClaimStatus = "REJECTED"
    EclipseClaimExpired    EclipseClaimStatus = "EXPIRED"
)

const (
    // MinEclipseConfirmations is the minimum independent detections required
    MinEclipseConfirmations = 3
    
    // MinEclipseASNDiversity requires confirmations from different ASNs
    MinEclipseASNDiversity = 3
    
    // EclipseValidationWindow is the time window for gathering confirmations
    EclipseValidationWindow = 5 * time.Minute
    
    // FalseEclipseClaimPenalty is the reputation penalty for unconfirmed claims
    FalseEclipseClaimPenalty = -0.10
)

// BroadcastEclipseClaim announces a potential eclipse attack to the network
func (v *NetworkEclipseValidator) BroadcastEclipseClaim(ctx context.Context, indicators []EclipseIndicator) error {
    // Build Merkle tree of evidence
    evidenceRoot, proof := v.buildEvidenceMerkleTree(indicators)
    
    claim := &EclipseClaim{
        ClaimantNodeID: v.localDetector.routingTable.LocalNodeID(),
        ClaimantASN:    v.localDetector.routingTable.LocalASN(),
        Indicators:     indicators,
        EvidenceRoot:   evidenceRoot,
        EvidenceProof:  proof,
        Timestamp:      time.Now(),
    }
    
    // Sign the claim
    claim.Signature = v.signClaim(claim)
    
    // Epidemic broadcast to neighbors
    return v.p2pNetwork.EpidemicBroadcast(ctx, "eclipse-claim", claim)
}

// ValidateEclipseClaim processes incoming eclipse claims from peers
func (v *NetworkEclipseValidator) ValidateEclipseClaim(ctx context.Context, claim *EclipseClaim) error {
    // Step 1: Verify claim signature
    if err := v.verifyClaimSignature(claim); err != nil {
        return fmt.Errorf("invalid claim signature: %w", err)
    }
    
    // Step 2: Verify Merkle proof of evidence
    if !v.verifyEvidenceMerkleProof(claim.Indicators, claim.EvidenceRoot, claim.EvidenceProof) {
        return ErrInvalidEvidenceProof
    }
    
    // Step 3: Register claim and check for existing validation
    validation := v.claimRegistry.GetOrCreate(claim)
    
    // Step 4: Perform local verification of similar indicators
    localIndicators := v.localDetector.DetectEclipseAttempt(ctx)
    if v.indicatorsCorrelate(claim.Indicators, localIndicators) {
        confirmation := &EclipseConfirmation{
            ConfirmerNodeID: v.localDetector.routingTable.LocalNodeID(),
            ConfirmerASN:    v.localDetector.routingTable.LocalASN(),
            LocalIndicators: localIndicators,
            Timestamp:       time.Now(),
        }
        validation.AddConfirmation(confirmation)
    }
    
    // Step 5: Check if validation threshold reached
    if validation.IsValidated() {
        return v.executeNetworkWideResponse(ctx, validation)
    }
    
    return nil
}

// CheckClaimExpiration handles expired claims and applies penalties
func (v *NetworkEclipseValidator) CheckClaimExpiration(ctx context.Context) {
    expiredClaims := v.claimRegistry.GetExpiredClaims()
    
    for _, validation := range expiredClaims {
        if validation.Status == EclipseClaimPending {
            // Claim was not corroborated - apply reputation penalty
            v.reputationMgr.AdjustReputation(
                validation.OriginalClaim.ClaimantNodeID,
                FalseEclipseClaimPenalty,
                "false_eclipse_claim",
            )
            
            validation.Status = EclipseClaimRejected
            v.claimRegistry.Update(validation)
            
            // Log for security audit
            v.auditLog.Record("false_eclipse_claim", map[string]interface{}{
                "claimant":      hex.EncodeToString(validation.OriginalClaim.ClaimantNodeID[:]),
                "confirmations": len(validation.Confirmations),
                "required":      MinEclipseConfirmations,
                "penalty":       FalseEclipseClaimPenalty,
            })
        }
    }
}

// IsValidated checks if the claim has sufficient diverse confirmations
func (v *EclipseClaimValidation) IsValidated() bool {
    if time.Since(v.ValidationStart) > v.ValidationWindow {
        return false // Expired
    }
    
    if len(v.Confirmations) < MinEclipseConfirmations {
        return false // Not enough confirmations
    }
    
    if len(v.UniqueASNs) < MinEclipseASNDiversity {
        return false // Not enough ASN diversity
    }
    
    v.Status = EclipseClaimValidated
    return true
}
```

**Epidemic Alert Propagation:**

Validated eclipse claims are propagated using epidemic (gossip) protocol with Merkle proof of evidence:

```
1. Node A detects eclipse indicators
2. Node A broadcasts EclipseClaim with Merkle proof
3. Neighbors B, C, D receive claim
4. Each neighbor independently verifies:
   - Signature validity
   - Evidence Merkle proof
   - Local indicator correlation
5. Confirming neighbors broadcast EclipseConfirmation
6. When 3+ confirmations from 3+ ASNs received:
   - Claim is VALIDATED
   - Network-wide alert broadcast
   - Coordinated response initiated
7. If claim expires without validation:
   - Claimant receives -0.10 reputation penalty
   - Claim marked REJECTED
```

#### Bucket Eviction Resistance

Kademlia bucket eviction is hardened against eclipse attacks:

```go
// EvictionPolicy defines secure bucket eviction rules
type EvictionPolicy struct {
    // Never evict peers with high reputation for new unknown peers
    MinReputationForEviction float64 // Peer must have < 0.5 reputation to be evicted

    // Diversity-aware eviction: prefer evicting from over-represented groups
    PreferDiversityPreservingEviction bool

    // Liveness check before eviction
    RequireLivenessCheckBeforeEviction bool

    // Minimum peer age before eligible for eviction
    MinPeerAgeForEviction time.Duration
}

var DefaultEvictionPolicy = EvictionPolicy{
    MinReputationForEviction:          0.50,
    PreferDiversityPreservingEviction: true,
    RequireLivenessCheckBeforeEviction: true,
    MinPeerAgeForEviction:             1 * time.Hour,
}

// EvaluateEviction determines if a peer should be evicted for a new peer
func (rt *RoutingTable) EvaluateEviction(existing *PeerDiversityInfo, candidate *PeerDiversityInfo) bool {
    // Rule 1: Never evict for untrusted candidates
    if candidate.TrustLevel != TrustLevelTrusted {
        return false
    }

    // Rule 2: Protect high-reputation peers
    if existing.Reputation >= DefaultEvictionPolicy.MinReputationForEviction {
        return false
    }

    // Rule 3: Protect young peers (recently verified)
    if time.Since(existing.AddedAt) < DefaultEvictionPolicy.MinPeerAgeForEviction {
        return false
    }

    // Rule 4: Liveness check - only evict if peer fails to respond
    if DefaultEvictionPolicy.RequireLivenessCheckBeforeEviction {
        if rt.pingPeer(existing.NodeID) {
            return false // Peer is alive, don't evict
        }
    }

    return true
}
```

#### Eclipse Attack Mitigation Summary

| Defense Layer | Implementation | Effectiveness |
|---------------|----------------|---------------|
| **Diversity Requirements** | Minimum regions/ASNs/prefixes enforced | Prevents single-source dominance |
| **Continuous Monitoring** | 5-minute diversity checks | Early detection |
| **Coordinated Join Detection** | Timing analysis of peer joins | Identifies Sybil clusters |
| **Bucket Protection** | Reputation-based eviction resistance | Preserves established peers |
| **Out-of-Band Verification** | DNS/HTTP bootstrap cross-reference | Validates network view |
| **Bootstrap Refresh** | Multiple geographically distributed bootstraps | Recovery mechanism |
| **Defensive Mode** | Temporary connection rejection during attack | Prevents escalation |


### Nonce Reuse Attack

**Threat:** Same nonce used twice leaks secret key.

**Mitigations:**
- One-time commitments with unique IDs
- Immediate nonce deletion after use
- Atomic "used" marking
- TPM enforces single-use

---

## 9. BGP Security

### BGP Controller Architecture

The BGP Controller is a Go component running on backbone nodes:
- Monitors DHT for gateway promotions
- Validates gateway eligibility (reputation, uptime, age, TPM attestation)
- Coordinates multi-signature route announcements (3+ coordinators)
- Manages route injection via native Go BGP speaker (gobgp)
- Revokes routes immediately on demotions or security alerts

### Prefix Allocation

Automatic /48 assignment from pool:

```go
type PrefixAllocator struct {
    basePrefix   string        // "2602:F5BB::"
    allocatedMap sync.Map      // nodeID -> /48 prefix
    nextRegion   atomic.Uint32
}

func (pa *PrefixAllocator) AllocatePrefix(nodeID NodeID) (string, error) {
    if prefix, ok := pa.allocatedMap.Load(nodeID); ok {
        return prefix.(string), nil
    }

    regionID := pa.nextRegion.Add(1)
    if regionID > MaxRegions {
        return "", errors.New("exhausted region space")
    }

    // Format: 2602:F5BB:RRRR::/48
    prefix := fmt.Sprintf("2602:F5BB:%04X::/48", regionID)
    pa.allocatedMap.Store(nodeID, prefix)
    pa.db.Save(nodeID, prefix, regionID)
    return prefix, nil
}
```

### BGP Controller Workflow

1. **DHT Event** - Node promoted to Gateway tier
2. **Validate** - Reputation >= 0.85, uptime >= 95%, age >= 90 days, TPM current
3. **Allocate Prefix** - Assign /48 from pool (2602:F5BB:XXXX::/48)
4. **Collect Signatures** - Request 3+ coordinator signatures for route
5. **Announce Route:**
   - Backbone/Datacenter: Inject route via Go BGP speaker
   - Residential: Establish WireGuard tunnel to backbone
6. **Monitor** - Continuous health, traffic patterns, routing behavior
7. **Publish** - Gateway info to DHT

### BGP Hijacking Mitigations

**V1.0 (Required):**
- BGP MD5 session authentication (RFC 2385)
- BGP FlowSpec filtering (RFC 5575)
- Route anomaly monitoring

**V1.1:**
- RPKI validation
- ROA publication for all prefixes

---

## 10. Rogue Gateway Protection

### Multi-Layer Defense

#### Layer 1: Extended Probation

```go
const (
    MinAgeGateway          = 90 * 24 * time.Hour  // 3 months
    MinSuccessfulCASigning = 100                  // 100+ certs signed
    MinPeerConnections     = 50                   // 50+ verified peers
    NoViolationsPeriod     = 30 * 24 * time.Hour  // Clean for 30 days
)

func IsEligibleForGateway(node *Node) bool {
    if node.Age < MinAgeGateway {
        return false
    }
    if node.CASigning.SuccessCount < MinSuccessfulCASigning {
        return false
    }
    if node.Violations.LastViolation.After(time.Now().Add(-NoViolationsPeriod)) {
        return false
    }
    return node.Reputation >= MinReputationGateway &&
           node.Uptime >= MinUptimeHub &&
           node.TPMAttestation.Current()
}
```

#### Layer 2: Traffic Attestation

Coordinators send random test traffic through gateways:

```go
func (bc *BGPController) ProbeGateway(gateway *Node) {
    testDest := bc.selectRandomDestination()
    testPacket := createTestPacket(testDest)
    bc.sendViaGateway(gateway, testPacket)

    if !bc.checkDestinationReceived(testDest, testPacket) {
        gateway.Violations.RoutingFailures++
        if gateway.Violations.RoutingFailures > 3 {
            bc.revokeGateway(gateway, "repeated routing failures")
        }
    }
}
```

#### Layer 3: Multi-Signature Route Announcements

Gateways require 3+ coordinator co-signatures for BGP announcements:

```go
type RouteAnnouncement struct {
    GatewayID             NodeID
    Prefix                string
    Timestamp             time.Time
    GatewaySignature      []byte
    CoordinatorSignatures [][]byte  // 3+ required
}
```

#### Layer 4: Behavioral Monitoring

```go
type GatewayMonitor struct {
    baselines map[NodeID]*TrafficBaseline
}

type TrafficBaseline struct {
    AvgBytesPerSec       float64
    AvgConnectionsPerSec float64
    TopDestinations      []string
    TypicalLatency       time.Duration
}

func (gm *GatewayMonitor) DetectAnomalies(gateway *Node) []Anomaly {
    baseline := gm.baselines[gateway.ID]
    current := gm.getCurrentMetrics(gateway)

    var anomalies []Anomaly

    // Traffic spike (10x baseline)
    if current.BytesPerSec > baseline.AvgBytesPerSec*10 {
        anomalies = append(anomalies, Anomaly{Type: "traffic_spike", Severity: HIGH})
    }

    // Unusual destinations
    if !gm.destinationsMatch(current.Destinations, baseline.TopDestinations) {
        anomalies = append(anomalies, Anomaly{Type: "unusual_destinations", Severity: MEDIUM})
    }

    // High latency (3x typical)
    if current.Latency > baseline.TypicalLatency*3 {
        anomalies = append(anomalies, Anomaly{Type: "high_latency", Severity: MEDIUM})
    }

    if len(anomalies) > 0 {
        gm.investigateGateway(gateway, anomalies)
    }
    return anomalies
}
```

#### Layer 5: Economic Deterrence (Future)

```go
type GatewayStake struct {
    NodeID      NodeID
    Amount      uint64
    LockedUntil time.Time
}

func (gm *GatewayMonitor) SlashStake(gateway *Node, reason string) {
    stake := gm.getStake(gateway.ID)
    slashAmount := stake.Amount * 50 / 100  // Slash 50%
    gm.transferToInsurance(slashAmount)
    gm.revokeGateway(gateway, reason)
}
```

### Gateway Revocation Process

```go
func (bc *BGPController) RevokeGateway(gateway *Node, reason string) error {
    // 1. Emergency demotion in DHT
    bc.dht.Publish("tier-demotion", TierDemotionEvent{
        NodeID:    gateway.ID,
        Reason:    reason,
        Emergency: true,
    })

    // 2. Revoke BGP announcement
    if gateway.CanAnnounceBGP {
        bc.withdrawBGPRoute(gateway.AssignedPrefix)
        bc.frrGenerator.RemoveAnnouncement(gateway)
    } else {
        bc.terminateTunnel(gateway.ID)
    }

    // 3. Deallocate prefix
    bc.prefixAllocator.DeallocatePrefix(gateway.ID)

    // 4. 30-day blacklist
    bc.blacklistNode(gateway.ID, 30*24*time.Hour)

    // 5. Publish alert
    bc.dht.Publish("security-alert", SecurityAlert{
        Type:      "gateway_revoked",
        NodeID:    gateway.ID,
        Reason:    reason,
        Timestamp: time.Now(),
    })

    return nil
}
```

### Defense Summary

```
Layer 1: Extended Probation (90 days + 100 CA signatures + no violations)
Layer 2: Traffic Attestation (random probes verify routing)
Layer 3: Multi-Signature (coordinators co-sign BGP announcements)
Layer 4: Behavioral Monitoring (anomaly detection, traffic analysis)
Layer 5: Economic Deterrence (stake slashing)
Layer 6: Instant Revocation (automatic on detection)
```

---

## 11. Incident Response

### Key Compromise Detected

1. **Immediate:** Trigger emergency DKG rotation
2. **Within 5 min:** New pool active
3. **Within 1 hour:** Full investigation
4. **Within 24 hours:** Root cause analysis

### TPM Vulnerability Discovered

1. Identify affected TPM manufacturers/models
2. Add to blocklist
3. Force attestation refresh for affected nodes
4. Exclude from CA pools until patched

### DDoS Attack

1. Increase PoW difficulty dynamically
2. Activate threat intelligence sharing
3. Coordinate with gateway operators
4. Block attacking IPs at BGP level if necessary

---

## 12. Security Testing Requirements

| Test Type | Scope | Tools | Frequency |
|-----------|-------|-------|-----------|
| **Adversarial** | Protocol fuzzing | go-fuzz, AFL | Every PR |
| **Cryptographic** | FROST verification | Test vectors | Every build |
| **Failure Injection** | DKG interruption | Chaos engineering | Weekly |
| **Timing** | Side-channel leaks | Constant-time verification | Every crypto change |
| **Network** | Eclipse/Sybil simulation | Custom harness | Monthly |
| **Penetration** | Full system | External audit | Annually |

---

## 13. TPM Verification Flow (CA-Based Trust Model)

The verification flow determines a single binary outcome: **Trusted** or **Untrusted** based purely on EK certificate chain validation against configured Manufacturer CAs.

**Key Principle**: Trust is NOT hardcoded. It is determined entirely by whether the EK certificate validates to a configured Manufacturer CA in the Privacy CA's trust store.

```
Node Enrollment (ACME enroll-01)
    |
    v
Extract EK Certificate from TPM Attestation
    |
    v
+----------------------------------------+
| Validate EK Certificate Chain Against  |
| Privacy CA's Configured Manufacturer   |
| CA Certificates                        |
+----------------------------------------+
    |
    v
Does EK chain validate to ANY configured Manufacturer CA?
    |
    +-- No --> UNTRUSTED
    |          (EK doesn't chain to configured CA)
    |
    +-- Yes
    |
    v
[Optional] Check CVE Database for known vulnerabilities
    |
    +-- Critical/Blocked CVE --> UNTRUSTED
    |
    v
TRUSTED (Issue IDevID with TrustLevel=Trusted)
```

```go
// TrustDetermination validates EK certificates against configured CAs
// NO hardcoding of TPM types - trust is entirely configuration-driven
type TrustDetermination struct {
    // Configured trusted TPM Manufacturer CA certificates
    // Loaded from Privacy CA configuration at startup
    TrustedManufacturerCAs []*x509.Certificate
}

func (td *TrustDetermination) DetermineTrustLevel(ekCert *x509.Certificate) TrustLevel {
    // Build certificate pool from configured manufacturer CAs
    roots := x509.NewCertPool()
    for _, ca := range td.TrustedManufacturerCAs {
        roots.AddCert(ca)
    }

    // Validate EK certificate chain against configured CAs
    // This is the ONLY trust determination logic
    opts := x509.VerifyOptions{
        Roots: roots,
    }

    if _, err := ekCert.Verify(opts); err == nil {
        // EK chains to a configured manufacturer CA
        return TrustLevelTrusted
    }

    // EK does not chain to any configured CA
    return TrustLevelUntrusted
}

func (ca *PrivacyCA) IssueIDevID(csr *x509.CertificateRequest, attestation *TPMAttestation) (*x509.Certificate, error) {
    // Determine trust level
    trustLevel := ca.verifier.DetermineTrustLevel(attestation)

    // Create IDevID certificate with trust level embedded
    cert := &x509.Certificate{
        // ... standard fields ...
        ExtraExtensions: []pkix.Extension{
            {
                Id:       OIDTrustLevel,
                Critical: true,
                Value:    []byte{byte(trustLevel)},
            },
        },
    }

    // FROST threshold sign the certificate
    signedCert, err := ca.frostPool.Sign(cert)
    if err != nil {
        return nil, err
    }

    return signedCert, nil
}
```

### Trust Level in IDevID Certificate

The trust level is embedded in the IDevID certificate as a critical extension:

```go
var OIDTrustLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1} // Example OID

// ExtractTrustLevel reads trust level from IDevID certificate
func ExtractTrustLevel(cert *x509.Certificate) TrustLevel {
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(OIDTrustLevel) {
            if len(ext.Value) > 0 {
                return TrustLevel(ext.Value[0])
            }
        }
    }
    return TrustLevelUntrusted // Default to untrusted if not found
}
```

---

## 14. TPM Verification Protocol (Explicit Failure Handling)

**CRITICAL SECURITY REQUIREMENT**: TPM verification failures MUST result in explicit node rejection. Silent fallback to untrusted status is a security vulnerability that enables attackers to bypass hardware trust requirements.

### TPMVerificationResult Struct (Canonical)

All TPM verification operations MUST return a structured result with explicit error handling. NEVER return a silent fallback to untrusted status.

```go
// TPMVerificationResult is the canonical return type for all TPM verification operations
// MUST return explicit error - NEVER silent fallback to untrusted
type TPMVerificationResult struct {
    Valid       bool                        // Whether verification succeeded
    TrustLevel  TrustLevel                  // Resulting trust level (only valid if Valid=true)
    Error       error                       // Error if verification failed (nil if Valid=true)
    ErrorCode   TPMVerificationErrorCode    // Specific error code for categorization
    Details     *TPMVerificationDetails     // Additional verification details
}

// TPMVerificationErrorCode provides categorized error codes for programmatic handling
type TPMVerificationErrorCode string

const (
    TPMErrorNone                 TPMVerificationErrorCode = ""
    TPMErrorCertificateInvalid   TPMVerificationErrorCode = "CERTIFICATE_INVALID"
    TPMErrorChainUnverifiable    TPMVerificationErrorCode = "CHAIN_UNVERIFIABLE"
    TPMErrorQuoteFailed          TPMVerificationErrorCode = "QUOTE_VERIFICATION_FAILED"
    TPMErrorNonceMismatch        TPMVerificationErrorCode = "NONCE_MISMATCH"
    TPMErrorFreshnessExpired     TPMVerificationErrorCode = "FRESHNESS_EXPIRED"
    TPMErrorPCRViolation         TPMVerificationErrorCode = "PCR_POLICY_VIOLATION"
    TPMErrorCVEBlocked           TPMVerificationErrorCode = "CVE_BLOCKED"
    TPMErrorManufacturerBlocked  TPMVerificationErrorCode = "MANUFACTURER_BLOCKED"
    TPMErrorTimeout              TPMVerificationErrorCode = "ATTESTATION_TIMEOUT"
    TPMErrorOperationMismatch    TPMVerificationErrorCode = "OPERATION_HASH_MISMATCH"
)

// TPMVerificationDetails provides additional context for verification results
type TPMVerificationDetails struct {
    Manufacturer    string
    Model           string
    FirmwareVersion string
    EKFingerprint   string
    QuoteTimestamp  time.Time
    VerifiedAt      time.Time
    ChainDepth      int
    PCRsVerified    []int
}

// NewSuccessResult creates a successful verification result
func NewSuccessResult(trustLevel TrustLevel, details *TPMVerificationDetails) *TPMVerificationResult {
    return &TPMVerificationResult{
        Valid:      true,
        TrustLevel: trustLevel,
        Error:      nil,
        ErrorCode:  TPMErrorNone,
        Details:    details,
    }
}

// NewFailureResult creates a failed verification result
// CRITICAL: Always use this for failures - never return nil or silent fallback
func NewFailureResult(errorCode TPMVerificationErrorCode, err error) *TPMVerificationResult {
    return &TPMVerificationResult{
        Valid:      false,
        TrustLevel: 0,  // Invalid - do not use
        Error:      err,
        ErrorCode:  errorCode,
        Details:    nil,
    }
}
```

### Fail-Secure Design Principle

The TPM verification protocol follows fail-secure design: any verification failure results in enrollment rejection, not degraded trust status.

```
SECURITY INVARIANT:
  Verification Failure != Untrusted Status
  Verification Failure == Enrollment Rejection

RATIONALE:
  - Untrusted status grants network access (DHT routing, observation)
  - Attackers could intentionally fail verification to gain untrusted access
  - Untrusted nodes can still observe network state and patterns
  - Silent fallback creates audit gaps in security monitoring
```

### Verification Protocol Steps

The TPM verification protocol follows these steps with explicit error handling:

1. **Validate Certificate Chain**: Verify EK certificate chains to a configured Manufacturer CA
2. **Verify Quote Signature**: Cryptographically verify the TPM quote signature
3. **Check Nonce Freshness**: Verify quote nonce is within +/-100ms freshness window
4. **Determine Trust Level**: Extract trust level from validated certificate chain

```go
// VerifyTPMAttestation performs full TPM verification with explicit error handling
// Returns TPMVerificationResult - NEVER returns (TrustLevel, nil) for failures
func (v *TPMVerifier) VerifyTPMAttestation(
    ctx context.Context,
    attestation *TPMAttestation,
) *TPMVerificationResult {
    // Step 1: Validate certificate chain
    if err := v.validateCertificateChain(attestation.EKCertificate); err != nil {
        return NewFailureResult(TPMErrorChainUnverifiable, err)
    }

    // Step 2: Verify quote signature
    if err := v.verifyQuoteSignature(attestation); err != nil {
        return NewFailureResult(TPMErrorQuoteFailed, err)
    }

    // Step 3: Check nonce freshness (+/-100ms)
    if err := v.checkNonceFreshness(attestation.QuoteNonce, attestation.QuoteTimestamp); err != nil {
        return NewFailureResult(TPMErrorFreshnessExpired, err)
    }

    // Step 4: Determine trust level from chain
    trustLevel := v.determineTrustLevel(attestation.EKCertificate)

    details := &TPMVerificationDetails{
        Manufacturer:    v.extractManufacturer(attestation.EKCertificate),
        Model:           v.extractModel(attestation.EKCertificate),
        FirmwareVersion: attestation.FirmwareVersion,
        EKFingerprint:   v.computeEKFingerprint(attestation.EKCertificate),
        QuoteTimestamp:  time.Unix(0, attestation.QuoteTimestamp),
        VerifiedAt:      time.Now(),
        ChainDepth:      v.getChainDepth(attestation.EKCertificate),
        PCRsVerified:    attestation.PCRSelection,
    }

    return NewSuccessResult(trustLevel, details)
}
```

### Verification Failure Categories

| Category | Description | Result | Retry Allowed |
|----------|-------------|--------|---------------|
| **EK Certificate Invalid** | Malformed, expired, or corrupted EK cert | REJECT | No |
| **EK Chain Unverifiable** | Cannot build chain to any configured CA | REJECT | No |
| **Quote Verification Failed** | TPM quote signature invalid | REJECT | Yes (1x) |
| **Quote Freshness Expired** | Quote timestamp outside +/-100ms window | REJECT | Yes (1x) |
| **Nonce Mismatch** | Quote nonce does not match challenge | REJECT | No |
| **PCR Policy Violation** | PCR values do not match expected state | REJECT | No |
| **CVE Blocked** | TPM model has critical unpatched CVE | REJECT | No |
| **Manufacturer Blocklisted** | Manufacturer CA removed from trust store | REJECT | No |
| **Attestation Timeout** | Attestation response not received in time | REJECT | Yes (2x) |

### Verification State Machine

```go
type VerificationState uint8

const (
    VerificationPending    VerificationState = iota // Initial state
    VerificationInProgress                          // Attestation challenge sent
    VerificationSucceeded                           // Full verification passed
    VerificationRejected                            // Explicit rejection (terminal)
)

// VerificationRejected is a TERMINAL state - no transitions allowed
// Node must re-enroll with new attestation to attempt verification again
```

### Explicit Failure Protocol

```go
// TPMVerificationError represents an explicit verification failure
// All verification failures MUST be typed errors, never silent fallbacks
type TPMVerificationError struct {
    Category    VerificationFailureCategory
    NodeID      [32]byte
    Timestamp   time.Time
    Details     string
    RetryCount  int
    MaxRetries  int
    AuditTrail  []AuditEntry
}

func (e *TPMVerificationError) Error() string {
    return fmt.Sprintf("TPM verification rejected: category=%s, node=%x, details=%s",
        e.Category, e.NodeID[:8], e.Details)
}

// VerificationFailureCategory defines the type of verification failure
type VerificationFailureCategory string

const (
    FailureCategoryEKInvalid         VerificationFailureCategory = "ek_certificate_invalid"
    FailureCategoryChainUnverifiable VerificationFailureCategory = "chain_unverifiable"
    FailureCategoryQuoteFailed       VerificationFailureCategory = "quote_verification_failed"
    FailureCategoryFreshnessExpired  VerificationFailureCategory = "freshness_expired"
    FailureCategoryNonceMismatch     VerificationFailureCategory = "nonce_mismatch"
    FailureCategoryPCRViolation      VerificationFailureCategory = "pcr_policy_violation"
    FailureCategoryCVEBlocked        VerificationFailureCategory = "cve_blocked"
    FailureCategoryManufacturerBlock VerificationFailureCategory = "manufacturer_blocklisted"
    FailureCategoryTimeout           VerificationFailureCategory = "attestation_timeout"
)
```

### Verification Protocol Implementation

```go
type TPMVerifier struct {
    manufacturerCAs  []*x509.Certificate
    cveDatabase      CVEDatabase
    blocklist        Blocklist
    auditLog         AuditLogger
    metrics          MetricsCollector
}

// VerifyTPM performs full TPM verification with explicit failure handling
// Returns (TrustLevelTrusted, nil) on success
// Returns (_, TPMVerificationError) on failure - NEVER returns TrustLevelUntrusted
func (v *TPMVerifier) VerifyTPM(ctx context.Context, attestation *TPMAttestation) (TrustLevel, error) {
    // Create audit trail for this verification attempt
    audit := v.auditLog.BeginVerification(attestation.NodeID)
    defer audit.Complete()

    // Step 1: Validate EK certificate structure
    ekCert, err := v.parseEKCertificate(attestation.EKCertificate)
    if err != nil {
        audit.RecordFailure(FailureCategoryEKInvalid, err.Error())
        v.metrics.RecordVerificationFailure(FailureCategoryEKInvalid)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryEKInvalid,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   err.Error(),
        }
    }

    // Step 2: Verify EK certificate chain against configured manufacturer CAs
    if err := v.verifyEKChain(ekCert); err != nil {
        audit.RecordFailure(FailureCategoryChainUnverifiable, err.Error())
        v.metrics.RecordVerificationFailure(FailureCategoryChainUnverifiable)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryChainUnverifiable,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("EK does not chain to any configured manufacturer CA: %v", err),
        }
    }

    // Step 3: Check manufacturer blocklist
    manufacturer := v.extractManufacturer(ekCert)
    if v.blocklist.IsManufacturerBlocked(manufacturer) {
        audit.RecordFailure(FailureCategoryManufacturerBlock, manufacturer)
        v.metrics.RecordVerificationFailure(FailureCategoryManufacturerBlock)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryManufacturerBlock,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("manufacturer %s is blocklisted", manufacturer),
        }
    }

    // Step 4: Check CVE database for blocking vulnerabilities
    model := v.extractModel(ekCert)
    firmware := attestation.FirmwareVersion
    if cve := v.cveDatabase.CheckBlocking(manufacturer, model, firmware); cve != nil {
        audit.RecordFailure(FailureCategoryCVEBlocked, cve.ID)
        v.metrics.RecordVerificationFailure(FailureCategoryCVEBlocked)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryCVEBlocked,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("TPM affected by blocking CVE: %s", cve.ID),
        }
    }

    // Step 5: Verify quote nonce matches challenge
    if !bytes.Equal(attestation.QuoteNonce, attestation.ChallengeNonce) {
        audit.RecordFailure(FailureCategoryNonceMismatch, "nonce mismatch")
        v.metrics.RecordVerificationFailure(FailureCategoryNonceMismatch)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryNonceMismatch,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   "quote nonce does not match challenge nonce",
        }
    }

    // Step 6: Verify quote freshness (+/-100ms)
    quoteAge := time.Since(time.Unix(0, attestation.QuoteTimestamp))
    if quoteAge > TPMQuoteFreshness || quoteAge < -TPMQuoteFreshness {
        audit.RecordFailure(FailureCategoryFreshnessExpired, quoteAge.String())
        v.metrics.RecordVerificationFailure(FailureCategoryFreshnessExpired)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryFreshnessExpired,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("quote age %v exceeds freshness window of %v", quoteAge, TPMQuoteFreshness),
        }
    }

    // Step 7: Verify TPM quote signature
    if err := v.verifyQuoteSignature(attestation); err != nil {
        audit.RecordFailure(FailureCategoryQuoteFailed, err.Error())
        v.metrics.RecordVerificationFailure(FailureCategoryQuoteFailed)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryQuoteFailed,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("quote signature verification failed: %v", err),
        }
    }

    // Step 8: Verify PCR values match expected policy
    if err := v.verifyPCRPolicy(attestation.PCRValues); err != nil {
        audit.RecordFailure(FailureCategoryPCRViolation, err.Error())
        v.metrics.RecordVerificationFailure(FailureCategoryPCRViolation)
        return 0, &TPMVerificationError{
            Category:  FailureCategoryPCRViolation,
            NodeID:    attestation.NodeID,
            Timestamp: time.Now(),
            Details:   fmt.Sprintf("PCR policy violation: %v", err),
        }
    }

    // All verification steps passed - node is TRUSTED
    audit.RecordSuccess()
    v.metrics.RecordVerificationSuccess()
    return TrustLevelTrusted, nil
}
```

### Atomic TPM Quote Verification (TOCTOU Prevention)

**CRITICAL SECURITY**: A time-of-check-to-time-of-use (TOCTOU) vulnerability exists if quote verification and operation execution are not atomic. An attacker could:

1. Present a valid TPM quote with legitimate hardware
2. Pass verification
3. Swap TPM state (e.g., via hot-swap, VM migration, or software TPM substitution)
4. Execute privileged operations with unattested hardware

**Mitigation**: All operations requiring attestation MUST use atomic quote-verify-execute with operation binding.

### Binding Quote to Operation

Every TPM quote MUST be cryptographically bound to the specific operation it authorizes. The operation hash is computed as:

```
operation_hash = SHA256(operation_type || operation_params || timestamp)
```

The quote MUST include this operation_hash in its external data field, creating an unforgeable binding between the attestation and the operation.

```go
// OperationBinding ties a TPM quote to a specific operation
// The quote MUST include the OperationHash in its external data
type OperationBinding struct {
    OperationType   OperationType    // What operation is being authorized
    OperationParams []byte           // Serialized operation parameters
    Timestamp       time.Time        // Binding creation timestamp
    OperationHash   [32]byte         // SHA256(operation_type || params || timestamp)
    QuoteNonce      [32]byte         // Challenge nonce
    ExpiresAt       time.Time        // Binding expiration (100ms default)
    NodeID          [32]byte         // Node requesting authorization
}

type OperationType uint8

const (
    OpTypeEnrollment       OperationType = 1   // IDevID enrollment
    OpTypeDHTWrite         OperationType = 2   // DHT data writes
    OpTypeCASigning        OperationType = 3   // CA signing participation
    OpTypeConsensusVote    OperationType = 4   // PBFT consensus voting
    OpTypeServiceContract  OperationType = 5   // Contract signing
    OpTypePaymentAuth      OperationType = 6   // Payment authorization
)

// CreateOperationBinding generates a binding for an operation
// The binding hash MUST be included in the TPM quote external data
func CreateOperationBinding(op OperationType, params []byte) *OperationBinding {
    timestamp := time.Now()

    // Compute operation_hash = SHA256(operation_type || operation_params || timestamp)
    h := sha256.New()
    h.Write([]byte{byte(op)})
    h.Write(params)
    binary.Write(h, binary.BigEndian, timestamp.UnixNano())

    binding := &OperationBinding{
        OperationType:   op,
        OperationParams: params,
        Timestamp:       timestamp,
        ExpiresAt:       timestamp.Add(100 * time.Millisecond),
    }
    copy(binding.OperationHash[:], h.Sum(nil))

    // Generate fresh nonce for quote challenge
    nonce := make([]byte, 32)
    rand.Read(nonce)
    copy(binding.QuoteNonce[:], nonce)

    return binding
}

### Single Atomic Section

The atomic section provides TOCTOU protection through a single critical section. The verification lock is:
- **Acquired** before quote validation begins
- **Held** through the entire operation execution
- **Released** only after operation completion (success or failure)

No TPM state changes are allowed within the verification scope.

```go
// AtomicVerifyAndExecute prevents TOCTOU by verifying the quote includes
// the operation binding and executing within a single atomic context
//
// CRITICAL: Lock is acquired BEFORE quote validation and held through
// operation execution. Released ONLY after completion.
func (v *TPMVerifier) AtomicVerifyAndExecute(
    ctx context.Context,
    attestation *TPMAttestation,
    binding *OperationBinding,
    executor func(ctx context.Context, trustLevel TrustLevel) error,
) error {
    // === ATOMIC SECTION START ===
    // Acquire per-node lock BEFORE any validation
    v.nodeLocks.Lock(binding.NodeID)
    defer v.nodeLocks.Unlock(binding.NodeID)

    // Step 1: Check binding hasn't expired
    if time.Now().After(binding.ExpiresAt) {
        return &OperationBindingError{
            Reason: "binding expired",
            Binding: binding,
        }
    }

    // Step 2: Verify quote includes operation hash
    // Quote external data format: QuoteNonce (32 bytes) || OperationHash (32 bytes)
    expectedExternalData := make([]byte, 64)
    copy(expectedExternalData[:32], binding.QuoteNonce[:])
    copy(expectedExternalData[32:], binding.OperationHash[:])

    if !bytes.Equal(attestation.ExternalData, expectedExternalData) {
        return &OperationBindingError{
            Reason:  "quote external data does not match operation binding",
            Binding: binding,
        }
    }

    // Step 3: Verify TPM attestation (nonce, freshness, PCR checks)
    // STILL WITHIN ATOMIC SECTION - lock is held
    trustLevel, err := v.VerifyTPM(ctx, attestation)
    if err != nil {
        return err
    }

    // Step 4: Execute operation within same atomic context
    // CRITICAL: Lock is still held - no TPM state changes possible
    err = executor(ctx, trustLevel)

    // === ATOMIC SECTION END ===
    // Lock released by defer after return
    return err
}

// OperationBindingError indicates a binding verification failure
type OperationBindingError struct {
    Reason  string
    Binding *OperationBinding
}

func (e *OperationBindingError) Error() string {
    return fmt.Sprintf("operation binding failed: %s", e.Reason)
}

// NodeLockManager manages per-node locks for atomic operations
type NodeLockManager struct {
    locks sync.Map // [32]byte -> *sync.Mutex
}

func (m *NodeLockManager) Lock(nodeID [32]byte) {
    lock, _ := m.locks.LoadOrStore(nodeID, &sync.Mutex{})
    lock.(*sync.Mutex).Lock()
}

func (m *NodeLockManager) Unlock(nodeID [32]byte) {
    if lock, ok := m.locks.Load(nodeID); ok {
        lock.(*sync.Mutex).Unlock()
    }
}
```

#### TPM Operation Timeout and Lock Semantics (CANONICAL)

**CRITICAL SECURITY REQUIREMENT**: TPM TOCTOU operations MUST have strict timeout enforcement to prevent deadlocks, resource exhaustion, and privilege escalation through lock holding attacks.

**Operation Timeout Constants:**

```go
const (
    // TPMOperationTimeout is the maximum time any atomic operation may hold the lock
    // Rationale: 500ms accommodates network latency + TPM hardware response time
    // while preventing indefinite lock holding that could enable DoS
    TPMOperationTimeout = 500 * time.Millisecond

    // TPMQuoteGenerationTimeout is the time allowed for TPM to generate a quote
    // TPM 2.0 quote generation typically takes 50-200ms on real hardware
    TPMQuoteGenerationTimeout = 300 * time.Millisecond

    // TPMVerificationTimeout is the time allowed for quote verification
    // Includes signature verification and PCR policy checks
    TPMVerificationTimeout = 200 * time.Millisecond

    // OperationBindingGracePeriod extends binding validity during execution
    // Once execution begins, binding is extended by this amount
    OperationBindingGracePeriod = 50 * time.Millisecond
)
```

**Lock Fairness and Preemption Rules:**

| Rule | Description | Enforcement |
|------|-------------|-------------|
| **No Nested Operations** | A node CANNOT initiate a new atomic operation while one is in progress | Lock acquisition fails |
| **FIFO Ordering** | Waiting operations are serviced in arrival order | Mutex with fair scheduling |
| **Timeout Preemption** | Operations exceeding timeout are forcibly terminated | Context cancellation |
| **No Lock Upgrading** | Read locks cannot be upgraded to write locks | Separate lock types |

```go
// AtomicOperationContext manages timeout and preemption for TOCTOU operations
type AtomicOperationContext struct {
    ctx          context.Context
    cancel       context.CancelFunc
    nodeID       [32]byte
    operationType OperationType
    startTime    time.Time
    deadline     time.Time
    binding      *OperationBinding
}

// NewAtomicOperationContext creates a timeout-bound operation context
func NewAtomicOperationContext(
    parentCtx context.Context,
    nodeID [32]byte,
    binding *OperationBinding,
) (*AtomicOperationContext, error) {
    // Calculate deadline: minimum of binding expiration and operation timeout
    deadline := time.Now().Add(TPMOperationTimeout)
    if binding.ExpiresAt.Before(deadline) {
        deadline = binding.ExpiresAt
    }

    ctx, cancel := context.WithDeadline(parentCtx, deadline)

    return &AtomicOperationContext{
        ctx:           ctx,
        cancel:        cancel,
        nodeID:        nodeID,
        operationType: binding.OperationType,
        startTime:     time.Now(),
        deadline:      deadline,
        binding:       binding,
    }, nil
}

// ExtendBindingIfExecuting extends the operation binding during active execution
// This prevents premature expiration while the executor is running
func (aoc *AtomicOperationContext) ExtendBindingIfExecuting() {
    if time.Now().After(aoc.binding.ExpiresAt.Add(-OperationBindingGracePeriod)) {
        aoc.binding.ExpiresAt = time.Now().Add(OperationBindingGracePeriod)
    }
}

// TimeRemaining returns how much time is left before timeout
func (aoc *AtomicOperationContext) TimeRemaining() time.Duration {
    return time.Until(aoc.deadline)
}
```

**Nested Operation Prevention:**

```go
// NodeOperationTracker prevents concurrent operations per node
type NodeOperationTracker struct {
    activeOps sync.Map // [32]byte -> *ActiveOperation
}

type ActiveOperation struct {
    OperationType OperationType
    StartTime     time.Time
    ThreadID      uint64
}

// TryBeginOperation attempts to start a new operation, fails if one is active
func (t *NodeOperationTracker) TryBeginOperation(nodeID [32]byte, opType OperationType) error {
    existing, loaded := t.activeOps.LoadOrStore(nodeID, &ActiveOperation{
        OperationType: opType,
        StartTime:     time.Now(),
        ThreadID:      getGoroutineID(),
    })

    if loaded {
        activeOp := existing.(*ActiveOperation)
        return &NestedOperationError{
            NodeID:            nodeID,
            ExistingOperation: activeOp.OperationType,
            AttemptedOperation: opType,
            ExistingStartTime: activeOp.StartTime,
        }
    }

    return nil
}

// EndOperation marks an operation as complete
func (t *NodeOperationTracker) EndOperation(nodeID [32]byte) {
    t.activeOps.Delete(nodeID)
}

// NestedOperationError indicates an attempt to nest atomic operations
type NestedOperationError struct {
    NodeID             [32]byte
    ExistingOperation  OperationType
    AttemptedOperation OperationType
    ExistingStartTime  time.Time
}

func (e *NestedOperationError) Error() string {
    return fmt.Sprintf("nested atomic operation rejected: node %x already has %s operation in progress since %v, cannot start %s",
        e.NodeID[:8], e.ExistingOperation, e.ExistingStartTime, e.AttemptedOperation)
}
```

**Operation Binding Expiration During Execution:**

When an operation binding expires mid-execution, the following protocol applies:

| Phase | Binding Expired | Behavior |
|-------|-----------------|----------|
| **Before Lock Acquired** | Yes | Operation rejected with `ErrBindingExpired` |
| **During Quote Verification** | Yes | Verification aborted, lock released |
| **During Executor** | No (grace period) | Extended by `OperationBindingGracePeriod` |
| **After Executor Completes** | N/A | Success, lock released |

```go
// AtomicVerifyAndExecuteWithTimeout provides timeout-aware atomic operations
func (v *TPMVerifier) AtomicVerifyAndExecuteWithTimeout(
    parentCtx context.Context,
    attestation *TPMAttestation,
    binding *OperationBinding,
    executor func(ctx context.Context, trustLevel TrustLevel) error,
) error {
    // Step 0: Check for nested operations
    if err := v.opTracker.TryBeginOperation(binding.NodeID, binding.OperationType); err != nil {
        return err
    }
    defer v.opTracker.EndOperation(binding.NodeID)

    // Step 1: Create timeout-bound context
    opCtx, err := NewAtomicOperationContext(parentCtx, binding.NodeID, binding)
    if err != nil {
        return err
    }
    defer opCtx.cancel()

    // === ATOMIC SECTION START ===
    // Acquire per-node lock with timeout
    lockAcquired := make(chan struct{})
    go func() {
        v.nodeLocks.Lock(binding.NodeID)
        close(lockAcquired)
    }()

    select {
    case <-lockAcquired:
        // Lock acquired successfully
    case <-opCtx.Done():
        return &OperationTimeoutError{
            Phase:    "lock_acquisition",
            NodeID:   binding.NodeID,
            Timeout:  TPMOperationTimeout,
            Elapsed:  time.Since(opCtx.startTime),
        }
    }
    defer v.nodeLocks.Unlock(binding.NodeID)

    // Step 2: Check binding hasn't expired after acquiring lock
    if time.Now().After(binding.ExpiresAt) {
        return &OperationBindingError{
            Reason:  "binding expired during lock acquisition",
            Binding: binding,
        }
    }

    // Step 3: Verify quote with remaining timeout
    quoteCtx, quoteCancel := context.WithTimeout(opCtx.ctx, TPMQuoteGenerationTimeout)
    defer quoteCancel()

    // Verify quote includes operation hash
    expectedExternalData := make([]byte, 64)
    copy(expectedExternalData[:32], binding.QuoteNonce[:])
    copy(expectedExternalData[32:], binding.OperationHash[:])

    if !bytes.Equal(attestation.ExternalData, expectedExternalData) {
        return &OperationBindingError{
            Reason:  "quote external data does not match operation binding",
            Binding: binding,
        }
    }

    // Step 4: Verify TPM attestation with timeout
    verifyCtx, verifyCancel := context.WithTimeout(opCtx.ctx, TPMVerificationTimeout)
    defer verifyCancel()

    trustLevel, err := v.VerifyTPMWithContext(verifyCtx, attestation)
    if err != nil {
        if verifyCtx.Err() == context.DeadlineExceeded {
            return &OperationTimeoutError{
                Phase:   "quote_verification",
                NodeID:  binding.NodeID,
                Timeout: TPMVerificationTimeout,
                Elapsed: time.Since(opCtx.startTime),
            }
        }
        return err
    }

    // Step 5: Extend binding grace period for executor
    opCtx.ExtendBindingIfExecuting()

    // Step 6: Execute operation
    err = executor(opCtx.ctx, trustLevel)

    // === ATOMIC SECTION END ===
    return err
}

// OperationTimeoutError indicates operation exceeded timeout
type OperationTimeoutError struct {
    Phase   string        // "lock_acquisition", "quote_verification", "execution"
    NodeID  [32]byte
    Timeout time.Duration
    Elapsed time.Duration
}

func (e *OperationTimeoutError) Error() string {
    return fmt.Sprintf("TPM operation timeout in phase %s: node %x exceeded %v timeout after %v",
        e.Phase, e.NodeID[:8], e.Timeout, e.Elapsed)
}
```

**Lock Implementation with Fair Scheduling:**

```go
// FairNodeLockManager provides FIFO-ordered lock acquisition
type FairNodeLockManager struct {
    locks     sync.Map // [32]byte -> *fairMutex
    waitQueue sync.Map // [32]byte -> *lockQueue
}

type fairMutex struct {
    mu       sync.Mutex
    held     bool
    holder   uint64 // goroutine ID
    acquired time.Time
}

func (m *FairNodeLockManager) Lock(nodeID [32]byte) {
    // Get or create fair mutex for this node
    rawLock, _ := m.locks.LoadOrStore(nodeID, &fairMutex{})
    fMutex := rawLock.(*fairMutex)

    // Try immediate acquisition
    fMutex.mu.Lock()
    if !fMutex.held {
        fMutex.held = true
        fMutex.holder = getGoroutineID()
        fMutex.acquired = time.Now()
        fMutex.mu.Unlock()
        return
    }
    fMutex.mu.Unlock()

    // Create wait channel and add to queue (FIFO)
    waiter := make(chan struct{})
    rawQueue, _ := m.waitQueue.LoadOrStore(nodeID, &lockQueue{})
    queue := rawQueue.(*lockQueue)
    
    queue.mu.Lock()
    queue.waiters = append(queue.waiters, waiter)
    queue.mu.Unlock()

    // Wait for signal
    <-waiter
}

func (m *FairNodeLockManager) Unlock(nodeID [32]byte) {
    rawLock, ok := m.locks.Load(nodeID)
    if !ok {
        return
    }
    fMutex := rawLock.(*fairMutex)

    fMutex.mu.Lock()
    fMutex.held = false
    fMutex.holder = 0
    fMutex.mu.Unlock()

    // Signal next waiter in queue (FIFO)
    rawQueue, ok := m.waitQueue.Load(nodeID)
    if !ok {
        return
    }
    queue := rawQueue.(*lockQueue)

    queue.mu.Lock()
    if len(queue.waiters) > 0 {
        nextWaiter := queue.waiters[0]
        queue.waiters = queue.waiters[1:]
        
        // Transfer lock to next waiter
        fMutex.mu.Lock()
        fMutex.held = true
        fMutex.mu.Unlock()
        
        close(nextWaiter) // Signal waiter
    }
    queue.mu.Unlock()
}

type lockQueue struct {
    mu      sync.Mutex
    waiters []chan struct{}
}
```


#### Usage Example

All operations requiring attestation MUST use the atomic pattern:

```go
// CORRECT: Atomic quote-verify-execute
func (node *Node) WriteToCA(ctx context.Context, data []byte) error {
    // Create binding for this specific operation
    binding := CreateOperationBinding(OpTypeCASigning, data)

    // Get fresh TPM quote with binding hash in external data
    attestation := node.tpm.GetQuote(binding.QuoteNonce, binding.OperationHash)

    // Atomic verify and execute
    return node.verifier.AtomicVerifyAndExecute(ctx, attestation, binding,
        func(ctx context.Context, trustLevel TrustLevel) error {
            if trustLevel != TrustLevelTrusted {
                return ErrInsufficientTrust
            }
            return node.ca.Write(ctx, data)
        },
    )
}

// WRONG: Separate verify and execute (TOCTOU vulnerable)
func (node *Node) WriteToCAUnsafe(ctx context.Context, data []byte) error {
    // DON'T DO THIS - gap between verify and execute
    trustLevel, err := node.verifier.VerifyTPM(ctx, attestation)
    if err != nil {
        return err
    }
    // Attacker can swap TPM state here!
    return node.ca.Write(ctx, data)
}
```

### Enrollment Rejection Response

When verification fails, the node receives an explicit rejection with details:

```go
type EnrollmentRejection struct {
    NodeID          [32]byte
    RejectionCode   string
    Reason          string
    RetryAllowed    bool
    RetryAfter      time.Duration
    AuditReference  string
    Timestamp       time.Time
}

// ACME error response for verification failure
// Uses standard ACME error format with custom subproblems
func (ca *PrivacyCA) RejectEnrollment(ctx context.Context, err *TPMVerificationError) *acme.Error {
    rejection := &EnrollmentRejection{
        NodeID:         err.NodeID,
        RejectionCode:  string(err.Category),
        Reason:         err.Details,
        RetryAllowed:   isRetryAllowed(err.Category),
        RetryAfter:     calculateRetryDelay(err),
        AuditReference: err.AuditTrail[0].ID,
        Timestamp:      time.Now(),
    }

    // Publish rejection to network for audit trail
    ca.publishRejection(ctx, rejection)

    return &acme.Error{
        Type:   "urn:ietf:params:acme:error:unauthorized",
        Detail: fmt.Sprintf("TPM verification failed: %s", err.Category),
        Status: http.StatusForbidden,
        Subproblems: []acme.Subproblem{{
            Type:       fmt.Sprintf("urn:platform:error:tpm:%s", err.Category),
            Detail:     err.Details,
            Identifier: acme.Identifier{Type: "dns", Value: hex.EncodeToString(err.NodeID[:])},
        }},
    }
}

func isRetryAllowed(category VerificationFailureCategory) bool {
    switch category {
    case FailureCategoryQuoteFailed, FailureCategoryFreshnessExpired, FailureCategoryTimeout:
        return true
    default:
        return false
    }
}
```

### Audit and Monitoring

All verification failures are logged with full audit trail:

```go
type VerificationAuditEntry struct {
    EntryID         string
    NodeID          [32]byte
    Timestamp       time.Time
    Category        VerificationFailureCategory
    Details         string
    EKFingerprint   string
    Manufacturer    string
    Model           string
    FirmwareVersion string
    SourceIP        string
    RetryCount      int
}

// Metrics for monitoring verification failures
type VerificationMetrics struct {
    TotalAttempts        atomic.Uint64
    SuccessCount         atomic.Uint64
    FailuresByCategory   sync.Map // VerificationFailureCategory -> atomic.Uint64
    FailuresByManufacturer sync.Map // string -> atomic.Uint64
    RecentFailures       *ring.Buffer // Last 1000 failures for analysis
}
```

### Security Monitoring Alerts

Verification failures trigger security monitoring alerts:

```go
const (
    AlertThresholdFailuresPerMinute = 10  // Alert if >10 failures/minute
    AlertThresholdSameNodeRetries   = 3   // Alert if same node retries >3 times
    AlertThresholdManufacturerSpike = 50  // Alert if manufacturer failures spike
)

func (v *TPMVerifier) checkAlertConditions(err *TPMVerificationError) {
    // Check for attack patterns
    if v.metrics.FailuresLastMinute() > AlertThresholdFailuresPerMinute {
        v.alertManager.Fire(AlertVerificationFlood{
            Count:     v.metrics.FailuresLastMinute(),
            Threshold: AlertThresholdFailuresPerMinute,
            TopNodes:  v.metrics.TopFailingNodes(5),
        })
    }

    // Check for retry abuse
    if retries := v.metrics.NodeRetryCount(err.NodeID); retries > AlertThresholdSameNodeRetries {
        v.alertManager.Fire(AlertRetryAbuse{
            NodeID:    err.NodeID,
            Count:     retries,
            Threshold: AlertThresholdSameNodeRetries,
        })
    }
}
```

### TPM Failure Recovery Procedure (CANONICAL - A1 Fix)

**CRITICAL**: TPM failures can occur due to hardware malfunction, firmware issues, or
physical damage. This section defines the recovery procedure to restore node functionality
while maintaining security guarantees.

#### TPM Failure Categories

| Category | Cause | Recovery Path | Time to Recover |
|----------|-------|---------------|-----------------|
| **Transient** | Power glitch, driver error | Automatic retry (3x) | < 1 minute |
| **Firmware** | TPM firmware crash | TPM reset + re-attestation | 5-15 minutes |
| **Hardware** | Physical TPM failure | Hardware replacement | Hours-days |
| **Key Loss** | TPM cleared/wiped | New identity enrollment | Hours-days |

#### Recovery Protocol

```go
// TPMFailureRecoveryManager handles node recovery after TPM failures
type TPMFailureRecoveryManager struct {
    nodeID           [32]byte
    recoveryAttempts int
    lastFailure      time.Time
    failureHistory   []TPMFailureEvent
}

// RecoveryConfig defines recovery parameters
type RecoveryConfig struct {
    MaxTransientRetries    int           // 3 retries for transient failures
    TransientRetryDelay    time.Duration // 5 seconds between retries
    MaxFirmwareRecoveries  int           // 5 per day for firmware recovery
    FirmwareRecoveryDelay  time.Duration // 1 minute cooldown
    HardwareReplacementTTL time.Duration // 7 days to complete replacement
    KeyLossGracePeriod     time.Duration // 24 hours before revocation
}

var DefaultRecoveryConfig = RecoveryConfig{
    MaxTransientRetries:    3,
    TransientRetryDelay:    5 * time.Second,
    MaxFirmwareRecoveries:  5,
    FirmwareRecoveryDelay:  1 * time.Minute,
    HardwareReplacementTTL: 7 * 24 * time.Hour,
    KeyLossGracePeriod:     24 * time.Hour,
}

// Error types for recovery phases
var (
    ErrRecoveryExhausted     = errors.New("recovery attempts exhausted")
    ErrRecoveryInProgress    = errors.New("recovery already in progress")
    ErrHardwareReplacement   = errors.New("hardware replacement required")
    ErrIdentityRevoked       = errors.New("node identity has been revoked")
)

// RecoverTransientFailure handles temporary TPM errors
func (rm *TPMFailureRecoveryManager) RecoverTransientFailure(
    ctx context.Context,
    failure *TPMFailureEvent,
) error {
    for attempt := 1; attempt <= DefaultRecoveryConfig.MaxTransientRetries; attempt++ {
        // Wait before retry
        time.Sleep(DefaultRecoveryConfig.TransientRetryDelay)

        // Attempt TPM re-initialization
        if err := rm.reinitializeTPM(ctx); err != nil {
            rm.logRecoveryAttempt(attempt, err)
            continue
        }

        // Attempt fresh attestation
        if err := rm.performFreshAttestation(ctx); err != nil {
            rm.logRecoveryAttempt(attempt, err)
            continue
        }

        // Recovery successful
        rm.recordRecovery(RecoveryTypeTransient, attempt)
        return nil
    }

    // Transient recovery exhausted - escalate to firmware recovery
    return rm.RecoverFirmwareFailure(ctx, failure)
}

// RecoverFirmwareFailure handles TPM firmware crashes
func (rm *TPMFailureRecoveryManager) RecoverFirmwareFailure(
    ctx context.Context,
    failure *TPMFailureEvent,
) error {
    // Check daily limit
    if rm.dailyFirmwareRecoveries() >= DefaultRecoveryConfig.MaxFirmwareRecoveries {
        return ErrRecoveryExhausted
    }

    // Notify operator of firmware recovery initiation
    rm.notifyOperator(NotificationFirmwareRecovery{
        NodeID:   rm.nodeID,
        Failure:  failure,
        Action:   "TPM firmware recovery initiated",
    })

    // Step 1: Request TPM reset from firmware interface
    if err := rm.tpmResetRequest(ctx); err != nil {
        return fmt.Errorf("TPM reset failed: %w", err)
    }

    // Step 2: Wait for TPM to reinitialize
    time.Sleep(DefaultRecoveryConfig.FirmwareRecoveryDelay)

    // Step 3: Perform fresh attestation with new session
    if err := rm.performFreshAttestation(ctx); err != nil {
        // Firmware recovery failed - may need hardware replacement
        return fmt.Errorf("post-reset attestation failed: %w", err)
    }

    // Step 4: Re-establish network presence
    if err := rm.reEstablishNetworkPresence(ctx); err != nil {
        return fmt.Errorf("network re-establishment failed: %w", err)
    }

    rm.recordRecovery(RecoveryTypeFirmware, 1)
    return nil
}

// InitiateHardwareReplacement begins hardware replacement workflow
func (rm *TPMFailureRecoveryManager) InitiateHardwareReplacement(
    ctx context.Context,
) (*HardwareReplacementToken, error) {
    // Create time-limited replacement token
    token := &HardwareReplacementToken{
        NodeID:         rm.nodeID,
        OldEKHash:      rm.getCurrentEKHash(),
        IssuedAt:       time.Now(),
        ExpiresAt:      time.Now().Add(DefaultRecoveryConfig.HardwareReplacementTTL),
        ReplacementID:  generateReplacementID(),
    }

    // Notify network of pending replacement
    if err := rm.publishReplacementNotice(ctx, token); err != nil {
        return nil, err
    }

    // Node enters degraded mode during replacement
    if err := rm.enterDegradedMode(ctx); err != nil {
        return nil, err
    }

    return token, nil
}

// CompleteHardwareReplacement finalizes replacement with new TPM
func (rm *TPMFailureRecoveryManager) CompleteHardwareReplacement(
    ctx context.Context,
    token *HardwareReplacementToken,
    newAttestation *TPMAttestation,
) error {
    // Validate token hasn't expired
    if time.Now().After(token.ExpiresAt) {
        return ErrRecoveryExhausted
    }

    // Verify new TPM is legitimate (different EK)
    if bytes.Equal(newAttestation.EKHash, token.OldEKHash) {
        return errors.New("new TPM EK matches old EK - not a replacement")
    }

    // Request new IDevID enrollment
    if err := rm.enrollNewIdentity(ctx, newAttestation); err != nil {
        return err
    }

    // Transfer node state to new identity (reputation, roles, etc.)
    if err := rm.transferNodeState(ctx, token.NodeID, newAttestation.NodeID); err != nil {
        return err
    }

    // Revoke old identity
    if err := rm.revokeOldIdentity(ctx, token.OldEKHash); err != nil {
        return err
    }

    rm.recordRecovery(RecoveryTypeHardware, 1)
    return nil
}

// HandleKeyLoss manages recovery when TPM keys are lost (TPM cleared)
func (rm *TPMFailureRecoveryManager) HandleKeyLoss(
    ctx context.Context,
) error {
    // Begin grace period - node can still operate with degraded trust
    graceExpiry := time.Now().Add(DefaultRecoveryConfig.KeyLossGracePeriod)

    // Notify network of key loss
    rm.publishKeyLossNotice(ctx, rm.nodeID, graceExpiry)

    // Node must re-enroll before grace period expires
    // During grace period:
    // - No new reputation can be earned
    // - Cannot participate in CA operations
    // - Cannot hold escrow or arbiter roles
    // - Can continue basic DHT operations

    return nil
}
```

#### Recovery Flow Diagram

```
                    TPM FAILURE DETECTED
                           |
                           v
            +--------------------------------+
            |   Identify Failure Category    |
            +--------------------------------+
                           |
       +-------------------+-------------------+
       |                   |                   |
       v                   v                   v
   TRANSIENT          FIRMWARE             HARDWARE
       |                   |                   |
       v                   v                   v
   3x Retry           TPM Reset         Issue Replacement
   with Delay        + Re-attest          Token
       |                   |                   |
   Success?           Success?           New Hardware
       |                   |              Installed?
       No                  No                  |
       |                   |                   v
       +--------->---------+            Re-enroll
                  |                      + Transfer State
                  v                           |
            Escalate to                  Revoke Old
            Next Level                    Identity
                  |                           |
                  v                           v
         If all fail:                 RECOVERY
       REVOKE IDENTITY               COMPLETE
```

#### Operator Notifications

| Event | Notification Method | Action Required |
|-------|---------------------|-----------------|
| Transient failure | Log only | None |
| Firmware recovery started | Alert + Dashboard | Monitor |
| Firmware recovery failed | Urgent alert | Manual intervention |
| Hardware replacement started | Email + SMS | Schedule replacement |
| Grace period started | Email + Dashboard | Re-enroll within 24h |
| Grace period expiring | Urgent alerts | Immediate re-enrollment |
| Identity revoked | Critical alert | New node enrollment |

#### Security Considerations

1. **Replacement Token Security**: Tokens are cryptographically bound to the old EK and
   expire after 7 days to prevent long-term identity theft.

2. **State Transfer Limits**: Not all state can be transferred during replacement:
   - Reputation: 90% transferred (10% penalty for disruption)
   - Active contracts: Must be completed or terminated before transfer
   - CA pool membership: Must re-qualify after replacement
   - Escrow holdings: Requires manual settlement

3. **Attack Prevention**:
   - Rate limiting on recovery attempts prevents brute-force
   - Network-wide notification prevents parallel recovery attacks
   - Grace periods allow legitimate operators time without enabling attackers

4. **Audit Trail**: All recovery events are logged to the DHT for forensic analysis.

---

## 15. Trust Level Enforcement (Hard Caps for Untrusted Nodes)

**CRITICAL SECURITY REQUIREMENT**: Untrusted nodes (swtpm, unverified fTPM, unknown manufacturers) MUST have hard-coded capability caps that cannot be bypassed through reputation accumulation, time-based progression, or any other mechanism.

### Untrusted Node Hard Caps (CANONICAL)

These caps are enforced at the protocol level and cannot be overridden:

| Capability | Untrusted Cap | Trusted Minimum | Enforcement |
|------------|---------------|-----------------|-------------|
| **Reputation** | 0.0 (hard cap) | 0.0 (can grow) | Protocol-level rejection |
| **Maximum Role** | Observer only | Leaf (can progress) | Role promotion blocked |
| **CA Pool Access** | NEVER | Requires 0.80+ reputation | Membership rejected |
| **FROST Shares** | NEVER | Requires CA pool membership | DKG participation blocked |
| **Hub Promotion** | NEVER | Requires 0.80 reputation | Promotion blocked |
| **Gateway Promotion** | NEVER | Requires 0.85 reputation | Promotion blocked |
| **Coordinator Promotion** | NEVER | Requires 0.95 reputation | Promotion blocked |
| **Voting Rights** | NEVER | Role-dependent | Vote rejected |
| **DHT Write** | Limited (observation only) | Full access | Write operations rejected |
| **Certificate Signing** | NEVER | CA pool members only | Signing request rejected |

### Protocol-Level Enforcement

```go
// UntrustedCapEnforcer enforces hard caps at the protocol level
// These checks run BEFORE any operation processing
type UntrustedCapEnforcer struct {
    trustStore TrustStore
}

// EnforceReputationCap ensures untrusted nodes cannot gain reputation
// This is called by the reputation system before ANY reputation update
func (e *UntrustedCapEnforcer) EnforceReputationCap(nodeID [32]byte, delta float64) error {
    trustLevel := e.trustStore.GetTrustLevel(nodeID)
    if trustLevel == TrustLevelUntrusted {
        if delta > 0 {
            return ErrUntrustedReputationCapped
        }
    }
    return nil
}

// EnforceRoleCap ensures untrusted nodes cannot assume privileged roles
func (e *UntrustedCapEnforcer) EnforceRoleCap(nodeID [32]byte, targetRole Role) error {
    trustLevel := e.trustStore.GetTrustLevel(nodeID)
    if trustLevel == TrustLevelUntrusted {
        if targetRole != RoleObserver {
            return ErrUntrustedRoleCapped
        }
    }
    return nil
}

// EnforceCAPoolAccess ensures untrusted nodes cannot join CA pool
func (e *UntrustedCapEnforcer) EnforceCAPoolAccess(nodeID [32]byte) error {
    trustLevel := e.trustStore.GetTrustLevel(nodeID)
    if trustLevel == TrustLevelUntrusted {
        return ErrUntrustedCAPoolBlocked
    }
    return nil
}

// EnforceFROSTParticipation ensures untrusted nodes cannot hold key shares
func (e *UntrustedCapEnforcer) EnforceFROSTParticipation(nodeID [32]byte) error {
    trustLevel := e.trustStore.GetTrustLevel(nodeID)
    if trustLevel == TrustLevelUntrusted {
        return ErrUntrustedFROSTBlocked
    }
    return nil
}

// EnforceVotingRights ensures untrusted nodes cannot vote
func (e *UntrustedCapEnforcer) EnforceVotingRights(nodeID [32]byte) error {
    trustLevel := e.trustStore.GetTrustLevel(nodeID)
    if trustLevel == TrustLevelUntrusted {
        return ErrUntrustedVotingBlocked
    }
    return nil
}
```

### Typed Errors for Cap Violations

```go
// Cap violation errors - these are security events, not normal errors
var (
    ErrUntrustedReputationCapped = &CapViolationError{
        Code:    "UNTRUSTED_REPUTATION_CAPPED",
        Message: "untrusted nodes cannot gain reputation",
        Cap:     "reputation=0.0",
    }

    ErrUntrustedRoleCapped = &CapViolationError{
        Code:    "UNTRUSTED_ROLE_CAPPED",
        Message: "untrusted nodes cannot assume privileged roles",
        Cap:     "max_role=observer",
    }

    ErrUntrustedCAPoolBlocked = &CapViolationError{
        Code:    "UNTRUSTED_CA_POOL_BLOCKED",
        Message: "untrusted nodes cannot join CA pool",
        Cap:     "ca_pool_access=never",
    }

    ErrUntrustedFROSTBlocked = &CapViolationError{
        Code:    "UNTRUSTED_FROST_BLOCKED",
        Message: "untrusted nodes cannot participate in FROST DKG",
        Cap:     "frost_shares=never",
    }

    ErrUntrustedVotingBlocked = &CapViolationError{
        Code:    "UNTRUSTED_VOTING_BLOCKED",
        Message: "untrusted nodes cannot vote",
        Cap:     "voting_rights=never",
    }
)

type CapViolationError struct {
    Code    string
    Message string
    Cap     string
}

func (e *CapViolationError) Error() string {
    return fmt.Sprintf("%s: %s (cap: %s)", e.Code, e.Message, e.Cap)
}
```

### Integration Points

The enforcer is integrated at all privilege escalation points:

```go
// ReputationManager integration
func (rm *ReputationManager) AddReputation(nodeID [32]byte, delta float64, reason string) error {
    // FIRST: Check trust level cap
    if err := rm.capEnforcer.EnforceReputationCap(nodeID, delta); err != nil {
        rm.auditLog.RecordCapViolation(nodeID, "reputation", delta, err)
        return err
    }

    // Proceed with reputation update
    return rm.updateReputation(nodeID, delta, reason)
}

// RoleManager integration
func (rm *RoleManager) PromoteNode(nodeID [32]byte, targetRole Role) error {
    // FIRST: Check trust level cap
    if err := rm.capEnforcer.EnforceRoleCap(nodeID, targetRole); err != nil {
        rm.auditLog.RecordCapViolation(nodeID, "role", targetRole, err)
        return err
    }

    // Proceed with role promotion
    return rm.executePromotion(nodeID, targetRole)
}

// CAPool integration
func (pool *CAPool) AddMember(nodeID [32]byte) error {
    // FIRST: Check trust level cap
    if err := pool.capEnforcer.EnforceCAPoolAccess(nodeID); err != nil {
        pool.auditLog.RecordCapViolation(nodeID, "ca_pool", "join", err)
        return err
    }

    // Proceed with membership addition
    return pool.addMemberInternal(nodeID)
}

// FROST DKG integration
func (dkg *DKGCoordinator) AddParticipant(nodeID [32]byte) error {
    // FIRST: Check trust level cap
    if err := dkg.capEnforcer.EnforceFROSTParticipation(nodeID); err != nil {
        dkg.auditLog.RecordCapViolation(nodeID, "frost", "dkg_participate", err)
        return err
    }

    // Proceed with DKG participation
    return dkg.addParticipantInternal(nodeID)
}
```

### Observer Role Definition

Untrusted nodes are limited to the Observer role:

```go
type Role uint8

const (
    RoleObserver    Role = iota // Untrusted nodes only - read-only network access
    RoleLeaf                    // Basic trusted node
    RoleHub                     // Regional hub
    RoleGateway                 // External gateway
    RoleCoordinator             // Network coordinator
)

// Observer capabilities (untrusted nodes)
type ObserverCapabilities struct {
    // Allowed operations
    CanReadDHT         bool // true - can query DHT
    CanRouteDHTQueries bool // true - can forward queries
    CanObserveState    bool // true - can read network state

    // Blocked operations
    CanWriteDHT        bool // false - cannot store data
    CanEarnReputation  bool // false - reputation capped at 0.0
    CanVote            bool // false - no voting rights
    CanJoinCAPool      bool // false - CA pool blocked
    CanHoldFROSTShares bool // false - FROST participation blocked
    CanPromote         bool // false - role promotion blocked
}

var DefaultObserverCapabilities = ObserverCapabilities{
    CanReadDHT:         true,
    CanRouteDHTQueries: true,
    CanObserveState:    true,
    CanWriteDHT:        false,
    CanEarnReputation:  false,
    CanVote:            false,
    CanJoinCAPool:      false,
    CanHoldFROSTShares: false,
    CanPromote:         false,
}
```

### Audit Trail for Cap Enforcement

All cap violations are logged for security monitoring:

```go
type CapViolationAuditEntry struct {
    EntryID      string
    NodeID       [32]byte
    Timestamp    time.Time
    TrustLevel   TrustLevel
    Capability   string    // "reputation", "role", "ca_pool", "frost", "voting"
    Attempted    string    // What was attempted
    Error        string    // Cap violation error
    SourceIP     string
    RequestID    string
}

// Security alerts for repeated cap violation attempts
const (
    CapViolationAlertThreshold = 5 // Alert after 5 violations from same node
)

func (e *UntrustedCapEnforcer) recordViolation(nodeID [32]byte, cap string, attempted interface{}) {
    entry := &CapViolationAuditEntry{
        EntryID:    generateAuditID(),
        NodeID:     nodeID,
        Timestamp:  time.Now(),
        TrustLevel: TrustLevelUntrusted,
        Capability: cap,
        Attempted:  fmt.Sprintf("%v", attempted),
    }

    e.auditLog.Record(entry)

    // Check for abuse patterns
    if e.violationCount(nodeID) > CapViolationAlertThreshold {
        e.alertManager.Fire(AlertCapViolationAbuse{
            NodeID:     nodeID,
            Count:      e.violationCount(nodeID),
            Capability: cap,
        })
    }
}
```

---

## 16. Trust Downgrade Protocol

**CRITICAL SECURITY REQUIREMENT**: When a node's EK certificate becomes invalid (manufacturer CA revoked, CVE blocked, certificate expired), their IDevID MUST be invalidated and all roles revoked immediately. Trust is not grandfathered.

### Continuous TPM Health Check

The platform performs continuous TPM health verification to ensure ongoing trust validity. Re-attestation occurs every 4 hours to detect:
- TPM firmware changes
- EK certificate revocation
- Manufacturer CA status changes
- CVE database updates affecting the TPM model

```go
const (
    // Re-attestation interval - 4 hours
    TPMReAttestationInterval = 4 * time.Hour

    // Grace period for re-attestation failures
    ReAttestationGracePeriod = 1 * time.Hour
)

// TPMHealthMonitor performs continuous TPM health verification
type TPMHealthMonitor struct {
    verifier         *TPMVerifier
    downgradeManager *TrustDowngradeManager
    trustStore       TrustStore
    auditLog         AuditLogger
    ticker           *time.Ticker
}

// StartHealthMonitoring begins continuous TPM health checks
func (m *TPMHealthMonitor) StartHealthMonitoring(ctx context.Context) {
    m.ticker = time.NewTicker(TPMReAttestationInterval)
    defer m.ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-m.ticker.C:
            m.performHealthCheck(ctx)
        }
    }
}

// performHealthCheck verifies all trusted nodes
func (m *TPMHealthMonitor) performHealthCheck(ctx context.Context) {
    trustedNodes := m.trustStore.GetAllTrustedNodes()

    for _, nodeID := range trustedNodes {
        select {
        case <-ctx.Done():
            return
        default:
        }

        // Request fresh attestation
        result := m.verifier.RequestReAttestation(ctx, nodeID)
        if !result.Valid {
            // Schedule downgrade with grace period
            m.downgradeManager.ProcessDowngrade(ctx, &DowngradeTrigger{
                Type:        TriggerReAttestationFailed,
                NodeID:      nodeID,
                Reason:      result.Error.Error(),
                Evidence:    nil,
                Timestamp:   time.Now(),
                GracePeriod: ReAttestationGracePeriod,
            })
        }

        m.auditLog.RecordHealthCheck(nodeID, result.Valid)
    }
}
```

### Trust Downgrade Handling

When a trust level transition from TRUSTED to UNTRUSTED is detected, the following sequence executes immediately:

1. **Detection**: TPM health check, CVE alert, or manufacturer revocation
2. **Immediate Quarantine**: Node is quarantined pending full downgrade
3. **Role Strip**: All privileged roles (Hub, Coordinator, CA) are stripped
4. **Peer Notification**: All connected peers are notified of trust change

```
Trust Downgrade State Machine:

    TRUSTED ──────────────────────────────────────────────────→ UNTRUSTED
       │                                                            │
       │ Detection                                                  │
       │ (health check fail, CVE, revocation)                       │
       ▼                                                            │
  ┌─────────────┐                                                   │
  │ QUARANTINE  │ ← Immediate isolation (< 1 second)                │
  └─────────────┘                                                   │
       │                                                            │
       │ Role Strip                                                 │
       │ (Hub, Coordinator, CA all stripped immediately)            │
       ▼                                                            │
  ┌─────────────┐                                                   │
  │ ROLE_STRIP  │                                                   │
  └─────────────┘                                                   │
       │                                                            │
       │ Peer Notification                                          │
       │ (broadcast to all connected peers)                         │
       ▼                                                            │
  ┌─────────────┐                                                   │
  │ NOTIFIED    │ ──────────────────────────────────────────────────┘
  └─────────────┘
```

```go
// TrustTransitionHandler manages trust level transitions
type TrustTransitionHandler struct {
    roleManager    RoleManager
    peerNotifier   PeerNotifier
    auditLog       AuditLogger
}

// HandleTrustDowngrade executes immediate trust downgrade actions
// State: TRUSTED → UNTRUSTED triggers immediate role strip
func (h *TrustTransitionHandler) HandleTrustDowngrade(ctx context.Context, nodeID [32]byte, reason string) error {
    // Step 1: Immediate quarantine
    if err := h.roleManager.QuarantineNode(nodeID); err != nil {
        h.auditLog.RecordQuarantineFailure(nodeID, err)
        // Continue despite error - security takes priority
    }

    // Step 2: Strip ALL privileged roles immediately
    // Hub, Coordinator, CA are all stripped in single atomic operation
    strippedRoles, err := h.roleManager.StripAllPrivilegedRoles(nodeID)
    if err != nil {
        h.auditLog.RecordRoleStripFailure(nodeID, err)
    }

    // Step 3: Notify all connected peers
    notification := &TrustDowngradeNotification{
        NodeID:       nodeID,
        Reason:       reason,
        StrippedRoles: strippedRoles,
        Timestamp:    time.Now(),
    }
    h.peerNotifier.BroadcastTrustChange(ctx, notification)

    // Step 4: Record audit trail with evidence
    h.auditLog.RecordTrustTransition(TrustTransitionAuditEntry{
        NodeID:        nodeID,
        FromTrust:     TrustLevelTrusted,
        ToTrust:       TrustLevelUntrusted,
        Reason:        reason,
        StrippedRoles: strippedRoles,
        Timestamp:     time.Now(),
    })

    return nil
}

// TrustTransitionAuditEntry records trust level transitions with full evidence
type TrustTransitionAuditEntry struct {
    EntryID       string
    NodeID        [32]byte
    FromTrust     TrustLevel
    ToTrust       TrustLevel
    Reason        string
    Evidence      []byte
    StrippedRoles []Role
    Timestamp     time.Time
    Duration      time.Duration  // Time from detection to completion
}
```

### Downgrade Triggers

| Trigger | Description | Response Time | Severity |
|---------|-------------|---------------|----------|
| **Manufacturer CA Revoked** | Manufacturer removed from trust store | Immediate | Critical |
| **EK Certificate Revoked** | Individual EK cert added to revocation list | Immediate | Critical |
| **CVE Blocking** | TPM model affected by critical CVE | Immediate | High |
| **EK Certificate Expired** | EK cert validity period ended | Immediate | Medium |
| **Hardware Change Detected** | EK fingerprint changed without re-enrollment | Immediate | Critical |
| **Periodic Re-Attestation Failed** | Scheduled re-verification failed | 24 hours grace | Medium |

### Downgrade State Machine

```
                     +------------------+
                     |     TRUSTED      |
                     +------------------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
    [Manufacturer CA   [CVE Blocking   [EK Revoked/
       Revoked]          Detected]      Expired/Changed]
              |               |               |
              +-------+-------+-------+-------+
                      |
                      v
             +------------------+
             |   DOWNGRADING    |
             | (grace period)   |
             +------------------+
                      |
                      v
             +------------------+
             |    UNTRUSTED     |
             +------------------+
                      |
                      v
             +------------------+
             |   ROLES REVOKED  |
             +------------------+
                      |
                      v
             +------------------+
             | IDevID INVALID   |
             +------------------+
```

### Downgrade Protocol Implementation

```go
// TrustDowngradeManager handles trust level downgrades
type TrustDowngradeManager struct {
    trustStore     TrustStore
    roleManager    RoleManager
    caPool         CAPool
    frostManager   FROSTManager
    certRevocation CertRevocationList
    auditLog       AuditLogger
    alertManager   AlertManager
}

// DowngradeTrigger represents an event that triggers trust downgrade
type DowngradeTrigger struct {
    Type        DowngradeTriggerType
    NodeID      [32]byte
    Reason      string
    Evidence    []byte
    Timestamp   time.Time
    GracePeriod time.Duration // 0 = immediate
}

type DowngradeTriggerType string

const (
    TriggerManufacturerRevoked    DowngradeTriggerType = "manufacturer_ca_revoked"
    TriggerEKCertRevoked          DowngradeTriggerType = "ek_certificate_revoked"
    TriggerCVEBlocking            DowngradeTriggerType = "cve_blocking"
    TriggerEKCertExpired          DowngradeTriggerType = "ek_certificate_expired"
    TriggerHardwareChange         DowngradeTriggerType = "hardware_change_detected"
    TriggerReAttestationFailed    DowngradeTriggerType = "re_attestation_failed"
)

// ProcessDowngrade executes the complete downgrade protocol
func (dm *TrustDowngradeManager) ProcessDowngrade(ctx context.Context, trigger *DowngradeTrigger) error {
    dm.auditLog.BeginDowngrade(trigger)

    // Step 1: Validate trigger
    if err := dm.validateTrigger(trigger); err != nil {
        return fmt.Errorf("invalid downgrade trigger: %w", err)
    }

    // Step 2: Check grace period
    if trigger.GracePeriod > 0 {
        dm.scheduleDowngrade(trigger)
        dm.notifyPendingDowngrade(trigger)
        return nil
    }

    // Step 3: Execute immediate downgrade
    return dm.executeDowngrade(ctx, trigger)
}

func (dm *TrustDowngradeManager) executeDowngrade(ctx context.Context, trigger *DowngradeTrigger) error {
    nodeID := trigger.NodeID

    // Phase 1: Revoke all roles (most time-sensitive)
    if err := dm.revokeAllRoles(ctx, nodeID, trigger.Reason); err != nil {
        dm.alertManager.Fire(AlertDowngradeRoleRevocationFailed{
            NodeID: nodeID,
            Error:  err,
        })
        // Continue with downgrade - role revocation failure is logged but not blocking
    }

    // Phase 2: Remove from CA pool
    if err := dm.removeFromCAPool(ctx, nodeID); err != nil {
        dm.auditLog.RecordPhaseError("ca_pool_removal", err)
    }

    // Phase 3: Revoke FROST shares
    if err := dm.revokeFROSTShares(ctx, nodeID); err != nil {
        dm.auditLog.RecordPhaseError("frost_revocation", err)
    }

    // Phase 4: Invalidate IDevID certificate
    if err := dm.invalidateIDevID(ctx, nodeID); err != nil {
        dm.auditLog.RecordPhaseError("idedevid_invalidation", err)
    }

    // Phase 5: Update trust level to Untrusted
    if err := dm.trustStore.SetTrustLevel(nodeID, TrustLevelUntrusted); err != nil {
        return fmt.Errorf("failed to update trust level: %w", err)
    }

    // Phase 6: Reset reputation to 0.0
    if err := dm.resetReputation(ctx, nodeID); err != nil {
        dm.auditLog.RecordPhaseError("reputation_reset", err)
    }

    // Phase 7: Broadcast downgrade to network
    dm.broadcastDowngrade(ctx, trigger)

    // Phase 8: Complete audit trail
    dm.auditLog.CompleteDowngrade(trigger, "success")

    return nil
}
```

### Role Revocation Protocol

```go
// revokeAllRoles immediately revokes all node roles
func (dm *TrustDowngradeManager) revokeAllRoles(ctx context.Context, nodeID [32]byte, reason string) error {
    currentRole := dm.roleManager.GetRole(nodeID)

    // Create revocation record
    revocation := &RoleRevocation{
        NodeID:        nodeID,
        PreviousRole:  currentRole,
        NewRole:       RoleObserver,
        Reason:        reason,
        Timestamp:     time.Now(),
        IsEmergency:   true,
    }

    // Role-specific cleanup
    switch currentRole {
    case RoleCoordinator:
        // Remove from coordinator pool
        if err := dm.removeCoordinator(ctx, nodeID); err != nil {
            return err
        }
        // Trigger coordinator replacement
        dm.triggerCoordinatorReplacement(ctx, nodeID)
        fallthrough

    case RoleGateway:
        // Revoke BGP announcements
        if err := dm.revokeGatewayRoutes(ctx, nodeID); err != nil {
            dm.auditLog.RecordPhaseError("gateway_revocation", err)
        }
        // Deallocate IP prefix
        dm.prefixAllocator.DeallocatePrefix(nodeID)
        fallthrough

    case RoleHub:
        // Remove from hub pool
        if err := dm.removeHub(ctx, nodeID); err != nil {
            dm.auditLog.RecordPhaseError("hub_removal", err)
        }
        // Redirect traffic to other hubs
        dm.redirectHubTraffic(ctx, nodeID)
        fallthrough

    case RoleLeaf:
        // Demote to observer
        dm.roleManager.SetRole(nodeID, RoleObserver)
    }

    // Publish revocation to DHT
    dm.publishRoleRevocation(ctx, revocation)

    return nil
}
```

### IDevID Invalidation Protocol

```go
// IDevIDInvalidation represents the invalidation of an IDevID certificate
type IDevIDInvalidation struct {
    CertificateSerial   *big.Int
    NodeID              [32]byte
    InvalidationReason  string
    InvalidatedAt       time.Time
    RevokedByCA         bool
    AddedToCRL          bool
    CTLogNotified       bool
}

func (dm *TrustDowngradeManager) invalidateIDevID(ctx context.Context, nodeID [32]byte) error {
    cert := dm.trustStore.GetIDevIDCert(nodeID)
    if cert == nil {
        return ErrNoCertificateFound
    }

    invalidation := &IDevIDInvalidation{
        CertificateSerial:  cert.SerialNumber,
        NodeID:             nodeID,
        InvalidationReason: "trust_downgrade",
        InvalidatedAt:      time.Now(),
    }

    // Step 1: Add to Certificate Revocation List (CRL)
    if err := dm.certRevocation.AddToCRL(cert.SerialNumber, "trust_downgrade"); err != nil {
        return fmt.Errorf("failed to add to CRL: %w", err)
    }
    invalidation.AddedToCRL = true

    // Step 2: Publish to OCSP responders
    if err := dm.publishOCSPRevocation(ctx, cert); err != nil {
        dm.auditLog.RecordPhaseError("ocsp_publication", err)
    }

    // Step 3: Notify CT log of revocation
    if err := dm.notifyCTLog(ctx, cert, "revoked"); err != nil {
        dm.auditLog.RecordPhaseError("ct_log_notification", err)
    }
    invalidation.CTLogNotified = true

    // Step 4: Broadcast invalidation to network
    dm.broadcastCertInvalidation(ctx, invalidation)

    // Step 5: Remove certificate from local trust store
    dm.trustStore.RemoveIDevIDCert(nodeID)
    invalidation.RevokedByCA = true

    dm.auditLog.RecordIDevIDInvalidation(invalidation)
    return nil
}
```

### FROST Share Revocation

```go
func (dm *TrustDowngradeManager) revokeFROSTShares(ctx context.Context, nodeID [32]byte) error {
    // Get all FROST shares held by this node
    shares := dm.frostManager.GetSharesForNode(nodeID)
    if len(shares) == 0 {
        return nil
    }

    for _, share := range shares {
        // Mark share as revoked
        if err := dm.frostManager.RevokeShare(share.ShareID); err != nil {
            dm.auditLog.RecordPhaseError("frost_share_revocation", err)
            continue
        }

        // Trigger share redistribution if needed
        if dm.frostManager.NeedsRedistribution(share.PoolID) {
            dm.triggerShareRedistribution(ctx, share.PoolID, nodeID)
        }
    }

    return nil
}
```

### Network Broadcast Protocol

```go
// TrustDowngradeEvent is broadcast to all network nodes
type TrustDowngradeEvent struct {
    EventID           [32]byte
    NodeID            [32]byte
    TriggerType       DowngradeTriggerType
    Reason            string
    PreviousTrustLevel TrustLevel
    NewTrustLevel      TrustLevel
    RevokedRoles       []Role
    IDevIDRevoked      bool
    FROSTSharesRevoked int
    Timestamp          time.Time
    Signature          []byte  // Signed by coordinator quorum
}

func (dm *TrustDowngradeManager) broadcastDowngrade(ctx context.Context, trigger *DowngradeTrigger) {
    event := &TrustDowngradeEvent{
        EventID:            generateEventID(),
        NodeID:             trigger.NodeID,
        TriggerType:        trigger.Type,
        Reason:             trigger.Reason,
        PreviousTrustLevel: TrustLevelTrusted,
        NewTrustLevel:      TrustLevelUntrusted,
        Timestamp:          time.Now(),
    }

    // Get coordinator signatures
    signatures, err := dm.collectCoordinatorSignatures(ctx, event)
    if err != nil {
        dm.auditLog.RecordPhaseError("coordinator_signatures", err)
    }
    event.Signature = signatures

    // Publish to DHT
    dm.dht.Publish("trust-downgrade", event)

    // Direct notification to affected node
    dm.notifyNode(ctx, trigger.NodeID, event)
}
```

### Periodic Trust Verification

```go
const (
    TrustReVerificationInterval = 24 * time.Hour
    ReVerificationGracePeriod   = 24 * time.Hour
)

// TrustVerificationScheduler runs periodic trust re-verification
type TrustVerificationScheduler struct {
    verifier          TPMVerifier
    downgradeManager  TrustDowngradeManager
    trustStore        TrustStore
}

func (s *TrustVerificationScheduler) RunVerificationCycle(ctx context.Context) {
    trustedNodes := s.trustStore.GetAllTrustedNodes()

    for _, nodeID := range trustedNodes {
        select {
        case <-ctx.Done():
            return
        default:
        }

        // Request fresh attestation
        attestation, err := s.requestAttestation(ctx, nodeID)
        if err != nil {
            // Failed to get attestation - schedule downgrade with grace period
            s.downgradeManager.ProcessDowngrade(ctx, &DowngradeTrigger{
                Type:        TriggerReAttestationFailed,
                NodeID:      nodeID,
                Reason:      fmt.Sprintf("failed to obtain attestation: %v", err),
                GracePeriod: ReVerificationGracePeriod,
            })
            continue
        }

        // Verify attestation
        trustLevel, err := s.verifier.VerifyTPM(ctx, attestation)
        if err != nil {
            // Verification failed - immediate downgrade
            s.downgradeManager.ProcessDowngrade(ctx, &DowngradeTrigger{
                Type:        TriggerReAttestationFailed,
                NodeID:      nodeID,
                Reason:      fmt.Sprintf("re-attestation verification failed: %v", err),
                GracePeriod: 0, // Immediate
            })
            continue
        }

        if trustLevel != TrustLevelTrusted {
            // Trust level changed - downgrade
            s.downgradeManager.ProcessDowngrade(ctx, &DowngradeTrigger{
                Type:        TriggerReAttestationFailed,
                NodeID:      nodeID,
                Reason:      "trust level no longer valid after re-attestation",
                GracePeriod: 0,
            })
        }
    }
}
```

---

## 17. Deterministic Judge Selection (VRF-Based)

**CRITICAL SECURITY REQUIREMENT**: Judge selection for disputes MUST be deterministic to prevent false accusation attacks where an attacker selects favorable judges. VRF-based selection ensures unpredictable yet verifiable judge assignment.

### Attack Vector: Non-Deterministic Judge Selection

Without deterministic selection, an attacker can:
1. File false accusations against legitimate nodes
2. Manipulate which judges are selected (through timing, network manipulation, etc.)
3. Collude with selected judges to reach guilty verdicts
4. Damage reputation of targeted nodes

### VRF-Based Selection Protocol

```go
// JudgeSelector implements deterministic VRF-based judge selection
type JudgeSelector struct {
    vrfKey        *vrf.PrivateKey  // Node's VRF private key
    vrfPublicKeys map[[32]byte]*vrf.PublicKey  // All eligible judges' VRF public keys
    eligibilityChecker EligibilityChecker
}

// VRFProof contains the verifiable random function output
type VRFProof struct {
    Output    [32]byte  // VRF output (used for selection)
    Proof     []byte    // VRF proof (for verification)
    PublicKey []byte    // VRF public key of prover
}

// JudgeSelection represents a deterministic judge assignment
type JudgeSelection struct {
    DisputeID       [32]byte
    EvidenceHash    [32]byte
    BlockHeight     uint64
    BlockHash       [32]byte
    SelectedJudges  [][32]byte
    VRFProofs       []VRFProof
    SelectionSeed   [32]byte
    Timestamp       time.Time
}
```

### Selection Seed Derivation

The selection seed is derived from immutable on-chain data to prevent manipulation:

```go
// DeriveSelectionSeed creates a deterministic seed from dispute parameters
// This seed cannot be manipulated after the dispute is filed
func DeriveSelectionSeed(dispute *Dispute) [32]byte {
    h := sha256.New()

    // Component 1: Dispute ID (unique per dispute)
    h.Write(dispute.ID[:])

    // Component 2: Evidence hash (commits to evidence content)
    h.Write(dispute.EvidenceHash[:])

    // Component 3: Block hash at filing time (adds blockchain randomness)
    h.Write(dispute.FilingBlockHash[:])

    // Component 4: Block height (prevents pre-computation)
    binary.Write(h, binary.BigEndian, dispute.FilingBlockHeight)

    // Component 5: Accused node ID (ties selection to specific dispute)
    h.Write(dispute.AccusedNodeID[:])

    // Component 6: Accuser node ID (prevents accuser from optimizing)
    h.Write(dispute.AccuserNodeID[:])

    var seed [32]byte
    copy(seed[:], h.Sum(nil))
    return seed
}
```

### VRF-Based Judge Selection Algorithm

```go
// SelectJudges deterministically selects judges using VRF
func (js *JudgeSelector) SelectJudges(ctx context.Context, dispute *Dispute, numJudges int) (*JudgeSelection, error) {
    // Step 1: Derive selection seed
    seed := DeriveSelectionSeed(dispute)

    // Step 2: Get eligible judges (excludes accuser, accused, and their peers)
    eligibleJudges, err := js.getEligibleJudges(ctx, dispute)
    if err != nil {
        return nil, fmt.Errorf("failed to get eligible judges: %w", err)
    }

    if len(eligibleJudges) < numJudges {
        return nil, ErrInsufficientEligibleJudges
    }

    // Step 3: Each eligible judge generates VRF output using seed
    vrfOutputs := make(map[[32]byte]VRFProof)
    for _, judgeID := range eligibleJudges {
        proof, err := js.generateVRFOutput(judgeID, seed)
        if err != nil {
            continue // Skip judges that fail to generate proof
        }
        vrfOutputs[judgeID] = proof
    }

    // Step 4: Sort judges by VRF output (deterministic ordering)
    sortedJudges := js.sortByVRFOutput(vrfOutputs)

    // Step 5: Select top N judges
    selectedJudges := sortedJudges[:numJudges]
    selectedProofs := make([]VRFProof, numJudges)
    for i, judgeID := range selectedJudges {
        selectedProofs[i] = vrfOutputs[judgeID]
    }

    selection := &JudgeSelection{
        DisputeID:      dispute.ID,
        EvidenceHash:   dispute.EvidenceHash,
        BlockHeight:    dispute.FilingBlockHeight,
        BlockHash:      dispute.FilingBlockHash,
        SelectedJudges: selectedJudges,
        VRFProofs:      selectedProofs,
        SelectionSeed:  seed,
        Timestamp:      time.Now(),
    }

    return selection, nil
}

// sortByVRFOutput sorts judges deterministically by their VRF output
func (js *JudgeSelector) sortByVRFOutput(outputs map[[32]byte]VRFProof) [][32]byte {
    judges := make([][32]byte, 0, len(outputs))
    for judgeID := range outputs {
        judges = append(judges, judgeID)
    }

    sort.Slice(judges, func(i, j int) bool {
        // Compare VRF outputs lexicographically
        return bytes.Compare(outputs[judges[i]].Output[:], outputs[judges[j]].Output[:]) < 0
    })

    return judges
}
```

### Judge Eligibility Requirements

```go
// EligibilityChecker determines if a node can serve as judge
type EligibilityChecker struct {
    trustStore      TrustStore
    reputationStore ReputationStore
    peerGraph       PeerGraph
}

// JudgeEligibilityRequirements defines minimum requirements for judges
type JudgeEligibilityRequirements struct {
    MinReputation       float64       // 0.80 minimum
    MinAge              time.Duration // 90 days minimum
    MinCASignatures     int           // 50 minimum
    MaxViolations30Days int           // 0 violations in last 30 days
    TrustLevel          TrustLevel    // Must be Trusted
}

var DefaultJudgeRequirements = JudgeEligibilityRequirements{
    MinReputation:       0.80,
    MinAge:              90 * 24 * time.Hour,
    MinCASignatures:     50,
    MaxViolations30Days: 0,
    TrustLevel:          TrustLevelTrusted,
}

func (ec *EligibilityChecker) IsEligibleJudge(nodeID [32]byte, dispute *Dispute) (bool, string) {
    // Rule 1: Must be trusted
    if ec.trustStore.GetTrustLevel(nodeID) != TrustLevelTrusted {
        return false, "node is not trusted"
    }

    // Rule 2: Cannot be the accuser
    if nodeID == dispute.AccuserNodeID {
        return false, "node is the accuser"
    }

    // Rule 3: Cannot be the accused
    if nodeID == dispute.AccusedNodeID {
        return false, "node is the accused"
    }

    // Rule 4: Cannot be a direct peer of accuser or accused
    if ec.peerGraph.IsDirectPeer(nodeID, dispute.AccuserNodeID) {
        return false, "node is direct peer of accuser"
    }
    if ec.peerGraph.IsDirectPeer(nodeID, dispute.AccusedNodeID) {
        return false, "node is direct peer of accused"
    }

    // Rule 5: Must meet reputation requirement
    reputation := ec.reputationStore.GetReputation(nodeID)
    if reputation < DefaultJudgeRequirements.MinReputation {
        return false, "insufficient reputation"
    }

    // Rule 6: Must meet age requirement
    age := ec.trustStore.GetNodeAge(nodeID)
    if age < DefaultJudgeRequirements.MinAge {
        return false, "insufficient node age"
    }

    // Rule 7: Must have no recent violations
    violations := ec.reputationStore.GetViolationsInPeriod(nodeID, 30*24*time.Hour)
    if violations > DefaultJudgeRequirements.MaxViolations30Days {
        return false, "recent violations"
    }

    // Rule 8: Geographic diversity check
    if ec.violatesGeographicDiversity(nodeID, dispute) {
        return false, "geographic diversity violation"
    }

    return true, ""
}

// violatesGeographicDiversity ensures judges are from different regions
func (ec *EligibilityChecker) violatesGeographicDiversity(nodeID [32]byte, dispute *Dispute) bool {
    nodeRegion := ec.peerGraph.GetRegion(nodeID)
    accuserRegion := ec.peerGraph.GetRegion(dispute.AccuserNodeID)
    accusedRegion := ec.peerGraph.GetRegion(dispute.AccusedNodeID)

    // Judge should not be from same region as accuser or accused
    return nodeRegion == accuserRegion || nodeRegion == accusedRegion
}
```

### VRF Output Generation and Verification

```go
// generateVRFOutput generates a verifiable random output for judge selection
func (js *JudgeSelector) generateVRFOutput(judgeID [32]byte, seed [32]byte) (VRFProof, error) {
    // Get judge's VRF private key (stored in TPM)
    vrfPrivKey := js.getVRFPrivateKey(judgeID)
    if vrfPrivKey == nil {
        return VRFProof{}, ErrNoVRFKey
    }

    // Generate VRF output and proof
    output, proof := vrf.Prove(vrfPrivKey, seed[:])

    return VRFProof{
        Output:    output,
        Proof:     proof,
        PublicKey: vrfPrivKey.Public().Bytes(),
    }, nil
}

// VerifyJudgeSelection verifies that judge selection was deterministic
func (js *JudgeSelector) VerifyJudgeSelection(selection *JudgeSelection) error {
    // Verify each judge's VRF proof
    for i, judgeID := range selection.SelectedJudges {
        proof := selection.VRFProofs[i]

        // Get judge's VRF public key
        pubKey := js.vrfPublicKeys[judgeID]
        if pubKey == nil {
            return fmt.Errorf("unknown VRF public key for judge %x", judgeID[:8])
        }

        // Verify VRF proof
        valid, computedOutput := vrf.Verify(pubKey, selection.SelectionSeed[:], proof.Proof)
        if !valid {
            return fmt.Errorf("invalid VRF proof for judge %x", judgeID[:8])
        }

        // Verify output matches
        if !bytes.Equal(computedOutput[:], proof.Output[:]) {
            return fmt.Errorf("VRF output mismatch for judge %x", judgeID[:8])
        }
    }

    // Verify selection order is correct (sorted by VRF output)
    for i := 1; i < len(selection.SelectedJudges); i++ {
        prev := selection.VRFProofs[i-1].Output[:]
        curr := selection.VRFProofs[i].Output[:]
        if bytes.Compare(prev, curr) > 0 {
            return ErrInvalidSelectionOrder
        }
    }

    return nil
}
```

### Anti-Manipulation Protections

```go
// SelectionManipulationDetector detects attempts to game judge selection
type SelectionManipulationDetector struct {
    disputeHistory map[[32]byte][]time.Time // nodeID -> dispute filing times
    vrfOutputHistory map[[32]byte][][32]byte // nodeID -> recent VRF outputs
}

// DetectManipulation checks for selection manipulation patterns
func (d *SelectionManipulationDetector) DetectManipulation(dispute *Dispute) []ManipulationAlert {
    var alerts []ManipulationAlert

    // Check 1: Rapid-fire disputes from same accuser
    recentDisputes := d.disputeHistory[dispute.AccuserNodeID]
    if len(recentDisputes) > 5 {
        lastHour := 0
        for _, t := range recentDisputes {
            if time.Since(t) < time.Hour {
                lastHour++
            }
        }
        if lastHour > 3 {
            alerts = append(alerts, ManipulationAlert{
                Type:    "rapid_dispute_filing",
                NodeID:  dispute.AccuserNodeID,
                Details: fmt.Sprintf("%d disputes in last hour", lastHour),
            })
        }
    }

    // Check 2: Dispute filed immediately after block (timing attack)
    blockTime := d.getBlockTime(dispute.FilingBlockHash)
    timeSinceBlock := dispute.Timestamp.Sub(blockTime)
    if timeSinceBlock < 100*time.Millisecond {
        alerts = append(alerts, ManipulationAlert{
            Type:    "timing_attack_suspected",
            NodeID:  dispute.AccuserNodeID,
            Details: fmt.Sprintf("dispute filed %v after block", timeSinceBlock),
        })
    }

    // Check 3: Same accuser-accused pair repeated
    if d.hasRepeatedPair(dispute.AccuserNodeID, dispute.AccusedNodeID, 7*24*time.Hour) {
        alerts = append(alerts, ManipulationAlert{
            Type:    "repeated_accusation_pair",
            NodeID:  dispute.AccuserNodeID,
            Details: "same accuser-accused pair within 7 days",
        })
    }

    return alerts
}

// False Accusation Penalties
type FalseAccusationPenalty struct {
    AccuserID         [32]byte
    DisputeID         [32]byte
    ReputationPenalty float64
    BanDuration       time.Duration
    Reason            string
}

func (js *JudgeSelector) ProcessNotGuiltyVerdict(dispute *Dispute, verdict *Verdict) {
    if !verdict.Guilty {
        // Apply false accusation penalty
        penalty := &FalseAccusationPenalty{
            AccuserID:         dispute.AccuserNodeID,
            DisputeID:         dispute.ID,
            ReputationPenalty: 0.05, // 5% reputation loss
            Reason:            "false accusation - not guilty verdict",
        }

        // Apply escalating penalties for repeat offenders
        repeatCount := js.getFalseAccusationCount(dispute.AccuserNodeID)
        if repeatCount >= 3 {
            penalty.BanDuration = 24 * time.Hour
        }
        if repeatCount >= 5 {
            penalty.BanDuration = 7 * 24 * time.Hour
        }

        js.applyPenalty(penalty)
    }
}
```

#### Appeal Process (P4-H16 Cross-Reference)

**IMPORTANT**: All judgment verdicts can be appealed. The complete appeal system, including:
- Appeal filing requirements and fees
- Appeal review process
- Appeal bond mechanics
- Escalation to human arbiters for AI decisions

Is documented in [09-defense-reputation.md](09-defense-reputation.md#appeal-process).

Key appeal parameters:
- Appeal window: 48 hours from verdict
- Appeal fee: 10% of stake (refunded if appeal succeeds)
- Appeal quorum: Different set of judges (no overlap with original)
- AI decisions: Can escalate to human arbitration (see [21-ai-arbitration-system.md](21-ai-arbitration-system.md))

```go
// AppealRequest represents a request to appeal a judgment
// Full implementation in 09-defense-reputation.md
type AppealRequest struct {
    OriginalDisputeID [32]byte
    OriginalVerdictID [32]byte
    AppealReason      string
    AppealBond        uint64    // 10% of original stake
    FiledAt           time.Time
    FiledBy           [32]byte  // NodeID of appealing party
}
```

### Complete Judge Selection Flow

```
1. Dispute Filed
       |
       v
2. Derive Selection Seed (dispute_id + evidence_hash + block_hash + block_height)
       |
       v
3. Get Eligible Judges (filter by trust, reputation, conflicts)
       |
       v
4. Each Eligible Judge Generates VRF Output Using Seed
       |
       v
5. Sort Judges by VRF Output (deterministic ordering)
       |
       v
6. Select Top N Judges
       |
       v
7. Verify All VRF Proofs (public verification)
       |
       v
8. Publish Selection (with proofs for transparency)
       |
       v
9. Judges Vote on Dispute
       |
       v
10. Apply Verdict (penalties or exoneration)
```

---

## 18. Quantum-Resistant Cryptography

The go-trusted-platform supports post-quantum cryptography (PQC) through the go-xkms quantum backend, implementing NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards. This provides cryptographic agility and a migration path for quantum-safe security.

### NIST Post-Quantum Standards

| Standard | Algorithm | Purpose | Implementation |
|----------|-----------|---------|----------------|
| **FIPS 203** | ML-KEM (CRYSTALS-Kyber) | Key Encapsulation Mechanism | go-xkms quantum backend |
| **FIPS 204** | ML-DSA (CRYSTALS-Dilithium) | Digital Signatures | go-xkms quantum backend |

### Supported Algorithm Variants

#### ML-DSA (Digital Signatures)

| Variant | Security Level | Public Key Size | Signature Size | Recommendation |
|---------|----------------|-----------------|----------------|----------------|
| **ML-DSA-44** | NIST Level 2 (~128-bit) | 1,312 bytes | 2,420 bytes | Low-resource environments |
| **ML-DSA-65** | NIST Level 3 (~192-bit) | 1,952 bytes | 3,293 bytes | **Recommended default** |
| **ML-DSA-87** | NIST Level 5 (~256-bit) | 2,592 bytes | 4,595 bytes | Maximum security |

#### ML-KEM (Key Encapsulation)

| Variant | Security Level | Public Key Size | Ciphertext Size | Shared Secret | Recommendation |
|---------|----------------|-----------------|-----------------|---------------|----------------|
| **ML-KEM-512** | NIST Level 1 (~128-bit) | 800 bytes | 768 bytes | 32 bytes | Low-resource environments |
| **ML-KEM-768** | NIST Level 3 (~192-bit) | 1,184 bytes | 1,088 bytes | 32 bytes | **Recommended default** |
| **ML-KEM-1024** | NIST Level 5 (~256-bit) | 1,568 bytes | 1,568 bytes | 32 bytes | Maximum security |

### go-xkms Quantum Backend Integration

The quantum cryptography implementation is accessed through the go-xkms package:

```go
import (
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Create quantum backend with recommended security levels
func createQuantumBackend() (*xkmssdk.QuantumBackend, error) {
    config := &quantum.Config{
        SignatureAlgorithm: quantum.MLDSA65,   // Recommended for signatures
        KEMAlgorithm:       quantum.MLKEM768,  // Recommended for key encapsulation
        HybridMode:         true,              // Enable hybrid classical+PQC mode
    }

    backend, err := quantum.NewBackend(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create quantum backend: %w", err)
    }

    return backend, nil
}

// Generate ML-DSA key pair for quantum-safe signatures
func generateQuantumSigningKey(backend *quantum.Backend) (*quantum.KeyPair, error) {
    keyPair, err := backend.GenerateSigningKeyPair()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-DSA key pair: %w", err)
    }

    return keyPair, nil
}

// Generate ML-KEM key pair for quantum-safe key encapsulation
func generateQuantumKEMKey(backend *quantum.Backend) (*quantum.KEMKeyPair, error) {
    keyPair, err := backend.GenerateKEMKeyPair()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
    }

    return keyPair, nil
}
```

### Quantum-Safe Signature Operations

```go
// Sign data with ML-DSA
func signWithMLDSA(backend *quantum.Backend, privateKey *quantum.PrivateKey, data []byte) ([]byte, error) {
    signature, err := backend.Sign(privateKey, data)
    if err != nil {
        return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
    }

    return signature, nil
}

// Verify ML-DSA signature
func verifyMLDSA(backend *quantum.Backend, publicKey *quantum.PublicKey, data, signature []byte) error {
    valid, err := backend.Verify(publicKey, data, signature)
    if err != nil {
        return fmt.Errorf("ML-DSA verification error: %w", err)
    }
    if !valid {
        return ErrInvalidQuantumSignature
    }

    return nil
}

// QuantumSignatureError represents a quantum signature verification failure
var ErrInvalidQuantumSignature = &QuantumSignatureError{
    Code:    "INVALID_QUANTUM_SIGNATURE",
    Message: "ML-DSA signature verification failed",
}

type QuantumSignatureError struct {
    Code    string
    Message string
}

func (e *QuantumSignatureError) Error() string {
    return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
```

### Hybrid Encryption Scheme: ML-KEM + AES-256-GCM

For data encryption, the platform uses a hybrid scheme combining ML-KEM for key encapsulation with AES-256-GCM for symmetric encryption:

```go
// HybridEncryptionScheme combines ML-KEM with AES-256-GCM
type HybridEncryptionScheme struct {
    backend *quantum.Backend
}

// EncryptedPayload contains the ML-KEM ciphertext and AES-encrypted data
type EncryptedPayload struct {
    KEMCiphertext []byte // ML-KEM encapsulated key
    Nonce         []byte // AES-GCM nonce (12 bytes)
    Ciphertext    []byte // AES-256-GCM encrypted data
    Tag           []byte // AES-GCM authentication tag
}

// Encrypt uses ML-KEM to encapsulate a key, then AES-256-GCM to encrypt data
func (h *HybridEncryptionScheme) Encrypt(recipientPublicKey *quantum.KEMPublicKey, plaintext []byte) (*EncryptedPayload, error) {
    // Step 1: Encapsulate shared secret using ML-KEM
    sharedSecret, kemCiphertext, err := h.backend.Encapsulate(recipientPublicKey)
    if err != nil {
        return nil, fmt.Errorf("ML-KEM encapsulation failed: %w", err)
    }

    // Step 2: Derive AES-256 key from shared secret using HKDF
    aesKey, err := deriveAESKey(sharedSecret)
    if err != nil {
        return nil, fmt.Errorf("key derivation failed: %w", err)
    }

    // Step 3: Generate random nonce for AES-GCM
    nonce := make([]byte, 12)
    if _, err := xkms.Rand(nonce); err != nil {
        return nil, fmt.Errorf("nonce generation failed: %w", err)
    }

    // Step 4: Encrypt with AES-256-GCM
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, fmt.Errorf("AES cipher creation failed: %w", err)
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("GCM mode creation failed: %w", err)
    }

    ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

    return &EncryptedPayload{
        KEMCiphertext: kemCiphertext,
        Nonce:         nonce,
        Ciphertext:    ciphertext[:len(ciphertext)-aesGCM.Overhead()],
        Tag:           ciphertext[len(ciphertext)-aesGCM.Overhead():],
    }, nil
}

// Decrypt uses ML-KEM to decapsulate the key, then AES-256-GCM to decrypt data
func (h *HybridEncryptionScheme) Decrypt(privateKey *quantum.KEMPrivateKey, payload *EncryptedPayload) ([]byte, error) {
    // Step 1: Decapsulate shared secret using ML-KEM
    sharedSecret, err := h.backend.Decapsulate(privateKey, payload.KEMCiphertext)
    if err != nil {
        return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
    }

    // Step 2: Derive AES-256 key from shared secret
    aesKey, err := deriveAESKey(sharedSecret)
    if err != nil {
        return nil, fmt.Errorf("key derivation failed: %w", err)
    }

    // Step 3: Decrypt with AES-256-GCM
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, fmt.Errorf("AES cipher creation failed: %w", err)
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("GCM mode creation failed: %w", err)
    }

    // Combine ciphertext and tag for decryption
    ciphertextWithTag := append(payload.Ciphertext, payload.Tag...)

    plaintext, err := aesGCM.Open(nil, payload.Nonce, ciphertextWithTag, nil)
    if err != nil {
        return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
    }

    return plaintext, nil
}

// deriveAESKey derives a 256-bit AES key from the ML-KEM shared secret using HKDF
func deriveAESKey(sharedSecret []byte) ([]byte, error) {
    hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("go-trusted-platform-aes-key"))
    aesKey := make([]byte, 32) // AES-256

    if _, err := io.ReadFull(hkdf, aesKey); err != nil {
        return nil, err
    }

    return aesKey, nil
}
```

### Integration with go-xkms for Quantum-Safe Certificates

The go-xkms CA component (pkg/ca, formerly go-trusted-ca, consumed via go-quicbaas SDK) supports quantum-safe X.509 certificates with ML-DSA signatures:

```go
import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// QuantumCertificateAuthority extends the CA with quantum-safe capabilities
type QuantumCertificateAuthority struct {
    classicalCA    xkmssdk.TrustedCA  // From go-xkms, consumed via go-quicbaas SDK
    quantumBackend *quantum.Backend
    mldsaKeyPair   *quantum.KeyPair
}

// QuantumCertificateConfig defines quantum certificate parameters
type QuantumCertificateConfig struct {
    SignatureAlgorithm quantum.SignatureAlgorithm // ML-DSA-44, ML-DSA-65, or ML-DSA-87
    IncludeClassical   bool                        // Include classical signature for hybrid
    ClassicalAlgorithm string                      // e.g., "ECDSA-P384" for hybrid mode
}

// IssueQuantumCertificate issues an X.509 certificate with ML-DSA signature
func (qca *QuantumCertificateAuthority) IssueQuantumCertificate(
    csr *x509.CertificateRequest,
    config *QuantumCertificateConfig,
) (*QuantumCertificate, error) {

    // Create certificate template
    template := &x509.Certificate{
        SerialNumber: generateSerialNumber(),
        Subject:      csr.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(CertificateValidity),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

        // Add quantum signature algorithm extension
        ExtraExtensions: []pkix.Extension{
            {
                Id:       OIDQuantumSignatureAlgorithm,
                Critical: false,
                Value:    encodeSignatureAlgorithm(config.SignatureAlgorithm),
            },
        },
    }

    // Sign certificate with ML-DSA
    certDER, err := qca.signCertificateWithMLDSA(template, csr.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("quantum certificate signing failed: %w", err)
    }

    // Optionally add classical signature for hybrid mode
    var classicalSig []byte
    if config.IncludeClassical {
        classicalSig, err = qca.classicalCA.SignCertificate(template, csr.PublicKey)
        if err != nil {
            return nil, fmt.Errorf("classical signature failed: %w", err)
        }
    }

    return &QuantumCertificate{
        Certificate:        certDER,
        QuantumSignature:   template.Signature,
        ClassicalSignature: classicalSig,
        Algorithm:          config.SignatureAlgorithm,
    }, nil
}

// QuantumCertificate represents an X.509 certificate with quantum signature
type QuantumCertificate struct {
    Certificate        []byte                      // DER-encoded certificate
    QuantumSignature   []byte                      // ML-DSA signature
    ClassicalSignature []byte                      // Optional classical signature (hybrid mode)
    Algorithm          quantum.SignatureAlgorithm  // ML-DSA variant used
}
```

### X.509 Certificate Extensions for Quantum Signatures

Custom X.509 extensions identify quantum signature algorithms and support hybrid certificates:

```go
// OIDs for quantum cryptography extensions
var (
    // OID arc: 1.3.6.1.4.1.99999.2.x (example private enterprise arc)
    OIDQuantumSignatureAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1}
    OIDQuantumPublicKey          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 2}
    OIDHybridSignature           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 3}

    // NIST ML-DSA algorithm OIDs (per FIPS 204)
    OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
    OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
    OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

    // NIST ML-KEM algorithm OIDs (per FIPS 203)
    OIDMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
    OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
    OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// QuantumExtension represents a quantum algorithm extension in X.509
type QuantumExtension struct {
    Algorithm   asn1.ObjectIdentifier
    PublicKey   []byte // ML-DSA or ML-KEM public key
    HybridMode  bool
    Classical   *ClassicalComponent // Present if HybridMode is true
}

type ClassicalComponent struct {
    Algorithm asn1.ObjectIdentifier
    PublicKey []byte
    Signature []byte
}

// ParseQuantumExtension extracts quantum algorithm info from certificate
func ParseQuantumExtension(cert *x509.Certificate) (*QuantumExtension, error) {
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(OIDQuantumSignatureAlgorithm) {
            var qext QuantumExtension
            if _, err := asn1.Unmarshal(ext.Value, &qext); err != nil {
                return nil, fmt.Errorf("failed to parse quantum extension: %w", err)
            }
            return &qext, nil
        }
    }
    return nil, ErrNoQuantumExtension
}

var ErrNoQuantumExtension = errors.New("certificate does not contain quantum extension")
```

### Migration Strategy for Existing Classical Cryptography

The platform supports a phased migration from classical to quantum-resistant cryptography:

```go
// MigrationPhase defines the current quantum migration phase
type MigrationPhase uint8

const (
    // Phase 1: Classical only (legacy)
    MigrationPhaseClassicalOnly MigrationPhase = iota

    // Phase 2: Hybrid mode - both classical and quantum signatures
    MigrationPhaseHybrid

    // Phase 3: Quantum preferred - quantum primary, classical fallback
    MigrationPhaseQuantumPreferred

    // Phase 4: Quantum only - classical deprecated
    MigrationPhaseQuantumOnly
)

// CryptoMigrationConfig defines the migration configuration
type CryptoMigrationConfig struct {
    CurrentPhase       MigrationPhase
    HybridSignatures   bool   // Issue certificates with both signature types
    AcceptClassical    bool   // Accept classical-only signatures
    AcceptQuantum      bool   // Accept quantum-only signatures
    AcceptHybrid       bool   // Accept hybrid signatures
    DefaultSignature   string // "classical", "quantum", or "hybrid"
}

// DefaultMigrationConfig returns the recommended migration configuration
func DefaultMigrationConfig() *CryptoMigrationConfig {
    return &CryptoMigrationConfig{
        CurrentPhase:     MigrationPhaseHybrid,
        HybridSignatures: true,
        AcceptClassical:  true,  // Still accept during transition
        AcceptQuantum:    true,
        AcceptHybrid:     true,
        DefaultSignature: "hybrid",
    }
}

// CryptoMigrationManager handles the transition to quantum-safe cryptography
type CryptoMigrationManager struct {
    config         *CryptoMigrationConfig
    quantumBackend *quantum.Backend
    classicalCA    *ca.CertificateAuthority
    auditLog       AuditLogger
}

// VerifySignature validates a signature based on current migration phase
// Includes downgrade attack detection for phases 2-4
func (m *CryptoMigrationManager) VerifySignature(
    cert *x509.Certificate,
    signature []byte,
    signatureType string,
) error {
    // CRITICAL: Check for quantum downgrade attacks before signature validation
    if err := m.ValidateQuantumCoverage(cert); err != nil {
        m.auditLog.RecordSecurityEvent("quantum_downgrade_detected", cert.Subject.String(), err.Error())
        return err
    }

    switch signatureType {
    case "classical":
        if !m.config.AcceptClassical {
            return ErrClassicalSignaturesDeprecated
        }
        return m.classicalCA.VerifySignature(cert, signature)

    case "quantum":
        if !m.config.AcceptQuantum {
            return ErrQuantumSignaturesNotAccepted
        }
        return m.quantumBackend.VerifySignature(cert, signature)

    case "hybrid":
        if !m.config.AcceptHybrid {
            return ErrHybridSignaturesNotAccepted
        }
        // Verify both classical and quantum components
        if err := m.classicalCA.VerifySignature(cert, signature); err != nil {
            return fmt.Errorf("hybrid classical verification failed: %w", err)
        }
        if err := m.quantumBackend.VerifySignature(cert, signature); err != nil {
            return fmt.Errorf("hybrid quantum verification failed: %w", err)
        }
        return nil

    default:
        return ErrUnknownSignatureType
    }
}

// ValidateQuantumCoverage ensures certificate has appropriate quantum protection
// for the current migration phase. Prevents downgrade attacks where an attacker
// strips quantum signatures from nodes that claim quantum capability.
func (m *CryptoMigrationManager) ValidateQuantumCoverage(cert *x509.Certificate) error {
    if m.config.CurrentPhase >= MigrationPhaseHybrid {
        // In Phase 2+, classical-only certs from nodes claiming quantum capability
        // must be rejected to prevent downgrade attacks
        if !hasQuantumExtension(cert) && nodeClaimsQuantumCapability(cert.Subject) {
            return ErrQuantumDowngradeDetected
        }
    }

    if m.config.CurrentPhase >= MigrationPhaseQuantumPreferred {
        // In Phase 3+, all new certs MUST have quantum signatures
        if !hasQuantumExtension(cert) {
            return ErrQuantumSignatureRequired
        }
    }

    return nil
}

// hasQuantumExtension checks if a certificate contains a quantum signature extension
func hasQuantumExtension(cert *x509.Certificate) bool {
    for _, ext := range cert.Extensions {
        if ext.Id.Equal(OIDQuantumSignatureAlgorithm) {
            return true
        }
    }
    return false
}

// nodeClaimsQuantumCapability checks if the certificate subject has previously
// advertised quantum capability (stored in DHT or certificate extension)
func nodeClaimsQuantumCapability(subject pkix.Name) bool {
    // Check for quantum capability extension in subject
    for _, name := range subject.Names {
        if name.Type.Equal(OIDQuantumCapability) {
            return true
        }
    }
    return false
}

// OIDQuantumCapability identifies nodes that have advertised quantum capability
var OIDQuantumCapability = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 4}

// ReissueCertificateWithQuantum migrates a classical certificate to quantum-safe
func (m *CryptoMigrationManager) ReissueCertificateWithQuantum(
    classicalCert *x509.Certificate,
) (*QuantumCertificate, error) {
    m.auditLog.RecordMigration(classicalCert.SerialNumber, "reissue_quantum")

    // Generate new quantum key pair for the subject
    quantumKeyPair, err := m.quantumBackend.GenerateSigningKeyPair()
    if err != nil {
        return nil, fmt.Errorf("quantum key generation failed: %w", err)
    }

    // Create CSR with quantum public key
    csr := &x509.CertificateRequest{
        Subject:   classicalCert.Subject,
        PublicKey: quantumKeyPair.PublicKey,
    }

    // Issue new certificate with quantum signature
    config := &QuantumCertificateConfig{
        SignatureAlgorithm: quantum.MLDSA65,
        IncludeClassical:   m.config.HybridSignatures,
        ClassicalAlgorithm: "ECDSA-P384",
    }

    return m.quantumCA.IssueQuantumCertificate(csr, config)
}

// Migration error types
var (
    ErrClassicalSignaturesDeprecated = errors.New("classical signatures are deprecated in current migration phase")
    ErrQuantumSignaturesNotAccepted  = errors.New("quantum signatures not accepted in current migration phase")
    ErrHybridSignaturesNotAccepted   = errors.New("hybrid signatures not accepted in current migration phase")
    ErrUnknownSignatureType          = errors.New("unknown signature type")
    ErrQuantumDowngradeDetected      = errors.New("quantum downgrade attack detected: node claims quantum capability but presented classical-only certificate")
    ErrQuantumSignatureRequired      = errors.New("quantum signature required in current migration phase")
)
```

### Quantum Cryptography Constants

```go
const (
    // Recommended algorithm defaults
    DefaultMLDSAVariant = quantum.MLDSA65  // Balance of security and performance
    DefaultMLKEMVariant = quantum.MLKEM768 // Balance of security and performance

    // Key sizes
    MLDSA65PublicKeySize  = 1952
    MLDSA65PrivateKeySize = 4032
    MLDSA65SignatureSize  = 3293

    MLKEM768PublicKeySize   = 1184
    MLKEM768PrivateKeySize  = 2400
    MLKEM768CiphertextSize  = 1088
    MLKEM768SharedSecretSize = 32

    // Hybrid encryption
    AES256GCMKeySize   = 32
    AES256GCMNonceSize = 12
    AES256GCMTagSize   = 16
)
```

### Security Considerations

| Consideration | Mitigation |
|---------------|------------|
| **Larger key/signature sizes** | Use hybrid mode during transition; optimize storage |
| **Performance overhead** | ML-DSA/ML-KEM are efficient; benchmark for specific use cases |
| **Algorithm updates** | Crypto agility design allows algorithm replacement |
| **Side-channel attacks** | Use constant-time implementations from go-xkms |
| **Key management** | Store quantum keys in TPM where supported |
| **Interoperability** | Hybrid mode ensures backward compatibility |

### Quantum Migration Security

**CRITICAL SECURITY REQUIREMENT**: During the quantum cryptography migration (Phases 2-4), the platform must prevent downgrade attacks where malicious nodes strip quantum signatures to bypass post-quantum security requirements.

#### Downgrade Attack Prevention

A downgrade attack occurs when:
1. A node has previously advertised quantum capability
2. The node presents a classical-only certificate in a phase requiring quantum
3. The attacker strips the quantum signature to exploit classical-only validation

```go
// QuantumDowngradeProtection prevents stripping quantum signatures
type QuantumDowngradeProtection struct {
    MinPhase            MigrationPhase
    EnforceHybrid       bool
    RejectClassicalOnly bool
}

// ValidateQuantumCoverage ensures certificate has appropriate quantum protection
func ValidateQuantumCoverage(cert *x509.Certificate, config *CryptoMigrationConfig) error {
    if config.CurrentPhase >= MigrationPhaseHybrid {
        // In Phase 2+, classical-only certs from nodes claiming quantum capability
        // must be rejected to prevent downgrade attacks
        if !hasQuantumExtension(cert) && nodeClaimsQuantumCapability(cert.Subject) {
            return ErrQuantumDowngradeDetected
        }
    }

    if config.CurrentPhase >= MigrationPhaseQuantumPreferred {
        // In Phase 3+, all new certs MUST have quantum signatures
        if !hasQuantumExtension(cert) {
            return ErrQuantumSignatureRequired
        }
    }

    return nil
}

var ErrQuantumDowngradeDetected = errors.New("quantum downgrade attack detected: node claims quantum capability but presented classical-only certificate")
var ErrQuantumSignatureRequired = errors.New("quantum signature required in current migration phase")
```

#### Mandatory Capability Advertisement

Nodes MUST advertise their quantum capabilities in their certificates:

1. **Quantum Capability Extension**: When a node generates quantum keys, it MUST include the `OIDQuantumCapability` extension in its certificate
2. **Capability Persistence**: Once a node advertises quantum capability, it cannot downgrade to classical-only
3. **DHT Advertisement**: Quantum-capable nodes publish their capability to the DHT for network-wide visibility

```go
// QuantumCapabilityAdvertisement embeds quantum capability in certificates
type QuantumCapabilityAdvertisement struct {
    QuantumCapable     bool
    SupportedAlgorithms []asn1.ObjectIdentifier // ML-DSA variants supported
    FirstQuantumCert   time.Time               // When node first obtained quantum cert
}

// AdvertiseQuantumCapability adds quantum capability extension to certificate
func AdvertiseQuantumCapability(template *x509.Certificate, capability *QuantumCapabilityAdvertisement) {
    capBytes, _ := asn1.Marshal(capability)
    template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
        Id:       OIDQuantumCapability,
        Critical: true,  // CRITICAL: Must be processed
        Value:    capBytes,
    })
}
```

#### Migration Phase Enforcement Table

| Phase | Accept Classical | Accept Hybrid | Accept Quantum | Downgrade Detection |
|-------|-----------------|---------------|----------------|---------------------|
| Phase 1 | Yes | Yes | Yes | N/A |
| Phase 2 | Yes (legacy) | **Required** | Yes | Active |
| Phase 3 | **No** | Yes (fallback) | **Required** | Strict |
| Phase 4 | **No** | **No** | **Required** | N/A |

**Phase-Specific Security Policies:**

- **Phase 1 (Classical Only)**: No quantum requirements, downgrade detection inactive
- **Phase 2 (Hybrid)**: New certificates MUST be hybrid; classical accepted for legacy nodes only; downgrade detection active for quantum-capable nodes
- **Phase 3 (Quantum Preferred)**: All new certificates MUST have quantum signatures; hybrid accepted as fallback; strict downgrade detection
- **Phase 4 (Quantum Only)**: Only quantum signatures accepted; classical and hybrid deprecated

```go
// GetPhasePolicy returns the security policy for a migration phase
func GetPhasePolicy(phase MigrationPhase) *MigrationPhasePolicy {
    policies := map[MigrationPhase]*MigrationPhasePolicy{
        MigrationPhaseClassicalOnly: {
            AcceptClassical:    true,
            AcceptHybrid:       true,
            AcceptQuantum:      true,
            DowngradeDetection: false,
        },
        MigrationPhaseHybrid: {
            AcceptClassical:    true,  // Legacy only
            AcceptHybrid:       true,  // Required for new certs
            AcceptQuantum:      true,
            DowngradeDetection: true,  // Active
        },
        MigrationPhaseQuantumPreferred: {
            AcceptClassical:    false, // Rejected
            AcceptHybrid:       true,  // Fallback only
            AcceptQuantum:      true,  // Required
            DowngradeDetection: true,  // Strict
        },
        MigrationPhaseQuantumOnly: {
            AcceptClassical:    false, // Rejected
            AcceptHybrid:       false, // Rejected
            AcceptQuantum:      true,  // Required
            DowngradeDetection: false, // N/A - only quantum accepted
        },
    }
    return policies[phase]
}

type MigrationPhasePolicy struct {
    AcceptClassical    bool
    AcceptHybrid       bool
    AcceptQuantum      bool
    DowngradeDetection bool
}
```

#### Downgrade Attack Audit Trail

All downgrade detection events are logged for security monitoring:

```go
type QuantumDowngradeEvent struct {
    EventID           [32]byte
    NodeID            [32]byte
    CertificateSerial *big.Int
    DetectedAt        time.Time
    MigrationPhase    MigrationPhase
    ExpectedType      string  // "hybrid" or "quantum"
    ReceivedType      string  // "classical"
    NodeQuantumSince  time.Time  // When node first advertised quantum capability
    Action            string  // "rejected", "quarantined"
}

func (m *CryptoMigrationManager) recordDowngradeAttempt(cert *x509.Certificate, err error) {
    event := &QuantumDowngradeEvent{
        EventID:        generateEventID(),
        CertificateSerial: cert.SerialNumber,
        DetectedAt:     time.Now(),
        MigrationPhase: m.config.CurrentPhase,
        ExpectedType:   m.getExpectedSignatureType(),
        ReceivedType:   "classical",
        Action:         "rejected",
    }
    
    m.auditLog.RecordSecurityEvent("quantum_downgrade_attempt", event)
    m.alertManager.Fire(AlertQuantumDowngrade{Event: event})
}
```

### Recommended Deployment Timeline

| Phase | Timeline | Actions |
|-------|----------|---------|
| **Phase 1** | Now | Deploy quantum backend, generate quantum keys |
| **Phase 2** | 2025-2026 | Enable hybrid signatures for new certificates |
| **Phase 3** | 2027-2028 | Quantum preferred, migrate existing certificates |
| **Phase 4** | 2029+ | Classical deprecated, quantum-only mode |

---

## 19. I1: TPM Crypto Primitives Interface (CANONICAL)

**CRITICAL REQUIREMENT**: All TPM cryptographic operations across the platform MUST use this canonical interface. This ensures consistent security guarantees, proper error handling, and atomic operations across all components.

### Interface Definition

```go
// TPMCryptoPrimitives is the canonical interface for all TPM operations
// I1: Define missing TPM crypto primitives interface
//
// All components MUST use this interface - no direct TPM access allowed.
// This provides:
// - Consistent error handling across all TPM operations
// - Atomic operations with proper cleanup on failure
// - Security audit logging for all cryptographic operations
// - Hardware abstraction for testing (mock TPM) and production (real TPM)
type TPMCryptoPrimitives interface {
    // === Key Management ===

    // GetEKPublic returns the Endorsement Key public portion
    GetEKPublic(ctx context.Context) ([]byte, error)

    // GetEKCertificate returns the manufacturer EK certificate
    GetEKCertificate(ctx context.Context) (*x509.Certificate, error)

    // CreateAK creates a new Attestation Key under the EK hierarchy
    CreateAK(ctx context.Context) (TPMHandle, error)

    // CreateIDevIDKey creates an IDevID key pair for device identity
    CreateIDevIDKey(ctx context.Context) (TPMHandle, []byte, error)

    // StoreIDevIDCertificate stores the IDevID certificate in NVRAM
    StoreIDevIDCertificate(cert *x509.Certificate) error

    // GetIDevIDCertificate retrieves the IDevID certificate from NVRAM
    GetIDevIDCertificate(ctx context.Context) (*x509.Certificate, error)

    // StoreNVRAM stores data in TPM NVRAM at the specified index
    StoreNVRAM(index uint32, data []byte) error

    // ReadNVRAM reads data from TPM NVRAM at the specified index
    ReadNVRAM(ctx context.Context, index uint32) ([]byte, error)

    // FlushContext releases a TPM handle
    FlushContext(ctx context.Context, handle TPMHandle) error

    // ExportIdentityKey exports the identity key (requires owner auth)
    ExportIdentityKey() ([]byte, error)

    // === Attestation Operations ===

    // Quote generates a TPM quote over specified PCRs with nonce
    Quote(ctx context.Context, akHandle TPMHandle, nonce []byte, pcrSelection []int) (*TPMQuote, error)

    // CreateAttestationQuote generates an attestation quote for verification
    CreateAttestationQuote(nonce []byte) (*TPMQuote, error)

    // CreateAttestationQuoteWithExternalData includes additional data in quote
    CreateAttestationQuoteWithExternalData(externalData []byte) (*TPMQuote, error)

    // CreateQuote generates a quote binding data to PCR state
    CreateQuote(dataHash []byte, nonce []byte) (*TPMQuote, error)

    // GetQuote generates a quote with operation hash binding
    GetQuote(nonce []byte, operationHash []byte) (*TPMQuote, error)

    // VerifyQuote verifies a quote from another node
    VerifyQuote(quote *TPMQuote, akCert *x509.Certificate, nonce []byte) error

    // VerifyQuoteFreshness checks if a quote is within acceptable time window
    VerifyQuoteFreshness(quote *TPMQuote, maxAge time.Duration) bool

    // Certify certifies one key with another (TPM2_Certify)
    Certify(ctx context.Context, signingKey TPMHandle, keyToCertify []byte) ([]byte, []byte, error)

    // === PCR Operations ===

    // ExtendPCR extends a PCR with new measurement data
    ExtendPCR(pcrIndex int, data []byte) error

    // ReadPCR reads the current value of a PCR
    ReadPCR(pcrIndex int) ([]byte, error)

    // ReadPCRs reads multiple PCRs at once
    ReadPCRs(pcrSelection []int) (map[int][]byte, error)

    // === Sealing/Unsealing ===

    // SealKey seals a key to specific PCR values
    SealKey(key []byte, pcrSelection []int) (*SealedData, error)

    // UnsealKey unseals a key (only succeeds if PCRs match)
    UnsealKey(sealed *SealedData) ([]byte, error)

    // SealNonces seals FROST nonces to TPM with commitment ID
    SealNonces(commitID [16]byte, d, e []byte) (TPMHandle, error)

    // UnsealNonces unseals FROST nonces from TPM
    UnsealNonces(commitID [16]byte) (d, e []byte, err error)

    // DeleteNonces permanently deletes sealed nonces
    DeleteNonces(commitID [16]byte) error

    // DestroyHandle destroys a TPM object handle
    DestroyHandle(handle TPMHandle) error

    // === Cryptographic Operations ===

    // Sign signs data using a TPM-resident key
    Sign(keyHandle TPMHandle, digest []byte) ([]byte, error)

    // GenerateScalarPair generates a pair of scalars for FROST
    GenerateScalarPair() (d, e []byte, err error)

    // GenerateScalars generates N scalars for cryptographic protocols
    GenerateScalars(n int) ([][]byte, error)

    // ComputePartialSignature computes FROST partial signature using sealed key
    ComputePartialSignature(lambda []byte, challenge []byte) ([]byte, error)

    // GenerateECDHKeypair generates ephemeral ECDH key pair in TPM
    GenerateECDHKeypair() (privateHandle TPMHandle, publicKey []byte, err error)

    // ECDH computes ECDH shared secret using TPM-resident private key
    ECDH(privateHandle TPMHandle, peerPublicKey []byte) ([]byte, error)

    // === Random Number Generation ===

    // GetRandom generates cryptographically secure random bytes
    GetRandom(numBytes int) ([]byte, error)

    // GenerateNonce generates a cryptographic nonce
    GenerateNonce() ([]byte, error)

    // === Device Information ===

    // GetManufacturerInfo returns TPM manufacturer information
    GetManufacturerInfo(ctx context.Context) (*TPMManufacturerInfo, error)

    // NodeID returns this node's cryptographic identity
    NodeID() [32]byte

    // === Health and Diagnostics ===

    // HealthCheck performs a basic TPM functionality test
    HealthCheck(ctx context.Context) error

    // GetCapabilities returns TPM capabilities and limits
    GetCapabilities(ctx context.Context) (*TPMCapabilities, error)
}
```

### Supporting Types

```go
// TPMHandle represents a handle to a TPM object
type TPMHandle uint32

// TPMQuote contains a TPM attestation quote
type TPMQuote struct {
    QuoteData     []byte           // TPMS_ATTEST structure
    Signature     []byte           // Quote signature
    PCRValues     map[int][]byte   // PCR values at quote time
    Nonce         []byte           // Nonce used in quote
    Timestamp     time.Time        // TPM clock at quote time
    FirmwareVersion string         // TPM firmware version
}

// SealedData represents data sealed to PCR values
type SealedData struct {
    Handle        TPMHandle
    EncryptedBlob []byte
    PCRPolicy     []int   // PCRs this data is bound to
    CreatedAt     time.Time
}

// TPMManufacturerInfo contains TPM manufacturer details
type TPMManufacturerInfo struct {
    Manufacturer    string   // e.g., "Intel", "AMD", "STMicroelectronics"
    Model           string   // TPM model identifier
    FirmwareVersion string   // Firmware version string
    SpecVersion     string   // TCG spec version (e.g., "2.0")
    VendorID        uint32   // Vendor-specific identifier
    IsDiscrete      bool     // true = dTPM, false = fTPM
}

// TPMCapabilities describes TPM limits and features
type TPMCapabilities struct {
    MaxNVBufferSize    int      // Maximum NV write size
    MaxDigestSize      int      // Maximum digest size
    MaxSessionHandles  int      // Maximum concurrent sessions
    MaxLoadedObjects   int      // Maximum loaded objects
    SupportedAlgorithms []TPMAlgorithm  // Supported crypto algorithms
    HasRNG             bool     // Hardware RNG available
    HasDualPrimaries   bool     // Dual primaries supported
}

// TPMAlgorithm represents a TPM algorithm identifier
type TPMAlgorithm uint16

const (
    TPMAlgSHA256   TPMAlgorithm = 0x000B
    TPMAlgSHA384   TPMAlgorithm = 0x000C
    TPMAlgSHA512   TPMAlgorithm = 0x000D
    TPMAlgRSA      TPMAlgorithm = 0x0001
    TPMAlgECC      TPMAlgorithm = 0x0023
    TPMAlgAES      TPMAlgorithm = 0x0006
)
```

### Error Types

```go
// TPM operation errors - all callers MUST handle these appropriately
var (
    ErrTPMNotInitialized = &TPMError{
        Code:    "TPM_NOT_INITIALIZED",
        Message: "TPM has not been initialized",
    }

    ErrTPMCommunicationFailed = &TPMError{
        Code:      "TPM_COMMUNICATION_FAILED",
        Message:   "failed to communicate with TPM",
        Retriable: true,
    }

    ErrTPMKeyNotFound = &TPMError{
        Code:    "TPM_KEY_NOT_FOUND",
        Message: "requested key not found in TPM",
    }

    ErrTPMPCRMismatch = &TPMError{
        Code:    "TPM_PCR_MISMATCH",
        Message: "PCR values do not match sealing policy",
    }

    ErrTPMQuoteVerificationFailed = &TPMError{
        Code:    "TPM_QUOTE_VERIFICATION_FAILED",
        Message: "TPM quote signature verification failed",
    }

    ErrTPMQuoteExpired = &TPMError{
        Code:    "TPM_QUOTE_EXPIRED",
        Message: "TPM quote is too old",
    }

    ErrTPMNonceNotFound = &TPMError{
        Code:    "TPM_NONCE_NOT_FOUND",
        Message: "sealed nonce not found",
    }

    ErrTPMNonceAlreadyUsed = &TPMError{
        Code:    "TPM_NONCE_ALREADY_USED",
        Message: "nonce has already been consumed",
    }

    ErrTPMHandleExhausted = &TPMError{
        Code:    "TPM_HANDLE_EXHAUSTED",
        Message: "no more TPM handles available",
    }

    ErrTPMNVRAMFull = &TPMError{
        Code:    "TPM_NVRAM_FULL",
        Message: "TPM NVRAM storage is full",
    }

    ErrTPMOwnerAuthFailed = &TPMError{
        Code:    "TPM_OWNER_AUTH_FAILED",
        Message: "TPM owner authorization failed",
    }

    ErrTPMFirmwareCorrupt = &TPMError{
        Code:    "TPM_FIRMWARE_CORRUPT",
        Message: "TPM firmware integrity check failed",
    }

    ErrTPMHardwareFailure = &TPMError{
        Code:      "TPM_HARDWARE_FAILURE",
        Message:   "TPM hardware failure detected",
        Retriable: false,
    }
)

// TPMError represents a TPM operation error
type TPMError struct {
    Code      string
    Message   string
    Retriable bool
    Cause     error
}

func (e *TPMError) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("%s: %s (cause: %v)", e.Code, e.Message, e.Cause)
    }
    return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *TPMError) Unwrap() error {
    return e.Cause
}

func (e *TPMError) Is(target error) bool {
    t, ok := target.(*TPMError)
    if !ok {
        return false
    }
    return e.Code == t.Code
}
```

### Factory and Implementation Registration

```go
// TPMFactory creates TPM primitives instances
type TPMFactory interface {
    // CreateRealTPM creates a TPM interface for real hardware
    CreateRealTPM(devicePath string) (TPMCryptoPrimitives, error)

    // CreateMockTPM creates a mock TPM for testing (NEVER use in production)
    CreateMockTPM() (TPMCryptoPrimitives, error)

    // CreateRemoteTPM creates a TPM interface for remote attestation
    CreateRemoteTPM(endpoint string, tlsConfig *tls.Config) (TPMCryptoPrimitives, error)
}

// DefaultTPMFactory is the production factory
var DefaultTPMFactory TPMFactory = &tpm2Factory{}

// tpm2Factory implements TPMFactory for real TPM 2.0 hardware
type tpm2Factory struct{}

func (f *tpm2Factory) CreateRealTPM(devicePath string) (TPMCryptoPrimitives, error) {
    if devicePath == "" {
        devicePath = "/dev/tpmrm0"  // Linux default
    }

    // Open TPM device
    tpm, err := tpm2.OpenTPM(devicePath)
    if err != nil {
        return nil, &TPMError{
            Code:    "TPM_OPEN_FAILED",
            Message: fmt.Sprintf("failed to open TPM at %s", devicePath),
            Cause:   err,
        }
    }

    return &realTPM{device: tpm, path: devicePath}, nil
}

func (f *tpm2Factory) CreateMockTPM() (TPMCryptoPrimitives, error) {
    // SECURITY: Only allow mock TPM in test mode
    if !isTestMode() {
        return nil, &TPMError{
            Code:    "MOCK_TPM_DENIED",
            Message: "mock TPM not allowed in production",
        }
    }
    return &mockTPM{}, nil
}
```

### Usage Patterns

```go
// Recommended pattern for TPM operations with proper error handling
func performTPMOperation(tpm TPMCryptoPrimitives) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Generate attestation with proper error handling
    quote, err := tpm.CreateAttestationQuote(generateNonce())
    if err != nil {
        var tpmErr *TPMError
        if errors.As(err, &tpmErr) {
            if tpmErr.Retriable {
                // Retry with backoff
                return retryWithBackoff(func() error {
                    quote, err = tpm.CreateAttestationQuote(generateNonce())
                    return err
                })
            }
            // Non-retriable - log and fail
            logTPMError(tpmErr)
        }
        return fmt.Errorf("attestation failed: %w", err)
    }

    return nil
}

// Atomic seal-use-delete pattern for FROST nonces
func useFROSTNonceAtomically(tpm TPMCryptoPrimitives, commitID [16]byte) error {
    // Unseal nonces (marks as in-use)
    d, e, err := tpm.UnsealNonces(commitID)
    if err != nil {
        return fmt.Errorf("unseal nonces: %w", err)
    }

    // Use nonces for signing...
    defer func() {
        // CRITICAL: Always delete nonces after use (one-time use)
        if delErr := tpm.DeleteNonces(commitID); delErr != nil {
            // Log but don't fail - nonces were already used
            logNonceDeletionError(commitID, delErr)
        }
    }()

    // Perform FROST signing with d, e
    return performFROSTSigning(d, e)
}
```

### Interface Compliance Table

All components using TPM operations MUST use this interface:

| Component | TPM Methods Used | Compliance |
|-----------|------------------|------------|
| **CA Pool (05)** | Quote, CreateAttestationQuote, StoreNVRAM | REQUIRED |
| **FROST Protocol (04)** | SealNonces, UnsealNonces, DeleteNonces, GenerateScalarPair, ComputePartialSignature | REQUIRED |
| **P2P Enrollment (18)** | GetEKPublic, CreateAK, Certify, Quote, CreateIDevIDKey, GetEKCertificate | REQUIRED |
| **Defense System (09)** | CreateAttestationQuoteWithExternalData, NodeID | REQUIRED |
| **DDoS Protection (16)** | GenerateNonce, CreateQuote, VerifyQuote, VerifyQuoteFreshness | REQUIRED |
| **Content Storage (12)** | SealKey, UnsealKey, ExtendPCR | REQUIRED |
| **Service Contracts (19)** | Quote | REQUIRED |
| **Content Distribution (08)** | ExtendPCR, SealKey, UnsealKey, CreateAttestationQuote | REQUIRED |

### Security Audit Requirements

All TPM operations MUST be logged:

```go
// TPMAuditEntry records a TPM operation for security audit
type TPMAuditEntry struct {
    EntryID       string
    Operation     string    // Method name
    NodeID        [32]byte
    Timestamp     time.Time
    Success       bool
    ErrorCode     string    // If failed
    KeyHandle     TPMHandle // If applicable
    PCRSelection  []int     // If applicable
    Duration      time.Duration
}

// AuditableTPM wraps TPMCryptoPrimitives with mandatory audit logging
type AuditableTPM struct {
    inner    TPMCryptoPrimitives
    auditLog TPMAuditLog
}

// All methods delegate to inner with audit logging
func (a *AuditableTPM) Quote(ctx context.Context, akHandle TPMHandle, nonce []byte, pcrSelection []int) (*TPMQuote, error) {
    start := time.Now()
    quote, err := a.inner.Quote(ctx, akHandle, nonce, pcrSelection)

    entry := &TPMAuditEntry{
        EntryID:      generateAuditID(),
        Operation:    "Quote",
        Timestamp:    start,
        Duration:     time.Since(start),
        PCRSelection: pcrSelection,
    }

    if err != nil {
        entry.Success = false
        if tpmErr, ok := err.(*TPMError); ok {
            entry.ErrorCode = tpmErr.Code
        }
    } else {
        entry.Success = true
    }

    a.auditLog.Record(entry)
    return quote, err
}

// Production code MUST use AuditableTPM wrapper
func NewProductionTPM(devicePath string) (TPMCryptoPrimitives, error) {
    inner, err := DefaultTPMFactory.CreateRealTPM(devicePath)
    if err != nil {
        return nil, err
    }

    return &AuditableTPM{
        inner:    inner,
        auditLog: NewFileAuditLog("/var/log/tpm-audit.log"),
    }, nil
}
```

---

## Quick Reference for Developers

When implementing features, use these canonical sources:

| Category | Canonical Location | Section |
|----------|-------------------|---------|
| **Reputation Thresholds** | `09-defense-reputation.md` Line 127 | "Role Eligibility Thresholds (CANONICAL)" |
| **Security Constants** | This document, Line 55 | "3. Security Constants (CANONICAL)" |
| **DHT Parameters** | This document, Line 59 | Kademlia constants |
| **Age Requirements** | This document, Line 146 | Network participation minimums |
| **Role Progression** | `09-defense-reputation.md` | Timeline calculations |
| **Trust Model** | This document, Section 6 | "TPM Trust Policy (CANONICAL)" |
| **Defense System** | `09-defense-reputation.md` | Judges, penalties, violations |
| **Navigation Index** | `00-README.md` Lines 56-151 | Quick reference table |
| **Clock Synchronization** | This document, Section 3 | "Clock Synchronization Parameters" |
| **Nonce Management** | This document, Section 4 | "Nonce Management Parameters (CANONICAL)" |
| **TPM EK Certificate Transparency** | This document, Section 6 | "Certificate Transparency for TPM EK Certificates" |
| **TPM Clock Drift Analysis** | This document, Section 4 | "TPM Clock Drift Tolerance Analysis (CANONICAL)" |

**Verification Status** (as of 2026-01-10):
- All reputation thresholds consistent across documents
- Age requirements complete in 02-network-architecture.md
- Uptime requirements clarified (probation vs ongoing)
- All cryptographic constants verified consistent
- DHT parameters verified consistent
- Binary trust model enforced consistently
- Clock synchronization requirements documented with NTP integration
- Nonce management enhanced with structured format and per-node tracking
- Certificate Transparency for TPM EK certificates documented
- TPM clock drift tolerance analysis with attack scenarios complete

---

## Cross-References

- **Architecture Overview:** See `docs/design/02-architecture-patterns.md` for system design
- **FROST Protocol:** See `docs/design/04-frost-ca.md` for threshold signature details
- **DHT Design:** See `docs/design/05-dht-overlay.md` for Kademlia implementation
- **Tier System:** See `docs/design/06-tier-reputation.md` for role promotion rules
- **Enhancements:** See `docs/architecture/enhancements.md` for planned improvements
- **Defense and Reputation:** See `docs/dht/09-defense-reputation.md` for reputation system details

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-10 | 3.1 | Added TPM Tier Classification (TPMTierHardware, TPMTierFirmware, TPMTierCloud, TPMTierPlatform); added Manufacturer CA Whitelist with approved hardware TPM manufacturers (Infineon, STMicroelectronics, Nuvoton, Microchip/Atmel, Nations Technologies); added TPM Tier Eligibility Matrix for CA pool and infrastructure participation; added OrganizationID note for CA pool constraints referencing docs/dht/26-organization-identity.md |
| 2026-01-10 | 3.0 | Added Clock Synchronization Parameters (NTP sync mandatory, 100ms max drift, 1-min check interval, 5-min grace period, -0.10 reputation penalty); enhanced Nonce Management (30s max age, 60s replay window, 10K batch cleanup, structured nonce format with embedded timestamp, per-node tracking); added Certificate Transparency for TPM EK (CT log submission required, anomaly detection for issuance spikes, batch record cross-reference, compromised manufacturer CA detection); enhanced TPM Clock Drift Tolerance analysis (5s window rationale, attack scenario analysis for timing manipulation, security vs operational tradeoffs) |
| 2026-01-10 | 2.9 | Fixed coordinator heartbeat timing (2s interval, 10s failover) to match 06-consensus-coordination.md canonical values; added clock drift justification for 5s window vs 100ms quote freshness; added per-bucket diversity thresholds (50% subnet, 33% ASN, 25% org, 3 effective groups); added network-wide eclipse claim validation requiring 3 confirmations from 3 ASNs with -0.10 penalty for false claims |
| 2026-01-10 | 2.8 | Added Nonce Storage Bounds specifications (MaxNonceCacheSize=100K, eviction policy, cleanup frequency 5s), expanded Eclipse Attack Mitigation (DHT neighbor diversity requirements with geographic/ASN/organization thresholds, detection mechanisms, response protocol), added TPM TOCTOU Operation Timeout specifications (500ms max timeout, nested operation prevention, FIFO lock fairness, binding expiration handling) |
| 2026-01-10 | 2.7 | Added Quick Reference for Developers section; merged CANONICAL_VALUES_REFERENCE.md content; documentation consistency audit complete |
| 2026-01-10 | 2.6 | Enhanced TPM verification: atomic quote verification with operation binding (operation_hash = SHA256(type \|\| params \|\| timestamp)), single atomic section with lock semantics, TPMVerificationResult struct with explicit error codes. Added continuous TPM health check (4-hour re-attestation), trust downgrade state machine (TRUSTED -> quarantine -> role strip -> notification), DKG timing clarification (10 min fast path with overlap, 13 min slow path) |
| 2026-01-09 | 2.5 | Added TPM Crypto Primitives Interface (I1) - canonical interface for all TPM operations with error types, factory pattern, usage examples, compliance table |
| 2026-01-09 | 2.4 | Added Quantum Migration Security subsection with downgrade attack prevention, mandatory capability advertisement, and migration phase enforcement |
| 2026-01-09 | 2.3 | Added Quantum-Resistant Cryptography section (NIST FIPS 203/204, ML-KEM, ML-DSA, hybrid encryption, migration strategy) |
| 2026-01-09 | 2.2 | Added TPM Verification Protocol (explicit failure handling), Trust Level Enforcement (hard caps), Trust Downgrade Protocol, Deterministic Judge Selection (VRF-based) |
| 2026-01-08 | 2.1 | Added Node Scrutiny System section with scrutiny levels, constraints, and misbehavior types |
| 2026-01-07 | 2.0 | Binary TPM trust model (Trusted/Untrusted only), removed fTPM Leaf-Only tier, IDevID enrollment via ACME enroll-01 to Privacy CA |
| 2025-12-30 | 1.0 | Consolidated from security-overview.md, security-and-automation.md, tpm-trust-policy.md |

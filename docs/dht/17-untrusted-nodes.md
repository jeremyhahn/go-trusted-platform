# Untrusted Node Work Assignment and Scrutiny System

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

## Overview

Untrusted nodes represent participants in the Trusted DHT network that lack hardware-backed TPM attestation with whitelisted endorsement keys. While these nodes cannot earn reputation or assume privileged roles, they serve a critical function in network security by performing defensive work assignments that protect the network from malicious actors.

This document defines the work assignment system, scrutiny levels, misbehavior detection, and penalty mechanisms for untrusted nodes.

**Key Principle**: Untrusted nodes contribute to network security through work, receiving network access privileges in exchange rather than reputation tokens.

**Source**: `pkg/dht/untrusted/`

---

## Trust Determination (CANONICAL)

Trust status is determined during node enrollment via the ACME enroll-01 challenge to the DHT Privacy CA. The determination is **purely based on EK certificate chain validation** against configured TPM Manufacturer CA certificates.

**Key Principle**: Trust is NOT hardcoded based on TPM type (hardware, firmware, virtual). Trust is determined SOLELY by whether the EK certificate validates to a **configured Manufacturer CA** in the Privacy CA's trust store.

### Trust Classification Flow

```
Node Enrollment (ACME enroll-01)
        |
        v
+------------------------+
| Extract EK Certificate |
| from TPM Attestation   |
+--------+---------------+
         |
         v
+----------------------------------+
| Validate EK Certificate Chain    |
| Against Privacy CA's Configured  |
| TPM Manufacturer CA Certificates |
+--------+-------------------------+
         |
         v
+-------------------+     +-------------------+
| Chain Validates?  |--No-|     UNTRUSTED     |
| (to any configured|     | EK does not chain |
|  Manufacturer CA) |     | to trusted CA     |
+--------+----------+     +-------------------+
         |
         | Yes
         v
+-------------------+
|      TRUSTED      |
| (Full privileges) |
+-------------------+
```

### Trust Classification Summary

| Condition | Trust Level | Outcome |
|-----------|-------------|---------|
| EK validates to configured Manufacturer CA | **TRUSTED** | Can earn reputation, all roles available |
| EK does NOT validate to any configured CA | **UNTRUSTED** | Cannot earn reputation, restricted access |

**Examples** (assuming Intel and AMD CAs are configured):

| TPM Type | Manufacturer | EK Chain | Trust Level |
|----------|--------------|----------|-------------|
| Intel fTPM (PTT) | Intel | Chains to Intel CA | **TRUSTED** |
| AMD fTPM | AMD | Chains to AMD CA | **TRUSTED** |
| Infineon dTPM | Infineon | Chains to Infineon CA | **TRUSTED** (if configured) |
| swtpm | Self-signed | No valid chain | **UNTRUSTED** |
| Unknown vendor | Unknown | No configured CA | **UNTRUSTED** |

### Privacy CA Manufacturer Configuration

The Privacy CA dynamically loads trusted TPM Manufacturer CA certificates via the go-xkms CA API (consumed through go-quicbaas SDK). This is the **only** mechanism for determining trust - no hardcoded logic.

**Dynamic CA Loading**: Manufacturer CA certificates are imported using the CA's API methods:

```go
// Import a manufacturer's EK CA certificate into the Privacy CA
err := privacyCA.ImportEndorsementKeyCertificate(manufacturerCACert)

// For certificates with AIA extensions, recursively import the full chain
err := privacyCA.ImportIssuingCAs(ekCert)
```

**Storage Location**: Imported certificates are stored in the CA's certificate store:
```
/app/data/ca/certs/
├── intel-tpm-ek-ca.pem        # Intel fTPM + dTPM
├── amd-tpm-ek-ca.pem          # AMD fTPM
├── infineon-tpm-ek-ca.pem     # Infineon dTPM
├── stmicro-tpm-ek-ca.pem      # STMicroelectronics
├── nuvoton-tpm-ek-ca.pem      # Nuvoton
└── ...                        # Additional manufacturers
```

**Import Methods**:
- **`ImportEndorsementKeyCertificate(cert)`**: Import a manufacturer EK CA certificate directly
- **`ImportIssuingCAs(cert)`**: Auto-import all issuing CAs from a certificate's AIA extension (recursive)
- Factory pattern with `CertStoreFactory` for per-CA certificate stores

**Bootstrap Process**: Network operators pre-import trusted manufacturer CAs before the network goes live. New manufacturers can be added via governance proposal (see [10-governance-economics.md](10-governance-economics.md)).

### Trust Level Implementation

```go
// TrustLevel represents the binary trust classification
type TrustLevel uint8

const (
    // TrustLevelUntrusted - EK does not chain to any configured Manufacturer CA
    TrustLevelUntrusted TrustLevel = iota
    // TrustLevelTrusted - EK chains to a configured Manufacturer CA
    TrustLevelTrusted
)

// TrustDetermination validates EK certificates against configured CAs
type TrustDetermination struct {
    // Configured trusted TPM Manufacturer CA certificates
    // Loaded from Privacy CA configuration - NOT hardcoded
    TrustedManufacturerCAs []*x509.Certificate
}

// DetermineTrustLevel validates EK certificate chain against configured CAs
// This is the ONLY trust determination logic - no hardcoding of TPM types
func (td *TrustDetermination) DetermineTrustLevel(ekCert *x509.Certificate) TrustLevel {
    // Build certificate pool from configured manufacturer CAs
    roots := x509.NewCertPool()
    for _, ca := range td.TrustedManufacturerCAs {
        roots.AddCert(ca)
    }

    // Validate EK certificate chain
    opts := x509.VerifyOptions{
        Roots: roots,
        KeyUsages: []x509.ExtKeyUsage{
            x509.ExtKeyUsageAny,
        },
    }

    if _, err := ekCert.Verify(opts); err == nil {
        // EK chains to a configured manufacturer CA
        return TrustLevelTrusted
    }

    // EK does not chain to any configured CA
    return TrustLevelUntrusted
}
```

### Adding New Trusted Manufacturers

To trust a new TPM manufacturer:

1. Obtain the manufacturer's TPM CA certificate
2. Add the certificate to the Privacy CA's trust store
3. Restart the Privacy CA (or trigger certificate reload)
4. New nodes with EKs from that manufacturer will now be TRUSTED

No code changes required - trust is entirely configuration-driven.

---

## Work Types for Untrusted Nodes

Untrusted nodes participate in network security by performing defensive work assignments. These assignments leverage untrusted nodes as a first line of defense against attacks, protecting trusted infrastructure.

### Work Assignment Categories

| Work Type | Description | Compensation | Duration |
|-----------|-------------|--------------|----------|
| **PoW Verification** | Verify proof-of-work solutions from incoming requests | Network access | Per-request |
| **Traffic Scrubbing** | First-hop proxy filtering malicious traffic patterns | Bandwidth allocation | Continuous |
| **Challenge Generation** | Generate and distribute PoW challenges to requesters | Reduced rate limits | Per-challenge |
| **IP Scoring** | Report suspicious IP behavior and anomaly patterns | Priority queue access | Per-report |
| **Blocklist Propagation** | Store and serve threat intelligence data | Storage credits | Per-block |

### Work Assignment Architecture

```
                    UNTRUSTED NODE WORK FLOW

+-------------------------------------------------------------------+
|                      WORK COORDINATOR                              |
|  +-------------------------------------------------------------+  |
|  |                   Assignment Queue                          |  |
|  |  +--------+ +--------+ +--------+ +--------+ +--------+     |  |
|  |  | PoW    | |Traffic | |Chall.  | | IP     | |Block-  |     |  |
|  |  | Verify | |Scrub   | |Gen     | |Score   | |list    |     |  |
|  |  +---+----+ +---+----+ +---+----+ +---+----+ +---+----+     |  |
|  +------|----------|----------|----------|----------|----------+  |
|         |          |          |          |          |             |
+---------|----------|----------|----------|----------|-------------+
          |          |          |          |          |
          v          v          v          v          v
+-------------------------------------------------------------------+
|                     UNTRUSTED NODE POOL                            |
|  +----------+ +----------+ +----------+ +----------+               |
|  | Node A   | | Node B   | | Node C   | | Node D   |  ...         |
|  | PoW      | | Scrub    | | Chall    | | Score    |               |
|  | Verify   | | Traffic  | | Gen      | | IP       |               |
|  +----+-----+ +----+-----+ +----+-----+ +----+-----+               |
|       |            |            |            |                     |
|       v            v            v            v                     |
|  +----------+ +----------+ +----------+ +----------+               |
|  | Compen-  | | Compen-  | | Compen-  | | Compen-  |               |
|  | sation:  | | sation:  | | sation:  | | sation:  |               |
|  | Access   | | Bandwidth| | Rate     | | Priority |               |
|  +----------+ +----------+ +----------+ +----------+               |
+-------------------------------------------------------------------+
```

### Work Type Specifications

#### PoW Verification

Untrusted nodes verify proof-of-work solutions submitted by incoming requests, offloading computational verification from trusted infrastructure.

```go
type PoWVerificationWork struct {
    WorkID        [32]byte
    Challenge     [32]byte
    Difficulty    uint8
    Solution      []byte
    SubmitterIP   string
    AssignedAt    time.Time
    Deadline      time.Time
    Verified      bool
    VerifiedAt    time.Time
}

// Compensation: Network access tokens valid for 1 hour per 100 verifications
const PoWVerificationQuota = 100
const PoWAccessDuration    = 1 * time.Hour
```

#### Traffic Scrubbing

Untrusted nodes act as first-hop proxies, analyzing and filtering traffic before it reaches trusted nodes.

```go
type TrafficScrubbingWork struct {
    WorkID           [32]byte
    TrafficStream    string     // Stream identifier
    FilterRules      []FilterRule
    BytesProcessed   uint64
    MaliciousBlocked uint64
    AssignedAt       time.Time
    Duration         time.Duration
}

// Compensation: Bandwidth allocation (MB) = BytesProcessed / 1000
const BandwidthMultiplier = 0.001
```

#### Challenge Generation

Untrusted nodes generate cryptographic challenges for the PoW system.

```go
type ChallengeGenerationWork struct {
    WorkID          [32]byte
    ChallengeCount  int
    Challenges      [][32]byte
    Difficulty      uint8
    GeneratedAt     time.Time
    ExpiresAt       time.Time
}

// Compensation: Rate limit reduction of 10% per 1000 challenges
const ChallengeRateLimitReduction = 0.10
const ChallengesPerReduction      = 1000
```

#### IP Scoring

Untrusted nodes monitor and report suspicious IP behavior patterns.

```go
type IPScoringWork struct {
    WorkID        [32]byte
    MonitoredIPs  []string
    Reports       []IPReport
    Accuracy      float64      // Historical accuracy (0.0-1.0)
    AssignedAt    time.Time
    ReportedAt    time.Time
}

type IPReport struct {
    IP            string
    Score         float64      // 0.0 (malicious) to 1.0 (benign)
    Confidence    float64
    Behaviors     []string
    Timestamp     time.Time
}

// Compensation: Priority queue access for accurate reports (>80% accuracy)
const IPScoringAccuracyThreshold = 0.80
```

#### Blocklist Propagation

Untrusted nodes store and serve threat intelligence data across the network.

```go
type BlocklistPropagationWork struct {
    WorkID            [32]byte
    BlocklistID       [32]byte
    EntriesStored     int
    QueriesServed     uint64
    StorageBytes      uint64
    AssignedAt        time.Time
    LastServedAt      time.Time
}

// Compensation: Storage credits (1 credit per 1MB stored * days)
const StorageCreditRate = 1.0 // credits per MB-day
```

---

## Scrutiny Levels

The network applies different scrutiny levels to nodes based on their trust status and behavioral history. Scrutiny determines rate limits, PoW requirements, work obligations, and monitoring frequency.

### Scrutiny Level Definitions

```go
// ScrutinyLevel defines monitoring and restriction tiers
type ScrutinyLevel uint8

const (
    // ScrutinyMinimal applies to trusted nodes with good standing
    ScrutinyMinimal ScrutinyLevel = iota
    // ScrutinyStandard applies to trusted nodes in probation
    ScrutinyStandard
    // ScrutinyElevated applies to untrusted nodes
    ScrutinyElevated
    // ScrutinyMaximum applies to flagged/suspicious nodes
    ScrutinyMaximum
)
```

### Scrutiny Level Matrix

| Level | Target | Rate Limit | PoW Required | Work Obligation | Monitoring Interval |
|-------|--------|------------|--------------|-----------------|---------------------|
| **ScrutinyMinimal** | Trusted nodes (good standing) | 100% | No | None | 5 minutes |
| **ScrutinyStandard** | Trusted nodes (probationary) | 80% | No | None | 1 minute |
| **ScrutinyElevated** | Untrusted nodes | 50% | Yes | 4 hours/day | 30 seconds |
| **ScrutinyMaximum** | Flagged/suspicious nodes | 10% | Yes | 8 hours/day | 10 seconds |

### Scrutiny Configuration

```go
type ScrutinyConfig struct {
    Level              ScrutinyLevel
    RateLimitPercent   float64       // Percentage of base rate limit
    PoWRequired        bool          // Whether PoW is required per request
    PoWDifficulty      uint8         // PoW difficulty (bits)
    WorkHoursPerDay    float64       // Required work hours per day
    MonitoringInterval time.Duration // Behavior check interval
    MaxViolations      int           // Violations before escalation
    CooldownPeriod     time.Duration // Time to de-escalate
}

// DefaultScrutinyConfigs returns the canonical scrutiny configurations
func DefaultScrutinyConfigs() map[ScrutinyLevel]*ScrutinyConfig {
    return map[ScrutinyLevel]*ScrutinyConfig{
        ScrutinyMinimal: {
            Level:              ScrutinyMinimal,
            RateLimitPercent:   1.0,    // 100%
            PoWRequired:        false,
            PoWDifficulty:      0,
            WorkHoursPerDay:    0,
            MonitoringInterval: 5 * time.Minute,
            MaxViolations:      10,
            CooldownPeriod:     7 * 24 * time.Hour,
        },
        ScrutinyStandard: {
            Level:              ScrutinyStandard,
            RateLimitPercent:   0.80,   // 80%
            PoWRequired:        false,
            PoWDifficulty:      0,
            WorkHoursPerDay:    0,
            MonitoringInterval: 1 * time.Minute,
            MaxViolations:      5,
            CooldownPeriod:     3 * 24 * time.Hour,
        },
        ScrutinyElevated: {
            Level:              ScrutinyElevated,
            RateLimitPercent:   0.50,   // 50%
            PoWRequired:        true,
            PoWDifficulty:      20,     // ~1 second of work
            WorkHoursPerDay:    4.0,
            MonitoringInterval: 30 * time.Second,
            MaxViolations:      3,
            CooldownPeriod:     24 * time.Hour,
        },
        ScrutinyMaximum: {
            Level:              ScrutinyMaximum,
            RateLimitPercent:   0.10,   // 10%
            PoWRequired:        true,
            PoWDifficulty:      24,     // ~16 seconds of work
            WorkHoursPerDay:    8.0,
            MonitoringInterval: 10 * time.Second,
            MaxViolations:      1,
            CooldownPeriod:     0,      // No de-escalation
        },
    }
}
```

### Scrutiny Level Progression

```
                    SCRUTINY LEVEL PROGRESSION

                         +----------------+
                         | Node Enrolls   |
                         +-------+--------+
                                 |
              +------------------+------------------+
              |                                     |
              v                                     v
    +-------------------+               +-------------------+
    | TRUSTED           |               | UNTRUSTED         |
    | ScrutinyMinimal   |               | ScrutinyElevated  |
    +--------+----------+               +--------+----------+
             |                                   |
             | Probation                         | Violations
             v                                   v
    +-------------------+               +-------------------+
    | ScrutinyStandard  |               | ScrutinyMaximum   |
    | (Probation)       |               | (Flagged)         |
    +--------+----------+               +--------+----------+
             |                                   |
             | Probation Complete                | Persistent
             v                                   | Violations
    +-------------------+                        v
    | ScrutinyMinimal   |               +-------------------+
    | (Full Trust)      |               | PERMANENT BAN     |
    +-------------------+               +-------------------+
```

---

## Misbehavior Detection

The network continuously monitors node behavior to detect policy violations. Misbehavior detection applies to all nodes but triggers different consequences based on trust level.

### Detectable Misbehaviors

| Misbehavior Type | Description | Detection Method |
|------------------|-------------|------------------|
| **Rate Limit Violations** | Exceeding allowed request rate | Request counter |
| **Malformed Requests** | Invalid protocol messages | Protocol parser |
| **Replay Attacks** | Reusing expired/used nonces | Nonce registry |
| **Protocol Violations** | Non-compliant message sequences | State machine |
| **Sybil Patterns** | Multiple identities from same source | Fingerprinting |
| **DDoS Participation** | Flooding or amplification attacks | Traffic analysis |
| **Work Refusal** | Rejecting assigned work tasks | Work tracker |
| **False Reporting** | Submitting fabricated evidence | Cross-validation |

### Misbehavior Classification

```go
// MisbehaviorType enumerates detectable violations
type MisbehaviorType uint8

const (
    MisbehaviorRateLimitViolation MisbehaviorType = iota
    MisbehaviorMalformedRequest
    MisbehaviorReplayAttack
    MisbehaviorProtocolViolation
    MisbehaviorSybilPattern
    MisbehaviorDDoSParticipation
    MisbehaviorWorkRefusal
    MisbehaviorFalseReporting
)

// MisbehaviorSeverity categorizes violation impact
type MisbehaviorSeverity uint8

const (
    SeverityLow MisbehaviorSeverity = iota      // Warning
    SeverityMedium                               // Escalation
    SeverityHigh                                 // Temporary ban
    SeverityCritical                             // Permanent ban
)

// Detection Thresholds (P4-H2: Define all detection constants - FINAL DESIGN)
// These MUST be explicitly defined - never use magic numbers
const (
    // SybilThreshold is the max matching fingerprints before Sybil detection triggers
    // RATIONALE: Based on birthday paradox analysis
    // - 1-2 fingerprints: Single user with backup device (common)
    // - 3-4 fingerprints: Power user or small organization (acceptable)
    // - 5+ fingerprints: 99.9% probability indicates coordinated Sybil attack
    // Birthday paradox: P(collision) with 5 independent devices << 0.001
    // Any legitimate scenario with 5+ identical fingerprints is statistically improbable
    SybilThreshold = 5

    // AmplificationThreshold: ratio of outbound to inbound traffic
    // RATIONALE: Statistical analysis of legitimate DHT patterns
    // - Normal DHT query: 1.0-2.0x (request + response)
    // - Content delivery: 3.0-5.0x (small request, large response)
    // - Legitimate relay: 5.0-8.0x (forwarding with overhead)
    // - 10.0x+ exceeds 99th percentile of legitimate traffic patterns
    // Amplification attacks typically show 50x-1000x ratios
    AmplificationThreshold = 10.0

    // FloodThreshold: requests per second burst rate
    // RATIONALE: 99th percentile analysis of legitimate client behavior
    // - Typical client: 1-10 req/sec average
    // - Busy client: 50-100 req/sec during bursts
    // - Automated tools: 200-500 req/sec (still acceptable)
    // - Attack traffic: 1000+ req/sec sustained
    // Threshold set at 99th percentile to minimize false positives
    FloodThreshold = 1000.0

    // ReplayWindowSeconds: nonce replay detection window
    // Challenge nonces must be unique within this window
    ReplayWindowSeconds = 300 // 5 minutes

    // FingerprintMinSimilarity: threshold for fingerprint matching
    // 0.0 = completely different, 1.0 = identical
    // 0.95+ indicates same device/virtualized clones
    FingerprintMinSimilarity = 0.95

    // FingerprintClusterSimilarity: threshold for ML-based clustering (FINAL DESIGN)
    // Lower threshold for cluster membership detection
    // 0.85+ indicates similar enough to be part of Sybil cluster
    FingerprintClusterSimilarity = 0.85
)

// MisbehaviorRecord captures detected violation details
type MisbehaviorRecord struct {
    RecordID        [32]byte
    NodeID          string
    Type            MisbehaviorType
    Severity        MisbehaviorSeverity
    Description     string
    Evidence        []byte
    DetectedAt      time.Time
    DetectedBy      string              // Detecting node/system
    Corroborations  int                 // Number of confirming reports
}
```

### Detection Implementation

```go
// MisbehaviorDetector monitors node behavior for violations
type MisbehaviorDetector struct {
    nodeID           string
    requestCounter   *RateLimitCounter
    nonceRegistry    *NonceRegistry
    protocolState    *ProtocolStateMachine
    workTracker      *WorkTracker
    fingerprinter    *NodeFingerprinter
    trafficAnalyzer  *TrafficAnalyzer
}

// CheckRequest validates an incoming request for misbehavior
func (md *MisbehaviorDetector) CheckRequest(req *Request) (*MisbehaviorRecord, error) {
    // Rate limit check
    if md.requestCounter.IsExceeded(req.NodeID) {
        return &MisbehaviorRecord{
            Type:        MisbehaviorRateLimitViolation,
            Severity:    SeverityLow,
            Description: "Rate limit exceeded",
            DetectedAt:  time.Now(),
        }, ErrRateLimitExceeded
    }

    // Replay attack check
    if md.nonceRegistry.IsUsed(req.Nonce) {
        return &MisbehaviorRecord{
            Type:        MisbehaviorReplayAttack,
            Severity:    SeverityHigh,
            Description: "Nonce replay detected",
            DetectedAt:  time.Now(),
        }, ErrReplayAttack
    }

    // Protocol compliance check
    if !md.protocolState.IsValidTransition(req.MessageType) {
        return &MisbehaviorRecord{
            Type:        MisbehaviorProtocolViolation,
            Severity:    SeverityMedium,
            Description: "Invalid protocol state transition",
            DetectedAt:  time.Now(),
        }, ErrProtocolViolation
    }

    // Malformed request check
    if err := req.Validate(); err != nil {
        return &MisbehaviorRecord{
            Type:        MisbehaviorMalformedRequest,
            Severity:    SeverityLow,
            Description: fmt.Sprintf("Malformed request: %v", err),
            DetectedAt:  time.Now(),
        }, ErrMalformedRequest
    }

    return nil, nil
}

// CheckSybilPattern analyzes node fingerprint for Sybil indicators
func (md *MisbehaviorDetector) CheckSybilPattern(nodeID string) (*MisbehaviorRecord, error) {
    fingerprint := md.fingerprinter.GetFingerprint(nodeID)

    // Check for matching fingerprints from different node IDs
    matches := md.fingerprinter.FindMatches(fingerprint)
    if len(matches) > SybilThreshold {
        return &MisbehaviorRecord{
            Type:        MisbehaviorSybilPattern,
            Severity:    SeverityCritical,
            Description: fmt.Sprintf("Sybil pattern: %d matching fingerprints", len(matches)),
            Evidence:    serializeFingerprints(matches),
            DetectedAt:  time.Now(),
        }, ErrSybilDetected
    }

    return nil, nil
}

// CheckDDoSParticipation analyzes traffic patterns for attack indicators
func (md *MisbehaviorDetector) CheckDDoSParticipation(nodeID string) (*MisbehaviorRecord, error) {
    patterns := md.trafficAnalyzer.GetPatterns(nodeID)

    // Check for amplification attack patterns
    if patterns.AmplificationRatio > AmplificationThreshold {
        return &MisbehaviorRecord{
            Type:        MisbehaviorDDoSParticipation,
            Severity:    SeverityCritical,
            Description: fmt.Sprintf("DDoS amplification: ratio %.2f", patterns.AmplificationRatio),
            DetectedAt:  time.Now(),
        }, ErrDDoSDetected
    }

    // Check for flood patterns
    if patterns.RequestBurstRate > FloodThreshold {
        return &MisbehaviorRecord{
            Type:        MisbehaviorDDoSParticipation,
            Severity:    SeverityCritical,
            Description: fmt.Sprintf("DDoS flood: %.0f req/sec burst", patterns.RequestBurstRate),
            DetectedAt:  time.Now(),
        }, ErrDDoSDetected
    }

    return nil, nil
}
```

### ML-Based Fingerprint Clustering (FINAL DESIGN)

Enhanced Sybil detection using hierarchical clustering to identify related nodes even with slight fingerprint variations.

```go
// FingerprintClusterer uses ML clustering for Sybil detection
type FingerprintClusterer struct {
    fingerprints map[[32]byte]FingerprintVector
    clusters     []FingerprintCluster
    mu           sync.RWMutex
}

// FingerprintVector represents multi-dimensional device characteristics
type FingerprintVector struct {
    NodeID         [32]byte
    Features       []float64  // CPU, memory, network stack, timing patterns
    Timestamp      time.Time
    ClusterID      int        // -1 if unassigned
}

// FingerprintCluster represents a group of similar fingerprints
type FingerprintCluster struct {
    ClusterID    int
    Members      [][32]byte
    Centroid     []float64
    IntraClusterSimilarity float64
}

// DetectSybilClusters identifies groups of related nodes
func (fc *FingerprintClusterer) DetectSybilClusters() []FingerprintCluster {
    fc.mu.RLock()
    defer fc.mu.RUnlock()

    // Build similarity matrix
    nodes := make([][32]byte, 0, len(fc.fingerprints))
    for nodeID := range fc.fingerprints {
        nodes = append(nodes, nodeID)
    }

    // Hierarchical clustering
    clusters := fc.hierarchicalClustering(nodes, FingerprintClusterSimilarity)

    // Filter clusters with >5 members (Sybil threshold)
    var sybilClusters []FingerprintCluster
    for _, cluster := range clusters {
        if len(cluster.Members) > SybilThreshold {
            sybilClusters = append(sybilClusters, cluster)
        }
    }

    return sybilClusters
}

// hierarchicalClustering performs agglomerative clustering
func (fc *FingerprintClusterer) hierarchicalClustering(
    nodes [][32]byte,
    similarityThreshold float64,
) []FingerprintCluster {
    // Initialize each node as its own cluster
    clusters := make([]FingerprintCluster, len(nodes))
    for i, nodeID := range nodes {
        fp := fc.fingerprints[nodeID]
        clusters[i] = FingerprintCluster{
            ClusterID: i,
            Members:   [][32]byte{nodeID},
            Centroid:  fp.Features,
            IntraClusterSimilarity: 1.0,
        }
    }

    // Merge similar clusters iteratively
    merged := true
    for merged {
        merged = false
        for i := 0; i < len(clusters); i++ {
            for j := i + 1; j < len(clusters); j++ {
                similarity := fc.computeSimilarity(clusters[i].Centroid, clusters[j].Centroid)

                if similarity >= similarityThreshold {
                    // Merge cluster j into cluster i
                    clusters[i].Members = append(clusters[i].Members, clusters[j].Members...)
                    clusters[i].Centroid = fc.recomputeCentroid(clusters[i].Members)
                    clusters[i].IntraClusterSimilarity = fc.computeIntraClusterSimilarity(clusters[i])

                    // Remove cluster j
                    clusters = append(clusters[:j], clusters[j+1:]...)
                    merged = true
                    break
                }
            }
            if merged {
                break
            }
        }
    }

    return clusters
}

// computeSimilarity calculates cosine similarity between feature vectors
func (fc *FingerprintClusterer) computeSimilarity(a, b []float64) float64 {
    if len(a) != len(b) {
        return 0.0
    }

    dotProduct := 0.0
    normA := 0.0
    normB := 0.0

    for i := range a {
        dotProduct += a[i] * b[i]
        normA += a[i] * a[i]
        normB += b[i] * b[i]
    }

    if normA == 0.0 || normB == 0.0 {
        return 0.0
    }

    return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// recomputeCentroid calculates mean feature vector for cluster members
func (fc *FingerprintClusterer) recomputeCentroid(members [][32]byte) []float64 {
    if len(members) == 0 {
        return nil
    }

    firstFP := fc.fingerprints[members[0]]
    centroid := make([]float64, len(firstFP.Features))

    for _, nodeID := range members {
        fp := fc.fingerprints[nodeID]
        for i, val := range fp.Features {
            centroid[i] += val
        }
    }

    for i := range centroid {
        centroid[i] /= float64(len(members))
    }

    return centroid
}

// computeIntraClusterSimilarity measures how tightly clustered members are
func (fc *FingerprintClusterer) computeIntraClusterSimilarity(
    cluster FingerprintCluster,
) float64 {
    if len(cluster.Members) <= 1 {
        return 1.0
    }

    totalSimilarity := 0.0
    comparisons := 0

    for i := 0; i < len(cluster.Members); i++ {
        for j := i + 1; j < len(cluster.Members); j++ {
            fpA := fc.fingerprints[cluster.Members[i]]
            fpB := fc.fingerprints[cluster.Members[j]]
            similarity := fc.computeSimilarity(fpA.Features, fpB.Features)
            totalSimilarity += similarity
            comparisons++
        }
    }

    if comparisons == 0 {
        return 1.0
    }

    return totalSimilarity / float64(comparisons)
}
```

### Cross-Node Correlation (FINAL DESIGN)

Network-wide misbehavior aggregation detects coordinated attacks across multiple nodes.

```go
// MisbehaviorCorrelator aggregates misbehavior reports across the network
type MisbehaviorCorrelator struct {
    reports map[string][]MisbehaviorReport  // reportType -> reports
    mu      sync.RWMutex
}

// MisbehaviorReport represents a detected violation
type MisbehaviorReport struct {
    ReportID    [32]byte
    ReporterID  [32]byte
    TargetID    [32]byte
    Type        MisbehaviorType
    DetectedAt  time.Time
    Evidence    []byte
}

// DetectCoordinatedAttack identifies correlated misbehavior patterns
func (mc *MisbehaviorCorrelator) DetectCoordinatedAttack(
    window time.Duration,
) []CoordinatedAttackPattern {
    mc.mu.RLock()
    defer mc.mu.RUnlock()

    now := time.Now()
    var patterns []CoordinatedAttackPattern

    // Group reports by type and time window
    for misbehaviorType, reports := range mc.reports {
        recentReports := mc.filterRecentReports(reports, now, window)

        // Detect same misbehavior from multiple nodes in short window
        if len(recentReports) >= 3 {
            // Check if reports are temporally clustered
            if mc.isTemporallyClustered(recentReports, 10*time.Minute) {
                pattern := CoordinatedAttackPattern{
                    Type:              misbehaviorType,
                    ParticipatingNodes: mc.extractNodeIDs(recentReports),
                    ReportCount:       len(recentReports),
                    TimeWindow:        window,
                    DetectedAt:        now,
                    Severity:          SeverityCritical,
                }
                patterns = append(patterns, pattern)
            }
        }
    }

    return patterns
}

// CoordinatedAttackPattern represents a multi-node attack
type CoordinatedAttackPattern struct {
    Type               string
    ParticipatingNodes [][32]byte
    ReportCount        int
    TimeWindow         time.Duration
    DetectedAt         time.Time
    Severity           MisbehaviorSeverity
}

// isTemporallyClustered checks if reports are clustered in time
func (mc *MisbehaviorCorrelator) isTemporallyClustered(
    reports []MisbehaviorReport,
    clusterWindow time.Duration,
) bool {
    if len(reports) < 3 {
        return false
    }

    // Sort by timestamp
    sort.Slice(reports, func(i, j int) bool {
        return reports[i].DetectedAt.Before(reports[j].DetectedAt)
    })

    // Check if 3+ reports fall within cluster window
    for i := 0; i <= len(reports)-3; i++ {
        windowStart := reports[i].DetectedAt
        windowEnd := windowStart.Add(clusterWindow)

        clusteredCount := 1
        for j := i + 1; j < len(reports); j++ {
            if reports[j].DetectedAt.Before(windowEnd) {
                clusteredCount++
                if clusteredCount >= 3 {
                    return true
                }
            } else {
                break
            }
        }
    }

    return false
}

// ApplyCoordinatedAttackPenalty penalizes all participating nodes
func (mc *MisbehaviorCorrelator) ApplyCoordinatedAttackPenalty(
    pattern CoordinatedAttackPattern,
) error {
    // All participating nodes receive severe penalty
    for _, nodeID := range pattern.ParticipatingNodes {
        penalty := &Penalty{
            PenaltyID: generatePenaltyID(),
            NodeID:    fmt.Sprintf("%x", nodeID),
            Type:      PenaltyPermanentBan,
            AppliedAt: time.Now(),
            Reason:    fmt.Sprintf("Coordinated attack: %s", pattern.Type),
        }

        if err := applyPenalty(nodeID, penalty); err != nil {
            return fmt.Errorf("failed to apply penalty to %x: %w", nodeID, err)
        }
    }

    // Escalate to security review
    escalateToSecurityReview(pattern)

    return nil
}

// filterRecentReports returns reports within time window
func (mc *MisbehaviorCorrelator) filterRecentReports(
    reports []MisbehaviorReport,
    now time.Time,
    window time.Duration,
) []MisbehaviorReport {
    var recent []MisbehaviorReport
    cutoff := now.Add(-window)

    for _, report := range reports {
        if report.DetectedAt.After(cutoff) {
            recent = append(recent, report)
        }
    }

    return recent
}

// extractNodeIDs extracts unique node IDs from reports
func (mc *MisbehaviorCorrelator) extractNodeIDs(
    reports []MisbehaviorReport,
) [][32]byte {
    seen := make(map[[32]byte]bool)
    var nodeIDs [][32]byte

    for _, report := range reports {
        if !seen[report.TargetID] {
            seen[report.TargetID] = true
            nodeIDs = append(nodeIDs, report.TargetID)
        }
    }

    return nodeIDs
}
```

### Evidence Integrity (FINAL DESIGN)

All misbehavior evidence must be cryptographically signed and verifiable to prevent evidence tampering.

```go
// EvidencePackage represents signed misbehavior evidence
type EvidencePackage struct {
    EvidenceID       [32]byte
    DetectorNodeID   [32]byte
    TargetNodeID     [32]byte
    MisbehaviorType  MisbehaviorType
    Timestamp        time.Time
    RawEvidence      []byte
    EvidenceHash     [32]byte
    TPMSignature     []byte     // TPM-backed signature
    DetectorSignature []byte     // Node's certificate signature
}

// CreateSignedEvidence creates TPM-signed evidence package
func CreateSignedEvidence(
    detector *Node,
    target [32]byte,
    misbehaviorType MisbehaviorType,
    evidence []byte,
) (*EvidencePackage, error) {
    timestamp := time.Now()
    evidenceHash := sha256.Sum256(evidence)

    // Create package for signing
    pkg := &EvidencePackage{
        EvidenceID:      generateEvidenceID(),
        DetectorNodeID:  detector.NodeID,
        TargetNodeID:    target,
        MisbehaviorType: misbehaviorType,
        Timestamp:       timestamp,
        RawEvidence:     evidence,
        EvidenceHash:    evidenceHash,
    }

    // Sign with TPM (hardware-backed)
    tpmSig, err := detector.TPM.Sign(pkg.SignableData())
    if err != nil {
        return nil, fmt.Errorf("TPM signing failed: %w", err)
    }
    pkg.TPMSignature = tpmSig

    // Sign with node certificate
    certSig, err := detector.SignWithCertificate(pkg.SignableData())
    if err != nil {
        return nil, fmt.Errorf("certificate signing failed: %w", err)
    }
    pkg.DetectorSignature = certSig

    return pkg, nil
}

// VerifyEvidenceIntegrity validates evidence signatures and integrity
func VerifyEvidenceIntegrity(pkg *EvidencePackage) error {
    // Step 1: Verify evidence hash matches raw data
    computedHash := sha256.Sum256(pkg.RawEvidence)
    if !bytes.Equal(computedHash[:], pkg.EvidenceHash[:]) {
        return ErrEvidenceTampered{
            Expected: pkg.EvidenceHash,
            Actual:   computedHash,
        }
    }

    // Step 2: Verify TPM signature
    if err := verifyTPMSignature(pkg.DetectorNodeID, pkg.SignableData(), pkg.TPMSignature); err != nil {
        return fmt.Errorf("TPM signature verification failed: %w", err)
    }

    // Step 3: Verify node certificate signature
    cert, err := getCertificate(pkg.DetectorNodeID)
    if err != nil {
        return fmt.Errorf("failed to get detector certificate: %w", err)
    }

    if err := verifyCertificateSignature(cert, pkg.SignableData(), pkg.DetectorSignature); err != nil {
        return fmt.Errorf("certificate signature verification failed: %w", err)
    }

    // Step 4: Verify timestamp is recent (within 5 minutes)
    if time.Since(pkg.Timestamp) > 5*time.Minute {
        return ErrStaleEvidence{Age: time.Since(pkg.Timestamp)}
    }

    return nil
}

// SignableData returns canonical byte representation for signing
func (pkg *EvidencePackage) SignableData() []byte {
    h := sha256.New()
    h.Write(pkg.EvidenceID[:])
    h.Write(pkg.DetectorNodeID[:])
    h.Write(pkg.TargetNodeID[:])
    binary.Write(h, binary.BigEndian, uint8(pkg.MisbehaviorType))
    binary.Write(h, binary.BigEndian, pkg.Timestamp.Unix())
    h.Write(pkg.EvidenceHash[:])
    return h.Sum(nil)
}

// Typed errors for evidence verification
type ErrEvidenceTampered struct {
    Expected, Actual [32]byte
}

func (e ErrEvidenceTampered) Error() string {
    return fmt.Sprintf("evidence tampered: hash mismatch (expected %x, got %x)",
        e.Expected[:8], e.Actual[:8])
}

type ErrStaleEvidence struct {
    Age time.Duration
}

func (e ErrStaleEvidence) Error() string {
    return fmt.Sprintf("stale evidence: %v old (max 5m)", e.Age)
}
```

### Scrutiny Downgrade Process (FINAL DESIGN)

Manual review process for downgrading scrutiny levels with governance oversight.

```go
// ScrutinyDowngradeRequest represents a request to reduce scrutiny
type ScrutinyDowngradeRequest struct {
    RequestID       [32]byte
    NodeID          [32]byte
    CurrentLevel    ScrutinyLevel
    RequestedLevel  ScrutinyLevel
    Justification   string
    SupportingData  []byte
    RequestedAt     time.Time
    RequestedBy     [32]byte  // Coordinator who submitted
}

// SubmitScrutinyDowngrade submits downgrade request to governance
func (sdp *ScrutinyDowngradeProcessor) SubmitScrutinyDowngrade(
    nodeID [32]byte,
    targetLevel ScrutinyLevel,
    justification string,
    supportingData []byte,
) (*ScrutinyDowngradeRequest, error) {
    currentLevel := getNodeScrutinyLevel(nodeID)

    // Validate downgrade is appropriate
    if !isValidDowngrade(currentLevel, targetLevel) {
        return nil, ErrInvalidScrutinyDowngrade{
            From: currentLevel,
            To:   targetLevel,
        }
    }

    // Check cooldown period
    lastRequest := sdp.getLastDowngradeRequest(nodeID)
    if time.Since(lastRequest) < 30*24*time.Hour {
        return nil, ErrDowngradeCooldown{
            LastRequest: lastRequest,
            NextEligible: lastRequest.Add(30 * 24 * time.Hour),
        }
    }

    req := &ScrutinyDowngradeRequest{
        RequestID:      generateRequestID(),
        NodeID:         nodeID,
        CurrentLevel:   currentLevel,
        RequestedLevel: targetLevel,
        Justification:  justification,
        SupportingData: supportingData,
        RequestedAt:    time.Now(),
        RequestedBy:    sdp.coordinatorID,
    }

    // Submit to coordinator committee for vote
    return req, sdp.submitToGovernance(req)
}

// ProcessScrutinyDowngrade handles governance approval
func (sdp *ScrutinyDowngradeProcessor) ProcessScrutinyDowngrade(
    requestID [32]byte,
    coordinatorVotes []CoordinatorVote,
) error {
    req := sdp.getRequest(requestID)

    // Require 3-of-7 coordinator committee approval
    if len(coordinatorVotes) < 3 {
        return ErrInsufficientApprovalVotes{
            Required: 3,
            Actual:   len(coordinatorVotes),
        }
    }

    // Verify votes are valid
    for _, vote := range coordinatorVotes {
        if err := verifyCoordinatorVote(vote, req); err != nil {
            return fmt.Errorf("invalid vote from %x: %w", vote.CoordinatorID, err)
        }
    }

    // Apply downgrade
    if err := setNodeScrutinyLevel(req.NodeID, req.RequestedLevel); err != nil {
        return fmt.Errorf("failed to apply scrutiny level: %w", err)
    }

    // Record in audit trail
    auditEntry := &ScrutinyDowngradeAudit{
        RequestID:      requestID,
        NodeID:         req.NodeID,
        FromLevel:      req.CurrentLevel,
        ToLevel:        req.RequestedLevel,
        ApprovedBy:     extractCoordinatorIDs(coordinatorVotes),
        Justification:  req.Justification,
        ApprovedAt:     time.Now(),
    }
    sdp.recordAudit(auditEntry)

    return nil
}

// ScrutinyDowngradeAudit captures audit trail
type ScrutinyDowngradeAudit struct {
    RequestID     [32]byte
    NodeID        [32]byte
    FromLevel     ScrutinyLevel
    ToLevel       ScrutinyLevel
    ApprovedBy    [][32]byte  // Coordinator IDs
    Justification string
    ApprovedAt    time.Time
}

// Cooldown enforcement: 30 days between downgrade requests
const ScrutinyDowngradeCooldown = 30 * 24 * time.Hour

type ErrDowngradeCooldown struct {
    LastRequest  time.Time
    NextEligible time.Time
}

func (e ErrDowngradeCooldown) Error() string {
    return fmt.Sprintf("downgrade cooldown: last request %v, next eligible %v",
        e.LastRequest, e.NextEligible)
}
```

### Work-to-Trust Path for Unknown Manufacturers (FINAL DESIGN)

Untrusted nodes with legitimate hardware from unknown manufacturers can earn trust through sustained good behavior and governance approval.

```go
// UnknownManufacturerTrustPath manages trust upgrade for unknown TPM vendors
type UnknownManufacturerTrustPath struct {
    observations map[[32]byte]*ObservationPeriod
    proposals    map[string]*ManufacturerProposal
    mu           sync.RWMutex
}

// ObservationPeriod tracks node behavior during 180-day evaluation
type ObservationPeriod struct {
    NodeID              [32]byte
    ManufacturerOID     string
    StartedAt           time.Time
    EndsAt              time.Time
    ViolationCount      int
    WorkCompletionRate  float64
    UptimePercentage    float64
    Status              ObservationStatus
}

type ObservationStatus uint8

const (
    ObservationActive ObservationStatus = iota
    ObservationPassed
    ObservationFailed
)

// StartObservationPeriod begins 180-day evaluation for unknown manufacturer
func (umtp *UnknownManufacturerTrustPath) StartObservationPeriod(
    nodeID [32]byte,
    manufacturerOID string,
) (*ObservationPeriod, error) {
    umtp.mu.Lock()
    defer umtp.mu.Unlock()

    // Check if node is untrusted due to unknown manufacturer
    trustLevel, reason := getTrustLevel(nodeID)
    if trustLevel != TrustLevelUntrusted {
        return nil, ErrNodeAlreadyTrusted
    }
    if reason != "unknown_manufacturer" {
        return nil, ErrIneligibleForTrustPath{Reason: reason}
    }

    obs := &ObservationPeriod{
        NodeID:          nodeID,
        ManufacturerOID: manufacturerOID,
        StartedAt:       time.Now(),
        EndsAt:          time.Now().Add(180 * 24 * time.Hour),
        Status:          ObservationActive,
    }

    umtp.observations[nodeID] = obs
    return obs, nil
}

// CompleteObservationPeriod evaluates node after 180 days
func (umtp *UnknownManufacturerTrustPath) CompleteObservationPeriod(
    nodeID [32]byte,
) (*ObservationResult, error) {
    umtp.mu.Lock()
    defer umtp.mu.Unlock()

    obs, exists := umtp.observations[nodeID]
    if !exists {
        return nil, ErrObservationNotFound
    }

    if time.Now().Before(obs.EndsAt) {
        return nil, ErrObservationIncomplete{
            EndsAt: obs.EndsAt,
        }
    }

    // Evaluate clean record requirement
    if obs.ViolationCount > 0 {
        obs.Status = ObservationFailed
        return &ObservationResult{
            Passed: false,
            Reason: fmt.Sprintf("%d violations during observation", obs.ViolationCount),
        }, nil
    }

    obs.Status = ObservationPassed

    return &ObservationResult{
        Passed:             true,
        ManufacturerOID:    obs.ManufacturerOID,
        EligibleForProposal: true,
    }, nil
}

// ObservationResult captures evaluation outcome
type ObservationResult struct {
    Passed              bool
    Reason              string
    ManufacturerOID     string
    EligibleForProposal bool
}

// ProposeManufacturerWhitelist submits governance proposal to add manufacturer
func (umtp *UnknownManufacturerTrustPath) ProposeManufacturerWhitelist(
    manufacturerOID string,
    manufacturerCA []byte,
    successfulNodes [][32]byte,
) (*ManufacturerProposal, error) {
    proposal := &ManufacturerProposal{
        ProposalID:       generateProposalID(),
        ManufacturerOID:  manufacturerOID,
        ManufacturerCA:   manufacturerCA,
        ObservationNodes: successfulNodes,
        SubmittedAt:      time.Now(),
        RequiredVotes:    3,  // 3-of-7 coordinator committee
    }

    if err := umtp.submitToGovernance(proposal); err != nil {
        return nil, fmt.Errorf("governance submission failed: %w", err)
    }

    umtp.mu.Lock()
    umtp.proposals[manufacturerOID] = proposal
    umtp.mu.Unlock()

    return proposal, nil
}

// ManufacturerProposal represents governance proposal to whitelist TPM vendor
type ManufacturerProposal struct {
    ProposalID       [32]byte
    ManufacturerOID  string
    ManufacturerCA   []byte
    ObservationNodes [][32]byte
    SubmittedAt      time.Time
    RequiredVotes    int
    ApprovedAt       time.Time
    Approved         bool
}

// ApproveManufacturerWhitelist executes approved proposal
func (umtp *UnknownManufacturerTrustPath) ApproveManufacturerWhitelist(
    proposalID [32]byte,
    coordinatorVotes []CoordinatorVote,
) error {
    proposal := umtp.getProposal(proposalID)

    // Verify 3-of-7 approval
    if len(coordinatorVotes) < proposal.RequiredVotes {
        return ErrInsufficientApprovalVotes{
            Required: proposal.RequiredVotes,
            Actual:   len(coordinatorVotes),
        }
    }

    // Add manufacturer to Privacy CA whitelist
    if err := addManufacturerCA(proposal.ManufacturerOID, proposal.ManufacturerCA); err != nil {
        return fmt.Errorf("failed to add manufacturer CA: %w", err)
    }

    // Retroactively upgrade observation nodes to Trusted
    for _, nodeID := range proposal.ObservationNodes {
        if err := upgradeNodeTrustLevel(nodeID, TrustLevelTrusted); err != nil {
            return fmt.Errorf("failed to upgrade node %x: %w", nodeID, err)
        }
    }

    proposal.Approved = true
    proposal.ApprovedAt = time.Now()

    logManufacturerWhitelisting(proposal)

    return nil
}

// Observation period requirements
const (
    ObservationPeriodDays = 180
    RequiredCleanRecord   = true
)

type ErrIneligibleForTrustPath struct {
    Reason string
}

func (e ErrIneligibleForTrustPath) Error() string {
    return fmt.Sprintf("node ineligible for trust path: %s", e.Reason)
}

type ErrObservationIncomplete struct {
    EndsAt time.Time
}

func (e ErrObservationIncomplete) Error() string {
    return fmt.Sprintf("observation period incomplete, ends at %v", e.EndsAt)
}
```

---

## Penalty Matrix

Penalties are applied based on misbehavior type and occurrence count. The penalty system uses progressive escalation for repeated violations.

### Penalty Escalation by Misbehavior Type

| Misbehavior | 1st Offense | 2nd Offense | 3rd+ Offense |
|-------------|-------------|-------------|--------------|
| **Rate Limit Violation** | 1 hour cooldown | 24 hour cooldown | Permanent ban |
| **Malformed Request** | Warning | 1 hour cooldown | 24 hour cooldown |
| **Replay Attack** | 24 hour cooldown | 7 day ban | Permanent ban |
| **Protocol Violation** | Warning | 1 hour cooldown | 24 hour cooldown |
| **Sybil Pattern** | **Immediate permanent ban** | - | - |
| **DDoS Participation** | **Immediate permanent ban** | - | - |
| **Work Refusal** | Scrutiny escalation | 24 hour ban | Permanent ban |
| **False Reporting** | 24 hour cooldown | 7 day ban | Permanent ban |

### Penalty Implementation

```go
// PenaltyType defines the consequence categories
type PenaltyType uint8

const (
    PenaltyWarning PenaltyType = iota
    PenaltyCooldown
    PenaltyTemporaryBan
    PenaltyPermanentBan
    PenaltyScrutinyEscalation
)

// Penalty represents an applied consequence
type Penalty struct {
    PenaltyID     [32]byte
    NodeID        string
    Type          PenaltyType
    Duration      time.Duration    // 0 for permanent
    AppliedAt     time.Time
    ExpiresAt     time.Time        // Zero for permanent
    Reason        string
    MisbehaviorID [32]byte
}

// PenaltyMatrix defines escalation rules per misbehavior type
type PenaltyMatrix struct {
    rules map[MisbehaviorType][]PenaltyRule
}

type PenaltyRule struct {
    Occurrence   int
    Type         PenaltyType
    Duration     time.Duration
}

// DefaultPenaltyMatrix returns the canonical penalty escalation rules
func DefaultPenaltyMatrix() *PenaltyMatrix {
    return &PenaltyMatrix{
        rules: map[MisbehaviorType][]PenaltyRule{
            MisbehaviorRateLimitViolation: {
                {Occurrence: 1, Type: PenaltyCooldown, Duration: 1 * time.Hour},
                {Occurrence: 2, Type: PenaltyCooldown, Duration: 24 * time.Hour},
                {Occurrence: 3, Type: PenaltyPermanentBan, Duration: 0},
            },
            MisbehaviorMalformedRequest: {
                {Occurrence: 1, Type: PenaltyWarning, Duration: 0},
                {Occurrence: 2, Type: PenaltyCooldown, Duration: 1 * time.Hour},
                {Occurrence: 3, Type: PenaltyCooldown, Duration: 24 * time.Hour},
            },
            MisbehaviorReplayAttack: {
                {Occurrence: 1, Type: PenaltyCooldown, Duration: 24 * time.Hour},
                {Occurrence: 2, Type: PenaltyTemporaryBan, Duration: 7 * 24 * time.Hour},
                {Occurrence: 3, Type: PenaltyPermanentBan, Duration: 0},
            },
            MisbehaviorProtocolViolation: {
                {Occurrence: 1, Type: PenaltyWarning, Duration: 0},
                {Occurrence: 2, Type: PenaltyCooldown, Duration: 1 * time.Hour},
                {Occurrence: 3, Type: PenaltyCooldown, Duration: 24 * time.Hour},
            },
            MisbehaviorSybilPattern: {
                // Immediate permanent ban - no escalation
                {Occurrence: 1, Type: PenaltyPermanentBan, Duration: 0},
            },
            MisbehaviorDDoSParticipation: {
                // Immediate permanent ban - no escalation
                {Occurrence: 1, Type: PenaltyPermanentBan, Duration: 0},
            },
            MisbehaviorWorkRefusal: {
                {Occurrence: 1, Type: PenaltyScrutinyEscalation, Duration: 0},
                {Occurrence: 2, Type: PenaltyTemporaryBan, Duration: 24 * time.Hour},
                {Occurrence: 3, Type: PenaltyPermanentBan, Duration: 0},
            },
            MisbehaviorFalseReporting: {
                {Occurrence: 1, Type: PenaltyCooldown, Duration: 24 * time.Hour},
                {Occurrence: 2, Type: PenaltyTemporaryBan, Duration: 7 * 24 * time.Hour},
                {Occurrence: 3, Type: PenaltyPermanentBan, Duration: 0},
            },
        },
    }
}

// GetPenalty returns the appropriate penalty for a misbehavior occurrence
func (pm *PenaltyMatrix) GetPenalty(misbehavior MisbehaviorType, occurrenceCount int) *PenaltyRule {
    rules, exists := pm.rules[misbehavior]
    if !exists {
        return &PenaltyRule{Type: PenaltyWarning}
    }

    // Find the applicable rule based on occurrence count
    for i := len(rules) - 1; i >= 0; i-- {
        if occurrenceCount >= rules[i].Occurrence {
            return &rules[i]
        }
    }

    return &rules[0]
}

// ApplyPenalty enforces a penalty against a node
func (pe *PenaltyEnforcer) ApplyPenalty(nodeID string, misbehavior *MisbehaviorRecord) (*Penalty, error) {
    // Get occurrence count for this misbehavior type
    count := pe.getOccurrenceCount(nodeID, misbehavior.Type)
    count++

    // Determine penalty
    rule := pe.matrix.GetPenalty(misbehavior.Type, count)

    penalty := &Penalty{
        PenaltyID:     generatePenaltyID(),
        NodeID:        nodeID,
        Type:          rule.Type,
        Duration:      rule.Duration,
        AppliedAt:     time.Now(),
        Reason:        misbehavior.Description,
        MisbehaviorID: misbehavior.RecordID,
    }

    if rule.Duration > 0 {
        penalty.ExpiresAt = time.Now().Add(rule.Duration)
    }

    // Execute penalty
    switch rule.Type {
    case PenaltyWarning:
        pe.issueWarning(nodeID, penalty)
    case PenaltyCooldown:
        pe.applyCooldown(nodeID, penalty)
    case PenaltyTemporaryBan:
        pe.applyTemporaryBan(nodeID, penalty)
    case PenaltyPermanentBan:
        pe.applyPermanentBan(nodeID, penalty)
    case PenaltyScrutinyEscalation:
        pe.escalateScrutiny(nodeID)
    }

    // Record occurrence
    pe.recordOccurrence(nodeID, misbehavior.Type)

    return penalty, nil
}
```

### Atomic Scrutiny Level Transitions (P4-M20 Fix)

**CRITICAL SECURITY**: Scrutiny level changes MUST be atomic to prevent race conditions where a node briefly operates at a lower scrutiny level during transition.

**CONSTRAINT APPLICATION RULE**: All constraints MUST be applied INSIDE the mutex lock, NEVER outside. This ensures:
1. No window where old constraints apply with new level
2. No window where new level applies without constraints
3. Atomic visibility of both level AND constraints to all observers

```go
// pkg/defense/scrutiny_transition.go

// ScrutinyTransitionRequest represents a pending scrutiny level change
type ScrutinyTransitionRequest struct {
    NodeID      string
    FromLevel   ScrutinyLevel
    ToLevel     ScrutinyLevel
    Reason      string
    RequestedAt time.Time
}

// AtomicScrutinyManager handles atomic scrutiny level transitions
type AtomicScrutinyManager struct {
    mu        sync.Mutex
    levels    map[string]ScrutinyLevel          // nodeID -> current level
    pending   map[string]*ScrutinyTransitionRequest
}

// TransitionScrutinyLevel atomically changes a node's scrutiny level
// SECURITY: Uses compare-and-swap to ensure no intermediate states
func (asm *AtomicScrutinyManager) TransitionScrutinyLevel(
    nodeID string,
    expectedCurrent ScrutinyLevel,
    newLevel ScrutinyLevel,
    reason string,
) error {
    asm.mu.Lock()
    defer asm.mu.Unlock()

    // Verify current state matches expected
    currentLevel, exists := asm.levels[nodeID]
    if !exists {
        return ErrNodeNotFound
    }

    if currentLevel != expectedCurrent {
        return &ErrScrutinyLevelMismatch{
            Expected: expectedCurrent,
            Actual:   currentLevel,
        }
    }

    // Validate transition is allowed
    if !isValidTransition(currentLevel, newLevel) {
        return &ErrInvalidScrutinyTransition{
            From: currentLevel,
            To:   newLevel,
        }
    }

    // ATOMIC: All changes happen within the lock
    // 1. Update level
    asm.levels[nodeID] = newLevel

    // 2. Apply new constraints immediately (within lock)
    applyScrutinyConstraints(nodeID, newLevel)

    // 3. Log transition for audit
    logScrutinyTransition(nodeID, currentLevel, newLevel, reason)

    return nil
}

// isValidTransition defines allowed scrutiny level state machine
func isValidTransition(from, to ScrutinyLevel) bool {
    validTransitions := map[ScrutinyLevel][]ScrutinyLevel{
        ScrutinyMinimal:  {ScrutinyStandard, ScrutinyMaximum},  // Can escalate
        ScrutinyStandard: {ScrutinyMinimal, ScrutinyElevated, ScrutinyMaximum}, // Can de-escalate or escalate
        ScrutinyElevated: {ScrutinyMaximum},                    // Can only escalate (untrusted)
        ScrutinyMaximum:  {},                                   // Cannot de-escalate without manual review
    }

    allowed, exists := validTransitions[from]
    if !exists {
        return false
    }

    for _, valid := range allowed {
        if valid == to {
            return true
        }
    }
    return false
}

// applyScrutinyConstraints applies all constraints for a scrutiny level atomically
// SECURITY FIX (P5-H1): All constraint changes MUST happen within the same lock
// to prevent partial application creating a race window
func applyScrutinyConstraints(nodeID string, level ScrutinyLevel) {
    constraints := ScrutinyConstraints[level]

    // ATOMIC: All constraints applied in single operation
    // The caller MUST hold the scrutiny lock when calling this function
    nodeState := getNodeState(nodeID)

    // Apply rate limit multiplier
    nodeState.RateMultiplier.Store(uint64(constraints.RateMultiplier * 1000)) // Store as fixed-point

    // Apply PoW requirement
    nodeState.PoWRequired.Store(constraints.PoWRequired)

    // Apply work contribution requirement
    nodeState.WorkContribution.Store(uint32(constraints.WorkContribution))

    // Apply monitoring interval
    nodeState.MonitoringInterval.Store(int64(constraints.MonitoringInterval))

    // Apply quarantine flag
    nodeState.QuarantineOnFlag.Store(constraints.QuarantineOnFlag)

    // Emit constraint change event for audit
    emitConstraintChangeEvent(nodeID, level, constraints)
}

// logScrutinyTransition logs a scrutiny level change for audit trail
func logScrutinyTransition(nodeID string, from, to ScrutinyLevel, reason string) {
    auditLog := &ScrutinyTransitionLog{
        NodeID:     nodeID,
        FromLevel:  from,
        ToLevel:    to,
        Reason:     reason,
        Timestamp:  time.Now(),
    }
    persistScrutinyAuditLog(auditLog)
}

type ScrutinyTransitionLog struct {
    NodeID    string
    FromLevel ScrutinyLevel
    ToLevel   ScrutinyLevel
    Reason    string
    Timestamp time.Time
}

var (
    ErrNodeNotFound             = errors.New("node not found in scrutiny registry")
    ErrInvalidScrutinyTransition = errors.New("invalid scrutiny level transition")
)

type ErrScrutinyLevelMismatch struct {
    Expected, Actual ScrutinyLevel
}

func (e *ErrScrutinyLevelMismatch) Error() string {
    return fmt.Sprintf("scrutiny level mismatch: expected %d, got %d", e.Expected, e.Actual)
}
```

### Saturating Misbehavior Counters (P4-M21 Fix)

**CRITICAL SECURITY**: Misbehavior counters MUST use saturating arithmetic to prevent overflow attacks where counters wrap around to zero, effectively resetting penalties.

**Counter Reset Mechanism**: After 30 consecutive days of clean behavior (no violations), counters MAY be reduced (not zeroed) to allow rehabilitation while maintaining audit history.

**Memory Exhaustion Prevention**: Old penalty records MUST be pruned to prevent unbounded memory growth from persistent bad actors.

```go
// pkg/defense/misbehavior_counter.go

// MaxOccurrenceCount defines the maximum occurrence count to prevent overflow
// At max value, the counter saturates (stays at max) instead of wrapping
const MaxOccurrenceCount = math.MaxUint32 // 4,294,967,295 occurrences

// OccurrenceTracker tracks misbehavior occurrences with overflow protection
type OccurrenceTracker struct {
    mu         sync.RWMutex
    counts     map[string]map[MisbehaviorType]uint32 // nodeID -> type -> count
    timestamps map[string]map[MisbehaviorType]time.Time // Last occurrence time
}

// IncrementOccurrence safely increments the occurrence count with saturation
// SECURITY: Prevents counter overflow attacks
func (ot *OccurrenceTracker) IncrementOccurrence(nodeID string, misbehavior MisbehaviorType) uint32 {
    ot.mu.Lock()
    defer ot.mu.Unlock()

    if ot.counts[nodeID] == nil {
        ot.counts[nodeID] = make(map[MisbehaviorType]uint32)
        ot.timestamps[nodeID] = make(map[MisbehaviorType]time.Time)
    }

    current := ot.counts[nodeID][misbehavior]

    // SATURATING ARITHMETIC: Do not wrap around
    if current < MaxOccurrenceCount {
        ot.counts[nodeID][misbehavior] = current + 1
    }
    // If already at max, stays at max (saturated)

    ot.timestamps[nodeID][misbehavior] = time.Now()

    return ot.counts[nodeID][misbehavior]
}

// GetOccurrenceCount returns the current occurrence count
func (ot *OccurrenceTracker) GetOccurrenceCount(nodeID string, misbehavior MisbehaviorType) uint32 {
    ot.mu.RLock()
    defer ot.mu.RUnlock()

    if ot.counts[nodeID] == nil {
        return 0
    }
    return ot.counts[nodeID][misbehavior]
}

// IsSaturated returns true if the counter has hit the maximum
// A saturated counter indicates a persistent bad actor
func (ot *OccurrenceTracker) IsSaturated(nodeID string, misbehavior MisbehaviorType) bool {
    return ot.GetOccurrenceCount(nodeID, misbehavior) >= MaxOccurrenceCount
}

// SECURITY FIX (P5-M2): Counter reset mechanism after sustained good behavior
// Allows nodes to recover from past misbehavior through demonstrated reliability
//
// RESET REQUIREMENTS (30-Day Clean Period):
// 1. Node must have ZERO violations for 30 consecutive days
// 2. Node must have completed at least 90% of work quota during this period
// 3. Reset reduces counter by ResetFraction, does NOT zero it (maintains history)
// 4. Maximum reduction per period prevents rapid rehabilitation gaming

// ResetConfig defines when and how counters can be reset
type ResetConfig struct {
    MinGoodBehaviorDays  int      // Minimum days of good behavior (REQUIRED: 30)
    ResetFraction        float64  // Fraction to reduce by (default: 0.5 = halve)
    ResetInterval        time.Duration // How often to check for resets (default: 24h)
    MaxResetPerPeriod    uint32   // Max reduction per period (default: 10)
    RequireWorkComplete  bool     // Require work quota completion (default: true)
}

// DefaultResetConfig - 30 days clean before any counter reduction
var DefaultResetConfig = ResetConfig{
    MinGoodBehaviorDays:  30,           // MANDATORY: 30 days clean behavior
    ResetFraction:        0.5,          // Halve the counter, don't zero it
    ResetInterval:        24 * time.Hour,
    MaxResetPerPeriod:    10,           // Prevent gaming via rapid resets
    RequireWorkComplete:  true,          // Must complete work quota too
}

// AttemptReset tries to reduce misbehavior counters for nodes showing good behavior
// SECURITY: Only reduces counters, never fully clears (permanent audit trail)
func (ot *OccurrenceTracker) AttemptReset(
    nodeID string,
    misbehavior MisbehaviorType,
    config *ResetConfig,
    behaviorRecord *GoodBehaviorRecord,
) (uint32, error) {
    ot.mu.Lock()
    defer ot.mu.Unlock()

    if ot.counts[nodeID] == nil {
        return 0, nil // Nothing to reset
    }

    current := ot.counts[nodeID][misbehavior]
    if current == 0 {
        return 0, nil // Already at zero
    }

    // Verify good behavior requirements
    if err := validateGoodBehavior(behaviorRecord, config); err != nil {
        return current, err
    }

    // Calculate reduction (cannot exceed MaxResetPerPeriod)
    reduction := uint32(float64(current) * config.ResetFraction)
    if reduction > config.MaxResetPerPeriod {
        reduction = config.MaxResetPerPeriod
    }
    if reduction == 0 && current > 0 {
        reduction = 1 // Minimum reduction of 1
    }

    // Apply reduction (never go below 0)
    if reduction > current {
        reduction = current
    }
    newCount := current - reduction

    ot.counts[nodeID][misbehavior] = newCount

    log.Info("misbehavior counter reset applied",
        "nodeID", nodeID,
        "misbehavior", misbehavior,
        "previous", current,
        "reduction", reduction,
        "new", newCount)

    return newCount, nil
}

// GoodBehaviorRecord tracks sustained positive behavior
type GoodBehaviorRecord struct {
    NodeID               string
    DaysWithoutIncident  int
    WorkQuotaCompletion  float64  // 0.0-1.0
    PositiveContributions int
    LastIncidentAt       time.Time
}

// validateGoodBehavior checks if node qualifies for counter reduction
func validateGoodBehavior(record *GoodBehaviorRecord, config *ResetConfig) error {
    if record.DaysWithoutIncident < config.MinGoodBehaviorDays {
        return ErrInsufficientGoodBehavior{
            Required: config.MinGoodBehaviorDays,
            Actual:   record.DaysWithoutIncident,
        }
    }

    if config.RequireWorkComplete && record.WorkQuotaCompletion < 0.9 {
        return ErrWorkQuotaNotMet{
            Required: 0.9,
            Actual:   record.WorkQuotaCompletion,
        }
    }

    return nil
}

// ErrInsufficientGoodBehavior indicates not enough good behavior for reset
type ErrInsufficientGoodBehavior struct {
    Required, Actual int
}

func (e ErrInsufficientGoodBehavior) Error() string {
    return fmt.Sprintf("insufficient good behavior: %d days required, %d days observed",
        e.Required, e.Actual)
}

// ErrWorkQuotaNotMet indicates work quota requirements not met
type ErrWorkQuotaNotMet struct {
    Required, Actual float64
}

func (e ErrWorkQuotaNotMet) Error() string {
    return fmt.Sprintf("work quota not met: %.1f%% required, %.1f%% completed",
        e.Required*100, e.Actual*100)
}
```

### Penalty History Pruning (P4-M22 Fix)

**CRITICAL SECURITY**: Penalty history MUST be bounded to prevent memory exhaustion attacks where an attacker causes unlimited penalty records to accumulate.

**MEMORY BUDGET ANALYSIS**:
- MaxTotalPenaltyRecords = 10M records
- Estimated record size = ~1KB (including all fields)
- Maximum memory usage = 10GB at full capacity
- Target operational memory = 8.5GB (85% threshold)

**PRUNING REQUIREMENTS**:
1. **Per-Node Limit**: Maximum 1000 penalty records per node (oldest evicted first)
2. **Global Limit**: Maximum 10M total records across all nodes
3. **Retention Period**: 90 days - older records are automatically pruned
4. **Cleanup Trigger**: When at 85% capacity (8.5M records), proactive cleanup begins
5. **Eviction Batch Size**: Remove oldest 5% (500K records) per cleanup cycle
6. **Cleanup Interval**: Background worker runs every hour
7. **Async Cleanup**: Cleanup runs in background goroutine, may temporarily exceed limit by up to 5%
8. **Audit Preservation**: Penalty records older than 90 days but involved in active disputes are preserved until dispute resolution

```go
// pkg/defense/penalty_history.go

// Penalty History Limits (non-configurable security parameters)
const (
    MaxPenaltyHistoryPerNode = 1000                       // Max penalties tracked per node
    PenaltyHistoryRetention  = 90 * 24 * time.Hour        // 90 days retention
    PruneInterval            = 1 * time.Hour              // Run pruning every hour
    MaxTotalPenaltyRecords   = 10_000_000                 // Global limit (10M records)

    // C4 FIX: Comprehensive memory management parameters
    PenaltyCleanupTrigger    = 0.85                       // Trigger cleanup at 85% capacity = 8.5M records
    PenaltyEvictionBatchSize = 0.05                       // Evict oldest 5% = 500K records per cycle
    PenaltyMaxOverage        = 0.05                       // Allow temporary 5% overage during async cleanup
)

// PenaltyHistoryManager manages bounded penalty record storage
// SECURITY: This manager ensures penalty history cannot be used as a memory exhaustion vector
type PenaltyHistoryManager struct {
    mu              sync.RWMutex
    history         map[string][]*PenaltyRecord    // nodeID -> penalties (bounded)
    totalRecords    int64
    lastPrune       time.Time
    disputeRegistry *DisputeRegistry              // Reference to active disputes for audit preservation
    cleanupRunning  atomic.Bool                    // Prevents concurrent cleanup operations
}

// PenaltyRecord is a single penalty entry
type PenaltyRecord struct {
    PenaltyID   [32]byte
    Type        PenaltyType
    AppliedAt   time.Time
    ExpiresAt   time.Time
    Reason      string
    Misbehavior MisbehaviorType
    DisputeID   [32]byte        // Non-zero if part of active dispute (audit preservation)
}

// RecordPenalty adds a penalty to history with automatic pruning
func (phm *PenaltyHistoryManager) RecordPenalty(nodeID string, penalty *PenaltyRecord) error {
    phm.mu.Lock()
    defer phm.mu.Unlock()

    // Check global limit with cleanup trigger
    currentRecords := atomic.LoadInt64(&phm.totalRecords)
    cleanupThreshold := int64(float64(MaxTotalPenaltyRecords) * PenaltyCleanupTrigger)

    if currentRecords >= cleanupThreshold {
        // Trigger async cleanup if not already running
        if phm.cleanupRunning.CompareAndSwap(false, true) {
            go phm.asyncCleanup()
        }
    }

    // Hard limit check - block if we exceed max + overage allowance
    maxWithOverage := int64(float64(MaxTotalPenaltyRecords) * (1.0 + PenaltyMaxOverage))
    if currentRecords >= maxWithOverage {
        // Force synchronous pruning
        phm.pruneOldestRecords(int64(float64(MaxTotalPenaltyRecords) * PenaltyEvictionBatchSize))
    }

    // Initialize node history if needed
    if phm.history[nodeID] == nil {
        phm.history[nodeID] = make([]*PenaltyRecord, 0, 100)
    }

    // Check per-node limit
    if len(phm.history[nodeID]) >= MaxPenaltyHistoryPerNode {
        // Remove oldest record for this node (unless involved in dispute)
        phm.evictOldestNonDisputedRecord(nodeID)
    }

    // Add new record
    phm.history[nodeID] = append(phm.history[nodeID], penalty)
    atomic.AddInt64(&phm.totalRecords, 1)

    return nil
}

// evictOldestNonDisputedRecord removes oldest record not involved in active dispute
// AUDIT PRESERVATION: Records involved in disputes are preserved until resolution
func (phm *PenaltyHistoryManager) evictOldestNonDisputedRecord(nodeID string) {
    records := phm.history[nodeID]
    for i := 0; i < len(records); i++ {
        // Check if record is involved in active dispute
        if records[i].DisputeID == [32]byte{} || !phm.disputeRegistry.IsActiveDispute(records[i].DisputeID) {
            // Safe to evict - not in active dispute
            phm.history[nodeID] = append(records[:i], records[i+1:]...)
            atomic.AddInt64(&phm.totalRecords, -1)
            return
        }
    }
    // All records are in disputes - force evict oldest anyway (dispute takes precedence for audit)
    // This should be rare - log a warning
    log.Warn("All penalty records for node are in active disputes, cannot evict",
        "nodeID", nodeID, "recordCount", len(records))
}

// asyncCleanup runs cleanup in background goroutine
// ASYNC BEHAVIOR: May temporarily exceed limit by up to 5% during cleanup
func (phm *PenaltyHistoryManager) asyncCleanup() {
    defer phm.cleanupRunning.Store(false)

    // Calculate eviction target
    evictionCount := int64(float64(MaxTotalPenaltyRecords) * PenaltyEvictionBatchSize)

    log.Info("Starting async penalty history cleanup",
        "currentRecords", atomic.LoadInt64(&phm.totalRecords),
        "evictionTarget", evictionCount)

    // First pass: prune expired records (respects audit preservation)
    expiredPruned := phm.PruneExpiredRecords()

    // If we're still above threshold, evict oldest records
    currentRecords := atomic.LoadInt64(&phm.totalRecords)
    cleanupThreshold := int64(float64(MaxTotalPenaltyRecords) * PenaltyCleanupTrigger)

    if currentRecords > cleanupThreshold {
        remaining := currentRecords - cleanupThreshold
        phm.mu.Lock()
        phm.pruneOldestRecords(remaining)
        phm.mu.Unlock()
    }

    log.Info("Completed async penalty history cleanup",
        "expiredPruned", expiredPruned,
        "finalRecords", atomic.LoadInt64(&phm.totalRecords))
}

// PruneExpiredRecords removes penalty records older than retention period
// AUDIT PRESERVATION: Records involved in active disputes are preserved regardless of age
func (phm *PenaltyHistoryManager) PruneExpiredRecords() int {
    phm.mu.Lock()
    defer phm.mu.Unlock()

    cutoff := time.Now().Add(-PenaltyHistoryRetention)
    totalPruned := 0

    for nodeID, penalties := range phm.history {
        newPenalties := make([]*PenaltyRecord, 0, len(penalties))
        for _, p := range penalties {
            // Keep if: not expired OR involved in active dispute
            keepForAge := p.AppliedAt.After(cutoff)
            keepForDispute := p.DisputeID != [32]byte{} && phm.disputeRegistry.IsActiveDispute(p.DisputeID)

            if keepForAge || keepForDispute {
                newPenalties = append(newPenalties, p)
            } else {
                totalPruned++
            }
        }

        if len(newPenalties) == 0 {
            delete(phm.history, nodeID)
        } else {
            phm.history[nodeID] = newPenalties
        }
    }

    atomic.AddInt64(&phm.totalRecords, -int64(totalPruned))
    phm.lastPrune = time.Now()

    return totalPruned
}

// pruneOldestRecords removes N oldest records globally (for emergency pruning)
// AUDIT PRESERVATION: Skips records involved in active disputes
func (phm *PenaltyHistoryManager) pruneOldestRecords(count int64) {
    // Collect all records with timestamps
    type recordRef struct {
        nodeID      string
        index       int
        appliedAt   time.Time
        inDispute   bool
    }

    var allRecords []recordRef
    for nodeID, penalties := range phm.history {
        for i, p := range penalties {
            inDispute := p.DisputeID != [32]byte{} && phm.disputeRegistry.IsActiveDispute(p.DisputeID)
            allRecords = append(allRecords, recordRef{nodeID, i, p.AppliedAt, inDispute})
        }
    }

    // Sort by time (oldest first), but put disputed records last
    sort.Slice(allRecords, func(i, j int) bool {
        // Non-disputed records come first (can be evicted)
        if allRecords[i].inDispute != allRecords[j].inDispute {
            return !allRecords[i].inDispute
        }
        return allRecords[i].appliedAt.Before(allRecords[j].appliedAt)
    })

    // Mark oldest non-disputed for removal
    toRemove := make(map[string]map[int]bool)
    removed := int64(0)
    for i := 0; removed < count && i < len(allRecords); i++ {
        ref := allRecords[i]
        if ref.inDispute {
            // Skip disputed records - they're protected
            continue
        }
        if toRemove[ref.nodeID] == nil {
            toRemove[ref.nodeID] = make(map[int]bool)
        }
        toRemove[ref.nodeID][ref.index] = true
        removed++
    }

    // Remove marked records
    for nodeID, indices := range toRemove {
        newPenalties := make([]*PenaltyRecord, 0)
        for i, p := range phm.history[nodeID] {
            if !indices[i] {
                newPenalties = append(newPenalties, p)
            }
        }
        if len(newPenalties) == 0 {
            delete(phm.history, nodeID)
        } else {
            phm.history[nodeID] = newPenalties
        }
    }

    atomic.AddInt64(&phm.totalRecords, -removed)
}

// StartPruningWorker starts background pruning goroutine
func (phm *PenaltyHistoryManager) StartPruningWorker(ctx context.Context) {
    ticker := time.NewTicker(PruneInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            pruned := phm.PruneExpiredRecords()
            currentRecords := atomic.LoadInt64(&phm.totalRecords)

            if pruned > 0 {
                log.Debug("Pruned penalty history",
                    "count", pruned,
                    "remaining", currentRecords)
            }

            // Check if we need proactive cleanup
            cleanupThreshold := int64(float64(MaxTotalPenaltyRecords) * PenaltyCleanupTrigger)
            if currentRecords >= cleanupThreshold {
                if phm.cleanupRunning.CompareAndSwap(false, true) {
                    go phm.asyncCleanup()
                }
            }
        }
    }
}

// GetMemoryStats returns current memory usage statistics
func (phm *PenaltyHistoryManager) GetMemoryStats() *PenaltyHistoryStats {
    phm.mu.RLock()
    defer phm.mu.RUnlock()

    totalRecords := atomic.LoadInt64(&phm.totalRecords)
    return &PenaltyHistoryStats{
        TotalRecords:     totalRecords,
        MaxRecords:       MaxTotalPenaltyRecords,
        CapacityPercent:  float64(totalRecords) / float64(MaxTotalPenaltyRecords) * 100,
        UniqueNodes:      len(phm.history),
        LastPrune:        phm.lastPrune,
        CleanupRunning:   phm.cleanupRunning.Load(),
    }
}

// PenaltyHistoryStats provides memory usage information
type PenaltyHistoryStats struct {
    TotalRecords     int64
    MaxRecords       int64
    CapacityPercent  float64
    UniqueNodes      int
    LastPrune        time.Time
    CleanupRunning   bool
}

// DisputeRegistry interface for checking active disputes
// Required for audit preservation during pruning
type DisputeRegistry interface {
    IsActiveDispute(disputeID [32]byte) bool
}
```

---

## Untrusted Node Capabilities

### What Untrusted Nodes CAN Do

Untrusted nodes maintain limited but meaningful participation in the network:

| Operation | Allowed | Conditions |
|-----------|---------|------------|
| **Route DHT Messages** | Yes | Subject to rate limits |
| **Store DHT Data** | Yes | Limited storage quota |
| **Retrieve DHT Data** | Yes | Subject to PoW and rate limits |
| **Use Network Services** | Yes | With elevated scrutiny restrictions |
| **Participate in DDoS Protection Work** | Yes | Required for network access |
| **Forward Transactions** | Yes | Cannot validate or sign |
| **Maintain Routing Table** | Yes | Standard Kademlia operations |

### What Untrusted Nodes CANNOT Do

Critical operations are restricted to prevent network compromise:

| Operation | Allowed | Reason |
|-----------|---------|--------|
| **Earn Reputation** | No | Cannot demonstrate hardware trust root |
| **Be Promoted to Hub** | No | Requires reputation >= 0.80 |
| **Be Promoted to Gateway** | No | Requires reputation >= 0.85 |
| **Be Promoted to Coordinator** | No | Requires reputation >= 0.95 |
| **Participate as CA Pool Member** | No | Requires reputation >= 0.90 |
| **Participate in Consensus Voting** | No | Requires trusted status |
| **Issue or Sign Certificates** | No | Requires CA pool membership |
| **Hold Escrow Funds** | No | Requires reputation >= 0.50 |
| **Validate Transactions** | No | Requires trusted status |
| **Participate in FROST DKG** | No | Requires CA eligibility |

### Capability Implementation

```go
// UntrustedCapabilities defines allowed operations for untrusted nodes
type UntrustedCapabilities struct {
    // Allowed operations
    CanRouteDHT           bool
    CanStoreDHT           bool
    CanRetrieveDHT        bool
    CanForwardTransactions bool
    CanPerformWork        bool

    // Restricted operations
    CanEarnReputation     bool  // Always false
    CanBeHub              bool  // Always false
    CanBeGateway          bool  // Always false
    CanBeCoordinator      bool  // Always false
    CanBeCAParticipant    bool  // Always false
    CanVoteConsensus      bool  // Always false
    CanIssueCertificates  bool  // Always false
    CanHoldEscrow         bool  // Always false
    CanValidateTransactions bool // Always false

    // Resource limits
    MaxStorageBytes       uint64
    MaxBandwidthBps       uint64
    MaxRequestsPerSecond  float64
}

// DefaultUntrustedCapabilities returns the canonical capability set
func DefaultUntrustedCapabilities() *UntrustedCapabilities {
    return &UntrustedCapabilities{
        // Allowed
        CanRouteDHT:            true,
        CanStoreDHT:            true,
        CanRetrieveDHT:         true,
        CanForwardTransactions: true,
        CanPerformWork:         true,

        // Restricted (all false)
        CanEarnReputation:       false,
        CanBeHub:                false,
        CanBeGateway:            false,
        CanBeCoordinator:        false,
        CanBeCAParticipant:      false,
        CanVoteConsensus:        false,
        CanIssueCertificates:    false,
        CanHoldEscrow:           false,
        CanValidateTransactions: false,

        // Resource limits
        MaxStorageBytes:      1 * 1024 * 1024 * 1024,  // 1 GB
        MaxBandwidthBps:      10 * 1000 * 1000,        // 10 Mbps
        MaxRequestsPerSecond: 50,                       // 50 req/s
    }
}

// CheckCapability validates if an operation is allowed
func (uc *UntrustedCapabilities) CheckCapability(operation string) error {
    switch operation {
    case "route_dht":
        if !uc.CanRouteDHT {
            return ErrOperationNotAllowed
        }
    case "earn_reputation":
        return ErrReputationEarningDisabled
    case "ca_participate":
        return ErrCAParticipationDisabled
    case "vote_consensus":
        return ErrConsensusVotingDisabled
    // ... additional operation checks
    }
    return nil
}

// SECURITY FIX (P5-M1): API Gateway capability enforcement
// All API requests from untrusted nodes MUST pass through this middleware
//
// CAPABILITY ENFORCEMENT REQUIREMENTS:
// 1. API gateway middleware validates capabilities BEFORE execution
// 2. Capability certificate MUST be verified before allowing operation
// 3. No operation proceeds without explicit capability check
// 4. Failed capability checks result in immediate request rejection
// 5. All capability violations are logged for audit

// CapabilityEnforcementMiddleware enforces capability restrictions at API gateway
// CRITICAL: This middleware MUST be applied to ALL API endpoints
type CapabilityEnforcementMiddleware struct {
    nodeRegistry    *NodeRegistry
    capabilityCache sync.Map  // Cache of node capabilities for performance
    cacheTTL        time.Duration
    metrics         *CapabilityMetrics
    certVerifier    *CapabilityCertVerifier  // Verifies capability certificates
}

type CapabilityMetrics struct {
    AllowedRequests   uint64  // Atomic
    DeniedRequests    uint64  // Atomic
    CacheHits         uint64  // Atomic
    CacheMisses       uint64  // Atomic
}

// CapabilityCertVerifier verifies capability certificates before allowing operations
type CapabilityCertVerifier struct {
    trustedCAs      []*x509.Certificate  // CA certs that can issue capability certs
    revokedCerts    sync.Map             // Set of revoked certificate serial numbers
}

// VerifyCapabilityCert validates a capability certificate
// SECURITY: This MUST be called before any privileged operation
func (v *CapabilityCertVerifier) VerifyCapabilityCert(cert *x509.Certificate, operation string) error {
    // Step 1: Verify certificate chain to trusted CA
    roots := x509.NewCertPool()
    for _, ca := range v.trustedCAs {
        roots.AddCert(ca)
    }
    opts := x509.VerifyOptions{Roots: roots}
    if _, err := cert.Verify(opts); err != nil {
        return &ErrCapabilityCertInvalid{
            Operation: operation,
            Reason:    "certificate chain verification failed",
            Inner:     err,
        }
    }

    // Step 2: Check revocation status
    serialNum := cert.SerialNumber.String()
    if _, revoked := v.revokedCerts.Load(serialNum); revoked {
        return &ErrCapabilityCertRevoked{
            Operation:    operation,
            SerialNumber: serialNum,
        }
    }

    // Step 3: Check certificate is not expired
    now := time.Now()
    if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
        return &ErrCapabilityCertExpired{
            Operation: operation,
            NotBefore: cert.NotBefore,
            NotAfter:  cert.NotAfter,
        }
    }

    // Step 4: Verify operation is in certificate's allowed operations
    // (Capability certs use custom extension to list allowed operations)
    allowedOps := extractAllowedOperations(cert)
    if !containsOperation(allowedOps, operation) {
        return &ErrCapabilityNotGranted{
            Operation:   operation,
            AllowedOps:  allowedOps,
        }
    }

    return nil
}

// ErrCapabilityCertInvalid indicates certificate verification failed
type ErrCapabilityCertInvalid struct {
    Operation string
    Reason    string
    Inner     error
}
func (e *ErrCapabilityCertInvalid) Error() string {
    return fmt.Sprintf("capability cert invalid for %s: %s", e.Operation, e.Reason)
}

// ErrCapabilityCertRevoked indicates certificate has been revoked
type ErrCapabilityCertRevoked struct {
    Operation    string
    SerialNumber string
}
func (e *ErrCapabilityCertRevoked) Error() string {
    return fmt.Sprintf("capability cert revoked for %s (serial: %s)", e.Operation, e.SerialNumber)
}

// ErrCapabilityCertExpired indicates certificate is expired or not yet valid
type ErrCapabilityCertExpired struct {
    Operation string
    NotBefore time.Time
    NotAfter  time.Time
}
func (e *ErrCapabilityCertExpired) Error() string {
    return fmt.Sprintf("capability cert expired for %s (valid: %v to %v)",
        e.Operation, e.NotBefore, e.NotAfter)
}

// ErrCapabilityNotGranted indicates operation not in certificate's allowed list
type ErrCapabilityNotGranted struct {
    Operation  string
    AllowedOps []string
}
func (e *ErrCapabilityNotGranted) Error() string {
    return fmt.Sprintf("capability not granted for %s (allowed: %v)", e.Operation, e.AllowedOps)
}

// NewCapabilityEnforcementMiddleware creates the API gateway middleware
func NewCapabilityEnforcementMiddleware(registry *NodeRegistry, certVerifier *CapabilityCertVerifier) *CapabilityEnforcementMiddleware {
    return &CapabilityEnforcementMiddleware{
        nodeRegistry: registry,
        cacheTTL:     5 * time.Minute,
        metrics:      &CapabilityMetrics{},
        certVerifier: certVerifier,
    }
}

// Enforce checks if the requesting node has capability for the operation
// MUST be called for every API request before processing
// SECURITY: This is the gateway enforcement point - NO bypasses allowed
func (m *CapabilityEnforcementMiddleware) Enforce(
    ctx context.Context,
    nodeID [32]byte,
    operation string,
) error {
    // Get node capabilities (from cache or registry)
    caps, err := m.getCapabilities(nodeID)
    if err != nil {
        atomic.AddUint64(&m.metrics.DeniedRequests, 1)
        return ErrCapabilityLookupFailed{NodeID: nodeID, Cause: err}
    }

    // Check if operation is allowed by capability rules
    if err := caps.CheckCapability(operation); err != nil {
        atomic.AddUint64(&m.metrics.DeniedRequests, 1)
        log.Warn("capability enforcement denied request",
            "nodeID", nodeID,
            "operation", operation,
            "error", err)
        return err
    }

    atomic.AddUint64(&m.metrics.AllowedRequests, 1)
    return nil
}

// EnforceWithCert checks capability AND verifies the capability certificate
// SECURITY: For privileged operations, BOTH capability check AND cert verification required
func (m *CapabilityEnforcementMiddleware) EnforceWithCert(
    ctx context.Context,
    nodeID [32]byte,
    operation string,
    capabilityCert *x509.Certificate,
) error {
    // Step 1: Standard capability enforcement
    if err := m.Enforce(ctx, nodeID, operation); err != nil {
        return err
    }

    // Step 2: Verify capability certificate before allowing operation
    // SECURITY: Capability cert MUST be verified - this proves the node was granted
    // this specific capability by a trusted CA
    if capabilityCert == nil {
        atomic.AddUint64(&m.metrics.DeniedRequests, 1)
        return &ErrCapabilityCertRequired{
            NodeID:    nodeID,
            Operation: operation,
        }
    }

    if err := m.certVerifier.VerifyCapabilityCert(capabilityCert, operation); err != nil {
        atomic.AddUint64(&m.metrics.DeniedRequests, 1)
        log.Warn("capability cert verification failed",
            "nodeID", nodeID,
            "operation", operation,
            "error", err)
        return err
    }

    // Step 3: Verify certificate subject matches requesting node
    // Prevents using someone else's capability certificate
    certNodeID := extractNodeIDFromCert(capabilityCert)
    if certNodeID != nodeID {
        atomic.AddUint64(&m.metrics.DeniedRequests, 1)
        return &ErrCapabilityCertMismatch{
            Operation:    operation,
            RequestingID: nodeID,
            CertNodeID:   certNodeID,
        }
    }

    atomic.AddUint64(&m.metrics.AllowedRequests, 1)
    return nil
}

// ErrCapabilityCertRequired indicates a capability cert is required but not provided
type ErrCapabilityCertRequired struct {
    NodeID    [32]byte
    Operation string
}
func (e *ErrCapabilityCertRequired) Error() string {
    return fmt.Sprintf("capability certificate required for operation %s (node: %x)",
        e.Operation, e.NodeID[:8])
}

// ErrCapabilityCertMismatch indicates the cert doesn't belong to the requesting node
type ErrCapabilityCertMismatch struct {
    Operation    string
    RequestingID [32]byte
    CertNodeID   [32]byte
}
func (e *ErrCapabilityCertMismatch) Error() string {
    return fmt.Sprintf("capability cert mismatch for %s: requesting=%x, cert=%x",
        e.Operation, e.RequestingID[:8], e.CertNodeID[:8])
}

// getCapabilities retrieves capabilities from cache or registry
func (m *CapabilityEnforcementMiddleware) getCapabilities(nodeID [32]byte) (*UntrustedCapabilities, error) {
    // Check cache first
    if cached, ok := m.capabilityCache.Load(nodeID); ok {
        entry := cached.(*cachedCapability)
        if time.Since(entry.cachedAt) < m.cacheTTL {
            atomic.AddUint64(&m.metrics.CacheHits, 1)
            return entry.caps, nil
        }
        // Expired, delete from cache
        m.capabilityCache.Delete(nodeID)
    }

    atomic.AddUint64(&m.metrics.CacheMisses, 1)

    // Get fresh capabilities from registry
    node, err := m.nodeRegistry.GetNode(nodeID)
    if err != nil {
        return nil, err
    }

    var caps *UntrustedCapabilities
    if node.TrustLevel == TrustLevelUntrusted {
        caps = DefaultUntrustedCapabilities()
    } else {
        // Trusted nodes have full capabilities (nil = no restrictions)
        return nil, nil
    }

    // Cache for future requests
    m.capabilityCache.Store(nodeID, &cachedCapability{
        caps:     caps,
        cachedAt: time.Now(),
    })

    return caps, nil
}

type cachedCapability struct {
    caps     *UntrustedCapabilities
    cachedAt time.Time
}

// ErrCapabilityLookupFailed indicates capability lookup failed
type ErrCapabilityLookupFailed struct {
    NodeID [32]byte
    Cause  error
}

func (e ErrCapabilityLookupFailed) Error() string {
    return fmt.Sprintf("capability lookup failed for node %x: %v", e.NodeID[:8], e.Cause)
}

// OperationToCapability maps API operations to capability checks
var OperationToCapability = map[string]string{
    "PUT /dht/value":         "store_dht",
    "GET /dht/value":         "retrieve_dht",
    "POST /dht/route":        "route_dht",
    "POST /tx/forward":       "forward_transactions",
    "POST /work/submit":      "perform_work",
    "POST /reputation/earn":  "earn_reputation",       // Always denied for untrusted
    "POST /ca/participate":   "ca_participate",        // Always denied for untrusted
    "POST /consensus/vote":   "vote_consensus",        // Always denied for untrusted
    "POST /cert/issue":       "issue_certificates",    // Always denied for untrusted
}
```

---

## Work Assignment Workflow

### Complete Work Assignment Flow

```
              UNTRUSTED NODE WORK ASSIGNMENT FLOW

+---------------------------------------------------------------------+
|                                                                     |
|  1. NODE JOINS NETWORK                                              |
|     |                                                               |
|     v                                                               |
|  +-------------------+                                              |
|  | Trust Assessment  |                                              |
|  | Result: UNTRUSTED |                                              |
|  +---------+---------+                                              |
|            |                                                        |
|  2. INITIAL SCRUTINY LEVEL ASSIGNED                                 |
|     |                                                               |
|     v                                                               |
|  +-------------------+                                              |
|  | ScrutinyElevated  |                                              |
|  | - 50% rate limit  |                                              |
|  | - PoW required    |                                              |
|  | - 4h work/day     |                                              |
|  +---------+---------+                                              |
|            |                                                        |
|  3. WORK ASSIGNED                                                   |
|     |                                                               |
|     v                                                               |
|  +-------------------+    +-------------------+                      |
|  | Work Coordinator  |--->| Available Work    |                      |
|  | assigns task      |    | - PoW Verify      |                      |
|  +---------+---------+    | - Traffic Scrub   |                      |
|            |              | - IP Scoring      |                      |
|            |              +-------------------+                      |
|  4. WORK PERFORMED                                                  |
|     |                                                               |
|     v                                                               |
|  +-------------------+                                              |
|  | Node completes    |                                              |
|  | assigned work     |                                              |
|  +---------+---------+                                              |
|            |                                                        |
|            +---------------+---------------+                        |
|            |               |               |                        |
|  5. OUTCOME                                                         |
|     |               |               |                               |
|     v               v               v                               |
|  +----------+  +----------+  +----------+                           |
|  | SUCCESS  |  | PARTIAL  |  | FAILURE  |                           |
|  +----+-----+  +----+-----+  +----+-----+                           |
|       |             |             |                                 |
|       v             v             v                                 |
|  +----------+  +----------+  +----------+                           |
|  | Compen-  |  | Reduced  |  | Work     |                           |
|  | sation   |  | Compen-  |  | Refusal  |                           |
|  | granted  |  | sation   |  | Recorded |                           |
|  +----------+  +----------+  +----+-----+                           |
|                                   |                                 |
|  6. MISBEHAVIOR TRACKING          |                                 |
|                                   v                                 |
|                            +-------------+                          |
|                            | Penalty     |                          |
|                            | Applied     |                          |
|                            +------+------+                          |
|                                   |                                 |
|                                   v                                 |
|                            +-------------+                          |
|                            | Scrutiny    |                          |
|                            | Escalated   |                          |
|                            +-------------+                          |
|                                                                     |
+---------------------------------------------------------------------+
```

### Work Coordinator Implementation

```go
// WorkCoordinator manages work assignment for untrusted nodes
type WorkCoordinator struct {
    workQueue       *WorkQueue
    nodeRegistry    *UntrustedNodeRegistry
    compensator     *CompensationManager
    penaltyEnforcer *PenaltyEnforcer
    db              *Database                  // Persistent storage
    completionGroup singleflight.Group         // Prevents concurrent completion attempts
    idempotencyLog  *IdempotencyCache          // SECURITY FIX (P5-C3): In-memory cache for fast idempotency checks
}

// IdempotencyCache provides fast in-memory checks for completed work
// SECURITY: This is an optimization only - database is authoritative
type IdempotencyCache struct {
    mu      sync.RWMutex
    keys    map[[32]byte]time.Time  // Key -> Expiration time
    maxSize int                      // Maximum entries before cleanup
}

// Contains checks if an idempotency key was already processed
func (c *IdempotencyCache) Contains(key [32]byte) bool {
    c.mu.RLock()
    defer c.mu.RUnlock()
    exp, exists := c.keys[key]
    return exists && time.Now().Before(exp)
}

// Add records an idempotency key with 7-day expiration
func (c *IdempotencyCache) Add(key [32]byte) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Cleanup if at capacity
    if len(c.keys) >= c.maxSize {
        now := time.Now()
        for k, exp := range c.keys {
            if now.After(exp) {
                delete(c.keys, k)
            }
        }
    }

    c.keys[key] = time.Now().Add(7 * 24 * time.Hour)
}

// WorkQueue implements a lock-free queue for work assignment
// CRITICAL SECURITY: Uses atomic CAS to prevent work stealing and double-assignment
type WorkQueue struct {
    assignments sync.Map  // assignmentID -> *WorkAssignment
    pending     []atomic.Pointer[WorkAssignment]  // Lock-free pending queue
    head        atomic.Uint64
    tail        atomic.Uint64
}

// AtomicAssign performs a CAS operation to claim work
// SECURITY: This is the ONLY way to assign work - prevents race conditions
func (wq *WorkQueue) AtomicAssign(assignment *WorkAssignment) bool {
    // CAS(assignment.claimed, nil, node_id)
    // Only succeeds if assignment is unclaimed (nil)
    return assignment.ClaimedBy.CompareAndSwap(nil, &assignment.NodeID)
}

// ClaimWork atomically claims an assignment for a specific node
// Returns false if work was already claimed by another node
func (wq *WorkQueue) ClaimWork(assignmentID [32]byte, nodeID [32]byte) (*WorkAssignment, error) {
    val, ok := wq.assignments.Load(assignmentID)
    if !ok {
        return nil, ErrAssignmentNotFound
    }

    assignment := val.(*WorkAssignment)

    // Atomic claim: CAS(assignment.claimed, nil, node_id)
    // This is the ONLY way to claim work - no bypasses allowed
    if !assignment.ClaimedBy.CompareAndSwap(nil, &nodeID) {
        // Work already claimed by another node
        currentClaimer := assignment.ClaimedBy.Load()
        return nil, &ErrWorkAlreadyClaimed{
            AssignmentID: assignmentID,
            ClaimedBy:    *currentClaimer,
            AttemptedBy:  nodeID,
        }
    }

    // Record claim timestamp atomically
    assignment.ClaimedAt.Store(time.Now().UnixNano())

    return assignment, nil
}

// ErrWorkAlreadyClaimed indicates work was claimed by another node
type ErrWorkAlreadyClaimed struct {
    AssignmentID [32]byte
    ClaimedBy    [32]byte
    AttemptedBy  [32]byte
}

func (e *ErrWorkAlreadyClaimed) Error() string {
    return fmt.Sprintf("work %x already claimed by %x, attempted by %x",
        e.AssignmentID[:8], e.ClaimedBy[:8], e.AttemptedBy[:8])
}

var ErrAssignmentNotFound = errors.New("assignment not found in work queue")

// AssignWork allocates work to an untrusted node with atomic assignment
// CRITICAL: Uses lock-free queue to prevent work stealing between nodes
func (wc *WorkCoordinator) AssignWork(nodeID string) (*WorkAssignment, error) {
    // Get node's current status
    node, err := wc.nodeRegistry.Get(nodeID)
    if err != nil {
        return nil, err
    }

    // Atomic check-and-increment for daily work tracking
    // Prevents node from being assigned work beyond obligation
    currentWork := atomic.LoadInt64(&node.DailyWorkCompleted)
    if currentWork >= int64(node.ScrutinyConfig.WorkHoursPerDay * 3600) { // Convert hours to seconds
        return nil, ErrWorkObligationMet
    }

    // Select appropriate work type based on node capabilities
    workType := wc.selectWorkType(node)

    // Generate unique assignment ID (includes nodeID to prevent cross-node conflicts)
    assignmentID := generateAssignmentID(nodeID)

    // Create assignment
    assignment := &WorkAssignment{
        AssignmentID: assignmentID,
        NodeID:       nodeID,
        WorkType:     workType,
        AssignedAt:   time.Now(),
        Deadline:     time.Now().Add(1 * time.Hour),
        StatusFlag:   uint32(WorkStatusAssigned), // Atomic status flag
    }

    // Populate work-specific details
    switch workType {
    case WorkTypePoWVerification:
        assignment.Details = wc.createPoWVerificationWork()
    case WorkTypeTrafficScrubbing:
        assignment.Details = wc.createTrafficScrubbingWork()
    case WorkTypeChallengeGeneration:
        assignment.Details = wc.createChallengeGenerationWork()
    case WorkTypeIPScoring:
        assignment.Details = wc.createIPScoringWork()
    case WorkTypeBlocklistPropagation:
        assignment.Details = wc.createBlocklistPropagationWork()
    }

    // Atomic assignment - uses CAS to ensure work isn't double-assigned
    if !wc.workQueue.AtomicAssign(assignment) {
        return nil, ErrWorkAssignmentConflict
    }

    return assignment, nil
}

var ErrWorkAssignmentConflict = errors.New("work assignment conflict - already assigned")

// CompleteWork processes a completed work assignment with FULLY ATOMIC completion
// CRITICAL FIX (P4-C1): Status change AND compensation MUST be a single atomic operation
// to prevent double-claim race conditions where two threads both read status before either writes.
func (wc *WorkCoordinator) CompleteWork(assignmentID [32]byte, result *WorkResult) error {
    assignment, err := wc.workQueue.Get(assignmentID)
    if err != nil {
        return err
    }

    // CRITICAL FIX: Use single atomic transaction that includes BOTH status and compensation
    // This prevents the race condition where:
    // 1. Thread A reads status=Assigned, begins processing
    // 2. Thread B reads status=Assigned (still), begins processing
    // 3. Both threads try to apply compensation
    return wc.atomicCompleteWork(assignment, result)
}

// atomicCompleteWork performs work completion as a single atomic transaction
// SECURITY: This is the ONLY way to complete work - no bypasses allowed
// SECURITY FIX (P5-C3): Added persistent idempotency check to prevent double-claim
// after single-flight lock releases. Single-flight only prevents concurrent calls,
// NOT subsequent calls after the first completes.
func (wc *WorkCoordinator) atomicCompleteWork(assignment *WorkAssignment, result *WorkResult) error {
    // CRITICAL FIX (P5-C3): Check idempotency log FIRST, before any processing
    // This idempotency key ties the assignment to the specific result
    idempotencyKey := computeIdempotencyKey(assignment.ID, result)

    // Check if this exact completion was already processed
    if wc.idempotencyLog.Contains(idempotencyKey) {
        return ErrWorkAlreadyCompleted
    }

    // Acquire completion lock specific to this assignment
    // Uses the assignment's unique ID as the lock key
    lockKey := fmt.Sprintf("work_completion:%x", assignment.ID)

    // CRITICAL: Single-flight pattern - only one completion attempt can proceed concurrently
    completionResult, err, shared := wc.completionGroup.Do(lockKey, func() (interface{}, error) {
        return wc.executeAtomicCompletion(assignment, result, idempotencyKey)
    })

    if shared {
        // Another goroutine completed the same work - this is a double-claim attempt
        return ErrWorkCompletionInProgress
    }

    if err != nil {
        return err
    }

    return completionResult.(error)
}

// computeIdempotencyKey creates a unique key for this specific assignment+result
// FORMULA: idempotencyKey = SHA256(assignmentID || result.Hash)
// SECURITY: This prevents accepting duplicate completions even after single-flight releases
// The key binds both the assignment AND the specific result, so:
// - Same assignment with different results = different keys (allows retry with different work)
// - Same assignment with same result = same key (blocks duplicate claims)
func computeIdempotencyKey(assignmentID [32]byte, result *WorkResult) [32]byte {
    // Compute result hash first
    resultHash := sha256.Sum256(result.Output)

    // idempotencyKey = hash(assignmentID, result.Hash)
    h := sha256.New()
    h.Write(assignmentID[:])
    h.Write(resultHash[:])
    var key [32]byte
    copy(key[:], h.Sum(nil))
    return key
}

// executeAtomicCompletion performs the actual completion within single-flight protection
// SECURITY FIX (P5-C3): Now accepts idempotency key to persist after successful completion
//
// ATOMICITY GUARANTEES:
// 1. Idempotency key = hash(assignmentID, result.Hash) - checked FIRST
// 2. CAS on status: if status != PENDING, return ErrAlreadyCompleted
// 3. Atomic transaction: status + compensation together in single DB transaction
// 4. Mark processed in idempotency log within same transaction
// 5. Lock held until state persisted (single-flight ensures this)
func (wc *WorkCoordinator) executeAtomicCompletion(
    assignment *WorkAssignment,
    result *WorkResult,
    idempotencyKey [32]byte,
) (interface{}, error) {
    // STEP 0: Pre-flight check - verify assignment status is PENDING before ANY processing
    // This is a read-only check that fails fast for obvious duplicates
    currentStatus := atomic.LoadUint32(&assignment.StatusFlag)
    if currentStatus != uint32(WorkStatusAssigned) {
        return nil, &ErrStatusNotPending{
            AssignmentID:  assignment.ID,
            CurrentStatus: currentStatus,
            ExpectedStatus: uint32(WorkStatusAssigned),
        }
    }

    // STEP 1: Atomic status transition with CAS
    // CAS on status: if status != PENDING, return ErrAlreadyCompleted
    // Only ONE thread can ever succeed here for a given assignment
    if !atomic.CompareAndSwapUint32(&assignment.StatusFlag,
        uint32(WorkStatusAssigned),
        uint32(WorkStatusCompleting)) {

        // CAS failed - get current status for specific error
        currentStatus := atomic.LoadUint32(&assignment.StatusFlag)
        switch currentStatus {
        case uint32(WorkStatusCompleted):
            return nil, ErrWorkAlreadyCompleted
        case uint32(WorkStatusCompleting):
            return nil, ErrWorkCompletionInProgress
        case uint32(WorkStatusFailed):
            return nil, ErrWorkPreviouslyFailed
        default:
            return nil, ErrInvalidWorkStatus
        }
    }

    // CRITICAL: From this point, we hold exclusive completion rights via CAS
    // The single-flight lock persists until state is fully persisted

    // Step 2: Validate work result
    valid, quality := wc.validateWorkResult(assignment, result)

    if !valid {
        atomic.StoreUint32(&assignment.StatusFlag, uint32(WorkStatusFailed))
        wc.penaltyEnforcer.RecordMisbehavior(assignment.NodeID, &MisbehaviorRecord{
            Type:        MisbehaviorWorkRefusal,
            Severity:    SeverityMedium,
            Description: "Failed to complete assigned work",
        })
        return nil, ErrWorkValidationFailed
    }

    // Step 3: Calculate and apply compensation in SAME atomic scope
    compensation := wc.compensator.Calculate(assignment.WorkType, quality)

    // CRITICAL: CompensationRecord includes assignment ID to prevent any double-application
    compensationRecord := &CompensationRecord{
        AssignmentID:   assignment.ID,
        NodeID:         assignment.NodeID,
        Amount:         compensation,
        Quality:        quality,
        CompletedAt:    time.Now(),
        // Include hash of work result to prove this specific completion
        ResultHash:     sha256.Sum256(result.Output),
    }

    // Atomic persist: status + compensation + idempotency as single database transaction
    // SECURITY FIX (P5-C3): Include idempotency key in the atomic transaction
    if err := wc.persistCompletion(assignment, compensationRecord, idempotencyKey); err != nil {
        // Rollback status on persistence failure
        atomic.StoreUint32(&assignment.StatusFlag, uint32(WorkStatusAssigned))
        return nil, fmt.Errorf("completion persistence failed: %w", err)
    }

    // CRITICAL (P5-C3): Record idempotency key in memory cache for fast pre-flight check
    // This is in addition to database persistence - protects against rapid retries
    wc.idempotencyLog.Add(idempotencyKey)

    // Step 4: Update tracking (already protected by single-flight)
    atomic.AddInt64(&assignment.node.DailyWorkCompleted, int64(assignment.Duration().Seconds()))
    atomic.StoreUint32(&assignment.StatusFlag, uint32(WorkStatusCompleted))
    assignment.CompletedAt = compensationRecord.CompletedAt
    assignment.Quality = quality

    return nil, nil
}

// persistCompletion writes status + compensation + idempotency atomically to storage
// Uses database transaction to ensure all operations succeed or all fail
// SECURITY FIX (P5-C3): Now includes idempotency key persistence
func (wc *WorkCoordinator) persistCompletion(
    assignment *WorkAssignment,
    compensation *CompensationRecord,
    idempotencyKey [32]byte,
) error {
    // Database transaction: ALL updates must succeed or ALL fail
    return wc.db.Transaction(func(tx *Transaction) error {
        // CRITICAL (P5-C3): Check idempotency key in database FIRST
        // This is the authoritative check (memory cache is optimization only)
        if tx.IdempotencyKeyExists(idempotencyKey) {
            return ErrWorkAlreadyCompleted
        }

        // Check compensation hasn't already been applied (belt and suspenders)
        existing, _ := tx.GetCompensation(compensation.AssignmentID)
        if existing != nil {
            return ErrCompensationAlreadyApplied
        }

        // CRITICAL (P5-C3): Persist idempotency key FIRST before any side effects
        // Key expires after 7 days to prevent unbounded growth
        if err := tx.SaveIdempotencyKey(idempotencyKey, 7*24*time.Hour); err != nil {
            return err
        }

        // Write compensation record
        if err := tx.SaveCompensation(compensation); err != nil {
            return err
        }

        // Update assignment status
        if err := tx.UpdateAssignmentStatus(assignment.ID, WorkStatusCompleted); err != nil {
            return err
        }

        // Apply compensation to node's balance
        if err := tx.CreditNodeBalance(compensation.NodeID, compensation.Amount); err != nil {
            return err
        }

        return nil
    })
}

// CompensationRecord tracks compensation with idempotency protection
type CompensationRecord struct {
    AssignmentID [32]byte
    NodeID       [32]byte
    Amount       uint64
    Quality      float64
    CompletedAt  time.Time
    ResultHash   [32]byte  // Hash of work output for verification
}

// Work status constants for atomic operations
const (
    WorkStatusPending    uint32 = 0
    WorkStatusAssigned   uint32 = 1
    WorkStatusCompleting uint32 = 2  // Transitional state during completion
    WorkStatusCompleted  uint32 = 3
    WorkStatusFailed     uint32 = 4
    WorkStatusExpired    uint32 = 5
)

var (
    ErrWorkAlreadyCompleted       = errors.New("work assignment already completed")
    ErrWorkCompletionInProgress   = errors.New("work completion already in progress")
    ErrWorkPreviouslyFailed       = errors.New("work assignment previously failed")
    ErrInvalidWorkStatus          = errors.New("invalid work assignment status")
    ErrCompensationAlreadyApplied = errors.New("compensation already applied for this work")
    ErrWorkValidationFailed       = errors.New("work result validation failed")
)

// ErrStatusNotPending indicates the assignment status was not PENDING when completion attempted
// This is the pre-flight check error before CAS is attempted
type ErrStatusNotPending struct {
    AssignmentID   [32]byte
    CurrentStatus  uint32
    ExpectedStatus uint32
}

func (e *ErrStatusNotPending) Error() string {
    statusNames := map[uint32]string{
        WorkStatusPending:    "PENDING",
        WorkStatusAssigned:   "ASSIGNED",
        WorkStatusCompleting: "COMPLETING",
        WorkStatusCompleted:  "COMPLETED",
        WorkStatusFailed:     "FAILED",
        WorkStatusExpired:    "EXPIRED",
    }
    return fmt.Sprintf("assignment %x status is %s, expected %s",
        e.AssignmentID[:8],
        statusNames[e.CurrentStatus],
        statusNames[e.ExpectedStatus])
}
```

### Work Status Transition Matrix (M6 Fix)

**CRITICAL SECURITY**: Work assignment status transitions MUST use atomic operations to prevent race conditions where two nodes claim the same work, or a node receives duplicate compensation.

**PROBLEM ADDRESSED**: Pre-flight status checks without atomic updates create a time-of-check to time-of-use (TOCTOU) vulnerability. Between reading status and updating status, another thread may have already claimed the work.

**SOLUTION**: All status transitions MUST use `atomic.CompareAndSwapUint32` to ensure only one actor can successfully transition between any two states.

#### Valid Status Transitions

The following state machine defines all valid work status transitions:

```
                     WORK STATUS STATE MACHINE

    +-------------+
    |  PENDING    |  (Work created, awaiting assignment)
    |  (status=0) |
    +------+------+
           |
           | AssignWork() - CAS(status, 0, 1)
           v
    +-------------+
    |  ASSIGNED   |  (Work assigned to specific node)
    |  (status=1) |
    +------+------+
           |
           +----------+----------+-----------+
           |          |          |           |
           | Complete | Fail     | Expire    |
           | CAS(1,2) | CAS(1,4) | CAS(1,5)  |
           v          v          v           |
    +-------------+  +--------+  +--------+  |
    | COMPLETING  |  | FAILED |  | EXPIRED|  |
    | (status=2)  |  | (st=4) |  | (st=5) |  |
    +------+------+  +--------+  +--------+  |
           |                                  |
           | Finalize                         |
           | CAS(2,3)                         |
           v                                  |
    +-------------+                           |
    | COMPLETED   |                           |
    | (status=3)  |                           |
    +-------------+                           |
                                              |
    TERMINAL STATES: COMPLETED, FAILED, EXPIRED
    (No transitions out of terminal states)
```

#### Transition Matrix Table

| From Status | To Status | Condition | Atomic Operation |
|-------------|-----------|-----------|------------------|
| PENDING (0) | ASSIGNED (1) | Node claims work | `CAS(&status, 0, 1)` |
| ASSIGNED (1) | COMPLETING (2) | Node begins completion | `CAS(&status, 1, 2)` |
| ASSIGNED (1) | FAILED (4) | Work validation fails | `CAS(&status, 1, 4)` |
| ASSIGNED (1) | EXPIRED (5) | Deadline passed | `CAS(&status, 1, 5)` |
| COMPLETING (2) | COMPLETED (3) | Compensation applied | `CAS(&status, 2, 3)` |
| COMPLETING (2) | FAILED (4) | Post-completion failure | `CAS(&status, 2, 4)` |

**INVALID TRANSITIONS** (will be rejected):
- Any transition FROM terminal states (COMPLETED, FAILED, EXPIRED)
- PENDING -> COMPLETING (must go through ASSIGNED)
- PENDING -> COMPLETED (must go through ASSIGNED and COMPLETING)
- Any backward transition (lower status number)

#### Atomic Status Transition Implementation

```go
// pkg/dht/untrusted/work_status.go

// WorkStatusTransition performs atomic status transition using CAS
// CRITICAL: This is the ONLY way to change work status - no direct assignment allowed
type WorkStatusTransition struct{}

// TransitionResult contains the outcome of an attempted transition
type TransitionResult struct {
    Success       bool
    PreviousState WorkStatus
    NewState      WorkStatus
    FailureReason string
}

// Transition atomically transitions work status from expected to new state
// SECURITY: Uses CAS to prevent double-assignment race conditions
//
// USAGE PATTERN:
//   old := atomic.CompareAndSwapUint32(&assignment.Status, StatusPending, StatusAssigned)
//   if !old {
//       return ErrAlreadyAssigned
//   }
//
func (wst *WorkStatusTransition) Transition(
    assignment *WorkAssignment,
    expectedStatus WorkStatus,
    newStatus WorkStatus,
) (*TransitionResult, error) {
    // Validate transition is allowed by state machine
    if !isValidStatusTransition(expectedStatus, newStatus) {
        return &TransitionResult{
            Success:       false,
            PreviousState: expectedStatus,
            NewState:      newStatus,
            FailureReason: "invalid state transition",
        }, &ErrInvalidStatusTransition{
            From: expectedStatus,
            To:   newStatus,
        }
    }

    // ATOMIC: Compare-and-swap status transition
    // This is the critical section - only ONE thread can succeed
    swapped := atomic.CompareAndSwapUint32(
        &assignment.StatusFlag,
        uint32(expectedStatus),
        uint32(newStatus),
    )

    if !swapped {
        // CAS failed - get current status for error reporting
        currentStatus := WorkStatus(atomic.LoadUint32(&assignment.StatusFlag))
        return &TransitionResult{
            Success:       false,
            PreviousState: currentStatus,
            NewState:      newStatus,
            FailureReason: "status already changed by another actor",
        }, &ErrStatusTransitionFailed{
            AssignmentID:   assignment.ID,
            ExpectedStatus: expectedStatus,
            ActualStatus:   currentStatus,
            TargetStatus:   newStatus,
        }
    }

    // Record transition timestamp atomically
    atomic.StoreInt64(&assignment.LastTransitionAt, time.Now().UnixNano())

    return &TransitionResult{
        Success:       true,
        PreviousState: expectedStatus,
        NewState:      newStatus,
    }, nil
}

// isValidStatusTransition checks if transition is allowed by state machine
func isValidStatusTransition(from, to WorkStatus) bool {
    validTransitions := map[WorkStatus][]WorkStatus{
        WorkStatus(WorkStatusPending): {
            WorkStatus(WorkStatusAssigned),
        },
        WorkStatus(WorkStatusAssigned): {
            WorkStatus(WorkStatusCompleting),
            WorkStatus(WorkStatusFailed),
            WorkStatus(WorkStatusExpired),
        },
        WorkStatus(WorkStatusCompleting): {
            WorkStatus(WorkStatusCompleted),
            WorkStatus(WorkStatusFailed),
        },
        // Terminal states - no transitions allowed
        WorkStatus(WorkStatusCompleted): {},
        WorkStatus(WorkStatusFailed):    {},
        WorkStatus(WorkStatusExpired):   {},
    }

    allowed, exists := validTransitions[from]
    if !exists {
        return false
    }

    for _, valid := range allowed {
        if valid == to {
            return true
        }
    }
    return false
}

// AssignWorkToNode atomically assigns pending work to a node
// SECURITY FIX (M6): Uses atomic CAS to prevent double-assignment
func (wc *WorkCoordinator) AssignWorkToNode(
    assignmentID [32]byte,
    nodeID [32]byte,
) (*WorkAssignment, error) {
    assignment, err := wc.workQueue.Get(assignmentID)
    if err != nil {
        return nil, err
    }

    // ATOMIC: CAS transition from PENDING to ASSIGNED
    // Only one node can succeed in claiming this work
    result, err := wc.transitioner.Transition(
        assignment,
        WorkStatus(WorkStatusPending),
        WorkStatus(WorkStatusAssigned),
    )

    if err != nil {
        if result != nil && !result.Success {
            return nil, &ErrWorkAlreadyAssigned{
                AssignmentID: assignmentID,
                CurrentState: result.PreviousState,
            }
        }
        return nil, err
    }

    // CAS succeeded - update node binding atomically
    if !assignment.ClaimedBy.CompareAndSwap(nil, &nodeID) {
        // Another thread beat us to the node binding - this shouldn't happen
        // if status CAS succeeded, but handle defensively
        return nil, ErrConcurrentClaimConflict
    }

    return assignment, nil
}

// BeginWorkCompletion atomically transitions to COMPLETING state
// SECURITY: Prevents multiple completion attempts from same or different nodes
func (wc *WorkCoordinator) BeginWorkCompletion(
    assignment *WorkAssignment,
) error {
    result, err := wc.transitioner.Transition(
        assignment,
        WorkStatus(WorkStatusAssigned),
        WorkStatus(WorkStatusCompleting),
    )

    if err != nil {
        if result != nil {
            switch WorkStatus(uint32(result.PreviousState)) {
            case WorkStatus(WorkStatusCompleting):
                return ErrWorkCompletionInProgress
            case WorkStatus(WorkStatusCompleted):
                return ErrWorkAlreadyCompleted
            case WorkStatus(WorkStatusFailed):
                return ErrWorkPreviouslyFailed
            case WorkStatus(WorkStatusExpired):
                return ErrWorkExpired
            }
        }
        return err
    }

    return nil
}

// FinalizeWorkCompletion atomically transitions to COMPLETED state
// SECURITY: Only called after compensation is applied
func (wc *WorkCoordinator) FinalizeWorkCompletion(
    assignment *WorkAssignment,
) error {
    _, err := wc.transitioner.Transition(
        assignment,
        WorkStatus(WorkStatusCompleting),
        WorkStatus(WorkStatusCompleted),
    )
    return err
}

// Error types for status transitions

// ErrInvalidStatusTransition indicates an illegal state machine transition
type ErrInvalidStatusTransition struct {
    From WorkStatus
    To   WorkStatus
}

func (e *ErrInvalidStatusTransition) Error() string {
    return fmt.Sprintf("invalid work status transition: %d -> %d", e.From, e.To)
}

// ErrStatusTransitionFailed indicates CAS failed due to concurrent modification
type ErrStatusTransitionFailed struct {
    AssignmentID   [32]byte
    ExpectedStatus WorkStatus
    ActualStatus   WorkStatus
    TargetStatus   WorkStatus
}

func (e *ErrStatusTransitionFailed) Error() string {
    return fmt.Sprintf("status transition failed for %x: expected %d, actual %d, target %d",
        e.AssignmentID[:8], e.ExpectedStatus, e.ActualStatus, e.TargetStatus)
}

// ErrWorkAlreadyAssigned indicates work was claimed by another node
type ErrWorkAlreadyAssigned struct {
    AssignmentID [32]byte
    CurrentState WorkStatus
}

func (e *ErrWorkAlreadyAssigned) Error() string {
    return fmt.Sprintf("work %x already assigned (status=%d)", e.AssignmentID[:8], e.CurrentState)
}

var (
    ErrConcurrentClaimConflict = errors.New("concurrent claim conflict on node binding")
    ErrWorkExpired             = errors.New("work assignment has expired")
)
```

#### Status Transition Guarantees

1. **Atomicity**: Every status change uses CAS - no intermediate states visible
2. **Consistency**: State machine enforces valid transitions only
3. **Isolation**: Each CAS operates on a single assignment independently
4. **Durability**: Transitions are logged with timestamps for audit

#### Pre-Flight Check Pattern (Recommended)

For performance, a pre-flight check can be used before attempting CAS:

```go
// Pre-flight check: Fast path rejection for obvious failures
// IMPORTANT: This is an OPTIMIZATION only - CAS is still required
currentStatus := atomic.LoadUint32(&assignment.StatusFlag)
if currentStatus != uint32(WorkStatusPending) {
    // Fast-fail without attempting CAS
    return &ErrWorkAlreadyAssigned{CurrentState: WorkStatus(currentStatus)}
}

// CAS is STILL required even after pre-flight check passes
// Another thread may have changed status between Load and CAS
swapped := atomic.CompareAndSwapUint32(&assignment.StatusFlag,
    uint32(WorkStatusPending),
    uint32(WorkStatusAssigned))
if !swapped {
    return ErrAlreadyAssigned
}
```

**WARNING**: The pre-flight check alone is NOT sufficient for thread safety. The CAS operation MUST always be performed.

#### CAS Failure Retry Strategy (M6 Enhancement)

**PROBLEM**: When multiple nodes contend for the same work assignment, CAS operations may fail. Without a proper retry strategy, nodes may give up too early or retry indefinitely, causing resource exhaustion.

**SOLUTION**: Implement exponential backoff with jitter and maximum retry limits.

**Retry Configuration Constants**:

| Parameter | Value | Description |
|-----------|-------|-------------|
| `MaxCASRetries` | 3 | Maximum retry attempts before escalation |
| `InitialBackoff` | 10ms | Initial wait before first retry |
| `MaxBackoff` | 100ms | Maximum backoff duration |
| `BackoffMultiplier` | 2.0 | Exponential backoff factor |
| `JitterFraction` | 0.25 | Random jitter (0-25% of backoff) |

```go
// pkg/dht/untrusted/work_retry.go

// RetryConfig defines CAS retry behavior
// SECURITY: Bounded retries prevent resource exhaustion attacks
type RetryConfig struct {
    MaxRetries        int           // Maximum retry attempts (default: 3)
    InitialBackoff    time.Duration // Initial backoff (default: 10ms)
    MaxBackoff        time.Duration // Maximum backoff cap (default: 100ms)
    BackoffMultiplier float64       // Exponential factor (default: 2.0)
    JitterFraction    float64       // Random jitter 0-N (default: 0.25)
}

// DefaultRetryConfig returns production retry configuration
func DefaultRetryConfig() *RetryConfig {
    return &RetryConfig{
        MaxRetries:        3,
        InitialBackoff:    10 * time.Millisecond,
        MaxBackoff:        100 * time.Millisecond,
        BackoffMultiplier: 2.0,
        JitterFraction:    0.25,
    }
}

// RetryResult contains the outcome of a retry operation
type RetryResult struct {
    Success      bool
    Attempts     int
    FinalError   error
    TotalLatency time.Duration
}

// AtomicAssignWithRetry attempts work assignment with bounded retries
// SECURITY: Uses exponential backoff to prevent thundering herd
// SECURITY: Maximum retries prevent infinite loops from contention attacks
func (wc *WorkCoordinator) AtomicAssignWithRetry(
    ctx context.Context,
    assignmentID [32]byte,
    nodeID [32]byte,
    config *RetryConfig,
) (*WorkAssignment, *RetryResult) {
    if config == nil {
        config = DefaultRetryConfig()
    }

    result := &RetryResult{}
    startTime := time.Now()
    backoff := config.InitialBackoff

    for attempt := 0; attempt <= config.MaxRetries; attempt++ {
        result.Attempts = attempt + 1

        // Check context cancellation before each attempt
        if ctx.Err() != nil {
            result.FinalError = ctx.Err()
            result.TotalLatency = time.Since(startTime)
            return nil, result
        }

        // Attempt atomic assignment
        assignment, err := wc.AssignWorkToNode(assignmentID, nodeID)
        if err == nil {
            result.Success = true
            result.TotalLatency = time.Since(startTime)
            return assignment, result
        }

        // Check if error is retryable
        if !isRetryableCASError(err) {
            result.FinalError = err
            result.TotalLatency = time.Since(startTime)
            return nil, result
        }

        // Don't sleep after last attempt
        if attempt < config.MaxRetries {
            // Calculate backoff with jitter
            jitter := time.Duration(float64(backoff) * config.JitterFraction * rand.Float64())
            sleepDuration := backoff + jitter

            select {
            case <-ctx.Done():
                result.FinalError = ctx.Err()
                result.TotalLatency = time.Since(startTime)
                return nil, result
            case <-time.After(sleepDuration):
            }

            // Exponential backoff
            backoff = time.Duration(float64(backoff) * config.BackoffMultiplier)
            if backoff > config.MaxBackoff {
                backoff = config.MaxBackoff
            }
        }

        result.FinalError = err
    }

    // All retries exhausted - escalate
    result.TotalLatency = time.Since(startTime)
    wc.escalateExhaustedRetries(nodeID, assignmentID, result)

    return nil, result
}

// isRetryableCASError determines if a CAS error warrants retry
func isRetryableCASError(err error) bool {
    switch err.(type) {
    case *ErrStatusTransitionFailed:
        // CAS failed due to concurrent modification - retryable
        return true
    case *ErrWorkAlreadyAssigned:
        // Work claimed by another node - NOT retryable
        return false
    case *ErrInvalidStatusTransition:
        // Invalid state machine transition - NOT retryable
        return false
    default:
        return false
    }
}

// escalateExhaustedRetries handles the case when all retries fail
// SECURITY: Logs contention event for monitoring and potential attack detection
func (wc *WorkCoordinator) escalateExhaustedRetries(
    nodeID [32]byte,
    assignmentID [32]byte,
    result *RetryResult,
) {
    // Record contention event for monitoring
    wc.metrics.RecordContentionEvent(ContentionEvent{
        NodeID:       nodeID,
        AssignmentID: assignmentID,
        Attempts:     result.Attempts,
        TotalLatency: result.TotalLatency,
        FinalError:   result.FinalError,
        Timestamp:    time.Now(),
    })

    // Check for contention attack pattern
    // Many nodes failing repeatedly on same work = potential attack
    if wc.contentionMonitor.IsAnomalousContention(assignmentID) {
        wc.reportMisbehavior(&MisbehaviorReport{
            Type:     MisbehaviorContentionAttack,
            Evidence: []byte(fmt.Sprintf("assignment %x exceeded contention threshold", assignmentID)),
        })
    }
}

// ContentionEvent records a CAS contention failure
type ContentionEvent struct {
    NodeID       [32]byte
    AssignmentID [32]byte
    Attempts     int
    TotalLatency time.Duration
    FinalError   error
    Timestamp    time.Time
}
```

**Escalation Behavior**:

1. **Logging**: Every retry exhaustion is logged with full context (node ID, assignment ID, attempts, latency)
2. **Metrics**: Contention events are recorded for operational monitoring
3. **Attack Detection**: Abnormal contention patterns (many nodes failing on same work) trigger misbehavior investigation
4. **Node Action**: After exhausted retries, node SHOULD request a different work assignment rather than continue retrying

**Contention Attack Detection**:

| Metric | Threshold | Action |
|--------|-----------|--------|
| Same work fails 10+ times in 1 minute | Anomalous | Flag for investigation |
| Same node fails 5+ assignments in 1 minute | Suspicious | Increase scrutiny |
| Cluster of nodes fail same work | Coordinated attack | Escalate to security |


### TPM-Attested Work Quality (P4-M4 Fix)

**Problem**: Work quality scores can be gamed by untrusted nodes. Without attestation,
a node can claim high-quality work completion without actually performing the work,
or manipulate quality metrics to earn more compensation.

**Solution**: Require TPM-attested proof of work quality that includes:
1. Measurement of work execution environment
2. Cryptographic binding of output to input
3. Verifiable computation time bounds
4. Independent quality verification by trusted nodes

**CRITICAL - TPM-Attested Execution Metrics Required**:
- All execution time measurements MUST be TPM-attested
- All timestamps MUST be cryptographically bound to TPM quotes
- Untrusted self-reported timestamps are NEVER accepted
- TPM monotonic counter provides ordering guarantees

**TIMESTAMP TRUST POLICY**:
- Untrusted nodes CANNOT self-report timestamps - they will be manipulated
- All timestamps MUST be either:
  1. From TPM-attested quote (includes TPM internal clock)
  2. From authoritative coordinator (assignment issuance time)
  3. Cross-validated against current time with strict skew bounds

```go
// WorkQualityAttestation provides TPM-backed proof of work quality
// SECURITY: All work completed by untrusted nodes MUST include this attestation
type WorkQualityAttestation struct {
    // Work identification
    AssignmentID    [32]byte
    NodeID          [32]byte

    // Input binding (proves work was done on correct input)
    InputHash       [32]byte     // SHA256 of work input
    InputTimestamp  time.Time    // When input was received

    // Output binding (proves output came from this execution)
    OutputHash      [32]byte     // SHA256 of work output
    OutputTimestamp time.Time    // When output was produced

    // Execution metrics (attested by TPM)
    ExecutionTimeNs uint64       // Nanoseconds spent executing
    CPUCycles       uint64       // CPU cycles consumed (if available)
    MemoryPeakKB    uint64       // Peak memory usage in KB

    // TPM attestation
    PCRValues       [24][32]byte // PCR values at execution time
    QuoteSignature  []byte       // TPM2_Quote signature over all above
    QuoteNonce      [32]byte     // Nonce from verifier
    AIKCertificate  []byte       // AIK certificate for verification

    // Quality self-assessment (subject to verification)
    SelfQualityScore float64     // 0.0 to 1.0
    QualityMetrics   map[string]float64  // Type-specific quality metrics
}

// WorkQualityVerifier validates work quality attestations
type WorkQualityVerifier struct {
    tpmVerifier       *TPMVerifier
    qualityBaselines  map[WorkType]*QualityBaseline
    trustedVerifiers  []NodeID       // Pool of trusted nodes for spot-checks
    verificationRate  float64        // Rate of independent verification (0.1 = 10%)
}

// QualityBaseline defines expected quality metrics for a work type
type QualityBaseline struct {
    WorkType          WorkType
    MinExecutionTime  time.Duration  // Minimum expected time
    MaxExecutionTime  time.Duration  // Maximum allowed time
    MinQualityScore   float64        // Below this = reject
    ExpectedMetrics   map[string]MetricRange
}

type MetricRange struct {
    Min float64
    Max float64
}

// VerifyWorkQuality validates a work quality attestation
func (v *WorkQualityVerifier) VerifyWorkQuality(
    attestation *WorkQualityAttestation,
    assignment *WorkAssignment,
    result *WorkResult,
) (*QualityVerificationResult, error) {

    // Step 1: Verify TPM quote signature
    if err := v.verifyTPMQuote(attestation); err != nil {
        return nil, &ErrAttestationInvalid{
            AssignmentID: attestation.AssignmentID,
            Reason:       "TPM quote verification failed",
            Inner:        err,
        }
    }

    // Step 2: Verify input binding (work was done on correct input)
    expectedInputHash := sha256.Sum256(assignment.WorkInput)
    if attestation.InputHash != expectedInputHash {
        return nil, &ErrInputMismatch{
            AssignmentID: attestation.AssignmentID,
            Expected:     expectedInputHash,
            Actual:       attestation.InputHash,
        }
    }

    // Step 3: Verify output binding (output matches what was submitted)
    expectedOutputHash := sha256.Sum256(result.Output)
    if attestation.OutputHash != expectedOutputHash {
        return nil, &ErrOutputMismatch{
            AssignmentID: attestation.AssignmentID,
            Expected:     expectedOutputHash,
            Actual:       attestation.OutputHash,
        }
    }

    // Step 4: Verify timestamp ordering (input before output)
    if !attestation.InputTimestamp.Before(attestation.OutputTimestamp) {
        return nil, &ErrTimestampOrdering{
            AssignmentID:    attestation.AssignmentID,
            InputTimestamp:  attestation.InputTimestamp,
            OutputTimestamp: attestation.OutputTimestamp,
        }
    }

    // SECURITY FIX (P5-H4): Validate timestamps against trusted sources
    // Self-reported timestamps cannot be trusted from untrusted nodes
    // Must cross-reference with:
    // 1. Assignment issuance time (authoritative from coordinator)
    // 2. Current time (with clock skew tolerance)
    // 3. TPM monotonic counter (if available)
    if err := v.validateTimestampTrust(attestation, assignment); err != nil {
        return nil, &ErrTimestampUntrusted{
            AssignmentID: attestation.AssignmentID,
            Reason:       err.Error(),
        }
    }

    // Step 5: Verify execution time is within expected bounds
    baseline := v.qualityBaselines[assignment.WorkType]
    executionTime := time.Duration(attestation.ExecutionTimeNs) * time.Nanosecond

    if executionTime < baseline.MinExecutionTime {
        // Too fast - likely didn't actually do the work
        return nil, &ErrExecutionTooFast{
            AssignmentID:  attestation.AssignmentID,
            ActualTime:    executionTime,
            MinExpected:   baseline.MinExecutionTime,
        }
    }

    if executionTime > baseline.MaxExecutionTime {
        // Too slow - penalize quality but don't reject
        // Quality penalty is applied in step 7
    }

    // Step 6: Verify PCR values indicate clean execution environment
    if err := v.verifyExecutionEnvironment(attestation.PCRValues); err != nil {
        return nil, &ErrCompromisedEnvironment{
            AssignmentID: attestation.AssignmentID,
            Reason:       err.Error(),
        }
    }

    // Step 7: Calculate verified quality score
    verifiedQuality := v.calculateVerifiedQuality(attestation, baseline, executionTime)

    // Step 8: Optionally trigger independent verification
    var independentVerification *IndependentVerification
    if v.shouldTriggerIndependentVerification(attestation) {
        independentVerification = v.requestIndependentVerification(attestation, assignment, result)
    }

    return &QualityVerificationResult{
        AssignmentID:            attestation.AssignmentID,
        AttestationValid:        true,
        VerifiedQualityScore:    verifiedQuality,
        SelfReportedScore:       attestation.SelfQualityScore,
        ScoreDiscrepancy:        math.Abs(verifiedQuality - attestation.SelfQualityScore),
        IndependentVerification: independentVerification,
        VerifiedAt:              time.Now(),
    }, nil
}

// calculateVerifiedQuality computes the actual quality score from attestation data
func (v *WorkQualityVerifier) calculateVerifiedQuality(
    attestation *WorkQualityAttestation,
    baseline *QualityBaseline,
    executionTime time.Duration,
) float64 {
    baseScore := 1.0

    // Penalty for slow execution
    if executionTime > baseline.MaxExecutionTime {
        overageRatio := float64(executionTime) / float64(baseline.MaxExecutionTime)
        baseScore *= 1.0 / overageRatio // Linear penalty
    }

    // Bonus for optimal execution time
    optimalTime := (baseline.MinExecutionTime + baseline.MaxExecutionTime) / 2
    if executionTime >= baseline.MinExecutionTime && executionTime <= optimalTime {
        // Slight bonus for efficient execution
        baseScore = math.Min(1.0, baseScore*1.05)
    }

    // Verify self-reported metrics against expectations
    for metric, expected := range baseline.ExpectedMetrics {
        actual, ok := attestation.QualityMetrics[metric]
        if !ok {
            baseScore *= 0.9 // Missing metric = penalty
            continue
        }
        if actual < expected.Min || actual > expected.Max {
            // Out of range metric = penalty proportional to deviation
            deviation := 0.0
            if actual < expected.Min {
                deviation = (expected.Min - actual) / expected.Min
            } else {
                deviation = (actual - expected.Max) / expected.Max
            }
            baseScore *= (1.0 - deviation*0.5) // Max 50% penalty per metric
        }
    }

    return math.Max(0.0, math.Min(1.0, baseScore))
}

// verifyTPMQuote verifies the TPM quote signature
func (v *WorkQualityVerifier) verifyTPMQuote(attestation *WorkQualityAttestation) error {
    // Reconstruct the data that was quoted
    quotedData := v.buildQuotedData(attestation)

    // Verify the AIK certificate chains to a trusted manufacturer CA
    aikPubKey, err := v.tpmVerifier.VerifyAIKCertificate(attestation.AIKCertificate)
    if err != nil {
        return err
    }

    // Verify the quote signature
    return v.tpmVerifier.VerifyQuote(quotedData, attestation.QuoteSignature, aikPubKey)
}

// shouldTriggerIndependentVerification decides if we need a spot-check
func (v *WorkQualityVerifier) shouldTriggerIndependentVerification(
    attestation *WorkQualityAttestation,
) bool {
    // Random sampling at configured rate
    if rand.Float64() < v.verificationRate {
        return true
    }

    // Always verify if self-reported score is suspiciously high
    if attestation.SelfQualityScore > 0.95 {
        return true
    }

    // Always verify for new nodes (first 10 completions)
    nodeCompletions := v.getNodeCompletionCount(attestation.NodeID)
    if nodeCompletions < 10 {
        return true
    }

    return false
}

// IndependentVerification represents verification by a trusted node
type IndependentVerification struct {
    VerifierNodeID       NodeID
    VerifiedQualityScore float64
    VerifiedAt           time.Time
    VerifierSignature    []byte
    // If discrepancy is high, this triggers penalty
    DiscrepancyPenalty   float64
}

// QualityVerificationResult contains the complete verification outcome
type QualityVerificationResult struct {
    AssignmentID            [32]byte
    AttestationValid        bool
    VerifiedQualityScore    float64
    SelfReportedScore       float64
    ScoreDiscrepancy        float64
    IndependentVerification *IndependentVerification
    VerifiedAt              time.Time
}

// Quality verification error types
type ErrAttestationInvalid struct {
    AssignmentID [32]byte
    Reason       string
    Inner        error
}
func (e *ErrAttestationInvalid) Error() string {
    return fmt.Sprintf("attestation invalid for %x: %s", e.AssignmentID[:8], e.Reason)
}

type ErrInputMismatch struct {
    AssignmentID [32]byte
    Expected     [32]byte
    Actual       [32]byte
}
func (e *ErrInputMismatch) Error() string {
    return fmt.Sprintf("input hash mismatch for %x", e.AssignmentID[:8])
}

type ErrOutputMismatch struct {
    AssignmentID [32]byte
    Expected     [32]byte
    Actual       [32]byte
}
func (e *ErrOutputMismatch) Error() string {
    return fmt.Sprintf("output hash mismatch for %x", e.AssignmentID[:8])
}

type ErrTimestampOrdering struct {
    AssignmentID    [32]byte
    InputTimestamp  time.Time
    OutputTimestamp time.Time
}
func (e *ErrTimestampOrdering) Error() string {
    return fmt.Sprintf("timestamp ordering violation for %x: input=%v output=%v",
        e.AssignmentID[:8], e.InputTimestamp, e.OutputTimestamp)
}

type ErrExecutionTooFast struct {
    AssignmentID [32]byte
    ActualTime   time.Duration
    MinExpected  time.Duration
}
func (e *ErrExecutionTooFast) Error() string {
    return fmt.Sprintf("execution too fast for %x: %v (min: %v)",
        e.AssignmentID[:8], e.ActualTime, e.MinExpected)
}

type ErrCompromisedEnvironment struct {
    AssignmentID [32]byte
    Reason       string
}
func (e *ErrCompromisedEnvironment) Error() string {
    return fmt.Sprintf("compromised execution environment for %x: %s",
        e.AssignmentID[:8], e.Reason)
}

// SECURITY FIX (P5-H4): Error type for untrusted timestamps
type ErrTimestampUntrusted struct {
    AssignmentID [32]byte
    Reason       string
}
func (e *ErrTimestampUntrusted) Error() string {
    return fmt.Sprintf("timestamp validation failed for %x: %s",
        e.AssignmentID[:8], e.Reason)
}

// validateTimestampTrust validates timestamps against trusted sources
// SECURITY FIX (P5-H4): Untrusted nodes can fake self-reported timestamps
// This cross-references against authoritative timestamps
func (v *WorkQualityVerifier) validateTimestampTrust(
    attestation *WorkQualityAttestation,
    assignment *WorkAssignment,
) error {
    const MaxClockSkew = 30 * time.Second // Allowed clock skew tolerance

    now := time.Now()

    // Check 1: Input timestamp must be AFTER assignment issuance
    // Assignment issuance time is authoritative (from trusted coordinator)
    if attestation.InputTimestamp.Before(assignment.IssuedAt) {
        return fmt.Errorf("input timestamp %v before assignment issuance %v",
            attestation.InputTimestamp, assignment.IssuedAt)
    }

    // Check 2: Output timestamp must be BEFORE current time (+ skew)
    // Node cannot claim to complete work in the future
    maxAllowed := now.Add(MaxClockSkew)
    if attestation.OutputTimestamp.After(maxAllowed) {
        return fmt.Errorf("output timestamp %v is in the future (max allowed: %v)",
            attestation.OutputTimestamp, maxAllowed)
    }

    // Check 3: Work cannot complete BEFORE it was issued (even with skew)
    // Catches backdated timestamps
    if attestation.OutputTimestamp.Before(assignment.IssuedAt) {
        return fmt.Errorf("output timestamp %v before assignment issuance %v",
            attestation.OutputTimestamp, assignment.IssuedAt)
    }

    // Check 4: Execution duration must be plausible
    // If claimed execution time doesn't match timestamp delta, something is wrong
    claimedDuration := attestation.OutputTimestamp.Sub(attestation.InputTimestamp)
    reportedDuration := time.Duration(attestation.ExecutionTimeNs) * time.Nanosecond

    // Allow 50% variance for scheduling/context switching
    if reportedDuration > 0 {
        ratio := float64(claimedDuration) / float64(reportedDuration)
        if ratio < 0.5 || ratio > 2.0 {
            return fmt.Errorf("timestamp delta %v inconsistent with execution time %v (ratio: %.2f)",
                claimedDuration, reportedDuration, ratio)
        }
    }

    return nil
}

// Work-Type Specific Quality Baselines
var DefaultQualityBaselines = map[WorkType]*QualityBaseline{
    TaskPoWVerify: {
        WorkType:         TaskPoWVerify,
        MinExecutionTime: 10 * time.Millisecond,
        MaxExecutionTime: 100 * time.Millisecond,
        MinQualityScore:  0.8,
        ExpectedMetrics: map[string]MetricRange{
            "hash_operations":    {Min: 1, Max: 1000},
            "verification_count": {Min: 1, Max: 100},
        },
    },
    TaskTrafficScrub: {
        WorkType:         TaskTrafficScrub,
        MinExecutionTime: 1 * time.Millisecond,
        MaxExecutionTime: 50 * time.Millisecond,
        MinQualityScore:  0.7,
        ExpectedMetrics: map[string]MetricRange{
            "packets_processed":  {Min: 1, Max: 10000},
            "packets_dropped":    {Min: 0, Max: 1000},
            "false_positive_rate": {Min: 0.0, Max: 0.05},
        },
    },
    TaskChallengeGen: {
        WorkType:         TaskChallengeGen,
        MinExecutionTime: 5 * time.Millisecond,
        MaxExecutionTime: 50 * time.Millisecond,
        MinQualityScore:  0.9,
        ExpectedMetrics: map[string]MetricRange{
            "entropy_bits":      {Min: 128, Max: 256},
            "challenges_issued": {Min: 1, Max: 100},
        },
    },
    TaskIPScore: {
        WorkType:         TaskIPScore,
        MinExecutionTime: 50 * time.Millisecond,
        MaxExecutionTime: 500 * time.Millisecond,
        MinQualityScore:  0.75,
        ExpectedMetrics: map[string]MetricRange{
            "ips_analyzed":     {Min: 1, Max: 1000},
            "lookups_performed": {Min: 1, Max: 100},
        },
    },
}
```

---

## Integration with Network Systems

### DHT Integration

Untrusted nodes participate in DHT operations with restrictions:

```go
// UntrustedDHTHandler wraps DHT operations for untrusted nodes
type UntrustedDHTHandler struct {
    dht             *DHT
    scrutinyManager *ScrutinyManager
    workCoordinator *WorkCoordinator
    rateLimiter     *RateLimiter
}

// HandleRequest processes a DHT request from an untrusted node
func (h *UntrustedDHTHandler) HandleRequest(nodeID string, req *DHTRequest) (*DHTResponse, error) {
    // Check scrutiny level
    config := h.scrutinyManager.GetConfig(nodeID)

    // Apply rate limiting
    if !h.rateLimiter.Allow(nodeID, config.RateLimitPercent) {
        return nil, ErrRateLimitExceeded
    }

    // Require PoW if configured
    if config.PoWRequired {
        if !h.verifyPoW(req.PoWProof, config.PoWDifficulty) {
            return nil, ErrPoWRequired
        }
    }

    // Check work obligation
    if !h.workCoordinator.HasMetObligation(nodeID) {
        return nil, ErrWorkObligationNotMet
    }

    // Process request
    return h.dht.HandleRequest(req)
}
```

### Defense System Integration

The defense system monitors untrusted node behavior:

```go
// DefenseIntegration connects untrusted node handling with defense system
type DefenseIntegration struct {
    monitor         *defense.Monitor
    judge           *defense.Judge
    scrutinyManager *ScrutinyManager
}

// ReportMisbehavior escalates detected misbehavior to the defense system
func (di *DefenseIntegration) ReportMisbehavior(record *MisbehaviorRecord) error {
    // For critical misbehaviors, create evidence packet
    if record.Severity >= SeverityCritical {
        evidence := &defense.EvidencePacket{
            AccusedNodeID: record.NodeID,
            ViolationType: mapToDefenseViolation(record.Type),
            Severity:      defense.SeveritySevere,
            Description:   record.Description,
            Evidence:      record.Evidence,
            Timestamp:     record.DetectedAt.Unix(),
        }

        return di.judge.SubmitAccusation(context.Background(), evidence)
    }

    // For lower severity, record in monitor
    di.monitor.RecordViolation(record.NodeID, record.Type.String())

    return nil
}
```

---

## Metrics and Monitoring

### Untrusted Node Metrics

```go
// UntrustedNodeMetrics tracks performance and behavior
type UntrustedNodeMetrics struct {
    NodeID                string
    ScrutinyLevel         ScrutinyLevel

    // Work metrics
    WorkAssignments       int64
    WorkCompleted         int64
    WorkFailed            int64
    WorkQuality           float64         // Average quality 0.0-1.0
    DailyWorkHours        float64

    // Behavior metrics
    RequestCount          int64
    RateLimitViolations   int64
    PoWVerifications      int64
    ProtocolViolations    int64

    // Penalty metrics
    WarningsReceived      int64
    CooldownsApplied      int64
    TemporaryBans         int64

    // Network contribution
    DHTMessagesRouted     int64
    DataStored            uint64          // Bytes
    BandwidthProvided     uint64          // Bytes

    // Timestamps
    JoinedAt              time.Time
    LastActiveAt          time.Time
    LastPenaltyAt         time.Time
}

// MetricsCollector gathers metrics for monitoring
type MetricsCollector struct {
    metrics sync.Map // nodeID -> *UntrustedNodeMetrics
}

// Export returns metrics for external monitoring systems
func (mc *MetricsCollector) Export() []*UntrustedNodeMetrics {
    var result []*UntrustedNodeMetrics
    mc.metrics.Range(func(key, value interface{}) bool {
        result = append(result, value.(*UntrustedNodeMetrics))
        return true
    })
    return result
}
```

### Monitoring Dashboard Data

| Metric Category | Measurements | Alert Threshold |
|-----------------|--------------|-----------------|
| **Work Completion** | Assignments, completed, failed, quality | Quality < 70% |
| **Misbehavior** | Violations by type, severity distribution | Critical violations |
| **Resource Usage** | Storage, bandwidth, request rate | Exceeds allocation |
| **Scrutiny Distribution** | Nodes per level, escalations | >50% at Maximum |
| **Network Contribution** | Messages routed, data served | Below minimum quota |

---

## Security Considerations

### Sybil Attack Resistance

Untrusted node handling includes multiple Sybil defenses:

1. **Fingerprinting**: Hardware and behavioral fingerprinting detects multiple identities
2. **Work Requirements**: Economic cost of work makes large-scale Sybil attacks expensive
3. **Rate Limiting**: Prevents resource exhaustion from node multiplication
4. **Immediate Ban**: Sybil pattern detection results in permanent ban

### DDoS Protection

Untrusted nodes serve as a buffer against DDoS attacks:

1. **Traffic Scrubbing**: Malicious traffic is filtered at untrusted layer
2. **PoW Requirement**: Computational cost limits attack throughput
3. **IP Scoring**: Coordinated identification of attack sources
4. **Blocklist Propagation**: Rapid distribution of threat intelligence

### Trust Boundary Enforcement (P4-M5 Fix)

**Problem**: The TrustBoundaryEnforcer struct exists but has no default configuration,
leaving the system vulnerable if operations aren't properly categorized.

**Solution**: Define complete DefaultTrustBoundaryEnforcer() with all operations
explicitly categorized and audit logging.

Strict separation between trusted and untrusted operations:

```go
// TrustBoundaryEnforcer prevents untrusted privilege escalation
type TrustBoundaryEnforcer struct {
    trustedOnlyOps   map[string]bool  // Operations ONLY trusted nodes can perform
    untrustedOps     map[string]bool  // Operations untrusted nodes CAN perform
    auditLog         AuditLogger      // Log all boundary violations
    mu               sync.RWMutex
}

// OperationCategory defines the trust requirements for an operation
type OperationCategory uint8

const (
    OpCategoryTrustedOnly   OperationCategory = iota  // Trusted nodes only
    OpCategoryUntrustedOK                              // Untrusted nodes can perform
    OpCategoryProhibited                               // Nobody can perform (reserved)
)

// DefaultTrustBoundaryEnforcer creates an enforcer with all operations defined
// SECURITY: This is the ONLY way to create an enforcer - no empty constructors
func DefaultTrustBoundaryEnforcer(auditLog AuditLogger) *TrustBoundaryEnforcer {
    tbe := &TrustBoundaryEnforcer{
        trustedOnlyOps: make(map[string]bool),
        untrustedOps:   make(map[string]bool),
        auditLog:       auditLog,
    }

    // === TRUSTED-ONLY OPERATIONS ===
    // These operations are FORBIDDEN for untrusted nodes

    // CA Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["ca:sign_certificate"] = true
    tbe.trustedOnlyOps["ca:revoke_certificate"] = true
    tbe.trustedOnlyOps["ca:participate_pool"] = true
    tbe.trustedOnlyOps["ca:dkg_participate"] = true
    tbe.trustedOnlyOps["ca:frost_sign"] = true

    // Consensus Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["consensus:coordinate"] = true
    tbe.trustedOnlyOps["consensus:pbft_vote"] = true
    tbe.trustedOnlyOps["consensus:view_change"] = true
    tbe.trustedOnlyOps["consensus:batch_commit"] = true

    // Gateway Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["gateway:serve_external"] = true
    tbe.trustedOnlyOps["gateway:proxy_traffic"] = true
    tbe.trustedOnlyOps["gateway:issue_certificate"] = true

    // Hub Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["hub:regional_coordinate"] = true
    tbe.trustedOnlyOps["hub:aggregate_metrics"] = true
    tbe.trustedOnlyOps["hub:threat_intel_aggregate"] = true

    // Currency Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["currency:validate_tx"] = true
    tbe.trustedOnlyOps["currency:confirm_tx"] = true
    tbe.trustedOnlyOps["currency:shard_coordinate"] = true

    // Reputation Operations - NEVER allowed for untrusted
    tbe.trustedOnlyOps["reputation:earn"] = true
    tbe.trustedOnlyOps["reputation:judge_dispute"] = true
    tbe.trustedOnlyOps["reputation:verify_attestation"] = true

    // AI Arbitration - NEVER allowed for untrusted
    tbe.trustedOnlyOps["arbitration:serve_arbitrator"] = true
    tbe.trustedOnlyOps["arbitration:render_decision"] = true

    // Service Contracts - Trusted operations
    tbe.trustedOnlyOps["contract:provide_service"] = true
    tbe.trustedOnlyOps["contract:receive_payment"] = true

    // Storage - Encrypted content operations
    tbe.trustedOnlyOps["storage:ksp_store"] = true
    tbe.trustedOnlyOps["storage:ksp_retrieve"] = true

    // === UNTRUSTED-ALLOWED OPERATIONS ===
    // These operations ARE permitted for untrusted nodes

    // DHT Operations - Basic participation allowed
    tbe.untrustedOps["dht:route_message"] = true
    tbe.untrustedOps["dht:store_value"] = true
    tbe.untrustedOps["dht:retrieve_value"] = true
    tbe.untrustedOps["dht:lookup_node"] = true
    tbe.untrustedOps["dht:ping"] = true

    // DDoS Work - REQUIRED for untrusted
    tbe.untrustedOps["ddos:pow_verify"] = true
    tbe.untrustedOps["ddos:traffic_scrub"] = true
    tbe.untrustedOps["ddos:challenge_generate"] = true
    tbe.untrustedOps["ddos:ip_score"] = true
    tbe.untrustedOps["ddos:blocklist_propagate"] = true

    // Service - Consume only, never provide
    tbe.untrustedOps["service:consume"] = true
    tbe.untrustedOps["service:query_catalog"] = true

    // Contract - Consume only (with prepayment)
    tbe.untrustedOps["contract:consume_service"] = true
    tbe.untrustedOps["contract:prepay_escrow"] = true

    // Health - Self-reporting allowed
    tbe.untrustedOps["health:report_status"] = true
    tbe.untrustedOps["health:respond_probe"] = true

    return tbe
}

// Enforce validates operation is allowed for trust level
// Returns error if operation is not permitted for the given trust level
func (tbe *TrustBoundaryEnforcer) Enforce(trustLevel TrustLevel, operation string) error {
    tbe.mu.RLock()
    defer tbe.mu.RUnlock()

    // Step 1: Check if operation is explicitly allowed for untrusted
    if trustLevel == TrustLevelUntrusted {
        if tbe.trustedOnlyOps[operation] {
            // Attempted trusted operation by untrusted node - VIOLATION
            tbe.logViolation(trustLevel, operation, "trusted_only_op_by_untrusted")
            return &ErrTrustBoundaryViolation{
                Operation:   operation,
                TrustLevel:  trustLevel,
                Reason:      "operation requires trusted status",
            }
        }

        // For untrusted nodes, operation must be explicitly allowed
        if !tbe.untrustedOps[operation] {
            tbe.logViolation(trustLevel, operation, "unknown_op_by_untrusted")
            return &ErrTrustBoundaryViolation{
                Operation:   operation,
                TrustLevel:  trustLevel,
                Reason:      "operation not in untrusted allowlist",
            }
        }
    }

    // Step 2: For trusted nodes, check operation isn't in neither list (unknown)
    if trustLevel == TrustLevelTrusted {
        if !tbe.trustedOnlyOps[operation] && !tbe.untrustedOps[operation] {
            // Unknown operation - log but allow for trusted nodes
            tbe.logWarning(trustLevel, operation, "unknown_operation")
        }
    }

    return nil
}

// EnforceWithContext provides richer context for boundary enforcement
func (tbe *TrustBoundaryEnforcer) EnforceWithContext(
    ctx context.Context,
    trustLevel TrustLevel,
    operation string,
    nodeID [32]byte,
    metadata map[string]string,
) error {
    if err := tbe.Enforce(trustLevel, operation); err != nil {
        // Enrich error with context
        if violation, ok := err.(*ErrTrustBoundaryViolation); ok {
            violation.NodeID = nodeID
            violation.Metadata = metadata
            violation.Timestamp = time.Now()

            // For severe violations, escalate immediately
            if tbe.isSevereViolation(operation) {
                tbe.escalateViolation(ctx, violation)
            }
        }
        return err
    }
    return nil
}

// isSevereViolation checks if the attempted operation is a severe security violation
func (tbe *TrustBoundaryEnforcer) isSevereViolation(operation string) bool {
    severeOps := map[string]bool{
        "ca:sign_certificate":    true,
        "ca:dkg_participate":     true,
        "ca:frost_sign":          true,
        "consensus:coordinate":   true,
        "consensus:batch_commit": true,
        "currency:shard_coordinate": true,
    }
    return severeOps[operation]
}

// escalateViolation immediately reports severe violations to the network
func (tbe *TrustBoundaryEnforcer) escalateViolation(ctx context.Context, violation *ErrTrustBoundaryViolation) {
    // Create misbehavior record
    record := &MisbehaviorRecord{
        Type:        MisbehaviorProtocolViolation,
        Severity:    SeverityCritical,
        NodeID:      violation.NodeID,
        Description: fmt.Sprintf("trust boundary violation: %s", violation.Operation),
        Evidence:    []byte(fmt.Sprintf("%+v", violation)),
        Timestamp:   violation.Timestamp,
    }

    // Submit to penalty enforcer (non-blocking)
    go func() {
        if penaltyEnforcer != nil {
            penaltyEnforcer.RecordMisbehavior(violation.NodeID, record)
        }
    }()
}

// logViolation logs a trust boundary violation
func (tbe *TrustBoundaryEnforcer) logViolation(trustLevel TrustLevel, operation, reason string) {
    if tbe.auditLog != nil {
        tbe.auditLog.Log(AuditEntry{
            Type:      AuditTypeTrustViolation,
            Severity:  AuditSeverityCritical,
            Operation: operation,
            TrustLevel: trustLevel,
            Reason:    reason,
            Timestamp: time.Now(),
        })
    }
}

// logWarning logs a warning for unknown operations
func (tbe *TrustBoundaryEnforcer) logWarning(trustLevel TrustLevel, operation, reason string) {
    if tbe.auditLog != nil {
        tbe.auditLog.Log(AuditEntry{
            Type:      AuditTypeTrustWarning,
            Severity:  AuditSeverityWarning,
            Operation: operation,
            TrustLevel: trustLevel,
            Reason:    reason,
            Timestamp: time.Now(),
        })
    }
}

// ListAllowedOperations returns operations allowed for a trust level
func (tbe *TrustBoundaryEnforcer) ListAllowedOperations(trustLevel TrustLevel) []string {
    tbe.mu.RLock()
    defer tbe.mu.RUnlock()

    var ops []string

    // Untrusted can only perform untrusted ops
    if trustLevel == TrustLevelUntrusted {
        for op := range tbe.untrustedOps {
            ops = append(ops, op)
        }
        return ops
    }

    // Trusted can perform all ops
    for op := range tbe.untrustedOps {
        ops = append(ops, op)
    }
    for op := range tbe.trustedOnlyOps {
        ops = append(ops, op)
    }
    return ops
}

// ErrTrustBoundaryViolation represents a security violation
type ErrTrustBoundaryViolation struct {
    Operation   string
    TrustLevel  TrustLevel
    Reason      string
    NodeID      [32]byte
    Metadata    map[string]string
    Timestamp   time.Time
}

func (e *ErrTrustBoundaryViolation) Error() string {
    return fmt.Sprintf("trust boundary violation: %s attempted by %v - %s",
        e.Operation, e.TrustLevel, e.Reason)
}

// AuditEntry for trust boundary logging
type AuditEntry struct {
    Type       AuditType
    Severity   AuditSeverity
    Operation  string
    TrustLevel TrustLevel
    Reason     string
    NodeID     [32]byte
    Timestamp  time.Time
}

type AuditType uint8
const (
    AuditTypeTrustViolation AuditType = iota
    AuditTypeTrustWarning
    AuditTypeTrustSuccess
)

type AuditSeverity uint8
const (
    AuditSeverityInfo AuditSeverity = iota
    AuditSeverityWarning
    AuditSeverityCritical
)

// AuditLogger interface for logging trust boundary events
type AuditLogger interface {
    Log(entry AuditEntry)
}
```

---

## Cross-References

- **Trust Determination**: See [03-security-trust.md](03-security-trust.md) - TPM Trust Policy (CANONICAL)
- **Reputation System**: See [09-defense-reputation.md](09-defense-reputation.md) - Reputation thresholds and role eligibility
- **Defense System**: See [09-defense-reputation.md](09-defense-reputation.md) - Collaborative defense and penalties
- **Node Enrollment**: See [05-certificate-authority.md](05-certificate-authority.md) - IDevID enrollment via ACME enroll-01
- **DDoS Protection**: See [03-security-trust.md](03-security-trust.md) - DDoS Protection Parameters

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-10 | 1.4 | M6 ENHANCEMENT: CAS Failure Retry Strategy - Added bounded retry configuration (MaxCASRetries=3, InitialBackoff=10ms, MaxBackoff=100ms, BackoffMultiplier=2.0, JitterFraction=0.25), exponential backoff with jitter implementation, retryable vs non-retryable error classification, escalation behavior on exhausted retries (logging, metrics, attack detection), contention attack detection thresholds (10+ failures/min per work, 5+ failures/min per node). Verified existing atomic CAS operations and idempotency key handling are complete. |
| 2026-01-10 | 1.3 | C4 FIX: Penalty History Unbounded Memory - Added comprehensive cleanup specification (PenaltyCleanupTrigger=0.85 at 8.5M records, PenaltyRetentionPeriod=90 days, PenaltyEvictionBatchSize=5% per cycle, PenaltyCleanupInterval=1 hour, async cleanup with 5% max overage, audit preservation for active disputes). M6 FIX: Work Assignment Race Condition - Added Work Status Transition Matrix with atomic CAS operations for all status changes, valid transition state machine (PENDING->ASSIGNED->COMPLETING->COMPLETED), typed errors for transition failures, pre-flight check pattern with mandatory CAS. |
| 2026-01-10 | 1.2 | FINAL DESIGN: Added Detection Threshold Justifications (Sybil=5 based on birthday paradox, Amplification=10.0 based on 99th percentile analysis, Flood=1000 based on legitimate traffic patterns), ML-Based Fingerprint Clustering (hierarchical clustering with 0.85 similarity threshold for Sybil cluster detection), Cross-Node Correlation (coordinated attack detection with 3+ nodes in 10-minute window), Evidence Integrity (TPM-signed evidence packages with timestamp verification), Scrutiny Downgrade Process (3-of-7 coordinator approval, 30-day cooldown, full audit trail), Work-to-Trust Path (180-day observation for unknown manufacturers, governance-approved whitelist additions, retroactive trust upgrade) |
| 2026-01-10 | 1.1 | Enhanced atomicity guarantees: Work completion idempotency key formula (hash(assignmentID, result.Hash)), lock-free queue with CAS claim, single-flight lock pattern, explicit status pre-check. Scrutiny level transitions now document constraints applied inside lock. Misbehavior counter 30-day reset mechanism explicit. Penalty history pruning requirements documented. TPM-attested execution metrics required - untrusted timestamps rejected. Capability enforcement enhanced with cert verification before operation. |
| 2026-01-08 | 1.0 | Initial document: Work assignment, scrutiny levels, misbehavior detection, penalty matrix |

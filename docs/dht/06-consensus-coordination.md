# Consensus and Coordinator Election

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

## Overview

The Coordinator Election and Consensus protocol enables the go-trusted-platform network to select a committee of trusted coordinators for managing distributed operations (DKG, FROST signing, key rotation) without introducing single points of failure or centralized trust.

### Design Goals

| Goal | Description |
|------|-------------|
| **Decentralization** | No trusted third party; coordinator selection verifiable by all participants |
| **Byzantine Fault Tolerance** | System remains secure with up to 33% malicious coordinators (7-of-21) |
| **Anti-Collusion** | Prevent coordinator cartels through geographic, vendor, and reputation diversity |
| **Low Latency** | Consensus achieves finality in ~500ms under normal conditions |
| **Automated Failover** | Detect and replace failed coordinators within 10 seconds |
| **Verifiable Randomness** | VRF-based selection prevents manipulation and pre-computation attacks |

**Cross-References:**
- Security constants: [03-security-trust.md](03-security-trust.md) Section 3
- FROST/DKG protocols: [04-cryptographic-protocols.md](04-cryptographic-protocols.md)
- Reputation thresholds: [09-defense-reputation.md](09-defense-reputation.md)

---

## VRF Selection Algorithm

### Seed Generation

Each operation generates a deterministic, unpredictable seed through a commit-reveal mechanism that prevents seed prediction attacks.

#### VRF Seed Commit-Reveal Protocol

The seed generation uses a two-phase commit-reveal scheme to ensure no participant can manipulate the selection outcome by timing node joins or predicting the seed:

```go
// VRFSeedCommitReveal implements secure seed generation with timing windows
type VRFSeedCommitReveal struct {
    Round           uint64
    CommitWindow    time.Duration  // 30 seconds for commits
    RevealWindow    time.Duration  // 30 seconds for reveals
    MinBlockGap     uint64         // Minimum 2 blocks between commit and reveal
    Commits         map[NodeID]*SeedCommit
    Reveals         map[NodeID]*SeedReveal
    FinalSeed       [32]byte
}

// SeedCommit contains the blinded commitment
type SeedCommit struct {
    CoordinatorID   NodeID
    CommitHash      [32]byte    // H(seed || blinding_factor)
    BlockHeight     uint64      // Block when commit was submitted
    Timestamp       int64
    TPMSignature    []byte
}

// SeedReveal exposes the actual seed value
type SeedReveal struct {
    CoordinatorID   NodeID
    Seed            []byte       // Actual seed value
    BlindingFactor  []byte       // Random blinding factor
    BlockHeight     uint64       // Must be >= CommitBlockHeight + MinBlockGap
    TPMSignature    []byte
}

// VRF seed timing constants (security critical, non-configurable)
const (
    SeedCommitWindow    = 30 * time.Second  // Window for submitting commits
    SeedRevealWindow    = 30 * time.Second  // Window for revealing seeds
    SeedMinBlockGap     = 2                  // Minimum blocks between commit and reveal
    SeedMinParticipants = 15                 // Minimum coordinators for valid seed
)
```

**Commit-Reveal Timeline:**

```
Time    0s              30s              60s              65s
        |               |                |                |
        +-- COMMIT WINDOW (30s) --+-- REVEAL WINDOW (30s) --+-- FINALIZE
        |                         |                          |
        |  Coordinators submit    |  Coordinators reveal     |  Compute
        |  H(seed || blinding)    |  actual seed values      |  final seed
        |                         |                          |
        |  BlockHeight recorded   |  Must be >= commit       |  XOR all
        |                         |  block + 2 blocks        |  valid reveals
```

**Security Properties:**
- **Commit Binding**: SHA256 commitment prevents changing seed after commit
- **Block Gap Requirement**: 2-block minimum prevents commit-reveal in same block
- **Timing Attack Prevention**: Commit window closes before reveals accepted
- **Multi-Party Combination**: Final seed XORs all valid reveals

```go
type OperationType uint8

const (
    OpDKG         OperationType = 1
    OpSigning     OperationType = 2
    OpKeyRotation OperationType = 3
)

// ComputeSeedCommitment creates the blinded commitment hash
func ComputeSeedCommitment(seed, blindingFactor []byte, nodeID NodeID) [32]byte {
    h := sha256.New()
    h.Write(seed)
    h.Write(blindingFactor)
    h.Write(nodeID[:])
    var hash [32]byte
    copy(hash[:], h.Sum(nil))
    return hash
}

// VerifySeedReveal checks that reveal matches commitment
func VerifySeedReveal(commit *SeedCommit, reveal *SeedReveal) error {
    // Verify block gap requirement
    if reveal.BlockHeight < commit.BlockHeight + SeedMinBlockGap {
        return &ErrInsufficientBlockGap{
            CommitBlock: commit.BlockHeight,
            RevealBlock: reveal.BlockHeight,
            MinGap:      SeedMinBlockGap,
        }
    }

    // Verify commitment matches reveal
    expectedCommit := ComputeSeedCommitment(reveal.Seed, reveal.BlindingFactor, reveal.CoordinatorID)
    if expectedCommit != commit.CommitHash {
        return ErrCommitRevealMismatch
    }

    return nil
}

// CombineSeedReveals creates final seed from all valid reveals
func CombineSeedReveals(reveals []*SeedReveal, opType OperationType) []byte {
    h := sha256.New()

    // Sort reveals by coordinator ID for deterministic ordering
    sort.Slice(reveals, func(i, j int) bool {
        return bytes.Compare(reveals[i].CoordinatorID[:], reveals[j].CoordinatorID[:]) < 0
    })

    // XOR all seed contributions
    var combined [32]byte
    for _, reveal := range reveals {
        seedHash := sha256.Sum256(reveal.Seed)
        for i := range combined {
            combined[i] ^= seedHash[i]
        }
    }

    // Add operation type for domain separation
    h.Write(combined[:])
    h.Write([]byte{byte(opType)})

    return h.Sum(nil)
}
```

**Properties:**
- **Deterministic**: Same inputs always produce same seed
- **Unpredictable**: Cannot be known before reveal phase completes
- **Verifiable**: Any participant can reconstruct and verify
- **Collision-Resistant**: SHA256 ensures unique seeds per operation
- **Timing-Attack Resistant**: Block gap prevents same-block manipulation

### Candidate Pool Selection

Only nodes meeting strict eligibility criteria enter the candidate pool:

```go
type EligibilityCriteria struct {
    MinReputation float64       // >= 0.95 (coordinator tier)
    MinUptime     float64       // >= 99% (30-day rolling average)
    MaxAttAge     time.Duration // < 24 hours (TPM attestation freshness)
    MinBandwidth  uint64        // >= 1 Gbps
}

var CoordinatorEligibility = EligibilityCriteria{
    MinReputation: 0.95,
    MinUptime:     0.99,
    MaxAttAge:     24 * time.Hour,
    MinBandwidth:  1_000_000_000, // 1 Gbps
}

func GetEligibleCandidates(nodes []Node, criteria EligibilityCriteria) []Node {
    eligible := make([]Node, 0)
    for _, node := range nodes {
        if node.Reputation < criteria.MinReputation ||
           node.Uptime30Day < criteria.MinUptime ||
           time.Since(node.LastAttestation) > criteria.MaxAttAge ||
           node.Bandwidth < criteria.MinBandwidth {
            continue
        }
        eligible = append(eligible, node)
    }
    return eligible
}
```

**Note:** Reputation thresholds defined in [09-defense-reputation.md](09-defense-reputation.md).

**Typical Pool Size**: 50,000-100,000 coordinator-tier nodes (from 1B+ total nodes)

### VRF Evaluation and Ranking

Each candidate evaluates the VRF with their private key:

```go
type VRFResult struct {
    NodeID NodeID
    Output []byte // VRF output (32 bytes)
    Proof  []byte // VRF proof (80 bytes)
}

func (n *Node) EvaluateVRF(seed []byte) (*VRFResult, error) {
    // ECVRF-ED25519-SHA512-Elligator2 (RFC 9381)
    output, proof := n.vrfKey.Prove(seed)
    return &VRFResult{
        NodeID: n.ID,
        Output: output,
        Proof:  proof,
    }, nil
}

func SelectCoordinators(seed []byte, candidates []Node, committeeSize int) ([]Node, error) {
    results := make([]VRFResult, 0, len(candidates))

    for _, c := range candidates {
        result, err := c.EvaluateVRF(seed)
        if err != nil {
            continue
        }
        if !VerifyVRFProof(c.VRFPublicKey, seed, result.Output, result.Proof) {
            continue
        }
        results = append(results, *result)
    }

    // Sort by VRF output (deterministic ordering)
    sort.Slice(results, func(i, j int) bool {
        return bytes.Compare(results[i].Output, results[j].Output) < 0
    })

    return selectWithDiversity(results, committeeSize)
}
```

**VRF Properties:**
- **Uniqueness**: Each seed produces unique output per node
- **Verifiability**: Anyone can verify VRF proof without knowing private key
- **Pseudorandomness**: Output indistinguishable from random
- **Unpredictability**: Cannot predict output before seed is known

### VRF Selection Edge Cases (FINAL DESIGN)

The VRF selection process must handle various edge cases to ensure robust coordinator selection:

#### VRF Key Rotation Mid-Session

```go
// VRF Key Binding - SECURITY-CRITICAL
//
// VRF public key rotation during an active session is NOT ALLOWED.
// The session uses the VRF key that was bound at selection time.
//
// Rationale:
// - Prevents coordinators from manipulating selection after being chosen
// - Ensures verification consistency across all participants
// - Prevents race conditions between key rotation and verification

type CommitteeMembership struct {
    CoordinatorID     NodeID
    VRFPublicKeyHash  [32]byte  // Hash of VRF public key at selection time
    SelectionProof    []byte    // VRF proof generated with this key
    SessionID         [32]byte  // Committee session identifier
    BoundAt           time.Time // When key was bound to this session
}

func (c *Committee) VerifyCoordinatorMembership(
    coordinatorID NodeID,
    proof []byte,
) error {
    membership := c.getMembership(coordinatorID)
    if membership == nil {
        return ErrNotCommitteeMember
    }

    // Verify proof was generated with the bound key
    currentKeyHash := sha256.Sum256(c.getCoordinatorVRFKey(coordinatorID))
    if !bytes.Equal(currentKeyHash[:], membership.VRFPublicKeyHash[:]) {
        return ErrVRFKeyRotatedDuringSession{
            CoordinatorID:    coordinatorID,
            BoundKeyHash:     membership.VRFPublicKeyHash,
            CurrentKeyHash:   currentKeyHash,
        }
    }

    return nil
}
```

#### Key Compromise Handling

```go
// VRF Key Compromise Protocol
//
// If a coordinator's VRF key is compromised during an active session:
// 1. Immediate exclusion from current committee
// 2. Remaining committee continues if quorum (7-of-21) is still met
// 3. If quorum is lost, emergency re-selection is triggered
// 4. Compromised coordinator reputation penalty: -0.75

const (
    VRFKeyCompromiseReputationPenalty = 0.75
    MinimumCommitteeQuorum           = 7  // 7-of-21 for BFT
)

func (c *Committee) HandleVRFKeyCompromise(coordinatorID NodeID) error {
    // Remove compromised coordinator
    c.removeCoordinator(coordinatorID)

    // Apply reputation penalty
    node := c.getNode(coordinatorID)
    node.Reputation -= VRFKeyCompromiseReputationPenalty
    c.reputationLog.Record(coordinatorID, "VRF_KEY_COMPROMISE", -0.75)

    // Check if quorum is still met
    if len(c.Coordinators) < MinimumCommitteeQuorum {
        c.logger.Error("committee quorum lost due to VRF key compromise",
            "remaining", len(c.Coordinators),
            "required", MinimumCommitteeQuorum)
        return c.triggerEmergencyReelection()
    }

    c.logger.Warn("coordinator excluded due to VRF key compromise",
        "coordinator", coordinatorID,
        "remaining", len(c.Coordinators))

    return nil
}
```

#### Insufficient Diversity Fallback

```go
// Diversity Fallback Strategy
//
// If initial diversity requirements cannot be met from candidate pool:
// 1. Reduce diversity requirements by 1 level
// 2. Retry selection with relaxed constraints
// 3. If still insufficient, use available candidates with warning logged
// 4. Never proceed with less than minimum BFT threshold (7 coordinators)

type DiversityLevel uint8

const (
    DiversityLevelStrict   DiversityLevel = 3  // 3+ regions, 3+ vendors
    DiversityLevelModerate DiversityLevel = 2  // 2+ regions, 2+ vendors
    DiversityLevelMinimal  DiversityLevel = 1  // Best effort diversity
)

func selectWithDiversityFallback(
    results []VRFResult,
    committeeSize int,
    level DiversityLevel,
) ([]Node, error) {
    var requirements DiversityRequirements

    switch level {
    case DiversityLevelStrict:
        requirements = DiversityRequirements{
            MinGeographicRegions: 3,
            MinTPMManufacturers:  3,
            MaxSameTier:          2,
        }
    case DiversityLevelModerate:
        requirements = DiversityRequirements{
            MinGeographicRegions: 2,
            MinTPMManufacturers:  2,
            MaxSameTier:          3,
        }
    case DiversityLevelMinimal:
        requirements = DiversityRequirements{
            MinGeographicRegions: 1,
            MinTPMManufacturers:  1,
            MaxSameTier:          5,
        }
    }

    selected, err := selectWithDiversity(results, committeeSize, requirements)
    if err == ErrInsufficientDiversity {
        if level > DiversityLevelMinimal {
            // Retry with reduced requirements
            logger.Warn("insufficient diversity, reducing requirements",
                "current_level", level,
                "next_level", level-1)
            return selectWithDiversityFallback(results, committeeSize, level-1)
        }

        // Even minimal diversity failed - use available candidates
        logger.Error("insufficient diversity at all levels, using available candidates",
            "candidates", len(results),
            "required", committeeSize)

        if len(results) < committeeSize {
            return nil, ErrInsufficientCandidates{
                Available: len(results),
                Required:  committeeSize,
            }
        }

        // Take first N candidates (already sorted by VRF output)
        nodes := make([]Node, committeeSize)
        for i := 0; i < committeeSize; i++ {
            nodes[i] = GetNodeByID(results[i].NodeID)
        }
        return nodes, nil
    }

    return selected, err
}
```

---

## Committee Formation Rules

### Diversity Requirements

Anti-collusion rules prevent concentration of power:

```go
type DiversityPolicy struct {
    MinGeographicRegions int // >= 3 different countries
    MinTPMManufacturers  int // >= 3 different vendors
    MaxSameTier          int // <= 2 from same reputation tier
}

var CommitteeDiversity = DiversityPolicy{
    MinGeographicRegions: 3,
    MinTPMManufacturers:  3,
    MaxSameTier:          2,
}

func selectWithDiversity(results []VRFResult, size int) ([]Node, error) {
    selected := make([]Node, 0, size)
    geoRegions := make(map[string]int)
    tpmVendors := make(map[string]int)
    repTiers := make(map[int]int)

    for _, r := range results {
        node := GetNodeByID(r.NodeID)

        // Enforce diversity constraints
        if geoRegions[node.Country]++; len(geoRegions) < CommitteeDiversity.MinGeographicRegions {
            if len(selected) == size-1 {
                continue
            }
        }
        if tpmVendors[node.TPMManufacturer]++; len(tpmVendors) < CommitteeDiversity.MinTPMManufacturers {
            if len(selected) == size-1 {
                continue
            }
        }

        tier := GetReputationTier(node.Reputation)
        if repTiers[tier] >= CommitteeDiversity.MaxSameTier {
            continue
        }
        repTiers[tier]++

        selected = append(selected, node)
        if len(selected) == size {
            break
        }
    }

    if len(selected) < size {
        return nil, ErrInsufficientDiversity
    }
    return selected, nil
}

func GetReputationTier(rep float64) int {
    switch {
    case rep >= 0.99:
        return 4 // Elite
    case rep >= 0.97:
        return 3 // Excellent
    case rep >= 0.95:
        return 2 // Good
    default:
        return 1 // Below coordinator threshold
    }
}
```

**Diversity Enforcement:**
- **Geographic**: Prevents nation-state attacks (3+ countries required)
- **Vendor**: Prevents TPM backdoor exploitation (3+ manufacturers required)
- **Reputation**: Prevents top-node oligopoly (max 2 from same tier)

### Committee Structure

```go
type CoordinatorRole uint8

const (
    RolePrimary   CoordinatorRole = 1 // Initiates proposals
    RoleValidator CoordinatorRole = 2 // Validates and votes
)

// CRITICAL: Committee Size and Threshold Selection
//
// A 5-node committee with 3-of-5 threshold creates a dangerous SPOF:
// - Only 2 compromised nodes needed to block consensus
// - All cross-shard transactions flow through this bottleneck
// - If 3 coordinators collude OR fail simultaneously, network halts
//
// Solution: Use 21-node committee with 7-of-21 threshold
// - Requires 7 compromised nodes to block (14 to take over)
// - Geographic + vendor + reputation diversity spread across 21 nodes
// - VRF rotation every epoch prevents persistent control
//
// Committee Size Justification:
// | Size | Threshold | To Block | To Control | Geographic Diversity |
// |------|-----------|----------|------------|---------------------|
// | 5    | 3         | 2        | 3          | 5 regions           |
// | 11   | 6         | 5        | 6          | 11 regions          |
// | 21   | 7         | 14       | 7          | 21 regions          | ← SELECTED
// | 33   | 11        | 22       | 11         | 33 regions          |

const (
    CommitteeSize     = 21  // Total committee members
    CommitteeThreshold = 7   // Minimum for consensus (BFT: n > 3f, f=6)
)

type Committee struct {
    SessionID     [32]byte
    OperationType OperationType
    Coordinators  []Coordinator
    Threshold     int // 7-of-21 (CommitteeThreshold)
    Seed          []byte
    Timestamp     int64
    Epoch         uint64         // Rotation epoch
    GeoDistribution []string      // Required: coordinators from different regions
}

type Coordinator struct {
    NodeID    NodeID
    Role      CoordinatorRole
    VRFProof  []byte
    PublicKey []byte
    Index     int // 0-20
    Region    string // Geographic region (required for diversity)
    Vendor    string // TPM vendor (required for diversity)
}

func FormCommittee(seed []byte, opType OperationType) (*Committee, error) {
    candidates := GetEligibleCandidates(GetAllNodes(), CoordinatorEligibility)

    // Select 21 coordinators with geographic and vendor diversity
    coordinators, err := SelectCoordinatorsWithDiversity(seed, candidates, CommitteeSize, DiversityRequirements{
        MinRegions:  15,  // At least 15 different geographic regions
        MinVendors:  3,   // At least 3 different TPM vendors
        MaxPerRegion: 2,  // Max 2 coordinators per region
        MaxPerVendor: 8,  // Max 8 coordinators per vendor
    })
    if err != nil {
        return nil, err
    }

    committee := &Committee{
        SessionID:     sha256.Sum256(seed),
        OperationType: opType,
        Threshold:     CommitteeThreshold,
        Seed:          seed,
        Timestamp:     time.Now().Unix(),
        Epoch:         getCurrentEpoch(),
    }

    for i, c := range coordinators {
        role := RoleValidator
        if i == 0 {
            role = RolePrimary
        }
        committee.Coordinators = append(committee.Coordinators, Coordinator{
            NodeID:    c.ID,
            Role:      role,
            VRFProof:  c.LastVRFProof,
            PublicKey: c.PublicKey,
            Index:     i,
        })
    }
    return committee, nil
}
```

### Coordinator Fencing Tokens

New coordinators must obtain authorization through a quorum-signed fencing token before they can act. This prevents split-brain scenarios and ensures smooth transitions between coordinators.

```go
// FencingToken authorizes a coordinator to act for a specific epoch
type FencingToken struct {
    Epoch           uint64        // Epoch this token authorizes
    CoordinatorID   NodeID        // Coordinator being authorized
    VRFProof        []byte        // VRF proof of valid selection
    CommitteeSession [32]byte     // Committee session identifier
    IssuedAt        int64         // Token creation timestamp
    ExpiresAt       int64         // Token expiration (epoch end)
    Signatures      []QuorumSignature  // 15-of-21 coordinator signatures
}

// QuorumSignature is a committee member's endorsement
type QuorumSignature struct {
    SignerID        NodeID
    SignerIndex     int           // Position in committee (0-20)
    Signature       []byte        // TPM-backed signature
    Timestamp       int64
}

// Fencing token constants (security critical)
const (
    FencingQuorumRequired   = 15    // 15-of-21 signatures required
    FencingTokenTTL         = 1 * time.Hour  // Token validity period
    FencingPublishTimeout   = 30 * time.Second
)
```

#### Token Acquisition Protocol

```go
// FencingTokenManager handles token acquisition and validation
type FencingTokenManager struct {
    currentToken    *FencingToken
    tokenStore      *DHTTokenStore
    committee       *Committee
    localNodeID     NodeID
    mu              sync.RWMutex
}

// AcquireFencingToken obtains quorum endorsement before acting
func (ftm *FencingTokenManager) AcquireFencingToken(
    ctx context.Context,
    epoch uint64,
    vrfProof []byte,
) (*FencingToken, error) {
    ftm.mu.Lock()
    defer ftm.mu.Unlock()

    // Create unsigned token
    token := &FencingToken{
        Epoch:           epoch,
        CoordinatorID:   ftm.localNodeID,
        VRFProof:        vrfProof,
        CommitteeSession: ftm.committee.SessionID,
        IssuedAt:        time.Now().Unix(),
        ExpiresAt:       time.Now().Add(FencingTokenTTL).Unix(),
        Signatures:      make([]QuorumSignature, 0, FencingQuorumRequired),
    }

    // Request signatures from committee members
    signaturesChan := make(chan *QuorumSignature, len(ftm.committee.Coordinators))
    for _, coord := range ftm.committee.Coordinators {
        if coord.NodeID == ftm.localNodeID {
            continue // Don't sign own token
        }
        go ftm.requestSignature(ctx, coord.NodeID, token, signaturesChan)
    }

    // Collect signatures until quorum reached or timeout
    collected := make(map[NodeID]*QuorumSignature)
    deadline := time.After(FencingPublishTimeout)

    for {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-deadline:
            if len(collected) >= FencingQuorumRequired {
                break
            }
            return nil, &ErrInsufficientFencingSignatures{
                Required: FencingQuorumRequired,
                Received: len(collected),
            }
        case sig := <-signaturesChan:
            if sig != nil {
                collected[sig.SignerID] = sig
                if len(collected) >= FencingQuorumRequired {
                    goto quorumReached
                }
            }
        }
    }

quorumReached:
    // Add collected signatures to token
    for _, sig := range collected {
        token.Signatures = append(token.Signatures, *sig)
    }

    // Publish token to DHT with PutIfAbsent (atomic)
    if err := ftm.publishToken(ctx, token); err != nil {
        return nil, fmt.Errorf("publishing fencing token: %w", err)
    }

    ftm.currentToken = token
    return token, nil
}

// publishToken atomically publishes the token to DHT
func (ftm *FencingTokenManager) publishToken(ctx context.Context, token *FencingToken) error {
    key := ftm.tokenKey(token.Epoch, token.CoordinatorID)
    tokenBytes, err := token.Marshal()
    if err != nil {
        return err
    }

    // PutIfAbsent ensures only one coordinator can claim this epoch
    success, err := ftm.tokenStore.PutIfAbsent(ctx, key, tokenBytes)
    if err != nil {
        return err
    }
    if !success {
        // Another coordinator already published a token for this epoch
        existingToken, _ := ftm.tokenStore.Get(ctx, key)
        return &ErrFencingTokenConflict{
            Epoch:            token.Epoch,
            ExistingCoordinator: existingToken.CoordinatorID,
        }
    }

    return nil
}

// ValidateFencingToken verifies a coordinator's authorization
func (ftm *FencingTokenManager) ValidateFencingToken(token *FencingToken) error {
    // Verify token is not expired
    if time.Now().Unix() > token.ExpiresAt {
        return ErrFencingTokenExpired
    }

    // Verify epoch matches current epoch
    currentEpoch := ftm.getCurrentEpoch()
    if token.Epoch != currentEpoch {
        return &ErrFencingTokenStaleEpoch{
            TokenEpoch:   token.Epoch,
            CurrentEpoch: currentEpoch,
        }
    }

    // Verify VRF proof shows valid selection
    if !ftm.verifyVRFSelection(token.CoordinatorID, token.VRFProof) {
        return ErrInvalidVRFProof
    }

    // Verify quorum signatures (15-of-21)
    validSigs := 0
    signers := make(map[NodeID]bool)
    for _, sig := range token.Signatures {
        // Verify signer is committee member
        if !ftm.committee.IsMember(sig.SignerID) {
            continue
        }
        // Verify no duplicate signers
        if signers[sig.SignerID] {
            continue
        }
        // Verify signature
        if ftm.verifyQuorumSignature(token, &sig) {
            validSigs++
            signers[sig.SignerID] = true
        }
    }

    if validSigs < FencingQuorumRequired {
        return &ErrInsufficientFencingSignatures{
            Required: FencingQuorumRequired,
            Received: validSigs,
        }
    }

    return nil
}
```

#### Message Validation with Fencing

All coordinator messages are rejected if the sender lacks a valid fencing token:

```go
// ValidateCoordinatorMessage checks fencing token before processing
func (node *PBFTNode) ValidateCoordinatorMessage(msg *CoordinatorMessage) error {
    // Get coordinator's fencing token from DHT
    token, err := node.fencingManager.GetTokenForCoordinator(msg.CoordinatorID, msg.Epoch)
    if err != nil {
        return &ErrNoFencingToken{
            CoordinatorID: msg.CoordinatorID,
            Epoch:         msg.Epoch,
        }
    }

    // Validate the token
    if err := node.fencingManager.ValidateFencingToken(token); err != nil {
        return &ErrInvalidFencingToken{
            CoordinatorID: msg.CoordinatorID,
            Reason:        err.Error(),
        }
    }

    // Token valid - allow message processing
    return nil
}
```

**Fencing Token Properties:**

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Quorum Authorization** | 15-of-21 signatures required | Prevents minority coordinator claims |
| **Atomic Publication** | PutIfAbsent in DHT | Only one coordinator per epoch |
| **VRF Binding** | Token includes VRF proof | Proves valid selection |
| **Time-Bounded** | 1-hour TTL | Prevents stale token reuse |
| **Message Rejection** | Nodes reject stale/invalid tokens | Prevents split-brain operations |

---

## PBFT Consensus Protocol

The committee uses a simplified PBFT for consensus on operation proposals.

### Protocol Phases

```
Primary                   Validators (4)              Network
   |                            |                        |
   | 1. PRE-PREPARE             |                        |
   |   (proposal + signature)   |                        |
   |--------------------------->|                        |
   |                            | 2. Validate proposal   |
   |      3. PREPARE            |                        |
   |   (proposal hash + vote)   |                        |
   |<---------------------------|                        |
   | 4. Collect PREPARE votes   |                        |
   |    (need 3/5 = 60%)        |                        |
   |      5. COMMIT             |                        |
   |<---------------------------|                        |
   |--------------------------->|                        |
   | 6. Collect COMMIT votes    |                        |
   | 7. COMMITTED               |                        |
   |------------------------------------------------------>|
```

### Phase 1: Pre-Prepare

Primary proposes operation parameters:

```go
type Proposal struct {
    SessionID     [32]byte
    OperationType OperationType
    Height        uint64 // Sequence number
    Payload       []byte // Operation-specific data
    PrimaryID     NodeID
    Timestamp     int64
    Signature     []byte
}

func (c *Coordinator) ProposeOperation(payload []byte) (*Proposal, error) {
    if c.Role != RolePrimary {
        return nil, ErrNotPrimary
    }

    proposal := &Proposal{
        SessionID:     c.committee.SessionID,
        OperationType: c.committee.OperationType,
        Height:        c.nextHeight(),
        Payload:       payload,
        PrimaryID:     c.NodeID,
        Timestamp:     time.Now().UnixMilli(),
    }

    hash := proposal.Hash()
    proposal.Signature = c.signWithTPM(hash)
    return proposal, c.broadcastToCommittee(proposal)
}
```

### Phase 2: Prepare

Validators vote on the proposal:

```go
type PrepareVote struct {
    SessionID      [32]byte
    ProposalHash   []byte
    ValidatorID    NodeID
    ValidatorIndex int
    Timestamp      int64
    Signature      []byte
}

func (c *Coordinator) ValidateAndPrepare(proposal *Proposal) (*PrepareVote, error) {
    // Verify proposal signature
    if !VerifySignature(proposal.PrimaryID, proposal.Hash(), proposal.Signature) {
        return nil, ErrInvalidProposalSignature
    }

    // Check timestamp freshness (within 5 seconds)
    if abs(time.Now().UnixMilli()-proposal.Timestamp) > 5000 {
        return nil, ErrProposalStale
    }

    if err := c.validatePayload(proposal); err != nil {
        return nil, err
    }

    vote := &PrepareVote{
        SessionID:      proposal.SessionID,
        ProposalHash:   proposal.Hash(),
        ValidatorID:    c.NodeID,
        ValidatorIndex: c.Index,
        Timestamp:      time.Now().UnixMilli(),
    }
    vote.Signature = c.signWithTPM(vote.Hash())
    return vote, c.broadcastToCommittee(vote)
}
```

### Phase 3: Commit

After collecting 3+ prepare votes, coordinators commit:

```go
type CommitVote struct {
    SessionID     [32]byte
    ProposalHash  []byte
    CoordinatorID NodeID
    PrepareVotes  []PrepareVote // Evidence of 3+ prepare votes
    Timestamp     int64
    Signature     []byte
}

func (c *Coordinator) Commit(proposal *Proposal, prepareVotes []PrepareVote) (*CommitVote, error) {
    if len(prepareVotes) < c.committee.Threshold {
        return nil, ErrInsufficientPrepareVotes{
            Required: c.committee.Threshold,
            Received: len(prepareVotes),
        }
    }

    uniqueValidators := make(map[NodeID]bool)
    for _, vote := range prepareVotes {
        if !VerifySignature(vote.ValidatorID, vote.Hash(), vote.Signature) {
            return nil, ErrInvalidPrepareVote
        }
        if !bytes.Equal(vote.ProposalHash, proposal.Hash()) {
            return nil, ErrPrepareHashMismatch
        }
        uniqueValidators[vote.ValidatorID] = true
    }

    if len(uniqueValidators) < c.committee.Threshold {
        return nil, ErrDuplicatePrepareVotes
    }

    commit := &CommitVote{
        SessionID:     proposal.SessionID,
        ProposalHash:  proposal.Hash(),
        CoordinatorID: c.NodeID,
        PrepareVotes:  prepareVotes,
        Timestamp:     time.Now().UnixMilli(),
    }
    commit.Signature = c.signWithTPM(commit.Hash())
    return commit, c.broadcastToCommittee(commit)
}
```

### Phase 4: Finalization

After collecting 3+ commit votes, operation is finalized:

```go
type FinalizedOperation struct {
    Proposal    Proposal
    CommitVotes []CommitVote
    FinalizedAt int64
}

func (c *Coordinator) Finalize(proposal *Proposal, commitVotes []CommitVote) (*FinalizedOperation, error) {
    if len(commitVotes) < c.committee.Threshold {
        return nil, ErrInsufficientCommitVotes
    }

    for _, commit := range commitVotes {
        if !VerifySignature(commit.CoordinatorID, commit.Hash(), commit.Signature) {
            return nil, ErrInvalidCommitVote
        }
        if len(commit.PrepareVotes) < c.committee.Threshold {
            return nil, ErrInvalidCommitEvidence
        }
    }

    finalized := &FinalizedOperation{
        Proposal:    *proposal,
        CommitVotes: commitVotes,
        FinalizedAt: time.Now().UnixMilli(),
    }
    return finalized, c.broadcastToNetwork(finalized)
}
```

### Consensus Latency

| Phase | Typical Time | Timeout |
|-------|--------------|---------|
| Pre-Prepare | 50ms | 5s |
| Prepare (3 votes) | 150ms | 10s |
| Commit (3 votes) | 200ms | 15s |
| Finalization | 100ms | 5s |
| **Total** | **~500ms** | **35s** |

### PBFT Phase Timeouts

Explicit timeout definitions for each PBFT phase are security-critical and ensure deterministic failure detection and view change behavior.

```go
// pkg/consensus/pbft_timeouts.go

// PBFTPhaseTimeouts defines explicit timeouts for each PBFT phase
// These are SECURITY-CRITICAL and must not be configurable
const (
    // Pre-prepare phase: Primary broadcasts proposal
    PrePrepareTimeout = 2 * time.Second

    // Prepare phase: Replicas acknowledge proposal
    PrepareTimeout = 3 * time.Second

    // Commit phase: Replicas commit to ordering
    CommitTimeout = 5 * time.Second

    // View change timeout: Trigger view change on primary failure
    ViewChangeTimeout = 10 * time.Second

    // New view timeout: Complete view change
    NewViewTimeout = 5 * time.Second

    // Checkpoint interval
    CheckpointInterval = 100  // Every 100 requests

    // Maximum concurrent requests before backpressure
    MaxConcurrentRequests = 1000

    // View change circuit breaker - max view changes before abort
    MaxViewChangesPerConsensusRound = 7
)

// PBFTTimeoutConfig holds all timeout parameters
type PBFTTimeoutConfig struct {
    PrePrepare    time.Duration
    Prepare       time.Duration
    Commit        time.Duration
    ViewChange    time.Duration
    NewView       time.Duration
    RequestExpiry time.Duration  // Client request timeout
}

var DefaultPBFTTimeouts = PBFTTimeoutConfig{
    PrePrepare:    PrePrepareTimeout,
    Prepare:       PrepareTimeout,
    Commit:        CommitTimeout,
    ViewChange:    ViewChangeTimeout,
    NewView:       NewViewTimeout,
    RequestExpiry: 30 * time.Second,
}

// PBFTPhase represents a phase in the protocol
type PBFTPhase uint8

const (
    PhaseIdle PBFTPhase = iota
    PhasePrePrepare
    PhasePrepare
    PhaseCommit
    PhaseViewChange
)

// PhaseTimer monitors phase timeouts and triggers view changes
type PhaseTimer struct {
    phase     PBFTPhase
    startTime time.Time
    timer     *time.Timer
    timeouts  PBFTTimeoutConfig
    onTimeout func(phase PBFTPhase)
}

func NewPhaseTimer(config PBFTTimeoutConfig, onTimeout func(PBFTPhase)) *PhaseTimer {
    return &PhaseTimer{
        phase:     PhaseIdle,
        timeouts:  config,
        onTimeout: onTimeout,
    }
}

// StartPhase begins timing for a new phase
func (pt *PhaseTimer) StartPhase(phase PBFTPhase) {
    pt.phase = phase
    pt.startTime = time.Now()
    
    var timeout time.Duration
    switch phase {
    case PhasePrePrepare:
        timeout = pt.timeouts.PrePrepare
    case PhasePrepare:
        timeout = pt.timeouts.Prepare
    case PhaseCommit:
        timeout = pt.timeouts.Commit
    case PhaseViewChange:
        timeout = pt.timeouts.ViewChange
    default:
        return
    }
    
    if pt.timer != nil {
        pt.timer.Stop()
    }
    
    pt.timer = time.AfterFunc(timeout, func() {
        pt.onTimeout(phase)
    })
}

// PhaseComplete stops the timer for completed phase
func (pt *PhaseTimer) PhaseComplete(phase PBFTPhase) {
    if pt.phase == phase && pt.timer != nil {
        pt.timer.Stop()
    }
}

// OnPhaseTimeout handles phase timeout events
func (node *PBFTNode) OnPhaseTimeout(phase PBFTPhase) {
    switch phase {
    case PhasePrePrepare, PhasePrepare, PhaseCommit:
        // Phase timeout indicates primary failure
        node.initiateViewChange(ViewChangeReasonTimeout, phase)
        
    case PhaseViewChange:
        // View change timeout - retry with higher view
        node.retryViewChange()
    }
}
```

#### PBFT Timeout Parameters

| Phase | Timeout | On Timeout Action |
|-------|---------|-------------------|
| **Pre-Prepare** | 2 seconds | Initiate view change |
| **Prepare** | 3 seconds | Re-broadcast prepare, escalate to view change |
| **Commit** | 5 seconds | Query peers for decision, commit if found |
| **View Change** | 10 seconds | Increment view number, retry |
| **New View** | 5 seconds | Retry view change |
| **Request Expiry** | 30 seconds | Return error to client |

#### Per-Phase Timeout Actions

Each PBFT phase has specific actions that must be taken when a timeout occurs:

| Phase | Timeout | Primary Action | Secondary Action | Final Escalation |
|-------|---------|----------------|------------------|------------------|
| **Pre-Prepare** | 2s | Initiate view change immediately | N/A | View change |
| **Prepare** | 3s | Re-broadcast PREPARE message | Wait 1s for responses | Escalate to view change if no progress |
| **Commit** | 5s | Query 3 random peers for commit decision | Apply decision if f+1 peers confirm | If no decision found, initiate view change |
| **View Change** | 10s | Increment view number | Retry view change with new primary | After 7 view changes, abort consensus round |

**Pre-Prepare Timeout (2 seconds)**:
- The primary has failed to propose within the expected window
- Immediately stop accepting messages from current primary
- Initiate view change to new primary

**Prepare Timeout (3 seconds)**:
- First, re-broadcast the PREPARE message to ensure delivery
- Wait an additional 1 second for responses
- If still insufficient prepares, escalate to view change
- Log which replicas have not responded for diagnostics

**Commit Timeout (5 seconds)**:
- Before aborting, query 3 random peers for their commit decision
- If f+1 peers report they have committed, apply the commit locally
- If peers report conflicting states, initiate view change
- This prevents unnecessary view changes due to message loss

**View Change Timeout (10 seconds)**:
- Increment the view number and retry with new primary
- The view change circuit breaker limits this to 7 attempts maximum
- After 7 view changes without progress, abort the consensus round entirely

#### View Change Circuit Breaker

To prevent livelock from repeated view changes, a circuit breaker limits the maximum number of view changes per consensus round:

```go
const (
    // Maximum view changes before aborting the consensus round
    MaxViewChangesPerConsensusRound = 7

    // After this many view changes, the round is aborted
    // and the request is returned to the client with an error
)
```

| View Change Count | Action |
|-------------------|--------|
| 1-3 | Normal view change, log warning |
| 4-5 | Critical alert, increase monitoring |
| 6 | Final attempt, prepare for abort |
| 7 | **Abort consensus round**, return error to client |

After 7 view changes, the system:
1. Aborts the current consensus round
2. Returns an error to the client indicating consensus failure
3. Logs detailed diagnostics for investigation
4. Triggers alerts for potential Byzantine behavior or network issues

#### Timeout Tuning Considerations

- Timeouts should be 2-3x expected network RTT
- Lower timeouts = faster failure detection but more false positives
- Higher timeouts = more tolerant but slower recovery
- View change timeout should be significantly higher to prevent thrashing
- The 7-view-change limit prevents infinite loops while allowing recovery from transient failures

### PBFT Timeout Cascade and Total Deadline (P4-H9)

Individual phase timeouts are insufficient - without a total deadline across all phases, a consensus round can livelock with repeated view changes. This section defines the cascade behavior and total deadline enforcement.

```go
// pkg/consensus/pbft_cascade.go

// PBFT Timeout Cascade - non-configurable security parameters
const (
    // Total deadline for entire consensus round (all phases + view changes)
    TotalConsensusDeadline = 60 * time.Second

    // Maximum view changes before aborting (circuit breaker)
    MaxViewChangesPerRound = 7

    // Escalating timeouts for repeated failures
    PhaseTimeoutMultiplier = 1.5  // Each retry increases timeout by 50%
    MaxPhaseTimeout        = 10 * time.Second  // Cap on individual phase timeout

    // Heartbeat for progress tracking
    ProgressCheckInterval  = 1 * time.Second
)

// PBFTCascadeController manages overall consensus round progress
type PBFTCascadeController struct {
    roundID            [32]byte
    roundStartTime     time.Time
    totalDeadline      time.Time

    // Phase tracking
    currentPhase       PBFTPhase
    phaseAttempts      map[PBFTPhase]int
    phaseStartTime     time.Time

    // View change tracking
    viewChangeCount    int
    currentView        uint64

    // Escalation state
    escalationLevel    EscalationLevel
    lastProgressTime   time.Time

    // Callbacks
    onDeadlineExceeded func(reason CascadeFailureReason)
    onProgressStall    func(stallDuration time.Duration)
}

type EscalationLevel uint8

const (
    EscalationNormal    EscalationLevel = iota // Normal operation
    EscalationWarning                          // Progress stalled > 10s
    EscalationCritical                         // Progress stalled > 20s
    EscalationAbort                            // Total deadline exceeded
)

type CascadeFailureReason uint8

const (
    CascadeReasonTotalDeadline   CascadeFailureReason = 1 // 60s total exceeded
    CascadeReasonMaxViewChanges  CascadeFailureReason = 2 // 3 view changes exhausted
    CascadeReasonProgressStall   CascadeFailureReason = 3 // No progress for 30s
    CascadeReasonQuorumLost      CascadeFailureReason = 4 // Insufficient replicas
)

// NewPBFTCascadeController creates a new cascade controller
func NewPBFTCascadeController(roundID [32]byte) *PBFTCascadeController {
    now := time.Now()
    return &PBFTCascadeController{
        roundID:          roundID,
        roundStartTime:   now,
        totalDeadline:    now.Add(TotalConsensusDeadline),
        phaseAttempts:    make(map[PBFTPhase]int),
        currentView:      0,
        escalationLevel:  EscalationNormal,
        lastProgressTime: now,
    }
}

// StartPhase begins a new phase with cascade-aware timeout
func (c *PBFTCascadeController) StartPhase(phase PBFTPhase) (time.Duration, error) {
    // Check total deadline
    if time.Now().After(c.totalDeadline) {
        c.escalationLevel = EscalationAbort
        return 0, &CascadeDeadlineError{
            Reason:     CascadeReasonTotalDeadline,
            Elapsed:    time.Since(c.roundStartTime),
            Phase:      c.currentPhase,
            ViewChanges: c.viewChangeCount,
        }
    }

    // Check max view changes
    if c.viewChangeCount >= MaxViewChangesPerRound {
        return 0, &CascadeDeadlineError{
            Reason:     CascadeReasonMaxViewChanges,
            ViewChanges: c.viewChangeCount,
        }
    }

    c.currentPhase = phase
    c.phaseStartTime = time.Now()
    c.phaseAttempts[phase]++

    // Calculate escalating timeout
    timeout := c.calculatePhaseTimeout(phase)

    // Ensure we don't exceed total deadline
    remaining := time.Until(c.totalDeadline)
    if timeout > remaining {
        timeout = remaining
    }

    c.lastProgressTime = time.Now()
    return timeout, nil
}

// calculatePhaseTimeout computes timeout with escalation multiplier
func (c *PBFTCascadeController) calculatePhaseTimeout(phase PBFTPhase) time.Duration {
    baseTimeout := getBaseTimeout(phase)
    attempts := c.phaseAttempts[phase]

    // Exponential backoff with multiplier
    multiplier := math.Pow(PhaseTimeoutMultiplier, float64(attempts-1))
    timeout := time.Duration(float64(baseTimeout) * multiplier)

    // Cap at max timeout
    if timeout > MaxPhaseTimeout {
        timeout = MaxPhaseTimeout
    }

    return timeout
}

func getBaseTimeout(phase PBFTPhase) time.Duration {
    switch phase {
    case PhasePrePrepare:
        return PrePrepareTimeout
    case PhasePrepare:
        return PrepareTimeout
    case PhaseCommit:
        return CommitTimeout
    case PhaseViewChange:
        return ViewChangeTimeout
    default:
        return 5 * time.Second
    }
}

// RecordProgress updates progress timestamp to reset stall detection
func (c *PBFTCascadeController) RecordProgress() {
    c.lastProgressTime = time.Now()
    if c.escalationLevel < EscalationAbort {
        c.escalationLevel = EscalationNormal
    }
}

// RecordViewChange increments view change counter
func (c *PBFTCascadeController) RecordViewChange() error {
    c.viewChangeCount++
    c.currentView++

    if c.viewChangeCount >= MaxViewChangesPerRound {
        return &CascadeDeadlineError{
            Reason:      CascadeReasonMaxViewChanges,
            ViewChanges: c.viewChangeCount,
        }
    }

    return nil
}

// CheckDeadlines verifies all cascade deadlines
func (c *PBFTCascadeController) CheckDeadlines() error {
    now := time.Now()

    // Check total deadline
    if now.After(c.totalDeadline) {
        return &CascadeDeadlineError{
            Reason:  CascadeReasonTotalDeadline,
            Elapsed: time.Since(c.roundStartTime),
        }
    }

    // Check progress stall
    stallDuration := now.Sub(c.lastProgressTime)
    switch {
    case stallDuration > 30*time.Second:
        return &CascadeDeadlineError{
            Reason:        CascadeReasonProgressStall,
            StallDuration: stallDuration,
        }
    case stallDuration > 20*time.Second:
        c.escalationLevel = EscalationCritical
        if c.onProgressStall != nil {
            c.onProgressStall(stallDuration)
        }
    case stallDuration > 10*time.Second:
        c.escalationLevel = EscalationWarning
    }

    return nil
}

// MonitorProgress runs background deadline monitoring
func (c *PBFTCascadeController) MonitorProgress(ctx context.Context) {
    ticker := time.NewTicker(ProgressCheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := c.CheckDeadlines(); err != nil {
                if c.onDeadlineExceeded != nil {
                    c.onDeadlineExceeded(err.(*CascadeDeadlineError).Reason)
                }
                return
            }
        }
    }
}

// GetRemainingTime returns time until total deadline
func (c *PBFTCascadeController) GetRemainingTime() time.Duration {
    return time.Until(c.totalDeadline)
}

// GetStatus returns current cascade status
func (c *PBFTCascadeController) GetStatus() *CascadeStatus {
    return &CascadeStatus{
        RoundID:         c.roundID,
        CurrentPhase:    c.currentPhase,
        CurrentView:     c.currentView,
        ViewChangeCount: c.viewChangeCount,
        Elapsed:         time.Since(c.roundStartTime),
        Remaining:       time.Until(c.totalDeadline),
        EscalationLevel: c.escalationLevel,
        LastProgress:    c.lastProgressTime,
    }
}

type CascadeStatus struct {
    RoundID         [32]byte
    CurrentPhase    PBFTPhase
    CurrentView     uint64
    ViewChangeCount int
    Elapsed         time.Duration
    Remaining       time.Duration
    EscalationLevel EscalationLevel
    LastProgress    time.Time
}

type CascadeDeadlineError struct {
    Reason        CascadeFailureReason
    Elapsed       time.Duration
    Phase         PBFTPhase
    ViewChanges   int
    StallDuration time.Duration
}

func (e *CascadeDeadlineError) Error() string {
    switch e.Reason {
    case CascadeReasonTotalDeadline:
        return fmt.Sprintf("pbft_cascade: total deadline exceeded (elapsed=%v, phase=%d)",
            e.Elapsed, e.Phase)
    case CascadeReasonMaxViewChanges:
        return fmt.Sprintf("pbft_cascade: max view changes exceeded (count=%d)",
            e.ViewChanges)
    case CascadeReasonProgressStall:
        return fmt.Sprintf("pbft_cascade: progress stalled (duration=%v)",
            e.StallDuration)
    default:
        return "pbft_cascade: unknown failure"
    }
}
```

**Cascade Timeline**:

```
Time 0s                    30s                    60s
  │                         │                      │
  │  ┌────────────────────────────────────────────────────────────┐
  │  │                  TOTAL DEADLINE (60s)                      │
  │  └────────────────────────────────────────────────────────────┘
  │                         │                      │
  │  ┌──────┐ ┌──────┐ ┌──────┐                   │
  │  │Phase1│ │Phase2│ │Phase3│ Normal            │
  │  └──────┘ └──────┘ └──────┘                   │
  │        │         │                            │
  │        │  TIMEOUT → View Change 1             │
  │        │         │                            │
  │        │  ┌──────┐ ┌──────┐ ┌──────┐         │
  │        │  │Phase1│ │Phase2│ │Phase3│ VC1     │
  │        │  └──────┘ └──────┘ └──────┘         │
  │        │              │                       │
  │        │       ... (View Changes 2-6) ...     │
  │        │              │                       │
  │        │            TIMEOUT → View Change 7   │
  │        │                   │                  │
  │        │            ┌──────────────────┐      │
  │        │            │ MAX_VIEW_CHANGES │      │
  │        │            │  (7) - ABORT     │      │
  │        │            └──────────────────┘      │
  │                                               │
  └───────────────────────────────────────────────┘
```

**Cascade Thresholds**:

| Threshold | Value | Action |
|-----------|-------|--------|
| Total deadline | 60 seconds | Abort round, return error to client |
| Max view changes | 7 | Abort round, suspect Byzantine primary |
| Progress warning | 10 seconds | Log warning, increase monitoring |
| Progress critical | 20 seconds | Alert, prepare for abort |
| Progress stall | 30 seconds | Abort round, investigate |

**Escalation Behavior**:

| Level | Trigger | Actions |
|-------|---------|---------|
| NORMAL | Progress within 10s | Standard operation |
| WARNING | No progress 10-20s | Increase log verbosity, alert monitoring |
| CRITICAL | No progress 20-30s | Prepare abort, check replica health |
| ABORT | No progress 30s+ OR total deadline | Abort round, return error, log for analysis |

### Byzantine Primary Detection (FINAL DESIGN)

The PBFT protocol must detect and handle Byzantine (malicious or faulty) primary coordinators through equivocation detection, message deduplication, and out-of-order handling.

#### Equivocation Detection

```go
// Byzantine Primary Equivocation
//
// If a validator receives conflicting pre-prepares from the primary
// (same view and sequence but different payloads), this is evidence
// of Byzantine behavior. The validator must:
// 1. Broadcast equivocation evidence to all coordinators
// 2. Immediately exclude the primary from the committee
// 3. Apply reputation penalty: -0.50
// 4. Initiate view change to new primary

const (
    EquivocationReputationPenalty = 0.50
)

type EquivocationEvidence struct {
    ViewNumber      uint64
    SequenceNumber  uint64
    PrimaryID       NodeID
    PrePrepare1     *PrePrepareMessage  // First pre-prepare
    PrePrepare2     *PrePrepareMessage  // Conflicting pre-prepare
    DetectorID      NodeID              // Validator who detected
    DetectedAt      time.Time
    TPMQuote        []byte              // TPM-attested evidence
    Signature       []byte              // Detector's signature
}

func (v *Validator) DetectEquivocation(
    pp1 *PrePrepareMessage,
    pp2 *PrePrepareMessage,
) (*EquivocationEvidence, error) {
    // Check if this is actual equivocation
    if pp1.ViewNumber != pp2.ViewNumber ||
       pp1.SequenceNumber != pp2.SequenceNumber {
        return nil, ErrNotEquivocation
    }

    if bytes.Equal(pp1.Hash(), pp2.Hash()) {
        return nil, ErrNotEquivocation
    }

    if pp1.PrimaryID != pp2.PrimaryID {
        return nil, ErrDifferentPrimaries
    }

    // Verify both pre-prepares are validly signed by the primary
    if err := v.verifyPrePrepareSignature(pp1); err != nil {
        return nil, fmt.Errorf("invalid first pre-prepare: %w", err)
    }
    if err := v.verifyPrePrepareSignature(pp2); err != nil {
        return nil, fmt.Errorf("invalid second pre-prepare: %w", err)
    }

    // Create TPM-attested evidence
    evidence := &EquivocationEvidence{
        ViewNumber:     pp1.ViewNumber,
        SequenceNumber: pp1.SequenceNumber,
        PrimaryID:      pp1.PrimaryID,
        PrePrepare1:    pp1,
        PrePrepare2:    pp2,
        DetectorID:     v.nodeID,
        DetectedAt:     time.Now(),
    }

    // Bind evidence to TPM state
    evidence.TPMQuote = v.tpm.Quote(evidence.Hash())
    evidence.Signature = v.signWithTPM(evidence.Hash())

    return evidence, nil
}

func (c *Committee) HandleEquivocationEvidence(
    evidence *EquivocationEvidence,
) error {
    // Verify evidence is valid
    if err := c.verifyEquivocationEvidence(evidence); err != nil {
        return fmt.Errorf("invalid equivocation evidence: %w", err)
    }

    // Immediate exclusion
    c.removeCoordinator(evidence.PrimaryID)

    // Apply reputation penalty
    node := c.getNode(evidence.PrimaryID)
    node.Reputation -= EquivocationReputationPenalty
    c.reputationLog.Record(evidence.PrimaryID, "BYZANTINE_EQUIVOCATION", -0.50)

    c.logger.Error("byzantine primary detected and excluded",
        "primary", evidence.PrimaryID,
        "view", evidence.ViewNumber,
        "sequence", evidence.SequenceNumber,
        "detector", evidence.DetectorID)

    // Broadcast evidence to all coordinators
    c.broadcastToCommittee(evidence)

    // Initiate view change
    return c.initiateViewChange(ViewChangeReasonMalicious, evidence)
}
```

#### Message Deduplication

```go
// Out-of-Order Message Handling
//
// Validators must buffer out-of-order messages and deduplicate
// to prevent replay attacks and resource exhaustion.
//
// Configuration:
// - Buffer up to 1000 messages per validator
// - 60-second message expiry
// - Bloom filter with 1-hour TTL for deduplication

const (
    MaxBufferedMessagesPerValidator = 1000
    MessageExpiryDuration          = 60 * time.Second
    BloomFilterTTL                 = 1 * time.Hour
    BloomFilterFalsePositiveRate   = 0.001  // 0.1%
)

type MessageBuffer struct {
    mu           sync.RWMutex
    messages     map[NodeID]*ValidatorMessageQueue
    bloomFilter  *bloom.BloomFilter  // Deduplication
    cleanupTimer *time.Timer
}

type ValidatorMessageQueue struct {
    validatorID NodeID
    messages    []*BufferedMessage
    messageMap  map[[32]byte]int  // Hash -> index for fast lookup
    maxSize     int
}

type BufferedMessage struct {
    Message     interface{}  // PBFTMessage
    MessageHash [32]byte     // SHA256(message)
    UUID        uuid.UUID    // UUID v7 for ordering
    ReceivedAt  time.Time
    ExpiresAt   time.Time
}

func NewMessageBuffer() *MessageBuffer {
    // Bloom filter sized for 1M messages with 0.1% false positive rate
    bf := bloom.NewWithEstimates(1_000_000, BloomFilterFalsePositiveRate)

    mb := &MessageBuffer{
        messages:    make(map[NodeID]*ValidatorMessageQueue),
        bloomFilter: bf,
    }

    mb.startCleanupTimer()
    return mb
}

func (mb *MessageBuffer) AddMessage(
    validatorID NodeID,
    msg interface{},
) error {
    mb.mu.Lock()
    defer mb.mu.Unlock()

    // Compute message hash for deduplication
    msgHash := computeMessageHash(msg)

    // Check bloom filter first (fast path)
    if mb.bloomFilter.Test(msgHash[:]) {
        // Might be duplicate - verify with precise check
        if mb.isDuplicate(validatorID, msgHash) {
            return ErrDuplicateMessage{
                ValidatorID: validatorID,
                MessageHash: msgHash,
            }
        }
    }

    // Add to bloom filter
    mb.bloomFilter.Add(msgHash[:])

    // Get or create validator queue
    queue := mb.messages[validatorID]
    if queue == nil {
        queue = &ValidatorMessageQueue{
            validatorID: validatorID,
            messages:    make([]*BufferedMessage, 0, MaxBufferedMessagesPerValidator),
            messageMap:  make(map[[32]byte]int),
            maxSize:     MaxBufferedMessagesPerValidator,
        }
        mb.messages[validatorID] = queue
    }

    // Check queue size
    if len(queue.messages) >= queue.maxSize {
        // Remove oldest message
        oldest := queue.messages[0]
        queue.messages = queue.messages[1:]
        delete(queue.messageMap, oldest.MessageHash)
    }

    // Add message
    buffered := &BufferedMessage{
        Message:     msg,
        MessageHash: msgHash,
        UUID:        uuid.Must(uuid.NewV7()),  // UUID v7 for time-based ordering
        ReceivedAt:  time.Now(),
        ExpiresAt:   time.Now().Add(MessageExpiryDuration),
    }

    queue.messages = append(queue.messages, buffered)
    queue.messageMap[msgHash] = len(queue.messages) - 1

    return nil
}

func (mb *MessageBuffer) isDuplicate(
    validatorID NodeID,
    msgHash [32]byte,
) bool {
    queue := mb.messages[validatorID]
    if queue == nil {
        return false
    }

    _, exists := queue.messageMap[msgHash]
    return exists
}

func (mb *MessageBuffer) cleanupExpired() {
    mb.mu.Lock()
    defer mb.mu.Unlock()

    now := time.Now()

    for validatorID, queue := range mb.messages {
        i := 0
        for _, msg := range queue.messages {
            if now.Before(msg.ExpiresAt) {
                queue.messages[i] = msg
                i++
            } else {
                delete(queue.messageMap, msg.MessageHash)
            }
        }
        queue.messages = queue.messages[:i]

        // Remove empty queues
        if len(queue.messages) == 0 {
            delete(mb.messages, validatorID)
        }
    }
}

func (mb *MessageBuffer) startCleanupTimer() {
    mb.cleanupTimer = time.AfterFunc(MessageExpiryDuration, func() {
        mb.cleanupExpired()
        mb.startCleanupTimer()  // Restart timer
    })
}
```

### View Change Protocol Specification

The view change protocol enables the committee to safely transition from a failed or malicious primary to a new primary while preserving safety and liveness guarantees.

#### View Change Message Types

```go
// pkg/consensus/viewchange.go

// ViewChangeReason identifies why a view change was initiated
type ViewChangeReason uint8

const (
    ViewChangeReasonTimeout      ViewChangeReason = 1 // Primary unresponsive
    ViewChangeReasonMalicious    ViewChangeReason = 2 // Primary equivocation detected
    ViewChangeReasonPartition    ViewChangeReason = 3 // Network partition suspected
    ViewChangeReasonExplicit     ViewChangeReason = 4 // Coordinator initiated
)

// ViewChangeMessage is sent by a replica to initiate view change
// CRITICAL: All fields must be signed and verified
type ViewChangeMessage struct {
    // Header
    Type           MessageType   // VIEW_CHANGE
    ViewNumber     uint64        // New view number (current view + 1)
    ReplicaID      NodeID        // Sending replica
    SessionID      [32]byte      // Committee session

    // Proof of validity
    LastStableCheckpoint   *Checkpoint  // Most recent stable checkpoint
    CheckpointProofs       []CheckpointProof // 7-of-21 signatures on checkpoint
    PreparedProofs         []PreparedProof   // Prepared requests since checkpoint

    // Reason and evidence
    Reason         ViewChangeReason
    Evidence       []byte        // TPM-attested evidence if malicious

    // Authentication (REQUIRED)
    Timestamp      int64         // Milliseconds since epoch
    TPMQuote       []byte        // TPM quote binding message to current PCR state
    Signature      []byte        // TPM-backed ECDSA signature over all fields
}

// PreparedProof proves a request was prepared in a previous view
type PreparedProof struct {
    Request        *ClientRequest
    ViewNumber     uint64
    PrePrepare     *PrePrepareMessage
    Prepares       []PrepareMessage  // 14+ prepare messages (2f+1 for f=6)
}

// NewViewMessage is sent by the new primary to complete view change
type NewViewMessage struct {
    // Header
    Type           MessageType   // NEW_VIEW
    ViewNumber     uint64        // New view number
    PrimaryID      NodeID        // New primary (must match view number)
    SessionID      [32]byte

    // Collected proofs
    ViewChangeSet  []ViewChangeMessage  // 7+ valid view change messages

    // New primary's prepared state
    PrePrepareSet  []PrePrepareMessage  // Pre-prepares for requests to re-execute

    // Authentication (REQUIRED)
    Timestamp      int64
    TPMQuote       []byte
    Signature      []byte
}
```

#### View Change Protocol Flow

```
    REPLICA (detects timeout)              ALL REPLICAS              NEW PRIMARY
    ========================              =============              ===========
              |                                 |                         |
    1. Timeout on current view                 |                         |
              |                                 |                         |
              v                                 |                         |
    2. Stop accepting messages                 |                         |
       from current primary                    |                         |
              |                                 |                         |
              v                                 |                         |
    3. Increment view number                   |                         |
              |                                 |                         |
              v                                 |                         |
    4. Create ViewChangeMessage                |                         |
       - Include last checkpoint               |                         |
       - Include all prepared proofs           |                         |
       - Sign with TPM                         |                         |
              |                                 |                         |
              +------ VIEW_CHANGE ------------>|                         |
                                               |                         |
                                               v                         |
                                    5. Verify signature                  |
                                       and TPM quote                     |
                                               |                         |
                                               |--- Forward to new ----->|
                                               |    primary              |
                                                                         |
                                                                         v
                                               |          6. Collect 7+ valid VIEW_CHANGE
                                               |                         |
                                               |                         v
                                               |          7. Create NewViewMessage
                                               |             - Include all VIEW_CHANGE messages
                                               |             - Compute PRE-PREPARE set
                                               |             - Sign with TPM
                                               |                         |
                                               |<---- NEW_VIEW ----------+
                                               |                         |
                                               v                         |
                                    8. Verify NEW_VIEW                   |
                                       - Check 7+ valid view changes     |
                                       - Verify pre-prepare set          |
                                       - Verify new primary signature    |
                                               |                         |
                                               v                         |
                                    9. Accept new view                   |
                                       Resume normal operation           |
```

#### View Change Signature Verification

```go
// VerifyViewChangeMessage performs comprehensive validation
func (node *PBFTNode) VerifyViewChangeMessage(msg *ViewChangeMessage) error {
    // 1. Verify timestamp freshness (prevent replay)
    if abs(time.Now().UnixMilli()-msg.Timestamp) > ViewChangeTimestampWindow {
        return ErrViewChangeTimestampStale
    }

    // 2. Verify TPM quote binds message to sender's current state
    if err := node.verifyTPMQuote(msg.ReplicaID, msg.TPMQuote, msg.Hash()); err != nil {
        return fmt.Errorf("TPM quote verification failed: %w", err)
    }

    // 3. Verify message signature
    pubKey := node.getReplicaPublicKey(msg.ReplicaID)
    if !ecdsa.Verify(pubKey, msg.Hash(), msg.Signature) {
        return ErrViewChangeSignatureInvalid
    }

    // 4. Verify sender is a valid committee member
    if !node.committee.IsMember(msg.ReplicaID) {
        return ErrViewChangeSenderNotMember
    }

    // 5. Verify view number is exactly current view + 1
    if msg.ViewNumber != node.currentView+1 {
        return ErrViewChangeInvalidViewNumber
    }

    // 6. Verify checkpoint proofs
    if err := node.verifyCheckpointProofs(msg.LastStableCheckpoint, msg.CheckpointProofs); err != nil {
        return fmt.Errorf("checkpoint proof invalid: %w", err)
    }

    // 7. Verify prepared proofs
    for _, proof := range msg.PreparedProofs {
        if err := node.verifyPreparedProof(&proof); err != nil {
            return fmt.Errorf("prepared proof invalid: %w", err)
        }
    }

    return nil
}

// VerifyNewViewMessage validates the new primary's NEW_VIEW message
func (node *PBFTNode) VerifyNewViewMessage(msg *NewViewMessage) error {
    // 1. Verify timestamp freshness
    if abs(time.Now().UnixMilli()-msg.Timestamp) > NewViewTimestampWindow {
        return ErrNewViewTimestampStale
    }

    // 2. Verify the claimed primary matches view number
    expectedPrimary := node.committee.Coordinators[msg.ViewNumber%uint64(len(node.committee.Coordinators))]
    if msg.PrimaryID != expectedPrimary.NodeID {
        return ErrNewViewInvalidPrimary
    }

    // 3. Verify TPM quote
    if err := node.verifyTPMQuote(msg.PrimaryID, msg.TPMQuote, msg.Hash()); err != nil {
        return fmt.Errorf("new primary TPM quote failed: %w", err)
    }

    // 4. Verify signature
    pubKey := node.getReplicaPublicKey(msg.PrimaryID)
    if !ecdsa.Verify(pubKey, msg.Hash(), msg.Signature) {
        return ErrNewViewSignatureInvalid
    }

    // 5. Verify quorum of valid view change messages (7-of-21)
    if len(msg.ViewChangeSet) < node.committee.Threshold {
        return ErrNewViewInsufficientViewChanges
    }

    validCount := 0
    for _, vc := range msg.ViewChangeSet {
        if err := node.VerifyViewChangeMessage(&vc); err == nil {
            validCount++
        }
    }
    if validCount < node.committee.Threshold {
        return ErrNewViewInsufficientValidViewChanges
    }

    // 6. Verify pre-prepare set is correctly computed from view changes
    expectedPrePrepares := node.computeExpectedPrePrepares(msg.ViewChangeSet)
    if !equalPrePrepareSets(msg.PrePrepareSet, expectedPrePrepares) {
        return ErrNewViewInvalidPrePrepareSet
    }

    return nil
}

// ViewChange security constants
const (
    ViewChangeTimestampWindow = 30 * time.Second  // Max clock skew for view change
    NewViewTimestampWindow    = 30 * time.Second  // Max clock skew for new view
    ViewChangeQuorum          = 7                  // 7-of-21 for view change
)
```

### View Change Ordering and Deduplication (P4-M11)

**CRITICAL**: Without proper ordering and deduplication of VIEW_CHANGE messages, the protocol is vulnerable to:
- Duplicate counting (same replica counted twice toward quorum)
- Ordering attacks (selecting favorable subset of view changes)
- Replay attacks (old view changes reused in new views)

**Invariant**: Exactly ONE view change message per replica per view number.

```go
// pkg/consensus/viewchange_ordering.go

// ViewChangeTracker ensures exactly one VIEW_CHANGE per replica per view
type ViewChangeTracker struct {
    mu                sync.RWMutex

    // Per-view tracking: viewNumber -> replicaID -> message
    viewChanges       map[uint64]map[NodeID]*ViewChangeMessage

    // Ordering: viewNumber -> ordered list of (replicaID, receiveTime)
    receiveOrder      map[uint64][]ViewChangeReceipt

    // Duplicate detection: hash(viewNumber, replicaID) -> first seen timestamp
    seen              map[[32]byte]int64

    // Metrics
    duplicatesRejected atomic.Uint64
    invalidRejected    atomic.Uint64
}

// ViewChangeReceipt records when a view change was received
type ViewChangeReceipt struct {
    ReplicaID    NodeID
    ViewNumber   uint64
    ReceivedAt   time.Time
    MessageHash  [32]byte
}

// NewViewChangeTracker creates a new tracker
func NewViewChangeTracker() *ViewChangeTracker {
    return &ViewChangeTracker{
        viewChanges:  make(map[uint64]map[NodeID]*ViewChangeMessage),
        receiveOrder: make(map[uint64][]ViewChangeReceipt),
        seen:         make(map[[32]byte]int64),
    }
}

// ViewChangeDuplicateError indicates a duplicate view change was received
type ViewChangeDuplicateError struct {
    ReplicaID      NodeID
    ViewNumber     uint64
    OriginalTime   time.Time
    DuplicateTime  time.Time
}

func (e *ViewChangeDuplicateError) Error() string {
    return fmt.Sprintf(
        "duplicate VIEW_CHANGE from replica %x for view %d (original: %v, duplicate: %v)",
        e.ReplicaID[:8], e.ViewNumber, e.OriginalTime, e.DuplicateTime,
    )
}

// ViewChangeOrderViolationError indicates an ordering constraint was violated
type ViewChangeOrderViolationError struct {
    ReplicaID      NodeID
    ViewNumber     uint64
    CurrentView    uint64
    Reason         string
}

func (e *ViewChangeOrderViolationError) Error() string {
    return fmt.Sprintf(
        "VIEW_CHANGE ordering violation from %x: view %d (current: %d) - %s",
        e.ReplicaID[:8], e.ViewNumber, e.CurrentView, e.Reason,
    )
}

// RecordViewChange records a VIEW_CHANGE message with deduplication
// Returns error if duplicate or ordering violation detected
func (t *ViewChangeTracker) RecordViewChange(
    msg *ViewChangeMessage,
    currentView uint64,
) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    now := time.Now()

    // 1. Check view number ordering
    if msg.ViewNumber < currentView {
        t.invalidRejected.Add(1)
        return &ViewChangeOrderViolationError{
            ReplicaID:   msg.ReplicaID,
            ViewNumber:  msg.ViewNumber,
            CurrentView: currentView,
            Reason:      "view number less than current view",
        }
    }

    if msg.ViewNumber > currentView+1 {
        // Future view change - could be partition recovery, but suspicious
        t.invalidRejected.Add(1)
        return &ViewChangeOrderViolationError{
            ReplicaID:   msg.ReplicaID,
            ViewNumber:  msg.ViewNumber,
            CurrentView: currentView,
            Reason:      "view number too far ahead (max: current+1)",
        }
    }

    // 2. Check for duplicate from same replica for same view
    dedupeKey := computeViewChangeDedupeKey(msg.ViewNumber, msg.ReplicaID)
    if firstSeen, exists := t.seen[dedupeKey]; exists {
        t.duplicatesRejected.Add(1)
        return &ViewChangeDuplicateError{
            ReplicaID:     msg.ReplicaID,
            ViewNumber:    msg.ViewNumber,
            OriginalTime:  time.UnixMilli(firstSeen),
            DuplicateTime: now,
        }
    }

    // 3. Initialize per-view maps if needed
    if t.viewChanges[msg.ViewNumber] == nil {
        t.viewChanges[msg.ViewNumber] = make(map[NodeID]*ViewChangeMessage)
        t.receiveOrder[msg.ViewNumber] = make([]ViewChangeReceipt, 0)
    }

    // 4. Double-check no existing message from this replica
    if _, exists := t.viewChanges[msg.ViewNumber][msg.ReplicaID]; exists {
        // This shouldn't happen if seen map is correct, but defense in depth
        t.duplicatesRejected.Add(1)
        return &ViewChangeDuplicateError{
            ReplicaID:     msg.ReplicaID,
            ViewNumber:    msg.ViewNumber,
            OriginalTime:  time.Time{}, // Unknown
            DuplicateTime: now,
        }
    }

    // 5. Record the view change
    t.seen[dedupeKey] = now.UnixMilli()
    t.viewChanges[msg.ViewNumber][msg.ReplicaID] = msg
    t.receiveOrder[msg.ViewNumber] = append(t.receiveOrder[msg.ViewNumber], ViewChangeReceipt{
        ReplicaID:   msg.ReplicaID,
        ViewNumber:  msg.ViewNumber,
        ReceivedAt:  now,
        MessageHash: sha256.Sum256(msg.Hash()),
    })

    return nil
}

// computeViewChangeDedupeKey creates a unique key for deduplication
func computeViewChangeDedupeKey(viewNumber uint64, replicaID NodeID) [32]byte {
    h := sha256.New()
    binary.Write(h, binary.BigEndian, viewNumber)
    h.Write(replicaID[:])
    var key [32]byte
    copy(key[:], h.Sum(nil))
    return key
}

// GetViewChangesForView returns all view changes for a specific view
// Messages are returned in receive order for deterministic processing
func (t *ViewChangeTracker) GetViewChangesForView(viewNumber uint64) []*ViewChangeMessage {
    t.mu.RLock()
    defer t.mu.RUnlock()

    receipts := t.receiveOrder[viewNumber]
    if receipts == nil {
        return nil
    }

    messages := make([]*ViewChangeMessage, 0, len(receipts))
    viewMap := t.viewChanges[viewNumber]

    // Return in receive order for deterministic processing
    for _, receipt := range receipts {
        if msg, exists := viewMap[receipt.ReplicaID]; exists {
            messages = append(messages, msg)
        }
    }

    return messages
}

// GetViewChangeCount returns the number of unique view changes for a view
func (t *ViewChangeTracker) GetViewChangeCount(viewNumber uint64) int {
    t.mu.RLock()
    defer t.mu.RUnlock()

    if viewMap := t.viewChanges[viewNumber]; viewMap != nil {
        return len(viewMap)
    }
    return 0
}

// HasQuorum checks if sufficient view changes have been received
func (t *ViewChangeTracker) HasQuorum(viewNumber uint64, threshold int) bool {
    return t.GetViewChangeCount(viewNumber) >= threshold
}

// CleanupOldViews removes tracking data for views older than the specified view
func (t *ViewChangeTracker) CleanupOldViews(currentView uint64) {
    t.mu.Lock()
    defer t.mu.Unlock()

    for viewNum := range t.viewChanges {
        if viewNum < currentView {
            // Remove view change messages
            delete(t.viewChanges, viewNum)
            delete(t.receiveOrder, viewNum)
        }
    }

    // Remove old seen entries
    for key := range t.seen {
        // Extract view number from key (it's hashed, so we need to iterate)
        // For efficiency, we track view numbers separately or use TTL-based cleanup
    }
}

// GetDuplicateStats returns duplicate rejection statistics
func (t *ViewChangeTracker) GetDuplicateStats() (duplicates, invalid uint64) {
    return t.duplicatesRejected.Load(), t.invalidRejected.Load()
}
```

**Ordering Guarantees for NewViewMessage Construction:**

```go
// pkg/consensus/newview_ordering.go

// BuildNewViewMessage constructs a NEW_VIEW message with deterministic ordering
// CRITICAL: The ViewChangeSet MUST be ordered deterministically to ensure
// all replicas compute the same pre-prepare set
func (node *PBFTNode) BuildNewViewMessage(viewNumber uint64) (*NewViewMessage, error) {
    // 1. Get all view changes for this view
    viewChanges := node.viewChangeTracker.GetViewChangesForView(viewNumber)

    // 2. Verify we have quorum
    if len(viewChanges) < ViewChangeQuorum {
        return nil, &InsufficientViewChangesError{
            ViewNumber: viewNumber,
            Required:   ViewChangeQuorum,
            Received:   len(viewChanges),
        }
    }

    // 3. Sort view changes deterministically (by ReplicaID for consistency)
    sortedViewChanges := make([]*ViewChangeMessage, len(viewChanges))
    copy(sortedViewChanges, viewChanges)
    sort.Slice(sortedViewChanges, func(i, j int) bool {
        return bytes.Compare(
            sortedViewChanges[i].ReplicaID[:],
            sortedViewChanges[j].ReplicaID[:],
        ) < 0
    })

    // 4. Select exactly ViewChangeQuorum messages (first N after sorting)
    // This ensures deterministic selection across all replicas
    selectedViewChanges := sortedViewChanges[:ViewChangeQuorum]

    // 5. Compute pre-prepare set from selected view changes
    prePrepareSet := node.computePrePrepareSet(selectedViewChanges)

    // 6. Build the message
    msg := &NewViewMessage{
        Type:          MessageTypeNewView,
        ViewNumber:    viewNumber,
        PrimaryID:     node.nodeID,
        SessionID:     node.sessionID,
        ViewChangeSet: make([]ViewChangeMessage, len(selectedViewChanges)),
        PrePrepareSet: prePrepareSet,
        Timestamp:     time.Now().UnixMilli(),
    }

    // 7. Copy view changes (deep copy to avoid mutation)
    for i, vc := range selectedViewChanges {
        msg.ViewChangeSet[i] = *vc
    }

    // 8. Sign with TPM
    if err := node.signNewViewMessage(msg); err != nil {
        return nil, fmt.Errorf("sign NEW_VIEW: %w", err)
    }

    return msg, nil
}

// computePrePrepareSet determines which requests need re-preparation
// based on the collected view changes
func (node *PBFTNode) computePrePrepareSet(viewChanges []*ViewChangeMessage) []PrePrepareMessage {
    // Find the highest stable checkpoint across all view changes
    maxCheckpoint := findMaxStableCheckpoint(viewChanges)

    // Collect all prepared proofs across all view changes
    preparedRequests := make(map[[32]byte]*PreparedProof)
    for _, vc := range viewChanges {
        for _, proof := range vc.PreparedProofs {
            // Only consider requests after the stable checkpoint
            if proof.Request.SequenceNumber > maxCheckpoint.SequenceNumber {
                reqHash := sha256.Sum256(proof.Request.Payload)
                // Keep the proof with the highest view number for each request
                if existing, ok := preparedRequests[reqHash]; !ok ||
                    proof.ViewNumber > existing.ViewNumber {
                    preparedRequests[reqHash] = &proof
                }
            }
        }
    }

    // Create pre-prepares for all prepared requests
    prePrepares := make([]PrePrepareMessage, 0, len(preparedRequests))

    // Sort by sequence number for deterministic ordering
    var sortedProofs []*PreparedProof
    for _, proof := range preparedRequests {
        sortedProofs = append(sortedProofs, proof)
    }
    sort.Slice(sortedProofs, func(i, j int) bool {
        return sortedProofs[i].Request.SequenceNumber <
            sortedProofs[j].Request.SequenceNumber
    })

    for _, proof := range sortedProofs {
        prePrepares = append(prePrepares, PrePrepareMessage{
            ViewNumber:     node.currentView,
            SequenceNumber: proof.Request.SequenceNumber,
            Digest:         sha256.Sum256(proof.Request.Payload),
            Request:        proof.Request,
        })
    }

    return prePrepares
}
```

**Ordering Invariants:**

| Invariant | Enforcement | Consequence of Violation |
|-----------|-------------|--------------------------|
| **One VIEW_CHANGE per replica per view** | Deduplication map | Duplicate counting in quorum |
| **VIEW_CHANGE for view N only during view N-1** | View number check | Stale or future attacks |
| **Deterministic ViewChangeSet selection** | Sort by ReplicaID | Different replicas compute different pre-prepares |
| **Deterministic PrePrepareSet ordering** | Sort by SequenceNumber | Inconsistent state after view change |
| **No gaps in selected VIEW_CHANGES** | Take first N after sort | Non-deterministic selection |

#### View Change Security Properties

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| **Non-Forgeability** | TPM-backed signatures | Cannot forge view change messages |
| **Non-Replay** | Timestamp + view number | Old view changes rejected |
| **Primary Binding** | View number mod N | New primary is deterministic |
| **Liveness** | 7-of-21 quorum | Completes with any 7 honest nodes |
| **Safety** | Prepared proof collection | No committed request is lost |

### View Change During Active DKG (FINAL DESIGN)

When a view change occurs during an active Distributed Key Generation (DKG) session, the system must handle the transition safely to prevent partial key material from being used or leaked.

#### DKG Abort Protocol

```go
// View Change DKG Handling
//
// If a view change is initiated while DKG is in progress:
// 1. Immediately abort the DKG session
// 2. Discard all generated shares
// 3. New view coordinator initiates fresh DKG with remaining participants
// 4. Share re-collection is NOT attempted (prevents replay attacks)
//
// Checkpoint divergence handling:
// - Request missing checkpoints from quorum
// - Reconcile via majority vote among 7+ coordinators

const (
    DKGAbortGracePeriod = 5 * time.Second  // Time to abort cleanly
)

type DKGSession struct {
    SessionID       [32]byte
    ViewNumber      uint64
    Participants    []NodeID
    State           DKGState
    Shares          map[NodeID]*DKGShare  // Ephemeral - discarded on abort
    CreatedAt       time.Time
    AbortRequested  bool
    mu              sync.RWMutex
}

type DKGState uint8

const (
    DKGStateInit       DKGState = 0
    DKGStateRound1     DKGState = 1
    DKGStateRound2     DKGState = 2
    DKGStateFinalized  DKGState = 3
    DKGStateAborted    DKGState = 4
)

func (s *DKGSession) HandleViewChange(newView uint64) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    if s.State == DKGStateFinalized {
        // DKG already complete - no action needed
        return nil
    }

    if s.State == DKGStateAborted {
        // Already aborted
        return nil
    }

    s.logger.Warn("view change during active DKG, aborting session",
        "session_id", s.SessionID,
        "old_view", s.ViewNumber,
        "new_view", newView,
        "dkg_state", s.State)

    // Mark for abort
    s.AbortRequested = true

    // Discard all shares immediately
    for participantID := range s.Shares {
        delete(s.Shares, participantID)
    }
    s.Shares = nil

    // Update state
    s.State = DKGStateAborted

    return nil
}

func (c *Committee) InitiateFreshDKGAfterViewChange(
    newView uint64,
) (*DKGSession, error) {
    // Only the new primary initiates DKG
    newPrimary := c.Coordinators[newView%uint64(len(c.Coordinators))]
    if newPrimary.NodeID != c.localNodeID {
        return nil, ErrNotNewPrimary
    }

    // Collect remaining participants (excluding failed/excluded coordinators)
    participants := make([]NodeID, 0, len(c.Coordinators))
    for _, coord := range c.Coordinators {
        if c.isCoordinatorHealthy(coord.NodeID) {
            participants = append(participants, coord.NodeID)
        }
    }

    if len(participants) < c.Threshold {
        return nil, ErrInsufficientDKGParticipants{
            Available: len(participants),
            Required:  c.Threshold,
        }
    }

    c.logger.Info("initiating fresh DKG after view change",
        "view", newView,
        "participants", len(participants),
        "threshold", c.Threshold)

    // Create new DKG session
    sessionID := sha256.Sum256(append(
        []byte(fmt.Sprintf("dkg-view-%d", newView)),
        c.SessionID[:]...))

    session := &DKGSession{
        SessionID:    sessionID,
        ViewNumber:   newView,
        Participants: participants,
        State:        DKGStateInit,
        Shares:       make(map[NodeID]*DKGShare),
        CreatedAt:    time.Now(),
    }

    return session, c.runDKG(session)
}
```

#### Checkpoint Divergence Reconciliation

```go
// Checkpoint Reconciliation
//
// When coordinators have divergent checkpoint states after a view change,
// the system must reconcile to a canonical checkpoint before proceeding.

type CheckpointReconciliation struct {
    ViewNumber          uint64
    CheckpointCandidates map[[32]byte]*CheckpointVote  // Hash -> votes
    QuorumSize          int                            // 7-of-21
}

type CheckpointVote struct {
    Checkpoint     *Checkpoint
    CheckpointHash [32]byte
    Voters         []NodeID
    VoteCount      int
}

func (c *Committee) ReconcileCheckpoints(
    viewChangeSet []ViewChangeMessage,
) (*Checkpoint, error) {
    reconciliation := &CheckpointReconciliation{
        ViewNumber:          c.currentView + 1,
        CheckpointCandidates: make(map[[32]byte]*CheckpointVote),
        QuorumSize:          c.Threshold,
    }

    // Collect all checkpoint candidates from view change messages
    for _, vc := range viewChangeSet {
        if vc.LastStableCheckpoint == nil {
            continue
        }

        ckptHash := sha256.Sum256(vc.LastStableCheckpoint.Bytes())

        vote := reconciliation.CheckpointCandidates[ckptHash]
        if vote == nil {
            vote = &CheckpointVote{
                Checkpoint:     vc.LastStableCheckpoint,
                CheckpointHash: ckptHash,
                Voters:         make([]NodeID, 0),
            }
            reconciliation.CheckpointCandidates[ckptHash] = vote
        }

        vote.Voters = append(vote.Voters, vc.ReplicaID)
        vote.VoteCount++
    }

    // Find checkpoint with quorum (7+ votes)
    var canonicalCheckpoint *Checkpoint
    var maxVotes int

    for _, vote := range reconciliation.CheckpointCandidates {
        if vote.VoteCount >= reconciliation.QuorumSize {
            if vote.VoteCount > maxVotes {
                canonicalCheckpoint = vote.Checkpoint
                maxVotes = vote.VoteCount
            }
        }
    }

    if canonicalCheckpoint == nil {
        // No quorum on any checkpoint - request missing checkpoints
        return c.requestMissingCheckpoints(viewChangeSet)
    }

    c.logger.Info("checkpoint reconciled via majority vote",
        "view", reconciliation.ViewNumber,
        "checkpoint_hash", sha256.Sum256(canonicalCheckpoint.Bytes()),
        "votes", maxVotes,
        "quorum", reconciliation.QuorumSize)

    return canonicalCheckpoint, nil
}

func (c *Committee) requestMissingCheckpoints(
    viewChangeSet []ViewChangeMessage,
) (*Checkpoint, error) {
    // Request checkpoints from all coordinators
    requests := make([]*CheckpointRequest, 0)

    for _, vc := range viewChangeSet {
        request := &CheckpointRequest{
            RequestID:  uuid.New(),
            RequesterID: c.localNodeID,
            CoordinatorID: vc.ReplicaID,
            RequestedAt: time.Now(),
        }
        requests = append(requests, request)
    }

    // Send requests and collect responses
    responses := c.collectCheckpointResponses(requests, 10*time.Second)

    if len(responses) < c.Threshold {
        return nil, ErrInsufficientCheckpointResponses{
            Received: len(responses),
            Required: c.Threshold,
        }
    }

    // Build reconciliation from responses
    reconciliation := &CheckpointReconciliation{
        ViewNumber:          c.currentView + 1,
        CheckpointCandidates: make(map[[32]byte]*CheckpointVote),
        QuorumSize:          c.Threshold,
    }

    for _, resp := range responses {
        ckptHash := sha256.Sum256(resp.Checkpoint.Bytes())

        vote := reconciliation.CheckpointCandidates[ckptHash]
        if vote == nil {
            vote = &CheckpointVote{
                Checkpoint:     resp.Checkpoint,
                CheckpointHash: ckptHash,
                Voters:         make([]NodeID, 0),
            }
            reconciliation.CheckpointCandidates[ckptHash] = vote
        }

        vote.Voters = append(vote.Voters, resp.CoordinatorID)
        vote.VoteCount++
    }

    // Return checkpoint with most votes
    var canonicalCheckpoint *Checkpoint
    var maxVotes int

    for _, vote := range reconciliation.CheckpointCandidates {
        if vote.VoteCount > maxVotes {
            canonicalCheckpoint = vote.Checkpoint
            maxVotes = vote.VoteCount
        }
    }

    if maxVotes < c.Threshold {
        return nil, ErrNoCheckpointQuorum{
            MaxVotes: maxVotes,
            Required: c.Threshold,
        }
    }

    return canonicalCheckpoint, nil
}
```

### Partition-Aware PBFT Consensus

The PBFT protocol must handle network partitions gracefully, detecting partition conditions and transitioning to appropriate modes to preserve consistency while maintaining availability for queries.

#### Partition Detection

```go
// PartitionDetector monitors coordinator visibility to detect network partitions
type PartitionDetector struct {
    committee           *Committee
    visibilityState     map[NodeID]*CoordinatorVisibility
    partitionState      PartitionState
    stateTransitionTime time.Time
    stabilityPeriod     time.Duration
    mu                  sync.RWMutex
}

// Partition detection thresholds (security critical, non-configurable)
const (
    // PartitionSuspectedThreshold: Visibility below this triggers partition mode
    // Rationale: <48% means minority partition, cannot achieve consensus
    PartitionSuspectedThreshold = 0.48  // 48% of coordinators visible

    // PartitionRecoveryThreshold: Visibility above this allows exiting partition mode
    // Rationale: >52% ensures we're in majority partition
    PartitionRecoveryThreshold = 0.52  // 52% of coordinators visible

    // PartitionStabilityPeriod: Time visibility must remain stable before state change
    // Rationale: 30s prevents flapping on transient network issues
    PartitionStabilityPeriod = 30 * time.Second
)

// PartitionState represents the current partition mode
type PartitionState uint8

const (
    PartitionStateNormal    PartitionState = iota  // Full consensus available
    PartitionStateSuspected                         // Partition suspected, monitoring
    PartitionStateConfirmed                         // In minority partition, read-only
    PartitionStateRecovering                        // Healing detected, stabilizing
)

// CoordinatorVisibility tracks reachability of a coordinator
type CoordinatorVisibility struct {
    CoordinatorID    NodeID
    LastSeen         time.Time
    ConsecutiveMisses int
    IsVisible        bool
}
```

#### Read-Only Mode in Minority Partition

```go
// MinorityPartitionHandler manages operations when in minority partition
type MinorityPartitionHandler struct {
    detector        *PartitionDetector
    queryHandler    *QueryHandler
    writeHandler    *WriteHandler
    timeoutManager  *PartitionTimeoutManager
}

// HandleRequest routes requests based on partition state
func (mph *MinorityPartitionHandler) HandleRequest(
    ctx context.Context,
    request *ConsensusRequest,
) (*ConsensusResponse, error) {
    partitionState := mph.detector.GetPartitionState()

    switch partitionState {
    case PartitionStateNormal:
        // Full consensus available - process normally
        return mph.processFullConsensus(ctx, request)

    case PartitionStateConfirmed:
        // Minority partition - read-only mode
        if request.IsWriteOperation() {
            return nil, &ErrPartitionReadOnly{
                PartitionState: partitionState,
                Message:        "write operations rejected during partition",
            }
        }
        // Queries allowed with stale data warning
        response, err := mph.queryHandler.HandleQuery(ctx, request)
        if err != nil {
            return nil, err
        }
        response.PartitionWarning = true
        response.DataMayBeStale = true
        return response, nil

    case PartitionStateSuspected, PartitionStateRecovering:
        // Transitional states - wait for stability
        return nil, &ErrPartitionTransitioning{
            State:    partitionState,
            WaitTime: mph.timeoutManager.GetRemainingStabilityTime(),
        }
    }

    return nil, ErrUnknownPartitionState
}
```

#### Timeout Escalation During Partition

```go
// PartitionTimeoutManager implements exponential backoff during partition
type PartitionTimeoutManager struct {
    baseTimeout     time.Duration
    maxTimeout      time.Duration
    currentTimeout  time.Duration
    escalationCount int
    mu              sync.RWMutex
}

// Timeout escalation constants
const (
    PartitionBaseTimeout = 500 * time.Millisecond
    PartitionMaxTimeout  = 10 * time.Second
)

// Timeout escalation sequence: 500ms -> 1s -> 2s -> 4s -> 8s -> 10s (max)
var PartitionTimeoutEscalation = []time.Duration{
    500 * time.Millisecond,
    1 * time.Second,
    2 * time.Second,
    4 * time.Second,
    8 * time.Second,
    10 * time.Second, // Max timeout
}

// NewPartitionTimeoutManager creates a timeout manager with exponential backoff
func NewPartitionTimeoutManager() *PartitionTimeoutManager {
    return &PartitionTimeoutManager{
        baseTimeout:    PartitionBaseTimeout,
        maxTimeout:     PartitionMaxTimeout,
        currentTimeout: PartitionBaseTimeout,
    }
}

// GetTimeout returns current timeout and escalates for next call
func (ptm *PartitionTimeoutManager) GetTimeout() time.Duration {
    ptm.mu.Lock()
    defer ptm.mu.Unlock()

    timeout := ptm.currentTimeout

    // Escalate for next call
    if ptm.escalationCount < len(PartitionTimeoutEscalation)-1 {
        ptm.escalationCount++
        ptm.currentTimeout = PartitionTimeoutEscalation[ptm.escalationCount]
    }

    return timeout
}

// Reset returns to base timeout after successful operation
func (ptm *PartitionTimeoutManager) Reset() {
    ptm.mu.Lock()
    defer ptm.mu.Unlock()

    ptm.escalationCount = 0
    ptm.currentTimeout = ptm.baseTimeout
}
```

#### Partition State Machine

```go
// UpdateVisibility updates coordinator visibility and checks for partition state changes
func (pd *PartitionDetector) UpdateVisibility(coordinatorID NodeID, visible bool) {
    pd.mu.Lock()
    defer pd.mu.Unlock()

    // Update visibility state
    state := pd.visibilityState[coordinatorID]
    if state == nil {
        state = &CoordinatorVisibility{CoordinatorID: coordinatorID}
        pd.visibilityState[coordinatorID] = state
    }

    if visible {
        state.LastSeen = time.Now()
        state.ConsecutiveMisses = 0
        state.IsVisible = true
    } else {
        state.ConsecutiveMisses++
        if state.ConsecutiveMisses >= 3 {
            state.IsVisible = false
        }
    }

    // Calculate visibility ratio
    visibleCount := 0
    for _, v := range pd.visibilityState {
        if v.IsVisible {
            visibleCount++
        }
    }
    visibilityRatio := float64(visibleCount) / float64(len(pd.committee.Coordinators))

    // Check for partition state transitions
    pd.checkStateTransition(visibilityRatio)
}

// checkStateTransition handles partition state machine transitions
func (pd *PartitionDetector) checkStateTransition(visibilityRatio float64) {
    now := time.Now()
    newState := pd.partitionState

    switch pd.partitionState {
    case PartitionStateNormal:
        if visibilityRatio < PartitionSuspectedThreshold {
            newState = PartitionStateSuspected
        }

    case PartitionStateSuspected:
        if visibilityRatio >= PartitionRecoveryThreshold {
            newState = PartitionStateNormal
        } else if now.Sub(pd.stateTransitionTime) >= pd.stabilityPeriod {
            // Remained below threshold for stability period
            newState = PartitionStateConfirmed
            pd.enterReadOnlyMode()
        }

    case PartitionStateConfirmed:
        if visibilityRatio >= PartitionRecoveryThreshold {
            newState = PartitionStateRecovering
        }

    case PartitionStateRecovering:
        if visibilityRatio < PartitionSuspectedThreshold {
            // Recovery failed, back to confirmed
            newState = PartitionStateConfirmed
        } else if now.Sub(pd.stateTransitionTime) >= pd.stabilityPeriod {
            // Stability period passed, exit partition mode
            newState = PartitionStateNormal
            pd.exitReadOnlyMode()
        }
    }

    if newState != pd.partitionState {
        pd.partitionState = newState
        pd.stateTransitionTime = now
        pd.logStateTransition(newState, visibilityRatio)
    }
}
```

**Partition State Transition Diagram:**

```
                                          visibility >= 52%
    ┌───────────────────────────────────────────────────────────────┐
    │                                                               │
    ▼                                                               │
┌────────┐  visibility < 48%  ┌───────────┐  30s stable  ┌──────────┴──┐
│ NORMAL │ ─────────────────▶ │ SUSPECTED │ ───────────▶ │  CONFIRMED  │
└────────┘                    └───────────┘              │ (Read-Only) │
    ▲                              │                     └──────┬──────┘
    │                              │                            │
    │ visibility >= 52%            │ visibility >= 52%          │ visibility >= 52%
    │ + 30s stable                 │                            │
    │                              ▼                            ▼
    │                         back to normal              ┌───────────┐
    └─────────────────────────────────────────────────────│ RECOVERING│
                                                          └───────────┘
```

**Partition Detection Thresholds:**

| Threshold | Value | Purpose |
|-----------|-------|---------|
| **Partition Suspected** | <48% coordinators visible | Enter partition monitoring |
| **Partition Confirmed** | <48% for 30s stable | Enter read-only mode |
| **Recovery Threshold** | >=52% coordinators visible | Begin recovery process |
| **Recovery Confirmed** | >=52% for 30s stable | Exit read-only mode |
| **Stability Period** | 30 seconds | Prevent flapping on transient issues |

---

## Failure Detection and Re-election

### Heartbeat Monitoring

```go
type Heartbeat struct {
    SessionID     [32]byte
    CoordinatorID NodeID
    Timestamp     int64
    Signature     []byte
}

const (
    HeartbeatInterval = 2 * time.Second
    HeartbeatTimeout  = 10 * time.Second
)

func (c *Coordinator) SendHeartbeats(ctx context.Context) {
    ticker := time.NewTicker(HeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            hb := &Heartbeat{
                SessionID:     c.committee.SessionID,
                CoordinatorID: c.NodeID,
                Timestamp:     time.Now().UnixMilli(),
            }
            hb.Signature = c.signWithTPM(hb.Hash())
            c.broadcastToCommittee(hb)
        }
    }
}

func (c *Coordinator) MonitorCoordinators(ctx context.Context) {
    lastSeen := make(map[NodeID]time.Time)
    for _, coord := range c.committee.Coordinators {
        lastSeen[coord.NodeID] = time.Now()
    }

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case hb := <-c.heartbeatChan:
            lastSeen[hb.CoordinatorID] = time.Now()
        case <-ticker.C:
            for id, lastTime := range lastSeen {
                if time.Since(lastTime) > HeartbeatTimeout {
                    c.handleCoordinatorFailure(id)
                }
            }
        }
    }
}
```

### Comprehensive Heartbeat Specification (P4-M12)

**CRITICAL**: Coordinator failure detection must balance fast detection against false positives from network jitter. This section specifies the complete heartbeat protocol with guaranteed detection latency bounds.

#### Canonical Coordinator Failure Detection Constants

**IMPORTANT**: This section defines the SINGLE CANONICAL source of truth for all coordinator failure detection timeouts. All other references in this document defer to these values.

```go
// pkg/consensus/heartbeat_spec.go

// Heartbeat timing parameters (non-configurable security constants)
const (
    // HeartbeatInterval: Time between consecutive heartbeats from a coordinator
    // Rationale: 2s provides good balance between network overhead and detection speed
    // CANONICAL VALUE: All references to heartbeat interval use this constant
    HeartbeatInterval = 2 * time.Second

    // MissedHeartbeatThreshold: Number of consecutive missed heartbeats before FAILED state
    // Rationale: 4 missed heartbeats (8s) confirms coordinator failure
    // CANONICAL VALUE: Replaces conflicting references to "4 missed heartbeats" vs "5-10s timeout"
    MissedHeartbeatThreshold = 4

    // PrimaryFailureDetectionTimeout: Maximum time to detect primary coordinator failure
    // Rationale: Computed as MissedHeartbeatThreshold * HeartbeatInterval = 8 seconds
    // CANONICAL VALUE: This is the authoritative timeout for primary failure detection
    // Previous conflicting values (5-10s, 10s) are SUPERSEDED by this definition
    PrimaryFailureDetectionTimeout = time.Duration(MissedHeartbeatThreshold) * HeartbeatInterval  // 8 seconds

    // HeartbeatTimeout: Time after which ANY coordinator is considered unresponsive
    // Rationale: Same as primary timeout + monitor interval = 9 seconds total
    // This accounts for the granularity of the monitoring check (1s)
    HeartbeatTimeout = PrimaryFailureDetectionTimeout + HeartbeatMonitorInterval  // 9 seconds

    // HeartbeatJitterMax: Maximum random jitter added to heartbeat interval
    // Rationale: Prevents thundering herd on simultaneous timeouts
    HeartbeatJitterMax = 500 * time.Millisecond

    // HeartbeatMonitorInterval: How often to check heartbeat freshness
    // Rationale: 1s granularity for timely detection without CPU overhead
    HeartbeatMonitorInterval = 1 * time.Second

    // SuspicionThreshold: Number of consecutive missed heartbeats before SUSPECTED state
    // Rationale: 2 missed heartbeats triggers suspicion, allows for network hiccups
    SuspicionThreshold = 2

    // FailureThreshold: Number of consecutive missed heartbeats before FAILED state
    // Rationale: Same as MissedHeartbeatThreshold for consistency
    FailureThreshold = MissedHeartbeatThreshold  // 4 missed heartbeats

    // GracePeriodOnStartup: Extra time allowed after coordinator election
    // Rationale: New coordinators may need time to initialize
    GracePeriodOnStartup = 5 * time.Second

    // MinHeartbeatsBeforeReset: Heartbeats needed to clear suspicion
    // Rationale: 3 consecutive heartbeats proves sustained connectivity
    MinHeartbeatsBeforeReset = 3
)

// Detection latency guarantees (derived from canonical constants above)
const (
    // MinDetectionLatency: Fastest possible failure detection
    // = HeartbeatInterval + HeartbeatMonitorInterval = 3 seconds
    MinDetectionLatency = HeartbeatInterval + HeartbeatMonitorInterval

    // MaxDetectionLatency: Slowest failure detection (worst case)
    // = MissedHeartbeatThreshold * HeartbeatInterval + HeartbeatMonitorInterval = 9 seconds
    MaxDetectionLatency = time.Duration(MissedHeartbeatThreshold)*HeartbeatInterval + HeartbeatMonitorInterval

    // TypicalDetectionLatency: Expected detection time under normal network conditions
    // = SuspicionThreshold * HeartbeatInterval + HeartbeatMonitorInterval = 5 seconds
    TypicalDetectionLatency = time.Duration(SuspicionThreshold)*HeartbeatInterval + HeartbeatMonitorInterval
)
```

**Failure Detection Summary**:

| Metric | Value | Computation | Description |
|--------|-------|-------------|-------------|
| **Heartbeat Interval** | 2 seconds | Fixed constant | Time between heartbeats |
| **Missed Heartbeat Threshold** | 4 heartbeats | Fixed constant | Heartbeats before FAILED state |
| **Primary Failure Timeout** | 8 seconds | 4 × 2s | CANONICAL coordinator failure detection timeout |
| **Heartbeat Timeout** | 9 seconds | 8s + 1s monitor | Total timeout including monitor granularity |
| **Suspicion Timeout** | 4 seconds | 2 × 2s | Time to enter SUSPECTED state |
| **Min Detection Latency** | 3 seconds | 2s + 1s | Best case failure detection |
| **Max Detection Latency** | 9 seconds | 4 × 2s + 1s | Worst case failure detection |
| **Typical Detection Latency** | 5 seconds | 2 × 2s + 1s | Expected failure detection time |

**Resolution of Previous Ambiguity**:

This specification SUPERSEDES all previous conflicting timeout values:
- "4 missed heartbeats (8s)" - CORRECT: This is the PrimaryFailureDetectionTimeout
- "5-10s primary failure" - DEPRECATED: Use PrimaryFailureDetectionTimeout = 8 seconds
- "10s heartbeat timeout" - CLARIFIED: This refers to HeartbeatTimeout (9s) rounded up for documentation purposes

All implementations MUST use the canonical constants defined above.

#### Enhanced Heartbeat Message

```go
// pkg/consensus/heartbeat_enhanced.go

// EnhancedHeartbeat includes all fields necessary for robust failure detection
type EnhancedHeartbeat struct {
    // Identity
    SessionID       [32]byte  // Current committee session
    CoordinatorID   NodeID    // Sending coordinator
    CoordinatorIndex uint8    // Position in committee (0-20)

    // Timing
    Timestamp       int64     // Sender's wall clock (milliseconds)
    SequenceNumber  uint64    // Monotonic counter (for ordering)
    MonotonicNanos  int64     // Monotonic clock (for RTT measurement)

    // State
    ViewNumber      uint64    // Current view in PBFT
    LastCommitSeq   uint64    // Last committed sequence number
    PendingRequests uint32    // Number of pending client requests

    // Health indicators
    CPULoad         uint8     // 0-100 percentage
    MemoryLoad      uint8     // 0-100 percentage
    QueueDepth      uint32    // Pending consensus messages

    // Authentication (REQUIRED)
    TPMQuote        []byte    // TPM quote binding to PCR state
    Signature       []byte    // ECDSA signature over all above fields
}

// HeartbeatValidationError indicates a heartbeat failed validation
type HeartbeatValidationError struct {
    CoordinatorID NodeID
    Reason        string
    ReceivedAt    time.Time
}

func (e *HeartbeatValidationError) Error() string {
    return fmt.Sprintf("heartbeat validation failed for %x: %s",
        e.CoordinatorID[:8], e.Reason)
}

// ValidateHeartbeat performs comprehensive validation
func ValidateHeartbeat(hb *EnhancedHeartbeat, committee *Committee) error {
    // 1. Verify sender is a current committee coordinator
    if !committee.IsCoordinator(hb.CoordinatorID) {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        "sender not a committee coordinator",
        }
    }

    // 2. Verify coordinator index matches
    expectedIndex := committee.GetCoordinatorIndex(hb.CoordinatorID)
    if hb.CoordinatorIndex != expectedIndex {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        fmt.Sprintf("coordinator index mismatch: got %d, expected %d",
                hb.CoordinatorIndex, expectedIndex),
        }
    }

    // 3. Verify timestamp freshness (within reasonable clock skew)
    now := time.Now().UnixMilli()
    clockSkew := abs(now - hb.Timestamp)
    if clockSkew > int64(HeartbeatTimeout.Milliseconds()) {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        fmt.Sprintf("timestamp too stale: %dms skew", clockSkew),
        }
    }

    // 4. Verify session ID matches current session
    if hb.SessionID != committee.SessionID {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        "session ID mismatch",
        }
    }

    // 5. Verify TPM quote (proves sender has expected hardware state)
    pubKey := committee.GetCoordinatorPublicKey(hb.CoordinatorID)
    if err := verifyTPMQuote(hb.TPMQuote, hb.Hash(), pubKey); err != nil {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        fmt.Sprintf("TPM quote invalid: %v", err),
        }
    }

    // 6. Verify signature
    if !ecdsa.Verify(pubKey, hb.Hash(), hb.Signature) {
        return &HeartbeatValidationError{
            CoordinatorID: hb.CoordinatorID,
            Reason:        "signature invalid",
        }
    }

    return nil
}
```

#### Failure Detection State Machine

```go
// pkg/consensus/heartbeat_fsm.go

// CoordinatorState represents the health state of a coordinator
type CoordinatorState uint8

const (
    StateHealthy    CoordinatorState = 0  // Receiving heartbeats normally
    StateSuspected  CoordinatorState = 1  // Missed 2+ heartbeats
    StateFailed     CoordinatorState = 2  // Confirmed failed (4+ missed)
    StateRecovering CoordinatorState = 3  // Was failed, now receiving again
)

// CoordinatorHealthTracker monitors individual coordinator health
type CoordinatorHealthTracker struct {
    coordinatorID       NodeID
    state               CoordinatorState
    mu                  sync.RWMutex

    // Heartbeat tracking
    lastHeartbeat       time.Time
    lastSequenceNum     uint64
    missedCount         int
    recoveryCount       int        // Heartbeats since returning from failed

    // Statistics
    totalReceived       uint64
    totalMissed         uint64
    avgLatency          time.Duration
    maxLatency          time.Duration

    // RTT tracking for adaptive timeout
    rttSamples          []time.Duration
    rttSampleIndex      int
    adaptiveTimeout     time.Duration

    // Callbacks
    onStateChange       func(old, new CoordinatorState)
}

// HeartbeatReceived processes a received heartbeat
func (t *CoordinatorHealthTracker) HeartbeatReceived(hb *EnhancedHeartbeat) {
    t.mu.Lock()
    defer t.mu.Unlock()

    now := time.Now()

    // Record RTT if we can (using monotonic timestamps)
    if hb.MonotonicNanos > 0 {
        rtt := now.UnixNano() - hb.MonotonicNanos
        if rtt > 0 && rtt < int64(HeartbeatTimeout) {
            t.recordRTT(time.Duration(rtt))
        }
    }

    // Update tracking
    t.lastHeartbeat = now
    t.lastSequenceNum = hb.SequenceNumber
    t.missedCount = 0
    t.totalReceived++

    // State transitions on heartbeat receipt
    oldState := t.state
    switch t.state {
    case StateHealthy:
        // Stay healthy
    case StateSuspected:
        // One heartbeat clears suspicion
        t.state = StateHealthy
    case StateFailed:
        // Need sustained heartbeats to recover
        t.recoveryCount++
        if t.recoveryCount >= MinHeartbeatsBeforeReset {
            t.state = StateHealthy
            t.recoveryCount = 0
        } else {
            t.state = StateRecovering
        }
    case StateRecovering:
        t.recoveryCount++
        if t.recoveryCount >= MinHeartbeatsBeforeReset {
            t.state = StateHealthy
            t.recoveryCount = 0
        }
    }

    if oldState != t.state && t.onStateChange != nil {
        t.onStateChange(oldState, t.state)
    }
}

// CheckTimeout is called periodically to detect missed heartbeats
func (t *CoordinatorHealthTracker) CheckTimeout() {
    t.mu.Lock()
    defer t.mu.Unlock()

    timeSinceLastHB := time.Since(t.lastHeartbeat)
    timeout := t.getEffectiveTimeout()

    if timeSinceLastHB < timeout {
        return // Not timed out
    }

    // Calculate missed heartbeats
    missedIntervals := int(timeSinceLastHB / HeartbeatInterval)
    if missedIntervals > t.missedCount {
        t.missedCount = missedIntervals
        t.totalMissed += uint64(missedIntervals - t.missedCount)
    }

    // State transitions on missed heartbeats
    oldState := t.state
    switch {
    case t.missedCount >= FailureThreshold:
        t.state = StateFailed
        t.recoveryCount = 0
    case t.missedCount >= SuspicionThreshold:
        t.state = StateSuspected
    }

    if oldState != t.state && t.onStateChange != nil {
        t.onStateChange(oldState, t.state)
    }
}

// recordRTT records a RTT sample for adaptive timeout calculation
func (t *CoordinatorHealthTracker) recordRTT(rtt time.Duration) {
    const maxSamples = 20

    if t.rttSamples == nil {
        t.rttSamples = make([]time.Duration, maxSamples)
    }

    t.rttSamples[t.rttSampleIndex] = rtt
    t.rttSampleIndex = (t.rttSampleIndex + 1) % maxSamples

    // Update adaptive timeout (use 99th percentile of RTT + margin)
    t.adaptiveTimeout = t.computeAdaptiveTimeout()
}

// computeAdaptiveTimeout calculates timeout based on observed RTT
func (t *CoordinatorHealthTracker) computeAdaptiveTimeout() time.Duration {
    // Collect valid samples
    var samples []time.Duration
    for _, rtt := range t.rttSamples {
        if rtt > 0 {
            samples = append(samples, rtt)
        }
    }

    if len(samples) < 5 {
        return HeartbeatTimeout // Use default if insufficient samples
    }

    // Sort and get 99th percentile
    sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
    p99Index := int(float64(len(samples)) * 0.99)
    p99RTT := samples[p99Index]

    // Adaptive timeout = 2x P99 RTT + base interval + margin
    adaptive := 2*p99RTT + HeartbeatInterval + HeartbeatJitterMax

    // Clamp to [MinDetectionLatency, HeartbeatTimeout]
    if adaptive < MinDetectionLatency {
        return MinDetectionLatency
    }
    if adaptive > HeartbeatTimeout {
        return HeartbeatTimeout
    }
    return adaptive
}

// getEffectiveTimeout returns the timeout to use (adaptive or default)
func (t *CoordinatorHealthTracker) getEffectiveTimeout() time.Duration {
    if t.adaptiveTimeout > 0 {
        return t.adaptiveTimeout
    }
    return HeartbeatTimeout
}

// GetState returns current coordinator state
func (t *CoordinatorHealthTracker) GetState() CoordinatorState {
    t.mu.RLock()
    defer t.mu.RUnlock()
    return t.state
}

// GetStatistics returns health statistics
func (t *CoordinatorHealthTracker) GetStatistics() CoordinatorHealthStats {
    t.mu.RLock()
    defer t.mu.RUnlock()
    return CoordinatorHealthStats{
        State:           t.state,
        LastHeartbeat:   t.lastHeartbeat,
        MissedCount:     t.missedCount,
        TotalReceived:   t.totalReceived,
        TotalMissed:     t.totalMissed,
        AdaptiveTimeout: t.adaptiveTimeout,
    }
}

type CoordinatorHealthStats struct {
    State           CoordinatorState
    LastHeartbeat   time.Time
    MissedCount     int
    TotalReceived   uint64
    TotalMissed     uint64
    AdaptiveTimeout time.Duration
}
```

#### Failure Detection Latency Guarantees

| Scenario | Detection Latency | Mechanism |
|----------|-------------------|-----------|
| **Clean crash** | 3-5 seconds | Miss 2 heartbeats → SUSPECTED |
| **Network partition** | 5-9 seconds | Miss 4 heartbeats → FAILED |
| **Graceful shutdown** | Immediate | Explicit LEAVING message |
| **Byzantine (stops signing)** | 3-5 seconds | Invalid heartbeat detected |
| **Byzantine (replays old HB)** | Immediate | Sequence number regression |

#### False Positive Mitigation

```go
// pkg/consensus/false_positive_mitigation.go

// FalsePositiveMitigation reduces false positive failure detections
type FalsePositiveMitigation struct {
    // Cross-validation: require multiple reporters to confirm failure
    minReportersRequired   int  // Default: 3 coordinators must agree

    // Probe-before-declare: actively probe before declaring failure
    probeBeforeFailure     bool // Default: true
    probeTimeout           time.Duration // Default: 2s
    probeRetries           int  // Default: 2

    // Reputation tracking: coordinators with history of false reports
    falseReportThreshold   int  // Reports before penalty
    falseReporterPenalty   time.Duration // Ignore reports for this duration
}

// CrossValidateFailure checks if multiple coordinators agree on failure
func (m *FalsePositiveMitigation) CrossValidateFailure(
    failedID NodeID,
    reports []*FailureReport,
) (confirmed bool, reporters []NodeID) {
    // Count unique reporters
    reporterSet := make(map[NodeID]bool)
    for _, report := range reports {
        if report.FailedNodeID == failedID {
            reporterSet[report.ReporterID] = true
        }
    }

    if len(reporterSet) >= m.minReportersRequired {
        reporters = make([]NodeID, 0, len(reporterSet))
        for reporter := range reporterSet {
            reporters = append(reporters, reporter)
        }
        return true, reporters
    }
    return false, nil
}

// ProbeBeforeDeclare sends direct probes to suspected coordinator
func (m *FalsePositiveMitigation) ProbeBeforeDeclare(
    ctx context.Context,
    suspectedID NodeID,
    dialer P2PDialer,
) (alive bool, err error) {
    for retry := 0; retry < m.probeRetries; retry++ {
        probeCtx, cancel := context.WithTimeout(ctx, m.probeTimeout)
        defer cancel()

        // Direct connection attempt
        conn, err := dialer.DialDirect(probeCtx, suspectedID)
        if err != nil {
            continue // Try again
        }
        defer conn.Close()

        // Send probe message
        resp, err := conn.SendProbe(probeCtx, &ProbeMessage{
            Type:      ProbeTypeLiveness,
            Timestamp: time.Now().UnixMilli(),
        })
        if err != nil {
            continue
        }

        // Verify response
        if resp.Type == ProbeTypeAlive {
            return true, nil
        }
    }
    return false, nil
}
```

**Heartbeat State Machine Diagram:**

```
                           ┌──────────────────────────┐
                           │       HEALTHY            │
                           │ (receiving heartbeats)   │
                           └────────────┬─────────────┘
                                        │
                       Miss 2+ heartbeats (4+ seconds)
                                        │
                                        ▼
                           ┌──────────────────────────┐
                           │       SUSPECTED          │
                           │ (probing, not yet failed)│
                           └────────────┬─────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
    Receive heartbeat          Miss 4+ heartbeats         Probe succeeds
              │                    (8+ seconds)                   │
              │                         │                         │
              ▼                         ▼                         ▼
    ┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
    │    HEALTHY      │     │       FAILED         │     │    HEALTHY      │
    │(back to normal) │     │ (trigger replacement)│     │(false positive) │
    └─────────────────┘     └──────────────────────┘     └─────────────────┘
                                        │
                           Receive heartbeat (recovering)
                                        │
                                        ▼
                           ┌──────────────────────────┐
                           │      RECOVERING          │
                           │ (wait for 3 heartbeats)  │
                           └────────────┬─────────────┘
                                        │
                           Receive 3 consecutive heartbeats
                                        │
                                        ▼
                           ┌──────────────────────────┐
                           │       HEALTHY            │
                           │ (fully recovered)        │
                           └──────────────────────────┘
```

### Failure Triggers

```go
type FailureReason uint8

const (
    FailureHeartbeatTimeout  FailureReason = 1
    FailureInvalidSignature  FailureReason = 2
    FailureMaliciousBehavior FailureReason = 3
    FailureNetworkPartition  FailureReason = 4
)

type FailureReport struct {
    FailedNodeID NodeID
    Reason       FailureReason
    ReporterID   NodeID
    Evidence     []byte
    Timestamp    int64
    Signature    []byte
}

func (c *Coordinator) ReportFailure(failedID NodeID, reason FailureReason, evidence []byte) error {
    report := &FailureReport{
        FailedNodeID: failedID,
        Reason:       reason,
        ReporterID:   c.NodeID,
        Evidence:     evidence,
        Timestamp:    time.Now().UnixMilli(),
    }
    report.Signature = c.signWithTPM(report.Hash())
    return c.broadcastToCommittee(report)
}
```

### Re-election Process

```go
func (c *Committee) HandleFailure(failedID NodeID) error {
    newCoordinators := make([]Coordinator, 0)
    for _, coord := range c.Coordinators {
        if coord.NodeID != failedID {
            newCoordinators = append(newCoordinators, coord)
        }
    }

    if len(newCoordinators) < c.Threshold {
        return c.FullReelection()
    }

    newSeed := GenerateFailoverSeed(c.Seed, failedID)
    candidates := GetEligibleCandidates(GetAllNodes(), CoordinatorEligibility)
    candidates = excludeNodes(candidates, append(newCoordinators, Coordinator{NodeID: failedID}))

    replacement, err := SelectCoordinators(newSeed, candidates, 1)
    if err != nil {
        return err
    }

    c.Coordinators = append(newCoordinators, Coordinator{
        NodeID:    replacement[0].ID,
        Role:      RoleValidator,
        VRFProof:  replacement[0].LastVRFProof,
        PublicKey: replacement[0].PublicKey,
        Index:     len(newCoordinators),
    })

    return c.ConsensusOnCommitteeUpdate()
}

func GenerateFailoverSeed(originalSeed []byte, failedNodeID NodeID) []byte {
    h := sha256.New()
    h.Write(originalSeed)
    h.Write([]byte("failover"))
    h.Write(failedNodeID[:])
    return h.Sum(nil)
}

func (c *Committee) FullReelection() error {
    newSeed := GenerateVRFSeed(c.Seed, time.Now().Unix(), c.OperationType)
    newCommittee, err := FormCommittee(newSeed, c.OperationType)
    if err != nil {
        return err
    }
    newCommittee.Height = c.Height
    *c = *newCommittee
    return nil
}
```

### Failover Timing

| Scenario | Detection | Re-election | Total |
|----------|-----------|-------------|-------|
| Single coordinator failure | 10s | 5s | 15s |
| Multiple failures (<3) | 10s | 5s | 15s |
| Threshold failure (3+) | 10s | 10s | 20s |
| Primary failure | 5s | 5s | 10s |

---

## Anti-Collusion Mechanisms

### Geographic Distribution

```go
type GeographicPolicy struct {
    MinCountries    int
    MaxPerCountry   int
    MaxPerRegion    int
    BannedCountries map[string]bool
}

var GeoPolicy = GeographicPolicy{
    MinCountries:    3,
    MaxPerCountry:   2,
    MaxPerRegion:    3,
    BannedCountries: map[string]bool{},
}

func ValidateGeographicDiversity(coordinators []Coordinator) error {
    countries := make(map[string]int)
    regions := make(map[string]int)

    for _, c := range coordinators {
        node := GetNodeByID(c.NodeID)
        countries[node.Country]++
        regions[node.Region]++

        if countries[node.Country] > GeoPolicy.MaxPerCountry {
            return ErrTooManyFromCountry{Country: node.Country, Count: countries[node.Country]}
        }
        if regions[node.Region] > GeoPolicy.MaxPerRegion {
            return ErrTooManyFromRegion{Region: node.Region, Count: regions[node.Region]}
        }
    }

    if len(countries) < GeoPolicy.MinCountries {
        return ErrInsufficientCountries{Required: GeoPolicy.MinCountries, Actual: len(countries)}
    }
    return nil
}
```

### TPM Manufacturer Diversity

```go
type TPMManufacturer string

const (
    TPMIntel    TPMManufacturer = "Intel"
    TPMInfineon TPMManufacturer = "Infineon"
    TPMSTMicro  TPMManufacturer = "STMicroelectronics"
    TPMNuvoton  TPMManufacturer = "Nuvoton"
    TPMQualcomm TPMManufacturer = "Qualcomm"
    TPMNationz  TPMManufacturer = "Nationz"
)

type TPMPolicy struct {
    MinManufacturers int
    MaxPerVendor     int
}

var TPMDiversityPolicy = TPMPolicy{
    MinManufacturers: 3,
    MaxPerVendor:     2,
}

func ValidateTPMDiversity(coordinators []Coordinator) error {
    vendors := make(map[TPMManufacturer]int)

    for _, c := range coordinators {
        node := GetNodeByID(c.NodeID)
        vendors[node.TPMManufacturer]++

        if vendors[node.TPMManufacturer] > TPMDiversityPolicy.MaxPerVendor {
            return ErrTooManyFromVendor{Vendor: node.TPMManufacturer, Count: vendors[node.TPMManufacturer]}
        }
    }

    if len(vendors) < TPMDiversityPolicy.MinManufacturers {
        return ErrInsufficientTPMDiversity{Required: TPMDiversityPolicy.MinManufacturers, Actual: len(vendors)}
    }
    return nil
}
```

### Collusion Detection

```go
type CollusionIndicator struct {
    SuspectNodes    []NodeID
    Behavior        string
    ConfidenceScore float64
    DetectedAt      time.Time
}

func DetectCollusion(coordinators []Coordinator, history []Proposal) []CollusionIndicator {
    indicators := make([]CollusionIndicator, 0)

    // Pattern 1: Synchronized voting
    votePatterns := analyzeVotePatterns(coordinators, history)
    for pattern, confidence := range votePatterns {
        if confidence > 0.95 {
            indicators = append(indicators, CollusionIndicator{
                SuspectNodes:    pattern.Nodes,
                Behavior:        "synchronized_voting",
                ConfidenceScore: confidence,
                DetectedAt:      time.Now(),
            })
        }
    }

    // Pattern 2: Suspicious selection frequency (VRF manipulation)
    selectionFreq := analyzeSelectionFrequency(coordinators, 100)
    for nodeID, freq := range selectionFreq {
        expected := 1.0 / float64(GetEligibleCandidateCount())
        if freq > expected*3 {
            indicators = append(indicators, CollusionIndicator{
                SuspectNodes:    []NodeID{nodeID},
                Behavior:        "suspicious_selection_frequency",
                ConfidenceScore: min(freq/expected/3, 1.0),
                DetectedAt:      time.Now(),
            })
        }
    }

    // Pattern 3: Coordinated timing attacks
    indicators = append(indicators, analyzeTimingPatterns(coordinators, history)...)

    return indicators
}
```

### Transaction Ordering Integrity (CANONICAL)

Coordinators must provide cryptographic proof of transaction ordering to prevent double-spend attacks through reordering. This is critical for cross-shard transactions where a malicious coordinator set could accept two transactions spending the same UTXO.

#### UTXO Hash Chain in 3PC Messages

All three-phase commit (3PC) messages include UTXO hashes to ensure shards can verify transaction inputs match coordinator claims:

```go
// ThreePhaseMessage includes cryptographic proof of UTXO inputs
type ThreePhaseMessage struct {
    Phase          Phase           // CanCommit, PreCommit, DoCommit
    TransactionID  TxID            // Transaction being coordinated
    SourceShard    uint16          // Authoritative shard for sender
    DestShard      uint16          // Destination shard (if cross-shard)
    UTXOInputs     []UTXOID        // Input UTXOs being consumed
    UTXOHash       [32]byte        // SHA256(sorted UTXO IDs) - verifiable by shards
    PrevTxHash     [32]byte        // Hash of previous TX in coordinator's queue
    Sequence       uint64          // Monotonic sequence within coordinator batch
    CoordinatorID  NodeID          // Coordinator sending this message
    CoordinatorSig []byte          // TPM-signed message hash
    Timestamp      int64           // Message timestamp (must be within 5s)
}

// ComputeUTXOHash creates deterministic hash of UTXO inputs
func ComputeUTXOHash(utxos []UTXOID) [32]byte {
    // Sort for deterministic ordering
    sorted := make([]UTXOID, len(utxos))
    copy(sorted, utxos)
    sort.Slice(sorted, func(i, j int) bool {
        return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
    })

    h := sha256.New()
    for _, utxo := range sorted {
        h.Write(utxo[:])
    }
    var hash [32]byte
    copy(hash[:], h.Sum(nil))
    return hash
}

// VerifyUTXOHash allows shards to verify coordinator claims
func VerifyUTXOHash(msg *ThreePhaseMessage, expectedUTXOs []UTXOID) error {
    computed := ComputeUTXOHash(expectedUTXOs)
    if computed != msg.UTXOHash {
        return &ErrUTXOHashMismatch{
            Expected: computed,
            Received: msg.UTXOHash,
            TxID:     msg.TransactionID,
        }
    }
    return nil
}
```

**Security Properties:**
- **Non-Substitution**: Coordinator cannot substitute different UTXOs without detection
- **Deterministic**: Any party can independently compute expected hash
- **Verifiable**: Shards verify hash matches their local UTXO state
- **Linkage**: PrevTxHash creates audit chain within coordinator batch

#### Coordinator Signed Transaction Batch

To prevent individual coordinator reordering, batches require 7-of-21 signatures before shards accept:

```go
// CoordinatorBatch represents an ordered set of transactions
type CoordinatorBatch struct {
    BatchID       [32]byte           // SHA256(SessionID || BatchNumber)
    SessionID     [32]byte           // Committee session identifier
    BatchNumber   uint64             // Monotonic batch counter
    Transactions  []BatchTransaction // Ordered transaction list
    BatchHash     [32]byte           // SHA256(concat(TxID || UTXOHash for each TX))
    Timestamp     int64              // Batch creation timestamp
    Signatures    []CoordinatorSig   // 7-of-21 coordinator signatures
}

// BatchTransaction represents a transaction within a batch
type BatchTransaction struct {
    TxID        TxID        // Transaction identifier
    UTXOHash    [32]byte    // Hash of UTXO inputs
    SourceShard uint16      // Source shard
    DestShard   uint16      // Destination shard (0 if same-shard)
    Sequence    uint64      // Position within batch (0-indexed)
}

// CoordinatorSig is a TPM-backed signature from a coordinator
type CoordinatorSig struct {
    CoordinatorID    NodeID    // Signing coordinator
    CoordinatorIndex int       // Index in committee (0-4)
    Signature        []byte    // TPM-signed batch hash
    Timestamp        int64     // When signed
}

// ComputeBatchHash creates deterministic hash of ordered transactions
func ComputeBatchHash(transactions []BatchTransaction) [32]byte {
    h := sha256.New()
    for _, tx := range transactions {
        h.Write(tx.TxID[:])
        h.Write(tx.UTXOHash[:])
    }
    var hash [32]byte
    copy(hash[:], h.Sum(nil))
    return hash
}

// ValidateBatch verifies batch has required signatures and ordering
func ValidateBatch(batch *CoordinatorBatch, committee *Committee) error {
    // Verify batch hash matches transactions
    computed := ComputeBatchHash(batch.Transactions)
    if computed != batch.BatchHash {
        return ErrBatchHashMismatch
    }

    // Verify 3+ unique coordinator signatures
    signers := make(map[NodeID]bool)
    for _, sig := range batch.Signatures {
        // Verify coordinator is in committee
        if !committee.HasCoordinator(sig.CoordinatorID) {
            return &ErrUnknownCoordinator{NodeID: sig.CoordinatorID}
        }

        // Verify signature over batch hash
        if !VerifyTPMSignature(sig.CoordinatorID, batch.BatchHash[:], sig.Signature) {
            return &ErrInvalidBatchSignature{CoordinatorID: sig.CoordinatorID}
        }

        signers[sig.CoordinatorID] = true
    }

    if len(signers) < committee.Threshold {
        return &ErrInsufficientBatchSignatures{
            Required: committee.Threshold,
            Received: len(signers),
        }
    }

    // Verify transaction sequences are contiguous
    for i, tx := range batch.Transactions {
        if int(tx.Sequence) != i {
            return &ErrSequenceGap{Expected: i, Actual: int(tx.Sequence)}
        }
    }

    return nil
}
```

#### Double-Spend Detection via Batch

Shards detect conflicting transactions within the same batch:

```go
// DetectConflictsInBatch finds transactions spending same UTXOs
func DetectConflictsInBatch(batch *CoordinatorBatch) []ConflictPair {
    utxoUsage := make(map[UTXOID][]int) // UTXO -> transaction indices
    conflicts := make([]ConflictPair, 0)

    for i, tx := range batch.Transactions {
        // Decode UTXOs from hash (shards have local state)
        for _, utxo := range GetUTXOsForTx(tx.TxID) {
            utxoUsage[utxo] = append(utxoUsage[utxo], i)
        }
    }

    // Find UTXOs used by multiple transactions
    for utxo, indices := range utxoUsage {
        if len(indices) > 1 {
            for i := 0; i < len(indices)-1; i++ {
                conflicts = append(conflicts, ConflictPair{
                    UTXO:   utxo,
                    TxA:    batch.Transactions[indices[i]].TxID,
                    TxB:    batch.Transactions[indices[i+1]].TxID,
                    IndexA: indices[i],
                    IndexB: indices[i+1],
                })
            }
        }
    }

    return conflicts
}

// ConflictPair represents two transactions attempting same UTXO
type ConflictPair struct {
    UTXO   UTXOID
    TxA    TxID
    TxB    TxID
    IndexA int
    IndexB int
}

// HandleConflict processes detected double-spend attempt
func (s *Shard) HandleConflict(conflict ConflictPair, batch *CoordinatorBatch) error {
    // Report malicious coordinators who signed conflicting batch
    for _, sig := range batch.Signatures {
        s.ReportMaliciousCoordinator(sig.CoordinatorID, &MaliciousReport{
            Type:      MaliciousDoubleSpendBatch,
            Evidence:  batch,
            Conflict:  conflict,
            Timestamp: time.Now(),
        })
    }

    // Reject entire batch - cannot trust ordering
    return &ErrBatchRejectedDoubleSpend{
        BatchID:  batch.BatchID,
        Conflict: conflict,
    }
}
```

#### Cross-Shard Ordering Protocol

For cross-shard transactions, source shard verifies batch ordering before locking:

```go
// CrossShardCanCommit validates batch before locking UTXOs
func (s *Shard) CrossShardCanCommit(
    msg *ThreePhaseMessage,
    batch *CoordinatorBatch,
) error {
    // Step 1: Validate batch has sufficient signatures
    if err := ValidateBatch(batch, s.currentCommittee); err != nil {
        return fmt.Errorf("batch validation failed: %w", err)
    }

    // Step 2: Verify this transaction is in the batch
    found := false
    var batchTx *BatchTransaction
    for i := range batch.Transactions {
        if batch.Transactions[i].TxID == msg.TransactionID {
            found = true
            batchTx = &batch.Transactions[i]
            break
        }
    }
    if !found {
        return ErrTransactionNotInBatch
    }

    // Step 3: Verify UTXO hash in message matches batch
    if batchTx.UTXOHash != msg.UTXOHash {
        return ErrUTXOHashMismatch
    }

    // Step 4: Verify UTXOs exist and are owned by sender
    utxos, err := s.GetUTXOsForTransaction(msg.TransactionID)
    if err != nil {
        return err
    }
    if err := VerifyUTXOHash(msg, utxos); err != nil {
        return err
    }

    // Step 5: Check no earlier transaction in batch uses same UTXOs
    for i := 0; i < int(batchTx.Sequence); i++ {
        priorTx := batch.Transactions[i]
        if s.SharesUTXOs(priorTx.TxID, msg.TransactionID) {
            return &ErrPriorTransactionConflict{
                PriorTxID:   priorTx.TxID,
                CurrentTxID: msg.TransactionID,
                Sequence:    priorTx.Sequence,
            }
        }
    }

    // Step 6: Lock UTXOs (with batch reference for audit)
    return s.LockUTXOs(msg.TransactionID, utxos, batch.BatchID)
}
```

#### Audit Trail for Ordering Disputes

All batch operations are logged for dispute resolution:

```go
// BatchAuditEntry records batch processing for disputes
type BatchAuditEntry struct {
    BatchID       [32]byte
    ShardID       uint16
    ReceivedAt    time.Time
    ValidatedAt   time.Time
    Status        BatchStatus
    FailureReason string
    Signatures    []CoordinatorSig  // Copy for evidence
    TxCount       int
}

type BatchStatus uint8
const (
    BatchPending   BatchStatus = iota
    BatchValidated
    BatchRejected
    BatchExecuted
)

// Audit log is retained for 30 days for dispute resolution
const BatchAuditRetention = 30 * 24 * time.Hour
```

#### Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Ordering Immutability** | Batch order cannot be changed | 7-of-21 signatures on BatchHash |
| **Non-Repudiation** | Coordinators cannot deny signing | TPM-backed signatures + audit log |
| **Conflict Detection** | Double-spends detected pre-execution | UTXO hash comparison across batch |
| **Shard Verification** | Shards verify claims independently | UTXOHash matches local state |
| **Audit Trail** | 30-day evidence retention | BatchAuditEntry logs |

#### Attack Mitigation

| Attack | Without Batching | With Signed Batches |
|--------|------------------|---------------------|
| Coordinator reorders TX-A before TX-B | Possible | Rejected - batch hash mismatch |
| Coordinator substitutes UTXOs | Possible | Rejected - UTXO hash verification |
| 2 coordinators collude on conflicting batch | Possible | Rejected - need 3/5 signatures |
| Coordinator denies signing | Possible | Provable - TPM audit log |
| Double-spend via simultaneous batches | Possible | Detected - sequence number gaps |

---

## Partition Recovery (FINAL DESIGN)

The committee must detect and recover from network partitions that could cause quorum loss, ensuring the system can safely resume operations after network healing.

### Committee Quorum Loss Detection

```go
// Partition Detection
//
// Committee quorum loss is detected when:
// - Less than 7 coordinators are reachable for 60 consecutive seconds
// - Minority partition must stop processing new transactions
// - Announce partition state to prevent split-brain scenarios

const (
    QuorumLossDetectionWindow = 60 * time.Second
    MinimumQuorumSize        = 7  // 7-of-21 for BFT
    PartitionCheckInterval   = 5 * time.Second
)

type PartitionDetector struct {
    committee           *Committee
    reachableCoordinators map[NodeID]*ReachabilityStatus
    quorumLostSince     *time.Time
    inPartition         bool
    mu                  sync.RWMutex
}

type ReachabilityStatus struct {
    CoordinatorID  NodeID
    LastReachable  time.Time
    ConsecutiveFails int
    IsReachable    bool
}

func NewPartitionDetector(committee *Committee) *PartitionDetector {
    pd := &PartitionDetector{
        committee:           committee,
        reachableCoordinators: make(map[NodeID]*ReachabilityStatus),
        inPartition:         false,
    }

    // Initialize reachability status for all coordinators
    for _, coord := range committee.Coordinators {
        pd.reachableCoordinators[coord.NodeID] = &ReachabilityStatus{
            CoordinatorID:  coord.NodeID,
            LastReachable:  time.Now(),
            IsReachable:    true,
        }
    }

    return pd
}

func (pd *PartitionDetector) MonitorQuorum(ctx context.Context) {
    ticker := time.NewTicker(PartitionCheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            pd.checkQuorumStatus()
        }
    }
}

func (pd *PartitionDetector) checkQuorumStatus() {
    pd.mu.Lock()
    defer pd.mu.Unlock()

    now := time.Now()
    reachableCount := 0

    // Count reachable coordinators
    for _, status := range pd.reachableCoordinators {
        if now.Sub(status.LastReachable) < QuorumLossDetectionWindow {
            status.IsReachable = true
            reachableCount++
        } else {
            status.IsReachable = false
        }
    }

    // Check if quorum is met
    if reachableCount < MinimumQuorumSize {
        if !pd.inPartition {
            // Quorum just lost
            pd.handleQuorumLoss(reachableCount)
        } else {
            // Still in partition
            pd.logger.Debug("still in partition",
                "reachable", reachableCount,
                "required", MinimumQuorumSize,
                "duration", time.Since(*pd.quorumLostSince))
        }
    } else {
        if pd.inPartition {
            // Quorum restored - partition healed
            pd.handlePartitionHealed(reachableCount)
        }
    }
}

func (pd *PartitionDetector) handleQuorumLoss(reachableCount int) {
    now := time.Now()
    pd.quorumLostSince = &now
    pd.inPartition = true

    pd.logger.Error("committee quorum lost - entering partition mode",
        "reachable", reachableCount,
        "required", MinimumQuorumSize,
        "total_coordinators", len(pd.committee.Coordinators))

    // Announce partition state to prevent split-brain
    pd.announcePartitionState()

    // Stop processing new transactions
    pd.committee.SetPartitionMode(true)
}

func (pd *PartitionDetector) announcePartitionState() {
    announcement := &PartitionAnnouncement{
        CommitteeID:      pd.committee.SessionID,
        AnnouncerID:      pd.committee.localNodeID,
        PartitionedAt:    time.Now(),
        ReachableCount:   pd.getReachableCount(),
        TPMQuote:         pd.committee.tpm.Quote([]byte("PARTITION")),
        Signature:        pd.committee.signWithTPM([]byte("PARTITION")),
    }

    pd.committee.broadcastToNetwork(announcement)
}
```

### Minority Partition Behavior

```go
// Safe Shutdown in Minority Partition
//
// When a node detects it's in the minority partition:
// 1. Stop processing new transactions immediately
// 2. Complete in-flight operations gracefully
// 3. Checkpoint current state
// 4. Wait for partition healing (network recovery)

type PartitionMode struct {
    Active           bool
    ActivatedAt      time.Time
    InFlightOps      map[string]*Operation
    LastCheckpoint   *Checkpoint
    mu               sync.RWMutex
}

func (c *Committee) SetPartitionMode(active bool) {
    c.partitionMode.mu.Lock()
    defer c.partitionMode.mu.Unlock()

    if active == c.partitionMode.Active {
        return  // No change
    }

    if active {
        c.logger.Warn("entering partition mode - stopping new transactions")
        c.partitionMode.Active = true
        c.partitionMode.ActivatedAt = time.Now()

        // Complete in-flight operations
        c.completeInFlightOperations()

        // Create checkpoint
        checkpoint := c.createCheckpoint()
        c.partitionMode.LastCheckpoint = checkpoint

        c.logger.Info("partition mode activated",
            "in_flight_ops", len(c.partitionMode.InFlightOps),
            "checkpoint_seq", checkpoint.SequenceNumber)
    } else {
        c.logger.Info("exiting partition mode - resuming operations",
            "partition_duration", time.Since(c.partitionMode.ActivatedAt))
        c.partitionMode.Active = false
        c.partitionMode.ActivatedAt = time.Time{}
    }
}

func (c *Committee) completeInFlightOperations() {
    timeout := 30 * time.Second
    deadline := time.Now().Add(timeout)

    c.logger.Info("completing in-flight operations",
        "count", len(c.partitionMode.InFlightOps),
        "timeout", timeout)

    for opID, op := range c.partitionMode.InFlightOps {
        if time.Now().After(deadline) {
            c.logger.Warn("operation timeout during partition shutdown",
                "op_id", opID)
            op.Cancel()
            continue
        }

        // Wait for operation to complete or timeout
        select {
        case <-op.Done():
            c.logger.Debug("operation completed", "op_id", opID)
        case <-time.After(time.Until(deadline)):
            c.logger.Warn("operation did not complete before deadline",
                "op_id", opID)
            op.Cancel()
        }
    }

    c.partitionMode.InFlightOps = make(map[string]*Operation)
}
```

### Reconstitution After Healing

```go
// Partition Healing and Reconstitution
//
// When network partition heals and quorum is restored:
// 1. Sync to canonical chain (majority partition's state)
// 2. Re-run coordinator selection for new epoch
// 3. Resume normal operations

func (pd *PartitionDetector) handlePartitionHealed(reachableCount int) {
    pd.logger.Info("partition healed - quorum restored",
        "reachable", reachableCount,
        "required", MinimumQuorumSize,
        "partition_duration", time.Since(*pd.quorumLostSince))

    pd.inPartition = false
    pd.quorumLostSince = nil

    // Begin reconstitution process
    if err := pd.committee.ReconstitutAfterPartition(); err != nil {
        pd.logger.Error("reconstitution failed", "error", err)
        return
    }

    // Exit partition mode
    pd.committee.SetPartitionMode(false)
}

func (c *Committee) ReconstitutAfterPartition() error {
    c.logger.Info("beginning partition reconstitution")

    // Step 1: Sync to canonical chain
    canonicalState, err := c.syncToCanonicalChain()
    if err != nil {
        return fmt.Errorf("failed to sync to canonical chain: %w", err)
    }

    c.logger.Info("synced to canonical chain",
        "checkpoint_seq", canonicalState.LastCheckpoint.SequenceNumber,
        "epoch", canonicalState.Epoch)

    // Step 2: Re-run coordinator selection for new epoch
    newCommittee, err := c.electCoordinatorsForNextEpoch()
    if err != nil {
        return fmt.Errorf("failed to elect new coordinators: %w", err)
    }

    c.logger.Info("new committee elected after partition healing",
        "committee_size", len(newCommittee.Coordinators),
        "epoch", newCommittee.Epoch)

    // Step 3: Resume normal operations
    c.resumeNormalOperations()

    return nil
}

func (c *Committee) syncToCanonicalChain() (*CanonicalState, error) {
    // Query quorum of coordinators for their current state
    states := make([]*CoordinatorState, 0)

    for _, coord := range c.Coordinators {
        if !c.isCoordinatorReachable(coord.NodeID) {
            continue
        }

        state, err := c.requestCoordinatorState(coord.NodeID)
        if err != nil {
            c.logger.Warn("failed to get coordinator state",
                "coordinator", coord.NodeID,
                "error", err)
            continue
        }

        states = append(states, state)
    }

    if len(states) < c.Threshold {
        return nil, ErrInsufficientStatesForSync{
            Received: len(states),
            Required: c.Threshold,
        }
    }

    // Find canonical state (majority consensus)
    canonical := c.findCanonicalState(states)

    // Apply canonical state
    if err := c.applyCanonicalState(canonical); err != nil {
        return nil, fmt.Errorf("failed to apply canonical state: %w", err)
    }

    return canonical, nil
}

func (c *Committee) findCanonicalState(
    states []*CoordinatorState,
) *CanonicalState {
    // Group states by checkpoint hash
    stateGroups := make(map[[32]byte][]*CoordinatorState)

    for _, state := range states {
        ckptHash := sha256.Sum256(state.LastCheckpoint.Bytes())
        stateGroups[ckptHash] = append(stateGroups[ckptHash], state)
    }

    // Find state with most agreement (majority)
    var canonicalStates []*CoordinatorState
    var maxCount int

    for _, group := range stateGroups {
        if len(group) > maxCount {
            canonicalStates = group
            maxCount = len(group)
        }
    }

    if len(canonicalStates) == 0 {
        c.logger.Error("no canonical state found")
        return nil
    }

    // Use the state with highest epoch from canonical group
    canonical := canonicalStates[0]
    for _, state := range canonicalStates {
        if state.Epoch > canonical.Epoch {
            canonical = state
        }
    }

    return &CanonicalState{
        LastCheckpoint: canonical.LastCheckpoint,
        Epoch:          canonical.Epoch,
        ViewNumber:     canonical.ViewNumber,
    }
}

type CanonicalState struct {
    LastCheckpoint *Checkpoint
    Epoch          uint64
    ViewNumber     uint64
}
```

**Partition Recovery Timeline:**

| Time | Event | Action |
|------|-------|--------|
| T+0s | Quorum loss detected (<7 reachable) | Log warning, continue monitoring |
| T+60s | Quorum still lost | Enter partition mode, stop new transactions |
| T+60s - Healing | Partition active | Complete in-flight ops, checkpoint state |
| Healing | Quorum restored (7+ reachable) | Begin reconstitution |
| Healing+10s | Sync to canonical chain | Query states, apply majority |
| Healing+20s | Re-run coordinator selection | Elect new committee for next epoch |
| Healing+30s | Resume operations | Exit partition mode |

### Partition Recovery Protocol

When network partitions heal, the system must reconcile divergent states across partitions using vector clocks for lineage tracking and deterministic conflict resolution.

#### Vector Clock Partition Tracking

```go
// PartitionVectorClock tracks partition lineage for conflict resolution
type PartitionVectorClock struct {
    PartitionID     [32]byte           // Unique partition identifier
    CoordinatorClocks map[NodeID]uint64 // Per-coordinator logical clocks
    StartHeight     uint64              // Block height when partition started
    LatestHeight    uint64              // Current block height in partition
    TransactionLog  []TxID              // Ordered list of transactions
    CreatedAt       time.Time
}

// PartitionRecoveryManager handles partition merge and reconciliation
type PartitionRecoveryManager struct {
    localPartition    *PartitionVectorClock
    discoveredParts   map[[32]byte]*PartitionVectorClock
    mergeTimeout      time.Duration
    mu                sync.RWMutex
}

// Partition recovery constants
const (
    PartitionMergeTimeout       = 60 * time.Second  // Max time to complete merge
    PartitionDiscoveryInterval  = 5 * time.Second   // DHT advertisement refresh
    PartitionBatchSize          = 100               // Transactions per reconciliation batch
)
```

#### Partition Discovery via DHT

```go
// PartitionAdvertisement announces partition presence in DHT
type PartitionAdvertisement struct {
    PartitionID       [32]byte
    VectorClock       *PartitionVectorClock
    CoordinatorCount  int
    StakeWeight       uint64        // Total stake in partition
    LatestCheckpoint  *Checkpoint
    AdvertisedAt      time.Time
    Signature         []byte        // Signed by partition's active coordinators
}

// DiscoverPartitions finds all partitions via DHT advertisements
func (prm *PartitionRecoveryManager) DiscoverPartitions(
    ctx context.Context,
) ([]*PartitionAdvertisement, error) {
    // Query DHT for partition advertisements
    key := computePartitionDiscoveryKey()

    results, err := prm.dht.GetAll(ctx, key)
    if err != nil {
        return nil, fmt.Errorf("querying partitions: %w", err)
    }

    partitions := make([]*PartitionAdvertisement, 0)
    for _, result := range results {
        advert, err := parsePartitionAdvertisement(result)
        if err != nil {
            continue // Skip invalid advertisements
        }

        // Verify advertisement signatures
        if !prm.verifyPartitionSignatures(advert) {
            continue
        }

        partitions = append(partitions, advert)
    }

    return partitions, nil
}

// AdvertisePartition publishes local partition state to DHT
func (prm *PartitionRecoveryManager) AdvertisePartition(ctx context.Context) error {
    prm.mu.RLock()
    defer prm.mu.RUnlock()

    advert := &PartitionAdvertisement{
        PartitionID:      prm.localPartition.PartitionID,
        VectorClock:      prm.localPartition,
        CoordinatorCount: prm.getActiveCoordinatorCount(),
        StakeWeight:      prm.calculatePartitionStake(),
        LatestCheckpoint: prm.getLatestCheckpoint(),
        AdvertisedAt:     time.Now(),
    }

    // Sign with quorum of active coordinators
    advert.Signature = prm.signWithPartitionQuorum(advert)

    key := computePartitionDiscoveryKey()
    return prm.dht.Put(ctx, key, advert.Marshal())
}
```

#### Deterministic Conflict Resolution

```go
// DetermineCanonicalPartition selects the authoritative partition
// Uses deterministic rules: largest partition wins
func DetermineCanonicalPartition(partitions []*PartitionAdvertisement) *PartitionAdvertisement {
    if len(partitions) == 0 {
        return nil
    }

    // Sort by stake weight (descending), then by partition ID for tiebreaker
    sort.Slice(partitions, func(i, j int) bool {
        if partitions[i].StakeWeight != partitions[j].StakeWeight {
            return partitions[i].StakeWeight > partitions[j].StakeWeight
        }
        // Deterministic tiebreaker: lower partition ID wins
        return bytes.Compare(partitions[i].PartitionID[:], partitions[j].PartitionID[:]) < 0
    })

    return partitions[0]
}

// TransactionLogReconciliation merges transaction logs from partitions
type TransactionLogReconciliation struct {
    CanonicalPartition  *PartitionAdvertisement
    MinorityPartitions  []*PartitionAdvertisement
    CommonAncestor      *Checkpoint
    ConflictingTxs      []TxConflict
    ReplayableTxs       []TxID
    ProcessedBatches    int
}

// TxConflict records a transaction that conflicts across partitions
type TxConflict struct {
    TxID              TxID
    CanonicalVersion  *Transaction
    MinorityVersion   *Transaction
    ConflictType      TxConflictType
    Resolution        TxResolution
}

type TxConflictType uint8

const (
    ConflictTypeDoubleSpend TxConflictType = iota
    ConflictTypeOrderDiff
    ConflictTypeStateDiv
)

type TxResolution uint8

const (
    ResolutionKeepCanonical TxResolution = iota
    ResolutionReplayMinority
    ResolutionReject
)
```

#### Batched Transaction Reconciliation

```go
// ReconcileTransactionLogs merges transaction logs with batched processing
func (prm *PartitionRecoveryManager) ReconcileTransactionLogs(
    ctx context.Context,
    canonical *PartitionAdvertisement,
    minority []*PartitionAdvertisement,
) (*TransactionLogReconciliation, error) {
    reconciliation := &TransactionLogReconciliation{
        CanonicalPartition: canonical,
        MinorityPartitions: minority,
        ConflictingTxs:     make([]TxConflict, 0),
        ReplayableTxs:      make([]TxID, 0),
    }

    // Find common ancestor checkpoint
    commonAncestor, err := prm.findCommonAncestor(canonical, minority)
    if err != nil {
        return nil, fmt.Errorf("finding common ancestor: %w", err)
    }
    reconciliation.CommonAncestor = commonAncestor

    // Get canonical transaction set since common ancestor
    canonicalTxs := prm.getTransactionsSince(canonical, commonAncestor)
    canonicalSet := make(map[TxID]bool)
    for _, txID := range canonicalTxs {
        canonicalSet[txID] = true
    }

    // Process minority partitions in batches
    for _, minPart := range minority {
        minorityTxs := prm.getTransactionsSince(minPart, commonAncestor)

        // Process in batches to limit memory and enable progress
        for i := 0; i < len(minorityTxs); i += PartitionBatchSize {
            end := i + PartitionBatchSize
            if end > len(minorityTxs) {
                end = len(minorityTxs)
            }
            batch := minorityTxs[i:end]

            for _, txID := range batch {
                if canonicalSet[txID] {
                    // Already in canonical - skip
                    continue
                }

                // Check for conflicts
                conflict := prm.checkTxConflict(txID, canonicalTxs)
                if conflict != nil {
                    reconciliation.ConflictingTxs = append(reconciliation.ConflictingTxs, *conflict)
                } else {
                    // No conflict - can be replayed
                    reconciliation.ReplayableTxs = append(reconciliation.ReplayableTxs, txID)
                }
            }

            reconciliation.ProcessedBatches++
        }
    }

    return reconciliation, nil
}

// ApplyReconciliation applies the reconciliation result
func (prm *PartitionRecoveryManager) ApplyReconciliation(
    ctx context.Context,
    reconciliation *TransactionLogReconciliation,
) error {
    // Apply canonical state first
    if err := prm.syncToCanonicalState(ctx, reconciliation.CanonicalPartition); err != nil {
        return fmt.Errorf("syncing to canonical: %w", err)
    }

    // Replay non-conflicting minority transactions
    for _, txID := range reconciliation.ReplayableTxs {
        tx, err := prm.fetchTransaction(txID)
        if err != nil {
            continue // Skip if transaction unavailable
        }

        if err := prm.replayTransaction(ctx, tx); err != nil {
            // Log but continue - transaction may have become invalid
            prm.logger.Warn("failed to replay minority transaction",
                "tx_id", txID,
                "error", err)
        }
    }

    // Log conflicts for audit
    for _, conflict := range reconciliation.ConflictingTxs {
        prm.logConflictResolution(conflict)
    }

    return nil
}
```

**Partition Merge Timeline:**

| Phase | Duration | Action |
|-------|----------|--------|
| Partition Discovery | 0-10s | Query DHT for partition advertisements |
| Canonical Selection | 10-15s | Determine largest partition by stake |
| Common Ancestor | 15-20s | Find shared checkpoint between partitions |
| Transaction Batch 1 | 20-30s | Process first batch of minority transactions |
| Transaction Batch N | 30-60s | Process remaining batches |
| State Application | 60-90s | Apply canonical state + replay valid transactions |
| **Merge Timeout** | **60s max** | Abort merge if not complete within timeout |

**Conflict Resolution Rules:**

| Conflict Type | Resolution | Rationale |
|---------------|------------|-----------|
| **Double Spend** | Keep canonical | Canonical partition has quorum |
| **Order Difference** | Keep canonical order | Deterministic ordering |
| **State Divergence** | Reject minority tx | Canonical state is authoritative |
| **No Conflict** | Replay minority tx | Preserve valid minority work |

---

## Security Analysis

### Threat Model

| Attack Vector | Mitigation | Residual Risk |
|---------------|------------|---------------|
| **Sybil Attack** | VRF + reputation threshold + TPM attestation | Low |
| **Coordinator Collusion** | Geographic + vendor + tier diversity | Low |
| **VRF Manipulation** | Deterministic seed + cryptographic proofs | Negligible |
| **Primary Censorship** | 10s timeout + automatic failover | Low |
| **DoS on Coordinators** | Committee rotation + DDoS protection | Medium |
| **Long-Range Attack** | 30-day uptime requirement + fresh attestations | Low |
| **Network Partition** | Multiple regions required + timeout detection | Medium |

**Note:** Detailed threat analysis in [03-security-trust.md](03-security-trust.md) Section 2.

### Byzantine Fault Tolerance

```
Committee Size: 21
Threshold: 7 (33%)
Byzantine Tolerance: 6 (28%)
```

- **Honest Majority**: At least 7 of 21 must be honest for consensus (BFT requires n > 3f)
- **Safety**: Cannot finalize conflicting proposals (requires 3+ votes)
- **Liveness**: Guaranteed if >=3 coordinators responsive (60%)
- **Accountability**: All votes signed, misbehavior provable

### Cryptographic Security

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| VRF | ECVRF-ED25519-SHA512 (RFC 9381) | 128-bit |
| Signatures | Ed25519 (RFC 8032) | 128-bit |
| Hashing | SHA-256 | 128-bit |
| TPM | TPM 2.0 with EK/AK | Hardware-backed |

**Note:** Cryptographic details in [04-cryptographic-protocols.md](04-cryptographic-protocols.md).

### Attack Cost Analysis

**Scenario 1: Dominate Committee (control 7+ of 21 coordinators)**
- Requirements: Reputation >=0.95 on 7+ nodes, 99% uptime over 30 days, valid TPM attestations from 3+ different manufacturers
- Geographic constraint: Committee selected from MinRegions=15 with MaxPerRegion=2. To get 7 nodes, attacker needs control in 4+ different regions minimum (worst case: 2 nodes × 4 regions = 8 compromised positions)
- Attack difficulty: Must establish and maintain high-reputation nodes across 4+ different geographic regions with 3+ different TPM vendors over 185+ days (reputation earning + probation)
- **Estimated Cost**: $100K+ in infrastructure over 185+ days

**Scenario 2: Manipulate VRF**
- Requirements: Break SHA-256 preimage resistance OR break Ed25519 VRF security
- **Estimated Cost**: Computationally infeasible

**Scenario 3: Compromise TPMs**
- Requirements: Extract signing keys from 3+ TPMs from different vendors
- **Estimated Cost**: $1M+ per vendor (hardware security analysis)

---

## Performance Targets

| Metric | Target |
|--------|--------|
| VRF Evaluation | <10ms per candidate |
| Committee Selection | <5s (including diversity checks) |
| Consensus Latency | <500ms (p99 normal conditions) |
| Failure Detection | 10s (heartbeat timeout) |
| Re-election Time | <5s (single coordinator) |
| Full Re-election | <10s (complete committee) |
| Throughput | 100+ ops/sec (network-wide) |

---

## Protocol Hardening

This section addresses critical security issues in the consensus and coordination protocols.

### C1: Partition Recovery Consensus Protocol

Network partitions can cause divergent state across partition boundaries. Without proper recovery mechanisms, the network could permanently split after partition heals. This section defines canonical chain selection rules, checkpoint anchoring, and state reconciliation protocols.

#### Problem Statement

When a network partition occurs:
1. Each partition may elect separate coordinator committees
2. Transactions may be committed in conflicting orders
3. UTXO state may diverge between partitions
4. After partition heals, no mechanism exists to reconcile

**Attack Scenario**: Adversary induces partition, double-spends in minority partition, then reconnects expecting both transactions to persist.

#### Partition Detection

```go
// PartitionDetector monitors network connectivity for partition events
type PartitionDetector struct {
    reachabilityThreshold float64         // 0.50 = 50% of known nodes
    healingThreshold      float64         // 0.80 = 80% for healing
    checkInterval         time.Duration   // How often to check
    lastKnownGood         time.Time       // Last time we had full connectivity
    partitionStartTime    time.Time       // When current partition began
}

// PartitionState represents network state during partition
type PartitionState struct {
    PartitionID        [32]byte           // SHA256(sorted node IDs in partition)
    Nodes              []NodeID           // Nodes in this partition
    StakeWeight        uint64             // Total stake weight of partition
    CheckpointHeight   uint64             // Highest checkpoint in partition
    LastCheckpointHash [32]byte           // Hash of highest checkpoint
    TipHeight          uint64             // Highest block/batch height
    TipHash            [32]byte           // Hash of tip
    Committee          *Committee         // Active coordinator committee
    TransactionLog     []TxID             // Transactions since last checkpoint
}

// PartitionRecoveryState tracks recovery state machine
type PartitionRecoveryState uint8

const (
    PRStateNormal        PartitionRecoveryState = iota // >80% reachability
    PRStatePartitioned                                  // Detected <50% reachability
    PRStateHealing                                      // >80% reachability, reconciling
    PRStateReconciled                                   // Consensus achieved
)

// DetectPartition monitors reachability and triggers partition mode
func (pd *PartitionDetector) DetectPartition(ctx context.Context) <-chan PartitionEvent {
    events := make(chan PartitionEvent, 10)

    go func() {
        defer close(events)
        ticker := time.NewTicker(pd.checkInterval)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                reachability := pd.calculateReachability()

                if reachability < pd.reachabilityThreshold {
                    if pd.partitionStartTime.IsZero() {
                        pd.partitionStartTime = time.Now()
                        events <- PartitionEvent{
                            Type:         PartitionDetected,
                            Reachability: reachability,
                            Timestamp:    time.Now(),
                        }
                    }
                } else if reachability >= pd.healingThreshold {
                    if !pd.partitionStartTime.IsZero() {
                        events <- PartitionEvent{
                            Type:              PartitionHealing,
                            Reachability:      reachability,
                            PartitionDuration: time.Since(pd.partitionStartTime),
                            Timestamp:         time.Now(),
                        }
                        pd.partitionStartTime = time.Time{}
                    }
                }
            }
        }
    }()

    return events
}
```

#### Canonical Chain Selection Rules

When partitions merge, the canonical chain is selected using a deterministic algorithm that all nodes can independently verify:

```go
// CanonicalChainSelector implements deterministic chain selection
type CanonicalChainSelector struct {
    stakeWeightAdvantage float64 // 1.10 = 10% advantage required
}

// SelectCanonicalPartition determines which partition's state is authoritative
// Rules applied in order:
// 1. Largest partition by stake weight (if >10% advantage)
// 2. Longest checkpoint chain (tie-breaker)
// 3. VRF deterministic random (final tie-breaker)
func (ccs *CanonicalChainSelector) SelectCanonicalPartition(
    partitions []PartitionState,
) (*PartitionState, error) {
    if len(partitions) == 0 {
        return nil, ErrNoPartitions
    }
    if len(partitions) == 1 {
        return &partitions[0], nil
    }

    // Sort by stake weight descending
    byStake := make([]PartitionState, len(partitions))
    copy(byStake, partitions)
    sort.Slice(byStake, func(i, j int) bool {
        return byStake[i].StakeWeight > byStake[j].StakeWeight
    })

    // Rule 1: Largest partition by stake weight wins (if >10% advantage)
    stakeRatio := float64(byStake[0].StakeWeight) / float64(byStake[1].StakeWeight)
    if stakeRatio >= ccs.stakeWeightAdvantage {
        return &byStake[0], nil
    }

    // Rule 2: Longest checkpoint chain wins (tie-breaker)
    byCheckpoints := make([]PartitionState, len(partitions))
    copy(byCheckpoints, partitions)
    sort.Slice(byCheckpoints, func(i, j int) bool {
        return byCheckpoints[i].CheckpointHeight > byCheckpoints[j].CheckpointHeight
    })

    if byCheckpoints[0].CheckpointHeight > byCheckpoints[1].CheckpointHeight {
        return &byCheckpoints[0], nil
    }

    // Rule 3: VRF tiebreaker (deterministic random selection)
    return ccs.vrfTiebreaker(byCheckpoints[0], byCheckpoints[1])
}

// vrfTiebreaker uses VRF for deterministic random selection
func (ccs *CanonicalChainSelector) vrfTiebreaker(
    p1, p2 PartitionState,
) (*PartitionState, error) {
    // Create deterministic seed from both partition states
    h := sha256.New()
    h.Write(p1.LastCheckpointHash[:])
    h.Write(p2.LastCheckpointHash[:])
    binary.Write(h, binary.BigEndian, p1.TipHeight)
    binary.Write(h, binary.BigEndian, p2.TipHeight)
    seed := h.Sum(nil)

    // Evaluate VRF for representative node of each partition
    // (use node with lowest ID for determinism)
    p1Rep := lowestNodeID(p1.Nodes)
    p2Rep := lowestNodeID(p2.Nodes)

    p1VRF := evaluateVRF(p1Rep, seed)
    p2VRF := evaluateVRF(p2Rep, seed)

    if bytes.Compare(p1VRF, p2VRF) < 0 {
        return &p1, nil
    }
    return &p2, nil
}
```

##### Exact 50%-50% Partition Handling (P4-C8)

**PROBLEM**: When network splits into exactly equal halves (by stake weight AND checkpoint height), the VRF tiebreaker alone is insufficient. Without explicit handling:
1. Both partitions may continue accepting transactions indefinitely
2. Orphaned transactions on the losing side have no recovery path
3. No reconciliation timeout means indefinite parallel operation

**SOLUTION**: Define explicit 50-50 partition behavior with reconciliation window, orphan handling, and mandatory freeze period.

```
                    50%-50% PARTITION RESOLUTION PROTOCOL

    ┌─────────────────────────────────────────────────────────────────────┐
    │                   PARTITION DETECTED                                │
    │                   (< 50% nodes reachable)                          │
    └──────────────────────────────┬──────────────────────────────────────┘
                                   │
                                   ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                   DETERMINE PARTITION TYPE                          │
    │                                                                     │
    │   Calculate stake weight ratio between detected partitions          │
    │   If stake difference > 10%: Clear winner → normal operation       │
    │   If stake difference ≤ 10%: 50-50 split → SPECIAL HANDLING        │
    └──────────────────────────────┬──────────────────────────────────────┘
                                   │
                       (Stake difference ≤ 10%)
                                   │
                                   ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │           ENTER CONSERVATIVE MODE (Both Partitions)                 │
    │                                                                     │
    │   1. Broadcast PARTITION_CONSERVATIVE message                       │
    │   2. Set ConservativeMode = true                                    │
    │   3. Start ReconciliationTimeout (10 minutes)                       │
    │   4. Reduce transaction acceptance rate to 50%                      │
    │   5. Begin collecting partition-specific checkpoint                  │
    │                                                                     │
    │   WHY: Reduces total orphan transactions if we're the loser        │
    └──────────────────────────────┬──────────────────────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
    ┌─────────────────────────┐    ┌─────────────────────────────────────┐
    │  Partition Heals        │    │  Timeout (10min) Reached            │
    │  (Other side reachable) │    │  (Still partitioned)                │
    └───────────┬─────────────┘    └──────────────────┬──────────────────┘
                │                                     │
                └────────────────┬────────────────────┘
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │               VRF TIEBREAKER EVALUATION                             │
    │                                                                     │
    │   When partition is EXACTLY 50%-50%:                                │
    │                                                                     │
    │   1. Both partitions compute VRF on: partition_id || epoch          │
    │   2. VRF input: SHA256(partition_id || current_epoch)               │
    │   3. Each partition uses its lowest NodeID as VRF signer            │
    │   4. Partition with LOWER VRF output is canonical                   │
    │                                                                     │
    │   VRF(lowestNodeID(p1), partition_id || epoch) vs                   │
    │   VRF(lowestNodeID(p2), partition_id || epoch)                      │
    │                                                                     │
    │   CRITICAL: All nodes MUST compute the same result                  │
    │   CRITICAL: VRF is deterministic - same input = same output         │
    └──────────────────────────────┬──────────────────────────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │                                         │
              ▼                                         ▼
    ┌─────────────────────────┐          ┌─────────────────────────────┐
    │   CANONICAL PARTITION   │          │   NON-CANONICAL PARTITION   │
    │   (VRF Winner)          │          │   (VRF Loser)               │
    │                         │          │                             │
    │   1. Resume normal ops  │          │   1. FREEZE all new TXs     │
    │   2. Exit conservative  │          │   2. Begin orphan export    │
    │   3. Accept incoming    │          │   3. Rollback to last       │
    │      reconciliation     │          │      shared checkpoint      │
    │                         │          │   4. Import canonical state │
    └─────────────────────────┘          └─────────────────────────────┘
```

```go
// FiftyFiftyPartitionConfig defines 50-50 split handling parameters
const (
    // When to consider a split "50-50" (stake ratio < this threshold)
    FiftyFiftyThreshold        = 1.10  // 10% stake advantage required for clear winner

    // How long to operate in conservative mode before forcing resolution
    ReconciliationTimeout      = 10 * time.Minute

    // Transaction rate reduction during conservative mode
    ConservativeTxRateMultiplier = 0.50  // 50% of normal rate

    // Orphan transaction handling
    OrphanExportBatchSize      = 1000
    OrphanExportTimeout        = 5 * time.Minute
    MaxOrphanRetryAttempts     = 3
)

// PartitionOperatingMode tracks partition-aware operation state
type PartitionOperatingMode uint8

const (
    ModeNormal           PartitionOperatingMode = 0 // Normal operation (>50% reachable)
    ModeConservative     PartitionOperatingMode = 1 // 50-50 split detected
    ModeFrozen           PartitionOperatingMode = 2 // Lost VRF, awaiting reconciliation
    ModeReconciling      PartitionOperatingMode = 3 // Importing canonical state
)

// FiftyFiftyPartitionManager handles exact split scenarios
type FiftyFiftyPartitionManager struct {
    mode                PartitionOperatingMode
    enteredConservative time.Time
    localPartition      *PartitionState
    knownPartitions     []PartitionState

    // Orphan transaction tracking
    orphanTxs           map[TxID]*OrphanTransaction
    orphanExportStatus  map[TxID]OrphanExportStatus

    // VRF result (computed once, cached)
    vrfResult           *VRFTiebreakerResult
    vrfComputed         bool

    mu                  sync.RWMutex
}

// OrphanTransaction tracks transactions that may need re-submission
type OrphanTransaction struct {
    TxID            TxID
    Transaction     []byte          // Serialized transaction
    ConfirmedAt     time.Time       // When confirmed in this partition
    PartitionID     [32]byte        // Which partition confirmed it
    OrphanedReason  OrphanReason
    RetryCount      int
    LastRetryAt     time.Time
}

type OrphanReason uint8

const (
    OrphanReasonVRFLoss       OrphanReason = 1 // Partition lost VRF tiebreaker
    OrphanReasonLowerStake    OrphanReason = 2 // Partition had lower stake
    OrphanReasonShorterChain  OrphanReason = 3 // Partition had shorter chain
)

// HandlePartitionDetected processes new partition detection
func (pm *FiftyFiftyPartitionManager) HandlePartitionDetected(
    localPartition *PartitionState,
    detectedPartitions []PartitionState,
) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pm.localPartition = localPartition
    pm.knownPartitions = detectedPartitions

    // Determine if this is a 50-50 split
    if pm.is5050Split(detectedPartitions) {
        pm.enterConservativeMode()
        return nil
    }

    // Clear winner exists - no special handling needed
    pm.mode = ModeNormal
    return nil
}

// is5050Split checks if partition is close enough to require special handling
func (pm *FiftyFiftyPartitionManager) is5050Split(partitions []PartitionState) bool {
    if len(partitions) < 2 {
        return false
    }

    // Find two largest partitions by stake
    sorted := make([]PartitionState, len(partitions))
    copy(sorted, partitions)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i].StakeWeight > sorted[j].StakeWeight
    })

    if sorted[1].StakeWeight == 0 {
        return false
    }

    ratio := float64(sorted[0].StakeWeight) / float64(sorted[1].StakeWeight)
    return ratio < FiftyFiftyThreshold
}

// enterConservativeMode reduces operation intensity during uncertain split
func (pm *FiftyFiftyPartitionManager) enterConservativeMode() {
    pm.mode = ModeConservative
    pm.enteredConservative = time.Now()

    log.Warn("Entering 50-50 partition conservative mode",
        "local_stake", pm.localPartition.StakeWeight,
        "timeout", ReconciliationTimeout)

    // Broadcast conservative mode to partition peers
    pm.broadcastPartitionMessage(&PartitionMessage{
        Type:        PartitionMsgConservative,
        PartitionID: pm.localPartition.PartitionID,
        Timestamp:   time.Now(),
    })

    // Start reconciliation timeout
    go pm.reconciliationTimeoutWatcher()
}

// reconciliationTimeoutWatcher forces resolution after timeout
func (pm *FiftyFiftyPartitionManager) reconciliationTimeoutWatcher() {
    timer := time.NewTimer(ReconciliationTimeout)
    <-timer.C

    pm.mu.Lock()
    defer pm.mu.Unlock()

    if pm.mode != ModeConservative {
        return // Already resolved
    }

    log.Warn("50-50 partition reconciliation timeout reached, forcing VRF resolution")
    pm.forceVRFResolution()
}

// forceVRFResolution computes VRF tiebreaker and handles result
// Uses partition_id || epoch as VRF input for deterministic resolution
func (pm *FiftyFiftyPartitionManager) forceVRFResolution() {
    if pm.vrfComputed {
        return // Already computed
    }

    // Find the other partition (largest that isn't us)
    var otherPartition *PartitionState
    for i := range pm.knownPartitions {
        if pm.knownPartitions[i].PartitionID != pm.localPartition.PartitionID {
            if otherPartition == nil || pm.knownPartitions[i].StakeWeight > otherPartition.StakeWeight {
                otherPartition = &pm.knownPartitions[i]
            }
        }
    }

    if otherPartition == nil {
        log.Error("Cannot resolve 50-50: no other partition known")
        return
    }

    // Compute VRF tiebreaker using partition_id || epoch
    currentEpoch := GetCurrentEpoch()
    localVRF := pm.computePartitionVRF(pm.localPartition, currentEpoch)
    otherVRF := pm.computePartitionVRF(otherPartition, currentEpoch)

    // Lower VRF output wins (canonical partition)
    localWins := bytes.Compare(localVRF, otherVRF) < 0

    pm.vrfComputed = true
    if localWins {
        pm.vrfResult = &VRFTiebreakerResult{
            Winner:        pm.localPartition.PartitionID,
            Loser:         otherPartition.PartitionID,
            WinnerVRF:     localVRF,
            LoserVRF:      otherVRF,
            ComputedAt:    time.Now(),
        }
        pm.handleVRFWin()
    } else {
        pm.vrfResult = &VRFTiebreakerResult{
            Winner:        otherPartition.PartitionID,
            Loser:         pm.localPartition.PartitionID,
            WinnerVRF:     otherVRF,
            LoserVRF:      localVRF,
            ComputedAt:    time.Now(),
        }
        pm.handleVRFLoss()
    }
}

// computePartitionVRF generates VRF output for partition using partition_id || epoch
func (pm *FiftyFiftyPartitionManager) computePartitionVRF(
    partition *PartitionState,
    epoch uint64,
) []byte {
    // VRF input: SHA256(partition_id || epoch)
    h := sha256.New()
    h.Write(partition.PartitionID[:])
    binary.Write(h, binary.BigEndian, epoch)
    vrfInput := h.Sum(nil)

    // Get lowest NodeID in partition (deterministic signer selection)
    lowestNode := partition.GetLowestNodeID()

    // Compute VRF using the lowest node's VRF key
    vrfOutput, _ := ComputeVRF(lowestNode.VRFPrivateKey, vrfInput)
    return vrfOutput
}

#### Cross-Partition VRF Proof Verification Protocol

During a 50-50 network split, both partitions must independently compute VRF outputs and verify each other's proofs to deterministically select the canonical partition. This section specifies the complete cross-partition VRF proof exchange and verification protocol.

**Protocol Overview:**

When a 50-50 split is detected and the reconciliation timeout expires, both partitions execute the following protocol:

1. Each partition computes a VRF output using their lowest NodeID's VRF key
2. VRF proofs are broadcast via DHT advertisement
3. Both partitions verify the received VRF proof using public keys
4. The partition with the lower VRF output becomes canonical
5. The losing partition freezes and begins reconciliation

**VRF Proof Message Types:**

```go
// pkg/dht/partition/vrf_messages.go

// VRFProofAdvertisement is broadcast via DHT to announce partition's VRF output
type VRFProofAdvertisement struct {
    // Message header
    Type          PartitionMsgType  // PartitionMsgVRFProof
    PartitionID   [32]byte
    Epoch         uint64
    Timestamp     time.Time

    // VRF computation details
    SignerNodeID  NodeID            // Lowest NodeID that computed the VRF
    SignerVRFPK   *vrf.PublicKey    // VRF public key for verification

    // VRF input and output
    VRFInput      [32]byte          // SHA256(partition_id || epoch)
    VRFOutput     [64]byte          // VRF output (pseudorandom value)
    VRFProof      []byte            // VRF proof for verification

    // Partition membership proof
    MembershipRoot [32]byte         // Merkle root of partition members
    MembershipProof [][]byte        // Merkle proof for SignerNodeID

    // Signature over entire message
    Signature     []byte            // Ed25519 signature by SignerNodeID
}

// VRFVerificationResult contains the outcome of VRF proof verification
type VRFVerificationResult struct {
    PartitionID     [32]byte
    Valid           bool
    VRFOutput       [64]byte
    VerifiedAt      time.Time
    ErrorCode       VRFVerificationError
    ErrorDetail     string
}

// VRFVerificationError codes
type VRFVerificationError uint8

const (
    VRFVerifySuccess           VRFVerificationError = iota
    VRFVerifyInvalidProof                           // VRF proof does not verify
    VRFVerifyWrongSigner                            // Signer is not lowest NodeID
    VRFVerifyInvalidMembership                      // Membership proof invalid
    VRFVerifyInputMismatch                          // VRF input doesn't match expected
    VRFVerifyExpired                                // Message too old
    VRFVerifyBadSignature                           // Message signature invalid
)
```

**VRF Computation for Partition:**

```go
// pkg/dht/partition/vrf_compute.go

// ComputePartitionVRFWithProof generates VRF output and proof for partition
func (pm *FiftyFiftyPartitionManager) ComputePartitionVRFWithProof(
    partition *PartitionState,
    epoch uint64,
) (*VRFProofAdvertisement, error) {

    // Step 1: Compute VRF input
    // VRF input: SHA256(partition_id || epoch)
    vrfInput := computeVRFInput(partition.PartitionID, epoch)

    // Step 2: Get lowest NodeID in partition (deterministic signer selection)
    lowestNode := partition.GetLowestNodeID()
    if lowestNode == nil {
        return nil, &VRFComputationError{
            Phase:  "signer_selection",
            Reason: "no_nodes_in_partition",
        }
    }

    // Step 3: Compute VRF using the lowest node's VRF key
    vrfOutput, vrfProof, err := vrf.Prove(lowestNode.VRFPrivateKey, vrfInput[:])
    if err != nil {
        return nil, &VRFComputationError{
            Phase:  "vrf_prove",
            Cause:  err,
        }
    }

    // Step 4: Generate membership proof for the signer
    membershipRoot, membershipProof := partition.GenerateMembershipProof(lowestNode.ID)

    // Step 5: Construct advertisement message
    advert := &VRFProofAdvertisement{
        Type:            PartitionMsgVRFProof,
        PartitionID:     partition.PartitionID,
        Epoch:           epoch,
        Timestamp:       time.Now(),
        SignerNodeID:    lowestNode.ID,
        SignerVRFPK:     lowestNode.VRFPublicKey,
        MembershipRoot:  membershipRoot,
        MembershipProof: membershipProof,
    }
    copy(advert.VRFInput[:], vrfInput[:])
    copy(advert.VRFOutput[:], vrfOutput)
    advert.VRFProof = vrfProof

    // Step 6: Sign the advertisement
    advert.Signature = pm.signVRFAdvertisement(advert, lowestNode.SigningKey)

    return advert, nil
}

// computeVRFInput creates the deterministic input for VRF computation
func computeVRFInput(partitionID [32]byte, epoch uint64) [32]byte {
    h := sha256.New()
    h.Write(partitionID[:])
    binary.Write(h, binary.BigEndian, epoch)
    var input [32]byte
    copy(input[:], h.Sum(nil))
    return input
}
```

**DHT Advertisement and Discovery:**

```go
// pkg/dht/partition/vrf_broadcast.go

// BroadcastVRFProof advertises the VRF proof via DHT
func (pm *FiftyFiftyPartitionManager) BroadcastVRFProof(advert *VRFProofAdvertisement) error {
    // Serialize advertisement
    data, err := proto.Marshal(advert)
    if err != nil {
        return &VRFBroadcastError{Phase: "serialize", Cause: err}
    }

    // DHT key for VRF proofs: /partition/vrf/{epoch}/{partition_id}
    key := fmt.Sprintf("/partition/vrf/%d/%x", advert.Epoch, advert.PartitionID[:8])

    // Store in DHT with TTL of 1 hour
    err = pm.dht.Put(key, data, DHTPutOptions{
        TTL:       1 * time.Hour,
        Replicas:  5,  // Higher replication for critical data
        Quorum:    3,
    })
    if err != nil {
        return &VRFBroadcastError{Phase: "dht_put", Cause: err}
    }

    // Also broadcast via gossip for faster propagation
    pm.gossip.Broadcast(&GossipMessage{
        Type:    GossipVRFProof,
        Payload: data,
        TTL:     3,  // 3-hop propagation
    })

    return nil
}

// DiscoverOtherPartitionVRF attempts to find VRF proofs from other partitions
func (pm *FiftyFiftyPartitionManager) DiscoverOtherPartitionVRF(epoch uint64) ([]*VRFProofAdvertisement, error) {
    // Search for all VRF proofs at this epoch
    keyPrefix := fmt.Sprintf("/partition/vrf/%d/", epoch)

    results, err := pm.dht.GetWithPrefix(keyPrefix, DHTGetOptions{
        Timeout: 30 * time.Second,
        MaxResults: 10,
    })
    if err != nil {
        return nil, &VRFDiscoveryError{Phase: "dht_get", Cause: err}
    }

    adverts := make([]*VRFProofAdvertisement, 0, len(results))
    for _, data := range results {
        var advert VRFProofAdvertisement
        if err := proto.Unmarshal(data, &advert); err != nil {
            continue  // Skip malformed advertisements
        }

        // Skip our own partition
        if advert.PartitionID == pm.localPartition.PartitionID {
            continue
        }

        adverts = append(adverts, &advert)
    }

    return adverts, nil
}
```

**VRF Proof Verification:**

```go
// pkg/dht/partition/vrf_verify.go

// VerifyVRFProof validates a VRF proof advertisement from another partition
func (pm *FiftyFiftyPartitionManager) VerifyVRFProof(
    advert *VRFProofAdvertisement,
    expectedEpoch uint64,
) *VRFVerificationResult {

    result := &VRFVerificationResult{
        PartitionID: advert.PartitionID,
        VerifiedAt:  time.Now(),
    }

    // Check 1: Verify message is not expired (within 5 minutes)
    if time.Since(advert.Timestamp) > 5*time.Minute {
        result.ErrorCode = VRFVerifyExpired
        result.ErrorDetail = fmt.Sprintf("message_age=%v", time.Since(advert.Timestamp))
        return result
    }

    // Check 2: Verify epoch matches
    if advert.Epoch != expectedEpoch {
        result.ErrorCode = VRFVerifyInputMismatch
        result.ErrorDetail = fmt.Sprintf("expected_epoch=%d, got=%d", expectedEpoch, advert.Epoch)
        return result
    }

    // Check 3: Verify VRF input is correctly computed
    expectedInput := computeVRFInput(advert.PartitionID, advert.Epoch)
    if expectedInput != advert.VRFInput {
        result.ErrorCode = VRFVerifyInputMismatch
        result.ErrorDetail = "vrf_input_mismatch"
        return result
    }

    // Check 4: Verify membership proof (signer is actually in the partition)
    if !verifyMembershipProof(advert.SignerNodeID, advert.MembershipRoot, advert.MembershipProof) {
        result.ErrorCode = VRFVerifyInvalidMembership
        result.ErrorDetail = "signer_not_in_partition"
        return result
    }

    // Check 5: Verify signer is the lowest NodeID (requires partition membership list)
    // This check uses the membership root to verify lowest-ness
    if !pm.verifyLowestNodeID(advert.SignerNodeID, advert.MembershipRoot) {
        result.ErrorCode = VRFVerifyWrongSigner
        result.ErrorDetail = "signer_not_lowest_node"
        return result
    }

    // Check 6: Verify message signature
    if !verifyAdvertisementSignature(advert) {
        result.ErrorCode = VRFVerifyBadSignature
        result.ErrorDetail = "invalid_message_signature"
        return result
    }

    // Check 7: Verify VRF proof using signer's public key
    valid, err := vrf.Verify(advert.SignerVRFPK, advert.VRFInput[:], advert.VRFOutput[:], advert.VRFProof)
    if err != nil || !valid {
        result.ErrorCode = VRFVerifyInvalidProof
        if err != nil {
            result.ErrorDetail = err.Error()
        } else {
            result.ErrorDetail = "vrf_proof_verification_failed"
        }
        return result
    }

    // All checks passed
    result.Valid = true
    result.ErrorCode = VRFVerifySuccess
    copy(result.VRFOutput[:], advert.VRFOutput[:])

    return result
}
```

**Complete 50-50 Resolution Protocol:**

```go
// pkg/dht/partition/vrf_resolution.go

// ResolveViaVRF executes the complete VRF-based partition resolution protocol
func (pm *FiftyFiftyPartitionManager) ResolveViaVRF() error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if pm.vrfComputed {
        return nil  // Already resolved
    }

    currentEpoch := GetCurrentEpoch()

    // Step 1: Compute and broadcast our VRF proof
    localAdvert, err := pm.ComputePartitionVRFWithProof(pm.localPartition, currentEpoch)
    if err != nil {
        return &VRFResolutionError{Phase: "compute_local", Cause: err}
    }

    if err := pm.BroadcastVRFProof(localAdvert); err != nil {
        return &VRFResolutionError{Phase: "broadcast", Cause: err}
    }

    // Step 2: Wait for and discover other partition's VRF proof
    var otherAdvert *VRFProofAdvertisement
    discoveryDeadline := time.Now().Add(30 * time.Second)

    for time.Now().Before(discoveryDeadline) {
        adverts, err := pm.DiscoverOtherPartitionVRF(currentEpoch)
        if err != nil {
            log.Warn("VRF discovery error", "error", err)
            time.Sleep(1 * time.Second)
            continue
        }

        if len(adverts) > 0 {
            otherAdvert = adverts[0]  // Take first valid other partition
            break
        }

        time.Sleep(1 * time.Second)
    }

    if otherAdvert == nil {
        return &VRFResolutionError{
            Phase:  "discovery",
            Reason: "no_other_partition_found",
        }
    }

    // Step 3: Verify other partition's VRF proof
    verifyResult := pm.VerifyVRFProof(otherAdvert, currentEpoch)
    if !verifyResult.Valid {
        return &VRFResolutionError{
            Phase:  "verification",
            Reason: string(verifyResult.ErrorCode),
            Detail: verifyResult.ErrorDetail,
        }
    }

    // Step 4: Compare VRF outputs - lower wins
    localWins := bytes.Compare(localAdvert.VRFOutput[:], otherAdvert.VRFOutput[:]) < 0

    pm.vrfComputed = true
    pm.vrfResult = &VRFTiebreakerResult{
        ComputedAt:   time.Now(),
        LocalVRF:     localAdvert.VRFOutput[:],
        OtherVRF:     otherAdvert.VRFOutput[:],
        LocalProof:   localAdvert.VRFProof,
        OtherProof:   otherAdvert.VRFProof,
        OtherPK:      otherAdvert.SignerVRFPK,
    }

    if localWins {
        pm.vrfResult.Winner = pm.localPartition.PartitionID
        pm.vrfResult.Loser = otherAdvert.PartitionID
        pm.vrfResult.WinnerVRF = localAdvert.VRFOutput[:]
        pm.vrfResult.LoserVRF = otherAdvert.VRFOutput[:]
        pm.handleVRFWin()
    } else {
        pm.vrfResult.Winner = otherAdvert.PartitionID
        pm.vrfResult.Loser = pm.localPartition.PartitionID
        pm.vrfResult.WinnerVRF = otherAdvert.VRFOutput[:]
        pm.vrfResult.LoserVRF = localAdvert.VRFOutput[:]
        pm.handleVRFLoss()
    }

    return nil
}
```

**Protocol Sequence Diagram:**

```
                    VRF-BASED 50-50 PARTITION RESOLUTION

    Partition A                    DHT                    Partition B
         │                          │                          │
         │  Compute VRF_A           │      Compute VRF_B       │
         │  (lowest node signs)     │      (lowest node signs) │
         │                          │                          │
         │  VRFProofAdvertisement   │                          │
         ├─────────────────────────>│                          │
         │                          │   VRFProofAdvertisement  │
         │                          │<─────────────────────────│
         │                          │                          │
         │  GetWithPrefix(/vrf/)    │                          │
         ├─────────────────────────>│                          │
         │                          │   GetWithPrefix(/vrf/)   │
         │                          │<─────────────────────────│
         │                          │                          │
         │  [VRFProofAdvertisement] │                          │
         │<─────────────────────────│                          │
         │                          │  [VRFProofAdvertisement] │
         │                          │─────────────────────────>│
         │                          │                          │
         │  VerifyVRFProof(B)       │       VerifyVRFProof(A)  │
         │  - Check epoch           │       - Check epoch      │
         │  - Check membership      │       - Check membership │
         │  - Check lowest node     │       - Check lowest node│
         │  - Verify VRF proof      │       - Verify VRF proof │
         │                          │                          │
         │  Compare: VRF_A < VRF_B  │       Compare: VRF_A < VRF_B
         │  Result: A WINS          │       Result: A WINS     │
         │                          │                          │
         │  handleVRFWin()          │       handleVRFLoss()    │
         │  - ModeNormal            │       - ModeFrozen       │
         │  - Broadcast canonical   │       - Begin reconcile  │
         │                          │                          │
```

**Security Properties:**

| Property | Guarantee |
|----------|-----------|
| **Determinism** | Same inputs always produce same winner |
| **Unpredictability** | VRF output cannot be predicted before computation |
| **Verifiability** | Any party can verify the VRF proof with public key |
| **Uniqueness** | Each partition can only produce one valid VRF output per epoch |
| **Non-manipulability** | Cannot choose favorable VRF output (determined by partition membership) |


// handleVRFWin resumes normal operation after winning VRF tiebreaker
func (pm *FiftyFiftyPartitionManager) handleVRFWin() {
    log.Info("Won VRF tiebreaker - resuming normal operation")

    pm.mode = ModeNormal

    // Broadcast canonical status
    pm.broadcastPartitionMessage(&PartitionMessage{
        Type:        PartitionMsgCanonical,
        PartitionID: pm.localPartition.PartitionID,
        VRFResult:   pm.vrfResult,
        Timestamp:   time.Now(),
    })
}

// handleVRFLoss freezes operation and begins reconciliation
func (pm *FiftyFiftyPartitionManager) handleVRFLoss() {
    log.Warn("Lost VRF tiebreaker - freezing transactions, beginning reconciliation")

    pm.mode = ModeFrozen

    // Identify orphan transactions (confirmed in our partition after split)
    pm.identifyOrphanTransactions()

    // Begin state reconciliation
    go pm.beginReconciliation()
}

// identifyOrphanTransactions finds transactions that will be orphaned
func (pm *FiftyFiftyPartitionManager) identifyOrphanTransactions() {
    // Get all transactions confirmed since partition began
    txs := GetTransactionsSince(pm.enteredConservative)

    for _, tx := range txs {
        pm.orphanTxs[tx.TxID] = &OrphanTransaction{
            TxID:           tx.TxID,
            Transaction:    tx.Serialize(),
            ConfirmedAt:    tx.ConfirmedAt,
            PartitionID:    pm.localPartition.PartitionID,
            OrphanedReason: OrphanReasonVRFLoss,
            RetryCount:     0,
        }
    }

    log.Info("Identified orphan transactions",
        "count", len(pm.orphanTxs),
        "partition_duration", time.Since(pm.enteredConservative))
}

// beginReconciliation imports canonical state and re-submits orphans
func (pm *FiftyFiftyPartitionManager) beginReconciliation() {
    pm.mu.Lock()
    pm.mode = ModeReconciling
    pm.mu.Unlock()

    // Step 1: Rollback to last shared checkpoint
    sharedCheckpoint := pm.findLastSharedCheckpoint()
    if err := RollbackToCheckpoint(sharedCheckpoint); err != nil {
        log.Error("Rollback failed", "checkpoint", sharedCheckpoint.Height, "error", err)
        return
    }

    // Step 2: Import canonical chain state
    if err := pm.importCanonicalState(); err != nil {
        log.Error("Canonical state import failed", "error", err)
        return
    }

    // Step 3: Re-submit orphan transactions to canonical chain
    pm.resubmitOrphanTransactions()

    // Step 4: Return to normal operation
    pm.mu.Lock()
    pm.mode = ModeNormal
    pm.enteredConservative = time.Time{}
    pm.vrfComputed = false
    pm.mu.Unlock()

    log.Info("Partition reconciliation complete")
}

// resubmitOrphanTransactions attempts to include orphans in canonical chain
func (pm *FiftyFiftyPartitionManager) resubmitOrphanTransactions() {
    for txID, orphan := range pm.orphanTxs {
        if orphan.RetryCount >= MaxOrphanRetryAttempts {
            pm.orphanExportStatus[txID] = OrphanExportFailed
            continue
        }

        // Attempt to submit to canonical chain
        err := SubmitTransaction(orphan.Transaction)
        if err != nil {
            if IsDoubleSpendError(err) {
                // Transaction conflicts with canonical chain - cannot recover
                pm.orphanExportStatus[txID] = OrphanExportConflict
                log.Warn("Orphan transaction conflicts with canonical chain",
                    "txid", txID, "error", err)
            } else {
                // Transient error - retry
                orphan.RetryCount++
                orphan.LastRetryAt = time.Now()
            }
        } else {
            pm.orphanExportStatus[txID] = OrphanExportSuccess
            log.Info("Orphan transaction resubmitted", "txid", txID)
        }
    }
}

type OrphanExportStatus uint8

const (
    OrphanExportPending   OrphanExportStatus = 0
    OrphanExportSuccess   OrphanExportStatus = 1
    OrphanExportConflict  OrphanExportStatus = 2 // Double-spend on canonical
    OrphanExportFailed    OrphanExportStatus = 3 // Max retries exceeded
)

// VRFTiebreakerResult records the deterministic VRF decision
type VRFTiebreakerResult struct {
    Winner      [32]byte
    Loser       [32]byte
    WinnerVRF   []byte
    LoserVRF    []byte
    Epoch       uint64    // Epoch used for VRF computation
    ComputedAt  time.Time
}
```

##### VRF Tie-Breaker Edge Cases and Failure Handling

**CRITICAL**: The VRF tie-breaker must handle edge cases to ensure deterministic partition resolution under all conditions, including VRF computation failures and the astronomically rare case of identical VRF outputs.

```go
// pkg/consensus/vrf_tiebreaker_edge_cases.go

// VRF computation constants
const (
    VRFComputationTimeout  = 5 * time.Second     // Maximum time for VRF computation
    VRFVerificationRetries = 3                    // Retry attempts on computation failure
    VRFVerificationWindow  = 30 * time.Second    // Time window for cross-partition verification
)

// VRFTiebreakerError tracks VRF computation failures
type VRFTiebreakerError struct {
    PartitionID    [32]byte
    NodeID         NodeID
    Reason         string
    Timestamp      time.Time
    FallbackUsed   bool
}

func (e *VRFTiebreakerError) Error() string {
    return fmt.Sprintf("VRF tiebreaker failure for partition %x node %x: %s (fallback=%v)",
        e.PartitionID[:8], e.NodeID[:8], e.Reason, e.FallbackUsed)
}

// computePartitionVRFWithFallback handles VRF computation with timeout and fallback
func (pm *FiftyFiftyPartitionManager) computePartitionVRFWithFallback(
    partition *PartitionState,
    epoch uint64,
) ([]byte, error) {
    // VRF input: SHA256(partition_id || epoch)
    h := sha256.New()
    h.Write(partition.PartitionID[:])
    binary.Write(h, binary.BigEndian, epoch)
    vrfInput := h.Sum(nil)

    // Get lowest NodeID in partition (deterministic signer selection)
    lowestNode := partition.GetLowestNodeID()

    // Attempt VRF computation with timeout
    vrfChan := make(chan []byte, 1)
    errChan := make(chan error, 1)

    go func() {
        vrfOutput, err := ComputeVRF(lowestNode.VRFPrivateKey, vrfInput)
        if err != nil {
            errChan <- err
            return
        }
        vrfChan <- vrfOutput
    }()

    select {
    case vrfOutput := <-vrfChan:
        return vrfOutput, nil
    case err := <-errChan:
        // VRF computation failed - use fallback
        return pm.fallbackDeterministicSelection(partition, epoch, err)
    case <-time.After(VRFComputationTimeout):
        // VRF computation timeout - use fallback
        return pm.fallbackDeterministicSelection(partition, epoch,
            fmt.Errorf("VRF computation timeout after %v", VRFComputationTimeout))
    }
}

// fallbackDeterministicSelection provides deterministic selection when VRF fails
// Fallback chain: Lexicographic NodeID sort
func (pm *FiftyFiftyPartitionManager) fallbackDeterministicSelection(
    partition *PartitionState,
    epoch uint64,
    vrfError error,
) ([]byte, error) {
    log.Warn("VRF computation failed, using fallback selection",
        "partition_id", partition.PartitionID,
        "epoch", epoch,
        "error", vrfError)

    // Fallback: Deterministic hash based on sorted NodeIDs
    // This ensures all partitions compute the same "VRF" output even if VRF fails
    sortedNodes := make([]NodeID, len(partition.Nodes))
    copy(sortedNodes, partition.Nodes)
    sort.Slice(sortedNodes, func(i, j int) bool {
        return bytes.Compare(sortedNodes[i][:], sortedNodes[j][:]) < 0
    })

    // Hash(epoch || sorted_node_ids)
    h := sha256.New()
    binary.Write(h, binary.BigEndian, epoch)
    for _, nodeID := range sortedNodes {
        h.Write(nodeID[:])
    }

    fallbackOutput := h.Sum(nil)

    // Record fallback usage
    pm.recordVRFFailure(&VRFTiebreakerError{
        PartitionID:  partition.PartitionID,
        NodeID:       sortedNodes[0],
        Reason:       vrfError.Error(),
        Timestamp:    time.Now(),
        FallbackUsed: true,
    })

    return fallbackOutput, nil
}

// resolveIdenticalVRFOutputs handles the astronomically rare case of identical VRF outputs
// Probability: ~2^-256 for SHA-256 based VRF
func (pm *FiftyFiftyPartitionManager) resolveIdenticalVRFOutputs(
    p1, p2 *PartitionState,
    vrfOutput []byte,
) *PartitionState {
    log.Error("CRITICAL: Identical VRF outputs detected (probability 2^-256)",
        "partition1", p1.PartitionID,
        "partition2", p2.PartitionID,
        "vrf_output", hex.EncodeToString(vrfOutput))

    // Final tiebreaker: Lowest NodeID lexicographically
    // This is the absolute last resort and ensures determinism
    p1LowestNode := p1.GetLowestNodeID()
    p2LowestNode := p2.GetLowestNodeID()

    if bytes.Compare(p1LowestNode[:], p2LowestNode[:]) < 0 {
        log.Info("Partition 1 selected via NodeID tiebreaker",
            "winning_node", p1LowestNode)
        return p1
    }

    log.Info("Partition 2 selected via NodeID tiebreaker",
        "winning_node", p2LowestNode)
    return p2
}

// Enhanced VRF resolution with complete edge case handling
func (pm *FiftyFiftyPartitionManager) forceVRFResolutionWithFallback() {
    if pm.vrfComputed {
        return // Already computed
    }

    // Find the other partition
    var otherPartition *PartitionState
    for i := range pm.knownPartitions {
        if pm.knownPartitions[i].PartitionID != pm.localPartition.PartitionID {
            if otherPartition == nil || pm.knownPartitions[i].StakeWeight > otherPartition.StakeWeight {
                otherPartition = &pm.knownPartitions[i]
            }
        }
    }

    if otherPartition == nil {
        log.Error("Cannot resolve 50-50: no other partition known")
        return
    }

    // Compute VRF with fallback handling
    currentEpoch := GetCurrentEpoch()
    localVRF, err1 := pm.computePartitionVRFWithFallback(pm.localPartition, currentEpoch)
    otherVRF, err2 := pm.computePartitionVRFWithFallback(otherPartition, currentEpoch)

    if err1 != nil || err2 != nil {
        log.Error("VRF computation failed for both partitions",
            "local_error", err1,
            "other_error", err2)
        // Both failed - this should never happen with fallback, but handle gracefully
        pm.handleCatastrophicVRFFailure()
        return
    }

    // Check for identical VRF outputs (astronomically rare)
    cmp := bytes.Compare(localVRF, otherVRF)
    var localWins bool

    if cmp == 0 {
        // Identical outputs - use NodeID tiebreaker
        winner := pm.resolveIdenticalVRFOutputs(pm.localPartition, otherPartition, localVRF)
        localWins = (winner.PartitionID == pm.localPartition.PartitionID)
    } else {
        // Normal case: lower VRF output wins
        localWins = (cmp < 0)
    }

    // Record result and handle outcome
    pm.vrfComputed = true
    if localWins {
        pm.vrfResult = &VRFTiebreakerResult{
            Winner:     pm.localPartition.PartitionID,
            Loser:      otherPartition.PartitionID,
            WinnerVRF:  localVRF,
            LoserVRF:   otherVRF,
            Epoch:      currentEpoch,
            ComputedAt: time.Now(),
        }
        pm.handleVRFWin()
    } else {
        pm.vrfResult = &VRFTiebreakerResult{
            Winner:     otherPartition.PartitionID,
            Loser:      pm.localPartition.PartitionID,
            WinnerVRF:  otherVRF,
            LoserVRF:   localVRF,
            Epoch:      currentEpoch,
            ComputedAt: time.Now(),
        }
        pm.handleVRFLoss()
    }

    // Cross-partition verification protocol
    go pm.verifyVRFConsensus()
}

// verifyVRFConsensus confirms all partitions reached the same conclusion
func (pm *FiftyFiftyPartitionManager) verifyVRFConsensus() {
    // Wait for verification window
    time.Sleep(VRFVerificationWindow)

    // Query other partition for their VRF result
    otherResult, err := pm.queryOtherPartitionVRFResult()
    if err != nil {
        log.Warn("Could not verify VRF consensus with other partition",
            "error", err)
        return // Best effort - proceed with local decision
    }

    // Verify both partitions computed the same winner
    if pm.vrfResult.Winner != otherResult.Winner {
        log.Error("CRITICAL: VRF consensus mismatch detected!",
            "local_winner", pm.vrfResult.Winner,
            "other_winner", otherResult.Winner)
        // Trigger manual intervention protocol
        pm.handleVRFConsensusMismatch(otherResult)
        return
    }

    log.Info("VRF consensus verified - both partitions agree",
        "winner", pm.vrfResult.Winner,
        "epoch", pm.vrfResult.Epoch)
}

// handleCatastrophicVRFFailure handles the case where VRF and all fallbacks fail
// This should never happen in practice but must be defined
func (pm *FiftyFiftyPartitionManager) handleCatastrophicVRFFailure() {
    log.Error("CATASTROPHIC: VRF and all fallbacks failed - manual intervention required")

    // Enter safe mode: freeze all operations
    pm.mode = ModeFrozen

    // Alert all administrators
    pm.broadcastEmergency(&EmergencyAlert{
        Type:      EmergencyVRFFailure,
        Timestamp: time.Now(),
        Details:   "VRF computation and all fallback mechanisms failed",
    })

    // Manual resolution required - wait for operator intervention
}
```

**VRF Tie-Breaker Resolution Chain**:

| Priority | Method | Trigger | Determinism |
|----------|--------|---------|-------------|
| 1 | VRF Computation | Normal operation | SHA-256 + Ed25519 VRF |
| 2 | Fallback: Hash(sorted NodeIDs) | VRF timeout or failure | SHA-256 deterministic hash |
| 3 | NodeID Lexicographic Sort | Identical VRF outputs (2^-256 probability) | Byte comparison |
| 4 | Manual Intervention | Catastrophic failure (all methods fail) | Operator decision |

**VRF Verification Protocol**:

After VRF tie-breaker resolution, both partitions MUST verify they reached the same conclusion:

1. **Compute Phase** (0-5s): Each partition computes VRF independently
2. **Decision Phase** (5-10s): Each partition determines winner/loser status
3. **Broadcast Phase** (10-20s): Partitions exchange VRF results
4. **Verification Phase** (20-50s): Confirm consensus on winner
5. **Reconciliation Phase** (50s+): Loser begins state import

If verification fails (partitions disagree on winner), manual intervention is required.

**50%-50% Partition Resolution Summary**:

| Parameter | Value | Description |
|-----------|-------|-------------|
| **VRF Input** | partition_id \|\| epoch | Deterministic input ensures all nodes compute same result |
| **VRF Computation Timeout** | 5 seconds | Maximum time for VRF evaluation before fallback |
| **Fallback Method** | Hash(sorted NodeIDs) | Deterministic fallback when VRF fails |
| **Final Tiebreaker** | Lowest NodeID | Ultimate deterministic selection (2^-256 probability) |
| **Verification Window** | 30 seconds | Time to confirm both partitions agree on winner |
| **Reconciliation Timeout** | 10 minutes | Maximum time to operate in conservative mode |
| **Canonical Selection** | Lower VRF output | Partition with lower VRF output becomes canonical |
| **Orphan Retry Attempts** | 3 | Maximum attempts to resubmit orphaned transactions |

**Orphan Transaction Handling for Non-Canonical Partition**:

When a partition loses the VRF tiebreaker:

1. **Freeze**: Immediately stop accepting new transactions
2. **Identify**: Collect all transactions confirmed during the partition
3. **Rollback**: Revert to the last shared checkpoint before partition
4. **Import**: Synchronize state from the canonical partition
5. **Resubmit**: Attempt to include orphan transactions in canonical chain
6. **Report**: Mark transactions as `Success`, `Conflict`, or `Failed`

Transactions that conflict with the canonical chain (double-spends) cannot be recovered and are marked as `OrphanExportConflict`.

```go
// ShouldAcceptTransaction checks if we should accept new transactions
func (pm *FiftyFiftyPartitionManager) ShouldAcceptTransaction() bool {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    switch pm.mode {
    case ModeNormal:
        return true
    case ModeConservative:
        // Accept at reduced rate (random sampling)
        return rand.Float64() < ConservativeTxRateMultiplier
    case ModeFrozen, ModeReconciling:
        return false
    default:
        return true
    }
}
```

#### Checkpoint Anchoring

Checkpoints provide irreversible finality anchors that prevent long-range attacks:

```go
// Checkpoint represents a finality anchor signed by CA pool
type Checkpoint struct {
    Height           uint64             // Checkpoint sequence number
    BlockHeight      uint64             // Block/batch height at checkpoint
    MerkleRoot       [32]byte           // State merkle root at this height
    UTXOSetHash      [32]byte           // Hash of UTXO set at checkpoint
    Timestamp        int64              // TPM-attested timestamp
    PrevCheckpoint   [32]byte           // Previous checkpoint hash (chain)
    VRFProof         []byte             // VRF proof for deterministic verification
    Signatures       []CheckpointSig    // Threshold signatures from CA pool
    ParticipantCount int                // Number of nodes that contributed
}

// CheckpointSig is a TPM-backed signature on checkpoint
type CheckpointSig struct {
    NodeID      NodeID
    Signature   []byte
    TPMQuote    []byte  // TPM quote proving timestamp authenticity
    Timestamp   int64
}

// CheckpointPolicy defines checkpoint creation rules
type CheckpointPolicy struct {
    IntervalBlocks      uint64        // Create checkpoint every N blocks
    IntervalTime        time.Duration // Or every N minutes (whichever first)
    MinSignatures       int           // Minimum signatures required (2/3 of CA pool)
    SignatureTimeout    time.Duration // Time to collect signatures
    FinalityDepth       uint64        // Blocks after checkpoint are final
}

var DefaultCheckpointPolicy = CheckpointPolicy{
    IntervalBlocks:   1000,
    IntervalTime:     10 * time.Minute,
    MinSignatures:    67, // 2/3 of 100-node CA pool
    SignatureTimeout: 30 * time.Second,
    FinalityDepth:    6,
}

// CheckpointManager handles checkpoint creation and verification
type CheckpointManager struct {
    policy          CheckpointPolicy
    lastCheckpoint  *Checkpoint
    pendingCheckpoint *PendingCheckpoint
}

// CreateCheckpoint initiates checkpoint creation
func (cm *CheckpointManager) CreateCheckpoint(
    blockHeight uint64,
    stateRoot [32]byte,
    utxoSetHash [32]byte,
) (*PendingCheckpoint, error) {
    // Verify enough blocks since last checkpoint
    if cm.lastCheckpoint != nil {
        if blockHeight-cm.lastCheckpoint.BlockHeight < cm.policy.IntervalBlocks {
            return nil, ErrCheckpointTooEarly
        }
    }

    checkpoint := &Checkpoint{
        Height:         cm.lastCheckpoint.Height + 1,
        BlockHeight:    blockHeight,
        MerkleRoot:     stateRoot,
        UTXOSetHash:    utxoSetHash,
        Timestamp:      time.Now().Unix(),
        PrevCheckpoint: cm.lastCheckpoint.Hash(),
    }

    // Generate VRF proof for this checkpoint
    checkpoint.VRFProof = generateVRFProof(checkpoint.Hash())

    pending := &PendingCheckpoint{
        Checkpoint:     checkpoint,
        Signatures:     make([]CheckpointSig, 0),
        Deadline:       time.Now().Add(cm.policy.SignatureTimeout),
    }
    cm.pendingCheckpoint = pending

    return pending, nil
}

// FinalizeCheckpoint completes checkpoint after collecting signatures
func (cm *CheckpointManager) FinalizeCheckpoint(
    pending *PendingCheckpoint,
) (*Checkpoint, error) {
    // Verify minimum signatures collected
    if len(pending.Signatures) < cm.policy.MinSignatures {
        return nil, &ErrInsufficientCheckpointSignatures{
            Required: cm.policy.MinSignatures,
            Received: len(pending.Signatures),
        }
    }

    // Verify all signatures
    uniqueSigners := make(map[NodeID]bool)
    for _, sig := range pending.Signatures {
        if !verifyCheckpointSignature(pending.Checkpoint, sig) {
            return nil, &ErrInvalidCheckpointSignature{NodeID: sig.NodeID}
        }
        uniqueSigners[sig.NodeID] = true
    }

    if len(uniqueSigners) < cm.policy.MinSignatures {
        return nil, ErrDuplicateCheckpointSignatures
    }

    pending.Checkpoint.Signatures = pending.Signatures
    pending.Checkpoint.ParticipantCount = len(uniqueSigners)

    cm.lastCheckpoint = pending.Checkpoint
    cm.pendingCheckpoint = nil

    return pending.Checkpoint, nil
}

// VerifyCheckpointChain validates checkpoint chain integrity
func VerifyCheckpointChain(checkpoints []Checkpoint) error {
    for i := 1; i < len(checkpoints); i++ {
        prev := checkpoints[i-1]
        curr := checkpoints[i]

        // Verify chain linkage
        if curr.PrevCheckpoint != prev.Hash() {
            return &ErrCheckpointChainBroken{
                Height:   curr.Height,
                Expected: prev.Hash(),
                Actual:   curr.PrevCheckpoint,
            }
        }

        // Verify height monotonicity
        if curr.Height != prev.Height+1 {
            return &ErrCheckpointHeightGap{
                Expected: prev.Height + 1,
                Actual:   curr.Height,
            }
        }

        // Verify block height progress
        if curr.BlockHeight <= prev.BlockHeight {
            return ErrCheckpointBlockHeightRegression
        }
    }
    return nil
}
```

#### State Reconciliation Protocol

After canonical chain selection, the minority partition must reconcile its state:

```go
// ReconciliationManager handles partition merge reconciliation
type ReconciliationManager struct {
    canonical       *PartitionState
    minority        *PartitionState
    reconcileState  ReconciliationState
    conflictLog     []ConflictResolution
}

// ReconciliationState tracks reconciliation progress
type ReconciliationState uint8

const (
    ReconcileStart           ReconciliationState = iota
    ReconcileCheckpointSync  // Syncing to canonical checkpoint
    ReconcileTxReplay        // Replaying minority transactions
    ReconcileConflictResolve // Resolving conflicts
    ReconcileComplete        // Reconciliation finished
)

// ConflictResolution records how a conflict was resolved
type ConflictResolution struct {
    TxID            TxID
    Resolution      ResolutionType
    Reason          string
    CanonicalTxID   TxID     // If replaced by canonical TX
    AffectedUTXOs   []UTXOID
    Timestamp       time.Time
}

type ResolutionType uint8

const (
    ResolutionAccepted  ResolutionType = iota // TX accepted into canonical
    ResolutionRejected                         // TX conflicts, rejected
    ResolutionReplayed                         // TX replayed with new inputs
)

// ReconciliationProtocol merges partitions after canonical selection
func (rm *ReconciliationManager) ReconciliationProtocol(
    ctx context.Context,
    canonical, minority PartitionState,
) error {
    rm.canonical = &canonical
    rm.minority = &minority
    rm.reconcileState = ReconcileStart

    // Step 1: Find common ancestor checkpoint
    commonAncestor, err := rm.findCommonAncestor()
    if err != nil {
        return fmt.Errorf("finding common ancestor: %w", err)
    }

    // Step 2: Broadcast canonical checkpoint chain to minority nodes
    rm.reconcileState = ReconcileCheckpointSync
    if err := rm.syncCheckpoints(ctx, commonAncestor); err != nil {
        return fmt.Errorf("syncing checkpoints: %w", err)
    }

    // Step 3: Get transactions from minority since common ancestor
    rm.reconcileState = ReconcileTxReplay
    minorityTxs := rm.minority.TransactionsSince(commonAncestor.Height)
    canonicalTxs := rm.canonical.TransactionsSince(commonAncestor.Height)

    // Build canonical UTXO state
    canonicalUTXOs := rm.buildUTXOSet(canonicalTxs)

    // Step 4: Process minority transactions
    rm.reconcileState = ReconcileConflictResolve
    for _, tx := range minorityTxs {
        resolution := rm.resolveTransaction(tx, canonicalTxs, canonicalUTXOs)
        rm.conflictLog = append(rm.conflictLog, resolution)

        if resolution.Resolution == ResolutionAccepted {
            // Apply transaction to canonical state
            if err := rm.applyTransaction(tx); err != nil {
                return fmt.Errorf("applying transaction %x: %w", tx.ID, err)
            }
        } else if resolution.Resolution == ResolutionRejected {
            // Notify affected parties
            rm.notifyRejection(tx, resolution)
        }
    }

    // Step 5: Emit reconciliation checkpoint
    rm.reconcileState = ReconcileComplete
    return rm.emitReconciliationCheckpoint()
}

// findCommonAncestor finds the most recent checkpoint in both partitions
func (rm *ReconciliationManager) findCommonAncestor() (*Checkpoint, error) {
    canonicalCheckpoints := rm.canonical.GetCheckpoints()
    minorityCheckpoints := rm.minority.GetCheckpoints()

    // Walk backwards from minority tip to find match
    for i := len(minorityCheckpoints) - 1; i >= 0; i-- {
        minorityCP := minorityCheckpoints[i]
        for _, canonicalCP := range canonicalCheckpoints {
            if canonicalCP.Hash() == minorityCP.Hash() {
                return &minorityCP, nil
            }
        }
    }

    return nil, ErrNoCommonAncestor
}

// resolveTransaction determines if minority TX can be accepted
func (rm *ReconciliationManager) resolveTransaction(
    tx Transaction,
    canonicalTxs []Transaction,
    canonicalUTXOs map[UTXOID]UTXOState,
) ConflictResolution {
    resolution := ConflictResolution{
        TxID:      tx.ID,
        Timestamp: time.Now(),
    }

    // Check if already in canonical chain
    for _, cTx := range canonicalTxs {
        if cTx.ID == tx.ID {
            resolution.Resolution = ResolutionAccepted
            resolution.Reason = "already_in_canonical"
            return resolution
        }
    }

    // Check for UTXO conflicts
    for _, input := range tx.Inputs {
        utxoState, exists := canonicalUTXOs[input.UTXOID]
        if !exists {
            resolution.Resolution = ResolutionRejected
            resolution.Reason = "utxo_not_found"
            resolution.AffectedUTXOs = append(resolution.AffectedUTXOs, input.UTXOID)
            return resolution
        }
        if utxoState.Spent {
            // Find which canonical TX spent this UTXO
            resolution.Resolution = ResolutionRejected
            resolution.Reason = "utxo_already_spent"
            resolution.CanonicalTxID = utxoState.SpentBy
            resolution.AffectedUTXOs = append(resolution.AffectedUTXOs, input.UTXOID)
            return resolution
        }
    }

    // No conflicts - accept transaction
    resolution.Resolution = ResolutionAccepted
    resolution.Reason = "no_conflict"
    return resolution
}

// emitReconciliationCheckpoint creates checkpoint after reconciliation
func (rm *ReconciliationManager) emitReconciliationCheckpoint() error {
    stateRoot := rm.computeCurrentStateRoot()
    utxoHash := rm.computeUTXOSetHash()

    checkpoint := &Checkpoint{
        Height:         rm.canonical.CheckpointHeight + 1,
        BlockHeight:    rm.canonical.TipHeight + 1,
        MerkleRoot:     stateRoot,
        UTXOSetHash:    utxoHash,
        Timestamp:      time.Now().Unix(),
        PrevCheckpoint: rm.canonical.LastCheckpointHash,
    }

    // Mark as reconciliation checkpoint
    checkpoint.VRFProof = append([]byte("reconcile:"), generateVRFProof(checkpoint.Hash())...)

    return broadcastCheckpoint(checkpoint)
}
```

#### Partition Recovery Guarantees

| Guarantee | Mechanism | Bound |
|-----------|-----------|-------|
| **Finality** | Checkpoint signatures | Transactions before checkpoint are irreversible |
| **Consistency** | Canonical chain selection | All nodes converge to same state |
| **Availability** | Minority TX replay | Non-conflicting TXs preserved |
| **Accountability** | Conflict log | All rejections documented |
| **Determinism** | VRF tiebreaker | Same inputs produce same canonical selection |

#### Recovery Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Partition Detection | 10-30s | Reachability drops below 50% |
| Partition Mode | Variable | Partitions operate independently |
| Healing Detection | 10-30s | Reachability exceeds 80% |
| Checkpoint Sync | 5-60s | Exchange checkpoint chains |
| TX Replay | 1-300s | Process minority transactions |
| Reconciliation Checkpoint | 30-60s | Collect signatures |
| **Total** | **~1-7 minutes** | After partition heals |

#### Partition Detection Thresholds

| Metric | Healthy | Degraded | Partition | Action |
|--------|---------|----------|-----------|--------|
| Peer Reachability | >80% | 50-80% | <50% | Enter partition mode |
| Coordinator Reachability | 5/5 | 3-4/5 | <3/5 | Suspend consensus |
| DHT Response Time | <500ms | 500ms-2s | >2s | Reduce operations |
| Cross-Shard Latency | <1s | 1-5s | >5s | Fallback to local |

#### Edge Cases and Complex Partitions

```go
// pkg/consensus/partition_edge_cases.go

// ThreeWayPartitionResolution handles 3+ way network splits
func ThreeWayPartitionResolution(partitions []PartitionState) (*PartitionState, error) {
    if len(partitions) < 2 {
        return nil, ErrNotEnoughPartitions
    }

    // Sort by stake weight (descending)
    sort.Slice(partitions, func(i, j int) bool {
        return partitions[i].StakeWeight > partitions[j].StakeWeight
    })

    // Canonical is largest partition
    canonical := &partitions[0]

    // Merge remaining partitions sequentially
    for i := 1; i < len(partitions); i++ {
        minority := &partitions[i]
        rm := &ReconciliationManager{}
        if err := rm.ReconciliationProtocol(context.Background(), *canonical, *minority); err != nil {
            return nil, fmt.Errorf("reconciling partition %d: %w", i, err)
        }
    }

    return canonical, nil
}

// CascadingPartitionHandler prevents reconciliation interruption
type CascadingPartitionHandler struct {
    inProgress      *ReconciliationManager
    queuedEvents    []PartitionEvent
    maxQueueDepth   int // Maximum queued events (default: 10)
}

// HandlePartitionEvent manages partition events during reconciliation
func (h *CascadingPartitionHandler) HandlePartitionEvent(event PartitionEvent) error {
    // If reconciliation in progress, queue the new event
    if h.inProgress != nil && h.inProgress.reconcileState != ReconcileComplete {
        if len(h.queuedEvents) >= h.maxQueueDepth {
            return ErrPartitionQueueFull
        }
        h.queuedEvents = append(h.queuedEvents, event)
        return nil // Process after current reconciliation
    }

    // Handle event immediately
    return h.processPartitionEvent(event)
}
```

#### Transaction Handling During Partition

| Transaction State | Majority Partition | Minority Partition |
|-------------------|--------------------|--------------------|
| Pending (unconfirmed) | Continue processing | **Suspend** |
| In-flight (partial confirmation) | Complete if possible | **Rollback** |
| Confirmed pre-partition | Retain | Subject to conflict resolution |
| New during partition | Process normally | **Reject** |

#### Partition Timeout Escalation

```go
// Long-running partitions require escalation
const (
    PartitionWarningThreshold  = 1 * time.Hour   // Alert operators
    PartitionCriticalThreshold = 24 * time.Hour  // Escalate to emergency
    PartitionManualThreshold   = 48 * time.Hour  // Require manual resolution
)

// PartitionEscalation handles long-running partition scenarios
func (pd *PartitionDetector) CheckPartitionEscalation() *EscalationEvent {
    if pd.partitionStartTime.IsZero() {
        return nil
    }

    duration := time.Since(pd.partitionStartTime)

    switch {
    case duration > PartitionManualThreshold:
        return &EscalationEvent{
            Level:    EscalationManual,
            Duration: duration,
            Message:  "Partition exceeds 48h - manual resolution required",
        }
    case duration > PartitionCriticalThreshold:
        return &EscalationEvent{
            Level:    EscalationCritical,
            Duration: duration,
            Message:  "Partition exceeds 24h - emergency procedures activated",
        }
    case duration > PartitionWarningThreshold:
        return &EscalationEvent{
            Level:    EscalationWarning,
            Duration: duration,
            Message:  "Partition exceeds 1h - operator attention required",
        }
    }

    return nil
}
```

---

### C2: Cross-Shard Coordinator Rotation Attack

When coordinators rotate during cross-shard operations, a malicious incoming coordinator could replay transactions in a different order than the outgoing coordinator committed.

#### Problem Statement

Attack scenario:
1. Coordinator A receives TX-1 and TX-2 in order
2. Coordinator A commits TX-1 first, starts TX-2
3. Rotation occurs, Coordinator B takes over
4. Coordinator B replays TX-2 before TX-1 was finalized
5. Cross-shard state becomes inconsistent

#### Rotation Epoch Protocol

Every batch signature includes the rotation epoch to bind transactions to specific coordinator tenures:

```go
// RotationEpoch uniquely identifies a coordinator tenure
type RotationEpoch struct {
    EpochNumber      uint64    // Monotonically increasing
    CoordinatorID    NodeID    // Coordinator for this epoch
    StartTime        int64     // Epoch start timestamp
    StartHeight      uint64    // First batch height in epoch
    PrevEpochHash    [32]byte  // Hash of previous epoch final state
    CommitteeSession [32]byte  // Committee session this epoch belongs to
}

// BatchWithEpoch includes rotation epoch to prevent replay attacks
type BatchWithEpoch struct {
    Epoch            uint64             // Current rotation epoch number
    SequenceNumber   uint64             // Batch sequence within epoch
    Transactions     []Transaction      // Ordered transaction list
    EpochProof       []byte             // Proof coordinator is valid for epoch
    CoordinatorID    NodeID             // Coordinator ID
    CoordinatorSig   []byte             // Signs: Epoch || Sequence || TxMerkleRoot
    Timestamp        int64              // Batch creation time
}

// EpochValidator ensures batches are from current epoch
type EpochValidator struct {
    currentEpoch      uint64
    epochHistory      map[uint64]*RotationEpoch
    coordinatorEpochs map[NodeID][]uint64 // Which epochs each coordinator served
}

// ValidateBatchEpoch rejects batches from stale or future epochs
func (ev *EpochValidator) ValidateBatchEpoch(batch *BatchWithEpoch) error {
    // Reject batches from previous epochs (prevents replay)
    if batch.Epoch < ev.currentEpoch {
        return &ErrStaleEpoch{
            BatchEpoch:   batch.Epoch,
            CurrentEpoch: ev.currentEpoch,
        }
    }

    // Reject batches from future epochs (prevents pre-computation)
    if batch.Epoch > ev.currentEpoch+1 {
        return &ErrFutureEpoch{
            BatchEpoch:   batch.Epoch,
            CurrentEpoch: ev.currentEpoch,
        }
    }

    // Verify coordinator was valid for claimed epoch
    if !ev.wasCoordinatorForEpoch(batch.CoordinatorID, batch.Epoch) {
        return &ErrInvalidCoordinatorForEpoch{
            CoordinatorID: batch.CoordinatorID,
            Epoch:         batch.Epoch,
        }
    }

    // Verify signature covers epoch
    sigData := ev.buildSignatureData(batch)
    if !verifySignature(batch.CoordinatorID, sigData, batch.CoordinatorSig) {
        return ErrInvalidBatchSignature
    }

    return nil
}

// buildSignatureData creates canonical data for signature verification
func (ev *EpochValidator) buildSignatureData(batch *BatchWithEpoch) []byte {
    h := sha256.New()
    binary.Write(h, binary.BigEndian, batch.Epoch)
    binary.Write(h, binary.BigEndian, batch.SequenceNumber)
    h.Write(computeTxMerkleRoot(batch.Transactions))
    binary.Write(h, binary.BigEndian, batch.Timestamp)
    return h.Sum(nil)
}

// wasCoordinatorForEpoch checks historical coordinator assignments
func (ev *EpochValidator) wasCoordinatorForEpoch(nodeID NodeID, epoch uint64) bool {
    epochs, exists := ev.coordinatorEpochs[nodeID]
    if !exists {
        return false
    }
    for _, e := range epochs {
        if e == epoch {
            return true
        }
    }
    return false
}
```

#### Coordinator Handoff Protocol

Clean handoff between coordinators ensures no transactions are lost or replayed:

```go
// CoordinatorHandoff manages the transition between coordinators
type CoordinatorHandoff struct {
    oldCoordinator    NodeID
    newCoordinator    NodeID
    handoffEpoch      uint64
    pendingBatches    []*BatchWithEpoch
    state             HandoffState
}

type HandoffState uint8

const (
    HandoffIdle        HandoffState = iota
    HandoffInitiated   // Old coordinator received rotation notice
    HandoffDraining    // Old coordinator finishing pending work
    HandoffTransfer    // State transfer to new coordinator
    HandoffConfirmed   // New coordinator acknowledged
    HandoffComplete    // Network using new coordinator
)

// EpochRotationCeremony performs safe coordinator handoff
func EpochRotationCeremony(
    ctx context.Context,
    oldCoord, newCoord NodeID,
    currentEpoch uint64,
) error {
    handoff := &CoordinatorHandoff{
        oldCoordinator: oldCoord,
        newCoordinator: newCoord,
        handoffEpoch:   currentEpoch,
        state:          HandoffInitiated,
    }

    // Phase 1: Notify old coordinator of pending rotation
    if err := notifyRotation(oldCoord, currentEpoch); err != nil {
        return fmt.Errorf("notify rotation: %w", err)
    }

    // Phase 2: Old coordinator commits final batch for current epoch
    handoff.state = HandoffDraining
    finalBatch, err := requestFinalBatch(ctx, oldCoord, currentEpoch)
    if err != nil {
        // Old coordinator unresponsive - emergency handoff
        return emergencyHandoff(ctx, handoff)
    }

    // Mark batch as epoch-final
    finalBatch.EpochProof = append([]byte("final:"), finalBatch.EpochProof...)

    // Phase 3: Wait for 2/3 network confirmation of final batch
    confirmed, err := waitForConfirmation(ctx, finalBatch, 2.0/3.0, 30*time.Second)
    if err != nil || !confirmed {
        return fmt.Errorf("final batch confirmation failed: %w", err)
    }

    // Phase 4: Transfer pending state to new coordinator
    handoff.state = HandoffTransfer
    pendingState := &PendingCoordinatorState{
        LastBatchSequence:  finalBatch.SequenceNumber,
        LastBatchHash:      finalBatch.Hash(),
        PendingTransactions: getPendingTransactions(oldCoord),
        UTXOLocks:          getActiveUTXOLocks(oldCoord),
        CrossShardState:    getCrossShardState(oldCoord),
    }

    if err := transferState(ctx, newCoord, pendingState); err != nil {
        return fmt.Errorf("state transfer: %w", err)
    }

    // Phase 5: New coordinator acknowledges and starts new epoch
    handoff.state = HandoffConfirmed
    newEpoch := currentEpoch + 1
    epochAnnouncement := &EpochAnnouncement{
        EpochNumber:      newEpoch,
        CoordinatorID:    newCoord,
        PrevEpochHash:    finalBatch.Hash(),
        StartHeight:      finalBatch.SequenceNumber + 1,
        Timestamp:        time.Now().Unix(),
    }

    if err := broadcastEpochStart(epochAnnouncement); err != nil {
        return fmt.Errorf("epoch announcement: %w", err)
    }

    // Phase 6: All nodes reject batches from old epoch
    handoff.state = HandoffComplete
    return nil
}

// PendingCoordinatorState captures state for handoff
type PendingCoordinatorState struct {
    LastBatchSequence   uint64
    LastBatchHash       [32]byte
    PendingTransactions []Transaction
    UTXOLocks           map[UTXOID]LockInfo
    CrossShardState     map[TxID]*CrossShardTxState
}

// emergencyHandoff handles unresponsive coordinator
func emergencyHandoff(ctx context.Context, handoff *CoordinatorHandoff) error {
    // Use last known good state from network consensus
    lastKnownState, err := queryNetworkForLastKnownState(handoff.oldCoordinator)
    if err != nil {
        return fmt.Errorf("query network state: %w", err)
    }

    // New coordinator starts from last confirmed batch
    return startEmergencyEpoch(ctx, handoff.newCoordinator, lastKnownState)
}
```

#### Cross-Shard Transaction Epoch Binding

Cross-shard transactions must complete within a single epoch or be explicitly continued:

```go
// CrossShardTxState tracks cross-shard transaction across epochs
type CrossShardTxState struct {
    TxID            TxID
    StartEpoch      uint64
    CurrentPhase    ThreePhaseState
    SourceShard     uint16
    DestShards      []uint16
    UTXOLocks       []UTXOID
    VotesCan        map[uint16]bool // Shard votes for CanCommit
    VotesPre        map[uint16]bool // Shard votes for PreCommit
    EpochContinued  bool            // If TX spans epochs
    ContinuationSig []byte          // New coordinator signature for continuation
}

// ValidateCrossShardInEpoch ensures cross-shard TX epoch consistency
func ValidateCrossShardInEpoch(
    msg *ThreePhaseMessage,
    txState *CrossShardTxState,
    currentEpoch uint64,
) error {
    // Transaction must have started in current or previous epoch
    if txState.StartEpoch < currentEpoch-1 {
        return &ErrCrossShardTxExpired{
            TxID:         txState.TxID,
            StartEpoch:   txState.StartEpoch,
            CurrentEpoch: currentEpoch,
        }
    }

    // If started in previous epoch, must have continuation signature
    if txState.StartEpoch < currentEpoch {
        if !txState.EpochContinued {
            return &ErrCrossShardMissingContinuation{
                TxID:       txState.TxID,
                StartEpoch: txState.StartEpoch,
            }
        }

        // Verify new coordinator signed continuation
        if !verifyContinuationSignature(txState) {
            return ErrInvalidContinuationSignature
        }
    }

    return nil
}

// ContinueCrossShardTx allows new coordinator to continue pending TX
func (c *Coordinator) ContinueCrossShardTx(
    txState *CrossShardTxState,
    newEpoch uint64,
) error {
    // Verify TX was in progress during handoff
    if txState.CurrentPhase == PhaseComplete || txState.CurrentPhase == PhaseAborted {
        return ErrCrossShardAlreadyComplete
    }

    // Sign continuation commitment
    continuationData := struct {
        TxID       TxID
        StartEpoch uint64
        NewEpoch   uint64
        Phase      ThreePhaseState
        Locks      []UTXOID
    }{
        TxID:       txState.TxID,
        StartEpoch: txState.StartEpoch,
        NewEpoch:   newEpoch,
        Phase:      txState.CurrentPhase,
        Locks:      txState.UTXOLocks,
    }

    txState.EpochContinued = true
    txState.ContinuationSig = c.signWithTPM(hashStruct(continuationData))

    // Broadcast continuation to shards
    return c.broadcastContinuation(txState)
}
```

#### Epoch Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **No Replay** | Batches rejected if epoch < current | EpochValidator |
| **No Pre-computation** | Batches rejected if epoch > current+1 | EpochValidator |
| **Coordinator Binding** | Only valid coordinator for epoch | coordinatorEpochs map |
| **Atomic Handoff** | State transfer before epoch change | EpochRotationCeremony |
| **Cross-shard Safety** | TXs must complete or continue | ContinueCrossShardTx |

---

### C3: Sequence Number Gap Attack

A malicious coordinator could skip sequence numbers to invalidate later batches or create ambiguity about transaction ordering.

#### Problem Statement

Attack scenario:
1. Coordinator processes batch seq=100, then seq=102 (skipping 101)
2. Later coordinator or nodes wonder if batch 101 exists
3. Coordinator could produce batch 101 later with different transactions
4. Creates ordering ambiguity for cross-shard transactions

#### Contiguous Sequence Enforcement

```go
// SequenceValidator enforces contiguous sequence numbers with gap detection
type SequenceValidator struct {
    lastSequence     map[NodeID]uint64       // Last seen sequence per coordinator
    epochSequences   map[uint64]uint64       // Last sequence per epoch
    gapReports       map[NodeID][]GapReport  // Gap violations per node
    mu               sync.RWMutex
}

// GapReport records a sequence gap violation
type GapReport struct {
    CoordinatorID   NodeID
    Epoch           uint64
    ExpectedSeq     uint64
    ReceivedSeq     uint64
    BatchHash       [32]byte
    Timestamp       time.Time
    Witnesses       []NodeID  // Nodes that observed the gap
}

// ValidateSequence ensures batch sequence is exactly lastSequence + 1
func (sv *SequenceValidator) ValidateSequence(batch *BatchWithEpoch) error {
    sv.mu.Lock()
    defer sv.mu.Unlock()

    // Get expected sequence for this coordinator in this epoch
    key := sv.coordinatorEpochKey(batch.CoordinatorID, batch.Epoch)
    lastSeq, exists := sv.lastSequence[batch.CoordinatorID]

    if !exists {
        // First batch from this coordinator - must be sequence 0 or continue from handoff
        expectedFirst := sv.getExpectedFirstSequence(batch.CoordinatorID, batch.Epoch)
        if batch.SequenceNumber != expectedFirst {
            return sv.reportGap(batch, expectedFirst)
        }
    } else {
        // Subsequent batch - must be exactly lastSeq + 1
        expected := lastSeq + 1

        if batch.SequenceNumber < expected {
            return &ErrDuplicateSequence{
                CoordinatorID: batch.CoordinatorID,
                Sequence:      batch.SequenceNumber,
                LastSeen:      lastSeq,
            }
        }

        if batch.SequenceNumber > expected {
            return sv.reportGap(batch, expected)
        }
    }

    // Valid sequence - update state
    sv.lastSequence[batch.CoordinatorID] = batch.SequenceNumber
    sv.epochSequences[batch.Epoch] = batch.SequenceNumber
    return nil
}

// reportGap creates a gap report and initiates penalty process
func (sv *SequenceValidator) reportGap(batch *BatchWithEpoch, expected uint64) error {
    report := GapReport{
        CoordinatorID: batch.CoordinatorID,
        Epoch:         batch.Epoch,
        ExpectedSeq:   expected,
        ReceivedSeq:   batch.SequenceNumber,
        BatchHash:     batch.Hash(),
        Timestamp:     time.Now(),
    }

    sv.gapReports[batch.CoordinatorID] = append(
        sv.gapReports[batch.CoordinatorID],
        report,
    )

    // Initiate gap penalty protocol
    go sv.initiateGapPenalty(report)

    return &ErrSequenceGap{
        CoordinatorID: batch.CoordinatorID,
        Expected:      expected,
        Actual:        batch.SequenceNumber,
        Gap:           batch.SequenceNumber - expected,
    }
}

// initiateGapPenalty handles penalty for sequence gap
func (sv *SequenceValidator) initiateGapPenalty(report GapReport) {
    // Collect witnesses who observed the gap
    witnesses := sv.collectGapWitnesses(report)
    report.Witnesses = witnesses

    // If sufficient witnesses, apply penalty
    if len(witnesses) >= 3 { // Minimum 3 independent observers
        penalty := &SequenceGapPenalty{
            Report:          report,
            WitnessCount:    len(witnesses),
            PenaltyType:     PenaltyReputationSlash,
            ReputationSlash: 0.05, // 5% reputation slash
        }

        applyCoordinatorPenalty(report.CoordinatorID, penalty)
    }
}
```

#### Gap Detection Protocol

Network nodes collectively detect and report gaps:

```go
// GapDetector monitors for sequence gaps across the network
type GapDetector struct {
    observedSequences map[NodeID]map[uint64]uint64 // coordinator -> epoch -> last seq
    pendingGaps       map[string]*PendingGap       // gap key -> pending investigation
    gapThreshold      time.Duration                // Time to wait for missing batch
}

// PendingGap tracks a potential gap under investigation
type PendingGap struct {
    CoordinatorID   NodeID
    Epoch           uint64
    MissingSeq      uint64
    DetectedAt      time.Time
    Reporters       []NodeID
    Resolution      GapResolution
}

type GapResolution uint8

const (
    GapPending      GapResolution = iota
    GapFilled       // Missing batch arrived
    GapConfirmed    // Gap confirmed, penalty applied
    GapFalsePositive // Reporter was wrong
)

// DetectGap checks for sequence gaps and initiates investigation
func (gd *GapDetector) DetectGap(
    batch *BatchWithEpoch,
    reporterID NodeID,
) (*PendingGap, error) {
    gd.mu.Lock()
    defer gd.mu.Unlock()

    // Get coordinator's sequence history
    coordSeqs, exists := gd.observedSequences[batch.CoordinatorID]
    if !exists {
        coordSeqs = make(map[uint64]uint64)
        gd.observedSequences[batch.CoordinatorID] = coordSeqs
    }

    lastSeq, hasHistory := coordSeqs[batch.Epoch]
    if !hasHistory {
        // First observation for this epoch
        coordSeqs[batch.Epoch] = batch.SequenceNumber
        return nil, nil
    }

    expected := lastSeq + 1
    if batch.SequenceNumber <= expected {
        // No gap (or duplicate)
        if batch.SequenceNumber == expected {
            coordSeqs[batch.Epoch] = batch.SequenceNumber
        }
        return nil, nil
    }

    // Gap detected - create or update pending investigation
    gapKey := fmt.Sprintf("%x:%d:%d", batch.CoordinatorID, batch.Epoch, expected)
    pending, exists := gd.pendingGaps[gapKey]
    if !exists {
        pending = &PendingGap{
            CoordinatorID: batch.CoordinatorID,
            Epoch:         batch.Epoch,
            MissingSeq:    expected,
            DetectedAt:    time.Now(),
            Reporters:     []NodeID{reporterID},
            Resolution:    GapPending,
        }
        gd.pendingGaps[gapKey] = pending

        // Start timer for gap resolution
        go gd.waitForGapResolution(gapKey)
    } else {
        // Add reporter if not already present
        if !containsNodeID(pending.Reporters, reporterID) {
            pending.Reporters = append(pending.Reporters, reporterID)
        }
    }

    return pending, nil
}

// waitForGapResolution waits for missing batch or confirms gap
func (gd *GapDetector) waitForGapResolution(gapKey string) {
    time.Sleep(gd.gapThreshold)

    gd.mu.Lock()
    defer gd.mu.Unlock()

    pending, exists := gd.pendingGaps[gapKey]
    if !exists || pending.Resolution != GapPending {
        return // Already resolved
    }

    // Check if batch arrived
    if gd.batchArrived(pending) {
        pending.Resolution = GapFilled
        return
    }

    // Gap confirmed - require minimum reporters
    if len(pending.Reporters) >= 3 {
        pending.Resolution = GapConfirmed
        gd.submitGapProof(pending)
    }
}

// submitGapProof creates cryptographic proof of gap for penalty
func (gd *GapDetector) submitGapProof(pending *PendingGap) {
    proof := &GapProof{
        CoordinatorID:    pending.CoordinatorID,
        Epoch:            pending.Epoch,
        MissingSequence:  pending.MissingSeq,
        DetectedAt:       pending.DetectedAt,
        ReporterSigs:     make([]ReporterSignature, len(pending.Reporters)),
    }

    // Collect signatures from reporters
    for i, reporter := range pending.Reporters {
        proof.ReporterSigs[i] = requestGapSignature(reporter, pending)
    }

    // Submit to reputation system
    submitReputationPenalty(pending.CoordinatorID, proof)
}
```

#### Sequence Number Recovery

If gaps are detected, recovery protocol fills missing sequences:

```go
// SequenceRecovery handles filling sequence gaps
type SequenceRecovery struct {
    validator *SequenceValidator
    detector  *GapDetector
}

// RecoverMissingSequence attempts to recover a missing batch
func (sr *SequenceRecovery) RecoverMissingSequence(
    ctx context.Context,
    coordinatorID NodeID,
    epoch uint64,
    missingSeq uint64,
) (*BatchWithEpoch, error) {
    // Step 1: Request from coordinator
    batch, err := requestBatchFromCoordinator(ctx, coordinatorID, epoch, missingSeq)
    if err == nil && batch != nil {
        return batch, nil
    }

    // Step 2: Request from committee members
    committee := getCommitteeForEpoch(epoch)
    for _, member := range committee.Coordinators {
        if member.NodeID == coordinatorID {
            continue
        }
        batch, err := requestBatchFromPeer(ctx, member.NodeID, epoch, missingSeq)
        if err == nil && batch != nil {
            return batch, nil
        }
    }

    // Step 3: Query network archive nodes
    batch, err = queryArchiveNodes(ctx, coordinatorID, epoch, missingSeq)
    if err == nil && batch != nil {
        return batch, nil
    }

    // Step 4: Gap is confirmed missing
    return nil, &ErrSequenceUnrecoverable{
        CoordinatorID: coordinatorID,
        Epoch:         epoch,
        Sequence:      missingSeq,
    }
}

// HandleConfirmedGap processes an unrecoverable sequence gap
func (sr *SequenceRecovery) HandleConfirmedGap(
    gap *PendingGap,
) error {
    // Mark all batches after gap as potentially invalid
    affectedBatches := sr.getAffectedBatches(gap)

    // Require re-validation with new sequence
    for _, batch := range affectedBatches {
        if err := sr.revalidateBatch(batch); err != nil {
            // Batch depends on missing sequence - reject
            rejectBatch(batch, "depends_on_missing_sequence")
        }
    }

    // Apply coordinator penalty
    return applySequenceGapPenalty(gap.CoordinatorID, gap)
}
```

#### Sequence Gap Penalties

| Violation | Penalty | Threshold |
|-----------|---------|-----------|
| Single gap (1 sequence) | 2% reputation slash | 3+ witnesses |
| Multiple gaps (2-5) | 5% reputation slash | 3+ witnesses |
| Large gap (>5) | 10% reputation slash + temp ban | 3+ witnesses |
| Repeated gaps (3+ in 24h) | 20% slash + committee removal | Pattern detection |
| Intentional gap (with evidence) | 50% slash + permanent ban | Cryptographic proof |

---

### C9: 3PC Coordinator Slashing

Three-phase commit coordinators can stall operations without penalty, causing locks to persist indefinitely and degrading network throughput.

#### Problem Statement

Attack scenarios:
1. Coordinator sends CanCommit, shards lock UTXOs, coordinator never sends PreCommit
2. Coordinator sends PreCommit, then disappears before DoCommit
3. Coordinator intentionally delays to grief specific transactions

Without slashing, coordinators have no economic incentive to complete transactions promptly.

#### Timeout-Based Slashing

```go
// ThreePhaseTimeouts defines timeout durations for each phase
type ThreePhaseTimeouts struct {
    CanCommitTimeout  time.Duration // Time to receive CanCommit responses
    PreCommitTimeout  time.Duration // Time from CanCommit to PreCommit
    DoCommitTimeout   time.Duration // Time from PreCommit to DoCommit
    GracePeriod       time.Duration // Grace period before slashing
}

var DefaultThreePhaseTimeouts = ThreePhaseTimeouts{
    CanCommitTimeout: 5 * time.Second,
    PreCommitTimeout: 10 * time.Second,
    DoCommitTimeout:  15 * time.Second,
    GracePeriod:      5 * time.Second,
}

// CoordinatorSlashingState tracks coordinator behavior for slashing
type CoordinatorSlashingState struct {
    ActiveTransactions map[TxID]*TrackedTransaction
    SlashingEvents     []SlashingEvent
    TotalSlashed       float64 // Cumulative reputation slashed
}

// TrackedTransaction monitors a transaction for timeout
type TrackedTransaction struct {
    TxID             TxID
    CoordinatorID    NodeID
    Phase            ThreePhaseState
    PhaseStartTime   time.Time
    LockedUTXOs      []UTXOID
    LockedShards     []uint16
    TimeoutDeadline  time.Time
    SlashingApplied  bool
}

// SlashingEvent records a slashing penalty
type SlashingEvent struct {
    TxID            TxID
    CoordinatorID   NodeID
    Phase           ThreePhaseState
    TimeoutDuration time.Duration
    SlashAmount     float64
    Timestamp       time.Time
    Witnesses       []NodeID
    Evidence        *TimeoutEvidence
}

// TimeoutEvidence provides cryptographic proof of timeout
type TimeoutEvidence struct {
    PhaseMessage     []byte    // Original phase message
    MessageTimestamp int64     // When message was sent
    TimeoutTimestamp int64     // When timeout occurred
    WitnessSigs      [][]byte  // Signatures from witnessing nodes
}

// ThreePhaseSlashingMonitor monitors for coordinator timeouts
type ThreePhaseSlashingMonitor struct {
    timeouts        ThreePhaseTimeouts
    state           map[NodeID]*CoordinatorSlashingState
    slashingRates   SlashingRates
}

// SlashingRates defines reputation penalties per phase
type SlashingRates struct {
    CanCommitStall  float64 // Penalty for stalling after CanCommit
    PreCommitStall  float64 // Penalty for stalling after PreCommit
    DoCommitStall   float64 // Penalty for stalling after DoCommit
    RepeatedOffense float64 // Multiplier for repeated offenses
    MaxSlashPerTx   float64 // Maximum slash per transaction
}

var DefaultSlashingRates = SlashingRates{
    CanCommitStall:  0.01, // 1% reputation
    PreCommitStall:  0.02, // 2% reputation (more serious)
    DoCommitStall:   0.03, // 3% reputation (most serious)
    RepeatedOffense: 1.5,  // 50% increase per repeat
    MaxSlashPerTx:   0.10, // 10% max per transaction
}

// StartTracking begins monitoring a transaction for timeouts
func (tsm *ThreePhaseSlashingMonitor) StartTracking(
    txID TxID,
    coordinatorID NodeID,
    phase ThreePhaseState,
) {
    state := tsm.getOrCreateState(coordinatorID)

    tracked := &TrackedTransaction{
        TxID:            txID,
        CoordinatorID:   coordinatorID,
        Phase:           phase,
        PhaseStartTime:  time.Now(),
        TimeoutDeadline: time.Now().Add(tsm.getTimeoutForPhase(phase)),
    }

    state.ActiveTransactions[txID] = tracked

    // Start timeout monitor
    go tsm.monitorTimeout(tracked)
}

// monitorTimeout watches for phase timeout
func (tsm *ThreePhaseSlashingMonitor) monitorTimeout(tracked *TrackedTransaction) {
    timer := time.NewTimer(time.Until(tracked.TimeoutDeadline))
    defer timer.Stop()

    select {
    case <-timer.C:
        // Timeout occurred - initiate slashing
        tsm.initiateSlashing(tracked)
    }
}

// initiateSlashing handles timeout slashing
func (tsm *ThreePhaseSlashingMonitor) initiateSlashing(tracked *TrackedTransaction) {
    state := tsm.state[tracked.CoordinatorID]
    if tracked.SlashingApplied {
        return // Already slashed
    }

    // Add grace period
    graceDeadline := tracked.TimeoutDeadline.Add(tsm.timeouts.GracePeriod)
    if time.Now().Before(graceDeadline) {
        // Wait for grace period
        time.Sleep(time.Until(graceDeadline))

        // Check if phase completed during grace
        if tracked.Phase != tsm.getCurrentPhase(tracked.TxID) {
            return // Phase completed, no slash
        }
    }

    // Calculate slash amount
    baseSlash := tsm.slashingRates.getBaseSlash(tracked.Phase)
    repeatMultiplier := tsm.calculateRepeatMultiplier(tracked.CoordinatorID)
    slashAmount := min(baseSlash*repeatMultiplier, tsm.slashingRates.MaxSlashPerTx)

    // Collect evidence
    evidence := tsm.collectTimeoutEvidence(tracked)

    // Create slashing event
    event := SlashingEvent{
        TxID:            tracked.TxID,
        CoordinatorID:   tracked.CoordinatorID,
        Phase:           tracked.Phase,
        TimeoutDuration: time.Since(tracked.PhaseStartTime),
        SlashAmount:     slashAmount,
        Timestamp:       time.Now(),
        Evidence:        evidence,
    }

    // Collect witness signatures
    event.Witnesses = tsm.collectWitnesses(tracked)

    // Apply slashing
    if len(event.Witnesses) >= 3 {
        applyReputationSlash(tracked.CoordinatorID, slashAmount)
        state.SlashingEvents = append(state.SlashingEvents, event)
        state.TotalSlashed += slashAmount
        tracked.SlashingApplied = true
    }

    // Check if coordinator should be removed
    if state.TotalSlashed >= 0.20 { // 20% cumulative
        initiateCoordinatorRemoval(tracked.CoordinatorID)
    }
}
```

#### Coordinator Replacement via Consensus

When a coordinator is slashed beyond threshold, consensus replaces them:

```go
// CoordinatorReplacement handles replacing failed/malicious coordinators
type CoordinatorReplacement struct {
    committee         *Committee
    replacementPolicy ReplacementPolicy
}

// ReplacementPolicy defines when coordinators are replaced
type ReplacementPolicy struct {
    SlashThreshold     float64       // Cumulative slash to trigger replacement
    TimeoutThreshold   int           // Number of timeouts to trigger
    MinWitnesses       int           // Minimum witnesses for replacement
    ReplacementTimeout time.Duration // Time to complete replacement
}

var DefaultReplacementPolicy = ReplacementPolicy{
    SlashThreshold:     0.15, // 15% cumulative slash
    TimeoutThreshold:   3,    // 3 timeouts in 1 hour
    MinWitnesses:       3,
    ReplacementTimeout: 30 * time.Second,
}

// InitiateReplacement starts the coordinator replacement process
func (cr *CoordinatorReplacement) InitiateReplacement(
    ctx context.Context,
    failedCoord NodeID,
    reason ReplacementReason,
) error {
    // Step 1: Verify replacement criteria met
    if !cr.verifyReplacementCriteria(failedCoord, reason) {
        return ErrReplacementCriteriaNotMet
    }

    // Step 2: Create replacement proposal
    proposal := &ReplacementProposal{
        FailedCoordinator: failedCoord,
        Reason:            reason,
        ProposedAt:        time.Now(),
        ProposerID:        cr.committee.Coordinators[0].NodeID,
    }

    // Step 3: Select replacement using VRF
    replacement, err := cr.selectReplacement(failedCoord)
    if err != nil {
        return fmt.Errorf("selecting replacement: %w", err)
    }
    proposal.ReplacementCoordinator = replacement.ID
    proposal.ReplacementVRFProof = replacement.LastVRFProof

    // Step 4: Committee votes on replacement
    votes, err := cr.collectReplacementVotes(ctx, proposal)
    if err != nil {
        return fmt.Errorf("collecting votes: %w", err)
    }

    // Step 5: Verify threshold met (3/5)
    if len(votes) < cr.committee.Threshold {
        return &ErrInsufficientReplacementVotes{
            Required: cr.committee.Threshold,
            Received: len(votes),
        }
    }

    // Step 6: Execute replacement
    return cr.executeReplacement(ctx, proposal, votes)
}

// executeReplacement performs the coordinator swap
func (cr *CoordinatorReplacement) executeReplacement(
    ctx context.Context,
    proposal *ReplacementProposal,
    votes []ReplacementVote,
) error {
    // Step 1: Abort pending transactions from failed coordinator
    pendingTxs := getPendingTransactions(proposal.FailedCoordinator)
    for _, tx := range pendingTxs {
        abortTransaction(tx.TxID, "coordinator_replaced")
    }

    // Step 2: Release UTXO locks held by failed coordinator
    locks := getUTXOLocks(proposal.FailedCoordinator)
    for _, lock := range locks {
        releaseUTXOLock(lock)
    }

    // Step 3: Update committee
    newCommittee := cr.committee.Clone()
    for i, coord := range newCommittee.Coordinators {
        if coord.NodeID == proposal.FailedCoordinator {
            newCommittee.Coordinators[i] = Coordinator{
                NodeID:    proposal.ReplacementCoordinator,
                Role:      coord.Role,
                VRFProof:  proposal.ReplacementVRFProof,
                PublicKey: getPublicKey(proposal.ReplacementCoordinator),
                Index:     coord.Index,
            }
            break
        }
    }

    // Step 4: Broadcast committee update
    updateMsg := &CommitteeUpdateMessage{
        OldCommittee:   cr.committee,
        NewCommittee:   newCommittee,
        ReplacedNode:   proposal.FailedCoordinator,
        ReplacementNode: proposal.ReplacementCoordinator,
        Votes:          votes,
        Timestamp:      time.Now(),
    }

    if err := broadcastCommitteeUpdate(updateMsg); err != nil {
        return fmt.Errorf("broadcasting update: %w", err)
    }

    // Step 5: Update local committee reference
    cr.committee = newCommittee
    return nil
}

// selectReplacement chooses new coordinator using VRF
func (cr *CoordinatorReplacement) selectReplacement(failedCoord NodeID) (*Node, error) {
    // Generate replacement seed
    replacementSeed := sha256.Sum256(append(
        cr.committee.Seed,
        append([]byte("replacement:"), failedCoord[:]...)...,
    ))

    // Get eligible candidates (excluding current committee)
    candidates := GetEligibleCandidates(GetAllNodes(), CoordinatorEligibility)
    currentCommittee := make(map[NodeID]bool)
    for _, coord := range cr.committee.Coordinators {
        currentCommittee[coord.NodeID] = true
    }

    eligibleCandidates := make([]Node, 0)
    for _, c := range candidates {
        if !currentCommittee[c.ID] {
            eligibleCandidates = append(eligibleCandidates, c)
        }
    }

    // Select using VRF
    selected, err := SelectCoordinators(replacementSeed[:], eligibleCandidates, 1)
    if err != nil {
        return nil, err
    }

    return &selected[0], nil
}
```

#### Coordinator Replacement Quorum Requirements

**CRITICAL**: Coordinator replacement requires different voting quorums depending on the number of affected shards to prevent both minority blocking and minority forcing of removals.

```go
// pkg/consensus/replacement_quorum.go

// ReplacementQuorumConfig defines voting requirements for coordinator replacement
type ReplacementQuorumConfig struct {
    // Committee quorum (always required)
    CommitteeThreshold      int     // 5-of-7 committee coordinators

    // Shard quorum (required when shards are affected)
    ShardThreshold          float64 // 2/3 of affected shards

    // Minimum shards to require shard voting
    MinShardsForShardVoting int     // Require shard votes if >= this many shards affected
}

var DefaultReplacementQuorum = ReplacementQuorumConfig{
    CommitteeThreshold:      5,     // 5-of-7 committee coordinators
    ShardThreshold:          0.667, // 2/3 of affected shards
    MinShardsForShardVoting: 2,     // If 2+ shards affected, require shard votes
}

// ReplacementVotingMatrix defines quorum requirements based on affected shard count
// This matrix ensures:
// - Single shard failures can be resolved by committee alone
// - Multi-shard failures require both committee AND shard agreement
// - Minority cannot block legitimate removals
// - Minority cannot force illegitimate removals
type ReplacementVotingMatrix struct {
    AffectedShards int
    RequireCommittee bool
    CommitteeQuorum int        // Minimum committee votes required
    RequireShards bool
    ShardQuorum float64        // Minimum shard agreement (fraction)
    Description string
}

// GetReplacementVotingRequirements returns voting requirements based on impact
func GetReplacementVotingRequirements(affectedShardCount int) ReplacementVotingMatrix {
    switch {
    case affectedShardCount == 1:
        // Single shard: Committee alone can decide
        // Rationale: Single shard failure is local, committee oversight sufficient
        return ReplacementVotingMatrix{
            AffectedShards:   1,
            RequireCommittee: true,
            CommitteeQuorum:  5, // 5-of-7
            RequireShards:    false,
            ShardQuorum:      0.0,
            Description:      "Single shard affected - committee quorum only (5/7)",
        }

    case affectedShardCount >= 2 && affectedShardCount <= 5:
        // Multiple shards (2-5): Require both committee AND affected shards
        // Rationale: Multi-shard impact requires shard agreement to prevent abuse
        return ReplacementVotingMatrix{
            AffectedShards:   affectedShardCount,
            RequireCommittee: true,
            CommitteeQuorum:  5, // 5-of-7
            RequireShards:    true,
            ShardQuorum:      0.667, // 2/3 of affected shards
            Description:      "Multiple shards affected - require committee (5/7) AND shard quorum (2/3)",
        }

    case affectedShardCount >= 6:
        // Many shards (6+): Same as multi-shard case
        // Rationale: Large impact requires maximum consensus
        return ReplacementVotingMatrix{
            AffectedShards:   affectedShardCount,
            RequireCommittee: true,
            CommitteeQuorum:  5, // 5-of-7
            RequireShards:    true,
            ShardQuorum:      0.667, // 2/3 of affected shards
            Description:      "Many shards affected - require committee (5/7) AND shard quorum (2/3)",
        }

    default:
        // Zero shards: Committee only (internal coordinator issue)
        return ReplacementVotingMatrix{
            AffectedShards:   0,
            RequireCommittee: true,
            CommitteeQuorum:  5, // 5-of-7
            RequireShards:    false,
            ShardQuorum:      0.0,
            Description:      "No shards affected - committee quorum only (5/7)",
        }
    }
}

// ValidateReplacementVotes verifies voting quorum is met
func (cr *CoordinatorReplacement) ValidateReplacementVotes(
    proposal *ReplacementProposal,
    votes *ReplacementVotes,
) error {
    // Determine affected shards
    affectedShards := cr.getAffectedShards(proposal.FailedCoordinator)

    // Get voting requirements
    requirements := GetReplacementVotingRequirements(len(affectedShards))

    // Validate committee votes
    committeeVotes := votes.GetCommitteeVotes()
    if len(committeeVotes) < requirements.CommitteeQuorum {
        return &ErrInsufficientCommitteeVotes{
            Required: requirements.CommitteeQuorum,
            Received: len(committeeVotes),
            Total:    len(cr.committee.Coordinators),
        }
    }

    // Validate shard votes (if required)
    if requirements.RequireShards {
        shardVotes := votes.GetShardVotes(affectedShards)
        shardApprovalCount := 0

        for _, shardID := range affectedShards {
            if shardVotes[shardID] != nil && shardVotes[shardID].Approved {
                shardApprovalCount++
            }
        }

        requiredShardVotes := int(math.Ceil(float64(len(affectedShards)) * requirements.ShardQuorum))
        if shardApprovalCount < requiredShardVotes {
            return &ErrInsufficientShardVotes{
                Required:       requiredShardVotes,
                Received:       shardApprovalCount,
                TotalAffected:  len(affectedShards),
                AffectedShards: affectedShards,
            }
        }
    }

    return nil
}

// ReplacementVotes tracks votes from committee and shards
type ReplacementVotes struct {
    CommitteeVotes map[NodeID]*CommitteeVote
    ShardVotes     map[uint16]*ShardVote
}

type CommitteeVote struct {
    CoordinatorID NodeID
    Approved      bool
    Timestamp     time.Time
    Signature     []byte
    TPMQuote      []byte
}

type ShardVote struct {
    ShardID       uint16
    Approved      bool
    VoterCount    int      // Number of shard nodes that voted
    VoteSignatures [][]byte
    AggregatedAt  time.Time
}

func (rv *ReplacementVotes) GetCommitteeVotes() []*CommitteeVote {
    votes := make([]*CommitteeVote, 0, len(rv.CommitteeVotes))
    for _, vote := range rv.CommitteeVotes {
        votes = append(votes, vote)
    }
    return votes
}

func (rv *ReplacementVotes) GetShardVotes(affectedShards []uint16) map[uint16]*ShardVote {
    result := make(map[uint16]*ShardVote)
    for _, shardID := range affectedShards {
        if vote, exists := rv.ShardVotes[shardID]; exists {
            result[shardID] = vote
        }
    }
    return result
}
```

**Coordinator Replacement Quorum Matrix**:

| Affected Shards | Committee Requirement | Shard Requirement | Rationale |
|-----------------|----------------------|-------------------|-----------|
| **0 shards** | 5/7 committee | None | Internal issue, committee oversight sufficient |
| **1 shard** | 5/7 committee | None | Single shard failure, committee can decide |
| **2-5 shards** | 5/7 committee | 2/3 of affected shards | Multi-shard impact requires shard consensus |
| **6+ shards** | 5/7 committee | 2/3 of affected shards | Large impact requires maximum consensus |

**Prevention of Minority Abuse**:

The quorum matrix prevents both blocking and forcing attacks:

1. **Minority Cannot Block**:
   - Committee quorum: 5/7 coordinators (71%) required
   - A minority of 2 coordinators cannot block removal
   - Shard quorum: 2/3 (67%) required when shards involved
   - A minority of 1/3 shards cannot block removal

2. **Minority Cannot Force**:
   - Even with 5/7 committee votes, multi-shard removals require shard agreement
   - A malicious committee minority (2/7) cannot force removal alone
   - Requires both committee supermajority AND affected shard supermajority

3. **Practical Example - 3 Shards Affected**:
   - Minimum committee votes: 5 of 7 coordinators
   - Minimum shard votes: 2 of 3 affected shards (2/3 = 67%)
   - A single shard cannot block (1/3 = 33% < required 67%)
   - A single shard cannot force (need 2/3 approval)

**Error Types**:

```go
type ErrInsufficientCommitteeVotes struct {
    Required int
    Received int
    Total    int
}

func (e *ErrInsufficientCommitteeVotes) Error() string {
    return fmt.Sprintf("insufficient committee votes: required %d, received %d of %d total",
        e.Required, e.Received, e.Total)
}

type ErrInsufficientShardVotes struct {
    Required       int
    Received       int
    TotalAffected  int
    AffectedShards []uint16
}

func (e *ErrInsufficientShardVotes) Error() string {
    return fmt.Sprintf("insufficient shard votes: required %d, received %d of %d affected shards %v",
        e.Required, e.Received, e.TotalAffected, e.AffectedShards)
}
```

#### Slashing Schedule

**Timeout-Based Slashing**:

| Timeout Type | Stake Slashed | Consequence |
|--------------|---------------|-------------|
| Phase timeout (>2 min) | 1% | Warning logged, reputation reduced |
| Complete timeout (>15 min) | 5% | Coordinator removed from pool for 7 days |

**Phase-Specific Timeout Slashing**:

| Phase Timeout | Base Slash | With Grace Period | Cumulative Threshold |
|---------------|------------|-------------------|---------------------|
| CanCommit stall | 1% | After 5s grace | 3 incidents -> review |
| PreCommit stall | 2% | After 5s grace | 2 incidents -> review |
| DoCommit stall | 3% | After 5s grace | 2 incidents -> removal |
| Repeated (same tx) | +50% | No grace | Immediate removal |
| **Cumulative total** | - | - | 15% -> replacement |

**Malicious Behavior Slashing**:

| Malicious Behavior | Stake Slashed | Additional Consequence |
|--------------------|---------------|------------------------|
| Invalid commitment | 10% | Removed from coordinator pool for 30 days |
| Equivocation (conflicting messages) | 50% | Removed from coordinator pool for 180 days |
| Proven collusion | 100% | **Permanent ban** from all coordinator roles |

**Slashing Evidence Requirements**:

All slashing decisions require cryptographic evidence:

```go
// SlashingEvidence contains cryptographic proof for slashing decisions
type SlashingEvidence struct {
    // All messages must be TPM-signed with sequence numbers
    Messages          []TPMSignedMessage
    SequenceNumbers   []uint64
    TPMQuotes         [][]byte           // TPM attestation for each message

    // Evidence type
    EvidenceType      SlashingEvidenceType
    Timestamp         int64

    // Witness signatures (3+ required for slashing)
    WitnessSignatures []WitnessSignature
}

type TPMSignedMessage struct {
    MessageType     MessageType
    Payload         []byte
    SequenceNumber  uint64
    TPMSignature    []byte
    TPMQuote        []byte    // Binds message to TPM state
    Timestamp       int64
}

// SlashingEvidenceType identifies the type of malicious behavior
type SlashingEvidenceType uint8

const (
    EvidenceTypeTimeout          SlashingEvidenceType = 1  // Phase/complete timeout
    EvidenceTypeInvalidCommit    SlashingEvidenceType = 2  // Invalid commitment
    EvidenceTypeEquivocation     SlashingEvidenceType = 3  // Conflicting messages
    EvidenceTypeCollusion        SlashingEvidenceType = 4  // Proven collusion
)
```

**Coordinator Rotation Limits**:

| Rotation Count | Action |
|----------------|--------|
| 1 | Normal rotation, log event |
| 2 | Warning, increase monitoring |
| 3 | **Maximum reached** - abort consensus round |

After 3 coordinator rotations within a single consensus round:
1. Abort the current consensus round
2. Return error to client
3. Trigger investigation into Byzantine behavior
4. All involved coordinators flagged for review

```go
const (
    // Maximum coordinator rotations per consensus round
    MaxCoordinatorRotationsPerRound = 3

    // Coordinator pool removal durations
    PoolRemovalPhaseTimeout    = 7 * 24 * time.Hour   // 7 days for >15min timeout
    PoolRemovalInvalidCommit   = 30 * 24 * time.Hour  // 30 days for invalid commitment
    PoolRemovalEquivocation    = 180 * 24 * time.Hour // 180 days for equivocation
    // Collusion: permanent ban (no duration - never reinstated)
)
```

### 3PC Timeout State Machine (P4-H10)

The 3PC timeout handling requires explicit actions for EACH state transition. Without this, locks may persist indefinitely and transactions may remain in undefined states.

```go
// pkg/consensus/three_phase_timeout.go

// ThreePhaseState represents the transaction state in 3PC
type ThreePhaseState uint8

const (
    ThreePhaseInit       ThreePhaseState = iota // Initial state
    ThreePhaseCanCommit                         // Waiting for CanCommit responses
    ThreePhasePreCommit                         // PreCommit sent, waiting for acks
    ThreePhaseDoCommit                          // DoCommit sent, waiting for completion
    ThreePhaseCommitted                         // Successfully committed
    ThreePhaseAborted                           // Transaction aborted
    ThreePhaseTimedOut                          // Timeout occurred (terminal)
)

// ThreePhaseTimeoutConfig defines per-phase timeout actions
const (
    CanCommitTimeout  = 5 * time.Second   // Phase 1 timeout
    PreCommitTimeout  = 10 * time.Second  // Phase 2 timeout
    DoCommitTimeout   = 15 * time.Second  // Phase 3 timeout
    TotalThreePhaseDeadline = 35 * time.Second  // Must complete all phases
    GracePeriod       = 5 * time.Second   // Grace before abort
)

// TimeoutAction defines what happens when a phase times out
type TimeoutAction struct {
    Phase           ThreePhaseState
    NewState        ThreePhaseState
    ReleaseLocks    bool
    NotifyShards    bool
    AbortMessage    string
    ReputationDelta float64
}

// TimeoutActionMatrix defines explicit actions for each state timeout
var TimeoutActionMatrix = map[ThreePhaseState]TimeoutAction{
    ThreePhaseCanCommit: {
        Phase:           ThreePhaseCanCommit,
        NewState:        ThreePhaseAborted,
        ReleaseLocks:    true,   // Release all acquired locks
        NotifyShards:    true,   // Notify all shards to release
        AbortMessage:    "cancommit_timeout",
        ReputationDelta: -0.01,  // Minimal - could be network issue
    },
    ThreePhasePreCommit: {
        Phase:           ThreePhasePreCommit,
        NewState:        ThreePhaseAborted,
        ReleaseLocks:    true,   // Release locks, but carefully
        NotifyShards:    true,   // All shards must abort
        AbortMessage:    "precommit_timeout",
        ReputationDelta: -0.02,  // More serious - work was done
    },
    ThreePhaseDoCommit: {
        Phase:           ThreePhaseDoCommit,
        NewState:        ThreePhaseTimedOut, // Special state - may need recovery
        ReleaseLocks:    false,  // DO NOT release - transaction may have partially committed
        NotifyShards:    true,   // Shards must determine final state
        AbortMessage:    "docommit_timeout_recovery_needed",
        ReputationDelta: -0.03,  // Serious - may require recovery
    },
}

// ThreePhaseTimeoutStateMachine manages timeout state transitions
type ThreePhaseTimeoutStateMachine struct {
    txID            TxID
    coordinatorID   NodeID
    state           ThreePhaseState
    stateStartTime  time.Time
    totalStartTime  time.Time
    totalDeadline   time.Time

    // Lock tracking
    lockedUTXOs     []UTXOID
    lockedShards    []uint16

    // Timeout handling
    phaseTimer      *time.Timer
    totalTimer      *time.Timer

    // Abort coordination
    abortVotes      map[uint16]bool  // Shard votes for abort
    commitVotes     map[uint16]bool  // Shard votes for commit (DoCommit only)

    // State persistence
    persisted       bool
    persistedAt     time.Time
}

// NewThreePhaseTimeoutSM creates a new timeout state machine
func NewThreePhaseTimeoutSM(txID TxID, coordID NodeID, utxos []UTXOID, shards []uint16) *ThreePhaseTimeoutStateMachine {
    now := time.Now()
    sm := &ThreePhaseTimeoutStateMachine{
        txID:           txID,
        coordinatorID:  coordID,
        state:          ThreePhaseInit,
        stateStartTime: now,
        totalStartTime: now,
        totalDeadline:  now.Add(TotalThreePhaseDeadline),
        lockedUTXOs:    utxos,
        lockedShards:   shards,
        abortVotes:     make(map[uint16]bool),
        commitVotes:    make(map[uint16]bool),
    }

    // Start total deadline timer
    sm.totalTimer = time.AfterFunc(TotalThreePhaseDeadline, func() {
        sm.handleTotalDeadline()
    })

    return sm
}

// TransitionTo moves to a new phase with timeout tracking
func (sm *ThreePhaseTimeoutStateMachine) TransitionTo(newState ThreePhaseState) error {
    // Validate transition
    if !sm.isValidTransition(sm.state, newState) {
        return &InvalidStateTransitionError{
            TxID:      sm.txID,
            FromState: sm.state,
            ToState:   newState,
        }
    }

    // Cancel existing phase timer
    if sm.phaseTimer != nil {
        sm.phaseTimer.Stop()
    }

    sm.state = newState
    sm.stateStartTime = time.Now()

    // Set new phase timeout
    timeout := sm.getPhaseTimeout(newState)
    if timeout > 0 {
        sm.phaseTimer = time.AfterFunc(timeout, func() {
            sm.handlePhaseTimeout()
        })
    }

    // Persist state change
    sm.persistState()

    return nil
}

// isValidTransition checks if state transition is allowed
func (sm *ThreePhaseTimeoutStateMachine) isValidTransition(from, to ThreePhaseState) bool {
    validTransitions := map[ThreePhaseState][]ThreePhaseState{
        ThreePhaseInit:       {ThreePhaseCanCommit, ThreePhaseAborted},
        ThreePhaseCanCommit:  {ThreePhasePreCommit, ThreePhaseAborted},
        ThreePhasePreCommit:  {ThreePhaseDoCommit, ThreePhaseAborted},
        ThreePhaseDoCommit:   {ThreePhaseCommitted, ThreePhaseTimedOut, ThreePhaseAborted},
        // Terminal states - no transitions out
        ThreePhaseCommitted:  {},
        ThreePhaseAborted:    {},
        ThreePhaseTimedOut:   {ThreePhaseAborted, ThreePhaseCommitted}, // Recovery can resolve
    }

    allowed := validTransitions[from]
    for _, s := range allowed {
        if s == to {
            return true
        }
    }
    return false
}

// getPhaseTimeout returns timeout for a given phase
func (sm *ThreePhaseTimeoutStateMachine) getPhaseTimeout(phase ThreePhaseState) time.Duration {
    switch phase {
    case ThreePhaseCanCommit:
        return CanCommitTimeout
    case ThreePhasePreCommit:
        return PreCommitTimeout
    case ThreePhaseDoCommit:
        return DoCommitTimeout
    default:
        return 0 // Terminal states have no timeout
    }
}

// handlePhaseTimeout executes timeout action for current phase
func (sm *ThreePhaseTimeoutStateMachine) handlePhaseTimeout() {
    action, exists := TimeoutActionMatrix[sm.state]
    if !exists {
        // No action defined for this state
        return
    }

    log.Warn("3PC phase timeout",
        "tx_id", sm.txID,
        "phase", sm.state,
        "coordinator", sm.coordinatorID,
        "elapsed", time.Since(sm.stateStartTime))

    // Apply grace period
    time.Sleep(GracePeriod)

    // Check if state changed during grace period
    if sm.state != action.Phase {
        return // State already transitioned
    }

    // Execute timeout action
    sm.executeTimeoutAction(action)
}

// handleTotalDeadline handles overall transaction deadline
func (sm *ThreePhaseTimeoutStateMachine) handleTotalDeadline() {
    log.Error("3PC total deadline exceeded",
        "tx_id", sm.txID,
        "phase", sm.state,
        "elapsed", time.Since(sm.totalStartTime))

    // Force abort regardless of current phase
    sm.forceAbort("total_deadline_exceeded")
}

// executeTimeoutAction performs the timeout action
func (sm *ThreePhaseTimeoutStateMachine) executeTimeoutAction(action TimeoutAction) {
    // Transition to new state
    sm.state = action.NewState

    // Apply reputation penalty
    if action.ReputationDelta != 0 {
        applyReputationDelta(sm.coordinatorID, action.ReputationDelta, action.AbortMessage)
    }

    // Handle locks based on action
    if action.ReleaseLocks {
        sm.releaseAllLocks()
    }

    // Notify shards based on phase
    if action.NotifyShards {
        sm.notifyShards(action)
    }

    // Persist final state
    sm.persistState()
}

// releaseAllLocks releases all UTXO locks held by this transaction
func (sm *ThreePhaseTimeoutStateMachine) releaseAllLocks() {
    for _, utxo := range sm.lockedUTXOs {
        if err := releaseUTXOLock(utxo, sm.txID); err != nil {
            log.Error("failed to release UTXO lock",
                "tx_id", sm.txID,
                "utxo", utxo,
                "error", err)
        }
    }
    sm.lockedUTXOs = nil
}

// notifyShards sends abort/recovery messages to all participating shards
func (sm *ThreePhaseTimeoutStateMachine) notifyShards(action TimeoutAction) {
    for _, shardID := range sm.lockedShards {
        msg := &ShardAbortMessage{
            TxID:           sm.txID,
            ShardID:        shardID,
            Reason:         action.AbortMessage,
            FromPhase:      action.Phase,
            ReleaseLocks:   action.ReleaseLocks,
            RecoveryNeeded: (action.NewState == ThreePhaseTimedOut),
            Timestamp:      time.Now(),
        }

        if err := sendToShard(shardID, msg); err != nil {
            log.Error("failed to notify shard of abort",
                "tx_id", sm.txID,
                "shard", shardID,
                "error", err)
        }
    }
}

// forceAbort forces immediate abort of the transaction
func (sm *ThreePhaseTimeoutStateMachine) forceAbort(reason string) {
    // Stop all timers
    if sm.phaseTimer != nil {
        sm.phaseTimer.Stop()
    }
    if sm.totalTimer != nil {
        sm.totalTimer.Stop()
    }

    // Determine if locks should be released based on current phase
    releaseLocks := true
    if sm.state == ThreePhaseDoCommit {
        // In DoCommit phase, some shards may have committed
        // Cannot safely release locks - need recovery
        releaseLocks = false
    }

    action := TimeoutAction{
        Phase:           sm.state,
        NewState:        ThreePhaseAborted,
        ReleaseLocks:    releaseLocks,
        NotifyShards:    true,
        AbortMessage:    reason,
        ReputationDelta: -0.05, // Higher penalty for force abort
    }

    sm.executeTimeoutAction(action)
}

// persistState saves state machine state for crash recovery
func (sm *ThreePhaseTimeoutStateMachine) persistState() {
    state := &PersistedThreePhaseState{
        TxID:           sm.txID,
        CoordinatorID:  sm.coordinatorID,
        CurrentState:   sm.state,
        StartTime:      sm.totalStartTime,
        StateStartTime: sm.stateStartTime,
        LockedUTXOs:    sm.lockedUTXOs,
        LockedShards:   sm.lockedShards,
        AbortVotes:     sm.abortVotes,
        CommitVotes:    sm.commitVotes,
        PersistedAt:    time.Now(),
    }

    if err := persistThreePhaseState(state); err != nil {
        log.Error("failed to persist 3PC state", "tx_id", sm.txID, "error", err)
    }
    sm.persisted = true
    sm.persistedAt = time.Now()
}

// Error types
type InvalidStateTransitionError struct {
    TxID      TxID
    FromState ThreePhaseState
    ToState   ThreePhaseState
}

func (e *InvalidStateTransitionError) Error() string {
    return fmt.Sprintf("invalid 3PC transition: %d -> %d (tx=%x)",
        e.FromState, e.ToState, e.TxID[:8])
}

type ShardAbortMessage struct {
    TxID           TxID
    ShardID        uint16
    Reason         string
    FromPhase      ThreePhaseState
    ReleaseLocks   bool
    RecoveryNeeded bool
    Timestamp      time.Time
}

type PersistedThreePhaseState struct {
    TxID           TxID
    CoordinatorID  NodeID
    CurrentState   ThreePhaseState
    StartTime      time.Time
    StateStartTime time.Time
    LockedUTXOs    []UTXOID
    LockedShards   []uint16
    AbortVotes     map[uint16]bool
    CommitVotes    map[uint16]bool
    PersistedAt    time.Time
}

// =============================================================================
// ORPHAN LOCK SCANNER (SECURITY FIX P5-C5)
// =============================================================================
// Addresses: Coordinator crash in CanCommit phase leaves locks forever
// Solution: Periodic scanner that identifies and releases orphaned locks

const (
    OrphanScanInterval      = 5 * time.Minute   // How often to scan
    LockOrphanThreshold     = 2 * time.Minute   // Lock age before considered orphan
    MaxOrphanCleanupPerScan = 1000              // Limit per scan to avoid overload
)

// OrphanLockScanner periodically scans for and cleans up orphaned locks
// SECURITY FIX (P5-C5): Prevents permanent lock starvation from coordinator crashes
type OrphanLockScanner struct {
    db              *Database
    lockManager     *UTXOLockManager
    coordinatorReg  *CoordinatorRegistry
    scanInterval    time.Duration
    stopCh          chan struct{}
    metrics         *OrphanScanMetrics
}

type OrphanScanMetrics struct {
    ScansCompleted     atomic.Uint64
    LocksScanned       atomic.Uint64
    OrphansFound       atomic.Uint64
    OrphansReleased    atomic.Uint64
    OrphansFailedClean atomic.Uint64
    LastScanDuration   atomic.Int64  // Nanoseconds
}

// NewOrphanLockScanner creates a scanner that runs every 5 minutes
func NewOrphanLockScanner(db *Database, lm *UTXOLockManager, cr *CoordinatorRegistry) *OrphanLockScanner {
    return &OrphanLockScanner{
        db:             db,
        lockManager:    lm,
        coordinatorReg: cr,
        scanInterval:   OrphanScanInterval,
        stopCh:         make(chan struct{}),
        metrics:        &OrphanScanMetrics{},
    }
}

// Start begins the background scanner
func (s *OrphanLockScanner) Start() {
    go s.runScanner()
}

// Stop halts the scanner
func (s *OrphanLockScanner) Stop() {
    close(s.stopCh)
}

// runScanner runs the main scan loop
func (s *OrphanLockScanner) runScanner() {
    ticker := time.NewTicker(s.scanInterval)
    defer ticker.Stop()

    for {
        select {
        case <-s.stopCh:
            return
        case <-ticker.C:
            s.performScan()
        }
    }
}

// performScan executes one scan cycle
func (s *OrphanLockScanner) performScan() {
    startTime := time.Now()
    defer func() {
        s.metrics.LastScanDuration.Store(time.Since(startTime).Nanoseconds())
        s.metrics.ScansCompleted.Add(1)
    }()

    // Get all active locks
    locks, err := s.lockManager.GetActiveLocks()
    if err != nil {
        log.Error("orphan scan failed to get locks", "error", err)
        return
    }

    s.metrics.LocksScanned.Add(uint64(len(locks)))

    orphanCount := 0
    now := time.Now()

    for _, lock := range locks {
        // Stop if we've hit the per-scan limit
        if orphanCount >= MaxOrphanCleanupPerScan {
            log.Warn("orphan scan hit cleanup limit",
                "limit", MaxOrphanCleanupPerScan,
                "remaining", len(locks)-orphanCount)
            break
        }

        // Check if lock is orphaned
        isOrphan, reason := s.isLockOrphaned(lock, now)
        if !isOrphan {
            continue
        }

        s.metrics.OrphansFound.Add(1)
        orphanCount++

        // Try to release the orphan lock
        if err := s.releaseOrphanLock(lock, reason); err != nil {
            s.metrics.OrphansFailedClean.Add(1)
            log.Error("failed to release orphan lock",
                "tx_id", lock.TxID,
                "utxo", lock.UTXOID,
                "reason", reason,
                "error", err)
        } else {
            s.metrics.OrphansReleased.Add(1)
            log.Info("released orphan lock",
                "tx_id", lock.TxID,
                "utxo", lock.UTXOID,
                "reason", reason,
                "lock_age", now.Sub(lock.AcquiredAt))
        }
    }
}

// isLockOrphaned determines if a lock should be considered orphaned
func (s *OrphanLockScanner) isLockOrphaned(lock *UTXOLock, now time.Time) (bool, string) {
    // Check 1: Lock age exceeds threshold AND no active 3PC state
    lockAge := now.Sub(lock.AcquiredAt)
    if lockAge < LockOrphanThreshold {
        return false, "" // Too young to be orphan
    }

    // Check 2: Is there an active 3PC transaction for this lock?
    state, err := s.db.GetThreePhaseState(lock.TxID)
    if err != nil || state == nil {
        // No 3PC state found - coordinator may have crashed before persisting
        return true, "no_3pc_state"
    }

    // Check 3: Is the 3PC in a terminal state?
    if state.CurrentState == ThreePhaseCommitted ||
       state.CurrentState == ThreePhaseAborted {
        // Transaction completed but lock wasn't released - cleanup needed
        return true, "3pc_completed_lock_orphaned"
    }

    // Check 4: Has the 3PC exceeded total deadline?
    if now.After(state.StartTime.Add(TotalThreePhaseDeadline)) {
        return true, "3pc_deadline_exceeded"
    }

    // Check 5: Is the coordinator still alive?
    if !s.coordinatorReg.IsCoordinatorActive(state.CoordinatorID) {
        return true, "coordinator_offline"
    }

    // Check 6: Is the 3PC stuck (no state change for extended period)?
    stateStaleness := now.Sub(state.StateStartTime)
    maxPhaseTime := DoCommitTimeout + GracePeriod
    if stateStaleness > maxPhaseTime*2 {
        return true, "3pc_state_stale"
    }

    return false, ""
}

// releaseOrphanLock safely releases an orphan lock
func (s *OrphanLockScanner) releaseOrphanLock(lock *UTXOLock, reason string) error {
    // Log the orphan event for audit
    auditLog := &OrphanLockAuditEntry{
        TxID:        lock.TxID,
        UTXOID:      lock.UTXOID,
        LockHolder:  lock.HolderID,
        AcquiredAt:  lock.AcquiredAt,
        ReleasedAt:  time.Now(),
        Reason:      reason,
        ReleasedBy:  "orphan_scanner",
    }
    s.db.LogOrphanRelease(auditLog)

    // Release the lock
    return s.lockManager.ForceRelease(lock.UTXOID, lock.TxID, reason)
}

type UTXOLock struct {
    UTXOID     UTXOID
    TxID       TxID
    HolderID   NodeID
    AcquiredAt time.Time
    Phase      ThreePhaseState
}

type OrphanLockAuditEntry struct {
    TxID        TxID
    UTXOID      UTXOID
    LockHolder  NodeID
    AcquiredAt  time.Time
    ReleasedAt  time.Time
    Reason      string
    ReleasedBy  string
}
```

**3PC Timeout State Machine Diagram**:

```
                           ┌──────────────────────────────────────────┐
                           │         TOTAL DEADLINE (35s)             │
                           │         Exceeds → FORCE ABORT            │
                           └──────────────────────────────────────────┘
                                              │
    ┌─────────────────────────────────────────┼─────────────────────────────────────────┐
    │                                         │                                         │
    │  ┌─────────┐    5s timeout    ┌─────────────────┐    10s timeout   ┌───────────┐ │
    │  │  INIT   │────────────────→ │   CAN_COMMIT    │───────────────→  │ PRE_COMMIT│ │
    │  └─────────┘                  └─────────────────┘                  └───────────┘ │
    │       │                              │ │                               │ │       │
    │       │                              │ │ Timeout                       │ │       │
    │       │                              │ ↓                               │ │       │
    │       │                              │ ┌────────────────────────┐      │ │       │
    │       │                              │ │ ABORT                  │      │ │       │
    │       │                              │ │ - Release ALL locks    │      │ │       │
    │       │                              │ │ - Notify ALL shards    │      │ │       │
    │       │                              │ │ - Slash 1% reputation  │      │ │       │
    │       │                              │ └────────────────────────┘      │ │       │
    │       │                              │                                 │ │       │
    │       │                              │                    Timeout      │ │       │
    │       │                              │                         ↓       │ │       │
    │       │                              │         ┌────────────────────────┘ │       │
    │       │                              │         │                          │       │
    │       │                              │         ↓                          │       │
    │       │                              │ ┌────────────────────────┐         │       │
    │       │                              │ │ ABORT                  │         │       │
    │       │                              │ │ - Release ALL locks    │         │       │
    │       │                              │ │ - Notify ALL shards    │         │       │
    │       │                              │ │ - Slash 2% reputation  │         │       │
    │       │                              │ └────────────────────────┘         │       │
    │       │                              │                                    │       │
    │       │                              │                  ┌─────────────────┘       │
    │       │                              │                  │ 15s timeout             │
    │       │                              │                  ↓                         │
    │       │                              │          ┌─────────────┐                   │
    │       │                              │          │  DO_COMMIT  │                   │
    │       │                              │          └──────┬──────┘                   │
    │       │                              │                 │                          │
    │       │                              │     ┌───────────┼───────────┐              │
    │       │                              │     │           │           │              │
    │       │                              │   Success   Timeout    Abort              │
    │       │                              │     │           │           │              │
    │       │                              │     ↓           ↓           ↓              │
    │       │                              │ ┌───────┐ ┌─────────────┐ ┌───────┐        │
    │       │                              │ │COMMIT │ │ TIMED_OUT   │ │ABORTED│        │
    │       │                              │ │       │ │(RECOVERY)   │ │       │        │
    │       │                              │ │       │ │             │ │       │        │
    │       │                              │ │Terminal│ │ - NO lock  │ │       │        │
    │       │                              │ │       │ │   release   │ │       │        │
    │       │                              │ │       │ │ - Shards    │ │       │        │
    │       │                              │ │       │ │   determine │ │       │        │
    │       │                              │ │       │ │   outcome   │ │       │        │
    │       │                              │ │       │ │ - 3% slash  │ │       │        │
    │       │                              │ └───────┘ └─────────────┘ └───────┘        │
    │                                                                                   │
    └───────────────────────────────────────────────────────────────────────────────────┘
```

**Timeout Actions Summary**:

| Phase | Timeout | Lock Action | Shard Action | Reputation | Recovery |
|-------|---------|-------------|--------------|------------|----------|
| CanCommit | 5s + 5s grace | RELEASE ALL | Abort message | -1% | None needed |
| PreCommit | 10s + 5s grace | RELEASE ALL | Abort message | -2% | None needed |
| DoCommit | 15s + 5s grace | **KEEP** | Recovery message | -3% | Shard consensus |
| Total deadline | 35s | Phase-dependent | Force abort | -5% | May need |

**DoCommit Timeout Recovery**:

When DoCommit times out, the transaction may have partially committed. Recovery requires:
1. All shards report their state (committed/not committed)
2. If ANY shard committed → all must commit (forward recovery)
3. If NO shard committed → all abort (backward recovery)
4. Recovery is coordinated by new coordinator or backup

---

### S10: Coordinator Latency-Based DoS Prevention

A coordinator can degrade network performance by consistently responding slowly (but just under timeout thresholds), avoiding penalties while reducing throughput. This section adds cumulative latency tracking with automatic rotation for consistently slow coordinators.

#### Problem Statement

**Slow-response DoS attack:**
1. Coordinator responds to PBFT phases at 4.9s (just under 5s timeout)
2. No timeout triggered, no slashing occurs
3. Network throughput degraded by ~10x
4. Attack is difficult to distinguish from network congestion

#### Cumulative Latency Tracking

```go
// CoordinatorLatencyTracker tracks response time patterns for DoS detection
type CoordinatorLatencyTracker struct {
    coordinators   map[NodeID]*LatencyStats
    windowSize     int           // Number of samples in rolling window
    slowThreshold  float64       // Response time as fraction of timeout (0.8 = 80%)
    penaltyRate    float64       // Reputation penalty per slow response
    rotationThresh float64       // Cumulative slowness for rotation
    mu             sync.RWMutex
}

// LatencyStats tracks per-coordinator response time statistics
type LatencyStats struct {
    NodeID            NodeID
    Samples           []LatencySample
    SlowResponseCount uint64     // Atomic counter
    CumulativePenalty float64    // Total penalties applied
    LastRotationCheck time.Time
}

// LatencySample records a single response measurement
type LatencySample struct {
    Phase         PBFTPhase
    ResponseTime  time.Duration
    ExpectedMax   time.Duration  // Timeout for this phase
    Timestamp     time.Time
    WasSlow       bool           // ResponseTime > slowThreshold * ExpectedMax
}

// Latency tracking constants - NOT configurable (security critical)
const (
    LatencyWindowSize     = 100    // Rolling window of 100 samples
    SlowResponseThreshold = 0.80   // 80% of timeout = "slow"
    SlowPenaltyRate       = 0.001  // 0.1% reputation per slow response
    RotationThreshold     = 0.05   // 5% cumulative slowness triggers rotation
    MinSamplesForPenalty  = 20     // Need 20 samples before penalties apply
)

// NewCoordinatorLatencyTracker creates a latency tracker with secure defaults
func NewCoordinatorLatencyTracker() *CoordinatorLatencyTracker {
    return &CoordinatorLatencyTracker{
        coordinators:   make(map[NodeID]*LatencyStats),
        windowSize:     LatencyWindowSize,
        slowThreshold:  SlowResponseThreshold,
        penaltyRate:    SlowPenaltyRate,
        rotationThresh: RotationThreshold,
    }
}

// RecordResponse atomically records a coordinator's response time
func (clt *CoordinatorLatencyTracker) RecordResponse(
    coordinatorID NodeID,
    phase PBFTPhase,
    responseTime time.Duration,
    timeout time.Duration,
) {
    clt.mu.Lock()
    defer clt.mu.Unlock()

    stats := clt.getOrCreateStats(coordinatorID)

    // Determine if response was slow
    slowThreshold := time.Duration(float64(timeout) * clt.slowThreshold)
    wasSlow := responseTime > slowThreshold

    sample := LatencySample{
        Phase:        phase,
        ResponseTime: responseTime,
        ExpectedMax:  timeout,
        Timestamp:    time.Now(),
        WasSlow:      wasSlow,
    }

    // Add to rolling window (evict oldest if full)
    if len(stats.Samples) >= clt.windowSize {
        // Remove oldest sample, adjust slow count if needed
        if stats.Samples[0].WasSlow {
            atomic.AddUint64(&stats.SlowResponseCount, ^uint64(0)) // Decrement
        }
        stats.Samples = stats.Samples[1:]
    }
    stats.Samples = append(stats.Samples, sample)

    // Track slow responses atomically
    if wasSlow {
        atomic.AddUint64(&stats.SlowResponseCount, 1)
        clt.applySlownessPenalty(stats)
    }

    // Check for rotation
    clt.checkRotationNeeded(stats)
}

// applySlownessPenalty applies incremental penalty for slow response
func (clt *CoordinatorLatencyTracker) applySlownessPenalty(stats *LatencyStats) {
    // Only penalize after sufficient samples
    if len(stats.Samples) < MinSamplesForPenalty {
        return
    }

    // Calculate slowness ratio
    slowCount := atomic.LoadUint64(&stats.SlowResponseCount)
    slowRatio := float64(slowCount) / float64(len(stats.Samples))

    // Only penalize if >50% of responses are slow (pattern, not noise)
    if slowRatio > 0.50 {
        stats.CumulativePenalty += clt.penaltyRate

        // Log for monitoring
        logSlowCoordinatorWarning(stats.NodeID, slowRatio, stats.CumulativePenalty)
    }
}

// checkRotationNeeded determines if coordinator should be rotated out
func (clt *CoordinatorLatencyTracker) checkRotationNeeded(stats *LatencyStats) {
    // Rate limit rotation checks
    if time.Since(stats.LastRotationCheck) < 30*time.Second {
        return
    }
    stats.LastRotationCheck = time.Now()

    // Check cumulative penalty threshold
    if stats.CumulativePenalty >= clt.rotationThresh {
        // Initiate rotation
        initiateSlowCoordinatorRotation(stats.NodeID, stats.CumulativePenalty)

        // Reset cumulative penalty after rotation
        stats.CumulativePenalty = 0
    }
}

// GetLatencyPercentiles returns p50, p95, p99 latencies for a coordinator
func (clt *CoordinatorLatencyTracker) GetLatencyPercentiles(coordinatorID NodeID) (p50, p95, p99 time.Duration) {
    clt.mu.RLock()
    defer clt.mu.RUnlock()

    stats, exists := clt.coordinators[coordinatorID]
    if !exists || len(stats.Samples) == 0 {
        return 0, 0, 0
    }

    // Sort samples by response time
    sorted := make([]time.Duration, len(stats.Samples))
    for i, s := range stats.Samples {
        sorted[i] = s.ResponseTime
    }
    sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

    n := len(sorted)
    p50 = sorted[n*50/100]
    p95 = sorted[n*95/100]
    p99 = sorted[n*99/100]
    return p50, p95, p99
}
```

#### Slow Coordinator Rotation Protocol

When a coordinator accumulates excessive slowness penalties, automatic rotation occurs:

```go
// SlowCoordinatorRotation handles rotating out slow coordinators
type SlowCoordinatorRotation struct {
    committee        *Committee
    latencyTracker   *CoordinatorLatencyTracker
    rotationTimeout  time.Duration
}

// initiateSlowCoordinatorRotation begins rotation process for slow coordinator
func initiateSlowCoordinatorRotation(slowCoordID NodeID, cumulativePenalty float64) error {
    // Step 1: Create rotation proposal with evidence
    proposal := &SlowRotationProposal{
        SlowCoordinator:   slowCoordID,
        CumulativePenalty: cumulativePenalty,
        Evidence:          collectSlownessEvidence(slowCoordID),
        ProposedAt:        time.Now(),
    }

    // Step 2: Verify evidence integrity
    if !verifySlownessEvidence(proposal.Evidence) {
        return ErrInvalidSlownessEvidence
    }

    // Step 3: Committee votes on rotation (requires threshold)
    votes, err := collectRotationVotes(proposal)
    if err != nil {
        return fmt.Errorf("collecting rotation votes: %w", err)
    }

    // Step 4: Execute rotation if threshold met
    if len(votes) >= CommitteeThreshold {
        return executeSlowRotation(slowCoordID, proposal)
    }

    return ErrInsufficientRotationVotes
}

// SlowRotationProposal contains evidence for slow coordinator rotation
type SlowRotationProposal struct {
    SlowCoordinator   NodeID
    CumulativePenalty float64
    Evidence          *SlownessEvidence
    ProposedAt        time.Time
    ProposerID        NodeID
}

// SlownessEvidence provides cryptographic proof of slow responses
type SlownessEvidence struct {
    CoordinatorID    NodeID
    SampleHashes     [][32]byte    // Hashes of latency samples
    SlowCount        uint64
    TotalSamples     uint64
    P95Latency       time.Duration
    ExpectedP95      time.Duration // What P95 should be (<50% of timeout)
    WitnessSigs      []WitnessSignature
    CollectedAt      time.Time
}

// WitnessSignature is a signed attestation of observed latency
type WitnessSignature struct {
    WitnessID       NodeID
    ObservedP95     time.Duration
    SampleCount     uint64
    Signature       []byte
    Timestamp       int64
}

// executeSlowRotation atomically rotates out slow coordinator
func executeSlowRotation(slowCoordID NodeID, proposal *SlowRotationProposal) error {
    // Atomic rotation with pending transaction handling
    rotation := &AtomicCoordinatorRotation{
        OldCoordinator: slowCoordID,
        Reason:         RotationReasonSlowResponse,
        Evidence:       proposal.Evidence,
    }

    // Step 1: Select replacement using VRF
    replacement, err := selectReplacementCoordinator(slowCoordID)
    if err != nil {
        return fmt.Errorf("selecting replacement: %w", err)
    }
    rotation.NewCoordinator = replacement.ID

    // Step 2: Freeze new transactions for old coordinator
    freezeCoordinatorTransactions(slowCoordID)

    // Step 3: Transfer pending transactions to replacement
    pending := getPendingTransactions(slowCoordID)
    for _, tx := range pending {
        if err := transferTransactionCoordinator(tx, replacement.ID); err != nil {
            // Log but continue - stuck transactions timeout normally
            logTransactionTransferFailure(tx.ID, err)
        }
    }

    // Step 4: Update committee membership
    if err := updateCommitteeMembership(slowCoordID, replacement.ID); err != nil {
        return fmt.Errorf("updating committee: %w", err)
    }

    // Step 5: Broadcast rotation to network
    broadcastCoordinatorRotation(rotation)

    // Step 6: Apply reputation penalty to rotated coordinator
    applyReputationSlash(slowCoordID, proposal.CumulativePenalty)

    return nil
}
```

#### Latency Tracking Integration Points

Latency tracking must be integrated at every PBFT phase completion:

```go
// Integration in PBFT message handling
func (node *PBFTNode) handlePrepareResponse(msg *PrepareMessage) {
    // ... existing validation ...

    // Record latency for coordinator latency tracking
    responseTime := time.Since(node.phaseStartTime[msg.SequenceNum])
    latencyTracker.RecordResponse(
        msg.SenderID,
        PhasePrepare,
        responseTime,
        DefaultPBFTTimeouts.Prepare,
    )

    // ... existing processing ...
}

func (node *PBFTNode) handleCommitResponse(msg *CommitMessage) {
    // ... existing validation ...

    // Record latency for coordinator latency tracking
    responseTime := time.Since(node.phaseStartTime[msg.SequenceNum])
    latencyTracker.RecordResponse(
        msg.SenderID,
        PhaseCommit,
        responseTime,
        DefaultPBFTTimeouts.Commit,
    )

    // ... existing processing ...
}
```

#### Slow Coordinator Detection Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Rolling Window** | 100 samples | Sufficient for statistical significance |
| **Slow Threshold** | 80% of timeout | Distinguishes slow from normal variance |
| **Penalty Rate** | 0.1% per slow response | Gradual accumulation |
| **Rotation Threshold** | 5% cumulative | ~50 slow responses trigger rotation |
| **Min Samples** | 20 | Avoid penalizing during warmup |
| **Pattern Threshold** | >50% slow | Distinguish attack from congestion |

#### Attack Detection vs Network Congestion

The system distinguishes malicious slowness from legitimate congestion:

| Signal | Slow Attack | Network Congestion |
|--------|-------------|-------------------|
| **Pattern** | Consistent 80%+ of timeout | Variable latency |
| **Scope** | Single coordinator | Multiple coordinators |
| **P95/P50 Ratio** | Low (consistent slowness) | High (variance) |
| **Response to Load** | No improvement | Improves when load decreases |
| **Geographic** | Isolated to coordinator | Network-wide |

```go
// isLikelyAttack distinguishes attack from congestion
func (clt *CoordinatorLatencyTracker) isLikelyAttack(stats *LatencyStats) bool {
    if len(stats.Samples) < MinSamplesForPenalty {
        return false
    }

    p50, p95, _ := clt.GetLatencyPercentiles(stats.NodeID)

    // Attack signature: consistent slowness (low variance)
    // Congestion signature: high variance (p95 >> p50)
    varianceRatio := float64(p95) / float64(p50)

    // Low variance (< 1.5x) + high absolute latency = likely attack
    slowCount := atomic.LoadUint64(&stats.SlowResponseCount)
    slowRatio := float64(slowCount) / float64(len(stats.Samples))

    return varianceRatio < 1.5 && slowRatio > 0.5
}
```

---

### Coordinator Performance Tracking

Coordinators that frequently trigger view changes can destabilize consensus and enable denial-of-service attacks. The system tracks view change triggers per coordinator and applies progressive exclusion to prevent abuse.

#### View Change Trigger Tracking

```go
// ViewChangeTriggerTracker monitors coordinators that cause view changes
type ViewChangeTriggerTracker struct {
    triggers        map[NodeID]*CoordinatorTriggerHistory
    exclusionWindow time.Duration
    mu              sync.RWMutex
}

// CoordinatorTriggerHistory tracks a coordinator's view change behavior
type CoordinatorTriggerHistory struct {
    CoordinatorID      NodeID
    RecentTriggers     []ViewChangeTrigger
    ExclusionCount     int           // Number of times excluded
    ExcludedUntil      time.Time     // Current exclusion end time
    TotalTriggers      uint64        // Lifetime count
}

// ViewChangeTrigger records a single view change trigger event
type ViewChangeTrigger struct {
    ViewNumber     uint64
    TriggerTime    time.Time
    Reason         ViewChangeReason
    WasTimeout     bool          // True if coordinator timed out
    WasMalicious   bool          // True if equivocation detected
}

// View change tracking constants
const (
    ViewChangeTriggerWindow     = 1 * time.Hour    // Window to track triggers
    ViewChangeExclusionRounds   = 3                // Exclude from next 3 selections
    ViewChangeProgressiveMultiplier = 2            // Double exclusion on repeat
    ViewChangeMaxExclusionRounds = 24              // Max 24 round exclusion
)
```

#### Progressive Exclusion Protocol

```go
// NewViewChangeTriggerTracker creates a tracker with default settings
func NewViewChangeTriggerTracker() *ViewChangeTriggerTracker {
    return &ViewChangeTriggerTracker{
        triggers:        make(map[NodeID]*CoordinatorTriggerHistory),
        exclusionWindow: ViewChangeTriggerWindow,
    }
}

// RecordViewChangeTrigger records that a coordinator triggered a view change
func (vct *ViewChangeTriggerTracker) RecordViewChangeTrigger(
    coordinatorID NodeID,
    viewNumber uint64,
    reason ViewChangeReason,
) {
    vct.mu.Lock()
    defer vct.mu.Unlock()

    history := vct.triggers[coordinatorID]
    if history == nil {
        history = &CoordinatorTriggerHistory{
            CoordinatorID:  coordinatorID,
            RecentTriggers: make([]ViewChangeTrigger, 0),
        }
        vct.triggers[coordinatorID] = history
    }

    trigger := ViewChangeTrigger{
        ViewNumber:  viewNumber,
        TriggerTime: time.Now(),
        Reason:      reason,
        WasTimeout:  reason == ViewChangeReasonTimeout,
        WasMalicious: reason == ViewChangeReasonMalicious,
    }

    history.RecentTriggers = append(history.RecentTriggers, trigger)
    history.TotalTriggers++

    // Clean up old triggers
    vct.pruneOldTriggers(history)

    // Apply exclusion if warranted
    vct.applyExclusion(history)
}

// pruneOldTriggers removes triggers outside the tracking window
func (vct *ViewChangeTriggerTracker) pruneOldTriggers(history *CoordinatorTriggerHistory) {
    cutoff := time.Now().Add(-vct.exclusionWindow)

    i := 0
    for _, trigger := range history.RecentTriggers {
        if trigger.TriggerTime.After(cutoff) {
            history.RecentTriggers[i] = trigger
            i++
        }
    }
    history.RecentTriggers = history.RecentTriggers[:i]
}

// applyExclusion determines if coordinator should be excluded from selection
func (vct *ViewChangeTriggerTracker) applyExclusion(history *CoordinatorTriggerHistory) {
    recentCount := len(history.RecentTriggers)

    // Check for malicious triggers (immediate exclusion)
    for _, trigger := range history.RecentTriggers {
        if trigger.WasMalicious {
            // Malicious behavior: maximum exclusion
            exclusionRounds := ViewChangeMaxExclusionRounds
            history.ExcludedUntil = time.Now().Add(time.Duration(exclusionRounds) * HeartbeatInterval * 10)
            history.ExclusionCount++
            return
        }
    }

    // Check for repeated timeout triggers (progressive exclusion)
    if recentCount >= 2 {
        // Calculate progressive exclusion duration
        baseRounds := ViewChangeExclusionRounds
        multiplier := 1

        // Progressive increase based on exclusion count
        for i := 0; i < history.ExclusionCount; i++ {
            multiplier *= ViewChangeProgressiveMultiplier
        }

        exclusionRounds := baseRounds * multiplier
        if exclusionRounds > ViewChangeMaxExclusionRounds {
            exclusionRounds = ViewChangeMaxExclusionRounds
        }

        // Exclude for N coordinator selection rounds
        history.ExcludedUntil = time.Now().Add(time.Duration(exclusionRounds) * HeartbeatInterval * 10)
        history.ExclusionCount++
    }
}

// IsExcluded checks if a coordinator is currently excluded from selection
func (vct *ViewChangeTriggerTracker) IsExcluded(coordinatorID NodeID) bool {
    vct.mu.RLock()
    defer vct.mu.RUnlock()

    history := vct.triggers[coordinatorID]
    if history == nil {
        return false
    }

    return time.Now().Before(history.ExcludedUntil)
}

// GetExclusionStatus returns detailed exclusion information
func (vct *ViewChangeTriggerTracker) GetExclusionStatus(coordinatorID NodeID) *ExclusionStatus {
    vct.mu.RLock()
    defer vct.mu.RUnlock()

    history := vct.triggers[coordinatorID]
    if history == nil {
        return &ExclusionStatus{IsExcluded: false}
    }

    isExcluded := time.Now().Before(history.ExcludedUntil)
    var remainingTime time.Duration
    if isExcluded {
        remainingTime = time.Until(history.ExcludedUntil)
    }

    return &ExclusionStatus{
        IsExcluded:      isExcluded,
        ExcludedUntil:   history.ExcludedUntil,
        RemainingTime:   remainingTime,
        ExclusionCount:  history.ExclusionCount,
        RecentTriggers:  len(history.RecentTriggers),
        TotalTriggers:   history.TotalTriggers,
    }
}

type ExclusionStatus struct {
    IsExcluded      bool
    ExcludedUntil   time.Time
    RemainingTime   time.Duration
    ExclusionCount  int
    RecentTriggers  int
    TotalTriggers   uint64
}
```

#### Integration with Coordinator Selection

```go
// FilterExcludedCandidates removes excluded coordinators from selection pool
func (selector *CoordinatorSelector) FilterExcludedCandidates(
    candidates []Node,
    tracker *ViewChangeTriggerTracker,
) []Node {
    filtered := make([]Node, 0, len(candidates))

    for _, candidate := range candidates {
        if !tracker.IsExcluded(candidate.ID) {
            filtered = append(filtered, candidate)
        } else {
            selector.logger.Info("coordinator excluded from selection",
                "node_id", candidate.ID,
                "status", tracker.GetExclusionStatus(candidate.ID))
        }
    }

    return filtered
}
```

**View Change Trigger Exclusion Table:**

| Trigger Count (1 hour) | Exclusion Duration | Progressive Multiplier |
|------------------------|-------------------|----------------------|
| 1 trigger | Warning only | None |
| 2 triggers | 3 selection rounds | 1x |
| 3+ triggers | 6 selection rounds | 2x |
| 4+ triggers | 12 selection rounds | 4x |
| 5+ triggers | 24 selection rounds (max) | 8x (capped) |
| Malicious trigger | 24 selection rounds | Immediate max |

**Attack Prevention Properties:**

| Attack Type | Detection | Response |
|-------------|-----------|----------|
| **Repeated Timeouts** | 2+ triggers in 1 hour | Progressive exclusion |
| **Intentional Slowness** | Latency tracking + trigger | Combined exclusion |
| **Equivocation** | Malicious flag in trigger | Immediate max exclusion |
| **Sybil View Changes** | Multiple node triggers | Each node tracked separately |
| **Rotation Abuse** | Trigger after each rotation | Progressive escalation |

---

### C11: VRF Seed Predictability Mitigation

Miners with significant resources could grind VRF inputs to achieve favorable selection outcomes. This section implements commit-reveal schemes and multi-party seed generation to ensure VRF unpredictability.

#### Problem Statement

VRF grinding attack:
1. Attacker controls timing of operations that generate VRF seeds
2. Attacker tries many timestamp values to find favorable VRF output
3. With enough computation, attacker increases selection probability

#### Commit-Reveal VRF Seed Generation

Two-phase commit-reveal ensures seed is unknown until all participants commit:

```go
// CommitRevealVRFSeed implements secure VRF seed generation
type CommitRevealVRFSeed struct {
    round           uint64
    commitPhase     *CommitPhase
    revealPhase     *RevealPhase
    finalSeed       [32]byte
    participants    map[NodeID]ParticipantState
    minParticipants int
    commitDeadline  time.Time
    revealDeadline  time.Time
}

// CommitPhase collects entropy commitments
type CommitPhase struct {
    commits      map[NodeID][32]byte // SHA256(entropy || nonce || nodeID)
    commitOrder  []NodeID            // Order commits received
    deadline     time.Time
}

// RevealPhase collects entropy reveals
type RevealPhase struct {
    reveals      map[NodeID]*VRFReveal
    validated    map[NodeID]bool
    deadline     time.Time
}

// VRFReveal contains revealed entropy with proof
type VRFReveal struct {
    Entropy       []byte    // Random bytes from TPM RNG
    Nonce         []byte    // Prevents replay
    NodeID        NodeID    // Revealer identity
    TPMSignature  []byte    // TPM signature proving entropy source
    TPMQuote      []byte    // TPM quote with PCR values
    Timestamp     int64     // When entropy was generated
}

// ParticipantState tracks participant in seed generation
type ParticipantState uint8

const (
    ParticipantPending  ParticipantState = iota
    ParticipantCommitted
    ParticipantRevealed
    ParticipantSlashed  // Failed to reveal
)

// VRFSeedGenerator orchestrates commit-reveal process
type VRFSeedGenerator struct {
    commitWindow   time.Duration // 30 seconds for commits
    revealWindow   time.Duration // 30 seconds for reveals
    minParticipants int          // Minimum valid participants
    currentRound   *CommitRevealVRFSeed
}

// StartSeedGeneration begins new VRF seed generation round
func (vsg *VRFSeedGenerator) StartSeedGeneration(ctx context.Context) error {
    round := &CommitRevealVRFSeed{
        round:           vsg.getNextRoundNumber(),
        commitPhase:     &CommitPhase{
            commits:     make(map[NodeID][32]byte),
            commitOrder: make([]NodeID, 0),
            deadline:    time.Now().Add(vsg.commitWindow),
        },
        participants:    make(map[NodeID]ParticipantState),
        minParticipants: vsg.minParticipants,
        commitDeadline:  time.Now().Add(vsg.commitWindow),
        revealDeadline:  time.Now().Add(vsg.commitWindow + vsg.revealWindow),
    }

    vsg.currentRound = round

    // Broadcast round start
    announcement := &SeedRoundAnnouncement{
        Round:          round.round,
        CommitDeadline: round.commitDeadline,
        RevealDeadline: round.revealDeadline,
    }
    broadcastSeedRoundStart(announcement)

    // Phase 1: Collect commits
    if err := vsg.collectCommits(ctx, round); err != nil {
        return fmt.Errorf("commit phase: %w", err)
    }

    // Phase 2: Collect reveals
    if err := vsg.collectReveals(ctx, round); err != nil {
        return fmt.Errorf("reveal phase: %w", err)
    }

    // Phase 3: Compute final seed
    return vsg.computeFinalSeed(round)
}

// collectCommits handles commit phase
func (vsg *VRFSeedGenerator) collectCommits(
    ctx context.Context,
    round *CommitRevealVRFSeed,
) error {
    deadline := time.After(time.Until(round.commitDeadline))

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-deadline:
            // Commit phase ended
            if len(round.commitPhase.commits) < vsg.minParticipants {
                return &ErrInsufficientCommits{
                    Required: vsg.minParticipants,
                    Received: len(round.commitPhase.commits),
                }
            }
            return nil
        case commit := <-vsg.commitChannel:
            if err := vsg.processCommit(round, commit); err != nil {
                // Log but don't fail - continue collecting
                logCommitError(commit.NodeID, err)
            }
        }
    }
}

// processCommit validates and records a commit
func (vsg *VRFSeedGenerator) processCommit(
    round *CommitRevealVRFSeed,
    commit *EntropyCommit,
) error {
    // Verify node is eligible to participate
    if !isCoordinatorTier(commit.NodeID) {
        return ErrNotCoordinatorTier
    }

    // Verify no duplicate commit
    if _, exists := round.commitPhase.commits[commit.NodeID]; exists {
        return ErrDuplicateCommit
    }

    // Verify commit signature
    if !verifyCommitSignature(commit) {
        return ErrInvalidCommitSignature
    }

    // Record commit
    round.commitPhase.commits[commit.NodeID] = commit.CommitHash
    round.commitPhase.commitOrder = append(round.commitPhase.commitOrder, commit.NodeID)
    round.participants[commit.NodeID] = ParticipantCommitted

    return nil
}

// collectReveals handles reveal phase
func (vsg *VRFSeedGenerator) collectReveals(
    ctx context.Context,
    round *CommitRevealVRFSeed,
) error {
    round.revealPhase = &RevealPhase{
        reveals:   make(map[NodeID]*VRFReveal),
        validated: make(map[NodeID]bool),
        deadline:  round.revealDeadline,
    }

    deadline := time.After(time.Until(round.revealDeadline))

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-deadline:
            // Reveal phase ended - slash non-revealers
            vsg.slashNonRevealers(round)
            return nil
        case reveal := <-vsg.revealChannel:
            if err := vsg.processReveal(round, reveal); err != nil {
                logRevealError(reveal.NodeID, err)
            }
        }
    }
}

// processReveal validates reveal matches commit
func (vsg *VRFSeedGenerator) processReveal(
    round *CommitRevealVRFSeed,
    reveal *VRFReveal,
) error {
    // Verify node committed
    commit, exists := round.commitPhase.commits[reveal.NodeID]
    if !exists {
        return ErrNoCommitForReveal
    }

    // Verify reveal matches commit
    expectedCommit := computeCommitHash(reveal.Entropy, reveal.Nonce, reveal.NodeID)
    if expectedCommit != commit {
        // Slash for invalid reveal
        slashNode(reveal.NodeID, SlashReasonRevealMismatch, 0.05)
        round.participants[reveal.NodeID] = ParticipantSlashed
        return ErrRevealMismatch
    }

    // Verify TPM signature on entropy
    if !verifyTPMEntropySignature(reveal) {
        slashNode(reveal.NodeID, SlashReasonInvalidTPMSig, 0.05)
        round.participants[reveal.NodeID] = ParticipantSlashed
        return ErrInvalidTPMSignature
    }

    // Verify TPM quote (entropy was generated on valid TPM)
    if !verifyTPMQuote(reveal) {
        slashNode(reveal.NodeID, SlashReasonInvalidTPMQuote, 0.05)
        round.participants[reveal.NodeID] = ParticipantSlashed
        return ErrInvalidTPMQuote
    }

    // Valid reveal
    round.revealPhase.reveals[reveal.NodeID] = reveal
    round.revealPhase.validated[reveal.NodeID] = true
    round.participants[reveal.NodeID] = ParticipantRevealed

    return nil
}

// slashNonRevealers penalizes nodes that committed but didn't reveal
func (vsg *VRFSeedGenerator) slashNonRevealers(round *CommitRevealVRFSeed) {
    for nodeID, state := range round.participants {
        if state == ParticipantCommitted {
            // Committed but didn't reveal
            slashNode(nodeID, SlashReasonCommitWithoutReveal, 0.05)
            round.participants[nodeID] = ParticipantSlashed
        }
    }
}

// computeFinalSeed combines all valid reveals into final seed
func (vsg *VRFSeedGenerator) computeFinalSeed(round *CommitRevealVRFSeed) error {
    validReveals := make([]*VRFReveal, 0)
    for _, reveal := range round.revealPhase.reveals {
        if round.revealPhase.validated[reveal.NodeID] {
            validReveals = append(validReveals, reveal)
        }
    }

    if len(validReveals) < vsg.minParticipants {
        return &ErrInsufficientReveals{
            Required: vsg.minParticipants,
            Valid:    len(validReveals),
        }
    }

    // XOR all entropy contributions
    // Even if n-1 participants collude, 1 honest participant makes seed unpredictable
    var seed [32]byte
    for _, reveal := range validReveals {
        entropyHash := sha256.Sum256(reveal.Entropy)
        for i := range seed {
            seed[i] ^= entropyHash[i]
        }
    }

    // Add round number to prevent replay
    roundBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(roundBytes, round.round)
    finalHash := sha256.Sum256(append(seed[:], roundBytes...))

    round.finalSeed = finalHash
    return nil
}

// computeCommitHash creates commitment hash
func computeCommitHash(entropy, nonce []byte, nodeID NodeID) [32]byte {
    h := sha256.New()
    h.Write(entropy)
    h.Write(nonce)
    h.Write(nodeID[:])
    var hash [32]byte
    copy(hash[:], h.Sum(nil))
    return hash
}
```

#### Multi-Party Seed Generation

For additional security, seeds can require contributions from multiple independent parties:

```go
// MultiPartySeedGeneration requires contributions from diverse sources
type MultiPartySeedGeneration struct {
    requiredParties   int              // Minimum parties required
    partyCategories   []PartyCategory  // Required diversity
    contributions     map[PartyCategory][]*PartyContribution
}

// PartyCategory represents a class of seed contributors
type PartyCategory uint8

const (
    CategoryValidatorNode  PartyCategory = iota
    CategoryArchiveNode
    CategoryExternalOracle // External randomness beacons
    CategoryTPMAttestation // TPM-derived entropy
)

// PartyContribution is entropy from a specific party type
type PartyContribution struct {
    Category     PartyCategory
    SourceID     string // Node ID or oracle identifier
    Entropy      []byte
    Proof        []byte // Category-specific proof
    Timestamp    int64
}

// GenerateMultiPartySeed creates seed from diverse sources
func (mpsg *MultiPartySeedGeneration) GenerateMultiPartySeed(
    ctx context.Context,
) ([32]byte, error) {
    var seed [32]byte

    // Collect from each required category
    for _, category := range mpsg.partyCategories {
        contribution, err := mpsg.collectFromCategory(ctx, category)
        if err != nil {
            return seed, fmt.Errorf("collecting from %v: %w", category, err)
        }

        // XOR contribution into seed
        entropyHash := sha256.Sum256(contribution.Entropy)
        for i := range seed {
            seed[i] ^= entropyHash[i]
        }
    }

    // Add timestamp and category info
    finalHash := sha256.Sum256(append(seed[:], mpsg.getCategoryDigest()...))
    return finalHash, nil
}

// collectFromCategory gets entropy from specific party type
func (mpsg *MultiPartySeedGeneration) collectFromCategory(
    ctx context.Context,
    category PartyCategory,
) (*PartyContribution, error) {
    switch category {
    case CategoryValidatorNode:
        return mpsg.collectValidatorEntropy(ctx)
    case CategoryArchiveNode:
        return mpsg.collectArchiveEntropy(ctx)
    case CategoryExternalOracle:
        return mpsg.collectOracleEntropy(ctx)
    case CategoryTPMAttestation:
        return mpsg.collectTPMEntropy(ctx)
    default:
        return nil, ErrUnknownPartyCategory
    }
}

// collectOracleEntropy gets randomness from external beacons
func (mpsg *MultiPartySeedGeneration) collectOracleEntropy(
    ctx context.Context,
) (*PartyContribution, error) {
    // Query multiple randomness beacons
    beacons := []RandomnessBeacon{
        &DrandBeacon{},       // drand.love
        &CloudflareBeacon{},  // Cloudflare drand
        &LeagueOfEntropy{},   // League of Entropy
    }

    var combinedEntropy []byte
    proofs := make([][]byte, 0)

    for _, beacon := range beacons {
        result, err := beacon.GetRandomness(ctx)
        if err != nil {
            continue // Try next beacon
        }

        if !beacon.VerifyRandomness(result) {
            continue // Invalid proof
        }

        combinedEntropy = append(combinedEntropy, result.Randomness...)
        proofs = append(proofs, result.Proof)
    }

    if len(proofs) < 2 {
        return nil, ErrInsufficientOracleResponses
    }

    return &PartyContribution{
        Category:  CategoryExternalOracle,
        SourceID:  "multi-beacon",
        Entropy:   combinedEntropy,
        Proof:     combineProofs(proofs),
        Timestamp: time.Now().Unix(),
    }, nil
}
```

#### VRF Grinding Prevention Properties

| Property | Mechanism | Security Guarantee |
|----------|-----------|-------------------|
| **Commit Binding** | SHA256 commitment | Cannot change entropy after commit |
| **Reveal Verification** | TPM signature + quote | Entropy genuinely from TPM RNG |
| **Single Honest** | XOR combination | 1 honest participant ensures randomness |
| **Grinding Infeasible** | Commit before seed known | Cannot try different inputs |
| **Multi-Source** | External beacons | Independent of network participants |
| **Slashing** | 5% penalty for misbehavior | Economic disincentive for attacks |

#### Commit-Reveal Timeline

| Phase | Duration | Action |
|-------|----------|--------|
| Announce | 0s | Broadcast round start |
| Commit Window | 0-60s | Participants submit commits |
| Reveal Window | 60-120s | Participants submit reveals |
| Slash Window | 120-125s | Penalize non-revealers |
| Finalization | 125-130s | Compute and broadcast final seed |
| **Total** | **~130s** | New seed available |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 3.2 | 2026-01-10 | Added advanced consensus mechanisms: VRF commit-reveal scheme (30s windows, 2-block gap), Coordinator fencing tokens (15-of-21 quorum, atomic DHT publication), Partition-aware PBFT (48%/52% thresholds, read-only mode, timeout escalation 500ms-10s), Partition recovery protocol (vector clocks, DHT discovery, 60s merge timeout), Coordinator performance tracking (progressive exclusion for view change triggers) |
| 3.1 | 2026-01-10 | Added FINAL DESIGN specifications: VRF selection edge cases (key rotation, compromise handling, diversity fallback), Byzantine primary detection (equivocation, message deduplication), View change DKG handling (abort protocol, checkpoint reconciliation), Partition recovery (quorum loss detection, minority partition behavior, reconstitution protocol) |
| 3.0 | 2026-01-09 | Architecture complete, ready for implementation |

---

## References

1. RFC 9381 - Verifiable Random Functions (ECVRF-ED25519-SHA512-Elligator2)
2. "Practical Byzantine Fault Tolerance" - Castro & Liskov, 1999
3. "The Byzantine Generals Problem" - Lamport et al., 1982
4. TPM 2.0 Library Specification, Trusted Computing Group
5. go-frostdkg - RFC 9591 compliant FROST DKG implementation
6. "Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain" - Bernardo et al., 2017
7. "RANDAO: A Decentralized Random Number Generator" - Ethereum Foundation
8. drand: Distributed Randomness Beacon - https://drand.love

**Related Documents:**
- [03-security-trust.md](03-security-trust.md) - Security constants and threat model
- [04-cryptographic-protocols.md](04-cryptographic-protocols.md) - FROST/go-frostdkg protocols
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation thresholds and tiers

---

**Status**: Architecture complete with FINAL DESIGN specifications, ready for implementation
**Last Updated**: 2026-01-10
**Version**: 3.2

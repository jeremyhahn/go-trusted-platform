# Governance and Economics

This document consolidates the governance, economic, and privacy models for go-trusted-platform, covering upgrade mechanisms, free market pricing, gateway incentives, and optional privacy features.

## Table of Contents

1. [Upgrade Governance](#upgrade-governance)
2. [Economic Model](#economic-model)
3. [Gateway Incentives](#gateway-incentives)
4. [Privacy Model](#privacy-model)
5. [Penalty Enforcement System](#penalty-enforcement-system)
6. [Economic Attack Mitigations](#economic-attack-mitigations)

---

## Upgrade Governance

The upgrade and governance system balances decentralization with practical upgrade mechanisms, combining community-driven feature development through crowdfunded voting with a hybrid activation strategy.

### Core Principles

- **Community-Funded Development**: Features funded by community voting with coins
- **Predictable Upgrades**: Hybrid activation prevents indefinite delays
- **No Chain Splits**: Strict upgrade policy forces compatibility
- **Transparent Process**: All proposals, votes, and funding flows are public
- **Emergency Response**: Critical security fixes can be fast-tracked

### Semantic Versioning

The protocol follows Semantic Versioning (SemVer):

```
MAJOR.MINOR.PATCH
  |     |     |
  |     |     +-- Bug fixes, security patches (backward compatible)
  |     +-------- New features (backward compatible)
  +-------------- Breaking changes (requires hard fork)
```

All network messages include a protocol version header:

```go
type ProtocolVersion struct {
    Major uint16  // Breaking changes
    Minor uint16  // Features
    Patch uint16  // Fixes
}
```

**Support Policy:**
- MAJOR version: Current only (no backward compatibility)
- MINOR versions: Current + previous 2 versions
- PATCH versions: Latest within MINOR version

### Proposal Process

#### Stage 1: Submission

Proposals require:
- Title and description
- Technical specification
- Cost estimate in coins
- Expected timeline
- Small submission fee (spam prevention)
- Well-defined success criteria

#### Stage 2: Technical Review (14 days maximum)

Foundation review includes:
- Technical feasibility assessment
- Security impact analysis
- Compatibility considerations
- Cost estimate validation

Outcomes: Approved, Rejected, or Needs Revision.

#### Stage 3: Community Voting (30 days)

Voting opens with proposal listing. Early close allowed if 90% threshold met. Extension by 15 days allowed if close vote.

#### Stage 4: Outcome Determination

**If Approved (>67% YES, funding met):**
- Implementation phase begins
- Funds allocated to implementers via milestones

**If Rejected (<67% YES or insufficient funding):**
- Proposal archived
- Voted coins go to Treasury
- Resubmission allowed after 90 days

#### Stage 5: Implementation

Milestone-based payment schedule:
- 20% upon approval (kickoff)
- 30% at 50% completion
- 30% at 90% completion
- 20% upon successful activation

#### Stage 6: Activation

Pre-activation includes binary releases, activation block height, and 90-day signaling period.

### Crowdfunded Voting Mechanism

**Voting with Coins:**
- YES vote: Send coins to proposal's YES address
- NO vote: Send coins to proposal's NO address
- Vote weight = Amount of coins sent
- Coins fund actual development work (not locked or burned)

```go
type ProposalAddresses struct {
    ProposalID    string
    YesAddress    string  // Unique address for YES votes
    NoAddress     string  // Unique address for NO votes
    TreasuryAddr  string  // Fallback for rejected proposals
}
```

**Voting Thresholds:**

| Threshold | Requirement |
|-----------|-------------|
| Minimum Funding | Total Voted Coins >= Cost Estimate |
| Approval Supermajority | YES / (YES + NO) >= 0.67 |
| Participation | Total Voted >= 0.01% of Circulating Supply |

### Snapshot Voting Model (CANONICAL)

To prevent double-voting across proposals and manipulation through coin acquisition after proposal announcement, the protocol uses snapshot-based voting power calculation.

#### Snapshot Creation

When a proposal is submitted, a snapshot of all wallet balances is captured at a **FINALIZED** block height (not merely confirmed). Finalized blocks have achieved irreversibility through sufficient confirmations and cannot be reorganized.

```go
// ProposalSnapshot captures balances at proposal creation time
type ProposalSnapshot struct {
    ProposalID      string              // Unique proposal identifier
    SnapshotHeight  uint64              // Block height at proposal creation (MUST be finalized)
    SnapshotTime    time.Time           // Timestamp of snapshot
    BalanceRoot     [32]byte            // Merkle root of all balances
    TotalSupply     uint64              // Total circulating supply at snapshot
    ParticipantCount uint64             // Number of wallets with balance > 0
    FinalityProof   []byte              // Proof that snapshot block is finalized
}

// SnapshotBalance represents a wallet's balance at snapshot time
type SnapshotBalance struct {
    WalletID        WalletID            // Wallet identifier
    Balance         uint64              // Balance at snapshot height (finalized)
    ProofPath       [][]byte            // Merkle proof path to root
}

// VoteEligibility contains TPM-attested proof of voting eligibility
type VoteEligibility struct {
    WalletID        WalletID            // Voter's wallet identifier
    NodeID          [32]byte            // TPM-bound node identity
    SnapshotBlock   uint64              // Finalized block for balance lookup
    Balance         uint64              // Balance at snapshot (voting weight)
    Signature       []byte              // TPM-signed attestation binding wallet to node
}

// VerifyVoteEligibility validates TPM binding before accepting vote
func VerifyVoteEligibility(eligibility *VoteEligibility, snapshot *ProposalSnapshot) error {
    // Verify snapshot block is finalized
    if !IsBlockFinalized(eligibility.SnapshotBlock) {
        return ErrSnapshotBlockNotFinalized
    }

    // Verify snapshot block matches proposal snapshot
    if eligibility.SnapshotBlock != snapshot.SnapshotHeight {
        return ErrSnapshotBlockMismatch
    }

    // Verify TPM attestation binds wallet to node
    attestationData := computeAttestationData(eligibility.WalletID, eligibility.NodeID, eligibility.SnapshotBlock)
    if !VerifyTPMSignature(eligibility.NodeID, attestationData, eligibility.Signature) {
        return ErrInvalidTPMBinding
    }

    // Verify balance from finalized block state
    actualBalance, proof, err := GetFinalizedBalance(eligibility.WalletID, eligibility.SnapshotBlock)
    if err != nil {
        return err
    }

    if eligibility.Balance != actualBalance {
        return &ErrBalanceMismatch{
            Claimed: eligibility.Balance,
            Actual:  actualBalance,
        }
    }

    // Verify Merkle proof against snapshot root
    if !VerifyBalanceProof(eligibility.WalletID, actualBalance, proof, snapshot.BalanceRoot) {
        return ErrInvalidBalanceProof
    }

    return nil
}
```

#### Voting Power Calculation

Voting power is determined ONLY by balance at snapshot time, not current balance:

```go
// Vote represents a cast vote with snapshot-based weight
type Vote struct {
    ProposalID      string              // Proposal being voted on
    VoterWallet     WalletID            // Voter's wallet ID
    Choice          VoteChoice          // YES, NO, ABSTAIN
    Weight          uint64              // Balance at snapshot time (NOT current)
    SnapshotProof   [][]byte            // Merkle proof of balance at snapshot
    Signature       []byte              // Wallet signature over vote
    TPMQuote        []byte              // TPM attestation of voter identity
    Timestamp       int64               // When vote was cast
}

type VoteChoice uint8
const (
    VoteYes     VoteChoice = 1
    VoteNo      VoteChoice = 2
    VoteAbstain VoteChoice = 3
)

// GetVotingPower returns voting power from snapshot (not current balance)
func GetVotingPower(voter WalletID, snapshot *ProposalSnapshot) (uint64, error) {
    // Retrieve balance from snapshot Merkle tree
    balance, proof, err := GetSnapshotBalance(snapshot.SnapshotHeight, voter)
    if err != nil {
        return 0, err
    }

    // Verify Merkle proof against snapshot root
    if !VerifyBalanceProof(voter, balance, proof, snapshot.BalanceRoot) {
        return 0, ErrInvalidBalanceProof
    }

    return balance, nil
}

// VerifyVote validates a vote against snapshot
func VerifyVote(vote *Vote, snapshot *ProposalSnapshot) error {
    // Verify weight matches snapshot balance
    actualWeight, err := GetVotingPower(vote.VoterWallet, snapshot)
    if err != nil {
        return err
    }
    if vote.Weight != actualWeight {
        return &ErrWeightMismatch{
            Claimed: vote.Weight,
            Actual:  actualWeight,
        }
    }

    // Verify signature
    voteData := computeVoteHash(vote)
    if !VerifyWalletSignature(vote.VoterWallet, voteData, vote.Signature) {
        return ErrInvalidVoteSignature
    }

    // Verify TPM attestation (prevents impersonation)
    if !VerifyTPMQuote(vote.VoterWallet, vote.TPMQuote) {
        return ErrInvalidTPMQuote
    }

    return nil
}
```

#### Double-Vote Prevention

Each wallet can only vote ONCE per proposal. The protocol uses **atomic Compare-And-Swap (CAS)** operations combined with **database unique constraints** to prevent race conditions and ensure exactly-once voting semantics.

```go
// VoteRegistry tracks votes per proposal with atomic operations
type VoteRegistry struct {
    ProposalID    string
    Votes         map[WalletID]*Vote  // One vote per wallet
    TotalYes      uint64              // Sum of YES vote weights
    TotalNo       uint64              // Sum of NO vote weights
    TotalAbstain  uint64              // Sum of ABSTAIN weights
    VoterCount    uint64              // Number of unique voters
}

// VoteRecord represents the database schema for vote storage
// Database table has UNIQUE constraint on (proposal_id, wallet_id)
type VoteRecord struct {
    VoteKey     [32]byte            // hash(proposalID, walletID) - primary key
    ProposalID  string              // Proposal identifier
    WalletID    WalletID            // Voter wallet (unique per proposal)
    Choice      VoteChoice          // YES, NO, ABSTAIN
    Weight      uint64              // Voting power at snapshot
    Timestamp   int64               // Vote timestamp
    Signature   []byte              // Vote signature
}

// ComputeVoteKey generates deterministic key for vote deduplication
func ComputeVoteKey(proposalID string, walletID WalletID) [32]byte {
    data := append([]byte(proposalID), walletID[:]...)
    return sha256.Sum256(data)
}

// CastVoteAtomic records a vote using atomic CAS with database constraint
func (r *VoteRegistry) CastVoteAtomic(vote *Vote, snapshot *ProposalSnapshot, db VoteDatabase) error {
    // Compute unique vote key: hash(proposalID, walletID)
    voteKey := ComputeVoteKey(vote.ProposalID, vote.VoterWallet)

    // Verify vote against snapshot before attempting insert
    if err := VerifyVote(vote, snapshot); err != nil {
        return err
    }

    // Create vote record for database
    record := &VoteRecord{
        VoteKey:    voteKey,
        ProposalID: vote.ProposalID,
        WalletID:   vote.VoterWallet,
        Choice:     vote.Choice,
        Weight:     vote.Weight,
        Timestamp:  vote.Timestamp,
        Signature:  vote.Signature,
    }

    // Atomic INSERT with unique constraint on voteKey
    // Database enforces: UNIQUE(proposal_id, wallet_id)
    // Returns ErrAlreadyVoted on duplicate key violation
    err := db.InsertVoteAtomic(record)
    if err != nil {
        if IsDuplicateKeyError(err) {
            // Fetch existing vote for error context
            existing, _ := db.GetVote(voteKey)
            return &ErrAlreadyVoted{
                WalletID:     vote.VoterWallet,
                ExistingVote: existing.Choice,
                VotedAt:      existing.Timestamp,
            }
        }
        return err
    }

    // Update in-memory tallies using atomic operations
    r.updateTalliesAtomic(vote)

    return nil
}

// updateTalliesAtomic updates vote tallies using lock-free atomic operations
func (r *VoteRegistry) updateTalliesAtomic(vote *Vote) {
    atomic.AddUint64(&r.VoterCount, 1)

    switch vote.Choice {
    case VoteYes:
        atomic.AddUint64(&r.TotalYes, vote.Weight)
    case VoteNo:
        atomic.AddUint64(&r.TotalNo, vote.Weight)
    case VoteAbstain:
        atomic.AddUint64(&r.TotalAbstain, vote.Weight)
    }
}

// VoteDatabase interface for atomic vote storage
type VoteDatabase interface {
    // InsertVoteAtomic atomically inserts vote, returns error on duplicate
    InsertVoteAtomic(record *VoteRecord) error
    // GetVote retrieves existing vote by key
    GetVote(voteKey [32]byte) (*VoteRecord, error)
}

// SQL schema for vote table with unique constraint
// CREATE TABLE votes (
//     vote_key     BYTEA PRIMARY KEY,           -- hash(proposal_id, wallet_id)
//     proposal_id  VARCHAR(64) NOT NULL,
//     wallet_id    BYTEA NOT NULL,
//     choice       SMALLINT NOT NULL,
//     weight       BIGINT NOT NULL,
//     timestamp    BIGINT NOT NULL,
//     signature    BYTEA NOT NULL,
//     UNIQUE(proposal_id, wallet_id)            -- Prevents double-voting
// );
```

#### Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **No Double-Voting** | Each wallet votes once per proposal | VoteRegistry map |
| **No Post-Announcement Manipulation** | Cannot acquire coins after proposal | Snapshot at proposal creation |
| **Verifiable Weight** | Anyone can verify voting power | Merkle proofs against snapshot root |
| **Coin Mobility** | Coins can be transferred after snapshot | Voting power frozen at snapshot |
| **Sybil Resistance** | Cannot split coins across wallets post-snapshot | Balance fixed at snapshot time |

#### Attack Prevention

| Attack | Without Snapshot | With Snapshot Voting |
|--------|------------------|----------------------|
| Double-voting across proposals | Possible (same coins vote on A and B) | Prevented (separate snapshot per proposal) |
| Acquiring coins after proposal | Can buy votes after seeing proposal | No effect (snapshot already taken) |
| Flash loan attack | Borrow coins, vote, return | Cannot (snapshot before proposal known) |
| Coin shuffling for multiple votes | Split to wallets, vote each | No effect (total balance same at snapshot) |

### Flash Loan Attack Prevention (E10 - CANONICAL)

Flash loan attacks on governance involve borrowing large amounts of coins, voting on proposals, and returning the coins in the same transaction or block. The protocol prevents this through mandatory **72-hour lockup periods**, source allowlisting, and sudden balance increase detection.

#### Voting Lockup Requirements

```go
// VotingLockup defines lockup requirements for governance participation
type VotingLockup struct {
    // Minimum time coins must be held before snapshot to count (CANONICAL: 72 hours)
    PreSnapshotHoldingPeriod time.Duration // Default: 72 hours (3 days)
    // Minimum time coins must remain locked after voting
    PostVoteUnlockDelay      time.Duration // Default: 3 days
    // Block confirmations required before balance counts
    MinConfirmations         uint64        // Default: 100 blocks
    // Allowlisted sources for legitimate balance increases
    AllowlistedSources       []SourceType  // Mining, staking rewards
    // Threshold for sudden balance increase detection
    SuddenIncreaseMultiplier uint64        // Default: 10 (10x within 24 hours)
    // Window for sudden increase detection
    SuddenIncreaseWindow     time.Duration // Default: 24 hours
}

// SourceType identifies the origin of balance changes
type SourceType uint8
const (
    SourceUnknown       SourceType = 0
    SourceMiningReward  SourceType = 1  // Block mining rewards
    SourceStakingReward SourceType = 2  // Staking/validation rewards
    SourceTransfer      SourceType = 3  // Standard transfer
    SourceExchange      SourceType = 4  // Exchange withdrawal
    SourceContract      SourceType = 5  // Smart contract interaction
)

// DefaultVotingLockup returns production lockup parameters (E10 hardened)
func DefaultVotingLockup() VotingLockup {
    return VotingLockup{
        PreSnapshotHoldingPeriod: 72 * time.Hour,      // 72 hours (CANONICAL)
        PostVoteUnlockDelay:      3 * 24 * time.Hour,  // 3 days
        MinConfirmations:         100,                  // ~100 blocks
        AllowlistedSources:       []SourceType{SourceMiningReward, SourceStakingReward},
        SuddenIncreaseMultiplier: 10,                  // 10x increase triggers review
        SuddenIncreaseWindow:     24 * time.Hour,      // Within 24 hours
    }
}

// CalculateEligibleBalance computes voting-eligible balance with source verification
func CalculateEligibleBalance(
    wallet WalletID,
    snapshotHeight uint64,
    lockup VotingLockup,
) (uint64, error) {
    var eligibleBalance uint64

    // Get all UTXOs for wallet at snapshot height
    utxos := GetWalletUTXOs(wallet, snapshotHeight)

    for _, utxo := range utxos {
        // Check if UTXO existed for required holding period (72 hours)
        utxoAge := snapshotHeight - utxo.CreatedAtHeight
        minAgeBlocks := uint64(lockup.PreSnapshotHoldingPeriod / AverageBlockTime)

        if utxoAge < minAgeBlocks {
            // UTXO too new - does not count for voting
            continue
        }

        if utxo.Confirmations < lockup.MinConfirmations {
            // Insufficient confirmations
            continue
        }

        // Verify source is allowlisted (mining/staking) or has met holding period
        if !isAllowlistedSource(utxo.SourceType, lockup.AllowlistedSources) {
            // Non-allowlisted sources must meet full 72-hour holding period
            if utxoAge < minAgeBlocks {
                continue
            }
        }

        eligibleBalance += utxo.Amount
    }

    return eligibleBalance, nil
}

// isAllowlistedSource checks if source type is in allowlist
func isAllowlistedSource(source SourceType, allowlist []SourceType) bool {
    for _, allowed := range allowlist {
        if source == allowed {
            return true
        }
    }
    return false
}
```

#### Lockup Enforcement

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Pre-snapshot holding | **72 hours** (CANONICAL) | Prevents flash loans (loans typically < 1 block) |
| Post-vote unlock | 3 days | Prevents vote-and-dump manipulation |
| Min confirmations | 100 blocks | Ensures finality, prevents reorg attacks |
| Lockup penalty for early withdrawal | 10% of locked amount | Economic disincentive |
| Allowlisted sources | Mining, Staking rewards | Legitimate reward accrual exempt from pattern detection |
| Sudden increase threshold | 10x within 24 hours | Triggers flash loan pattern alert |

#### Flash Loan Detection

The protocol detects flash loan patterns by monitoring for sudden large balance increases (greater than 10x within 24 hours) and blocking votes from addresses exhibiting flash loan behavior.

```go
// FlashLoanDetector identifies potential flash loan patterns
type FlashLoanDetector struct {
    // Suspicious if balance increased by more than this multiplier in detection window
    // Using integer multiplier to avoid floating-point rounding issues
    SuspiciousIncreaseMultiplier uint64  // Default: 10 (10x increase)
    // Detection window for sudden increases
    DetectionWindow              time.Duration // Default: 24 hours
    // Minimum absolute increase to trigger detection
    MinSuspiciousAmount          uint64  // Default: 100,000 coins
    // Allowlisted source types exempt from detection
    AllowlistedSources           []SourceType
}

// DefaultFlashLoanDetector returns production detection parameters
func DefaultFlashLoanDetector() FlashLoanDetector {
    return FlashLoanDetector{
        SuspiciousIncreaseMultiplier: 10,                // 10x (>1000% increase)
        DetectionWindow:              24 * time.Hour,    // Within 24 hours
        MinSuspiciousAmount:          100000,            // 100,000 coins minimum
        AllowlistedSources:           []SourceType{SourceMiningReward, SourceStakingReward},
    }
}

// FlashLoanAlert contains details of detected flash loan pattern
type FlashLoanAlert struct {
    Wallet          WalletID
    StartBalance    uint64
    EndBalance      uint64
    IncreaseRatio   uint64    // Integer ratio (e.g., 10 = 10x increase)
    DetectionWindow time.Duration
    Reason          string
    BlockedFromVote bool
    Sources         []SourceType
}

// DetectFlashLoanPattern checks for suspicious balance patterns
func (d *FlashLoanDetector) DetectFlashLoanPattern(
    wallet WalletID,
    snapshotHeight uint64,
    snapshotTime time.Time,
) (*FlashLoanAlert, error) {
    // Calculate window start (24 hours before snapshot)
    windowStartTime := snapshotTime.Add(-d.DetectionWindow)
    windowStartHeight := EstimateBlockHeight(windowStartTime)

    // Get balance at start of detection window
    startBalance := GetBalanceAtHeight(wallet, windowStartHeight)

    // Get balance at snapshot
    snapshotBalance := GetBalanceAtHeight(wallet, snapshotHeight)

    // Get transaction sources in the window
    txSources := GetTransactionSources(wallet, windowStartHeight, snapshotHeight)

    // Check if all increases are from allowlisted sources
    if allSourcesAllowlisted(txSources, d.AllowlistedSources) {
        return nil, nil // Legitimate reward accrual, not flash loan
    }

    // Detect new wallet with large balance
    if startBalance == 0 {
        if snapshotBalance >= d.MinSuspiciousAmount {
            return &FlashLoanAlert{
                Wallet:          wallet,
                StartBalance:    startBalance,
                EndBalance:      snapshotBalance,
                IncreaseRatio:   0, // Infinite (from zero)
                DetectionWindow: d.DetectionWindow,
                Reason:          "New wallet with large balance within 24 hours",
                BlockedFromVote: true,
                Sources:         txSources,
            }, nil
        }
        return nil, nil
    }

    // Calculate increase ratio using integer arithmetic (avoid floating-point)
    // increaseRatio = snapshotBalance / startBalance
    increaseRatio := snapshotBalance / startBalance
    absoluteIncrease := snapshotBalance - startBalance

    // Check if increase exceeds threshold (10x within 24 hours)
    if increaseRatio >= d.SuspiciousIncreaseMultiplier &&
       absoluteIncrease >= d.MinSuspiciousAmount {
        return &FlashLoanAlert{
            Wallet:          wallet,
            StartBalance:    startBalance,
            EndBalance:      snapshotBalance,
            IncreaseRatio:   increaseRatio,
            DetectionWindow: d.DetectionWindow,
            Reason:          "Sudden large balance increase (>10x within 24 hours)",
            BlockedFromVote: true,
            Sources:         txSources,
        }, nil
    }

    return nil, nil
}

// allSourcesAllowlisted checks if all transaction sources are in allowlist
func allSourcesAllowlisted(sources []SourceType, allowlist []SourceType) bool {
    for _, source := range sources {
        if !isAllowlistedSource(source, allowlist) {
            return false
        }
    }
    return true
}

// BlockVoteIfFlashLoan prevents voting for addresses with flash loan patterns
func BlockVoteIfFlashLoan(
    wallet WalletID,
    snapshot *ProposalSnapshot,
    detector *FlashLoanDetector,
) error {
    alert, err := detector.DetectFlashLoanPattern(
        wallet,
        snapshot.SnapshotHeight,
        snapshot.SnapshotTime,
    )
    if err != nil {
        return err
    }

    if alert != nil && alert.BlockedFromVote {
        return &ErrFlashLoanDetected{
            Wallet:        wallet,
            IncreaseRatio: alert.IncreaseRatio,
            Reason:        alert.Reason,
        }
    }

    return nil
}
```

#### Why These Lockup Values Work

| Attack Vector | Lockup Defense | Attack Cost |
|---------------|----------------|-------------|
| Flash loan (same block) | 72-hour pre-holding (CANONICAL) | Loan interest for 72+ hours |
| Flash loan (multi-block) | 100 block confirmations | Cannot reorg 100 blocks |
| Borrow and vote | Post-vote 3-day lock | Interest + opportunity cost |
| Vote manipulation via exchanges | Pre-holding requirement | Coins must leave exchange 72+ hours early |
| Sudden accumulation (>10x/24h) | Flash loan pattern detection | Blocked from voting |
| Disguised flash loan sources | Source allowlisting | Only mining/staking rewards exempt |

### Activation Thresholds and Process

#### Hybrid Activation

An upgrade activates when **either** condition is met:

1. **Signaling Threshold**: 75% of nodes signal readiness
2. **Timeout Deadline**: 3 months from proposal approval

Active nodes are defined as nodes that:
- Sent a message in the last 24 hours
- Responded to at least one peer query
- Maintain valid DHT state

#### Timeline

```
Day 0:     Proposal Approved
Day 1-90:  Signaling Period + Warning Period
Day 60:    Activation Warning (30 days before deadline)
Day 90:    Forced Activation (if threshold not met)
```

#### Hard Fork Policy

The **Strict Upgrade** policy enforces:
- No backward compatibility after activation
- Immediate enforcement at activation block
- Clear warnings 30, 14, 7, and 1 days before activation

#### Version Negotiation

```go
type VersionNegotiation struct {
    MinSupported ProtocolVersion  // Oldest version supported
    MaxSupported ProtocolVersion  // Newest version supported
    Preferred    ProtocolVersion  // Preferred version to use
    Features     []string          // Optional feature flags
}
```

Negotiation selects highest common version. Optional features negotiated separately via feature flags.

#### Emergency Upgrades

For critical security vulnerabilities:

**Timeline:**
- Hour 0-4: Security committee convened
- Hour 4-12: Patch developed and tested
- Hour 12-24: Emergency release published
- Day 1-7: Rapid deployment (7-day forced activation)
- Day 30: Community retrospective

**Constraints:**
- Security-only changes
- Minimal possible fix
- Full disclosure after deployment
- Requires unanimous security committee vote

---

## Economic Model

The economic model is built on free market principles with minimal protocol intervention, relying on market mechanisms for efficient resource allocation and price discovery.

### Free Market Pricing Principles

**Core Principles:**
- **Provider Autonomy**: Each provider independently sets prices
- **No Price Floors**: Market competition determines minimum viable pricing
- **Price Signals**: Supply and demand balance through natural discovery
- **Self-Correction**: Market forces restore equilibrium without intervention
- **Transparency**: All pricing publicly available via DHT

### DHT-Based Service Discovery

#### Service Advertisement Schema

```go
type ServiceAdvertisement struct {
    ProviderID      NodeID          // Unique provider identifier
    PublicKey       []byte          // Provider's public key

    ServiceType     ServiceType     // Storage, Compute, Bandwidth, etc.
    PricePerUnit    uint64          // Price in smallest coin unit
    PricingUnit     PricingUnit     // GB-month, CPU-hour, GB-transfer, etc.

    AvailableUnits  uint64          // Current available capacity
    MaxUnits        uint64          // Maximum capacity

    SLAOffered      float64         // 50.0 - 99.999% uptime guarantee
    Reputation      float64         // Current reputation score (0.0 - 100.0)

    HardwareSpecs   HardwareSpecs   // Detailed hardware information
    GeographicZone  string          // Data center location/region

    MinContractDuration  uint64     // Minimum service duration (blocks)
    PaymentTerms         PaymentTerms

    ExpiresAt       int64           // Unix timestamp for listing expiry
    PublishedAt     int64           // Unix timestamp of publication
    Signature       []byte          // Cryptographic signature
}
```

**DHT Key Scheme:**

| Purpose | DHT Key Format |
|---------|----------------|
| Service listing | `service:<type>:<provider_id>` |
| Price index | `price:<type>:bucket_<N>` |
| Provider catalog | `provider:<provider_id>` |
| Reputation index | `reputation:<type>:bucket_<N>` |

**Update Frequency:**
- Price changes: Immediate (real-time)
- Capacity updates: Every 10 blocks or 10% change
- Reputation updates: Automatic after contract completion
- Advertisement refresh: Every 1000 blocks minimum

#### Service Query

```go
type ServiceQuery struct {
    ServiceType     ServiceType
    MaxPrice        uint64          // Filter: price <= max
    MinReputation   float64         // Filter: reputation >= min
    MinSLA          float64         // Filter: SLA >= min
    RequiredUnits   uint64          // Filter: available >= required
    GeographicZones []string        // Filter: zone in list
    SortBy          SortCriteria    // Price, Reputation, SLA, Random
    Limit           uint32          // Max results
}
```

### Price Discovery Mechanisms

#### Transaction Fee Structure

Size-based fee model:

```
fee = max(base_rate * tx_size_bytes, minimum_fee)
```

**Parameters:**
- `base_rate`: 0.00001 coins per byte
- `minimum_fee`: 1 satoshi (0.00000001 coins)
- Maximum transaction size: 1 MB (max fee: 10.48576 coins)

| Transaction Type | Size | Fee (coins) |
|------------------|------|-------------|
| Simple transfer | 250 bytes | 0.0025 |
| Service contract | 800 bytes | 0.008 |
| Multi-signature | 1500 bytes | 0.015 |
| Data storage proof | 5000 bytes | 0.05 |

#### Fee Distribution

Transaction fees split three ways:

```go
type FeeDistribution struct {
    TotalFee        uint64
    ValidatorShare  uint64  // 70%
    FoundationShare uint64  // 15%
    TreasuryShare   uint64  // 15%
}
```

**Validator Distribution (70%):**
- Block Producer: 50% of validator share (35% of total)
- Transaction Validators: 50% of validator share (35% of total, split proportionally)

**Foundation Allocation (15%):**
- Core Protocol Development: 40%
- Security (audits, bounties): 30%
- Ecosystem Growth: 20%
- Operations: 10%

**Treasury (15%):**
- Community governed via stakeholder voting
- Requires multi-signature from elected treasury guardians
- Quarterly public financial reports

#### Market Equilibrium

Market self-corrects through price signals:

```
Excess Supply -> Prices Drop -> Marginal Providers Exit -> Equilibrium
Excess Demand -> Prices Rise -> New Providers Enter -> Equilibrium
```

#### Anti-Manipulation Measures

**Sybil Attack Prevention (CANONICAL - E6 Hardened):**

The Sybil cost model is designed to scale with network size to maintain security as the network grows.

```go
// SybilCostModel defines network-size-aware Sybil resistance
type SybilCostModel struct {
    // Base stake per listing (minimum network)
    BaseStake           uint64  // 1,000 coins
    // Network size scaling factor
    NetworkSizeMultiplier float64  // Scales with sqrt(network_size)
    // Maximum stake cap
    MaxStake            uint64  // 50,000 coins
    // TPM binding requirement
    RequireTPMBinding   bool    // Always true
}

// CalculateSybilCost computes required stake based on network size
func CalculateSybilCost(networkSize uint64, listingCount int) uint64 {
    // Base cost: 1,000 coins
    baseCost := uint64(1000)

    // Network size scaling: sqrt(N) / 100
    // At 10,000 nodes: multiplier = 1.0
    // At 100,000 nodes: multiplier = 3.16
    // At 1,000,000 nodes: multiplier = 10.0
    networkMultiplier := math.Sqrt(float64(networkSize)) / 100.0
    if networkMultiplier < 1.0 {
        networkMultiplier = 1.0
    }

    // Apply network scaling
    scaledCost := uint64(float64(baseCost) * networkMultiplier)

    // Apply exponential growth for multiple listings
    // 1 listing: 1x, 2 listings: 2x, 3 listings: 4x, etc.
    listingMultiplier := uint64(1 << (listingCount - 1))

    totalCost := scaledCost * listingMultiplier

    // Cap at maximum
    if totalCost > 50000 {
        totalCost = 50000
    }

    return totalCost
}
```

**Sybil Cost Analysis (E6):**

| Network Size | Base Cost | 1 Listing | 5 Listings | 10 Sybil Nodes |
|--------------|-----------|-----------|------------|----------------|
| 10,000 nodes | 1,000 | 1,000 | 31,000 | 310,000 |
| 100,000 nodes | 3,160 | 3,160 | 97,960 | 979,600 |
| 1,000,000 nodes | 10,000 | 10,000 | 310,000 | 3,100,000 |

**Why This Model Works:**
- At small network sizes, lower costs encourage growth
- At larger sizes, higher costs maintain Sybil resistance proportional to potential attack impact
- TPM binding ensures each identity requires unique hardware
- Exponential listing costs prevent service marketplace manipulation

**Additional Sybil Defenses:**
- TPM-bound identity limits (1 primary identity per TPM)
- 120+ days minimum to build CA-eligible reputation (0.90)
- Geographic diversity requirements for high-privilege roles
- Stake slashed if provider fails to deliver

**Spam Prevention:**
- Publication fee: 0.001 coins per advertisement
- Rate limiting: Max 10 updates per 100 blocks per provider
- Fee returned if listing expires naturally

**False Advertising Mitigation:**
- Hardware attestation via TEE
- Storage proofs for storage services
- Automatic SLA penalties for failures
- Reputation severely damaged by failed delivery

### Service Reward Balancing (E7 - CANONICAL)

To prevent nodes from neglecting routing duties in favor of storage earnings, the protocol caps the storage-to-routing reward multiplier. All service work requires **verified proof** before rewards are issued.

#### Service Reward Verification Requirements

| Service Type | Verification Method | Minimum Witnesses |
|--------------|---------------------|-------------------|
| Routing Work | Peer witness confirmations | 2 independent peers |
| Storage | Challenge-response proofs | Protocol-verified |
| Bandwidth (Gateway) | TPM-attested counters + peer observation | 2 independent peers |
| Compute | Execution attestation | TEE-verified |

#### Reward Balance Formula

```go
// ServiceRewardConfig defines balanced incentive structure
type ServiceRewardConfig struct {
    // Maximum multiplier for any service vs base routing
    MaxServiceMultiplier    float64 // Default: 10.0 (reduced from 100x)
    // Base routing reward per successful route
    BaseRoutingReward       uint64  // Default: 1 unit
    // Storage reward cap (per GB-hour)
    MaxStorageMultiplier    float64 // Default: 10.0
    // Compute reward cap (per CPU-hour)
    MaxComputeMultiplier    float64 // Default: 8.0
    // Bandwidth reward cap (per GB)
    MaxBandwidthMultiplier  float64 // Default: 5.0
    // Minimum routing activity required for service rewards
    MinRoutingActivityPercent float64 // Default: 0.20 (20%)
    // Minimum peer witnesses for routing work verification
    MinRoutingWitnesses     int     // Default: 2
}

// DefaultServiceRewardConfig returns production values (E7 hardened)
func DefaultServiceRewardConfig() ServiceRewardConfig {
    return ServiceRewardConfig{
        MaxServiceMultiplier:      10.0,
        BaseRoutingReward:         1,
        MaxStorageMultiplier:      10.0,
        MaxComputeMultiplier:      8.0,
        MaxBandwidthMultiplier:    5.0,
        MinRoutingActivityPercent: 0.20,
        MinRoutingWitnesses:       2,
    }
}

// RoutingWorkProof represents verified routing work with peer witnesses
type RoutingWorkProof struct {
    NodeID          [32]byte        // Node claiming routing reward
    RouteID         [32]byte        // Unique route identifier
    Timestamp       int64           // When routing occurred
    BytesRouted     uint64          // Data volume routed
    SourceNode      [32]byte        // Route source
    DestinationNode [32]byte        // Route destination
    Witnesses       []WitnessAttestation // At least 2 independent confirmations
}

// WitnessAttestation confirms routing work observation
type WitnessAttestation struct {
    WitnessNodeID   [32]byte        // Peer that witnessed the routing
    RouteID         [32]byte        // Route being attested
    ObservedAt      int64           // Observation timestamp
    BytesObserved   uint64          // Bytes the witness observed
    Signature       []byte          // TPM-signed attestation
}

// VerifyRoutingWork validates routing work proof before reward
func VerifyRoutingWork(proof *RoutingWorkProof, config ServiceRewardConfig) error {
    // Require minimum 2 independent peer witnesses
    if len(proof.Witnesses) < config.MinRoutingWitnesses {
        return &ErrInsufficientWitnesses{
            Required: config.MinRoutingWitnesses,
            Provided: len(proof.Witnesses),
        }
    }

    // Verify all witnesses are independent (different nodes)
    witnessSet := make(map[[32]byte]bool)
    for _, witness := range proof.Witnesses {
        // Witness cannot be the claiming node
        if witness.WitnessNodeID == proof.NodeID {
            return ErrSelfWitnessing
        }
        // Witness cannot be source or destination
        if witness.WitnessNodeID == proof.SourceNode ||
           witness.WitnessNodeID == proof.DestinationNode {
            return ErrEndpointWitnessing
        }
        // Check for duplicate witnesses
        if witnessSet[witness.WitnessNodeID] {
            return ErrDuplicateWitness
        }
        witnessSet[witness.WitnessNodeID] = true
    }

    // Verify each witness signature
    for _, witness := range proof.Witnesses {
        attestationData := computeWitnessAttestation(witness)
        if !VerifyTPMSignature(witness.WitnessNodeID, attestationData, witness.Signature) {
            return &ErrInvalidWitnessSignature{WitnessID: witness.WitnessNodeID}
        }
    }

    // Verify byte counts are consistent across witnesses (within 5% tolerance)
    for _, witness := range proof.Witnesses {
        deviation := absInt64(int64(witness.BytesObserved) - int64(proof.BytesRouted))
        tolerancePermille := uint64(50) // 5% = 50 permille
        maxDeviation := proof.BytesRouted * tolerancePermille / 1000
        if uint64(deviation) > maxDeviation {
            return &ErrWitnessBytesMismatch{
                Claimed:  proof.BytesRouted,
                Observed: witness.BytesObserved,
            }
        }
    }

    return nil
}

// StorageProof represents challenge-response storage verification
type StorageProof struct {
    NodeID          [32]byte        // Storage provider
    DataHash        [32]byte        // Hash of stored data
    ChallengeNonce  [32]byte        // Random challenge
    ChallengeByte   uint64          // Position to prove
    ProofResponse   []byte          // Merkle proof of data at position
    Timestamp       int64           // When challenge was issued
}

// VerifyStorageProof validates storage proof via challenge-response
func VerifyStorageProof(proof *StorageProof, expectedRoot [32]byte) error {
    // Verify Merkle proof against known data root
    if !VerifyMerkleProof(proof.ProofResponse, proof.ChallengeByte, expectedRoot) {
        return ErrInvalidStorageProof
    }

    // Verify challenge freshness (must be recent)
    challengeAge := time.Now().Unix() - proof.Timestamp
    if challengeAge > 3600 { // 1 hour max
        return ErrStaleChallenge
    }

    return nil
}

// CalculateNodeRewards computes balanced rewards
func CalculateNodeRewards(node *Node, period time.Duration) *RewardCalculation {
    // Calculate base routing reward
    routingReward := node.SuccessfulRoutes * BaseRoutingReward

    // Calculate service rewards with caps
    storageReward := min(
        node.StorageGBHours * StorageRatePerGBHour,
        routingReward * MaxStorageMultiplier,
    )

    computeReward := min(
        node.ComputeCPUHours * ComputeRatePerCPUHour,
        routingReward * MaxComputeMultiplier,
    )

    bandwidthReward := min(
        node.BandwidthGB * BandwidthRatePerGB,
        routingReward * MaxBandwidthMultiplier,
    )

    // Check minimum routing activity requirement
    totalActivity := routingReward + storageReward + computeReward + bandwidthReward
    routingPercent := float64(routingReward) / float64(totalActivity)

    if routingPercent < MinRoutingActivityPercent {
        // Penalize service rewards if routing neglected
        penaltyFactor := routingPercent / MinRoutingActivityPercent
        storageReward = uint64(float64(storageReward) * penaltyFactor)
        computeReward = uint64(float64(computeReward) * penaltyFactor)
        bandwidthReward = uint64(float64(bandwidthReward) * penaltyFactor)
    }

    return &RewardCalculation{
        RoutingReward:   routingReward,
        StorageReward:   storageReward,
        ComputeReward:   computeReward,
        BandwidthReward: bandwidthReward,
        TotalReward:     routingReward + storageReward + computeReward + bandwidthReward,
    }
}
```

**Reward Balance Rationale (E7):**

| Service | Old Multiplier | New Multiplier | Rationale |
|---------|---------------|----------------|-----------|
| Storage | 100x | 10x | Prevents routing neglect |
| Compute | 50x | 8x | Balanced with infrastructure cost |
| Bandwidth | 20x | 5x | Ensures routing participation |

**Minimum Routing Requirement:**
- Nodes must maintain at least 20% of activity as routing
- Service rewards are scaled down proportionally if routing is neglected
- Ensures network maintains routing capacity even as services grow

---

## Gateway Incentives

Gateways bridge non-trusted clients to the Trusted Computing P2P network, providing bandwidth relay services for lightweight clients and devices without TPM capabilities.

### Gateway Role and Compensation

**Key Gateway Functions:**
- Relay traffic between untrusted clients and trusted DHT nodes
- Maintain TPM-attested traffic counters for accurate billing
- Submit hourly traffic reports to the DHT
- Undergo 90-day probation period
- Operate under continuous reputation monitoring

#### Per-Byte Compensation

```
daily_earnings = bytes_relayed * rate_per_byte * probation_multiplier

Where:
- bytes_relayed: TPM-attested daily traffic volume
- rate_per_byte: Current market rate from service rewards pool
- probation_multiplier: 0.5 during probation, 1.0 after
```

**Rate Determination:**
- Supply/demand balance: More gateways = lower rate per GB
- Dynamic adjustment based on network capacity vs. demand
- Current rates published to DHT

#### Traffic Tracking

```go
type TrafficCounter struct {
    BytesRelayed    uint64    // Total bytes relayed
    LastReportTime  time.Time // Last report timestamp
    TPMAttestation  []byte    // TPM signature of counter state
    ReportSequence  uint64    // Monotonic sequence number
}
```

Hourly reports include TPM attestation signature, sequence numbers (preventing replay attacks), and cross-validation with peer observations.

### Gateway Selection (E8 - CANONICAL)

To prevent the "fastest gateway gets all traffic" race condition, the protocol implements weighted round-robin selection with load balancing.

#### Weighted Gateway Selection

```go
// GatewaySelector implements fair traffic distribution
type GatewaySelector struct {
    // Selection algorithm
    Algorithm       SelectionAlgorithm // Default: WeightedRoundRobin
    // Weight factors
    ReputationWeight float64           // Default: 0.40
    LatencyWeight    float64           // Default: 0.30
    LoadWeight       float64           // Default: 0.30
    // Anti-monopoly limits
    MaxTrafficShare  float64           // Default: 0.15 (15% max per gateway)
    // Rotation frequency
    RotationInterval time.Duration     // Default: 1 hour
}

type SelectionAlgorithm uint8
const (
    SelectionWeightedRoundRobin SelectionAlgorithm = iota
    SelectionRandomWeighted
    SelectionLeastConnections
)

// DefaultGatewaySelector returns production configuration
func DefaultGatewaySelector() GatewaySelector {
    return GatewaySelector{
        Algorithm:        SelectionWeightedRoundRobin,
        ReputationWeight: 0.40,
        LatencyWeight:    0.30,
        LoadWeight:       0.30,
        MaxTrafficShare:  0.15,
        RotationInterval: time.Hour,
    }
}

// SelectGateway chooses gateway using weighted round-robin
func (gs *GatewaySelector) SelectGateway(
    client ClientID,
    availableGateways []*Gateway,
    region string,
) (*Gateway, error) {
    if len(availableGateways) == 0 {
        return nil, ErrNoGatewaysAvailable
    }

    // Filter to region if specified
    regional := filterByRegion(availableGateways, region)
    if len(regional) == 0 {
        regional = availableGateways // Fallback to all
    }

    // Calculate weights for each gateway
    weights := make([]float64, len(regional))
    totalWeight := 0.0

    for i, gw := range regional {
        // Skip gateways at max traffic share
        if gw.CurrentTrafficShare >= gs.MaxTrafficShare {
            weights[i] = 0
            continue
        }

        // Calculate composite score
        reputationScore := gw.Reputation / 100.0 // Normalize to 0-1
        latencyScore := 1.0 - (float64(gw.AvgLatencyMs) / 1000.0) // Lower is better
        if latencyScore < 0 {
            latencyScore = 0
        }
        loadScore := 1.0 - gw.CurrentLoad // Lower load is better

        weights[i] = (reputationScore * gs.ReputationWeight) +
                     (latencyScore * gs.LatencyWeight) +
                     (loadScore * gs.LoadWeight)

        totalWeight += weights[i]
    }

    if totalWeight == 0 {
        return nil, ErrAllGatewaysAtCapacity
    }

    // Weighted random selection
    selection := rand.Float64() * totalWeight
    cumulative := 0.0

    for i, w := range weights {
        cumulative += w
        if selection <= cumulative {
            return regional[i], nil
        }
    }

    // Fallback to last gateway
    return regional[len(regional)-1], nil
}
```

**Gateway Selection Rules (E8):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max traffic share | 15% | Prevents monopolization |
| Reputation weight | 40% | Rewards reliable gateways |
| Latency weight | 30% | Rewards fast gateways |
| Load weight | 30% | Distributes load evenly |
| Rotation interval | 1 hour | Allows periodic rebalancing |

**Anti-Monopoly Protections:**
- No gateway can handle more than 15% of regional traffic
- Weighted selection ensures fair distribution
- Load factor prevents overloading single gateways
- Periodic rotation prevents sticky connections

### Service Rewards Pool

Gateway compensation is funded from the service rewards pool (75% of total token emissions):

**Token Emission Breakdown:**
- 25%: Validator rewards
- 75%: Service rewards pool
  - Bandwidth Relay (Gateways)
  - Storage services
  - Compute services
  - Other network services

**Important**: Users do not pay gateways directly. This simplifies UX, provides predictable costs, and ensures gateways compete on reliability rather than price.

Gateway compensation follows the network halving schedule, with gradual transition to fee-based model for long-term sustainability.

### Traffic Metering

#### Probation Period

New gateways complete a 90-day probation period at 50% compensation rate.

**Success Criteria:**
- Uptime > 99% during 90-day period
- Valid hourly traffic reports
- Pass random verification challenges
- Maintain positive reputation score
- No fraud detection incidents

**Post-Probation:** Compensation increases to 100% (2x probation rate).

#### Fraud Detection

**TPM-Attested Counters:**
- Counter in TPM-protected memory
- Signed by private attestation key
- Tampering results in invalid attestation

**Challenge-Response Verification:**
1. Traffic sampling: Coordinator sends test traffic, compares with reports
2. Peer observation: Cross-check with connected DHT nodes
3. Pattern analysis: Flag constant maximum or sudden spikes

```go
// GatewayFraudDetector implements sliding window fraud detection with integer thresholds
type GatewayFraudDetector struct {
    GatewayID             [32]byte
    // Current report data
    ReportedTraffic       uint64
    ObservedTraffic       uint64
    // Historical statistics
    HistoricalAverage     uint64
    HistoricalStdDevX1000 uint64    // Standard deviation * 1000 (integer)
    // Sliding window for deviation tracking
    DeviationWindow       []DeviationRecord
    WindowDuration        time.Duration // Default: 30 days
    // Cumulative deviation in permille (1000 = 100%)
    CumulativeDeviationPermille int64
    ReportCount           uint64
    LastCleanTimestamp    time.Time     // Last time investigation cleared gateway
}

// DeviationRecord tracks individual report deviations
type DeviationRecord struct {
    Timestamp         time.Time
    DeviationPermille int64   // Deviation in permille (50 = 5%)
    ReportedBytes     uint64
    ObservedBytes     uint64
}

// GatewayFraudConfig uses integer-based thresholds (permille) to avoid rounding issues
type GatewayFraudConfig struct {
    // Single report over-reporting threshold (permille: 50 = 5%)
    SingleReportThresholdPermille int64         // Default: 50 (5%)
    // Cumulative deviation threshold (permille: 200 = 20%)
    CumulativeThresholdPermille   int64         // Default: 200 (20%)
    // Average deviation threshold after N reports (permille: 20 = 2%)
    AverageThresholdPermille      int64         // Default: 20 (2%)
    // Minimum reports before average check applies
    MinReportsForAverage          uint64        // Default: 100
    // Statistical outlier threshold (multiplied by 1000)
    ZScoreThresholdX1000          int64         // Default: 3000 (3.0 sigma)
    // Sliding window duration
    WindowDuration                time.Duration // Default: 30 days
    // Clean period to reset cumulative deviation
    CleanPeriodDuration           time.Duration // Default: 30 days
}

// DefaultGatewayFraudConfig returns production fraud detection parameters
func DefaultGatewayFraudConfig() GatewayFraudConfig {
    return GatewayFraudConfig{
        SingleReportThresholdPermille: 50,              // 5%
        CumulativeThresholdPermille:   200,             // 20%
        AverageThresholdPermille:      20,              // 2%
        MinReportsForAverage:          100,
        ZScoreThresholdX1000:          3000,            // 3.0 sigma
        WindowDuration:                30 * 24 * time.Hour,
        CleanPeriodDuration:           30 * 24 * time.Hour,
    }
}

// DetectFraud checks for fraudulent traffic reporting using integer arithmetic
func (fd *GatewayFraudDetector) DetectFraud(config GatewayFraudConfig) *FraudResult {
    // Prune expired records from sliding window
    fd.pruneExpiredRecords(config.WindowDuration)

    // Check if clean period has elapsed (30 days without fraud)
    if time.Since(fd.LastCleanTimestamp) >= config.CleanPeriodDuration {
        fd.resetDeviationTracking()
    }

    // Calculate current deviation in permille (integer arithmetic)
    // deviationPermille = ((reported - observed) * 1000) / observed
    var currentDeviationPermille int64
    if fd.ObservedTraffic > 0 {
        diff := int64(fd.ReportedTraffic) - int64(fd.ObservedTraffic)
        currentDeviationPermille = (diff * 1000) / int64(fd.ObservedTraffic)
    }

    // Record this deviation in sliding window
    fd.DeviationWindow = append(fd.DeviationWindow, DeviationRecord{
        Timestamp:         time.Now(),
        DeviationPermille: currentDeviationPermille,
        ReportedBytes:     fd.ReportedTraffic,
        ObservedBytes:     fd.ObservedTraffic,
    })
    fd.CumulativeDeviationPermille += currentDeviationPermille
    fd.ReportCount++

    // Check 1: Single report over-reporting (> 5% = 50 permille)
    if currentDeviationPermille > config.SingleReportThresholdPermille {
        return &FraudResult{
            IsFraudulent: true,
            Reason:       "Single report over-reporting exceeds 5%",
            DeviationPermille: currentDeviationPermille,
            Threshold:    config.SingleReportThresholdPermille,
        }
    }

    // Check 2: Cumulative deviation exceeds 20% (200 permille)
    if fd.CumulativeDeviationPermille > config.CumulativeThresholdPermille {
        return &FraudResult{
            IsFraudulent: true,
            Reason:       "Cumulative deviation exceeds 20%",
            DeviationPermille: fd.CumulativeDeviationPermille,
            Threshold:    config.CumulativeThresholdPermille,
        }
    }

    // Check 3: Average deviation over 2% after 100+ reports
    if fd.ReportCount >= config.MinReportsForAverage {
        avgDeviationPermille := fd.CumulativeDeviationPermille / int64(fd.ReportCount)
        if avgDeviationPermille > config.AverageThresholdPermille {
            return &FraudResult{
                IsFraudulent: true,
                Reason:       "Average deviation exceeds 2% over 100+ reports",
                DeviationPermille: avgDeviationPermille,
                Threshold:    config.AverageThresholdPermille,
            }
        }
    }

    // Check 4: Statistical outlier (> 3 standard deviations)
    if fd.HistoricalStdDevX1000 > 0 {
        // zscoreX1000 = ((reported - average) * 1000) / stddev
        diff := int64(fd.ReportedTraffic) - int64(fd.HistoricalAverage)
        zscoreX1000 := (diff * 1000000) / int64(fd.HistoricalStdDevX1000)
        if zscoreX1000 > config.ZScoreThresholdX1000 {
            return &FraudResult{
                IsFraudulent: true,
                Reason:       "Statistical outlier exceeds 3 standard deviations",
                ZScoreX1000:  zscoreX1000,
                Threshold:    config.ZScoreThresholdX1000,
            }
        }
    }

    return &FraudResult{IsFraudulent: false}
}

// pruneExpiredRecords removes deviation records outside the sliding window
func (fd *GatewayFraudDetector) pruneExpiredRecords(windowDuration time.Duration) {
    cutoff := time.Now().Add(-windowDuration)
    var retained []DeviationRecord
    var prunedDeviation int64

    for _, record := range fd.DeviationWindow {
        if record.Timestamp.After(cutoff) {
            retained = append(retained, record)
        } else {
            prunedDeviation += record.DeviationPermille
        }
    }

    fd.DeviationWindow = retained
    fd.CumulativeDeviationPermille -= prunedDeviation
}

// resetDeviationTracking clears cumulative tracking after 30 days clean
func (fd *GatewayFraudDetector) resetDeviationTracking() {
    fd.CumulativeDeviationPermille = 0
    fd.ReportCount = 0
    fd.DeviationWindow = nil
    fd.LastCleanTimestamp = time.Now()
}

// ClearInvestigation marks gateway as cleared after fraud investigation
// Resets deviation tracking with sliding window preservation
func (fd *GatewayFraudDetector) ClearInvestigation() {
    fd.CumulativeDeviationPermille = 0
    fd.ReportCount = 0
    fd.LastCleanTimestamp = time.Now()
    // Note: DeviationWindow is NOT cleared - sliding window continues
    // This prevents abuse of investigation clearing
}

// FraudResult contains fraud detection outcome
type FraudResult struct {
    IsFraudulent      bool
    Reason            string
    DeviationPermille int64
    ZScoreX1000       int64
    Threshold         int64
}
```

**Fraud Detection Thresholds (CANONICAL - Integer-Based):**

All thresholds use **permille** (parts per thousand) instead of percentages to avoid floating-point rounding issues.

| Check | Threshold (Permille) | Equivalent % | Trigger |
|-------|---------------------|--------------|---------|
| Single Report Over-Reporting | > 50 permille | > 5% | Immediate fraud flag |
| Cumulative Deviation | > 200 permille | > 20% | Fraud flag |
| Average Deviation (100+ reports) | > 20 permille | > 2% | Fraud flag |
| Statistical Outlier | > 3000 (x1000) | > 3 sigma | Fraud flag |

**Sliding Window Mechanism:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Window Duration | 30 days | Limits historical deviation tracking |
| Clean Period | 30 days | Resets deviation after clean operation |
| Investigation Clear | Resets cumulative, preserves window | Prevents investigation abuse |

**Penalties:**
- Immediate reputation reduction
- Compensation clawback (last 30 days)
- Repeated fraud: permanent ban, TPM identity blacklisted

#### Regional Distribution

No minimum gateway requirements per region. Market-driven distribution through economic incentives:

```
Regional Value = User Demand / Gateway Supply
```

Underserved regions naturally attract gateways through higher traffic per gateway. Oversaturated regions see reduced earnings, incentivizing exit or relocation.

---

## Privacy Model

The privacy model enables **user choice and flexibility**. Users select the appropriate privacy level per transaction based on needs, budget, and regulatory requirements.

### Optional Confidential Transactions

#### Transaction Modes

**Transparent Mode:**
- Standard UTXO with visible amounts
- All details publicly verifiable
- Base fee (1.0x multiplier)
- Use cases: Public fundraising, donations, organizational transparency

**Confidential Mode:**
- Pedersen commitments hide amounts
- Transaction structure visible, values hidden
- Additional fee (+0.5x multiplier)
- Use cases: Private payments, salary, personal transfers

#### Pedersen Commitments

```
C = vG + rH
where:
  v = transaction value (hidden)
  r = random blinding factor
  G, H = generator points on elliptic curve
```

**Properties:**
- **Hiding**: Computationally infeasible to determine v from C
- **Binding**: Cannot find different (v', r') producing same commitment
- **Homomorphic**: C1 + C2 = (v1 + v2)G + (r1 + r2)H

**Balance Verification (without knowing amounts):**
```
Sum(Input_Commitments) - Sum(Output_Commitments) = Fee_Commitment
```

**Range Proofs (Bulletproofs):**
- Prove value in range [0, 2^64) without revealing exact value
- Logarithmic proof size: ~700 bytes per output
- Batch verification for improved performance
- Prevents negative values (supply inflation)

**Overhead:**
- Commitments: ~64 bytes per output
- Range proofs: ~700 bytes (single) or ~1000 bytes (aggregated)
- Verification: ~2-3ms per confidential output

### Stealth Addresses

Break the link between recipient's public identity and transaction history. Each payment uses a unique one-time address.

#### Protocol

**Receiver Setup:**
```
Meta-Address = (A, B)
where:
  A = aG (spend public key)
  B = bG (view public key)
  a, b = private keys known only to receiver
```

**Sender Creates One-Time Address:**
1. Generate random scalar `r`
2. Compute shared secret: `S = rB`
3. Derive one-time public key: `P = H(rB)G + A`
4. Publish ephemeral key `R = rG` in transaction
5. Send funds to address derived from `P`

**Receiver Scans:**
1. Retrieve ephemeral key `R`
2. Compute shared secret: `S = bR`
3. Derive expected public key: `P' = H(bR)G + A`
4. If match, compute spending key: `p = H(bR) + a`

#### Dual-Key Architecture

- **View Key (b)**: Scanning for incoming transactions (watch-only wallets)
- **Spend Key (a)**: Authorizing outgoing transactions

Enables delegated scanning without spending authority and compliance view keys for auditing.

**Overhead:** One ephemeral public key per transaction (~32 bytes), +0.5x fee multiplier.

### Privacy Guarantees

#### Metadata Protection Tiers

| Tier | Fee Multiplier | Protection | Latency |
|------|---------------|------------|---------|
| None | 1.0x | None (standard flooding) | ~100-200ms |
| Low | +0.2x | Timing jitter (0-30s delay) | ~30-60s |
| Medium | +0.5x | Dandelion++ (stem + fluff phases) | ~1-3min |
| High | +1.0x | Onion routing + mixing | ~5-10min |

**Dandelion++ (Medium):**
- Stem phase: Transaction propagated along random path (1-10 hops)
- Fluff phase: Standard flooding from random node
- Breaks link between originating IP and transaction

**Onion Routing (High):**
- Multiple encryption layers
- 3+ intermediate nodes
- Mixing with other transactions at each hop
- Timing obfuscation through batching

#### Fee Multipliers Summary

| Feature | Multiplier |
|---------|-----------|
| Stealth Address | +0.5x |
| Confidential Amounts | +0.5x |
| Metadata: None | +0.0x |
| Metadata: Low | +0.2x |
| Metadata: Medium | +0.5x |
| Metadata: High | +1.0x |

**Example: Full Privacy Transaction**
```
Base Fee: 1.0x
+ Stealth Address: +0.5x
+ Confidential Amounts: +0.5x
+ Metadata High: +1.0x
Total: 3.0x base fee
```

#### View Keys for Compliance

Enable optional transparency for regulatory compliance while preserving network-wide privacy.

```go
type ViewKey struct {
    KeyID           []byte    // Unique identifier (32 bytes)
    PublicAddress   []byte    // Address this key reveals
    StartTime       int64     // Optional: Unix timestamp (0 = no limit)
    EndTime         int64     // Optional: Unix timestamp (0 = no limit)
    Capabilities    uint8     // Bitmap of what key reveals
    ExpiresAt       int64     // Key expiration timestamp (0 = never)
    Signature       []byte    // Proof of authorization
}

const (
    CapViewAmounts       = 1 << 0  // Reveal transaction amounts
    CapViewTimestamps    = 1 << 1  // Reveal transaction times
    CapViewCounterparty  = 1 << 2  // Reveal sender/receiver identities
    CapViewMemo          = 1 << 3  // Reveal transaction memos
)
```

**View Key Types:**
- **Full View Key**: Identifies all incoming transactions (cannot spend)
- **Time-Bounded View Key**: Only reveals transactions within [StartTime, EndTime]
- **Capability-Restricted View Key**: Reveals only specific attributes

**Regulatory Use Cases:**

| Use Case | Capabilities | Time Range | Expiration |
|----------|-------------|------------|------------|
| Tax Reporting | Amounts + Timestamps | Tax year | None |
| AML Audit | All (0x0F) | Investigation period | 90 days after close |
| Balance Verification | Amounts only | All time | Single-use |

**Security Properties:**
- Non-spending: Cannot authorize transactions
- Revocable: Generate new addresses to invalidate
- Scoped: Time and capability restrictions limit exposure
- Provable: Cryptographic signatures prove authenticity
- Offline: Work without network access

View keys maintain network privacy because they are per-user, require explicit authorization, and cannot be derived by third parties.

---

## Penalty Enforcement System

This section defines the comprehensive penalty enforcement mechanism including violation triggers, detection methods, calculation formulas, enforcement parties, appeals processes, and penalty types.

### Canonical Penalty Values

All penalty amounts reference the canonical constants defined in [00-CONSTANTS.md](00-CONSTANTS.md):

| Penalty Level | Reputation Delta | Description |
|---------------|------------------|-------------|
| `MinorViolationPenalty` | -0.01 | Minor protocol deviations, single missed heartbeat |
| `ModerateViolationPenalty` | -0.05 | Multiple missed heartbeats, temporary unresponsiveness |
| `SevereViolationPenalty` | -0.15 | Prolonged downtime, repeated protocol violations |
| `CriticalViolationPenalty` | -0.30 | Major security violations, intentional misconduct |
| `MaxDailyPenalty` | -0.10 | Maximum cumulative penalty per 24-hour period |

### Violation Triggers

Penalties are triggered by specific detectable events. Each trigger has defined severity and enforcement timeline.

#### Tier 1: Automated Immediate Triggers

These violations are detected automatically and penalties are applied immediately without human intervention.

| Trigger | Detection Method | Penalty Level | Enforcement |
|---------|------------------|---------------|-------------|
| Failed TPM attestation | TPM quote verification failure | Moderate (-0.05) | Automated |
| Single missed heartbeat | Heartbeat timeout (>8s) | Minor (-0.01) | Automated |
| Invalid message signature | Cryptographic verification | Moderate (-0.05) | Automated |
| Nonce reuse | Nonce cache collision | Severe (-0.15) | Automated |
| Rate limit exceeded | Request counter overflow | Minor (-0.01) | Automated |
| Expired certificate usage | Certificate validity check | Moderate (-0.05) | Automated |

#### Tier 2: Automated Delayed Triggers

These violations require pattern verification before penalty application.

| Trigger | Detection Method | Penalty Level | Verification Period |
|---------|------------------|---------------|---------------------|
| Consecutive missed heartbeats (4+) | Heartbeat monitor | Moderate (-0.05) | 32 seconds |
| Repeated protocol violations (3+ in 1h) | Violation counter | Severe (-0.15) | 1 hour |
| Storage proof failure | Challenge-response timeout | Moderate (-0.05) | 1 hour max |
| Gateway over-reporting (>5%) | Traffic counter discrepancy | Severe (-0.15) | Single report |
| Cumulative over-reporting (>20%) | Sliding window analysis | Critical (-0.30) | 30-day window |
| DKG timeout | DKG ceremony deadline | Minor to Moderate (-0.01 to -0.05) | 10-13 minutes |

#### Tier 3: Consensus-Verified Triggers

These violations require multi-party consensus before penalty application.

| Trigger | Detection Method | Penalty Level | Consensus Required |
|---------|------------------|---------------|-------------------|
| Equivocation (conflicting signatures) | Proof submission | Severe (-0.15) + 50% stake slash | 3 arbitrators |
| Vote selling | Transaction analysis + witness | Critical + permanent ban | 3 arbitrators + evidence |
| Collusion | Pattern analysis + witness | Critical + permanent ban | 3 arbitrators + evidence |
| Malicious routing | Path analysis + peer reports | Severe (-0.15) | 2 independent peers |
| False fraud accusation | Counter-evidence submission | Severe (-0.15) | 3 arbitrators |

### Detection Mechanisms

#### Automated Monitoring System

```go
// ViolationDetector monitors for policy violations
type ViolationDetector struct {
    NodeID              [32]byte
    ViolationHistory    []ViolationRecord
    CurrentPeriodStart  time.Time
    DailyPenaltyApplied float64             // Tracks MaxDailyPenalty limit
    AlertSubscribers    []AlertHandler
}

// ViolationRecord captures a detected violation
type ViolationRecord struct {
    ViolationID     [32]byte
    ViolationType   ViolationType
    DetectedAt      time.Time
    DetectionMethod DetectionMethod
    Evidence        []byte              // Cryptographic proof of violation
    PenaltyApplied  float64
    EnforcementTier EnforcementTier
    Status          ViolationStatus     // Pending, Applied, Appealed, Reversed
}

// ViolationType enumerates all violation categories
type ViolationType uint16
const (
    ViolationHeartbeatMissed        ViolationType = 1
    ViolationAttestationFailed      ViolationType = 2
    ViolationSignatureInvalid       ViolationType = 3
    ViolationNonceReused            ViolationType = 4
    ViolationRateLimitExceeded      ViolationType = 5
    ViolationCertificateExpired     ViolationType = 6
    ViolationStorageProofFailed     ViolationType = 7
    ViolationGatewayOverreporting   ViolationType = 8
    ViolationDKGTimeout             ViolationType = 9
    ViolationEquivocation           ViolationType = 10
    ViolationVoteSelling            ViolationType = 11
    ViolationCollusion              ViolationType = 12
    ViolationMaliciousRouting       ViolationType = 13
    ViolationFalseAccusation        ViolationType = 14
)

// DetectionMethod indicates how violation was discovered
type DetectionMethod uint8
const (
    DetectionAutomatedMonitor   DetectionMethod = 1
    DetectionPeerReport         DetectionMethod = 2
    DetectionConsensusVerified  DetectionMethod = 3
    DetectionChallengeResponse  DetectionMethod = 4
    DetectionPatternAnalysis    DetectionMethod = 5
)

// EnforcementTier determines processing speed and verification
type EnforcementTier uint8
const (
    TierImmediate       EnforcementTier = 1  // Automated, instant
    TierDelayed         EnforcementTier = 2  // Automated, verification window
    TierConsensus       EnforcementTier = 3  // Requires multi-party agreement
)
```

#### Peer Report System

Nodes can report observed violations by peers. Reports require cryptographic evidence and TPM attestation.

```go
// PeerViolationReport submitted by observing nodes
type PeerViolationReport struct {
    ReporterNodeID    [32]byte
    AccusedNodeID     [32]byte
    ViolationType     ViolationType
    ObservedAt        time.Time
    Evidence          ViolationEvidence
    ReporterSignature []byte              // TPM-signed report
    Witnesses         []WitnessStatement  // Additional peer confirmations
}

// ViolationEvidence contains cryptographic proof
type ViolationEvidence struct {
    EvidenceType      EvidenceType
    Payload           []byte              // Signed messages, proofs, etc.
    MerkleProof       [][]byte            // Proof of inclusion in ledger
    Timestamp         int64
}

// WitnessStatement confirms observation of violation
type WitnessStatement struct {
    WitnessNodeID     [32]byte
    ObservationHash   [32]byte            // Hash of what was observed
    ObservedAt        time.Time
    Signature         []byte              // TPM-signed statement
}
```

#### False Report Prevention

To prevent weaponization of the reporting system:

| Protection | Mechanism | Penalty for Abuse |
|------------|-----------|-------------------|
| Report stake | 10 coins locked per report | Forfeited on false report |
| Evidence requirement | Cryptographic proof mandatory | Report rejected without proof |
| Witness threshold | 2+ independent witnesses for Tier 3 | Report requires corroboration |
| Reporter reputation | Minimum 0.50 reputation to report | Low-reputation reports deprioritized |
| False accusation penalty | Counter-evidence reverses penalty | Severe (-0.15) to accuser |

### Penalty Calculation

Penalties are calculated using a formula that considers base severity, repeat offender status, and time factors.

#### Calculation Formula

```go
// PenaltyCalculation computes final penalty amount
type PenaltyCalculation struct {
    BasePenalty         float64     // From canonical constants
    SeverityMultiplier  float64     // 1.0 - 3.0 based on impact
    RepeatOffenderFactor float64    // Increases with history
    TimeDecayFactor     float64     // Reduces for old offenses
    MitigatingFactors   float64     // Reduces for valid excuses
    FinalPenalty        float64     // Capped by MaxDailyPenalty
}

// CalculatePenalty computes penalty with all factors
func CalculatePenalty(
    violation ViolationType,
    history []ViolationRecord,
    mitigatingEvidence []byte,
) *PenaltyCalculation {
    calc := &PenaltyCalculation{}

    // Step 1: Get base penalty from canonical constants
    calc.BasePenalty = GetBasePenalty(violation)

    // Step 2: Calculate severity multiplier (1.0 - 3.0)
    // Based on impact: affected users, duration, reversibility
    calc.SeverityMultiplier = CalculateSeverityMultiplier(violation)

    // Step 3: Calculate repeat offender factor
    // Formula: 1.0 + (0.5 * violations_in_30_days)
    // Capped at 3.0x
    recentViolations := CountRecentViolations(history, 30*24*time.Hour)
    calc.RepeatOffenderFactor = math.Min(1.0+float64(recentViolations)*0.5, 3.0)

    // Step 4: Apply time decay to repeat factor
    // Older violations count less (decay by 50% per 30 days)
    calc.TimeDecayFactor = CalculateTimeDecay(history)

    // Step 5: Evaluate mitigating factors
    // Valid excuses: network partition, hardware failure with proof
    calc.MitigatingFactors = EvaluateMitigatingFactors(mitigatingEvidence)

    // Step 6: Calculate raw penalty
    rawPenalty := calc.BasePenalty *
        calc.SeverityMultiplier *
        (calc.RepeatOffenderFactor * calc.TimeDecayFactor) *
        (1.0 - calc.MitigatingFactors)

    // Step 7: Cap at MaxDailyPenalty (0.10)
    calc.FinalPenalty = math.Min(rawPenalty, MaxDailyPenalty)

    return calc
}

// GetBasePenalty returns canonical penalty for violation type
func GetBasePenalty(violation ViolationType) float64 {
    switch violation {
    case ViolationHeartbeatMissed, ViolationRateLimitExceeded:
        return MinorViolationPenalty      // 0.01
    case ViolationAttestationFailed, ViolationSignatureInvalid,
         ViolationCertificateExpired, ViolationStorageProofFailed,
         ViolationDKGTimeout:
        return ModerateViolationPenalty   // 0.05
    case ViolationNonceReused, ViolationGatewayOverreporting,
         ViolationEquivocation, ViolationMaliciousRouting,
         ViolationFalseAccusation:
        return SevereViolationPenalty     // 0.15
    case ViolationVoteSelling, ViolationCollusion:
        return CriticalViolationPenalty   // 0.30 (+ permanent ban)
    default:
        return MinorViolationPenalty
    }
}
```

#### Repeat Offender Escalation

| Violations (30 days) | Multiplier | Example: Moderate (-0.05) |
|---------------------|------------|---------------------------|
| 1 | 1.0x | -0.05 |
| 2 | 1.5x | -0.075 |
| 3 | 2.0x | -0.10 (capped by MaxDailyPenalty) |
| 4+ | 2.5x-3.0x | -0.10 (capped) + review trigger |

### Enforcement Parties

Different violation types are enforced by different parties based on severity and required expertise.

#### Enforcement Authority Matrix

| Violation Category | Primary Enforcer | Secondary/Appeal | Authority Basis |
|-------------------|------------------|------------------|-----------------|
| Protocol violations | Automated system | Arbitrator committee | Code-defined rules |
| Heartbeat/uptime | Automated system | Peer consensus | Network monitoring |
| Attestation failures | TPM verification | Security committee | Hardware attestation |
| Gateway fraud | Fraud detector | Treasury guardians | Economic monitoring |
| Equivocation | Consensus nodes | Arbitrator committee | Cryptographic proof |
| Collusion/vote selling | AI arbitrators | Appeal committee | Evidence analysis |
| Cross-shard violations | Source shard validators | Target shard validators | Transaction proofs |

#### Automated Enforcement

```go
// AutomatedEnforcer applies Tier 1 and Tier 2 penalties
type AutomatedEnforcer struct {
    ReputationStore     ReputationStore
    StakeManager        StakeManager
    ViolationLog        ViolationLog
    PenaltyCalculator   *PenaltyCalculation
    DailyPenaltyTracker map[[32]byte]float64  // Tracks MaxDailyPenalty per node
}

// EnforceViolation applies penalty for detected violation
func (ae *AutomatedEnforcer) EnforceViolation(
    violation *ViolationRecord,
    nodeID [32]byte,
) (*EnforcementResult, error) {
    // Check daily penalty cap
    dailyApplied := ae.DailyPenaltyTracker[nodeID]
    if dailyApplied >= MaxDailyPenalty {
        // Log violation but don't apply additional penalty today
        ae.ViolationLog.LogPendingViolation(violation)
        return &EnforcementResult{
            Applied:     false,
            Reason:      "Daily penalty cap reached",
            QueuedFor:   time.Now().Add(24 * time.Hour),
        }, nil
    }

    // Calculate penalty
    history := ae.ViolationLog.GetHistory(nodeID, 30*24*time.Hour)
    calc := CalculatePenalty(violation.ViolationType, history, nil)

    // Apply remaining daily allowance
    applicablePenalty := math.Min(calc.FinalPenalty, MaxDailyPenalty-dailyApplied)

    // Apply reputation penalty
    if err := ae.ReputationStore.ApplyPenalty(nodeID, applicablePenalty); err != nil {
        return nil, err
    }

    // Apply stake slash if required
    if RequiresStakeSlash(violation.ViolationType) {
        slashPercent := GetStakeSlashPercent(violation.ViolationType)
        if err := ae.StakeManager.SlashStake(nodeID, slashPercent); err != nil {
            return nil, err
        }
    }

    // Update daily tracker
    ae.DailyPenaltyTracker[nodeID] += applicablePenalty

    // Log enforcement
    ae.ViolationLog.LogEnforcement(violation, applicablePenalty)

    return &EnforcementResult{
        Applied:         true,
        PenaltyApplied:  applicablePenalty,
        NewReputation:   ae.ReputationStore.GetReputation(nodeID),
        StakeSlashed:    RequiresStakeSlash(violation.ViolationType),
    }, nil
}
```

#### Consensus-Based Enforcement

For Tier 3 violations requiring multi-party verification:

```go
// ConsensusEnforcer handles Tier 3 violations
type ConsensusEnforcer struct {
    ArbitratorPool      []NodeID
    MinQuorum           int       // Default: 3
    ConsensusThreshold  float64   // Default: 0.67 (2/3 majority)
    EvidenceValidator   EvidenceValidator
}

// InitiateConsensusEnforcement starts multi-party verification
func (ce *ConsensusEnforcer) InitiateConsensusEnforcement(
    report *PeerViolationReport,
) (*ConsensusProceeding, error) {
    // Select random arbitrators
    arbitrators, err := ce.SelectArbitrators(report.AccusedNodeID)
    if err != nil {
        return nil, err
    }

    // Create proceeding
    proceeding := &ConsensusProceeding{
        ProceedingID:   GenerateProceedingID(),
        Report:         report,
        Arbitrators:    arbitrators,
        Votes:          make(map[[32]byte]Vote),
        StartedAt:      time.Now(),
        Deadline:       time.Now().Add(72 * time.Hour),
        Status:         ProceedingPending,
    }

    // Distribute evidence to arbitrators
    for _, arb := range arbitrators {
        ce.DistributeEvidence(arb, proceeding)
    }

    return proceeding, nil
}

// CollectVote records arbitrator decision
func (ce *ConsensusEnforcer) CollectVote(
    proceedingID [32]byte,
    arbitratorID [32]byte,
    vote Vote,
) error {
    proceeding, err := ce.GetProceeding(proceedingID)
    if err != nil {
        return err
    }

    // Verify arbitrator is assigned
    if !ce.IsAssignedArbitrator(proceeding, arbitratorID) {
        return ErrUnauthorizedArbitrator
    }

    // Record vote
    proceeding.Votes[arbitratorID] = vote

    // Check if quorum reached
    if len(proceeding.Votes) >= ce.MinQuorum {
        ce.EvaluateConsensus(proceeding)
    }

    return nil
}
```

### Appeals Process

Nodes can appeal penalties through a structured process with escalation levels.

#### Appeal Levels

| Level | Authority | Timeline | Scope |
|-------|-----------|----------|-------|
| Level 1: Automated Review | System revalidation | 24 hours | Evidence re-check |
| Level 2: Arbitrator Committee | 3 AI arbitrators | 72 hours | Full case review |
| Level 3: Community Appeal | Governance vote | 14 days | Policy interpretation |

#### Appeal Requirements

```go
// Appeal represents a penalty appeal request
type Appeal struct {
    AppealID          [32]byte
    ViolationID       [32]byte
    AppellantNodeID   [32]byte
    AppealLevel       AppealLevel
    GroundsForAppeal  AppealGrounds
    Evidence          []byte              // Counter-evidence
    AppealStake       uint64              // Required stake (refunded if successful)
    SubmittedAt       time.Time
    Deadline          time.Time
    Status            AppealStatus
    Resolution        *AppealResolution
}

// AppealGrounds specifies valid reasons for appeal
type AppealGrounds uint8
const (
    GroundsInsufficientEvidence  AppealGrounds = 1
    GroundsProceduralError       AppealGrounds = 2
    GroundsMitigatingCircumstances AppealGrounds = 3
    GroundsTechnicalMalfunction  AppealGrounds = 4
    GroundsNetworkPartition      AppealGrounds = 5
    GroundsFalseAccusation       AppealGrounds = 6
)

// AppealConfig defines appeal system parameters
type AppealConfig struct {
    // Level 1: Automated
    Level1Deadline        time.Duration   // Default: 24 hours
    Level1Stake           uint64          // Default: 10 coins

    // Level 2: Arbitrator Committee
    Level2Deadline        time.Duration   // Default: 72 hours
    Level2Stake           uint64          // Default: 50 coins
    Level2MinArbitrators  int             // Default: 3

    // Level 3: Community
    Level3Deadline        time.Duration   // Default: 14 days
    Level3Stake           uint64          // Default: 200 coins
    Level3MinParticipation float64        // Default: 0.001 (0.1% of supply)

    // General
    MaxAppealLevels       int             // Default: 2 (Level 3 exceptional)
    StakeRefundOnSuccess  bool            // Default: true
}

// DefaultAppealConfig returns production appeal parameters
func DefaultAppealConfig() AppealConfig {
    return AppealConfig{
        Level1Deadline:        24 * time.Hour,
        Level1Stake:           10,
        Level2Deadline:        72 * time.Hour,
        Level2Stake:           50,
        Level2MinArbitrators:  3,
        Level3Deadline:        14 * 24 * time.Hour,
        Level3Stake:           200,
        Level3MinParticipation: 0.001,
        MaxAppealLevels:       2,
        StakeRefundOnSuccess:  true,
    }
}
```

#### Appeal Outcomes

| Outcome | Effect on Penalty | Effect on Appellant | Effect on Reporter |
|---------|-------------------|--------------------|--------------------|
| Appeal Upheld | Penalty reversed | Stake refunded + compensation | Possible counter-penalty |
| Appeal Denied | Penalty stands | Stake forfeited | No effect |
| Penalty Reduced | Partial reversal | Stake refunded | No effect |
| Escalated | Pending higher review | Stake held | No effect |

### Penalty Types

#### Reputation-Based Penalties

| Type | Application | Recovery Path |
|------|-------------|---------------|
| Minor reduction (-0.01 to -0.05) | Immediate | Natural recovery through good behavior |
| Moderate reduction (-0.05 to -0.15) | After verification | Extended recovery period |
| Severe reduction (-0.15 to -0.30) | After consensus | Probationary period + monitoring |
| Role demotion | When below threshold | Rebuild reputation to threshold |

#### Stake-Based Penalties

| Type | Percentage | Application | Recovery |
|------|------------|-------------|----------|
| Minor slash | 1-5% | DKG timeout, minor SLA miss | Re-stake to restore |
| Moderate slash | 10-25% | Repeated violations, fraud | Re-stake + probation |
| Severe slash | 50% | Equivocation, major violations | Re-stake + extended probation |
| Full slash | 100% | Collusion, vote selling | Permanent (no recovery) |

#### Access-Based Penalties

| Type | Duration | Trigger | Reinstatement |
|------|----------|---------|---------------|
| Temporary suspension | 1-7 days | Multiple SLA violations | Automatic after period |
| Extended suspension | 7-30 days | Severe violations | Manual review required |
| Role suspension | Until threshold met | Below role minimum | Rebuild reputation |
| Permanent ban | Indefinite | Collusion, vote selling | None (TPM blacklisted) |

### Enforcement Timeline

#### Immediate Penalties (Tier 1)

```
Detection -> Verification (<1s) -> Application (<1s) -> Logging (<1s)
Total: <3 seconds
```

#### Delayed Penalties (Tier 2)

```
Detection -> Pattern Accumulation (varies) -> Threshold Check -> Application -> Logging
Total: 1 minute to 30 days (depending on violation type)
```

#### Batch Penalties (Processed Periodically)

```
Collection Period (1 hour) -> Aggregation -> Deduplication -> Batch Application -> Logging
Total: Processed every hour on the hour
```

| Processing Type | Frequency | Included Violations |
|-----------------|-----------|---------------------|
| Real-time | Continuous | Tier 1 immediate |
| Hourly batch | Every hour | Minor violations, rate limit |
| Daily batch | Every 24h | Cumulative calculations, daily cap resets |
| Weekly batch | Every 7 days | Long-term pattern analysis |

### Common Violation Examples

#### Example 1: Missed Heartbeats

```
Scenario: Node misses 4 consecutive heartbeats due to temporary network issue

Timeline:
- T+0s: First heartbeat missed
- T+2s: Second heartbeat missed
- T+4s: Third heartbeat missed
- T+6s: Fourth heartbeat missed (threshold reached)
- T+8s: Detection confirmed
- T+8s: Penalty calculated:
  - Base: MinorViolationPenalty (0.01) per heartbeat
  - Consolidated: ModerateViolationPenalty (0.05) for 4+ consecutive
  - First offense: 1.0x multiplier
  - Final: -0.05 reputation
- T+9s: Penalty applied, node remains operational

Recovery:
- Node resumes heartbeats
- 50 successful attestations at +0.01 each
- Full recovery in ~5 days with normal operation
```

#### Example 2: Gateway Over-Reporting

```
Scenario: Gateway reports 110% of actual traffic (10% over-reporting)

Timeline:
- Hour 0: Traffic report submitted (10,000 GB reported vs 9,091 GB observed)
- Hour 0: Automated detection: 10% deviation > 5% threshold
- Hour 1: Fraud detection triggered
- Hour 1: Penalty calculated:
  - Base: SevereViolationPenalty (0.15)
  - First offense: 1.0x multiplier
  - Final: -0.15 reputation
- Hour 1: Penalty applied
- Hour 1-720: Compensation clawback (last 30 days)

Recovery:
- Gateway enters probation period (90 days at 50% rate)
- Must maintain <2% deviation for full period
- Reputation rebuilds through clean operation
```

#### Example 3: Equivocation (Conflicting Signatures)

```
Scenario: Node signs conflicting messages for same block

Timeline:
- Block N: Node signs block hash A
- Block N: Node signs block hash B (equivocation detected)
- T+0: Proof submitted by observing peer
- T+0-72h: Consensus enforcement initiated
  - 3 arbitrators selected
  - Evidence distributed
  - Voting period: 72 hours
- T+72h: Consensus reached (unanimous: guilty)
- T+72h: Penalties applied:
  - Reputation: SevereViolationPenalty (-0.15)
  - Stake: 50% slashed
  - Role: Demoted from any leadership positions

Appeal:
- Node may appeal within 72 hours
- Must stake 50 coins
- Arbitrator committee reviews
- If evidence is cryptographically valid, appeal likely denied
```

#### Example 4: Collusion Detection

```
Scenario: Pattern analysis reveals coordinated voting manipulation

Timeline:
- Day 0-30: Pattern accumulation
  - Multiple nodes vote identically on all proposals
  - Transaction analysis shows stake consolidation
  - Communication pattern suggests coordination
- Day 30: Pattern threshold exceeded
- Day 30: Consensus enforcement initiated
  - Evidence package compiled
  - 3 AI arbitrators assigned
  - Full investigation begins
- Day 30-33: Evidence review period
- Day 33: Consensus reached
- Day 33: Penalties applied to all colluding nodes:
  - Reputation: CriticalViolationPenalty (-0.30) + permanent ban
  - Stake: 100% slashed
  - Access: TPM identities blacklisted permanently

Appeal:
- Level 3 community appeal only
- Requires 200 coin stake per appellant
- 14-day voting period
- Extremely high bar for reversal (new exculpatory evidence)
```

---

## Economic Attack Mitigations

This section consolidates defenses against economic attacks on the protocol.

### CA Operator Extraction Prevention (E3 - CANONICAL)

CA operators may attempt to slow-roll certificate signing to extract bribes or preferential treatment. The protocol prevents this through randomized assignment and strict SLAs.

#### Random CA Assignment

```go
// CAAssignment uses VRF for unpredictable operator selection
type CAAssignment struct {
    CertificateRequestID [32]byte      // Request being processed
    BlockHash            [32]byte      // Block providing randomness
    VRFProof             []byte        // Proof of correct selection
    AssignedOperators    [][32]byte    // Selected CA operators (3 of N)
    BackupOperators      [][32]byte    // Backup if primary fails SLA
    AssignedAt           time.Time
    SLADeadline          time.Time     // Must complete by this time
}

// SelectCAOperators randomly assigns certificate request to operators
func SelectCAOperators(
    requestID [32]byte,
    blockHash [32]byte,
    eligibleOperators []NodeID,
    requiredSignatures int,
    vrfPrivateKey []byte,
) (*CAAssignment, error) {
    // Generate VRF output for unpredictable selection
    seed := computeVRFSeed(requestID, blockHash)
    vrfOutput, vrfProof, err := vrf.Prove(vrfPrivateKey, seed)
    if err != nil {
        return nil, err
    }

    // Shuffle operators using VRF output
    shuffled := shuffleWithSeed(eligibleOperators, vrfOutput)

    // Select primary operators
    primaryCount := requiredSignatures
    primary := shuffled[:primaryCount]

    // Select backup operators
    backupCount := requiredSignatures
    backup := shuffled[primaryCount:primaryCount+backupCount]

    return &CAAssignment{
        CertificateRequestID: requestID,
        BlockHash:            blockHash,
        VRFProof:             vrfProof,
        AssignedOperators:    primary,
        BackupOperators:      backup,
        AssignedAt:           time.Now(),
        SLADeadline:          time.Now().Add(CASLATimeout),
    }, nil
}
```

#### CA SLA Requirements

```go
// CASLAConfig defines service level requirements for CA operators
type CASLAConfig struct {
    // Maximum time to sign a certificate request
    MaxSigningTime      time.Duration // Default: 1 hour
    // Penalty for missing SLA
    SLAMissPenalty      uint64        // Default: 100 coins
    // Number of SLA misses before suspension
    MaxSLAMisses        int           // Default: 3 per 30 days
    // Suspension duration after max misses
    SuspensionDuration  time.Duration // Default: 7 days
    // Reward for on-time signing
    OnTimeReward        uint64        // Default: 10 coins
}

// DefaultCASLAConfig returns production SLA parameters
func DefaultCASLAConfig() CASLAConfig {
    return CASLAConfig{
        MaxSigningTime:     time.Hour,
        SLAMissPenalty:     100,
        MaxSLAMisses:       3,
        SuspensionDuration: 7 * 24 * time.Hour,
        OnTimeReward:       10,
    }
}

// EnforceCASLA checks and enforces SLA compliance
func EnforceCASLA(
    assignment *CAAssignment,
    completionTime time.Time,
    config CASLAConfig,
) *SLAResult {
    signingDuration := completionTime.Sub(assignment.AssignedAt)

    if signingDuration > config.MaxSigningTime {
        // SLA violated
        return &SLAResult{
            Violated:      true,
            Penalty:       config.SLAMissPenalty,
            Duration:      signingDuration,
            Deadline:      assignment.SLADeadline,
            OperatorIDs:   assignment.AssignedOperators,
        }
    }

    // SLA met - distribute rewards
    return &SLAResult{
        Violated:    false,
        Reward:      config.OnTimeReward,
        Duration:    signingDuration,
        OperatorIDs: assignment.AssignedOperators,
    }
}
```

**CA SLA Parameters (E3):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max signing time | 1 hour | Prevents indefinite delays |
| SLA miss penalty | 100 coins | Economic disincentive |
| Max misses (30 days) | 3 | Allows occasional issues |
| Suspension duration | 7 days | Significant impact on earnings |
| On-time reward | 10 coins | Positive incentive |

**Automatic Failover:**
- If primary operators miss SLA, request automatically routes to backups
- Primary operators still receive penalty even if backup completes
- Backup operators receive bonus for picking up slack

### Free-Rider Prevention (E4 - CANONICAL)

Nodes must contribute work to receive DDoS protection. Free-riders who consume protection without contributing are excluded.

#### Work Credits System

```go
// WorkCredits tracks node contributions for DDoS protection eligibility
type WorkCredits struct {
    NodeID             [32]byte
    CreditsEarned      uint64          // Total credits earned
    CreditsConsumed    uint64          // Credits used for protection
    CurrentBalance     int64           // Can go negative (debt)
    LastContribution   time.Time
    ContributionHistory []WorkContribution
}

// WorkContribution records a single contribution
type WorkContribution struct {
    WorkType        WorkType
    UnitsCompleted  uint64
    CreditsEarned   uint64
    Timestamp       time.Time
    VerifiedBy      [][32]byte      // Nodes that verified this work
}

// WorkCreditsConfig defines the work-for-protection parameters
type WorkCreditsConfig struct {
    // Credits required per hour of DDoS protection
    ProtectionCostPerHour uint64        // Default: 100 credits
    // Credits earned per work unit
    CreditsPerPowVerification uint64    // Default: 1 credit
    CreditsPerTrafficScrubGB  uint64    // Default: 10 credits
    CreditsPerChallengeGen    uint64    // Default: 5 credits
    // Maximum credit debt before protection disabled
    MaxDebtCredits        int64         // Default: -500 credits
    // Grace period for new nodes
    NewNodeGracePeriod    time.Duration // Default: 24 hours
}

// DefaultWorkCreditsConfig returns production values
func DefaultWorkCreditsConfig() WorkCreditsConfig {
    return WorkCreditsConfig{
        ProtectionCostPerHour:     100,
        CreditsPerPowVerification: 1,
        CreditsPerTrafficScrubGB:  10,
        CreditsPerChallengeGen:    5,
        MaxDebtCredits:            -500,
        NewNodeGracePeriod:        24 * time.Hour,
    }
}

// IsEligibleForProtection checks if node qualifies for DDoS protection
func (wc *WorkCredits) IsEligibleForProtection(config WorkCreditsConfig, nodeAge time.Duration) bool {
    // New nodes get grace period
    if nodeAge < config.NewNodeGracePeriod {
        return true
    }

    // Check credit balance
    if wc.CurrentBalance < config.MaxDebtCredits {
        return false // Too much debt
    }

    // Check recent activity (must have contributed in last 7 days)
    if time.Since(wc.LastContribution) > 7*24*time.Hour {
        return false // Inactive
    }

    return true
}

// ConsumeProtection deducts credits for DDoS protection
func (wc *WorkCredits) ConsumeProtection(hours float64, config WorkCreditsConfig) error {
    cost := uint64(float64(config.ProtectionCostPerHour) * hours)
    wc.CreditsConsumed += cost
    wc.CurrentBalance -= int64(cost)

    if wc.CurrentBalance < config.MaxDebtCredits {
        return ErrCreditDebtExceeded
    }

    return nil
}
```

**Work-for-Protection Rules (E4):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Protection cost | 100 credits/hour | Sustainable contribution rate |
| PoW verification | 1 credit/verification | Base work unit |
| Traffic scrubbing | 10 credits/GB | Higher-value work |
| Max debt | -500 credits | ~5 hours grace |
| New node grace | 24 hours | Allows bootstrapping |
| Activity requirement | 7 days | Prevents dormant free-riding |

**Free-Rider Consequences:**
- Protection disabled when credit debt exceeds -500
- Node must earn credits before protection resumes
- Inactive nodes (no contribution in 7 days) lose protection
- Repeat free-riders flagged for additional scrutiny

### Cross-Shard MEV Prevention (E5 - CANONICAL)

Cross-shard transactions can be front-run by observers who see pending transactions. Commit-reveal schemes prevent this.

#### Commit-Reveal Protocol

```go
// CrossShardCommit represents the commit phase of a cross-shard transaction
type CrossShardCommit struct {
    CommitID        [32]byte          // Hash of revealed data
    SourceShard     uint32            // Originating shard
    TargetShard     uint32            // Destination shard
    CommitHash      [32]byte          // H(transaction || secret || nonce)
    CommitTimestamp int64             // When commit was made
    CommitBlock     uint64            // Block containing commit
    SubmitterID     [32]byte          // Node that submitted commit
    Stake           uint64            // Stake locked with commit
}

// CrossShardReveal represents the reveal phase
type CrossShardReveal struct {
    CommitID        [32]byte          // Matches commit
    Transaction     []byte            // Full transaction data
    Secret          [32]byte          // Random secret used in commit
    Nonce           uint64            // Nonce used in commit
    RevealTimestamp int64
    RevealBlock     uint64
}

// CrossShardMEVConfig defines commit-reveal parameters
type CrossShardMEVConfig struct {
    // Minimum blocks between commit and reveal
    MinRevealDelay      uint64        // Default: 5 blocks
    // Maximum blocks before commit expires
    MaxRevealDelay      uint64        // Default: 100 blocks
    // Stake required with commit (prevents spam)
    // E3 Fix: Increased from 10 to 100 coins to prevent commit spam attacks
    CommitStake         uint64        // Default: 100 coins (E3: was 10)
    // Penalty for not revealing
    NoRevealPenalty     uint64        // Default: 100 coins (full stake)
    // Penalty for invalid reveal
    InvalidRevealPenalty uint64       // Default: 50 coins (half stake)
}

// DefaultCrossShardMEVConfig returns production values
// E3 Fix: Commit stake increased 10x to prevent MEV manipulation
// at low cost. With 10-coin stake, an attacker could submit millions
// of spam commits to clog cross-shard channels. At 100 coins, the
// economic barrier makes spam attacks costly while remaining
// accessible for legitimate high-value cross-shard transactions.
func DefaultCrossShardMEVConfig() CrossShardMEVConfig {
    return CrossShardMEVConfig{
        MinRevealDelay:       5,
        MaxRevealDelay:       100,
        CommitStake:          100,  // E3: was 10
        NoRevealPenalty:      100,  // E3: was 10 (matches stake)
        InvalidRevealPenalty: 50,   // E3: was 5 (half of stake)
    }
}

// CreateCommit generates a commit for cross-shard transaction
func CreateCommit(
    tx []byte,
    sourceShard, targetShard uint32,
    submitter [32]byte,
) (*CrossShardCommit, *CrossShardReveal, error) {
    // Generate random secret
    var secret [32]byte
    if _, err := rand.Read(secret[:]); err != nil {
        return nil, nil, err
    }

    // Generate nonce
    nonce := uint64(time.Now().UnixNano())

    // Create commit hash: H(tx || secret || nonce)
    commitData := append(tx, secret[:]...)
    commitData = append(commitData, uint64ToBytes(nonce)...)
    commitHash := sha256.Sum256(commitData)

    commitID := sha256.Sum256(commitHash[:])

    commit := &CrossShardCommit{
        CommitID:        commitID,
        SourceShard:     sourceShard,
        TargetShard:     targetShard,
        CommitHash:      commitHash,
        CommitTimestamp: time.Now().Unix(),
        SubmitterID:     submitter,
    }

    reveal := &CrossShardReveal{
        CommitID:    commitID,
        Transaction: tx,
        Secret:      secret,
        Nonce:       nonce,
    }

    return commit, reveal, nil
}

// VerifyReveal validates a reveal against its commit
func VerifyReveal(commit *CrossShardCommit, reveal *CrossShardReveal, currentBlock uint64) error {
    // Check commit ID matches
    if commit.CommitID != reveal.CommitID {
        return ErrCommitIDMismatch
    }

    // Check reveal timing
    blocksSinceCommit := currentBlock - commit.CommitBlock
    if blocksSinceCommit < MinRevealDelay {
        return &ErrRevealTooEarly{
            BlocksSinceCommit: blocksSinceCommit,
            MinRequired:       MinRevealDelay,
        }
    }
    if blocksSinceCommit > MaxRevealDelay {
        return &ErrRevealTooLate{
            BlocksSinceCommit: blocksSinceCommit,
            MaxAllowed:        MaxRevealDelay,
        }
    }

    // Verify commit hash
    commitData := append(reveal.Transaction, reveal.Secret[:]...)
    commitData = append(commitData, uint64ToBytes(reveal.Nonce)...)
    expectedHash := sha256.Sum256(commitData)

    if expectedHash != commit.CommitHash {
        return ErrInvalidReveal
    }

    return nil
}
```

**Commit-Reveal Parameters (E5):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Min reveal delay | 5 blocks | Prevents same-block front-running |
| Max reveal delay | 100 blocks | Prevents indefinite locking |
| Commit stake | 10 coins | Prevents commit spam |
| No-reveal penalty | 10 coins | Full stake lost |
| Invalid reveal penalty | 5 coins | Partial stake lost |

**MEV Prevention Properties:**
- Transaction details hidden until reveal window opens
- All observers see commit at same time
- Minimum delay ensures transaction ordering is fixed before reveal
- Stake requirement prevents costless commit spam

---

## Summary of Key Parameters

### Governance Parameters

| Parameter | Value |
|-----------|-------|
| Signaling threshold | 75% of active nodes |
| Timeout deadline | 90 days from approval |
| Approval supermajority | 67% YES votes |
| Participation minimum | 0.01% circulating supply |
| Voting period | 30 days |
| Emergency activation | 7 days |
| Technical review | 14 days maximum |
| **Pre-snapshot holding (E10)** | **72 hours** (CANONICAL) |
| **Post-vote unlock (E10)** | **3 days** |
| **Min confirmations (E10)** | **100 blocks** |
| **Snapshot block requirement** | **FINALIZED** (not just confirmed) |
| **Flash loan detection threshold** | **10x increase within 24 hours** |
| **Allowlisted vote sources** | Mining, Staking rewards |
| **Double-vote prevention** | Atomic CAS + DB unique constraint |

### Economic Parameters

| Parameter | Value |
|-----------|-------|
| Base fee rate | 0.00001 coins/byte |
| Minimum fee | 1 satoshi |
| Maximum transaction size | 1 MB |
| Validator fee share | 70% |
| Foundation fee share | 15% |
| Treasury fee share | 15% |
| Provider stake minimum | **1,000 coins** per listing (CANONICAL) |
| Additional listing stake | Exponential (2^(n-1) x 1000) |
| Advertisement fee | 0.001 coins |
| Rate limit | 10 updates/100 blocks |
| **Network size scaling (E6)** | **sqrt(N)/100 multiplier** |
| **Max storage multiplier (E7)** | **10x** (reduced from 100x) |
| **Min routing activity (E7)** | **20%** |

### Gateway Parameters

| Parameter | Value |
|-----------|-------|
| Probation duration | 90 days |
| Probation rate | 50% of normal |
| Uptime requirement | > 99% |
| Report frequency | Hourly |
| Over-reporting threshold | **50 permille (5%)** (CANONICAL) |
| Cumulative deviation limit | **200 permille (20%)** |
| Average deviation limit | **> 20 permille (2%)** over 100+ reports |
| Outlier detection | > 3 sigma (3000 x1000) |
| Service rewards pool | 75% of emissions |
| Validator rewards | 25% of emissions |
| **Max traffic share (E8)** | **15%** |
| **Selection rotation (E8)** | **1 hour** |
| **Sliding window duration** | **30 days** |
| **Clean period for reset** | **30 days** |
| **Threshold format** | **Permille (integer-based)** |

### Service Reward Verification Parameters (E7)

| Parameter | Value |
|-----------|-------|
| Min routing witnesses | 2 independent peers |
| Witness byte tolerance | 50 permille (5%) |
| Storage challenge max age | 1 hour |
| Self-witnessing | Prohibited |
| Endpoint witnessing | Prohibited |
| Duplicate witnesses | Prohibited |

### CA SLA Parameters (E3)

| Parameter | Value |
|-----------|-------|
| Max signing time | 1 hour |
| SLA miss penalty | 100 coins |
| Max misses (30 days) | 3 |
| Suspension duration | 7 days |
| On-time reward | 10 coins |

### Work Credits Parameters (E4)

| Parameter | Value |
|-----------|-------|
| Protection cost | 100 credits/hour |
| PoW verification credit | 1 credit |
| Traffic scrubbing credit | 10 credits/GB |
| Max debt | -500 credits |
| New node grace period | 24 hours |
| Activity requirement | 7 days |

### Cross-Shard MEV Parameters (E5)

| Parameter | Value |
|-----------|-------|
| Min reveal delay | 5 blocks |
| Max reveal delay | 100 blocks |
| Commit stake | 10 coins |
| No-reveal penalty | 10 coins |
| Invalid reveal penalty | 5 coins |

### Privacy Parameters

| Parameter | Value |
|-----------|-------|
| Commitment size | ~64 bytes/output |
| Range proof size | ~700-1000 bytes |
| Verification overhead | ~2-3ms/output |
| Stealth key overhead | ~32 bytes |
| Timing jitter (Low) | 0-30 seconds |
| Dandelion++ latency | 1-3 minutes |
| Onion routing latency | 5-10 minutes |

### Penalty Enforcement Parameters

Reference: [00-CONSTANTS.md](00-CONSTANTS.md) Section 4 (Penalty Constants)

| Parameter | Value | Description |
|-----------|-------|-------------|
| **MinorViolationPenalty** | -0.01 | Single heartbeat miss, rate limit exceed |
| **ModerateViolationPenalty** | -0.05 | Failed attestation, DKG timeout |
| **SevereViolationPenalty** | -0.15 | Nonce reuse, equivocation, false accusation |
| **CriticalViolationPenalty** | -0.30 | Collusion, vote selling |
| **MaxDailyPenalty** | -0.10 | Cumulative cap per 24-hour period |

**Enforcement Tiers:**

| Tier | Processing Time | Verification |
|------|-----------------|--------------|
| Tier 1: Immediate | < 3 seconds | Automated |
| Tier 2: Delayed | 1 min - 30 days | Pattern verification |
| Tier 3: Consensus | 72 hours | Multi-party (3 arbitrators) |

**Repeat Offender Multipliers:**

| Violations (30 days) | Multiplier |
|---------------------|------------|
| 1 | 1.0x |
| 2 | 1.5x |
| 3 | 2.0x |
| 4+ | 2.5x-3.0x (capped) |

**Appeal Parameters:**

| Level | Stake | Deadline |
|-------|-------|----------|
| Level 1 (Automated) | 10 coins | 24 hours |
| Level 2 (Arbitrator) | 50 coins | 72 hours |
| Level 3 (Community) | 200 coins | 14 days |

**Stake Slash Percentages:**

| Violation | Slash |
|-----------|-------|
| DKG timeout | 1-5% |
| Equivocation | 50% |
| Collusion/Vote selling | 100% |

---

## Cross-References

- **Canonical Constants**: See [00-CONSTANTS.md](00-CONSTANTS.md) for all penalty values, timing constants, and thresholds
- **Arbiter Collusion Prevention (E1)**: See [09-defense-reputation.md](09-defense-reputation.md) Section "PBFT-Style Quorum Judgment"
- **Confirmation Collusion Rings (E2)**: See [09-defense-reputation.md](09-defense-reputation.md) Section "Confirmation Collusion Ring Prevention"
- **Reputation Grinding (E9)**: See [09-defense-reputation.md](09-defense-reputation.md) Section "Reputation Grinding Prevention"
- **DDoS Protection**: See [16-ddos-protection.md](16-ddos-protection.md)
- **Security Trust Model**: See [03-security-trust.md](03-security-trust.md)

---

**Version:** 1.3
**Last Updated:** 2026-01-10
**Status:** Consolidated Specification with Penalty Enforcement System

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-10 | 1.3 | Added comprehensive Penalty Enforcement System section including: violation triggers (Tier 1/2/3), detection mechanisms, penalty calculation formula with repeat offender escalation, enforcement authority matrix, appeals process (3 levels), penalty types (reputation/stake/access), enforcement timeline, and common violation examples |
| 2026-01-10 | 1.2 | Enhanced snapshot balance verification with VoteEligibility TPM binding and finalized block requirement; Added atomic CAS with database unique constraint for double-vote prevention; Updated flash loan protection to 72-hour lockup with source allowlisting and 10x/24h detection; Added service reward verification with peer witness requirements (2 independent) and storage challenge-response; Improved gateway fraud detection with sliding window, 30-day clean reset, and integer-based permille thresholds |
| 2026-01-09 | 1.1 | Added E3 CA Operator Extraction prevention, E4 Free-Rider work credits, E5 Cross-Shard MEV commit-reveal, E6 Sybil economics scaling, E7 Storage/routing reward rebalancing, E8 Gateway selection fairness, E10 Flash loan lockup requirements |
| 2025-12-30 | 1.0 | Initial consolidated document |

# QuicBaaS Schema for DHT State Storage

## Revision History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | 2024-01-01 | Initial schema - Node, UTXO, Reputation, Certificate, DKG, Partition |
| 1.1 | 2024-06-01 | Added Three-Phase Commit state |
| 1.2 | 2024-09-01 | Added typed error definitions |
| 1.3 | 2026-01-10 | Added OrganizationID to NodeState, TPMTier to TPMInfo, OrganizationState schema |

---

## Overview

QuicBaaS serves as the persistence layer for all DHT state in the go-trusted-platform network. As a Multi-Raft distributed key-value store, QuicBaaS provides strong consistency guarantees, automatic sharding, and cross-region replication for critical DHT state.

> **Cross-References:**
> - System overview: [01-system-overview.md](01-system-overview.md) (QuicBaaS Platform Layer)
> - Currency and transactions: [07-currency-transactions.md](07-currency-transactions.md) (UTXO sharding)
> - Defense and reputation: [09-defense-reputation.md](09-defense-reputation.md) (reputation scoring)
> - Certificate authority: [05-certificate-authority.md](05-certificate-authority.md) (certificate state)
> - Consensus coordination: [06-consensus-coordination.md](06-consensus-coordination.md) (DKG sessions)
> - FROST key lifecycle: [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) (FROST share storage)

---

## DHT-QuicBaaS Relationship

```
+-------------------------------------------------------------------------+
|                         TRUSTED DHT NETWORK                             |
|  +-------------------------------------------------------------------+  |
|  |  Coordinator | Gateway | Hub | CA Participant | Leaf Node         |  |
|  +-------------------------------+-----------------------------------+  |
+----------------------------------+--------------------------------------+
                                   |
                                   | State Persistence (gRPC/QUIC/Unix)
                                   v
+-------------------------------------------------------------------------+
|                       QUICBAAS PLATFORM LAYER                           |
|                                                                         |
|  +--------------------+  +--------------------+  +--------------------+ |
|  |   MULTI-RAFT KV    |  |     SHARDING       |  |   REPLICATION     | |
|  |                    |  |                    |  |                    | |
|  | - Strong consensus |  | - Consistent hash  |  | - Cross-region    | |
|  | - Linearizable     |  | - Auto-balancing   |  | - Async/sync      | |
|  | - Point-in-time    |  | - Shard splitting  |  | - Geo-aware       | |
|  +--------------------+  +--------------------+  +--------------------+ |
|                                                                         |
|  STATE CATEGORIES:                                                      |
|  +-------------+ +-------------+ +-------------+ +-------------+        |
|  |    Node     | |   Routing   | |    UTXO     | | Reputation  |        |
|  |    State    | |   Tables    | |    State    | |   Records   |        |
|  +-------------+ +-------------+ +-------------+ +-------------+        |
|  +-------------+ +-------------+ +-------------+                        |
|  | Certificate | |     DKG     | |  Partition  |                        |
|  |    State    | |  Sessions   | |    State    |                        |
|  +-------------+ +-------------+ +-------------+                        |
|                                                                         |
+-------------------------------------------------------------------------+
```

**Key Properties:**

| Property | Value | Description |
|----------|-------|-------------|
| Consistency | Linearizable | All reads see most recent write |
| Availability | CP (CAP) | Prioritizes consistency over availability |
| Partition Tolerance | Yes | Continues operating during network partitions |
| Replication | Configurable | 3-7 replicas per shard |
| Sharding | Consistent Hash | DHT-aligned key distribution |

---

## Schema Definitions

### Node State

Node state represents the complete identity and status of a DHT participant.

```go
// NodeState represents the persistent state of a DHT node
type NodeState struct {
    // Identity
    NodeID         [32]byte  `json:"node_id"`         // SHA256 of IDevID public key
    PublicKey      []byte    `json:"public_key"`      // Ed25519 or ECDSA P-256 public key
    IDevID         []byte    `json:"idevid"`          // DER-encoded IDevID certificate
    OrganizationID [32]byte  `json:"organization_id"` // SHA256 hash binding node to verified organization

    // Trust and Role
    Reputation  float64   `json:"reputation"`    // 0.0 to 1.0 score
    Role        NodeRole  `json:"role"`          // leaf, hub, gateway, coordinator, ca_participant
    RoleHistory []RoleTransition `json:"role_history"` // Historical role changes

    // Network Connectivity
    Endpoints   []Endpoint `json:"endpoints"`    // Network addresses
    LastSeen    int64      `json:"last_seen"`    // Unix timestamp of last activity
    JoinedAt    int64      `json:"joined_at"`    // Unix timestamp of network join

    // TPM Information
    TPMInfo     *TPMInfo   `json:"tpm_info"`     // Hardware attestation details

    // Metadata
    Version     uint64     `json:"version"`      // Optimistic concurrency control
    UpdatedAt   int64      `json:"updated_at"`   // Last modification timestamp
}

// NodeRole represents the node's current role in the network
type NodeRole uint8

const (
    NodeRoleLeaf          NodeRole = iota // Rep 0.0+: Basic DHT participant
    NodeRoleCAParticipant                 // Rep 0.90+: FROST signing pool member
    NodeRoleHub                           // Rep 0.80+: Routing hub
    NodeRoleGateway                       // Rep 0.85+: External bridge
    NodeRoleCoordinator                   // Rep 0.95+: Consensus leader
)

// Endpoint represents a network address for a node
type Endpoint struct {
    Protocol    string `json:"protocol"`     // tcp, udp, quic
    Address     string `json:"address"`      // IPv6 address or hostname
    Port        uint16 `json:"port"`         // Port number
    Priority    uint8  `json:"priority"`     // 0 = primary, higher = fallback
    LastVerified int64 `json:"last_verified"` // Last successful connection
}

// TPMInfo contains hardware attestation details
type TPMInfo struct {
    Manufacturer    string   `json:"manufacturer"`     // TPM manufacturer
    FirmwareVersion string   `json:"firmware_version"` // TPM firmware version
    EKCertHash      [32]byte `json:"ek_cert_hash"`     // SHA256 of EK certificate
    PCRValues       []PCRValue `json:"pcr_values"`     // Last attested PCR state
    LastAttestation int64    `json:"last_attestation"` // Unix timestamp
    AttestationValid bool    `json:"attestation_valid"` // Current validity
    TPMTier         TPMTier  `json:"tpm_tier"`         // Classification of TPM type
}

// TPMTier classifies the type of TPM implementation
type TPMTier uint8

const (
    TPMTierHardware TPMTier = 1 // Physical hardware TPM (discrete or integrated)
    TPMTierFirmware TPMTier = 2 // Firmware-based TPM (fTPM in TEE)
    TPMTierCloud    TPMTier = 3 // Cloud-based vTPM (AWS Nitro, Azure vTPM, GCP vTPM)
    TPMTierPlatform TPMTier = 4 // Software TPM (swtpm for development/testing)
)

// PCRValue represents a single PCR measurement
type PCRValue struct {
    Index   uint8    `json:"index"`   // PCR index (0-23)
    Value   [32]byte `json:"value"`   // SHA256 digest
    Bank    string   `json:"bank"`    // sha256, sha384, sha512
}

// RoleTransition records a role change event
type RoleTransition struct {
    FromRole    NodeRole `json:"from_role"`
    ToRole      NodeRole `json:"to_role"`
    Timestamp   int64    `json:"timestamp"`
    Reason      string   `json:"reason"`      // promotion, demotion, penalty
    ReputationAt float64 `json:"reputation_at"` // Reputation at transition
}
```

**DHT Key:** `node:{node-id}`

---

### Routing Tables

Routing tables store the Kademlia k-bucket state for each node.

```go
// RoutingTable represents a node's complete Kademlia routing state
type RoutingTable struct {
    OwnerNodeID [32]byte      `json:"owner_node_id"` // Node that owns this table
    Buckets     []KBucket     `json:"buckets"`       // 256 k-buckets (one per bit)
    LastUpdated int64         `json:"last_updated"`  // Last modification timestamp
    Version     uint64        `json:"version"`       // Optimistic concurrency
}

// KBucket represents a single k-bucket in the routing table
type KBucket struct {
    BucketID      uint8         `json:"bucket_id"`      // 0-255 (XOR distance prefix)
    Nodes         []BucketNode  `json:"nodes"`          // Nodes in this bucket (max k=20)
    ReplacementCache []BucketNode `json:"replacement_cache"` // Pending replacements
    LastUpdated   int64         `json:"last_updated"`   // Last bucket modification
}

// BucketNode represents a node entry in a k-bucket
type BucketNode struct {
    NodeID      [32]byte `json:"node_id"`       // Node identifier
    Endpoints   []Endpoint `json:"endpoints"`   // Network addresses
    LastSeen    int64    `json:"last_seen"`     // Last successful contact
    FailCount   uint8    `json:"fail_count"`    // Consecutive failures
    Reputation  float64  `json:"reputation"`    // Cached reputation score
    Latency     uint32   `json:"latency_ms"`    // Average RTT in milliseconds
}

// RoutingTableStats provides routing table metrics
type RoutingTableStats struct {
    TotalNodes       uint32  `json:"total_nodes"`
    ActiveBuckets    uint8   `json:"active_buckets"`
    AverageLatency   uint32  `json:"average_latency_ms"`
    StaleNodeCount   uint32  `json:"stale_node_count"`
    ReplacementQueue uint32  `json:"replacement_queue"`
}
```

**DHT Key:** `routing:{node-id}`

---

### UTXO State

UTXO state represents the unspent transaction outputs for wallets.

```go
// UTXOState represents a wallet's complete UTXO state
type UTXOState struct {
    WalletID    [32]byte    `json:"wallet_id"`    // SHA256 of wallet public key
    Balance     uint64      `json:"balance"`      // Total unspent balance
    UTXOs       []UTXO      `json:"utxos"`        // List of unspent outputs
    Sequence    uint64      `json:"sequence"`     // Monotonic sequence number
    ShardID     uint16      `json:"shard_id"`     // Authoritative shard
    LastTxID    [32]byte    `json:"last_tx_id"`   // Most recent transaction
    UpdatedAt   int64       `json:"updated_at"`   // Last modification
    Version     uint64      `json:"version"`      // Optimistic concurrency
}

// UTXO represents a single unspent transaction output
type UTXO struct {
    TxID          [32]byte `json:"tx_id"`          // Source transaction ID
    OutputIndex   uint8    `json:"output_index"`   // Index within transaction
    Amount        uint64   `json:"amount"`         // Unspent amount
    CreatedAt     int64    `json:"created_at"`     // Creation timestamp
    LockScript    []byte   `json:"lock_script"`    // Spending conditions
    LockedUntil   int64    `json:"locked_until"`   // Time lock (0 = unlocked)
}

// PendingTransaction represents a transaction awaiting confirmation
type PendingTransaction struct {
    TxID        [32]byte    `json:"tx_id"`
    FromWallet  [32]byte    `json:"from_wallet"`
    ToWallet    [32]byte    `json:"to_wallet"`
    Amount      uint64      `json:"amount"`
    Fee         uint64      `json:"fee"`
    Sequence    uint64      `json:"sequence"`
    Inputs      []UTXORef   `json:"inputs"`
    Outputs     []TxOutput  `json:"outputs"`
    TPMQuote    []byte      `json:"tpm_quote"`
    Signature   []byte      `json:"signature"`
    SubmittedAt int64       `json:"submitted_at"`
    ExpiresAt   int64       `json:"expires_at"`
    State       TxState     `json:"state"`
}

// UTXORef references a specific UTXO
type UTXORef struct {
    TxID        [32]byte `json:"tx_id"`
    OutputIndex uint8    `json:"output_index"`
}

// TxOutput represents a transaction output
type TxOutput struct {
    WalletID   [32]byte `json:"wallet_id"`
    Amount     uint64   `json:"amount"`
    LockScript []byte   `json:"lock_script"`
}

// TxState represents transaction lifecycle state
type TxState uint8

const (
    TxStatePending   TxState = iota // Awaiting confirmation
    TxStateConfirmed                 // Confirmed by network
    TxStateRejected                  // Rejected (double-spend, invalid)
    TxStateExpired                   // TTL expired without confirmation
)

// ShardUTXOSummary provides shard-level UTXO statistics
type ShardUTXOSummary struct {
    ShardID         uint16 `json:"shard_id"`
    TotalWallets    uint64 `json:"total_wallets"`
    TotalBalance    uint64 `json:"total_balance"`
    TotalUTXOs      uint64 `json:"total_utxos"`
    PendingTxCount  uint32 `json:"pending_tx_count"`
    LastBlockHeight uint64 `json:"last_block_height"`
}
```

**DHT Key:** `utxo:{wallet-id}`

---

### Reputation Records

Reputation records track node behavior and trust scores.

```go
// ReputationRecord represents a node's complete reputation state
type ReputationRecord struct {
    NodeID       [32]byte         `json:"node_id"`
    Score        float64          `json:"score"`        // 0.0 to 1.0
    History      []ReputationEvent `json:"history"`     // Historical changes
    Violations   []Violation      `json:"violations"`   // Recorded violations
    LastUpdate   int64            `json:"last_update"`  // Last score change
    DecayApplied int64            `json:"decay_applied"` // Last decay application
    Version      uint64           `json:"version"`
}

// ReputationEvent represents a single reputation change
type ReputationEvent struct {
    Timestamp   int64     `json:"timestamp"`
    Delta       float64   `json:"delta"`       // Positive or negative change
    Reason      RepReason `json:"reason"`      // What caused the change
    Evidence    [32]byte  `json:"evidence"`    // Hash of evidence (if violation)
    Witnesses   [][32]byte `json:"witnesses"`  // Nodes that corroborated
    NewScore    float64   `json:"new_score"`   // Score after this event
}

// RepReason categorizes reputation changes
type RepReason uint8

const (
    RepReasonRoutingSuccess   RepReason = iota // Successfully routed requests
    RepReasonStorageServed                     // Served stored content
    RepReasonConsensusParticipation            // Participated in consensus
    RepReasonCASigningSuccess                  // Successful CA signing
    RepReasonViolationPenalty                  // Penalty for violation
    RepReasonDecay                             // Natural decay over time
    RepReasonBootstrapBonus                    // Initial bootstrap bonus
)

// Violation represents a recorded protocol violation
type Violation struct {
    ViolationID   [32]byte        `json:"violation_id"`   // Unique identifier
    Type          ViolationType   `json:"type"`           // Violation category
    Severity      ViolationSeverity `json:"severity"`     // minor, moderate, major, critical
    Timestamp     int64           `json:"timestamp"`      // When detected
    Evidence      []byte          `json:"evidence"`       // Serialized evidence
    ReporterID    [32]byte        `json:"reporter_id"`    // Who reported
    Corroborators [][32]byte      `json:"corroborators"`  // Who confirmed
    JudgmentTxID  [32]byte        `json:"judgment_tx_id"` // PBFT judgment transaction
    PenaltyApplied float64        `json:"penalty_applied"` // Reputation deducted
    SlashAmount   uint64          `json:"slash_amount"`   // Tokens slashed
}

// ViolationType categorizes protocol violations
type ViolationType uint8

const (
    ViolationTypeRoutingFailure    ViolationType = iota // Failed to route requests
    ViolationTypeDataManipulation                       // Served invalid data
    ViolationTypeConsensusViolation                     // Consensus protocol breach
    ViolationTypeDoubleSigning                          // Signed conflicting statements
    ViolationTypeAttestationFraud                       // Invalid TPM attestation
    ViolationTypeSybilAttempt                           // Multiple identity attempt
)

// ViolationSeverity defines penalty levels
type ViolationSeverity uint8

const (
    ViolationSeverityMinor    ViolationSeverity = iota // -0.05 reputation
    ViolationSeverityModerate                          // -0.15 reputation
    ViolationSeverityMajor                             // -0.30 reputation
    ViolationSeverityCritical                          // Immediate expulsion
)

// ReputationRanking provides network-wide reputation statistics
type ReputationRanking struct {
    Percentile50 float64 `json:"percentile_50"` // Median score
    Percentile75 float64 `json:"percentile_75"`
    Percentile90 float64 `json:"percentile_90"`
    Percentile95 float64 `json:"percentile_95"`
    Percentile99 float64 `json:"percentile_99"`
    TotalNodes   uint64  `json:"total_nodes"`
    UpdatedAt    int64   `json:"updated_at"`
}
```

**DHT Key:** `rep:{node-id}`

---

### Certificate State

Certificate state tracks issued certificates and their lifecycle.

```go
// CertificateState represents a certificate's complete state
type CertificateState struct {
    CertHash     [32]byte       `json:"cert_hash"`     // SHA256 of certificate
    Certificate  []byte         `json:"certificate"`   // DER-encoded certificate
    CTProof      *CTProof       `json:"ct_proof"`      // Certificate Transparency proof
    IssuedAt     int64          `json:"issued_at"`     // Issue timestamp
    ExpiresAt    int64          `json:"expires_at"`    // Expiration timestamp
    Revoked      bool           `json:"revoked"`       // Revocation status
    RevocationInfo *RevocationInfo `json:"revocation_info"` // If revoked
    SubjectNodeID [32]byte      `json:"subject_node_id"` // Node this cert belongs to
    IssuerPoolID  [32]byte      `json:"issuer_pool_id"`  // FROST pool that signed
    CertType      CertType      `json:"cert_type"`     // idevid, ldevid, service
    Version       uint64        `json:"version"`
}

// CTProof represents Certificate Transparency proof
type CTProof struct {
    LogID        [32]byte `json:"log_id"`        // CT log identifier
    Timestamp    int64    `json:"timestamp"`     // SCT timestamp
    Signature    []byte   `json:"signature"`     // Log signature
    MerkleProof  [][]byte `json:"merkle_proof"`  // Inclusion proof
    TreeSize     uint64   `json:"tree_size"`     // Tree size at inclusion
    LeafIndex    uint64   `json:"leaf_index"`    // Index in Merkle tree
}

// RevocationInfo contains revocation details
type RevocationInfo struct {
    RevokedAt    int64          `json:"revoked_at"`
    Reason       RevocationReason `json:"reason"`
    RevokerNodeID [32]byte      `json:"revoker_node_id"` // Who initiated
    JudgmentTxID [32]byte       `json:"judgment_tx_id"`  // PBFT decision
    CRLEntry     []byte         `json:"crl_entry"`       // CRL entry bytes
}

// RevocationReason follows RFC 5280 reasons
type RevocationReason uint8

const (
    RevocationReasonUnspecified          RevocationReason = 0
    RevocationReasonKeyCompromise        RevocationReason = 1
    RevocationReasonCACompromise         RevocationReason = 2
    RevocationReasonAffiliationChanged   RevocationReason = 3
    RevocationReasonSuperseded           RevocationReason = 4
    RevocationReasonCessationOfOperation RevocationReason = 5
    RevocationReasonCertificateHold      RevocationReason = 6
    RevocationReasonPrivilegeWithdrawn   RevocationReason = 9
    RevocationReasonAACompromise         RevocationReason = 10
)

// CertType identifies the certificate purpose
type CertType uint8

const (
    CertTypeIDevID   CertType = iota // Initial Device ID
    CertTypeLDevID                   // Local Device ID
    CertTypeService                  // Service certificate
    CertTypeSigning                  // Code signing
    CertTypeTLS                      // TLS client/server
)

// CertificateIndex provides lookup by various fields
type CertificateIndex struct {
    ByNodeID      map[[32]byte][][32]byte `json:"by_node_id"`      // NodeID -> CertHashes
    ByExpiration  map[int64][][32]byte    `json:"by_expiration"`   // Expiry bucket -> CertHashes
    ByIssuerPool  map[[32]byte][][32]byte `json:"by_issuer_pool"`  // PoolID -> CertHashes
    RevokedCerts  [][32]byte              `json:"revoked_certs"`   // All revoked cert hashes
    ExpiringWithin24h [][32]byte          `json:"expiring_within_24h"`
}
```

**DHT Key:** `cert:{cert-hash}`

---

### DKG Sessions

DKG (Distributed Key Generation) session state for FROST signing pools.

```go
// DKGSession represents a distributed key generation session
type DKGSession struct {
    SessionID    [32]byte        `json:"session_id"`    // Unique session identifier
    Phase        DKGPhase        `json:"phase"`         // Current protocol phase
    Participants []DKGParticipant `json:"participants"` // Pool members
    Checkpoints  []DKGCheckpoint `json:"checkpoints"`   // Progress checkpoints
    Coordinator  [32]byte        `json:"coordinator"`   // Coordinating node
    Purpose      DKGPurpose      `json:"purpose"`       // Why DKG is running
    CreatedAt    int64           `json:"created_at"`
    ExpiresAt    int64           `json:"expires_at"`
    CompletedAt  int64           `json:"completed_at"`  // 0 if not complete
    ResultKeyID  [32]byte        `json:"result_key_id"` // Generated key ID
    Version      uint64          `json:"version"`
}

// DKGPhase represents the current DKG protocol phase
type DKGPhase uint8

const (
    DKGPhaseInitializing  DKGPhase = iota // Session setup
    DKGPhaseCommitment                    // Round 1: commitments
    DKGPhaseSharing                       // Round 2: secret shares
    DKGPhaseVerification                  // Verifying shares
    DKGPhaseFinalization                  // Computing group key
    DKGPhaseComplete                      // Successfully completed
    DKGPhaseFailed                        // Failed (timeout, malicious)
    DKGPhaseAborted                       // Coordinator aborted
)

// DKGParticipant represents a session participant
type DKGParticipant struct {
    NodeID          [32]byte         `json:"node_id"`
    ParticipantIndex uint8           `json:"participant_index"` // 1-based index
    PublicShare     []byte           `json:"public_share"`      // Feldman VSS commitment
    CommitmentHash  [32]byte         `json:"commitment_hash"`
    SharesReceived  map[uint8]bool   `json:"shares_received"`   // From whom
    SharesSent      map[uint8]bool   `json:"shares_sent"`       // To whom
    Complaints      []DKGComplaint   `json:"complaints"`        // Filed complaints
    Status          ParticipantStatus `json:"status"`
    JoinedAt        int64            `json:"joined_at"`
}

// ParticipantStatus tracks participant state
type ParticipantStatus uint8

const (
    ParticipantStatusActive     ParticipantStatus = iota
    ParticipantStatusComplete
    ParticipantStatusFailed
    ParticipantStatusEvicted    // Removed for misbehavior
)

// DKGCheckpoint records phase completion
type DKGCheckpoint struct {
    Phase          DKGPhase   `json:"phase"`
    Timestamp      int64      `json:"timestamp"`
    ParticipantAcks [][32]byte `json:"participant_acks"` // Who acknowledged
    StateHash      [32]byte   `json:"state_hash"`        // Hash of phase state
}

// DKGComplaint represents a complaint against a participant
type DKGComplaint struct {
    ComplainantID [32]byte `json:"complainant_id"`
    AccusedID     [32]byte `json:"accused_id"`
    AccusedIndex  uint8    `json:"accused_index"`
    Reason        string   `json:"reason"`
    Evidence      []byte   `json:"evidence"`     // Invalid share proof
    Timestamp     int64    `json:"timestamp"`
    Resolved      bool     `json:"resolved"`
    Resolution    string   `json:"resolution"`   // upheld, dismissed
}

// DKGPurpose describes why DKG is being run
type DKGPurpose uint8

const (
    DKGPurposeNewPool       DKGPurpose = iota // Creating new signing pool
    DKGPurposeReshare                         // Key resharing
    DKGPurposeRecovery                        // Recovery from failure
    DKGPurposeRotation                        // Scheduled rotation
    DKGPurposeEmergency                       // Emergency replacement
)

// DKGSessionSummary provides overview of DKG sessions
type DKGSessionSummary struct {
    ActiveSessions    uint32 `json:"active_sessions"`
    CompletedLast24h  uint32 `json:"completed_last_24h"`
    FailedLast24h     uint32 `json:"failed_last_24h"`
    AverageDurationMs uint64 `json:"average_duration_ms"`
}
```

**DHT Key:** `dkg:{session-id}`

---

### Partition State

Partition state tracks network partition handling and recovery.

```go
// PartitionState represents a network partition's state
type PartitionState struct {
    PartitionID    [32]byte         `json:"partition_id"`
    VectorClock    map[string]uint64 `json:"vector_clock"` // NodeID -> logical clock
    Members        [][32]byte       `json:"members"`       // Nodes in this partition
    TransactionLog []PartitionTx    `json:"transaction_log"` // Uncommitted transactions
    CreatedAt      int64            `json:"created_at"`    // Partition detected
    ResolvedAt     int64            `json:"resolved_at"`   // 0 if ongoing
    ResolutionType ResolutionType   `json:"resolution_type"`
    LeaderNodeID   [32]byte         `json:"leader_node_id"` // Partition leader
    Version        uint64           `json:"version"`
}

// PartitionTx represents a transaction during partition
type PartitionTx struct {
    TxID        [32]byte `json:"tx_id"`
    TxType      string   `json:"tx_type"`       // utxo, reputation, cert, etc.
    Payload     []byte   `json:"payload"`       // Serialized transaction
    Timestamp   int64    `json:"timestamp"`
    Sequence    uint64   `json:"sequence"`      // Partition-local sequence
    Committed   bool     `json:"committed"`     // Post-resolution commit status
    ConflictWith [32]byte `json:"conflict_with"` // If conflicts detected
}

// ResolutionType describes how partition was resolved
type ResolutionType uint8

const (
    ResolutionTypePending      ResolutionType = iota // Not yet resolved
    ResolutionTypeMerged                             // Partitions merged cleanly
    ResolutionTypeConflict                           // Required conflict resolution
    ResolutionTypeMajorityWins                       // Larger partition prevailed
    ResolutionTypeManual                             // Manual intervention required
)

// PartitionHealth tracks partition-related metrics
type PartitionHealth struct {
    CurrentPartitions   uint32    `json:"current_partitions"`
    PartitionsLast24h   uint32    `json:"partitions_last_24h"`
    AverageResolutionMs uint64    `json:"average_resolution_ms"`
    ConflictsResolved   uint32    `json:"conflicts_resolved"`
    PendingConflicts    uint32    `json:"pending_conflicts"`
}
```

**DHT Key:** `partition:{partition-id}`

---

### Organization State

Organization state represents a verified organization in the network registry. Organizations provide accountability for nodes through either domain verification or economic stake.

```go
// OrganizationState represents a verified organization in the network registry
type OrganizationState struct {
    // Primary key
    OrganizationID   [32]byte         `json:"organization_id"`   // SHA256 hash - primary key
    VerificationType VerificationType `json:"verification_type"` // Domain or Economic verification

    // Domain verification fields (VerificationType == VerificationTypeDomain)
    Domain        string `json:"domain,omitempty"`         // e.g., "example.com"
    DNSVerifiedAt int64  `json:"dns_verified_at,omitempty"` // Unix timestamp of last verification
    DNSExpiresAt  int64  `json:"dns_expires_at,omitempty"`  // 90 days from verification

    // Economic verification fields (VerificationType == VerificationTypeEconomic)
    WalletID        [32]byte `json:"wallet_id,omitempty"`         // Stake wallet identifier
    StakeAmount     uint64   `json:"stake_amount,omitempty"`      // 1,000 coins minimum
    StakeLockedUntil int64   `json:"stake_locked_until,omitempty"` // 180 days from deposit

    // Organization metadata
    NodeCount   uint32 `json:"node_count"`    // Number of nodes in this org
    CAPoolNodes uint32 `json:"ca_pool_nodes"` // Nodes currently in CA pool
    CreatedAt   int64  `json:"created_at"`    // Unix timestamp of creation
    UpdatedAt   int64  `json:"updated_at"`    // Unix timestamp of last update

    // Slashing state
    SlashedAmount     uint64 `json:"slashed_amount"`               // Total amount slashed
    BanExpiresAt      int64  `json:"ban_expires_at,omitempty"`     // If temporarily banned (Unix timestamp)
    PermanentlyBanned bool   `json:"permanently_banned"`           // If permanently banned

    // Optimistic concurrency control
    Version uint64 `json:"version"`
}

// VerificationType defines how an organization was verified
type VerificationType uint8

const (
    VerificationTypeDomain   VerificationType = 1 // Verified via DNS TXT record
    VerificationTypeEconomic VerificationType = 2 // Verified via economic stake
)

// OrganizationIndex provides lookup structures for organizations
type OrganizationIndex struct {
    ByDomain    map[string][32]byte      `json:"by_domain"`    // Domain -> OrganizationID
    ByWallet    map[[32]byte][32]byte    `json:"by_wallet"`    // WalletID -> OrganizationID
    ByNodeCount map[uint32][][32]byte    `json:"by_node_count"` // NodeCount bucket -> OrganizationIDs
    BannedOrgs  [][32]byte               `json:"banned_orgs"`   // All banned organization IDs
}

// OrganizationSummary provides network-wide organization statistics
type OrganizationSummary struct {
    TotalOrganizations      uint64  `json:"total_organizations"`
    DomainVerified          uint64  `json:"domain_verified"`
    EconomicVerified        uint64  `json:"economic_verified"`
    TotalStaked             uint64  `json:"total_staked"`
    TotalSlashed            uint64  `json:"total_slashed"`
    BannedCount             uint32  `json:"banned_count"`
    AverageNodesPerOrg      float64 `json:"average_nodes_per_org"`
    ExpiringVerifications24h uint32 `json:"expiring_verifications_24h"`
    UpdatedAt               int64   `json:"updated_at"`
}
```

**DHT Key:** `org:{organization-id}`

---

### Three-Phase Commit State

Three-phase commit (3PC) state tracks cross-shard transaction coordination for distributed atomic operations.

```go
// ThreePhaseCommitState tracks cross-shard transaction state
type ThreePhaseCommitState struct {
    TxID              [32]byte         `json:"tx_id"`
    Phase             ThreePhasePhase  `json:"phase"`
    CoordinatorID     [32]byte         `json:"coordinator_id"`
    SourceShard       uint16           `json:"source_shard"`
    DestinationShards []uint16         `json:"destination_shards"`
    PrepareVotes      map[uint16]bool  `json:"prepare_votes"`
    CommitAcks        map[uint16]bool  `json:"commit_acks"`
    LockAcquiredAt    int64            `json:"lock_acquired_at"`
    LockExpiresAt     int64            `json:"lock_expires_at"`
    LastHeartbeat     int64            `json:"last_heartbeat"`
    TerminationState  TerminationState `json:"termination_state,omitempty"`
    Version           uint64           `json:"version"`
}

// ThreePhasePhase represents the current 3PC protocol phase
type ThreePhasePhase uint8

const (
    PhasePrepare     ThreePhasePhase = iota // Phase 1: Coordinator requests votes
    PhasePreCommit                          // Phase 2: All voted yes, prepare to commit
    PhaseCommit                             // Phase 3: Final commit
    PhaseAbort                              // Transaction aborted
    PhaseTerminating                        // Termination protocol active
)

// TerminationState tracks cooperative termination protocol state
type TerminationState struct {
    WitnessVotes map[uint16]WitnessVote `json:"witness_votes"`
    Decision     TerminationDecision    `json:"decision"`
    DecidedAt    int64                  `json:"decided_at"`
}

// WitnessVote represents a witness shard's vote during termination
type WitnessVote struct {
    ShardID      uint16          `json:"shard_id"`
    LastKnownPhase ThreePhasePhase `json:"last_known_phase"`
    VotedAt      int64           `json:"voted_at"`
    Signature    []byte          `json:"signature"`
}

// TerminationDecision represents the outcome of the termination protocol
type TerminationDecision uint8

const (
    TerminationPending   TerminationDecision = iota // Still collecting witness votes
    TerminationCommit                               // Majority witnessed pre-commit
    TerminationAbort                                // No evidence of pre-commit
    TerminationTimeout                              // Timeout, manual intervention required
)

// ThreePhaseCommitSummary provides 3PC transaction statistics
type ThreePhaseCommitSummary struct {
    ActiveTransactions   uint32  `json:"active_transactions"`
    CommittedLast24h     uint32  `json:"committed_last_24h"`
    AbortedLast24h       uint32  `json:"aborted_last_24h"`
    TerminationsLast24h  uint32  `json:"terminations_last_24h"`
    AverageLatencyMs     uint64  `json:"average_latency_ms"`
    CrossShardTxPercent  float64 `json:"cross_shard_tx_percent"`
}
```

**DHT Key:** `3pc:{tx-id}`

---

## Index Requirements

### Primary Indexes

| Index Name | Key Pattern | Purpose |
|------------|-------------|---------|
| `idx:node:id` | `node:{node-id}` | Direct node lookup |
| `idx:node:role` | `idx:node:role:{role}` | Find nodes by role |
| `idx:node:reputation` | `idx:node:rep:{bucket}` | Reputation range queries |
| `idx:node:org` | `idx:node:org:{organization-id}` | Nodes by organization |
| `idx:utxo:wallet` | `utxo:{wallet-id}` | Wallet UTXO lookup |
| `idx:utxo:shard` | `idx:utxo:shard:{shard-id}` | Shard-based queries |
| `idx:rep:score` | `idx:rep:score:{bucket}` | Reputation score ranges |
| `idx:cert:hash` | `cert:{cert-hash}` | Direct certificate lookup |
| `idx:cert:expiry` | `idx:cert:expiry:{day}` | Expiration queries |
| `idx:cert:node` | `idx:cert:node:{node-id}` | Certs by subject |
| `idx:dkg:session` | `dkg:{session-id}` | Direct session lookup |
| `idx:dkg:active` | `idx:dkg:active:{pool-id}` | Active sessions by pool |
| `idx:partition:id` | `partition:{partition-id}` | Direct partition lookup |
| `idx:partition:active` | `idx:partition:active` | All active partitions |
| `idx:org:id` | `org:{organization-id}` | Direct organization lookup |
| `idx:org:domain` | `idx:org:domain:{domain}` | Organizations by domain |
| `idx:org:wallet` | `idx:org:wallet:{wallet-id}` | Organizations by stake wallet |
| `idx:org:expiring` | `idx:org:expiring:{day}` | Organizations with expiring verification |
| `idx:org:banned` | `idx:org:banned` | All banned organizations |
| `idx:3pc:tx` | `3pc:{tx-id}` | Direct 3PC transaction lookup |
| `idx:3pc:active` | `idx:3pc:active:{shard-id}` | Active 3PC by shard |
| `idx:3pc:coordinator` | `idx:3pc:coordinator:{node-id}` | 3PC by coordinator |

### Index Structures

```go
// NodeIDIndex provides efficient node lookups
type NodeIDIndex struct {
    NodeID    [32]byte `json:"node_id"`
    KeyPrefix string   `json:"key_prefix"` // "node:" or "rep:" etc.
    ShardID   uint16   `json:"shard_id"`
}

// ReputationScoreIndex enables range queries on reputation
type ReputationScoreIndex struct {
    Bucket      uint8    `json:"bucket"`       // 0-100 (score * 100)
    NodeIDs     [][32]byte `json:"node_ids"`   // Nodes in this bucket
    LastUpdated int64    `json:"last_updated"`
}

// CertificateExpirationIndex tracks expiring certificates
type CertificateExpirationIndex struct {
    ExpiryDay   int64      `json:"expiry_day"`   // Unix day (timestamp / 86400)
    CertHashes  [][32]byte `json:"cert_hashes"`  // Certs expiring this day
    Count       uint32     `json:"count"`
}

// ShardUTXOIndex provides shard-scoped UTXO queries
type ShardUTXOIndex struct {
    ShardID     uint16     `json:"shard_id"`
    WalletIDs   [][32]byte `json:"wallet_ids"`  // Wallets in this shard
    TotalBalance uint64    `json:"total_balance"`
    LastUpdated int64      `json:"last_updated"`
}

// DKGSessionIndex tracks active DKG sessions
type DKGSessionIndex struct {
    PoolID      [32]byte   `json:"pool_id"`
    SessionIDs  [][32]byte `json:"session_ids"` // Active sessions for pool
    Purpose     DKGPurpose `json:"purpose"`
}

// OrganizationDomainIndex provides domain-to-organization lookups
type OrganizationDomainIndex struct {
    Domain         string   `json:"domain"`          // Domain name (e.g., "example.com")
    OrganizationID [32]byte `json:"organization_id"` // Owning organization
    VerifiedAt     int64    `json:"verified_at"`     // Last DNS verification timestamp
    ExpiresAt      int64    `json:"expires_at"`      // When verification expires
}

// OrganizationExpirationIndex tracks organizations with expiring verifications
type OrganizationExpirationIndex struct {
    ExpiryDay       int64      `json:"expiry_day"`       // Unix day (timestamp / 86400)
    OrganizationIDs [][32]byte `json:"organization_ids"` // Orgs expiring this day
    Count           uint32     `json:"count"`
}

// NodeOrganizationIndex provides organization-to-nodes lookups
type NodeOrganizationIndex struct {
    OrganizationID [32]byte   `json:"organization_id"`
    NodeIDs        [][32]byte `json:"node_ids"`     // Nodes in this organization
    CAPoolNodes    [][32]byte `json:"ca_pool_nodes"` // Subset of nodes in CA pool
    LastUpdated    int64      `json:"last_updated"`
}
```

---

## Replication Configuration

### Replication Factors

| Data Type | Replication Factor | Consistency Level | Rationale |
|-----------|-------------------|-------------------|-----------|
| Node State | 5 | Strong | Critical for network operation |
| Routing Tables | 3 | Eventual | Can be reconstructed from peers |
| UTXO State | 7 | Strong | Financial data requires highest durability |
| Reputation Records | 5 | Strong | Trust decisions require consistency |
| Certificate State | 7 | Strong | Security-critical, must not lose certs |
| DKG Sessions | 5 | Strong | Active cryptographic protocol |
| Partition State | 5 | Strong | Recovery coordination |
| Organization State | 5 | Strong | Identity binding requires consistency |

### Consistency Requirements

```go
// ConsistencyConfig defines per-data-type consistency
type ConsistencyConfig struct {
    // Node operations
    NodeRead       ConsistencyLevel // Default: Linearizable
    NodeWrite      ConsistencyLevel // Default: Linearizable

    // UTXO operations (highest consistency)
    UTXORead       ConsistencyLevel // Default: Linearizable
    UTXOWrite      ConsistencyLevel // Default: Linearizable

    // Routing tables (relaxed for performance)
    RoutingRead    ConsistencyLevel // Default: Eventual
    RoutingWrite   ConsistencyLevel // Default: Quorum

    // Certificate operations
    CertRead       ConsistencyLevel // Default: Linearizable
    CertWrite      ConsistencyLevel // Default: Linearizable
}

// ConsistencyLevel defines read/write consistency
type ConsistencyLevel uint8

const (
    ConsistencyEventual     ConsistencyLevel = iota // Any replica
    ConsistencyQuorum                               // Majority of replicas
    ConsistencyLinearizable                         // Leader-based, strongest
)
```

### Cross-Region Replication

```
+-------------------------------------------------------------------------+
|                    CROSS-REGION REPLICATION                              |
+-------------------------------------------------------------------------+
|                                                                          |
|  REGION: US-EAST              REGION: EU-WEST              REGION: APAC |
|  +------------------+         +------------------+         +------------+|
|  | Shard Leaders    |         | Shard Leaders    |         | Shard      ||
|  | (Primary)        |         | (Async Replica)  |         | Leaders    ||
|  |                  |         |                  |         |            ||
|  | UTXO: Shards 0-N |-------->| UTXO: Shards 0-N |-------->| UTXO: 0-N  ||
|  | Certs: All       |  async  | Certs: All       |  async  | Certs: All ||
|  | Nodes: Regional  |         | Nodes: Regional  |         | Nodes: Rgn ||
|  +------------------+         +------------------+         +------------+|
|         |                            |                            |      |
|         | Sync replication           | Sync replication           |      |
|         | within region              | within region              |      |
|         v                            v                            v      |
|  +------------------+         +------------------+         +------------+|
|  | Raft Followers   |         | Raft Followers   |         | Raft       ||
|  | (RF=3 regional)  |         | (RF=3 regional)  |         | Followers  ||
|  +------------------+         +------------------+         +------------+|
|                                                                          |
|  REPLICATION RULES:                                                      |
|  - UTXO: Sync within region, async across regions (RPO < 1 second)       |
|  - Certs: Sync within region, sync to at least 1 remote region           |
|  - Nodes: Regional primary, async to other regions                       |
|  - DKG: Sync to all participants (regardless of region)                  |
|                                                                          |
+-------------------------------------------------------------------------+
```

---

## Key Naming Conventions

### DHT Key Patterns

| Prefix | Pattern | Example | Description |
|--------|---------|---------|-------------|
| `node:` | `node:{node-id}` | `node:a1b2c3d4...` | Node state record |
| `routing:` | `routing:{node-id}` | `routing:a1b2c3d4...` | Routing table |
| `utxo:` | `utxo:{wallet-id}` | `utxo:e5f6g7h8...` | Wallet UTXO state |
| `rep:` | `rep:{node-id}` | `rep:a1b2c3d4...` | Reputation record |
| `cert:` | `cert:{cert-hash}` | `cert:i9j0k1l2...` | Certificate state |
| `dkg:` | `dkg:{session-id}` | `dkg:m3n4o5p6...` | DKG session |
| `partition:` | `partition:{partition-id}` | `partition:q7r8s9t0...` | Partition state |
| `org:` | `org:{organization-id}` | `org:y5z6a7b8...` | Organization state |
| `3pc:` | `3pc:{tx-id}` | `3pc:u1v2w3x4...` | 3PC transaction state |

### Index Key Patterns

| Prefix | Pattern | Example | Description |
|--------|---------|---------|-------------|
| `idx:node:role:` | `idx:node:role:{role}` | `idx:node:role:coordinator` | Nodes by role |
| `idx:node:rep:` | `idx:node:rep:{bucket}` | `idx:node:rep:95` | Nodes with rep 0.95+ |
| `idx:node:org:` | `idx:node:org:{org-id}` | `idx:node:org:y5z6...` | Nodes by organization |
| `idx:utxo:shard:` | `idx:utxo:shard:{shard}` | `idx:utxo:shard:1234` | UTXOs in shard |
| `idx:cert:expiry:` | `idx:cert:expiry:{day}` | `idx:cert:expiry:20240115` | Certs by expiry |
| `idx:cert:node:` | `idx:cert:node:{node-id}` | `idx:cert:node:a1b2...` | Certs by subject |
| `idx:dkg:active:` | `idx:dkg:active:{pool}` | `idx:dkg:active:pool1` | Active DKG sessions |
| `idx:partition:active` | `idx:partition:active` | `idx:partition:active` | Active partitions |
| `idx:org:domain:` | `idx:org:domain:{domain}` | `idx:org:domain:example.com` | Organization by domain |
| `idx:org:wallet:` | `idx:org:wallet:{wallet}` | `idx:org:wallet:w1x2...` | Organization by stake wallet |
| `idx:org:expiry:` | `idx:org:expiry:{day}` | `idx:org:expiry:20260401` | Orgs by verification expiry |
| `idx:org:banned` | `idx:org:banned` | `idx:org:banned` | Banned organizations |
| `idx:3pc:active:` | `idx:3pc:active:{shard}` | `idx:3pc:active:1234` | Active 3PC by shard |
| `idx:3pc:coordinator:` | `idx:3pc:coordinator:{node}` | `idx:3pc:coordinator:a1b2...` | 3PC by coordinator |

### Key Structure

```go
// KeyBuilder constructs DHT keys with proper formatting
type KeyBuilder struct{}

// NodeKey returns the key for a node state record
func (kb KeyBuilder) NodeKey(nodeID [32]byte) string {
    return fmt.Sprintf("node:%x", nodeID)
}

// RoutingKey returns the key for a routing table
func (kb KeyBuilder) RoutingKey(nodeID [32]byte) string {
    return fmt.Sprintf("routing:%x", nodeID)
}

// UTXOKey returns the key for a wallet's UTXO state
func (kb KeyBuilder) UTXOKey(walletID [32]byte) string {
    return fmt.Sprintf("utxo:%x", walletID)
}

// ReputationKey returns the key for a reputation record
func (kb KeyBuilder) ReputationKey(nodeID [32]byte) string {
    return fmt.Sprintf("rep:%x", nodeID)
}

// CertificateKey returns the key for a certificate state
func (kb KeyBuilder) CertificateKey(certHash [32]byte) string {
    return fmt.Sprintf("cert:%x", certHash)
}

// DKGSessionKey returns the key for a DKG session
func (kb KeyBuilder) DKGSessionKey(sessionID [32]byte) string {
    return fmt.Sprintf("dkg:%x", sessionID)
}

// PartitionKey returns the key for a partition state
func (kb KeyBuilder) PartitionKey(partitionID [32]byte) string {
    return fmt.Sprintf("partition:%x", partitionID)
}

// OrganizationKey returns the key for an organization state
func (kb KeyBuilder) OrganizationKey(organizationID [32]byte) string {
    return fmt.Sprintf("org:%x", organizationID)
}

// ThreePhaseCommitKey returns the key for a 3PC transaction state
func (kb KeyBuilder) ThreePhaseCommitKey(txID [32]byte) string {
    return fmt.Sprintf("3pc:%x", txID)
}

// IndexKey returns an index key
func (kb KeyBuilder) IndexKey(category, subcategory, value string) string {
    return fmt.Sprintf("idx:%s:%s:%s", category, subcategory, value)
}
```

---

## Migration Scripts

### Schema Versioning

```go
// SchemaVersion tracks the current schema version
type SchemaVersion struct {
    Version     uint32 `json:"version"`      // Current schema version
    AppliedAt   int64  `json:"applied_at"`   // When this version was applied
    MigratedBy  string `json:"migrated_by"`  // Node that ran migration
    Checksum    [32]byte `json:"checksum"`   // Schema checksum for verification
}

// Migration represents a schema migration
type Migration struct {
    Version     uint32         `json:"version"`
    Description string         `json:"description"`
    Up          MigrationFunc  `json:"-"` // Forward migration
    Down        MigrationFunc  `json:"-"` // Rollback migration
    Idempotent  bool           `json:"idempotent"`
}

// MigrationFunc is the signature for migration functions
type MigrationFunc func(ctx context.Context, db *quicbaas.Client) error
```

### Migration Registry

```go
// MigrationRegistry maintains all schema migrations
var MigrationRegistry = []Migration{
    {
        Version:     1,
        Description: "Initial schema - Node, UTXO, Reputation",
        Up:          migrateV1Up,
        Down:        migrateV1Down,
        Idempotent:  true,
    },
    {
        Version:     2,
        Description: "Add Certificate and DKG state",
        Up:          migrateV2Up,
        Down:        migrateV2Down,
        Idempotent:  true,
    },
    {
        Version:     3,
        Description: "Add Partition state and vector clocks",
        Up:          migrateV3Up,
        Down:        migrateV3Down,
        Idempotent:  true,
    },
    {
        Version:     4,
        Description: "Add reputation bucket indexes",
        Up:          migrateV4Up,
        Down:        migrateV4Down,
        Idempotent:  true,
    },
    {
        Version:     5,
        Description: "Add certificate expiration indexes",
        Up:          migrateV5Up,
        Down:        migrateV5Down,
        Idempotent:  true,
    },
    {
        Version:     6,
        Description: "Add OrganizationID to NodeState, TPMTier to TPMInfo, OrganizationState schema",
        Up:          migrateV6Up,
        Down:        migrateV6Down,
        Idempotent:  true,
    },
}
```

### Migration Strategy

```
+-------------------------------------------------------------------------+
|                       MIGRATION WORKFLOW                                 |
+-------------------------------------------------------------------------+
|                                                                          |
|  1. PRE-MIGRATION CHECKS                                                 |
|  +-------------------------------------------------------------------+  |
|  |  - Verify all nodes healthy                                        |  |
|  |  - Check replication lag < threshold                               |  |
|  |  - Snapshot current state                                          |  |
|  |  - Acquire distributed migration lock                              |  |
|  +-------------------------------------------------------------------+  |
|                                    |                                     |
|                                    v                                     |
|  2. SCHEMA COMPATIBILITY CHECK                                           |
|  +-------------------------------------------------------------------+  |
|  |  - Verify migration is next in sequence                            |  |
|  |  - Check no conflicting migrations running                         |  |
|  |  - Validate migration can be applied (prerequisites met)           |  |
|  +-------------------------------------------------------------------+  |
|                                    |                                     |
|                                    v                                     |
|  3. ROLLING MIGRATION (Zero-Downtime)                                    |
|  +-------------------------------------------------------------------+  |
|  |  Phase A: Add new fields/indexes (backward compatible)             |  |
|  |     - New code can read old data                                   |  |
|  |     - Old code ignores new fields                                  |  |
|  |                                                                     |  |
|  |  Phase B: Backfill data                                            |  |
|  |     - Populate new fields from existing data                       |  |
|  |     - Build new indexes in background                              |  |
|  |                                                                     |  |
|  |  Phase C: Switch writes to new schema                              |  |
|  |     - All nodes updated to new code version                        |  |
|  |     - Writes go to new fields                                      |  |
|  |                                                                     |  |
|  |  Phase D: Remove deprecated (after validation period)              |  |
|  |     - Clean up old fields/indexes                                  |  |
|  |     - Final schema optimization                                    |  |
|  +-------------------------------------------------------------------+  |
|                                    |                                     |
|                                    v                                     |
|  4. POST-MIGRATION VALIDATION                                            |
|  +-------------------------------------------------------------------+  |
|  |  - Verify data integrity                                           |  |
|  |  - Check index consistency                                         |  |
|  |  - Validate query performance                                      |  |
|  |  - Release migration lock                                          |  |
|  |  - Update schema version                                           |  |
|  +-------------------------------------------------------------------+  |
|                                                                          |
+-------------------------------------------------------------------------+
```

### Example Migration Implementation

```go
// migrateV5Up adds certificate expiration indexes
func migrateV5Up(ctx context.Context, db *quicbaas.Client) error {
    // Create expiration index for each day bucket
    iter := db.Scan(ctx, "cert:", "cert:~")
    defer iter.Close()

    for iter.Next() {
        var cert CertificateState
        if err := json.Unmarshal(iter.Value(), &cert); err != nil {
            continue // Skip malformed records
        }

        // Calculate expiry day bucket
        expiryDay := cert.ExpiresAt / 86400

        // Add to expiration index
        indexKey := fmt.Sprintf("idx:cert:expiry:%d", expiryDay)
        if err := db.AppendToSet(ctx, indexKey, cert.CertHash[:]); err != nil {
            return fmt.Errorf("failed to index cert %x: %w", cert.CertHash, err)
        }
    }

    return iter.Err()
}

// migrateV5Down removes certificate expiration indexes
func migrateV5Down(ctx context.Context, db *quicbaas.Client) error {
    // Remove all expiration indexes
    iter := db.Scan(ctx, "idx:cert:expiry:", "idx:cert:expiry:~")
    defer iter.Close()

    var keysToDelete []string
    for iter.Next() {
        keysToDelete = append(keysToDelete, string(iter.Key()))
    }

    for _, key := range keysToDelete {
        if err := db.Delete(ctx, key); err != nil {
            return fmt.Errorf("failed to delete index %s: %w", key, err)
        }
    }

    return nil
}
```

---

## Typed Error Definitions

All QuicBaaS schema operations use typed errors for consistent error handling and debugging.

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| `1001` | `ErrNodeNotFound` | Requested node does not exist in the DHT |
| `1002` | `ErrUTXONotFound` | Requested UTXO or wallet does not exist |
| `1003` | `ErrReputationRecordNotFound` | No reputation record for the specified node |
| `1004` | `ErrCertificateNotFound` | Certificate with specified hash not found |
| `1005` | `ErrDKGSessionNotFound` | DKG session does not exist or has expired |
| `1006` | `ErrPartitionNotFound` | Partition state record not found |
| `1007` | `Err3PCTransactionNotFound` | 3PC transaction record not found |
| `1008` | `ErrOrganizationNotFound` | Organization does not exist in registry |
| `1009` | `ErrOrganizationBanned` | Organization is banned (temporary or permanent) |
| `1010` | `ErrOrganizationVerificationExpired` | Organization verification has expired |
| `2001` | `ErrVersionConflict` | Optimistic concurrency violation |
| `2002` | `ErrReplicationFailure` | Failed to replicate to required number of nodes |
| `2003` | `ErrShardMismatch` | Operation targeted wrong shard for key |
| `2004` | `ErrQuorumNotReached` | Insufficient nodes responded for quorum |
| `3001` | `ErrInvalidSchema` | Record does not conform to expected schema |
| `3002` | `ErrKeyFormatInvalid` | DHT key does not match expected pattern |
| `3003` | `ErrIndexCorruption` | Index is inconsistent with source data |

### Error Type Definitions

```go
// ErrorCode represents a typed error code for DHT operations
type ErrorCode uint16

const (
    // Not Found Errors (1xxx)
    ErrCodeNodeNotFound                    ErrorCode = 1001
    ErrCodeUTXONotFound                    ErrorCode = 1002
    ErrCodeReputationRecordNotFound        ErrorCode = 1003
    ErrCodeCertificateNotFound             ErrorCode = 1004
    ErrCodeDKGSessionNotFound              ErrorCode = 1005
    ErrCodePartitionNotFound               ErrorCode = 1006
    ErrCode3PCTransactionNotFound          ErrorCode = 1007
    ErrCodeOrganizationNotFound            ErrorCode = 1008
    ErrCodeOrganizationBanned              ErrorCode = 1009
    ErrCodeOrganizationVerificationExpired ErrorCode = 1010

    // Consistency Errors (2xxx)
    ErrCodeVersionConflict     ErrorCode = 2001
    ErrCodeReplicationFailure  ErrorCode = 2002
    ErrCodeShardMismatch       ErrorCode = 2003
    ErrCodeQuorumNotReached    ErrorCode = 2004

    // Validation Errors (3xxx)
    ErrCodeInvalidSchema    ErrorCode = 3001
    ErrCodeKeyFormatInvalid ErrorCode = 3002
    ErrCodeIndexCorruption  ErrorCode = 3003
)

// DHTError represents a typed error from DHT operations
type DHTError struct {
    Code       ErrorCode `json:"code"`
    Message    string    `json:"message"`
    Key        string    `json:"key,omitempty"`        // DHT key involved
    ShardID    uint16    `json:"shard_id,omitempty"`   // Shard where error occurred
    Expected   uint64    `json:"expected,omitempty"`   // Expected version (for conflicts)
    Actual     uint64    `json:"actual,omitempty"`     // Actual version (for conflicts)
    RetryAfter int64     `json:"retry_after,omitempty"` // Suggested retry time (Unix ms)
}

// Error implements the error interface
func (e *DHTError) Error() string {
    return fmt.Sprintf("[%d] %s (key=%s)", e.Code, e.Message, e.Key)
}

// Is implements error comparison for errors.Is()
func (e *DHTError) Is(target error) bool {
    if t, ok := target.(*DHTError); ok {
        return e.Code == t.Code
    }
    return false
}

// Sentinel errors for use with errors.Is()
var (
    ErrNodeNotFound = &DHTError{
        Code:    ErrCodeNodeNotFound,
        Message: "node not found in DHT",
    }
    ErrUTXONotFound = &DHTError{
        Code:    ErrCodeUTXONotFound,
        Message: "UTXO or wallet not found",
    }
    ErrReputationRecordNotFound = &DHTError{
        Code:    ErrCodeReputationRecordNotFound,
        Message: "reputation record not found for node",
    }
    ErrCertificateNotFound = &DHTError{
        Code:    ErrCodeCertificateNotFound,
        Message: "certificate not found by hash",
    }
    ErrDKGSessionNotFound = &DHTError{
        Code:    ErrCodeDKGSessionNotFound,
        Message: "DKG session not found or expired",
    }
    ErrPartitionNotFound = &DHTError{
        Code:    ErrCodePartitionNotFound,
        Message: "partition state not found",
    }
    Err3PCTransactionNotFound = &DHTError{
        Code:    ErrCode3PCTransactionNotFound,
        Message: "3PC transaction not found",
    }
    ErrOrganizationNotFound = &DHTError{
        Code:    ErrCodeOrganizationNotFound,
        Message: "organization not found in registry",
    }
    ErrOrganizationBanned = &DHTError{
        Code:    ErrCodeOrganizationBanned,
        Message: "organization is banned",
    }
    ErrOrganizationVerificationExpired = &DHTError{
        Code:    ErrCodeOrganizationVerificationExpired,
        Message: "organization verification has expired",
    }
    ErrVersionConflict = &DHTError{
        Code:    ErrCodeVersionConflict,
        Message: "version conflict: record was modified concurrently",
    }
    ErrReplicationFailure = &DHTError{
        Code:    ErrCodeReplicationFailure,
        Message: "failed to replicate to required number of nodes",
    }
    ErrShardMismatch = &DHTError{
        Code:    ErrCodeShardMismatch,
        Message: "operation targeted wrong shard for key",
    }
    ErrQuorumNotReached = &DHTError{
        Code:    ErrCodeQuorumNotReached,
        Message: "insufficient nodes responded for quorum",
    }
    ErrInvalidSchema = &DHTError{
        Code:    ErrCodeInvalidSchema,
        Message: "record does not conform to expected schema",
    }
    ErrKeyFormatInvalid = &DHTError{
        Code:    ErrCodeKeyFormatInvalid,
        Message: "DHT key does not match expected pattern",
    }
    ErrIndexCorruption = &DHTError{
        Code:    ErrCodeIndexCorruption,
        Message: "index is inconsistent with source data",
    }
)

// NewDHTError creates a new typed error with context
func NewDHTError(code ErrorCode, key string, format string, args ...interface{}) *DHTError {
    return &DHTError{
        Code:    code,
        Message: fmt.Sprintf(format, args...),
        Key:     key,
    }
}

// WithVersion adds version conflict details to an error
func (e *DHTError) WithVersion(expected, actual uint64) *DHTError {
    e.Expected = expected
    e.Actual = actual
    return e
}

// WithShard adds shard context to an error
func (e *DHTError) WithShard(shardID uint16) *DHTError {
    e.ShardID = shardID
    return e
}

// WithRetry adds retry suggestion to an error
func (e *DHTError) WithRetry(retryAfterMs int64) *DHTError {
    e.RetryAfter = retryAfterMs
    return e
}
```

### Error Handling Examples

```go
// Example: Handling version conflicts with optimistic concurrency
func updateNodeReputation(ctx context.Context, db *quicbaas.Client, nodeID [32]byte, delta float64) error {
    for retries := 0; retries < 3; retries++ {
        // Read current state
        key := KeyBuilder{}.ReputationKey(nodeID)
        data, version, err := db.GetWithVersion(ctx, key)
        if err != nil {
            if errors.Is(err, ErrReputationRecordNotFound) {
                return fmt.Errorf("cannot update reputation: %w", err)
            }
            return err
        }

        var record ReputationRecord
        if err := json.Unmarshal(data, &record); err != nil {
            return NewDHTError(ErrCodeInvalidSchema, key, "failed to unmarshal: %v", err)
        }

        // Apply update
        record.Score = clamp(record.Score + delta, 0.0, 1.0)
        record.Version = version + 1
        record.LastUpdate = time.Now().Unix()

        // Attempt write with version check
        updated, err := json.Marshal(record)
        if err != nil {
            return err
        }

        err = db.PutWithVersion(ctx, key, updated, version)
        if err == nil {
            return nil // Success
        }

        if errors.Is(err, ErrVersionConflict) {
            continue // Retry with fresh data
        }
        return err // Other error, don't retry
    }

    return NewDHTError(ErrCodeVersionConflict, "", "exceeded retry limit for reputation update")
}

// Example: Handling shard mismatches
func getUTXOState(ctx context.Context, db *quicbaas.Client, walletID [32]byte) (*UTXOState, error) {
    key := KeyBuilder{}.UTXOKey(walletID)
    expectedShard := db.ShardForKey(key)

    data, err := db.Get(ctx, key)
    if err != nil {
        if errors.Is(err, ErrUTXONotFound) {
            return nil, err
        }
        if errors.Is(err, ErrShardMismatch) {
            // Redirect to correct shard
            correctShard := err.(*DHTError).ShardID
            return getUTXOStateFromShard(ctx, db, walletID, correctShard)
        }
        return nil, err
    }

    var state UTXOState
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, NewDHTError(ErrCodeInvalidSchema, key, "invalid UTXO state: %v", err)
    }

    return &state, nil
}
```

---

## QuicBaaS Cross-Region Resilience

This section defines the resilience requirements for QuicBaaS in a distributed DHT environment.

### Cross-Region Replication

QuicBaaS maintains data availability across geographic regions using Multi-Raft consensus.

| Requirement | Value | Description |
|-------------|-------|-------------|
| Minimum Regions | 3 | Data replicated across at least 3 geographic regions |
| Replication Factor | 5 | Total replicas per data item |
| Cross-Region Replicas | 3 | Minimum replicas in different regions |
| Sync Replication | 2 | Synchronous replicas before acknowledgment |
| Async Replication | 3 | Additional asynchronous replicas |

### DHT-QuicBaaS Partition Handling

When network partitions occur between DHT nodes and QuicBaaS clusters:

| Scenario | DHT Behavior | QuicBaaS Behavior | Recovery |
|----------|-------------|-------------------|----------|
| DHT → QuicBaaS partition | Continue with stale reads, queue writes | Process local requests | Reconcile on partition heal |
| QuicBaaS internal partition | DHT detects via health checks | Minority shards read-only | Automatic failover to majority |
| Complete QuicBaaS unavailability | DHT enters degraded mode | N/A | Manual intervention |

### Partition Detection

| Constant | Value | Description |
|----------|-------|-------------|
| QuicBaaSHealthCheckInterval | 30s | Interval for health checks |
| QuicBaaSPartitionTimeout | 90s | Time before declaring partition |
| QuicBaaSStaleReadTTL | 5 min | Maximum staleness for cached reads |
| QuicBaaSWriteQueueSize | 10,000 | Maximum queued writes during partition |

### Data Corruption Detection

QuicBaaS uses merkle tree verification for corruption detection:

| Component | Verification Method | Frequency |
|-----------|-------------------|-----------|
| Key-Value Data | Merkle tree root comparison | Hourly |
| Index Structures | Checksum validation | Daily |
| Raft Log | Hash chain verification | Per entry |
| Snapshots | Full merkle verification | On restore |

### Recovery Procedures

1. **Corruption Recovery**: Rebuild from DHT state using snapshot + replay
2. **Region Failure**: Automatic failover to surviving regions, re-replicate
3. **Complete Loss**: Restore from offline backup + DHT state reconstruction

For all constants, see `00-CONSTANTS.md` Section 20 (CA Pool Health Monitoring - QuicBaaS metrics).

---

## Related Documents

- [01-system-overview.md](01-system-overview.md) - QuicBaaS platform layer integration
- [07-currency-transactions.md](07-currency-transactions.md) - UTXO model and sharding
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system
- [05-certificate-authority.md](05-certificate-authority.md) - Certificate lifecycle
- [06-consensus-coordination.md](06-consensus-coordination.md) - DKG and consensus
- [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) - FROST share storage and key lifecycle management

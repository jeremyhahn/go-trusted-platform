# Currency and Transactions

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
## Overview

TrustedCurrency is a blockchainless cryptocurrency for the go-trusted-platform network:

- **No Blockchain**: Uses a DAG (Directed Acyclic Graph) structure inspired by IOTA Tangle
- **No Mining**: Trust derives from TPM attestation, not computational work
- **Utility Coin**: Compensation for network services (bandwidth, storage, DHT routing, CA signing)
- **Non-Custodial**: Users hold their own keys in TPM
- **Scales to Billions**: Designed for /36 IPv6 network (4B+ addresses)

### Proof of Trust (PoT)

Instead of Proof of Work or Proof of Stake, TrustedCurrency uses TPM attestation:

- Unforgeable identity (Endorsement Key)
- Tamper-evident state (PCRs)
- Secure key storage (sealed objects)
- Cryptographic attestation (quotes)

## UTXO Model

### Transaction Structure

```go
type Transaction struct {
    ID          TxID          // SHA256(content)
    Version     uint8         // Protocol version
    Parents     []TxID        // 2-3 parent references (DAG links)
    ParentProofs []ParentProof // TPM-attested confirmations

    From        WalletID      // Sender's wallet (TPM-backed)
    To          WalletID      // Recipient's wallet
    Amount      uint64        // Amount in smallest unit
    Fee         uint64        // Network fee (burned)
    Sequence    uint64        // Monotonic sequence number

    TPMQuote    []byte        // Fresh TPM attestation
    Timestamp   int64         // Unix timestamp
    Signature   []byte        // Ed25519 signature from TPM key
}
```

### UTXO Commitment

```go
type UTXOCommitment struct {
    TransactionID TxID      // Source transaction
    OutputIndex   uint8     // Output index within transaction
    WalletID      WalletID  // Owner wallet
    Amount        uint64    // Unspent amount
    Sequence      uint64    // Transaction sequence
    Spent         bool      // Has this been spent?
    SpentInTx     TxID      // If spent, which transaction consumed it
    CreatedAt     int64     // Unix timestamp
}
```

### Change Outputs

When a transaction spends less than the full UTXO amount, the remainder creates a change output back to the sender.

## Sharding Architecture

### Structure

The network uses hierarchical sharding for scalability:

| Parameter | Value |
|-----------|-------|
| Shard Bits | 16 (first 16 bits of wallet ID) |
| Max Shards | 65,536 |
| Nodes per Shard | ~65,536 (at full scale) |
| Total Capacity | 4 billion nodes |

### Shard Assignment

```go
const ShardBits = 16
const MaxShards = 65536

func GetShard(walletID WalletID) uint16 {
    return binary.BigEndian.Uint16(walletID[:2])
}
```

### Shard-Authoritative UTXO Model (CANONICAL)

**CRITICAL SECURITY PROPERTY**: Each wallet is assigned to exactly ONE authoritative shard. That shard is the **ONLY** authority for the wallet's UTXO state. This eliminates checkpoint race conditions that could enable double-spend attacks.

```go
// Shard authority - eliminates race conditions by having single source of truth
type ShardAuthority struct {
    WalletID    WalletID  // Wallet identifier
    ShardID     uint16    // Authoritative shard (derived deterministically)
    UTXOSet     []UTXO    // Live UTXOs owned by wallet (shard-local)
    Sequence    uint64    // Monotonic sequence number (shard-local)
    LastUpdate  time.Time // Last modification timestamp
}

// GetAuthoritativeShard returns the single shard that has authority over this wallet
// This is deterministic and cannot be changed - derived from wallet ID
func GetAuthoritativeShard(walletID WalletID) uint16 {
    // First 16 bits of SHA256(walletID) = authoritative shard
    hash := sha256.Sum256(walletID[:])
    return binary.BigEndian.Uint16(hash[:2])
}

// Key security properties:
// 1. Wallet can ONLY transact through its authoritative shard
// 2. All validation happens on the authoritative shard (no DHT race condition)
// 3. Cross-shard transactions MUST route through sender's authoritative shard first
// 4. DHT checkpoint is write-through for recovery (NOT for validation)
```

**Why Shard-Authoritative Prevents Double-Spend**:

| Old Model (DHT Checkpoint) | New Model (Shard Authority) |
|---------------------------|----------------------------|
| Validation queries DHT (~150ms) | Validation queries local shard (0ms) |
| Race window: 250-500ms | Race window: 0ms (single authority) |
| Two shards could accept same TX | Only authoritative shard validates |
| Double-spend possible | Double-spend impossible |

**Transaction Routing**:

```
SINGLE-SHARD: Sender submits TX → Authoritative shard validates & commits
CROSS-SHARD:  Sender submits TX → Sender's authoritative shard → 3PC → Destination shard
```

### Sequence Number Validation (CANONICAL)

**CRITICAL SECURITY PROPERTY**: Sequence numbers are shard-authoritative. Each wallet's sequence number can ONLY be incremented by its home shard. This eliminates race conditions and enables atomic sequence management.

#### Home Shard Assignment

Each wallet is assigned to exactly one "home shard" based on its wallet ID:

```go
// GetHomeShard returns the authoritative shard for sequence number management
// This is identical to GetAuthoritativeShard - single authority for all wallet state
func GetHomeShard(walletID WalletID) uint16 {
    return GetAuthoritativeShard(walletID)
}

// Key properties:
// 1. Wallet assigned to exactly ONE home shard (deterministic)
// 2. ONLY home shard can increment sequence number
// 3. Cross-shard tx requires sequence lock from home shard
// 4. Sequence is monotonically increasing, never gaps
```

#### Sequence Lock Structure

For cross-shard transactions, the home shard issues a sequence lock that reserves the next sequence number:

```go
// SequenceLock reserves a sequence number for a pending transaction
type SequenceLock struct {
    WalletID      WalletID      // Wallet this lock applies to
    Sequence      uint64        // Reserved sequence number
    LockedUntil   time.Time     // Lock expiration time
    TransactionID TxID          // Transaction holding this lock
    LockState     SeqLockState  // Current state of the lock
    CreatedAt     time.Time     // When lock was created
    TPMQuote      []byte        // TPM attestation at creation
}

// SeqLockState represents sequence lock lifecycle
type SeqLockState uint8
const (
    SeqLockStatePending   SeqLockState = iota  // Lock active, tx in progress
    SeqLockStateCommitted                       // Tx committed, sequence consumed
    SeqLockStateReleased                        // Tx failed, lock released (seq NOT consumed)
    SeqLockStateExpired                         // Lock TTL expired
)

// SequenceLockManager manages sequence locks for cross-shard transactions
type SequenceLockManager struct {
    locks      map[WalletID]*SequenceLock  // One lock per wallet at a time
    sequences  map[WalletID]uint64          // Current sequence per wallet
    mu         sync.RWMutex
}

// AcquireSequenceLock atomically reserves the next sequence number
func (slm *SequenceLockManager) AcquireSequenceLock(
    walletID WalletID,
    txID TxID,
    ttl time.Duration,
) (*SequenceLock, error) {
    slm.mu.Lock()
    defer slm.mu.Unlock()

    // Check if wallet already has an active lock
    if existing, ok := slm.locks[walletID]; ok {
        if time.Now().Before(existing.LockedUntil) {
            return nil, ErrSequenceAlreadyLocked{
                WalletID: walletID,
                HeldBy:   existing.TransactionID,
                Until:    existing.LockedUntil,
            }
        }
        // Expired lock - clean it up
        delete(slm.locks, walletID)
    }

    // Get current sequence and reserve next
    currentSeq := slm.sequences[walletID]
    nextSeq := currentSeq + 1

    // Create sequence lock
    lock := &SequenceLock{
        WalletID:      walletID,
        Sequence:      nextSeq,
        LockedUntil:   time.Now().Add(ttl),
        TransactionID: txID,
        LockState:     SeqLockStatePending,
        CreatedAt:     time.Now(),
        TPMQuote:      GenerateTPMQuote(),
    }

    slm.locks[walletID] = lock
    return lock, nil
}

// CommitSequence atomically commits a sequence lock (tx succeeded)
func (slm *SequenceLockManager) CommitSequence(
    walletID WalletID,
    txID TxID,
) error {
    slm.mu.Lock()
    defer slm.mu.Unlock()

    lock, ok := slm.locks[walletID]
    if !ok {
        return ErrSequenceLockNotFound{WalletID: walletID}
    }

    if lock.TransactionID != txID {
        return ErrSequenceLockMismatch{
            WalletID: walletID,
            Expected: lock.TransactionID,
            Got:      txID,
        }
    }

    // CRITICAL: Atomic increment - sequence is now consumed
    // Compare-and-swap ensures no race conditions
    expectedSeq := lock.Sequence - 1
    if !atomic.CompareAndSwapUint64(&slm.sequences[walletID], expectedSeq, lock.Sequence) {
        return ErrSequenceRace{WalletID: walletID, Expected: expectedSeq}
    }

    // Update lock state
    lock.LockState = SeqLockStateCommitted
    delete(slm.locks, walletID)

    return nil
}

// ReleaseSequenceLock releases lock WITHOUT consuming sequence (tx failed)
// CRITICAL: If tx fails, sequence is still consumed to prevent replay
func (slm *SequenceLockManager) ReleaseSequenceLock(
    walletID WalletID,
    txID TxID,
    consumeSequence bool,  // true = sequence consumed even on failure
) error {
    slm.mu.Lock()
    defer slm.mu.Unlock()

    lock, ok := slm.locks[walletID]
    if !ok {
        return nil  // Already released - idempotent
    }

    if lock.TransactionID != txID {
        return ErrSequenceLockMismatch{
            WalletID: walletID,
            Expected: lock.TransactionID,
            Got:      txID,
        }
    }

    // SECURITY DECISION: Consume sequence on failure to prevent replay attacks
    // If consumeSequence is true, the sequence number is "burned"
    if consumeSequence {
        expectedSeq := lock.Sequence - 1
        atomic.CompareAndSwapUint64(&slm.sequences[walletID], expectedSeq, lock.Sequence)
    }

    lock.LockState = SeqLockStateReleased
    delete(slm.locks, walletID)

    return nil
}
```

**Sequence Lock Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Single lock per wallet | No concurrent sequence claims | Map with wallet key |
| Atomic increment | CAS prevents race conditions | atomic.CompareAndSwapUint64 |
| Lock prevents concurrent requests | One tx at a time per wallet | Lock check before acquire |
| Failed tx consumes sequence | Prevents replay attacks | consumeSequence flag |

**Sequence Lock Lifecycle**:

```
1. Cross-shard TX initiated
   |
2. Home shard acquires sequence lock (reserves seq=N+1)
   |
3. 3PC protocol executes across shards
   |
   +-- SUCCESS: CommitSequence() - seq=N+1 committed, lock released
   |
   +-- FAILURE: ReleaseSequenceLock(consumeSequence=true) - seq=N+1 consumed, lock released
   |
   +-- TIMEOUT: Lock expires, seq=N+1 consumed automatically
```

**Why Sequences Are Consumed on Failure**:

If sequences were rolled back on failure, an attacker could:
1. Submit TX with seq=5, have it fail intentionally
2. Submit DIFFERENT TX with same seq=5
3. First TX gets replayed by malicious node
4. Double-spend achieved

By consuming the sequence even on failure, each sequence number is used exactly once.

### Storage Architecture

The DHT stores verification metadata only (not full transaction history):

| Layer | Purpose | Size |
|-------|---------|------|
| Local Wallet (TPM-Sealed) | Complete transaction history for this wallet | ~100KB per 1000 TX |
| DHT Checkpoints | Wallet state (balance, sequence, merkle root) | ~250 bytes per wallet |
| DAG Tips | Recent transactions for consensus | ~300 KB total (bounded) |
| Archival Nodes (Optional) | Long-term storage | Opt-in |

### Wallet Checkpoint

```go
type WalletCheckpoint struct {
    WalletID      WalletID  // Wallet identifier
    Balance       uint64    // Current balance
    Sequence      uint64    // Latest transaction sequence
    MerkleRoot    [32]byte  // Root of local transaction Merkle tree
    LastTxID      TxID      // Most recent transaction ID
    TPMQuote      []byte    // TPM attestation of state
    Timestamp     int64     // Unix timestamp
    Shard         uint16    // Shard assignment
    Signature     []byte    // Wallet signature
}
```

## Single-Shard Transactions

### Single-Shard Transaction Fast Path (CANONICAL)

**CRITICAL OPTIMIZATION**: When sender and receiver are assigned to the same shard, the transaction bypasses the 3PC protocol entirely and executes as a local ACID transaction.

```go
// SingleShardFastPath handles same-shard transactions without 3PC overhead
const (
    // Expected percentage of transactions using fast path
    // Based on shard assignment distribution (16-bit prefix = 65,536 shards)
    // With uniform distribution, same-shard probability = 1/65536 for random wallets
    // But in practice, 80%+ of transactions are expected to use fast path due to:
    // 1. Wallet clustering (users transact with nearby wallets)
    // 2. Business relationships (same merchant shard)
    // 3. Self-transfers (change outputs, consolidation)
    ExpectedFastPathPercentage = 0.80  // 80%+ of transactions

    // Fast path network overhead
    FastPathNetworkOverhead = 0  // No cross-shard communication
)

// IsSameShardTransaction determines if transaction qualifies for fast path
func IsSameShardTransaction(tx *Transaction) bool {
    senderShard := GetAuthoritativeShard(tx.From)
    receiverShard := GetAuthoritativeShard(tx.To)
    return senderShard == receiverShard
}

// ExecuteFastPath processes same-shard transaction as local ACID operation
func (s *Shard) ExecuteFastPath(tx *Transaction) error {
    // Verify fast path eligibility
    if !IsSameShardTransaction(tx) {
        return ErrNotSameShardTransaction{
            SenderShard:   GetAuthoritativeShard(tx.From),
            ReceiverShard: GetAuthoritativeShard(tx.To),
        }
    }

    // Execute as atomic local transaction (no 3PC)
    return s.db.Transaction(func(dbTx *DBTransaction) error {
        // Step 1: Validate sender UTXO and sequence
        if err := s.ValidateTransaction(tx); err != nil {
            return err
        }

        // Step 2: Debit sender (atomic within transaction)
        if err := s.debitSender(dbTx, tx); err != nil {
            return err
        }

        // Step 3: Credit receiver (atomic within transaction)
        if err := s.creditReceiver(dbTx, tx); err != nil {
            return err
        }

        // Step 4: Update DAG
        if err := s.addToDAG(dbTx, tx); err != nil {
            return err
        }

        return nil  // Commit transaction
    })
}
```

**Fast Path vs 3PC Comparison**:

| Metric | Fast Path (Same-Shard) | 3PC (Cross-Shard) |
|--------|----------------------|-------------------|
| Network RTTs | 0 | 3-6 |
| Latency | <5ms | 50-200ms |
| Lock required | No (local ACID) | Yes (60s TTL) |
| Coordinator | None | Global Coordinator |
| Rollback complexity | Simple | Multi-phase |
| Expected usage | 80%+ | ~20% |

**Fast Path Detection Flow**:

```
Transaction Received
       |
       v
┌─────────────────────────────┐
│ GetAuthoritativeShard(From) │
│ GetAuthoritativeShard(To)   │
└─────────────────────────────┘
       |
       v
   Same Shard?
   /        \
 YES         NO
  |           |
  v           v
Fast Path   3PC Protocol
(Local TX)  (Cross-Shard)
```

### Validation Flow (Shard-Authoritative Model)

Transactions are validated **ONLY** by the sender's authoritative shard, eliminating race conditions:

```go
func (s *Shard) ValidateTransaction(tx *Transaction) error {
    // Step 0: Verify this shard is authoritative for sender
    if GetAuthoritativeShard(tx.From) != s.ShardID {
        return ErrNotAuthoritativeShard  // Reject - wrong shard
    }

    // Step 1: Atomic sequence number validation with compare-and-swap
    // CRITICAL SECURITY: Without atomic CAS, an attacker can broadcast two
    // transactions with the same sequence to different nodes, causing double-spend.
    //
    // Attack scenario (without CAS):
    // 1. Attacker has balance=100, sequence=5
    // 2. Broadcasts TxA (seq=6, send 100 to Alice) to Node X
    // 3. Broadcasts TxB (seq=6, send 100 to Bob) to Node Y
    // 4. Both nodes validate: current_seq=5, expected=6 ✓
    // 5. Both nodes accept - 200 coins created from 100!
    //
    // Mitigation: Use atomic CAS to increment sequence during validation
    authority := s.GetShardAuthority(tx.From)
    expectedSeq := atomic.LoadUint64(&authority.Sequence) + 1
    if tx.Sequence != expectedSeq {
        return ErrInvalidSequence
    }
    // Atomically claim this sequence number - fails if another tx got it first
    if !atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq-1, expectedSeq) {
        return ErrSequenceRace  // Another transaction claimed this sequence
    }

    // CRITICAL (P4-H11): Persist sequence claim BEFORE continuing validation
    // If node crashes after CAS but before completion, rollback log enables recovery
    rollbackEntry := &SequenceRollbackEntry{
        AccountID:     tx.From,
        ClaimedSeq:    expectedSeq,
        TxID:          tx.ID,
        ClaimedAt:     time.Now(),
        Status:        SequenceStatusPending,
    }
    if err := s.persistSequenceRollback(rollbackEntry); err != nil {
        // Failed to persist - must rollback immediately
        atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq, expectedSeq-1)
        return ErrSequencePersistFailed
    }

    // Deferred rollback on validation failure
    var validationErr error
    defer func() {
        if validationErr != nil {
            // Rollback sequence
            atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq, expectedSeq-1)
            // Update rollback log
            rollbackEntry.Status = SequenceStatusRolledBack
            rollbackEntry.RolledBackAt = time.Now()
            s.updateSequenceRollback(rollbackEntry)
        } else {
            // Validation succeeded - mark as committed
            rollbackEntry.Status = SequenceStatusCommitted
            rollbackEntry.CommittedAt = time.Now()
            s.updateSequenceRollback(rollbackEntry)
        }
    }()

    // Step 2: Verify sufficient balance (local UTXO set)
    balance := s.CalculateBalance(authority.UTXOSet)
    if balance < tx.Amount + tx.Fee {
        return ErrInsufficientBalance
    }

    // Step 3: Check UTXO availability (local - no race condition)
    for _, utxo := range tx.Inputs {
        if !s.UTXOAvailable(utxo) {
            return ErrUTXOUnavailable
        }
    }

    // Step 4: Verify TPM attestation (fresh quote)
    if err := VerifyTPMQuote(tx.TPMQuote, tx.From, time.Now()); err != nil {
        return ErrInvalidTPMQuote
    }

    // Step 5: Verify signature
    if err := VerifySignature(tx); err != nil {
        return ErrInvalidSignature
    }

    // Step 6: Verify DAG parents are valid tips
    if err := s.VerifyDAGParents(tx.Parents); err != nil {
        return ErrInvalidDAGParents
    }

    return nil
}
```

**Validation Performance**:

| Step | Time | Notes |
|------|------|-------|
| Shard authority check | 0ms | Local computation |
| Sequence verification | 0ms | Local state |
| Balance verification | 0ms | Local UTXO set |

#### Sequence Number Gap Attack Prevention

A malicious node could attempt to skip sequence numbers to disrupt transaction ordering or cause batches to be invalidated. The system enforces **strict contiguity** with penalties for gap attempts.

```go
// pkg/currency/sequence_gap.go

// SequenceGapConfig defines gap detection and penalty parameters
const (
    // Maximum pending sequence gap before rejection
    // A wallet can have at most 10 pending transactions awaiting confirmation
    MaxPendingSequenceGap = 10

    // Reputation penalty for gap attempt
    SequenceGapAttemptPenalty = 0.05  // -5% reputation per attempt

    // Ban threshold - 3 gap attempts within 24 hours = temporary ban
    SequenceGapBanThreshold = 3
    SequenceGapBanWindow    = 24 * time.Hour
    SequenceGapBanDuration  = 1 * time.Hour
)

// SequenceGapTracker monitors and penalizes sequence gap attempts
type SequenceGapTracker struct {
    attemptHistory map[WalletID][]GapAttempt
    mu             sync.RWMutex
}

type GapAttempt struct {
    WalletID      WalletID
    ExpectedSeq   uint64
    AttemptedSeq  uint64
    Timestamp     time.Time
}

// ValidateSequenceGap checks for malicious sequence gaps
func (t *SequenceGapTracker) ValidateSequenceGap(
    walletID WalletID,
    currentSeq uint64,
    attemptedSeq uint64,
) error {
    // Case 1: Normal contiguous sequence
    if attemptedSeq == currentSeq+1 {
        return nil
    }

    // Case 2: Sequence in the past (replay attempt)
    if attemptedSeq <= currentSeq {
        return ErrSequenceReplay
    }

    // Case 3: Gap detected
    gap := attemptedSeq - currentSeq - 1
    if gap > MaxPendingSequenceGap {
        // Record gap attempt for penalty
        t.recordGapAttempt(walletID, currentSeq+1, attemptedSeq)
        return &ErrSequenceGap{
            Expected: currentSeq + 1,
            Got:      attemptedSeq,
            Gap:      gap,
        }
    }

    // Case 4: Gap within tolerance - allow if pending txs exist
    // This handles legitimate cases where transactions arrive out of order
    pendingCount := t.getPendingTransactionCount(walletID, currentSeq, attemptedSeq)
    if pendingCount < gap {
        t.recordGapAttempt(walletID, currentSeq+1, attemptedSeq)
        return &ErrSequenceGap{
            Expected: currentSeq + 1,
            Got:      attemptedSeq,
            Gap:      gap,
            Pending:  pendingCount,
        }
    }

    return nil
}

// recordGapAttempt logs and potentially penalizes gap attempts
func (t *SequenceGapTracker) recordGapAttempt(walletID WalletID, expected, attempted uint64) {
    t.mu.Lock()
    defer t.mu.Unlock()

    attempt := GapAttempt{
        WalletID:      walletID,
        ExpectedSeq:   expected,
        AttemptedSeq:  attempted,
        Timestamp:     time.Now(),
    }

    // Add to history
    t.attemptHistory[walletID] = append(t.attemptHistory[walletID], attempt)

    // Clean old attempts outside window
    t.cleanOldAttempts(walletID)

    // Check if ban threshold reached
    recentAttempts := t.attemptHistory[walletID]
    if len(recentAttempts) >= SequenceGapBanThreshold {
        // Trigger temporary ban
        BanWallet(walletID, SequenceGapBanDuration, "Repeated sequence gap attempts")
    }

    // Apply reputation penalty
    ApplyReputationPenalty(walletID, SequenceGapAttemptPenalty, "sequence_gap_attempt")
}

// ErrSequenceGap provides detailed gap information
type ErrSequenceGap struct {
    Expected uint64
    Got      uint64
    Gap      uint64
    Pending  uint64
}

func (e *ErrSequenceGap) Error() string {
    return fmt.Sprintf("sequence gap detected: expected %d, got %d (gap=%d, pending=%d)",
        e.Expected, e.Got, e.Gap, e.Pending)
}
```

**Sequence Gap Attack Vectors Mitigated**:

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **Batch Invalidation** | Skip sequences to make batches invalid | Strict contiguity requirement |
| **DoS via Gaps** | Create gaps to block legitimate transactions | Reject gaps > 10 |
| **Front-Running** | Reserve future sequences | Sequence is server-assigned, not client-chosen |
| **Replay Attack** | Reuse old sequence numbers | Reject sequence <= current |

### Sequence Rollback Log (P4-H11)

On crash, sequence numbers claimed via CAS but not committed would leak, permanently blocking accounts. The rollback log enables recovery.

```go
// pkg/currency/sequence_rollback.go

// SequenceRollbackEntry tracks claimed sequence numbers for crash recovery
type SequenceRollbackEntry struct {
    AccountID     WalletID
    ClaimedSeq    uint64
    TxID          TxID
    ClaimedAt     time.Time
    Status        SequenceStatus
    CommittedAt   time.Time     // Set when tx committed
    RolledBackAt  time.Time     // Set when rolled back
}

// SequenceStatus tracks sequence claim lifecycle
type SequenceStatus uint8

const (
    SequenceStatusPending    SequenceStatus = iota // Claimed but not committed
    SequenceStatusCommitted                        // Transaction committed
    SequenceStatusRolledBack                       // Validation failed, rolled back
    SequenceStatusRecovered                        // Recovered after crash
)

// SequenceRollbackLog manages crash-safe sequence tracking
type SequenceRollbackLog struct {
    db           *pebble.DB
    logPrefix    []byte
    recoveryMu   sync.Mutex
}

// persistSequenceRollback writes rollback entry to durable storage
func (s *Shard) persistSequenceRollback(entry *SequenceRollbackEntry) error {
    key := s.makeRollbackKey(entry.AccountID, entry.ClaimedSeq)
    value, err := msgpack.Marshal(entry)
    if err != nil {
        return fmt.Errorf("marshal rollback entry: %w", err)
    }

    // Sync write - MUST be durable before continuing
    writeOpts := pebble.WriteOptions{Sync: true}
    if err := s.rollbackLog.db.Set(key, value, &writeOpts); err != nil {
        return fmt.Errorf("persist rollback entry: %w", err)
    }

    return nil
}

// updateSequenceRollback updates status of existing entry
func (s *Shard) updateSequenceRollback(entry *SequenceRollbackEntry) error {
    key := s.makeRollbackKey(entry.AccountID, entry.ClaimedSeq)
    value, err := msgpack.Marshal(entry)
    if err != nil {
        return fmt.Errorf("marshal rollback entry: %w", err)
    }

    // Can be async since we're just updating status
    return s.rollbackLog.db.Set(key, value, pebble.NoSync)
}

// RecoverSequencesOnStartup processes rollback log after crash
func (s *Shard) RecoverSequencesOnStartup() error {
    s.rollbackLog.recoveryMu.Lock()
    defer s.rollbackLog.recoveryMu.Unlock()

    iter := s.rollbackLog.db.NewIter(&pebble.IterOptions{
        LowerBound: s.rollbackLog.logPrefix,
        UpperBound: incrementPrefix(s.rollbackLog.logPrefix),
    })
    defer iter.Close()

    recoveredCount := 0
    for iter.First(); iter.Valid(); iter.Next() {
        var entry SequenceRollbackEntry
        if err := msgpack.Unmarshal(iter.Value(), &entry); err != nil {
            log.Error("failed to unmarshal rollback entry",
                "key", iter.Key(),
                "error", err)
            continue
        }

        // Only recover pending entries
        if entry.Status != SequenceStatusPending {
            continue
        }

        // Check if transaction was actually committed (WAL check)
        if s.wal.IsCommitted(entry.TxID) {
            // Transaction committed - mark as such
            entry.Status = SequenceStatusCommitted
            entry.CommittedAt = time.Now()
            s.updateSequenceRollback(&entry)
        } else {
            // Transaction not committed - rollback sequence
            authority := s.GetShardAuthority(entry.AccountID)
            currentSeq := atomic.LoadUint64(&authority.Sequence)

            if currentSeq == entry.ClaimedSeq {
                // Sequence was claimed but not used - rollback
                atomic.CompareAndSwapUint64(&authority.Sequence, currentSeq, currentSeq-1)
                entry.Status = SequenceStatusRecovered
                entry.RolledBackAt = time.Now()
                s.updateSequenceRollback(&entry)
                recoveredCount++

                log.Info("recovered leaked sequence number",
                    "account", entry.AccountID,
                    "sequence", entry.ClaimedSeq,
                    "tx_id", entry.TxID)
            }
        }
    }

    if recoveredCount > 0 {
        log.Info("sequence rollback recovery complete",
            "recovered_count", recoveredCount)
    }

    return nil
}

// CleanupCommittedRollbackEntries removes old committed entries
func (s *Shard) CleanupCommittedRollbackEntries(olderThan time.Duration) error {
    cutoff := time.Now().Add(-olderThan)

    iter := s.rollbackLog.db.NewIter(&pebble.IterOptions{
        LowerBound: s.rollbackLog.logPrefix,
        UpperBound: incrementPrefix(s.rollbackLog.logPrefix),
    })
    defer iter.Close()

    batch := s.rollbackLog.db.NewBatch()
    defer batch.Close()

    for iter.First(); iter.Valid(); iter.Next() {
        var entry SequenceRollbackEntry
        if err := msgpack.Unmarshal(iter.Value(), &entry); err != nil {
            continue
        }

        // Delete committed/recovered entries older than cutoff
        shouldDelete := false
        switch entry.Status {
        case SequenceStatusCommitted:
            shouldDelete = entry.CommittedAt.Before(cutoff)
        case SequenceStatusRolledBack, SequenceStatusRecovered:
            shouldDelete = entry.RolledBackAt.Before(cutoff)
        }

        if shouldDelete {
            batch.Delete(iter.Key(), nil)
        }
    }

    return batch.Commit(pebble.NoSync)
}

// Error types
var (
    ErrSequencePersistFailed = errors.New("failed to persist sequence claim")
)
```

**Sequence Rollback Recovery Timeline**:

```
Time T=0: CAS succeeds, sequence claimed
Time T=1: Rollback entry persisted (SYNC write)
Time T=2: Validation continues...
         [CRASH OCCURS HERE]
Time T=3: Node restarts
Time T=4: RecoverSequencesOnStartup() runs
Time T=5: Finds pending entry from T=1
Time T=6: Checks WAL - tx not committed
Time T=7: Rolls back sequence via CAS
Time T=8: Account can use sequence number again
```

**Rollback Log Storage**:

| Key Format | Value |
|------------|-------|
| `rollback:{shard}:{account}:{seq}` | SequenceRollbackEntry (msgpack) |

### UTXO Validation Edge Cases (FINAL DESIGN)

The UTXO validation process must handle several edge cases to prevent double-spend attacks and ensure consistency.

#### Input Deduplication

```go
// Input Deduplication
//
// Transaction must be rejected if the same UTXO appears twice in inputs.
// This prevents inflation attacks where an attacker tries to spend the
// same UTXO multiple times within a single transaction.

func (s *Shard) ValidateUTXOInputs(tx *Transaction) error {
    seen := make(map[UTXOID]bool)

    for i, input := range tx.Inputs {
        utxoID := UTXOID{
            TxID:        input.SourceTx,
            OutputIndex: input.OutputIndex,
        }

        if seen[utxoID] {
            return ErrDuplicateUTXOInput{
                UTXOID:     utxoID,
                TxID:       tx.ID,
                FirstIndex: findFirstIndex(tx.Inputs, utxoID),
                DupIndex:   i,
            }
        }

        seen[utxoID] = true
    }

    return nil
}

type ErrDuplicateUTXOInput struct {
    UTXOID     UTXOID
    TxID       TxID
    FirstIndex int
    DupIndex   int
}

func (e *ErrDuplicateUTXOInput) Error() string {
    return fmt.Sprintf(
        "duplicate UTXO input in transaction %x: UTXO %x appears at indices %d and %d",
        e.TxID[:8], e.UTXOID.Bytes()[:8], e.FirstIndex, e.DupIndex,
    )
}
```

#### CAS Race Window and Atomic Operations

```go
// CAS Race Window Protection
//
// The sequence claim and rollback log write must be atomic to prevent
// a race condition where:
// 1. Thread A claims sequence N via CAS
// 2. Thread B claims sequence N via CAS (fails)
// 3. Thread A crashes before writing rollback log
// 4. Sequence N is permanently leaked
//
// Solution: Wrap CAS + rollback log write in single atomic operation

type SequenceClaimOperation struct {
    AccountID    WalletID
    Sequence     uint64
    TxID         TxID
    ClaimedAt    time.Time
}

func (s *Shard) AtomicSequenceClaim(
    accountID WalletID,
    expectedSeq uint64,
    txID TxID,
) error {
    // Begin atomic operation
    s.sequenceClaimMu.Lock()
    defer s.sequenceClaimMu.Unlock()

    authority := s.GetShardAuthority(accountID)

    // Step 1: CAS to claim sequence
    if !atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq-1, expectedSeq) {
        return ErrSequenceRace{
            Expected: expectedSeq,
            Actual:   atomic.LoadUint64(&authority.Sequence),
        }
    }

    // Step 2: Immediately write rollback log entry (SYNC)
    // This ensures that if we crash, we can recover the sequence
    rollbackEntry := &SequenceRollbackEntry{
        AccountID:  accountID,
        ClaimedSeq: expectedSeq,
        TxID:       txID,
        ClaimedAt:  time.Now(),
        Status:     SequenceStatusPending,
    }

    if err := s.persistSequenceRollback(rollbackEntry); err != nil {
        // CRITICAL: Rollback the CAS immediately
        atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq, expectedSeq-1)
        return fmt.Errorf("failed to persist sequence rollback: %w", err)
    }

    // Atomic operation complete
    return nil
}
```

#### Sequence Rollback Recovery

```go
// Sequence Rollback Recovery on Startup
//
// On node startup, scan the rollback log for orphaned sequence claims
// (claims where the transaction was never committed). Release these
// sequences so they can be reused.

func (s *Shard) RecoverOrphanedSequences() error {
    s.logger.Info("scanning rollback log for orphaned sequences")

    iter := s.rollbackLog.db.NewIter(&pebble.IterOptions{
        LowerBound: s.rollbackLog.logPrefix,
        UpperBound: incrementPrefix(s.rollbackLog.logPrefix),
    })
    defer iter.Close()

    orphanedCount := 0
    for iter.First(); iter.Valid(); iter.Next() {
        var entry SequenceRollbackEntry
        if err := msgpack.Unmarshal(iter.Value(), &entry); err != nil {
            s.logger.Warn("failed to unmarshal rollback entry",
                "key", iter.Key(),
                "error", err)
            continue
        }

        // Only process pending entries
        if entry.Status != SequenceStatusPending {
            continue
        }

        // Check if transaction was committed
        if s.isTransactionCommitted(entry.TxID) {
            // Transaction committed - update entry
            entry.Status = SequenceStatusCommitted
            entry.CommittedAt = time.Now()
            s.updateSequenceRollback(&entry)
            continue
        }

        // Transaction not committed - release sequence
        authority := s.GetShardAuthority(entry.AccountID)
        currentSeq := atomic.LoadUint64(&authority.Sequence)

        if currentSeq == entry.ClaimedSeq {
            // Rollback to previous sequence
            if atomic.CompareAndSwapUint64(&authority.Sequence, currentSeq, currentSeq-1) {
                entry.Status = SequenceStatusRecovered
                entry.RolledBackAt = time.Now()
                s.updateSequenceRollback(&entry)
                orphanedCount++

                s.logger.Info("recovered orphaned sequence",
                    "account", entry.AccountID,
                    "sequence", entry.ClaimedSeq,
                    "tx_id", entry.TxID,
                    "claim_age", time.Since(entry.ClaimedAt))
            }
        }
    }

    s.logger.Info("orphaned sequence recovery complete",
        "orphaned_count", orphanedCount)

    return nil
}

func (s *Shard) isTransactionCommitted(txID TxID) bool {
    // Check write-ahead log for commit record
    return s.wal.HasCommitRecord(txID)
}
```

**Edge Case Timeline:**

| Time | Event | Sequence State | Rollback Log |
|------|-------|----------------|--------------|
| T+0ms | CAS succeeds (seq=100) | 100 (claimed) | Empty |
| T+1ms | Rollback entry written (SYNC) | 100 (claimed) | Pending |
| T+2ms | Validation starts | 100 (claimed) | Pending |
| T+5ms | **CRASH** | 100 (claimed) | Pending |
| T+10s | Node restarts | 100 (orphaned) | Pending |
| T+11s | RecoverOrphanedSequences() runs | 100 (orphaned) | Pending |
| T+12s | Check WAL: no commit found | 100 (orphaned) | Pending |
| T+13s | CAS rollback: 100 → 99 | 99 (available) | Recovered |
| T+14s | Sequence 100 available for reuse | 99 (available) | Recovered |

### Finality (CANONICAL)

Transactions reach finality through **reputation-weighted confirmation**. This section specifies the exact algorithm to prevent ambiguity.

```go
// Finality configuration - non-configurable security parameters
const (
    FinalityThreshold     = 10.0  // Combined reputation weight needed
    MinConfirmReputation  = 0.5   // Minimum reputation to provide confirmation
    MaxWeightPerNode      = 1.0   // Cap weight per node (prevents dominance)
    MaxConfirmations      = 100   // Stop counting after this
)

// Confirmation represents a node's attestation of a transaction
type Confirmation struct {
    NodeID         NodeID
    TransactionID  TxID
    NodeReputation float64   // Reputation at time of confirmation
    TPMQuote       []byte    // Fresh TPM attestation
    Timestamp      int64
    Signature      []byte
}

// CalculateFinality determines if a transaction has achieved finality
// based on reputation-weighted confirmations
func CalculateFinality(tx *Transaction, confirmations []Confirmation) bool {
    var totalWeight float64
    seen := make(map[NodeID]bool)

    for _, conf := range confirmations {
        // Skip duplicate confirmations from same node
        if seen[conf.NodeID] {
            continue
        }

        // Skip confirmations from low-reputation nodes (Sybil protection)
        if conf.NodeReputation < MinConfirmReputation {
            continue
        }

        // Cap weight per node to prevent single-node dominance
        weight := math.Min(conf.NodeReputation, MaxWeightPerNode)
        totalWeight += weight
        seen[conf.NodeID] = true

        // Early exit if threshold reached
        if totalWeight >= FinalityThreshold {
            return true
        }

        // Stop processing after MaxConfirmations
        if len(seen) >= MaxConfirmations {
            break
        }
    }

    return totalWeight >= FinalityThreshold
}
```

**Finality Examples**:

| Network Size | Avg Reputation | Min Confirmations | Expected Time |
|--------------|----------------|-------------------|---------------|
| 1K nodes | 0.5 | 20 (10.0 / 0.5) | ~2 seconds |
| 100K nodes | 0.7 | 15 (10.0 / 0.67) | ~1 second |
| 1M nodes | 0.8 | 13 (10.0 / 0.77) | ~500ms |
| 1B nodes | 0.9 | 12 (10.0 / 0.83) | ~200ms |

**Security Properties**:

1. **Sybil Resistance**: Nodes with reputation < 0.5 cannot provide confirmations
2. **Weight Capping**: No single node can contribute more than 1.0 weight
3. **No Double-Counting**: Each NodeID counted only once
4. **TPM Attestation**: Each confirmation requires fresh TPM quote

### BFT Finality Committee (CANONICAL)

**SECURITY FIX (Issue C7)**: High-value transactions and all epoch finality MUST use Byzantine Fault Tolerant finality with fixed threshold (NOT reputation-weighted) to prevent high-reputation node collusion attacks.

```go
// BFT Finality Configuration - non-configurable security parameters
const (
    BFTFinalityThreshold    = 0.67  // 2/3 + 1 of committee must confirm
    FinalityCommitteeSize   = 21    // Fixed committee size
    CommitteeRotationPeriod = 1 * time.Hour
    MaxFinalityLatency      = 3 * time.Second
    HighValueThreshold      = 1000  // Transactions above this use BFT
)

// FinalityCommittee is selected via VRF for unpredictability
type FinalityCommittee struct {
    Epoch       uint64
    Members     []NodeID
    VRFSeed     [32]byte
    ValidUntil  time.Time
}

// SelectFinalityCommittee chooses committee via VRF from eligible nodes
func SelectFinalityCommittee(epoch uint64) (*FinalityCommittee, error) {
    // Eligibility: 0.8+ reputation, 99% uptime, valid TPM attestation
    eligible := GetEligibleFinalityNodes(0.8, 0.99)

    // VRF-based selection for unpredictability
    seed := GenerateCommitteeSeed(epoch)
    members := VRFSelectNodes(seed, eligible, FinalityCommitteeSize)

    return &FinalityCommittee{
        Epoch:      epoch,
        Members:    members,
        VRFSeed:    seed,
        ValidUntil: time.Now().Add(CommitteeRotationPeriod),
    }, nil
}

// BFTFinality uses Byzantine Fault Tolerant confirmation
func BFTFinality(tx *Transaction, committee *FinalityCommittee) bool {
    confirmations := CollectConfirmations(tx, committee.Members, MaxFinalityLatency)

    // Count valid confirmations
    validCount := 0
    for _, conf := range confirmations {
        // Verify confirmer is committee member
        if !isCommitteeMember(conf.NodeID, committee) {
            continue
        }

        // Verify TPM attestation
        if !VerifyTPMQuote(conf.TPMQuote, conf.NodeID) {
            continue
        }

        // Verify signature
        if !VerifySignature(conf.NodeID, tx.ID[:], conf.Signature) {
            continue
        }

        validCount++
    }

    // BFT threshold: 2/3 + 1
    required := (FinalityCommitteeSize * 2 / 3) + 1
    return validCount >= required
}

// AntiCollusionMeasures prevent committee collusion
func AntiCollusionMeasures(committee *FinalityCommittee) {
    // 1. Geographic diversity: max 3 members per region
    enforceGeographicDiversity(committee, 3)

    // 2. TPM vendor diversity: max 5 members per vendor
    enforceVendorDiversity(committee, 5)

    // 3. Reputation spread: members should span 0.8-1.0 range
    enforceReputationSpread(committee, 0.1)

    // 4. Random rotation: 1/7 of committee rotates every 10 minutes
    scheduleGradualRotation(committee, 10*time.Minute, 3)
}
```

**Comparison: Reputation-Weighted vs BFT Finality**:

| Aspect | Reputation-Weighted | BFT (Fixed Threshold) |
|--------|---------------------|----------------------|
| Attack surface | High-rep node collusion | Committee collusion |
| Predictability | Somewhat predictable | VRF-unpredictable |
| Latency | Variable (~200ms-2s) | Fixed (~1s) |
| Byzantine tolerance | ~10% of reputation | 33% of committee |
| Sybil resistance | Via reputation | Via committee selection |

**Mandatory BFT Usage**:

| Transaction Type | Finality Method | Rationale |
|------------------|-----------------|-----------|
| Low-value (<1000 coins) | Reputation-weighted | Fast, acceptable risk |
| High-value (>=1000 coins) | BFT committee | Collusion resistance |
| Epoch checkpoints | BFT committee | Critical for DAG integrity |
| Cross-shard commits | BFT committee | Atomic guarantee required |

### DAG Total Ordering via PBFT

The DAG requires PBFT-based total ordering before commit to establish canonical transaction order and resolve conflicting paths.

```go
// TotalOrderingConfig - non-configurable security parameters
const (
    OrderingBatchSize     = 100              // Transactions per ordering batch
    OrderingBatchInterval = 100 * time.Millisecond
    PBFTRounds            = 3                // Pre-prepare, Prepare, Commit
)

// OrderingBatch contains transactions to be totally ordered
type OrderingBatch struct {
    BatchID      uint64
    Epoch        uint64
    Transactions []*Transaction
    ProposedBy   NodeID
    Timestamp    time.Time
    Signature    []byte
}

// TotalOrdering ensures deterministic transaction order
type TotalOrdering struct {
    coordinator   NodeID
    pendingBatch  []*Transaction
    batchNumber   uint64
    confirmedOrder map[TxID]uint64  // TxID -> global sequence number
}

// ProposeOrder creates ordered batch via PBFT
func (to *TotalOrdering) ProposeOrder(ctx context.Context) error {
    if len(to.pendingBatch) == 0 {
        return nil
    }

    // Create batch
    batch := &OrderingBatch{
        BatchID:      to.batchNumber,
        Epoch:        GetCurrentEpoch(),
        Transactions: to.pendingBatch,
        ProposedBy:   to.coordinator,
        Timestamp:    time.Now(),
    }
    batch.Signature = SignBatch(batch)

    // PBFT Pre-Prepare: Coordinator broadcasts proposed order
    prePrepare := &PBFTPrePrepare{
        View:   GetCurrentView(),
        Seq:    to.batchNumber,
        Digest: HashBatch(batch),
        Batch:  batch,
    }
    broadcastToCommittee(prePrepare)

    // PBFT Prepare: Committee members verify and sign
    prepares, err := collectPrepares(prePrepare, 2*time.Second)
    if err != nil {
        return fmt.Errorf("prepare phase failed: %w", err)
    }

    // Need 2f+1 prepares (f = committee_size/3)
    if len(prepares) < (FinalityCommitteeSize*2/3)+1 {
        return ErrInsufficientPrepares
    }

    // PBFT Commit: Committee commits to order
    commit := &PBFTCommit{
        View:     GetCurrentView(),
        Seq:      to.batchNumber,
        Digest:   HashBatch(batch),
        Prepares: prepares,
    }
    broadcastToCommittee(commit)

    // Collect commits
    commits, err := collectCommits(commit, 2*time.Second)
    if err != nil {
        return fmt.Errorf("commit phase failed: %w", err)
    }

    if len(commits) < (FinalityCommitteeSize*2/3)+1 {
        return ErrInsufficientCommits
    }

    // Apply total ordering
    for i, tx := range batch.Transactions {
        globalSeq := to.batchNumber*OrderingBatchSize + uint64(i)
        to.confirmedOrder[tx.ID] = globalSeq
    }

    to.batchNumber++
    to.pendingBatch = nil
    return nil
}

// ResolveConflict uses total ordering to resolve DAG conflicts
func ResolveConflict(tx1, tx2 *Transaction, ordering *TotalOrdering) *Transaction {
    seq1, ok1 := ordering.confirmedOrder[tx1.ID]
    seq2, ok2 := ordering.confirmedOrder[tx2.ID]

    if !ok1 && !ok2 {
        // Neither ordered yet - cannot resolve
        return nil
    }

    if !ok1 {
        return tx2 // Only tx2 is ordered
    }
    if !ok2 {
        return tx1 // Only tx1 is ordered
    }

    // Lower sequence number wins (first-ordered)
    if seq1 < seq2 {
        return tx1
    }
    return tx2
}
```

**Total Ordering Guarantees**:
- **Deterministic**: All honest nodes agree on same order
- **Byzantine tolerant**: Survives up to f < n/3 malicious nodes
- **Efficient**: Batched for throughput (~100 tx/batch)
- **Auditable**: PBFT messages provide proof of ordering

## DAG Epoch Boundaries (CANONICAL)

**SECURITY FIX (Issue C6)**: The DAG uses periodic epoch boundaries with Merkle checkpoints signed by the BFT finality committee. This provides finality anchors, bounded DAG growth, and enables efficient state synchronization and pruning.

### Epoch Structure and Configuration

```go
// Epoch configuration - non-configurable security parameters
const (
    EpochDuration        = 10 * time.Minute  // New epoch every 10 minutes
    EpochOverlap         = 1 * time.Minute   // Grace period for late transactions
    MinTxPerEpoch        = 100               // Minimum transactions for valid epoch
    CheckpointReplicas   = 10                // DHT replication for checkpoints
    MaxEpochsRetained    = 10                // Epochs to retain before pruning
    EpochFinalityTimeout = 30 * time.Second  // Max time to finalize epoch
)

// Epoch represents a finality boundary in the DAG
type Epoch struct {
    EpochNumber     uint64             // Monotonically increasing
    StartTime       time.Time          // Epoch start (TPM-attested)
    EndTime         time.Time          // Epoch end
    TransactionRoot [32]byte           // Merkle root of all epoch transactions
    StateRoot       [32]byte           // Merkle root of UTXO state at epoch end
    TipSet          [][32]byte         // DAG tips at epoch boundary
    PreviousEpoch   [32]byte           // Link to previous epoch hash
    TxCount         uint64             // Number of transactions in epoch
    Signatures      []CommitteeSignature // BFT committee signatures (NOT reputation-weighted)
}

// CommitteeSignature represents a BFT committee member's signature
type CommitteeSignature struct {
    NodeID    NodeID
    Signature []byte     // Ed25519 signature over epoch hash
    TPMQuote  []byte     // Fresh TPM attestation
    Timestamp time.Time
}

// EpochHash computes the canonical hash of an epoch
func (e *Epoch) Hash() [32]byte {
    h := sha256.New()
    binary.Write(h, binary.BigEndian, e.EpochNumber)
    binary.Write(h, binary.BigEndian, e.StartTime.Unix())
    binary.Write(h, binary.BigEndian, e.EndTime.Unix())
    h.Write(e.TransactionRoot[:])
    h.Write(e.StateRoot[:])
    for _, tip := range e.TipSet {
        h.Write(tip[:])
    }
    h.Write(e.PreviousEpoch[:])
    binary.Write(h, binary.BigEndian, e.TxCount)

    var hash [32]byte
    copy(hash[:], h.Sum(nil))
    return hash
}
```

### Epoch Finality Rules

```go
// EpochFinalityRules defines when an epoch becomes irreversible
type EpochFinalityRules struct {
    // BFT threshold: 2/3 + 1 of committee must sign
    RequiredSignatures int  // = (FinalityCommitteeSize * 2 / 3) + 1 = 15

    // Time constraints
    MaxFinalityDelay   time.Duration  // 30 seconds max to finalize
    MinSignatureSpread time.Duration  // Signatures must span >= 5 seconds (anti-rush)

    // Diversity requirements
    MinGeographicRegions int  // >= 5 different regions
    MinTPMVendors        int  // >= 3 different TPM vendors
}

// ValidateEpochFinality checks if epoch has achieved irreversible finality
func ValidateEpochFinality(epoch *Epoch, committee *FinalityCommittee) error {
    rules := &EpochFinalityRules{
        RequiredSignatures:   (FinalityCommitteeSize * 2 / 3) + 1,
        MaxFinalityDelay:     30 * time.Second,
        MinSignatureSpread:   5 * time.Second,
        MinGeographicRegions: 5,
        MinTPMVendors:        3,
    }

    // Rule 1: Sufficient signatures from committee members
    validSigs := 0
    signerNodes := make(map[NodeID]bool)
    var timestamps []time.Time

    for _, sig := range epoch.Signatures {
        // Must be committee member
        if !isCommitteeMember(sig.NodeID, committee) {
            continue
        }

        // No duplicate signers
        if signerNodes[sig.NodeID] {
            continue
        }

        // Verify signature
        epochHash := epoch.Hash()
        if !VerifySignature(sig.NodeID, epochHash[:], sig.Signature) {
            continue
        }

        // Verify TPM quote is fresh
        if !VerifyTPMQuoteFreshness(sig.TPMQuote, sig.Timestamp, 30*time.Second) {
            continue
        }

        validSigs++
        signerNodes[sig.NodeID] = true
        timestamps = append(timestamps, sig.Timestamp)
    }

    if validSigs < rules.RequiredSignatures {
        return ErrInsufficientSignatures{Required: rules.RequiredSignatures, Got: validSigs}
    }

    // Rule 2: Signatures must span minimum time (anti-rush attack)
    sort.Slice(timestamps, func(i, j int) bool {
        return timestamps[i].Before(timestamps[j])
    })
    spread := timestamps[len(timestamps)-1].Sub(timestamps[0])
    if spread < rules.MinSignatureSpread {
        return ErrSignatureSpreadTooNarrow{Required: rules.MinSignatureSpread, Got: spread}
    }

    // Rule 3: Geographic diversity
    regions := countUniqueRegions(signerNodes)
    if regions < rules.MinGeographicRegions {
        return ErrInsufficientGeographicDiversity{Required: rules.MinGeographicRegions, Got: regions}
    }

    // Rule 4: TPM vendor diversity
    vendors := countUniqueTPMVendors(signerNodes)
    if vendors < rules.MinTPMVendors {
        return ErrInsufficientVendorDiversity{Required: rules.MinTPMVendors, Got: vendors}
    }

    return nil
}
```

### Checkpoint Finality and Fork Resolution (CANONICAL)

**CRITICAL**: When multiple competing checkpoints exist for the same epoch, the system must have deterministic rules for selecting the canonical checkpoint and detecting/resolving forks.

```go
// CheckpointForkDetection monitors for competing checkpoints
type CheckpointForkDetection struct {
    EpochNumber       uint64
    Checkpoints       []*Epoch              // Competing checkpoints for same epoch
    CanonicalHash     [32]byte              // Selected canonical checkpoint
    ForkDetected      bool
    DetectionTime     time.Time
    ResolutionMethod  ForkResolutionMethod
}

type ForkResolutionMethod uint8

const (
    ForkResolvedByFirstValid    ForkResolutionMethod = 1  // First checkpoint with 5/7 signatures
    ForkResolvedByMostSignatures ForkResolutionMethod = 2  // Checkpoint with most valid signatures
    ForkEscalatedToCommittee    ForkResolutionMethod = 3  // Requires full committee review
    ForkBothRejected            ForkResolutionMethod = 4  // Neither checkpoint valid
)

// CheckpointSelectionRules defines canonical checkpoint selection
type CheckpointSelectionRules struct {
    // Minimum signatures for validity (simple majority of committee)
    MinSignaturesForValidity int  // 11 out of 21 (simple majority)

    // Threshold for automatic acceptance (Byzantine fault tolerant)
    QuickAcceptanceThreshold int  // 15 out of 21 (2/3 + 1, BFT threshold)

    // Fork detection window
    ForkDetectionWindow      time.Duration  // 60 seconds to collect competing checkpoints

    // Previous checkpoint validation
    RequirePreviousHashChain bool  // True - must link to previous epoch
}

var CanonicalCheckpointRules = CheckpointSelectionRules{
    MinSignaturesForValidity: 11,  // (FinalityCommitteeSize / 2) + 1
    QuickAcceptanceThreshold: 15,  // (FinalityCommitteeSize * 2 / 3) + 1
    ForkDetectionWindow:      60 * time.Second,
    RequirePreviousHashChain: true,
}
```

**Canonical Checkpoint Selection Algorithm**:

```go
// SelectCanonicalCheckpoint implements deterministic checkpoint selection
func SelectCanonicalCheckpoint(
    epochNumber uint64,
    candidates []*Epoch,
    previousEpoch *Epoch,
) (*Epoch, error) {
    rules := CanonicalCheckpointRules

    // Step 1: Filter out invalid checkpoints
    validCandidates := make([]*Epoch, 0)
    for _, candidate := range candidates {
        // Must be for correct epoch number
        if candidate.EpochNumber != epochNumber {
            continue
        }

        // Must have minimum signatures
        validSigs := countValidSignatures(candidate)
        if validSigs < rules.MinSignaturesForValidity {
            continue
        }

        // Must link to previous epoch (fork detection via hash chain)
        if rules.RequirePreviousHashChain && previousEpoch != nil {
            if candidate.PreviousEpoch != previousEpoch.Hash() {
                // FORK DETECTED: checkpoint doesn't link to previous epoch
                continue
            }
        }

        validCandidates = append(validCandidates, candidate)
    }

    // Step 2: No valid candidates
    if len(validCandidates) == 0 {
        return nil, ErrNoValidCheckpoints{EpochNumber: epochNumber}
    }

    // Step 3: Single valid candidate - accept it
    if len(validCandidates) == 1 {
        return validCandidates[0], nil
    }

    // Step 4: Multiple valid candidates - FORK DETECTED
    // Apply canonical selection rules

    // Rule 1: First checkpoint to reach QuickAcceptanceThreshold (15 signatures)
    //         This is the primary rule - first to BFT threshold wins
    var firstToThreshold *Epoch
    var firstTime time.Time

    for _, candidate := range validCandidates {
        validSigs := countValidSignatures(candidate)
        if validSigs >= rules.QuickAcceptanceThreshold {
            // Get earliest signature timestamp for this checkpoint
            earliestSig := getEarliestSignatureTime(candidate)

            if firstToThreshold == nil || earliestSig.Before(firstTime) {
                firstToThreshold = candidate
                firstTime = earliestSig
            }
        }
    }

    if firstToThreshold != nil {
        return firstToThreshold, nil
    }

    // Rule 2: No checkpoint reached QuickAcceptanceThreshold
    //         Select checkpoint with most valid signatures
    var mostSignatures *Epoch
    maxSigs := 0

    for _, candidate := range validCandidates {
        validSigs := countValidSignatures(candidate)
        if validSigs > maxSigs {
            mostSignatures = candidate
            maxSigs = validSigs
        } else if validSigs == maxSigs {
            // Tie-breaker: checkpoint with lower hash (deterministic)
            if mostSignatures == nil || compareHashes(candidate.Hash(), mostSignatures.Hash()) < 0 {
                mostSignatures = candidate
            }
        }
    }

    if mostSignatures != nil && maxSigs >= rules.MinSignaturesForValidity {
        return mostSignatures, nil
    }

    // Rule 3: Cannot determine canonical checkpoint
    //         Escalate to full committee for manual resolution
    return nil, ErrCheckpointForkRequiresEscalation{
        EpochNumber: epochNumber,
        Candidates:  len(validCandidates),
    }
}

func countValidSignatures(epoch *Epoch) int {
    valid := 0
    seen := make(map[NodeID]bool)

    for _, sig := range epoch.Signatures {
        // No duplicates
        if seen[sig.NodeID] {
            continue
        }

        // Verify signature
        epochHash := epoch.Hash()
        if !VerifySignature(sig.NodeID, epochHash[:], sig.Signature) {
            continue
        }

        // Verify TPM quote freshness
        if !VerifyTPMQuoteFreshness(sig.TPMQuote, sig.Timestamp, 30*time.Second) {
            continue
        }

        valid++
        seen[sig.NodeID] = true
    }

    return valid
}

func getEarliestSignatureTime(epoch *Epoch) time.Time {
    if len(epoch.Signatures) == 0 {
        return time.Time{}
    }

    earliest := epoch.Signatures[0].Timestamp
    for _, sig := range epoch.Signatures[1:] {
        if sig.Timestamp.Before(earliest) {
            earliest = sig.Timestamp
        }
    }
    return earliest
}

func compareHashes(a, b [32]byte) int {
    for i := 0; i < 32; i++ {
        if a[i] < b[i] {
            return -1
        }
        if a[i] > b[i] {
            return 1
        }
    }
    return 0
}
```

**Fork Detection via Previous Checkpoint Hash Chain**:

Each epoch checkpoint includes `PreviousEpoch` hash, creating an immutable chain:

```
Epoch 1: Hash(Epoch1Data) = 0xAAA...
         PreviousEpoch = 0x000... (genesis)

Epoch 2: Hash(Epoch2Data) = 0xBBB...
         PreviousEpoch = 0xAAA... (links to Epoch 1)

Epoch 3: Hash(Epoch3Data) = 0xCCC...
         PreviousEpoch = 0xBBB... (links to Epoch 2)
```

Fork detection:

```go
// DetectCheckpointFork validates hash chain continuity
func DetectCheckpointFork(current *Epoch, previous *Epoch) (bool, error) {
    if previous == nil {
        // Genesis epoch - no previous to validate
        return false, nil
    }

    expectedPreviousHash := previous.Hash()

    if current.PreviousEpoch != expectedPreviousHash {
        // FORK DETECTED: current epoch doesn't link to expected previous
        return true, &CheckpointForkError{
            EpochNumber:      current.EpochNumber,
            ExpectedPrevious: expectedPreviousHash,
            ActualPrevious:   current.PreviousEpoch,
        }
    }

    return false, nil
}

type CheckpointForkError struct {
    EpochNumber      uint64
    ExpectedPrevious [32]byte
    ActualPrevious   [32]byte
}

func (e *CheckpointForkError) Error() string {
    return fmt.Sprintf(
        "checkpoint fork at epoch %d: expected previous %x, got %x",
        e.EpochNumber,
        e.ExpectedPrevious,
        e.ActualPrevious,
    )
}
```

**Competing Checkpoint Handling**:

When multiple valid checkpoints compete (both have valid signatures and hash chains):

```go
// CompetingCheckpointProtocol handles multiple valid checkpoints
func (em *EpochManager) HandleCompetingCheckpoints(
    ctx context.Context,
    epochNumber uint64,
    checkpoints []*Epoch,
) (*Epoch, error) {
    em.logger.Warn("competing checkpoints detected",
        "epoch", epochNumber,
        "count", len(checkpoints))

    // Apply canonical selection rules
    canonical, err := SelectCanonicalCheckpoint(
        epochNumber,
        checkpoints,
        em.currentEpoch,
    )

    if err == nil {
        em.logger.Info("canonical checkpoint selected",
            "epoch", epochNumber,
            "hash", hex.EncodeToString(canonical.Hash()[:]),
            "signatures", countValidSignatures(canonical))
        return canonical, nil
    }

    // Check if error is escalation required
    if errors.Is(err, ErrCheckpointForkRequiresEscalation{}) {
        // Cannot automatically resolve - escalate to committee
        em.logger.Error("checkpoint fork requires committee intervention",
            "epoch", epochNumber,
            "candidates", len(checkpoints))

        // Trigger escalation protocol
        return em.escalateCheckpointFork(ctx, epochNumber, checkpoints)
    }

    // No valid checkpoints found
    if errors.Is(err, ErrNoValidCheckpoints{}) {
        // Reject all candidates, retry epoch finalization
        em.logger.Error("no valid checkpoints found, retrying epoch",
            "epoch", epochNumber)
        return nil, err
    }

    return nil, err
}

// escalateCheckpointFork triggers manual committee intervention
func (em *EpochManager) escalateCheckpointFork(
    ctx context.Context,
    epochNumber uint64,
    checkpoints []*Epoch,
) (*Epoch, error) {
    escalation := &CheckpointEscalation{
        EpochNumber:     epochNumber,
        Checkpoints:     checkpoints,
        EscalatedAt:     time.Now(),
        RequiredVotes:   (FinalityCommitteeSize * 2 / 3) + 1,
    }

    // Request full committee to vote on canonical checkpoint
    votes, err := em.collectCommitteeVotes(ctx, escalation)
    if err != nil {
        return nil, fmt.Errorf("failed to collect votes: %w", err)
    }

    // Tally votes - checkpoint with 2/3+ votes wins
    tallies := make(map[[32]byte]int)
    for _, vote := range votes {
        tallies[vote.CheckpointHash]++
    }

    for _, checkpoint := range checkpoints {
        hash := checkpoint.Hash()
        if tallies[hash] >= escalation.RequiredVotes {
            em.logger.Info("checkpoint fork resolved via committee vote",
                "epoch", epochNumber,
                "hash", hex.EncodeToString(hash[:]),
                "votes", tallies[hash])
            return checkpoint, nil
        }
    }

    // No checkpoint achieved 2/3 votes - reject all, retry epoch
    em.logger.Error("committee could not resolve fork, rejecting all checkpoints",
        "epoch", epochNumber)
    return nil, ErrCheckpointForkUnresolved{EpochNumber: epochNumber}
}

type CheckpointEscalation struct {
    EpochNumber   uint64
    Checkpoints   []*Epoch
    EscalatedAt   time.Time
    RequiredVotes int
}
```

**Canonical Checkpoint Rules Summary**:

| Rule | Condition | Action |
|------|-----------|--------|
| Single valid checkpoint | Only one checkpoint with 11+ signatures | Accept immediately |
| First to BFT threshold | First checkpoint to reach 15 signatures | Select as canonical |
| Most signatures | Multiple checkpoints, none at BFT threshold | Select checkpoint with most signatures |
| Tie at same signature count | Multiple with same count | Select checkpoint with lowest hash (deterministic) |
| Invalid hash chain | Checkpoint doesn't link to previous epoch | Reject checkpoint (fork detected) |
| Both checkpoints invalid | Neither has 11+ signatures | Reject both, retry epoch |
| Cannot resolve automatically | Ambiguous or complex fork | Escalate to full committee vote |

**Timeline Example - Checkpoint Fork Resolution**:

```
Time   Event                                                       Action
─────────────────────────────────────────────────────────────────────────────────
0.0s   Epoch 42 finalization begins                               Collecting signatures
15.0s  Checkpoint A receives 12 signatures                        Valid but not BFT threshold
20.0s  Checkpoint B receives 11 signatures                        Valid but not BFT threshold
25.0s  Fork detected: two valid checkpoints for epoch 42          Apply selection rules
25.1s  Rule 1 check: Neither has 15 signatures yet                Continue
30.0s  Checkpoint A receives 15 signatures                        FIRST to BFT threshold
30.1s  Canonical checkpoint selected: A                           A is canonical
30.2s  Checkpoint A stored in DHT                                 Finalized
30.3s  Checkpoint B rejected                                      Fork resolved
```

**Previous Checkpoint Hash Chain Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Fork detection | Cannot accept checkpoint with wrong parent | PreviousEpoch hash validation |
| Chain continuity | Each epoch links to previous | Immutable hash chain |
| Deterministic ordering | No ambiguity in epoch sequence | Sequential epoch numbers + hash links |
| Tamper evidence | Modified epoch breaks chain | Hash mismatch detected |
| Fast validation | O(1) check for continuity | Single hash comparison |

### Epoch Transition Protocol

```go
// EpochManager coordinates epoch transitions
type EpochManager struct {
    currentEpoch     *Epoch
    pendingTx        []*Transaction
    epochTimer       *time.Timer
    committee        *FinalityCommittee
    mu               sync.RWMutex
}

// FinalizeEpoch creates checkpoint at epoch boundary using BFT committee
func (em *EpochManager) FinalizeEpoch(ctx context.Context) (*Epoch, error) {
    em.mu.Lock()
    defer em.mu.Unlock()

    // Step 1: Collect all transactions in epoch
    epochTx := em.collectEpochTransactions()
    if len(epochTx) < MinTxPerEpoch {
        // Extend epoch if insufficient transactions (prevents empty epochs)
        return nil, ErrEpochTooSmall
    }

    // Step 2: Build transaction Merkle tree
    txRoot := buildMerkleRoot(epochTx)

    // Step 3: Snapshot UTXO state
    stateRoot := em.snapshotUTXOState()

    // Step 4: Capture DAG tips
    tips := em.captureDAGTips()

    // Step 5: Create epoch record
    epoch := &Epoch{
        EpochNumber:     em.currentEpoch.EpochNumber + 1,
        StartTime:       em.currentEpoch.EndTime,
        EndTime:         time.Now(),
        TransactionRoot: txRoot,
        StateRoot:       stateRoot,
        TipSet:          tips,
        PreviousEpoch:   em.currentEpoch.Hash(),
        TxCount:         uint64(len(epochTx)),
    }

    // Step 6: Collect BFT committee signatures (NOT reputation-weighted)
    signatures, err := em.collectBFTSignatures(ctx, epoch)
    if err != nil {
        return nil, fmt.Errorf("failed to collect BFT signatures: %w", err)
    }
    epoch.Signatures = signatures

    // Step 7: Validate epoch finality
    if err := ValidateEpochFinality(epoch, em.committee); err != nil {
        return nil, fmt.Errorf("epoch finality validation failed: %w", err)
    }

    // Step 8: Store epoch checkpoint in DHT with replication
    epochKey := fmt.Sprintf("epoch:%d", epoch.EpochNumber)
    if err := dht.Put(epochKey, epoch, CheckpointReplicas); err != nil {
        return nil, fmt.Errorf("failed to store epoch: %w", err)
    }

    // Step 9: Trigger pruning of old epochs
    go em.pruneOldEpochs(epoch.EpochNumber)

    em.currentEpoch = epoch
    return epoch, nil
}

// collectBFTSignatures gathers signatures from committee with timeout
func (em *EpochManager) collectBFTSignatures(ctx context.Context, epoch *Epoch) ([]CommitteeSignature, error) {
    epochHash := epoch.Hash()
    required := (FinalityCommitteeSize * 2 / 3) + 1

    ctx, cancel := context.WithTimeout(ctx, EpochFinalityTimeout)
    defer cancel()

    // Request signatures from all committee members in parallel
    sigChan := make(chan CommitteeSignature, FinalityCommitteeSize)
    for _, member := range em.committee.Members {
        go func(nodeID NodeID) {
            sig, err := requestEpochSignature(ctx, nodeID, epochHash)
            if err == nil {
                sigChan <- sig
            }
        }(member)
    }

    // Collect until we have enough or timeout
    var signatures []CommitteeSignature
    for {
        select {
        case sig := <-sigChan:
            signatures = append(signatures, sig)
            if len(signatures) >= required {
                return signatures, nil
            }
        case <-ctx.Done():
            if len(signatures) >= required {
                return signatures, nil
            }
            return nil, ErrInsufficientSignatures{Required: required, Got: len(signatures)}
        }
    }
}
```

### Epoch Finality Escalation Path (CANONICAL - A2 Fix)

**CRITICAL**: When epoch finality fails to complete within the timeout, the system must
have a defined escalation path rather than blocking indefinitely. This section defines
the escalation levels and recovery procedures.

```go
// EscalationLevel defines the severity of finality failure
type EscalationLevel uint8

const (
    EscalationNone        EscalationLevel = 0  // Normal operation
    EscalationSoftTimeout EscalationLevel = 1  // Initial timeout, retry with relaxed params
    EscalationHardTimeout EscalationLevel = 2  // Extended timeout, committee rotation
    EscalationEmergency   EscalationLevel = 3  // Critical failure, manual intervention
)

// EscalationConfig defines timeout thresholds and actions
type EscalationConfig struct {
    // Soft timeout: first 30 seconds, relax diversity requirements
    SoftTimeout          time.Duration  // 30 seconds
    SoftMinSignatures    int            // 12 (reduced from 15)
    SoftMinRegions       int            // 3 (reduced from 5)

    // Hard timeout: 30-60 seconds, rotate unresponsive committee members
    HardTimeout          time.Duration  // 60 seconds
    HardMinSignatures    int            // 10 (minimum safe threshold)

    // Emergency: > 60 seconds, escalate to operator and fallback
    EmergencyTimeout     time.Duration  // 120 seconds
    MaxRetryAttempts     int            // 3 attempts per escalation level
}

var DefaultEscalationConfig = EscalationConfig{
    SoftTimeout:        30 * time.Second,
    SoftMinSignatures:  12,
    SoftMinRegions:     3,
    HardTimeout:        60 * time.Second,
    HardMinSignatures:  10,
    EmergencyTimeout:   120 * time.Second,
    MaxRetryAttempts:   3,
}

// Error types for escalation
var (
    ErrEscalationRequired  = errors.New("epoch finality requires escalation")
    ErrEscalationExhausted = errors.New("all escalation levels exhausted")
    ErrManualIntervention  = errors.New("manual intervention required")
)

// EpochFinalityEscalator manages escalation for finality failures
type EpochFinalityEscalator struct {
    config       EscalationConfig
    epochManager *EpochManager
    alertManager *AlertManager
    metrics      *FinalityMetrics
}

// FinalizeWithEscalation attempts epoch finality with automatic escalation
func (e *EpochFinalityEscalator) FinalizeWithEscalation(
    ctx context.Context,
    epoch *Epoch,
) error {
    level := EscalationNone
    attempt := 0

    for level <= EscalationEmergency {
        attempt++
        startTime := time.Now()

        err := e.attemptFinality(ctx, epoch, level)
        if err == nil {
            // Success - record metrics and return
            e.metrics.RecordFinalitySuccess(level, time.Since(startTime))
            return nil
        }

        // Determine if we should escalate or retry
        if attempt >= e.config.MaxRetryAttempts {
            level++
            attempt = 0
            e.handleEscalation(epoch, level, err)
        }

        // Brief pause between attempts
        time.Sleep(1 * time.Second)
    }

    // All escalation levels exhausted
    e.triggerEmergencyProtocol(epoch)
    return ErrEscalationExhausted
}

// attemptFinality tries to finalize epoch at the given escalation level
func (e *EpochFinalityEscalator) attemptFinality(
    ctx context.Context,
    epoch *Epoch,
    level EscalationLevel,
) error {
    timeout, rules := e.getEscalationParams(level)

    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    // Collect signatures with level-appropriate parameters
    signatures, err := e.collectSignaturesWithLevel(ctx, epoch, level)
    if err != nil {
        return err
    }

    // Validate with relaxed rules if escalated
    return e.validateWithRules(epoch, signatures, rules)
}

// getEscalationParams returns timeout and rules for escalation level
func (e *EpochFinalityEscalator) getEscalationParams(level EscalationLevel) (time.Duration, *EpochFinalityRules) {
    switch level {
    case EscalationNone:
        return EpochFinalityTimeout, &EpochFinalityRules{
            RequiredSignatures:   (FinalityCommitteeSize * 2 / 3) + 1,
            MaxFinalityDelay:     30 * time.Second,
            MinSignatureSpread:   5 * time.Second,
            MinGeographicRegions: 5,
            MinTPMVendors:        3,
        }
    case EscalationSoftTimeout:
        return e.config.SoftTimeout, &EpochFinalityRules{
            RequiredSignatures:   e.config.SoftMinSignatures,
            MaxFinalityDelay:     e.config.SoftTimeout,
            MinSignatureSpread:   3 * time.Second,  // Relaxed
            MinGeographicRegions: e.config.SoftMinRegions,
            MinTPMVendors:        2,  // Relaxed
        }
    case EscalationHardTimeout:
        return e.config.HardTimeout, &EpochFinalityRules{
            RequiredSignatures:   e.config.HardMinSignatures,
            MaxFinalityDelay:     e.config.HardTimeout,
            MinSignatureSpread:   1 * time.Second,  // Minimal
            MinGeographicRegions: 2,  // Minimal
            MinTPMVendors:        1,  // Minimal
        }
    default:
        return e.config.EmergencyTimeout, &EpochFinalityRules{
            RequiredSignatures:   e.config.HardMinSignatures,
            MaxFinalityDelay:     e.config.EmergencyTimeout,
            MinSignatureSpread:   0,  // Disabled
            MinGeographicRegions: 1,
            MinTPMVendors:        1,
        }
    }
}

// handleEscalation performs actions when escalating to a new level
func (e *EpochFinalityEscalator) handleEscalation(epoch *Epoch, level EscalationLevel, cause error) {
    e.metrics.RecordEscalation(level)

    switch level {
    case EscalationSoftTimeout:
        e.alertManager.Info("Epoch finality soft timeout",
            "epoch", epoch.EpochNumber,
            "cause", cause)

    case EscalationHardTimeout:
        e.alertManager.Warn("Epoch finality hard timeout - rotating committee",
            "epoch", epoch.EpochNumber,
            "cause", cause)
        // Rotate unresponsive committee members
        e.rotateUnresponsiveMembers(epoch)

    case EscalationEmergency:
        e.alertManager.Critical("Epoch finality emergency - operator intervention required",
            "epoch", epoch.EpochNumber,
            "cause", cause)
        // Page on-call operator
        e.alertManager.Page(OnCallEpochFinality, "Epoch finality emergency", epoch)
    }
}

// rotateUnresponsiveMembers replaces committee members who haven't responded
func (e *EpochFinalityEscalator) rotateUnresponsiveMembers(epoch *Epoch) {
    unresponsive := e.identifyUnresponsiveMembers(epoch)
    for _, member := range unresponsive {
        // Select replacement via VRF
        replacement := e.selectReplacementMember(epoch, member)
        e.epochManager.committee.ReplaceMember(member, replacement)

        // Record the rotation for audit
        e.metrics.RecordMemberRotation(member, replacement, "unresponsive")
    }
}

// triggerEmergencyProtocol initiates emergency procedures when all escalation fails
func (e *EpochFinalityEscalator) triggerEmergencyProtocol(epoch *Epoch) {
    // Step 1: Halt new transaction acceptance
    e.epochManager.HaltTransactionAcceptance()

    // Step 2: Broadcast emergency state to network
    e.broadcastEmergencyState(epoch)

    // Step 3: Page all operators
    e.alertManager.PageAll("EPOCH FINALITY FAILURE - EMERGENCY", epoch)

    // Step 4: Begin genesis trustee recovery if automated recovery fails
    // (This is the last resort and requires trustee consensus)
    e.scheduleGenesisRecovery(epoch)
}
```

#### Escalation Flow Diagram

```
        EPOCH FINALITY ATTEMPT
                  |
                  v
    +---------------------------+
    |   Normal Finality (30s)   |
    |   15 sigs, 5 regions      |
    +---------------------------+
                  |
            Success?  ----Yes----> FINALIZED
                  |
                 No (3 retries)
                  |
                  v
    +---------------------------+
    | SOFT ESCALATION (30-60s)  |
    | 12 sigs, 3 regions        |
    | Relaxed diversity         |
    +---------------------------+
                  |
            Success?  ----Yes----> FINALIZED
                  |
                 No (3 retries)
                  |
                  v
    +---------------------------+
    | HARD ESCALATION (60-120s) |
    | 10 sigs, 2 regions        |
    | Committee rotation        |
    +---------------------------+
                  |
            Success?  ----Yes----> FINALIZED
                  |
                 No (3 retries)
                  |
                  v
    +---------------------------+
    | EMERGENCY (>120s)         |
    | Halt transactions         |
    | Page operators            |
    | Genesis trustee recovery  |
    +---------------------------+
```

#### Escalation Metrics and Monitoring

| Metric | Normal Range | Alert Threshold | Action |
|--------|--------------|-----------------|--------|
| Finality Time | < 10s | > 20s | Monitor |
| Soft Escalations/hour | 0 | > 2 | Investigate |
| Hard Escalations/day | 0 | > 0 | Immediate review |
| Emergency Escalations | 0 | > 0 | Incident response |
| Committee rotations/day | < 1 | > 3 | Committee health check |

#### Recovery After Emergency

After an emergency escalation, the following steps restore normal operation:

1. **Root Cause Analysis**: Identify why finality failed (network partition, attack, etc.)
2. **Committee Reconstitution**: Rebuild committee with healthy nodes
3. **State Reconciliation**: Ensure all nodes agree on the last finalized epoch
4. **Transaction Replay**: Reprocess pending transactions from halted state
5. **Gradual Resumption**: Slowly increase transaction acceptance rate
6. **Post-Mortem**: Document incident and implement preventive measures

### Pruning Protocol

```go
// PruningConfig defines DAG pruning parameters
const (
    MaxEpochsRetained    = 10                // Keep last 10 epochs (~100 minutes)
    PruningGracePeriod   = 5 * time.Minute   // Grace period after epoch finality
    MinConfirmationsForPrune = 3             // Epochs must be confirmed by N subsequent epochs
)

// PruningManager handles safe removal of old DAG state
type PruningManager struct {
    epochStore   EpochStore
    txStore      TransactionStore
    utxoStore    UTXOStore
    pruneLog     *PruneLog
}

// PruneOldEpochs removes DAG state older than retention threshold
func (pm *PruningManager) PruneOldEpochs(currentEpoch uint64) error {
    if currentEpoch <= MaxEpochsRetained {
        return nil  // Not enough epochs yet
    }

    pruneThreshold := currentEpoch - MaxEpochsRetained

    // Step 1: Verify epochs to prune are sufficiently confirmed
    for epochNum := uint64(1); epochNum <= pruneThreshold; epochNum++ {
        confirmations := pm.countEpochConfirmations(epochNum, currentEpoch)
        if confirmations < MinConfirmationsForPrune {
            return ErrEpochNotSufficientlyConfirmed{Epoch: epochNum, Confirmations: confirmations}
        }
    }

    // Step 2: Create prune log entry (for recovery)
    pruneEntry := &PruneLogEntry{
        PruneTime:      time.Now(),
        OldestRetained: pruneThreshold + 1,
        NewestPruned:   pruneThreshold,
        StateRoot:      pm.epochStore.GetEpoch(pruneThreshold + 1).StateRoot,
    }
    if err := pm.pruneLog.Append(pruneEntry); err != nil {
        return fmt.Errorf("failed to write prune log: %w", err)
    }

    // Step 3: Prune transactions (keep headers for Merkle verification)
    for epochNum := uint64(1); epochNum <= pruneThreshold; epochNum++ {
        epoch := pm.epochStore.GetEpoch(epochNum)

        // Remove transaction bodies, keep TxID -> Epoch mapping
        for _, txID := range pm.txStore.GetTxIDsInEpoch(epochNum) {
            pm.txStore.PruneTransactionBody(txID)
            pm.txStore.SetTxEpochMapping(txID, epochNum)  // Keep index
        }

        // Keep epoch headers forever (small, needed for chain verification)
        // Only prune transaction Merkle tree leaves
        pm.epochStore.PruneMerkleLeaves(epochNum)
    }

    // Step 4: Prune spent UTXOs from old epochs
    for epochNum := uint64(1); epochNum <= pruneThreshold; epochNum++ {
        pm.utxoStore.PruneSpentUTXOs(epochNum)
    }

    return nil
}

// countEpochConfirmations counts how many subsequent epochs reference this one
func (pm *PruningManager) countEpochConfirmations(epochNum uint64, currentEpoch uint64) int {
    confirmations := 0
    for e := epochNum + 1; e <= currentEpoch; e++ {
        epoch := pm.epochStore.GetEpoch(e)
        if epoch != nil && pm.epochChainValid(epochNum, e) {
            confirmations++
        }
    }
    return confirmations
}

// PruneLogEntry records pruning actions for recovery
type PruneLogEntry struct {
    PruneTime      time.Time
    OldestRetained uint64
    NewestPruned   uint64
    StateRoot      [32]byte  // UTXO state root at oldest retained
}
```

### Epoch Timeline

```
    Epoch N-2          Epoch N-1          Epoch N              Epoch N+1
    |                  |                  |                    |
    v                  v                  v                    v
----+------------------+------------------+--------------------+---------->
    |  PRUNED          |  PRUNABLE        |   FINALIZED        |  PENDING
    |  (state removed) |  (3+ confirms)   |   (BFT signed)     |  (collecting)
    |                  |                  |                    |
    +---> Header only  +---> Full epoch   +---> Full epoch     +---> Building
```

**Epoch Finality Guarantees**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Irreversibility | Epoch N-1 cannot be reversed after epoch N finalizes | BFT 2/3+1 signatures |
| Bounded DAG | Only last 10 epochs (~100 min) stored | Automatic pruning |
| Fast sync | New nodes sync from latest checkpoint | Epoch state roots |
| Partition recovery | Use epoch chain for canonical selection | Epoch hash chain |

**Storage Requirements**:

| Data Type | Retention | Size per Epoch | Total for 10 Epochs |
|-----------|-----------|----------------|---------------------|
| Epoch Header | Forever | ~500 bytes | ~5 KB |
| Transaction Merkle | 10 epochs | ~10 MB | ~100 MB |
| UTXO State | Current only | ~1 GB (1B wallets) | ~1 GB |
| DAG Tips | 2 epochs | ~1 MB | ~2 MB |

## VRF-Based Dynamic Shard Rotation (CANONICAL)

**SECURITY FIX (Issue C8)**: Static shard authority assignment enables Sybil attacks through predictable positioning. This section specifies VRF-based dynamic shard rotation with secure handoff protocol.

### Shard Rotation Configuration

```go
// ShardRotationConfig - non-configurable security parameters
const (
    ShardRotationEpoch      = 6 * time.Hour  // Shard assignments rotate every 6 hours
    RotationAnnouncePeriod  = 1 * time.Hour  // Announce rotation 1 hour in advance
    HandoffGracePeriod      = 30 * time.Minute // Grace period for completing handoff
    MinShardValidators      = 100            // Minimum validators per shard
    MaxRotationPerEpoch     = 0.10           // Max 10% of validators rotate per epoch
)

// ShardRotationEpoch represents a rotation boundary
type ShardRotationEpoch struct {
    EpochNumber       uint64
    VRFSeed           [32]byte           // Unpredictable seed for this epoch
    PreviousSeed      [32]byte           // Link to previous epoch seed
    RotationSchedule  []ShardTransfer    // Scheduled validator movements
    EffectiveTime     time.Time          // When rotation takes effect
    Signatures        []CommitteeSignature // BFT committee signatures
}

// ShardTransfer represents a single validator rotation
type ShardTransfer struct {
    ValidatorID   NodeID
    FromShard     uint16
    ToShard       uint16
    TransferProof VRFProof
    HandoffState  HandoffState
}

// HandoffState tracks the handoff progress
type HandoffState int
const (
    HandoffPending   HandoffState = iota  // Rotation announced, not started
    HandoffStarted                         // State transfer in progress
    HandoffCompleted                       // Validator active on new shard
    HandoffFailed                          // Handoff failed, rollback
)
```

### VRF-Based Shard Assignment

```go
// ShardAssignmentManager handles VRF-based shard assignment
type ShardAssignmentManager struct {
    currentEpoch     *ShardRotationEpoch
    assignments      map[NodeID]uint16      // Current shard assignments
    pendingRotations map[NodeID]*ShardTransfer
    vrfKey           VRFPrivateKey          // Node's VRF key
}

// ComputeShardAssignment computes a validator's shard using VRF
// This is deterministic given the epoch seed and validator ID
func (m *ShardAssignmentManager) ComputeShardAssignment(
    validatorID NodeID,
    epochSeed [32]byte,
) (uint16, *VRFProof, error) {

    // VRF input: epoch_seed || validator_id || "shard_assignment_v1"
    vrfInput := make([]byte, 0, 32+32+20)
    vrfInput = append(vrfInput, epochSeed[:]...)
    vrfInput = append(vrfInput, validatorID[:]...)
    vrfInput = append(vrfInput, []byte("shard_assignment_v1")...)

    // Generate VRF output and proof
    vrfOutput, vrfProof, err := m.vrfKey.Evaluate(vrfInput)
    if err != nil {
        return 0, nil, fmt.Errorf("VRF evaluation failed: %w", err)
    }

    // Deterministic shard selection: first 2 bytes of VRF output mod MaxShards
    shardIndex := binary.BigEndian.Uint16(vrfOutput[:2]) % MaxShards

    return shardIndex, vrfProof, nil
}

// VerifyShardAssignment allows anyone to verify a validator's claimed shard
func VerifyShardAssignment(
    validatorID NodeID,
    claimedShard uint16,
    epochSeed [32]byte,
    vrfProof *VRFProof,
    vrfPublicKey VRFPublicKey,
) error {

    // Reconstruct VRF input
    vrfInput := make([]byte, 0, 32+32+20)
    vrfInput = append(vrfInput, epochSeed[:]...)
    vrfInput = append(vrfInput, validatorID[:]...)
    vrfInput = append(vrfInput, []byte("shard_assignment_v1")...)

    // Verify VRF proof
    vrfOutput, err := vrfPublicKey.Verify(vrfInput, vrfProof)
    if err != nil {
        return ErrInvalidVRFProof{ValidatorID: validatorID, Reason: err.Error()}
    }

    // Verify shard matches VRF output
    expectedShard := binary.BigEndian.Uint16(vrfOutput[:2]) % MaxShards
    if claimedShard != expectedShard {
        return ErrShardMismatch{Claimed: claimedShard, Expected: expectedShard}
    }

    return nil
}

// GenerateRotationEpochSeed creates unpredictable seed for rotation epoch
func (m *ShardAssignmentManager) GenerateRotationEpochSeed(epochNumber uint64) ([32]byte, error) {
    // Combine multiple entropy sources to prevent prediction
    h := sha256.New()

    // Previous epoch seed (chain continuity)
    h.Write(m.currentEpoch.VRFSeed[:])

    // Epoch number
    binary.Write(h, binary.BigEndian, epochNumber)

    // Latest DAG epoch checkpoint (unpredictable at announcement time)
    dagEpoch := GetLatestFinalizedDAGEpoch()
    h.Write(dagEpoch.TransactionRoot[:])

    // CA pool commitment (rotates independently)
    h.Write(GetCAPoolCommitment())

    // TPM random from BFT committee (threshold-combined)
    tpmRandom, err := CollectTPMRandomFromCommittee()
    if err != nil {
        return [32]byte{}, fmt.Errorf("failed to collect TPM random: %w", err)
    }
    h.Write(tpmRandom)

    var seed [32]byte
    copy(seed[:], h.Sum(nil))
    return seed, nil
}
```

### Rotation Epoch Protocol

```go
// RotationEpochManager coordinates shard rotation epochs
type RotationEpochManager struct {
    shardManager     *ShardAssignmentManager
    committee        *FinalityCommittee
    pendingRotation  *ShardRotationEpoch
}

// InitiateRotationEpoch starts the rotation epoch process
func (rem *RotationEpochManager) InitiateRotationEpoch(ctx context.Context) error {
    nextEpochNumber := rem.shardManager.currentEpoch.EpochNumber + 1

    // Step 1: Generate new epoch seed (1 hour before rotation)
    seed, err := rem.shardManager.GenerateRotationEpochSeed(nextEpochNumber)
    if err != nil {
        return fmt.Errorf("failed to generate seed: %w", err)
    }

    // Step 2: Compute all new shard assignments
    rotations := rem.computeRotationSchedule(seed)

    // Step 3: Filter to respect MaxRotationPerEpoch
    rotations = rem.limitRotations(rotations, MaxRotationPerEpoch)

    // Step 4: Create rotation epoch
    rotationEpoch := &ShardRotationEpoch{
        EpochNumber:      nextEpochNumber,
        VRFSeed:          seed,
        PreviousSeed:     rem.shardManager.currentEpoch.VRFSeed,
        RotationSchedule: rotations,
        EffectiveTime:    time.Now().Add(RotationAnnouncePeriod),
    }

    // Step 5: Get BFT committee signatures
    signatures, err := rem.collectBFTSignatures(ctx, rotationEpoch)
    if err != nil {
        return fmt.Errorf("failed to collect signatures: %w", err)
    }
    rotationEpoch.Signatures = signatures

    // Step 6: Broadcast rotation announcement
    if err := rem.broadcastRotationAnnouncement(rotationEpoch); err != nil {
        return fmt.Errorf("failed to broadcast: %w", err)
    }

    rem.pendingRotation = rotationEpoch
    return nil
}

// computeRotationSchedule determines which validators rotate
func (rem *RotationEpochManager) computeRotationSchedule(seed [32]byte) []ShardTransfer {
    var rotations []ShardTransfer

    for validatorID, currentShard := range rem.shardManager.assignments {
        newShard, vrfProof, err := rem.shardManager.ComputeShardAssignment(validatorID, seed)
        if err != nil {
            continue
        }

        if newShard != currentShard {
            rotations = append(rotations, ShardTransfer{
                ValidatorID:   validatorID,
                FromShard:     currentShard,
                ToShard:       newShard,
                TransferProof: *vrfProof,
                HandoffState:  HandoffPending,
            })
        }
    }

    return rotations
}

// limitRotations ensures no more than maxPercent of validators rotate
func (rem *RotationEpochManager) limitRotations(rotations []ShardTransfer, maxPercent float64) []ShardTransfer {
    totalValidators := len(rem.shardManager.assignments)
    maxRotations := int(float64(totalValidators) * maxPercent)

    if len(rotations) <= maxRotations {
        return rotations
    }

    // Sort by VRF output to deterministically select which rotations proceed
    sort.Slice(rotations, func(i, j int) bool {
        return bytes.Compare(rotations[i].TransferProof.Output[:], rotations[j].TransferProof.Output[:]) < 0
    })

    return rotations[:maxRotations]
}
```

### Handoff Protocol

```go
// ShardHandoffManager handles secure state transfer during rotation
type ShardHandoffManager struct {
    validator       NodeID
    pendingHandoff  *ShardTransfer
    stateTransfer   *StateTransfer
}

// ExecuteHandoff performs the shard rotation handoff
func (hm *ShardHandoffManager) ExecuteHandoff(ctx context.Context, transfer *ShardTransfer) error {
    if transfer.ValidatorID != hm.validator {
        return ErrNotMyHandoff
    }

    // Phase 1: Prepare - notify both shards
    if err := hm.prepareHandoff(ctx, transfer); err != nil {
        return fmt.Errorf("prepare failed: %w", err)
    }
    transfer.HandoffState = HandoffStarted

    // Phase 2: Transfer state from old shard
    stateBundle, err := hm.transferState(ctx, transfer.FromShard)
    if err != nil {
        transfer.HandoffState = HandoffFailed
        return fmt.Errorf("state transfer failed: %w", err)
    }

    // Phase 3: Join new shard with transferred state
    if err := hm.joinNewShard(ctx, transfer.ToShard, stateBundle); err != nil {
        transfer.HandoffState = HandoffFailed
        return fmt.Errorf("join new shard failed: %w", err)
    }

    // Phase 4: Confirm handoff completion
    if err := hm.confirmHandoff(ctx, transfer); err != nil {
        return fmt.Errorf("confirm failed: %w", err)
    }
    transfer.HandoffState = HandoffCompleted

    return nil
}

// prepareHandoff notifies both shards of pending rotation
func (hm *ShardHandoffManager) prepareHandoff(ctx context.Context, transfer *ShardTransfer) error {
    // Create TPM-attested handoff announcement
    announcement := &HandoffAnnouncement{
        ValidatorID:   transfer.ValidatorID,
        FromShard:     transfer.FromShard,
        ToShard:       transfer.ToShard,
        VRFProof:      transfer.TransferProof,
        TPMQuote:      GenerateTPMQuote(),
        Timestamp:     time.Now(),
    }

    // Notify old shard (prepare to release validator)
    if err := NotifyShard(transfer.FromShard, &HandoffPrepare{
        Type:         HandoffPrepareLeave,
        Announcement: announcement,
    }); err != nil {
        return fmt.Errorf("notify old shard: %w", err)
    }

    // Notify new shard (prepare to accept validator)
    if err := NotifyShard(transfer.ToShard, &HandoffPrepare{
        Type:         HandoffPrepareJoin,
        Announcement: announcement,
    }); err != nil {
        return fmt.Errorf("notify new shard: %w", err)
    }

    return nil
}

// transferState retrieves validator's state from old shard
func (hm *ShardHandoffManager) transferState(ctx context.Context, fromShard uint16) (*StateBundle, error) {
    // Request state bundle from old shard
    stateReq := &StateTransferRequest{
        ValidatorID: hm.validator,
        TPMQuote:    GenerateTPMQuote(),
        Timestamp:   time.Now(),
    }

    // State bundle includes:
    // - Pending transactions being validated
    // - UTXO locks held by this validator
    // - Reputation data
    // - Recent confirmation history
    stateBundle, err := RequestStateTransfer(fromShard, stateReq)
    if err != nil {
        return nil, fmt.Errorf("request state: %w", err)
    }

    // Verify state bundle integrity
    if err := stateBundle.Verify(); err != nil {
        return nil, fmt.Errorf("invalid state bundle: %w", err)
    }

    return stateBundle, nil
}

// joinNewShard registers validator on new shard with transferred state
func (hm *ShardHandoffManager) joinNewShard(ctx context.Context, toShard uint16, state *StateBundle) error {
    joinReq := &ShardJoinRequest{
        ValidatorID:  hm.validator,
        StateBundle:  state,
        VRFProof:     hm.pendingHandoff.TransferProof,
        TPMQuote:     GenerateTPMQuote(),
        Timestamp:    time.Now(),
    }

    // New shard verifies:
    // 1. VRF proof is valid for this epoch
    // 2. State bundle is properly signed by old shard
    // 3. TPM attestation is fresh
    return JoinShard(toShard, joinReq)
}

// confirmHandoff finalizes the rotation
func (hm *ShardHandoffManager) confirmHandoff(ctx context.Context, transfer *ShardTransfer) error {
    confirmation := &HandoffConfirmation{
        ValidatorID:   transfer.ValidatorID,
        FromShard:     transfer.FromShard,
        ToShard:       transfer.ToShard,
        CompletedAt:   time.Now(),
        TPMQuote:      GenerateTPMQuote(),
    }

    // Notify old shard to release resources
    if err := NotifyShard(transfer.FromShard, &HandoffComplete{
        Type:         HandoffCompleteLeave,
        Confirmation: confirmation,
    }); err != nil {
        return fmt.Errorf("confirm leave: %w", err)
    }

    // Notify new shard that validator is fully active
    if err := NotifyShard(transfer.ToShard, &HandoffComplete{
        Type:         HandoffCompleteJoin,
        Confirmation: confirmation,
    }); err != nil {
        return fmt.Errorf("confirm join: %w", err)
    }

    return nil
}
```

**Shard Rotation Security Properties**:

| Property | Mechanism | Attack Prevented |
|----------|-----------|------------------|
| Unpredictable | VRF-based assignment | Sybil pre-positioning |
| Verifiable | VRF proofs | False assignment claims |
| Gradual | Max 10% rotation/epoch | Mass migration attacks |
| Recoverable | Handoff state transfer | State loss during rotation |
| Auditable | BFT-signed rotation epochs | Unauthorized rotations |

## Cross-Shard Transaction Lock TTL (CANONICAL)

**SECURITY FIX (Issue #12)**: Without explicit lock TTL, funds can be frozen permanently if a cross-shard transaction fails to complete. This section specifies explicit lock TTL, timeout recovery protocol, and orphan lock cleanup.

### Lock Configuration

```go
// LockTTLConfig - non-configurable security parameters
//
// P4-M13 FIX: Harmonize Lock TTL with 3PC Protocol Timeouts
//
// The 3PC protocol has total timeout of ~10 seconds (2s+3s+5s). Lock TTL MUST be
// consistent with this to avoid:
// 1. Lock expiring during slow 3PC → transaction fails
// 2. Lock held for hours after 3PC aborts → funds frozen
//
// Solution: Short operational lock TTL, longer recovery TTL
const (
    // Operational Lock TTL (for active 3PC transactions)
    // CANONICAL VALUE: 60 seconds
    // Derivation: CoordinatorFailoverTimeout (30s) + detection latency (8s) + buffer (22s)
    // Rationale: Lock TTL MUST exceed NewCoordinatorWaitTimeout to prevent race condition
    //            where locks expire during coordinator failover, freezing funds.
    OperationalLockTTL    = 60 * time.Second   // Default for 3PC transactions

    // 3PC Phase Timeouts (inner ring - must complete within Lock TTL)
    Phase1CanCommitTimeout  = 2 * time.Second  // CanCommit phase timeout
    Phase2PreCommitTimeout  = 3 * time.Second  // PreCommit phase timeout
    Phase3DoCommitTimeout   = 5 * time.Second  // DoCommit phase timeout
    Total3PCTimeout         = 10 * time.Second // Sum of all phases
    NetworkBufferMargin     = 20 * time.Second // Network latency + retry margin

    // Recovery Lock TTL (for orphan detection and recovery)
    // Longer to allow coordinator restart and recovery protocols
    RecoveryLockTTL       = 5 * time.Minute    // For recovery scenarios

    // Legacy/backward compatibility (DEPRECATED - do not use for new code)
    DefaultLockTTL        = OperationalLockTTL // Alias to operational
    MinLockTTL            = 10 * time.Second   // Must allow 3PC to complete
    MaxLockTTL            = 120 * time.Second  // Max total including one extension

    // Lock Extension Configuration
    // Coordinator can extend ONCE with 2/3 shard agreement
    LockExtensionLimit       = 1                  // Max ONE extension per lock
    LockExtensionDuration    = 30 * time.Second   // Duration per extension
    LockExtensionQuorum      = 0.67               // 2/3 shard agreement required
    MaxTotalLockDuration     = 120 * time.Second  // 60s base + 30s extension + 30s buffer

    // Orphan Lock Scanner Configuration
    OrphanLockScanInterval   = 5 * time.Minute    // Scan every 5 minutes
    OrphanLockAgeThreshold   = 120 * time.Second  // Locks > 2x TTL (60s * 2)
    OrphanLockGracePeriod    = 5 * time.Minute    // Grace period before cleanup
)

// LockTTLPolicy determines appropriate lock TTL based on context
type LockTTLPolicy uint8

const (
    LockTTLPolicyOperational LockTTLPolicy = iota // Normal 3PC transaction
    LockTTLPolicyRecovery                          // Coordinator recovery
    LockTTLPolicyManual                            // Explicit TTL specified
)

// GetRecommendedLockTTL returns the appropriate lock TTL for a given context
func GetRecommendedLockTTL(policy LockTTLPolicy) time.Duration {
    switch policy {
    case LockTTLPolicyOperational:
        return OperationalLockTTL
    case LockTTLPolicyRecovery:
        return RecoveryLockTTL
    default:
        return OperationalLockTTL
    }
}
```

### Lock TTL and 3PC Timeout Harmonization (P4-M13)

**CRITICAL**: Lock TTL and 3PC timeouts MUST be harmonized to prevent:
1. **Lock-Protocol Race**: Lock expires during valid 3PC → spurious abort
2. **Zombie Locks**: Lock held long after 3PC aborts → funds frozen
3. **Timeout Storm**: Mismatched timeouts cause cascading failures

#### Timeout Hierarchy

```
┌────────────────────────────────────────────────────────────────────┐
│                      TIMEOUT HIERARCHY                              │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  3PC Protocol Timeouts (Inner Ring - Fastest)                      │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ T1 (CanCommit)  = 2 seconds                            │       │
│  │ T2 (PreCommit)  = 3 seconds                            │       │
│  │ T3 (DoCommit)   = 5 seconds                            │       │
│  │ ──────────────────────────────────────────────────     │       │
│  │ Total 3PC Time  = 10 seconds                           │       │
│  └────────────────────────────────────────────────────────┘       │
│                                                                    │
│  Coordinator Failover Timeout                                      │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ NewCoordinatorWaitTimeout = 30 seconds                 │       │
│  │   Time to detect crash + elect new coordinator         │       │
│  └────────────────────────────────────────────────────────┘       │
│                                                                    │
│  Lock TTL (Must Exceed Failover + Detection)                       │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ OperationalLockTTL = 60 seconds                        │       │
│  │   = 30s (failover) + 8s (detection) + 22s (buffer)     │       │
│  │   CRITICAL: Must be > NewCoordinatorWaitTimeout        │       │
│  └────────────────────────────────────────────────────────┘       │
│                                                                    │
│  Recovery TTL (For Coordinator Restart)                            │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ RecoveryLockTTL = 5 minutes                            │       │
│  │   Allows coordinator restart + state recovery          │       │
│  └────────────────────────────────────────────────────────┘       │
│                                                                    │
│  Orphan Detection (Cleanup Safety Net)                             │
│  ┌────────────────────────────────────────────────────────┐       │
│  │ OrphanLockGracePeriod = 5 minutes                      │       │
│  │   Final safety net for stuck locks                     │       │
│  └────────────────────────────────────────────────────────┘       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

#### Invariants

| Invariant | Constraint | Reason |
|-----------|------------|--------|
| Lock TTL > Failover + Detection | 60s > (30s + 8s) | Prevent race condition during coordinator failover |
| Lock TTL > 3PC Total | 60s > 10s | Lock must survive full 3PC |
| Lock TTL < Orphan Grace | 60s < 300s | Orphan scanner catches stuck locks |
| Extension Duration ≤ Lock TTL | 30s < 60s | Extensions are smaller than base TTL |
| Orphan Age = 2x Lock TTL | 120s = 2 * 60s | Detect potential orphans after max expected duration |
| Max Total Duration | 120s = 60s + 30s + 30s | Base TTL + one extension + buffer |

#### Lock TTL Canonical Reference (AUTHORITATIVE)

This section provides the single source of truth for all Lock TTL values to eliminate ambiguity and ensure consistency across the system.

**CANONICAL LOCK TTL VALUES**:

```go
// Lock TTL Configuration - CANONICAL VALUES
// All lock-related timeouts are defined here. Do NOT define lock timeouts elsewhere.

const (
    // ═══════════════════════════════════════════════════════════════════
    // OPERATIONAL LOCK TTL (Primary)
    // ═══════════════════════════════════════════════════════════════════
    // Used for: Active 3PC cross-shard transactions
    // Derivation: Lock TTL must exceed CoordinatorFailoverTimeout (30s) +
    //             detection latency (8s) + buffer (22s) = 60s minimum
    // Rationale: Lock TTL MUST be >= NewCoordinatorWaitTimeout to prevent
    //            race condition where locks expire during coordinator failover,
    //            freezing funds. Detection latency accounts for heartbeat
    //            timeout (15s max) minus heartbeat interval (5s) = 10s worst-case,
    //            rounded to 8s for safety margin.
    //           = 30s (failover) + 8s (detection) + 22s (buffer)
    //           = 60 seconds
    OperationalLockTTL = 60 * time.Second

    // ═══════════════════════════════════════════════════════════════════
    // LOCK EXTENSION (Optional, Coordinator-Initiated)
    // ═══════════════════════════════════════════════════════════════════
    // Maximum extensions: 1 (requires 2/3 shard quorum)
    // Extension duration: 30 seconds (increased to maintain 50% ratio)
    // Total maximum lock time: 60s + 30s = 90 seconds
    LockExtensionLimit     = 1
    LockExtensionDuration  = 30 * time.Second
    LockExtensionQuorum    = 0.67  // 2/3 shard agreement required
    MaxTotalLockDuration   = 120 * time.Second  // 60s base + 30s extension + 30s buffer

    // ═══════════════════════════════════════════════════════════════════
    // RECOVERY LOCK TTL (Extended for Coordinator Recovery)
    // ═══════════════════════════════════════════════════════════════════
    // Used for: Coordinator crash recovery scenarios
    // Allows time for: New coordinator election + state recovery + retry
    RecoveryLockTTL = 5 * time.Minute  // 300 seconds

    // ═══════════════════════════════════════════════════════════════════
    // ORPHAN DETECTION AND CLEANUP
    // ═══════════════════════════════════════════════════════════════════
    // Scan interval: How often to check for orphaned locks
    // Age threshold: Locks older than this are investigated (2x OperationalLockTTL)
    // Grace period: How long to wait before forcing cleanup
    OrphanLockScanInterval = 5 * time.Minute   // 300 seconds
    OrphanLockAgeThreshold = 120 * time.Second // 2x OperationalLockTTL (2 * 60s)
    OrphanLockGracePeriod  = 5 * time.Minute   // 300 seconds

    // ═══════════════════════════════════════════════════════════════════
    // DEPRECATED (For Backward Compatibility Only)
    // ═══════════════════════════════════════════════════════════════════
    // DO NOT use these in new code. Use OperationalLockTTL instead.
    DefaultLockTTL = OperationalLockTTL
    MinLockTTL     = 10 * time.Second  // Must allow 3PC to complete
    MaxLockTTL     = MaxTotalLockDuration
)
```

**Lock TTL Selection Decision Tree**:

```
┌─────────────────────────────────────────────────────────────────┐
│           LOCK TTL SELECTION DECISION TREE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Is this a cross-shard transaction?                             │
│  └─ YES: Is coordinator in recovery mode?                       │
│     ├─ YES: Use RecoveryLockTTL (300s)                          │
│     │        Reason: Allow time for coordinator election +      │
│     │                state recovery + retry attempts            │
│     │                                                            │
│     └─ NO:  Use OperationalLockTTL (60s)                        │
│             Reason: Normal 3PC transaction                      │
│             Extension: +30s if coordinator requests (max 1x)    │
│                                                                 │
│  Is this a single-shard transaction?                            │
│  └─ YES: No lock TTL needed                                     │
│           Reason: Atomic local transaction                      │
│                                                                 │
│  Is this an orphan lock cleanup?                                │
│  └─ YES: Check OrphanLockAgeThreshold (60s)                     │
│           If age > 60s: Mark for cleanup                        │
│           If age > 300s: Force cleanup (grace period expired)   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Lock TTL State Transition Timing**:

```
Lock Lifecycle with TTL:

0s     Lock Acquired
       ├─ OperationalLockTTL = 60s
       ├─ State: LockStateHeld
       └─ Transaction begins 3PC

10s    3PC completes (typical case)
       └─ Lock released early (best case)

30s    Coordinator failover window
       ├─ NewCoordinatorWaitTimeout = 30s
       └─ Lock remains valid during coordinator election

60s    OperationalLockTTL expires
       ├─ If transaction still active: Coordinator can request extension
       ├─ Extension requires 2/3 shard quorum
       └─ Extension adds +30s (LockExtensionDuration)

90s    Extension period complete (if extended)
       └─ Coordinator can commit or must abort

120s   MaxTotalLockDuration reached (2x OperationalLockTTL)
       ├─ OrphanLockAgeThreshold: Orphan scanner investigates
       ├─ Lock marked as potentially orphaned
       └─ Coordinator contact attempted

300s   OrphanLockGracePeriod expires
       ├─ Lock forcibly released
       ├─ Funds unfrozen
       └─ Transaction permanently failed
```

**Lock TTL Validation Rules**:

All lock acquisitions MUST validate TTL against these rules:

```go
// ValidateLockTTL ensures requested TTL is within acceptable bounds
func ValidateLockTTL(requestedTTL time.Duration, policy LockTTLPolicy) error {
    switch policy {
    case LockTTLPolicyOperational:
        // Operational locks must be exactly OperationalLockTTL
        if requestedTTL != OperationalLockTTL {
            return ErrInvalidLockTTL{
                Requested: requestedTTL,
                Required:  OperationalLockTTL,
                Reason:    "operational locks must use canonical 60s TTL",
            }
        }

    case LockTTLPolicyRecovery:
        // Recovery locks must be exactly RecoveryLockTTL
        if requestedTTL != RecoveryLockTTL {
            return ErrInvalidLockTTL{
                Requested: requestedTTL,
                Required:  RecoveryLockTTL,
                Reason:    "recovery locks must use canonical 300s TTL",
            }
        }

    case LockTTLPolicyManual:
        // Manual locks must be within bounds
        if requestedTTL < MinLockTTL {
            return ErrLockTTLTooShort{
                Requested: requestedTTL,
                Minimum:   MinLockTTL,
            }
        }
        if requestedTTL > MaxTotalLockDuration {
            return ErrLockTTLTooLong{
                Requested: requestedTTL,
                Maximum:   MaxTotalLockDuration,
            }
        }

    default:
        return ErrUnknownLockTTLPolicy{Policy: policy}
    }

    return nil
}
```

**Lock TTL Extension Protocol**:

```go
// ExtendLockTTL extends a lock's TTL with quorum approval
func (lm *LockManager) ExtendLockTTL(
    ctx context.Context,
    lockID [32]byte,
    coordinatorID NodeID,
) error {
    lock := lm.getLock(lockID)
    if lock == nil {
        return ErrLockNotFound{LockID: lockID}
    }

    // Rule 1: Cannot extend beyond MaxExtensions
    if lock.ExtensionCount >= LockExtensionLimit {
        return ErrMaxExtensionsReached{
            LockID:        lockID,
            CurrentCount:  lock.ExtensionCount,
            MaxAllowed:    LockExtensionLimit,
        }
    }

    // Rule 2: Cannot extend beyond MaxTotalLockDuration
    totalDuration := time.Since(lock.AcquiredAt)
    if totalDuration+LockExtensionDuration > MaxTotalLockDuration {
        return ErrLockDurationExceeded{
            LockID:       lockID,
            CurrentAge:   totalDuration,
            MaxDuration:  MaxTotalLockDuration,
        }
    }

    // Rule 3: Require 2/3 shard quorum approval
    shards := lm.getParticipantShards(lock.TransactionID)
    approvals := lm.requestExtensionApprovals(ctx, lockID, shards)

    requiredApprovals := int(float64(len(shards)) * LockExtensionQuorum)
    if approvals < requiredApprovals {
        return ErrInsufficientQuorum{
            Required: requiredApprovals,
            Received: approvals,
        }
    }

    // Rule 4: Extend TTL atomically
    newExpiry := lock.ExpiresAt.Add(LockExtensionDuration)
    if err := lm.atomicUpdateExpiry(lockID, newExpiry); err != nil {
        return fmt.Errorf("failed to extend lock: %w", err)
    }

    lock.ExtensionCount++
    lock.ExpiresAt = newExpiry

    lm.logger.Info("lock extended",
        "lock_id", hex.EncodeToString(lockID[:]),
        "extension_count", lock.ExtensionCount,
        "new_expiry", newExpiry)

    return nil
}
```

**CRITICAL CONSISTENCY RULES**:

1. **Single Source of Truth**: All lock TTL values are defined in the constants above. Do NOT hardcode lock timeouts elsewhere.

2. **No Magic Numbers**: Never use literal timeout values (e.g., `30 * time.Second`). Always reference the named constant (e.g., `OperationalLockTTL`).

3. **Extension Limits**: Locks can be extended MAX 1 time for 30 seconds. Total maximum lock duration is 120 seconds (60s base + 30s extension + 30s buffer).

4. **Orphan Cleanup**: Locks older than 2x OperationalLockTTL (120 seconds) are investigated. Locks older than OrphanLockGracePeriod (300 seconds) are forcibly released.

5. **Recovery TTL**: Only use RecoveryLockTTL during coordinator crash recovery. Normal operations use OperationalLockTTL.

6. **Failover Protection**: OperationalLockTTL MUST exceed NewCoordinatorWaitTimeout + detection latency to prevent race conditions during coordinator failover that could freeze funds.

7. **Validation Required**: All lock acquisitions MUST call ValidateLockTTL() to ensure compliance with canonical values.

#### Timeline Example

```
Time   Action                                    Lock State
──────────────────────────────────────────────────────────────────
0.0s   Coordinator receives cross-shard TX       (no lock)
0.1s   CanCommit sent, locks acquired            Lock acquired (TTL=30s)
0.1s   Lock TTL deadline = T+30s                 Expires at 30.1s
2.0s   CanCommit timeout (worst case)            Lock age: 2s
2.1s   PreCommit sent                            Lock age: 2s
5.0s   PreCommit timeout (worst case)            Lock age: 5s
5.1s   DoCommit sent                             Lock age: 5s
10.0s  DoCommit timeout (worst case)             Lock age: 10s
10.1s  Transaction complete, lock released       Lock released
30.0s  (If not released) Lock expires            Lock auto-released

Note: 20 second margin (30s - 10s) allows for:
- Network latency (up to 5s each direction)
- Retries (one full retry = +10s)
- Clock skew (up to 2s)
```

// UTXOLock represents a lock on a UTXO during cross-shard transaction
type UTXOLock struct {
    LockID          [32]byte      // Unique lock identifier
    UTXOID          UTXOID        // Locked UTXO
    TransactionID   TxID          // Cross-shard transaction holding lock
    HolderShard     uint16        // Shard that created the lock
    AcquiredAt      time.Time     // When lock was acquired
    ExpiresAt       time.Time     // Absolute expiration time (TTL)
    ExtensionCount  int           // Number of extensions granted
    State           LockState     // Current lock state
    TPMQuote        []byte        // TPM attestation at acquisition
}

// LockState represents the current state of a UTXO lock
type LockState int
const (
    LockStateHeld       LockState = iota  // Lock is active (CanCommit phase)
    LockStatePreCommit                     // Lock in PreCommit phase (durable)
    LockStateCommitting                    // Lock in DoCommit phase
    LockStateReleased                      // Lock has been released
    LockStateExpired                       // Lock expired (TTL reached)
    LockStateOrphaned                      // Lock orphaned (no coordinator)
)

// LockAcquisitionRequest for acquiring a UTXO lock with explicit TTL
type LockAcquisitionRequest struct {
    UTXOID        UTXOID
    TransactionID TxID
    RequestedTTL  time.Duration  // Requested lock duration
    ShardID       uint16
    TPMQuote      []byte
    Timestamp     time.Time
    Signature     []byte
}
```

### Lock Acquisition with TTL

```go
// LockManager handles UTXO lock lifecycle with TTL enforcement
type LockManager struct {
    locks          map[UTXOID]*UTXOLock
    locksByTx      map[TxID][]*UTXOLock
    orphanScanner  *OrphanLockScanner
    mu             sync.RWMutex
}

// AcquireLock creates a new UTXO lock with explicit TTL
func (lm *LockManager) AcquireLock(ctx context.Context, req *LockAcquisitionRequest) (*UTXOLock, error) {
    lm.mu.Lock()
    defer lm.mu.Unlock()

    // Validate TTL bounds
    ttl := req.RequestedTTL
    if ttl < MinLockTTL {
        ttl = MinLockTTL
    }
    if ttl > MaxLockTTL {
        ttl = MaxLockTTL
    }

    // Check if UTXO is already locked
    if existing, ok := lm.locks[req.UTXOID]; ok {
        // Check if existing lock has expired
        if time.Now().Before(existing.ExpiresAt) {
            return nil, ErrUTXOAlreadyLocked{
                UTXOID:    req.UTXOID,
                HeldBy:    existing.TransactionID,
                ExpiresAt: existing.ExpiresAt,
            }
        }
        // Existing lock expired, clean it up
        lm.cleanupExpiredLock(existing)
    }

    // Verify UTXO exists and is unspent
    utxo, err := lm.getUTXO(req.UTXOID)
    if err != nil {
        return nil, fmt.Errorf("UTXO not found: %w", err)
    }
    if utxo.Spent {
        return nil, ErrUTXOAlreadySpent{UTXOID: req.UTXOID}
    }

    // Create lock with explicit TTL
    now := time.Now()
    lock := &UTXOLock{
        LockID:         generateLockID(req.UTXOID, req.TransactionID),
        UTXOID:         req.UTXOID,
        TransactionID:  req.TransactionID,
        HolderShard:    req.ShardID,
        AcquiredAt:     now,
        ExpiresAt:      now.Add(ttl),
        ExtensionCount: 0,
        State:          LockStateHeld,
        TPMQuote:       req.TPMQuote,
    }

    // Store lock
    lm.locks[req.UTXOID] = lock
    lm.locksByTx[req.TransactionID] = append(lm.locksByTx[req.TransactionID], lock)

    // Schedule expiration check
    go lm.scheduleExpirationCheck(lock)

    return lock, nil
}

// scheduleExpirationCheck monitors lock for TTL expiration
func (lm *LockManager) scheduleExpirationCheck(lock *UTXOLock) {
    timer := time.NewTimer(time.Until(lock.ExpiresAt))
    defer timer.Stop()

    <-timer.C

    lm.mu.Lock()
    defer lm.mu.Unlock()

    // Check if lock still exists and hasn't been released
    currentLock, ok := lm.locks[lock.UTXOID]
    if !ok || currentLock.LockID != lock.LockID {
        return // Lock was released or replaced
    }

    if currentLock.State == LockStateHeld || currentLock.State == LockStatePreCommit {
        // Lock expired - mark as expired
        currentLock.State = LockStateExpired
        lm.handleLockExpiration(currentLock)
    }
}
```

### Deterministic Lock TTL (CANONICAL - Non-Renewable)

**CRITICAL SECURITY PROPERTY**: Cross-shard transaction locks are **NOT** renewable. This design decision ensures deterministic transaction completion and prevents indefinite resource holds.

**Design Rationale**:

| Property | Value | Rationale |
|----------|-------|-----------|
| Lock TTL | 60 seconds | Hard deadline, non-negotiable |
| Extensions | **NOT ALLOWED** | Prevents indefinite resource holds |
| Renewal mechanism | **NONE** | By design - forces deterministic completion |
| Failure mode | Transaction rollback | Clean failure, no stuck funds |

**Why No Lock Extensions**:

1. **Deterministic Completion**: Transactions MUST complete or fail within 60 seconds. No exceptions.
2. **Prevents Griefing**: Malicious coordinators cannot hold locks indefinitely by repeatedly requesting extensions.
3. **Resource Fairness**: UTXOs cannot be locked beyond a known maximum duration.
4. **Simplifies Recovery**: Participants know exactly when locks expire without tracking extension state.
5. **DoS Resistance**: Attackers cannot tie up resources by stalling transactions.

```go
// DeterministicLockTTL - CANONICAL SPECIFICATION
//
// Cross-shard locks have a hard 60-second deadline with NO extension mechanism.
// This is a deliberate security design choice, not a limitation.

const (
    // CrossShardLockTTL is the non-negotiable lock duration
    // Transactions MUST complete within this window or fail
    CrossShardLockTTL = 60 * time.Second

    // LockExtensionAllowed is explicitly false - extensions are NOT supported
    LockExtensionAllowed = false

    // LockRenewalAllowed is explicitly false - renewals are NOT supported
    LockRenewalAllowed = false
)

// ErrLockExtensionNotSupported is returned when extension is attempted
type ErrLockExtensionNotSupported struct {
    LockID        [32]byte
    TransactionID TxID
    Reason        string
}

func (e ErrLockExtensionNotSupported) Error() string {
    return fmt.Sprintf("lock extension not supported: %s (lock=%x, tx=%x)",
        e.Reason, e.LockID[:8], e.TransactionID[:8])
}

// ValidateLockLifecycle ensures lock adheres to non-renewable policy
func ValidateLockLifecycle(lock *UTXOLock) error {
    // Check if lock has exceeded hard TTL deadline
    lockAge := time.Since(lock.AcquiredAt)
    if lockAge > CrossShardLockTTL {
        return ErrLockExpired{
            LockID:     lock.LockID,
            AcquiredAt: lock.AcquiredAt,
            ExpiredAt:  lock.AcquiredAt.Add(CrossShardLockTTL),
            CurrentAge: lockAge,
        }
    }

    // Reject any extension attempts
    if lock.ExtensionCount > 0 {
        return ErrLockExtensionNotSupported{
            LockID:        lock.LockID,
            TransactionID: lock.TransactionID,
            Reason:        "lock extensions are disabled by protocol design",
        }
    }

    return nil
}
```

**Lock Lifecycle with Hard Deadline**:

```
0s     Lock Acquired (CrossShardLockTTL = 60s starts)
       |
       | Transaction executes 3PC protocol
       | Must complete within 60 seconds
       |
10s    Typical 3PC completion (best case)
       |
30s    Coordinator failover window
       | New coordinator has 30s remaining
       |
60s    HARD DEADLINE - Lock EXPIRES
       |
       v
       ┌─────────────────────────────────────┐
       │ Lock State = LockStateExpired       │
       │ Transaction = ROLLBACK              │
       │ UTXOs = UNLOCKED                    │
       │ Funds = AVAILABLE                   │
       └─────────────────────────────────────┘

NO EXTENSION POSSIBLE - BY DESIGN
```

**Comparison with Extension-Based Systems**:

| Aspect | Non-Renewable (Our Design) | Extension-Based |
|--------|---------------------------|-----------------|
| Max lock duration | 60s (guaranteed) | Unbounded |
| Griefing risk | None | High |
| Recovery complexity | Simple | Complex |
| State tracking | Minimal | Extension history |
| Determinism | Full | Partial |
| DoS resistance | High | Medium |

### Legacy Lock Extension Protocol (DEPRECATED)

**WARNING**: Lock extensions are **DEPRECATED** and **DISABLED**. This section is retained for historical reference only. All extension requests will be rejected with `ErrLockExtensionNotSupported`.

```go
// DEPRECATED: LockExtensionRequest - Extensions are no longer supported
// Retained for backward compatibility during transition period
type LockExtensionRequest struct {
    LockID        [32]byte
    TransactionID TxID
    Reason        ExtensionReason  // DEPRECATED
    RequestedBy   NodeID
    TPMQuote      []byte
    Timestamp     time.Time
    Signature     []byte
}

// DEPRECATED: LockExtensionVote - Extensions are no longer supported
type LockExtensionVote struct {
    ShardID       uint16
    TransactionID TxID
    Vote          bool              // true = approve, false = reject
    Reason        string            // Reason for rejection (if any)
    TPMQuote      []byte            // TPM attestation of vote
    Timestamp     time.Time
    Signature     []byte
}

// ExtensionReason documents why extension is needed
type ExtensionReason int
const (
    ExtensionReasonNetworkDelay    ExtensionReason = iota  // Network latency
    ExtensionReasonShardCongestion                          // Destination shard busy
    ExtensionReasonCoordinatorSwitch                        // Coordinator failover
)

// ExtendLockWithQuorum extends lock TTL with 2/3 shard agreement
func (lm *LockManager) ExtendLockWithQuorum(
    ctx context.Context,
    req *LockExtensionRequest,
    involvedShards []uint16,
) error {
    lm.mu.Lock()
    defer lm.mu.Unlock()

    // Find lock by transaction ID
    locks, ok := lm.locksByTx[req.TransactionID]
    if !ok {
        return ErrLockNotFound{TransactionID: req.TransactionID}
    }

    var targetLock *UTXOLock
    for _, lock := range locks {
        if lock.LockID == req.LockID {
            targetLock = lock
            break
        }
    }
    if targetLock == nil {
        return ErrLockNotFound{LockID: req.LockID}
    }

    // Check extension limit - ONLY ONE EXTENSION ALLOWED
    if targetLock.ExtensionCount >= LockExtensionLimit {
        return ErrExtensionLimitReached{
            LockID:     req.LockID,
            Extensions: targetLock.ExtensionCount,
            Limit:      LockExtensionLimit,
        }
    }

    // Check lock state allows extension
    if targetLock.State != LockStateHeld && targetLock.State != LockStatePreCommit {
        return ErrLockStateInvalid{State: targetLock.State, Required: LockStateHeld}
    }

    // CRITICAL: Collect 2/3 shard agreement for extension
    votes, err := lm.collectExtensionVotes(ctx, req, involvedShards)
    if err != nil {
        return fmt.Errorf("failed to collect extension votes: %w", err)
    }

    // Count approvals
    approvals := 0
    for _, vote := range votes {
        if vote.Vote {
            approvals++
        }
    }

    // Require 2/3 quorum
    requiredApprovals := int(math.Ceil(float64(len(involvedShards)) * LockExtensionQuorum))
    if approvals < requiredApprovals {
        return ErrExtensionQuorumNotMet{
            Required: requiredApprovals,
            Received: approvals,
            Total:    len(involvedShards),
        }
    }

    // Extend TTL by fixed 15 seconds
    newExpiry := time.Now().Add(LockExtensionDuration)

    // Enforce maximum total duration of 45 seconds
    maxExpiry := targetLock.AcquiredAt.Add(MaxTotalLockDuration)
    if newExpiry.After(maxExpiry) {
        newExpiry = maxExpiry
    }

    targetLock.ExpiresAt = newExpiry
    targetLock.ExtensionCount++

    // Log extension with quorum evidence for audit
    lm.logExtensionWithQuorum(targetLock, req.Reason, votes)

    return nil
}

// collectExtensionVotes requests extension votes from all participating shards
func (lm *LockManager) collectExtensionVotes(
    ctx context.Context,
    req *LockExtensionRequest,
    shards []uint16,
) ([]LockExtensionVote, error) {
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()

    votes := make([]LockExtensionVote, 0, len(shards))
    voteChan := make(chan LockExtensionVote, len(shards))

    // Request votes in parallel
    for _, shardID := range shards {
        go func(sid uint16) {
            vote, err := lm.requestShardExtensionVote(ctx, sid, req)
            if err != nil {
                voteChan <- LockExtensionVote{
                    ShardID: sid,
                    Vote:    false,
                    Reason:  err.Error(),
                }
                return
            }
            voteChan <- *vote
        }(shardID)
    }

    // Collect votes with timeout
    for i := 0; i < len(shards); i++ {
        select {
        case vote := <-voteChan:
            votes = append(votes, vote)
        case <-ctx.Done():
            break
        }
    }

    return votes, nil
}
```

**Lock Extension Quorum Table**:

| Shards Involved | Required Approvals (2/3) | Can Extend Without |
|-----------------|--------------------------|-------------------|
| 2 | 2 | No minority extension |
| 3 | 2 | 1 non-responding shard |
| 4 | 3 | 1 non-responding shard |
| 5 | 4 | 1 non-responding shard |

### Timeout Recovery Protocol

```go
// TimeoutRecoveryManager handles lock expiration and recovery
type TimeoutRecoveryManager struct {
    lockManager    *LockManager
    coordinator    *CrossShardCoordinator
}

// handleLockExpiration processes an expired lock
func (lm *LockManager) handleLockExpiration(lock *UTXOLock) {
    // Step 1: Query coordinator for transaction status
    txStatus, err := lm.queryCoordinatorStatus(lock.TransactionID)
    if err != nil {
        // Coordinator unreachable - mark as orphaned
        lock.State = LockStateOrphaned
        lm.handleOrphanedLock(lock)
        return
    }

    switch txStatus.Phase {
    case PhaseCanCommit:
        // Transaction still in CanCommit - safe to abort
        lm.abortTransaction(lock)

    case PhasePreCommit:
        // Transaction in PreCommit - check if majority committed
        if txStatus.MajorityPreCommitted {
            // Force completion
            lm.forceCompletion(lock, txStatus)
        } else {
            // Safe to abort
            lm.abortTransaction(lock)
        }

    case PhaseDoCommit:
        // Transaction in DoCommit - must complete
        lm.forceCompletion(lock, txStatus)

    case PhaseAborted:
        // Already aborted - release lock
        lm.releaseLock(lock)

    case PhaseCommitted:
        // Already committed - release lock
        lm.releaseLock(lock)
    }
}

// abortTransaction safely aborts a transaction with expired lock
func (lm *LockManager) abortTransaction(lock *UTXOLock) {
    // Create abort record
    abortRecord := &TransactionAbort{
        TransactionID: lock.TransactionID,
        Reason:        AbortReasonLockExpired,
        LockID:        lock.LockID,
        AbortedAt:     time.Now(),
        TPMQuote:      GenerateTPMQuote(),
    }

    // Broadcast abort to all involved shards
    involvedShards := lm.getInvolvedShards(lock.TransactionID)
    for _, shardID := range involvedShards {
        NotifyShard(shardID, &AbortNotification{
            AbortRecord: abortRecord,
        })
    }

    // Release all locks for this transaction
    for _, txLock := range lm.locksByTx[lock.TransactionID] {
        txLock.State = LockStateReleased
        delete(lm.locks, txLock.UTXOID)
    }
    delete(lm.locksByTx, lock.TransactionID)

    // Log abort for audit
    lm.logAbort(abortRecord)
}

// forceCompletion attempts to complete a stuck transaction
func (lm *LockManager) forceCompletion(lock *UTXOLock, txStatus *TransactionStatus) {
    // This transaction is past the point of no return
    // Must complete even if coordinator is unavailable

    // Step 1: Gather PreCommit evidence from shards
    preCommitEvidence := lm.gatherPreCommitEvidence(lock.TransactionID)

    // Step 2: Verify majority have PreCommitted
    if len(preCommitEvidence) < (len(txStatus.InvolvedShards)*2/3)+1 {
        // Cannot force complete without majority
        lm.escalateToManualRecovery(lock)
        return
    }

    // Step 3: Force DoCommit on all shards
    forceCommit := &ForceDoCommit{
        TransactionID:     lock.TransactionID,
        PreCommitEvidence: preCommitEvidence,
        ForcedAt:          time.Now(),
        TPMQuote:          GenerateTPMQuote(),
    }

    for _, shardID := range txStatus.InvolvedShards {
        NotifyShard(shardID, &ForceCommitNotification{
            ForceCommit: forceCommit,
        })
    }

    // Release lock after forced completion
    lock.State = LockStateReleased
}
```

### Forced Lock Release Protocol (CANONICAL)

After lock TTL expiry, any participating shard can force-release the lock by providing signed timeout evidence. This prevents permanent fund lockup when the coordinator becomes unavailable.

**CANONICAL RULES**:
- Any shard participant can initiate forced release after TTL expiry
- Must provide TPM-attested timeout evidence with timestamp proof
- Release requires cryptographic proof that TTL has expired
- All shards must accept the forced release or provide counter-evidence

```go
// ForcedLockRelease represents a participant-initiated lock release after TTL expiry
type ForcedLockRelease struct {
    LockID          [32]byte
    TransactionID   TxID
    InitiatorShard  uint16            // Shard initiating the forced release
    TimeoutEvidence *LockTimeoutEvidence
    TPMQuote        []byte            // TPM attestation of release decision
    Timestamp       time.Time
    Signature       []byte
}

// LockTimeoutEvidence provides cryptographic proof that lock TTL has expired
type LockTimeoutEvidence struct {
    LockID         [32]byte
    AcquiredAt     time.Time         // Original lock acquisition time
    ExpiresAt      time.Time         // Lock expiration time (TTL deadline)
    CurrentTime    time.Time         // Current time (must be > ExpiresAt)
    LockState      LockState         // State at time of evidence generation
    TPMTimestamp   []byte            // TPM-attested timestamp proving current time
    ShardID        uint16            // Shard generating evidence
    Signature      []byte            // Shard signature over evidence
}

// ForceReleaseLock allows any shard participant to release an expired lock
func (lm *LockManager) ForceReleaseLock(
    ctx context.Context,
    release *ForcedLockRelease,
) error {
    // Step 1: Verify timeout evidence
    if err := lm.verifyTimeoutEvidence(release.TimeoutEvidence); err != nil {
        return fmt.Errorf("invalid timeout evidence: %w", err)
    }

    // Step 2: Verify initiator is a valid participant in this transaction
    if !lm.isTransactionParticipant(release.TransactionID, release.InitiatorShard) {
        return ErrNotTransactionParticipant{
            TxID:    release.TransactionID,
            ShardID: release.InitiatorShard,
        }
    }

    // Step 3: Verify TPM attestation
    if err := VerifyTPMQuote(release.TPMQuote, release.InitiatorShard); err != nil {
        return fmt.Errorf("invalid TPM attestation: %w", err)
    }

    lm.mu.Lock()
    defer lm.mu.Unlock()

    // Step 4: Find and release the lock
    lock, ok := lm.locks[release.TimeoutEvidence.LockID]
    if !ok {
        // Lock already released - idempotent success
        return nil
    }

    // Step 5: Verify lock is actually expired
    if time.Now().Before(lock.ExpiresAt) {
        return ErrLockNotExpired{
            LockID:    release.LockID,
            ExpiresAt: lock.ExpiresAt,
        }
    }

    // Step 6: Create forced release record for audit
    releaseRecord := &ForcedReleaseRecord{
        LockID:          release.LockID,
        TransactionID:   release.TransactionID,
        InitiatorShard:  release.InitiatorShard,
        TimeoutEvidence: release.TimeoutEvidence,
        ReleasedAt:      time.Now(),
        TPMQuote:        release.TPMQuote,
    }

    // Step 7: Persist record before releasing
    if err := lm.persistForcedReleaseRecord(releaseRecord); err != nil {
        return fmt.Errorf("failed to persist release record: %w", err)
    }

    // Step 8: Broadcast release notification to all participants
    lm.broadcastForcedRelease(release)

    // Step 9: Release the lock
    lock.State = LockStateReleased
    delete(lm.locks, lock.UTXOID)

    return nil
}

// verifyTimeoutEvidence validates the cryptographic proof of lock expiry
func (lm *LockManager) verifyTimeoutEvidence(evidence *LockTimeoutEvidence) error {
    // Verify signature
    if err := VerifyShardSignature(evidence.ShardID, evidence); err != nil {
        return fmt.Errorf("invalid evidence signature: %w", err)
    }

    // Verify TPM timestamp attestation
    if err := VerifyTPMTimestamp(evidence.TPMTimestamp, evidence.CurrentTime); err != nil {
        return fmt.Errorf("invalid TPM timestamp: %w", err)
    }

    // Verify time relationship: CurrentTime > ExpiresAt
    if !evidence.CurrentTime.After(evidence.ExpiresAt) {
        return ErrLockNotExpired{
            LockID:    evidence.LockID,
            ExpiresAt: evidence.ExpiresAt,
        }
    }

    return nil
}
```

**Forced Release Timeline**:

```
Time   Event                                    Action
----------------------------------------------------------------------
0.0s   Lock acquired                            TTL = 30s, expires at T+30s
30.0s  Lock TTL expires                         Lock state = Expired
30.1s  Participant detects expiry               Generates timeout evidence
30.2s  Participant broadcasts ForcedLockRelease All shards verify and release
30.5s  Lock released on all shards              Funds unlocked
```

**Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No premature release | Evidence proves TTL expired | TPM-attested timestamp |
| Audit trail | All forced releases logged | ForcedReleaseRecord persistence |
| Non-repudiation | Initiator identity verified | TPM attestation + signature |
| Participant-only | Only tx participants can release | isTransactionParticipant check |

### Orphan Lock Cleanup Protocol

**CANONICAL RULES**:
- Scanner runs every 5 minutes (OrphanLockScanInterval)
- Identifies locks older than 2x TTL (60 seconds for 30s TTL)
- Auto-releases orphaned locks with audit trail
- Best-effort coordinator notification

```go
// OrphanLockScanner periodically cleans up orphaned locks
// CANONICAL: Runs every 5 minutes, identifies locks > 2x TTL (60s)
type OrphanLockScanner struct {
    lockManager    *LockManager
    scanInterval   time.Duration  // CANONICAL: 5 minutes
    ageThreshold   time.Duration  // CANONICAL: 2x TTL = 60 seconds
    gracePeriod    time.Duration
    stopChan       chan struct{}
}

// NewOrphanLockScanner creates scanner with canonical configuration
func NewOrphanLockScanner(lm *LockManager) *OrphanLockScanner {
    return &OrphanLockScanner{
        lockManager:  lm,
        scanInterval: OrphanLockScanInterval,   // 5 minutes
        ageThreshold: OrphanLockAgeThreshold,   // 60 seconds (2x 30s TTL)
        gracePeriod:  OrphanLockGracePeriod,    // 5 minutes
        stopChan:     make(chan struct{}),
    }
}

// StartOrphanScanner begins periodic orphan lock cleanup
func (ols *OrphanLockScanner) Start(ctx context.Context) {
    ticker := time.NewTicker(ols.scanInterval)  // Every 5 minutes
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ols.stopChan:
            return
        case <-ticker.C:
            ols.scanAndCleanup()
        }
    }
}

// scanAndCleanup identifies and cleans orphaned locks
func (ols *OrphanLockScanner) scanAndCleanup() {
    ols.lockManager.mu.Lock()
    defer ols.lockManager.mu.Unlock()

    now := time.Now()
    var orphanedLocks []*UTXOLock

    // Step 1: Identify orphaned locks (age > 2x TTL = 60 seconds)
    for _, lock := range ols.lockManager.locks {
        if ols.isOrphaned(lock, now) {
            orphanedLocks = append(orphanedLocks, lock)
        }
    }

    // Step 2: Process each orphaned lock
    for _, lock := range orphanedLocks {
        ols.cleanupOrphanedLock(lock)
    }

    // Step 3: Log scan results
    if len(orphanedLocks) > 0 {
        logOrphanScanResult(len(orphanedLocks), now)
    }
}

// isOrphaned determines if a lock should be considered orphaned
// CANONICAL: Lock is orphaned if age > 2x TTL (60 seconds)
func (ols *OrphanLockScanner) isOrphaned(lock *UTXOLock, now time.Time) bool {
    // Already marked as orphaned
    if lock.State == LockStateOrphaned {
        return true
    }

    // CANONICAL: Check if lock age exceeds 2x TTL threshold (60 seconds)
    lockAge := now.Sub(lock.AcquiredAt)
    if lockAge > ols.ageThreshold {  // > 60 seconds
        // Check if coordinator is still alive before orphaning
        if !ols.coordinatorAlive(lock.TransactionID) {
            return true
        }
        // Coordinator alive but lock is stale - still orphan it
        // This handles the case where coordinator is alive but stuck
        if lockAge > ols.ageThreshold*2 {  // > 120 seconds absolute max
            return true
        }
    }

    // Expired and past grace period
    if lock.State == LockStateExpired {
        return now.After(lock.ExpiresAt.Add(ols.gracePeriod))
    }

    return false
}

// cleanupOrphanedLock safely releases an orphaned lock
func (ols *OrphanLockScanner) cleanupOrphanedLock(lock *UTXOLock) {
    // Step 1: Create cleanup record for audit
    cleanupRecord := &OrphanCleanupRecord{
        LockID:        lock.LockID,
        UTXOID:        lock.UTXOID,
        TransactionID: lock.TransactionID,
        AcquiredAt:    lock.AcquiredAt,
        ExpiredAt:     lock.ExpiresAt,
        CleanedAt:     time.Now(),
        Reason:        "orphan_cleanup",
        TPMQuote:      GenerateTPMQuote(),
    }

    // Step 2: Persist cleanup record (for dispute resolution)
    ols.lockManager.persistCleanupRecord(cleanupRecord)

    // Step 3: Attempt to notify coordinator (best effort)
    go ols.notifyCoordinatorOfCleanup(lock.TransactionID, cleanupRecord)

    // Step 4: Release the lock
    lock.State = LockStateReleased
    delete(ols.lockManager.locks, lock.UTXOID)

    // Step 5: Remove from transaction index
    txLocks := ols.lockManager.locksByTx[lock.TransactionID]
    for i, l := range txLocks {
        if l.LockID == lock.LockID {
            txLocks = append(txLocks[:i], txLocks[i+1:]...)
            break
        }
    }
    if len(txLocks) == 0 {
        delete(ols.lockManager.locksByTx, lock.TransactionID)
    } else {
        ols.lockManager.locksByTx[lock.TransactionID] = txLocks
    }

    // Step 6: Log cleanup event
    ols.lockManager.logOrphanCleanup(cleanupRecord)
}

// coordinatorAlive checks if the transaction coordinator is responsive
func (ols *OrphanLockScanner) coordinatorAlive(txID TxID) bool {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    coordinator := ols.lockManager.getCoordinator(txID)
    if coordinator == nil {
        return false
    }

    // Ping coordinator
    return PingNode(ctx, coordinator.NodeID) == nil
}
```

**Lock TTL Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No permanent freeze | Funds released after TTL | Explicit expiration |
| Bounded lock time | Max 24 hours | MaxLockTTL constant |
| Limited extensions | Max 3 extensions | ExtensionLimit constant |
| Orphan cleanup | Automatic recovery | OrphanLockScanner |
| Audit trail | All cleanups logged | CleanupRecord persistence |

**Lock State Transitions**:

```
    AcquireLock()
         |
         v
    [LockStateHeld] -----> ExtendLock() -----> [LockStateHeld]
         |                                          |
         | PreCommit                                 |
         v                                           |
    [LockStatePreCommit] <---------------------------+
         |
         | DoCommit
         v
    [LockStateCommitting]
         |
         +-----> Success -----> [LockStateReleased]
         |
         +-----> TTL Expired -----> [LockStateExpired]
                                         |
                                         | Grace period
                                         v
                                   [LockStateOrphaned]
                                         |
                                         | Cleanup
                                         v
                                   [LockStateReleased]
```

### S11: Atomic Lock State Transitions (SECURITY FIX)

Lock state transitions MUST be atomic to prevent race conditions where multiple goroutines attempt to transition the same lock simultaneously. This section specifies atomic state transition using compare-and-swap operations.

#### Problem Statement

**Race condition vulnerability:**
1. Goroutine A calls `handleLockExpiration()` and reads `lock.State = LockStateHeld`
2. Goroutine B calls `handleLockExpiration()` and reads `lock.State = LockStateHeld`
3. Both attempt to transition to `LockStateExpired`
4. Both succeed (non-atomic assignment)
5. Double cleanup triggers, potentially corrupting state

#### Atomic Lock State Implementation

```go
// LockState is stored atomically to prevent concurrent transition races
type UTXOLock struct {
    LockID          [32]byte
    UTXOID          UTXOID
    TransactionID   TxID
    HolderShard     uint16
    AcquiredAt      time.Time
    ExpiresAt       time.Time
    ExtensionCount  int
    StateFlag       uint32        // ATOMIC: Use atomic.CompareAndSwapUint32
    TPMQuote        []byte
}

// Typed errors for state transition failures
var (
    ErrStateTransitionRace     = errors.New("lock state transition race detected")
    ErrInvalidStateTransition  = errors.New("invalid lock state transition")
)

// ValidStateTransitions defines allowed state transitions (adjacency list)
var ValidStateTransitions = map[LockState][]LockState{
    LockStateHeld:       {LockStatePreCommit, LockStateExpired, LockStateReleased},
    LockStatePreCommit:  {LockStateCommitting, LockStateExpired, LockStateReleased},
    LockStateCommitting: {LockStateReleased, LockStateExpired},
    LockStateExpired:    {LockStateOrphaned, LockStateReleased},
    LockStateOrphaned:   {LockStateReleased},
    LockStateReleased:   {}, // Terminal state - no transitions allowed
}

// transitionState atomically transitions lock from expected to new state
func (lock *UTXOLock) transitionState(expected, newState LockState) error {
    // Validate transition is allowed
    allowedTransitions, ok := ValidStateTransitions[expected]
    if !ok {
        return fmt.Errorf("%w: unknown current state %d", ErrInvalidStateTransition, expected)
    }

    transitionAllowed := false
    for _, allowed := range allowedTransitions {
        if allowed == newState {
            transitionAllowed = true
            break
        }
    }
    if !transitionAllowed {
        return fmt.Errorf("%w: %d -> %d not allowed", ErrInvalidStateTransition, expected, newState)
    }

    // Atomic compare-and-swap
    if !atomic.CompareAndSwapUint32(&lock.StateFlag, uint32(expected), uint32(newState)) {
        currentState := LockState(atomic.LoadUint32(&lock.StateFlag))
        return fmt.Errorf("%w: expected %d, found %d", ErrStateTransitionRace, expected, currentState)
    }

    return nil
}

// getState atomically reads lock state
func (lock *UTXOLock) getState() LockState {
    return LockState(atomic.LoadUint32(&lock.StateFlag))
}
```

#### Updated Expiration Handler with Atomic Transitions

```go
// handleLockExpiration with atomic state transitions
func (lm *LockManager) handleLockExpiration(lock *UTXOLock) {
    // Atomic transition to expired state
    currentState := lock.getState()
    if currentState != LockStateHeld && currentState != LockStatePreCommit {
        // Already transitioned by another goroutine - race handled
        return
    }

    // Attempt atomic transition
    if err := lock.transitionState(currentState, LockStateExpired); err != nil {
        // Race condition - another goroutine won
        // Log and return - the other goroutine will handle it
        logStateTransitionRace(lock.LockID, currentState, LockStateExpired, err)
        return
    }

    // Now we own the transition - proceed with recovery
    txStatus, err := lm.queryCoordinatorStatus(lock.TransactionID)
    if err != nil {
        // Coordinator unreachable - transition to orphaned
        if err := lock.transitionState(LockStateExpired, LockStateOrphaned); err != nil {
            logStateTransitionRace(lock.LockID, LockStateExpired, LockStateOrphaned, err)
            return
        }
        lm.handleOrphanedLock(lock)
        return
    }

    // ... rest of recovery logic with atomic transitions ...
}

// abortTransaction with atomic state transitions
func (lm *LockManager) abortTransaction(lock *UTXOLock) {
    // Create abort record first (before state changes)
    abortRecord := &TransactionAbort{
        TransactionID: lock.TransactionID,
        Reason:        AbortReasonLockExpired,
        LockID:        lock.LockID,
        AbortedAt:     time.Now(),
        TPMQuote:      GenerateTPMQuote(),
    }

    // Broadcast abort to all involved shards
    involvedShards := lm.getInvolvedShards(lock.TransactionID)
    for _, shardID := range involvedShards {
        NotifyShard(shardID, &AbortNotification{AbortRecord: abortRecord})
    }

    // Release all locks atomically
    lm.mu.Lock()
    defer lm.mu.Unlock()

    for _, txLock := range lm.locksByTx[lock.TransactionID] {
        currentState := txLock.getState()

        // Only transition if in a valid pre-release state
        if _, allowed := ValidStateTransitions[currentState]; allowed {
            for _, nextState := range ValidStateTransitions[currentState] {
                if nextState == LockStateReleased {
                    if err := txLock.transitionState(currentState, LockStateReleased); err == nil {
                        delete(lm.locks, txLock.UTXOID)
                    }
                    break
                }
            }
        }
    }
    delete(lm.locksByTx, lock.TransactionID)

    lm.logAbort(abortRecord)
}

// cleanupOrphanedLock with atomic state transitions
func (ols *OrphanLockScanner) cleanupOrphanedLock(lock *UTXOLock) {
    currentState := lock.getState()

    // Only cleanup if in orphaned or expired state
    if currentState != LockStateOrphaned && currentState != LockStateExpired {
        return
    }

    // Attempt atomic transition to released
    if err := lock.transitionState(currentState, LockStateReleased); err != nil {
        // Another goroutine handled this lock
        logStateTransitionRace(lock.LockID, currentState, LockStateReleased, err)
        return
    }

    // Create cleanup record for audit (after successful transition)
    cleanupRecord := &OrphanCleanupRecord{
        LockID:        lock.LockID,
        UTXOID:        lock.UTXOID,
        TransactionID: lock.TransactionID,
        AcquiredAt:    lock.AcquiredAt,
        ExpiredAt:     lock.ExpiresAt,
        CleanedAt:     time.Now(),
        FromState:     currentState,
        Reason:        "orphan_cleanup",
        TPMQuote:      GenerateTPMQuote(),
    }

    // Persist and cleanup (we now own the lock state)
    ols.lockManager.persistCleanupRecord(cleanupRecord)

    // Best effort coordinator notification
    go ols.notifyCoordinatorOfCleanup(lock.TransactionID, cleanupRecord)

    // Remove from lock maps
    ols.lockManager.mu.Lock()
    delete(ols.lockManager.locks, lock.UTXOID)
    txLocks := ols.lockManager.locksByTx[lock.TransactionID]
    for i, l := range txLocks {
        if l.LockID == lock.LockID {
            txLocks = append(txLocks[:i], txLocks[i+1:]...)
            break
        }
    }
    if len(txLocks) == 0 {
        delete(ols.lockManager.locksByTx, lock.TransactionID)
    } else {
        ols.lockManager.locksByTx[lock.TransactionID] = txLocks
    }
    ols.lockManager.mu.Unlock()

    ols.lockManager.logOrphanCleanup(cleanupRecord)
}
```

#### State Transition Race Detection Metrics

```go
// StateTransitionMetrics tracks race condition occurrences for monitoring
type StateTransitionMetrics struct {
    SuccessfulTransitions   uint64  // Atomic counter
    RaceConditionsDetected  uint64  // Atomic counter (should be low)
    InvalidTransitions      uint64  // Atomic counter (should be zero)
}

var lockMetrics StateTransitionMetrics

func recordSuccessfulTransition() {
    atomic.AddUint64(&lockMetrics.SuccessfulTransitions, 1)
}

func recordRaceCondition() {
    atomic.AddUint64(&lockMetrics.RaceConditionsDetected, 1)
}

func recordInvalidTransition() {
    atomic.AddUint64(&lockMetrics.InvalidTransitions, 1)
}
```

**Atomic Lock State Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No double cleanup | Single goroutine wins CAS | CompareAndSwap |
| Valid transitions only | Transition matrix validation | ValidStateTransitions map |
| Race detection | Metrics for monitoring | StateTransitionMetrics |
| State integrity | No intermediate states visible | Atomic operations |

## Parent Proof in Transaction Structure (CANONICAL)

**SECURITY FIX (Issue C14)**: Without Merkle proofs of parent inclusion, nodes cannot verify that referenced parent transactions actually exist in the DAG. This section specifies the parent proof structure and verification protocol.

### Parent Proof Structure

```go
// ParentProof provides cryptographic proof of parent transaction inclusion
type ParentProof struct {
    ParentTxID     TxID             // The parent transaction ID being proven
    EpochNumber    uint64           // Epoch containing the parent
    MerkleProof    []MerkleNode     // Proof path from leaf to root
    ProofIndex     uint64           // Index of parent in epoch's Merkle tree
    EpochRoot      [32]byte         // Epoch's transaction Merkle root
    EpochSignature CommitteeSignature // BFT signature on epoch (verifies root)
}

// MerkleNode represents a single node in the Merkle proof path
type MerkleNode struct {
    Hash     [32]byte
    Position MerklePosition  // Left or Right sibling
}

// MerklePosition indicates sibling position in proof
type MerklePosition int
const (
    MerkleLeft  MerklePosition = 0  // Sibling is on the left
    MerkleRight MerklePosition = 1  // Sibling is on the right
)

// Transaction with mandatory parent proofs
type TransactionWithProofs struct {
    // Core transaction fields
    ID          TxID
    Version     uint8
    Parents     []TxID            // 2-3 parent transaction IDs
    ParentProofs []ParentProof    // MANDATORY: Proof for each parent

    // Payment fields
    From        WalletID
    To          WalletID
    Amount      uint64
    Fee         uint64
    Sequence    uint64

    // Attestation
    TPMQuote    []byte
    Timestamp   int64
    Signature   []byte
}
```

### Parent Proof Timing and Validity (P4-M15)

**CRITICAL**: Parent proofs have a limited validity window to prevent:
1. **Stale proof attacks**: Using ancient proofs to reference pruned data
2. **Replay attacks**: Reusing old proofs after epoch finalization
3. **Storage bloat**: Requiring nodes to store all historical epoch data

#### Timing Constants

```go
// pkg/currency/parent_proof_timing.go

// Parent proof validity window - non-configurable security parameters
const (
    // ParentProofEpochWindow: Number of epochs during which a parent proof is valid
    // Proof valid in: current epoch + previous 2 epochs = 3 epoch window
    ParentProofEpochWindow = 2

    // MaxParentAge: Maximum age of a parent transaction relative to child
    // Transactions cannot reference parents older than this
    MaxParentAge = 3 * EpochDuration  // Approximately 3 epochs worth of time

    // MinParentAge: Minimum age before a parent can be referenced
    // Parents must be in a finalized epoch (not current unfinalized)
    MinParentAge = 1 * time.Minute    // Must survive at least one finality round

    // ProofRefreshGracePeriod: Time before proof expiration to request refresh
    ProofRefreshGracePeriod = 30 * time.Second
)

// EpochDuration varies by network load, but typically:
// - Light load: 5-10 minutes per epoch
// - Normal load: 1-5 minutes per epoch
// - Heavy load: 30 seconds - 1 minute per epoch
var EpochDuration = 5 * time.Minute  // Default for planning purposes

// ParentProofValidityError indicates a timing violation
type ParentProofValidityError struct {
    ProofEpoch     uint64
    CurrentEpoch   uint64
    WindowSize     int
    Reason         string
}

func (e *ParentProofValidityError) Error() string {
    return fmt.Sprintf(
        "parent proof epoch %d invalid (current: %d, window: %d epochs): %s",
        e.ProofEpoch, e.CurrentEpoch, e.WindowSize, e.Reason,
    )
}
```

#### Validity Window Calculation

```go
// ValidateParentProofTiming checks if a parent proof is within the valid epoch window
func ValidateParentProofTiming(proof *ParentProof, currentEpoch uint64) error {
    // Rule 1: Proof cannot be from the future
    if proof.EpochNumber > currentEpoch {
        return &ParentProofValidityError{
            ProofEpoch:   proof.EpochNumber,
            CurrentEpoch: currentEpoch,
            WindowSize:   ParentProofEpochWindow,
            Reason:       "proof epoch is in the future",
        }
    }

    // Rule 2: Proof must be within the validity window
    // Valid epochs: [currentEpoch - ParentProofEpochWindow, currentEpoch]
    minValidEpoch := currentEpoch - uint64(ParentProofEpochWindow)
    if currentEpoch < uint64(ParentProofEpochWindow) {
        minValidEpoch = 0  // Handle underflow at network start
    }

    if proof.EpochNumber < minValidEpoch {
        return &ParentProofValidityError{
            ProofEpoch:   proof.EpochNumber,
            CurrentEpoch: currentEpoch,
            WindowSize:   ParentProofEpochWindow,
            Reason:       fmt.Sprintf("proof too old (min valid: epoch %d)", minValidEpoch),
        }
    }

    return nil
}

// GetValidEpochWindow returns the range of valid epochs for parent proofs
func GetValidEpochWindow(currentEpoch uint64) (minEpoch, maxEpoch uint64) {
    maxEpoch = currentEpoch
    if currentEpoch >= uint64(ParentProofEpochWindow) {
        minEpoch = currentEpoch - uint64(ParentProofEpochWindow)
    } else {
        minEpoch = 0
    }
    return minEpoch, maxEpoch
}
```

#### Timing Diagram

```
                    PARENT PROOF VALIDITY WINDOW

    Epoch Timeline:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │ E-5 │ E-4 │ E-3 │ E-2 │ E-1 │ E-0 │ E+1 │
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    │           │           │
                    │ EXPIRED   │  VALID    │ FUTURE
                    │ (pruned)  │  WINDOW   │ (reject)
                    │           │           │

    Given: Current epoch = E-0 (epoch N)
           ParentProofEpochWindow = 2

    Valid parent proof epochs: [E-2, E-1, E-0]
    - E-2: Valid (oldest allowed)
    - E-1: Valid
    - E-0: Valid (current, if finalized)

    Invalid:
    - E-3 and older: EXPIRED (proofs no longer accepted)
    - E+1 and newer: FUTURE (epochs don't exist yet)

    Transition at epoch boundary:

    When current epoch advances N → N+1:
    - E-3 (epoch N-3) → Now expired, proofs invalid
    - E-2 (epoch N-2) → Still valid (now oldest)
    - E-1 (epoch N-1) → Still valid
    - E-0 (epoch N)   → Still valid
    - E+1 (epoch N+1) → Now current (valid when finalized)
```

#### Edge Cases

| Scenario | Handling |
|----------|----------|
| **Network start (epoch 0-2)** | Accept proofs from all existing epochs |
| **Parent in current unfnalized epoch** | Reject - parent must be finalized |
| **Epoch boundary during TX creation** | Re-fetch proof if epoch changes |
| **Proof expires during TX propagation** | Receiver rejects, sender must retry |
| **Long partition (miss epochs)** | Node must sync epochs before validating |

#### Proof Refresh Protocol

```go
// ParentProofRefresher handles proof updates for long-running transactions
type ParentProofRefresher struct {
    proofGenerator *ParentProofGenerator
    epochWatcher   *EpochWatcher
}

// RefreshIfNeeded checks if proofs need updating and regenerates them
func (ppr *ParentProofRefresher) RefreshIfNeeded(
    tx *TransactionWithProofs,
    currentEpoch uint64,
) (*TransactionWithProofs, error) {
    needsRefresh := false

    for _, proof := range tx.ParentProofs {
        minValidEpoch, _ := GetValidEpochWindow(currentEpoch)

        // Check if proof is about to expire (within grace period)
        if proof.EpochNumber == minValidEpoch {
            // Proof is at the edge of validity
            needsRefresh = true
            break
        }
    }

    if !needsRefresh {
        return tx, nil
    }

    // Regenerate all parent proofs with current epoch data
    newProofs := make([]ParentProof, len(tx.Parents))
    for i, parentID := range tx.Parents {
        proof, err := ppr.proofGenerator.GenerateParentProof(parentID)
        if err != nil {
            return nil, fmt.Errorf("failed to refresh proof for parent %d: %w", i, err)
        }
        newProofs[i] = *proof
    }

    // Create new transaction with fresh proofs
    refreshedTx := *tx
    refreshedTx.ParentProofs = newProofs

    // Re-sign with TPM (proofs changed)
    if err := ppr.resignTransaction(&refreshedTx); err != nil {
        return nil, fmt.Errorf("failed to re-sign transaction: %w", err)
    }

    return &refreshedTx, nil
}
```

### Parent Proof Generation

```go
// ParentProofGenerator creates proofs for parent transactions
type ParentProofGenerator struct {
    epochStore   EpochStore
    merkleStore  MerkleStore
}

// GenerateParentProof creates a proof that parentTxID exists in a finalized epoch
func (ppg *ParentProofGenerator) GenerateParentProof(parentTxID TxID) (*ParentProof, error) {
    // Step 1: Find which epoch contains the parent transaction
    epochNum, err := ppg.findEpochContainingTx(parentTxID)
    if err != nil {
        return nil, ErrParentNotInFinalizedEpoch{TxID: parentTxID}
    }

    // Step 2: Get the epoch data
    epoch, err := ppg.epochStore.GetEpoch(epochNum)
    if err != nil {
        return nil, fmt.Errorf("epoch not found: %w", err)
    }

    // Step 3: Verify epoch is finalized (has BFT signatures)
    if len(epoch.Signatures) < (FinalityCommitteeSize*2/3)+1 {
        return nil, ErrEpochNotFinalized{EpochNumber: epochNum}
    }

    // Step 4: Get Merkle proof from epoch's transaction tree
    merkleTree, err := ppg.merkleStore.GetEpochMerkleTree(epochNum)
    if err != nil {
        return nil, fmt.Errorf("merkle tree not found: %w", err)
    }

    proofPath, proofIndex, err := merkleTree.GenerateProof(parentTxID[:])
    if err != nil {
        return nil, fmt.Errorf("failed to generate merkle proof: %w", err)
    }

    // Step 5: Build parent proof
    proof := &ParentProof{
        ParentTxID:     parentTxID,
        EpochNumber:    epochNum,
        MerkleProof:    proofPath,
        ProofIndex:     proofIndex,
        EpochRoot:      epoch.TransactionRoot,
        EpochSignature: epoch.Signatures[0], // Include one committee signature
    }

    return proof, nil
}

// findEpochContainingTx searches for the epoch containing a transaction
func (ppg *ParentProofGenerator) findEpochContainingTx(txID TxID) (uint64, error) {
    // Check transaction-to-epoch index first (fast path)
    if epochNum, ok := ppg.merkleStore.GetTxEpochMapping(txID); ok {
        return epochNum, nil
    }

    // Slow path: scan recent epochs
    currentEpoch := ppg.epochStore.GetCurrentEpochNumber()
    for e := currentEpoch; e > 0 && e > currentEpoch-MaxEpochsRetained; e-- {
        if ppg.epochContainsTx(e, txID) {
            return e, nil
        }
    }

    return 0, ErrTransactionNotFound{TxID: txID}
}
```

### Parent Proof Verification Protocol

```go
// ParentProofVerifier validates parent proofs in transactions
type ParentProofVerifier struct {
    epochStore    EpochStore
    committeeStore CommitteeStore
}

// VerifyParentProofs validates all parent proofs in a transaction
func (ppv *ParentProofVerifier) VerifyParentProofs(tx *TransactionWithProofs) error {
    // Rule 1: Must have same number of parents and proofs
    if len(tx.Parents) != len(tx.ParentProofs) {
        return ErrParentProofCountMismatch{
            Parents: len(tx.Parents),
            Proofs:  len(tx.ParentProofs),
        }
    }

    // Rule 2: Must have 2-3 parents
    if len(tx.Parents) < 2 || len(tx.Parents) > 3 {
        return ErrInvalidParentCount{Count: len(tx.Parents)}
    }

    // Rule 3: Parents must be unique
    parentSet := make(map[TxID]bool)
    for _, parentID := range tx.Parents {
        if parentSet[parentID] {
            return ErrDuplicateParent{TxID: parentID}
        }
        parentSet[parentID] = true
    }

    // Rule 4: Cannot reference self
    for _, parentID := range tx.Parents {
        if parentID == tx.ID {
            return ErrSelfReferentialParent{}
        }
    }

    // Rule 5: Verify each parent proof
    for i, parentID := range tx.Parents {
        proof := tx.ParentProofs[i]

        if err := ppv.verifyIndividualProof(parentID, &proof); err != nil {
            return fmt.Errorf("parent %d proof invalid: %w", i, err)
        }
    }

    // Rule 6: Parents must be from recent epochs (within retention window)
    currentEpoch := ppv.epochStore.GetCurrentEpochNumber()
    for i, proof := range tx.ParentProofs {
        if proof.EpochNumber < currentEpoch-MaxEpochsRetained {
            return ErrParentTooOld{
                ParentTxID: tx.Parents[i],
                Epoch:      proof.EpochNumber,
                MinEpoch:   currentEpoch - MaxEpochsRetained,
            }
        }
    }

    return nil
}

// verifyIndividualProof validates a single parent proof
func (ppv *ParentProofVerifier) verifyIndividualProof(parentID TxID, proof *ParentProof) error {
    // Check 1: Proof claims correct parent
    if proof.ParentTxID != parentID {
        return ErrParentIDMismatch{Expected: parentID, Got: proof.ParentTxID}
    }

    // Check 2: Epoch exists and is finalized
    epoch, err := ppv.epochStore.GetEpoch(proof.EpochNumber)
    if err != nil {
        return ErrEpochNotFound{EpochNumber: proof.EpochNumber}
    }

    // Check 3: Epoch root matches
    if epoch.TransactionRoot != proof.EpochRoot {
        return ErrEpochRootMismatch{
            Expected: epoch.TransactionRoot,
            Got:      proof.EpochRoot,
        }
    }

    // Check 4: Verify BFT signature on epoch
    if err := ppv.verifyEpochSignature(epoch, &proof.EpochSignature); err != nil {
        return fmt.Errorf("invalid epoch signature: %w", err)
    }

    // Check 5: Verify Merkle proof
    if err := ppv.verifyMerkleProof(parentID, proof); err != nil {
        return fmt.Errorf("invalid merkle proof: %w", err)
    }

    return nil
}

// verifyMerkleProof validates the Merkle inclusion proof
func (ppv *ParentProofVerifier) verifyMerkleProof(parentID TxID, proof *ParentProof) error {
    // Start with the leaf hash (parent transaction ID)
    currentHash := parentID

    // Walk up the proof path
    for _, node := range proof.MerkleProof {
        var combined []byte
        if node.Position == MerkleLeft {
            // Sibling is on the left
            combined = append(node.Hash[:], currentHash[:]...)
        } else {
            // Sibling is on the right
            combined = append(currentHash[:], node.Hash[:]...)
        }
        currentHash = sha256.Sum256(combined)
    }

    // Final hash should equal the epoch root
    if currentHash != proof.EpochRoot {
        return ErrMerkleProofInvalid{
            ComputedRoot: currentHash,
            ExpectedRoot: proof.EpochRoot,
        }
    }

    return nil
}

// verifyEpochSignature validates a BFT committee signature on epoch
func (ppv *ParentProofVerifier) verifyEpochSignature(epoch *Epoch, sig *CommitteeSignature) error {
    // Get committee for this epoch
    committee, err := ppv.committeeStore.GetCommitteeForEpoch(epoch.EpochNumber)
    if err != nil {
        return fmt.Errorf("committee not found: %w", err)
    }

    // Verify signer is committee member
    if !isCommitteeMember(sig.NodeID, committee) {
        return ErrSignerNotCommitteeMember{NodeID: sig.NodeID}
    }

    // Verify signature
    epochHash := epoch.Hash()
    if !VerifySignature(sig.NodeID, epochHash[:], sig.Signature) {
        return ErrInvalidSignature{NodeID: sig.NodeID}
    }

    // Verify TPM quote freshness (within epoch timeframe)
    if !VerifyTPMQuoteFreshness(sig.TPMQuote, epoch.EndTime, 1*time.Hour) {
        return ErrStaleTPMQuote{NodeID: sig.NodeID}
    }

    return nil
}
```

### Special Cases

```go
// SpecialCaseHandler manages edge cases in parent proof verification
type SpecialCaseHandler struct {
    verifier *ParentProofVerifier
    tipCache *DAGTipCache
}

// HandleCurrentEpochParent handles parents from unfinalized current epoch
func (sch *SpecialCaseHandler) HandleCurrentEpochParent(parentID TxID) error {
    // Parents from current epoch cannot have Merkle proofs yet
    // They must be confirmed through tip cache verification

    // Check if parent is a confirmed DAG tip
    if !sch.tipCache.IsTip(parentID) {
        // Check if parent has sufficient confirmations in current epoch
        confirmations := sch.tipCache.GetConfirmationCount(parentID)
        if confirmations < MinParentConfirmations {
            return ErrInsufficientParentConfirmations{
                TxID:         parentID,
                Confirmations: confirmations,
                Required:     MinParentConfirmations,
            }
        }
    }

    return nil
}

// DetectCircularReferences prevents circular DAG references
func (sch *SpecialCaseHandler) DetectCircularReferences(tx *TransactionWithProofs, depth int) error {
    if depth > MaxDAGDepthCheck {
        return nil // Stop checking at max depth
    }

    for _, parentID := range tx.Parents {
        // Get parent transaction
        parentTx, err := sch.getTransaction(parentID)
        if err != nil {
            continue // Parent in old epoch, no need to check
        }

        // Check if any of parent's ancestors reference our tx
        for _, grandparentID := range parentTx.Parents {
            if grandparentID == tx.ID {
                return ErrCircularDAGReference{
                    TxID:       tx.ID,
                    ParentID:   parentID,
                    AncestorID: grandparentID,
                }
            }
        }

        // Recursively check grandparents
        if err := sch.DetectCircularReferences(parentTx, depth+1); err != nil {
            return err
        }
    }

    return nil
}
```

**Parent Proof Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Existence proof | Parent exists in DAG | Merkle inclusion proof |
| Epoch binding | Parent is finalized | BFT signature on epoch |
| Freshness | Parent is recent | Epoch retention window |
| Uniqueness | No duplicate parents | Parent set validation |
| Acyclicity | No circular references | Depth-limited DAG traversal |

**Parent Proof Size Analysis**:

| Component | Size | Notes |
|-----------|------|-------|
| ParentTxID | 32 bytes | SHA256 hash |
| EpochNumber | 8 bytes | uint64 |
| MerkleProof | ~640 bytes | ~20 nodes * 32 bytes (for 1M tx/epoch) |
| ProofIndex | 8 bytes | uint64 |
| EpochRoot | 32 bytes | SHA256 hash |
| EpochSignature | ~200 bytes | NodeID + signature + TPM quote |
| **Total per parent** | **~920 bytes** | |
| **Total for 2 parents** | **~1.84 KB** | Typical transaction |
| **Total for 3 parents** | **~2.76 KB** | Maximum parents |

### DAG Ordering Specifications (FINAL DESIGN)

The DAG ordering rules ensure deterministic transaction processing and prevent conflicts.

#### Valid Tip Definition

```go
// Valid DAG Tip Criteria
//
// A transaction is a valid tip if:
// - It is confirmed (has sufficient confirmations)
// - It is from the last 100 epochs (not too old)
// - It is not orphaned (has path to genesis)

const (
    MaxTipAgeEpochs    = 100   // Tips older than this are invalid
    MinTipConfirmations = 3     // Minimum confirmations for tip status
)

func (dtc *DAGTipCache) IsValidTip(txID TxID) bool {
    tx := dtc.getTransaction(txID)
    if tx == nil {
        return false
    }

    // Check epoch age
    currentEpoch := dtc.epochStore.GetCurrentEpochNumber()
    if currentEpoch-tx.EpochNumber > MaxTipAgeEpochs {
        return false
    }

    // Check confirmations
    if dtc.GetConfirmationCount(txID) < MinTipConfirmations {
        return false
    }

    // Check not orphaned
    if dtc.isOrphaned(txID) {
        return false
    }

    return true
}
```

#### Maximum Parent Age

```go
// Maximum Parent Age
//
// Parents must be from within the last 1000 epochs (approximately 1 hour
// at 10 minutes per epoch). This prevents unbounded DAG growth.

const MaxParentAgeEpochs = 1000  // Approximately 1 hour

func (v *Validator) ValidateParentAge(tx *Transaction) error {
    currentEpoch := v.epochStore.GetCurrentEpochNumber()

    for i, proof := range tx.ParentProofs {
        if currentEpoch-proof.EpochNumber > MaxParentAgeEpochs {
            return ErrParentTooOld{
                ParentIndex:   i,
                ParentEpoch:   proof.EpochNumber,
                CurrentEpoch:  currentEpoch,
                MaxAge:        MaxParentAgeEpochs,
            }
        }
    }

    return nil
}
```

#### Orphan Handling

```go
// Orphan Transaction Handling
//
// Transactions are queued for 60 seconds awaiting parents.
// If parents don't arrive, the transaction is rejected.

const (
    OrphanQueueDuration = 60 * time.Second
    MaxOrphanQueueSize  = 10000
)

func (oq *OrphanQueue) HandleOrphanTransaction(tx *Transaction) error {
    // Check if parents exist
    missingParents := oq.findMissingParents(tx)

    if len(missingParents) == 0 {
        // All parents present - process immediately
        return oq.processTransaction(tx)
    }

    // Queue for 60 seconds
    entry := &OrphanEntry{
        Transaction:    tx,
        MissingParents: missingParents,
        QueuedAt:       time.Now(),
        ExpiresAt:      time.Now().Add(OrphanQueueDuration),
    }

    if err := oq.addOrphan(entry); err != nil {
        return err
    }

    // Start expiry timer
    time.AfterFunc(OrphanQueueDuration, func() {
        oq.expireOrphan(tx.ID)
    })

    return nil
}

func (oq *OrphanQueue) expireOrphan(txID TxID) {
    oq.mu.Lock()
    defer oq.mu.Unlock()

    entry, exists := oq.orphans[txID]
    if !exists {
        return
    }

    // Check if still missing parents
    if len(oq.findMissingParents(entry.Transaction)) > 0 {
        oq.logger.Warn("orphan transaction expired",
            "tx_id", txID,
            "missing_parents", entry.MissingParents,
            "queued_duration", time.Since(entry.QueuedAt))

        delete(oq.orphans, txID)
        oq.rejectTransaction(txID, "orphan timeout - parents not found")
    }
}
```

#### Same-Batch Conflict Resolution

```go
// Same-Batch Conflict Resolution
//
// When multiple transactions in the same batch conflict (e.g., spending
// the same UTXO), deterministic ordering by transaction hash is used.
// Lower transaction hash wins.

func (bc *BatchCoordinator) ResolveSameBatchConflicts(batch []*Transaction) []*Transaction {
    // Group transactions by conflicting UTXOs
    conflicts := bc.findConflicts(batch)

    resolvedBatch := make([]*Transaction, 0, len(batch))
    excluded := make(map[TxID]bool)

    for utxo, txs := range conflicts {
        if len(txs) == 1 {
            continue  // No conflict
        }

        // Sort by transaction hash (lexicographic)
        sort.Slice(txs, func(i, j int) bool {
            return bytes.Compare(txs[i].ID[:], txs[j].ID[:]) < 0
        })

        // First transaction wins
        winner := txs[0]

        // Exclude all others
        for _, tx := range txs[1:] {
            excluded[tx.ID] = true
            bc.logger.Info("transaction excluded due to UTXO conflict",
                "excluded_tx", tx.ID,
                "winner_tx", winner.ID,
                "conflicting_utxo", utxo)
        }
    }

    // Build final batch without excluded transactions
    for _, tx := range batch {
        if !excluded[tx.ID] {
            resolvedBatch = append(resolvedBatch, tx)
        }
    }

    return resolvedBatch
}
```

#### Tie-Breaker for Same-Sequence

```go
// Same-Sequence Tie-Breaker
//
// If two transactions have the same sequence number (rare race condition),
// the one with the lower transaction hash wins.

func (sv *SequenceValidator) ResolveSequenceTie(tx1, tx2 *Transaction) *Transaction {
    if tx1.Sequence != tx2.Sequence {
        panic("sequences must be equal for tie-breaking")
    }

    // Lexicographic comparison of transaction hashes
    if bytes.Compare(tx1.ID[:], tx2.ID[:]) < 0 {
        sv.logger.Info("sequence tie resolved",
            "winner", tx1.ID,
            "loser", tx2.ID,
            "sequence", tx1.Sequence)
        return tx1
    }

    sv.logger.Info("sequence tie resolved",
        "winner", tx2.ID,
        "loser", tx1.ID,
        "sequence", tx2.Sequence)
    return tx2
}
```

### TPM Quote Validation (FINAL DESIGN)

TPM quotes must be validated for freshness and reuse to prevent replay attacks.

#### Quote Timestamp Validation

```go
// TPM Quote Timestamp Validation
//
// Quote timestamp must be within 5 seconds of transaction timestamp
// to prevent stale quote reuse.

const MaxQuoteTimestampSkew = 5 * time.Second

func ValidateTPMQuoteTimestamp(quote []byte, txTimestamp int64) error {
    // Extract timestamp from TPM quote
    quoteTimestamp, err := ExtractTPMQuoteTimestamp(quote)
    if err != nil {
        return fmt.Errorf("failed to extract quote timestamp: %w", err)
    }

    // Compare with transaction timestamp
    skew := abs(time.Unix(txTimestamp, 0).Sub(time.Unix(quoteTimestamp, 0)))

    if skew > MaxQuoteTimestampSkew {
        return ErrQuoteTimestampSkew{
            QuoteTimestamp: time.Unix(quoteTimestamp, 0),
            TxTimestamp:    time.Unix(txTimestamp, 0),
            Skew:           skew,
            MaxAllowed:     MaxQuoteTimestampSkew,
        }
    }

    return nil
}
```

#### Quote Reuse Prevention

```go
// Quote Reuse Prevention
//
// Same quote valid for 60 seconds, maximum 100 transactions.
// This prevents quote grinding attacks while allowing legitimate reuse.

const (
    QuoteReuseWindow        = 60 * time.Second
    MaxTransactionsPerQuote = 100
)

type QuoteCache struct {
    quotes map[[32]byte]*QuoteCacheEntry
    mu     sync.RWMutex
}

type QuoteCacheEntry struct {
    QuoteHash      [32]byte
    FirstSeen      time.Time
    LastSeen       time.Time
    UsageCount     int
    TransactionIDs []TxID
}

func (qc *QuoteCache) ValidateQuoteReuse(quote []byte, txID TxID) error {
    quoteHash := sha256.Sum256(quote)

    qc.mu.Lock()
    defer qc.mu.Unlock()

    entry, exists := qc.quotes[quoteHash]
    if !exists {
        // First use - create entry
        qc.quotes[quoteHash] = &QuoteCacheEntry{
            QuoteHash:      quoteHash,
            FirstSeen:      time.Now(),
            LastSeen:       time.Now(),
            UsageCount:     1,
            TransactionIDs: []TxID{txID},
        }
        return nil
    }

    // Check reuse window
    if time.Since(entry.FirstSeen) > QuoteReuseWindow {
        return ErrQuoteReuseWindowExpired{
            QuoteHash:  quoteHash,
            FirstSeen:  entry.FirstSeen,
            WindowSize: QuoteReuseWindow,
        }
    }

    // Check usage count
    if entry.UsageCount >= MaxTransactionsPerQuote {
        return ErrQuoteReuseLimit{
            QuoteHash:  quoteHash,
            UsageCount: entry.UsageCount,
            MaxAllowed: MaxTransactionsPerQuote,
        }
    }

    // Update entry
    entry.LastSeen = time.Now()
    entry.UsageCount++
    entry.TransactionIDs = append(entry.TransactionIDs, txID)

    return nil
}

func (qc *QuoteCache) CleanupExpiredQuotes() {
    qc.mu.Lock()
    defer qc.mu.Unlock()

    now := time.Now()
    for hash, entry := range qc.quotes {
        if now.Sub(entry.LastSeen) > QuoteReuseWindow {
            delete(qc.quotes, hash)
        }
    }
}
```

#### Per-Node Quote Cache

```go
// Per-Node Quote Cache
//
// Each node maintains a sliding 60-second window cache of TPM quotes
// to track reuse and prevent abuse.

type NodeQuoteCache struct {
    nodeID     NodeID
    cache      *QuoteCache
    cleanupTicker *time.Ticker
}

func NewNodeQuoteCache(nodeID NodeID) *NodeQuoteCache {
    nqc := &NodeQuoteCache{
        nodeID: nodeID,
        cache:  &QuoteCache{
            quotes: make(map[[32]byte]*QuoteCacheEntry),
        },
    }

    // Start cleanup ticker
    nqc.cleanupTicker = time.NewTicker(QuoteReuseWindow)
    go func() {
        for range nqc.cleanupTicker.C {
            nqc.cache.CleanupExpiredQuotes()
        }
    }()

    return nqc
}
```

## Cross-Shard Protocol (CANONICAL)

This section is the authoritative specification for cross-shard transactions using the Three-Phase Commit (3PC) protocol.

### Design Goals

- **Atomicity**: Complete fully or rollback completely across all shards
- **Non-blocking**: Prevent indefinite blocking through adaptive timeouts
- **Fairness**: Dynamic fee structure based on network load

### Coordinator

The coordinator is the **Global Coordinator Committee** (21-node PBFT):

- Fault tolerant (f=7, n=21, requires 7-of-21 threshold)
- Consistent transaction ordering
- High availability
- See `06-consensus-coordination.md` for committee election

### Three-Phase Commit Protocol

```
[Idle]
  |
[CanCommit] --(any NO/timeout)--> [Abort] --> [Idle]
  | (all YES)
[PreCommit] --(timeout/failure)--> [Recovery]
  | (all ACK)
[DoCommit]
  |
[Committed] --> [Idle]
```

#### Phase 1: CanCommit

**Timeout**: T1 = 2 seconds

**Coordinator**:
1. Receive cross-shard transaction request
2. Assign unique transaction ID (TXID)
3. Send CanCommit to source and destination shards
4. Start timeout timer

**Source Shard**:
1. **CRITICAL: Verify shard authority** - Confirm this shard IS the authoritative shard for sender's wallet (see GetAuthoritativeShard). REJECT if not authoritative.
2. Verify UTXO existence and ownership
3. Acquire UTXO locks (lexicographic ordering) **with explicit TTL**
4. Verify sufficient balance
5. Check no conflicting locks
6. Respond: CanCommit-YES or NO

**Shard Authority Verification (SECURITY FIX)**:
```go
func (s *Shard) HandleCanCommit(req *CanCommitRequest) (*CanCommitResponse, error) {
    // CRITICAL: Verify we are authoritative for this wallet
    authShard := GetAuthoritativeShard(req.SenderWallet)
    if authShard != s.shardID {
        return &CanCommitResponse{
            Vote:   VoteNo,
            Reason: ErrNotAuthoritativeShard,
            // Include proof so coordinator can't retry maliciously
            AuthoritativeShardProof: s.getShardAssignmentProof(req.SenderWallet),
        }, nil
    }
    // ... proceed with validation
}
```

This prevents a malicious coordinator from:
- Routing transactions to non-authoritative shards for double-spend
- Replaying transactions across shards by claiming different authorities

**Destination Shard**:
1. **CRITICAL: Verify shard authority** - Confirm this shard IS authoritative for recipient's wallet. REJECT if not authoritative.
2. Verify recipient account exists (or can be created)
3. Check account not frozen
4. Validate amount > 0 and within limits
5. Respond: CanCommit-YES or NO

**Outcomes**:
- All YES: Proceed to Phase 2
- Any NO or timeout: Abort

#### Phase 2: PreCommit

**Timeout**: T2 = 3 seconds

**Coordinator**:
- If all CanCommit = YES: Send PreCommit to all shards
- Otherwise: Send Abort

**Shard Actions**:
1. Persist transaction in PreCommit state to durable storage
2. Respond: PreCommit-ACK

**Critical Property**: Once a shard enters PreCommit, it can complete the transaction independently if coordinator fails.

**Outcomes**:
- All ACK: Proceed to Phase 3
- Failure: Coordinator decides abort or retry (up to 3 times)

#### Phase 3: DoCommit

**Timeout**: T3 = 5 seconds

**Source Shard**:
1. Debit funds from locked UTXOs
2. Mark UTXOs as spent
3. Release UTXO locks
4. Persist new state
5. Respond: Commit-DONE

**Destination Shard**:
1. Credit funds to recipient
2. Create new UTXO(s)
3. Persist new state
4. Respond: Commit-DONE

### 3PC Timeout Actions (CANONICAL)

Each 3PC phase has specific timeout actions that participants MUST take when timeouts occur. These ensure the protocol makes progress even when coordinators or participants fail.

**CANONICAL TIMEOUT VALUES**:

| Phase | Timeout | Total Elapsed |
|-------|---------|---------------|
| CanCommit (T1) | 2 seconds | 0-2s |
| PreCommit (T2) | 3 seconds | 2-5s |
| DoCommit (T3) | 5 seconds | 5-10s |
| **Total 3PC** | **10 seconds** | - |

#### CanCommit Timeout Actions (T1 = 2 seconds)

When CanCommit phase times out without receiving all votes:

```go
// CanCommitTimeoutAction specifies actions when T1 expires
type CanCommitTimeoutAction struct {
    Timeout time.Duration  // 2 seconds
}

func (p *Participant) HandleCanCommitTimeout(txID TxID) {
    // Action 1: Release all local locks acquired for this transaction
    p.lockManager.ReleaseTransactionLocks(txID)

    // Action 2: Broadcast ABORT to all known participants
    abort := &AbortMessage{
        TransactionID: txID,
        Phase:         PhaseCanCommit,
        Reason:        "CanCommit timeout - T1 expired",
        AbortedBy:     p.shardID,
        Timestamp:     time.Now(),
        TPMQuote:      GenerateTPMQuote(),
    }
    p.broadcastToParticipants(txID, abort)

    // Action 3: Log abort for audit
    p.logPhaseTimeout(txID, PhaseCanCommit, abort)

    // Action 4: Notify coordinator of timeout (best effort)
    go p.notifyCoordinatorTimeout(txID, PhaseCanCommit)
}
```

**CanCommit Timeout Properties**:
- **Safe to abort**: No durable state has been written yet
- **Lock release**: All locally acquired locks are released immediately
- **Broadcast abort**: Ensures all participants know to abort
- **No rollback needed**: Transaction never progressed past voting

#### CanCommit Coordinator Crash Recovery (CANONICAL)

**Crash Scenario**: Coordinator crashes during CanCommit phase (Phase 1) before collecting all votes or sending PreCommit.

This is the simplest crash recovery scenario because no durable state has been written and no participant has committed to the transaction.

```go
// CanCommit Crash Recovery Protocol
//
// When coordinator crashes during CanCommit:
// 1. Participants detect coordinator timeout (2 second CanCommit timeout)
// 2. Participants release locks and abort locally
// 3. New coordinator (if elected) inherits ABORT decision
// 4. No recovery needed - transaction is safely discarded

type CanCommitCrashRecovery struct {
    TxID              TxID
    CrashDetectedAt   time.Time
    ParticipantStates map[uint16]CanCommitParticipantState  // Shard ID -> State
    RecoveryDecision  RecoveryDecision
}

type CanCommitParticipantState struct {
    ShardID           uint16
    VoteSent          bool         // Did participant send YES/NO vote?
    Vote              Vote         // YES/NO/UNKNOWN
    LocksAcquired     bool         // Were locks acquired?
    LocksReleased     bool         // Were locks released after timeout?
    TimeoutOccurred   bool         // Did participant timeout waiting for PreCommit?
    AbortBroadcasted  bool         // Did participant broadcast abort?
    LastStateChange   time.Time
}

type RecoveryDecision uint8

const (
    RecoveryAbort    RecoveryDecision = 1  // Abort transaction (default)
    RecoveryRetry    RecoveryDecision = 2  // Retry from CanCommit (rare)
    RecoveryUnknown  RecoveryDecision = 3  // Cannot determine state
)
```

**New Coordinator Recovery Protocol**:

When a new coordinator is elected after original coordinator crashes during CanCommit:

```go
func (nc *NewCoordinator) RecoverCanCommitTransaction(
    ctx context.Context,
    txID TxID,
) (*CanCommitCrashRecovery, error) {
    nc.logger.Info("recovering transaction from CanCommit crash",
        "tx_id", txID)

    // Step 1: Query all participants for their state
    participants := nc.getTransactionParticipants(txID)
    states := make(map[uint16]CanCommitParticipantState)

    for _, participantID := range participants {
        state, err := nc.queryCanCommitState(participantID, txID)
        if err != nil {
            nc.logger.Warn("failed to query participant CanCommit state",
                "participant", participantID,
                "error", err)
            // Missing response = assume participant timed out and aborted
            states[participantID] = CanCommitParticipantState{
                ShardID:         participantID,
                TimeoutOccurred: true,
                LocksReleased:   true,
                AbortBroadcasted: true,
            }
            continue
        }
        states[participantID] = *state
    }

    // Step 2: Analyze participant states
    recovery := &CanCommitCrashRecovery{
        TxID:              txID,
        CrashDetectedAt:   time.Now(),
        ParticipantStates: states,
    }

    allVotedYes := true
    anyTimedOut := false
    anyAborted := false

    for _, state := range states {
        if state.Vote != VoteYes {
            allVotedYes = false
        }
        if state.TimeoutOccurred {
            anyTimedOut = true
        }
        if state.AbortBroadcasted {
            anyAborted = true
        }
    }

    // Step 3: Make recovery decision
    // CANONICAL RULE: Default to ABORT for safety
    if anyTimedOut || anyAborted || !allVotedYes {
        recovery.RecoveryDecision = RecoveryAbort
        nc.logger.Info("recovery decision: ABORT",
            "tx_id", txID,
            "reason", "participants timed out or did not all vote YES")
    } else {
        // All voted YES and no timeouts - could retry
        // But for simplicity and safety, still abort
        recovery.RecoveryDecision = RecoveryAbort
        nc.logger.Info("recovery decision: ABORT (conservative)",
            "tx_id", txID,
            "reason", "coordinator crash during CanCommit - safer to abort and let client retry")
    }

    // Step 4: Execute recovery decision
    if err := nc.executeCanCommitRecovery(ctx, recovery); err != nil {
        return nil, fmt.Errorf("failed to execute recovery: %w", err)
    }

    return recovery, nil
}

func (nc *NewCoordinator) executeCanCommitRecovery(
    ctx context.Context,
    recovery *CanCommitCrashRecovery,
) error {
    switch recovery.RecoveryDecision {
    case RecoveryAbort:
        // Send abort to all participants (idempotent - they may have already aborted)
        abort := &AbortMessage{
            TransactionID: recovery.TxID,
            Phase:         PhaseCanCommit,
            Reason:        "coordinator crash during CanCommit - recovery abort",
            AbortedBy:     nc.nodeID,
            Timestamp:     time.Now(),
            Evidence:      nc.buildAbortEvidence(recovery),
        }

        for shardID := range recovery.ParticipantStates {
            if err := nc.sendAbort(ctx, shardID, abort); err != nil {
                nc.logger.Warn("failed to send abort to participant",
                    "shard_id", shardID,
                    "error", err)
                // Continue - participant likely already aborted
            }
        }

        nc.logger.Info("CanCommit recovery abort complete",
            "tx_id", recovery.TxID)
        return nil

    case RecoveryRetry:
        // Not implemented - requires client to resubmit transaction
        return ErrCanCommitRecoveryRetryNotSupported

    default:
        return ErrUnknownRecoveryDecision{Decision: recovery.RecoveryDecision}
    }
}
```

**CanCommit Crash Recovery Rules**:

| Participant State | Recovery Decision | Rationale |
|-------------------|-------------------|-----------|
| All voted YES, no timeouts | ABORT | Conservative - coordinator crashed, safer to retry |
| Any voted NO | ABORT | Transaction cannot proceed |
| Any timed out | ABORT | Participants already released locks |
| Any aborted | ABORT | Abort already propagated |
| Missing responses | ABORT | Assume participants timed out |

**State Inheritance by New Coordinator**:

The new coordinator queries participants for:

1. **Vote Status**: Did participant send YES/NO vote to original coordinator?
2. **Lock Status**: Are locks still held or were they released?
3. **Timeout Status**: Did participant timeout waiting for PreCommit?
4. **Abort Status**: Did participant already broadcast abort?

Based on these states, the new coordinator makes an ABORT decision in all cases during CanCommit recovery.

**Commit vs Abort Decision Rules**:

```go
// CANONICAL DECISION RULES for CanCommit Crash Recovery
//
// Rule 1: If any participant timed out → ABORT
// Rule 2: If any participant voted NO → ABORT
// Rule 3: If any participant already aborted → ABORT
// Rule 4: If all voted YES but coordinator crashed → ABORT (conservative)
//
// RATIONALE: CanCommit phase has no durable state, so aborting is safe
// and allows client to retry. Attempting to recover forward risks
// inconsistency if participants have already released locks.

func (nc *NewCoordinator) canCommitDecisionRules(
    states map[uint16]CanCommitParticipantState,
) RecoveryDecision {
    // Rule 1: Any timeout → ABORT
    for _, state := range states {
        if state.TimeoutOccurred {
            return RecoveryAbort
        }
    }

    // Rule 2: Any NO vote → ABORT
    for _, state := range states {
        if state.Vote == VoteNo {
            return RecoveryAbort
        }
    }

    // Rule 3: Any abort → ABORT
    for _, state := range states {
        if state.AbortBroadcasted {
            return RecoveryAbort
        }
    }

    // Rule 4: All YES but coordinator crashed → ABORT (conservative)
    // Even if all voted YES, coordinator crash during CanCommit means
    // participants likely timed out and released locks. Safer to abort
    // and let client retry entire transaction.
    return RecoveryAbort
}
```

**Timeline Example - CanCommit Crash Recovery**:

```
Time   Event                                    Coordinator         Participants
──────────────────────────────────────────────────────────────────────────────────
0.0s   CanCommit sent to all shards            Sent                Received
0.5s   Shard 1 votes YES                       -                   Voted YES
0.6s   Shard 2 votes YES                       -                   Voted YES
0.7s   Coordinator crashes                     CRASHED             Waiting
2.0s   CanCommit timeout (T1)                  -                   Timeout detected
2.1s   Participants release locks              -                   Locks released
2.2s   Participants broadcast ABORT            -                   Abort sent
5.0s   New coordinator elected                 Elected             -
5.1s   New coordinator queries shard states    Querying            Responding
5.2s   All shards report: voted YES, timed out -                   States sent
5.3s   New coordinator decides: ABORT          Decision=ABORT      -
5.4s   New coordinator sends ABORT (idempotent) ABORT sent         ABORT received
5.5s   Transaction fully aborted               Complete            Complete
```

**CanCommit Crash Recovery Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Always safe to abort | No durable state written | CanCommit is voting phase only |
| Locks automatically released | Timeout triggers lock release | T1 timeout handler |
| Client can safely retry | Transaction never committed | Abort is final state |
| Idempotent abort | Multiple aborts are safe | Participants ignore duplicate aborts |
| No compensation needed | No funds moved | CanCommit precedes state changes |

#### PreCommit Timeout Actions (T2 = 3 seconds)

When PreCommit phase times out, participants enter recovery mode:

```go
// PreCommitTimeoutAction specifies actions when T2 expires
type PreCommitTimeoutAction struct {
    Timeout                time.Duration  // 3 seconds
    CoordinatorElectionWait time.Duration  // 5 seconds
}

func (p *Participant) HandlePreCommitTimeout(txID TxID) {
    // Action 1: Query coordinator for status
    status, err := p.queryCoordinatorWithTimeout(txID, 2*time.Second)
    if err == nil && status.Phase == PhasePreCommit {
        // Coordinator alive and in PreCommit - wait for DoCommit
        return
    }

    // Action 2: Coordinator unreachable - wait for new coordinator election
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    newCoordinator, err := p.waitForCoordinatorElection(ctx, txID)
    if err == nil {
        // New coordinator elected - query for decision
        decision, err := p.queryNewCoordinator(newCoordinator, txID)
        if err == nil {
            p.executeDecision(txID, decision)
            return
        }
    }

    // Action 3: No coordinator available - participant-initiated abort with evidence
    evidence := &PreCommitTimeoutEvidence{
        TransactionID:      txID,
        ParticipantShard:   p.shardID,
        TimeoutAt:          time.Now(),
        CoordinatorQueries: p.getCoordinatorQueryLog(txID),
        ElectionAttempt:    true,
        TPMQuote:           GenerateTPMQuote(),
    }

    abort := &AbortWithEvidence{
        TransactionID: txID,
        Phase:         PhasePreCommit,
        Reason:        "PreCommit timeout - coordinator unavailable, election failed",
        Evidence:      evidence,
    }

    // Action 4: Check if this shard already PreCommitted
    if p.hasPreCommitRecord(txID) {
        // CRITICAL: Cannot unilaterally abort - must query other participants
        p.initiateRecoveryProtocol(txID, evidence)
        return
    }

    // Action 5: Broadcast abort with evidence
    p.broadcastAbortWithEvidence(txID, abort)
    p.lockManager.ReleaseTransactionLocks(txID)
}
```

**PreCommit Timeout Properties**:
- **Query coordinator first**: 2 second query before assuming failure
- **Wait for election**: 5 second wait for new coordinator
- **Evidence required**: All aborts must include timeout evidence
- **Recovery protocol**: If already PreCommitted, cannot abort unilaterally

#### DoCommit Timeout Actions (T3 = 5 seconds)

When DoCommit phase times out, the participant COMMITS ANYWAY because PreCommit has already been received:

```go
// DoCommitTimeoutAction specifies actions when T3 expires
type DoCommitTimeoutAction struct {
    Timeout time.Duration  // 5 seconds
}

func (p *Participant) HandleDoCommitTimeout(txID TxID) {
    // CRITICAL: If we received PreCommit, we MUST commit
    // This is the key safety property of 3PC

    // Action 1: Verify PreCommit was received
    preCommitRecord := p.getPreCommitRecord(txID)
    if preCommitRecord == nil {
        // No PreCommit received - should not be in this state
        p.logInvalidState(txID, "DoCommit timeout without PreCommit")
        p.lockManager.ReleaseTransactionLocks(txID)
        return
    }

    // Action 2: Commit the transaction (PreCommit guarantees safety)
    commitRecord := &LocalCommit{
        TransactionID:    txID,
        PreCommitEvidence: preCommitRecord,
        CommitReason:     "DoCommit timeout with PreCommit evidence",
        CommittedAt:      time.Now(),
        TPMQuote:         GenerateTPMQuote(),
    }

    // Action 3: Apply transaction to local state (idempotent)
    if err := p.applyTransaction(txID, commitRecord); err != nil {
        // Retry - commit is required
        p.scheduleRetry(txID, commitRecord)
        return
    }

    // Action 4: Release locks after commit
    p.lockManager.ReleaseTransactionLocks(txID)

    // Action 5: Log commit for audit
    p.logTimeoutCommit(txID, commitRecord)

    // Action 6: Notify coordinator of commit (idempotent replay)
    go p.notifyCoordinatorCommit(txID, commitRecord)
}
```

**DoCommit Timeout Properties**:
- **Commit anyway**: PreCommit guarantees all participants will commit
- **Idempotent replay**: Safe to replay commit if coordinator later asks
- **No rollback**: Once PreCommit received, rollback is not allowed
- **WAL protection**: Commit is logged before state changes

#### DoCommit Failure and Rollback Prohibition (CRITICAL)

**SECURITY INVARIANT**: Shards CANNOT unilaterally rollback after DoCommit phase begins.

Once a shard receives DoCommit, it MUST complete the commit operation even if other shards fail. This prevents atomicity violations where some shards commit and others abort, creating inconsistent state.

```go
// DoCommit Failure Scenarios and Recovery

// Scenario 1: Shard commits, then crashes before responding to coordinator
// Resolution: WAL ensures idempotent replay on recovery
//
// Scenario 2: Shard commits, coordinator crashes before receiving response
// Resolution: New coordinator queries shard state, discovers commit, propagates to other shards
//
// Scenario 3: One shard commits successfully, another shard fails DoCommit
// Resolution: COMPENSATION PROTOCOL (see below)

type DoCommitFailureType uint8

const (
    DoCommitSuccess           DoCommitFailureType = 0  // Normal completion
    DoCommitPartialCommit     DoCommitFailureType = 1  // Some shards committed
    DoCommitCoordinatorCrash  DoCommitFailureType = 2  // Coordinator crash
    DoCommitShardUnreachable  DoCommitFailureType = 3  // Shard network partition
)
```

**Orphaned Commit Compensation Protocol**:

When one shard successfully commits but another fails (network partition, crash, etc.), the system CANNOT rollback the committed shard. Instead, it uses a compensation protocol:

```go
// OrphanedCommitDetection monitors for partial commit scenarios
type OrphanedCommitDetection struct {
    TxID              TxID
    SourceCommitted   bool         // Source shard committed?
    DestCommitted     bool         // Destination shard committed?
    DetectedAt        time.Time    // When inconsistency detected
    CompensationState CompensationState
}

type CompensationState uint8

const (
    CompensationPending   CompensationState = 0  // Detected, not yet compensated
    CompensationInProgress CompensationState = 1  // Compensation transaction initiated
    CompensationComplete  CompensationState = 2  // Funds returned + penalty applied
)

// Compensation Protocol:
// 1. New coordinator detects partial commit (one shard committed, one didn't)
// 2. Coordinator re-initiates 3PC to the failed shard with PreCommit evidence
// 3. If failed shard cannot complete commit within 3 retry attempts:
//    a. Automatic revert transaction created
//    b. Revert debits committed shard, credits original sender
//    c. Penalty fee applied to coordinator bond for failed coordination
// 4. Both shards reach consistent state (either both committed or both reverted)

func (c *Coordinator) HandleOrphanedCommit(
    ctx context.Context,
    txID TxID,
    detection *OrphanedCommitDetection,
) error {
    c.logger.Error("orphaned commit detected",
        "tx_id", txID,
        "source_committed", detection.SourceCommitted,
        "dest_committed", detection.DestCommitted)

    // Step 1: Attempt to complete commit on failed shard
    // Use PreCommit evidence from successful shard as proof
    preCommitEvidence := c.getPreCommitEvidence(txID)

    retryAttempts := 3
    for i := 0; i < retryAttempts; i++ {
        err := c.retryDoCommitWithEvidence(ctx, txID, preCommitEvidence)
        if err == nil {
            c.logger.Info("orphaned commit resolved via retry",
                "tx_id", txID,
                "attempt", i+1)
            return nil
        }

        c.logger.Warn("retry failed",
            "tx_id", txID,
            "attempt", i+1,
            "error", err)
        time.Sleep(time.Duration(i+1) * 5 * time.Second)
    }

    // Step 2: Retries exhausted - initiate compensation
    c.logger.Error("initiating compensation protocol",
        "tx_id", txID,
        "reason", "failed shard unreachable after 3 retries")

    compensation := &CompensationTransaction{
        OriginalTxID:     txID,
        CompensationType: CompensationRevert,
        RevertReason:     "partial commit - failed shard unreachable",
        CreatedAt:        time.Now(),
    }

    // Step 3: Execute compensation transaction
    if err := c.executeCompensation(ctx, compensation, detection); err != nil {
        return fmt.Errorf("compensation failed: %w", err)
    }

    // Step 4: Slash coordinator bond for coordination failure
    penalty := CalculateCoordinatorPenalty(txID)
    if err := c.applyCoordinatorPenalty(penalty); err != nil {
        c.logger.Error("failed to apply coordinator penalty",
            "tx_id", txID,
            "penalty", penalty,
            "error", err)
    }

    return nil
}

// CompensationTransaction creates a revert transaction to restore consistency
type CompensationTransaction struct {
    OriginalTxID     TxID
    CompensationType CompensationType
    RevertReason     string
    SourceRevert     *RevertOp  // Debit from committed shard
    DestRevert       *RevertOp  // Credit back to original sender
    PenaltyFee       uint64     // Coordinator penalty amount
    CreatedAt        time.Time
    Signatures       []CommitteeSignature  // Requires BFT committee approval
}

type CompensationType uint8

const (
    CompensationRevert CompensationType = 1  // Revert committed shard
    CompensationForward CompensationType = 2 // Complete failed shard (if later recovered)
)

type RevertOp struct {
    ShardID      uint16
    Amount       uint64
    FromWallet   WalletID
    ToWallet     WalletID
    Evidence     []byte  // PreCommit evidence proving original commitment
    TPMQuote     []byte
    Timestamp    time.Time
}
```

**Compensation Transaction Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Cannot rollback committed shard | Immutability after DoCommit | WAL + PreCommit evidence |
| Eventual consistency | Both shards reach same state | Retry + compensation |
| Blame assignment | Coordinator pays penalty | Bond slashing |
| Auditability | Full transaction history | WAL + compensation log |
| BFT approval required | Cannot be executed unilaterally | Committee signatures |

**Timeline Example - Orphaned Commit**:

```
Time   Event                                          Source Shard        Dest Shard
─────────────────────────────────────────────────────────────────────────────────────
0.0s   DoCommit sent to both shards                   Received            Received
0.5s   Source commits, sends DONE                     COMMITTED           Processing
0.6s   Dest shard crashes                             COMMITTED           CRASHED
2.0s   Coordinator timeout waiting for dest           COMMITTED           UNREACHABLE
2.1s   New coordinator elected                        COMMITTED           UNREACHABLE
2.2s   New coordinator queries shard states           COMMITTED           UNREACHABLE
2.3s   Orphaned commit detected                       COMMITTED           UNREACHABLE
2.4s   Retry DoCommit with PreCommit evidence (1/3)   COMMITTED           UNREACHABLE
7.4s   Retry DoCommit with PreCommit evidence (2/3)   COMMITTED           UNREACHABLE
17.4s  Retry DoCommit with PreCommit evidence (3/3)   COMMITTED           UNREACHABLE
17.5s  Initiate compensation protocol                 COMMITTED           UNREACHABLE
17.6s  Create revert transaction                      Revert pending      -
18.0s  Execute revert: debit source                   REVERTED            -
18.1s  Execute revert: credit original sender         REVERTED            CONSISTENT
18.2s  Apply coordinator penalty (10% of tx amount)   REVERTED            CONSISTENT
18.3s  Compensation complete                          CONSISTENT          CONSISTENT
```

**CRITICAL SECURITY PROPERTIES**:

1. **No Unilateral Rollback**: Shards CANNOT rollback after DoCommit without BFT committee approval
2. **Compensation Required**: Failed commits require explicit compensation transactions
3. **Economic Penalty**: Coordinators pay for coordination failures (incentivizes reliability)
4. **Auditability**: All compensation transactions are logged with full evidence chain
5. **Eventual Consistency**: System guarantees eventual consistent state across all shards

#### Timeout Action Summary Table

| Phase | Timeout | Action | Can Abort? | Requires Evidence? |
|-------|---------|--------|------------|-------------------|
| CanCommit | 2s | Release locks, broadcast ABORT | YES | No |
| PreCommit | 3s | Query coordinator, wait 5s for election, abort with evidence | MAYBE | Yes (if aborting) |
| DoCommit | 5s | COMMIT (PreCommit received) | NO | N/A (always commits) |

#### Timeout Evidence Structure

```go
// TimeoutEvidence provides cryptographic proof of timeout for dispute resolution
type TimeoutEvidence struct {
    TransactionID    TxID
    Phase            Phase
    ParticipantShard uint16
    TimeoutOccurred  time.Time
    ExpectedDeadline time.Time
    CoordinatorID    NodeID            // Last known coordinator
    QueryAttempts    []QueryAttempt    // Log of coordinator queries
    ElectionAttempts []ElectionAttempt // Log of election attempts
    TPMQuote         []byte            // TPM attestation of timeout
    Signature        []byte
}

// QueryAttempt logs a coordinator query for evidence
type QueryAttempt struct {
    Timestamp time.Time
    Success   bool
    Error     string
    Latency   time.Duration
}

// ElectionAttempt logs a coordinator election attempt
type ElectionAttempt struct {
    Timestamp     time.Time
    Success       bool
    NewCoordinator NodeID
    Error         string
}
```

### 3PC Coordinator Crash Recovery (FINAL DESIGN)

When the coordinator crashes during an active 3PC transaction, participants must recover safely without violating atomicity or consistency guarantees.

#### Participant State During Coordinator Crash

```go
// 3PC Coordinator Crash Protocol
//
// Participants in PreCommit state:
// 1. Wait for new coordinator (30-second timeout)
// 2. New coordinator election via VRF among remaining shard coordinators
// 3. Transaction log recovery: new coordinator queries all participants
// 4. Heuristic decision: if all participants voted YES, commit; otherwise abort
// 5. Participant timeout: if no coordinator after 60 seconds, autonomous abort

const (
    NewCoordinatorWaitTimeout    = 30 * time.Second
    TotalCoordinatorWaitTimeout  = 60 * time.Second
    CoordinatorElectionTimeout   = 10 * time.Second
)

type ParticipantCrashState uint8

const (
    StateCanCommitWaiting     ParticipantCrashState = 1 // Waiting for CanCommit response
    StatePreCommitReceived    ParticipantCrashState = 2 // PreCommit received, can complete
    StateDoCommitWaiting      ParticipantCrashState = 3 // Waiting for DoCommit
    StateAbortReceived        ParticipantCrashState = 4 // Abort received
)

func (p *Participant) HandleCoordinatorCrash(txID TxID) error {
    state := p.getTransactionState(txID)

    switch state {
    case StateCanCommitWaiting:
        // Not yet committed to transaction - safe to abort
        return p.abortTransactionSafely(txID, "coordinator crash in CanCommit")

    case StatePreCommitReceived:
        // CRITICAL: We received PreCommit - must complete the transaction
        // Wait for new coordinator election
        return p.waitForNewCoordinator(txID)

    case StateDoCommitWaiting:
        // Coordinator told us to commit but didn't confirm - check with peers
        return p.queryPeersForDecision(txID)

    case StateAbortReceived:
        // Already aborted - nothing to do
        return nil

    default:
        return ErrUnknownTransactionState{TxID: txID, State: state}
    }
}
```

#### New Coordinator Election

```go
// New Coordinator Election Protocol
//
// When primary coordinator crashes, remaining shard coordinators
// elect a new coordinator using VRF.

func (p *Participant) waitForNewCoordinator(txID TxID) error {
    timeout := time.After(NewCoordinatorWaitTimeout)
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-timeout:
            // First timeout - try autonomous abort with evidence
            if time.Since(p.getPreCommitTime(txID)) > TotalCoordinatorWaitTimeout {
                p.logger.Error("coordinator not recovered, aborting autonomously",
                    "tx_id", txID,
                    "wait_time", TotalCoordinatorWaitTimeout)
                return p.autonomousAbort(txID)
            }

            // Extend wait one more period
            timeout = time.After(NewCoordinatorWaitTimeout)

        case <-ticker.C:
            // Check for new coordinator election
            newCoord, err := p.checkForNewCoordinator(txID)
            if err != nil {
                continue
            }

            if newCoord != nil {
                p.logger.Info("new coordinator elected",
                    "tx_id", txID,
                    "new_coordinator", newCoord.NodeID)
                return p.resumeWithNewCoordinator(txID, newCoord)
            }
        }
    }
}

func (p *Participant) checkForNewCoordinator(txID TxID) (*Coordinator, error) {
    // Query shard coordinators for election status
    election, err := p.queryCoordinatorElection(txID)
    if err != nil {
        return nil, err
    }

    if election.Complete && election.NewCoordinator != nil {
        return election.NewCoordinator, nil
    }

    return nil, nil
}
```

#### Transaction Log Recovery

```go
// Transaction Log Recovery
//
// New coordinator recovers transaction state by querying all participants
// for their vote status and current transaction state.

func (c *Coordinator) RecoverTransactionState(txID TxID) (*TransactionRecovery, error) {
    c.logger.Info("recovering transaction state",
        "tx_id", txID)

    // Query all participants
    participants := c.getTransactionParticipants(txID)
    responses := make([]*ParticipantStateResponse, 0, len(participants))

    for _, participantID := range participants {
        resp, err := c.queryParticipantState(participantID, txID)
        if err != nil {
            c.logger.Warn("failed to query participant",
                "participant", participantID,
                "error", err)
            continue
        }
        responses = append(responses, resp)
    }

    // Need responses from quorum of participants
    if len(responses) < (len(participants)/2 + 1) {
        return nil, ErrInsufficientParticipantResponses{
            Received: len(responses),
            Required: len(participants)/2 + 1,
        }
    }

    // Analyze responses for heuristic decision
    return c.makeHeuristicDecision(txID, responses)
}

type ParticipantStateResponse struct {
    ParticipantID   NodeID
    TxID            TxID
    CanCommitVote   Vote              // YES/NO/UNKNOWN
    PreCommitState  bool              // Received PreCommit?
    CommitComplete  bool              // Already committed?
    Timestamp       time.Time
    TPMQuote        []byte
    Signature       []byte
}

func (c *Coordinator) makeHeuristicDecision(
    txID TxID,
    responses []*ParticipantStateResponse,
) (*TransactionRecovery, error) {
    allVotedYes := true
    anyPreCommit := false
    anyCommitted := false

    for _, resp := range responses {
        if resp.CanCommitVote != VoteYes {
            allVotedYes = false
        }
        if resp.PreCommitState {
            anyPreCommit = true
        }
        if resp.CommitComplete {
            anyCommitted = true
        }
    }

    decision := &TransactionRecovery{
        TxID:      txID,
        Timestamp: time.Now(),
    }

    // Decision logic:
    // 1. If any participant already committed -> COMMIT
    // 2. If all voted YES and any received PreCommit -> COMMIT
    // 3. Otherwise -> ABORT

    if anyCommitted {
        decision.Decision = DecisionCommit
        decision.Reason = "at least one participant already committed"
    } else if allVotedYes && anyPreCommit {
        decision.Decision = DecisionCommit
        decision.Reason = "all participants voted YES and PreCommit was sent"
    } else {
        decision.Decision = DecisionAbort
        decision.Reason = "uncertain state, aborting for safety"
    }

    c.logger.Info("heuristic decision made",
        "tx_id", txID,
        "decision", decision.Decision,
        "reason", decision.Reason)

    return decision, nil
}
```

#### Autonomous Abort

```go
// Autonomous Abort
//
// If no coordinator appears after 60 seconds total wait time,
// participants autonomously abort the transaction with evidence.

func (p *Participant) autonomousAbort(txID TxID) error {
    // Create abort evidence
    evidence := &AutonomousAbortEvidence{
        TxID:              txID,
        ParticipantID:     p.nodeID,
        AbortReason:       "coordinator crash, timeout exceeded",
        WaitDuration:      TotalCoordinatorWaitTimeout,
        PreCommitReceived: p.hasPreCommitRecord(txID),
        AbortedAt:         time.Now(),
        TPMQuote:          p.tpm.Quote(txID[:]),
    }
    evidence.Signature = p.signWithTPM(evidence.Hash())

    // Abort transaction
    if err := p.abortTransaction(txID, evidence); err != nil {
        return fmt.Errorf("autonomous abort failed: %w", err)
    }

    // Broadcast abort evidence to network
    p.broadcastAbortEvidence(evidence)

    p.logger.Warn("autonomous abort completed",
        "tx_id", txID,
        "wait_duration", TotalCoordinatorWaitTimeout)

    return nil
}

type AutonomousAbortEvidence struct {
    TxID              TxID
    ParticipantID     NodeID
    AbortReason       string
    WaitDuration      time.Duration
    PreCommitReceived bool
    AbortedAt         time.Time
    TPMQuote          []byte
    Signature         []byte
}
```

### 3PC Termination Protocol (CANONICAL)

When the coordinator fails between PREPARE (PreCommit) and COMMIT (DoCommit) phases, the termination protocol activates to ensure consistent outcome across all participant shards.

**Termination Protocol Overview**:

```
Coordinator Crash Detected (15s timeout - 3 missed heartbeats)
              |
              v
┌─────────────────────────────────────────────────────────┐
│            TERMINATION PROTOCOL ACTIVATES               │
├─────────────────────────────────────────────────────────┤
│ 1. Participant shards detect coordinator death          │
│ 2. Shards query each other for coordinator intent       │
│ 3. 2-of-3 shard witnesses required for decision         │
│ 4. If commit evidence exists → ALL COMMIT               │
│ 5. If no commit evidence → ALL ROLLBACK                 │
└─────────────────────────────────────────────────────────┘
```

**Termination Protocol Configuration**:

```go
// TerminationProtocolConfig - non-configurable security parameters
const (
    // Coordinator failure detection
    CoordinatorDeathTimeout = 15 * time.Second  // 3 missed heartbeats

    // Shard witness quorum for termination decision
    TerminationWitnessQuorum = 2  // 2-of-3 shards must agree

    // Rollback timing
    RollbackGracePeriod   = 5 * time.Second  // Wait before auto-rollback
    RollbackRetryAttempts = 3                 // Max rollback retry attempts
    RollbackRetryDelay    = 2 * time.Second  // Delay between retries
)

// TerminationDecision represents the outcome of termination protocol
type TerminationDecision uint8

const (
    TerminationDecisionUnknown  TerminationDecision = iota
    TerminationDecisionCommit                         // Coordinator committed to at least one shard
    TerminationDecisionRollback                       // No commit evidence found
)

// ShardWitnessState represents a shard's knowledge of coordinator intent
type ShardWitnessState struct {
    ShardID           uint16
    TxID              TxID
    LastCoordinatorContact time.Time
    ReceivedPreCommit bool
    ReceivedDoCommit  bool              // CRITICAL: If true, coordinator intended to commit
    CoordinatorPhase  Phase              // Last known coordinator phase
    TPMQuote          []byte
    Timestamp         time.Time
    Signature         []byte
}
```

**Termination Protocol Implementation**:

```go
// TerminationProtocol handles coordinator failure during 3PC
type TerminationProtocol struct {
    shardID     uint16
    txID        TxID
    participants []uint16
    witnesses   map[uint16]*ShardWitnessState
    decision    TerminationDecision
    mu          sync.Mutex
}

// InitiateTermination starts the termination protocol after coordinator death
func (tp *TerminationProtocol) InitiateTermination(ctx context.Context) (*TerminationResult, error) {
    tp.mu.Lock()
    defer tp.mu.Unlock()

    // Step 1: Query all participant shards for their witness state
    tp.witnesses = make(map[uint16]*ShardWitnessState)
    for _, participantID := range tp.participants {
        state, err := tp.queryShardWitnessState(ctx, participantID)
        if err != nil {
            // Shard unreachable - continue with available witnesses
            continue
        }
        tp.witnesses[participantID] = state
    }

    // Step 2: Check if we have enough witnesses (2-of-3 minimum)
    if len(tp.witnesses) < TerminationWitnessQuorum {
        return nil, ErrInsufficientWitnesses{
            Required: TerminationWitnessQuorum,
            Available: len(tp.witnesses),
        }
    }

    // Step 3: Analyze witness states for commit evidence
    commitEvidence := false
    for _, witness := range tp.witnesses {
        if witness.ReceivedDoCommit {
            // CRITICAL: If ANY shard received DoCommit, coordinator intended to commit
            commitEvidence = true
            break
        }
    }

    // Step 4: Make termination decision
    if commitEvidence {
        tp.decision = TerminationDecisionCommit
        return tp.executeCommit(ctx)
    } else {
        tp.decision = TerminationDecisionRollback
        return tp.executeRollback(ctx)
    }
}

// executeCommit forces all shards to commit when commit evidence exists
func (tp *TerminationProtocol) executeCommit(ctx context.Context) (*TerminationResult, error) {
    result := &TerminationResult{
        TxID:     tp.txID,
        Decision: TerminationDecisionCommit,
        ShardResults: make(map[uint16]bool),
    }

    for _, participantID := range tp.participants {
        forceCommit := &ForceCommitMessage{
            TxID:            tp.txID,
            TerminationReason: "coordinator_death_with_commit_evidence",
            WitnessEvidence:  tp.collectWitnessEvidence(),
            Timestamp:        time.Now(),
        }
        forceCommit.Signature = signWithTPM(forceCommit.Hash())

        err := tp.sendForceCommit(ctx, participantID, forceCommit)
        result.ShardResults[participantID] = (err == nil)
    }

    return result, nil
}

// executeRollback initiates coordinated rollback with grace period
func (tp *TerminationProtocol) executeRollback(ctx context.Context) (*TerminationResult, error) {
    result := &TerminationResult{
        TxID:     tp.txID,
        Decision: TerminationDecisionRollback,
        ShardResults: make(map[uint16]bool),
    }

    // Wait grace period before rollback (allows late messages)
    select {
    case <-time.After(RollbackGracePeriod):
        // Grace period elapsed - proceed with rollback
    case <-ctx.Done():
        return nil, ctx.Err()
    }

    // Execute rollback with retries
    for _, participantID := range tp.participants {
        var lastErr error
        for attempt := 0; attempt < RollbackRetryAttempts; attempt++ {
            rollback := &RollbackMessage{
                TxID:            tp.txID,
                TerminationReason: "coordinator_death_no_commit_evidence",
                Attempt:         attempt + 1,
                WitnessEvidence:  tp.collectWitnessEvidence(),
                Timestamp:        time.Now(),
            }
            rollback.Signature = signWithTPM(rollback.Hash())

            lastErr = tp.sendRollback(ctx, participantID, rollback)
            if lastErr == nil {
                result.ShardResults[participantID] = true
                break
            }

            // Wait before retry
            time.Sleep(RollbackRetryDelay)
        }

        if lastErr != nil {
            result.ShardResults[participantID] = false
        }
    }

    return result, nil
}
```

**Termination Decision Flow**:

```
┌─────────────────────────────────────────────────────────────────┐
│               TERMINATION DECISION FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Coordinator Death Detected (15s timeout)                       │
│           |                                                     │
│           v                                                     │
│  Query Participant Shards for Witness State                     │
│           |                                                     │
│           v                                                     │
│  ┌─────────────────────────────────────────┐                   │
│  │ Have 2-of-3 Witnesses?                  │                   │
│  │   NO  → Wait + Retry (up to 30s)        │                   │
│  │   YES → Continue                        │                   │
│  └─────────────────────────────────────────┘                   │
│           |                                                     │
│           v                                                     │
│  ┌─────────────────────────────────────────┐                   │
│  │ Any Shard Received DoCommit?            │                   │
│  │                                          │                   │
│  │   YES → COMMIT ALL SHARDS               │                   │
│  │         (Coordinator intended commit)    │                   │
│  │                                          │                   │
│  │   NO  → Wait Grace Period (5s)          │                   │
│  │         Then ROLLBACK ALL SHARDS        │                   │
│  │         (Retry 3x with 2s delay)        │                   │
│  └─────────────────────────────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Termination Protocol Timing**:

| Event | Time | Action |
|-------|------|--------|
| Last heartbeat | 0s | Coordinator last seen |
| Heartbeat timeout | 15s | 3 missed heartbeats detected |
| Witness query | 15-20s | Query shards for state |
| Decision made | 20-25s | Commit or rollback decided |
| Grace period (rollback only) | 25-30s | Wait for late messages |
| Execution | 30-35s | Force commit or rollback |
| Retry (if needed) | 35-41s | Up to 3 retries, 2s apart |

**Safety Properties**:

1. **Agreement**: All shards reach the same decision (commit or rollback)
2. **Validity**: Decision reflects coordinator intent when evidence exists
3. **Termination**: Protocol completes within bounded time (< 45s)
4. **Integrity**: Witness evidence is TPM-attested and tamper-evident

### Cross-Shard Consistency (FINAL DESIGN)

Cross-shard transactions must maintain consistency even when different shards experience different timeout behavior or partial failures.

#### Timeout Asymmetry Handling

```go
// Two-Phase Visibility
//
// Transaction visibility is locked until all shards confirm completion.
// This prevents partial visibility where some shards see the transaction
// and others don't, leading to inconsistent balances.

type TransactionVisibility struct {
    TxID            TxID
    SourceShard     uint16
    DestShard       uint16
    SourceComplete  bool
    DestComplete    bool
    VisibilityLock  bool
    LockedAt        time.Time
}

const (
    MaxVisibilityLockDuration = 120 * time.Second
)

func (tv *TransactionVisibility) IsVisible() bool {
    // Transaction only visible after ALL shards confirm
    return tv.SourceComplete && tv.DestComplete && !tv.VisibilityLock
}

func (tv *TransactionVisibility) CheckVisibilityTimeout() error {
    if !tv.VisibilityLock {
        return nil
    }

    if time.Since(tv.LockedAt) > MaxVisibilityLockDuration {
        // Visibility lock expired - investigate
        return ErrVisibilityLockExpired{
            TxID:       tv.TxID,
            LockedAt:   tv.LockedAt,
            Duration:   time.Since(tv.LockedAt),
        }
    }

    return nil
}
```

#### Atomic Visibility Protocol

```go
// Atomic Visibility
//
// Transaction only becomes visible after all shards report CommitComplete.
// Compensating transactions are issued if any shard fails to commit.

func (c *Coordinator) EnsureAtomicVisibility(txID TxID) error {
    participants := c.getTransactionParticipants(txID)

    // Wait for all shards to report completion
    completions := make(map[uint16]*CommitCompleteReport)
    timeout := time.After(30 * time.Second)

    for len(completions) < len(participants) {
        select {
        case report := <-c.commitCompleteChan:
            if report.TxID == txID {
                completions[report.ShardID] = report
            }

        case <-timeout:
            // Timeout - check which shards haven't responded
            missing := c.findMissingShards(participants, completions)
            c.logger.Warn("commit complete timeout, missing shards",
                "tx_id", txID,
                "missing_shards", missing)

            // Issue compensating transaction
            return c.issueCompensatingTransaction(txID, completions)
        }
    }

    // All shards confirmed - make transaction visible
    return c.makeTransactionVisible(txID)
}
```

#### Partial Commit Recovery

```go
// Partial Commit Recovery
//
// If commit fails on any shard after PreCommit, a compensating
// transaction reverses the effects on successful shards.

func (c *Coordinator) issueCompensatingTransaction(
    txID TxID,
    completions map[uint16]*CommitCompleteReport,
) error {
    c.logger.Error("partial commit detected, issuing compensating transaction",
        "tx_id", txID,
        "completed_shards", len(completions))

    // Create compensating transaction
    compTx := &CompensatingTransaction{
        OriginalTxID:    txID,
        CompensatingAt:  time.Now(),
        AffectedShards:  make([]uint16, 0),
    }

    // For each shard that completed, reverse the transaction
    for shardID, report := range completions {
        if report.Success {
            reversal := &ShardReversal{
                ShardID:       shardID,
                OriginalOp:    report.Operation,
                ReversalOp:    c.computeReversalOperation(report.Operation),
            }
            compTx.Reversals = append(compTx.Reversals, reversal)
            compTx.AffectedShards = append(compTx.AffectedShards, shardID)
        }
    }

    // Execute compensating transaction
    if err := c.executeCompensatingTransaction(compTx); err != nil {
        return fmt.Errorf("compensating transaction failed: %w", err)
    }

    c.logger.Info("compensating transaction completed",
        "tx_id", txID,
        "comp_tx_id", compTx.ID,
        "reversed_shards", len(compTx.Reversals))

    return nil
}

type CompensatingTransaction struct {
    ID              TxID
    OriginalTxID    TxID
    Reversals       []*ShardReversal
    AffectedShards  []uint16
    CompensatingAt  time.Time
    Signature       []byte
}

type ShardReversal struct {
    ShardID     uint16
    OriginalOp  *ShardOperation
    ReversalOp  *ShardOperation
}
```

### UTXO Locking

#### Lock Granularity

UTXO-level locks (not account-level) maximize concurrency:

- Multiple transactions can operate on same account using different UTXOs
- Only transactions spending exact same UTXOs conflict

#### Deadlock Prevention

All transactions acquire locks in ascending lexicographic order of UTXO IDs:

```go
func AcquireUTXOLocks(utxos []UTXOID, txid TransactionID) error {
    sort.Slice(utxos, func(i, j int) bool {
        return utxos[i].String() < utxos[j].String()
    })
    for _, utxo := range utxos {
        if !lockManager.TryLock(utxo, txid, timeout) {
            ReleaseUTXOLocks(utxos[:i], txid)
            return ErrLockAcquisitionFailed
        }
    }
    return nil
}
```

### A3: Cross-Shard Deadlock Prevention (SECURITY FIX)

Cross-shard transactions MUST acquire shard locks in ascending shard ID order to prevent circular wait deadlocks. This section specifies the global lock ordering protocol and deadlock detection/resolution mechanisms.

#### Problem Statement

**Circular wait deadlock:**
1. Tx1 coordinator acquires lock on Shard A UTXOs, then requests Shard B
2. Tx2 coordinator acquires lock on Shard B UTXOs, then requests Shard A
3. Both wait indefinitely → deadlock (even with TTL, causes timeout storm)

#### Global Shard Lock Ordering

```go
// CrossShardLockManager coordinates lock acquisition across shards
type CrossShardLockManager struct {
    localShardID   uint16
    lockState      map[TxID]*CrossShardLockState
    deadlockTimer  *DeadlockDetector
    mu             sync.RWMutex
}

// CrossShardLockState tracks cross-shard lock acquisition for a transaction
type CrossShardLockState struct {
    TxID              TxID
    InvolvedShards    []uint16            // Sorted in ascending order
    AcquiredShards    map[uint16]bool     // Shards where locks are held
    PendingShard      uint16              // Currently trying to acquire
    State             CrossShardState
    StartTime         time.Time
    DeadlockDetected  bool
}

type CrossShardState uint32

const (
    CrossShardStateAcquiring   CrossShardState = iota  // Acquiring locks in order
    CrossShardStateAllAcquired                          // All shards locked
    CrossShardStateReleasing                            // Releasing due to abort/deadlock
    CrossShardStateComplete                             // Transaction complete
)

// Deadlock prevention constants
const (
    MaxShardLockWait   = 10 * time.Second  // Max wait per shard
    DeadlockCheckInterval = 1 * time.Second // How often to check for deadlocks
    MaxDeadlockRetries = 3                  // Max retries after deadlock resolution
)

// AcquireCrossShardLocks acquires locks across multiple shards in global order
func (csm *CrossShardLockManager) AcquireCrossShardLocks(
    ctx context.Context,
    txID TxID,
    shardUTXOs map[uint16][]UTXOID,
) error {
    // Step 1: Extract and sort shard IDs (GLOBAL ORDERING)
    shardIDs := make([]uint16, 0, len(shardUTXOs))
    for shardID := range shardUTXOs {
        shardIDs = append(shardIDs, shardID)
    }
    sort.Slice(shardIDs, func(i, j int) bool {
        return shardIDs[i] < shardIDs[j]
    })

    // Step 2: Initialize lock state
    state := &CrossShardLockState{
        TxID:           txID,
        InvolvedShards: shardIDs,
        AcquiredShards: make(map[uint16]bool),
        State:          CrossShardStateAcquiring,
        StartTime:      time.Now(),
    }

    csm.mu.Lock()
    csm.lockState[txID] = state
    csm.mu.Unlock()

    // Step 3: Acquire locks in ascending shard ID order (PREVENTS CIRCULAR WAIT)
    for _, shardID := range shardIDs {
        state.PendingShard = shardID
        utxos := shardUTXOs[shardID]

        // Sort UTXOs within shard lexicographically
        sort.Slice(utxos, func(i, j int) bool {
            return utxos[i].String() < utxos[j].String()
        })

        // Acquire with timeout and deadlock detection
        if err := csm.acquireShardLocks(ctx, state, shardID, utxos); err != nil {
            // Failed to acquire - release all held locks
            csm.releaseCrossShardLocks(txID)
            return fmt.Errorf("shard %d lock acquisition failed: %w", shardID, err)
        }

        state.AcquiredShards[shardID] = true
    }

    state.State = CrossShardStateAllAcquired
    return nil
}

// acquireShardLocks acquires locks on a single shard with deadlock detection
func (csm *CrossShardLockManager) acquireShardLocks(
    ctx context.Context,
    state *CrossShardLockState,
    shardID uint16,
    utxos []UTXOID,
) error {
    ctx, cancel := context.WithTimeout(ctx, MaxShardLockWait)
    defer cancel()

    // Try to acquire locks
    for _, utxo := range utxos {
        select {
        case <-ctx.Done():
            return ErrShardLockTimeout{ShardID: shardID}
        default:
        }

        acquired, err := csm.tryAcquireUTXOLock(ctx, shardID, utxo, state.TxID)
        if err != nil {
            return err
        }
        if !acquired {
            // Check for potential deadlock
            if csm.detectDeadlock(state, shardID, utxo) {
                return ErrDeadlockDetected{
                    TxID:    state.TxID,
                    ShardID: shardID,
                    UTXOID:  utxo,
                }
            }
            // Wait and retry
            time.Sleep(100 * time.Millisecond)
        }
    }

    return nil
}
```

#### Deadlock Detection

```go
// DeadlockDetector identifies circular wait conditions
type DeadlockDetector struct {
    waitForGraph   map[TxID][]TxID  // Tx A is waiting for Tx B to release
    mu             sync.RWMutex
}

// detectDeadlock checks if acquiring this lock would cause deadlock
func (csm *CrossShardLockManager) detectDeadlock(
    state *CrossShardLockState,
    shardID uint16,
    utxo UTXOID,
) bool {
    // Get holder of the contested lock
    holder := csm.getLockHolder(shardID, utxo)
    if holder == nil {
        return false  // No holder, no deadlock
    }

    // Check if holder is waiting for us (circular dependency)
    return csm.deadlockTimer.checkCycle(state.TxID, *holder)
}

// checkCycle performs DFS to detect circular wait
func (dd *DeadlockDetector) checkCycle(from, to TxID) bool {
    dd.mu.RLock()
    defer dd.mu.RUnlock()

    visited := make(map[TxID]bool)
    return dd.dfs(from, to, visited)
}

func (dd *DeadlockDetector) dfs(current, target TxID, visited map[TxID]bool) bool {
    if current == target {
        return true
    }
    if visited[current] {
        return false
    }
    visited[current] = true

    for _, next := range dd.waitForGraph[current] {
        if dd.dfs(next, target, visited) {
            return true
        }
    }
    return false
}

// recordWait adds a wait edge to the graph
func (dd *DeadlockDetector) recordWait(waiter, holder TxID) {
    dd.mu.Lock()
    defer dd.mu.Unlock()
    dd.waitForGraph[waiter] = append(dd.waitForGraph[waiter], holder)
}

// clearWait removes wait edges for a transaction
func (dd *DeadlockDetector) clearWait(txID TxID) {
    dd.mu.Lock()
    defer dd.mu.Unlock()
    delete(dd.waitForGraph, txID)

    // Remove from all holders' lists
    for holder, waiters := range dd.waitForGraph {
        filtered := make([]TxID, 0, len(waiters))
        for _, w := range waiters {
            if w != txID {
                filtered = append(filtered, w)
            }
        }
        dd.waitForGraph[holder] = filtered
    }
}
```

#### Deadlock Resolution Protocol

```go
// DeadlockResolution defines how to resolve detected deadlocks
type DeadlockResolution struct {
    priorityFunc   func(TxID) int  // Higher priority wins
    retryDelay     time.Duration
    maxRetries     int
}

// resolveDeadlock handles a detected deadlock condition
func (csm *CrossShardLockManager) resolveDeadlock(
    ctx context.Context,
    state *CrossShardLockState,
) error {
    // Strategy: Lower priority transaction backs off and retries

    myPriority := csm.calculatePriority(state.TxID)

    // Find all transactions we're waiting for
    dd := csm.deadlockTimer
    dd.mu.RLock()
    waitingFor := dd.waitForGraph[state.TxID]
    dd.mu.RUnlock()

    for _, otherTxID := range waitingFor {
        otherPriority := csm.calculatePriority(otherTxID)

        if myPriority < otherPriority {
            // We lose - back off
            logDeadlockResolution(state.TxID, otherTxID, "backing_off")
            return ErrDeadlockBackoff{
                MyTxID:        state.TxID,
                WinnerTxID:    otherTxID,
                MyPriority:    myPriority,
                WinnerPriority: otherPriority,
            }
        }
    }

    // We have higher priority - other transaction should back off
    // Wait briefly for them to detect and abort
    time.Sleep(500 * time.Millisecond)
    return nil
}

// calculatePriority determines transaction priority for deadlock resolution
// Uses combination of: age (older = higher), gas price, and randomness
func (csm *CrossShardLockManager) calculatePriority(txID TxID) int {
    csm.mu.RLock()
    state, exists := csm.lockState[txID]
    csm.mu.RUnlock()

    if !exists {
        return 0
    }

    // Age-based priority: older transactions win (prevents starvation)
    agePriority := int(time.Since(state.StartTime).Milliseconds())

    // Add small random component to break ties deterministically
    tieBreaker := int(txID[0])

    return agePriority + tieBreaker
}
```

#### Cross-Shard Lock Ordering Verification

```go
// verifyLockOrdering validates that locks are being acquired in correct order
func verifyLockOrdering(txID TxID, shardHistory []uint16) error {
    for i := 1; i < len(shardHistory); i++ {
        if shardHistory[i] <= shardHistory[i-1] {
            return ErrLockOrderingViolation{
                TxID:     txID,
                Expected: "ascending shard ID order",
                Got:      fmt.Sprintf("shard %d after shard %d", shardHistory[i], shardHistory[i-1]),
            }
        }
    }
    return nil
}
```

**Cross-Shard Deadlock Prevention Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No circular wait | Shards locked in ascending ID order | Global ordering |
| No starvation | Older transactions have priority | Age-based priority |
| Fast detection | DFS on wait-for graph | DeadlockDetector |
| Graceful resolution | Lower priority backs off | Priority comparison |
| Bounded wait | Max 10s per shard | MaxShardLockWait constant |

#### Lock State

```go
type UTXOLock struct {
    UTXOID        string
    TransactionID string
    AcquiredAt    time.Time
    ExpiresAt     time.Time     // MANDATORY: Explicit TTL
    State         LockState     // HELD, PRECOMMIT, RELEASED, EXPIRED, ORPHANED
}

type LockState int
const (
    LockHeld      LockState = 0  // CanCommit phase
    LockPreCommit LockState = 1  // PreCommit phase (durable)
    LockReleased  LockState = 2  // DoCommit or Abort completed
    LockExpired   LockState = 3  // TTL expired
    LockOrphaned  LockState = 4  // Coordinator unreachable
)
```

### Timeout and Adaptive Lock Duration

| Phase | Base Timeout | Purpose |
|-------|-------------|---------|
| CanCommit (T1) | 2s | Shard response collection |
| PreCommit (T2) | 3s | Durable state persistence |
| DoCommit (T3) | 5s | Final state transition |
| Lock Expiry | Adaptive (max 1hr) | UTXO lock auto-release |

#### Adaptive Lock Calculation (CANONICAL)

**SECURITY FIX**: Uses p95 percentile instead of average to prevent premature lock release during congestion spikes. Includes jitter to prevent coordinated attacks.

```
adaptive_timeout = p95_confirmation_time * 1.5 + jitter

Where:
  p95_confirmation_time = 95th percentile of last 100 transactions
  jitter = random(0, timeout * 0.1)  // Prevents coordinated attacks
  Update frequency = Every 10 transactions
  Minimum timeout = 5s
  Maximum timeout = 60s
```

```go
type TimeoutManager struct {
    completionTimes []time.Duration
    windowSize      int           // 100 transactions
    minTimeout      time.Duration // 5s
    maxTimeout      time.Duration // 60s
    rng             *rand.Rand    // Hardware RNG via go-xkms
}

func (tm *TimeoutManager) CalculateLockTimeout() time.Duration {
    if len(tm.completionTimes) < 10 {
        return tm.minTimeout
    }

    // Use p95 instead of average for resilience to congestion spikes
    p95 := calculatePercentile(tm.completionTimes, 95)
    adaptive := time.Duration(float64(p95) * 1.5)

    // Add jitter to prevent coordinated timing attacks
    // Jitter range: 0 to 10% of timeout
    maxJitter := float64(adaptive) * 0.1
    jitter := time.Duration(tm.rng.Float64() * maxJitter)
    adaptive += jitter

    // Extend timeout if queue depth indicates congestion
    if tm.getQueueDepth() > 50 {
        adaptive = time.Duration(float64(adaptive) * 1.5)
    }

    return clamp(adaptive, tm.minTimeout, tm.maxTimeout)
}

func calculatePercentile(times []time.Duration, percentile int) time.Duration {
    sorted := make([]time.Duration, len(times))
    copy(sorted, times)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i] < sorted[j]
    })
    index := (percentile * len(sorted)) / 100
    return sorted[index]
}
```

**Why p95 + Jitter?**

| Attack | Average-Based | p95 + Jitter |
|--------|---------------|--------------|
| Congestion spike | Locks expire prematurely | p95 accounts for spikes |
| Coordinated timing | Predictable lock expiry | Jitter randomizes expiry |
| Queue flooding | Average lags behind | Queue-based extension |

### Failure Scenarios and Recovery

#### Scenario 1: Shard Failure During CanCommit

- **Detection**: Timeout T1 expires
- **Recovery**: Coordinator sends Abort to all responsive shards
- **Impact**: Minimal - only lock cleanup needed

#### Scenario 2: Shard Failure During PreCommit

- **Detection**: Timeout T2 expires
- **Recovery**:
  1. Retry up to 3 times
  2. Query all shards for PreCommit state
  3. Majority PreCommitted: Force DoCommit
  4. Majority not PreCommitted: Force Abort

#### Scenario 3: Shard Failure During DoCommit

- **Detection**: Timeout T3 expires
- **Recovery**: Shard independently decides based on PreCommit log
  - PreCommit log exists: Complete commit
  - No log: Abort

**Critical**: This is the key advantage of 3PC - shards can progress without coordinator.

#### Scenario 4: Coordinator Failure

- **Detection**: Heartbeat timeout (10s)
- **Recovery**:
  1. Shards contact new committee leader
  2. New coordinator queries all shards for state
  3. State reconciliation:
     - All in PreCommit: Send DoCommit
     - Any in Abort: Send Abort
     - Mixed: Use PreCommit majority rule

#### Scenario 5: Network Partition

- During CanCommit/PreCommit: Abort (cannot guarantee atomicity)
- During DoCommit: Complete on accessible shards; partitioned shards use PreCommit log

#### Scenario 6: Lock Timeout Expiry

- Shard releases expired locks
- Transaction transitions to Aborted
- Coordinator notifies other shards
- Client can retry

### Cross-Shard Failure Recovery Paths (COMPREHENSIVE)

This section documents the complete failure recovery protocols for cross-shard transactions, covering participant crashes, network partitions, and coordinator election during active transactions.

#### Failure Recovery 1: Participant Crash During 3PC

When a participant shard crashes during an active 3PC transaction, the coordinator must detect the failure and either continue with remaining participants (if quorum available) or abort the transaction.

**Detection Mechanism:**

```go
const (
    ParticipantHeartbeatInterval = 2 * time.Second  // Heartbeat frequency
    ParticipantTimeoutThreshold  = 8 * time.Second  // 4 missed heartbeats = crash
    ParticipantQuorumThreshold   = 0.67             // 2/3 participants required
)

// Coordinator tracks participant health during transaction
type ParticipantHealth struct {
    NodeID          NodeID
    LastHeartbeat   time.Time
    Phase           Phase          // Last known phase
    Responsive      bool
}

func (c *Coordinator) monitorParticipant(txID TxID, nodeID NodeID) {
    ticker := time.NewTicker(ParticipantHeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            elapsed := time.Since(c.getLastHeartbeat(txID, nodeID))
            if elapsed > ParticipantTimeoutThreshold {
                c.handleParticipantTimeout(txID, nodeID)
                return
            }
        case <-c.transactionComplete(txID):
            return
        }
    }
}
```

**Recovery Protocol by Phase:**

**Phase 1: CanCommit**
- Participant crash detected via heartbeat timeout (8s)
- If remaining participants >= quorum (2/3): Continue transaction
- If quorum lost: Abort entire transaction
- Coordinator sends Abort to all responsive participants
- Locks released immediately (no PreCommit issued yet)
- Transaction state: ABORTED
- Client notification: Transaction failed, safe to retry

```go
func (c *Coordinator) handleCanCommitCrash(txID TxID, crashedNode NodeID) error {
    tx := c.getTransaction(txID)
    tx.markParticipantUnresponsive(crashedNode)

    responsiveCount := tx.countResponsiveParticipants()
    requiredQuorum := int(float64(tx.totalParticipants) * ParticipantQuorumThreshold)

    if responsiveCount >= requiredQuorum {
        // Continue with reduced participant set
        c.logger.Warn("participant crashed during CanCommit, continuing with quorum",
            "tx_id", txID,
            "crashed_node", crashedNode,
            "responsive", responsiveCount,
            "required_quorum", requiredQuorum)
        return c.continueCanCommit(txID)
    }

    // Quorum lost - abort transaction
    c.logger.Error("quorum lost during CanCommit, aborting transaction",
        "tx_id", txID,
        "responsive", responsiveCount,
        "required_quorum", requiredQuorum)
    return c.abortTransaction(txID, "quorum lost - participant crash")
}
```

**Phase 2: PreCommit**
- Participant crash detected via heartbeat timeout (8s)
- Coordinator has already sent PreCommit to all participants
- If remaining participants >= quorum: Proceed to DoCommit
- If quorum lost: Cannot safely commit or abort (3PC blocking scenario)
  - Wait for crashed participant recovery (up to RecoveryLockTTL = 5 minutes)
  - If participant recovers: Query its PreCommit state and continue
  - If timeout expires: Initiate coordinator election for recovery

```go
func (c *Coordinator) handlePreCommitCrash(txID TxID, crashedNode NodeID) error {
    tx := c.getTransaction(txID)
    tx.markParticipantUnresponsive(crashedNode)

    // Check if we received PreCommit ACK from crashed node before crash
    preCommitACK := tx.hasPreCommitAck(crashedNode)

    responsiveCount := tx.countResponsiveParticipants()
    requiredQuorum := int(float64(tx.totalParticipants) * ParticipantQuorumThreshold)

    if responsiveCount >= requiredQuorum && preCommitACK {
        // Safe to proceed to DoCommit - crashed node already acknowledged PreCommit
        c.logger.Warn("participant crashed after PreCommit ACK, continuing to DoCommit",
            "tx_id", txID,
            "crashed_node", crashedNode)
        return c.sendDoCommit(txID)
    }

    if responsiveCount >= requiredQuorum && !preCommitACK {
        // Crashed before ACK - wait for recovery or timeout
        c.logger.Warn("participant crashed before PreCommit ACK, waiting for recovery",
            "tx_id", txID,
            "crashed_node", crashedNode,
            "timeout", RecoveryLockTTL)
        return c.waitForParticipantRecovery(txID, crashedNode, RecoveryLockTTL)
    }

    // Quorum lost - enter recovery mode
    c.logger.Error("quorum lost during PreCommit, entering recovery mode",
        "tx_id", txID)
    return c.enterRecoveryMode(txID)
}
```

**Phase 3: DoCommit**
- Participant crash detected via heartbeat timeout (8s)
- Transaction MUST complete - PreCommit decision is durable
- Coordinator continues sending DoCommit to responsive participants
- Crashed participant will recover from WAL and complete commit on restart
- Lock extension may be required if recovery takes > OperationalLockTTL

```go
func (c *Coordinator) handleDoCommitCrash(txID TxID, crashedNode NodeID) error {
    // DoCommit is best-effort - participants are committed to transaction
    c.logger.Warn("participant crashed during DoCommit, will recover from WAL",
        "tx_id", txID,
        "crashed_node", crashedNode)

    // Continue with remaining participants
    tx := c.getTransaction(txID)
    tx.markParticipantUnresponsive(crashedNode)

    // Monitor for recovery and retry DoCommit when participant returns
    go c.retryDoCommitOnRecovery(txID, crashedNode)

    return nil // Non-blocking - transaction continues
}
```

#### Failure Recovery 2: Shard Partition During Transaction

Network partitions can split the cluster into multiple components that cannot communicate. The 3PC protocol must handle partitions without violating atomicity.

**Partition Detection:**

```go
const (
    PartitionDetectionInterval = 3 * time.Second   // Check for partition
    PartitionSuspectThreshold  = 10 * time.Second  // Suspect partition after 10s
    PartitionConfirmThreshold  = 30 * time.Second  // Confirm partition after 30s
)

type PartitionState uint8
const (
    PartitionNone      PartitionState = 0  // No partition detected
    PartitionSuspected PartitionState = 1  // Possible partition
    PartitionConfirmed PartitionState = 2  // Partition confirmed
)

func (p *Participant) detectPartition() PartitionState {
    // Check connectivity to coordinator and peer shards
    unreachableNodes := p.checkNodeConnectivity()

    if len(unreachableNodes) == 0 {
        return PartitionNone
    }

    // Check how long nodes have been unreachable
    oldestUnreachable := p.getOldestUnreachableTime(unreachableNodes)

    if oldestUnreachable > PartitionConfirmThreshold {
        return PartitionConfirmed
    }

    if oldestUnreachable > PartitionSuspectThreshold {
        return PartitionSuspected
    }

    return PartitionNone
}
```

**Partition Recovery Protocol:**

**During CanCommit:**
- Participant detects partition to coordinator
- Cannot receive CanCommit message
- After timeout (Phase1CanCommitTimeout = 2s), participant aborts locally
- Transaction state: ABORTED
- Locks released immediately
- When partition heals: Coordinator confirms abort with participant

**During PreCommit:**
- Participants in partition enter SUSPENDED state
- MUST NOT commit or abort until partition resolves
- Locks are automatically extended during partition (special partition extension)
- Participants log partition event in WAL
- When partition heals:
  - Participants contact coordinator for transaction status
  - Coordinator sends DoCommit or Abort based on overall transaction state
  - Participants complete transaction according to coordinator decision

```go
func (p *Participant) handlePreCommitPartition(txID TxID) error {
    // Enter SUSPENDED state - cannot proceed without coordinator
    p.setTransactionState(txID, StateSuspended)

    // Enable partition lock extensions
    p.enablePartitionLockExtension(txID)

    // Log partition event
    p.wal.LogPartitionEvent(txID, time.Now())

    c.logger.Warn("partition detected during PreCommit, entering SUSPENDED state",
        "tx_id", txID,
        "state", "SUSPENDED")

    // Wait for partition to heal
    return p.waitForPartitionResolution(txID)
}

func (p *Participant) enablePartitionLockExtension(txID TxID) {
    // During partition, automatically extend locks without quorum
    // This is safe because all participants are in same suspended state
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if p.getTransactionState(txID) != StateSuspended {
                return // Partition resolved or transaction completed
            }

            // Extend lock unilaterally during partition
            p.extendLockDuringPartition(txID, 60 * time.Second)

            c.logger.Debug("lock extended during partition",
                "tx_id", txID,
                "extension", "60s")

        case <-p.partitionResolved(txID):
            return
        }
    }
}

func (p *Participant) waitForPartitionResolution(txID TxID) error {
    ticker := time.NewTicker(PartitionDetectionInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            partitionState := p.detectPartition()

            if partitionState == PartitionNone {
                // Partition healed - contact coordinator
                c.logger.Info("partition resolved, contacting coordinator",
                    "tx_id", txID)
                return p.resumeAfterPartition(txID)
            }

        case <-time.After(RecoveryLockTTL):
            // Partition lasted too long - abort transaction
            c.logger.Error("partition timeout exceeded, aborting transaction",
                "tx_id", txID,
                "timeout", RecoveryLockTTL)
            return p.abortTransaction(txID, "partition timeout")
        }
    }
}

func (p *Participant) resumeAfterPartition(txID TxID) error {
    // Contact coordinator to get transaction status
    coord := p.getCoordinator(txID)
    if coord == nil {
        // Coordinator unreachable - trigger coordinator election
        return p.triggerCoordinatorElection(txID)
    }

    // Query coordinator for transaction decision
    decision, err := coord.GetTransactionDecision(txID)
    if err != nil {
        return fmt.Errorf("failed to get transaction decision: %w", err)
    }

    // Execute decision
    switch decision {
    case DecisionCommit:
        return p.executeDoCommit(txID)
    case DecisionAbort:
        return p.executeAbort(txID)
    default:
        return fmt.Errorf("unknown decision: %v", decision)
    }
}
```

**During DoCommit:**
- Partition cannot prevent commit - decision is already made
- Participants in partition complete commit using PreCommit log
- Locks released after commit completes
- When partition heals: Coordinator confirms commit with participants

#### Failure Recovery 3: Coordinator Election During Transaction

When the coordinator crashes during an active transaction, a new coordinator must be elected to complete the transaction. The election protocol ensures safety and liveness.

**Election Protocol:**

```go
const (
    CoordinatorElectionTimeout   = 10 * time.Second  // Max time for election
    NewCoordinatorWaitTimeout    = 30 * time.Second  // Participant wait time
    TotalCoordinatorWaitTimeout  = 60 * time.Second  // Absolute maximum wait
)

// Coordinator election uses VRF among remaining shard coordinators
func (p *Participant) triggerCoordinatorElection(txID TxID) error {
    c.logger.Info("triggering coordinator election",
        "tx_id", txID)

    // Get all shard coordinators for this transaction
    shardCoords := p.getTransactionShardCoordinators(txID)

    // Broadcast election request
    electionReq := &CoordinatorElectionRequest{
        TxID:              txID,
        RequestTime:       time.Now(),
        RequesterNodeID:   p.nodeID,
    }

    responses := make([]*ElectionResponse, 0, len(shardCoords))
    timeout := time.After(CoordinatorElectionTimeout)

    // Collect VRF-based votes from all shard coordinators
    for _, coord := range shardCoords {
        go func(c NodeID) {
            resp, err := p.sendElectionRequest(c, electionReq)
            if err == nil {
                responses = append(responses, resp)
            }
        }(coord)
    }

    // Wait for quorum of responses
    select {
    case <-timeout:
        if len(responses) < int(float64(len(shardCoords))*ParticipantQuorumThreshold) {
            return ErrElectionQuorumNotReached
        }
    case <-p.electionComplete(txID):
        // Got quorum
    }

    // Select new coordinator based on highest VRF output
    newCoord := p.selectCoordinatorByVRF(responses)

    c.logger.Info("new coordinator elected",
        "tx_id", txID,
        "new_coordinator", newCoord.NodeID)

    return p.resumeWithNewCoordinator(txID, newCoord)
}
```

**New Coordinator State Reconstruction:**

The new coordinator must reconstruct the transaction state by querying all participants:

```go
func (nc *NewCoordinator) reconstructTransactionState(txID TxID) (*TransactionState, error) {
    c.logger.Info("reconstructing transaction state",
        "tx_id", txID)

    // Query all known participants for their transaction state
    participants := nc.getTransactionParticipants(txID)
    states := make(map[NodeID]*ParticipantState)

    for _, p := range participants {
        state, err := nc.queryParticipantState(p, txID)
        if err != nil {
            c.logger.Warn("failed to query participant",
                "participant", p,
                "error", err)
            continue
        }
        states[p] = state
    }

    // Reconstruct 3PC phase from participant responses
    return nc.determineTransactionPhase(txID, states)
}

func (nc *NewCoordinator) determineTransactionPhase(
    txID TxID,
    states map[NodeID]*ParticipantState,
) (*TransactionState, error) {

    // Count states
    canCommitCount := 0
    preCommitCount := 0
    doCommitCount := 0
    abortCount := 0

    for _, state := range states {
        switch state.Phase {
        case PhaseCanCommit:
            canCommitCount++
        case PhasePreCommit:
            preCommitCount++
        case PhaseDoCommit:
            doCommitCount++
        case PhaseAbort:
            abortCount++
        }
    }

    totalParticipants := len(states)
    quorum := int(float64(totalParticipants) * ParticipantQuorumThreshold)

    // Decision logic based on 3PC semantics:
    // 1. If any participant in DoCommit or committed: COMMIT
    // 2. If quorum in PreCommit and none aborted: COMMIT
    // 3. If any participant aborted: ABORT
    // 4. Otherwise: ABORT (safe default)

    if doCommitCount > 0 {
        // At least one participant already committing - must complete commit
        return &TransactionState{
            TxID:     txID,
            Decision: DecisionCommit,
            Phase:    PhaseDoCommit,
            Reason:   "participant(s) already in DoCommit",
        }, nil
    }

    if abortCount > 0 {
        // Any participant aborted - entire transaction aborts
        return &TransactionState{
            TxID:     txID,
            Decision: DecisionAbort,
            Phase:    PhaseAbort,
            Reason:   "participant(s) already aborted",
        }, nil
    }

    if preCommitCount >= quorum {
        // Quorum in PreCommit and no aborts - safe to commit
        return &TransactionState{
            TxID:     txID,
            Decision: DecisionCommit,
            Phase:    PhasePreCommit,
            Reason:   "quorum in PreCommit, no aborts",
        }, nil
    }

    // Default: abort for safety
    return &TransactionState{
        TxID:     txID,
        Decision: DecisionAbort,
        Phase:    PhaseAbort,
        Reason:   "no clear commit quorum - safe abort",
    }, nil
}
```

**Resume or Abort Decision:**

Once the new coordinator reconstructs the state, it resumes or aborts the transaction:

```go
func (nc *NewCoordinator) resumeTransaction(txID TxID) error {
    state, err := nc.reconstructTransactionState(txID)
    if err != nil {
        return fmt.Errorf("failed to reconstruct state: %w", err)
    }

    c.logger.Info("transaction state reconstructed",
        "tx_id", txID,
        "decision", state.Decision,
        "phase", state.Phase,
        "reason", state.Reason)

    switch state.Decision {
    case DecisionCommit:
        // Send DoCommit to all participants
        return nc.sendDoCommitToAll(txID)

    case DecisionAbort:
        // Send Abort to all participants
        return nc.sendAbortToAll(txID)

    default:
        return fmt.Errorf("unknown decision: %v", state.Decision)
    }
}

func (nc *NewCoordinator) sendDoCommitToAll(txID TxID) error {
    participants := nc.getTransactionParticipants(txID)

    errors := make([]error, 0)
    for _, p := range participants {
        if err := nc.sendDoCommit(p, txID); err != nil {
            c.logger.Error("failed to send DoCommit to participant",
                "participant", p,
                "error", err)
            errors = append(errors, err)
        }
    }

    if len(errors) > 0 {
        // Log errors but don't fail - participants will complete from PreCommit log
        c.logger.Warn("some DoCommit messages failed, participants will recover from WAL",
            "tx_id", txID,
            "error_count", len(errors))
    }

    return nil
}
```

**Lock Extension During Election:**

During coordinator election, locks must be extended to prevent expiration:

```go
func (p *Participant) extendLocksDuringElection(txID TxID) error {
    // Automatically extend locks while waiting for new coordinator
    // Use RecoveryLockTTL for extended timeout

    currentLock := p.getLock(txID)
    if currentLock == nil {
        return ErrLockNotFound
    }

    // Extend to RecoveryLockTTL (5 minutes) during coordinator election
    newExpiry := time.Now().Add(RecoveryLockTTL)

    if err := p.extendLock(txID, newExpiry); err != nil {
        return fmt.Errorf("failed to extend lock during election: %w", err)
    }

    c.logger.Info("lock extended during coordinator election",
        "tx_id", txID,
        "new_expiry", newExpiry,
        "ttl", RecoveryLockTTL)

    return nil
}
```

**Summary of Coordinator Election Recovery:**

1. **Detection**: Participant detects coordinator failure via heartbeat timeout (15s max)
2. **Election**: VRF-based election among shard coordinators (10s timeout)
3. **State Reconstruction**: New coordinator queries all participants (within 30s total)
4. **Decision**: Resume commit or abort based on collected state
5. **Lock Protection**: Locks extended to RecoveryLockTTL (5 minutes) during election
6. **Completion**: Transaction completes or aborts safely

This comprehensive failure recovery design ensures that cross-shard transactions maintain atomicity and consistency even in the presence of participant crashes, network partitions, and coordinator failures.

### Write-Ahead Log (WAL) for DoCommit Idempotency

DoCommit consists of multiple atomic operations. Failure between steps creates inconsistent state. The Write-Ahead Log (WAL) ensures idempotency and crash recovery.

#### WAL Entry Structure

```go
// WALEntry represents a single transaction commit operation
type WALEntry struct {
    TxID        TxID           // Transaction identifier
    Phase       Phase          // CanCommit, PreCommit, DoCommit
    Operations  []WALOp        // Ordered list of operations
    Committed   bool           // True when all operations completed
    Timestamp   time.Time      // Entry creation time
    Checksum    [32]byte       // SHA256(TxID || Phase || Operations)
}

// WALOp represents a single atomic operation within a transaction
type WALOp struct {
    Type        OpType         // DEBIT, CREDIT, MARK_SPENT, RELEASE_LOCK
    Target      []byte         // UTXO ID or Wallet ID
    Amount      uint64         // Amount for DEBIT/CREDIT operations
    Applied     bool           // True when operation has been applied
    AppliedAt   time.Time      // When operation was applied
}

// OpType defines the types of WAL operations
type OpType uint8
const (
    OpDebit       OpType = iota  // Debit funds from wallet
    OpCredit                      // Credit funds to wallet
    OpMarkSpent                   // Mark UTXO as spent
    OpReleaseLock                 // Release transaction lock
    OpCreateUTXO                  // Create new UTXO
)
```

#### WAL Commit Protocol

```go
// DoCommit with WAL protection
func (s *Shard) DoCommitWithWAL(ctx context.Context, tx *Transaction) error {
    // Step 1: Write WAL entry BEFORE any state changes
    walEntry := &WALEntry{
        TxID:      tx.ID,
        Phase:     PhaseDoCommit,
        Timestamp: time.Now(),
        Operations: []WALOp{
            {Type: OpMarkSpent, Target: tx.InputUTXOs},
            {Type: OpDebit, Target: tx.Sender[:], Amount: tx.Amount + tx.Fee},
            {Type: OpCreateUTXO, Target: tx.OutputUTXO},
            {Type: OpCredit, Target: tx.Receiver[:], Amount: tx.Amount},
            {Type: OpReleaseLock, Target: tx.ID[:]},
        },
    }
    walEntry.Checksum = walEntry.computeChecksum()

    if err := s.wal.Append(walEntry); err != nil {
        return fmt.Errorf("WAL append failed: %w", err)
    }
    if err := s.wal.Sync(); err != nil {  // fsync to disk
        return fmt.Errorf("WAL sync failed: %w", err)
    }

    // Step 2: Apply operations in order
    for i := range walEntry.Operations {
        op := &walEntry.Operations[i]
        if err := s.applyOperation(ctx, op); err != nil {
            // Operation failed - WAL ensures retry on recovery
            return fmt.Errorf("operation %d failed: %w", i, err)
        }
        op.Applied = true
        op.AppliedAt = time.Now()
    }

    // Step 3: Mark WAL entry as committed
    walEntry.Committed = true
    if err := s.wal.Update(walEntry); err != nil {
        // Entry committed but not marked - recovery will detect
        return fmt.Errorf("WAL update failed: %w", err)
    }

    // Step 4: Optionally truncate old WAL entries
    s.wal.TruncateOlderThan(time.Now().Add(-24 * time.Hour))

    return nil
}
```

#### Sequence Number Rollback on Commit Failure

**CRITICAL SECURITY**: Sequence numbers claimed during validation must be rolled back
if commit fails. Without this, an attacker can create sequence gaps that:
1. Cause legitimate transactions to fail (wrong sequence)
2. Enable replay attacks with the "missing" sequence

```go
// SequenceRollbackManager handles atomic sequence number management
// across validation and commit phases
type SequenceRollbackManager struct {
    // pendingSequences tracks sequences claimed but not yet committed
    // Key: WalletID, Value: map[Sequence]TxID
    pendingSequences sync.Map

    // Metrics for monitoring sequence health
    metrics *SequenceMetrics
}

type PendingSequence struct {
    TxID       TxID
    Sequence   uint64
    ClaimedAt  time.Time
    WalletID   WalletID
}

type SequenceMetrics struct {
    SequencesClaimed   uint64  // atomic
    SequencesCommitted uint64  // atomic
    SequencesRolledBack uint64 // atomic
    GapAttempts        uint64  // atomic: attempted gap exploits
}

// Error types for sequence management
var (
    ErrSequenceRollbackFailed = errors.New("sequence rollback failed")
    ErrSequenceGapDetected    = errors.New("sequence gap detected")
    ErrSequenceAlreadyPending = errors.New("sequence already pending")
)

// ClaimSequence atomically claims a sequence number and tracks it as pending
func (srm *SequenceRollbackManager) ClaimSequence(
    authority *ShardAuthority,
    tx *Transaction,
) error {
    expectedSeq := atomic.LoadUint64(&authority.Sequence) + 1
    if tx.Sequence != expectedSeq {
        return ErrInvalidSequence
    }

    // Check for gap attacks: ensure no pending sequence with lower number
    if srm.hasPendingSequenceBelow(tx.From, tx.Sequence) {
        atomic.AddUint64(&srm.metrics.GapAttempts, 1)
        return ErrSequenceGapDetected
    }

    // Atomically claim the sequence
    if !atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq-1, expectedSeq) {
        return ErrSequenceRace
    }

    // Track as pending
    pending := &PendingSequence{
        TxID:      tx.ID,
        Sequence:  expectedSeq,
        ClaimedAt: time.Now(),
        WalletID:  tx.From,
    }

    key := srm.makeKey(tx.From, expectedSeq)
    if _, loaded := srm.pendingSequences.LoadOrStore(key, pending); loaded {
        // Race condition: another tx claimed same sequence
        // Roll back our claim
        atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq, expectedSeq-1)
        return ErrSequenceAlreadyPending
    }

    atomic.AddUint64(&srm.metrics.SequencesClaimed, 1)
    return nil
}

// CommitSequence marks a pending sequence as committed (removes from pending)
func (srm *SequenceRollbackManager) CommitSequence(walletID WalletID, sequence uint64) {
    key := srm.makeKey(walletID, sequence)
    srm.pendingSequences.Delete(key)
    atomic.AddUint64(&srm.metrics.SequencesCommitted, 1)
}

// RollbackSequence atomically rolls back a claimed sequence on commit failure
// SECURITY FIX (P5-H5): Enforces LIFO ordering - can only roll back highest pending sequence
func (srm *SequenceRollbackManager) RollbackSequence(
    authority *ShardAuthority,
    walletID WalletID,
    sequence uint64,
) error {
    key := srm.makeKey(walletID, sequence)

    // Remove from pending
    val, ok := srm.pendingSequences.LoadAndDelete(key)
    if !ok {
        // Not pending - may have been committed or already rolled back
        return nil
    }

    pending := val.(*PendingSequence)

    // SECURITY FIX (P5-H5): Enforce LIFO ordering via explicit sequence queue
    // Cannot roll back sequence N if sequence N+1 or higher is still pending
    highestPending := srm.findHighestPendingSequence(walletID)
    if highestPending > pending.Sequence {
        // Restore the pending entry - we can't roll back yet
        srm.pendingSequences.Store(key, pending)
        return ErrSequenceRollbackOrderViolation{
            Attempted:       pending.Sequence,
            HighestPending:  highestPending,
            WalletID:        walletID,
        }
    }

    // CRITICAL: Only roll back if this sequence is still the current one
    // If another transaction has advanced past this sequence, we cannot roll back
    currentSeq := atomic.LoadUint64(&authority.Sequence)
    if currentSeq != pending.Sequence {
        // Sequence has advanced - rollback not possible
        // This is a serious error: we have a gap
        return fmt.Errorf("%w: current=%d, rolling_back=%d",
            ErrSequenceRollbackFailed, currentSeq, pending.Sequence)
    }

    // Atomically roll back
    if !atomic.CompareAndSwapUint64(&authority.Sequence, pending.Sequence, pending.Sequence-1) {
        return ErrSequenceRollbackFailed
    }

    atomic.AddUint64(&srm.metrics.SequencesRolledBack, 1)
    return nil
}

// SECURITY FIX (P5-H5): Helper to find highest pending sequence for a wallet
func (srm *SequenceRollbackManager) findHighestPendingSequence(walletID WalletID) uint64 {
    var highest uint64 = 0
    srm.pendingSequences.Range(func(key, value interface{}) bool {
        pending := value.(*PendingSequence)
        if pending.WalletID == walletID && pending.Sequence > highest {
            highest = pending.Sequence
        }
        return true
    })
    return highest
}

// ErrSequenceRollbackOrderViolation indicates LIFO ordering was violated
type ErrSequenceRollbackOrderViolation struct {
    Attempted      uint64
    HighestPending uint64
    WalletID       WalletID
}

func (e ErrSequenceRollbackOrderViolation) Error() string {
    return fmt.Sprintf("cannot rollback sequence %d: higher sequence %d still pending for wallet %x",
        e.Attempted, e.HighestPending, e.WalletID[:8])
}

// hasPendingSequenceBelow checks if there's a pending sequence with lower number
// This detects gap attacks where an attacker tries to skip sequences
func (srm *SequenceRollbackManager) hasPendingSequenceBelow(walletID WalletID, sequence uint64) bool {
    found := false
    srm.pendingSequences.Range(func(key, value interface{}) bool {
        pending := value.(*PendingSequence)
        if pending.WalletID == walletID && pending.Sequence < sequence {
            found = true
            return false // stop iteration
        }
        return true
    })
    return found
}

// CleanupStalePending removes pending sequences older than timeout
// Called periodically to handle abandoned transactions
func (srm *SequenceRollbackManager) CleanupStalePending(
    shards map[uint16]*Shard,
    timeout time.Duration,
) {
    cutoff := time.Now().Add(-timeout)

    srm.pendingSequences.Range(func(key, value interface{}) bool {
        pending := value.(*PendingSequence)
        if pending.ClaimedAt.Before(cutoff) {
            // Stale pending sequence - attempt rollback
            shardID := GetAuthoritativeShard(pending.WalletID)
            if shard, ok := shards[shardID]; ok {
                authority := shard.GetShardAuthority(pending.WalletID)
                srm.RollbackSequence(authority, pending.WalletID, pending.Sequence)
            }
        }
        return true
    })
}

func (srm *SequenceRollbackManager) makeKey(walletID WalletID, seq uint64) string {
    return fmt.Sprintf("%x:%d", walletID[:], seq)
}
```

#### Updated DoCommitWithWAL with Sequence Rollback

```go
// DoCommitWithWALAndSequence extends DoCommitWithWAL with proper sequence management
func (s *Shard) DoCommitWithWALAndSequence(
    ctx context.Context,
    tx *Transaction,
    seqManager *SequenceRollbackManager,
) error {
    // Include sequence in WAL for recovery
    walEntry := &WALEntry{
        TxID:      tx.ID,
        Phase:     PhaseDoCommit,
        Timestamp: time.Now(),
        Sequence:  tx.Sequence,  // CRITICAL: Track sequence for recovery
        WalletID:  tx.From,      // CRITICAL: Track wallet for recovery
        Operations: []WALOp{
            {Type: OpMarkSpent, Target: tx.InputUTXOs},
            {Type: OpDebit, Target: tx.Sender[:], Amount: tx.Amount + tx.Fee},
            {Type: OpCreateUTXO, Target: tx.OutputUTXO},
            {Type: OpCredit, Target: tx.Receiver[:], Amount: tx.Amount},
            {Type: OpReleaseLock, Target: tx.ID[:]},
            {Type: OpCommitSequence, Target: tx.From[:], Sequence: tx.Sequence},
        },
    }
    walEntry.Checksum = walEntry.computeChecksum()

    if err := s.wal.Append(walEntry); err != nil {
        // WAL failed - roll back sequence
        authority := s.GetShardAuthority(tx.From)
        if rbErr := seqManager.RollbackSequence(authority, tx.From, tx.Sequence); rbErr != nil {
            // Double failure - log for manual intervention
            s.log.Error("WAL and sequence rollback both failed",
                "txid", tx.ID, "sequence", tx.Sequence, "err", rbErr)
        }
        return fmt.Errorf("WAL append failed: %w", err)
    }

    if err := s.wal.Sync(); err != nil {
        // WAL sync failed - roll back sequence
        authority := s.GetShardAuthority(tx.From)
        if rbErr := seqManager.RollbackSequence(authority, tx.From, tx.Sequence); rbErr != nil {
            s.log.Error("WAL sync and sequence rollback both failed",
                "txid", tx.ID, "sequence", tx.Sequence, "err", rbErr)
        }
        return fmt.Errorf("WAL sync failed: %w", err)
    }

    // Apply operations
    for i := range walEntry.Operations {
        op := &walEntry.Operations[i]
        if err := s.applyOperation(ctx, op); err != nil {
            // Operation failed - WAL ensures retry, but sequence is now committed
            // Do NOT roll back sequence here - WAL recovery will handle
            return fmt.Errorf("operation %d failed: %w", i, err)
        }
        op.Applied = true
        op.AppliedAt = time.Now()
    }

    // Mark committed - this also commits the sequence
    walEntry.Committed = true
    if err := s.wal.Update(walEntry); err != nil {
        return fmt.Errorf("WAL update failed: %w", err)
    }

    // Clear pending sequence tracking
    seqManager.CommitSequence(tx.From, tx.Sequence)

    s.wal.TruncateOlderThan(time.Now().Add(-24 * time.Hour))
    return nil
}
```

#### Sequence Recovery from WAL

```go
// RecoverSequencesFromWAL ensures sequence consistency after crash
func (s *Shard) RecoverSequencesFromWAL(
    ctx context.Context,
    seqManager *SequenceRollbackManager,
) error {
    entries, err := s.wal.ReadAll() // Read all, not just uncommitted
    if err != nil {
        return fmt.Errorf("WAL read failed: %w", err)
    }

    // Build set of committed sequences per wallet
    committedSeqs := make(map[WalletID]uint64)
    for _, entry := range entries {
        if entry.Committed && entry.Sequence > 0 {
            if existing, ok := committedSeqs[entry.WalletID]; !ok || entry.Sequence > existing {
                committedSeqs[entry.WalletID] = entry.Sequence
            }
        }
    }

    // Reconcile authority sequence numbers with WAL
    for walletID, maxCommittedSeq := range committedSeqs {
        authority := s.GetShardAuthority(walletID)
        currentSeq := atomic.LoadUint64(&authority.Sequence)

        if maxCommittedSeq > currentSeq {
            // WAL shows higher sequence than state - update state
            atomic.StoreUint64(&authority.Sequence, maxCommittedSeq)
            s.log.Info("sequence recovered from WAL",
                "wallet", walletID, "old", currentSeq, "new", maxCommittedSeq)
        } else if maxCommittedSeq < currentSeq {
            // State shows higher sequence than WAL - potential uncommitted tx
            // Roll back to WAL's committed state
            atomic.StoreUint64(&authority.Sequence, maxCommittedSeq)
            s.log.Warn("sequence rolled back during recovery",
                "wallet", walletID, "was", currentSeq, "now", maxCommittedSeq)
        }
    }

    // Handle uncommitted WAL entries
    uncommitted, err := s.wal.ReadUncommitted()
    if err != nil {
        return fmt.Errorf("WAL uncommitted read failed: %w", err)
    }

    for _, entry := range uncommitted {
        // Uncommitted entry - determine if we should complete or abort
        if s.canCompleteTransaction(entry) {
            // Complete the transaction
            if err := s.completeUncommittedTransaction(ctx, entry); err != nil {
                s.log.Error("failed to complete uncommitted tx", "txid", entry.TxID, "err", err)
                // Abort and roll back sequence
                authority := s.GetShardAuthority(entry.WalletID)
                if currentSeq := atomic.LoadUint64(&authority.Sequence); currentSeq == entry.Sequence {
                    atomic.AddUint64(&authority.Sequence, ^uint64(0)) // Decrement
                }
            }
        } else {
            // Cannot complete - abort and roll back sequence
            s.log.Warn("aborting uncommitted transaction", "txid", entry.TxID)
            authority := s.GetShardAuthority(entry.WalletID)
            if currentSeq := atomic.LoadUint64(&authority.Sequence); currentSeq == entry.Sequence {
                atomic.AddUint64(&authority.Sequence, ^uint64(0)) // Decrement
            }
        }
    }

    return nil
}

// canCompleteTransaction checks if an uncommitted transaction can be completed
func (s *Shard) canCompleteTransaction(entry *WALEntry) bool {
    // Check if all prerequisites are still valid:
    // 1. UTXOs are still available
    // 2. Balance is still sufficient
    // 3. Transaction hasn't expired

    if time.Since(entry.Timestamp) > TransactionTTL {
        return false // Expired
    }

    // Additional validation would go here
    return true
}
```

#### Recovery from WAL

```go
// RecoverFromWAL replays uncommitted entries on startup
func (s *Shard) RecoverFromWAL(ctx context.Context) error {
    entries, err := s.wal.ReadUncommitted()
    if err != nil {
        return fmt.Errorf("WAL read failed: %w", err)
    }

    for _, entry := range entries {
        // Verify checksum integrity
        if entry.Checksum != entry.computeChecksum() {
            s.log.Warn("corrupt WAL entry", "txid", entry.TxID)
            continue
        }

        // Replay unapplied operations (idempotent)
        for i := range entry.Operations {
            op := &entry.Operations[i]
            if op.Applied {
                continue  // Already applied before crash
            }

            // Idempotent: applyOperation checks if already applied
            if err := s.applyOperationIdempotent(ctx, op); err != nil {
                return fmt.Errorf("recovery op %d failed: %w", i, err)
            }
            op.Applied = true
        }

        // Mark as committed
        entry.Committed = true
        s.wal.Update(entry)
    }

    return nil
}

// applyOperationIdempotent applies operation only if not already applied
func (s *Shard) applyOperationIdempotent(ctx context.Context, op *WALOp) error {
    switch op.Type {
    case OpMarkSpent:
        utxo, err := s.utxoStore.Get(op.Target)
        if err != nil {
            return err
        }
        if utxo.Spent {
            return nil  // Already spent - idempotent
        }
        return s.utxoStore.MarkSpent(op.Target)

    case OpCreateUTXO:
        if s.utxoStore.Exists(op.Target) {
            return nil  // Already exists - idempotent
        }
        return s.utxoStore.Create(op.Target, op.Amount)

    case OpReleaseLock:
        if !s.lockStore.IsLocked(op.Target) {
            return nil  // Already released - idempotent
        }
        return s.lockStore.Release(op.Target)

    default:
        return fmt.Errorf("unknown operation type: %d", op.Type)
    }
}
```

#### WAL Properties

| Property | Guarantee | Implementation |
|----------|-----------|----------------|
| **Durability** | WAL survives crashes | fsync after append |
| **Atomicity** | All-or-nothing commit | Recovery replays partial |
| **Idempotency** | Safe to replay | UUID tracking + state check |
| **Ordering** | Operations in order | Sequential replay |
| **Truncation** | Bounded storage | Remove committed entries >24h |

### WAL Idempotency with UUID Tracking (P4-H12)

State-based idempotency alone is insufficient. If an operation fails after modifying state but before marking as applied, replaying it could corrupt state. Every WAL operation must have a UUID tracked in a persistent Applied set.

```go
// pkg/currency/wal_idempotency.go

// WAL Idempotency - non-configurable security parameters
const (
    AppliedSetRetentionPeriod = 72 * time.Hour  // Keep UUIDs for 72 hours
    AppliedSetCleanupInterval = 1 * time.Hour   // Cleanup old entries hourly
    AppliedSetMaxSize         = 10_000_000      // 10M entries max
)

// WALOp with UUID for idempotency (updated structure)
type WALOpWithUUID struct {
    UUID        [16]byte       // Unique operation identifier (UUIDv7 for ordering)
    Type        OpType         // DEBIT, CREDIT, MARK_SPENT, RELEASE_LOCK
    Target      []byte         // UTXO ID or Wallet ID
    Amount      uint64         // Amount for DEBIT/CREDIT operations
    TxID        TxID           // Parent transaction ID
    Sequence    uint32         // Operation sequence within transaction
    Timestamp   time.Time      // Operation creation time
}

// AppliedOperationsSet tracks which operations have been executed
// CRITICAL: Must survive crashes - stored in PebbleDB
type AppliedOperationsSet struct {
    db           *pebble.DB
    prefix       []byte
    mu           sync.RWMutex

    // In-memory cache for fast lookups (rebuilds on startup)
    cache        map[[16]byte]time.Time
    cacheMaxSize int
}

// NewAppliedOperationsSet creates a new applied set with persistence
func NewAppliedOperationsSet(db *pebble.DB, shardID uint16) *AppliedOperationsSet {
    return &AppliedOperationsSet{
        db:           db,
        prefix:       []byte(fmt.Sprintf("applied:%d:", shardID)),
        cache:        make(map[[16]byte]time.Time),
        cacheMaxSize: 1_000_000,  // 1M entries in memory
    }
}

// IsApplied checks if an operation has already been executed
// Fast path: check in-memory cache
// Slow path: check persistent storage
func (aos *AppliedOperationsSet) IsApplied(uuid [16]byte) bool {
    // Fast path: in-memory cache
    aos.mu.RLock()
    _, exists := aos.cache[uuid]
    aos.mu.RUnlock()
    if exists {
        return true
    }

    // Slow path: check persistent storage
    key := append(aos.prefix, uuid[:]...)
    _, closer, err := aos.db.Get(key)
    if err == nil {
        closer.Close()
        // Add to cache for future lookups
        aos.addToCache(uuid)
        return true
    }

    return false
}

// MarkApplied records an operation as successfully executed
// MUST be called BEFORE the actual state modification completes
func (aos *AppliedOperationsSet) MarkApplied(uuid [16]byte) error {
    key := append(aos.prefix, uuid[:]...)
    value := make([]byte, 8)
    binary.BigEndian.PutUint64(value, uint64(time.Now().UnixNano()))

    // Sync write - MUST be durable before continuing
    writeOpts := pebble.WriteOptions{Sync: true}
    if err := aos.db.Set(key, value, &writeOpts); err != nil {
        return fmt.Errorf("mark applied failed: %w", err)
    }

    // Update cache
    aos.addToCache(uuid)

    return nil
}

// addToCache adds UUID to in-memory cache with LRU eviction
func (aos *AppliedOperationsSet) addToCache(uuid [16]byte) {
    aos.mu.Lock()
    defer aos.mu.Unlock()

    if len(aos.cache) >= aos.cacheMaxSize {
        // Evict oldest 10% of cache
        aos.evictOldest(aos.cacheMaxSize / 10)
    }

    aos.cache[uuid] = time.Now()
}

// evictOldest removes the oldest n entries from cache
func (aos *AppliedOperationsSet) evictOldest(n int) {
    // Simple eviction - in production, use proper LRU
    count := 0
    for uuid := range aos.cache {
        if count >= n {
            break
        }
        delete(aos.cache, uuid)
        count++
    }
}

// CleanupExpired removes UUIDs older than retention period
func (aos *AppliedOperationsSet) CleanupExpired() error {
    cutoff := time.Now().Add(-AppliedSetRetentionPeriod).UnixNano()

    iter := aos.db.NewIter(&pebble.IterOptions{
        LowerBound: aos.prefix,
        UpperBound: incrementPrefix(aos.prefix),
    })
    defer iter.Close()

    batch := aos.db.NewBatch()
    defer batch.Close()

    deletedCount := 0
    for iter.First(); iter.Valid(); iter.Next() {
        if len(iter.Value()) < 8 {
            continue
        }
        timestamp := int64(binary.BigEndian.Uint64(iter.Value()))
        if timestamp < cutoff {
            batch.Delete(iter.Key(), nil)
            deletedCount++
        }
    }

    if deletedCount > 0 {
        if err := batch.Commit(pebble.NoSync); err != nil {
            return fmt.Errorf("cleanup commit failed: %w", err)
        }
        log.Info("cleaned up expired applied operations",
            "deleted_count", deletedCount)
    }

    return nil
}

// RebuildCache populates in-memory cache from persistent storage on startup
func (aos *AppliedOperationsSet) RebuildCache() error {
    aos.mu.Lock()
    defer aos.mu.Unlock()

    iter := aos.db.NewIter(&pebble.IterOptions{
        LowerBound: aos.prefix,
        UpperBound: incrementPrefix(aos.prefix),
    })
    defer iter.Close()

    // Only cache recent entries (last 1 hour)
    recentCutoff := time.Now().Add(-1 * time.Hour).UnixNano()

    for iter.First(); iter.Valid(); iter.Next() {
        if len(aos.cache) >= aos.cacheMaxSize {
            break  // Cache full
        }

        if len(iter.Value()) < 8 {
            continue
        }
        timestamp := int64(binary.BigEndian.Uint64(iter.Value()))
        if timestamp > recentCutoff {
            var uuid [16]byte
            copy(uuid[:], iter.Key()[len(aos.prefix):])
            aos.cache[uuid] = time.Unix(0, timestamp)
        }
    }

    log.Info("rebuilt applied operations cache",
        "cache_size", len(aos.cache))

    return nil
}

// applyOperationWithIdempotency applies operation only if not already executed
func (s *Shard) applyOperationWithIdempotency(ctx context.Context, op *WALOpWithUUID) error {
    // Step 1: Check if already applied (fast path)
    if s.appliedSet.IsApplied(op.UUID) {
        log.Debug("skipping already-applied operation",
            "uuid", op.UUID,
            "tx_id", op.TxID,
            "type", op.Type)
        return nil  // Idempotent - already executed
    }

    // Step 2: Mark as applied BEFORE execution
    // This ensures that if we crash mid-operation, we won't retry
    if err := s.appliedSet.MarkApplied(op.UUID); err != nil {
        return fmt.Errorf("mark applied failed: %w", err)
    }

    // Step 3: Execute the operation
    switch op.Type {
    case OpMarkSpent:
        return s.utxoStore.MarkSpent(op.Target)

    case OpCreateUTXO:
        return s.utxoStore.Create(op.Target, op.Amount)

    case OpReleaseLock:
        return s.lockStore.Release(op.Target)

    case OpDebit:
        return s.walletStore.Debit(op.Target, op.Amount)

    case OpCredit:
        return s.walletStore.Credit(op.Target, op.Amount)

    default:
        return fmt.Errorf("unknown operation type: %d", op.Type)
    }
}

// RecoverFromWALWithIdempotency replays WAL with UUID-based idempotency
func (s *Shard) RecoverFromWALWithIdempotency(ctx context.Context) error {
    // Step 1: Rebuild applied set cache
    if err := s.appliedSet.RebuildCache(); err != nil {
        return fmt.Errorf("rebuild cache failed: %w", err)
    }

    // Step 2: Read uncommitted WAL entries
    entries, err := s.wal.ReadUncommitted()
    if err != nil {
        return fmt.Errorf("WAL read failed: %w", err)
    }

    // Step 3: Replay each entry
    for _, entry := range entries {
        // Verify checksum integrity
        if entry.Checksum != entry.computeChecksum() {
            s.log.Warn("corrupt WAL entry skipped",
                "txid", entry.TxID)
            continue
        }

        // Replay operations with idempotency
        for i := range entry.Operations {
            op := &entry.Operations[i]
            if err := s.applyOperationWithIdempotency(ctx, op); err != nil {
                return fmt.Errorf("recovery op %d failed: %w", i, err)
            }
        }

        // Mark entry as committed
        entry.Committed = true
        s.wal.Update(entry)
    }

    log.Info("WAL recovery completed",
        "recovered_entries", len(entries))

    return nil
}

// GenerateOperationUUID creates a UUIDv7 for a WAL operation
func GenerateOperationUUID(txID TxID, sequence uint32) [16]byte {
    var uuid [16]byte

    // UUIDv7 format: timestamp (48 bits) + version (4) + random (12) + variant (2) + random (62)
    // For determinism, use TxID + sequence instead of random
    timestamp := time.Now().UnixMilli()
    binary.BigEndian.PutUint64(uuid[0:8], uint64(timestamp)<<16)

    // Include TxID hash for uniqueness
    h := sha256.Sum256(append(txID[:], byte(sequence)))
    copy(uuid[6:16], h[0:10])

    // Set version (7) and variant bits
    uuid[6] = (uuid[6] & 0x0F) | 0x70  // Version 7
    uuid[8] = (uuid[8] & 0x3F) | 0x80  // Variant 10

    return uuid
}
```

**Idempotency Flow**:

```
Step 1: Generate UUID for operation
        uuid = GenerateOperationUUID(txID, sequence)

Step 2: Check if UUID in AppliedSet
        IF IsApplied(uuid) THEN skip (already done)

Step 3: Mark UUID as applied (SYNC write)
        MarkApplied(uuid) → PebbleDB fsync

Step 4: Execute operation
        applyOperation(op)
        ↓
   [CRASH HERE IS SAFE - UUID already marked]
        ↓

Step 5: Mark WAL entry as committed
        entry.Committed = true
```

**Crash Recovery With UUID Tracking**:

| Crash Point | Applied Set State | WAL State | Recovery Action |
|-------------|-------------------|-----------|-----------------|
| Before MarkApplied | UUID not in set | Op not committed | Execute operation |
| After MarkApplied, before op | UUID in set | Op not committed | Skip operation |
| After op, before WAL commit | UUID in set | Entry uncommitted | Mark entry committed |
| After WAL commit | UUID in set | Entry committed | No action |

#### Failure Scenarios with WAL

| Failure Point | State | Recovery Action |
|---------------|-------|-----------------|
| Before WAL append | None | Transaction never started |
| After WAL, before ops | WAL entry | Replay all operations |
| Mid-operations | Partial | Replay unapplied ops |
| After ops, before commit | Complete | Mark committed |
| After commit mark | Complete | No action needed |

### Dynamic Fee Calculation

```
cross_shard_fee = base_fee * (1 + queue_depth / 100)

Bounds:
  Floor: 1.0x base_fee
  Cap: 5.0x base_fee
```

| Queue Depth | Multiplier | Final Fee (base=100) |
|-------------|-----------|----------------------|
| 0 | 1.00x | 100 |
| 50 | 1.50x | 150 |
| 100 | 2.00x | 200 |
| 200 | 3.00x | 300 |
| 400+ | 5.00x (capped) | 500 |

#### Fee Distribution

| Recipient | Share | Justification |
|-----------|-------|---------------|
| Coordinator Committee | 40% | Orchestration overhead |
| Source Shard | 30% | Lock management, validation |
| Destination Shard | 30% | State update, UTXO creation |

### 3PC Coordinator Slashing

Cross-shard coordinators are subject to timeout-based slashing with automatic replacement via consensus to ensure transaction progress.

#### Coordinator Heartbeat During 3PC (CANONICAL)

During active 3PC transactions, coordinators MUST send heartbeats to all participant shards. Heartbeat failure triggers coordinator death detection and activates the termination protocol.

**Heartbeat Configuration**:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Heartbeat Interval | 5 seconds | Time between heartbeats |
| Death Timeout | 15 seconds | 3 missed heartbeats = coordinator death |
| Grace Period | 2 seconds | Network latency allowance |

**Heartbeat Message Structure**:

```go
// CoordinatorHeartbeat sent during active 3PC transactions
type CoordinatorHeartbeat struct {
    TxID          TxID      // Transaction this heartbeat relates to
    CoordinatorID NodeID    // Coordinator sending heartbeat
    Sequence      uint64    // Monotonic heartbeat sequence (detects reordering)
    Phase         Phase     // Current 3PC phase (CanCommit, PreCommit, DoCommit)
    Timestamp     time.Time // Heartbeat generation time
    TPMQuote      []byte    // TPM attestation of heartbeat
    Signature     []byte    // Signature over heartbeat content
}

// HeartbeatTracker monitors coordinator liveness per transaction
type HeartbeatTracker struct {
    coordinatorID     NodeID
    txID              TxID
    lastHeartbeat     time.Time
    lastSequence      uint64
    lastPhase         Phase
    missedHeartbeats  int
    deathDetected     bool
    mu                sync.RWMutex
}

// UpdateHeartbeat processes incoming heartbeat from coordinator
func (ht *HeartbeatTracker) UpdateHeartbeat(hb *CoordinatorHeartbeat) error {
    ht.mu.Lock()
    defer ht.mu.Unlock()

    // Verify heartbeat is for correct transaction
    if hb.TxID != ht.txID {
        return ErrWrongTransaction{Expected: ht.txID, Received: hb.TxID}
    }

    // Verify heartbeat is from expected coordinator
    if hb.CoordinatorID != ht.coordinatorID {
        return ErrWrongCoordinator{Expected: ht.coordinatorID, Received: hb.CoordinatorID}
    }

    // Verify monotonic sequence (prevents replay)
    if hb.Sequence <= ht.lastSequence {
        return ErrStaleHeartbeat{LastSeq: ht.lastSequence, ReceivedSeq: hb.Sequence}
    }

    // Verify TPM attestation
    if err := VerifyTPMQuote(hb.TPMQuote, hb.CoordinatorID, hb.Timestamp); err != nil {
        return ErrInvalidHeartbeatAttestation{Err: err}
    }

    // Update tracker state
    ht.lastHeartbeat = hb.Timestamp
    ht.lastSequence = hb.Sequence
    ht.lastPhase = hb.Phase
    ht.missedHeartbeats = 0  // Reset on valid heartbeat

    return nil
}

// CheckHeartbeatTimeout detects coordinator death
func (ht *HeartbeatTracker) CheckHeartbeatTimeout() bool {
    ht.mu.Lock()
    defer ht.mu.Unlock()

    timeSinceLastHeartbeat := time.Since(ht.lastHeartbeat)

    if timeSinceLastHeartbeat > CoordinatorDeathTimeout {
        ht.deathDetected = true
        return true  // Coordinator presumed dead
    }

    // Track missed heartbeats
    missedCount := int(timeSinceLastHeartbeat / CoordinatorHeartbeatInterval)
    ht.missedHeartbeats = missedCount

    return false
}
```

**Heartbeat Monitoring Flow**:

```
Coordinator sends heartbeat every 5 seconds during 3PC:

0s    HB#1 ──────────────────────────► Participants receive
5s    HB#2 ──────────────────────────► Participants receive
10s   HB#3 ──────────────────────────► Participants receive
15s   [No HB#4 - Coordinator crashed]
      │
      │ 3 missed heartbeats detected
      v
┌─────────────────────────────────────────────────┐
│ COORDINATOR DEATH TIMEOUT (15s)                 │
│                                                 │
│ Participant Actions:                            │
│ 1. Mark coordinator as dead                     │
│ 2. Initiate termination protocol                │
│ 3. Query other shards for witness state         │
│ 4. Reach consensus on commit/rollback           │
└─────────────────────────────────────────────────┘
```

#### Coordinator Accountability and Slashing (CANONICAL)

Coordinators are held accountable for transaction outcomes through stake-based slashing. Misbehavior is detected via TPM-attested evidence and penalized according to severity.

**Slashing Configuration**:

| Violation | Stake Slash | Additional Penalty | Evidence Required |
|-----------|------------|-------------------|-------------------|
| Abandoned Transaction | 10% | - | TPM-attested timeout from 2+ shards |
| Double-Commit (Byzantine) | 100% | Permanent ban | Conflicting commit messages with same TxID |
| Invalid Prepare | 5% | - | Shard rejection with reason |
| Coordinator Cooldown Violation | 5% | Extended cooldown | Coordination attempt during cooldown |

**Cooldown Period**: 1 hour after failed coordination before coordinator can accept new transactions.

```go
// CoordinatorAccountabilityConfig - stake-based slashing parameters
const (
    // Slashing percentages (of coordinator stake)
    SlashAbandonedTransaction     = 0.10   // 10% for abandoned tx
    SlashDoubleCommit             = 1.00   // 100% for double-commit (Byzantine)
    SlashInvalidPrepare           = 0.05   // 5% for invalid prepare
    SlashCooldownViolation        = 0.05   // 5% for violating cooldown

    // Cooldown after failed coordination
    CoordinatorCooldownDuration   = 1 * time.Hour

    // Permanent ban threshold
    PermanentBanViolation         = ViolationDoubleCommit
)

// ViolationType categorizes coordinator misbehavior
type ViolationType uint8

const (
    ViolationTimeout           ViolationType = iota  // Missed heartbeats
    ViolationAbandonedTx                              // Abandoned mid-3PC
    ViolationDoubleCommit                             // Byzantine double-commit
    ViolationInvalidPrepare                           // Sent invalid prepare
    ViolationCooldownViolation                        // Coordinated during cooldown
)

// SlashingEvidence provides TPM-attested proof of coordinator misbehavior
type SlashingEvidence struct {
    ViolationType    ViolationType
    CoordinatorID    NodeID
    TxID             TxID
    Timestamp        time.Time
    Description      string

    // Evidence specifics
    WitnessShards    []uint16              // Shards that witnessed violation
    TimeoutEvidence  *TimeoutEvidence      // For timeout violations
    ConflictEvidence *ConflictEvidence     // For double-commit
    RejectEvidence   *RejectEvidence       // For invalid prepare

    // TPM attestation of evidence validity
    TPMQuotes        map[uint16][]byte     // TPM quotes from witness shards
    Signatures       map[uint16][]byte     // Signatures from witness shards
}

// ConflictEvidence proves double-commit attempt
type ConflictEvidence struct {
    TxID           TxID
    CommitMessage1 *DoCommitMessage  // First commit message
    CommitMessage2 *DoCommitMessage  // Conflicting commit message
    // Both messages signed by same coordinator for same TxID
    // but with different outcomes/destinations
}

// ProcessSlashing evaluates evidence and applies penalties
func (sm *SlashingManager) ProcessSlashing(evidence *SlashingEvidence) (*SlashingResult, error) {
    // Step 1: Verify evidence authenticity
    if err := sm.verifySlashingEvidence(evidence); err != nil {
        return nil, ErrInvalidSlashingEvidence{Err: err}
    }

    // Step 2: Verify required witness count (2+ shards for most violations)
    minWitnesses := 2
    if evidence.ViolationType == ViolationDoubleCommit {
        minWitnesses = 1  // Cryptographic proof is sufficient
    }
    if len(evidence.WitnessShards) < minWitnesses {
        return nil, ErrInsufficientWitnesses{
            Required: minWitnesses,
            Provided: len(evidence.WitnessShards),
        }
    }

    // Step 3: Calculate slash amount
    slashPercentage := sm.getSlashPercentage(evidence.ViolationType)
    coordinatorStake := sm.getCoordinatorStake(evidence.CoordinatorID)
    slashAmount := uint64(float64(coordinatorStake) * slashPercentage)

    // Step 4: Apply slash
    result := &SlashingResult{
        CoordinatorID:   evidence.CoordinatorID,
        ViolationType:   evidence.ViolationType,
        SlashAmount:     slashAmount,
        SlashPercentage: slashPercentage,
        AppliedAt:       time.Now(),
    }

    if err := sm.applySlash(evidence.CoordinatorID, slashAmount); err != nil {
        return nil, ErrSlashFailed{Err: err}
    }

    // Step 5: Apply additional penalties
    switch evidence.ViolationType {
    case ViolationDoubleCommit:
        // Permanent ban for Byzantine behavior
        sm.permanentlyBan(evidence.CoordinatorID)
        result.PermanentBan = true

    case ViolationAbandonedTx, ViolationInvalidPrepare:
        // Apply cooldown
        sm.applyCooldown(evidence.CoordinatorID, CoordinatorCooldownDuration)
        result.CooldownUntil = time.Now().Add(CoordinatorCooldownDuration)
    }

    // Step 6: Distribute slashed stake
    sm.distributeSlashedStake(slashAmount, evidence.WitnessShards)

    return result, nil
}

func (sm *SlashingManager) getSlashPercentage(violation ViolationType) float64 {
    switch violation {
    case ViolationAbandonedTx:
        return SlashAbandonedTransaction
    case ViolationDoubleCommit:
        return SlashDoubleCommit
    case ViolationInvalidPrepare:
        return SlashInvalidPrepare
    case ViolationCooldownViolation:
        return SlashCooldownViolation
    default:
        return SlashPerTimeout  // Default to timeout slash
    }
}
```

**Slashing Evidence Requirements**:

| Violation | Evidence Type | Minimum Witnesses | Cryptographic Proof |
|-----------|--------------|-------------------|---------------------|
| Abandoned Transaction | TimeoutEvidence | 2 shards | TPM-attested timestamps |
| Double-Commit | ConflictEvidence | 1 shard | Conflicting signed messages |
| Invalid Prepare | RejectEvidence | 2 shards | Signed rejection messages |

**Cooldown Enforcement**:

```
Coordinator fails transaction at T=0
              |
              v
┌─────────────────────────────────────────┐
│ COOLDOWN PERIOD: 1 HOUR                 │
│                                         │
│ T=0 to T=1h:                            │
│   - Cannot accept new coordination      │
│   - Existing transactions continue      │
│   - Reputation recovery possible        │
│                                         │
│ T=1h:                                   │
│   - Cooldown ends                       │
│   - Can accept new transactions         │
│   - Must pass eligibility check         │
└─────────────────────────────────────────┘
```

#### Coordinator Performance Configuration

```go
// CoordinatorSlashingConfig - non-configurable security parameters
const (
    CoordinatorHeartbeatInterval = 5 * time.Second   // Expected heartbeat frequency
    CoordinatorTimeoutThreshold  = 15 * time.Second  // Timeout before slash (3 missed heartbeats)
    MaxConsecutiveTimeouts       = 3                 // Timeouts before removal
    SlashPerTimeout              = 0.05              // 5% reputation per timeout
    SlashForStall                = 0.20              // 20% for proven stall attack
)

// CoordinatorMonitor tracks coordinator performance
type CoordinatorMonitor struct {
    coordinatorID     NodeID
    lastHeartbeat     time.Time
    consecutiveTimeouts int
    activeTransactions map[TxID]*TransactionState
}

// MonitorCoordinator detects and penalizes misbehaving coordinators
func (m *CoordinatorMonitor) MonitorCoordinator(ctx context.Context) {
    ticker := time.NewTicker(CoordinatorHeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if time.Since(m.lastHeartbeat) > CoordinatorTimeoutThreshold {
                m.handleTimeout()
            }
        }
    }
}

func (m *CoordinatorMonitor) handleTimeout() {
    m.consecutiveTimeouts++

    // Slash reputation for timeout
    slashReputation(m.coordinatorID, -SlashPerTimeout, "coordinator_timeout")

    // Broadcast timeout evidence to network
    evidence := &TimeoutEvidence{
        CoordinatorID:      m.coordinatorID,
        LastHeartbeat:      m.lastHeartbeat,
        TimeoutAt:          time.Now(),
        ActiveTransactions: len(m.activeTransactions),
        TPMAttestation:     generateTimeoutAttestation(),
    }
    broadcastTimeoutEvidence(evidence)

    if m.consecutiveTimeouts >= MaxConsecutiveTimeouts {
        // Remove coordinator from committee
        m.removeAndReplace()
    }
}

// removeAndReplace initiates coordinator replacement via PBFT
func (m *CoordinatorMonitor) removeAndReplace() {
    // Propose coordinator removal to committee
    proposal := &CoordinatorRemovalProposal{
        TargetID:           m.coordinatorID,
        Reason:             "consecutive_timeouts",
        TimeoutCount:       m.consecutiveTimeouts,
        Evidence:           m.collectEvidence(),
        ProposedReplacement: selectReplacementCoordinator(),
    }

    // PBFT vote on removal with shard agreement (see quorum spec below)
    if approved := m.voteWithShardQuorum(proposal); approved {
        // Apply removal
        removeFromCoordinatorCommittee(m.coordinatorID)

        // Major reputation slash
        slashReputation(m.coordinatorID, -SlashForStall, "coordinator_removal")

        // Add replacement
        addToCoordinatorCommittee(proposal.ProposedReplacement)

        // Transfer pending transactions to new coordinator
        transferPendingTransactions(m.activeTransactions, proposal.ProposedReplacement)
    }
}
```

### Coordinator Replacement Quorum (P4-M14)

**CRITICAL**: Coordinator replacement MUST require agreement from shards to prevent Byzantine coordinators from orchestrating their own replacement with colluding nodes. This section specifies the quorum requirements.

#### Quorum Requirements

```go
// pkg/currency/coordinator_quorum.go

// CoordinatorReplacementQuorum specifies voting requirements
const (
    // Committee quorum: 3-of-5 committee members must agree
    CommitteeQuorum = 3

    // Shard quorum: 2/3 of affected shards must confirm timeout
    ShardQuorumFraction = 0.67

    // Minimum shard confirmation: At least 2 shards must confirm
    MinShardConfirmations = 2

    // Timeout evidence age: Max age of timeout evidence
    MaxEvidenceAge = 60 * time.Second

    // Replacement cooldown: Minimum time between replacements
    ReplacementCooldown = 5 * time.Minute
)

// CoordinatorReplacementVote represents a vote for coordinator replacement
type CoordinatorReplacementVote struct {
    ProposalID        [32]byte
    TargetCoordinator NodeID
    VoterType         VoterType         // Committee member or Shard
    VoterID           NodeID            // For committee: member ID, For shard: shard leader ID
    ShardID           uint16            // Only set if VoterType == VoterTypeShard
    Vote              bool              // true = approve replacement
    Evidence          *TimeoutEvidence  // Supporting evidence
    Timestamp         time.Time
    Signature         []byte            // TPM-backed signature
}

type VoterType uint8

const (
    VoterTypeCommittee VoterType = iota
    VoterTypeShard
)

// CoordinatorReplacementResult tracks voting progress
type CoordinatorReplacementResult struct {
    ProposalID          [32]byte
    TargetCoordinator   NodeID
    CommitteeVotes      map[NodeID]*CoordinatorReplacementVote
    ShardVotes          map[uint16]*CoordinatorReplacementVote
    AffectedShards      []uint16
    RequiredShardVotes  int
    Status              ReplacementStatus
    CreatedAt           time.Time
    CompletedAt         time.Time
}

type ReplacementStatus uint8

const (
    ReplacementPending    ReplacementStatus = iota
    ReplacementApproved
    ReplacementRejected
    ReplacementExpired
)

// voteWithShardQuorum implements the two-phase voting process
func (m *CoordinatorMonitor) voteWithShardQuorum(proposal *CoordinatorRemovalProposal) bool {
    result := &CoordinatorReplacementResult{
        ProposalID:        proposal.Hash(),
        TargetCoordinator: proposal.TargetID,
        CommitteeVotes:    make(map[NodeID]*CoordinatorReplacementVote),
        ShardVotes:        make(map[uint16]*CoordinatorReplacementVote),
        AffectedShards:    m.getAffectedShards(),
        Status:            ReplacementPending,
        CreatedAt:         time.Now(),
    }

    // Calculate required shard votes
    result.RequiredShardVotes = max(
        MinShardConfirmations,
        int(float64(len(result.AffectedShards))*ShardQuorumFraction),
    )

    // Phase 1: Collect committee votes
    committeeApproved := m.collectCommitteeVotes(proposal, result)
    if !committeeApproved {
        result.Status = ReplacementRejected
        return false
    }

    // Phase 2: Collect shard confirmations
    shardApproved := m.collectShardConfirmations(proposal, result)
    if !shardApproved {
        result.Status = ReplacementRejected
        return false
    }

    result.Status = ReplacementApproved
    result.CompletedAt = time.Now()

    // Store result for audit
    m.storeReplacementResult(result)

    return true
}

// collectCommitteeVotes gathers votes from committee members
func (m *CoordinatorMonitor) collectCommitteeVotes(
    proposal *CoordinatorRemovalProposal,
    result *CoordinatorReplacementResult,
) bool {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    votes := make(chan *CoordinatorReplacementVote, 5)
    for _, member := range m.committee.Members {
        go func(memberID NodeID) {
            vote, err := m.requestCommitteeVote(ctx, memberID, proposal)
            if err == nil {
                votes <- vote
            }
        }(member)
    }

    // Wait for quorum
    approvals := 0
    for i := 0; i < len(m.committee.Members); i++ {
        select {
        case vote := <-votes:
            result.CommitteeVotes[vote.VoterID] = vote
            if vote.Vote {
                approvals++
            }
            if approvals >= CommitteeQuorum {
                return true
            }
        case <-ctx.Done():
            return false
        }
    }

    return approvals >= CommitteeQuorum
}

// collectShardConfirmations gathers confirmations from affected shards
func (m *CoordinatorMonitor) collectShardConfirmations(
    proposal *CoordinatorRemovalProposal,
    result *CoordinatorReplacementResult,
) bool {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    votes := make(chan *CoordinatorReplacementVote, len(result.AffectedShards))
    for _, shardID := range result.AffectedShards {
        go func(sid uint16) {
            vote, err := m.requestShardConfirmation(ctx, sid, proposal)
            if err == nil {
                votes <- vote
            }
        }(shardID)
    }

    // Wait for shard quorum
    confirmations := 0
    for i := 0; i < len(result.AffectedShards); i++ {
        select {
        case vote := <-votes:
            result.ShardVotes[vote.ShardID] = vote
            if vote.Vote {
                confirmations++
            }
            if confirmations >= result.RequiredShardVotes {
                return true
            }
        case <-ctx.Done():
            return false
        }
    }

    return confirmations >= result.RequiredShardVotes
}

// getAffectedShards returns shards with pending transactions from this coordinator
func (m *CoordinatorMonitor) getAffectedShards() []uint16 {
    shardSet := make(map[uint16]bool)
    for _, txState := range m.activeTransactions {
        shardSet[txState.SourceShard] = true
        shardSet[txState.DestShard] = true
    }

    shards := make([]uint16, 0, len(shardSet))
    for shard := range shardSet {
        shards = append(shards, shard)
    }
    sort.Slice(shards, func(i, j int) bool { return shards[i] < shards[j] })
    return shards
}
```

#### Voting State Machine

```
                     ┌────────────────────────────┐
                     │    PROPOSAL CREATED        │
                     └─────────────┬──────────────┘
                                   │
                     ┌─────────────▼──────────────┐
                     │  PHASE 1: COMMITTEE VOTE   │
                     │  Require: 3-of-5 approval  │
                     └─────────────┬──────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
     < 3 approve             >= 3 approve          Timeout
              │                    │                    │
              ▼                    ▼                    ▼
       ┌──────────┐     ┌──────────────────┐     ┌──────────┐
       │ REJECTED │     │ PHASE 2: SHARDS  │     │ EXPIRED  │
       └──────────┘     │ Require: 2/3     │     └──────────┘
                        │ of affected      │
                        └────────┬─────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
     < 2/3 confirm        >= 2/3 confirm       Timeout
              │                  │                  │
              ▼                  ▼                  ▼
       ┌──────────┐     ┌──────────────┐     ┌──────────┐
       │ REJECTED │     │   APPROVED   │     │ EXPIRED  │
       └──────────┘     └──────┬───────┘     └──────────┘
                               │
                     ┌─────────▼─────────┐
                     │ EXECUTE REPLACE   │
                     │ - Remove old      │
                     │ - Add new         │
                     │ - Transfer TX     │
                     └───────────────────┘
```

#### Quorum Rationale

| Requirement | Value | Rationale |
|-------------|-------|-----------|
| Committee Quorum | 3-of-5 | Standard BFT tolerance for f=1 |
| Shard Quorum | 2/3 (67%) | Prevents minority shard from blocking |
| Min Shard Confirmations | 2 | Requires at least one cross-shard confirmation |
| Evidence Age | 60s | Prevents stale evidence replay |
| Replacement Cooldown | 5 min | Prevents replacement thrashing |

**Security Properties:**

1. **Byzantine Tolerance**: Malicious coordinator cannot replace themselves with a colluding node (requires committee + shard agreement)
2. **Liveness**: Honest majority can always replace faulty coordinator
3. **Consistency**: All honest nodes agree on replacement before execution
4. **Evidence Binding**: All votes are TPM-attested and include timeout evidence

// StallAttackDetector identifies intentional transaction stalling
type StallAttackDetector struct {
    transactions map[TxID]*TransactionTiming
}

func (d *StallAttackDetector) DetectStallPattern(coordinatorID NodeID) *StallReport {
    coordTx := d.getTransactionsForCoordinator(coordinatorID)

    // Pattern 1: Selective stalling (some TX fast, some slow)
    avgTime := d.calculateAverageTime(coordTx)
    slowTx := d.findSlowTransactions(coordTx, avgTime*3)
    if len(slowTx) > len(coordTx)/10 { // >10% slow
        return &StallReport{
            Type:        StallSelective,
            Evidence:    slowTx,
            Coordinator: coordinatorID,
        }
    }

    // Pattern 2: Competitor targeting (slow TX to specific shards)
    targetedShards := d.findTargetedShards(slowTx)
    if len(targetedShards) > 0 {
        return &StallReport{
            Type:          StallTargeted,
            TargetShards:  targetedShards,
            Evidence:      slowTx,
            Coordinator:   coordinatorID,
        }
    }

    // Pattern 3: Correlated with competitor activity
    if d.correlatesWithCompetitorActivity(slowTx) {
        return &StallReport{
            Type:        StallAntiCompetitive,
            Evidence:    slowTx,
            Coordinator: coordinatorID,
        }
    }

    return nil
}
```

**Slashing Matrix**:

| Offense | Reputation Penalty | Action |
|---------|-------------------|--------|
| Single timeout | -5% | Warning |
| 2 consecutive timeouts | -10% | Probation |
| 3 consecutive timeouts | -20% | Removal from committee |
| Proven stall attack | -50% | Permanent ban from coordinator |
| Collusion with attackers | -100% | Network-wide ban |

## Transaction Recovery and Storage

### Recovery Options

| Method | Cost | Availability | Use Case |
|--------|------|--------------|----------|
| Counterparty Request | Free | If counterparty online | Single TX verification |
| Partner Recovery | Free | If partners online | Lost database recovery |
| Paid DHT Storage | Fee x Replicas | Guaranteed by replicas | Critical TX redundancy |
| Archival Nodes | Query fee | Opt-in archival | Historical queries |

### Counterparty Request Protocol

Direct P2P query to transaction counterparty:

1. Discover counterparty's node via DHT (wallet-to-node mapping)
2. Send signed request with TPM attestation
3. Receive transaction with Merkle proof
4. Verify proof against DHT checkpoint

Rate limits based on reputation:

| Reputation | Requests/Hour | Requests/Day |
|------------|---------------|--------------|
| 0.0 (Low) | 10 | 100 |
| 1.0 (High) | 100 | 1000 |

### Partner Recovery Protocol

Recover complete transaction history from partners:

1. Get target checkpoint from DHT (sequence, merkle root, balance)
2. Discover partners from recent DAG tips
3. Request transaction batches in parallel
4. Verify each TX (Merkle proof, signature, TPM quote)
5. Rebuild local database and Merkle tree
6. Verify computed root matches checkpoint

### Paid Storage Service

Optional redundant DHT storage with compensation:

```go
type StorageConfig struct {
    ReplicaCount   uint8   // 3-20 replicas
    RetentionDays  uint16  // 1-3650 days
    Priority       string  // "standard" | "high"
    UptimeSLA      float64 // 50.0% - 99.999%
}

const BaseFeePerReplicaPerDay = 1  // at 90% baseline
```

#### Uptime SLA Pricing

| Tier | Uptime | Downtime/Month | Multiplier |
|------|--------|----------------|------------|
| Economy | 50% | ~15 days | 0.25x |
| Economy | 80% | ~6 days | 0.7x |
| Standard | 90% | ~3 days | 1.0x |
| Professional | 99% | ~7 hours | 1.5x |
| Enterprise | 99.9% | ~43 min | 3.0x |
| Enterprise | 99.99% | ~4 min | 6.0x |
| Premium | 99.999% | ~26 sec | 10.0x |

#### Proof-of-Storage

Storage nodes prove data possession hourly:

1. Coordinator sends random challenge
2. Node responds with hash(data + challenge) + TPM quote
3. Valid proof: Release compensation
4. Invalid/missing proof: Initiate replica replacement

#### SLA Violation Handling

- Forfeit remaining escrowed fees (refunded to user)
- 5% reputation penalty per violation
- Automatic replica replacement

### Reconciliation

Recovery verification against checkpoint:

```go
func (s *PartnerRecoverySession) Execute(ctx context.Context) error {
    partners, _ := s.discoverPartners(ctx)
    txs, proofs, _ := s.requestTransactionsParallel(ctx, partners)
    s.rebuildDatabase(txs)
    s.rebuildMerkleTree(txs)

    // Verify against checkpoint
    if s.wallet.MerkleTree.Root != s.TargetCheckpoint.MerkleRoot {
        return ErrMerkleRootMismatch
    }
    if s.wallet.ComputeBalance() != s.TargetCheckpoint.Balance {
        return ErrBalanceMismatch
    }
    return nil
}
```

## Performance Analysis

### Throughput Targets

| Metric | Target | How Achieved |
|--------|--------|--------------|
| TPS per shard | 10,000 | DAG parallelism |
| Global TPS | 650M | 65,536 shards x 10,000 TPS |
| Finality | <1 sec | Trusted confirmation |
| DHT storage/shard | ~4 MB | Checkpoints only |
| Validation time | 250-500ms | Checkpoint lookup |

### Cross-Shard Performance

| Metric | Value |
|--------|-------|
| Best Case Latency | ~10s |
| Average Latency | ~15s |
| Worst Case Latency | ~70s |
| Messages per TX | 12-18 |
| Coordinator TPS | ~20-25 |

### Scalability Considerations

**Bottleneck**: Coordinator committee limits cross-shard throughput

**Mitigations**:
1. Hierarchical coordinators for regional shards
2. Separate committees for different shard ranges
3. Optimistic execution for low-value transactions
4. Transaction batching

### Storage Comparison

| Scenario | Old (Full TX in DHT) | New (Checkpoints Only) |
|----------|---------------------|------------------------|
| 1M wallets x 100 TX | 50 GB | 250 MB |
| 1B wallets x 100 TX | 50 TB | 250 GB (3.8 MB/shard) |
| Validation time | 2-10 seconds | 250-500ms |
| IoT participation | NO | YES |

## Security Guarantees

### Double-Spend Prevention (CANONICAL)

The system employs multiple layers of defense against double-spend attacks:

#### 1. Shard-Authoritative UTXO Model

Each wallet is assigned to exactly ONE authoritative shard. That shard is the ONLY authority for the wallet's UTXO state.

```go
// Shard-authoritative UTXO prevents double-spend by eliminating race conditions
// See: "Shard-Authoritative UTXO Model (CANONICAL)" section
func GetAuthoritativeShard(walletID WalletID) uint16 {
    hash := sha256.Sum256(walletID[:])
    return binary.BigEndian.Uint16(hash[:2])
}
```

**Key properties**:
- Wallet can ONLY transact through its authoritative shard
- All validation happens on the authoritative shard (no DHT race condition)
- Cross-shard transactions MUST route through sender's authoritative shard first

#### 2. Sequence Lock for Cross-Shard Transactions

The sequence lock structure prevents concurrent transaction attempts:

```go
// SequenceLock structure for double-spend prevention
// See: "Sequence Lock Structure" section for full implementation
type SequenceLock struct {
    WalletID      WalletID      // Wallet this lock applies to
    Sequence      uint64        // Reserved sequence number
    LockedUntil   time.Time     // Lock expiration time
    TransactionID TxID          // Transaction holding this lock
}
```

**Key properties**:
- Single sequence per wallet per transaction
- Lock prevents concurrent requests from same wallet
- Failed transactions still consume sequence (no rollback)

#### 3. Atomic Sequence Increment

Sequence numbers use compare-and-swap (CAS) for atomic increment:

```go
// Atomic CAS prevents race conditions on sequence increment
if !atomic.CompareAndSwapUint64(&authority.Sequence, expectedSeq-1, expectedSeq) {
    return ErrSequenceRace  // Another transaction claimed this sequence
}
```

**If current sequence != expected, the transaction fails immediately**.

#### 4. Additional Protections

| Protection | Description | Mechanism |
|------------|-------------|-----------|
| TPM-enforced ordering | Monotonic sequence numbers attested by TPM | TPM quote on every tx |
| UTXO tracking | Shard-local UTXO set for each wallet | ShardAuthority.UTXOSet |
| Lock ordering | Lexicographic UTXO locking prevents deadlocks | sorted UTXO acquisition |
| Failed tx sequence burn | Sequence consumed even on failure | prevents replay attacks |

#### Double-Spend Attack Scenarios and Mitigations

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Same sequence to different nodes | Broadcast TxA and TxB with same seq to nodes X and Y | Atomic CAS - only first wins |
| Cross-shard race | Submit same funds to different destination shards | Authoritative shard validates first |
| Replay old transaction | Replay previously valid transaction | Sequence already consumed |
| Sequence gap attack | Skip sequences to create gaps | Strict contiguity + gap penalty |
| Coordinator collusion | Malicious coordinator routes to wrong shard | Shard verifies its own authority |

### Anti-Spam Protection

- Reputation-gated rate limits
- Request signing (non-repudiation)
- Response size limits
- TPM-attested responses

### Storage Fraud Prevention

- Challenge-response proof-of-storage
- TPM attestation of proofs
- Escrowed fees with forfeiture
- Automatic replica replacement

## Security Fix Summary

This document addresses the following critical security issues:

| Issue | Description | Solution |
|-------|-------------|----------|
| C6 | DAG grows unbounded | Epoch boundaries with BFT-signed Merkle checkpoints, finality rules, pruning protocol |
| C7 | Reputation-weighted finality gameable | BFT finality with fixed 2/3+1 threshold for high-value TX and epoch finality |
| C8 | Static shard assignment enables Sybil | VRF-based dynamic shard rotation with secure handoff protocol |
| #12 | Cross-shard lock TTL missing | 60s deterministic non-renewable TTL, no extensions by design, orphan scanner every 5 min |
| C14 | Parent proof missing | Merkle proof of parent inclusion in epoch with verification protocol |
| C15 | Coordinator crash during 3PC | Termination protocol with 2-of-3 shard witness quorum, 5s grace period, 3 rollback retries |
| C16 | Coordinator accountability | Stake-based slashing (10% abandoned, 100% double-commit, 5% invalid prepare), 1h cooldown |
| C17 | Same-shard transaction overhead | Fast path bypasses 3PC entirely for same-shard transactions (80%+ expected usage) |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 2.2 | 2026-01-10 | Added cross-shard transaction enhancements: Single-shard fast path (80%+ transactions, 0ms network overhead), 3PC termination protocol (2-of-3 shard witness quorum, 5s rollback grace period, 3 retry attempts), Deterministic non-renewable lock TTL (60s hard deadline, no extensions by design), Coordinator heartbeat during 3PC (5s interval, 15s death timeout), Coordinator accountability and slashing (10% abandoned tx, 100% double-commit, 5% invalid prepare, 1h cooldown) |
| 2.1 | 2026-01-10 | Added FINAL DESIGN specifications: UTXO validation edge cases (input deduplication, CAS race window protection, sequence rollback recovery), 3PC coordinator crash recovery (participant states, coordinator election, transaction log recovery, autonomous abort), Cross-shard consistency (timeout asymmetry, atomic visibility, partial commit recovery, compensating transactions), DAG ordering (valid tip criteria, max parent age, orphan handling, conflict resolution), TPM quote validation (timestamp verification, quote reuse prevention, per-node caching) |
| 2.0 | Previous | Security fixes for DAG, finality, shard rotation, lock TTL, parent proof |

---

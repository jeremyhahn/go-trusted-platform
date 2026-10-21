# Certificate Authority Architecture

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
## Overview

A fully decentralized Certificate Authority using threshold signatures with hourly key rotation, TPM attestation, and Certificate Transparency for a billion-scale IoT P2P network.

> **Cross-Reference:** See [04-cryptographic-protocols.md](04-cryptographic-protocols.md) for FROST protocol details and DKG protocol details.

---

## Node IDevID Enrollment (CANONICAL)

### ACME enroll-01 Challenge

Nodes obtain their IDevID certificates from the DHT Privacy CA via the ACME enroll-01 challenge. **Nodes do NOT generate IDevID locally** - the Privacy CA issues the IDevID after verifying the node's TPM attestation.

```
Node                                DHT Privacy CA (FROST Pool)
  │                                          │
  │ 1. Generate key pair in local TPM        │
  │ 2. Create CSR with:                      │
  │    - Public key from TPM                 │
  │    - TPM Quote (PCRs 0,2,7)              │
  │    - EK Certificate                       │
  │    - Nonce (freshness)                   │
  │                                          │
  │──── ACME enroll-01 Challenge ───────────>│
  │                                          │
  │                                          │ 3. Verify TPM Quote signature
  │                                          │ 4. Verify nonce freshness (+/-100ms)
  │                                          │ 5. Extract EK cert chain
  │                                          │ 6. Check manufacturer whitelist
  │                                          │ 7. Determine trust level:
  │                                          │    - Hardware TPM + whitelisted EK → Trusted
  │                                          │    - Otherwise → Untrusted
  │                                          │ 8. FROST threshold sign IDevID
  │                                          │
  │<──── IDevID Certificate ─────────────────│
  │      (contains TrustLevel extension)     │
  │                                          │
  │ 9. Store IDevID in TPM NVRAM             │
  │ 10. Derive NodeID from IDevID            │
```

### IDevID Certificate Structure

```go
type IDevIDCertificate struct {
    // Standard X.509 fields
    Version      int
    SerialNumber []byte
    Subject      pkix.Name
    NotBefore    time.Time
    NotAfter     time.Time      // 90 days validity
    PublicKey    crypto.PublicKey

    // DHT Extensions
    Extensions   []pkix.Extension{
        {
            Id:       OIDTrustLevel,      // Trust level (Trusted/Untrusted)
            Critical: true,
            Value:    []byte{byte(trustLevel)},
        },
        {
            Id:       OIDEKFingerprint,   // SHA-256 of EK certificate
            Critical: false,
            Value:    ekFingerprint,
        },
        {
            Id:       OIDTPMManufacturer, // TPM manufacturer ID
            Critical: false,
            Value:    manufacturerID,
        },
    }

    // FROST signature from Privacy CA pool
    Signature    []byte         // 64-byte Schnorr signature
    CAEpoch      uint64         // Which pool signed this cert
    CAPoolID     string         // "ed25519-a", etc.
}
```

### NodeID Derivation

The 160-bit NodeID is derived from the IDevID certificate:

```go
func DeriveNodeID(idevid *x509.Certificate) NodeID {
    // Combine public key and EK fingerprint for uniqueness
    ekFingerprint := extractEKFingerprint(idevid)
    pubKeyBytes := marshalPublicKey(idevid.PublicKey)

    // SHA-256 hash, truncated to 160 bits for Kademlia
    hash := sha256.Sum256(append(pubKeyBytes, ekFingerprint...))

    var nodeID NodeID // [20]byte
    copy(nodeID[:], hash[:20])
    return nodeID
}
```

### Trust Level Enforcement

The trust level embedded in the IDevID certificate determines node capabilities:

| Trust Level | Can Earn Reputation | Role Access | FROST Participation |
|-------------|---------------------|-------------|---------------------|
| **Trusted** | Yes | All roles (Leaf → Coordinator) | Yes (CA pool member) |
| **Untrusted** | No | Observer only (no roles) | No |

> **Cross-Reference:** See [03-security-trust.md](03-security-trust.md) for the full TPM Trust Policy.

### Privacy CA Pool Requirements

The Privacy CA pool that issues IDevID certificates has special requirements:

- **Pool composition:** Ed25519 and P-256 pools (same as other CAs)
- **Threshold:** 33% for signing (tolerates 67% offline)
- **Availability:** 99.9999% uptime target
- **Latency:** <200ms for IDevID issuance
- **Attestation verification:** Must verify TPM quote within +/-100ms of nonce creation

### Re-Enrollment

IDevID certificates are valid for 90 days. Before expiration, nodes must re-enroll:

```go
func (node *Node) ShouldReEnroll() bool {
    // Re-enroll 7 days before expiration
    expiresAt := node.IDevID.NotAfter
    reEnrollThreshold := expiresAt.Add(-7 * 24 * time.Hour)
    return time.Now().After(reEnrollThreshold)
}

func (node *Node) ReEnroll(ctx context.Context) error {
    // Generate fresh TPM quote
    nonce, _ := crypto.RandBytes(32)
    quote, _ := node.tpm.Quote(ctx, nonce, []int{0, 2, 7})

    // Create CSR
    csr := node.createCSR(quote, nonce)

    // Submit ACME enroll-01 challenge
    newIDevID, err := node.acmeClient.EnrollChallenge(ctx, csr)
    if err != nil {
        return err
    }

    // Store new IDevID
    return node.tpm.StoreNVRAM(newIDevID)
}
```

### Trust Level Changes

A node's trust level can only change through re-enrollment with different hardware:

- **Trusted -> Untrusted:** Not possible (would need to remove hardware TPM)
- **Untrusted -> Trusted:** Re-enroll with hardware TPM from whitelisted manufacturer
- **No in-place upgrades:** Must obtain new IDevID certificate

---

## ACME Challenge Edge Cases (FINAL DESIGN)

### EK Chain Validation Failure

When the EK certificate chain from a node cannot be validated against known manufacturer roots:

```go
type EKValidationError struct {
    NodeID        NodeID
    EKFingerprint [32]byte
    Manufacturer  string
    FailureReason string
    RetryCount    int
}

func (ca *PrivacyCA) ValidateEKChain(ekCert *x509.Certificate) error {
    // Retry with exponential backoff
    maxRetries := 3
    backoff := 100 * time.Millisecond

    for attempt := 1; attempt <= maxRetries; attempt++ {
        if err := ca.verifyEKAgainstRoots(ekCert); err == nil {
            return nil // Success
        }

        if attempt < maxRetries {
            time.Sleep(backoff)
            backoff *= 2 // Exponential backoff: 100ms, 200ms, 400ms
        }
    }

    // Rejection after 3 failed attempts
    return &EKValidationError{
        FailureReason: "EK chain validation failed after 3 retries",
        RetryCount:    maxRetries,
    }
}
```

**Error Response to Node:**
```json
{
  "error": "ek_validation_failed",
  "message": "EK certificate chain could not be validated",
  "details": "Manufacturer not in whitelist or certificate chain broken",
  "retry_after": 3600,
  "remediation": "Ensure TPM EK certificate is from whitelisted manufacturer"
}
```

---

### TPM Attestation Timeout

Standard timeout is 100ms for TPM quote verification. For slow TPMs (embedded devices, older hardware):

```go
type AttestationConfig struct {
    StandardTimeout time.Duration // 100ms
    ExtendedTimeout time.Duration // 500ms for slow TPM
    SlowTPMThreshold int          // Mark as slow after 3 timeouts
}

func (ca *PrivacyCA) VerifyTPMQuote(quote *TPMQuote, nonce []byte) error {
    timeout := ca.config.StandardTimeout

    // Check if this node has history of slow attestation
    if ca.isSlowTPM(quote.NodeID) {
        timeout = ca.config.ExtendedTimeout
        ca.logger.Warn("Using extended timeout for slow TPM",
            "node_id", quote.NodeID,
            "timeout", timeout)
    }

    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    if err := ca.verifyQuoteWithContext(ctx, quote, nonce); err != nil {
        if errors.Is(err, context.DeadlineExceeded) {
            ca.recordSlowTPM(quote.NodeID)

            if timeout == ca.config.StandardTimeout {
                // Retry with extended timeout
                return ca.VerifyTPMQuote(quote, nonce)
            }
        }
        return err
    }

    return nil
}
```

---

### Nonce Freshness Failure (Clock Skew)

Allow +/-5 second tolerance for clock skew while maintaining security:

```go
type NonceValidator struct {
    MaxClockSkew time.Duration // 5 seconds
    NonceWindow  time.Duration // 10 seconds total window
}

func (nv *NonceValidator) ValidateNonce(nonce []byte, timestamp time.Time) error {
    // Decode nonce to extract timestamp
    nonceTime, err := extractTimestamp(nonce)
    if err != nil {
        return fmt.Errorf("invalid nonce format: %w", err)
    }

    // Calculate time difference
    diff := timestamp.Sub(nonceTime).Abs()

    if diff > nv.MaxClockSkew {
        return &NonceFreshnessError{
            NonceTime:    nonceTime,
            CurrentTime:  timestamp,
            Skew:         diff,
            MaxAllowed:   nv.MaxClockSkew,
            Recommendation: "Synchronize system clock with NTP",
        }
    }

    return nil
}
```

**Error Response with NTP Recommendation:**
```json
{
  "error": "nonce_freshness_failed",
  "message": "Nonce timestamp outside acceptable window",
  "details": {
    "clock_skew_seconds": 7.3,
    "max_allowed_seconds": 5.0,
    "node_time": "2026-01-10T14:30:07Z",
    "ca_time": "2026-01-10T14:30:00Z"
  },
  "remediation": "Synchronize system clock using NTP (ntpdate pool.ntp.org)"
}
```

---

### Unknown TPM Manufacturer

When a node presents an EK from a manufacturer not in the whitelist:

```go
type ManufacturerGovernance struct {
    Whitelist     map[string]ManufacturerInfo
    PetitionQueue chan *ManufacturerPetition
}

type ManufacturerPetition struct {
    Manufacturer    string
    RootCA          *x509.Certificate
    Petitioner      NodeID
    Evidence        []byte // Documentation, security audit, etc.
    SubmittedAt     time.Time
    CommunityVotes  int
}

func (ca *PrivacyCA) HandleUnknownManufacturer(ekCert *x509.Certificate) error {
    manufacturer := extractManufacturer(ekCert)

    // Check if already in whitelist
    if ca.governance.IsWhitelisted(manufacturer) {
        return nil
    }

    // Reject with petition path
    return &UnknownManufacturerError{
        Manufacturer: manufacturer,
        PetitionURL:  "https://governance.dht.network/manufacturer-petition",
        Message:      "TPM manufacturer not whitelisted",
        NextSteps: []string{
            "Submit manufacturer addition petition",
            "Provide manufacturer root CA certificate",
            "Attach security audit documentation",
            "Await community governance vote (7-day voting period)",
        },
    }
}
```

**Governance Process:**
1. Node operator submits petition with manufacturer details
2. Community reviews security audit and manufacturer reputation
3. 7-day voting period (Trusted nodes only, weighted by reputation)
4. 67% approval required to add manufacturer to whitelist
5. Manufacturer root CA added to trust store
6. Node can re-enroll after whitelist update

---

### Re-Enrollment with Pending Transactions

Prevent re-enrollment conflicts when node has active transactions:

```go
type ReEnrollmentValidator struct {
    transactionStore TransactionStore
}

func (v *ReEnrollmentValidator) ValidateReEnrollment(nodeID NodeID) error {
    // Check for pending transactions
    pending, err := v.transactionStore.GetPendingTransactions(nodeID)
    if err != nil {
        return fmt.Errorf("failed to check pending transactions: %w", err)
    }

    if len(pending) > 0 {
        return &PendingTransactionsError{
            NodeID:              nodeID,
            PendingTransactions: pending,
            Message:             "Complete pending transactions before re-enrollment",
            Resolution: "Wait for transactions to settle or cancel pending transactions",
        }
    }

    return nil
}

func (node *Node) ReEnrollWithTransactionCheck(ctx context.Context) error {
    // Step 1: Complete all pending transactions
    if err := node.settlePendingTransactions(ctx); err != nil {
        return fmt.Errorf("failed to settle transactions: %w", err)
    }

    // Step 2: Wait for settlement confirmation
    if err := node.waitForSettlement(ctx, 30*time.Second); err != nil {
        return fmt.Errorf("transaction settlement timeout: %w", err)
    }

    // Step 3: Proceed with re-enrollment
    return node.ReEnroll(ctx)
}
```

---

## CA Rotation with Pending Requests (FINAL DESIGN)

### In-Flight Certificate Request Handling

```go
type PendingRequestPool struct {
    requests    map[string]*CertificateRequest
    maxSize     int           // 10000 max pending
    maxAge      time.Duration // 5 minutes max
    mu          sync.RWMutex
}

func (pool *PendingRequestPool) EnqueueRequest(req *CertificateRequest) error {
    pool.mu.Lock()
    defer pool.mu.Unlock()

    if len(pool.requests) >= pool.maxSize {
        return &QueueFullError{
            Current: len(pool.requests),
            Maximum: pool.maxSize,
            Message: "Pending request queue full, retry in 30 seconds",
        }
    }

    pool.requests[req.ID] = req
    return nil
}

func (ca *CAPoolManager) RotateWithPendingRequests(oldPool, newPool *CAPool) error {
    // Step 1: Stop accepting new requests on old pool
    oldPool.SetState(StateRotating)

    // Step 2: Transfer pending requests to new pool
    pending := oldPool.GetPendingRequests()
    ca.logger.Info("Transferring pending requests",
        "count", len(pending),
        "from_pool", oldPool.ID,
        "to_pool", newPool.ID)

    for _, req := range pending {
        if err := newPool.EnqueueRequest(req); err != nil {
            // If new pool queue full, reject with retry guidance
            req.Reject(&QueueFullError{
                RetryAfter: 30 * time.Second,
            })
        }
    }

    // Step 3: New pool processes queue before accepting new requests
    newPool.SetState(StateProcessingQueue)
    if err := newPool.ProcessPendingQueue(context.Background()); err != nil {
        return fmt.Errorf("failed to process pending queue: %w", err)
    }

    // Step 4: Activate new pool for new requests
    newPool.SetState(StateActive)

    // Step 5: Deactivate old pool
    oldPool.SetState(StateDeactivated)

    return nil
}
```

---

### Queue Timeout and Rejection

```go
func (pool *CAPool) ProcessPendingQueue(ctx context.Context) error {
    now := time.Now()
    processed := 0
    rejected := 0

    for id, req := range pool.pendingPool.requests {
        age := now.Sub(req.SubmittedAt)

        if age > 5*time.Minute {
            // Reject old requests with retry guidance
            req.Reject(&TimeoutError{
                Age:        age,
                MaxAllowed: 5 * time.Minute,
                RetryGuidance: "Request expired during CA rotation, resubmit with fresh CSR",
            })
            delete(pool.pendingPool.requests, id)
            rejected++
            continue
        }

        // Process valid requests
        if err := pool.ProcessCertificateRequest(ctx, req); err != nil {
            pool.logger.Error("Failed to process pending request",
                "request_id", id,
                "error", err)
        } else {
            processed++
        }

        delete(pool.pendingPool.requests, id)
    }

    pool.logger.Info("Pending queue processing complete",
        "processed", processed,
        "rejected", rejected)

    return nil
}
```

---

### DKG Abort During Emergency

```go
type EmergencyDKGProtocol struct {
    participants []*Node
    timeoutTimer *time.Timer
    abortChan    chan struct{}
}

func (dkg *EmergencyDKGProtocol) ExecuteWithAbortCapability(ctx context.Context) error {
    // Set aggressive timeout for emergency rotation
    ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
    defer cancel()

    errChan := make(chan error, 1)

    go func() {
        errChan <- dkg.runDKGProtocol(ctx)
    }()

    select {
    case err := <-errChan:
        if err != nil {
            return dkg.handleDKGFailure(err)
        }
        return nil

    case <-ctx.Done():
        return dkg.abortDKG("DKG timeout during emergency rotation")

    case <-dkg.abortChan:
        return dkg.abortDKG("Manual abort triggered")
    }
}

func (dkg *EmergencyDKGProtocol) abortDKG(reason string) error {
    // Zero out all secret shares in memory
    for _, participant := range dkg.participants {
        participant.ZeroSecretShare()
    }

    // Notify all participants
    for _, participant := range dkg.participants {
        participant.NotifyDKGAbort(reason)
    }

    // Restart with reduced pool size
    reducedPool := dkg.selectReducedPool(0.8) // 80% of original size
    return NewEmergencyDKGProtocol(reducedPool).ExecuteWithAbortCapability(context.Background())
}
```

---

## CA Pool Failure Scenarios (FINAL DESIGN)

### Pool Degraded Mode (>67% Offline)

```go
type PoolHealthMonitor struct {
    pool          *CAPool
    threshold     float64 // 0.67 = 67% offline triggers degraded
    degradedSince time.Time
    maxDegraded   time.Duration // 4 hours max
}

func (monitor *PoolHealthMonitor) CheckHealth(ctx context.Context) PoolState {
    onlineNodes := monitor.pool.CountOnlineNodes()
    totalNodes := monitor.pool.TotalNodes()
    availability := float64(onlineNodes) / float64(totalNodes)

    if availability < (1.0 - monitor.threshold) { // < 33% online
        if monitor.pool.State != StateDegraded {
            monitor.pool.SetState(StateDegraded)
            monitor.degradedSince = time.Now()

            monitor.logger.Warn("Pool entered degraded mode",
                "pool_id", monitor.pool.ID,
                "availability", availability,
                "online_nodes", onlineNodes,
                "total_nodes", totalNodes)
        }

        // Check if degraded for too long
        if time.Since(monitor.degradedSince) > monitor.maxDegraded {
            return monitor.failoverToBackup()
        }

        return StateDegraded
    }

    if monitor.pool.State == StateDegraded {
        monitor.pool.SetState(StateActive)
        monitor.logger.Info("Pool recovered from degraded mode",
            "pool_id", monitor.pool.ID,
            "availability", availability)
    }

    return StateActive
}

func (monitor *PoolHealthMonitor) failoverToBackup() PoolState {
    monitor.logger.Error("Pool degraded for too long, failing over",
        "pool_id", monitor.pool.ID,
        "degraded_duration", time.Since(monitor.degradedSince))

    // Activate backup pool
    backupPool := monitor.getBackupPool()
    backupPool.SetState(StateActive)

    // Deactivate current pool
    monitor.pool.SetState(StateFailed)

    // Trigger emergency pool rotation to restore redundancy
    go monitor.triggerEmergencyRotation(backupPool)

    return StateFailed
}
```

---

### Byzantine Node During Rotation

```go
type ByzantineDetector struct {
    suspiciousNodes map[NodeID]*SuspiciousActivity
    slashThreshold  int // 3 strikes
}

type SuspiciousActivity struct {
    NodeID         NodeID
    Violations     []Violation
    FirstDetected  time.Time
    LastDetected   time.Time
}

func (detector *ByzantineDetector) DetectDuringDKG(
    participants []*Node,
    dkgMessages map[NodeID]*DKGMessage,
) []NodeID {
    byzantine := make([]NodeID, 0)

    for _, node := range participants {
        msg := dkgMessages[node.ID]

        // Check for invalid commitments
        if !detector.validateCommitment(msg.Commitment) {
            detector.recordViolation(node.ID, ViolationInvalidCommitment)
        }

        // Check for double-sending
        if detector.detectDoubleSending(node.ID, msg) {
            detector.recordViolation(node.ID, ViolationDoubleSending)
        }

        // Check for timing attacks
        if detector.detectTimingAttack(node.ID, msg) {
            detector.recordViolation(node.ID, ViolationTimingAttack)
        }

        // Determine if node is byzantine
        if detector.isByzantine(node.ID) {
            byzantine = append(byzantine, node.ID)
        }
    }

    return byzantine
}

func (detector *ByzantineDetector) HandleByzantineNode(nodeID NodeID) error {
    // Exclude from new pool
    detector.logger.Warn("Excluding byzantine node from CA pool",
        "node_id", nodeID,
        "violations", detector.suspiciousNodes[nodeID].Violations)

    // Report to reputation system
    ReportByzantineBehavior(nodeID, detector.suspiciousNodes[nodeID])

    // Slash reputation
    SlashReputation(nodeID, 0.25) // 25% reputation penalty

    // Ban from pool participation
    BanFromPoolParticipation(nodeID, 24*time.Hour*7) // 7-day ban

    return nil
}
```

---

### Certificate Validation During Rotation

```go
type DualPoolValidator struct {
    oldPool *CAPool
    newPool *CAPool
    overlapWindow time.Duration // 30 minutes
}

func (validator *DualPoolValidator) ValidateCertificate(
    cert *x509.Certificate,
    timestamp time.Time,
) error {
    epoch := cert.Extensions.GetEpoch()
    poolID := cert.Extensions.GetPoolID()

    // Determine which pool should have signed this
    pool := validator.getPoolForEpoch(epoch, poolID)
    if pool == nil {
        return fmt.Errorf("no pool found for epoch %d", epoch)
    }

    // During overlap window, accept signatures from both pools
    if validator.isInOverlapWindow(timestamp) {
        if err := validator.oldPool.VerifySignature(cert); err == nil {
            return nil // Valid with old pool
        }
        if err := validator.newPool.VerifySignature(cert); err == nil {
            return nil // Valid with new pool
        }
        return fmt.Errorf("certificate invalid with both old and new pool")
    }

    // Outside overlap window, use specific pool
    return pool.VerifySignature(cert)
}

func (validator *DualPoolValidator) isInOverlapWindow(timestamp time.Time) bool {
    rotationTime := validator.newPool.ActivatedAt
    windowEnd := rotationTime.Add(validator.overlapWindow)

    return timestamp.After(rotationTime) && timestamp.Before(windowEnd)
}
```

---

## CT Log Edge Cases (FINAL DESIGN)

### Signature Failure at 34% Threshold

```go
type CTLogSigner struct {
    currentPool *CAPool
    nextPool    *CAPool
    threshold   int // 34% of pool
}

func (signer *CTLogSigner) SignCTLogEntry(entry *CTLogEntry) (*SignedCTEntry, error) {
    signatures, err := signer.currentPool.CollectSignatures(entry)
    if err != nil {
        return nil, err
    }

    // Check if we have enough signatures
    if len(signatures) < signer.threshold {
        signer.logger.Warn("Insufficient signatures for current epoch, trying next epoch",
            "current_epoch", entry.Epoch,
            "signatures_collected", len(signatures),
            "threshold", signer.threshold)

        // Retry with next epoch
        entry.Epoch++
        entry.Timestamp = time.Now()

        signatures, err = signer.nextPool.CollectSignatures(entry)
        if err != nil {
            return nil, fmt.Errorf("failed to collect signatures from next pool: %w", err)
        }

        // Log the failure for monitoring
        signer.logCTSignatureFailure(entry.Epoch-1, len(signatures))
    }

    // Aggregate signatures
    aggregated := signer.aggregateSignatures(signatures)

    return &SignedCTEntry{
        Entry:     entry,
        Signature: aggregated,
    }, nil
}
```

---

### Merkle Root Mismatch Detection

```go
type CTAuditor struct {
    poolMembers []*Node
    tolerance   int // Number of mismatches to trigger audit
}

func (auditor *CTAuditor) VerifyMerkleRoot(
    epoch uint64,
    expectedRoot [32]byte,
) error {
    // Query multiple pool members
    roots := make(map[[32]byte]int) // root -> count

    for _, member := range auditor.poolMembers {
        root, err := member.GetMerkleRoot(epoch)
        if err != nil {
            auditor.logger.Warn("Failed to query pool member",
                "member", member.ID,
                "error", err)
            continue
        }

        roots[root]++
    }

    // Check for consensus
    maxCount := 0
    var consensusRoot [32]byte
    for root, count := range roots {
        if count > maxCount {
            maxCount = count
            consensusRoot = root
        }
    }

    if consensusRoot != expectedRoot {
        // Trigger full audit
        return auditor.triggerFullAudit(epoch, expectedRoot, consensusRoot, roots)
    }

    return nil
}

func (auditor *CTAuditor) triggerFullAudit(
    epoch uint64,
    expectedRoot [32]byte,
    consensusRoot [32]byte,
    allRoots map[[32]byte]int,
) error {
    auditor.logger.Error("Merkle root mismatch detected",
        "epoch", epoch,
        "expected", hex.EncodeToString(expectedRoot[:]),
        "consensus", hex.EncodeToString(consensusRoot[:]),
        "unique_roots", len(allRoots))

    // Compare roots from multiple pool members
    audit := &CTAuditReport{
        Epoch:        epoch,
        ExpectedRoot: expectedRoot,
        ActualRoots:  allRoots,
        Timestamp:    time.Now(),
    }

    // Retrieve individual certificates from epoch
    certs := auditor.retrieveCertificatesForEpoch(epoch)

    // Recompute Merkle root locally
    computedRoot := auditor.computeMerkleRoot(certs)

    if computedRoot == consensusRoot {
        // Consensus root is correct, expected root was wrong
        audit.Resolution = "Expected root incorrect, consensus root valid"
        return auditor.updateExpectedRoot(epoch, consensusRoot)
    }

    // Neither root matches - potential byzantine behavior
    audit.Resolution = "Byzantine behavior detected, investigating pool members"
    return auditor.investigateByzantineNodes(epoch, certs, allRoots)
}
```

---

### Historical Certificate Verification

```go
type HistoricalCAStore struct {
    archivedKeys map[uint64]map[string]*GroupPublicKey // epoch -> poolID -> key
    ctLogStore   CTLogStore
}

func (store *HistoricalCAStore) ArchivePoolKey(
    epoch uint64,
    poolID string,
    groupKey *GroupPublicKey,
) error {
    if store.archivedKeys[epoch] == nil {
        store.archivedKeys[epoch] = make(map[string]*GroupPublicKey)
    }

    store.archivedKeys[epoch][poolID] = groupKey

    // Also store in DHT for redundancy
    return store.storeInDHT(epoch, poolID, groupKey)
}

func (store *HistoricalCAStore) VerifyOldCertificate(
    cert *x509.Certificate,
) error {
    // Extract epoch and pool from certificate
    epoch := cert.Extensions.GetEpoch()
    poolID := cert.Extensions.GetPoolID()

    // Retrieve archived pool key
    groupKey := store.archivedKeys[epoch][poolID]
    if groupKey == nil {
        // Try to retrieve from DHT
        var err error
        groupKey, err = store.retrieveFromDHT(epoch, poolID)
        if err != nil {
            return fmt.Errorf("pool key not found for epoch %d, pool %s: %w",
                epoch, poolID, err)
        }
    }

    // Verify signature using archived key
    return VerifyFROSTSignature(cert.Signature, cert.TBSCertificate, groupKey)
}
```

---

### New API Endpoints

```go
// GET /api/v1/ca/pools/current - Returns current active pools
func (h *CAHandler) GetCurrentPools(w http.ResponseWriter, r *http.Request) {
    pools := h.caManager.GetActivePools()

    response := make([]*PoolInfo, 0, len(pools))
    for _, pool := range pools {
        response = append(response, &PoolInfo{
            PoolID:      pool.ID,
            Algorithm:   pool.Algorithm,
            Epoch:       pool.CurrentEpoch,
            State:       pool.State,
            OnlineNodes: pool.CountOnlineNodes(),
            TotalNodes:  pool.TotalNodes(),
            Availability: pool.CalculateAvailability(),
        })
    }

    json.NewEncoder(w).Encode(response)
}

// GET /api/v1/ca/pools/{pool_id}/status - Pool health and member status
func (h *CAHandler) GetPoolStatus(w http.ResponseWriter, r *http.Request) {
    poolID := mux.Vars(r)["pool_id"]
    pool := h.caManager.GetPool(poolID)

    if pool == nil {
        http.Error(w, "Pool not found", http.StatusNotFound)
        return
    }

    status := &PoolStatus{
        PoolID:       pool.ID,
        State:        pool.State,
        HealthScore:  pool.CalculateHealthScore(),
        Members:      pool.GetMemberStatus(),
        LastRotation: pool.LastRotationTime,
        NextRotation: pool.NextRotationTime,
    }

    json.NewEncoder(w).Encode(status)
}

// GET /api/v1/ct-log/{algorithm}/{epoch} - Retrieve CT log for epoch
func (h *CAHandler) GetCTLogEntry(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    algorithm := vars["algorithm"]
    epoch, err := strconv.ParseUint(vars["epoch"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid epoch", http.StatusBadRequest)
        return
    }

    entry, err := h.ctLog.GetEntry(algorithm, epoch)
    if err != nil {
        http.Error(w, "CT log entry not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(entry)
}
```

---

## Design Principles

- **No single point of failure:** Distributed threshold signatures
- **No trusted dealer:** Distributed Key Generation (DKG)
- **Hardware root of trust:** TPM 2.0 attestation required
- **Any node can be CA signer:** If meets requirements (bandwidth, uptime, reputation, TPM)
- **Continuous operation:** Pools run 24/7, emergency rotation only when needed
- **Zero downtime:** Multiple pools active, seamless failover
- **Standards-based:** RFC 9591 (FROST), X.509 certificates, NIST curves

---

## Algorithm Selection

### Dual-Algorithm Pools

**Pool Set 1: Ed25519** - RFC 9591 Section 6.1
- **Performance:** Fastest (~150ms signing)
- **Signature size:** 64 bytes (compact)
- **Security:** 128-bit
- **Use case:** Default for IoT devices, high-throughput

**Pool Set 2: P-256** - RFC 9591 Section 6.4
- **Compliance:** NIST curve (P-256), NIST hash (SHA-256)
- **Performance:** Fast (~200ms signing)
- **Signature size:** 64 bytes
- **Security:** 128-bit
- **Use case:** Enterprise, government, compliance requirements

> **Cross-Reference:** See [04-cryptographic-protocols.md](04-cryptographic-protocols.md) for FROST protocol details.

---

## Pool Architecture

### Dual Rotation Strategy

**Time-Based Rotation (Security):**
- Fixed 1-hour rotation (non-configurable)
- Pools rotate 180 degrees apart (30-minute offsets)
- Never rotate simultaneously (always 3+ pools active)
- Regular key refresh reduces attack surface

**Health-Based Rotation (Availability):**
- Emergency rotation when pool health degrades
- Triggered by: node failures, performance degradation, attacks
- Fast-path DKG (5 minutes vs 10 minutes normal)
- Self-healing without human intervention

### Pool Configuration

**4 Pools Active Simultaneously:**
```
Ed25519-A (Epoch 0) --------------------------------> [ACTIVE]
Ed25519-B (Epoch 0) --------------------------------> [ACTIVE]
P-256-A   (Epoch 0) --------------------------------> [ACTIVE]
P-256-B   (Epoch 0) --------------------------------> [ACTIVE]

Properties:
- 2 pools per algorithm (redundancy)
- Load balanced across all healthy pools
- No PRIMARY/BACKUP designation (all equal)
- Continuous operation until health degrades
```

### Dynamic Pool Sizing

| Network Size | Pool % | Example Pool Size |
|--------------|--------|------------------|
| < 10K | 5% | 500 |
| 10K - 100K | 2% | 2K |
| 100K - 1M | 1% | 10K |
| 1M - 10M | 0.5% | 50K |
| 10M - 100M | 0.1% | 100K |
| 100M - 1B | 0.05% | 500K |
| > 1B | 0.01% | 1M+ |

**For 1 billion nodes:** Pool size = 1M nodes per pool

---

## Threshold Selection

### 33% Threshold (Optimized for TPM)

**Traditional BFT:** Requires 51-67% threshold (assumes untrusted nodes)

**With TPM Attestation:** Can use 33% threshold (higher availability)

**Rationale:**
- TPM prevents compromised nodes from joining CA pool
- Main risk: Offline nodes (not malicious nodes)
- 33% threshold = tolerates 67% offline (excellent availability)
- Attack requires compromising TPM on 330K+ devices (practically impossible)

**Performance at 1B Node Scale:**
- Pool size: 1M nodes
- Threshold: 330K signatures required
- DDoS attack would need to compromise 330K TPMs (infeasible)

---

## Hierarchical CA Architecture for Ultra-Scale

For networks exceeding 100 million nodes, a single global CA pool becomes a latency bottleneck. The hierarchical CA architecture distributes signing load across regional sub-CAs while maintaining cryptographic trust through cross-certification.

### Scalability Analysis

FROST Distributed Key Generation (DKG) has O(n^2) communication complexity, where n is the number of participants. This quadratic scaling creates hard limits on pool sizes:

| Participants | DKG Messages | Practical Latency | Feasibility |
|--------------|--------------|-------------------|-------------|
| 1,000 | 1M | 30 seconds | Optimal |
| 10,000 | 100M | 5 minutes | Maximum practical |
| 100,000 | 10B | 8+ hours | Infeasible |
| 1,000,000 | 1T | Days | Impossible |

**Why Hierarchical is Required at Scale:**

At 1 billion nodes with a flat 0.1% CA pool (1 million participants), DKG would require 1 trillion point-to-point messages per key rotation. This is computationally and network-wise infeasible. The hierarchical architecture caps each tier at 10,000 participants maximum (the tested scalability limit), while still providing full network coverage.

**Mathematical Justification:**
- Flat architecture at 1B nodes: Pool = 0.1% = 1,000,000 participants
- DKG messages = n(n-1)/2 = ~500 billion messages per rotation
- Network bandwidth required: ~50 PB per rotation (infeasible)
- Hierarchical architecture: Max 10K per tier = ~50M messages per tier
- Total across all tiers: ~200M messages (10,000x reduction)

### Three-Tier CA Structure

The hierarchical CA uses a three-tier structure designed for billion-scale deployments:

| Tier | Role | Participants | Threshold | Rotation | Scope |
|------|------|--------------|-----------|----------|-------|
| **Tier 1** | Global Root CA | 100 trustees | FROST t=33 | Annual | Entire network |
| **Tier 2** | Regional CAs | 16 pools x 1,000 nodes | 33% per pool | Hourly | ~62.5M nodes each |
| **Tier 3** | Local Issuers | 100 nodes per /48 prefix | 33% | 24-hour | IPv6 prefix scope |

**Tier 1: Global Root CA**
- 100 geographically distributed trustees
- FROST threshold signature with t=33 (33% required)
- Annual key rotation ceremony
- Cross-certifies all Tier 2 Regional CAs
- Provides certificate chain anchor

**Tier 2: Regional CAs**
- 16 regional pools covering global deployment
- Each pool has up to 1,000 participating nodes
- Hourly key rotation for forward secrecy
- Handle certificate issuance for their region
- Cross-certified by adjacent regions for redundancy

**Tier 3: Local Issuers**
- 100 nodes per IPv6 /48 prefix
- 24-hour key rotation
- Handle high-volume local certificate operations
- Direct IDevID issuance for enrolled nodes

### Scaling Thresholds

| Network Size | CA Architecture | Pool Size | Threshold | Rotation | Regions |
|--------------|-----------------|-----------|-----------|----------|---------|
| < 1M nodes | Single Global | 20 | 7-of-20 (35%) | 90 days | 3 |
| 1M - 100M | Single Global | 50 | 17-of-50 (34%) | 60 days | 5 |
| 100M - 1B | **Hierarchical** | 100 (root) | 34-of-100 (34%) | 30 days | 16 |
| > 1B nodes | **Hierarchical** | 100 (root) | 33-of-100 (33%) | Annual | 16 |

### Hierarchical Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              THREE-TIER HIERARCHICAL CA ARCHITECTURE (1B+ nodes)             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TIER 1: GLOBAL ROOT CA (100 trustees, FROST t=33, annual rotation)          │
│                    ┌─────────────────────────────┐                           │
│                    │       Global Root Pool       │                          │
│                    │     33-of-100 FROST          │                          │
│                    │   Cross-certifies all        │                          │
│                    │     regional CAs             │                          │
│                    └──────────────┬──────────────┘                           │
│                                   │                                          │
│  ┌────────────────────────────────┼────────────────────────────────┐        │
│  │                                │                                 │        │
│  │  TIER 2: REGIONAL CAs (16 pools x up to 1,000 nodes, hourly rotation)    │
│  │                                                                   │       │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │       │
│  │  │Region 1 │ │Region 2 │ │Region 3 │ │Region 4 │ │Region 5 │    │       │
│  │  │N.America│◄─►│ Europe │◄─►│Asia-Pac│◄─►│S.America│◄─►│ Africa │    │       │
│  │  │~1K nodes│ │~1K nodes│ │~1K nodes│ │~1K nodes│ │~1K nodes│    │       │
│  │  │33% thres│ │33% thres│ │33% thres│ │33% thres│ │33% thres│    │       │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘    │       │
│  │       │           │           │           │           │          │       │
│  │  (... + 11 more regional CA pools for global coverage ...)       │       │
│  │                                                                   │       │
│  └───────┼───────────┼───────────┼───────────┼───────────┼──────────┘       │
│          │           │           │           │           │                   │
│  TIER 3: LOCAL ISSUERS (100 nodes per /48 prefix, 24-hour rotation)          │
│          │           │           │           │           │                   │
│     ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐             │
│     │  /48-A  │ │  /48-B  │ │  /48-C  │ │  /48-D  │ │  /48-E  │             │
│     │100 nodes│ │100 nodes│ │100 nodes│ │100 nodes│ │100 nodes│             │
│     │ 33% thr │ │ 33% thr │ │ 33% thr │ │ 33% thr │ │ 33% thr │             │
│     └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘             │
│          │           │           │           │           │                   │
│      Enrolled     Enrolled    Enrolled    Enrolled    Enrolled               │
│       Nodes        Nodes       Nodes       Nodes       Nodes                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Certificate Chain: Root CA → Regional CA → Node IDevID
```

### Maximum Participants Per DKG Tier

Each DKG tier is capped at 10,000 participants to ensure reliable key generation:

```go
const (
    // MaxDKGParticipants is the tested scalability limit for FROST DKG
    MaxDKGParticipants = 10_000

    // GlobalRootPoolSize is the Tier 1 pool size
    GlobalRootPoolSize = 100

    // RegionalPoolMaxSize is the maximum Tier 2 pool size
    RegionalPoolMaxSize = 1_000

    // LocalIssuerPoolSize is the Tier 3 pool size
    LocalIssuerPoolSize = 100

    // RegionalCACount is the number of Tier 2 regional pools
    RegionalCACount = 16

    // NodesPerRegion is the approximate node count per region at 1B scale
    NodesPerRegion = 62_500_000 // 1B / 16 regions
)

// ValidateDKGPoolSize ensures pool size is within scalability limits
func ValidateDKGPoolSize(poolSize int) error {
    if poolSize > MaxDKGParticipants {
        return ErrDKGPoolTooLarge{
            MaxAllowed: MaxDKGParticipants,
            Requested:  poolSize,
            Reason:     "FROST DKG O(n^2) complexity exceeds practical limits",
        }
    }
    return nil
}
```

### Regional CA Responsibilities

```go
// pkg/ca/hierarchical.go

// RegionalCAConfig defines a regional sub-CA
type RegionalCAConfig struct {
    RegionID          string       // "north-america", "europe", etc.
    PoolSize          int          // 30-50 nodes
    Threshold         int          // 33% of pool
    ParentCrossChain  bool         // Cross-certified by root
    FallbackToRoot    bool         // Use root if regional unavailable
}

// HierarchicalCARouter directs signing requests
type HierarchicalCARouter struct {
    rootCA        *CAPool
    regionalCAs   map[string]*CAPool
    nodeRegions   map[NodeID]string
}

// RouteSigningRequest determines which CA pool handles request
func (h *HierarchicalCARouter) RouteSigningRequest(
    nodeID NodeID,
    certType CertificateType,
) (*CAPool, error) {
    region := h.nodeRegions[nodeID]

    // Regional CA handles normal certificates
    if certType == CertTypeIDevID || certType == CertTypeNode {
        if regionalCA, ok := h.regionalCAs[region]; ok {
            if regionalCA.IsHealthy() {
                return regionalCA, nil
            }
        }
    }

    // Root CA handles cross-region or fallback
    if h.rootCA.IsHealthy() {
        return h.rootCA, nil
    }

    return nil, ErrNoAvailableCA
}
```

### Certificate Chain Structure

```
Node Certificate
  └── Signed by: Regional CA (e.g., North America)
        └── Cross-certified by: Root CA
              └── Self-signed Root (bootstrap)

Verification Path:
1. Verify node certificate signature (regional CA public key)
2. Verify regional CA certificate (root CA public key)
3. Verify root CA against known root keys
```

### Benefits of Hierarchical Architecture

| Benefit | Description |
|---------|-------------|
| **Reduced Latency** | Nodes sign with geographically close CA (50-100ms vs 200-500ms) |
| **Increased Throughput** | Each regional CA handles 10-20% of load |
| **Fault Isolation** | Regional CA failure only affects that region |
| **Graceful Degradation** | Fallback to root CA maintains availability |
| **Regulatory Compliance** | Data residency requirements can be met |

### Automatic Scaling Formula

```go
// CalculateOptimalCAArchitecture determines CA topology for network size
func CalculateOptimalCAArchitecture(nodeCount int64) *CAArchitecture {
    if nodeCount < 100_000_000 { // < 100M
        return &CAArchitecture{
            Type:     ArchitectureSingleGlobal,
            PoolSize: calculatePoolSize(nodeCount),
        }
    }

    // Hierarchical for 100M+
    numRegions := int(math.Ceil(math.Log10(float64(nodeCount)) * 3))
    if numRegions > 20 {
        numRegions = 20
    }

    return &CAArchitecture{
        Type:             ArchitectureHierarchical,
        RootPoolSize:     200,
        RootThreshold:    67,
        RegionalPoolSize: 50,
        RegionalThreshold: 17,
        NumRegions:       numRegions,
    }
}

func calculatePoolSize(nodeCount int64) int {
    // Formula: 20 + 5 * log10(nodeCount)
    base := 20
    scaling := int(5 * math.Log10(float64(nodeCount)))
    size := base + scaling

    if size < 20 {
        return 20
    }
    if size > 200 {
        return 200
    }
    return size
}
```

### Regional CA Geographic Distribution

The 16 regional CAs are distributed globally to ensure low latency and regulatory compliance:

| Region ID | Geographic Area | Min Eligible Nodes | Approx. Node Capacity |
|-----------|-----------------|--------------------|-----------------------|
| `na-east` | North America East | 100 | ~62.5M |
| `na-west` | North America West | 100 | ~62.5M |
| `eu-west` | Western Europe | 100 | ~62.5M |
| `eu-east` | Eastern Europe | 100 | ~62.5M |
| `asia-east` | East Asia | 100 | ~62.5M |
| `asia-south` | South Asia | 100 | ~62.5M |
| `asia-se` | Southeast Asia | 100 | ~62.5M |
| `oceania` | Australia/Oceania | 100 | ~62.5M |
| `sa-north` | South America North | 100 | ~62.5M |
| `sa-south` | South America South | 100 | ~62.5M |
| `africa-north` | North Africa | 100 | ~62.5M |
| `africa-sub` | Sub-Saharan Africa | 100 | ~62.5M |
| `middle-east` | Middle East | 100 | ~62.5M |
| `central-asia` | Central Asia | 100 | ~62.5M |
| `arctic` | Arctic Region | 100 | ~62.5M |
| `global-backup` | Multi-region backup | 100 | Overflow |

**Minimum Eligibility Requirements:**
- Each region must have minimum 100 eligible nodes before a Regional CA can be established
- If a region has fewer than 100 eligible nodes, nodes join the nearest adjacent region
- The `global-backup` region handles overflow and nodes in sparse regions

```go
// RegionalCADistribution defines the 16-region global topology
type RegionalCADistribution struct {
    Regions       map[string]*RegionalCA
    MinEligible   int     // Minimum nodes required per region (100)
    AdjacentPairs [][2]string // Cross-signing pairs
}

// RegionalCA represents a Tier 2 CA pool
type RegionalCA struct {
    RegionID       string
    GeographicArea string
    BoundingBox    GeoBoundingBox    // Lat/long boundaries
    PoolSize       int               // Up to 1,000 nodes
    Threshold      int               // 33% of pool
    EligibleNodes  []NodeID
    ActiveNodes    []NodeID
    CrossSignWith  []string          // Adjacent region IDs
    LastRotation   time.Time
    NextRotation   time.Time
}

// GeoBoundingBox defines regional boundaries
type GeoBoundingBox struct {
    MinLat  float64
    MaxLat  float64
    MinLong float64
    MaxLong float64
}

// DefaultRegionalDistribution returns the 16-region configuration
func DefaultRegionalDistribution() *RegionalCADistribution {
    return &RegionalCADistribution{
        MinEligible: 100,
        AdjacentPairs: [][2]string{
            {"na-east", "na-west"},
            {"na-east", "eu-west"},
            {"eu-west", "eu-east"},
            {"eu-east", "asia-east"},
            {"asia-east", "asia-south"},
            {"asia-south", "asia-se"},
            {"asia-se", "oceania"},
            {"sa-north", "sa-south"},
            {"sa-north", "na-east"},
            {"africa-north", "eu-west"},
            {"africa-north", "africa-sub"},
            {"africa-sub", "middle-east"},
            {"middle-east", "central-asia"},
            {"central-asia", "asia-south"},
            {"arctic", "na-west"},
            {"arctic", "eu-east"},
        },
    }
}
```

### VRF-Based Regional CA Selection

Regional CA pool members are selected using VRF with mandatory geographic diversity constraints:

```go
// RegionalVRFSelector selects CA pool members with geographic diversity
type RegionalVRFSelector struct {
    vrfSelector      *VRFPoolSelector
    regionID         string
    geoConstraints   *GeoDiversityConstraints
}

// GeoDiversityConstraints ensures geographic spread within a region
type GeoDiversityConstraints struct {
    MaxPerCountry      float64 // Max 20% from any single country
    MaxPerCity         float64 // Max 10% from any single city
    MaxPerASN          float64 // Max 15% from any single network
    MinCountries       int     // At least 5 countries represented
    MinDistanceKm      float64 // Minimum 100km between any two nodes
}

// SelectRegionalPoolMembers selects nodes for a regional CA pool
func (s *RegionalVRFSelector) SelectRegionalPoolMembers(
    epoch uint64,
    candidates []NodeInfo,
    poolSize int,
) ([]NodeInfo, error) {
    // Step 1: Filter to nodes within this region
    regionalCandidates := s.filterByRegion(candidates)

    // Step 2: Verify minimum eligibility
    if len(regionalCandidates) < s.geoConstraints.MinEligible {
        return nil, ErrInsufficientRegionalNodes{
            RegionID: s.regionID,
            Required: s.geoConstraints.MinEligible,
            Found:    len(regionalCandidates),
        }
    }

    // Step 3: Apply VRF selection with geographic diversity
    selected := make([]NodeInfo, 0, poolSize)
    countryCount := make(map[string]int)
    cityCount := make(map[string]int)
    asnCount := make(map[string]int)

    // Compute VRF scores
    scoredNodes := s.vrfSelector.computeVRFScores(epoch, regionalCandidates)

    for _, scored := range scoredNodes {
        if len(selected) >= poolSize {
            break
        }

        node := scored.Node

        // Check country constraint
        if float64(countryCount[node.Country]+1)/float64(poolSize) > s.geoConstraints.MaxPerCountry {
            continue
        }

        // Check city constraint
        if float64(cityCount[node.City]+1)/float64(poolSize) > s.geoConstraints.MaxPerCity {
            continue
        }

        // Check ASN constraint
        if float64(asnCount[node.ASN]+1)/float64(poolSize) > s.geoConstraints.MaxPerASN {
            continue
        }

        // Check minimum distance from existing selections
        if !s.meetsMinDistanceRequirement(node, selected) {
            continue
        }

        selected = append(selected, node)
        countryCount[node.Country]++
        cityCount[node.City]++
        asnCount[node.ASN]++
    }

    // Verify minimum country diversity
    if len(countryCount) < s.geoConstraints.MinCountries {
        return nil, ErrInsufficientCountryDiversity{
            RegionID: s.regionID,
            Required: s.geoConstraints.MinCountries,
            Found:    len(countryCount),
        }
    }

    return selected, nil
}

// meetsMinDistanceRequirement checks geographic separation
func (s *RegionalVRFSelector) meetsMinDistanceRequirement(
    candidate NodeInfo,
    selected []NodeInfo,
) bool {
    for _, existing := range selected {
        distance := haversineDistance(
            candidate.Latitude, candidate.Longitude,
            existing.Latitude, existing.Longitude,
        )
        if distance < s.geoConstraints.MinDistanceKm {
            return false
        }
    }
    return true
}
```

### Cross-Certification Between Regional CAs

Adjacent regional CAs cross-sign each other's certificates for redundancy:

```go
// CrossCertificationProtocol manages inter-regional cross-signing
type CrossCertificationProtocol struct {
    localRegion    *RegionalCA
    adjacentRegions []*RegionalCA
}

// CrossCertificationRecord represents a cross-signing relationship
type CrossCertificationRecord struct {
    SourceRegion     string
    TargetRegion     string
    SourcePoolKey    []byte                // Source regional CA's group public key
    TargetPoolKey    []byte                // Target regional CA's group public key
    CrossSignature   []byte                // Source signing target's key
    ReverseSignature []byte                // Target signing source's key
    ValidFrom        time.Time
    ValidUntil       time.Time
    Epoch            uint64
}

// EstablishCrossCertification creates mutual cross-signing with adjacent region
func (p *CrossCertificationProtocol) EstablishCrossCertification(
    ctx context.Context,
    adjacentRegion *RegionalCA,
) (*CrossCertificationRecord, error) {
    // Step 1: Verify regions are adjacent
    if !p.areAdjacent(p.localRegion.RegionID, adjacentRegion.RegionID) {
        return nil, ErrRegionsNotAdjacent{
            Region1: p.localRegion.RegionID,
            Region2: adjacentRegion.RegionID,
        }
    }

    // Step 2: Exchange pool public keys
    localKey := p.localRegion.GetGroupPublicKey()
    adjacentKey := adjacentRegion.GetGroupPublicKey()

    // Step 3: Local region signs adjacent region's key
    crossSignData := EncodeCrossSignData(adjacentRegion.RegionID, adjacentKey)
    crossSig, err := p.localRegion.ThresholdSign(ctx, crossSignData)
    if err != nil {
        return nil, fmt.Errorf("cross-signing failed: %w", err)
    }

    // Step 4: Adjacent region signs local region's key
    reverseSignData := EncodeCrossSignData(p.localRegion.RegionID, localKey)
    reverseSig, err := adjacentRegion.ThresholdSign(ctx, reverseSignData)
    if err != nil {
        return nil, fmt.Errorf("reverse cross-signing failed: %w", err)
    }

    // Step 5: Create cross-certification record
    record := &CrossCertificationRecord{
        SourceRegion:     p.localRegion.RegionID,
        TargetRegion:     adjacentRegion.RegionID,
        SourcePoolKey:    localKey,
        TargetPoolKey:    adjacentKey,
        CrossSignature:   crossSig.Signature,
        ReverseSignature: reverseSig.Signature,
        ValidFrom:        time.Now(),
        ValidUntil:       time.Now().Add(2 * time.Hour), // Valid for 2 rotation cycles
        Epoch:            p.localRegion.CurrentEpoch,
    }

    // Step 6: Publish to DHT
    if err := PublishCrossCertification(ctx, record); err != nil {
        return nil, fmt.Errorf("cross-cert publish failed: %w", err)
    }

    return record, nil
}

// ValidateCrossCertifiedCertificate verifies a certificate through cross-certification
func ValidateCrossCertifiedCertificate(
    cert *x509.Certificate,
    primaryRegion *RegionalCA,
    crossCertRecords []*CrossCertificationRecord,
) error {
    // Try primary regional CA first
    if err := primaryRegion.VerifySignature(cert); err == nil {
        return nil // Valid with primary
    }

    // Fall back to cross-certified adjacent regions
    for _, record := range crossCertRecords {
        if record.TargetRegion == primaryRegion.RegionID {
            // Verify using source region's key with cross-certification
            adjacentRegion, err := GetRegionalCA(record.SourceRegion)
            if err != nil {
                continue
            }

            // Verify cross-certification is still valid
            if time.Now().After(record.ValidUntil) {
                continue
            }

            // Verify through adjacent region
            if err := adjacentRegion.VerifySignature(cert); err == nil {
                return nil // Valid through cross-certification
            }
        }
    }

    return ErrCertificateValidationFailed
}
```

---

### Regional CA Failure Recovery

Regional CA failures are detected and handled through automatic failover to geographically adjacent regions with subsequent recovery procedures.

> **Cross-Reference:** See [00-CONSTANTS.md Section 20.3](00-CONSTANTS.md#203-automatic-failover-triggers) for regional CA failure thresholds.

#### Detection Criteria

A Regional CA is considered failed when it misses **3 consecutive hourly rotations**. This 3-hour detection window balances rapid failure response against transient network issues.

```go
// RegionalCAFailureDetector monitors regional CA health
type RegionalCAFailureDetector struct {
    region            string
    missedRotations   int
    lastSuccessfulRot time.Time
    failureThreshold  int // 3 consecutive missed rotations
}

// CheckRegionalCAHealth evaluates if regional CA has failed
func (d *RegionalCAFailureDetector) CheckRegionalCAHealth(
    ctx context.Context,
    region *RegionalCA,
) *RegionalCAFailure {
    expectedRotations := d.getExpectedRotationsSince(d.lastSuccessfulRot)
    actualRotations := region.GetRotationCount()

    missedCount := expectedRotations - actualRotations
    if missedCount >= d.failureThreshold {
        return &RegionalCAFailure{
            RegionID:         region.RegionID,
            MissedRotations:  missedCount,
            LastSuccessful:   d.lastSuccessfulRot,
            DetectedAt:       time.Now(),
            FailureDuration:  time.Since(d.lastSuccessfulRot),
        }
    }

    return nil
}
```

#### Geographic Proximity Failover

When a Regional CA fails, certificate issuance fails over to the geographically adjacent region with the lowest latency.

```go
// AdjacentRegionFailover handles regional CA failure
type AdjacentRegionFailover struct {
    failedRegion     string
    adjacentRegions  []string    // Ordered by geographic proximity
    activeFailover   string      // Currently active failover region
}

// DefaultAdjacentRegions returns adjacent regions by geographic proximity
func DefaultAdjacentRegions() map[string][]string {
    return map[string][]string{
        "na-east":      {"na-west", "eu-west", "sa-north"},
        "na-west":      {"na-east", "asia-east", "oceania"},
        "eu-west":      {"eu-east", "africa-north", "na-east"},
        "eu-east":      {"eu-west", "central-asia", "middle-east"},
        "asia-east":    {"asia-se", "asia-south", "na-west"},
        "asia-south":   {"asia-se", "central-asia", "middle-east"},
        "asia-se":      {"asia-east", "asia-south", "oceania"},
        "oceania":      {"asia-se", "asia-east", "na-west"},
        "sa-north":     {"sa-south", "na-east", "africa-sub"},
        "sa-south":     {"sa-north", "africa-sub", "oceania"},
        "africa-north": {"africa-sub", "eu-west", "middle-east"},
        "africa-sub":   {"africa-north", "sa-south", "middle-east"},
        "middle-east":  {"eu-east", "central-asia", "africa-north"},
        "central-asia": {"asia-south", "eu-east", "middle-east"},
        "arctic":       {"na-west", "eu-east", "na-east"},
        "global-backup": {"na-east", "eu-west", "asia-east"},
    }
}

// FailoverToAdjacent redirects traffic to adjacent region
func (f *AdjacentRegionFailover) FailoverToAdjacent(
    ctx context.Context,
    failure *RegionalCAFailure,
) (*RegionalCA, error) {
    adjacents := DefaultAdjacentRegions()[failure.RegionID]

    for _, adjacentID := range adjacents {
        adjacentCA, err := GetRegionalCA(adjacentID)
        if err != nil {
            continue
        }

        // Verify adjacent region is healthy
        if adjacentCA.IsHealthy() && adjacentCA.HasCapacity() {
            f.activeFailover = adjacentID

            log.Printf("Regional CA failover: %s -> %s",
                failure.RegionID, adjacentID)

            // Notify adjacent region of increased load
            adjacentCA.NotifyFailoverLoad(failure.RegionID)

            return adjacentCA, nil
        }
    }

    // No healthy adjacent region - escalate to global-backup
    return GetRegionalCA("global-backup")
}
```

#### Recovery Procedure

Once a failed Regional CA's infrastructure stabilizes, a Re-DKG ceremony is conducted with surviving nodes from the affected region.

```go
// RegionalCARecovery manages recovery of a failed regional CA
type RegionalCARecovery struct {
    failedRegion     string
    survivingNodes   []NodeInfo
    recoveryStatus   RecoveryStatus
}

// RecoverRegionalCA performs Re-DKG with surviving nodes
func (r *RegionalCARecovery) RecoverRegionalCA(
    ctx context.Context,
    failure *RegionalCAFailure,
) error {
    // Step 1: Identify surviving nodes from affected region
    allRegionalNodes, err := GetNodesInRegion(ctx, failure.RegionID)
    if err != nil {
        return fmt.Errorf("node lookup failed: %w", err)
    }

    survivingNodes := make([]NodeInfo, 0)
    for _, node := range allRegionalNodes {
        if IsNodeOnline(ctx, node.NodeID) && node.PassedRecentAttestation() {
            survivingNodes = append(survivingNodes, node)
        }
    }

    // Step 2: Verify minimum pool size
    minNodes := 100 // Minimum for regional CA
    if len(survivingNodes) < minNodes {
        // Insufficient survivors - recruit from adjacent regions
        survivingNodes = r.recruitFromAdjacent(ctx, survivingNodes, minNodes)
    }

    // Step 3: Execute Re-DKG ceremony
    dkgResult, err := RunRegionalDKG(ctx, failure.RegionID, survivingNodes, RegionalDKGConfig{
        Duration:  5 * time.Minute,
        Threshold: len(survivingNodes) / 3,
    })
    if err != nil {
        return fmt.Errorf("Re-DKG failed: %w", err)
    }

    // Step 4: Create new regional CA pool
    newPool := &RegionalCA{
        RegionID:      failure.RegionID,
        PoolSize:      len(survivingNodes),
        Threshold:     dkgResult.Threshold,
        ActiveNodes:   ExtractNodeIDs(survivingNodes),
        GroupPubKey:   dkgResult.GroupPublicKey,
        LastRotation:  time.Now(),
        NextRotation:  time.Now().Add(1 * time.Hour),
        IsRecovered:   true,
        RecoveryEpoch: failure.DetectedAt,
    }

    // Step 5: Establish cross-certification with adjacent regions
    adjacents := DefaultAdjacentRegions()[failure.RegionID]
    for _, adjacentID := range adjacents[:2] { // Cross-sign with 2 closest
        if err := EstablishCrossCertification(ctx, newPool, adjacentID); err != nil {
            log.Printf("Cross-certification with %s failed: %v", adjacentID, err)
        }
    }

    // Step 6: Activate recovered regional CA
    if err := ActivateRegionalCA(ctx, newPool); err != nil {
        return fmt.Errorf("activation failed: %w", err)
    }

    // Step 7: Terminate failover to adjacent region
    if err := TerminateFailover(ctx, failure.RegionID); err != nil {
        log.Printf("Failover termination warning: %v", err)
    }

    log.Printf("Regional CA %s recovered with %d nodes",
        failure.RegionID, len(survivingNodes))

    return nil
}
```

---

### Tier 1 Annual Rotation Ceremony

The Global Root CA (Tier 1) rotates annually through a coordinated ceremony involving all 100 geographically distributed trustees.

> **Cross-Reference:** See [00-CONSTANTS.md Section 11.1](00-CONSTANTS.md#111-ca-tier-structure) for tier rotation periods.

#### Pre-Ceremony Requirements

| Requirement | Value | Description |
|-------------|-------|-------------|
| Advance Notice | 30 days | Minimum notice to all trustees before ceremony |
| Trustee Verification | Identity + Availability | Each trustee must confirm identity and availability |
| Emergency Quorum | 67/100 | Relaxed threshold for ceremony (normal: 33/100) |
| Ceremony Window | 48 hours | Maximum duration for ceremony completion |

```go
// Tier1RotationCeremony manages the annual Global Root CA rotation
type Tier1RotationCeremony struct {
    scheduledDate     time.Time
    advanceNoticeDays int           // 30 days required
    emergencyQuorum   int           // 67 of 100 trustees
    normalQuorum      int           // 33 of 100 trustees
    ceremonyWindow    time.Duration // 48 hours
    trustees          []GlobalRootTrustee
    verifiedTrustees  map[string]*TrusteeVerification
}

// TrusteeVerification records trustee readiness for ceremony
type TrusteeVerification struct {
    TrusteeID          string
    IdentityVerified   bool
    IdentityMethod     IdentityVerificationMethod
    AvailabilityConfirmed bool
    ConfirmedAt        time.Time
    ContactMethods     []string // Verified contact channels
    BackupContact      string   // Emergency backup contact
}

type IdentityVerificationMethod uint8

const (
    IdentityPGPSignature   IdentityVerificationMethod = iota // PGP-signed challenge
    IdentityHardwareToken                                     // Hardware security key
    IdentityVideoCall                                         // Live video verification
    IdentityNotarized                                         // Notarized attestation
)

// InitiateTier1Rotation starts the annual rotation process
func (c *Tier1RotationCeremony) InitiateTier1Rotation(
    ctx context.Context,
) error {
    // Verify 30-day advance notice
    if time.Until(c.scheduledDate) < 30*24*time.Hour {
        return ErrInsufficientAdvanceNotice{
            Required: 30 * 24 * time.Hour,
            Actual:   time.Until(c.scheduledDate),
        }
    }

    // Step 1: Send advance notice to all trustees
    for _, trustee := range c.trustees {
        notice := &CeremonyNotice{
            Type:          NoticeTier1Rotation,
            ScheduledDate: c.scheduledDate,
            CeremonyWindow: c.ceremonyWindow,
            RequiredActions: []string{
                "Confirm identity via PGP-signed response",
                "Confirm availability for 48-hour ceremony window",
                "Verify access to share recovery materials",
                "Test secure communication channels",
            },
            ResponseDeadline: c.scheduledDate.Add(-7 * 24 * time.Hour),
        }

        if err := SendCeremonyNotice(ctx, trustee, notice); err != nil {
            log.Printf("Notice delivery failed for %s: %v", trustee.ID, err)
        }
    }

    return nil
}

// VerifyTrusteeReadiness confirms trustee identity and availability
func (c *Tier1RotationCeremony) VerifyTrusteeReadiness(
    ctx context.Context,
    trusteeID string,
    verification *TrusteeVerification,
) error {
    // Verify identity using at least two methods
    identityMethods := 0
    if verification.IdentityMethod != 0 {
        identityMethods++
    }
    // Additional verification methods checked here

    if identityMethods < 1 {
        return ErrInsufficientIdentityVerification{
            TrusteeID: trusteeID,
            Required:  1,
            Provided:  identityMethods,
        }
    }

    // Verify availability confirmation
    if !verification.AvailabilityConfirmed {
        return ErrAvailabilityNotConfirmed{TrusteeID: trusteeID}
    }

    // Store verification
    c.verifiedTrustees[trusteeID] = verification

    return nil
}

// ExecuteCeremony performs the 48-hour rotation ceremony
func (c *Tier1RotationCeremony) ExecuteCeremony(
    ctx context.Context,
) (*Tier1RotationResult, error) {
    // Verify emergency quorum is met
    verifiedCount := len(c.verifiedTrustees)
    if verifiedCount < c.emergencyQuorum {
        return nil, ErrInsufficientVerifiedTrustees{
            Required: c.emergencyQuorum,
            Verified: verifiedCount,
        }
    }

    ceremonyCtx, cancel := context.WithTimeout(ctx, c.ceremonyWindow)
    defer cancel()

    // Phase 1: Collect current share fragments (hours 0-12)
    shares, err := c.collectShareFragments(ceremonyCtx)
    if err != nil {
        return nil, fmt.Errorf("share collection failed: %w", err)
    }

    // Phase 2: Reconstruct and rotate key (hours 12-24)
    newKeyPair, err := c.rotateGlobalRootKey(ceremonyCtx, shares)
    if err != nil {
        return nil, fmt.Errorf("key rotation failed: %w", err)
    }

    // Phase 3: Distribute new shares (hours 24-36)
    if err := c.distributeNewShares(ceremonyCtx, newKeyPair); err != nil {
        return nil, fmt.Errorf("share distribution failed: %w", err)
    }

    // Phase 4: Cross-certify all Regional CAs (hours 36-48)
    if err := c.crossCertifyRegionalCAs(ceremonyCtx, newKeyPair); err != nil {
        return nil, fmt.Errorf("cross-certification failed: %w", err)
    }

    return &Tier1RotationResult{
        NewPublicKey:     &newKeyPair.PublicKey,
        CeremonyDuration: time.Since(c.scheduledDate),
        ParticipatingTrustees: verifiedCount,
        CrossCertifiedRegions: 16,
    }, nil
}
```

---

### DKG Bandwidth Requirements

Each CA tier has specific bandwidth requirements during DKG ceremonies and steady-state operation.

> **Cross-Reference:** See [00-CONSTANTS.md Section 18.4](00-CONSTANTS.md#184-per-tier-resource-budgets) for resource budgets.

| Tier | Role | During DKG | Steady State | Rationale |
|------|------|------------|--------------|-----------|
| Global Root (Tier 1) | 100 trustees | 100 Mbps | 10 Mbps | Annual ceremony with large share distribution |
| Regional CA (Tier 2) | 1,000 nodes | 25 Mbps | 5 Mbps | Hourly rotation with moderate message volume |
| Local Issuer (Tier 3) | 100 nodes | 10 Mbps | 2 Mbps | 24-hour rotation with local scope |

```go
// DKGBandwidthRequirements defines per-tier bandwidth minimums
type DKGBandwidthRequirements struct {
    Tier           CATier
    DuringDKG      int64 // Bits per second
    SteadyState    int64 // Bits per second
}

func GetDKGBandwidthRequirements(tier CATier) *DKGBandwidthRequirements {
    switch tier {
    case TierGlobalRoot:
        return &DKGBandwidthRequirements{
            Tier:        TierGlobalRoot,
            DuringDKG:   100 * 1_000_000, // 100 Mbps
            SteadyState: 10 * 1_000_000,  // 10 Mbps
        }
    case TierRegionalCA:
        return &DKGBandwidthRequirements{
            Tier:        TierRegionalCA,
            DuringDKG:   25 * 1_000_000, // 25 Mbps
            SteadyState: 5 * 1_000_000,  // 5 Mbps
        }
    case TierLocalIssuer:
        return &DKGBandwidthRequirements{
            Tier:        TierLocalIssuer,
            DuringDKG:   10 * 1_000_000, // 10 Mbps
            SteadyState: 2 * 1_000_000,  // 2 Mbps
        }
    default:
        return nil
    }
}

// ValidateNodeBandwidth ensures node meets tier requirements
func ValidateNodeBandwidth(node *NodeInfo, tier CATier) error {
    requirements := GetDKGBandwidthRequirements(tier)
    if requirements == nil {
        return ErrUnknownCATier{Tier: tier}
    }

    measuredBandwidth := node.MeasuredBandwidth
    if measuredBandwidth < requirements.DuringDKG {
        return ErrInsufficientBandwidth{
            NodeID:   node.NodeID,
            Tier:     tier,
            Required: requirements.DuringDKG,
            Measured: measuredBandwidth,
        }
    }

    return nil
}
```

---

### CA Pool Health Monitoring

Continuous health monitoring ensures CA pools maintain signing availability with rapid failure detection and recovery.

> **Cross-Reference:** See [00-CONSTANTS.md Section 20](00-CONSTANTS.md#20-ca-pool-health-monitoring) for health monitoring constants.

#### Health Monitoring Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Health Check Interval | 5 minutes | Frequency of pool-wide health assessments |
| Failure Detection Window | 15 minutes | Maximum time to detect pool degradation |
| Recovery SLA | 1 hour | Target time from detection to full recovery |
| Heartbeat Interval | 30 seconds | Frequency of individual member heartbeats |
| Missed Heartbeats Threshold | 6 | Heartbeats missed before member flagged unhealthy |

```go
// CAPoolHealthMonitor continuously monitors pool health
type CAPoolHealthMonitor struct {
    pool                  *CAPool
    healthCheckInterval   time.Duration // 5 minutes
    failureDetectionWindow time.Duration // 15 minutes
    recoverySLA           time.Duration // 1 hour
    heartbeatInterval     time.Duration // 30 seconds
    missedHeartbeatThreshold int        // 6 heartbeats
    memberHealth          map[NodeID]*MemberHealthStatus
    poolHealthHistory     []PoolHealthSnapshot
}

// MemberHealthStatus tracks individual pool member health
type MemberHealthStatus struct {
    NodeID             NodeID
    LastHeartbeat      time.Time
    MissedHeartbeats   int
    IsHealthy          bool
    SigningLatencyP99  time.Duration
    AttestationValid   bool
    LastAttestationAt  time.Time
}

// PoolHealthSnapshot captures point-in-time pool health
type PoolHealthSnapshot struct {
    Timestamp          time.Time
    HealthyMembers     int
    TotalMembers       int
    HealthPercentage   float64
    SigningLatencyP99  time.Duration
    IssuanceRate       float64 // Certificates per second
}

// StartHealthMonitoring begins continuous health monitoring
func (m *CAPoolHealthMonitor) StartHealthMonitoring(ctx context.Context) {
    // Start heartbeat receiver
    go m.receiveHeartbeats(ctx)

    // Start periodic health checks
    ticker := time.NewTicker(m.healthCheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.performHealthCheck(ctx)
        }
    }
}

// performHealthCheck evaluates pool health
func (m *CAPoolHealthMonitor) performHealthCheck(ctx context.Context) {
    now := time.Now()
    healthyCount := 0

    for nodeID, status := range m.memberHealth {
        // Check heartbeat freshness
        timeSinceHeartbeat := now.Sub(status.LastHeartbeat)
        expectedHeartbeats := int(timeSinceHeartbeat / m.heartbeatInterval)

        if expectedHeartbeats > m.missedHeartbeatThreshold {
            status.IsHealthy = false
            status.MissedHeartbeats = expectedHeartbeats
            m.handleUnhealthyMember(ctx, nodeID, status)
        } else {
            status.IsHealthy = true
            status.MissedHeartbeats = 0
            healthyCount++
        }

        m.memberHealth[nodeID] = status
    }

    // Create health snapshot
    snapshot := PoolHealthSnapshot{
        Timestamp:        now,
        HealthyMembers:   healthyCount,
        TotalMembers:     len(m.memberHealth),
        HealthPercentage: float64(healthyCount) / float64(len(m.memberHealth)),
        SigningLatencyP99: m.calculatePoolLatency(),
        IssuanceRate:     m.calculateIssuanceRate(),
    }

    m.poolHealthHistory = append(m.poolHealthHistory, snapshot)

    // Check for pool-level failures
    m.checkPoolHealthThresholds(ctx, snapshot)
}

// checkPoolHealthThresholds triggers alerts and failover
func (m *CAPoolHealthMonitor) checkPoolHealthThresholds(
    ctx context.Context,
    snapshot PoolHealthSnapshot,
) {
    switch {
    case snapshot.HealthPercentage < 0.34:
        // Critical: Below quorum - emergency DKG required
        m.triggerEmergencyDKG(ctx, "Pool below quorum threshold")

    case snapshot.HealthPercentage < 0.67:
        // Warning: Pool degraded - accelerate standby promotion
        m.accelerateStandbyPromotion(ctx)

    case snapshot.HealthPercentage < 0.80:
        // Alert: Pool approaching degradation
        m.sendPoolHealthAlert(ctx, AlertSeverityWarning, snapshot)
    }

    // Check signing latency
    if snapshot.SigningLatencyP99 > 2*time.Second {
        m.sendPoolHealthAlert(ctx, AlertSeverityCritical, snapshot)
    }
}
```

---

### Standby Pool Management

Standby pools provide rapid replacement capacity for failed active pool members while maintaining share fragment integrity.

> **Cross-Reference:** See [00-CONSTANTS.md Section 20.2](00-CONSTANTS.md#202-standby-pool-management) for standby pool constants.

#### Standby Pool Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Standby Pool Size | 20% of active pool | Minimum 10 members |
| Share Fragment Maintenance | Yes | Standby nodes hold encrypted share fragments |
| Signing Rights | No | Standby nodes cannot participate in signing |
| Promotion Approval | 67% | Active pool approval required for promotion |
| Standby Rotation | 30 days | Rotation interval for standby membership |
| Share Refresh | 7 days | Frequency of share fragment refresh |

```go
// StandbyPoolManager manages standby CA pool members
type StandbyPoolManager struct {
    activePool           *CAPool
    standbyMembers       []StandbyMember
    standbyRatio         float64       // 0.20 (20%)
    minStandbySize       int           // 10 minimum
    promotionQuorum      float64       // 0.67 (67%)
    rotationInterval     time.Duration // 30 days
    shareRefreshInterval time.Duration // 7 days
}

// StandbyMember represents a node in the standby pool
type StandbyMember struct {
    NodeID             NodeID
    JoinedStandbyAt    time.Time
    ShareFragments     []EncryptedShareFragment // Cannot be used for signing
    LastShareRefresh   time.Time
    PromotionEligible  bool
    HealthStatus       MemberHealthStatus
}

// EncryptedShareFragment holds a share piece without signing capability
type EncryptedShareFragment struct {
    FragmentID       string
    EncryptedData    []byte   // Encrypted with pool public key
    FragmentIndex    int
    ExpiresAt        time.Time
    RefreshRequired  bool
}

// CalculateStandbyPoolSize determines required standby size
func (m *StandbyPoolManager) CalculateStandbyPoolSize() int {
    activeSize := m.activePool.GetMemberCount()
    calculatedSize := int(float64(activeSize) * m.standbyRatio)

    if calculatedSize < m.minStandbySize {
        return m.minStandbySize
    }
    return calculatedSize
}

// PromoteToActive promotes a standby member to active pool
func (m *StandbyPoolManager) PromoteToActive(
    ctx context.Context,
    standbyNodeID NodeID,
) error {
    // Step 1: Verify standby member exists and is eligible
    standby, err := m.getStandbyMember(standbyNodeID)
    if err != nil {
        return fmt.Errorf("standby member not found: %w", err)
    }

    if !standby.PromotionEligible {
        return ErrStandbyNotEligible{NodeID: standbyNodeID}
    }

    // Step 2: Request promotion approval from active pool
    approvalRequest := &PromotionRequest{
        StandbyNodeID: standbyNodeID,
        RequestedAt:   time.Now(),
        Reason:        "Active member failure replacement",
    }

    approvalVotes, err := m.collectPromotionVotes(ctx, approvalRequest)
    if err != nil {
        return fmt.Errorf("vote collection failed: %w", err)
    }

    // Step 3: Verify 67% approval threshold
    totalActive := m.activePool.GetMemberCount()
    approvalPercentage := float64(approvalVotes) / float64(totalActive)

    if approvalPercentage < m.promotionQuorum {
        return ErrInsufficientPromotionApproval{
            Required: m.promotionQuorum,
            Received: approvalPercentage,
        }
    }

    // Step 4: Convert share fragments to active shares
    activeShares, err := m.convertFragmentsToActiveShares(ctx, standby)
    if err != nil {
        return fmt.Errorf("share conversion failed: %w", err)
    }

    // Step 5: Add to active pool
    if err := m.activePool.AddMember(ctx, standbyNodeID, activeShares); err != nil {
        return fmt.Errorf("active pool addition failed: %w", err)
    }

    // Step 6: Remove from standby pool
    m.removeFromStandby(standbyNodeID)

    // Step 7: Recruit replacement standby
    go m.recruitStandbyReplacement(ctx)

    log.Printf("Promoted standby %s to active pool (approval: %.1f%%)",
        standbyNodeID, approvalPercentage*100)

    return nil
}

// RefreshShareFragments updates standby share fragments
func (m *StandbyPoolManager) RefreshShareFragments(ctx context.Context) error {
    for i, standby := range m.standbyMembers {
        // Check if refresh is needed
        if time.Since(standby.LastShareRefresh) < m.shareRefreshInterval {
            continue
        }

        // Generate new share fragments from active pool
        newFragments, err := m.activePool.GenerateShareFragments(ctx, standby.NodeID)
        if err != nil {
            log.Printf("Share fragment refresh failed for %s: %v",
                standby.NodeID, err)
            continue
        }

        // Update standby member
        m.standbyMembers[i].ShareFragments = newFragments
        m.standbyMembers[i].LastShareRefresh = time.Now()

        log.Printf("Refreshed share fragments for standby %s", standby.NodeID)
    }

    return nil
}

// RotateStandbyPool rotates standby membership
func (m *StandbyPoolManager) RotateStandbyPool(ctx context.Context) error {
    now := time.Now()

    // Identify standby members due for rotation
    toRotate := make([]NodeID, 0)
    for _, standby := range m.standbyMembers {
        if now.Sub(standby.JoinedStandbyAt) >= m.rotationInterval {
            toRotate = append(toRotate, standby.NodeID)
        }
    }

    // Rotate 25% of eligible members per cycle
    rotationCount := len(toRotate) / 4
    if rotationCount < 1 {
        rotationCount = 1
    }

    for i := 0; i < rotationCount && i < len(toRotate); i++ {
        nodeID := toRotate[i]

        // Remove from standby
        m.removeFromStandby(nodeID)

        // Node returns to general eligibility pool
        log.Printf("Rotated standby member %s out of pool", nodeID)
    }

    // Recruit replacements
    return m.recruitStandbyReplacements(ctx, rotationCount)
}

// EnsureStandbyPoolSize maintains minimum standby pool size
func (m *StandbyPoolManager) EnsureStandbyPoolSize(ctx context.Context) error {
    requiredSize := m.CalculateStandbyPoolSize()
    currentSize := len(m.standbyMembers)

    if currentSize < requiredSize {
        deficit := requiredSize - currentSize
        return m.recruitStandbyReplacements(ctx, deficit)
    }

    return nil
}
```

---

## TPM Attestation

### 100% Required for CA Participation

```go
func IsEligibleForCAPool(node Node) bool {
    return node.HasTPM() &&                // TPM hardware present
           node.PassedAttestation() &&      // 100% REQUIRED
           node.Reputation > 0.80 &&        // Minimum reputation score
           node.Uptime > 0.95 &&            // 95%+ uptime over 30 days
           node.Bandwidth > MinBandwidth    // Sufficient bandwidth
}
```

**No TPM = No CA Participation.**

### Attestation Process

1. Pool selection begins
2. Filter all nodes: HasTPM() == true
3. Request fresh TPM attestation quote from each
4. Verify quote against TPM Endorsement Key certificate
5. Check Platform Configuration Registers (PCRs) match expected state
6. Only nodes with SUCCESSFUL attestation proceed to DKG
7. Failed attestation -> excluded from this rotation
8. Repeated failures -> reputation penalty

### Bandwidth Requirements

- **Leaf node:** 10 Mbps+ (~100 signatures/hour)
- **Hub node:** 100 Mbps+ (~1000 signatures/hour)
- **Coordinator:** 1 Gbps+ (~10K signatures/hour)

---

## Pool Selection Algorithm

### Anti-Cartel VRF-Based Selection (Issue #8 Fix)

High-reputation nodes could theoretically collude to control CA pools. The VRF-based selection with diversity requirements prevents cartel formation through cryptographic randomness and mandatory diversity constraints.

#### VRF Selection Protocol

```go
// VRFPoolSelector implements cartel-resistant pool selection
type VRFPoolSelector struct {
    genesisVRFSeed  [32]byte           // Immutable genesis randomness
    epochRandomness map[uint64][32]byte // Per-epoch VRF outputs
}

// VRFProof is a verifiable random function proof
type VRFProof struct {
    PublicKey  ed25519.PublicKey // Prover's VRF public key
    Output     [32]byte          // Deterministic random output
    Proof      [80]byte          // ECVRF proof (RFC 9381)
}

// SelectPoolMembers uses VRF for unpredictable but verifiable selection
func (s *VRFPoolSelector) SelectPoolMembers(
    epoch uint64,
    candidates []NodeInfo,
    poolSize int,
) ([]NodeInfo, error) {
    // Step 1: Generate epoch randomness from previous block hash + genesis seed
    epochSeed := s.deriveEpochSeed(epoch)

    // Step 2: Each candidate computes VRF proof
    type scoredNode struct {
        Node     NodeInfo
        VRFScore *big.Int
        Proof    VRFProof
    }
    scoredNodes := make([]scoredNode, 0, len(candidates))

    for _, candidate := range candidates {
        // VRF input = epoch_seed || node_id
        vrfInput := append(epochSeed[:], candidate.NodeID[:]...)

        // Each node proves their VRF output
        proof, err := candidate.ComputeVRF(vrfInput)
        if err != nil {
            continue // Skip nodes that cannot prove
        }

        // Score = VRF_output (uniform random in [0, 2^256))
        // Reputation is NOT used as multiplier to prevent gaming
        score := new(big.Int).SetBytes(proof.Output[:])

        scoredNodes = append(scoredNodes, scoredNode{
            Node:     candidate,
            VRFScore: score,
            Proof:    proof,
        })
    }

    // Step 3: Sort by VRF score (deterministic ordering)
    sort.Slice(scoredNodes, func(i, j int) bool {
        return scoredNodes[i].VRFScore.Cmp(scoredNodes[j].VRFScore) < 0
    })

    // Step 4: Apply diversity constraints during selection
    selected := s.applyDiversityConstraints(scoredNodes, poolSize)

    // Step 5: Verify anti-cartel properties
    if err := s.verifyAntiCartelProperties(selected); err != nil {
        return nil, fmt.Errorf("cartel detection failed: %w", err)
    }

    return selected, nil
}

// deriveEpochSeed creates unpredictable but verifiable randomness
func (s *VRFPoolSelector) deriveEpochSeed(epoch uint64) [32]byte {
    // Combine genesis seed with recent unpredictable data
    // - Previous epoch's aggregate signature (unpredictable before epoch end)
    // - Block hash from external blockchain (Bitcoin/Ethereum for additional entropy)
    prevSig := GetPreviousEpochSignature(epoch - 1)
    externalEntropy := GetExternalBlockHash(epoch)

    h := sha256.New()
    h.Write(s.genesisVRFSeed[:])
    h.Write(prevSig)
    h.Write(externalEntropy)
    binary.Write(h, binary.BigEndian, epoch)

    var seed [32]byte
    copy(seed[:], h.Sum(nil))
    return seed
}
```

#### Diversity Requirements

```go
// DiversityConstraints enforces pool heterogeneity
type DiversityConstraints struct {
    // Geographic diversity
    MaxPerRegion      float64 // Max 30% from any single region
    MinRegions        int     // At least 5 regions represented

    // Vendor diversity
    MaxPerVendor      float64 // Max 25% from any TPM vendor
    MinVendors        int     // At least 3 TPM vendors

    // Age diversity (prevents old-node cartels)
    MaxOldNodes       float64 // Max 40% with age > 1 year
    MinNewNodes       float64 // At least 20% with age < 90 days

    // Reputation diversity (prevents reputation cartel)
    MaxEliteNodes     float64 // Max 30% with reputation > 0.95
    ReputationBuckets int     // Distribute across 5 reputation bands
}

// applyDiversityConstraints selects nodes while enforcing diversity
func (s *VRFPoolSelector) applyDiversityConstraints(
    candidates []scoredNode,
    poolSize int,
) []NodeInfo {
    constraints := DefaultDiversityConstraints()

    selected := make([]NodeInfo, 0, poolSize)
    regionCount := make(map[string]int)
    vendorCount := make(map[string]int)
    ageDistribution := &AgeDistribution{}
    repBuckets := make([]int, 5) // 5 reputation bands

    for _, candidate := range candidates {
        if len(selected) >= poolSize {
            break
        }

        node := candidate.Node

        // Check region constraint
        if float64(regionCount[node.Region]+1)/float64(poolSize) > constraints.MaxPerRegion {
            continue // Skip: would exceed region limit
        }

        // Check vendor constraint
        if float64(vendorCount[node.TPMVendor]+1)/float64(poolSize) > constraints.MaxPerVendor {
            continue // Skip: would exceed vendor limit
        }

        // Check age constraint
        if node.Age > 365*24*time.Hour {
            if float64(ageDistribution.OldCount+1)/float64(poolSize) > constraints.MaxOldNodes {
                continue // Skip: too many old nodes
            }
        }

        // Check reputation bucket constraint
        bucket := int(node.Reputation * 5) // 0-4
        if bucket == 4 { // Elite nodes (0.95+)
            if float64(repBuckets[4]+1)/float64(poolSize) > constraints.MaxEliteNodes {
                continue // Skip: too many elite nodes
            }
        }

        // Node passes all constraints
        selected = append(selected, node)
        regionCount[node.Region]++
        vendorCount[node.TPMVendor]++
        if node.Age > 365*24*time.Hour {
            ageDistribution.OldCount++
        } else if node.Age < 90*24*time.Hour {
            ageDistribution.NewCount++
        }
        repBuckets[bucket]++
    }

    return selected
}

// DefaultDiversityConstraints returns production diversity settings
func DefaultDiversityConstraints() *DiversityConstraints {
    return &DiversityConstraints{
        MaxPerRegion:      0.30, // 30% max from any region
        MinRegions:        5,    // At least 5 regions
        MaxPerVendor:      0.25, // 25% max from any TPM vendor
        MinVendors:        3,    // At least 3 vendors
        MaxOldNodes:       0.40, // 40% max older than 1 year
        MinNewNodes:       0.20, // 20% min newer than 90 days
        MaxEliteNodes:     0.30, // 30% max with 0.95+ reputation
        ReputationBuckets: 5,    // Distribute across 5 bands
    }
}
```

#### Network Diversity Constraints for CA Pool Selection

Beyond the geographic and vendor diversity above, the CA pool enforces strict network topology constraints to prevent Sybil attacks where an attacker controls multiple nodes from concentrated network locations.

> **Cross-Reference:** See [00-CONSTANTS.md Section 17.1](00-CONSTANTS.md#171-network-diversity-requirements) for the canonical network diversity constant values.

```go
// CAPoolNetworkConstraints enforces network topology diversity
type CAPoolNetworkConstraints struct {
    // ASN diversity prevents single ISP dominance
    MaxPercentPerASN  float64 // 0.15 (15% max from any single ASN)
    MinUniqueASNs     int     // 7 minimum unique ASNs required

    // Subnet diversity prevents co-location attacks
    MaxPercentPerSubnet24 float64 // 0.03 (3% max from any /24 subnet)
    MaxNodesPerSubnet     int     // 5 maximum nodes per /24 subnet

    // Country diversity ensures global distribution
    MaxPercentPerCountry float64 // 0.25 (25% max from any single country)
    MinCountries         int     // 3 minimum countries required
}

// DefaultCAPoolNetworkConstraints returns production network constraints
func DefaultCAPoolNetworkConstraints() *CAPoolNetworkConstraints {
    return &CAPoolNetworkConstraints{
        MaxPercentPerASN:      0.15, // Max 15% per ASN
        MinUniqueASNs:         7,    // Min 7 ASNs
        MaxPercentPerSubnet24: 0.03, // Max 3% per /24
        MaxNodesPerSubnet:     5,    // Max 5 nodes per subnet
        MaxPercentPerCountry:  0.25, // Max 25% per country
        MinCountries:          3,    // Min 3 countries
    }
}

// applyNetworkConstraints filters candidates based on network topology
func (s *VRFPoolSelector) applyNetworkConstraints(
    candidates []scoredNode,
    poolSize int,
    constraints *CAPoolNetworkConstraints,
) []scoredNode {
    asnCount := make(map[uint32]int)
    subnetCount := make(map[string]int)
    countryCount := make(map[string]int)

    filtered := make([]scoredNode, 0, len(candidates))

    for _, candidate := range candidates {
        node := candidate.Node

        // Check ASN constraint
        if float64(asnCount[node.ASN]+1)/float64(poolSize) > constraints.MaxPercentPerASN {
            continue // Would exceed ASN limit
        }

        // Check subnet constraint (/24)
        subnet := node.IP.Mask(net.CIDRMask(24, 32)).String()
        if subnetCount[subnet]+1 > constraints.MaxNodesPerSubnet {
            continue // Would exceed subnet limit
        }
        if float64(subnetCount[subnet]+1)/float64(poolSize) > constraints.MaxPercentPerSubnet24 {
            continue // Would exceed subnet percentage
        }

        // Check country constraint
        if float64(countryCount[node.Country]+1)/float64(poolSize) > constraints.MaxPercentPerCountry {
            continue // Would exceed country limit
        }

        // Node passes network constraints
        filtered = append(filtered, candidate)
        asnCount[node.ASN]++
        subnetCount[subnet]++
        countryCount[node.Country]++
    }

    return filtered
}
```

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| ASN | Max 15% per ASN, Min 7 ASNs | Prevents single ISP dominance |
| Subnet | Max 3% per /24, Max 5 nodes/subnet | Prevents co-location attacks |
| Country | Max 25% per country, Min 3 countries | Geographic distribution |

#### Organization-Based CA Pool Constraints

To prevent Sybil attacks where an attacker acquires multiple TPM devices, CA pool selection enforces organization-level limits. Organizations are verified through domain verification or economic staking.

```go
// OrganizationConstraints limits single-organization control
type OrganizationConstraints struct {
    // Maximum percentage of pool from any single organization
    MaxPercentPerOrg float64 // 0.05 (5% max)

    // Minimum unique organizations required (at network maturity)
    MinUniqueOrgs int // 20

    // Bootstrap thresholds (relaxed during early network growth)
    BootstrapMinOrgs map[int]int // Network size -> min orgs required
}

// DefaultOrganizationConstraints returns production organization limits
func DefaultOrganizationConstraints() *OrganizationConstraints {
    return &OrganizationConstraints{
        MaxPercentPerOrg: 0.05, // Max 5% per organization
        MinUniqueOrgs:    20,   // Min 20 organizations at maturity
        BootstrapMinOrgs: map[int]int{
            100:   3,  // 0-100 nodes: 3 orgs minimum
            1000:  5,  // 100-1000 nodes: 5 orgs minimum
            10000: 10, // 1000-10000 nodes: 10 orgs minimum
            // 10000+ nodes: full 20 orgs requirement
        },
    }
}

// verifyOrganizationDiversity validates org distribution in pool
func (s *VRFPoolSelector) verifyOrganizationDiversity(
    selected []NodeInfo,
    constraints *OrganizationConstraints,
) error {
    orgCounts := make(map[string]int)
    for _, node := range selected {
        orgCounts[node.OrganizationID]++
    }

    // Check single-org limit
    for orgID, count := range orgCounts {
        if float64(count)/float64(len(selected)) > constraints.MaxPercentPerOrg {
            return ErrOrganizationExceedsThreshold{
                OrgID:      orgID,
                MaxAllowed: constraints.MaxPercentPerOrg,
                Actual:     float64(count) / float64(len(selected)),
            }
        }
    }

    // Check minimum unique organizations
    minRequired := constraints.getMinOrgsForNetworkSize(len(selected))
    if len(orgCounts) < minRequired {
        return ErrInsufficientOrganizationDiversity{
            Required: minRequired,
            Actual:   len(orgCounts),
        }
    }

    return nil
}
```

> **Cross-Reference:** See [26-organization-identity.md](26-organization-identity.md) for organization verification protocols (domain and economic verification).

#### TPM Tier Requirements for CA Pool

Only nodes with discrete hardware TPMs from whitelisted manufacturers are eligible for CA pool participation. This prevents attacks using virtual or firmware TPMs which can be more easily compromised.

```go
// TPMTier classifies TPM implementations by security level
type TPMTier uint8

const (
    // TPMTierHardware: Discrete hardware TPM (highest security)
    // Eligible for CA pool participation
    TPMTierHardware TPMTier = 1

    // TPMTierFirmware: Firmware TPM (Intel PTT, AMD fTPM)
    // Infrastructure only, NOT CA pool eligible
    TPMTierFirmware TPMTier = 2

    // TPMTierCloud: Virtual TPM (AWS Nitro, Azure, GCP)
    // Infrastructure only, NOT CA pool eligible
    TPMTierCloud TPMTier = 3

    // TPMTierPlatform: Platform-minted EK (foundation backbone)
    // Infrastructure only, NOT CA pool eligible
    TPMTierPlatform TPMTier = 4
)

// IsCAPoolEligible returns true only for discrete hardware TPMs
func IsCAPoolEligible(node *NodeInfo) bool {
    return node.TPMTier == TPMTierHardware
}

// IsInfrastructureEligible returns true for all TPM tiers
func IsInfrastructureEligible(node *NodeInfo) bool {
    return node.TPMTier <= TPMTierPlatform
}
```

| TPM Type | CA Pool Eligible | Infrastructure Eligible |
|----------|------------------|-------------------------|
| Discrete Hardware TPM | Yes | Yes |
| Firmware TPM (fTPM) | No | Yes |
| Cloud vTPM (Nitro, etc.) | No | Yes |
| Platform-Minted EK | No | Yes (backbone only) |

**Manufacturer CA Whitelist for Hardware TPM:**

Hardware TPMs must have an EK certificate chain rooted at an approved manufacturer CA:

- Infineon Technologies
- STMicroelectronics
- Nuvoton Technology
- Microchip/Atmel
- Nations Technologies
- Additional manufacturers added via governance process

#### CA Pool Staking Requirements

Economic staking creates financial accountability for CA pool participants. Stakes are slashable for misconduct, providing a strong disincentive against attacks.

```go
// CAPoolStakeRequirements defines staking parameters
type CAPoolStakeRequirements struct {
    // Organization stake (one-time per org, alternative to domain verification)
    OrganizationStake     uint64        // 1,000 coins
    OrgStakeLockDuration  time.Duration // 180 days

    // Per-node stake for CA pool participation
    BaseNodeStake         uint64  // 100 coins base
    CompoundingFactor     float64 // 1.2x per additional node in same org
    NodeStakeLockDuration time.Duration // 24 hours (one epoch)

    // Reputation discount for established nodes
    MaxReputationDiscount float64 // 0.30 (30% max discount at 0.95+ rep)
}

// CalculateNodeStake computes required stake for a node
func (req *CAPoolStakeRequirements) CalculateNodeStake(
    orgNodeCount int,
    reputation float64,
) uint64 {
    // Base stake with compounding for multiple nodes
    stake := float64(req.BaseNodeStake)
    for i := 1; i < orgNodeCount; i++ {
        stake *= req.CompoundingFactor
    }

    // Apply reputation discount (up to 30% for 0.95+ reputation)
    if reputation >= 0.95 {
        stake *= (1.0 - req.MaxReputationDiscount)
    } else if reputation >= 0.90 {
        // Linear scaling from 0% to 30% discount
        discount := (reputation - 0.90) / 0.05 * req.MaxReputationDiscount
        stake *= (1.0 - discount)
    }

    return uint64(stake)
}
```

**Stake Calculation Examples (single organization):**

| Node | Base Stake | Compounding | Required Stake |
|------|------------|-------------|----------------|
| Node 1 | 100 coins | 1.0x | 100 coins |
| Node 2 | 100 coins | 1.2x | 120 coins |
| Node 3 | 100 coins | 1.44x | 144 coins |
| Node 5 | 100 coins | 2.07x | 207 coins |
| Node 10 | 100 coins | 5.16x | 516 coins |
| Node 20 | 100 coins | 38.34x | 3,834 coins |

**Total stake for 10 nodes in one org:** ~1,600 coins (reduced by reputation discount)

**Slashing Conditions:**

| Misconduct | Stake Loss | Reputation Loss | Ban Duration |
|------------|------------|-----------------|--------------|
| Equivocation (double signing) | 100% | 100% | Permanent |
| Invalid Signature | 50% | 50% | 90 days |
| Unavailability | 10% | 10% | 7 days |
| Collusion (coordinated attack) | 100% + 50% org stake | 100% | Permanent |

#### Anti-Cartel Rotation

```go
// AntiCartelRotation prevents long-term pool control
type AntiCartelRotation struct {
    // Mandatory rotation: no node can be in pool for > N consecutive epochs
    MaxConsecutiveEpochs int // Default: 24 (24 hours with 1-hour epochs)

    // Cooldown period after serving
    CooldownEpochs int // Default: 6 (6 hours before eligible again)

    // Maximum pool participation rate
    MaxParticipationRate float64 // Default: 0.5 (50% of epochs max)

    // Historical tracking
    participationHistory map[NodeID][]uint64 // Epochs where node participated
}

// IsEligibleForPool checks anti-cartel eligibility
func (acr *AntiCartelRotation) IsEligibleForPool(nodeID NodeID, epoch uint64) bool {
    history := acr.participationHistory[nodeID]
    if len(history) == 0 {
        return true // New nodes always eligible
    }

    // Check consecutive epochs constraint
    consecutiveCount := 0
    for i := len(history) - 1; i >= 0; i-- {
        if history[i] == epoch-uint64(len(history)-i) {
            consecutiveCount++
        } else {
            break
        }
    }
    if consecutiveCount >= acr.MaxConsecutiveEpochs {
        return false // Must rotate out
    }

    // Check cooldown period
    lastParticipation := history[len(history)-1]
    if epoch-lastParticipation < uint64(acr.CooldownEpochs) {
        // In cooldown, but consecutive service bypasses cooldown
        if consecutiveCount == 0 {
            return false
        }
    }

    // Check overall participation rate (rolling 7-day window)
    windowStart := epoch - 168 // 168 hours = 7 days
    windowParticipation := 0
    for _, e := range history {
        if e >= windowStart {
            windowParticipation++
        }
    }
    if float64(windowParticipation)/168.0 > acr.MaxParticipationRate {
        return false // Exceeded participation rate
    }

    return true
}

// verifyAntiCartelProperties validates pool composition
func (s *VRFPoolSelector) verifyAntiCartelProperties(selected []NodeInfo) error {
    // Verify no single organization controls > threshold
    orgCounts := make(map[string]int)
    for _, node := range selected {
        orgCounts[node.OrganizationID]++
    }

    maxOrgShare := 0
    for _, count := range orgCounts {
        if count > maxOrgShare {
            maxOrgShare = count
        }
    }

    // Single organization cannot control > 5% of pool
    if float64(maxOrgShare)/float64(len(selected)) > 0.05 {
        return ErrSingleOrganizationExceedsThreshold{
            MaxAllowed: 0.05,
            Actual:     float64(maxOrgShare) / float64(len(selected)),
        }
    }

    // Verify geographic distribution
    regions := make(map[string]bool)
    for _, node := range selected {
        regions[node.Region] = true
    }
    if len(regions) < 5 {
        return ErrInsufficientGeographicDiversity{
            Required: 5,
            Actual:   len(regions),
        }
    }

    // Verify vendor distribution
    vendors := make(map[string]bool)
    for _, node := range selected {
        vendors[node.TPMVendor] = true
    }
    if len(vendors) < 3 {
        return ErrInsufficientVendorDiversity{
            Required: 3,
            Actual:   len(vendors),
        }
    }

    return nil
}
```

#### Cartel Detection and Response

```go
// CartelDetector monitors for collusion patterns
type CartelDetector struct {
    // Behavioral signals
    votingPatterns    map[NodeID][]VoteRecord
    communicationGraph *NetworkGraph

    // Statistical analysis
    correlationThreshold float64 // 0.85 = suspicious
    alertThreshold       float64 // 0.95 = confirmed cartel
}

// DetectCartelBehavior analyzes pool behavior for collusion
func (cd *CartelDetector) DetectCartelBehavior(pool *CAPool) *CartelAlert {
    // Signal 1: Voting correlation analysis
    // Cartels tend to vote identically on all decisions
    votingCorrelation := cd.analyzeVotingCorrelation(pool)
    if votingCorrelation > cd.correlationThreshold {
        return &CartelAlert{
            Type:       AlertVotingCorrelation,
            Confidence: votingCorrelation,
            Nodes:      cd.identifyCorrelatedNodes(pool),
        }
    }

    // Signal 2: Communication pattern analysis
    // Cartels show unusual coordination patterns
    commScore := cd.analyzeCommunicationPatterns(pool)
    if commScore > cd.correlationThreshold {
        return &CartelAlert{
            Type:       AlertCommunicationPattern,
            Confidence: commScore,
            Nodes:      cd.identifyCoordinatingNodes(pool),
        }
    }

    // Signal 3: Timing analysis
    // Cartels respond with suspiciously low variance
    timingScore := cd.analyzeTimingVariance(pool)
    if timingScore > cd.correlationThreshold {
        return &CartelAlert{
            Type:       AlertTimingAnomaly,
            Confidence: timingScore,
            Nodes:      cd.identifySynchronizedNodes(pool),
        }
    }

    return nil // No cartel detected
}

// RespondToCartelAlert handles detected cartel behavior
func RespondToCartelAlert(alert *CartelAlert) error {
    switch {
    case alert.Confidence >= 0.95:
        // Confirmed cartel: immediate action
        for _, nodeID := range alert.Nodes {
            // Slash reputation severely
            SlashReputation(nodeID, 0.5)
            // Remove from current pool
            RemoveFromPool(nodeID)
            // Ban from pool participation for 30 days
            BanFromPoolParticipation(nodeID, 30*24*time.Hour)
        }
        // Trigger emergency pool rotation
        TriggerEmergencyPoolRotation()

    case alert.Confidence >= 0.85:
        // Suspected cartel: increased monitoring
        for _, nodeID := range alert.Nodes {
            // Flag for enhanced monitoring
            FlagForMonitoring(nodeID, "suspected_cartel")
            // Reduce pool selection probability
            ReduceSelectionProbability(nodeID, 0.5)
        }
        // Alert network operators
        BroadcastSecurityAlert(AlertSuspectedCartel, alert)
    }

    return nil
}
```

#### Security Properties of Anti-Cartel Design

| Property | Mechanism | Effectiveness |
|----------|-----------|---------------|
| Unpredictability | VRF-based selection | Cannot predict pool membership in advance |
| Verifiability | VRF proofs published | Anyone can verify selection was fair |
| Diversity | Multi-dimensional constraints | No single attribute dominates |
| Rotation | Mandatory cooldowns | Prevents permanent control |
| Detection | Behavioral analysis | Identifies collusion patterns |
| Response | Automatic slashing | Economic disincentive for cartels |

---

### Reputation Scoring

```
Reputation Score =
    0.40 * Uptime (exponential moving average, 30 days) +
    0.25 * Bandwidth (measured throughput) +
    0.15 * Latency (lower is better, avg RTT) +
    0.10 * CA Participation (successful signing history) +
    0.10 * TPM History (consistent attestation success)

Result: 0.0 (lowest) to 1.0 (highest)
```

**Storage:** DHT key `reputation-{node_id}`, TTL 24 hours, replication k=3

---

## Pool Lifecycle

### 1. Genesis (Initial Pool Creation)

```
T-10min: Genesis CA Ceremony (manual, trusted setup)
  - 5-10 founding nodes perform initial DKG
  - Generate first group keys for all 4 pools
  - Create CT log entry for epoch 0
  - Publish to DHT

T+0min: Network Bootstrap
  - 4 pools active: Ed25519-A/B, P-256-A/B
  - Ready to issue certificates
```

### 2. Normal Operation

```
Certificate Request Flow:
1. Node submits CSR with algorithm preference (Ed25519 or P-256)
2. Load balancer selects pool (round-robin, <1us)
3. Random pool member becomes coordinator
4. 2-round signing (~200ms):
   - Round 1: Collect commitments from 330K nodes (80ms)
   - Round 2: Collect signature shares from 330K nodes (80ms)
   - Aggregate: Combine shares into signature (20ms)
5. Certificate returned to requester
6. Node stores certificate locally (/var/lib/dht-node/node.cert)

Total Latency: ~200ms
Success Rate: >99.9% (with 4 pools + 33% threshold)
```

### 3. Emergency Rotation (Health-Based)

**Trigger Conditions:**
- Pool availability < 40%
- Failed signatures > 100/hour
- Average latency > 5 seconds
- Pool unhealthy for > 1 hour

```
Emergency Rotation Process:
T+0min: Detection - Health monitor detects degradation
T+1min: Selection - New pool members via reputation-weighted VRF
T+2min: Fast DKG (5 minutes total)
T+7min: Activation - New pool active, old deactivated
T+8min: Recovery Complete - 4 pools active again

Total Downtime: 0 seconds (other pools handled load)
```

### 4. Time-Based Rotation (Scheduled)

**Trigger Conditions (FIXED, NON-CONFIGURABLE):**
- Pool age >= 1 hour
- Staggered 30-minute offsets

```
Scheduled Rotation Process:
T-15min: Pre-Rotation - Begin DKG in background
T+0min:  DKG Complete - New pool ready
T+1min:  Graceful Cutover - Seamless transition
T+2min:  CT Log Update - Publish new epoch
T+3min:  Complete - 4 pools active
```

**Staggered Rotation Schedule:**
```
Hour 0:00: Ed25519-A rotates
Hour 0:30: P-256-A rotates
Hour 1:00: Ed25519-B rotates
Hour 1:30: P-256-B rotates
Hour 2:00: Cycle repeats...

Result: Always 3+ pools active during rotation
```

---

## Certificate Transparency Log

### Purpose

- **Historical validation:** Verify certificates signed with old keys
- **Auditability:** Public log of all CA operations
- **Tamper-evident:** Append-only, Merkle tree structure
- **Industry standard:** Similar to Google CT, Let's Encrypt

### Certificate Transparency Requirements

All certificates issued by the DHT Privacy CA must comply with the following CT requirements:

| Requirement | Specification | Enforcement |
|-------------|---------------|-------------|
| CT Log Submission | Mandatory for all certificates | Pre-certificate signed before final issuance |
| Probation Period | 1 hour from issuance | Certificate restricted until CT proof confirmed |
| Maximum CT Delay | 24 hours | Certificate revoked if CT inclusion not confirmed |
| TPM EK Certificates | CT log submission required | Anomaly detection for issuance spikes |
| SCT Embedding | Signed Certificate Timestamp in cert | Required for certificate validity |

```go
// CTRequirements defines mandatory Certificate Transparency compliance
type CTRequirements struct {
    // SubmissionMandatory requires all certs to be submitted to CT log
    SubmissionMandatory bool // Always true

    // ProbationPeriod is the time before CT proof must be confirmed
    ProbationPeriod time.Duration // 1 hour

    // MaxInclusionDelay is the maximum acceptable CT inclusion delay
    MaxInclusionDelay time.Duration // 24 hours

    // EKCertsCTRequired requires TPM EK certificates to be logged
    EKCertsCTRequired bool // Always true

    // AnomalyDetectionEnabled monitors for EK issuance rate spikes
    AnomalyDetectionEnabled bool // Always true
}

// DefaultCTRequirements returns the mandatory CT compliance settings
func DefaultCTRequirements() *CTRequirements {
    return &CTRequirements{
        SubmissionMandatory:     true,
        ProbationPeriod:         1 * time.Hour,
        MaxInclusionDelay:       24 * time.Hour,
        EKCertsCTRequired:       true,
        AnomalyDetectionEnabled: true,
    }
}

// CertificateWithCTStatus tracks CT compliance state
type CertificateWithCTStatus struct {
    Certificate     *x509.Certificate
    CTStatus        CTComplianceStatus
    SubmittedAt     time.Time
    SCT             *SignedCertTimestamp  // Signed Certificate Timestamp
    InclusionProof  *InclusionProof       // Merkle inclusion proof
    ProbationEndsAt time.Time
}

type CTComplianceStatus uint8

const (
    CTStatusPending      CTComplianceStatus = iota // Awaiting CT submission
    CTStatusProbation                              // Submitted, awaiting inclusion proof
    CTStatusConfirmed                              // CT inclusion confirmed
    CTStatusFailed                                 // CT inclusion failed
    CTStatusRevoked                                // Revoked due to CT failure
)

// SignedCertTimestamp is the CT log's promise to include the certificate
type SignedCertTimestamp struct {
    Version       uint8
    LogID         [32]byte      // SHA-256 of log's public key
    Timestamp     int64         // Milliseconds since epoch
    Extensions    []byte
    Signature     []byte        // Log's signature over the SCT data
}

// InclusionProof proves certificate is in the CT Merkle tree
type InclusionProof struct {
    LogID      [32]byte
    TreeSize   uint64
    LeafIndex  uint64
    AuditPath  [][32]byte    // Merkle proof nodes
    STH        *SignedTreeHead
}
```

#### CT Submission and Probation Protocol

```go
// CTSubmissionProtocol manages certificate transparency compliance
type CTSubmissionProtocol struct {
    ctLog           *CTLog
    requirements    *CTRequirements
    pendingCerts    map[string]*CertificateWithCTStatus
    anomalyDetector *EKAnomalyDetector
}

// SubmitCertificateToCT submits a certificate to the CT log
func (p *CTSubmissionProtocol) SubmitCertificateToCT(
    ctx context.Context,
    cert *x509.Certificate,
) (*CertificateWithCTStatus, error) {
    // Step 1: Create pre-certificate for CT submission
    preCert := CreatePreCertificate(cert)

    // Step 2: Submit to CT log and get SCT
    sct, err := p.ctLog.AddPreCertificate(ctx, preCert)
    if err != nil {
        return nil, fmt.Errorf("CT submission failed: %w", err)
    }

    // Step 3: Verify SCT signature
    if err := VerifySCT(sct, p.ctLog.GetPublicKey()); err != nil {
        return nil, fmt.Errorf("SCT verification failed: %w", err)
    }

    // Step 4: Create certificate status with probation
    status := &CertificateWithCTStatus{
        Certificate:     cert,
        CTStatus:        CTStatusProbation,
        SubmittedAt:     time.Now(),
        SCT:             sct,
        ProbationEndsAt: time.Now().Add(p.requirements.ProbationPeriod),
    }

    // Step 5: Store pending certificate
    certID := ComputeCertificateID(cert)
    p.pendingCerts[certID] = status

    // Step 6: Schedule inclusion proof verification
    go p.scheduleInclusionVerification(ctx, status)

    return status, nil
}

// scheduleInclusionVerification waits for and verifies CT inclusion
func (p *CTSubmissionProtocol) scheduleInclusionVerification(
    ctx context.Context,
    status *CertificateWithCTStatus,
) {
    certID := ComputeCertificateID(status.Certificate)

    // Wait for probation period
    select {
    case <-time.After(p.requirements.ProbationPeriod):
        // Continue to verification
    case <-ctx.Done():
        return
    }

    // Attempt to get inclusion proof
    deadline := status.SubmittedAt.Add(p.requirements.MaxInclusionDelay)
    for time.Now().Before(deadline) {
        proof, err := p.ctLog.GetInclusionProof(ctx, status.SCT)
        if err == nil {
            // Verify inclusion proof
            if err := VerifyInclusionProof(proof, status.Certificate); err == nil {
                status.InclusionProof = proof
                status.CTStatus = CTStatusConfirmed
                p.pendingCerts[certID] = status
                return
            }
        }

        // Retry with exponential backoff
        select {
        case <-time.After(5 * time.Minute):
            continue
        case <-ctx.Done():
            return
        }
    }

    // CT inclusion failed - revoke certificate
    status.CTStatus = CTStatusFailed
    p.pendingCerts[certID] = status
    RevokeCertificate(status.Certificate, ReasonCTInclusionFailed)
}
```

#### TPM EK Certificate CT Logging

```go
// EKCertificateCTLogger logs TPM Endorsement Key certificates to CT
type EKCertificateCTLogger struct {
    ctLog           *CTLog
    anomalyDetector *EKAnomalyDetector
}

// EKAnomalyDetector monitors for suspicious EK issuance patterns
type EKAnomalyDetector struct {
    // Baseline rates per manufacturer
    baselineRates    map[string]float64  // Manufacturer -> certs per hour
    currentRates     map[string]*RateTracker
    alertThreshold   float64             // 3.0 = 3x baseline triggers alert

    // Spike detection window
    windowSize       time.Duration       // 1 hour sliding window
}

// RateTracker tracks certificate issuance rate
type RateTracker struct {
    Manufacturer   string
    RecentCount    uint64
    WindowStart    time.Time
    HourlyRate     float64
}

// LogEKCertificate submits a TPM EK certificate to CT log with anomaly detection
func (l *EKCertificateCTLogger) LogEKCertificate(
    ctx context.Context,
    ekCert *x509.Certificate,
    manufacturer string,
) error {
    // Step 1: Check for anomalous issuance rate
    if alert := l.anomalyDetector.CheckRate(manufacturer); alert != nil {
        // Log alert but continue - don't block legitimate issuance
        l.logAnomalyAlert(alert)
    }

    // Step 2: Submit EK certificate to CT log
    sct, err := l.ctLog.AddCertificate(ctx, ekCert)
    if err != nil {
        return fmt.Errorf("EK CT submission failed: %w", err)
    }

    // Step 3: Update rate tracker
    l.anomalyDetector.RecordIssuance(manufacturer)

    // Step 4: Store SCT with EK certificate record
    return StoreEKWithSCT(ekCert, sct)
}

// CheckRate detects anomalous EK issuance rate spikes
func (d *EKAnomalyDetector) CheckRate(manufacturer string) *EKAnomalyAlert {
    tracker := d.currentRates[manufacturer]
    if tracker == nil {
        return nil // No baseline yet
    }

    baseline := d.baselineRates[manufacturer]
    if baseline == 0 {
        return nil // No baseline established
    }

    // Calculate current rate vs baseline
    ratio := tracker.HourlyRate / baseline

    if ratio > d.alertThreshold {
        return &EKAnomalyAlert{
            Manufacturer:  manufacturer,
            CurrentRate:   tracker.HourlyRate,
            BaselineRate:  baseline,
            RatioToBaseline: ratio,
            Severity:      d.calculateSeverity(ratio),
            DetectedAt:    time.Now(),
        }
    }

    return nil
}

// EKAnomalyAlert represents a detected EK issuance anomaly
type EKAnomalyAlert struct {
    Manufacturer     string
    CurrentRate      float64
    BaselineRate     float64
    RatioToBaseline  float64
    Severity         AlertSeverity
    DetectedAt       time.Time
}

// calculateSeverity determines alert severity based on rate ratio
func (d *EKAnomalyDetector) calculateSeverity(ratio float64) AlertSeverity {
    switch {
    case ratio > 10.0:
        return AlertSeverityCritical  // 10x baseline
    case ratio > 5.0:
        return AlertSeverityHigh      // 5x baseline
    case ratio > 3.0:
        return AlertSeverityMedium    // 3x baseline
    default:
        return AlertSeverityLow
    }
}
```

#### CT Compliance Summary

| Metric | Requirement | Consequence of Violation |
|--------|-------------|--------------------------|
| CT Submission | 100% of certificates | Certificate not valid without SCT |
| Probation Period | 1 hour | Certificate usage restricted |
| Inclusion Confirmation | Within 24 hours | Certificate automatically revoked |
| EK Certificate Logging | Mandatory | EK rejected for enrollment |
| Anomaly Detection | Continuous monitoring | Security alert broadcast |

### CT Log Entry Structure

```go
type CTLogEntry struct {
    Epoch          uint64      // Unique epoch number
    Timestamp      time.Time   // Exact rotation time
    Algorithm      string      // "Ed25519" or "P-256"
    PoolID         string      // "ed25519-a", "p256-b", etc.
    GroupPubKey    []byte      // Group public key
    Participants   []NodeID    // Pool member list
    MerkleRoot     [32]byte    // Root of certs issued this epoch
    PrevEpochHash  [32]byte    // Chain to previous epoch
    Signature      []byte      // Self-signed by pool
}
```

**Storage:**
- DHT key: `ct-log-{algorithm}-{epoch}`
- Replication: k=10
- Size: ~1KB per entry

### Algorithm Selection

```go
type CertificateRequest struct {
    CSR         []byte
    Algorithm   AlgorithmType  // Ed25519 or P-256
    NodeID      [32]byte
    PublicKey   crypto.PublicKey
}

const (
    AlgorithmEd25519 AlgorithmType = iota  // Fast, compact (default)
    AlgorithmP256                          // NIST P-256 (compliance)
)
```

**Use cases:**
- **Ed25519** (default): IoT devices, high performance
- **P-256**: Enterprise compliance, FIPS requirements

### Certificate Format

```go
type Certificate struct {
    // Standard X.509 fields
    Version      int
    SerialNumber []byte
    Subject      pkix.Name
    NotBefore    time.Time
    NotAfter     time.Time  // 90 days validity
    PublicKey    crypto.PublicKey

    // CA signing information
    CAAlgorithm  string     // "Ed25519" or "P-256"
    CAEpoch      uint64     // Which pool signed this cert
    CAPoolID     string     // "ed25519-a", "p256-b", etc.
    CAGroupKey   []byte     // Group public key

    // Signature (RFC 9591)
    Signature    []byte     // 64-byte Schnorr signature
}

// Storage: /var/lib/dht-node/node.cert (local, not DHT)
```

### Historical Validation

```go
func ValidateCertificate(cert Certificate) error {
    if time.Now().After(cert.NotAfter) {
        return ErrCertificateExpired
    }

    ctKey := fmt.Sprintf("ct-log-%s-%d", cert.CAAlgorithm, cert.CAEpoch)
    entry, err := dht.Get(ctKey)
    if err != nil {
        return ErrCTLogEntryNotFound
    }

    if !frost.Verify(entry.GroupPubKey, cert.TBS, cert.Signature) {
        return ErrInvalidSignature
    }

    return nil
}
```

**Key Property:** Certificates remain valid until expiration, even after pool rotation.

### CT Log Append-Only Verification with Threshold Signatures (Issue C10 Fix)

CT logs use Signed Tree Heads (STH) with threshold signatures from ALL pools and a gossip protocol to ensure append-only consistency across all DHT replicas. This prevents DHT nodes from serving forked CT log histories.

#### Signed Tree Head Structure

```go
// SignedTreeHead provides cryptographic proof of CT log state
type SignedTreeHead struct {
    Version       uint8       // STH format version (current: 1)
    TreeSize      uint64      // Number of entries in log
    Timestamp     int64       // Unix timestamp (TPM-attested)
    RootHash      [32]byte    // SHA-256 Merkle tree root hash
    Epoch         uint64      // Current epoch number
    PreviousSTH   [32]byte    // Hash of previous STH (chain link)

    // Threshold signatures from ALL 4 pools (quorum requirement)
    Signatures    []PoolSignature
}

// PoolSignature is a threshold signature from one CA pool
type PoolSignature struct {
    PoolID        string      // "ed25519-a", "ed25519-b", "p256-a", "p256-b"
    Epoch         uint64      // Pool epoch when signature was created
    GroupPubKey   []byte      // Pool's group public key at signing time
    Signature     []byte      // FROST threshold signature (64 bytes)
    SignerCount   uint32      // Number of signers that participated
    SignerBitmap  []byte      // Bitmap of which pool members signed
}

// STHSigningData is the canonical data signed by each pool
type STHSigningData struct {
    Version     uint8
    TreeSize    uint64
    Timestamp   int64
    RootHash    [32]byte
    Epoch       uint64
    PreviousSTH [32]byte
}

// encodeSTHForSigning creates canonical signing data
func encodeSTHForSigning(sth *SignedTreeHead) []byte {
    data := &STHSigningData{
        Version:     sth.Version,
        TreeSize:    sth.TreeSize,
        Timestamp:   sth.Timestamp,
        RootHash:    sth.RootHash,
        Epoch:       sth.Epoch,
        PreviousSTH: sth.PreviousSTH,
    }
    // Use deterministic encoding (no field reordering)
    return cbor.Marshal(data)
}
```

#### Threshold STH Signing Protocol

```go
// STHSigningCoordinator manages threshold signing of STH updates
type STHSigningCoordinator struct {
    pools         []*CAPool
    currentSTH    *SignedTreeHead
    pendingSTH    *SignedTreeHead
    sigCollector  *SignatureCollector
}

// CreateNewSTH generates and signs a new STH
func (c *STHSigningCoordinator) CreateNewSTH(
    ctx context.Context,
    newEntries []CTLogEntry,
) (*SignedTreeHead, error) {
    // Step 1: Build new Merkle tree
    newTreeSize := c.currentSTH.TreeSize + uint64(len(newEntries))
    newRoot, err := c.buildMerkleTree(newEntries)
    if err != nil {
        return nil, fmt.Errorf("merkle tree build failed: %w", err)
    }

    // Step 2: Create unsigned STH
    pendingSTH := &SignedTreeHead{
        Version:     1,
        TreeSize:    newTreeSize,
        Timestamp:   time.Now().Unix(),
        RootHash:    newRoot,
        Epoch:       c.currentSTH.Epoch + 1,
        PreviousSTH: hashSTH(c.currentSTH),
        Signatures:  make([]PoolSignature, 0, 4),
    }

    // Step 3: Collect threshold signatures from ALL 4 pools
    signingData := encodeSTHForSigning(pendingSTH)

    var wg sync.WaitGroup
    var mu sync.Mutex
    signatures := make([]PoolSignature, 0, 4)
    errs := make([]error, 0)

    for _, pool := range c.pools {
        wg.Add(1)
        go func(p *CAPool) {
            defer wg.Done()

            // Each pool performs FROST threshold signing
            sig, err := p.ThresholdSign(ctx, signingData)
            if err != nil {
                mu.Lock()
                errs = append(errs, fmt.Errorf("pool %s failed: %w", p.ID, err))
                mu.Unlock()
                return
            }

            mu.Lock()
            signatures = append(signatures, PoolSignature{
                PoolID:       p.ID,
                Epoch:        p.CurrentEpoch,
                GroupPubKey:  p.GroupPublicKey,
                Signature:    sig.Signature,
                SignerCount:  sig.SignerCount,
                SignerBitmap: sig.SignerBitmap,
            })
            mu.Unlock()
        }(pool)
    }

    wg.Wait()

    // Step 4: Require ALL 4 pools to sign
    if len(signatures) < 4 {
        return nil, ErrInsufficientPoolSignatures{
            Required: 4,
            Got:      len(signatures),
            Errors:   errs,
        }
    }

    pendingSTH.Signatures = signatures

    // Step 5: Verify all signatures before publishing
    if err := ValidateSTH(pendingSTH); err != nil {
        return nil, fmt.Errorf("STH validation failed: %w", err)
    }

    // Step 6: Publish to DHT with high replication
    if err := c.publishSTH(pendingSTH); err != nil {
        return nil, fmt.Errorf("STH publish failed: %w", err)
    }

    c.currentSTH = pendingSTH
    return pendingSTH, nil
}

// ValidateSTH verifies the signed tree head is authentic
func ValidateSTH(sth *SignedTreeHead) error {
    // Require signatures from ALL 4 pools
    requiredPools := map[string]bool{
        "ed25519-a": false,
        "ed25519-b": false,
        "p256-a":    false,
        "p256-b":    false,
    }

    signingData := encodeSTHForSigning(sth)

    for _, sig := range sth.Signatures {
        // Check pool is in required set
        if _, ok := requiredPools[sig.PoolID]; !ok {
            return ErrUnknownPool{PoolID: sig.PoolID}
        }

        // Get pool's group public key (verify it matches expected)
        pool, err := GetPoolByIDAndEpoch(sig.PoolID, sig.Epoch)
        if err != nil {
            return fmt.Errorf("pool lookup failed: %w", err)
        }

        if !bytes.Equal(pool.GroupPubKey, sig.GroupPubKey) {
            return ErrGroupKeyMismatch{
                PoolID:   sig.PoolID,
                Expected: pool.GroupPubKey,
                Got:      sig.GroupPubKey,
            }
        }

        // Verify FROST threshold signature
        if !frost.Verify(sig.GroupPubKey, signingData, sig.Signature) {
            return ErrInvalidPoolSignature{PoolID: sig.PoolID}
        }

        requiredPools[sig.PoolID] = true
    }

    // Verify all required pools signed
    for poolID, signed := range requiredPools {
        if !signed {
            return ErrMissingPoolSignature{PoolID: poolID}
        }
    }

    return nil
}
```

#### Gossip Protocol for STH Consistency

```go
// STHGossipProtocol ensures all nodes have consistent CT log view
type STHGossipProtocol struct {
    localSTH       *SignedTreeHead
    peerSTHs       map[NodeID]*SignedTreeHead // Recent STHs from peers
    lastGossip     time.Time
    forkDetector   *ForkDetector
    consistencyLog *ConsistencyAuditLog
}

const (
    STHGossipInterval     = 5 * time.Minute  // Gossip frequency
    STHGossipFanout       = 20               // Peers per gossip round
    STHMaxAgeDrift        = 30 * time.Minute // Max acceptable STH age
    STHConsistencyTimeout = 10 * time.Minute // Max time to resolve inconsistency
)

// GossipSTH exchanges STH information with peers
func (g *STHGossipProtocol) GossipSTH(ctx context.Context) error {
    // Select peers with geographic and network diversity
    peers := g.selectDiversePeers(STHGossipFanout)

    var wg sync.WaitGroup
    inconsistencies := make(chan *STHInconsistency, len(peers))

    for _, peer := range peers {
        wg.Add(1)
        go func(p *Peer) {
            defer wg.Done()

            // Exchange STH with peer
            peerSTH, err := p.GetLatestSTH(ctx)
            if err != nil {
                log.Printf("STH exchange with %s failed: %v", p.ID, err)
                return
            }

            // Validate peer's STH
            if err := ValidateSTH(peerSTH); err != nil {
                log.Printf("Invalid STH from %s: %v", p.ID, err)
                g.reportMaliciousPeer(p.ID, "invalid_sth")
                return
            }

            // Check for inconsistency
            if inc := g.checkConsistency(peerSTH); inc != nil {
                inconsistencies <- inc
            }

            // Store peer's STH for analysis
            g.peerSTHs[p.ID] = peerSTH

        }(peer)
    }

    wg.Wait()
    close(inconsistencies)

    // Process any detected inconsistencies
    for inc := range inconsistencies {
        if err := g.handleInconsistency(ctx, inc); err != nil {
            return fmt.Errorf("inconsistency handling failed: %w", err)
        }
    }

    return nil
}

// checkConsistency compares local STH with peer STH
func (g *STHGossipProtocol) checkConsistency(peerSTH *SignedTreeHead) *STHInconsistency {
    localSTH := g.localSTH

    // Same tree size but different root = FORK
    if peerSTH.TreeSize == localSTH.TreeSize &&
        peerSTH.RootHash != localSTH.RootHash {
        return &STHInconsistency{
            Type:     InconsistencyFork,
            LocalSTH: localSTH,
            PeerSTH:  peerSTH,
            Severity: SeverityCritical,
        }
    }

    // Same epoch but different previous STH hash = CHAIN BREAK
    if peerSTH.Epoch == localSTH.Epoch &&
        peerSTH.PreviousSTH != localSTH.PreviousSTH {
        return &STHInconsistency{
            Type:     InconsistencyChainBreak,
            LocalSTH: localSTH,
            PeerSTH:  peerSTH,
            Severity: SeverityCritical,
        }
    }

    // Peer has newer STH - verify consistency proof
    if peerSTH.TreeSize > localSTH.TreeSize {
        return &STHInconsistency{
            Type:     InconsistencyBehind,
            LocalSTH: localSTH,
            PeerSTH:  peerSTH,
            Severity: SeverityInfo,
        }
    }

    return nil
}

// selectDiversePeers chooses peers for gossip with diversity requirements
func (g *STHGossipProtocol) selectDiversePeers(count int) []*Peer {
    allPeers := g.getPeerList()

    // Ensure diversity across:
    // - Geographic regions (at least 5 different regions)
    // - Network ASNs (at least 3 different ASNs)
    // - Node ages (mix of old and new nodes)

    selected := make([]*Peer, 0, count)
    regionCounts := make(map[string]int)
    asnCounts := make(map[string]int)

    // Shuffle peers for randomness
    rand.Shuffle(len(allPeers), func(i, j int) {
        allPeers[i], allPeers[j] = allPeers[j], allPeers[i]
    })

    for _, peer := range allPeers {
        if len(selected) >= count {
            break
        }

        // Limit per region (max 4 per region for 20 peers)
        if regionCounts[peer.Region] >= count/5 {
            continue
        }

        // Limit per ASN (max 3 per ASN)
        if asnCounts[peer.ASN] >= 3 {
            continue
        }

        selected = append(selected, peer)
        regionCounts[peer.Region]++
        asnCounts[peer.ASN]++
    }

    return selected
}
```

#### Fork Detection and Resolution

```go
// ForkDetector identifies and resolves CT log forks
type ForkDetector struct {
    forkHistory    []*DetectedFork
    resolutionLog  *ResolutionAuditLog
}

// DetectedFork represents a detected CT log fork
type DetectedFork struct {
    ID             string
    DetectedAt     time.Time
    ForkPoint      uint64              // Tree size where fork occurred
    Branches       []*ForkBranch       // Competing branches
    CanonicalBranch *ForkBranch        // Resolved canonical branch
    Resolution     *ForkResolution
    Status         ForkStatus
}

// ForkBranch represents one branch of a forked CT log
type ForkBranch struct {
    STH            *SignedTreeHead
    Witnesses      []NodeID           // Nodes that have this STH
    WitnessCount   int
    PoolSignatures map[string]bool    // Which pools signed this branch
    FirstSeen      time.Time
}

// DetectFork analyzes STH reports for fork evidence
func (fd *ForkDetector) DetectFork(localSTH, peerSTH *SignedTreeHead) *DetectedFork {
    // Forks occur when two valid STHs exist at the same tree size
    // with different root hashes
    if localSTH.TreeSize != peerSTH.TreeSize {
        return nil
    }
    if localSTH.RootHash == peerSTH.RootHash {
        return nil
    }

    // Both STHs must have valid signatures to be a true fork
    // (invalid signatures indicate malicious peer, not fork)
    if ValidateSTH(localSTH) != nil || ValidateSTH(peerSTH) != nil {
        return nil
    }

    // CRITICAL: Valid fork detected
    fork := &DetectedFork{
        ID:         generateForkID(localSTH, peerSTH),
        DetectedAt: time.Now(),
        ForkPoint:  localSTH.TreeSize,
        Branches: []*ForkBranch{
            {
                STH:            localSTH,
                WitnessCount:   1,
                PoolSignatures: extractPoolSignatures(localSTH),
                FirstSeen:      time.Now(),
            },
            {
                STH:            peerSTH,
                WitnessCount:   1,
                PoolSignatures: extractPoolSignatures(peerSTH),
                FirstSeen:      time.Now(),
            },
        },
        Status: ForkStatusDetected,
    }

    return fork
}

// ResolveFork determines the canonical branch and takes corrective action
func (fd *ForkDetector) ResolveFork(ctx context.Context, fork *DetectedFork) (*ForkResolution, error) {
    // Step 1: Gather witnesses for each branch
    if err := fd.gatherWitnesses(ctx, fork); err != nil {
        return nil, fmt.Errorf("witness gathering failed: %w", err)
    }

    // Step 2: Apply fork resolution rules
    canonical := fd.selectCanonicalBranch(fork)
    if canonical == nil {
        return nil, ErrCannotResolveFork
    }

    fork.CanonicalBranch = canonical

    // Step 3: Identify malicious signers
    maliciousSigners := fd.identifyMaliciousSigners(fork)

    // Step 4: Create resolution record
    resolution := &ForkResolution{
        ForkID:           fork.ID,
        ResolvedAt:       time.Now(),
        CanonicalSTH:     canonical.STH,
        MaliciousSigners: maliciousSigners,
        Action:           ResolutionActionSlash,
    }

    // Step 5: Execute resolution
    if err := fd.executeResolution(ctx, resolution); err != nil {
        return nil, fmt.Errorf("resolution execution failed: %w", err)
    }

    fork.Resolution = resolution
    fork.Status = ForkStatusResolved

    return resolution, nil
}

// selectCanonicalBranch determines which branch is authoritative
func (fd *ForkDetector) selectCanonicalBranch(fork *DetectedFork) *ForkBranch {
    // Resolution priority (in order):
    // 1. Branch with more pool signatures (indicates broader consensus)
    // 2. Branch with more witnesses (indicates broader propagation)
    // 3. Branch seen first (tie-breaker)

    var canonical *ForkBranch
    maxScore := -1

    for _, branch := range fork.Branches {
        score := 0

        // Score based on pool signatures (weight: 1000 per pool)
        score += len(branch.PoolSignatures) * 1000

        // Score based on witnesses (weight: 1 per witness)
        score += branch.WitnessCount

        // Tie-breaker: earlier timestamp
        if score > maxScore || (score == maxScore && branch.FirstSeen.Before(canonical.FirstSeen)) {
            maxScore = score
            canonical = branch
        }
    }

    return canonical
}

// identifyMaliciousSigners finds pool members who signed conflicting STHs
func (fd *ForkDetector) identifyMaliciousSigners(fork *DetectedFork) []MaliciousSigner {
    // A pool member is malicious if they signed multiple branches
    // This violates the fundamental safety property

    signerVotes := make(map[NodeID]map[string]bool) // signer -> branch_id -> signed

    for _, branch := range fork.Branches {
        branchID := hashSTH(branch.STH).String()
        for _, poolSig := range branch.STH.Signatures {
            // Decode signer bitmap to identify individual signers
            signers := decodeSignerBitmap(poolSig.SignerBitmap)
            for _, signer := range signers {
                if signerVotes[signer] == nil {
                    signerVotes[signer] = make(map[string]bool)
                }
                signerVotes[signer][branchID] = true
            }
        }
    }

    // Find signers who signed multiple branches
    malicious := make([]MaliciousSigner, 0)
    for signer, votes := range signerVotes {
        if len(votes) > 1 {
            malicious = append(malicious, MaliciousSigner{
                NodeID:        signer,
                SignedBranches: len(votes),
                Violation:     ViolationDoubleSign,
            })
        }
    }

    return malicious
}

// executeResolution applies the fork resolution
func (fd *ForkDetector) executeResolution(ctx context.Context, res *ForkResolution) error {
    // Step 1: Broadcast canonical STH to all nodes
    if err := BroadcastCanonicalSTH(ctx, res.CanonicalSTH); err != nil {
        return fmt.Errorf("STH broadcast failed: %w", err)
    }

    // Step 2: Slash malicious signers
    for _, signer := range res.MaliciousSigners {
        // Maximum reputation slash (-1.0 = complete reputation loss)
        if err := SlashReputation(signer.NodeID, -1.0); err != nil {
            log.Printf("Slash failed for %s: %v", signer.NodeID, err)
        }

        // Remove from all CA pools immediately
        if err := RemoveFromAllPools(signer.NodeID); err != nil {
            log.Printf("Pool removal failed for %s: %v", signer.NodeID, err)
        }

        // Permanent ban from CA participation
        if err := BanFromCAParticipation(signer.NodeID, PermanentBan); err != nil {
            log.Printf("Ban failed for %s: %v", signer.NodeID, err)
        }
    }

    // Step 3: Trigger emergency pool rotation for affected pools
    affectedPools := fd.identifyAffectedPools(res.MaliciousSigners)
    for _, poolID := range affectedPools {
        if err := TriggerEmergencyPoolRotation(poolID); err != nil {
            log.Printf("Emergency rotation failed for %s: %v", poolID, err)
        }
    }

    // Step 4: Publish fork resolution to CT log (for audit trail)
    if err := PublishForkResolution(ctx, res); err != nil {
        return fmt.Errorf("resolution publish failed: %w", err)
    }

    return nil
}
```

#### Consistency Proof Verification

```go
// ConsistencyProof proves old STH is prefix of new STH
type ConsistencyProof struct {
    OldTreeSize   uint64
    NewTreeSize   uint64
    ProofNodes    [][32]byte  // Merkle proof nodes
}

// VerifyConsistency proves CT log hasn't been forked
func VerifyConsistency(oldSTH, newSTH *SignedTreeHead, proof *ConsistencyProof) error {
    // Sanity checks
    if newSTH.TreeSize < oldSTH.TreeSize {
        return ErrSTHRegression{
            OldSize: oldSTH.TreeSize,
            NewSize: newSTH.TreeSize,
        }
    }

    if proof.OldTreeSize != oldSTH.TreeSize || proof.NewTreeSize != newSTH.TreeSize {
        return ErrProofSizeMismatch
    }

    // Verify Merkle consistency proof (RFC 6962 Section 2.1.2)
    if !merkle.VerifyConsistency(
        proof.OldTreeSize,
        proof.NewTreeSize,
        oldSTH.RootHash[:],
        newSTH.RootHash[:],
        proof.ProofNodes,
    ) {
        return ErrCTLogForked{
            OldSTH: oldSTH,
            NewSTH: newSTH,
        }
    }

    // Verify chain link (PreviousSTH should eventually link back)
    if err := verifySTHChain(oldSTH, newSTH); err != nil {
        return fmt.Errorf("STH chain verification failed: %w", err)
    }

    return nil
}

// verifySTHChain verifies the STH chain from old to new
func verifySTHChain(oldSTH, newSTH *SignedTreeHead) error {
    // Walk backwards from newSTH to find oldSTH
    current := newSTH
    visited := make(map[uint64]bool)

    for current.Epoch > oldSTH.Epoch {
        if visited[current.Epoch] {
            return ErrSTHChainLoop
        }
        visited[current.Epoch] = true

        // Fetch previous STH
        prevSTH, err := GetSTHByHash(current.PreviousSTH)
        if err != nil {
            return fmt.Errorf("previous STH not found: %w", err)
        }

        current = prevSTH
    }

    // Verify we reached the old STH
    if hashSTH(current) != hashSTH(oldSTH) {
        return ErrSTHChainBroken{
            Expected: oldSTH,
            Got:      current,
        }
    }

    return nil
}
```

#### Security Properties of CT Log Verification

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| Append-only | Merkle consistency proofs | History cannot be rewritten |
| Fork-resistant | Gossip + threshold signatures | Forks detected within minutes |
| Accountable | Signer bitmap in signatures | Individual signers identified |
| Verifiable | All proofs are cryptographic | Any node can independently verify |
| Recoverable | Fork resolution protocol | Network converges on canonical history |

---

## Load Balancing

### Smart Pool Selection

```go
type LoadBalancer struct {
    pools    map[Algorithm][]*CAPool
    counters map[Algorithm]*atomic.Uint64
    health   *HealthCache
}

func (lb *LoadBalancer) SelectPool(algo Algorithm) *CAPool {
    poolList := lb.pools[algo]

    // Lock-free round-robin (<1us overhead)
    idx := lb.counters[algo].Add(1) % uint64(len(poolList))
    selected := poolList[idx]

    if lb.health.IsHealthy(selected.ID) {
        return selected
    }

    // Fallback to healthy pool
    for _, pool := range poolList {
        if lb.health.IsHealthy(pool.ID) {
            return pool
        }
    }
    return nil
}
```

**Performance:**
- Pool selection: <1us (atomic increment + array lookup)
- No network calls, no locks
- Cached health checks (60s interval)

### Failover Strategy

```
1. Select pool via round-robin (Pool A)
2. Send request to Pool A
3. If success -> done
4. If failure -> retry with Pool B
5. If both fail -> return error

Success rate: 99.9999% with failover
```

---

## Automation and Self-Healing

```go
type AutoPoolManager struct {
    pools         []*CAPool
    healthMonitor *HealthMonitor
    autoRotator   *AutoRotator
}

func (apm *AutoPoolManager) Run(ctx context.Context) {
    go apm.healthMonitor.MonitorContinuously(ctx)  // Every 60 seconds
    go apm.autoRotator.HandleHealthEvents(ctx)     // Auto-healing
    go apm.autoRotator.ScheduledMaintenance(ctx)   // Hourly rotation
    <-ctx.Done()
}
```

**Event-Driven Architecture:**
```
Health monitor detects issue
  -> Publishes PoolUnhealthyEvent
  -> AutoRotator initiates emergency rotation
  -> New pool created, old deactivated
  -> CT log updated, load balancer reroutes
  -> System healed (no human intervention)
```

---

## Performance Targets

### Certificate Issuance

| Metric | Target | Scale |
|--------|--------|-------|
| Latency (P50) | <150ms | Ed25519 pools |
| Latency (P95) | <200ms | P-256 pools |
| Latency (P99) | <300ms | With failover |
| Throughput | 10K req/sec | Network-wide |
| Success Rate | >99.9999% | With failover |

### Pool Operations

| Operation | Duration | Frequency |
|-----------|----------|-----------|
| Pool selection | <1us | Per request |
| Health check | 60s interval | Passive |
| Emergency DKG | 5 minutes | When needed |
| Scheduled DKG | 10 minutes | Every hour |

### Scalability

| Network Size | Pool Size | Threshold | Cert Issuance Time |
|--------------|-----------|-----------|-------------------|
| 1M nodes | 10K | 3.3K sigs | ~150ms |
| 10M nodes | 100K | 33K sigs | ~180ms |
| 100M nodes | 500K | 165K sigs | ~200ms |
| 1B nodes | 1M | 330K sigs | ~200ms |

**Key Insight:** Performance scales logarithmically, not linearly.

---

## Security Properties

### Threat Model

| Attack Vector | Mitigation |
|---------------|------------|
| Compromise CA nodes | TPM attestation; need 330K+ broken TPMs |
| Offline nodes | 33% threshold tolerates 67% offline |
| Replay old certs | Expiration dates; revocation via CT log |
| Man-in-the-middle | All traffic encrypted; certificate validation |
| Sybil attack | Reputation + TPM uniqueness + bandwidth proof |
| Pool selection manipulation | Deterministic VRF; publicly verifiable |
| Key theft | Threshold shares useless alone; TPM-protected |
| CT log tampering | Append-only; Merkle tree; k=10 replication |

### Security Guarantees

- **No single point of failure** (33% threshold, distributed)
- **No trusted dealer** (Pedersen DKG)
- **Hardware root of trust** (TPM 2.0 required)
- **Verifiable randomness** (VRF for pool selection)
- **Forward secrecy** (hourly key rotation)
- **Historical auditability** (CT log, Merkle tree)
- **Byzantine fault tolerance** (with TPM: 33% threshold secure)
- **Self-healing** (automatic emergency rotation)

> **Cross-Reference:** See [04-cryptographic-protocols.md](04-cryptographic-protocols.md) for cryptographic security analysis.

---

## Manufacturer CA Compromise Recovery (Issue C5 Fix)

The system provides multi-layer defense for TPM manufacturer CA compromise with comprehensive revocation, cross-attestation, and emergency trust anchor updates.

### Compromise Detection

```go
// ManufacturerCACompromise represents a detected CA breach
type ManufacturerCACompromise struct {
    ManufacturerID    string            // e.g., "Intel", "AMD", "Infineon"
    CompromisedCACert *x509.Certificate // The compromised CA certificate
    DetectedAt        time.Time
    ReportedBy        []NodeID          // Nodes that reported the compromise
    Evidence          []CompromiseEvidence
    Severity          CompromiseSeverity
    AffectedSerials   []string          // Known affected certificate serials
}

type CompromiseEvidence struct {
    Type        EvidenceType
    Description string
    Proof       []byte    // Cryptographic proof if available
    Source      string    // Where evidence came from
    Timestamp   time.Time
}

type EvidenceType uint8

const (
    EvidenceForgedCertificate  EvidenceType = iota // Forged cert using CA key
    EvidenceKeyLeakage                              // Private key found in wild
    EvidenceRogueIssuance                          // Unauthorized cert issuance
    EvidenceVendorDisclosure                       // Vendor announced breach
    EvidenceAuditFinding                           // Third-party audit found issue
)

type CompromiseSeverity uint8

const (
    SeverityPartial      CompromiseSeverity = iota // Subset of certs affected
    SeverityFull                                    // All certs from CA affected
    SeverityCatastrophic                           // Multiple CAs compromised
)

// DetectManufacturerCACompromise monitors for compromise indicators
func DetectManufacturerCACompromise(ctx context.Context) <-chan *ManufacturerCACompromise {
    compromises := make(chan *ManufacturerCACompromise)

    go func() {
        defer close(compromises)

        for {
            select {
            case <-ctx.Done():
                return

            case report := <-GetCompromiseReports():
                // Verify report validity
                if err := VerifyCompromiseReport(report); err != nil {
                    log.Printf("Invalid compromise report: %v", err)
                    continue
                }

                // Require multiple independent reports
                if report.ReporterCount < 3 {
                    AddPendingCompromiseReport(report)
                    continue
                }

                // Verify evidence
                evidence, err := ValidateCompromiseEvidence(report.Evidence)
                if err != nil {
                    log.Printf("Evidence validation failed: %v", err)
                    continue
                }

                compromise := &ManufacturerCACompromise{
                    ManufacturerID:    report.ManufacturerID,
                    CompromisedCACert: report.CACert,
                    DetectedAt:        time.Now(),
                    ReportedBy:        report.Reporters,
                    Evidence:          evidence,
                    Severity:          DetermineSeverity(evidence),
                }

                compromises <- compromise
            }
        }
    }()

    return compromises
}
```

### CA Revocation Protocol

```go
// CARevocationProtocol handles manufacturer CA compromise
type CARevocationProtocol struct {
    revocationList    *CARevocationList
    trustAnchors      *TrustAnchorStore
    emergencyContacts []EmergencyContact
}

// CARevocationList tracks revoked manufacturer CAs
type CARevocationList struct {
    Version       uint64
    LastUpdated   time.Time
    RevokedCAs    []RevokedCA
    Signatures    []PoolSignature // Signed by all 4 CA pools
}

type RevokedCA struct {
    ManufacturerID  string
    CertFingerprint [32]byte   // SHA-256 of DER-encoded cert
    SerialNumber    *big.Int
    RevokedAt       time.Time
    Reason          RevocationReason
    EffectiveDate   time.Time   // When revocation takes effect
    AffectedNodes   uint64      // Estimated affected nodes
}

type RevocationReason uint8

const (
    ReasonKeyCompromise     RevocationReason = iota
    ReasonCACompromise
    ReasonAffiliationChanged
    ReasonSuperseded
    ReasonCessationOfOperation
)

// ExecuteCARevocation performs the full revocation protocol
func (p *CARevocationProtocol) ExecuteCARevocation(
    ctx context.Context,
    compromise *ManufacturerCACompromise,
) error {
    // Phase 1: Immediate containment (0-5 minutes)
    if err := p.phase1Containment(ctx, compromise); err != nil {
        return fmt.Errorf("containment failed: %w", err)
    }

    // Phase 2: Impact assessment (5-60 minutes)
    assessment, err := p.phase2Assessment(ctx, compromise)
    if err != nil {
        return fmt.Errorf("assessment failed: %w", err)
    }

    // Phase 3: Graceful degradation (1-4 hours)
    if err := p.phase3Degradation(ctx, assessment); err != nil {
        return fmt.Errorf("degradation failed: %w", err)
    }

    // Phase 4: Re-attestation campaign (days to weeks)
    if err := p.phase4ReAttestation(ctx, assessment); err != nil {
        return fmt.Errorf("re-attestation failed: %w", err)
    }

    // Phase 5: Long-term recovery (weeks to months)
    if err := p.phase5Recovery(ctx, assessment); err != nil {
        return fmt.Errorf("recovery failed: %w", err)
    }

    return nil
}

// phase1Containment performs immediate threat containment
func (p *CARevocationProtocol) phase1Containment(
    ctx context.Context,
    compromise *ManufacturerCACompromise,
) error {
    // 1a. Stop accepting new enrollments from compromised CA
    if err := SuspendManufacturerEnrollments(compromise.ManufacturerID); err != nil {
        return fmt.Errorf("enrollment suspension failed: %w", err)
    }

    // 1b. Alert all network coordinators
    alert := &SecurityAlert{
        Type:     AlertManufacturerCACompromise,
        Severity: AlertSeverityCritical,
        Data:     compromise,
    }
    if err := BroadcastSecurityAlert(ctx, alert); err != nil {
        log.Printf("Alert broadcast partially failed: %v", err)
    }

    // 1c. Add to CA revocation list
    revokedCA := &RevokedCA{
        ManufacturerID:  compromise.ManufacturerID,
        CertFingerprint: sha256.Sum256(compromise.CompromisedCACert.Raw),
        SerialNumber:    compromise.CompromisedCACert.SerialNumber,
        RevokedAt:       time.Now(),
        Reason:          ReasonCACompromise,
        EffectiveDate:   time.Now().Add(1 * time.Hour), // 1-hour grace period
    }

    if err := p.revocationList.Add(revokedCA); err != nil {
        return fmt.Errorf("revocation list update failed: %w", err)
    }

    // 1d. Sign and publish updated revocation list
    if err := p.signAndPublishRevocationList(ctx); err != nil {
        return fmt.Errorf("revocation list publish failed: %w", err)
    }

    // 1e. Notify emergency contacts (out-of-band)
    p.notifyEmergencyContacts(compromise)

    return nil
}

// phase2Assessment evaluates compromise impact
func (p *CARevocationProtocol) phase2Assessment(
    ctx context.Context,
    compromise *ManufacturerCACompromise,
) (*ImpactAssessment, error) {
    // 2a. Identify all nodes using compromised CA
    affectedNodes, err := FindNodesByManufacturerCA(ctx, compromise.ManufacturerID)
    if err != nil {
        return nil, fmt.Errorf("node lookup failed: %w", err)
    }

    // 2b. Categorize by role and criticality
    assessment := &ImpactAssessment{
        CompromiseID:      compromise.ManufacturerID,
        TotalAffected:     len(affectedNodes),
        CoordinatorNodes:  make([]NodeInfo, 0),
        CAPoolNodes:       make([]NodeInfo, 0),
        GatewayNodes:      make([]NodeInfo, 0),
        LeafNodes:         make([]NodeInfo, 0),
        CriticalityScore:  0,
    }

    for _, node := range affectedNodes {
        switch node.Role {
        case RoleCoordinator:
            assessment.CoordinatorNodes = append(assessment.CoordinatorNodes, node)
            assessment.CriticalityScore += 100
        case RoleCAParticipant:
            assessment.CAPoolNodes = append(assessment.CAPoolNodes, node)
            assessment.CriticalityScore += 50
        case RoleGateway:
            assessment.GatewayNodes = append(assessment.GatewayNodes, node)
            assessment.CriticalityScore += 25
        default:
            assessment.LeafNodes = append(assessment.LeafNodes, node)
            assessment.CriticalityScore += 1
        }
    }

    // 2c. Calculate network impact percentage
    totalNodes := GetTotalNetworkNodes()
    assessment.ImpactPercentage = float64(assessment.TotalAffected) / float64(totalNodes)

    // 2d. Estimate recovery timeline
    assessment.EstimatedRecoveryTime = p.estimateRecoveryTime(assessment)

    return assessment, nil
}

// phase3Degradation performs graceful degradation
func (p *CARevocationProtocol) phase3Degradation(
    ctx context.Context,
    assessment *ImpactAssessment,
) error {
    // 3a. Demote affected coordinator nodes
    for _, node := range assessment.CoordinatorNodes {
        if err := DemoteNode(ctx, node.NodeID, RoleLeaf, "manufacturer_ca_compromise"); err != nil {
            log.Printf("Demotion failed for %s: %v", node.NodeID, err)
        }
    }

    // 3b. Remove affected nodes from CA pools
    for _, node := range assessment.CAPoolNodes {
        if err := RemoveFromCAPool(ctx, node.NodeID, "manufacturer_ca_compromise"); err != nil {
            log.Printf("CA pool removal failed for %s: %v", node.NodeID, err)
        }
    }

    // 3c. Trigger emergency CA pool rotation if needed
    if len(assessment.CAPoolNodes) > 0 {
        // Calculate if pool integrity is compromised
        for _, poolID := range []string{"ed25519-a", "ed25519-b", "p256-a", "p256-b"} {
            affectedInPool := CountAffectedInPool(poolID, assessment.CAPoolNodes)
            poolSize := GetPoolSize(poolID)

            // If >20% of pool is affected, rotate
            if float64(affectedInPool)/float64(poolSize) > 0.20 {
                if err := TriggerEmergencyPoolRotation(poolID); err != nil {
                    log.Printf("Emergency rotation failed for %s: %v", poolID, err)
                }
            }
        }
    }

    // 3d. Suspend affected gateway nodes
    for _, node := range assessment.GatewayNodes {
        if err := SuspendGateway(ctx, node.NodeID, "manufacturer_ca_compromise"); err != nil {
            log.Printf("Gateway suspension failed for %s: %v", node.NodeID, err)
        }
    }

    return nil
}
```

### Cross-Manufacturer Attestation

```go
// CrossManufacturerAttestation provides defense-in-depth for high-value nodes
type CrossManufacturerAttestation struct {
    NodeID          NodeID
    PrimaryTPM      TPMInfo             // Node's primary TPM
    SecondaryTPMs   []TPMInfo           // Additional TPMs from different manufacturers
    Attestations    map[string]*TPMQuote // Manufacturer -> Quote
    CrossValidated  bool
    ValidatedAt     time.Time
}

type TPMInfo struct {
    Manufacturer    string            // "Intel", "AMD", "Infineon", etc.
    Model           string
    FirmwareVersion string
    EKCertificate   *x509.Certificate
    EKFingerprint   [32]byte
}

type TPMQuote struct {
    Nonce           [32]byte
    PCRSelection    []int
    PCRDigest       [32]byte
    Quote           []byte    // TPM2_Quote output
    Signature       []byte
    Timestamp       time.Time
}

// RequireCrossAttestation mandates multi-vendor attestation for critical nodes
func RequireCrossAttestation(
    ctx context.Context,
    nodeID NodeID,
    minManufacturers int,
) error {
    node, err := GetNodeInfo(nodeID)
    if err != nil {
        return fmt.Errorf("node lookup failed: %w", err)
    }

    // Get node's available TPMs
    tpms, err := node.GetAvailableTPMs(ctx)
    if err != nil {
        return fmt.Errorf("TPM enumeration failed: %w", err)
    }

    // Check manufacturer diversity
    manufacturers := make(map[string]TPMInfo)
    for _, tpm := range tpms {
        manufacturers[tpm.Manufacturer] = tpm
    }

    if len(manufacturers) < minManufacturers {
        return ErrInsufficientManufacturerDiversity{
            Required: minManufacturers,
            Found:    len(manufacturers),
        }
    }

    // Perform cross-attestation
    crossAttest := &CrossManufacturerAttestation{
        NodeID:        nodeID,
        PrimaryTPM:    tpms[0],
        SecondaryTPMs: tpms[1:],
        Attestations:  make(map[string]*TPMQuote),
    }

    // Generate shared nonce for all attestations
    nonce := GenerateAttestationNonce()

    // Collect attestations from all TPMs
    for mfr, tpm := range manufacturers {
        quote, err := PerformTPMQuote(ctx, tpm, nonce, StandardPCRSelection)
        if err != nil {
            return fmt.Errorf("quote from %s failed: %w", mfr, err)
        }
        crossAttest.Attestations[mfr] = quote
    }

    // Validate cross-attestation
    if err := ValidateCrossAttestation(crossAttest); err != nil {
        return fmt.Errorf("cross-attestation validation failed: %w", err)
    }

    crossAttest.CrossValidated = true
    crossAttest.ValidatedAt = time.Now()

    // Store cross-attestation record
    if err := StoreCrossAttestation(crossAttest); err != nil {
        return fmt.Errorf("cross-attestation storage failed: %w", err)
    }

    return nil
}

// ValidateCrossAttestation verifies all TPMs attest to same system state
func ValidateCrossAttestation(cma *CrossManufacturerAttestation) error {
    // Requirement 1: At least 2 different manufacturers
    if len(cma.Attestations) < 2 {
        return ErrInsufficientAttestations{
            Required: 2,
            Got:      len(cma.Attestations),
        }
    }

    // Requirement 2: All attestations use same nonce
    var expectedNonce [32]byte
    nonceSet := false
    for mfr, quote := range cma.Attestations {
        if !nonceSet {
            expectedNonce = quote.Nonce
            nonceSet = true
        } else if quote.Nonce != expectedNonce {
            return ErrNonceMismatch{
                Manufacturer: mfr,
                Expected:     expectedNonce,
                Got:          quote.Nonce,
            }
        }
    }

    // Requirement 3: All TPMs attest same PCR values
    var expectedPCRDigest [32]byte
    digestSet := false
    for mfr, quote := range cma.Attestations {
        if !digestSet {
            expectedPCRDigest = quote.PCRDigest
            digestSet = true
        } else if quote.PCRDigest != expectedPCRDigest {
            return ErrPCRMismatch{
                Manufacturer: mfr,
                Expected:     expectedPCRDigest,
                Got:          quote.PCRDigest,
            }
        }
    }

    // Requirement 4: All quote signatures are valid
    for mfr, quote := range cma.Attestations {
        tpm := cma.getTPMByManufacturer(mfr)
        if err := VerifyTPMQuoteSignature(quote, tpm.EKCertificate); err != nil {
            return ErrInvalidQuoteSignature{
                Manufacturer: mfr,
                Err:          err,
            }
        }
    }

    // Requirement 5: Timestamp freshness (within 30 seconds)
    now := time.Now()
    for mfr, quote := range cma.Attestations {
        if now.Sub(quote.Timestamp) > 30*time.Second {
            return ErrQuoteStale{
                Manufacturer: mfr,
                Age:          now.Sub(quote.Timestamp),
            }
        }
    }

    return nil
}
```

### Emergency Trust Anchor Update

```go
// EmergencyTrustAnchorUpdate handles trust anchor replacement
type EmergencyTrustAnchorUpdate struct {
    UpdateID        string
    Reason          string
    OldAnchors      []TrustAnchor
    NewAnchors      []TrustAnchor
    EffectiveDate   time.Time
    GracePeriod     time.Duration
    Signatures      []PoolSignature
}

type TrustAnchor struct {
    ManufacturerID  string
    CACertificate   *x509.Certificate
    Fingerprint     [32]byte
    ValidFrom       time.Time
    ValidUntil      time.Time
    Status          TrustAnchorStatus
}

type TrustAnchorStatus uint8

const (
    TrustAnchorActive     TrustAnchorStatus = iota
    TrustAnchorPending                      // Not yet effective
    TrustAnchorRevoked                      // Compromised/revoked
    TrustAnchorExpired                      // Past validity period
    TrustAnchorSuperseded                   // Replaced by newer anchor
)

// ExecuteEmergencyTrustAnchorUpdate replaces compromised trust anchors
func ExecuteEmergencyTrustAnchorUpdate(
    ctx context.Context,
    compromise *ManufacturerCACompromise,
    newCACert *x509.Certificate,
) error {
    // Step 1: Validate new CA certificate
    if err := ValidateNewCACertificate(newCACert); err != nil {
        return fmt.Errorf("new CA validation failed: %w", err)
    }

    // Step 2: Create trust anchor update
    update := &EmergencyTrustAnchorUpdate{
        UpdateID: GenerateUpdateID(),
        Reason:   fmt.Sprintf("Manufacturer CA compromise: %s", compromise.ManufacturerID),
        OldAnchors: []TrustAnchor{
            {
                ManufacturerID: compromise.ManufacturerID,
                CACertificate:  compromise.CompromisedCACert,
                Fingerprint:    sha256.Sum256(compromise.CompromisedCACert.Raw),
                Status:         TrustAnchorRevoked,
            },
        },
        NewAnchors: []TrustAnchor{
            {
                ManufacturerID: compromise.ManufacturerID,
                CACertificate:  newCACert,
                Fingerprint:    sha256.Sum256(newCACert.Raw),
                ValidFrom:      time.Now().Add(24 * time.Hour), // 24-hour notice
                ValidUntil:     newCACert.NotAfter,
                Status:         TrustAnchorPending,
            },
        },
        EffectiveDate: time.Now().Add(24 * time.Hour),
        GracePeriod:   7 * 24 * time.Hour, // 7-day grace period
    }

    // Step 3: Get threshold signatures from all CA pools
    updateData := EncodeUpdateForSigning(update)

    for _, poolID := range []string{"ed25519-a", "ed25519-b", "p256-a", "p256-b"} {
        pool, err := GetPoolByID(poolID)
        if err != nil {
            return fmt.Errorf("pool %s not found: %w", poolID, err)
        }

        sig, err := pool.ThresholdSign(ctx, updateData)
        if err != nil {
            return fmt.Errorf("pool %s signing failed: %w", poolID, err)
        }

        update.Signatures = append(update.Signatures, PoolSignature{
            PoolID:    poolID,
            Signature: sig.Signature,
        })
    }

    // Step 4: Publish update to DHT with high replication
    if err := PublishTrustAnchorUpdate(ctx, update); err != nil {
        return fmt.Errorf("update publish failed: %w", err)
    }

    // Step 5: Broadcast update notification
    if err := BroadcastTrustAnchorUpdate(ctx, update); err != nil {
        log.Printf("Broadcast partially failed: %v", err)
    }

    return nil
}

// ValidateTrustAnchorUpdate verifies an incoming trust anchor update
func ValidateTrustAnchorUpdate(update *EmergencyTrustAnchorUpdate) error {
    // Require signatures from all 4 pools
    if len(update.Signatures) < 4 {
        return ErrInsufficientUpdateSignatures{
            Required: 4,
            Got:      len(update.Signatures),
        }
    }

    // Verify each signature
    updateData := EncodeUpdateForSigning(update)
    for _, sig := range update.Signatures {
        pool, err := GetPoolByID(sig.PoolID)
        if err != nil {
            return fmt.Errorf("pool lookup failed: %w", err)
        }

        if !frost.Verify(pool.GroupPubKey, updateData, sig.Signature) {
            return ErrInvalidUpdateSignature{PoolID: sig.PoolID}
        }
    }

    // Validate new anchor certificates
    for _, anchor := range update.NewAnchors {
        if err := ValidateNewCACertificate(anchor.CACertificate); err != nil {
            return fmt.Errorf("invalid new anchor: %w", err)
        }
    }

    return nil
}
```

### Network Survival Matrix

| Scenario | Affected Nodes | Network Status | Recovery Action | Timeline |
|----------|----------------|----------------|-----------------|----------|
| 1 manufacturer compromised | ~20-30% | Operational | Demote affected, rotate pools, re-attest | Days |
| 2 manufacturers compromised | ~50-60% | Degraded | Emergency rotation, cross-attestation | Weeks |
| 3 manufacturers compromised | ~75-85% | Critical | Genesis key activation | Weeks |
| All manufacturers compromised | 100% | Emergency | Full genesis recovery | Months |

---

## Total CA Pool Failure Recovery (Issue C12 Fix)

Genesis key escrow with M-of-N recovery provides a comprehensive bootstrap protocol for complete CA pool failure scenarios, ensuring network recovery even in catastrophic circumstances.

### Genesis Trustee Protocol

```go
// GenesisTrusteeProtocol manages the trusted parties holding recovery keys
type GenesisTrusteeProtocol struct {
    trustees         []GenesisT trustee
    threshold        int       // M of N required
    totalShares      int       // N total
    shareCommitments [][32]byte
    genesisPublicKey *ecdsa.PublicKey
    lastVerification time.Time
}

// GenesisTrustee represents a key custodian
type GenesisTrustee struct {
    ID                string
    Organization      string              // e.g., "EFF", "ISRG", "Mozilla Foundation"
    OrganizationType  OrganizationType
    Location          GeographicLocation
    PublicKey         *ecdsa.PublicKey    // For encrypted share delivery
    ShareCommitment   [32]byte            // SHA-256(share) for verification
    ContactInfo       TrusteeContact
    LastVerification  time.Time
    VerificationCount uint32
    Status            TrusteeStatus
}

type OrganizationType uint8

const (
    OrgNonProfit      OrganizationType = iota // Non-profit organizations
    OrgAcademic                               // Universities/research institutions
    OrgGovernment                             // Government entities (multi-national)
    OrgFoundation                             // Technical foundations
    OrgCorporate                              // Major tech companies (limited)
)

type GeographicLocation struct {
    Country    string
    Continent  string
    Region     string
    TimeZone   string
}

type TrusteeContact struct {
    PrimaryEmail    string
    SecondaryEmail  string
    Phone           string
    SignalNumber    string              // For emergency contact
    PGPKeyID        string
}

type TrusteeStatus uint8

const (
    TrusteeActive       TrusteeStatus = iota
    TrusteeSuspended                   // Temporarily unavailable
    TrusteeRevoked                     // Removed from protocol
    TrusteePending                     // Awaiting verification
)

// DefaultTrusteeRequirements returns production trustee diversity requirements
func DefaultTrusteeRequirements() *TrusteeRequirements {
    return &TrusteeRequirements{
        MinTrustees:             9,
        Threshold:               5,     // 5-of-9
        MinCountries:            5,
        MinContinents:           3,
        MaxPerOrganization:      1,
        MaxPerOrgType:           3,
        MaxPerCountry:           2,
        RequiredOrgTypes: []OrganizationType{
            OrgNonProfit,
            OrgAcademic,
            OrgFoundation,
        },
        VerificationInterval:    90 * 24 * time.Hour, // Quarterly
    }
}

// ValidateTrusteeDistribution ensures trustees meet diversity requirements
func ValidateTrusteeDistribution(trustees []GenesisTrustee) error {
    req := DefaultTrusteeRequirements()

    // Check minimum trustee count
    if len(trustees) < req.MinTrustees {
        return ErrInsufficientTrustees{Required: req.MinTrustees, Got: len(trustees)}
    }

    // Check geographic distribution
    countries := make(map[string]int)
    continents := make(map[string]int)
    for _, t := range trustees {
        countries[t.Location.Country]++
        continents[t.Location.Continent]++
    }

    if len(countries) < req.MinCountries {
        return ErrInsufficientCountries{Required: req.MinCountries, Got: len(countries)}
    }

    if len(continents) < req.MinContinents {
        return ErrInsufficientContinents{Required: req.MinContinents, Got: len(continents)}
    }

    // Check per-country limit
    for country, count := range countries {
        if count > req.MaxPerCountry {
            return ErrCountryLimitExceeded{Country: country, Limit: req.MaxPerCountry, Got: count}
        }
    }

    // Check organization type distribution
    orgTypes := make(map[OrganizationType]int)
    for _, t := range trustees {
        orgTypes[t.OrganizationType]++
    }

    for _, requiredType := range req.RequiredOrgTypes {
        if orgTypes[requiredType] == 0 {
            return ErrMissingOrgType{Type: requiredType}
        }
    }

    for orgType, count := range orgTypes {
        if count > req.MaxPerOrgType {
            return ErrOrgTypeLimitExceeded{Type: orgType, Limit: req.MaxPerOrgType, Got: count}
        }
    }

    return nil
}
```

### Cold Storage Key Activation

```go
// ColdStorageKeyActivation manages secure key recovery from cold storage
type ColdStorageKeyActivation struct {
    ActivationID      string
    RequestedAt       time.Time
    RequestedBy       []NodeID            // Nodes that requested activation
    Reason            ActivationReason
    Status            ActivationStatus
    CollectedShares   []*DecryptedShare
    ReconstructedKey  *ecdsa.PrivateKey   // Only populated during ceremony
    CeremonyLog       *ActivationAuditLog
}

type ActivationReason uint8

const (
    ReasonTotalPoolFailure    ActivationReason = iota // All CA pools failed
    ReasonNetworkPartition                             // Network split recovery
    ReasonGenesisMigration                             // Planned key rotation
    ReasonSecurityIncident                             // Emergency response
)

type ActivationStatus uint8

const (
    ActivationPending        ActivationStatus = iota
    ActivationShareCollection
    ActivationKeyReconstruction
    ActivationPoolBootstrap
    ActivationComplete
    ActivationAborted
)

// DecryptedShare represents a trustee's decrypted key share
type DecryptedShare struct {
    TrusteeID       string
    ShareData       []byte              // Decrypted Shamir share
    ShareIndex      int                 // Share index for reconstruction
    ProvidedAt      time.Time
    VerificationSig []byte              // Trustee's signature on provision
}

// InitiateColdStorageActivation starts the key recovery process
func InitiateColdStorageActivation(
    ctx context.Context,
    reason ActivationReason,
    requesters []NodeID,
) (*ColdStorageKeyActivation, error) {
    // Step 1: Verify activation conditions are met
    if err := VerifyActivationConditions(reason); err != nil {
        return nil, fmt.Errorf("conditions not met: %w", err)
    }

    // Step 2: Create activation record
    activation := &ColdStorageKeyActivation{
        ActivationID:    GenerateActivationID(),
        RequestedAt:     time.Now(),
        RequestedBy:     requesters,
        Reason:          reason,
        Status:          ActivationPending,
        CollectedShares: make([]*DecryptedShare, 0),
        CeremonyLog:     NewActivationAuditLog(),
    }

    // Step 3: Log activation initiation
    activation.CeremonyLog.Log(CeremonyEventInitiated, map[string]interface{}{
        "reason":     reason,
        "requesters": requesters,
    })

    // Step 4: Notify trustees
    trustees := GetActiveTrustees()
    for _, trustee := range trustees {
        if err := NotifyTrusteeActivation(trustee, activation); err != nil {
            log.Printf("Failed to notify trustee %s: %v", trustee.ID, err)
        }
    }

    // Step 5: Store activation record
    if err := StoreActivation(activation); err != nil {
        return nil, fmt.Errorf("activation storage failed: %w", err)
    }

    activation.Status = ActivationShareCollection

    return activation, nil
}

// VerifyActivationConditions ensures recovery is warranted
func VerifyActivationConditions(reason ActivationReason) error {
    switch reason {
    case ReasonTotalPoolFailure:
        // Verify all pools are actually down
        for _, poolID := range []string{"ed25519-a", "ed25519-b", "p256-a", "p256-b"} {
            pool, err := GetPoolByID(poolID)
            if err == nil && pool.IsHealthy() {
                return ErrPoolStillOperational{PoolID: poolID}
            }
        }

        // Verify failure duration exceeds threshold
        failureDuration := GetPoolFailureDuration()
        if failureDuration < 4*time.Hour {
            return ErrInsufficientFailureDuration{
                Required: 4 * time.Hour,
                Actual:   failureDuration,
            }
        }

    case ReasonNetworkPartition:
        // Verify network partition exists
        if !IsNetworkPartitioned() {
            return ErrNoPartitionDetected
        }

    case ReasonSecurityIncident:
        // Require multiple independent incident reports
        reports := GetSecurityIncidentReports()
        if len(reports) < 3 {
            return ErrInsufficientIncidentReports{Required: 3, Got: len(reports)}
        }
    }

    return nil
}

// CollectTrusteeShare receives and validates a trustee's share
func (a *ColdStorageKeyActivation) CollectTrusteeShare(
    ctx context.Context,
    trusteeID string,
    encryptedShare []byte,
    signature []byte,
) error {
    // Step 1: Get trustee info
    trustee, err := GetTrusteeByID(trusteeID)
    if err != nil {
        return fmt.Errorf("trustee not found: %w", err)
    }

    // Step 2: Verify trustee signature
    signedData := append([]byte(a.ActivationID), encryptedShare...)
    if !VerifySignature(trustee.PublicKey, signedData, signature) {
        return ErrInvalidTrusteeSignature{TrusteeID: trusteeID}
    }

    // Step 3: Decrypt share using ceremony key
    ceremonyKey := GetCeremonyDecryptionKey()
    decryptedShare, err := ecies.Decrypt(ceremonyKey, encryptedShare)
    if err != nil {
        return fmt.Errorf("share decryption failed: %w", err)
    }

    // Step 4: Verify share commitment
    shareCommitment := sha256.Sum256(decryptedShare)
    if shareCommitment != trustee.ShareCommitment {
        return ErrShareCommitmentMismatch{TrusteeID: trusteeID}
    }

    // Step 5: Extract share index
    shareIndex, shareData := ParseShamirShare(decryptedShare)

    // Step 6: Store collected share
    share := &DecryptedShare{
        TrusteeID:       trusteeID,
        ShareData:       shareData,
        ShareIndex:      shareIndex,
        ProvidedAt:      time.Now(),
        VerificationSig: signature,
    }

    a.CollectedShares = append(a.CollectedShares, share)

    // Step 7: Log collection
    a.CeremonyLog.Log(CeremonyEventShareCollected, map[string]interface{}{
        "trustee_id": trusteeID,
        "share_index": shareIndex,
        "total_collected": len(a.CollectedShares),
    })

    return nil
}
```

### Bootstrap Sequence

```go
// BootstrapSequence performs full network recovery from genesis keys
type BootstrapSequence struct {
    Activation       *ColdStorageKeyActivation
    ReconstructedKey *ecdsa.PrivateKey
    BootstrappedPools []*CAPool
    Status           BootstrapStatus
    AuditLog         *BootstrapAuditLog
}

type BootstrapStatus uint8

const (
    BootstrapPending          BootstrapStatus = iota
    BootstrapKeyReconstruction
    BootstrapTrusteeSelection
    BootstrapDKGExecution
    BootstrapPoolActivation
    BootstrapNetworkAnnouncement
    BootstrapComplete
    BootstrapFailed
)

// ExecuteBootstrapSequence performs the full recovery procedure
func ExecuteBootstrapSequence(
    ctx context.Context,
    activation *ColdStorageKeyActivation,
) error {
    bootstrap := &BootstrapSequence{
        Activation: activation,
        Status:     BootstrapPending,
        AuditLog:   NewBootstrapAuditLog(),
    }

    // Phase 1: Reconstruct genesis key
    if err := bootstrap.phase1KeyReconstruction(ctx); err != nil {
        bootstrap.Status = BootstrapFailed
        return fmt.Errorf("key reconstruction failed: %w", err)
    }

    // Phase 2: Select initial pool members
    if err := bootstrap.phase2TrusteeSelection(ctx); err != nil {
        bootstrap.Status = BootstrapFailed
        return fmt.Errorf("trustee selection failed: %w", err)
    }

    // Phase 3: Execute emergency DKG for all pools
    if err := bootstrap.phase3DKGExecution(ctx); err != nil {
        bootstrap.Status = BootstrapFailed
        return fmt.Errorf("DKG execution failed: %w", err)
    }

    // Phase 4: Activate new pools
    if err := bootstrap.phase4PoolActivation(ctx); err != nil {
        bootstrap.Status = BootstrapFailed
        return fmt.Errorf("pool activation failed: %w", err)
    }

    // Phase 5: Announce recovery to network
    if err := bootstrap.phase5NetworkAnnouncement(ctx); err != nil {
        // Non-fatal: pools are active, announcement can be retried
        log.Printf("Network announcement partially failed: %v", err)
    }

    // Phase 6: Secure cleanup
    bootstrap.phase6SecureCleanup()

    bootstrap.Status = BootstrapComplete
    return nil
}

// phase1KeyReconstruction reconstructs genesis key from shares
func (b *BootstrapSequence) phase1KeyReconstruction(ctx context.Context) error {
    b.Status = BootstrapKeyReconstruction
    b.AuditLog.Log(BootstrapEventKeyReconstructionStart, nil)

    activation := b.Activation

    // Verify threshold is met
    threshold := GetGenesisThreshold()
    if len(activation.CollectedShares) < threshold {
        return ErrInsufficientShares{
            Required: threshold,
            Got:      len(activation.CollectedShares),
        }
    }

    // Prepare shares for Shamir reconstruction
    shares := make([][]byte, 0, len(activation.CollectedShares))
    indices := make([]int, 0, len(activation.CollectedShares))

    for _, share := range activation.CollectedShares {
        shares = append(shares, share.ShareData)
        indices = append(indices, share.ShareIndex)
    }

    // Reconstruct secret
    secret, err := ShamirReconstruct(shares, indices)
    if err != nil {
        return fmt.Errorf("Shamir reconstruction failed: %w", err)
    }

    // Convert to ECDSA private key
    privateKey, err := BytesToECDSAPrivateKey(secret)
    if err != nil {
        return fmt.Errorf("key conversion failed: %w", err)
    }

    // Verify against known public key
    if !PublicKeysEqual(&privateKey.PublicKey, GetGenesisPublicKey()) {
        return ErrReconstructedKeyMismatch
    }

    b.ReconstructedKey = privateKey
    b.AuditLog.Log(BootstrapEventKeyReconstructed, nil)

    return nil
}

// phase2TrusteeSelection selects nodes for initial pool membership
func (b *BootstrapSequence) phase2TrusteeSelection(ctx context.Context) error {
    b.Status = BootstrapTrusteeSelection
    b.AuditLog.Log(BootstrapEventTrusteeSelectionStart, nil)

    // Get historically trusted nodes
    // During recovery, we use nodes with highest historical reputation
    trustedNodes, err := GetHistoricallyTrustedNodes(ctx, 200)
    if err != nil {
        return fmt.Errorf("trusted node lookup failed: %w", err)
    }

    if len(trustedNodes) < 100 {
        return ErrInsufficientTrustedNodes{Required: 100, Got: len(trustedNodes)}
    }

    // Verify node availability
    availableNodes := make([]NodeInfo, 0)
    for _, node := range trustedNodes {
        if IsNodeOnline(ctx, node.NodeID) {
            availableNodes = append(availableNodes, node)
        }
    }

    if len(availableNodes) < 100 {
        return ErrInsufficientAvailableNodes{Required: 100, Got: len(availableNodes)}
    }

    // Apply diversity constraints for pool selection
    selector := &VRFPoolSelector{}
    b.selectedNodes = selector.applyDiversityConstraints(
        convertToScoredNodes(availableNodes),
        100,
    )

    b.AuditLog.Log(BootstrapEventTrusteeSelectionComplete, map[string]interface{}{
        "selected_count": len(b.selectedNodes),
    })

    return nil
}

// phase3DKGExecution runs emergency DKG for all pools
func (b *BootstrapSequence) phase3DKGExecution(ctx context.Context) error {
    b.Status = BootstrapDKGExecution
    b.AuditLog.Log(BootstrapEventDKGStart, nil)

    poolConfigs := []struct {
        ID        string
        Algorithm string
        Members   []NodeInfo
    }{
        {"ed25519-a", "ed25519", b.selectedNodes[:25]},
        {"ed25519-b", "ed25519", b.selectedNodes[25:50]},
        {"p256-a", "p256", b.selectedNodes[50:75]},
        {"p256-b", "p256", b.selectedNodes[75:100]},
    }

    b.BootstrappedPools = make([]*CAPool, 0, 4)

    for _, config := range poolConfigs {
        // Run emergency DKG with shorter timeouts
        dkgResult, err := RunEmergencyDKG(ctx, config.Algorithm, config.Members, EmergencyDKGConfig{
            Timeout:   5 * time.Minute,
            Threshold: len(config.Members) / 3,
        })
        if err != nil {
            return fmt.Errorf("DKG failed for %s: %w", config.ID, err)
        }

        // Create pool creation certificate signed by genesis key
        poolCert := &PoolCreationCertificate{
            PoolID:       config.ID,
            Algorithm:    config.Algorithm,
            GroupPubKey:  dkgResult.GroupPublicKey,
            Participants: ExtractNodeIDs(config.Members),
            Threshold:    dkgResult.Threshold,
            CreatedAt:    time.Now(),
            Epoch:        0, // Reset epoch for recovery
            IsRecovery:   true,
        }

        // Sign with genesis key
        certData := EncodeCertForSigning(poolCert)
        sig, err := ecdsa.Sign(rand.Reader, b.ReconstructedKey, sha256Sum(certData))
        if err != nil {
            return fmt.Errorf("genesis signature failed: %w", err)
        }
        poolCert.GenesisSignature = sig

        // Create pool
        pool := &CAPool{
            ID:                  config.ID,
            Algorithm:           config.Algorithm,
            GroupPublicKey:      dkgResult.GroupPublicKey,
            Threshold:           dkgResult.Threshold,
            Members:             config.Members,
            CreationCertificate: poolCert,
            Status:              PoolPendingActivation,
        }

        b.BootstrappedPools = append(b.BootstrappedPools, pool)

        b.AuditLog.Log(BootstrapEventPoolDKGComplete, map[string]interface{}{
            "pool_id": config.ID,
        })
    }

    return nil
}

// phase4PoolActivation activates all bootstrapped pools
func (b *BootstrapSequence) phase4PoolActivation(ctx context.Context) error {
    b.Status = BootstrapPoolActivation
    b.AuditLog.Log(BootstrapEventActivationStart, nil)

    for _, pool := range b.BootstrappedPools {
        // Store pool in DHT
        if err := StorePoolInDHT(ctx, pool); err != nil {
            return fmt.Errorf("pool storage failed for %s: %w", pool.ID, err)
        }

        // Update CT log with new pool
        ctEntry := &CTLogEntry{
            Epoch:        0,
            Timestamp:    time.Now(),
            Algorithm:    pool.Algorithm,
            PoolID:       pool.ID,
            GroupPubKey:  pool.GroupPublicKey,
            Participants: ExtractNodeIDs(pool.Members),
            IsRecovery:   true,
            RecoveryInfo: &RecoveryInfo{
                ActivationID: b.Activation.ActivationID,
                Reason:       b.Activation.Reason,
            },
        }

        if err := AppendCTLogEntry(ctx, ctEntry); err != nil {
            return fmt.Errorf("CT log update failed for %s: %w", pool.ID, err)
        }

        // Activate pool
        pool.Status = PoolActive
        if err := ActivatePool(ctx, pool); err != nil {
            return fmt.Errorf("pool activation failed for %s: %w", pool.ID, err)
        }

        b.AuditLog.Log(BootstrapEventPoolActivated, map[string]interface{}{
            "pool_id": pool.ID,
        })
    }

    return nil
}

// phase5NetworkAnnouncement broadcasts recovery completion
func (b *BootstrapSequence) phase5NetworkAnnouncement(ctx context.Context) error {
    b.Status = BootstrapNetworkAnnouncement
    b.AuditLog.Log(BootstrapEventAnnouncementStart, nil)

    announcement := &RecoveryAnnouncement{
        Type:         AnnouncementTypeRecoveryComplete,
        ActivationID: b.Activation.ActivationID,
        Pools:        ExtractPoolSummaries(b.BootstrappedPools),
        Timestamp:    time.Now(),
    }

    // Sign announcement with all new pools
    for _, pool := range b.BootstrappedPools {
        sig, err := pool.ThresholdSign(ctx, EncodeAnnouncement(announcement))
        if err != nil {
            log.Printf("Announcement signing failed for %s: %v", pool.ID, err)
            continue
        }
        announcement.Signatures = append(announcement.Signatures, PoolSignature{
            PoolID:    pool.ID,
            Signature: sig.Signature,
        })
    }

    // Broadcast to all known nodes
    if err := BroadcastAnnouncement(ctx, announcement); err != nil {
        return fmt.Errorf("broadcast failed: %w", err)
    }

    b.AuditLog.Log(BootstrapEventAnnouncementComplete, nil)

    return nil
}

// phase6SecureCleanup securely destroys reconstructed key
func (b *BootstrapSequence) phase6SecureCleanup() {
    b.AuditLog.Log(BootstrapEventCleanupStart, nil)

    // Zero out reconstructed key from memory
    if b.ReconstructedKey != nil {
        ZeroMemory(b.ReconstructedKey.D.Bytes())
        b.ReconstructedKey = nil
    }

    // Zero out collected shares
    for _, share := range b.Activation.CollectedShares {
        ZeroMemory(share.ShareData)
        share.ShareData = nil
    }

    b.AuditLog.Log(BootstrapEventCleanupComplete, nil)
}

// ZeroMemory securely zeros a byte slice
func ZeroMemory(data []byte) {
    for i := range data {
        data[i] = 0
    }
    // Force memory barrier to prevent optimization
    runtime.KeepAlive(data)
}
```

### Genesis Key Creation Ceremony

```go
// GenesisKeyCreationCeremony creates initial escrow during network setup
func GenesisKeyCreationCeremony(
    ctx context.Context,
    trustees []GenesisTrustee,
) (*GenesisKeyEscrow, error) {
    // Step 1: Validate trustee distribution
    if err := ValidateTrusteeDistribution(trustees); err != nil {
        return nil, fmt.Errorf("trustee validation failed: %w", err)
    }

    threshold := 5 // 5-of-9 default
    if len(trustees) > 9 {
        threshold = (len(trustees) * 5) / 9 // Scale threshold proportionally
    }

    // Step 2: Generate genesis keypair in secure enclave
    genesisKey, err := GenerateGenesisKeyInEnclave()
    if err != nil {
        return nil, fmt.Errorf("key generation failed: %w", err)
    }

    // Step 3: Split using Shamir's Secret Sharing
    shares, err := ShamirSplit(genesisKey.D.Bytes(), threshold, len(trustees))
    if err != nil {
        return nil, fmt.Errorf("Shamir split failed: %w", err)
    }

    // Step 4: Create escrow record
    escrow := &GenesisKeyEscrow{
        Version:          1,
        CreatedAt:        time.Now(),
        Threshold:        threshold,
        TotalShares:      len(trustees),
        GenesisPublicKey: &genesisKey.PublicKey,
        Trustees:         make([]TrusteeRecord, len(trustees)),
    }

    // Step 5: Encrypt and distribute shares to trustees
    for i, trustee := range trustees {
        // Add share index to share data
        indexedShare := PrependShareIndex(shares[i], i)

        // Encrypt share for trustee's public key
        encryptedShare, err := ecies.Encrypt(trustee.PublicKey, indexedShare)
        if err != nil {
            return nil, fmt.Errorf("share encryption failed for %s: %w", trustee.ID, err)
        }

        // Compute commitment
        commitment := sha256.Sum256(indexedShare)

        // Record trustee info
        escrow.Trustees[i] = TrusteeRecord{
            ID:              trustee.ID,
            Organization:    trustee.Organization,
            Location:        trustee.Location,
            PublicKey:       trustee.PublicKey,
            ShareCommitment: commitment,
        }

        // Securely deliver encrypted share to trustee
        if err := DeliverShareToCustodian(ctx, trustee, encryptedShare); err != nil {
            return nil, fmt.Errorf("share delivery failed for %s: %w", trustee.ID, err)
        }
    }

    // Step 6: Compute overall escrow commitment
    escrow.EscrowCommitment = ComputeEscrowCommitment(escrow)

    // Step 7: Store escrow metadata (NOT the shares!)
    if err := StoreEscrowMetadata(ctx, escrow); err != nil {
        return nil, fmt.Errorf("escrow storage failed: %w", err)
    }

    // Step 8: Publish genesis public key
    if err := PublishGenesisPublicKey(ctx, escrow.GenesisPublicKey); err != nil {
        return nil, fmt.Errorf("public key publish failed: %w", err)
    }

    // Step 9: Secure cleanup - destroy genesis key and shares
    ZeroMemory(genesisKey.D.Bytes())
    for _, share := range shares {
        ZeroMemory(share)
    }

    return escrow, nil
}

// GenesisKeyEscrow stores metadata for emergency recovery
type GenesisKeyEscrow struct {
    Version          uint8
    CreatedAt        time.Time
    Threshold        int
    TotalShares      int
    GenesisPublicKey *ecdsa.PublicKey
    Trustees         []TrusteeRecord
    EscrowCommitment [32]byte
}

type TrusteeRecord struct {
    ID              string
    Organization    string
    Location        GeographicLocation
    PublicKey       *ecdsa.PublicKey
    ShareCommitment [32]byte
}
```

### Genesis Key Custodian Requirements

| Requirement | Specification | Rationale |
|-------------|---------------|-----------|
| Geographic distribution | Minimum 5 countries, 3 continents | Prevents regional seizure |
| Organizational diversity | Mix of non-profits, universities, companies | Prevents single-org control |
| Security requirements | HSM storage, air-gapped systems | Protects key material |
| Legal jurisdiction | Multiple legal jurisdictions | Prevents legal coercion |
| Threshold | 5-of-9 recommended | Balances security and availability |
| Audit | Annual key share verification | Ensures recoverability |
| Communication | Multiple secure channels (Signal, PGP) | Emergency coordination |
| Backup custodians | 2 alternates per primary | Handles trustee unavailability |

### Recovery Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Detection | 0-4 hours | Automated detection of total pool failure |
| Verification | 4-8 hours | Verify failure conditions, multiple confirmations |
| Trustee notification | 8-24 hours | Contact trustees through multiple channels |
| Share collection | 24-72 hours | Trustees provide encrypted shares |
| Key reconstruction | 1-2 hours | Ceremony to reconstruct genesis key |
| DKG execution | 1-2 hours | Run DKG for all 4 pools |
| Pool activation | 30 minutes | Activate and publish pools |
| Network announcement | 1 hour | Broadcast recovery to network |
| **Total** | **3-5 days** | Full recovery timeline |

---

## Implementation Phases

### Phase 1: Core Threshold Signatures (Weeks 1-2)
- FROST(Ed25519) per RFC 9591 Section 6.1
- FROST(P-256) per RFC 9591 Section 6.4
- Pedersen DKG integration
- Unit tests (90%+ coverage)

> **Cross-Reference:** See [04-cryptographic-protocols.md](04-cryptographic-protocols.md) for FROST/DKG details.

### Phase 2: Certificate Transparency (Week 3)
- CT log structure (Merkle tree)
- DHT integration (storage, replication)
- Historical validation

### Phase 3: Pool Management (Weeks 4-5)
- Pool lifecycle (creation, rotation, deactivation)
- Health monitoring (passive, event-driven)
- Load balancing (round-robin, failover)

### Phase 4: TPM Integration (Week 6)
- Remote attestation protocol
- TPM quote verification
- Integration with pool selection

### Phase 5: Testing and Optimization (Weeks 7-8)
- Large-scale simulation (100K+ nodes)
- Performance benchmarks
- Security audit

---

## Planned Enhancements

**V1.0 (High Priority):**
- Certificate Pinning (TOFU)
- Clock Synchronization (NTP enforcement)
- Certificate Caching
- Bloom Filter Revocation

**V1.1 (Medium Priority):**
- BGP RPKI
- Network Partition Handling
- Reputation Gossiping

**V2.0 (Future):**
- Post-Quantum Cryptography (Dilithium)
- Batch Certificate Issuance

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-07 | Platform Team | Initial CA architecture specification |
| 1.1 | 2026-01-10 | Platform Team | Added ACME challenge edge cases, CA rotation with pending requests, pool failure scenarios, CT log edge cases, and new API endpoints |
| 1.2 | 2026-01-10 | Platform Team | Added three-tier hierarchical CA architecture (Global Root, Regional, Local Issuers), scalability analysis explaining O(n^2) DKG limits, Certificate Transparency requirements with probation periods, regional CA geographic distribution with 16 regions, VRF-based regional selection, and cross-certification between adjacent regions |
| 1.3 | 2026-01-10 | Platform Team | Enhanced anti-Sybil protections: added network diversity constraints (ASN/subnet/country limits) with cross-reference to 00-CONSTANTS.md Section 17.1; organization-based pool constraints replacing per-TPM OwnerID with OrganizationID (max 5% per org, min 20 orgs); TPM tier requirements restricting CA pool eligibility to discrete hardware TPM (Tier 1) with manufacturer CA whitelist; CA pool staking requirements with compounding per-node stake and reputation discounts; updated verifyAntiCartelProperties to use OrganizationID |
| 1.4 | 2026-01-10 | Platform Team | Added Regional CA Failure Recovery (detection after 3 missed hourly rotations, geographic proximity failover, Re-DKG with surviving nodes); Tier 1 Annual Rotation Ceremony (30-day advance notice, trustee identity/availability verification, 67/100 emergency quorum, 48-hour ceremony window); DKG Bandwidth Requirements table (Tier 1: 100/10 Mbps, Tier 2: 25/5 Mbps, Tier 3: 10/2 Mbps); CA Pool Health Monitoring (5-min health check, 15-min failure detection, 1-hour recovery SLA, 30s heartbeat); Standby Pool Management (20% standby ratio, 10 minimum, 67% promotion approval, 30-day rotation, 7-day share refresh). Cross-references to 00-CONSTANTS.md Sections 11 and 20. |

---

## Summary

This CA architecture provides:

- **Fully decentralized** - No single point of failure
- **Scalable** - Supports billions of devices with three-tier hierarchy
- **Secure** - TPM + threshold signatures + 33% threshold
- **Standards-based** - RFC 9591, X.509, NIST curves
- **High availability** - 99.9999% uptime with multi-pool
- **Self-healing** - Automated health monitoring and rotation
- **Zero overhead** - <1us pool selection
- **Future-proof** - Hourly key rotation, extensible design
- **Cartel-resistant** - VRF selection with diversity requirements
- **Fork-resistant** - Threshold-signed STH with gossip protocol
- **Compromise-recoverable** - Cross-attestation and trust anchor updates
- **Catastrophe-recoverable** - Genesis trustee protocol with cold storage
- **Robust edge case handling** - Comprehensive failure recovery and validation procedures
- **Geographically distributed** - 16 regional CAs with cross-certification
- **CT compliant** - Mandatory certificate transparency with probation periods

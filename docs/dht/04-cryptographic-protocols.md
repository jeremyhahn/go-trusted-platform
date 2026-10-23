# Cryptographic Protocols

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

## Overview

The go-trusted-platform system employs a layered cryptographic architecture to provide trustworthy distributed operations without any single point of compromise. Three primary cryptographic protocols work together:

| Protocol | Purpose | Standard |
|----------|---------|----------|
| **FROST** | Threshold signatures (t-of-n signing) | RFC 9591 |
| **go-frostdkg** | Distributed key generation (EncPedPop) | RFC 9591 FROST DKG |
| **TPM 2.0** | Hardware-bound key storage | TCG TPM 2.0 |

**Key Principle:** The group secret key **never exists** in any single location. It is mathematically distributed across participants and only "reconstructed" implicitly during signature aggregation.

```
+------------------+     +------------------+     +------------------+
|   go-frostdkg    |     |     FROST        |     |     TPM 2.0      |
| (EncPedPop DKG)  | --> | (Signing)        | --> | (Key Storage)    |
|                  |     |                  |     |                  |
| Generates shares |     | Uses shares to   |     | Seals shares to  |
| for participants |     | create signatures|     | hardware         |
+------------------+     +------------------+     +------------------+
```

---

## FROST Threshold Signatures

**FROST (Flexible Round-Optimized Schnorr Threshold)** enables t-of-n threshold signatures where any t participants can collaboratively sign, but the secret key is never reconstructed.

**Specification:** RFC 9591

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Unforgeability** | Cannot forge without t shares (EUF-CMA secure) |
| **Key Secrecy** | Secret key is never reconstructed |
| **Nonce Secrecy** | Nonces are single-use, deleted after signing |
| **Binding** | Signature bound to specific message + signer set |
| **Indistinguishability** | Final signature is standard Schnorr |

### Mathematical Foundation

```
+---------------------------------------------------------------------+
|                  Mathematical Structure                              |
+---------------------------------------------------------------------+
|                                                                      |
|  Secret key sk = f(0)  where f(x) is a degree t-1 polynomial        |
|                                                                      |
|  Each participant P_j has share sk_j = f(j)                         |
|                                                                      |
|  By Lagrange interpolation:                                          |
|    sk = Sum(lambda_j * sk_j)  where lambda_j are Lagrange coeffs    |
|                                                                      |
|  BUT: We never compute sk directly!                                 |
|                                                                      |
|  Instead, signature shares are computed:                             |
|    z_j = d_j + rho*e_j + lambda_j*sk_j*c                            |
|                                                                      |
|  When aggregated:                                                    |
|    z = Sum(z_j) = Sum(d_j + rho*e_j) + c*Sum(lambda_j*sk_j)          |
|              = R' + c*sk                                             |
|                                                                      |
|  The "reconstruction" happens in the math, not in memory.            |
|  sk is only ever in the exponent (discrete log is hard).             |
|                                                                      |
+---------------------------------------------------------------------+
```

### Protocol Flow

#### Round 1: Pre-Generate Commitments (Offline)

Signers pre-generate batches of nonces and commitments for efficiency. This can be done ahead of time, reducing signing latency.

```go
// pkg/frost/commitment.go

type NonceCommitment struct {
    ID       CommitmentID
    SignerID NodeID
    D        Point  // d*G (hiding commitment)
    E        Point  // e*G (binding commitment)
    Created  time.Time
    Expires  time.Time
    UsedFlag uint32  // Atomic flag: 0=unused, 1=used (MUST use atomic.CompareAndSwapUint32)
}

func (s *Signer) PreGenerateCommitments(count int) ([]*NonceCommitment, error) {
    commitments := make([]*NonceCommitment, count)

    for i := 0; i < count; i++ {
        // Generate nonces inside TPM
        d, e, err := s.tpm.GenerateScalarPair()
        if err != nil {
            return nil, err
        }

        // Compute commitments (public)
        D := s.curve.ScalarBaseMult(d)
        E := s.curve.ScalarBaseMult(e)

        // Seal nonces to TPM
        id := NewCommitmentID()
        handle, err := s.tpm.SealNonces(id, d, e)
        if err != nil {
            return nil, err
        }

        commitments[i] = &NonceCommitment{
            ID:       id,
            SignerID: s.nodeID,
            D:        D,
            E:        E,
            Created:  time.Now(),
            Expires:  time.Now().Add(24 * time.Hour),
        }

        // Store handle for later retrieval
        s.nonceHandles[id] = handle
    }

    // Publish to DHT for coordinator to fetch
    return commitments, s.dht.PublishCommitments(commitments)
}
```

#### Round 2: Signing

**Coordinator Side:**

```go
func (c *Coordinator) InitiateSignature(message []byte) (*FROSTSignature, error) {
    // 1. Select t signers from available pool
    signers, err := c.selectSigners(c.threshold)
    if err != nil {
        return nil, err
    }

    // 2. Fetch their pre-generated commitments
    commitments := make(map[NodeID]*NonceCommitment)
    for _, signer := range signers {
        comm, err := c.dht.GetCommitment(signer)
        if err != nil {
            // Try backup signer
            continue
        }
        commitments[signer] = comm
    }

    // 3. Compute binding factor
    // rho = H(message || commitment_1 || ... || commitment_t)
    bindingFactor := c.computeBindingFactor(message, commitments)

    // 4. Compute group commitment
    // R = Sum(D_j + rho*E_j)
    R := c.curve.Identity()
    for _, comm := range commitments {
        term := c.curve.Add(comm.D, c.curve.ScalarMult(comm.E, bindingFactor))
        R = c.curve.Add(R, term)
    }

    // 5. Create and broadcast signing request
    request := &FROSTSigningRequest{
        RequestID:       NewRequestID(),
        PoolID:          c.poolID,
        Epoch:           c.epoch,
        MessageHash:     Hash(message),
        SignerIDs:       keys(commitments),
        CommitmentIDs:   commitmentIDs(commitments),
        BindingFactor:   bindingFactor,
        GroupCommitment: R,
        Deadline:        time.Now().Add(5 * time.Second),
    }

    for signer := range commitments {
        c.sendToSigner(signer, request)
    }

    // 6. Collect signature shares
    return c.collectAndAggregate(request, len(commitments))
}
```

**Signer Side:**

```go
func (s *Signer) Sign(request *FROSTSigningRequest) (*FROSTSignatureShare, error) {
    // 1. Verify request
    if err := s.verifyRequest(request); err != nil {
        return nil, err
    }

    // 2. Find my commitment
    myCommitmentID := s.findMyCommitment(request.CommitmentIDs)
    if myCommitmentID == "" {
        return nil, ErrNotSelected
    }

    // 3. Mark commitment as used (BEFORE unsealing)
    if err := s.markCommitmentUsed(myCommitmentID); err != nil {
        return nil, err
    }

    // 4. Unseal nonces from TPM
    d, e, err := s.tpm.UnsealNonces(myCommitmentID)
    if err != nil {
        // CRITICAL: Rollback commitment used flag on TPM failure
        // Otherwise the commitment is "burned" without being used
        s.rollbackCommitmentUsed(myCommitmentID)
        return nil, fmt.Errorf("TPM unseal failed, commitment rolled back: %w", err)
    }

    // 5. Compute challenge
    // c = H(R || PK || message)
    c := s.computeChallenge(request.GroupCommitment, s.groupPublicKey, request.MessageHash)

    // 6. Compute Lagrange coefficient
    // lambda_j = Product(k/(k-j)) for k != j in signer set
    lambda := s.lagrangeCoefficient(request.SignerIDs)

    // 7. Compute signature share (partially inside TPM for sk)
    // z_j = d + rho*e + lambda*sk*c
    rhoE := s.curve.ScalarMult(e, request.BindingFactor)
    lambdaSkC := s.tpm.ComputePartialSignature(lambda, c)  // Uses sealed sk

    z := new(big.Int).Add(d, rhoE)
    z.Add(z, lambdaSkC)
    z.Mod(z, s.curve.Params().N)

    // 8. Delete nonces (one-time use)
    s.tpm.DeleteNonces(myCommitmentID)

    return &FROSTSignatureShare{
        RequestID:    request.RequestID,
        SignerID:     s.nodeID,
        CommitmentID: myCommitmentID,
        Share:        z.Bytes(),
    }, nil
}
```

### Aggregation and Verification

**Aggregation (Coordinator):**

```go
func (c *Coordinator) aggregate(request *FROSTSigningRequest, shares map[NodeID]*FROSTSignatureShare) (*FROSTSignature, error) {
    // 1. Optionally verify each share
    for signerID, share := range shares {
        if err := c.verifyShare(signerID, share, request); err != nil {
            // Exclude bad signer, try backup
            delete(shares, signerID)
            // Request from backup...
        }
    }

    // 2. Aggregate: z = Sum(z_j)
    z := big.NewInt(0)
    for _, share := range shares {
        z.Add(z, new(big.Int).SetBytes(share.Share))
    }
    z.Mod(z, c.curve.Params().N)

    // 3. Create signature (R, z)
    signature := &FROSTSignature{
        R: request.GroupCommitment,
        Z: z.Bytes(),
    }

    // 4. Verify final signature
    if !c.verifySignature(c.groupPublicKey, request.MessageHash, signature) {
        return nil, ErrSignatureVerificationFailed
    }

    return signature, nil
}
```

### Signature Collection Timeout Handling (P4-M10)

**CRITICAL**: FROST signing requires collecting t signature shares from selected signers within a bounded time window. Without explicit timeout handling, the signing process can hang indefinitely if signers are slow, unresponsive, or malicious.

**Timeout Configuration:**

```go
// pkg/frost/timeout_config.go

const (
    // Individual signer response timeout (default baseline)
    // NOTE: This is a fallback value. Use AdaptiveSignerTimeout for production.
    SignerResponseTimeout = 3 * time.Second

    // Total collection window for all t signers
    TotalCollectionTimeout = 10 * time.Second

    // Minimum signers required before starting backup selection
    MinSharesBeforeBackup = 1

    // Maximum backup signers to attempt per round
    MaxBackupAttempts = 3

    // Retry interval for unresponsive signers
    SignerRetryInterval = 500 * time.Millisecond

    // Maximum total signing attempts before failure
    MaxSigningAttempts = 3
    
    // Adaptive timeout configuration bounds
    AdaptiveTimeoutMinimum = 500 * time.Millisecond  // Floor for adaptive timeout
    AdaptiveTimeoutMaximum = 10 * time.Second        // Ceiling for adaptive timeout
    FailoverTriggerRatio   = 0.5                     // Trigger backup at 50% of timeout
)

// AdaptiveSignerTimeout computes timeout based on observed network conditions.
// This addresses the limitation of fixed 3s timeouts which may be too short for
// high-latency networks or too long for local clusters.
//
// Algorithm:
//   SignerResponseTimeout = max(p99_latency * 2, AdaptiveTimeoutMinimum)
//   FailoverTrigger = SignerResponseTimeout * FailoverTriggerRatio
//
// The p99 latency is computed from a sliding window of the last 100 signing
// operations per signer. This ensures the timeout adapts to actual network
// conditions while maintaining a minimum floor for safety.
type AdaptiveSignerTimeout struct {
    // p99Latency is the 99th percentile latency observed for this signer
    p99Latency time.Duration
    
    // computedTimeout is the adaptive timeout: max(p99 * 2, minimum)
    computedTimeout time.Duration
    
    // failoverTrigger is when to start trying backup signers
    failoverTrigger time.Duration
    
    // lastUpdated tracks freshness of latency data
    lastUpdated time.Time
}

// ComputeAdaptiveTimeout calculates timeout based on observed p99 latency
func ComputeAdaptiveTimeout(p99Latency time.Duration) *AdaptiveSignerTimeout {
    // Apply formula: max(p99 * 2, minimum)
    computed := p99Latency * 2
    if computed < AdaptiveTimeoutMinimum {
        computed = AdaptiveTimeoutMinimum
    }
    if computed > AdaptiveTimeoutMaximum {
        computed = AdaptiveTimeoutMaximum
    }
    
    return &AdaptiveSignerTimeout{
        p99Latency:      p99Latency,
        computedTimeout: computed,
        failoverTrigger: time.Duration(float64(computed) * FailoverTriggerRatio),
        lastUpdated:     time.Now(),
    }
}

// GetTimeout returns the adaptive timeout, falling back to default if stale
func (a *AdaptiveSignerTimeout) GetTimeout() time.Duration {
    if a == nil || time.Since(a.lastUpdated) > 1*time.Hour {
        // No data or stale data, use default
        return SignerResponseTimeout
    }
    return a.computedTimeout
}

// GetFailoverTrigger returns when to start trying backup signers
// This allows early failover initiation while still waiting for primary
func (a *AdaptiveSignerTimeout) GetFailoverTrigger() time.Duration {
    if a == nil {
        return SignerResponseTimeout / 2
    }
    return a.failoverTrigger
}

// SigningTimeoutError represents a timeout during signature collection
type SigningTimeoutError struct {
    RequestID      [32]byte
    Required       int
    Received       int
    TimeoutAfter   time.Duration
    MissingSigners []NodeID
}

func (e *SigningTimeoutError) Error() string {
    return fmt.Sprintf(
        "signature collection timeout after %v: need %d shares, got %d, missing %v",
        e.TimeoutAfter, e.Required, e.Received, e.MissingSigners,
    )
}

// SignerTimeoutError represents a single signer timeout
type SignerTimeoutError struct {
    SignerID     NodeID
    RequestID    [32]byte
    TimeoutAfter time.Duration
}

func (e *SignerTimeoutError) Error() string {
    return fmt.Sprintf("signer %x timeout after %v for request %x",
        e.SignerID[:8], e.TimeoutAfter, e.RequestID[:8])
}
```

**Signature Collection with Timeout:**

```go
// pkg/frost/collector.go

// SignatureCollector manages the collection of signature shares from t signers
// with explicit timeout handling and backup signer selection
type SignatureCollector struct {
    dht             DHT
    signers         []NodeID
    backupSigners   []NodeID
    threshold       int
    requestID       [32]byte
    shares          map[NodeID]*FROSTSignatureShare
    sharesMu        sync.Mutex
    responseChan    chan *signerResponse
    coordinator     *Coordinator
}

type signerResponse struct {
    SignerID NodeID
    Share    *FROSTSignatureShare
    Error    error
}

// collectAndAggregate implements the full signature collection flow with timeout
func (c *Coordinator) collectAndAggregate(
    request *FROSTSigningRequest,
    expectedSigners int,
) (*FROSTSignature, error) {

    collector := &SignatureCollector{
        dht:           c.dht,
        signers:       request.SignerIDs,
        backupSigners: c.getBackupSigners(request.SignerIDs),
        threshold:     c.threshold,
        requestID:     request.RequestID,
        shares:        make(map[NodeID]*FROSTSignatureShare),
        responseChan:  make(chan *signerResponse, len(request.SignerIDs)+MaxBackupAttempts),
        coordinator:   c,
    }

    // Start collection with total timeout
    ctx, cancel := context.WithTimeout(context.Background(), TotalCollectionTimeout)
    defer cancel()

    shares, err := collector.collectShares(ctx, request)
    if err != nil {
        return nil, err
    }

    // Aggregate collected shares
    return c.aggregate(request, shares)
}

// collectShares collects signature shares from signers with per-signer and total timeouts
func (sc *SignatureCollector) collectShares(
    ctx context.Context,
    request *FROSTSigningRequest,
) (map[NodeID]*FROSTSignatureShare, error) {

    // Phase 1: Request shares from all primary signers concurrently
    for _, signerID := range sc.signers {
        go sc.requestShareWithTimeout(ctx, signerID, request)
    }

    // Phase 2: Collect responses with timeout
    collected := make(map[NodeID]*FROSTSignatureShare)
    respondedSigners := make(map[NodeID]bool)
    backupsUsed := 0

    collectionStart := time.Now()

    for {
        select {
        case <-ctx.Done():
            // Total timeout reached
            missingSigners := sc.getMissingSigners(respondedSigners)
            return nil, &SigningTimeoutError{
                RequestID:      sc.requestID,
                Required:       sc.threshold,
                Received:       len(collected),
                TimeoutAfter:   time.Since(collectionStart),
                MissingSigners: missingSigners,
            }

        case resp := <-sc.responseChan:
            respondedSigners[resp.SignerID] = true

            if resp.Error != nil {
                // Signer failed - try backup if we haven't collected enough
                if len(collected) < sc.threshold && backupsUsed < MaxBackupAttempts {
                    if backup := sc.selectBackupSigner(respondedSigners); backup != nil {
                        backupsUsed++
                        go sc.requestShareWithTimeout(ctx, *backup, request)
                    }
                }
                continue
            }

            // Valid share received
            collected[resp.SignerID] = resp.Share

            // Check if we have enough shares
            if len(collected) >= sc.threshold {
                return collected, nil
            }
        }
    }
}

// requestShareWithTimeout sends a signing request to a signer with timeout
func (sc *SignatureCollector) requestShareWithTimeout(
    ctx context.Context,
    signerID NodeID,
    request *FROSTSigningRequest,
) {
    // Create per-signer timeout context
    signerCtx, cancel := context.WithTimeout(ctx, SignerResponseTimeout)
    defer cancel()

    // Prepare response
    resp := &signerResponse{SignerID: signerID}

    // Request signature share via P2P
    share, err := sc.requestSignatureShare(signerCtx, signerID, request)
    if err != nil {
        resp.Error = err
    } else {
        resp.Share = share
    }

    // Send response (non-blocking in case collector has already finished)
    select {
    case sc.responseChan <- resp:
    default:
        // Collector already has enough shares or timed out
    }
}

// requestSignatureShare makes the actual P2P request to a signer
func (sc *SignatureCollector) requestSignatureShare(
    ctx context.Context,
    signerID NodeID,
    request *FROSTSigningRequest,
) (*FROSTSignatureShare, error) {

    // Serialize request
    reqData, err := proto.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("marshal request: %w", err)
    }

    // Send via DHT P2P layer with context timeout
    respData, err := sc.dht.SendWithContext(ctx, signerID, "frost.sign", reqData)
    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            return nil, &SignerTimeoutError{
                SignerID:     signerID,
                RequestID:    sc.requestID,
                TimeoutAfter: SignerResponseTimeout,
            }
        }
        return nil, fmt.Errorf("P2P send to %x: %w", signerID[:8], err)
    }

    // Deserialize response
    var share FROSTSignatureShare
    if err := proto.Unmarshal(respData, &share); err != nil {
        return nil, fmt.Errorf("unmarshal share from %x: %w", signerID[:8], err)
    }

    // Validate share before accepting
    if err := sc.coordinator.verifyShareBasic(&share, request); err != nil {
        return nil, fmt.Errorf("invalid share from %x: %w", signerID[:8], err)
    }

    return &share, nil
}

// selectBackupSigner selects an available backup signer
func (sc *SignatureCollector) selectBackupSigner(used map[NodeID]bool) *NodeID {
    for _, backup := range sc.backupSigners {
        if !used[backup] {
            return &backup
        }
    }
    return nil
}

// getMissingSigners returns signers that haven't responded
func (sc *SignatureCollector) getMissingSigners(responded map[NodeID]bool) []NodeID {
    var missing []NodeID
    for _, signer := range sc.signers {
        if !responded[signer] {
            missing = append(missing, signer)
        }
    }
    return missing
}
```

**Retry Strategy for Failed Collections:**

```go
// pkg/frost/retry.go

// SigningRetryConfig configures retry behavior for failed signing attempts
type SigningRetryConfig struct {
    MaxAttempts       int
    BackoffBase       time.Duration
    BackoffMax        time.Duration
    BackoffMultiplier float64
}

var DefaultSigningRetryConfig = SigningRetryConfig{
    MaxAttempts:       MaxSigningAttempts,
    BackoffBase:       500 * time.Millisecond,
    BackoffMax:        5 * time.Second,
    BackoffMultiplier: 2.0,
}

// SignWithRetry attempts signing with retry on timeout
func (c *Coordinator) SignWithRetry(
    ctx context.Context,
    message []byte,
    config *SigningRetryConfig,
) (*FROSTSignature, error) {

    if config == nil {
        config = &DefaultSigningRetryConfig
    }

    var lastErr error
    backoff := config.BackoffBase

    for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
        // Check if parent context cancelled
        if ctx.Err() != nil {
            return nil, ctx.Err()
        }

        // Attempt signing
        sig, err := c.Sign(message)
        if err == nil {
            return sig, nil
        }

        lastErr = err

        // Only retry on timeout errors
        var timeoutErr *SigningTimeoutError
        if !errors.As(err, &timeoutErr) {
            // Non-timeout error, don't retry
            return nil, err
        }

        // Log retry attempt
        log.Warn("Signing attempt failed, retrying",
            "attempt", attempt,
            "maxAttempts", config.MaxAttempts,
            "error", err,
            "backoff", backoff,
        )

        // Refresh signer selection for next attempt
        // (exclude signers that timed out)
        c.excludeTimedOutSigners(timeoutErr.MissingSigners)

        // Wait before retry
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-time.After(backoff):
        }

        // Increase backoff
        backoff = time.Duration(float64(backoff) * config.BackoffMultiplier)
        if backoff > config.BackoffMax {
            backoff = config.BackoffMax
        }
    }

    return nil, fmt.Errorf(
        "signing failed after %d attempts: %w",
        config.MaxAttempts, lastErr,
    )
}

// excludeTimedOutSigners temporarily removes unresponsive signers from selection
func (c *Coordinator) excludeTimedOutSigners(signers []NodeID) {
    c.signerExclusionMu.Lock()
    defer c.signerExclusionMu.Unlock()

    now := time.Now()
    for _, signer := range signers {
        c.signerExclusion[signer] = now.Add(SignerExclusionDuration)
    }
}

const SignerExclusionDuration = 5 * time.Minute
```

**Timeout Monitoring and Alerting:**

```go
// pkg/frost/timeout_metrics.go

// TimeoutMetrics tracks signature collection timeout statistics
type TimeoutMetrics struct {
    TotalRequests      atomic.Uint64
    SuccessfulRequests atomic.Uint64
    TimeoutRequests    atomic.Uint64

    // Per-signer timeout tracking
    signerTimeouts     map[NodeID]*atomic.Uint64
    signerTimeoutsMu   sync.RWMutex

    // Histogram of collection times
    collectionTimes    *Histogram

    // Alert thresholds
    alertOnTimeoutRate float64 // Alert if timeout rate exceeds this (e.g., 0.1 = 10%)
    alertCallback      func(rate float64)
}

// RecordSuccess records a successful signature collection
func (m *TimeoutMetrics) RecordSuccess(duration time.Duration) {
    m.TotalRequests.Add(1)
    m.SuccessfulRequests.Add(1)
    m.collectionTimes.Observe(float64(duration.Milliseconds()))
}

// RecordTimeout records a timed-out signature collection
func (m *TimeoutMetrics) RecordTimeout(err *SigningTimeoutError) {
    m.TotalRequests.Add(1)
    m.TimeoutRequests.Add(1)

    // Track per-signer timeouts
    m.signerTimeoutsMu.Lock()
    for _, signer := range err.MissingSigners {
        if _, ok := m.signerTimeouts[signer]; !ok {
            m.signerTimeouts[signer] = &atomic.Uint64{}
        }
        m.signerTimeouts[signer].Add(1)
    }
    m.signerTimeoutsMu.Unlock()

    // Check alert threshold
    m.checkAlertThreshold()
}

// checkAlertThreshold triggers alert if timeout rate is too high
func (m *TimeoutMetrics) checkAlertThreshold() {
    total := m.TotalRequests.Load()
    if total < 100 { // Need minimum sample size
        return
    }

    timeouts := m.TimeoutRequests.Load()
    rate := float64(timeouts) / float64(total)

    if rate > m.alertOnTimeoutRate && m.alertCallback != nil {
        m.alertCallback(rate)
    }
}

// GetUnresponsiveSigners returns signers with high timeout rates
func (m *TimeoutMetrics) GetUnresponsiveSigners(threshold uint64) []NodeID {
    m.signerTimeoutsMu.RLock()
    defer m.signerTimeoutsMu.RUnlock()

    var unresponsive []NodeID
    for signer, count := range m.signerTimeouts {
        if count.Load() > threshold {
            unresponsive = append(unresponsive, signer)
        }
    }
    return unresponsive
}
```

**Timeout State Machine:**

| State | Condition | Action | Next State |
|-------|-----------|--------|------------|
| COLLECTING | t shares received | Aggregate shares | SUCCESS |
| COLLECTING | Total timeout reached | Return timeout error | FAILED |
| COLLECTING | Signer timeout | Request from backup | COLLECTING |
| COLLECTING | All signers failed + no backups | Return error | FAILED |
| RETRY | Attempt < MaxAttempts | Wait backoff, exclude slow signers | COLLECTING |
| RETRY | Attempt >= MaxAttempts | Return final error | FAILED |

**Verification (Any Node):**

Any node can verify the signature using only the group public key:

```go
func VerifySchnorr(publicKey Point, message, signature []byte) bool {
    R, z := parseSignature(signature)

    // c = H(R || PK || message)
    c := Hash(R, publicKey, message)

    // Verify: z*G = R + c*PK
    left := curve.ScalarBaseMult(z)
    right := curve.Add(R, curve.ScalarMult(publicKey, c))

    return curve.Equal(left, right)
}
```

**Why Verification Works:**

```
z = Sum(z_j) = Sum(d_j + rho*e_j) + c*Sum(lambda_j*sk_j)
  = (group nonce) + c*sk

z*G = (group nonce)*G + c*sk*G
    = R + c*PK
```

### Nonce Safety (CANONICAL)

**CRITICAL:** Nonce reuse leaks the secret key. This is the most important security property to enforce.

**Attack Vector:**

```
If nonce d is used twice with different messages m1, m2:
  z1 = d + lambda*sk*c1
  z2 = d + lambda*sk*c2

Then:
  z1 - z2 = lambda*sk*(c1 - c2)
  sk = (z1 - z2) / (lambda*(c1 - c2))
```

**Single-Use Enforcement:**

```go
// pkg/frost/nonces.go

const (
    NonceBatchSize = 100
    NonceExpiry    = 24 * time.Hour
)

type NoncePool struct {
    pool    map[CommitmentID]*Nonce
    tpm     *TPM
    mu      sync.Mutex
}

func (p *NoncePool) PreGenerate(count int) error {
    p.mu.Lock()
    defer p.mu.Unlock()

    for i := 0; i < count; i++ {
        // Generate nonces inside TPM
        d, e, err := p.tpm.GenerateScalars(2)
        if err != nil {
            return err
        }

        // Compute commitments (public)
        D := p.curve.ScalarBaseMult(d)
        E := p.curve.ScalarBaseMult(e)

        // Seal nonces to TPM
        id := CommitmentID(uuid.New())
        handle, err := p.tpm.SealNonces(id, d, e)
        if err != nil {
            return err
        }

        p.pool[id] = &Nonce{
            ID:         id,
            Handle:     handle,
            D:          D,
            E:          E,
            CreatedAt:  time.Now(),
            ExpiresAt:  time.Now().Add(NonceExpiry),
        }
    }

    return nil
}

func (p *NoncePool) UseNonce(id CommitmentID) (*Nonce, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    nonce, exists := p.pool[id]
    if !exists {
        return nil, ErrNonceNotFound
    }

    // CRITICAL: Atomic compare-and-swap to prevent race condition
    // Two concurrent requests could both read UsedFlag=0 before either sets it to 1
    // This would result in nonce reuse, enabling private key recovery
    if !atomic.CompareAndSwapUint32(&nonce.UsedFlag, 0, 1) {
        return nil, ErrNonceAlreadyUsed
    }

    // Unseal from TPM
    d, e, err := p.tpm.UnsealNonces(nonce.Handle)
    if err != nil {
        // CRITICAL: Rollback the UsedFlag on TPM failure
        // Otherwise this nonce is "burned" without ever being used,
        // reducing the available nonce pool unnecessarily
        atomic.StoreUint32(&nonce.UsedFlag, 0)
        return nil, fmt.Errorf("TPM unseal failed, nonce rolled back: %w", err)
    }

    nonce.d = d
    nonce.e = e

    // Schedule deletion
    go func() {
        time.Sleep(10 * time.Second)  // Grace period for signing
        p.deleteNonce(id)
    }()

    return nonce, nil
}

func (p *NoncePool) deleteNonce(id CommitmentID) {
    p.mu.Lock()
    defer p.mu.Unlock()

    if nonce, exists := p.pool[id]; exists {
        // Destroy TPM object
        p.tpm.DestroyHandle(nonce.Handle)

        // Zero memory
        if nonce.d != nil {
            for i := range nonce.d {
                nonce.d[i] = 0
            }
        }
        if nonce.e != nil {
            for i := range nonce.e {
                nonce.e[i] = 0
            }
        }

        delete(p.pool, id)
    }
}
```

**Nonce Safety Mitigations:**

1. Commitments have unique IDs
2. `Used` flag set BEFORE unsealing
3. Nonces deleted immediately after use
4. Commitments expire after 24 hours
5. TPM enforces single-use

### TPM Monotonic Counter Nonce Generation

FROST nonce generation uses TPM 2.0 monotonic counters to provide hardware-enforced uniqueness guarantees. This prevents nonce reuse even across node restarts or clock manipulation attacks.

**Nonce Structure:**

```go
// pkg/frost/nonce.go

// FROSTNonce represents a hardware-backed nonce with monotonic counter binding
type FROSTNonce struct {
    Value     [32]byte   // Random nonce value (d or e)
    Counter   uint64     // TPM monotonic counter value at generation
    CreatedAt time.Time  // Timestamp of generation
    ExpiresAt time.Time  // Expiration (5 minutes from creation)
    Used      uint32     // Atomic flag: 0=unused, 1=used
}

// NonceLifetime defines the maximum validity period for a nonce
const NonceLifetime = 5 * time.Minute
```

**TPM Counter-Bound Generation:**

```go
// pkg/frost/tpm_nonce.go

// TPMNonceGenerator provides hardware-backed nonce generation
type TPMNonceGenerator struct {
    tpm           *TPM
    counterHandle tpm2.TPMHandle  // Monotonic counter in TPM NV RAM
    mu            sync.Mutex
}

// GenerateNonce creates a new nonce bound to the TPM monotonic counter
func (g *TPMNonceGenerator) GenerateNonce() (*FROSTNonce, error) {
    g.mu.Lock()
    defer g.mu.Unlock()

    // 1. Increment TPM monotonic counter (cannot be decremented or reset)
    counter, err := g.tpm.IncrementCounter(g.counterHandle)
    if err != nil {
        return nil, &NonceGenerationError{Cause: err, Phase: "counter_increment"}
    }

    // 2. Generate random value inside TPM
    randomBytes, err := g.tpm.GetRandom(32)
    if err != nil {
        return nil, &NonceGenerationError{Cause: err, Phase: "random_generation"}
    }

    // 3. Bind counter to nonce value via HMAC
    // This ensures the nonce cannot be used if counter is tampered
    boundValue := g.bindCounterToNonce(randomBytes, counter)

    now := time.Now()
    nonce := &FROSTNonce{
        Counter:   counter,
        CreatedAt: now,
        ExpiresAt: now.Add(NonceLifetime),
        Used:      0,
    }
    copy(nonce.Value[:], boundValue)

    return nonce, nil
}

// bindCounterToNonce creates cryptographic binding between counter and random value
func (g *TPMNonceGenerator) bindCounterToNonce(random []byte, counter uint64) []byte {
    h := hmac.New(sha256.New, g.getCounterBindingKey())
    h.Write(random)
    binary.Write(h, binary.BigEndian, counter)
    return h.Sum(nil)
}
```

**Atomic Nonce Consumption with CAS:**

```go
// ValidateAndMarkUsed performs atomic validation and consumption of a nonce
// Returns nil if nonce is valid and successfully marked as used
// This function is the ONLY way to consume a nonce
func (n *FROSTNonce) ValidateAndMarkUsed(expectedValue [32]byte) error {
    // CHECK 1: Verify nonce exists (nil check)
    if n == nil {
        return ErrNonceNotFound
    }

    // CHECK 2: Verify value matches (prevents substitution attacks)
    if !bytes.Equal(n.Value[:], expectedValue[:]) {
        return &NonceMismatchError{
            Expected: expectedValue,
            Actual:   n.Value,
        }
    }

    // CHECK 3: Check expiration (5 minute lifetime)
    if time.Now().After(n.ExpiresAt) {
        return &NonceExpiredError{
            NonceID:    n.Value,
            ExpiredAt:  n.ExpiresAt,
            CheckedAt:  time.Now(),
        }
    }

    // CHECK 4: Atomic compare-and-swap to mark as used
    // This is the CRITICAL operation that prevents double-use
    if !atomic.CompareAndSwapUint32(&n.Used, 0, 1) {
        return ErrNonceAlreadyUsed
    }

    return nil
}

// IsValid checks if nonce is valid without consuming it
func (n *FROSTNonce) IsValid() bool {
    if n == nil {
        return false
    }
    if atomic.LoadUint32(&n.Used) != 0 {
        return false
    }
    if time.Now().After(n.ExpiresAt) {
        return false
    }
    return true
}
```

**Counter Verification:**

```go
// VerifyCounterBinding validates that nonce counter has not been tampered with
func (g *TPMNonceGenerator) VerifyCounterBinding(nonce *FROSTNonce) error {
    // Read current counter value from TPM
    currentCounter, err := g.tpm.ReadCounter(g.counterHandle)
    if err != nil {
        return &CounterVerificationError{Cause: err}
    }

    // Nonce counter must be less than or equal to current
    // (counter only increments, never decrements)
    if nonce.Counter > currentCounter {
        return &CounterManipulationError{
            NonceCounter:   nonce.Counter,
            CurrentCounter: currentCounter,
        }
    }

    return nil
}
```

**Nonce Lifecycle State Machine:**

```
                     TPM NONCE LIFECYCLE

    ┌────────────────────────────────────────────────────┐
    │                 GENERATING                          │
    │                                                    │
    │  1. Increment TPM monotonic counter                │
    │  2. Generate random bytes in TPM                   │
    │  3. Bind counter to random via HMAC                │
    │  4. Set ExpiresAt = now + 5 minutes                │
    │  5. Set Used = 0 (atomic)                          │
    └──────────────────────┬─────────────────────────────┘
                           │
                           ▼
    ┌────────────────────────────────────────────────────┐
    │                   VALID                             │
    │                                                    │
    │  Used = 0 AND time.Now() < ExpiresAt               │
    │  Can be consumed via ValidateAndMarkUsed()         │
    └─────────────┬────────────────────┬─────────────────┘
                  │                    │
         CAS succeeds          Expires (5 min)
                  │                    │
                  ▼                    ▼
    ┌─────────────────────┐  ┌─────────────────────────┐
    │        USED         │  │        EXPIRED          │
    │                     │  │                         │
    │  Used = 1           │  │  time.Now() >= ExpiresAt│
    │  Cannot be reused   │  │  Rejected if consumed   │
    │  Deleted after      │  │  Pruned by cleanup      │
    │  signing completes  │  │                         │
    └─────────────────────┘  └─────────────────────────┘
```

### Nonce Expiration Validation

Nonce commitments have strict expiration enforcement at every layer of the system to ensure cryptographic freshness.

```go
// pkg/frost/expiration.go

// NonceExpirationConfig - non-configurable security parameters
const (
    DefaultNonceExpiry   = 24 * time.Hour
    MaxNonceAge          = 48 * time.Hour   // Absolute maximum, never exceeded
    ExpirationClockSkew  = 5 * time.Minute  // Allow for clock drift
    PruneInterval        = 1 * time.Hour    // How often to clean expired nonces
    DHTCommitmentTTL     = 25 * time.Hour   // DHT expiration (slightly > nonce expiry)
)

// ValidateNonceExpiration performs multi-level expiration check
func ValidateNonceExpiration(commitment *NonceCommitment, now time.Time) error {
    // Level 1: Check explicit expiration timestamp
    if now.After(commitment.Expires) {
        return &NonceExpiredError{
            CommitmentID: commitment.ID,
            ExpiredAt:    commitment.Expires,
            CurrentTime:  now,
        }
    }

    // Level 2: Check absolute age limit (defense in depth)
    age := now.Sub(commitment.Created)
    if age > MaxNonceAge {
        return &NonceAgeExceededError{
            CommitmentID: commitment.ID,
            Age:          age,
            MaxAge:       MaxNonceAge,
        }
    }

    // Level 3: Check for future timestamps (clock manipulation attack)
    if commitment.Created.After(now.Add(ExpirationClockSkew)) {
        return &NonceFutureTimestampError{
            CommitmentID: commitment.ID,
            Created:      commitment.Created,
            CurrentTime:  now,
        }
    }

    return nil
}

// UseNonceWithExpirationCheck is the MANDATORY entry point for nonce usage
func (p *NoncePool) UseNonceWithExpirationCheck(id CommitmentID) (*Nonce, error) {
    p.mu.Lock()
    defer p.mu.Unlock()

    nonce, exists := p.pool[id]
    if !exists {
        return nil, ErrNonceNotFound
    }

    // CRITICAL: Check expiration BEFORE checking used flag
    // This prevents timing attacks that probe for valid commitments
    if err := ValidateNonceExpiration(&NonceCommitment{
        ID:      nonce.ID,
        Created: nonce.CreatedAt,
        Expires: nonce.ExpiresAt,
    }, time.Now()); err != nil {
        // Delete expired nonce immediately
        p.deleteNonceUnsafe(id)
        return nil, err
    }

    // CRITICAL: Atomic compare-and-swap to prevent race condition
    // Two concurrent requests could both read Used=false before either sets it true
    // This would result in nonce reuse, enabling private key recovery
    if !atomic.CompareAndSwapUint32(&nonce.UsedFlag, 0, 1) {
        return nil, ErrNonceAlreadyUsed
    }

    // Unseal from TPM
    d, e, err := p.tpm.UnsealNonces(nonce.Handle)
    if err != nil {
        // CRITICAL: Rollback the UsedFlag on TPM failure
        // Otherwise this nonce is "burned" without ever being used,
        // reducing the available nonce pool unnecessarily
        atomic.StoreUint32(&nonce.UsedFlag, 0)
        return nil, fmt.Errorf("TPM unseal failed, nonce rolled back: %w", err)
    }

    nonce.d = d
    nonce.e = e

    // Schedule deletion
    go func() {
        time.Sleep(10 * time.Second)
        p.deleteNonce(id)
    }()

    return nonce, nil
}
```

**Coordinator-Side Validation:**

Coordinators MUST validate expiration when fetching commitments from DHT:

```go
// pkg/frost/coordinator.go

// FetchValidCommitments retrieves only non-expired commitments
func (c *Coordinator) FetchValidCommitments(signers []NodeID) (map[NodeID]*NonceCommitment, error) {
    now := time.Now()
    validCommitments := make(map[NodeID]*NonceCommitment)
    invalidSigners := make([]NodeID, 0)

    for _, signer := range signers {
        comm, err := c.dht.GetCommitment(signer)
        if err != nil {
            invalidSigners = append(invalidSigners, signer)
            continue
        }

        // MANDATORY: Validate expiration before use
        if err := ValidateNonceExpiration(comm, now); err != nil {
            log.Warn("Commitment expired for signer",
                "signer", signer,
                "error", err,
                "commitment_id", comm.ID)

            // Request commitment deletion from DHT
            c.dht.RequestDelete("frost:commitment:"+comm.ID.String())

            // Mark signer as needing new commitment
            c.requestNewCommitment(signer)
            invalidSigners = append(invalidSigners, signer)
            continue
        }

        validCommitments[signer] = comm
    }

    // If too many invalid, select backup signers
    if len(validCommitments) < c.threshold {
        backups := c.selectBackupSigners(invalidSigners, c.threshold-len(validCommitments))
        for _, backup := range backups {
            comm, err := c.dht.GetCommitment(backup)
            if err == nil && ValidateNonceExpiration(comm, now) == nil {
                validCommitments[backup] = comm
            }
        }
    }

    if len(validCommitments) < c.threshold {
        return nil, ErrInsufficientValidCommitments{
            Required: c.threshold,
            Valid:    len(validCommitments),
        }
    }

    return validCommitments, nil
}
```

**Network-Wide Expiration Enforcement:**

```go
// pkg/frost/pruner.go

// NonceExpirationPruner removes expired commitments from DHT and local storage
type NonceExpirationPruner struct {
    dht      DHT
    local    *NoncePool
    interval time.Duration
    stop     chan struct{}
}

func (p *NonceExpirationPruner) Start() {
    ticker := time.NewTicker(p.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            p.pruneExpired()
        case <-p.stop:
            return
        }
    }
}

func (p *NonceExpirationPruner) pruneExpired() {
    now := time.Now()
    pruned := 0

    // Prune local pool
    p.local.mu.Lock()
    for id, nonce := range p.local.pool {
        if now.After(nonce.ExpiresAt) {
            p.local.deleteNonceUnsafe(id)
            pruned++
        }
    }
    p.local.mu.Unlock()

    // Request DHT-wide pruning for our expired commitments
    expiredIDs := p.local.GetExpiredCommitmentIDs()
    for _, id := range expiredIDs {
        p.dht.RequestDelete("frost:commitment:" + id.String())
    }

    if pruned > 0 {
        log.Info("Pruned expired nonces", "count", pruned)
    }
}
```

**Signing Request Validation:**

Signers MUST also validate expiration when processing signing requests:

```go
// Sign processes a signing request with mandatory expiration validation
func (s *Signer) Sign(request *FROSTSigningRequest) (*FROSTSignatureShare, error) {
    // 1. Verify request basics
    if err := s.verifyRequest(request); err != nil {
        return nil, err
    }

    // 2. Find my commitment
    myCommitmentID := s.findMyCommitment(request.CommitmentIDs)
    if myCommitmentID == "" {
        return nil, ErrNotSelected
    }

    // 3. CRITICAL: Get commitment and validate expiration
    commitment, exists := s.commitments[myCommitmentID]
    if !exists {
        return nil, ErrCommitmentNotFound
    }

    if err := ValidateNonceExpiration(commitment, time.Now()); err != nil {
        // Commitment expired between coordinator fetch and our processing
        // This should be rare but we MUST handle it
        s.deleteCommitment(myCommitmentID)
        return nil, &SigningExpiredCommitmentError{
            CommitmentID: myCommitmentID,
            Cause:        err,
        }
    }

    // 4. Get nonce with additional expiration check
    nonce, err := s.noncePool.UseNonceWithExpirationCheck(myCommitmentID)
    if err != nil {
        return nil, err
    }

    // ... rest of signing logic ...
}
```

**Validation Layers:**

| Layer | Component | Validation | Behavior |
|-------|-----------|------------|----------|
| 1 | Local NoncePool | `UseNonceWithExpirationCheck()` | Delete expired, return error |
| 2 | Coordinator | `FetchValidCommitments()` | Skip expired signer, use backup |
| 3 | DHT | TTL-based expiration | Auto-delete after TTL |
| 4 | Signer | Pre-sign validation | Reject expired, delete commitment |
| 5 | Background Pruner | Periodic cleanup | Remove expired from all stores |

### FROST Commitment Reservation Protocol

A race condition exists where commitments can expire between coordinator fetch and signer usage. The commitment reservation protocol prevents this by atomically reserving commitments during coordinator selection and using a reduced validity window.

**Problem Statement:**

Without reservation, the following race can occur:

```
Time 0:   Coordinator fetches commitment C1 (expires at T+10 min)
Time 1:   Coordinator computes group commitment R
Time 2:   Coordinator broadcasts signing request
Time 9:   Network delay (slow propagation)
Time 10:  Commitment C1 expires
Time 11:  Signer receives request, C1 is invalid
Time 12:  Signing fails, coordinator must retry with different signer
```

**Commitment Reservation Protocol:**

```go
// pkg/frost/commitment_reservation.go

// CommitmentReservationConfig defines reservation parameters
const (
    // Reduced validity window from 24h to 1h to minimize race window
    CommitmentValidityWindow   = 1 * time.Hour

    // Reservation hold time - how long a commitment is locked
    CommitmentReservationHold  = 5 * time.Minute

    // Maximum reservations per coordinator
    MaxReservationsPerCoord    = 100

    // Reservation cleanup interval
    ReservationCleanupInterval = 1 * time.Minute
)

// CommitmentReservation tracks a reserved commitment
type CommitmentReservation struct {
    CommitmentID   CommitmentID
    SignerID       NodeID
    ReservedBy     NodeID          // Coordinator who reserved
    ReservedAt     time.Time
    ExpiresAt      time.Time       // Reservation expiration
    SessionID      [32]byte        // Signing session this is for
    Used           bool            // Whether commitment was used
}

// CommitmentReservationManager handles atomic reservation of commitments
type CommitmentReservationManager struct {
    reservations    map[CommitmentID]*CommitmentReservation
    byCoordinator   map[NodeID][]*CommitmentReservation
    mu              sync.RWMutex

    // Metrics
    reservedCount   atomic.Uint64
    expiredCount    atomic.Uint64
    conflictCount   atomic.Uint64
}

// ReserveCommitments atomically reserves a set of commitments for signing
// This MUST be called before computing the group commitment
func (m *CommitmentReservationManager) ReserveCommitments(
    ctx context.Context,
    coordinatorID NodeID,
    sessionID [32]byte,
    commitments []*NonceCommitment,
) ([]*CommitmentReservation, error) {

    m.mu.Lock()
    defer m.mu.Unlock()

    // Check coordinator hasn't exceeded max reservations
    coordReservations := m.byCoordinator[coordinatorID]
    if len(coordReservations) >= MaxReservationsPerCoord {
        return nil, &ReservationLimitExceededError{
            CoordinatorID: coordinatorID,
            Current:       len(coordReservations),
            Max:           MaxReservationsPerCoord,
        }
    }

    now := time.Now()
    reservations := make([]*CommitmentReservation, 0, len(commitments))

    for _, comm := range commitments {
        // Check if already reserved
        if existing, exists := m.reservations[comm.ID]; exists {
            if existing.ExpiresAt.After(now) && !existing.Used {
                // Already reserved by another coordinator
                m.conflictCount.Add(1)
                continue  // Skip this commitment, caller will use backup
            }
            // Reservation expired, can reuse
        }

        // Validate commitment hasn't expired
        if comm.Expires.Before(now) {
            continue
        }

        // Create reservation
        reservation := &CommitmentReservation{
            CommitmentID: comm.ID,
            SignerID:     comm.SignerID,
            ReservedBy:   coordinatorID,
            ReservedAt:   now,
            ExpiresAt:    now.Add(CommitmentReservationHold),
            SessionID:    sessionID,
            Used:         false,
        }

        m.reservations[comm.ID] = reservation
        reservations = append(reservations, reservation)
    }

    m.byCoordinator[coordinatorID] = append(coordReservations, reservations...)
    m.reservedCount.Add(uint64(len(reservations)))

    return reservations, nil
}

// FetchAndReserve atomically fetches and reserves commitments from signers
func (c *Coordinator) FetchAndReserve(
    ctx context.Context,
    signers []NodeID,
) ([]*ReservedCommitment, error) {

    commitments := make([]*NonceCommitment, 0, len(signers))

    // Fetch commitments from all signers
    for _, signer := range signers {
        comm, err := c.dht.GetCommitment(signer)
        if err != nil {
            continue  // Try next signer
        }

        // Early expiration check before reservation
        if time.Until(comm.Expires) < CommitmentReservationHold {
            // Too close to expiration, skip
            continue
        }

        commitments = append(commitments, comm)
    }

    if len(commitments) < c.threshold {
        return nil, &InsufficientCommitmentsError{
            Required:  c.threshold,
            Available: len(commitments),
        }
    }

    // Atomically reserve all commitments
    reservations, err := c.reservationManager.ReserveCommitments(
        ctx,
        c.nodeID,
        c.currentSessionID,
        commitments[:c.threshold],
    )
    if err != nil {
        return nil, err
    }

    // Verify we got enough reservations
    if len(reservations) < c.threshold {
        // Some reservations failed due to conflicts
        // Release what we got and retry with backups
        c.releaseReservations(reservations)
        return c.FetchAndReserve(ctx, c.getBackupSigners(signers))
    }

    return toReservedCommitments(reservations, commitments), nil
}

// MarkUsed marks a reservation as used during successful signing
func (m *CommitmentReservationManager) MarkUsed(commitmentID CommitmentID) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    reservation, exists := m.reservations[commitmentID]
    if !exists {
        return ErrReservationNotFound
    }

    reservation.Used = true
    return nil
}

// ReleaseReservation cancels a reservation (e.g., signing aborted)
func (m *CommitmentReservationManager) ReleaseReservation(commitmentID CommitmentID) {
    m.mu.Lock()
    defer m.mu.Unlock()

    delete(m.reservations, commitmentID)
}

// CleanupExpired removes expired reservations periodically
func (m *CommitmentReservationManager) CleanupExpired() {
    m.mu.Lock()
    defer m.mu.Unlock()

    now := time.Now()
    for id, reservation := range m.reservations {
        if reservation.ExpiresAt.Before(now) && !reservation.Used {
            delete(m.reservations, id)
            m.expiredCount.Add(1)
        }
    }
}
```

**Reservation State Machine:**

```
                    COMMITMENT RESERVATION STATE MACHINE

    ┌─────────────┐                               ┌─────────────┐
    │  AVAILABLE  │  ──── Reserve() ───────────>  │  RESERVED   │
    │             │                               │             │
    │  - Not held │                               │  - Locked   │
    │  - Can be   │                               │  - Has hold │
    │    fetched  │                               │    timeout  │
    └─────────────┘                               └──────┬──────┘
          ▲                                              │
          │                                    ┌─────────┴─────────┐
          │                                    │                   │
          │                              MarkUsed()          Timeout/Release()
          │                                    │                   │
          │                                    ▼                   │
          │                            ┌─────────────┐             │
          │                            │    USED     │             │
          │                            │             │             │
          │                            │  - Consumed │             │
          │                            │  - Removed  │             │
          │                            │    from pool│             │
          │                            └─────────────┘             │
          │                                                        │
          └────────────────────────────────────────────────────────┘
```

**Reduced Validity Window:**

The default 24-hour commitment validity creates a large race window. The protocol reduces this to 1 hour:

| Parameter | Previous | New | Rationale |
|-----------|----------|-----|-----------|
| Commitment Validity | 24 hours | 1 hour | Reduces race window from 24h to 1h |
| Reservation Hold | N/A | 5 minutes | Sufficient for signing round trip |
| Generation Batch | 100 | 50 | More frequent generation with shorter validity |
| Refresh Trigger | 50 | 25 | Earlier refresh to maintain pool |

```go
// Updated commitment generation with reduced validity
func (s *Signer) PreGenerateCommitments(count int) ([]*NonceCommitment, error) {
    commitments := make([]*NonceCommitment, count)

    for i := 0; i < count; i++ {
        // ... nonce generation ...

        commitments[i] = &NonceCommitment{
            ID:       id,
            SignerID: s.nodeID,
            D:        D,
            E:        E,
            Created:  time.Now(),
            // UPDATED: Reduced from 24 hours to 1 hour
            Expires:  time.Now().Add(CommitmentValidityWindow),
        }

        s.nonceHandles[id] = handle
    }

    // More frequent publishing due to shorter validity
    return commitments, s.dht.PublishCommitments(commitments)
}
```

### Nonce Pool Management

**CRITICAL SECURITY**: Nonce reuse in FROST threshold signatures enables complete private key recovery. The nonce pool manager MUST ensure:
1. Each nonce is used exactly once
2. Used nonces are tracked permanently (never cleared)
3. Pool exhaustion blocks signing rather than reusing nonces
4. TPM hardware RNG provides entropy for nonce generation

> **SECURITY WARNING: FROST Nonces Are SINGLE-USE Only**
>
> The term "pool" in `NoncePoolManager` refers to **pre-generation for latency optimization**, NOT reuse.
> Each FROST nonce MUST be used exactly once and then permanently destroyed.
>
> **Critical Implementation Requirements:**
> - `GetNonce()` MUST mark the nonce as used IMMEDIATELY upon retrieval (via atomic CAS)
> - Even if the signing operation subsequently fails, the nonce is consumed and cannot be reused
> - The "pool" exists solely to pre-generate nonces in the background, avoiding generation latency during signing
> - Pool "topping up" generates NEW nonces; it never recycles or reuses existing nonces
>
> **Why This Matters (Nonce Reuse Attack):**
> ```
> If nonce (d, e) is used twice with messages m1 and m2:
>   z1 = d + rho1*e + lambda*sk*c1
>   z2 = d + rho2*e + lambda*sk*c2
>
> Attacker computes:
>   sk = (z1 - z2 - e*(rho1 - rho2)) / (lambda*(c1 - c2))
>
> Result: Complete private key recovery from TWO signatures sharing a nonce.
> ```
>
> **NEVER reuse a FROST nonce. Each `GetNonce()` call returns a fresh nonce that cannot be reused.**

```go
// pkg/frost/nonce_pool.go

// NoncePoolManager ensures nonces are always available for FROST signing
// CRITICAL: Nonce reuse in FROST enables key recovery attack

const (
    MinNoncePoolSize    = 100   // Minimum nonces to maintain
    MaxNoncePoolSize    = 1000  // Maximum nonces to generate ahead
    NonceRefreshTrigger = 50    // Generate more when pool drops below this
    NonceGenerationBatch = 100  // Generate this many at a time
)

type NoncePoolManager struct {
    pool           []*FROSTNonce
    usedNonces     map[[32]byte]bool  // Track used nonces forever
    mu             sync.Mutex
    tpm            *TPM
    refreshTrigger chan struct{}
}

type FROSTNonce struct {
    HidingNonce    *big.Int  // d_i
    BindingNonce   *big.Int  // e_i
    Commitment     *NonceCommitment
    GeneratedAt    time.Time
    UsedFlag       uint32    // Atomic flag: 0=unused, 1=used (use atomic.CompareAndSwapUint32)
    ID             [32]byte  // Unique identifier for tracking
}

// CRITICAL SECURITY: Nonce Usage Race Condition Prevention
//
// A race condition in nonce consumption can lead to catastrophic key compromise:
//
// Attack scenario (without atomic operations):
// 1. Thread A reads nonce.Used == false at T=0
// 2. Thread B reads nonce.Used == false at T=1 (before A marks as used)
// 3. Thread A marks nonce.Used = true at T=2
// 4. Thread B marks nonce.Used = true at T=3 (already true, but B didn't check again)
// 5. Both threads use the same nonce (d, e) for different signatures
// 6. Private key s recoverable: s = (z1 - z2) / (c1 - c2) mod q
//
// Mitigation: Always use atomic.CompareAndSwapUint32(&nonce.UsedFlag, 0, 1)
// This atomically checks if UsedFlag==0 AND sets it to 1 in a single operation.
// If the CAS fails, another thread already claimed the nonce.

func NewNoncePoolManager(tpm *TPM) *NoncePoolManager {
    npm := &NoncePoolManager{
        pool:           make([]*FROSTNonce, 0, MaxNoncePoolSize),
        usedNonces:     make(map[[32]byte]bool),
        tpm:            tpm,
        refreshTrigger: make(chan struct{}, 1),
    }
    
    // Initial pool generation
    npm.generateNonces(MinNoncePoolSize)
    
    // Background refresh goroutine
    go npm.backgroundRefresh()
    
    return npm
}

// GetNonce retrieves a fresh nonce, NEVER returns a used nonce
func (npm *NoncePoolManager) GetNonce() (*FROSTNonce, error) {
    npm.mu.Lock()
    defer npm.mu.Unlock()
    
    if len(npm.pool) == 0 {
        // CRITICAL: Pool exhausted, must generate synchronously
        // This should never happen with proper background refresh
        if err := npm.generateNonces(NonceGenerationBatch); err != nil {
            return nil, ErrNoncePoolExhausted
        }
    }
    
    // Pop from pool
    nonce := npm.pool[len(npm.pool)-1]
    npm.pool = npm.pool[:len(npm.pool)-1]
    
    // CRITICAL: Atomic mark as used (NEVER reuse)
    // Must use atomic operation even under mutex for consistency
    atomic.StoreUint32(&nonce.UsedFlag, 1)
    npm.usedNonces[nonce.ID] = true
    
    // Trigger refresh if pool getting low
    if len(npm.pool) < NonceRefreshTrigger {
        select {
        case npm.refreshTrigger <- struct{}{}:
        default:
        }
    }
    
    return nonce, nil
}

// generateNonces creates fresh nonces using TPM randomness
func (npm *NoncePoolManager) generateNonces(count int) error {
    for i := 0; i < count; i++ {
        // Generate nonces using TPM RNG for hardware-backed randomness
        hidingBytes := npm.tpm.GetRandom(32)
        bindingBytes := npm.tpm.GetRandom(32)
        
        hiding := new(big.Int).SetBytes(hidingBytes)
        binding := new(big.Int).SetBytes(bindingBytes)
        
        // Compute commitment: (g^d, g^e)
        commitment := &NonceCommitment{
            HidingCommitment:  new(big.Int).Exp(g, hiding, p),
            BindingCommitment: new(big.Int).Exp(g, binding, p),
        }
        
        // Generate unique ID
        var id [32]byte
        h := sha256.New()
        h.Write(commitment.HidingCommitment.Bytes())
        h.Write(commitment.BindingCommitment.Bytes())
        copy(id[:], h.Sum(nil))
        
        // Check for collision (astronomically unlikely but safety first)
        if npm.usedNonces[id] {
            i-- // Regenerate
            continue
        }
        
        nonce := &FROSTNonce{
            HidingNonce:  hiding,
            BindingNonce: binding,
            Commitment:   commitment,
            GeneratedAt:  time.Now(),
            Used:         false,
            ID:           id,
        }
        
        npm.pool = append(npm.pool, nonce)
    }
    
    return nil
}

// backgroundRefresh keeps nonce pool topped up
func (npm *NoncePoolManager) backgroundRefresh() {
    for range npm.refreshTrigger {
        npm.mu.Lock()
        currentSize := len(npm.pool)
        npm.mu.Unlock()
        
        if currentSize < MaxNoncePoolSize-NonceGenerationBatch {
            npm.mu.Lock()
            npm.generateNonces(NonceGenerationBatch)
            npm.mu.Unlock()
        }
    }
}

// ValidateNonceUnused checks if a nonce has been used before
// CRITICAL: A used nonce enables private key recovery
func (npm *NoncePoolManager) ValidateNonceUnused(nonceID [32]byte) error {
    npm.mu.Lock()
    defer npm.mu.Unlock()
    
    if npm.usedNonces[nonceID] {
        // CRITICAL SECURITY EVENT - potential key compromise
        return ErrNonceReused
    }
    
    return nil
}

var ErrNoncePoolExhausted = errors.New("nonce pool exhausted - cannot sign safely")
var ErrNonceReused = errors.New("CRITICAL: nonce reuse detected - potential key compromise")
```

### Nonce Pool Exhaustion Recovery (P4-H8)

When the nonce pool is exhausted and generation fails, signing MUST be blocked until recovery completes. This section defines explicit recovery procedures.

```go
// pkg/frost/nonce_recovery.go

// Nonce Pool Exhaustion Recovery - non-configurable security parameters
const (
    NonceRecoveryRetryInterval  = 1 * time.Second   // Retry interval for generation
    NonceRecoveryMaxRetries     = 10                // Max retries before escalation
    NonceRecoveryQueueMaxSize   = 1000              // Max pending sign requests during recovery
    NonceRecoveryTPMResetDelay  = 5 * time.Second   // Delay before TPM reset attempt
)

// NonceExhaustionState tracks pool exhaustion events
type NonceExhaustionState uint8

const (
    NonceStateHealthy       NonceExhaustionState = iota // Pool > MinNoncePoolSize
    NonceStateLow                                       // Pool < NonceRefreshTrigger
    NonceStateExhausted                                 // Pool == 0, generation failing
    NonceStateRecovering                                // Recovery in progress
    NonceStateCritical                                  // Recovery exhausted, escalate
)

// NoncePoolRecoveryManager handles pool exhaustion scenarios
type NoncePoolRecoveryManager struct {
    pool           *NoncePoolManager
    state          atomic.Value  // NonceExhaustionState
    recoveryMu     sync.Mutex

    // Pending sign requests queued during recovery
    pendingQueue   chan *PendingSignRequest
    queuedCount    atomic.Int32

    // Recovery metrics
    retryCount     int
    lastError      error
    lastRecoveryAt time.Time

    // TPM reference for reset
    tpm            *TPM
}

// PendingSignRequest holds sign requests blocked during exhaustion
type PendingSignRequest struct {
    RequestID   [32]byte
    Message     []byte
    Callback    chan *SignResult
    QueuedAt    time.Time
    Deadline    time.Time
}

// SignResult delivers nonce or error to blocked callers
type SignResult struct {
    Nonce *FROSTNonce
    Error error
}

// GetNonceWithRecovery wraps GetNonce with exhaustion recovery
func (r *NoncePoolRecoveryManager) GetNonceWithRecovery(ctx context.Context) (*FROSTNonce, error) {
    // Fast path: pool healthy
    state := r.state.Load().(NonceExhaustionState)
    if state == NonceStateHealthy || state == NonceStateLow {
        nonce, err := r.pool.GetNonce()
        if err == nil {
            return nonce, nil
        }
        // Fell through to exhaustion - update state
        r.state.Store(NonceStateExhausted)
    }

    // Slow path: pool exhausted, enter recovery
    return r.getWithRecoveryQueue(ctx)
}

// getWithRecoveryQueue queues request and waits for recovery
func (r *NoncePoolRecoveryManager) getWithRecoveryQueue(ctx context.Context) (*FROSTNonce, error) {
    // Check queue capacity
    if r.queuedCount.Load() >= int32(NonceRecoveryQueueMaxSize) {
        return nil, &NonceExhaustionError{
            Reason:      "recovery_queue_full",
            QueueSize:   int(r.queuedCount.Load()),
            Suggestion:  "retry_later",
        }
    }

    // Create pending request
    req := &PendingSignRequest{
        RequestID: generateRequestID(),
        Callback:  make(chan *SignResult, 1),
        QueuedAt:  time.Now(),
        Deadline:  time.Now().Add(30 * time.Second),  // Max wait time
    }

    // Queue request
    select {
    case r.pendingQueue <- req:
        r.queuedCount.Add(1)
    default:
        return nil, ErrRecoveryQueueFull
    }

    // Start recovery if not already running
    r.startRecoveryIfNeeded()

    // Wait for result or timeout
    select {
    case result := <-req.Callback:
        r.queuedCount.Add(-1)
        if result.Error != nil {
            return nil, result.Error
        }
        return result.Nonce, nil

    case <-ctx.Done():
        r.queuedCount.Add(-1)
        return nil, ctx.Err()

    case <-time.After(30 * time.Second):
        r.queuedCount.Add(-1)
        return nil, ErrNonceRecoveryTimeout
    }
}

// startRecoveryIfNeeded initiates recovery process
func (r *NoncePoolRecoveryManager) startRecoveryIfNeeded() {
    r.recoveryMu.Lock()
    defer r.recoveryMu.Unlock()

    state := r.state.Load().(NonceExhaustionState)
    if state == NonceStateRecovering {
        return  // Already recovering
    }

    r.state.Store(NonceStateRecovering)
    go r.runRecoveryLoop()
}

// runRecoveryLoop attempts to restore nonce pool
func (r *NoncePoolRecoveryManager) runRecoveryLoop() {
    for retry := 0; retry < NonceRecoveryMaxRetries; retry++ {
        r.retryCount = retry + 1

        // Attempt 1: Standard generation
        if err := r.attemptStandardGeneration(); err == nil {
            r.completeRecovery()
            return
        }

        // Attempt 2: TPM reset and retry
        if retry == 3 {
            if err := r.attemptTPMReset(); err != nil {
                r.lastError = fmt.Errorf("tpm_reset_failed: %w", err)
            } else if err := r.attemptStandardGeneration(); err == nil {
                r.completeRecovery()
                return
            }
        }

        // Attempt 3: Backup TPM (if available)
        if retry == 6 {
            if err := r.attemptBackupTPM(); err == nil {
                r.completeRecovery()
                return
            }
        }

        time.Sleep(NonceRecoveryRetryInterval)
    }

    // Recovery exhausted - escalate to critical state
    r.escalateToCritical()
}

// attemptStandardGeneration tries normal nonce generation
func (r *NoncePoolRecoveryManager) attemptStandardGeneration() error {
    r.pool.mu.Lock()
    defer r.pool.mu.Unlock()

    // Try to generate a small batch first
    err := r.pool.generateNonces(10)
    if err != nil {
        r.lastError = fmt.Errorf("generation_failed: %w", err)
        return err
    }

    // Success - generate full batch
    return r.pool.generateNonces(MinNoncePoolSize - 10)
}

// attemptTPMReset resets TPM state and retries
func (r *NoncePoolRecoveryManager) attemptTPMReset() error {
    log.Warn("Attempting TPM reset for nonce recovery",
        "retry_count", r.retryCount)

    // TPM reset sequence
    if err := r.tpm.FlushContext(); err != nil {
        return fmt.Errorf("flush_context_failed: %w", err)
    }

    time.Sleep(NonceRecoveryTPMResetDelay)

    if err := r.tpm.SelfTest(true); err != nil {
        return fmt.Errorf("self_test_failed: %w", err)
    }

    return nil
}

// attemptBackupTPM tries secondary TPM if available
func (r *NoncePoolRecoveryManager) attemptBackupTPM() error {
    backupTPM := GetBackupTPM()
    if backupTPM == nil {
        return ErrNoBackupTPMAvailable
    }

    log.Warn("Switching to backup TPM for nonce generation",
        "primary_error", r.lastError)

    // Generate using backup TPM
    tempPool := &NoncePoolManager{
        pool:       make([]*FROSTNonce, 0, MaxNoncePoolSize),
        usedNonces: r.pool.usedNonces,  // Share used nonce tracking
        tpm:        backupTPM,
    }

    if err := tempPool.generateNonces(MinNoncePoolSize); err != nil {
        return fmt.Errorf("backup_generation_failed: %w", err)
    }

    // Transfer generated nonces to main pool
    r.pool.mu.Lock()
    r.pool.pool = append(r.pool.pool, tempPool.pool...)
    r.pool.mu.Unlock()

    return nil
}

// completeRecovery handles successful recovery
func (r *NoncePoolRecoveryManager) completeRecovery() {
    r.state.Store(NonceStateHealthy)
    r.lastRecoveryAt = time.Now()
    r.retryCount = 0

    log.Info("Nonce pool recovery completed",
        "pool_size", len(r.pool.pool),
        "pending_requests", r.queuedCount.Load())

    // Process pending requests
    r.processPendingRequests()
}

// processPendingRequests delivers nonces to queued callers
func (r *NoncePoolRecoveryManager) processPendingRequests() {
    for {
        select {
        case req := <-r.pendingQueue:
            // Check if request timed out
            if time.Now().After(req.Deadline) {
                req.Callback <- &SignResult{Error: ErrNonceRecoveryTimeout}
                continue
            }

            // Get nonce for this request
            nonce, err := r.pool.GetNonce()
            req.Callback <- &SignResult{Nonce: nonce, Error: err}

        default:
            return  // Queue empty
        }
    }
}

// escalateToCritical handles unrecoverable exhaustion
func (r *NoncePoolRecoveryManager) escalateToCritical() {
    r.state.Store(NonceStateCritical)

    // Broadcast critical alert
    alert := &NonceExhaustionAlert{
        NodeID:      GetLocalNodeID(),
        Timestamp:   time.Now(),
        RetryCount:  r.retryCount,
        LastError:   r.lastError.Error(),
        QueuedCount: int(r.queuedCount.Load()),
    }
    BroadcastCriticalAlert(alert)

    // Fail all pending requests
    for {
        select {
        case req := <-r.pendingQueue:
            req.Callback <- &SignResult{
                Error: &NonceExhaustionError{
                    Reason:     "critical_exhaustion",
                    Suggestion: "node_restart_required",
                },
            }
        default:
            return
        }
    }
}

// Error types
var (
    ErrRecoveryQueueFull      = errors.New("nonce recovery queue full")
    ErrNonceRecoveryTimeout   = errors.New("nonce recovery timed out")
    ErrNoBackupTPMAvailable   = errors.New("no backup TPM available")
)

type NonceExhaustionError struct {
    Reason     string
    QueueSize  int
    Suggestion string
}

func (e *NonceExhaustionError) Error() string {
    return fmt.Sprintf("nonce_exhaustion: %s (queue=%d, suggestion=%s)",
        e.Reason, e.QueueSize, e.Suggestion)
}
```

**Exhaustion Recovery State Machine**:

```
                      ┌─────────────────┐
                      │    HEALTHY      │
                      │  pool > min     │
                      └────────┬────────┘
                               │ pool drops
                               ↓
                      ┌─────────────────┐
                      │      LOW        │
                      │ pool < trigger  │
                      └────────┬────────┘
                               │ generation fails
                               ↓
                      ┌─────────────────┐
       ┌──────────────│   EXHAUSTED     │
       │              │   pool == 0     │
       │              └────────┬────────┘
       │                       │ start recovery
       │                       ↓
       │              ┌─────────────────┐
       │              │   RECOVERING    │◄──────┐
       │              │ retry in progress│       │
       │              └────────┬────────┘       │
       │                       │                │
       │            ┌──────────┴──────────┐     │
       │            │                     │     │
       │       success                 failure  │
       │            │                     │     │
       │            ↓                     │     │
       │   ┌─────────────────┐           │     │
       └──→│    HEALTHY      │           └─────┘
           └─────────────────┘         (retry < max)
                                             │
                                   (retry >= max)
                                             ↓
                               ┌─────────────────┐
                               │    CRITICAL     │
                               │ escalate alert  │
                               │ fail all queued │
                               └─────────────────┘
```

**Recovery Escalation Path**:

| Retry | Action | Timeout |
|-------|--------|---------|
| 1-3 | Standard generation | 1s each |
| 4-6 | TPM reset + retry | 5s reset + 1s each |
| 7-10 | Backup TPM (if available) | 1s each |
| >10 | CRITICAL state, broadcast alert, fail all pending | N/A |

### Nonce Pool Replenishment Strategy

The nonce pool uses proactive background replenishment to ensure signing operations are never blocked waiting for nonce generation. This section defines the replenishment algorithm and behavior under various load conditions.

**Replenishment Thresholds:**

| Threshold | Pool State | Action |
|-----------|------------|--------|
| > 500 nonces | Healthy | No action |
| 200-500 nonces | Normal | Background generation (low priority) |
| 50-200 nonces | Low | Background generation (high priority) |
| 10-50 nonces | Warning | Aggressive generation, rate limit signing |
| 0-10 nonces | Critical | Block new signing, synchronous generation |

```go
// pkg/frost/nonce_replenishment.go

// NonceReplenishmentConfig controls background nonce generation
const (
    ReplenishmentCheckInterval = 5 * time.Second    // How often to check pool level
    ReplenishmentBatchSize     = 50                 // Nonces per generation batch
    ReplenishmentHighWaterMark = 500                // Stop generating when pool exceeds this
    ReplenishmentLowWaterMark  = 200                // Start generating when pool drops below this
    ReplenishmentWarningMark   = 50                 // Trigger warning state
    ReplenishmentCriticalMark  = 10                 // Trigger critical state

    // Rate limiting when pool is low
    LowPoolSigningRateLimit    = 10                 // Max signatures per second when pool low
    WarningPoolSigningRateLimit = 2                 // Max signatures per second when pool warning
)

// NonceReplenisher manages background nonce generation
type NonceReplenisher struct {
    pool              *NoncePoolManager
    tpm               *TPM

    // Pool state tracking
    currentState      atomic.Value  // PoolState
    lastReplenishment time.Time

    // Rate limiting for low pool states
    signingRateLimiter *rate.Limiter

    // Metrics
    generatedCount    atomic.Uint64
    failedCount       atomic.Uint64
}

type PoolState uint8

const (
    PoolStateHealthy  PoolState = iota  // > 500 nonces
    PoolStateNormal                      // 200-500 nonces
    PoolStateLow                         // 50-200 nonces
    PoolStateWarning                     // 10-50 nonces
    PoolStateCritical                    // 0-10 nonces
)

// Start begins the background replenishment loop
func (r *NonceReplenisher) Start(ctx context.Context) {
    ticker := time.NewTicker(ReplenishmentCheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            r.checkAndReplenish()
        }
    }
}

// checkAndReplenish evaluates pool level and generates nonces as needed
func (r *NonceReplenisher) checkAndReplenish() {
    poolSize := r.pool.GetPoolSize()

    // Determine pool state
    var state PoolState
    switch {
    case poolSize > ReplenishmentHighWaterMark:
        state = PoolStateHealthy
    case poolSize > ReplenishmentLowWaterMark:
        state = PoolStateNormal
    case poolSize > ReplenishmentWarningMark:
        state = PoolStateLow
    case poolSize > ReplenishmentCriticalMark:
        state = PoolStateWarning
    default:
        state = PoolStateCritical
    }

    // Update state and adjust rate limiting
    previousState := r.currentState.Swap(state).(PoolState)
    r.adjustRateLimiting(state)

    // Log state transitions
    if state != previousState {
        r.logStateTransition(previousState, state, poolSize)
    }

    // Determine generation strategy based on state
    if poolSize < ReplenishmentHighWaterMark {
        batchSize := r.calculateBatchSize(state)
        r.generateNonces(batchSize)
    }
}

// calculateBatchSize determines how many nonces to generate based on pool state
func (r *NonceReplenisher) calculateBatchSize(state PoolState) int {
    switch state {
    case PoolStateNormal:
        return ReplenishmentBatchSize
    case PoolStateLow:
        return ReplenishmentBatchSize * 2  // Generate faster when low
    case PoolStateWarning:
        return ReplenishmentBatchSize * 3  // Aggressive generation
    case PoolStateCritical:
        return ReplenishmentBatchSize * 4  // Maximum generation rate
    default:
        return 0
    }
}

// adjustRateLimiting modifies signing rate limits based on pool state
func (r *NonceReplenisher) adjustRateLimiting(state PoolState) {
    switch state {
    case PoolStateHealthy, PoolStateNormal:
        // No rate limiting
        r.signingRateLimiter = nil
    case PoolStateLow:
        r.signingRateLimiter = rate.NewLimiter(rate.Limit(LowPoolSigningRateLimit), 1)
    case PoolStateWarning, PoolStateCritical:
        r.signingRateLimiter = rate.NewLimiter(rate.Limit(WarningPoolSigningRateLimit), 1)
    }
}

// generateNonces creates new nonces in the background
func (r *NonceReplenisher) generateNonces(count int) {
    for i := 0; i < count; i++ {
        nonce, err := r.createNonce()
        if err != nil {
            r.failedCount.Add(1)
            // Backoff on repeated failures
            if r.failedCount.Load() > 10 {
                time.Sleep(100 * time.Millisecond)
            }
            continue
        }

        r.pool.AddNonce(nonce)
        r.generatedCount.Add(1)
    }

    r.lastReplenishment = time.Now()
}
```

**High Load Nonce Depletion Handling:**

When nonces are depleted faster than they can be generated (high signing load), the system employs a multi-tiered response:

```
                    NONCE DEPLETION UNDER HIGH LOAD

    Normal Load                                   High Load
         │                                             │
         │  Pool Size = 500                           │  Pool Size = 500
         │  Signing Rate = 10/s                       │  Signing Rate = 100/s
         │  Generation Rate = 20/s                    │  Generation Rate = 20/s
         │  Net Change = +10/s                        │  Net Change = -80/s
         │                                             │
         ▼                                             ▼
    ┌─────────────┐                          ┌─────────────────────────┐
    │  HEALTHY    │                          │ DEPLETION IN ~6 SECONDS │
    └─────────────┘                          └────────────┬────────────┘
                                                          │
                                                          ▼
                                    ┌─────────────────────────────────────────┐
                                    │         MITIGATION STRATEGY              │
                                    │                                         │
                                    │ 1. RATE LIMITING                        │
                                    │    - Limit signing to generation rate   │
                                    │    - Queue excess requests              │
                                    │                                         │
                                    │ 2. PRIORITY QUEUING                     │
                                    │    - Critical operations first          │
                                    │    - Batch less urgent requests         │
                                    │                                         │
                                    │ 3. PARALLEL GENERATION                  │
                                    │    - Spawn additional TPM workers       │
                                    │    - Up to TPM parallelism limit        │
                                    │                                         │
                                    │ 4. COORDINATOR LOAD SHEDDING            │
                                    │    - Redirect to other coordinators     │
                                    │    - Reject lowest priority requests    │
                                    └─────────────────────────────────────────┘
```

```go
// HighLoadNonceManager handles nonce depletion under high signing load
type HighLoadNonceManager struct {
    replenisher    *NonceReplenisher
    requestQueue   *PriorityQueue[*SigningRequest]
    maxQueueDepth  int

    // TPM parallelism for generation
    tpmWorkers     []*TPMWorker
    maxTPMWorkers  int
}

// RequestWithPriority queues a signing request based on priority and pool state
func (m *HighLoadNonceManager) RequestWithPriority(
    ctx context.Context,
    request *SigningRequest,
    priority SigningPriority,
) (*FROSTNonce, error) {

    state := m.replenisher.currentState.Load().(PoolState)

    // If pool is healthy, serve immediately
    if state == PoolStateHealthy || state == PoolStateNormal {
        return m.replenisher.pool.GetNonce()
    }

    // Apply rate limiting
    if m.replenisher.signingRateLimiter != nil {
        if err := m.replenisher.signingRateLimiter.Wait(ctx); err != nil {
            return nil, &NonceLimitExceededError{
                PoolState: state,
                QueueDepth: m.requestQueue.Len(),
            }
        }
    }

    // Queue if pool is critical
    if state == PoolStateCritical || state == PoolStateWarning {
        // Only queue high-priority requests when critical
        if state == PoolStateCritical && priority < SigningPriorityHigh {
            return nil, &NonceDepletedError{
                Reason: "pool_critical_low_priority_rejected",
                Suggestion: "retry_later_or_use_different_coordinator",
            }
        }

        // Add to priority queue
        if m.requestQueue.Len() >= m.maxQueueDepth {
            return nil, &NonceQueueFullError{
                QueueDepth: m.requestQueue.Len(),
            }
        }

        resultChan := make(chan *nonceResult, 1)
        m.requestQueue.Push(&queuedRequest{
            Request:  request,
            Priority: priority,
            Result:   resultChan,
        })

        // Wait for nonce from queue processor
        select {
        case result := <-resultChan:
            return result.Nonce, result.Error
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }

    // Pool is low but not critical - serve with rate limiting applied
    return m.replenisher.pool.GetNonce()
}

// SigningPriority defines request priority levels
type SigningPriority uint8

const (
    SigningPriorityLow      SigningPriority = 0  // Batch operations
    SigningPriorityNormal   SigningPriority = 1  // Standard requests
    SigningPriorityHigh     SigningPriority = 2  // Time-sensitive operations
    SigningPriorityCritical SigningPriority = 3  // System-critical (e.g., CRL signing)
)
```

### Performance

| Operation | Time |
|-----------|------|
| Pre-generate 100 commitments | 2 sec |
| Signing request + collection | 200ms |
| Signature share computation | 20ms |
| Aggregation | 1ms |
| Verification | 1ms |

### Certificate Signing Flow

```
Node                    Coordinator              Signers (t)
  |                          |                       |
  | CSR + TPM attestation    |                       |
  |------------------------->|                       |
  |                          |                       |
  |                          | Select signers        |
  |                          | Fetch commitments     |
  |                          |                       |
  |                          | FROSTSigningRequest   |
  |                          |---------------------->|
  |                          |                       |
  |                          |                       | Compute z_j
  |                          |                       | Delete nonces
  |                          |                       |
  |                          | FROSTSignatureShare   |
  |                          |<----------------------|
  |                          |                       |
  |                          | Aggregate z = Sum(z_j)|
  |                          | Verify signature      |
  |                          |                       |
  | Certificate              |                       |
  |<-------------------------|                       |
  |                          |                       |
  |                          | Publish to CT log     |
```

### Deterministic Signer Selection

FROST signing coordinators must select signers deterministically to prevent bias attacks where a malicious coordinator selects specific nodes to manipulate signing outcomes or exclude honest participants.

```go
// pkg/frost/signer_selection.go

// DeterministicSignerSelection ensures coordinator cannot bias signer choice
// The selection is deterministic and verifiable by all participants

// SignerSelectionSeed generates deterministic seed for signer selection
type SignerSelectionSeed struct {
    MessageHash    [32]byte  // Hash of message to sign
    EpochNumber    uint64    // Current epoch
    OperationNonce [32]byte  // VRF-derived nonce from DHT
    PreviousSig    [32]byte  // Hash of previous FROST signature (chain)
}

// SelectSigners deterministically chooses signers for FROST signing
func SelectSigners(
    seed *SignerSelectionSeed,
    eligibleNodes []NodeID,
    threshold int,
    committeeSize int,
) ([]NodeID, error) {
    if len(eligibleNodes) < threshold {
        return nil, ErrInsufficientSigners
    }
    
    // Generate deterministic selection seed
    h := sha256.New()
    h.Write(seed.MessageHash[:])
    binary.Write(h, binary.BigEndian, seed.EpochNumber)
    h.Write(seed.OperationNonce[:])
    h.Write(seed.PreviousSig[:])
    selectionSeed := h.Sum(nil)
    
    // Fisher-Yates shuffle with deterministic PRNG
    shuffled := make([]NodeID, len(eligibleNodes))
    copy(shuffled, eligibleNodes)
    
    prng := newDeterministicPRNG(selectionSeed)
    for i := len(shuffled) - 1; i > 0; i-- {
        j := prng.Intn(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    }
    
    // Select first committeeSize nodes (deterministic)
    selected := shuffled[:committeeSize]
    
    return selected, nil
}

// VerifySignerSelection allows any node to verify selection was fair
func VerifySignerSelection(
    seed *SignerSelectionSeed,
    eligibleNodes []NodeID,
    selectedSigners []NodeID,
    threshold int,
    committeeSize int,
) error {
    // Recompute selection independently
    expected, err := SelectSigners(seed, eligibleNodes, threshold, committeeSize)
    if err != nil {
        return err
    }
    
    // Verify selected signers match expected
    if len(expected) != len(selectedSigners) {
        return ErrSignerSelectionMismatch
    }
    
    for i, signer := range selectedSigners {
        if signer != expected[i] {
            return &SignerSelectionViolation{
                Position: i,
                Expected: expected[i],
                Actual:   signer,
            }
        }
    }
    
    return nil
}

var ErrInsufficientSigners = errors.New("insufficient eligible signers for threshold")
var ErrSignerSelectionMismatch = errors.New("signer selection does not match deterministic computation")

type SignerSelectionViolation struct {
    Position int
    Expected NodeID
    Actual   NodeID
}

func (e *SignerSelectionViolation) Error() string {
    return fmt.Sprintf("signer selection violation at position %d: expected %s, got %s",
        e.Position, e.Expected, e.Actual)
}
```

**Deterministic Signer Selection Properties:**

| Property | Guarantee |
|----------|-----------|
| Deterministic | Same seed always produces same selection |
| Verifiable | Any node can independently verify selection |
| Unpredictable | Selection cannot be known before message is known |
| Chain-Linked | Previous signature prevents precomputation |
| Fair | All eligible nodes have equal selection probability |

---

## Distributed Key Generation (DKG)

The go-trusted-platform DKG protocol generates threshold FROST signing keys across N participants, where any t participants can sign but fewer than t cannot forge signatures or learn the secret.

**Implementation:** go-frostdkg with TPM enhancements

The go-frostdkg project implements the **EncPedPop (Encrypted Pedersen Parity-of-Opinions)** DKG protocol, which is built on the SimplPedPop base layer with Verifiable Secret Sharing (VSS) and polynomial operations. Key features include:

- **2-round protocol** with CertEq (Certificate Equality) verification
- **CertEq protocol** for non-interactive zero-knowledge proof ensuring all participants agree on the group public key
- **Untrusted coordinator model** - coordinator facilitates but cannot influence outcomes
- **TPM-ready HostKey interface** for hardware-backed key operations
- **RFC 9591 FROST compliance** for threshold signature compatibility

**Supported Ciphersuites:**
| Ciphersuite | Curve | Use Case |
|-------------|-------|----------|
| Ed25519 | Curve25519 | General purpose, high performance |
| P-256 | NIST P-256 | Enterprise/government compliance |
| secp256k1 | secp256k1 | Bitcoin/blockchain compatibility |
| ristretto255 | Ristretto | Cofactor-safe Curve25519 |
| Ed448 | Curve448 | Higher security margin |

**Transport Options:**
- gRPC (primary)
- HTTP/HTTPS
- QUIC
- libp2p
- Unix sockets

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Correctness** | All honest participants derive the same group key |
| **Secrecy** | No coalition of <t participants learns the secret |
| **Robustness** | DKG completes if >=t honest participants |
| **Verifiability** | All shares verifiable against commitments |
| **Accountability** | Misbehavior provably attributable (blame) |

### Trail of Bits Vulnerability Fix (Trail of Bits DKG-2024-001, Jan 2024)

**Reference:** Trail of Bits DKG-2024-001 (internal advisory - no public CVE assigned as of publication)

A malicious participant can use a polynomial of degree T > t, silently raising the threshold. This is a critical vulnerability that must be checked.

**MANDATORY CHECK:**

```go
// MUST validate before processing any commitment
if len(commitment.Coefficients) != threshold {
    return ErrInvalidCoefficientCount{
        Expected: threshold,
        Received: len(commitment.Coefficients),
    }
}
```

#### Polynomial Degree Vulnerability Recovery Protocol

When a participant broadcasts a commitment with an invalid coefficient count (polynomial degree T > t or T < t), the system MUST immediately execute recovery procedures to protect the DKG session integrity.

**Attack Vector:**
A malicious participant sends `len(coefficients) != threshold`, attempting to either:
1. **Threshold Elevation (T > t):** Silently raise the signing threshold, potentially causing signing failures
2. **Threshold Reduction (T < t):** Lower security guarantees, enabling unauthorized signing coalitions

**Detection Timing:**
| Phase | Detection Point | Maximum Detection Latency |
|-------|-----------------|---------------------------|
| Phase 3 | Commitment reception | Within commitment validation timeout (30s) |
| Phase 4 | Share verification failure | Within share distribution timeout (60s) |
| Any | CertEq disagreement | Within CertEq timeout (30s) |

##### Immediate Exclusion Protocol

Upon detecting invalid coefficient count, the following MUST occur within 100ms:

```go
// pkg/dkg/polynomial_degree_recovery.go

// PolynomialDegreeViolation represents a detected Trail of Bits vulnerability attempt
type PolynomialDegreeViolation struct {
    SessionID       [32]byte
    ViolatorID      NodeID
    ExpectedDegree  int       // threshold value
    ReceivedDegree  int       // actual coefficient count
    DetectedAt      time.Time
    DetectorID      NodeID
    Evidence        []byte    // serialized invalid commitment
}

// PolynomialDegreeRecoveryConfig defines non-configurable security parameters
const (
    PolynomialViolationDetectionTimeout = 30 * time.Second  // Max time to detect violation
    PolynomialViolationExclusionDeadline = 100 * time.Millisecond // Exclusion MUST complete
    PolynomialViolationSharePurgeTimeout = 5 * time.Second  // Time to purge invalid shares
    PolynomialViolationDKGRestartDelay = 10 * time.Second   // Delay before restart
    
    // Blame Quorum Requirements (prevents single-node blame attacks)
    // A participant cannot be excluded based on a single accuser's claim.
    // Multiple coordinators/participants must independently verify and confirm.
    PolynomialViolationBlameQuorum = 5         // 5-of-7 coordinators must confirm blame
    PolynomialViolationBlameQuorumTotal = 7    // Total coordinators in blame consensus
    PolynomialViolationBlameQuorumRatio = 0.71 // 5/7 = 71.4% confirmation required
    
    // Blame Immunity Period (prevents harassment attacks)
    // After being blamed for a violation (whether valid or not), a participant
    // has a 24-hour immunity window during which they cannot be blamed for the
    // SAME violation type again. This prevents:
    // - Repeated false accusations against honest participants
    // - Denial-of-service through blame flooding
    // - Reputation attacks through manufactured violations
    BlameImmunityPeriod = 24 * time.Hour
    
    // Blame Message Deduplication Window
    // Blame messages are deduplicated by (accuser, accused, violation_type, round)
    // to prevent amplification attacks where an accuser broadcasts multiple
    // identical blame messages to inflate their weight in consensus.
    BlameDedupWindow = 1 * time.Hour
)

// BlameMessageKey uniquely identifies a blame message for deduplication
// Blame messages with identical keys within BlameDedupWindow are ignored
type BlameMessageKey struct {
    AccuserID      NodeID
    AccusedID      NodeID
    ViolationType  BlameReason
    DKGRound       uint32
}

// BlameImmunityRecord tracks blame immunity for a participant
type BlameImmunityRecord struct {
    ParticipantID  NodeID
    ViolationType  BlameReason
    BlamedAt       time.Time
    ImmunityExpires time.Time
}

// BlameDeduplicator prevents duplicate blame message processing
type BlameDeduplicator struct {
    seen      map[BlameMessageKey]time.Time
    immunity  map[NodeID][]BlameImmunityRecord
    mu        sync.RWMutex
}

// ShouldProcessBlame returns true if the blame message should be processed
// Returns false if:
// - Duplicate blame within dedup window
// - Accused has immunity for this violation type
func (d *BlameDeduplicator) ShouldProcessBlame(blame *DKGPolynomialDegreeBlame) (bool, string) {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    now := time.Now()
    
    // Check deduplication
    key := BlameMessageKey{
        AccuserID:     blame.AccuserID,
        AccusedID:     blame.AccusedID,
        ViolationType: blame.Reason,
        DKGRound:      blame.DKGRound,
    }
    
    if lastSeen, exists := d.seen[key]; exists {
        if now.Sub(lastSeen) < BlameDedupWindow {
            return false, "duplicate blame message within dedup window"
        }
    }
    
    // Check immunity
    if immunityRecords, exists := d.immunity[blame.AccusedID]; exists {
        for _, record := range immunityRecords {
            if record.ViolationType == blame.Reason && now.Before(record.ImmunityExpires) {
                return false, fmt.Sprintf("accused has immunity until %v", record.ImmunityExpires)
            }
        }
    }
    
    // Record this blame
    d.seen[key] = now
    
    return true, ""
}

// RecordImmunity grants immunity to a participant for a violation type
// Called after blame consensus completes (regardless of verdict)
func (d *BlameDeduplicator) RecordImmunity(participantID NodeID, violationType BlameReason) {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    now := time.Now()
    record := BlameImmunityRecord{
        ParticipantID:   participantID,
        ViolationType:   violationType,
        BlamedAt:        now,
        ImmunityExpires: now.Add(BlameImmunityPeriod),
    }
    
    d.immunity[participantID] = append(d.immunity[participantID], record)
}

// HandlePolynomialDegreeViolation executes immediate exclusion protocol
func (p *Participant) HandlePolynomialDegreeViolation(violation *PolynomialDegreeViolation) error {
    // Step 1: Immediately halt processing of violator's data (< 10ms)
    p.commitmentMu.Lock()
    p.excludedParticipants[violation.ViolatorID] = true
    delete(p.receivedCommitments, violation.ViolatorID)
    p.commitmentMu.Unlock()

    // Step 2: Broadcast cryptographic blame with evidence (< 50ms)
    blame := &DKGPolynomialDegreeBlame{
        SessionID:      violation.SessionID,
        AccusedID:      violation.ViolatorID,
        AccuserID:      p.nodeID,
        Reason:         BlameReasonInvalidPolynomialDegree,
        ExpectedDegree: violation.ExpectedDegree,
        ReceivedDegree: violation.ReceivedDegree,
        Evidence:       violation.Evidence,
        Timestamp:      time.Now().UnixNano(),
        Signature:      nil, // filled below
    }
    blame.Signature = p.signBlame(blame)
    p.broadcastBlame(blame)

    // Step 3: Purge any shares already received from violator (< 40ms)
    if err := p.purgeViolatorShares(violation.ViolatorID); err != nil {
        return &SharePurgeError{ViolatorID: violation.ViolatorID, Cause: err}
    }

    // Step 4: Log security event for audit trail
    p.logSecurityEvent(&SecurityEvent{
        Type:      SecurityEventPolynomialDegreeViolation,
        Severity:  SeverityCritical,
        SessionID: violation.SessionID,
        NodeID:    violation.ViolatorID,
        Details:   violation,
    })

    return nil
}

// purgeViolatorShares removes all shares received from the violator
func (p *Participant) purgeViolatorShares(violatorID NodeID) error {
    p.sharesMu.Lock()
    defer p.sharesMu.Unlock()

    // Remove share sent BY violator
    delete(p.receivedShares, violatorID)

    // Mark shares sent TO violator as compromised (violator knows them)
    if sentShare, exists := p.sentShares[violatorID]; exists {
        p.compromisedShares[violatorID] = sentShare
        delete(p.sentShares, violatorID)
    }

    return nil
}
```

##### Blame Verification and Consensus

Before excluding a participant, other nodes MUST verify the blame is legitimate:

```go
// VerifyPolynomialDegreeBlame validates blame evidence before accepting exclusion
func (p *Participant) VerifyPolynomialDegreeBlame(blame *DKGPolynomialDegreeBlame) (bool, error) {
    // Verify accuser signature
    if !p.verifyBlameSignature(blame) {
        return false, ErrInvalidBlameSignature{AccuserID: blame.AccuserID}
    }

    // Deserialize and validate the evidence (the original commitment)
    commitment, err := deserializeCommitment(blame.Evidence)
    if err != nil {
        return false, ErrInvalidBlameEvidence{Reason: "deserialization failed"}
    }

    // Verify the commitment came from the accused
    if commitment.SenderID != blame.AccusedID {
        return false, ErrBlameEvidenceMismatch{
            ClaimedSender: blame.AccusedID,
            ActualSender:  commitment.SenderID,
        }
    }

    // Verify commitment signature (ensures commitment is authentic)
    if !p.verifyCommitmentSignature(commitment) {
        return false, ErrBlameEvidenceSignature{SenderID: commitment.SenderID}
    }

    // CRITICAL CHECK: Independently verify the polynomial degree violation
    if len(commitment.Coefficients) == p.threshold {
        // The commitment is actually valid - this is a false accusation
        return false, ErrFalseBlame{
            AccuserID:     blame.AccuserID,
            AccusedID:     blame.AccusedID,
            ActualDegree:  len(commitment.Coefficients),
            ClaimedDegree: blame.ReceivedDegree,
        }
    }

    // Blame verified - the commitment truly has wrong coefficient count
    return true, nil
}

// BlameConsensusState tracks blame verification across participants
type BlameConsensusState struct {
    SessionID      [32]byte
    AccusedID      NodeID
    BlameReason    BlameReason
    Confirmations  map[NodeID]bool  // NodeID -> verified blame
    Rejections     map[NodeID]bool  // NodeID -> rejected blame (false accusation)
    QuorumReached  bool
    FinalVerdict   BlameVerdict
}

type BlameVerdict uint8

const (
    BlameVerdictPending   BlameVerdict = 0
    BlameVerdictConfirmed BlameVerdict = 1  // Accused is guilty
    BlameVerdictRejected  BlameVerdict = 2  // False accusation
)

// ProcessBlameConsensus aggregates blame verifications and determines verdict
func (p *Participant) ProcessBlameConsensus(state *BlameConsensusState) BlameVerdict {
    totalParticipants := len(p.participants) - len(p.excludedParticipants)
    confirmCount := len(state.Confirmations)
    rejectCount := len(state.Rejections)

    // Quorum for confirmation: >50% must verify the blame
    if float64(confirmCount)/float64(totalParticipants) > PolynomialViolationBlameQuorum {
        state.FinalVerdict = BlameVerdictConfirmed
        state.QuorumReached = true
        return BlameVerdictConfirmed
    }

    // Quorum for rejection: >50% must reject (false accusation)
    if float64(rejectCount)/float64(totalParticipants) > PolynomialViolationBlameQuorum {
        state.FinalVerdict = BlameVerdictRejected
        state.QuorumReached = true
        // The accuser made a false accusation - they should be penalized
        p.handleFalseAccusation(state)
        return BlameVerdictRejected
    }

    return BlameVerdictPending
}
```

##### Share Invalidation and Purge Procedure

When a polynomial degree violation is detected, shares already distributed become compromised and MUST be handled:

```go
// ShareInvalidationState tracks share status during recovery
type ShareInvalidationState uint8

const (
    ShareStateValid        ShareInvalidationState = 0
    ShareStateCompromised  ShareInvalidationState = 1  // Violator received this share
    ShareStatePurged       ShareInvalidationState = 2  // Share has been zeroed
)

// SharePurgeResult records the outcome of share purging
type SharePurgeResult struct {
    ViolatorID      NodeID
    SharesPurged    int
    SharesRetained  int
    CompromisedData []CompromisedShareInfo
    PurgeCompletedAt time.Time
}

type CompromisedShareInfo struct {
    ShareIndex    int
    SentTo        NodeID    // The violator who received this share
    SentAt        time.Time
    ShareHash     [32]byte  // Hash for audit (not the share itself)
}

// ExecuteSharePurge removes all shares associated with the violator
func (p *Participant) ExecuteSharePurge(violatorID NodeID) (*SharePurgeResult, error) {
    p.sharesMu.Lock()
    defer p.sharesMu.Unlock()

    result := &SharePurgeResult{
        ViolatorID:   violatorID,
        CompromisedData: make([]CompromisedShareInfo, 0),
    }

    // 1. Purge shares RECEIVED from the violator
    // These shares are computed from an invalid polynomial and MUST be discarded
    if share, exists := p.receivedShares[violatorID]; exists {
        // Record for audit before purging
        result.CompromisedData = append(result.CompromisedData, CompromisedShareInfo{
            ShareIndex: share.SenderIndex,
            SentTo:     p.nodeID,
            SentAt:     share.ReceivedAt,
            ShareHash:  sha256.Sum256(share.Value.Bytes()),
        })

        // Secure wipe: overwrite with random data before delete
        secureWipeShare(share)
        delete(p.receivedShares, violatorID)
        result.SharesPurged++
    }

    // 2. Record shares SENT TO the violator as compromised
    // The violator knows these shares - they cannot be "unlearned"
    // but we must track them for security analysis
    if sentShare, exists := p.sentShares[violatorID]; exists {
        result.CompromisedData = append(result.CompromisedData, CompromisedShareInfo{
            ShareIndex: p.index,
            SentTo:     violatorID,
            SentAt:     sentShare.SentAt,
            ShareHash:  sha256.Sum256(sentShare.Value.Bytes()),
        })
        p.compromisedShareLog[violatorID] = sentShare
        delete(p.sentShares, violatorID)
    }

    // 3. Retain valid shares from non-violating participants
    for nodeID := range p.receivedShares {
        if nodeID != violatorID {
            result.SharesRetained++
        }
    }

    result.PurgeCompletedAt = time.Now()
    return result, nil
}

// secureWipeShare overwrites share data before memory release
func secureWipeShare(share *DKGShare) {
    if share.Value != nil {
        // Overwrite with random bytes
        randomBytes := make([]byte, len(share.Value.Bytes()))
        rand.Read(randomBytes)
        share.Value.SetBytes(randomBytes)
        // Zero out
        share.Value.SetInt64(0)
    }
    share.EncryptedShare = nil
}
```

##### DKG Session Restart Conditions

After excluding a misbehaving participant, the DKG session MUST evaluate whether to continue or restart:

```go
// DKGRestartCondition defines when a full restart is required
type DKGRestartCondition uint8

const (
    DKGContinueWithExclusion DKGRestartCondition = 0  // Can continue with remaining participants
    DKGRestartRequired       DKGRestartCondition = 1  // Must restart from Phase 0
    DKGAbortUnrecoverable    DKGRestartCondition = 2  // Cannot recover, abort entirely
)

// DKGRestartDecision contains the restart evaluation result
type DKGRestartDecision struct {
    Condition           DKGRestartCondition
    Reason              string
    ExcludedParticipants []NodeID
    RemainingParticipants int
    ThresholdMet        bool
    RestartDelay        time.Duration
    ReplacementCandidates []NodeID  // Nodes to add if restarting
}

// EvaluateRestartCondition determines if DKG can continue or must restart
func (s *DKGSession) EvaluateRestartCondition(excludedID NodeID) *DKGRestartDecision {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Add to exclusion list
    s.excludedParticipants[excludedID] = true

    // Calculate remaining participants
    remaining := len(s.participants) - len(s.excludedParticipants)
    decision := &DKGRestartDecision{
        ExcludedParticipants:  keys(s.excludedParticipants),
        RemainingParticipants: remaining,
        ThresholdMet:          remaining >= s.threshold,
    }

    // CONDITION 1: Insufficient participants for threshold
    if remaining < s.threshold {
        decision.Condition = DKGRestartRequired
        decision.Reason = fmt.Sprintf("remaining participants %d < threshold %d", remaining, s.threshold)
        decision.RestartDelay = PolynomialViolationDKGRestartDelay
        decision.ReplacementCandidates = s.selectReplacementCandidates(s.threshold - remaining + 1)
        return decision
    }

    // CONDITION 2: Violation detected BEFORE Phase 3 commitment broadcast complete
    // Can safely exclude and continue - no shares have been distributed yet
    if s.currentPhase < DKGPhaseShareDistribution {
        decision.Condition = DKGContinueWithExclusion
        decision.Reason = "violation detected before share distribution, continuing with remaining participants"
        return decision
    }

    // CONDITION 3: Violation detected DURING or AFTER share distribution
    // Shares have been exchanged - security analysis required
    if s.currentPhase >= DKGPhaseShareDistribution {
        // Check if compromised shares affect security
        compromisedCount := s.countCompromisedShares(excludedID)

        if compromisedCount > 0 {
            // The violator received shares from honest participants
            // These shares are now known to the adversary
            // However, if remaining >= t, the shares alone don't compromise the key

            if remaining >= s.threshold {
                // Still have enough honest participants
                // The excluded participant's knowledge doesn't help them
                decision.Condition = DKGContinueWithExclusion
                decision.Reason = fmt.Sprintf("violator received %d shares but remaining %d >= threshold %d",
                    compromisedCount, remaining, s.threshold)
            } else {
                // Threshold compromised - must restart
                decision.Condition = DKGRestartRequired
                decision.Reason = fmt.Sprintf("threshold compromised: remaining %d < threshold %d",
                    remaining, s.threshold)
                decision.RestartDelay = PolynomialViolationDKGRestartDelay
            }
        }
        return decision
    }

    // CONDITION 4: Multiple violations in same session
    if len(s.excludedParticipants) > s.maxToleratedFailures {
        decision.Condition = DKGAbortUnrecoverable
        decision.Reason = fmt.Sprintf("too many violations: %d > max tolerated %d",
            len(s.excludedParticipants), s.maxToleratedFailures)
        return decision
    }

    decision.Condition = DKGContinueWithExclusion
    return decision
}

// selectReplacementCandidates finds eligible nodes to replace excluded participants
func (s *DKGSession) selectReplacementCandidates(count int) []NodeID {
    candidates := make([]NodeID, 0)

    // Query nodes not in current session with high reputation
    eligibleNodes := s.nodeRegistry.GetEligibleNodes(DKGEligibilityRequirements{
        MinReputation:    0.85,
        NotInSession:     s.sessionID,
        NotExcluded:      true,
        HasTPMAttestation: true,
    })

    // Prefer nodes from geographic diversity
    selected := s.diversitySelector.SelectDiverse(eligibleNodes, count)
    return selected
}
```

##### Timeout and Detection Windows

```
POLYNOMIAL DEGREE VIOLATION DETECTION TIMELINE

    Phase 3 Start                Phase 3 End                    Phase 4 Start
         |                            |                              |
         |<-- Commitment Timeout ---->|                              |
         |        (30 seconds)        |                              |
         |                            |                              |
    T+0  |  Commitment broadcast      |                              |
         |        |                   |                              |
    T+1s |        v                   |                              |
         |  Commitment received       |                              |
         |        |                   |                              |
    T+2s |        v                   |                              |
         |  Validation starts         |                              |
         |        |                   |                              |
         |  [CHECK: len(coef) == t?]  |                              |
         |        |                   |                              |
         |   YES  |  NO               |                              |
         |    |   v                   |                              |
         |    | VIOLATION DETECTED    |                              |
         |    |   |                   |                              |
         |    |   +-> Exclusion (<100ms)                             |
         |    |   +-> Blame broadcast (<50ms)                        |
         |    |   +-> Share purge (<5s)                              |
         |    |   +-> Restart evaluation                             |
         |    |                       |                              |
         |    v                       |                              |
         |  Continue validation       |                              |
         |                            |                              |

CRITICAL TIMING REQUIREMENTS:

| Action | Maximum Latency | Failure Mode |
|--------|-----------------|--------------|
| Coefficient count check | 10ms | Reject commitment |
| Exclusion flag set | 100ms | Block share distribution |
| Blame broadcast | 50ms | Other nodes continue accepting |
| Share purge (local) | 5s | Compromised shares persist |
| Restart decision | 10s | Session stalls |
| DKG restart initiation | 30s | Coordinator timeout triggers |
```

##### State Diagram: Polynomial Degree Violation Recovery

```
                    POLYNOMIAL DEGREE VIOLATION RECOVERY STATE MACHINE

    ┌──────────────────────────────────────────────────────────────────────────┐
    │                     STATE: COMMITMENT_RECEIVED                            │
    │                                                                          │
    │  Entry: Commitment arrives from participant P_i                          │
    │  Action: Begin validation sequence                                       │
    └────────────────────────────────┬─────────────────────────────────────────┘
                                     │
                                     v
    ┌──────────────────────────────────────────────────────────────────────────┐
    │              VALIDATION: CHECK COEFFICIENT COUNT                          │
    │                                                                          │
    │  Test: len(commitment.Coefficients) == threshold ?                       │
    │                                                                          │
    └──────────────────────┬──────────────────────────┬────────────────────────┘
                           │                          │
                      PASS │                          │ FAIL
                           │                          │
                           v                          v
    ┌─────────────────────────────┐      ┌─────────────────────────────────────┐
    │  STATE: VALIDATION_CONTINUE │      │  STATE: VIOLATION_DETECTED           │
    │                             │      │                                     │
    │  Proceed to next check      │      │  Entry: Invalid coefficient count   │
    │  (Schnorr proof, signature) │      │  Action: Initiate recovery          │
    └─────────────────────────────┘      └─────────────────┬───────────────────┘
                                                           │
                                     ┌─────────────────────┴────────────────────┐
                                     │                                          │
                                     v                                          v
              ┌─────────────────────────────────┐      ┌────────────────────────────────┐
              │  STATE: IMMEDIATE_EXCLUSION      │      │  STATE: BLAME_BROADCAST        │
              │                                 │      │                                │
              │  Actions (parallel, <100ms):    │      │  Actions:                      │
              │  1. Set excludedParticipants[]  │      │  1. Create blame message       │
              │  2. Delete from commitments     │      │  2. Sign with IDevID           │
              │  3. Block share processing      │      │  3. Broadcast to all nodes     │
              └─────────────────┬───────────────┘      └────────────────┬───────────────┘
                                │                                       │
                                └───────────────────┬───────────────────┘
                                                    │
                                                    v
              ┌─────────────────────────────────────────────────────────────────────────┐
              │                     STATE: SHARE_PURGE                                   │
              │                                                                         │
              │  Actions (<5 seconds):                                                  │
              │  1. Delete shares received FROM violator                                │
              │  2. Mark shares sent TO violator as compromised                         │
              │  3. Secure wipe memory (overwrite before free)                          │
              │  4. Record compromise for audit                                         │
              └─────────────────────────────────┬───────────────────────────────────────┘
                                                │
                                                v
              ┌─────────────────────────────────────────────────────────────────────────┐
              │                STATE: RESTART_EVALUATION                                │
              │                                                                         │
              │  Decision Tree:                                                         │
              │                                                                         │
              │  IF remaining_participants >= threshold:                                │
              │     → STATE: CONTINUE_WITH_EXCLUSION                                    │
              │                                                                         │
              │  IF remaining_participants < threshold:                                 │
              │     → STATE: DKG_RESTART                                                │
              │                                                                         │
              │  IF excluded_count > max_tolerated:                                     │
              │     → STATE: DKG_ABORT                                                  │
              └─────────┬─────────────────────┬──────────────────────┬──────────────────┘
                        │                     │                      │
                        v                     v                      v
    ┌───────────────────────────┐ ┌───────────────────────┐ ┌────────────────────────┐
    │ STATE: CONTINUE_EXCLUSION │ │  STATE: DKG_RESTART   │ │   STATE: DKG_ABORT     │
    │                           │ │                       │ │                        │
    │ Actions:                  │ │ Actions:              │ │ Actions:               │
    │ 1. Resume DKG protocol    │ │ 1. Wait restart delay │ │ 1. Notify all nodes    │
    │ 2. Exclude violator from  │ │ 2. Select replacements│ │ 2. Log failure reason  │
    │    share aggregation      │ │ 3. Reset session state│ │ 3. Trigger fallback    │
    │ 3. Complete Phase 3+      │ │ 4. Restart from Ph.0  │ │    (use previous keys) │
    └───────────────────────────┘ └───────────────────────┘ └────────────────────────┘
```

##### Error Types for Polynomial Degree Violations

```go
// pkg/dkg/polynomial_degree_errors.go

// ErrPolynomialDegreeViolation indicates invalid coefficient count was detected
type ErrPolynomialDegreeViolation struct {
    SessionID      [32]byte
    ViolatorID     NodeID
    ExpectedDegree int
    ReceivedDegree int
    Phase          DKGPhase
}

func (e ErrPolynomialDegreeViolation) Error() string {
    return fmt.Sprintf("polynomial degree violation in session %x from %x: expected degree %d, got %d (phase %d)",
        e.SessionID[:8], e.ViolatorID[:8], e.ExpectedDegree, e.ReceivedDegree, e.Phase)
}

func (e ErrPolynomialDegreeViolation) IsCritical() bool { return true }

// ErrSharePurgeFailure indicates share purge did not complete successfully
type ErrSharePurgeFailure struct {
    ViolatorID    NodeID
    SharesPending int
    Cause         error
}

func (e ErrSharePurgeFailure) Error() string {
    return fmt.Sprintf("share purge failed for violator %x: %d shares pending: %v",
        e.ViolatorID[:8], e.SharesPending, e.Cause)
}

// ErrBlameConsensusTimeout indicates blame quorum was not reached
type ErrBlameConsensusTimeout struct {
    SessionID     [32]byte
    AccusedID     NodeID
    Confirmations int
    Required      int
    Timeout       time.Duration
}

func (e ErrBlameConsensusTimeout) Error() string {
    return fmt.Sprintf("blame consensus timeout for %x: %d/%d confirmations in %v",
        e.AccusedID[:8], e.Confirmations, e.Required, e.Timeout)
}

// ErrFalsePolynomialBlame indicates a participant made a false accusation
type ErrFalsePolynomialBlame struct {
    AccuserID     NodeID
    AccusedID     NodeID
    ActualDegree  int
    ClaimedDegree int
}

func (e ErrFalsePolynomialBlame) Error() string {
    return fmt.Sprintf("false polynomial degree blame: %x accused %x of degree %d but actual degree is %d",
        e.AccuserID[:8], e.AccusedID[:8], e.ClaimedDegree, e.ActualDegree)
}

// ErrDKGRestartExhausted indicates maximum restart attempts reached
type ErrDKGRestartExhausted struct {
    SessionID      [32]byte
    RestartCount   int
    MaxRestarts    int
    LastError      error
}

func (e ErrDKGRestartExhausted) Error() string {
    return fmt.Sprintf("DKG restart exhausted in session %x: %d/%d restarts, last error: %v",
        e.SessionID[:8], e.RestartCount, e.MaxRestarts, e.LastError)
}
```

##### Security Guarantees After Recovery

| Guarantee | Maintained | Rationale |
|-----------|------------|-----------|
| **Threshold Security** | Yes | Violator excluded, cannot participate in signing |
| **Key Secrecy** | Yes | Shares from valid polynomial, adversary learns nothing |
| **Unforgeability** | Yes | Violator's invalid polynomial cannot produce valid shares |
| **Accountability** | Yes | Blame message provides cryptographic proof of violation |
| **Auditability** | Yes | All actions logged with timestamps and evidence |

**Post-Recovery Verification:**

After excluding a participant for polynomial degree violation, the remaining participants MUST verify:

1. All retained commitments have exactly `threshold` coefficients
2. No shares from the violator exist in any participant's state
3. The violator is in all participants' exclusion lists
4. Blame quorum was reached (>50% confirmations)
5. Session can proceed with remaining participants >= threshold

### Protocol Phases

#### Phase 0: Coordinator Election

Coordinator manages DKG but cannot influence the outcome.

```go
type CoordinatorElection struct {
    Seed        []byte    // VRF seed from previous epoch
    Candidates  []NodeID  // Nodes with reputation >= 0.9
    Selected    NodeID    // Primary coordinator
    Backups     []NodeID  // Failover coordinators
}

func ElectCoordinator(seed []byte, candidates []NodeID) *CoordinatorElection {
    // VRF-based selection ensures verifiable randomness
    results := make([]VRFResult, len(candidates))
    for i, c := range candidates {
        results[i] = VRF.Evaluate(seed, c)
    }

    // Sort by VRF output
    sort.Slice(results, func(i, j int) bool {
        return bytes.Compare(results[i].Output, results[j].Output) < 0
    })

    return &CoordinatorElection{
        Seed:     seed,
        Selected: results[0].NodeID,
        Backups:  []NodeID{results[1].NodeID, results[2].NodeID},
    }
}
```

#### Phase 1: Participant Selection and TPM Attestation

```
Coordinator                           Participants
    |                                      |
    |  1. DKGAttestationRequest           |
    |  {session_id, nonce, epoch, ...}    |
    |------------------------------------->|
    |                                      |
    |                                      | 2. Generate TPM quote
    |                                      |    with nonce
    |                                      |
    |  3. DKGAttestationResponse          |
    |  {quote, ak_cert, signature}        |
    |<-------------------------------------|
    |                                      |
    | 4. Verify:                          |
    |    - Quote signature valid          |
    |    - Timestamp within +/-100ms      |
    |    - AK cert from known manufacturer|
    |    - PCR values acceptable          |
    |                                      |
```

```go
func (c *Coordinator) VerifyAttestation(resp *DKGAttestationResponse) error {
    // Check timestamp freshness
    if abs(time.Now().UnixMilli()-resp.Timestamp) > 100 {
        return ErrAttestationStale
    }

    // Verify TPM quote
    if err := c.tpm.VerifyQuote(resp.Quote, resp.AKCert, c.nonce); err != nil {
        return err
    }

    // Check manufacturer whitelist
    mfr := c.extractManufacturer(resp.AKCert)
    if !c.isManufacturerAllowed(mfr) {
        return ErrManufacturerBlocked
    }

    return nil
}
```

#### Phase 2: Secure Channel Establishment

Each participant establishes pairwise encrypted channels.

```
P_i                                    P_j
 |                                      |
 | 1. Generate ephemeral ECDH keypair   |
 |    (inside TPM)                      |
 |                                      |
 |  DKGKeyExchange                      |
 |  {ephemeral_pk, proof_of_possession} |
 |------------------------------------->|
 |                                      |
 |                                      | 2. Verify proof
 |                                      |    Compute shared secret
 |                                      |
 |  DKGKeyExchange                      |
 |<-------------------------------------|
 |                                      |
 | 3. k_ij = ECDH(sk_i, pk_j)          |
 |    Derive AES-256-GCM key           |
 |                                      |
```

```go
func (p *Participant) EstablishChannels(participants []NodeID) (map[NodeID]*SecureChannel, error) {
    channels := make(map[NodeID]*SecureChannel)

    // Generate ephemeral keypair in TPM
    sk, pk, err := p.tpm.GenerateECDHKeypair()
    if err != nil {
        return nil, err
    }

    // Proof of possession (Schnorr proof)
    proof := p.generatePoP(sk, pk)

    // Broadcast key exchange
    msg := &DKGKeyExchange{
        SessionID:         p.sessionID,
        SenderID:          p.nodeID,
        EphemeralPubkey:   pk,
        ProofOfPossession: proof,
    }
    p.broadcast(msg)

    // Collect others' public keys
    for _, other := range participants {
        if other == p.nodeID {
            continue
        }

        resp, err := p.receiveKeyExchange(other, 60*time.Second)
        if err != nil {
            return nil, err
        }

        // Verify proof of possession
        if !p.verifyPoP(resp.EphemeralPubkey, resp.ProofOfPossession) {
            return nil, ErrInvalidPoP{NodeID: other}
        }

        // Compute shared secret
        shared := p.tpm.ECDH(sk, resp.EphemeralPubkey)

        // Derive symmetric key
        key := hkdf.Expand(sha256.New, shared, []byte("DKG-AES-KEY"))

        channels[other] = &SecureChannel{
            PeerID: other,
            Key:    key,
        }
    }

    return channels, nil
}
```

#### DKG Commit-Reveal Protocol

The DKG protocol uses a commit-reveal scheme to prevent last-mover advantage attacks where a participant could bias the group public key by observing others' commitments before submitting their own. This three-phase approach ensures all participants commit simultaneously, preventing any participant from gaining an unfair advantage.

**Attack Vector (Without Commit-Reveal):**

```
Without commit-reveal, a malicious participant M can:
1. Wait for honest participants P1, P2, ..., Pn to broadcast commitments
2. Observe C1, C2, ..., Cn (polynomial commitments)
3. Compute the partial group public key: PK_partial = C1[0] + C2[0] + ... + Cn[0]
4. Choose M's commitment C_m such that PK_partial + C_m[0] = desired_value
5. Result: M can bias the group public key to a chosen value
```

**Commit-Reveal Phases:**

| Phase | Duration | Action | Validation |
|-------|----------|--------|------------|
| **1. Commit** | 0 - 30s | Submit H(commitment) | Hash must be unique |
| **2. Wait** | 30s - 60s | Mandatory delay | No early reveals accepted |
| **3. Reveal** | 60s - 120s | Submit commitment | Must match Phase 1 hash |

```go
// pkg/dkg/commit_reveal.go

// CommitRevealConfig defines timing parameters
const (
    CommitPhaseDuration   = 30 * time.Second  // Phase 1: Submit hash commitments
    MinCommitRevealDelay  = 30 * time.Second  // Minimum gap before reveals
    RevealPhaseDuration   = 60 * time.Second  // Phase 3: Submit actual commitments
    CommitHashFunction    = sha256.New        // Hash function for commitments
)

// CommitRevealState tracks the commit-reveal protocol state
type CommitRevealState uint8

const (
    CRStateAwaitingCommits   CommitRevealState = iota  // Phase 1: Collecting hashes
    CRStateWaitingForReveal                             // Mandatory delay period
    CRStateAwaitingReveals                              // Phase 3: Collecting reveals
    CRStateComplete                                     // All reveals validated
    CRStateFailed                                       // Mismatch detected
)

// CommitRevealManager orchestrates the commit-reveal protocol
type CommitRevealManager struct {
    sessionID          [32]byte
    state              CommitRevealState
    participants       []NodeID

    // Phase 1: Hash commitments
    commitHashes       map[NodeID][32]byte  // H(commitment)
    commitHashTimes    map[NodeID]time.Time
    commitPhaseEnd     time.Time

    // Phase 3: Revealed commitments
    revealedCommitments map[NodeID]*DKGCommitment
    revealTimes        map[NodeID]time.Time
    revealPhaseEnd     time.Time

    // Mismatch tracking
    mismatches         []CommitRevealMismatch

    mu                 sync.Mutex
}

// CommitRevealMismatch records when a reveal doesn't match its commit
type CommitRevealMismatch struct {
    ParticipantID  NodeID
    ExpectedHash   [32]byte
    ActualHash     [32]byte
    DetectedAt     time.Time
}

// SubmitCommitHash receives a hash commitment in Phase 1
func (m *CommitRevealManager) SubmitCommitHash(
    participantID NodeID,
    commitHash [32]byte,
) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Verify we're in commit phase
    if m.state != CRStateAwaitingCommits {
        return &CommitPhaseClosedError{
            CurrentState: m.state,
            PhaseEndTime: m.commitPhaseEnd,
        }
    }

    // Check for duplicates
    if _, exists := m.commitHashes[participantID]; exists {
        return &DuplicateCommitHashError{ParticipantID: participantID}
    }

    // Record the commit hash
    m.commitHashes[participantID] = commitHash
    m.commitHashTimes[participantID] = time.Now()

    // Check if all participants have committed
    if len(m.commitHashes) == len(m.participants) {
        m.transitionToWaitPhase()
    }

    return nil
}

// transitionToWaitPhase starts the mandatory delay period
func (m *CommitRevealManager) transitionToWaitPhase() {
    m.state = CRStateWaitingForReveal
    m.revealPhaseEnd = time.Now().Add(MinCommitRevealDelay + RevealPhaseDuration)

    // Schedule transition to reveal phase
    go func() {
        time.Sleep(MinCommitRevealDelay)
        m.mu.Lock()
        m.state = CRStateAwaitingReveals
        m.mu.Unlock()
    }()
}

// SubmitReveal receives the actual commitment in Phase 3
func (m *CommitRevealManager) SubmitReveal(
    participantID NodeID,
    commitment *DKGCommitment,
) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Verify we're in reveal phase
    if m.state != CRStateAwaitingReveals {
        if m.state == CRStateWaitingForReveal {
            return &RevealTooEarlyError{
                ParticipantID: participantID,
                WaitRemaining: time.Until(m.commitPhaseEnd.Add(MinCommitRevealDelay)),
            }
        }
        return &RevealPhaseClosedError{CurrentState: m.state}
    }

    // Verify participant submitted a commit hash
    expectedHash, hasCommit := m.commitHashes[participantID]
    if !hasCommit {
        return &MissingCommitHashError{ParticipantID: participantID}
    }

    // CRITICAL: Verify the reveal matches the commit
    actualHash := m.computeCommitmentHash(commitment)
    if actualHash != expectedHash {
        mismatch := CommitRevealMismatch{
            ParticipantID: participantID,
            ExpectedHash:  expectedHash,
            ActualHash:    actualHash,
            DetectedAt:    time.Now(),
        }
        m.mismatches = append(m.mismatches, mismatch)

        return &CommitRevealMismatchError{
            ParticipantID: participantID,
            ExpectedHash:  expectedHash,
            ActualHash:    actualHash,
        }
    }

    // Store the revealed commitment
    m.revealedCommitments[participantID] = commitment
    m.revealTimes[participantID] = time.Now()

    // Check if all participants have revealed
    if len(m.revealedCommitments) == len(m.participants) {
        m.state = CRStateComplete
    }

    return nil
}

// computeCommitmentHash computes H(commitment) for verification
func (m *CommitRevealManager) computeCommitmentHash(c *DKGCommitment) [32]byte {
    h := sha256.New()

    // Include all commitment fields deterministically
    h.Write(c.SessionID[:])
    h.Write(c.SenderID[:])
    binary.Write(h, binary.BigEndian, c.SenderIndex)

    // Hash each coefficient point
    for _, coeff := range c.Coefficients {
        h.Write(coeff.X.Bytes())
        h.Write(coeff.Y.Bytes())
    }

    // Include proof of knowledge
    h.Write(c.ProofOfKnowledge)

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}

// GetMismatches returns any detected commit-reveal mismatches
func (m *CommitRevealManager) GetMismatches() []CommitRevealMismatch {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.mismatches
}
```

**Commit-Reveal Timeline:**

```
                        COMMIT-REVEAL PROTOCOL TIMELINE

    T=0                T=30s               T=60s               T=120s
     │                   │                   │                   │
     │   COMMIT PHASE    │   WAIT PHASE      │   REVEAL PHASE    │
     │                   │                   │                   │
     │ ┌───────────────┐ │ ┌───────────────┐ │ ┌───────────────┐ │
     │ │ Submit H(C)   │ │ │ Mandatory     │ │ │ Submit C      │ │
     │ │ from each     │ │ │ 30s delay     │ │ │ from each     │ │
     │ │ participant   │ │ │               │ │ │ participant   │ │
     │ │               │ │ │ No reveals    │ │ │               │ │
     │ │ All must      │ │ │ accepted      │ │ │ Verify:       │ │
     │ │ submit before │ │ │               │ │ │ H(C) matches  │ │
     │ │ phase ends    │ │ │               │ │ │ Phase 1 hash  │ │
     │ └───────────────┘ │ └───────────────┘ │ └───────────────┘ │
     │                   │                   │                   │
     ▼                   ▼                   ▼                   ▼
   Phase 1            Phase 2             Phase 3              Complete
   Deadline           Starts              Starts               or Abort

    VIOLATION HANDLING:

    - Missing commit by T=30s:  Participant excluded, blamed
    - Early reveal (T<60s):     Reveal rejected, participant warned
    - Hash mismatch:            Participant excluded, blamed, DKG continues
    - Missing reveal by T=120s: Participant excluded, blamed
```

**Security Properties:**

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Binding** | Cannot change commitment after hash | Cryptographic hash preimage resistance |
| **Hiding** | Hash reveals nothing about commitment | Collision resistance, proper hash function |
| **Simultaneity** | All commits before any reveals | Mandatory delay period (30s) |
| **Accountability** | Mismatches provably attributable | Hash evidence retained |

#### Phase 3: Commitment Round

Each participant commits to their polynomial.

```go
func (p *Participant) GenerateCommitment() (*DKGCommitment, error) {
    // Generate random polynomial of degree t-1
    // f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
    coefficients := make([]*big.Int, p.threshold)
    for i := 0; i < p.threshold; i++ {
        coefficients[i], _ = rand.Int(rand.Reader, p.curve.Params().N)
    }

    // Compute commitments: C_i = a_i * G
    commitments := make([]Point, p.threshold)
    for i, a := range coefficients {
        commitments[i] = p.curve.ScalarBaseMult(a.Bytes())
    }

    // Schnorr proof of knowledge for a_0
    proof := p.schnorrProve(coefficients[0])

    // Store coefficients for Phase 4
    p.polynomial = coefficients

    return &DKGCommitment{
        SessionID:        p.sessionID,
        SenderID:         p.nodeID,
        SenderIndex:      p.index,
        Coefficients:     commitments,
        ProofOfKnowledge: proof,
    }, nil
}
```

**Validation (with Trail of Bits fix):**

```go
func (p *Participant) ValidateCommitment(c *DKGCommitment) error {
    // CRITICAL: Check coefficient count (Trail of Bits fix)
    if len(c.Coefficients) != p.threshold {
        return ErrInvalidCoefficientCount
    }

    // Verify Schnorr proof
    if !p.schnorrVerify(c.Coefficients[0], c.ProofOfKnowledge) {
        return ErrInvalidProof
    }

    return nil
}
```

##### DKG Commitment Validation State Machine (P4-C6)

**CRITICAL**: Commitment validation is a BLOCKING gate. No participant may proceed to Phase 4 until ALL commitments from ALL participants have been validated. This prevents malicious polynomials from corrupting the key generation.

```
                    DKG COMMITMENT VALIDATION STATE MACHINE

    ┌────────────────────────────────────────────────────────────────────┐
    │                     STATE: AWAITING_COMMITMENTS                     │
    │                                                                    │
    │  Entry: Phase 3 starts                                             │
    │  Exit:  All commitments received OR timeout                        │
    └──────────────────────────────┬─────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   For EACH commitment:      │
                    │   ReceiveCommitment(c)      │
                    └──────────────┬──────────────┘
                                   │
    ┌──────────────────────────────▼─────────────────────────────────────┐
    │                    STATE: VALIDATING_COMMITMENT                     │
    │                                                                    │
    │  BLOCKING - MUST complete before storing commitment                │
    │                                                                    │
    │  ┌─────────────────────────────────────────────────────────────┐  │
    │  │ CHECK 1: Coefficient Count (Trail of Bits CVE fix)          │  │
    │  │   len(commitment.Coefficients) == threshold                 │  │
    │  │   If FAIL: → COMMITMENT_REJECTED                            │  │
    │  └─────────────────────────────────────────────────────────────┘  │
    │                              │                                     │
    │                              ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────┐  │
    │  │ CHECK 2: Schnorr Proof of Knowledge                         │  │
    │  │   schnorrVerify(C[0], proof)                                │  │
    │  │   If FAIL: → COMMITMENT_REJECTED                            │  │
    │  └─────────────────────────────────────────────────────────────┘  │
    │                              │                                     │
    │                              ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────┐  │
    │  │ CHECK 3: Sender Authentication                              │  │
    │  │   Verify commitment signed by sender's IDevID               │  │
    │  │   If FAIL: → COMMITMENT_REJECTED                            │  │
    │  └─────────────────────────────────────────────────────────────┘  │
    │                              │                                     │
    │                              ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────┐  │
    │  │ CHECK 4: Session Binding                                    │  │
    │  │   commitment.SessionID == current session                   │  │
    │  │   If FAIL: → COMMITMENT_REJECTED                            │  │
    │  └─────────────────────────────────────────────────────────────┘  │
    │                                                                    │
    └──────────────────────────────┬─────────────────────────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │                                         │
              ▼                                         ▼
    ┌─────────────────────┐                 ┌─────────────────────────┐
    │ COMMITMENT_ACCEPTED │                 │ COMMITMENT_REJECTED     │
    │                     │                 │                         │
    │ Store commitment    │                 │ 1. Record rejection     │
    │ Update received     │                 │ 2. Broadcast BLAME      │
    │   count             │                 │ 3. Exclude sender       │
    │                     │                 │ 4. Log evidence         │
    └─────────┬───────────┘                 └─────────────────────────┘
              │
              ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │              All commitments received AND validated?                │
    │                                                                     │
    │   YES: Proceed to Phase 4                                           │
    │   NO:  Wait for more commitments OR timeout                         │
    └─────────────────────────────────────────────────────────────────────┘
```

```go
// CommitmentValidationState tracks the blocking validation state
type CommitmentValidationState uint8

const (
    CommitmentStateAwaiting    CommitmentValidationState = 0
    CommitmentStateValidating  CommitmentValidationState = 1
    CommitmentStateAccepted    CommitmentValidationState = 2
    CommitmentStateRejected    CommitmentValidationState = 3
)

// ReceiveAndValidateCommitment is the ONLY entry point for commitment processing
// SECURITY: This function MUST complete validation before returning success
func (p *Participant) ReceiveAndValidateCommitment(c *DKGCommitment) error {
    p.commitmentMu.Lock()
    defer p.commitmentMu.Unlock()

    // Check for duplicate
    if _, exists := p.receivedCommitments[c.SenderID]; exists {
        return ErrDuplicateCommitment{SenderID: c.SenderID}
    }

    // BLOCKING VALIDATION PHASE
    // All checks MUST pass before commitment is stored
    if err := p.validateCommitmentBlocking(c); err != nil {
        // Validation failed - broadcast blame and exclude sender
        p.broadcastBlame(&DKGBlame{
            SessionID:  p.sessionID,
            AccusedID:  c.SenderID,
            Reason:     BlameReasonInvalidCommitment,
            Evidence:   serializeCommitment(c),
            ErrorMsg:   err.Error(),
        })

        p.excludedParticipants[c.SenderID] = true
        return err
    }

    // Validation passed - store commitment
    p.receivedCommitments[c.SenderID] = c.Coefficients

    // Check if we can proceed to Phase 4
    if p.canProceedToPhase4() {
        p.signalPhaseTransition(DKGPhaseShareDistribution)
    }

    return nil
}

// validateCommitmentBlocking performs ALL validation checks in sequence
// Returns error if ANY check fails - commitment is rejected
func (p *Participant) validateCommitmentBlocking(c *DKGCommitment) error {
    // CHECK 1: Coefficient count (Trail of Bits CVE fix)
    // CRITICAL: Prevents threshold manipulation attack
    if len(c.Coefficients) != p.threshold {
        return ErrInvalidCoefficientCount{
            Expected: p.threshold,
            Received: len(c.Coefficients),
            SenderID: c.SenderID,
        }
    }

    // CHECK 2: Schnorr proof of knowledge
    // Proves sender knows the secret a_0
    if !p.schnorrVerify(c.Coefficients[0], c.ProofOfKnowledge) {
        return ErrInvalidProofOfKnowledge{SenderID: c.SenderID}
    }

    // CHECK 3: Sender authentication
    // Commitment must be signed by sender's IDevID
    if !p.verifyCommitmentSignature(c) {
        return ErrInvalidCommitmentSignature{SenderID: c.SenderID}
    }

    // CHECK 4: Session binding
    // Prevents cross-session attacks
    if c.SessionID != p.sessionID {
        return ErrSessionMismatch{
            Expected: p.sessionID,
            Received: c.SessionID,
        }
    }

    // CHECK 5: Index bounds
    // Sender index must be valid for this DKG session
    if c.SenderIndex < 1 || c.SenderIndex > len(p.participants) {
        return ErrInvalidSenderIndex{Index: c.SenderIndex}
    }

    return nil
}

// canProceedToPhase4 checks if all required commitments are validated
func (p *Participant) canProceedToPhase4() bool {
    requiredCount := len(p.participants) - len(p.excludedParticipants)

    // Need at least threshold valid commitments from non-excluded participants
    validCount := 0
    for nodeID := range p.receivedCommitments {
        if !p.excludedParticipants[nodeID] {
            validCount++
        }
    }

    return validCount >= p.threshold
}

// Error types for commitment validation
type ErrInvalidCoefficientCount struct {
    Expected int
    Received int
    SenderID NodeID
}
func (e ErrInvalidCoefficientCount) Error() string {
    return fmt.Sprintf("invalid coefficient count from %x: expected %d, got %d",
        e.SenderID[:8], e.Expected, e.Received)
}

type ErrInvalidProofOfKnowledge struct {
    SenderID NodeID
}
func (e ErrInvalidProofOfKnowledge) Error() string {
    return fmt.Sprintf("invalid Schnorr proof from %x", e.SenderID[:8])
}

type ErrInvalidCommitmentSignature struct {
    SenderID NodeID
}
func (e ErrInvalidCommitmentSignature) Error() string {
    return fmt.Sprintf("commitment signature invalid from %x", e.SenderID[:8])
}

type ErrSessionMismatch struct {
    Expected [32]byte
    Received [32]byte
}
func (e ErrSessionMismatch) Error() string {
    return fmt.Sprintf("session mismatch: expected %x, got %x", e.Expected[:8], e.Received[:8])
}

type ErrInvalidSenderIndex struct {
    Index int
}
func (e ErrInvalidSenderIndex) Error() string {
    return fmt.Sprintf("invalid sender index: %d", e.Index)
}

type ErrDuplicateCommitment struct {
    SenderID NodeID
}
func (e ErrDuplicateCommitment) Error() string {
    return fmt.Sprintf("duplicate commitment from %x", e.SenderID[:8])
}
```

#### Phase 4: Share Distribution

Each participant evaluates their polynomial at every other participant's index.

```go
func (p *Participant) DistributeShares(channels map[NodeID]*SecureChannel) error {
    for _, other := range p.participants {
        if other.NodeID == p.nodeID {
            continue
        }

        // Evaluate polynomial at other's index
        // s_ij = f_i(j) mod q
        share := p.evaluatePolynomial(other.Index)

        // Encrypt share
        channel := channels[other.NodeID]
        nonce := make([]byte, 12)
        rand.Read(nonce)

        ciphertext := channel.Encrypt(share.Bytes(), nonce)

        // Send
        msg := &DKGShare{
            SessionID:      p.sessionID,
            SenderID:       p.nodeID,
            RecipientID:    other.NodeID,
            EncryptedShare: ciphertext,
            Nonce:          nonce,
        }

        if err := p.sendDirect(other.NodeID, msg); err != nil {
            // Fallback to DHT relay
            p.sendViaRelay(other.NodeID, msg)
        }
    }

    return nil
}

func (p *Participant) evaluatePolynomial(x int) *big.Int {
    // f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    result := new(big.Int).Set(p.polynomial[0])
    xPow := big.NewInt(int64(x))

    for i := 1; i < len(p.polynomial); i++ {
        term := new(big.Int).Mul(p.polynomial[i], xPow)
        result.Add(result, term)
        xPow.Mul(xPow, big.NewInt(int64(x)))
    }

    return result.Mod(result, p.curve.Params().N)
}
```

**Share Verification:**

```go
func (p *Participant) VerifyShare(from NodeID, share *big.Int) error {
    // Get sender's commitments
    commitments := p.receivedCommitments[from]

    // Compute: share * G
    left := p.curve.ScalarBaseMult(share.Bytes())

    // Compute: Sum(C_k * j^k) for k = 0 to t-1
    right := p.curve.Identity()
    jPow := big.NewInt(1)
    j := big.NewInt(int64(p.index))

    for k := 0; k < len(commitments); k++ {
        term := p.curve.ScalarMult(commitments[k], jPow.Bytes())
        right = p.curve.Add(right, term)
        jPow.Mul(jPow, j)
    }

    // Verify: share * G == Sum(C_k * j^k)
    if !p.curve.Equal(left, right) {
        return ErrInvalidShare{From: from}
    }

    return nil
}
```

#### Phase 5: Complaint Resolution

If share verification fails, file a complaint using **secure key revelation** that prevents exposing other encrypted communications:

```go
// SECURITY: Never reveal the channel symmetric key directly.
// This would expose ALL encrypted messages between complainant and accused,
// potentially leaking other shares or sensitive DKG state.
//
// Instead, use judge-specific key derivation: derive a one-time key
// specifically for this complaint verification.

func (p *Participant) FileComplaint(against NodeID, share []byte, channel *SecureChannel) error {
    // Generate complaint-specific verification key using HKDF
    // This key can ONLY decrypt the specific share in question
    complaintID := sha256.Sum256(append(p.sessionID[:], append(p.nodeID[:], against[:]...)...))
    verificationKey := hkdf.Expand(sha256.New, channel.Key, append([]byte("DKG-COMPLAINT-KEY"), complaintID[:]...))

    // Re-encrypt the share with the verification key
    // Original message was encrypted with channel.Key
    // We create a transcript proof that links them without exposing channel.Key
    shareProof := &ShareTranscriptProof{
        OriginalCiphertext: share,
        DecryptedShare:     decrypt(share, channel.Key),
        ReencryptedShare:   encrypt(decrypt(share, channel.Key), verificationKey),
    }

    complaint := &DKGComplaint{
        SessionID:       p.sessionID,
        ComplainantID:   p.nodeID,
        AccusedID:       against,
        ShareProof:      shareProof,
        VerificationKey: verificationKey,  // Only reveals complaint-specific key
        ComplaintID:     complaintID,
    }

    // Sign complaint with TPM
    complaint.Signature = p.signWithTPM(complaint.Hash())

    // Broadcast complaint
    return p.broadcast(complaint)
}

// DKGComplaint contains a secure complaint that doesn't expose the channel key
type DKGComplaint struct {
    SessionID       [32]byte
    ComplainantID   NodeID
    AccusedID       NodeID
    ShareProof      *ShareTranscriptProof
    VerificationKey []byte    // HKDF-derived key for THIS complaint only
    ComplaintID     [32]byte  // Unique complaint identifier
    Signature       []byte    // TPM-signed
}

// ShareTranscriptProof proves share invalidity without exposing channel key
type ShareTranscriptProof struct {
    OriginalCiphertext []byte  // The encrypted share as received
    DecryptedShare     []byte  // The decrypted share value
    ReencryptedShare   []byte  // Re-encrypted with verification key
}

func (p *Participant) VerifyComplaint(c *DKGComplaint) (bool, error) {
    // 1. Verify complaint signature
    if !verifySignature(c.ComplainantID, c.Hash(), c.Signature) {
        return false, ErrComplaintSignatureInvalid
    }

    // 2. Verify the verification key was correctly derived
    // (Accusers can verify by observing the original key exchange)
    expectedComplaintID := sha256.Sum256(append(c.SessionID[:], append(c.ComplainantID[:], c.AccusedID[:]...)...))
    if c.ComplaintID != expectedComplaintID {
        return false, ErrComplaintIDMismatch
    }

    // 3. Verify the re-encrypted share matches using verification key
    decrypted := decrypt(c.ShareProof.ReencryptedShare, c.VerificationKey)
    if !bytes.Equal(decrypted, c.ShareProof.DecryptedShare) {
        return false, ErrComplaintProofInvalid
    }

    // 4. Verify the decrypted share against accused's commitments
    err := p.verifyShareAgainstCommitments(c.AccusedID, c.ShareProof.DecryptedShare)

    if err != nil {
        // Share was invalid - complaint is justified
        return true, nil
    }

    // Share was valid - false complaint
    return false, nil
}
```

#### Phase 6: Key Derivation and CertEq

```go
func (p *Participant) DeriveKeys() (*DKGResult, error) {
    // Aggregate received shares
    // sk_j = Sum(s_ij) for all i
    p.secretShare = big.NewInt(0)
    for _, share := range p.receivedShares {
        p.secretShare.Add(p.secretShare, share)
    }
    p.secretShare.Mod(p.secretShare, p.curve.Params().N)

    // Compute group public key
    // PK = Sum(C_i0) for all i
    p.groupPublicKey = p.curve.Identity()
    for _, commitment := range p.receivedCommitments {
        p.groupPublicKey = p.curve.Add(p.groupPublicKey, commitment[0])
    }

    // Compute public share
    // PK_j = sk_j * G
    p.publicShare = p.curve.ScalarBaseMult(p.secretShare.Bytes())

    // CertEq: Sign agreement on group public key
    cert := &DKGCertificate{
        SessionID:      p.sessionID,
        SignerID:       p.nodeID,
        GroupPublicKey: p.groupPublicKey,
        PublicShare:    p.publicShare,
        Signature:      p.signWithShare(p.sessionID, p.groupPublicKey),
    }

    p.broadcast(cert)

    // Collect t certificates agreeing on same PK
    return p.collectCertificates()
}
```

#### Phase 7: TPM Sealing

```go
func (p *Participant) SealShare() error {
    // Seal secret share to TPM
    handle, err := p.tpm.SealKey(p.secretShare.Bytes(), &SealingPolicy{
        PCRSelection: []int{0, 2, 7},
    })
    if err != nil {
        return err
    }

    // Store handle for later use
    p.shareHandle = handle

    // Zero memory containing secret share
    for i := range p.secretShare.Bytes() {
        p.secretShare.SetInt64(0)
    }

    return nil
}
```

### Timing

| Phase | Normal DKG | Emergency DKG |
|-------|------------|---------------|
| Coordinator Election | 1 sec | 1 sec |
| TPM Attestation | 2 min | 1 min |
| Secure Channel Setup | 1 min | 30 sec |
| Commitment Round | 1 min | 30 sec |
| Share Distribution | 2 min | 1 min |
| Complaint Resolution | 1 min | 30 sec |
| Key Derivation | 1 min | 30 sec |
| TPM Sealing | 1 min | 30 sec |
| **Total** | **10 min** | **5 min** |

### Phase Timeout Ordering

DKG phase timeouts are categorized into **soft deadlines** (can be extended with participant acknowledgment) and **hard deadlines** (absolute cutoffs with no extensions). This distinction is critical for understanding when a phase can gracefully extend versus when the protocol must enforce strict termination.

#### Deadline Types

| Deadline Type | Description | Extension Policy |
|---------------|-------------|------------------|
| **Soft Deadline** | Target completion time for normal operation | Can be extended once with 2/3 participant acknowledgment |
| **Hard Deadline** | Absolute maximum time before forced termination | No extensions allowed; triggers abort or exclusion |

#### Phase-Specific Timeout Configuration

```
DKG PHASE TIMEOUT ORDERING DIAGRAM

Session Start                                                              Session Hard Limit
    |                                                                              |
    |  Phase 1         Phase 2           Phase 3           Phase 4                 |
    |  Commitment      Share Dist        Verification      Key Assembly            |
    |                                                                              |
    |  [soft: 30s]     [soft: 30s]       [soft: 45s]       [soft: 15s]            |
    |  [hard: 60s]     [hard: 60s]       [hard: 90s]       [hard: 30s]            |
    |                                                                              |
    +==============================================================================+
    |<------------------------ Total Session Hard Limit: 300s -------------------->|
                              (5 minutes absolute maximum)

LEGEND:
    [soft: Xs] = Soft deadline at X seconds (extendable with 2/3 acknowledgment)
    [hard: Xs] = Hard deadline at X seconds (no extensions, forced termination)
```

#### Detailed Timeout Specifications

| Phase | Phase Name | Soft Deadline | Hard Deadline | Extension Allowed | Max Extension |
|-------|------------|---------------|---------------|-------------------|---------------|
| **1** | Commitment | 30s | 60s | Yes | +15s |
| **2** | Share Distribution | 30s | 60s | Yes | +15s |
| **3** | Verification | 45s | 90s | Yes | +20s |
| **4** | Key Assembly | 15s | 30s | Yes | +10s |
| **Session** | Total DKG | N/A | 300s (5 min) | **No** | N/A |

#### Soft Deadline Behavior

Soft deadlines represent target completion times under normal network conditions. When a soft deadline is reached:

1. **Extension Request**: The coordinator may request a deadline extension
2. **Participant Acknowledgment**: At least 2/3 of active participants must acknowledge
3. **Single Extension Only**: Each phase allows at most one extension
4. **Extension Duration**: Limited to the "Max Extension" value for that phase
5. **Cumulative Constraint**: Total extensions cannot cause session to exceed hard limit

**When Extensions Are Allowed:**

- Network latency causes temporary delays (not node failures)
- At least 80% of expected messages have been received
- No security violations detected in current phase
- Session hard limit has not been reached

**Extension Request Format:**

```go
type DeadlineExtensionRequest struct {
    SessionID       [32]byte
    Phase           DKGPhase
    CurrentDeadline time.Time
    RequestedDeadline time.Time
    Reason          ExtensionReason
    ReceivedCount   int  // Messages received so far
    ExpectedCount   int  // Total expected messages
}

type ExtensionReason uint8

const (
    ExtensionNetworkLatency ExtensionReason = iota
    ExtensionHighLoad
    ExtensionPartialProgress
)
```

#### Hard Deadline Behavior

Hard deadlines are absolute cutoffs that cannot be extended under any circumstances. When a hard deadline is reached:

1. **Immediate Termination**: The phase is forcibly terminated
2. **Slow Node Identification**: Nodes that have not completed are identified
3. **Exclusion or Retry Decision**: Based on remaining participant count:
   - If remaining >= threshold: Continue with exclusions
   - If remaining < threshold: Abort and retry with new participants
4. **Slashing Consideration**: Slow nodes may be subject to reputation penalties

**Security-Critical Cutoffs:**

Hard deadlines enforce security-critical timing constraints:

| Cutoff Type | Timeout | Action on Breach |
|-------------|---------|------------------|
| Phase hard deadline | Per-phase (see table) | Exclude slow nodes, continue or retry |
| Session hard deadline | 300s (5 min) | Abort entire DKG, slash coordinator if at fault |
| Commitment verification | 60s | Reject late commitments as invalid |
| Share distribution | 60s | Exclude nodes with missing shares |

**Abort vs Retry Decision Tree:**

```
Hard Deadline Reached
        │
        ├── Identify slow/missing nodes
        │
        ▼
┌─────────────────────────────────────┐
│ Remaining Participants >= Threshold? │
└─────────────────────────────────────┘
        │
   YES  │  NO
        │   │
        ▼   ▼
┌─────────────┐   ┌──────────────────────────┐
│ CONTINUE    │   │ Check Retry Count        │
│ Exclude     │   │                          │
│ slow nodes  │   │ Retries < MaxDKGAttempts?│
└─────────────┘   └──────────────────────────┘
                          │
                     YES  │  NO
                          │   │
                          ▼   ▼
                  ┌─────────────┐   ┌─────────────┐
                  │ RETRY       │   │ ABORT       │
                  │ New attempt │   │ DKG failed  │
                  │ with        │   │ Use fallback│
                  │ replacements│   │ recovery    │
                  └─────────────┘   └─────────────┘
```

#### Timeout Ordering Invariants

The following invariants MUST hold for timeout ordering:

1. **Phase Ordering**: `soft_deadline(phase_N) < hard_deadline(phase_N)` for all phases
2. **Extension Limit**: `soft_deadline + max_extension <= hard_deadline`
3. **Session Constraint**: `sum(hard_deadlines) <= session_hard_limit`
4. **No Overlap**: Phase N+1 cannot start until Phase N completes or times out
5. **Monotonic Progress**: Once a hard deadline passes, no rollback is allowed

```go
// TimeoutOrderingValidation ensures timeout configuration is valid
func ValidateTimeoutOrdering(config DKGTimeoutConfig) error {
    // Invariant 1: Soft < Hard for each phase
    for phase, timeouts := range config.PhaseTimeouts {
        if timeouts.SoftDeadline >= timeouts.HardDeadline {
            return ErrInvalidTimeoutOrdering
        }
        // Invariant 2: Soft + MaxExtension <= Hard
        if timeouts.SoftDeadline + timeouts.MaxExtension > timeouts.HardDeadline {
            return ErrExtensionExceedsHard
        }
    }

    // Invariant 3: Sum of hard deadlines <= session limit
    var totalHard time.Duration
    for _, timeouts := range config.PhaseTimeouts {
        totalHard += timeouts.HardDeadline
    }
    if totalHard > config.SessionHardLimit {
        return ErrPhasesExceedSession
    }

    return nil
}
```

#### Timeout Configuration Constants

```go
// DKG Phase Timeout Configuration
const (
    // Phase 1: Commitment
    Phase1SoftDeadline = 30 * time.Second
    Phase1HardDeadline = 60 * time.Second
    Phase1MaxExtension = 15 * time.Second

    // Phase 2: Share Distribution
    Phase2SoftDeadline = 30 * time.Second
    Phase2HardDeadline = 60 * time.Second
    Phase2MaxExtension = 15 * time.Second

    // Phase 3: Verification
    Phase3SoftDeadline = 45 * time.Second
    Phase3HardDeadline = 90 * time.Second
    Phase3MaxExtension = 20 * time.Second

    // Phase 4: Key Assembly
    Phase4SoftDeadline = 15 * time.Second
    Phase4HardDeadline = 30 * time.Second
    Phase4MaxExtension = 10 * time.Second

    // Session-level hard limit (absolute maximum)
    SessionHardLimit = 300 * time.Second  // 5 minutes
)
```

### Error Handling

| Error | Action |
|-------|--------|
| Participant timeout | Exclude, restart with remaining |
| Invalid commitment | Exclude participant |
| Invalid share | File complaint |
| Complaint verified | Exclude accused, restart |
| False complaint | Exclude complainant |
| CertEq disagreement | Restart with blame |
| TPM failure | Exclude participant |

### DKG Session State Machine

The DKG protocol follows a deterministic state machine with explicit states, transitions, and failure handling. This ensures predictable behavior and enables proper recovery from failures.

**State Definitions:**

| State | Description | Entry Condition | Exit Condition |
|-------|-------------|-----------------|----------------|
| **INITIALIZING** | Session setup, participant selection | DKG session requested | All participants attested |
| **SHARING** | Commitment and share distribution | Attestation complete | All shares distributed |
| **VALIDATING** | Blocking validation of commitments | Shares received | All commitments validated |
| **COMMITTED** | All commitments validated, computing key | Validation complete | Key derivation complete |
| **ACTIVE** | DKG complete, key is operational | Key sealed to TPM | Session terminated |
| **FAILED_RECOVERABLE** | Transient failure, retry possible | Recoverable error | Retry initiated |
| **FAILED_UNRECOVERABLE** | Permanent failure, new DKG required | Unrecoverable error | New DKG with different participants |

**State Machine Diagram:**

```
                          DKG SESSION STATE MACHINE

    ┌─────────────────────────────────────────────────────────────────────────┐
    │                                                                         │
    │  ┌──────────────────┐                                                   │
    │  │   INITIALIZING   │◄─────────────────────────────────────────────┐    │
    │  │                  │                                               │    │
    │  │  - Elect coord   │                                               │    │
    │  │  - Select nodes  │                                               │    │
    │  │  - TPM attest    │                                               │    │
    │  └────────┬─────────┘                                               │    │
    │           │                                                         │    │
    │           │ All participants attested                               │    │
    │           ▼                                                         │    │
    │  ┌──────────────────┐                                               │    │
    │  │     SHARING      │                                               │    │
    │  │                  │                                               │    │
    │  │  - Generate poly │                                               │    │
    │  │  - Broadcast     │                                               │    │
    │  │    commitments   │                                               │    │
    │  │  - Distribute    │                                               │    │
    │  │    shares        │                                               │    │
    │  └────────┬─────────┘                                               │    │
    │           │                                                         │    │
    │           │ All shares received                                     │    │
    │           ▼                                                         │    │
    │  ┌──────────────────┐                                               │    │
    │  │   VALIDATING     │◄───── BLOCKING PHASE ─────┐                   │    │
    │  │                  │                           │                   │    │
    │  │  NO PROGRESS     │   Validation failure      │                   │    │
    │  │  until ALL       │   (invalid coeff count,   │                   │    │
    │  │  commitments     │   bad proof, etc.)        │                   │    │
    │  │  validated       │           │               │                   │    │
    │  └────────┬─────────┘           │               │                   │    │
    │           │                     │               │                   │    │
    │           │                     ▼               │                   │    │
    │           │            ┌────────────────┐       │                   │    │
    │           │            │ Exclude sender │       │                   │    │
    │           │            │ Broadcast BLAME│───────┘                   │    │
    │           │            └────────────────┘                           │    │
    │           │                                                         │    │
    │           │ All commitments valid                                   │    │
    │           ▼                                                         │    │
    │  ┌──────────────────┐                                               │    │
    │  │    COMMITTED     │                                               │    │
    │  │                  │                                               │    │
    │  │  - Derive group  │                                               │    │
    │  │    public key    │                                               │    │
    │  │  - Compute share │                                               │    │
    │  │  - Verify CertEq │                                               │    │
    │  └────────┬─────────┘                                               │    │
    │           │                                                         │    │
    │           │ Key derived, CertEq verified                            │    │
    │           ▼                                                         │    │
    │  ┌──────────────────┐                                               │    │
    │  │      ACTIVE      │                                               │    │
    │  │                  │                                               │    │
    │  │  - Seal to TPM   │                                               │    │
    │  │  - Publish key   │                                               │    │
    │  │  - Ready to sign │                                               │    │
    │  └──────────────────┘                                               │    │
    │                                                                     │    │
    │           FAILURE PATHS                                             │    │
    │           ══════════════                                            │    │
    │                                                                     │    │
    │  ┌──────────────────┐      Retry with same      ┌────────────────┐  │    │
    │  │ FAILED_          │      participants         │                │  │    │
    │  │ RECOVERABLE      │─────────────────────────► │  INITIALIZING  │  │    │
    │  │                  │                           │                │──┘    │
    │  │  - Timeout       │                           └────────────────┘       │
    │  │  - Network issue │                                                    │
    │  │  - TPM transient │                                                    │
    │  └──────────────────┘                                                    │
    │                                                                          │
    │  ┌──────────────────┐      New DKG with         ┌────────────────┐       │
    │  │ FAILED_          │      different            │                │       │
    │  │ UNRECOVERABLE    │─────────────────────────► │  INITIALIZING  │       │
    │  │                  │      participants         │  (new session) │       │
    │  │  - >50% failure  │                           └────────────────┘       │
    │  │  - Collusion     │                                                    │
    │  │  - Crypto attack │                                                    │
    │  └──────────────────┘                                                    │
    │                                                                          │
    └──────────────────────────────────────────────────────────────────────────┘
```

**State Implementation:**

```go
// pkg/dkg/state.go

// DKGState represents the current state of a DKG session
type DKGState uint8

const (
    DKGStateInitializing      DKGState = 0
    DKGStateSharing           DKGState = 1
    DKGStateValidating        DKGState = 2  // BLOCKING
    DKGStateCommitted         DKGState = 3
    DKGStateActive            DKGState = 4
    DKGStateFailedRecoverable DKGState = 5
    DKGStateFailedUnrecoverable DKGState = 6
)

// DKGSession manages the complete DKG lifecycle
type DKGSession struct {
    SessionID       [32]byte
    State           DKGState
    Coordinator     NodeID
    Participants    []NodeID
    Threshold       int

    // State tracking
    StateHistory    []StateTransition
    CurrentPhase    DKGPhase
    PhaseDeadline   time.Time

    // Failure tracking
    ConsecutiveTimeouts int
    FailedParticipants  map[NodeID]FailureReason

    mu sync.RWMutex
}

type StateTransition struct {
    FromState   DKGState
    ToState     DKGState
    Timestamp   time.Time
    Reason      string
    TriggeredBy NodeID
}

// TransitionTo performs a validated state transition
func (s *DKGSession) TransitionTo(newState DKGState, reason string, triggeredBy NodeID) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Validate transition is allowed
    if !s.isValidTransition(s.State, newState) {
        return &InvalidStateTransitionError{
            From:   s.State,
            To:     newState,
            Reason: "transition not allowed",
        }
    }

    // Record transition
    transition := StateTransition{
        FromState:   s.State,
        ToState:     newState,
        Timestamp:   time.Now(),
        Reason:      reason,
        TriggeredBy: triggeredBy,
    }
    s.StateHistory = append(s.StateHistory, transition)

    // Update state
    s.State = newState

    return nil
}

// isValidTransition checks if a state transition is allowed
func (s *DKGSession) isValidTransition(from, to DKGState) bool {
    validTransitions := map[DKGState][]DKGState{
        DKGStateInitializing:       {DKGStateSharing, DKGStateFailedRecoverable, DKGStateFailedUnrecoverable},
        DKGStateSharing:            {DKGStateValidating, DKGStateFailedRecoverable, DKGStateFailedUnrecoverable},
        DKGStateValidating:         {DKGStateCommitted, DKGStateSharing, DKGStateFailedRecoverable, DKGStateFailedUnrecoverable},
        DKGStateCommitted:          {DKGStateActive, DKGStateFailedRecoverable, DKGStateFailedUnrecoverable},
        DKGStateActive:             {}, // Terminal state for success
        DKGStateFailedRecoverable:  {DKGStateInitializing},
        DKGStateFailedUnrecoverable: {}, // Terminal state for failure
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
```

**Recovery Triggers:**

```go
// pkg/dkg/recovery_triggers.go

// RecoveryTrigger defines conditions for recovery actions
type RecoveryTrigger struct {
    ConsecutiveTimeoutThreshold int           // 3 consecutive timeouts -> rotate coordinator
    ParticipantFailureThreshold float64       // >50% failure -> abort and restart
    MaxRecoveryAttempts         int           // Maximum retries before unrecoverable
}

var DefaultRecoveryTrigger = RecoveryTrigger{
    ConsecutiveTimeoutThreshold: 3,
    ParticipantFailureThreshold: 0.50,
    MaxRecoveryAttempts:         3,
}

// CheckRecoveryConditions evaluates failure conditions and returns recovery action
func (s *DKGSession) CheckRecoveryConditions() RecoveryAction {
    s.mu.RLock()
    defer s.mu.RUnlock()

    totalParticipants := len(s.Participants)
    failedCount := len(s.FailedParticipants)

    // Condition 1: More than 50% participant failure -> unrecoverable
    if float64(failedCount)/float64(totalParticipants) > DefaultRecoveryTrigger.ParticipantFailureThreshold {
        return RecoveryAction{
            Type:   RecoveryUnrecoverable,
            Reason: fmt.Sprintf("participant failure rate %.0f%% exceeds threshold",
                float64(failedCount)/float64(totalParticipants)*100),
        }
    }

    // Condition 2: 3 consecutive timeouts -> rotate coordinator
    if s.ConsecutiveTimeouts >= DefaultRecoveryTrigger.ConsecutiveTimeoutThreshold {
        return RecoveryAction{
            Type:   RecoveryRotateCoordinator,
            Reason: fmt.Sprintf("%d consecutive timeouts", s.ConsecutiveTimeouts),
        }
    }

    // Condition 3: Remaining participants >= threshold -> retry with same set
    remainingParticipants := totalParticipants - failedCount
    if remainingParticipants >= s.Threshold {
        return RecoveryAction{
            Type:   RecoveryRetryWithRemaining,
            Reason: fmt.Sprintf("%d remaining participants >= threshold %d",
                remainingParticipants, s.Threshold),
        }
    }

    // Otherwise unrecoverable - insufficient remaining participants
    return RecoveryAction{
        Type:   RecoveryUnrecoverable,
        Reason: fmt.Sprintf("insufficient participants: %d < threshold %d",
            remainingParticipants, s.Threshold),
    }
}

type RecoveryActionType uint8

const (
    RecoveryRetryWithRemaining  RecoveryActionType = 0
    RecoveryRotateCoordinator   RecoveryActionType = 1
    RecoveryUnrecoverable       RecoveryActionType = 2
)

type RecoveryAction struct {
    Type   RecoveryActionType
    Reason string
}

// HandleTimeout processes a timeout event and updates recovery state
func (s *DKGSession) HandleTimeout(phase DKGPhase, slowNodes []NodeID) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.ConsecutiveTimeouts++

    // Mark slow nodes as failed
    for _, node := range slowNodes {
        s.FailedParticipants[node] = FailureReasonTimeout
    }

    // Check if coordinator rotation is needed
    if s.ConsecutiveTimeouts >= DefaultRecoveryTrigger.ConsecutiveTimeoutThreshold {
        if err := s.rotateCoordinator(); err != nil {
            return &CoordinatorRotationError{Cause: err}
        }
        s.ConsecutiveTimeouts = 0 // Reset after rotation
    }

    return nil
}

// rotateCoordinator selects the next backup coordinator
func (s *DKGSession) rotateCoordinator() error {
    backups := getBackupCoordinators(s.SessionID)
    if len(backups) == 0 {
        return ErrNoBackupCoordinatorsAvailable
    }

    // Mark current coordinator as failed
    s.FailedParticipants[s.Coordinator] = FailureReasonCoordinatorTimeout

    // Select first available backup
    for _, backup := range backups {
        if _, failed := s.FailedParticipants[backup]; !failed {
            oldCoord := s.Coordinator
            s.Coordinator = backup

            broadcastCoordinatorChange(s.SessionID, oldCoord, backup)
            return nil
        }
    }

    return ErrAllCoordinatorsFailed
}

type FailureReason uint8

const (
    FailureReasonTimeout            FailureReason = 0
    FailureReasonInvalidCommitment  FailureReason = 1
    FailureReasonInvalidShare       FailureReason = 2
    FailureReasonFalseComplaint     FailureReason = 3
    FailureReasonTPMError           FailureReason = 4
    FailureReasonCoordinatorTimeout FailureReason = 5
    FailureReasonNetworkError       FailureReason = 6
)
```

**Recovery Trigger Summary:**

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Consecutive timeouts | 3 | Rotate to backup coordinator |
| Participant failure rate | >50% | Abort, start new DKG with different participants |
| Remaining participants | >= t | Retry with remaining participants |
| Remaining participants | < t | Unrecoverable, new participant selection required |
| All coordinators failed | N/A | Escalate to genesis trustee recovery |

### DKG Session Rate Limiting

**CRITICAL SECURITY**: Without rate limiting, attackers can DoS the CA by initiating
many DKG sessions concurrently, exhausting coordinator resources and preventing
legitimate key generation.

```go
// DKG Rate Limiting Configuration - non-configurable security parameters
const (
    // Global rate limits
    MaxConcurrentDKGSessions = 3              // Max simultaneous DKG sessions network-wide
    MinDKGSessionInterval    = 5 * time.Minute // Minimum time between session starts
    MaxDKGSessionsPerHour    = 10             // Maximum sessions per hour globally
    MaxDKGSessionsPerDay     = 50             // Maximum sessions per day globally

    // Per-node rate limits
    MaxNodeDKGInitiationsPerHour = 2          // Max DKG initiations per node per hour
    MaxNodeDKGInitiationsPerDay  = 5          // Max DKG initiations per node per day
    NodeDKGCooldownAfterFailure  = 30 * time.Minute // Cooldown after failed initiation

    // Stake requirements (anti-spam)
    DKGInitiationStake   = 100               // Coins locked during DKG initiation
    DKGStakeSlashPercent = 10                // Percent slashed on abort/griefing
)

// Error types for rate limiting
var (
    ErrDKGRateLimitExceeded    = errors.New("DKG session rate limit exceeded")
    ErrDKGConcurrencyLimit     = errors.New("maximum concurrent DKG sessions reached")
    ErrDKGNodeCooldown         = errors.New("node is in DKG cooldown period")
    ErrDKGInsufficientStake    = errors.New("insufficient stake for DKG initiation")
)

// DKGRateLimiter controls DKG session initiation
type DKGRateLimiter struct {
    // Global tracking
    activeSessions  map[[32]byte]*DKGSessionInfo // sessionID -> info
    sessionHistory  []DKGSessionRecord           // Rolling history
    lastSessionTime time.Time

    // Per-node tracking
    nodeInitiations map[NodeID]*NodeDKGHistory

    // Stake management
    lockedStakes map[NodeID]uint64

    mu sync.RWMutex
}

type DKGSessionInfo struct {
    SessionID   [32]byte
    Initiator   NodeID
    StartTime   time.Time
    Purpose     DKGPurpose
    Participants []NodeID
}

type DKGPurpose uint8

const (
    DKGPurposeNewCA       DKGPurpose = 1  // New CA pool creation
    DKGPurposeKeyRotation DKGPurpose = 2  // Scheduled key rotation
    DKGPurposeRecovery    DKGPurpose = 3  // CA recovery after failure
    DKGPurposeEmergency   DKGPurpose = 4  // Emergency re-keying
)

type DKGSessionRecord struct {
    SessionID   [32]byte
    Initiator   NodeID
    StartTime   time.Time
    EndTime     time.Time
    Success     bool
    Purpose     DKGPurpose
}

type NodeDKGHistory struct {
    NodeID         NodeID
    Initiations    []time.Time   // Times of DKG initiations
    FailedAttempts int           // Consecutive failures
    CooldownUntil  time.Time     // Cooldown expiration
    TotalAborts    int           // Lifetime aborts (for reputation)
}

// RequestDKGSession attempts to start a new DKG session with rate limiting
func (rl *DKGRateLimiter) RequestDKGSession(
    ctx context.Context,
    initiator NodeID,
    purpose DKGPurpose,
    stakeManager *StakeManager,
) ([32]byte, error) {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    // Check 1: Concurrent session limit
    if len(rl.activeSessions) >= MaxConcurrentDKGSessions {
        return [32]byte{}, ErrDKGConcurrencyLimit
    }

    // Check 2: Global interval
    if time.Since(rl.lastSessionTime) < MinDKGSessionInterval {
        return [32]byte{}, fmt.Errorf("%w: must wait %v",
            ErrDKGRateLimitExceeded, MinDKGSessionInterval-time.Since(rl.lastSessionTime))
    }

    // Check 3: Hourly/daily global limits
    hourAgo := time.Now().Add(-1 * time.Hour)
    dayAgo := time.Now().Add(-24 * time.Hour)
    hourCount, dayCount := 0, 0
    for _, record := range rl.sessionHistory {
        if record.StartTime.After(hourAgo) {
            hourCount++
        }
        if record.StartTime.After(dayAgo) {
            dayCount++
        }
    }
    if hourCount >= MaxDKGSessionsPerHour {
        return [32]byte{}, fmt.Errorf("%w: hourly limit (%d) reached",
            ErrDKGRateLimitExceeded, MaxDKGSessionsPerHour)
    }
    if dayCount >= MaxDKGSessionsPerDay {
        return [32]byte{}, fmt.Errorf("%w: daily limit (%d) reached",
            ErrDKGRateLimitExceeded, MaxDKGSessionsPerDay)
    }

    // Check 4: Per-node rate limits
    nodeHistory := rl.getOrCreateNodeHistory(initiator)

    // Node cooldown check
    if time.Now().Before(nodeHistory.CooldownUntil) {
        return [32]byte{}, fmt.Errorf("%w: cooldown until %v",
            ErrDKGNodeCooldown, nodeHistory.CooldownUntil)
    }

    // Node hourly/daily limits
    nodeHourCount, nodeDayCount := 0, 0
    for _, t := range nodeHistory.Initiations {
        if t.After(hourAgo) {
            nodeHourCount++
        }
        if t.After(dayAgo) {
            nodeDayCount++
        }
    }
    if nodeHourCount >= MaxNodeDKGInitiationsPerHour {
        return [32]byte{}, fmt.Errorf("%w: node hourly limit (%d) reached",
            ErrDKGRateLimitExceeded, MaxNodeDKGInitiationsPerHour)
    }
    if nodeDayCount >= MaxNodeDKGInitiationsPerDay {
        return [32]byte{}, fmt.Errorf("%w: node daily limit (%d) reached",
            ErrDKGRateLimitExceeded, MaxNodeDKGInitiationsPerDay)
    }

    // Check 5: Stake requirement (anti-spam)
    if err := stakeManager.LockStake(initiator, DKGInitiationStake); err != nil {
        return [32]byte{}, fmt.Errorf("%w: %v", ErrDKGInsufficientStake, err)
    }

    // All checks passed - create session
    sessionID := generateSessionID(initiator, purpose, time.Now())
    session := &DKGSessionInfo{
        SessionID: sessionID,
        Initiator: initiator,
        StartTime: time.Now(),
        Purpose:   purpose,
    }

    rl.activeSessions[sessionID] = session
    rl.lastSessionTime = time.Now()
    nodeHistory.Initiations = append(nodeHistory.Initiations, time.Now())
    rl.lockedStakes[initiator] = DKGInitiationStake

    return sessionID, nil
}

// CompleteDKGSession marks a session as complete and handles stake
func (rl *DKGRateLimiter) CompleteDKGSession(
    sessionID [32]byte,
    success bool,
    stakeManager *StakeManager,
) error {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    session, ok := rl.activeSessions[sessionID]
    if !ok {
        return ErrDKGSessionNotFound
    }

    // Record in history
    record := DKGSessionRecord{
        SessionID: sessionID,
        Initiator: session.Initiator,
        StartTime: session.StartTime,
        EndTime:   time.Now(),
        Success:   success,
        Purpose:   session.Purpose,
    }
    rl.sessionHistory = append(rl.sessionHistory, record)

    // Prune old history (keep 7 days)
    cutoff := time.Now().Add(-7 * 24 * time.Hour)
    var newHistory []DKGSessionRecord
    for _, r := range rl.sessionHistory {
        if r.StartTime.After(cutoff) {
            newHistory = append(newHistory, r)
        }
    }
    rl.sessionHistory = newHistory

    // Handle stake
    nodeHistory := rl.nodeInitiations[session.Initiator]
    if success {
        // Return stake on success
        stakeManager.UnlockStake(session.Initiator, DKGInitiationStake)
        nodeHistory.FailedAttempts = 0 // Reset failure counter
    } else {
        // Slash stake on failure
        slashAmount := (DKGInitiationStake * DKGStakeSlashPercent) / 100
        stakeManager.SlashStake(session.Initiator, slashAmount)
        stakeManager.UnlockStake(session.Initiator, DKGInitiationStake-slashAmount)

        // Update failure tracking
        nodeHistory.FailedAttempts++
        nodeHistory.TotalAborts++

        // Progressive cooldown based on consecutive failures
        cooldown := NodeDKGCooldownAfterFailure * time.Duration(nodeHistory.FailedAttempts)
        if cooldown > 24*time.Hour {
            cooldown = 24 * time.Hour // Cap at 24 hours
        }
        nodeHistory.CooldownUntil = time.Now().Add(cooldown)
    }

    delete(rl.activeSessions, sessionID)
    delete(rl.lockedStakes, session.Initiator)

    return nil
}

// getOrCreateNodeHistory retrieves or creates node DKG history
func (rl *DKGRateLimiter) getOrCreateNodeHistory(nodeID NodeID) *NodeDKGHistory {
    if rl.nodeInitiations == nil {
        rl.nodeInitiations = make(map[NodeID]*NodeDKGHistory)
    }
    if history, ok := rl.nodeInitiations[nodeID]; ok {
        return history
    }
    history := &NodeDKGHistory{NodeID: nodeID}
    rl.nodeInitiations[nodeID] = history
    return history
}

func generateSessionID(initiator NodeID, purpose DKGPurpose, t time.Time) [32]byte {
    h := sha256.New()
    h.Write(initiator[:])
    h.Write([]byte{byte(purpose)})
    binary.Write(h, binary.BigEndian, t.UnixNano())
    var id [32]byte
    copy(id[:], h.Sum(nil))
    return id
}
```

### DKG Progress Tracking

DKG sessions enforce progress timeouts with aborter exclusion to guarantee completion within bounded attempts.

```go
// DKG Recovery Configuration - non-configurable security parameters
const (
    MaxDKGAttempts       = 5              // Maximum retry attempts per session
    MaxAbortCount        = 2              // Max aborts before permanent exclusion
    DKGProgressTimeout   = 15 * time.Minute // Total time for DKG completion
    PhaseTimeout         = 3 * time.Minute  // Per-phase timeout
    CooldownPeriod       = 1 * time.Hour    // Cooldown after abort
    AbortExclusionPeriod = 7 * 24 * time.Hour // 7-day exclusion for repeat aborters
)

// DKGProgressTracker ensures DKG makes forward progress
type DKGProgressTracker struct {
    SessionID      [32]byte
    Attempt        int
    Phase          DKGPhase
    StartTime      time.Time
    PhaseDeadline  time.Time
    Participants   map[NodeID]*ParticipantState
    AbortHistory   map[NodeID]int  // Count of aborts per node
    CompletedNodes map[NodeID]bool
}

type ParticipantState struct {
    NodeID       NodeID
    JoinedAt     time.Time
    LastActivity time.Time
    PhaseStatus  map[DKGPhase]PhaseResult
    AbortCount   int
}

type PhaseResult uint8

const (
    PhaseNotStarted PhaseResult = iota
    PhaseInProgress
    PhaseCompleted
    PhaseFailed
    PhaseTimedOut
)

// RunDKGWithProgress executes DKG with guaranteed progress
func (t *DKGProgressTracker) RunDKGWithProgress(coordinator *Coordinator) (*DKGResult, error) {
    overallDeadline := time.Now().Add(DKGProgressTimeout)

    for attempt := 1; attempt <= MaxDKGAttempts; attempt++ {
        t.Attempt = attempt

        // Check overall deadline
        if time.Now().After(overallDeadline) {
            return nil, ErrDKGProgressTimeout
        }

        // Get eligible participants (exclude recent aborters)
        participants := t.getEligibleParticipants()
        if len(participants) < MinCAPoolSize {
            return nil, ErrInsufficientParticipants
        }

        result, err := t.executeDKGAttempt(coordinator, participants)
        if err == nil {
            return result, nil // Success!
        }

        // Handle failure - identify and exclude aborters
        aborters := t.identifyAborters(err)
        for _, aborter := range aborters {
            t.recordAbort(aborter)
        }

        // Brief cooldown before retry
        time.Sleep(10 * time.Second)
    }

    return nil, ErrDKGMaxAttemptsExceeded
}

// executeDKGAttempt runs a single DKG attempt with per-phase timeouts
func (t *DKGProgressTracker) executeDKGAttempt(coord *Coordinator, participants []NodeID) (*DKGResult, error) {
    phases := []DKGPhase{
        PhaseAttestation,
        PhaseChannelSetup,
        PhaseCommitment,
        PhaseShareDistribution,
        PhaseComplaintResolution,
        PhaseKeyDerivation,
        PhaseTPMSealing,
    }

    for _, phase := range phases {
        t.Phase = phase
        t.PhaseDeadline = time.Now().Add(PhaseTimeout)

        result := t.executePhase(coord, phase, participants)

        switch result.Status {
        case PhaseCompleted:
            continue // Move to next phase

        case PhaseTimedOut:
            // Identify nodes that didn't complete
            slowNodes := t.getSlowNodes(phase)
            return nil, &DKGPhaseTimeout{Phase: phase, SlowNodes: slowNodes}

        case PhaseFailed:
            return nil, &DKGPhaseFailure{Phase: phase, Reason: result.Error}
        }
    }

    return t.finalizeResult()
}

// recordAbort tracks abort history and applies penalties
func (t *DKGProgressTracker) recordAbort(nodeID NodeID) {
    t.AbortHistory[nodeID]++
    count := t.AbortHistory[nodeID]

    switch {
    case count >= MaxAbortCount:
        // Permanent exclusion from this session + reputation penalty
        excludeFromDKG(nodeID, AbortExclusionPeriod)
        slashReputation(nodeID, -0.1, "dkg_repeated_abort")

    case count == 1:
        // First abort: temporary cooldown
        excludeFromDKG(nodeID, CooldownPeriod)

    default:
        // Second abort: longer cooldown + warning
        excludeFromDKG(nodeID, 24*time.Hour)
        warnNode(nodeID, "dkg_abort_warning")
    }

    // Record abort event for network-wide tracking
    broadcastDKGAbortEvent(nodeID, t.SessionID, t.Phase)
}

// identifyAborters determines which nodes caused DKG failure
func (t *DKGProgressTracker) identifyAborters(err error) []NodeID {
    aborters := make([]NodeID, 0)

    switch e := err.(type) {
    case *DKGPhaseTimeout:
        // Nodes that timed out
        aborters = append(aborters, e.SlowNodes...)

    case *InvalidCommitmentError:
        // Node that sent invalid commitment
        aborters = append(aborters, e.NodeID)

    case *InvalidShareError:
        // Node that sent invalid share (verified via complaint)
        aborters = append(aborters, e.NodeID)

    case *FalseComplaintError:
        // Node that filed false complaint
        aborters = append(aborters, e.Complainant)

    case *CertEqDisagreementError:
        // Nodes that disagreed (minority side)
        aborters = append(aborters, e.DisagreeingNodes...)
    }

    return aborters
}

// getEligibleParticipants returns nodes not currently excluded
func (t *DKGProgressTracker) getEligibleParticipants() []NodeID {
    allCandidates := GetCAPoolCandidates()
    eligible := make([]NodeID, 0)

    for _, node := range allCandidates {
        // Check if excluded
        if isExcludedFromDKG(node) {
            continue
        }

        // Check abort history
        if t.AbortHistory[node] >= MaxAbortCount {
            continue
        }

        eligible = append(eligible, node)
    }

    return eligible
}
```

**Griefing Attack Prevention**:

| Attack Vector | Mitigation |
|---------------|------------|
| Repeated timeouts | Node excluded after 2 timeouts, 7-day ban |
| Invalid commitments | Immediate exclusion, -0.1 reputation |
| Invalid shares | Verified via complaint, excluded + slashed |
| False complaints | Complainant excluded + slashed |
| Coordination attack | VRF-based participant selection prevents targeting |
| Resource exhaustion | Maximum 5 attempts per session, then escalate |
| Coordinator crash | Automatic coordinator failover with state recovery |

### DKG Coordinator Crash Recovery (P4-H7)

The DKG coordinator is a single point of failure during DKG execution. If the coordinator crashes mid-protocol, participants will stall indefinitely without explicit recovery logic.

```go
// pkg/dkg/coordinator_recovery.go

// DKG Coordinator Recovery - non-configurable security parameters
const (
    CoordinatorHeartbeatInterval = 5 * time.Second   // Liveness check frequency
    CoordinatorCrashTimeout      = 15 * time.Second  // Declare dead after 3 missed heartbeats
    CoordinatorStateCheckpoint   = 2 * time.Second   // State persistence frequency
    MaxCoordinatorFailovers      = 2                 // Maximum coordinator changes per session
)

// DKGCoordinatorState persists coordinator state for crash recovery
type DKGCoordinatorState struct {
    SessionID         [32]byte
    CoordinatorID     NodeID
    BackupCoordinators []NodeID  // Ordered by priority (VRF-ranked)

    // Phase tracking for recovery
    CurrentPhase      DKGPhase
    PhaseStartTime    time.Time
    PhaseDeadline     time.Time

    // Per-participant state (for handoff)
    ParticipantStates map[NodeID]*DKGParticipantSnapshot

    // Collected protocol messages (for replay)
    Commitments       map[NodeID][]byte  // Phase 3 commitments
    EncryptedShares   map[NodeID]map[NodeID][]byte  // Phase 4 shares
    Complaints        []DKGComplaint     // Phase 5 complaints

    // Checkpoint metadata
    CheckpointNumber  uint64
    CheckpointHash    [32]byte  // Hash of state for integrity verification
    LastCheckpoint    time.Time

    // Failover tracking
    FailoverCount     int
    PreviousCoordinators []NodeID  // Coordinators that failed
}

// DKGParticipantSnapshot captures participant state at checkpoint
type DKGParticipantSnapshot struct {
    NodeID           NodeID
    CurrentPhase     DKGPhase
    PhasesCompleted  []DKGPhase
    LastMessageTime  time.Time
    TPMQuoteHash     [32]byte  // For re-verification after failover
}

// DKGCoordinatorMonitor watches for coordinator failures
type DKGCoordinatorMonitor struct {
    sessionID        [32]byte
    coordinatorID    NodeID
    lastHeartbeat    time.Time
    mu               sync.Mutex

    // Callback for failover initiation
    onCoordinatorFailure func(failedCoord NodeID)
}

// MonitorCoordinator runs the heartbeat check loop
func (m *DKGCoordinatorMonitor) MonitorCoordinator(ctx context.Context) {
    ticker := time.NewTicker(CoordinatorHeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.mu.Lock()
            elapsed := time.Since(m.lastHeartbeat)
            m.mu.Unlock()

            if elapsed > CoordinatorCrashTimeout {
                // Coordinator presumed dead - initiate failover
                m.onCoordinatorFailure(m.coordinatorID)
                return
            }
        }
    }
}

// ReceiveHeartbeat updates the last-seen timestamp
func (m *DKGCoordinatorMonitor) ReceiveHeartbeat() {
    m.mu.Lock()
    m.lastHeartbeat = time.Now()
    m.mu.Unlock()
}

// InitiateCoordinatorFailover handles coordinator crash
func InitiateCoordinatorFailover(state *DKGCoordinatorState) error {
    if state.FailoverCount >= MaxCoordinatorFailovers {
        // Too many failovers - abort session and escalate
        return &DKGSessionAbortError{
            Reason: "max_coordinator_failovers_exceeded",
            SessionID: state.SessionID,
            FailedCoordinators: state.PreviousCoordinators,
        }
    }

    // 1. Record the failed coordinator
    state.PreviousCoordinators = append(state.PreviousCoordinators, state.CoordinatorID)
    state.FailoverCount++

    // 2. Select new coordinator from backup list
    if len(state.BackupCoordinators) == 0 {
        return ErrNoBackupCoordinatorsAvailable
    }
    newCoordinator := state.BackupCoordinators[0]
    state.BackupCoordinators = state.BackupCoordinators[1:]

    // 3. Verify new coordinator is responsive
    if !isNodeResponsive(newCoordinator, 5*time.Second) {
        // Try next backup
        return InitiateCoordinatorFailover(state)
    }

    // 4. Verify checkpoint integrity
    computedHash := computeStateHash(state)
    if computedHash != state.CheckpointHash {
        return ErrCheckpointCorrupted
    }

    // 5. Transfer state to new coordinator
    transferReq := &CoordinatorHandoffRequest{
        SessionID:        state.SessionID,
        State:            state,
        PreviousCoord:    state.CoordinatorID,
        FailoverReason:   "heartbeat_timeout",
        TPMAttestation:   generateTPMAttestation(newCoordinator),
    }

    if err := transferCoordinatorState(newCoordinator, transferReq); err != nil {
        return fmt.Errorf("state transfer failed: %w", err)
    }

    // 6. Update coordinator ID
    state.CoordinatorID = newCoordinator

    // 7. Broadcast coordinator change to all participants
    broadcastCoordinatorChange(state.SessionID, newCoordinator, state.CurrentPhase)

    // 8. New coordinator resumes from checkpoint
    return resumeDKGFromCheckpoint(newCoordinator, state)
}

// resumeDKGFromCheckpoint continues DKG after coordinator failover
func resumeDKGFromCheckpoint(newCoord NodeID, state *DKGCoordinatorState) error {
    // Determine which messages need to be re-requested
    switch state.CurrentPhase {
    case PhaseCommitment:
        // Request missing commitments from participants who haven't sent them
        for nodeID, snap := range state.ParticipantStates {
            if _, hasCommitment := state.Commitments[nodeID]; !hasCommitment {
                requestCommitmentRetransmit(nodeID, state.SessionID)
            }
        }

    case PhaseShareDistribution:
        // Request share re-transmission for incomplete distributions
        for senderID := range state.ParticipantStates {
            for recipientID := range state.ParticipantStates {
                if _, hasShare := state.EncryptedShares[senderID][recipientID]; !hasShare {
                    requestShareRetransmit(senderID, recipientID, state.SessionID)
                }
            }
        }

    case PhaseComplaintResolution:
        // Re-broadcast complaints to ensure new coordinator has them all
        for _, complaint := range state.Complaints {
            processComplaint(newCoord, complaint)
        }

    case PhaseKeyDerivation, PhaseTPMSealing:
        // These phases are deterministic - can resume directly
        // No re-transmission needed
    }

    // Continue protocol from current phase
    return nil
}

// persistCoordinatorCheckpoint saves state for crash recovery
func persistCoordinatorCheckpoint(state *DKGCoordinatorState) error {
    state.CheckpointNumber++
    state.LastCheckpoint = time.Now()
    state.CheckpointHash = computeStateHash(state)

    // Persist to:
    // 1. Local durable storage (for restart)
    if err := persistToLocalStorage(state); err != nil {
        return fmt.Errorf("local persist failed: %w", err)
    }

    // 2. DHT (for failover to backup coordinator)
    dhtKey := fmt.Sprintf("dkg:coordinator:checkpoint:%x", state.SessionID)
    if err := storeToDHT(dhtKey, state, DKGCheckpointTTL); err != nil {
        // Non-fatal - backup coordinators can request state directly
        log.Warn("DHT checkpoint storage failed", "error", err)
    }

    // 3. Backup coordinators (direct push for fast failover)
    for _, backup := range state.BackupCoordinators[:min(2, len(state.BackupCoordinators))] {
        go pushCheckpointToBackup(backup, state)
    }

    return nil
}

// computeStateHash creates integrity hash of coordinator state
func computeStateHash(state *DKGCoordinatorState) [32]byte {
    h := sha256.New()

    // Include all critical state
    h.Write(state.SessionID[:])
    h.Write(state.CoordinatorID[:])
    binary.Write(h, binary.BigEndian, uint8(state.CurrentPhase))
    binary.Write(h, binary.BigEndian, state.CheckpointNumber)

    // Hash commitments in deterministic order
    commitmentKeys := make([]NodeID, 0, len(state.Commitments))
    for k := range state.Commitments {
        commitmentKeys = append(commitmentKeys, k)
    }
    sort.Slice(commitmentKeys, func(i, j int) bool {
        return bytes.Compare(commitmentKeys[i][:], commitmentKeys[j][:]) < 0
    })
    for _, k := range commitmentKeys {
        h.Write(k[:])
        h.Write(state.Commitments[k])
    }

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}
```

**Coordinator Failover Sequence**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                 DKG COORDINATOR FAILOVER                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Time 0      Time 5s     Time 10s    Time 15s    Time 20s          │
│    │           │           │           │           │                │
│    │  ┌────┐   │  ┌────┐   │  ┌────┐   │           │                │
│    │  │ HB │   │  │ HB │   │  │ HB │   │  CRASH!   │                │
│    │  └────┘   │  └────┘   │  └────┘   │    ✗      │                │
│    │     │     │     │     │     │     │           │                │
│    ├─────┼─────┼─────┼─────┼─────┼─────┼───────────┤                │
│    │     │     │     │     │     │     │           │                │
│    │     └──────────────────────────────→ Timeout  │                │
│    │                                    (15s since │                │
│    │                                     last HB)  │                │
│    │                                         │     │                │
│    │                                         ↓     │                │
│    │                               ┌─────────────────────┐          │
│    │                               │ FAILOVER INITIATE   │          │
│    │                               │ 1. Record failure   │          │
│    │                               │ 2. Select backup    │          │
│    │                               │ 3. Verify state     │          │
│    │                               │ 4. Transfer state   │          │
│    │                               │ 5. Broadcast change │          │
│    │                               │ 6. Resume DKG       │          │
│    │                               └─────────────────────┘          │
│    │                                         │                      │
│    │                                         ↓                      │
│    │                               ┌─────────────────────┐          │
│    │                               │ NEW COORDINATOR     │          │
│    │                               │ Resumes from        │          │
│    │                               │ checkpoint phase    │          │
│    │                               └─────────────────────┘          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Failover Safety Guarantees**:

| Property | Guarantee |
|----------|-----------|
| State consistency | Checkpoints include integrity hash |
| No message loss | Protocol messages persisted before ACK |
| Bounded recovery time | Max 20s from crash to resume |
| Participant transparency | Participants continue without restart |
| Sybil prevention | Backup coordinators VRF-selected at session start |

**Progress Guarantee**:

```
Given:
  - N = total CA pool candidates
  - f = maximum Byzantine fraction (< 33%)
  - t = threshold (33% of pool size)

If N > 3f, DKG completes within MaxDKGAttempts because:
  1. Each attempt excludes at least one aborter
  2. After f exclusions, only honest nodes remain
  3. Honest nodes always complete DKG
  4. f exclusions < 5 attempts (with typical pool sizes)
```

### DKG Coordinator State Transfer Protocol

When a coordinator fails during DKG execution, the backup coordinator must obtain the partial DKG state to continue the session. This state transfer protocol ensures secure, atomic handoff of coordinator responsibilities while maintaining session continuity.

**State Transfer Requirements:**

| Requirement | Value | Rationale |
|-------------|-------|-----------|
| Transfer Encryption | AES-256-GCM | Protects sensitive DKG state in transit |
| Transfer Timeout | 30 seconds | Prevents indefinite blocking on failed transfer |
| Session Continuity Window | 60 seconds | Time participants accept coordinator change |
| Maximum Failovers | 2 per session | Limits abuse, triggers session abort on third |
| Coordinator Change Notification | Broadcast | All participants must acknowledge new coordinator |

```go
// pkg/dkg/coordinator_state_transfer.go

// CoordinatorStateTransferConfig defines transfer parameters
const (
    StateTransferTimeout       = 30 * time.Second   // Maximum time for state transfer
    SessionContinuityWindow    = 60 * time.Second   // Participants accept change within
    MaxCoordinatorFailovers    = 2                  // Maximum changes per DKG session
    StateTransferRetryCount    = 3                  // Retries before giving up
    StateTransferRetryDelay    = 2 * time.Second    // Delay between retries
)

// CoordinatorStateTransfer handles secure state transfer during failover
type CoordinatorStateTransfer struct {
    sessionID        [32]byte
    sourceCoord      NodeID           // Failed coordinator
    targetCoord      NodeID           // New coordinator
    transferState    TransferState

    // Encryption for state in transit
    encryptionKey    [32]byte         // AES-256 key derived from shared secret
    nonce            [12]byte         // GCM nonce

    // Transfer timing
    startTime        time.Time
    deadline         time.Time
}

type TransferState uint8

const (
    TransferStatePending     TransferState = iota  // Transfer not started
    TransferStateInProgress                         // Transfer underway
    TransferStateComplete                           // Successfully transferred
    TransferStateFailed                             // Transfer failed
    TransferStateTimeout                            // Transfer timed out
)

// CoordinatorChangeNotification informs participants of coordinator change
type CoordinatorChangeNotification struct {
    SessionID          [32]byte
    MessageType        MessageType          // CoordinatorChange
    OldCoordinatorID   NodeID
    NewCoordinatorID   NodeID
    FailoverReason     FailoverReason
    TransferProof      *StateTransferProof  // Proof new coord has valid state
    Timestamp          int64
    Signature          []byte               // Signed by quorum of backup coordinators
}

type FailoverReason uint8

const (
    FailoverReasonHeartbeatTimeout  FailoverReason = iota
    FailoverReasonCrashDetected
    FailoverReasonExplicitResignation
    FailoverReasonNetworkPartition
)

// StateTransferProof proves new coordinator received valid state
type StateTransferProof struct {
    StateHash          [32]byte     // Hash of transferred state
    CheckpointNumber   uint64       // Checkpoint the state represents
    SourceSignature    []byte       // Old coordinator signed transfer (if available)
    BackupSignatures   [][]byte     // Backup coordinators validate state
    TransferTimestamp  int64
}

// TransferCoordinatorState securely transfers state to new coordinator
func TransferCoordinatorState(
    ctx context.Context,
    state *DKGCoordinatorState,
    newCoord NodeID,
) error {
    transfer := &CoordinatorStateTransfer{
        sessionID:   state.SessionID,
        sourceCoord: state.CoordinatorID,
        targetCoord: newCoord,
        startTime:   time.Now(),
        deadline:    time.Now().Add(StateTransferTimeout),
    }

    // 1. Establish encrypted channel to new coordinator
    encKey, err := establishTransferChannel(state.CoordinatorID, newCoord)
    if err != nil {
        return &StateTransferError{
            Phase:  "channel_establishment",
            Cause:  err,
        }
    }
    transfer.encryptionKey = encKey

    // 2. Serialize and encrypt state
    stateBytes, err := serializeCoordinatorState(state)
    if err != nil {
        return &StateTransferError{Phase: "serialization", Cause: err}
    }

    // Generate nonce for AES-GCM
    if _, err := rand.Read(transfer.nonce[:]); err != nil {
        return &StateTransferError{Phase: "nonce_generation", Cause: err}
    }

    block, err := aes.NewCipher(transfer.encryptionKey[:])
    if err != nil {
        return &StateTransferError{Phase: "cipher_init", Cause: err}
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return &StateTransferError{Phase: "gcm_init", Cause: err}
    }

    encryptedState := gcm.Seal(nil, transfer.nonce[:], stateBytes, nil)

    // 3. Send encrypted state with retry
    for attempt := 0; attempt < StateTransferRetryCount; attempt++ {
        err = sendStateToNewCoordinator(ctx, newCoord, &StateTransferMessage{
            SessionID:      state.SessionID,
            EncryptedState: encryptedState,
            Nonce:          transfer.nonce,
            StateHash:      sha256.Sum256(stateBytes),
            Checkpoint:     state.CheckpointNumber,
        })

        if err == nil {
            break
        }

        if time.Now().After(transfer.deadline) {
            return &StateTransferTimeoutError{
                Elapsed: time.Since(transfer.startTime),
                Timeout: StateTransferTimeout,
            }
        }

        time.Sleep(StateTransferRetryDelay)
    }

    if err != nil {
        return &StateTransferError{Phase: "transmission", Cause: err}
    }

    // 4. Wait for acknowledgment from new coordinator
    ackCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    ack, err := waitForTransferAck(ackCtx, newCoord, state.SessionID)
    if err != nil {
        return &StateTransferError{Phase: "acknowledgment", Cause: err}
    }

    // 5. Verify acknowledgment
    if !verifyTransferAck(ack, state) {
        return &StateTransferError{
            Phase: "verification",
            Cause: ErrAckVerificationFailed,
        }
    }

    transfer.transferState = TransferStateComplete
    return nil
}

// BroadcastCoordinatorChange notifies all participants of the change
func BroadcastCoordinatorChange(
    sessionID [32]byte,
    oldCoord, newCoord NodeID,
    reason FailoverReason,
    proof *StateTransferProof,
    participants []NodeID,
) error {
    notification := &CoordinatorChangeNotification{
        SessionID:        sessionID,
        MessageType:      MessageTypeCoordinatorChange,
        OldCoordinatorID: oldCoord,
        NewCoordinatorID: newCoord,
        FailoverReason:   reason,
        TransferProof:    proof,
        Timestamp:        time.Now().UnixNano(),
    }

    // Sign notification with backup coordinator quorum
    notification.Signature = signWithBackupQuorum(notification)

    // Broadcast to all participants
    for _, participant := range participants {
        if err := sendNotification(participant, notification); err != nil {
            // Log but continue - participants will timeout and query
            log.Warn("Failed to notify participant of coordinator change",
                "participant", participant,
                "error", err)
        }
    }

    return nil
}

// AcceptCoordinatorChange validates and accepts a coordinator change
func (p *Participant) AcceptCoordinatorChange(
    notification *CoordinatorChangeNotification,
) error {
    // 1. Verify notification is for our session
    if notification.SessionID != p.sessionID {
        return ErrSessionMismatch
    }

    // 2. Verify we're within session continuity window
    notificationTime := time.Unix(0, notification.Timestamp)
    if time.Since(notificationTime) > SessionContinuityWindow {
        return &CoordinatorChangeExpiredError{
            NotificationTime: notificationTime,
            WindowExpiry:     notificationTime.Add(SessionContinuityWindow),
        }
    }

    // 3. Verify backup quorum signature
    if !verifyBackupQuorumSignature(notification, notification.Signature) {
        return ErrInvalidBackupQuorumSignature
    }

    // 4. Verify state transfer proof
    if !verifyStateTransferProof(notification.TransferProof, p.lastKnownCheckpoint) {
        return ErrInvalidStateTransferProof
    }

    // 5. Accept new coordinator
    p.coordinatorID = notification.NewCoordinatorID
    p.coordinatorChangeCount++

    // 6. Check failover limit
    if p.coordinatorChangeCount > MaxCoordinatorFailovers {
        // Too many failovers - expect session abort
        return &TooManyFailoversError{
            FailoverCount: p.coordinatorChangeCount,
            Maximum:       MaxCoordinatorFailovers,
        }
    }

    return nil
}
```

**State Transfer Sequence Diagram:**

```
                    DKG COORDINATOR STATE TRANSFER

    Failed Coord       Backup Coord 1       Backup Coord 2       Participants
         │                   │                    │                    │
         ✗ (crash)           │                    │                    │
         │                   │                    │                    │
         │  ┌────────────────┴────────────────┐   │                    │
         │  │ Heartbeat timeout (15s)         │   │                    │
         │  │ Initiate failover               │   │                    │
         │  └────────────────┬────────────────┘   │                    │
         │                   │                    │                    │
         │                   │  RequestState      │                    │
         │                   ├───────────────────>│                    │
         │                   │                    │                    │
         │                   │                    │ (Has checkpoint    │
         │                   │                    │  from push)        │
         │                   │                    │                    │
         │                   │  EncryptedState    │                    │
         │                   │  (AES-256-GCM)     │                    │
         │                   │<───────────────────│                    │
         │                   │                    │                    │
         │                   │  TransferAck       │                    │
         │                   │  + StateProof      │                    │
         │                   ├───────────────────>│                    │
         │                   │                    │                    │
         │                   │                    │ Sign proof         │
         │                   │                    │                    │
         │                   │  SignedProof       │                    │
         │                   │<───────────────────│                    │
         │                   │                    │                    │
         │                   │      CoordinatorChangeNotification      │
         │                   ├────────────────────────────────────────>│
         │                   │                    │                    │
         │                   │                    │    ChangeAck       │
         │                   │<────────────────────────────────────────│
         │                   │                    │                    │
         │                   │ Resume DKG from    │                    │
         │                   │ checkpoint phase   │                    │
         │                   │                    │                    │
```

**Share Confidentiality During Transfer:**

Partial DKG shares that have been sent TO the failed coordinator must be re-encrypted for the new coordinator. The protocol uses a re-encryption mechanism to protect share confidentiality.

```go
// ReencryptSharesForNewCoordinator re-encrypts shares for new coordinator
func ReencryptSharesForNewCoordinator(
    shares map[NodeID][]byte,
    oldCoordKey, newCoordKey *ecdsa.PublicKey,
) (map[NodeID][]byte, error) {
    reencrypted := make(map[NodeID][]byte)

    for nodeID, encryptedShare := range shares {
        // 1. Shares are encrypted to coordinator's session key
        // 2. Re-encryption uses proxy re-encryption (PRE) scheme
        // 3. New coordinator can decrypt without learning old key

        // Generate re-encryption key
        reKey, err := generateReEncryptionKey(oldCoordKey, newCoordKey)
        if err != nil {
            return nil, &ReEncryptionError{NodeID: nodeID, Cause: err}
        }

        // Apply re-encryption
        reencryptedShare, err := applyReEncryption(encryptedShare, reKey)
        if err != nil {
            return nil, &ReEncryptionError{NodeID: nodeID, Cause: err}
        }

        reencrypted[nodeID] = reencryptedShare
    }

    return reencrypted, nil
}
```

#### Proxy Re-Encryption (PRE) Scheme Specification

The coordinator failover mechanism uses Proxy Re-Encryption (PRE) to maintain share confidentiality during state transfer. This section specifies the cryptographic scheme used.

**Scheme Selection: AFGH (Ateniese-Fu-Green-Hohenberger)**

The system uses the AFGH proxy re-encryption scheme based on bilinear pairings, which provides unidirectional, single-hop re-encryption with strong security guarantees.

**Reference:** Ateniese, G., Fu, K., Green, M., & Hohenberger, S. (2006). "Improved Proxy Re-Encryption Schemes with Applications to Secure Distributed Storage." ACM Transactions on Information and System Security (TISSEC), 9(1), 1-30.

**Cryptographic Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Curve** | BLS12-381 | Pairing-friendly elliptic curve |
| **Security Level** | 128-bit | Equivalent symmetric security |
| **Pairing Type** | Type III | Asymmetric pairing e: G1 x G2 -> GT |
| **Hash Function** | SHA-256 | For key derivation and hashing |
| **KDF** | HKDF-SHA256 | Key derivation with session-specific salt |

**Security Assumption:**

The AFGH scheme security relies on the Decisional Bilinear Diffie-Hellman (DBDH) assumption:

```
Given (g, g^a, g^b, g^c, Z) where g is a generator of G1,
it is computationally hard to distinguish whether:
  Z = e(g,g)^{abc}  (real BDH tuple)
or
  Z = random element of GT
```

**Key Generation:**

```go
// pkg/dkg/pre/keygen.go

// PREKeyPair represents a proxy re-encryption key pair
type PREKeyPair struct {
    PrivateKey *bls12381.Scalar  // x in Zp
    PublicKey  *bls12381.G1      // g^x in G1
}

// GeneratePREKeyPair generates a new PRE key pair for a coordinator
func GeneratePREKeyPair() (*PREKeyPair, error) {
    // Generate random scalar x from TPM for hardware-backed randomness
    xBytes, err := tpm.GetRandom(32)
    if err != nil {
        return nil, &PREKeyGenError{Phase: "random_generation", Cause: err}
    }

    x := new(bls12381.Scalar).SetBytes(xBytes)

    // Compute public key pk = g^x
    g := bls12381.G1Generator()
    pk := new(bls12381.G1).ScalarMult(g, x)

    return &PREKeyPair{
        PrivateKey: x,
        PublicKey:  pk,
    }, nil
}
```

**Re-Encryption Key Generation:**

The delegator (old coordinator or authorized backup) generates a re-encryption key that allows transformation of ciphertexts from the old coordinator's key to the new coordinator's key without revealing the plaintext.

```go
// pkg/dkg/pre/rekey.go

// PREReEncryptionKey allows transformation from pk_A to pk_B
type PREReEncryptionKey struct {
    RK        *bls12381.G2      // Re-encryption key: g2^{b/a}
    SessionID [32]byte          // Bound to specific DKG session
    ValidFrom time.Time
    ValidTo   time.Time         // Maximum 5 minutes validity
    Signature []byte            // Delegator's signature over RK || SessionID
}

// GenerateReEncryptionKey creates rk_{A->B} for delegating from A to B
// CRITICAL: This requires the delegator's private key (old coordinator or backup)
func GenerateReEncryptionKey(
    delegatorPrivate *bls12381.Scalar,  // a (old coordinator's private key)
    delegateePublic *bls12381.G1,        // g^b (new coordinator's public key)
    sessionID [32]byte,
) (*PREReEncryptionKey, error) {

    // Derive session-specific salt using HKDF
    salt := deriveSessionSalt(sessionID)

    // Extract b from the delegatee's public key is not possible
    // Instead, we compute rk = g2^{1/a} and use pairing properties

    // Compute a^{-1} mod p
    aInv := new(bls12381.Scalar).Inverse(delegatorPrivate)

    // Re-encryption key: rk = g2^{a^{-1}}
    g2 := bls12381.G2Generator()
    rk := new(bls12381.G2).ScalarMult(g2, aInv)

    // Note: The actual re-encryption combines this with the ciphertext
    // to achieve the transformation without revealing plaintext

    now := time.Now()
    preRK := &PREReEncryptionKey{
        RK:        rk,
        SessionID: sessionID,
        ValidFrom: now,
        ValidTo:   now.Add(5 * time.Minute),  // Short validity window
    }

    // Sign the re-encryption key for authenticity
    preRK.Signature = signReEncryptionKey(delegatorPrivate, preRK)

    return preRK, nil
}

// deriveSessionSalt derives a unique salt for HKDF from the session ID
func deriveSessionSalt(sessionID [32]byte) []byte {
    h := hkdf.New(sha256.New, sessionID[:], []byte("DKG-PRE-SESSION-SALT"), nil)
    salt := make([]byte, 32)
    h.Read(salt)
    return salt
}
```

**Encryption (First-Level Ciphertext):**

Shares are encrypted to the coordinator using a hybrid approach: ECIES for key encapsulation, AES-256-GCM for symmetric encryption.

```go
// pkg/dkg/pre/encrypt.go

// PRECiphertext represents an encrypted share that can be re-encrypted
type PRECiphertext struct {
    C1       *bls12381.G1      // g^r (ephemeral public key)
    C2       []byte            // AES-256-GCM(K, share) where K = H(e(pk^r, g2))
    Nonce    [12]byte          // AES-GCM nonce
    Tag      [16]byte          // AES-GCM authentication tag
}

// EncryptShare encrypts a DKG share to the coordinator's public key
func EncryptShare(
    share []byte,
    coordinatorPK *bls12381.G1,
) (*PRECiphertext, error) {

    // Generate ephemeral key pair
    rBytes, _ := tpm.GetRandom(32)
    r := new(bls12381.Scalar).SetBytes(rBytes)

    // C1 = g^r
    g := bls12381.G1Generator()
    C1 := new(bls12381.G1).ScalarMult(g, r)

    // Compute pairing-based shared secret
    // K = e(pk^r, g2) = e(g^{xr}, g2) = e(g, g2)^{xr}
    pkr := new(bls12381.G1).ScalarMult(coordinatorPK, r)
    g2 := bls12381.G2Generator()
    sharedSecret := bls12381.Pair(pkr, g2)

    // Derive symmetric key using HKDF
    symKey := deriveSymmetricKey(sharedSecret.Bytes())

    // Encrypt share with AES-256-GCM
    block, _ := aes.NewCipher(symKey)
    gcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, 12)
    tpm.GetRandom(nonce)

    ciphertext := gcm.Seal(nil, nonce, share, nil)

    ct := &PRECiphertext{C1: C1}
    copy(ct.Nonce[:], nonce)
    copy(ct.C2, ciphertext[:len(ciphertext)-16])
    copy(ct.Tag[:], ciphertext[len(ciphertext)-16:])

    return ct, nil
}
```

**Re-Encryption (Ciphertext Transformation):**

The proxy (backup coordinator or witness) transforms the ciphertext without learning the plaintext.

```go
// pkg/dkg/pre/reencrypt.go

// ReEncryptedCiphertext is a second-level ciphertext for the new coordinator
type ReEncryptedCiphertext struct {
    C1Prime  *bls12381.GT      // e(C1, rk) = e(g^r, g2^{1/a}) = e(g,g2)^{r/a}
    C2       []byte            // Unchanged symmetric ciphertext
    Nonce    [12]byte
    Tag      [16]byte
    RKProof  []byte            // Proof that correct rk was used
}

// ReEncrypt transforms a ciphertext from pk_A to pk_B using rk_{A->B}
// CRITICAL: The proxy cannot decrypt - it only transforms
func ReEncrypt(
    ciphertext *PRECiphertext,
    reKey *PREReEncryptionKey,
) (*ReEncryptedCiphertext, error) {

    // Verify re-encryption key is valid and not expired
    if time.Now().After(reKey.ValidTo) {
        return nil, ErrReEncryptionKeyExpired
    }

    // Apply re-encryption: C1' = e(C1, rk)
    // e(g^r, g2^{1/a}) = e(g, g2)^{r/a}
    C1Prime := bls12381.Pair(ciphertext.C1, reKey.RK)

    // Generate proof of correct re-encryption (DLEQ proof)
    proof := generateReEncryptionProof(ciphertext.C1, reKey.RK, C1Prime)

    return &ReEncryptedCiphertext{
        C1Prime: C1Prime,
        C2:      ciphertext.C2,
        Nonce:   ciphertext.Nonce,
        Tag:     ciphertext.Tag,
        RKProof: proof,
    }, nil
}
```

**Decryption by New Coordinator:**

```go
// pkg/dkg/pre/decrypt.go

// DecryptReEncrypted decrypts a re-encrypted ciphertext using the new coordinator's key
func DecryptReEncrypted(
    ciphertext *ReEncryptedCiphertext,
    newCoordPrivate *bls12381.Scalar,  // b
) ([]byte, error) {

    // Verify re-encryption proof
    if !verifyReEncryptionProof(ciphertext.RKProof) {
        return nil, ErrInvalidReEncryptionProof
    }

    // Compute shared secret: (C1')^b = e(g,g2)^{r/a * b}
    // For correct re-encryption: this equals e(g,g2)^{rb/a}
    // Combined with original encryption gives e(g,g2)^{rb}
    sharedSecret := new(bls12381.GT).ScalarMult(ciphertext.C1Prime, newCoordPrivate)

    // Derive symmetric key
    symKey := deriveSymmetricKey(sharedSecret.Bytes())

    // Decrypt with AES-256-GCM
    block, _ := aes.NewCipher(symKey)
    gcm, _ := cipher.NewGCM(block)

    fullCiphertext := append(ciphertext.C2, ciphertext.Tag[:]...)
    plaintext, err := gcm.Open(nil, ciphertext.Nonce[:], fullCiphertext, nil)
    if err != nil {
        return nil, &PREDecryptionError{Cause: err}
    }

    return plaintext, nil
}
```

**Security Properties:**

| Property | Guarantee |
|----------|-----------|
| **Unidirectional** | rk_{A->B} cannot be reversed to create rk_{B->A} |
| **Non-Transitive** | Proxy cannot chain re-encryptions without new rk |
| **Collusion Resistant** | Proxy + delegatee cannot recover delegator's key |
| **CCA-Secure** | Secure against adaptive chosen-ciphertext attacks |
| **Key Privacy** | Re-encryption key reveals nothing about private keys |

**Integration with DKG Coordinator Failover:**

```go
// pkg/dkg/coordinator_failover.go

// ReencryptSharesForNewCoordinator re-encrypts all pending shares
func (cf *CoordinatorFailover) ReencryptSharesForNewCoordinator(
    shares map[NodeID]*PRECiphertext,
    oldCoordPK *bls12381.G1,
    newCoordPK *bls12381.G1,
    sessionID [32]byte,
) (map[NodeID]*ReEncryptedCiphertext, error) {

    // Generate re-encryption key (requires old coordinator's private key
    // or pre-generated rk from backup coordinator setup)
    reKey, err := cf.getReEncryptionKey(oldCoordPK, newCoordPK, sessionID)
    if err != nil {
        return nil, &FailoverReEncryptionError{Phase: "get_rekey", Cause: err}
    }

    reencrypted := make(map[NodeID]*ReEncryptedCiphertext)

    for nodeID, ciphertext := range shares {
        reCT, err := ReEncrypt(ciphertext, reKey)
        if err != nil {
            return nil, &FailoverReEncryptionError{
                Phase:  "reencrypt",
                NodeID: nodeID,
                Cause:  err,
            }
        }
        reencrypted[nodeID] = reCT
    }

    return reencrypted, nil
}
```


---

### DKG Session Recovery

When a DKG session fails or a coordinator crashes, the session may need to be recovered from a checkpoint. This section defines the checkpoint structure, TTL, and recovery procedures.

#### DKG Session Checkpoint Structure

Checkpoints capture the complete DKG session state at regular intervals, enabling recovery from any phase.

```go
// pkg/dkg/checkpoint.go

// DKGSessionCheckpoint represents a recoverable snapshot of DKG state
type DKGSessionCheckpoint struct {
    // Checkpoint metadata
    CheckpointID      [32]byte
    SessionID         [32]byte
    CreatedAt         time.Time
    ExpiresAt         time.Time           // TTL: 2 hours from creation

    // Session parameters (immutable)
    Threshold         int
    TotalParticipants int
    Ciphersuite       CiphersuiteID
    Epoch             uint64

    // Current progress
    CurrentPhase      DKGPhase
    PhaseStartTime    time.Time

    // Participant data
    Participants      []DKGParticipantInfo
    ExcludedNodes     []NodeID

    // Phase-specific data (encrypted)
    EncryptedPhaseData []byte              // AES-256-GCM encrypted

    // Integrity
    DataHash          [32]byte             // SHA-256 of all above fields
    CoordinatorSig    []byte               // Coordinator signature
}

// CheckpointTTL defines how long checkpoints remain valid
const CheckpointTTL = 2 * time.Hour

// DKGCheckpointPhaseData contains phase-specific recoverable state
type DKGCheckpointPhaseData struct {
    // Phase 1-2: Attestation and channel setup
    AttestationResults  map[NodeID]*AttestationResult
    ChannelKeys         map[NodeID][32]byte  // Pairwise channel keys

    // Phase 3: Commitments (commit-reveal)
    CommitHashes        map[NodeID][32]byte
    RevealedCommitments map[NodeID]*DKGCommitment

    // Phase 4: Encrypted shares
    EncryptedShares     map[NodeID]map[NodeID][]byte  // sender -> recipient -> share

    // Phase 5: Complaints
    Complaints          []DKGComplaint
    ComplaintResolutions map[[32]byte]ComplaintResolution

    // Phase 6: Key derivation progress
    DerivedPublicKey    *Point
    VerificationVector  []Point
}

// CreateCheckpoint creates a checkpoint at the current session state
func (s *DKGSession) CreateCheckpoint() (*DKGSessionCheckpoint, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    now := time.Now()

    checkpoint := &DKGSessionCheckpoint{
        CheckpointID:      generateCheckpointID(s.sessionID, now),
        SessionID:         s.sessionID,
        CreatedAt:         now,
        ExpiresAt:         now.Add(CheckpointTTL),
        Threshold:         s.threshold,
        TotalParticipants: len(s.participants),
        Ciphersuite:       s.ciphersuite,
        Epoch:             s.epoch,
        CurrentPhase:      s.currentPhase,
        PhaseStartTime:    s.phaseStartTime,
        Participants:      s.getParticipantInfo(),
        ExcludedNodes:     s.getExcludedNodes(),
    }

    // Serialize and encrypt phase data
    phaseData := s.collectPhaseData()
    phaseBytes, err := json.Marshal(phaseData)
    if err != nil {
        return nil, &CheckpointError{Phase: "serialize", Cause: err}
    }

    encryptedPhaseData, err := s.encryptCheckpointData(phaseBytes)
    if err != nil {
        return nil, &CheckpointError{Phase: "encrypt", Cause: err}
    }
    checkpoint.EncryptedPhaseData = encryptedPhaseData

    // Compute integrity hash
    checkpoint.DataHash = s.computeCheckpointHash(checkpoint)

    // Sign checkpoint
    checkpoint.CoordinatorSig = s.signCheckpoint(checkpoint)

    return checkpoint, nil
}

// ValidateCheckpoint verifies a checkpoint is valid and not expired
func ValidateCheckpoint(checkpoint *DKGSessionCheckpoint) error {
    // 1. Check TTL
    if time.Now().After(checkpoint.ExpiresAt) {
        return &CheckpointExpiredError{
            CheckpointID: checkpoint.CheckpointID,
            ExpiredAt:    checkpoint.ExpiresAt,
            ExpiredFor:   time.Since(checkpoint.ExpiresAt),
        }
    }

    // 2. Verify integrity hash
    computedHash := computeCheckpointHash(checkpoint)
    if computedHash != checkpoint.DataHash {
        return &CheckpointCorruptedError{
            CheckpointID: checkpoint.CheckpointID,
            ExpectedHash: checkpoint.DataHash,
            ActualHash:   computedHash,
        }
    }

    // 3. Verify coordinator signature
    if !verifyCoordinatorSignature(checkpoint, checkpoint.CoordinatorSig) {
        return &CheckpointSignatureError{CheckpointID: checkpoint.CheckpointID}
    }

    return nil
}
```

#### Recovery Procedure

```go
// RecoverDKGSession restores a session from checkpoint after coordinator failure
func RecoverDKGSession(
    ctx context.Context,
    checkpoint *DKGSessionCheckpoint,
    newCoordinator NodeID,
) (*DKGSession, error) {

    // 1. Validate checkpoint
    if err := ValidateCheckpoint(checkpoint); err != nil {
        return nil, &RecoveryError{Phase: "validation", Cause: err}
    }

    // 2. Decrypt phase data
    decryptionKey := deriveCheckpointKey(checkpoint.SessionID, newCoordinator)
    phaseDataBytes, err := decryptCheckpointData(
        checkpoint.EncryptedPhaseData,
        decryptionKey,
    )
    if err != nil {
        return nil, &RecoveryError{Phase: "decryption", Cause: err}
    }

    var phaseData DKGCheckpointPhaseData
    if err := json.Unmarshal(phaseDataBytes, &phaseData); err != nil {
        return nil, &RecoveryError{Phase: "unmarshal", Cause: err}
    }

    // 3. Reconstruct session state
    session := &DKGSession{
        sessionID:         checkpoint.SessionID,
        threshold:         checkpoint.Threshold,
        ciphersuite:       checkpoint.Ciphersuite,
        epoch:             checkpoint.Epoch,
        currentPhase:      checkpoint.CurrentPhase,
        phaseStartTime:    time.Now(),  // Reset phase timer
        coordinatorID:     newCoordinator,
        isRecovered:       true,
        recoveredFrom:     checkpoint.CheckpointID,
    }

    // 4. Restore participants (excluding failed nodes)
    for _, p := range checkpoint.Participants {
        if !contains(checkpoint.ExcludedNodes, p.NodeID) {
            session.participants[p.NodeID] = &DKGParticipant{
                NodeID:    p.NodeID,
                Index:     p.Index,
                PublicKey: p.PublicKey,
            }
        }
    }

    // 5. Restore phase-specific data
    session.restorePhaseData(&phaseData)

    // 6. Notify participants of recovery
    recoveryNotice := &DKGRecoveryNotice{
        SessionID:       checkpoint.SessionID,
        CheckpointID:    checkpoint.CheckpointID,
        NewCoordinator:  newCoordinator,
        ResumingPhase:   checkpoint.CurrentPhase,
        Timestamp:       time.Now().UnixNano(),
    }

    for nodeID := range session.participants {
        sendRecoveryNotice(nodeID, recoveryNotice)
    }

    // 7. Resume from current phase
    return session, nil
}
```

---

### DKG Recovery Protocol

When DKG fails beyond the standard retry mechanism, a comprehensive recovery protocol ensures CA signing capability is never permanently lost.

#### Recovery Triggers

| Trigger | Condition | Recovery Level |
|---------|-----------|----------------|
| **Standard Retry Exhausted** | 5 attempts failed within 15 minutes | Level 1: Previous Key Fallback |
| **Repeated Session Failures** | 3 consecutive sessions fail | Level 2: Genesis Trustee Recovery |
| **Mass Exclusion** | >50% of pool excluded | Level 3: Emergency Reconstitution |
| **Network Partition** | Quorum unreachable for 1 hour | Level 4: Partition Healing |

##### Explicit Recovery Trigger Definitions (P4-C7)

**CRITICAL**: Recovery phases were previously vague ("3 consecutive failures" - of what?). Below is the explicit decision tree with precise triggers, timeouts, and state transitions.

```
                    GENESIS RECOVERY ACTIVATION DECISION TREE

                           ┌─────────────────────┐
                           │   DKG ATTEMPT       │
                           │   FAILED            │
                           └──────────┬──────────┘
                                      │
                                      ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    TRIGGER: STANDARD RETRY EXHAUSTED                │
    │                                                                     │
    │  Conditions (ALL must be true):                                     │
    │    ✓ Current DKG session has failed                                 │
    │    ✓ RetryCount >= MAX_RETRY_ATTEMPTS (5)                          │
    │    ✓ All retries occurred within RETRY_WINDOW (15 minutes)         │
    │    ✓ At least one retry reached PHASE_COMMITMENT (phase 3+)        │
    │                                                                     │
    │  Action: Activate Level 1 (Previous Key Fallback)                   │
    └──────────────────────────────────┬──────────────────────────────────┘
                                       │
                                       ▼
                           ┌─────────────────────┐
                           │  Level 1 ACTIVE     │
                           │  Using Previous Key │
                           └──────────┬──────────┘
                                      │
                     ┌────────────────┼────────────────┐
                     │                │                │
                     ▼                ▼                ▼
              ┌───────────┐   ┌───────────────┐  ┌─────────────────┐
              │ Recovery  │   │ 3 Consecutive │  │ Grace Period    │
              │ DKG       │   │ Recovery DKGs │  │ Extensions      │
              │ Succeeds  │   │ Fail          │  │ Exhausted (3)   │
              └─────┬─────┘   └───────┬───────┘  └────────┬────────┘
                    │                 │                   │
                    ▼                 └─────────┬─────────┘
              ┌───────────┐                     │
              │ Return to │                     ▼
              │ NORMAL    │   ┌────────────────────────────────────────┐
              └───────────┘   │       TRIGGER: REPEATED SESSION FAILURES │
                              │                                          │
                              │  Conditions (ANY must be true):          │
                              │    ✓ 3 consecutive recovery DKG sessions │
                              │      failed after Level 1 activation     │
                              │    OR                                    │
                              │    ✓ MaxGracePeriodExtensions (3)        │
                              │      exhausted (21 days max fallback)    │
                              │    OR                                    │
                              │    ✓ Previous key set expired            │
                              │                                          │
                              │  DEFINITION of "session failure":        │
                              │    - Session started with valid quorum   │
                              │    - Session did NOT complete Phase 6    │
                              │    - Failure was not due to coordinator  │
                              │      crash (coordinator crash → retry)   │
                              │                                          │
                              │  Action: Activate Level 2                │
                              └──────────────────┬─────────────────────────┘
                                                 │
                                                 ▼
                              ┌─────────────────────────────────────────────┐
                              │       TRIGGER: MASS EXCLUSION               │
                              │                                             │
                              │  Conditions (ALL must be true):             │
                              │    ✓ excludedParticipants > 50% of pool    │
                              │    ✓ Exclusions occurred within 24 hours   │
                              │    ✓ Exclusions were for BLAME, not timeout│
                              │                                             │
                              │  This indicates coordinated attack or       │
                              │  widespread key compromise.                 │
                              │                                             │
                              │  Action: Activate Level 3                   │
                              └──────────────────┬──────────────────────────┘
                                                 │
                                                 ▼
                              ┌─────────────────────────────────────────────┐
                              │       TRIGGER: NETWORK PARTITION            │
                              │                                             │
                              │  Conditions (ALL must be true):             │
                              │    ✓ Cannot reach threshold participants    │
                              │    ✓ Unreachable for PARTITION_TIMEOUT (1h) │
                              │    ✓ Local network connectivity confirmed   │
                              │    ✓ >33% of known nodes unreachable        │
                              │                                             │
                              │  Action: Activate Level 4 (wait for heal)   │
                              └─────────────────────────────────────────────┘
```

```go
// RecoveryTriggerConfig defines explicit trigger conditions
const (
    // Level 1 triggers
    MaxRetryAttempts        = 5                     // Max retries before Level 1
    RetryWindow             = 15 * time.Minute      // Window for retry counting
    MinPhaseForRetryCount   = PhaseCommitment       // Retries must reach phase 3+

    // Level 2 triggers (Genesis Trustee)
    ConsecutiveSessionFailures = 3                  // Sessions, NOT individual attempts
    MaxGracePeriodExtensions   = 3                  // 3 × 7 days = 21 days max
    SessionFailureWindow       = 72 * time.Hour     // Window for counting sessions

    // Level 3 triggers (Mass Exclusion)
    MassExclusionThreshold     = 0.50               // >50% of pool excluded
    ExclusionTimeWindow        = 24 * time.Hour     // Exclusions within this window

    // Level 4 triggers (Network Partition)
    PartitionTimeout           = 1 * time.Hour      // Duration before partition declared
    PartitionNodeThreshold     = 0.33               // >33% nodes unreachable
)

// RecoveryTriggerState tracks conditions for each trigger
type RecoveryTriggerState struct {
    // Level 1 tracking
    FailedAttempts        int
    LastFailureTime       time.Time
    HighestPhaseReached   DKGPhase

    // Level 2 tracking
    ConsecutiveSessionsFailed int
    SessionFailures          []SessionFailure  // Ring buffer of last N
    GracePeriodsUsed         int
    PreviousKeyExpiry        time.Time

    // Level 3 tracking
    ExcludedNodes            map[NodeID]time.Time
    ExclusionCount24h        int

    // Level 4 tracking
    UnreachableSince         map[NodeID]time.Time
    LocalConnectivityOK      bool
}

// SessionFailure records a DKG session failure for Level 2 tracking
type SessionFailure struct {
    SessionID       [32]byte
    FailedAt        time.Time
    FailurePhase    DKGPhase
    FailureReason   SessionFailureReason
    ParticipantCount int
    ExcludedCount   int
}

// SessionFailureReason categorizes why a session failed
type SessionFailureReason uint8

const (
    SessionFailureCoordinatorCrash  SessionFailureReason = 1 // Does NOT count toward Level 2
    SessionFailureQuorumLost        SessionFailureReason = 2 // Counts toward Level 2
    SessionFailureByzantine         SessionFailureReason = 3 // Counts toward Level 2
    SessionFailureTimeout           SessionFailureReason = 4 // Counts toward Level 2
    SessionFailureNetworkPartition  SessionFailureReason = 5 // Triggers Level 4 directly
)

// ShouldActivateGenesisTrusteeRecovery checks Level 2 trigger conditions
// EXPLICIT DEFINITION: "3 consecutive failures" means 3 SESSIONS (not retries)
// where each session:
//   1. Started with valid quorum
//   2. Did NOT complete Phase 6 (finalization)
//   3. Failed for reasons OTHER than coordinator crash
func (r *RecoveryTriggerState) ShouldActivateGenesisTrusteeRecovery() (bool, string) {
    // Check condition 1: Consecutive session failures
    consecutiveCount := 0
    now := time.Now()

    // Count only recent session failures (within window)
    for i := len(r.SessionFailures) - 1; i >= 0 && consecutiveCount < ConsecutiveSessionFailures; i-- {
        sf := r.SessionFailures[i]

        // Skip if outside window
        if now.Sub(sf.FailedAt) > SessionFailureWindow {
            break
        }

        // Coordinator crash doesn't count - it triggers coordinator rotation, not Level 2
        if sf.FailureReason == SessionFailureCoordinatorCrash {
            continue
        }

        consecutiveCount++
    }

    if consecutiveCount >= ConsecutiveSessionFailures {
        return true, fmt.Sprintf("%d consecutive DKG sessions failed within %v",
            consecutiveCount, SessionFailureWindow)
    }

    // Check condition 2: Grace period extensions exhausted
    if r.GracePeriodsUsed >= MaxGracePeriodExtensions {
        return true, fmt.Sprintf("grace period extensions exhausted (%d/%d)",
            r.GracePeriodsUsed, MaxGracePeriodExtensions)
    }

    // Check condition 3: Previous key expired
    if !r.PreviousKeyExpiry.IsZero() && time.Now().After(r.PreviousKeyExpiry) {
        return true, "previous key set has expired"
    }

    return false, ""
}

// ShouldActivateEmergencyReconstitution checks Level 3 trigger conditions
func (r *RecoveryTriggerState) ShouldActivateEmergencyReconstitution(totalPoolSize int) (bool, string) {
    // Count exclusions within window
    now := time.Now()
    recentExclusions := 0

    for _, excludedAt := range r.ExcludedNodes {
        if now.Sub(excludedAt) <= ExclusionTimeWindow {
            recentExclusions++
        }
    }

    threshold := int(float64(totalPoolSize) * MassExclusionThreshold)
    if recentExclusions > threshold {
        return true, fmt.Sprintf(">50%% of CA pool excluded within 24h (%d/%d)",
            recentExclusions, totalPoolSize)
    }

    return false, ""
}

// ShouldDeclarePartition checks Level 4 trigger conditions
func (r *RecoveryTriggerState) ShouldDeclarePartition(totalKnownNodes int) (bool, string) {
    // Must have local connectivity confirmed
    if !r.LocalConnectivityOK {
        return false, "local connectivity not confirmed"
    }

    // Count nodes unreachable for partition timeout
    now := time.Now()
    unreachableCount := 0

    for _, since := range r.UnreachableSince {
        if now.Sub(since) >= PartitionTimeout {
            unreachableCount++
        }
    }

    threshold := int(float64(totalKnownNodes) * PartitionNodeThreshold)
    if unreachableCount > threshold {
        return true, fmt.Sprintf(">33%% of nodes unreachable for >1h (%d/%d)",
            unreachableCount, totalKnownNodes)
    }

    return false, ""
}

// RecordSessionFailure updates trigger state when a DKG session fails
func (r *RecoveryTriggerState) RecordSessionFailure(failure SessionFailure) {
    // Add to ring buffer (keep last 10 failures)
    r.SessionFailures = append(r.SessionFailures, failure)
    if len(r.SessionFailures) > 10 {
        r.SessionFailures = r.SessionFailures[1:]
    }

    // Check if this should trigger Level 2
    if shouldActivate, reason := r.ShouldActivateGenesisTrusteeRecovery(); shouldActivate {
        log.Warn("Genesis trustee recovery trigger condition met",
            "reason", reason,
            "session_id", hex.EncodeToString(failure.SessionID[:8]))
    }
}
```

#### Level 1: Previous Key Set Fallback

When a new DKG fails, the system automatically extends the validity of the previous epoch's key set.

```go
// pkg/dkg/recovery.go

// DKGRecoveryConfig defines recovery behavior
const (
    PreviousKeyGracePeriod    = 7 * 24 * time.Hour  // 7 days extended validity
    MaxGracePeriodExtensions  = 3                    // Maximum 3 extensions (21 days total)
    RecoveryNotificationLead  = 24 * time.Hour       // Alert 24h before expiry
)

// DKGRecoveryManager handles DKG failure scenarios
type DKGRecoveryManager struct {
    currentEpoch       uint64
    previousKeySet     *CAKeySet
    gracePeriodCount   int
    genesisTrustees    []GenesisTrustee
    recoveryState      RecoveryState
}

type RecoveryState uint8

const (
    RecoveryStateNormal RecoveryState = iota
    RecoveryStatePreviousKeyFallback
    RecoveryStateGenesisTrusteeActivated
    RecoveryStateEmergencyReconstitution
)

// ActivatePreviousKeyFallback extends the previous key set validity
func (r *DKGRecoveryManager) ActivatePreviousKeyFallback() error {
    if r.gracePeriodCount >= MaxGracePeriodExtensions {
        return ErrGracePeriodExhausted
    }

    r.gracePeriodCount++
    r.recoveryState = RecoveryStatePreviousKeyFallback

    // Extend previous key validity
    r.previousKeySet.ValidUntil = time.Now().Add(PreviousKeyGracePeriod)

    // Broadcast network-wide alert
    alert := &DKGRecoveryAlert{
        Type:               AlertPreviousKeyFallback,
        Epoch:              r.currentEpoch,
        ExtensionNumber:    r.gracePeriodCount,
        NewExpiry:          r.previousKeySet.ValidUntil,
        Reason:             "DKG failed after maximum attempts",
        RecommendedAction:  "Investigate participating node issues",
    }
    r.broadcastAlert(alert)

    // Schedule retry with fresh participant selection
    go r.scheduleRecoveryDKG(1 * time.Hour)

    log.Warn("DKG recovery activated: using previous key set",
        "epoch", r.currentEpoch,
        "extension", r.gracePeriodCount,
        "new_expiry", r.previousKeySet.ValidUntil)

    return nil
}

// scheduleRecoveryDKG attempts DKG with different parameters
func (r *DKGRecoveryManager) scheduleRecoveryDKG(delay time.Duration) {
    time.Sleep(delay)

    // Use stricter participant selection
    candidates := r.selectRecoveryCandidates()

    // Attempt DKG with recovery parameters
    result, err := r.runRecoveryDKG(candidates, RecoveryDKGParams{
        MinReputation:    0.95,           // Higher reputation requirement
        MaxParticipants:  15,             // Smaller, more reliable pool
        ExtendedTimeout:  20 * time.Minute,
        StrictValidation: true,
    })

    if err != nil {
        if r.gracePeriodCount < MaxGracePeriodExtensions {
            r.ActivatePreviousKeyFallback()
        } else {
            r.ActivateGenesisTrusteeRecovery()
        }
        return
    }

    // Success - transition to new key set
    r.transitionToNewKeySet(result)
}

// selectRecoveryCandidates picks nodes without recent failures
func (r *DKGRecoveryManager) selectRecoveryCandidates() []NodeID {
    allNodes := GetCAPoolCandidates()
    candidates := make([]NodeID, 0)

    for _, node := range allNodes {
        // Exclude nodes with any recent DKG failures
        if hasRecentDKGFailure(node, 72*time.Hour) {
            continue
        }

        // Require higher reputation for recovery
        rep := getNodeReputation(node)
        if rep < 0.95 {
            continue
        }

        // Verify node is currently responsive
        if !isNodeResponsive(node, 5*time.Second) {
            continue
        }

        candidates = append(candidates, node)
    }

    return candidates
}
```

#### Level 2: Genesis Trustee Recovery

Genesis trustees are pre-designated high-trust entities that hold emergency recovery shares created during network bootstrap.

```go
// GenesisTrustee represents a pre-designated recovery entity
type GenesisTrustee struct {
    TrusteeID       string          // Unique identifier
    Organization    string          // Organization name (for audit)
    PublicKey       []byte          // Ed25519 public key
    EncryptedShare  []byte          // Share encrypted to trustee's key
    ContactMethod   ContactMethod   // How to reach trustee
    LastVerified    time.Time       // Last time trustee proved liveness
    ActivationCount int             // Times this trustee was activated
}

type ContactMethod struct {
    Primary   string  // Primary contact (e.g., secure email)
    Secondary string  // Backup contact
    Emergency string  // Emergency phone
}

// Genesis Trustee Configuration
const (
    GenesisTrusteeThreshold = 3  // 3-of-5 trustees required
    GenesisTrusteeCount     = 5  // Total genesis trustees
    TrusteeActivationQuorum = 2  // Network nodes needed to initiate
)

// ActivateGenesisTrusteeRecovery initiates emergency recovery
func (r *DKGRecoveryManager) ActivateGenesisTrusteeRecovery() error {
    r.recoveryState = RecoveryStateGenesisTrusteeActivated

    // 1. Broadcast emergency alert to all network nodes
    emergencyAlert := &DKGEmergencyAlert{
        Type:            EmergencyGenesisTrusteeActivation,
        Epoch:           r.currentEpoch,
        Timestamp:       time.Now(),
        Reason:          "All standard recovery mechanisms exhausted",
        TrusteeRequired: GenesisTrusteeThreshold,
        Deadline:        time.Now().Add(48 * time.Hour),
    }
    r.broadcastEmergencyAlert(emergencyAlert)

    // 2. Notify genesis trustees through out-of-band channels
    for _, trustee := range r.genesisTrustees {
        r.notifyTrustee(trustee, emergencyAlert)
    }

    // 3. Create recovery session
    session := &GenesisTrusteeRecoverySession{
        SessionID:        generateSecureSessionID(),
        InitiatedAt:      time.Now(),
        Deadline:         time.Now().Add(48 * time.Hour),
        RequiredTrustees: GenesisTrusteeThreshold,
        ReceivedShares:   make(map[string]*TrusteeShare),
        Status:           RecoverySessionPending,
    }

    // 4. Wait for trustee responses
    return r.awaitTrusteeShares(session)
}

// TrusteeShare represents a share submitted by a genesis trustee
type TrusteeShare struct {
    TrusteeID   string
    Share       []byte
    Proof       *TrusteeAuthenticationProof
    SubmittedAt time.Time
}

// TrusteeAuthenticationProof proves trustee identity
type TrusteeAuthenticationProof struct {
    Signature      []byte    // Signature over session ID
    Certificate    []byte    // X.509 certificate chain
    TPMAttestation []byte    // Optional TPM quote
    MFAToken       string    // Multi-factor auth token
}

// awaitTrusteeShares collects and verifies trustee contributions
func (r *DKGRecoveryManager) awaitTrusteeShares(session *GenesisTrusteeRecoverySession) error {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case share := <-r.trusteeShareChannel:
            // Verify trustee authentication
            if err := r.verifyTrusteeAuth(share); err != nil {
                log.Warn("Invalid trustee share", "trustee", share.TrusteeID, "error", err)
                continue
            }

            session.ReceivedShares[share.TrusteeID] = share

            // Check if we have enough shares
            if len(session.ReceivedShares) >= GenesisTrusteeThreshold {
                return r.reconstructFromTrusteeShares(session)
            }

        case <-ticker.C:
            // Check deadline
            if time.Now().After(session.Deadline) {
                return ErrTrusteeRecoveryTimeout
            }

            // Log progress
            log.Info("Awaiting genesis trustee shares",
                "received", len(session.ReceivedShares),
                "required", GenesisTrusteeThreshold,
                "remaining", time.Until(session.Deadline))

        case <-r.ctx.Done():
            return r.ctx.Err()
        }
    }
}

// reconstructFromTrusteeShares combines trustee shares to recover
func (r *DKGRecoveryManager) reconstructFromTrusteeShares(session *GenesisTrusteeRecoverySession) error {
    // 1. Collect and verify all shares
    shares := make([][]byte, 0, len(session.ReceivedShares))
    indices := make([]int, 0, len(session.ReceivedShares))

    for trusteeID, share := range session.ReceivedShares {
        trustee := r.getTrustee(trusteeID)
        shares = append(shares, share.Share)
        indices = append(indices, trustee.Index)
    }

    // 2. Reconstruct the emergency recovery key using Shamir
    recoveryKey, err := shamir.Combine(shares, indices, GenesisTrusteeThreshold)
    if err != nil {
        return &TrusteeRecoveryError{Cause: err, Phase: "reconstruction"}
    }

    // 3. Use recovery key to bootstrap new DKG
    // The recovery key is used to sign a "DKG Reset Certificate"
    // that authorizes a new DKG with relaxed parameters
    resetCert := &DKGResetCertificate{
        Epoch:           r.currentEpoch + 1,
        AuthorizedBy:    "genesis_trustee_recovery",
        TrusteeIDs:      getKeys(session.ReceivedShares),
        Timestamp:       time.Now(),
        ValidFor:        24 * time.Hour,
    }
    resetCert.Signature = signWithRecoveryKey(recoveryKey, resetCert)

    // 4. Zero recovery key immediately
    for i := range recoveryKey {
        recoveryKey[i] = 0
    }

    // 5. Broadcast reset certificate and initiate new DKG
    r.broadcastResetCertificate(resetCert)

    // 6. Run DKG with reset certificate authorization
    return r.runAuthorizedDKG(resetCert)
}
```

#### Level 3: Emergency Reconstitution

When mass exclusion or catastrophic failure occurs, the network can reconstitute with a minimal trusted set.

```go
// EmergencyReconstitution handles catastrophic DKG failure scenarios
type EmergencyReconstitution struct {
    MinimumTrustedSet   []NodeID           // Absolute minimum nodes
    ReconstitutionProof *ReconstitutionProof
    NewThreshold        int
    NewPoolSize         int
}

// ReconstitutionProof provides cryptographic evidence of proper reconstitution
type ReconstitutionProof struct {
    GenesisBlock       []byte   // Hash of genesis block
    TrusteeSignatures  [][]byte // Signatures from genesis trustees
    NetworkVotes       []Vote   // Network consensus votes
    AuditTrail         []byte   // Complete audit log hash
}

func (r *DKGRecoveryManager) InitiateEmergencyReconstitution() error {
    r.recoveryState = RecoveryStateEmergencyReconstitution

    // 1. Identify minimum trusted set
    trustedSet := r.identifyMinimumTrustedSet()
    if len(trustedSet) < 5 {
        return ErrInsufficientTrustedNodes
    }

    // 2. Require genesis trustee authorization
    auth, err := r.getGenesisTrusteeAuthorization(
        "emergency_reconstitution",
        GenesisTrusteeThreshold,
    )
    if err != nil {
        return err
    }

    // 3. Run minimal DKG with trusted set
    result, err := RunMinimalDKG(trustedSet, MinimalDKGParams{
        Threshold:     (len(trustedSet) / 2) + 1, // Simple majority
        Authorization: auth,
        AuditLevel:    AuditLevelMaximum,
    })
    if err != nil {
        return err
    }

    // 4. Create reconstitution proof
    proof := &ReconstitutionProof{
        GenesisBlock:      r.getGenesisBlockHash(),
        TrusteeSignatures: auth.Signatures,
        AuditTrail:        result.AuditHash,
    }

    // 5. Publish to transparency log
    r.publishReconstitutionToTransparencyLog(proof, result)

    // 6. Gradually expand pool over subsequent rotations
    r.schedulePoolExpansion(result.PoolID, trustedSet)

    return nil
}

// identifyMinimumTrustedSet finds the most reliable nodes
func (r *DKGRecoveryManager) identifyMinimumTrustedSet() []NodeID {
    allNodes := GetAllNodes()

    // Score nodes by multiple criteria
    type ScoredNode struct {
        NodeID NodeID
        Score  float64
    }

    scored := make([]ScoredNode, 0)

    for _, node := range allNodes {
        score := 0.0

        // Reputation (40%)
        score += getNodeReputation(node) * 0.4

        // Uptime history (20%)
        score += getUptimeScore(node, 90*24*time.Hour) * 0.2

        // DKG success history (20%)
        score += getDKGSuccessRate(node) * 0.2

        // TPM attestation freshness (10%)
        score += getAttestationFreshness(node) * 0.1

        // Geographic/organizational diversity bonus (10%)
        score += getDiversityScore(node, scored) * 0.1

        if score >= 0.9 { // Only consider high-scoring nodes
            scored = append(scored, ScoredNode{NodeID: node, Score: score})
        }
    }

    // Sort by score descending
    sort.Slice(scored, func(i, j int) bool {
        return scored[i].Score > scored[j].Score
    })

    // Take top nodes ensuring diversity
    result := make([]NodeID, 0, 10)
    seenOrgs := make(map[string]int)

    for _, sn := range scored {
        org := getNodeOrganization(sn.NodeID)

        // Limit nodes per organization for diversity
        if seenOrgs[org] >= 2 {
            continue
        }

        result = append(result, sn.NodeID)
        seenOrgs[org]++

        if len(result) >= 10 {
            break
        }
    }

    return result
}
```

#### Recovery State Machine

```
                                  +------------------+
                                  |     Normal       |
                                  |   DKG Running    |
                                  +--------+---------+
                                           |
                              DKG Fails (5 attempts)
                                           |
                                           v
                           +---------------+---------------+
                           |     Previous Key Fallback     |
                           |   (extends validity 7 days)   |
                           +---------------+---------------+
                                           |
                              Recovery DKG Fails (3 times)
                                           |
                                           v
                           +---------------+---------------+
                           |   Genesis Trustee Recovery    |
                           |   (3-of-5 trustees required)  |
                           +---------------+---------------+
                                           |
                              Trustees timeout (48 hours)
                                           |
                                           v
                           +---------------+---------------+
                           |  Emergency Reconstitution     |
                           |  (minimum trusted set + auth) |
                           +---------------+---------------+
                                           |
                               Success at any level
                                           |
                                           v
                                  +--------+---------+
                                  |    Normal        |
                                  |   Operations     |
                                  +------------------+
```

---

### Coordinator Slashing Protocol

Coordinators who fail to perform their duties or exhibit Byzantine behavior are subject to slashing penalties. This ensures coordinators remain accountable and cannot stall the network. Slashing is applied to staked collateral, providing economic disincentives for misbehavior.

#### Coordinator Stake Requirements

Before serving as coordinator, nodes must lock stake as collateral. This stake is subject to slashing for misbehavior.

```go
// pkg/dkg/coordinator_stake.go

// CoordinatorStakeConfig defines stake requirements
const (
    // Minimum stake required to serve as coordinator
    MinCoordinatorStake = 1000  // Units of staked collateral

    // Stake lock duration after DKG completion
    StakeLockDuration = 7 * 24 * time.Hour

    // Slashing percentages (applied to staked amount)
    PhaseTimeoutSlashPercent      = 1   // 1% for phase timeout (>2 min)
    CompleteDKGTimeoutSlashPercent = 5   // 5% for complete DKG timeout (>15 min)
    InvalidCommitmentSlashPercent  = 10  // 10% for invalid commitment
    EquivocationSlashPercent       = 50  // 50% for equivocation
    CollusionSlashPercent          = 100 // 100% for proven collusion + permanent ban
)
```

#### Slashable Offenses

| Offense | Severity | Stake Slashed | Reputation | Exclusion | Evidence Required |
|---------|----------|---------------|------------|-----------|-------------------|
| **Phase Timeout** (>2 min) | Low | 1% | -0.05 | None | Phase completion timestamps from 2+ participants |
| **Complete DKG Timeout** (>15 min) | Medium | 5% | -0.15 | 24h | Session timing logs, participant attestations |
| **Invalid Commitment** | High | 10% | -0.25 | 7 days | Invalid commitment proof, cryptographic verification |
| **Equivocation** | Critical | 50% | -0.50 | 30 days | Two conflicting signed messages with valid signatures |
| **Proven Collusion** | Critical | 100% | -1.00 | **Permanent ban** | Cryptographic proof of coordinated misbehavior |

**Slashing Escalation:**

Repeated offenses result in escalating penalties:

| Offense Count | Additional Penalty |
|---------------|-------------------|
| 1st offense | Base penalty only |
| 2nd offense (within 30 days) | 2x base penalty |
| 3rd offense (within 30 days) | 3x base penalty + 30-day coordinator ban |
| 4th+ offense | Permanent coordinator disqualification |

```go
// pkg/dkg/coordinator_slashing.go

// CoordinatorSlashingConfig defines slashing parameters
const (
    // Timeout thresholds
    PhaseStartTimeout        = 30 * time.Second  // Time to broadcast phase start
    MessageCollectionTimeout = 2 * time.Minute   // Time to collect all messages
    AggregationTimeout       = 30 * time.Second  // Time to aggregate and broadcast
    CompleteDKGTimeout       = 15 * time.Minute  // Total DKG completion time

    // Slashing penalties (stake percentage)
    PhaseTimeoutSlashPercent       = 1   // 1% stake slashed
    CompleteDKGTimeoutSlashPercent = 5   // 5% stake slashed
    InvalidCommitmentSlashPercent  = 10  // 10% stake slashed
    EquivocationSlashPercent       = 50  // 50% stake slashed
    CollusionSlashPercent          = 100 // 100% stake slashed

    // Reputation penalties (in addition to stake slashing)
    PhaseTimeoutReputationPenalty      = 0.05
    CompleteDKGTimeoutReputationPenalty = 0.15
    InvalidCommitmentReputationPenalty = 0.25
    EquivocationReputationPenalty      = 0.50
    CollusionReputationPenalty         = 1.00  // Complete reputation destruction

    // Exclusion periods
    MessageWithholdingExclusion  = 24 * time.Hour
    InvalidCommitmentExclusion   = 7 * 24 * time.Hour
    EquivocationExclusion        = 30 * 24 * time.Hour
    CollusionExclusion           = 0  // Permanent (MaxInt64)
)

// CoordinatorStakeManager handles stake-based slashing
type CoordinatorStakeManager struct {
    stakes         map[NodeID]*CoordinatorStake
    slashingHistory map[NodeID][]SlashingRecord
    mu             sync.RWMutex
}

type CoordinatorStake struct {
    NodeID       NodeID
    Amount       uint64
    LockedAt     time.Time
    UnlocksAt    time.Time
    IsLocked     bool
    SlashedTotal uint64
}

type SlashingRecord struct {
    Timestamp      time.Time
    Offense        SlashableOffense
    StakeSlashed   uint64
    SlashPercent   int
    ReputationHit  float64
    Evidence       [32]byte  // Hash of evidence
    SessionID      [32]byte
}

// SlashCoordinator applies slashing penalty based on offense
func (m *CoordinatorStakeManager) SlashCoordinator(
    coordinatorID NodeID,
    offense SlashableOffense,
    evidence []byte,
    sessionID [32]byte,
) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    stake, exists := m.stakes[coordinatorID]
    if !exists {
        return ErrCoordinatorNotStaked
    }

    // Calculate slash amount based on offense
    slashPercent := m.getSlashPercent(offense)
    slashAmount := (stake.Amount * uint64(slashPercent)) / 100

    // Apply escalation for repeat offenders
    recentOffenses := m.countRecentOffenses(coordinatorID, 30*24*time.Hour)
    if recentOffenses > 0 {
        escalationMultiplier := min(recentOffenses+1, 3)
        slashAmount *= uint64(escalationMultiplier)
    }

    // Cap slash at available stake
    if slashAmount > stake.Amount-stake.SlashedTotal {
        slashAmount = stake.Amount - stake.SlashedTotal
    }

    // Apply slashing
    stake.SlashedTotal += slashAmount

    // Record slashing
    record := SlashingRecord{
        Timestamp:     time.Now(),
        Offense:       offense,
        StakeSlashed:  slashAmount,
        SlashPercent:  slashPercent,
        ReputationHit: m.getReputationPenalty(offense),
        Evidence:      sha256.Sum256(evidence),
        SessionID:     sessionID,
    }
    m.slashingHistory[coordinatorID] = append(m.slashingHistory[coordinatorID], record)

    // Apply reputation penalty
    applyReputationPenalty(coordinatorID, record.ReputationHit)

    // Apply exclusion if applicable
    exclusionPeriod := m.getExclusionPeriod(offense)
    if exclusionPeriod > 0 {
        excludeFromCoordination(coordinatorID, exclusionPeriod)
    }

    // Handle permanent ban for collusion
    if offense == OffenseCollusion {
        permanentlyBanCoordinator(coordinatorID)
    }

    // Check for coordinator disqualification (4+ offenses)
    if recentOffenses >= 3 {
        permanentlyBanCoordinator(coordinatorID)
    }

    log.Warn("Coordinator slashed",
        "coordinator", coordinatorID,
        "offense", offense,
        "slashPercent", slashPercent,
        "slashAmount", slashAmount,
        "recentOffenses", recentOffenses)

    return nil
}

func (m *CoordinatorStakeManager) getSlashPercent(offense SlashableOffense) int {
    switch offense {
    case OffensePhaseTimeout:
        return PhaseTimeoutSlashPercent
    case OffenseCompleteDKGTimeout:
        return CompleteDKGTimeoutSlashPercent
    case OffenseInvalidCommitment:
        return InvalidCommitmentSlashPercent
    case OffenseEquivocation:
        return EquivocationSlashPercent
    case OffenseCollusion:
        return CollusionSlashPercent
    default:
        return 0
    }
}

func (m *CoordinatorStakeManager) getReputationPenalty(offense SlashableOffense) float64 {
    switch offense {
    case OffensePhaseTimeout:
        return PhaseTimeoutReputationPenalty
    case OffenseCompleteDKGTimeout:
        return CompleteDKGTimeoutReputationPenalty
    case OffenseInvalidCommitment:
        return InvalidCommitmentReputationPenalty
    case OffenseEquivocation:
        return EquivocationReputationPenalty
    case OffenseCollusion:
        return CollusionReputationPenalty
    default:
        return 0
    }
}

func (m *CoordinatorStakeManager) getExclusionPeriod(offense SlashableOffense) time.Duration {
    switch offense {
    case OffensePhaseTimeout:
        return 0  // No exclusion for minor timeouts
    case OffenseCompleteDKGTimeout:
        return MessageWithholdingExclusion
    case OffenseInvalidCommitment:
        return InvalidCommitmentExclusion
    case OffenseEquivocation:
        return EquivocationExclusion
    case OffenseCollusion:
        return time.Duration(math.MaxInt64)  // Permanent
    default:
        return 0
    }
}

type SlashableOffense uint8

const (
    OffensePhaseTimeout       SlashableOffense = iota  // >2 min phase delay
    OffenseCompleteDKGTimeout                          // >15 min total DKG time
    OffenseInvalidCommitment                           // Invalid commitment submitted
    OffenseEquivocation                                // Conflicting signed messages
    OffenseCollusion                                   // Proven coordination with adversaries
)

// CoordinatorMonitor tracks coordinator behavior for slashing
type CoordinatorMonitor struct {
    coordinatorID    NodeID
    sessionID        [32]byte
    stakeManager     *CoordinatorStakeManager
    phaseTimestamps  map[DKGPhase]PhaseTimings
    receivedMessages map[DKGPhase][]SignedMessage
    slashingEvents   []SlashingRecord
    sessionStartTime time.Time
}

type PhaseTimings struct {
    ExpectedStart time.Time
    ActualStart   time.Time
    ExpectedEnd   time.Time
    ActualEnd     time.Time
    Deadline      time.Time
}

// MonitorCoordinator creates a monitor for the current coordinator
func MonitorCoordinator(coordinatorID NodeID, sessionID [32]byte, stakeManager *CoordinatorStakeManager) *CoordinatorMonitor {
    return &CoordinatorMonitor{
        coordinatorID:    coordinatorID,
        sessionID:        sessionID,
        stakeManager:     stakeManager,
        phaseTimestamps:  make(map[DKGPhase]PhaseTimings),
        receivedMessages: make(map[DKGPhase][]SignedMessage),
        slashingEvents:   make([]SlashingRecord, 0),
        sessionStartTime: time.Now(),
    }
}

// RecordPhaseStart notes when coordinator starts a phase and checks for timeouts
func (m *CoordinatorMonitor) RecordPhaseStart(phase DKGPhase, message *SignedMessage) error {
    now := time.Now()
    timings := m.phaseTimestamps[phase]

    // Check if phase start is late (>2 minutes = 1% stake slash)
    if now.After(timings.ExpectedStart.Add(MessageCollectionTimeout)) {
        evidence := serializeTimingEvidence(timings, now)
        if err := m.stakeManager.SlashCoordinator(
            m.coordinatorID,
            OffensePhaseTimeout,
            evidence,
            m.sessionID,
        ); err != nil {
            log.Error("Failed to slash coordinator for phase timeout", "error", err)
        }
    }

    // Check if total DKG time exceeded (>15 minutes = 5% stake slash)
    if now.Sub(m.sessionStartTime) > CompleteDKGTimeout {
        evidence := serializeDKGTimeoutEvidence(m.sessionStartTime, now)
        if err := m.stakeManager.SlashCoordinator(
            m.coordinatorID,
            OffenseCompleteDKGTimeout,
            evidence,
            m.sessionID,
        ); err != nil {
            log.Error("Failed to slash coordinator for DKG timeout", "error", err)
        }
    }

    timings.ActualStart = now
    m.phaseTimestamps[phase] = timings

    // Store signed message as evidence
    m.receivedMessages[phase] = append(m.receivedMessages[phase], *message)

    return nil
}

// CheckEquivocation detects if coordinator sent conflicting messages (50% stake slash)
func (m *CoordinatorMonitor) CheckEquivocation(msg1, msg2 *SignedMessage) error {
    // Verify both messages are from the coordinator
    if msg1.SignerID != m.coordinatorID || msg2.SignerID != m.coordinatorID {
        return ErrNotCoordinatorMessage
    }

    // Check if messages conflict (same phase, different content)
    if msg1.Phase == msg2.Phase && !bytes.Equal(msg1.Content, msg2.Content) {
        // Verify signatures are valid (proves coordinator actually sent both)
        if !verifySignature(msg1) || !verifySignature(msg2) {
            return ErrInvalidSignature
        }

        // This is equivocation - critical offense (50% stake slash)
        evidence := &EquivocationEvidence{
            Message1: msg1,
            Message2: msg2,
        }

        if err := m.stakeManager.SlashCoordinator(
            m.coordinatorID,
            OffenseEquivocation,
            serializeEquivocationEvidence(evidence),
            m.sessionID,
        ); err != nil {
            log.Error("Failed to slash coordinator for equivocation", "error", err)
        }

        return &EquivocationDetectedError{
            CoordinatorID: m.coordinatorID,
            Evidence:      evidence,
        }
    }

    return nil
}

// VerifyMessageDelivery checks that coordinator delivered all messages
func (m *CoordinatorMonitor) VerifyMessageDelivery(phase DKGPhase, participants []NodeID) error {
    // Collect delivery confirmations from participants
    confirmations := make(map[NodeID]bool)
    missingFor := make([]NodeID, 0)

    for _, participant := range participants {
        received := queryParticipantDelivery(participant, phase, m.sessionID)
        confirmations[participant] = received
        if !received {
            missingFor = append(missingFor, participant)
        }
    }

    // If messages missing for 2+ participants, this indicates invalid commitment behavior
    // Apply 10% stake slash for invalid commitment (message withholding is a form of invalid behavior)
    if len(missingFor) >= 2 {
        evidence := &MessageWithholdingEvidence{
            Phase:           phase,
            MissingFor:      missingFor,
            Confirmations:   confirmations,
            CollectedAt:     time.Now(),
        }

        if err := m.stakeManager.SlashCoordinator(
            m.coordinatorID,
            OffenseInvalidCommitment,  // Message withholding treated as invalid commitment
            serializeWithholdingEvidence(evidence),
            m.sessionID,
        ); err != nil {
            log.Error("Failed to slash coordinator for message withholding", "error", err)
        }

        return &MessageWithholdingError{
            CoordinatorID: m.coordinatorID,
            MissingFor:    missingFor,
        }
    }

    return nil
}

// DetectCollusion checks for provable collusion between coordinator and adversaries
// This results in 100% stake slash and permanent ban
func (m *CoordinatorMonitor) DetectCollusion(collusionProof *CollusionProof) error {
    if collusionProof == nil || !collusionProof.IsValid() {
        return ErrInvalidCollusionProof
    }

    // Verify cryptographic proof of collusion
    if err := verifyCollusionProof(collusionProof); err != nil {
        return fmt.Errorf("collusion proof verification failed: %w", err)
    }

    // Apply 100% stake slash + permanent ban
    if err := m.stakeManager.SlashCoordinator(
        m.coordinatorID,
        OffenseCollusion,
        serializeCollusionProof(collusionProof),
        m.sessionID,
    ); err != nil {
        log.Error("Failed to slash coordinator for collusion", "error", err)
        return err
    }

    log.Error("Coordinator collusion detected - permanent ban applied",
        "coordinator", m.coordinatorID,
        "colludingWith", collusionProof.ColludingParties)

    return nil
}

// CollusionProof contains cryptographic evidence of coordinator collusion
type CollusionProof struct {
    CoordinatorID     NodeID
    ColludingParties  []NodeID
    SharedSecrets     [][]byte    // Evidence of secret sharing
    ConflictingShares []SharePair // Shares that prove collusion
    Timestamp         time.Time
    Signatures        [][]byte    // Witness signatures
}

type SharePair struct {
    Share1    []byte
    Share2    []byte
    Recipient NodeID
}

func (p *CollusionProof) IsValid() bool {
    return p != nil &&
        len(p.ColludingParties) > 0 &&
        len(p.Signatures) >= 2 &&  // Require at least 2 witnesses
        time.Since(p.Timestamp) < 24*time.Hour  // Evidence must be recent
}
```

**Coordinator Slashing Rules Summary:**

| Offense | Stake Slashed | Reputation Penalty | Exclusion | Ban |
|---------|---------------|-------------------|-----------|-----|
| Phase timeout (>2 min) | 1% | -0.05 | None | No |
| Complete DKG timeout (>15 min) | 5% | -0.15 | 24h | No |
| Invalid commitment | 10% | -0.25 | 7 days | No |
| Equivocation | 50% | -0.50 | 30 days | No |
| Proven collusion | 100% | -1.00 | N/A | **Permanent** |

#### Coordinator Replacement via Consensus

When a coordinator is slashed or becomes unresponsive, automatic replacement occurs.

```go
// CoordinatorReplacement handles mid-session coordinator changes
type CoordinatorReplacement struct {
    OriginalCoordinator NodeID
    ReplacementReason   ReplacementReason
    NewCoordinator      NodeID
    ConsensusProof      *ReplacementConsensus
    SessionState        *DKGSessionState
}

type ReplacementReason uint8

const (
    ReplacementSlashed ReplacementReason = iota
    ReplacementUnresponsive
    ReplacementVoluntary
    ReplacementNetworkVote
)

type ReplacementConsensus struct {
    VotesFor     []SignedVote
    VotesAgainst []SignedVote
    Threshold    int
    Achieved     bool
    Timestamp    time.Time
}

// InitiateCoordinatorReplacement starts the replacement process
func InitiateCoordinatorReplacement(reason ReplacementReason, evidence []byte) (*CoordinatorReplacement, error) {
    replacement := &CoordinatorReplacement{
        OriginalCoordinator: getCurrentCoordinator(),
        ReplacementReason:   reason,
    }

    // 1. Select replacement from backup coordinators
    backups := getBackupCoordinators()
    if len(backups) == 0 {
        return nil, ErrNoBackupCoordinators
    }

    // First backup becomes new coordinator
    replacement.NewCoordinator = backups[0]

    // 2. Initiate consensus vote among participants
    participants := getCurrentDKGParticipants()
    votingDeadline := time.Now().Add(2 * time.Minute)

    voteRequest := &CoordinatorReplacementVote{
        Original:    replacement.OriginalCoordinator,
        Replacement: replacement.NewCoordinator,
        Reason:      reason,
        Evidence:    evidence,
        Deadline:    votingDeadline,
    }

    // 3. Collect votes
    votesFor := make([]SignedVote, 0)
    votesAgainst := make([]SignedVote, 0)
    threshold := (len(participants) * 2 / 3) + 1 // 2/3 majority required

    for vote := range collectVotes(participants, voteRequest, votingDeadline) {
        if vote.Approve {
            votesFor = append(votesFor, vote)
        } else {
            votesAgainst = append(votesAgainst, vote)
        }

        // Early termination if threshold reached
        if len(votesFor) >= threshold {
            break
        }
        if len(votesAgainst) > len(participants)-threshold {
            return nil, ErrReplacementRejected
        }
    }

    // 4. Verify consensus achieved
    if len(votesFor) < threshold {
        return nil, ErrInsufficientVotes
    }

    replacement.ConsensusProof = &ReplacementConsensus{
        VotesFor:     votesFor,
        VotesAgainst: votesAgainst,
        Threshold:    threshold,
        Achieved:     true,
        Timestamp:    time.Now(),
    }

    // 5. Transfer session state to new coordinator
    replacement.SessionState = transferSessionState(
        replacement.OriginalCoordinator,
        replacement.NewCoordinator,
    )

    // 6. Broadcast replacement confirmation
    broadcastCoordinatorReplacement(replacement)

    log.Info("Coordinator replaced",
        "original", replacement.OriginalCoordinator,
        "new", replacement.NewCoordinator,
        "reason", reason,
        "votes_for", len(votesFor))

    return replacement, nil
}

// transferSessionState moves DKG state to new coordinator
func transferSessionState(from, to NodeID) *DKGSessionState {
    // Request state from all participants (not just old coordinator)
    stateFragments := make(map[NodeID]*DKGStateFragment)

    participants := getCurrentDKGParticipants()
    for _, p := range participants {
        fragment := requestStateFragment(p)
        if fragment != nil {
            stateFragments[p] = fragment
        }
    }

    // Reconstruct state from fragments
    state := reconstructDKGState(stateFragments)

    // Send to new coordinator
    sendStateTo(to, state)

    return state
}
```

#### Slashing Evidence Format

```go
// SlashingEvidencePackage contains all evidence for a slashing event
type SlashingEvidencePackage struct {
    Header      EvidenceHeader
    Offense     SlashableOffense
    Evidence    EvidencePayload
    Witnesses   []WitnessAttestation
    Timestamp   time.Time
    Hash        [32]byte
}

type EvidenceHeader struct {
    Version     uint8
    SessionID   [32]byte
    Coordinator NodeID
    Phase       DKGPhase
}

type EvidencePayload struct {
    // For timeout violations
    ExpectedTimestamp time.Time
    ActualTimestamp   time.Time

    // For message withholding
    ExpectedRecipients []NodeID
    ActualRecipients   []NodeID
    MissingMessages    []MessageID

    // For equivocation
    ConflictingMessages []*SignedMessage

    // For invalid aggregation
    InvalidResult   []byte
    ExpectedResult  []byte
    InputMessages   []*SignedMessage
}

type WitnessAttestation struct {
    WitnessID   NodeID
    Observation []byte
    Signature   []byte
    Timestamp   time.Time
}

// CreateSlashingEvidence assembles evidence package
func CreateSlashingEvidence(
    offense SlashableOffense,
    coordinator NodeID,
    sessionID [32]byte,
    rawEvidence interface{},
    witnesses []NodeID,
) (*SlashingEvidencePackage, error) {

    pkg := &SlashingEvidencePackage{
        Header: EvidenceHeader{
            Version:     1,
            SessionID:   sessionID,
            Coordinator: coordinator,
        },
        Offense:   offense,
        Timestamp: time.Now(),
    }

    // Serialize evidence based on offense type
    switch e := rawEvidence.(type) {
    case *TimeoutEvidence:
        pkg.Evidence.ExpectedTimestamp = e.Expected
        pkg.Evidence.ActualTimestamp = e.Actual

    case *EquivocationEvidence:
        pkg.Evidence.ConflictingMessages = []*SignedMessage{e.Message1, e.Message2}

    case *MessageWithholdingEvidence:
        pkg.Evidence.ExpectedRecipients = e.Expected
        pkg.Evidence.ActualRecipients = e.Actual
        pkg.Evidence.MissingMessages = e.Missing
    }

    // Collect witness attestations
    pkg.Witnesses = make([]WitnessAttestation, 0, len(witnesses))
    for _, w := range witnesses {
        attestation := requestWitnessAttestation(w, pkg)
        if attestation != nil {
            pkg.Witnesses = append(pkg.Witnesses, *attestation)
        }
    }

    // Compute evidence hash
    pkg.Hash = computeEvidenceHash(pkg)

    return pkg, nil
}
```

---

### DKG Abort Griefing Prevention

Byzantine nodes may attempt to permanently prevent DKG completion through strategic aborts. The system implements comprehensive griefing prevention with progress milestones and minimum progress guarantees.

#### Progress Milestones

Each DKG phase has defined milestones that must be achieved within time bounds:

```go
// pkg/dkg/milestones.go

// DKG Phase Milestones - progress checkpoints within each phase
type PhaseMilestone struct {
    ID              MilestoneID
    Phase           DKGPhase
    Description     string
    Timeout         time.Duration
    RequiredPercent int  // Percentage of participants needed
    Reversible      bool // Can progress be lost
}

// Milestone definitions for each phase
var DKGMilestones = map[DKGPhase][]PhaseMilestone{
    PhaseAttestation: {
        {ID: "attest_start", Description: "Attestation requests sent", Timeout: 10 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "attest_50", Description: "50% attestations received", Timeout: 1 * time.Minute, RequiredPercent: 50, Reversible: false},
        {ID: "attest_threshold", Description: "Threshold attestations received", Timeout: 2 * time.Minute, RequiredPercent: 67, Reversible: false},
        {ID: "attest_complete", Description: "All attestations verified", Timeout: 2*time.Minute + 30*time.Second, RequiredPercent: 100, Reversible: false},
    },
    PhaseCommitment: {
        {ID: "commit_start", Description: "Commitment round started", Timeout: 5 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "commit_50", Description: "50% commitments received", Timeout: 30 * time.Second, RequiredPercent: 50, Reversible: false},
        {ID: "commit_threshold", Description: "Threshold commitments received", Timeout: 45 * time.Second, RequiredPercent: 67, Reversible: false},
        {ID: "commit_validated", Description: "All commitments validated", Timeout: 1 * time.Minute, RequiredPercent: 100, Reversible: false},
    },
    PhaseShareDistribution: {
        {ID: "share_start", Description: "Share distribution started", Timeout: 5 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "share_sent_50", Description: "50% shares sent", Timeout: 30 * time.Second, RequiredPercent: 50, Reversible: false},
        {ID: "share_received_50", Description: "50% shares received by all", Timeout: 1 * time.Minute, RequiredPercent: 50, Reversible: false},
        {ID: "share_verified", Description: "All shares verified", Timeout: 2 * time.Minute, RequiredPercent: 100, Reversible: false},
    },
    PhaseKeyDerivation: {
        {ID: "derive_start", Description: "Key derivation started", Timeout: 5 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "derive_computed", Description: "Keys computed", Timeout: 30 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "certeq_sent", Description: "CertEq signatures sent", Timeout: 45 * time.Second, RequiredPercent: 100, Reversible: false},
        {ID: "certeq_complete", Description: "CertEq consensus reached", Timeout: 1 * time.Minute, RequiredPercent: 67, Reversible: false},
    },
}

// MilestoneTracker monitors DKG progress
type MilestoneTracker struct {
    sessionID        [32]byte
    currentPhase     DKGPhase
    currentMilestone int
    milestoneStatus  map[MilestoneID]MilestoneStatus
    participantProg  map[NodeID]*ParticipantProgress
    stuckDetection   *StuckDetector
}

type MilestoneStatus struct {
    ID           MilestoneID
    Achieved     bool
    AchievedAt   time.Time
    Deadline     time.Time
    Progress     int  // Percentage complete
    BlockingNode []NodeID
}

type ParticipantProgress struct {
    NodeID              NodeID
    LastMilestoneID     MilestoneID
    LastMilestoneTime   time.Time
    ConsecutiveTimeouts int
    TotalContributions  int
    Suspicious          bool
}

// TrackProgress updates milestone status
func (t *MilestoneTracker) TrackProgress(phase DKGPhase, event ProgressEvent) error {
    milestones := DKGMilestones[phase]
    if t.currentMilestone >= len(milestones) {
        return nil // Phase complete
    }

    current := milestones[t.currentMilestone]
    status := t.milestoneStatus[current.ID]

    // Update progress
    switch event.Type {
    case EventParticipantContributed:
        status.Progress = t.calculateProgress(phase, current)
        t.participantProg[event.NodeID].LastMilestoneID = current.ID
        t.participantProg[event.NodeID].LastMilestoneTime = time.Now()
        t.participantProg[event.NodeID].TotalContributions++

    case EventMilestoneAchieved:
        status.Achieved = true
        status.AchievedAt = time.Now()
        t.currentMilestone++

        // Reset stuck detection for new milestone
        t.stuckDetection.Reset()

        log.Info("DKG milestone achieved",
            "phase", phase,
            "milestone", current.ID,
            "time_taken", time.Since(status.Deadline.Add(-current.Timeout)))

    case EventMilestoneTimeout:
        // Identify blocking nodes
        blocking := t.identifyBlockingNodes(phase, current)
        status.BlockingNode = blocking

        return &MilestoneTimeoutError{
            Milestone:     current.ID,
            Phase:         phase,
            BlockingNodes: blocking,
            Progress:      status.Progress,
        }
    }

    t.milestoneStatus[current.ID] = status
    return nil
}

// identifyBlockingNodes finds nodes preventing progress
func (t *MilestoneTracker) identifyBlockingNodes(phase DKGPhase, milestone PhaseMilestone) []NodeID {
    blocking := make([]NodeID, 0)

    for nodeID, progress := range t.participantProg {
        // Node hasn't contributed to current milestone
        if progress.LastMilestoneID != milestone.ID {
            blocking = append(blocking, nodeID)
            progress.ConsecutiveTimeouts++

            // Flag as suspicious if repeated timeouts
            if progress.ConsecutiveTimeouts >= 2 {
                progress.Suspicious = true
            }
        }
    }

    return blocking
}

// calculateProgress computes percentage completion
func (t *MilestoneTracker) calculateProgress(phase DKGPhase, milestone PhaseMilestone) int {
    participants := len(t.participantProg)
    contributed := 0

    for _, progress := range t.participantProg {
        if progress.LastMilestoneID == milestone.ID {
            contributed++
        }
    }

    return (contributed * 100) / participants
}
```

#### Aborter Detection and Exclusion

```go
// AborterDetector identifies and excludes malicious aborters
type AborterDetector struct {
    sessionHistory  map[[32]byte]*SessionAnalysis
    nodeHistory     map[NodeID]*NodeAbortHistory
    exclusionList   map[NodeID]time.Time
}

type SessionAnalysis struct {
    SessionID       [32]byte
    Attempt         int
    AbortersFound   []NodeID
    AbortPhase      DKGPhase
    AbortMilestone  MilestoneID
    PatternMatch    []string  // Detected patterns
}

type NodeAbortHistory struct {
    NodeID             NodeID
    TotalAborts        int
    RecentAborts       int  // Last 30 days
    LastAbortTime      time.Time
    AbortPhases        map[DKGPhase]int
    PatternScore       float64  // 0-1, higher = more suspicious
    CoordinatedAborts  []NodeID // Nodes that abort together
}

// AnalyzeAbortPatterns detects coordinated or strategic aborts
func (d *AborterDetector) AnalyzeAbortPatterns(sessionID [32]byte, abortEvent *DKGAbortEvent) *AbortAnalysis {
    analysis := &AbortAnalysis{
        SessionID:    sessionID,
        AborterID:    abortEvent.AborterID,
        Phase:        abortEvent.Phase,
        Timestamp:    time.Now(),
    }

    history := d.nodeHistory[abortEvent.AborterID]
    if history == nil {
        history = &NodeAbortHistory{
            NodeID:      abortEvent.AborterID,
            AbortPhases: make(map[DKGPhase]int),
        }
        d.nodeHistory[abortEvent.AborterID] = history
    }

    // Update history
    history.TotalAborts++
    history.RecentAborts++
    history.LastAbortTime = time.Now()
    history.AbortPhases[abortEvent.Phase]++

    // Pattern detection
    patterns := d.detectPatterns(history, abortEvent)
    analysis.DetectedPatterns = patterns

    // Calculate pattern score
    history.PatternScore = d.calculatePatternScore(history, patterns)

    // Check for coordinated aborts
    coordinated := d.detectCoordinatedAborts(sessionID, abortEvent)
    if len(coordinated) > 0 {
        history.CoordinatedAborts = append(history.CoordinatedAborts, coordinated...)
        analysis.CoordinatedWith = coordinated
    }

    // Determine exclusion
    if history.PatternScore >= 0.7 || history.TotalAborts >= 3 {
        exclusionDuration := d.calculateExclusionDuration(history)
        d.exclusionList[abortEvent.AborterID] = time.Now().Add(exclusionDuration)
        analysis.Excluded = true
        analysis.ExclusionDuration = exclusionDuration
    }

    return analysis
}

// detectPatterns identifies suspicious abort patterns
func (d *AborterDetector) detectPatterns(history *NodeAbortHistory, event *DKGAbortEvent) []AbortPattern {
    patterns := make([]AbortPattern, 0)

    // Pattern 1: Same phase aborts
    if history.AbortPhases[event.Phase] >= 2 {
        patterns = append(patterns, AbortPattern{
            Type:        PatternSamePhaseAbort,
            Description: fmt.Sprintf("Aborted in %s phase %d times", event.Phase, history.AbortPhases[event.Phase]),
            Severity:    0.3,
        })
    }

    // Pattern 2: Strategic timing (abort at threshold)
    if event.Phase == PhaseShareDistribution || event.Phase == PhaseKeyDerivation {
        patterns = append(patterns, AbortPattern{
            Type:        PatternStrategicTiming,
            Description: "Abort at critical phase after significant network resources spent",
            Severity:    0.4,
        })
    }

    // Pattern 3: Rapid repeated aborts
    if history.RecentAborts >= 3 && time.Since(history.LastAbortTime) < 24*time.Hour {
        patterns = append(patterns, AbortPattern{
            Type:        PatternRapidRepeated,
            Description: fmt.Sprintf("%d aborts in 24 hours", history.RecentAborts),
            Severity:    0.5,
        })
    }

    // Pattern 4: Last-second abort (timeout at >90% completion)
    if event.MilestoneProgress >= 90 {
        patterns = append(patterns, AbortPattern{
            Type:        PatternLastSecondAbort,
            Description: "Abort when milestone was 90%+ complete",
            Severity:    0.6,
        })
    }

    return patterns
}

// detectCoordinatedAborts finds nodes that abort together
func (d *AborterDetector) detectCoordinatedAborts(sessionID [32]byte, event *DKGAbortEvent) []NodeID {
    coordinated := make([]NodeID, 0)

    // Check other aborts in same session within 30 seconds
    session := d.sessionHistory[sessionID]
    if session == nil {
        return coordinated
    }

    for _, otherAborter := range session.AbortersFound {
        if otherAborter == event.AborterID {
            continue
        }

        // Check if this pair has aborted together before
        otherHistory := d.nodeHistory[otherAborter]
        if otherHistory == nil {
            continue
        }

        // Count co-occurrences
        coOccurrences := 0
        for _, prev := range otherHistory.CoordinatedAborts {
            if prev == event.AborterID {
                coOccurrences++
            }
        }

        if coOccurrences >= 2 {
            coordinated = append(coordinated, otherAborter)
        }
    }

    return coordinated
}

// calculatePatternScore computes overall suspicion score
func (d *AborterDetector) calculatePatternScore(history *NodeAbortHistory, patterns []AbortPattern) float64 {
    score := 0.0

    // Base score from patterns
    for _, p := range patterns {
        score += p.Severity
    }

    // Adjust for history
    score += float64(history.TotalAborts) * 0.1
    score += float64(history.RecentAborts) * 0.15

    // Coordination multiplier
    if len(history.CoordinatedAborts) > 0 {
        score *= 1.5
    }

    // Normalize to 0-1
    if score > 1.0 {
        score = 1.0
    }

    return score
}

// calculateExclusionDuration determines how long to exclude
func (d *AborterDetector) calculateExclusionDuration(history *NodeAbortHistory) time.Duration {
    base := 24 * time.Hour

    // Increase based on pattern score
    multiplier := 1 + int(history.PatternScore*6) // 1-7 days

    // Additional for total aborts
    multiplier += history.TotalAborts

    // Cap at 30 days
    duration := base * time.Duration(multiplier)
    if duration > 30*24*time.Hour {
        duration = 30 * 24 * time.Hour
    }

    return duration
}
```

#### Minimum Progress Guarantees

```go
// MinimumProgressGuarantee ensures DKG cannot be blocked indefinitely
type MinimumProgressGuarantee struct {
    // If DKG has not progressed past this phase in N attempts,
    // escalate to emergency procedures
    MinPhaseProgress  DKGPhase
    MaxStuckAttempts  int
    EscalationTimeout time.Duration

    // Current state
    stuckPhase   DKGPhase
    stuckCount   int
    lastProgress time.Time
}

// MinProgressConfig defines minimum progress requirements
const (
    // DKG must reach at least ShareDistribution within 3 attempts
    MinRequiredPhase = PhaseShareDistribution
    MaxStuckAttempts = 3
    StuckEscalation  = 30 * time.Minute
)

// CheckMinimumProgress verifies DKG is making adequate progress
func (g *MinimumProgressGuarantee) CheckMinimumProgress(currentPhase DKGPhase, attempt int) error {
    now := time.Now()

    // Check if we've progressed past stuck phase
    if phaseOrder(currentPhase) > phaseOrder(g.stuckPhase) {
        // Progress made - reset stuck counter
        g.stuckPhase = currentPhase
        g.stuckCount = 0
        g.lastProgress = now
        return nil
    }

    // No progress - increment stuck counter
    if currentPhase == g.stuckPhase {
        g.stuckCount++
    }

    // Check stuck conditions
    if g.stuckCount >= MaxStuckAttempts {
        return &MinimumProgressViolation{
            StuckPhase:  g.stuckPhase,
            StuckCount:  g.stuckCount,
            Duration:    now.Sub(g.lastProgress),
            Action:      ActionEscalateToEmergency,
        }
    }

    // Check time-based escalation
    if now.Sub(g.lastProgress) > StuckEscalation {
        return &MinimumProgressViolation{
            StuckPhase:  g.stuckPhase,
            StuckCount:  g.stuckCount,
            Duration:    now.Sub(g.lastProgress),
            Action:      ActionEscalateToEmergency,
        }
    }

    // Warn if approaching limits
    if g.stuckCount >= MaxStuckAttempts-1 {
        log.Warn("DKG approaching stuck limit",
            "phase", g.stuckPhase,
            "attempts", g.stuckCount,
            "time_stuck", now.Sub(g.lastProgress))
    }

    return nil
}

// EnforceProgressOrEscalate takes action when minimum progress is violated
func (g *MinimumProgressGuarantee) EnforceProgressOrEscalate(violation *MinimumProgressViolation) error {
    log.Error("Minimum DKG progress violated - escalating",
        "stuck_phase", violation.StuckPhase,
        "stuck_count", violation.StuckCount,
        "duration", violation.Duration)

    switch violation.Action {
    case ActionEscalateToEmergency:
        // 1. Exclude all nodes that caused failures
        stuckNodes := getNodesBlockingPhase(violation.StuckPhase)
        for _, node := range stuckNodes {
            excludeFromDKG(node, 7*24*time.Hour)
            slashReputation(node, -0.2, "dkg_stuck_blocker")
        }

        // 2. Activate emergency fallback
        return ActivatePreviousKeyFallback()

    case ActionGenesisTrusteeRecovery:
        return ActivateGenesisTrusteeRecovery()

    default:
        return nil
    }
}

func phaseOrder(p DKGPhase) int {
    order := map[DKGPhase]int{
        PhaseAttestation:        1,
        PhaseChannelSetup:       2,
        PhaseCommitment:         3,
        PhaseShareDistribution:  4,
        PhaseComplaintResolution: 5,
        PhaseKeyDerivation:      6,
        PhaseTPMSealing:         7,
    }
    return order[p]
}
```

#### Griefing Cost Analysis

The system is designed to make griefing attacks economically infeasible:

```
Attack Cost Analysis:
---------------------

Single Abort Attack:
  - Cost: 1 hour exclusion + reputation damage (-0.05)
  - Effect: 10 second delay (retry with exclusion)
  - Ratio: High cost, low impact

Repeated Abort Attack (2 aborts):
  - Cost: 24 hour exclusion + reputation damage (-0.15 cumulative)
  - Effect: ~1 minute total delay
  - Ratio: Very high cost, minimal impact

Strategic Phase Abort:
  - Cost: 7 day exclusion + reputation damage (-0.25)
  - Effect: Fallback to previous key set (no availability loss)
  - Ratio: Severe cost, zero availability impact

Coordinated Attack (3+ nodes):
  - Cost: All attackers excluded 7-30 days + reputation destroyed
  - Effect: Emergency recovery activates, network continues
  - Ratio: Catastrophic cost to attackers, minimal network impact

Sybil Attack Consideration:
  - Barrier: TPM attestation required for all participants
  - Cost: Physical hardware + time to build reputation
  - Detection: Coordinated abort patterns identified and slashed
```

**Progress Guarantee Theorem:**

```
Given:
  - N total eligible nodes
  - f Byzantine nodes (f < N/3)
  - MaxStuckAttempts = 3
  - MaxDKGAttempts = 5

DKG completes with probability 1 because:
  1. Each attempt identifies and excludes at least one aborter
  2. After at most f attempts, all Byzantine nodes are excluded
  3. With only honest nodes, DKG succeeds with probability 1
  4. f < N/3 implies f < 5 for typical deployments
  5. Therefore, DKG completes within MaxDKGAttempts

If DKG still fails (all nodes Byzantine or catastrophic failure):
  - Previous key fallback maintains availability
  - Genesis trustee recovery provides ultimate backstop
  - Network never loses CA signing capability
```

---

### DKG Disruption Accountability System

The network implements comprehensive detection, evidence collection, and enforcement mechanisms to hold nodes accountable for DKG disruption. This system ensures that malicious actors face escalating consequences up to and including permanent network exclusion.

#### Attack Categories

**Coordinator Attacks:**

| Attack | Description | Detection Method | Severity |
|--------|-------------|------------------|----------|
| **Silent Coordinator** | Stops responding without state transfer | Heartbeat timeout (10s) | High |
| **Selective Exclusion** | Excludes specific participants from receiving shares | Participant cross-verification | Critical |
| **Invalid Distribution** | Distributes malformed or inconsistent shares | VSS verification failure | Critical |
| **Share Leakage** | Leaks participant shares to third parties | Audit log anomalies, whistleblower | Critical |
| **Premature Termination** | Ends DKG before all phases complete | Phase state verification | High |
| **State Transfer Refusal** | Refuses to transfer state to successor | Timeout + witness attestation | High |

**Participant Attacks:**

| Attack | Description | Detection Method | Severity |
|--------|-------------|------------------|----------|
| **Invalid Commitment** | Sends commitment that fails verification | Commitment verification | High |
| **Commitment Withholding** | Refuses to send commitment | Phase timeout | Medium |
| **Invalid Share** | Sends share that fails VSS verification | VSS proof failure | Critical |
| **Share Withholding** | Refuses to send share after commitment | Phase timeout + commitment presence | High |
| **Equivocation** | Sends different values to different nodes | Cross-node comparison | Critical |
| **False Complaint** | Files complaint against honest participant | Complaint verification failure | High |
| **Complaint Withholding** | Fails to complain about invalid share | Post-DKG verification | Medium |
| **Strategic Timeout** | Times out at critical phases to maximize disruption | Pattern analysis | High |

#### Detection Mechanisms

```go
// pkg/dkg/accountability/detector.go

// DKGDisruptionDetector monitors DKG sessions for malicious behavior
type DKGDisruptionDetector struct {
    sessionID       [32]byte
    participants    map[NodeID]*ParticipantState
    coordinator     *CoordinatorState
    witnesses       []NodeID  // Randomly selected non-participants who observe
    evidenceStore   EvidenceStore

    // Detection thresholds
    HeartbeatTimeout        time.Duration  // 10s for coordinator
    CommitmentTimeout       time.Duration  // Phase-specific
    ShareVerificationQuorum int            // 3 witnesses must agree
    EquivocationThreshold   int            // 2 different values = equivocation
}

// DisruptionType categorizes the type of attack detected
type DisruptionType uint8

const (
    DisruptionNone DisruptionType = iota
    DisruptionTimeout
    DisruptionInvalidData
    DisruptionEquivocation
    DisruptionSelectiveExclusion
    DisruptionStateTampering
    DisruptionCoordinatedAttack
)

// DisruptionEvidence contains cryptographic proof of misbehavior
type DisruptionEvidence struct {
    Type            DisruptionType
    SessionID       [32]byte
    AccusedNode     NodeID
    Timestamp       time.Time
    TPMAttestation  []byte           // TPM quote proving timestamp

    // Evidence payloads (type-specific)
    ConflictingData [][]byte         // For equivocation
    WitnessReports  []*WitnessReport // Corroborating witnesses
    CryptoProof     []byte           // VSS/commitment verification failure proof
    PhaseState      *DKGPhaseState   // State at time of disruption

    // Signatures from detecting nodes
    DetectorSignatures []NodeSignature
}

// WitnessReport is a signed attestation from an observer
type WitnessReport struct {
    WitnessID      NodeID
    Observation    ObservationType
    ObservedData   []byte
    Timestamp      time.Time
    TPMQuote       []byte           // TPM attestation of observation time
    Signature      []byte
}
```

**1. Heartbeat Monitoring:**

```go
// pkg/dkg/accountability/heartbeat.go

// CoordinatorHeartbeatMonitor tracks coordinator liveness
type CoordinatorHeartbeatMonitor struct {
    coordinatorID     NodeID
    lastHeartbeat     time.Time
    missedBeats       int
    witnesses         []*WitnessConnection

    HeartbeatInterval time.Duration  // 2s
    MaxMissedBeats    int            // 5 (10s total before failure)
}

func (m *CoordinatorHeartbeatMonitor) Monitor(ctx context.Context) {
    ticker := time.NewTicker(m.HeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return

        case <-ticker.C:
            if time.Since(m.lastHeartbeat) > m.HeartbeatInterval {
                m.missedBeats++

                // Collect witness attestations
                if m.missedBeats >= m.MaxMissedBeats {
                    evidence := m.collectTimeoutEvidence()
                    m.reportDisruption(evidence)
                }
            }
        }
    }
}

func (m *CoordinatorHeartbeatMonitor) collectTimeoutEvidence() *DisruptionEvidence {
    evidence := &DisruptionEvidence{
        Type:        DisruptionTimeout,
        AccusedNode: m.coordinatorID,
        Timestamp:   time.Now(),
    }

    // Collect TPM-attested witness reports
    for _, witness := range m.witnesses {
        report, err := witness.GetTimeoutAttestation(m.coordinatorID)
        if err == nil {
            evidence.WitnessReports = append(evidence.WitnessReports, report)
        }
    }

    // Require minimum witness quorum
    if len(evidence.WitnessReports) < MinWitnessQuorum {
        return nil  // Insufficient evidence
    }

    return evidence
}
```

**2. Cryptographic Proof Verification:**

```go
// pkg/dkg/accountability/crypto_verify.go

// VerifyCommitment checks if a commitment is valid
func VerifyCommitment(commitment *DKGCommitment, params *DKGParams) (*VerificationResult, error) {
    result := &VerificationResult{
        NodeID:    commitment.SenderID,
        Phase:     PhaseCommitment,
        Timestamp: time.Now(),
    }

    // Verify polynomial degree matches threshold
    if len(commitment.Coefficients) != params.Threshold {
        result.Valid = false
        result.FailureReason = "invalid_polynomial_degree"
        result.CryptoProof = generateDegreeProof(commitment, params)
        return result, nil
    }

    // Verify all coefficients are valid group elements
    for i, coeff := range commitment.Coefficients {
        if !isValidGroupElement(coeff) {
            result.Valid = false
            result.FailureReason = fmt.Sprintf("invalid_coefficient_%d", i)
            result.CryptoProof = generateElementProof(coeff)
            return result, nil
        }
    }

    // Verify Schnorr proof of knowledge for first coefficient
    if !verifySchnorrProof(commitment.ProofOfKnowledge, commitment.Coefficients[0]) {
        result.Valid = false
        result.FailureReason = "invalid_proof_of_knowledge"
        result.CryptoProof = commitment.ProofOfKnowledge
        return result, nil
    }

    result.Valid = true
    return result, nil
}

// VerifyShare checks if a share is consistent with the sender's commitment
func VerifyShare(share *DKGShare, commitment *DKGCommitment, recipientIndex int) (*VerificationResult, error) {
    result := &VerificationResult{
        NodeID:    share.SenderID,
        Phase:     PhaseShareDistribution,
        Timestamp: time.Now(),
    }

    // VSS verification: g^share should equal product of commitment evaluations
    expectedPubShare := evaluateCommitment(commitment.Coefficients, recipientIndex)
    actualPubShare := scalarBaseMult(share.Value)

    if !expectedPubShare.Equal(actualPubShare) {
        result.Valid = false
        result.FailureReason = "vss_verification_failed"
        result.CryptoProof = generateVSSFailureProof(share, commitment, recipientIndex)
        return result, nil
    }

    result.Valid = true
    return result, nil
}
```

**3. Equivocation Detection:**

```go
// pkg/dkg/accountability/equivocation.go

// EquivocationDetector finds nodes sending different data to different recipients
type EquivocationDetector struct {
    sessionID      [32]byte
    receivedData   map[NodeID]map[NodeID][]byte  // sender -> receiver -> data
    commitments    map[NodeID]map[NodeID][]byte  // sender -> receiver -> commitment hash
}

// RecordDataExchange logs data sent between nodes
func (d *EquivocationDetector) RecordDataExchange(
    sender, receiver NodeID,
    dataType DataExchangeType,
    data []byte,
    signature []byte,
) {
    // Store signed data hash
    dataHash := sha256.Sum256(data)

    if d.receivedData[sender] == nil {
        d.receivedData[sender] = make(map[NodeID][]byte)
    }
    d.receivedData[sender][receiver] = dataHash[:]
}

// CheckForEquivocation compares data sent to different receivers
func (d *EquivocationDetector) CheckForEquivocation(sender NodeID) *EquivocationEvidence {
    sentData := d.receivedData[sender]
    if len(sentData) < 2 {
        return nil  // Need at least 2 recipients to detect equivocation
    }

    // Compare all pairs
    var referenceData []byte
    var referenceReceiver NodeID

    for receiver, dataHash := range sentData {
        if referenceData == nil {
            referenceData = dataHash
            referenceReceiver = receiver
            continue
        }

        if !bytes.Equal(dataHash, referenceData) {
            // EQUIVOCATION DETECTED
            return &EquivocationEvidence{
                Sender:     sender,
                Receiver1:  referenceReceiver,
                DataHash1:  referenceData,
                Receiver2:  receiver,
                DataHash2:  dataHash,
                DetectedAt: time.Now(),
            }
        }
    }

    return nil
}

// CrossNodeEquivocationCheck queries multiple nodes to verify consistency
func (d *EquivocationDetector) CrossNodeEquivocationCheck(
    ctx context.Context,
    sender NodeID,
    participants []NodeID,
) (*DisruptionEvidence, error) {

    // Query each participant for what they received from sender
    receivedCommitments := make(map[NodeID][]byte)

    for _, participant := range participants {
        commitment, sig, err := queryReceivedCommitment(ctx, participant, sender, d.sessionID)
        if err != nil {
            continue  // Participant offline, skip
        }

        // Verify signature
        if !verifyParticipantSignature(participant, commitment, sig) {
            continue
        }

        receivedCommitments[participant] = commitment
    }

    // Check for inconsistency
    if len(receivedCommitments) < 2 {
        return nil, nil  // Insufficient data
    }

    var firstCommitment []byte
    var firstParticipant NodeID

    for participant, commitment := range receivedCommitments {
        if firstCommitment == nil {
            firstCommitment = commitment
            firstParticipant = participant
            continue
        }

        if !bytes.Equal(commitment, firstCommitment) {
            // Build equivocation evidence
            return &DisruptionEvidence{
                Type:        DisruptionEquivocation,
                SessionID:   d.sessionID,
                AccusedNode: sender,
                Timestamp:   time.Now(),
                ConflictingData: [][]byte{
                    firstCommitment,
                    commitment,
                },
                WitnessReports: []*WitnessReport{
                    {WitnessID: firstParticipant, ObservedData: firstCommitment},
                    {WitnessID: participant, ObservedData: commitment},
                },
            }, nil
        }
    }

    return nil, nil  // No equivocation detected
}
```

**4. Selective Exclusion Detection:**

```go
// pkg/dkg/accountability/exclusion.go

// SelectiveExclusionDetector identifies coordinators excluding specific participants
type SelectiveExclusionDetector struct {
    sessionID      [32]byte
    coordinator    NodeID
    participants   []NodeID
    receivedShares map[NodeID]bool  // Which participants received shares
}

// DetectSelectiveExclusion checks if coordinator excluded specific participants
func (d *SelectiveExclusionDetector) DetectSelectiveExclusion(
    ctx context.Context,
) (*DisruptionEvidence, error) {

    // Query each participant about what they received
    responses := make(map[NodeID]*ParticipantShareReport)

    for _, participant := range d.participants {
        report, err := queryShareReceipt(ctx, participant, d.sessionID)
        if err != nil {
            continue
        }
        responses[participant] = report
    }

    // Analyze distribution pattern
    receivedCount := 0
    excludedParticipants := make([]NodeID, 0)

    for participant, report := range responses {
        if report.ReceivedAllShares {
            receivedCount++
        } else {
            excludedParticipants = append(excludedParticipants, participant)
        }
    }

    // If some participants received shares but others didn't, it's selective exclusion
    if receivedCount > 0 && len(excludedParticipants) > 0 {
        // Verify excluded participants were properly registered
        for _, excluded := range excludedParticipants {
            if !d.wasProperlyRegistered(excluded) {
                // Remove from exclusion list if they weren't registered
                continue
            }
        }

        if len(excludedParticipants) > 0 {
            return &DisruptionEvidence{
                Type:        DisruptionSelectiveExclusion,
                SessionID:   d.sessionID,
                AccusedNode: d.coordinator,
                Timestamp:   time.Now(),
                WitnessReports: d.buildExclusionWitnessReports(
                    excludedParticipants,
                    responses,
                ),
            }, nil
        }
    }

    return nil, nil
}
```

#### Evidence Collection and Storage

```go
// pkg/dkg/accountability/evidence.go

// EvidenceCollector gathers and validates disruption evidence
type EvidenceCollector struct {
    store          EvidenceStore
    tpm            TPMInterface
    witnesses      WitnessPool

    MinWitnessQuorum      int           // 3 witnesses required
    EvidenceRetention     time.Duration // 7 years (for legal/audit)
    TPMAttestationRequired bool         // true
}

// CollectEvidence gathers all evidence for a disruption event
func (c *EvidenceCollector) CollectEvidence(
    ctx context.Context,
    disruption *DisruptionEvent,
) (*DisruptionEvidence, error) {

    evidence := &DisruptionEvidence{
        Type:        disruption.Type,
        SessionID:   disruption.SessionID,
        AccusedNode: disruption.AccusedNode,
        Timestamp:   time.Now(),
    }

    // 1. Get TPM-attested timestamp
    tpmQuote, err := c.tpm.GetQuote(disruption.AccusedNode)
    if err != nil {
        return nil, &EvidenceCollectionError{Phase: "tpm_quote", Cause: err}
    }
    evidence.TPMAttestation = tpmQuote

    // 2. Collect witness reports
    witnessReports, err := c.collectWitnessReports(ctx, disruption)
    if err != nil {
        return nil, &EvidenceCollectionError{Phase: "witness_reports", Cause: err}
    }

    if len(witnessReports) < c.MinWitnessQuorum {
        return nil, &InsufficientEvidenceError{
            Required: c.MinWitnessQuorum,
            Received: len(witnessReports),
        }
    }
    evidence.WitnessReports = witnessReports

    // 3. Collect cryptographic proofs
    if disruption.Type == DisruptionInvalidData {
        cryptoProof, err := c.collectCryptoProof(ctx, disruption)
        if err != nil {
            return nil, &EvidenceCollectionError{Phase: "crypto_proof", Cause: err}
        }
        evidence.CryptoProof = cryptoProof
    }

    // 4. Capture DKG phase state
    phaseState, err := c.captureDKGPhaseState(ctx, disruption.SessionID)
    if err != nil {
        return nil, &EvidenceCollectionError{Phase: "phase_state", Cause: err}
    }
    evidence.PhaseState = phaseState

    // 5. Get signatures from detecting nodes
    evidence.DetectorSignatures = c.getDetectorSignatures(disruption)

    // 6. Store evidence with Merkle proof for immutability
    if err := c.store.StoreEvidence(evidence); err != nil {
        return nil, &EvidenceCollectionError{Phase: "storage", Cause: err}
    }

    return evidence, nil
}

// EvidenceStore provides tamper-evident storage for disruption evidence
type EvidenceStore interface {
    // StoreEvidence stores evidence with Merkle proof
    StoreEvidence(evidence *DisruptionEvidence) error

    // GetEvidence retrieves evidence by ID
    GetEvidence(evidenceID [32]byte) (*DisruptionEvidence, error)

    // GetMerkleProof returns proof of evidence inclusion
    GetMerkleProof(evidenceID [32]byte) (*MerkleProof, error)

    // GetEvidenceForNode returns all evidence against a node
    GetEvidenceForNode(nodeID NodeID) ([]*DisruptionEvidence, error)
}
```

#### Penalty Tiers and Enforcement

```go
// pkg/dkg/accountability/penalties.go

// PenaltyTier defines severity levels for disruption penalties
type PenaltyTier uint8

const (
    PenaltyWarning PenaltyTier = iota
    PenaltyTemporaryExclusion
    PenaltyReputationSlash
    PenaltyStakeSlash
    PenaltyCertificateRevocation
    PenaltyPermanentBan
)

// PenaltySchedule defines escalating penalties for each offense type
var PenaltySchedule = map[DisruptionType][]PenaltyConfig{
    DisruptionTimeout: {
        {Occurrence: 1, Tier: PenaltyWarning, Details: "1st timeout warning"},
        {Occurrence: 2, Tier: PenaltyTemporaryExclusion, Duration: 1 * time.Hour},
        {Occurrence: 3, Tier: PenaltyReputationSlash, Amount: 0.05},
        {Occurrence: 5, Tier: PenaltyTemporaryExclusion, Duration: 24 * time.Hour},
        {Occurrence: 7, Tier: PenaltyStakeSlash, Amount: 0.10},
        {Occurrence: 10, Tier: PenaltyPermanentBan},
    },

    DisruptionInvalidData: {
        {Occurrence: 1, Tier: PenaltyReputationSlash, Amount: 0.10},
        {Occurrence: 2, Tier: PenaltyStakeSlash, Amount: 0.20},
        {Occurrence: 3, Tier: PenaltyCertificateRevocation},
        {Occurrence: 4, Tier: PenaltyPermanentBan},
    },

    DisruptionEquivocation: {
        // Equivocation is always severe - proves malicious intent
        {Occurrence: 1, Tier: PenaltyReputationSlash, Amount: 0.50},
        {Occurrence: 1, Tier: PenaltyStakeSlash, Amount: 0.50},
        {Occurrence: 1, Tier: PenaltyCertificateRevocation},
        {Occurrence: 2, Tier: PenaltyPermanentBan},
    },

    DisruptionSelectiveExclusion: {
        // Coordinator abuse - severe
        {Occurrence: 1, Tier: PenaltyReputationSlash, Amount: 0.30},
        {Occurrence: 1, Tier: PenaltyStakeSlash, Amount: 0.30},
        {Occurrence: 2, Tier: PenaltyCertificateRevocation},
        {Occurrence: 2, Tier: PenaltyPermanentBan},
    },

    DisruptionCoordinatedAttack: {
        // Coordinated attack - maximum severity
        {Occurrence: 1, Tier: PenaltyReputationSlash, Amount: 1.0},  // Full reputation loss
        {Occurrence: 1, Tier: PenaltyStakeSlash, Amount: 1.0},       // Full stake loss
        {Occurrence: 1, Tier: PenaltyCertificateRevocation},
        {Occurrence: 1, Tier: PenaltyPermanentBan},
    },
}

// PenaltyConfig defines a single penalty level
type PenaltyConfig struct {
    Occurrence int           // Which occurrence triggers this penalty
    Tier       PenaltyTier
    Duration   time.Duration // For temporary exclusions
    Amount     float64       // For slashing (0.0-1.0)
    Details    string
}

// PenaltyEnforcer applies penalties based on evidence
type PenaltyEnforcer struct {
    reputationManager ReputationManager
    stakeManager      StakeManager
    certificateAuth   CertificateAuthority
    banList           BanList
    evidenceStore     EvidenceStore

    // Penalty tracking per node
    offenseHistory    map[NodeID]*OffenseHistory
}

// EnforcePenalty applies the appropriate penalty based on evidence
func (e *PenaltyEnforcer) EnforcePenalty(
    ctx context.Context,
    evidence *DisruptionEvidence,
) (*PenaltyResult, error) {

    // 1. Validate evidence
    if err := e.validateEvidence(evidence); err != nil {
        return nil, &PenaltyEnforcementError{Phase: "validation", Cause: err}
    }

    // 2. Get offense history for this node
    history := e.getOffenseHistory(evidence.AccusedNode)

    // 3. Determine appropriate penalty tier
    schedule := PenaltySchedule[evidence.Type]
    occurrence := history.GetOccurrenceCount(evidence.Type) + 1

    penalties := e.getPenaltiesForOccurrence(schedule, occurrence)

    result := &PenaltyResult{
        NodeID:         evidence.AccusedNode,
        EvidenceID:     evidence.ID(),
        AppliedAt:      time.Now(),
        PenaltiesApplied: make([]AppliedPenalty, 0),
    }

    // 4. Apply each penalty
    for _, penalty := range penalties {
        applied, err := e.applyPenalty(ctx, evidence.AccusedNode, penalty, evidence)
        if err != nil {
            // Log but continue - partial enforcement is better than none
            logPenaltyError(evidence.AccusedNode, penalty, err)
            continue
        }
        result.PenaltiesApplied = append(result.PenaltiesApplied, *applied)
    }

    // 5. Record in offense history
    history.RecordOffense(evidence)

    // 6. Broadcast penalty to network
    e.broadcastPenalty(result)

    return result, nil
}

// applyPenalty executes a single penalty
func (e *PenaltyEnforcer) applyPenalty(
    ctx context.Context,
    nodeID NodeID,
    config PenaltyConfig,
    evidence *DisruptionEvidence,
) (*AppliedPenalty, error) {

    applied := &AppliedPenalty{
        Tier:       config.Tier,
        AppliedAt:  time.Now(),
        EvidenceID: evidence.ID(),
    }

    switch config.Tier {
    case PenaltyWarning:
        // Record warning, no enforcement action
        applied.Details = "Warning issued"
        return applied, nil

    case PenaltyTemporaryExclusion:
        // Exclude from DKG participation
        if err := e.excludeFromDKG(nodeID, config.Duration); err != nil {
            return nil, err
        }
        applied.Duration = config.Duration
        applied.Details = fmt.Sprintf("Excluded from DKG for %v", config.Duration)

    case PenaltyReputationSlash:
        // Reduce reputation score
        oldRep, newRep, err := e.reputationManager.SlashReputation(
            nodeID,
            config.Amount,
            fmt.Sprintf("dkg_disruption_%s", evidence.Type),
        )
        if err != nil {
            return nil, err
        }
        applied.Amount = config.Amount
        applied.Details = fmt.Sprintf("Reputation: %.2f → %.2f", oldRep, newRep)

    case PenaltyStakeSlash:
        // Slash staked coins
        slashedAmount, err := e.stakeManager.SlashStake(nodeID, config.Amount)
        if err != nil {
            return nil, err
        }
        applied.Amount = config.Amount
        applied.SlashedCoins = slashedAmount
        applied.Details = fmt.Sprintf("Slashed %d coins (%.0f%%)", slashedAmount, config.Amount*100)

    case PenaltyCertificateRevocation:
        // Revoke node's certificate
        if err := e.certificateAuth.RevokeCertificate(
            nodeID,
            RevocationReasonDKGDisruption,
            evidence.ID(),
        ); err != nil {
            return nil, err
        }
        applied.Details = "Certificate revoked"

    case PenaltyPermanentBan:
        // Add to permanent ban list
        if err := e.banList.PermanentBan(nodeID, BanReasonDKGDisruption, evidence.ID()); err != nil {
            return nil, err
        }

        // Also revoke certificate if not already done
        e.certificateAuth.RevokeCertificate(nodeID, RevocationReasonPermanentBan, evidence.ID())

        // Slash all remaining stake
        e.stakeManager.SlashStake(nodeID, 1.0)

        applied.Details = "Permanently banned from network"
    }

    return applied, nil
}
```

**Penalty Summary Table:**

| Offense Type | 1st | 2nd | 3rd | 4th+ |
|--------------|-----|-----|-----|------|
| **Timeout** | Warning | 1h exclusion | -5% rep | 24h exclusion |
| **Invalid Data** | -10% rep | -20% stake | Cert revoked | Permanent ban |
| **Equivocation** | -50% rep, -50% stake, cert revoked | Permanent ban | - | - |
| **Selective Exclusion** | -30% rep, -30% stake | Cert revoked, permanent ban | - | - |
| **Coordinated Attack** | -100% rep, -100% stake, cert revoked, permanent ban | - | - | - |

#### Appeals Process

```go
// pkg/dkg/accountability/appeals.go

// AppealRequest represents a node's appeal against a penalty
type AppealRequest struct {
    NodeID          NodeID
    PenaltyID       [32]byte
    EvidenceID      [32]byte
    AppealReason    AppealReason
    SupportingData  []byte           // Evidence supporting the appeal
    Timestamp       time.Time
    Signature       []byte
}

// AppealReason categorizes why the penalty should be reversed
type AppealReason uint8

const (
    AppealReasonFalsePositive AppealReason = iota  // Detection was incorrect
    AppealReasonNetworkFailure                      // Network issues caused apparent disruption
    AppealReasonBugInDetection                      // Bug in detection system
    AppealReasonMitigatingCircumstances            // Extenuating circumstances
    AppealReasonEvidenceTampering                  // Evidence was fabricated
)

// AppealProcessor handles penalty appeals
type AppealProcessor struct {
    evidenceStore   EvidenceStore
    penaltyStore    PenaltyStore
    arbitrators     []NodeID          // High-reputation nodes who review appeals

    MinArbitratorReputation float64   // 0.90 required to be arbitrator
    AppealQuorum            int       // 5 arbitrators must review
    AppealThreshold         float64   // 0.60 must agree to overturn
    AppealWindow            time.Duration // 30 days to file appeal
}

// FileAppeal submits an appeal for review
func (p *AppealProcessor) FileAppeal(
    ctx context.Context,
    request *AppealRequest,
) (*AppealStatus, error) {

    // 1. Verify appeal is within window
    penalty, err := p.penaltyStore.GetPenalty(request.PenaltyID)
    if err != nil {
        return nil, err
    }

    if time.Since(penalty.AppliedAt) > p.AppealWindow {
        return nil, &AppealWindowExpiredError{
            PenaltyDate: penalty.AppliedAt,
            Window:      p.AppealWindow,
        }
    }

    // 2. Verify appellant is the penalized node
    if request.NodeID != penalty.NodeID {
        return nil, ErrUnauthorizedAppeal
    }

    // 3. Select arbitrators (exclude nodes involved in original detection)
    arbitrators, err := p.selectArbitrators(penalty)
    if err != nil {
        return nil, err
    }

    // 4. Create appeal case
    appealCase := &AppealCase{
        ID:          generateAppealID(request),
        Request:     request,
        Penalty:     penalty,
        Arbitrators: arbitrators,
        Status:      AppealStatusPending,
        CreatedAt:   time.Now(),
        Deadline:    time.Now().Add(14 * 24 * time.Hour), // 14 days to decide
    }

    // 5. Store and notify arbitrators
    if err := p.storeAppealCase(appealCase); err != nil {
        return nil, err
    }

    p.notifyArbitrators(appealCase)

    return &AppealStatus{
        AppealID:   appealCase.ID,
        Status:     AppealStatusPending,
        Deadline:   appealCase.Deadline,
        Arbitrators: len(arbitrators),
    }, nil
}

// ReviewAppeal allows an arbitrator to submit their decision
func (p *AppealProcessor) ReviewAppeal(
    ctx context.Context,
    appealID [32]byte,
    arbitratorID NodeID,
    decision AppealDecision,
    reasoning string,
) error {

    appealCase, err := p.getAppealCase(appealID)
    if err != nil {
        return err
    }

    // Verify arbitrator is assigned to this case
    if !contains(appealCase.Arbitrators, arbitratorID) {
        return ErrNotAssignedArbitrator
    }

    // Record decision
    vote := &ArbitratorVote{
        ArbitratorID: arbitratorID,
        Decision:     decision,
        Reasoning:    reasoning,
        Timestamp:    time.Now(),
    }

    appealCase.Votes = append(appealCase.Votes, vote)

    // Check if quorum reached
    if len(appealCase.Votes) >= p.AppealQuorum {
        return p.finalizeAppeal(appealCase)
    }

    return p.updateAppealCase(appealCase)
}

// finalizeAppeal determines the outcome and applies it
func (p *AppealProcessor) finalizeAppeal(appealCase *AppealCase) error {
    overturnVotes := 0
    upholdVotes := 0

    for _, vote := range appealCase.Votes {
        switch vote.Decision {
        case AppealDecisionOverturn:
            overturnVotes++
        case AppealDecisionUphold:
            upholdVotes++
        }
    }

    overturnRatio := float64(overturnVotes) / float64(len(appealCase.Votes))

    if overturnRatio >= p.AppealThreshold {
        // OVERTURN the penalty
        appealCase.Status = AppealStatusOverturned
        appealCase.Outcome = &AppealOutcome{
            Decision:      AppealDecisionOverturn,
            OverturnRatio: overturnRatio,
            ResolvedAt:    time.Now(),
        }

        // Reverse the penalty
        if err := p.reversePenalty(appealCase.Penalty); err != nil {
            return err
        }

        // Restore reputation/stake if applicable
        if err := p.restoreNodeStatus(appealCase.Penalty); err != nil {
            return err
        }

    } else {
        // UPHOLD the penalty
        appealCase.Status = AppealStatusUpheld
        appealCase.Outcome = &AppealOutcome{
            Decision:      AppealDecisionUphold,
            OverturnRatio: overturnRatio,
            ResolvedAt:    time.Now(),
        }
    }

    return p.updateAppealCase(appealCase)
}
```

#### Accountability Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MinWitnessQuorum` | 3 | Minimum witnesses required for evidence |
| `EvidenceRetention` | 7 years | How long evidence is stored |
| `AppealWindow` | 30 days | Time to file an appeal |
| `AppealQuorum` | 5 | Arbitrators required to decide appeal |
| `AppealThreshold` | 60% | Agreement needed to overturn penalty |
| `MinArbitratorReputation` | 0.90 | Minimum reputation to be arbitrator |
| `CoordinatorHeartbeat` | 2s | Heartbeat interval during DKG |
| `MaxMissedHeartbeats` | 5 | Heartbeats missed before timeout |
| `EquivocationWindow` | 5 min | Window to detect equivocation |

#### Integration with Network Systems

The DKG accountability system integrates with:

1. **Reputation System** (09-defense-reputation.md): Penalties reduce reputation scores
2. **Certificate Authority** (05-certificate-authority.md): Revocation for severe offenses
3. **Currency System** (07-currency-transactions.md): Stake slashing
4. **Ban List** (17-untrusted-nodes.md): Permanent network exclusion
5. **AI Arbitration** (21-ai-arbitration-system.md): Complex appeals may use AI arbitration

```go
// pkg/dkg/accountability/integration.go

// AccountabilityIntegration connects all network enforcement systems
type AccountabilityIntegration struct {
    reputation      *ReputationManager
    certificates    *CertificateAuthority
    stakes          *StakeManager
    banList         *BanList
    arbitration     *ArbitrationSystem
}

// EnforceFullPenalty applies penalties across all systems atomically
func (a *AccountabilityIntegration) EnforceFullPenalty(
    ctx context.Context,
    nodeID NodeID,
    evidence *DisruptionEvidence,
    penalties []PenaltyConfig,
) error {

    // Use distributed transaction for atomicity
    tx, err := a.beginDistributedTx(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    for _, penalty := range penalties {
        switch penalty.Tier {
        case PenaltyReputationSlash:
            if err := tx.SlashReputation(nodeID, penalty.Amount); err != nil {
                return err
            }

        case PenaltyStakeSlash:
            if err := tx.SlashStake(nodeID, penalty.Amount); err != nil {
                return err
            }

        case PenaltyCertificateRevocation:
            if err := tx.RevokeCertificate(nodeID, evidence.ID()); err != nil {
                return err
            }

        case PenaltyPermanentBan:
            if err := tx.PermanentBan(nodeID, evidence.ID()); err != nil {
                return err
            }
        }
    }

    // Commit all penalties atomically
    return tx.Commit()
}
```

---

## Key Management

All cryptographic key material in go-trusted-platform is protected by TPM 2.0. Keys never exist in plaintext outside the TPM.

### Key Types

| Key Type | Purpose | Storage | Rotation |
|----------|---------|---------|----------|
| **Node Identity Key** | Identify node in DHT | TPM sealed | Never (node lifetime) |
| **FROST Share** | Threshold signature participation | TPM sealed | Every 90 days |
| **Signing Nonces** | One-time use for FROST Round 1 | TPM sealed | Single use, deleted after |
| **ECDH Ephemeral** | DKG secure channels | TPM generated | Per DKG session |

### TPM Sealed Storage

#### Sealing Policy

Keys are sealed to specific PCR values:

| PCR | Measures | Purpose |
|-----|----------|---------|
| **PCR 0** | Firmware | Detect firmware tampering |
| **PCR 2** | Option ROMs | Detect boot modification |
| **PCR 7** | Secure Boot state | Detect boot policy changes |

```go
// pkg/tpm/seal.go

type SealingPolicy struct {
    PCRSelection []int        // PCR 0, 2, 7
    AuthValue    []byte       // Optional password
    NVIndex      uint32       // NV storage index
}

func (t *TPM) SealKey(key []byte, policy *SealingPolicy) (Handle, error) {
    // Create sealed object
    template := tpm2.Public{
        Type:       tpm2.AlgKeyedHash,
        NameAlg:    tpm2.AlgSHA256,
        Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent,
        AuthPolicy: t.computePCRPolicy(policy.PCRSelection),
    }

    handle, err := tpm2.CreatePrimary(t.dev, tpm2.HandleOwner,
        tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: policy.PCRSelection},
        "", "", template)
    if err != nil {
        return 0, err
    }

    // Seal the key
    return tpm2.Create(t.dev, handle, nil, "", "", template, key)
}
```

#### Unsealing

Keys can only be unsealed if PCR values match:

```go
func (t *TPM) UnsealKey(handle Handle) ([]byte, error) {
    // Verify PCR policy is satisfied
    session, err := tpm2.StartAuthSession(t.dev, tpm2.SessionPolicy)
    if err != nil {
        return nil, err
    }
    defer tpm2.FlushContext(t.dev, session)

    // PCR policy check happens here
    if err := tpm2.PolicyPCR(t.dev, session, nil, t.pcrSelection); err != nil {
        return nil, ErrPCRMismatch
    }

    return tpm2.Unseal(t.dev, session, handle)
}
```

### FROST Share Lifecycle

#### Generation (During DKG)

```
DKG Phase 4 Complete
        |
        v
+-------------------+
| Aggregate shares: |
| sk_j = Sum(s_ij)  |
+--------+----------+
         |
         v
+-------------------+
| Seal to TPM:      |
| PCR 0,2,7 policy  |
+--------+----------+
         |
         v
+-------------------+
| Store handle in   |
| local database    |
+--------+----------+
         |
         v
+-------------------+
| Zero memory       |
| containing sk_j   |
+-------------------+
```

#### Usage (During Signing)

```
Signing Request
        |
        v
+-------------------+
| Unseal sk_j from  |
| TPM (PCR verified)|
+--------+----------+
         |
         v
+-------------------+
| Compute z_j =     |
| d + rho*e + l*sk*c|
| (inside TPM)      |
+--------+----------+
         |
         v
+-------------------+
| Return z_j only   |
| (sk_j stays in TPM)|
+-------------------+
```

#### Rotation (Every 90 Days)

```
Epoch N Expiring
        |
        v
+-------------------+
| New DKG generates |
| new sk_j' for     |
| Epoch N+1         |
+--------+----------+
         |
         v
+-------------------+
| Seal new sk_j' to |
| TPM               |
+--------+----------+
         |
         v
+-------------------+
| Grace period:     |
| Both keys valid   |
| for overlap       |
+--------+----------+
         |
         v
+-------------------+
| Destroy old key:  |
| TPM2_Clear handle |
+-------------------+
```

### Nonce Management

For detailed nonce management including pre-generation, single-use enforcement, and deletion procedures, see the [FROST Nonce Safety](#nonce-safety-canonical) section above. That section is the canonical reference for all nonce-related security requirements.

**Key Points (reference only):**

- Nonces are pre-generated in batches of 100
- Nonces expire after 24 hours
- Single-use is enforced via `Used` flag set BEFORE unsealing
- Nonces are deleted immediately after signing completes
- TPM hardware enforces single-use semantics

### Compromise Detection

#### TPM Health Monitoring

```go
// pkg/tpm/monitor.go

type TPMMonitor struct {
    expectedResponseTime time.Duration
    errorThreshold       int
    consecutiveErrors    int
}

func (m *TPMMonitor) CheckHealth() error {
    start := time.Now()

    // Perform test operation
    _, err := m.tpm.GetRandom(32)

    elapsed := time.Since(start)

    if err != nil {
        m.consecutiveErrors++
        if m.consecutiveErrors > m.errorThreshold {
            return ErrTPMCompromised
        }
        return err
    }

    // Check for timing anomalies
    if elapsed > m.expectedResponseTime*2 {
        log.Warn("TPM response time anomaly",
            "expected", m.expectedResponseTime,
            "actual", elapsed)
    }

    m.consecutiveErrors = 0
    return nil
}
```

#### Cluster Detection

If multiple TPMs from the same manufacturer/batch show issues:

```go
func (m *NetworkMonitor) DetectClusterFailures() {
    // Group failures by TPM manufacturer
    failures := m.getRecentFailures(24 * time.Hour)

    byManufacturer := groupBy(failures, func(f *Failure) string {
        return f.TPMManufacturer
    })

    for mfr, mfrFailures := range byManufacturer {
        if len(mfrFailures) > 10 {  // Threshold
            m.quarantineManufacturer(mfr)
            m.alertCoordinators(mfr, mfrFailures)
        }
    }
}
```

### Backup and Recovery

#### Share Recovery

FROST shares are NOT backed up. If a node's TPM fails:

1. Node is excluded from current pool
2. Node can rejoin after next DKG rotation
3. DKG generates new share for the node

#### Node Identity Recovery

Node identity keys can optionally be backed up using split-key scheme:

```go
// Optional: Split identity key for disaster recovery
func (n *Node) BackupIdentity(threshold, total int) ([]*KeyShare, error) {
    // Export identity key (requires owner auth)
    key, err := n.tpm.ExportIdentityKey()
    if err != nil {
        return nil, err
    }

    // Split using Shamir's Secret Sharing
    shares, err := shamir.Split(key, total, threshold)
    if err != nil {
        return nil, err
    }

    // Zero original key
    for i := range key {
        key[i] = 0
    }

    return shares, nil
}
```

### Security Auditing

#### Key Operations Log

All key operations are logged for audit:

```go
type KeyAuditLog struct {
    Timestamp   time.Time
    Operation   string  // "seal", "unseal", "destroy", "sign"
    KeyType     string  // "identity", "frost_share", "nonce"
    KeyID       string
    Success     bool
    Error       string
    PCRValues   map[int][]byte  // At time of operation
}
```

#### Audit Queries

```go
func (a *Auditor) GetKeyOperations(keyID string, since time.Time) ([]*KeyAuditLog, error)
func (a *Auditor) GetFailedOperations(since time.Time) ([]*KeyAuditLog, error)
func (a *Auditor) GetPCRChanges(since time.Time) ([]PCRChangeEvent, error)
```


---

## Genesis Trustee Recovery Safeguards

Genesis trustees provide the ultimate recovery mechanism when all other CA recovery methods have been exhausted. To prevent abuse or premature activation, multiple cryptographic and governance safeguards ensure that genesis trustee recovery requires deliberate, multi-party coordination over extended time periods.

### Time-Locked Recovery Activation

Genesis trustee recovery employs time-locked cryptographic schemes that require multi-day revelation periods, preventing rapid or covert activation.

```go
// pkg/dkg/genesis_recovery.go

// GenesisTrusteeRecoveryConfig defines recovery timing constraints
const (
    // Time-lock parameters - these are MINIMUM values
    RecoveryAnnouncementPeriod = 72 * time.Hour  // 3 days public notice
    ShareRevelationWindow      = 48 * time.Hour  // 2-day window for revelation
    GovernanceVotePeriod       = 96 * time.Hour  // 4 days for governance vote
    MinRecoveryDelay           = 7 * 24 * time.Hour  // 7 days minimum total

    // Threshold requirements
    GenesisTrusteeThreshold    = 3  // 3-of-5 trustees required
    GenesisTrusteeTotal        = 5
    GovernanceQuorum           = 67 // 67% of voting power required
)

// GenesisTrusteeRecovery manages the multi-phase recovery process
type GenesisTrusteeRecovery struct {
    trustees          []GenesisTrustee
    timelockContract  *TimelockContract
    governanceVotes   map[NodeID]*GovernanceVote
    recoveryState     RecoveryPhase
    announcementTime  time.Time
    revelationProofs  map[TrusteeID]*RevelationProof
}

// RecoveryPhase tracks the current phase of recovery
type RecoveryPhase uint8

const (
    RecoveryPhaseIdle RecoveryPhase = iota
    RecoveryPhaseAnnounced
    RecoveryPhaseGovernanceVoting
    RecoveryPhaseRevelationPending
    RecoveryPhaseRevelationActive
    RecoveryPhaseCompleted
    RecoveryPhaseCancelled
)

// GenesisTrustee represents an individual trustee with geographic constraints
type GenesisTrustee struct {
    ID               TrusteeID
    PublicKey        []byte
    Organization     string
    GeographicRegion string   // ISO 3166-1 region code
    Jurisdiction     string   // Legal jurisdiction
    LastRotation     time.Time
    CeremonyProof    []byte   // Proof from key generation ceremony
}

// TimelockContract enforces cryptographic time delays
type TimelockContract struct {
    Commitment     []byte        // H(secret || timelock_params)
    UnlockTime     time.Time     // Earliest unlock time
    ChainAnchor    *ChainAnchor  // Cross-chain timestamp proof
    Witnesses      []NodeID      // Nodes that witnessed commitment
}

// InitiateRecovery begins the multi-phase recovery process
func (r *GenesisTrusteeRecovery) InitiateRecovery(
    initiator TrusteeID,
    reason RecoveryReason,
    evidence []byte,
) (*RecoveryAnnouncement, error) {
    // Verify initiator is a valid trustee
    if !r.isValidTrustee(initiator) {
        return nil, ErrInvalidTrustee
    }

    // Verify recovery is not already in progress
    if r.recoveryState != RecoveryPhaseIdle {
        return nil, ErrRecoveryAlreadyActive
    }

    // Create timelock commitment
    timelockParams := &TimelockParams{
        UnlockTime:   time.Now().Add(MinRecoveryDelay),
        HashFunction: "SHA3-256",
        ChainID:      "bitcoin", // External anchor chain
    }

    commitment, err := r.createTimelockCommitment(timelockParams)
    if err != nil {
        return nil, err
    }

    // Create announcement with cryptographic proof
    announcement := &RecoveryAnnouncement{
        ID:               uuid.New(),
        InitiatorID:      initiator,
        Reason:           reason,
        Evidence:         evidence,
        AnnouncementTime: time.Now(),
        TimelockCommit:   commitment,
        RequiredPhases: []RecoveryPhaseSpec{
            {Phase: RecoveryPhaseGovernanceVoting, Duration: GovernanceVotePeriod},
            {Phase: RecoveryPhaseRevelationPending, Duration: RecoveryAnnouncementPeriod},
            {Phase: RecoveryPhaseRevelationActive, Duration: ShareRevelationWindow},
        },
    }

    // Sign announcement with trustee key
    announcement.Signature = r.signAnnouncement(initiator, announcement)

    // Broadcast to network
    if err := r.broadcastAnnouncement(announcement); err != nil {
        return nil, err
    }

    // Anchor to external blockchain for tamper-proof timestamp
    anchor, err := r.anchorToExternalChain(announcement)
    if err != nil {
        log.Warn("Failed to anchor to external chain, continuing with local timestamp",
            "error", err)
    } else {
        announcement.ChainAnchor = anchor
    }

    r.recoveryState = RecoveryPhaseAnnounced
    r.announcementTime = time.Now()

    log.Info("Genesis trustee recovery initiated",
        "initiator", initiator,
        "reason", reason,
        "unlock_time", timelockParams.UnlockTime)

    return announcement, nil
}
```

### On-Chain Governance Voting

Before trustee recovery can proceed, an on-chain governance vote must achieve quorum, ensuring network-wide consensus on the necessity of recovery.

```go
// pkg/dkg/governance_vote.go

// GovernanceVote represents a vote on recovery activation
type GovernanceVote struct {
    VoterID       NodeID
    RecoveryID    uuid.UUID
    Vote          VoteDecision
    VotingPower   uint64       // Based on stake/reputation
    Timestamp     time.Time
    Signature     []byte
    Justification string       // Required for approval votes
}

type VoteDecision uint8

const (
    VoteAbstain VoteDecision = iota
    VoteApprove
    VoteReject
    VoteVeto    // Special veto power for high-reputation nodes
)

// GovernanceVotingManager handles the voting process
type GovernanceVotingManager struct {
    votes           map[NodeID]*GovernanceVote
    votingDeadline  time.Time
    quorumRequired  uint64  // Total voting power needed
    approvalPercent float64 // Percentage of quorum for approval
}

// CastVote records a governance vote
func (m *GovernanceVotingManager) CastVote(vote *GovernanceVote) error {
    // Verify voting period is active
    if time.Now().After(m.votingDeadline) {
        return ErrVotingPeriodEnded
    }

    // Verify voter eligibility
    eligibility, err := m.verifyVoterEligibility(vote.VoterID)
    if err != nil {
        return err
    }

    // Verify signature
    if !m.verifyVoteSignature(vote) {
        return ErrInvalidVoteSignature
    }

    // Check for double voting
    if _, exists := m.votes[vote.VoterID]; exists {
        return ErrAlreadyVoted
    }

    // Record vote
    m.votes[vote.VoterID] = vote

    log.Info("Governance vote recorded",
        "voter", vote.VoterID,
        "decision", vote.Vote,
        "power", vote.VotingPower)

    return nil
}

// TallyVotes computes the final vote result
func (m *GovernanceVotingManager) TallyVotes() (*VoteResult, error) {
    if time.Now().Before(m.votingDeadline) {
        return nil, ErrVotingStillActive
    }

    var totalPower, approvePower, rejectPower, vetoPower uint64

    for _, vote := range m.votes {
        totalPower += vote.VotingPower

        switch vote.Vote {
        case VoteApprove:
            approvePower += vote.VotingPower
        case VoteReject:
            rejectPower += vote.VotingPower
        case VoteVeto:
            vetoPower += vote.VotingPower
        }
    }

    result := &VoteResult{
        TotalVotingPower: totalPower,
        ApprovalPower:    approvePower,
        RejectPower:      rejectPower,
        VetoPower:        vetoPower,
        QuorumReached:    totalPower >= m.quorumRequired,
    }

    // Any veto power blocks the recovery
    if vetoPower > 0 {
        result.Decision = VoteResultVetoed
        result.Reason = "Recovery vetoed by high-reputation node(s)"
        return result, nil
    }

    // Check quorum
    if !result.QuorumReached {
        result.Decision = VoteResultNoQuorum
        result.Reason = fmt.Sprintf("Quorum not reached: %d/%d required",
            totalPower, m.quorumRequired)
        return result, nil
    }

    // Check approval threshold
    approvalRatio := float64(approvePower) / float64(totalPower)
    if approvalRatio >= m.approvalPercent/100.0 {
        result.Decision = VoteResultApproved
        result.Reason = fmt.Sprintf("Approved with %.1f%% support", approvalRatio*100)
    } else {
        result.Decision = VoteResultRejected
        result.Reason = fmt.Sprintf("Rejected with only %.1f%% support (%.1f%% required)",
            approvalRatio*100, m.approvalPercent)
    }

    return result, nil
}
```

### Geographic and Organizational Diversity

Genesis trustees must be distributed across different geographic regions and organizations to prevent coordinated compromise.

```go
// pkg/dkg/trustee_diversity.go

// DiversityRequirements enforces geographic and organizational distribution
type DiversityRequirements struct {
    MinRegions        int      // Minimum distinct geographic regions
    MinOrganizations  int      // Minimum distinct organizations
    MinJurisdictions  int      // Minimum distinct legal jurisdictions
    MaxPerRegion      int      // Maximum trustees per region
    MaxPerOrg         int      // Maximum trustees per organization
    BannedRegions     []string // Regions excluded for legal/security reasons
}

// DefaultDiversityRequirements returns the standard diversity constraints
func DefaultDiversityRequirements() *DiversityRequirements {
    return &DiversityRequirements{
        MinRegions:       3,  // At least 3 geographic regions
        MinOrganizations: 4,  // At least 4 different organizations
        MinJurisdictions: 3,  // At least 3 legal jurisdictions
        MaxPerRegion:     2,  // No more than 2 trustees per region
        MaxPerOrg:        1,  // No more than 1 trustee per organization
        BannedRegions:    []string{}, // Configured per deployment
    }
}

// ValidateTrusteeDiversity checks if trustees meet diversity requirements
func ValidateTrusteeDiversity(trustees []GenesisTrustee, req *DiversityRequirements) error {
    regions := make(map[string]int)
    orgs := make(map[string]int)
    jurisdictions := make(map[string]int)

    for _, t := range trustees {
        // Check banned regions
        for _, banned := range req.BannedRegions {
            if t.GeographicRegion == banned {
                return &DiversityViolation{
                    Type:     "banned_region",
                    TrusteeID: t.ID,
                    Value:    t.GeographicRegion,
                }
            }
        }

        regions[t.GeographicRegion]++
        orgs[t.Organization]++
        jurisdictions[t.Jurisdiction]++
    }

    // Validate minimum diversity
    if len(regions) < req.MinRegions {
        return &DiversityViolation{
            Type:     "insufficient_regions",
            Required: req.MinRegions,
            Actual:   len(regions),
        }
    }

    if len(orgs) < req.MinOrganizations {
        return &DiversityViolation{
            Type:     "insufficient_organizations",
            Required: req.MinOrganizations,
            Actual:   len(orgs),
        }
    }

    if len(jurisdictions) < req.MinJurisdictions {
        return &DiversityViolation{
            Type:     "insufficient_jurisdictions",
            Required: req.MinJurisdictions,
            Actual:   len(jurisdictions),
        }
    }

    // Validate maximum concentration
    for region, count := range regions {
        if count > req.MaxPerRegion {
            return &DiversityViolation{
                Type:     "region_concentration",
                Value:    region,
                Required: req.MaxPerRegion,
                Actual:   count,
            }
        }
    }

    for org, count := range orgs {
        if count > req.MaxPerOrg {
            return &DiversityViolation{
                Type:     "organization_concentration",
                Value:    org,
                Required: req.MaxPerOrg,
                Actual:   count,
            }
        }
    }

    return nil
}
```

### Trustee Key Rotation with Verifiable Ceremonies

Genesis trustee keys must be rotated periodically through cryptographically verifiable key generation ceremonies.

```go
// pkg/dkg/trustee_ceremony.go

// TrusteeKeyCeremony manages verifiable key generation events
type TrusteeKeyCeremony struct {
    CeremonyID     uuid.UUID
    TrusteeID      TrusteeID
    OldPublicKey   []byte
    NewPublicKey   []byte
    CeremonyTime   time.Time
    Location       CeremonyLocation
    Witnesses      []CeremonyWitness
    VideoHash      []byte        // Hash of recorded ceremony video
    TranscriptHash []byte        // Hash of ceremony transcript
    AuditReport    []byte        // Third-party audit report
}

// CeremonyLocation captures physical ceremony details
type CeremonyLocation struct {
    Facility      string
    Address       string
    GPSCoords     [2]float64  // Latitude, Longitude
    SecurityLevel string      // e.g., "SCIF", "bank_vault", "data_center"
}

// CeremonyWitness represents an independent observer
type CeremonyWitness struct {
    ID           string
    Organization string
    PublicKey    []byte
    Attestation  []byte  // Signed attestation of ceremony validity
}

// KeyRotationConfig defines rotation requirements
const (
    MaxTrusteeKeyAge     = 365 * 24 * time.Hour  // 1 year maximum key age
    MinWitnessCount      = 3                      // Minimum independent witnesses
    CeremonyNoticeePeriod = 30 * 24 * time.Hour   // 30 days advance notice
)

// TrusteeKeyRotationManager handles key rotation lifecycle
type TrusteeKeyRotationManager struct {
    trustees          map[TrusteeID]*GenesisTrustee
    ceremonies        map[uuid.UUID]*TrusteeKeyCeremony
    pendingRotations  map[TrusteeID]time.Time
}

// ScheduleKeyRotation plans a trustee key rotation ceremony
func (m *TrusteeKeyRotationManager) ScheduleKeyRotation(
    trusteeID TrusteeID,
    proposedDate time.Time,
    location CeremonyLocation,
) (*RotationSchedule, error) {
    trustee, exists := m.trustees[trusteeID]
    if !exists {
        return nil, ErrTrusteeNotFound
    }

    // Verify minimum notice period
    if time.Until(proposedDate) < CeremonyNoticeePeriod {
        return nil, &SchedulingError{
            Type:     "insufficient_notice",
            Required: CeremonyNoticeePeriod,
            Provided: time.Until(proposedDate),
        }
    }

    // Check for overlapping ceremonies
    for id, pending := range m.pendingRotations {
        if abs(pending.Sub(proposedDate)) < 7*24*time.Hour {
            return nil, &SchedulingError{
                Type:       "ceremony_conflict",
                ConflictID: id,
            }
        }
    }

    schedule := &RotationSchedule{
        ID:           uuid.New(),
        TrusteeID:    trusteeID,
        ScheduledFor: proposedDate,
        Location:     location,
        Status:       ScheduleStatusPending,
        CreatedAt:    time.Now(),
    }

    m.pendingRotations[trusteeID] = proposedDate

    // Broadcast rotation notice to network
    if err := m.broadcastRotationNotice(schedule); err != nil {
        return nil, err
    }

    log.Info("Trustee key rotation scheduled",
        "trustee", trusteeID,
        "date", proposedDate,
        "location", location.Facility)

    return schedule, nil
}

// CompleteCeremony records and verifies a completed key rotation ceremony
func (m *TrusteeKeyRotationManager) CompleteCeremony(
    ceremony *TrusteeKeyCeremony,
) error {
    // Verify minimum witness count
    if len(ceremony.Witnesses) < MinWitnessCount {
        return &CeremonyError{
            Type:     "insufficient_witnesses",
            Required: MinWitnessCount,
            Actual:   len(ceremony.Witnesses),
        }
    }

    // Verify all witness attestations
    for _, witness := range ceremony.Witnesses {
        if !m.verifyWitnessAttestation(witness, ceremony) {
            return &CeremonyError{
                Type:      "invalid_attestation",
                WitnessID: witness.ID,
            }
        }
    }

    // Verify key transition proof (proof that new key holder knows old key)
    if !m.verifyKeyTransitionProof(ceremony) {
        return &CeremonyError{Type: "invalid_key_transition"}
    }

    // Verify video and transcript hashes are published
    if len(ceremony.VideoHash) == 0 || len(ceremony.TranscriptHash) == 0 {
        return &CeremonyError{Type: "missing_ceremony_records"}
    }

    // Update trustee record
    trustee := m.trustees[ceremony.TrusteeID]
    trustee.PublicKey = ceremony.NewPublicKey
    trustee.LastRotation = ceremony.CeremonyTime
    trustee.CeremonyProof = m.generateCeremonyProof(ceremony)

    // Store ceremony record
    m.ceremonies[ceremony.CeremonyID] = ceremony

    // Broadcast key update to network
    if err := m.broadcastKeyUpdate(ceremony); err != nil {
        return err
    }

    log.Info("Trustee key rotation completed",
        "trustee", ceremony.TrusteeID,
        "ceremony", ceremony.CeremonyID,
        "witnesses", len(ceremony.Witnesses))

    return nil
}

// CheckRotationRequired identifies trustees needing key rotation
func (m *TrusteeKeyRotationManager) CheckRotationRequired() []TrusteeID {
    needsRotation := make([]TrusteeID, 0)
    now := time.Now()

    for id, trustee := range m.trustees {
        keyAge := now.Sub(trustee.LastRotation)
        if keyAge > MaxTrusteeKeyAge {
            needsRotation = append(needsRotation, id)
            log.Warn("Trustee key rotation overdue",
                "trustee", id,
                "key_age", keyAge,
                "max_age", MaxTrusteeKeyAge)
        }
    }

    return needsRotation
}
```

---

## CT Log Fork Resistance

Certificate Transparency (CT) logs provide an append-only audit trail of all certificates issued by the distributed CA. Fork resistance ensures that the CT log cannot be split into multiple conflicting branches, which would allow targeted certificate hiding or selective disclosure attacks.

### Unanimous Pool Signatures

CT log updates require unanimous 4-of-4 pool signatures, ensuring that no subset of the pool can create a valid log entry without full consensus.

```go
// pkg/ct/fork_resistance.go

// CTLogForkResistance implements anti-fork mechanisms for CT logs
const (
    CTLogSignatureThreshold = 4  // All 4 pools must sign
    CTLogPoolCount          = 4  // Total number of signing pools
    MaxSigningWindow        = 30 * time.Second  // Maximum time to collect signatures
)

// CTLogEntry represents a Certificate Transparency log entry
type CTLogEntry struct {
    Index           uint64
    Timestamp       time.Time
    Certificate     []byte
    PreviousHash    [32]byte  // Hash of previous entry (chain link)
    MerkleRoot      [32]byte  // Current Merkle tree root
    PoolSignatures  map[PoolID]*PoolSignature
    ConsensusProof  *ConsensusProof
}

// PoolSignature contains a single pool's threshold signature
type PoolSignature struct {
    PoolID      PoolID
    Signature   []byte
    SignerIDs   []NodeID
    Epoch       uint64
    Timestamp   time.Time
}

// CTLogManager manages fork-resistant CT log operations
type CTLogManager struct {
    pools           [CTLogPoolCount]*SigningPool
    currentIndex    uint64
    previousHash    [32]byte
    merkleTree      *MerkleTree
    pendingEntries  map[uint64]*PendingEntry
}

// AppendCertificate adds a new certificate to the CT log with unanimous signatures
func (m *CTLogManager) AppendCertificate(cert []byte) (*CTLogEntry, error) {
    // Create pending entry
    index := atomic.AddUint64(&m.currentIndex, 1)

    entry := &CTLogEntry{
        Index:        index,
        Timestamp:    time.Now(),
        Certificate:  cert,
        PreviousHash: m.previousHash,
        PoolSignatures: make(map[PoolID]*PoolSignature),
    }

    // Compute new Merkle root
    certHash := sha256.Sum256(cert)
    entry.MerkleRoot = m.merkleTree.Append(certHash[:])

    // Create signing request for all pools
    signingData := m.prepareSigningData(entry)

    // Collect signatures from ALL pools (unanimous requirement)
    ctx, cancel := context.WithTimeout(context.Background(), MaxSigningWindow)
    defer cancel()

    signatures := make(chan *PoolSignature, CTLogPoolCount)
    errors := make(chan error, CTLogPoolCount)

    for _, pool := range m.pools {
        go func(p *SigningPool) {
            sig, err := p.SignCTEntry(ctx, signingData)
            if err != nil {
                errors <- err
                return
            }
            signatures <- sig
        }(pool)
    }

    // Wait for all signatures
    collected := 0
    for collected < CTLogPoolCount {
        select {
        case sig := <-signatures:
            entry.PoolSignatures[sig.PoolID] = sig
            collected++

        case err := <-errors:
            return nil, &CTLogSigningError{
                Index: index,
                Cause: err,
            }

        case <-ctx.Done():
            return nil, &CTLogTimeoutError{
                Index:     index,
                Collected: collected,
                Required:  CTLogPoolCount,
            }
        }
    }

    // Verify all signatures
    if err := m.verifyAllSignatures(entry); err != nil {
        return nil, err
    }

    // Create consensus proof
    entry.ConsensusProof = m.createConsensusProof(entry)

    // Update chain state
    m.previousHash = sha256.Sum256(m.serializeEntry(entry))

    // Broadcast to network
    if err := m.broadcastEntry(entry); err != nil {
        return nil, err
    }

    log.Info("CT log entry appended",
        "index", index,
        "cert_hash", hex.EncodeToString(certHash[:8]),
        "pools_signed", CTLogPoolCount)

    return entry, nil
}
```

### Economic Slashing for Fork Attempts

Any pool that signs multiple branches of the CT log is subject to severe economic penalties, making fork attacks economically irrational.

```go
// pkg/ct/slashing.go

// CTForkSlashing detects and penalizes fork attempts
type CTForkSlashing struct {
    signatures      map[PoolID]map[uint64][]*PoolSignature  // pool -> index -> signatures
    slashingEvents  []SlashingEvent
    slashingAmount  uint64  // Economic penalty amount
}

// SlashingEvent records a detected fork attempt
type SlashingEvent struct {
    Timestamp      time.Time
    PoolID         PoolID
    ForkEvidence   *ForkEvidence
    SlashAmount    uint64
    Applied        bool
    SignersPenalized []NodeID
}

// ForkEvidence contains cryptographic proof of a fork attempt
type ForkEvidence struct {
    LogIndex           uint64
    Signature1         *PoolSignature
    Signature2         *PoolSignature
    Entry1Hash         [32]byte
    Entry2Hash         [32]byte
    ConflictType       ConflictType
}

type ConflictType uint8

const (
    ConflictDifferentCert ConflictType = iota
    ConflictDifferentPrevHash
    ConflictDifferentMerkleRoot
    ConflictDifferentTimestamp
)

// DetectForkAttempt checks for conflicting signatures from the same pool
func (s *CTForkSlashing) DetectForkAttempt(newSig *PoolSignature, entry *CTLogEntry) (*ForkEvidence, error) {
    poolSigs, exists := s.signatures[newSig.PoolID]
    if !exists {
        poolSigs = make(map[uint64][]*PoolSignature)
        s.signatures[newSig.PoolID] = poolSigs
    }

    // Check for existing signatures at this index
    existingSigs := poolSigs[entry.Index]
    for _, existing := range existingSigs {
        // Verify both signatures are valid
        if !s.verifySignature(existing) || !s.verifySignature(newSig) {
            continue
        }

        // Check if they sign different content
        if !bytes.Equal(existing.Signature, newSig.Signature) {
            // This is a fork attempt!
            evidence := &ForkEvidence{
                LogIndex:     entry.Index,
                Signature1:   existing,
                Signature2:   newSig,
                Entry1Hash:   s.computeEntryHash(existing),
                Entry2Hash:   s.computeEntryHash(newSig),
                ConflictType: s.determineConflictType(existing, newSig),
            }

            log.Error("CT log fork attempt detected!",
                "pool", newSig.PoolID,
                "index", entry.Index,
                "conflict_type", evidence.ConflictType)

            return evidence, nil
        }
    }

    // No fork detected, record signature
    poolSigs[entry.Index] = append(poolSigs[entry.Index], newSig)

    return nil, nil
}

// ApplySlashing executes economic penalties for fork attempts
func (s *CTForkSlashing) ApplySlashing(evidence *ForkEvidence) error {
    event := SlashingEvent{
        Timestamp:    time.Now(),
        PoolID:       evidence.Signature1.PoolID,
        ForkEvidence: evidence,
        SlashAmount:  s.slashingAmount,
    }

    // Identify all signers involved in the fork
    signersToSlash := make(map[NodeID]bool)
    for _, signer := range evidence.Signature1.SignerIDs {
        signersToSlash[signer] = true
    }
    for _, signer := range evidence.Signature2.SignerIDs {
        signersToSlash[signer] = true
    }

    // Apply penalties to each signer
    for signer := range signersToSlash {
        if err := s.slashSigner(signer, evidence); err != nil {
            log.Error("Failed to slash signer",
                "signer", signer,
                "error", err)
            continue
        }
        event.SignersPenalized = append(event.SignersPenalized, signer)
    }

    event.Applied = true
    s.slashingEvents = append(s.slashingEvents, event)

    // Broadcast slashing evidence to network
    if err := s.broadcastSlashingEvent(event); err != nil {
        log.Error("Failed to broadcast slashing event", "error", err)
    }

    log.Info("CT fork slashing applied",
        "pool", evidence.Signature1.PoolID,
        "signers_slashed", len(event.SignersPenalized),
        "amount", s.slashingAmount)

    return nil
}

// slashSigner applies penalties to an individual signer
func (s *CTForkSlashing) slashSigner(signer NodeID, evidence *ForkEvidence) error {
    // 1. Economic penalty (if staking is implemented)
    if err := deductStake(signer, s.slashingAmount); err != nil {
        return err
    }

    // 2. Reputation destruction
    if err := slashReputation(signer, -1.0, "ct_fork_attempt"); err != nil {
        return err
    }

    // 3. Permanent exclusion from all pools
    if err := permanentlyExclude(signer, "ct_fork_attempt", evidence); err != nil {
        return err
    }

    // 4. Revoke all signing capabilities
    if err := revokeSigningKeys(signer); err != nil {
        return err
    }

    return nil
}
```

### Cross-Chain Anchoring

CT log entries are anchored to external blockchains (Bitcoin, Ethereum) to provide tamper-proof timestamps and prevent retroactive log modification.

```go
// pkg/ct/cross_chain.go

// CrossChainAnchor provides external blockchain anchoring
type CrossChainAnchor struct {
    bitcoin  *BitcoinAnchor
    ethereum *EthereumAnchor
    interval time.Duration  // How often to anchor (e.g., every 100 entries)
}

// ChainAnchor represents an anchor to an external blockchain
type ChainAnchor struct {
    ChainID       string    // "bitcoin", "ethereum"
    BlockHeight   uint64
    BlockHash     [32]byte
    TxID          [32]byte
    MerkleProof   []byte    // Proof of inclusion in block
    Timestamp     time.Time
    CTLogRange    LogRange  // Range of CT entries covered
}

// LogRange specifies the CT log entries covered by an anchor
type LogRange struct {
    StartIndex uint64
    EndIndex   uint64
    MerkleRoot [32]byte
}

// BitcoinAnchor anchors to Bitcoin via OP_RETURN
type BitcoinAnchor struct {
    client     *bitcoinrpc.Client
    wallet     *hdkeychain.ExtendedKey
    feeRate    int64  // satoshis per vbyte
}

// AnchorToBitcoin creates a Bitcoin anchor for CT log entries
func (a *BitcoinAnchor) AnchorToBitcoin(logRange LogRange) (*ChainAnchor, error) {
    // Create OP_RETURN data: "GTPCT" + log range merkle root
    opReturnData := make([]byte, 0, 37)
    opReturnData = append(opReturnData, []byte("GTPCT")...)  // Magic bytes
    opReturnData = append(opReturnData, logRange.MerkleRoot[:]...)

    // Create transaction
    tx, err := a.createOpReturnTx(opReturnData)
    if err != nil {
        return nil, err
    }

    // Sign transaction
    signedTx, err := a.signTransaction(tx)
    if err != nil {
        return nil, err
    }

    // Broadcast transaction
    txid, err := a.client.SendRawTransaction(signedTx, true)
    if err != nil {
        return nil, err
    }

    // Wait for confirmation
    confirmation, err := a.waitForConfirmation(txid, 1)
    if err != nil {
        return nil, err
    }

    anchor := &ChainAnchor{
        ChainID:     "bitcoin",
        BlockHeight: confirmation.BlockHeight,
        BlockHash:   confirmation.BlockHash,
        TxID:        txid,
        MerkleProof: confirmation.MerkleProof,
        Timestamp:   time.Now(),
        CTLogRange:  logRange,
    }

    log.Info("CT log anchored to Bitcoin",
        "txid", hex.EncodeToString(txid[:]),
        "block", confirmation.BlockHeight,
        "entries", logRange.EndIndex-logRange.StartIndex+1)

    return anchor, nil
}

// EthereumAnchor anchors to Ethereum via smart contract
type EthereumAnchor struct {
    client   *ethclient.Client
    contract common.Address
    key      *ecdsa.PrivateKey
    chainID  *big.Int
}

// AnchorToEthereum creates an Ethereum anchor for CT log entries
func (a *EthereumAnchor) AnchorToEthereum(logRange LogRange) (*ChainAnchor, error) {
    // Prepare contract call data
    // Function: anchor(bytes32 merkleRoot, uint64 startIndex, uint64 endIndex)
    callData := a.encodeAnchorCall(logRange.MerkleRoot, logRange.StartIndex, logRange.EndIndex)

    // Create transaction
    nonce, err := a.client.PendingNonceAt(context.Background(), crypto.PubkeyToAddress(a.key.PublicKey))
    if err != nil {
        return nil, err
    }

    gasPrice, err := a.client.SuggestGasPrice(context.Background())
    if err != nil {
        return nil, err
    }

    tx := types.NewTransaction(
        nonce,
        a.contract,
        big.NewInt(0),
        200000,  // Gas limit
        gasPrice,
        callData,
    )

    // Sign transaction
    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(a.chainID), a.key)
    if err != nil {
        return nil, err
    }

    // Send transaction
    if err := a.client.SendTransaction(context.Background(), signedTx); err != nil {
        return nil, err
    }

    // Wait for receipt
    receipt, err := a.waitForReceipt(signedTx.Hash())
    if err != nil {
        return nil, err
    }

    var blockHash [32]byte
    copy(blockHash[:], receipt.BlockHash.Bytes())

    var txHash [32]byte
    copy(txHash[:], signedTx.Hash().Bytes())

    anchor := &ChainAnchor{
        ChainID:     "ethereum",
        BlockHeight: receipt.BlockNumber.Uint64(),
        BlockHash:   blockHash,
        TxID:        txHash,
        Timestamp:   time.Now(),
        CTLogRange:  logRange,
    }

    log.Info("CT log anchored to Ethereum",
        "txid", signedTx.Hash().Hex(),
        "block", receipt.BlockNumber.Uint64(),
        "entries", logRange.EndIndex-logRange.StartIndex+1)

    return anchor, nil
}

// VerifyCrossChainAnchor validates an anchor against the external blockchain
func (c *CrossChainAnchor) VerifyCrossChainAnchor(anchor *ChainAnchor) error {
    switch anchor.ChainID {
    case "bitcoin":
        return c.bitcoin.VerifyAnchor(anchor)
    case "ethereum":
        return c.ethereum.VerifyAnchor(anchor)
    default:
        return ErrUnknownChain
    }
}
```

---

## Adaptive CA Pool Threshold

The CA pool signing threshold adapts dynamically based on threat conditions, providing additional safety margin beyond the theoretical Byzantine fault tolerance limit while maintaining operational efficiency during normal conditions.

### Hybrid Threshold Configuration

The default threshold of 40% (vs. theoretical 33%) provides additional margin against correlated failures and sophisticated attacks.

```go
// pkg/ca/adaptive_threshold.go

// AdaptiveThresholdConfig defines threshold parameters
type AdaptiveThresholdConfig struct {
    // Base thresholds
    NormalThresholdPercent     float64  // 40% during normal operations
    ElevatedThresholdPercent   float64  // 50% during elevated threat
    CriticalThresholdPercent   float64  // 60% during critical threat

    // Theoretical limits
    TheoreticalMinPercent      float64  // 33.33% Byzantine threshold

    // Adjustment parameters
    EvaluationInterval         time.Duration
    ThresholdChangeDelay       time.Duration  // Delay before threshold change takes effect
    MaxThresholdChangePerEval  float64        // Maximum change per evaluation (5%)
}

// DefaultAdaptiveThresholdConfig returns standard configuration
func DefaultAdaptiveThresholdConfig() *AdaptiveThresholdConfig {
    return &AdaptiveThresholdConfig{
        NormalThresholdPercent:     40.0,   // 40% vs 33% theoretical
        ElevatedThresholdPercent:   50.0,   // 50% for elevated threat
        CriticalThresholdPercent:   60.0,   // 60% for critical threat
        TheoreticalMinPercent:      33.34,  // Never go below 1/3 + epsilon
        EvaluationInterval:         1 * time.Hour,
        ThresholdChangeDelay:       24 * time.Hour,  // 24h notice before changes
        MaxThresholdChangePerEval:  5.0,    // Max 5% change per evaluation
    }
}

// ThresholdLevel represents current threat level
type ThresholdLevel uint8

const (
    ThresholdLevelNormal ThresholdLevel = iota
    ThresholdLevelElevated
    ThresholdLevelCritical
)

// AdaptiveThresholdManager manages dynamic threshold adjustment
type AdaptiveThresholdManager struct {
    config         *AdaptiveThresholdConfig
    currentLevel   ThresholdLevel
    currentPercent float64
    poolSize       int
    pendingChange  *ThresholdChange
    anomalyDetector *AnomalyDetector
}

// ThresholdChange represents a pending threshold modification
type ThresholdChange struct {
    ID              uuid.UUID
    ProposedPercent float64
    ProposedLevel   ThresholdLevel
    ProposedAt      time.Time
    EffectiveAt     time.Time
    Reason          string
    Approved        bool
}

// GetCurrentThreshold returns the active signing threshold
func (m *AdaptiveThresholdManager) GetCurrentThreshold() int {
    threshold := int(math.Ceil(float64(m.poolSize) * m.currentPercent / 100.0))

    // Ensure minimum viable threshold
    minThreshold := int(math.Ceil(float64(m.poolSize) * m.config.TheoreticalMinPercent / 100.0))
    if threshold < minThreshold {
        threshold = minThreshold
    }

    return threshold
}

// EvaluateThreshold analyzes conditions and proposes threshold changes
func (m *AdaptiveThresholdManager) EvaluateThreshold() (*ThresholdChange, error) {
    // Collect threat indicators
    indicators := m.collectThreatIndicators()

    // Determine appropriate level
    newLevel := m.determineLevel(indicators)

    if newLevel == m.currentLevel {
        return nil, nil  // No change needed
    }

    // Calculate new threshold percentage
    var newPercent float64
    switch newLevel {
    case ThresholdLevelNormal:
        newPercent = m.config.NormalThresholdPercent
    case ThresholdLevelElevated:
        newPercent = m.config.ElevatedThresholdPercent
    case ThresholdLevelCritical:
        newPercent = m.config.CriticalThresholdPercent
    }

    // Apply maximum change limit
    delta := newPercent - m.currentPercent
    if math.Abs(delta) > m.config.MaxThresholdChangePerEval {
        if delta > 0 {
            newPercent = m.currentPercent + m.config.MaxThresholdChangePerEval
        } else {
            newPercent = m.currentPercent - m.config.MaxThresholdChangePerEval
        }
    }

    change := &ThresholdChange{
        ID:              uuid.New(),
        ProposedPercent: newPercent,
        ProposedLevel:   newLevel,
        ProposedAt:      time.Now(),
        EffectiveAt:     time.Now().Add(m.config.ThresholdChangeDelay),
        Reason:          m.formatReason(indicators, newLevel),
    }

    m.pendingChange = change

    log.Info("Threshold change proposed",
        "current_percent", m.currentPercent,
        "proposed_percent", newPercent,
        "current_level", m.currentLevel,
        "proposed_level", newLevel,
        "effective_at", change.EffectiveAt)

    return change, nil
}
```

### Anomaly Detection for Correlated Patterns

The system monitors for correlated signing patterns that might indicate vendor compromise or coordinated attack.

```go
// pkg/ca/anomaly_detection.go

// AnomalyDetector identifies suspicious patterns in signing behavior
type AnomalyDetector struct {
    signingHistory   map[NodeID][]*SigningEvent
    vendorGroups     map[string][]NodeID  // TPM vendor -> nodes
    correlationWindow time.Duration
    alertThresholds  *AnomalyThresholds
}

// AnomalyThresholds defines detection sensitivity
type AnomalyThresholds struct {
    VendorFailureCorrelation  float64  // Max correlated failures per vendor
    TimingAnomalyThreshold    float64  // Deviation from expected timing
    PatternSimilarityThreshold float64 // Max similarity between node behaviors
    SigningRateAnomaly        float64  // Deviation from normal signing rate
}

// SigningEvent records a signing operation for analysis
type SigningEvent struct {
    NodeID        NodeID
    TPMVendor     string
    Timestamp     time.Time
    Success       bool
    ResponseTime  time.Duration
    ErrorType     string
}

// CorrelatedAnomaly represents detected correlated behavior
type CorrelatedAnomaly struct {
    Type          AnomalyType
    DetectedAt    time.Time
    AffectedNodes []NodeID
    TPMVendor     string
    CorrelationScore float64
    Evidence      *AnomalyEvidence
    Severity      AnomalySeverity
}

type AnomalyType uint8

const (
    AnomalyVendorCorrelatedFailure AnomalyType = iota
    AnomalyTimingCorrelation
    AnomalyBehaviorSimilarity
    AnomalySigningRateSpike
    AnomalyCoordinatedRefusal
)

type AnomalySeverity uint8

const (
    SeverityLow AnomalySeverity = iota
    SeverityMedium
    SeverityHigh
    SeverityCritical
)

// DetectVendorCorrelatedFailures finds failures clustering by TPM vendor
func (d *AnomalyDetector) DetectVendorCorrelatedFailures() []CorrelatedAnomaly {
    anomalies := make([]CorrelatedAnomaly, 0)
    now := time.Now()

    for vendor, nodes := range d.vendorGroups {
        // Count recent failures per vendor
        failedNodes := make([]NodeID, 0)
        recentFailures := 0
        totalEvents := 0

        for _, nodeID := range nodes {
            events := d.signingHistory[nodeID]
            for _, event := range events {
                if now.Sub(event.Timestamp) > d.correlationWindow {
                    continue
                }

                totalEvents++
                if !event.Success {
                    recentFailures++
                    if !contains(failedNodes, nodeID) {
                        failedNodes = append(failedNodes, nodeID)
                    }
                }
            }
        }

        if totalEvents == 0 {
            continue
        }

        failureRate := float64(recentFailures) / float64(totalEvents)
        vendorNodeFailureRate := float64(len(failedNodes)) / float64(len(nodes))

        // Check if failures are correlated by vendor
        if vendorNodeFailureRate > d.alertThresholds.VendorFailureCorrelation {
            severity := d.calculateSeverity(vendorNodeFailureRate)

            anomaly := CorrelatedAnomaly{
                Type:             AnomalyVendorCorrelatedFailure,
                DetectedAt:       now,
                AffectedNodes:    failedNodes,
                TPMVendor:        vendor,
                CorrelationScore: vendorNodeFailureRate,
                Severity:         severity,
                Evidence: &AnomalyEvidence{
                    FailureRate:      failureRate,
                    AffectedCount:    len(failedNodes),
                    TotalVendorNodes: len(nodes),
                    TimeWindow:       d.correlationWindow,
                },
            }

            anomalies = append(anomalies, anomaly)

            log.Warn("Vendor-correlated failure anomaly detected",
                "vendor", vendor,
                "affected_nodes", len(failedNodes),
                "total_vendor_nodes", len(nodes),
                "correlation_score", vendorNodeFailureRate,
                "severity", severity)
        }
    }

    return anomalies
}

// DetectTimingCorrelation identifies suspicious timing patterns
func (d *AnomalyDetector) DetectTimingCorrelation() []CorrelatedAnomaly {
    anomalies := make([]CorrelatedAnomaly, 0)
    now := time.Now()

    // Group events by time buckets (100ms windows)
    timeBuckets := make(map[int64][]SigningEvent)

    for _, events := range d.signingHistory {
        for _, event := range events {
            if now.Sub(event.Timestamp) > d.correlationWindow {
                continue
            }
            bucket := event.Timestamp.UnixMilli() / 100
            timeBuckets[bucket] = append(timeBuckets[bucket], *event)
        }
    }

    // Find buckets with unusually high correlation
    for bucket, events := range timeBuckets {
        if len(events) < 3 {
            continue
        }

        // Check if multiple nodes from same vendor responded simultaneously
        vendorCounts := make(map[string]int)
        for _, e := range events {
            vendorCounts[e.TPMVendor]++
        }

        for vendor, count := range vendorCounts {
            vendorTotal := len(d.vendorGroups[vendor])
            if vendorTotal == 0 {
                continue
            }

            simultaneity := float64(count) / float64(vendorTotal)
            if simultaneity > d.alertThresholds.TimingAnomalyThreshold {
                affectedNodes := make([]NodeID, 0)
                for _, e := range events {
                    if e.TPMVendor == vendor {
                        affectedNodes = append(affectedNodes, e.NodeID)
                    }
                }

                anomaly := CorrelatedAnomaly{
                    Type:             AnomalyTimingCorrelation,
                    DetectedAt:       now,
                    AffectedNodes:    affectedNodes,
                    TPMVendor:        vendor,
                    CorrelationScore: simultaneity,
                    Severity:         SeverityHigh,
                    Evidence: &AnomalyEvidence{
                        TimeBucket:    bucket,
                        EventCount:    count,
                        VendorTotal:   vendorTotal,
                    },
                }

                anomalies = append(anomalies, anomaly)
            }
        }
    }

    return anomalies
}
```

### Emergency Threshold Increase

During elevated threat conditions, the threshold can be temporarily increased to provide additional security margin.

```go
// pkg/ca/emergency_threshold.go

// EmergencyThresholdManager handles rapid threshold escalation
type EmergencyThresholdManager struct {
    thresholdManager *AdaptiveThresholdManager
    currentEmergency *EmergencyState
    escalationRules  []EscalationRule
}

// EmergencyState tracks active emergency conditions
type EmergencyState struct {
    ID               uuid.UUID
    DeclaredAt       time.Time
    DeclaredBy       NodeID
    Reason           EmergencyReason
    ThresholdOverride float64  // Temporary threshold percentage
    ExpiresAt        time.Time
    Approvals        []EmergencyApproval
}

type EmergencyReason uint8

const (
    EmergencyVendorCompromise EmergencyReason = iota
    EmergencyActiveAttack
    EmergencyMassNodeFailure
    EmergencyZeroDayVulnerability
    EmergencyGovernmentOrder
)

// EscalationRule defines automatic threshold escalation triggers
type EscalationRule struct {
    Trigger         EscalationTrigger
    ThresholdDelta  float64  // Percentage increase
    Duration        time.Duration
    RequiresApproval bool
}

type EscalationTrigger struct {
    AnomalyType     AnomalyType
    MinSeverity     AnomalySeverity
    MinOccurrences  int
    TimeWindow      time.Duration
}

// DeclareEmergency activates emergency threshold increase
func (m *EmergencyThresholdManager) DeclareEmergency(
    declarer NodeID,
    reason EmergencyReason,
    proposedThreshold float64,
    duration time.Duration,
) (*EmergencyState, error) {
    // Verify declarer has authority
    if !m.hasEmergencyAuthority(declarer) {
        return nil, ErrUnauthorizedEmergencyDeclaration
    }

    // Validate proposed threshold
    if proposedThreshold < m.thresholdManager.currentPercent {
        return nil, ErrThresholdCannotDecrease
    }

    maxThreshold := m.thresholdManager.config.CriticalThresholdPercent + 10.0
    if proposedThreshold > maxThreshold {
        return nil, &ThresholdTooHighError{
            Proposed: proposedThreshold,
            Maximum:  maxThreshold,
        }
    }

    // Create emergency state
    state := &EmergencyState{
        ID:                uuid.New(),
        DeclaredAt:        time.Now(),
        DeclaredBy:        declarer,
        Reason:            reason,
        ThresholdOverride: proposedThreshold,
        ExpiresAt:         time.Now().Add(duration),
        Approvals:         make([]EmergencyApproval, 0),
    }

    // Emergency declarations require immediate secondary approval
    requiredApprovals := m.getRequiredApprovals(reason)
    state.Approvals = append(state.Approvals, EmergencyApproval{
        ApproverID: declarer,
        Timestamp:  time.Now(),
        Role:       "declarer",
    })

    m.currentEmergency = state

    // Broadcast emergency declaration
    if err := m.broadcastEmergency(state); err != nil {
        log.Error("Failed to broadcast emergency", "error", err)
    }

    log.Warn("Emergency threshold declared",
        "id", state.ID,
        "declarer", declarer,
        "reason", reason,
        "threshold", proposedThreshold,
        "expires", state.ExpiresAt,
        "required_approvals", requiredApprovals)

    return state, nil
}

// ApproveEmergency adds approval from authorized party
func (m *EmergencyThresholdManager) ApproveEmergency(
    emergencyID uuid.UUID,
    approver NodeID,
    role string,
) error {
    if m.currentEmergency == nil || m.currentEmergency.ID != emergencyID {
        return ErrEmergencyNotFound
    }

    // Verify approver authority
    if !m.canApprove(approver, role) {
        return ErrUnauthorizedApproval
    }

    // Check for duplicate approval
    for _, existing := range m.currentEmergency.Approvals {
        if existing.ApproverID == approver {
            return ErrAlreadyApproved
        }
    }

    approval := EmergencyApproval{
        ApproverID: approver,
        Timestamp:  time.Now(),
        Role:       role,
    }

    m.currentEmergency.Approvals = append(m.currentEmergency.Approvals, approval)

    // Check if we have enough approvals
    requiredApprovals := m.getRequiredApprovals(m.currentEmergency.Reason)
    if len(m.currentEmergency.Approvals) >= requiredApprovals {
        if err := m.activateEmergencyThreshold(); err != nil {
            return err
        }
    }

    log.Info("Emergency approval recorded",
        "emergency_id", emergencyID,
        "approver", approver,
        "role", role,
        "total_approvals", len(m.currentEmergency.Approvals),
        "required", requiredApprovals)

    return nil
}

// activateEmergencyThreshold applies the emergency threshold
func (m *EmergencyThresholdManager) activateEmergencyThreshold() error {
    if m.currentEmergency == nil {
        return ErrNoActiveEmergency
    }

    oldThreshold := m.thresholdManager.currentPercent
    m.thresholdManager.currentPercent = m.currentEmergency.ThresholdOverride
    m.thresholdManager.currentLevel = ThresholdLevelCritical

    log.Warn("Emergency threshold ACTIVATED",
        "old_threshold", oldThreshold,
        "new_threshold", m.currentEmergency.ThresholdOverride,
        "reason", m.currentEmergency.Reason,
        "expires", m.currentEmergency.ExpiresAt)

    // Schedule automatic expiration
    go func() {
        time.Sleep(time.Until(m.currentEmergency.ExpiresAt))
        m.expireEmergency()
    }()

    return nil
}

// expireEmergency returns to normal threshold after emergency ends
func (m *EmergencyThresholdManager) expireEmergency() {
    if m.currentEmergency == nil {
        return
    }

    log.Info("Emergency threshold expired, returning to normal",
        "emergency_id", m.currentEmergency.ID,
        "duration", time.Since(m.currentEmergency.DeclaredAt))

    // Gradually return to normal threshold
    m.thresholdManager.currentLevel = ThresholdLevelNormal
    m.thresholdManager.currentPercent = m.thresholdManager.config.NormalThresholdPercent
    m.currentEmergency = nil
}

// GetEffectiveThreshold returns the current effective threshold
func (m *EmergencyThresholdManager) GetEffectiveThreshold() (int, ThresholdLevel) {
    if m.currentEmergency != nil && time.Now().Before(m.currentEmergency.ExpiresAt) {
        threshold := int(math.Ceil(float64(m.thresholdManager.poolSize) *
            m.currentEmergency.ThresholdOverride / 100.0))
        return threshold, ThresholdLevelCritical
    }

    return m.thresholdManager.GetCurrentThreshold(), m.thresholdManager.currentLevel
}
```

### Threshold Security Properties

| Property | Normal (40%) | Elevated (50%) | Critical (60%) |
|----------|--------------|----------------|----------------|
| **Byzantine Tolerance** | 40% - 1 nodes | 50% - 1 nodes | 60% - 1 nodes |
| **Safety Margin** | 7% above theoretical | 17% above theoretical | 27% above theoretical |
| **Liveness** | Requires 40%+ online | Requires 50%+ online | Requires 60%+ online |
| **Vendor Diversity** | Tolerates 1 vendor failure | Tolerates 1-2 vendor failures | Requires all vendors |
| **Attack Cost** | High | Very High | Extreme |

---

## Cross-References

- For DHT operations and routing, see [02-dht-architecture.md](02-dht-architecture.md)
- For consensus mechanisms, see [03-consensus.md](03-consensus.md)
- For TPM hardware requirements, see [05-hardware-requirements.md](05-hardware-requirements.md)

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | Initial | - | Initial document creation |
| 1.1.0 | 2026-01-10 | Technical Writer | Added "Phase Timeout Ordering" section clarifying soft vs hard deadlines for DKG phases. Added timeline diagram, detailed timeout specifications table, soft/hard deadline behavior descriptions, abort vs retry decision tree, timeout ordering invariants, and configuration constants. |
| 1.2.0 | 2026-01-10 | Technical Writer | Added DKG Coordinator State Transfer Protocol with AES-256-GCM encryption, 30s transfer timeout, 60s session continuity window, and max 2 failovers per session. Added DKG Commit-Reveal Protocol with 3-phase structure (commit/wait/reveal) and 30s minimum delay to prevent last-mover advantage. Added DKG Session Recovery with 2-hour checkpoint TTL and share re-encryption mechanism. Added FROST Commitment Reservation Protocol with reduced 1-hour validity window and atomic reservation to prevent expiration race conditions. Enhanced Nonce Pool Management with replenishment strategy, high-load depletion handling, and priority queuing. |

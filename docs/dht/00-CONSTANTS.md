# DHT Constants Reference

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
**Version:** 1.5.0
**Last Updated:** 2026-01-10
**Status:** Canonical Reference

## Purpose

This document is the **SINGLE SOURCE OF TRUTH** for all constants, timeouts, thresholds, and parameters used across the DHT implementation and documentation. All other documentation files reference values defined here.

## Referenced By

- `01-system-overview.md` - System overview and architecture
- `09-defense-reputation.md` - Reputation system and thresholds (CANONICAL)
- `03-security-trust.md` - Security mechanisms and parameters
- `04-cryptographic-protocols.md` - Distributed Key Generation timing
- `06-consensus-coordination.md` - Coordinator election and failover
- `11-operations.md` - Partition recovery and operations
- `21-ai-arbitration-system.md` - AI agent parameters
- Implementation packages in `pkg/dht/*`

---

## 1. Timing Constants

### 1.1 Heartbeat and Health Monitoring

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `HeartbeatInterval` | 2s | Interval between node heartbeat broadcasts | 06-consensus-coordination.md, 11-operations.md |
| `MissedHeartbeatThreshold` | 4 | Number of consecutive missed heartbeats before node considered suspect | 06-consensus-coordination.md |
| `FailureDetectionTimeout` | 8s | Time to detect node failure (HeartbeatInterval × MissedThreshold) | 06-consensus-coordination.md, 11-operations.md |

### 1.2 Distributed Key Generation (DKG)

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `DKGDuration` | 10min | Standard DKG ceremony duration | 04-cryptographic-protocols.md |
| `DKGSlowPath` | 13min | Extended DKG duration for slow participants | 04-cryptographic-protocols.md |
| `DKGFastPath` | 5min | Optimistic DKG completion for fast paths | 04-cryptographic-protocols.md |
| `DKGCheckpointInterval` | 30s | Interval for progress checkpoints during DKG | 04-cryptographic-protocols.md |

### 1.3 Lock Management

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `OperationalLockTTL` | 60s | Base TTL for operational locks | 06-consensus-coordination.md |
| `LockExtensionInterval` | 30s | Interval for lock TTL extensions | 06-consensus-coordination.md |
| `MaxLockTTL` | 120s | Maximum cumulative lock TTL | 06-consensus-coordination.md |
| `RecoveryLockTTL` | 5min | Extended TTL for partition recovery operations | 11-operations.md |

### 1.4 Coordinator Election and Failover

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CoordinatorFailoverTimeout` | 10s | Maximum time to complete coordinator failover | 06-consensus-coordination.md |
| `CoordinatorHeartbeatInterval` | 2s | Coordinator heartbeat interval | 06-consensus-coordination.md |
| `ElectionTimeout` | 5s | Timeout for leader election process | 06-consensus-coordination.md |
| `FencingTokenQuorum` | 15/21 | Minimum signatures required for valid fencing token | 06-consensus-coordination.md |
| `EpochTransitionGrace` | 30s | Grace period for epoch boundary synchronization | 06-consensus-coordination.md |

### 1.5 PBFT Consensus Timing

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `PBFTBaseTimeout` | 800ms | Base timeout for PBFT consensus rounds. Adjusted from 500ms to account for global coordinator distribution (worst-case 3 RTTs = 1050ms) | 06-consensus-coordination.md |
| `PBFTMaxTimeout` | 10s | Maximum timeout after escalation | 06-consensus-coordination.md |
| `ViewChangeTimeout` | 2s | Timeout before initiating view change | 06-consensus-coordination.md |
| `MaxConsecutiveViewChanges` | 7 | Circuit breaker for view change loops | 06-consensus-coordination.md |
| `ViewChangeBackoffBase` | 500ms | Base backoff for timeout escalation | 06-consensus-coordination.md |
| `ViewChangeBackoffMultiplier` | 2 | Exponential backoff multiplier | 06-consensus-coordination.md |

### 1.6 VRF Coordinator Selection

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `VRFCommitWindow` | 30s | Window for VRF seed commitment submission | 06-consensus-coordination.md |
| `VRFRevealWindow` | 30s | Window for VRF seed reveal after commit | 06-consensus-coordination.md |
| `VRFMinRevealDelay` | 2 blocks | Minimum blocks between commit and reveal | 06-consensus-coordination.md |
| `VRFBlindingFactorSize` | 32 bytes | Size of blinding factor for commitment | 06-consensus-coordination.md |

---

## 2. Reputation Thresholds

### 2.1 Role-Based Minimum Reputation

| Role | Minimum Reputation | Rationale | Referenced In |
|------|-------------------|-----------|---------------|
| `Leaf` | 0.0 | Default entry point, no special privileges | 09-defense-reputation.md |
| `CA Participant` | 0.90 | Requires proven trustworthiness for certificate operations; elevated for anti-Sybil defense | 09-defense-reputation.md, 04-cryptographic-protocols.md |
| `Hub` | 0.80 | Critical routing position requires reliability | 09-defense-reputation.md |
| `Gateway` | 0.85 | External-facing nodes need higher trust | 09-defense-reputation.md |
| `AI Arbitrator` | 0.85 | High-stakes decision-making requires proven track record | 09-defense-reputation.md, 21-ai-arbitration-system.md |
| `Coordinator` | 0.95 | System-critical role demands highest trust | 09-defense-reputation.md, 06-consensus-coordination.md |

### 2.2 Reputation Bounds

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MinReputation` | 0.0 | Absolute minimum (new nodes) | 09-defense-reputation.md |
| `MaxReputation` | 1.0 | Perfect reputation score | 09-defense-reputation.md |
| `InitialReputation` | 0.0 | Starting reputation for new nodes (must earn trust) | 09-defense-reputation.md |

---

## 3. Security Constants

### 3.1 Nonce Management

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `NonceMaxCacheSize` | 100,000 | Maximum nonces cached per node | 03-security-trust.md |
| `NonceTTL` | 30s | Time-to-live for cached nonces | 03-security-trust.md |
| `NonceCleanupInterval` | 5s | Interval for removing expired nonces | 03-security-trust.md |

### 3.2 Challenge-Response Pool

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MaxPendingChallenges` | 1,000,000 | Maximum concurrent pending challenges | 03-security-trust.md |
| `ChallengeValidityWindow` | 5min | How long a challenge remains valid | 03-security-trust.md |
| `ChallengeEvictionThreshold` | 95% | Pool utilization triggering eviction | 03-security-trust.md |

### 3.3 TPM Attestation

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TPMQuoteFreshness` | ±100ms | Maximum acceptable clock skew for quotes | 03-security-trust.md |
| `TPMClockDriftTolerance` | 5s | Tolerable drift for TPM clock synchronization | 03-security-trust.md |

**Rationale for TPMClockDriftTolerance (5s):**
- Balances security (replay attack prevention) with operational reality (network latency, NTP sync delays)
- Accounts for TPM hardware clock drift (typically <1s/day)
- Allows for brief network partitions without false positives
- Sufficient for detecting stale quotes while avoiding spurious rejections

---

## 4. Penalty Constants

### 4.1 Byzantine Behavior Penalties

| Offense | Stake Slash | Reputation Penalty | Rationale | Referenced In |
|---------|-------------|-------------------|-----------|---------------|
| `Collusion` | 100% | -1.0 (permanent ban) | Fundamental trust violation | 09-defense-reputation.md, 21-ai-arbitration-system.md |
| `VoteSelling` | 100% | -1.0 (permanent ban) | Compromises voting integrity | 09-defense-reputation.md, 21-ai-arbitration-system.md |
| `Equivocation` | 50% | -0.50 | Signing conflicting statements | 09-defense-reputation.md, 04-cryptographic-protocols.md |
| `DKGTimeout` | 1-5% | -0.05 to -0.15 | Delayed DKG participation | 09-defense-reputation.md, 04-cryptographic-protocols.md |

### 4.2 Operational Penalties

| Severity | Reputation Delta | Example Violations | Referenced In |
|----------|-----------------|-------------------|---------------|
| `MinorPenalty` | -0.05 | Single missed heartbeat, minor protocol deviation | 09-defense-reputation.md |
| `ModeratePenalty` | -0.15 | Multiple missed heartbeats, temporary unresponsiveness | 09-defense-reputation.md |
| `MajorPenalty` | -0.30 | Prolonged downtime, repeated protocol violations | 09-defense-reputation.md |

### 4.3 Positive Rewards

| Action | Reputation Delta | Description | Referenced In |
|--------|-----------------|-------------|---------------|
| `SuccessfulAttestation` | +0.01 | Per successful TPM attestation | 09-defense-reputation.md |
| `DKGCompletion` | +0.05 | Completing DKG on time | 09-defense-reputation.md, 04-cryptographic-protocols.md |
| `UptimeBonus` | +0.02/week | Continuous 99.9%+ uptime | 09-defense-reputation.md |

---

## 5. Rate Limits

### 5.1 Request Rate Limits

| Category | Limit | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TrustedNodeRate` | 100 req/s | Nodes with reputation ≥ 0.80 | 03-security-trust.md |
| `UntrustedNodeRate` | 10 req/s | Nodes with reputation < 0.80 | 03-security-trust.md |
| `MinIPReputation` | 0.20 | Minimum reputation to avoid IP-based throttling | 03-security-trust.md |

### 5.2 Burst Allowances

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TrustedBurstSize` | 200 | Burst capacity for trusted nodes | 03-security-trust.md |
| `UntrustedBurstSize` | 20 | Burst capacity for untrusted nodes | 03-security-trust.md |

---

## 6. Network Parameters

### 6.1 Kademlia DHT Configuration

| Parameter | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `K` | 20 | Bucket size (nodes per routing table bucket) | 01-system-overview.md |
| `Alpha` | 3 | Concurrency parameter for parallel lookups | 01-system-overview.md |
| `KeySize` | 160 | DHT key size in bits (SHA-1 hash) | 01-system-overview.md |

### 6.2 Replication and Redundancy

| Parameter | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `ReplicationFactor` | 3 | Number of replicas for each DHT value | 01-system-overview.md |
| `MinHealthyReplicas` | 2 | Minimum replicas required for data availability | 11-operations.md |

### 6.3 Network Partition Thresholds

| Threshold | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `PartitionEnterThreshold` | 48% | Partition suspected when <48% of coordinators visible | 11-operations.md |
| `PartitionExitThreshold` | 52% | Partition resolved when ≥52% of coordinators visible | 11-operations.md |
| `RecoveryConfidenceThreshold` | 80% | Required coordinator visibility for full recovery | 11-operations.md |
| `MinorityPartitionMode` | read-only | Behavior when in minority partition | 06-consensus-coordination.md |
| `PartitionStabilityPeriod` | 30s | Required stability before state transition | 06-consensus-coordination.md |

**Rationale for Hysteresis (48%/52%):**
- Prevents flapping between partition states during transient network issues
- 4% gap provides stability during gradual network degradation/recovery
- Aligns with quorum-based systems (simple majority = 51%)

### 6.4 Partition Recovery

| Parameter | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `VectorClockDrift` | 5s | Maximum acceptable vector clock drift | 06-consensus-coordination.md |
| `PartitionMergeTimeout` | 60s | Timeout for partition merge completion | 06-consensus-coordination.md |
| `ConflictResolutionMode` | largest-partition | Tiebreaker: largest partition wins | 06-consensus-coordination.md |
| `TransactionReconciliationBatch` | 1000 | Batch size for transaction log reconciliation | 06-consensus-coordination.md |

### 6.5 DHT Routing Optimization

| Parameter | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `RegionalCacheSize` | 1000 nodes | Top nodes cached per region | 02-network-architecture.md |
| `GlobalCacheSize` | 10000 nodes | Top nodes cached globally | 02-network-architecture.md |
| `NegativeCacheTTL` | 5min | TTL for negative lookup results | 02-network-architecture.md |
| `MessageBatchSize` | 10 | Keys per batched DHT lookup | 02-network-architecture.md |
| `MessageBatchFlushInterval` | 50ms | Interval before flushing partial batch | 02-network-architecture.md |

### 6.6 Eclipse Attack Prevention

| Parameter | Value | Description | Referenced In |
|-----------|-------|-------------|---------------|
| `MaxSameASNPerBucket` | 20% | Maximum same-ASN nodes per routing bucket | 02-network-architecture.md |
| `MinDistinctASNs` | 5 | Minimum distinct ASNs in routing table | 02-network-architecture.md |
| `CloudProviderASNEquivalence` | true | Treat major cloud providers as single meta-ASN | 02-network-architecture.md |
| `MinResidentialDiversity` | 30% | Minimum non-datacenter nodes in routing | 02-network-architecture.md |

---

## 7. AI/Agent Constants

### 7.1 AI Arbitrator Parameters

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `AIConfidenceThreshold` | 0.75 | Minimum confidence for AI arbitration decision | 21-ai-arbitration-system.md |
| `AppealWindow` | 72 hours | Time window to appeal AI arbitration decision | 21-ai-arbitration-system.md |
| `MaxAppealRounds` | 2 | Maximum number of appeal escalations | 21-ai-arbitration-system.md |

### 7.2 Quorum Requirements

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MinArbitratorQuorum` | 3 | Minimum AI arbitrators for consensus | 21-ai-arbitration-system.md |
| `ArbitratorConsensusThreshold` | 0.67 | Required agreement (2/3 majority) | 21-ai-arbitration-system.md |

### 7.3 AI Model Governance

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `ModelApprovalThreshold` | 67% | Supermajority required for AI model approval | 21-ai-arbitration-system.md |
| `ModelTrialPeriod` | 1000 decisions | Human oversight period for new models (extended from 100) | 21-ai-arbitration-system.md |
| `BiasAuditRequired` | true | Independent bias audit required before approval | 21-ai-arbitration-system.md |
| `BiasDetectionThreshold` | 0.15 | Maximum acceptable bias score | 21-ai-arbitration-system.md |
| `ModelSuspensionTrigger` | 3 bias violations | Auto-suspend after repeated bias detection | 21-ai-arbitration-system.md |
| `ModelReviewPeriod` | 30 days | Mandatory review period before approval vote | 21-ai-arbitration-system.md |

### 7.4 AI Model Adversarial Testing

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `AdversarialTestRatio` | 10% | Percentage of trial cases that are adversarial | 21-ai-arbitration-system.md |
| `AdversarialAccuracyThreshold` | 95% | Required accuracy on adversarial test cases | 21-ai-arbitration-system.md |
| `AdversarialTestSetSize` | 100 cases | Minimum adversarial cases for trial period | 21-ai-arbitration-system.md |
| `AdversarialTestCategories` | 5 | Number of distinct attack categories tested | 21-ai-arbitration-system.md |

### 7.5 AI Model Diversity Requirements

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MinModelArchitectures` | 2 | Minimum distinct model architectures in quorum | 21-ai-arbitration-system.md |
| `MaxSingleModelDecisions` | 50% | Maximum decisions from single model version | 21-ai-arbitration-system.md |
| `ModelVersionDiversity` | required | Different model versions required in quorum | 21-ai-arbitration-system.md |
| `ModelProviderDiversity` | recommended | Different model providers recommended | 21-ai-arbitration-system.md |

---

## 8. Storage and Caching

### 8.1 DHT Storage Limits

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MaxValueSize` | 1 MB | Maximum size for a single DHT value | 01-system-overview.md |
| `MaxKeysPerNode` | 10,000 | Maximum keys stored per node | 01-system-overview.md |

### 8.2 Cache Parameters

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `ReputationCacheTTL` | 5min | Cache TTL for reputation scores | 09-defense-reputation.md |
| `CoordinatorListCacheTTL` | 30s | Cache TTL for coordinator registry | 06-consensus-coordination.md |

---

## 9. Cryptographic Parameters

### 9.1 Key Sizes

| Parameter | Size (bits) | Description | Referenced In |
|-----------|-------------|-------------|---------------|
| `ECCCurve` | P-256 | Elliptic curve for signatures (NIST P-256) | 03-security-trust.md, 04-cryptographic-protocols.md |
| `AESKeySize` | 256 | Symmetric encryption key size | 03-security-trust.md |
| `HMACKeySize` | 256 | HMAC key size for message authentication | 03-security-trust.md |

### 9.2 Certificate Lifetimes

| Certificate Type | Lifetime | Description | Referenced In |
|-----------------|----------|-------------|---------------|
| `RootCA` | 10 years | Root certificate authority | 04-cryptographic-protocols.md |
| `IntermediateCA` | 5 years | Intermediate CA certificates | 04-cryptographic-protocols.md |
| `NodeCertificate` | 1 year | Individual node certificates | 04-cryptographic-protocols.md |

---

## 10. Cross-Shard Transaction Parameters

### 10.1 3PC Protocol Timing

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CrossShardLockTTL` | 60s | Hard deadline for cross-shard locks (non-renewable) | 07-currency-transactions.md |
| `CoordinatorHeartbeatInterval` | 5s | Heartbeat interval during 3PC | 07-currency-transactions.md |
| `CoordinatorDeathTimeout` | 15s | Time to declare coordinator dead (3 missed heartbeats) | 07-currency-transactions.md |
| `PreparePhaseTimeout` | 20s | Maximum time for prepare phase | 07-currency-transactions.md |
| `CommitPhaseTimeout` | 10s | Maximum time for commit phase | 07-currency-transactions.md |

### 10.2 3PC Termination Protocol

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TerminationWitnessQuorum` | 2/3 | Required shard witnesses for termination decision | 07-currency-transactions.md |
| `RollbackGracePeriod` | 5s | Grace period before automatic rollback | 07-currency-transactions.md |
| `RollbackRetryAttempts` | 3 | Maximum rollback message retry attempts | 07-currency-transactions.md |
| `RollbackRetryDelay` | 2s | Delay between rollback retries | 07-currency-transactions.md |

### 10.3 Coordinator Accountability

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `AbandonedTxSlash` | 10% | Stake slash for abandoned transactions | 07-currency-transactions.md |
| `DoubleCommitSlash` | 100% | Stake slash for double-commit (permanent ban) | 07-currency-transactions.md |
| `InvalidPrepareSlash` | 5% | Stake slash for invalid prepare messages | 07-currency-transactions.md |
| `CoordinatorCooldown` | 1 hour | Cooldown after failed coordination | 07-currency-transactions.md |

---

## 11. Hierarchical CA Parameters

### 11.1 CA Tier Structure

| Tier | Max Participants | DKG Duration | Rotation Period | Referenced In |
|------|------------------|--------------|-----------------|---------------|
| Global Root | 100 | 10 min | 1 year | 05-certificate-authority.md |
| Regional CA | 1,000 | 5 min | 1 hour | 05-certificate-authority.md |
| Local Issuer | 100 | 2 min | 24 hours | 05-certificate-authority.md |

### 11.2 Regional CA Distribution

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `NumRegionalCAs` | 16 | Number of regional CA pools | 05-certificate-authority.md |
| `MinRegionalNodes` | 100 | Minimum nodes for regional CA operation | 05-certificate-authority.md |
| `MaxRegionalNodes` | 10,000 | Maximum nodes per regional DKG | 05-certificate-authority.md |
| `RegionalCACrossSign` | 2 | Number of cross-signatures per regional CA | 05-certificate-authority.md |

### 11.3 Certificate Transparency

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CTLogSubmissionRequired` | true | Mandatory CT log submission | 05-certificate-authority.md |
| `CTProbationPeriod` | 1 hour | Certificate probation until CT proof confirmed | 05-certificate-authority.md |
| `CTMaxInclusionDelay` | 24 hours | Maximum acceptable CT inclusion delay | 05-certificate-authority.md |
| `EKCertCTRequired` | true | CT log required for TPM EK certificates | 03-security-trust.md |

---

## 12. Clock Synchronization

### 12.1 NTP Requirements

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MaxClockDrift` | 100ms | Maximum acceptable system clock drift from NTP time sources (not to be confused with `TPMClockDriftTolerance`) | 03-security-trust.md |
| `NTPCheckInterval` | 1 min | Interval for NTP synchronization checks | 03-security-trust.md |
| `NTPFailureGrace` | 5 min | Grace period before clock drift rejection | 03-security-trust.md |
| `ClockDriftPenalty` | -0.10 | Reputation penalty for excessive drift | 03-security-trust.md |

### 12.2 TPM Clock Tolerance

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TPMClockDriftTolerance` | 5s | Maximum allowed TPM internal clock drift for attestation validity. This is distinct from `MaxClockDrift` (100ms) which governs NTP synchronization. The 5-second tolerance accommodates TPM hardware oscillator variations and 1-second clock resolution on some TPMs, while quote freshness is enforced separately via nonce validation. | 03-security-trust.md |

### 12.3 Nonce Management

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `NonceMaxAge` | 30s | Maximum nonce age before expiration | 03-security-trust.md |
| `NonceReplayWindow` | 60s | Window for nonce replay detection | 03-security-trust.md |
| `NonceCleanupBatch` | 10,000 | Batch size for nonce cache cleanup | 03-security-trust.md |

---

## 13. Reputation Eligibility Staggering

### 13.1 Role Eligibility

**Note:** Effective Min Age includes base age requirement + probation period + random delay for Sybil resistance.

| Role | Min Reputation | Min Network Age | Probation | Random Delay | Effective Min Age | Referenced In |
|------|----------------|-----------------|-----------|--------------|-------------------|---------------|
| Leaf | 0.0 | 0 days | 0 days | 0 days | 0 days | 09-defense-reputation.md |
| CA Participant | 0.90 | 120 days | 0 days | 0-14 days | 120-134 days | 09-defense-reputation.md |
| Hub | 0.80 | 80 days | 30 days | 0-21 days | 110+ days | 09-defense-reputation.md |
| Gateway | 0.85 | 85 days | 90 days | 0-30 days | 175+ days | 09-defense-reputation.md |
| Coordinator | 0.95 | 95 days | 90 days | 0-30 days | 185+ days | 09-defense-reputation.md |

### 13.2 Promotion Anomaly Detection

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `SynchronizedPromotionWindow` | 7 days | Window for detecting synchronized promotions | 09-defense-reputation.md |
| `MaxSimultaneousPromotions` | 10 | Maximum promotions from same source in window | 09-defense-reputation.md |
| `PromotionVelocityThreshold` | 0.005/day | Abnormal reputation gain rate trigger | 09-defense-reputation.md |
| `VoucherRequirement` | 2 | Established nodes required to vouch for promotion | 09-defense-reputation.md |

---

## 14. DDoS Protection Enhancements

### 14.1 Bloom Filter Configuration

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `BloomFilterType` | counting | Counting Bloom filter for removal support | 16-ddos-protection.md |
| `BloomFilterFPRate` | 0.001 | Target false positive rate (0.1%) | 16-ddos-protection.md |
| `BloomFilterPartitions` | 6 | Time-based partitions (10-min windows) | 16-ddos-protection.md |
| `BloomFilterMaxSize` | 100MB | Maximum memory for Bloom filter | 16-ddos-protection.md |

### 14.2 Rate Limit State Management

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `RateLimitStateMaxEntries` | 1,000,000 | Maximum tracked IP addresses | 16-ddos-protection.md |
| `RateLimitEvictionPolicy` | LRU | Eviction policy for state overflow | 16-ddos-protection.md |
| `RateLimitMemoryBudget` | 256MB | Maximum memory for rate limit state | 16-ddos-protection.md |

### 14.3 BGP Security

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `RPKIValidationRequired` | true | RPKI validation for BGP announcements | 16-ddos-protection.md |
| `MultiGatewayRouteVerification` | 3 | Minimum gateways to verify route | 16-ddos-protection.md |
| `BGPAggregationPrefix` | /40 | Regional aggregation prefix size | 02-network-architecture.md |

---

## 15. Operational Limits

### 15.1 Connection Limits

| Limit | Value | Description | Referenced In |
|-------|-------|-------------|---------------|
| `MaxInboundConnections` | 100 | Maximum concurrent inbound connections per node | 01-system-overview.md |
| `MaxOutboundConnections` | 50 | Maximum concurrent outbound connections per node | 01-system-overview.md |

### 15.2 Message Sizes

| Message Type | Max Size | Description | Referenced In |
|--------------|----------|-------------|---------------|
| `MaxMessageSize` | 10 MB | Maximum size for any DHT message | 01-system-overview.md |
| `MaxBatchSize` | 100 | Maximum items in batched operations | 01-system-overview.md |

---

## 16. DKG State Management

### 16.1 DKG Coordinator State Transfer

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `DKGStateTransferTimeout` | 30s | Timeout for state transfer to new coordinator | 04-cryptographic-protocols.md |
| `DKGShareEncryptionAlgo` | AES-256-GCM | Encryption for share transfer | 04-cryptographic-protocols.md |
| `DKGCommitRevealDelay` | 30s | Minimum delay between commit and reveal phases | 04-cryptographic-protocols.md |
| `DKGMaxParticipantsPerTier` | 10,000 | Maximum participants in any DKG tier | 04-cryptographic-protocols.md |

### 16.2 DKG Session Recovery

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `DKGCheckpointTTL` | 2 hours | TTL for DKG checkpoint in DHT | 04-cryptographic-protocols.md |
| `DKGMaxCoordinatorFailovers` | 2 | Maximum coordinator changes per session | 04-cryptographic-protocols.md |
| `DKGSessionContinuityWindow` | 60s | Window to accept coordinator change notification | 04-cryptographic-protocols.md |

### 16.3 DKG Disruption Accountability

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `MinWitnessQuorum` | See Section 16.6.1 | Dynamic formula: max(7, log₂(NetworkSize) / 2) | 04-cryptographic-protocols.md |
| `EvidenceRetentionPeriod` | 7 years | How long disruption evidence is stored | 04-cryptographic-protocols.md |
| `EquivocationWindow` | 5 min | Window to detect equivocation across participants | 04-cryptographic-protocols.md |
| `DKGHeartbeatInterval` | 2s | Coordinator heartbeat interval during DKG | 04-cryptographic-protocols.md |
| `MaxMissedHeartbeats` | 5 | Heartbeats missed before coordinator timeout (10s total) | 04-cryptographic-protocols.md |

### 16.4 DKG Penalty Tiers

| Offense Type | 1st Offense | 2nd Offense | 3rd Offense | 4th+ Offense |
|--------------|-------------|-------------|-------------|--------------|
| **Timeout** | Warning | 1h exclusion | -5% reputation | 24h exclusion |
| **Invalid Data** | -10% reputation | -20% stake | Certificate revoked | Permanent ban |
| **Equivocation** | -50% rep, -50% stake, cert revoked | Permanent ban | - | - |
| **Selective Exclusion** | -30% rep, -30% stake | Cert revoked + permanent ban | - | - |
| **Coordinated Attack** | -100% rep, -100% stake, cert revoked, permanent ban | - | - | - |

### 16.5 DKG Appeals

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `AppealWindow` | 30 days | Time window to file an appeal after penalty | 04-cryptographic-protocols.md |
| `AppealQuorum` | 5 | Number of arbitrators required to decide appeal | 04-cryptographic-protocols.md |
| `AppealThreshold` | 60% | Agreement percentage needed to overturn penalty | 04-cryptographic-protocols.md |
| `AppealDecisionDeadline` | 14 days | Maximum time for arbitrators to decide | 04-cryptographic-protocols.md |
| `MinArbitratorReputation` | 0.90 | Minimum reputation score to serve as arbitrator | 04-cryptographic-protocols.md |

### 16.6 Witness Pool Requirements

Witnesses provide independent attestation of DKG events to prevent fabricated disruption evidence.

#### 16.6.1 Dynamic Witness Scaling

| Constant | Formula/Value | Description | Referenced In |
|----------|---------------|-------------|---------------|
| `MinWitnessQuorum` | max(7, log₂(NetworkSize) / 2) | Dynamic minimum based on network size | 04-cryptographic-protocols.md |
| `WitnessQuorumTier0` | 7 | Minimum witnesses for networks < 10K nodes | 04-cryptographic-protocols.md |
| `WitnessQuorumTier1` | 10 | Minimum witnesses for 10K - 1M nodes | 04-cryptographic-protocols.md |
| `WitnessQuorumTier2` | 13 | Minimum witnesses for 1M - 100M nodes | 04-cryptographic-protocols.md |
| `WitnessQuorumTier3` | 15 | Minimum witnesses for 100M - 1B nodes | 04-cryptographic-protocols.md |
| `WitnessQuorumTier4` | 16 | Minimum witnesses for 1B+ nodes | 04-cryptographic-protocols.md |

**Scale Tier Calculation Examples:**
| Network Size | log₂(N) | log₂(N)/2 | MinWitnessQuorum |
|--------------|---------|-----------|------------------|
| 10,000 | 13.3 | 6.6 | 7 (floor capped at 7) |
| 100,000 | 16.6 | 8.3 | 8 |
| 1,000,000 | 20.0 | 10.0 | 10 |
| 100,000,000 | 26.6 | 13.3 | 13 |
| 1,000,000,000 | 30.0 | 15.0 | 15 |
| 4,000,000,000 | 32.0 | 16.0 | 16 |

#### 16.6.2 Witness Diversity Requirements

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `WitnessMinDistinctASNs` | 3 | Minimum distinct ASNs among witnesses | 04-cryptographic-protocols.md |
| `WitnessMinGeoRegions` | 2 | Minimum geographic regions among witnesses | 04-cryptographic-protocols.md |
| `WitnessMinOrganizations` | 2 | Minimum distinct organizations among witnesses | 04-cryptographic-protocols.md |
| `WitnessMinReputation` | 0.70 | Minimum reputation to serve as witness | 04-cryptographic-protocols.md |
| `WitnessMinNetworkAge` | 60 days | Minimum network age to serve as witness | 04-cryptographic-protocols.md |
| `WitnessMaxPerASN` | 30% | Maximum witnesses from single ASN | 04-cryptographic-protocols.md |

**Rationale:** Witness diversity prevents coordinated fabrication of false disruption evidence. An attacker would need to compromise nodes across multiple ASNs, geographic regions, and organizations simultaneously to fabricate evidence.

#### 16.6.3 Witness Selection Protocol

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `WitnessSelectionAlgorithm` | VRF-weighted | VRF selection weighted by reputation | 04-cryptographic-protocols.md |
| `WitnessSelectionSeed` | DKGSessionID + Phase | Deterministic seed per DKG phase | 04-cryptographic-protocols.md |
| `WitnessCandidatePool` | 3 × MinWitnessQuorum | Candidate pool size for selection | 04-cryptographic-protocols.md |
| `WitnessSelectionWindow` | 30s | Time window for witness selection | 04-cryptographic-protocols.md |
| `WitnessAcceptanceTimeout` | 10s | Timeout for witness to accept selection | 04-cryptographic-protocols.md |

#### 16.6.4 Witness Incentive Structure

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `WitnessStake` | 100 coins | Minimum stake to serve as DKG witness | 04-cryptographic-protocols.md |
| `WitnessReward` | 1 coin | Reward per valid attestation | 04-cryptographic-protocols.md |
| `WitnessFalseAttestationSlash` | 200 coins | Penalty for proven false attestation | 04-cryptographic-protocols.md |
| `WitnessAbsenceSlash` | 10 coins | Penalty for failure to attest when selected | 04-cryptographic-protocols.md |
| `WitnessReputationReward` | +0.01 | Reputation bonus per valid attestation | 04-cryptographic-protocols.md |
| `WitnessFalseAttestationRepPenalty` | -0.50 | Reputation penalty for false attestation | 04-cryptographic-protocols.md |

**Incentive Analysis:**
- Expected honest witness return: 1 coin reward + 0.01 reputation per attestation
- False attestation cost: 200 coins + 0.50 reputation loss
- Break-even attack threshold: 200 successful false attestations (economically irrational)
- Collusion requirement: 3+ ASNs, 2+ regions, 2+ orgs (organizational barrier)

---

## 17. CA Pool Anti-Sybil Constants

These constants define the enhanced protections against Sybil attacks on the FROST CA pool. The defense relies on six layers: network diversity, organization identity, TPM tiering, economic staking, reputation hardening, and behavioral monitoring.

### 17.1 Network Diversity Requirements

CA pool selection enforces strict network diversity to prevent single-entity dominance.

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolMaxPercentPerASN` | 15% | Maximum nodes from single ASN in CA pool | 05-certificate-authority.md |
| `CAPoolMinUniqueASNs` | 7 | Minimum distinct ASNs required in CA pool | 05-certificate-authority.md |
| `CAPoolMaxPercentPerSubnet24` | 3% | Maximum nodes from single /24 subnet | 05-certificate-authority.md |
| `CAPoolMaxNodesPerSubnet` | 5 | Hard limit on nodes per /24 subnet | 05-certificate-authority.md |
| `CAPoolMaxPercentPerCountry` | 15% | Maximum nodes from single country | 05-certificate-authority.md |
| `CAPoolMinCountries` | 5 | Minimum countries represented in CA pool | 05-certificate-authority.md |
| `CAPoolMaxPercentPerOrg` | 5% | Maximum nodes from single organization | 05-certificate-authority.md |
| `CAPoolMinUniqueOrgs` | 20 | Minimum distinct organizations at maturity | 05-certificate-authority.md |

**Rationale:** These constraints ensure that even if an attacker acquires many TPMs, they cannot dominate the CA pool without establishing presence across multiple ASNs, subnets, countries, and verified organizations. Increased from 25%/3 to 15%/5 to mitigate nation-state attack vectors where a nation + allied nations could control CA pool majority.

### 17.2 Organization Verification

Organization identity replaces per-TPM OwnerID with true organizational binding.

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `OrgVerificationDomain` | free | Domain verification cost (DNS TXT record) | 26-organization-identity.md |
| `OrgVerificationEconomic` | 1,000 coins | Economic verification stake amount | 26-organization-identity.md |
| `OrgStakeLockDuration` | 180 days | Lock duration for organization stake | 26-organization-identity.md |
| `OrgDomainVerificationTTL` | 90 days | Expiration for domain-based verification | 26-organization-identity.md |
| `OrgDNSRecordPrefix` | `_trusted-platform-org` | DNS TXT record prefix for verification | 26-organization-identity.md |

**Domain Verification Protocol:**
1. Operator sets DNS TXT record: `_trusted-platform-org.example.com`
2. Record contains: challenge + IDevID fingerprint
3. Platform verifies DNS + IDevID signature
4. Organization ID = SHA256(domain + IDevID)
5. Expires in 90 days (renewable)

**Economic Verification Protocol:**
1. Operator deposits 1,000 coins
2. Locked for 180 days minimum
3. IDevID must control deposit wallet
4. Organization ID = SHA256(wallet_id)
5. Stake is slashable for org-level misconduct

### 17.3 CA Pool Node Staking

Per-node staking requirements for CA pool participation with compounding costs.

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolBaseNodeStake` | 100 coins | Base stake for first CA-eligible node | 05-certificate-authority.md |
| `CAPoolCompoundingFactor` | 1.2 | Multiplier per additional node (exponential) | 05-certificate-authority.md |
| `CAPoolNodeStakeLockDuration` | 24 hours | Lock duration per node (one epoch) | 05-certificate-authority.md |
| `CAPoolMaxReputationDiscount` | 30% | Maximum stake discount at 0.95+ reputation | 05-certificate-authority.md |

**Stake Calculation Examples (single organization):**
| Node Count | Per-Node Stake | Cumulative Total |
|------------|----------------|------------------|
| Node 1 | 100 coins | 100 coins |
| Node 2 | 120 coins | 220 coins |
| Node 3 | 144 coins | 364 coins |
| Node 5 | 207 coins | 732 coins |
| Node 10 | 516 coins | ~1,600 coins |
| Node 20 | 3,834 coins | ~9,500 coins |

### 17.4 TPM Tier Classification

TPM hardware classification determines CA pool eligibility.

| Tier | Value | CA Pool Eligible | Infrastructure Eligible | Description | Referenced In |
|------|-------|-----------------|------------------------|-------------|---------------|
| `TPMTierHardware` | 1 | YES | YES | Discrete TPM (Infineon, STMicro, Nuvoton, etc.) | 03-security-trust.md |
| `TPMTierFirmware` | 2 | NO | YES | Firmware TPM (Intel PTT, AMD fTPM) | 03-security-trust.md |
| `TPMTierCloud` | 3 | NO | YES | Virtual TPM (AWS Nitro, Azure, GCP) | 03-security-trust.md |
| `TPMTierPlatform` | 4 | NO | YES | Platform-minted EK (foundation backbone) | 03-security-trust.md |

**Approved Hardware TPM Manufacturers:**
- Infineon Technologies
- STMicroelectronics
- Nuvoton Technology
- Microchip/Atmel
- Nations Technologies
- Additional manufacturers via governance approval

**Rationale:** Only discrete hardware TPMs provide the physical isolation and tamper resistance required for CA pool participation. Other tiers are acceptable for infrastructure roles (routing, DNS, gateway) but not certificate signing.

### 17.5 Verifier Diversity Requirements

CA eligibility requires verification from diverse sources to prevent collusion rings.

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolMinUniqueVerifiers` | 25 | Minimum distinct verifiers for CA eligibility | 09-defense-reputation.md |
| `CAPoolMinVerifierASNs` | 10 | Minimum ASNs among verifiers | 09-defense-reputation.md |
| `CAPoolMinVerifierRegions` | 5 | Minimum geographic regions among verifiers | 09-defense-reputation.md |
| `CAPoolMinVerifierOrgs` | 5 | Minimum organizations among verifiers | 09-defense-reputation.md |
| `CAPoolVerificationCooldown` | 4 hours | Minimum time between verifications from same source | 09-defense-reputation.md |

### 17.6 Early Period Reputation Caps

New nodes have capped reputation earning rates to prevent rapid Sybil promotion.

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `EarlyPeriodDays` | 180 | Duration of early period reputation caps | 09-defense-reputation.md |
| `EarlyPeriodMaxDailyGain` | 0.005 | Maximum daily reputation gain in early period | 09-defense-reputation.md |
| `NormalPeriodMaxDailyGain` | 0.01 | Maximum daily reputation gain after early period | 09-defense-reputation.md |

**Rationale:** At 0.005/day for 180 days, a node can reach 0.90 reputation in 180 days minimum. This extends the effective time barrier for CA eligibility to approximately 180 days regardless of activity level.

### 17.7 Behavioral Monitoring Thresholds

Graduated response based on collusion detection confidence.

| Confidence Level | VRF Weight Reduction | Stake Slash | Ban Duration | Actions |
|-----------------|---------------------|-------------|--------------|---------|
| 0.70-0.79 | 0% | 0% | None | Enhanced monitoring |
| 0.80-0.89 | 50% | 0% | None | Reduced VRF weight, monitoring |
| 0.90-0.94 | 75% | 0% | None | Alert operators, reduced weight |
| 0.95-0.98 | 100% | 25% | 30 days | Remove from pool, slash stake |
| 0.99+ | 100% | 100% | Permanent | Full slash, emergency rotation |

**Slashing Conditions:**

| Misconduct | Stake Loss | Reputation Loss | Ban Duration | Referenced In |
|------------|------------|-----------------|--------------|---------------|
| `Equivocation` | 100% | 100% | Permanent | 05-certificate-authority.md |
| `InvalidSignature` | 50% | 50% | 90 days | 05-certificate-authority.md |
| `Unavailability` | 10% | 10% | 7 days | 05-certificate-authority.md |
| `Collusion` | 100% + 50% org | 100% | Permanent | 05-certificate-authority.md |

### 17.8 Bootstrap Network Size Thresholds

Network size determines which diversity requirements apply.

| Phase | Node Count | Min Orgs | Min ASNs | Genesis Node Status | Referenced In |
|-------|------------|----------|----------|---------------------|---------------|
| Genesis | 0-100 | 3 | 2 | Foundation backbone active | 05-certificate-authority.md |
| Early | 100-1,000 | 5 | 3 | Genesis = regular nodes | 05-certificate-authority.md |
| Growth | 1,000-10,000 | 10 | 5 | Full competition | 05-certificate-authority.md |
| Mature | 10,000+ | 20 | 7 | Full requirements | 05-certificate-authority.md |

**Genesis Node Properties:**

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `GenesisNodeInitialReputation` | 0.95 | Starting reputation for genesis nodes | 05-certificate-authority.md |
| `GenesisNodeCAEligible` | hardware TPM only | CA pool eligible only with discrete TPM | 05-certificate-authority.md |
| `GenesisNodeForcedRetirement` | never | Genesis nodes are never forcibly retired | 05-certificate-authority.md |
| `FoundationBackboneSize` | 10-20 nodes | Foundation-operated infrastructure nodes | 05-certificate-authority.md |

**Rationale:** Bootstrap requirements are relaxed for small networks to allow initial growth, then progressively tighten as the network matures. Genesis nodes start with elevated trust but are subject to the same monitoring and slashing as all other nodes.

### 17.9 TPM Manufacturer Diversity for CA Pool

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolMaxPercentPerTPMManufacturer` | 30% | Maximum CA pool nodes from single TPM manufacturer | 05-certificate-authority.md |
| `CAPoolMinTPMManufacturers` | 3 | Minimum distinct TPM manufacturers in CA pool | 05-certificate-authority.md |

**Rationale:** Manufacturer diversity prevents supply chain attacks where a compromised TPM manufacturer could subvert the CA pool.

---

## 18. Network Scale Tiers

The network operates in different modes based on total node count. Many constants scale dynamically with network size.

### 18.1 Scale Tier Definitions

| Tier | Name | Node Range | Description | Referenced In |
|------|------|------------|-------------|---------------|
| 0 | Development | 0 - 10,000 | Testing and early development | 11-operations.md |
| 1 | Early Production | 10,000 - 1,000,000 | Initial production deployment | 11-operations.md |
| 2 | Growth | 1,000,000 - 100,000,000 | Scaling phase | 11-operations.md |
| 3 | Scale | 100,000,000 - 1,000,000,000 | Large-scale operation | 11-operations.md |
| 4 | Hyperscale | 1,000,000,000+ | Full IPv6 /36 capacity (4B+ nodes) | 11-operations.md |

### 18.2 Dynamic Scaling Formulas

Constants that scale with network size use these formulas:

| Constant | Formula | Tier 0 (10K) | Tier 2 (100M) | Tier 4 (4B) | Referenced In |
|----------|---------|--------------|---------------|-------------|---------------|
| `MaxPendingChallenges` | max(1M, NetworkSize / 1000) | 1,000,000 | 100,000,000 | 4,000,000,000 | 03-security-trust.md |
| `MinArbitratorQuorum` | max(3, ⌊log₂(NetworkSize) / 5⌋) | 3 | 5 | 6 | 21-ai-arbitration-system.md |
| `MinDistinctASNs` | max(5, ⌊log₂(NetworkSize) / 3⌋) | 5 | 9 | 11 | 02-network-architecture.md |
| `MinWitnessQuorum` | max(7, ⌊log₂(NetworkSize) / 2⌋) | 7 | 13 | 16 | 04-cryptographic-protocols.md |
| `ReputationCacheTTL` | max(5min, NetworkSize / 100M × 1min) | 5 min | 6 min | 45 min | 09-defense-reputation.md |

### 18.3 Scale Tier Detection

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `ScaleTierCheckInterval` | 1 hour | How often to recalculate network size | 11-operations.md |
| `ScaleTierHysteresis` | 10% | Hysteresis to prevent tier flapping | 11-operations.md |
| `ScaleTierSourceNodes` | 100 | Random sample size for network size estimation | 11-operations.md |
| `NetworkSizeEstimationAlgo` | capture-recapture | Statistical estimation algorithm | 11-operations.md |

### 18.4 Per-Tier Resource Budgets

| Resource | Tier 0 | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|----------|--------|--------|--------|--------|--------|
| Memory per node | 512 MB | 1 GB | 2 GB | 4 GB | 8 GB |
| Storage per node | 10 GB | 50 GB | 100 GB | 250 GB | 500 GB |
| Bandwidth (Leaf) | 10 Mbps | 25 Mbps | 50 Mbps | 100 Mbps | 200 Mbps |
| Bandwidth (Hub) | 50 Mbps | 100 Mbps | 250 Mbps | 500 Mbps | 1 Gbps |
| Bandwidth (Coordinator) | 100 Mbps | 250 Mbps | 500 Mbps | 1 Gbps | 2 Gbps |

---

## 19. Nonce Pool Management

FROST signing requires pre-generated nonces. These constants manage nonce pool pressure.

### 19.1 Nonce Pool Thresholds

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `NoncePoolMaxSize` | 1,000 | Maximum pre-generated nonces per node | 04-cryptographic-protocols.md |
| `NoncePoolWarningThreshold` | 200 | Trigger background replenishment | 04-cryptographic-protocols.md |
| `NoncePoolCriticalThreshold` | 50 | Enter rate-limited signing mode | 04-cryptographic-protocols.md |
| `NoncePoolEmergencyThreshold` | 10 | Reject new signing requests (except emergencies) | 04-cryptographic-protocols.md |
| `NonceReplenishmentRate` | 10/sec | Background nonce generation rate | 04-cryptographic-protocols.md |
| `NonceReservationEnabled` | true | Enable nonce reservation with rollback | 04-cryptographic-protocols.md |
| `NonceReservationTimeout` | 30s | Timeout before reserved nonce is released | 04-cryptographic-protocols.md |

**Note:** Nonces are reserved but not consumed until signature completion. Failed signatures release reserved nonces.

### 19.2 Nonce Pool Pressure Response

| Pool Level | State | Signing Rate Limit | Emergency Override | Referenced In |
|------------|-------|-------------------|-------------------|---------------|
| 200+ | Normal | No limit | N/A | 04-cryptographic-protocols.md |
| 50-199 | Warning | 50 req/min | Allowed | 04-cryptographic-protocols.md |
| 10-49 | Critical | 10 req/min | Allowed (priority queue) | 04-cryptographic-protocols.md |
| 0-9 | Emergency | 0 (blocked) | Emergency only (cert revocation) | 04-cryptographic-protocols.md |

### 19.3 TPM RNG Constraints

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `TPMRNGThroughput` | ~32 KB/s | Typical TPM random number generation rate | 04-cryptographic-protocols.md |
| `NonceSize` | 32 bytes | Size of each FROST nonce | 04-cryptographic-protocols.md |
| `MaxNonceGenRate` | ~1000/s | Theoretical max nonce generation rate | 04-cryptographic-protocols.md |
| `PracticalNonceGenRate` | 10-50/s | Practical rate accounting for TPM latency | 04-cryptographic-protocols.md |

---

## 20. CA Pool Health Monitoring

CA pool health monitoring ensures continuous certificate issuance availability.

### 20.1 Health Check Timing

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolHealthCheckInterval` | 5 min | Frequency of pool health checks | 05-certificate-authority.md |
| `CAPoolFailureDetectionWindow` | 15 min | Max time to detect pool failure | 05-certificate-authority.md |
| `CAPoolRecoverySLA` | 1 hour | Target time from detection to recovery | 05-certificate-authority.md |
| `CAPoolHeartbeatInterval` | 30s | Heartbeat interval for active pool members | 05-certificate-authority.md |
| `CAPoolMissedHeartbeats` | 6 | Missed heartbeats before member flagged unhealthy | 05-certificate-authority.md |

### 20.2 Standby Pool Management

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `CAPoolStandbyRatio` | 0.2 | Standby pool size as ratio of active pool | 05-certificate-authority.md |
| `CAPoolMinStandby` | 10 | Minimum standby pool members | 05-certificate-authority.md |
| `CAPoolStandbyRotationInterval` | 30 days | Rotation interval for standby members | 05-certificate-authority.md |
| `CAPoolStandbyPromotionQuorum` | 67% | Active pool approval for standby promotion | 05-certificate-authority.md |
| `CAPoolStandbyShareRefresh` | 7 days | Frequency of share fragment refresh for standby | 05-certificate-authority.md |

### 20.3 Automatic Failover Triggers

| Trigger | Threshold | Action | Referenced In |
|---------|-----------|--------|---------------|
| Active member failure | 1 member | Promote from standby | 05-certificate-authority.md |
| Pool below threshold | < 67% healthy | Alert + accelerated promotion | 05-certificate-authority.md |
| Pool quorum loss | < 34% healthy | Emergency DKG ceremony | 05-certificate-authority.md |
| Regional CA failure | 3 missed rotations | Failover to adjacent region | 05-certificate-authority.md |

### 20.4 Pool Health Metrics

| Metric | Warning Threshold | Critical Threshold | Referenced In |
|--------|------------------|-------------------|---------------|
| Healthy member % | < 80% | < 67% | 11-operations.md |
| Signing latency P99 | > 500ms | > 2s | 11-operations.md |
| Missed rotation count | 1 | 3 | 11-operations.md |
| Certificate issuance rate | < 50% baseline | < 20% baseline | 11-operations.md |

---

## 21. Collusion Economics

Dynamic collusion cost formula and sleeper attack detection.

### 21.1 Dynamic Collusion Cost

| Constant | Formula/Value | Description | Referenced In |
|----------|---------------|-------------|---------------|
| `BaseCollusionCost` | 35,000 coins | Minimum cost to attempt collusion | 09-defense-reputation.md |
| `DynamicCollusionCost` | max(35000, NetworkMarketCap^1.1 × 0.0000001) | Superlinear scaling with network value | 09-defense-reputation.md |
| `CollusionCostUpdateInterval` | 24 hours | How often to recalculate dynamic cost | 09-defense-reputation.md |
| `MarketCapSmoothingWindow` | 30 days | EMA window for market cap calculation | 09-defense-reputation.md |

**Rationale:** Superlinear scaling ensures attack cost grows faster than network value.

**Example Cost Scaling:**
| Network Market Cap | Dynamic Collusion Cost | Multiple of Base |
|-------------------|------------------------|------------------|
| $100M | 35,000 coins (floor) | 1x |
| $1B | 35,000 coins (floor) | 1x |
| $10B | 158,489 coins | 4.5x |
| $100B | 1,995,262 coins | 57x |
| $1T | 25,118,864 coins | 718x |

### 21.2 Sleeper Attack Detection

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `SleeperInactivityThreshold` | 90 days | Inactivity period triggering sleeper classification | 09-defense-reputation.md |
| `SleeperReactivationWindow` | 7 days | Monitoring window after reactivation | 09-defense-reputation.md |
| `SleeperCoordinationThreshold` | 3 nodes | Reactivations within window triggering alert. Reduced from 5 to prevent attackers from staggering 4 reactivations/week below detection | 09-defense-reputation.md |
| `DormantAccountReverification` | 180 days | Re-verification required after dormancy | 09-defense-reputation.md |
| `DormantReputationDecay` | 0.002/day | Additional decay for dormant accounts | 09-defense-reputation.md |

### 21.3 Cross-Domain Collusion Detection

| Domain Combination | Detection Signal | Action | Referenced In |
|-------------------|------------------|--------|---------------|
| CA + Judge | Same org controlling both | Enhanced monitoring | 09-defense-reputation.md |
| CA + Witness | Witness always supports CA member | Witness exclusion | 09-defense-reputation.md |
| Judge + Coordinator | Coordinated voting patterns | Both flagged | 09-defense-reputation.md |
| All domains | Same entity in 3+ critical roles | Emergency review | 09-defense-reputation.md |

---

## 22. Genesis Bootstrap Robustness

Enhanced genesis network bootstrap with checkpoint recovery.

### 22.1 Dynamic Bootstrap Timeout

| Constant | Formula/Value | Description | Referenced In |
|----------|---------------|-------------|---------------|
| `GenesisBaseTimeout` | 5 min | Base timeout for bootstrap | 11-operations.md |
| `GenesisTimeoutPerNode` | 30s | Additional timeout per genesis node | 11-operations.md |
| `GenesisBootstrapTimeout` | max(5min, 30s × GenesisNodeCount) | Dynamic total timeout | 11-operations.md |
| `GenesisMaxTimeout` | 30 min | Hard cap on bootstrap timeout | 11-operations.md |

**Timeout Examples:**
| Genesis Nodes | Calculated Timeout | Actual Timeout |
|---------------|-------------------|----------------|
| 10 | 5 min | 5 min (base) |
| 20 | 10 min | 10 min |
| 50 | 25 min | 25 min |
| 100 | 50 min | 30 min (capped) |

### 22.2 Bootstrap Checkpoint Protocol

| Phase | Checkpoint Name | Data Persisted | Referenced In |
|-------|-----------------|----------------|---------------|
| 1 | Discovery | Genesis node list, network topology | 11-operations.md |
| 2 | DKG Init | DKG session ID, participant commitments | 11-operations.md |
| 3 | DKG Complete | Group public key, share distribution | 11-operations.md |
| 4 | Finalization | Genesis block, initial state | 11-operations.md |

| Constant | Value | Description | Referenced In |
|----------|-------|-------------|---------------|
| `BootstrapMaxRetries` | 3 | Maximum retry attempts per phase | 11-operations.md |
| `BootstrapRetryDelay` | 60s | Delay between retry attempts | 11-operations.md |
| `BootstrapCheckpointTTL` | 24 hours | TTL for checkpoint data | 11-operations.md |
| `BootstrapRollbackDepth` | 1 phase | How many phases to rollback on failure | 11-operations.md |

### 22.3 Bootstrap Failure Recovery

| Failure Type | Recovery Action | Retry Allowed | Referenced In |
|--------------|-----------------|---------------|---------------|
| Discovery timeout | Retry with extended timeout | Yes (3x) | 11-operations.md |
| DKG participant failure | Exclude participant, restart DKG | Yes (3x) | 11-operations.md |
| DKG quorum loss | Full restart from discovery | Yes (1x) | 11-operations.md |
| Finalization failure | Rollback to DKG complete | Yes (3x) | 11-operations.md |
| All retries exhausted | Manual intervention required | No | 11-operations.md |

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0.0 | 2026-01-10 | Initial canonical constants reference | Backend Architect |
| 1.1.0 | 2026-01-10 | Added PBFT timing, VRF commit-reveal, partition recovery, hierarchical CA, cross-shard 3PC, clock sync, DKG state transfer, reputation staggering, DDoS enhancements | Architecture Review |
| 1.2.0 | 2026-01-10 | Added DKG disruption accountability constants: witness quorum, evidence retention, penalty tiers, appeals process | Architecture Review |
| 1.3.0 | 2026-01-10 | Enhanced CA Pool Anti-Sybil protections: increased CA Participant reputation (0.80->0.90) and min age (80->120 days); added Section 17 with network diversity requirements, organization verification, CA pool staking, TPM tier classification, verifier diversity, early period reputation caps, behavioral monitoring thresholds, and bootstrap network size thresholds | Security Review |
| 1.4.0 | 2026-01-10 | IPv6 /36 Production Readiness: Added Section 16.6 (Witness Pool Requirements with dynamic scaling, diversity requirements, selection protocol, and incentive structure); Section 18 (Network Scale Tiers with dynamic formulas and per-tier resource budgets); Section 19 (Nonce Pool Management with pressure response protocol); Section 20 (CA Pool Health Monitoring with standby pool management); Section 21 (Collusion Economics with dynamic cost formula and sleeper attack detection); Section 22 (Genesis Bootstrap Robustness with checkpoint protocol); Updated Section 7.3-7.5 (AI Arbitrator trial period increased to 1000 decisions, adversarial testing, model diversity requirements) | Production Review |
| 1.5.0 | 2026-01-10 | Security hardening: Nation-state defense strengthening (CAPoolMaxPercentPerCountry 25%->15%, CAPoolMinCountries 3->5); TPM manufacturer diversity (Section 17.9); PBFT timing adjustment (PBFTBaseTimeout 500ms->800ms for global distribution); Sleeper detection strengthening (SleeperCoordinationThreshold 5->3); Collusion cost superlinear scaling (NetworkMarketCap^1.1); Nonce reservation with rollback (Section 19.1) | Security Review |

---

## Usage Guidelines

1. **For Documentation Authors:**
   - Reference constants using format: `(see 00-CONSTANTS.md#section)`
   - Never duplicate constant values in other documents
   - Link to specific sections for context

2. **For Implementers:**
   - Import constants from canonical source files in `pkg/dht/constants/`
   - Never hardcode values; always reference named constants
   - Validate ranges and thresholds match this specification

3. **For Reviewers:**
   - Verify all hardcoded values match this reference
   - Flag any discrepancies between docs and implementation
   - Ensure new constants are added here before use

4. **Updating This Document:**
   - Increment version number for any changes
   - Document rationale for threshold adjustments
   - Update "Referenced In" columns
   - Notify all stakeholders of changes

---

## Notes

- All timing values assume stable network conditions (latency <100ms)
- Thresholds may require tuning based on production telemetry
- Security constants prioritize safety over performance
- Reputation thresholds follow principle of least privilege
- Network parameters balance discovery speed vs. bandwidth


# Defense and Reputation System

## Overview

The Defense and Reputation System provides a complete framework for establishing trust, maintaining network integrity, and enforcing behavioral standards in the trusted DHT network. This document is the **canonical source** for all reputation thresholds, role eligibility requirements, and defense mechanisms.

The system operates on two interconnected pillars:

1. **Reputation System**: A meritocratic model where nodes start with zero reputation and earn privileges through demonstrated value and reliability
2. **Collaborative Defense**: Byzantine fault-tolerant peer monitoring with TPM-attested evidence, PBFT-style quorum judgment, and automated penalty enforcement

**Source**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/`

---

## Terminology: Judge vs Arbiter

The go-trusted-platform documentation uses two distinct terms for decision-makers in dispute resolution:

| Term | Context | Scope | Role |
|------|---------|-------|------|
| **Judge** | Defense/Reputation System | Protocol violations | Evaluates TPM-attested evidence of misbehavior (DoS, protocol violations, manipulation) |
| **Arbiter** | Service Contracts | Business disputes | Resolves disputes between contract parties (quality, delivery, payment) |

**Key Differences:**

| Aspect | Judge | Arbiter |
|--------|-------|---------|
| **Selection** | VRF-based deterministic selection | VRF-based from contract's arbiter pool |
| **Quorum** | 7-of-11 (defense system) | 5-of-7 (contract disputes) |
| **Evidence** | TPM-attested packets, signed proofs | Contract terms, delivery records, communications |
| **Penalties** | Reputation reduction, ban | Escrow distribution, contract termination |
| **Canonical Doc** | This document (09-defense-reputation.md) | 19-service-contracts.md |

**Do NOT use interchangeably.** This distinction is enforced throughout the documentation.

---

# Part 1: Reputation System

## Zero-Trust Start

All nodes join the network with no inherent trust. This design prevents Sybil attacks by making it economically and temporally expensive to establish trusted nodes.

### Initial State

| Attribute | Value |
|-----------|-------|
| Initial Reputation | 0.0 |
| Default Role | Leaf |
| Minimum Capabilities | Basic network participation |

### Zero-Reputation Capabilities

Nodes with 0.0 reputation can perform:

1. **DHT Routing**: Participate in distributed hash table operations
   - Store and retrieve data
   - Route queries to appropriate nodes
   - Maintain routing table entries

2. **Transaction Confirmation**: Validate and confirm transactions
   - Verify transaction signatures
   - Propagate confirmed transactions
   - Participate in consensus mechanisms

### Restricted Operations

Zero-reputation nodes cannot:
- Participate in Certificate Authority operations
- Serve as network hubs
- Act as gateways to external networks
- Coordinate network-wide operations
- Influence critical governance decisions

## Trust Level Prerequisites (CRITICAL)

**IMPORTANT**: The reputation system ONLY applies to **Trusted** nodes. Untrusted nodes have hard-coded capability caps that cannot be bypassed.

| Trust Level | Reputation Capability | Role Progression | CA Access |
|-------------|----------------------|------------------|-----------|
| **Trusted** | Can earn 0.0 to 1.0 | Full progression (Leaf to Coordinator) | Yes (at 0.90+) |
| **Untrusted** | **Hard cap at 0.0** | **Observer only (NEVER)** | **NEVER** |

See [03-security-trust.md](03-security-trust.md) Section 15 "Trust Level Enforcement" for complete details on untrusted node hard caps.

## Reputation Growth Formula

Reputation increases through a hybrid model combining passive time-based accrual and active contribution rewards.

### Daily Gain Calculation

```
daily_gain = min(0.01, time_component + activity_component)
```

### Time Component (Passive)

| Parameter | Value |
|-----------|-------|
| Rate | 0.003 reputation per day |
| Requirement | Node must be online and responsive |
| Annual Maximum | 1.095 reputation (without activity) |

### Activity Component (Active)

| Parameter | Value |
|-----------|-------|
| Maximum | 0.007 reputation per day |
| Calculation | Sum of all successful operations |
| Acceleration | Active nodes earn up to 3.3x faster than passive nodes |

### Daily Cap Rationale

The standard 0.01/day maximum (0.005/day during early period) ensures:
- Minimum 180 days to reach CA participant eligibility (0.90 reputation with 0.005/day early period cap)
- Minimum 80 days to reach Hub eligibility (0.80 reputation with 0.01/day cap, assuming early period passed)
- Minimum 95 days to reach coordinator eligibility (0.95 reputation with 0.01/day cap)
- Prevents rapid reputation accumulation through burst activity
- Creates predictable timelines for role progression

**Mathematical Verification (Standard Period)**:
- Time Component: 0.003/day
- Activity Component: 0.007/day (maximum)
- Total Daily Cap: 0.01/day
- Days to reach 0.70: 70 days (0.70 / 0.01 = 70)
- Days to reach 0.80: 80 days (0.80 / 0.01 = 80)
- Days to reach 0.90: 90 days (0.90 / 0.01 = 90)
- Days to reach 0.95: 95 days (0.95 / 0.01 = 95)

**Early Period Cap Impact (First 180 Days)**:
- Early Period Cap: 0.005/day maximum
- Days to reach 0.90 during early period: 180 days (0.90 / 0.005 = 180)
- See "Early Period Reputation Earning Caps" section for full details

## Activity-Based Earnings

| Activity | Reputation Gain | Notes |
|----------|-----------------|-------|
| **DHT Operations** | | |
| DHT query routed | 0.000001 | Per successful query routing |
| DHT data stored | 0.000005 | Per data item stored (max 1 hour) |
| **Transaction Processing** | | |
| Transaction confirmation | 0.00001 | Per validated transaction |
| **Service Provision** | | |
| Storage service hour | 0.0001 | Per hour of storage provided |
| Compute service hour | 0.0001 | Per hour of compute resources |
| Bandwidth relay (1GB) | 0.00005 | Per gigabyte relayed |

### Earning Examples

**Low Activity Node** (DHT only):
- 1,000 DHT queries/day = 0.001
- 200 data stores/day = 0.001
- Time component = 0.003
- **Total**: 0.005/day (50% of cap)

**High Activity Node** (Multiple services):
- DHT operations = 0.002
- Transaction confirmations (100/day) = 0.001
- Storage service (24 hours) = 0.0024
- Time component = 0.003
- **Total**: 0.0084/day -> **Capped at 0.01/day**

## Role Eligibility Thresholds (CANONICAL)

This section defines the **authoritative** role eligibility requirements for the entire system. All other documents must reference this table.

### Progression Timeline

**TERMINOLOGY CLARIFICATION (P5-M11)**:
- **Min. Network Age**: Days of continuous network participation required before role eligibility
- **Effective Minimum**: Total days including probation period enforcement
- These values are INDEPENDENT of reputation thresholds (coincidental numerical similarity)

| Role | Required Reputation | Min. Network Age (Days) | Effective Minimum* |
|------|---------------------|------------------------|-------------------|
| Leaf | 0.0 | 0 | Immediate |
| CA Participant | 0.90 | 120 | 127-141 days |
| Hub | 0.80 | 80 | 110 days |
| Gateway | 0.85 | 85 | 175 days |
| Coordinator | 0.95 | 95 | 185 days |

*Effective minimum = Min. Network Age + Probation Period + Random Stagger Delay (see below)

**SECURITY NOTE (H2/H16)**: CA participants require 0.90 minimum reputation and 120 days network age to ensure certificate signing authority is granted only to highly trusted nodes with extended behavioral history. This elevated threshold (increased from 0.80/80 days) provides stronger anti-Sybil defense by requiring longer observation periods before CA pool eligibility. See `00-CONSTANTS.md` Section 17 for canonical CA Pool Anti-Sybil constants.

### Role Eligibility Staggering (CANONICAL)

To prevent coordinated promotion attacks where multiple Sybil nodes attempt to gain elevated roles simultaneously, the system enforces deterministic random delays on role promotions. Even when a node meets all reputation and network age requirements, promotion is delayed by a node-specific random period.

**Stagger Delay Calculation:**

```go
// RoleStaggerConfig defines staggered promotion delays per role
type RoleStaggerConfig struct {
    BaseMinNetworkAge  time.Duration  // Minimum network age before eligibility check
    MaxStaggerDelay    time.Duration  // Maximum additional random delay
}

var RoleStaggerDelays = map[Role]RoleStaggerConfig{
    RoleCAParticipant: {BaseMinNetworkAge: 120 * 24 * time.Hour, MaxStaggerDelay: 14 * 24 * time.Hour},
    RoleHub:           {BaseMinNetworkAge: 80 * 24 * time.Hour, MaxStaggerDelay: 21 * 24 * time.Hour},
    RoleGateway:       {BaseMinNetworkAge: 85 * 24 * time.Hour, MaxStaggerDelay: 30 * 24 * time.Hour},
    RoleCoordinator:   {BaseMinNetworkAge: 95 * 24 * time.Hour, MaxStaggerDelay: 30 * 24 * time.Hour},
}

// CalculateStaggerDelay returns deterministic delay based on NodeID
// The delay is consistent across restarts and cannot be gamed
func CalculateStaggerDelay(nodeID [32]byte, role Role) time.Duration {
    config := RoleStaggerDelays[role]

    // Create deterministic seed from NodeID and role
    h := sha256.New()
    h.Write(nodeID[:])
    h.Write([]byte(fmt.Sprintf("stagger:%d", role)))
    seed := h.Sum(nil)

    // Convert first 8 bytes to uint64 for consistent random value
    randomValue := binary.BigEndian.Uint64(seed[:8])

    // Scale to delay range [0, MaxStaggerDelay]
    maxDelayNanos := uint64(config.MaxStaggerDelay.Nanoseconds())
    delayNanos := randomValue % maxDelayNanos

    return time.Duration(delayNanos)
}

// IsEligibleForPromotion checks all promotion requirements including stagger
func IsEligibleForPromotion(node *Node, targetRole Role) (bool, time.Time, error) {
    config := RoleStaggerDelays[targetRole]

    // Check base reputation requirement
    requiredRep := RoleReputationThresholds[targetRole]
    if node.Reputation < requiredRep {
        return false, time.Time{}, nil
    }

    // Check base network age
    networkAge := time.Since(node.JoinedAt)
    if networkAge < config.BaseMinNetworkAge {
        return false, time.Time{}, nil
    }

    // Calculate node-specific stagger delay
    staggerDelay := CalculateStaggerDelay(node.ID, targetRole)

    // Effective eligibility time = join time + base age + stagger delay
    eligibleAt := node.JoinedAt.Add(config.BaseMinNetworkAge).Add(staggerDelay)

    if time.Now().Before(eligibleAt) {
        return false, eligibleAt, nil // Not yet eligible, return when they will be
    }

    return true, eligibleAt, nil
}
```

**Effective Minimum Ages with Stagger:**

| Role | Base Min. Age | Stagger Range | Effective Min. Age |
|------|---------------|---------------|-------------------|
| CA Participant | 120 days | 0-14 days | 120-134 days |
| Hub | 80 days | 0-21 days | 80-101 days |
| Gateway | 85 days | 0-30 days | 85-115 days |
| Coordinator | 95 days | 0-30 days | 95-125 days |

**Security Properties:**

| Property | Guarantee |
|----------|-----------|
| Deterministic | Same NodeID always gets same delay (no retry advantage) |
| Unpredictable | Cannot predict delay before node creation |
| Attack-resistant | Coordinated Sybil nodes get distributed delays |
| Verifiable | Any node can verify another's eligibility time |

### Role Capabilities

**Leaf Node** (0.0 reputation)
- DHT routing and storage
- Transaction confirmation
- Basic network participation

**CA Participant** (0.90 reputation)
- Certificate generation and validation
- Participate in trust decisions
- Vote on node reputation challenges
- Must meet Verifier Diversity Requirements (see below)

**Hub** (0.80 reputation)
- Serve as routing hub for network traffic
- Maintain connections to multiple regions
- Cache frequently accessed data

**Gateway** (0.85 reputation)
- Bridge to external networks
- API endpoint for external services
- Protocol translation

**Coordinator** (0.95 reputation)
- Network-wide coordination
- Consensus leadership
- Emergency governance actions

## Probation Periods

Probation periods serve as additional security barriers that verify sustained reputation maintenance and prevent rapid privilege escalation attacks.

### Probation Requirements

**SECURITY FIX (P5-H12): Uptime Requirements Clarification**

Probation periods have STRICTER uptime requirements than ongoing operation.
Once probation completes, nodes must maintain the lower ongoing uptime threshold.

| Role | Probation Duration | Requirements During Probation | Ongoing Requirements |
|------|-------------------|------------------------------|---------------------|
| Leaf | None | Immediate activation | N/A (basic DHT only) |
| CA Participant | 7 days | Maintain >=0.90 reputation, no violations, verifier diversity met | >=0.90 rep, 95% uptime |
| Hub | 30 days | Maintain >=0.80 reputation, **99% uptime** | >=0.80 rep, **95% uptime** |
| Gateway | 90 days | Maintain >=0.85 reputation, **99.5% uptime**, security audit | >=0.85 rep, **95% uptime** |
| Coordinator | 90 days | Maintain >=0.95 reputation, **99% uptime**, community review | >=0.95 rep, **99% uptime** |

**Rationale**: Stricter probation requirements ensure new role-holders demonstrate
sustained reliability before being granted reduced thresholds. Coordinators maintain
99% uptime permanently due to their critical role in consensus.

### Probation Failure

If a node drops below the required reputation threshold during probation:
- Probation period resets to day 0
- Role promotion is cancelled
- Node must regain reputation and restart probation

### Early Termination

Probation may be extended or terminated if:
- Security violations are detected
- Abnormal activity patterns emerge
- Community governance raises concerns
- Network stability requires stricter controls

## Verifier Diversity Requirements for CA Eligibility (CANONICAL)

CA pool participation requires verification from diverse sources to prevent collusion rings and Sybil attacks. These requirements ensure that no single entity can artificially boost nodes to CA eligibility through coordinated verification.

**Reference**: See `00-CONSTANTS.md` Section 17.5 for canonical constant values.

### Diversity Thresholds

| Requirement | Value | Description |
|-------------|-------|-------------|
| `MinUniqueVerifiers` | 25 | Must have attestations from 25 unique nodes |
| `MinVerifierASNs` | 10 | Verifiers must come from at least 10 distinct ASNs |
| `MinVerifierRegions` | 5 | Verifiers must be from at least 5 geographic regions |
| `MinVerifierOrgs` | 5 | Verifiers must be from at least 5 different organizations |
| `VerificationCooldown` | 4 hours | Minimum time between verifications from the same verifier |

### Rationale

These diversity requirements provide multiple layers of anti-Sybil defense:

1. **Unique Verifier Count (25)**: Ensures broad validation across the network, making it expensive to create fake verification networks
2. **ASN Diversity (10)**: Prevents an attacker from using nodes within a single network to self-verify
3. **Geographic Diversity (5 regions)**: Ensures global distribution and prevents single-jurisdiction attacks
4. **Organization Diversity (5)**: Leverages organization verification to prevent corporate Sybil attacks
5. **Verification Cooldown (4 hours)**: Prevents rapid re-verification and forces temporal distribution

### Implementation

```go
// CAEligibilityVerifierDiversity defines diversity requirements for CA pool eligibility
type CAEligibilityVerifierDiversity struct {
    MinUniqueVerifiers   int           // Minimum 25 unique verifiers
    MinVerifierASNs      int           // Minimum 10 distinct ASNs
    MinVerifierRegions   int           // Minimum 5 geographic regions
    MinVerifierOrgs      int           // Minimum 5 organizations
    VerificationCooldown time.Duration // Minimum 4 hours between same-verifier attestations
}

// DefaultCAEligibilityDiversity returns production configuration
func DefaultCAEligibilityDiversity() CAEligibilityVerifierDiversity {
    return CAEligibilityVerifierDiversity{
        MinUniqueVerifiers:   25,
        MinVerifierASNs:      10,
        MinVerifierRegions:   5,
        MinVerifierOrgs:      5,
        VerificationCooldown: 4 * time.Hour,
    }
}

// VerifierRecord tracks a single verification for diversity analysis
type VerifierRecord struct {
    VerifierID    [32]byte
    VerifierASN   uint32
    VerifierRegion string
    VerifierOrg   string
    Timestamp     time.Time
    TPMQuote      []byte
}

// ValidateCAVerifierDiversity checks if a node meets CA eligibility diversity requirements
func ValidateCAVerifierDiversity(
    nodeID [32]byte,
    verifications []VerifierRecord,
    config CAEligibilityVerifierDiversity,
) (*CADiversityResult, error) {
    result := &CADiversityResult{
        NodeID:         nodeID,
        TotalVerifiers: 0,
        UniqueASNs:     make(map[uint32]bool),
        UniqueRegions:  make(map[string]bool),
        UniqueOrgs:     make(map[string]bool),
    }

    // Track verifiers and their last verification time
    verifierLastTime := make(map[[32]byte]time.Time)
    validVerifications := make([]VerifierRecord, 0)

    for _, v := range verifications {
        // Check cooldown period
        if lastTime, exists := verifierLastTime[v.VerifierID]; exists {
            if v.Timestamp.Sub(lastTime) < config.VerificationCooldown {
                continue // Skip verification within cooldown
            }
        }
        verifierLastTime[v.VerifierID] = v.Timestamp
        validVerifications = append(validVerifications, v)

        result.UniqueASNs[v.VerifierASN] = true
        result.UniqueRegions[v.VerifierRegion] = true
        result.UniqueOrgs[v.VerifierOrg] = true
    }

    result.TotalVerifiers = len(verifierLastTime)
    result.ASNCount = len(result.UniqueASNs)
    result.RegionCount = len(result.UniqueRegions)
    result.OrgCount = len(result.UniqueOrgs)

    // Validate all requirements
    result.MeetsRequirements = result.TotalVerifiers >= config.MinUniqueVerifiers &&
        result.ASNCount >= config.MinVerifierASNs &&
        result.RegionCount >= config.MinVerifierRegions &&
        result.OrgCount >= config.MinVerifierOrgs

    // Build detailed failure reasons if not meeting requirements
    if !result.MeetsRequirements {
        if result.TotalVerifiers < config.MinUniqueVerifiers {
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("insufficient verifiers: %d/%d", result.TotalVerifiers, config.MinUniqueVerifiers))
        }
        if result.ASNCount < config.MinVerifierASNs {
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("insufficient ASN diversity: %d/%d", result.ASNCount, config.MinVerifierASNs))
        }
        if result.RegionCount < config.MinVerifierRegions {
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("insufficient regional diversity: %d/%d", result.RegionCount, config.MinVerifierRegions))
        }
        if result.OrgCount < config.MinVerifierOrgs {
            result.FailureReasons = append(result.FailureReasons,
                fmt.Sprintf("insufficient organization diversity: %d/%d", result.OrgCount, config.MinVerifierOrgs))
        }
    }

    return result, nil
}

// CADiversityResult contains the verification diversity analysis
type CADiversityResult struct {
    NodeID          [32]byte
    TotalVerifiers  int
    ASNCount        int
    RegionCount     int
    OrgCount        int
    UniqueASNs      map[uint32]bool
    UniqueRegions   map[string]bool
    UniqueOrgs      map[string]bool
    MeetsRequirements bool
    FailureReasons  []string
}
```

### Verification Process

1. **Collect Verifications**: Node accumulates attestations from other network participants
2. **Apply Cooldown Filter**: Only count verifications that respect the 4-hour cooldown per verifier
3. **Calculate Diversity Metrics**: Count unique verifiers, ASNs, regions, and organizations
4. **Evaluate Eligibility**: All four diversity thresholds must be met simultaneously
5. **Record Result**: Store diversity analysis for CA pool selection consideration

### Attack Mitigation

| Attack Vector | Mitigation |
|---------------|------------|
| Single-entity verification ring | 25 unique verifiers required |
| Same-network Sybil cluster | 10 ASN minimum prevents single-network attacks |
| Regional collusion | 5 region minimum ensures global distribution |
| Corporate bulk attacks | 5 organization minimum, leveraging OrgID verification |
| Rapid farming | 4-hour cooldown prevents burst verification |

## Early Period Reputation Earning Caps (CANONICAL)

New nodes have capped reputation earning rates during their first 180 days ("early period") to prevent rapid Sybil promotion and ensure adequate time for behavioral monitoring.

**Reference**: See `00-CONSTANTS.md` Section 17.6 for canonical constant values.

### Earning Rate Limits

| Period | Duration | Max Daily Gain | Purpose |
|--------|----------|----------------|---------|
| Early Period | Days 0-180 | 0.005/day | Extended observation, anti-Sybil defense |
| Normal Period | Day 181+ | 0.01/day | Standard earning rate for established nodes |

### Mathematical Analysis

**Time to CA Eligibility (0.90 reputation):**

- **With Early Period Caps**: At maximum 0.005/day for 180 days = 0.90 reputation
  - Minimum time to 0.90: **180 days**

- **Without Early Period Caps**: At maximum 0.01/day = 90 days to 0.90
  - This would allow rapid farming before behavioral patterns can be detected

**Combined with Network Age Requirement:**

| Requirement | Value | Binding Constraint |
|-------------|-------|-------------------|
| Min Network Age | 120 days | Network age reached first |
| Time to 0.90 reputation | 180 days (early period) | Reputation is binding constraint |
| Effective minimum | **180 days** | Early period cap ensures extended observation |

### Rationale

1. **Extended Behavioral Monitoring**: 180 days provides sufficient time to detect anomalous patterns, collusion attempts, and Sybil behavior
2. **Economic Cost Increase**: Attackers must maintain nodes for 180 days minimum, increasing operational costs
3. **Pattern Detection Window**: Network monitoring systems have 6 months to identify coordinated attacks
4. **Reputation Integrity**: Prevents nodes from "gaming" to CA eligibility faster than legitimate participants

### Implementation

```go
// EarlyPeriodConfig defines reputation earning caps for new nodes
type EarlyPeriodConfig struct {
    EarlyPeriodDays       int     // Duration of early period (180 days)
    EarlyPeriodMaxDaily   float64 // Max daily gain during early period (0.005)
    NormalPeriodMaxDaily  float64 // Max daily gain after early period (0.01)
}

// DefaultEarlyPeriodConfig returns production configuration
func DefaultEarlyPeriodConfig() EarlyPeriodConfig {
    return EarlyPeriodConfig{
        EarlyPeriodDays:      180,
        EarlyPeriodMaxDaily:  0.005,
        NormalPeriodMaxDaily: 0.01,
    }
}

// CalculateDailyCap returns the applicable daily reputation cap for a node
func CalculateDailyCap(node *Node, config EarlyPeriodConfig) float64 {
    networkAgeDays := int(time.Since(node.JoinedAt).Hours() / 24)

    if networkAgeDays < config.EarlyPeriodDays {
        return config.EarlyPeriodMaxDaily
    }
    return config.NormalPeriodMaxDaily
}

// ApplyReputationGain applies reputation gain with early period caps
func ApplyReputationGain(
    node *Node,
    earnedReputation float64,
    config EarlyPeriodConfig,
) (appliedGain float64, cappedAmount float64) {
    dailyCap := CalculateDailyCap(node, config)

    // Check if node has already earned reputation today
    todayGain := node.GetTodayReputationGain()
    remainingCap := dailyCap - todayGain

    if remainingCap <= 0 {
        return 0, earnedReputation // Fully capped
    }

    if earnedReputation <= remainingCap {
        appliedGain = earnedReputation
        cappedAmount = 0
    } else {
        appliedGain = remainingCap
        cappedAmount = earnedReputation - remainingCap
    }

    node.AddReputationGain(appliedGain)
    return appliedGain, cappedAmount
}
```

### Interaction with Daily Cap

The early period cap replaces the standard daily cap during the first 180 days:

| Node Age | Daily Cap | Days to 0.90 | Notes |
|----------|-----------|--------------|-------|
| 0-180 days | 0.005/day | 180 days | Early period rate |
| 181+ days | 0.01/day | 90 days (from 0) | Standard rate |

**Note**: Since early period applies from day 0, a new node reaching 0.90 reputation requires exactly 180 days at maximum earning rate (180 * 0.005 = 0.90).

## Decay Mechanics

### Inactivity Decay

| Parameter | Value |
|-----------|-------|
| Trigger | No network activity for 7+ consecutive days |
| Rate | -0.005 reputation per day |
| Floor | 0.0 (reputation cannot go negative) |

**Example**:
- Node reaches 0.80 reputation, then goes offline
- After 7 days of inactivity, decay begins
- After 30 additional days: 0.80 - (30 x 0.005) = 0.65 reputation
- Node drops below hub eligibility, loses hub role

### Violation-Based Decay

| Violation Level | Reputation Penalty | Examples |
|-----------------|-------------------|----------|
| Minor | -0.05 | Intermittent availability, slow response times, stale routing data |
| Moderate | -0.15 | Incorrect data, failed validations, missed service commitments |
| Major | -0.30 | Deliberate misinformation, data manipulation, Byzantine behavior |

### Recovery from Decay

Nodes recover lost reputation by:
1. Resuming active participation (stops decay)
2. Earning reputation through normal activities
3. Maintaining consistent uptime
4. Avoiding further violations

**Recovery Time Example**:
- Node loses 0.15 reputation (moderate violation)
- At maximum earning rate (0.01/day), requires 15 days to recover
- Effective penalty includes both immediate loss and recovery time

## Anti-Gaming Measures

### Sybil Resistance

**Time Requirements**:
- Minimum 95 days to reach coordinator status
- Probation periods cannot be accelerated
- Creating multiple identities provides no time advantage

**Economic Cost**:
- Maintaining active nodes requires real resources
- Uptime requirements necessitate infrastructure investment
- Service provision has measurable costs

### Activity Validation

**Rate Limiting**:
- Daily reputation cap prevents burst farming
- Activity must be distributed across time
- Sudden activity spikes trigger monitoring

**Quality Verification**:
- DHT queries must be successfully routed (not just attempted)
- Stored data must remain available for verification
- Transactions must be correctly validated
- Service hours must meet quality thresholds

**Peer Validation**:
- Other nodes verify reputation-earning activities
- Invalid claims result in violation penalties
- Reputation challenges can trigger audits

### Collusion Prevention

**Distributed Validation**:
- Multiple nodes must confirm activity
- Random sampling prevents predictable collusion
- Reputation from single source is limited

**Economic Disincentives**:
- Creating verification cartels requires many long-lived nodes
- Cost of maintaining collusion exceeds reputation value
- Detection results in severe penalties for all participants

### Anomaly Detection

**Pattern Analysis**:
- Statistical models identify unusual earning patterns
- Machine learning detects coordinated behavior
- Temporal analysis reveals automation

**Threshold Monitoring**:
- Nodes approaching role thresholds receive extra scrutiny
- Probation periods allow additional validation
- Community governance can flag suspicious nodes

### Promotion Anomaly Detection (CANONICAL)

The system actively monitors for suspicious patterns in role promotions that may indicate coordinated attacks or manipulation.

**Synchronized Promotion Detection:**

```go
// PromotionAnomalyDetector monitors for suspicious promotion patterns
type PromotionAnomalyDetector struct {
    promotionHistory  map[time.Time][]PromotionEvent
    deploymentSources map[string][]PromotionEvent
    reputationVelocity map[[32]byte]float64
    mu               sync.RWMutex
}

// PromotionAnomalyConfig defines detection thresholds
type PromotionAnomalyConfig struct {
    SyncWindowDays            int     // Window for synchronized promotion check (default: 7)
    MaxSimultaneousPromotions int     // Max promotions from same source (default: 10)
    ReputationVelocityThreshold float64 // Max rep gain per day before review (default: 0.005)
    VoucherRequirement        int     // Established nodes required to vouch (default: 2)
    VoucherMinReputation      float64 // Min reputation for voucher (default: 0.85)
    VoucherMinAge             time.Duration // Min age for voucher (default: 180 days)
}

var DefaultPromotionAnomalyConfig = PromotionAnomalyConfig{
    SyncWindowDays:            7,
    MaxSimultaneousPromotions: 10,
    ReputationVelocityThreshold: 0.005,
    VoucherRequirement:        2,
    VoucherMinReputation:      0.85,
    VoucherMinAge:             180 * 24 * time.Hour,
}

// DetectSynchronizedPromotions identifies nodes promoted within suspicious windows
func (pad *PromotionAnomalyDetector) DetectSynchronizedPromotions(
    windowDays int,
) []PromotionCluster {
    pad.mu.RLock()
    defer pad.mu.RUnlock()

    var clusters []PromotionCluster
    window := time.Duration(windowDays) * 24 * time.Hour

    // Group promotions by window
    for baseTime, events := range pad.promotionHistory {
        windowEnd := baseTime.Add(window)

        var inWindow []PromotionEvent
        for t, evts := range pad.promotionHistory {
            if t.After(baseTime) && t.Before(windowEnd) {
                inWindow = append(inWindow, evts...)
            }
        }

        // Flag if too many promotions in window
        if len(inWindow) > DefaultPromotionAnomalyConfig.MaxSimultaneousPromotions {
            clusters = append(clusters, PromotionCluster{
                WindowStart: baseTime,
                WindowEnd:   windowEnd,
                Promotions:  inWindow,
                Severity:    calculateClusterSeverity(len(inWindow)),
            })
        }
    }

    return clusters
}

// CheckDeploymentSourceLimit enforces max promotions from same deployment
func (pad *PromotionAnomalyDetector) CheckDeploymentSourceLimit(
    nodeID [32]byte,
    deploymentSource string,
) error {
    pad.mu.RLock()
    promotions := pad.deploymentSources[deploymentSource]
    pad.mu.RUnlock()

    // Count recent promotions from this source (last 30 days)
    recentCount := 0
    cutoff := time.Now().Add(-30 * 24 * time.Hour)
    for _, p := range promotions {
        if p.Timestamp.After(cutoff) {
            recentCount++
        }
    }

    if recentCount >= DefaultPromotionAnomalyConfig.MaxSimultaneousPromotions {
        return &ErrDeploymentSourceLimitExceeded{
            Source:     deploymentSource,
            Count:      recentCount,
            Limit:      DefaultPromotionAnomalyConfig.MaxSimultaneousPromotions,
        }
    }

    return nil
}

// CheckReputationVelocity flags nodes gaining reputation too quickly
func (pad *PromotionAnomalyDetector) CheckReputationVelocity(
    nodeID [32]byte,
    currentRep, previousRep float64,
    daysSinceLastCheck int,
) (bool, float64) {
    if daysSinceLastCheck == 0 {
        return false, 0
    }

    velocity := (currentRep - previousRep) / float64(daysSinceLastCheck)
    pad.mu.Lock()
    pad.reputationVelocity[nodeID] = velocity
    pad.mu.Unlock()

    // Flag if velocity exceeds threshold
    if velocity > DefaultPromotionAnomalyConfig.ReputationVelocityThreshold {
        return true, velocity
    }

    return false, velocity
}
```

**Voucher Requirement for Promotion:**

High-privilege role promotions require endorsement from established nodes to prevent isolated Sybil clusters from self-promoting.

```go
// VoucherRequirement defines promotion endorsement requirements
type VoucherRequirement struct {
    NodeID         [32]byte
    TargetRole     Role
    RequiredCount  int
    Vouchers       []Voucher
    VerifiedAt     time.Time
}

// Voucher represents an endorsement from an established node
type Voucher struct {
    VoucherID       [32]byte   // Vouching node's ID
    VoucherRep      float64    // Voucher's reputation at time of vouching
    VoucherAge      time.Duration // Voucher's network age
    VoucheeID       [32]byte   // Node being vouched for
    TargetRole      Role       // Role being vouched for
    Signature       []byte     // TPM-attested signature
    Timestamp       time.Time
    Justification   string     // Why this node should be promoted
}

// ValidateVoucherRequirements checks if promotion vouchers are satisfied
func ValidateVoucherRequirements(
    nodeID [32]byte,
    targetRole Role,
    vouchers []Voucher,
    config PromotionAnomalyConfig,
) error {
    // Critical roles require vouchers
    if targetRole == RoleGateway || targetRole == RoleCoordinator {
        if len(vouchers) < config.VoucherRequirement {
            return &ErrInsufficientVouchers{
                Required: config.VoucherRequirement,
                Provided: len(vouchers),
                Role:     targetRole,
            }
        }
    }

    // Validate each voucher
    validVouchers := 0
    for _, v := range vouchers {
        // Voucher must meet reputation threshold
        if v.VoucherRep < config.VoucherMinReputation {
            continue
        }

        // Voucher must meet age threshold
        if v.VoucherAge < config.VoucherMinAge {
            continue
        }

        // Voucher cannot vouch for themselves
        if v.VoucherID == v.VoucheeID {
            continue
        }

        // Verify voucher signature
        if err := verifyVoucherSignature(&v); err != nil {
            continue
        }

        validVouchers++
    }

    if validVouchers < config.VoucherRequirement {
        return &ErrInsufficientValidVouchers{
            Required: config.VoucherRequirement,
            Valid:    validVouchers,
            Role:     targetRole,
        }
    }

    return nil
}
```

**Promotion Anomaly Detection Summary:**

| Check | Threshold | Action on Violation |
|-------|-----------|---------------------|
| Synchronized promotions | >10 in 7-day window | Manual review, possible delay extension |
| Same deployment source | Max 10 per 30 days | Promotion blocked until window passes |
| Reputation velocity | >0.005/day | Flagged for review, activity audit |
| Voucher requirement | 2 established nodes | Promotion blocked until vouchers obtained |

### Activity Validation Protocol (CANONICAL)

Activity claims for reputation gains must be independently verified to prevent fabrication. The protocol uses multiple monitors, cross-shard validation, and TPM-attested evidence submission.

**Multi-Monitor Verification:**

```go
// ActivityValidationConfig defines verification requirements
type ActivityValidationConfig struct {
    MinIndependentMonitors   int           // Minimum monitors to verify (default: 3)
    MonitorAgreementThreshold float64      // Percentage agreement required (default: 0.67)
    ValidationWindow         time.Duration // Window for activity verification (default: 1 hour)
    CrossShardValidation     bool          // Enable cross-shard checks (default: true)
}

var DefaultActivityValidationConfig = ActivityValidationConfig{
    MinIndependentMonitors:   3,
    MonitorAgreementThreshold: 0.67,
    ValidationWindow:         1 * time.Hour,
    CrossShardValidation:     true,
}

// ActivityClaim represents a node's claim for reputation-earning activity
type ActivityClaim struct {
    ClaimID         [32]byte
    NodeID          [32]byte
    ActivityType    ActivityType
    ClaimedAmount   float64        // Reputation amount claimed
    Evidence        []byte         // Activity evidence
    TPMAttestation  []byte         // TPM quote over evidence
    Timestamp       time.Time
    ShardID         uint32         // Shard where activity occurred
}

// ActivityMonitor tracks and verifies activity claims
type ActivityMonitor struct {
    nodeID          [32]byte
    observedActivity map[[32]byte][]ObservedActivity
    mu              sync.RWMutex
}

// ObservedActivity represents a monitor's observation of node activity
type ObservedActivity struct {
    MonitorID       [32]byte
    TargetNodeID    [32]byte
    ActivityType    ActivityType
    ObservedAt      time.Time
    Evidence        []byte         // Monitor's independent evidence
    TPMQuote        []byte         // Monitor's TPM attestation
    Verified        bool
}

// ValidateActivityClaim verifies a claim against multiple monitors
func ValidateActivityClaim(
    claim *ActivityClaim,
    monitors []*ActivityMonitor,
    config ActivityValidationConfig,
) (*ActivityValidationResult, error) {
    if len(monitors) < config.MinIndependentMonitors {
        return nil, &ErrInsufficientMonitors{
            Required: config.MinIndependentMonitors,
            Available: len(monitors),
        }
    }

    // Collect observations from monitors
    var confirmations, rejections int
    var monitorReports []MonitorReport

    for _, monitor := range monitors {
        observation, found := monitor.GetObservation(claim.NodeID, claim.Timestamp, config.ValidationWindow)
        if !found {
            rejections++
            monitorReports = append(monitorReports, MonitorReport{
                MonitorID: monitor.nodeID,
                Confirmed: false,
                Reason:    "No observation recorded",
            })
            continue
        }

        // Verify monitor's TPM attestation
        if err := VerifyTPMQuote(observation.TPMQuote, monitor.nodeID); err != nil {
            rejections++
            monitorReports = append(monitorReports, MonitorReport{
                MonitorID: monitor.nodeID,
                Confirmed: false,
                Reason:    "Invalid TPM attestation",
            })
            continue
        }

        // Compare observation with claim
        if observation.ActivityType == claim.ActivityType && observation.Verified {
            confirmations++
            monitorReports = append(monitorReports, MonitorReport{
                MonitorID: monitor.nodeID,
                Confirmed: true,
            })
        } else {
            rejections++
            monitorReports = append(monitorReports, MonitorReport{
                MonitorID: monitor.nodeID,
                Confirmed: false,
                Reason:    "Activity mismatch",
            })
        }
    }

    // Calculate agreement ratio
    total := confirmations + rejections
    agreementRatio := float64(confirmations) / float64(total)

    result := &ActivityValidationResult{
        ClaimID:        claim.ClaimID,
        Validated:      agreementRatio >= config.MonitorAgreementThreshold,
        Confirmations:  confirmations,
        Rejections:     rejections,
        AgreementRatio: agreementRatio,
        MonitorReports: monitorReports,
    }

    return result, nil
}
```

**Cross-Shard Reputation Sync Validation:**

```go
// CrossShardValidator ensures reputation consistency across shards
type CrossShardValidator struct {
    localShardID uint32
    peerShards   map[uint32]*ShardConnection
    mu           sync.RWMutex
}

// CrossShardReputationSync synchronizes and validates reputation across shards
type CrossShardReputationSync struct {
    NodeID          [32]byte
    LocalReputation float64
    ShardReputations map[uint32]float64  // ShardID -> Reputation
    LastSyncTime    time.Time
    Discrepancies   []ReputationDiscrepancy
}

// ValidateCrossShardReputation checks reputation consistency
func (csv *CrossShardValidator) ValidateCrossShardReputation(
    nodeID [32]byte,
) (*CrossShardReputationSync, error) {
    csv.mu.RLock()
    defer csv.mu.RUnlock()

    sync := &CrossShardReputationSync{
        NodeID:           nodeID,
        ShardReputations: make(map[uint32]float64),
        LastSyncTime:     time.Now(),
    }

    // Get local reputation
    sync.LocalReputation = getLocalReputation(nodeID)
    sync.ShardReputations[csv.localShardID] = sync.LocalReputation

    // Query peer shards
    for shardID, conn := range csv.peerShards {
        rep, err := conn.GetNodeReputation(nodeID)
        if err != nil {
            continue // Shard may not have this node
        }
        sync.ShardReputations[shardID] = rep
    }

    // Detect discrepancies (>0.05 difference)
    const maxDiscrepancy = 0.05
    for shardID, rep := range sync.ShardReputations {
        if shardID == csv.localShardID {
            continue
        }

        diff := math.Abs(rep - sync.LocalReputation)
        if diff > maxDiscrepancy {
            sync.Discrepancies = append(sync.Discrepancies, ReputationDiscrepancy{
                ShardID:         shardID,
                LocalReputation: sync.LocalReputation,
                RemoteReputation: rep,
                Difference:      diff,
            })
        }
    }

    return sync, nil
}
```

**TPM-Attested Evidence Submission:**

All activity claims must include TPM attestation to prove the claim originates from a legitimate device and has not been tampered with.

| Requirement | Implementation |
|-------------|----------------|
| Evidence binding | SHA-256 hash of evidence included in TPM quote |
| Freshness | TPM quote timestamp within 30 seconds of claim |
| Device authenticity | AIK certificate chain validation |
| Tamper detection | PCR values indicate unmodified firmware |

## Confirmation Collusion Ring Prevention (E2)

High-reputation nodes may attempt to form collusion rings where they exclusively confirm each other's transactions to inflate reputation scores. This section defines countermeasures.

### Same-Confirmer Frequency Limits (CANONICAL)

To prevent confirmation collusion rings, the protocol enforces strict limits on how often the same node pair can participate in confirmations:

```go
// ConfirmationLimits defines anti-collusion parameters
type ConfirmationLimits struct {
    // Maximum confirmations from same confirmer per 24h window
    MaxSameConfirmerDaily     int           // Default: 3
    // Minimum unique confirmers required per rolling week
    MinUniqueConfirmersWeekly int           // Default: 10
    // Cooling period after max same-confirmer reached
    SameConfirmerCooldown     time.Duration // Default: 48 hours
    // Maximum percentage of confirmations from any single source
    MaxSingleSourcePercent    float64       // Default: 0.10 (10%)
}

// DefaultConfirmationLimits returns production values
func DefaultConfirmationLimits() ConfirmationLimits {
    return ConfirmationLimits{
        MaxSameConfirmerDaily:     3,
        MinUniqueConfirmersWeekly: 10,
        SameConfirmerCooldown:     48 * time.Hour,
        MaxSingleSourcePercent:    0.10,
    }
}
```

**Enforcement Rules:**

| Rule | Threshold | Consequence |
|------|-----------|-------------|
| Daily same-confirmer limit | 3 per 24h | Confirmation rejected, no reputation gain |
| Weekly diversity requirement | 10 unique confirmers | Node flagged for review, reduced earning rate |
| Single source percentage | Max 10% of total | Excess confirmations invalidated retroactively |
| Cooling period violation | Before 48h elapsed | Confirmer reputation penalty (-0.02) |

### VRF-Based Confirmer Assignment (CANONICAL)

Rather than allowing nodes to choose their confirmers, the protocol uses Verifiable Random Functions (VRF) to deterministically assign confirmers:

```go
// ConfirmerAssignment uses VRF for unpredictable but verifiable selection
type ConfirmerAssignment struct {
    TransactionID   [32]byte          // Transaction being confirmed
    BlockHash       [32]byte          // Reference block for randomness
    VRFProof        []byte            // Proof of correct selection
    AssignedNodes   [][32]byte        // Selected confirmer node IDs
    SelectionSeed   [32]byte          // Derived seed for selection
}

// SelectConfirmers deterministically selects confirmers using VRF
func SelectConfirmers(
    txID [32]byte,
    blockHash [32]byte,
    eligibleNodes []NodeID,
    requiredCount int,
    vrfPrivateKey []byte,
) (*ConfirmerAssignment, error) {
    // Generate VRF output and proof
    seed := computeVRFSeed(txID, blockHash)
    vrfOutput, vrfProof, err := vrf.Prove(vrfPrivateKey, seed)
    if err != nil {
        return nil, err
    }

    // Filter eligible nodes (exclude transaction parties, recently used)
    filtered := filterEligibleConfirmers(eligibleNodes, txID)

    // Deterministically select from filtered pool using VRF output
    selected := selectFromPool(filtered, vrfOutput, requiredCount)

    return &ConfirmerAssignment{
        TransactionID: txID,
        BlockHash:     blockHash,
        VRFProof:      vrfProof,
        AssignedNodes: selected,
        SelectionSeed: seed,
    }, nil
}

// filterEligibleConfirmers removes ineligible nodes
func filterEligibleConfirmers(nodes []NodeID, txID [32]byte) []NodeID {
    var eligible []NodeID
    for _, node := range nodes {
        // Exclude transaction sender/receiver
        if isTransactionParty(node, txID) {
            continue
        }
        // Exclude nodes that confirmed this sender recently (past 48h)
        if hasRecentConfirmation(node, getTxSender(txID), 48*time.Hour) {
            continue
        }
        // Exclude nodes with insufficient reputation
        if getNodeReputation(node) < 0.50 {
            continue
        }
        eligible = append(eligible, node)
    }
    return eligible
}
```

**VRF Selection Properties:**

| Property | Guarantee |
|----------|-----------|
| Unpredictability | Cannot predict confirmers before block is finalized |
| Verifiability | Anyone can verify selection was correct |
| Manipulation resistance | Cannot game selection without controlling VRF key |
| Diversity enforcement | Algorithm ensures geographic/network diversity |

### Collusion Ring Detection (CANONICAL)

The system actively monitors for collusion patterns using graph analysis with defined thresholds.

**Detection Thresholds:**

| Indicator | Threshold | Description |
|-----------|-----------|-------------|
| Reciprocity | 0.80 (80%) | Percentage of mutual confirmations (A confirms B AND B confirms A) |
| Exclusivity | 0.70 (70%) | Percentage of confirmations within suspected ring vs. external |
| Temporal clustering | 0.60 (60%) | Percentage of confirmations occurring in burst patterns |

```go
// CollusionDetector identifies suspicious confirmation patterns
type CollusionDetector struct {
    ConfirmationGraph map[NodeID]map[NodeID]uint64 // Confirmation counts
    WindowStart       time.Time
    WindowDuration    time.Duration
}

// CollusionDetectionConfig defines detection thresholds
type CollusionDetectionConfig struct {
    ReciprocityThreshold float64 // Default: 0.80 (80% mutual confirmation)
    ExclusivityThreshold float64 // Default: 0.70 (70% internal confirmations)
    TemporalClusterThreshold float64 // Default: 0.60 (60% burst pattern)
    MinRingSize          int     // Default: 3 nodes minimum for ring
    DetectionWindow      time.Duration // Default: 30 days
}

var DefaultCollusionConfig = CollusionDetectionConfig{
    ReciprocityThreshold:     0.80,
    ExclusivityThreshold:     0.70,
    TemporalClusterThreshold: 0.60,
    MinRingSize:              3,
    DetectionWindow:          30 * 24 * time.Hour,
}

// DetectCollusionRing identifies nodes with suspicious mutual confirmation patterns
func (cd *CollusionDetector) DetectCollusionRing(minRingSize int) [][]NodeID {
    var rings [][]NodeID

    // Find strongly connected components in confirmation graph
    components := findStronglyConnectedComponents(cd.ConfirmationGraph)

    for _, component := range components {
        if len(component) < minRingSize {
            continue
        }

        // Check if component exhibits collusion characteristics
        if cd.isCollusionRing(component) {
            rings = append(rings, component)
        }
    }

    return rings
}

// isCollusionRing checks for collusion indicators against thresholds
func (cd *CollusionDetector) isCollusionRing(nodes []NodeID) bool {
    config := DefaultCollusionConfig

    // Indicator 1: High reciprocity (A confirms B, B confirms A)
    reciprocityScore := cd.calculateReciprocity(nodes)
    if reciprocityScore > config.ReciprocityThreshold {
        return true
    }

    // Indicator 2: Exclusivity (ring members rarely confirm outsiders)
    exclusivityScore := cd.calculateExclusivity(nodes)
    if exclusivityScore > config.ExclusivityThreshold {
        return true
    }

    // Indicator 3: Temporal clustering (confirmations happen in bursts)
    temporalScore := cd.calculateTemporalClustering(nodes)
    if temporalScore > config.TemporalClusterThreshold {
        return true
    }

    return false
}

// calculateReciprocity measures mutual confirmation percentage
func (cd *CollusionDetector) calculateReciprocity(nodes []NodeID) float64 {
    nodeSet := make(map[NodeID]bool)
    for _, n := range nodes {
        nodeSet[n] = true
    }

    var totalPairs, reciprocalPairs int

    for _, nodeA := range nodes {
        for _, nodeB := range nodes {
            if nodeA == nodeB {
                continue
            }
            totalPairs++

            // Check if A confirmed B AND B confirmed A
            aToB := cd.ConfirmationGraph[nodeA][nodeB] > 0
            bToA := cd.ConfirmationGraph[nodeB][nodeA] > 0

            if aToB && bToA {
                reciprocalPairs++
            }
        }
    }

    if totalPairs == 0 {
        return 0
    }

    return float64(reciprocalPairs) / float64(totalPairs)
}

// calculateExclusivity measures internal vs external confirmation ratio
func (cd *CollusionDetector) calculateExclusivity(nodes []NodeID) float64 {
    nodeSet := make(map[NodeID]bool)
    for _, n := range nodes {
        nodeSet[n] = true
    }

    var internalConfirmations, externalConfirmations uint64

    for _, node := range nodes {
        for target, count := range cd.ConfirmationGraph[node] {
            if nodeSet[target] {
                internalConfirmations += count
            } else {
                externalConfirmations += count
            }
        }
    }

    total := internalConfirmations + externalConfirmations
    if total == 0 {
        return 0
    }

    return float64(internalConfirmations) / float64(total)
}
```

**Collusion Ring Penalties:**

| Detection | Penalty | Duration |
|-----------|---------|----------|
| First detection (warning) | Reputation frozen | 7 days |
| Confirmed collusion ring | -0.30 reputation to all members | Immediate |
| Repeat offense | Permanent ban | Indefinite |

### Sleeper Attack Detection

Sleeper attacks involve deploying nodes, building reputation over time, then coordinating malicious activity after a period of dormancy.

**Detection Signals:**

| Signal | Threshold | Description |
|--------|-----------|-------------|
| Inactivity Period | 90 days | Account classified as "dormant" after 90 days inactivity |
| Reactivation Window | 7 days | Monitoring window after dormant account reactivates |
| Coordination Threshold | 5 nodes | Alert if 5+ dormant accounts reactivate within window |
| Re-verification Required | 180 days | Accounts dormant >180 days require re-verification |

**Dormant Account Handling:**

| Aspect | Policy | Rationale |
|--------|--------|-----------|
| Reputation Decay | 0.002/day additional | Dormant accounts decay faster to reduce attack value |
| Role Demotion | After 90 days | High-privilege roles (Hub, Gateway, Coordinator) demoted |
| CA Pool Removal | Immediate | CA participants removed on dormancy classification |
| Re-verification | Full process | Must complete original verification again |

**Cross-Domain Collusion Detection:**

The system monitors for collusion across critical roles:

| Domain Combination | Detection Signal | Action |
|-------------------|------------------|--------|
| CA + Judge | Same organization controlling both | Enhanced monitoring, flag for review |
| CA + Witness | Witness consistently supports CA member | Witness excluded from future attestations |
| Judge + Coordinator | Coordinated voting patterns detected | Both flagged, decisions reviewed |
| All domains | Same entity in 3+ critical roles | Emergency review, potential suspension |

For all constants, see `00-CONSTANTS.md` Section 21 (Collusion Economics).

### Judge Selection Cooldown (CANONICAL)

To prevent concentration of judgment power and reduce collusion risk, judges have mandatory cooldown periods between selections.

```go
// JudgeSelectionCooldown manages judge selection frequency
type JudgeSelectionCooldown struct {
    selectionHistory map[[32]byte][]JudgeSelectionRecord
    mu               sync.RWMutex
}

// JudgeCooldownConfig defines cooldown parameters
type JudgeCooldownConfig struct {
    MinCooldownPeriod    time.Duration // Minimum time between judge selections (default: 24h)
    MaxSelectionsPerWeek int           // Maximum selections per rolling week (default: 5)
    MaxSelectionsPerMonth int          // Maximum selections per rolling month (default: 15)
    CooldownMultiplier   float64       // Increase cooldown after consecutive selections (default: 1.5)
}

var DefaultJudgeCooldownConfig = JudgeCooldownConfig{
    MinCooldownPeriod:    24 * time.Hour,
    MaxSelectionsPerWeek: 5,
    MaxSelectionsPerMonth: 15,
    CooldownMultiplier:   1.5,
}

// JudgeSelectionRecord tracks when a judge was selected
type JudgeSelectionRecord struct {
    DisputeID    [32]byte
    SelectedAt   time.Time
    VoteCast     bool
    VoteTimestamp time.Time
}

// IsEligibleForSelection checks if judge can be selected for new dispute
func (jsc *JudgeSelectionCooldown) IsEligibleForSelection(
    judgeID [32]byte,
    config JudgeCooldownConfig,
) (bool, time.Time, error) {
    jsc.mu.RLock()
    history := jsc.selectionHistory[judgeID]
    jsc.mu.RUnlock()

    now := time.Now()

    // Check minimum cooldown from last selection
    if len(history) > 0 {
        lastSelection := history[len(history)-1]
        cooldownEnd := lastSelection.SelectedAt.Add(config.MinCooldownPeriod)

        // Apply multiplier for consecutive selections
        consecutiveCount := jsc.getConsecutiveSelections(judgeID)
        if consecutiveCount > 1 {
            multiplier := math.Pow(config.CooldownMultiplier, float64(consecutiveCount-1))
            extendedCooldown := time.Duration(float64(config.MinCooldownPeriod) * multiplier)
            cooldownEnd = lastSelection.SelectedAt.Add(extendedCooldown)
        }

        if now.Before(cooldownEnd) {
            return false, cooldownEnd, nil
        }
    }

    // Check weekly limit
    weekAgo := now.Add(-7 * 24 * time.Hour)
    weeklyCount := 0
    for _, record := range history {
        if record.SelectedAt.After(weekAgo) {
            weeklyCount++
        }
    }
    if weeklyCount >= config.MaxSelectionsPerWeek {
        return false, weekAgo.Add(7 * 24 * time.Hour), &ErrWeeklyLimitExceeded{
            JudgeID: judgeID,
            Count:   weeklyCount,
            Limit:   config.MaxSelectionsPerWeek,
        }
    }

    // Check monthly limit
    monthAgo := now.Add(-30 * 24 * time.Hour)
    monthlyCount := 0
    for _, record := range history {
        if record.SelectedAt.After(monthAgo) {
            monthlyCount++
        }
    }
    if monthlyCount >= config.MaxSelectionsPerMonth {
        return false, monthAgo.Add(30 * 24 * time.Hour), &ErrMonthlyLimitExceeded{
            JudgeID: judgeID,
            Count:   monthlyCount,
            Limit:   config.MaxSelectionsPerMonth,
        }
    }

    return true, time.Time{}, nil
}

// RecordJudgeSelection logs a judge selection
func (jsc *JudgeSelectionCooldown) RecordJudgeSelection(
    judgeID [32]byte,
    disputeID [32]byte,
) {
    jsc.mu.Lock()
    defer jsc.mu.Unlock()

    record := JudgeSelectionRecord{
        DisputeID:  disputeID,
        SelectedAt: time.Now(),
    }

    jsc.selectionHistory[judgeID] = append(jsc.selectionHistory[judgeID], record)
}
```

**Judge Selection Cooldown Summary:**

| Constraint | Threshold | Purpose |
|------------|-----------|---------|
| Minimum cooldown | 24 hours | Prevents rapid consecutive selection |
| Weekly limit | 5 selections | Ensures judge diversity across disputes |
| Monthly limit | 15 selections | Prevents judgment concentration |
| Consecutive multiplier | 1.5x | Increasing cooldown for frequent judges |

**Judge Selection History Tracking:**

The system maintains a rolling history of judge selections to detect patterns that might indicate manipulation.

```go
// JudgeSelectionHistoryAnalyzer tracks and analyzes selection patterns
type JudgeSelectionHistoryAnalyzer struct {
    selectionPairs   map[[64]byte][]time.Time // Tracks (JudgeA, JudgeB) co-selection frequency
    disputeJudges    map[[32]byte][][32]byte  // DisputeID -> list of judges
    mu               sync.RWMutex
}

// DetectJudgeConcentration identifies if same judges are selected too often together
func (jsha *JudgeSelectionHistoryAnalyzer) DetectJudgeConcentration(
    windowDays int,
    maxCoOccurrences int,
) []JudgeConcentrationAlert {
    jsha.mu.RLock()
    defer jsha.mu.RUnlock()

    var alerts []JudgeConcentrationAlert
    cutoff := time.Now().Add(-time.Duration(windowDays) * 24 * time.Hour)

    for pairKey, occurrences := range jsha.selectionPairs {
        recentOccurrences := 0
        for _, t := range occurrences {
            if t.After(cutoff) {
                recentOccurrences++
            }
        }

        if recentOccurrences > maxCoOccurrences {
            judgeA := [32]byte{}
            judgeB := [32]byte{}
            copy(judgeA[:], pairKey[:32])
            copy(judgeB[:], pairKey[32:])

            alerts = append(alerts, JudgeConcentrationAlert{
                JudgeA:       judgeA,
                JudgeB:       judgeB,
                CoOccurrences: recentOccurrences,
                WindowDays:   windowDays,
                Severity:     calculateConcentrationSeverity(recentOccurrences, maxCoOccurrences),
            })
        }
    }

    return alerts
}
```

## Reputation Grinding Prevention (E9)

Reputation grinding attacks involve creating alternate accounts that verify each other to artificially inflate reputation scores. This section defines hardware-based countermeasures.

### Unique Device Attestation Requirement (CANONICAL)

Each verification action MUST include TPM-backed device attestation that proves:

1. The device has not previously registered another identity
2. The attestation is fresh (not replayed)
3. The device firmware is unmodified

```go
// DeviceAttestation binds identity to unique hardware
type DeviceAttestation struct {
    TPMEndorsementKey   []byte            // Unique per TPM, certified by manufacturer
    AttestationKey      []byte            // AIK derived from EK
    PlatformCertificate []byte            // Manufacturer certificate chain
    PCRValues           map[int][]byte    // Platform Configuration Registers
    AttestationQuote    []byte            // Signed quote over PCRs
    Nonce               [32]byte          // Fresh nonce for anti-replay
    Timestamp           int64             // Quote creation time
    EKCertChain         [][]byte          // Full endorsement key certificate chain
}

// VerifyDeviceAttestation validates device uniqueness
func VerifyDeviceAttestation(attestation *DeviceAttestation) error {
    // Step 1: Verify EK certificate chain to known TPM manufacturers
    if err := verifyEKCertificateChain(attestation.EKCertChain); err != nil {
        return &ErrInvalidEKChain{Cause: err}
    }

    // Step 2: Verify attestation quote signature
    if err := verifyQuoteSignature(attestation); err != nil {
        return &ErrInvalidQuote{Cause: err}
    }

    // Step 3: Check nonce freshness (must be from last 30 seconds)
    // SECURITY: 5-minute window was too long - allowed quote replay attacks
    // 30-second window aligns with NonceExpirationWindow in security-trust.md
    const AttestationFreshnessWindow = 30 // seconds
    if time.Now().Unix() - attestation.Timestamp > AttestationFreshnessWindow {
        return ErrStaleAttestation
    }

    // Step 4: Verify PCR values match expected secure boot state
    if err := verifyPCRValues(attestation.PCRValues); err != nil {
        return &ErrInvalidPCR{Cause: err}
    }

    return nil
}
```

### TPM Binding for Identity Uniqueness (CANONICAL)

The system enforces one primary identity per TPM:

```go
// TPMIdentityRegistry tracks TPM-to-identity bindings
type TPMIdentityRegistry struct {
    // Maps EK hash to registered identity
    Bindings map[[32]byte]IdentityBinding
    mu       sync.RWMutex
}

// IdentityBinding represents TPM-to-node mapping
type IdentityBinding struct {
    EKHash          [32]byte          // SHA-256 of Endorsement Key
    NodeID          [32]byte          // Bound node identity
    RegistrationTime int64            // When binding was created
    LastAttested    int64             // Most recent attestation
    BindingProof    []byte            // Cryptographic proof of binding
}

// RegisterIdentity binds a node identity to a TPM
func (r *TPMIdentityRegistry) RegisterIdentity(
    attestation *DeviceAttestation,
    nodeID [32]byte,
) error {
    r.mu.Lock()
    defer r.mu.Unlock()

    // Compute EK hash for lookup
    ekHash := sha256.Sum256(attestation.TPMEndorsementKey)

    // Check if TPM already has a registered identity
    if existing, exists := r.Bindings[ekHash]; exists {
        // Same TPM cannot register multiple identities
        if existing.NodeID != nodeID {
            return &ErrTPMAlreadyBound{
                ExistingNodeID: existing.NodeID,
                BoundAt:        existing.RegistrationTime,
            }
        }
        // Update last attestation time for existing binding
        existing.LastAttested = time.Now().Unix()
        r.Bindings[ekHash] = existing
        return nil
    }

    // Create new binding
    r.Bindings[ekHash] = IdentityBinding{
        EKHash:           ekHash,
        NodeID:           nodeID,
        RegistrationTime: time.Now().Unix(),
        LastAttested:     time.Now().Unix(),
        BindingProof:     createBindingProof(attestation, nodeID),
    }

    return nil
}

// ValidateUniqueDevice checks verification includes unique device proof
func ValidateUniqueDevice(
    verifierAttestation *DeviceAttestation,
    targetNodeID [32]byte,
    registry *TPMIdentityRegistry,
) error {
    // Verify attestation is valid
    if err := VerifyDeviceAttestation(verifierAttestation); err != nil {
        return err
    }

    // Verify device is registered to a legitimate identity
    ekHash := sha256.Sum256(verifierAttestation.TPMEndorsementKey)
    binding, exists := registry.Bindings[ekHash]
    if !exists {
        return ErrUnregisteredDevice
    }

    // Verify the verifier is not the same as target (self-verification)
    if binding.NodeID == targetNodeID {
        return ErrSelfVerification
    }

    return nil
}
```

### Anti-Grinding Enforcement Rules

| Rule | Requirement | Penalty for Violation |
|------|-------------|----------------------|
| TPM binding | One identity per TPM | Second identity rejected |
| Fresh attestation | Attestation < 30 seconds old | Verification rejected |
| Self-verification | Cannot verify own node | -0.10 reputation |
| Attestation tampering | Valid PCR values | Immediate ban |
| EK spoofing | Valid manufacturer chain | Immediate ban + legal referral |

### Verification Diversity Requirements

To prevent coordinated grinding even with legitimate devices:

```go
// VerificationDiversityConfig ensures verifiers come from diverse sources
type VerificationDiversityConfig struct {
    // Minimum unique verifiers required for reputation milestone
    MinUniqueVerifiers      map[float64]int
    // Maximum verifications from same geographic region
    MaxSameRegionPercent    float64
    // Minimum time between verifications from same verifier
    MinVerifierCooldown     time.Duration
    // Maximum verifications any single node can provide per day
    MaxDailyVerifications   int
}

// DefaultVerificationDiversity returns production values
func DefaultVerificationDiversity() VerificationDiversityConfig {
    return VerificationDiversityConfig{
        MinUniqueVerifiers: map[float64]int{
            0.50: 10,   // 10 unique verifiers to reach 0.50 reputation
            0.80: 50,   // 50 unique verifiers to reach 0.80 (Hub eligible)
            0.90: 75,   // 75 unique verifiers to reach 0.90 (CA eligible, plus diversity requirements)
            0.95: 100,  // 100 unique verifiers to reach 0.95 (Coordinator)
        },
        MaxSameRegionPercent:  0.30,           // Max 30% from same region
        MinVerifierCooldown:   7 * 24 * time.Hour, // 7 days between verifications
        MaxDailyVerifications: 5,              // Max 5 verifications issued per day
    }
}
```

## Untrusted Node DDoS Work Integration

Untrusted nodes cannot earn reputation but MUST contribute to network security through DDoS protection work.

### Work-For-Access Model

| Work Type | Description | Compensation |
|-----------|-------------|--------------|
| **PoW Verification** | Verify proof-of-work solutions from incoming requests | Network access |
| **Traffic Scrubbing** | Act as first-hop proxy to filter malicious traffic | Bandwidth allocation |
| **Challenge Generation** | Generate and distribute PoW challenges | Reduced rate limits |
| **IP Scoring** | Report suspicious IP behavior patterns | Priority queue access |
| **Blocklist Propagation** | Store and serve threat intelligence data | Storage credits |

### Work Requirements by Scrutiny Level

| Scrutiny Level | Work Hours/Day | Rate Multiplier |
|----------------|----------------|-----------------|
| Elevated (untrusted) | 4 hours | 50% |
| Maximum (flagged) | 8 hours | 10% |

### Work Assignment Flow

```go
// WorkAssignment for untrusted nodes
type WorkAssignment struct {
    NodeID         [32]byte
    WorkType       WorkType
    AssignedAt     time.Time
    Duration       time.Duration
    WorkUnits      uint64
    CompletedUnits uint64
}

func AssignWork(node *Node) (*WorkAssignment, error) {
    if node.TrustLevel == TrustLevelTrusted {
        return nil, nil  // Trusted nodes don't need work assignments
    }

    scrutiny := GetScrutinyLevel(node)
    workHours := ScrutinyConstraints[scrutiny].WorkContribution

    return &WorkAssignment{
        NodeID:    node.ID,
        WorkType:  SelectWorkType(node),
        Duration:  time.Duration(workHours) * time.Hour,
    }, nil
}
```

### Work Refusal Penalties

Untrusted nodes that refuse work assignments face escalating penalties:

| Offense | Penalty |
|---------|---------|
| First | Scrutiny escalation to Maximum |
| Second | 24-hour temporary ban |
| Third | Permanent ban |

### Relationship to Reputation

**IMPORTANT**: Completing DDoS work does NOT earn reputation for untrusted nodes.

- Untrusted nodes: Reputation permanently capped at 0.0
- Work completion grants network access and service usage rights
- Work is a prerequisite for using network resources, not a path to trust

See [17-untrusted-nodes.md](17-untrusted-nodes.md) for complete untrusted node work assignment details.
See [16-ddos-protection.md](16-ddos-protection.md) for network-wide DDoS protection architecture.

---

# Part 2: Collaborative Defense System

## Behavior Monitoring

The system tracks four key behavioral metrics to detect anomalous or malicious behavior.

### Monitored Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Response Time | <1000ms | Request latency |
| Success Rate | >95% | Request completion rate |
| Data Integrity | >98% | Hash verification rate |
| Protocol Compliance | >90% | Protocol adherence rate |

### Monitor Configuration

```go
type MonitorConfig struct {
    MetricsWindow   time.Duration       // Aggregation window (default: 5min)
    SampleInterval  time.Duration       // Sample frequency (default: 10sec)
    AlertThresholds map[string]float64  // Threshold values
}

config := defense.DefaultMonitorConfig()
// AlertThresholds:
// - success_rate: 0.95 (95%)
// - data_integrity: 0.98 (98%)
// - protocol_compliance: 0.90 (90%)
// - response_time_ms: 1000 (1 second)

monitor := defense.NewMonitor(config)
```

### Recording Observations

```go
// Record request response
monitor.RecordResponse(nodeID, duration, success)

// Record data integrity check
monitor.RecordDataIntegrity(nodeID, hashValid)

// Record protocol compliance
monitor.RecordProtocolCompliance(nodeID, compliant)
```

### Retrieving Metrics

```go
type BehaviorMetrics struct {
    NodeID             string
    ResponseTime       time.Duration  // Average response time
    SuccessRate        float64        // Success percentage (0.0-1.0)
    DataIntegrity      float64        // Integrity percentage
    ProtocolCompliance float64        // Compliance percentage
    LastUpdated        time.Time
}

metrics, err := monitor.GetMetrics(nodeID)
```

### Anomaly Detection

```go
isAnomalous, description := monitor.CheckAnomaly(nodeID)

if isAnomalous {
    fmt.Printf("Anomaly detected: %s\n", description)
    // Triggers alert and potential accusation
}

alerts := monitor.GetAlerts(time.Now().Add(-1 * time.Hour))
for _, alert := range alerts {
    fmt.Printf("[%s] %s: %s - %s\n",
        alert.Severity,
        alert.NodeID,
        alert.Type,
        alert.Description)
}
```

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/monitor.go`

## TPM-Attested Evidence

All evidence submitted to the judgment system must include TPM attestation to prove authenticity and prevent fabrication.

### Evidence Packet Structure

```go
type EvidencePacket struct {
    PacketID          [32]byte          // Unique packet identifier
    ReporterID        string            // Node reporting violation
    AccusedNodeID     string            // Accused node
    Timestamp         int64             // Report timestamp
    ViolationType     ViolationType     // Type of violation
    Severity          ViolationSeverity // Severity level
    Description       string            // Human-readable description
    Evidence          []byte            // Supporting evidence data
    EvidenceType      string            // Evidence format
    TPMQuote          []byte            // TPM attestation quote
    TPMTimestamp      int64             // Quote timestamp
    ReporterSignature []byte            // Reporter's signature
    Corroborations    []Corroboration   // Supporting witnesses
}
```

### Violation Types

```go
const (
    ViolationSlowResponse      = "slow_response"
    ViolationStaleData         = "stale_data"
    ViolationIncorrectRoute    = "incorrect_routing"
    ViolationDataManipulation  = "data_manipulation"
    ViolationDoubleSpend       = "double_spend"
    ViolationConsensusAttack   = "consensus_attack"
    ViolationNetworkAttack     = "network_attack"
    ViolationProtocolViolation = "protocol_violation"
    ViolationSybilAttack       = "sybil_attack"
    ViolationEclipseAttack     = "eclipse_attack"
    ViolationMalformedData     = "malformed_data"
    ViolationInvalidSignature  = "invalid_signature"
)
```

### Severity Levels

| Severity | Consequence |
|----------|-------------|
| Minor | Warning, reputation penalty |
| Moderate | Reputation penalty |
| Major | Slash or temporary ban |
| Severe | Permanent ban |
| Critical | Immediate permanent ban |

### Creating Evidence (Atomic Collection)

**CRITICAL SECURITY**: Evidence collection MUST be atomic to prevent tampering between collection and submission. An attacker could modify evidence data after TPM quote but before signature, creating plausible deniability or false accusations.

```go
// AtomicEvidenceCollector ensures evidence integrity from collection to submission
type AtomicEvidenceCollector struct {
    tpm        *TPM
    privateKey crypto.PrivateKey
    mu         sync.Mutex  // Prevent concurrent evidence modification
}

// CollectEvidence atomically gathers and signs evidence
// All operations happen under lock to prevent TOCTOU attacks
func (c *AtomicEvidenceCollector) CollectEvidence(
    ctx context.Context,
    accusedNodeID string,
    violationType ViolationType,
    severity ViolationSeverity,
    description string,
    rawEvidence []byte,
    evidenceType string,
) (*EvidencePacket, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    timestamp := time.Now().Unix()

    // Step 1: Compute evidence hash BEFORE any other operations
    evidenceHash := sha256.Sum256(rawEvidence)

    // Step 2: Create TPM quote that includes the evidence hash
    // This binds the TPM attestation to the specific evidence data
    nonce := generateNonce()
    externalData := append(nonce, evidenceHash[:]...)  // Nonce || EvidenceHash
    tpmQuote, err := c.tpm.CreateAttestationQuoteWithExternalData(externalData)
    if err != nil {
        return nil, fmt.Errorf("TPM quote failed: %w", err)
    }

    // Step 3: Build evidence packet
    packet := &EvidencePacket{
        PacketID:      sha256.Sum256(append([]byte(c.tpm.NodeID), nonce...)),
        ReporterID:    c.tpm.NodeID,
        AccusedNodeID: accusedNodeID,
        Timestamp:     timestamp,
        ViolationType: violationType,
        Severity:      severity,
        Description:   description,
        Evidence:      rawEvidence,
        EvidenceHash:  evidenceHash,  // NEW: Include hash for verification
        EvidenceType:  evidenceType,
        TPMQuote:      tpmQuote,
        TPMTimestamp:  timestamp,
        Nonce:         nonce,
    }

    // Step 4: Sign the entire packet (including TPM quote)
    // This creates a chain: Evidence -> Hash -> TPM Quote -> Signature
    packetBytes, err := packet.MarshalForSigning()
    if err != nil {
        return nil, fmt.Errorf("marshal failed: %w", err)
    }
    signature, err := ecdsa.SignASN1(rand.Reader, c.privateKey.(*ecdsa.PrivateKey),
        sha256.Sum256(packetBytes)[:])
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }
    packet.ReporterSignature = signature

    return packet, nil
}

// VerifyEvidenceIntegrity verifies the atomic collection chain
func VerifyEvidenceIntegrity(packet *EvidencePacket, reporterCert *x509.Certificate) error {
    // Step 1: Verify evidence hash matches data
    computedHash := sha256.Sum256(packet.Evidence)
    if !bytes.Equal(computedHash[:], packet.EvidenceHash[:]) {
        return ErrEvidenceTampered
    }

    // Step 2: Verify TPM quote includes evidence hash
    expectedExternalData := append(packet.Nonce, packet.EvidenceHash[:]...)
    if !bytes.Equal(packet.TPMQuote.ExternalData, expectedExternalData) {
        return ErrEvidenceNotBoundToQuote
    }

    // Step 3: Verify TPM quote signature
    if err := VerifyTPMQuote(packet.TPMQuote, packet.ReporterID); err != nil {
        return fmt.Errorf("TPM quote verification failed: %w", err)
    }

    // Step 4: Verify reporter signature over entire packet
    packetBytes, _ := packet.MarshalForSigning()
    if !ecdsa.VerifyASN1(reporterCert.PublicKey.(*ecdsa.PublicKey),
        sha256.Sum256(packetBytes)[:], packet.ReporterSignature) {
        return ErrInvalidReporterSignature
    }

    return nil
}

var (
    ErrEvidenceTampered        = errors.New("evidence data does not match hash")
    ErrEvidenceNotBoundToQuote = errors.New("evidence hash not included in TPM quote")
    ErrInvalidReporterSignature = errors.New("reporter signature verification failed")
)
```

**Usage Example:**

```go
collector := NewAtomicEvidenceCollector(tpm, privateKey)

// Atomically collect and sign evidence
evidence, err := collector.CollectEvidence(ctx,
    violatorNodeID,
    defense.ViolationDataManipulation,
    defense.SeverityMajor,
    "Node returned block with invalid hash",
    blockData,
    "block_hash_mismatch",
)
if err != nil {
    return err
}

// Submit atomically collected evidence
err = judge.SubmitAccusation(ctx, evidence)
```

### Corroboration

```go
type Corroboration struct {
    NodeID      string  // Corroborating node
    ObserverID  string  // Observer identity
    Timestamp   int64   // Observation time
    TPMQuote    []byte  // TPM attestation (optional)
    Observation []byte  // Supporting data
    Signature   []byte  // Signature
}

corroboration := defense.Corroboration{
    NodeID:      witnessNodeID,
    ObserverID:  witnessNodeID,
    Timestamp:   time.Now().Unix(),
    TPMQuote:    witnessTPMQuote,
    Observation: witnessData,
    Signature:   witnessSignature,
}

evidence.Corroborations = append(evidence.Corroborations, corroboration)
```

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/evidence.go`

## Accusation Protocol

### Submission Requirements

Evidence requirements vary by severity to prevent frivolous accusations while enabling rapid response to critical violations.

| Severity | Reporter | Corroborations | Total Witnesses |
|----------|----------|----------------|-----------------|
| Minor | 1 | 0 | 1 |
| Moderate | 1 | 2 | 3 |
| Major | 1 | 3 | 4 |
| Severe | 1 | 5 | 6 |
| Critical | 1 | 5 | 6 |

### Submitting Accusation

```go
judge := defense.NewJudge(defense.DefaultJudgmentConfig())

// Submit accusation (automatically validated)
err := judge.SubmitAccusation(ctx, evidence)

// Minor violations are auto-processed
// Major+ violations require committee judgment
```

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/judgment.go`

## PBFT-Style Quorum Judgment

### Judgment Configuration (CANONICAL - E1 Hardened)

The judgment system uses an enhanced 7-of-11 **judge** quorum to prevent collusion attacks:

```go
type JudgmentConfig struct {
    MinJudges          int           // Minimum judges: 11 (increased from 5)
    QuorumThreshold    float64       // Vote ratio: 0.636 (7/11)
    AppealPeriod       time.Duration // Appeal window: 24h
    SevereQuorum       float64       // Unanimous for severe: 1.0
    JudgeStakeMin      uint64        // Minimum stake required: 5,000 coins
    JudgeSlashAmount   uint64        // Stake slashed for misconduct: 2,500 coins
}

// DefaultJudgmentConfig returns production values (E1 hardened)
func DefaultJudgmentConfig() JudgmentConfig {
    return JudgmentConfig{
        MinJudges:          11,              // Increased from 5
        QuorumThreshold:    0.636,           // 7 of 11 (was 3 of 5)
        AppealPeriod:       24 * time.Hour,
        SevereQuorum:       1.0,             // 100% for critical
        JudgeStakeMin:      5000,            // 5,000 coins minimum stake
        JudgeSlashAmount:   2500,            // 50% stake at risk
    }
}
```

**Why 7-of-11 (E1 Mitigation):**

| Quorum | Judges to Bribe | Bribe Cost (5K stake each) | Attack Difficulty |
|--------|-----------------|---------------------------|-------------------|
| 3-of-5 | 3 | 15,000 coins + bribes | Low |
| 5-of-9 | 5 | 25,000 coins + bribes | Medium |
| **7-of-11** | **7** | **35,000 coins + bribes** | **High** |

The 7-of-11 quorum requires bribing 7 separate judges who each have 5,000 coins at stake, making collusion economically infeasible.

### Judge Stake Requirements (CANONICAL)

Judges must post collateral that can be slashed for misconduct:

```go
// JudgeStake represents a judge's collateral for defense system participation
type JudgeStake struct {
    JudgeID         [32]byte
    StakeAmount     uint64            // Minimum 5,000 coins
    StakedAt        time.Time
    LockDuration    time.Duration     // 90 days minimum
    SlashHistory    []SlashEvent
    TotalSlashed    uint64
}

// JudgeEligibility checks if node can serve as judge in defense disputes
type JudgeEligibility struct {
    NodeID           [32]byte
    Reputation       float64           // Must be >= 0.85
    StakeAmount      uint64            // Must be >= 5,000
    StakeLocked      bool              // Must be locked
    NodeAge          time.Duration     // Must be >= 120 days
    RecentViolations int               // Must be 0 in last 90 days
    JudgmentHistory  JudgmentStats     // Track record
}

// ValidateJudgeEligibility checks all requirements
func ValidateJudgeEligibility(node *Node, stake *JudgeStake) error {
    if node.Reputation < 0.85 {
        return &ErrInsufficientReputation{
            Required: 0.85,
            Actual:   node.Reputation,
        }
    }

    if stake.StakeAmount < 5000 {
        return &ErrInsufficientStake{
            Required: 5000,
            Actual:   stake.StakeAmount,
        }
    }

    if !stake.isLocked() {
        return ErrStakeNotLocked
    }

    nodeAge := time.Since(node.CreatedAt)
    if nodeAge < 120*24*time.Hour {
        return &ErrNodeTooYoung{
            Required: 120 * 24 * time.Hour,
            Actual:   nodeAge,
        }
    }

    if node.getRecentViolations(90*24*time.Hour) > 0 {
        return ErrRecentViolations
    }

    return nil
}
```

### Value-Scaled Judge Stake Requirements (CANONICAL - E2 Fix)

**CRITICAL SECURITY**: Fixed minimum stake (5,000 coins) is insufficient for high-value disputes.
An attacker bribing judges for a 1M coin escrow would only need to overcome 35K coins of stake
(7 judges × 5K each), making the attack economically viable for disputes > ~100K coins.

The E2 fix scales required judge stake proportionally with dispute value:

```go
// StakeScaling defines how judge stake scales with dispute value
type StakeScaling struct {
    BaseStake       uint64    // Minimum stake (5,000 coins)
    ScaleThreshold  uint64    // Disputes below this use base stake (10,000 coins)
    ScaleFactor     float64   // Stake = max(BaseStake, DisputeValue * ScaleFactor)
    MaxStake        uint64    // Cap to prevent barrier to entry (100,000 coins)
}

var DefaultStakeScaling = StakeScaling{
    BaseStake:      5000,     // 5,000 coins minimum
    ScaleThreshold: 10000,    // Disputes >= 10K coins trigger scaling
    ScaleFactor:    0.05,     // 5% of dispute value
    MaxStake:       100000,   // 100,000 coin cap
}

// CalculateRequiredStake determines judge stake for a dispute value
func CalculateRequiredStake(disputeValue uint64, config StakeScaling) uint64 {
    if disputeValue < config.ScaleThreshold {
        return config.BaseStake
    }

    // Scale stake with dispute value
    scaledStake := uint64(float64(disputeValue) * config.ScaleFactor)

    // Apply floor and ceiling
    if scaledStake < config.BaseStake {
        return config.BaseStake
    }
    if scaledStake > config.MaxStake {
        return config.MaxStake
    }

    return scaledStake
}

// JudgeEligibilityForDispute checks stake against dispute-specific requirements
func JudgeEligibilityForDispute(judge *Node, stake *JudgeStake, dispute *Dispute) error {
    // Standard eligibility checks
    if err := ValidateJudgeEligibility(judge, stake); err != nil {
        return err
    }

    // E2 Fix: Value-scaled stake requirement
    requiredStake := CalculateRequiredStake(dispute.EscrowValue, DefaultStakeScaling)
    if stake.StakeAmount < requiredStake {
        return &ErrInsufficientStakeForDispute{
            DisputeValue:  dispute.EscrowValue,
            RequiredStake: requiredStake,
            ActualStake:   stake.StakeAmount,
        }
    }

    return nil
}
```

**E2 Scaling Table**:

| Dispute Value | Required Stake per Judge | Total at Risk (7 judges) | Attack Economics |
|---------------|--------------------------|--------------------------|------------------|
| 5,000 coins | 5,000 (base) | 35,000 | Attacker profits if bribe < 35K |
| 10,000 coins | 5,000 (base) | 35,000 | Marginal |
| 50,000 coins | 2,500 (5%) | 17,500 | Still profitable, but... |
| 100,000 coins | 5,000 (5%) | 35,000 | Attacker needs 50K+ stake |
| 500,000 coins | 25,000 (5%) | 175,000 | Attacker needs 175K+ bribe |
| 1,000,000 coins | 50,000 (5%) | 350,000 | Economically secure |
| 2,000,000+ coins | 100,000 (cap) | 700,000 | Maximum protection |

**Security Analysis**:
- For any dispute, an attacker must bribe judges with more than (RequiredStake × Quorum) coins
- With 5% scaling and 7-of-11 quorum, breaking the system requires bribing ~3.5% of dispute value
- This makes attacks economically irrational for all but the smallest disputes
- The 100K cap ensures high-stake judges remain available (market won't be too exclusive)

### Judge Misconduct Penalties

| Misconduct | Penalty | Evidence Required |
|------------|---------|-------------------|
| Collusion (proven) | 100% stake slash + permanent ban | On-chain evidence of coordination |
| Vote selling | 100% stake slash + permanent ban | Transaction evidence |
| Biased voting pattern | 50% stake slash + 90-day suspension | Statistical analysis |
| Failure to vote | 10% stake slash per missed case | Timeout record |
| Conflict of interest (undisclosed) | 25% stake slash + 30-day suspension | Relationship evidence |

## Penalty Constants (CANONICAL)

This section is the **single source of truth** for all penalty amounts across the entire system. All other documents must reference this table. For detailed context and implementation specifics, see the respective documents.

### System-Wide Penalty Reference

| Violation Category | Specific Violation | Stake Slash % | Reputation Penalty | Ban Duration | Document Reference |
|-------------------|-------------------|---------------|-------------------|--------------|-------------------|
| **Judge Misconduct** | | | | | |
| | Collusion (proven) | 100% | -1.00 | Permanent | 09-defense-reputation.md §1283 |
| | Vote selling | 100% | -1.00 | Permanent | 09-defense-reputation.md §1283 |
| | Biased voting pattern | 50% | -0.50 | 90 days | 09-defense-reputation.md §1283 |
| | Failure to vote | 10% | -0.10 | None | 09-defense-reputation.md §1283 |
| | Conflict of interest | 25% | -0.25 | 30 days | 09-defense-reputation.md §1283 |
| **DKG Protocol** | | | | | |
| | Phase timeout (>3 min) | 1% | -0.01 | None | 04-cryptographic-protocols.md §5543 |
| | Complete DKG timeout (>15 min) | 5% | -0.15 | 24 hours | 04-cryptographic-protocols.md §5544 |
| | Invalid commitment | 10% | -0.25 | 7 days | 04-cryptographic-protocols.md §5545 |
| | Equivocation | 50% | -0.50 | 30 days | 04-cryptographic-protocols.md §5546 |
| | Proven collusion | 100% | -1.00 | Permanent | 04-cryptographic-protocols.md §5547 |
| **General Violations** | | | | | |
| | Minor violation | 0% | -0.05 | None | 09-defense-reputation.md §254 |
| | Moderate violation | 0% | -0.15 | None | 09-defense-reputation.md §254 |
| | Major violation | 0% | -0.30 | Varies | 09-defense-reputation.md §254 |
| **Collusion Rings** | | | | | |
| | First detection (warning) | 0% | 0 (frozen) | 7 days | 09-defense-reputation.md §502 |
| | Confirmed collusion ring | 0% | -0.30 | Immediate | 09-defense-reputation.md §502 |
| | Proven collusion ring | 100% | -1.00 | Permanent | 09-defense-reputation.md §502 |

### Critical Consistency Rules

1. **100% Stake Slash = Permanent Ban**: Any violation that results in 100% stake slashing MUST also result in permanent network ban
2. **Reputation Floor**: Reputation penalty cannot reduce reputation below 0.0
3. **Stake Floor**: Stake slashing cannot reduce stake below 0
4. **Ban Precedence**: If a node is banned, stake slashing and reputation penalties are still applied but the ban takes precedence for network participation
5. **Cross-Document Coherence**: When updating penalty amounts, ALL referenced documents must be updated simultaneously

### Implementation Notes

- All percentage-based slashes apply to the node's **staked amount**, not total balance
- Reputation penalties are applied **immediately** upon verdict finalization
- Ban durations start **immediately** upon verdict execution
- "Permanent" ban = `time.Duration(math.MaxInt64)` in code
- For violations with multiple severity levels, the table shows the base case; see specific documents for escalation rules

### Deterministic Judge Selection (VRF-Based with Replay Protection)

**CRITICAL SECURITY REQUIREMENT**: Judge selection MUST be deterministic AND replay-resistant.

Judge selection uses Verifiable Random Functions (VRF) to ensure:
- **Unpredictability**: Judges cannot be predicted before dispute filing
- **Verifiability**: Anyone can verify the selection was fair
- **Determinism**: Same inputs always produce same judges
- **Manipulation Resistance**: Attackers cannot game the selection
- **Replay Resistance**: Old selections cannot be replayed to get favorable committees

**CRITICAL**: Selection seed MUST include timestamp to prevent replay attacks.

```go
// JudgeSelection includes replay protection via timestamp binding
type JudgeSelection struct {
    SelectionID     [32]byte        // SHA256(Seed)
    DisputeID       [32]byte        // Dispute being judged
    Timestamp       int64           // Selection timestamp (Unix seconds)
    Epoch           uint64          // Network epoch at selection time
    Seed            []byte          // VRF output
    SelectedJudges  []NodeID        // Selected judge node IDs
    VRFProof        []byte          // Proof of correct selection
    ExpiresAt       time.Time       // Selection validity window
}

// SelectJudges generates a replay-resistant judge selection
func (s *JudgeSelector) SelectJudges(
    ctx context.Context,
    dispute *Dispute,
    numJudges int,
) (*JudgeSelection, error) {
    timestamp := time.Now().Unix()
    epoch := s.network.CurrentEpoch()

    // Step 1: Generate VRF seed including timestamp for replay protection
    // Seed = VRF(DisputeID || Timestamp || Epoch || PrevBlockHash)
    seedInput := make([]byte, 0, 128)
    seedInput = append(seedInput, dispute.ID[:]...)
    seedInput = binary.BigEndian.AppendUint64(seedInput, uint64(timestamp))
    seedInput = binary.BigEndian.AppendUint64(seedInput, epoch)
    seedInput = append(seedInput, s.network.PrevBlockHash()...)

    seed, vrfProof, err := s.vrf.Evaluate(seedInput)
    if err != nil {
        return nil, fmt.Errorf("VRF evaluation failed: %w", err)
    }

    // Step 2: Select judges using VRF output
    eligibleJudges := s.getEligibleJudges(dispute)
    selectedJudges := s.selectFromSeed(seed, eligibleJudges, numJudges)

    selection := &JudgeSelection{
        SelectionID:    sha256.Sum256(seed),
        DisputeID:      dispute.ID,
        Timestamp:      timestamp,
        Epoch:          epoch,
        Seed:           seed,
        SelectedJudges: selectedJudges,
        VRFProof:       vrfProof,
        ExpiresAt:      time.Now().Add(24 * time.Hour), // Selection valid for 24h
    }

    return selection, nil
}

// VerifySelection verifies a judge selection is valid and not replayed
func (s *JudgeSelector) VerifySelection(selection *JudgeSelection) error {
    // Step 1: Check selection hasn't expired
    if time.Now().After(selection.ExpiresAt) {
        return ErrSelectionExpired
    }

    // Step 2: Verify timestamp is recent (within last 24h)
    selectionTime := time.Unix(selection.Timestamp, 0)
    if time.Since(selectionTime) > 24*time.Hour {
        return ErrSelectionTooOld
    }

    // Step 3: Verify epoch matches (prevents cross-epoch replay)
    if selection.Epoch != s.network.EpochAtTime(selectionTime) {
        return ErrEpochMismatch
    }

    // Step 4: Verify VRF proof
    seedInput := make([]byte, 0, 128)
    seedInput = append(seedInput, selection.DisputeID[:]...)
    seedInput = binary.BigEndian.AppendUint64(seedInput, uint64(selection.Timestamp))
    seedInput = binary.BigEndian.AppendUint64(seedInput, selection.Epoch)
    seedInput = append(seedInput, s.network.BlockHashAtEpoch(selection.Epoch)...)

    if !s.vrf.Verify(seedInput, selection.Seed, selection.VRFProof) {
        return ErrInvalidVRFProof
    }

    // Step 5: Check for replay (selection ID must be unique)
    if s.usedSelections.Contains(selection.SelectionID) {
        return ErrSelectionReplayed
    }
    s.usedSelections.Add(selection.SelectionID)

    return nil
}

var (
    ErrSelectionExpired  = errors.New("judge selection has expired")
    ErrSelectionTooOld   = errors.New("judge selection timestamp is too old")
    ErrEpochMismatch     = errors.New("selection epoch does not match network epoch")
    ErrInvalidVRFProof   = errors.New("VRF proof verification failed")
    ErrSelectionReplayed = errors.New("this selection has already been used (replay attack)")
)
```

See [03-security-trust.md](03-security-trust.md) Section 17 "Deterministic Judge Selection" for additional VRF implementation details.

### Judge Eligibility Requirements

| Requirement | Threshold | Rationale |
|-------------|-----------|-----------|
| Trust Level | Trusted only | Untrusted nodes cannot judge |
| Reputation | >= 0.85 (increased from 0.80) | Higher bar for arbiters |
| Node Age | >= 120 days (increased from 90) | Longer track record required |
| CA Signatures | >= 50 | Proven participation history |
| Recent Violations | 0 (90 days, increased from 30) | Stricter clean record |
| Stake | >= 5,000 coins | Economic commitment |
| Conflict of Interest | None | Cannot be accuser, accused, or direct peer |
| Geographic Diversity | Different region | Prevents regional collusion |

### Voting Process

```go
// CRITICAL SECURITY: All judge votes MUST have signature verification
// Without verification, an attacker could forge votes to manipulate verdicts

type Vote struct {
    JudgeID   string
    Guilty    bool
    Timestamp int64
    Signature []byte    // ECDSA signature over (PacketID || JudgeID || Guilty || Timestamp)
    PublicKey []byte    // Judge's public key (from IDevID)
}

// Vote submits a judge's vote with mandatory signature verification
func (j *Judge) Vote(packetID [32]byte, judgeID string, guilty bool, signature []byte) error {
    // Step 1: Verify judge is on the selected committee
    if !j.isSelectedJudge(packetID, judgeID) {
        return ErrNotSelectedJudge
    }

    // Step 2: Get judge's public key from IDevID certificate
    judgeCert, err := j.getJudgeCertificate(judgeID)
    if err != nil {
        return fmt.Errorf("failed to get judge certificate: %w", err)
    }

    // Step 3: Verify signature over vote data
    voteData := j.computeVoteHash(packetID, judgeID, guilty, time.Now().Unix())
    if !ecdsa.VerifyASN1(judgeCert.PublicKey.(*ecdsa.PublicKey), voteData, signature) {
        return ErrInvalidJudgeSignature
    }

    // Step 4: Check for duplicate votes (prevent vote replay)
    if j.hasVoted(packetID, judgeID) {
        return ErrDuplicateVote
    }

    // Step 5: Record the verified vote
    vote := &Vote{
        JudgeID:   judgeID,
        Guilty:    guilty,
        Timestamp: time.Now().Unix(),
        Signature: signature,
        PublicKey: judgeCert.PublicKey.(*ecdsa.PublicKey).Bytes(),
    }

    return j.recordVote(packetID, vote)
}

func (j *Judge) computeVoteHash(packetID [32]byte, judgeID string, guilty bool, timestamp int64) []byte {
    h := sha256.New()
    h.Write(packetID[:])
    h.Write([]byte(judgeID))
    if guilty {
        h.Write([]byte{1})
    } else {
        h.Write([]byte{0})
    }
    binary.Write(h, binary.BigEndian, timestamp)
    return h.Sum(nil)
}

var (
    ErrNotSelectedJudge     = errors.New("node is not a selected judge for this case")
    ErrInvalidJudgeSignature = errors.New("judge vote signature verification failed")
    ErrDuplicateVote        = errors.New("judge has already voted on this case")
)
```

### Quorum Rules

| Rule Type | Threshold | Application |
|-----------|-----------|-------------|
| Standard | 64% (7 of 11) | Moderate violations |
| Unanimous | 100% | Critical violations |

### Finalization

```go
verdict, err := judge.Finalize(ctx, packetID)

type Verdict struct {
    VerdictID      [32]byte
    PacketID       [32]byte
    Guilty         bool
    PenaltyType    PenaltyType      // "reputation", "slash", "ban"
    ReputationLoss float64          // Reputation points
    SlashAmount    uint64           // Tokens slashed
    BanDuration    int64            // Seconds (-1 = permanent)
    JudgeCommittee []string         // Judge IDs
    Votes          []Vote           // All votes
    ExecutedAt     time.Time
}
```

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/judgment.go`

## Judge Selection Fallback (FINAL DESIGN)

When insufficient eligible judges are available for the standard 7-of-11 quorum, the system uses dynamic committee sizing with scaled quorum requirements.

### Fallback Committee Sizes

| Eligible Judges | Committee Size | Quorum | Rationale |
|-----------------|----------------|--------|-----------|
| 7-10 | Available count | (N+1)/2 + 1 | 5-of-7, 6-of-9, 7-of-10 |
| 5-6 | Available count | 3-of-5, 4-of-6 | Minimum viable BFT |
| 3-4 | Available count | 2-of-3, 3-of-4 | Emergency minimum |
| <3 | Escalate to coordinators | 7-of-21 | Coordinator committee |

### Judge Selection Fallback Implementation

```go
// JudgeSelectionFallback handles insufficient judge scenarios
type JudgeSelectionFallback struct {
    PreferredJudges int     // Default: 11
    MinimumJudges   int     // Default: 3
    CoordinatorPool []NodeID
}

// SelectJudgesWithFallback selects judges with fallback logic
func (jsf *JudgeSelectionFallback) SelectJudgesWithFallback(
    ctx context.Context,
    dispute *Dispute,
) (*JudgeCommittee, error) {
    eligibleJudges := jsf.getEligibleJudges(dispute)

    if len(eligibleJudges) >= jsf.PreferredJudges {
        // Standard case: full 7-of-11 quorum
        return jsf.selectStandardCommittee(eligibleJudges, 11)
    }

    if len(eligibleJudges) >= jsf.MinimumJudges {
        // Fallback: reduced committee with scaled quorum
        committeeSize := len(eligibleJudges)
        quorum := (committeeSize + 1) / 2 + 1  // Byzantine-tolerant majority

        return &JudgeCommittee{
            Judges:      eligibleJudges,
            RequiredVotes: quorum,
            IsFallback:    true,
            Reason:        fmt.Sprintf("Insufficient judges (%d available)", committeeSize),
        }, nil
    }

    // Escalation: use coordinator committee
    return jsf.escalateToCoordinators(ctx, dispute)
}

// escalateToCoordinators uses coordinator committee for disputes
func (jsf *JudgeSelectionFallback) escalateToCoordinators(
    ctx context.Context,
    dispute *Dispute,
) (*JudgeCommittee, error) {
    // Use VRF to select 21 coordinators from coordinator pool
    selectedCoordinators := jsf.selectCoordinatorsVRF(dispute, 21)

    return &JudgeCommittee{
        Judges:        selectedCoordinators,
        RequiredVotes: 7,  // 7-of-21 quorum
        IsFallback:    true,
        IsEscalated:   true,
        Reason:        "Insufficient judges - escalated to coordinator committee",
    }, nil
}

var (
    ErrInsufficientJudges = errors.New("insufficient eligible judges for dispute")
)
```

## Judge Lifecycle Management (FINAL DESIGN)

Judges may become unavailable or ineligible during active disputes. The system handles these scenarios with replacement and vote preservation.

### Conflict of Interest Discovery

If a judge's conflict of interest is discovered after selection:

```go
// RemoveJudgeConflict removes a judge due to conflict of interest
func (jc *JudgeCommittee) RemoveJudgeConflict(
    judgeID [32]byte,
    conflictReason string,
) error {
    // Step 1: Validate judge is on committee
    if !jc.containsJudge(judgeID) {
        return ErrJudgeNotOnCommittee
    }

    // Step 2: Check if they already voted
    if jc.hasVoted(judgeID) {
        // Preserve vote for audit, but invalidate it
        jc.invalidateVote(judgeID, conflictReason)
    }

    // Step 3: Remove from committee
    jc.removeJudge(judgeID)

    // Step 4: Select replacement via VRF continuation
    replacement := jc.selectReplacementJudge(judgeID)
    jc.addJudge(replacement)

    // Log conflict removal
    logJudgeConflict(judgeID, replacement, conflictReason)

    return nil
}
```

### Judge Offline Timeout

If a judge goes offline during deliberation:

| Timeout | Action | Implementation |
|---------|--------|----------------|
| 1 hour | Replace judge | VRF continuation selects replacement |
| Previous votes | Preserved | Original votes remain in record |
| New judge | Fresh vote window | Replacement gets full deliberation time |

```go
// MonitorJudgeAvailability checks judge connectivity
func (jm *JudgeMonitor) MonitorJudgeAvailability(
    ctx context.Context,
    committee *JudgeCommittee,
) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for _, judgeID := range committee.Judges {
                lastSeen := jm.getLastSeen(judgeID)
                if time.Since(lastSeen) > 1*time.Hour {
                    // Judge offline - replace
                    jm.handleOfflineJudge(committee, judgeID)
                }
            }
        }
    }
}

// handleOfflineJudge replaces an offline judge
func (jm *JudgeMonitor) handleOfflineJudge(
    committee *JudgeCommittee,
    offlineJudge [32]byte,
) {
    // Preserve existing vote if any
    if committee.hasVoted(offlineJudge) {
        vote := committee.getVote(offlineJudge)
        committee.markVoteAsPreserved(vote)
    }

    // Select replacement
    replacement := committee.selectReplacementJudge(offlineJudge)
    committee.replaceJudge(offlineJudge, replacement)

    // Notify replacement
    notifyJudgeAssignment(replacement, committee.DisputeID)

    logJudgeReplacement(offlineJudge, replacement, "offline_timeout")
}
```

### Reputation Drop Mid-Dispute

If a judge's reputation drops below 0.85 during active deliberation:

```go
// CheckJudgeEligibility validates ongoing judge eligibility
func (jc *JudgeCommittee) CheckJudgeEligibility(judgeID [32]byte) error {
    judge := jc.getJudge(judgeID)
    currentReputation := getNodeReputation(judgeID)

    if currentReputation < 0.85 {
        // Judge no longer eligible - replace immediately
        jc.removeJudge(judgeID)

        replacement := jc.selectReplacementJudge(judgeID)
        jc.addJudge(replacement)

        logJudgeRemoval(judgeID, replacement, "reputation_drop", currentReputation)

        return ErrJudgeIneligible{
            JudgeID:    judgeID,
            Reputation: currentReputation,
            Required:   0.85,
        }
    }

    return nil
}
```

## TPM Hardware Replacement (FINAL DESIGN)

Nodes with legitimate hardware failures requiring TPM replacement follow a migration procedure to preserve identity while rebuilding trust.

### Migration Procedure

```go
// TPMMigrationRequest represents a hardware replacement request
type TPMMigrationRequest struct {
    NodeID              [32]byte
    OldTPMEndorsementKey []byte
    NewTPMEndorsementKey []byte
    MigrationReason     string
    OldTPMSignature     []byte    // Signed with old TPM
    NewTPMAttestation   *DeviceAttestation
    RequestedAt         time.Time
}

// SubmitTPMMigration initiates TPM hardware replacement
func (tm *TPMManager) SubmitTPMMigration(
    req *TPMMigrationRequest,
) (*MigrationApproval, error) {
    // Step 1: Verify old TPM signature
    if !tm.verifyOldTPMSignature(req) {
        return nil, ErrInvalidOldTPMSignature
    }

    // Step 2: Verify new TPM attestation
    if err := VerifyDeviceAttestation(req.NewTPMAttestation); err != nil {
        return nil, fmt.Errorf("new TPM attestation invalid: %w", err)
    }

    // Step 3: Submit to governance for approval
    proposal := &GovernanceProposal{
        Type:        ProposalTypeTPMMigration,
        NodeID:      req.NodeID,
        MigrationReq: req,
        RequiredVotes: 3,  // 3-of-7 coordinator committee
    }

    return tm.governanceSubmit(proposal)
}
```

### Governance Approval

| Requirement | Threshold | Rationale |
|-------------|-----------|-----------|
| Coordinator votes | 3-of-7 | Prevents abuse while allowing legitimate migrations |
| Old TPM signature | Valid | Proves control of original hardware |
| New TPM attestation | Valid | Ensures new hardware is legitimate |
| Migration reason | Documented | Audit trail for governance review |

### Reputation Preservation and Probation

```go
// ApproveTPMMigration executes approved TPM migration
func (tm *TPMManager) ApproveTPMMigration(
    migrationID [32]byte,
    approvalVotes []CoordinatorVote,
) error {
    migration := tm.getMigration(migrationID)

    // Verify 3-of-7 approval
    if len(approvalVotes) < 3 {
        return ErrInsufficientApprovalVotes
    }

    // Step 1: Record new TPM binding
    tm.registry.UnbindTPM(migration.OldTPMEndorsementKey)
    tm.registry.BindTPM(migration.NewTPMEndorsementKey, migration.NodeID)

    // Step 2: Preserve reputation at 50%
    oldReputation := getNodeReputation(migration.NodeID)
    newReputation := oldReputation * 0.50
    setNodeReputation(migration.NodeID, newReputation)

    // Step 3: Enter 90-day probation
    tm.startMigrationProbation(migration.NodeID, 90*24*time.Hour)

    logTPMMigration(migration.NodeID, oldReputation, newReputation)

    return nil
}

// MigrationProbation enforces 90-day rebuild period
type MigrationProbation struct {
    NodeID      [32]byte
    StartedAt   time.Time
    EndsAt      time.Time
    MinReputation float64  // Must stay above this
    Violations  int        // Any violation extends probation
}
```

### Probation Requirements

| Requirement | Value | Consequence of Violation |
|-------------|-------|--------------------------|
| Duration | 90 days | Extended by 30 days per violation |
| Minimum reputation | 50% of pre-migration | Probation reset to day 0 |
| Violations allowed | 0 | Each violation adds 30 days |
| Uptime | 99% | Same as standard probation |

## Sybil Attack Countermeasures (FINAL DESIGN)

The system detects coordinated Sybil attacks through pattern analysis and enforces geographic diversity requirements.

### Coordinated Probation Detection

```go
// ProbationCompletionMonitor detects coordinated probation patterns
type ProbationCompletionMonitor struct {
    completions map[string][]time.Time  // date -> []nodeID completions
    mu          sync.RWMutex
}

// RecordProbationCompletion tracks probation completions
func (pcm *ProbationCompletionMonitor) RecordProbationCompletion(
    nodeID [32]byte,
    completedAt time.Time,
) {
    pcm.mu.Lock()
    defer pcm.mu.Unlock()

    dateKey := completedAt.Format("2006-01-02")
    pcm.completions[dateKey] = append(pcm.completions[dateKey], completedAt)

    // Check for coordinated completion pattern
    if len(pcm.completions[dateKey]) > 100 {
        pcm.flagCoordinatedCompletions(dateKey)
    }
}

// flagCoordinatedCompletions alerts on suspicious patterns
func (pcm *ProbationCompletionMonitor) flagCoordinatedCompletions(date string) {
    completions := pcm.completions[date]

    // Analyze temporal clustering
    var withinHour int
    window := time.Hour

    for i, t1 := range completions {
        for j := i + 1; j < len(completions); j++ {
            if completions[j].Sub(t1) < window {
                withinHour++
            }
        }
    }

    if withinHour > 50 {
        alert := &SybilAlert{
            Type:        SybilAlertCoordinatedProbation,
            Date:        date,
            Count:       len(completions),
            ClusterSize: withinHour,
            Severity:    SeverityCritical,
        }

        submitForManualReview(alert)
        logSybilPattern("coordinated_probation", alert)
    }
}
```

### Activity Padding Detection

```go
// ActivityPaddingDetector identifies synthetic activity patterns
type ActivityPaddingDetector struct {
    activityLog map[[32]byte][]ActivityEvent
    mu          sync.RWMutex
}

// AnalyzeActivityVariance detects low-variance patterns
func (apd *ActivityPaddingDetector) AnalyzeActivityVariance(
    nodeID [32]byte,
    period time.Duration,
) (variance float64, isSuspicious bool) {
    apd.mu.RLock()
    events := apd.activityLog[nodeID]
    apd.mu.RUnlock()

    if len(events) < 100 {
        return 0, false  // Insufficient data
    }

    // Calculate inter-event time variance
    var intervals []float64
    for i := 1; i < len(events); i++ {
        interval := events[i].Timestamp.Sub(events[i-1].Timestamp).Seconds()
        intervals = append(intervals, interval)
    }

    variance = calculateVariance(intervals)

    // Low variance indicates automated/scripted behavior
    // Legitimate users have high variance in activity timing
    if variance < 10.0 {  // Very consistent timing
        return variance, true
    }

    return variance, false
}

// calculateVariance computes statistical variance
func calculateVariance(data []float64) float64 {
    if len(data) == 0 {
        return 0
    }

    mean := 0.0
    for _, v := range data {
        mean += v
    }
    mean /= float64(len(data))

    variance := 0.0
    for _, v := range data {
        diff := v - mean
        variance += diff * diff
    }
    variance /= float64(len(data))

    return variance
}
```

### Geographic Diversity Requirement

```go
// GeographicDiversityChecker ensures verifier distribution
type GeographicDiversityChecker struct {
    regionMap map[[32]byte]string  // nodeID -> region
}

// ValidateGeographicDiversity checks verifier distribution
func (gdc *GeographicDiversityChecker) ValidateGeographicDiversity(
    verifiers [][32]byte,
    minRegions int,
) error {
    regions := make(map[string]int)

    for _, verifierID := range verifiers {
        region := gdc.regionMap[verifierID]
        regions[region]++
    }

    if len(regions) < minRegions {
        if len(regions) < 3 {
            // Critical: insufficient geographic diversity
            return &ErrInsufficientGeographicDiversity{
                Required: minRegions,
                Actual:   len(regions),
                Regions:  regions,
            }
        }

        // Warning: below preferred diversity, but acceptable with attestation
        return gdc.requestRegionalCoordinatorAttestation(verifiers, regions)
    }

    return nil
}

// requestRegionalCoordinatorAttestation gets approval for low diversity
func (gdc *GeographicDiversityChecker) requestRegionalCoordinatorAttestation(
    verifiers [][32]byte,
    regions map[string]int,
) error {
    // Require regional coordinator to sign off on low diversity
    for region := range regions {
        coordinator := gdc.getRegionalCoordinator(region)
        attestation := coordinator.AttestLowDiversity(verifiers, region)

        if !attestation.Approved {
            return ErrRegionalCoordinatorRejected
        }

        logLowDiversityWarning(verifiers, regions, attestation)
    }

    return nil
}
```

## Penalty Escalation (FINAL DESIGN)

Violations are tracked with time-decay and escalation for persistent moderate violations.

### Violation Tracking with Decay

```go
// ViolationTracker tracks violations with 90-day rolling window
type ViolationTracker struct {
    violations map[[32]byte][]ViolationRecord
    mu         sync.RWMutex
}

// ViolationRecord stores violation with decay metadata
type ViolationRecord struct {
    ViolationID   [32]byte
    Type          ViolationType
    Severity      ViolationSeverity
    OccurredAt    time.Time
    DecayedWeight float64  // Current weight after decay
    OriginalWeight float64  // Weight at occurrence
}

// RecordViolation adds a violation with full weight
func (vt *ViolationTracker) RecordViolation(
    nodeID [32]byte,
    violationType ViolationType,
    severity ViolationSeverity,
) {
    vt.mu.Lock()
    defer vt.mu.Unlock()

    weight := severityToWeight(severity)

    violation := ViolationRecord{
        ViolationID:    generateViolationID(),
        Type:           violationType,
        Severity:       severity,
        OccurredAt:     time.Now(),
        DecayedWeight:  weight,
        OriginalWeight: weight,
    }

    vt.violations[nodeID] = append(vt.violations[nodeID], violation)
}

// GetViolationCount returns count with decay applied
func (vt *ViolationTracker) GetViolationCount(
    nodeID [32]byte,
    window time.Duration,
) float64 {
    vt.mu.RLock()
    defer vt.mu.RUnlock()

    now := time.Now()
    totalWeight := 0.0

    for _, violation := range vt.violations[nodeID] {
        age := now.Sub(violation.OccurredAt)

        if age > window {
            continue  // Outside window
        }

        // Apply 50% decay every 30 days
        decayPeriods := age.Hours() / (30 * 24)
        decayFactor := math.Pow(0.5, decayPeriods)

        totalWeight += violation.OriginalWeight * decayFactor
    }

    return totalWeight
}

// CheckEscalation determines if violations should escalate
func (vt *ViolationTracker) CheckEscalation(
    nodeID [32]byte,
    violationType ViolationType,
) bool {
    count := vt.getViolationCountByType(nodeID, violationType, 90*24*time.Hour)

    // 3+ moderate violations in 90 days = escalate to severe
    if violationType == ViolationModerate && count >= 3.0 {
        return true
    }

    return false
}
```

### Persistent Moderate Violations Escalation

| Threshold | Window | Action | Justification |
|-----------|--------|--------|---------------|
| 3+ moderate violations | 90 days | Escalate to severe category | Pattern of persistent misbehavior |
| Weight-based | Decay by 50% per 30 days | Fair aging of old violations | Allows rehabilitation |

### Role Loss Mid-Operation

When a node loses role eligibility during active operations:

```go
// GracefulRoleTransition handles in-flight operations during role loss
type GracefulRoleTransition struct {
    transitionPeriod time.Duration  // Default: 1 hour
    supervisor       *OperationSupervisor
}

// InitiateRoleTransition begins graceful handoff
func (grt *GracefulRoleTransition) InitiateRoleTransition(
    nodeID [32]byte,
    oldRole, newRole Role,
    reason string,
) error {
    // Step 1: Identify in-flight operations
    operations := grt.getInFlightOperations(nodeID)

    // Step 2: Start transition period
    transition := &RoleTransition{
        NodeID:          nodeID,
        OldRole:         oldRole,
        NewRole:         newRole,
        StartedAt:       time.Now(),
        CompletionDeadline: time.Now().Add(grt.transitionPeriod),
        InFlightOps:     operations,
    }

    // Step 3: Assign supervisor if operations exist
    if len(operations) > 0 {
        grt.supervisor.SuperviseTransition(transition)
    }

    // Step 4: Block new operations in old role
    blockNewOperations(nodeID, oldRole)

    logRoleTransition(nodeID, oldRole, newRole, reason)

    return nil
}

// SuperviseTransition monitors in-flight ops during role transition
func (os *OperationSupervisor) SuperviseTransition(
    transition *RoleTransition,
) {
    for _, op := range transition.InFlightOps {
        // Assign supervisor to monitor completion
        os.assignSupervisor(op, transition)
    }
}
```

### In-Flight Contracts During Role Loss

| Contract Stage | Action | Supervision |
|----------------|--------|-------------|
| Active | Continue to completion | Supervisor monitors |
| Pending | Transfer to eligible node | VRF selects replacement |
| Disputed | Hold until resolution | Normal dispute process |

```go
// handleContractDuringRoleLoss manages contracts when node loses role
func handleContractDuringRoleLoss(
    nodeID [32]byte,
    contract *ServiceContract,
) error {
    switch contract.Stage {
    case ContractStageActive:
        // Allow completion under supervision
        assignContractSupervisor(contract, nodeID)
        contract.UnderSupervision = true

    case ContractStagePending:
        // Transfer to replacement node
        replacement := selectReplacementVRF(contract)
        transferContract(contract, nodeID, replacement)

    case ContractStageDisputed:
        // Hold for normal dispute resolution
        flagContractForReview(contract, "provider_role_loss")
    }

    return nil
}
```

## False Accusation Protection

To prevent abuse of the dispute system, false accusations result in penalties for the accuser.

### False Accusation Detection

A false accusation is identified when:
- Judges reach a "not guilty" verdict
- Evidence is determined to be fabricated
- Accusation pattern matches manipulation signatures

### False Accusation Penalties

| Offense Count | Reputation Penalty | Ban Duration |
|---------------|-------------------|--------------|
| 1st offense | -0.05 (5%) | None |
| 2nd offense | -0.10 (10%) | None |
| 3rd offense | -0.15 (15%) | 24 hours |
| 4th offense | -0.20 (20%) | 7 days |
| 5th+ offense | -0.30 (30%) | 30 days |

### Manipulation Pattern Detection

The system monitors for:
- **Rapid-fire disputes**: >3 disputes in 1 hour from same accuser
- **Timing attacks**: Disputes filed immediately after block publication
- **Repeated pairs**: Same accuser-accused pair within 7 days
- **Coordinated accusations**: Multiple accusers targeting same node simultaneously

See [03-security-trust.md](03-security-trust.md) Section 17 for anti-manipulation detection algorithms.

## Penalty Calculation

### Penalty Types

```go
const (
    PenaltyNone       = "none"        // No penalty
    PenaltyReputation = "reputation"  // Reputation loss
    PenaltySlash      = "slash"       // Stake slashing
    PenaltyBan        = "ban"         // Network ban
)
```

### Penalty Matrix

| Severity | Penalty Type | Reputation Loss | Slash Amount | Ban Duration |
|----------|--------------|-----------------|--------------|--------------|
| Minor | Reputation | -10 | 0 | None |
| Moderate | Reputation | -50 to -100 | 0 | None |
| Major (Network Attack) | Ban | 0 | 0 | 7 days |
| Major (Data Manipulation) | Ban | 0 | 0 | 7 days |
| Major (Other) | Slash | 0 | 1000 tokens | None |
| Severe (Sybil/Eclipse/Consensus) | Ban | 0 | 0 | Permanent |
| Severe (Other) | Ban | 0 | 0 | 30 days |

### Penalty Execution

```go
err := judge.ExecutePenalty(ctx, verdict)

isBanned := judge.IsBanned(nodeID)

type BanEntry struct {
    NodeID    string
    BannedAt  time.Time
    ExpiresAt time.Time    // Zero = permanent
    Reason    string
    PacketID  [32]byte
}

banInfo, exists := judge.GetBanInfo(nodeID)
if exists {
    if banInfo.ExpiresAt.IsZero() {
        fmt.Println("Permanent ban")
    } else {
        fmt.Printf("Banned until: %v\n", banInfo.ExpiresAt)
    }
}
```

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/judgment.go`

## Reporter Rewards

### Reward Distribution

When a guilty verdict is reached, the slashed/penalty amount is distributed to incentivize active monitoring.

| Recipient | Percentage |
|-----------|------------|
| Primary reporter | 60% |
| First corroborator | 30% |
| Second corroborator | 10% |

### Reward Calculation

```go
type RewardDistribution struct {
    PacketID       [32]byte
    TotalReward    uint64
    PrimaryReward  uint64  // 60%
    FirstSupport   uint64  // 30%
    SecondSupport  uint64  // 10%
    ReporterID     string
    Supporters     []string
}

rewards := calculateRewards(verdict)
// rewards.TotalReward = 1000 tokens
// rewards.PrimaryReward = 600 (60%)
// rewards.FirstSupport = 300 (30%)
// rewards.SecondSupport = 100 (10%)
```

### Incentive Structure

This creates strong incentives for:

1. **Active monitoring** - Reporters earn rewards
2. **Evidence quality** - Only guilty verdicts pay out
3. **Early reporting** - First corroborators earn more
4. **Network health** - Reduces malicious behavior

**Implementation**: `/mnt/vm-host-1/go-trusted-platform/pkg/defense/rewards.go`

---

# Part 3: Integration

## Complete Workflow Example

```go
// 1. Monitor detects anomaly
monitor := defense.NewMonitor(defense.DefaultMonitorConfig())
monitor.RecordDataIntegrity(violatorID, false)

isAnomalous, desc := monitor.CheckAnomaly(violatorID)
if !isAnomalous {
    return
}

// 2. Create TPM-attested evidence
tpm, _ := boot.NewTPM(tpmConfig)
nonce, _ := boot.GenerateNonce()
tpmQuote, _ := tpm.CreateAttestationQuote(nonce)

evidence := &defense.EvidencePacket{
    ReporterID:        myNodeID,
    AccusedNodeID:     violatorID,
    Timestamp:         time.Now().Unix(),
    ViolationType:     defense.ViolationDataManipulation,
    Severity:          defense.SeverityMajor,
    Description:       desc,
    Evidence:          corruptedData,
    EvidenceType:      "integrity_failure",
    TPMQuote:          tpmQuote,
    TPMTimestamp:      time.Now().Unix(),
    ReporterSignature: signData(evidence),
}

// 3. Gather corroborations
for _, witness := range witnesses {
    corroboration := witness.CreateCorroboration(evidence)
    evidence.Corroborations = append(evidence.Corroborations, corroboration)
}

// 4. Submit to judgment system
judge := defense.NewJudge(defense.DefaultJudgmentConfig())
err := judge.SubmitAccusation(ctx, evidence)

// 5. Deterministic judge selection (VRF-based)
dispute := &Dispute{
    ID:               evidence.PacketID,
    EvidenceHash:     sha256.Sum256(evidence.Evidence),
    AccuserNodeID:    evidence.ReporterID,
    AccusedNodeID:    evidence.AccusedNodeID,
    FilingBlockHash:  currentBlockHash,
    FilingBlockHeight: currentBlockHeight,
}
selection, _ := judgeSelector.SelectJudges(ctx, dispute, 11) // 11 judges now

// 6. Selected judges vote
for _, judgeID := range selection.SelectedJudges {
    vote := getJudgeVote(judgeID, evidence)
    judge.Vote(evidence.PacketID, judgeID, vote.Guilty, vote.Signature)
}

// 7. Finalize verdict
verdict, err := judge.Finalize(ctx, evidence.PacketID)

// 8. Execute penalty and update reputation
if verdict.Guilty {
    judge.ExecutePenalty(ctx, verdict)

    // Reputation is automatically reduced based on verdict
    // Violation-based decay is applied (see Decay Mechanics)

    // 9. Distribute rewards
    rewards := calculateRewards(verdict)
    distributeRewards(rewards)
} else {
    // 10. Apply false accusation penalty to reporter
    applyFalseAccusationPenalty(evidence.ReporterID)
}
```

## Security Considerations

### TPM Attestation

- **Quote Freshness**: Nonce prevents replay attacks
- **PCR Values**: Validates system integrity
- **Signature**: Proves quote authenticity

### Sybil Resistance (Combined)

Defense layer:
- Requires multiple independent witnesses
- TPM quotes link identity to hardware
- Corroboration threshold prevents single-node attacks

Reputation layer:
- Minimum 95 days to reach coordinator status
- Probation periods cannot be accelerated
- Time and resource costs make Sybil attacks expensive

### Byzantine Fault Tolerance

- PBFT-style quorum (3f+1 nodes tolerate f faults)
- 7-of-11 threshold (tolerates up to 4 Byzantine arbiters)
- Unanimous requirement for severe penalties

### Trust Level Enforcement

- Untrusted nodes CANNOT serve as judges
- Untrusted nodes CANNOT earn reputation through defense activities
- All defense system participants must be Trusted

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Monitoring Overhead | ~1% CPU per 100 monitored nodes |
| Evidence Size | ~2-5 KB per packet |
| TPM Quote Generation | ~100ms |
| Judgment Latency | <1 second (quorum reached) |
| Appeal Period | 24 hours (configurable) |
| VRF Proof Generation | ~10ms |
| VRF Proof Verification | ~5ms |

---

# Part 4: Atomic State Management

## S12: Atomic Reputation Updates (SECURITY FIX)

Reputation updates MUST be atomic to prevent race conditions where concurrent updates result in stale reads or lost writes. This section specifies compare-and-swap based reputation management.

### Problem Statement

**Race condition vulnerability:**
1. Thread A reads reputation = 0.80
2. Thread B reads reputation = 0.80
3. Thread A applies +0.01 bonus, writes 0.81
4. Thread B applies -0.05 penalty, writes 0.75 (should be 0.76)
5. The +0.01 bonus is silently lost

### Atomic Reputation Implementation

```go
// NodeReputation uses atomic operations for thread-safe updates
type NodeReputation struct {
    NodeID          [32]byte
    // ReputationBits stores reputation as fixed-point integer for atomic ops
    // Reputation 0.85 = 8500 (scaled by 10000)
    ReputationBits  uint64        // ATOMIC: Use atomic.CompareAndSwapUint64
    LastUpdateEpoch uint64        // ATOMIC: Epoch of last update
    Version         uint64        // ATOMIC: Monotonic version for CAS validation
}

const ReputationScale = 10000 // 0.0001 precision

// Typed errors for reputation operations
var (
    ErrReputationRace          = errors.New("reputation update race detected")
    ErrReputationOverflow      = errors.New("reputation would exceed 1.0")
    ErrReputationUnderflow     = errors.New("reputation would go below 0.0")
    ErrStaleReputationVersion  = errors.New("stale reputation version")
)

// getReputation returns current reputation as float64
func (nr *NodeReputation) getReputation() float64 {
    bits := atomic.LoadUint64(&nr.ReputationBits)
    return float64(bits) / ReputationScale
}

// updateReputationCAS atomically updates reputation using CAS loop
func (nr *NodeReputation) updateReputationCAS(delta float64) (newRep float64, err error) {
    deltaBits := int64(delta * ReputationScale)

    for attempts := 0; attempts < 10; attempts++ {
        oldBits := atomic.LoadUint64(&nr.ReputationBits)
        oldVersion := atomic.LoadUint64(&nr.Version)

        // Calculate new value with bounds checking
        var newBits uint64
        if deltaBits < 0 {
            // Negative delta (penalty)
            if uint64(-deltaBits) > oldBits {
                newBits = 0 // Floor at 0
            } else {
                newBits = oldBits - uint64(-deltaBits)
            }
        } else {
            // Positive delta (reward)
            newBits = oldBits + uint64(deltaBits)
            if newBits > ReputationScale { // Cap at 1.0
                newBits = ReputationScale
            }
        }

        // Atomic CAS on both reputation and version
        if atomic.CompareAndSwapUint64(&nr.ReputationBits, oldBits, newBits) {
            atomic.AddUint64(&nr.Version, 1)
            return float64(newBits) / ReputationScale, nil
        }

        // CAS failed - another thread updated first, retry
        runtime.Gosched() // Yield to reduce contention
    }

    return 0, ErrReputationRace
}

// batchUpdateReputationCAS applies multiple deltas atomically
func (nr *NodeReputation) batchUpdateReputationCAS(deltas []ReputationDelta) error {
    totalDelta := 0.0
    for _, d := range deltas {
        totalDelta += d.Amount
    }
    _, err := nr.updateReputationCAS(totalDelta)
    return err
}

// ReputationDelta represents a single reputation change
type ReputationDelta struct {
    Reason    ReputationChangeReason
    Amount    float64
    Timestamp time.Time
    Evidence  [32]byte // Hash of evidence supporting change
}

type ReputationChangeReason uint8

const (
    ReputationChangeTimeAccrual    ReputationChangeReason = iota
    ReputationChangeActivityBonus
    ReputationChangeViolationPenalty
    ReputationChangeSlashing
    ReputationChangeAppealReversal
    ReputationChangeManualAdjustment
)
```

### Reputation Update Integration

```go
// ReputationManager coordinates all reputation updates
type ReputationManager struct {
    nodes       map[[32]byte]*NodeReputation
    updateQueue chan *ReputationUpdateRequest
    mu          sync.RWMutex // Only for map access, not for reputation values
}

// UpdateReputation applies a reputation change with full audit trail
func (rm *ReputationManager) UpdateReputation(
    ctx context.Context,
    nodeID [32]byte,
    delta float64,
    reason ReputationChangeReason,
    evidence [32]byte,
) (newRep float64, err error) {
    rm.mu.RLock()
    rep, exists := rm.nodes[nodeID]
    rm.mu.RUnlock()

    if !exists {
        return 0, ErrNodeNotFound{NodeID: nodeID}
    }

    // Atomic update
    newRep, err = rep.updateReputationCAS(delta)
    if err != nil {
        return 0, fmt.Errorf("reputation update failed: %w", err)
    }

    // Log change for audit (async, non-blocking)
    go rm.logReputationChange(nodeID, delta, newRep, reason, evidence)

    return newRep, nil
}
```

---

## S13: Atomic Appeal and Bond Management (SECURITY FIX)

Appeal bonds and refunds MUST use atomic state transitions to prevent double-refund attacks. This section specifies the atomic appeal state machine.

### Problem Statement

**Double-refund vulnerability:**
1. Node A files appeal with 1000 coin bond
2. Appeal succeeds, refund triggered
3. Two goroutines both read bond state = "pending_refund"
4. Both execute refund, node receives 2000 coins
5. Bond escrow is now negative

### Appeal State Machine

```go
// AppealState represents appeal lifecycle states
type AppealState uint32

const (
    AppealStatePending      AppealState = iota  // Appeal filed, awaiting review
    AppealStateUnderReview                       // Arbiters reviewing
    AppealStateDecided                           // Decision rendered
    AppealStateRefundPending                     // Refund approved, processing
    AppealStateRefundComplete                    // Refund executed (terminal)
    AppealStateBondForfeited                     // Bond seized (terminal)
    AppealStateCancelled                         // Appeal withdrawn (terminal)
)

// ValidAppealTransitions defines allowed state transitions
var ValidAppealTransitions = map[AppealState][]AppealState{
    AppealStatePending:       {AppealStateUnderReview, AppealStateCancelled},
    AppealStateUnderReview:   {AppealStateDecided},
    AppealStateDecided:       {AppealStateRefundPending, AppealStateBondForfeited},
    AppealStateRefundPending: {AppealStateRefundComplete},
    // Terminal states - no further transitions
    AppealStateRefundComplete: {},
    AppealStateBondForfeited:  {},
    AppealStateCancelled:      {},
}

// Appeal represents an appeal with atomic state management
type Appeal struct {
    AppealID        [32]byte
    DisputeID       [32]byte
    AppellantID     [32]byte
    BondAmount      uint64
    StateFlag       uint32        // ATOMIC: Current AppealState
    FiledAt         time.Time
    DecidedAt       time.Time
    RefundedAt      time.Time
    Decision        AppealDecision
    Version         uint64        // ATOMIC: For optimistic concurrency
}

// Typed errors for appeal operations
var (
    ErrAppealStateRace        = errors.New("appeal state transition race")
    ErrInvalidAppealTransition = errors.New("invalid appeal state transition")
    ErrAppealAlreadyRefunded  = errors.New("appeal bond already refunded")
    ErrAppealBondForfeited    = errors.New("appeal bond already forfeited")
)

// transitionAppealState atomically transitions appeal state
func (a *Appeal) transitionAppealState(expected, newState AppealState) error {
    // Validate transition is allowed
    allowedTransitions, ok := ValidAppealTransitions[expected]
    if !ok {
        return fmt.Errorf("%w: unknown state %d", ErrInvalidAppealTransition, expected)
    }

    transitionAllowed := false
    for _, allowed := range allowedTransitions {
        if allowed == newState {
            transitionAllowed = true
            break
        }
    }
    if !transitionAllowed {
        return fmt.Errorf("%w: %d -> %d", ErrInvalidAppealTransition, expected, newState)
    }

    // Atomic compare-and-swap
    if !atomic.CompareAndSwapUint32(&a.StateFlag, uint32(expected), uint32(newState)) {
        currentState := AppealState(atomic.LoadUint32(&a.StateFlag))
        return fmt.Errorf("%w: expected %d, found %d", ErrAppealStateRace, expected, currentState)
    }

    atomic.AddUint64(&a.Version, 1)
    return nil
}

// getAppealState atomically reads current state
func (a *Appeal) getAppealState() AppealState {
    return AppealState(atomic.LoadUint32(&a.StateFlag))
}
```

### Atomic Bond Refund Protocol

```go
// BondManager handles appeal bonds with atomic operations
type BondManager struct {
    appeals       map[[32]byte]*Appeal
    escrowAccount *EscrowAccount
    mu            sync.RWMutex
}

// ProcessAppealDecision handles appeal decision with atomic bond resolution
func (bm *BondManager) ProcessAppealDecision(
    ctx context.Context,
    appealID [32]byte,
    decision AppealDecision,
) error {
    bm.mu.RLock()
    appeal, exists := bm.appeals[appealID]
    bm.mu.RUnlock()

    if !exists {
        return ErrAppealNotFound{AppealID: appealID}
    }

    // Step 1: Atomically transition from UnderReview to Decided
    if err := appeal.transitionAppealState(AppealStateUnderReview, AppealStateDecided); err != nil {
        return fmt.Errorf("state transition to decided failed: %w", err)
    }

    appeal.Decision = decision
    appeal.DecidedAt = time.Now()

    // Step 2: Determine bond disposition based on decision
    if decision == AppealDecisionUpheld {
        // Appeal succeeded - refund bond
        return bm.initiateBondRefund(ctx, appeal)
    } else {
        // Appeal failed - forfeit bond
        return bm.forfeitBond(ctx, appeal)
    }
}

// initiateBondRefund atomically processes bond refund
// SECURITY FIX (P5-H11): Added idempotency log to prevent double-refund on retry
func (bm *BondManager) initiateBondRefund(ctx context.Context, appeal *Appeal) error {
    // Step 0 (P5-H11): Check idempotency log first
    // This catches retries where previous refund succeeded but caller didn't receive confirmation
    if bm.isRefundComplete(appeal.AppealID) {
        log.Info("refund already completed (idempotency check)",
            "appealID", appeal.AppealID)
        return nil // Idempotent success
    }

    // Step 1: Atomically transition to RefundPending
    if err := appeal.transitionAppealState(AppealStateDecided, AppealStateRefundPending); err != nil {
        if errors.Is(err, ErrAppealStateRace) {
            // Another goroutine is handling this - check if they completed
            if bm.isRefundComplete(appeal.AppealID) {
                return nil // The other goroutine completed successfully
            }
            // Still in progress, return error to let caller retry
            return ErrRefundInProgress{AppealID: appeal.AppealID}
        }
        return fmt.Errorf("transition to refund pending: %w", err)
    }

    // Step 2: Execute the actual refund (we now own this transition)
    if err := bm.escrowAccount.Transfer(appeal.AppellantID, appeal.BondAmount); err != nil {
        // Refund failed - DO NOT revert state (would allow retry attack)
        // Log for manual intervention
        logRefundFailure(appeal.AppealID, err)
        return fmt.Errorf("escrow transfer failed: %w", err)
    }

    // Step 3 (P5-H11): Record in idempotency log BEFORE state transition
    // This ensures the refund is recorded even if state transition fails
    bm.recordRefundComplete(appeal.AppealID, appeal.AppellantID, appeal.BondAmount)

    // Step 4: Atomically transition to RefundComplete (terminal)
    if err := appeal.transitionAppealState(AppealStateRefundPending, AppealStateRefundComplete); err != nil {
        // This should never fail if we reached here
        // Log critical error - money was transferred but state not updated
        // However, idempotency log already recorded, so retries will be safe
        logCriticalStateInconsistency(appeal.AppealID, "refund_complete_transition_failed", err)
        return err
    }

    appeal.RefundedAt = time.Now()

    // Log successful refund
    logBondRefund(appeal.AppealID, appeal.AppellantID, appeal.BondAmount)

    return nil
}

// SECURITY FIX (P5-H11): Idempotency log for bond refunds
type RefundIdempotencyLog struct {
    completedRefunds sync.Map // map[[32]byte]*CompletedRefund
    persistedStore   *PersistentStore
}

type CompletedRefund struct {
    AppealID    [32]byte
    RecipientID [32]byte
    Amount      uint64
    RefundedAt  time.Time
    TxID        [32]byte   // Transaction ID for audit
}

// isRefundComplete checks if a refund has already been processed
func (bm *BondManager) isRefundComplete(appealID [32]byte) bool {
    // Check in-memory cache first
    if _, found := bm.refundLog.completedRefunds.Load(appealID); found {
        return true
    }

    // Check persistent store for crash recovery cases
    if bm.refundLog.persistedStore != nil {
        key := fmt.Sprintf("refund:complete:%x", appealID)
        if _, err := bm.refundLog.persistedStore.Get(key); err == nil {
            return true
        }
    }

    return false
}

// recordRefundComplete persistently records a completed refund
func (bm *BondManager) recordRefundComplete(
    appealID, recipientID [32]byte,
    amount uint64,
) {
    record := &CompletedRefund{
        AppealID:    appealID,
        RecipientID: recipientID,
        Amount:      amount,
        RefundedAt:  time.Now(),
        TxID:        generateTxID(),
    }

    // Store in memory (for fast lookup)
    bm.refundLog.completedRefunds.Store(appealID, record)

    // Persist to durable store (for crash recovery)
    if bm.refundLog.persistedStore != nil {
        key := fmt.Sprintf("refund:complete:%x", appealID)
        if err := bm.refundLog.persistedStore.Put(key, record); err != nil {
            log.Error("failed to persist refund record",
                "appealID", appealID,
                "error", err)
            // Don't fail the refund - the in-memory record is sufficient
            // for duplicate detection during this process lifetime
        }
    }

    log.Info("refund recorded in idempotency log",
        "appealID", appealID,
        "recipientID", recipientID,
        "amount", amount)
}

// ErrRefundInProgress indicates a refund is currently being processed
type ErrRefundInProgress struct {
    AppealID [32]byte
}

func (e ErrRefundInProgress) Error() string {
    return fmt.Sprintf("refund in progress for appeal %x", e.AppealID[:8])
}

// forfeitBond atomically forfeits the appeal bond
func (bm *BondManager) forfeitBond(ctx context.Context, appeal *Appeal) error {
    // Step 1: Atomically transition to BondForfeited
    if err := appeal.transitionAppealState(AppealStateDecided, AppealStateBondForfeited); err != nil {
        if errors.Is(err, ErrAppealStateRace) {
            // Another goroutine is handling this
            return nil
        }
        return fmt.Errorf("transition to forfeited: %w", err)
    }

    // Step 2: Transfer bond to network treasury
    if err := bm.escrowAccount.TransferToTreasury(appeal.BondAmount); err != nil {
        logForfeitFailure(appeal.AppealID, err)
        return fmt.Errorf("treasury transfer failed: %w", err)
    }

    // Log forfeiture
    logBondForfeiture(appeal.AppealID, appeal.AppellantID, appeal.BondAmount)

    return nil
}
```

### Appeal State Metrics

```go
// AppealStateMetrics tracks appeal state transitions for monitoring
type AppealStateMetrics struct {
    TotalAppeals          uint64 // Atomic
    SuccessfulRefunds     uint64 // Atomic
    ForfeitedBonds        uint64 // Atomic
    RaceConditionsHandled uint64 // Atomic (should be low)
    FailedRefunds         uint64 // Atomic (should be zero)
}

var appealMetrics AppealStateMetrics

func recordAppealMetric(metricType string) {
    switch metricType {
    case "refund_success":
        atomic.AddUint64(&appealMetrics.SuccessfulRefunds, 1)
    case "bond_forfeited":
        atomic.AddUint64(&appealMetrics.ForfeitedBonds, 1)
    case "race_handled":
        atomic.AddUint64(&appealMetrics.RaceConditionsHandled, 1)
    case "refund_failed":
        atomic.AddUint64(&appealMetrics.FailedRefunds, 1)
    }
}
```

**Atomic State Management Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No double refund | Single goroutine processes refund | CAS state transition |
| No lost reputation | Atomic CAS with retry | CompareAndSwap loop |
| Audit trail | All changes logged | Async logging |
| Race detection | Metrics for monitoring | Atomic counters |
| Terminal state safety | No transitions from terminal | ValidTransitions map |

---

# Part 5: Configuration Reference

## Reputation Configuration

```go
type ReputationConfig struct {
    // Growth parameters
    TimeComponentRate    float64       // Default: 0.003/day
    ActivityCapPerDay    float64       // Default: 0.007/day
    TotalCapPerDay       float64       // Default: 0.01/day

    // Decay parameters
    InactivityThreshold      time.Duration // Default: 7 days
    InactivityDecayRate      float64       // Default: -0.005/day
    MinorViolationPenalty    float64       // Default: -0.05
    ModerateViolationPenalty float64       // Default: -0.15
    MajorViolationPenalty    float64       // Default: -0.30

    // Role thresholds (CANONICAL VALUES - see 00-CONSTANTS.md Section 17)
    CAParticipantThreshold float64 // Default: 0.90 (elevated for anti-Sybil)
    HubThreshold           float64 // Default: 0.80
    GatewayThreshold       float64 // Default: 0.85
    CoordinatorThreshold   float64 // Default: 0.95

    // Probation periods
    CAParticipantProbation time.Duration // Default: 7 days
    HubProbation           time.Duration // Default: 30 days
    GatewayProbation       time.Duration // Default: 90 days
    CoordinatorProbation   time.Duration // Default: 90 days
}
```

## Defense Configuration

```go
type MonitorConfig struct {
    MetricsWindow   time.Duration       // Default: 5 minutes
    SampleInterval  time.Duration       // Default: 10 seconds
    AlertThresholds map[string]float64  // See Monitored Metrics
}

type JudgmentConfig struct {
    MinJudges          int           // Default: 11 (E1 hardened)
    QuorumThreshold    float64       // Default: 0.636 (7/11)
    AppealPeriod       time.Duration // Default: 24 hours
    SevereQuorum       float64       // Default: 1.0 (100%)
    ArbiterStakeMin    uint64        // Default: 5,000 coins
    ArbiterSlashAmount uint64        // Default: 2,500 coins
}

type JudgeSelectionConfig struct {
    MinReputation       float64       // Default: 0.85
    MinAge              time.Duration // Default: 120 days
    MinCASignatures     int           // Default: 50
    MaxViolations90Days int           // Default: 0
    MinStake            uint64        // Default: 5,000 coins
    RequireGeoDiversity bool          // Default: true
}
```

---

## Cross-References

- **TPM Verification Protocol**: See [03-security-trust.md](03-security-trust.md) Section 14
- **Trust Level Enforcement**: See [03-security-trust.md](03-security-trust.md) Section 15
- **Trust Downgrade Protocol**: See [03-security-trust.md](03-security-trust.md) Section 16
- **Deterministic Judge Selection**: See [03-security-trust.md](03-security-trust.md) Section 17
- **Untrusted Node Work System**: See [17-untrusted-nodes.md](17-untrusted-nodes.md)
- **DDoS Protection**: See [16-ddos-protection.md](16-ddos-protection.md)
- **Governance Economics**: See [10-governance-economics.md](10-governance-economics.md)

---

**Document Version**: 1.6
**Last Updated**: 2026-01-10
**Canonical For**: Role eligibility thresholds, reputation parameters, defense mechanisms, judge quorum, collusion detection, CA eligibility requirements

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-10 | 1.6 | **CA ANTI-SYBIL HARDENING**: Increased CA Participant reputation threshold from 0.80 to 0.90 and network age from 80 to 120 days (per 00-CONSTANTS.md Section 17). Added Verifier Diversity Requirements for CA Eligibility (MinUniqueVerifiers: 25, MinVerifierASNs: 10, MinVerifierRegions: 5, MinVerifierOrgs: 5, VerificationCooldown: 4 hours). Added Early Period Reputation Earning Caps (0.005/day max for first 180 days, making 0.90 reputation require 180 days minimum). Updated Role Eligibility Staggering code to reflect 120-day CA base age. |
| 2026-01-10 | 1.5 | **ANTI-SYBIL ENHANCEMENTS**: Added Role Eligibility Staggering (deterministic random delays: CA 0-14d, Hub 0-21d, Gateway/Coordinator 0-30d), Promotion Anomaly Detection (synchronized promotion monitoring, deployment source limits, reputation velocity threshold 0.005/day, voucher requirement for critical roles), Enhanced Collusion Ring Detection (explicit reciprocity threshold 0.80, exclusivity threshold 0.70, judge selection cooldown periods), Activity Validation Protocol (multi-monitor verification, cross-shard reputation sync, TPM-attested evidence submission) |
| 2026-01-10 | 1.4 | **SECURITY FIXES**: M2 - Fixed daily cap math verification (added mathematical proof for 0.01/day cap), H2 - Increased CA participant reputation threshold from 0.70 to 0.80 to prevent security inversion, H4 - Added canonical penalty reference table as single source of truth for all penalty amounts across system documents |
| 2026-01-10 | 1.3 | FINAL DESIGN: Added Judge Selection Fallback (dynamic committee sizing, coordinator escalation), Judge Lifecycle Management (conflict resolution, offline timeout, reputation drop handling), TPM Hardware Replacement (migration procedure, governance approval, 50% reputation preservation, 90-day probation), Sybil Attack Countermeasures (coordinated probation detection, activity padding analysis, geographic diversity requirements), Penalty Escalation (violation decay, persistent moderate escalation, role loss mid-operation with graceful handoff) |
| 2026-01-09 | 1.2 | Added E1 Arbiter Collusion mitigation (7-of-11 quorum, stake requirements), E2 Confirmation Collusion Ring prevention, E9 Reputation Grinding prevention with TPM binding |
| 2026-01-09 | 1.1 | Added Trust Level Prerequisites, Deterministic Judge Selection, False Accusation Protection, cross-references to security-trust.md sections 14-17 |
| 2025-12-30 | 1.0 | Initial consolidated document |

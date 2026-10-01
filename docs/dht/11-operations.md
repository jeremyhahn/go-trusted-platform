# Operations

This document consolidates operational aspects of the go-trusted-platform network including genesis protocol, partition handling, telemetry, and planned enhancements.

## Genesis Protocol

### Network Bootstrap Sequence

The genesis block creates the entire coin supply and establishes the initial network state.

**Genesis Block Structure:**
```
Genesis Block #0
|- Timestamp: Network launch date/time (UTC)
|- Previous Hash: 0x00...00 (64 zeros)
|- Merkle Root: Root of genesis transactions
|- Difficulty: 1 (minimum)
|- Nonce: 0
|- Transactions:
    |- Coinbase Transaction (creates 100M coins)
    |- Foundation Allocation (10M coins)
    |- Treasury Allocation (15M coins)
    |- Service Rewards Pool (75M coins)
```

### Initial State Setup

**Total Supply Characteristics:**
- Maximum Supply: 100,000,000 coins (hard cap, immutable)
- Precision: 8 decimal places
- Smallest Unit: 1 satoshi = 0.00000001 coin
- Total Satoshis: 10^16 (10 quadrillion)

**Genesis Transactions:**

| Transaction | Amount | Recipient | Vesting |
|-------------|--------|-----------|---------|
| 0: Coinbase | 100M | Genesis address | N/A |
| 1: Foundation | 10M | Foundation multi-sig (3-of-5) | None |
| 2: Treasury | 15M | Treasury multi-sig (5-of-9) | None |
| 3: Rewards Pool | 75M | Protocol-controlled address | Halving schedule |

### Initial Coin Distribution

**Emission Schedule with Halving:**

| Period | Years | Annual Emission | Period Total | Cumulative | % Released |
|--------|-------|-----------------|--------------|------------|------------|
| 0 | 0-2 | 18,750,000 | 37,500,000 | 37,500,000 | 50.0% |
| 1 | 2-4 | 9,375,000 | 18,750,000 | 56,250,000 | 75.0% |
| 2 | 4-6 | 4,687,500 | 9,375,000 | 65,625,000 | 87.5% |
| 3 | 6-8 | 2,343,750 | 4,687,500 | 70,312,500 | 93.75% |
| 4 | 8-10 | 1,171,875 | 2,343,750 | 72,656,250 | 96.875% |
| 5+ | 10+ | Decreasing | ~2.3M | 75,000,000 | 100% |

**Block Reward Calculation** (assuming 6-second block time):
- Blocks per year: ~5,256,000
- Blocks per 2-year period: ~10,512,000
- Period 0 block reward: 37,500,000 / 10,512,000 = 3.567 coins
- Period 1 block reward: 18,750,000 / 10,512,000 = 1.784 coins

**Block Reward Distribution:**
- 60%: Validator/block producer
- 30%: Service providers (storage, compute, bandwidth)
- 10%: Staking rewards (delegators)

**Transaction Fee Distribution:**
- 70%: Validators
- 15%: Foundation
- 15%: Treasury

### Founding Node Requirements

**Bootstrap Period Criteria** (ends when ALL milestones are met):
1. Active Nodes: >= 10,000 nodes participating in consensus
2. Service Providers: >= 1,000 active providers (storage/compute/bandwidth)
3. Minimum Duration: >= 6 months since genesis block
4. Network Stability: 30-day average uptime >= 99%

**Bootstrap Reward Multiplier:** 2x standard block rewards

**Transition Process:**
1. All milestones met confirmation
2. 14-day transition notice broadcasted
3. Block reward gradually steps down over 7 days
4. Transition to standard emission schedule complete

**Multi-Signature Security:**
- Foundation Wallet: 3-of-5 or 5-of-7 multi-sig
- Treasury Wallet: 5-of-9 multi-sig recommended
- Key Distribution: Geographic and organizational diversity
- Key Rotation: Regular rotation procedures required

---

## Partition Handling

### Partition Detection Mechanisms

The network employs active partition detection through periodic sampling.

**Detection Algorithm:**
```
Every 60 seconds:
    1. Select 1000 random nodes from DHT routing table
    2. Send lightweight ping/health check to each node
    3. Count successful responses within timeout (5 seconds)
    4. Calculate reachability percentage = (responses / 1000) * 100
    5. If reachability < 50%: PARTITION DETECTED
```

### Health Check Endpoint Specifications

The network provides standardized health and readiness endpoints for monitoring node status and partition detection.

**Endpoint Paths:**
- `/health` - Liveness probe (is the process running?)
- `/ready` - Readiness probe (can the node accept traffic?)
- `/metrics` - Prometheus-compatible metrics (includes partition state)

**Health Endpoint Specification (`/health`):**

Purpose: Determines if the node process is alive and responsive.

Response Format:
```json
{
  "status": "healthy|unhealthy",
  "timestamp": "2026-01-10T15:04:05Z",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "checks": {
    "process": {
      "status": "pass",
      "description": "Process is running"
    },
    "memory": {
      "status": "pass|warn|fail",
      "description": "Memory usage within limits",
      "usage_mb": 512,
      "limit_mb": 2048,
      "usage_percent": 25.0
    },
    "goroutines": {
      "status": "pass|warn|fail",
      "description": "Goroutine count within limits",
      "count": 150,
      "limit": 10000
    }
  }
}
```

Response Codes:
- `200 OK`: Node is healthy
- `503 Service Unavailable`: Node is unhealthy (memory exceeded, goroutine leak, etc.)

**Readiness Endpoint Specification (`/ready`):**

Purpose: Determines if the node is ready to accept and process requests.

Response Format:
```json
{
  "status": "ready|not_ready",
  "timestamp": "2026-01-10T15:04:05Z",
  "partition_state": "healthy|degraded|indeterminate|partitioned|split_brain",
  "reachability_percent": 85.2,
  "checks": {
    "dht_connectivity": {
      "status": "pass|fail",
      "description": "Connected to DHT network",
      "peer_count": 1523,
      "min_peers": 10,
      "routing_table_size": 2048
    },
    "coordinator_availability": {
      "status": "pass|fail",
      "description": "Coordinator nodes reachable",
      "reachable_coordinators": 18,
      "total_coordinators": 21,
      "quorum_threshold": 14
    },
    "storage": {
      "status": "pass|warn|fail",
      "description": "Storage available for transactions",
      "available_gb": 45.2,
      "total_gb": 100.0,
      "usage_percent": 54.8
    },
    "tpm": {
      "status": "pass|fail",
      "description": "TPM hardware functional",
      "manufacturer": "Intel",
      "version": "2.0",
      "pcr_banks": ["SHA256", "SHA384"]
    },
    "partition_state": {
      "status": "pass|warn|fail",
      "description": "Network partition status",
      "state": "healthy",
      "reachability": 0.852,
      "last_check": "2026-01-10T15:04:00Z",
      "time_in_state": "3h25m10s"
    }
  }
}
```

Response Codes:
- `200 OK`: Node is ready to accept traffic
- `503 Service Unavailable`: Node is not ready (partitioned, no coordinators, etc.)

**Dependency Checks:**

1. DHT Connectivity Check:
   - Minimum peer count: 10 peers
   - Routing table populated: >= 256 entries
   - Recent peer activity: At least 1 message in last 60 seconds
   - Check timeout: 2 seconds

2. Coordinator Availability Check:
   - Quorum reachable: >= 14 of 21 coordinators responding
   - Response time: < 500ms average
   - Check method: Lightweight heartbeat message
   - Check timeout: 5 seconds

3. Storage Check:
   - Available disk space: >= 10 GB free
   - Write test: Create/delete test file successfully
   - Read test: Verify can read existing data
   - Check timeout: 1 second

4. TPM Check:
   - TPM device accessible: `/dev/tpm0` or `/dev/tpmrm0`
   - TPM version: 2.0 required
   - PCR banks available: SHA256 minimum
   - Quote generation: Can generate quote successfully
   - Check timeout: 3 seconds

5. Partition State Check:
   - Current state: Healthy, Degraded, Indeterminate, Partitioned, or SplitBrain
   - Reachability: Current percentage of reachable nodes
   - Time in state: Duration in current partition state
   - Threshold breaches: Any threshold violations detected

**Startup Delay / Grace Period:**

During node startup, readiness checks are delayed to allow initialization to complete.

Grace Period Configuration:
```go
const (
    // StartupGracePeriod is the time after node start where readiness checks
    // return "not_ready" regardless of actual status
    StartupGracePeriod = 30 * time.Second

    // StartupPhaseTimeout is the maximum time allowed for startup initialization
    // If exceeded, node is marked unhealthy
    StartupPhaseTimeout = 5 * time.Minute

    // MinimumPeersBeforeReady is the minimum peer count required before
    // transitioning from startup to ready state
    MinimumPeersBeforeReady = 10

    // MinimumCoordinatorsBeforeReady is the minimum coordinator count
    // required before accepting transactions
    MinimumCoordinatorsBeforeReady = 11  // Quorum
)

type StartupPhase uint32

const (
    StartupPhaseInit           StartupPhase = iota  // Initializing
    StartupPhaseTPMInit                              // TPM initialization
    StartupPhaseDHTBootstrap                         // Bootstrapping DHT
    StartupPhaseCoordinatorSync                      // Syncing with coordinators
    StartupPhaseReady                                // Ready to accept traffic
)

type StartupStatus struct {
    Phase          StartupPhase
    StartedAt      time.Time
    PhaseStartedAt time.Time
    PeerCount      int
    CoordinatorCount int
}

// IsInGracePeriod checks if node is within startup grace period
func (ss *StartupStatus) IsInGracePeriod() bool {
    return time.Since(ss.StartedAt) < StartupGracePeriod
}

// IsStartupTimedOut checks if startup exceeded maximum allowed time
func (ss *StartupStatus) IsStartupTimedOut() bool {
    return time.Since(ss.StartedAt) > StartupPhaseTimeout &&
           ss.Phase != StartupPhaseReady
}

// CanTransitionToReady checks if node meets readiness criteria
func (ss *StartupStatus) CanTransitionToReady() bool {
    return ss.PeerCount >= MinimumPeersBeforeReady &&
           ss.CoordinatorCount >= MinimumCoordinatorsBeforeReady &&
           !ss.IsInGracePeriod()
}
```

**Grace Period Behavior:**

During startup grace period (first 30 seconds):
- `/health`: Returns `200 OK` (process is alive)
- `/ready`: Returns `503 Service Unavailable` with status "not_ready"
- Reason: "startup_grace_period"
- Transaction submission: Rejected with `ERR_NODE_NOT_READY`

After grace period, normal readiness checks apply.

**Health Check Request Format:**

Clients can request specific check details using query parameters:

```
GET /health?verbose=true
GET /ready?verbose=true&include=dht_connectivity,coordinator_availability
```

Query Parameters:
- `verbose`: Include detailed check information (default: false)
- `include`: Comma-separated list of specific checks to include
- `format`: Response format (json, prometheus) (default: json)

**Metrics Endpoint (`/metrics`):**

Prometheus-compatible metrics including:

```
# HELP node_health_status Node health status (1=healthy, 0=unhealthy)
# TYPE node_health_status gauge
node_health_status 1

# HELP node_ready_status Node readiness status (1=ready, 0=not_ready)
# TYPE node_ready_status gauge
node_ready_status 1

# HELP node_partition_state Current partition state (0=healthy, 1=degraded, 2=indeterminate, 3=partitioned, 4=split_brain)
# TYPE node_partition_state gauge
node_partition_state{state="healthy"} 0

# HELP node_reachability_percent Current network reachability percentage
# TYPE node_reachability_percent gauge
node_reachability_percent 85.2

# HELP node_uptime_seconds Node uptime in seconds
# TYPE node_uptime_seconds counter
node_uptime_seconds 86400

# HELP node_peer_count Number of connected DHT peers
# TYPE node_peer_count gauge
node_peer_count 1523

# HELP node_coordinator_reachable_count Number of reachable coordinators
# TYPE node_coordinator_reachable_count gauge
node_coordinator_reachable_count 18

# HELP node_memory_usage_bytes Current memory usage in bytes
# TYPE node_memory_usage_bytes gauge
node_memory_usage_bytes 536870912

# HELP node_goroutine_count Current number of goroutines
# TYPE node_goroutine_count gauge
node_goroutine_count 150
```

**Health Check Summary Table:**

| Endpoint | Purpose | Grace Period | Status Codes | Update Frequency |
|----------|---------|--------------|--------------|------------------|
| `/health` | Liveness | No grace period | 200, 503 | Real-time |
| `/ready` | Readiness | 30 second grace | 200, 503 | Real-time |
| `/metrics` | Metrics | No grace period | 200 | 10 second scrape |

**Integration with Partition Detection:**

The readiness endpoint integrates with partition detection:

- When partition state changes, `/ready` status updates immediately
- Partitioned state: Returns `503 Service Unavailable`
- Degraded state: Returns `200 OK` with warning in response
- Indeterminate state: Returns `200 OK` with warning (maintains behavior)
- SplitBrain state: Returns `503 Service Unavailable` (loser partition only)

**Monitoring Best Practices:**

1. Liveness Probe: Use `/health` with 5-second timeout
2. Readiness Probe: Use `/ready` with 10-second timeout
3. Metrics Scraping: Scrape `/metrics` every 15 seconds
4. Alert on readiness failures exceeding 2 minutes
5. Alert on health failures immediately (process crash)

**Partition Thresholds:**
- <50% reachability: Partition state triggered
- 50-80% reachability: Degraded state (continue monitoring)
- >80% reachability: Healthy state, begin reconciliation if recovering

**Configuration Parameters:**
```go
const (
    PartitionCheckInterval   = 60 * time.Second   // How often to check reachability
    PartitionThreshold       = 0.50               // <50% = partition detected
    RecoveryThreshold        = 0.80               // >80% = begin reconciliation
    SampleSize               = 1000               // Nodes to sample for reachability
    HealthCheckTimeout       = 5 * time.Second    // Timeout for ping/pong
    TransactionTTL           = 1 * time.Hour      // Expire suspended TXs after 1hr
    ReconciliationStability  = 5 * time.Minute    // Sustain >80% for 5min before merge
    CheckpointInterval       = 1000               // Transactions per checkpoint
)
```

### A6: Partition Detection Hysteresis (SECURITY FIX)

**CRITICAL SECURITY REQUIREMENT**: The 50% split-brain scenario requires special handling to prevent oscillation and ensure deterministic behavior. Without hysteresis, the network can rapidly flip between partition states, causing cascading failures.

#### Problem Statement

**50% Split-Brain Attack:**
1. Attacker causes network partition at exactly 50/50 split
2. Neither partition has majority - both see 50% reachability
3. Both partitions freeze transactions (neither is majority)
4. Legitimate users on both sides are blocked indefinitely
5. Oscillation occurs as reachability fluctuates around threshold

**Issues with Simple Thresholds:**
- At 50.1% vs 49.9% - majority flips on single node failure
- No stability period - rapid state transitions cause issues
- No dead zone - encourages oscillation around threshold

#### Hysteresis State Machine

```go
// HysteresisConfig prevents oscillation in partition detection
// A6: Add partition detection hysteresis (50% split-brain)
type HysteresisConfig struct {
    // Lower bound: must drop BELOW this to enter partition state
    PartitionEnterThreshold float64  // 0.48 (48%)

    // Upper bound: must rise ABOVE this to exit partition state
    PartitionExitThreshold  float64  // 0.52 (52%)

    // Dead zone: 48-52% is "indeterminate" - maintain current state
    DeadZoneLower           float64  // 0.48
    DeadZoneUpper           float64  // 0.52

    // Stability requirements
    StabilityPeriod         time.Duration  // 3 minutes
    StabilityCheckCount     int            // 3 consecutive checks

    // Split-brain detection
    SplitBrainThreshold     float64        // 0.50 exactly
    SplitBrainTolerance     float64        // 0.02 (+/- 2%)
}

// DefaultHysteresisConfig returns production-safe defaults
func DefaultHysteresisConfig() HysteresisConfig {
    return HysteresisConfig{
        PartitionEnterThreshold: 0.48,
        PartitionExitThreshold:  0.52,
        DeadZoneLower:           0.48,
        DeadZoneUpper:           0.52,
        StabilityPeriod:         3 * time.Minute,
        StabilityCheckCount:     3,
        SplitBrainThreshold:     0.50,
        SplitBrainTolerance:     0.02,
    }
}

// PartitionState with hysteresis tracking
type PartitionState uint32

const (
    PartitionStateHealthy       PartitionState = iota  // >52% reachability, stable
    PartitionStateDegraded                              // 48-80%, monitoring
    PartitionStateIndeterminate                         // 48-52%, dead zone
    PartitionStatePartitioned                           // <48% reachability
    PartitionStateSplitBrain                            // Exactly 50% detected
)

// State Transition Matrix
//
// Comprehensive state machine covering ALL possible transitions with conditions.
//
// ┌──────────────────┬──────────────────────────────────────────────────────────────────────────┐
// │ FROM → TO        │ Condition                                                                │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Healthy → Degraded                                                                          │
// │                  │ reachability < RecoveryThreshold (0.80) AND                              │
// │                  │ reachability >= PartitionExitThreshold (0.52)                            │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Healthy → Indeterminate                                                                     │
// │                  │ IMPOSSIBLE - Must transition through Degraded first                      │
// │                  │ (Prevented by shouldTransition() anti-skip rule)                         │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Healthy → Partitioned                                                                       │
// │                  │ reachability < 0.40 (severe drop bypass) OR                              │
// │                  │ reachability < PartitionEnterThreshold (0.48) AND                        │
// │                  │ rapid degradation detected                                               │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Healthy → SplitBrain                                                                        │
// │                  │ |reachability - 0.50| <= SplitBrainTolerance (0.02) AND                  │
// │                  │ isSplitBrain() returns true                                              │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Degraded → Healthy                                                                          │
// │                  │ reachability >= RecoveryThreshold (0.80) AND                             │
// │                  │ isStable(PartitionStateHealthy) returns true AND                         │
// │                  │ time.Since(lastStateChange) >= StabilityPeriod (3 min)                   │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Degraded → Indeterminate                                                                    │
// │                  │ isInDeadZone(reachability) returns true AND                              │
// │                  │ 0.48 <= reachability <= 0.52                                             │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Degraded → Partitioned                                                                      │
// │                  │ reachability < PartitionEnterThreshold (0.48)                            │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Degraded → SplitBrain                                                                       │
// │                  │ isSplitBrain(reachability) returns true                                  │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Indeterminate → Healthy                                                                     │
// │                  │ IMPOSSIBLE - Must transition through Degraded first                      │
// │                  │ reachability > DeadZoneUpper (0.52) requires Degraded intermediate       │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Indeterminate → Degraded                                                                    │
// │                  │ reachability > DeadZoneUpper (0.52) AND                                  │
// │                  │ isStable(PartitionStateDegraded) returns true AND                        │
// │                  │ time.Since(lastStateChange) >= StabilityPeriod (3 min)                   │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Indeterminate → Indeterminate                                                               │
// │                  │ 0.48 <= reachability <= 0.52 (remain in dead zone) AND                   │
// │                  │ NO stable exit signal for 3+ consecutive measurements                    │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Indeterminate → Partitioned                                                                 │
// │                  │ reachability < DeadZoneLower (0.48)                                      │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Indeterminate → SplitBrain                                                                  │
// │                  │ isSplitBrain(reachability) returns true (within dead zone)               │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Partitioned → Healthy                                                                       │
// │                  │ IMPOSSIBLE - Must transition through Degraded first                      │
// │                  │ Requires isStable() checks prevent direct jump                           │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Partitioned → Degraded                                                                      │
// │                  │ reachability > PartitionExitThreshold (0.52) AND                         │
// │                  │ isStable(PartitionStateDegraded) returns true AND                        │
// │                  │ time.Since(lastStateChange) >= StabilityPeriod (3 min) AND               │
// │                  │ 3 consecutive measurements in degraded range                             │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Partitioned → Indeterminate                                                                 │
// │                  │ RARE: reachability rises into dead zone (0.48-0.52) from below           │
// │                  │ Remain in Partitioned unless crosses PartitionExitThreshold              │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Partitioned → Partitioned                                                                   │
// │                  │ reachability < PartitionExitThreshold (0.52) AND                         │
// │                  │ NOT isSplitBrain()                                                       │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ Partitioned → SplitBrain                                                                    │
// │                  │ isSplitBrain(reachability) returns true                                  │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ SplitBrain → Healthy                                                                        │
// │                  │ IMPOSSIBLE - Must resolve split-brain, transition through Degraded       │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ SplitBrain → Degraded                                                                       │
// │                  │ determineSplitBrainWinner() selects this partition as winner AND         │
// │                  │ reachability > 0.52 (exited dead zone upward)                            │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ SplitBrain → Indeterminate                                                                  │
// │                  │ !isSplitBrain(reachability) AND                                          │
// │                  │ isInDeadZone(reachability) AND                                           │
// │                  │ split-brain condition resolved but still in dead zone                    │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ SplitBrain → Partitioned                                                                    │
// │                  │ determineSplitBrainWinner() selects OTHER partition as winner OR         │
// │                  │ !isSplitBrain() AND reachability < 0.48                                  │
// ├──────────────────┼──────────────────────────────────────────────────────────────────────────┤
// │ SplitBrain → SplitBrain                                                                     │
// │                  │ isSplitBrain(reachability) returns true AND                              │
// │                  │ determineSplitBrainWinner() not yet completed                            │
// └──────────────────┴──────────────────────────────────────────────────────────────────────────┘
//
// OSCILLATION HANDLING: Degraded ↔ Indeterminate
//
// When reachability oscillates around the dead zone boundaries (48% and 52%):
//
// 1. Entry into Indeterminate from Degraded:
//    - Triggered when reachability drops into dead zone (48-52%)
//    - MAINTAINS current operational behavior (do NOT change transaction policy)
//    - Logs entry: "entering indeterminate state, maintaining degraded behavior"
//
// 2. Behavior while in Indeterminate:
//    - Continue monitoring reachability every 60 seconds
//    - Increment oscillation counter if state would change again within 3 minutes
//    - If oscillation counter >= 3: Trigger stabilization mode (10 min freeze)
//    - NO transaction policy changes while oscillating
//
// 3. Exit from Indeterminate:
//    a) Upward exit (to Degraded): Requires isStable() check
//       - 3 consecutive measurements > 0.52
//       - 3 minutes minimum time in current state
//       - Resets oscillation counter on successful stable exit
//
//    b) Downward exit (to Partitioned): Immediate
//       - Single measurement < 0.48 triggers immediate transition
//       - Freezes transactions (enters Partitioned mode)
//       - Logs: "rapid degradation from indeterminate to partitioned"
//
// 4. Oscillation Mitigation:
//    - After 3 oscillations within 1 hour: Enter stabilization mode
//    - Stabilization mode: Freeze state machine for 10 minutes
//    - During stabilization: Continue monitoring but suppress transitions
//    - Log all would-be transitions for debugging
//
// SPLIT-BRAIN RECOVERY: Reachability in Dead Zone (48-52%)
//
// When recovering from split-brain state with reachability oscillating in dead zone:
//
// 1. Split-Brain Detection Exit:
//    - When |reachability - 0.50| > SplitBrainTolerance (0.02)
//    - Split-brain flag cleared: splitBrainDetected = false
//    - Check if still in dead zone (0.48-0.52)
//
// 2. Transition Path from SplitBrain:
//    a) If reachability > 0.52 (exited upward):
//       - Transition to Degraded (winner partition behavior)
//       - Requires determineSplitBrainWinner() completed
//       - Apply winning partition's transaction log
//
//    b) If 0.48 <= reachability <= 0.52 (still in dead zone):
//       - Transition to Indeterminate
//       - CRITICAL: Maintain split-brain resolution decision
//       - If this partition was winner: Allow transactions (degraded mode)
//       - If this partition was loser: Freeze transactions (partitioned mode)
//       - Wait for stable exit from dead zone before full reconciliation
//
//    c) If reachability < 0.48 (exited downward):
//       - Transition to Partitioned
//       - Freeze all transactions
//       - Log: "split-brain recovery failed, entered partition state"
//
// 3. Dead Zone Behavior After Split-Brain:
//    - Record split-brain winner decision in persistent state
//    - Apply winner's behavior even while in Indeterminate
//    - Prevents flip-flopping between winner/loser behavior
//    - Example:
//      ```go
//      if ht.inDeadZoneAfterSplitBrain {
//          if ht.wasWinningPartition {
//              return PartitionStateDegraded  // Allow transactions
//          } else {
//              return PartitionStatePartitioned  // Freeze transactions
//          }
//      }
//      ```
//
// 4. Full Recovery Requirements:
//    - Must sustain reachability > 0.52 for 3 minutes (exit dead zone upward)
//    - Complete gray zone reconciliation protocol
//    - Verify no conflicts remain before resuming normal operation
//    - Transition: SplitBrain → Indeterminate → Degraded → Healthy
//
// 5. Timeout Protection:
//    - Maximum time in dead zone after split-brain: 10 minutes
//    - If exceeded: Force transition to Partitioned
//    - Trigger manual intervention alert
//    - Prevents indefinite oscillation in edge cases

// HysteresisTracker maintains state with oscillation prevention
type HysteresisTracker struct {
    currentState      PartitionState
    stateFlag         uint32             // Atomic state access
    config            HysteresisConfig

    // Stability tracking
    reachabilityHistory []float64        // Last N measurements
    stateHistory        []PartitionState // Last N states
    lastStateChange     time.Time
    consecutiveStable   int

    // Split-brain detection
    splitBrainDetected  bool
    splitBrainStartTime time.Time
    peerPartitionSize   float64          // Estimated size of other partition

    // Metrics
    metrics             *HysteresisMetrics
    mu                  sync.RWMutex
}

// HysteresisMetrics for monitoring
type HysteresisMetrics struct {
    StateTransitions      uint64
    OscillationsPrevented uint64
    SplitBrainEvents      uint64
    DeadZoneTime          time.Duration
    AverageReachability   float64
}
```

#### Hysteresis State Transition Logic

```go
// EvaluateReachability determines partition state with hysteresis
func (ht *HysteresisTracker) EvaluateReachability(reachability float64) (PartitionState, error) {
    ht.mu.Lock()
    defer ht.mu.Unlock()

    // Record measurement
    ht.reachabilityHistory = append(ht.reachabilityHistory, reachability)
    if len(ht.reachabilityHistory) > 10 {
        ht.reachabilityHistory = ht.reachabilityHistory[1:]
    }

    currentState := PartitionState(atomic.LoadUint32(&ht.stateFlag))
    newState := currentState

    // Check for split-brain condition first
    if ht.isSplitBrain(reachability) {
        newState = PartitionStateSplitBrain
        if !ht.splitBrainDetected {
            ht.splitBrainDetected = true
            ht.splitBrainStartTime = time.Now()
            atomic.AddUint64(&ht.metrics.SplitBrainEvents, 1)
        }
        return ht.handleSplitBrain(reachability)
    }

    ht.splitBrainDetected = false

    // Apply hysteresis based on current state
    switch currentState {
    case PartitionStateHealthy:
        // Only transition DOWN if we drop below partition ENTER threshold
        if reachability < ht.config.PartitionEnterThreshold {
            newState = PartitionStatePartitioned
        } else if reachability < ht.config.RecoveryThreshold {
            newState = PartitionStateDegraded
        }

    case PartitionStateDegraded:
        if reachability < ht.config.PartitionEnterThreshold {
            newState = PartitionStatePartitioned
        } else if reachability >= ht.config.RecoveryThreshold {
            // Require stability before transitioning to healthy
            if ht.isStable(PartitionStateHealthy) {
                newState = PartitionStateHealthy
            }
        } else if ht.isInDeadZone(reachability) {
            newState = PartitionStateIndeterminate
        }

    case PartitionStateIndeterminate:
        // In dead zone - maintain current behavior until clear signal
        if reachability < ht.config.DeadZoneLower {
            newState = PartitionStatePartitioned
        } else if reachability > ht.config.DeadZoneUpper {
            // Require stability before leaving dead zone upward
            if ht.isStable(PartitionStateDegraded) {
                newState = PartitionStateDegraded
            }
        }
        // Stay indeterminate if still in dead zone

    case PartitionStatePartitioned:
        // Only transition UP if we rise above partition EXIT threshold
        if reachability > ht.config.PartitionExitThreshold {
            // Require stability before exiting partition state
            if ht.isStable(PartitionStateDegraded) {
                newState = PartitionStateDegraded
            }
        }

    case PartitionStateSplitBrain:
        // Handled above, but if we somehow get here
        if !ht.isSplitBrain(reachability) {
            newState = PartitionStateIndeterminate
        }
    }

    // Apply state change if different and stable
    if newState != currentState {
        if ht.shouldTransition(currentState, newState) {
            ht.transitionState(newState)
        } else {
            newState = currentState // Suppress oscillation
            atomic.AddUint64(&ht.metrics.OscillationsPrevented, 1)
        }
    }

    return PartitionState(atomic.LoadUint32(&ht.stateFlag)), nil
}

// isInDeadZone checks if reachability is in the 48-52% dead zone
func (ht *HysteresisTracker) isInDeadZone(reachability float64) bool {
    return reachability >= ht.config.DeadZoneLower &&
           reachability <= ht.config.DeadZoneUpper
}

// isSplitBrain detects 50/50 split condition
func (ht *HysteresisTracker) isSplitBrain(reachability float64) bool {
    return math.Abs(reachability - ht.config.SplitBrainThreshold) <= ht.config.SplitBrainTolerance
}

// isStable checks if we've had consistent readings for stability period
func (ht *HysteresisTracker) isStable(targetState PartitionState) bool {
    if len(ht.reachabilityHistory) < ht.config.StabilityCheckCount {
        return false
    }

    // Check time-based stability
    if time.Since(ht.lastStateChange) < ht.config.StabilityPeriod {
        return false
    }

    // Check measurement consistency
    recent := ht.reachabilityHistory[len(ht.reachabilityHistory)-ht.config.StabilityCheckCount:]
    for _, r := range recent {
        if !ht.measurementSupportsState(r, targetState) {
            return false
        }
    }

    return true
}

// shouldTransition applies anti-oscillation rules
func (ht *HysteresisTracker) shouldTransition(from, to PartitionState) bool {
    // Minimum time between transitions (anti-flapping)
    if time.Since(ht.lastStateChange) < 60*time.Second {
        return false
    }

    // Don't allow direct healthy -> partitioned without passing through degraded
    if from == PartitionStateHealthy && to == PartitionStatePartitioned {
        // Allow only if severe drop (< 40%)
        if len(ht.reachabilityHistory) > 0 {
            latest := ht.reachabilityHistory[len(ht.reachabilityHistory)-1]
            if latest >= 0.40 {
                return false // Force transition through degraded
            }
        }
    }

    return true
}

// transitionState performs atomic state change with metrics
func (ht *HysteresisTracker) transitionState(newState PartitionState) {
    oldState := PartitionState(atomic.LoadUint32(&ht.stateFlag))
    atomic.StoreUint32(&ht.stateFlag, uint32(newState))
    ht.currentState = newState
    ht.lastStateChange = time.Now()
    ht.consecutiveStable = 0
    atomic.AddUint64(&ht.metrics.StateTransitions, 1)

    // Log transition for audit
    logPartitionTransition(oldState, newState, ht.reachabilityHistory)
}
```

#### Split-Brain Resolution Protocol

```go
// handleSplitBrain implements deterministic resolution for 50/50 splits
func (ht *HysteresisTracker) handleSplitBrain(reachability float64) (PartitionState, error) {
    // In split-brain, neither partition can claim majority
    // Resolution strategy: deterministic leader election

    // Step 1: Exchange partition membership with other partition
    otherPartitionInfo := ht.discoverOtherPartition()

    // Step 2: Deterministic winner selection (cannot rely on size)
    winner := ht.determineSplitBrainWinner(otherPartitionInfo)

    if winner == localPartitionID {
        // We are the canonical partition - continue operating in degraded mode
        // but with transaction freeze for safety
        return PartitionStateDegraded, nil
    }

    // Other partition is canonical - we must freeze and wait for merge
    return PartitionStatePartitioned, nil
}

// SplitBrainResolutionCriteria defines the tiebreaker order
type SplitBrainResolutionCriteria struct {
    // Primary: Partition with more coordinator nodes wins
    CoordinatorCount int

    // Secondary: Partition with higher total stake wins
    TotalStake uint64

    // Tertiary: Partition with lower hash of member NodeIDs wins
    MembershipHash [32]byte

    // Quaternary: Partition with node holding genesis key wins
    HasGenesisKey bool
}

// determineSplitBrainWinner applies deterministic tiebreaker rules
func (ht *HysteresisTracker) determineSplitBrainWinner(
    otherPartition *PartitionInfo,
) PartitionID {
    local := ht.getLocalPartitionCriteria()
    remote := otherPartition.Criteria

    // Rule 1: More coordinator nodes wins
    if local.CoordinatorCount != remote.CoordinatorCount {
        if local.CoordinatorCount > remote.CoordinatorCount {
            return localPartitionID
        }
        return otherPartition.ID
    }

    // Rule 2: Higher total stake wins
    if local.TotalStake != remote.TotalStake {
        if local.TotalStake > remote.TotalStake {
            return localPartitionID
        }
        return otherPartition.ID
    }

    // Rule 3: Genesis key holder wins
    if local.HasGenesisKey && !remote.HasGenesisKey {
        return localPartitionID
    }
    if remote.HasGenesisKey && !local.HasGenesisKey {
        return otherPartition.ID
    }

    // Rule 4: Lower membership hash wins (deterministic random)
    if bytes.Compare(local.MembershipHash[:], remote.MembershipHash[:]) < 0 {
        return localPartitionID
    }
    return otherPartition.ID
}
```

#### Hysteresis Visualization

```
                    PARTITION STATE HYSTERESIS

  100% ─┬─────────────────────────────────────────────────
        │                    HEALTHY
   80% ─┼─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
        │                    DEGRADED
        │     ┌────────────────────────────────────┐
   52% ─┼─────┤  EXIT threshold (rising edge)      │─────
        │     │                                    │
   50% ─┼─────┤  DEAD ZONE (indeterminate)         │─────
        │     │  Split-brain detection zone        │
   48% ─┼─────┤  ENTER threshold (falling edge)    │─────
        │     └────────────────────────────────────┘
        │                  PARTITIONED
    0% ─┴─────────────────────────────────────────────────

        State transitions require:
        1. Crossing threshold (not just touching)
        2. 3 consecutive readings in target zone
        3. 3 minutes stability in current state
        4. Anti-oscillation cooldown (60s between transitions)
```

#### Split-Brain Handling Summary

| Scenario | Detection | Resolution |
|----------|-----------|------------|
| **Clear Majority** (>52%) | Normal operation | N/A |
| **Clear Minority** (<48%) | Partition detected | Freeze transactions |
| **Dead Zone** (48-52%) | Indeterminate state | Maintain current state |
| **Exact 50/50** | Split-brain | Deterministic tiebreaker |
| **Oscillating** | Hysteresis active | Suppress rapid transitions |

**Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No oscillation | Max 1 transition per 60s | Anti-flapping cooldown |
| Deterministic resolution | Same inputs → same winner | Tiebreaker rules |
| Safety in dead zone | No risky transitions | Maintain current state |
| Split-brain detection | 48-52% identified | Tolerance window |
| Audit trail | All transitions logged | logPartitionTransition |

---

### Operations During Partition

**Majority Partition (>= 51% reachability):**
- Transaction submission: ALLOWED
- Transaction confirmation: ALLOWED
- Checkpoint creation: ALLOWED
- DHT read/write: ALLOWED

**Minority Partition (< 51% reachability):**
- Transaction submission: REJECTED (return error)
- Transaction confirmation: SUSPENDED
- Checkpoint creation: SUSPENDED
- DHT read: ALLOWED
- DHT write: ALLOWED (non-currency data only)

**Transaction Queue Management:**
- Pending Queue: Transactions submitted but not confirmed - move to suspended on freeze
- Suspended Queue: Transactions held during partition - track original timestamp, expire after TTL (1 hour)
- Confirmed Queue: Transactions confirmed before partition - remain confirmed, subject to conflict resolution

**Client Error Response:**
```json
{
  "error": "partition_freeze",
  "message": "Node is in minority partition, transactions suspended",
  "partition_state": "MINORITY",
  "reachability": 0.35,
  "estimated_recovery": "unknown"
}
```

### Partition Reconciliation

**DAG Merge Protocol** (triggered when reachability exceeds 80% for 5 minutes):

1. **Exchange DAG Tips**: Each partition broadcasts current DAG tips
2. **Identify Common Ancestor**: Traverse DAG backward to find last shared checkpoint
3. **Replay Transactions**: Collect and sort all transactions by TPM timestamp
4. **Reject Conflicts**: Apply first-seen wins rule, detect double-spends
5. **Rebuild Checkpoints**: Recompute Merkle roots from merged state
6. **Broadcast Reconciled State**: Propagate merged DAG to all nodes

**Checkpoint Reconciliation Strategy:**
- Higher sequence number wins
- Verify Merkle root, signature, sequence continuity, and parent hash before accepting
- If Merkle roots differ at same sequence: request full history, replay, and rebuild

### Conflict Resolution

**Resolution Rules:**
1. **First-seen wins**: Transaction with earlier TPM monotonic counter value is canonical
2. **Timestamp tie-breaker**: Lower transaction ID wins (lexicographic comparison)
3. **Double-spend handling**: Reject BOTH transactions, return funds to sender, log for audit

```go
func DetectConflict(tx1, tx2 Transaction) bool {
    for _, input1 := range tx1.Inputs {
        for _, input2 := range tx2.Inputs {
            if input1.UTXO == input2.UTXO {
                return true  // Double-spend detected
            }
        }
    }
    return false
}

func ResolveConflict(tx1, tx2 Transaction) Transaction {
    if tx1.TPMCounter < tx2.TPMCounter {
        return tx1
    }
    if tx1.TPMCounter > tx2.TPMCounter {
        return tx2
    }
    if tx1.ID < tx2.ID {
        return tx1
    }
    return tx2
}
```

**Edge Cases:**
- Three-way partition: Largest segment (>51%) is canonical, others merge into it
- Simultaneous double-spend: Apply tie-breaker rule, reject higher ID
- Checkpoint sequence gap: Discard minority checkpoint, accept majority's
- Cascading partitions: Complete first reconciliation before handling second
- Byzantine node during reconciliation: Verify all DAG tips against TPM attestations

### Three-Way Partition Handling - FINAL DESIGN

When the network fragments into three or more partitions, special handling is required since no partition may have >50% of coordinators.

**VRF-Based Canonical Selection:**

If no partition has a majority (>50% of 21 coordinators = >10), use VRF to select canonical partition deterministically.

```go
// Three-way partition handler
type ThreeWayPartitionResolver struct {
    partitions []*PartitionInfo
}

// SelectCanonicalPartition determines which partition is canonical
func (tpr *ThreeWayPartitionResolver) SelectCanonicalPartition() (*PartitionInfo, error) {
    // Step 1: Check if any partition has majority
    for _, partition := range tpr.partitions {
        if partition.CoordinatorCount > 10 { // >50% of 21
            return partition, nil // Majority wins
        }
    }

    // Step 2: No majority - use VRF selection
    // Each partition coordinator computes VRF(partition_id, epoch)
    var lowestVRFOutput [32]byte
    var selectedPartition *PartitionInfo

    for i := 0; i < 32; i++ {
        lowestVRFOutput[i] = 0xFF // Start with max value
    }

    for _, partition := range tpr.partitions {
        // VRF computation using partition ID and current epoch
        vrfOutput := partition.ComputeVRF(getCurrentEpoch())

        if bytes.Compare(vrfOutput[:], lowestVRFOutput[:]) < 0 {
            lowestVRFOutput = vrfOutput
            selectedPartition = partition
        }
    }

    log.Info("three-way partition resolved via VRF",
        "selectedPartitionID", hex.EncodeToString(selectedPartition.ID[:8]),
        "coordinatorCount", selectedPartition.CoordinatorCount)

    return selectedPartition, nil
}

// PartitionInfo with VRF computation
type PartitionInfo struct {
    ID               [32]byte
    CoordinatorCount int
    Coordinators     [][32]byte
    CurrentEpoch     uint64
}

// ComputeVRF produces deterministic random output for partition selection
func (pi *PartitionInfo) ComputeVRF(epoch uint64) [32]byte {
    h := sha256.New()
    h.Write(pi.ID[:])
    binary.Write(h, binary.BigEndian, epoch)
    return sha256.Sum256(h.Sum(nil))
}
```

**Non-Canonical Partition Behavior:**

All partitions that are not selected as canonical enter read-only mode:

- No new transactions accepted
- No role promotions
- DHT reads allowed, writes rejected
- Monitor for reconnection to canonical partition

**Healing Process:**

When partitions reconnect:
1. All non-canonical partitions sync state from canonical partition
2. Canonical partition chain state is replayed on non-canonical partitions
3. Conflicting local state on non-canonical partitions is discarded
4. After sync complete, all partitions resume normal operation

### A4: Partition Gray Zone Protection (SECURITY FIX)

**CRITICAL SECURITY REQUIREMENT**: During partition recovery, there's a "gray zone" period where conflicting transactions may have been committed on both sides. This section specifies the freeze-reconcile-resume protocol to prevent double-spend attacks during recovery.

#### Problem Statement

**Gray zone double-spend attack:**
1. Partition occurs, Alice is in majority, Bob in minority
2. Alice sends 100 coins to Charlie (commits on majority side)
3. Alice also sends same 100 coins to Dave (commits on minority side during partition)
4. Partition heals, gray zone begins
5. Without proper handling, both transactions could be accepted briefly

#### Partition Recovery State Machine

```go
// PartitionRecoveryState tracks recovery through gray zone
type PartitionRecoveryState uint32

const (
    PartitionStateNormal         PartitionRecoveryState = iota  // No partition
    PartitionStatePartitioned                                    // Active partition
    PartitionStateHealing                                        // >80% reachability detected
    PartitionStateGrayZone                                       // Freeze period for reconciliation
    PartitionStateReconciling                                    // Active DAG merge
    PartitionStateValidating                                     // Validating reconciled state
    PartitionStateResuming                                       // Transitioning back to normal
)

// Gray zone constants - NOT configurable (security critical)
const (
    GrayZoneFreezeMinDuration = 30 * time.Second   // Minimum freeze period
    GrayZoneMaxDuration       = 5 * time.Minute    // Maximum gray zone before forced resolution
    ReconciliationStability   = 5 * time.Minute    // Required stability before unfreezing
    MinConfirmationsForUnfreeze = 10               // Minimum epoch confirmations

    // SECURITY FIX (P5-H8): View change circuit breaker constants
    MaxConsecutiveViewChanges = 7                   // Max view changes before forced abort
    ViewChangeCooldown        = 30 * time.Second   // Minimum time between view changes
    CircuitBreakerReset       = 10 * time.Minute   // Time to reset circuit breaker counter
)

// ViewChangeCircuitBreaker prevents livelock from repeated view changes
// SECURITY FIX (P5-H8): Without this, malicious nodes can trigger endless view changes
type ViewChangeCircuitBreaker struct {
    consecutiveChanges  uint32            // Atomic counter
    lastChangeTime      int64             // Unix nano timestamp (atomic)
    lastResetTime       int64             // When counter was last reset
    tripCount           uint32            // Number of times breaker has tripped
    state               uint32            // 0=closed (normal), 1=open (blocked)
    mu                  sync.Mutex        // For non-atomic operations
}

// TryViewChange attempts a view change, returns error if circuit breaker is open
func (cb *ViewChangeCircuitBreaker) TryViewChange() error {
    now := time.Now().UnixNano()

    // Check if circuit breaker should reset (10 minutes of stability)
    lastReset := atomic.LoadInt64(&cb.lastResetTime)
    if now-lastReset > int64(CircuitBreakerReset) {
        cb.reset(now)
    }

    // Check if circuit breaker is open (tripped)
    if atomic.LoadUint32(&cb.state) == 1 {
        return ErrViewChangeCircuitBreakerOpen{
            ConsecutiveChanges: atomic.LoadUint32(&cb.consecutiveChanges),
            MaxAllowed:         MaxConsecutiveViewChanges,
            CooldownRemaining:  cb.remainingCooldown(),
        }
    }

    // Check cooldown between view changes
    lastChange := atomic.LoadInt64(&cb.lastChangeTime)
    if now-lastChange < int64(ViewChangeCooldown) {
        return ErrViewChangeTooFrequent{
            MinInterval:       ViewChangeCooldown,
            TimeSinceLast:     time.Duration(now - lastChange),
        }
    }

    // Increment counter and check threshold
    count := atomic.AddUint32(&cb.consecutiveChanges, 1)
    atomic.StoreInt64(&cb.lastChangeTime, now)

    if count >= MaxConsecutiveViewChanges {
        // Trip the circuit breaker
        atomic.StoreUint32(&cb.state, 1)
        atomic.AddUint32(&cb.tripCount, 1)

        log.Error("view change circuit breaker TRIPPED",
            "consecutiveChanges", count,
            "maxAllowed", MaxConsecutiveViewChanges,
            "tripCount", atomic.LoadUint32(&cb.tripCount))

        // Alert operators for manual intervention
        alertCircuitBreakerTripped(cb)

        return ErrViewChangeCircuitBreakerTripped{
            ConsecutiveChanges: count,
            Action:             "consensus aborted - manual intervention required",
        }
    }

    log.Warn("view change accepted, approaching limit",
        "current", count,
        "max", MaxConsecutiveViewChanges,
        "remaining", MaxConsecutiveViewChanges-count)

    return nil
}

// RecordSuccessfulConsensus resets the counter after successful consensus
func (cb *ViewChangeCircuitBreaker) RecordSuccessfulConsensus() {
    atomic.StoreUint32(&cb.consecutiveChanges, 0)
    // Note: Don't reset the breaker state - that requires operator action
}

// reset clears the counter (called after CircuitBreakerReset period of stability)
func (cb *ViewChangeCircuitBreaker) reset(now int64) {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    // Double-check inside lock
    lastReset := atomic.LoadInt64(&cb.lastResetTime)
    if now-lastReset < int64(CircuitBreakerReset) {
        return
    }

    atomic.StoreUint32(&cb.consecutiveChanges, 0)
    atomic.StoreInt64(&cb.lastResetTime, now)
    // Note: tripCount is NOT reset - it's a lifetime counter
}

func (cb *ViewChangeCircuitBreaker) remainingCooldown() time.Duration {
    lastChange := atomic.LoadInt64(&cb.lastChangeTime)
    elapsed := time.Duration(time.Now().UnixNano() - lastChange)
    if elapsed >= ViewChangeCooldown {
        return 0
    }
    return ViewChangeCooldown - elapsed
}

// ManualResetCircuitBreaker allows operators to reset after investigation
// Requires operator signature verification
func (cb *ViewChangeCircuitBreaker) ManualResetCircuitBreaker(operatorSig []byte) error {
    if !verifyOperatorSignature(operatorSig) {
        return ErrUnauthorizedCircuitBreakerReset
    }

    cb.mu.Lock()
    defer cb.mu.Unlock()

    atomic.StoreUint32(&cb.state, 0)  // Close breaker
    atomic.StoreUint32(&cb.consecutiveChanges, 0)
    atomic.StoreInt64(&cb.lastResetTime, time.Now().UnixNano())

    log.Info("circuit breaker manually reset by operator")
    return nil
}

// ErrViewChangeCircuitBreakerOpen indicates breaker is open
type ErrViewChangeCircuitBreakerOpen struct {
    ConsecutiveChanges uint32
    MaxAllowed         uint32
    CooldownRemaining  time.Duration
}

func (e ErrViewChangeCircuitBreakerOpen) Error() string {
    return fmt.Sprintf("view change circuit breaker open: %d consecutive changes (max %d)",
        e.ConsecutiveChanges, e.MaxAllowed)
}

// ErrViewChangeCircuitBreakerTripped indicates breaker just tripped
type ErrViewChangeCircuitBreakerTripped struct {
    ConsecutiveChanges uint32
    Action             string
}

func (e ErrViewChangeCircuitBreakerTripped) Error() string {
    return fmt.Sprintf("view change circuit breaker TRIPPED after %d changes: %s",
        e.ConsecutiveChanges, e.Action)
}

// ErrViewChangeTooFrequent indicates view changes are happening too fast
type ErrViewChangeTooFrequent struct {
    MinInterval   time.Duration
    TimeSinceLast time.Duration
}

func (e ErrViewChangeTooFrequent) Error() string {
    return fmt.Sprintf("view change too frequent: %v since last, minimum %v required",
        e.TimeSinceLast, e.MinInterval)
}
)

// PartitionRecoveryManager handles gray zone protection
type PartitionRecoveryManager struct {
    currentState      PartitionRecoveryState
    stateFlag         uint32              // ATOMIC for thread-safe state checks
    grayZoneStartTime time.Time
    frozenTransactions map[TxID]*FrozenTransaction
    conflictLog       *ConflictLog
    mu                sync.RWMutex
}

// FrozenTransaction holds transaction during gray zone
type FrozenTransaction struct {
    Transaction   *Transaction
    FrozenAt      time.Time
    OriginalShard uint16
    Resolution    *ConflictResolution
}
```

#### Gray Zone Freeze Protocol

```go
// SECURITY FIX (P5-H9): VRF-based initiator selection to prevent conflict
// When partition heals, both sides could try to initiate gray zone.
// VRF selection ensures only one deterministic initiator.

// GrayZoneInitiatorSelection determines which node initiates recovery
type GrayZoneInitiatorSelection struct {
    PartitionID      [32]byte   // Hash of partition event
    HealingTimestamp time.Time  // When >80% reachability detected
    CandidateNodes   [][32]byte // Nodes that detected healing
    SelectedNode     [32]byte   // VRF-selected initiator
    VRFProof         []byte     // Proof of selection
    Verified         bool       // Selection has been verified
}

// selectGrayZoneInitiator uses VRF to deterministically select single initiator
// SECURITY FIX (P5-H9): Prevents both partitions from trying to initiate
func selectGrayZoneInitiator(
    partitionID [32]byte,
    healingTime time.Time,
    candidates [][32]byte,
) (*GrayZoneInitiatorSelection, error) {
    if len(candidates) == 0 {
        return nil, ErrNoCandidatesForGrayZone
    }

    // Create deterministic seed from partition event
    seed := computeGrayZoneSeed(partitionID, healingTime)

    // Each candidate computes VRF output with their private key
    // The candidate with the lowest VRF output is selected
    var lowestOutput [32]byte
    var selectedNode [32]byte
    var selectedProof []byte

    for i := 0; i < 32; i++ {
        lowestOutput[i] = 0xFF // Start with max value
    }

    for _, nodeID := range candidates {
        vrfOutput, proof, err := computeVRF(nodeID, seed)
        if err != nil {
            continue // Skip nodes that can't compute VRF
        }

        if bytes.Compare(vrfOutput[:], lowestOutput[:]) < 0 {
            lowestOutput = vrfOutput
            selectedNode = nodeID
            selectedProof = proof
        }
    }

    return &GrayZoneInitiatorSelection{
        PartitionID:      partitionID,
        HealingTimestamp: healingTime,
        CandidateNodes:   candidates,
        SelectedNode:     selectedNode,
        VRFProof:         selectedProof,
        Verified:         true,
    }, nil
}

// computeGrayZoneSeed creates deterministic seed for initiator selection
func computeGrayZoneSeed(partitionID [32]byte, healingTime time.Time) []byte {
    h := sha256.New()
    h.Write(partitionID[:])
    binary.Write(h, binary.BigEndian, healingTime.Unix())
    h.Write([]byte("gray_zone_initiator_selection"))
    return h.Sum(nil)
}

// enterGrayZone initiates the freeze period for reconciliation
// SECURITY FIX (P5-H9): Now requires VRF-based initiator selection
func (prm *PartitionRecoveryManager) enterGrayZone(ctx context.Context) error {
    // Step 0: Verify this node is the VRF-selected initiator
    if !prm.isSelectedInitiator() {
        return ErrNotSelectedInitiator{
            SelectedNode: prm.initiatorSelection.SelectedNode,
            LocalNode:    localNodeID,
        }
    }

    // Atomic transition to gray zone
    if !atomic.CompareAndSwapUint32(&prm.stateFlag,
        uint32(PartitionStateHealing),
        uint32(PartitionStateGrayZone)) {
        return ErrInvalidPartitionTransition
    }

    prm.mu.Lock()
    prm.grayZoneStartTime = time.Now()
    prm.currentState = PartitionStateGrayZone
    prm.mu.Unlock()

    // Step 1: Broadcast gray zone entry with VRF proof
    broadcastGrayZoneEntry(&GrayZoneAnnouncement{
        StartTime:         prm.grayZoneStartTime,
        MaxDuration:       GrayZoneMaxDuration,
        InitiatorID:       localNodeID,
        TPMAttestation:    GenerateTPMQuote(),
        InitiatorSelection: prm.initiatorSelection, // Include VRF selection proof
    })

    // Step 2: Freeze all pending transactions
    prm.freezeAllPendingTransactions()

    // Step 3: Reject new transaction submissions
    prm.rejectNewTransactions = true

    return nil
}

// isSelectedInitiator checks if local node is the VRF-selected initiator
func (prm *PartitionRecoveryManager) isSelectedInitiator() bool {
    prm.mu.RLock()
    defer prm.mu.RUnlock()

    if prm.initiatorSelection == nil {
        return false
    }

    return prm.initiatorSelection.SelectedNode == localNodeID &&
           prm.initiatorSelection.Verified
}

// onPartitionHealing is called when >80% reachability is detected
// SECURITY FIX (P5-H9): Performs VRF selection before gray zone entry
func (prm *PartitionRecoveryManager) onPartitionHealing(
    partitionID [32]byte,
    healingTime time.Time,
    visibleNodes [][32]byte,
) error {
    // Perform VRF selection
    selection, err := selectGrayZoneInitiator(partitionID, healingTime, visibleNodes)
    if err != nil {
        return err
    }

    prm.mu.Lock()
    prm.initiatorSelection = selection
    prm.mu.Unlock()

    // Broadcast selection to all visible nodes for verification
    broadcastInitiatorSelection(selection)

    // Wait for selection acknowledgment (timeout: 10 seconds)
    if err := waitForSelectionAck(selection, 10*time.Second); err != nil {
        return ErrInitiatorSelectionFailed{Cause: err}
    }

    // Only the selected node proceeds to enter gray zone
    if selection.SelectedNode == localNodeID {
        return prm.enterGrayZone(context.Background())
    }

    // Non-selected nodes wait for initiator's gray zone announcement
    return nil
}

// ErrNotSelectedInitiator indicates this node was not VRF-selected
type ErrNotSelectedInitiator struct {
    SelectedNode [32]byte
    LocalNode    [32]byte
}

func (e ErrNotSelectedInitiator) Error() string {
    return fmt.Sprintf("not selected initiator: selected=%x, local=%x",
        e.SelectedNode[:8], e.LocalNode[:8])
}

// ErrInitiatorSelectionFailed indicates VRF selection process failed
type ErrInitiatorSelectionFailed struct {
    Cause error
}

func (e ErrInitiatorSelectionFailed) Error() string {
    return fmt.Sprintf("gray zone initiator selection failed: %v", e.Cause)
}

// TransactionSubmissionHandler during gray zone
func (prm *PartitionRecoveryManager) HandleTransactionSubmission(tx *Transaction) error {
    currentState := PartitionRecoveryState(atomic.LoadUint32(&prm.stateFlag))

    if currentState == PartitionStateGrayZone ||
       currentState == PartitionStateReconciling {
        return ErrGrayZoneFreezeActive{
            Transaction: tx.ID,
            EstimatedResume: prm.estimateResumeTime(),
            RetryAfter:     30 * time.Second,
        }
    }

    // Normal transaction processing
    return prm.processTransaction(tx)
}
```

#### Conflict Detection and Resolution During Gray Zone

```go
// ConflictLog records all conflicts found during reconciliation
type ConflictLog struct {
    Conflicts     []Conflict
    ResolutionLog []ConflictResolution
    mu            sync.RWMutex
}

// Conflict represents a detected conflict during gray zone
type Conflict struct {
    ConflictID      [32]byte
    Transaction1    *Transaction
    Transaction2    *Transaction
    ConflictType    ConflictType
    DetectedAt      time.Time
    SharedUTXOs     []UTXOID
}

type ConflictType uint8

const (
    ConflictTypeDoubleSpend    ConflictType = iota  // Same UTXO spent twice
    ConflictTypeSequenceGap                          // Missing sequence numbers
    ConflictTypeTimestampAnomal                      // TPM timestamp inconsistency
    ConflictTypeSignatureInvalid                     // Signature doesn't verify
)

// ConflictResolution records how a conflict was resolved
type ConflictResolution struct {
    ConflictID       [32]byte
    WinningTx        TxID
    LosingTx         TxID
    ResolutionReason ResolutionReason
    ResolvedAt       time.Time
    ReversalTx       *Transaction    // Compensating transaction if needed
    AffectedAccounts []WalletAddress
}

type ResolutionReason uint8

const (
    ResolutionTPMCounterFirst   ResolutionReason = iota  // Lower TPM counter wins
    ResolutionTxIDTiebreaker                              // Lower tx ID wins
    ResolutionMajorityPartition                           // Majority partition wins
    ResolutionBothRejected                                // Double-spend: both rejected
    ResolutionManualIntervention                          // Required human review
)

// detectAllConflicts scans both partition histories for conflicts
func (prm *PartitionRecoveryManager) detectAllConflicts(
    majorityDAG *DAGSnapshot,
    minorityDAG *DAGSnapshot,
) ([]Conflict, error) {
    var conflicts []Conflict

    // Build UTXO spending map from majority partition
    majoritySpends := make(map[UTXOID]*Transaction)
    for _, tx := range majorityDAG.Transactions {
        for _, input := range tx.Inputs {
            majoritySpends[input.UTXO] = tx
        }
    }

    // Check minority transactions against majority
    for _, tx := range minorityDAG.Transactions {
        for _, input := range tx.Inputs {
            if majorityTx, exists := majoritySpends[input.UTXO]; exists {
                // CONFLICT: Same UTXO spent in both partitions
                conflicts = append(conflicts, Conflict{
                    ConflictID:   generateConflictID(majorityTx, tx),
                    Transaction1: majorityTx,
                    Transaction2: tx,
                    ConflictType: ConflictTypeDoubleSpend,
                    DetectedAt:   time.Now(),
                    SharedUTXOs:  []UTXOID{input.UTXO},
                })
            }
        }
    }

    return conflicts, nil
}

// resolveConflicts applies resolution rules to all detected conflicts
func (prm *PartitionRecoveryManager) resolveConflicts(conflicts []Conflict) error {
    prm.conflictLog.mu.Lock()
    defer prm.conflictLog.mu.Unlock()

    for _, conflict := range conflicts {
        var resolution ConflictResolution

        switch conflict.ConflictType {
        case ConflictTypeDoubleSpend:
            resolution = prm.resolveDoubleSpend(conflict)

        case ConflictTypeSequenceGap:
            resolution = prm.resolveSequenceGap(conflict)

        default:
            resolution = ConflictResolution{
                ConflictID:       conflict.ConflictID,
                ResolutionReason: ResolutionManualIntervention,
            }
        }

        prm.conflictLog.Conflicts = append(prm.conflictLog.Conflicts, conflict)
        prm.conflictLog.ResolutionLog = append(prm.conflictLog.ResolutionLog, resolution)

        // Execute resolution
        if err := prm.executeResolution(resolution); err != nil {
            return fmt.Errorf("resolution execution failed: %w", err)
        }
    }

    return nil
}

// resolveDoubleSpend handles double-spend conflicts deterministically
func (prm *PartitionRecoveryManager) resolveDoubleSpend(conflict Conflict) ConflictResolution {
    tx1 := conflict.Transaction1
    tx2 := conflict.Transaction2

    resolution := ConflictResolution{
        ConflictID: conflict.ConflictID,
        ResolvedAt: time.Now(),
    }

    // Rule 1: Lower TPM monotonic counter wins (proves earlier creation)
    if tx1.TPMCounter < tx2.TPMCounter {
        resolution.WinningTx = tx1.ID
        resolution.LosingTx = tx2.ID
        resolution.ResolutionReason = ResolutionTPMCounterFirst
        return resolution
    }
    if tx2.TPMCounter < tx1.TPMCounter {
        resolution.WinningTx = tx2.ID
        resolution.LosingTx = tx1.ID
        resolution.ResolutionReason = ResolutionTPMCounterFirst
        return resolution
    }

    // Rule 2: Same TPM counter (extremely rare) - use tx ID as tiebreaker
    if bytes.Compare(tx1.ID[:], tx2.ID[:]) < 0 {
        resolution.WinningTx = tx1.ID
        resolution.LosingTx = tx2.ID
    } else {
        resolution.WinningTx = tx2.ID
        resolution.LosingTx = tx1.ID
    }
    resolution.ResolutionReason = ResolutionTxIDTiebreaker

    return resolution
}

// executeResolution applies the resolution decision
func (prm *PartitionRecoveryManager) executeResolution(resolution ConflictResolution) error {
    // Mark losing transaction as reverted
    if err := markTransactionReverted(resolution.LosingTx, resolution.ConflictID); err != nil {
        return fmt.Errorf("marking tx reverted: %w", err)
    }

    // Notify affected wallets
    for _, wallet := range resolution.AffectedAccounts {
        notifyWalletOfConflictResolution(wallet, resolution)
    }

    // Log for audit and compliance
    logConflictResolution(resolution)

    return nil
}
```

#### Gray Zone Exit Protocol

```go
// exitGrayZone transitions back to normal operation
func (prm *PartitionRecoveryManager) exitGrayZone(ctx context.Context) error {
    // Validate minimum gray zone duration passed
    prm.mu.RLock()
    elapsed := time.Since(prm.grayZoneStartTime)
    prm.mu.RUnlock()

    if elapsed < GrayZoneFreezeMinDuration {
        return ErrGrayZoneTooShort{
            Elapsed:  elapsed,
            Required: GrayZoneFreezeMinDuration,
        }
    }

    // Verify all conflicts resolved
    if prm.hasUnresolvedConflicts() {
        return ErrUnresolvedConflicts{
            Count: prm.unresolvedConflictCount(),
        }
    }

    // Verify network stability
    if !prm.isNetworkStable() {
        return ErrNetworkUnstable{
            CurrentReachability: prm.getCurrentReachability(),
            RequiredReachability: RecoveryThreshold,
        }
    }

    // Atomic transition to normal
    if !atomic.CompareAndSwapUint32(&prm.stateFlag,
        uint32(PartitionStateValidating),
        uint32(PartitionStateNormal)) {
        return ErrInvalidPartitionTransition
    }

    // Unfreeze transactions
    prm.unfreezeTransactions()

    // Broadcast recovery complete
    broadcastRecoveryComplete(&RecoveryAnnouncement{
        CompletedAt:    time.Now(),
        ConflictsFound: len(prm.conflictLog.Conflicts),
        ConflictsResolved: len(prm.conflictLog.ResolutionLog),
        TPMAttestation: GenerateTPMQuote(),
    })

    return nil
}
```

**Gray Zone Protocol Enhancements - FINAL DESIGN:**

**VRF Initiator Selection Tie-Breaker:**

When a partition heals, both sides might try to initiate the gray zone simultaneously. VRF selection ensures only one initiator.

```go
// If VRF outputs are identical (extremely rare), use NodeID tie-breaker
func selectGrayZoneInitiator(candidates []NodeID, seed []byte) NodeID {
    var lowestVRF [32]byte
    var selectedNode NodeID
    selectedNodes := make([]NodeID, 0)

    // Compute VRF for each candidate
    for _, candidate := range candidates {
        vrf := computeVRF(candidate, seed)

        cmp := bytes.Compare(vrf[:], lowestVRF[:])
        if cmp < 0 || lowestVRF == [32]byte{} {
            lowestVRF = vrf
            selectedNodes = []NodeID{candidate}
        } else if cmp == 0 {
            // Tie in VRF output
            selectedNodes = append(selectedNodes, candidate)
        }
    }

    // If VRF tie, use lowest NodeID lexicographically
    if len(selectedNodes) > 1 {
        sort.Slice(selectedNodes, func(i, j int) bool {
            return bytes.Compare(selectedNodes[i][:], selectedNodes[j][:]) < 0
        })
        selectedNode = selectedNodes[0]

        log.Warn("VRF tie detected, using NodeID tie-breaker",
            "tiedNodes", len(selectedNodes),
            "selectedNode", hex.EncodeToString(selectedNode[:8]))
    } else {
        selectedNode = selectedNodes[0]
    }

    return selectedNode
}
```

**Gray Zone Timeout Handling:**

If gray zone exceeds 5 minutes, automatic abort with state rollback prevents indefinite freeze.

```go
// Gray zone timeout handler
func (prm *PartitionRecoveryManager) monitorGrayZoneTimeout(ctx context.Context) {
    timer := time.NewTimer(GrayZoneMaxDuration)
    defer timer.Stop()

    select {
    case <-ctx.Done():
        // Gray zone completed successfully
        return

    case <-timer.C:
        // Timeout exceeded - abort gray zone
        log.Error("gray zone timeout exceeded, aborting reconciliation",
            "duration", GrayZoneMaxDuration)

        // Rollback all changes made during gray zone
        if err := prm.rollbackGrayZoneChanges(); err != nil {
            log.Error("gray zone rollback failed", "error", err)
            // Trigger emergency intervention
            triggerEmergencyIntervention("gray_zone_rollback_failed")
        }

        // Transition back to partition state
        atomic.StoreUint32(&prm.stateFlag, uint32(PartitionStatePartitioned))

        // Notify operators
        alertOperators(&GrayZoneTimeoutAlert{
            StartTime: prm.grayZoneStartTime,
            Duration:  time.Since(prm.grayZoneStartTime),
            Reason:    "exceeded maximum duration",
        })
    }
}

// rollbackGrayZoneChanges specification
//
// CRITICAL OPERATION: Atomically rolls back all state changes made during gray zone.
// This function is called when gray zone exceeds maximum duration (5 minutes).
//
// Rollback Sequence (MUST be executed in reverse order of operations):
//
// 1. FREEZE IN-FLIGHT TRANSACTIONS
//    - Identify all transactions in processing state (not yet committed)
//    - Set transaction state to FROZEN (atomic state flag update)
//    - Record freeze timestamp for each transaction
//    - Frozen transactions remain in queue but processing halts immediately
//    - No new state mutations allowed from frozen transactions
//
//    Implementation:
//    ```go
//    for txID, tx := range prm.inFlightTransactions {
//        if !atomic.CompareAndSwapUint32(&tx.stateFlag,
//            uint32(TxStateProcessing), uint32(TxStateFrozen)) {
//            log.Warn("transaction already in terminal state", "txID", txID)
//            continue
//        }
//        tx.frozenAt = time.Now()
//        prm.frozenTxLog = append(prm.frozenTxLog, txID)
//    }
//    ```
//
// 2. RELEASE LOCKS ATOMICALLY
//    - Collect all locks held during gray zone (tracked in lockRegistry)
//    - For each lock:
//      a) Verify lock is still held by this node
//      b) Release lock from DHT with atomic CAS operation
//      c) Remove lock from local registry
//      d) Log lock release with timestamp and reason
//    - If any lock release fails: Log error but continue (prevent partial rollback)
//    - Total lock release timeout: 30 seconds (prevent indefinite blocking)
//
//    Lock Release Protocol:
//    ```go
//    type LockReleaseRecord struct {
//        LockID      UTXOID
//        HeldSince   time.Time
//        ReleasedAt  time.Time
//        Reason      string  // "gray_zone_timeout_rollback"
//        Success     bool
//    }
//
//    func (prm *PartitionRecoveryManager) releaseLocks() error {
//        prm.lockRegistry.mu.Lock()
//        heldLocks := make([]UTXOID, 0, len(prm.lockRegistry.locks))
//        for lockID := range prm.lockRegistry.locks {
//            heldLocks = append(heldLocks, lockID)
//        }
//        prm.lockRegistry.mu.Unlock()
//
//        releaseCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//        defer cancel()
//
//        var releaseRecords []LockReleaseRecord
//        for _, lockID := range heldLocks {
//            record := LockReleaseRecord{
//                LockID:    lockID,
//                HeldSince: prm.lockRegistry.locks[lockID].acquiredAt,
//                Reason:    "gray_zone_timeout_rollback",
//            }
//
//            if err := releaseLockWithContext(releaseCtx, lockID); err != nil {
//                log.Error("lock release failed during rollback",
//                    "lockID", lockID, "error", err)
//                record.Success = false
//            } else {
//                prm.lockRegistry.mu.Lock()
//                delete(prm.lockRegistry.locks, lockID)
//                prm.lockRegistry.mu.Unlock()
//                record.Success = true
//            }
//
//            record.ReleasedAt = time.Now()
//            releaseRecords = append(releaseRecords, record)
//        }
//
//        // Persist release records for audit
//        persistLockReleaseLog(releaseRecords)
//        return nil
//    }
//    ```
//
// 3. HANDLE IN-FLIGHT OPERATIONS
//    - In-flight operations are transactions in the following states:
//      a) TxStateValidating: Transaction signature/structure validation in progress
//      b) TxStateProcessing: UTXO conflict checks, balance verification in progress
//      c) TxStatePreparing: Two-phase commit PREPARE phase sent to coordinators
//      d) TxStateCommitting: Two-phase commit COMMIT phase in progress (CRITICAL)
//
//    State-Specific Handling:
//
//    a) TxStateValidating / TxStateProcessing:
//       - ABORT immediately (no external state modified yet)
//       - Set transaction state to TxStateAborted
//       - Return queued transactions to submission queue with retry flag
//       - No compensating actions needed
//
//    b) TxStatePreparing:
//       - Send ABORT message to all coordinators that received PREPARE
//       - Wait for ABORT acknowledgment (timeout: 10 seconds)
//       - If timeout: Log coordinator IDs that failed to acknowledge
//       - Coordinator crash detection will clean up orphaned PREPARE state
//       - Set transaction state to TxStateAborted
//
//    c) TxStateCommitting (CRITICAL - partially committed):
//       - CANNOT abort safely (some coordinators may have committed)
//       - Option 1: Allow commit to complete (wait up to 30 seconds)
//       - Option 2: If timeout, mark transaction as UNCERTAIN
//       - UNCERTAIN transactions require manual reconciliation after recovery
//       - Log transaction to uncertainty log for post-recovery resolution
//       - Alert operators: "transaction in uncertain state after rollback"
//
//    Implementation:
//    ```go
//    type InFlightOperation struct {
//        TxID        TxID
//        State       TxState
//        StartedAt   time.Time
//        Coordinators [][32]byte  // Involved coordinator nodes
//    }
//
//    func (prm *PartitionRecoveryManager) handleInFlightOps() error {
//        prm.inFlightOps.mu.RLock()
//        ops := make([]*InFlightOperation, 0, len(prm.inFlightOps.operations))
//        for _, op := range prm.inFlightOps.operations {
//            ops = append(ops, op)
//        }
//        prm.inFlightOps.mu.RUnlock()
//
//        var uncertainTxs []TxID
//
//        for _, op := range ops {
//            switch op.State {
//            case TxStateValidating, TxStateProcessing:
//                // Safe to abort
//                abortTransaction(op.TxID, "gray_zone_timeout_rollback")
//                requeueTransaction(op.TxID)
//
//            case TxStatePreparing:
//                // Send ABORT to coordinators
//                abortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//                sendAbortToCoordinators(abortCtx, op.TxID, op.Coordinators)
//                cancel()
//                abortTransaction(op.TxID, "gray_zone_timeout_rollback")
//
//            case TxStateCommitting:
//                // CRITICAL: Partially committed
//                commitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//                if err := waitForCommitCompletion(commitCtx, op.TxID); err != nil {
//                    // Timeout - mark as uncertain
//                    markTransactionUncertain(op.TxID, op.Coordinators)
//                    uncertainTxs = append(uncertainTxs, op.TxID)
//                    log.Error("transaction uncertain after rollback",
//                        "txID", op.TxID,
//                        "coordinators", op.Coordinators)
//                }
//                cancel()
//            }
//        }
//
//        if len(uncertainTxs) > 0 {
//            alertOperators(&UncertainTransactionsAlert{
//                Count:        len(uncertainTxs),
//                Transactions: uncertainTxs,
//                Reason:       "gray_zone_timeout_rollback",
//            })
//        }
//
//        return nil
//    }
//    ```
//
// 4. HANDLE QUEUED TRANSACTIONS
//    - Queued transactions are in gray zone transaction queue (not yet processed)
//    - These transactions are safe to handle without rollback (no state modified)
//    - Options for queued transactions:
//      a) Requeue for processing after partition recovery (default)
//      b) Expire transactions queued > 10 minutes (max queue time)
//      c) Return error to submitter with retry instruction
//
//    Implementation:
//    ```go
//    func (prm *PartitionRecoveryManager) handleQueuedTransactions() error {
//        prm.grayZoneQueue.mu.Lock()
//        defer prm.grayZoneQueue.mu.Unlock()
//
//        now := time.Now()
//        requeuedCount := 0
//        expiredCount := 0
//
//        for _, tx := range prm.grayZoneQueue.pendingTxs {
//            queuedAt := prm.grayZoneQueue.queuedAt[tx.ID]
//
//            // Expire transactions queued > 10 minutes
//            if now.Sub(queuedAt) > 10*time.Minute {
//                expiredCount++
//                notifyTxExpired(tx.ID, "gray_zone_timeout_rollback")
//                delete(prm.grayZoneQueue.queuedAt, tx.ID)
//                continue
//            }
//
//            // Requeue for processing after recovery
//            if err := requeueTransactionForRetry(tx); err != nil {
//                log.Warn("transaction requeue failed", "txID", tx.ID, "error", err)
//                notifyTxRejected(tx.ID, "rollback_requeue_failed")
//            } else {
//                requeuedCount++
//            }
//        }
//
//        log.Info("queued transactions processed during rollback",
//            "requeued", requeuedCount,
//            "expired", expiredCount)
//
//        // Clear queue
//        prm.grayZoneQueue.pendingTxs = nil
//        prm.grayZoneQueue.queuedAt = make(map[TxID]time.Time)
//
//        return nil
//    }
//    ```
//
// 5. GRAY ZONE RE-ENTRY HANDLING
//    - After rollback, system returns to PartitionStatePartitioned
//    - If conflicts reappear during exit (reachability improves again):
//      a) Re-entry is allowed ONLY after 10-minute cooldown
//      b) Track gray zone entry count (max 3 attempts per partition event)
//      c) After 3 failed attempts: Require manual intervention
//      d) Persist gray zone attempt history to prevent reset on node restart
//
//    Re-Entry Protection:
//    ```go
//    type GrayZoneAttemptHistory struct {
//        PartitionEventID [32]byte
//        Attempts         []GrayZoneAttempt
//        LastAttemptAt    time.Time
//        MaxAttempts      int  // 3
//    }
//
//    type GrayZoneAttempt struct {
//        AttemptNum    int
//        StartedAt     time.Time
//        EndedAt       time.Time
//        Outcome       string  // "success", "timeout", "conflict_reappeared"
//        ConflictCount int
//    }
//
//    func (prm *PartitionRecoveryManager) canEnterGrayZone(
//        partitionEventID [32]byte,
//    ) error {
//        history := prm.getGrayZoneHistory(partitionEventID)
//
//        // Check cooldown period
//        if time.Since(history.LastAttemptAt) < 10*time.Minute {
//            return ErrGrayZoneCooldownActive{
//                Remaining: 10*time.Minute - time.Since(history.LastAttemptAt),
//            }
//        }
//
//        // Check max attempts
//        if len(history.Attempts) >= history.MaxAttempts {
//            return ErrGrayZoneMaxAttemptsExceeded{
//                Attempts:   len(history.Attempts),
//                MaxAllowed: history.MaxAttempts,
//                Action:     "manual intervention required",
//            }
//        }
//
//        return nil
//    }
//
//    func (prm *PartitionRecoveryManager) recordGrayZoneAttempt(
//        partitionEventID [32]byte,
//        outcome string,
//        conflictCount int,
//    ) {
//        history := prm.getGrayZoneHistory(partitionEventID)
//
//        attempt := GrayZoneAttempt{
//            AttemptNum:    len(history.Attempts) + 1,
//            StartedAt:     prm.grayZoneStartTime,
//            EndedAt:       time.Now(),
//            Outcome:       outcome,
//            ConflictCount: conflictCount,
//        }
//
//        history.Attempts = append(history.Attempts, attempt)
//        history.LastAttemptAt = time.Now()
//
//        // Persist to storage (survives node restart)
//        persistGrayZoneHistory(history)
//    }
//    ```
//
// ROLLBACK SUMMARY
//
// ┌─────────────────────────┬──────────────────────┬─────────────────────────────────┐
// │ Component               │ Action               │ Timeout                         │
// ├─────────────────────────┼──────────────────────┼─────────────────────────────────┤
// │ In-flight transactions  │ Freeze processing    │ Immediate (atomic flag update)  │
// │ Locks                   │ Release atomically   │ 30 seconds total                │
// │ Validating/Processing   │ Abort + requeue      │ Immediate                       │
// │ Preparing               │ Send ABORT           │ 10 seconds (coordinator ACK)    │
// │ Committing              │ Wait or mark UNCERTAIN│ 30 seconds (commit completion)  │
// │ Queued transactions     │ Requeue or expire    │ N/A (safe to handle)            │
// │ Gray zone re-entry      │ 10-minute cooldown   │ Max 3 attempts                  │
// └─────────────────────────┴──────────────────────┴─────────────────────────────────┘
//
// ERROR HANDLING
//
// If any rollback step fails:
// 1. Log detailed error with context (which step, which transaction/lock)
// 2. Continue with remaining rollback steps (prevent partial rollback)
// 3. Collect all failures and report to operators
// 4. Trigger emergency intervention if critical errors detected
// 5. Persist rollback failure log for post-mortem analysis
//
// Critical errors requiring emergency intervention:
// - Lock release failures exceeding 50% of held locks
// - Uncertain transaction count exceeding 10
// - DHT communication failures during rollback
// - Rollback timeout exceeding 2 minutes total
```

**Transaction Race Condition Handling:**

Transactions submitted during gray zone entry are queued and processed after resolution.

```go
// Transaction queue during gray zone
type GrayZoneTransactionQueue struct {
    pendingTxs    []*Transaction
    queuedAt      map[TxID]time.Time
    maxQueueTime  time.Duration // 10 minutes
    mu            sync.RWMutex
}

// EnqueueTransaction adds transaction to gray zone queue
func (gztq *GrayZoneTransactionQueue) EnqueueTransaction(tx *Transaction) error {
    gztq.mu.Lock()
    defer gztq.mu.Unlock()

    // Check if queue is full
    if len(gztq.pendingTxs) >= 10000 {
        return ErrGrayZoneQueueFull
    }

    gztq.pendingTxs = append(gztq.pendingTxs, tx)
    gztq.queuedAt[tx.ID] = time.Now()

    return nil
}

// ProcessQueuedTransactions executes after gray zone resolution
func (gztq *GrayZoneTransactionQueue) ProcessQueuedTransactions() error {
    gztq.mu.Lock()
    defer gztq.mu.Unlock()

    log.Info("processing gray zone transaction queue",
        "count", len(gztq.pendingTxs))

    processedCount := 0
    expiredCount := 0

    for _, tx := range gztq.pendingTxs {
        queuedAt := gztq.queuedAt[tx.ID]

        // Expire transactions queued for >10 minutes
        if time.Since(queuedAt) > gztq.maxQueueTime {
            expiredCount++
            notifyTxExpired(tx.ID, "gray_zone_timeout")
            continue
        }

        // Process transaction normally
        if err := processTransaction(tx); err != nil {
            log.Warn("queued transaction processing failed",
                "txID", tx.ID,
                "error", err)
        } else {
            processedCount++
        }
    }

    log.Info("gray zone queue processing complete",
        "processed", processedCount,
        "expired", expiredCount)

    // Clear queue
    gztq.pendingTxs = nil
    gztq.queuedAt = make(map[TxID]time.Time)

    return nil
}
```

**Gray Zone Security Properties**:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| No new double-spends | Transactions frozen during gray zone | Transaction rejection |
| Deterministic resolution | Same conflicts resolve same way everywhere | TPM counter + tx ID rules |
| Audit trail | All conflicts and resolutions logged | ConflictLog persistence |
| Bounded duration | Max 5 minutes in gray zone | GrayZoneMaxDuration with abort |
| Notification | Affected wallets notified of reversals | Wallet notification system |
| Single initiator | Only one node initiates gray zone | VRF selection with tie-breaker |
| Transaction queuing | Transactions during entry are queued | GrayZoneTransactionQueue |
| Timeout protection | Auto-abort if exceeds max duration | monitorGrayZoneTimeout |

---

### Flapping Partition Detection - FINAL DESIGN

Rapid partition state transitions can indicate network instability or Byzantine behavior. Flapping detection prevents oscillation.

**Flap Detection:**

Track partition state transitions per hour:
- If >3 transitions in 1 hour: Enter stabilization mode
- Stabilization: 10-minute cooldown before allowing new transitions

**Stabilization Mode:**

During stabilization:
- Maintain current partition state (freeze state machine)
- Continue monitoring reachability
- Log all would-be transitions for debugging
- After 10 minutes: Exit stabilization, allow transitions again

**Byzantine Reachability Detection:**

To prevent malicious nodes from faking reachability:
- Require signed heartbeats with TPM attestation
- Heartbeat includes: timestamp, node ID, TPM quote
- Invalid heartbeats are rejected from reachability calculation

```go
// Flapping partition detector
type FlappingPartitionDetector struct {
    transitions      []time.Time
    inStabilization  bool
    stabilizationEnd time.Time
    mu               sync.RWMutex
}

// RecordTransition logs partition state transition
func (fpd *FlappingPartitionDetector) RecordTransition() bool {
    fpd.mu.Lock()
    defer fpd.mu.Unlock()

    now := time.Now()

    // Check if in stabilization mode
    if fpd.inStabilization {
        if now.Before(fpd.stabilizationEnd) {
            log.Warn("partition transition blocked - in stabilization mode",
                "remainingTime", time.Until(fpd.stabilizationEnd))
            return false // Block transition
        }
        // Stabilization period ended
        fpd.inStabilization = false
        fpd.transitions = nil // Clear history
    }

    // Record transition
    fpd.transitions = append(fpd.transitions, now)

    // Remove transitions older than 1 hour
    cutoff := now.Add(-1 * time.Hour)
    filtered := make([]time.Time, 0)
    for _, t := range fpd.transitions {
        if t.After(cutoff) {
            filtered = append(filtered, t)
        }
    }
    fpd.transitions = filtered

    // Check for flapping (>3 transitions in 1 hour)
    if len(fpd.transitions) > 3 {
        log.Error("partition flapping detected, entering stabilization mode",
            "transitionsPerHour", len(fpd.transitions),
            "stabilizationDuration", 10*time.Minute)

        fpd.inStabilization = true
        fpd.stabilizationEnd = now.Add(10 * time.Minute)

        // Alert operators
        alertPartitionFlapping(len(fpd.transitions))
    }

    return true // Allow transition
}

// TPM-attested heartbeat for Byzantine protection
type TPMHeartbeat struct {
    NodeID     [32]byte
    Timestamp  time.Time
    TPMQuote   []byte // TPM 2.0 quote
    Signature  []byte // Signed by node's key
}

// ValidateHeartbeat verifies heartbeat authenticity
func ValidateHeartbeat(hb *TPMHeartbeat) error {
    // Step 1: Verify signature
    if !verifySignature(hb.NodeID, hb.Signature, serializeHeartbeat(hb)) {
        return ErrInvalidHeartbeatSignature
    }

    // Step 2: Verify TPM quote
    if err := verifyTPMQuote(hb.TPMQuote, hb.NodeID); err != nil {
        return fmt.Errorf("TPM quote verification failed: %w", err)
    }

    // Step 3: Check timestamp freshness (must be within 60 seconds)
    if time.Since(hb.Timestamp) > 60*time.Second {
        return ErrHeartbeatTooOld{Age: time.Since(hb.Timestamp)}
    }

    return nil
}

// ReachabilityCalculator with Byzantine protection
func calculateReachability(heartbeats []*TPMHeartbeat) float64 {
    validCount := 0
    totalSampled := len(heartbeats)

    for _, hb := range heartbeats {
        if err := ValidateHeartbeat(hb); err != nil {
            log.Warn("invalid heartbeat excluded from reachability",
                "nodeID", hex.EncodeToString(hb.NodeID[:8]),
                "error", err)
            continue
        }
        validCount++
    }

    if totalSampled == 0 {
        return 0.0
    }

    return float64(validCount) / float64(totalSampled)
}
```

**Flapping Partition Summary:**

| Metric | Threshold | Action |
|--------|-----------|--------|
| **Transitions/hour** | >3 | Enter stabilization mode |
| **Stabilization duration** | 10 minutes | Freeze state transitions |
| **Heartbeat freshness** | 60 seconds | Reject stale heartbeats |
| **TPM attestation** | Required | Reject unauthenticated heartbeats |

---

### Partition Recovery Operations

This section defines the operational procedures for recovering from network partitions, including partition discovery, transaction log reconciliation, and expected recovery times.

#### Vector Clock Based Partition Discovery

Partition discovery uses vector clocks to identify divergent network states and determine which nodes belong to which partition:

```go
// PartitionDiscovery uses vector clocks to identify partition boundaries
type PartitionDiscovery struct {
    LocalNodeID     [32]byte
    VectorClock     map[[32]byte]uint64  // NodeID -> logical timestamp
    LastSync        time.Time
    PartitionID     [32]byte             // Computed from member set
    MemberNodes     [][32]byte
}

// VectorClockEntry represents a single node's clock state
type VectorClockEntry struct {
    NodeID          [32]byte
    LogicalTime     uint64
    PhysicalTime    time.Time
    LastSeenBy      [][32]byte    // Nodes that have observed this entry
}

// DiscoverPartition identifies partition membership via vector clock comparison
func (pd *PartitionDiscovery) DiscoverPartition(ctx context.Context) (*PartitionInfo, error) {
    // Step 1: Broadcast vector clock request to all known peers
    responses := pd.broadcastClockRequest(ctx)

    // Step 2: Identify clock divergence
    divergentNodes := make(map[[32]byte]bool)
    convergentNodes := make(map[[32]byte]bool)

    for nodeID, response := range responses {
        if pd.clocksDiverged(pd.VectorClock, response.VectorClock) {
            divergentNodes[nodeID] = true
        } else {
            convergentNodes[nodeID] = true
        }
    }

    // Step 3: Determine partition membership
    partitionMembers := make([][32]byte, 0, len(convergentNodes)+1)
    partitionMembers = append(partitionMembers, pd.LocalNodeID)

    for nodeID := range convergentNodes {
        partitionMembers = append(partitionMembers, nodeID)
    }

    // Step 4: Compute partition ID (deterministic hash of sorted members)
    partitionID := pd.computePartitionID(partitionMembers)

    return &PartitionInfo{
        ID:              partitionID,
        Members:         partitionMembers,
        DivergentNodes:  mapKeys(divergentNodes),
        DiscoveredAt:    time.Now(),
        VectorClock:     pd.VectorClock,
    }, nil
}

// clocksDiverged checks if two vector clocks have diverged
func (pd *PartitionDiscovery) clocksDiverged(local, remote map[[32]byte]uint64) bool {
    // Clocks have diverged if neither dominates the other
    localDominates := true
    remoteDominates := true

    for nodeID, localTime := range local {
        remoteTime, exists := remote[nodeID]
        if !exists || localTime > remoteTime {
            remoteDominates = false
        }
        if exists && localTime < remoteTime {
            localDominates = false
        }
    }

    for nodeID, remoteTime := range remote {
        if _, exists := local[nodeID]; !exists {
            localDominates = false
            break
        }
    }

    // Diverged if neither dominates (concurrent modifications)
    return !localDominates && !remoteDominates
}

// computePartitionID creates deterministic partition identifier
func (pd *PartitionDiscovery) computePartitionID(members [][32]byte) [32]byte {
    // Sort members for deterministic ordering
    sort.Slice(members, func(i, j int) bool {
        return bytes.Compare(members[i][:], members[j][:]) < 0
    })

    h := sha256.New()
    for _, member := range members {
        h.Write(member[:])
    }
    var id [32]byte
    copy(id[:], h.Sum(nil))
    return id
}
```

#### Partition Advertisement via DHT

Partitions advertise their existence and membership through the DHT for discovery by other partitions:

```go
// PartitionAdvertisement published to DHT for partition discovery
type PartitionAdvertisement struct {
    PartitionID     [32]byte
    MemberCount     int
    CoordinatorCount int
    LeaderNodeID    [32]byte
    VectorClockHash [32]byte    // Hash of current vector clock state
    LastBlockHeight uint64
    LastBlockHash   [32]byte
    AdvertisedAt    time.Time
    TTL             time.Duration
    Signature       []byte      // Signed by partition leader
}

// DHT key pattern for partition advertisements
const PartitionAdvertisementKeyPattern = "partition:advertisement:%x"

// AdvertisePartition publishes partition info to DHT
func (pd *PartitionDiscovery) AdvertisePartition(
    ctx context.Context,
    dht DHT,
    partitionInfo *PartitionInfo,
) error {
    ad := &PartitionAdvertisement{
        PartitionID:      partitionInfo.ID,
        MemberCount:      len(partitionInfo.Members),
        CoordinatorCount: partitionInfo.CoordinatorCount,
        LeaderNodeID:     partitionInfo.LeaderNode,
        VectorClockHash:  pd.hashVectorClock(),
        LastBlockHeight:  partitionInfo.LastBlockHeight,
        LastBlockHash:    partitionInfo.LastBlockHash,
        AdvertisedAt:     time.Now(),
        TTL:              5 * time.Minute,
    }

    // Sign advertisement
    ad.Signature = signWithTPM(ad)

    // Publish to DHT
    key := fmt.Sprintf(PartitionAdvertisementKeyPattern, partitionInfo.ID[:8])
    return dht.Put(ctx, key, ad, ad.TTL)
}

// DiscoverOtherPartitions finds other partition advertisements
func (pd *PartitionDiscovery) DiscoverOtherPartitions(
    ctx context.Context,
    dht DHT,
) ([]*PartitionAdvertisement, error) {
    // Query DHT for all partition advertisements
    pattern := "partition:advertisement:*"
    results, err := dht.GetPattern(ctx, pattern)
    if err != nil {
        return nil, err
    }

    var partitions []*PartitionAdvertisement
    for _, result := range results {
        ad, ok := result.(*PartitionAdvertisement)
        if !ok {
            continue
        }

        // Skip our own partition
        if ad.PartitionID == pd.PartitionID {
            continue
        }

        // Verify signature
        if !verifySignature(ad.LeaderNodeID, ad.Signature, ad) {
            log.Warn("invalid partition advertisement signature",
                "partitionID", hex.EncodeToString(ad.PartitionID[:8]))
            continue
        }

        partitions = append(partitions, ad)
    }

    return partitions, nil
}
```

#### Minority Partition Read-Only Mode

When a node determines it is in the minority partition, it enters read-only mode:

```go
// MinorityPartitionMode defines behavior for minority partition nodes
type MinorityPartitionMode struct {
    IsMinority      bool
    EnteredAt       time.Time
    PartitionID     [32]byte
    MajorityPartitionID [32]byte  // Known majority partition (if discovered)
    ReadOnlyMode    bool
}

// MinorityPartitionBehavior specifies allowed operations
var MinorityPartitionBehavior = struct {
    // Allowed operations
    DHTRead          bool  // true - can read DHT data
    DHTWrite         bool  // true - non-currency data only
    TransactionRead  bool  // true - can read transaction history
    TransactionWrite bool  // false - cannot submit new transactions
    BlockRead        bool  // true - can read blocks
    BlockWrite       bool  // false - cannot propose blocks
    PeerDiscovery    bool  // true - continue peer discovery
    HealthChecks     bool  // true - respond to health checks

    // Response codes for rejected operations
    TransactionRejectionCode string  // "PARTITION_MINORITY"
    BlockRejectionCode       string  // "PARTITION_MINORITY"
}{
    DHTRead:                  true,
    DHTWrite:                 true,   // Non-currency only
    TransactionRead:          true,
    TransactionWrite:         false,
    BlockRead:                true,
    BlockWrite:               false,
    PeerDiscovery:            true,
    HealthChecks:             true,
    TransactionRejectionCode: "PARTITION_MINORITY",
    BlockRejectionCode:       "PARTITION_MINORITY",
}

// HandleTransactionInMinority returns appropriate error for minority partition
func (mpm *MinorityPartitionMode) HandleTransactionInMinority(tx *Transaction) error {
    if !mpm.IsMinority {
        return nil  // Not in minority, proceed normally
    }

    return ErrMinorityPartition{
        PartitionID:       mpm.PartitionID,
        MajorityPartition: mpm.MajorityPartitionID,
        Message:           "Transaction rejected: node is in minority partition",
        RetryAfter:        5 * time.Minute,
        ReadOnlyOps:       []string{"GET /transaction/{id}", "GET /balance/{address}"},
    }
}
```

#### Transaction Log Reconciliation Procedure

When partitions merge, transaction logs must be reconciled to resolve conflicts:

```go
// TransactionLogReconciliation handles merging divergent transaction logs
type TransactionLogReconciliation struct {
    LocalLog        *TransactionLog
    RemoteLog       *TransactionLog
    CommonAncestor  *TransactionLogEntry  // Last common entry before divergence
    ConflictEntries []TransactionConflict
    ResolvedEntries []ResolvedTransaction
}

// ReconciliationProcedure defines the step-by-step process
type ReconciliationProcedure struct {
    Steps []ReconciliationStep
}

var StandardReconciliationProcedure = ReconciliationProcedure{
    Steps: []ReconciliationStep{
        {
            Name: "FindCommonAncestor",
            Description: "Identify the last transaction log entry that exists in both partitions",
            Timeout: 30 * time.Second,
        },
        {
            Name: "CollectDivergentEntries",
            Description: "Gather all entries after the common ancestor from both partitions",
            Timeout: 2 * time.Minute,
        },
        {
            Name: "DetectConflicts",
            Description: "Identify double-spends and other conflicts between divergent entries",
            Timeout: 1 * time.Minute,
        },
        {
            Name: "ResolveConflicts",
            Description: "Apply conflict resolution rules (TPM timestamp, transaction ID)",
            Timeout: 2 * time.Minute,
        },
        {
            Name: "BuildMergedLog",
            Description: "Construct the reconciled transaction log",
            Timeout: 1 * time.Minute,
        },
        {
            Name: "ValidateMergedState",
            Description: "Verify all balances and UTXOs are consistent",
            Timeout: 2 * time.Minute,
        },
        {
            Name: "BroadcastReconciliation",
            Description: "Notify all nodes of reconciled state",
            Timeout: 1 * time.Minute,
        },
    },
}

// ExecuteReconciliation runs the full reconciliation procedure
func (tlr *TransactionLogReconciliation) ExecuteReconciliation(
    ctx context.Context,
) (*ReconciledLog, error) {
    log.Info("starting transaction log reconciliation")

    // Step 1: Find common ancestor
    ancestor, err := tlr.findCommonAncestor(ctx)
    if err != nil {
        return nil, fmt.Errorf("find common ancestor: %w", err)
    }
    tlr.CommonAncestor = ancestor

    log.Info("common ancestor found",
        "blockHeight", ancestor.BlockHeight,
        "txCount", ancestor.TransactionCount)

    // Step 2: Collect divergent entries
    localDivergent := tlr.LocalLog.EntriesAfter(ancestor.Hash)
    remoteDivergent := tlr.RemoteLog.EntriesAfter(ancestor.Hash)

    log.Info("divergent entries collected",
        "localCount", len(localDivergent),
        "remoteCount", len(remoteDivergent))

    // Step 3: Detect conflicts
    conflicts := tlr.detectConflicts(localDivergent, remoteDivergent)
    tlr.ConflictEntries = conflicts

    log.Info("conflicts detected", "count", len(conflicts))

    // Step 4: Resolve conflicts
    resolved, err := tlr.resolveConflicts(ctx, conflicts)
    if err != nil {
        return nil, fmt.Errorf("resolve conflicts: %w", err)
    }
    tlr.ResolvedEntries = resolved

    // Step 5: Build merged log
    mergedLog, err := tlr.buildMergedLog(ancestor, localDivergent, remoteDivergent, resolved)
    if err != nil {
        return nil, fmt.Errorf("build merged log: %w", err)
    }

    // Step 6: Validate merged state
    if err := tlr.validateMergedState(mergedLog); err != nil {
        return nil, fmt.Errorf("validate merged state: %w", err)
    }

    // Step 7: Broadcast reconciliation (handled by caller)
    log.Info("transaction log reconciliation complete",
        "entriesReconciled", mergedLog.EntryCount,
        "conflictsResolved", len(resolved))

    return mergedLog, nil
}
```

#### Expected Recovery Times by Partition Type

Recovery time depends on the partition type and severity:

| Partition Type | Detection Time | Recovery Time | Total Expected |
|----------------|----------------|---------------|----------------|
| **Transient (<5 min)** | 60 seconds | Automatic (0-2 min) | 1-3 minutes |
| **Short (5-30 min)** | 60 seconds | 5-15 minutes | 6-16 minutes |
| **Extended (30 min - 4 hr)** | 60 seconds | 15-60 minutes | 16-61 minutes |
| **Prolonged (>4 hr)** | 60 seconds | 1-4 hours | 1-4 hours |
| **Split-brain (50/50)** | 60 seconds | 10-30 minutes | 11-31 minutes |
| **Three-way** | 2 minutes | 30-60 minutes | 32-62 minutes |

**Recovery Time Breakdown by Phase:**

| Phase | Transient | Short | Extended | Prolonged |
|-------|-----------|-------|----------|-----------|
| Detection | 60s | 60s | 60s | 60s |
| Partition discovery | 30s | 30s | 1min | 2min |
| Gray zone entry | 30s | 30s | 30s | 30s |
| Conflict detection | 10s | 1min | 5min | 30min |
| Conflict resolution | 10s | 2min | 10min | 60min |
| State validation | 10s | 1min | 5min | 30min |
| Broadcast reconciliation | 10s | 30s | 2min | 10min |
| Gray zone exit | 30s | 30s | 30s | 30s |
| **Total** | ~3min | ~6min | ~25min | ~2.5hr |

**Factors Affecting Recovery Time:**

1. **Transaction volume during partition**: Higher volume = more conflicts = longer reconciliation
2. **Partition duration**: Longer partitions accumulate more divergent state
3. **Coordinator availability**: Quorum availability affects FROST signing speed
4. **Network latency**: Cross-region partitions have higher communication overhead
5. **Conflict complexity**: Double-spends require more careful resolution

---

### A5: Lock TTL Consistency (SECURITY FIX)

Lock TTLs MUST be consistent across all contexts to prevent race conditions during normal operation and partition recovery. This section establishes the canonical lock TTL values.

#### Problem Statement

Different parts of the documentation previously specified inconsistent lock TTLs:
- Normal UTXO operations: 30 seconds
- Cross-shard transactions: 60 seconds
- Partition recovery operations: 5 minutes
- Gray zone freeze: 10 minutes

Without explicit definitions, this inconsistency can cause:
1. Premature lock release while coordinator still processing
2. Locks held too long during partition, blocking reconciliation

#### Canonical Lock TTL Values

```go
// CanonicalLockTTLs - SINGLE SOURCE OF TRUTH for all lock durations
// These values MUST be used consistently across all components
const (
    // UTXO lock during normal operation
    UTXOLockTTL = 30 * time.Second

    // Extended lock for cross-shard transactions
    CrossShardLockTTL = 60 * time.Second

    // Lock extension duration (max 3 extensions)
    LockExtensionDuration = 30 * time.Second

    // Maximum total lock time (initial + extensions)
    MaxTotalLockTime = 2 * time.Minute

    // Lock TTL during partition recovery
    PartitionRecoveryLockTTL = 5 * time.Minute

    // Gray zone freeze lock (suspended transactions)
    GrayZoneLockTTL = 10 * time.Minute
)

// LockTTLContext specifies which TTL to use
type LockTTLContext uint8

const (
    LockContextNormal          LockTTLContext = iota
    LockContextCrossShard
    LockContextPartitionRecovery
    LockContextGrayZone
)

// GetLockTTL returns the canonical TTL for the given context
func GetLockTTL(ctx LockTTLContext) time.Duration {
    switch ctx {
    case LockContextNormal:
        return UTXOLockTTL
    case LockContextCrossShard:
        return CrossShardLockTTL
    case LockContextPartitionRecovery:
        return PartitionRecoveryLockTTL
    case LockContextGrayZone:
        return GrayZoneLockTTL
    default:
        return UTXOLockTTL
    }
}
```

#### Lock TTL Summary Table

| Context | TTL | Extensions | Max Total | Rationale |
|---------|-----|------------|-----------|-----------|
| **Normal UTXO** | 30s | 3 x 30s | 2 min | Fast operation, quick timeout |
| **Cross-Shard** | 60s | 3 x 30s | 2.5 min | Allow for multi-shard coordination |
| **Partition Recovery** | 5 min | None | 5 min | Allow time for reconciliation |
| **Gray Zone Freeze** | 10 min | None | 10 min | Extended for conflict resolution |

**Cross-Reference**: All lock-related code MUST import `LockTTL` constants from this canonical source. Direct TTL specifications in other files are deprecated.

### Lock TTL Extensions - FINAL DESIGN

Coordinators may need to extend lock duration during complex transaction processing. Extensions prevent premature lock expiry while maintaining bounded lock times.

**Lock Extension Rules:**

- Initial lock: 30 seconds (normal) or 60 seconds (cross-shard)
- Extension duration: 30 seconds per extension
- Maximum extensions: 3 extensions allowed
- Maximum total lock time: 2 minutes (initial + all extensions)
- Extension justification: Coordinator must log reason for extension

**Lock Extension Protocol:**

```go
// Lock extension handler
type LockExtension struct {
    utxoID       UTXOID
    currentTTL   time.Time
    extensions   int           // Count of extensions
    maxExtensions int          // 3
    justification string       // Why extension is needed
}

// ExtendLock increases lock TTL by 30 seconds
func (le *LockExtension) ExtendLock(reason string) error {
    if le.extensions >= le.maxExtensions {
        return ErrMaxExtensionsReached{
            UTXO:       le.utxoID,
            Extensions: le.extensions,
            MaxAllowed: le.maxExtensions,
        }
    }

    // Extend TTL
    newTTL := le.currentTTL.Add(LockExtensionDuration)

    // Verify total lock time doesn't exceed maximum
    totalLockTime := time.Until(newTTL)
    if totalLockTime > MaxTotalLockTime {
        return ErrMaxLockTimeExceeded{
            UTXO:          le.utxoID,
            RequestedTime: totalLockTime,
            MaxAllowed:    MaxTotalLockTime,
        }
    }

    // Update lock in DHT
    if err := updateLockTTL(le.utxoID, newTTL); err != nil {
        return fmt.Errorf("lock TTL update failed: %w", err)
    }

    // Log justification
    logLockExtension(&LockExtensionEvent{
        UTXO:          le.utxoID,
        OldTTL:        le.currentTTL,
        NewTTL:        newTTL,
        ExtensionNum:  le.extensions + 1,
        Justification: reason,
        Timestamp:     time.Now(),
    })

    le.currentTTL = newTTL
    le.extensions++
    le.justification = reason

    return nil
}
```

**Lock Expiry Mid-Processing:**

If a lock expires while a transaction is being processed, the transaction must be aborted and cleanup initiated.

```go
// Lock expiry handler
type LockExpiryHandler struct {
    monitoredLocks map[UTXOID]*LockMonitor
    mu             sync.RWMutex
}

// MonitorLock tracks lock TTL and aborts on expiry
func (leh *LockExpiryHandler) MonitorLock(
    ctx context.Context,
    utxoID UTXOID,
    initialTTL time.Time,
    processingFn func() error,
) error {
    // Create cancellable context that expires with lock TTL
    lockCtx, cancel := context.WithDeadline(ctx, initialTTL)
    defer cancel()

    // Execute processing with lock monitoring
    errCh := make(chan error, 1)
    go func() {
        errCh <- processingFn()
    }()

    select {
    case err := <-errCh:
        // Processing completed before lock expiry
        return err

    case <-lockCtx.Done():
        // Lock expired during processing
        log.Error("lock expired during transaction processing, aborting",
            "utxo", utxoID,
            "initialTTL", initialTTL)

        // Abort transaction
        abortTransaction(utxoID, "lock_expired")

        // Initiate cleanup
        cleanupExpiredLock(utxoID)

        return ErrLockExpiredDuringProcessing{
            UTXO:       utxoID,
            ExpiredAt:  initialTTL,
        }
    }
}

// cleanupExpiredLock rolls back partial transaction state
func cleanupExpiredLock(utxoID UTXOID) error {
    // Step 1: Release lock from DHT
    if err := releaseLock(utxoID); err != nil {
        log.Error("lock release failed during cleanup", "error", err)
    }

    // Step 2: Rollback any partial state changes
    if err := rollbackPartialTransaction(utxoID); err != nil {
        log.Error("rollback failed during cleanup", "error", err)
        return err
    }

    // Step 3: Return UTXO to available pool
    if err := markUTXOAvailable(utxoID); err != nil {
        log.Error("UTXO availability update failed", "error", err)
        return err
    }

    log.Info("expired lock cleanup complete", "utxo", utxoID)
    return nil
}
```

**Lock Holder Crash Detection:**

If a coordinator crashes while holding a lock, automatic detection and release prevents deadlock.

```go
// Coordinator crash detector
type CoordinatorCrashDetector struct {
    heartbeatInterval time.Duration // 10 seconds
    crashTimeout      time.Duration // 30 seconds
}

// DetectCrash monitors coordinator heartbeats for crash detection
func (ccd *CoordinatorCrashDetector) DetectCrash(
    ctx context.Context,
    coordinatorID NodeID,
    heldLocks []UTXOID,
) {
    lastHeartbeat := time.Now()
    ticker := time.NewTicker(ccd.heartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return

        case <-ticker.C:
            // Check for heartbeat
            if isAlive, timestamp := checkHeartbeat(coordinatorID); isAlive {
                lastHeartbeat = timestamp
                continue
            }

            // No heartbeat received
            if time.Since(lastHeartbeat) > ccd.crashTimeout {
                // Crash detected
                log.Error("coordinator crash detected, releasing locks",
                    "coordinatorID", coordinatorID,
                    "heldLocks", len(heldLocks),
                    "lastHeartbeat", lastHeartbeat)

                // Release all locks held by crashed coordinator
                for _, utxoID := range heldLocks {
                    if err := forceReleaseLock(utxoID, "coordinator_crash"); err != nil {
                        log.Error("force lock release failed",
                            "utxo", utxoID,
                            "error", err)
                    }

                    // Apply rollback log for this UTXO
                    applyRollbackLog(utxoID)
                }

                return
            }
        }
    }
}

// applyRollbackLog executes compensating actions for incomplete transaction
func applyRollbackLog(utxoID UTXOID) error {
    log, err := getTransactionRollbackLog(utxoID)
    if err != nil {
        return fmt.Errorf("rollback log retrieval failed: %w", err)
    }

    for i := len(log.Actions) - 1; i >= 0; i-- {
        action := log.Actions[i]
        if err := action.Undo(); err != nil {
            log.Error("rollback action failed",
                "utxo", utxoID,
                "actionIndex", i,
                "error", err)
            return err
        }
    }

    log.Info("rollback log applied successfully", "utxo", utxoID)
    return nil
}
```

**Lock TTL Extension Summary:**

| Scenario | Action | TTL Impact |
|----------|--------|------------|
| **Normal processing** | No extension needed | 30s expires naturally |
| **Complex transaction** | Extend with justification | +30s per extension (max 3x) |
| **Lock expires mid-process** | Abort transaction, cleanup | Release lock, rollback state |
| **Coordinator crash** | Force release after 30s | Automatic lock release + rollback |
| **Maximum extensions reached** | No further extensions allowed | Transaction must complete or abort |

---

## Telemetry

### Metrics Collection

The telemetry system reports update lifecycle events to the DHT for aggregation.

**TelemetryEvent Structure:**
- Event ID (unique identifier)
- Node ID (source node)
- Package name and version
- Event type and status
- Timestamp and duration
- Error information
- Custom metadata

**Event Types:**

| Type | Status | Records |
|------|--------|---------|
| download_started | downloading | Package name, version, timestamp |
| download_complete | verifying | Duration, file size |
| download_failed | failed | Duration, error message |
| install_success | installed | Duration, current/previous versions |
| install_failed | failed | Duration, error message |
| rollback | rolled_back | Target version, reason |

**Configuration:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| NodeID | string | Required | Unique node identifier |
| Enabled | bool | true | Enable/disable telemetry |
| BatchSize | int | 10 | Events before auto-flush |
| FlushInterval | duration | 30s | Max time between flushes |
| MaxRetries | int | 3 | Retry attempts for failures |

**DHT Key Patterns:**
```
telemetry:{nodeId}:{eventId}                    # Individual events
telemetry:aggregate:{packageName}:{version}     # Aggregated statistics
```

**Retry Backoff:**
1. First attempt fails: 100ms backoff
2. Second retry fails: 200ms backoff
3. Third retry fails: 400ms backoff
4. After MaxRetries: return error, re-queue for next flush

### Privacy Considerations

- No sensitive data in events
- Error messages sanitized
- Metadata limited to operational information
- Event IDs cryptographically random
- Timestamps verified at ingestion
- Node IDs authenticated via DHT

**Rate Limiting (recommended):**
- Per-node event rate limits
- Batch size limits
- Storage quotas

### Monitoring Integration

**Network-Wide Metrics:**
- Update success rate per package/version
- Common failure patterns
- Average installation times
- Rollback frequency
- Network health indicators

**Query Examples:**
```go
// Get all events for a node
events := dht.GetPattern("telemetry:node-123:*")

// Get aggregated stats for a package
stats := dht.Get("telemetry:aggregate:my-package:1.0.0")
```

**Performance Characteristics:**
- Thread-safe concurrent operations
- Lock-free atomic operations where possible
- Mutex protection for event queue
- Pre-allocated slice capacity matches BatchSize
- Minimal allocation during normal operation

---

## Alert Threshold Definitions

This section defines concrete alerting thresholds, escalation paths, and notification channels for operational monitoring.

### Alert Severity Levels

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| **P1 - Critical** | Service degradation or data loss imminent | Immediate (page on-call) | After 5 minutes |
| **P2 - High** | Service degraded but operational | 15 minutes | After 30 minutes |
| **P3 - Medium** | Potential issue requiring investigation | 1 hour | After 4 hours |
| **P4 - Low** | Informational, investigate during business hours | 24 hours | No escalation |

### Partition and Network Health Alerts

#### Alert: PartitionDetected

**Threshold:**
- Reachability < 48% (PartitionEnterThreshold)
- State transition: Any → Partitioned

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Network partition detected
Reachability: {reachability}%
Partition State: PARTITIONED
Visible Peers: {peer_count}
Last State Change: {time_since_change}
Action Required: Monitor for recovery, investigate network connectivity
```

**Escalation Path:**
1. Immediate: Page on-call SRE
2. +5 minutes: Escalate to senior SRE
3. +15 minutes: Escalate to engineering manager
4. +30 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page
- Slack: #alerts-critical
- Email: oncall-sre@example.com
- SMS: On-call phone

**Auto-remediation:**
- None (requires manual investigation)

---

#### Alert: SplitBrainDetected

**Threshold:**
- Reachability 48-52% (in dead zone)
- isSplitBrain() returns true
- State transition: → SplitBrain

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Split-brain network partition detected
Reachability: {reachability}%
Partition State: SPLIT_BRAIN
VRF Winner: {winner_partition_id}
This Partition Role: {winner|loser}
Action Required: Monitor resolution, verify coordinator availability
```

**Escalation Path:**
1. Immediate: Page on-call SRE + Network engineer
2. +5 minutes: Escalate to senior SRE + senior network engineer
3. +15 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page (2 recipients)
- Slack: #alerts-critical, #network-ops
- Email: oncall-sre@example.com, network-oncall@example.com
- SMS: On-call phones

**Auto-remediation:**
- Automatic VRF-based winner selection
- Log split-brain resolution decision

---

#### Alert: NetworkDegraded

**Threshold:**
- Reachability 52-80%
- State transition: Healthy → Degraded

**Severity:** P2 - High

**Alert Message:**
```
WARNING: Network in degraded state
Reachability: {reachability}%
Partition State: DEGRADED
Trend: {improving|stable|degrading}
Duration in State: {time_in_state}
Action Required: Monitor for further degradation
```

**Escalation Path:**
1. +15 minutes: Notify on-call SRE (non-page)
2. +30 minutes: Page on-call SRE
3. +1 hour: Escalate to senior SRE

**Channels:**
- Slack: #alerts-high-priority
- Email: oncall-sre@example.com
- PagerDuty: Alert (non-page initially)

**Auto-remediation:**
- None

---

#### Alert: IndeterminateStateExtended

**Threshold:**
- State: Indeterminate
- Duration in state > 10 minutes

**Severity:** P2 - High

**Alert Message:**
```
WARNING: Node in indeterminate state for extended period
Reachability: {reachability}% (oscillating in dead zone)
Duration: {duration}
Oscillation Count: {oscillation_count}
Action Required: Investigate network instability
```

**Escalation Path:**
1. +15 minutes: Notify on-call SRE
2. +30 minutes: Escalate to senior SRE

**Channels:**
- Slack: #alerts-high-priority
- Email: oncall-sre@example.com

**Auto-remediation:**
- If oscillation count >= 3: Enter stabilization mode (automatic)

---

### Resource and Performance Alerts

#### Alert: MemoryHighUsage

**Threshold:**
- Memory usage > 80% of limit

**Severity:** P3 - Medium

**Alert Message:**
```
WARNING: High memory usage detected
Usage: {usage_mb} MB ({usage_percent}%)
Limit: {limit_mb} MB
Node: {node_id}
Action Required: Monitor for memory leak, consider restart if exceeds 90%
```

**Escalation Path:**
1. +1 hour: Notify on-call SRE
2. +4 hours: Escalate to senior SRE

**Channels:**
- Slack: #alerts-medium-priority
- Email: oncall-sre@example.com

**Auto-remediation:**
- If usage > 95%: Trigger graceful restart (automatic)

---

#### Alert: MemoryCritical

**Threshold:**
- Memory usage > 95% of limit

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Memory usage critical
Usage: {usage_mb} MB ({usage_percent}%)
Limit: {limit_mb} MB
Node: {node_id}
Action Required: Immediate restart recommended
```

**Escalation Path:**
1. Immediate: Page on-call SRE
2. +5 minutes: Escalate to senior SRE

**Channels:**
- PagerDuty: Immediate page
- Slack: #alerts-critical
- Email: oncall-sre@example.com

**Auto-remediation:**
- Trigger graceful restart (automatic after 2 minute delay)

---

#### Alert: GoroutineLeakDetected

**Threshold:**
- Goroutine count > 10,000
- Goroutine count increasing > 100/minute for 5 minutes

**Severity:** P2 - High

**Alert Message:**
```
WARNING: Goroutine leak detected
Current Count: {goroutine_count}
Rate of Increase: {increase_rate}/minute
Node: {node_id}
Action Required: Investigate goroutine leak, restart may be required
```

**Escalation Path:**
1. +15 minutes: Notify on-call SRE
2. +30 minutes: Page on-call SRE
3. +1 hour: Escalate to engineering

**Channels:**
- Slack: #alerts-high-priority
- Email: oncall-sre@example.com

**Auto-remediation:**
- If count > 50,000: Trigger graceful restart (automatic)

---

#### Alert: DiskSpaceLow

**Threshold:**
- Available disk space < 10 GB
- Available disk space < 10% of total

**Severity:** P2 - High

**Alert Message:**
```
WARNING: Low disk space
Available: {available_gb} GB ({available_percent}%)
Total: {total_gb} GB
Node: {node_id}
Action Required: Cleanup old data or expand storage
```

**Escalation Path:**
1. +15 minutes: Notify on-call SRE
2. +1 hour: Escalate to senior SRE + storage team

**Channels:**
- Slack: #alerts-high-priority, #storage-ops
- Email: oncall-sre@example.com, storage-oncall@example.com

**Auto-remediation:**
- Trigger log rotation (automatic)
- Cleanup temporary files (automatic)

---

### Coordinator and Consensus Alerts

#### Alert: CoordinatorQuorumLost

**Threshold:**
- Reachable coordinators < 14 (out of 21)
- Duration > 30 seconds

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Coordinator quorum lost
Reachable: {reachable_coordinators}/21
Required: 14 (quorum)
Transaction Processing: FROZEN
Action Required: Immediate investigation of coordinator availability
```

**Escalation Path:**
1. Immediate: Page on-call SRE + on-call coordinator operator
2. +5 minutes: Escalate to senior SRE + engineering manager
3. +15 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page (multiple recipients)
- Slack: #alerts-critical, #coordinator-ops
- Email: oncall-sre@example.com, coordinator-oncall@example.com
- SMS: On-call phones

**Auto-remediation:**
- None (requires manual investigation)

---

#### Alert: ViewChangeCircuitBreakerTripped

**Threshold:**
- View changes >= 7 within CircuitBreakerReset period (10 minutes)

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: View change circuit breaker tripped
Consecutive Changes: {consecutive_changes}
Max Allowed: 7
Consensus Status: ABORTED
Action Required: Manual intervention required, investigate Byzantine behavior
```

**Escalation Path:**
1. Immediate: Page on-call SRE + coordinator operator + engineering lead
2. +5 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page (multiple recipients)
- Slack: #alerts-critical, #consensus-ops
- Email: oncall-sre@example.com, consensus-oncall@example.com
- SMS: On-call phones

**Auto-remediation:**
- Consensus aborted (automatic)
- Requires manual circuit breaker reset with operator signature

---

### Gray Zone and Recovery Alerts

#### Alert: GrayZoneTimeout

**Threshold:**
- Gray zone duration > 5 minutes (GrayZoneMaxDuration)

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Gray zone timeout exceeded
Duration: {duration}
Max Allowed: 5 minutes
Conflicts Detected: {conflict_count}
Rollback Status: {in_progress|completed|failed}
Action Required: Investigate reconciliation failure
```

**Escalation Path:**
1. Immediate: Page on-call SRE
2. +5 minutes: Escalate to senior SRE + engineering
3. +15 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page
- Slack: #alerts-critical, #partition-recovery
- Email: oncall-sre@example.com

**Auto-remediation:**
- Automatic rollback triggered (see rollbackGrayZoneChanges)

---

#### Alert: UncertainTransactionsDetected

**Threshold:**
- Uncertain transaction count > 0 after gray zone rollback

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Uncertain transactions detected after rollback
Count: {uncertain_tx_count}
Transaction IDs: {tx_id_list}
Action Required: Manual reconciliation required for uncertain transactions
```

**Escalation Path:**
1. Immediate: Page on-call SRE + financial operations
2. +5 minutes: Escalate to engineering manager

**Channels:**
- PagerDuty: Immediate page
- Slack: #alerts-critical, #finance-ops
- Email: oncall-sre@example.com, finops@example.com

**Auto-remediation:**
- None (requires manual reconciliation)

---

#### Alert: GrayZoneMaxAttemptsExceeded

**Threshold:**
- Gray zone entry attempts >= 3 for same partition event

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: Gray zone max attempts exceeded
Attempts: 3
Partition Event: {partition_event_id}
Last Failure: {last_failure_reason}
Action Required: Manual intervention required, investigate persistent conflicts
```

**Escalation Path:**
1. Immediate: Page senior SRE + engineering lead
2. +5 minutes: Incident commander activated

**Channels:**
- PagerDuty: Immediate page
- Slack: #alerts-critical, #engineering
- Email: oncall-sre@example.com, engineering-leads@example.com

**Auto-remediation:**
- Gray zone entry blocked (automatic)
- Requires manual investigation and reset

---

### TPM and Security Alerts

#### Alert: TPMQuoteVerificationFailed

**Threshold:**
- TPM quote verification failures > 5 in 1 minute

**Severity:** P1 - Critical

**Alert Message:**
```
CRITICAL: TPM quote verification failures detected
Failure Count: {failure_count}
Node ID: {node_id}
Potential Security Issue: Byzantine behavior or compromised TPM
Action Required: Immediate investigation, potential node quarantine
```

**Escalation Path:**
1. Immediate: Page security on-call + SRE on-call
2. +5 minutes: Escalate to security team lead + engineering manager
3. +15 minutes: Security incident response team activated

**Channels:**
- PagerDuty: Immediate page (security + SRE)
- Slack: #security-incidents, #alerts-critical
- Email: security-oncall@example.com, oncall-sre@example.com
- SMS: Security on-call phone

**Auto-remediation:**
- Node quarantined from consensus (automatic)
- Reject all transactions from node (automatic)

---

### Alert Threshold Summary Table

| Alert Name | Metric | Threshold | Severity | Response Time | Auto-Remediation |
|------------|--------|-----------|----------|---------------|------------------|
| PartitionDetected | Reachability | < 48% | P1 | Immediate | None |
| SplitBrainDetected | Reachability | 48-52% + split-brain | P1 | Immediate | VRF winner selection |
| NetworkDegraded | Reachability | 52-80% | P2 | 15 min | None |
| IndeterminateStateExtended | Time in state | > 10 min | P2 | 15 min | Stabilization mode |
| MemoryHighUsage | Memory % | > 80% | P3 | 1 hour | None |
| MemoryCritical | Memory % | > 95% | P1 | Immediate | Graceful restart |
| GoroutineLeakDetected | Goroutine count | > 10k, +100/min | P2 | 15 min | Restart at 50k |
| DiskSpaceLow | Available space | < 10 GB or 10% | P2 | 15 min | Log rotation, cleanup |
| CoordinatorQuorumLost | Reachable coordinators | < 14/21 | P1 | Immediate | None |
| ViewChangeCircuitBreakerTripped | View changes | >= 7 in 10 min | P1 | Immediate | Consensus abort |
| GrayZoneTimeout | Gray zone duration | > 5 min | P1 | Immediate | Automatic rollback |
| UncertainTransactionsDetected | Uncertain TX count | > 0 | P1 | Immediate | None |
| GrayZoneMaxAttemptsExceeded | Gray zone attempts | >= 3 | P1 | Immediate | Entry blocked |
| TPMQuoteVerificationFailed | Verification failures | > 5/min | P1 | Immediate | Node quarantine |

---

### Notification Channels Configuration

**PagerDuty Integration:**
```yaml
pagerduty:
  api_key: ${PAGERDUTY_API_KEY}
  service_key: ${PAGERDUTY_SERVICE_KEY}
  escalation_policy: "SRE On-Call"
  urgency_mapping:
    P1: high
    P2: low
    P3: low
    P4: low
```

**Slack Integration:**
```yaml
slack:
  webhook_url: ${SLACK_WEBHOOK_URL}
  channels:
    critical: "#alerts-critical"
    high: "#alerts-high-priority"
    medium: "#alerts-medium-priority"
    low: "#alerts-low-priority"
    security: "#security-incidents"
    partition: "#partition-recovery"
    coordinator: "#coordinator-ops"
```

**Email Configuration:**
```yaml
email:
  smtp_host: smtp.example.com
  smtp_port: 587
  from: "alerts@letstrust.net"
  recipients:
    oncall_sre: oncall-sre@example.com
    senior_sre: senior-sre@example.com
    security: security-oncall@example.com
    finops: finops@example.com
```

**SMS Configuration:**
```yaml
sms:
  provider: twilio
  account_sid: ${TWILIO_ACCOUNT_SID}
  auth_token: ${TWILIO_AUTH_TOKEN}
  from_number: "+1234567890"
  recipients:
    oncall_sre: "+1234567891"
    security_oncall: "+1234567892"
```

---

### Alert Testing and Validation

All alert thresholds must be tested quarterly using controlled scenarios:

1. **Partition Testing:** Simulate network partition using network isolation
2. **Memory Testing:** Gradual memory allocation to trigger thresholds
3. **Goroutine Testing:** Intentional goroutine leak to verify detection
4. **Coordinator Testing:** Coordinator node shutdown to test quorum alerts
5. **Gray Zone Testing:** Controlled conflict injection to test gray zone alerts

Test results must be documented and reviewed by SRE and engineering teams

---

### Structured Logging Format

All platform components use structured JSON logging with correlation IDs for distributed tracing and analysis.

#### Log Entry Structure

```go
// StructuredLogEntry defines the canonical log format
type StructuredLogEntry struct {
    // Required fields
    Timestamp     time.Time `json:"timestamp"`      // ISO 8601 format
    Level         string    `json:"level"`          // DEBUG, INFO, WARN, ERROR, FATAL
    Message       string    `json:"message"`        // Human-readable message
    Component     string    `json:"component"`      // Source component name
    NodeID        string    `json:"node_id"`        // Truncated node ID (first 16 hex chars)

    // Correlation fields
    CorrelationID string    `json:"correlation_id"` // Request/operation correlation ID
    TraceID       string    `json:"trace_id,omitempty"`  // Distributed tracing ID
    SpanID        string    `json:"span_id,omitempty"`   // Span within trace

    // Context fields
    RequestID     string    `json:"request_id,omitempty"`
    TransactionID string    `json:"tx_id,omitempty"`
    BlockHeight   uint64    `json:"block_height,omitempty"`
    PartitionID   string    `json:"partition_id,omitempty"`

    // Error fields
    ErrorCode     string    `json:"error_code,omitempty"`
    ErrorMessage  string    `json:"error_message,omitempty"`
    StackTrace    string    `json:"stack_trace,omitempty"`

    // Metrics fields
    DurationMs    float64   `json:"duration_ms,omitempty"`
    BytesProcessed int64    `json:"bytes_processed,omitempty"`

    // Custom fields
    Extra         map[string]interface{} `json:"extra,omitempty"`
}
```

#### Example Log Entries

**Normal Operation:**
```json
{
    "timestamp": "2026-01-10T15:04:05.123Z",
    "level": "INFO",
    "message": "Transaction committed successfully",
    "component": "consensus",
    "node_id": "a1b2c3d4e5f67890",
    "correlation_id": "req-abc123",
    "tx_id": "tx-def456",
    "block_height": 1234567,
    "duration_ms": 45.2
}
```

**Partition Event:**
```json
{
    "timestamp": "2026-01-10T15:04:05.123Z",
    "level": "WARN",
    "message": "Network partition detected",
    "component": "partition_detector",
    "node_id": "a1b2c3d4e5f67890",
    "correlation_id": "partition-event-789",
    "extra": {
        "reachability_percent": 45.2,
        "partition_state": "PARTITIONED",
        "visible_coordinators": 12,
        "required_coordinators": 14
    }
}
```

**Error with Stack Trace:**
```json
{
    "timestamp": "2026-01-10T15:04:05.123Z",
    "level": "ERROR",
    "message": "FROST signing failed",
    "component": "frost_pool",
    "node_id": "a1b2c3d4e5f67890",
    "correlation_id": "sign-req-999",
    "error_code": "FROST_THRESHOLD_NOT_MET",
    "error_message": "Only 10 of 14 required participants responded",
    "extra": {
        "pool_id": "Ed25519",
        "participants_responded": 10,
        "threshold": 14,
        "timeout_seconds": 30
    }
}
```

#### Correlation ID Propagation

Correlation IDs are propagated across all components for request tracing:

```go
// CorrelationContext carries correlation IDs through the system
type CorrelationContext struct {
    CorrelationID string // Primary correlation ID
    TraceID       string // Distributed trace ID (optional)
    SpanID        string // Current span ID (optional)
    ParentSpanID  string // Parent span ID (optional)
}

// Example: Propagating correlation through gRPC interceptor
func UnaryServerInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    // Extract or generate correlation ID
    correlationID := extractCorrelationID(ctx)
    if correlationID == "" {
        correlationID = generateCorrelationID()
    }

    // Add to context
    ctx = context.WithValue(ctx, correlationIDKey, correlationID)

    // Log incoming request
    log.Info("incoming request",
        "correlation_id", correlationID,
        "method", info.FullMethod)

    // Execute handler
    resp, err := handler(ctx, req)

    // Log completion
    log.Info("request completed",
        "correlation_id", correlationID,
        "method", info.FullMethod,
        "error", err)

    return resp, err
}
```

#### Log Level Guidelines

| Level | Use Case | Examples |
|-------|----------|----------|
| **DEBUG** | Detailed diagnostic information | Variable values, intermediate states |
| **INFO** | Normal operational events | Startup, config loaded, block committed |
| **WARN** | Unexpected but recoverable events | Degraded state, retry needed, timeout |
| **ERROR** | Failure requiring attention | Transaction failed, connection lost |
| **FATAL** | Unrecoverable failure | Process termination, data corruption |

---

### Operational Runbook References

This section provides quick reference to operational runbooks for common scenarios.

#### Runbook Index

| Runbook ID | Title | Section Reference | Severity |
|------------|-------|-------------------|----------|
| **RB-001** | Coordinator Initialization | Deployment Runbooks > Coordinator Initialization | N/A |
| **RB-002** | Network Bootstrap (Genesis) | Deployment Runbooks > Network Bootstrap Procedure | N/A |
| **RB-003** | Coordinator Failover | Deployment Runbooks > Coordinator Failover | Critical |
| **RB-004** | Rolling Upgrade | Rolling Upgrade Procedure | High |
| **RB-005** | Network Partition Recovery | Recovery Procedures > Network Partition Recovery | Critical |
| **RB-006** | Coordinator Quorum Loss | Recovery Procedures > Coordinator Quorum Loss | Critical |
| **RB-007** | Gray Zone Reconciliation | Recovery Procedures > Gray Zone Reconciliation | Critical |
| **RB-008** | Node Recovery | Recovery Procedures > Node Recovery Procedure | Medium |
| **RB-009** | TPM Attestation Failure | Recovery Procedures > TPM Attestation Failure | Critical |
| **RB-010** | Memory Exhaustion | Recovery Procedures > Memory Exhaustion | High |
| **RB-011** | Disk Space Exhaustion | Recovery Procedures > Disk Space Exhaustion | High |
| **RB-012** | Disaster Recovery | Disaster Recovery Procedures | Critical |

#### Key Metrics Quick Reference

| Metric Category | Key Metrics | Alert Threshold | Runbook |
|-----------------|-------------|-----------------|---------|
| **Partition** | `reachability_percent` | <48% | RB-005 |
| **Partition** | `partition_state_changes` | >3/hour | RB-005 |
| **Coordinator** | `coordinator_reachable_count` | <14/21 | RB-003, RB-006 |
| **Coordinator** | `frost_signature_failures` | >3 consecutive | RB-003 |
| **DKG** | `dkg_round_failures` | >0 | RB-003 |
| **Consensus** | `view_change_count` | >7 in 10min | RB-006 |
| **Gray Zone** | `gray_zone_duration` | >5 minutes | RB-007 |
| **Reputation** | `reputation_violations` | >5/hour | RB-008 |
| **Resource** | `memory_usage_percent` | >95% | RB-010 |
| **Resource** | `disk_available_gb` | <10 GB | RB-011 |

---

## Deployment Runbooks

This section provides step-by-step procedures for deploying and managing the go-trusted-platform network infrastructure.

### Coordinator Initialization Procedure

**Prerequisites:**
- TPM 2.0 hardware provisioned and verified
- Network connectivity to existing coordinators (if not genesis)
- Valid TLS certificates issued by platform CA
- Minimum 16 GB RAM, 4 CPU cores, 500 GB SSD

**Responsible Party:** Infrastructure Team + Security Team

**Timing Constraints:**
- Total initialization: 15-30 minutes
- DKG participation window: 10 minutes
- FROST key share generation: 2-5 minutes

#### Step 1: Pre-flight Checks (5 minutes)

```bash
# Verify TPM availability
platformctl tpm status --verify-quote

# Verify network connectivity to existing coordinators
platformctl coordinator ping --all

# Verify system requirements
platformctl system check --coordinator-requirements

# Verify certificate chain
platformctl certs verify --chain
```

**Expected Output:**
- TPM: "Quote verified successfully"
- Network: "All coordinators reachable (21/21)"
- System: "All requirements met"
- Certs: "Certificate chain valid"

**Rollback:** If any check fails, do not proceed. Address the issue before continuing.

#### Step 2: Generate Coordinator Identity (2 minutes)

```bash
# Generate coordinator keypair bound to TPM
platformctl coordinator init --tpm-bind \
    --region us-east-1 \
    --datacenter dc1

# Register coordinator with network
platformctl coordinator register --await-confirmation
```

**Expected Output:**
- "Coordinator identity generated: coord-XXXX"
- "Registration confirmed by 14/21 coordinators"

**Rollback:** If registration fails, run `platformctl coordinator deregister --force` and retry.

#### Step 3: Join Coordinator Pool (5-10 minutes)

```bash
# Request pool membership
platformctl coordinator join-pool \
    --pool-type frost \
    --algorithms "Ed25519,P256"

# Wait for existing coordinators to approve
platformctl coordinator await-approval --timeout 10m
```

**Expected Output:**
- "Pool join request submitted"
- "Approval received from 14/21 coordinators"
- "Pool membership confirmed"

**Rollback:** Run `platformctl coordinator leave-pool --force` if timeout occurs.

#### Step 4: Participate in DKG (5-10 minutes)

```bash
# Participate in Distributed Key Generation
platformctl dkg participate --round current \
    --timeout 10m \
    --verbose

# Verify key share received
platformctl dkg verify-share --pool Ed25519
platformctl dkg verify-share --pool P256
```

**Expected Output:**
- "DKG round started, participants: 21"
- "Round 1/3 complete"
- "Round 2/3 complete"
- "Round 3/3 complete"
- "Key shares received and verified"

**Rollback:** If DKG fails, the round will be restarted automatically. Do not manually intervene unless directed by incident commander.

#### Step 5: Enable Consensus Participation (2 minutes)

```bash
# Enable consensus voting
platformctl coordinator enable-consensus

# Verify participation in first block
platformctl coordinator status --await-first-vote --timeout 5m
```

**Expected Output:**
- "Consensus participation enabled"
- "First vote cast for block #XXXXXX"

**Rollback:** Run `platformctl coordinator disable-consensus` if issues occur.

#### Post-Initialization Verification

| Check | Command | Expected Result |
|-------|---------|-----------------|
| Pool membership | `platformctl coordinator pools` | "Member of Ed25519, P256 pools" |
| FROST threshold | `platformctl frost status` | "Threshold: 14/21" |
| Consensus status | `platformctl consensus status` | "Active, last vote: <30s ago" |
| Peer connectivity | `platformctl coordinator peers` | "Connected: 20/20" |

---

### Network Bootstrap Procedure (Genesis)

**Prerequisites:**
- Minimum 21 coordinator nodes provisioned
- Genesis configuration file prepared
- Multi-signature quorum for foundation wallet (3-of-5)
- Multi-signature quorum for treasury wallet (5-of-9)

**Responsible Party:** Founding Team + Security Team + Legal/Compliance

**Timing Constraints:**
- Genesis block creation: 10 minutes
- Initial DKG: 15-20 minutes
- Network stabilization: 1 hour

#### Phase 1: Genesis Configuration (Pre-Launch)

```yaml
# genesis-config.yaml
network:
  name: "trusted-platform-mainnet"
  chain_id: 1
  genesis_time: "2026-02-01T00:00:00Z"

supply:
  total: 100000000
  foundation_allocation: 10000000
  treasury_allocation: 15000000
  rewards_pool: 75000000

coordinators:
  initial_count: 21
  quorum_threshold: 14
  geographic_distribution:
    - region: us-east
      count: 5
    - region: us-west
      count: 4
    - region: eu-west
      count: 4
    - region: eu-central
      count: 4
    - region: ap-northeast
      count: 4

bootstrap_period:
  min_duration_days: 180
  min_active_nodes: 10000
  min_service_providers: 1000
  min_uptime_percent: 99.0
  reward_multiplier: 2.0
```

**Verification:** Run `platformctl genesis validate --config genesis-config.yaml`

#### Phase 2: Coordinator Initialization (Day 0, T-2 hours)

```bash
# On each of 21 coordinator nodes (parallel execution)
platformctl coordinator init --genesis \
    --config genesis-config.yaml \
    --coordinator-index ${COORDINATOR_INDEX}

# All coordinators must complete within window
```

**Expected Timeline:**
| Time | Action |
|------|--------|
| T-2:00 | Begin coordinator initialization |
| T-1:45 | All 21 coordinators initialized |
| T-1:30 | Network connectivity verified |
| T-1:00 | DKG ceremony begins |
| T-0:30 | DKG complete, FROST pools ready |
| T-0:15 | Genesis block prepared |
| T-0:00 | Genesis block signed and published |

#### Phase 3: Genesis DKG Ceremony (Day 0, T-1 hour)

```bash
# Coordinator 0 initiates DKG
platformctl dkg initiate --genesis \
    --participants 21 \
    --threshold 14 \
    --algorithms "Ed25519,P256"

# All coordinators participate
platformctl dkg participate --genesis --round 0
```

**Verification Checkpoints:**
1. All 21 participants registered
2. Round 1 commitments received (21/21)
3. Round 2 shares distributed (21/21)
4. Round 3 complaints resolved (0 complaints expected)
5. Public keys published to all coordinators

#### Phase 4: Genesis Block Creation (Day 0, T-0)

```bash
# Coordinator quorum signs genesis block
platformctl genesis create \
    --config genesis-config.yaml \
    --sign-quorum

# Broadcast genesis block
platformctl genesis broadcast --await-confirmation
```

**Expected Output:**
- "Genesis block #0 created"
- "Hash: 0xABCD..."
- "Merkle root: 0xEFGH..."
- "Signatures: 14/21 coordinators"
- "Broadcast confirmed by 21/21 coordinators"

#### Phase 5: Network Expansion (Days 1-180)

**First Nodes (Day 1-7):**
```bash
# New nodes bootstrap from coordinators
platformctl node init --bootstrap-from coordinators

# Nodes request attestation
platformctl node attest --tpm

# Begin reputation building
platformctl node enable-services
```

**Monitoring Milestones:**
| Day | Target Nodes | Target Providers | Action |
|-----|--------------|------------------|--------|
| 7 | 100 | 10 | Verify stability |
| 30 | 1,000 | 100 | First metrics review |
| 90 | 5,000 | 500 | Mid-bootstrap assessment |
| 180 | 10,000 | 1,000 | Bootstrap period evaluation |

**Rollback:** Genesis cannot be rolled back. If critical issues occur within first 24 hours, emergency consensus halt and network restart may be required per Emergency Procedures.

---

### Coordinator Failover Procedure

**Prerequisites:**
- Coordinator quorum maintained (>= 14/21)
- Replacement coordinator hardware provisioned
- TPM attestation verified on new hardware

**Responsible Party:** SRE On-Call + Coordinator Operations

**Timing Constraints:**
- Detection to acknowledgment: 5 minutes
- Failover initiation: 15 minutes
- Full replacement: 1 hour
- DKG key share refresh: 2 hours (scheduled)

#### Detection Phase

**Automated Detection:**

| Metric | Threshold | Alert Level |
|--------|-----------|-------------|
| Coordinator heartbeat | Missing > 30s | P2 - High |
| Coordinator heartbeat | Missing > 2min | P1 - Critical |
| FROST signature participation | Missed > 3 rounds | P2 - High |
| TPM attestation | Failed verification | P1 - Critical |

**Detection Sources:**
1. **Health Check Monitoring:** `/health` endpoint returns non-200 for >30 seconds
2. **Heartbeat Protocol:** Peer coordinators detect missing heartbeats
3. **FROST Participation:** Missed signature threshold contribution
4. **Network Partition:** Coordinator unreachable by >50% of peers

**Alert Notification:**
```
CRITICAL: Coordinator failover required
Coordinator ID: coord-XXXX
Last Seen: 2026-01-10T15:04:05Z
Reason: Heartbeat timeout (>2 minutes)
Quorum Status: 20/21 reachable (quorum maintained)
Action Required: Initiate failover procedure
```

#### Assessment Phase

**Severity Classification:**

| Condition | Severity | Action |
|-----------|----------|--------|
| Single coordinator unreachable, quorum maintained | Medium | Schedule replacement, no emergency |
| Multiple coordinators unreachable, quorum at risk | High | Immediate failover for one coordinator |
| Quorum lost (< 14 coordinators) | Critical | Emergency recovery procedure |
| TPM attestation failure | Critical | Security investigation + replacement |

**Impact Analysis:**

```bash
# Check current quorum status
platformctl coordinator quorum-status

# Identify affected FROST pools
platformctl frost pool-status --detailed

# Check pending transactions
platformctl transaction pending --coordinator coord-XXXX
```

**Expected Assessment Output:**
- Quorum status: "Maintained (20/21)" or "At Risk (14/21)" or "Lost (13/21)"
- Affected pools: List of FROST signing pools where coordinator participates
- Pending transactions: Count of transactions awaiting coordinator signature

#### Recovery Phase - Coordinator Replacement

**Step 1: Isolate Failed Coordinator (2 minutes)**

```bash
# Mark coordinator as failed (requires quorum approval)
platformctl coordinator mark-failed coord-XXXX \
    --reason "heartbeat-timeout" \
    --approval-quorum

# Verify isolation
platformctl coordinator status coord-XXXX
```

**Expected Output:** "Coordinator coord-XXXX marked as FAILED, excluded from consensus"

**Step 2: Provision Replacement (10-15 minutes)**

Follow the Coordinator Initialization Procedure above with these additions:

```bash
# Initialize as replacement for failed coordinator
platformctl coordinator init --tpm-bind \
    --replace coord-XXXX \
    --region ${SAME_REGION}
```

**Step 3: Key Share Handoff (30-60 minutes)**

```bash
# Initiate proactive secret sharing refresh
platformctl dkg refresh --exclude coord-XXXX \
    --new-participant coord-YYYY \
    --pools "Ed25519,P256"

# Verify new shares distributed
platformctl dkg verify-share --coordinator coord-YYYY
```

**Expected Output:**
- "DKG refresh initiated, excluding coord-XXXX"
- "New participant coord-YYYY included"
- "Key shares redistributed to 21 coordinators"
- "FROST threshold maintained: 14/21"

**Step 4: Enable Replacement in Consensus (5 minutes)**

```bash
# Enable new coordinator
platformctl coordinator enable coord-YYYY --consensus

# Verify participation
platformctl coordinator status coord-YYYY --await-first-vote
```

#### Verification Phase

| Check | Command | Expected Result |
|-------|---------|-----------------|
| Quorum restored | `platformctl coordinator quorum-status` | "21/21 reachable" |
| FROST signing | `platformctl frost test-sign` | "Signature verified" |
| Consensus active | `platformctl consensus status` | "Active, all coordinators" |
| Failed coordinator isolated | `platformctl coordinator list` | "coord-XXXX: RETIRED" |

**Post-Failover Monitoring:**
- Monitor replacement coordinator for 24 hours
- Verify all FROST pools functioning correctly
- Confirm no pending transactions were lost
- Update runbooks with any lessons learned

---

### Rolling Upgrade Procedure

This section defines the comprehensive rolling upgrade procedure for the go-trusted-platform network, including protocol version support policy, upgrade governance, and rollback procedures.

#### Protocol Version Support Policy

The network maintains backward compatibility to ensure smooth upgrades:

**Version Support Matrix:**

| Protocol Version | Support Status | End of Support |
|------------------|----------------|----------------|
| Current (N) | Full support | N/A |
| Previous (N-1) | Full support | 6 months after N+1 release |
| Legacy (N-2) | Limited support | 3 months after N+1 release |
| Deprecated (N-3+) | No support | Immediately after N+1 release |

**Compatibility Requirements:**

```go
// ProtocolVersionPolicy defines version compatibility rules
type ProtocolVersionPolicy struct {
    // Current protocol version
    CurrentVersion  uint32  // e.g., 3

    // Minimum supported version (N-2)
    MinSupportedVersion uint32  // e.g., 1

    // Preferred version for new connections
    PreferredVersion uint32  // Same as CurrentVersion

    // Version negotiation timeout
    NegotiationTimeout time.Duration  // 10 seconds
}

// IsVersionSupported checks if peer version is acceptable
func (p *ProtocolVersionPolicy) IsVersionSupported(peerVersion uint32) bool {
    return peerVersion >= p.MinSupportedVersion &&
           peerVersion <= p.CurrentVersion + 1  // Allow N+1 during upgrades
}

// NegotiateVersion selects protocol version for connection
func (p *ProtocolVersionPolicy) NegotiateVersion(localVer, remoteVer uint32) uint32 {
    if localVer < remoteVer {
        return localVer
    }
    return remoteVer
}
```

**Version Feature Flags:**

| Version | Features | Breaking Changes |
|---------|----------|------------------|
| v1.0.x | Base protocol | N/A (genesis) |
| v1.1.x | Enhanced partition handling | None |
| v1.2.x | Gray zone reconciliation | None |
| v2.0.x | Post-quantum support | Signature format |

#### Upgrade Governance Process

All protocol upgrades follow a structured governance process to ensure network-wide coordination:

**Upgrade Announcement Timeline:**

| Phase | Duration | Action |
|-------|----------|--------|
| **Proposal** | Day 0 | Submit upgrade proposal with specification |
| **Review** | Days 1-14 | Technical review by coordinators and community |
| **Vote** | Days 15-44 | Coordinator vote (14/21 quorum required) |
| **Activation** | Days 45-134 | 90-day activation window for node upgrades |
| **Enforcement** | Day 135+ | Old version connections deprecated |

**Upgrade Proposal Structure:**

```yaml
# upgrade-proposal.yaml
proposal:
  id: "PROP-2026-001"
  title: "Protocol v1.2.0 Upgrade"
  version: "1.2.0"
  author: "platform-engineering"
  created: "2026-01-10"

timeline:
  review_start: "2026-01-10"
  review_end: "2026-01-24"
  vote_start: "2026-01-25"
  vote_end: "2026-02-23"
  activation_start: "2026-02-24"
  activation_end: "2026-05-24"

changes:
  - type: "feature"
    description: "Enhanced partition recovery"
    breaking: false

  - type: "security"
    description: "Improved gray zone reconciliation"
    breaking: false

requirements:
  min_node_version: "1.1.0"
  coordinator_approval: 14
  node_upgrade_threshold: "50%"

rollback_trigger:
  consensus_failure_rate: "5%"
  error_rate_spike: "10x baseline"
  coordinator_quorum_loss: true
```

**Coordinator Voting:**

```bash
# View pending upgrade proposals
platformctl governance proposals --pending

# Review proposal details
platformctl governance proposal PROP-2026-001 --detailed

# Cast vote (requires coordinator key)
platformctl governance vote PROP-2026-001 \
    --decision approve \
    --reason "Security improvements validated" \
    --sign-with-tpm
```

#### Rolling Upgrade Execution

**Prerequisites:**
- New version tested in staging environment
- Upgrade manifest approved by engineering
- Rollback procedures verified
- Maintenance window scheduled (if required)

**Responsible Party:** Platform Engineering + SRE

**Timing Constraints:**
- Per-node upgrade: 5-10 minutes
- Coordinator upgrade (with key refresh): 30-60 minutes
- Full network upgrade: 24-72 hours (rolling)

#### Version Compatibility Matrix

| Current Version | Target Version | Upgrade Path | Notes |
|-----------------|----------------|--------------|-------|
| v1.0.x | v1.0.y | Direct | Patch upgrades, no protocol changes |
| v1.0.x | v1.1.x | Direct | Minor version, backward compatible |
| v1.x | v2.0 | Staged | Major version, requires coordination |

**Compatibility Requirements:**
- Nodes MUST support n-1 and n+1 protocol versions during upgrade window
- Coordinators MUST upgrade after 50% of regular nodes upgraded
- Genesis nodes have no upgrade path (they are always v0)

#### Regular Node Upgrade Procedure

**Step 1: Pre-Upgrade Verification (2 minutes)**

```bash
# Check current version and upgrade eligibility
platformctl version
platformctl upgrade check --target v1.1.0

# Verify node health
platformctl node health --detailed
```

**Expected Output:**
- Current version: v1.0.5
- Target version: v1.1.0 - "Upgrade eligible"
- Health: "All checks passed"

**Step 2: Graceful Drain (2-3 minutes)**

```bash
# Stop accepting new connections
platformctl node drain --timeout 2m

# Wait for in-flight requests to complete
platformctl node await-quiesce --timeout 30s
```

**Expected Output:**
- "Node draining, 15 active connections"
- "All connections closed, node quiesced"

**Step 3: Perform Upgrade (3-5 minutes)**

```bash
# Stop service
systemctl stop platformd

# Upgrade binary
apt-get update && apt-get install platformd=1.1.0

# Verify binary version
platformd --version

# Start service
systemctl start platformd
```

**Step 4: Post-Upgrade Verification (2 minutes)**

```bash
# Verify node rejoined network
platformctl node status --await-ready --timeout 60s

# Verify protocol version negotiation
platformctl node peers --show-versions

# Run smoke tests
platformctl node test --smoke
```

**Rollback Procedure (if verification fails):**

```bash
# Stop service
systemctl stop platformd

# Revert to previous version
apt-get install platformd=1.0.5

# Start service
systemctl start platformd

# Verify rollback successful
platformctl node status
```

#### Coordinator Upgrade Procedure

**Important:** Coordinators MUST be upgraded one at a time to maintain quorum.

**Step 1: Notify Network (5 minutes)**

```bash
# Announce coordinator maintenance
platformctl coordinator announce-maintenance \
    --coordinator coord-XXXX \
    --duration 30m \
    --reason "scheduled-upgrade"

# Verify announcement received
platformctl coordinator maintenance-status
```

**Step 2: Suspend Coordinator (2 minutes)**

```bash
# Temporarily exclude from FROST signing
platformctl coordinator suspend coord-XXXX \
    --frost-pools all \
    --duration 30m

# Verify quorum maintained
platformctl coordinator quorum-status
```

**Expected Output:**
- "Coordinator coord-XXXX suspended from FROST pools"
- "Quorum maintained: 20/21 available (14 required)"

**Step 3: Perform Upgrade (5-10 minutes)**

Follow regular node upgrade procedure above.

**Step 4: Rejoin FROST Pools (5 minutes)**

```bash
# Resume FROST participation
platformctl coordinator resume coord-XXXX --frost-pools all

# Verify key shares still valid
platformctl dkg verify-share --coordinator coord-XXXX

# Test FROST signing
platformctl frost test-sign --coordinator coord-XXXX
```

**Step 5: Resume Full Operations (2 minutes)**

```bash
# End maintenance mode
platformctl coordinator end-maintenance coord-XXXX

# Verify full participation
platformctl coordinator status coord-XXXX
```

**Coordinator Upgrade Sequence:**
1. Upgrade coordinators in regions sequentially (not all in same region at once)
2. Wait 10 minutes between coordinator upgrades to verify stability
3. If any coordinator fails, halt upgrades and investigate
4. Resume only after issue resolved

#### Coordinator Upgrade Order

Coordinators must be upgraded in a specific order to maintain quorum and minimize risk:

**Upgrade Order Priority:**

| Priority | Selection Criteria | Rationale |
|----------|-------------------|-----------|
| 1 | Oldest software version | Most likely to have issues |
| 2 | Lowest uptime | Already unstable, minimize additional risk |
| 3 | Non-leader nodes first | Preserve consensus leadership stability |
| 4 | Geographic distribution | Never upgrade >2 coordinators per region simultaneously |

**Upgrade Sequencing Algorithm:**

```go
// CoordinatorUpgradeOrder determines safe upgrade sequence
type CoordinatorUpgradeOrder struct {
    Coordinators []CoordinatorInfo
}

// SortForUpgrade orders coordinators by upgrade priority
func (o *CoordinatorUpgradeOrder) SortForUpgrade() []CoordinatorInfo {
    sort.Slice(o.Coordinators, func(i, j int) bool {
        // Priority 1: Oldest version first
        if o.Coordinators[i].Version != o.Coordinators[j].Version {
            return o.Coordinators[i].Version < o.Coordinators[j].Version
        }

        // Priority 2: Lowest uptime first
        if o.Coordinators[i].Uptime != o.Coordinators[j].Uptime {
            return o.Coordinators[i].Uptime < o.Coordinators[j].Uptime
        }

        // Priority 3: Non-leaders before leaders
        if o.Coordinators[i].IsLeader != o.Coordinators[j].IsLeader {
            return !o.Coordinators[i].IsLeader
        }

        // Priority 4: Alphabetical by region for consistency
        return o.Coordinators[i].Region < o.Coordinators[j].Region
    })

    return o.Coordinators
}

// ValidateUpgradeOrder ensures quorum maintained throughout
func (o *CoordinatorUpgradeOrder) ValidateUpgradeOrder(sequence []CoordinatorInfo) error {
    regionCounts := make(map[string]int)

    for i, coord := range sequence {
        regionCounts[coord.Region]++

        // Never upgrade more than 2 per region before moving on
        if regionCounts[coord.Region] > 2 {
            return ErrTooManyPerRegion{
                Region:  coord.Region,
                Count:   regionCounts[coord.Region],
                Index:   i,
            }
        }

        // Verify quorum would be maintained
        activeAfter := len(o.Coordinators) - (i + 1)
        if activeAfter < 14 {
            return ErrQuorumAtRisk{
                RemainingActive: activeAfter,
                RequiredQuorum:  14,
            }
        }
    }

    return nil
}
```

**Step-by-Step Coordinator Upgrade:**

```bash
# 1. Generate upgrade order
platformctl coordinator upgrade-order --target-version 1.2.0

# 2. Review and approve order
platformctl coordinator upgrade-order --approve

# 3. Begin sequential upgrades (automated with manual gates)
platformctl coordinator upgrade-batch --batch-size 1 \
    --verification-wait 10m \
    --manual-approval-required
```

#### Upgrade Verification Steps

At each stage of the rolling upgrade, verification must confirm system stability:

**Per-Node Verification (5 minutes):**

| Check | Command | Pass Criteria |
|-------|---------|---------------|
| Version | `platformctl version` | Matches target |
| Health | `platformctl health` | All checks pass |
| Peers | `platformctl peers --count` | >90% baseline |
| Latency | `platformctl latency --p99` | <500ms |

**Per-Batch Verification (10 minutes):**

| Check | Command | Pass Criteria |
|-------|---------|---------------|
| Consensus | `platformctl consensus status` | Active, no failures |
| FROST signing | `platformctl frost test-sign` | Success |
| Transaction throughput | `platformctl tps` | >80% baseline |
| Error rate | `platformctl errors --rate` | <0.1% |

**Verification Script:**

```bash
#!/bin/bash
# upgrade-verification.sh

set -e

echo "=== Upgrade Verification ==="

# Node-level checks
echo "Checking node health..."
platformctl health --detailed || { echo "FAIL: Health check"; exit 1; }

echo "Checking peer connectivity..."
PEERS=$(platformctl peers --count)
if [ "$PEERS" -lt 90 ]; then
    echo "FAIL: Peer count too low ($PEERS)"
    exit 1
fi

# Consensus checks
echo "Checking consensus participation..."
platformctl consensus status --json | jq -e '.active == true' || {
    echo "FAIL: Consensus not active"
    exit 1
}

# FROST signature test
echo "Testing FROST signing..."
platformctl frost test-sign --timeout 30s || {
    echo "FAIL: FROST signing failed"
    exit 1
}

echo "=== All verifications passed ==="
```

#### Rollback Triggers

Automatic rollback is triggered when any of the following conditions are detected:

**Rollback Trigger Conditions:**

| Condition | Threshold | Detection Window | Action |
|-----------|-----------|------------------|--------|
| Consensus failure rate | >5% | 5 minutes | Automatic rollback |
| Error rate spike | >10x baseline | 2 minutes | Automatic rollback |
| Quorum loss | <14 coordinators | Immediate | Emergency halt + rollback |
| FROST signing failures | >3 consecutive | 1 minute | Coordinator rollback |
| Transaction throughput drop | >50% | 5 minutes | Investigation pause |
| P99 latency spike | >5x baseline | 5 minutes | Investigation pause |

**Rollback Decision Tree:**

```
Upgrade Issue Detected
        |
        v
Is quorum at risk? ----YES----> Emergency halt + immediate rollback
        |
        NO
        |
        v
Is error rate >10x? ---YES----> Automatic rollback of last batch
        |
        NO
        |
        v
Is consensus failing? -YES----> Rollback affected coordinators
        |
        NO
        |
        v
Is throughput <50%? ---YES----> Pause upgrades, investigate
        |
        NO
        |
        v
Continue monitoring
```

**Rollback Procedure:**

```bash
# Manual rollback of single node
platformctl node rollback --target-version 1.1.5 \
    --reason "consensus_failure"

# Automatic batch rollback (triggered by monitoring)
platformctl upgrade rollback --batch-id BATCH_001 \
    --automatic \
    --preserve-state

# Emergency coordinator rollback
platformctl coordinator rollback coord-XXXX \
    --emergency \
    --skip-drain
```

**Rollback Verification:**

| Check | Expected Result |
|-------|-----------------|
| Version reverted | Previous stable version |
| Health restored | All checks passing |
| Consensus resumed | Active, no failures |
| Error rate normalized | <0.1% |

---

## Recovery Procedures

This section provides comprehensive procedures for detecting, assessing, recovering from, and verifying resolution of common operational issues.

### Detection Mechanisms

#### Health Check Monitoring

**Endpoint Monitoring:**

| Endpoint | Interval | Timeout | Failure Threshold |
|----------|----------|---------|-------------------|
| `/health` | 10s | 5s | 3 consecutive failures |
| `/ready` | 30s | 5s | 2 consecutive failures |
| `/metrics` | 60s | 10s | 5 consecutive failures |

**Health Check Implementation:**

```yaml
monitoring:
  health_checks:
    - name: liveness
      endpoint: /health
      interval: 10s
      timeout: 5s
      failure_threshold: 3
      success_threshold: 1

    - name: readiness
      endpoint: /ready
      interval: 30s
      timeout: 5s
      failure_threshold: 2
      success_threshold: 2
```

#### Metric-Based Detection

**Threshold Monitoring:**

| Metric | Warning | Critical | Detection Latency |
|--------|---------|----------|-------------------|
| `reachability_percent` | < 80% | < 48% | 60 seconds |
| `consensus_latency_p99` | > 500ms | > 2s | 30 seconds |
| `frost_signature_failures` | > 1/min | > 5/min | 60 seconds |
| `memory_usage_percent` | > 80% | > 95% | 30 seconds |
| `goroutine_count` | > 5000 | > 10000 | 60 seconds |
| `disk_available_percent` | < 20% | < 10% | 300 seconds |

**Anomaly Detection:**

```yaml
anomaly_detection:
  enabled: true
  baseline_window: 7d
  sensitivity: 3.0  # Standard deviations
  metrics:
    - transaction_rate
    - block_time
    - peer_count
    - replication_lag
```

#### Log-Based Detection

**Critical Log Patterns:**

| Pattern | Severity | Action |
|---------|----------|--------|
| `FATAL:` | Critical | Immediate alert |
| `PANIC:` | Critical | Immediate alert + auto-restart |
| `split-brain detected` | Critical | Partition alert |
| `quorum lost` | Critical | Coordinator alert |
| `TPM verification failed` | Critical | Security alert |
| `DKG round failed` | High | Key management alert |

**Log Aggregation Configuration:**

```yaml
logging:
  aggregation:
    endpoint: "https://logs.example.com"
    batch_size: 100
    flush_interval: 5s

  alerts:
    - pattern: "FATAL|PANIC"
      severity: critical
      notification: pagerduty

    - pattern: "partition.*detected|quorum.*lost"
      severity: critical
      notification: pagerduty
```

### Assessment Framework

#### Severity Classification

**Impact Matrix:**

| User Impact | Data Impact | Security Impact | Severity |
|-------------|-------------|-----------------|----------|
| None | None | None | P4 - Low |
| Degraded | None | None | P3 - Medium |
| Partial outage | At risk | None | P2 - High |
| Full outage | Loss possible | Compromise possible | P1 - Critical |

**Severity Definitions:**

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| P1 - Critical | Service unavailable or data loss imminent | Immediate | 5 minutes |
| P2 - High | Service degraded, workaround available | 15 minutes | 30 minutes |
| P3 - Medium | Minor issue, no user impact | 1 hour | 4 hours |
| P4 - Low | Informational, improvement opportunity | 24 hours | None |

#### Impact Analysis Procedure

**Step 1: Scope Determination**

```bash
# Determine affected components
platformctl status --all-components

# Identify affected users/nodes
platformctl impact-analysis --scope

# Check cascading failures
platformctl dependencies --trace
```

**Step 2: Timeline Establishment**

| Question | Command | Purpose |
|----------|---------|---------|
| When did it start? | `platformctl logs --first-error` | Root cause timeline |
| What changed? | `platformctl changes --recent 24h` | Change correlation |
| Who is affected? | `platformctl users --affected` | Impact scope |
| What is broken? | `platformctl health --detailed` | Component status |

**Step 3: Root Cause Hypothesis**

```
1. Review recent changes (deployments, config changes)
2. Check external dependencies (network, DNS, time sync)
3. Analyze error patterns in logs
4. Check resource utilization trends
5. Review security events
```

### Recovery Procedures by Failure Type

#### Network Partition Recovery

**Detection:**
- Reachability < 48% for > 60 seconds
- State transition to PartitionStatePartitioned

**Assessment:**
1. Confirm partition scope: `platformctl partition status`
2. Identify affected coordinators: `platformctl coordinator reachability`
3. Check transaction freeze status: `platformctl transaction status --frozen`

**Recovery Actions:**

| Condition | Action | Timing |
|-----------|--------|--------|
| Partition healing naturally | Monitor and wait | Automatic |
| Network issue identified | Fix network connectivity | Depends on cause |
| Coordinator failure | Initiate failover | 15-30 minutes |
| Split-brain detected | Execute VRF resolution | Automatic |

**Step-by-Step Recovery:**

```bash
# 1. Confirm partition status
platformctl partition status --detailed

# 2. If network issue, coordinate with network team
# [External: Network team troubleshooting]

# 3. Once connectivity restored, monitor recovery
platformctl partition await-healing --timeout 30m

# 4. Verify gray zone reconciliation
platformctl grayzone status

# 5. Confirm all transactions reconciled
platformctl transaction reconciliation-status
```

**Verification:**
- Reachability > 80% sustained for 5 minutes
- State transition to PartitionStateHealthy
- No pending gray zone conflicts
- All transactions processed or properly rejected

#### Coordinator Quorum Loss Recovery

**Detection:**
- Reachable coordinators < 14/21
- FROST signing failures

**Assessment:**
1. Count reachable coordinators: `platformctl coordinator count --reachable`
2. Identify unreachable coordinators: `platformctl coordinator list --unreachable`
3. Determine cause (network, hardware, software)

**Recovery Actions:**

| Coordinators Lost | Action | Priority |
|-------------------|--------|----------|
| 1-3 | Standard failover procedure | High |
| 4-7 | Emergency coordinator recovery | Critical |
| 8+ | Disaster recovery procedure | Critical |

**Step-by-Step Recovery (1-3 coordinators):**

```bash
# 1. Initiate failover for first unreachable coordinator
platformctl coordinator failover coord-XXXX --emergency

# 2. If hardware available, provision replacement
platformctl coordinator init --emergency-replacement

# 3. If no hardware available, attempt recovery of existing
platformctl coordinator recover coord-XXXX --force

# 4. Verify quorum restored
platformctl coordinator quorum-status
```

**Verification:**
- Quorum status: "Maintained (>=14/21)"
- FROST signing: "Operational"
- Consensus: "Active"

#### Memory Exhaustion Recovery

**Detection:**
- Memory usage > 95%
- OOM killer events in system logs

**Assessment:**
1. Identify memory consumer: `platformctl debug memory --top`
2. Check for memory leaks: `platformctl debug memory --growth-rate`
3. Determine if traffic spike or bug

**Recovery Actions:**

```bash
# 1. Immediate: Graceful restart if > 95%
platformctl node restart --graceful --reason "memory-exhaustion"

# 2. If restart fails, force restart
systemctl restart platformd

# 3. If recurring, enable memory limiting
platformctl config set memory.max_heap_mb=4096
platformctl config set memory.gc_percent=50

# 4. Collect diagnostics for engineering
platformctl debug dump --memory --output /tmp/memdump
```

**Verification:**
- Memory usage < 80%
- No OOM events in 1 hour
- All services responding normally

#### Disk Space Exhaustion Recovery

**Detection:**
- Available disk < 10% or < 10GB

**Assessment:**
1. Check disk usage: `df -h`
2. Identify large consumers: `du -sh /var/lib/platformd/*`
3. Check log rotation status

**Recovery Actions:**

```bash
# 1. Immediate: Clear old logs
platformctl logs rotate --force --older-than 7d

# 2. Clear temporary files
platformctl cache clear --temporary

# 3. Archive old blocks (if configured)
platformctl blocks archive --older-than 30d --to s3://archive

# 4. If still low, expand storage
# [External: Storage expansion procedure]
```

**Verification:**
- Available disk > 20%
- Log rotation functioning
- No disk-related errors

#### Gray Zone Reconciliation Failure

**Detection:**
- Gray zone duration > 5 minutes
- Conflict count > 0 after reconciliation

**Assessment:**
1. Check gray zone status: `platformctl grayzone status --detailed`
2. List conflicts: `platformctl grayzone conflicts`
3. Identify conflict type (double-spend, timestamp, etc.)

**Recovery Actions:**

```bash
# 1. If automatic reconciliation failed, review conflicts
platformctl grayzone conflicts --export conflicts.json

# 2. For each conflict, determine resolution
platformctl grayzone resolve --conflict-id XXXX \
    --resolution "accept-majority" \
    --approval-quorum

# 3. If manual resolution required
platformctl grayzone manual-resolve --conflict-id XXXX \
    --accept-transaction TX_XXXX \
    --reject-transaction TX_YYYY \
    --justification "Majority partition transaction selected"

# 4. Complete gray zone exit
platformctl grayzone exit --force-complete
```

**Verification:**
- Gray zone status: "NORMAL"
- Conflict count: 0
- All affected accounts balanced correctly

#### TPM Attestation Failure Recovery

**Detection:**
- TPM quote verification failures > 5/minute
- Node quarantined from consensus

**Assessment:**
1. Determine failure type: hardware, firmware, or software
2. Check TPM event log for anomalies
3. Verify no security compromise

**Recovery Actions:**

```bash
# 1. Attempt TPM re-attestation
platformctl tpm reattest --verbose

# 2. If re-attestation fails, check TPM health
platformctl tpm diagnostic --full

# 3. If TPM hardware failure, replace node
platformctl node decommission --tpm-failure

# 4. If potential security compromise
platformctl security incident-report \
    --type tpm-failure \
    --node-id NODE_XXXX \
    --quarantine
```

**Security Escalation:**
If TPM failure cannot be attributed to hardware:
1. Isolate node immediately
2. Preserve all logs and TPM event data
3. Notify security team
4. Begin forensic investigation

**Verification:**
- TPM attestation: "Verified"
- Node status: "Active" (or "Decommissioned" if replaced)
- Security review: "Complete"

#### Node Recovery Procedure

This section defines the comprehensive procedure for recovering failed nodes, including state reconstruction, FROST share re-enrollment, and reputation restoration.

**Recovery Scenarios:**

| Scenario | Severity | Recovery Path | Expected Time |
|----------|----------|---------------|---------------|
| Transient failure (restart) | Low | Automatic rejoin | 2-5 minutes |
| Storage corruption | Medium | State reconstruction | 15-30 minutes |
| Hardware failure (new host) | High | Full re-enrollment | 30-60 minutes |
| Coordinator failure | Critical | FROST share refresh | 1-2 hours |
| TPM compromise | Critical | New identity + audit | 2-4 hours |

##### State Reconstruction from DHT

When a node restarts or recovers from failure, it must reconstruct its local state from the DHT:

```go
// NodeStateReconstruction handles rebuilding node state from DHT
type NodeStateReconstruction struct {
    NodeID          [32]byte
    LastKnownState  *NodeState          // Cached before failure (if available)
    ReconstructedAt time.Time
    DHT             DHT
}

// ReconstructionPhase defines stages of state reconstruction
type ReconstructionPhase struct {
    Name        string
    Description string
    Timeout     time.Duration
    Required    bool
}

var NodeRecoveryPhases = []ReconstructionPhase{
    {
        Name:        "TPMVerification",
        Description: "Verify TPM hardware and attestation capability",
        Timeout:     30 * time.Second,
        Required:    true,
    },
    {
        Name:        "IdentityRecovery",
        Description: "Recover node identity from TPM-bound keys",
        Timeout:     30 * time.Second,
        Required:    true,
    },
    {
        Name:        "PeerDiscovery",
        Description: "Bootstrap DHT connectivity via known peers",
        Timeout:     2 * time.Minute,
        Required:    true,
    },
    {
        Name:        "ChainStateSync",
        Description: "Synchronize blockchain state from peers",
        Timeout:     10 * time.Minute,
        Required:    true,
    },
    {
        Name:        "UTXOSetReconstruction",
        Description: "Rebuild UTXO set from chain state",
        Timeout:     5 * time.Minute,
        Required:    true,
    },
    {
        Name:        "ReputationSync",
        Description: "Restore reputation data from DHT",
        Timeout:     1 * time.Minute,
        Required:    false,
    },
    {
        Name:        "ServiceRegistration",
        Description: "Re-register services with network",
        Timeout:     30 * time.Second,
        Required:    false,
    },
}

// ExecuteRecovery performs full node state reconstruction
func (nsr *NodeStateReconstruction) ExecuteRecovery(
    ctx context.Context,
) (*RecoveredNodeState, error) {
    log.Info("starting node state reconstruction",
        "nodeID", hex.EncodeToString(nsr.NodeID[:8]))

    result := &RecoveredNodeState{
        NodeID:    nsr.NodeID,
        StartedAt: time.Now(),
        Phases:    make(map[string]*PhaseResult),
    }

    for _, phase := range NodeRecoveryPhases {
        phaseCtx, cancel := context.WithTimeout(ctx, phase.Timeout)

        log.Info("executing recovery phase",
            "phase", phase.Name,
            "timeout", phase.Timeout)

        phaseResult, err := nsr.executePhase(phaseCtx, phase)
        cancel()

        result.Phases[phase.Name] = phaseResult

        if err != nil {
            if phase.Required {
                log.Error("required recovery phase failed",
                    "phase", phase.Name,
                    "error", err)
                return nil, fmt.Errorf("recovery phase %s failed: %w", phase.Name, err)
            }
            log.Warn("optional recovery phase failed, continuing",
                "phase", phase.Name,
                "error", err)
        }
    }

    result.CompletedAt = time.Now()
    result.Duration = result.CompletedAt.Sub(result.StartedAt)

    log.Info("node state reconstruction complete",
        "duration", result.Duration,
        "phasesSucceeded", result.SuccessCount(),
        "phasesFailed", result.FailureCount())

    return result, nil
}

// executePhase runs a single recovery phase
func (nsr *NodeStateReconstruction) executePhase(
    ctx context.Context,
    phase ReconstructionPhase,
) (*PhaseResult, error) {
    result := &PhaseResult{
        Name:      phase.Name,
        StartedAt: time.Now(),
    }

    var err error
    switch phase.Name {
    case "TPMVerification":
        err = nsr.verifyTPM(ctx)
    case "IdentityRecovery":
        err = nsr.recoverIdentity(ctx)
    case "PeerDiscovery":
        err = nsr.discoverPeers(ctx)
    case "ChainStateSync":
        err = nsr.syncChainState(ctx)
    case "UTXOSetReconstruction":
        err = nsr.reconstructUTXOSet(ctx)
    case "ReputationSync":
        err = nsr.syncReputation(ctx)
    case "ServiceRegistration":
        err = nsr.registerServices(ctx)
    }

    result.CompletedAt = time.Now()
    result.Duration = result.CompletedAt.Sub(result.StartedAt)
    result.Success = (err == nil)
    result.Error = err

    return result, err
}
```

**Recovery CLI Commands:**

```bash
# Full node recovery (automatic phase execution)
platformctl node recover --full --verbose

# Recovery with specific phases
platformctl node recover --phases "TPMVerification,IdentityRecovery,PeerDiscovery"

# Resume interrupted recovery
platformctl node recover --resume --from-checkpoint

# Check recovery status
platformctl node recovery-status
```

##### FROST Share Re-Enrollment

For coordinator nodes, FROST key shares must be re-enrolled after recovery:

```go
// FROSTShareReEnrollment handles coordinator key share recovery
type FROSTShareReEnrollment struct {
    CoordinatorID   [32]byte
    Pools           []PoolID        // FROST pools to re-enroll in
    OldSharesValid  bool            // Whether old shares can be reused
    ReEnrollmentID  [32]byte        // Unique ID for this re-enrollment
}

// ReEnrollmentStrategy determines how to recover FROST shares
type ReEnrollmentStrategy uint8

const (
    // StrategyReshare triggers a proactive secret sharing refresh
    // Used when old shares are compromised or unavailable
    StrategyReshare ReEnrollmentStrategy = iota

    // StrategyRecover attempts to recover shares from secure backup
    // Used when shares were backed up to secure storage
    StrategyRecover

    // StrategyRejoin re-joins with existing shares if still valid
    // Used when node was temporarily offline but shares intact
    StrategyRejoin
)

// ExecuteReEnrollment performs FROST share re-enrollment
func (fsr *FROSTShareReEnrollment) ExecuteReEnrollment(
    ctx context.Context,
    strategy ReEnrollmentStrategy,
) error {
    log.Info("starting FROST share re-enrollment",
        "coordinatorID", hex.EncodeToString(fsr.CoordinatorID[:8]),
        "strategy", strategy,
        "pools", fsr.Pools)

    switch strategy {
    case StrategyRejoin:
        return fsr.rejoinWithExistingShares(ctx)

    case StrategyRecover:
        return fsr.recoverFromBackup(ctx)

    case StrategyReshare:
        return fsr.triggerReshare(ctx)
    }

    return ErrUnknownReEnrollmentStrategy
}

// rejoinWithExistingShares verifies and reactivates existing shares
func (fsr *FROSTShareReEnrollment) rejoinWithExistingShares(ctx context.Context) error {
    // Step 1: Verify local shares still valid
    for _, poolID := range fsr.Pools {
        share, err := loadLocalShare(fsr.CoordinatorID, poolID)
        if err != nil {
            return fmt.Errorf("load share for pool %s: %w", poolID, err)
        }

        // Step 2: Verify share against public polynomial
        if err := verifyShareAgainstPublicKey(share, poolID); err != nil {
            return fmt.Errorf("share verification failed for pool %s: %w", poolID, err)
        }
    }

    // Step 3: Notify other coordinators of rejoining
    announcement := &CoordinatorRejoinAnnouncement{
        CoordinatorID: fsr.CoordinatorID,
        Pools:         fsr.Pools,
        TPMQuote:      generateTPMQuote(),
        Timestamp:     time.Now(),
    }

    if err := broadcastRejoinAnnouncement(ctx, announcement); err != nil {
        return fmt.Errorf("broadcast rejoin: %w", err)
    }

    // Step 4: Wait for acknowledgment from quorum
    if err := waitForRejoinAck(ctx, fsr.CoordinatorID, 10*time.Minute); err != nil {
        return fmt.Errorf("rejoin acknowledgment: %w", err)
    }

    log.Info("FROST share rejoin complete")
    return nil
}

// triggerReshare initiates a proactive secret sharing refresh
func (fsr *FROSTShareReEnrollment) triggerReshare(ctx context.Context) error {
    log.Info("triggering FROST proactive secret sharing refresh")

    for _, poolID := range fsr.Pools {
        // Request reshare from current pool members
        reshareReq := &ReshareRequest{
            PoolID:           poolID,
            RequestingNode:   fsr.CoordinatorID,
            Reason:           "node_recovery",
            TPMAttestation:   generateTPMQuote(),
            ReEnrollmentID:   fsr.ReEnrollmentID,
        }

        // Initiate DKG refresh round
        if err := initiateDKGRefresh(ctx, reshareReq); err != nil {
            return fmt.Errorf("initiate DKG refresh for pool %s: %w", poolID, err)
        }

        // Participate in refresh protocol
        if err := participateInRefresh(ctx, poolID, fsr.CoordinatorID); err != nil {
            return fmt.Errorf("participate in refresh for pool %s: %w", poolID, err)
        }

        log.Info("reshare complete for pool", "poolID", poolID)
    }

    return nil
}
```

**FROST Re-Enrollment CLI:**

```bash
# Rejoin with existing shares (fastest)
platformctl frost reenroll --strategy rejoin --pools "Ed25519,P256"

# Recover from secure backup
platformctl frost reenroll --strategy recover \
    --backup-source "hsm://backup-key" \
    --pools "Ed25519,P256"

# Trigger full reshare (slowest but most secure)
platformctl frost reenroll --strategy reshare \
    --reason "hardware_replacement" \
    --pools "Ed25519,P256"

# Check re-enrollment status
platformctl frost reenroll-status
```

##### Reputation Restoration

Nodes with established reputation can restore their reputation score after recovery:

```go
// ReputationRestoration handles reputation score recovery
type ReputationRestoration struct {
    NodeID              [32]byte
    LastKnownReputation float64       // Cached reputation before failure
    DowntimeStart       time.Time     // When node went offline
    DowntimeEnd         time.Time     // When node came back online
    RestoredReputation  float64       // Restored reputation (may include penalty)
}

// DowntimePenalty calculates reputation penalty based on downtime
type DowntimePenalty struct {
    // GracePeriod: No penalty during this window
    GracePeriod time.Duration  // 30 minutes

    // PenaltyRate: Reputation points lost per hour after grace period
    PenaltyRate float64  // 0.01 per hour (1% per hour)

    // MaxPenalty: Maximum reputation loss from downtime
    MaxPenalty float64  // 0.10 (10% maximum)

    // RecoveryRate: Reputation recovery rate per day of good service
    RecoveryRate float64  // 0.005 per day (0.5% per day)
}

var DefaultDowntimePenalty = DowntimePenalty{
    GracePeriod:  30 * time.Minute,
    PenaltyRate:  0.01,
    MaxPenalty:   0.10,
    RecoveryRate: 0.005,
}

// RestoreReputation calculates and applies reputation restoration
func (rr *ReputationRestoration) RestoreReputation(
    ctx context.Context,
    dht DHT,
) (*RestoredReputation, error) {
    // Step 1: Fetch last known reputation from DHT
    storedRep, err := dht.GetReputation(ctx, rr.NodeID)
    if err != nil {
        log.Warn("could not fetch stored reputation, using default",
            "error", err)
        storedRep = DefaultBaseReputation
    }

    // Step 2: Calculate downtime penalty
    downtime := rr.DowntimeEnd.Sub(rr.DowntimeStart)
    penalty := rr.calculatePenalty(downtime)

    // Step 3: Apply penalty
    restoredRep := storedRep - penalty
    if restoredRep < MinimumReputation {
        restoredRep = MinimumReputation
    }

    rr.RestoredReputation = restoredRep

    // Step 4: Update reputation in DHT
    repUpdate := &ReputationUpdate{
        NodeID:        rr.NodeID,
        OldValue:      storedRep,
        NewValue:      restoredRep,
        Reason:        "downtime_recovery",
        Penalty:       penalty,
        Downtime:      downtime,
        Timestamp:     time.Now(),
        TPMAttestation: generateTPMQuote(),
    }

    if err := dht.UpdateReputation(ctx, repUpdate); err != nil {
        return nil, fmt.Errorf("update reputation in DHT: %w", err)
    }

    log.Info("reputation restored",
        "nodeID", hex.EncodeToString(rr.NodeID[:8]),
        "previous", storedRep,
        "restored", restoredRep,
        "penalty", penalty,
        "downtime", downtime)

    return &RestoredReputation{
        NodeID:           rr.NodeID,
        PreviousScore:    storedRep,
        RestoredScore:    restoredRep,
        DowntimePenalty:  penalty,
        Downtime:         downtime,
        EstimatedRecovery: rr.estimateFullRecovery(penalty),
    }, nil
}

// calculatePenalty computes reputation penalty for downtime
func (rr *ReputationRestoration) calculatePenalty(downtime time.Duration) float64 {
    dp := DefaultDowntimePenalty

    // No penalty during grace period
    if downtime <= dp.GracePeriod {
        return 0.0
    }

    // Calculate penalty hours (excluding grace period)
    penaltyHours := (downtime - dp.GracePeriod).Hours()

    // Apply penalty rate
    penalty := penaltyHours * dp.PenaltyRate

    // Cap at maximum penalty
    if penalty > dp.MaxPenalty {
        penalty = dp.MaxPenalty
    }

    return penalty
}
```

**Reputation Restoration CLI:**

```bash
# Restore reputation after recovery
platformctl reputation restore --verbose

# Check current reputation status
platformctl reputation status

# Estimate reputation recovery timeline
platformctl reputation estimate-recovery
```

##### Bootstrap Sequence for Recovered Node

Complete bootstrap sequence for a recovered node:

```bash
#!/bin/bash
# node-recovery-bootstrap.sh
# Complete bootstrap sequence for recovered node

set -e

echo "=== Node Recovery Bootstrap ==="
echo "Started at: $(date)"

# Phase 1: Hardware Verification
echo "Phase 1: Hardware verification..."
platformctl tpm status --verify-quote || {
    echo "FAIL: TPM verification failed"
    exit 1
}

# Phase 2: Identity Recovery
echo "Phase 2: Recovering node identity..."
platformctl node recover-identity --tpm-bound || {
    echo "FAIL: Identity recovery failed"
    exit 1
}

# Phase 3: Network Bootstrap
echo "Phase 3: Bootstrapping network connectivity..."
platformctl node bootstrap --timeout 5m || {
    echo "FAIL: Network bootstrap failed"
    exit 1
}

# Phase 4: Chain State Synchronization
echo "Phase 4: Synchronizing chain state..."
platformctl chain sync --verify --progress || {
    echo "FAIL: Chain sync failed"
    exit 1
}

# Phase 5: FROST Re-enrollment (coordinators only)
if platformctl coordinator is-coordinator; then
    echo "Phase 5: FROST share re-enrollment..."
    platformctl frost reenroll --strategy rejoin \
        --pools "Ed25519,P256" \
        --timeout 30m || {
        echo "WARN: FROST rejoin failed, trying reshare..."
        platformctl frost reenroll --strategy reshare \
            --pools "Ed25519,P256" \
            --timeout 60m || {
            echo "FAIL: FROST re-enrollment failed"
            exit 1
        }
    }
fi

# Phase 6: Reputation Restoration
echo "Phase 6: Restoring reputation..."
platformctl reputation restore || {
    echo "WARN: Reputation restoration failed, starting with base reputation"
}

# Phase 7: Service Registration
echo "Phase 7: Registering services..."
platformctl services register --all || {
    echo "WARN: Some services failed to register"
}

# Phase 8: Final Verification
echo "Phase 8: Final verification..."
platformctl node verify-recovery || {
    echo "FAIL: Recovery verification failed"
    exit 1
}

echo "=== Node Recovery Complete ==="
echo "Completed at: $(date)"
platformctl node status --detailed
```

**Recovery Verification Checklist:**

| Check | Command | Expected |
|-------|---------|----------|
| TPM status | `platformctl tpm status` | "Verified" |
| Node identity | `platformctl node identity` | Matches pre-failure |
| Peer connectivity | `platformctl peers count` | >10 peers |
| Chain sync | `platformctl chain sync-status` | "Synchronized" |
| FROST shares (coordinator) | `platformctl frost verify-shares` | "All shares valid" |
| Reputation | `platformctl reputation status` | >0.5 score |
| Services | `platformctl services status` | "All registered" |

---

### Verification Procedures

#### Post-Recovery Checklist

**Network Health:**

| Check | Command | Expected |
|-------|---------|----------|
| Reachability | `platformctl network reachability` | > 95% |
| Peer count | `platformctl peers count` | > 90% of baseline |
| Latency | `platformctl network latency --p99` | < 200ms |

**Consensus Health:**

| Check | Command | Expected |
|-------|---------|----------|
| Block production | `platformctl blocks latest` | Block age < 30s |
| FROST signing | `platformctl frost status` | All pools operational |
| Coordinator quorum | `platformctl coordinator quorum` | >= 14/21 |

**Transaction Processing:**

| Check | Command | Expected |
|-------|---------|----------|
| Pending transactions | `platformctl transaction pending` | Decreasing |
| Transaction throughput | `platformctl transaction tps` | Within normal range |
| Failed transactions | `platformctl transaction failed --recent` | 0 unexpected |

**Resource Utilization:**

| Check | Command | Expected |
|-------|---------|----------|
| CPU usage | `platformctl system cpu` | < 80% |
| Memory usage | `platformctl system memory` | < 80% |
| Disk usage | `platformctl system disk` | < 80% |
| Goroutine count | `platformctl system goroutines` | < 5000 |

#### Sustained Recovery Verification

**Monitoring Window:** 1 hour after recovery complete

```yaml
verification:
  window: 1h
  checks:
    - metric: error_rate
      threshold: "< 0.1%"
      duration: 1h

    - metric: latency_p99
      threshold: "< 500ms"
      duration: 1h

    - metric: reachability
      threshold: "> 95%"
      duration: 1h
```

**Verification Sign-Off:**

| Role | Verification | Signature |
|------|--------------|-----------|
| SRE On-Call | System metrics normal | ____________ |
| Engineering | No error patterns | ____________ |
| Security (if applicable) | No compromise indicators | ____________ |
| Incident Commander | Recovery complete | ____________ |

---

## Disaster Recovery Procedures

This section defines the disaster recovery (DR) plan for the go-trusted-platform network, including multi-region failover, RTO/RPO requirements, FROST share backup strategies, and cross-region failover procedures.

### Recovery Objectives

**Recovery Time Objective (RTO) and Recovery Point Objective (RPO):**

| Scenario | RTO Target | RPO Target | Priority |
|----------|------------|------------|----------|
| Single coordinator failure | 30 minutes | 0 (no data loss) | High |
| Multiple coordinator failure (1-3) | 1 hour | 0 (no data loss) | Critical |
| Regional outage (single region) | 2 hours | < 6 seconds (1 block) | Critical |
| Multi-region outage (2+ regions) | 4 hours | < 1 minute | Critical |
| Complete network failure | 24 hours | < 10 minutes | Emergency |
| Cryptographic key compromise | 4 hours | N/A | Emergency |

**Service Level Objectives:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| Network availability | 99.99% (52 min/year downtime) | Monthly |
| Transaction finality | < 6 seconds | Per transaction |
| Consensus availability | 99.9% (8.7 hr/year downtime) | Monthly |
| FROST signing availability | 99.9% | Monthly |
| Data durability | 99.999999% (8 nines) | Annual |

### Multi-Region Architecture

The platform deploys coordinators across multiple geographic regions for disaster resilience:

```
                        GLOBAL COORDINATOR DISTRIBUTION

    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │   US-EAST (5)        EU-WEST (4)       EU-CENTRAL (4)          │
    │   ┌─────────┐        ┌─────────┐       ┌─────────┐             │
    │   │ coord-1 │        │ coord-6 │       │coord-10 │             │
    │   │ coord-2 │        │ coord-7 │       │coord-11 │             │
    │   │ coord-3 │        │ coord-8 │       │coord-12 │             │
    │   │ coord-4 │        │ coord-9 │       │coord-13 │             │
    │   │ coord-5 │        └─────────┘       └─────────┘             │
    │   └─────────┘                                                   │
    │                                                                 │
    │   US-WEST (4)        AP-NORTHEAST (4)                          │
    │   ┌─────────┐        ┌─────────┐                               │
    │   │coord-14 │        │coord-18 │                               │
    │   │coord-15 │        │coord-19 │                               │
    │   │coord-16 │        │coord-20 │                               │
    │   │coord-17 │        │coord-21 │                               │
    │   └─────────┘        └─────────┘                               │
    │                                                                 │
    │   Quorum requirement: 14/21 coordinators                        │
    │   Single region failure tolerance: YES (max 5 coordinators)     │
    │   Two region failure tolerance: PARTIAL (depends on regions)    │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
```

**Regional Failure Impact:**

| Region Lost | Coordinators Lost | Quorum Status | Recovery Action |
|-------------|-------------------|---------------|-----------------|
| US-EAST | 5 | Maintained (16/21) | Monitor, no action |
| US-WEST | 4 | Maintained (17/21) | Monitor, no action |
| EU-WEST | 4 | Maintained (17/21) | Monitor, no action |
| EU-CENTRAL | 4 | Maintained (17/21) | Monitor, no action |
| AP-NORTHEAST | 4 | Maintained (17/21) | Monitor, no action |
| US-EAST + US-WEST | 9 | AT RISK (12/21) | Emergency failover |
| US-EAST + EU-WEST | 9 | AT RISK (12/21) | Emergency failover |
| Any 3 regions | 12-13 | LOST | Disaster recovery |

### FROST Share Backup Strategy

FROST key shares are critical cryptographic material that must be backed up securely for disaster recovery.

#### Backup Architecture

```go
// FROSTShareBackup defines the backup configuration
type FROSTShareBackup struct {
    // Primary storage: TPM-sealed on coordinator
    PrimaryStorage    StorageLocation

    // Secondary storage: Encrypted backup in secure HSM
    SecondaryStorage  StorageLocation

    // Tertiary storage: Shamir-split across cold storage
    TertiaryStorage   []StorageLocation

    // Backup metadata
    BackupSchedule    time.Duration  // 24 hours
    RetentionPeriod   time.Duration  // 90 days
    EncryptionKey     KeyReference   // Reference to backup encryption key
}

// StorageLocation defines where backups are stored
type StorageLocation struct {
    Type        string  // "tpm", "hsm", "cold_storage", "s3_encrypted"
    Region      string  // Geographic region
    Provider    string  // Cloud provider or "on-premise"
    Endpoint    string  // Access endpoint
    Redundancy  int     // Replication factor
}

// DefaultBackupConfig for coordinator FROST shares
var DefaultBackupConfig = FROSTShareBackup{
    PrimaryStorage: StorageLocation{
        Type:       "tpm",
        Region:     "local",
        Provider:   "on-premise",
        Redundancy: 1,
    },
    SecondaryStorage: StorageLocation{
        Type:       "hsm",
        Region:     "same-region",
        Provider:   "cloud-hsm",
        Redundancy: 2,
    },
    TertiaryStorage: []StorageLocation{
        {
            Type:       "cold_storage",
            Region:     "us-east-1",
            Provider:   "secure-vault",
            Redundancy: 1,
        },
        {
            Type:       "cold_storage",
            Region:     "eu-west-1",
            Provider:   "secure-vault",
            Redundancy: 1,
        },
    },
    BackupSchedule:  24 * time.Hour,
    RetentionPeriod: 90 * 24 * time.Hour,
}
```

#### Backup Procedure

**Daily Automated Backup:**

```bash
#!/bin/bash
# frost-share-backup.sh
# Daily FROST share backup procedure

set -e

BACKUP_DATE=$(date +%Y%m%d)
COORDINATOR_ID=$(platformctl coordinator identity --short)

echo "=== FROST Share Backup: $BACKUP_DATE ==="

# Step 1: Export shares (encrypted with TPM-sealed key)
echo "Exporting FROST shares..."
platformctl frost backup export \
    --pools "Ed25519,P256" \
    --encrypt-with-tpm \
    --output /tmp/frost-backup-${BACKUP_DATE}.enc

# Step 2: Verify backup integrity
echo "Verifying backup integrity..."
platformctl frost backup verify \
    --input /tmp/frost-backup-${BACKUP_DATE}.enc

# Step 3: Upload to secondary storage (HSM)
echo "Uploading to HSM storage..."
platformctl frost backup upload \
    --input /tmp/frost-backup-${BACKUP_DATE}.enc \
    --destination "hsm://backup-vault/frost/${COORDINATOR_ID}/${BACKUP_DATE}"

# Step 4: Replicate to tertiary storage (monthly)
if [ $(date +%d) -eq "01" ]; then
    echo "Monthly cold storage replication..."
    platformctl frost backup replicate \
        --input /tmp/frost-backup-${BACKUP_DATE}.enc \
        --destinations "cold://us-east-1,cold://eu-west-1"
fi

# Step 5: Clean up local backup
rm -f /tmp/frost-backup-${BACKUP_DATE}.enc

# Step 6: Update backup registry
platformctl frost backup register \
    --date ${BACKUP_DATE} \
    --coordinator ${COORDINATOR_ID} \
    --status "completed"

echo "=== Backup Complete ==="
```

#### Share Recovery Procedure

**Recovery from Secondary Storage (HSM):**

```bash
# Recover FROST shares from HSM backup
platformctl frost backup restore \
    --source "hsm://backup-vault/frost/${COORDINATOR_ID}/latest" \
    --decrypt-with-tpm \
    --verify-before-apply

# Verify recovered shares
platformctl frost verify-shares --all-pools

# Re-register with FROST pools
platformctl frost reenroll --strategy rejoin --pools "Ed25519,P256"
```

**Recovery from Tertiary Storage (Cold):**

```bash
# Retrieve from cold storage (requires multiple approvals)
platformctl frost backup retrieve \
    --source "cold://us-east-1/frost/${COORDINATOR_ID}" \
    --approvals "security-team,sre-lead,cto" \
    --output /secure/frost-recovery.enc

# Decrypt with recovery key (stored separately)
platformctl frost backup decrypt \
    --input /secure/frost-recovery.enc \
    --recovery-key "hsm://recovery-key-vault/frost-recovery"

# Restore shares
platformctl frost backup restore \
    --source /secure/frost-recovery.dec \
    --verify-before-apply
```

### Cross-Region Failover Procedure

When a region becomes unavailable, coordinators in that region must be failed over to backup infrastructure.

#### Failover Triggers

| Trigger | Detection | Automatic | Manual Approval |
|---------|-----------|-----------|-----------------|
| Single coordinator failure | Heartbeat timeout (2 min) | Yes | No |
| Multiple coordinator failure (2+) | Quorum monitoring | Yes | No |
| Region connectivity loss | BGP/DNS monitoring | No | Yes (5 min SLA) |
| Region infrastructure failure | Cloud provider notification | No | Yes |
| Security incident | Manual trigger | No | Yes (immediate) |

#### Failover Procedure

**Phase 1: Detection and Assessment (5 minutes)**

```bash
# Automated detection triggers alert
# On-call SRE assesses situation

# Check quorum status
platformctl coordinator quorum-status --detailed

# Identify affected coordinators
platformctl coordinator list --region us-east-1 --status unreachable

# Check if failover is required
platformctl dr assess --region us-east-1
```

**Phase 2: Failover Initiation (10 minutes)**

```bash
# Declare regional failover
platformctl dr initiate-failover \
    --region us-east-1 \
    --reason "regional_outage" \
    --approval-required

# Activate standby coordinators in backup region
platformctl coordinator activate-standby \
    --primary-region us-east-1 \
    --backup-region us-east-2 \
    --count 5

# Restore FROST shares to standby coordinators
platformctl frost restore-to-standby \
    --primary-region us-east-1 \
    --backup-region us-east-2 \
    --source "hsm://backup-vault"
```

**Phase 3: DKG Refresh (30-60 minutes)**

```bash
# Initiate proactive secret sharing refresh
platformctl dkg refresh \
    --exclude-region us-east-1 \
    --include-standby us-east-2 \
    --pools "Ed25519,P256"

# Verify new shares distributed
platformctl frost verify-shares --region us-east-2

# Test FROST signing with new configuration
platformctl frost test-sign --verbose
```

**Phase 4: Traffic Cutover (5 minutes)**

```bash
# Update DNS to point to new coordinators
platformctl dr update-dns \
    --old-region us-east-1 \
    --new-region us-east-2

# Update DHT routing
platformctl dht update-routing \
    --exclude-region us-east-1 \
    --add-region us-east-2

# Verify traffic flowing to new region
platformctl dr verify-cutover --timeout 5m
```

**Phase 5: Verification (15 minutes)**

```bash
# Verify consensus operational
platformctl consensus status --detailed

# Verify FROST signing operational
platformctl frost test-sign --all-pools

# Verify transaction processing
platformctl transaction submit --test --verify

# Declare failover complete
platformctl dr complete-failover \
    --region us-east-1 \
    --backup-region us-east-2
```

#### Failback Procedure

When the original region recovers, traffic can be failed back:

```bash
# Verify primary region recovered
platformctl dr verify-region-health --region us-east-1

# Prepare failback
platformctl dr prepare-failback \
    --primary-region us-east-1 \
    --current-region us-east-2

# Synchronize state from backup to primary
platformctl dr sync-state \
    --from us-east-2 \
    --to us-east-1

# Restore FROST shares to primary coordinators
platformctl frost restore-to-primary \
    --region us-east-1 \
    --source "hsm://backup-vault"

# Execute failback
platformctl dr execute-failback \
    --from us-east-2 \
    --to us-east-1 \
    --gradual  # Gradually shift traffic over 30 minutes

# Deactivate standby coordinators
platformctl coordinator deactivate-standby \
    --region us-east-2 \
    --retain-shares  # Keep shares for future DR
```

### Emergency Procedures

#### Complete Network Failure Recovery

In the catastrophic scenario of complete network failure:

**Prerequisites:**
- At least 14 coordinator cold storage backups accessible
- Recovery environment prepared (air-gapped if security incident)
- Recovery team assembled with required key holders

**Recovery Steps:**

```bash
# Step 1: Establish secure recovery environment
# (Manual: Air-gapped network, verified hardware)

# Step 2: Recover minimum quorum of coordinators (14)
for i in {1..14}; do
    platformctl coordinator recover \
        --from-cold-storage \
        --coordinator-id coord-$i \
        --recovery-key "holder-$i-key"
done

# Step 3: Restore FROST shares from tertiary backups
platformctl frost recover-from-cold \
    --shares-required 14 \
    --multi-party-decrypt \
    --key-holders "security,sre,legal,cto"

# Step 4: Rebuild DKG (new shares if necessary)
platformctl dkg rebuild \
    --participants 14 \
    --threshold 14 \
    --generate-new-shares

# Step 5: Verify cryptographic material
platformctl frost verify-all \
    --thorough \
    --audit-log

# Step 6: Bootstrap network from recovered state
platformctl network bootstrap \
    --from-recovery \
    --genesis-override \
    --coordinator-count 14

# Step 7: Gradually add remaining coordinators
for i in {15..21}; do
    platformctl coordinator add \
        --coordinator-id coord-$i \
        --join-existing
done

# Step 8: Verify full functionality
platformctl dr verify-full-recovery
```

### DR Testing Schedule

| Test Type | Frequency | Scope | Duration |
|-----------|-----------|-------|----------|
| Backup verification | Daily | Automated | 5 minutes |
| Single coordinator failover | Monthly | Single coordinator | 1 hour |
| Multi-coordinator failover | Quarterly | 3 coordinators | 2 hours |
| Regional failover | Semi-annually | Full region | 4 hours |
| Full DR exercise | Annually | Complete network | 1 day |

**DR Test Procedure:**

```bash
# Initiate DR test
platformctl dr test initiate \
    --type regional \
    --target-region us-east-1 \
    --test-mode  # Non-destructive

# Execute test scenarios
platformctl dr test execute \
    --scenario "coordinator_failure,frost_signing,transaction_processing"

# Capture metrics
platformctl dr test metrics \
    --export dr-test-results-$(date +%Y%m%d).json

# Generate report
platformctl dr test report \
    --output dr-test-report-$(date +%Y%m%d).pdf
```

---

## Planned Enhancements

### V1.0 Scope

**Security:**

1. **Certificate Pinning (TOFU)**: Trust On First Use pinning for P2P connections
   - Storage: ~100 bytes per pinned node
   - Detects MITM attacks, faster validation on repeat connections
   - **SECURITY FIX (P5-M6)**: Pin validity policy

   ```go
   // CertificatePinConfig defines pin lifecycle parameters
   type CertificatePinConfig struct {
       // Pin validity (SECURITY FIX P5-M6)
       PinValidityDuration = 90 * 24 * time.Hour   // 90 days max validity
       PinWarningThreshold = 14 * 24 * time.Hour   // Warn 14 days before expiry
       PinGracePeriod      = 7 * 24 * time.Hour    // Grace period after expiry

       // Verification behavior
       ExpiredPinAction    = "warn_and_reverify"   // Options: reject, warn_and_reverify
       MismatchAction      = "reject"              // Options: reject, warn_only
   }

   // PinnedCertificate stores TOFU pinning state
   type PinnedCertificate struct {
       NodeID         [32]byte
       CertHash       [32]byte       // SHA256 of DER-encoded certificate
       FirstSeen      time.Time      // TOFU timestamp
       ExpiresAt      time.Time      // Pin expiration (FirstSeen + 90 days)
       VerifiedCount  uint32         // Successful verifications
       LastVerified   time.Time
   }

   // IsExpired checks if pin has exceeded validity period
   func (p *PinnedCertificate) IsExpired() bool {
       return time.Now().After(p.ExpiresAt)
   }

   // NeedsRenewal checks if pin should be renewed soon
   func (p *PinnedCertificate) NeedsRenewal(config *CertificatePinConfig) bool {
       return time.Until(p.ExpiresAt) < config.PinWarningThreshold
   }
   ```

2. **Clock Synchronization**: Enforce NTP synchronization with monitoring
   - MaxClockSkew: 100ms (hard limit)
   - WarnClockSkew: 50ms (warning threshold)
   - NTPSyncInterval: 5 minutes
   - Default servers: time.cloudflare.com, time.google.com, pool.ntp.org

3. **Enhanced Sybil Resistance**: Multi-factor defense
   - Proof-of-work on join (difficulty 22, ~4 seconds)
   - IP diversity scoring (penalize same /24 subnets)
   - Bandwidth proof-of-capacity (10 MB upload test)
   - TPM manufacturer diversity detection

4. **Bloom Filter Revocation**: Space-efficient revocation checking
   - 92% storage reduction vs CRL (1M revocations = 1.25 MB)
   - 0.1% false positive rate
   - Update interval: hourly (sync with CA rotation)

**Performance:**

5. **Certificate Caching at Gateways**: LRU cache (10K entries, ~2.5 MB)
   - Cache hit: <1ms, Cache miss: ~500ms
   - Expected hit rate: 90%+
   - Cache TTL: 1 hour

6. **Connection Multiplexing (QUIC)**: Reuse connections for multiple queries
   - Without pooling: ~50ms overhead per query
   - With pooling: <1ms overhead (0-RTT reconnection)
   - MaxIdleTimeout: 5 minutes

7. **Geographic Proximity Routing**: Prefer nearby nodes
   - Combined score: 50% XOR distance + 50% geographic distance
   - Expected latency reduction: 50%

**Reliability:**

8. **Multiple Bootstrap Nodes**: Hardcoded + DNS seed discovery
   - 6+ hardcoded nodes (globally distributed)
   - DNS TXT record: seed.dht.example.com
   - Parallel connection attempts with first-success wins

   **SECURITY FIX (P5-M5): DNS Seed Fallback Recovery**

   When hardcoded bootstrap nodes are unreachable, the system must fall back
   to DNS seed discovery with multiple failover levels:

   ```go
   // BootstrapRecovery defines multi-tier bootstrap fallback
   type BootstrapRecovery struct {
       HardcodedPeers   []string        // Tier 1: Static hardcoded peers
       DNSSeeds         []string        // Tier 2: DNS TXT record lookups
       BackupDNSSeeds   []string        // Tier 3: Secondary DNS seeds
       CachedPeers      []string        // Tier 4: Previously successful peers
       LastResort       []string        // Tier 5: Well-known fallback IPs
   }

   // DefaultBootstrapConfig with DNS fallback
   var DefaultBootstrapConfig = BootstrapConfig{
       ConnectTimeout:     10 * time.Second,
       MaxParallelDials:   10,
       TierTimeout:        30 * time.Second,  // Time before moving to next tier
       MaxRetries:         3,
       RetryDelay:         5 * time.Second,
       DNSSeedDomains: []string{
           "seed.letstrust.net",
           "seed2.letstrust.net",
           "seed.example.com",          // Backup TLD
       },
   }

   // Bootstrap attempts connection with tiered fallback
   func (r *BootstrapRecovery) Bootstrap(ctx context.Context) error {
       tiers := [][]string{
           r.HardcodedPeers,
           r.resolveDNSSeeds(r.DNSSeeds),
           r.resolveDNSSeeds(r.BackupDNSSeeds),
           r.CachedPeers,
           r.LastResort,
       }

       for tierNum, peers := range tiers {
           if len(peers) == 0 {
               continue
           }

           log.Info("attempting bootstrap tier",
               "tier", tierNum+1,
               "peerCount", len(peers))

           if err := r.tryPeers(ctx, peers); err == nil {
               log.Info("bootstrap successful", "tier", tierNum+1)
               return nil
           }
       }

       return ErrAllBootstrapTiersFailed
   }

   // resolveDNSSeeds performs DNS TXT record lookup for peer addresses
   func (r *BootstrapRecovery) resolveDNSSeeds(domains []string) []string {
       var peers []string
       for _, domain := range domains {
           records, err := net.LookupTXT(domain)
           if err != nil {
               log.Warn("DNS seed lookup failed", "domain", domain, "error", err)
               continue
           }
           for _, record := range records {
               // TXT format: "p2p://<multiaddr>"
               if strings.HasPrefix(record, "p2p://") {
                   peers = append(peers, record)
               }
           }
       }
       return peers
   }
   ```

9. **DHT Replication Factor Tuning**: By data importance
   - CT log entries: k=10 (99.9999% availability)
   - Gateway information: k=5
   - Node info/reputation: k=3
   - Cached content: k=1

### V1.1 Roadmap

1. **BGP RPKI (Route Origin Authorization)**: Prevent unauthorized BGP announcements
   - ROA validity: 90 days
   - Signed by coordinators (multi-sig)
   - Integration with RPKI validators

2. **Network Partition Handling**: (detailed in Partition Handling section)

3. **Reputation Gossiping & Verification**: Byzantine-resistant reputation
   - Quorum: 3+ coordinator signatures required
   - Outlier detection: flag scores > 3 standard deviations from mean
   - Score tolerance: +/- 0.05 for quorum agreement

4. **Graceful CA Degradation**: Fallback modes when pools fail

   | State | Healthy Pools | Behavior |
   |-------|---------------|----------|
   | Normal | 4 | Load balance across all pools |
   | Degraded | 3 | Disable unhealthy pools, continue operation |
   | Emergency | 2 | Increase threshold to 50%, slower but reliable |
   | Disaster | 1 | Accept cached certificates, trigger emergency rotation |
   | Frozen | 0 | Stop issuing, accept only cached/pinned certificates |

### V2.0 Vision

1. **Post-Quantum Cryptography**: Hybrid certificates (classical + PQC)
   - Add Dilithium pool (post-quantum)
   - Validation requires both classical and PQ signatures valid
   - Timeline: Monitor NIST PQC standards

2. **Batch Certificate Issuance**: Sign multiple certificates in one FROST round
   - Build Merkle tree of requests
   - Single FROST signature on Merkle root
   - Include Merkle proofs in certificates
   - Performance: 1000x throughput improvement (1000 certs in 200ms vs 200 seconds)

3. **Backup CA Pools**: Standby pools for catastrophic failure
   - 2 additional standby pools (PoolEd25519C, PoolP256C)
   - Maintain via DKG every 7 days
   - Activate only when both primary pools for an algorithm fail

4. **Advanced BFT Improvements**: Enhanced Byzantine fault tolerance

**Testing Requirements for All Enhancements:**
1. Unit tests (90%+ coverage)
2. Integration tests (E2E scenarios)
3. Chaos testing (random failures)
4. Large-scale simulation (1M+ nodes)
5. Security audit (external review)

**Metrics to Track:**
- Performance impact (latency, throughput)
- Reliability improvement (uptime, failure rate)
- Security effectiveness (attacks detected/prevented)
- Resource usage (CPU, memory, bandwidth)

---

---

## Scale Testing Methodology

This section defines the comprehensive approach to validating the DHT network at scale, including test harness architecture, performance baselines, fault injection strategies, and chaos engineering practices.

### Test Harness Architecture

The scale testing infrastructure enables validation of the DHT network from hundreds to billions of simulated nodes.

**Node Simulation Framework:**

The framework supports three node types with different resource profiles:

| Node Type | Memory | CPU | Network | Use Case |
|-----------|--------|-----|---------|----------|
| Full Node | 512MB | 0.5 core | Full stack | Realistic behavior validation |
| Lightweight Stub | 8MB | 0.01 core | Minimal | Scale simulation |
| Hybrid Node | 64MB | 0.1 core | Partial | Balance of fidelity and scale |

**Recommended Node Ratio by Scale:**

| Scale Target | Full Nodes | Hybrid Nodes | Lightweight Stubs | Total |
|--------------|------------|--------------|-------------------|-------|
| 1K | 1,000 (100%) | 0 | 0 | 1,000 |
| 10K | 1,000 (10%) | 5,000 (50%) | 4,000 (40%) | 10,000 |
| 100K | 1,000 (1%) | 10,000 (10%) | 89,000 (89%) | 100,000 |
| 1M | 1,000 (0.1%) | 10,000 (1%) | 989,000 (98.9%) | 1,000,000 |
| 1B (simulated) | 100 | 1,000 | Routing table extrapolation | N/A |

**Infrastructure Requirements:**

| Scale | Compute | Memory | Network | Storage |
|-------|---------|--------|---------|---------|
| 1K nodes | 8 vCPUs | 32GB | 1Gbps | 100GB SSD |
| 10K nodes | 32 vCPUs | 128GB | 10Gbps | 500GB SSD |
| 100K nodes | 128 vCPUs | 512GB | 25Gbps | 2TB NVMe |
| 1M nodes | 512 vCPUs | 2TB | 100Gbps | 10TB NVMe |

**Node Stub Implementation:**

```go
// LightweightNodeStub provides minimal DHT participation for scale testing
type LightweightNodeStub struct {
    NodeID        [32]byte
    RoutingTable  *CompressedRoutingTable
    ResponseDelay time.Duration
    FailureRate   float64

    // Metrics
    MessagesReceived atomic.Uint64
    MessagesSent     atomic.Uint64
    LookupLatencies  *LatencyHistogram
}

// CompressedRoutingTable stores only essential routing information
type CompressedRoutingTable struct {
    Buckets      [256][]NodeID  // K-bucket entries (NodeID only)
    LastRefresh  [256]time.Time
    BucketSize   int            // Typically 20
}

// HandleMessage processes incoming DHT messages with configurable behavior
func (s *LightweightNodeStub) HandleMessage(msg *DHTMessage) *DHTResponse {
    s.MessagesReceived.Add(1)

    // Simulate failure
    if rand.Float64() < s.FailureRate {
        return nil
    }

    // Simulate network latency
    time.Sleep(s.ResponseDelay)

    switch msg.Type {
    case MessagePing:
        return &DHTResponse{Type: ResponsePong, NodeID: s.NodeID}
    case MessageFindNode:
        return s.findNodeResponse(msg.TargetID)
    case MessageFindValue:
        return s.findValueResponse(msg.Key)
    default:
        return &DHTResponse{Type: ResponseError, Error: "unsupported"}
    }
}
```

**Test Coordinator Architecture:**

```
+------------------+     +------------------+     +------------------+
|  Test Controller |---->|  Node Scheduler  |---->|  Metrics Collector|
|  (orchestrates)  |     |  (K8s/Docker)    |     |  (Prometheus)    |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         v                       v                        v
+------------------+     +------------------+     +------------------+
|  Scenario Engine |     |  Node Pool       |     |  Grafana         |
|  (test cases)    |     |  (1M+ stubs)     |     |  (dashboards)    |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         v                       v                        v
+------------------+     +------------------+     +------------------+
|  Fault Injector  |     |  Network Sim     |     |  Report Generator|
|  (chaos)         |     |  (toxiproxy)     |     |  (analysis)      |
+------------------+     +------------------+     +------------------+
```

---

### Scale Testing Milestones

Each milestone validates specific system behaviors and must pass before proceeding to the next scale level.

**Milestone 1: 1K Nodes (Unit/Integration Baseline)**

| Metric | Target | Validation Method |
|--------|--------|-------------------|
| DHT lookup latency (p99) | < 100ms | Automated test suite |
| Routing table convergence | < 30 seconds | Bootstrap time measurement |
| Transaction throughput | > 100 TPS | Sustained load test |
| Certificate issuance | > 10 certs/second | FROST round timing |
| Byzantine tolerance | f=3 | Fault injection |

Test Scenarios:
1. Full network bootstrap from genesis
2. Node churn (10% join/leave per minute)
3. Single coordinator failure and recovery
4. Network partition (50/50 split) and healing
5. Concurrent transaction storm (1000 concurrent)

**Milestone 2: 10K Nodes (Regional Functionality)**

| Metric | Target | Validation Method |
|--------|--------|-------------------|
| DHT lookup latency (p99) | < 200ms | Multi-region simulation |
| Cross-region replication | < 5 seconds | Geo-distributed test |
| Transaction throughput | > 500 TPS | Sustained 1-hour test |
| Coordinator election | < 10 seconds | Leader failure injection |
| Memory per node | < 256MB | Resource monitoring |

Test Scenarios:
1. Multi-region deployment (3 regions, 3.3K nodes each)
2. Region isolation and recovery
3. Coordinator rotation under load
4. DKG refresh with 21 participants
5. Reputation system convergence

**Milestone 3: 100K Nodes (Multi-Region Coordination)**

| Metric | Target | Validation Method |
|--------|--------|-------------------|
| DHT lookup latency (p99) | < 500ms | Global distribution |
| Transaction throughput | > 2,000 TPS | Multi-client load test |
| Certificate issuance | > 50 certs/second | Parallel FROST pools |
| Storage efficiency | < 1KB/node metadata | DHT storage audit |
| Gossip convergence | < 60 seconds | Information propagation test |

Test Scenarios:
1. Global deployment (7 regions)
2. Cascading region failures (3 regions down)
3. Byzantine attack on coordinator pool (f=7)
4. Mass node restart (10K simultaneous)
5. Storage rebalancing after node churn

**Milestone 4: 1M Nodes (Full DHT Stress Test)**

| Metric | Target | Validation Method |
|--------|--------|-------------------|
| DHT lookup latency (p99) | < 1 second | Hybrid node simulation |
| Transaction throughput | > 10,000 TPS | Distributed load generation |
| Routing table accuracy | > 99% | Lookup success rate |
| Memory efficiency | < 128MB for stubs | Resource profiling |
| Network bandwidth | < 100KB/s per node | Traffic analysis |

Test Scenarios:
1. Sustained 24-hour operation
2. 10% node churn rate continuous
3. Geographic routing optimization
4. Sybil attack resistance (100K malicious nodes)
5. Eclipse attack on specific nodes

**Milestone 5: 1B Nodes (Simulated Routing Validation)**

At billion-node scale, full simulation is impractical. Instead, routing table behavior is validated through mathematical modeling and selective simulation.

Validation Approach:
1. **Routing Table Extrapolation**: Model k-bucket distribution for 1B nodes
2. **Lookup Path Analysis**: Simulate O(log N) lookup hops
3. **Memory Projection**: Validate routing table memory scales logarithmically
4. **Convergence Modeling**: Estimate gossip propagation time

```go
// BillionNodeSimulator validates routing behavior at extreme scale
type BillionNodeSimulator struct {
    NodeCount        uint64        // 1,000,000,000
    BucketSize       int           // 20
    ReplicationFactor int          // 5

    // Statistical models
    LookupHopsModel  *ProbabilityDistribution
    LatencyModel     *LatencyDistribution
    FailureModel     *ReliabilityModel
}

// SimulateLookup estimates lookup behavior for 1B node network
func (s *BillionNodeSimulator) SimulateLookup() LookupResult {
    // Expected hops = log2(1B) / log2(BucketSize) = ~7.5 hops
    expectedHops := math.Log2(float64(s.NodeCount)) / math.Log2(float64(s.BucketSize))

    // Model per-hop latency (50ms average, 200ms p99)
    hopLatency := s.LatencyModel.Sample()

    // Model node availability (99.9% uptime)
    successProb := math.Pow(0.999, expectedHops)

    return LookupResult{
        ExpectedHops:    expectedHops,
        EstimatedLatency: time.Duration(expectedHops * hopLatency),
        SuccessProbability: successProb,
    }
}

// Expected Results for 1B Nodes:
// - Routing table size: ~20 * 30 = 600 entries (30 bits needed for 1B)
// - Memory per node: ~20KB for routing table
// - Expected lookup hops: 7-8
// - Lookup latency (p99): < 2 seconds
// - Lookup success rate: > 99.3%
```

---

### Performance Baselines

Target performance metrics by operation type and scale.

**DHT Operations:**

| Operation | 1K Nodes | 10K Nodes | 100K Nodes | 1M Nodes |
|-----------|----------|-----------|------------|----------|
| PING latency (p50) | 5ms | 10ms | 25ms | 50ms |
| PING latency (p95) | 20ms | 50ms | 100ms | 200ms |
| PING latency (p99) | 50ms | 100ms | 200ms | 500ms |
| FIND_NODE latency (p50) | 20ms | 40ms | 80ms | 150ms |
| FIND_NODE latency (p95) | 80ms | 150ms | 300ms | 600ms |
| FIND_NODE latency (p99) | 150ms | 300ms | 500ms | 1000ms |
| STORE latency (p50) | 30ms | 60ms | 120ms | 250ms |
| STORE latency (p95) | 100ms | 200ms | 400ms | 800ms |
| STORE latency (p99) | 200ms | 400ms | 800ms | 1500ms |

**Transaction Operations:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| Transaction throughput (sustained) | 10,000 TPS | 24-hour average |
| Transaction latency (p50) | < 500ms | End-to-end confirmation |
| Transaction latency (p95) | < 2 seconds | End-to-end confirmation |
| Transaction latency (p99) | < 5 seconds | End-to-end confirmation |
| Block finalization | < 6 seconds | Consensus completion |
| Double-spend prevention | 100% | Byzantine test scenarios |

**Certificate Operations:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| Certificate issuance (single pool) | 5 certs/second | FROST round time |
| Certificate issuance (parallel pools) | 50 certs/second | 10 parallel pools |
| Certificate validation | 10,000/second | Signature verification |
| FROST round completion | < 200ms | DKG participant coordination |
| DKG refresh | < 5 minutes | Full key rotation |

**Resource Utilization Targets:**

| Node Type | CPU (idle) | CPU (loaded) | Memory | Bandwidth |
|-----------|------------|--------------|--------|-----------|
| Coordinator | < 10% | < 80% | < 2GB | < 10MB/s |
| Full Node | < 5% | < 50% | < 512MB | < 1MB/s |
| Service Provider | < 10% | < 70% | < 1GB | < 5MB/s |
| Lightweight Client | < 1% | < 20% | < 64MB | < 100KB/s |

---

### Byzantine Fault Injection

Systematic testing of Byzantine fault tolerance through controlled fault injection.

**Equivocating Coordinator Scenarios:**

```go
// EquivocatingCoordinatorTest validates detection and handling of coordinators
// that send conflicting messages to different nodes
type EquivocatingCoordinatorTest struct {
    CoordinatorID   [32]byte
    VictimNodes     [][32]byte
    ConflictingMsgs []ConflictingMessage
}

// Scenario 1: Double-signing blocks
// Coordinator signs two different blocks at the same height
func TestEquivocatingBlockSigning(t *testing.T) {
    coordinator := createByzantineCoordinator()

    // Sign block A and send to 50% of network
    blockA := createBlock(height: 100, txns: txSetA)
    sigA := coordinator.Sign(blockA)
    broadcastToSubset(blockA, sigA, network[:len(network)/2])

    // Sign block B and send to other 50%
    blockB := createBlock(height: 100, txns: txSetB)
    sigB := coordinator.Sign(blockB)
    broadcastToSubset(blockB, sigB, network[len(network)/2:])

    // Verify detection
    evidence := waitForEquivocationEvidence(timeout: 30*time.Second)
    assert.NotNil(t, evidence)
    assert.Equal(t, coordinator.ID, evidence.AccusedNode)

    // Verify slashing
    slashingTx := waitForSlashing(coordinator.ID, timeout: 60*time.Second)
    assert.NotNil(t, slashingTx)
    assert.True(t, coordinator.Stake == 0)
}

// Scenario 2: Selective message forwarding
// Coordinator forwards transactions to some nodes but not others
func TestSelectiveForwarding(t *testing.T) {
    coordinator := createByzantineCoordinator()

    for i := 0; i < 100; i++ {
        tx := generateTransaction()

        // Forward to only 70% of committee
        recipients := selectRandomSubset(committee, 0.7)
        coordinator.ForwardSelectively(tx, recipients)
    }

    // Verify detection through gossip protocol
    detected := waitForByzantineDetection(coordinator.ID, timeout: 120*time.Second)
    assert.True(t, detected)
}
```

**f=7 Byzantine Committee Testing:**

With a 21-node coordinator committee, up to 7 Byzantine nodes can be tolerated (f = (n-1)/3).

```go
// ByzantineCommitteeTest validates f=7 Byzantine fault tolerance
type ByzantineCommitteeTest struct {
    CommitteeSize   int  // 21
    ByzantineCount  int  // 7 (max tolerable)
    TestDuration    time.Duration
}

// Test scenarios for f=7 Byzantine nodes
var byzantineScenarios = []ByzantineScenario{
    {
        Name: "7 nodes crash simultaneously",
        Type: CrashFault,
        Count: 7,
        ExpectedOutcome: SystemContinues,
    },
    {
        Name: "7 nodes send garbage",
        Type: OmissionFault,
        Count: 7,
        ExpectedOutcome: SystemContinues,
    },
    {
        Name: "7 nodes collude to equivocate",
        Type: ByzantineFault,
        Count: 7,
        ExpectedOutcome: SystemContinues,
    },
    {
        Name: "8 nodes Byzantine (exceeds f)",
        Type: ByzantineFault,
        Count: 8,
        ExpectedOutcome: SystemHalts,  // Safety preserved, liveness lost
    },
    {
        Name: "7 Byzantine + 7 crash",
        Type: MixedFault,
        Count: 14,
        ExpectedOutcome: SystemHalts,  // Only 7 honest nodes remain
    },
}

// RunByzantineCommitteeTests executes all Byzantine scenarios
func RunByzantineCommitteeTests(t *testing.T) {
    committee := createCoordinatorCommittee(21)

    for _, scenario := range byzantineScenarios {
        t.Run(scenario.Name, func(t *testing.T) {
            // Select Byzantine nodes
            byzantineNodes := selectRandomNodes(committee, scenario.Count)

            // Inject Byzantine behavior
            for _, node := range byzantineNodes {
                injectByzantineBehavior(node, scenario.Type)
            }

            // Run transactions
            results := runTransactionWorkload(duration: 5*time.Minute)

            // Verify expected outcome
            if scenario.ExpectedOutcome == SystemContinues {
                assert.True(t, results.TransactionsProcessed > 0)
                assert.True(t, results.SafetyViolations == 0)
            } else {
                assert.True(t, results.SafetyViolations == 0)  // Safety always preserved
            }
        })
    }
}
```

**Malicious Transaction Manipulation:**

```go
// TransactionManipulationTests validates resistance to transaction attacks
var transactionAttacks = []TransactionAttack{
    {
        Name: "Double spend attempt",
        Setup: func(attacker *Node) {
            tx1 := createTransaction(from: attacker, to: victimA, amount: 100)
            tx2 := createTransaction(from: attacker, to: victimB, amount: 100)
            // Both use same UTXO
            broadcastSimultaneously(tx1, tx2)
        },
        ExpectedResult: OnlyOneSucceeds,
    },
    {
        Name: "Invalid signature injection",
        Setup: func(attacker *Node) {
            tx := createTransaction(from: victim, to: attacker, amount: 1000)
            tx.Signature = forgeSignature()  // Invalid
            broadcast(tx)
        },
        ExpectedResult: TransactionRejected,
    },
    {
        Name: "Transaction replay attack",
        Setup: func(attacker *Node) {
            // Capture valid transaction
            validTx := captureTransaction()
            // Wait for confirmation
            waitForConfirmation(validTx)
            // Replay
            broadcast(validTx)
        },
        ExpectedResult: ReplayRejected,
    },
    {
        Name: "Amount overflow attack",
        Setup: func(attacker *Node) {
            tx := createTransaction(from: attacker, to: victim, amount: MaxUint64)
            broadcast(tx)
        },
        ExpectedResult: TransactionRejected,
    },
}
```

**DKG Abort Attacks:**

```go
// DKGAbortAttackTests validates resilience to DKG protocol disruption
type DKGAbortAttackTests struct {
    Participants    int           // 21
    Threshold       int           // 14
    MaxAbortingNodes int          // 7
}

var dkgAbortScenarios = []DKGAbortScenario{
    {
        Name: "Single node aborts Round 1",
        AbortingNodes: 1,
        AbortRound: 1,
        ExpectedOutcome: DKGCompletes,
    },
    {
        Name: "f nodes abort Round 2",
        AbortingNodes: 7,
        AbortRound: 2,
        ExpectedOutcome: DKGCompletes,
    },
    {
        Name: "f nodes send invalid shares",
        AbortingNodes: 7,
        BehaviorType: InvalidShares,
        ExpectedOutcome: DKGCompletes,  // Bad shares detected and excluded
    },
    {
        Name: "f+1 nodes abort (exceeds threshold)",
        AbortingNodes: 8,
        AbortRound: 1,
        ExpectedOutcome: DKGFails,  // Graceful failure, no key generated
    },
    {
        Name: "Delayed share submission",
        AbortingNodes: 7,
        BehaviorType: DelayedShares,
        Delay: 30 * time.Second,
        ExpectedOutcome: DKGCompletes,  // Timeout and exclude slow nodes
    },
    {
        Name: "Inconsistent complaints",
        AbortingNodes: 7,
        BehaviorType: InconsistentComplaints,
        ExpectedOutcome: DKGCompletes,  // Detect and exclude inconsistent nodes
    },
}

// TestDKGAbortResilience validates DKG completes despite Byzantine participants
func TestDKGAbortResilience(t *testing.T) {
    for _, scenario := range dkgAbortScenarios {
        t.Run(scenario.Name, func(t *testing.T) {
            participants := createDKGParticipants(21)

            // Configure aborting nodes
            abortingNodes := selectRandomNodes(participants, scenario.AbortingNodes)
            for _, node := range abortingNodes {
                configureDKGAbort(node, scenario)
            }

            // Run DKG
            result := runDKG(participants, threshold: 14)

            // Verify outcome
            if scenario.ExpectedOutcome == DKGCompletes {
                assert.NotNil(t, result.PublicKey)
                assert.Equal(t, 14, result.QualifiedParticipants)
                assert.True(t, result.Duration < 60*time.Second)
            } else {
                assert.Nil(t, result.PublicKey)
                assert.Equal(t, DKGAborted, result.Status)
            }
        })
    }
}
```

---

### Chaos Engineering Integration

Systematic chaos engineering practices to validate system resilience under real-world failure conditions.

**Network Partition Simulation:**

Using toxiproxy for controlled network degradation:

```yaml
# toxiproxy configuration for partition simulation
# File: test/chaos/toxiproxy-config.yaml

proxies:
  - name: dht_node_proxy
    listen: 0.0.0.0:8080
    upstream: dht-node:8080

toxics:
  # Simulate network partition
  partition:
    type: timeout
    stream: upstream
    attributes:
      timeout: 0  # Complete disconnect

  # Simulate high latency
  latency:
    type: latency
    stream: upstream
    attributes:
      latency: 500
      jitter: 100

  # Simulate packet loss
  packet_loss:
    type: limit_data
    stream: upstream
    attributes:
      bytes: 0  # Drop all packets

  # Simulate bandwidth constraint
  bandwidth:
    type: bandwidth
    stream: upstream
    attributes:
      rate: 1024  # 1KB/s
```

Using tc/netem for kernel-level network simulation:

```bash
#!/bin/bash
# File: test/chaos/network-chaos.sh

# Partition simulation - block traffic to specific nodes
partition_nodes() {
    local partition_targets="$1"
    for target in $partition_targets; do
        iptables -A OUTPUT -d "$target" -j DROP
        iptables -A INPUT -s "$target" -j DROP
    done
}

# Latency injection
inject_latency() {
    local interface="$1"
    local delay_ms="$2"
    local jitter_ms="$3"
    tc qdisc add dev "$interface" root netem delay "${delay_ms}ms" "${jitter_ms}ms" distribution normal
}

# Packet loss injection
inject_packet_loss() {
    local interface="$1"
    local loss_percent="$2"
    tc qdisc add dev "$interface" root netem loss "${loss_percent}%"
}

# Bandwidth limitation
limit_bandwidth() {
    local interface="$1"
    local rate="$2"  # e.g., "1mbit"
    tc qdisc add dev "$interface" root tbf rate "$rate" burst 32kbit latency 400ms
}

# Packet corruption
inject_corruption() {
    local interface="$1"
    local corrupt_percent="$2"
    tc qdisc add dev "$interface" root netem corrupt "${corrupt_percent}%"
}

# Packet reordering
inject_reordering() {
    local interface="$1"
    local reorder_percent="$2"
    local delay_ms="$3"
    tc qdisc add dev "$interface" root netem delay "${delay_ms}ms" reorder "${reorder_percent}%"
}

# Clear all network chaos
cleanup() {
    tc qdisc del dev "$interface" root 2>/dev/null
    iptables -F
}
```

**Coordinator Failure Injection:**

```go
// CoordinatorChaosTests injects various failure modes into coordinators
type CoordinatorChaosTests struct {
    Network         *TestNetwork
    FailureInterval time.Duration
    RecoveryTime    time.Duration
}

var coordinatorFailureModes = []FailureMode{
    {
        Name: "Graceful shutdown",
        Inject: func(c *Coordinator) {
            c.Shutdown(graceful: true)
        },
        ExpectedRecovery: 10 * time.Second,
    },
    {
        Name: "SIGKILL (crash)",
        Inject: func(c *Coordinator) {
            syscall.Kill(c.PID, syscall.SIGKILL)
        },
        ExpectedRecovery: 30 * time.Second,
    },
    {
        Name: "OOM killer simulation",
        Inject: func(c *Coordinator) {
            // Trigger memory limit
            c.AllocateMemory(10 * GB)
        },
        ExpectedRecovery: 60 * time.Second,
    },
    {
        Name: "Disk full",
        Inject: func(c *Coordinator) {
            fillDisk(c.DataDir)
        },
        ExpectedRecovery: 120 * time.Second,  // Requires cleanup
    },
    {
        Name: "CPU starvation",
        Inject: func(c *Coordinator) {
            // Run CPU-intensive process
            startCPUHog(c.ContainerID, cores: 4)
        },
        ExpectedRecovery: 10 * time.Second,  // After CPU hog stops
    },
    {
        Name: "Network interface down",
        Inject: func(c *Coordinator) {
            exec.Command("ip", "link", "set", c.Interface, "down").Run()
        },
        ExpectedRecovery: 5 * time.Second,  // After interface up
    },
}

// RunCoordinatorChaos executes coordinator failure scenarios
func (ct *CoordinatorChaosTests) RunCoordinatorChaos(t *testing.T) {
    for _, mode := range coordinatorFailureModes {
        t.Run(mode.Name, func(t *testing.T) {
            // Select random coordinator
            coordinator := ct.Network.SelectRandomCoordinator()

            // Record pre-failure state
            preFailureState := ct.Network.CaptureState()

            // Inject failure
            mode.Inject(coordinator)

            // Measure recovery time
            start := time.Now()
            ct.Network.WaitForRecovery(coordinator.ID)
            recoveryTime := time.Since(start)

            // Verify recovery within expected time
            assert.LessOrEqual(t, recoveryTime, mode.ExpectedRecovery*2)

            // Verify no data loss
            postRecoveryState := ct.Network.CaptureState()
            assert.True(t, statesConsistent(preFailureState, postRecoveryState))

            // Verify transactions continue
            tx := createTestTransaction()
            result := ct.Network.SubmitTransaction(tx)
            assert.True(t, result.Success)
        })
    }
}
```

**Clock Skew Testing:**

```go
// ClockSkewTests validates system behavior under time synchronization issues
type ClockSkewTests struct {
    MaxSkew      time.Duration
    SkewPatterns []SkewPattern
}

var clockSkewPatterns = []SkewPattern{
    {
        Name: "Single node 30s ahead",
        Nodes: 1,
        Skew: 30 * time.Second,
        Direction: Forward,
    },
    {
        Name: "Single node 30s behind",
        Nodes: 1,
        Skew: 30 * time.Second,
        Direction: Backward,
    },
    {
        Name: "50% of nodes 1 minute skew",
        Nodes: -1,  // 50% of network
        Skew: 60 * time.Second,
        Direction: Forward,
    },
    {
        Name: "Gradual drift (1s/minute)",
        Nodes: 1,
        DriftRate: 1 * time.Second,
        DriftPeriod: 1 * time.Minute,
        Duration: 1 * time.Hour,
    },
    {
        Name: "Clock jump backwards",
        Nodes: 1,
        Skew: -5 * time.Minute,  // NTP correction scenario
        Direction: Backward,
    },
}

// InjectClockSkew uses libfaketime or similar to adjust node clocks
func InjectClockSkew(node *Node, skew time.Duration) error {
    // For container-based testing
    cmd := fmt.Sprintf("date -s '%s'", time.Now().Add(skew).Format(time.RFC3339))
    return exec.Command("docker", "exec", node.ContainerID, "sh", "-c", cmd).Run()
}

// TestClockSkewResilience validates system handles clock skew
func TestClockSkewResilience(t *testing.T) {
    for _, pattern := range clockSkewPatterns {
        t.Run(pattern.Name, func(t *testing.T) {
            network := createTestNetwork(nodeCount: 100)

            // Select nodes for skew
            var skewNodes []*Node
            if pattern.Nodes == -1 {
                skewNodes = network.Nodes[:len(network.Nodes)/2]
            } else {
                skewNodes = network.SelectRandom(pattern.Nodes)
            }

            // Inject clock skew
            for _, node := range skewNodes {
                InjectClockSkew(node, pattern.Skew)
            }

            // Run workload
            results := network.RunTransactionWorkload(duration: 5*time.Minute)

            // Verify correctness
            assert.Equal(t, 0, results.SafetyViolations)
            assert.True(t, results.SuccessRate > 0.95)  // 95% success despite skew

            // Verify skewed nodes eventually sync or are excluded
            syncStatus := network.CheckClockSync(tolerance: 5*time.Second)
            assert.True(t, syncStatus.InSyncNodes >= len(network.Nodes)-pattern.Nodes)
        })
    }
}
```

**CI/CD Pipeline Integration:**

```yaml
# File: .github/workflows/chaos-testing.yml

name: Chaos Engineering Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:
    inputs:
      chaos_level:
        description: 'Chaos intensity (low/medium/high)'
        required: true
        default: 'medium'

jobs:
  network-partition-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4

      - name: Setup test infrastructure
        run: |
          docker-compose -f test/chaos/docker-compose.yml up -d

      - name: Install chaos tools
        run: |
          # Install toxiproxy
          wget https://github.com/Shopify/toxiproxy/releases/download/v2.7.0/toxiproxy-server-linux-amd64
          chmod +x toxiproxy-server-linux-amd64
          ./toxiproxy-server-linux-amd64 &

      - name: Run partition tests
        run: |
          go test -v -timeout 45m ./test/chaos/partition_test.go

      - name: Collect metrics
        if: always()
        run: |
          ./scripts/collect-chaos-metrics.sh > chaos-metrics.json

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: partition-test-results
          path: chaos-metrics.json

  coordinator-failure-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4

      - name: Setup Kubernetes cluster
        uses: azure/setup-kubectl@v3

      - name: Deploy test network
        run: |
          kubectl apply -f test/chaos/k8s/test-network.yaml
          kubectl wait --for=condition=ready pod -l app=dht-node --timeout=300s

      - name: Run coordinator chaos
        run: |
          go test -v -timeout 45m ./test/chaos/coordinator_test.go

  byzantine-fault-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4

      - name: Deploy Byzantine test network
        run: |
          docker-compose -f test/chaos/byzantine-compose.yml up -d

      - name: Run Byzantine scenarios
        run: |
          go test -v -timeout 75m ./test/chaos/byzantine_test.go

      - name: Generate report
        if: always()
        run: |
          ./scripts/generate-chaos-report.sh

  weekly-extended-chaos:
    if: github.event.schedule == '0 2 * * 0'  # Sundays only
    runs-on: self-hosted  # Requires dedicated hardware
    timeout-minutes: 480  # 8 hours
    steps:
      - uses: actions/checkout@v4

      - name: Run extended chaos suite
        run: |
          ./scripts/run-extended-chaos.sh --duration 6h --intensity high
```

---

### Load Testing Procedures

Comprehensive load testing validates system performance under various load patterns.

**Sustained Load Testing (24-Hour Runs):**

```go
// SustainedLoadTest runs 24-hour continuous load tests
type SustainedLoadTest struct {
    TargetTPS       int           // Target transactions per second
    Duration        time.Duration // 24 hours
    RampUpTime      time.Duration // Time to reach target TPS
    MetricInterval  time.Duration // Metric collection interval
}

// SustainedLoadConfig defines 24-hour test parameters
var sustainedLoadConfig = SustainedLoadConfig{
    TargetTPS:      1000,
    Duration:       24 * time.Hour,
    RampUpTime:     30 * time.Minute,
    MetricInterval: 1 * time.Minute,

    // Success criteria
    MinSuccessRate:     0.999,  // 99.9%
    MaxP99Latency:      5 * time.Second,
    MaxErrorRate:       0.001,  // 0.1%
    MaxMemoryGrowth:    1.5,    // 50% growth allowed
    MaxGoroutineGrowth: 1.2,    // 20% growth allowed
}

// RunSustainedLoadTest executes 24-hour load test
func RunSustainedLoadTest(t *testing.T, config SustainedLoadConfig) {
    network := setupTestNetwork()
    defer network.Teardown()

    // Baseline metrics
    baselineMetrics := network.CollectMetrics()

    // Start load generation
    loadGen := NewLoadGenerator(config.TargetTPS)
    loadGen.RampUp(config.RampUpTime)

    // Collect metrics throughout test
    var allMetrics []Metrics
    ticker := time.NewTicker(config.MetricInterval)

    startTime := time.Now()
    for time.Since(startTime) < config.Duration {
        select {
        case <-ticker.C:
            metrics := network.CollectMetrics()
            allMetrics = append(allMetrics, metrics)

            // Check for degradation
            if metrics.P99Latency > config.MaxP99Latency {
                t.Logf("WARNING: P99 latency exceeded threshold: %v", metrics.P99Latency)
            }

            // Check for memory leak
            memoryGrowth := float64(metrics.MemoryUsage) / float64(baselineMetrics.MemoryUsage)
            if memoryGrowth > config.MaxMemoryGrowth {
                t.Errorf("Memory leak detected: %.2fx growth", memoryGrowth)
            }

            // Check for goroutine leak
            goroutineGrowth := float64(metrics.GoroutineCount) / float64(baselineMetrics.GoroutineCount)
            if goroutineGrowth > config.MaxGoroutineGrowth {
                t.Errorf("Goroutine leak detected: %.2fx growth", goroutineGrowth)
            }
        }
    }

    // Final analysis
    report := AnalyzeLoadTestResults(allMetrics)
    assert.GreaterOrEqual(t, report.OverallSuccessRate, config.MinSuccessRate)
    assert.LessOrEqual(t, report.MaxP99Latency, config.MaxP99Latency)

    // Generate report
    GenerateLoadTestReport(report, "sustained-load-24h.html")
}

// MetricsToCollect defines what to measure during load tests
type MetricsToCollect struct {
    // Throughput
    TransactionsPerSecond   float64
    BytesPerSecond          float64
    RequestsPerSecond       float64

    // Latency
    P50Latency              time.Duration
    P95Latency              time.Duration
    P99Latency              time.Duration
    P999Latency             time.Duration
    MaxLatency              time.Duration

    // Errors
    ErrorRate               float64
    ErrorsByType            map[string]int

    // Resources
    CPUUsage                float64
    MemoryUsage             uint64
    GoroutineCount          int
    OpenFileDescriptors     int
    NetworkConnections      int

    // DHT-specific
    RoutingTableSize        int
    PendingLookups          int
    ReplicationLag          time.Duration
}
```

**Spike Testing (10x Normal Load):**

```go
// SpikeTest validates system behavior under sudden load increases
type SpikeTest struct {
    BaselineTPS     int           // Normal operating load
    SpikeTPS        int           // Spike load (10x baseline)
    SpikeDuration   time.Duration // How long spike lasts
    RecoveryTimeout time.Duration // Max time to return to normal
}

// SpikeTestScenarios defines various spike patterns
var spikeTestScenarios = []SpikeScenario{
    {
        Name: "Instant 10x spike",
        Pattern: InstantSpike,
        BaselineTPS: 1000,
        SpikeTPS: 10000,
        SpikeDuration: 5 * time.Minute,
        ExpectedBehavior: GracefulDegradation,
    },
    {
        Name: "Gradual ramp to 10x",
        Pattern: GradualRamp,
        BaselineTPS: 1000,
        SpikeTPS: 10000,
        RampTime: 2 * time.Minute,
        SpikeDuration: 5 * time.Minute,
        ExpectedBehavior: SmoothHandling,
    },
    {
        Name: "Repeated spikes",
        Pattern: RepeatedSpikes,
        BaselineTPS: 1000,
        SpikeTPS: 5000,
        SpikeDuration: 1 * time.Minute,
        IntervalBetweenSpikes: 5 * time.Minute,
        SpikeCount: 5,
        ExpectedBehavior: ConsistentRecovery,
    },
    {
        Name: "Thundering herd",
        Pattern: ThunderingHerd,
        BaselineTPS: 0,
        SpikeTPS: 10000,  // All at once after quiet period
        QuietPeriod: 10 * time.Minute,
        SpikeDuration: 1 * time.Minute,
        ExpectedBehavior: BackpressureActivated,
    },
}

// RunSpikeTest executes spike load scenario
func RunSpikeTest(t *testing.T, scenario SpikeScenario) {
    network := setupTestNetwork()
    loadGen := NewLoadGenerator(scenario.BaselineTPS)

    // Establish baseline
    baselineMetrics := runBaselineLoad(loadGen, duration: 5*time.Minute)

    // Generate spike
    switch scenario.Pattern {
    case InstantSpike:
        loadGen.SetTPS(scenario.SpikeTPS)

    case GradualRamp:
        loadGen.RampTo(scenario.SpikeTPS, scenario.RampTime)

    case RepeatedSpikes:
        for i := 0; i < scenario.SpikeCount; i++ {
            loadGen.SetTPS(scenario.SpikeTPS)
            time.Sleep(scenario.SpikeDuration)
            loadGen.SetTPS(scenario.BaselineTPS)
            time.Sleep(scenario.IntervalBetweenSpikes)
        }

    case ThunderingHerd:
        loadGen.Stop()
        time.Sleep(scenario.QuietPeriod)
        loadGen.SetTPS(scenario.SpikeTPS)
    }

    // Collect spike metrics
    spikeMetrics := collectMetrics(duration: scenario.SpikeDuration)

    // Return to baseline and measure recovery
    loadGen.SetTPS(scenario.BaselineTPS)
    recoveryStart := time.Now()

    for time.Since(recoveryStart) < scenario.RecoveryTimeout {
        currentMetrics := network.CollectMetrics()
        if metricsStabilized(currentMetrics, baselineMetrics) {
            t.Logf("System recovered in %v", time.Since(recoveryStart))
            break
        }
        time.Sleep(10 * time.Second)
    }

    // Verify no permanent degradation
    finalMetrics := runBaselineLoad(loadGen, duration: 5*time.Minute)
    assert.InDelta(t, baselineMetrics.P99Latency, finalMetrics.P99Latency, 0.2)
    assert.InDelta(t, baselineMetrics.SuccessRate, finalMetrics.SuccessRate, 0.01)
}
```

**Soak Testing (Memory Leak Detection):**

```go
// SoakTest runs extended tests to detect resource leaks
type SoakTest struct {
    Duration          time.Duration // 72 hours recommended
    LowLoadTPS        int           // Minimal background load
    MetricInterval    time.Duration // How often to check
    LeakThresholds    LeakThresholds
}

// LeakThresholds defines acceptable resource growth
type LeakThresholds struct {
    MaxMemoryGrowthPercent    float64 // e.g., 10% growth over 72h
    MaxGoroutineGrowthPercent float64 // e.g., 5% growth
    MaxFDGrowthPercent        float64 // e.g., 5% growth
    MaxConnectionGrowth       float64 // e.g., 5% growth
}

// DefaultSoakThresholds for 72-hour test
var DefaultSoakThresholds = LeakThresholds{
    MaxMemoryGrowthPercent:    10.0,
    MaxGoroutineGrowthPercent: 5.0,
    MaxFDGrowthPercent:        5.0,
    MaxConnectionGrowth:       5.0,
}

// RunSoakTest executes extended leak detection test
func RunSoakTest(t *testing.T, config SoakTest) {
    network := setupTestNetwork()

    // Force GC and get baseline
    runtime.GC()
    time.Sleep(10 * time.Second)
    baseline := collectResourceMetrics()

    // Start minimal load
    loadGen := NewLoadGenerator(config.LowLoadTPS)
    loadGen.Start()

    // Track metrics over time
    var resourceHistory []ResourceMetrics
    ticker := time.NewTicker(config.MetricInterval)

    startTime := time.Now()
    for time.Since(startTime) < config.Duration {
        select {
        case <-ticker.C:
            // Force GC before measurement to get accurate heap size
            runtime.GC()

            metrics := collectResourceMetrics()
            resourceHistory = append(resourceHistory, metrics)

            // Log progress
            elapsed := time.Since(startTime)
            memGrowth := (float64(metrics.HeapAlloc) - float64(baseline.HeapAlloc)) / float64(baseline.HeapAlloc) * 100
            t.Logf("[%v] Memory growth: %.2f%%, Goroutines: %d, FDs: %d",
                elapsed.Truncate(time.Minute),
                memGrowth,
                metrics.GoroutineCount,
                metrics.OpenFDs,
            )

            // Early termination on severe leak
            if memGrowth > config.LeakThresholds.MaxMemoryGrowthPercent*2 {
                t.Fatalf("Severe memory leak detected: %.2f%% growth", memGrowth)
            }
        }
    }

    // Final analysis
    final := resourceHistory[len(resourceHistory)-1]

    // Check memory growth
    memGrowth := (float64(final.HeapAlloc) - float64(baseline.HeapAlloc)) / float64(baseline.HeapAlloc) * 100
    if memGrowth > config.LeakThresholds.MaxMemoryGrowthPercent {
        t.Errorf("Memory leak: %.2f%% growth (threshold: %.2f%%)",
            memGrowth, config.LeakThresholds.MaxMemoryGrowthPercent)

        // Capture heap profile for analysis
        captureHeapProfile("soak-test-heap.pprof")
    }

    // Check goroutine growth
    goroutineGrowth := (float64(final.GoroutineCount) - float64(baseline.GoroutineCount)) / float64(baseline.GoroutineCount) * 100
    if goroutineGrowth > config.LeakThresholds.MaxGoroutineGrowthPercent {
        t.Errorf("Goroutine leak: %.2f%% growth (threshold: %.2f%%)",
            goroutineGrowth, config.LeakThresholds.MaxGoroutineGrowthPercent)

        // Capture goroutine profile
        captureGoroutineProfile("soak-test-goroutines.txt")
    }

    // Check file descriptor growth
    fdGrowth := (float64(final.OpenFDs) - float64(baseline.OpenFDs)) / float64(baseline.OpenFDs) * 100
    if fdGrowth > config.LeakThresholds.MaxFDGrowthPercent {
        t.Errorf("File descriptor leak: %.2f%% growth (threshold: %.2f%%)",
            fdGrowth, config.LeakThresholds.MaxFDGrowthPercent)
    }

    // Generate trend analysis
    GenerateSoakTestReport(resourceHistory, "soak-test-report.html")
}

// ResourceMetrics captured during soak test
type ResourceMetrics struct {
    Timestamp       time.Time
    HeapAlloc       uint64
    HeapInuse       uint64
    HeapObjects     uint64
    GoroutineCount  int
    OpenFDs         int
    NetworkConns    int
    ThreadCount     int

    // GC metrics
    NumGC           uint32
    PauseTotal      time.Duration
    LastPause       time.Duration
}

// collectResourceMetrics gathers all resource metrics
func collectResourceMetrics() ResourceMetrics {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)

    return ResourceMetrics{
        Timestamp:      time.Now(),
        HeapAlloc:      m.HeapAlloc,
        HeapInuse:      m.HeapInuse,
        HeapObjects:    m.HeapObjects,
        GoroutineCount: runtime.NumGoroutine(),
        OpenFDs:        countOpenFDs(),
        NetworkConns:   countNetworkConnections(),
        ThreadCount:    runtime.GOMAXPROCS(-1),
        NumGC:          m.NumGC,
        PauseTotal:     time.Duration(m.PauseTotalNs),
        LastPause:      time.Duration(m.PauseNs[(m.NumGC+255)%256]),
    }
}
```

**Load Test Execution Scripts:**

```bash
#!/bin/bash
# File: scripts/run-load-tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
LOAD_TEST_TYPE="${1:-sustained}"
DURATION="${2:-24h}"
TARGET_TPS="${3:-1000}"
REPORT_DIR="${PROJECT_ROOT}/test/reports/load-tests"

mkdir -p "$REPORT_DIR"

run_sustained_load() {
    echo "Running sustained load test: ${DURATION} at ${TARGET_TPS} TPS"

    go test -v -timeout 25h \
        -run TestSustainedLoad \
        -args \
            -duration="$DURATION" \
            -target-tps="$TARGET_TPS" \
            -report-dir="$REPORT_DIR" \
        "${PROJECT_ROOT}/test/load/..."
}

run_spike_test() {
    echo "Running spike test: 10x load spike"

    go test -v -timeout 2h \
        -run TestSpikeLoad \
        -args \
            -baseline-tps="$TARGET_TPS" \
            -spike-multiplier=10 \
            -report-dir="$REPORT_DIR" \
        "${PROJECT_ROOT}/test/load/..."
}

run_soak_test() {
    echo "Running soak test: ${DURATION} for leak detection"

    go test -v -timeout 75h \
        -run TestSoakLoad \
        -args \
            -duration="$DURATION" \
            -low-tps=100 \
            -report-dir="$REPORT_DIR" \
        "${PROJECT_ROOT}/test/load/..."
}

case "$LOAD_TEST_TYPE" in
    sustained)
        run_sustained_load
        ;;
    spike)
        run_spike_test
        ;;
    soak)
        run_soak_test
        ;;
    all)
        run_sustained_load
        run_spike_test
        run_soak_test
        ;;
    *)
        echo "Usage: $0 {sustained|spike|soak|all} [duration] [target-tps]"
        exit 1
        ;;
esac

# Generate combined report
echo "Generating combined load test report..."
go run "${PROJECT_ROOT}/cmd/tools/load-report/main.go" \
    --input-dir="$REPORT_DIR" \
    --output="${REPORT_DIR}/combined-report-$(date +%Y%m%d-%H%M%S).html"

echo "Load tests completed. Reports available in: $REPORT_DIR"
```

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.4 | 2026-01-10 | Added comprehensive Scale Testing Methodology section: test harness architecture with node simulation framework (full/hybrid/stub nodes), scale testing milestones (1K to 1B nodes), performance baselines by operation type, Byzantine fault injection scenarios (equivocating coordinators, f=7 committee testing, DKG abort attacks), chaos engineering integration (toxiproxy, tc/netem, CI/CD pipeline), and load testing procedures (sustained 24h, spike 10x, soak 72h) |
| 1.3 | 2026-01-10 | Added comprehensive operational procedures: rolling upgrade procedure with governance process and rollback triggers, partition recovery operations with vector clock discovery and transaction log reconciliation, node recovery procedure with FROST re-enrollment and reputation restoration, enhanced monitoring with structured logging format and operational runbook references, disaster recovery procedures with multi-region architecture and FROST share backup strategy |
| 1.2 | 2026-01-10 | Added deployment runbooks (coordinator init, genesis bootstrap, failover, rolling upgrades), expanded recovery procedures (detection, assessment, recovery, verification), fixed lock TTL documentation |
| 1.1 | 2026-01-10 | FINAL DESIGN: Three-way partition VRF selection, gray zone enhancements (timeout, transaction queuing, VRF initiator tie-breaking), flapping partition detection, lock TTL extensions |
| 1.0 | 2025-12-30 | Consolidated specification: genesis protocol, partition handling, telemetry |

**Document Version:** 1.4
**Last Updated:** 2026-01-10
**Status:** Production Specification

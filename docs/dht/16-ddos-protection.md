# Network-Wide DDoS Protection System

## Overview

The Trusted DHT Network provides **network-wide DDoS protection** for ALL nodes and services. This protection extends not only to the DHT infrastructure itself, but to any service hosted on the network - including e-commerce sites, cloud hosting, SaaS applications, and any user-deployed workloads.

The system implements a **5-layer defense model** that combines traffic dilution, rate limiting, proof-of-work challenges, untrusted node work pools, and collaborative threat intelligence to create a resilient, self-healing defense infrastructure.

> **Cross-References:**
> - Security constants and cryptographic requirements: See [03-security-trust.md](03-security-trust.md)
> - Reputation thresholds and collaborative defense: See [09-defense-reputation.md](09-defense-reputation.md)
> - Network architecture and gateway mesh: See [02-network-architecture.md](02-network-architecture.md)

**Source**: `pkg/defense/`

---

## Quick Reference: Resource Bounds

### PoW Challenge Pool

| Parameter | Value | Description |
|-----------|-------|-------------|
| Max Total Challenges | 1,000,000 | Global pool limit (~100MB memory) |
| Memory Budget | ~100MB | 1M challenges x 128 bytes/slot |
| Pre-emptive Eviction | 95% (950,000) | Triggers LRU eviction |
| Eviction Amount | 5% (50,000) | Oldest challenges removed |
| Eviction Algorithm | LRU | Least Recently Used eviction |
| Per-IP Pending | 3 | Max outstanding per IP |
| Per-IP Rate | 10/minute | Challenge request rate |
| Challenge TTL | 5 minutes | CreatedAt to ExpiresAt |
| Solution Deadline | 5 minutes | Must submit within TTL |
| Cleanup Interval | 30 seconds | Expired challenge removal |
| Pool Structure | Pre-allocated | Fixed-size, no runtime alloc |
| IP Deduplication | Allowed | Same IP can have multiple challenges (up to 3) |
| Pool Full Behavior | Evict oldest | Pre-emptive eviction at 95%, reject at 100% |

### Flow State Tracker

| Parameter | Value | Description |
|-----------|-------|-------------|
| Max Flows | 1,000,000 | Global flow limit |
| Pre-emptive Eviction | 95% (950,000) | Triggers eviction |
| Eviction Amount | 5% (50,000) | Oldest flows removed |
| Eviction Order | By LastSeen | Sorted by activity time |
| Idle Timeout | 60 seconds | Inactive flow cleanup |

### IP Spoofing Protection

| Parameter | Value | Description |
|-----------|-------|-------------|
| Bidirectional Verify | Required | Must complete challenge-response |
| Asymmetric RTT Max | 10x baseline | Rejects extreme path asymmetry |
| Connectivity Timeout | 5 seconds | Max time for verification handshake |
| Verification Methods | 3 | TCP handshake, PoW challenge, QUIC token |

### Threat Intelligence

| Parameter | Value | Description |
|-----------|-------|-------------|
| Cleanup Interval | 5 minutes | `CleanupExpiredThreats()` |
| Confidence Decay | 5%/day | `0.95^days` formula |
| LastUpdated Reset | On report | Prevents stale accumulation |
| Deactivation Threshold | 0.3 | Confidence below deactivates |
| Deletion Threshold | 0.1 | Confidence below deletes |

### Rate Limiting

| Parameter | Value | Description |
|-----------|-------|-------------|
| TOCTOU Prevention | Check in lock | Atomic check-and-modify |
| Per-Transport | Variable | See transport table |
| IP State Cleanup | 5 minutes | Removes stale entries |
| IP State Max Age | 1 hour | Idle entry expiration |

### Rate Limit State Management

| Parameter | Value | Description |
|-----------|-------|-------------|
| Max Tracked IPs | 1,000,000 | Global IP tracking limit |
| Memory Budget | 256MB | Maximum memory for rate limit state |
| Eviction Policy | LRU | Least Recently Used eviction on overflow |
| Pre-emptive Eviction | 95% (950,000) | Triggers LRU eviction before overflow |
| Eviction Amount | 5% (50,000) | Oldest entries removed per eviction |
| Entry Size | ~256 bytes | Per-IP state structure size |
| Cleanup Interval | 5 minutes | Stale entry removal frequency |

### Nonce Replay Prevention (Counting Bloom Filter)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Filter Type | Counting Bloom | Supports removal (not standard Bloom) |
| False Positive Rate | 0.1% (0.001) | Target false positive rate |
| Time Partitions | 6 partitions | 10-minute windows per partition |
| Memory Budget | 100MB | Maximum memory for Bloom filter |
| Partition Rotation | 10 minutes | Oldest partition cleared on rotation |
| Counter Size | 4 bits | Per-bucket counter (max 15) |
| Hash Functions | 7 | Optimal for target FP rate |

---

## Architecture

### 5-Layer Protection Model

```
+===========================================================================+
|                       NETWORK-WIDE DDOS PROTECTION                        |
+===========================================================================+
|                                                                           |
|  INCOMING ATTACK TRAFFIC                                                  |
|  ========================                                                 |
|          |                                                                |
|          v                                                                |
|  +-------------------------------------------------------------------+    |
|  | LAYER 1: TRAFFIC DILUTION (Gateway Mesh)                          |    |
|  |                                                                   |    |
|  |  +--------+  +--------+  +--------+       +--------+              |    |
|  |  |Gateway |  |Gateway |  |Gateway |  ...  |Gateway |  10,000+     |    |
|  |  |  #1    |  |  #2    |  |  #3    |       | #N     |  Nodes       |    |
|  |  +---+----+  +---+----+  +---+----+       +---+----+              |    |
|  |      |           |           |               |                    |    |
|  |      +-----------+-----------+---------------+                    |    |
|  |                  |                                                |    |
|  |          Anycast + BGP FlowSpec                                   |    |
|  |          Attack distributed across all gateways                   |    |
|  +---------------------------+---------------------------------------+    |
|                              |                                            |
|                              v                                            |
|  +-------------------------------------------------------------------+    |
|  | LAYER 2: RATE LIMITING & REPUTATION                               |    |
|  |                                                                   |    |
|  |  Per-IP Controls:                                                 |    |
|  |    - Max 10 concurrent connections                                |    |
|  |    - Max 100 requests/second                                      |    |
|  |    - Max 20 new connections/minute                                |    |
|  |    - Bandwidth throttling for low-reputation IPs                  |    |
|  |    - IP reputation scoring (0.0 - 1.0)                            |    |
|  +---------------------------+---------------------------------------+    |
|                              |                                            |
|                              v                                            |
|  +-------------------------------------------------------------------+    |
|  | LAYER 3: PROOF-OF-WORK CHALLENGE                                  |    |
|  |                                                                   |    |
|  |  +------------------+    +------------------+                     |    |
|  |  | Challenge Issue  |--->| PoW Verification |                     |    |
|  |  | (Hashcash-style) |    | (2^20 hashes)    |                     |    |
|  |  +------------------+    +------------------+                     |    |
|  |                                                                   |    |
|  |  - Adaptive difficulty based on network load                      |    |
|  |  - 1-hour solution cache (prevents repeat work)                   |    |
|  |  - Prioritizes clients with valid solutions                       |    |
|  +---------------------------+---------------------------------------+    |
|                              |                                            |
|                              v                                            |
|  +-------------------------------------------------------------------+    |
|  | LAYER 4: UNTRUSTED NODE WORK POOL                                 |    |
|  |                                                                   |    |
|  |  +-------------+  +-------------+  +-------------+                |    |
|  |  | Untrusted   |  | Untrusted   |  | Untrusted   |  ...           |    |
|  |  | Node #1     |  | Node #2     |  | Node #3     |                |    |
|  |  | PoW Verify  |  | PoW Verify  |  | Traffic     |                |    |
|  |  | + Scrub     |  | + Scrub     |  | Scrubbing   |                |    |
|  |  +-------------+  +-------------+  +-------------+                |    |
|  |                                                                   |    |
|  |  Untrusted nodes contribute CPU for:                               |    |
|  |    - PoW solution verification                                    |    |
|  |    - Traffic scrubbing and filtering                              |    |
|  |    - Challenge generation                                         |    |
|  |  (Untrusted = EK doesn't chain to configured Manufacturer CA)     |    |
|  +---------------------------+---------------------------------------+    |
|                              |                                            |
|                              v                                            |
|  +-------------------------------------------------------------------+    |
|  | LAYER 5: COLLABORATIVE THREAT INTELLIGENCE                        |    |
|  |                                                                   |    |
|  |  +-------------------+    +-------------------+                   |    |
|  |  | DHT-Backed Threat |    | Real-Time         |                   |    |
|  |  | Database          |<-->| Threat Sharing    |                   |    |
|  |  | - IP blacklists   |    | - Attack patterns |                   |    |
|  |  | - Attack patterns |    | - IP reputation   |                   |    |
|  |  | - Signatures      |    | - Mitigation rules|                   |    |
|  |  +-------------------+    +-------------------+                   |    |
|  |                                                                   |    |
|  |  - 3+ node reports required for blacklisting                      |    |
|  |  - 24-hour expiry on threat intelligence                          |    |
|  |  - TPM-attested evidence prevents fabrication                     |    |
|  +-------------------------------------------------------------------+    |
|                              |                                            |
|                              v                                            |
|                    CLEAN TRAFFIC TO SERVICES                              |
|                                                                           |
+===========================================================================+
```

---

## Layer 1: Traffic Dilution (Gateway Mesh)

### Gateway Mesh Architecture

The gateway mesh consists of 10,000+ geographically distributed gateway nodes that collectively absorb and distribute attack traffic. No single point of failure exists.

```
                         GATEWAY MESH TOPOLOGY

                         +-----------------+
                         |   ANYCAST DNS   |
                         | Same IP for all |
                         +---------+-------+
                                   |
               +-------------------+-------------------+
               |                   |                   |
               v                   v                   v
        +------+------+     +------+------+     +------+------+
        |  Gateway    |     |  Gateway    |     |  Gateway    |
        |  Region US  |     |  Region EU  |     |  Region AS  |
        | 2001:db8::  |     | 2001:db8::  |     | 2001:db8::  |
        +------+------+     +------+------+     +------+------+
               |                   |                   |
       +-------+-------+   +-------+-------+   +-------+-------+
       |       |       |   |       |       |   |       |       |
       v       v       v   v       v       v   v       v       v
    +----+  +----+  +----+ +----+  +----+  +----+ +----+  +----+  +----+
    |GW01|  |GW02|  |GW03| |GW04|  |GW05|  |GW06| |GW07|  |GW08|  |GW09|
    +----+  +----+  +----+ +----+  +----+  +----+ +----+  +----+  +----+

                        Total: 10,000+ Gateway Nodes
```

### Anycast Routing

All gateway nodes announce the same IP prefixes via BGP, creating an anycast mesh:

```go
type AnycastConfig struct {
    IPv6Prefix     string   // "2001:db8::/36"
    IPv4Prefix     string   // "203.0.113.0/24"
    ASN            uint32   // Network ASN
    Communities    []string // BGP communities for traffic engineering
}
```

When an attack originates from multiple sources:
- Traffic is automatically distributed to the nearest gateway
- Each gateway only receives a fraction of total attack volume
- Attack capacity is diluted across the entire mesh

### BGP FlowSpec Integration

Gateways coordinate real-time traffic filtering using BGP FlowSpec (RFC 5575):

```go
type FlowSpecRule struct {
    RuleID        string
    SourcePrefix  string        // Attacker IP/prefix
    DestPrefix    string        // Target service prefix
    Protocol      uint8         // TCP=6, UDP=17
    DestPort      uint16        // Target port
    Action        FlowSpecAction
    ValidUntil    time.Time     // Auto-expiry
    CreatedBy     NodeID        // Originating gateway
    Signatures    [][]byte      // 3+ coordinator signatures
}

type FlowSpecAction int
const (
    FlowSpecDrop        FlowSpecAction = iota // Drop packets
    FlowSpecRateLimit                         // Rate limit
    FlowSpecRedirect                          // Redirect to scrubbing
    FlowSpecMark                              // Mark for monitoring
)
```

### BGP Security and Route Validation

To prevent BGP hijacking and ensure routing integrity, all gateway nodes implement comprehensive BGP security measures.

#### RPKI Validation

All BGP route announcements MUST be validated against RPKI (Resource Public Key Infrastructure):

```go
type RPKIValidator struct {
    rpkiCache      *RPKICache           // Local RPKI cache (RTR protocol)
    validators     []string             // RPKI validator endpoints
    refreshInterval time.Duration       // Cache refresh interval (default: 30 minutes)
    mu             sync.RWMutex
}

type RouteOriginValidation uint8
const (
    ROVValid      RouteOriginValidation = iota // ROA exists and matches
    ROVNotFound                                 // No ROA found (unknown)
    ROVInvalid                                  // ROA exists but doesn't match - REJECT
)

// ValidateAnnouncement checks if a BGP announcement is RPKI-valid
// Returns error if the route should be rejected
func (v *RPKIValidator) ValidateAnnouncement(prefix net.IPNet, asn uint32) error {
    validation := v.checkROV(prefix, asn)

    switch validation {
    case ROVValid:
        return nil // Accept route
    case ROVNotFound:
        // Policy decision: accept with lower preference or require ROA
        log.Warn("BGP route has no RPKI ROA",
            "prefix", prefix.String(),
            "asn", asn)
        return nil // Accept but log
    case ROVInvalid:
        return ErrRPKIInvalid{
            Prefix:   prefix,
            ASN:      asn,
            Expected: v.getExpectedASN(prefix),
        }
    }
    return nil
}
```

#### Multi-Gateway Route Verification

To prevent single-gateway compromise from propagating malicious routes, route announcements require multi-gateway verification:

```go
const (
    MinGatewayVerification = 3      // Minimum gateways that must verify a route
    RouteVerificationTimeout = 30 * time.Second
    MaliciousGatewayThreshold = 3   // Conflicting announcements before flagging
)

type RouteVerification struct {
    Prefix          net.IPNet
    AnnouncingASN   uint32
    Verifications   map[NodeID]*GatewayVerification
    RequiredCount   int
    VerifiedAt      time.Time
    Status          RouteStatus
}

type GatewayVerification struct {
    GatewayID       NodeID
    Verified        bool
    VerifiedAt      time.Time
    SeenPath        []uint32          // AS path seen by this gateway
    Signature       []byte            // TPM-attested verification
}

type RouteStatus uint8
const (
    RouteStatusPending   RouteStatus = iota
    RouteStatusVerified              // MinGatewayVerification+ confirmations
    RouteStatusConflict              // Gateways see different routes
    RouteStatusRejected              // Failed verification
)

// VerifyRoute requires minimum 3 gateways to confirm a route announcement
func (m *RouteMesh) VerifyRoute(prefix net.IPNet, asn uint32) (*RouteVerification, error) {
    rv := &RouteVerification{
        Prefix:        prefix,
        AnnouncingASN: asn,
        Verifications: make(map[NodeID]*GatewayVerification),
        RequiredCount: MinGatewayVerification,
    }

    // Query geographically distributed gateways
    gateways := m.selectVerificationGateways(prefix, MinGatewayVerification*2)

    var wg sync.WaitGroup
    var mu sync.Mutex

    for _, gw := range gateways {
        wg.Add(1)
        go func(gateway *Gateway) {
            defer wg.Done()

            verification, err := gateway.VerifyRouteAnnouncement(prefix, asn)
            if err != nil {
                log.Warn("gateway route verification failed",
                    "gateway", gateway.ID,
                    "prefix", prefix.String(),
                    "error", err)
                return
            }

            mu.Lock()
            rv.Verifications[gateway.ID] = verification
            mu.Unlock()
        }(gw)
    }

    wg.Wait()

    // Analyze verification results
    return m.analyzeVerifications(rv)
}
```

#### Regional Route Aggregation

To reduce routing table size and improve scalability, gateways aggregate routes at regional boundaries:

```go
const (
    RegionalAggregationPrefix = 40  // Aggregate to /40 for regional announcements
    MaxRouteAnnouncements     = 1000 // Max distinct route announcements per gateway
)

type RouteAggregator struct {
    regionalPrefixes map[string]net.IPNet  // Aggregated regional prefixes
    memberPrefixes   map[string][]net.IPNet // Member prefixes per aggregate
    mu               sync.RWMutex
}

// AggregateRoutes combines multiple specific routes into regional /40 aggregates
func (a *RouteAggregator) AggregateRoutes(prefixes []net.IPNet) []net.IPNet {
    a.mu.Lock()
    defer a.mu.Unlock()

    aggregates := make(map[string]net.IPNet)

    for _, prefix := range prefixes {
        // Calculate /40 aggregate for this prefix
        aggregate := a.calculateAggregate(prefix, RegionalAggregationPrefix)
        key := aggregate.String()

        if _, exists := aggregates[key]; !exists {
            aggregates[key] = aggregate
        }

        // Track member prefixes for deaggregation if needed
        a.memberPrefixes[key] = append(a.memberPrefixes[key], prefix)
    }

    result := make([]net.IPNet, 0, len(aggregates))
    for _, agg := range aggregates {
        result = append(result, agg)
    }

    return result
}
```

#### Malicious Gateway Detection and Removal

Gateways that announce conflicting or invalid routes are detected and isolated:

```go
type MaliciousGatewayDetector struct {
    conflictCounts   map[NodeID]*GatewayConflicts
    blockedGateways  map[NodeID]time.Time
    mu               sync.RWMutex
}

type GatewayConflicts struct {
    Count           int
    FirstConflict   time.Time
    LastConflict    time.Time
    ConflictDetails []RouteConflict
}

type RouteConflict struct {
    Prefix          net.IPNet
    AnnouncedASN    uint32
    ExpectedASN     uint32
    Timestamp       time.Time
    Evidence        []byte  // TPM-attested evidence
}

// DetectMaliciousGateway flags gateways with repeated conflicting announcements
func (d *MaliciousGatewayDetector) RecordConflict(
    gatewayID NodeID,
    conflict RouteConflict,
) error {
    d.mu.Lock()
    defer d.mu.Unlock()

    conflicts, exists := d.conflictCounts[gatewayID]
    if !exists {
        conflicts = &GatewayConflicts{
            FirstConflict: time.Now(),
        }
        d.conflictCounts[gatewayID] = conflicts
    }

    conflicts.Count++
    conflicts.LastConflict = time.Now()
    conflicts.ConflictDetails = append(conflicts.ConflictDetails, conflict)

    // Threshold exceeded - block gateway
    if conflicts.Count >= MaliciousGatewayThreshold {
        d.blockedGateways[gatewayID] = time.Now()

        // Propagate block to network via threat intelligence
        return d.propagateGatewayBlock(gatewayID, conflicts)
    }

    return nil
}

// IsGatewayBlocked checks if a gateway has been flagged as malicious
func (d *MaliciousGatewayDetector) IsGatewayBlocked(gatewayID NodeID) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()

    _, blocked := d.blockedGateways[gatewayID]
    return blocked
}
```

---

## Layer 2: Rate Limiting and Reputation

### Per-IP Rate Limits

```go
const (
    // Connection Limits
    MaxConnectionsPerIP   = 10   // Concurrent connections per IP
    MaxNewConnsPerMinute  = 20   // New connections per minute

    // Request Limits
    MaxRequestsPerSecond  = 100  // Requests per second per IP

    // Bandwidth Limits (applied based on reputation)
    HighRepBandwidth      = 0    // Unlimited for high-rep IPs
    MedRepBandwidth       = 100  // 100 Mbps for medium-rep
    LowRepBandwidth       = 10   // 10 Mbps for low-rep
    MinRepBandwidth       = 1    // 1 Mbps for minimum rep
)
```

### IP Reputation System

Every IP address that interacts with the network receives a reputation score:

```go
type IPReputation struct {
    IP              net.IP
    Score           float64   // 0.0 to 1.0
    LastUpdated     time.Time
    TotalRequests   uint64
    GoodRequests    uint64
    BadRequests     uint64
    PoWSolutions    uint32    // Valid PoW solutions submitted
    FirstSeen       time.Time
    Flags           uint32    // Behavioral flags
}

const (
    // Reputation Thresholds
    MinIPReputation       = 0.20  // Block if below
    LowIPReputation       = 0.40  // Require PoW
    MedIPReputation       = 0.60  // Rate limited
    HighIPReputation      = 0.80  // Relaxed limits

    // Reputation Adjustments
    IPReputationDecay     = 0.01   // Per bad request
    IPReputationRestore   = 0.001  // Per good request
    PoWSolutionBonus      = 0.05   // Per valid PoW
)
```

### Rate Limit Tiers

| IP Reputation | Connections | Requests/sec | Bandwidth | PoW Required |
|---------------|-------------|--------------|-----------|--------------|
| >= 0.80 | 50 | 500 | Unlimited | No |
| 0.60 - 0.79 | 20 | 200 | 100 Mbps | No |
| 0.40 - 0.59 | 10 | 100 | 10 Mbps | Optional |
| 0.20 - 0.39 | 5 | 20 | 1 Mbps | Required |
| < 0.20 | **BLOCKED** | **BLOCKED** | **BLOCKED** | N/A |

### Per-Transport Rate Limits

Rate limits are applied per transport protocol as documented in the wire-protocol specification:

| Transport | Default Limit | Burst | Notes |
|-----------|--------------|-------|-------|
| **TCP** | 100 req/s | 200 | Standard DHT operations |
| **QUIC** | 150 req/s | 300 | Higher due to multiplexing |
| **UDP** | 50 req/s | 100 | Lower due to amplification risk |
| **gRPC** | 200 req/s | 400 | Service-to-service |
| **REST** | 100 req/s | 200 | External API clients |
| **Unix Socket** | 1000 req/s | 2000 | Local IPC (trusted) |

### Rate Limit Implementation (TOCTOU Prevention)

**CRITICAL**: Rate limit checks MUST be performed WITHIN the lock, not before acquiring or after releasing.

```go
// RateLimiter implements per-IP rate limiting with TOCTOU prevention
type RateLimiter struct {
    limits      map[string]*IPRateState
    mu          sync.RWMutex
    transport   TransportType
    config      RateLimitConfig
}

type IPRateState struct {
    requests    int64
    windowStart time.Time
    mu          sync.Mutex
}

type RateLimitConfig struct {
    RequestsPerSecond int64
    BurstSize         int64
    WindowDuration    time.Duration
}

// CheckAndConsume atomically checks AND updates rate limit state
// SECURITY FIX: Rate limit check WITHIN lock prevents TOCTOU race
//
// BAD (TOCTOU vulnerable):
//   state.mu.Lock()
//   count := state.requests     // Read
//   state.mu.Unlock()
//   if count >= limit {         // Check outside lock - RACE!
//       return false
//   }
//   state.mu.Lock()
//   state.requests++            // Modify - could exceed limit
//   state.mu.Unlock()
//
// GOOD (atomic check-and-modify):
//   state.mu.Lock()
//   defer state.mu.Unlock()
//   if state.requests >= limit { // Check inside lock
//       return false
//   }
//   state.requests++             // Modify while still holding lock
//   return true
func (r *RateLimiter) CheckAndConsume(clientIP net.IP) (allowed bool, remaining int64) {
    key := clientIP.String()

    r.mu.RLock()
    state, exists := r.limits[key]
    r.mu.RUnlock()

    if !exists {
        r.mu.Lock()
        // Double-check after acquiring write lock
        if state, exists = r.limits[key]; !exists {
            state = &IPRateState{
                windowStart: time.Now(),
            }
            r.limits[key] = state
        }
        r.mu.Unlock()
    }

    // CRITICAL: All rate limit logic INSIDE the state lock
    state.mu.Lock()
    defer state.mu.Unlock()

    now := time.Now()

    // Reset window if expired
    if now.Sub(state.windowStart) >= r.config.WindowDuration {
        state.requests = 0
        state.windowStart = now
    }

    // Check limit INSIDE lock (prevents TOCTOU)
    limit := r.config.RequestsPerSecond
    if state.requests >= limit {
        return false, 0
    }

    // Consume one request slot (still inside lock)
    state.requests++
    remaining = limit - state.requests

    return true, remaining
}

// Transport-specific rate limit configurations
var TransportRateLimits = map[TransportType]RateLimitConfig{
    TransportTCP: {
        RequestsPerSecond: 100,
        BurstSize:         200,
        WindowDuration:    time.Second,
    },
    TransportQUIC: {
        RequestsPerSecond: 150,
        BurstSize:         300,
        WindowDuration:    time.Second,
    },
    TransportUDP: {
        RequestsPerSecond: 50,
        BurstSize:         100,
        WindowDuration:    time.Second,
    },
    TransportGRPC: {
        RequestsPerSecond: 200,
        BurstSize:         400,
        WindowDuration:    time.Second,
    },
    TransportREST: {
        RequestsPerSecond: 100,
        BurstSize:         200,
        WindowDuration:    time.Second,
    },
    TransportUnixSocket: {
        RequestsPerSecond: 1000,
        BurstSize:         2000,
        WindowDuration:    time.Second,
    },
}

type TransportType uint8
const (
    TransportTCP TransportType = iota
    TransportQUIC
    TransportUDP
    TransportGRPC
    TransportREST
    TransportUnixSocket
)
```

### Rate Limit State Management

To prevent memory exhaustion attacks, rate limit state tracking implements strict memory bounds with LRU eviction.

**Memory Protection Requirements:**
- Maximum 1,000,000 tracked IP addresses
- Memory budget: 256MB maximum
- Pre-emptive eviction at 95% capacity
- LRU eviction policy prevents memory exhaustion DoS

```go
const (
    MaxTrackedIPs           = 1_000_000    // Maximum IP addresses tracked
    RateLimitMemoryBudget   = 256 << 20    // 256MB maximum memory
    RateLimitEntrySize      = 256          // ~256 bytes per IP entry
    PreemptiveEvictionPct   = 95           // Evict at 95% capacity
    EvictionBatchPct        = 5            // Evict 5% of entries per batch
    IPStateCleanupInterval  = 5 * time.Minute
    IPStateMaxIdleTime      = 1 * time.Hour
)

// RateLimitStateManager manages per-IP rate limit state with bounded memory
type RateLimitStateManager struct {
    states        map[string]*IPRateLimitState
    lruList       *list.List
    lruIndex      map[string]*list.Element
    maxEntries    int
    mu            sync.RWMutex

    // Metrics
    evictionCount atomic.Uint64
    hitCount      atomic.Uint64
    missCount     atomic.Uint64
}

// IPRateLimitState tracks rate limit state for a single IP
// Size: ~256 bytes (designed for memory efficiency)
type IPRateLimitState struct {
    IP            [16]byte      // IPv6 or IPv4-mapped (16 bytes)
    WindowStart   int64         // Unix timestamp (8 bytes)
    RequestCount  int64         // Requests in current window (8 bytes)
    LastAccess    int64         // For LRU tracking (8 bytes)
    BurstTokens   int32         // Token bucket burst tokens (4 bytes)
    Violations    int32         // Rate limit violations (4 bytes)
    BannedUntil   int64         // Ban expiry timestamp (8 bytes)
    TransportLimits [6]int64    // Per-transport request counts (48 bytes)
    _padding      [152]byte     // Pad to 256 bytes for alignment
}

// NewRateLimitStateManager creates a bounded state manager
func NewRateLimitStateManager() *RateLimitStateManager {
    mgr := &RateLimitStateManager{
        states:     make(map[string]*IPRateLimitState, MaxTrackedIPs),
        lruList:    list.New(),
        lruIndex:   make(map[string]*list.Element, MaxTrackedIPs),
        maxEntries: MaxTrackedIPs,
    }

    // Start cleanup goroutine
    go mgr.cleanupWorker()

    return mgr
}

// GetOrCreate retrieves or creates rate limit state for an IP
// Implements LRU eviction when capacity is reached
func (m *RateLimitStateManager) GetOrCreate(ip net.IP) (*IPRateLimitState, error) {
    key := ip.String()

    // Fast path: check if exists (read lock)
    m.mu.RLock()
    if state, exists := m.states[key]; exists {
        m.hitCount.Add(1)
        m.mu.RUnlock()

        // Update LRU position (requires write lock)
        m.mu.Lock()
        if elem, ok := m.lruIndex[key]; ok {
            m.lruList.MoveToFront(elem)
        }
        state.LastAccess = time.Now().Unix()
        m.mu.Unlock()

        return state, nil
    }
    m.mu.RUnlock()

    m.missCount.Add(1)

    // Slow path: create new entry (write lock)
    m.mu.Lock()
    defer m.mu.Unlock()

    // Double-check after acquiring write lock
    if state, exists := m.states[key]; exists {
        return state, nil
    }

    // Pre-emptive eviction at 95% capacity
    threshold := (m.maxEntries * PreemptiveEvictionPct) / 100
    if len(m.states) >= threshold {
        m.evictOldestLocked(EvictionBatchPct)
    }

    // Hard limit check
    if len(m.states) >= m.maxEntries {
        return nil, ErrRateLimitStateCapacityExceeded{
            CurrentEntries: len(m.states),
            MaxEntries:     m.maxEntries,
        }
    }

    // Create new state
    state := &IPRateLimitState{
        WindowStart: time.Now().Unix(),
        LastAccess:  time.Now().Unix(),
    }
    copy(state.IP[:], ip.To16())

    m.states[key] = state
    elem := m.lruList.PushFront(key)
    m.lruIndex[key] = elem

    return state, nil
}

// evictOldestLocked removes the oldest percent of entries
// MUST hold write lock when calling
func (m *RateLimitStateManager) evictOldestLocked(percent int) {
    toEvict := (len(m.states) * percent) / 100
    if toEvict == 0 {
        toEvict = 1
    }

    for i := 0; i < toEvict && m.lruList.Len() > 0; i++ {
        elem := m.lruList.Back()
        if elem == nil {
            break
        }

        key := elem.Value.(string)
        m.lruList.Remove(elem)
        delete(m.lruIndex, key)
        delete(m.states, key)
        m.evictionCount.Add(1)
    }

    log.Debug("rate limit state eviction completed",
        "evicted", toEvict,
        "remaining", len(m.states),
        "totalEvictions", m.evictionCount.Load())
}

// cleanupWorker periodically removes idle entries
func (m *RateLimitStateManager) cleanupWorker() {
    ticker := time.NewTicker(IPStateCleanupInterval)
    defer ticker.Stop()

    for range ticker.C {
        m.cleanupIdleEntries()
    }
}

// cleanupIdleEntries removes entries that haven't been accessed within MaxIdleTime
func (m *RateLimitStateManager) cleanupIdleEntries() {
    m.mu.Lock()
    defer m.mu.Unlock()

    cutoff := time.Now().Add(-IPStateMaxIdleTime).Unix()
    removed := 0

    for key, state := range m.states {
        if state.LastAccess < cutoff {
            if elem, ok := m.lruIndex[key]; ok {
                m.lruList.Remove(elem)
                delete(m.lruIndex, key)
            }
            delete(m.states, key)
            removed++
        }
    }

    if removed > 0 {
        log.Info("rate limit idle cleanup completed",
            "removed", removed,
            "remaining", len(m.states))
    }
}

// Error types
type ErrRateLimitStateCapacityExceeded struct {
    CurrentEntries int
    MaxEntries     int
}

func (e ErrRateLimitStateCapacityExceeded) Error() string {
    return fmt.Sprintf("rate limit state capacity exceeded: %d/%d entries",
        e.CurrentEntries, e.MaxEntries)
}
```

---

## Layer 3: Proof-of-Work Challenge

### Hashcash-Style PoW

Clients with low reputation or during high-load periods must complete a proof-of-work challenge:

```go
type PoWChallenge struct {
    ChallengeID   [32]byte      // Unique challenge identifier
    Timestamp     int64         // Issue time (Unix seconds)
    Difficulty    uint8         // Number of leading zero bits
    Nonce         [16]byte      // Server-generated nonce
    ClientIP      net.IP        // Client IP (bound to challenge)
    ExpiresAt     time.Time     // Challenge expiry
}

type PoWSolution struct {
    ChallengeID   [32]byte      // Reference to challenge
    Solution      [32]byte      // Client-computed nonce
    Proof         [32]byte      // SHA256(challenge || solution)
    ComputeTimeMS uint32        // Reported compute time
}

const (
    PoWDifficulty      = 20               // 2^20 hashes (~1 second on modern CPU)
    PoWCacheDuration   = 1 * time.Hour    // Solutions valid for 1 hour
    PoWMaxDifficulty   = 28               // Maximum adaptive difficulty
    PoWMinDifficulty   = 16               // Minimum difficulty

    // CRITICAL: Rate limiting for challenge generation DoS prevention
    MaxPendingChallengesPerIP  = 3                    // Max outstanding challenges per IP
    MaxChallengesPerIPPerMin   = 10                   // Max challenge requests per IP per minute
    MaxTotalPendingChallenges  = 1_000_000            // Global cap: 1M pending challenges
    PreemptiveEvictionThreshold = 950_000             // 95% capacity triggers eviction
    ChallengeTTL               = 5 * time.Minute      // Challenge expiry (CreatedAt + 5min = ExpiresAt)
    ChallengeCleanupInterval   = 30 * time.Second     // Expired challenge cleanup frequency
)
```

### Challenge Generation Rate Limiting (DoS Prevention)

**CRITICAL SECURITY**: Without rate limiting, an attacker can exhaust server memory by requesting challenges faster than they solve them. Each pending challenge consumes ~100 bytes, so 10M challenges = 1GB memory.

#### Challenge Pool Architecture

The challenge pool uses a **pre-allocated, fixed-size structure** to prevent runtime allocation attacks:

```go
// ChallengePool manages the global pool of pending challenges
// DESIGN: Pre-allocated fixed-size pool with LRU eviction
type ChallengePool struct {
    // Pre-allocated challenge slots (no runtime allocation)
    challenges    [MaxTotalPendingChallenges]ChallengeSlot
    freeList      []int32                   // Indices of free slots
    usedCount     atomic.Int64              // Current usage count

    // Index structures for O(1) lookups
    byID          map[[32]byte]int32        // ChallengeID -> slot index
    byIP          map[string][]int32        // ClientIP -> slot indices

    // LRU tracking for eviction
    lruHead       int32                     // Most recently used
    lruTail       int32                     // Least recently used (evict first)

    mu            sync.RWMutex
    cleanupTicker *time.Ticker
    stopCh        chan struct{}
}

// ChallengeSlot is a fixed-size struct (no variable allocation)
// Size: 32 + 8 + 1 + 16 + 16 + 8 + 8 + 4 + 4 = 97 bytes, padded to 128 bytes
type ChallengeSlot struct {
    ChallengeID   [32]byte      // Unique identifier
    Timestamp     int64         // CreatedAt (Unix seconds)
    Difficulty    uint8         // Required leading zero bits
    Nonce         [16]byte      // Server-generated nonce
    ClientIP      [16]byte      // IPv6 or IPv4-mapped (fixed size)
    CreatedAt     int64         // Unix timestamp when issued
    ExpiresAt     int64         // CreatedAt + ChallengeTTL (5 minutes)
    LRUNext       int32         // Next slot in LRU chain
    LRUPrev       int32         // Previous slot in LRU chain
    InUse         bool          // Slot is allocated
    _padding      [31]byte      // Pad to 128 bytes for cache alignment
}

// NewChallengePool creates a pre-allocated pool
func NewChallengePool() *ChallengePool {
    pool := &ChallengePool{
        byID:     make(map[[32]byte]int32, MaxTotalPendingChallenges),
        byIP:     make(map[string][]int32),
        freeList: make([]int32, MaxTotalPendingChallenges),
        stopCh:   make(chan struct{}),
    }

    // Initialize free list with all slots
    for i := int32(0); i < MaxTotalPendingChallenges; i++ {
        pool.freeList[i] = i
    }

    // Start cleanup goroutine (runs every 30 seconds)
    pool.cleanupTicker = time.NewTicker(ChallengeCleanupInterval)
    go pool.cleanupWorker()

    return pool
}

// cleanupWorker removes expired challenges every 30 seconds
func (p *ChallengePool) cleanupWorker() {
    for {
        select {
        case <-p.stopCh:
            return
        case <-p.cleanupTicker.C:
            p.cleanupExpiredChallenges()
        }
    }
}

// cleanupExpiredChallenges removes all challenges past ExpiresAt
func (p *ChallengePool) cleanupExpiredChallenges() {
    now := time.Now().Unix()

    p.mu.Lock()
    defer p.mu.Unlock()

    var expired int
    for id, idx := range p.byID {
        slot := &p.challenges[idx]
        if slot.ExpiresAt < now {
            p.releaseSlotLocked(idx)
            delete(p.byID, id)
            expired++
        }
    }

    if expired > 0 {
        log.Debug("expired challenges cleaned up",
            "count", expired,
            "remaining", p.usedCount.Load())
    }
}
```

#### Per-IP Rate Limiter

```go
// ChallengeRateLimiter prevents challenge request flooding
type ChallengeRateLimiter struct {
    pool           *ChallengePool
    perIPLimits    sync.Map              // map[IP]*IPLimitState
    globalCounter  atomic.Int64          // Total pending challenges
    mu             sync.RWMutex
}

type IPLimitState struct {
    PendingCount   atomic.Int32          // Outstanding unsolved challenges
    RequestTimes   []time.Time           // Rolling window of request times
    Banned         atomic.Bool           // Temporary ban flag
    BannedUntil    time.Time
    mu             sync.Mutex
}

// RequestChallenge checks rate limits BEFORE generating a challenge
// SECURITY FIX (P4-C11): All checks and state updates MUST be atomic
// Previous version had TOCTOU race between PendingCount check and increment
func (r *ChallengeRateLimiter) RequestChallenge(clientIP net.IP) error {
    // Check 1: Global memory protection with pre-emptive eviction
    // Pre-emptive eviction at 95% capacity (950,000 challenges)
    currentCount := r.globalCounter.Load()
    if currentCount >= PreemptiveEvictionThreshold {
        // Trigger pre-emptive eviction of oldest 5% of challenges
        r.pool.evictOldestPercent(5) // Evict ~50,000 challenges
    }

    // Hard limit check after potential eviction
    if r.globalCounter.Load() >= MaxTotalPendingChallenges {
        return ErrChallengePoolExhausted
    }

    // Get or create IP state
    key := clientIP.String()
    stateI, _ := r.perIPLimits.LoadOrStore(key, &IPLimitState{})
    state := stateI.(*IPLimitState)

    // Check 2: IP not banned (atomic pre-check)
    if state.Banned.Load() && time.Now().Before(state.BannedUntil) {
        return ErrIPTemporarilyBanned
    }

    // CRITICAL FIX (P4-C11): ALL rate limit checks INSIDE the lock
    // Previous version checked PendingCount outside lock, then incremented inside
    // This allowed race: two goroutines both pass check (2 < 3), both increment (→ 4)
    state.mu.Lock()
    defer state.mu.Unlock()

    // Clear expired ban (inside lock now)
    if state.Banned.Load() && time.Now().After(state.BannedUntil) {
        state.Banned.Store(false)
    }

    // Re-check banned status inside lock
    if state.Banned.Load() {
        return ErrIPTemporarilyBanned
    }

    // Check 3: Not too many pending challenges (INSIDE LOCK)
    currentPending := state.PendingCount.Load()
    if currentPending >= MaxPendingChallengesPerIP {
        return ErrTooManyPendingChallenges
    }

    // Check 4: Rate limit (requests per minute)
    now := time.Now()
    cutoff := now.Add(-1 * time.Minute)

    // Prune old entries
    validTimes := make([]time.Time, 0, len(state.RequestTimes))
    for _, t := range state.RequestTimes {
        if t.After(cutoff) {
            validTimes = append(validTimes, t)
        }
    }
    state.RequestTimes = validTimes

    if len(state.RequestTimes) >= MaxChallengesPerIPPerMin {
        // Ban for 5 minutes
        state.Banned.Store(true)
        state.BannedUntil = now.Add(5 * time.Minute)
        return ErrRateLimitExceeded
    }

    // SECURITY FIX (P5-H2): Use atomic increment with hard bounds
    // Previous version had race between check (line 378) and increment (line 386)
    // Multiple threads could all pass the check and then all increment
    //
    // Solution: Atomic increment-if-under-limit pattern
    for {
        current := r.globalCounter.Load()
        if current >= MaxTotalPendingChallenges {
            return ErrChallengePoolExhausted
        }
        // Attempt atomic increment only if still under limit
        if r.globalCounter.CompareAndSwap(current, current+1) {
            break // Successfully reserved our slot
        }
        // Another goroutine incremented - retry the check
    }

    // Global slot reserved - now update local state
    // If local update fails, we must decrement global counter
    state.RequestTimes = append(state.RequestTimes, now)
    state.PendingCount.Add(1)

    return nil
}

// OnChallengeSolved decrements pending count
func (r *ChallengeRateLimiter) OnChallengeSolved(clientIP net.IP) {
    key := clientIP.String()
    if stateI, ok := r.perIPLimits.Load(key); ok {
        state := stateI.(*IPLimitState)
        state.PendingCount.Add(-1)
        r.globalCounter.Add(-1)
    }
}

// OnChallengeExpired decrements pending count and may penalize IP
func (r *ChallengeRateLimiter) OnChallengeExpired(clientIP net.IP) {
    key := clientIP.String()
    if stateI, ok := r.perIPLimits.Load(key); ok {
        state := stateI.(*IPLimitState)
        state.PendingCount.Add(-1)
        r.globalCounter.Add(-1)
    }
}

// Challenge generation error types
var (
    ErrChallengePoolExhausted   = errors.New("challenge pool exhausted - try again later")
    ErrIPTemporarilyBanned      = errors.New("IP temporarily banned for abuse")
    ErrTooManyPendingChallenges = errors.New("too many pending challenges - solve existing ones first")
    ErrRateLimitExceeded        = errors.New("challenge request rate limit exceeded")
)
```

### Adaptive Difficulty

Difficulty adjusts automatically based on network load:

```go
func (p *PoWController) CalculateDifficulty() uint8 {
    loadFactor := p.getCurrentLoadFactor() // 0.0 to 1.0

    switch {
    case loadFactor < 0.5:
        return PoWMinDifficulty  // 16 bits = ~65K hashes
    case loadFactor < 0.7:
        return PoWDifficulty     // 20 bits = ~1M hashes
    case loadFactor < 0.9:
        return 24                // 24 bits = ~16M hashes
    default:
        return PoWMaxDifficulty  // 28 bits = ~256M hashes
    }
}
```

### PoW Solution Caching

Valid solutions are cached to prevent clients from repeatedly solving challenges:

```go
type PoWCache struct {
    solutions     sync.Map      // map[ClientIP]CachedSolution
    cleanupTicker *time.Ticker
    stopChan      chan struct{} // SECURITY FIX (P5-M4): For graceful shutdown
    wg            sync.WaitGroup
}

type CachedSolution struct {
    Solution      PoWSolution
    ValidUntil    time.Time     // PoWCacheDuration from solve time
    UseCount      uint32        // Number of times used
    MaxUses       uint32        // Maximum uses (default: unlimited)
}

// SECURITY FIX (P5-M4): Periodic cleanup to prevent memory leak
const (
    PoWCacheCleanupInterval = 5 * time.Minute   // How often to run cleanup
    PoWCacheMaxSize         = 100000            // Max entries before forced cleanup
)

// NewPoWCache creates a cache with automatic cleanup goroutine
func NewPoWCache() *PoWCache {
    cache := &PoWCache{
        cleanupTicker: time.NewTicker(PoWCacheCleanupInterval),
        stopChan:      make(chan struct{}),
    }

    cache.wg.Add(1)
    go cache.cleanupWorker()

    return cache
}

// cleanupWorker periodically removes expired solutions
// SECURITY FIX (P5-M4): Prevents memory leak from accumulated expired solutions
func (c *PoWCache) cleanupWorker() {
    defer c.wg.Done()

    log.Info("PoW cache cleanup worker started",
        "interval", PoWCacheCleanupInterval)

    for {
        select {
        case <-c.stopChan:
            log.Info("PoW cache cleanup worker stopped")
            return

        case <-c.cleanupTicker.C:
            expired, remaining := c.cleanupExpired()
            if expired > 0 {
                log.Info("PoW cache cleanup completed",
                    "expired", expired,
                    "remaining", remaining)
            }
        }
    }
}

// cleanupExpired removes expired solutions and enforces size limits
func (c *PoWCache) cleanupExpired() (expired, remaining int) {
    now := time.Now()
    totalEntries := 0

    // First pass: count and remove expired
    c.solutions.Range(func(key, value interface{}) bool {
        totalEntries++
        cached := value.(*CachedSolution)
        if now.After(cached.ValidUntil) {
            c.solutions.Delete(key)
            expired++
        }
        return true
    })

    remaining = totalEntries - expired

    // Emergency cleanup if still too large
    if remaining > PoWCacheMaxSize {
        toRemove := remaining - PoWCacheMaxSize
        removed := 0
        c.solutions.Range(func(key, value interface{}) bool {
            if removed >= toRemove {
                return false
            }
            c.solutions.Delete(key)
            removed++
            remaining--
            return true
        })
        log.Warn("PoW cache emergency cleanup - size exceeded limit",
            "forciblyRemoved", removed,
            "maxSize", PoWCacheMaxSize)
    }

    return expired, remaining
}

// Stop gracefully shuts down the cleanup worker
func (c *PoWCache) Stop() {
    close(c.stopChan)
    c.cleanupTicker.Stop()
    c.wg.Wait()
}
```

### PoW Solution Validation with Nonce Freshness (P4-M1)

**SECURITY FIX**: Without nonce freshness validation, attackers can replay old PoW solutions. The server must verify that:
1. The challenge was recently issued (not expired)
2. The challenge was issued to this specific IP
3. The nonce hasn't been used before (replay prevention)
4. The solution correctly solves the challenge

#### Counting Bloom Filter for Nonce Replay Prevention

Unlike standard Bloom filters, a **counting Bloom filter** supports element removal, which is essential for efficient nonce expiration. The filter uses time-based partitioning to prevent filter pollution attacks and enable efficient cleanup.

**Design Rationale:**
- **Counting vs Standard**: Standard Bloom filters cannot remove elements. When nonces expire, they would remain in the filter forever, eventually causing 100% false positives. Counting Bloom filters use counters instead of bits, allowing decrement operations.
- **Time Partitioning**: Dividing the filter into time-based partitions (6 x 10-minute windows) allows efficient bulk expiration by simply clearing the oldest partition, preventing pollution attacks.
- **Memory Efficiency**: 100MB budget supports ~100M nonces at 0.1% false positive rate with 4-bit counters.

```go
const (
    // Counting Bloom Filter Configuration
    BloomFilterMemoryBudget   = 100 << 20    // 100MB maximum memory
    BloomFilterFalsePositive  = 0.001        // 0.1% target false positive rate
    BloomFilterPartitions     = 6            // Time-based partitions
    BloomFilterPartitionTime  = 10 * time.Minute // 10 minutes per partition
    BloomFilterCounterBits    = 4            // 4-bit counters (max value 15)
    BloomFilterHashFunctions  = 7            // Optimal for target FP rate
)

// CountingBloomFilter implements a time-partitioned counting Bloom filter
// for nonce replay prevention with support for element removal
type CountingBloomFilter struct {
    partitions    [BloomFilterPartitions]*BloomPartition
    currentIdx    atomic.Int32           // Current active partition index
    rotationTime  time.Time              // When current partition started
    mu            sync.RWMutex

    // Metrics
    insertCount   atomic.Uint64
    queryCount    atomic.Uint64
    falsePositives atomic.Uint64         // Estimated based on fill ratio
}

// BloomPartition is a single time-windowed counting Bloom filter partition
type BloomPartition struct {
    counters      []uint8                // 4-bit counters packed (2 per byte)
    size          uint64                 // Number of counter positions
    hashSeeds     [BloomFilterHashFunctions]uint64
    elementCount  atomic.Uint64          // Approximate element count
    createdAt     time.Time
    mu            sync.Mutex             // Per-partition lock for writes
}

// NewCountingBloomFilter creates a time-partitioned counting Bloom filter
func NewCountingBloomFilter() *CountingBloomFilter {
    // Calculate optimal size for target false positive rate
    // Formula: m = -n * ln(p) / (ln(2)^2) where n=elements, p=FP rate
    // For 100MB budget with 4-bit counters: ~200M counter positions
    sizePerPartition := uint64(BloomFilterMemoryBudget / BloomFilterPartitions / 2) // 2 counters per byte

    cbf := &CountingBloomFilter{
        rotationTime: time.Now(),
    }

    // Initialize all partitions
    for i := 0; i < BloomFilterPartitions; i++ {
        cbf.partitions[i] = newBloomPartition(sizePerPartition)
    }

    // Start partition rotation worker
    go cbf.rotationWorker()

    return cbf
}

func newBloomPartition(size uint64) *BloomPartition {
    p := &BloomPartition{
        counters:  make([]uint8, (size+1)/2), // 2 counters per byte
        size:      size,
        createdAt: time.Now(),
    }

    // Generate random hash seeds
    for i := 0; i < BloomFilterHashFunctions; i++ {
        p.hashSeeds[i] = uint64(rand.Int63())
    }

    return p
}

// Add inserts a nonce into the current partition
// Returns true if the nonce was newly added (not already present)
func (cbf *CountingBloomFilter) Add(nonce []byte) bool {
    cbf.mu.RLock()
    partition := cbf.partitions[cbf.currentIdx.Load()]
    cbf.mu.RUnlock()

    cbf.insertCount.Add(1)
    return partition.add(nonce)
}

// Contains checks if a nonce exists in ANY partition
// This is the core replay prevention check
func (cbf *CountingBloomFilter) Contains(nonce []byte) bool {
    cbf.mu.RLock()
    defer cbf.mu.RUnlock()

    cbf.queryCount.Add(1)

    // Check all partitions (nonce could be in any time window)
    for i := 0; i < BloomFilterPartitions; i++ {
        if cbf.partitions[i].contains(nonce) {
            return true
        }
    }
    return false
}

// Remove decrements counters for a nonce (for explicit expiration)
// Note: Time-based partition rotation is the primary expiration mechanism
func (cbf *CountingBloomFilter) Remove(nonce []byte) {
    cbf.mu.RLock()
    defer cbf.mu.RUnlock()

    // Remove from all partitions (nonce location unknown)
    for i := 0; i < BloomFilterPartitions; i++ {
        cbf.partitions[i].remove(nonce)
    }
}

// rotationWorker rotates partitions based on time
func (cbf *CountingBloomFilter) rotationWorker() {
    ticker := time.NewTicker(BloomFilterPartitionTime)
    defer ticker.Stop()

    for range ticker.C {
        cbf.rotatePartition()
    }
}

// rotatePartition advances to the next partition and clears the oldest
func (cbf *CountingBloomFilter) rotatePartition() {
    cbf.mu.Lock()
    defer cbf.mu.Unlock()

    // Advance to next partition (circular)
    nextIdx := (cbf.currentIdx.Load() + 1) % BloomFilterPartitions

    // Clear the oldest partition (which is now next in rotation)
    // This efficiently removes all expired nonces in O(n) where n = partition size
    oldPartition := cbf.partitions[nextIdx]
    cbf.partitions[nextIdx] = newBloomPartition(oldPartition.size)

    cbf.currentIdx.Store(nextIdx)
    cbf.rotationTime = time.Now()

    log.Debug("bloom filter partition rotated",
        "newPartition", nextIdx,
        "clearedElements", oldPartition.elementCount.Load())
}

// Partition methods
func (p *BloomPartition) add(data []byte) bool {
    p.mu.Lock()
    defer p.mu.Unlock()

    wasNew := false
    for _, seed := range p.hashSeeds {
        pos := p.hash(data, seed) % p.size
        if p.getCounter(pos) == 0 {
            wasNew = true
        }
        p.incrementCounter(pos)
    }

    if wasNew {
        p.elementCount.Add(1)
    }
    return wasNew
}

func (p *BloomPartition) contains(data []byte) bool {
    for _, seed := range p.hashSeeds {
        pos := p.hash(data, seed) % p.size
        if p.getCounter(pos) == 0 {
            return false
        }
    }
    return true
}

func (p *BloomPartition) remove(data []byte) {
    p.mu.Lock()
    defer p.mu.Unlock()

    for _, seed := range p.hashSeeds {
        pos := p.hash(data, seed) % p.size
        p.decrementCounter(pos)
    }
    p.elementCount.Add(^uint64(0)) // Decrement
}

// Counter operations (4-bit counters, 2 per byte)
func (p *BloomPartition) getCounter(pos uint64) uint8 {
    byteIdx := pos / 2
    if pos%2 == 0 {
        return p.counters[byteIdx] & 0x0F // Lower 4 bits
    }
    return p.counters[byteIdx] >> 4 // Upper 4 bits
}

func (p *BloomPartition) incrementCounter(pos uint64) {
    byteIdx := pos / 2
    current := p.getCounter(pos)
    if current < 15 { // Max 4-bit value
        if pos%2 == 0 {
            p.counters[byteIdx] = (p.counters[byteIdx] & 0xF0) | (current + 1)
        } else {
            p.counters[byteIdx] = (p.counters[byteIdx] & 0x0F) | ((current + 1) << 4)
        }
    }
}

func (p *BloomPartition) decrementCounter(pos uint64) {
    byteIdx := pos / 2
    current := p.getCounter(pos)
    if current > 0 {
        if pos%2 == 0 {
            p.counters[byteIdx] = (p.counters[byteIdx] & 0xF0) | (current - 1)
        } else {
            p.counters[byteIdx] = (p.counters[byteIdx] & 0x0F) | ((current - 1) << 4)
        }
    }
}

func (p *BloomPartition) hash(data []byte, seed uint64) uint64 {
    h := xxhash.New()
    binary.Write(h, binary.LittleEndian, seed)
    h.Write(data)
    return h.Sum64()
}
```

#### PoW Solution Validator

```go
// PoWSolutionValidator validates PoW solutions with comprehensive freshness checks
type PoWSolutionValidator struct {
    pendingChallenges sync.Map                  // ChallengeID -> IssuedChallenge
    usedNonces        *CountingBloomFilter      // Counting Bloom filter for nonce replay prevention
    nonceMu           sync.Mutex                // SECURITY FIX (P5-C1): Protects atomic nonce check+add
    challengeTTL      time.Duration             // How long challenges remain valid
    maxNonceFreshness time.Duration             // Maximum age for nonce (stricter than TTL)
}

// IssuedChallenge tracks a challenge from issuance to solution
type IssuedChallenge struct {
    Challenge     *PoWChallenge
    IssuedAt      time.Time
    IssuedToIP    net.IP
    ExpiresAt     time.Time
    Consumed      bool               // Set true once solved (one-time use)
}

// ValidatePoWSolution performs complete validation of a PoW solution
// SECURITY: This function MUST be called for every solution submission
//
// OPTIMIZATION: Pre-filter by difficulty bits before expensive operations
// This rejects obviously invalid solutions in ~10ns instead of ~1us
func (v *PoWSolutionValidator) ValidatePoWSolution(
    solution *PoWSolution,
    clientIP net.IP,
) error {
    // Step 0: PRE-FILTER - Quick rejection of obviously invalid proofs
    // Check first few bytes of proof for required leading zeros
    // This is a cheap O(1) check that rejects ~99.9% of invalid solutions immediately
    // without needing to look up the challenge or compute anything
    if !quickDifficultyPreCheck(solution.Proof, PoWMinDifficulty) {
        return ErrInsufficientDifficulty{
            Required: PoWMinDifficulty,
            Actual:   countLeadingZeroBytesOnly(solution.Proof),
        }
    }

    // Step 1: Verify challenge exists and was issued to this IP
    challengeI, exists := v.pendingChallenges.Load(solution.ChallengeID)
    if !exists {
        return ErrChallengeNotFound
    }
    issued := challengeI.(*IssuedChallenge)

    // Step 2: CRITICAL - Nonce freshness check (P4-M1)
    // Challenge must not be expired
    now := time.Now()
    if now.After(issued.ExpiresAt) {
        v.pendingChallenges.Delete(solution.ChallengeID)
        return ErrChallengeExpired{
            ChallengeID: solution.ChallengeID,
            ExpiredAt:   issued.ExpiresAt,
            CurrentTime: now,
        }
    }

    // Step 3: CRITICAL - Strict nonce freshness (narrower than TTL)
    // Nonce must have been issued within maxNonceFreshness window
    nonceAge := now.Sub(issued.IssuedAt)
    if nonceAge > v.maxNonceFreshness {
        return ErrNonceTooOld{
            ChallengeID: solution.ChallengeID,
            IssuedAt:    issued.IssuedAt,
            MaxAge:      v.maxNonceFreshness,
            ActualAge:   nonceAge,
        }
    }

    // Step 4: Verify challenge was issued to this IP (prevents IP spoofing)
    if !issued.IssuedToIP.Equal(clientIP) {
        return ErrIPMismatch{
            ChallengeID: solution.ChallengeID,
            ExpectedIP:  issued.IssuedToIP,
            ActualIP:    clientIP,
        }
    }

    // Step 5: Check if challenge already consumed (replay prevention)
    if issued.Consumed {
        return ErrChallengeAlreadyUsed{ChallengeID: solution.ChallengeID}
    }

    // Step 6: ATOMIC nonce check+add (SECURITY FIX P5-C1)
    // CRITICAL: Must be atomic to prevent race condition where two concurrent
    // requests both pass Contains() check before either calls Add()
    // Attack scenario without fix:
    //   Thread A: Contains(nonce) = false  [passes]
    //   Thread B: Contains(nonce) = false  [passes - race!]
    //   Thread A: Add(nonce)
    //   Thread B: Add(nonce)  [duplicate nonce accepted!]
    nonceKey := append(issued.Challenge.Nonce[:], solution.Solution[:]...)

    v.nonceMu.Lock()
    if v.usedNonces.Contains(nonceKey) {
        v.nonceMu.Unlock()
        return ErrNonceReplay{ChallengeID: solution.ChallengeID}
    }
    // Immediately add nonce while still holding lock - atomic check+add
    v.usedNonces.Add(nonceKey)
    v.nonceMu.Unlock()

    // Step 7: Verify the actual PoW computation
    expectedProof := computePoWProof(issued.Challenge, solution.Solution)
    if !bytes.Equal(expectedProof[:], solution.Proof[:]) {
        return ErrInvalidProof{ChallengeID: solution.ChallengeID}
    }

    // Step 8: Verify difficulty (leading zeros)
    if !verifyDifficulty(solution.Proof, issued.Challenge.Difficulty) {
        return ErrInsufficientDifficulty{
            Required: issued.Challenge.Difficulty,
            Actual:   countLeadingZeros(solution.Proof),
        }
    }

    // SUCCESS - Mark challenge as consumed (nonce already recorded atomically in step 6)
    issued.Consumed = true
    v.pendingChallenges.Delete(solution.ChallengeID)

    return nil
}

// computePoWProof computes the expected proof from challenge and solution
func computePoWProof(challenge *PoWChallenge, solution [32]byte) [32]byte {
    h := sha256.New()
    h.Write(challenge.ChallengeID[:])
    h.Write(challenge.Nonce[:])
    binary.Write(h, binary.BigEndian, challenge.Timestamp)
    h.Write(solution[:])
    var proof [32]byte
    copy(proof[:], h.Sum(nil))
    return proof
}

// verifyDifficulty checks that proof has required leading zero bits
func verifyDifficulty(proof [32]byte, requiredBits uint8) bool {
    return countLeadingZeros(proof) >= int(requiredBits)
}

// countLeadingZeros counts leading zero bits in a hash
func countLeadingZeros(hash [32]byte) int {
    zeros := 0
    for _, b := range hash {
        if b == 0 {
            zeros += 8
        } else {
            // Count leading zeros in this byte
            for i := 7; i >= 0; i-- {
                if (b & (1 << i)) == 0 {
                    zeros++
                } else {
                    return zeros
                }
            }
        }
    }
    return zeros
}

// quickDifficultyPreCheck performs fast pre-filtering of obviously invalid proofs
// OPTIMIZATION: Checks only full zero bytes, not individual bits
// For difficulty 16, we need at least 2 full zero bytes (16 bits = 2 bytes)
// This is ~10x faster than full bit counting and rejects most garbage immediately
func quickDifficultyPreCheck(proof [32]byte, minDifficulty uint8) bool {
    // Calculate minimum required zero bytes (conservative - rounds down)
    minZeroBytes := int(minDifficulty / 8)

    // Quick check: verify first N bytes are zero
    for i := 0; i < minZeroBytes && i < len(proof); i++ {
        if proof[i] != 0 {
            return false
        }
    }
    return true
}

// countLeadingZeroBytesOnly counts only complete zero bytes (for error reporting)
// Returns count * 8 to express as bits
func countLeadingZeroBytesOnly(hash [32]byte) int {
    zeros := 0
    for _, b := range hash {
        if b == 0 {
            zeros += 8
        } else {
            break
        }
    }
    return zeros
}

// PoW validation error types
type ErrChallengeNotFound struct{}
func (e ErrChallengeNotFound) Error() string { return "challenge not found" }

type ErrChallengeExpired struct {
    ChallengeID [32]byte
    ExpiredAt   time.Time
    CurrentTime time.Time
}
func (e ErrChallengeExpired) Error() string {
    return fmt.Sprintf("challenge %x expired at %v (now: %v)",
        e.ChallengeID[:8], e.ExpiredAt, e.CurrentTime)
}

type ErrNonceTooOld struct {
    ChallengeID [32]byte
    IssuedAt    time.Time
    MaxAge      time.Duration
    ActualAge   time.Duration
}
func (e ErrNonceTooOld) Error() string {
    return fmt.Sprintf("nonce too old for challenge %x: issued %v ago (max: %v)",
        e.ChallengeID[:8], e.ActualAge, e.MaxAge)
}

type ErrIPMismatch struct {
    ChallengeID [32]byte
    ExpectedIP  net.IP
    ActualIP    net.IP
}
func (e ErrIPMismatch) Error() string {
    return fmt.Sprintf("IP mismatch for challenge %x: expected %v, got %v",
        e.ChallengeID[:8], e.ExpectedIP, e.ActualIP)
}

type ErrChallengeAlreadyUsed struct {
    ChallengeID [32]byte
}
func (e ErrChallengeAlreadyUsed) Error() string {
    return fmt.Sprintf("challenge %x already used", e.ChallengeID[:8])
}

type ErrNonceReplay struct {
    ChallengeID [32]byte
}
func (e ErrNonceReplay) Error() string {
    return fmt.Sprintf("nonce replay detected for challenge %x", e.ChallengeID[:8])
}

type ErrInvalidProof struct {
    ChallengeID [32]byte
}
func (e ErrInvalidProof) Error() string {
    return fmt.Sprintf("invalid proof for challenge %x", e.ChallengeID[:8])
}

type ErrInsufficientDifficulty struct {
    Required uint8
    Actual   int
}
func (e ErrInsufficientDifficulty) Error() string {
    return fmt.Sprintf("insufficient difficulty: required %d bits, got %d", e.Required, e.Actual)
}

// Freshness configuration
const (
    ChallengeTTL        = 30 * time.Second   // Challenges expire after 30s
    MaxNonceFreshness   = 100 * time.Millisecond // Nonce must be < 100ms old for validation
    BloomFilterSize     = 1 << 20            // 1M entries for used nonces
    BloomFilterFalsePos = 0.001              // 0.1% false positive rate
)
```

---

## Layer 4: Role-Based DDoS Work Distribution

### All Nodes Contribute - Tiered by Role

DDoS protection is a **network-wide collaborative effort**. ALL nodes contribute to defense, but work types are assigned based on role to avoid degrading primary functions.

**Trust Definition**: Untrusted = EK certificate does NOT chain to a configured TPM Manufacturer CA in the Privacy CA's trust store. This is NOT hardcoded - it's entirely configuration-driven.

### Role-Based Work Assignment (CANONICAL)

| Role | Primary Function | DDoS Work Type | Work Load |
|------|------------------|----------------|-----------|
| **Leaf** | DHT routing | PoW verification, traffic scrubbing | Heavy |
| **Hub** | Regional routing | Threat intel aggregation, blocklist serving | Light |
| **Gateway** | External connectivity | Edge rate limiting, IP reputation (built-in) | Integrated |
| **Coordinator** | Consensus leadership | Attack detection, emergency response coordination | Minimal |
| **CA Participant** | Certificate operations | None | None (critical) |
| **Untrusted** | Basic DHT participation | PoW verification, traffic scrubbing, challenge generation | Heavy (required) |

### Untrusted Node Work Pool

Untrusted nodes cannot earn reputation or assume network roles, but they MUST contribute CPU resources to network defense in exchange for network access:

```go
type WorkPool struct {
    workers       map[NodeID]*Worker
    taskQueue     chan Task
    resultQueue   chan Result
    mu            sync.RWMutex
}

type Worker struct {
    NodeID        NodeID
    TrustLevel    TrustLevel   // Always TrustLevelUntrusted
    Capacity      uint32       // Tasks per second
    CurrentLoad   uint32
    LastHeartbeat time.Time
}

type TaskType uint8
const (
    TaskPoWVerify     TaskType = iota  // Verify PoW solutions
    TaskTrafficScrub                   // Scrub/filter traffic
    TaskChallengeGen                   // Generate challenges
    TaskHashCompute                    // General hash computation
)
```

### Work Distribution

```
                    WORK POOL ARCHITECTURE

    +------------------+     +------------------+
    | Trusted Gateway  |     | Trusted Gateway  |
    | (Coordinator)    |     | (Coordinator)    |
    +--------+---------+     +--------+---------+
             |                        |
             +------------+-----------+
                          |
                          v
              +-----------+-----------+
              |    TASK DISTRIBUTOR   |
              | - Load balancing      |
              | - Task prioritization |
              | - Result aggregation  |
              +-----+-----+-----+-----+
                    |     |     |
          +---------+     |     +---------+
          |               |               |
          v               v               v
    +-----------+   +-----------+   +-----------+
    | Untrusted |   | Untrusted |   | Untrusted |
    |  Worker   |   |  Worker   |   |  Worker   |
    | (Node A)  |   | (Node B)  |   | (Node C)  |
    +-----------+   +-----------+   +-----------+

    (Untrusted = EK doesn't chain to configured Manufacturer CA)
    Tasks: PoW Verify, Traffic Scrub, Challenge Gen
```

### Traffic Scrubbing

Untrusted nodes perform traffic scrubbing to filter malicious packets:

```go
type Scrubber struct {
    ruleEngine    *RuleEngine
    packetQueue   chan RawPacket
    cleanQueue    chan CleanPacket
    dropCount     atomic.Uint64
    passCount     atomic.Uint64
}

func (s *Scrubber) ScrubPacket(pkt RawPacket) (CleanPacket, bool) {
    // Check against known attack signatures
    if s.ruleEngine.MatchesAttackPattern(pkt) {
        s.dropCount.Add(1)
        return CleanPacket{}, false
    }

    // Validate protocol compliance
    if !s.ruleEngine.ValidateProtocol(pkt) {
        s.dropCount.Add(1)
        return CleanPacket{}, false
    }

    // Rate limit per-source
    if s.ruleEngine.ExceedsRateLimit(pkt.SourceIP) {
        s.dropCount.Add(1)
        return CleanPacket{}, false
    }

    s.passCount.Add(1)
    return s.sanitize(pkt), true
}
```

### Flow-Level Rate Limiting (P4-M2 Fix)

**Problem**: Simple per-source IP rate limiting can be trivially bypassed by IP spoofing.
Attackers can spoof thousands of source IPs to evade per-IP limits.

**Solution**: Flow-aware scrubbing with connection state tracking that detects spoofed packets.

```go
// FlowAwareScrubber extends basic scrubbing with flow-level rate limiting
// to detect and block IP spoofing attacks
type FlowAwareScrubber struct {
    // Basic scrubbing
    ruleEngine     *RuleEngine
    packetQueue    chan RawPacket
    cleanQueue     chan CleanPacket

    // Flow tracking (P4-M2)
    flowTracker    *FlowStateTracker
    synFloodGuard  *SYNFloodDetector

    // Metrics
    dropCount      atomic.Uint64
    passCount      atomic.Uint64
    spoofDropCount atomic.Uint64
}

// FlowKey identifies a unique network flow (5-tuple)
type FlowKey struct {
    SrcIP     [16]byte  // IPv6 or IPv4-mapped
    DstIP     [16]byte
    SrcPort   uint16
    DstPort   uint16
    Protocol  uint8     // TCP, UDP, etc.
}

// FlowState tracks the state of a network flow
type FlowState struct {
    Key            FlowKey
    State          TCPState      // SYN_SENT, ESTABLISHED, etc.
    PacketCount    uint64
    ByteCount      uint64
    FirstSeen      time.Time
    LastSeen       time.Time
    LastSeqNum     uint32        // For TCP sequence tracking
    ExpectedAckNum uint32        // For TCP acknowledgment tracking
    WindowSize     uint16
    Flags          FlowFlags
}

type FlowFlags uint8
const (
    FlowFlagValidated FlowFlags = 1 << iota  // Has passed challenge-response
    FlowFlagSuspect                           // Potentially spoofed
    FlowFlagBlocked                           // Confirmed spoofed
)

type TCPState uint8
const (
    TCPStateNew         TCPState = iota
    TCPStateSynSent
    TCPStateSynReceived
    TCPStateEstablished
    TCPStateFinWait
    TCPStateClosed
)

// FlowStateTracker manages flow state with LRU eviction
type FlowStateTracker struct {
    mu          sync.RWMutex
    flows       map[FlowKey]*FlowState
    lru         *list.List
    lruMap      map[FlowKey]*list.Element
    maxFlows    int
    evictCount  atomic.Uint64  // Metrics: flows evicted due to capacity
}

// SECURITY FIX (P5-C2): Flow tracker methods with mandatory bounds checking
// Issue: UpdateFlow() was not checking bounds before insertion, allowing memory
// exhaustion DoS by opening flows faster than eviction could clean them.
// Fix: Pre-emptive eviction at 95% capacity, atomic bounds enforcement.

// Flow Tracker Bounds:
//   - Max 1,000,000 flows (MaxTrackedFlows constant)
//   - Check bounds BEFORE insertion (prevents TOCTOU race)
//   - Pre-emptive eviction at 95% capacity (950,000 flows)
//   - Evicts oldest 5% (50,000 flows) when threshold reached
//   - Sorted by LastSeen (last activity time), evicts oldest first

// FlowExists checks if a flow is already tracked (read-only, no allocation)
func (t *FlowStateTracker) FlowExists(key FlowKey) bool {
    t.mu.RLock()
    _, exists := t.flows[key]
    t.mu.RUnlock()
    return exists
}

// GetFlow retrieves a flow state (returns nil if not found)
func (t *FlowStateTracker) GetFlow(key FlowKey) *FlowState {
    t.mu.RLock()
    defer t.mu.RUnlock()
    if flow, ok := t.flows[key]; ok {
        return flow
    }
    return nil
}

// UpdateFlow creates or updates a flow with mandatory bounds checking
// SECURITY: MUST check capacity BEFORE inserting new flows
func (t *FlowStateTracker) UpdateFlow(key FlowKey, state *FlowState) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    // Case 1: Update existing flow (no capacity impact)
    if existing, ok := t.flows[key]; ok {
        *existing = *state
        existing.LastSeen = time.Now() // Update activity timestamp
        // Move to front of LRU (most recently used)
        if elem, ok := t.lruMap[key]; ok {
            t.lru.MoveToFront(elem)
        }
        return nil
    }

    // Case 2: New flow - MUST check capacity FIRST (before any insertion attempt)
    // P5-C2 FIX: Pre-emptive eviction at 95% to prevent overflow
    preemptiveThreshold := int(float64(t.maxFlows) * 0.95) // 950,000 flows
    if len(t.flows) >= preemptiveThreshold {
        // Evict oldest 5% of flows sorted by LastSeen (activity time)
        t.evictOldestByActivityLocked(5)
    }

    // Hard limit: reject if still at max capacity after eviction
    if len(t.flows) >= t.maxFlows {
        return ErrFlowCapacityExceeded{
            CurrentFlows: len(t.flows),
            MaxFlows:     t.maxFlows,
        }
    }

    // Safe to insert
    t.flows[key] = state
    elem := t.lru.PushFront(key)
    t.lruMap[key] = elem
    return nil
}

// evictOldestLocked removes oldest flow (MUST hold write lock)
func (t *FlowStateTracker) evictOldestLocked() {
    if t.lru.Len() == 0 {
        return
    }
    elem := t.lru.Back()
    if elem == nil {
        return
    }
    key := elem.Value.(FlowKey)
    t.lru.Remove(elem)
    delete(t.lruMap, key)
    delete(t.flows, key)
    t.evictCount.Add(1)
}

// evictOldestByActivityLocked evicts the oldest percent of flows by LastSeen time
// MUST hold write lock. This ensures we evict truly inactive flows, not just LRU.
func (t *FlowStateTracker) evictOldestByActivityLocked(percent int) {
    if len(t.flows) == 0 {
        return
    }

    // Calculate how many to evict
    toEvict := (len(t.flows) * percent) / 100
    if toEvict == 0 {
        toEvict = 1
    }

    // Collect all flows with their keys for sorting
    type flowEntry struct {
        key      FlowKey
        lastSeen time.Time
    }
    entries := make([]flowEntry, 0, len(t.flows))
    for key, flow := range t.flows {
        entries = append(entries, flowEntry{key: key, lastSeen: flow.LastSeen})
    }

    // Sort by LastSeen ascending (oldest first)
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].lastSeen.Before(entries[j].lastSeen)
    })

    // Evict oldest entries
    for i := 0; i < toEvict && i < len(entries); i++ {
        key := entries[i].key
        if elem, ok := t.lruMap[key]; ok {
            t.lru.Remove(elem)
            delete(t.lruMap, key)
        }
        delete(t.flows, key)
        t.evictCount.Add(1)
    }

    log.Debug("pre-emptive flow eviction completed",
        "evicted", toEvict,
        "remaining", len(t.flows),
        "threshold", "95%")
}

// CleanupIdleFlows removes flows that haven't been accessed within timeout
// Should be called periodically (e.g., every 30 seconds)
func (t *FlowStateTracker) CleanupIdleFlows(idleTimeout time.Duration) int {
    t.mu.Lock()
    defer t.mu.Unlock()

    now := time.Now()
    removed := 0

    for key, flow := range t.flows {
        if now.Sub(flow.LastSeen) > idleTimeout {
            if elem, ok := t.lruMap[key]; ok {
                t.lru.Remove(elem)
                delete(t.lruMap, key)
            }
            delete(t.flows, key)
            removed++
        }
    }
    return removed
}

// Metrics returns current flow tracker metrics
func (t *FlowStateTracker) Metrics() FlowTrackerMetrics {
    t.mu.RLock()
    count := len(t.flows)
    t.mu.RUnlock()
    return FlowTrackerMetrics{
        CurrentFlows:   count,
        MaxFlows:       t.maxFlows,
        EvictedFlows:   t.evictCount.Load(),
        CapacityUsed:   float64(count) / float64(t.maxFlows) * 100,
    }
}

type FlowTrackerMetrics struct {
    CurrentFlows   int
    MaxFlows       int
    EvictedFlows   uint64
    CapacityUsed   float64  // Percentage
}

type ErrFlowCapacityExceeded struct {
    CurrentFlows int
    MaxFlows     int
}

func (e ErrFlowCapacityExceeded) Error() string {
    return fmt.Sprintf("flow tracker at capacity: %d/%d flows", e.CurrentFlows, e.MaxFlows)
}

const (
    MaxTrackedFlows    = 1_000_000    // 1M concurrent flows
    FlowIdleTimeout    = 60 * time.Second
    SYNCookieSecret    = 32           // bytes
    MaxSYNsPerSecond   = 10000        // Per destination IP
    MaxNewFlowsPerIP   = 100          // New flows per source IP per second
    SpoofDetectionWindow = 5 * time.Second
)

// SYNFloodDetector implements SYN cookie validation
type SYNFloodDetector struct {
    secret        [SYNCookieSecret]byte
    synCounters   sync.Map           // DstIP -> *SYNCounter
    newFlowRates  sync.Map           // SrcIP -> *RateLimiter
}

type SYNCounter struct {
    count     atomic.Uint64
    windowEnd atomic.Int64
}

// ScrubPacketWithFlowTracking performs flow-aware packet validation
func (s *FlowAwareScrubber) ScrubPacketWithFlowTracking(pkt RawPacket) (CleanPacket, error) {
    // Step 1: Basic signature and protocol validation (unchanged)
    if s.ruleEngine.MatchesAttackPattern(pkt) {
        s.dropCount.Add(1)
        return CleanPacket{}, ErrAttackPatternMatched
    }

    if !s.ruleEngine.ValidateProtocol(pkt) {
        s.dropCount.Add(1)
        return CleanPacket{}, ErrProtocolViolation
    }

    // Step 2: Flow-level rate limiting (P4-M2 - prevents IP spoofing bypass)
    flowKey := extractFlowKey(pkt)

    // Step 2a: New flow rate limiting per source IP
    if !s.flowTracker.FlowExists(flowKey) {
        if !s.checkNewFlowRate(pkt.SourceIP) {
            s.spoofDropCount.Add(1)
            s.dropCount.Add(1)
            return CleanPacket{}, ErrNewFlowRateLimitExceeded{
                SourceIP: pkt.SourceIP,
                Limit:    MaxNewFlowsPerIP,
            }
        }
    }

    // Step 2b: TCP-specific spoofing detection
    if pkt.Protocol == ProtocolTCP {
        if err := s.validateTCPFlow(flowKey, pkt); err != nil {
            s.spoofDropCount.Add(1)
            s.dropCount.Add(1)
            return CleanPacket{}, err
        }
    }

    // Step 2c: UDP-specific spoofing detection (stateless - use challenge)
    if pkt.Protocol == ProtocolUDP {
        if err := s.validateUDPPacket(flowKey, pkt); err != nil {
            s.spoofDropCount.Add(1)
            s.dropCount.Add(1)
            return CleanPacket{}, err
        }
    }

    // Step 3: SYN flood protection
    if pkt.Protocol == ProtocolTCP && pkt.TCPFlags&TCPFlagSYN != 0 {
        if !s.synFloodGuard.CheckSYN(pkt.DstIP) {
            s.dropCount.Add(1)
            return CleanPacket{}, ErrSYNFloodDetected{
                DestIP: pkt.DstIP,
                Rate:   MaxSYNsPerSecond,
            }
        }
    }

    // Step 4: Update flow state
    s.flowTracker.UpdateFlow(flowKey, pkt)

    // Step 5: Per-source rate limit (existing check)
    if s.ruleEngine.ExceedsRateLimit(pkt.SourceIP) {
        s.dropCount.Add(1)
        return CleanPacket{}, ErrRateLimitExceeded{SourceIP: pkt.SourceIP}
    }

    s.passCount.Add(1)
    return s.sanitize(pkt), nil
}

// validateTCPFlow performs stateful TCP validation to detect spoofed packets
func (s *FlowAwareScrubber) validateTCPFlow(key FlowKey, pkt RawPacket) error {
    flow := s.flowTracker.GetFlow(key)

    // New flow: must start with SYN (or SYN-ACK for server response)
    if flow == nil {
        if pkt.TCPFlags&TCPFlagSYN == 0 {
            // Non-SYN packet for non-existent flow = spoofed
            return ErrTCPStateMismatch{
                FlowKey:      key,
                ExpectedState: TCPStateNew,
                ActualFlags:   pkt.TCPFlags,
                Reason:        "non-SYN packet without established flow",
            }
        }
        return nil // Valid SYN
    }

    // State machine validation
    switch flow.State {
    case TCPStateSynSent:
        // Expect SYN-ACK
        if pkt.TCPFlags != (TCPFlagSYN | TCPFlagACK) {
            return ErrTCPStateMismatch{
                FlowKey:      key,
                ExpectedState: TCPStateSynSent,
                ActualFlags:   pkt.TCPFlags,
                Reason:        "expected SYN-ACK",
            }
        }

    case TCPStateSynReceived:
        // Expect ACK with correct sequence number
        if pkt.TCPFlags&TCPFlagACK == 0 {
            return ErrTCPStateMismatch{
                FlowKey:      key,
                ExpectedState: TCPStateSynReceived,
                ActualFlags:   pkt.TCPFlags,
                Reason:        "expected ACK",
            }
        }
        // Validate sequence number is in expected window
        if !isSeqNumInWindow(pkt.SeqNum, flow.ExpectedAckNum, flow.WindowSize) {
            return ErrTCPSequenceMismatch{
                FlowKey:     key,
                ExpectedSeq: flow.ExpectedAckNum,
                ActualSeq:   pkt.SeqNum,
                WindowSize:  flow.WindowSize,
            }
        }

    case TCPStateEstablished:
        // Validate sequence number is in expected window
        if !isSeqNumInWindow(pkt.SeqNum, flow.LastSeqNum, flow.WindowSize) {
            return ErrTCPSequenceMismatch{
                FlowKey:     key,
                ExpectedSeq: flow.LastSeqNum,
                ActualSeq:   pkt.SeqNum,
                WindowSize:  flow.WindowSize,
            }
        }
    }

    return nil
}

// validateUDPPacket validates UDP packets using challenge-response for new flows
func (s *FlowAwareScrubber) validateUDPPacket(key FlowKey, pkt RawPacket) error {
    flow := s.flowTracker.GetFlow(key)

    // Known validated flow - allow
    if flow != nil && flow.Flags&FlowFlagValidated != 0 {
        return nil
    }

    // New UDP flow or unvalidated flow - require PoW challenge completion first
    // UDP is stateless, so we can't verify the source IP directly
    // The node must have completed PoW challenge (which validates IP) before sending UDP

    // Check if source IP has completed PoW challenge recently
    if !s.hasValidPoWToken(pkt.SourceIP) {
        return ErrUDPRequiresPoW{
            SourceIP: pkt.SourceIP,
            Reason:   "UDP packets require PoW challenge completion to validate source IP",
        }
    }

    return nil
}

// checkNewFlowRate implements per-source new flow rate limiting
func (s *FlowAwareScrubber) checkNewFlowRate(srcIP net.IP) bool {
    limiter, _ := s.synFloodGuard.newFlowRates.LoadOrStore(
        srcIP.String(),
        &RateLimiter{
            rate:   MaxNewFlowsPerIP,
            window: time.Second,
        },
    )
    return limiter.(*RateLimiter).Allow()
}

// isSeqNumInWindow checks if sequence number is within valid TCP window
func isSeqNumInWindow(seqNum, expectedSeq uint32, windowSize uint16) bool {
    // TCP sequence number wraparound handling
    diff := int64(seqNum) - int64(expectedSeq)
    if diff < 0 {
        diff += 0x100000000 // 2^32 wraparound
    }
    return diff <= int64(windowSize)*2 // Allow 2x window for latency
}

// hasValidPoWToken checks if IP has recently completed PoW challenge
func (s *FlowAwareScrubber) hasValidPoWToken(ip net.IP) bool {
    // Integration with PoW system - check if IP has valid token
    // Token is granted upon successful PoW challenge completion
    // Token expires after PoWTokenTTL (e.g., 1 hour)
    return s.powValidator.HasValidToken(ip)
}

// Flow tracking error types
type ErrNewFlowRateLimitExceeded struct {
    SourceIP net.IP
    Limit    int
}
func (e ErrNewFlowRateLimitExceeded) Error() string {
    return fmt.Sprintf("new flow rate limit exceeded for %s (limit: %d/s)", e.SourceIP, e.Limit)
}

type ErrTCPStateMismatch struct {
    FlowKey       FlowKey
    ExpectedState TCPState
    ActualFlags   uint8
    Reason        string
}
func (e ErrTCPStateMismatch) Error() string {
    return fmt.Sprintf("TCP state mismatch: %s", e.Reason)
}

type ErrTCPSequenceMismatch struct {
    FlowKey     FlowKey
    ExpectedSeq uint32
    ActualSeq   uint32
    WindowSize  uint16
}
func (e ErrTCPSequenceMismatch) Error() string {
    return fmt.Sprintf("TCP sequence mismatch: expected %d, got %d (window: %d)",
        e.ExpectedSeq, e.ActualSeq, e.WindowSize)
}

type ErrSYNFloodDetected struct {
    DestIP net.IP
    Rate   int
}
func (e ErrSYNFloodDetected) Error() string {
    return fmt.Sprintf("SYN flood detected targeting %s (limit: %d/s)", e.DestIP, e.Rate)
}

type ErrUDPRequiresPoW struct {
    SourceIP net.IP
    Reason   string
}
func (e ErrUDPRequiresPoW) Error() string {
    return fmt.Sprintf("UDP from %s requires PoW: %s", e.SourceIP, e.Reason)
}

// SYN Cookie Implementation (for SYN flood mitigation)
type SYNCookieValidator struct {
    secret    [32]byte
    timestamp atomic.Int64  // Divided into 64-second intervals
}

// GenerateSYNCookie creates a cryptographic SYN cookie
func (v *SYNCookieValidator) GenerateSYNCookie(pkt RawPacket) uint32 {
    // SYN cookie = hash(secret || srcIP || dstIP || ports || timestamp) & 0xFFFFFF00
    //            | (MSS index & 0xFF)
    h := hmac.New(sha256.New, v.secret[:])
    h.Write(pkt.SourceIP)
    h.Write(pkt.DstIP)
    binary.Write(h, binary.BigEndian, pkt.SrcPort)
    binary.Write(h, binary.BigEndian, pkt.DstPort)
    binary.Write(h, binary.BigEndian, v.timestamp.Load())

    sum := h.Sum(nil)
    cookie := binary.BigEndian.Uint32(sum[:4]) & 0xFFFFFF00
    cookie |= uint32(v.getMSSIndex(pkt.TCPOptions.MSS))

    return cookie
}

// ValidateSYNCookie verifies a SYN cookie from ACK response
func (v *SYNCookieValidator) ValidateSYNCookie(pkt RawPacket, ackNum uint32) bool {
    // ACK number should be our SYN cookie + 1
    cookie := ackNum - 1

    // Try current and previous timestamp (64-second windows)
    for _, ts := range []int64{v.timestamp.Load(), v.timestamp.Load() - 1} {
        h := hmac.New(sha256.New, v.secret[:])
        h.Write(pkt.DstIP)  // Note: reversed for ACK
        h.Write(pkt.SourceIP)
        binary.Write(h, binary.BigEndian, pkt.DstPort)
        binary.Write(h, binary.BigEndian, pkt.SrcPort)
        binary.Write(h, binary.BigEndian, ts)

        sum := h.Sum(nil)
        expectedCookie := binary.BigEndian.Uint32(sum[:4]) & 0xFFFFFF00
        expectedCookie |= cookie & 0xFF  // Preserve MSS index

        if cookie == expectedCookie {
            return true
        }
    }

    return false
}

func (v *SYNCookieValidator) getMSSIndex(mss uint16) uint8 {
    // Map common MSS values to 8-bit index
    switch {
    case mss >= 1460:
        return 0
    case mss >= 1440:
        return 1
    case mss >= 1300:
        return 2
    case mss >= 1200:
        return 3
    default:
        return 4
    }
}
```

### IP Spoofing Bypass Protection (P4-M2 Enhancement)

**Problem**: Attackers can bypass per-IP rate limiting by spoofing source IP addresses. Without bidirectional connectivity verification, attackers can send traffic with arbitrary source IPs to evade detection and overwhelm targets.

**Attack Vectors**:
1. **Asymmetric Routing Exploitation**: Attacker sends packets via path A, expects responses via path B (which they control)
2. **Blind Spoofing**: Attacker sends traffic with random source IPs, never receives responses
3. **Reflective Amplification**: Attacker spoofs victim's IP to trigger amplified responses

**Solution**: Multi-layer IP validation with asymmetric routing detection and mandatory bidirectional connectivity verification.

#### Asymmetric Routing Validation

Asymmetric routing occurs when inbound and outbound paths differ significantly. While some asymmetry is normal in the Internet, extreme asymmetry often indicates spoofing.

```go
// AsymmetricRoutingDetector validates bidirectional path consistency
type AsymmetricRoutingDetector struct {
    // RTT baseline per source IP/subnet
    rttBaselines    sync.Map              // IP/subnet -> *RTTBaseline
    
    // Configuration
    config AsymmetricRoutingConfig
}

type AsymmetricRoutingConfig struct {
    // Maximum RTT ratio (inbound vs outbound) before flagging
    // Normal Internet asymmetry: 1.5-3x
    // Suspicious: >5x
    // Almost certainly spoofed: >10x
    MaxRTTAsymmetryRatio   float64       // Default: 10.0
    
    // Minimum samples before establishing baseline
    MinRTTSamples          int           // Default: 5
    
    // RTT measurement timeout
    RTTMeasurementTimeout  time.Duration // Default: 5 seconds
    
    // Baseline expiry (recalculate periodically)
    BaselineExpiry         time.Duration // Default: 1 hour
    
    // Enable strict mode (reject all asymmetric traffic)
    StrictMode             bool          // Default: false
}

type RTTBaseline struct {
    InboundRTT     time.Duration  // Average RTT for inbound path
    OutboundRTT    time.Duration  // Average RTT for outbound path
    SampleCount    int
    LastUpdated    time.Time
    AsymmetryRatio float64        // InboundRTT / OutboundRTT
    Validated      bool           // Has passed bidirectional check
}

const (
    // Asymmetric routing thresholds
    RTTAsymmetryWarning    = 5.0   // Log warning
    RTTAsymmetryReject     = 10.0  // Reject traffic
    RTTAsymmetryBlock      = 20.0  // Temporary block + report
    
    // Measurement parameters
    MinRTTSamples          = 5
    RTTMeasurementTimeout  = 5 * time.Second
    RTTBaselineExpiry      = 1 * time.Hour
)

// ValidateAsymmetricRouting checks if traffic path is consistent
func (d *AsymmetricRoutingDetector) ValidateAsymmetricRouting(
    clientIP net.IP,
    measuredRTT time.Duration,
    direction PacketDirection,
) (AsymmetryResult, error) {
    key := d.getSubnetKey(clientIP)
    
    baselineI, exists := d.rttBaselines.Load(key)
    if !exists {
        // New client - start baseline measurement
        baseline := &RTTBaseline{
            LastUpdated: time.Now(),
        }
        d.rttBaselines.Store(key, baseline)
        return AsymmetryResultPending, nil
    }
    
    baseline := baselineI.(*RTTBaseline)
    
    // Update baseline with new sample
    if direction == DirectionInbound {
        baseline.InboundRTT = d.updateAverage(baseline.InboundRTT, measuredRTT, baseline.SampleCount)
    } else {
        baseline.OutboundRTT = d.updateAverage(baseline.OutboundRTT, measuredRTT, baseline.SampleCount)
    }
    baseline.SampleCount++
    baseline.LastUpdated = time.Now()
    
    // Need minimum samples before validation
    if baseline.SampleCount < MinRTTSamples {
        return AsymmetryResultPending, nil
    }
    
    // Calculate asymmetry ratio
    if baseline.OutboundRTT > 0 {
        baseline.AsymmetryRatio = float64(baseline.InboundRTT) / float64(baseline.OutboundRTT)
    }
    
    // Evaluate asymmetry
    switch {
    case baseline.AsymmetryRatio >= RTTAsymmetryBlock:
        return AsymmetryResultBlock, ErrExtremeAsymmetry{
            ClientIP:       clientIP,
            AsymmetryRatio: baseline.AsymmetryRatio,
            Threshold:      RTTAsymmetryBlock,
        }
        
    case baseline.AsymmetryRatio >= RTTAsymmetryReject:
        return AsymmetryResultReject, ErrHighAsymmetry{
            ClientIP:       clientIP,
            AsymmetryRatio: baseline.AsymmetryRatio,
            Threshold:      RTTAsymmetryReject,
        }
        
    case baseline.AsymmetryRatio >= RTTAsymmetryWarning:
        // Log but allow (might be legitimate CDN/anycast)
        log.Warn("moderate RTT asymmetry detected",
            "client_ip", clientIP,
            "ratio", baseline.AsymmetryRatio)
        return AsymmetryResultWarn, nil
        
    default:
        baseline.Validated = true
        return AsymmetryResultOK, nil
    }
}

type AsymmetryResult uint8
const (
    AsymmetryResultOK AsymmetryResult = iota
    AsymmetryResultPending
    AsymmetryResultWarn
    AsymmetryResultReject
    AsymmetryResultBlock
)

type PacketDirection uint8
const (
    DirectionInbound PacketDirection = iota
    DirectionOutbound
)

// Asymmetry error types
type ErrExtremeAsymmetry struct {
    ClientIP       net.IP
    AsymmetryRatio float64
    Threshold      float64
}
func (e ErrExtremeAsymmetry) Error() string {
    return fmt.Sprintf("extreme RTT asymmetry from %s: ratio %.1fx exceeds block threshold %.1fx",
        e.ClientIP, e.AsymmetryRatio, e.Threshold)
}

type ErrHighAsymmetry struct {
    ClientIP       net.IP
    AsymmetryRatio float64
    Threshold      float64
}
func (e ErrHighAsymmetry) Error() string {
    return fmt.Sprintf("high RTT asymmetry from %s: ratio %.1fx exceeds reject threshold %.1fx",
        e.ClientIP, e.AsymmetryRatio, e.Threshold)
}
```

#### Bidirectional Connectivity Verification

All new connections MUST complete bidirectional verification before being granted full access. This prevents blind spoofing attacks.

```go
// BidirectionalVerifier ensures clients can receive responses
type BidirectionalVerifier struct {
    // Pending verifications
    pending      sync.Map              // ClientIP -> *PendingVerification
    
    // Verified clients (cached)
    verified     sync.Map              // ClientIP -> *VerifiedClient
    
    // Configuration
    config BidirectionalConfig
}

type BidirectionalConfig struct {
    // Verification timeout
    VerificationTimeout    time.Duration // Default: 5 seconds
    
    // Verification methods (in order of preference)
    Methods                []VerificationMethod
    
    // Cache duration for verified clients
    VerifiedCacheDuration  time.Duration // Default: 1 hour
    
    // Re-verification interval for long-lived connections
    ReVerificationInterval time.Duration // Default: 30 minutes
    
    // Maximum pending verifications per IP
    MaxPendingPerIP        int           // Default: 1
}

type VerificationMethod uint8
const (
    // TCP three-way handshake (implicit verification)
    VerifyTCPHandshake VerificationMethod = iota
    
    // PoW challenge-response (explicit verification)
    VerifyPoWChallenge
    
    // QUIC address validation token
    VerifyQUICToken
    
    // Application-layer ping/pong
    VerifyAppPing
    
    // Cryptographic nonce echo
    VerifyCryptoNonce
)

type PendingVerification struct {
    ClientIP       net.IP
    Method         VerificationMethod
    Challenge      []byte            // Method-specific challenge
    IssuedAt       time.Time
    ExpiresAt      time.Time
    Attempts       int               // Failed attempts
    MaxAttempts    int               // Default: 3
}

type VerifiedClient struct {
    ClientIP         net.IP
    VerifiedAt       time.Time
    VerifiedVia      VerificationMethod
    ExpiresAt        time.Time
    ReVerifyAt       time.Time
    ConnectionCount  atomic.Int64
}

const (
    // Bidirectional verification constants
    BidirectionalTimeout       = 5 * time.Second
    VerifiedClientCacheTTL     = 1 * time.Hour
    ReVerificationInterval     = 30 * time.Minute
    MaxVerificationAttempts    = 3
    MaxPendingVerificationsIP  = 1
)

// StartVerification initiates bidirectional check for new client
func (v *BidirectionalVerifier) StartVerification(
    clientIP net.IP,
    method VerificationMethod,
) (*PendingVerification, error) {
    key := clientIP.String()
    
    // Check if already verified
    if verifiedI, ok := v.verified.Load(key); ok {
        verified := verifiedI.(*VerifiedClient)
        if time.Now().Before(verified.ExpiresAt) {
            return nil, nil // Already verified
        }
        // Expired - remove and re-verify
        v.verified.Delete(key)
    }
    
    // Check pending limit
    pendingCount := 0
    v.pending.Range(func(k, val interface{}) bool {
        if strings.HasPrefix(k.(string), key) {
            pendingCount++
        }
        return true
    })
    if pendingCount >= MaxPendingVerificationsIP {
        return nil, ErrTooManyPendingVerifications{
            ClientIP: clientIP,
            Current:  pendingCount,
            Max:      MaxPendingVerificationsIP,
        }
    }
    
    // Generate method-specific challenge
    challenge, err := v.generateChallenge(method)
    if err != nil {
        return nil, err
    }
    
    pending := &PendingVerification{
        ClientIP:    clientIP,
        Method:      method,
        Challenge:   challenge,
        IssuedAt:    time.Now(),
        ExpiresAt:   time.Now().Add(BidirectionalTimeout),
        MaxAttempts: MaxVerificationAttempts,
    }
    
    v.pending.Store(key, pending)
    return pending, nil
}

// CompleteVerification validates client's response to challenge
func (v *BidirectionalVerifier) CompleteVerification(
    clientIP net.IP,
    response []byte,
) error {
    key := clientIP.String()
    
    pendingI, ok := v.pending.Load(key)
    if !ok {
        return ErrNoVerificationPending{ClientIP: clientIP}
    }
    pending := pendingI.(*PendingVerification)
    
    // Check expiry
    if time.Now().After(pending.ExpiresAt) {
        v.pending.Delete(key)
        return ErrVerificationExpired{
            ClientIP:  clientIP,
            ExpiredAt: pending.ExpiresAt,
        }
    }
    
    // Validate response
    valid, err := v.validateResponse(pending.Method, pending.Challenge, response)
    if err != nil {
        return err
    }
    
    if !valid {
        pending.Attempts++
        if pending.Attempts >= pending.MaxAttempts {
            v.pending.Delete(key)
            return ErrVerificationFailed{
                ClientIP: clientIP,
                Attempts: pending.Attempts,
                Reason:   "max attempts exceeded",
            }
        }
        return ErrInvalidVerificationResponse{
            ClientIP:  clientIP,
            Attempt:   pending.Attempts,
            Remaining: pending.MaxAttempts - pending.Attempts,
        }
    }
    
    // SUCCESS - Client proved bidirectional connectivity
    v.pending.Delete(key)
    
    now := time.Now()
    verified := &VerifiedClient{
        ClientIP:    clientIP,
        VerifiedAt:  now,
        VerifiedVia: pending.Method,
        ExpiresAt:   now.Add(VerifiedClientCacheTTL),
        ReVerifyAt:  now.Add(ReVerificationInterval),
    }
    v.verified.Store(key, verified)
    
    return nil
}

// IsVerified checks if client has completed bidirectional verification
func (v *BidirectionalVerifier) IsVerified(clientIP net.IP) bool {
    key := clientIP.String()
    
    verifiedI, ok := v.verified.Load(key)
    if !ok {
        return false
    }
    
    verified := verifiedI.(*VerifiedClient)
    return time.Now().Before(verified.ExpiresAt)
}

// generateChallenge creates method-specific verification challenge
func (v *BidirectionalVerifier) generateChallenge(method VerificationMethod) ([]byte, error) {
    switch method {
    case VerifyPoWChallenge:
        // Use existing PoW challenge system
        nonce := make([]byte, 16)
        if _, err := rand.Read(nonce); err != nil {
            return nil, err
        }
        return nonce, nil
        
    case VerifyQUICToken:
        // Generate QUIC address validation token
        token := make([]byte, 32)
        if _, err := rand.Read(token); err != nil {
            return nil, err
        }
        return token, nil
        
    case VerifyCryptoNonce:
        // Generate cryptographic nonce for echo
        nonce := make([]byte, 32)
        if _, err := rand.Read(nonce); err != nil {
            return nil, err
        }
        return nonce, nil
        
    default:
        return nil, ErrUnsupportedVerificationMethod{Method: method}
    }
}

// validateResponse verifies client's response to challenge
func (v *BidirectionalVerifier) validateResponse(
    method VerificationMethod,
    challenge, response []byte,
) (bool, error) {
    switch method {
    case VerifyPoWChallenge:
        // Validate PoW solution
        return v.validatePoWResponse(challenge, response)
        
    case VerifyQUICToken:
        // QUIC token must match exactly
        return bytes.Equal(challenge, response), nil
        
    case VerifyCryptoNonce:
        // Nonce echo must match exactly
        return bytes.Equal(challenge, response), nil
        
    case VerifyTCPHandshake:
        // TCP handshake is implicit - if we receive the response,
        // the handshake completed successfully
        return true, nil
        
    default:
        return false, ErrUnsupportedVerificationMethod{Method: method}
    }
}

// Bidirectional verification error types
type ErrTooManyPendingVerifications struct {
    ClientIP net.IP
    Current  int
    Max      int
}
func (e ErrTooManyPendingVerifications) Error() string {
    return fmt.Sprintf("too many pending verifications for %s: %d/%d",
        e.ClientIP, e.Current, e.Max)
}

type ErrNoVerificationPending struct {
    ClientIP net.IP
}
func (e ErrNoVerificationPending) Error() string {
    return fmt.Sprintf("no verification pending for %s", e.ClientIP)
}

type ErrVerificationExpired struct {
    ClientIP  net.IP
    ExpiredAt time.Time
}
func (e ErrVerificationExpired) Error() string {
    return fmt.Sprintf("verification expired for %s at %v", e.ClientIP, e.ExpiredAt)
}

type ErrVerificationFailed struct {
    ClientIP net.IP
    Attempts int
    Reason   string
}
func (e ErrVerificationFailed) Error() string {
    return fmt.Sprintf("verification failed for %s after %d attempts: %s",
        e.ClientIP, e.Attempts, e.Reason)
}

type ErrInvalidVerificationResponse struct {
    ClientIP  net.IP
    Attempt   int
    Remaining int
}
func (e ErrInvalidVerificationResponse) Error() string {
    return fmt.Sprintf("invalid verification response from %s (attempt %d, %d remaining)",
        e.ClientIP, e.Attempt, e.Remaining)
}

type ErrUnsupportedVerificationMethod struct {
    Method VerificationMethod
}
func (e ErrUnsupportedVerificationMethod) Error() string {
    return fmt.Sprintf("unsupported verification method: %d", e.Method)
}
```

#### Integrated IP Spoofing Protection Flow

```
                    IP SPOOFING PROTECTION FLOW

    Incoming Packet
          |
          v
    +------------------+
    | 1. Flow Tracking |  Is this a known, validated flow?
    +--------+---------+
             |
        No   |   Yes
        +----+----+
        |         |
        v         v
    +-------+   ALLOW
    | 2. TCP|   (flow already verified)
    | State |
    +---+---+
        |
        | New flow or unvalidated
        v
    +------------------+
    | 3. Bidirectional |  Client must prove it can receive responses
    |    Verification  |
    +--------+---------+
             |
        +----+----+
        |         |
    FAIL    SUCCESS
        |         |
        v         v
    +-------+   +------------------+
    | DROP  |   | 4. Asymmetric    |
    | PACKET|   |    RTT Check     |
    +-------+   +--------+---------+
                         |
                    +----+----+
                    |         |
                 WARN/OK    REJECT
                    |         |
                    v         v
               +--------+  +-------+
               | ALLOW  |  | DROP  |
               | TRAFFIC|  | + LOG |
               +--------+  +-------+
```

#### IP Spoofing Protection Constants

```go
const (
    // Asymmetric routing detection
    RTTAsymmetryWarning        = 5.0               // Log warning threshold
    RTTAsymmetryReject         = 10.0              // Reject traffic threshold
    RTTAsymmetryBlock          = 20.0              // Block + report threshold
    MinRTTSamples              = 5                 // Samples before validation
    RTTMeasurementTimeout      = 5 * time.Second   // Per-measurement timeout
    RTTBaselineExpiry          = 1 * time.Hour     // Recalculate baseline
    
    // Bidirectional verification
    BidirectionalTimeout       = 5 * time.Second   // Verification timeout
    VerifiedClientCacheTTL     = 1 * time.Hour     // Cache verified clients
    ReVerificationInterval     = 30 * time.Minute  // Re-verify long connections
    MaxVerificationAttempts    = 3                 // Failed attempts before block
    MaxPendingVerificationsIP  = 1                 // Pending verifications per IP
)
```

### Scrubber Metrics Dashboard

```go
// ScrubberMetrics provides real-time visibility into scrubbing effectiveness
type ScrubberMetrics struct {
    TotalPackets        atomic.Uint64
    CleanPackets        atomic.Uint64
    DroppedAttack       atomic.Uint64
    DroppedProtocol     atomic.Uint64
    DroppedRateLimit    atomic.Uint64
    DroppedSpoof        atomic.Uint64  // P4-M2: IP spoofing detections
    DroppedSYNFlood     atomic.Uint64
    DroppedTCPState     atomic.Uint64
    DroppedUDPNoPoW     atomic.Uint64
    ActiveFlows         atomic.Int64
    SYNCookiesGenerated atomic.Uint64
    SYNCookiesValidated atomic.Uint64
}
```

---

## Layer 5: Collaborative Threat Intelligence

### DHT-Backed Threat Database

Threat intelligence is stored in the DHT and synchronized across all nodes:

```go
type ThreatEntry struct {
    EntryID       [32]byte
    ThreatType    ThreatType
    Indicator     string        // IP, CIDR, pattern, signature
    Confidence    float64       // 0.0 to 1.0
    ReportCount   uint32        // Number of reporting nodes
    Reporters     []NodeID      // First N reporters
    FirstReported time.Time
    LastUpdated   time.Time
    ExpiresAt     time.Time     // Auto-expire after ThreatIntelExpiry
    Evidence      []byte        // Compressed evidence data
    TPMAttestation []byte       // TPM-attested proof
}

type ThreatType uint8
const (
    ThreatIPBlacklist  ThreatType = iota  // Known malicious IP
    ThreatCIDRBlock                        // Malicious network block
    ThreatPatternMatch                     // Traffic pattern signature
    ThreatBehavioral                       // Behavioral anomaly
    ThreatASNBlock                         // Malicious ASN
)

const (
    ThreatIntelExpiry     = 24 * time.Hour  // Auto-expire threats
    ThreatIntelMinReports = 3               // Reports required for action
)
```

### Threat Sharing Protocol

```go
type ThreatReport struct {
    ReporterID      NodeID
    ThreatType      ThreatType
    Indicator       string
    Evidence        []byte
    Timestamp       time.Time
    TPMQuote        []byte        // TPM attestation
    Signature       []byte        // Reporter signature
}

func (ti *ThreatIntelligence) ReportThreat(report ThreatReport) error {
    // Verify TPM attestation
    if !ti.verifyTPMQuote(report.TPMQuote, report.ReporterID) {
        return ErrInvalidAttestation
    }

    // Check reporter reputation
    rep := ti.getNodeReputation(report.ReporterID)
    if rep < MinReputationForReporting {
        return ErrInsufficientReputation
    }

    // Store in DHT
    entry := ti.getOrCreateEntry(report.Indicator)
    entry.ReportCount++
    entry.Reporters = append(entry.Reporters, report.ReporterID)

    // SECURITY FIX: Reset LastUpdated on new reports
    // This prevents stale threat accumulation by ensuring recent reports
    // keep the entry fresh and prevent premature cleanup
    now := time.Now()
    entry.LastUpdated = now

    // Also reset confidence if it had decayed significantly
    // New reports indicate continued malicious activity
    if entry.Confidence < 0.5 && entry.ReportCount >= ThreatIntelMinReports {
        entry.Confidence = 0.5 + (float64(entry.ReportCount-ThreatIntelMinReports) * 0.1)
        if entry.Confidence > 1.0 {
            entry.Confidence = 1.0
        }
    }

    // Activate if threshold met
    if entry.ReportCount >= ThreatIntelMinReports {
        ti.activateThreat(entry)
    }

    return ti.dht.Store(entry.Key(), entry)
}
```

### Threat Database Schema

```
DHT Keys for Threat Intelligence:
  threat:ip:<ip-address>        -> ThreatEntry
  threat:cidr:<cidr-block>      -> ThreatEntry
  threat:pattern:<sha256-hash>  -> ThreatEntry
  threat:asn:<asn-number>       -> ThreatEntry
  threat:index:active           -> []ThreatEntryID (active threats)
  threat:index:recent           -> []ThreatEntryID (last 24h)
```

### Threat Intel Cleanup Mechanism (P4-M3 Fix)

**Problem**: ThreatEntry has `ExpiresAt` field but NO cleanup mechanism exists.
Expired threats accumulate indefinitely, consuming DHT storage and degrading lookup performance.

**Solution**: Periodic cleanup goroutine with bounded memory usage and stale entry eviction.

#### Threat Intelligence Cleanup Summary

| Parameter | Value | Description |
|-----------|-------|-------------|
| **CleanupExpiredThreats()** | Every 5 minutes | Removes threats past ExpiresAt |
| **Confidence Decay** | 5% per day | `confidence = original * 0.95^days` |
| **Stale Threshold** | 7 days | Entries with no new reports |
| **LastUpdated Reset** | On new report | Prevents premature cleanup |
| **Max Entries Per Type** | 100,000 | Per threat category limit |

**Key Behaviors:**
- `CleanupExpiredThreats()` runs every 5 minutes via `DefaultCleanupInterval`
- `LastUpdated` is reset on EVERY new report (prevents stale accumulation)
- Confidence decays over time but is restored by new reports
- Entries below `ThreatDeletionThreshold` (0.1) are marked for cleanup

```go
// ThreatIntelCleaner manages threat intel lifecycle and cleanup
type ThreatIntelCleaner struct {
    dht           DHT
    localCache    *ThreatCache
    cleanupTicker *time.Ticker
    stopCh        chan struct{}

    // Configuration
    config ThreatCleanerConfig

    // Metrics
    expiredCount    atomic.Uint64
    staleCount      atomic.Uint64
    orphanCount     atomic.Uint64
    cleanupDuration atomic.Int64
}

type ThreatCleanerConfig struct {
    CleanupInterval     time.Duration  // How often to run cleanup
    ExpiryGracePeriod   time.Duration  // Extra time before hard delete
    MaxEntriesPerType   int            // Max entries per threat type
    StaleThreshold      time.Duration  // Entries with no reports in this window
    MaxCacheMemory      int64          // Max memory for local cache (bytes)
    OrphanCheckInterval time.Duration  // How often to check for orphaned entries
}

const (
    DefaultCleanupInterval     = 5 * time.Minute
    DefaultExpiryGracePeriod   = 1 * time.Hour
    DefaultMaxEntriesPerType   = 100_000
    DefaultStaleThreshold      = 7 * 24 * time.Hour  // 7 days without reports
    DefaultMaxCacheMemory      = 256 * 1024 * 1024   // 256 MB
    DefaultOrphanCheckInterval = 1 * time.Hour
)

// NewThreatIntelCleaner creates a cleaner with default configuration
func NewThreatIntelCleaner(dht DHT) *ThreatIntelCleaner {
    return &ThreatIntelCleaner{
        dht: dht,
        config: ThreatCleanerConfig{
            CleanupInterval:     DefaultCleanupInterval,
            ExpiryGracePeriod:   DefaultExpiryGracePeriod,
            MaxEntriesPerType:   DefaultMaxEntriesPerType,
            StaleThreshold:      DefaultStaleThreshold,
            MaxCacheMemory:      DefaultMaxCacheMemory,
            OrphanCheckInterval: DefaultOrphanCheckInterval,
        },
        stopCh: make(chan struct{}),
    }
}

// Start begins the periodic cleanup process
func (c *ThreatIntelCleaner) Start() {
    c.cleanupTicker = time.NewTicker(c.config.CleanupInterval)

    go func() {
        for {
            select {
            case <-c.cleanupTicker.C:
                c.runCleanupCycle()
            case <-c.stopCh:
                c.cleanupTicker.Stop()
                return
            }
        }
    }()
}

// Stop halts the cleanup process
func (c *ThreatIntelCleaner) Stop() {
    close(c.stopCh)
}

// runCleanupCycle performs a complete cleanup pass
func (c *ThreatIntelCleaner) runCleanupCycle() {
    start := time.Now()
    defer func() {
        c.cleanupDuration.Store(time.Since(start).Milliseconds())
    }()

    // Step 1: Clean expired entries
    c.cleanExpiredEntries()

    // Step 2: Clean stale entries (no recent reports)
    c.cleanStaleEntries()

    // Step 3: Enforce per-type limits (evict lowest confidence)
    c.enforceTypeLimits()

    // Step 4: Clean local cache if over memory limit
    c.evictCacheIfNeeded()

    // Step 5: Periodically check for orphaned entries
    if time.Now().Truncate(c.config.OrphanCheckInterval) == time.Now().Truncate(c.config.CleanupInterval) {
        c.cleanOrphanedEntries()
    }
}

// cleanExpiredEntries removes entries past their ExpiresAt + grace period
func (c *ThreatIntelCleaner) cleanExpiredEntries() {
    now := time.Now()
    expiryThreshold := now.Add(-c.config.ExpiryGracePeriod)

    for _, threatType := range allThreatTypes {
        entries, err := c.listEntriesByType(threatType)
        if err != nil {
            continue
        }

        for _, entry := range entries {
            if entry.ExpiresAt.Before(expiryThreshold) {
                if err := c.deleteEntry(entry); err == nil {
                    c.expiredCount.Add(1)
                }
            }
        }
    }
}

// cleanStaleEntries removes entries with no recent reports
func (c *ThreatIntelCleaner) cleanStaleEntries() {
    now := time.Now()
    staleThreshold := now.Add(-c.config.StaleThreshold)

    for _, threatType := range allThreatTypes {
        entries, err := c.listEntriesByType(threatType)
        if err != nil {
            continue
        }

        for _, entry := range entries {
            // Entry is stale if:
            // 1. LastUpdated is older than threshold
            // 2. ReportCount is below minimum (3)
            // 3. Confidence has decayed below 0.1
            if entry.LastUpdated.Before(staleThreshold) &&
               entry.ReportCount < ThreatIntelMinReports &&
               entry.Confidence < 0.1 {
                if err := c.deleteEntry(entry); err == nil {
                    c.staleCount.Add(1)
                }
            }
        }
    }
}

// enforceTypeLimits ensures no threat type exceeds max entries
func (c *ThreatIntelCleaner) enforceTypeLimits() {
    for _, threatType := range allThreatTypes {
        entries, err := c.listEntriesByType(threatType)
        if err != nil {
            continue
        }

        if len(entries) <= c.config.MaxEntriesPerType {
            continue
        }

        // Sort by confidence (ascending) - evict lowest confidence first
        sort.Slice(entries, func(i, j int) bool {
            return entries[i].Confidence < entries[j].Confidence
        })

        // Evict entries exceeding limit
        toEvict := len(entries) - c.config.MaxEntriesPerType
        for i := 0; i < toEvict; i++ {
            c.deleteEntry(entries[i])
        }
    }
}

// cleanOrphanedEntries removes entries not in any index
func (c *ThreatIntelCleaner) cleanOrphanedEntries() {
    // Get all entries in active and recent indexes
    activeIDs := c.getIndexEntries("threat:index:active")
    recentIDs := c.getIndexEntries("threat:index:recent")

    indexed := make(map[[32]byte]bool)
    for _, id := range activeIDs {
        indexed[id] = true
    }
    for _, id := range recentIDs {
        indexed[id] = true
    }

    // Scan all threat entries and find orphans
    for _, threatType := range allThreatTypes {
        entries, err := c.listEntriesByType(threatType)
        if err != nil {
            continue
        }

        for _, entry := range entries {
            if !indexed[entry.EntryID] {
                // Entry exists but not in any index - orphan
                // Either delete or re-index based on entry state
                if entry.ReportCount >= ThreatIntelMinReports {
                    // Should be active - re-index
                    c.addToIndex("threat:index:active", entry.EntryID)
                } else {
                    // Below threshold and orphaned - delete
                    if err := c.deleteEntry(entry); err == nil {
                        c.orphanCount.Add(1)
                    }
                }
            }
        }
    }
}

// evictCacheIfNeeded evicts local cache entries if over memory limit
func (c *ThreatIntelCleaner) evictCacheIfNeeded() {
    if c.localCache == nil {
        return
    }

    currentSize := c.localCache.Size()
    if currentSize <= c.config.MaxCacheMemory {
        return
    }

    // Evict 25% of entries (LRU)
    toEvict := currentSize / 4
    c.localCache.EvictOldest(toEvict)
}

// deleteEntry removes an entry from DHT and all indexes
func (c *ThreatIntelCleaner) deleteEntry(entry *ThreatEntry) error {
    // Remove from type-specific storage
    key := threatKey(entry.ThreatType, entry.Indicator)
    if err := c.dht.Delete(key); err != nil {
        return err
    }

    // Remove from indexes
    c.removeFromIndex("threat:index:active", entry.EntryID)
    c.removeFromIndex("threat:index:recent", entry.EntryID)

    // Remove from local cache
    if c.localCache != nil {
        c.localCache.Delete(entry.EntryID)
    }

    return nil
}

// Cleanup metrics for monitoring
type ThreatCleanerMetrics struct {
    ExpiredRemoved    uint64
    StaleRemoved      uint64
    OrphansRemoved    uint64
    LimitEvictions    uint64
    CacheEvictions    uint64
    LastCleanupMs     int64
    ActiveEntries     int64
    CacheMemoryBytes  int64
}

func (c *ThreatIntelCleaner) GetMetrics() ThreatCleanerMetrics {
    return ThreatCleanerMetrics{
        ExpiredRemoved:    c.expiredCount.Load(),
        StaleRemoved:      c.staleCount.Load(),
        OrphansRemoved:    c.orphanCount.Load(),
        LastCleanupMs:     c.cleanupDuration.Load(),
    }
}

// Helper: List all threat types
var allThreatTypes = []ThreatType{
    ThreatIPBlacklist,
    ThreatCIDRBlock,
    ThreatPatternMatch,
    ThreatBehavioral,
    ThreatASNBlock,
}

// Helper: Generate threat key
func threatKey(t ThreatType, indicator string) string {
    switch t {
    case ThreatIPBlacklist:
        return "threat:ip:" + indicator
    case ThreatCIDRBlock:
        return "threat:cidr:" + indicator
    case ThreatPatternMatch:
        return "threat:pattern:" + indicator
    case ThreatASNBlock:
        return "threat:asn:" + indicator
    default:
        return "threat:unknown:" + indicator
    }
}
```

### Threat Intel Confidence Decay

In addition to cleanup, active threats should have confidence decay over time to prevent permanently blocked IPs:

```go
// DecayThreatConfidence applies time-based decay to threat confidence
// Called during cleanup cycle for all active entries
// SECURITY FIX (P5-H3): Decayed confidence MUST be persisted to enable cleanup
func (ti *ThreatIntelligence) DecayThreatConfidence(entry *ThreatEntry) {
    // Confidence decays by 5% per day without new reports
    daysSinceUpdate := time.Since(entry.LastUpdated).Hours() / 24
    if daysSinceUpdate < 1 {
        return // No decay within first day
    }

    // Decay formula: confidence = original * (0.95 ^ days)
    decayFactor := math.Pow(0.95, daysSinceUpdate)
    oldConfidence := entry.Confidence
    entry.Confidence *= decayFactor

    // CRITICAL FIX (P5-H3): Persist the decayed confidence to DHT
    // Without this, cleanup mechanism never sees low-confidence entries
    if err := ti.dht.Store(entry.Key(), entry); err != nil {
        log.Warn("failed to persist threat confidence decay",
            "key", entry.Key(),
            "old_confidence", oldConfidence,
            "new_confidence", entry.Confidence,
            "error", err)
    }

    // If confidence drops below threshold, deactivate
    if entry.Confidence < ThreatDeactivationThreshold {
        ti.deactivateThreat(entry)
    }

    // If confidence drops below deletion threshold, mark for cleanup
    if entry.Confidence < ThreatDeletionThreshold {
        ti.markForCleanup(entry)
    }
}

// markForCleanup adds entry to cleanup queue for next cycle
func (ti *ThreatIntelligence) markForCleanup(entry *ThreatEntry) {
    entry.MarkedForDeletion = true
    entry.MarkedAt = time.Now()
    ti.dht.Store(entry.Key(), entry)
}

const (
    ThreatDeactivationThreshold = 0.3  // Below this, threat is deactivated
    ThreatDeletionThreshold     = 0.1  // Below this, entry eligible for cleanup
)
```

---

## DDoS Protection for Services

### Automatic Protection for All Services

Any service hosted on the Trusted DHT Network automatically receives DDoS protection:

```
                    SERVICE PROTECTION FLOW

    Client Request
          |
          v
    +------------------+
    | Gateway Mesh     |  Layer 1: Traffic diluted across 10,000+ gateways
    | (Anycast)        |
    +--------+---------+
             |
             v
    +------------------+
    | Rate Limiting    |  Layer 2: Per-IP limits enforced
    | (Per-IP Quotas)  |
    +--------+---------+
             |
             v
    +------------------+
    | PoW Challenge?   |  Layer 3: Low-rep IPs complete PoW
    | (If Required)    |
    +--------+---------+
             |
             v
    +------------------+
    | Traffic Scrubbing|  Layer 4: Untrusted nodes filter traffic
    | (Work Pool)      |
    +--------+---------+
             |
             v
    +------------------+
    | Threat Check     |  Layer 5: Check against threat database
    | (DHT Lookup)     |
    +--------+---------+
             |
             v
    +------------------+
    |  USER SERVICE    |  Clean traffic delivered
    | (E-commerce,     |
    |  Cloud, SaaS)    |
    +------------------+
```

### Service Types Protected

| Service Type | Protection Level | Special Features |
|--------------|------------------|------------------|
| **E-Commerce** | Full | Transaction rate limiting, bot detection |
| **Cloud Hosting** | Full | Per-tenant isolation, bandwidth quotas |
| **SaaS Applications** | Full | API rate limiting, authentication checks |
| **Static Content** | Full | CDN caching, edge delivery |
| **Streaming Media** | Full | Bandwidth management, adaptive bitrate |
| **IoT Endpoints** | Full | Protocol validation, device authentication |
| **DHT Infrastructure** | Full | Core network operations protected |

### Service-Specific Configuration

```go
type ServiceProtection struct {
    ServiceID         string
    OwnerNodeID       NodeID
    ProtectionLevel   ProtectionLevel
    CustomRateLimits  *RateLimits     // Override defaults
    AllowedOrigins    []string        // CORS-style origin list
    RequirePoW        bool            // Always require PoW
    BlockedCountries  []string        // GeoIP blocking
    CustomPatterns    []AttackPattern // Service-specific signatures
}

type ProtectionLevel uint8
const (
    ProtectionStandard  ProtectionLevel = iota  // Default 5-layer
    ProtectionEnhanced                          // + Additional scrubbing
    ProtectionMaximum                           // + Strict rate limits + PoW
)
```

---

## Implementation

### Package Structure

```
pkg/defense/
    ddos/
        protection.go      # Main DDoS protection coordinator
        pow.go             # Proof-of-work challenge system
        ratelimit.go       # Rate limiting and quotas
        reputation.go      # IP reputation management
        scrubber.go        # Traffic scrubbing
        threat_intel.go    # Collaborative threat intelligence
        work_pool.go       # Untrusted node work pool

    monitor/
        behavior.go        # Behavioral monitoring
        metrics.go         # Metrics collection
        anomaly.go         # Anomaly detection

    judgment/
        evidence.go        # Evidence collection
        quorum.go          # PBFT quorum voting
        appeal.go          # Appeal process

    penalty/
        executor.go        # Penalty execution
        ban.go             # Ban management
        quarantine.go      # Quarantine handling
```

### Core Protection Interface

```go
type DDoSProtection interface {
    // Request Processing
    ProcessRequest(ctx context.Context, req *Request) (*Response, error)
    ValidatePoW(solution *PoWSolution) (bool, error)
    IssueChallenge(clientIP net.IP) (*PoWChallenge, error)

    // Rate Limiting
    CheckRateLimit(clientIP net.IP) (bool, error)
    GetIPReputation(clientIP net.IP) (*IPReputation, error)
    UpdateIPReputation(clientIP net.IP, delta float64) error

    // Threat Intelligence
    ReportThreat(report *ThreatReport) error
    CheckThreat(indicator string) (*ThreatEntry, error)
    SubscribeThreatUpdates(handler ThreatHandler) error

    // Work Pool
    SubmitTask(task *Task) error
    GetWorkerStats() (*WorkerStats, error)

    // Metrics
    GetProtectionMetrics() (*ProtectionMetrics, error)
}
```

### Initialization

```go
func NewDDoSProtection(config *DDoSConfig) (*Protection, error) {
    p := &Protection{
        rateLimiter:    NewRateLimiter(config.RateLimits),
        powController:  NewPoWController(config.PoW),
        ipReputation:   NewIPReputationStore(config.Reputation),
        threatIntel:    NewThreatIntelligence(config.DHT),
        workPool:       NewWorkPool(config.Workers),
        scrubber:       NewScrubber(config.Scrubbing),
    }

    // Start background workers
    go p.cleanupLoop()
    go p.syncThreatIntel()
    go p.updateMetrics()

    return p, nil
}
```

---

## Security Constants (CANONICAL)

All DDoS-related constants from the canonical security configuration:

```go
// pkg/config/constants.go

const (
    // Rate Limiting
    MaxConnectionsPerIP    = 10                     // Concurrent per IP
    MaxRequestsPerSecond   = 100                    // Requests per second per IP
    MaxNewConnsPerMinute   = 20                     // New connections per minute

    // Proof-of-Work
    PoWDifficulty          = 20                     // 2^20 hashes (~1 second)
    PoWCacheDuration       = 1 * time.Hour          // Solution cache duration
    PoWMaxDifficulty       = 28                     // Maximum adaptive difficulty
    PoWMinDifficulty       = 16                     // Minimum difficulty

    // IP Reputation
    MinIPReputation        = 0.20                   // Block if below
    IPReputationDecay      = 0.01                   // Per bad request
    IPReputationRestore    = 0.001                  // Per good request

    // Threat Intelligence
    ThreatIntelExpiry         = 24 * time.Hour      // Auto-expire threats
    ThreatIntelMinReports     = 3                   // Reports to blacklist
    ThreatIntelCleanupInterval = 5 * time.Minute    // CleanupExpiredThreats() frequency
    ThreatConfidenceDecayRate = 0.95                // Per-day decay multiplier

    // Work Pool
    WorkPoolMaxTasks       = 10000                  // Max queued tasks
    WorkPoolTimeout        = 5 * time.Second        // Task timeout
    WorkerHeartbeat        = 30 * time.Second       // Worker keepalive

    // Traffic Scrubbing
    ScrubberQueueSize      = 50000                  // Packet queue size
    ScrubberWorkers        = 16                     // Parallel workers

    // Challenge Pool Bounds (P4-H1: Resource Management)
    MaxPendingChallengesPerIP  = 3                  // Max unsolved per IP
    MaxChallengesPerIPPerMin   = 10                 // Rate limit per minute
    MaxTotalPendingChallenges  = 1_000_000          // Global cap: 1M challenges
    PreemptiveEvictionThreshold = 950_000           // 95% capacity triggers eviction
    ChallengeTTL               = 5 * time.Minute    // Challenge lifecycle (CreatedAt -> ExpiresAt)
    ChallengeCleanupInterval   = 30 * time.Second   // Expired challenge cleanup frequency
    IPStateCleanupInterval     = 5 * time.Minute    // Cleanup stale IP entries
    IPStateMaxAge              = 1 * time.Hour      // Max age for idle IP state

    // Flow State Tracker Bounds
    MaxTrackedFlows            = 1_000_000          // Max concurrent flows
    FlowPreemptiveThreshold    = 950_000            // 95% triggers eviction
    FlowEvictionPercent        = 5                  // Evict oldest 5% when triggered
    FlowIdleTimeout            = 60 * time.Second   // Idle flow cleanup
)
```

### IP State Cleanup (P4-H1)

**Problem**: The `perIPLimits` sync.Map can grow unbounded as IPs come and go. Without cleanup, memory usage grows indefinitely.

**Solution**: Periodic cleanup of stale IP entries.

```go
// cleanupLoop periodically removes stale IP state entries (P4-H1)
// This prevents unbounded memory growth from abandoned IP sessions
func (r *ChallengeRateLimiter) cleanupLoop(ctx context.Context) {
    ticker := time.NewTicker(IPStateCleanupInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            r.cleanupStaleEntries()
        }
    }
}

// cleanupStaleEntries removes IP states that haven't been used recently
func (r *ChallengeRateLimiter) cleanupStaleEntries() {
    now := time.Now()
    cutoff := now.Add(-IPStateMaxAge)
    var removed int

    r.perIPLimits.Range(func(key, value interface{}) bool {
        state := value.(*IPLimitState)
        state.mu.Lock()

        // Check if state is stale:
        // 1. No pending challenges
        // 2. No recent request times
        // 3. Not currently banned
        isPending := state.PendingCount.Load() > 0
        isBanned := state.Banned.Load() && now.Before(state.BannedUntil)

        // Find most recent activity
        var mostRecent time.Time
        for _, t := range state.RequestTimes {
            if t.After(mostRecent) {
                mostRecent = t
            }
        }
        isRecent := mostRecent.After(cutoff)

        state.mu.Unlock()

        // Only delete if truly stale
        if !isPending && !isBanned && !isRecent {
            r.perIPLimits.Delete(key)
            removed++
        }

        return true // continue iteration
    })

    if removed > 0 {
        log.Debug("cleaned up stale IP rate limit entries",
            "removed", removed,
            "cutoff", cutoff)
    }
}

// GetStats returns current rate limiter statistics
func (r *ChallengeRateLimiter) GetStats() RateLimiterStats {
    var ipCount int
    var totalPending int64

    r.perIPLimits.Range(func(key, value interface{}) bool {
        ipCount++
        state := value.(*IPLimitState)
        totalPending += int64(state.PendingCount.Load())
        return true
    })

    return RateLimiterStats{
        TrackedIPs:          ipCount,
        TotalPendingLocal:   totalPending,
        TotalPendingGlobal:  r.globalCounter.Load(),
        LastCleanup:         r.lastCleanup,
    }
}

type RateLimiterStats struct {
    TrackedIPs         int
    TotalPendingLocal  int64
    TotalPendingGlobal int64
    LastCleanup        time.Time
}
```

---

## Attack Response

### Automated Response Matrix

| Attack Type | Detection Method | Response | Escalation |
|-------------|-----------------|----------|------------|
| **Volumetric Flood** | Bandwidth spike | Rate limit + PoW | BGP FlowSpec |
| **SYN Flood** | Connection rate | SYN cookies + block | Gateway coordination |
| **Amplification** | Protocol anomaly | Protocol filter | Upstream filtering |
| **Application Layer** | Request pattern | PoW + scrubbing | Enhanced validation |
| **Slowloris** | Connection duration | Timeout + ban | Connection limits |
| **DNS Amplification** | DNS query volume | DNS rate limit | DNS response filter |
| **NTP Amplification** | NTP traffic spike | NTP block | Protocol blacklist |

### Attack Response Flow

```go
type AttackResponse struct {
    AttackID       [32]byte
    DetectedAt     time.Time
    AttackType     AttackType
    Severity       Severity
    Actions        []ResponseAction
    Status         ResponseStatus
}

type ResponseAction struct {
    ActionType     ActionType
    Target         string          // IP, CIDR, or pattern
    Duration       time.Duration
    ExecutedAt     time.Time
    ExecutedBy     NodeID
}

func (p *Protection) HandleAttack(attack *AttackDetection) error {
    response := &AttackResponse{
        AttackID:   attack.ID,
        DetectedAt: time.Now(),
        AttackType: attack.Type,
        Severity:   attack.Severity,
    }

    // Layer 1: Immediate mitigation
    switch attack.Severity {
    case SeverityCritical:
        response.Actions = append(response.Actions,
            p.activateFlowSpec(attack.Sources),
            p.increasePowDifficulty(PoWMaxDifficulty),
            p.activateWorkPool(WorkPoolEmergency),
        )
    case SeverityHigh:
        response.Actions = append(response.Actions,
            p.blockSources(attack.Sources, 1*time.Hour),
            p.increasePowDifficulty(24),
        )
    case SeverityMedium:
        response.Actions = append(response.Actions,
            p.rateLimitSources(attack.Sources),
            p.requirePow(attack.Sources),
        )
    default:
        response.Actions = append(response.Actions,
            p.monitorSources(attack.Sources),
        )
    }

    // Layer 2: Propagate to network
    if attack.Severity >= SeverityHigh {
        p.broadcastThreat(attack)
    }

    return p.logResponse(response)
}
```

### Escalation Procedure

```
ATTACK ESCALATION PROCEDURE

Level 1: Automatic Mitigation (0-5 seconds)
    - Rate limiting activated
    - PoW challenges issued
    - IP reputation decreased
    - Traffic scrubbing engaged

Level 2: Network Coordination (5-30 seconds)
    - Threat intel shared to DHT
    - Nearby gateways notified
    - Work pool fully activated
    - FlowSpec rules deployed

Level 3: Regional Response (30 seconds - 5 minutes)
    - Regional coordinators engaged
    - BGP announcements adjusted
    - Upstream filtering requested
    - Incident logged for analysis

Level 4: Global Response (5+ minutes)
    - Full network mobilization
    - All gateways in defense mode
    - External ISP coordination
    - Post-incident analysis scheduled
```

---

## Integration

### Gateway Mesh Integration

```go
type GatewayIntegration struct {
    mesh          *GatewayMesh
    protection    *DDoSProtection
    flowSpec      *FlowSpecController
}

func (gi *GatewayIntegration) OnTrafficReceived(pkt *Packet) error {
    // Check threat database first
    if threat, _ := gi.protection.CheckThreat(pkt.SourceIP.String()); threat != nil {
        return ErrBlockedByThreatIntel
    }

    // Check rate limits
    if allowed, _ := gi.protection.CheckRateLimit(pkt.SourceIP); !allowed {
        return ErrRateLimited
    }

    // Check if PoW required
    rep, _ := gi.protection.GetIPReputation(pkt.SourceIP)
    if rep.Score < LowIPReputation {
        if !pkt.HasValidPoW() {
            challenge, _ := gi.protection.IssueChallenge(pkt.SourceIP)
            return &PoWRequired{Challenge: challenge}
        }
    }

    // Forward to service
    return gi.mesh.Forward(pkt)
}
```

### Reputation System Integration

DDoS protection integrates with the node reputation system (see [09-defense-reputation.md](09-defense-reputation.md)):

```go
type ReputationIntegration struct {
    nodeReputation  *ReputationStore
    ipReputation    *IPReputationStore
}

// Nodes that report valid threats earn reputation
func (ri *ReputationIntegration) OnThreatConfirmed(report *ThreatReport) {
    // Award reputation to reporter
    ri.nodeReputation.Add(report.ReporterID, ThreatReportReward)

    // Record contribution
    ri.nodeReputation.RecordActivity(report.ReporterID, ActivityThreatReport)
}

// Nodes that submit false reports lose reputation
func (ri *ReputationIntegration) OnFalseReport(report *ThreatReport) {
    // Penalize reporter
    ri.nodeReputation.Subtract(report.ReporterID, FalseReportPenalty)

    // Record violation
    ri.nodeReputation.RecordViolation(report.ReporterID, ViolationFalseReport)
}
```

### Trusted Computing Integration

TPM attestation ensures threat reports are authentic:

```go
type TPMIntegration struct {
    tpm         *TPMController
    quoteSigner *QuoteSigner
}

func (ti *TPMIntegration) CreateAttestedReport(report *ThreatReport) error {
    // Generate fresh nonce
    nonce, _ := ti.tpm.GenerateNonce()

    // Create TPM quote over report data
    reportHash := sha256.Sum256(report.Evidence)
    quote, _ := ti.tpm.CreateQuote(reportHash[:], nonce)

    report.TPMQuote = quote
    report.Timestamp = time.Now()

    // Sign the complete report
    report.Signature, _ = ti.quoteSigner.Sign(report)

    return nil
}

func (ti *TPMIntegration) VerifyAttestedReport(report *ThreatReport) bool {
    // Verify TPM quote freshness
    if !ti.tpm.VerifyQuoteFreshness(report.TPMQuote, TPMQuoteFreshness) {
        return false
    }

    // Verify quote signature
    if !ti.tpm.VerifyQuote(report.TPMQuote) {
        return false
    }

    // Verify report signature
    return ti.quoteSigner.Verify(report, report.Signature)
}
```

---

## Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Rate Limit Check | <1ms | Lock-free atomic counters |
| PoW Verification | <100us | SHA256 comparison |
| Threat DB Lookup | <5ms | DHT cache hit |
| IP Reputation Check | <1ms | In-memory LRU cache |
| Scrubber Latency | <500us | Per packet |
| Work Pool Task | <100ms | Average completion |
| FlowSpec Deployment | <30s | Network-wide propagation |

---

## Monitoring and Metrics

### Key Metrics

```go
type ProtectionMetrics struct {
    // Traffic
    TotalRequests       uint64
    BlockedRequests     uint64
    ScrubbedPackets     uint64

    // Rate Limiting
    RateLimitedIPs      uint32
    PoWChallengesIssued uint64
    PoWSolutionsValid   uint64

    // Threat Intelligence
    ActiveThreats       uint32
    ThreatReportsToday  uint32
    BlockedByThreatDB   uint64

    // Work Pool
    ActiveWorkers       uint32
    QueuedTasks         uint32
    TasksCompleted      uint64

    // Attack Detection
    AttacksDetected     uint32
    AttacksMitigated    uint32
    CurrentAttackLevel  Severity
}
```

### Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Blocked Requests % | > 20% | > 50% |
| PoW Queue Depth | > 1000 | > 5000 |
| Attack Detection | Any | Severity >= High |
| Work Pool Queue | > 5000 | > 8000 |
| Threat DB Updates | > 100/hour | > 500/hour |

---

## Final Design Specifications

This section contains the finalized design decisions for DDoS protection. These specifications are authoritative and supersede any conflicting information in earlier sections.

### IPv6 Rate Limiting (Final Design)

**Subnet-Based Limiting:**
- Rate limit per /64 subnet (NOT per /128 address)
- Optional /48 limiting for persistent attackers
- Per-subnet tracking with 1-hour sliding window

```go
const (
    IPv6RateLimitSubnet       = 64   // Default: /64 subnet
    IPv6EscalatedSubnet       = 48   // For persistent attackers: /48
    IPv6SubnetTrackingWindow  = 1 * time.Hour
)

// IPv6SubnetRateLimiter implements /64 and /48 subnet rate limiting
type IPv6SubnetRateLimiter struct {
    // Track per /64 subnet
    subnet64Limits map[string]*SubnetRateState // key: /64 prefix
    // Track per /48 for persistent attackers
    subnet48Limits map[string]*SubnetRateState // key: /48 prefix
    windowDuration time.Duration
    mu             sync.RWMutex
}

// GetSubnetKey extracts the rate limit key from an IPv6 address
func GetSubnetKey(ip net.IP, prefixLen int) string {
    ipv6 := ip.To16()
    if ipv6 == nil {
        return ip.String() // Fallback for IPv4
    }
    // Mask to specified prefix length
    mask := net.CIDRMask(prefixLen, 128)
    subnet := ipv6.Mask(mask)
    return fmt.Sprintf("%s/%d", subnet.String(), prefixLen)
}
```

### Rate Limit Windows (Final Design)

**Sliding Window Algorithm:**
- Window size: 1 second with 100ms granularity
- Algorithm: Sliding window (NOT fixed window)
- Burst handling: Allow 2x rate for 100ms, then enforce limit

```go
const (
    RateLimitWindowSize    = 1 * time.Second
    RateLimitGranularity   = 100 * time.Millisecond
    RateLimitBurstMultiple = 2.0
    RateLimitBurstWindow   = 100 * time.Millisecond
)

type SlidingWindowRateLimiter struct {
    windowSize   time.Duration
    granularity  time.Duration
    buckets      []int64        // Request counts per granularity bucket
    bucketIdx    int            // Current bucket index
    lastRotation time.Time
    maxRate      int64          // Requests per window
    burstRate    int64          // maxRate * BurstMultiple
    mu           sync.Mutex
}
```

### IP Reputation Bootstrap (Final Design)

**New IP Initial State:**
- Initial reputation: 0.50 (neutral)
- First 10 requests: Observed with standard limits
- Reputation adjusts based on behavior

```go
const (
    IPReputationInitial      = 0.50  // New IP starts neutral
    IPReputationObservation  = 10    // Requests before reputation adjusts
)

// NewIPState creates state for a previously unseen IP
func NewIPState(ip net.IP) *IPReputation {
    return &IPReputation{
        IP:              ip,
        Score:           IPReputationInitial, // 0.50 neutral
        FirstSeen:       time.Now(),
        LastUpdated:     time.Now(),
        TotalRequests:   0,
        GoodRequests:    0,
        BadRequests:     0,
        ObservationMode: true, // First 10 requests observed
    }
}
```

### IP Reputation Enhanced Verification (Final Design)

When Bloom filter lookups return borderline results (near the false positive threshold), secondary exact verification is performed using IP reputation weighting.

**Design Rationale:**
- Bloom filters have a non-zero false positive rate (0.1%)
- High-reputation IPs should not be penalized for false positives
- Secondary verification resolves ambiguous cases using exact lookups
- IP reputation weighting breaks ties in collision scenarios

```go
const (
    // Bloom filter borderline threshold for secondary verification
    BloomBorderlineThreshold = 0.8  // 80% of hash functions match = borderline

    // IP reputation weights for collision resolution
    HighReputationWeight     = 3.0  // High-rep IPs get benefit of doubt
    MediumReputationWeight   = 1.0  // Medium-rep IPs neutral
    LowReputationWeight      = 0.5  // Low-rep IPs stricter verification

    // Secondary verification cache
    ExactVerificationCacheSize = 100000  // Exact nonce verification cache
    ExactVerificationCacheTTL  = 30 * time.Minute
)

// EnhancedNonceVerifier combines Bloom filter with exact verification for edge cases
type EnhancedNonceVerifier struct {
    bloomFilter     *CountingBloomFilter    // Primary fast-path filter
    exactCache      *ExactNonceCache        // Secondary exact verification
    reputationStore *IPReputationStore      // For reputation-weighted decisions
    mu              sync.RWMutex

    // Metrics
    bloomHits        atomic.Uint64
    bloomMisses      atomic.Uint64
    exactVerifications atomic.Uint64
    falsePositivesSaved atomic.Uint64
}

// ExactNonceCache stores exact nonce values for secondary verification
type ExactNonceCache struct {
    entries   map[string]time.Time  // nonce -> expiry time
    mu        sync.RWMutex
    maxSize   int
    ttl       time.Duration
}

// VerifyNonce performs nonce replay check with reputation-weighted edge case handling
func (v *EnhancedNonceVerifier) VerifyNonce(
    nonce []byte,
    clientIP net.IP,
) (isReplay bool, err error) {
    // Step 1: Fast path - Bloom filter check
    if !v.bloomFilter.Contains(nonce) {
        // Definitely not seen before (no false negatives in Bloom filters)
        v.bloomMisses.Add(1)
        return false, nil
    }

    v.bloomHits.Add(1)

    // Step 2: Bloom filter says "maybe seen" - check match confidence
    matchConfidence := v.bloomFilter.MatchConfidence(nonce)

    // Step 3: If clearly above threshold, trust Bloom filter
    if matchConfidence >= 0.95 {
        return true, nil // High confidence replay
    }

    // Step 4: Borderline case - perform secondary exact verification
    if matchConfidence >= BloomBorderlineThreshold {
        v.exactVerifications.Add(1)

        // Check exact cache
        if v.exactCache.Contains(nonce) {
            return true, nil // Confirmed replay
        }

        // Get client IP reputation for weighted decision
        reputation, err := v.reputationStore.GetReputation(clientIP)
        if err != nil {
            // Default to strict verification on error
            return true, nil
        }

        // Apply reputation weighting
        adjustedConfidence := v.applyReputationWeight(matchConfidence, reputation.Score)

        if adjustedConfidence < BloomBorderlineThreshold {
            // High-reputation IP, likely false positive
            v.falsePositivesSaved.Add(1)
            log.Debug("bloom filter false positive avoided via reputation",
                "ip", clientIP,
                "reputation", reputation.Score,
                "rawConfidence", matchConfidence,
                "adjustedConfidence", adjustedConfidence)
            return false, nil
        }
    }

    return true, nil // Treat as replay
}

// applyReputationWeight adjusts Bloom filter confidence based on IP reputation
func (v *EnhancedNonceVerifier) applyReputationWeight(confidence float64, reputation float64) float64 {
    var weight float64
    switch {
    case reputation >= HighIPReputation:
        weight = HighReputationWeight
    case reputation >= MedIPReputation:
        weight = MediumReputationWeight
    default:
        weight = LowReputationWeight
    }

    // Higher weight = lower effective confidence (benefit of doubt)
    // Formula: adjusted = confidence / weight
    // High-rep (weight 3.0): 0.85 confidence -> 0.28 adjusted (passes)
    // Low-rep (weight 0.5): 0.85 confidence -> 1.70 adjusted (fails, capped at 1.0)
    adjusted := confidence / weight
    if adjusted > 1.0 {
        adjusted = 1.0
    }
    return adjusted
}

// RecordNonce adds a nonce to both Bloom filter and exact cache
func (v *EnhancedNonceVerifier) RecordNonce(nonce []byte) {
    v.bloomFilter.Add(nonce)
    v.exactCache.Add(nonce)
}

// ExactNonceCache methods
func NewExactNonceCache(maxSize int, ttl time.Duration) *ExactNonceCache {
    cache := &ExactNonceCache{
        entries: make(map[string]time.Time, maxSize),
        maxSize: maxSize,
        ttl:     ttl,
    }
    go cache.cleanupWorker()
    return cache
}

func (c *ExactNonceCache) Add(nonce []byte) {
    c.mu.Lock()
    defer c.mu.Unlock()

    key := string(nonce)

    // Evict if at capacity
    if len(c.entries) >= c.maxSize {
        c.evictOldest()
    }

    c.entries[key] = time.Now().Add(c.ttl)
}

func (c *ExactNonceCache) Contains(nonce []byte) bool {
    c.mu.RLock()
    defer c.mu.RUnlock()

    key := string(nonce)
    expiry, exists := c.entries[key]
    if !exists {
        return false
    }
    return time.Now().Before(expiry)
}

func (c *ExactNonceCache) evictOldest() {
    var oldestKey string
    var oldestTime time.Time

    for key, expiry := range c.entries {
        if oldestKey == "" || expiry.Before(oldestTime) {
            oldestKey = key
            oldestTime = expiry
        }
    }

    if oldestKey != "" {
        delete(c.entries, oldestKey)
    }
}

func (c *ExactNonceCache) cleanupWorker() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for key, expiry := range c.entries {
            if now.After(expiry) {
                delete(c.entries, key)
            }
        }
        c.mu.Unlock()
    }
}
```

#### Partition-Based Pollution Mitigation

Time-windowed partitioning limits the impact of filter pollution attacks:

```go
// BloomPollutionMitigation explains how partitioning prevents pollution attacks
//
// Attack Scenario: Attacker floods system with random nonces to fill Bloom filter,
// causing all future lookups to return false positives (100% false positive rate).
//
// Mitigation: 6 time-based partitions (10 minutes each)
// - Only current partition receives new insertions
// - Oldest partition is cleared every 10 minutes
// - Maximum pollution impact: 1/6 of total capacity
// - Full recovery time: 60 minutes (all partitions rotated)
//
// Memory Calculation:
// - Total budget: 100MB
// - Per-partition: 100MB / 6 = ~16.7MB
// - Counter positions per partition: 16.7MB * 2 (4-bit counters) = ~33M positions
// - At 0.1% FP rate with 7 hash functions: ~4.7M nonces per partition
// - Total capacity: ~28M nonces across all partitions
//
// Pollution Attack Analysis:
// - Attacker fills current partition with 4.7M garbage nonces
// - Impact: Current partition has ~10% false positive rate
// - After 10 minutes: Polluted partition rotates out
// - Other 5 partitions remain clean
// - Legitimate nonces in other partitions unaffected
```

### PoW Difficulty Scaling (Final Design)

**Per-IP Difficulty Escalation:**
- Double difficulty after each violation
- Maximum difficulty: 2^32 (for persistent attackers)
- Difficulty decay: Halve every hour of good behavior
- ASIC resistance: Use memory-hard PoW (Argon2id)

```go
const (
    PoWDifficultyEscalation = 2      // Double per violation
    PoWMaxDifficulty        = 32     // 2^32 maximum
    PoWDifficultyDecayHours = 1      // Halve every hour of good behavior
    PoWAlgorithm            = "argon2id" // Memory-hard for ASIC resistance
)

type PerIPPoWDifficulty struct {
    BaseDifficulty    uint8
    CurrentDifficulty uint8
    ViolationCount    uint32
    LastViolation     time.Time
    LastGoodBehavior  time.Time
}

// EscalateDifficulty doubles difficulty after a violation
func (d *PerIPPoWDifficulty) EscalateDifficulty() {
    d.ViolationCount++
    d.LastViolation = time.Now()
    newDiff := d.CurrentDifficulty * PoWDifficultyEscalation
    if newDiff > PoWMaxDifficulty {
        newDiff = PoWMaxDifficulty
    }
    d.CurrentDifficulty = uint8(newDiff)
}

// DecayDifficulty halves difficulty for each hour of good behavior
func (d *PerIPPoWDifficulty) DecayDifficulty() {
    hoursSinceViolation := time.Since(d.LastViolation).Hours()
    if hoursSinceViolation >= float64(PoWDifficultyDecayHours) {
        decaySteps := int(hoursSinceViolation / float64(PoWDifficultyDecayHours))
        for i := 0; i < decaySteps && d.CurrentDifficulty > d.BaseDifficulty; i++ {
            d.CurrentDifficulty /= 2
        }
        if d.CurrentDifficulty < d.BaseDifficulty {
            d.CurrentDifficulty = d.BaseDifficulty
        }
    }
}
```

### Work Pool Verification (Final Design)

**Redundant Verification:**
- 3 workers verify each PoW solution
- 2-of-3 agreement required for acceptance
- Disagreement: Flag all 3 workers for review
- Cross-check: 10% of all work randomly re-verified by trusted nodes

```go
const (
    PoWVerificationRedundancy = 3     // Workers per solution
    PoWVerificationQuorum     = 2     // Required agreement (2-of-3)
    PoWCrossCheckPercent      = 0.10  // 10% random re-verification
)

type PoWVerificationResult struct {
    SolutionID  [32]byte
    WorkerIDs   [3][32]byte
    Results     [3]bool      // true = valid, false = invalid
    Agreement   bool         // 2+ workers agree
    Flagged     bool         // Disagreement detected
    CrossCheck  bool         // Selected for trusted node re-verification
}

// VerifyPoWSolution distributes verification to 3 workers
func (wp *WorkPool) VerifyPoWSolution(solution *PoWSolution) (*PoWVerificationResult, error) {
    workers := wp.SelectVerifiers(PoWVerificationRedundancy)
    
    results := make([]bool, PoWVerificationRedundancy)
    var wg sync.WaitGroup
    
    for i, worker := range workers {
        wg.Add(1)
        go func(idx int, w *Worker) {
            defer wg.Done()
            results[idx] = w.VerifySolution(solution)
        }(i, worker)
    }
    wg.Wait()
    
    // Count agreements
    validCount := 0
    for _, r := range results {
        if r {
            validCount++
        }
    }
    
    result := &PoWVerificationResult{
        SolutionID: solution.ChallengeID,
        Agreement:  validCount >= PoWVerificationQuorum || validCount == 0,
    }
    copy(result.Results[:], results)
    
    // Flag for review if disagreement
    if validCount > 0 && validCount < PoWVerificationRedundancy {
        result.Flagged = true
        wp.FlagWorkersForReview(workers)
    }
    
    // Random cross-check selection
    if rand.Float64() < PoWCrossCheckPercent {
        result.CrossCheck = true
    }
    
    return result, nil
}
```

### Threat Intelligence (Final Design)

**Reporter Reputation Weighting:**
- High-rep reporter weight: 3x
- Low-rep reporter weight: 0.5x
- TPM attestation required: Report must include TPM quote of observed behavior

**Escalating Expiry:**
| Offense | Ban Duration |
|---------|-------------|
| First | 24 hours |
| Second | 7 days |
| Third | 30 days |
| Fourth+ | Permanent |

**Repeat Offender Detection:**
- Track offense history in DHT
- Key: `threat:history:<ip-hash>`

```go
const (
    ThreatReportWeightHigh = 3.0  // High-rep reporter
    ThreatReportWeightLow  = 0.5  // Low-rep reporter
)

var ThreatBanDurations = []time.Duration{
    24 * time.Hour,       // First offense
    7 * 24 * time.Hour,   // Second offense
    30 * 24 * time.Hour,  // Third offense
    0,                    // Fourth+: permanent (0 = no expiry)
}

type ThreatReport struct {
    ReporterID       [32]byte
    ReporterRep      float64       // Reputation score of reporter
    ThreatType       ThreatType
    Indicator        string
    Evidence         []byte
    TPMQuote         []byte        // REQUIRED: TPM attestation of observed behavior
    TPMNonce         [32]byte      // Freshness nonce for TPM quote
    Timestamp        time.Time
    Signature        []byte
}

// GetReportWeight returns the weight based on reporter reputation
func (r *ThreatReport) GetReportWeight() float64 {
    if r.ReporterRep >= 0.8 {
        return ThreatReportWeightHigh // 3x weight
    }
    if r.ReporterRep <= 0.4 {
        return ThreatReportWeightLow // 0.5x weight
    }
    return 1.0 // Standard weight
}

// GetBanDuration returns ban duration based on offense count
func GetBanDuration(offenseCount int) time.Duration {
    if offenseCount >= len(ThreatBanDurations) {
        return 0 // Permanent ban
    }
    return ThreatBanDurations[offenseCount]
}
```

### Application-Layer Protection (Final Design)

**Protocol-Specific Limits:**

| Attack Vector | Limit | Description |
|---------------|-------|-------------|
| DHT lookup amplification | Max 3 recursive hops | Per query |
| Certificate request flooding | 10 requests/minute | Per node |
| DKG session initiation | 1 session/hour | Per node |

```go
const (
    DHTMaxRecursiveHops     = 3
    CertRequestsPerMinute   = 10
    DKGSessionsPerHour      = 1
)

type ApplicationLayerLimits struct {
    DHTHopLimit         int
    CertRequestLimit    int
    CertRequestWindow   time.Duration
    DKGSessionLimit     int
    DKGSessionWindow    time.Duration
}

var DefaultAppLimits = ApplicationLayerLimits{
    DHTHopLimit:       DHTMaxRecursiveHops,
    CertRequestLimit:  CertRequestsPerMinute,
    CertRequestWindow: time.Minute,
    DKGSessionLimit:   DKGSessionsPerHour,
    DKGSessionWindow:  time.Hour,
}
```

### Slow-Rate Attack Detection (Final Design)

**Request Complexity Scoring:**
- Track request complexity score (CPU/memory cost)
- Slow requests (>1s processing) count as 10 requests for rate limiting
- Malformed request penalty: -0.05 reputation per occurrence

```go
const (
    SlowRequestThreshold      = 1 * time.Second
    SlowRequestMultiplier     = 10  // Count as 10 requests
    MalformedRequestPenalty   = -0.05
)

type RequestComplexityTracker struct {
    processingTimes map[[32]byte]time.Duration // Request ID -> processing time
    complexityCosts map[[32]byte]int64         // Request ID -> CPU/memory cost
    mu              sync.RWMutex
}

// ScoreRequest calculates the rate limit cost of a request
func (t *RequestComplexityTracker) ScoreRequest(requestID [32]byte, duration time.Duration) int64 {
    if duration >= SlowRequestThreshold {
        return SlowRequestMultiplier // Counts as 10 requests
    }
    return 1 // Standard request
}

// PenalizeMalformed applies reputation penalty for malformed requests
func (r *IPReputation) PenalizeMalformed() {
    r.Score += MalformedRequestPenalty // -0.05
    if r.Score < 0 {
        r.Score = 0
    }
    r.BadRequests++
}
```

---

## Related Documents

- [02-network-architecture.md](02-network-architecture.md) - Gateway mesh and network topology
- [03-security-trust.md](03-security-trust.md) - Security constants and TPM requirements
- [09-defense-reputation.md](09-defense-reputation.md) - Node reputation and collaborative defense

---

**Document Version**: 1.4
**Last Updated**: 2026-01-10
**Canonical For**: Network-wide DDoS protection, rate limiting, proof-of-work challenges, threat intelligence

**Version 1.4 Changes** (COUNTING BLOOM FILTER & BGP SECURITY):
- Added Counting Bloom Filter for nonce replay prevention (replaces standard Bloom filter)
  - Supports element removal via 4-bit counters
  - Time-based partitioning: 6 partitions x 10-minute windows
  - Target false positive rate: 0.1% (0.001)
  - Memory budget: 100MB maximum
  - Prevents filter pollution attacks via partition rotation
- Added Rate Limit State Management section
  - Maximum 1,000,000 tracked IP addresses
  - LRU eviction policy with 95% pre-emptive eviction threshold
  - Memory budget: 256MB maximum
  - Prevents memory exhaustion attacks
- Added BGP Security and Route Validation section
  - RPKI validation required for BGP announcements
  - Multi-gateway route verification: minimum 3 gateways
  - Regional /40 aggregation for route announcements
  - Malicious gateway detection and removal
- Added IP Reputation Enhanced Verification
  - Secondary exact verification for Bloom filter borderline cases
  - IP reputation weighting for collision resolution (high-rep 3x, low-rep 0.5x)
  - Partition-based pollution mitigation analysis
- Added Quick Reference tables for Rate Limit State Management and Nonce Replay Prevention

**Version 1.3 Changes** (CHALLENGE POOL & IP SPOOFING SPECIFICATIONS):
- Enhanced Quick Reference table with complete Challenge Pool specifications
- Added Memory Budget calculation (1M challenges x 128 bytes = ~100MB)
- Added explicit Solution Deadline specification (must submit within 5 min TTL)
- Added IP Deduplication rules (same IP can have up to 3 pending challenges)
- Added Pool Full Behavior specification (pre-emptive eviction at 95%, reject at 100%)
- Added Eviction Algorithm specification (LRU - Least Recently Used)
- Added complete IP Spoofing Bypass Protection section
- Added Asymmetric Routing Validation with RTT ratio thresholds (5x warn, 10x reject, 20x block)
- Added Bidirectional Connectivity Verification (5s timeout, 3 attempts max)
- Added verification methods: TCP handshake, PoW challenge, QUIC token, crypto nonce
- Added IP Spoofing Protection Quick Reference table
- Added integrated IP Spoofing Protection Flow diagram

**Version 1.2 Changes** (FINAL DESIGN):
- Added IPv6 rate limiting: Per /64 subnet (not /128), optional /48 for persistent attackers
- Added sliding window rate limiting: 1s window with 100ms granularity, 2x burst for 100ms
- Added IP reputation bootstrap: Initial score 0.50 (neutral), first 10 requests observed
- Added PoW difficulty scaling: Double per violation, max 2^32, halve hourly on good behavior
- Added ASIC resistance: Argon2id memory-hard PoW
- Added work pool verification: 3 workers verify, 2-of-3 agreement, 10% cross-check by trusted nodes
- Added threat intelligence weighting: High-rep 3x, low-rep 0.5x, TPM attestation required
- Added escalating ban expiry: 24h, 7d, 30d, permanent
- Added repeat offender tracking in DHT
- Added application-layer limits: DHT 3 hops max, certs 10/min, DKG 1/hour
- Added slow-rate attack detection: >1s requests count as 10x, malformed penalty -0.05 rep

**Version 1.1 Changes**:
- Added comprehensive PoW Challenge Pool bounds (1M max, 95% pre-emptive eviction, 30s cleanup)
- Added pre-allocated fixed-size ChallengeSlot structure with lifecycle fields
- Added PoW difficulty pre-filter for fast rejection of invalid solutions
- Enhanced Flow State Tracker with sort-by-activity eviction
- Added per-transport rate limits (TCP, QUIC, UDP, gRPC, REST, Unix Socket)
- Added TOCTOU prevention pattern for rate limit implementation
- Enhanced Threat Intelligence with LastUpdated reset on new reports
- Added Quick Reference tables for all resource bounds

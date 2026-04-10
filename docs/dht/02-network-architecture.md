# Network Architecture

## Overview

A massively scalable **hierarchical Kademlia DHT** supporting billions of IoT nodes with **publicly routable IPv6** (2602:F5BB::/36), **distributed gateway architecture**, **multi-path routing**, and **distributed DDoS protection**.

> **Cross-References:**
> - Security parameters and cryptographic constants: See [03-security-trust.md](03-security-trust.md)
> - Gateway promotion requirements and reputation thresholds: See [09-defense-reputation.md](09-defense-reputation.md)

---

## Design Principles

- **Fully decentralized:** No fixed infrastructure, emergent hierarchy
- **Publicly routable IPv6:** Global internet can reach P2P nodes
- **Distributed routing:** Traffic routes via backbone OR P2P gateways OR direct
- **Leverage all nodes:** Every node's internet connection contributes to network capacity
- **DDoS protection:** Attack traffic distributed across thousands of gateway nodes
- **Self-organizing:** Nodes promote/demote based on reputation automatically
- **Scalable:** O(log n) DHT lookups, efficient at billion+ node scale

---

## Network Topology

### Three-Tier Emergent Hierarchy

**NOT fixed tiers - nodes move between tiers based on reputation!**

```
+-------------------------------------------------------------+
| TIER 1: HIGH-REPUTATION NODES (Emergent Backbone)           |
| - Top 1% reputation nodes                                   |
| - Act as regional coordinators automatically                |
| - Coordinate cross-region routing                           |
| - Participate in global DHT                                 |
| - ANY node can become Tier 1 with high reputation           |
+-------------------------------------------------------------+
                          |
                          v
+-------------------------------------------------------------+
| TIER 2: REGIONAL HUBS (Mid-Reputation Nodes)                |
| - Good uptime (95%+), bandwidth (100 Mbps+)                 |
| - Participate fully in regional DHT                         |
| - Act as gateways for public internet traffic               |
| - Relay traffic for lower-tier nodes                        |
| - Promotion: Leaf -> Hub when reputation increases          |
+-------------------------------------------------------------+
                          |
                          v
+-------------------------------------------------------------+
| TIER 3: LEAF NODES (All Nodes Start Here)                   |
| - IoT devices, new nodes, low-bandwidth nodes               |
| - Lightweight DHT participation                             |
| - Connect to regional hubs                                  |
| - Can promote to Tier 2 with good reputation                |
+-------------------------------------------------------------+
```

**Key Property:** No pre-designated nodes! Tiers emerge from reputation.

> **See Also:** [09-defense-reputation.md](09-defense-reputation.md) for tier promotion thresholds and reputation requirements.

---

## IP Address Strategy

### Infrastructure Overview

**BGP ASN:** (Your existing ASN)

**IPv4 Pool:** 23.143.36.0/24 (254 usable addresses)
- Reserved for gateway nodes
- Announced via Go BGP gateway nodes
- Used for public internet access points

**IPv6 Pool:** 2602:F5BB::/36 (4.7 quintillion addresses!)
- Announced via Go BGP gateway nodes
- Assigned to P2P nodes (publicly routable)
- Hierarchical allocation:
  ```
  2602:F5BB:RRRR:SSSS:HHHH:HHHH:HHHH:HHHH/64

  RRRR (16 bits) = Region ID (65,536 regions possible)
  SSSS (16 bits) = Subnet within region (65,536 subnets/region)
  HHHH:HHHH:HHHH:HHHH (64 bits) = Host ID
  ```

**Example Allocation:**
```
Region 1 (North America East): 2602:F5BB:0001::/48
Region 2 (North America West): 2602:F5BB:0002::/48
Region 3 (Europe West): 2602:F5BB:0003::/48
...
Region 65535: 2602:F5BB:FFFF::/48
```

### IPv6 Assignment Process

```
New node joins:
1. Node connects to any existing node (bootstrap)
2. Node requests IPv6 allocation
3. Regional coordinator queries DHT for available addresses in region
4. Assigns next available: 2602:F5BB:RRRR:SSSS::XXXX using CAS (compare-and-swap)
5. Verifies address not in use (collision detection)
6. Publishes to DHT: "ipv6-{address}" -> node_id with 30-day lease
7. Node configures interface
8. Node performs TPM attestation
9. Node receives certificate (with IPv6 in SAN)
10. Node announces to DHT (overlay + underlay addresses)
11. Node stores assigned address in TPM-sealed config (persistence)

IPv6 is now globally routable!
- Internet can reach 2602:F5BB:RRRR:SSSS::XXXX
- Default route: via Go BGP gateway nodes (backbone speakers)
- Alternate routes: via P2P gateways (distributed)
```

**IPv6 Address Allocation - FINAL DESIGN:**

**Collision Handling:**
- Regional coordinator uses DHT CAS (compare-and-swap) for atomic allocation
- Before assigning, coordinator verifies address is not in use via DHT query
- Collision detection: If address shows existing binding, coordinator selects next available
- Allocation is atomic: publish succeeds only if key does not exist

**Address Lease Management:**
- Lease duration: 30 days from assignment
- Renewal window: Last 7 days of lease (days 23-30)
- Auto-renewal: Node renews lease every 7 days via DHT update
- Lease expiration: If node fails to renew, address returns to pool after 30 days
- Grace period: 48 hours after expiration before address is reassigned

**Address Persistence:**
- Assigned IPv6 stored in TPM-sealed configuration file
- Survives node restarts without re-allocation
- On restart: Node attempts to renew existing lease before requesting new address
- If lease expired during downtime: Request new address through normal flow

**Region Determination:**
- Primary method: IP geolocation (GeoIP2 database)
- Fallback: RTT measurement to regional coordinators (select lowest latency)
- Manual override: Node operator can specify preferred region in config
- Region assignment is permanent unless manually changed

**Multi-homed Nodes:**
- Nodes with multiple internet connections select primary region based on lowest latency to regional coordinator
- Secondary connections can be registered as alternate paths
- Primary region determines IPv6 allocation pool

```go
// IPv6 allocation with collision handling
type IPv6Allocator struct {
    dht          DHT
    region       RegionID
    leaseDuration time.Duration // 30 days
    renewalWindow time.Duration // 7 days
}

func (a *IPv6Allocator) AllocateIPv6(nodeID NodeID) (net.IP, error) {
    // Step 1: Check if node has existing lease
    existingKey := "ipv6-lease:" + nodeID.String()
    if lease, err := a.dht.Get(existingKey); err == nil {
        if !lease.IsExpired() {
            return lease.Address, nil // Reuse existing
        }
    }

    // Step 2: Find next available address in region pool
    for attempt := 0; attempt < 100; attempt++ {
        candidate := a.generateCandidateAddress()

        // Step 3: Attempt CAS allocation
        key := "ipv6-allocated:" + candidate.String()
        value := nodeID.String()

        // CAS: only succeed if key does not exist
        if err := a.dht.PutIfAbsent(key, value, 30*24*time.Hour); err == nil {
            // Success! Publish lease record
            lease := &IPv6Lease{
                Address:   candidate,
                NodeID:    nodeID,
                AllocatedAt: time.Now(),
                ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
                Region:    a.region,
            }
            a.dht.Put(existingKey, lease, 30*24*time.Hour)
            return candidate, nil
        }
        // CAS failed - address in use, try next
    }

    return nil, ErrNoAvailableAddresses
}

// Region determination with manual override
func DetermineRegion(nodePublicIP net.IP, configOverride string) (RegionID, error) {
    // Manual override takes precedence
    if configOverride != "" {
        return parseRegionID(configOverride)
    }

    // Geographic determination via GeoIP
    location, err := geolocate(nodePublicIP)
    if err == nil {
        return mapLocationToRegion(location), nil
    }

    // Fallback: RTT-based selection
    coordinators := getRegionalCoordinators()
    lowestLatency := time.Hour
    selectedRegion := RegionID(0)

    for region, coordinator := range coordinators {
        start := time.Now()
        if err := ping(coordinator); err == nil {
            latency := time.Since(start)
            if latency < lowestLatency {
                lowestLatency = latency
                selectedRegion = region
            }
        }
    }

    if selectedRegion == 0 {
        return 0, ErrRegionDeterminationFailed
    }
    return selectedRegion, nil
}
```

---

## BGP Configuration

### Go BGP Gateway Architecture

The trusted DHT uses native Go gateway nodes as BGP speakers, eliminating the need for external hardware routers. Gateway nodes use the `gobgp` library to implement full BGP protocol support.

#### Speaker Roles

| Role | Description |
|------|-------------|
| `backbone` | Core BGP speaker, announces aggregate prefixes (2602:F5BB::/36) to ISPs |
| `datacenter` | Datacenter gateway with direct eBGP to local ISP, announces /48 prefixes |
| `coordinator` | Route coordination node (signs route announcements) |

#### High Availability Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                   BGP HA CLUSTER TOPOLOGY                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                        ┌─────────────┐                          │
│                        │   ISP A     │                          │
│                        │  (Primary)  │                          │
│                        └──────┬──────┘                          │
│                               │                                  │
│       ┌───────────────────────┼───────────────────────┐         │
│       │                       │                       │         │
│  ┌────▼────┐            ┌────▼────┐            ┌────▼────┐     │
│  │ Speaker │◄──iBGP────►│ Speaker │◄──iBGP────►│ Speaker │     │
│  │   #1    │            │   #2    │            │   #3    │     │
│  │ (Active)│            │(Standby)│            │(Standby)│     │
│  └────┬────┘            └────┬────┘            └────┬────┘     │
│       │                       │                       │         │
│       └───────────────────────┴───────────────────────┘         │
│                               │                                  │
│                      ┌────────▼────────┐                        │
│                      │  DHT Network    │                        │
│                      │  (Event Bus)    │                        │
│                      └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

#### Route Announcement Workflow

```
1. DHT Event: Gateway Promotion
   ↓
2. Controller validates eligibility:
   - Reputation >= 0.85
   - Uptime >= 95%
   - Age >= 90 days
   - TPM attestation current
   ↓
3. Allocate /48 prefix from pool (2602:F5BB:XXXX::/48)
   ↓
4. Request coordinator signatures (3+ required)
   ↓
5. Announce route via BGP speaker
   ↓
6. Publish gateway info to DHT
```

**BGP Route Withdrawal - FINAL DESIGN:**

Routes must be withdrawn when a gateway is demoted or becomes unavailable to prevent traffic blackholing.

**Withdrawal Triggers:**
- Gateway demotion (reputation drops below 0.85)
- Node shutdown (graceful or ungraceful)
- Reputation drops below 0.85 threshold
- Stake slashing event
- Manual operator intervention

**Withdrawal Protocol:**
- BGP UPDATE message with route withdrawal
- Propagation delay: 30 seconds (standard BGP hold timer)
- Graceful shutdown: Explicitly withdraw routes before terminating
- Ungraceful shutdown: Stale route timeout of 5 minutes

**Stale Route Handling:**
- If gateway becomes unreachable without graceful withdrawal:
  - Monitor BGP peer session state
  - After 5-minute timeout, automatic route withdrawal by controller
  - Other BGP speakers detect peer down and withdraw routes
- Route reflectors propagate withdrawal to all peers

**BGP Flap Dampening:**
- Detects rapid route announcements/withdrawals (flapping)
- Trigger: 3 or more withdrawals within 1 hour
- Action: Suppress route announcements for 15 minutes
- After suppression period: Allow re-announcement with exponential backoff
- Maximum suppression: 60 minutes

```go
// BGP route withdrawal handler
type BGPRouteManager struct {
    speaker        *BGPSpeaker
    flapDampening  *FlapDampener
    withdrawalLog  *WithdrawalLog
}

// WithdrawRoute handles route withdrawal with dampening
func (m *BGPRouteManager) WithdrawRoute(
    gatewayID NodeID,
    prefix netip.Prefix,
    reason WithdrawalReason,
) error {
    // Check flap dampening state
    if m.flapDampening.IsSuppressed(gatewayID, prefix) {
        return ErrRouteSuppressed{
            Gateway: gatewayID,
            Prefix:  prefix,
            Until:   m.flapDampening.SuppressionEndTime(gatewayID, prefix),
        }
    }

    // Record withdrawal event
    m.flapDampening.RecordWithdrawal(gatewayID, prefix)

    // Send BGP UPDATE with route withdrawal
    if err := m.speaker.WithdrawRoute(prefix); err != nil {
        return fmt.Errorf("BGP withdrawal failed: %w", err)
    }

    // Log withdrawal for audit
    m.withdrawalLog.Record(&WithdrawalEvent{
        GatewayID:  gatewayID,
        Prefix:     prefix,
        Reason:     reason,
        Timestamp:  time.Now(),
        Graceful:   reason != WithdrawalReasonCrash,
    })

    return nil
}

// FlapDampener prevents route oscillation
type FlapDampener struct {
    history map[RouteKey]*FlapHistory
    mu      sync.RWMutex
}

type FlapHistory struct {
    Withdrawals    []time.Time
    SuppressedUntil time.Time
}

func (fd *FlapDampener) RecordWithdrawal(gateway NodeID, prefix netip.Prefix) {
    fd.mu.Lock()
    defer fd.mu.Unlock()

    key := RouteKey{Gateway: gateway, Prefix: prefix}
    if _, exists := fd.history[key]; !exists {
        fd.history[key] = &FlapHistory{}
    }

    history := fd.history[key]
    history.Withdrawals = append(history.Withdrawals, time.Now())

    // Check for flapping (3+ withdrawals in 1 hour)
    recent := fd.countRecentWithdrawals(history.Withdrawals, 1*time.Hour)
    if recent >= 3 {
        // Suppress for 15 minutes
        history.SuppressedUntil = time.Now().Add(15 * time.Minute)
        log.Warn("BGP route flapping detected, suppressing",
            "gateway", gateway,
            "prefix", prefix,
            "withdrawals", recent,
            "suppressedUntil", history.SuppressedUntil)
    }
}
```

#### BGP Session Configuration

```go
// Example BGP configuration
type BGPConfig struct {
    LocalAS     uint32            // e.g., 65001
    RouterID    string            // e.g., "23.143.36.1"
    Role        SpeakerRole       // backbone, datacenter, coordinator

    Peers []PeerConfig{
        {
            Address:   "198.51.100.1",     // ISP peer
            RemoteAS:  64500,
            Type:      "ebgp",
            MD5Key:    "secret_key",
            Families:  []string{"ipv4", "ipv6", "flowspec"},
        },
    }

    Security: SecurityConfig{
        RPKI:     true,           // Route origin validation
        FlowSpec: true,           // DDoS mitigation
    }
}
```

**Result:**
- Global BGP table contains: 2602:F5BB::/36 -> {YOUR_ASN}
- All internet traffic to 2602:F5BB::* routes to Go BGP gateway nodes
- Gateway nodes forward to appropriate node via P2P mesh

### BGP Route Aggregation

At scale, individual gateway route announcements would overwhelm global BGP tables. The network uses regional prefix aggregation to minimize BGP table impact while maintaining routing granularity.

#### Regional Aggregation Strategy

Instead of announcing individual /48 prefixes per gateway, the network aggregates routes at the regional level using /40 prefixes.

```go
// pkg/bgp/aggregation.go

// RegionalAggregation handles BGP route consolidation
type RegionalAggregation struct {
    basePrefix        netip.Prefix  // 2602:F5BB::/36
    aggregationLevel  int           // /40 for regional aggregates
    regions           map[RegionID]*RegionalPrefix
}

const (
    // Aggregation reduces BGP table entries from 10K routes to ~16 routes
    AggregationPrefixLen = 40    // Regional /40 aggregates
    GatewayPrefixLen     = 48    // Individual gateway /48s (internal only)
)

// RegionalPrefix represents an aggregated regional route
type RegionalPrefix struct {
    RegionID       RegionID
    AggregateRoute netip.Prefix   // e.g., 2602:F5BB:0100::/40
    GatewayRoutes  []netip.Prefix // Internal /48 routes
    PrimaryGateway NodeID         // Primary BGP speaker for region
    BackupGateways []NodeID       // Backup speakers for failover
}

// BGP Table Impact Analysis
//
// Without aggregation (per-gateway /48):
//   - 10,000 gateways = 10,000 BGP routes
//   - Global BGP table impact: Significant
//   - ISP filter risk: High (too many specifics)
//
// With aggregation (regional /40):
//   - 16 regions = 16 BGP routes
//   - Global BGP table impact: Minimal
//   - ISP filter risk: Low (reasonable prefix count)
//
// Allocation scheme:
//   2602:F5BB::/36 = Full allocation
//   2602:F5BB:0000::/40 = Region 0 (North America East)
//   2602:F5BB:0100::/40 = Region 1 (North America West)
//   2602:F5BB:0200::/40 = Region 2 (Europe West)
//   ...
//   2602:F5BB:0F00::/40 = Region 15 (Asia Pacific South)

func (ra *RegionalAggregation) CalculateRegionalPrefix(regionID RegionID) netip.Prefix {
    // Base: 2602:F5BB::/36
    // Region offset in 4th nibble group: 2602:F5BB:XX00::/40
    baseBytes := ra.basePrefix.Addr().As16()
    baseBytes[4] = byte(regionID << 4)  // Region in upper nibble
    addr := netip.AddrFrom16(baseBytes)
    return netip.PrefixFrom(addr, ra.aggregationLevel)
}
```

#### Internal Routing via IGP

Within each region, traffic is routed to specific gateways using Interior Gateway Protocol (OSPF or IS-IS) rather than external BGP.

```go
// pkg/bgp/internal_routing.go

// InternalRoutingConfig configures IGP for intra-region routing
type InternalRoutingConfig struct {
    Protocol       IGPProtocol  // OSPF or IS-IS
    AreaID         uint32       // OSPF area or IS-IS level
    MetricType     string       // "bandwidth" or "latency"
    HelloInterval  time.Duration
    DeadInterval   time.Duration
}

type IGPProtocol string

const (
    IGPProtocolOSPF  IGPProtocol = "ospf"
    IGPProtocolISIS  IGPProtocol = "is-is"
)

// IGPRouteDistributor announces internal routes via OSPF/IS-IS
type IGPRouteDistributor struct {
    config        *InternalRoutingConfig
    ospfSpeaker   *OSPFSpeaker
    isisSpeaker   *ISISSpeaker
    gatewayRoutes map[NodeID]netip.Prefix
}

// AnnounceGatewayRoute distributes /48 gateway route internally
func (d *IGPRouteDistributor) AnnounceGatewayRoute(
    gatewayID NodeID,
    prefix netip.Prefix,
    metric uint32,
) error {
    // Internal /48 routes are NOT announced to external BGP
    // Only distributed within region via IGP

    switch d.config.Protocol {
    case IGPProtocolOSPF:
        return d.ospfSpeaker.AnnounceRoute(prefix, metric)
    case IGPProtocolISIS:
        return d.isisSpeaker.AnnounceRoute(prefix, metric)
    default:
        return ErrUnsupportedIGP
    }
}

// Traffic flow example:
// 1. External traffic arrives at regional aggregate prefix (2602:F5BB:0100::/40)
// 2. Regional border gateway receives traffic
// 3. IGP routing directs to specific gateway based on /48 destination
// 4. Gateway forwards to target node via P2P mesh
```

#### RPKI Validation

All BGP route announcements require Resource Public Key Infrastructure (RPKI) validation to prevent route hijacking.

```go
// pkg/bgp/rpki.go

// RPKIValidator validates route origin authorization
type RPKIValidator struct {
    rtrClient      *RTRClient       // RPKI-to-Router protocol client
    validators     []string         // RPKI validator endpoints
    refreshInterval time.Duration   // ROA refresh interval
    roaCache       *ROACache        // Cached Route Origin Authorizations
}

const (
    RPKIRefreshInterval = 30 * time.Minute
    MinRPKIValidators   = 2  // Require at least 2 validators
)

// ValidateRouteAnnouncement checks RPKI validity before announcing
func (v *RPKIValidator) ValidateRouteAnnouncement(
    prefix netip.Prefix,
    originASN uint32,
) (*RPKIValidationResult, error) {
    // Query ROA cache
    roas := v.roaCache.GetROAsForPrefix(prefix)
    if len(roas) == 0 {
        return &RPKIValidationResult{
            Status: RPKIStatusNotFound,
            Reason: "no ROA found for prefix",
        }, nil
    }

    // Check if origin ASN is authorized
    for _, roa := range roas {
        if roa.ASN == originASN && roa.MaxLength >= prefix.Bits() {
            return &RPKIValidationResult{
                Status: RPKIStatusValid,
                ROA:    roa,
            }, nil
        }
    }

    return &RPKIValidationResult{
        Status: RPKIStatusInvalid,
        Reason: fmt.Sprintf("ASN %d not authorized for prefix %s", originASN, prefix),
    }, nil
}

// RPKIValidationResult indicates route validity
type RPKIValidationResult struct {
    Status RPKIStatus
    Reason string
    ROA    *RouteOriginAuthorization
}

type RPKIStatus string

const (
    RPKIStatusValid    RPKIStatus = "valid"
    RPKIStatusInvalid  RPKIStatus = "invalid"
    RPKIStatusNotFound RPKIStatus = "not_found"
)
```

#### Multi-Gateway Route Verification

Route announcements require verification from multiple gateways before propagation to prevent single-point-of-compromise attacks.

```go
// pkg/bgp/multi_gateway_verify.go

// MultiGatewayVerifier requires consensus for route announcements
type MultiGatewayVerifier struct {
    minVerifiers     int           // Minimum 3 gateway verifications
    verificationTTL  time.Duration // Verification window
    verifications    map[string]*RouteVerification
}

const (
    MinRouteVerifiers       = 3     // At least 3 gateways must verify
    RouteVerificationWindow = 5 * time.Minute
)

// VerifyRouteAnnouncement collects multi-gateway attestation
func (v *MultiGatewayVerifier) VerifyRouteAnnouncement(
    ctx context.Context,
    announcement *RouteAnnouncement,
) (*VerificationResult, error) {
    verificationID := computeVerificationID(announcement)

    // Check existing verifications
    existing := v.verifications[verificationID]
    if existing != nil && len(existing.Verifiers) >= v.minVerifiers {
        return &VerificationResult{
            Verified:   true,
            Verifiers:  existing.Verifiers,
            Timestamp:  existing.Timestamp,
        }, nil
    }

    // Request verification from regional gateways
    gateways := selectVerificationGateways(announcement.Region, 5)
    var verifiers []NodeID

    for _, gw := range gateways {
        // Each gateway independently verifies:
        // 1. Announcing node is legitimate gateway
        // 2. Prefix is correctly allocated to region
        // 3. RPKI ROA exists and is valid
        // 4. No conflicting announcements detected
        verified, err := gw.VerifyRoute(ctx, announcement)
        if err != nil {
            continue
        }
        if verified {
            verifiers = append(verifiers, gw.NodeID)
        }

        if len(verifiers) >= v.minVerifiers {
            break
        }
    }

    if len(verifiers) < v.minVerifiers {
        return &VerificationResult{
            Verified: false,
            Reason:   fmt.Sprintf("insufficient verifiers: %d/%d", len(verifiers), v.minVerifiers),
        }, nil
    }

    // Store verification for future reference
    v.verifications[verificationID] = &RouteVerification{
        Announcement: announcement,
        Verifiers:    verifiers,
        Timestamp:    time.Now(),
    }

    return &VerificationResult{
        Verified:  true,
        Verifiers: verifiers,
        Timestamp: time.Now(),
    }, nil
}
```

#### BGP Aggregation Summary

| Aspect | Per-Gateway Approach | Aggregated Approach |
|--------|---------------------|---------------------|
| BGP routes announced | 10,000 (per gateway /48) | 16 (regional /40) |
| Global BGP table impact | High | Minimal |
| ISP filtering risk | High | Low |
| Internal routing | N/A | OSPF/IS-IS for /48s |
| RPKI validation | Required | Required |
| Multi-gateway verification | 3 minimum | 3 minimum |

#### Datacenter Gateway (More Specific Routes)

Datacenter gateways announce more specific /48 prefixes:

```go
// Datacenter gateway announces its allocated /48
announcement := &RouteAnnouncement{
    GatewayID: nodeID,
    Prefix:    "2602:F5BB:0001::/48",  // Allocated prefix
    NextHop:   gatewayPublicIP,
}

// Collect 3+ coordinator signatures
sigs, _ := coordinator.CollectSignatures(ctx, announcement)

// Announce via BGP
speaker.AnnounceRoute(ctx, announcement)

// BGP prefers more specific routes:
// Traffic to 2602:F5BB:0001::1234 goes directly to gateway
```

#### Residential Gateway Tunnels

```bash
# Residential gateways use WireGuard tunnels
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.1.2/24
PrivateKey = {gateway_private_key}
ListenPort = 51820

[Peer]
PublicKey = {backbone_vpn_public_key}
Endpoint = vpn.yourdomain.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## Routing Architecture

### Multi-Path Routing

**Traffic to 2602:F5BB:0001::1234 can arrive via MULTIPLE paths:**

```
+-------------------------------------------------------------+
| PATH 1: Via Backbone (Default BGP Route)                    |
|                                                             |
| Internet -> BGP routing -> Go BGP Gateways -> Node          |
|                                                             |
| - Default route (BGP advertised globally)                   |
| - Always available (infrastructure)                         |
| - Premium tier uses this (paid service)                     |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| PATH 2: Via P2P Gateway Nodes (Distributed)                 |
|                                                             |
| Internet -> Gateway Node -> P2P Mesh -> Target Node         |
|                                                             |
| - Gateway = any P2P node with public IP                     |
| - Traffic routed through P2P overlay mesh                   |
| - Free tier uses this                                       |
| - DDoS protection: attack diluted across 1000s nodes        |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
| PATH 3: Direct to Node's ISP (If Node Has Public IP)        |
|                                                             |
| Internet -> Target Node's ISP -> Target Node                |
|                                                             |
| - Node has public IPv6 from their own ISP also              |
| - Fastest (no intermediaries)                               |
| - Limited: only works if node publicly accessible           |
+-------------------------------------------------------------+
```

**Routing Decision (Client-Side):**
```
Client wants to reach 2602:F5BB:0001::1234

Option 1: Standard BGP routing
- Client's OS does normal IPv6 routing
- BGP tables route to Go BGP gateway nodes
- Gateway nodes forward to target via P2P mesh

Option 2: P2P-aware client (browser extension, native app)
- Client queries DHT for node information
- DHT returns: gateway nodes in client's region
- Client connects to nearest gateway
- Gateway routes via P2P mesh to target
- Bypasses backbone entirely

Option 3: Direct connection (if node publicly accessible)
- DHT also returns node's own public IP (if available)
- Client can connect directly
- Fastest path
```

---

## DHT Architecture - Hierarchical Kademlia

### Two-Level DHT

**Global DHT:**
- **Node IDs:** 160-bit (SHA-256 truncated)
- **Participants:** Top 10% reputation nodes (coordinators, hubs)
- **Stores:** Regional metadata, cross-region routing, root CA info
- **Lookup complexity:** O(log R) where R = number of regions
- **Example:** 10K regions -> ~13 hops average

**Regional DHT:**
- **Node IDs:** 128-bit (SHA-256 truncated, region-specific)
- **Participants:** All nodes in region (full Kademlia)
- **Stores:** Node info, certificates, reputation, content, app data
- **Lookup complexity:** O(log N/R) where N = total nodes, R = regions
- **Example:** 1B nodes, 10K regions -> 100K nodes/region -> ~17 hops

**Total Lookup Cost:** O(log R + log N/R) = O(log N)
- For 1B nodes: ~13 + ~17 = **~30 hops maximum**
- Each hop: ~50ms latency -> ~1.5s worst case
- With caching: ~300-500ms typical

### Kademlia Routing Table

```go
type RoutingTable struct {
    localNodeID [20]byte     // 160-bit node ID
    buckets     [160]*KBucket // One bucket per bit
}

type KBucket struct {
    nodes []*Contact // Up to k=20 contacts
    mu    sync.RWMutex
}

type Contact struct {
    NodeID       [20]byte
    OverlayIPv6  net.IP        // 2602:F5BB:RRRR:SSSS::HHHH
    UnderlayAddr []string      // ["73.25.142.88:9999", "[2001:db8::1]:9999"]
    Reputation   float64
    LastSeen     time.Time
}
```

**XOR Distance Metric:**
```
Distance(A, B) = A XOR B

Example:
NodeA = 0b10110011...
NodeB = 0b10101100...
Dist  = 0b00011111... (XOR result)

Closer nodes have smaller XOR distance
```

### DHT Operations

**PUT (Store Key-Value):**
```go
func (dht *DHT) Put(key []byte, value []byte) error {
    // 1. Hash key to get 160-bit ID
    keyID := sha256.Sum256(key)[:20] // Truncate to 160 bits

    // 2. Find k=20 closest nodes to keyID
    closest := dht.FindClosestNodes(keyID, k=20)

    // 3. Store value on all k nodes (replication)
    for _, node := range closest {
        node.Store(key, value)
    }

    return nil
}
```

**GET (Retrieve Value):**
```go
func (dht *DHT) Get(key []byte) ([]byte, error) {
    keyID := sha256.Sum256(key)[:20]

    // Iterative lookup (alpha=3 parallel requests)
    closest := dht.FindClosestNodes(keyID, k=20)

    // Query nodes in parallel
    for _, node := range closest[:3] { // alpha=3 parallelism
        value := node.Retrieve(key)
        if value != nil {
            return value, nil // Found!
        }
    }

    // Try next closest nodes
    return dht.recursiveGet(key, closest[3:])
}
```

**FIND_NODE (Routing):**
```go
func (dht *DHT) FindClosestNodes(targetID [20]byte, k int) []*Contact {
    // Start with closest nodes in local routing table
    candidates := dht.routingTable.Closest(targetID, k)
    queried := make(map[[20]byte]bool)

    // Iterative lookup
    for len(candidates) < k {
        // Query alpha=3 closest unqueried nodes
        toQuery := selectUnqueried(candidates, queried, alpha=3)
        if len(toQuery) == 0 {
            break
        }

        // Parallel queries
        responses := parallelQuery(toQuery, targetID)

        // Merge responses
        for _, resp := range responses {
            candidates = merge(candidates, resp.Nodes)
        }
    }

    return candidates[:k]
}
```

---

## DHT Routing Optimizations

At billion-node scale, standard Kademlia lookup latency (350ms-1.1s) becomes a bottleneck for interactive applications. The routing layer implements aggressive caching, batching, and peer selection optimizations to reduce typical lookup latency to 50-200ms.

### Regional Node Caching

Each node maintains a regional cache of frequently-contacted nodes to minimize cross-region lookups.

```go
// pkg/dht/regional_cache.go

// RegionalNodeCache caches top nodes per region for fast routing
type RegionalNodeCache struct {
    localRegion       RegionID
    regionalCache     map[RegionID]*NodeCache  // Top 1000 nodes per region
    globalCache       *NodeCache               // Top 10000 nodes globally
    cacheHitRate      atomic.Uint64
    cacheMissRate     atomic.Uint64
}

const (
    RegionalCacheSize     = 1000   // Top 1000 nodes per region
    GlobalCacheSize       = 10000  // Top 10000 nodes globally
    RegionalCacheRefresh  = 5 * time.Minute
    TargetCacheHitRate    = 0.80   // 80% regional cache hit rate target
)

// CacheConfig defines routing cache parameters
type CacheConfig struct {
    RegionalSize      int           // 1000 nodes per region
    GlobalSize        int           // 10000 nodes globally
    RefreshInterval   time.Duration // 5 minutes
    NegativeTTL       time.Duration // 5 minutes for non-existent keys
    BatchSize         int           // 10 keys per batch
    BatchFlushDelay   time.Duration // 50ms flush interval
}

func DefaultCacheConfig() *CacheConfig {
    return &CacheConfig{
        RegionalSize:    1000,
        GlobalSize:      10000,
        RefreshInterval: 5 * time.Minute,
        NegativeTTL:     5 * time.Minute,
        BatchSize:       10,
        BatchFlushDelay: 50 * time.Millisecond,
    }
}

// LookupWithCache performs DHT lookup with multi-layer caching
func (rc *RegionalNodeCache) LookupWithCache(
    ctx context.Context,
    targetID NodeID,
) (*Contact, error) {
    targetRegion := rc.determineRegion(targetID)

    // Level 1: Check regional cache (local region)
    if targetRegion == rc.localRegion {
        if contact := rc.regionalCache[rc.localRegion].Get(targetID); contact != nil {
            rc.cacheHitRate.Add(1)
            return contact, nil
        }
    }

    // Level 2: Check global cache
    if contact := rc.globalCache.Get(targetID); contact != nil {
        rc.cacheHitRate.Add(1)
        return contact, nil
    }

    // Level 3: Check remote regional cache
    if targetRegion != rc.localRegion {
        if contact := rc.regionalCache[targetRegion].Get(targetID); contact != nil {
            rc.cacheHitRate.Add(1)
            return contact, nil
        }
    }

    // Cache miss - perform full DHT lookup
    rc.cacheMissRate.Add(1)
    contact, err := rc.fullDHTLookup(ctx, targetID)
    if err != nil {
        return nil, err
    }

    // Populate caches
    rc.updateCaches(targetRegion, targetID, contact)
    return contact, nil
}
```

### Message Batching

Multiple DHT operations destined for the same node are batched to reduce round-trips.

```go
// pkg/dht/message_batch.go

// RoutingMessageBatcher combines operations for network efficiency
type RoutingMessageBatcher struct {
    pending      map[NodeID]*BatchQueue  // Per-destination batches
    maxBatchSize int                     // 10 keys per batch
    flushDelay   time.Duration           // 50ms flush interval
    mu           sync.Mutex
}

const (
    DefaultBatchSize      = 10              // Keys per batch
    DefaultBatchFlushMs   = 50              // Milliseconds before flush
)

// BatchedLookup queues a lookup for batching
func (b *RoutingMessageBatcher) BatchedLookup(
    ctx context.Context,
    targetNode NodeID,
    key []byte,
) <-chan *LookupResult {
    resultCh := make(chan *LookupResult, 1)

    b.mu.Lock()
    queue, exists := b.pending[targetNode]
    if !exists {
        queue = &BatchQueue{
            items:   make([]*BatchItem, 0, b.maxBatchSize),
            timer:   time.NewTimer(b.flushDelay),
            node:    targetNode,
        }
        b.pending[targetNode] = queue

        // Start flush timer
        go b.watchFlushTimer(targetNode, queue)
    }

    queue.items = append(queue.items, &BatchItem{
        Key:      key,
        ResultCh: resultCh,
    })

    // Flush immediately if batch is full
    if len(queue.items) >= b.maxBatchSize {
        b.flushBatch(targetNode, queue)
    }
    b.mu.Unlock()

    return resultCh
}

// flushBatch sends all pending operations in a single message
func (b *RoutingMessageBatcher) flushBatch(targetNode NodeID, queue *BatchQueue) {
    if len(queue.items) == 0 {
        return
    }

    // Build batch request
    keys := make([][]byte, len(queue.items))
    for i, item := range queue.items {
        keys[i] = item.Key
    }

    // Single network round-trip for all keys
    results, err := b.sendBatchRequest(targetNode, keys)

    // Distribute results to waiting callers
    for i, item := range queue.items {
        if err != nil {
            item.ResultCh <- &LookupResult{Err: err}
        } else {
            item.ResultCh <- results[i]
        }
        close(item.ResultCh)
    }

    queue.items = queue.items[:0]
}
```

### Negative Result Caching

Non-existent keys are cached to prevent repeated failed lookups.

```go
// pkg/dht/negative_cache.go

// NegativeResultCache prevents repeated lookups for non-existent keys
type NegativeResultCache struct {
    cache   *lru.Cache
    ttl     time.Duration  // 5 minutes
}

const (
    NegativeCacheTTL     = 5 * time.Minute
    NegativeCacheMaxSize = 1000000  // 1M entries
)

// RecordNotFound caches a negative lookup result
func (nc *NegativeResultCache) RecordNotFound(key []byte) {
    nc.cache.Add(string(key), &NegativeEntry{
        CachedAt: time.Now(),
    })
}

// IsKnownNotFound checks if key is known to not exist
func (nc *NegativeResultCache) IsKnownNotFound(key []byte) bool {
    if entry, ok := nc.cache.Get(string(key)); ok {
        neg := entry.(*NegativeEntry)
        if time.Since(neg.CachedAt) < nc.ttl {
            return true  // Skip DHT lookup
        }
        // TTL expired, remove stale entry
        nc.cache.Remove(string(key))
    }
    return false
}
```

### Routing Performance Targets

| Metric | Before Optimization | After Optimization | Improvement |
|--------|---------------------|-------------------|-------------|
| Average lookup latency | 350ms - 1.1s | 50ms - 200ms | 5-7x faster |
| Regional cache hit rate | N/A | 80% target | - |
| Network round-trips | 1 per key | 1 per 10 keys (batched) | 10x reduction |
| Negative lookup cost | Full DHT lookup | Local cache check | ~1000x faster |
| Memory overhead | - | ~500MB for caches | Acceptable |

### Optimization Configuration

```yaml
# DHT routing optimization settings
routing:
  regional_cache:
    size_per_region: 1000        # Top nodes cached per region
    global_size: 10000           # Global hot node cache
    refresh_interval: 5m         # Cache refresh period

  message_batching:
    max_batch_size: 10           # Keys per batch
    flush_delay_ms: 50           # Maximum batch delay

  negative_cache:
    ttl: 5m                      # Non-existent key cache TTL
    max_entries: 1000000         # Maximum cached entries

  performance_targets:
    lookup_latency_p50_ms: 75    # Target 50th percentile
    lookup_latency_p99_ms: 200   # Target 99th percentile
    cache_hit_rate: 0.80         # Target 80% regional hits
```

---

## Gateway Node Architecture

### What is a Gateway Node?

**Any P2P node with public IP can become a gateway:**

```go
type GatewayNode struct {
    // Overlay addressing (P2P network identity)
    OverlayIPv6   net.IP // 2602:F5BB:0001::1234

    // Underlay addressing (actual internet connectivity)
    PublicIPv4    string // "73.25.142.88" (node's ISP-provided IP)
    PublicIPv6    string // "2001:db8::1" (node's ISP-provided IPv6)
    PublicPort    int    // 9999

    // Gateway capabilities
    Bandwidth     uint64  // 100 Mbps (available for gateway traffic)
    Reputation    float64 // Must meet threshold (see reputation docs)
    Region        string  // "us-east-1"

    // DDoS mitigation
    RateLimit     uint64   // requests/sec
    Firewall      []string // Blocked IP ranges
}
```

> **See Also:** [09-defense-reputation.md](09-defense-reputation.md) for gateway promotion requirements and reputation thresholds.

### Gateway Node Lifecycle - FINAL DESIGN

**Gateway Demotion Protocol:**

Gateways can be demoted when they no longer meet eligibility requirements. This ensures only high-quality nodes serve as network entry points.

**Demotion Triggers:**
- Reputation falls below 0.85 (promotion threshold)
- Uptime drops below 95% (rolling 7-day window)
- Stake is slashed due to misbehavior
- Manual demotion by operators

**Grace Period:**
- 1-hour grace period after demotion trigger detected
- Allows temporary issues to resolve without immediate demotion
- Node remains in gateway role during grace period
- If condition persists after grace period: demotion proceeds

**In-flight Connection Handling:**
- When demotion occurs, gateway has active connections to clients
- Drain phase: No new connections accepted, existing connections allowed to complete
- Drain timeout: 60 seconds maximum
- After timeout: Force close remaining connections
- Clients receive TCP RST and must reconnect to different gateway

**Client Notification:**
- Gateway publishes demotion notice to DHT
- Notice includes: timestamp, reason, recommended alternate gateways
- Clients monitoring DHT receive proactive notification
- Clients can begin selecting new gateway before force disconnect

```go
// Gateway demotion handler
type GatewayDemotion struct {
    nodeID          NodeID
    demotionReason  DemotionReason
    gracePeriod     time.Duration // 1 hour
    drainTimeout    time.Duration // 60 seconds
}

type DemotionReason uint8

const (
    DemotionReasonReputationDrop DemotionReason = iota
    DemotionReasonUptimeDrop
    DemotionReasonStakeSlashed
    DemotionReasonManual
)

func (gd *GatewayDemotion) InitiateDemotion() error {
    // Step 1: Enter grace period
    log.Info("gateway entering demotion grace period",
        "nodeID", gd.nodeID,
        "reason", gd.demotionReason,
        "gracePeriod", gd.gracePeriod)

    // Publish early warning to DHT
    publishDemotionWarning(gd.nodeID, gd.demotionReason, gd.gracePeriod)

    // Wait for grace period
    time.Sleep(gd.gracePeriod)

    // Step 2: Re-check eligibility after grace period
    if gd.isNowEligible() {
        log.Info("gateway recovered during grace period, demotion cancelled",
            "nodeID", gd.nodeID)
        return nil
    }

    // Step 3: Begin demotion process
    log.Warn("gateway demotion proceeding after grace period",
        "nodeID", gd.nodeID,
        "reason", gd.demotionReason)

    // Step 4: Stop accepting new connections
    stopAcceptingConnections(gd.nodeID)

    // Step 5: Publish demotion notice with alternate gateways
    alternates := selectAlternateGateways(gd.nodeID, 5)
    publishDemotionNotice(&DemotionNotice{
        NodeID:     gd.nodeID,
        Reason:     gd.demotionReason,
        Timestamp:  time.Now(),
        Alternates: alternates,
    })

    // Step 6: Drain existing connections
    drainCtx, cancel := context.WithTimeout(context.Background(), gd.drainTimeout)
    defer cancel()

    drainConnections(drainCtx, gd.nodeID)

    // Step 7: Force close any remaining connections
    forceCloseConnections(gd.nodeID)

    // Step 8: Withdraw BGP routes
    withdrawGatewayRoutes(gd.nodeID, WithdrawalReasonDemotion)

    // Step 9: Remove from gateway registry in DHT
    removeFromGatewayRegistry(gd.nodeID)

    log.Info("gateway demotion complete", "nodeID", gd.nodeID)
    return nil
}

// drainConnections allows existing connections to complete gracefully
func drainConnections(ctx context.Context, nodeID NodeID) {
    activeConns := getActiveConnections(nodeID)
    log.Info("draining gateway connections",
        "nodeID", nodeID,
        "activeConnections", len(activeConns))

    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            // Timeout reached
            remaining := getActiveConnections(nodeID)
            log.Warn("drain timeout reached, force closing connections",
                "nodeID", nodeID,
                "remainingConnections", len(remaining))
            return

        case <-ticker.C:
            remaining := getActiveConnections(nodeID)
            if len(remaining) == 0 {
                log.Info("all connections drained gracefully",
                    "nodeID", nodeID)
                return
            }
            log.Debug("draining in progress",
                "nodeID", nodeID,
                "remainingConnections", len(remaining))
        }
    }
}

// DemotionNotice published to DHT for client awareness
type DemotionNotice struct {
    NodeID     NodeID
    Reason     DemotionReason
    Timestamp  time.Time
    Alternates []GatewayInfo // Recommended replacement gateways
    TTL        time.Duration // How long clients should avoid this gateway
}
```

### Gateway Registration

```go
func (g *GatewayNode) Register() {
    // Publish to DHT
    dht.Publish("gateway-"+g.Region, GatewayInfo{
        OverlayIPv6: g.OverlayIPv6.String(),
        PublicAddr:  g.PublicIPv4 + ":" + strconv.Itoa(g.PublicPort),
        Bandwidth:   g.Bandwidth,
        Reputation:  g.Reputation,
        Region:      g.Region,
    })

    // Update every 5 minutes (heartbeat)
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        g.RefreshRegistration()
    }
}
```

### Gateway Traffic Handling

**Inbound Connection from Internet:**
```go
func (g *GatewayNode) HandleInboundConnection(conn net.Conn) {
    srcIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

    // 1. DDoS protection: Rate limiting
    if !g.rateLimiter.Allow(srcIP, g.RateLimit) {
        conn.Close()
        return
    }

    // 2. Read destination overlay IPv6
    dstOverlay := readDestination(conn) // e.g., 2602:F5BB:0002::5678

    // 3. Look up target node in DHT
    targetNode := dht.Lookup(dstOverlay)
    if targetNode == nil {
        conn.Write([]byte("404 Not Found"))
        conn.Close()
        return
    }

    // 4. Establish P2P mesh connection to target
    p2pConn := g.establishMeshConnection(targetNode)
    if p2pConn == nil {
        conn.Write([]byte("503 Service Unavailable"))
        conn.Close()
        return
    }

    // 5. Proxy bidirectional traffic
    go io.Copy(p2pConn, conn) // client -> target
    io.Copy(conn, p2pConn)    // target -> client
}
```

### P2P Mesh Routing

**Multi-hop routing (onion-routing style):**
```go
func (g *GatewayNode) establishMeshConnection(target NodeInfo) net.Conn {
    // Option 1: Direct connection (if target has public IP)
    if target.HasPublicIP {
        conn, err := net.Dial("tcp", target.UnderlayAddr)
        if err == nil {
            return conn // Direct connection
        }
    }

    // Option 2: Multi-hop via P2P mesh (target behind NAT)
    path := g.buildPath(target, numHops=2)

    // Path example: Gateway -> HubA -> Target
    hop1, _ := net.Dial("tcp", path[0].UnderlayAddr)

    // Send routing request
    sendRoutingRequest(hop1, RoutingRequest{
        Destination: target.OverlayIPv6,
        NextHop:     path[1].NodeID,
    })

    return hop1 // Tunneled connection through mesh
}
```

**Privacy Benefit:** Multi-hop routing means gateway doesn't connect directly to target (like Tor)

### Gateway Promotion and Selection

Gateway nodes require strict eligibility criteria and diversity enforcement to maintain network integrity. The system enforces geographic, network, and vendor diversity across all gateway selections.

```go
// pkg/gateway/sybil_defense.go

// Role Promotion Requirements (P4-H15: Complete age requirements)
// CANONICAL: All role promotions require minimum network participation
// NOTE: Canonical values are in 03-security-trust.md - these MUST match!
const (
    // Leaf -> Hub promotion requirements
    MinHubReputation         = 0.80   // Hub requires 0.80 (canonical: 03-security-trust.md)
    MinHubAge                = 30     // 30 days of network participation
    MinHubUptime             = 0.95   // 95% uptime (99% during 30-day probation)
    MinHubStorage            = 100    // GB of available storage

    // Hub -> Coordinator promotion requirements
    MinCoordinatorReputation = 0.95   // Coordinator requires 0.95 (canonical: 03-security-trust.md)
    MinCoordinatorAge        = 180    // 180 days (6 months) network participation
    MinCoordinatorUptime     = 0.99   // 99% uptime over rolling 90 days
    MinCoordinatorStorage    = 1000   // GB of available storage

    // CA Pool Participant requirements (see also 05-certificate-authority.md)
    MinCAParticipantReputation = 0.90 // CA signing eligible at 0.90 (canonical: 00-CONSTANTS.md)
    MinCAParticipantAge        = 90   // 90 days minimum
    MinCAParticipantUptime     = 0.95 // 95% uptime for CA

    // Gateway promotion requirements (subset of Hub requirements)
    MinGatewayReputation     = 0.85   // Must have high reputation
    MinGatewayAge            = 90     // Days of network participation
    MinGatewayUptime         = 0.95   // 95% uptime over rolling 30 days

    // Sybil prevention limits
    MaxGatewaysPerASN        = 50     // Limit gateways per Autonomous System
    MaxGatewaysPerSubnet     = 5      // Limit gateways per /24 IPv4 or /48 IPv6
    MaxGatewaysPerEKVendor   = 0.25   // Max 25% of gateways from same TPM vendor

    // Geographic diversity
    MinRegionsForSelection   = 3      // Select from at least 3 regions
    MaxGatewaysPerRegion     = 0.20   // No region can have >20% of gateways

    // Economic deterrent
    GatewayStakeRequired     = 1000   // Coins staked for gateway role
    SlashingForMisbehavior   = 0.20   // 20% stake slashed for proven misbehavior
)

// GatewaySybilDefense implements multi-layer Sybil protection
type GatewaySybilDefense struct {
    gatewayRegistry  *GatewayRegistry
    asnTracker       *ASNTracker
    subnetTracker    *SubnetTracker
    vendorTracker    *TPMVendorTracker
    regionTracker    *RegionTracker
}

// ValidateGatewayPromotion checks all Sybil defense criteria
func (d *GatewaySybilDefense) ValidateGatewayPromotion(candidate *Node) error {
    // Layer 1: Basic eligibility
    if candidate.Reputation < MinGatewayReputation {
        return &GatewayPromotionDenied{
            Reason: "insufficient_reputation",
            Required: MinGatewayReputation,
            Actual: candidate.Reputation,
        }
    }

    age := time.Since(candidate.JoinedAt)
    if age < MinGatewayAge*24*time.Hour {
        return &GatewayPromotionDenied{
            Reason: "insufficient_age",
            Required: fmt.Sprintf("%d days", MinGatewayAge),
            Actual: fmt.Sprintf("%.1f days", age.Hours()/24),
        }
    }

    // Layer 2: TPM/IDevID validation
    if err := d.validateTPMBinding(candidate); err != nil {
        return err
    }

    // Layer 3: ASN diversity check
    asn := d.asnTracker.GetASN(candidate.PublicIP)
    asnCount := d.asnTracker.CountGatewaysInASN(asn)
    if asnCount >= MaxGatewaysPerASN {
        return &GatewayPromotionDenied{
            Reason: "asn_limit_exceeded",
            Details: fmt.Sprintf("ASN %d already has %d gateways", asn, asnCount),
        }
    }

    // Layer 4: Subnet diversity check
    subnet := d.subnetTracker.GetSubnet(candidate.PublicIP)
    subnetCount := d.subnetTracker.CountGatewaysInSubnet(subnet)
    if subnetCount >= MaxGatewaysPerSubnet {
        return &GatewayPromotionDenied{
            Reason: "subnet_limit_exceeded",
            Details: fmt.Sprintf("Subnet %s already has %d gateways", subnet, subnetCount),
        }
    }

    // Layer 5: TPM vendor diversity check
    vendor := d.vendorTracker.GetVendor(candidate.IDevIDCert)
    vendorRatio := d.vendorTracker.GetVendorRatio(vendor)
    if vendorRatio >= MaxGatewaysPerEKVendor {
        return &GatewayPromotionDenied{
            Reason: "vendor_concentration_exceeded",
            Details: fmt.Sprintf("Vendor %s at %.0f%% of gateways", vendor, vendorRatio*100),
        }
    }

    // Layer 6: Regional diversity check
    region := d.regionTracker.GetRegion(candidate.PublicIP)
    regionRatio := d.regionTracker.GetRegionRatio(region)
    if regionRatio >= MaxGatewaysPerRegion {
        return &GatewayPromotionDenied{
            Reason: "region_concentration_exceeded",
            Details: fmt.Sprintf("Region %s at %.0f%% of gateways", region, regionRatio*100),
        }
    }

    // Layer 7: Economic stake verification
    if err := d.verifyStake(candidate, GatewayStakeRequired); err != nil {
        return err
    }

    return nil
}

// validateTPMBinding ensures gateway has valid hardware attestation
func (d *GatewaySybilDefense) validateTPMBinding(candidate *Node) error {
    // Verify IDevID certificate is valid
    if candidate.IDevIDCert == nil {
        return &GatewayPromotionDenied{Reason: "missing_idevid"}
    }

    // Verify certificate chain to trusted manufacturer CA
    if err := d.verifyIDevIDChain(candidate.IDevIDCert); err != nil {
        return &GatewayPromotionDenied{
            Reason: "invalid_idevid_chain",
            Details: err.Error(),
        }
    }

    // Request fresh TPM quote
    quote, err := d.requestFreshQuote(candidate)
    if err != nil {
        return &GatewayPromotionDenied{
            Reason: "quote_failed",
            Details: err.Error(),
        }
    }

    // Verify quote binds to IDevID
    if err := d.verifyQuoteBinding(quote, candidate.IDevIDCert); err != nil {
        return &GatewayPromotionDenied{
            Reason: "quote_binding_failed",
            Details: err.Error(),
        }
    }

    return nil
}
```

**Gateway Selection with Sybil Resistance**:

```go
// SelectGatewaysForClient chooses gateways with Sybil-resistant diversity
func (d *GatewaySybilDefense) SelectGatewaysForClient(
    clientRegion string,
    count int,
) ([]*Gateway, error) {
    allGateways := d.gatewayRegistry.GetAll()

    // Step 1: Filter to only valid, high-reputation gateways
    validGateways := filterValid(allGateways)

    // Step 2: Ensure geographic diversity
    // Must select from at least MinRegionsForSelection regions
    regionGroups := groupByRegion(validGateways)
    if len(regionGroups) < MinRegionsForSelection {
        return nil, ErrInsufficientGatewayDiversity
    }

    // Step 3: Ensure ASN diversity
    // No more than 2 gateways from same ASN in selection
    asnGroups := groupByASN(validGateways)

    // Step 4: Ensure vendor diversity
    // No more than 50% from same TPM vendor in selection
    vendorGroups := groupByVendor(validGateways)

    // Step 5: VRF-based selection for unpredictability
    // Prevents attacker from positioning gateways to intercept specific clients
    seed := deriveVRFSeed(clientRegion, time.Now().Unix()/3600) // Hourly rotation
    selected := make([]*Gateway, 0, count)
    usedASNs := make(map[uint32]int)
    usedVendors := make(map[string]int)
    usedRegions := make(map[string]bool)

    // Shuffle gateways using VRF
    shuffled := vrfShuffle(validGateways, seed)

    for _, gw := range shuffled {
        if len(selected) >= count {
            break
        }

        // Check ASN diversity (max 2 per ASN)
        if usedASNs[gw.ASN] >= 2 {
            continue
        }

        // Check vendor diversity (max 50% of selection)
        maxVendor := count / 2
        if maxVendor < 1 {
            maxVendor = 1
        }
        if usedVendors[gw.TPMVendor] >= maxVendor {
            continue
        }

        selected = append(selected, gw)
        usedASNs[gw.ASN]++
        usedVendors[gw.TPMVendor]++
        usedRegions[gw.Region] = true
    }

    // Verify we have sufficient regional diversity
    if len(usedRegions) < MinRegionsForSelection && len(selected) >= count {
        // Need to reshuffle to ensure regional diversity
        return d.selectWithRegionalDiversity(validGateways, count, seed)
    }

    return selected, nil
}
```

**Continuous Gateway Monitoring**:

```go
// GatewayMonitor detects and responds to suspicious gateway behavior
type GatewayMonitor struct {
    dht            DHT
    defense        *GatewaySybilDefense
    alertThreshold float64
}

// MonitorGatewayBehavior runs continuous monitoring
func (m *GatewayMonitor) MonitorGatewayBehavior(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.detectAnomalies()
        }
    }
}

func (m *GatewayMonitor) detectAnomalies() {
    // Check 1: Sudden gateway registration spike
    newGateways := m.defense.GetRecentRegistrations(1 * time.Hour)
    if len(newGateways) > 100 {
        m.alertPotentialSybilAttack("registration_spike", len(newGateways))
    }

    // Check 2: ASN concentration anomaly
    asnCounts := m.defense.asnTracker.GetAllCounts()
    for asn, count := range asnCounts {
        if count > MaxGatewaysPerASN*2 { // 2x threshold = alert
            m.alertPotentialSybilAttack("asn_concentration", asn)
        }
    }

    // Check 3: Geographic clustering
    regionCounts := m.defense.regionTracker.GetAllCounts()
    totalGateways := m.defense.gatewayRegistry.Count()
    for region, count := range regionCounts {
        ratio := float64(count) / float64(totalGateways)
        if ratio > MaxGatewaysPerRegion*1.5 { // 1.5x threshold = alert
            m.alertPotentialSybilAttack("regional_concentration", region)
        }
    }

    // Check 4: Gateway traffic anomalies
    gateways := m.defense.gatewayRegistry.GetAll()
    for _, gw := range gateways {
        stats := m.getGatewayStats(gw.NodeID)

        // Suspiciously high drop rate
        if stats.DropRate > 0.10 { // >10% drops
            m.flagSuspiciousGateway(gw.NodeID, "high_drop_rate", stats.DropRate)
        }

        // Selective routing (only routes to certain targets)
        if stats.RoutingEntropyScore < 0.5 {
            m.flagSuspiciousGateway(gw.NodeID, "selective_routing", stats.RoutingEntropyScore)
        }

        // Latency inflation (artificially slow for certain traffic)
        if stats.LatencyVariance > 500*time.Millisecond {
            m.flagSuspiciousGateway(gw.NodeID, "latency_inflation", stats.LatencyVariance)
        }
    }
}

// SlashMaliciousGateway removes gateway and slashes stake for proven misbehavior
func (m *GatewayMonitor) SlashMaliciousGateway(nodeID NodeID, evidence *MisbehaviorEvidence) error {
    // Verify evidence is TPM-attested and signed
    if err := evidence.Verify(); err != nil {
        return ErrInvalidEvidence
    }

    // Submit to PBFT quorum for judgment
    verdict, err := m.submitToQuorum(nodeID, evidence)
    if err != nil {
        return err
    }

    if verdict.Guilty {
        // Slash stake
        stake := m.defense.gatewayRegistry.GetStake(nodeID)
        slashAmount := uint64(float64(stake) * SlashingForMisbehavior)
        m.slashStake(nodeID, slashAmount)

        // Remove gateway role
        m.defense.gatewayRegistry.Remove(nodeID)

        // Publish misbehavior record
        m.dht.Put("gateway:misbehavior:"+nodeID.String(), verdict)

        // Ban from gateway role for 30 days
        m.defense.banFromGatewayRole(nodeID, 30*24*time.Hour)
    }

    return nil
}
```

**Gateway Eligibility Requirements:**

| Requirement | Value | Purpose |
|-------------|-------|---------|
| Reputation | >= 0.85 | Proven reliable operation |
| Network Age | >= 90 days | Established presence |
| Uptime | >= 95% | Reliable availability |
| TPM/IDevID | Required | Hardware identity binding |
| Stake | 1000 coins | Economic commitment |

**Diversity Constraints:**

| Constraint | Limit | Scope |
|------------|-------|-------|
| Per ASN | 50 gateways | Network diversity |
| Per Subnet | 5 gateways | /24 IPv4 or /48 IPv6 |
| Per TPM Vendor | 25% of total | Vendor diversity |
| Per Region | 20% of total | Geographic distribution |
| Selection Regions | >= 3 | Per client selection |

**Gateway Penalties:**

| Violation | Penalty |
|-----------|---------|
| Traffic manipulation | 20% stake slashed, role removed |
| Selective routing | 20% stake slashed, role removed |
| Service degradation | Warning, then escalation |
| Repeat offense | 30-day ban from gateway role |

### Eclipse Attack Prevention

Eclipse attacks attempt to isolate a target node by controlling all its routing table entries. The routing table implements strict diversity requirements to prevent attackers from surrounding victim nodes.

#### ASN Diversity Requirements

```go
// pkg/dht/eclipse_defense.go

// EclipseDefenseConfig defines routing table diversity constraints
type EclipseDefenseConfig struct {
    // ASN diversity - reduced from 33% to 20% for stronger protection
    MaxSameASNPerBucket    float64  // Maximum 20% same-ASN nodes per bucket
    MinDistinctASNs        int      // Minimum 5 distinct ASNs in routing table

    // Cloud provider classification
    CloudProviderMetaASNs  map[string][]uint32  // AWS, GCP, Azure ASN groups
    MaxCloudProviderRatio  float64              // Max 30% from any cloud provider

    // Network diversity
    MinNonDatacenterRatio  float64  // Minimum 30% residential/edge nodes
    MaxIPRangePerBucket    int      // Max nodes from same /24 IPv4 or /48 IPv6
}

const (
    // Routing table diversity constraints
    MaxSameASNPerBucket      = 0.20   // 20% (reduced from 33%)
    MinDistinctASNsInTable   = 5      // At least 5 different ASNs
    MinNonDatacenterRatio    = 0.30   // 30% must be residential/edge
    MaxNodesPerIPRange       = 2      // Max 2 nodes per /24 or /48
)

// CloudProviderASNs maps major cloud providers to their ASN groups
// These are treated as equivalent for diversity calculations
var CloudProviderASNs = map[string][]uint32{
    "aws":   {14618, 16509, 7224, 8987},      // Amazon AWS ASNs
    "gcp":   {15169, 396982, 36040},          // Google Cloud ASNs
    "azure": {8075, 8068, 8069},              // Microsoft Azure ASNs
    "alibaba": {45102, 37963, 45096},         // Alibaba Cloud ASNs
    "oracle": {31898, 7160},                  // Oracle Cloud ASNs
}

// ValidateRoutingDiversity ensures routing table meets diversity requirements
func (rt *RoutingTable) ValidateRoutingDiversity(
    defense *EclipseDefenseConfig,
) error {
    // Check 1: ASN diversity per bucket
    for i, bucket := range rt.buckets {
        asnCounts := make(map[uint32]int)
        for _, contact := range bucket.nodes {
            asn := lookupASN(contact.UnderlayAddr)
            asnCounts[asn]++
        }

        totalNodes := len(bucket.nodes)
        for asn, count := range asnCounts {
            ratio := float64(count) / float64(totalNodes)
            if ratio > defense.MaxSameASNPerBucket {
                return &EclipseDiversityViolation{
                    Type:     "asn_concentration",
                    Bucket:   i,
                    ASN:      asn,
                    Ratio:    ratio,
                    MaxRatio: defense.MaxSameASNPerBucket,
                }
            }
        }
    }

    // Check 2: Minimum distinct ASNs across entire table
    allASNs := make(map[uint32]bool)
    for _, bucket := range rt.buckets {
        for _, contact := range bucket.nodes {
            asn := lookupASN(contact.UnderlayAddr)
            allASNs[asn] = true
        }
    }
    if len(allASNs) < defense.MinDistinctASNs {
        return &EclipseDiversityViolation{
            Type:        "insufficient_asn_diversity",
            DistinctASNs: len(allASNs),
            MinRequired: defense.MinDistinctASNs,
        }
    }

    // Check 3: Cloud provider meta-ASN classification
    cloudProviderCounts := make(map[string]int)
    totalNodes := rt.totalNodeCount()
    for _, bucket := range rt.buckets {
        for _, contact := range bucket.nodes {
            asn := lookupASN(contact.UnderlayAddr)
            provider := classifyCloudProvider(asn, CloudProviderASNs)
            if provider != "" {
                cloudProviderCounts[provider]++
            }
        }
    }

    for provider, count := range cloudProviderCounts {
        ratio := float64(count) / float64(totalNodes)
        if ratio > defense.MaxCloudProviderRatio {
            return &EclipseDiversityViolation{
                Type:         "cloud_provider_concentration",
                Provider:     provider,
                Ratio:        ratio,
                MaxRatio:     defense.MaxCloudProviderRatio,
            }
        }
    }

    // Check 4: Non-datacenter diversity
    nonDatacenterCount := 0
    for _, bucket := range rt.buckets {
        for _, contact := range bucket.nodes {
            if !isDatacenterIP(contact.UnderlayAddr) {
                nonDatacenterCount++
            }
        }
    }
    nonDCRatio := float64(nonDatacenterCount) / float64(totalNodes)
    if nonDCRatio < defense.MinNonDatacenterRatio {
        return &EclipseDiversityViolation{
            Type:         "insufficient_edge_diversity",
            Ratio:        nonDCRatio,
            MinRequired:  defense.MinNonDatacenterRatio,
        }
    }

    return nil
}

// classifyCloudProvider determines if ASN belongs to a cloud provider
func classifyCloudProvider(asn uint32, providers map[string][]uint32) string {
    for provider, asns := range providers {
        for _, providerASN := range asns {
            if asn == providerASN {
                return provider
            }
        }
    }
    return ""  // Not a known cloud provider
}

// isDatacenterIP checks if IP belongs to known datacenter ranges
func isDatacenterIP(addr string) bool {
    ip := net.ParseIP(addr)
    if ip == nil {
        return false
    }

    // Check against datacenter IP databases (MaxMind, IP2Location)
    return datacenterIPDB.Contains(ip)
}
```

#### IP Range Analysis

Beyond ASN-level diversity, the routing table analyzes IP address ranges to detect coordinated attacks from adjacent address blocks.

```go
// pkg/dht/ip_range_analysis.go

// IPRangeAnalyzer detects suspicious IP clustering
type IPRangeAnalyzer struct {
    ipv4PrefixLen  int  // /24 for IPv4 analysis
    ipv6PrefixLen  int  // /48 for IPv6 analysis
}

// AnalyzeIPClustering detects suspicious IP address patterns
func (a *IPRangeAnalyzer) AnalyzeIPClustering(contacts []*Contact) *ClusterAnalysis {
    ipv4Ranges := make(map[string]int)  // /24 prefix -> count
    ipv6Ranges := make(map[string]int)  // /48 prefix -> count

    for _, contact := range contacts {
        for _, addr := range contact.UnderlayAddr {
            ip := extractIP(addr)
            if ip == nil {
                continue
            }

            if ip4 := ip.To4(); ip4 != nil {
                // IPv4: use /24 prefix
                prefix := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
                ipv4Ranges[prefix]++
            } else {
                // IPv6: use /48 prefix
                prefix := formatIPv6Prefix(ip, 48)
                ipv6Ranges[prefix]++
            }
        }
    }

    // Identify suspicious clusters
    var suspiciousClusters []IPCluster
    for prefix, count := range ipv4Ranges {
        if count > MaxNodesPerIPRange {
            suspiciousClusters = append(suspiciousClusters, IPCluster{
                Prefix: prefix,
                Count:  count,
                Type:   "ipv4",
            })
        }
    }
    for prefix, count := range ipv6Ranges {
        if count > MaxNodesPerIPRange {
            suspiciousClusters = append(suspiciousClusters, IPCluster{
                Prefix: prefix,
                Count:  count,
                Type:   "ipv6",
            })
        }
    }

    return &ClusterAnalysis{
        TotalContacts:      len(contacts),
        IPv4Ranges:         len(ipv4Ranges),
        IPv6Ranges:         len(ipv6Ranges),
        SuspiciousClusters: suspiciousClusters,
    }
}
```

#### Eclipse Defense Summary

| Defense Layer | Constraint | Purpose |
|---------------|------------|---------|
| ASN diversity | Max 20% same-ASN per bucket | Prevent single-network dominance |
| Minimum ASNs | At least 5 distinct ASNs | Ensure network heterogeneity |
| Cloud meta-ASN | AWS/GCP/Azure treated equivalently | Prevent cloud provider monoculture |
| Edge diversity | Min 30% non-datacenter nodes | Include residential/edge networks |
| IP range limits | Max 2 nodes per /24 or /48 | Detect adjacent IP attacks |

---

## Wire Protocol

### Node Information Storage

```go
type NodeInfo struct {
    // Identity
    NodeID        [32]byte // SHA-256(public_key)

    // Overlay addressing (P2P network)
    OverlayIPv6   net.IP // 2602:F5BB:0001::1234

    // Underlay addressing (actual connectivity)
    UnderlayAddrs []string // ["73.25.142.88:9999", "[2001:db8::1]:9999"]
    NATType       string   // "none", "symmetric", "cone"

    // Capabilities
    Tier          string // "leaf", "hub", "coordinator"
    Bandwidth     uint64 // Mbps
    Storage       uint64 // GB available for DHT
    IsGateway     bool   // Accepting public internet traffic?

    // Reputation & Stats
    Reputation    float64
    Uptime        float64
    JoinedAt      time.Time
    LastSeen      time.Time

    // Region
    Region        string // "us-east-1", "eu-west-1", etc.
}

// Storage in DHT
// Key: "node-{nodeID}"
// Value: NodeInfo (protobuf-encoded)
// TTL: 24 hours (refreshed by node)
// Replication: k=3
// Size: ~100 bytes per node

// NOTE: Certificates are NOT stored in DHT
// Nodes store certificates locally and present during connection handshake
```

### Connection Establishment

```go
func ConnectToNode(overlayIPv6 string) (net.Conn, error) {
    // 1. Look up node info in DHT
    nodeInfo := dht.Get("node-" + overlayIPv6)
    if nodeInfo == nil {
        return nil, errors.New("node not found")
    }

    // 2. Try direct connection first (fastest)
    for _, addr := range nodeInfo.UnderlayAddrs {
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err == nil {
            // 3. Perform TLS-style handshake
            cert := performHandshake(conn)

            // 4. Validate certificate
            if err := ValidateCertificate(cert); err != nil {
                conn.Close()
                return nil, err
            }

            return conn, nil // Authenticated connection
        }
    }

    // 5. Direct failed, try via gateway
    if nodeInfo.NATType != "none" {
        return connectViaGateway(nodeInfo)
    }

    // 6. Last resort: NAT traversal
    return natTraversal(nodeInfo)
}

func connectViaGateway(target NodeInfo) (net.Conn, error) {
    // Find gateway in target's region
    gateways := dht.Lookup("gateway-" + target.Region)
    if len(gateways) == 0 {
        return nil, errors.New("no gateways available")
    }

    // Select best gateway (lowest latency, highest reputation)
    gateway := selectBestGateway(gateways)

    // Connect to gateway
    conn, _ := net.Dial("tcp", gateway.PublicAddr)

    // Request routing to target
    sendRoutingRequest(conn, target.OverlayIPv6)

    return conn, nil
}
```

---

## Public Internet Access

### DNS Strategy: Hybrid (A + AAAA Records)

```
DNS returns BOTH record types:
- A record: 23.143.36.10 (gateway IPv4, works for everyone)
- AAAA record: 2602:F5BB:0001::1234 (direct IPv6, fastest for IPv6 users)

Client behavior:
- IPv6-capable clients: Try AAAA first (direct, fastest)
- IPv6 connection fails: Fallback to A record (gateway)
- IPv4-only clients: Use A record (gateway)
```

**Example DNS Zone:**
```dns
myapp.example.com.    300  IN  A      23.143.36.10
myapp.example.com.    300  IN  AAAA   2602:F5BB:0001::1234
```

### Gateway IP Configuration Options

**Configuration A: Gateway's Own Public IP (Performance)**
```yaml
dns_strategy: gateway_ip_only
records:
  - type: A
    value: 73.25.142.88 # Gateway's ISP-provided IP
# Best for: Personal websites, maximum performance
```

**Configuration B: Pool IPv6 Only (Redundancy)**
```yaml
dns_strategy: pool_ipv6_only
records:
  - type: AAAA
    value: 2602:F5BB:0001::1234
# Best for: High-availability, portable addressing
```

**Configuration C: Both (Recommended for Production)**
```yaml
dns_strategy: hybrid
records:
  - type: A
    value: 73.25.142.88
  - type: AAAA
    value: 2602:F5BB:0001::1234
# Best for: Maximum redundancy + performance
```

### BGP Propagation Strategy

**Tier 1: Backbone (Default Route)**
- Backbone speakers announce: 2602:F5BB::/36 globally
- Catches all traffic (default route)
- Always available (fallback)
- Handles residential gateways via tunnels

**Tier 2: Datacenter Gateways (Direct Routing)**
- Capable gateways announce more specific /48 routes
- BGP prefers more specific -> traffic goes directly to gateway
- Bypasses backbone (zero cost)

**Tier 3: Residential Gateways (Tunnel)**
- Connect to backbone via WireGuard tunnel
- Receive forwarded traffic from backbone speakers

---

## Performance Optimizations

### Multi-Tier Caching

```go
type CacheHierarchy struct {
    l1 *LRUCache  // In-memory, 100MB, <1ms access
    l2 *DiskCache // SSD, 10GB, ~5ms access
    l3 *DHT       // Network, unlimited, ~500ms access
}

func (ch *CacheHierarchy) Get(key []byte) []byte {
    // L1: Memory cache
    if val := ch.l1.Get(key); val != nil {
        return val // <1ms
    }

    // L2: Disk cache
    if val := ch.l2.Get(key); val != nil {
        ch.l1.Set(key, val)
        return val // ~5ms
    }

    // L3: DHT (network)
    val := ch.l3.Get(key)
    ch.l2.Set(key, val)
    ch.l1.Set(key, val)
    return val // ~500ms
}

// With 90% cache hit rate:
// Average latency: 0.9 * 1ms + 0.1 * 500ms = 50.9ms
```

### Batched DHT Operations

```go
type BatchPublisher struct {
    buffer      []*Certificate
    maxBatch    int // 1000
    flushTimer  *time.Timer
}

func (bp *BatchPublisher) flush() {
    // Build Merkle tree of all certs in batch
    tree := NewMerkleTree(bp.buffer)

    // Single DHT put for entire batch
    dht.Put("cert-batch-"+tree.Root(), tree)

    bp.buffer = nil
}

// 10M certs/hour / 1000 = 10K DHT puts/hour
// 1000x reduction in DHT operations
```

### Bloom Filters

```go
type CertificateIndex struct {
    bloomFilter *bloom.BloomFilter // 1B capacity, 1% false positive
}

func (ci *CertificateIndex) Has(nodeID string) bool {
    // Fast local check (no network)
    if !ci.bloomFilter.Test([]byte(nodeID)) {
        return false // Definitely doesn't exist
    }
    // Maybe exists, check DHT
    return dht.Has(nodeID)
}

// Saves 99% of "not found" DHT lookups
```

### Connection Pooling

```go
type ConnectionPool struct {
    conns map[string]*grpc.ClientConn
    mu    sync.RWMutex
}

func (cp *ConnectionPool) Get(addr string) *grpc.ClientConn {
    cp.mu.RLock()
    conn, exists := cp.conns[addr]
    cp.mu.RUnlock()

    if exists {
        return conn // Reuse existing
    }

    cp.mu.Lock()
    conn, _ = grpc.Dial(addr)
    cp.conns[addr] = conn
    cp.mu.Unlock()

    return conn
}
```

### Hot Key Handling

Certain DHT keys experience disproportionately high access rates, creating hotspots that overwhelm the nodes responsible for those keys. The hot key detection and distribution system automatically identifies and mitigates these situations.

#### Hot Key Detection

```go
// pkg/dht/hot_key.go

// HotKeyDetector identifies keys with abnormally high request rates
type HotKeyDetector struct {
    requestCounts   map[string]*RequestCounter  // Per-key counters
    hotKeyThreshold int64                       // Requests/minute threshold
    windowSize      time.Duration               // Detection window
    mu              sync.RWMutex
}

const (
    // Hot key detection thresholds
    HotKeyThreshold      = 1000   // >1000 requests/minute = hot key
    HotKeyWindowSize     = 1 * time.Minute
    HotKeySampleRate     = 0.01   // Sample 1% of requests for counting
)

// RequestCounter tracks per-key request rates
type RequestCounter struct {
    Key           []byte
    Count         atomic.Int64
    WindowStart   time.Time
    IsHot         bool
    ReplicaCount  int
}

// RecordRequest samples and counts requests for hot key detection
func (d *HotKeyDetector) RecordRequest(key []byte) {
    // Probabilistic sampling to reduce overhead
    if rand.Float64() > HotKeySampleRate {
        return
    }

    keyStr := string(key)

    d.mu.Lock()
    counter, exists := d.requestCounts[keyStr]
    if !exists {
        counter = &RequestCounter{
            Key:         key,
            WindowStart: time.Now(),
        }
        d.requestCounts[keyStr] = counter
    }
    d.mu.Unlock()

    // Increment count (scaled by sample rate)
    counter.Count.Add(int64(1 / HotKeySampleRate))

    // Check if window expired
    if time.Since(counter.WindowStart) > d.windowSize {
        d.evaluateHotKey(counter)
    }
}

// evaluateHotKey determines if key exceeds hot threshold
func (d *HotKeyDetector) evaluateHotKey(counter *RequestCounter) {
    requestRate := counter.Count.Load()
    counter.Count.Store(0)
    counter.WindowStart = time.Now()

    if requestRate > d.hotKeyThreshold {
        if !counter.IsHot {
            counter.IsHot = true
            d.promoteToHotKey(counter)
        }
    } else if counter.IsHot && requestRate < d.hotKeyThreshold/2 {
        // Hysteresis: only demote when below 50% of threshold
        counter.IsHot = false
        d.demoteFromHotKey(counter)
    }
}
```

#### Aggressive Hot Key Replication

When a key is detected as hot, replication factor increases dramatically from standard (3 replicas) to aggressive (100 replicas).

```go
// pkg/dht/hot_replication.go

// HotKeyReplicator manages aggressive replication for hot keys
type HotKeyReplicator struct {
    dht             *DHT
    detector        *HotKeyDetector
    normalReplicas  int  // Standard replication factor (3)
    hotReplicas     int  // Hot key replication factor (100)
}

const (
    NormalReplicationFactor = 3    // Standard DHT replication
    HotKeyReplicationFactor = 100  // Aggressive replication for hot keys
)

// HotKeyConfig defines hot key handling parameters
type HotKeyConfig struct {
    DetectionThreshold  int64         // 1000 requests/minute
    NormalReplicas      int           // 3 replicas normally
    HotReplicas         int           // 100 replicas when hot
    CDNDistribution     bool          // Enable CDN-style distribution
    TieredStorage       bool          // Enable hot/warm/cold tiering
}

func DefaultHotKeyConfig() *HotKeyConfig {
    return &HotKeyConfig{
        DetectionThreshold: 1000,
        NormalReplicas:     3,
        HotReplicas:        100,
        CDNDistribution:    true,
        TieredStorage:      true,
    }
}

// PromoteToHotKey increases replication and distributes globally
func (r *HotKeyReplicator) PromoteToHotKey(key []byte, value []byte) error {
    log.Info("promoting to hot key",
        "key", hex.EncodeToString(key[:8]),
        "targetReplicas", r.hotReplicas)

    // Step 1: Find geographically diverse nodes for replication
    candidates := r.selectDiverseNodes(r.hotReplicas)

    // Step 2: Replicate to all selected nodes in parallel
    var wg sync.WaitGroup
    var successCount atomic.Int32

    for _, node := range candidates {
        wg.Add(1)
        go func(n *Contact) {
            defer wg.Done()
            if err := r.replicateToNode(n, key, value); err == nil {
                successCount.Add(1)
            }
        }(node)
    }

    wg.Wait()

    if successCount.Load() < int32(r.hotReplicas/2) {
        return &HotKeyReplicationError{
            Key:             key,
            TargetReplicas:  r.hotReplicas,
            ActualReplicas:  int(successCount.Load()),
        }
    }

    // Step 3: Update routing hints for hot key
    r.publishHotKeyRouting(key, candidates[:successCount.Load()])

    return nil
}

// selectDiverseNodes chooses nodes across regions for hot key distribution
func (r *HotKeyReplicator) selectDiverseNodes(count int) []*Contact {
    regions := r.dht.GetAllRegions()
    nodesPerRegion := count / len(regions)
    if nodesPerRegion < 1 {
        nodesPerRegion = 1
    }

    var selected []*Contact
    for _, region := range regions {
        regionNodes := r.dht.GetTopNodesByRegion(region, nodesPerRegion)
        selected = append(selected, regionNodes...)
        if len(selected) >= count {
            break
        }
    }

    return selected[:count]
}
```

#### CDN-Style Distribution for Coordinator Metadata

Coordinator metadata (governance records, epoch checkpoints, etc.) experiences consistently high access patterns. These are distributed using CDN-style edge caching.

```go
// pkg/dht/cdn_distribution.go

// CDNDistributor provides CDN-style distribution for critical metadata
type CDNDistributor struct {
    edgeCaches      map[RegionID]*EdgeCache
    originNodes     []NodeID  // Authoritative sources
    ttl             time.Duration
    refreshInterval time.Duration
}

const (
    CDNRefreshInterval = 30 * time.Second
    CDNEdgeTTL         = 5 * time.Minute
    CDNCacheSize       = 10000  // Entries per edge cache
)

// CoordinatorMetadataKeys lists keys that receive CDN treatment
var CoordinatorMetadataKeys = []string{
    "coordinator:list",           // Current coordinator set
    "epoch:current",              // Current epoch number
    "epoch:checkpoint:*",         // Epoch checkpoints
    "governance:proposals:active", // Active governance proposals
    "network:parameters",         // Network configuration
}

// DistributeToEdges pushes metadata to regional edge caches
func (d *CDNDistributor) DistributeToEdges(key []byte, value []byte) error {
    // Push to all regional edge caches in parallel
    var wg sync.WaitGroup
    var errors []error
    var mu sync.Mutex

    for regionID, cache := range d.edgeCaches {
        wg.Add(1)
        go func(r RegionID, c *EdgeCache) {
            defer wg.Done()
            if err := c.Set(key, value, d.ttl); err != nil {
                mu.Lock()
                errors = append(errors, fmt.Errorf("region %d: %w", r, err))
                mu.Unlock()
            }
        }(regionID, cache)
    }

    wg.Wait()

    if len(errors) > len(d.edgeCaches)/2 {
        return &CDNDistributionError{Errors: errors}
    }

    return nil
}

// GetFromNearestEdge retrieves from closest edge cache
func (d *CDNDistributor) GetFromNearestEdge(
    clientRegion RegionID,
    key []byte,
) ([]byte, error) {
    // Try local edge cache first
    if cache, exists := d.edgeCaches[clientRegion]; exists {
        if value, err := cache.Get(key); err == nil {
            return value, nil
        }
    }

    // Fall back to origin
    return d.getFromOrigin(key)
}
```

#### Tiered Storage for Access Frequency

Data is classified into hot, warm, and cold tiers based on access frequency, with different storage and caching strategies for each.

```go
// pkg/dht/tiered_storage.go

// TieredStorage manages data across hot/warm/cold tiers
type TieredStorage struct {
    hotTier    *HotStorage   // In-memory, <1ms access
    warmTier   *WarmStorage  // SSD, ~5ms access
    coldTier   *ColdStorage  // DHT network, ~500ms access
    classifier *AccessClassifier
}

// StorageTier represents data access frequency classification
type StorageTier string

const (
    TierHot  StorageTier = "hot"   // >100 accesses/hour
    TierWarm StorageTier = "warm"  // 10-100 accesses/hour
    TierCold StorageTier = "cold"  // <10 accesses/hour
)

// AccessClassifier determines storage tier based on access patterns
type AccessClassifier struct {
    accessCounts  map[string]*AccessStats
    hotThreshold  int64  // >100 accesses/hour
    warmThreshold int64  // >10 accesses/hour
}

const (
    HotTierThreshold  = 100  // Accesses per hour
    WarmTierThreshold = 10   // Accesses per hour
    ClassificationWindow = 1 * time.Hour
)

// ClassifyKey determines appropriate storage tier
func (c *AccessClassifier) ClassifyKey(key []byte) StorageTier {
    stats, exists := c.accessCounts[string(key)]
    if !exists {
        return TierCold  // Default to cold for unknown keys
    }

    hourlyRate := stats.HourlyAccessRate()
    switch {
    case hourlyRate > c.hotThreshold:
        return TierHot
    case hourlyRate > c.warmThreshold:
        return TierWarm
    default:
        return TierCold
    }
}

// PromoteKey moves data to higher-performance tier
func (ts *TieredStorage) PromoteKey(key []byte, targetTier StorageTier) error {
    // Get value from current location
    value, currentTier, err := ts.locateKey(key)
    if err != nil {
        return err
    }

    if tierPriority(targetTier) <= tierPriority(currentTier) {
        return nil  // Already in same or higher tier
    }

    // Copy to target tier
    switch targetTier {
    case TierHot:
        return ts.hotTier.Set(key, value)
    case TierWarm:
        return ts.warmTier.Set(key, value)
    default:
        return nil  // Cold tier is default DHT storage
    }
}

// DemoteKey moves data to lower-cost tier
func (ts *TieredStorage) DemoteKey(key []byte, targetTier StorageTier) error {
    switch targetTier {
    case TierWarm:
        // Move from hot to warm
        value, err := ts.hotTier.Get(key)
        if err != nil {
            return err
        }
        ts.hotTier.Delete(key)
        return ts.warmTier.Set(key, value)

    case TierCold:
        // Move from warm to cold (DHT)
        value, err := ts.warmTier.Get(key)
        if err != nil {
            return err
        }
        ts.warmTier.Delete(key)
        return ts.coldTier.Set(key, value)

    default:
        return ErrInvalidTierDemotion
    }
}
```

#### Hot Key Handling Summary

| Aspect | Normal Keys | Hot Keys |
|--------|------------|----------|
| Detection threshold | N/A | >1000 requests/minute |
| Replication factor | 3 replicas | 100 replicas |
| Distribution | Standard DHT | CDN-style edge caching |
| Storage tier | Cold (DHT network) | Hot (in-memory) |
| Access latency | ~500ms | <1ms |
| Geographic spread | K-closest nodes | All regions |

#### Hot Key Configuration

```yaml
# Hot key handling configuration
hot_key:
  detection:
    threshold_per_minute: 1000     # Requests triggering hot status
    sample_rate: 0.01              # 1% request sampling
    window_size: 1m                # Detection window

  replication:
    normal_factor: 3               # Standard replication
    hot_factor: 100                # Hot key replication
    geographic_diversity: true     # Spread across regions

  cdn_distribution:
    enabled: true                  # CDN-style distribution
    edge_ttl: 5m                   # Edge cache TTL
    refresh_interval: 30s          # Background refresh

  tiered_storage:
    enabled: true
    hot_threshold: 100             # Accesses/hour for hot tier
    warm_threshold: 10             # Accesses/hour for warm tier
```

---

## Network Efficiency at Scale

This section documents optimizations specifically designed for IPv6 /36 scale networks supporting billions of nodes.

### IPv6 /36 Capacity Analysis

```
2602:F5BB::/36 provides:
- 2^92 = 4.95 x 10^27 possible addresses
- Practically unlimited for any foreseeable network size

Allocation Strategy:
- /48 per region (65,536 regions possible)
- /64 per subnet (65,536 subnets per region)
- /128 per node (18 quintillion nodes per subnet)

DHT Parameters at Scale:
| Network Size | K  | Alpha | Lookup Hops | Lookup Latency |
|--------------|----|-------|-------------|----------------|
| 1M nodes     | 20 | 3     | ~20         | ~1s            |
| 100M nodes   | 20 | 3     | ~27         | ~1.4s          |
| 1B nodes     | 20 | 3     | ~30         | ~1.5s          |
| 10B nodes    | 20 | 5     | ~34         | ~1.4s (alpha=5)|
```

### Efficiency Optimizations

```go
// pkg/dht/efficiency.go

// NetworkEfficiencyOptimizations for IPv6 /36 scale (billions of nodes)
// Target: Handle 2602:F5BB::/36 (4.7 quintillion possible addresses)

// 1. Negative Caching - Cache "not found" results
type NegativeCache struct {
    cache    *lru.Cache  // LRU cache for not-found keys
    ttl      time.Duration // 5 minutes default
    maxSize  int           // 1M entries default
}

func (nc *NegativeCache) RecordNotFound(key []byte) {
    nc.cache.Add(string(key), time.Now())
}

func (nc *NegativeCache) IsKnownNotFound(key []byte) bool {
    if entry, ok := nc.cache.Get(string(key)); ok {
        if time.Since(entry.(time.Time)) < nc.ttl {
            return true // Skip DHT lookup
        }
        nc.cache.Remove(string(key))
    }
    return false
}

// Impact: 20-30% reduction in DHT lookups for non-existent keys

// 2. Message Batching - Combine multiple operations
type MessageBatcher struct {
    buffer     []*DHTMessage
    maxBatch   int           // 100 messages max
    maxDelay   time.Duration // 10ms max wait
    targetNode NodeID
}

func (mb *MessageBatcher) AddMessage(msg *DHTMessage) {
    mb.buffer = append(mb.buffer, msg)
    if len(mb.buffer) >= mb.maxBatch {
        mb.Flush()
    }
}

// Impact: 50-70% reduction in network round-trips

// 3. RTT-Aware Peer Selection
type RTTTracker struct {
    rtts     map[NodeID]time.Duration
    samples  map[NodeID][]time.Duration
    mu       sync.RWMutex
}

func (rt *RTTTracker) SelectFastestPeers(candidates []NodeID, count int) []NodeID {
    rt.mu.RLock()
    defer rt.mu.RUnlock()

    // Sort by RTT
    sort.Slice(candidates, func(i, j int) bool {
        return rt.rtts[candidates[i]] < rt.rtts[candidates[j]]
    })

    return candidates[:count]
}

// Impact: 20-35% reduction in lookup latency

// 4. Bloom Filters for Routing Tables
type RoutingBloomFilter struct {
    filter   *bloom.BloomFilter
    capacity int64  // 1B nodes
    fpRate   float64 // 1% false positive rate
}

func (rbf *RoutingBloomFilter) MayContain(nodeID NodeID) bool {
    return rbf.filter.Test(nodeID[:])
}

// Impact: 99% of "not in routing table" checks avoid full table scan

// 5. Erasure Coding for Replication
type ErasureCodingConfig struct {
    DataShards   int // 10
    ParityShards int // 4 (can recover from any 4 failures)
    // Storage efficiency: 10/14 = 71% (vs 300% for 3x replication)
}

// Impact: 60% reduction in storage overhead while maintaining durability
```

### Performance Impact Summary

| Optimization | Impact | Memory Cost | Implementation |
|--------------|--------|-------------|----------------|
| Negative Caching | -30% lookups | 100MB | Low |
| Message Batching | -60% RTTs | Minimal | Medium |
| RTT-Aware Selection | -30% latency | 10MB | Low |
| Bloom Filters | -99% table scans | 1GB | Low |
| Erasure Coding | -60% storage | CPU | High |

### Optimization Details

#### Negative Caching

Negative caching prevents repeated DHT lookups for keys that are known not to exist. At billion-node scale, a significant portion of lookups may be for non-existent keys (stale references, typos, or probing attacks). By caching negative results with a short TTL, nodes avoid wasting network resources on futile lookups.

**Configuration:**
- Default TTL: 5 minutes (balances freshness with efficiency)
- Default cache size: 1 million entries
- Memory overhead: ~100MB

#### Message Batching

Message batching combines multiple DHT operations destined for the same node into a single network round-trip. This is particularly effective for:
- Bulk node lookups during routing table refresh
- Batch certificate queries
- Replication operations

**Parameters:**
- Maximum batch size: 100 messages
- Maximum delay: 10ms (prevents latency spikes)
- Automatic flush on timeout or batch full

#### RTT-Aware Peer Selection

Instead of randomly selecting peers for parallel lookups, RTT-aware selection prioritizes nodes with historically lower latency. This reduces average lookup time without increasing network load.

**Implementation:**
- Maintains exponential moving average of RTT per peer
- Samples at least 5 RTTs before using in selection
- Falls back to random selection for new/unknown peers

#### Bloom Filters for Routing Tables

At billion-node scale, routing table operations become a bottleneck. Bloom filters provide O(1) membership testing with 1% false positive rate, eliminating 99% of unnecessary routing table scans.

**Sizing:**
- 1 billion node capacity
- 1% false positive rate
- ~1GB memory footprint
- Rebuilt during routing table refresh

#### Erasure Coding

Traditional 3x replication requires 300% storage overhead. Erasure coding with 10 data shards and 4 parity shards achieves the same durability (can survive any 4 node failures) with only 140% storage overhead.

**Trade-offs:**
- Pro: 60% reduction in storage requirements
- Pro: Same or better durability
- Con: Higher CPU usage for encoding/decoding
- Con: More complex recovery process

---

## Node Configuration

### Automatic Tier Assignment

Nodes are automatically assigned tiers based on capabilities and reputation.

```go
type NodeTier string

const (
    TierLeaf        NodeTier = "leaf"        // Default for all new nodes
    TierHub         NodeTier = "hub"         // Promoted automatically
    TierCoordinator NodeTier = "coordinator" // Top 1% nodes
)
```

> **See Also:** [09-defense-reputation.md](09-defense-reputation.md) for tier promotion criteria and thresholds.

### Tier Capabilities

**Leaf Nodes (Default, ~90% of network):**
- DHT storage: 10 GB
- DHT participation: limited (queries only)
- Routing: connects to hubs only
- Gateway: no (typically behind NAT)

**Hub Nodes (Promoted, ~9% of network):**
- DHT storage: 100 GB
- DHT participation: full (storage, routing, replication)
- Routing: participates in regional DHT
- Gateway: yes (if has public IP)

**Coordinator Nodes (Top 1%):**
- DHT storage: 1 TB+
- DHT participation: full + global DHT
- Routing: participates in global + regional DHT
- Gateway: yes (premium gateway)

### Node Configuration File

```yaml
# /etc/dht-node/config.yaml
# NOTE: Only node-specific settings (NOT protocol parameters)

node:
  id: auto
  private_key_path: /var/lib/dht-node/node.key

  listen_addr: "0.0.0.0:9999"
  public_ip: auto
  ipv6: auto

  storage:
    max_dht_storage: 100GB
    storage_path: /var/lib/dht-node/storage

  bandwidth:
    max_upload: 100Mbps
    max_download: 500Mbps

  capabilities:
    can_be_gateway: true
    can_announce_bgp: false
    tpm_available: true

  tier: auto # System determines based on reputation

  gateway:
    type: residential
    tunnel_endpoint: vpn.yourdomain.com:51820
    tunnel_type: wireguard
```

> **See Also:** [03-security-trust.md](03-security-trust.md) for protocol-level security constants that are NOT configurable.

---

## Distributed DDoS Protection

### Traffic Dilution

```
Traditional (Centralized):
Attacker -> 100 Gbps DDoS -> Single Target
Result: Target overwhelmed

Distributed (This Architecture):
Attacker -> 100 Gbps DDoS -> 2602:F5BB:0001::1234
Traffic distributed across 10,000 gateway nodes
Each gateway receives: 100 Gbps / 10,000 = 10 Mbps
Attack diluted, target protected
```

### Multi-Layer Defense

**Layer 1: Traffic Dilution**
- 10,000+ entry points instead of 1
- Attack traffic divided by number of gateways

**Layer 2: Edge Rate Limiting**
- Per-source-IP rate limits at each gateway
- Token bucket algorithm

**Layer 3: Proof-of-Work**
- Computational challenge for new connections
- Makes volumetric attacks expensive

**Layer 4: Reputation-Based Filtering**
- Track source IP reputation across gateways
- Higher reputation = higher rate limits

**Layer 5: Collaborative Threat Intelligence**
- Gateways share attack intelligence via DHT
- Attack detected by one gateway -> all gateways block

> **See Also:** [03-security-trust.md](03-security-trust.md) for security parameters and [09-defense-reputation.md](09-defense-reputation.md) for reputation thresholds.

---

## Website Hosting on P2P Network

### Content Storage in DHT

```go
type ContentBlock struct {
    Hash     [32]byte // SHA-256 of content
    Content  []byte   // Actual data (max 1MB per block)
    MimeType string   // "text/html", "image/png", etc.
    Size     uint64
}

func StoreWebsite(domain string, files map[string][]byte) error {
    manifest := &Manifest{
        Domain:  domain,
        Paths:   make(map[string][32]byte),
        Updated: time.Now(),
    }

    for path, content := range files {
        hash := sha256.Sum256(content)
        dht.Put(hash[:], ContentBlock{
            Hash:     hash,
            Content:  content,
            MimeType: mime.TypeByExtension(filepath.Ext(path)),
            Size:     uint64(len(content)),
        })
        manifest.Paths[path] = hash
    }

    manifestHash := sha256.Sum256(json.Marshal(manifest))
    dht.Put(manifestHash[:], manifest)
    dht.Put([]byte("website:"+domain), manifestHash[:])

    return nil
}
```

### HTTP Gateway

```go
type HTTPGateway struct {
    dht   *DHT
    cache *ContentCache
}

func (hg *HTTPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    domain := r.Host
    path := r.URL.Path

    // Look up manifest in DHT
    manifestHash := hg.dht.Get([]byte("website:" + domain))
    manifest := hg.dht.Get(manifestHash)

    // Get content hash for requested path
    contentHash := manifest.Paths[path]
    if contentHash == nil && path == "/" {
        contentHash = manifest.Paths["/index.html"]
    }

    // Retrieve content (with caching)
    content := hg.cache.Get(contentHash)
    if content == nil {
        content = hg.dht.Get(contentHash[:])
        hg.cache.Set(contentHash, content)
    }

    w.Header().Set("Content-Type", content.MimeType)
    w.Write(content.Content)
}
```

---

## Tiered Service Model

### Free Tier (P2P Routing)

- Full P2P network access
- IPv6 address from pool
- DHT storage (reasonable limits)
- Certificate issuance
- Routing via P2P gateways
- Basic DDoS protection
- Community support

**Routing:** Via volunteer gateway nodes, multi-hop P2P mesh

### Premium Tier (Backbone Routing)

- Routing via high-performance backbone
- Static IPv6 assignment
- DNS domain support
- CDN caching at gateway nodes
- Enhanced DDoS protection
- Priority CA signing
- Analytics and monitoring
- SLA (99.9% uptime)
- Dedicated support

**Routing:** Via backbone (low latency, direct paths)

---

## 11. SDN Integration for Network Isolation

The DHT network integrates with the platform's Software-Defined Networking (SDN) subsystem to provide hardware-level network isolation, 802.1X port-based authentication, and dynamic flow control. This integration enables zero-trust network segmentation where DHT nodes are isolated based on their enrollment state, trust level, and tenant membership.

> **Implementation:** See `pkg/sdn/` for the SDN controller, OpenFlow integration, and VLAN management.

### SDN Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SDN INTEGRATION ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ DHT Network  │◄──►│ SDN Controller│◄──►│Policy Engine │       │
│  │  (Overlay)   │    │  (pkg/sdn/)  │    │  (pkg/policy)│       │
│  └──────────────┘    └──────┬───────┘    └──────────────┘       │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │  OpenFlow 1.3   │                          │
│                    │   Controller    │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│       ┌─────────────────────┼─────────────────────┐             │
│       │                     │                     │             │
│  ┌────▼────┐          ┌────▼────┐          ┌────▼────┐         │
│  │ Switch  │          │ Switch  │          │ Switch  │         │
│  │  (OVS)  │          │  (OVS)  │          │  (OVS)  │         │
│  └────┬────┘          └────┬────┘          └────┬────┘         │
│       │                     │                     │             │
│  ┌────▼────┐          ┌────▼────┐          ┌────▼────┐         │
│  │  Nodes  │          │  Nodes  │          │  Nodes  │         │
│  │(VLAN X) │          │(VLAN Y) │          │(VLAN Z) │         │
│  └─────────┘          └─────────┘          └─────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

### VLAN-Based Network Isolation

The SDN subsystem uses IEEE 802.1Q VLANs to provide Layer 2 network isolation for DHT nodes. Nodes are dynamically assigned to VLANs based on their enrollment state, trust status, and tenant membership.

#### Reserved VLAN Assignments

| VLAN ID | Name | Purpose |
|---------|------|---------|
| 998 | Provisioning | New nodes during enrollment and attestation |
| 666 | Quarantine | Misbehaving nodes, failed attestation, or security incidents |
| 1-997 | Production | Per-tenant isolation (997 available tenant VLANs) |
| 999-4094 | Extended Production | Additional tenant VLANs for large deployments |

#### Provisioning VLAN (998)

New nodes joining the DHT network are initially placed in the Provisioning VLAN where they can only communicate with enrollment services:

```go
// pkg/sdn/vlan.go

const (
    VLANProvisioning = 998  // New nodes during enrollment
    VLANQuarantine   = 666  // Misbehaving or untrusted nodes
)

// ProvisioningVLANConfig defines allowed traffic in provisioning network
type ProvisioningVLANConfig struct {
    // Only allow communication with these services
    AllowedServices []string{
        "enrollment.platform.local:8443",   // Enrollment API
        "attestation.platform.local:8444",  // TPM attestation service
        "ca.platform.local:8445",           // Certificate authority
        "ntp.platform.local:123",           // Time synchronization
        "dns.platform.local:53",            // DNS resolution
    }

    // Block all other traffic
    DefaultPolicy: "deny"

    // Maximum time in provisioning before auto-quarantine
    MaxProvisioningTime: 1 * time.Hour
}

// OnNodeConnect handles new node connection to network
func (c *SDNController) OnNodeConnect(portID string, macAddr net.HardwareAddr) error {
    // Place node in provisioning VLAN by default
    if err := c.assignVLAN(portID, VLANProvisioning); err != nil {
        return &SDNError{Op: "assign_vlan", Err: err}
    }

    // Install restrictive flow rules
    flows := c.buildProvisioningFlows(portID, macAddr)
    return c.installFlows(flows)
}
```

#### Quarantine VLAN (666)

Nodes are moved to the Quarantine VLAN when they exhibit suspicious behavior, fail attestation, or are flagged by the reputation system:

```go
// pkg/sdn/quarantine.go

// QuarantineReasons defines why a node may be quarantined
type QuarantineReason string

const (
    QuarantineReasonAttestationFailure QuarantineReason = "attestation_failure"
    QuarantineReasonReputationDrop     QuarantineReason = "reputation_below_threshold"
    QuarantineReasonSecurityIncident   QuarantineReason = "security_incident"
    QuarantineReasonPolicyViolation    QuarantineReason = "policy_violation"
    QuarantineReasonManualReview       QuarantineReason = "manual_review_required"
)

// QuarantineNode moves a node to the quarantine VLAN
func (c *SDNController) QuarantineNode(nodeID NodeID, reason QuarantineReason) error {
    // Get node's current port assignment
    port, err := c.getNodePort(nodeID)
    if err != nil {
        return &SDNError{Op: "get_port", NodeID: nodeID, Err: err}
    }

    // Move to quarantine VLAN
    if err := c.assignVLAN(port.ID, VLANQuarantine); err != nil {
        return &SDNError{Op: "quarantine", NodeID: nodeID, Err: err}
    }

    // Install quarantine flow rules (very restrictive)
    flows := []OpenFlowRule{
        // Allow only health check from monitoring
        {
            Match:    Match{InPort: port.ID, EthType: IPv4, IPProto: TCP, DstPort: 9100},
            Actions:  []Action{Output{Port: ControllerPort}},
            Priority: 100,
        },
        // Drop all other traffic
        {
            Match:    Match{InPort: port.ID},
            Actions:  []Action{Drop{}},
            Priority: 1,
        },
    }

    if err := c.installFlows(flows); err != nil {
        return &SDNError{Op: "install_flows", NodeID: nodeID, Err: err}
    }

    // Publish quarantine event to DHT
    event := QuarantineEvent{
        NodeID:    nodeID,
        Reason:    reason,
        Timestamp: time.Now(),
        VLAN:      VLANQuarantine,
    }
    c.dht.Publish("node:quarantine:"+nodeID.String(), event)

    return nil
}
```

#### Production VLANs (Per-Tenant Isolation)

Production VLANs provide network-level isolation between tenants. Each service provider or organization receives a dedicated VLAN:

```go
// pkg/sdn/tenant.go

// TenantVLANManager handles per-tenant VLAN allocation
type TenantVLANManager struct {
    controller    *SDNController
    allocations   map[TenantID]uint16  // TenantID -> VLAN ID
    vlanPool      *VLANPool            // Available VLAN IDs
    mu            sync.RWMutex
}

// AllocateTenantVLAN assigns a VLAN to a new tenant
func (m *TenantVLANManager) AllocateTenantVLAN(tenantID TenantID) (uint16, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Check if tenant already has a VLAN
    if vlan, exists := m.allocations[tenantID]; exists {
        return vlan, nil
    }

    // Allocate from pool (1-997, 999-4094)
    vlan, err := m.vlanPool.Allocate()
    if err != nil {
        return 0, &VLANAllocationError{TenantID: tenantID, Err: err}
    }

    m.allocations[tenantID] = vlan

    // Configure VLAN on all switches
    if err := m.controller.createVLAN(vlan, tenantID.String()); err != nil {
        m.vlanPool.Release(vlan)
        delete(m.allocations, tenantID)
        return 0, err
    }

    return vlan, nil
}

// AssignNodeToTenant moves a node to tenant's production VLAN
func (m *TenantVLANManager) AssignNodeToTenant(nodeID NodeID, tenantID TenantID) error {
    vlan, err := m.GetTenantVLAN(tenantID)
    if err != nil {
        return err
    }

    port, err := m.controller.getNodePort(nodeID)
    if err != nil {
        return err
    }

    // Move from provisioning to production VLAN
    return m.controller.assignVLAN(port.ID, vlan)
}
```

### 802.1X Port-Based Authentication

DHT nodes authenticate to the network using 802.1X with EAP-TLS, presenting their platform-issued certificates for port-based access control:

```go
// pkg/sdn/dot1x.go

// Dot1XAuthenticator handles 802.1X authentication for DHT nodes
type Dot1XAuthenticator struct {
    radiusClient   *radius.Client
    caPool         *x509.CertPool    // Trusted platform CAs
    controller     *SDNController
    policyEngine   *PolicyEngine
}

// AuthenticateNode performs 802.1X authentication
func (a *Dot1XAuthenticator) AuthenticateNode(
    portID string,
    clientCert *x509.Certificate,
) (*AuthResult, error) {
    // Step 1: Validate certificate chain
    if err := a.validateCertificateChain(clientCert); err != nil {
        return &AuthResult{
            Success: false,
            Reason:  "certificate_validation_failed",
            Action:  ActionQuarantine,
        }, nil
    }

    // Step 2: Extract node identity from certificate
    nodeID, err := extractNodeID(clientCert)
    if err != nil {
        return &AuthResult{
            Success: false,
            Reason:  "invalid_node_identity",
            Action:  ActionQuarantine,
        }, nil
    }

    // Step 3: Check certificate revocation status
    if revoked, err := a.checkRevocation(clientCert); err != nil || revoked {
        return &AuthResult{
            Success: false,
            Reason:  "certificate_revoked",
            Action:  ActionQuarantine,
        }, nil
    }

    // Step 4: Query policy engine for VLAN assignment
    policy, err := a.policyEngine.GetNodePolicy(nodeID, clientCert)
    if err != nil {
        return &AuthResult{
            Success: false,
            Reason:  "policy_lookup_failed",
            Action:  ActionProvisioning,
        }, nil
    }

    // Step 5: Determine VLAN based on policy
    vlan := a.determineVLAN(nodeID, policy)

    return &AuthResult{
        Success:  true,
        NodeID:   nodeID,
        VLAN:     vlan,
        Policy:   policy,
        Action:   ActionAuthorize,
    }, nil
}

// determineVLAN selects appropriate VLAN based on node state
func (a *Dot1XAuthenticator) determineVLAN(nodeID NodeID, policy *NodePolicy) uint16 {
    // New nodes go to provisioning
    if policy.State == NodeStateNew {
        return VLANProvisioning
    }

    // Quarantined nodes stay in quarantine
    if policy.State == NodeStateQuarantined {
        return VLANQuarantine
    }

    // Active nodes go to their tenant VLAN
    if policy.TenantID != "" {
        vlan, _ := a.controller.tenantVLANManager.GetTenantVLAN(policy.TenantID)
        return vlan
    }

    // Default: provisioning until tenant assigned
    return VLANProvisioning
}
```

### OpenFlow 1.3 Integration

The SDN controller uses OpenFlow 1.3 to program switch flow tables for dynamic traffic control:

```go
// pkg/sdn/openflow.go

// OpenFlowController manages OpenFlow connections to switches
type OpenFlowController struct {
    switches    map[SwitchID]*OFSwitch
    flowCache   *FlowCache
    mu          sync.RWMutex
}

// InstallNodeFlows programs flow rules for a DHT node
func (c *OpenFlowController) InstallNodeFlows(
    nodeID NodeID,
    port uint32,
    vlan uint16,
    policy *NodePolicy,
) error {
    flows := make([]OpenFlowRule, 0)

    // Flow 1: Tag incoming traffic with VLAN
    flows = append(flows, OpenFlowRule{
        Table:    TableIngress,
        Priority: 1000,
        Match: Match{
            InPort:  port,
            EthType: EthTypeAll,
        },
        Actions: []Action{
            PushVLAN{EtherType: 0x8100},
            SetField{Field: VLANVid, Value: vlan},
            GotoTable{Table: TableACL},
        },
    })

    // Flow 2: Apply policy-based ACLs
    for _, rule := range policy.ACLRules {
        flows = append(flows, c.buildACLFlow(port, vlan, rule))
    }

    // Flow 3: Allow DHT protocol traffic within VLAN
    flows = append(flows, OpenFlowRule{
        Table:    TableACL,
        Priority: 500,
        Match: Match{
            VLANVid: vlan,
            EthType: IPv6,
            IPProto: UDP,
            DstPort: DHTPort,
        },
        Actions: []Action{
            GotoTable{Table: TableForwarding},
        },
    })

    // Flow 4: Allow mTLS traffic within VLAN
    flows = append(flows, OpenFlowRule{
        Table:    TableACL,
        Priority: 500,
        Match: Match{
            VLANVid: vlan,
            EthType: IPv6,
            IPProto: TCP,
            DstPort: MTLSPort,
        },
        Actions: []Action{
            GotoTable{Table: TableForwarding},
        },
    })

    // Flow 5: Default deny for this port
    flows = append(flows, OpenFlowRule{
        Table:    TableACL,
        Priority: 1,
        Match: Match{
            InPort: port,
        },
        Actions: []Action{
            Drop{},
        },
    })

    return c.installFlowBatch(flows)
}

// HandleNodeStateChange updates flows when node state changes
func (c *OpenFlowController) HandleNodeStateChange(
    nodeID NodeID,
    oldState NodeState,
    newState NodeState,
    newVLAN uint16,
) error {
    port, err := c.getNodePort(nodeID)
    if err != nil {
        return err
    }

    // Delete old flows
    if err := c.deleteNodeFlows(nodeID); err != nil {
        return err
    }

    // Get updated policy
    policy, err := c.policyEngine.GetNodePolicy(nodeID, nil)
    if err != nil {
        return err
    }

    // Install new flows for new VLAN
    return c.InstallNodeFlows(nodeID, port, newVLAN, policy)
}
```

### Policy Engine Integration

The SDN controller integrates with the platform's policy engine to make certificate-based access control decisions:

```go
// pkg/sdn/policy_integration.go

// PolicySDNIntegration bridges policy engine and SDN controller
type PolicySDNIntegration struct {
    policyEngine  *policy.Engine
    sdnController *SDNController
    dht           DHT
}

// EvaluateNetworkAccess determines network access based on certificate attributes
func (p *PolicySDNIntegration) EvaluateNetworkAccess(
    nodeID NodeID,
    cert *x509.Certificate,
) (*NetworkAccessDecision, error) {
    // Extract policy-relevant attributes from certificate
    attrs := p.extractCertAttributes(cert)

    // Build policy evaluation request
    req := &policy.EvaluationRequest{
        Subject: policy.Subject{
            NodeID:      nodeID.String(),
            Certificate: cert,
            Attributes:  attrs,
        },
        Resource: policy.Resource{
            Type: "network",
            ID:   "dht-overlay",
        },
        Action: "connect",
    }

    // Evaluate against policy rules
    decision, err := p.policyEngine.Evaluate(req)
    if err != nil {
        return nil, &PolicyEvaluationError{NodeID: nodeID, Err: err}
    }

    // Map policy decision to network access
    return &NetworkAccessDecision{
        Allowed:    decision.Effect == policy.EffectAllow,
        VLAN:       p.mapPolicyToVLAN(decision),
        ACLRules:   p.extractACLRules(decision),
        Expiration: decision.Expiration,
    }, nil
}

// mapPolicyToVLAN determines VLAN based on policy attributes
func (p *PolicySDNIntegration) mapPolicyToVLAN(decision *policy.Decision) uint16 {
    // Check for explicit VLAN assignment in policy
    if vlanAttr, ok := decision.Attributes["network.vlan"]; ok {
        return uint16(vlanAttr.(int))
    }

    // Check trust level
    trustLevel := decision.Attributes["trust.level"].(string)
    switch trustLevel {
    case "untrusted":
        return VLANQuarantine
    case "pending":
        return VLANProvisioning
    case "trusted":
        // Get tenant VLAN
        tenantID := decision.Attributes["tenant.id"].(string)
        vlan, _ := p.sdnController.tenantVLANManager.GetTenantVLAN(TenantID(tenantID))
        return vlan
    default:
        return VLANProvisioning
    }
}

// OnPolicyChange handles policy updates affecting network access
func (p *PolicySDNIntegration) OnPolicyChange(policyID string) error {
    // Get all nodes affected by this policy
    affectedNodes, err := p.policyEngine.GetAffectedNodes(policyID)
    if err != nil {
        return err
    }

    // Re-evaluate network access for each affected node
    for _, nodeID := range affectedNodes {
        cert, err := p.getNodeCertificate(nodeID)
        if err != nil {
            continue // Skip nodes without valid certificates
        }

        decision, err := p.EvaluateNetworkAccess(nodeID, cert)
        if err != nil {
            continue
        }

        // Update SDN configuration
        currentVLAN, _ := p.sdnController.getNodeVLAN(nodeID)
        if currentVLAN != decision.VLAN {
            p.sdnController.moveNodeToVLAN(nodeID, decision.VLAN)
        }
    }

    return nil
}
```

### Service Provider VLAN Isolation

Service providers can use VLANs to isolate their clients while still participating in the shared DHT network:

```go
// pkg/sdn/service_provider.go

// ServiceProviderNetworkConfig defines network isolation for a service provider
type ServiceProviderNetworkConfig struct {
    ProviderID       TenantID
    ManagementVLAN   uint16           // Provider's management network
    ClientVLANs      map[ClientID]uint16  // Per-client VLANs
    SharedServices   []string         // Services accessible across client VLANs
}

// ConfigureServiceProviderNetwork sets up network isolation for SP clients
func (c *SDNController) ConfigureServiceProviderNetwork(
    config *ServiceProviderNetworkConfig,
) error {
    // Create management VLAN for provider
    if err := c.createVLAN(config.ManagementVLAN, config.ProviderID.String()+"-mgmt"); err != nil {
        return err
    }

    // Create client VLANs
    for clientID, vlan := range config.ClientVLANs {
        if err := c.createVLAN(vlan, clientID.String()); err != nil {
            return err
        }

        // Install inter-VLAN routing rules for shared services
        for _, service := range config.SharedServices {
            if err := c.allowServiceAccess(vlan, config.ManagementVLAN, service); err != nil {
                return err
            }
        }
    }

    // Install isolation rules (clients cannot reach each other)
    for clientA, vlanA := range config.ClientVLANs {
        for clientB, vlanB := range config.ClientVLANs {
            if clientA != clientB {
                if err := c.blockInterVLAN(vlanA, vlanB); err != nil {
                    return err
                }
            }
        }
    }

    return nil
}

// allowServiceAccess permits traffic from client VLAN to specific service
func (c *SDNController) allowServiceAccess(
    clientVLAN uint16,
    serviceVLAN uint16,
    serviceEndpoint string,
) error {
    host, port, _ := net.SplitHostPort(serviceEndpoint)
    dstPort, _ := strconv.Atoi(port)

    // Resolve service IP
    serviceIP := net.ParseIP(host)

    flows := []OpenFlowRule{
        // Allow client -> service
        {
            Table:    TableACL,
            Priority: 600,
            Match: Match{
                VLANVid: clientVLAN,
                EthType: IPv4,
                IPProto: TCP,
                DstIP:   serviceIP,
                DstPort: uint16(dstPort),
            },
            Actions: []Action{
                SetField{Field: VLANVid, Value: serviceVLAN},
                GotoTable{Table: TableForwarding},
            },
        },
        // Allow service -> client (return traffic)
        {
            Table:    TableACL,
            Priority: 600,
            Match: Match{
                VLANVid: serviceVLAN,
                EthType: IPv4,
                IPProto: TCP,
                SrcIP:   serviceIP,
                SrcPort: uint16(dstPort),
            },
            Actions: []Action{
                // Destination VLAN determined by L2 lookup
                GotoTable{Table: TableForwarding},
            },
        },
    }

    return c.installFlowBatch(flows)
}
```

### Node Lifecycle and VLAN Transitions

```
┌─────────────────────────────────────────────────────────────────┐
│                   NODE VLAN LIFECYCLE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐                                               │
│   │ Node Boots  │                                               │
│   │  (No VLAN)  │                                               │
│   └──────┬──────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌─────────────────┐     802.1X Auth     ┌────────────────┐    │
│   │  Provisioning   │◄────────────────────│  New Node      │    │
│   │   VLAN (998)    │      Success        │  Connects      │    │
│   └────────┬────────┘                     └────────────────┘    │
│            │                                                     │
│            │ TPM Attestation                                     │
│            │ + Certificate Issued                                │
│            │                                                     │
│            ▼                                                     │
│   ┌─────────────────┐                                           │
│   │  Tenant Assigned│                                           │
│   │  Policy Applied │                                           │
│   └────────┬────────┘                                           │
│            │                                                     │
│            ▼                                                     │
│   ┌─────────────────┐                                           │
│   │   Production    │◄──── Normal Operation ────────────────┐   │
│   │  VLAN (1-997)   │                                       │   │
│   └────────┬────────┘                                       │   │
│            │                                                 │   │
│            │ Attestation Failure                             │   │
│            │ OR Reputation Drop                              │   │
│            │ OR Security Incident                            │   │
│            │                                                 │   │
│            ▼                                                 │   │
│   ┌─────────────────┐     Remediation      ┌────────────────┘   │
│   │   Quarantine    │─────────────────────►│                    │
│   │   VLAN (666)    │     Complete         │                    │
│   └─────────────────┘                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### SDN Configuration Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| OpenFlow Version | 1.3 | Protocol version for switch control |
| Flow Idle Timeout | 300s | Flows expire after 5 minutes idle |
| Flow Hard Timeout | 3600s | Maximum flow lifetime (1 hour) |
| Table 0 (Ingress) | VLAN tagging | Tags untagged traffic |
| Table 1 (ACL) | Access control | Policy-based filtering |
| Table 2 (Forwarding) | L2/L3 forwarding | MAC/IP-based switching |
| 802.1X Reauth Period | 3600s | Re-authenticate every hour |
| VLAN Pool Range | 1-997, 999-4094 | Available for tenant allocation |

### VLAN Security Hardening

VLAN isolation alone is insufficient to prevent sophisticated attacks such as MAC spoofing, VLAN hopping, and ARP poisoning. The SDN controller implements comprehensive Layer 2 security controls that bind network access to cryptographic node identity through the IDevID certificate.

```go
// pkg/sdn/vlan_security.go

// VLANSecurityConfig hardens VLAN isolation against bypass attacks
type VLANSecurityConfig struct {
    // MAC address authentication - bind MAC to IDevID certificate
    EnableMACAuthentication  bool

    // Anti-spoofing measures
    EnableIPSourceGuard      bool  // Verify IP-MAC binding
    EnableDHCPSnooping       bool  // Track DHCP assignments
    EnableDynamicARPInspection bool  // Validate ARP packets

    // Physical port binding
    EnablePortSecurity       bool
    MaxMACPerPort            int    // Default: 1

    // Storm control
    BroadcastStormThreshold  uint64 // pps before blocking
    MulticastStormThreshold  uint64
    UnknownUnicastThreshold  uint64
}

const (
    DefaultMaxMACPerPort         = 1
    DefaultBroadcastStormPPS     = 1000
    DefaultMulticastStormPPS     = 500
    DefaultUnknownUnicastStormPPS = 500
)

// PortSecurityBinding ties MAC address to node identity
type PortSecurityBinding struct {
    PortID          string
    AllowedMAC      net.HardwareAddr
    BoundNodeID     NodeID
    IDevIDCertHash  [32]byte  // MAC must match cert subject
    VLANAssignment  uint16
    LastVerified    time.Time
}

// ValidateMACBinding verifies MAC address matches IDevID certificate
func (c *SDNController) ValidateMACBinding(portID string, macAddr net.HardwareAddr) error {
    binding, exists := c.portBindings[portID]
    if !exists {
        // New port - establish binding during 802.1X auth
        return ErrPortNotBound
    }

    if !bytes.Equal(binding.AllowedMAC, macAddr) {
        // MAC spoofing attempt detected
        c.triggerSecurityAlert(&SecurityAlert{
            Type:      AlertMACSpoof,
            PortID:    portID,
            ExpectedMAC: binding.AllowedMAC,
            ActualMAC:   macAddr,
            Timestamp:   time.Now(),
        })

        // Immediately quarantine port
        c.quarantinePort(portID, QuarantineReasonMACSpoof)
        return ErrMACSpoofingDetected
    }

    return nil
}

// InstallAntiSpoofFlows programs OpenFlow rules to prevent VLAN bypass
func (c *SDNController) InstallAntiSpoofFlows(portID string, binding *PortSecurityBinding) error {
    flows := []OpenFlowRule{
        // Drop any frame with spoofed MAC
        {
            Table:    TableIngress,
            Priority: 10000, // Highest priority
            Match: Match{
                InPort:     portID,
                EthSrc:     Not(binding.AllowedMAC), // NOT the bound MAC
            },
            Actions: []Action{
                Drop{},
                SendToController{Reason: "mac_violation"},
            },
        },
        // Drop VLAN-tagged frames on access ports (VLAN hopping prevention)
        {
            Table:    TableIngress,
            Priority: 9999,
            Match: Match{
                InPort:  portID,
                VLANVid: AnyVLAN, // Has VLAN tag
            },
            Actions: []Action{
                Drop{},
                SendToController{Reason: "vlan_hopping_attempt"},
            },
        },
        // IP source guard - drop packets with wrong source IP
        {
            Table:    TableIngress,
            Priority: 9998,
            Match: Match{
                InPort:  portID,
                EthType: IPv4,
                IPSrc:   Not(binding.AllowedIP),
            },
            Actions: []Action{
                Drop{},
                SendToController{Reason: "ip_spoof_attempt"},
            },
        },
    }

    return c.installFlowBatch(flows)
}
```

**VLAN Security Parameters:**

| Security Control | Default Value | Description |
|------------------|---------------|-------------|
| MAC Authentication | **Enabled** | Bind MAC to IDevID certificate |
| IP Source Guard | **Enabled** | Verify source IP matches DHCP binding |
| DHCP Snooping | **Enabled** | Track IP-MAC assignments |
| Dynamic ARP Inspection | **Enabled** | Validate ARP packets |
| Port Security | **Enabled** | Max 1 MAC per port |
| Broadcast Storm Control | 1000 pps | Block broadcast floods |
| VLAN Hopping Prevention | **Enabled** | Drop tagged frames on access ports |

> **See Also:**
> - [03-security-trust.md](03-security-trust.md) for certificate-based authentication
> - [09-defense-reputation.md](09-defense-reputation.md) for reputation-triggered quarantine

---

## Split-Brain Detection - FINAL DESIGN

Network partitions can result in multiple isolated sub-networks, each believing they are the canonical network. Split-brain detection ensures deterministic resolution when the network fragments.

### Partition Detection

**Coordinator Quorum Loss:**
- Network partition detected when <7 of 21 coordinators are reachable
- Each partition computes its own partition identity
- Partition ID = SHA256(sorted list of reachable coordinator public keys)

**Canonical Partition Selection:**
- Partition with higher Partition ID (numerically) is canonical
- Selection is deterministic: all nodes compute same result
- Minority partitions enter read-only mode

### Minority Partition Behavior

**Read-Only Mode:**
- No new transactions accepted
- Transaction submissions return error: "minority partition, read-only mode"
- No role promotions allowed (no new coordinators, no new gateways)
- DHT reads allowed, writes rejected

**Client Notification:**
```json
{
  "error": "minority_partition",
  "message": "Node is in minority partition, no writes allowed",
  "partition_id": "a3f5...",
  "coordinator_count": 6,
  "required_quorum": 11,
  "estimated_healing": "unknown"
}
```

### Healing Protocol

**Reconnection Detection:**
- Partitions monitor coordinator reachability continuously
- When connectivity improves, partitions detect each other
- Healing begins when combined coordinator count reaches quorum (11+)

**State Reconciliation:**
- Minority partition replays missed epochs from majority
- Majority partition state is canonical
- Minority discards conflicting local state
- Checkpoint synchronization from majority to minority

```go
// Split-brain detector
type SplitBrainDetector struct {
    localCoordinators  [][32]byte      // Reachable coordinators
    totalCoordinators  [][32]byte      // All known coordinators (21)
    partitionID        [32]byte        // SHA256(sorted coordinator keys)
    isCanonical        bool            // Is this the canonical partition?
    mu                 sync.RWMutex
}

// DetectPartition computes partition state
func (sbd *SplitBrainDetector) DetectPartition() (*PartitionState, error) {
    sbd.mu.Lock()
    defer sbd.mu.Unlock()

    reachable := len(sbd.localCoordinators)
    quorumSize := (len(sbd.totalCoordinators) / 2) + 1 // 11 for 21 coordinators

    if reachable < quorumSize {
        // Partition detected
        partitionID := computePartitionID(sbd.localCoordinators)
        sbd.partitionID = partitionID

        return &PartitionState{
            Partitioned:     true,
            PartitionID:     partitionID,
            CoordinatorCount: reachable,
            QuorumSize:      quorumSize,
            IsCanonical:     false, // Determined by comparing with other partitions
        }, nil
    }

    // No partition, have quorum
    return &PartitionState{
        Partitioned:     false,
        CoordinatorCount: reachable,
        QuorumSize:      quorumSize,
        IsCanonical:     true,
    }, nil
}

// computePartitionID creates deterministic partition identifier
func computePartitionID(coordinators [][32]byte) [32]byte {
    // Sort coordinators deterministically
    sorted := make([][32]byte, len(coordinators))
    copy(sorted, coordinators)
    sort.Slice(sorted, func(i, j int) bool {
        return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
    })

    // Hash sorted list
    h := sha256.New()
    for _, coordinator := range sorted {
        h.Write(coordinator[:])
    }
    return sha256.Sum256(h.Sum(nil))
}

// DetermineCanonicalPartition compares partition IDs from two partitions
func DetermineCanonicalPartition(
    localPartitionID [32]byte,
    remotePartitionID [32]byte,
) bool {
    // Higher ID wins (deterministic)
    comparison := bytes.Compare(localPartitionID[:], remotePartitionID[:])
    return comparison > 0
}

// HealPartition synchronizes state from canonical to minority
func (sbd *SplitBrainDetector) HealPartition(
    ctx context.Context,
    canonicalPartition *PartitionInfo,
) error {
    if sbd.isCanonical {
        // We are canonical, nothing to do
        return nil
    }

    log.Info("healing from canonical partition",
        "localPartitionID", hex.EncodeToString(sbd.partitionID[:8]),
        "canonicalPartitionID", hex.EncodeToString(canonicalPartition.ID[:8]))

    // Step 1: Request epoch range we missed
    localEpoch := getCurrentEpoch()
    canonicalEpoch := canonicalPartition.CurrentEpoch

    if canonicalEpoch <= localEpoch {
        // No state to catch up
        return nil
    }

    // Step 2: Fetch missing epochs from canonical partition
    for epoch := localEpoch + 1; epoch <= canonicalEpoch; epoch++ {
        epochData, err := fetchEpochFromCanonical(ctx, canonicalPartition, epoch)
        if err != nil {
            return fmt.Errorf("fetching epoch %d: %w", epoch, err)
        }

        // Step 3: Validate epoch data
        if err := validateEpochData(epochData); err != nil {
            return fmt.Errorf("validating epoch %d: %w", epoch, err)
        }

        // Step 4: Apply epoch to local state
        if err := applyEpoch(epochData); err != nil {
            return fmt.Errorf("applying epoch %d: %w", epoch, err)
        }
    }

    // Step 5: Transition to normal mode
    sbd.mu.Lock()
    sbd.isCanonical = true // Rejoined canonical partition
    sbd.mu.Unlock()

    log.Info("partition healing complete",
        "catchupEpochs", canonicalEpoch-localEpoch)

    return nil
}
```

### Split-Brain Summary

| Condition | Coordinator Count | Behavior |
|-----------|-------------------|----------|
| **Healthy Network** | 11+ reachable (quorum) | Normal operation, full write access |
| **Majority Partition** | 11+ (>50%) | Canonical partition, continue operating |
| **Minority Partition** | <11 (<50%) | Read-only mode, no new transactions |
| **Healing** | Partitions reconnect | Minority replays epochs from majority |

**Security Properties:**
- Deterministic canonical selection (same inputs always yield same result)
- Minority partitions cannot create conflicting state
- Healing is one-directional: minority adopts majority state
- No manual intervention required for standard split-brain scenarios

> **Cross-Reference:** See [11-operations.md](11-operations.md) for three-way partition handling and VRF-based tie-breaking.

---

## Summary

This network architecture provides:

- **Publicly routable IPv6** (2602:F5BB::/36 announced globally)
- **Distributed routing** (backbone OR P2P gateways OR direct)
- **DDoS protection** (distributed across 1000s of gateways)
- **Scalable** (O(log n) DHT, billions of nodes)
- **Self-organizing** (emergent hierarchy, reputation-based)
- **Leverage all nodes** (every node's bandwidth contributes)
- **Multi-path redundancy** (multiple routing options)

---

## Related Documents

- [03-security-trust.md](03-security-trust.md) - Security parameters, cryptographic constants, TPM attestation
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system, gateway promotion, Sybil defense
- [04-certificate-authority.md](04-certificate-authority.md) - FROST threshold CA architecture
- [11-operations.md](11-operations.md) - Partition handling, three-way partitions, VRF tie-breaking

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.2 | 2026-01-10 | Added DHT routing optimizations, eclipse attack prevention, BGP route aggregation, hot key handling |
| 1.1 | 2026-01-10 | FINAL DESIGN: IPv6 collision handling, BGP route withdrawal, gateway demotion protocol, split-brain detection |
| 1.0 | (original) | Initial network architecture specification |

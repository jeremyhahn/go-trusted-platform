# BGP Transit Mode

## Overview

Transit mode enables gateway nodes to announce platform-owned IP prefixes to the global routing table via BGP. Transit gateways serve as eBGP speakers, announcing the platform's IPv6 (/36) and IPv4 (/24) address blocks to upstream ISPs, enabling publicly routable addresses for all nodes in the trusted network.

## IP Block Announcements

### IPv6 Allocation: 2602:F5BB::/36

| Block | CIDR | Purpose | Announcement Level |
|-------|------|---------|-------------------|
| Full Aggregate | 2602:F5BB::/36 | Platform aggregate | Backbone speakers only |
| Regional | 2602:F5BB:XXXX::/48 | Regional prefix | Datacenter speakers |
| Subnet | 2602:F5BB:XXXX:YYYY::/64 | Host subnets | Internal only (not announced) |

### IPv6 Hierarchy

```
2602:F5BB::/36 (Platform Aggregate - 4.7 quintillion addresses)
|
+-- 2602:F5BB:0000::/40 (Region 0 - North America East)
|   +-- 2602:F5BB:0000::/48 (Datacenter 1)
|   |   +-- 2602:F5BB:0000:0001::/64 (Subnet 1)
|   |   +-- 2602:F5BB:0000:0002::/64 (Subnet 2)
|   +-- 2602:F5BB:0001::/48 (Datacenter 2)
|
+-- 2602:F5BB:0100::/40 (Region 1 - North America West)
+-- 2602:F5BB:0200::/40 (Region 2 - Europe West)
+-- 2602:F5BB:0300::/40 (Region 3 - Europe East)
+-- 2602:F5BB:0400::/40 (Region 4 - Asia Pacific North)
+-- 2602:F5BB:0500::/40 (Region 5 - Asia Pacific South)
+-- ... (up to 16 regions with /40 aggregates)
```

### IPv4 Allocation: 23.143.36.0/24

| Block | CIDR | Purpose | Notes |
|-------|------|---------|-------|
| Platform | 23.143.36.0/24 | Legacy IPv4 connectivity | 254 usable addresses |

IPv4 is used sparingly for:
- Gateway nodes requiring IPv4 reachability
- Legacy system compatibility
- NAT64 translation endpoints

## Route Announcement Architecture

### Speaker Hierarchy

```
+------------------------------------------------------------------+
|                  ROUTE ANNOUNCEMENT HIERARCHY                      |
+------------------------------------------------------------------+
|                                                                   |
|  Level 1: Backbone Speakers (Global)                              |
|  +--------------------------------------------------------------+ |
|  | Announce to ISPs:                                            | |
|  |   - 2602:F5BB::/36 (aggregate)                               | |
|  |   - 23.143.36.0/24 (IPv4)                                    | |
|  |                                                               | |
|  | Requirements:                                                 | |
|  |   - Reputation >= 0.95 (Coordinator tier)                    | |
|  |   - Direct ISP peering                                       | |
|  |   - Coordinator signature for routes                          | |
|  |                                                               | |
|  | Suppress: All more-specific routes                            | |
|  +--------------------------------------------------------------+ |
|                           |                                       |
|                           | iBGP                                  |
|                           v                                       |
|  Level 2: Datacenter Speakers (Regional)                          |
|  +--------------------------------------------------------------+ |
|  | Announce to Backbone (iBGP):                                 | |
|  |   - 2602:F5BB:XXXX::/48 (Regional)                          | |
|  |                                                               | |
|  | Requirements:                                                 | |
|  |   - Reputation >= 0.85 (Gateway tier)                        | |
|  |   - Route signing from coordinators                          | |
|  |                                                               | |
|  | Suppress: /64 subnets (internal only)                        | |
|  +--------------------------------------------------------------+ |
|                           |                                       |
|                           | Internal                               |
|                           v                                       |
|  Level 3: Internal Routing (Subnets)                              |
|  +--------------------------------------------------------------+ |
|  | Internal FIB only:                                           | |
|  |   - 2602:F5BB:XXXX:YYYY::/64 (Subnets)                      | |
|  |                                                               | |
|  | Not announced externally                                      | |
|  +--------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### ISP Peering Configuration

```go
// ISPPeerConfig defines eBGP peer to upstream ISP
type ISPPeerConfig struct {
    Name        string
    Address     netip.Addr
    RemoteAS    uint32
    LocalAS     uint32
    Type        PeerType
    MD5Secret   string
    Families    []AddressFamily
    Policies    PeerPolicies
}

// Example: Primary ISP peer
func (t *TransitState) ConfigurePrimaryISP() *ISPPeerConfig {
    return &ISPPeerConfig{
        Name:      "ISP-Primary",
        Address:   netip.MustParseAddr("198.51.100.1"),
        RemoteAS:  64500,
        LocalAS:   t.config.ASN,
        Type:      PeerTypeEBGP,
        MD5Secret: t.config.ISPSecrets["primary"],
        Families: []AddressFamily{
            {AFI: AFI_IPv4, SAFI: SAFI_Unicast},
            {AFI: AFI_IPv6, SAFI: SAFI_Unicast},
        },
        Policies: PeerPolicies{
            ExportPolicy: "export-to-isp",
            ImportPolicy: "import-from-isp",
        },
    }
}

// Export policy: Only announce aggregates
func (t *TransitState) ExportPolicy() *RoutingPolicy {
    return &RoutingPolicy{
        Name: "export-to-isp",
        Statements: []PolicyStatement{
            {
                Conditions: MatchConditions{
                    PrefixList: "platform-aggregates",
                },
                Actions: PolicyActions{
                    Accept:       true,
                    SetCommunity: []string{fmt.Sprintf("%d:100", t.config.ASN)},
                },
            },
            {
                // Default: reject all others
                Actions: PolicyActions{Accept: false},
            },
        },
    }
}
```

## RPKI Validation

Resource Public Key Infrastructure (RPKI) validates that route announcements originate from authorized ASNs.

### RPKI Validation Flow

```
+------------------------------------------------------------------+
|                    RPKI VALIDATION FLOW                            |
+------------------------------------------------------------------+
|                                                                   |
|  1. Create ROA (Route Origin Authorization)                       |
|     +----------------------------------------------------------+ |
|     | Prefix: 2602:F5BB::/36                                   | |
|     | Max Length: /48                                           | |
|     | Origin ASN: 65001 (platform ASN)                         | |
|     | Signed by: ARIN (Regional Internet Registry)             | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. Publish to RPKI Repository                                    |
|     +----------------------------------------------------------+ |
|     | rsync://rpki.arin.net/repository/                        | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  3. BGP Speaker Validates Received Routes                         |
|     +----------------------------------------------------------+ |
|     | Route: 2602:F5BB::/36 from AS 65001                      | |
|     |                                                          | |
|     | Lookup ROA:                                              | |
|     |   - Prefix matches: Yes                                  | |
|     |   - Length <= Max: Yes (/36 <= /48)                     | |
|     |   - ASN matches: Yes (65001)                            | |
|     |                                                          | |
|     | Result: VALID                                            | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  4. Apply RPKI Policy                                             |
|     +----------------------------------------------------------+ |
|     | - VALID: Accept with preference                          | |
|     | - NOT_FOUND: Accept (no ROA exists)                      | |
|     | - INVALID: Reject                                        | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### RPKI Implementation

```go
// RPKIValidator validates routes against RPKI
type RPKIValidator struct {
    servers     []RPKIServer
    cache       *RPKICache
    policy      RPKIPolicy
    refreshInterval time.Duration
}

type RPKIServer struct {
    Address string
    Port    uint16
    Prefer  bool
}

type RPKIPolicy struct {
    ValidAction    PolicyAction  // Accept with preference
    InvalidAction  PolicyAction  // Reject
    NotFoundAction PolicyAction  // Accept (no ROA)
}

// Validate checks route against RPKI
func (v *RPKIValidator) Validate(prefix netip.Prefix, originAS uint32) RPKIStatus {
    roas := v.cache.LookupROAs(prefix)

    if len(roas) == 0 {
        return RPKIStatusNotFound
    }

    for _, roa := range roas {
        if roa.ASN == originAS && prefix.Bits() <= roa.MaxLength {
            return RPKIStatusValid
        }
    }

    return RPKIStatusInvalid
}

// CreateROA creates and publishes a ROA
func (t *TransitState) CreateROA(ctx context.Context, prefix netip.Prefix, maxLen int) error {
    roa := &ROA{
        Prefix:    prefix,
        MaxLength: maxLen,
        ASN:       t.config.ASN,
        ValidFrom: time.Now(),
        ValidTo:   time.Now().AddDate(1, 0, 0), // 1 year
    }

    // Sign with platform CA
    signed, err := t.caClient.SignROA(ctx, roa)
    if err != nil {
        return fmt.Errorf("sign ROA: %w", err)
    }

    // Publish to RPKI repository
    if err := t.rpkiClient.PublishROA(ctx, signed); err != nil {
        return fmt.Errorf("publish ROA: %w", err)
    }

    slog.Info("ROA created",
        slog.String("prefix", prefix.String()),
        slog.Int("max_length", maxLen),
        slog.Uint64("asn", uint64(t.config.ASN)),
    )

    return nil
}
```

## BGP Dampening

BGP dampening suppresses unstable (flapping) routes to prevent route oscillation from propagating through the network.

### Dampening Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Half-Life | 15 minutes | Time for penalty to decay by half |
| Suppress Threshold | 2000 | Penalty at which route is suppressed |
| Reuse Threshold | 750 | Penalty at which route is reused |
| Max Suppress Time | 60 minutes | Maximum suppression duration |

### Dampening Flow

```
+------------------------------------------------------------------+
|                   BGP DAMPENING FLOW                               |
+------------------------------------------------------------------+
|                                                                   |
|  Route Flap Events:                                               |
|  +--------------------------------------------------------------+ |
|  | t=0:  Route announced      Penalty: 0                        | |
|  | t=1:  Route withdrawn      Penalty: +1000                    | |
|  | t=2:  Route announced      Penalty: +1000 = 2000             | |
|  |       (Penalty >= Suppress Threshold)                        | |
|  |       -> Route SUPPRESSED                                    | |
|  +--------------------------------------------------------------+ |
|                                                                   |
|  Penalty Decay (Half-Life = 15 min):                              |
|  +--------------------------------------------------------------+ |
|  | t=2:   Penalty = 2000 (suppressed)                           | |
|  | t=17:  Penalty = 1000 (half-life decay)                      | |
|  | t=32:  Penalty = 500  (below reuse threshold)                | |
|  |        -> Route REUSED (unsuppressed)                        | |
|  +--------------------------------------------------------------+ |
|                                                                   |
|  Penalty Ceiling:                                                 |
|  +--------------------------------------------------------------+ |
|  | Max penalty = reuse * 2^(max_suppress/half_life)             | |
|  |             = 750 * 2^(60/15) = 750 * 16 = 12000             | |
|  +--------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Implementation

```go
// FlapDampener tracks route stability
type FlapDampener struct {
    config   DampeningConfig
    routes   map[string]*FlapState
    mu       sync.RWMutex
}

type DampeningConfig struct {
    HalfLife          time.Duration  // 15 minutes
    SuppressThreshold uint32         // 2000
    ReuseThreshold    uint32         // 750
    MaxSuppressTime   time.Duration  // 60 minutes
}

type FlapState struct {
    Penalty       float64
    LastFlap      time.Time
    Suppressed    bool
    SuppressUntil time.Time
}

// RecordWithdrawal records a route withdrawal event
func (d *FlapDampener) RecordWithdrawal(prefix netip.Prefix) {
    d.mu.Lock()
    defer d.mu.Unlock()

    key := prefix.String()
    state, exists := d.routes[key]
    if !exists {
        state = &FlapState{}
        d.routes[key] = state
    }

    // Decay existing penalty
    elapsed := time.Since(state.LastFlap)
    state.Penalty = d.decayPenalty(state.Penalty, elapsed)

    // Add penalty for withdrawal
    state.Penalty += 1000

    // Cap at ceiling
    ceiling := d.calculateCeiling()
    if state.Penalty > ceiling {
        state.Penalty = ceiling
    }

    state.LastFlap = time.Now()

    // Check suppression
    if state.Penalty >= float64(d.config.SuppressThreshold) {
        state.Suppressed = true
        state.SuppressUntil = d.calculateSuppressUntil(state.Penalty)

        slog.Warn("Route suppressed due to flapping",
            slog.String("prefix", key),
            slog.Float64("penalty", state.Penalty),
            slog.Time("suppress_until", state.SuppressUntil),
        )
    }
}

// decayPenalty calculates penalty decay based on half-life
func (d *FlapDampener) decayPenalty(penalty float64, elapsed time.Duration) float64 {
    if elapsed <= 0 {
        return penalty
    }
    halfLives := float64(elapsed) / float64(d.config.HalfLife)
    return penalty * math.Pow(0.5, halfLives)
}

// ShouldReuse checks if route should be readvertised
func (d *FlapDampener) ShouldReuse(prefix netip.Prefix) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()

    state, exists := d.routes[prefix.String()]
    if !exists || !state.Suppressed {
        return true
    }

    // Decay penalty
    elapsed := time.Since(state.LastFlap)
    currentPenalty := d.decayPenalty(state.Penalty, elapsed)

    return currentPenalty < float64(d.config.ReuseThreshold)
}
```

## Route Signing

Transit gateways require coordinator signatures for route announcements to prevent unauthorized route hijacking.

### Signing Workflow

```
+------------------------------------------------------------------+
|                  ROUTE SIGNING WORKFLOW                            |
+------------------------------------------------------------------+
|                                                                   |
|  1. Gateway Creates Route Request                                 |
|     +----------------------------------------------------------+ |
|     | Prefix: 2602:F5BB:0001::/48                              | |
|     | Origin: AS 65001                                          | |
|     | Next-Hop: 10.0.0.1                                        | |
|     | Timestamp: 2026-01-18T10:30:00Z                           | |
|     | Requestor: gateway-na-east-01                             | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. Request Sent to Coordinator Cluster                           |
|     +----------------------------------------------------------+ |
|     | Requires 3+ coordinator signatures (quorum)              | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  3. Coordinators Validate Request                                 |
|     +----------------------------------------------------------+ |
|     | Checks:                                                   | |
|     |  - Prefix within platform allocation                     | |
|     |  - Requestor is authorized gateway (rep >= 0.85)         | |
|     |  - RPKI ROA exists and is valid                          | |
|     |  - No conflicting announcements                          | |
|     |  - Rate limiting (prevent floods)                        | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  4. Coordinators Sign Route                                       |
|     +----------------------------------------------------------+ |
|     | Signature = Sign(TPM_Key, RouteHash)                     | |
|     |                                                          | |
|     | Coordinator 1: Sig_1 (TPM-backed)                        | |
|     | Coordinator 2: Sig_2 (TPM-backed)                        | |
|     | Coordinator 3: Sig_3 (TPM-backed)                        | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  5. Signed Route Announced via BGP                                |
|     +----------------------------------------------------------+ |
|     | Signatures embedded in BGP extended community            | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Implementation

```go
// RouteSignRequest defines a route signing request
type RouteSignRequest struct {
    Prefix    netip.Prefix
    Origin    uint32
    NextHop   netip.Addr
    Timestamp time.Time
    Requestor string
    Nonce     []byte
}

// RouteSignature represents a coordinator signature
type RouteSignature struct {
    CoordinatorID string
    Signature     []byte
    PublicKey     []byte
    Timestamp     time.Time
}

// SignedRoute is a route with coordinator signatures
type SignedRoute struct {
    Route      RouteSignRequest
    Signatures []RouteSignature
    Quorum     int
}

// RequestRouteSigning requests coordinator signatures
func (t *TransitState) RequestRouteSigning(ctx context.Context, prefix netip.Prefix) (*SignedRoute, error) {
    req := &RouteSignRequest{
        Prefix:    prefix,
        Origin:    t.config.ASN,
        NextHop:   t.routerIP,
        Timestamp: time.Now(),
        Requestor: t.gateway.ID.String(),
        Nonce:     generateNonce(),
    }

    // Request signatures from coordinator cluster
    signatures, err := t.coordinatorClient.RequestSignatures(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("request signatures: %w", err)
    }

    // Verify quorum
    if len(signatures) < t.config.SignatureQuorum {
        return nil, ErrInsufficientSignatures{
            Required: t.config.SignatureQuorum,
            Received: len(signatures),
        }
    }

    return &SignedRoute{
        Route:      *req,
        Signatures: signatures,
        Quorum:     t.config.SignatureQuorum,
    }, nil
}

// ValidateRouteSigning validates route signatures (coordinator side)
func (c *Coordinator) ValidateRouteSigning(ctx context.Context, req *RouteSignRequest) error {
    // Check prefix is within platform allocation
    if !c.isPlatformPrefix(req.Prefix) {
        return ErrPrefixNotAuthorized
    }

    // Check requestor is authorized gateway
    gateway, err := c.gatewayRegistry.Get(req.Requestor)
    if err != nil {
        return ErrGatewayNotFound
    }
    if gateway.Reputation < 0.85 {
        return ErrInsufficientReputation
    }

    // Check RPKI ROA
    validity := c.rpkiValidator.Validate(req.Prefix, req.Origin)
    if validity == RPKIStatusInvalid {
        return ErrRPKIInvalid
    }

    // Check timestamp freshness
    if time.Since(req.Timestamp) > 5*time.Minute {
        return ErrRequestExpired
    }

    // Rate limiting
    if c.rateLimiter.IsLimited(req.Requestor) {
        return ErrRateLimited
    }

    return nil
}

// SignRoute creates TPM-backed signature (coordinator side)
func (c *Coordinator) SignRoute(ctx context.Context, req *RouteSignRequest) (*RouteSignature, error) {
    if err := c.ValidateRouteSigning(ctx, req); err != nil {
        return nil, err
    }

    hash := c.hashRouteRequest(req)

    // Sign with TPM-backed key
    sig, err := c.tpmSigner.Sign(ctx, hash)
    if err != nil {
        return nil, fmt.Errorf("TPM sign: %w", err)
    }

    return &RouteSignature{
        CoordinatorID: c.config.ID,
        Signature:     sig,
        PublicKey:     c.publicKey,
        Timestamp:     time.Now(),
    }, nil
}
```

## Route Withdrawal

Routes must be withdrawn when a gateway is demoted or becomes unavailable.

### Withdrawal Triggers

- Gateway demotion (reputation drops below 0.85)
- Node shutdown (graceful or ungraceful)
- Stake slashing event
- Manual operator intervention
- Health check failure

### Withdrawal Protocol

```go
// WithdrawRoutes handles graceful route withdrawal
func (t *TransitState) WithdrawRoutes(ctx context.Context, reason WithdrawalReason) error {
    // Check dampening state
    for prefix := range t.SignedRoutes {
        if t.dampener.IsSuppressed(prefix) {
            continue // Already suppressed
        }

        // Record withdrawal
        t.dampener.RecordWithdrawal(prefix)

        // Send BGP UPDATE with route withdrawal
        if err := t.bgpSpeaker.WithdrawRoute(ctx, prefix); err != nil {
            slog.Error("Route withdrawal failed",
                slog.String("prefix", prefix.String()),
                slog.Any("error", err),
            )
            continue
        }

        slog.Info("Route withdrawn",
            slog.String("prefix", prefix.String()),
            slog.String("reason", reason.String()),
        )
    }

    return nil
}

type WithdrawalReason uint8

const (
    WithdrawalReasonGracefulShutdown WithdrawalReason = iota
    WithdrawalReasonDemotion
    WithdrawalReasonHealthCheckFail
    WithdrawalReasonSlashing
    WithdrawalReasonManual
)

func (r WithdrawalReason) String() string {
    switch r {
    case WithdrawalReasonGracefulShutdown:
        return "graceful_shutdown"
    case WithdrawalReasonDemotion:
        return "demotion"
    case WithdrawalReasonHealthCheckFail:
        return "health_check_fail"
    case WithdrawalReasonSlashing:
        return "slashing"
    case WithdrawalReasonManual:
        return "manual"
    default:
        return "unknown"
    }
}
```

### Stale Route Handling

For ungraceful shutdowns (crashes, network partitions):

| Phase | Timing | Action |
|-------|--------|--------|
| BGP Hold Timer | 0-30s | Wait for keepalive |
| Session Down | 30s | Mark peer as down |
| Route Stale | 30s-5min | Stale route timeout |
| Route Withdrawal | 5min | Controller withdraws route |

## Multi-Gateway Verification

Routes require verification from multiple gateways to prevent unauthorized announcements.

```go
// MultiGatewayVerifier ensures route consistency
type MultiGatewayVerifier struct {
    gateways        []*GatewayNode
    minVerifiers    int   // Minimum 3 gateways
    verifyInterval  time.Duration
}

// VerifyRoute checks route is consistently announced
func (v *MultiGatewayVerifier) VerifyRoute(ctx context.Context, prefix netip.Prefix) error {
    var verified int
    var announcements []RouteAnnouncement

    for _, gw := range v.gateways {
        ann, err := gw.GetRouteAnnouncement(ctx, prefix)
        if err != nil {
            continue
        }

        // Check announcement matches expected
        if v.validateAnnouncement(ann, prefix) {
            verified++
            announcements = append(announcements, ann)
        }
    }

    if verified < v.minVerifiers {
        return ErrInsufficientVerification{
            Required: v.minVerifiers,
            Verified: verified,
        }
    }

    // Check consistency across gateways
    if !v.announcementsConsistent(announcements) {
        return ErrInconsistentAnnouncements
    }

    return nil
}
```

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `transit_prefixes_announced` | Gauge | family | Announced prefixes |
| `transit_prefixes_suppressed` | Gauge | - | Dampened routes |
| `transit_rpki_valid` | Counter | - | Valid RPKI routes |
| `transit_rpki_invalid` | Counter | - | Invalid RPKI routes |
| `transit_rpki_not_found` | Counter | - | Routes without ROA |
| `transit_signing_requests` | Counter | result | Route signing requests |
| `transit_withdrawals` | Counter | reason | Route withdrawals |
| `transit_peer_sessions` | Gauge | peer, state | BGP peer session state |
| `transit_flap_events` | Counter | prefix | Route flap events |
| `transit_verification_failures` | Counter | - | Multi-gateway verification failures |

## See Also

- [Gateway Architecture](architecture.md) - Core gateway design
- [BGP Transit](../bgp/transit.md) - BGP transit details
- [RPKI Validation](../bgp/transit.md#rpki-validation) - RPKI implementation
- [Configuration](configuration.md) - Transit mode configuration

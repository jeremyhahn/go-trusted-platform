# BGP Transit Mode

## Overview

BGP transit mode enables go-trusted-platform to announce platform-owned IP prefixes to the global routing table, providing publicly routable addresses for DHT nodes, VMs, and services.

## Platform IP Blocks

### IPv6 Allocation

| Block | CIDR | Purpose | Announcement Level |
|-------|------|---------|-------------------|
| Full Allocation | 2602:F5BB::/36 | Platform aggregate | Backbone speakers |
| Regional | 2602:F5BB:XXXX::/48 | Regional prefix | Datacenter speakers |
| Subnet | 2602:F5BB:XXXX:YYYY::/64 | Host subnets | Internal only |

### IPv6 Hierarchy

```
2602:F5BB::/36 (Platform Aggregate - 4.7 quintillion addresses)
├── 2602:F5BB:0000::/40 (Region 0 - North America East)
│   ├── 2602:F5BB:0000::/48 (Datacenter 1)
│   │   ├── 2602:F5BB:0000:0001::/64 (Subnet 1)
│   │   ├── 2602:F5BB:0000:0002::/64 (Subnet 2)
│   │   └── ...
│   ├── 2602:F5BB:0001::/48 (Datacenter 2)
│   └── ...
├── 2602:F5BB:0100::/40 (Region 1 - North America West)
├── 2602:F5BB:0200::/40 (Region 2 - Europe West)
├── 2602:F5BB:0300::/40 (Region 3 - Europe East)
├── 2602:F5BB:0400::/40 (Region 4 - Asia Pacific North)
├── 2602:F5BB:0500::/40 (Region 5 - Asia Pacific South)
└── ... (up to 16 regions with /40 aggregates)
```

### IPv4 Allocation

| Block | CIDR | Purpose | Notes |
|-------|------|---------|-------|
| Platform | 23.143.36.0/24 | Legacy IPv4 connectivity | 254 usable addresses |

IPv4 is used sparingly for:
- Gateway nodes requiring IPv4 reachability
- Legacy system compatibility
- NAT64 translation endpoints

## Route Announcement Architecture

### Announcement Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                  ROUTE ANNOUNCEMENT FLOW                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Level 1: Backbone Speakers (Global)                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Announce to ISPs:                                   │    │
│  │   - 2602:F5BB::/36 (aggregate)                     │    │
│  │   - 23.143.36.0/24 (IPv4)                          │    │
│  │                                                     │    │
│  │ Suppress: All more-specific routes                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           │ iBGP                             │
│                           ▼                                  │
│  Level 2: Datacenter Speakers (Regional)                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Announce to Backbone (iBGP):                        │    │
│  │   - 2602:F5BB:0001::/48 (Region 1)                 │    │
│  │   - 2602:F5BB:0002::/48 (Region 2)                 │    │
│  │                                                     │    │
│  │ Suppress: /64 subnets (internal only)              │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           │ Internal                         │
│                           ▼                                  │
│  Level 3: Internal Routing (Subnets)                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Internal FIB only:                                  │    │
│  │   - 2602:F5BB:0001:0001::/64 (Subnet 1)           │    │
│  │   - 2602:F5BB:0001:0002::/64 (Subnet 2)           │    │
│  │                                                     │    │
│  │ Not announced externally                            │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### ISP Peering Configuration

```go
// Backbone speaker ISP peering
type ISPPeerConfig struct {
    Name        string
    Address     string
    RemoteAS    uint32
    Type        PeerType
    MD5Secret   string
    Families    []AddressFamily
    Policies    PeerPolicies
}

// Example: Primary ISP peer
primaryISP := &ISPPeerConfig{
    Name:      "ISP-Primary",
    Address:   "198.51.100.1",
    RemoteAS:  64500,
    Type:      PeerTypeEBGP,
    MD5Secret: "bgp_md5_secret",
    Families: []AddressFamily{
        {AFI: AFI_IPv4, SAFI: SAFI_Unicast},
        {AFI: AFI_IPv6, SAFI: SAFI_Unicast},
    },
    Policies: PeerPolicies{
        ExportPolicy: "export-to-isp",
        ImportPolicy: "import-from-isp",
    },
}

// Export policy: Only announce aggregates
exportPolicy := &RoutingPolicy{
    Name: "export-to-isp",
    Statements: []PolicyStatement{
        {
            Conditions: MatchConditions{
                PrefixList: "platform-aggregates",
            },
            Actions: PolicyActions{
                Accept: true,
                SetCommunity: []string{"65001:100"},  // Originated
            },
        },
        {
            // Default: reject all others
            Actions: PolicyActions{Accept: false},
        },
    },
}

// Prefix list: Platform aggregates only
aggregatePrefixes := &PrefixList{
    Name: "platform-aggregates",
    Entries: []PrefixEntry{
        {Prefix: "2602:F5BB::/36", Exact: true},
        {Prefix: "23.143.36.0/24", Exact: true},
    },
}
```

## RPKI Validation

### Overview

Resource Public Key Infrastructure (RPKI) validates that route announcements originate from authorized ASNs.

```
┌─────────────────────────────────────────────────────────────┐
│                    RPKI VALIDATION FLOW                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Create ROA (Route Origin Authorization)                 │
│     ┌─────────────────────────────────────────────┐         │
│     │ Prefix: 2602:F5BB::/36                     │         │
│     │ Max Length: /48                             │         │
│     │ Origin ASN: 65001                           │         │
│     │ Signed by: ARIN (RIR)                       │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  2. Publish to RPKI Repository                              │
│     └─► rsync://rpki.arin.net/repository/                   │
│                                                              │
│  3. BGP Speaker Validates Received Routes                   │
│     ┌─────────────────────────────────────────────┐         │
│     │ Route: 2602:F5BB::/36 from AS 65001        │         │
│     │                                             │         │
│     │ Lookup ROA:                                 │         │
│     │   - Prefix matches: Yes                     │         │
│     │   - Length <= Max: Yes (/36 <= /48)        │         │
│     │   - ASN matches: Yes (65001)               │         │
│     │                                             │         │
│     │ Result: VALID                               │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  4. Apply RPKI Policy                                       │
│     - VALID: Accept with preference                         │
│     - NOT_FOUND: Accept (no ROA exists)                     │
│     - INVALID: Reject                                       │
└─────────────────────────────────────────────────────────────┘
```

### RPKI Configuration

```go
// RPKI validator configuration
type RPKIConfig struct {
    // RPKI-to-Router (RTR) servers
    Servers []RPKIServer

    // Validation policy
    Policy RPKIPolicy

    // Cache settings
    CacheLifetime time.Duration
    RefreshInterval time.Duration
}

// RTR server connection
type RPKIServer struct {
    Address string
    Port    uint16
    Prefer  bool  // Prefer this server
}

// Example configuration
rpkiConfig := &RPKIConfig{
    Servers: []RPKIServer{
        {Address: "rpki-validator.example.com", Port: 8323, Prefer: true},
        {Address: "rpki-backup.example.com", Port: 8323},
    },
    Policy: RPKIPolicy{
        ValidAction:    PolicyActionAccept,
        InvalidAction:  PolicyActionReject,
        NotFoundAction: PolicyActionAccept,  // Default accept if no ROA
    },
    CacheLifetime:   3600 * time.Second,
    RefreshInterval: 300 * time.Second,
}
```

### ROA Management

```go
// Create ROA for platform prefixes
func (s *Speaker) CreateROA(ctx context.Context, prefix netip.Prefix, maxLen int) (*ROA, error) {
    roa := &ROA{
        Prefix:    prefix,
        MaxLength: maxLen,
        ASN:       s.config.ASN,
        ValidFrom: time.Now(),
        ValidTo:   time.Now().AddDate(1, 0, 0),  // 1 year validity
    }

    // Sign ROA with platform CA
    signed, err := s.caClient.SignROA(ctx, roa)
    if err != nil {
        return nil, fmt.Errorf("failed to sign ROA: %w", err)
    }

    // Publish to RPKI repository
    if err := s.rpkiClient.PublishROA(ctx, signed); err != nil {
        return nil, fmt.Errorf("failed to publish ROA: %w", err)
    }

    s.logger.Info("ROA created",
        slog.String("prefix", prefix.String()),
        slog.Int("max_length", maxLen),
        slog.Uint64("asn", uint64(s.config.ASN)),
    )

    return roa, nil
}
```

## BGP Dampening

### Overview

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
┌─────────────────────────────────────────────────────────────┐
│                   BGP DAMPENING FLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Route Flap Events:                                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ t=0:  Route announced      Penalty: 0              │    │
│  │ t=1:  Route withdrawn      Penalty: +1000          │    │
│  │ t=2:  Route announced      Penalty: +1000 = 2000   │    │
│  │       (Penalty >= Suppress Threshold)               │    │
│  │       → Route SUPPRESSED                            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Penalty Decay (Half-Life = 15 min):                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ t=2:   Penalty = 2000 (suppressed)                 │    │
│  │ t=17:  Penalty = 1000 (half-life decay)            │    │
│  │ t=32:  Penalty = 500  (below reuse threshold)      │    │
│  │        → Route REUSED (unsuppressed)                │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Penalty Ceiling:                                           │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Max penalty calculated to limit suppression to      │    │
│  │ max_suppress_time (60 min) from reuse_threshold     │    │
│  │                                                     │    │
│  │ ceiling = reuse * 2^(max_suppress/half_life)       │    │
│  │         = 750 * 2^(60/15) = 750 * 16 = 12000       │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```go
// BGP dampening configuration
type DampeningConfig struct {
    HalfLife          time.Duration  // 15 minutes
    SuppressThreshold uint32         // 2000
    ReuseThreshold    uint32         // 750
    MaxSuppressTime   time.Duration  // 60 minutes
}

// Flap dampening state per route
type FlapState struct {
    Penalty       float64
    LastFlap      time.Time
    Suppressed    bool
    SuppressUntil time.Time
}

// Dampening handler
type Dampener struct {
    config DampeningConfig
    routes map[string]*FlapState
    mu     sync.RWMutex
}

// Record route withdrawal (flap)
func (d *Dampener) RecordWithdrawal(prefix string) {
    d.mu.Lock()
    defer d.mu.Unlock()

    state, exists := d.routes[prefix]
    if !exists {
        state = &FlapState{}
        d.routes[prefix] = state
    }

    // Decay existing penalty based on time since last flap
    elapsed := time.Since(state.LastFlap)
    state.Penalty = d.decayPenalty(state.Penalty, elapsed)

    // Add penalty for this withdrawal
    state.Penalty += 1000

    // Cap at ceiling
    ceiling := d.calculateCeiling()
    if state.Penalty > ceiling {
        state.Penalty = ceiling
    }

    state.LastFlap = time.Now()

    // Check if route should be suppressed
    if state.Penalty >= float64(d.config.SuppressThreshold) {
        state.Suppressed = true
        state.SuppressUntil = d.calculateSuppressUntil(state.Penalty)

        slog.Warn("Route suppressed due to flapping",
            slog.String("prefix", prefix),
            slog.Float64("penalty", state.Penalty),
            slog.Time("suppress_until", state.SuppressUntil),
        )
    }
}

// Decay penalty based on half-life
func (d *Dampener) decayPenalty(penalty float64, elapsed time.Duration) float64 {
    if elapsed <= 0 {
        return penalty
    }
    // penalty * 0.5^(elapsed/half_life)
    halfLives := float64(elapsed) / float64(d.config.HalfLife)
    return penalty * math.Pow(0.5, halfLives)
}

// Check if route should be reused
func (d *Dampener) ShouldReuse(prefix string) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()

    state, exists := d.routes[prefix]
    if !exists {
        return true  // No dampening state, allow
    }

    if !state.Suppressed {
        return true  // Not suppressed, allow
    }

    // Decay penalty
    elapsed := time.Since(state.LastFlap)
    currentPenalty := d.decayPenalty(state.Penalty, elapsed)

    // Check against reuse threshold
    if currentPenalty < float64(d.config.ReuseThreshold) {
        return true
    }

    return false
}
```

## Route Signing by Coordinators

### Overview

Coordinator nodes cryptographically sign route announcements to prevent unauthorized route hijacking.

### Signing Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                  ROUTE SIGNING WORKFLOW                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Datacenter Speaker Creates Route Request                │
│     ┌─────────────────────────────────────────────┐         │
│     │ Prefix: 2602:F5BB:0001::/48                │         │
│     │ Origin: AS 65001                            │         │
│     │ Next-Hop: 10.0.0.1                         │         │
│     │ Timestamp: 2024-01-15T10:30:00Z            │         │
│     │ Requestor: dc-speaker-1                     │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  2. Request Sent to Coordinator Cluster                     │
│     └─► Requires 3+ coordinator signatures (quorum)         │
│                                                              │
│  3. Coordinators Validate Request                           │
│     ┌─────────────────────────────────────────────┐         │
│     │ Checks:                                     │         │
│     │  - Prefix within platform allocation        │         │
│     │  - Requestor is authorized speaker          │         │
│     │  - RPKI ROA exists and is valid            │         │
│     │  - No conflicting announcements            │         │
│     │  - Rate limiting (prevent floods)          │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  4. Coordinators Sign Route                                 │
│     ┌─────────────────────────────────────────────┐         │
│     │ Signature = Sign(TPM_Key, RouteHash)        │         │
│     │                                             │         │
│     │ Coordinator 1: Sig_1 (TPM-backed)          │         │
│     │ Coordinator 2: Sig_2 (TPM-backed)          │         │
│     │ Coordinator 3: Sig_3 (TPM-backed)          │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  5. Signed Route Returned to Speaker                        │
│     └─► Speaker announces via BGP with signatures           │
│         (Signatures in BGP extended community)              │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```go
// Route signing request
type RouteSignRequest struct {
    Prefix    netip.Prefix
    Origin    uint32
    NextHop   netip.Addr
    Timestamp time.Time
    Requestor string  // Speaker ID
    Nonce     []byte  // Replay protection
}

// Route signature
type RouteSignature struct {
    CoordinatorID string
    Signature     []byte
    PublicKey     []byte  // For verification
    Timestamp     time.Time
}

// Signed route announcement
type SignedRoute struct {
    Route      RouteSignRequest
    Signatures []RouteSignature
    Quorum     int  // Required signatures (e.g., 3)
}

// Request route signing from coordinators
func (s *Speaker) RequestRouteSigning(ctx context.Context, prefix netip.Prefix) (*SignedRoute, error) {
    req := &RouteSignRequest{
        Prefix:    prefix,
        Origin:    s.config.ASN,
        NextHop:   s.routerIP,
        Timestamp: time.Now(),
        Requestor: s.config.SpeakerID,
        Nonce:     generateNonce(),
    }

    // Request signatures from coordinator cluster
    signatures, err := s.coordinatorClient.RequestSignatures(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("failed to get signatures: %w", err)
    }

    // Verify quorum
    if len(signatures) < s.config.SignatureQuorum {
        return nil, ErrInsufficientSignatures{
            Required: s.config.SignatureQuorum,
            Received: len(signatures),
        }
    }

    return &SignedRoute{
        Route:      *req,
        Signatures: signatures,
        Quorum:     s.config.SignatureQuorum,
    }, nil
}

// Coordinator: Sign route request
func (c *Coordinator) SignRoute(ctx context.Context, req *RouteSignRequest) (*RouteSignature, error) {
    // Validate request
    if err := c.validateRouteRequest(req); err != nil {
        return nil, fmt.Errorf("validation failed: %w", err)
    }

    // Create hash of route data
    hash := c.hashRouteRequest(req)

    // Sign with TPM-backed key
    sig, err := c.tpmSigner.Sign(ctx, hash)
    if err != nil {
        return nil, fmt.Errorf("TPM signing failed: %w", err)
    }

    return &RouteSignature{
        CoordinatorID: c.config.ID,
        Signature:     sig,
        PublicKey:     c.publicKey,
        Timestamp:     time.Now(),
    }, nil
}

// Validate route request
func (c *Coordinator) validateRouteRequest(req *RouteSignRequest) error {
    // Check prefix is within platform allocation
    if !c.isPlatformPrefix(req.Prefix) {
        return ErrPrefixNotAuthorized
    }

    // Check requestor is authorized speaker
    if !c.isAuthorizedSpeaker(req.Requestor) {
        return ErrSpeakerNotAuthorized
    }

    // Check RPKI ROA
    validity := c.rpkiValidator.Validate(req.Prefix, req.Origin)
    if validity == RPKIInvalid {
        return ErrRPKIInvalid
    }

    // Check rate limiting
    if c.rateLimiter.IsLimited(req.Requestor) {
        return ErrRateLimited
    }

    // Check timestamp freshness (prevent replay)
    if time.Since(req.Timestamp) > 5*time.Minute {
        return ErrRequestExpired
    }

    return nil
}
```

## Traffic Engineering

### AS-PATH Prepending

Control inbound traffic by making paths less attractive:

```go
// Configure AS-PATH prepending for backup ISP
func (s *Speaker) configureBackupISP(ctx context.Context, peer *PeerConfig) error {
    // Export policy with prepending
    policy := &RoutingPolicy{
        Name: "export-to-backup-isp",
        Statements: []PolicyStatement{
            {
                Conditions: MatchConditions{
                    PrefixList: "platform-aggregates",
                },
                Actions: PolicyActions{
                    Accept: true,
                    ASPathPrepend: &ASPathPrepend{
                        ASN:   s.config.ASN,
                        Count: 3,  // Prepend 3 times
                    },
                },
            },
        },
    }

    // Apply policy to peer
    return s.applyExportPolicy(ctx, peer, policy)
}

// Result:
// Primary ISP: AS-PATH = 65001
// Backup ISP:  AS-PATH = 65001 65001 65001 65001
// Traffic prefers shorter path (primary)
```

### MED (Multi-Exit Discriminator)

Influence ISP route selection when multiple entry points exist:

```go
// Set MED for traffic engineering
func (s *Speaker) setMED(ctx context.Context, prefix netip.Prefix, med uint32) error {
    // Lower MED is preferred
    // Use to prefer specific datacenter entry point

    policy := &RoutingPolicy{
        Name: "set-med-for-dc1",
        Statements: []PolicyStatement{
            {
                Conditions: MatchConditions{
                    Prefix: prefix,
                },
                Actions: PolicyActions{
                    Accept: true,
                    SetMED: med,
                },
            },
        },
    }

    return s.applyExportPolicy(ctx, nil, policy)
}

// Example:
// DC1: MED = 100 (preferred)
// DC2: MED = 200
// Traffic to prefix routes via DC1
```

### Community-Based Routing

Use BGP communities to signal routing preferences:

```go
// Standard communities for traffic engineering
const (
    CommunityNoExport       = "65535:65281"  // Do not export to eBGP
    CommunityNoAdvertise    = "65535:65282"  // Do not advertise
    CommunityLocalAS        = "65535:65283"  // Do not export outside local AS

    // Platform-specific communities
    CommunityOriginated     = "65001:100"    // Originated by platform
    CommunityBackbone       = "65001:200"    // Backbone route
    CommunityDatacenter     = "65001:300"    // Datacenter route
    CommunityBlackhole      = "65001:666"    // DDoS blackhole
)

// Apply blackhole community for DDoS mitigation
func (s *Speaker) BlackholePrefix(ctx context.Context, prefix netip.Prefix) error {
    path := &api.Path{
        Family: ipv6Family,
        Nlri:   marshal(&api.IPAddressPrefix{Prefix: prefix.String()}),
        Pattrs: []*any.Any{
            marshal(&api.OriginAttribute{Origin: 0}),
            marshal(&api.NextHopAttribute{NextHop: "192.0.2.1"}),  // RFC 5737 blackhole
            marshal(&api.CommunitiesAttribute{
                Communities: []uint32{
                    parseCommunity(CommunityBlackhole),
                },
            }),
        },
    }

    _, err := s.server.AddPath(ctx, &api.AddPathRequest{
        TableType: api.TableType_GLOBAL,
        Path:      path,
    })

    s.logger.Warn("Blackhole route announced",
        slog.String("prefix", prefix.String()),
        slog.String("reason", "DDoS mitigation"),
    )

    return err
}
```

## Monitoring and Operations

### Route Health Checks

```go
// Monitor announced routes
func (s *Speaker) monitorRoutes(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            s.checkRouteHealth()
        }
    }
}

func (s *Speaker) checkRouteHealth() {
    // List all announced routes
    routes, _ := s.server.ListPath(ctx, &api.ListPathRequest{
        TableType: api.TableType_GLOBAL,
        Family:    ipv6Family,
    })

    for _, route := range routes {
        // Check if route is being received by ISP (looking glass)
        if !s.verifyRouteReachability(route.Prefix) {
            s.logger.Warn("Route not visible externally",
                slog.String("prefix", route.Prefix),
            )
            s.metrics.RouteHealthy.WithLabelValues(route.Prefix).Set(0)
        } else {
            s.metrics.RouteHealthy.WithLabelValues(route.Prefix).Set(1)
        }
    }
}
```

### Metrics

| Metric | Description |
|--------|-------------|
| `bgp_transit_prefixes_announced` | Number of prefixes announced to ISPs |
| `bgp_transit_prefixes_received` | Number of prefixes received from ISPs |
| `bgp_rpki_valid_routes` | Routes with valid RPKI status |
| `bgp_rpki_invalid_routes` | Routes with invalid RPKI status |
| `bgp_dampened_routes` | Currently suppressed routes |
| `bgp_route_signatures_requested` | Route signing requests to coordinators |
| `bgp_route_signatures_failed` | Failed signing requests |

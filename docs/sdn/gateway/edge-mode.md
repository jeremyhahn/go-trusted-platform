# Edge/P2P/IoT Gateway Mode

## Overview

Edge mode enables gateway nodes to serve as entry points for new devices joining the trusted network. Edge gateways handle device onboarding through ACME-based enrollment, provide DHT bootstrap services for P2P connectivity, allocate IPv6 addresses from the platform pool, and implement NAT traversal for devices behind firewalls.

## Key Functions

| Function | Description |
|----------|-------------|
| **ACME Endorse-01** | TPM endorsement key validation |
| **ACME Enroll-01** | IDevID certificate issuance via FROST |
| **DHT Bootstrap** | Entry point for joining DHT network |
| **IPv6 Allocation** | Address assignment from 2001:db8::/36 pool |
| **NAT Traversal** | STUN/TURN for firewall bypass |
| **Rate Limiting** | Per-peer request throttling |

## ACME Challenge Types

### Endorse-01: TPM Endorsement Validation

The `endorse-01` challenge validates that a device possesses a genuine TPM with a manufacturer-endorsed EK (Endorsement Key).

```
+------------------------------------------------------------------+
|                    ACME endorse-01 Flow                           |
+------------------------------------------------------------------+
|                                                                   |
|  1. Device Initiates Enrollment                                   |
|     +----------------------------------------------------------+ |
|     | POST /acme/new-order                                     | |
|     | {                                                         | |
|     |   "identifiers": [{"type": "device", "value": "new-dev"}]| |
|     | }                                                         | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. Gateway Returns Challenge                                     |
|     +----------------------------------------------------------+ |
|     | {                                                         | |
|     |   "type": "endorse-01",                                  | |
|     |   "token": "random-challenge-token",                     | |
|     |   "nonce": "gateway-generated-nonce"                     | |
|     | }                                                         | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  3. Device Responds with TPM Attestation                          |
|     +----------------------------------------------------------+ |
|     | POST /acme/challenge/{id}                                | |
|     | {                                                         | |
|     |   "ekCert": "base64(EK_Certificate)",                    | |
|     |   "akPub": "base64(AK_Public_Key)",                      | |
|     |   "certifyInfo": "base64(TPM2_Certify_Output)",          | |
|     |   "signature": "base64(AK_Signature)"                    | |
|     | }                                                         | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  4. Gateway Validates                                             |
|     +----------------------------------------------------------+ |
|     | - Verify EK cert chain to manufacturer root              | |
|     | - Check EK cert is not revoked                           | |
|     | - Verify AK is resident in same TPM (certify)            | |
|     | - Verify signature over challenge token                  | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  5. Challenge Complete                                            |
|     +----------------------------------------------------------+ |
|     | {"status": "valid"}                                      | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Enroll-01: IDevID Certificate Issuance

The `enroll-01` challenge issues an IDevID certificate via the distributed FROST CA.

```go
// Enroll01Handler processes IDevID enrollment
type Enroll01Handler struct {
    caClient     *frost.CAClient
    policyEngine *policy.Engine
    ipv6Alloc    *IPv6Allocator
}

// HandleEnroll01 issues IDevID via FROST
func (h *Enroll01Handler) HandleEnroll01(ctx context.Context, req *Enroll01Request) (*Enroll01Response, error) {
    // 1. Validate CSR
    csr, err := x509.ParseCertificateRequest(req.CSR)
    if err != nil {
        return nil, ErrInvalidCSR
    }

    // 2. Verify device passed endorse-01
    if !h.hasValidEndorsement(req.DeviceID) {
        return nil, ErrEndorsementRequired
    }

    // 3. Allocate IPv6 address
    ipv6, err := h.ipv6Alloc.AllocateIPv6(ctx, req.DeviceID, req.Region)
    if err != nil {
        return nil, fmt.Errorf("allocate IPv6: %w", err)
    }

    // 4. Build certificate template
    template := &x509.Certificate{
        Subject: pkix.Name{
            CommonName:   req.DeviceID,
            Organization: []string{req.Organization},
        },
        // Include allocated IPv6 in SAN
        IPAddresses: []net.IP{net.IP(ipv6.AsSlice())},
        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year validity
    }

    // 5. Request FROST threshold signature
    cert, err := h.caClient.SignCertificate(ctx, template, csr.PublicKey)
    if err != nil {
        // Rollback IPv6 allocation
        h.ipv6Alloc.Release(ctx, ipv6)
        return nil, fmt.Errorf("FROST signing: %w", err)
    }

    return &Enroll01Response{
        Certificate: cert,
        IPv6Address: ipv6,
        CAChain:     h.caClient.GetCAChain(),
    }, nil
}
```

## DHT Bootstrap

Edge gateways serve as bootstrap entry points for new nodes joining the DHT network.

### Bootstrap Protocol

```
+------------------------------------------------------------------+
|                     DHT Bootstrap Flow                            |
+------------------------------------------------------------------+
|                                                                   |
|  1. New Node Discovers Edge Gateway                               |
|     +----------------------------------------------------------+ |
|     | Methods:                                                  | |
|     | - DNS seed: _dht._tcp.trusted-platform.example.com       | |
|     | - Hardcoded bootstrap list                                | |
|     | - mDNS local discovery                                    | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. TLS Connection with Client Certificate                        |
|     +----------------------------------------------------------+ |
|     | - New node presents IDevID (from enroll-01)              | |
|     | - Gateway validates certificate chain                    | |
|     | - Mutual TLS established                                  | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  3. Bootstrap Request                                             |
|     +----------------------------------------------------------+ |
|     | {                                                         | |
|     |   "node_id": "Qm...",                                    | |
|     |   "public_key": "base64(Ed25519_Pub)",                   | |
|     |   "addresses": ["[2001:db8:1::123]:10443"],             | |
|     |   "capabilities": ["leaf", "relay"]                      | |
|     | }                                                         | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  4. Gateway Validates and Responds                                |
|     +----------------------------------------------------------+ |
|     | - Verify node certificate                                 | |
|     | - Check reputation (new nodes start at 0.0)              | |
|     | - Return k-closest nodes (k=20)                          | |
|     | - Provide regional coordinator addresses                 | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  5. Node Joins Overlay                                            |
|     +----------------------------------------------------------+ |
|     | - Connect to k-closest nodes                              | |
|     | - Begin participating in DHT                              | |
|     | - Start reputation building                               | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Bootstrap Implementation

```go
// BootstrapService handles DHT entry for new nodes
type BootstrapService struct {
    dht           *dht.Node
    regionManager *RegionManager
    rateLimiter   *RateLimiter
}

// HandleBootstrap processes bootstrap request
func (b *BootstrapService) HandleBootstrap(ctx context.Context, req *BootstrapRequest) (*BootstrapResponse, error) {
    // Rate limiting check
    if !b.rateLimiter.Allow(req.NodeID) {
        return nil, ErrRateLimited
    }

    // Validate node certificate (extracted from TLS)
    cert := getCertFromContext(ctx)
    if err := b.validateNodeCert(cert); err != nil {
        return nil, fmt.Errorf("invalid certificate: %w", err)
    }

    // Find k-closest nodes
    closest, err := b.dht.FindClosest(req.NodeID, 20)
    if err != nil {
        return nil, fmt.Errorf("find closest: %w", err)
    }

    // Get regional coordinators
    region := b.regionManager.DetermineRegion(req.Addresses[0])
    coordinators := b.regionManager.GetCoordinators(region)

    // Register node in DHT (lightweight entry)
    if err := b.dht.RegisterNode(ctx, &dht.NodeInfo{
        ID:           req.NodeID,
        PublicKey:    req.PublicKey,
        Addresses:    req.Addresses,
        Capabilities: req.Capabilities,
        Reputation:   0.0, // New nodes start at 0
        JoinedAt:     time.Now(),
    }); err != nil {
        return nil, fmt.Errorf("register node: %w", err)
    }

    return &BootstrapResponse{
        ClosestNodes:  closest,
        Coordinators:  coordinators,
        Region:        region,
        NetworkParams: b.dht.GetNetworkParams(),
    }, nil
}
```

## IPv6 Allocation

Edge gateways manage IPv6 address allocation from the platform's 2001:db8::/36 pool.

### Allocation Hierarchy

```
2001:db8::/36 (Platform Aggregate - 4.7 quintillion addresses)
|
+-- Regional Pool Assignment
|   |
|   +-- 2001:DB8:0000::/40 (Region 0 - North America East)
|   |   +-- 2001:DB8:0000:0001::/64 (Subnet 1)
|   |   +-- 2001:DB8:0000:0002::/64 (Subnet 2)
|   |   +-- ...
|   |
|   +-- 2001:DB8:0100::/40 (Region 1 - North America West)
|   +-- 2001:DB8:0200::/40 (Region 2 - Europe West)
|   +-- 2001:DB8:0300::/40 (Region 3 - Europe East)
|   +-- 2001:DB8:0400::/40 (Region 4 - Asia Pacific North)
|   +-- 2001:DB8:0500::/40 (Region 5 - Asia Pacific South)
|   +-- ... (up to 16 regions with /40 aggregates)
```

### Allocation Protocol

```go
// IPv6Allocator manages address assignment
type IPv6Allocator struct {
    db                *quicbaas.Client
    region            RegionID
    prefix            netip.Prefix    // Regional /40 or /48
    inactivityTimeout time.Duration   // 30 days - reallocate if inactive this long
}

// AllocateIPv6 assigns an address to a node
// Nodes keep their IP forever as long as they remain active (connect within 30 days)
func (a *IPv6Allocator) AllocateIPv6(ctx context.Context, nodeID NodeID, region RegionID) (netip.Addr, error) {
    // Check for existing allocation
    existingKey := fmt.Sprintf("ipv6-allocation:%s", nodeID)
    if allocData, err := a.db.Get(ctx, existingKey); err == nil {
        var existing IPv6Allocation
        if json.Unmarshal(allocData, &existing) == nil {
            // Node already has an IP - refresh last seen and return it
            existing.LastSeen = time.Now()
            allocBytes, _ := json.Marshal(existing)
            a.db.Put(ctx, existingKey, string(allocBytes), 0) // No TTL - permanent until inactive
            return existing.Address, nil
        }
    }

    // New allocation via atomic CAS
    for attempt := 0; attempt < 100; attempt++ {
        candidate := a.generateCandidateAddress()
        addrKey := fmt.Sprintf("ipv6-addr:%s", candidate)

        // CAS: only succeed if address is not allocated
        err := a.db.PutIfAbsent(ctx, addrKey, nodeID.String(), 0) // No TTL
        if err == nil {
            // Success - record allocation (not a lease - permanent until inactive)
            alloc := &IPv6Allocation{
                Address:     candidate,
                NodeID:      nodeID,
                Region:      region,
                AllocatedAt: time.Now(),
                LastSeen:    time.Now(),
            }
            allocBytes, _ := json.Marshal(alloc)
            a.db.Put(ctx, existingKey, string(allocBytes), 0) // No TTL

            return candidate, nil
        }

        // Address in use, try next
    }

    return netip.Addr{}, ErrNoAvailableAddresses
}

// TouchLastSeen updates the last seen timestamp for an IP allocation
// Called automatically when a node connects - keeps the IP active
func (a *IPv6Allocator) TouchLastSeen(ctx context.Context, nodeID NodeID, addr netip.Addr) error {
    key := fmt.Sprintf("ipv6-allocation:%s", nodeID)

    // Get existing allocation
    allocData, err := a.db.Get(ctx, key)
    if err != nil {
        return ErrAllocationNotFound
    }

    var alloc IPv6Allocation
    if err := json.Unmarshal(allocData, &alloc); err != nil {
        return err
    }

    // Verify ownership
    if alloc.Address != addr {
        return ErrAddressMismatch
    }

    // Update last seen
    alloc.LastSeen = time.Now()
    allocBytes, _ := json.Marshal(alloc)
    return a.db.Put(ctx, key, string(allocBytes), 0) // No TTL
}

// ReclaimInactive runs periodically to reclaim IPs from inactive nodes
// Only reclaims if node has not been seen for inactivityTimeout (30 days)
func (a *IPv6Allocator) ReclaimInactive(ctx context.Context) (int, error) {
    cutoff := time.Now().Add(-a.inactivityTimeout)
    reclaimed := 0

    // Scan all allocations
    allocations, err := a.db.ScanPrefix(ctx, "ipv6-allocation:")
    if err != nil {
        return 0, err
    }

    for _, allocData := range allocations {
        var alloc IPv6Allocation
        if err := json.Unmarshal(allocData.Value, &alloc); err != nil {
            continue
        }

        // Only reclaim if inactive for 30+ days
        if alloc.LastSeen.Before(cutoff) {
            // Delete allocation record
            a.db.Delete(ctx, fmt.Sprintf("ipv6-allocation:%s", alloc.NodeID))
            // Delete address reservation
            a.db.Delete(ctx, fmt.Sprintf("ipv6-addr:%s", alloc.Address))
            reclaimed++
        }
    }

    return reclaimed, nil
}

// generateCandidateAddress creates a candidate from regional pool
func (a *IPv6Allocator) generateCandidateAddress() netip.Addr {
    // Use HMAC-based generation for predictable distribution
    // Regional prefix + random host portion
    base := a.prefix.Addr().As16()

    // Generate random host portion
    var host [8]byte
    rand.Read(host[:])

    // Combine prefix with host
    var addr [16]byte
    copy(addr[:], base[:8])  // /64 prefix
    copy(addr[8:], host[:])  // Host portion

    return netip.AddrFrom16(addr)
}
```

### IPv6 Allocation Lifecycle (Inactivity Model)

**Key Principle**: Nodes keep their IPv6 address **forever** as long as they remain active on the network. The address is only reclaimed if the node has been inactive (not connected) for 30+ days.

| State | Condition | Actions |
|-------|-----------|---------|
| **Allocated** | Node receives IP | Address permanently assigned to node |
| **Active** | Node connects regularly | LastSeen timestamp updated on each connection |
| **Inactive Warning** | No connection for 23+ days | Notification sent to node (if reachable) |
| **Reclaimable** | No connection for 30+ days | Address eligible for reclamation |
| **Reclaimed** | Background job runs | Address returns to pool for new nodes |

### Why Inactivity Timeout vs Hard Lease

| Approach | Pros | Cons |
|----------|------|------|
| **Hard Lease (old)** | Predictable expiration | Forces renewal overhead, loses IP on brief outages |
| **Inactivity Timeout (current)** | Zero overhead for active nodes, survives brief outages | Requires background cleanup job |

With 4+ quintillion available IPv6 addresses, there is no scarcity pressure. The inactivity model optimizes for:
1. **Stability**: Active nodes keep their IP forever
2. **Efficiency**: No renewal traffic for active nodes
3. **Resilience**: Brief network outages don't cause IP loss

## NAT Traversal (STUN/TURN)

Edge gateways provide NAT traversal services for devices behind firewalls.

### STUN Service

```go
// STUNService provides NAT type detection and address discovery
type STUNService struct {
    listenAddr netip.AddrPort
    altAddr    netip.AddrPort  // Alternative address for NAT detection
}

// HandleBinding processes STUN Binding request
func (s *STUNService) HandleBinding(req *stun.Message, from netip.AddrPort) (*stun.Message, error) {
    resp := stun.NewMessage()
    resp.Type = stun.BindingSuccess
    resp.TransactionID = req.TransactionID

    // Return observed address (XOR-MAPPED-ADDRESS)
    xorAddr := stun.XORMappedAddress{
        IP:   from.Addr().AsSlice(),
        Port: int(from.Port()),
    }
    xorAddr.AddTo(resp)

    return resp, nil
}

// DetectNATType determines NAT type for a client
func (s *STUNService) DetectNATType(clientAddr netip.AddrPort) NATType {
    // Test 1: Same IP, same port
    // Test 2: Same IP, different port
    // Test 3: Different IP, different port
    // Based on RFC 3489 NAT classification
    ...
}
```

### TURN Relay

```go
// TURNService provides relay for symmetric NAT
type TURNService struct {
    allocations map[string]*Allocation
    mu          sync.RWMutex
}

type Allocation struct {
    ClientAddr  netip.AddrPort
    RelayAddr   netip.AddrPort
    Permissions map[netip.AddrPort]time.Time
    ExpiresAt   time.Time
}

// Allocate creates a relay allocation
func (t *TURNService) Allocate(ctx context.Context, client netip.AddrPort, lifetime time.Duration) (*Allocation, error) {
    // Allocate relay port
    relayAddr, err := t.allocateRelayPort()
    if err != nil {
        return nil, err
    }

    alloc := &Allocation{
        ClientAddr:  client,
        RelayAddr:   relayAddr,
        Permissions: make(map[netip.AddrPort]time.Time),
        ExpiresAt:   time.Now().Add(lifetime),
    }

    key := fmt.Sprintf("%s:%d", client.Addr(), client.Port())
    t.mu.Lock()
    t.allocations[key] = alloc
    t.mu.Unlock()

    return alloc, nil
}

// Relay forwards data between client and peer
func (t *TURNService) Relay(data []byte, from netip.AddrPort, alloc *Allocation) error {
    if from == alloc.ClientAddr {
        // Client -> Peer (via relay)
        // Extract peer address from ChannelData
        // Forward to peer
    } else {
        // Peer -> Client (via relay)
        // Check permissions
        if _, ok := alloc.Permissions[from]; !ok {
            return ErrPermissionDenied
        }
        // Forward to client
    }
    return nil
}
```

## Rate Limiting

Edge gateways enforce per-peer rate limits based on reputation.

### Rate Limit Tiers

| Trust Level | Rate Limit | Burst | Description |
|-------------|------------|-------|-------------|
| **Trusted** | 100 req/s | 200 | Reputation >= 0.80 |
| **Untrusted** | 10 req/s | 20 | Reputation < 0.80 |
| **New/Unknown** | 5 req/s | 10 | No reputation history |
| **Blocked** | 0 req/s | 0 | Blacklisted |

### Implementation

```go
// RateLimiter implements token bucket with reputation tiers
type RateLimiter struct {
    buckets       map[NodeID]*TokenBucket
    reputationSvc *reputation.Service
    mu            sync.RWMutex
}

type TokenBucket struct {
    Rate       float64       // Tokens per second
    Burst      int           // Maximum tokens
    Tokens     float64       // Current tokens
    LastUpdate time.Time
}

// Allow checks if request should be allowed
func (r *RateLimiter) Allow(nodeID NodeID) bool {
    r.mu.Lock()
    defer r.mu.Unlock()

    bucket, exists := r.buckets[nodeID]
    if !exists {
        // Determine rate based on reputation
        rate, burst := r.getRateLimits(nodeID)
        bucket = &TokenBucket{
            Rate:       rate,
            Burst:      burst,
            Tokens:     float64(burst),
            LastUpdate: time.Now(),
        }
        r.buckets[nodeID] = bucket
    }

    // Refill tokens based on elapsed time
    now := time.Now()
    elapsed := now.Sub(bucket.LastUpdate).Seconds()
    bucket.Tokens = min(float64(bucket.Burst), bucket.Tokens+elapsed*bucket.Rate)
    bucket.LastUpdate = now

    // Check if token available
    if bucket.Tokens >= 1 {
        bucket.Tokens--
        return true
    }

    return false
}

// getRateLimits returns rate limits based on reputation
func (r *RateLimiter) getRateLimits(nodeID NodeID) (rate float64, burst int) {
    rep, err := r.reputationSvc.GetReputation(nodeID)
    if err != nil {
        return 5, 10 // Unknown
    }

    switch {
    case rep >= 0.80:
        return 100, 200 // Trusted
    case rep >= 0.20:
        return 10, 20 // Untrusted
    default:
        return 5, 10 // New
    }
}
```

## IoT Onboarding Flow

Complete 7-step onboarding flow for IoT devices:

```
+------------------------------------------------------------------+
|                    IoT Onboarding Flow (7 Steps)                  |
+------------------------------------------------------------------+
|                                                                   |
|  Step 1: Device Discovery                                         |
|  +--------------------------------------------------------------+ |
|  | - Device discovers edge gateway via DNS/mDNS/bootstrap list  | |
|  | - Establishes TLS connection (server-only auth initially)    | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 2: ACME endorse-01 Challenge                                |
|  +--------------------------------------------------------------+ |
|  | - Gateway sends challenge with nonce                         | |
|  | - Device responds with EK cert + TPM attestation             | |
|  | - Gateway validates EK chain to manufacturer root            | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 3: ACME enroll-01 Challenge                                 |
|  +--------------------------------------------------------------+ |
|  | - Device generates key pair (RSA-2048 or EC P-256)           | |
|  | - Device submits CSR signed by TPM-resident key              | |
|  | - Gateway requests FROST threshold signature from CA         | |
|  | - IDevID certificate issued with IPv6 in SAN                 | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 4: IPv6 Allocation                                          |
|  +--------------------------------------------------------------+ |
|  | - Gateway allocates IPv6 from regional pool                  | |
|  | - Address embedded in IDevID certificate                     | |
|  | - Allocation recorded in QuicBaaS (kept while active)        | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 5: DHT Bootstrap                                            |
|  +--------------------------------------------------------------+ |
|  | - Device receives k-closest nodes                            | |
|  | - Device receives regional coordinator addresses             | |
|  | - Device registered as leaf node in DHT                      | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 6: Network Configuration                                    |
|  +--------------------------------------------------------------+ |
|  | - Device configures allocated IPv6 on interface              | |
|  | - Routes configured via gateway                               | |
|  | - DNS resolver configured                                     | |
|  +--------------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  Step 7: Reputation Building                                      |
|  +--------------------------------------------------------------+ |
|  | - Device starts at reputation 0.0                            | |
|  | - Participates in DHT (routing, storage)                     | |
|  | - Periodic TPM attestation (+0.01 per success)               | |
|  | - Uptime monitoring begins                                    | |
|  +--------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Onboarding State Machine

```go
// OnboardingSession tracks device onboarding state
type OnboardingSession struct {
    ID           string
    DeviceID     NodeID
    State        OnboardingState
    StartedAt    time.Time
    ExpiresAt    time.Time

    // Challenge state
    EndorseToken string
    EnrollToken  string
    EKCert       *x509.Certificate
    AKPublic     crypto.PublicKey

    // Results
    IDevID       *x509.Certificate
    IPv6Address  netip.Addr
    BootstrapNodes []NodeInfo
}

type OnboardingState uint8

const (
    OnboardingStateNew OnboardingState = iota
    OnboardingStateEndorseChallengePending
    OnboardingStateEndorseComplete
    OnboardingStateEnrollChallengePending
    OnboardingStateEnrollComplete
    OnboardingStateIPv6Allocated
    OnboardingStateDHTBootstrapped
    OnboardingStateComplete
    OnboardingStateFailed
)

// StateTransitions defines valid state transitions
var StateTransitions = map[OnboardingState][]OnboardingState{
    OnboardingStateNew:                     {OnboardingStateEndorseChallengePending},
    OnboardingStateEndorseChallengePending: {OnboardingStateEndorseComplete, OnboardingStateFailed},
    OnboardingStateEndorseComplete:         {OnboardingStateEnrollChallengePending},
    OnboardingStateEnrollChallengePending:  {OnboardingStateEnrollComplete, OnboardingStateFailed},
    OnboardingStateEnrollComplete:          {OnboardingStateIPv6Allocated},
    OnboardingStateIPv6Allocated:           {OnboardingStateDHTBootstrapped},
    OnboardingStateDHTBootstrapped:         {OnboardingStateComplete},
}
```

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edge_onboarding_sessions` | Gauge | state | Sessions by state |
| `edge_onboarding_completed` | Counter | - | Successful onboardings |
| `edge_onboarding_failed` | Counter | reason | Failed onboardings |
| `edge_acme_challenges` | Counter | type, result | ACME challenge outcomes |
| `edge_ipv6_allocations` | Counter | region | IPv6 allocations |
| `edge_ipv6_renewals` | Counter | - | Lease renewals |
| `edge_dht_bootstraps` | Counter | - | DHT bootstrap requests |
| `edge_rate_limited` | Counter | tier | Rate limit rejections |
| `edge_stun_requests` | Counter | - | STUN binding requests |
| `edge_turn_allocations` | Gauge | - | Active TURN allocations |

## See Also

- [Gateway Architecture](architecture.md) - Core gateway design
- [ACME Protocol](../../dht/04-cryptographic-protocols.md) - ACME challenge details
- [IPv6 Allocation](../../dht/02-network-architecture.md) - Address allocation design
- [Reputation System](../../dht/09-defense-reputation.md) - Rate limiting tiers
- [Configuration](configuration.md) - Edge mode configuration

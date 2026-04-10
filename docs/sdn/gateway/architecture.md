# Gateway Architecture

## Overview

The unified gateway architecture provides a modular, extensible framework for network gateway functions. Each gateway node can operate multiple modes simultaneously through a shared infrastructure layer that handles common concerns like clustering, health monitoring, and security.

## Core Components

### GatewayNode Structure

```go
// GatewayNode represents a unified gateway node
type GatewayNode struct {
    // Identity
    ID              NodeID
    PublicKey       crypto.PublicKey
    Certificate     *x509.Certificate

    // Network
    UnderlayIP      netip.Addr           // Physical network IP
    OverlayIP       netip.Addr           // Overlay network IP
    AdvertisedIPs   []netip.Addr         // Anycast/VIP addresses

    // Mode configuration
    Modes           GatewayMode          // Bitmask of active modes
    OverlayState    *OverlayState        // Overlay mode state
    EdgeState       *EdgeState           // Edge mode state
    TransitState    *TransitState        // Transit mode state

    // Cluster membership
    ClusterID       string
    ClusterRole     ClusterRole          // Primary, Secondary, Witness
    ClusterPeers    []NodeID

    // Capabilities
    Capabilities    GatewayCapabilities

    // Runtime
    Status          GatewayStatus
    StartedAt       time.Time
    LastHeartbeat   time.Time
}

// GatewayMode is a bitmask of enabled modes
type GatewayMode uint8

const (
    GatewayModeOverlay GatewayMode = 1 << 0  // 0x01 - SDN overlay
    GatewayModeEdge    GatewayMode = 1 << 1  // 0x02 - Edge/P2P/IoT
    GatewayModeTransit GatewayMode = 1 << 2  // 0x04 - BGP transit
)

// Mode helpers
func (m GatewayMode) HasOverlay() bool { return m&GatewayModeOverlay != 0 }
func (m GatewayMode) HasEdge() bool    { return m&GatewayModeEdge != 0 }
func (m GatewayMode) HasTransit() bool { return m&GatewayModeTransit != 0 }
```

### Mode-Specific State

Each enabled mode maintains its own operational state:

```go
// OverlayState holds SDN overlay mode state
type OverlayState struct {
    VTEP            *VTEP                // VXLAN tunnel endpoint
    MACTable        *MACTable            // Learned MAC addresses
    ARPCache        *ARPCache            // Proxy ARP entries
    EVPNRoutes      *EVPNRouteTable      // EVPN Type-2/3 routes
    FlowRules       []OpenFlowRule       // Installed OpenFlow rules
    ActiveVNIs      map[uint32]VNIInfo   // Active VXLAN Network IDs
}

// EdgeState holds edge/P2P gateway mode state
type EdgeState struct {
    ACMEServer      *ACMEServer          // ACME challenge server
    DHTBootstrap    *BootstrapService    // DHT entry point
    IPv6Allocator   *IPv6Allocator       // Address pool manager
    NATTraversal    *NATTraversalService // STUN/TURN
    RateLimiter     *RateLimiter         // Per-peer rate limiting
    OnboardingSessions map[string]*Session // Active onboarding
}

// TransitState holds BGP transit mode state
type TransitState struct {
    BGPSpeaker      *BGPSpeaker          // BGP protocol handler
    RIB             *RoutingInfoBase     // Routing table
    RPKIValidator   *RPKIValidator       // RPKI cache client
    Dampener        *FlapDampener        // Route stability
    SignedRoutes    map[netip.Prefix]*SignedRoute // Coordinator-signed
    Peers           map[string]*BGPPeer  // eBGP/iBGP peers
}
```

## Component Architecture

```
+------------------------------------------------------------------+
|                        Gateway Node                               |
+------------------------------------------------------------------+
|                                                                   |
|  +-------------------+  +-------------------+  +-----------------+|
|  |   Overlay Mode    |  |    Edge Mode      |  |  Transit Mode   ||
|  |                   |  |                   |  |                 ||
|  | - VTEP            |  | - ACME Server     |  | - BGP Speaker   ||
|  | - EVPN Routes     |  | - DHT Bootstrap   |  | - RIB           ||
|  | - ARP Suppression |  | - IPv6 Allocator  |  | - RPKI          ||
|  | - MAC Learning    |  | - NAT Traversal   |  | - Dampening     ||
|  +--------+----------+  +--------+----------+  +--------+--------+|
|           |                      |                      |         |
|  +--------v----------------------v----------------------v--------+|
|  |                     Shared Infrastructure                      ||
|  |                                                                ||
|  |  +------------+  +------------+  +------------+  +----------+ ||
|  |  |  Routing   |  |    NAT     |  |    Load    |  | Security | ||
|  |  |  Engine    |  |  Handler   |  |  Balancer  |  |  Module  | ||
|  |  +------------+  +------------+  +------------+  +----------+ ||
|  |                                                                ||
|  +----------------------------------------------------------------+|
|                                |                                   |
|  +----------------------------v----------------------------------+|
|  |                    Cluster Manager                             ||
|  |                                                                ||
|  |  +-------------+  +-------------+  +-------------+            ||
|  |  |   Health    |  |   State     |  |  Failover   |            ||
|  |  |   Monitor   |  |   Sync      |  |  Handler    |            ||
|  |  +-------------+  +-------------+  +-------------+            ||
|  |                                                                ||
|  +----------------------------+-----------------------------------+|
|                               |                                    |
+-------------------------------|------------------------------------+
                                |
                         +------v------+
                         |  QuicBaaS   |
                         |  Cluster    |
                         +-------------+
```

## Cluster Coordination via QuicBaaS

Gateway nodes coordinate through QuicBaaS for distributed state management.

### QuicBaaS Partitions

| Partition | Purpose | Consistency |
|-----------|---------|-------------|
| `sdn/gateway/nodes` | Gateway registry | Linearizable |
| `sdn/gateway/vips` | VIP ownership | Linearizable |
| `sdn/gateway/macs` | MAC table | Eventual |
| `sdn/gateway/sessions` | Onboarding sessions | Linearizable |
| `sdn/gateway/routes` | BGP route state | Linearizable |

### State Replication

```go
// GatewayRegistry manages gateway cluster membership
type GatewayRegistry struct {
    db          *quicbaas.Client
    partition   string
    localNode   *GatewayNode
    peers       map[NodeID]*GatewayNode
    mu          sync.RWMutex
}

// Register gateway node in cluster
func (r *GatewayRegistry) Register(ctx context.Context, node *GatewayNode) error {
    key := fmt.Sprintf("%s/%s", r.partition, node.ID)
    value, err := json.Marshal(node)
    if err != nil {
        return fmt.Errorf("marshal node: %w", err)
    }

    // Atomic registration with TTL
    if err := r.db.PutWithTTL(ctx, key, value, 30*time.Second); err != nil {
        return fmt.Errorf("register node: %w", err)
    }

    return nil
}

// Heartbeat refreshes node registration
func (r *GatewayRegistry) Heartbeat(ctx context.Context) error {
    r.localNode.LastHeartbeat = time.Now()
    return r.Register(ctx, r.localNode)
}

// WatchPeers monitors cluster membership changes
func (r *GatewayRegistry) WatchPeers(ctx context.Context, handler func(NodeID, *GatewayNode)) {
    prefix := r.partition + "/"
    ch := r.db.Watch(ctx, prefix)

    for event := range ch {
        switch event.Type {
        case quicbaas.EventPut:
            var node GatewayNode
            if err := json.Unmarshal(event.Value, &node); err != nil {
                continue
            }
            r.mu.Lock()
            r.peers[node.ID] = &node
            r.mu.Unlock()
            handler(node.ID, &node)

        case quicbaas.EventDelete:
            nodeID := NodeID(strings.TrimPrefix(event.Key, prefix))
            r.mu.Lock()
            delete(r.peers, nodeID)
            r.mu.Unlock()
            handler(nodeID, nil)
        }
    }
}
```

## Gateway Promotion/Demotion Flow

### Promotion Flow

```
+------------------------------------------------------------------+
|                    Gateway Promotion Flow                          |
+------------------------------------------------------------------+
|                                                                   |
|  1. Node Eligibility Check                                        |
|     +----------------------------------------------------------+ |
|     | - Reputation >= 0.85                                     | |
|     | - Network age >= 175 days (85 base + 90 probation)       | |
|     | - Uptime >= 95%                                          | |
|     | - Bandwidth >= 100 Mbps                                  | |
|     | - TPM attestation current                                | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. Capability Assessment                                         |
|     +----------------------------------------------------------+ |
|     | - Network connectivity (IPv4/IPv6)                       | |
|     | - BGP peering capability (for transit mode)              | |
|     | - Available IP pools (for edge mode)                     | |
|     | - OVS/OpenFlow support (for overlay mode)                | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  3. Cluster Admission                                             |
|     +----------------------------------------------------------+ |
|     | - Request admission from existing gateways               | |
|     | - Receive cluster configuration                          | |
|     | - Synchronize initial state from QuicBaaS                | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  4. Mode Activation                                               |
|     +----------------------------------------------------------+ |
|     | - Initialize mode-specific state                         | |
|     | - Configure network interfaces                           | |
|     | - Install OpenFlow rules (overlay mode)                  | |
|     | - Establish BGP sessions (transit mode)                  | |
|     | - Start ACME server (edge mode)                          | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  5. Service Announcement                                          |
|     +----------------------------------------------------------+ |
|     | - Register in QuicBaaS gateway partition                 | |
|     | - Announce routes (transit mode)                         | |
|     | - Publish capabilities to DHT                            | |
|     | - Begin accepting traffic                                | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Demotion Flow

```go
// DemoteGateway handles graceful gateway demotion
func (g *GatewayNode) Demote(ctx context.Context, reason DemotionReason) error {
    g.Status = GatewayStatusDemoting

    // 1. Stop accepting new connections
    g.stopAcceptingConnections()

    // 2. Drain existing connections (graceful)
    drainCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    if err := g.drainConnections(drainCtx); err != nil {
        // Force close if drain timeout
        g.forceCloseConnections()
    }

    // 3. Mode-specific shutdown
    if g.Modes.HasTransit() {
        // Withdraw BGP routes
        if err := g.TransitState.BGPSpeaker.WithdrawAllRoutes(ctx); err != nil {
            return fmt.Errorf("withdraw routes: %w", err)
        }
    }

    if g.Modes.HasOverlay() {
        // Remove from VTEP mesh
        if err := g.OverlayState.VTEP.Deregister(ctx); err != nil {
            return fmt.Errorf("deregister VTEP: %w", err)
        }
    }

    if g.Modes.HasEdge() {
        // Stop accepting onboarding
        g.EdgeState.ACMEServer.Stop()
        g.EdgeState.DHTBootstrap.Stop()
    }

    // 4. Transfer VIP ownership
    if err := g.transferVIPs(ctx); err != nil {
        return fmt.Errorf("transfer VIPs: %w", err)
    }

    // 5. Deregister from cluster
    if err := g.clusterRegistry.Deregister(ctx, g.ID); err != nil {
        return fmt.Errorf("deregister: %w", err)
    }

    g.Status = GatewayStatusDemoted
    return nil
}

type DemotionReason uint8

const (
    DemotionReasonManual           DemotionReason = iota // Operator requested
    DemotionReasonReputationDrop                          // Reputation < 0.85
    DemotionReasonUptimeDrop                              // Uptime < 95%
    DemotionReasonHealthCheckFail                         // Failed health checks
    DemotionReasonSlashing                                // Stake slashing event
    DemotionReasonGracefulShutdown                        // Node shutdown
)
```

## Health Monitoring and Heartbeat

### Health Check Protocol

```go
// HealthMonitor monitors gateway health
type HealthMonitor struct {
    gateway     *GatewayNode
    interval    time.Duration           // HeartbeatInterval = 2s
    threshold   int                     // MissedHeartbeatThreshold = 4
    failTimeout time.Duration           // FailureDetectionTimeout = 8s

    peers       map[NodeID]*PeerHealth
    mu          sync.RWMutex
}

type PeerHealth struct {
    NodeID          NodeID
    LastHeartbeat   time.Time
    MissedCount     int
    Status          HealthStatus
}

type HealthStatus uint8

const (
    HealthStatusHealthy  HealthStatus = iota
    HealthStatusSuspect
    HealthStatusFailed
)

// MonitorPeers watches peer health
func (h *HealthMonitor) MonitorPeers(ctx context.Context) {
    ticker := time.NewTicker(h.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            h.checkPeers()
        }
    }
}

func (h *HealthMonitor) checkPeers() {
    h.mu.Lock()
    defer h.mu.Unlock()

    now := time.Now()
    for id, peer := range h.peers {
        timeSinceHeartbeat := now.Sub(peer.LastHeartbeat)

        switch {
        case timeSinceHeartbeat > h.failTimeout:
            // Failed
            if peer.Status != HealthStatusFailed {
                peer.Status = HealthStatusFailed
                h.handlePeerFailure(id)
            }

        case timeSinceHeartbeat > h.interval*time.Duration(h.threshold/2):
            // Suspect
            peer.Status = HealthStatusSuspect
            peer.MissedCount++

        default:
            // Healthy
            peer.Status = HealthStatusHealthy
            peer.MissedCount = 0
        }
    }
}

func (h *HealthMonitor) handlePeerFailure(peerID NodeID) {
    // Trigger failover for VIPs owned by failed peer
    h.gateway.clusterManager.TriggerFailover(peerID)
}
```

### Multi-Layer Health Probes

| Layer | Probe Type | Interval | Timeout | Threshold |
|-------|------------|----------|---------|-----------|
| L3 | ICMP ping | 1s | 500ms | 3 failures |
| L4 | TCP connect | 2s | 1s | 2 failures |
| L7 | HTTP /health | 5s | 2s | 2 failures |
| Cluster | Heartbeat | 2s | 2s | 4 missed |

## Failover Coordination

### VIP Failover

```go
// VIPManager handles VIP ownership and failover
type VIPManager struct {
    db           *quicbaas.Client
    localGateway *GatewayNode
    ownedVIPs    map[netip.Addr]*VIPInfo
    mu           sync.RWMutex
}

type VIPInfo struct {
    Address     netip.Addr
    Owner       NodeID
    Priority    int
    LastClaim   time.Time
}

// ClaimVIP attempts to claim a VIP during failover
func (v *VIPManager) ClaimVIP(ctx context.Context, vip netip.Addr) error {
    key := fmt.Sprintf("sdn/gateway/vips/%s", vip)

    // Attempt CAS claim
    claim := &VIPClaim{
        VIP:       vip,
        Owner:     v.localGateway.ID,
        ClaimedAt: time.Now(),
        Priority:  v.calculatePriority(),
    }

    claimBytes, _ := json.Marshal(claim)

    // CAS: only succeed if we have highest priority or VIP is unclaimed
    if err := v.db.CompareAndSwap(ctx, key, nil, claimBytes); err != nil {
        // Check if we should preempt current owner
        return v.attemptPreemption(ctx, vip, claim)
    }

    // Claim successful - configure VIP on interface
    if err := v.configureVIP(vip); err != nil {
        // Rollback claim
        v.db.Delete(ctx, key)
        return fmt.Errorf("configure VIP: %w", err)
    }

    v.mu.Lock()
    v.ownedVIPs[vip] = &VIPInfo{
        Address:   vip,
        Owner:     v.localGateway.ID,
        Priority:  claim.Priority,
        LastClaim: claim.ClaimedAt,
    }
    v.mu.Unlock()

    return nil
}

// TriggerFailover handles peer failure
func (c *ClusterManager) TriggerFailover(failedPeer NodeID) {
    // Find VIPs owned by failed peer
    vips := c.vipManager.GetVIPsByOwner(failedPeer)

    // Attempt to claim each VIP
    for _, vip := range vips {
        go func(v netip.Addr) {
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            defer cancel()

            if err := c.vipManager.ClaimVIP(ctx, v); err != nil {
                slog.Warn("VIP claim failed",
                    slog.String("vip", v.String()),
                    slog.Any("error", err),
                )
            } else {
                slog.Info("VIP claimed",
                    slog.String("vip", v.String()),
                )
            }
        }(vip.Address)
    }
}
```

## Gateway Lifecycle

### Initialization

```go
// NewGatewayNode creates and initializes a gateway node
func NewGatewayNode(config *GatewayConfig) (*GatewayNode, error) {
    node := &GatewayNode{
        ID:         config.NodeID,
        UnderlayIP: config.UnderlayIP,
        Modes:      config.Modes,
        Status:     GatewayStatusInitializing,
        StartedAt:  time.Now(),
    }

    // Initialize cluster manager
    clusterMgr, err := NewClusterManager(config.QuicBaaS, node)
    if err != nil {
        return nil, fmt.Errorf("cluster manager: %w", err)
    }
    node.clusterManager = clusterMgr

    // Initialize mode-specific state
    if config.Modes.HasOverlay() {
        node.OverlayState, err = NewOverlayState(config.Overlay)
        if err != nil {
            return nil, fmt.Errorf("overlay state: %w", err)
        }
    }

    if config.Modes.HasEdge() {
        node.EdgeState, err = NewEdgeState(config.Edge)
        if err != nil {
            return nil, fmt.Errorf("edge state: %w", err)
        }
    }

    if config.Modes.HasTransit() {
        node.TransitState, err = NewTransitState(config.Transit)
        if err != nil {
            return nil, fmt.Errorf("transit state: %w", err)
        }
    }

    return node, nil
}

// Start begins gateway operation
func (g *GatewayNode) Start(ctx context.Context) error {
    // Join cluster
    if err := g.clusterManager.Join(ctx); err != nil {
        return fmt.Errorf("join cluster: %w", err)
    }

    // Start health monitoring
    go g.clusterManager.HealthMonitor.MonitorPeers(ctx)

    // Start heartbeat
    go g.clusterManager.StartHeartbeat(ctx)

    // Activate modes
    if g.Modes.HasOverlay() {
        if err := g.OverlayState.Activate(ctx); err != nil {
            return fmt.Errorf("activate overlay: %w", err)
        }
    }

    if g.Modes.HasEdge() {
        if err := g.EdgeState.Activate(ctx); err != nil {
            return fmt.Errorf("activate edge: %w", err)
        }
    }

    if g.Modes.HasTransit() {
        if err := g.TransitState.Activate(ctx); err != nil {
            return fmt.Errorf("activate transit: %w", err)
        }
    }

    g.Status = GatewayStatusActive
    return nil
}

// Stop gracefully shuts down the gateway
func (g *GatewayNode) Stop(ctx context.Context) error {
    return g.Demote(ctx, DemotionReasonGracefulShutdown)
}
```

## Integration Points

### SDN Policy Engine

```go
// PolicyEngineAdapter integrates with 802.1X policy engine
type PolicyEngineAdapter struct {
    policyEngine *policy.Engine
    gateway      *GatewayNode
}

// OnDeviceAuthenticated handles device authentication
func (a *PolicyEngineAdapter) OnDeviceAuthenticated(port string, cert *x509.Certificate) {
    // Extract policy from certificate
    pol := a.policyEngine.ExtractPolicy(cert)

    // Assign VLAN
    vlan := pol.VLAN

    // Derive VNI for overlay
    vni := VNIBase + uint32(vlan)

    // Update overlay state
    if a.gateway.Modes.HasOverlay() {
        a.gateway.OverlayState.AddVNI(vni, VNIInfo{
            VLAN:        vlan,
            TenantID:    pol.TenantID,
            DeviceCount: 1,
        })
    }
}
```

### BGP Speaker

```go
// BGPAdapter integrates with BGP subsystem
type BGPAdapter struct {
    speaker  *bgp.Speaker
    gateway  *GatewayNode
}

// AnnouncePrefix announces a prefix via BGP
func (a *BGPAdapter) AnnouncePrefix(ctx context.Context, prefix netip.Prefix) error {
    if !a.gateway.Modes.HasTransit() {
        return ErrTransitModeNotEnabled
    }

    // Request coordinator signature
    signed, err := a.gateway.TransitState.RequestRouteSigning(ctx, prefix)
    if err != nil {
        return fmt.Errorf("sign route: %w", err)
    }

    // Announce via BGP
    if err := a.speaker.AnnounceRoute(ctx, signed); err != nil {
        return fmt.Errorf("announce: %w", err)
    }

    // Store in state
    a.gateway.TransitState.SignedRoutes[prefix] = signed

    return nil
}
```

## Metrics

### Gateway Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gateway_active_modes` | Gauge | mode | Currently active modes |
| `gateway_cluster_peers` | Gauge | - | Number of cluster peers |
| `gateway_vips_owned` | Gauge | - | Number of VIPs owned |
| `gateway_connections_active` | Gauge | mode | Active connections per mode |
| `gateway_heartbeats_sent` | Counter | - | Heartbeats sent |
| `gateway_heartbeats_missed` | Counter | peer | Missed heartbeats per peer |
| `gateway_failovers_triggered` | Counter | - | Failover events |
| `gateway_vip_claims_total` | Counter | result | VIP claim attempts |
| `gateway_mode_activations` | Counter | mode | Mode activation count |
| `gateway_demotions` | Counter | reason | Demotion events by reason |

## See Also

- [Overlay Mode](overlay-mode.md) - SDN overlay mode details
- [Edge Mode](edge-mode.md) - Edge/P2P/IoT gateway mode
- [Transit Mode](transit-mode.md) - BGP transit mode
- [Configuration](configuration.md) - Complete configuration reference

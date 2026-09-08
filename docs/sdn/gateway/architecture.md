# Gateway Architecture

## Overview

The unified gateway architecture provides a modular, extensible framework for network gateway functions. Each gateway node can operate multiple modes simultaneously through a shared infrastructure layer.

> **Not re-verified legacy material.** The normative description is
> [`docs/gateway/architecture.md`](../../gateway/architecture.md). Where this
> file disagrees with it, that file wins. The clustering, heartbeat and
> failover sections below are marked superseded (#559): no such code exists.

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

    // Cluster membership — DESIGN ONLY; none of these fields exist in
    // pkg/sdn/gateway (#559)
    ClusterID       string
    ClusterRole     ClusterRole          // Primary, Secondary, Witness
    ClusterPeers    []NodeID

    // Capabilities
    Capabilities    GatewayCapabilities

    // Runtime
    Status          GatewayStatus
    StartedAt       time.Time
    LastHeartbeat   time.Time            // DESIGN ONLY (#559)
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

> **Superseded — not implemented (2026-09-07, #559).** The four sections that stood here — *Cluster Coordination via QuicBaaS* (partitions and state replication), *Gateway Promotion/Demotion Flow* (Primary/Secondary/Witness roles, admission, 30-second drain then BGP withdrawal), *Health Monitoring and Heartbeat*, and *Failover Coordination* (VIP failover) — described a cluster manager that was never written. `ClusterRole`, `ClusterPeers`, `ClusterID`, `LastHeartbeat`, `Demote` and `DemotionReason` are not identifiers in `pkg/sdn/gateway`.
> The normative statement is [`docs/gateway/architecture.md`](../../gateway/architecture.md)
> §High availability; the two-gateway design is decided under epic #553
> (Phase 5, ruling R7). Do not build against the removed text.
>
> What exists today: a single gateway per site, no clustering, election,
> heartbeat, VIP takeover or state replication in code. `pkg/sdn/cluster/gateway_partitions.go`
> declares partition keys for such a design and is referenced by nothing.
> The load balancer's VIP is a single-node OpenFlow select group
> (`pkg/sdn/gateway/services/loadbalancer/`), with no ownership or migration.

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

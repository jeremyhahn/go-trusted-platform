# Unified Gateway Nodes

## Overview

Unified gateway nodes are high-reputation network infrastructure nodes that provide multiple network functions through a single, coordinated component. Each gateway can operate in one or more modes simultaneously, providing SDN overlay connectivity, edge/P2P/IoT onboarding, and BGP transit services.

The gateway architecture consolidates network functions that traditionally required separate infrastructure into a unified, software-defined node that participates in the distributed trust network.

## Gateway Modes

Gateway nodes support three operational modes that can be enabled independently or combined:

| Mode | Purpose | Key Functions |
|------|---------|---------------|
| **Overlay** | SDN east-west connectivity | VTEP, VXLAN encap/decap, EVPN, ARP suppression |
| **Edge** | P2P/IoT device onboarding | ACME challenges, DHT bootstrap, IPv6 allocation, NAT traversal |
| **Transit** | BGP route announcement | IPv6/IPv4 announcement, RPKI validation, route signing |

### Mode Bitmask

Modes are represented as a bitmask allowing combinations:

```go
type GatewayMode uint8

const (
    GatewayModeOverlay GatewayMode = 1 << 0  // 0x01
    GatewayModeEdge    GatewayMode = 1 << 1  // 0x02
    GatewayModeTransit GatewayMode = 1 << 2  // 0x04
)

// Combined modes
const (
    GatewayModeOverlayEdge   = GatewayModeOverlay | GatewayModeEdge    // 0x03
    GatewayModeEdgeTransit   = GatewayModeEdge | GatewayModeTransit    // 0x06
    GatewayModeFull          = GatewayModeOverlay | GatewayModeEdge | GatewayModeTransit // 0x07
)
```

## Gateway Requirements

Gateway nodes must meet strict eligibility requirements before promotion. These thresholds protect the network by ensuring only proven, reliable nodes handle critical infrastructure functions.

| Requirement | Value | Rationale |
|-------------|-------|-----------|
| **Minimum Reputation** | 0.85 | External-facing nodes need high trust |
| **Minimum Network Age** | 85 days base | Sybil attack prevention |
| **Probation Period** | 90 days | Behavioral observation period |
| **Random Delay** | 0-30 days | Additional Sybil resistance |
| **Effective Minimum Age** | 175+ days | Combined requirements |
| **Minimum Uptime** | 95% | Reliability for routing |
| **Minimum Bandwidth** | 100 Mbps | Capacity for relay traffic |
| **TPM Attestation** | Current | Hardware security verification |

> **Cross-Reference:** See [00-CONSTANTS.md](../../dht/00-CONSTANTS.md) Section 13 for complete role eligibility staggering and [09-defense-reputation.md](../../dht/09-defense-reputation.md) for reputation system details.

## Anycast Gateway Architecture

Multiple gateway nodes can provide the same service through anycast addressing, enabling automatic failover and distributed load.

### Distributed Anycast Design

```
                    Internet
                       |
        +------+-------+-------+------+
        |      |       |       |      |
    +---v--+ +-v---+ +-v---+ +-v---+ +-v---+
    |GW-NA1| |GW-NA2| |GW-EU1| |GW-EU2| |GW-AP1|
    +------+ +-----+ +-----+ +-----+ +------+
       |        |       |       |       |
       +--------+-------+-------+-------+
                        |
                   DHT Network
              (Overlay Connectivity)
```

### Anycast IP Assignment

| IP Block | Purpose | Announcement Level |
|----------|---------|-------------------|
| 2602:F5BB::/36 | IPv6 aggregate | Backbone speakers (global) |
| 2602:F5BB:XXXX::/48 | Regional prefix | Datacenter speakers |
| 23.143.36.0/24 | IPv4 gateway pool | Selected gateways |

### Traffic Distribution

1. **Geographic affinity**: DNS resolves to nearest gateway via anycast
2. **BGP routing**: Internet routes to shortest AS path
3. **Health-aware**: Unhealthy gateways withdraw routes automatically
4. **Load distribution**: Multiple gateways share traffic within region

## High Availability Design

### Active-Active Clustering

Gateway nodes operate in active-active clusters coordinated through QuicBaaS:

```
+----------------------------------------------------------+
|                    QuicBaaS Cluster                       |
|  (Distributed State for Gateway Coordination)            |
+----------------------------------------------------------+
         |              |              |
    +----v----+    +----v----+    +----v----+
    | Gateway |    | Gateway |    | Gateway |
    |   #1    |    |   #2    |    |   #3    |
    | Active  |    | Active  |    | Active  |
    +---------+    +---------+    +---------+
         |              |              |
    +----v--------------v--------------v----+
    |          Shared VIP Pool              |
    |    (Distributed Load Balancing)       |
    +---------------------------------------+
```

### Failover Mechanisms

| Layer | Detection | Recovery Time | Mechanism |
|-------|-----------|---------------|-----------|
| L3/BGP | BGP hold timer | 30 seconds | Route withdrawal |
| L4/VIP | Health probe | 5 seconds | VIP migration |
| L7/App | HTTP probe | 10 seconds | Backend removal |
| Cluster | Heartbeat | 8 seconds | State failover |

### State Synchronization

- **Session state**: Replicated via QuicBaaS for stateful failover
- **MAC tables**: Eventually consistent across overlay gateways
- **NAT mappings**: Distributed across active gateways
- **Rate limit state**: Per-gateway with global aggregation

## Package Structure

```
pkg/sdn/gateway/
+-- types.go              # GatewayNode, GatewayMode, GatewayCapabilities
+-- errors.go             # Typed errors
+-- node.go               # Gateway node lifecycle
+-- modes/
|   +-- overlay.go        # SDN overlay mode (VXLAN, EVPN)
|   +-- edge.go           # Edge/P2P/IoT mode (device onboarding, DHT)
|   +-- transit.go        # BGP transit mode (IP block announcement)
+-- cluster/
|   +-- manager.go        # HA coordination via QuicBaaS
|   +-- election.go       # Gateway promotion/demotion
|   +-- health.go         # Health monitoring, heartbeat
+-- routing/
|   +-- router.go         # L3 routing engine
|   +-- ecmp.go           # Equal-cost multi-path
|   +-- rib.go            # Routing Information Base
+-- nat/
|   +-- snat.go           # Source NAT for egress
|   +-- dnat.go           # Destination NAT for ingress
|   +-- cgnat.go          # Carrier-grade NAT for IoT (RFC 6598)
+-- loadbalancer/
|   +-- ingress.go        # VIP-based load balancing
|   +-- algorithm.go      # RR, WRR, least-conn, maglev
|   +-- health.go         # Backend health probes
+-- edge/
|   +-- onboarding.go     # IoT device onboarding
|   +-- acme.go           # ACME endorse-01/enroll-01 support
|   +-- dht_bootstrap.go  # DHT bootstrap for new nodes
|   +-- ipv6_alloc.go     # IPv6 address allocation from pool
+-- security/
    +-- ddos.go           # 5-layer DDoS protection
    +-- ratelimit.go      # Per-peer rate limiting
    +-- reputation.go     # Reputation-based access
```

## Gateway Capabilities

Each gateway advertises its capabilities to the network:

```go
type GatewayCapabilities struct {
    // Mode support
    Modes           GatewayMode

    // Overlay capabilities
    VTEPEnabled     bool
    EVPNEnabled     bool
    VXLANPort       uint16

    // Edge capabilities
    ACMEEnabled     bool
    DHTBootstrap    bool
    IPv6Pool        netip.Prefix

    // Transit capabilities
    BGPEnabled      bool
    IPv6Prefixes    []netip.Prefix
    IPv4Prefixes    []netip.Prefix

    // Capacity
    MaxConnections  int
    BandwidthMbps   int

    // Location
    Region          string
    ASN             uint32
}
```

## Quick Start

### Enable Gateway Mode

```yaml
# config.yaml
sdn:
  gateway:
    enabled: true
    modes:
      overlay: true
      edge: true
      transit: false  # Requires additional BGP configuration

    cluster:
      enabled: true
      quicbaas_partition: "sdn/gateway"
      heartbeat_interval: 2s

    overlay:
      vtep_ip: "10.0.0.1"
      vxlan_port: 4789

    edge:
      acme_enabled: true
      ipv6_pool: "2602:F5BB:0001::/48"
```

### Verify Gateway Status

```bash
# Check gateway status
platformctl sdn gateway status

# List active modes
platformctl sdn gateway modes

# Show cluster membership
platformctl sdn gateway cluster members

# View gateway capabilities
platformctl sdn gateway capabilities
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Detailed gateway architecture and component design |
| [Overlay Mode](overlay-mode.md) | SDN overlay mode with VTEP and EVPN |
| [Edge Mode](edge-mode.md) | Edge/P2P/IoT gateway mode |
| [Transit Mode](transit-mode.md) | BGP transit mode |
| [Load Balancer](loadbalancer.md) | VIP-based load balancing |
| [Configuration](configuration.md) | Complete configuration reference |

## Related Documentation

- [SDN Architecture](../architecture.md) - SDN subsystem overview
- [BGP Transit](../bgp/transit.md) - BGP transit mode details
- [VXLAN Overlay](../overlay/README.md) - Overlay networking
- [DHT Network Architecture](../../dht/02-network-architecture.md) - P2P network design
- [Reputation System](../../dht/09-defense-reputation.md) - Gateway promotion requirements

## References

- RFC 7348 - VXLAN: A Framework for Overlaying Virtualized Layer 2 Networks
- RFC 7432 - BGP MPLS-Based Ethernet VPN
- RFC 8555 - ACME Protocol
- RFC 6598 - IANA-Reserved IPv4 Prefix for Shared Address Space (CGNAT)

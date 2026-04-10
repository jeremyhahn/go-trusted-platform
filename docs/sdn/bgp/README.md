# BGP Service

Unified BGP service providing both EVPN control plane functionality and IP block transit capabilities for go-trusted-platform.

## Overview

The BGP service implements a pure Go BGP speaker using the GoBGP library, enabling the platform to:

- Announce platform-owned IP prefixes to upstream ISPs
- Participate in EVPN overlay networks for VM/container connectivity
- Coordinate route distribution across a three-tier speaker architecture
- Provide RPKI validation and route signing for security

## Status

| Component | Status | Description |
|-----------|--------|-------------|
| GoBGP Integration | Complete | Pure Go BGP implementation |
| Backbone Speakers | Complete | Core BGP speakers for aggregate announcements |
| Datacenter Speakers | Complete | Regional /48 prefix announcements |
| Coordinator Nodes | Complete | Route signing and coordination |
| EVPN Type-2 | Complete | MAC/IP advertisement |
| EVPN Type-3 | Complete | Inclusive multicast Ethernet tag |
| EVPN Type-5 | Complete | IP prefix advertisement |
| Transit Mode | Complete | IPv4/IPv6 prefix announcements |
| RPKI Validation | Complete | Route origin validation |
| BGP Dampening | Complete | Flap suppression (15-60 min) |

## Architecture

### Three-Tier Speaker Architecture

The BGP service uses a hierarchical speaker topology:

```
                    ┌────────────────────┐
                    │   ISP Upstream     │
                    │   (eBGP Peers)     │
                    └─────────┬──────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
    │Backbone │◄──iBGP──►│Backbone │◄──iBGP──►│Backbone │
    │Speaker 1│          │Speaker 2│          │Speaker 3│
    │(Active) │          │(Standby)│          │(Standby)│
    └────┬────┘          └────┬────┘          └────┬────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │ iBGP Mesh
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
    │  DC     │          │  DC     │          │  DC     │
    │Speaker  │          │Speaker  │          │Speaker  │
    │Region 1 │          │Region 2 │          │Region N │
    └────┬────┘          └────┬────┘          └────┬────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Coordinator      │
                    │   Nodes            │
                    │   (Route Signing)  │
                    └────────────────────┘
```

### Speaker Roles

| Role | Description | Prefix Scope |
|------|-------------|--------------|
| `backbone` | Core BGP speakers announcing aggregate prefixes to ISPs | /36 aggregate |
| `datacenter` | Regional gateways with direct eBGP to local ISPs | /48 regional |
| `coordinator` | Route coordination and cryptographic signing | N/A (control plane) |

## Dual-Mode Operation

### EVPN Mode (Overlay)

EVPN (Ethernet VPN) provides Layer 2 connectivity across Layer 3 networks using BGP as the control plane:

- **Type-2 Routes**: MAC/IP advertisement for ARP suppression
- **Type-3 Routes**: Inclusive multicast for BUM traffic handling
- **Type-5 Routes**: IP prefix routes for inter-subnet routing

### Transit Mode (Underlay)

Transit mode announces platform-owned IP blocks to the global routing table:

- **IPv6**: 2602:F5BB::/36 (backbone aggregate), regional /48 prefixes
- **IPv4**: 23.143.36.0/24 (legacy connectivity)
- **RPKI**: Route origin validation against RPKI repositories
- **Signing**: Coordinator nodes cryptographically sign route announcements

## GoBGP Integration

The service uses the [GoBGP](https://github.com/osrg/gobgp) library for pure Go BGP implementation:

```go
import (
    "github.com/osrg/gobgp/v3/pkg/server"
    "github.com/osrg/gobgp/v3/pkg/config"
)

// Create BGP server
bgpServer := server.NewBgpServer()
go bgpServer.Serve()

// Configure global settings
err := bgpServer.StartBgp(context.Background(), &config.BgpConfigSet{
    Global: config.Global{
        Config: config.GlobalConfig{
            As:       65001,
            RouterId: "23.143.36.1",
        },
    },
})
```

## Key Features

### High Availability

- Active/standby speaker failover
- iBGP full mesh between speakers
- BFD (Bidirectional Forwarding Detection) for fast failure detection
- Graceful restart support

### Security

- MD5 authentication for BGP sessions
- RPKI route origin validation
- Coordinator-signed route announcements
- TPM-backed key storage for session secrets

### Traffic Engineering

- AS-PATH prepending for traffic steering
- MED (Multi-Exit Discriminator) manipulation
- Local preference policies
- Community-based routing policies

## Documentation

- [Architecture](architecture.md) - Detailed BGP architecture and topology
- [EVPN](evpn.md) - EVPN implementation details (Type-2, Type-3, Type-5)
- [Transit](transit.md) - BGP transit mode and IP block management
- [Configuration](configuration.md) - Configuration reference

## Quick Start

### Basic BGP Speaker

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"

// Create BGP service
config := &bgp.Config{
    ASN:       65001,
    RouterID:  "23.143.36.1",
    Role:      bgp.RoleBackbone,
    ListenPort: 179,
}

speaker, err := bgp.NewSpeaker(config)
if err != nil {
    return err
}

// Start BGP speaker
ctx := context.Background()
if err := speaker.Start(ctx); err != nil {
    return err
}

// Add eBGP peer (ISP)
peer := &bgp.PeerConfig{
    Address:   "198.51.100.1",
    RemoteAS:  64500,
    Type:      bgp.PeerTypeEBGP,
    MD5Secret: "bgp_secret_key",
}

if err := speaker.AddPeer(ctx, peer); err != nil {
    return err
}

// Announce prefix
prefix := &bgp.Prefix{
    Network: "2602:F5BB::/36",
    NextHop: "2602:F5BB::1",
}

if err := speaker.Announce(ctx, prefix); err != nil {
    return err
}
```

### EVPN Configuration

```go
// Enable EVPN address family
evpnConfig := &bgp.EVPNConfig{
    RD:  "65001:100",  // Route Distinguisher
    RT:  []string{"65001:100"},  // Route Targets
    VNI: 10000,  // VXLAN Network Identifier
}

if err := speaker.EnableEVPN(ctx, evpnConfig); err != nil {
    return err
}

// Advertise MAC/IP (Type-2)
macIP := &bgp.EVPNMacIP{
    MAC:     "aa:bb:cc:dd:ee:ff",
    IP:      "192.168.100.10",
    VNI:     10000,
    NextHop: "10.0.0.1",
}

if err := speaker.AdvertiseMacIP(ctx, macIP); err != nil {
    return err
}
```

## Integration Points

### SDN Integration

The BGP service integrates with the SDN subsystem:

- EVPN routes inform OpenFlow table updates
- MAC learning triggers Type-2 advertisements
- Subnet configuration drives Type-5 routes

### DHT Integration

For distributed deployments:

- Gateway promotion triggers route announcements
- DHT publishes gateway reachability information
- Coordinator election via DHT consensus

### Policy Engine

Certificate-based policy affects routing:

- Tenant isolation via Route Targets
- VLAN-to-VNI mapping from device profiles
- ACL-driven route filtering

## References

- [RFC 4271 - BGP-4](https://datatracker.ietf.org/doc/html/rfc4271)
- [RFC 7432 - BGP MPLS-Based EVPN](https://datatracker.ietf.org/doc/html/rfc7432)
- [RFC 8365 - VXLAN-GPE EVPN](https://datatracker.ietf.org/doc/html/rfc8365)
- [RFC 6811 - RPKI Route Origin Validation](https://datatracker.ietf.org/doc/html/rfc6811)
- [GoBGP Documentation](https://github.com/osrg/gobgp)

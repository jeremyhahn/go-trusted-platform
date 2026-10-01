# BGP Architecture

## Overview

The BGP service implements a three-tier speaker architecture using the GoBGP library (pure Go) for both EVPN overlay control plane and IP transit underlay routing.

## Speaker Tiers

> **Status: DESIGN — not implemented (2026-09-07, #559).** The three-tier
> topology below (backbone, datacenter and coordinator speakers; "minimum 3
> speakers", "minimum 3 coordinators for quorum"; TPM-backed route signing)
> is a design for the planned P2P network. The code has one `SpeakerTier`
> enum (`pkg/sdn/bgp/types.go`) and one speaker; route signing is a single
> in-process Ed25519 key in `pkg/sdn/gateway/modes/transit.go` whose
> signature is discarded by `AnnouncePrefix` (see
> [transit.md](transit.md) §Route Signing by Coordinators). A two-gateway
> site runs none of this; epic #553 decides what it runs.

### Tier 1: Backbone Speakers

Backbone speakers are the primary BGP routers that peer with upstream ISPs and announce aggregate prefixes.

**Responsibilities:**
- Announce aggregate /36 prefix (2001:db8::/36) to ISPs
- Maintain eBGP sessions with transit providers
- Participate in iBGP full mesh with other backbone speakers
- Aggregate more-specific routes from datacenter speakers
- Handle ISP failover and traffic engineering

**Deployment:**
- Minimum 3 speakers for redundancy
- Geographically distributed across regions
- Direct connections to multiple ISP routers

```
┌─────────────────────────────────────────────────────────────┐
│                    BACKBONE SPEAKER                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   eBGP to    │    │   iBGP to    │    │  Route       │   │
│  │   ISP A      │    │   Other      │    │  Aggregation │   │
│  │   (AS64500)  │    │   Backbone   │    │  Engine      │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │            │
│         └───────────────────┼───────────────────┘            │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │   GoBGP Core    │                       │
│                    │   RIB Manager   │                       │
│                    └─────────────────┘                       │
│                                                              │
│  Announces: 2001:db8::/36 (aggregate)                        │
│  ASN: 65001 (platform AS)                                    │
│  Router-ID: 203.0.113.1                                      │
└─────────────────────────────────────────────────────────────┘
```

### Tier 2: Datacenter Speakers

Datacenter speakers handle regional routing and EVPN control plane for local workloads.

**Responsibilities:**
- Announce regional /48 prefixes to backbone speakers
- Maintain EVPN sessions for local VXLAN fabric
- Handle MAC/IP learning and advertisement
- Provide local breakout for regional traffic
- Participate in iBGP with backbone and other DC speakers

**Deployment:**
- One or more speakers per datacenter/region
- Connected to local leaf/spine fabric
- VXLAN VTEP functionality

```
┌─────────────────────────────────────────────────────────────┐
│                   DATACENTER SPEAKER                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   iBGP to    │    │   EVPN to    │    │  VXLAN       │   │
│  │   Backbone   │    │   Local Leaf │    │  VTEP        │   │
│  │   Speakers   │    │   Switches   │    │  Endpoint    │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │            │
│         └───────────────────┼───────────────────┘            │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │   GoBGP Core    │                       │
│                    │   + EVPN AFI    │                       │
│                    └─────────────────┘                       │
│                                                              │
│  Announces: 2001:DB8:0001::/48 (regional)                   │
│  EVPN RD: 65001:100                                          │
│  EVPN RT: 65001:100                                          │
└─────────────────────────────────────────────────────────────┘
```

### Tier 3: Coordinator Nodes

Coordinator nodes provide control plane functions without direct BGP peering to external networks.

**Responsibilities:**
- Cryptographically sign route announcements
- Validate route origin against RPKI
- Coordinate route policy across regions
- Manage route signing keys (TPM-backed)
- Audit and log route changes

**Deployment:**
- Minimum 3 coordinators for quorum
- Co-located with platform control plane
- HSM/TPM integration for key management

```
┌─────────────────────────────────────────────────────────────┐
│                    COORDINATOR NODE                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Route      │    │   RPKI       │    │   TPM Key    │   │
│  │   Signing    │    │   Validator  │    │   Manager    │   │
│  │   Engine     │    │              │    │              │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │            │
│         └───────────────────┼───────────────────┘            │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │   Coordination  │                       │
│                    │   Protocol      │                       │
│                    └─────────────────┘                       │
│                                                              │
│  Signs: Route announcements (3+ signatures required)         │
│  Validates: RPKI origin, policy compliance                   │
└─────────────────────────────────────────────────────────────┘
```

## iBGP Route Reflector Topology (MANDATORY)

**CRITICAL**: A full iBGP mesh is completely infeasible for a network with 4+ quintillion potential nodes (IPv6 /36). Route reflectors are **MANDATORY** to contain the iBGP mesh and prevent session explosion.

### Why Route Reflectors Are Required

In traditional iBGP, every speaker must peer with every other speaker, creating `n*(n-1)/2` sessions:
- 10 nodes = 45 sessions
- 100 nodes = 4,950 sessions
- 1,000 nodes = 499,500 sessions
- 1,000,000 nodes = 499,999,500,000 sessions (impossible)

Route reflectors break this O(n²) scaling by creating a hub-and-spoke topology with hierarchical clusters.

### Three-Tier Route Reflector Hierarchy

The BGP topology mirrors the three-tier speaker architecture. Only backbone speakers maintain a full mesh (3-5 nodes max). All other nodes are route reflector clients.

### Hierarchical Topology

```
                         ┌─────────────────────────────────────┐
                         │           iBGP FULL MESH            │
                         └─────────────────────────────────────┘

    ┌─────────┐         ┌─────────┐         ┌─────────┐
    │Backbone │◄───────►│Backbone │◄───────►│Backbone │
    │    1    │         │    2    │         │    3    │
    └────┬────┘         └────┬────┘         └────┬────┘
         │    ╲              │              ╱    │
         │     ╲             │             ╱     │
         │      ╲            │            ╱      │
         │       ╲           │           ╱       │
    ┌────▼────┐   ╲    ┌────▼────┐    ╱   ┌────▼────┐
    │   DC    │────╲──►│   DC    │◄──╱────│   DC    │
    │ West    │     ╲  │ Central │  ╱     │ East    │
    └─────────┘      ╲ └─────────┘ ╱      └─────────┘
                      ╲           ╱
                       ╲         ╱
                        ╲       ╱
                         ╲     ╱
                    ┌─────▼───▼─────┐
                    │  Coordinator  │
                    │    Cluster    │
                    └───────────────┘
```

### Route Reflector Session Scaling

Route reflectors provide massive reduction in BGP session counts:

| Topology | Without RR | With Hierarchical RR | Savings |
|----------|------------|---------------------|---------|
| 100 nodes | 4,950 sessions | ~200 sessions | 96% |
| 1,000 nodes | 499,500 sessions | ~2,000 sessions | 99.6% |
| 10,000 nodes | 49,995,000 sessions | ~20,000 sessions | 99.96% |
| 1M nodes | 500 billion sessions | ~2M sessions | 99.9996% |

### Hierarchical Route Reflector Design

```
┌──────────────────────────────────────────────────────────────────┐
│           THREE-TIER ROUTE REFLECTOR HIERARCHY                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  TIER 1: Backbone RRs (full mesh, 3-5 nodes only)                 │
│                                                                   │
│        ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│        │ Backbone │◄───►│ Backbone │◄───►│ Backbone │            │
│        │  RR-1    │     │  RR-2    │     │  RR-3    │            │
│        │ (C-ID:1) │     │ (C-ID:2) │     │ (C-ID:3) │            │
│        └────┬─────┘     └────┬─────┘     └────┬─────┘            │
│             │                │                │                   │
│  TIER 2: Datacenter RRs (clients of backbone)                     │
│             │                │                │                   │
│     ┌───────┴───────┐        │        ┌───────┴───────┐          │
│     │               │        │        │               │          │
│  ┌──▼──┐         ┌──▼──┐  ┌──▼──┐  ┌──▼──┐         ┌──▼──┐      │
│  │DC-1 │         │DC-2 │  │DC-3 │  │DC-4 │         │DC-5 │      │
│  │RR   │         │RR   │  │RR   │  │RR   │         │RR   │      │
│  │C:101│         │C:102│  │C:201│  │C:301│         │C:302│      │
│  └──┬──┘         └──┬──┘  └──┬──┘  └──┬──┘         └──┬──┘      │
│     │               │        │        │               │          │
│  TIER 3: Compute nodes (clients of DC, never reflectors)          │
│     │               │        │        │               │          │
│  ┌──▼──┐         ┌──▼──┐  ┌──▼──┐  ┌──▼──┐         ┌──▼──┐      │
│  │Node │         │Node │  │Node │  │Node │         │Node │      │
│  │VTEP │         │VTEP │  │VTEP │  │VTEP │         │VTEP │      │
│  │     │  ...    │     │  │     │  │     │  ...    │     │      │
│  └─────┘         └─────┘  └─────┘  └─────┘         └─────┘      │
│                                                                   │
│  Cluster-IDs:                                                     │
│    - Backbone: 1, 2, 3 (global)                                   │
│    - Datacenter: 100-999 (regional)                               │
│    - Compute: N/A (clients only)                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Route Reflection Rules

1. **Client → Non-Client**: Route is reflected (sent to non-clients)
2. **Client → Client**: Route is reflected (sent to other clients)
3. **Non-Client → Client**: Route is reflected (sent to clients)
4. **Non-Client → Non-Client**: Route is NOT reflected (standard iBGP)

This ensures routes from compute nodes reach all other compute nodes while preventing loops via CLUSTER_LIST.

## eBGP Peering to ISPs

Backbone speakers establish eBGP sessions with upstream transit providers.

### Multi-Homed ISP Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    MULTI-HOMED eBGP                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│    ┌──────────┐              ┌──────────┐                   │
│    │  ISP A   │              │  ISP B   │                   │
│    │ (AS64500)│              │ (AS64501)│                   │
│    └────┬─────┘              └────┬─────┘                   │
│         │                         │                          │
│         │ eBGP                    │ eBGP                     │
│         │ Primary                 │ Backup                   │
│         │                         │                          │
│    ┌────▼─────────────────────────▼────┐                    │
│    │         Backbone Speaker           │                    │
│    │          (AS 65001)                │                    │
│    └────────────────────────────────────┘                    │
│                                                              │
│  Announces to ISP A:                                         │
│    - 2001:db8::/36 (AS-PATH: 65001)                         │
│    - 203.0.113.0/24 (AS-PATH: 65001)                        │
│                                                              │
│  Announces to ISP B:                                         │
│    - 2001:db8::/36 (AS-PATH: 65001 65001 65001) [prepend]   │
│    - 203.0.113.0/24 (AS-PATH: 65001 65001 65001) [prepend]  │
└─────────────────────────────────────────────────────────────┘
```

### Session Parameters

| Parameter | ISP Primary | ISP Backup |
|-----------|-------------|------------|
| Session Type | eBGP | eBGP |
| Hold Timer | 90s | 90s |
| Keepalive | 30s | 30s |
| BFD | Enabled (300ms) | Enabled (300ms) |
| MD5 Auth | Required | Required |
| TTL Security | 1 hop | 1 hop |
| Graceful Restart | Enabled | Enabled |

## EVPN Address Family

EVPN uses BGP Address Family Identifier (AFI) 25 and Subsequent Address Family Identifier (SAFI) 70.

### Address Family Configuration

```
AFI 25 (L2VPN) + SAFI 70 (EVPN)

Capabilities Negotiated:
  - Route Refresh
  - Extended Next-Hop Encoding
  - Add-Path (send/receive)
  - Extended Community
  - Long-Lived Graceful Restart
```

### EVPN Route Types

| Type | Name | Purpose |
|------|------|---------|
| 2 | MAC/IP Advertisement | ARP suppression, MAC mobility |
| 3 | Inclusive Multicast | BUM traffic handling |
| 5 | IP Prefix | Inter-subnet routing |

### Route Distinguisher and Route Target

```
┌─────────────────────────────────────────────────────────────┐
│                  RD/RT ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Route Distinguisher (RD):                                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ Type 1: ASN:NN format                                   ││
│  │ Example: 65001:100                                       ││
│  │                                                          ││
│  │ 65001 = Platform ASN                                     ││
│  │ 100   = VNI / Tenant ID                                  ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  Route Target (RT):                                          │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ Import RT: Controls which routes are imported           ││
│  │ Export RT: Tags routes for export to specific VRFs      ││
│  │                                                          ││
│  │ Example:                                                 ││
│  │   VRF Tenant-A: import/export 65001:100                 ││
│  │   VRF Tenant-B: import/export 65001:200                 ││
│  │   Shared Services: import 65001:100, 65001:200          ││
│  │                    export 65001:999                      ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Route Distribution Flow

### Inbound Route Flow (Learning)

```
┌─────────────────────────────────────────────────────────────┐
│                INBOUND ROUTE FLOW                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. MAC learned on local VTEP                               │
│     └─► aa:bb:cc:dd:ee:ff on VNI 10000                      │
│                                                              │
│  2. DC Speaker creates EVPN Type-2 route                    │
│     └─► RD: 65001:10000                                     │
│     └─► RT: 65001:10000                                     │
│     └─► MAC: aa:bb:cc:dd:ee:ff                              │
│     └─► IP: 192.168.100.10 (if known)                       │
│     └─► MPLS Label: 10000 (VNI)                             │
│     └─► Next-Hop: 10.0.0.1 (VTEP IP)                        │
│                                                              │
│  3. Route advertised via iBGP to all DC speakers            │
│     └─► Full mesh or route reflector                        │
│                                                              │
│  4. Remote DC speakers import route                         │
│     └─► Match RT: 65001:10000                               │
│     └─► Install in local FIB                                │
│     └─► Program VTEP encapsulation                          │
│                                                              │
│  5. Traffic to aa:bb:cc:dd:ee:ff VXLAN-encapsulated         │
│     └─► Outer: src=local-VTEP, dst=10.0.0.1                 │
│     └─► Inner: original L2 frame                            │
└─────────────────────────────────────────────────────────────┘
```

### Outbound Route Flow (Announcing)

```
┌─────────────────────────────────────────────────────────────┐
│                OUTBOUND ROUTE FLOW                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Platform allocates IPv6 subnet                          │
│     └─► 2001:DB8:0001:0100::/64 for Region 1 Subnet 256    │
│                                                              │
│  2. DC Speaker creates transit route                        │
│     └─► Prefix: 2001:DB8:0001::/48                         │
│     └─► Next-Hop: Self                                      │
│     └─► Origin: IGP                                         │
│     └─► AS-PATH: (empty - originated here)                  │
│                                                              │
│  3. Route sent to backbone speakers via iBGP                │
│     └─► Next-Hop unchanged (iBGP)                           │
│     └─► LOCAL_PREF: 100                                     │
│                                                              │
│  4. Backbone aggregates regional routes                     │
│     └─► Aggregate: 2001:db8::/36                            │
│     └─► Suppresses more-specifics to ISPs                   │
│                                                              │
│  5. Backbone announces aggregate to ISPs via eBGP           │
│     └─► AS-PATH: 65001                                      │
│     └─► Next-Hop: Backbone router IP                        │
│                                                              │
│  6. Coordinator validates and signs announcement            │
│     └─► RPKI ROA validation                                 │
│     └─► 3+ coordinator signatures                           │
└─────────────────────────────────────────────────────────────┘
```

## GoBGP Library Integration

> **GoBGP v4.9.0 since #556 (2026-09-08).** The speaker links
> `github.com/osrg/gobgp/v4`. v4 replaced the `anypb.Any` NLRI/attribute
> encoding with typed oneofs (`api.NLRI`, `api.Attribute`), moved the
> in-process path API to `pkg/apiutil` (`AddPath`, `DeletePath`, `ListPath`
> take native paths; `WatchEvent` takes callbacks and options), renamed the
> enums (`TableType_TABLE_TYPE_GLOBAL`, `PeerState_SESSION_STATE_ESTABLISHED`,
> `PeerState_ADMIN_STATE_DOWN`), dropped the soft-reset flag from
> `UpdatePeer`, and added native single-hop BFD (`Peer.Bfd`) and a TCP-AO
> keychain store (`AddTcpAoKeychain`). All of it is confined to
> `pkg/sdn/bgp/speaker.go`: `gobgpServerWrapper` (exported as
> `NewGoBGPServerAdapter` for the integration mock peer) keeps
> `BGPServerInterface` in the wire-shaped `api.*` vocabulary and converts at
> the seam, so the speaker, its mocks and the integration harness are
> unchanged by the library's API. GO-2026-4736 (NEXT_HOP panic) is **still
> open against v4.9.0** per govulncheck; it stays allowlisted under #25.

### Server Initialization

```go
import (
    "github.com/osrg/gobgp/v4/pkg/server"
    api "github.com/osrg/gobgp/v4/api"
)

// Create and start GoBGP server
bgpServer := server.NewBgpServer()
go bgpServer.Serve()

// Configure global settings
global := &api.Global{
    Asn:        65001,
    RouterId:   "203.0.113.1",
    ListenPort: 179,
    ListenAddresses: []string{"0.0.0.0", "::"},
}

if err := bgpServer.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
    return fmt.Errorf("failed to start BGP: %w", err)
}
```

### Peer Configuration

```go
// Add eBGP peer
peer := &api.Peer{
    Conf: &api.PeerConf{
        NeighborAddress: "198.51.100.1",
        PeerAsn:         64500,
        AuthPassword:    "md5_secret",
    },
    Transport: &api.Transport{
        RemotePort: 179,
    },
    Timers: &api.Timers{
        Config: &api.TimersConfig{
            HoldTime:           90,
            KeepaliveInterval:  30,
        },
    },
    AfiSafis: []*api.AfiSafi{
        {
            Config: &api.AfiSafiConfig{
                Family: &api.Family{
                    Afi:  api.Family_AFI_IP6,
                    Safi: api.Family_SAFI_UNICAST,
                },
                Enabled: true,
            },
        },
    },
}

if err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
    return fmt.Errorf("failed to add peer: %w", err)
}
```

### EVPN Configuration

```go
// Add EVPN address family to peer
evpnAfiSafi := &api.AfiSafi{
    Config: &api.AfiSafiConfig{
        Family: &api.Family{
            Afi:  api.Family_AFI_L2VPN,
            Safi: api.Family_SAFI_EVPN,
        },
        Enabled: true,
    },
}

// Create EVPN Type-2 route
nlri, _ := ptypes.MarshalAny(&api.EVPNMacIPRoute{
    EthernetTag: 0,
    MacAddress:  "aa:bb:cc:dd:ee:ff",
    IpAddress:   "192.168.100.10",
    Labels:      []uint32{10000},  // VNI
})

attrs := []*any.Any{
    // Origin
    marshal(&api.OriginAttribute{Origin: 0}),
    // Next-Hop
    marshal(&api.NextHopAttribute{NextHop: "10.0.0.1"}),
    // Extended Community (Route Target)
    marshal(&api.ExtendedCommunitiesAttribute{
        Communities: [][]byte{
            rtCommunity(65001, 10000),
        },
    }),
}

path := &api.Path{
    Family: &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN},
    Nlri:   nlri,
    Pattrs: attrs,
}

bgpServer.AddPath(ctx, &api.AddPathRequest{
    TableType: api.TableType_GLOBAL,
    Path:      path,
})
```

## Convergence and Failover

### Failover Scenarios

> The BFD rows below are targets, not measurements: no BFD runs today
> (#559, #556). Without BFD, failure detection is the BGP hold timer.

| Scenario | Detection Time | Recovery Time |
|----------|----------------|---------------|
| Speaker failure (with BFD) | 300ms - 1s | 1-3s |
| Speaker failure (without BFD) | 90s (hold timer) | 90-180s |
| ISP link failure | 300ms (BFD) | 1-5s |
| Region isolation | 5-30s | 30-60s |

### Graceful Restart

```go
// Enable graceful restart
grConfig := &api.GracefulRestartConfig{
    Enabled:     true,
    RestartTime: 120,  // seconds
    LongLivedEnabled: true,
    StaleRoutesTime:  300,  // seconds
}
```

## Monitoring and Observability

### Metrics

| Metric | Description |
|--------|-------------|
| `bgp_peer_state` | Peer session state (Established, Active, etc.) |
| `bgp_routes_received` | Routes received per peer/AFI/SAFI |
| `bgp_routes_advertised` | Routes advertised per peer/AFI/SAFI |
| `bgp_updates_received` | BGP UPDATE messages received |
| `bgp_updates_sent` | BGP UPDATE messages sent |
| `bgp_route_flaps` | Route flap events detected |

### Logging

```go
// Structured logging for BGP events
logger.Info("BGP peer state change",
    slog.String("peer", "198.51.100.1"),
    slog.String("old_state", "Active"),
    slog.String("new_state", "Established"),
    slog.Uint64("asn", 64500),
)

logger.Info("Route announced",
    slog.String("prefix", "2001:db8::/36"),
    slog.String("next_hop", "203.0.113.1"),
    slog.String("peer", "198.51.100.1"),
)
```

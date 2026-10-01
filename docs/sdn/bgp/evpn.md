# EVPN Implementation

## Overview

EVPN (Ethernet VPN) provides a BGP-based control plane for Layer 2 and Layer 3 VPN services. The go-trusted-platform BGP service implements EVPN to enable seamless VM and container connectivity across distributed datacenters.

## EVPN Fundamentals

### Address Family

EVPN uses BGP with:
- **AFI 25** (L2VPN)
- **SAFI 70** (EVPN)

### Route Types Implemented

| Type | Name | RFC Section | Status |
|------|------|-------------|--------|
| 1 | Ethernet Auto-Discovery | RFC 7432 Sec 7.1 | Not Implemented |
| 2 | MAC/IP Advertisement | RFC 7432 Sec 7.2 | Implemented |
| 3 | Inclusive Multicast Ethernet Tag | RFC 7432 Sec 7.3 | Implemented |
| 4 | Ethernet Segment | RFC 7432 Sec 7.4 | Not Implemented |
| 5 | IP Prefix | RFC 9136 | Implemented |

## Type-2: MAC/IP Advertisement

Type-2 routes advertise MAC addresses (and optionally IP addresses) learned on local VTEPs to remote VTEPs for ARP suppression and MAC forwarding.

### Route Format

```
+---------------------------------------+
|  Route Distinguisher (8 bytes)        |
+---------------------------------------+
|  Ethernet Tag ID (4 bytes)            |
+---------------------------------------+
|  MAC Address Length (1 byte)          |
+---------------------------------------+
|  MAC Address (6 bytes)                |
+---------------------------------------+
|  IP Address Length (1 byte)           |
+---------------------------------------+
|  IP Address (0, 4, or 16 bytes)       |
+---------------------------------------+
|  MPLS Label (3 bytes) - VNI           |
+---------------------------------------+
```

### ARP Suppression

Type-2 routes enable ARP suppression, reducing broadcast traffic in VXLAN overlays:

```
┌─────────────────────────────────────────────────────────────┐
│                   ARP SUPPRESSION FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Without EVPN (Traditional VXLAN):                          │
│  ┌─────┐     ARP Request      ┌─────┐                       │
│  │ VM1 │ ──────────────────►  │VTEP1│                       │
│  └─────┘                      └──┬──┘                       │
│                                  │  Flood to all VTEPs       │
│                 ┌────────────────┼────────────────┐          │
│                 ▼                ▼                ▼          │
│            ┌─────┐          ┌─────┐          ┌─────┐        │
│            │VTEP2│          │VTEP3│          │VTEP4│        │
│            └─────┘          └─────┘          └─────┘        │
│                                                              │
│  With EVPN (Type-2):                                        │
│  ┌─────┐     ARP Request      ┌─────┐                       │
│  │ VM1 │ ──────────────────►  │VTEP1│                       │
│  └─────┘                      └──┬──┘                       │
│                                  │  Lookup EVPN cache        │
│                                  │  (MAC -> VTEP mapping)    │
│                                  ▼                           │
│                             ┌─────────┐                      │
│                             │ Direct  │                      │
│                             │ ARP     │                      │
│                             │ Reply   │                      │
│                             └─────────┘                      │
│                                                              │
│  Benefit: No flooding, O(1) lookup                          │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```go
// Type-2 MAC/IP route structure
type EVPNType2Route struct {
    RD           RouteDistinguisher
    EthernetTag  uint32
    MACLength    uint8
    MAC          net.HardwareAddr
    IPLength     uint8
    IP           net.IP  // Optional: IPv4 or IPv6
    MPLSLabel    uint32  // VNI
}

// Create Type-2 route for MAC/IP binding
func (s *Speaker) AdvertiseMacIP(ctx context.Context, mac net.HardwareAddr, ip net.IP, vni uint32) error {
    rd := s.buildRD(vni)
    rt := s.buildRT(vni)

    nlri := &api.EVPNMacIPRoute{
        Rd: &api.RouteDistinguisher{
            Type: api.RouteDistinguisher_TYPE_2OCTET_AS,
            Admin: uint32(s.config.ASN),
            Assigned: vni,
        },
        EthernetTag: 0,
        MacAddress:  mac.String(),
        IpAddress:   ip.String(),
        Labels:      []uint32{vni},
    }

    path := &api.Path{
        Family: &api.Family{
            Afi:  api.Family_AFI_L2VPN,
            Safi: api.Family_SAFI_EVPN,
        },
        Nlri: marshal(nlri),
        Pattrs: []*any.Any{
            marshal(&api.OriginAttribute{Origin: 0}),  // IGP
            marshal(&api.NextHopAttribute{NextHop: s.vtepIP.String()}),
            marshal(&api.ExtendedCommunitiesAttribute{
                Communities: [][]byte{rt.Bytes()},
            }),
        },
    }

    _, err := s.server.AddPath(ctx, &api.AddPathRequest{
        TableType: api.TableType_GLOBAL,
        Path:      path,
    })
    return err
}
```

### MAC Learning Integration

```go
// MAC learning callback from SDN layer
func (s *Speaker) OnMACLearned(event *MACLearnEvent) {
    // Skip if MAC already advertised
    if s.macCache.Has(event.MAC, event.VNI) {
        return
    }

    // Advertise via EVPN Type-2
    if err := s.AdvertiseMacIP(context.Background(),
        event.MAC,
        event.IP,  // May be nil if IP not yet learned
        event.VNI,
    ); err != nil {
        s.logger.Error("Failed to advertise MAC",
            slog.String("mac", event.MAC.String()),
            slog.Any("error", err),
        )
        return
    }

    s.macCache.Add(event.MAC, event.VNI)
}
```

## Type-3: Inclusive Multicast Ethernet Tag

Type-3 routes establish multicast trees for BUM (Broadcast, Unknown unicast, Multicast) traffic handling.

### Route Format

```
+---------------------------------------+
|  Route Distinguisher (8 bytes)        |
+---------------------------------------+
|  Ethernet Tag ID (4 bytes)            |
+---------------------------------------+
|  IP Address Length (1 byte)           |
+---------------------------------------+
|  Originating Router IP (4/16 bytes)   |
+---------------------------------------+
```

### BUM Traffic Handling

Type-3 routes enable efficient BUM traffic replication:

```
┌─────────────────────────────────────────────────────────────┐
│                   BUM TRAFFIC FLOW                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. VTEP1 originates Type-3 route:                          │
│     RD: 65001:10000                                         │
│     Ethernet Tag: 0                                         │
│     Originator: 10.0.0.1 (VTEP1)                           │
│                                                              │
│  2. All VTEPs in VNI 10000 receive Type-3                   │
│     ┌─────────────────────────────────────────────────┐     │
│     │ VTEP1: 10.0.0.1 (self)                         │     │
│     │ VTEP2: 10.0.0.2 (from BGP)                     │     │
│     │ VTEP3: 10.0.0.3 (from BGP)                     │     │
│     └─────────────────────────────────────────────────┘     │
│                                                              │
│  3. When BUM traffic arrives at VTEP1:                      │
│     Source: VM-A (on VTEP1)                                 │
│     Dest: ff:ff:ff:ff:ff:ff (broadcast)                     │
│                                                              │
│  4. VTEP1 replicates to all peers in multicast tree:        │
│     ┌─────┐                                                 │
│     │VTEP1│──────►  VTEP2 (10.0.0.2)                       │
│     │     │──────►  VTEP3 (10.0.0.3)                       │
│     └─────┘                                                 │
│                                                              │
│  Replication Mode: Ingress Replication (head-end)           │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```go
// Type-3 Inclusive Multicast route
type EVPNType3Route struct {
    RD              RouteDistinguisher
    EthernetTag     uint32
    IPLength        uint8
    OriginatorIP    net.IP
}

// Advertise Type-3 for BUM traffic tree
func (s *Speaker) AdvertiseInclusiveMulticast(ctx context.Context, vni uint32) error {
    rd := s.buildRD(vni)
    rt := s.buildRT(vni)

    nlri := &api.EVPNInclusiveMulticastRoute{
        Rd: &api.RouteDistinguisher{
            Type:     api.RouteDistinguisher_TYPE_2OCTET_AS,
            Admin:    uint32(s.config.ASN),
            Assigned: vni,
        },
        EthernetTag: 0,
        IpAddress:   s.vtepIP.String(),
    }

    path := &api.Path{
        Family: &api.Family{
            Afi:  api.Family_AFI_L2VPN,
            Safi: api.Family_SAFI_EVPN,
        },
        Nlri: marshal(nlri),
        Pattrs: []*any.Any{
            marshal(&api.OriginAttribute{Origin: 0}),
            marshal(&api.NextHopAttribute{NextHop: s.vtepIP.String()}),
            marshal(&api.ExtendedCommunitiesAttribute{
                Communities: [][]byte{rt.Bytes()},
            }),
            marshal(&api.PmsiTunnelAttribute{
                Type:  api.PmsiTunnelType_INGRESS_REPLICATION,
                Label: vni,
                Id:    s.vtepIP,
            }),
        },
    }

    _, err := s.server.AddPath(ctx, &api.AddPathRequest{
        TableType: api.TableType_GLOBAL,
        Path:      path,
    })
    return err
}
```

### VNI Registration

```go
// Register VNI and advertise Type-3
func (s *Speaker) RegisterVNI(ctx context.Context, vni uint32, subnets []net.IPNet) error {
    // 1. Advertise Type-3 for BUM traffic
    if err := s.AdvertiseInclusiveMulticast(ctx, vni); err != nil {
        return fmt.Errorf("failed to advertise Type-3: %w", err)
    }

    // 2. Advertise Type-5 for each subnet
    for _, subnet := range subnets {
        if err := s.AdvertiseIPPrefix(ctx, subnet, vni); err != nil {
            return fmt.Errorf("failed to advertise Type-5: %w", err)
        }
    }

    s.vniRegistry.Add(vni, subnets)
    return nil
}
```

## Type-5: IP Prefix Advertisement

Type-5 routes advertise IP prefixes for inter-subnet routing, enabling routing between VNIs.

### Route Format

```
+---------------------------------------+
|  Route Distinguisher (8 bytes)        |
+---------------------------------------+
|  Ethernet Segment Identifier (10 b)   |
+---------------------------------------+
|  Ethernet Tag ID (4 bytes)            |
+---------------------------------------+
|  IP Prefix Length (1 byte)            |
+---------------------------------------+
|  IP Prefix (4 or 16 bytes)            |
+---------------------------------------+
|  GW IP Address (4 or 16 bytes)        |
+---------------------------------------+
|  MPLS Label (3 bytes) - L3 VNI        |
+---------------------------------------+
```

### Inter-Subnet Routing

Type-5 routes enable routing between different VNIs/subnets:

```
┌─────────────────────────────────────────────────────────────┐
│                INTER-SUBNET ROUTING                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Tenant-A VRF:                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ VNI 10001: 192.168.1.0/24 (Web Tier)               │    │
│  │ VNI 10002: 192.168.2.0/24 (App Tier)               │    │
│  │ VNI 10003: 192.168.3.0/24 (DB Tier)                │    │
│  │ L3 VNI: 10000 (symmetric IRB)                       │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Type-5 Routes Advertised:                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Prefix: 192.168.1.0/24                              │    │
│  │ RD: 65001:10000                                     │    │
│  │ RT: 65001:10000 (Tenant-A VRF)                      │    │
│  │ Label: 10000 (L3 VNI)                               │    │
│  │ Gateway: Router MAC (for VXLAN routing)             │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Traffic Flow (Web -> DB):                                  │
│  1. VM in Web (192.168.1.10) sends to DB (192.168.3.20)    │
│  2. Local VTEP does L3 lookup in Tenant-A VRF              │
│  3. Matches Type-5 route for 192.168.3.0/24                │
│  4. Encapsulates with L3 VNI (10000) and router MAC        │
│  5. Remote VTEP decaps, routes to destination VNI          │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

```go
// Type-5 IP Prefix route
type EVPNType5Route struct {
    RD            RouteDistinguisher
    ESI           [10]byte  // Ethernet Segment ID (usually zero)
    EthernetTag   uint32
    IPPrefixLen   uint8
    IPPrefix      net.IPNet
    GatewayIP     net.IP
    MPLSLabel     uint32  // L3 VNI
}

// Advertise IP prefix (Type-5)
func (s *Speaker) AdvertiseIPPrefix(ctx context.Context, prefix net.IPNet, l3vni uint32) error {
    rd := s.buildRD(l3vni)
    rt := s.buildRT(l3vni)

    prefixLen, _ := prefix.Mask.Size()

    nlri := &api.EVPNIPPrefixRoute{
        Rd: &api.RouteDistinguisher{
            Type:     api.RouteDistinguisher_TYPE_2OCTET_AS,
            Admin:    uint32(s.config.ASN),
            Assigned: l3vni,
        },
        EthernetTag:  0,
        IpPrefixLen:  uint32(prefixLen),
        IpPrefix:     prefix.IP.String(),
        GwAddress:    s.routerIP.String(),
        Label:        l3vni,
    }

    path := &api.Path{
        Family: &api.Family{
            Afi:  api.Family_AFI_L2VPN,
            Safi: api.Family_SAFI_EVPN,
        },
        Nlri: marshal(nlri),
        Pattrs: []*any.Any{
            marshal(&api.OriginAttribute{Origin: 0}),
            marshal(&api.NextHopAttribute{NextHop: s.vtepIP.String()}),
            marshal(&api.ExtendedCommunitiesAttribute{
                Communities: [][]byte{
                    rt.Bytes(),
                    s.routerMACExtCommunity(),  // Router MAC for routing
                },
            }),
        },
    }

    _, err := s.server.AddPath(ctx, &api.AddPathRequest{
        TableType: api.TableType_GLOBAL,
        Path:      path,
    })
    return err
}
```

## Route Distinguisher and Route Targets

### Route Distinguisher (RD)

RD makes routes unique within the BGP table, even if the same prefix exists in multiple VRFs.

```go
// RD Types
const (
    RDType0 = 0  // 2-byte ASN : 4-byte assigned
    RDType1 = 1  // 4-byte IPv4 : 2-byte assigned
    RDType2 = 2  // 4-byte ASN : 2-byte assigned
)

// Build RD from ASN and VNI
func (s *Speaker) buildRD(vni uint32) *api.RouteDistinguisher {
    return &api.RouteDistinguisher{
        Type:     api.RouteDistinguisher_TYPE_2OCTET_AS,
        Admin:    uint32(s.config.ASN),  // 65001
        Assigned: vni,                    // 10000
    }
    // Result: 65001:10000
}
```

### Route Targets (RT)

RT controls route import/export between VRFs.

```go
// Route Target Extended Community
type RouteTarget struct {
    Type     uint8   // 0x00 (2-byte AS) or 0x02 (4-byte AS)
    Subtype  uint8   // 0x02 (route target)
    ASN      uint16  // or uint32 for 4-byte AS
    Assigned uint32  // or uint16 for 4-byte AS
}

// Build RT from ASN and VNI
func (s *Speaker) buildRT(vni uint32) RouteTarget {
    return RouteTarget{
        Type:     0x00,
        Subtype:  0x02,
        ASN:      uint16(s.config.ASN),
        Assigned: vni,
    }
    // Result: target:65001:10000
}

// RT Import/Export Configuration
type VRFConfig struct {
    Name       string
    RD         RouteDistinguisher
    ImportRT   []RouteTarget
    ExportRT   []RouteTarget
}

// Example: Tenant-A VRF
tenantAVRF := &VRFConfig{
    Name: "Tenant-A",
    RD:   RD{ASN: 65001, Assigned: 10000},
    ImportRT: []RouteTarget{
        {ASN: 65001, Assigned: 10000},  // Import own routes
        {ASN: 65001, Assigned: 99999},  // Import shared services
    },
    ExportRT: []RouteTarget{
        {ASN: 65001, Assigned: 10000},  // Export to own VRF
    },
}
```

### Session policy: route-target allowlists

What an l2vpn-evpn peer may send and be sent is decided per neighbor by route
target, under `policy` (see [configuration.md](configuration.md)):

```yaml
peers:
  - address: 10.4.0.1
    families: [evpn]
    max-evpn-prefixes: 100000
    policy:
      import-route-targets: ["65000:10100"]   # admit a route carrying one of these
      export-route-targets: ["65000:10100"]   # announce a route carrying one of these
```

Both directions default to reject (RFC 8212). A route is admitted when it
carries **at least one** listed route target; an empty list admits nothing, so an
EVPN neighbor without route targets exchanges no EVPN routes. The filter is a
statement in the speaker's global import or export policy, matched on the
neighbor, the l2vpn-evpn family and an extended-community set; GoBGP ignores
per-neighbor policy on anything but a route-server client, which is why the
policy is global (#717). Unicast prefix allowlists never match an EVPN route,
and the route-target statement never admits a unicast one.

`max-evpn-prefixes` is the session's EVPN route limit, separate from the
unicast `max-prefixes`; size it to VTEPs x MACs. The default is 100000.

### Multi-Tenancy with RT

```
┌─────────────────────────────────────────────────────────────┐
│                  MULTI-TENANCY WITH RT                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Tenant-A VRF                    Tenant-B VRF               │
│  ┌──────────────────┐            ┌──────────────────┐       │
│  │ RD: 65001:100    │            │ RD: 65001:200    │       │
│  │ Import: 65001:100│            │ Import: 65001:200│       │
│  │ Export: 65001:100│            │ Export: 65001:200│       │
│  │                  │            │                  │       │
│  │ 192.168.1.0/24   │            │ 192.168.1.0/24   │       │
│  │ (Tenant-A net)   │            │ (Tenant-B net)   │       │
│  └──────────────────┘            └──────────────────┘       │
│           │                               │                  │
│           │ RT: 65001:100                 │ RT: 65001:200   │
│           │                               │                  │
│           ▼                               ▼                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  BGP RIB                            │    │
│  │                                                     │    │
│  │  192.168.1.0/24 RD:65001:100 RT:65001:100 (A)      │    │
│  │  192.168.1.0/24 RD:65001:200 RT:65001:200 (B)      │    │
│  │                                                     │    │
│  │  Same prefix, different RDs -> unique in BGP       │    │
│  │  Different RTs -> isolated VRFs                    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Shared Services VRF                                        │
│  ┌──────────────────┐                                       │
│  │ RD: 65001:999    │                                       │
│  │ Import: 65001:100│  <- Can reach Tenant-A                │
│  │ Import: 65001:200│  <- Can reach Tenant-B                │
│  │ Export: 65001:999│  -> Advertise to all tenants          │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

## MAC Mobility Handling

EVPN supports seamless VM migration with MAC mobility extended community.

### MAC Move Detection

```go
// MAC Mobility Extended Community
type MACMobility struct {
    Flags    uint8   // Bit 0: Sticky (static MAC)
    Reserved uint8
    SeqNum   uint32  // Sequence number (increments on move)
}

// Handle MAC move event
func (s *Speaker) OnMACMove(event *MACMoveEvent) error {
    // Increment sequence number
    seqNum := s.macSeqNum.Inc(event.MAC)

    // Re-advertise with higher sequence number
    nlri := &api.EVPNMacIPRoute{
        Rd:          s.buildRD(event.VNI),
        EthernetTag: 0,
        MacAddress:  event.MAC.String(),
        IpAddress:   event.IP.String(),
        Labels:      []uint32{event.VNI},
    }

    // Add MAC Mobility extended community
    macMobility := &MACMobility{
        Flags:  0,       // Not sticky
        SeqNum: seqNum,  // Higher seq wins
    }

    path := &api.Path{
        Family: evpnFamily,
        Nlri:   marshal(nlri),
        Pattrs: []*any.Any{
            marshal(&api.OriginAttribute{Origin: 0}),
            marshal(&api.NextHopAttribute{NextHop: s.vtepIP.String()}),
            marshal(&api.ExtendedCommunitiesAttribute{
                Communities: [][]byte{
                    s.buildRT(event.VNI).Bytes(),
                    macMobility.Bytes(),
                },
            }),
        },
    }

    _, err := s.server.AddPath(ctx, &api.AddPathRequest{
        TableType: api.TableType_GLOBAL,
        Path:      path,
    })

    s.logger.Info("MAC mobility advertised",
        slog.String("mac", event.MAC.String()),
        slog.Uint64("seq", uint64(seqNum)),
        slog.String("old_vtep", event.OldVTEP.String()),
        slog.String("new_vtep", s.vtepIP.String()),
    )

    return err
}
```

### MAC Move Sequence Resolution

```
┌─────────────────────────────────────────────────────────────┐
│                  MAC MOBILITY RESOLUTION                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Initial State:                                             │
│  MAC aa:bb:cc:dd:ee:ff on VTEP1, Seq=0                      │
│                                                              │
│  VM Migrates to VTEP2:                                      │
│  1. VTEP2 learns MAC locally                                │
│  2. VTEP2 advertises Type-2 with Seq=1                      │
│  3. All VTEPs receive update                                │
│  4. Higher Seq (1 > 0) wins                                 │
│  5. FIB updated: MAC -> VTEP2                               │
│                                                              │
│  Race Condition (simultaneous move):                        │
│  - Both VTEPs advertise with Seq=1                          │
│  - Tie-breaker: Highest VTEP IP wins                        │
│  - Ensures deterministic convergence                        │
│                                                              │
│  Sticky MAC (prevent mobility):                             │
│  - Flags bit 0 = 1                                          │
│  - Used for static MAC entries                              │
│  - Ignores sequence number from other VTEPs                 │
└─────────────────────────────────────────────────────────────┘
```

## Integration with SDN Layer

### OpenFlow Table Updates

EVPN route updates trigger OpenFlow table programming:

```go
// EVPN route callback
func (s *Speaker) onEVPNRouteReceived(route *EVPNRoute) {
    switch route.Type {
    case EVPNRouteType2:
        // MAC/IP learned from remote VTEP
        s.sdnController.AddRemoteMAC(
            route.MAC,
            route.IP,
            route.VNI,
            route.NextHop,  // Remote VTEP IP
        )

    case EVPNRouteType3:
        // Add VTEP to multicast tree
        s.sdnController.AddMulticastPeer(
            route.VNI,
            route.OriginatorIP,
        )

    case EVPNRouteType5:
        // Add remote subnet route
        s.sdnController.AddRemoteSubnet(
            route.Prefix,
            route.L3VNI,
            route.NextHop,
            route.GatewayMAC,
        )
    }
}
```

### VXLAN Encapsulation

```go
// OpenFlow rules for VXLAN encapsulation
func (c *SDNController) AddRemoteMAC(mac net.HardwareAddr, ip net.IP, vni uint32, vtep net.IP) error {
    // Table 0: L2 forwarding
    flow := &openflow.FlowMod{
        TableID:  0,
        Priority: 100,
        Match: openflow.Match{
            EthDst:  mac,
            Metadata: vni,  // VNI in metadata
        },
        Actions: []openflow.Action{
            // Set VXLAN tunnel destination
            openflow.SetTunnelDst(vtep),
            openflow.SetTunnelID(vni),
            // Output to VXLAN tunnel port
            openflow.Output(c.vxlanPort),
        },
    }

    return c.ofClient.AddFlow(ctx, flow)
}
```

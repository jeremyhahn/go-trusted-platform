# SDN Overlay Mode

## Overview

Overlay mode enables gateway nodes to act as VXLAN Tunnel Endpoints (VTEPs) for east-west traffic across the distributed network. Gateways in overlay mode encapsulate and decapsulate VXLAN frames, participate in EVPN route exchange, suppress broadcast traffic, and provide distributed anycast gateway services.

## Key Components

| Component | Description |
|-----------|-------------|
| **VTEP** | VXLAN Tunnel Endpoint for encap/decap |
| **EVPN Integration** | BGP EVPN for MAC/IP advertisement |
| **ARP Suppression** | Reduce broadcast with proxy ARP |
| **Distributed Anycast Gateway** | Shared gateway IP across VTEPs |
| **OpenFlow Pipeline** | Flow tables for packet processing |

## VTEP Architecture

### VTEP Responsibilities

```
+------------------------------------------------------------------+
|                         VTEP Functions                            |
+------------------------------------------------------------------+
|                                                                   |
|  Encapsulation (TX Path)                                          |
|  +--------------------------------------------------------------+ |
|  | 1. Receive L2 frame from OVS bridge                          | |
|  | 2. Lookup destination MAC in local table                      | |
|  |    - If local: Forward to local port                          | |
|  |    - If remote: Encapsulate in VXLAN                          | |
|  | 3. Add VXLAN header with VNI (VNI = 1000000 + VLAN)          | |
|  | 4. Add UDP header (dest port 4789)                            | |
|  | 5. Add IP header (src=local VTEP, dst=remote VTEP)            | |
|  | 6. Send on underlay network                                   | |
|  +--------------------------------------------------------------+ |
|                                                                   |
|  Decapsulation (RX Path)                                          |
|  +--------------------------------------------------------------+ |
|  | 1. Receive VXLAN packet on UDP 4789                           | |
|  | 2. Validate VNI membership                                    | |
|  | 3. Strip outer IP/UDP/VXLAN headers                           | |
|  | 4. Learn source MAC (remote MAC -> source VTEP IP)            | |
|  | 5. Forward inner frame to local OVS bridge                    | |
|  +--------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### VTEP Configuration

```go
// VTEP represents a VXLAN Tunnel Endpoint
type VTEP struct {
    // Local endpoint
    LocalIP     netip.Addr    // Underlay IP for tunnel source
    ListenPort  uint16        // UDP port (default 4789)

    // Remote endpoints (discovered via QuicBaaS)
    RemoteVTEPs map[netip.Addr]*RemoteVTEP

    // VNI membership
    ActiveVNIs  map[uint32]*VNIState

    // MAC table
    MACTable    *MACTable

    // Statistics
    Stats       VTEPStats
}

type RemoteVTEP struct {
    IP          netip.Addr
    SharedVNIs  []uint32      // VNIs shared with this VTEP
    LastSeen    time.Time
    Status      VTEPStatus
}

type VNIState struct {
    VNI         uint32
    VLAN        uint16
    TenantID    string
    LocalMACs   map[string]netip.Addr  // MAC -> local port IP
    RemoteMACs  map[string]netip.Addr  // MAC -> remote VTEP IP
    ARPCache    map[netip.Addr]string  // IP -> MAC
}
```

## EVPN Integration

### EVPN Route Types

The overlay gateway supports EVPN Type-2 (MAC/IP) and Type-3 (Inclusive Multicast) routes for efficient overlay networking.

| Type | Name | Purpose |
|------|------|---------|
| Type-2 | MAC/IP Advertisement | MAC address and optional IP binding |
| Type-3 | Inclusive Multicast Ethernet Tag | BUM traffic handling |

### Type-2: MAC/IP Routes

```go
// EVPNType2Route advertises MAC/IP bindings
type EVPNType2Route struct {
    RouteDistinguisher RD         // VNI-based RD
    EthernetSegmentID  ESI        // Multi-homing identifier
    EthernetTag        uint32     // VLAN tag
    MACAddress         net.HardwareAddr
    IPAddress          netip.Addr // Optional IP binding
    MPLS               uint32     // VNI as MPLS label
}

// AdvertiseMAC announces a local MAC address
func (v *VTEP) AdvertiseMAC(vni uint32, mac net.HardwareAddr, ip netip.Addr) error {
    route := &EVPNType2Route{
        RouteDistinguisher: v.makeRD(vni),
        EthernetTag:        vni,
        MACAddress:         mac,
        IPAddress:          ip,
        MPLS:               vni,
    }

    // Announce via BGP EVPN
    if err := v.bgpSpeaker.AnnounceEVPN(route); err != nil {
        return fmt.Errorf("announce MAC: %w", err)
    }

    // Store locally
    state := v.ActiveVNIs[vni]
    state.LocalMACs[mac.String()] = v.LocalIP

    return nil
}

// HandleType2Route processes received MAC/IP advertisement
func (v *VTEP) HandleType2Route(route *EVPNType2Route, nextHop netip.Addr) {
    vni := route.EthernetTag
    state, ok := v.ActiveVNIs[vni]
    if !ok {
        return // VNI not active locally
    }

    // Learn remote MAC
    mac := route.MACAddress.String()
    state.RemoteMACs[mac] = nextHop

    // Update ARP cache if IP present
    if route.IPAddress.IsValid() {
        state.ARPCache[route.IPAddress] = mac
    }

    // Install OpenFlow rule for this MAC
    v.installRemoteMACFlow(vni, route.MACAddress, nextHop)
}
```

### Type-3: Ingress Replication

Type-3 routes establish the ingress replication list for BUM (Broadcast, Unknown unicast, Multicast) traffic:

```go
// EVPNType3Route for BUM traffic handling
type EVPNType3Route struct {
    RouteDistinguisher RD
    EthernetTag        uint32
    IP                 netip.Addr   // VTEP IP for replication
    PMSITunnelType     uint8        // 6 = ingress replication
}

// AnnounceType3 advertises this VTEP for BUM replication
func (v *VTEP) AnnounceType3(vni uint32) error {
    route := &EVPNType3Route{
        RouteDistinguisher: v.makeRD(vni),
        EthernetTag:        vni,
        IP:                 v.LocalIP,
        PMSITunnelType:     6, // Ingress replication
    }

    return v.bgpSpeaker.AnnounceEVPN(route)
}

// GetReplicationList returns VTEPs for BUM replication
func (v *VTEP) GetReplicationList(vni uint32) []netip.Addr {
    var vteps []netip.Addr

    for ip, remote := range v.RemoteVTEPs {
        for _, sharedVNI := range remote.SharedVNIs {
            if sharedVNI == vni {
                vteps = append(vteps, ip)
                break
            }
        }
    }

    return vteps
}

// HandleBUM processes broadcast/unknown/multicast traffic
func (v *VTEP) HandleBUM(vni uint32, frame []byte) {
    vteps := v.GetReplicationList(vni)

    // Replicate to all remote VTEPs
    for _, vtepIP := range vteps {
        v.sendVXLAN(vtepIP, vni, frame)
    }
}
```

## ARP Suppression

ARP suppression reduces broadcast traffic by answering ARP requests locally when the IP-MAC binding is known.

### ARP Suppression Flow

```
+------------------------------------------------------------------+
|                     ARP Suppression Flow                          |
+------------------------------------------------------------------+
|                                                                   |
|  1. ARP Request Received                                          |
|     +----------------------------------------------------------+ |
|     | Guest VM sends ARP: "Who has 10.0.0.50?"                 | |
|     +----------------------------------------------------------+ |
|                              |                                    |
|                              v                                    |
|  2. Check Local ARP Cache                                         |
|     +----------------------------------------------------------+ |
|     | Lookup 10.0.0.50 in VNI ARP cache                        | |
|     |                                                          | |
|     | if found:                                                | |
|     |   Generate proxy ARP reply with cached MAC               | |
|     |   Send reply to requesting VM                            | |
|     |   -> Broadcast suppressed!                               | |
|     |                                                          | |
|     | if not found:                                            | |
|     |   Forward ARP to ingress replication list                | |
|     |   Cache response when received                           | |
|     +----------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Implementation

```go
// ARPSuppressor handles proxy ARP for known bindings
type ARPSuppressor struct {
    vtep      *VTEP
    enabled   bool
    cacheHits uint64
    cacheMiss uint64
}

// HandleARP processes incoming ARP packets
func (a *ARPSuppressor) HandleARP(vni uint32, arpPacket []byte) ([]byte, bool) {
    arp, err := parseARP(arpPacket)
    if err != nil || arp.Operation != ARPRequest {
        return nil, false
    }

    state := a.vtep.ActiveVNIs[vni]
    if state == nil {
        return nil, false
    }

    // Lookup target IP in cache
    targetIP := arp.TargetIP
    targetMAC, found := state.ARPCache[targetIP]

    if !found {
        atomic.AddUint64(&a.cacheMiss, 1)
        return nil, false // Forward to replication list
    }

    atomic.AddUint64(&a.cacheHits, 1)

    // Generate proxy ARP reply
    reply := &ARPPacket{
        Operation:  ARPReply,
        SenderMAC:  parseMAC(targetMAC),
        SenderIP:   targetIP,
        TargetMAC:  arp.SenderMAC,
        TargetIP:   arp.SenderIP,
    }

    return reply.Encode(), true
}
```

## Distributed Anycast Gateway

The distributed anycast gateway allows the same gateway IP to be used across all VTEPs, enabling seamless L3 routing regardless of which VTEP a VM is attached to.

### Anycast Gateway Design

```
                   Anycast Gateway IP: 10.0.0.1
                           MAC: 00:00:5e:00:01:01

    +----------+         +----------+         +----------+
    |  VTEP A  |         |  VTEP B  |         |  VTEP C  |
    |          |         |          |         |          |
    | 10.0.0.1 |         | 10.0.0.1 |         | 10.0.0.1 |
    | (anycast)|         | (anycast)|         | (anycast)|
    +----+-----+         +----+-----+         +----+-----+
         |                    |                    |
    +----v----+          +----v----+          +----v----+
    |   VM1   |          |   VM2   |          |   VM3   |
    | 10.0.0.2|          | 10.0.0.3|          | 10.0.0.4|
    +---------+          +---------+          +---------+

    All VMs use 10.0.0.1 as default gateway
    Each VTEP responds locally - no hairpin traffic
```

### Implementation

```go
// AnycastGateway configures distributed gateway
type AnycastGateway struct {
    // Shared gateway identity
    GatewayIP   netip.Addr        // Same on all VTEPs
    GatewayMAC  net.HardwareAddr  // Same on all VTEPs (00:00:5e:00:01:XX)

    // VNI mappings
    VNIToSubnet map[uint32]netip.Prefix

    // Routing
    routes      []Route
}

// ConfigureAnycastGateway sets up distributed gateway
func (v *VTEP) ConfigureAnycastGateway(vni uint32, subnet netip.Prefix, gatewayIP netip.Addr) error {
    // Standard anycast gateway MAC (VRRP-style)
    gatewayMAC := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, byte(vni % 256)}

    v.anycastGateway.GatewayIP = gatewayIP
    v.anycastGateway.GatewayMAC = gatewayMAC
    v.anycastGateway.VNIToSubnet[vni] = subnet

    // Install OpenFlow rules to respond to gateway MAC/IP
    return v.installAnycastGatewayFlows(vni, gatewayIP, gatewayMAC)
}

// HandleRouting processes packets destined to gateway
func (v *VTEP) HandleRouting(vni uint32, packet []byte) error {
    ip := parseIPv4(packet)

    // Is destination local to this VNI?
    subnet := v.anycastGateway.VNIToSubnet[vni]
    if subnet.Contains(ip.DstIP) {
        // Lookup destination MAC
        dstMAC, found := v.ActiveVNIs[vni].ARPCache[ip.DstIP]
        if !found {
            // Generate ARP request
            return v.sendARPRequest(vni, ip.DstIP)
        }

        // L2 forward within VNI
        return v.forwardL2(vni, packet, dstMAC)
    }

    // Inter-VNI routing
    for targetVNI, targetSubnet := range v.anycastGateway.VNIToSubnet {
        if targetSubnet.Contains(ip.DstIP) {
            return v.routeToVNI(targetVNI, packet)
        }
    }

    // External routing
    return v.routeExternal(packet)
}
```

## OpenFlow Pipeline

The overlay gateway uses a multi-table OpenFlow pipeline for packet processing.

### Pipeline Tables

| Table | Name | Function |
|-------|------|----------|
| 0 | Ingress Classification | Classify packet source (local/tunnel) |
| 10 | VXLAN Decap | Strip VXLAN headers, map VNI to VLAN |
| 20 | Authentication | Certificate-based port authentication |
| 30 | MAC Learning | Learn source MAC, L2 forwarding decisions |
| 40 | ARP Handling | ARP suppression, proxy ARP |
| 50 | L3 Routing | Anycast gateway, inter-VNI routing |
| 60 | Egress | Output to local port or tunnel encap |

### Flow Installation

```go
// OpenFlowPipeline manages overlay flow tables
type OpenFlowPipeline struct {
    ofClient   *openflow.Client
    bridge     string
}

// InstallBaseFlows sets up the pipeline
func (p *OpenFlowPipeline) InstallBaseFlows() error {
    // Table 0: Ingress Classification
    flows := []openflow.FlowMod{
        // From VXLAN tunnel
        {
            Table:    0,
            Priority: 100,
            Match:    openflow.Match{InPort: VXLANPort, UDPDst: 4789},
            Actions:  []openflow.Action{{Type: openflow.ActionGotoTable, Value: 10}},
        },
        // From local ports
        {
            Table:    0,
            Priority: 50,
            Match:    openflow.Match{},
            Actions:  []openflow.Action{{Type: openflow.ActionGotoTable, 20}},
        },
    }

    // Table 10: VXLAN Decap
    // (VNI-specific rules installed dynamically)

    // Table 20: Authentication (handled by policy engine)

    // Table 30: MAC Learning
    flows = append(flows, openflow.FlowMod{
        Table:    30,
        Priority: 1,
        Match:    openflow.Match{},
        Actions:  []openflow.Action{
            {Type: openflow.ActionLearn},
            {Type: openflow.ActionGotoTable, Value: 40},
        },
    })

    // Table 40: ARP Handling
    flows = append(flows, openflow.FlowMod{
        Table:    40,
        Priority: 100,
        Match:    openflow.Match{EthType: 0x0806}, // ARP
        Actions:  []openflow.Action{{Type: openflow.ActionController}},
    })
    flows = append(flows, openflow.FlowMod{
        Table:    40,
        Priority: 50,
        Match:    openflow.Match{},
        Actions:  []openflow.Action{{Type: openflow.ActionGotoTable, Value: 50}},
    })

    // Table 50: L3 Routing (anycast gateway)
    // (Gateway-specific rules installed by ConfigureAnycastGateway)

    // Table 60: Egress
    flows = append(flows, openflow.FlowMod{
        Table:    60,
        Priority: 1,
        Match:    openflow.Match{},
        Actions:  []openflow.Action{{Type: openflow.ActionNormal}},
    })

    for _, flow := range flows {
        if err := p.ofClient.AddFlow(context.Background(), &flow); err != nil {
            return fmt.Errorf("install flow: %w", err)
        }
    }

    return nil
}

// InstallVNIFlows adds VNI-specific flows
func (p *OpenFlowPipeline) InstallVNIFlows(vni uint32, vlan uint16) error {
    // Table 10: VNI to VLAN mapping (decap)
    decapFlow := openflow.FlowMod{
        Table:    10,
        Priority: 100,
        Match:    openflow.Match{TunnelID: uint64(vni)},
        Actions: []openflow.Action{
            {Type: openflow.ActionSetVLAN, Value: int(vlan)},
            {Type: openflow.ActionGotoTable, Value: 20},
        },
    }

    // Table 60: VLAN to VNI mapping (encap)
    encapFlow := openflow.FlowMod{
        Table:    60,
        Priority: 100,
        Match:    openflow.Match{VLANVid: vlan, OutPort: VXLANPort},
        Actions: []openflow.Action{
            {Type: openflow.ActionSetTunnel, Value: int(vni)},
            {Type: openflow.ActionOutput, Value: VXLANPort},
        },
    }

    if err := p.ofClient.AddFlow(context.Background(), &decapFlow); err != nil {
        return err
    }
    return p.ofClient.AddFlow(context.Background(), &encapFlow)
}

// InstallRemoteMACFlow adds forwarding for remote MAC
func (p *OpenFlowPipeline) InstallRemoteMACFlow(vni uint32, mac net.HardwareAddr, vtepIP netip.Addr) error {
    flow := openflow.FlowMod{
        Table:    30,
        Priority: 100,
        Match: openflow.Match{
            TunnelID: uint64(vni),
            EthDst:   mac.String(),
        },
        Actions: []openflow.Action{
            {Type: openflow.ActionSetTunnelDst, Value: vtepIP.String()},
            {Type: openflow.ActionGotoTable, Value: 60},
        },
    }

    return p.ofClient.AddFlow(context.Background(), &flow)
}
```

## State Synchronization

### MAC Table Replication

MAC tables are replicated via QuicBaaS with eventual consistency:

```go
// MACTable with QuicBaaS replication
type MACTable struct {
    db         *quicbaas.Client
    partition  string
    local      map[string]*MACEntry
    mu         sync.RWMutex
}

type MACEntry struct {
    MAC        string
    VNI        uint32
    VTEPIP     netip.Addr
    LearnedAt  time.Time
    ExpiresAt  time.Time
}

// Learn adds a MAC entry with replication
func (m *MACTable) Learn(vni uint32, mac string, vtepIP netip.Addr) error {
    entry := &MACEntry{
        MAC:       mac,
        VNI:       vni,
        VTEPIP:    vtepIP,
        LearnedAt: time.Now(),
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }

    // Local cache
    m.mu.Lock()
    m.local[mac] = entry
    m.mu.Unlock()

    // Replicate to QuicBaaS
    key := fmt.Sprintf("%s/%d/%s", m.partition, vni, mac)
    value, _ := json.Marshal(entry)

    return m.db.PutWithTTL(context.Background(), key, value, 5*time.Minute)
}

// Lookup finds MAC entry
func (m *MACTable) Lookup(vni uint32, mac string) (*MACEntry, bool) {
    m.mu.RLock()
    entry, ok := m.local[mac]
    m.mu.RUnlock()

    if ok && entry.VNI == vni {
        return entry, true
    }

    // Check QuicBaaS
    key := fmt.Sprintf("%s/%d/%s", m.partition, vni, mac)
    value, err := m.db.Get(context.Background(), key)
    if err != nil {
        return nil, false
    }

    var dbEntry MACEntry
    if err := json.Unmarshal(value, &dbEntry); err != nil {
        return nil, false
    }

    return &dbEntry, true
}
```

## Performance Considerations

| Aspect | Recommendation |
|--------|----------------|
| Underlay MTU | 9000 (jumbo frames) to avoid fragmentation |
| VXLAN Overhead | 50 bytes (Ethernet + IP + UDP + VXLAN) |
| Effective VM MTU | 8950 with jumbo, 1450 with standard |
| Hardware Offload | Enable VXLAN offload on supported NICs |
| MAC Table Size | 64K entries per VNI typical |
| ARP Cache | 16K entries per VNI typical |

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vtep_vnis_active` | Gauge | - | Active VNI count |
| `vtep_mac_entries` | Gauge | vni | MAC table entries |
| `vtep_arp_cache_entries` | Gauge | vni | ARP cache entries |
| `vtep_packets_encap` | Counter | vni | Encapsulated packets |
| `vtep_packets_decap` | Counter | vni | Decapsulated packets |
| `vtep_arp_suppressed` | Counter | vni | Suppressed ARP requests |
| `vtep_bum_replicated` | Counter | vni | BUM packets replicated |
| `vtep_evpn_routes_rx` | Counter | type | EVPN routes received |
| `vtep_evpn_routes_tx` | Counter | type | EVPN routes sent |

## See Also

- [Gateway Architecture](architecture.md) - Core gateway design
- [VXLAN Overlay](../overlay/README.md) - Overlay networking overview
- [BGP EVPN](../bgp/evpn.md) - EVPN route exchange
- [Configuration](configuration.md) - Overlay configuration reference

# VXLAN Overlay Architecture

## System Overview

```
+-----------------------------------------------------------------------------+
|                          Trusted Platform Overlay                            |
|                        (Multi-Host VXLAN Networking)                         |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                        Overlay Manager (pkg/sdn/overlay)               |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +----------------------+  |  |
|  |  |  VTEP Manager    |  |  VNI Manager     |  |  Tunnel Manager      |  |  |
|  |  |                  |  |                  |  |                      |  |  |
|  |  |  - Registration  |  |  - VLAN-to-VNI   |  |  - Establishment     |  |  |
|  |  |  - Discovery     |  |  - Membership    |  |  - Health checks     |  |  |
|  |  |  - Health        |  |  - OpenFlow      |  |  - Failover          |  |  |
|  |  +------------------+  +------------------+  +----------------------+  |  |
|  |                                                                        |  |
|  |  +------------------+  +------------------+  +----------------------+  |  |
|  |  |  MAC Manager     |  |  BUM Handler     |  |  ARP Suppression     |  |  |
|  |  |                  |  |                  |  |                      |  |  |
|  |  |  - Learning      |  |  - Broadcast     |  |  - Proxy ARP         |  |  |
|  |  |  - Aging         |  |  - Unknown ucast |  |  - Gratuitous ARP    |  |  |
|  |  |  - Replication   |  |  - Multicast     |  |  - Cache sync        |  |  |
|  |  +------------------+  +------------------+  +----------------------+  |  |
|  +------------------------------------------------------------------------+  |
|                                      |                                       |
|              +-------------------+---+---+-------------------+               |
|              |                   |       |                   |               |
|              v                   v       v                   v               |
|  +------------------+  +------------------+  +------------------+            |
|  |   OVS Client     |  |  OpenFlow Client |  |    QuicBaaS      |            |
|  |  (pkg/sdn/ovs)   |  | (pkg/sdn/openflow)|  |  (State Store)   |            |
|  |                  |  |                  |  |                  |            |
|  |  - VXLAN ports   |  |  - Table 0-60    |  |  - VTEP registry |            |
|  |  - Bridge config |  |  - Encap/Decap   |  |  - MAC tables    |            |
|  |  - Port state    |  |  - Forwarding    |  |  - VNI membership|            |
|  +------------------+  +------------------+  +------------------+            |
|                                                                              |
+-----------------------------------------------------------------------------+
```

## Component Details

### Overlay Manager

The Overlay Manager coordinates all overlay networking operations.

```go
// OverlayManager manages VXLAN overlay networking
type OverlayManager struct {
    config       *OverlayConfig
    vtepManager  *VTEPManager
    vniManager   *VNIManager
    tunnelMgr    *TunnelManager
    macManager   *MACManager
    bumHandler   *BUMHandler
    arpSuppress  *ARPSuppression
    ovsClient    *ovs.Client
    ofClient     *openflow.Client
    store        datastore.Store
    logger       *slog.Logger
}
```

### VTEP Manager

Manages local VTEP registration and remote VTEP discovery.

```go
// VTEPManager handles VTEP lifecycle
type VTEPManager struct {
    localVTEP    *VTEP
    remoteVTEPs  map[string]*VTEP  // keyed by VTEP IP
    store        datastore.Store
    notifier     cluster.Notifier
    mu           sync.RWMutex
}

// VTEP represents a VXLAN Tunnel Endpoint
type VTEP struct {
    IP            net.IP
    UnderlayIface string
    UnderlayMTU   int
    VXLANPort     uint16
    ActiveVNIs    []uint32
    LastHeartbeat time.Time
    Healthy       bool
}
```

### VNI Manager

> **Superseded numbering.** The sketch below predates the reference network.
> VNIs are no longer VLAN-derived: overlay network n of environment E is VNI
> E·100000+n (`pkg/sdn/netplan.VNI`), and the controller derives the lowest
> free n when a VNI is created without one (`overlay.Config.Environment`).

Manages VNI membership.

```go
// VNIManager handles VNI-VLAN mapping
type VNIManager struct {
    environment  uint16           // E: VNIs are E·100000+n
    localVNIs    map[uint32]*VNI  // Active VNIs on this host
    vniPorts     map[uint32][]string // Ports per VNI
    store        datastore.Store
    mu           sync.RWMutex
}

// VNI represents a VXLAN Network Identifier
type VNI struct {
    ID          uint32
    VLANID      uint16
    LocalPorts  []string
    RemoteVTEPs []net.IP
    Multicast   net.IP  // Optional multicast group
}

// VNIFor derives the VNI of overlay network n (netplan.VNI)
func (m *VNIManager) VNIFor(n uint32) (uint32, error) {
    return netplan.VNI(m.environment, n)
}
```

### Tunnel Manager

Manages VXLAN tunnel establishment and health.

```go
// TunnelManager handles tunnel lifecycle
type TunnelManager struct {
    tunnels      map[string]*Tunnel  // keyed by "localIP-remoteIP-VNI"
    healthCheck  time.Duration
    ovsClient    *ovs.Client
    mu           sync.RWMutex
}

// Tunnel represents a VXLAN tunnel to a remote VTEP
type Tunnel struct {
    LocalVTEP   net.IP
    RemoteVTEP  net.IP
    VNI         uint32
    OVSPort     string
    OFPort      uint32
    State       TunnelState
    LastCheck   time.Time
    RTT         time.Duration
}
```

## Data Flow

### East-West Traffic (VM to VM across hosts)

```
VM1 (Host A, VLAN 100)                         VM2 (Host B, VLAN 100)
       |                                              ^
       | 1. L2 frame                                  | 8. L2 frame
       v                                              |
+------+------+                                +------+------+
|  OVS br-int |                                |  OVS br-int |
|             |                                |             |
|  Table 0:   |                                |  Table 50:  |
|  Classify   |                                |  Decap      |
|      |      |                                |      ^      |
|      v      |                                |      |      |
|  Table 10:  |                                |      |      |
|  L2 Lookup  |                                |      |      |
|  (miss)     |                                |      |      |
|      |      |                                |      |      |
|      v      |                                |      |      |
|  Table 20:  |                                |      |      |
|  Tunnel Sel |                                |      |      |
|      |      |                                |      |      |
|      v      |                                |      |      |
|  Table 30:  |                                |      |      |
|  Encap      |                                |      |      |
+------+------+                                +------+------+
       |                                              ^
       | 2. VXLAN encap                               | 7. UDP/4789
       | (VNI 1000100)                                |
       v                                              |
+------+------+                                +------+------+
|  VTEP       |                                |  VTEP       |
|  10.0.0.1   |                                |  10.0.0.2   |
+------+------+                                +------+------+
       |                                              ^
       | 3. UDP/4789                                  | 6. IP packet
       v                                              |
+------+------+                                +------+------+
|  eth0       |                                |  eth0       |
|  Underlay   |                                |  Underlay   |
+------+------+                                +------+------+
       |                                              ^
       | 4. IP packet (MTU 9000)                      |
       +-----------------> Physical Network ----------+
                           5. Route to 10.0.0.2
```

### VXLAN Encapsulation

```
Original L2 Frame (max 1500 bytes with standard MTU):
+------------------+------------------+------------------+
| Eth Header (14B) | IP Header (20B)  | Payload          |
+------------------+------------------+------------------+

After VXLAN Encapsulation (+50 bytes overhead):
+------------------+------------------+------------------+------------------+------------------+------------------+
| Outer Eth (14B)  | Outer IP (20B)   | UDP (8B)         | VXLAN (8B)       | Original L2      | Original Payload |
+------------------+------------------+------------------+------------------+------------------+------------------+
                   ^                  ^                  ^
                   |                  |                  |
                   |                  |                  +-- VNI (24-bit), Flags
                   |                  |
                   |                  +-- Src: random high, Dst: 4789
                   |
                   +-- Src: 10.0.0.1, Dst: 10.0.0.2, Protocol: UDP

Total Overhead: 50 bytes
- Outer Ethernet: 14 bytes
- Outer IP: 20 bytes
- UDP: 8 bytes
- VXLAN: 8 bytes
```

### MTU Considerations

```
Underlay MTU = 9000 (Jumbo Frames)
VXLAN Overhead = 50 bytes
Effective VM MTU = 9000 - 50 = 8950 bytes

Underlay MTU = 1500 (Standard)
VXLAN Overhead = 50 bytes
Effective VM MTU = 1500 - 50 = 1450 bytes

Recommendation: Use jumbo frames (MTU 9000) on underlay network
```

## OpenFlow Pipeline

### Pipeline Tables

| Table | Name | Purpose |
|-------|------|---------|
| 0 | Classifier | Classify packets by source (local port, tunnel) |
| 10 | L2 Lookup | MAC destination lookup |
| 20 | Tunnel Select | Select tunnel for remote destinations |
| 30 | Encapsulation | Apply VXLAN headers |
| 40 | Egress ACL | Apply egress policies |
| 50 | Decapsulation | Strip VXLAN headers |
| 60 | Local Delivery | Deliver to local port |

### Pipeline Flow Diagram

```
                    Ingress from Local Port
                              |
                              v
                    +-------------------+
                    | Table 0:          |
                    | Classifier        |
                    | - Set metadata    |
                    | - Mark as LOCAL   |
                    +--------+----------+
                             |
                             v
                    +-------------------+
                    | Table 10:         |
                    | L2 Lookup         |
                    | - Match dst_mac   |
                    | - Check VNI/VLAN  |
                    +--------+----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
    +-------------------+         +-------------------+
    | Local Destination |         | Remote Destination|
    | (MAC on this host)|         | (MAC on remote)   |
    +--------+----------+         +--------+----------+
             |                             |
             v                             v
    +-------------------+         +-------------------+
    | Table 60:         |         | Table 20:         |
    | Local Delivery    |         | Tunnel Select     |
    | - Output to port  |         | - Lookup VTEP     |
    +-------------------+         +--------+----------+
                                           |
                                           v
                                  +-------------------+
                                  | Table 30:         |
                                  | Encapsulation     |
                                  | - Set VNI         |
                                  | - Set tunnel dst  |
                                  +--------+----------+
                                           |
                                           v
                                  +-------------------+
                                  | Table 40:         |
                                  | Egress ACL        |
                                  | - Apply policies  |
                                  | - Output tunnel   |
                                  +-------------------+
```

### Sample OpenFlow Rules

```
# Table 0: Classifier - packet from local VM port
cookie=0x1, priority=100, in_port=1, actions=set_field:100->metadata,goto_table:10

# Table 0: Classifier - packet from VXLAN tunnel
cookie=0x2, priority=100, in_port=2, tun_id=1000100, actions=set_field:100->metadata,goto_table:50

# Table 10: L2 Lookup - known local MAC
cookie=0x10, priority=100, metadata=100, dl_dst=aa:bb:cc:dd:ee:ff, actions=goto_table:60

# Table 10: L2 Lookup - known remote MAC (on VTEP 10.0.0.2)
cookie=0x11, priority=100, metadata=100, dl_dst=11:22:33:44:55:66, actions=set_field:10.0.0.2->tun_dst,goto_table:30

# Table 10: L2 Lookup - unknown MAC (flood)
cookie=0x12, priority=1, metadata=100, actions=goto_table:20

# Table 20: Tunnel Select - flood to all VTEPs for VNI 1000100
cookie=0x20, priority=100, metadata=100, actions=output:LOCAL,output:2,output:3

# Table 30: Encapsulation - set VNI and send to tunnel
cookie=0x30, priority=100, actions=set_field:1000100->tun_id,goto_table:40

# Table 40: Egress ACL - allow all (default)
cookie=0x40, priority=1, actions=output:tun_port

# Table 50: Decapsulation - strip tunnel and process
cookie=0x50, priority=100, tun_id=1000100, actions=goto_table:60

# Table 60: Local Delivery - output to VM port
cookie=0x60, priority=100, metadata=100, dl_dst=aa:bb:cc:dd:ee:ff, actions=output:1
```

## Integration with Existing SDN

### OVS Client Integration

```go
// Create VXLAN port on bridge
func (m *OverlayManager) CreateVXLANPort(ctx context.Context, vni uint32, remoteVTEP net.IP) error {
    portName := fmt.Sprintf("vxlan-%d-%s", vni, remoteVTEP.String())

    // Create VXLAN interface via OVS
    iface := &ovs.Interface{
        Name: portName,
        Type: "vxlan",
        Options: map[string]string{
            "remote_ip": remoteVTEP.String(),
            "key":       strconv.FormatUint(uint64(vni), 10),
            "dst_port":  strconv.Itoa(int(m.config.VXLANPort)),
        },
    }

    return m.ovsClient.CreateInterface(ctx, m.config.BridgeName, iface)
}
```

### OpenFlow Integration

```go
// Install encapsulation flow
func (m *OverlayManager) InstallEncapFlow(ctx context.Context, vni uint32, remoteVTEP net.IP, dstMAC net.HardwareAddr) error {
    flow := openflow.NewFlowMod(100)
    flow.Table = TableL2Lookup
    flow.Match.SetMetadata(uint64(vni)) // VNI as metadata
    flow.Match.SetEthDst(dstMAC.String())
    flow.AddSetFieldAction("tun_dst", remoteVTEP.String())
    flow.AddGotoTableAction(TableEncap)

    return m.ofClient.AddFlow(ctx, flow)
}

// Install decapsulation flow
func (m *OverlayManager) InstallDecapFlow(ctx context.Context, vni uint32, tunnelPort uint32) error {
    flow := openflow.NewFlowMod(100)
    flow.Table = TableDecap
    flow.Match.SetInPort(tunnelPort)
    flow.Match.SetTunnelID(uint64(vni))
    flow.AddGotoTableAction(TableLocalDelivery)

    return m.ofClient.AddFlow(ctx, flow)
}
```

### Policy Engine Integration

```go
// Hook into device authentication
func (e *PolicyEngine) OnDeviceAuthorized(ctx context.Context, portID string, policy *PortPolicy) error {
    // Existing VLAN assignment
    if err := e.SetPortVLAN(ctx, portID, policy.VLAN); err != nil {
        return err
    }

    // Derive VNI from VLAN
    vni := e.overlayMgr.VNIManager.VLANToVNI(policy.VLAN)

    // Register port with VNI
    if err := e.overlayMgr.RegisterPortVNI(ctx, portID, vni); err != nil {
        return err
    }

    // Install local forwarding flows
    if err := e.overlayMgr.InstallLocalFlows(ctx, portID, vni); err != nil {
        return err
    }

    // Notify other hosts about new VNI membership
    return e.overlayMgr.AnnounceVNIMembership(ctx, vni)
}
```

## QuicBaaS State Schema

### VTEP Registry

```go
// Partition: sdn/overlay/vteps
type VTEPRecord struct {
    ID            uint64    `json:"id"`
    IP            string    `json:"ip"`
    NodeID        string    `json:"node_id"`
    UnderlayIface string    `json:"underlay_iface"`
    UnderlayMTU   int       `json:"underlay_mtu"`
    VXLANPort     uint16    `json:"vxlan_port"`
    ActiveVNIs    []uint32  `json:"active_vnis"`
    Healthy       bool      `json:"healthy"`
    LastHeartbeat time.Time `json:"last_heartbeat"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}
```

### VNI Membership

```go
// Partition: sdn/overlay/vnis
type VNIMembershipRecord struct {
    VNI         uint32   `json:"vni"`
    VLANID      uint16   `json:"vlan_id"`
    MemberVTEPs []string `json:"member_vteps"`  // VTEP IPs
    Multicast   string   `json:"multicast,omitempty"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

### MAC Table

```go
// Partition: sdn/overlay/macs
type MACRecord struct {
    MAC       string    `json:"mac"`
    VNI       uint32    `json:"vni"`
    VTEPIP    string    `json:"vtep_ip"`
    PortID    string    `json:"port_id"`
    LearnedAt time.Time `json:"learned_at"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

## BUM Traffic Handling

### Broadcast/Unknown Unicast/Multicast

```
BUM Traffic Sources:
1. ARP requests (broadcast)
2. DHCP discover (broadcast)
3. Unknown destination MAC (unicast flood)
4. Multicast traffic

Handling Strategies:
+------------------+--------------------+---------------------------+
| Traffic Type     | Strategy           | Implementation            |
+------------------+--------------------+---------------------------+
| ARP Broadcast    | ARP Suppression    | Proxy ARP from MAC table  |
| DHCP Broadcast   | Local + Tunnel     | Forward to all VTEPs      |
| Unknown Unicast  | Head-end Repl.     | Forward to all VTEPs      |
| Multicast        | Multicast Group    | IGMP snooping (optional)  |
+------------------+--------------------+---------------------------+
```

### ARP Suppression

```go
// ARPSuppression reduces broadcast by proxying ARP
type ARPSuppression struct {
    macTable map[uint32]map[string]net.IP  // VNI -> MAC -> IP
    store    datastore.Store
    mu       sync.RWMutex
}

func (a *ARPSuppression) HandleARPRequest(ctx context.Context, vni uint32, srcMAC, dstMAC net.HardwareAddr, targetIP net.IP) (*ARPReply, error) {
    a.mu.RLock()
    defer a.mu.RUnlock()

    // Check if we know the target IP's MAC
    if macs, ok := a.macTable[vni]; ok {
        for mac, ip := range macs {
            if ip.Equal(targetIP) {
                hwAddr, _ := net.ParseMAC(mac)
                return &ARPReply{
                    SenderMAC: hwAddr,
                    SenderIP:  targetIP,
                    TargetMAC: srcMAC,
                    TargetIP:  srcIP,
                }, nil
            }
        }
    }

    // Unknown - let it flood
    return nil, nil
}
```

## Thread Safety

### Concurrency Model

```go
// All managers use fine-grained locking
type OverlayManager struct {
    // ... fields ...

    // Separate locks for different operations
    vtepMu   sync.RWMutex  // VTEP operations
    vniMu    sync.RWMutex  // VNI operations
    tunnelMu sync.RWMutex  // Tunnel operations
    macMu    sync.RWMutex  // MAC table operations
}

// Read operations use RLock
func (m *OverlayManager) GetVTEP(ip net.IP) (*VTEP, error) {
    m.vtepMu.RLock()
    defer m.vtepMu.RUnlock()
    // ...
}

// Write operations use Lock
func (m *OverlayManager) RegisterVTEP(vtep *VTEP) error {
    m.vtepMu.Lock()
    defer m.vtepMu.Unlock()
    // ...
}
```

## Error Handling

```go
// pkg/sdn/overlay/errors.go
var (
    ErrVTEPNotFound       = errors.New("VTEP not found")
    ErrVTEPAlreadyExists  = errors.New("VTEP already registered")
    ErrVNINotFound        = errors.New("VNI not found")
    ErrVNIOutOfRange      = errors.New("VNI out of valid range")
    ErrTunnelFailed       = errors.New("tunnel establishment failed")
    ErrTunnelUnhealthy    = errors.New("tunnel health check failed")
    ErrMACNotFound        = errors.New("MAC address not found")
    ErrMACTableFull       = errors.New("MAC table capacity exceeded")
    ErrMTUTooSmall        = errors.New("underlay MTU too small for VXLAN")
    ErrInvalidVXLANPort   = errors.New("invalid VXLAN UDP port")
    ErrUnderlayUnreachable = errors.New("underlay network unreachable")
)
```

## Health Monitoring

### VTEP Health Checks

```go
// HealthChecker monitors tunnel and VTEP health
type HealthChecker struct {
    interval time.Duration
    timeout  time.Duration
    manager  *OverlayManager
}

func (h *HealthChecker) Run(ctx context.Context) {
    ticker := time.NewTicker(h.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            h.checkAllTunnels(ctx)
        }
    }
}

func (h *HealthChecker) checkAllTunnels(ctx context.Context) {
    tunnels := h.manager.ListTunnels()
    for _, t := range tunnels {
        start := time.Now()
        if err := h.pingVTEP(ctx, t.RemoteVTEP); err != nil {
            t.State = TunnelStateUnhealthy
            h.manager.HandleTunnelFailure(ctx, t)
        } else {
            t.RTT = time.Since(start)
            t.State = TunnelStateHealthy
            t.LastCheck = time.Now()
        }
    }
}
```

## Performance Considerations

| Aspect | Recommendation |
|--------|----------------|
| MAC Table Size | 64K entries per VNI (configurable) |
| MAC Aging | 300 seconds default |
| VTEP Health Interval | 10 seconds |
| Tunnel RTT Threshold | 100ms warning, 500ms critical |
| Flow Cookie Prefix | 0x0VLAN0000 for VNI flows |
| Flow Programming | One FlowMod per call today; OVS transaction batching is a planned optimization |

## See Also

- [SDN Architecture](../architecture.md)
- [OpenFlow Client](../README.md#openflow-client)
- [OVS Client](../README.md#ovsdb-client)
- [QuicBaaS](../../datastore/README.md)

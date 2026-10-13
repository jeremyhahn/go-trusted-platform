# SDN (Software-Defined Networking) Package

Pure Go implementation of SDN components for the Trusted Platform.

## Status

| Component | Status | Test Coverage | Integration Tests |
|-----------|--------|---------------|-------------------|
| ARP Reader | Complete | 95%+ | 10 tests |
| OpenFlow 1.3 | Complete | 90%+ | 18 tests |
| OVSDB Client | Complete | 90%+ | 12 tests |
| TAP/Netlink | Complete | 85%+ | 8 tests |
| Policy Engine | Complete | 90%+ | 27 tests |
| **Total** | **100% Complete** | **90%+** | **27 integration tests** |

## Features

### Single-Host Features (Complete)

| Feature | Description | Status |
|---------|-------------|--------|
| OVSDB JSON-RPC | RFC 7047 compliant client | Complete |
| OpenFlow 1.3 | Native binary protocol | Complete |
| 802.1X Policy | Certificate-based port authentication | Complete |
| VLAN Management | Provisioning (998), Production, Quarantine (666) | Complete |
| ARP Table | Pure Go /proc/net/arp reader | Complete |
| TAP Devices | Netlink-based TAP management | Complete |
| Certificate Policies | X.509 policy extraction | Complete |
| Flow Generation | Dynamic OpenFlow rule creation | Complete |
| State Machine | Port lifecycle management | Complete |
| Enrollment Hook | ACME enrollment integration | Complete |

### Multi-Host Features (Complete)

| Feature | Description | Status |
|---------|-------------|--------|
| VXLAN Overlay | East-west VM/container traffic across hosts | Complete |
| BGP EVPN | MAC/IP learning via EVPN Type-2/3/5 routes | Complete |
| BGP Transit | Platform IP block announcements (IPv4/IPv6) | Complete |
| Unified Gateway | Multi-mode gateway (overlay, edge, transit) | Complete |
| IoT Onboarding | ACME endorse-01/enroll-01 for device enrollment | Complete |
| IPv6 Allocation | Address assignment from 2001:db8::/36 pool | Complete |
| DHT Bootstrap | Entry point for Kademlia DHT network | Complete |
| IPAM | IP Address Management with pool-based allocation | Complete |
| DHCP | Integrated DHCP server for overlay networks | Complete |

See [ROADMAP-BGP.md](../archive/ROADMAP-BGP.md) for full implementation details.

## Package Structure

```
pkg/sdn/
├── arp/         # Pure Go ARP table reader (/proc/net/arp)
├── netlink/     # TAP device and link management
├── openflow/    # Native OpenFlow 1.3 protocol client
├── ovs/         # OVSDB client (RFC 7047) + flow management
├── policy/      # 802.1X port-based authentication engine
├── cluster/     # QuicBaaS-backed cluster state management
├── vxlan/       # VXLAN tunnel management, VNI mapping
├── bgp/         # GoBGP integration (EVPN + Transit)
├── gateway/     # Unified gateway nodes (overlay/edge/transit modes)
│   ├── commands/ # gatewayd CLI commands (serve, version)
│   ├── modes/    # The EVPN overlay mode handler
│   └── p2p/      # P2P gateway functionality
├── overlay/     # Multi-host overlay controller
├── ipam/        # IP Address Management (pool-based allocation)
│   └── backends/ # Storage backends (memory, quicbaas, dht)
└── dhcp/        # DHCP server for overlay networks
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Policy Engine                             │
│  (pkg/sdn/policy)                                                   │
│  - Port state machine (Unconnected -> Provisioning -> Authorized)   │
│  - Certificate policy extraction                                    │
│  - Flow rule generation                                             │
│  - VLAN management via OVSDB                                        │
└─────────────────┬───────────────────────────────────┬───────────────┘
                  │                                   │
        ┌─────────▼─────────┐               ┌─────────▼─────────┐
        │    OVS Client     │               │    ARP Reader     │
        │  (pkg/sdn/ovs)    │               │  (pkg/sdn/arp)    │
        │  - OVSDB JSON-RPC │               │  - /proc/net/arp  │
        │  - Bridge/Port    │               │  - MAC lookup     │
        └─────────┬─────────┘               └───────────────────┘
                  │
        ┌─────────▼─────────┐
        │  OpenFlow Client  │
        │ (pkg/sdn/openflow)│
        │  - OF 1.3 binary  │
        │  - Flow add/del   │
        └───────────────────┘
```

## Key Design Principles

1. **Pure Go Implementation** - No shell commands or exec.Command calls
2. **Native Protocols** - Direct OVSDB JSON-RPC and OpenFlow binary protocols
3. **RFC Compliant** - OVSDB (RFC 7047), OpenFlow 1.3, ACME (RFC 8555)
4. **Hand-rolled core protocol clients** - `pkg/sdn/ovs` (OVSDB JSON-RPC) and `pkg/sdn/openflow` (OpenFlow 1.3 binary) are written against the stdlib alone, with no protocol library behind them

The stdlib-only property covers those two packages, not the whole SDN subsystem. Elsewhere it uses established libraries rather than reimplementing them:

| Package | Dependency | Why |
|---------|------------|-----|
| `pkg/sdn/bgp` | `osrg/gobgp/v3` | BGP speaker (EVPN + Transit); GoBGP provides the session state machine and route handling |
| `pkg/sdn/netlink` | `vishvananda/netlink` | Kernel netlink socket operations |
| `test/integration/sdn` | `ovn-org/libovsdb` | Independent OVSDB client used as a test oracle against a real switch, so the hand-rolled client is checked against a second implementation rather than against itself |

## Documentation

### Core SDN
- [Architecture](architecture.md) - Design and component overview
- [Configuration](configuration.md) - Configuration reference
- [802.1X Authentication](802.1x.md) - Port-based authentication
- [Provisioning](provisioning.md) - Device provisioning flow
- [API Reference](api-reference.md) - gRPC API documentation
- [CLI Usage](cli-usage.md) - CLI commands reference
- [Testing](testing.md) - Testing strategy and guidelines

### Multi-Host Networking
- [BGP](bgp/README.md) - BGP service (EVPN + Transit)
- [Gateway](gateway/README.md) - Multi-mode gateway nodes
- [Overlay](overlay/README.md) - VXLAN overlay controller
- [IPAM](ipam/README.md) - IP Address Management
- [DHCP](dhcp/README.md) - DHCP server for overlay networks
- [Multi-Host Roadmap](../archive/ROADMAP-BGP.md) - Implementation roadmap

## Quick Start

### OVSDB Client

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"

// Create client
client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
if err != nil {
    return err
}

// Connect
ctx := context.Background()
if err := client.Connect(ctx); err != nil {
    return err
}
defer client.Close()

// Create bridge
bridge, err := client.CreateBridge(ctx, "br0")
if err != nil {
    return err
}

// Add port with VLAN
port, err := client.AddPort(ctx, "br0", "eth0")
if err != nil {
    return err
}

// Set port VLAN
err = client.SetPortVLAN(ctx, "eth0", 100)
```

### OpenFlow Client

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"

// Create client
ofClient, err := openflow.NewClient("br0")
if err != nil {
    return err
}

// Connect to bridge management socket
ctx := context.Background()
if err := ofClient.Connect(ctx); err != nil {
    return err
}
defer ofClient.Close()

// Add flow rule
flow := openflow.NewFlowMod(100) // priority 100
flow.Match.SetInPort(1)
flow.Match.SetEthType(0x0800) // IPv4
flow.AddOutputAction(2)

err = ofClient.AddFlow(ctx, flow)
```

### ARP Lookup

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"

// Create ARP table reader
table := arp.NewTable()

// Lookup MAC address from IP
mac, err := table.LookupMAC("192.168.1.100")
if err != nil {
    // IP not in ARP cache
    return err
}

fmt.Printf("MAC: %s\n", mac.String())
```

### Policy Engine

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"

// Create policy engine
config := policy.Config{
    BridgeName:     "br0",
    FlowController: ovsClient, // OVS client implements FlowController
    PortController: ovsClient, // OVS client implements OVSPortController
}

engine, err := policy.NewEngine(config)
if err != nil {
    return err
}

// Set port to provisioning state
err = engine.SetPortState("eth1", policy.PortStateProvisioning)

// Apply production policy
prodPolicy := &policy.PortPolicy{
    TenantID: "tenant-1",
    VLAN:     100,
    ACLs: []policy.ACLRule{
        {
            Priority: 1000,
            Match:    policy.FlowMatch{IPProto: 6, TCPDst: 443},
            Action:   policy.FlowAction{Type: policy.FlowActionAllow},
        },
    },
}

err = engine.ApplyPolicy("eth1", prodPolicy)
```

## Port States

The policy engine manages port authentication states:

| State | VLAN | Description |
|-------|------|-------------|
| `PortStateUnconnected` | - | No device connected |
| `PortStateProvisioning` | 998 | Limited access for enrollment |
| `PortStateEnrolled` | 998 | Enrolled, awaiting activation |
| `PortStateAuthorized` | Profile | Full production access |
| `PortStateQuarantined` | 666 | Isolated VLAN (compliance issue) |
| `PortStateBlocked` | - | Complete network isolation (DROP) |

## Port State Machine

```
                 device_connect
Unconnected ──────────────────────> Provisioning
                                          │
                                          │ enrollment_complete
                                          ▼
                                      Enrolled
                                          │
                                          │ client_activates
                                          ▼
                                     Authorized <────────────┐
                                          │                  │
                            cert_expired/ │                  │ remediation
                            compliance    │                  │ complete
                                          ▼                  │
                                    Quarantined ─────────────┘
                                          │
                                          │ cert_revoked
                                          ▼
                                       Blocked
```

## Integration with Compute

The SDN package integrates with the compute orchestrator to provide 802.1X network
access control for virtual machines. See [802.1X Network Attachment](../compute/802.1X-network-attachment.md).

## References

- [RFC 7047 - OVSDB Protocol](https://datatracker.ietf.org/doc/html/rfc7047)
- [OpenFlow 1.3 Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- [IEEE 802.1X-2010](https://standards.ieee.org/standard/802_1X-2010.html)
- [RFC 8555 - ACME Protocol](https://datatracker.ietf.org/doc/html/rfc8555)

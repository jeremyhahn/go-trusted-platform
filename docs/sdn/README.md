# SDN (Software-Defined Networking) Package

> **Status: REFERENCE** · Last verified: 2026-10-15
> Overview of the SDN packages under `pkg/sdn/`.

Pure Go implementation of SDN components for the Trusted Platform.

## Features

### Single-Host Features (Complete)

| Feature | Description | Status |
|---------|-------------|--------|
| OVSDB JSON-RPC | RFC 7047 compliant client | Complete |
| OpenFlow 1.3 | Native binary protocol | Complete |
| Port Policy | Certificate-based port authorisation engine (not 802.1X; the API refuses port authentication today, see [user.md](user.md)) | Engine only |
| Zone VLANs | Provisioning (zone offset 05), production zones, quarantine (offset 04), all numbered from `sdn.environment` | Complete |
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

See [ROADMAP.md](../../ROADMAP.md) for full implementation details.

## Package Structure

```
pkg/sdn/
├── arp/         # Pure Go ARP table reader (/proc/net/arp)
├── netlink/     # TAP device and link management
├── openflow/    # Native OpenFlow 1.3 protocol client
├── ovs/         # OVSDB client (RFC 7047) + flow management
├── policy/      # Certificate-based port authorisation engine, port state machine
├── zone/        # Underlay zone vocabulary of the reference network
├── netplan/     # Derives every VLAN and subnet number from sdn.environment
├── ct/          # OVS connection-tracking zone allocation
├── cluster/     # QuicBaaS-backed cluster state management
├── vxlan/       # The local VTEP of the overlay
├── ipsec/       # Host-to-host IPsec on the overlay underlay
├── tunnel/      # GRE/IPIP tunnel lifecycle
├── fabric/      # Physical switch fabric (VLAN/VNI provisioning)
├── fhrp/        # First-hop redundancy speaker (VRRPv3)
├── bgp/         # GoBGP integration (EVPN + Transit)
├── gateway/     # gatewayd: overlay, edge and transit gateway node
│   ├── commands/ # gatewayd CLI commands (serve, version)
│   ├── modes/    # The EVPN overlay mode handler
│   ├── services/ # firewall, hostfw, loadbalancer, nat64, perf, vpn
│   └── p2p/      # P2P gateway functionality
├── overlay/     # Multi-host overlay controller
├── ipam/        # IP Address Management (pool-based allocation)
│   └── backends/ # Storage backends (memory, quicbaas, dht)
└── dhcp/        # DHCP server for overlay networks
```

`gateway/` also holds `controlplane/`, `ipc/`, `process/`, `proxysvc/`,
`sdkclient/`, `secrets/` and `state/`; see [docs/gateway/](../gateway/).

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

1. **Pure Go Implementation** - No shell commands, with two exceptions in
   gatewayd: it re-executes itself to supervise its children
   (`gateway/process/launcher.go`), and the NAT64 driver runs the `jool`
   CLI (`gateway/services/nat64/driver.go`)
2. **Native Protocols** - Direct OVSDB JSON-RPC and OpenFlow binary protocols
3. **RFC Compliant** - OVSDB (RFC 7047), OpenFlow 1.3, ACME (RFC 8555)
4. **Hand-rolled core protocol clients** - `pkg/sdn/ovs` (OVSDB JSON-RPC) and `pkg/sdn/openflow` (OpenFlow 1.3 binary) are written against the stdlib alone, with no protocol library behind them

The stdlib-only property covers those two packages, not the whole SDN subsystem. Elsewhere it uses established libraries rather than reimplementing them:

| Package | Dependency | Why |
|---------|------------|-----|
| `pkg/sdn/bgp` | `osrg/gobgp/v4` | BGP speaker (EVPN + Transit); GoBGP provides the session state machine and route handling — see [docs/bgp/](../bgp/architecture.md) |
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
- [BGP](../bgp/architecture.md) - BGP speaker (EVPN + Transit)
- [Gateway](../gateway/architecture.md) - Multi-mode gateway nodes
- [Overlay](overlay/README.md) - VXLAN overlay controller
- [IPAM](ipam/README.md) - IP Address Management
- [DHCP](dhcp/README.md) - DHCP server for overlay networks
- [Multi-Host Roadmap](../../ROADMAP.md) - Implementation roadmap

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
flow := openflow.NewFlowMod(1) // transaction ID
flow.Priority = 100
flow.Match.AddInPort(1)
flow.Match.AddEthType(0x0800) // IPv4
flow.Instructions = append(flow.Instructions,
    openflow.NewInstructionApplyActions(openflow.NewActionOutput(2, 0xffff)))

err = ofClient.AddFlow(ctx, flow)
```

### ARP Lookup

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"

// Create ARP table reader
table := arp.NewTable()

// Lookup MAC address from IP
mac, err := table.LookupMAC("192.0.2.100")
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

The policy engine manages eight port states (`pkg/sdn/policy/types.go`):

| State | Zone | Description |
|-------|------|-------------|
| `PortStateUnconnected` | - | No device connected (the zero value) |
| `PortStateProvisioning` | provisioning | Limited access for enrollment |
| `PortStateEnrolled` | provisioning | Enrolled, awaiting activation |
| `PortStateUnauthorized` | - | Not authenticated |
| `PortStateAuthenticating` | - | Authentication in progress |
| `PortStateAuthorized` | the role's port class | Full production access |
| `PortStateQuarantined` | quarantine | Isolated for scanning or remediation |
| `PortStateBlocked` | - | Complete network isolation (DROP) |

## Port State Machine

The allowed transitions (`pkg/sdn/policy/state.go`). Every state except
`Blocked` may also move to `Blocked`.

| From | To |
|------|----|
| `Unconnected` | `Provisioning` |
| `Provisioning` | `Enrolled`, `Unauthorized`, `Authenticating`, `Authorized` |
| `Enrolled` | `Authorized` (client activates), `Provisioning` (re-enroll) |
| `Unauthorized` | `Authenticating`, `Provisioning` |
| `Authenticating` | `Authorized`, `Unauthorized` |
| `Authorized` | `Unauthorized`, `Quarantined` |
| `Quarantined` | `Authorized` (remediated), `Provisioning` (re-enroll) |
| `Blocked` | `Unconnected` (admin reset), `Provisioning` (admin re-enrollment) |

## Integration with Compute

The SDN package integrates with the compute orchestrator to provide 802.1X network
access control for virtual machines. See [802.1X Network Attachment](../compute/802.1X-network-attachment.md).

## References

- [RFC 7047 - OVSDB Protocol](https://datatracker.ietf.org/doc/html/rfc7047)
- [OpenFlow 1.3 Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- [IEEE 802.1X-2010](https://standards.ieee.org/standard/802_1X-2010.html)
- [RFC 8555 - ACME Protocol](https://datatracker.ietf.org/doc/html/rfc8555)

# Physical Switch Fabric Management

The `pkg/sdn/fabric` package provides unified orchestration of physical network switch fabric deployments, supporting both traditional VLAN-only and modern EVPN-VXLAN overlay architectures. All operations are vendor-agnostic through a pluggable driver interface.

## Features

- **Multi-vendor support**: Cisco Nexus, IOS-XE, Arista EOS, and others via pluggable drivers
- **VLAN management**: Create and configure VLAN segments across the fabric
- **Link aggregation**: Multi-chassis LAG (MC-LAG) and ESI-LAG support
- **EVPN overlay**: VXLAN VTEP provisioning with VNI mapping and ARP suppression
- **Port lifecycle**: Provision, activate, and quarantine physical ports
- **Idempotent operations**: All operations are safe to call repeatedly

## Operating Modes

### VLAN Mode (Traditional)

Uses 802.1Q VLANs for network segmentation on a single broadcast domain:

```yaml
fabric:
  mode: vlan
  switches:
    - id: core-01
      vendor: cisco-nexus
      mgmt-ip: 10.0.1.50
  segments:
    - name: provisioning
      vlan: 100
      cidr: 10.200.0.0/24
      dhcp: true
      role: provisioning
    - name: production
      vlan: 200
      cidr: 10.201.0.0/24
```

### EVPN Mode (Modern)

Uses VXLAN with EVPN for scalable multi-tenant overlays:

```yaml
fabric:
  mode: evpn
  evpn:
    vni-base: 100000
    anycast-gateway-mac: "00:1a:2b:3c:4d:5e"
    arp-suppression: true
  switches:
    - id: leaf-01
      vendor: cisco-nexus
      mgmt-ip: 10.0.1.51
      vtep-loopback: "10.0.0.51"
      bgp-asn: 65001
  segments:
    - name: tenant-a
      vlan: 100
      cidr: 10.100.0.0/24
```

## Architecture

```
┌───────────────────────────────────────────────┐
│ Fabric Configuration (YAML)                   │
│ - Switches, segments, LAGs, peers             │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Fabric Manager                              │
│ - Config validation                         │
│ - Segment resolution                        │
│ - Port lifecycle (provision/activate)       │
│ - Peer relationship tracking                │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Driver Factory (Vendor Dispatch)            │
│ - cisco-nexus → Nexus Driver                │
│ - noop → No-op (testing)                    │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Per-Switch Drivers (Pluggable)              │
│ - SSH CLI commands                          │
│ - NX-OS API                                 │
│ - Output parsing                            │
└────────────────────┬────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼────┐            ┌────▼────┐
    │ Switch1 │            │ Switch2 │
    │ (Nexus) │            │ (Nexus) │
    └─────────┘            └─────────┘
```

## Core Types

### FabricConfig

Top-level configuration object:

```go
type FabricConfig struct {
    Mode      FabricMode       // "vlan" or "evpn"
    EVPN      *EVPNConfig      // Required for EVPN mode
    Switches  []SwitchConfig   // Physical switches
    Peers     []PeerConfig     // MC-LAG relationships
    LAGs      []LAGConfig      // Link aggregation groups
    Segments  []SegmentConfig  // Network segments
}
```

### Segment

Runtime segment representation with computed VNI:

```go
type Segment struct {
    Name     string      // Unique name
    VLAN     uint16      // 802.1Q VLAN ID (1-4094)
    VNI      uint32      // VXLAN VNI (EVPN mode)
    CIDR     string      // IP network (e.g., "10.200.0.0/24")
    Gateway  string      // Default gateway IP
    DNS      []string    // DNS servers
    DHCP     bool        // DHCP enabled
    Role     SegmentRole // "provisioning", "quarantine", or ""
}
```

### PortRef

Identifies a switch port:

```go
type PortRef struct {
    SwitchID string // Switch identifier
    Port     string // Interface name (e.g., "Eth1/1")
    LAGID    string // Optional LAG group association
}
```

## Interfaces

### Driver

Vendor-specific switch operations:

```go
type Driver interface {
    Connect(ctx context.Context) error
    Close() error
    Ping(ctx context.Context) error
    EnsureVLAN(ctx context.Context, vlan uint16, name string) error
    EnsureVNI(ctx context.Context, vni uint32, vlan uint16) error  // EVPN only
    EnsureLAG(ctx context.Context, lag LAGConfig) error
    SetPortAccess(ctx context.Context, port PortRef, vlan uint16) error
    SetPortTrunk(ctx context.Context, port PortRef, allowed []uint16, native uint16) error
}
```

### Manager

Fabric-wide operations:

```go
type Manager interface {
    ApplyFabric(ctx context.Context) error
    ProvisionPort(ctx context.Context, port PortRef, segment string) error
    ActivatePort(ctx context.Context, port PortRef, segment string) error
    QuarantinePort(ctx context.Context, port PortRef, segment string) error
    SegmentByName(name string) (*Segment, error)
    SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error)
    Close() error
}
```

## Usage

### Initialize the Fabric Manager

```go
config := &fabric.FabricConfig{
    Mode: fabric.ModeVLAN,
    Switches: []fabric.SwitchConfig{
        {
            ID:       "core-01",
            Vendor:   "cisco-nexus",
            MgmtIP:   "10.0.1.50",
            SSHUser:  "admin",
            SSHPassword: "kms://secret-ref",
        },
    },
    Segments: []fabric.SegmentConfig{
        {
            Name:    "provisioning",
            VLAN:    100,
            CIDR:    "10.200.0.0/24",
            Gateway: "10.200.0.1",
            DHCP:    true,
            Role:    fabric.RoleProvisioning,
        },
    },
}

mgr, err := fabric.NewManager(config, logger)
if err != nil {
    log.Fatal(err)
}
defer mgr.Close()
```

### Apply Entire Fabric Configuration

```go
// Create all VLANs, VNIs, and LAGs on all switches
if err := mgr.ApplyFabric(ctx); err != nil {
    log.Fatal(err)
}
```

### Manage Port Lifecycle

```go
// Provision a port (move to provisioning segment)
port := fabric.PortRef{SwitchID: "core-01", Port: "Eth1/5"}
if err := mgr.ProvisionPort(ctx, port, "provisioning"); err != nil {
    log.Fatal(err)
}

// Activate a port after successful provisioning
if err := mgr.ActivatePort(ctx, port, "production"); err != nil {
    log.Fatal(err)
}

// Quarantine a failed or untrusted port
if err := mgr.QuarantinePort(ctx, port, "quarantine"); err != nil {
    log.Fatal(err)
}
```

### Monitor Switch Health

```go
status, err := mgr.SwitchStatus(ctx, "core-01")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Switch: %s, Connected: %v, Vendor: %s\n",
    status.ID, status.Connected, status.Vendor)
```

## Supported Vendors

| Vendor | Status | Notes |
|--------|--------|-------|
| Cisco Nexus (NX-OS) | Production | SSH NX-OS CLI commands |
| Arista EOS | Planned | Compatible SSH CLI |
| Cisco IOS-XE | Planned | Standard Catalyst/ASR CLI |
| Juniper | Planned | NETCONF support planned |

## See Also

- [Configuration Reference](./configuration.md) - Full config schema
- [API Reference](./api-reference.md) - Driver and Manager interfaces
- [Adding Drivers](./adding-drivers.md) - Implement a new vendor driver

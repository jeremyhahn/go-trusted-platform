# Fabric API Reference

## Driver Interface

The `Driver` interface is the abstraction point for vendor-specific switch operations. Each vendor implementation (Cisco Nexus, Arista EOS, etc.) implements this interface.

```go
type Driver interface {
    // Connect establishes a connection to the switch
    Connect(ctx context.Context) error

    // Close releases the connection
    Close() error

    // Ping verifies the connection to the switch is alive
    Ping(ctx context.Context) error

    // EnsureVLAN creates a VLAN if it does not already exist
    // Idempotent: calling multiple times is a no-op
    EnsureVLAN(ctx context.Context, vlan uint16, name string) error

    // EnsureVNI maps a VNI to a VLAN on the NVE interface (EVPN mode)
    // No-op in VLAN mode
    EnsureVNI(ctx context.Context, vni uint32, vlan uint16) error

    // EnsureLAG configures a link aggregation group
    // Idempotent: updating existing LAG is a no-op
    EnsureLAG(ctx context.Context, lag LAGConfig) error

    // SetPortAccess configures a port in access mode with the given VLAN
    SetPortAccess(ctx context.Context, port PortRef, vlan uint16) error

    // SetPortTrunk configures a port in trunk mode
    // allowed: list of allowed VLAN IDs
    // native: native (untagged) VLAN (0 for none)
    SetPortTrunk(ctx context.Context, port PortRef, allowed []uint16, native uint16) error
}
```

### Driver Registration

Drivers are registered at init time via `RegisterDriver()`:

```go
func init() {
    fabric.RegisterDriver("cisco-nexus", NewNexusDriver)
}
```

### DriverFor Function

Retrieve a driver factory for a vendor:

```go
func DriverFor(cfg SwitchConfig, logger *slog.Logger) (Driver, error)
```

Returns a Driver for the given SwitchConfig by vendor lookup. Returns `ErrDriverNotFound` if vendor is not registered.

## Manager Interface

The `Manager` interface orchestrates fabric-wide operations across all switches.

```go
type Manager interface {
    // ApplyFabric converges the entire fabric to the desired state
    // Creates all VLANs, VNIs, and LAGs on every switch
    ApplyFabric(ctx context.Context) error

    // ProvisionPort places a port onto the provisioning VLAN segment
    ProvisionPort(ctx context.Context, port PortRef, segment string) error

    // ActivatePort moves a port from provisioning to a production segment
    ActivatePort(ctx context.Context, port PortRef, segment string) error

    // QuarantinePort moves a port to the quarantine segment
    QuarantinePort(ctx context.Context, port PortRef, segment string) error

    // SegmentByName returns the resolved Segment for the given name
    SegmentByName(name string) (*Segment, error)

    // SwitchStatus returns the health status of a switch
    SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error)

    // Close releases all driver connections
    Close() error
}
```

### NewManager Function

Create a Manager from configuration:

```go
func NewManager(config *FabricConfig, logger *slog.Logger) (Manager, error)
```

Validates the configuration, resolves all segments, instantiates drivers for each switch, and returns a Manager. Returns errors if:
- Config is invalid
- A driver cannot be loaded for a vendor
- A driver fails to connect

### NewManagerWithDrivers Function

Create a Manager with pre-built drivers (for testing):

```go
func NewManagerWithDrivers(config *FabricConfig, logger *slog.Logger, 
    drivers map[string]Driver) (Manager, error)
```

## Types

### FabricConfig

```go
type FabricConfig struct {
    Mode      FabricMode       // "vlan" or "evpn"
    EVPN      *EVPNConfig      // Required for EVPN mode
    Switches  []SwitchConfig   // Physical switches
    Peers     []PeerConfig     // MC-LAG relationships
    LAGs      []LAGConfig      // Link aggregation groups
    Segments  []SegmentConfig  // Network segments
}

func (c *FabricConfig) Validate() error
```

### EVPNConfig

```go
type EVPNConfig struct {
    VNIBase            uint32 // Starting VNI (VNI = VNIBase + VLAN)
    AnycastGatewayMAC  string // Distributed gateway MAC
    ARPSuppression     bool   // Enable ARP suppression
    RTBase             string // Route-target base
}
```

### SwitchConfig

```go
type SwitchConfig struct {
    ID              string
    Vendor          string
    Model           string
    MgmtIP          string
    CredentialsRef  string
    VTEPLoopback    string
    BGPASN          uint32
    SSHPort         int
    SSHUser         string
    SSHPassword     string
    SSHKeyPath      string
    KnownHostsPath  string
}

func (c *SwitchConfig) Validate() error
```

### PeerConfig

```go
type PeerConfig struct {
    SwitchA        string   // First switch ID
    SwitchB        string   // Second switch ID
    PeerLinkPorts  []string // Peer link ports
    KeepaliveDest  string   // Keepalive destination IP
}

func (c *PeerConfig) Validate(switchIDs map[string]struct{}) error
```

### LAGConfig

```go
type LAGConfig struct {
    ID            string    // Unique LAG ID
    Members       []PortRef // Member ports
    MCLAG         bool      // Multi-chassis LAG
    ESI           string    // Ethernet Segment ID
    LACPMode      string    // "active" or "passive"
    LACPRate      string    // "fast" or "normal"
    PortChannelID uint16    // Port-channel number
}

func (c *LAGConfig) Validate() error
```

### SegmentConfig

```go
type SegmentConfig struct {
    Name    string      // Unique segment name
    VLAN    uint16      // 802.1Q VLAN ID
    CIDR    string      // IP network (e.g., "10.200.0.0/24")
    Gateway string      // Gateway IP
    DNS     []string    // DNS servers
    DHCP    bool        // DHCP enabled
    Role    SegmentRole // "provisioning", "quarantine", or ""
}

func (c *SegmentConfig) Validate() error
```

### PortRef

```go
type PortRef struct {
    SwitchID string // Switch ID
    Port     string // Interface name (e.g., "Eth1/1")
    LAGID    string // Optional LAG association
}

func (p PortRef) Validate() error
```

### Segment

Resolved runtime representation of a segment with computed VNI:

```go
type Segment struct {
    Name    string      // Unique name
    VLAN    uint16      // 802.1Q VLAN ID
    VNI     uint32      // VXLAN VNI (0 in VLAN mode)
    CIDR    string      // IP network
    Gateway string      // Gateway IP
    DNS     []string    // DNS servers
    DHCP    bool        // DHCP enabled
    Role    SegmentRole // Segment role
}
```

### SwitchStatus

Health status of a switch:

```go
type SwitchStatus struct {
    ID        string // Switch ID
    Connected bool   // Connection status
    Vendor    string // Vendor name
    Model     string // Model string
    MgmtIP    string // Management IP
}
```

## Constants

### FabricMode

```go
const (
    ModeVLAN FabricMode = "vlan"   // 802.1Q VLAN mode
    ModeEVPN FabricMode = "evpn"   // VXLAN EVPN mode
)
```

### SegmentRole

```go
const (
    RoleProvisioning SegmentRole = "provisioning" // PXE/bootstrap segment
    RoleQuarantine   SegmentRole = "quarantine"   // Isolation segment
    RoleNone         SegmentRole = ""             // Production segment
)
```

## Error Types

All error types are defined in `errors.go` and follow the pattern `Err{Name}`:

### Configuration Errors

- `ErrNilConfig`: Nil configuration provided
- `ErrInvalidFabricConfig`: Configuration validation failed
- `ErrInvalidPortRef`: Invalid port reference
- `ErrDuplicateVLAN`: VLAN ID used by multiple segments
- `ErrUnknownSwitch`: Referenced switch does not exist

### Runtime Errors

- `ErrDriverNotFound`: Vendor driver not registered
- `ErrDriverConnect`: Failed to connect to switch
- `ErrSegmentNotFound`: Segment name does not exist
- `ErrPortConfiguration`: Port configuration failed
- `ErrVLANConfiguration`: VLAN configuration failed

## Usage Patterns

### Initialize Fabric Manager

```go
config := &fabric.FabricConfig{
    Mode: fabric.ModeVLAN,
    Switches: []fabric.SwitchConfig{
        {
            ID:       "core-01",
            Vendor:   "cisco-nexus",
            MgmtIP:   "10.0.1.50",
            SSHUser:  "admin",
            SSHPassword: "kms://cred-ref",
        },
    },
    Segments: []fabric.SegmentConfig{
        {
            Name: "prod",
            VLAN: 200,
            CIDR: "10.201.0.0/24",
        },
    },
}

mgr, err := fabric.NewManager(config, logger)
if err != nil {
    return err
}
defer mgr.Close()
```

### Apply Fabric Configuration

```go
// Create all VLANs, LAGs, VNIs on all switches
if err := mgr.ApplyFabric(ctx); err != nil {
    return err
}
```

### Port Lifecycle

```go
port := fabric.PortRef{SwitchID: "core-01", Port: "Eth1/3"}

// Provision: move to provisioning segment
if err := mgr.ProvisionPort(ctx, port, "provisioning"); err != nil {
    return err
}

// Activate: move to production segment
if err := mgr.ActivatePort(ctx, port, "prod"); err != nil {
    return err
}

// Quarantine: move to quarantine segment
if err := mgr.QuarantinePort(ctx, port, "quarantine"); err != nil {
    return err
}
```

### Query Segment and Switch Status

```go
seg, err := mgr.SegmentByName("prod")
if err != nil {
    return err
}
fmt.Printf("Segment %s: VLAN=%d, VNI=%d\n", seg.Name, seg.VLAN, seg.VNI)

status, err := mgr.SwitchStatus(ctx, "core-01")
if err != nil {
    return err
}
fmt.Printf("Switch connected: %v\n", status.Connected)
```

## See Also

- [Configuration Reference](./configuration.md)
- [README](./README.md)
- [Adding Drivers](./adding-drivers.md)

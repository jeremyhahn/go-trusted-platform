# Fabric API Reference

Package `github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric`. A Go library: there is no network
API for the fabric manager (see [README](README.md#status)).

## Manager

```go
type Manager interface {
    ApplyFabric(ctx context.Context) error
    ProvisionPort(ctx context.Context, port PortRef) error
    ActivatePort(ctx context.Context, port PortRef, class zone.PortClass) error
    QuarantinePort(ctx context.Context, port PortRef) error
    DisablePort(ctx context.Context, port PortRef) error
    SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error)
    Close() error
}

func NewManager(config *FabricConfig, plan *netplan.Plan, logger *slog.Logger) (Manager, error)
func NewManagerWithDrivers(config *FabricConfig, plan *netplan.Plan, logger *slog.Logger,
    drivers map[string]Driver) (Manager, error)
```

`NewManager` validates the configuration, refuses a nil plan (`ErrNilPlan`) and creates a driver per
switch from the registered vendor factories. `NewManagerWithDrivers` takes caller-supplied drivers
keyed by switch ID.

| Method | Does |
|--------|------|
| `ApplyFabric` | Connects every driver; `EnsureVLAN` for every plan zone (name = zone) on every switch; `EnsureLAG`; the `peer-link` class on every peer-link port; each assigned port's class |
| `ProvisionPort` | `SetPortTrunk([provisioning], native provisioning, 9216)` on the port and its MC-LAG peers |
| `ActivatePort` | The class plan: `SetPortAccess` for `bmc`, `SetPortTrunk` otherwise |
| `QuarantinePort` | `SetPortTrunk([quarantine], native quarantine, 9216)` |
| `DisablePort` | `DisablePort` on the port and its peers |

## Driver

```go
type Driver interface {
    Connect(ctx context.Context) error
    Close() error
    Ping(ctx context.Context) error
    EnsureVLAN(ctx context.Context, vlan uint16, name string) error
    EnsureLAG(ctx context.Context, lag LAGConfig) error
    SetPortAccess(ctx context.Context, port PortRef, vlan uint16, mtu int) error
    SetPortTrunk(ctx context.Context, port PortRef, allowed []uint16, native uint16, mtu int) error
    DisablePort(ctx context.Context, port PortRef) error
}

type DriverFactory func(cfg SwitchConfig, logger *slog.Logger) (Driver, error)
func RegisterDriver(vendor string, factory DriverFactory)
func DriverFor(cfg SwitchConfig, logger *slog.Logger) (Driver, error)
```

An `mtu` of 0 leaves the port MTU as it is; a `native` of 0 means no native VLAN. Every method must be
idempotent. The Cisco Nexus driver (`pkg/sdn/fabric/nexus`, vendor `cisco-nexus`) reads the port's
running configuration first and leaves a converged port untouched.

## Types

| Type | Fields |
|------|--------|
| `FabricConfig` | `Switches`, `Peers`, `LAGs`, `Ports` |
| `PortAssignment` | `PortRef` (inline), `Class zone.PortClass`, `Description` |
| `PortRef` | `SwitchID`, `Port`, `LAGID` |
| `SwitchConfig` | `ID`, `Vendor`, `Model`, `MgmtIP`, `CredentialsRef`, SSH fields |
| `PeerConfig` | `SwitchA`, `SwitchB`, `PeerLinkPorts`, `KeepaliveDest` |
| `LAGConfig` | `ID`, `Members`, `MCLAG`, `ESI`, `LACPMode`, `LACPRate`, `PortChannelID` |
| `SwitchStatus` | `ID`, `Connected`, `Vendor`, `Model`, `MgmtIP` |

## Errors

| Error | When |
|-------|------|
| `ErrNilConfig`, `ErrInvalidFabricConfig`, `ErrInvalidPortRef` | Malformed configuration or port reference |
| `ErrUnknownSwitch` | A switch ID with no declaration or driver |
| `ErrUnknownPortClass`, `ErrDuplicatePort` | Bad port assignment |
| `ErrNilPlan` | Manager built without a plan |
| `ErrPortClassPlan` | The plan cannot realise a class (unknown class, or no zone in it); wraps the netplan error |
| `ErrDriverNotFound`, `ErrDriverConnect` | No factory for a vendor; connect failure |
| `ErrDriverOperation` | A driver call failed; names the switch and operation, wraps the cause |

## Usage

```go
plan := sdnCfg.Plan()           // after sdn.Config.Validate
mgr, err := fabric.NewManager(sdnCfg.Fabric, plan, logger)
if err != nil { … }
defer mgr.Close()

if err := mgr.ApplyFabric(ctx); err != nil { … }

port := fabric.PortRef{SwitchID: "sw-01", Port: "Ethernet1/26"}
_ = mgr.ProvisionPort(ctx, port)                           // enrollment
_ = mgr.ActivatePort(ctx, port, zone.PortClassHypervisor)  // attested
_ = mgr.QuarantinePort(ctx, port)                          // compliance failure
_ = mgr.DisablePort(ctx, port)                             // severe violation
```

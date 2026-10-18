# Adding Switch Vendor Drivers

> **Status: REFERENCE** · Last verified: 2026-10-15
> How to write a switch vendor driver for `pkg/sdn/fabric`.

This guide explains how to implement a new fabric driver for a switch vendor (e.g., Arista EOS, Juniper).

## Overview

Each vendor driver is a separate package in `pkg/sdn/fabric/{vendor}/` that implements the `Driver` interface and registers itself at init time.

## Architecture

```
pkg/sdn/fabric/
├── config.go              # FabricConfig and its validation
├── driver.go              # Driver interface and registry
├── types.go               # Shared types
├── manager.go             # Manager implementation
├── errors.go              # Shared error types
├── nexus/
│   ├── driver.go          # Cisco Nexus implementation
│   ├── parser.go          # Output parsing
│   ├── commands.go        # CLI command templates
│   └── errors.go          # Nexus-specific errors
└── arista/                # (Your new vendor)
    ├── driver.go          # Implementation
    ├── parser.go          # Output parsing
    ├── commands.go        # CLI templates
    └── errors.go          # Vendor-specific errors
```

## Step 1: Create the Driver Package

Create `pkg/sdn/fabric/{vendor}/driver.go`:

```go
package vendor

import (
    "context"
    "log/slog"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

// driver implements the fabric.Driver interface for {Vendor}.
type driver struct {
    config fabric.SwitchConfig
    logger *slog.Logger
    // Add vendor-specific fields (SSH client, API client, etc.)
}

// NewDriver creates a driver for {Vendor}.
func NewDriver(cfg fabric.SwitchConfig, logger *slog.Logger) (fabric.Driver, error) {
    if logger == nil {
        logger = slog.New(slog.DiscardHandler)
    }
    return &driver{
        config: cfg,
        logger: logger,
    }, nil
}

func (d *driver) Connect(ctx context.Context) error {
    // Establish connection to the switch
    d.logger.Info("connecting to switch", "mgmt_ip", d.config.MgmtIP)
    return nil
}

func (d *driver) Close() error {
    // Release connection
    return nil
}

func (d *driver) Ping(ctx context.Context) error {
    // Verify connection is alive
    return nil
}

func (d *driver) EnsureVLAN(ctx context.Context, vlan uint16, name string) error {
    // Create VLAN if it doesn't exist
    d.logger.Debug("ensuring VLAN", "vlan", vlan, "name", name)
    return nil
}

func (d *driver) EnsureLAG(ctx context.Context, lag fabric.LAGConfig) error {
    // Configure link aggregation group
    d.logger.Debug("ensuring LAG", "lag_id", lag.ID, "port_channel", lag.PortChannelID)
    return nil
}

func (d *driver) SetPortAccess(ctx context.Context, port fabric.PortRef, vlan uint16, mtu int) error {
    // Access mode on vlan; set the MTU when mtu > 0; bring the port up.
    // Leave a port already in that state untouched.
    d.logger.Debug("setting port access",
        "switch", port.SwitchID, "port", port.Port, "vlan", vlan, "mtu", mtu)
    return nil
}

func (d *driver) SetPortTrunk(ctx context.Context, port fabric.PortRef,
    allowed []uint16, native uint16, mtu int) error {
    // Trunk carrying exactly allowed; native VLAN (0 clears it); MTU when
    // mtu > 0; bring the port up. Leave a converged port untouched.
    d.logger.Debug("setting port trunk",
        "switch", port.SwitchID, "port", port.Port, "allowed", allowed, "native", native, "mtu", mtu)
    return nil
}

func (d *driver) DisablePort(ctx context.Context, port fabric.PortRef) error {
    // Administratively shut the port down.
    d.logger.Debug("disabling port", "switch", port.SwitchID, "port", port.Port)
    return nil
}
```

## Step 2: Register the Driver

Add an `init()` function that registers the driver:

```go
func init() {
    fabric.RegisterDriver("vendor-name", NewDriver)
}
```

Now the driver can be used in configuration:

```yaml
fabric:
  switches:
    - id: switch-01
      vendor: vendor-name      # Matches RegisterDriver() name
      mgmt-ip: 192.0.2.10
```

## Step 3: Implement SSH or API Access

Most drivers use SSH CLI commands. Create `commands.go`:

```go
package vendor

// CLICommand represents a single switch CLI command and expected output patterns
type CLICommand struct {
    Command string   // CLI command to execute
    Expect  []string // Expected output patterns (regex)
}

// VLANCommands returns CLI commands to create a VLAN
func VLANCommands(vlan uint16, name string) []CLICommand {
    return []CLICommand{
        {
            Command: "configure terminal",
            Expect:  []string{".*config.*"},
        },
        {
            Command: "vlan " + strconv.Itoa(int(vlan)),
            Expect:  []string{".*vlan.*config.*"},
        },
        {
            Command: "name " + name,
            Expect:  []string{".*"},
        },
        {
            Command: "end",
            Expect:  []string{".*#"},
        },
    }
}

// PortAccessCommands returns CLI commands to set a port to access mode
func PortAccessCommands(port string, vlan uint16) []CLICommand {
    return []CLICommand{
        {
            Command: "configure terminal",
            Expect:  []string{".*config.*"},
        },
        {
            Command: "interface " + port,
            Expect:  []string{".*interface.*config.*"},
        },
        {
            Command: "switchport mode access",
            Expect:  []string{".*"},
        },
        {
            Command: "switchport access vlan " + strconv.Itoa(int(vlan)),
            Expect:  []string{".*"},
        },
        {
            Command: "end",
            Expect:  []string{".*#"},
        },
    }
}
```

## Step 4: Implement Output Parsing

Create `parser.go` to parse switch CLI output:

```go
package vendor

import (
    "regexp"
    "strconv"
    "strings"
)

// ParseVLANList parses "show vlan" output to extract VLAN IDs
func ParseVLANList(output string) ([]uint16, error) {
    var vlans []uint16
    
    // Example regex: extract VLAN IDs from output
    re := regexp.MustCompile(`^\s*(\d+)\s+.*$`)
    
    for _, line := range strings.Split(output, "\n") {
        matches := re.FindStringSubmatch(line)
        if matches == nil {
            continue
        }
        vlan, err := strconv.ParseUint(matches[1], 10, 16)
        if err != nil {
            continue
        }
        vlans = append(vlans, uint16(vlan))
    }
    
    return vlans, nil
}

// ParsePortInfo extracts port status, VLAN membership
func ParsePortInfo(output string) (PortInfo, error) {
    // Parse output to extract:
    // - Current VLAN
    // - Port mode (access/trunk)
    // - Link status
    // - Description
    return PortInfo{}, nil
}
```

## Step 5: Define Vendor-Specific Errors

Create `errors.go` for vendor-specific error types:

```go
package vendor

import "fmt"

// ErrVendorSpecific is a base error for vendor-specific issues
type ErrVendorSpecific struct {
    Message string
}

func (e ErrVendorSpecific) Error() string {
    return fmt.Sprintf("vendor error: %s", e.Message)
}

// ErrSSHConnection is returned when SSH connection fails
type ErrSSHConnection struct {
    Host string
    Err  error
}

func (e ErrSSHConnection) Error() string {
    return fmt.Sprintf("ssh connection failed to %s: %v", e.Host, e.Err)
}
```

## Step 6: Add Tests

Create `driver_test.go`:

```go
package vendor

import (
    "context"
    "log/slog"
    "testing"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

func TestNewDriver(t *testing.T) {
    cfg := fabric.SwitchConfig{
        ID:     "test-switch",
        Vendor: "vendor-name",
        MgmtIP: "192.0.2.10",
    }
    
    drv, err := NewDriver(cfg, slog.Default())
    if err != nil {
        t.Fatalf("NewDriver failed: %v", err)
    }
    if drv == nil {
        t.Fatal("expected driver, got nil")
    }
}

func TestEnsureVLAN(t *testing.T) {
    cfg := fabric.SwitchConfig{
        ID:     "test-switch",
        Vendor: "vendor-name",
        MgmtIP: "192.0.2.10",
    }
    
    drv, _ := NewDriver(cfg, slog.Default())
    ctx := context.Background()
    
    // Test creating a VLAN
    err := drv.EnsureVLAN(ctx, 100, "test-vlan")
    if err != nil {
        t.Fatalf("EnsureVLAN failed: %v", err)
    }
    
    // Test idempotency: calling again should be a no-op
    err = drv.EnsureVLAN(ctx, 100, "test-vlan")
    if err != nil {
        t.Fatalf("EnsureVLAN (idempotent) failed: %v", err)
    }
}

func TestSetPortAccess(t *testing.T) {
    cfg := fabric.SwitchConfig{
        ID:     "test-switch",
        Vendor: "vendor-name",
        MgmtIP: "192.0.2.10",
    }
    
    drv, _ := NewDriver(cfg, slog.Default())
    ctx := context.Background()
    
    port := fabric.PortRef{SwitchID: "test-switch", Port: "Eth1/1"}
    err := drv.SetPortAccess(ctx, port, 402, 9216)
    if err != nil {
        t.Fatalf("SetPortAccess failed: %v", err)
    }
}
```

## Step 7: Register the Driver in the Main Module

The `init()` from Step 2 runs only when some binary imports the package. The Nexus driver registers
itself in `pkg/sdn/fabric/nexus/driver.go`:

```go
// pkg/sdn/fabric/nexus/driver.go
package nexus

import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

func init() {
    fabric.RegisterDriver(vendorName, NewDriver) // vendorName = "cisco-nexus"
}
```

For your new vendor:

```go
// In pkg/sdn/fabric/{vendor}/driver.go
package vendor

import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

func init() {
    fabric.RegisterDriver("vendor-name", NewDriver)
}
```

Import the package from the binary that builds the fabric manager. No binary does today, Nexus
included (see [README](README.md#status)):

```go
import (
    _ "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric/nexus"
    _ "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric/vendor"  // Your new vendor
)
```

## Reference Implementation: Cisco Nexus

See `pkg/sdn/fabric/nexus/` for a complete reference implementation with:

- SSH through an enclave-backed private key and a pinned host key (no trust-on-first-use)
- An `Executor` seam (`Execute`, `ExecuteBatch`) that tests replace via `NewDriverWithExecutor`
- NX-OS CLI command templates (`commands.go`)
- Output parsing of `show running-config interface` so a converged port is left untouched

## Testing Your Driver

```bash
# Run driver-specific tests
go test ./pkg/sdn/fabric/{vendor}/... -v

# Run all fabric tests
go test ./pkg/sdn/fabric/... -v
```

## Adding Driver to Documentation

Add the vendor name to the `vendor` row in [configuration.md](configuration.md#switches) and
document any vendor-specific fields there.

## Next Steps

1. Implement Connect/Close for your transport (SSH, API client, etc.)
2. Implement each Driver method
3. Add comprehensive tests
4. Document any vendor-specific configuration requirements
5. Submit for review and integration

## Common Patterns

### Idempotency

All operations must be idempotent:

```go
func (d *driver) EnsureVLAN(ctx context.Context, vlan uint16, name string) error {
    // Check if VLAN already exists
    exists, err := d.vlanExists(ctx, vlan)
    if err != nil {
        return err
    }
    
    // If exists, it's a no-op
    if exists {
        return nil
    }
    
    // Create VLAN
    return d.createVLAN(ctx, vlan, name)
}
```

### Error Handling

Return the driver's own typed errors. The manager wraps every driver operation failure in
`fabric.ErrDriverOperation` (switch ID, operation, cause) and a `Connect` failure in
`fabric.ErrDriverConnect`, so the driver does not wrap again:

```go
if err := d.executeCommand(ctx, cmd); err != nil {
    return ErrSSHConnection{Host: d.config.MgmtIP, Err: err}
}
```

### Logging

Use structured logging:

```go
d.logger.Debug("executing command",
    "switch", d.config.ID,
    "command", cmd,
    "vlan", vlan)
```

## See Also

- [Fabric README](./README.md)
- [Configuration Reference](./configuration.md)
- [API Reference](./api-reference.md)

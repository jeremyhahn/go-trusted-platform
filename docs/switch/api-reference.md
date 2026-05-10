# Switch Management API Reference

The switch management feature exposes runtime port operations through the Device REST API. The implementation is designed as a library that can be exposed through multiple protocol layers (REST, gRPC, QUIC, CLI).

## Current Implementation Status

- **REST API**: Integrated in Device activation handler (`POST /device/activate`)
- **gRPC**: Service definition available, handlers not yet exposed
- **QUIC**: Protocol support available, handlers not yet exposed
- **CLI**: Commands not yet exposed through `platformctl`
- **Unix Socket**: gRPC over UDS available

## REST API (Device Activation)

### POST /device/activate

Transitions a device to production network. Automatically moves physical switch port from provisioning VLAN to production VLAN if configured.

**Authentication:** mTLS certificate (device serial in CN)

**Request:**
```json
{}  // Empty body, all info from mTLS context
```

**Response (200 OK):**
```json
{
  "status": "activated",
  "vlan": 200,
  "transitionedAt": "2025-04-13T10:30:45Z"
}
```

**Response (400 Bad Request):**
```json
{
  "error": "missing device serial number"
}
```

**Response (404 Not Found):**
```json
{
  "error": "device profile not found"
}
```

**Response (500 Internal Server Error):**
```json
{
  "error": "switch vlan transition failed: switch connection failed to 10.0.1.50: network error"
}
```

**VLAN Transition Details:**

When a device calls this endpoint:
1. Platform extracts device serial from mTLS certificate
2. Platform looks up device profile (includes SwitchName, SwitchPort, ProductionVLAN)
3. If SwitchName and SwitchPort are configured:
   - Platform gets Manager by switch name
   - Calls `mgr.SetPortVLAN(ctx, SwitchPort, ProductionVLAN)`
   - Waits for completion before continuing
4. If switch information is missing:
   - VLAN transition is skipped (no-op)
   - Device activation proceeds normally
5. Platform applies SDN policy (VLAN + ACLs)
6. Returns activation response

**Example Flow:**
```
Device calls:   POST /device/activate
Platform:       1. Extract serial from cert: "device-001"
                2. Look up profile: SwitchName="core-switch-01", 
                                   SwitchPort="Eth1/3", 
                                   ProductionVLAN=200
                3. Get Manager("core-switch-01")
                4. mgr.SetPortVLAN(ctx, "Eth1/3", 200)
                5. SSH: "configure terminal"
                6. SSH: "interface Eth1/3"
                7. SSH: "switchport mode access"
                8. SSH: "switchport access vlan 200"
                9. SSH: "end"
                10. Apply policy, return 200 OK
```

## Manager Interface (Go API)

The Switch Management Service implements this interface for runtime operations:

### Service Layer

```go
// github.com/jeremyhahn/go-trusted-platform/pkg/switch

type Service struct {
    // Unexported: managers map[string]Manager
}

// NewService creates a Service with one Manager per Config
func NewService(configs []switchmgmt.Config, logger *slog.Logger) (*Service, error)

// Manager returns the Manager for the named switch
func (s *Service) Manager(name string) (Manager, error)

// Close closes all underlying Manager connections
func (s *Service) Close() error
```

### Manager Interface

```go
type Manager interface {
    // SetPortVLAN moves a single access-mode port to the specified VLAN
    SetPortVLAN(ctx context.Context, port string, vlanID uint16) error

    // GetPortVLAN returns the currently active access VLAN on a port
    GetPortVLAN(ctx context.Context, port string) (uint16, error)

    // GetPortStatus returns the full observable state of a port
    GetPortStatus(ctx context.Context, port string) (*PortStatus, error)

    // ListPorts returns the status of all physical ports on the switch
    ListPorts(ctx context.Context) ([]*PortStatus, error)

    // EnablePort administratively enables a port
    EnablePort(ctx context.Context, port string) error

    // DisablePort administratively shuts down a port
    DisablePort(ctx context.Context, port string) error

    // Close releases any underlying connections
    Close() error
}
```

### Data Types

```go
// PortStatus represents the observable state of a single switch port
type PortStatus struct {
    Port        string   // Port identifier (e.g., "Eth1/3")
    Mode        PortMode // "access" or "trunk"
    AccessVLAN  uint16   // VLAN ID if in access mode
    TrunkVLANs  []uint16 // Allowed VLAN IDs if in trunk mode
    Enabled     bool     // Administratively enabled
    LinkUp      bool     // Physical link is up
    Description string   // Optional port description
}

type PortMode string

const (
    PortModeAccess PortMode = "access"
    PortModeTrunk  PortMode = "trunk"
)
```

## Error Responses

All errors are typed for precise handling:

### Connection Errors

```go
// ErrSSHConnectionFailed occurs when SSH connection to switch fails
type ErrSSHConnectionFailed struct {
    Host  string  // Switch IP/hostname
    Cause error   // Underlying error (network, auth, etc.)
}

// ErrSwitchConnectionFailed is a synonym for ErrSSHConnectionFailed
type ErrSwitchConnectionFailed struct {
    Host  string
    Cause error
}
```

**Example:**
```
switchmgmt: ssh connection failed to 10.0.1.50: network error
switchmgmt: switch connection failed to 10.0.1.50: authentication failed
```

### VLAN/Port Errors

```go
// ErrPortVLANSetFailed when setting a port's VLAN fails
type ErrPortVLANSetFailed struct {
    Port   string  // Port identifier
    VLANID uint16  // Target VLAN
    Cause  error   // Underlying error
}

// ErrPortNotFound when requested port doesn't exist
type ErrPortNotFound struct {
    Port string
}

// ErrVLANNotFound when requested VLAN doesn't exist
type ErrVLANNotFound struct {
    VLANID uint16
}
```

**Example:**
```
switchmgmt: failed to set port Eth1/3 to vlan 200: command failed "switchport access vlan 200"
switchmgmt: port Eth1/99 not found
switchmgmt: vlan 5000 not found
```

### Command Execution Errors

```go
// ErrSSHCommandFailed when a CLI command fails
type ErrSSHCommandFailed struct {
    Command string  // CLI command that failed
    Output  string  // Switch output
    Cause   error   // Underlying error
}

// ErrSSHParseOutputFailed when parsing command output fails
type ErrSSHParseOutputFailed struct {
    Command string  // CLI command
    Output  string  // Switch output
    Reason  string  // Parse failure reason
}
```

**Example:**
```
switchmgmt: ssh command failed "switchport access vlan 200" (output: % Invalid VLAN): vlan not found
switchmgmt: failed to parse output for "show interfaces status": header line not found
```

### Configuration Errors

```go
// ErrInvalidConfig when switch configuration is invalid
type ErrInvalidConfig struct {
    Field  string  // Configuration field name
    Reason string  // Why it's invalid
}

// ErrInvalidPortRange when port range is malformed
type ErrInvalidPortRange struct {
    Port   string  // Port specification
    Reason string  // Parse failure reason
}

// ErrNilConfig when nil configuration provided
type ErrNilConfig struct {}

// ErrUnsupportedVendor when vendor is not recognized
type ErrUnsupportedVendor struct {
    Vendor SwitchVendor  // Vendor string
}
```

**Example:**
```
switchmgmt: invalid config: field host: must not be empty
switchmgmt: invalid port range "Eth1/1-1-5": invalid format
switchmgmt: unsupported vendor: juniper-junos
```

### Service Layer Errors

```go
// ErrManagerNotFound when Manager for switch name not found
type ErrManagerNotFound struct {
    Name string  // Switch name
}
```

**Example:**
```
switchmgmt: manager not found for switch "unknown-switch"
```

## Go Usage Examples

### Basic Usage

```go
package main

import (
    "context"
    "log/slog"
    switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
)

func main() {
    config := []switchmgmt.Config{
        {
            Name:   "core-switch",
            Vendor: switchmgmt.VendorCiscoNexus,
            Host:   "10.0.1.50",
            User:   "admin",
            SSHKey: "/etc/certs/switch.key",
        },
    }

    logger := slog.Default()
    service, err := switchmgmt.NewService(config, logger)
    if err != nil {
        panic(err)
    }
    defer service.Close()

    // Get manager for a switch
    mgr, err := service.Manager("core-switch")
    if err != nil {
        panic(err)
    }

    // Move port to VLAN 200
    ctx := context.Background()
    if err := mgr.SetPortVLAN(ctx, "Eth1/3", 200); err != nil {
        panic(err)
    }

    // Check current VLAN
    vlan, err := mgr.GetPortVLAN(ctx, "Eth1/3")
    if err != nil {
        panic(err)
    }
    println("Port is on VLAN", vlan)

    // Get full port status
    status, err := mgr.GetPortStatus(ctx, "Eth1/3")
    if err != nil {
        panic(err)
    }
    println("Port enabled:", status.Enabled)
    println("Port link up:", status.LinkUp)

    // List all ports
    ports, err := mgr.ListPorts(ctx)
    if err != nil {
        panic(err)
    }
    println("Total ports:", len(ports))

    // Enable/disable port
    if err := mgr.DisablePort(ctx, "Eth1/4"); err != nil {
        panic(err)
    }
    if err := mgr.EnablePort(ctx, "Eth1/4"); err != nil {
        panic(err)
    }
}
```

### Error Handling

```go
import "errors"

// Type assertions for specific errors
if err := mgr.SetPortVLAN(ctx, port, vlan); err != nil {
    var portNotFound switchmgmt.ErrPortNotFound
    if errors.As(err, &portNotFound) {
        // Handle missing port
        log.Printf("Port %s does not exist", portNotFound.Port)
    }

    var vlanNotFound switchmgmt.ErrVLANNotFound
    if errors.As(err, &vlanNotFound) {
        // Handle missing VLAN
        log.Printf("VLAN %d does not exist", vlanNotFound.VLANID)
    }

    var setFailed switchmgmt.ErrPortVLANSetFailed
    if errors.As(err, &setFailed) {
        // Handle general failure
        log.Printf("Failed to set port %s to VLAN %d: %v",
            setFailed.Port, setFailed.VLANID, setFailed.Cause)
    }
}
```

### Dependency Injection Pattern (REST Handler)

```go
// Handler receives a SwitchServiceProvider interface
type SwitchServiceProvider interface {
    Manager(name string) (switchmgmt.Manager, error)
}

func NewDeviceHandler(switchService SwitchServiceProvider) http.Handler {
    return &deviceHandler{switchService: switchService}
}

func (h *deviceHandler) handleActivate(w http.ResponseWriter, r *http.Request) {
    // Get manager by switch name (from device profile)
    mgr, err := h.switchService.Manager("core-switch")
    if err != nil {
        http.Error(w, "switch not configured", http.StatusInternalServerError)
        return
    }

    // Move port
    if err := mgr.SetPortVLAN(r.Context(), "Eth1/3", 200); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}
```

## Planned API Expansions

The following protocols are planned for future release:

### gRPC Service (Planned)

```protobuf
service SwitchManager {
    rpc SetPortVLAN(SetPortVLANRequest) returns (SetPortVLANResponse);
    rpc GetPortVLAN(GetPortVLANRequest) returns (GetPortVLANResponse);
    rpc GetPortStatus(GetPortStatusRequest) returns (GetPortStatusResponse);
    rpc ListPorts(ListPortsRequest) returns (ListPortsResponse);
    rpc EnablePort(EnablePortRequest) returns (EnablePortResponse);
    rpc DisablePort(DisablePortRequest) returns (DisablePortResponse);
}
```

### CLI Commands (Planned)

```bash
# List all ports on a switch
platformctl switch list-ports --switch core-switch-01

# Get port status
platformctl switch port-status --switch core-switch-01 --port Eth1/3

# Set port VLAN
platformctl switch set-vlan --switch core-switch-01 --port Eth1/3 --vlan 200

# Enable/disable port
platformctl switch enable-port --switch core-switch-01 --port Eth1/3
platformctl switch disable-port --switch core-switch-01 --port Eth1/3
```

## Backwards Compatibility

- Manager interface is stable and exported
- Error types will not change incompatibly
- New Manager methods will require interface change (breaking)
- New error types can be added without breaking existing code

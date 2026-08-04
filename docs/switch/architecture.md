# Switch Management Architecture

## Package Organization

```
pkg/switch/
├── types.go                 # Public interfaces and types
├── service.go               # Service layer (named Manager registry)
├── manager_factory.go       # ManagerFactory and vendor dispatch
├── ssh_manager.go           # SSH-based Manager implementation
├── noop_manager.go          # No-op Manager for testing
├── ssh.go                   # SSH connection and execution
├── cisco_nexus.go           # Cisco NX-OS Configurator (setup only)
├── errors.go                # Typed errors
└── *_test.go                # Comprehensive test coverage
```

The package has no external dependencies beyond Go stdlib and standard project libs (logging, slog).

## Core Concepts

### Manager Interface

The `Manager` interface defines runtime operations on a single physical switch:

```go
type Manager interface {
    // Runtime port operations
    SetPortVLAN(ctx context.Context, port string, vlanID uint16) error
    GetPortVLAN(ctx context.Context, port string) (uint16, error)
    GetPortStatus(ctx context.Context, port string) (*PortStatus, error)
    ListPorts(ctx context.Context) ([]*PortStatus, error)
    EnablePort(ctx context.Context, port string) error
    DisablePort(ctx context.Context, port string) error
    Close() error
}
```

**Implemented by:**
- `sshManager`: SSH-based CLI execution (production)
- `noopManager`: No-op stub (testing)

### Service Layer

The `Service` wraps Manager instances in a named registry:

```go
type Service struct {
    managers map[string]Manager  // keyed by switch name
    logger   *slog.Logger
}

// NewService(configs []Config) creates one Manager per Config
// Manager(name string) returns Manager by switch name
// Close() closes all Managers
```

**Purpose:**
- Dependency injection for handlers (avoids exposing ManagerFactory)
- Clean separation between public API and internal implementation
- Reference counting for cleanup (single Close() for all managers)

### ManagerFactory

Vendors register their Manager factory:

```go
type ManagerFactory func(config *Config, logger *slog.Logger) (Manager, error)

var managerRegistry = map[SwitchVendor]ManagerFactory{
    VendorCiscoNexus: newSSHManager,
    VendorNoop:       newNoopManagerFactory,
}
```

**Dispatch:**
- Config.Vendor determines factory
- Returns ErrUnsupportedVendor if vendor not found
- Returns nil Manager if config is nil (convenience for optional switches)

### SSH Manager

The SSH Manager uses CLI commands compatible with Cisco IOS, IOS-XE, NX-OS, and similar:

```go
// Lazy SSH connection (created on first use)
sshManager.ensureConnected() {
    if m.executor != nil { return nil }  // Already connected
    m.executor = NewSSHExecutor(m.config)
    return nil
}

// SetPortVLAN wraps commands with "configure terminal" / "end"
buildConfigCommands(
    "configure terminal",
    "interface Eth1/3",
    "switchport mode access",
    "switchport access vlan 200",
    "end",
)
```

**Connection lifecycle:**
- Created on demand (first Manager method call)
- Reused for subsequent calls
- Closed via Manager.Close()
- SSH connection handles auth (key or password)

### Configuration Types

```go
type Config struct {
    Name     string            // Switch identifier (key in Service registry)
    Vendor   SwitchVendor      // "cisco-nexus" | "noop"
    Host     string            // IP or hostname
    Port     int               // SSH port (usually 22)
    User     string            // SSH username
    Password string            // SSH password or kms://... reference
    SSHKey   string            // Path to SSH private key
    VLANs    []VLANConfig      // VLANs to create (used during setup, not runtime)
    Ports    []PortConfig      // Port configs (used during setup, not runtime)
}

type VLANConfig struct {
    ID          int     // VLAN ID (1-4094)
    Name        string  // VLAN name
    Subnet      string  // IP subnet (informational)
    Description string  // Optional description
}

type PortConfig struct {
    Port        string  // Port identifier (e.g., "Eth1/1" or "Eth1/3-5")
    Mode        string  // "trunk" | "access"
    VLANs       []int   // For trunk: allowed VLANs
    AccessVLAN  int     // For access: VLAN ID
    Description string  // Optional description
}
```

**Note:** VLANs and Ports in Config are for initial setup. Runtime operations use individual SetPortVLAN/GetPortVLAN calls. The Service layer doesn't execute ConfigureVLANs/ConfigurePorts (no Configurator exposed).

## Data Flow

### Device Activation with Switch VLAN Transition

```
Device REST API
  POST /device/activate
       │
       ├─ Extract device serial (mTLS cert)
       │
       ├─ Get device profile (serial → profile service)
       │  ├─ Profile.ProductionNetwork.VLAN = 200
       │  └─ Profile.SwitchName = "core-switch-01"
       │  └─ Profile.SwitchPort = "Eth1/3"
       │
       ├─ transitionSwitchPort(ctx, serial, 200)
       │  ├─ Get Manager from Service by switch name
       │  ├─ mgr.SetPortVLAN(ctx, "Eth1/3", 200)
       │  │  ├─ ensureConnected() → new SSH connection
       │  │  ├─ Execute: "configure terminal"
       │  │  ├─ Execute: "interface Eth1/3"
       │  │  ├─ Execute: "switchport mode access"
       │  │  ├─ Execute: "switchport access vlan 200"
       │  │  ├─ Execute: "end"
       │  │  └─ Parse output for errors
       │  │
       │  └─ Log success / error
       │
       ├─ Apply SDN policy (VLAN + ACLs)
       │
       └─ Return ActivateResponse
            ├─ Status: "activated"
            ├─ VLAN: 200
            └─ TransitionedAt: now()
```

## Error Handling Strategy

All errors are typed for precise error handling:

```go
// SSH connection errors
type ErrSSHConnectionFailed struct { Host string; Cause error }
type ErrSwitchConnectionFailed struct { Host string; Cause error }

// VLAN/Port operation errors
type ErrPortVLANSetFailed struct { Port string; VLANID uint16; Cause error }
type ErrPortNotFound struct { Port string }
type ErrVLANNotFound struct { VLANID uint16 }

// Configuration errors
type ErrInvalidConfig struct { Field string; Reason string }
type ErrInvalidPortRange struct { Port string; Reason string }
type ErrNilConfig struct {}

// Parsing errors
type ErrSSHParseOutputFailed struct { Command string; Output string; Reason string }

// Service layer errors
type ErrManagerNotFound struct { Name string }

// Vendor errors
type ErrUnsupportedVendor struct { Vendor SwitchVendor }
```

**Handler strategy:**
```go
// Device handler wraps errors in HTTP responses
if err := mgr.SetPortVLAN(ctx, port, vlan); err != nil {
    return ErrSwitchVLANTransitionFailed{
        SwitchName: switchName,
        Port:       switchPort,
        VLAN:       vlan,
        Cause:      err,
    }
}
// Client receives HTTP 500 with error details
```

## Dependencies

### External
- `golang.org/x/crypto/ssh`: SSH client implementation
- `log/slog`: Structured logging

### Internal
- `pkg/logging`: Logger wrapper
- `pkg/app`: Configuration loading

### Reverse Dependencies (depend on switch package)
- `pkg/daemon/commands/serve.go`: Initializes switch service
- `pkg/webservice/v1/device/handler.go`: Uses SwitchServiceProvider
- `pkg/app/app.go`: Stores SwitchConfigs

## Testing Strategy

The package is fully tested with:

### Unit Tests
- `ssh_manager_test.go`: SSH operations with mocked SSHExecutor
- `noop_manager_test.go`: No-op Manager behavior
- `service_test.go`: Service registry and cleanup
- `errors_test.go`: Error formatting
- `types_test.go`: Configuration validation

### Test Utilities
- Mock SSHExecutor: Simulates switch CLI responses
- Test fixtures: Example configs and command outputs
- Golden files: Expected output format samples

### Integration Tests (when switch hardware available)
- Real SSH connections to test switches
- Full VLAN transition workflows
- Port status verification

## Extending for New Vendors

### Step 1: Create Vendor Implementation

```go
// pkg/switch/arista_eos.go
type aristaEOSManager struct {
    config   *Config
    logger   *slog.Logger
    executor SSHExecutor
}

func newAristaEOSManager(config *Config, logger *slog.Logger) (Manager, error) {
    // Validate config
    // Return &aristaEOSManager{}
}

func (m *aristaEOSManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
    // EOS-specific commands (often identical to Cisco)
    // EOS uses "ethernet 1/1" instead of "eth1/1"
}
```

### Step 2: Register Factory

```go
// pkg/switch/manager_factory.go
const (
    VendorAristaEOS SwitchVendor = "arista-eos"
)

var managerRegistry = map[SwitchVendor]ManagerFactory{
    VendorCiscoNexus: newSSHManager,
    VendorAristaEOS:  newAristaEOSManager,  // Add here
    VendorNoop:       newNoopManagerFactory,
}
```

### Step 3: Add Tests

```go
// pkg/switch/arista_eos_test.go
func TestAristaEOS_SetPortVLAN(t *testing.T) {
    // Test with mocked executor
}
```

### Step 4: Update Configuration

```yaml
switches:
  - name: arista-switch-01
    vendor: arista-eos  # New vendor option
    host: 10.0.1.51
    user: admin
    ssh_key: /etc/certs/arista.key
```

## Performance Considerations

- **Lazy SSH connection**: Connected on first use, reduces startup time
- **Connection reuse**: Each Manager instance reuses one SSH connection
- **Timeout handling**: SSH executor respects context deadlines
- **No polling**: Manager methods perform single operations (no retry loops)

## Security Considerations

- **SSH key authentication**: Preferred over passwords
- **Password encryption**: Supports `kms://` references to platform secrets
- **No credential logging**: Passwords/keys never logged (except in debug mode)
- **Command injection prevention**: Port names and VLAN IDs are validated
- **Output parsing**: Regex-based with error boundaries (no shell parsing)

## Open Design Questions

1. **Batch operations**: Should Manager support batch VLAN moves for efficiency?
   - Current: One SetPortVLAN per request (acceptable for activation workflow)
   - Alternative: SetPortVLANs(context, []PortVLAN) for multi-port updates

2. **Configurator exposure**: Should Service expose Configurator for initial setup?
   - Current: No (only Manager for runtime operations)
   - Rationale: Setup is one-time during switch provisioning, separate workflow

3. **VLAN caching**: Should Manager cache ListPorts results?
   - Current: No (always fresh from switch)
   - Rationale: Network state changes outside the platform; stale cache is dangerous

4. **Connection pooling**: Should multiple Managers on same host share SSH connection?
   - Current: No (each Manager has one connection)
   - Rationale: Simplifies state management; switch CLI is not connection-heavy

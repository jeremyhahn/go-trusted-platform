# Compute Orchestration Package

Unified compute orchestration interface for managing VMs and containers with integrated OVS networking.

## Features

- **Unified Interface**: Single API for VMs and containers
- **Lifecycle Management**: Create, start, stop, delete operations
- **State Machine**: Validated state transitions with lifecycle manager
- **OVS Integration**: Seamless network attachment via Open vSwitch
- **Resource Management**: CPU, memory, disk allocation
- **Typed Errors**: Reliable error handling with sentinel errors
- **Thread-Safe**: Concurrent operation support
- **Context Support**: Cancellation and timeout propagation

## Quick Start

```go
import (
    "context"
    "github.com/jeremyhahn/go-trusted-platform/pkg/compute"
    "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Create orchestrator
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
logger := logging.DefaultLogger()
orch, err := compute.NewQEMUOrchestrator(config, logger)
if err != nil {
    panic(err)
}
defer orch.Close()

// Create instance
profile := &entities.DeviceProfile{
    ID:   1,
    Name: "test-vm",
}

ctx := context.Background()
instance, err := orch.Create(ctx, profile)
if err != nil {
    panic(err)
}

// Start instance
err = orch.Start(ctx, instance.ID)
if err != nil {
    panic(err)
}

// Attach network
err = orch.AttachNetwork(ctx, instance.ID, "vm-port-1")
if err != nil {
    panic(err)
}

// Wait for instance
err = orch.Wait(ctx, instance.ID)
if err != nil {
    panic(err)
}
```

## Architecture

### Components

- **orchestrator.go**: Core orchestrator interface
- **qemu.go**: QEMU/KVM implementation
- **lifecycle.go**: State machine and transition management
- **config.go**: Configuration structures and validation
- **types.go**: Core types and filters
- **errors.go**: Typed error definitions

### State Transitions

```
Unknown -> Creating -> Stopped -> Starting -> Running -> Stopping -> Stopped
                                                  |
                                                  v
Any State -> Error (terminal)
Stopped -> Deleting (terminal)
```

## Configuration

### Default VM Configuration

```go
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
// WorkDir:         /var/lib/trusted-platform/compute
// DefaultMemory:   4096 MB
// DefaultCPUs:     runtime.NumCPU()
// DefaultDiskSize: 20G
// MaxInstances:    100
// EnableKVM:       true
// NetworkBridge:   br-int
```

### Custom Configuration

```go
config := &compute.OrchestratorConfig{
    Type:            compute.ComputeTypeVM,
    WorkDir:         "/custom/path",
    DefaultMemory:   8192,
    DefaultCPUs:     8,
    DefaultDiskSize: "50G",
    MaxInstances:    50,
    EnableKVM:       true,
    NetworkBridge:   "br0",
    OVSSocketPath:   "/var/run/openvswitch/db.sock",
    QEMUBinary:      "qemu-system-x86_64",
    OVMFCode:        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    OVMFVars:        "/usr/share/OVMF/OVMF_VARS_4M.fd",
}
```

## Error Handling

All errors are typed for reliable handling:

```go
instance, err := orch.Create(ctx, profile)
if err != nil {
    switch {
    case errors.Is(err, compute.ErrResourceExhausted):
        // Too many instances
    case errors.Is(err, compute.ErrInvalidProfile):
        // Invalid device profile
    case errors.Is(err, compute.ErrInvalidConfiguration):
        // Invalid configuration
    default:
        // Other error
    }
}
```

## Testing

Run unit tests:

```bash
make test-compute
```

Generate coverage report:

```bash
make coverage-compute
```

Run with verbose output:

```bash
go test -v ./pkg/compute/...
```

## Implementation Status

### Completed

- [x] Core orchestrator interface
- [x] QEMU/KVM implementation
- [x] Lifecycle state machine
- [x] Configuration management
- [x] Instance filtering
- [x] OVS network integration
- [x] Error handling
- [x] Comprehensive unit tests
- [x] Thread-safe operations
- [x] Context support

### Planned

- [ ] Container orchestrator implementation
- [ ] Resource quota enforcement
- [ ] Snapshot management
- [ ] Live migration support
- [ ] Metrics collection
- [ ] Health monitoring
- [ ] Auto-scaling
- [ ] Storage pool management

## Dependencies

- `pkg/qemu`: QEMU VM management
- `pkg/sdn/ovs`: Open vSwitch integration
- `pkg/device/entities`: Device profile entities
- `pkg/logging`: Logging infrastructure

## Documentation

See [docs/compute-orchestration.md](../../docs/compute-orchestration.md) for detailed documentation.

## License

Apache-2.0

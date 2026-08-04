# Compute Orchestrator

Virtual machine and container orchestration for the Trusted Platform.

## Status

| Component | Status | Test Coverage |
|-----------|--------|---------------|
| QEMU Orchestrator | Complete | 90%+ |
| Lifecycle Manager | Complete | 90%+ |
| swtpm Integration | Complete | 90%+ |
| 802.1X Network | Complete | 90%+ |
| OVS Integration | Complete | 90%+ |
| Container Orchestrator | Complete | 90%+ |
| Trusted Registry | Complete | 92.1% |
| **Overall** | **100% Complete** | **90%+** |

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| VM Lifecycle | Create, Start, Stop, Delete, Wait | Complete |
| Network Attachment | OVS bridge integration with TAP devices | Complete |
| vTPM Support | Automatic swtpm provisioning per VM | Complete |
| 802.1X Port Auth | Certificate-based network access control | Complete |
| UEFI Boot | OVMF firmware with Secure Boot option | Complete |
| Instance Filtering | Query instances by state, type, profile | Complete |
| Concurrent Operations | Thread-safe instance management | Complete |
| Profile-Driven Config | DeviceProfile-based VM configuration | Complete |
| **QMP Control** | Runtime VM control via go-qemu | Complete |
| **VM Snapshots** | Full VM state snapshots via QMP | Complete |
| **Live Migration** | Pre-copy memory migration via QMP | Complete |
| **Container Lifecycle** | Create, Start, Stop, Remove via Podman | Complete |
| **Event-log Attestation** | PCR 14 aggregate + measurement log | Complete |
| **OPA Policy Engine** | Builtin + custom + remote bundle policies | Complete |
| **Image Verification** | Platform CA signature verification | Complete |
| **SDN/OpenFlow Network** | Unified host/VM/container networking | Complete |
| **Systemd/RC Services** | Standalone service mode with init auto-detect | Complete |
| **Multi-protocol API** | REST, gRPC, QUIC, MCP, Unix (90%+ coverage) | Complete |
| **Trusted Registry** | Attestation-gated access, encrypted images | Complete |

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                       Compute Orchestrator                         │
│  (pkg/compute)                                                     │
│                                                                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│  │ QEMUOrchestra │  │ Lifecycle     │  │ Port Auth     │           │
│  │ -tor          │  │ Manager       │  │ (802.1X)      │           │
│  │               │  │               │  │               │           │
│  │ • Create      │  │ • State       │  │ • Provisioning│           │
│  │ • Start/Stop  │  │ • Transitions │  │ • Activation  │           │
│  │ • Delete      │  │ • Validation  │  │ • Quarantine  │           │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘           │
│          │                  │                  │                   │
└──────────┼──────────────────┼──────────────────┼───────────────────┘
           │                  │                  │
   ┌───────▼───────┐  ┌───────▼───────┐  ┌───────▼───────┐
   │   QEMU/KVM    │  │    swtpm      │  │   SDN Policy  │
   │               │  │               │  │   Engine      │
   │  • VM Process │  │  • vTPM 2.0   │  │  • VLAN Mgmt  │
   │  • virtio-net │  │  • State Dir  │  │  • Flow Rules │
   └───────────────┘  └───────────────┘  └───────────────┘
```

## Quick Start

### Create Orchestrator

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/compute"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Use defaults
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)

// Or customize
config := &compute.OrchestratorConfig{
    Type:            compute.ComputeTypeVM,
    WorkDir:         "/var/lib/trusted-platform/compute",
    DefaultMemory:   4096,
    DefaultCPUs:     4,
    DefaultDiskSize: "20G",
    MaxInstances:    100,
    EnableKVM:       true,
    NetworkBridge:   "trusted0",
    OVSSocketPath:   "/var/run/openvswitch/db.sock",
    QEMUBinary:      "qemu-system-x86_64",
    OVMFCode:        "/usr/share/OVMF/OVMF_CODE_4M.fd",
}

logger := logging.DefaultLogger()
orchestrator, err := compute.NewQEMUOrchestrator(config, logger)
if err != nil {
    return err
}
defer orchestrator.Close()
```

### Create and Start VM

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"

// Create device profile
profile := &entities.DeviceProfile{
    Name:  "web-server-001",
    Model: "Standard VM",
    Role:  entities.DeviceRoleServer,
    ProvisioningNetwork: &entities.NetworkPhaseConfig{
        VLAN:       998,
        AuthMethod: entities.AuthMethod802_1X,
        Gateway:    "10.99.98.1",
    },
    ProductionNetwork: &entities.NetworkPhaseConfig{
        VLAN:       100,
        AuthMethod: entities.AuthMethod802_1X,
        Gateway:    "10.0.100.1",
    },
}

ctx := context.Background()

// Create instance
instance, err := orchestrator.Create(ctx, profile)
if err != nil {
    return err
}

// Attach network
portName := fmt.Sprintf("vm-%s", instance.ID[:8])
err = orchestrator.AttachNetwork(ctx, instance.ID, portName)
if err != nil {
    return err
}

// Start instance
err = orchestrator.Start(ctx, instance.ID)
if err != nil {
    return err
}

fmt.Printf("VM %s running with PID %d\n", instance.ID, instance.PID)
```

### Query Instances

```go
// List all running instances
runningState := compute.StateRunning
filter := &compute.InstanceFilter{State: &runningState}

instances, err := orchestrator.List(ctx, filter)
for _, inst := range instances {
    fmt.Printf("Instance: %s (%s) - State: %s\n",
        inst.Name, inst.ID, inst.State)
}

// Get specific instance
instance, err := orchestrator.Get(ctx, instanceID)
```

### Stop and Delete

```go
// Stop gracefully
err = orchestrator.Stop(ctx, instance.ID)

// Delete and cleanup
err = orchestrator.Delete(ctx, instance.ID)
```

## Instance States

| State | Description | Valid Transitions |
|-------|-------------|-------------------|
| Unknown | Initial state | creating, error |
| Creating | Being created | stopped, error |
| Stopped | Not running | starting, deleting, error |
| Starting | Booting | running, error |
| Running | Active | stopping, error |
| Stopping | Shutting down | stopped, error |
| Error | Failed state | (terminal) |
| Deleting | Being deleted | (terminal) |

## State Machine

```
Instance States:
  unknown ──▶ creating ──▶ stopped ──▶ starting ──▶ running ──▶ stopping ──▶ stopped
                 │                        │            │
                 ▼                        ▼            ▼
               error                    error        error

  stopped ──▶ deleting (terminal)
  error   ──▶ (terminal, requires manual cleanup)
```

## Documentation

- [Architecture](architecture.md) - Design and component overview
- [Configuration](configuration.md) - Configuration reference
- [Container Orchestrator](container-orchestrator.md) - Container management with attestation
- [Cloud Providers](cloud-providers.md) - AWS NitroTPM (+ GCP/Azure) provider factory & capability matrix
- [API Reference](api-reference.md) - Go and gRPC API documentation
- [CLI Usage](cli-usage.md) - Command-line reference
- [swtpm Integration](swtpm-integration.md) - vTPM provisioning
- [802.1X Network Attachment](802.1X-network-attachment.md) - Port authentication
- [Development Roadmap](ROADMAP.md) - Phases 1-7 implementation status

### Related Documentation

- [Device Provisioning](../provisioning/) - Client-side network setup and enrollment

## Integration with SDN

The compute orchestrator integrates with the SDN policy engine for 802.1X-style
network access control. When `PortAuthEnabled` is set:

1. VM network attached to OVS bridge
2. Port enters Provisioning state (VLAN 998)
3. VM enrolls via ACME and obtains IDevID
4. VM activates and enters Authorized state
5. Production VLAN applied from device profile

See [802.1X Network Attachment](802.1X-network-attachment.md) for details.

## Requirements

### System Dependencies

- QEMU 8.0+ with KVM support
- Open vSwitch 2.17+ with OVSDB
- swtpm 0.8+ for vTPM emulation
- Linux kernel 5.10+ with KVM module
- OVMF firmware for UEFI boot

### Installation

```bash
# Debian/Ubuntu
sudo apt-get install qemu-system-x86 openvswitch-switch swtpm swtpm-tools ovmf

# Verify KVM
ls -l /dev/kvm
```

## References

- [QEMU Documentation](https://www.qemu.org/documentation/)
- [OVS Documentation](https://docs.openvswitch.org/)
- [swtpm Documentation](https://github.com/stefanberger/swtpm)
- [OVMF Documentation](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)

# Physical Switch Management

go-trusted-platform includes native switch management for automating physical network port configuration during device provisioning. This feature enables seamless network integration of devices across VLANs without manual switch configuration.

## Overview

The switch management system provides:

- **Runtime port control**: Manage individual switch ports via SSH CLI commands
- **VLAN operations**: Move devices between provisioning and production VLANs
- **Port status monitoring**: Query port state, VLAN membership, and link status
- **Multi-vendor support**: SSH-based CLI works with Cisco IOS, IOS-XE, NX-OS, Arista EOS, and similar platforms
- **Extensible architecture**: Add new vendors by implementing the Manager interface

## Use Cases

### PXE Provisioning Workflow

When provisioning a new device:

1. Device registers with the platform (registered state)
2. Device port is configured on a provisioning VLAN
3. Platform performs secure boot, attestation, and installation
4. Device completes firstboot and enters production state (activated)
5. Platform moves device port to production VLAN using switch API
6. Device joins production network

### Zero-Touch Provisioning (ZTP)

Combined with device profiles and policy engine:

- Profile defines provisioning VLAN, production VLAN, and SDN policies
- Platform automatically transitions physical network configuration during device activation
- No manual switch CLI commands required

### Network Quarantine

Isolate problematic devices by moving them to a quarantine VLAN without physical intervention.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Device REST API / CLI Commands                          │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ Device Handler / Profile Service                        │
│ (transitionSwitchPort)                                  │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ Switch Service (named Manager registry)                 │
│ - Managers map[name]Manager                             │
│ - NewService(configs) creates managers per switch       │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ ManagerFactory (vendor dispatch)                        │
│ - cisco-nexus → SSH Manager                             │
│ - noop → No-op Manager (testing)                        │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ Manager Interface (runtime operations)                  │
│ - SetPortVLAN, GetPortVLAN, GetPortStatus               │
│ - ListPorts, EnablePort, DisablePort, Close             │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ SSH Manager (CLI execution)                             │
│ - SSH connection pooling                                │
│ - Command composition (configure terminal / end)        │
│ - Output parsing (regex-based)                          │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│ Physical Switch (Cisco NX-OS, IOS-XE, etc.)             │
└─────────────────────────────────────────────────────────┘
```

## Packages

- **`pkg/switch`**: Core manager interface, SSH implementation, vendor factories
  - `types.go`: Config, Manager, PortStatus types
  - `service.go`: Service layer with named registry
  - `manager_factory.go`: Vendor dispatch
  - `ssh_manager.go`: SSH CLI implementation
  - `errors.go`: All typed errors

**Note:** This package was moved from `pkg/bootstrap/switch/` to `pkg/switch/` in Phase 7. All imports use `pkg/switch`.

- **`pkg/webservice/v1/device`**: REST handler integration
  - `handler.go`: Device activation handler with VLAN transition
  - `types.go`: ProfileResponse, NetworkConfig
  - Integration via `WithSwitchService()` option

- **`pkg/app/app.go`**: Configuration integration
  - `SwitchConfigs []switchmgmt.Config` field
  - Loaded from YAML `switches:` section

## Quick Start

### 1. Configure Switch in YAML

```yaml
switches:
  - name: core-switch-01
    vendor: cisco-nexus
    host: 10.0.1.50
    port: 22
    user: admin
    password: "encrypted://..."  # Use platform secrets
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
      - id: 200
        name: production
        subnet: 203.0.113.0/24
    ports:
      - port: Eth1/1-10
        mode: access
        access_vlan: 100
```

### 2. Enable Switch Service at Startup

```go
// Platform daemon automatically initializes switch service:
// if len(App.SwitchConfigs) > 0 {
//     switchService, _ := switchmgmt.NewService(App.SwitchConfigs, logger)
//     defer switchService.Close()
// }
```

### 3. Use in Device Activation

When device calls `POST /device/activate`, platform automatically moves the port:

```go
// Handler calls transitionSwitchPort:
// mgr, _ := switchService.Manager("core-switch-01")
// mgr.SetPortVLAN(ctx, "Eth1/3", 200)  // Move to production VLAN
```

## Supported Vendors

| Vendor | CLI Platform | Status | Notes |
|--------|--------------|--------|-------|
| Cisco NX-OS | Nexus 9K, 3K | Production | SSH + NETCONF support planned |
| Cisco IOS/IOS-XE | Catalyst, ASR, ISR | Planned | Same SSH CLI commands |
| Arista EOS | All switches | Planned | Compatible SSH CLI |
| Juniper | All switches | Planned | NETCONF alternative |

## Next Steps

- [Configuration Guide](./configuration.md)
- [Architecture & Design](./architecture.md)
- [CLI Reference](./cli-reference.md)
- [REST API Reference](./api-reference.md)
- [Adding New Vendors](./adding-vendors.md)
- [Provisioning Workflow](./provisioning-workflow.md)

# BMC Management

Baseboard Management Controller (BMC) support for out-of-band server management via IPMI and Redfish protocols.

## Overview

The BMC subsystem provides programmatic control over bare metal servers through their baseboard management controllers. This enables power management, boot device selection, virtual media operations, and hardware monitoring without requiring an operating system on the target machine.

## Architecture

```
platformctl CLI ──► REST / gRPC / QUIC / MCP / Unix ──► BMC Service ──► BMC Client ──► IPMI / Redfish
                                                              │
                                                        Profile Store
                                                        (device profiles)
```

The BMC service maintains a cache of active BMC clients keyed by device profile ID. Clients are created on demand using the `ClientFactory` and cached for subsequent requests. Concurrent access is handled with lock-free `sync.Map` operations.

## Supported Hardware

Any server with a standards-compliant BMC supporting:

| Protocol | Standard | Typical Hardware |
|----------|----------|-----------------|
| IPMI 2.0 | DMTF DSP0239 | Dell iDRAC, HPE iLO, Supermicro BMC |
| Redfish | DMTF DSP0266 | Modern servers (Dell 14G+, HPE Gen10+) |

## Capabilities

| Capability | Description |
|-----------|-------------|
| Power Control | On, off, reset, cycle |
| Boot Device | PXE, disk, CD-ROM, virtual media |
| Virtual Media | Mount/unmount ISO images remotely |
| Sensors | Temperature, fan speed, voltage readings |
| System Info | Manufacturer, serial number, firmware versions |

## Components

| Component | Package | Documentation |
|-----------|---------|---------------|
| BMC Service | `pkg/bmc/` | Business logic and client lifecycle |
| REST Handler | `pkg/webservice/v1/bmc/` | HTTP endpoints |
| IPMI Client | `pkg/bmc/ipmi.go` | IPMI 2.0 protocol implementation |
| Configuration | `pkg/bmc/config.go` | Connection parameters |
| Bare Metal Provisioning | `pkg/provisioning/baremetal/` | Orchestrated provisioning workflows |

## Related Documentation

- [Configuration](configuration.md) - BMC connection setup and credential management
- [Operations](operations.md) - Power, boot, virtual media, and sensor operations
- [Bare Metal Provisioning](../provisioning/bare-metal.md) - End-to-end provisioning workflows

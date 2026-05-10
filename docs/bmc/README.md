# BMC Management

Baseboard Management Controller (BMC) support for out-of-band server management via IPMI and Redfish protocols.

## Overview

The BMC subsystem provides programmatic control over bare metal servers through their baseboard management controllers. This enables power management, boot device selection, virtual media operations, and hardware monitoring without requiring an operating system on the target machine.

## Architecture

```
platformctl CLI --* REST / gRPC / QUIC / MCP / Unix --* BMC Service --* BMC Client --* IPMI / Redfish
                                                              |
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
| User Management | Create/update/delete IPMI + Redfish accounts; automatic 90-day password rotation |
| TLS Certificate | Automatic dns-01 ACME issuance and deployment via Redfish CertificateService or Supermicro CGI |
| Credential Store | memguard-locked BMC credential storage backed by QuicBaaS secrets |

## Components

| Component | Package | Purpose |
|-----------|---------|---------|
| BMC Service | `pkg/bmc/` | Business logic and client lifecycle |
| REST Handler | `pkg/webservice/v1/bmc/` | HTTP endpoints |
| IPMI Client | `pkg/bmc/ipmi.go`, `pkg/bmc/rmcp.go` | IPMI 2.0 RMCP+ protocol |
| Redfish Client | `pkg/bmc/redfish.go`, `pkg/bmc/redfish_transport.go` | Redfish REST API client |
| SMC CGI Backend | `pkg/bmc/smc/` | Supermicro ATEN CGI cert upload |
| AutoCertManager | `pkg/bmc/auto_cert.go` | Vendor-dispatch cert management |
| User Management | `pkg/bmc/user.go`, `pkg/bmc/ipmi_user.go`, `pkg/bmc/redfish_user.go` | IPMI + Redfish account CRUD |
| Password Rotation | `pkg/bmc/rotation.go` | Store-ahead / apply / verify / rollback engine |
| Credential Store | `pkg/bmc/credentials.go`, `pkg/bmc/credentials/` | memguard-backed secret storage |
| Configuration | `pkg/bmc/config.go` | Connection parameters + TLS identity |
| RMCP Simulator | `test/integration/bmc/rmcpsim/` | Reusable IPMI 2.0 test responder (used by vBMC) |
| vBMC | `test/integration/bmc/vbmc/` | Virtual BMC responder for integration tests |
| Bare Metal Provisioning | `pkg/provisioning/baremetal/` | Orchestrated provisioning workflows |

## Related Documentation

- [Configuration](configuration.md) - BMC connection setup, credentials, and TLS identity
- [Operations](operations.md) - Power, boot, virtual media, sensor, and TLS-management operations
- [Testing](testing.md) - devcontainer vBMC harness for integration tests (Redfish + SMC CGI + IPMI 2.0 RMCP+)
- [Bare Metal Provisioning](../provisioning/bare-metal.md) - End-to-end provisioning workflows
- [BMC TLS architecture](../architecture/bmc-tls.md) - End-to-end automated cert issuance, deployment, renewal
- [Certificate lifecycle runbook](../operations/cert-lifecycle.md) - Renewal cadence, triggers, troubleshooting
- [X10 SMC CGI validation](../operations/x10-smc-cgi-validation.md) - Hardware validation before enabling auto-mode CGI fallback

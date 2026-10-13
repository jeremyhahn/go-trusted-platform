# BMC Management

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md).

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
| Credential Store | `MemoryEnclave`-locked BMC credential storage backed by QuicBaaS secrets |
| Enrollment | Trust-lifecycle ceremony: factory cert capture, platform cert replacement, DNS registration, DANE TLSA publication, Device entity stamping |
| Factory Cert Restore | Reverses enrollment: BMC regenerates default self-signed cert, SPKI pin deleted, TLSA records removed, Device entity cleared |

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
| Credential Store | `pkg/bmc/credentials.go`, `pkg/bmc/credentials/` | `MemoryEnclave`-backed credential storage |
| Enrollment ceremony | `pkg/app/bmc_enroll.go` | 7-step trust-lifecycle enrollment |
| Factory cert restore | `pkg/app/bmc_restore.go`, `pkg/bmc/cert_restore.go`, `pkg/bmc/smc/cert_restore.go` | Redfish and SMC CGI restore paths |
| Configuration | `pkg/bmc/config.go`, `pkg/bmc/enrollment.go` | Connection parameters, TLS identity, enrollment flags |
| RMCP Simulator | `test/integration/bmc/rmcpsim/` | Reusable IPMI 2.0 test responder (used by vBMC) |
| vBMC | `test/integration/bmc/vbmc/` | Virtual BMC responder for integration tests |
| Bare Metal Provisioning | `pkg/provisioning/baremetal/` | Orchestrated provisioning workflows |

## Related Documentation

- [Configuration](configuration.md) - BMC connection setup, credentials, TLS identity, and enrollment flags
- [Operations](operations.md) - Power, boot, virtual media, sensor, TLS-management, enrollment, and factory cert restore operations
- [Testing](testing.md) - devcontainer vBMC harness for integration tests (Redfish + SMC CGI + IPMI 2.0 RMCP+)
- [Bare Metal Provisioning](../provisioning/bare-metal.md) - End-to-end provisioning workflows
- [BMC TLS architecture](../architecture/bmc-tls.md) - End-to-end automated cert issuance, deployment, renewal
- [Certificate lifecycle runbook](../operations/cert-lifecycle.md) - Renewal cadence, triggers, troubleshooting
- [X10 SMC CGI validation](../operations/x10-smc-cgi-validation.md) - Hardware validation before enabling auto-mode CGI fallback

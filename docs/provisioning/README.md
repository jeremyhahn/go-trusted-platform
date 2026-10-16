# Device Provisioning

> **Status: REFERENCE** · Last verified: 2026-10-15
> Device enrollment, network configuration and production activation: an index of this folder.

Automated device enrollment, network configuration, and production activation.

## Overview

The provisioning system enables devices to self-enroll with the Trusted Platform using mTLS authentication with IDevID certificates. After enrollment, devices automatically receive their network configuration and transition from provisioning to production networks.

## PXE Network Bootstrap

For greenfield deployments (no existing infrastructure), use the PXE bootstrap system to go from bare metal to a running cluster in a single command:

```bash
platformctl bootstrap run --config bootstrap.yaml
```

See the [Bootstrap Documentation](../bootstrap/user.md) for the complete guide.

## Full Provisioning Lifecycle

```
Device Template --> Device Profile --> Device Config --> Provisioned System
   (blueprint)      (device-specific)    (on device)       (running)
```

### Phase 1: Config Delivery (Pre-Enrollment)

```
ISO Boot --> Trust Bootstrap --> Fetch Config --> Install OS
             (DANE/Noise/SPKI)   (EAB auth)       (LUKS, TPM)
                                      |
                              No match? --> QR Code --> Operator assigns
```

### Phase 2: Enrollment & Activation (Post-Install)

```
+------------------+     +------------------+     +------------------+
|   Device Boot    |     |  Provisioning    |     |   Production     |
|                  |---->|    Network       |---->|    Network       |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
        |                       |                       |
        v                       v                       v
   ACME Enroll             Fetch Profile            Apply Config
   Get IDevID              Activate Device          Full Access
```

## Components

| Component | Purpose | Documentation |
|-----------|---------|---------------|
| **Device Templates** | Reusable config blueprints for provisioning | [templates.md](templates.md) |
| **Config Delivery** | Pre-enrollment config fetch via EAB + trust bootstrap | [config-delivery.md](config-delivery.md) |
| **Config Delivery API** | Multi-protocol API reference (REST/gRPC/QUIC/MCP/Unix/CLI) | [api-reference.md](api-reference.md) |
| **Interactive QR** | Operator-at-console provisioning via QR code | [interactive.md](interactive.md) |
| **ISO Configuration** | Building ISOs with embedded or server-fetched config | [iso.md](iso.md) |
| **Provisioning Client** | mTLS client for profile fetch & activation | [client.md](client.md) |
| **Bare Metal** | BMC-driven (IPMI/Redfish) bare metal provisioning | [bare-metal.md](bare-metal.md) |
| **BMC Management** | Power, boot, virtual media, sensors | [../bmc/](../bmc/) |
| **PXE Bootstrap** | Single-command greenfield deployment | [../bootstrap/user.md](../bootstrap/user.md) |

## Quick Start

### Client-Side Setup

Nothing to install. Once ACME enrollment stores the IDevID certificate in the
TPM, platformd fetches the device profile and activates the device over mTLS,
presenting the TPM-resident IDevID; the IDevID private key never leaves the
TPM and no key file is involved
([device architecture §4.4](../device/architecture.md#44-activation-identity-becomes-network-access)).

### Server-Side Configuration

The network settings a device receives come from its device profile: the
post-enrollment network config is served as `admittedNetwork` (with its ACLs)
and the enrollment network config as `provisioningNetwork`
(`ProfileFromDeviceProfile`, `pkg/webservice/v1/device/profile_service.go`).
`GET /api/v1/device/profile` answers:

```json
{
  "serialNumber": "DEVICE-001",
  "admittedNetwork": {
    "vlan": 100,
    "useDHCP": true,
    "gateway": "198.51.100.1",
    "dns": ["10.99.99.2"]
  },
  "acls": [
    {"name": "acl-0", "priority": 100, "match": {"dst_port": "443"}, "action": "allow"}
  ]
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/device/profile` | GET | Fetch device profile via mTLS |
| `/api/v1/device/activate` | POST | Signal device activation |

## Security

- **mTLS Authentication**: All API calls use IDevID certificates
- **Certificate Validation**: Server and client certificates verified against CA
- **Secure Transport**: the provisioning client requires TLS 1.3
- **No Shared Secrets**: the device serial comes from the verified client certificate, never the request body

## Related Documentation

- [Compute Orchestration](../compute/) - VM/container management
- [Certificate Authority](../ca/) - Certificate issuance
- [ACME](../ca/acme.md) - Automated certificate enrollment
- [PXE Bootstrap](../bootstrap/user.md) - Greenfield deployment

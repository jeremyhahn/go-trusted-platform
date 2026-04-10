# PXE Network Bootstrap

Single-command greenfield deployment of bare metal infrastructure via PXE boot.

## Overview

The PXE bootstrap system automates the entire process of turning racked bare metal servers into a running Trusted Platform cluster. It handles:

- **MAC Discovery** -- queries BMC (Redfish/IPMI) to learn each server's NIC MAC address
- **Switch Configuration** -- optionally configures physical switches (VLANs, port assignments)
- **Bootstrap Container** -- deploys a PXE/DHCP/TFTP container to a target host
- **Control Plane Provisioning** -- PXE boots control-plane nodes first
- **Template Seeding** -- uploads device templates and creates profiles on the running control plane
- **Remaining Node Provisioning** -- PXE boots gateway and worker nodes
- **Auto-Teardown** -- removes the bootstrap container after all nodes are healthy

## Key Concepts

**Bootstrap Config** (`bootstrap.yaml`): A single YAML file describing the entire deployment -- nodes, roles, BMC credentials, network config, switch config, and deployer target.

**Node Roles**: `control-plane`, `gateway`, `worker`. Control-plane nodes boot first; gateways and workers boot after templates are seeded.

**BMC-Managed vs Manual Nodes**: Nodes with `bmc_address` get automatic MAC discovery and remote power-on. Manual nodes (with `mac` only) require the operator to PXE boot them.

**Device Templates**: Per-role configuration files (CA settings, TPM config, network config) that are seeded to the control plane after it boots.

**Bootstrap Container**: A Docker/Podman container running DHCP, TFTP, and HTTP services for PXE boot. Deployed via SSH to a target host.

## Quick Start

1. Create `bootstrap.yaml` (see [Config Reference](./config-reference.md))
2. Create device templates for each role
3. Run the bootstrap:

```bash
platformctl bootstrap run --config bootstrap.yaml
```

4. Monitor output for per-node status
5. After completion, all nodes are enrolled and running

## CLI Commands

| Command | Description |
|---------|-------------|
| `platformctl bootstrap run --config bootstrap.yaml` | Full bootstrap (all phases) |
| `platformctl bootstrap discover --config bootstrap.yaml` | Phase 0 only: discover MACs |
| `platformctl bootstrap deploy --config bootstrap.yaml` | Deploy bootstrap container |
| `platformctl bootstrap status --config bootstrap.yaml` | Health check all nodes |
| `platformctl bootstrap teardown --config bootstrap.yaml` | Remove bootstrap container |

## Bootstrap Phases

| Phase | Name | Description |
|-------|------|-------------|
| 0 | Discovery | Query BMCs for MAC addresses; validate manual MACs |
| 1 | Switch | Configure VLANs and port assignments (optional) |
| 2 | Deploy | Deploy PXE bootstrap container to target host |
| 3 | Control Plane | PXE boot and wait for control-plane nodes |
| 4 | Seed | Upload templates and create device profiles |
| 5 | Remaining | PXE boot gateway and worker nodes |
| 6 | Teardown | Remove bootstrap container (non-fatal if fails) |

## Related Documentation

- [Day Zero Guide](./day-zero.md) -- Step-by-step first deployment
- [Config Reference](./config-reference.md) -- Complete bootstrap.yaml reference
- [Deployer](./deployer.md) -- Bootstrap container deployment targets
- [Switch Management](./switch-management.md) -- Physical switch auto-configuration
- [Manual Nodes](./manual-nodes.md) -- Provisioning without BMC

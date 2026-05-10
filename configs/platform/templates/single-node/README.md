# Single-Node Deployment Profile

All services (control-plane + gateway + compute data plane) collocated
on a single host. Used as the **default** when `platformctl iso create`
is invoked with no flags.

## Status

`default.yaml` is the shipped single-node reference config. It enables:

- `platformd` in server mode with CA, ACME, DNS authoritative, IAM,
  KMS, QuicBaaS standalone (local pebble, no Raft)
- `gatewayd` with edge onboarding, firewall, NAT — DHCP/BGP/LB off by
  default (operator opts in)
- OVS bridge `trusted0` for local VM/container networking
- eth0 as the only NIC (DHCP from upstream router)
- Internal subnet `192.168.100.0/24` NAT'd out eth0

See `docs/architecture/deployment-reference.md` §1 for the topology
this template implements.

## Use Cases

- Development and demo environments
- Edge deployments where a single box is the only option
- Small-footprint reference architectures
- First-install for labs before promoting to `dedicated/` or `high-availability/`

## Usage

### Default (no flags)

```bash
platformctl iso create
```

Produces `trusted-alpine-<version>-<arch>.iso` with this template
baked in.

### With site-specific overrides

```bash
platformctl iso create \
  --platform-config configs/platform/templates/single-node/default.yaml \
  --overrides /path/to/my-site.yaml
```

Common overrides: `os.hostname`, `domain`, `network.interfaces[].name`,
`webservices[].sans`, `tpm.idevid.serial`.

## Process Model

| systemd unit | Binary | Role |
|--------------|--------|------|
| `platformd.service` | `platformd` | Control plane — CA, ACME, DNS, IAM, KMS, OVS master |
| `gatewayd.service` | `gatewayd` | Data plane — firewall, NAT, DHCP, BGP |
| `trusted-platform.target` | (target) | Bundles both services |

Both daemons run on the same host with a Unix-socket IPC boundary
between them. See `docs/architecture/binary-separation.md` and
`docs/architecture/bootstrap-flow.md` §1 for the architectural
rationale.

## Promoting to Multi-Node

To scale out to dedicated 3-node:

1. Install a second (gateway) + third (compute) box using the
   `dedicated/` role-specific templates.
2. On the original single-node host, set `gatewayd.enabled: false`
   and restart.
3. Point `sdn.gateway.endpoint` at the new gateway host (or leave
   platformd-local OVS and run with no external gateway).

See `dedicated/README.md` for the full 3-node flow.

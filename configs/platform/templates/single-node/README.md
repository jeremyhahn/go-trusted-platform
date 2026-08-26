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

## Time Synchronization (ntp)

The single-node template ships an `ntp:` section in `mode: both`: it
consumes public time from `pool.ntp.org` and serves the local
`192.168.100.0/24` network with NTS enabled, falling back to the local
clock at stratum 10 when no upstream is reachable.

Time is a trust primitive — TPM attestation freshness, ACME issuance,
DANE/DNSSEC signature windows and JWT validity all depend on it — so
the startup gate blocks bring-up for up to 120s after network setup and
before TPM/CA initialization. On timeout the node boots with the `ntp`
health component flagged `time-unsynced` rather than silently running
on a wrong clock. `rtc.write-back` persists the corrected time to the
hardware clock so the next cold boot starts sane.

chrony is installed as a mandatory package and managed by platformd;
removing the `ntp:` section entirely makes platformd leave it alone.

Full schema: `docs/device-templates.md` (Time Synchronization).
API surface: `docs/ntp/api-reference.md`.

## BMC Trust Chain (trust.bmc)

The single-node template ships a `trust.bmc` scope that configures the TLS
trust chain used when the platform connects to its own BMC (Redfish HTTPS,
IPMI-over-TLS). The single-node node serves its own public DNS on
`127.0.0.1:8053`, which is used for DANE TLSA lookups.

```yaml
trust:
  bmc:
    # tofu is NOT available here (#83): it fetches a CA bundle and a BMC
    # serves none. Use a per-node bmc_spki_pin for first contact.
    strategies: [dane, spki, ca-file]
    dane:
      dns-server: "127.0.0.1:8053"
```

Once BMC enrollment is complete and DANE TLSA records for
`_443._tcp.<hostname>-bmc.<internal-zone>` are live, you can drop `bmc_spki_pin` from the
chain in your override file:

```yaml
trust:
  bmc:
    strategies: [dane, spki, ca-file]
```

See [`docs/device-templates.md`](../../../docs/device-templates.md#bmc-trust-chain-trustbmc)
for full chain semantics and the deprecated `bmc.skip-tls-verify` /
`bmc.ca-cert-path` field replacements.

## Promoting to Multi-Node

To scale out to dedicated 3-node:

1. Install a second (gateway) + third (compute) box using the
   `dedicated/` role-specific templates.
2. On the original single-node host, set `gatewayd.enabled: false`
   and restart.
3. Point `sdn.gateway.endpoint` at the new gateway host (or leave
   platformd-local OVS and run with no external gateway).

See `dedicated/README.md` for the full 3-node flow.

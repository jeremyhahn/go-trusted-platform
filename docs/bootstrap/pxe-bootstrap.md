# PXE Network Bootstrap

Single-command greenfield deployment of bare metal infrastructure via PXE boot.

## Overview

The PXE bootstrap system automates the entire process of turning racked bare metal servers into a running Trusted Platform cluster. It handles:

- **MAC Discovery** -- queries BMC (Redfish/IPMI) to learn each server's NIC MAC address. Redfish walks `EthernetInterfaces`; on IPMI, Supermicro-family BMCs (including the VeloCloud EDGE840 rebadge) answer the OEM command NetFn `0x30`/Cmd `0x21` for the host LAN1 MAC -- the only out-of-band path on X10 ATEN firmware, whose Redfish interface list is unpopulated. Nodes whose BMC supports neither path fall back to operator-provided MACs in `bootstrap.yaml`
- **Switch Configuration** -- optionally configures physical switches (VLANs, port assignments)
- **Bootstrap Container** -- deploys a PXE/DHCP/TFTP container to a target host
- **Control Plane Provisioning** -- PXE boots control-plane nodes first
- **Template Seeding** -- uploads device templates and creates profiles on the running control plane
- **Remaining Node Provisioning** -- PXE boots gateway and worker nodes
- **BMC Enrollment** -- runs the BMC enrollment ceremony on nodes with `bmc_enroll: true`
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
| 4 | Seed | Merge per-node configs and publish to config server |
| 5 | Remaining | PXE/virtual-media boot gateway and worker nodes |
| 5a | BMC Enroll | Run BMC enrollment ceremony for nodes with `bmc_enroll: true` (skipped if none) |
| 6 | Watch | Stream install-log uploads; verify successful install |
| 7 | Teardown | Remove bootstrap container (non-fatal if fails) |

### Phase 4 — Seed (Detail)

This is the phase that matches each node to its role-specific device
config and publishes per-MAC values consumed by `autoinstall.sh`.

For each node in `bootstrap.yaml`:

1. **Load role template** from
   `configs/platform/templates/<profile>/<vendor>/<model>/<role>.yaml`.
2. **Apply overrides_file** (deep merge — override wins on conflict;
   path resolves relative to the bootstrap.yaml's directory).
3. **Apply inline overrides** from the `overrides:` block in
   bootstrap.yaml (deep merge).
4. **Inject node identity** (overwrite): `os.hostname` from `hostname`,
   `bmc.address/username/password/protocol` from the node's non-empty
   `bmc_*` fields, and `network.interfaces` from `interfaces`.
5. **Serialize** the merged YAML.

Overrides that duplicate these identity keys fail validation with
`ErrForbiddenOverrideKey` (reported with file:line) — see
[Config Reference](./config-reference.md#authoritative-node-identity).

For each MAC in the union of (YAML-declared MACs, BMC-discovered MACs):

6. **PUT** `http://<deployer>:8080/config/mac/<mac-dashed>/installer.yaml`
   with the merged YAML body.
7. **PUT** `http://<deployer>:8080/config/mac/<mac-dashed>/hostname`
   with the target hostname.

Publishing under every MAC ensures the installer finds its config on
whichever NIC the Alpine live environment enumerates as `eth0`.

This phase only runs for nodes being provisioned via dynamic config
delivery (shared ISO built with `--config-server`). For operators who
bake per-role ISOs, this phase is a no-op.

See [`config-delivery.md`](./config-delivery.md) for the full config
delivery architecture.

### Phase 5a — BMC Enroll (Detail)

This phase runs only when at least one node in `bootstrap.yaml` has
`bmc_enroll: true`. It is skipped entirely when no nodes require it.

For each node with `bmc_enroll: true`:

1. The orchestrator looks up the profile ID recorded during Phase 4 (Seed).
2. It sends `POST /api/v1/bmc/{profileID}/enroll` to the control plane
   with an empty JSON body `{}`.
3. On success the control plane returns a factory certificate and
   enrollment metadata.
4. The outcome (hostname, profile ID, success/failure, detail) is
   recorded in `BootstrapResult.BMCEnrollments` regardless of outcome.

**Non-fatal semantics**: A per-node enrollment failure is logged as a
warning and recorded in the result, but does NOT abort the remaining
phases. The orchestrator continues to Phase 6 (Watch) and teardown.

**Backup writing**: When `backups_dir` is set in the top-level bootstrap
config, successful enrollment artifacts are written to
`<backups_dir>/<hostname>/bmc/`:

| File | Mode | Contents |
|------|------|----------|
| `factory-cert.pem` | 0600 | PEM-encoded factory certificate |
| `factory-cert.json` | 0600 | Certificate metadata JSON |
| `enrollment.json` | 0600 | Full enrollment response JSON |

The backup directory itself is created with mode 0700. If `backups_dir`
is empty, backup writing is silently skipped.

Example configuration enabling BMC enrollment with backups:

```yaml
backups_dir: ~/.platform/backups   # ~ is expanded to $HOME

nodes:
  - hostname: cp-01
    bmc_address: 10.4.2.105
    bmc_protocol: ipmi
    bmc_spki_pin: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    bmc_enroll: true    # enroll this node's BMC after deploy
  - hostname: w-01
    bmc_address: 10.4.2.106
    bmc_protocol: ipmi
    bmc_spki_pin: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    # bmc_enroll not set — enrollment skipped for this node
```

## BMC TLS Trust

Bootstrap-time BMC connections use a per-node ordered strategy chain configured
via `bmc_trust`. The chain is evaluated left-to-right; the first successful
strategy provides the `*tls.Config`.

| Strategy | Description |
|----------|-------------|
| `spki` | Static SPKI pin from `bmc_spki_pin`. Use when the pin is known out-of-band. |
| `ca-file` | Verify against a PEM CA file path. Use when a private BMC CA exists. |
| `dane` | DNS-based Authentication of Named Entities. Requires DNS TLSA records for the BMC. |

`tofu` is **not** in that list: it fetches a CA bundle, and a BMC serves
Redfish rather than a bundle, so it can never verify one (#83; endpoint-pinning
tofu is requested upstream as go-xkms#139). Use `bmc_spki_pin`.

A single in-memory pin store is still constructed per orchestrator run, ready
for the day tofu becomes usable here. Pins are plain SPKI hashes (public data)
and are never persisted to disk — they exist only for the lifetime of the
`platformctl bootstrap run` process.

When `bmc_trust` is empty, the orchestrator falls back to the platform trust
config default. When neither is configured, the system roots and the `bmc.Config`
legacy path apply.

Example:

```yaml
nodes:
  - hostname: cp-01
    bmc_address: 10.4.2.105
    bmc_protocol: ipmi
    bmc_spki_pin: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"   # pin the BMC's own cert (tofu cannot verify a BMC, #83)
    bmc_enroll: true        # run BMC enrollment ceremony post-deploy
```

## Related Documentation

- [Config Delivery](./config-delivery.md) -- Bootstrap-time dynamic + baked config delivery
- [Day Zero Guide](./day-zero.md) -- Step-by-step first deployment
- [Config Reference](./config-reference.md) -- Complete bootstrap.yaml reference
- [Deployer](./deployer.md) -- Bootstrap container deployment targets
- [Switch Management](./switch-management.md) -- Physical switch auto-configuration
- [Manual Nodes](./manual-nodes.md) -- Provisioning without BMC
- [Architecture: Bootstrap Flow](../architecture/bootstrap-flow.md) -- End-to-end architecture

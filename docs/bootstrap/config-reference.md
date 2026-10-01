# Bootstrap Configuration Reference

Complete reference for `bootstrap.yaml`.

## Top-Level Structure

```yaml
deployer:           # Required: where to deploy the bootstrap container
switch:             # Optional: physical switch auto-configuration
provisioning_network:  # Required: PXE provisioning network
platform:           # Required: global platform settings
templates:          # Required: device template paths by role
nodes:              # Required: list of nodes to bootstrap
backups_dir:        # Optional: factory-cert backup directory
```

## File Location

Deployment-specific `bootstrap.yaml` and overrides files are not checked
into this repository — keep them in your private infrastructure repo and
pass the path with `platformctl bootstrap run --config <path>`. Per-node
`overrides_file` paths and `templates:` paths both resolve relative to the
bootstrap.yaml's own directory, never the working directory `platformctl`
was invoked from, so a bootstrap config is relocatable and `--dry-run`
reads the same files the real run does. Templates under
`configs/platform/templates/` remain the public, placeholder-valued
references.

## Deployer

Controls where the PXE bootstrap container is deployed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | **required** | SSH hostname or IP of the deployer host |
| `user` | string | | SSH username |
| `ssh_key` | string | | Path to SSH private key |
| `known_hosts_path` | string | | Directory of pinned SSH host-key envelopes; required (fail-closed, no trust-on-first-use) |
| `container_runtime` | string | `docker` | Container runtime: `docker` or `podman` |
| `bootstrap_http_port` | int | `8080` | Container HTTP service: per-MAC config, install-log sink, `/health` |
| `bootstrap_device_script_port` | int | `bootstrap_http_port` + 1 | Per-device boot script listener. Move it when the deployer already has something on the derived port |
| `netboot_media_dir` | string | — | The netboot media build to stage (media sets, the Raspberry Pi TFTP tree, the db-signed arm64 iPXE), relative to this file — built by `make netboot-media` / `platformctl diskimage netboot`. **Required**: the container image carries no installer media, and every PXE-installed node — x86_64 included — boots a set from this build |
| `proxy_dhcp` | bool | `false` | Answer PXE clients with boot options only; the segment's own DHCP server leases addresses |

```yaml
deployer:
  host: 192.0.2.5
  user: admin
  ssh_key: ~/.ssh/id_ed25519
  known_hosts_path: /etc/platform/deployer/known_hosts
  container_runtime: docker
```

## Environment and zones

The deployment's network is the [reference network](../architecture/reference-network.md). Every VLAN,
subnet and switch-port VLAN list is derived from the top-level `environment:` by the network plan
(`pkg/sdn/netplan`); `bootstrap.yaml` carries no VLAN or subnet numbers.

| Field | Type | Description |
|-------|------|-------------|
| `environment.id` | int | **Required**. Environment number _E_ (2–40): VLANs _E_·100+n, IPv4 `10.E.n.0/24`, VNIs _E_·100000+n |
| `environment.base` | CIDR | IPv4 `/8` base. Default `10.0.0.0/8` |
| `environment.ula` | CIDR | Deployment ULA `/48` (RFC 4193, random global ID). Omit for no IPv6 subnets |
| `environment.overrides` | list | Explicit `{zone, vlan, subnet, subnet6}` per zone, for sites that cannot follow the reference numbering |
| `zones` | list | Built-in zone policy tuning and owner-defined zones (offsets 9–99), the same schema as `sdn.zones` in a platform config |

The provisioning zone (offset 5) is always present; it is where the bootstrap container's DHCP/PXE
serves new nodes.

```yaml
environment:
  id: 4
  ula: fd12:3456:789a::/48   # example; generate your own random /48
zones:
  - name: lab                # owner-defined zone: VLAN 409, 10.4.9.0/24
    offset: 9
    port_classes: [hypervisor]
    isolate: true
```

`environment:` here is the network plan; `platform.environment` (below) is the deployment's name
(`production`, `staging`), a different setting.

## Switch (Optional)

Auto-configures a physical network switch. Omit this section if switch configuration is managed
manually. See [Physical Switch Auto-Configuration](switch-management.md).

| Field | Type | Description |
|-------|------|-------------|
| `vendor` | string | Switch vendor: `cisco-nexus` (or `noop`) |
| `host` | string | Switch management IP |
| `user` | string | SSH username |
| `ssh_key` | string | Path to SSH private key |
| `known_hosts_path` | string | Pinned host-key directory (switch SSH is fail-closed) |
| `port_assignments` | list | `{port, class, description}`: each platform port's class (`gateway`, `hypervisor`, `bmc`, `mgmt-uplink`, `peer-link`) |

The switch gets one VLAN per zone; each port gets its class's mode, allowed VLANs, native VLAN and MTU
9216, all derived from the environment.

```yaml
switch:
  vendor: cisco-nexus
  host: 192.0.2.10
  user: admin
  ssh_key: ~/.ssh/switch_key
  known_hosts_path: /etc/platform/switch/known_hosts
  port_assignments:
    - port: Ethernet1/3
      class: gateway
      description: "gw-01"
    - port: Ethernet1/25
      class: hypervisor
      description: "cp-01"
    - port: Ethernet1/41
      class: bmc
      description: "gw-01 BMC"
```

## Retired keys

These keys held literal VLAN and subnet numbers. Loading a `bootstrap.yaml` that still carries one
fails with `ErrRetiredKey`, naming the file, line and replacement:

| Retired key | Use instead |
|-------------|-------------|
| `subnets` | `environment` |
| `fabric` | `switch.port_assignments` with port classes |
| `platform.networks` | `environment` |
| `switch.vlans` | `environment` |
| `switch.port_assignments[].mode`, `[].vlans` | `switch.port_assignments[].class` |
| `nodes[].post_enrollment` | the port class (a hypervisor trunk's native VLAN is provisioning) |

## Platform

Global platform settings shared across all nodes.

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | **Required**. Primary domain name |
| `internal_domain` | string | Internal DNS domain |
| `hostmaster` | string | DNS hostmaster email |
| `tenant_id` | string | Tenant identifier |
| `environment` | string | Deployment environment name |
| `upstream_dns` | list | Upstream DNS resolvers |
| `bootstrap_strategy` | string | Trust bootstrap strategy |
| `health_timeout` | duration | Post-install health wait per node. Default `25m`. A node must finish install-reboot → firstboot seal → auto-provision → ACME enrollment → service restart before it answers; size this to that cycle, not to boot time (#134). **Must carry a unit** (`25m`, `90s`, `1h`) like every other duration in this file — a bare number is a config parse error, not a default. A zero or negative *duration* (`0s`, `-5m`) is treated as unset rather than as "no wait", since a zero-length window would fail every node instantly |

```yaml
platform:
  domain: example.com
  internal_domain: internal.example.com
  hostmaster: admin@example.com
  tenant_id: tenant-001
  environment: production
  upstream_dns:
    - 8.8.8.8
  bootstrap_strategy: dane
  # Optional. Omit to use the 25m default; raise it on slower chassis.
  health_timeout: 25m
```

## Templates

Maps node roles to device template file paths.

```yaml
templates:
  control-plane: templates/control-plane.yaml
  gateway: templates/gateway.yaml
  worker: templates/worker.yaml
```

A relative path resolves against the directory holding the bootstrap.yaml,
not the process working directory; an absolute path is used as written.
Every reader applies the same rule — the `--dry-run` plan, the per-node
config staged to virtual media, the control-plane TLS name, the template
upload, and the seeded per-node profile — so one entry names one file
regardless of where the command runs.

## Nodes

List of nodes to bootstrap. Each node must have either `bmc_address` (for BMC-managed) or `mac` (for manual).

### BMC-Managed Node

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | **Required**. Node hostname |
| `role` | string | **Required**. One of: `control-plane`, `gateway`, `worker`. Stored verbatim as the device template / profile role on the control plane (`entities.DeviceRole`, [`docs/device/api.md`](../device/api.md) §4.2) |
| `bmc_address` | string | BMC IP address or hostname |
| `bmc_user` | string | BMC username |
| `bmc_password` | string | BMC password (supports secret URIs) |
| `bmc_protocol` | string | `redfish`, `ipmi`, or `auto` |
| `bmc_encryption_key` | string | IPMI encryption key |
| `bmc_trust` | list | Ordered TLS strategy chain for BMC connections. Allowed: `dane`, `spki`, `ca-file`. Empty uses the platform default. **`tofu` is NOT accepted** — it fetches a CA bundle and a BMC serves none (#83); use `bmc_spki_pin`. |
| `bmc_spki_pin` | string | Hex-encoded SHA-256 SPKI pin for the `spki` strategy |
| `bmc_enroll` | bool | Operator intent to run the BMC enrollment ceremony post-deploy |
| `interfaces` | list | Network interfaces (`[]installer.InterfaceConfig`), injected into the merged config as `network.interfaces` |
| `overrides` | map | Per-node template overrides |

### Manual Node

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | **Required**. Node hostname |
| `role` | string | **Required**. Node role: `control-plane`, `gateway`, `worker` (stored verbatim on the control plane) |
| `mac` | string | NIC MAC address (e.g., `aa:bb:cc:dd:ee:ff`) |
| `interfaces` | list | Network interfaces (`[]installer.InterfaceConfig`), injected into the merged config as `network.interfaces` |
| `overrides` | map | Per-node template overrides |

### Raspberry Pi Node

A Raspberry Pi has no BMC: it is a manual node, booted over PXE and
observed, with these fields beside the manual-node ones
(`ErrInvalidNodePlatform` names the field when one is wrong).

| Field | Type | Description |
|-------|------|-------------|
| `platform` | string | `raspberrypi` |
| `model` | string | **Required**. `rpi4`, `rpi400`, `cm4`, `rpi3b+` or `rpi5` |
| `architecture` | string | `aarch64` (the default for a Pi; `x86_64` is rejected) |
| `serial` | string | The board serial, up to eight hex digits (`/proc/cpuinfo` `Serial`, low 32 bits) — what the bootloader sends in DHCP option 97 and the name of its per-device boot directory |
| `boot_model` | string | `sd` (default): the card is installed over the network once; the bootloader's `BOOT_ORDER` must try the card first and the network second (`0xf21`) |
| `bmc_address` | — | Not allowed: a Pi has no BMC, so `boot_method: virtual-media` is not possible either |

```yaml
  - hostname: pi-01
    role: worker
    macs: ["dc:a6:32:01:36:c2"]
    platform: raspberrypi
    model: rpi4
    serial: 9ffefdef
```

`architecture` is also accepted on a generic node (`aarch64` for an Arm
server); `model`, `serial` and `boot_model` are not.

### Authoritative Node Identity

First-class node fields are authoritative for node identity. The seeder
merge pipeline is: template → `overrides_file` → inline `overrides` →
**node identity injection (overwrite)** → global identity fill. The
injection step writes, overwriting anything the merge produced:

| Node field | Injected config key |
|------------|---------------------|
| `hostname` | `os.hostname` |
| `bmc_address` | `bmc.address` |
| `bmc_user` | `bmc.username` |
| `bmc_password` | `bmc.password` |
| `bmc_protocol` | `bmc.protocol` |
| `interfaces` | `network.interfaces` |

Only non-empty BMC fields are injected; other `bmc.*` keys such as
`bmc.port` are left untouched.

Duplicating identity in `overrides_file` or inline `overrides` is a hard
validation error (`ErrForbiddenOverrideKey`, reported with file:line):

- **Structurally forbidden keys**: `os.hostname`, `network.interfaces`,
  `bmc.address`, `bmc.username`, `bmc.password`, `bmc.protocol` — use
  the first-class node field instead.
- **Forbidden only when equal to the platform global**: top-level
  `domain`, `hostmaster`, `tenant-id`, `environment` that merely repeat
  the `platform.*` value. A differing value remains a legal per-node
  override.

All other override keys (`disk`, `dns`, `bonds`, `bridges`,
`dnsmasq`, `gateway`, `tpm.idevid.serial`, `bmc.port`, `root-password`,
`post-install`, ...) are unchanged and still legal.

### Example

```yaml
nodes:
  # BMC-managed node (SPKI pin captured out of band)
  - hostname: cp-01
    role: control-plane
    bmc_address: 192.0.2.20
    bmc_user: admin
    bmc_password: "kms://bmc/cp-01/password"
    bmc_protocol: redfish
    bmc_spki_pin: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    interfaces:
      - name: eth0
        type: static
        ipv4-address: 10.0.100.140/24
        ipv4-gateway: 10.0.100.1
        auto-start: true

  # Manual node (no BMC)
  - hostname: edge-01
    role: worker
    mac: "aa:bb:cc:dd:ee:ff"
    overrides:
      disk: /dev/nvme0n1
```

## Backups Directory

Optional top-level field specifying where factory-cert backups are written
during the BMC enrollment ceremony (`bmc_enroll: true` nodes). The backups
belong with the deployment's configuration, so the path is resolved like
`netboot_media_dir` and `overrides_file`: a relative path against this file's
directory, `~` to the operator's home directory, an absolute path as written.
Empty means `backups/` beside this file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backups_dir` | string | `backups` (beside `bootstrap.yaml`) | Local directory for BMC cert backups |

## Validation Rules

- At least one node is required
- Control-plane count must be 1 or odd >= 3
- Each node must have either `bmc_address` or `mac` (not both empty)
- No duplicate MAC addresses
- No duplicate BMC addresses
- `deployer.host` is required
- `deployer.bootstrap_http_port` and `deployer.bootstrap_device_script_port`, when set, must be in 1-65535
- The two ports must not resolve to the same value
- `bootstrap_http_port: 65535` is refused unless `bootstrap_device_script_port` is set explicitly, since it would otherwise derive 65536
- `provisioning_network.subnet` is required
- `platform.domain` is required

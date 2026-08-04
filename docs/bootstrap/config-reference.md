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

## Deployer

Controls where the PXE bootstrap container is deployed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | `linux` | Deployment target: `linux` or `cisco` |
| `host` | string | **required** | SSH hostname or IP of the deployer host |
| `user` | string | | SSH username |
| `ssh_key` | string | | Path to SSH private key |
| `known_hosts_path` | string | | Directory of pinned SSH host-key envelopes; required for `target: linux` (fail-closed, no trust-on-first-use) |
| `container_runtime` | string | `docker` | Container runtime: `docker` or `podman` |

```yaml
deployer:
  target: linux
  host: 192.168.1.5
  user: admin
  ssh_key: ~/.ssh/id_ed25519
  known_hosts_path: /etc/platform/deployer/known_hosts
  container_runtime: docker
```

## Switch (Optional)

Auto-configures a physical network switch. Omit this section if switch configuration is managed manually.

| Field | Type | Description |
|-------|------|-------------|
| `vendor` | string | Switch vendor: `nexus` |
| `host` | string | Switch management IP |
| `user` | string | SSH username |
| `ssh_key` | string | Path to SSH private key |
| `vlans` | map | VLAN definitions (name -> vlan/subnet) |
| `port_assignments` | list | Port-to-VLAN mappings |

```yaml
switch:
  vendor: nexus
  host: 192.168.1.254
  user: admin
  ssh_key: ~/.ssh/switch_key
  vlans:
    management:
      vlan: 100
      subnet: 10.0.100.0/24
    production:
      vlan: 200
      subnet: 10.0.200.0/24
  port_assignments:
    - port: Ethernet1/1
      mode: trunk
      vlans: [100, 200]
      description: "cp-01"
    - port: Ethernet1/2
      mode: access
      vlans: [200]
      description: "worker-01"
```

## Provisioning Network

Defines the PXE boot provisioning network.

| Field | Type | Description |
|-------|------|-------------|
| `subnet` | string | **Required**. Provisioning subnet CIDR |
| `gateway` | string | Default gateway for provisioning network |
| `dhcp_range_start` | string | DHCP range start IP |
| `dhcp_range_end` | string | DHCP range end IP |
| `dns` | list | DNS servers for provisioning |

```yaml
provisioning_network:
  subnet: 10.0.100.0/24
  gateway: 10.0.100.1
  dhcp_range_start: 10.0.100.100
  dhcp_range_end: 10.0.100.200
  dns:
    - 10.0.100.1
```

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
| `networks` | map | Named network definitions |
| `bootstrap_strategy` | string | Trust bootstrap strategy |

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
  networks:
    management:
      vlan: 100
      subnet: 10.0.100.0/24
```

## Templates

Maps node roles to device template file paths.

```yaml
templates:
  control-plane: templates/control-plane.yaml
  gateway: templates/gateway.yaml
  worker: templates/worker.yaml
```

## Nodes

List of nodes to bootstrap. Each node must have either `bmc_address` (for BMC-managed) or `mac` (for manual).

### BMC-Managed Node

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | **Required**. Node hostname |
| `role` | string | **Required**. One of: `control-plane`, `gateway`, `worker` |
| `bmc_address` | string | BMC IP address or hostname |
| `bmc_user` | string | BMC username |
| `bmc_password` | string | BMC password (supports secret URIs) |
| `bmc_protocol` | string | `redfish`, `ipmi`, or `auto` |
| `bmc_encryption_key` | string | IPMI encryption key |
| `bmc_trust` | list | Ordered TLS strategy chain for BMC connections. Allowed: `dane`, `spki`, `ca-file`, `tofu`. Empty uses the platform default. |
| `bmc_spki_pin` | string | Hex-encoded SHA-256 SPKI pin for the `spki` strategy |
| `bmc_enroll` | bool | Operator intent to run the BMC enrollment ceremony post-deploy |
| `overrides` | map | Per-node template overrides |

### Manual Node

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | **Required**. Node hostname |
| `role` | string | **Required**. Node role |
| `mac` | string | NIC MAC address (e.g., `aa:bb:cc:dd:ee:ff`) |
| `overrides` | map | Per-node template overrides |

### Example

```yaml
nodes:
  # BMC-managed node (TOFU trust-on-first-use)
  - hostname: cp-01
    role: control-plane
    bmc_address: 192.168.1.10
    bmc_user: admin
    bmc_password: "kms://bmc/cp-01/password"
    bmc_protocol: redfish
    bmc_trust: [tofu]

  # Manual node (no BMC)
  - hostname: edge-01
    role: worker
    mac: "aa:bb:cc:dd:ee:ff"
    overrides:
      disk: /dev/nvme0n1
```

## Backups Directory

Optional top-level field specifying where factory-cert backups are written
during the BMC enrollment ceremony (`bmc_enroll: true` nodes). `~` is expanded
to the operator's home directory. Defaults to
`~/sources/automatethethings/infra/backups` when empty.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backups_dir` | string | `~/sources/automatethethings/infra/backups` | Local directory for BMC cert backups |

## Validation Rules

- At least one node is required
- Control-plane count must be 1 or odd >= 3
- Each node must have either `bmc_address` or `mac` (not both empty)
- No duplicate MAC addresses
- No duplicate BMC addresses
- `deployer.host` is required
- `provisioning_network.subnet` is required
- `platform.domain` is required

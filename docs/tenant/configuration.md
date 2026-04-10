# Tenant Configuration Reference

This document provides a complete reference for configuring multi-tenancy in the Trusted Platform, including tenant settings, quota configuration, and isolation options.

## Configuration File Structure

Tenant configuration can be defined in the platform configuration file or via API/CLI.

### Platform Configuration

```yaml
# /etc/platformd/config.yaml
tenancy:
  # Enable multi-tenancy features
  enabled: true

  # Default tenant for resources without explicit tenant assignment
  default_tenant: "default"

  # Global tenant settings
  settings:
    # Maximum number of tenants
    max_tenants: 100

    # VLAN allocation strategy: "sequential" | "random" | "manual"
    vlan_allocation: "sequential"

    # Base VLAN ID for auto-allocation
    vlan_base: 100

    # VLANs reserved per tenant
    vlans_per_tenant: 100

    # Tenant name validation pattern (regex)
    name_pattern: "^[a-z][a-z0-9-]{2,62}$"

    # Auto-cleanup deleted tenants after duration
    cleanup_after: "24h"

  # Default quotas for new tenants
  default_quotas:
    compute:
      max_vms: 10
      max_containers: 50
      max_vcpus: 40
      max_memory_gb: 128
      max_disk_gb: 1000
    network:
      max_bridges: 2
      max_ports: 100
      max_bandwidth_gbps: 1
      max_flow_rules: 1000
    storage:
      max_volumes: 20
      max_snapshots: 50
      max_total_gb: 500

  # Tenant isolation settings
  isolation:
    # Network isolation mode: "vlan" | "vxlan" | "gre"
    network_mode: "vlan"

    # Enable per-tenant OVS bridges
    dedicated_bridges: true

    # Enable per-tenant DEK (data encryption key)
    dedicated_deks: true

    # TPM PCR policy for DEK sealing
    dek_pcr_indices: [0, 1, 2, 3, 7]
```

## Tenant Entity Configuration

### Complete Tenant Definition

```yaml
# Tenant configuration (via API or file import)
tenant:
  # Required fields
  name: "engineering"                    # Unique identifier (lowercase, alphanumeric + hyphen)
  display_name: "Engineering Department" # Human-readable name

  # Optional description
  description: "Engineering team development and staging environment"

  # Contact information
  contact:
    email: "eng-ops@example.com"
    slack: "#eng-platform"
    pagerduty: "PENG123"

  # State (managed by platform, read-only)
  # state: active

  # VLAN configuration
  network:
    # Explicit VLAN range (optional, auto-allocated if not specified)
    vlan_range:
      start: 100
      end: 199

    # Primary OVS bridge name (auto-generated if not specified)
    # bridge_name: "br-tenant-engineering"

    # Default VLAN for untagged traffic
    default_vlan: 100

    # Allowed external networks
    allowed_external:
      - "10.0.0.0/8"
      - "192.168.0.0/16"

  # Compute quotas
  quotas:
    compute:
      max_vms: 50
      max_containers: 200
      max_vcpus: 200
      max_memory_gb: 512
      max_disk_gb: 5000

    network:
      max_bridges: 5
      max_ports: 500
      max_bandwidth_gbps: 10
      max_flow_rules: 10000

    storage:
      max_volumes: 100
      max_snapshots: 500
      max_total_gb: 2000

  # Labels for grouping and filtering
  labels:
    environment: "development"
    cost_center: "CC-1234"
    team: "platform"

  # Annotations for extended metadata
  annotations:
    platform.trusted.io/created-by: "admin@example.com"
    platform.trusted.io/project: "Project Alpha"
```

## Quota Configuration

### Compute Quotas

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_vms` | int64 | 10 | Maximum VM instances |
| `max_containers` | int64 | 50 | Maximum container instances |
| `max_vcpus` | int64 | 40 | Total vCPU cores allowed |
| `max_memory_gb` | int64 | 128 | Total memory in GB |
| `max_disk_gb` | int64 | 1000 | Total disk storage in GB |

```yaml
quotas:
  compute:
    max_vms: 100
    max_containers: 500
    max_vcpus: 400
    max_memory_gb: 1024
    max_disk_gb: 10000
```

### Network Quotas

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_bridges` | int64 | 2 | Maximum OVS bridges |
| `max_ports` | int64 | 100 | Maximum OVS ports |
| `max_bandwidth_gbps` | float64 | 1 | Maximum bandwidth in Gbps |
| `max_flow_rules` | int64 | 1000 | Maximum OpenFlow rules |
| `max_vlans` | int64 | 100 | Maximum VLANs (within assigned range) |

```yaml
quotas:
  network:
    max_bridges: 10
    max_ports: 1000
    max_bandwidth_gbps: 10
    max_flow_rules: 50000
    max_vlans: 100
```

### Storage Quotas

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_volumes` | int64 | 20 | Maximum storage volumes |
| `max_snapshots` | int64 | 50 | Maximum volume snapshots |
| `max_total_gb` | int64 | 500 | Total storage capacity in GB |

```yaml
quotas:
  storage:
    max_volumes: 200
    max_snapshots: 1000
    max_total_gb: 5000
```

## Network Configuration

### VLAN Settings

```yaml
network:
  # VLAN range allocation
  vlan_range:
    start: 100     # First VLAN ID
    end: 199       # Last VLAN ID (inclusive)

  # Default VLAN for untagged traffic
  default_vlan: 100

  # VLAN trunking configuration
  trunk_config:
    enabled: true
    allowed_vlans: [100, 101, 102]

  # 802.1Q priority settings
  priority_mapping:
    high: 7
    medium: 4
    low: 1
    default: 0
```

### OVS Bridge Configuration

```yaml
network:
  # Primary tenant bridge
  bridge:
    # Name (auto-generated as br-tenant-{name} if not specified)
    name: "br-tenant-engineering"

    # Bridge type: "ovs" | "linux"
    type: "ovs"

    # Datapath type: "system" | "netdev" (DPDK)
    datapath_type: "system"

    # OpenFlow controller (optional)
    controller: "tcp:127.0.0.1:6653"

    # Fail mode: "standalone" | "secure"
    fail_mode: "standalone"

    # STP enabled
    stp_enabled: false

    # MTU
    mtu: 9000
```

### Flow Rules Configuration

```yaml
network:
  # Default flow rules for tenant traffic
  default_flows:
    # Allow internal traffic
    - priority: 100
      match:
        in_port: "*"
        vlan_id: "100-199"
      action: "normal"

    # Drop unauthorized traffic
    - priority: 1
      match:
        in_port: "*"
      action: "drop"

  # Rate limiting
  rate_limits:
    enabled: true
    default_rate_mbps: 1000
    burst_size_kb: 10240
```

## Isolation Settings

### Network Isolation

```yaml
isolation:
  network:
    # Isolation mode: "vlan" | "vxlan" | "gre" | "geneve"
    mode: "vlan"

    # Per-tenant bridge (recommended for strong isolation)
    dedicated_bridge: true

    # Prevent inter-tenant traffic
    strict_isolation: true

    # Allow specific cross-tenant communication
    cross_tenant_allowed:
      - source: "engineering"
        destination: "shared-services"
        ports: [443, 80]
```

### Storage Isolation

```yaml
isolation:
  storage:
    # Per-tenant storage namespace
    dedicated_namespace: true

    # Storage path prefix
    path_prefix: "/var/lib/platformd/tenants/{tenant_name}"

    # Encryption at rest
    encryption:
      enabled: true
      # DEK source: "per_tenant" | "shared"
      dek_mode: "per_tenant"
```

### Key Isolation

```yaml
isolation:
  keys:
    # Per-tenant DEK
    dedicated_dek: true

    # TPM sealing policy
    tpm_sealing:
      enabled: true
      pcr_indices: [0, 1, 2, 3, 7]
      pcr_bank: "sha256"

    # Key rotation interval
    rotation_interval: "720h"  # 30 days
```

## Environment Variables

Tenant configuration can be overridden with environment variables:

| Variable | Description |
|----------|-------------|
| `PLATFORMD_TENANCY_ENABLED` | Enable/disable multi-tenancy |
| `PLATFORMD_TENANCY_MAX_TENANTS` | Maximum number of tenants |
| `PLATFORMD_TENANCY_DEFAULT_QUOTA_VMS` | Default VM quota |
| `PLATFORMD_TENANCY_VLAN_BASE` | Base VLAN for allocation |

## Configuration Examples

### Small Team Tenant

```yaml
# Small development team
tenant:
  name: "dev-team-alpha"
  display_name: "Development Team Alpha"

  quotas:
    compute:
      max_vms: 5
      max_containers: 20
      max_vcpus: 20
      max_memory_gb: 64
      max_disk_gb: 500

    network:
      max_bridges: 1
      max_ports: 50
      max_bandwidth_gbps: 1

  labels:
    size: "small"
    tier: "development"
```

### Production Tenant

```yaml
# Production workload tenant
tenant:
  name: "production"
  display_name: "Production Environment"

  network:
    vlan_range:
      start: 200
      end: 299
    default_vlan: 200

  quotas:
    compute:
      max_vms: 200
      max_containers: 1000
      max_vcpus: 1000
      max_memory_gb: 4096
      max_disk_gb: 50000

    network:
      max_bridges: 10
      max_ports: 5000
      max_bandwidth_gbps: 100
      max_flow_rules: 100000

    storage:
      max_volumes: 500
      max_snapshots: 2000
      max_total_gb: 20000

  isolation:
    network:
      strict_isolation: true
      dedicated_bridge: true
    keys:
      dedicated_dek: true
      rotation_interval: "168h"  # 7 days

  labels:
    environment: "production"
    tier: "critical"
    compliance: "soc2"
```

### Shared Services Tenant

```yaml
# Shared services accessible by other tenants
tenant:
  name: "shared-services"
  display_name: "Shared Infrastructure Services"

  network:
    vlan_range:
      start: 50
      end: 99

  # Allow inbound from other tenants
  isolation:
    network:
      strict_isolation: false
      inbound_allowed:
        - source_tenant: "*"
          ports: [443, 80, 53]

  quotas:
    compute:
      max_vms: 20
      max_containers: 50

  labels:
    environment: "shared"
    type: "infrastructure"
```

## Validation Rules

### Tenant Name

- Must be 3-63 characters
- Start with lowercase letter
- Contain only lowercase letters, numbers, and hyphens
- Cannot end with hyphen
- Must be unique across platform

```go
// Name validation regex
var tenantNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)
```

### VLAN Range

- Start must be >= 2 (VLAN 1 is reserved)
- End must be <= 4094
- Range must not overlap with other tenants
- Minimum 10 VLANs per tenant

### Quota Values

- All quota values must be >= 0
- Used values cannot exceed max values
- Quotas can be modified only when usage allows

## Related Documentation

- [Architecture](architecture.md) - Multi-tenancy architecture
- [Isolation](isolation.md) - Isolation mechanisms
- [API Reference](api-reference.md) - API configuration methods
- [CLI Usage](cli-usage.md) - Command-line configuration

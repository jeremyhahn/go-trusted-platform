# Compute Configuration Reference

This document provides a comprehensive reference for configuring the compute orchestrator.

## Status: 100% Complete

The compute orchestrator configuration system is fully implemented and production-ready.

## OrchestratorConfig

The `OrchestratorConfig` struct configures the compute orchestrator behavior.

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/compute"

config := &compute.OrchestratorConfig{
    Type:            compute.ComputeTypeVM,
    WorkDir:         "/var/lib/trusted-platform/compute",
    DefaultMemory:   4096,
    DefaultCPUs:     4,
    DefaultDiskSize: "20G",
    MaxInstances:    100,
    EnableKVM:       true,
    NetworkBridge:   "trusted0",
    OVSSocketPath:   "/var/run/openvswitch/db.sock",
    QEMUBinary:      "qemu-system-x86_64",
    OVMFCode:        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    OVMFCodeSecure:  "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    OVMFVars:        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    PortAuthEnabled: false,
    PolicyEngine:    nil,
}
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| Type | ComputeType | - | Orchestrator type: `vm` or `container` |
| WorkDir | string | `/var/lib/trusted-platform/compute` | Base directory for instance data |
| DefaultMemory | int | 4096 | Default RAM allocation in MB |
| DefaultCPUs | int | runtime.NumCPU() | Default CPU core count |
| DefaultDiskSize | string | `"20G"` | Default disk image size |
| MaxInstances | int | 100 | Maximum concurrent instances |
| EnableKVM | bool | true | Enable KVM hardware acceleration |
| NetworkBridge | string | `"trusted0"` | Default OVS bridge name |
| OVSSocketPath | string | `/var/run/openvswitch/db.sock` | OVSDB Unix socket path |
| QEMUBinary | string | `qemu-system-x86_64` | QEMU executable path |
| OVMFCode | string | `/usr/share/OVMF/OVMF_CODE_4M.fd` | UEFI firmware path |
| OVMFCodeSecure | string | `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` | Secure Boot firmware path |
| OVMFVars | string | `/usr/share/OVMF/OVMF_VARS_4M.fd` | NVRAM template path |
| AutoCleanup | bool | false | Auto-cleanup stopped instances |
| Debug | bool | false | Enable debug logging |
| PortAuthEnabled | bool | false | Enable 802.1X port authentication |
| PolicyEngine | PolicyEngine | nil | SDN policy engine for port auth |

### Default Configuration

Use `DefaultOrchestratorConfig()` for sensible defaults:

```go
// VM orchestrator with defaults
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)

// Container orchestrator with defaults
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeContainer)
```

### Validation

Configuration is validated on orchestrator creation:

```go
if err := config.Validate(); err != nil {
    log.Fatalf("Invalid configuration: %v", err)
}
```

Validation checks:
- Type must be `vm` or `container`
- WorkDir must be non-empty
- DefaultMemory must be greater than 0
- DefaultCPUs must be greater than 0
- DefaultDiskSize must be non-empty
- MaxInstances must be greater than 0
- If PortAuthEnabled, PolicyEngine must not be nil
- For VM type: QEMUBinary, OVMFCode, OVMFVars must be non-empty

## InstanceConfig

Per-instance configuration overrides orchestrator defaults.

```go
instanceConfig := &compute.InstanceConfig{
    Memory:      8192,
    CPUs:        8,
    DiskPath:    "/var/lib/compute/vm-001/disk.qcow2",
    DiskSize:    "50G",
    WorkDir:     "/var/lib/compute/vm-001",
    SecureBoot:  true,
    EnableKVM:   true,
    TPMEnabled:  true,
    NetworkMode: "bridge",
    MACAddress:  "52:54:00:12:34:56",
    BootMode:    "boot",
    ISOPath:     "",
}
```

### Instance Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| Memory | int | RAM allocation in MB |
| CPUs | int | CPU core count |
| DiskPath | string | Path to disk image |
| DiskSize | string | Disk size (e.g., "20G", "100G") |
| WorkDir | string | Instance working directory |
| SecureBoot | bool | Enable UEFI Secure Boot |
| EnableKVM | bool | Enable KVM acceleration |
| TPMEnabled | bool | Enable virtual TPM |
| NetworkMode | string | Network mode: `bridge`, `user`, `none` |
| MACAddress | string | Network MAC address |
| BootMode | string | Boot mode: `install`, `boot`, `pxe` |
| ISOPath | string | Installation ISO path (for install mode) |
| AdditionalDisks | []string | Additional disk image paths |
| Environment | map[string]string | Environment variables |

## YAML Configuration

Configuration can be loaded from YAML files:

```yaml
# /etc/trusted-platform/compute.yaml
compute:
  type: vm
  work_dir: /var/lib/trusted-platform/compute
  default_memory: 4096
  default_cpus: 4
  default_disk_size: "20G"
  max_instances: 100
  enable_kvm: true
  network_bridge: trusted0
  ovs_socket_path: /var/run/openvswitch/db.sock
  qemu_binary: qemu-system-x86_64
  ovmf_code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf_code_secure: /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf_vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  auto_cleanup: false
  debug: false
  port_auth_enabled: false
```

## Environment Variables

Configuration can be overridden via environment variables:

| Environment Variable | Config Field | Example |
|---------------------|--------------|---------|
| COMPUTE_TYPE | Type | `vm` |
| COMPUTE_WORK_DIR | WorkDir | `/var/lib/compute` |
| COMPUTE_DEFAULT_MEMORY | DefaultMemory | `8192` |
| COMPUTE_DEFAULT_CPUS | DefaultCPUs | `4` |
| COMPUTE_MAX_INSTANCES | MaxInstances | `200` |
| COMPUTE_ENABLE_KVM | EnableKVM | `true` |
| COMPUTE_NETWORK_BRIDGE | NetworkBridge | `br0` |
| COMPUTE_OVS_SOCKET | OVSSocketPath | `/var/run/ovs.sock` |
| COMPUTE_QEMU_BINARY | QEMUBinary | `/usr/bin/qemu-system-x86_64` |

## Port Authentication Configuration

When port authentication is enabled, VMs start with restricted network access:

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/compute"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// Create policy engine
policyEngine := policy.NewPolicyEngine(policyConfig)

// Configure orchestrator with port auth
config := &compute.OrchestratorConfig{
    Type:            compute.ComputeTypeVM,
    WorkDir:         "/var/lib/trusted-platform/compute",
    NetworkBridge:   "trusted0",
    PortAuthEnabled: true,
    PolicyEngine:    policyEngine,
}
```

### Port Authentication Flow

1. **Provisioning State (VLAN 998)**
   - VM attached to network
   - Limited access: DHCP, DNS, ACME enrollment
   - Awaiting certificate enrollment

2. **Enrolled State**
   - VM obtained IDevID certificate
   - Awaiting activation

3. **Authorized State (Production VLAN)**
   - Full network access per policy
   - Production VLAN assigned from device profile

### PortAuthConfig

```go
portConfig := &compute.PortAuthConfig{
    PortID:       "vm-abc12345",
    BridgeName:   "trusted0",
    MACAddress:   "52:54:00:12:34:56",
    PolicyEngine: policyEngine,
}
```

## Device Profile Configuration

Instances are created from device profiles which define network configuration:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"

profile := &entities.DeviceProfile{
    Name:  "web-server-001",
    Model: "Standard VM",
    Role:  entities.DeviceRoleServer,

    // Provisioning network (enrollment phase)
    ProvisioningNetwork: &entities.NetworkPhaseConfig{
        VLAN:       998,
        AuthMethod: entities.AuthMethod802_1X,
        Gateway:    "10.99.98.1",
        DNS:        []string{"10.99.98.53"},
    },

    // Production network (after enrollment)
    ProductionNetwork: &entities.NetworkPhaseConfig{
        VLAN:       100,
        AuthMethod: entities.AuthMethod802_1X,
        Gateway:    "10.0.100.1",
        DNS:        []string{"10.0.100.53"},
    },
}
```

## swtpm Configuration

Virtual TPM is configured automatically per instance:

```
Instance Directory Structure:
{WorkDir}/{instanceID}/
    disk.qcow2          # VM disk image
    ovmf_vars.fd        # Per-instance NVRAM
    tpm/
        tpm2-00.permall # TPM permanent state
        .lock           # Lock file
        swtpm.sock      # Unix socket (runtime)
        swtpm.log       # Daemon logs
```

### TPM Configuration Details

| Setting | Value |
|---------|-------|
| TPM Version | 2.0 |
| PCR Banks | SHA-256 |
| Socket Mode | QEMU control channel |
| State Directory | `{workDir}/tpm/` |
| Socket Path | `{workDir}/tpm/swtpm.sock` |

## QEMU Configuration

### Generated QEMU Command

The orchestrator generates QEMU commands with these options:

```bash
qemu-system-x86_64 \
    -name <instance-name> \
    -machine q35,accel=kvm \
    -cpu host \
    -smp <cpus> \
    -m <memory> \
    -drive file=<disk>,format=qcow2,if=virtio \
    -drive if=pflash,format=raw,readonly=on,file=<OVMF_CODE> \
    -drive if=pflash,format=raw,file=<OVMF_VARS> \
    -netdev tap,id=net0,ifname=<tap>,script=no,downscript=no \
    -device virtio-net-pci,netdev=net0,mac=<mac> \
    -chardev socket,id=chrtpm,path=<swtpm.sock> \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -monitor unix:<monitor.sock>,server,nowait \
    -nographic
```

### Firmware Selection

| Boot Mode | Firmware |
|-----------|----------|
| Standard UEFI | OVMF_CODE_4M.fd |
| Secure Boot | OVMF_CODE_4M.secboot.fd |

## Resource Limits

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM per VM | 512 MB | 4096 MB |
| CPUs per VM | 1 | 2-4 |
| Disk per VM | 5 GB | 20 GB |
| Max Instances | - | 100 (configurable) |

### Performance Tuning

```go
config := &compute.OrchestratorConfig{
    // High-density configuration
    DefaultMemory:   2048,    // 2 GB per VM
    DefaultCPUs:     2,       // 2 cores per VM
    MaxInstances:    200,     // More instances
    EnableKVM:       true,    // Required for performance

    // High-performance configuration
    DefaultMemory:   16384,   // 16 GB per VM
    DefaultCPUs:     8,       // 8 cores per VM
    MaxInstances:    50,      // Fewer instances
}
```

## Security Configuration

### Recommended Production Settings

```go
config := &compute.OrchestratorConfig{
    // Enable security features
    EnableKVM:        true,   // Required for VM isolation
    PortAuthEnabled:  true,   // 802.1X authentication

    // Secure Boot (per-instance)
    // Set via InstanceConfig.SecureBoot = true
}
```

### Network Isolation

```yaml
# OVS bridge configuration
network_bridge: trusted0

# VLAN assignments
provisioning_vlan: 998    # Enrollment network
production_vlan: 100      # Production network
quarantine_vlan: 666      # Quarantine network
```

## Troubleshooting Configuration

### Common Issues

**KVM not available:**
```bash
# Check KVM module
ls -l /dev/kvm
# Expected: crw-rw---- 1 root kvm

# Add user to kvm group
sudo usermod -aG kvm $USER
```

**OVMF firmware not found:**
```bash
# Install OVMF
sudo apt-get install ovmf

# Verify paths
ls -l /usr/share/OVMF/
```

**OVS socket not accessible:**
```bash
# Check OVS service
systemctl status openvswitch-switch

# Verify socket
ls -l /var/run/openvswitch/db.sock
```

### Debug Mode

Enable debug logging for troubleshooting:

```go
config := &compute.OrchestratorConfig{
    Debug: true,
}
```

Or via environment:
```bash
export COMPUTE_DEBUG=true
```

## Container Configuration

### ContainerConfig in Device Profile

Containers are configured within Device Profiles alongside VMs:

```yaml
device_profile:
  name: "production-web-tier"

  # OS info used for init system auto-detection
  os:
    name: "debian"      # Auto-detects systemd
    version: "12"

  containers:
    - name: "web-api"
      image: "registry.example.com/api:v1.2"

      # Resource limits
      resources:
        memory: "2G"
        cpus: "2.0"

      # Environment variables
      environment:
        DB_HOST: "db.internal"
        LOG_LEVEL: "info"

      # Network configuration
      network:
        mode: sdn          # sdn, bridge, host, none
        vlan: 100
        security_groups:
          - web-frontend

      # Service mode configuration
      service:
        mode: embedded     # embedded or standalone
```

### ContainerConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| name | string | Container name (unique within profile) |
| image | string | Container image reference |
| resources | ResourceConfig | CPU and memory limits |
| environment | map[string]string | Environment variables |
| network | NetworkConfig | Network mode and SDN config |
| service | ServiceConfig | Service mode (embedded/standalone) |
| volumes | []VolumeMount | Volume mount specifications |
| ports | []PortMapping | Port mappings |

### Service Mode Configuration

Service mode determines how containers are managed:

```yaml
containers:
  # Embedded mode (default) - platformd manages directly
  - name: "sidecar-proxy"
    image: "envoyproxy/envoy:v1.28"
    service:
      mode: embedded

  # Standalone mode - runs as init system service
  - name: "database"
    image: "postgres:16"
    service:
      mode: standalone
      standalone:
        # Init system auto-detected from os.name, override if needed
        # init_system: systemd  # or "rc" for OpenRC
        restart: always
        after:
          - network-online.target
          - platformd.service
        memory_max: "4G"
        cpu_quota: "200%"
```

### Init System Auto-Detection

When `mode: standalone` is set, the init system is auto-detected from the
Device Profile OS configuration:

| OS Name | Init System |
|---------|-------------|
| alpine, gentoo, artix | rc (OpenRC) |
| debian, ubuntu, fedora, centos, rhel, rocky, alma, arch, opensuse | systemd |

Override with explicit `init_system` field if needed.

### ServiceConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| mode | string | embedded | Service mode: `embedded` or `standalone` |
| standalone.init_system | string | (auto) | Override init system detection |
| standalone.restart | string | always | Restart policy: `always`, `on-failure`, `no` |
| standalone.after | []string | - | Service dependencies (systemd After=) |
| standalone.wants | []string | - | Service wants (systemd Wants=) |
| standalone.cpu_quota | string | - | CPU quota (e.g., "200%") |
| standalone.memory_max | string | - | Memory limit (e.g., "4G") |

## Container Network Configuration

Containers use the same SDN/OVS network model as VMs:

```yaml
device_profile:
  network:
    ovs_bridge: "br-platform"
    default_vlan: 100

    # OpenFlow controller
    openflow:
      controller: "tcp:127.0.0.1:6653"
      version: "1.3"

    # Security groups (shared with VMs)
    security_groups:
      - name: "web-frontend"
        rules:
          - direction: ingress
            protocol: tcp
            port: 443
            action: allow
          - direction: egress
            protocol: tcp
            port: 5432
            action: allow

      - name: "backend-services"
        rules:
          - direction: ingress
            protocol: tcp
            port_range: "8080-8090"
            action: allow

    # Physical interfaces under OVS control
    physical_interfaces:
      - name: "eth0"
        bridge: "br-platform"
        vlan: 1
        trunk: false

      - name: "eth1"
        bridge: "br-platform"
        trunk: true
        trunk_vlans: [100, 200, 300]
```

### Container Network Modes

| Mode | Description |
|------|-------------|
| sdn | Full SDN/OVS/OpenFlow integration (recommended) |
| bridge | Standard container bridge networking |
| host | Share host network namespace |
| none | No networking |

### SDN Network Config

When `mode: sdn`, the following fields apply:

| Field | Type | Description |
|-------|------|-------------|
| vlan | uint16 | VLAN ID for container |
| security_groups | []string | Security group names to apply |
| ip_address | string | Static IP (optional) |

## Container Policy Configuration

OPA policies control container creation and runtime:

```yaml
container_policy:
  # Enable built-in security policies
  enable_builtin_policies: true

  # Custom policy directory
  custom_policy_dir: "/etc/platformd/policies/container/"

  # Remote policy bundle (optional)
  policy_bundle_url: "https://policies.example.com/container.tar.gz"

  # Enforcement mode
  decision_mode: enforce   # enforce, audit, disabled
```

### Policy Decision Modes

| Mode | Behavior |
|------|----------|
| enforce | Block container creation on policy violation |
| audit | Log violations but allow creation |
| disabled | Skip policy evaluation |

### Custom Policy Example

```rego
# /etc/platformd/policies/container/custom.rego
package container.custom

# Restrict to specific registries
deny[msg] {
    registry := input.image.registry
    allowed := {"registry.example.com", "docker.io"}
    not allowed[registry]
    msg := sprintf("Image registry %s not allowed", [registry])
}

# Block 'latest' tag in production
deny[msg] {
    input.image.tag == "latest"
    msg := "Tag 'latest' not allowed"
}

# Require maintainer label
deny[msg] {
    not input.image.labels["maintainer"]
    msg := "Image must have 'maintainer' label"
}
```

## Full Container Example

Complete Device Profile with containers:

```yaml
device_profile:
  name: "web-application"

  os:
    name: "debian"
    version: "12"

  network:
    ovs_bridge: "br-platform"
    default_vlan: 100
    openflow:
      controller: "tcp:127.0.0.1:6653"
      version: "1.3"
    security_groups:
      - name: "web"
        rules:
          - direction: ingress
            protocol: tcp
            port: 443
            action: allow

  containers:
    - name: "nginx"
      image: "nginx:1.25"
      resources:
        memory: "512M"
        cpus: "1.0"
      network:
        mode: sdn
        vlan: 100
        security_groups: ["web"]
      service:
        mode: embedded

    - name: "api"
      image: "registry.example.com/api:v2.0"
      resources:
        memory: "2G"
        cpus: "2.0"
      environment:
        DB_HOST: "postgres"
        REDIS_HOST: "redis"
      network:
        mode: sdn
        vlan: 100
        security_groups: ["web"]
      service:
        mode: standalone
        standalone:
          restart: always
          after:
            - network-online.target
          memory_max: "2G"

    - name: "postgres"
      image: "postgres:16"
      resources:
        memory: "4G"
        cpus: "2.0"
      environment:
        POSTGRES_PASSWORD_FILE: "/run/secrets/pg_password"
      volumes:
        - source: "/var/lib/postgres"
          target: "/var/lib/postgresql/data"
      network:
        mode: sdn
        vlan: 200
      service:
        mode: standalone
        standalone:
          restart: always
          memory_max: "4G"
```

## See Also

- [Architecture](architecture.md) - System design overview
- [Container Orchestrator](container-orchestrator.md) - Container orchestrator details
- [API Reference](api-reference.md) - API documentation
- [CLI Usage](cli-usage.md) - Command-line interface
- [swtpm Integration](swtpm-integration.md) - vTPM details
- [802.1X Network Attachment](802.1X-network-attachment.md) - Port authentication

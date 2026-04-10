# DHCP Configuration Reference

## Overview

This document provides a comprehensive configuration reference for the go-trusted-platform DHCP service, covering server configuration, interface bindings, DHCP options, and plugin settings.

## Configuration Structure

### YAML Configuration

```yaml
dhcp:
  # Server configuration
  server:
    default_lease_duration: "24h"
    ipam_backend: "memory"  # memory, quicbaas, dht
    ipam_config:
      # Backend-specific settings
      quicbaas_partition: "dhcp/leases"

  # Interface bindings
  interfaces:
    - name: "eth0"
      network: "private"
      address: "192.168.1.1"
      pool_id: "internal-pool"
      options:
        subnet_mask: "255.255.255.0"
        router: "192.168.1.1"
        dns:
          - "8.8.8.8"
          - "8.8.4.4"
        domain_name: "example.local"
        lease_time: "24h"
        renewal_time: "12h"
        rebind_time: "21h"
        ntp_servers:
          - "pool.ntp.org"
        mtu: 1500

    - name: "eth1"
      network: "public"
      address: "10.0.0.1"
      pool_id: "public-pool"
      options:
        subnet_mask: "255.255.255.0"
        router: "10.0.0.1"
        dns:
          - "1.1.1.1"
        lease_time: "8h"

  # PXE boot configuration (optional)
  pxe:
    enabled: true
    next_server: "192.168.1.10"
    boot_file: "pxelinux.0"
    tftp_root: "/var/lib/tftpboot"
    architecture_filters:
      0: "pxelinux.0"      # BIOS
      7: "shimx64.efi"     # UEFI x64
      11: "shimaa64.efi"   # ARM64 UEFI

  # Logging
  logging:
    level: "info"
    format: "json"
```

## Server Configuration

### ServerConfig

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `default_lease_duration` | duration | No | 24h | Default lease duration for all interfaces |
| `ipam_backend` | string | No | "memory" | IPAM storage backend |
| `ipam_config` | map | No | {} | Backend-specific configuration |

```go
type ServerConfig struct {
    Interfaces           []InterfaceConfig
    DefaultLeaseDuration time.Duration
    IPAMBackend          string
    IPAMConfig           map[string]string
}
```

### IPAM Backend Options

| Backend | Value | Description | Use Case |
|---------|-------|-------------|----------|
| Memory | `memory` | In-memory storage | Single instance, development |
| QuicBaaS | `quicbaas` | Distributed database | HA production deployments |
| DHT | `dht` | Distributed hash table | P2P/edge deployments |

```yaml
# Memory backend (default)
ipam_backend: "memory"

# QuicBaaS backend
ipam_backend: "quicbaas"
ipam_config:
  quicbaas_partition: "dhcp/leases"
  quicbaas_replication: "3"

# DHT backend
ipam_backend: "dht"
ipam_config:
  dht_bootstrap: "node1:9000,node2:9000"
```

## Interface Configuration

### InterfaceConfig

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Network interface name (eth0, br0) |
| `network` | string | No | "" | Network type: "public" or "private" |
| `address` | string | Yes | - | Server IP address on this interface |
| `pool_id` | string | Yes | - | IPAM pool ID for allocations |
| `options` | DHCPOptions | No | {} | DHCP options for this interface |

```go
type InterfaceConfig struct {
    Name    string
    Network string        // "public" or "private"
    Address netip.Addr
    PoolID  string
    Options DHCPOptions
}
```

### Network Types

| Type | Constant | Description |
|------|----------|-------------|
| Public | `public` | Internet-facing network |
| Private | `private` | Internal/management network |

```yaml
interfaces:
  # Public-facing network
  - name: "eth0"
    network: "public"
    address: "203.0.113.1"
    pool_id: "public-v4"

  # Internal management network
  - name: "eth1"
    network: "private"
    address: "192.168.1.1"
    pool_id: "mgmt-pool"
```

## DHCP Options

### DHCPOptions

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `subnet_mask` | string | No | - | Subnet mask (option 1) |
| `router` | string | No | - | Default gateway (option 3) |
| `dns` | []string | No | [] | DNS servers (option 6) |
| `domain_name` | string | No | "" | Domain name (option 15) |
| `lease_time` | duration | No | 24h | Lease duration (option 51) |
| `renewal_time` | duration | No | 50% lease | T1 renewal time (option 58) |
| `rebind_time` | duration | No | 87.5% lease | T2 rebinding time (option 59) |
| `ntp_servers` | []string | No | [] | NTP servers (option 42) |
| `mtu` | int | No | 0 | Interface MTU (option 26) |
| `hostname` | string | No | "" | Client hostname (option 12) |
| `next_server` | string | No | "" | TFTP server for PXE (siaddr) |
| `boot_file_name` | string | No | "" | Boot file name (option 67) |

```go
type DHCPOptions struct {
    SubnetMask   net.IPMask
    Router       netip.Addr
    DNS          []netip.Addr
    DomainName   string
    LeaseTime    time.Duration
    RenewalTime  time.Duration
    RebindTime   time.Duration
    NTPServers   []netip.Addr
    MTU          uint16
    Hostname     string
    NextServer   net.IP
    BootFileName string
}
```

### Lease Time Configuration

```yaml
options:
  # Full lease configuration
  lease_time: "24h"      # Total lease duration
  renewal_time: "12h"    # T1: Start unicast renewal (50%)
  rebind_time: "21h"     # T2: Start broadcast renewal (87.5%)

  # Defaults if not specified
  # renewal_time = lease_time / 2
  # rebind_time = lease_time * 7 / 8
```

### DNS and Domain Configuration

```yaml
options:
  # Multiple DNS servers
  dns:
    - "8.8.8.8"          # Google primary
    - "8.8.4.4"          # Google secondary
    - "1.1.1.1"          # Cloudflare

  # Domain search configuration
  domain_name: "corp.example.com"
```

### NTP Configuration

```yaml
options:
  ntp_servers:
    - "0.pool.ntp.org"
    - "1.pool.ntp.org"
    - "time.google.com"
```

## PXE Configuration

### PXEOptions

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable PXE support |
| `next_server` | string | Yes | - | TFTP server IP address |
| `boot_file` | string | Yes | - | Default boot file name |
| `tftp_root` | string | No | "" | TFTP root directory |
| `architecture_filters` | map | No | {} | Per-architecture boot files |

```go
type PXEOptions struct {
    NextServer          net.IP
    BootFileName        string
    TFTPRoot            string
    ArchitectureFilters map[uint16]string
}
```

### Architecture Codes

| Code | Constant | Architecture |
|------|----------|--------------|
| 0 | `PXEArchIntelX86` | Intel x86 BIOS |
| 6 | `PXEArchEFIIA32` | EFI IA32 |
| 7 | `PXEArchEFIX8664` | EFI x86-64 (UEFI) |
| 9 | `PXEArchEFIBC` | EFI Byte Code |
| 10 | `PXEArchARMUEFI32` | ARM 32-bit UEFI |
| 11 | `PXEArchARMUEFI64` | ARM 64-bit UEFI |
| 15 | `PXEArchX8664HTTP` | x86-64 UEFI HTTP |

### PXE Examples

```yaml
# Basic PXE configuration
pxe:
  enabled: true
  next_server: "192.168.1.10"
  boot_file: "pxelinux.0"

# Multi-architecture PXE
pxe:
  enabled: true
  next_server: "192.168.1.10"
  boot_file: "pxelinux.0"  # Default for unknown architectures
  tftp_root: "/var/lib/tftpboot"
  architecture_filters:
    0: "pxelinux.0"        # BIOS
    6: "bootia32.efi"      # 32-bit UEFI
    7: "shimx64.efi"       # 64-bit UEFI (Secure Boot)
    11: "shimaa64.efi"     # ARM64 UEFI

# iPXE chainloading
pxe:
  enabled: true
  next_server: "192.168.1.10"
  boot_file: "undionly.kpxe"  # BIOS iPXE
  architecture_filters:
    7: "ipxe.efi"           # UEFI iPXE
```

## Complete Configuration Examples

### Single Interface (Simple)

```yaml
dhcp:
  server:
    default_lease_duration: "24h"
    ipam_backend: "memory"

  interfaces:
    - name: "eth0"
      network: "private"
      address: "192.168.1.1"
      pool_id: "default-pool"
      options:
        subnet_mask: "255.255.255.0"
        router: "192.168.1.1"
        dns:
          - "8.8.8.8"
        domain_name: "local"
        lease_time: "24h"
```

### Multi-Interface (Enterprise)

```yaml
dhcp:
  server:
    default_lease_duration: "24h"
    ipam_backend: "quicbaas"
    ipam_config:
      quicbaas_partition: "dhcp/leases"

  interfaces:
    # Management network
    - name: "eth0"
      network: "private"
      address: "10.10.0.1"
      pool_id: "mgmt-pool"
      options:
        subnet_mask: "255.255.255.0"
        router: "10.10.0.1"
        dns:
          - "10.10.0.10"
          - "10.10.0.11"
        domain_name: "mgmt.corp.example.com"
        ntp_servers:
          - "10.10.0.100"
        lease_time: "168h"  # 7 days for management

    # Production network
    - name: "eth1"
      network: "private"
      address: "10.20.0.1"
      pool_id: "prod-pool"
      options:
        subnet_mask: "255.255.0.0"
        router: "10.20.0.1"
        dns:
          - "10.20.0.10"
          - "10.20.0.11"
        domain_name: "prod.corp.example.com"
        ntp_servers:
          - "10.20.0.100"
        lease_time: "24h"

    # Guest network
    - name: "eth2"
      network: "public"
      address: "172.16.0.1"
      pool_id: "guest-pool"
      options:
        subnet_mask: "255.255.255.0"
        router: "172.16.0.1"
        dns:
          - "8.8.8.8"
          - "1.1.1.1"
        domain_name: "guest.example.com"
        lease_time: "4h"  # Short lease for guests
        mtu: 1400

  pxe:
    enabled: true
    next_server: "10.10.0.50"
    boot_file: "pxelinux.0"
    tftp_root: "/var/lib/tftpboot"
    architecture_filters:
      0: "pxelinux.0"
      7: "shimx64.efi"

  logging:
    level: "info"
    format: "json"
```

### IoT/Edge Deployment

```yaml
dhcp:
  server:
    default_lease_duration: "1h"
    ipam_backend: "dht"
    ipam_config:
      dht_bootstrap: "gateway-1:9000,gateway-2:9000"

  interfaces:
    # Provisioning network
    - name: "br-prov"
      network: "private"
      address: "192.168.100.1"
      pool_id: "provisioning"
      options:
        subnet_mask: "255.255.255.0"
        router: "192.168.100.1"
        dns:
          - "192.168.100.1"
        domain_name: "prov.iot.local"
        lease_time: "15m"  # Short lease during provisioning

    # Production IoT network
    - name: "br-iot"
      network: "private"
      address: "10.100.0.1"
      pool_id: "iot-devices"
      options:
        subnet_mask: "255.255.0.0"
        router: "10.100.0.1"
        dns:
          - "10.100.0.1"
        domain_name: "iot.local"
        lease_time: "12h"
        mtu: 1280  # IPv6 minimum MTU for IoT
```

## Environment Variables

Configuration values can reference environment variables:

| Variable | Description |
|----------|-------------|
| `DHCP_LEASE_DURATION` | Default lease duration |
| `DHCP_IPAM_BACKEND` | IPAM backend type |
| `DHCP_LOG_LEVEL` | Logging level |
| `DHCP_PXE_ENABLED` | Enable PXE support |
| `DHCP_PXE_SERVER` | PXE/TFTP server address |

```yaml
dhcp:
  server:
    default_lease_duration: ${DHCP_LEASE_DURATION}
    ipam_backend: ${DHCP_IPAM_BACKEND}

  pxe:
    enabled: ${DHCP_PXE_ENABLED}
    next_server: ${DHCP_PXE_SERVER}
```

## Go Configuration

### Programmatic Configuration

```go
import (
    "net"
    "net/netip"
    "time"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Create server configuration
config := &dhcp.ServerConfig{
    Interfaces: []dhcp.InterfaceConfig{
        {
            Name:    "eth0",
            Network: dhcp.NetworkPrivate,
            Address: netip.MustParseAddr("192.168.1.1"),
            PoolID:  "internal-pool",
            Options: dhcp.DHCPOptions{
                SubnetMask: net.CIDRMask(24, 32),
                Router:     netip.MustParseAddr("192.168.1.1"),
                DNS: []netip.Addr{
                    netip.MustParseAddr("8.8.8.8"),
                    netip.MustParseAddr("8.8.4.4"),
                },
                DomainName:  "example.local",
                LeaseTime:   24 * time.Hour,
                RenewalTime: 12 * time.Hour,
                RebindTime:  21 * time.Hour,
                NTPServers: []netip.Addr{
                    netip.MustParseAddr("129.6.15.28"),
                },
                MTU: 1500,
            },
        },
    },
    DefaultLeaseDuration: 24 * time.Hour,
    IPAMBackend:          dhcp.IPAMBackendMemory,
}

// Validate configuration
if err := config.Validate(); err != nil {
    return err
}

// Create allocator
allocator := ipam.NewMemoryAllocator()

// Create server with options
server, err := dhcp.NewCoreDHCPServer(
    config,
    allocator,
    dhcp.WithCoreDHCPLogger(logger),
    dhcp.WithCoreDHCPLeaseStore(customLeaseStore),
)
```

### PXE Plugin Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"

// Create PXE plugin
pxe, err := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),  // TFTP server
    "pxelinux.0",                  // Default boot file
    dhcp.WithPXELogger(logger),
    dhcp.WithTFTPRoot("/var/lib/tftpboot"),
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchIntelX86:  "pxelinux.0",
        dhcp.PXEArchEFIX8664:  "shimx64.efi",
        dhcp.PXEArchARMUEFI64: "shimaa64.efi",
    }),
)
if err != nil {
    return err
}
```

## Validation

### Configuration Validation

The configuration is validated at creation time:

```go
// ServerConfig validation
func (c *ServerConfig) Validate() error {
    if c == nil {
        return ErrInvalidConfig
    }
    if len(c.Interfaces) == 0 {
        return ErrNoInterfacesConfigured
    }
    for i := range c.Interfaces {
        if err := c.Interfaces[i].Validate(); err != nil {
            return err
        }
    }
    // Validate IPAM backend
    switch c.IPAMBackend {
    case IPAMBackendMemory, IPAMBackendQuicBaaS, IPAMBackendDHT:
        // Valid
    default:
        return ErrIPAMBackendInvalid
    }
    return nil
}

// InterfaceConfig validation
func (c *InterfaceConfig) Validate() error {
    if c.Name == "" {
        return ErrInvalidInterface
    }
    if !c.Address.IsValid() {
        return ErrInvalidInterface
    }
    if c.PoolID == "" {
        return ErrPoolIDRequired
    }
    return nil
}

// DHCPOptions validation (sets defaults)
func (o *DHCPOptions) Validate() error {
    if o.LeaseTime == 0 {
        o.LeaseTime = DefaultLeaseDuration
    }
    if o.RenewalTime == 0 {
        o.RenewalTime = o.LeaseTime / 2
    }
    if o.RebindTime == 0 {
        o.RebindTime = o.LeaseTime * 7 / 8
    }
    return nil
}
```

### Validation Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidConfig` | Configuration is nil |
| `ErrNoInterfacesConfigured` | No interfaces defined |
| `ErrInvalidInterface` | Interface name or address invalid |
| `ErrPoolIDRequired` | Pool ID not specified |
| `ErrIPAMBackendInvalid` | Unknown IPAM backend |
| `ErrInvalidNextServer` | PXE server address invalid |
| `ErrInvalidBootFile` | Boot file name empty |

## Default Values

| Option | Default Value | Notes |
|--------|---------------|-------|
| Lease Time | 24 hours | `DefaultLeaseDuration` |
| Renewal Time (T1) | 50% of lease | 12 hours with default lease |
| Rebind Time (T2) | 87.5% of lease | 21 hours with default lease |
| IPAM Backend | memory | Single instance only |
| MTU | 0 (not sent) | Set explicitly if needed |

## See Also

- [README](README.md) - Package overview
- [Architecture](architecture.md) - Component design
- [Plugins](plugins.md) - Plugin documentation
- [API Reference](api-reference.md) - API overview

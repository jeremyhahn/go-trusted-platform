# VXLAN Overlay Configuration Reference

## Overview

This document provides a comprehensive reference for configuring the VXLAN overlay subsystem, including VTEP settings, VNI management, tunnel parameters, and integration options.

## Platform Configuration (YAML)

### Complete Configuration Example

```yaml
sdn:
  enabled: true
  bridge_name: "br-int"

  overlay:
    enabled: true

    # VTEP Configuration
    vtep_ip: "10.0.0.1"
    underlay_interface: "eth0"
    underlay_mtu: 9000
    vxlan_port: 4789

    # VNI Configuration
    vni_base: 1000000
    vni_max: 16777215

    # Tunnel Configuration
    tunnel_health_interval: 10s
    tunnel_health_timeout: 5s
    tunnel_retry_interval: 30s
    tunnel_max_retries: 3

    # MAC Learning
    mac_table_size: 65536
    mac_aging_time: 300s
    mac_learning_enabled: true

    # ARP Suppression
    arp_suppression_enabled: true
    arp_cache_size: 16384
    arp_cache_ttl: 300s

    # BUM Handling
    bum_handling: "head-end-replication"
    multicast_group: ""  # Optional multicast group base

    # QuicBaaS Settings
    state_sync_interval: 1s
    state_consistency: "eventual"  # "eventual" or "linearizable"

    # Performance Tuning
    flow_batch_size: 100
    flow_install_timeout: 5s

  # OVSDB Configuration
  ovsdb:
    socket: "/var/run/openvswitch/db.sock"
    database: "Open_vSwitch"
    timeout: 30s

  # OpenFlow Configuration
  openflow:
    socket_dir: "/var/run/openvswitch"
    version: "1.3"
    timeout: 30s
```

## Configuration Parameters

### VTEP Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| vtep_ip | string | Required | IP address for VTEP (must be reachable from other hosts) |
| underlay_interface | string | Required | Physical interface for VXLAN traffic |
| underlay_mtu | int | 9000 | MTU of underlay network (9000 for jumbo frames) |
| vxlan_port | int | 4789 | UDP port for VXLAN encapsulation |

### VNI Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| vni_base | uint32 | 1000000 | Base VNI for VLAN-to-VNI mapping |
| vni_max | uint32 | 16777215 | Maximum VNI value (24-bit space) |

### Tunnel Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| tunnel_health_interval | duration | 10s | Interval between tunnel health checks |
| tunnel_health_timeout | duration | 5s | Timeout for health check response |
| tunnel_retry_interval | duration | 30s | Interval between tunnel reconnection attempts |
| tunnel_max_retries | int | 3 | Maximum retries before marking tunnel unhealthy |

### MAC Learning Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| mac_table_size | int | 65536 | Maximum entries in MAC table per VNI |
| mac_aging_time | duration | 300s | Time before MAC entries expire |
| mac_learning_enabled | bool | true | Enable/disable MAC learning |

### ARP Suppression Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| arp_suppression_enabled | bool | true | Enable ARP proxy to reduce broadcast |
| arp_cache_size | int | 16384 | Maximum ARP cache entries |
| arp_cache_ttl | duration | 300s | ARP cache entry lifetime |

### BUM Handling Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| bum_handling | string | "head-end-replication" | BUM strategy: "head-end-replication" or "multicast" |
| multicast_group | string | "" | Base multicast group (e.g., "239.0.0.0") |

### State Synchronization

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| state_sync_interval | duration | 1s | Interval for state synchronization to QuicBaaS |
| state_consistency | string | "eventual" | Consistency level: "eventual" or "linearizable" |

### Performance Tuning

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| flow_batch_size | int | 100 | Number of flows per OVS transaction |
| flow_install_timeout | duration | 5s | Timeout for flow installation |

## Per-VNI Configuration

Individual VNIs can have custom settings.

```yaml
sdn:
  overlay:
    enabled: true
    vni_base: 1000000

    # Per-VNI overrides
    vnis:
      - vni: 1000100  # VLAN 100
        multicast_group: "239.0.0.100"
        mac_table_size: 32768
        mac_aging_time: 600s

      - vni: 1000200  # VLAN 200
        multicast_group: "239.0.0.200"
        mac_table_size: 16384
        bum_handling: "multicast"
```

### VNI-Specific Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| vni | uint32 | Required | VNI identifier |
| multicast_group | string | "" | Multicast group for this VNI |
| mac_table_size | int | (global) | Override global MAC table size |
| mac_aging_time | duration | (global) | Override global MAC aging |
| bum_handling | string | (global) | Override global BUM strategy |

## Tunnel Configuration

Explicit tunnel configuration for specific remote VTEPs.

```yaml
sdn:
  overlay:
    enabled: true

    # Static tunnel configuration
    tunnels:
      - remote_vtep: "10.0.0.2"
        vnis: [1000100, 1000200]
        priority: 100
        enabled: true

      - remote_vtep: "10.0.0.3"
        vnis: [1000100]
        priority: 50
        enabled: true
```

### Tunnel Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| remote_vtep | string | Required | Remote VTEP IP address |
| vnis | []uint32 | [] | VNIs to tunnel (empty = auto-discover) |
| priority | int | 100 | Tunnel priority for failover |
| enabled | bool | true | Enable/disable this tunnel |

## Go Configuration API

### Programmatic Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"

// Create overlay configuration
config := &overlay.Config{
    Enabled:           true,
    VTEPIP:            net.ParseIP("10.0.0.1"),
    UnderlayInterface: "eth0",
    UnderlayMTU:       9000,
    VXLANPort:         4789,
    VNIBase:           1000000,
    VNIMax:            16777215,

    TunnelHealthInterval: 10 * time.Second,
    TunnelHealthTimeout:  5 * time.Second,
    TunnelRetryInterval:  30 * time.Second,
    TunnelMaxRetries:     3,

    MACTableSize:       65536,
    MACAgingTime:       5 * time.Minute,
    MACLearningEnabled: true,

    ARPSuppressionEnabled: true,
    ARPCacheSize:          16384,
    ARPCacheTTL:           5 * time.Minute,

    BUMHandling:    overlay.BUMHeadEndReplication,
    MulticastGroup: nil,

    StateSyncInterval:  time.Second,
    StateConsistency:   overlay.ConsistencyEventual,

    FlowBatchSize:       100,
    FlowInstallTimeout:  5 * time.Second,
}

// Create overlay manager
manager, err := overlay.NewManager(ctx, config, ovsClient, ofClient, store, logger)
if err != nil {
    return err
}

// Start overlay manager
if err := manager.Start(ctx); err != nil {
    return err
}
```

### Configuration Options Pattern

```go
// Create manager with options
manager, err := overlay.NewManager(ctx, config, ovsClient, ofClient, store, logger,
    overlay.WithMACTableSize(128000),
    overlay.WithARPSuppression(true),
    overlay.WithHealthCheckInterval(5*time.Second),
    overlay.WithBUMHandling(overlay.BUMMulticast, "239.0.0.0"),
)
```

### Configuration Options

```go
// Available options
func WithMACTableSize(size int) Option
func WithMACAgingTime(d time.Duration) Option
func WithARPSuppression(enabled bool) Option
func WithARPCacheSize(size int) Option
func WithHealthCheckInterval(d time.Duration) Option
func WithHealthCheckTimeout(d time.Duration) Option
func WithBUMHandling(mode BUMMode, multicastBase string) Option
func WithStateConsistency(level ConsistencyLevel) Option
func WithFlowBatchSize(size int) Option
```

## Environment Variables

Environment variables override YAML configuration.

| Variable | Default | Description |
|----------|---------|-------------|
| SDN_OVERLAY_ENABLED | false | Enable overlay networking |
| SDN_OVERLAY_VTEP_IP | - | VTEP IP address |
| SDN_OVERLAY_UNDERLAY_IFACE | eth0 | Underlay interface |
| SDN_OVERLAY_UNDERLAY_MTU | 9000 | Underlay MTU |
| SDN_OVERLAY_VXLAN_PORT | 4789 | VXLAN UDP port |
| SDN_OVERLAY_VNI_BASE | 1000000 | VNI base for VLAN mapping |
| SDN_OVERLAY_MAC_TABLE_SIZE | 65536 | MAC table size |
| SDN_OVERLAY_MAC_AGING | 300 | MAC aging time (seconds) |
| SDN_OVERLAY_ARP_SUPPRESS | true | Enable ARP suppression |
| SDN_OVERLAY_HEALTH_INTERVAL | 10 | Health check interval (seconds) |

## Multi-Host Deployment

### Host A Configuration

```yaml
# /etc/platformd/config.yaml on Host A
sdn:
  overlay:
    enabled: true
    vtep_ip: "10.0.0.1"
    underlay_interface: "eth0"
    underlay_mtu: 9000
```

### Host B Configuration

```yaml
# /etc/platformd/config.yaml on Host B
sdn:
  overlay:
    enabled: true
    vtep_ip: "10.0.0.2"
    underlay_interface: "eth0"
    underlay_mtu: 9000
```

### Host C Configuration

```yaml
# /etc/platformd/config.yaml on Host C
sdn:
  overlay:
    enabled: true
    vtep_ip: "10.0.0.3"
    underlay_interface: "eth0"
    underlay_mtu: 9000
```

## MTU Planning

### Standard MTU (1500)

```yaml
sdn:
  overlay:
    underlay_mtu: 1500
    # Effective VM MTU: 1500 - 50 = 1450

    # Recommended: Configure VM MTU explicitly
    vm_mtu_override: 1450
```

### Jumbo Frames (9000)

```yaml
sdn:
  overlay:
    underlay_mtu: 9000
    # Effective VM MTU: 9000 - 50 = 8950

    # No MTU override needed for most workloads
```

### MTU Configuration Checklist

1. Configure physical switches for jumbo frames
2. Set underlay interface MTU on all hosts
3. Verify end-to-end MTU with ping
4. Configure overlay underlay_mtu parameter
5. VMs automatically get effective MTU

```bash
# Verify underlay MTU
ip link show eth0 | grep mtu

# Test end-to-end MTU (jumbo frames)
ping -M do -s 8972 10.0.0.2  # 8972 + 28 = 9000

# Test VXLAN path
ping -M do -s 8922 <vm-on-remote-host>  # 8922 + 28 + 50 = 9000
```

## Validation

### Configuration Validation

```bash
# Validate configuration file
platformctl config validate

# Check overlay status
platformctl sdn overlay status

# Verify VTEP registration
platformctl sdn overlay vtep list
```

### Pre-flight Checks

The overlay manager performs these checks on startup:

| Check | Description |
|-------|-------------|
| VTEP IP reachable | Verify VTEP IP is bound to underlay interface |
| Underlay MTU | Verify MTU >= 1550 (minimum for VXLAN) |
| VXLAN port available | Verify UDP port not in use |
| OVS bridge exists | Verify integration bridge configured |
| QuicBaaS connected | Verify connection to state store |

## Troubleshooting Configuration

### Common Configuration Issues

| Issue | Check | Fix |
|-------|-------|-----|
| VTEP not reachable | `ip addr show` | Correct vtep_ip to match interface IP |
| MTU too small | `ip link show eth0` | Set underlay_mtu to match interface |
| VNI collision | Check VNI base | Ensure vni_base + max_vlan < vni_max |
| OVS not found | `ovs-vsctl show` | Install and start Open vSwitch |

### Debug Configuration

```yaml
sdn:
  overlay:
    enabled: true
    # ... other settings ...

  logging:
    level: debug
    format: json

    # Component-specific logging
    overlay:
      level: debug
      # Log all tunnel events
      log_tunnel_events: true
      # Log MAC learning
      log_mac_learning: true
      # Log flow installations
      log_flows: true
```

### Verify Configuration at Runtime

```bash
# Show effective configuration
platformctl sdn overlay config show

# Show VTEP configuration
platformctl sdn overlay vtep show

# Show VNI configuration
platformctl sdn overlay vni show 1000100

# Show tunnel configuration
platformctl sdn overlay tunnel show 10.0.0.2
```

## Integration Configuration

### Integration with Policy Engine

```yaml
sdn:
  policy:
    enable_monitoring: true
    certificate_check_interval: 1h

  overlay:
    enabled: true
    # Policy engine automatically derives VNI from VLAN
    # No additional configuration needed
```

### Integration with QuicBaaS

```yaml
sdn:
  overlay:
    enabled: true
    state_sync_interval: 1s
    state_consistency: "eventual"

# QuicBaaS must be configured in main platform config
quicbaas:
  storage-backend: raft
  data-dir: /var/lib/platformd/quicbaas
  wal-dir: /var/lib/platformd/quicbaas/wal
  node-id: 1
  raft-address: "10.0.0.1:63000"
  join-addresses:
    - "10.0.0.2:63000"
    - "10.0.0.3:63000"
  cache-size: 67108864
  log-level: warn
  consistency-level: linearizable
```

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [SDN Configuration](../configuration.md)
- [QuicBaaS Configuration](../../datastore/configuration.md)

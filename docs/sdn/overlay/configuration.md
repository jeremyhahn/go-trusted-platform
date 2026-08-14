# VXLAN Overlay Configuration Reference

## Overview

This document is the reference for configuring the VXLAN overlay
subsystem: the platform YAML surface, runtime-derived settings, and the
Go configuration API.

## Platform Configuration (YAML)

The `sdn.overlay` YAML section is intentionally small; most overlay
settings are derived at runtime (see below).

```yaml
sdn:
  enabled: true

  # OVS connection (shared by all SDN components)
  ovs:
    socket: "/var/run/openvswitch/db.sock"
    bridge: "br-int"
    datapath: "system"

  overlay:
    enabled: true
    vxlan-port: 4789
    underlay-interface: "eth0"
```

### Overlay Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enabled | bool | false | Enable overlay networking |
| vxlan-port | uint16 | 4789 | UDP port for VXLAN encapsulation |
| underlay-interface | string | "lo" | Physical interface for VXLAN underlay traffic. The loopback default suits single-node and test environments; production deployments should set the uplink interface (e.g., `eth0`, `bond0`) |

### Runtime-Derived Settings

The daemon fills in the remaining overlay controller settings when it
builds the configuration:

| Setting | Source | Default |
|---------|--------|---------|
| VTEP IP | Node public IPv4 | 127.0.0.1 when unset (test / loopback nodes) |
| Bridge name | `sdn.ovs.bridge` | `br-overlay` |
| Underlay MTU | Applied default | 9000 |
| VNI base | Applied default | 1000000 |
| State backend | Applied default | `memory` (or `quicbaas` for cluster-shared state) |
| Health check interval | Applied default | 30s |
| MAC expiration | Applied default | 5m |

### Flow Programming

Flows are currently programmed one FlowMod per call; there is no flow
batching configuration. Batched OVS transactions are a planned
optimization.

## Go Configuration API

### Programmatic Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"

// Create overlay configuration
config := &overlay.Config{
    NodeID:            "node-001",
    VTEPIP:            netip.MustParseAddr("10.0.0.1"),
    UnderlayInterface: "eth0",
    UnderlayMTU:       9000,
    VXLANPort:         4789,
    VNIBase:           1000000,
    BridgeName:        "br-overlay",
    OVSSocketPath:     "/var/run/openvswitch/db.sock",
    StateBackend:      "memory",
    EnableEVPN:        true,
}
config.ApplyDefaults()

// Create the overlay controller
controller, err := overlay.New(config,
    overlay.WithLogger(logger),
    overlay.WithOVSClient(ovsClient),
    overlay.WithOpenFlowClient(ofClient),
)
if err != nil {
    return err
}

// Start the controller
if err := controller.Start(ctx); err != nil {
    return err
}
```

### Configuration Options

```go
// Available options
func WithLogger(logger *slog.Logger) Option
func WithOVSClient(client *ovs.Client) Option
func WithOpenFlowClient(client *openflow.Client) Option
func WithVTEPManager(manager *vxlan.VTEPManager) Option
func WithBGPSpeaker(speaker *bgp.Speaker) Option
func WithEVPNManager(manager *bgp.EVPNManager) Option
func WithGateway(gw *gateway.Gateway) Option
func WithIPAM(allocator ipam.Allocator) Option
func WithStateManager(state *StateManager) Option
```

### Config Fields

| Field | Type | Description |
|-------|------|-------------|
| NodeID | string | Unique identifier for this node (required) |
| VTEPIP | netip.Addr | This node's VTEP IP address (required) |
| UnderlayInterface | string | Physical interface for underlay traffic (required) |
| UnderlayMTU | int | Underlay MTU; must be >= 1550 |
| VXLANPort | uint16 | UDP port for VXLAN (default 4789) |
| VNIBase | uint32 | Base VNI for VLAN-to-VNI mapping |
| BridgeName | string | OVS bridge for overlay traffic |
| OVSSocketPath | string | Path to the OVSDB socket |
| BGPConfig | *bgp.BGPConfig | BGP service configuration |
| GatewayConfig | *gateway.GatewayConfig | Gateway node configuration |
| StateBackend | string | State storage: "memory" or "quicbaas" |
| HealthCheckInterval | time.Duration | Health check interval |
| MACExpiration | time.Duration | Expiration for learned remote MACs |
| EnableEVPN | bool | Enable EVPN MAC/IP advertisement and learning |

## Multi-Host Deployment

Each host sets its own underlay interface; the VTEP IP is derived from
the node's public IPv4 address.

```yaml
# /etc/platformd/config.yaml on each host
sdn:
  enabled: true
  overlay:
    enabled: true
    underlay-interface: "eth0"
```

## MTU Planning

VXLAN encapsulation adds 50 bytes of overhead, so the underlay MTU
must be at least 1550. With a standard 1500-byte underlay, configure
workload (VM) interfaces for 1450; with jumbo frames (9000) the
effective workload MTU is 8950.

### MTU Configuration Checklist

1. Configure physical switches for jumbo frames
2. Set underlay interface MTU on all hosts
3. Verify end-to-end MTU with ping

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
# Show the effective SDN configuration section
platformctl config get sdn

# Check overlay status
platformctl sdn overlay status

# Verify VTEP registration
platformctl sdn overlay vtep list
```

### Startup Validation

`Config.Validate()` enforces these invariants when the controller
starts:

| Check | Description |
|-------|-------------|
| Node ID set | NodeID must be non-empty |
| VTEP IP valid | VTEPIP must be a valid, specified address |
| Underlay interface set | UnderlayInterface must be non-empty |
| Underlay MTU | MTU must be >= 1550 (minimum for VXLAN) |
| VXLAN port | Port must be non-zero |
| Bridge name set | BridgeName must be non-empty |

## Troubleshooting Configuration

| Issue | Check | Fix |
|-------|-------|-----|
| VTEP not reachable | `ip addr show` | Ensure the node's public IPv4 is bound to the underlay interface |
| MTU too small | `ip link show eth0` | Raise the underlay interface MTU to >= 1550 |
| OVS not found | `ovs-vsctl show` | Install and start Open vSwitch; check `sdn.ovs.socket` |

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [SDN Configuration](../configuration.md)

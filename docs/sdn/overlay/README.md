# VXLAN Overlay Networking

Multi-host overlay networking for east-west VM and container traffic.

## Overview

The VXLAN overlay subsystem provides Layer 2 connectivity across multiple physical hosts, enabling seamless VM and container communication without requiring physical network reconfiguration. It integrates with the existing SDN policy engine and uses QuicBaaS for distributed state replication.

## Key Features

| Feature | Description |
|---------|-------------|
| **VXLAN Encapsulation** | RFC 7348 compliant tunneling with 24-bit VNI space |
| **Multi-Host Connectivity** | East-west traffic across physical host boundaries |
| **VNI-VLAN Mapping** | Automatic VNI = 1000000 + VLAN ID mapping (code default; the [reference network](../../architecture/reference-network.md) uses VNI = E×100000 + n, tracked in #708) |
| **VTEP Management** | Per-host VXLAN Tunnel Endpoint configuration |
| **QuicBaaS Replication** | Distributed state synchronization across cluster |
| **Policy Integration** | Seamless integration with existing 802.1X policy engine |
| **OpenFlow Control** | Pipeline tables 0-60 for overlay processing |

## Architecture Overview

```
Host A                                              Host B
+---------------------------+                       +---------------------------+
|  VM1          VM2         |                       |  VM3          VM4         |
|  VLAN 100     VLAN 200    |                       |  VLAN 100     VLAN 200    |
|    |            |         |                       |    |            |         |
|    +-----+------+         |                       |    +-----+------+         |
|          |                |                       |          |                |
|    +-----v------+         |                       |    +-----v------+         |
|    | OVS Bridge |         |                       |    | OVS Bridge |         |
|    | (br-int)   |         |                       |    | (br-int)   |         |
|    +-----+------+         |                       |    +-----+------+         |
|          |                |                       |          |                |
|    +-----v------+         |                       |    +-----v------+         |
|    |    VTEP    |         |                       |    |    VTEP    |         |
|    | 10.0.0.1   |         |                       |    | 10.0.0.2   |         |
|    +-----+------+         |                       |    +-----+------+         |
|          |                |                       |          |                |
+----------|----------------+                       +----------|----------------+
           |         VXLAN Tunnel (VNI 1000100)                |
           |            UDP Port 4789                          |
           +---------------------------------------------------+
                              |
                      Physical Network
                       (Underlay MTU 9000)
```

## VNI-VLAN Mapping

VXLAN Network Identifiers (VNIs) are derived from VLAN IDs using a deterministic formula:

```
VNI = VNI_BASE + VLAN_ID
VNI = 1000000 + VLAN_ID
```

| VLAN ID | VNI | Purpose |
|---------|-----|---------|
| 1 | 1000001 | Default |
| 6 | 1000006 | Quarantine |
| 7 | 1000007 | Provisioning |
| 100 | 1000100 | Tenant A Production |
| 200 | 1000200 | Tenant B Production |

This mapping ensures:
- No collision with VNI space (0-16777215)
- Easy debugging (VNI visually correlates with VLAN)
- Consistent mapping across all hosts

## VTEP (VXLAN Tunnel Endpoint)

Each host runs a VTEP that terminates VXLAN tunnels.

### VTEP Responsibilities

| Function | Description |
|----------|-------------|
| Encapsulation | Wrap L2 frames in VXLAN/UDP/IP headers |
| Decapsulation | Strip tunnel headers and deliver to local bridge |
| MAC Learning | Track remote MAC addresses per VNI |
| ARP Suppression | Reduce broadcast traffic via proxy ARP |
| BUM Handling | Manage Broadcast, Unknown unicast, Multicast |

### VTEP Discovery

VTEPs discover each other through QuicBaaS:

```
1. Host A registers VTEP: {vtep_ip: 10.0.0.1, vnis: [1000100, 1000200]}
2. QuicBaaS replicates to all nodes
3. Host B learns about Host A's VTEP
4. Host B establishes tunnel to 10.0.0.1 for shared VNIs
```

## QuicBaaS State Replication

The overlay subsystem uses QuicBaaS for distributed state.

### Replicated State

| Entity | Partition | Description |
|--------|-----------|-------------|
| VTEP Registry | `sdn/overlay/vteps` | VTEP IP and capability info |
| VNI Membership | `sdn/overlay/vnis` | Which VNIs are active on each host |
| MAC Tables | `sdn/overlay/macs` | Remote MAC-to-VTEP mappings |
| Tunnel State | `sdn/overlay/tunnels` | Active tunnel status |

### Consistency Model

- **VTEP/VNI changes**: Linearizable (strong consistency)
- **MAC learning**: Eventual consistency (performance)
- **Tunnel state**: Eventual consistency (health checks)

## Policy Engine Integration

The overlay subsystem integrates with the existing 802.1X policy engine.

### Flow Processing

When a device authenticates:

1. Policy engine assigns VLAN from device profile
2. Overlay subsystem derives VNI from VLAN
3. OpenFlow rules installed for local and remote forwarding
4. VTEP tunnels established to hosts with same VNI

### Security Enforcement

| Layer | Enforcement |
|-------|-------------|
| Port Authentication | 802.1X certificate validation |
| VLAN Assignment | Policy-based VLAN from device profile |
| VNI Isolation | VNI derived from VLAN |
| ACLs | OpenFlow rules per VNI |

## Quick Start

### Enable Overlay

```yaml
# config.yaml
sdn:
  enabled: true
  overlay:
    enabled: true
    vxlan-port: 4789
    underlay-interface: "eth0"
```

The VTEP IP is derived from the node's public IPv4 address; MTU, VNI
base, and bridge name use applied defaults (see
[Configuration](configuration.md)).

### Verify VTEP Status

```bash
# Check overlay and VTEP registration
platformctl sdn overlay status
platformctl sdn overlay vtep list

# List active VNIs
platformctl sdn overlay vni list

# Show tunnel endpoints
platformctl sdn overlay tunnel list
```

### Check Tunnel Connectivity

```bash
# Verify the remote VTEP is registered and tunnels exist
platformctl sdn overlay vtep get node-002
platformctl sdn overlay tunnel list --vni 1000100

# Check underlay reachability to the remote VTEP
ping 10.0.0.2
nc -zuv 10.0.0.2 4789
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Detailed component design and data flows |
| [Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | Multi-protocol API documentation |

## Integration with SDN Components

| Component | Integration |
|-----------|-------------|
| **OVS Bridge** | VXLAN ports attached to integration bridge |
| **OpenFlow** | Pipeline tables 0-60 for overlay processing |
| **Policy Engine** | VLAN-to-VNI mapping on device authentication |
| **QuicBaaS** | Distributed state for VTEP and MAC tables |
| **Cluster** | Multi-host coordination and health monitoring |

## Performance Considerations

| Aspect | Recommendation |
|--------|----------------|
| Underlay MTU | 9000 (jumbo frames) to avoid fragmentation |
| VXLAN Overhead | 50 bytes (Ethernet + IP + UDP + VXLAN) |
| Effective VM MTU | 8950 with jumbo frames, 1450 with standard MTU |
| Hardware Offload | Enable VXLAN offload on supported NICs |

## Security Model

### Tunnel Security

- VTEP-to-VTEP traffic traverses trusted underlay network
- VNI isolation prevents cross-tenant traffic
- MAC spoofing detected via OpenFlow rules
- QuicBaaS communication uses mTLS

### Defense in Depth

```
Layer 1: Physical network isolation (underlay)
Layer 2: VNI segmentation (overlay)
Layer 3: OpenFlow ACLs per VNI
Layer 4: 802.1X port authentication
Layer 5: mTLS for control plane
```

## Troubleshooting

### Common Issues

| Issue | Check |
|-------|-------|
| No tunnel connectivity | Verify underlay MTU (9000 recommended) |
| MAC not learned | Check QuicBaaS replication status |
| Dropped packets | Verify OpenFlow rules with `ovs-ofctl dump-flows` |
| VTEP not discovered | Check QuicBaaS cluster health |

### Debug Commands

```bash
# Show VXLAN interface status
ovs-vsctl show | grep vxlan

# Dump overlay flows
ovs-ofctl dump-flows br-int table=10

# Check QuicBaaS replication
platformctl cluster status
```

## See Also

- [SDN Architecture](../architecture.md)
- [SDN Configuration](../configuration.md)
- [Policy Engine](../802.1x.md)
- [Cluster Configuration](../../cluster/README.md)

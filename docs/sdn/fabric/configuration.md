# Fabric Configuration Reference

## Overview

The fabric configuration defines the physical network topology, segment layout, and device-specific parameters for unified fabric orchestration.

## Top-Level Configuration

```yaml
sdn:
  fabric:
    mode: vlan                    # "vlan" or "evpn"
    evpn:
      vni-base: 100000
      anycast-gateway-mac: "00:1a:2b:3c:4d:5e"
      arp-suppression: true
    switches:
      - id: core-01
        # ...
    peers:
      - switch-a: core-01
        switch-b: core-02
        # ...
    lags:
      - id: lag-uplink
        members:
          - switch-id: core-01
            port: Eth1/53
        # ...
    segments:
      - name: provisioning
        vlan: 100
        # ...
```

## FabricConfig Fields

### Root Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `vlan` | Operating mode: `vlan` (802.1Q) or `evpn` (VXLAN overlay) |
| `evpn` | object | Conditional | - | EVPN parameters. Required if `mode: evpn` |
| `switches` | array | Yes | - | Physical switch definitions (minimum 1) |
| `peers` | array | No | [] | MC-LAG/vPC peering relationships |
| `lags` | array | No | [] | Link aggregation group definitions |
| `segments` | array | Yes | - | Network segment definitions (minimum 1) |

## EVPNConfig Fields

EVPN-specific parameters for overlay mode:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `vni-base` | uint32 | Yes | - | Starting VNI value. Segment VNI = `vni-base + VLAN ID` |
| `anycast-gateway-mac` | string | Yes | - | MAC address for distributed VTEP gateway (format: `xx:xx:xx:xx:xx:xx`) |
| `arp-suppression` | bool | No | false | Enable ARP suppression on VTEP interfaces |
| `rt-base` | string | No | - | Base route-target for auto-derivation (e.g., `65001:0`) |

## SwitchConfig Fields

Defines a single physical switch:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | - | Unique switch identifier (used in PortRef) |
| `vendor` | string | Yes | - | Switch vendor: `cisco-nexus`, `noop` (testing only) |
| `model` | string | No | - | Switch hardware model (informational) |
| `mgmt-ip` | string | Yes | - | Management IP address for SSH access |
| `credentials-ref` | string | No | - | Secret reference for authentication credentials |
| `vtep-loopback` | string | No | - | Loopback IP for VXLAN VTEP (EVPN mode only) |
| `bgp-asn` | uint32 | No | - | BGP autonomous system number (EVPN) |
| `ssh-port` | int | No | 22 | SSH port |
| `ssh-user` | string | No | admin | SSH username |
| `ssh-password` | string | No | - | SSH password (use `encrypted://` prefix for secrets) |
| `ssh-key-path` | string | No | - | Path to SSH private key file |
| `known-hosts-path` | string | No | - | Path to SSH known_hosts file |

## PeerConfig Fields

Defines MC-LAG or vPC relationships:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `switch-a` | string | Yes | ID of first switch in pair |
| `switch-b` | string | Yes | ID of second switch in pair |
| `peer-link-ports` | array | Yes | Ports forming the peer link (minimum 1) |
| `keepalive-dest` | string | No | Keepalive destination IP for vPC |

### Example: vPC Configuration

```yaml
peers:
  - switch-a: core-01
    switch-b: core-02
    peer-link-ports:
      - Eth1/53
      - Eth1/54
    keepalive-dest: "10.0.1.100"
```

## LAGConfig Fields

Defines a link aggregation group:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | - | Unique LAG identifier |
| `members` | array | Yes | - | List of PortRef objects (minimum 1) |
| `mclag` | bool | No | false | Multi-chassis LAG across peer switches |
| `esi` | string | No | - | Ethernet Segment Identifier (ESI-LAG, NX-OS 10.2+) |
| `lacp-mode` | string | No | `active` | LACP mode: `active` or `passive` |
| `lacp-rate` | string | No | `normal` | LACP PDU rate: `fast` or `normal` |
| `port-channel-id` | uint16 | Yes | - | NX-OS port-channel number |

### PortRef Object

Identifies a physical port:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `switch-id` | string | Yes | Switch identifier |
| `port` | string | Yes | Interface name (e.g., `Eth1/1`, `Eth1/53-54`) |
| `lag-id` | string | No | Associated LAG group ID |

### Example: Multi-Chassis LAG

```yaml
lags:
  - id: lag-uplink-to-core
    members:
      - switch-id: leaf-01
        port: Eth1/53
      - switch-id: leaf-02
        port: Eth1/53
    mclag: true
    lacp-mode: active
    lacp-rate: fast
    port-channel-id: 1
```

## SegmentConfig Fields

Defines a network segment (VLAN + subnets):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique segment name |
| `vlan` | uint16 | Yes | - | 802.1Q VLAN ID (1-4094) |
| `cidr` | string | Yes | - | IP network in CIDR notation (e.g., `10.200.0.0/24`) |
| `gateway` | string | No | - | Default gateway IP address |
| `dns` | array | No | [] | DNS server IP addresses |
| `dhcp` | bool | No | false | Enable DHCP on this segment |
| `role` | string | No | `` | Segment purpose: `provisioning`, `quarantine`, or empty (production) |

## Complete Examples

### Example 1: Simple VLAN-Only Fabric (2 switches, 3 segments)

```yaml
sdn:
  fabric:
    mode: vlan

    switches:
      - id: core-01
        vendor: cisco-nexus
        model: "Cisco Nexus 9336PQ"
        mgmt-ip: 10.0.1.50
        ssh-user: admin
        ssh-password: "encrypted://core-switch-cred"

      - id: core-02
        vendor: cisco-nexus
        model: "Cisco Nexus 9336PQ"
        mgmt-ip: 10.0.1.51
        ssh-user: admin
        ssh-password: "encrypted://core-switch-cred"

    peers:
      - switch-a: core-01
        switch-b: core-02
        peer-link-ports:
          - Eth1/53
          - Eth1/54

    lags:
      - id: lag-core-link
        members:
          - switch-id: core-01
            port: Eth1/49
          - switch-id: core-02
            port: Eth1/49
        mclag: false
        port-channel-id: 1

    segments:
      - name: provisioning
        vlan: 100
        cidr: 10.200.0.0/24
        gateway: 10.200.0.1
        dhcp: true
        dns:
          - 10.0.1.10
          - 10.0.1.11
        role: provisioning

      - name: production
        vlan: 200
        cidr: 10.201.0.0/24
        gateway: 10.201.0.1
        dhcp: true
        role: ""

      - name: quarantine
        vlan: 300
        cidr: 10.202.0.0/24
        gateway: 10.202.0.1
        dhcp: false
        role: quarantine
```

### Example 2: EVPN-VXLAN Fabric (leaf-spine topology)

```yaml
sdn:
  fabric:
    mode: evpn

    evpn:
      vni-base: 100000
      anycast-gateway-mac: "00:1a:2b:3c:4d:5e"
      arp-suppression: true
      rt-base: "65001:0"

    switches:
      - id: spine-01
        vendor: cisco-nexus
        mgmt-ip: 10.0.1.60
        vtep-loopback: "10.0.0.1"
        bgp-asn: 65000
        ssh-user: admin
        ssh-password: "encrypted://spine-cred"

      - id: leaf-01
        vendor: cisco-nexus
        mgmt-ip: 10.0.1.61
        vtep-loopback: "10.0.0.11"
        bgp-asn: 65011
        ssh-user: admin
        ssh-password: "encrypted://leaf-cred"

      - id: leaf-02
        vendor: cisco-nexus
        mgmt-ip: 10.0.1.62
        vtep-loopback: "10.0.0.12"
        bgp-asn: 65012
        ssh-user: admin
        ssh-password: "encrypted://leaf-cred"

    lags:
      - id: lag-leaf1-to-spine
        members:
          - switch-id: leaf-01
            port: Eth1/53
          - switch-id: leaf-01
            port: Eth1/54
        port-channel-id: 1

      - id: lag-leaf2-to-spine
        members:
          - switch-id: leaf-02
            port: Eth1/53
          - switch-id: leaf-02
            port: Eth1/54
        port-channel-id: 1

    segments:
      - name: tenant-a-prod
        vlan: 100
        cidr: 10.100.0.0/24
        gateway: 10.100.0.1
        dhcp: true

      - name: tenant-b-prod
        vlan: 101
        cidr: 10.101.0.0/24
        gateway: 10.101.0.1
        dhcp: true

      - name: provisioning
        vlan: 200
        cidr: 10.200.0.0/24
        gateway: 10.200.0.1
        dhcp: true
        role: provisioning
```

## Validation Rules

- **Mode**: Must be `vlan` or `evpn`
- **EVPN requirement**: If `mode: evpn`, `evpn:` section is required
- **Switches**: At least one switch must be configured
- **Segments**: At least one segment must be configured
- **Duplicate checks**:
  - Switch IDs must be unique
  - Segment names must be unique
  - VLAN IDs must be unique per segment
- **VLAN range**: 1-4094
- **Port channels**: Port-channel IDs must be unique within a switch
- **Peer links**: Referenced switches must exist

## Error Handling

Common validation errors:

```
"mode must be 'vlan' or 'evpn'"
"evpn config required when mode is 'evpn'"
"at least one switch is required"
"duplicate switch id: core-01"
"duplicate segment name: production"
"duplicate vlan: 100 (segments: prod, backup)"
"switch vlan must be between 1 and 4094"
"segment role must be 'provisioning', 'quarantine', or empty"
```

## See Also

- [README](./README.md) - Overview and usage
- [API Reference](./api-reference.md) - Go interfaces
- [Adding Drivers](./adding-drivers.md) - Implement vendor support

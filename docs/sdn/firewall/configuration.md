# Firewall Configuration Reference

## Overview

The firewall is configured via the `firewall:` section of the platform configuration. It defines zones, rules, NAT policies, and connection tracking timeouts.

## Top-Level Configuration

```yaml
sdn:
  firewall:
    enabled: true
    default-policy: deny          # or "allow"

    zones:
      - name: trusted
        interfaces:
          - eth0
        policy: allow

    rules:
      - name: allow-ssh
        priority: 10
        match:
          dst-port: 22
          protocol: 6
        action: allow

    nat:
      snat:
        - name: masquerade-trusted
          from-zone: trusted
          masquerade: true

      dnat:
        - name: forward-http
          dst-port: 80
          target-ip: 10.0.1.100
          target-port: 8080
          protocol: 6

    timeouts:
      tcp-established: 5m
      tcp-close: 30s
      udp: 30s
      icmp: 30s
```

## Config Fields

### Root Firewall Config

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable/disable the firewall |
| `default-policy` | string | Yes | - | Default action: `allow` or `deny` |
| `zones` | array | Yes | - | Network zones (minimum 1) |
| `rules` | array | No | [] | Firewall rules |
| `nat` | object | No | {} | NAT configuration |
| `timeouts` | object | No | defaults | Connection tracking timeouts |

## Zone Configuration

Zones group interfaces with a default traffic policy:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique zone name |
| `interfaces` | array | Yes | List of interface names (minimum 1) |
| `policy` | string | Yes | Default policy: `allow` or `deny` |

### Zone Policy Model

- **allow**: Packets matching the zone policy are allowed by default
- **deny**: Packets matching the zone policy are denied by default
- Explicit rules override zone policy

```yaml
zones:
  - name: trusted
    interfaces:
      - eth0
      - eth1
    policy: allow

  - name: untrusted
    interfaces:
      - eth2
    policy: deny

  - name: dmz
    interfaces:
      - eth3
    policy: allow
```

## Rule Configuration

Rules are evaluated in priority order. The first matching rule wins.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique rule name |
| `priority` | int | Yes | - | Evaluation order (lower = first) |
| `action` | string | Yes | - | Verdict: `allow`, `deny`, `reject` |
| `match` | object | No | {} | Match criteria (empty = match all) |

### RuleMatch Fields

| Field | Type | Description |
|-------|------|-------------|
| `src-zone` | string | Source zone name (empty = any) |
| `dst-zone` | string | Destination zone name (empty = any) |
| `src-net` | string | Source network in CIDR (empty = any) |
| `dst-net` | string | Destination network in CIDR (empty = any) |
| `src-port` | int | Source port (0 = any) |
| `dst-port` | int | Destination port (0 = any) |
| `protocol` | int | IP protocol (0 = any, 6 = TCP, 17 = UDP, 1 = ICMP) |
| `conn-state` | string | Connection state: `new`, `established`, `related`, `invalid` |

### Rule Actions

- **allow**: Permit the packet to pass
- **deny**: Silently drop the packet
- **reject**: Drop the packet and send ICMP unreachable

### Example Rules

```yaml
rules:
  # Allow SSH from trusted zone
  - name: allow-ssh-from-trusted
    priority: 10
    match:
      src-zone: trusted
      dst-port: 22
      protocol: 6  # TCP
    action: allow

  # Allow established connections
  - name: allow-established
    priority: 5
    match:
      conn-state: established
    action: allow

  # Allow DNS queries
  - name: allow-dns
    priority: 15
    match:
      dst-port: 53
      protocol: 17  # UDP
    action: allow

  # Allow ICMP ping
  - name: allow-icmp-ping
    priority: 20
    match:
      protocol: 1  # ICMP
    action: allow

  # Block untrusted to trusted
  - name: deny-untrusted-to-trusted
    priority: 30
    match:
      src-zone: untrusted
      dst-zone: trusted
    action: deny

  # Default deny (catch-all)
  - name: deny-all
    priority: 999
    match: {}
    action: deny
```

## NAT Configuration

### SNAT (Source NAT)

Rewrites the source address (masquerade):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique rule name |
| `type` | string | No | SNAT | NAT type |
| `from-zone` | string | No | - | Source zone (empty = any) |
| `to-zone` | string | No | - | Destination zone (empty = any) |
| `protocol` | int | No | 0 | IP protocol (0 = any) |
| `masquerade` | bool | No | false | Use outgoing interface IP |

```yaml
nat:
  snat:
    - name: masquerade-trusted
      from-zone: trusted
      masquerade: true

    - name: masquerade-dmz-tcp
      from-zone: dmz
      protocol: 6  # TCP
      masquerade: true
```

### DNAT (Destination NAT)

Rewrites the destination address (port forward):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique rule name |
| `type` | string | No | DNAT | NAT type |
| `from-zone` | string | No | - | Source zone (empty = any) |
| `to-zone` | string | No | - | Destination zone (empty = any) |
| `dst-port` | int | No | 0 | Original destination port (0 = any) |
| `target-ip` | string | Yes | - | Translated destination IP |
| `target-port` | int | Yes | - | Translated destination port |
| `protocol` | int | No | 6 | IP protocol (6 = TCP, 17 = UDP) |

```yaml
nat:
  dnat:
    - name: forward-http-to-internal
      dst-port: 80
      target-ip: 10.0.1.100
      target-port: 8080
      protocol: 6  # TCP

    - name: forward-https-to-internal
      dst-port: 443
      target-ip: 10.0.1.100
      target-port: 8443
      protocol: 6  # TCP
```

## Connection Tracking Timeouts

Default timeouts for idle connections:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tcp-established` | duration | 5m | Established TCP connection timeout |
| `tcp-close` | duration | 30s | TCP connection in FIN/RST state |
| `udp` | duration | 30s | UDP flow timeout |
| `icmp` | duration | 30s | ICMP message timeout |

```yaml
timeouts:
  tcp-established: 5m      # 5 minutes
  tcp-close: 30s           # 30 seconds
  udp: 30s                 # 30 seconds
  icmp: 30s                # 30 seconds
```

Durations use Go time.Duration syntax:
- `30s` = 30 seconds
- `5m` = 5 minutes
- `1h` = 1 hour

## IP Protocol Numbers

Common protocol values:

| Name | Number |
|------|--------|
| ICMP | 1 |
| TCP | 6 |
| UDP | 17 |
| GRE | 47 |

## Complete Example

```yaml
sdn:
  firewall:
    enabled: true
    default-policy: deny

    zones:
      - name: trusted
        interfaces:
          - eth0
        policy: allow

      - name: untrusted
        interfaces:
          - eth1
        policy: deny

      - name: dmz
        interfaces:
          - eth2
        policy: allow

    rules:
      # Always allow loopback
      - name: allow-loopback
        priority: 1
        match:
          src-net: 127.0.0.0/8
          dst-net: 127.0.0.0/8
        action: allow

      # Allow established and related
      - name: allow-established
        priority: 5
        match:
          conn-state: established
        action: allow

      - name: allow-related
        priority: 6
        match:
          conn-state: related
        action: allow

      # Allow trusted zone traffic
      - name: allow-trusted-icmp
        priority: 10
        match:
          src-zone: trusted
          protocol: 1  # ICMP
        action: allow

      - name: allow-trusted-dns
        priority: 11
        match:
          src-zone: trusted
          dst-port: 53
          protocol: 17  # UDP
        action: allow

      - name: allow-trusted-ntp
        priority: 12
        match:
          src-zone: trusted
          dst-port: 123
          protocol: 17  # UDP
        action: allow

      # Allow DMZ to specific services
      - name: allow-dmz-http
        priority: 20
        match:
          src-zone: dmz
          dst-port: 80
          protocol: 6  # TCP
        action: allow

      - name: allow-dmz-https
        priority: 21
        match:
          src-zone: dmz
          dst-port: 443
          protocol: 6  # TCP
        action: allow

      # Block untrusted to trusted
      - name: block-untrusted-to-trusted
        priority: 50
        match:
          src-zone: untrusted
          dst-zone: trusted
        action: reject

      # Default deny
      - name: deny-all
        priority: 999
        match: {}
        action: deny

    nat:
      snat:
        - name: masquerade-dmz
          from-zone: dmz
          masquerade: true

      dnat:
        - name: http-forward
          dst-port: 80
          target-ip: 10.0.2.100
          target-port: 8080
          protocol: 6  # TCP

        - name: https-forward
          dst-port: 443
          target-ip: 10.0.2.100
          target-port: 8443
          protocol: 6  # TCP

    timeouts:
      tcp-established: 5m
      tcp-close: 30s
      udp: 30s
      icmp: 30s
```

## Validation Rules

- **Enabled field**: Boolean true/false
- **Default policy**: Must be "allow" or "deny"
- **Zone names**: Must be unique
- **Interface names**: Must not overlap between zones
- **Rule names**: Must be unique
- **Rule priority**: Unique values recommended (duplicates run in order)
- **Match fields**: Empty/zero = match any
- **NAT rules**: `target-ip` and `target-port` required for DNAT
- **Protocol numbers**: 0 (any) to 255

## Error Messages

- `invalid configuration: enabled must be boolean`
- `invalid configuration: default-policy must be 'allow' or 'deny'`
- `invalid configuration: zone name is required`
- `invalid configuration: duplicate zone name: trusted`
- `invalid configuration: rule name is required`
- `invalid configuration: DNAT rule requires target-ip and target-port`

## See Also

- [README](./README.md) - Overview and usage
- [Architecture](./architecture.md) - Design details
- [Performance](./performance.md) - Tuning guide

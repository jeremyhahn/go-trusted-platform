# Tunnel Configuration Reference

## TunnelConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | - | Interface name (max 15 chars) |
| `type` | string | yes | - | `gre`, `gre6`, or `ipip` |
| `local` | string | yes | - | Local endpoint IP address |
| `remote` | string | yes | - | Remote endpoint IP address |
| `tunnel-ip` | string | yes | - | Tunnel interface IP in CIDR (e.g., `10.255.0.1/30`) |
| `tunnel-ipv6` | string | no | - | Optional IPv6 address in CIDR |
| `mtu` | int | no | 1400 | Tunnel interface MTU (68-65535) |
| `ttl` | int | no | 64 | IP TTL for tunnel packets (1-255) |
| `key` | uint32 | no | 0 | GRE key for traffic isolation |

## Example: iBGP via GRE to VPS

```yaml
tunnels:
  - name: gre1
    type: gre
    local: "99.12.246.36"
    remote: "45.63.110.165"
    tunnel-ip: "10.255.0.1/30"
    mtu: 1400
    ttl: 64

  - name: gre2
    type: gre
    local: "99.12.246.37"
    remote: "45.63.110.165"
    tunnel-ip: "10.255.0.5/30"
    mtu: 1400
    ttl: 64

  - name: gre5
    type: gre
    local: "96.65.171.20"
    remote: "66.42.90.190"
    tunnel-ip: "10.255.0.17/30"
    mtu: 1400
    ttl: 64

  - name: gre6
    type: gre
    local: "96.65.171.21"
    remote: "66.42.90.190"
    tunnel-ip: "10.255.0.21/30"
    mtu: 1400
    ttl: 64
```

## BGP AnnounceConfig

Added to `BGPConfig.Announce` to declare prefixes for announcement:

| Field | Type | Description |
|-------|------|-------------|
| `ipv4` | []string | IPv4 CIDR prefixes to announce |
| `ipv6` | []string | IPv6 CIDR prefixes to announce |

```yaml
bgp:
  router-id: "10.255.0.1"
  asn: 401870
  announce:
    ipv4:
      - "23.143.36.0/24"
    ipv6:
      - "2602:F5BB::/36"
  neighbors:
    - address: "10.255.0.2"
      asn: 401870
      description: "VPS Miami primary"
      ipv4-unicast: true
      ipv6-unicast: true
    - address: "10.255.0.18"
      asn: 401870
      description: "VPS Atlanta backup"
      ipv4-unicast: true
      ipv6-unicast: true
```

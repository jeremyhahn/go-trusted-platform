# Tunnel Configuration Reference

## TunnelConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | - | Interface name (max 15 chars) |
| `type` | string | yes (not for `wireguard`) | - | Carrier: `gre`, `gre6`, or `ipip` |
| `transport` | string | no | `gre` | `gre`, `ipsec`, or `wireguard` (`wireguard` is refused in FIPS builds) |
| `uplink` | string | no | - | Name of the `UplinkConfig` whose table carries the outer packets |
| `local` | string | yes | - | Local endpoint IP address |
| `remote` | string | yes | - | Remote endpoint IP address |
| `tunnel-ip` | string | yes | - | Tunnel interface IP in CIDR (e.g., `10.255.0.1/30`) |
| `tunnel-ipv6` | string | no | - | Optional IPv6 address in CIDR |
| `mtu` | int | no | 1400 | Tunnel interface MTU (68-65535) |
| `ttl` | int | no | 64 | IP TTL for tunnel packets (1-255) |
| `key` | uint32 | no | 0 | GRE key for traffic isolation |
| `ipsec` | section | when `transport: ipsec` | - | see below |
| `wireguard` | section | when `transport: wireguard` | - | see below |

A `gre` transport with an `ipsec` or `wireguard` section, or a section that does
not match the transport, is a validation error.

### `ipsec`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `key-ref` | string | yes | - | Key-store reference for the outbound SA (36 bytes: AES-256 key + 4-byte salt) |
| `peer-key-ref` | string | no | `key-ref` | Reference for the inbound SA |
| `spi-out` | uint32 | yes | - | Outbound SPI, non-zero |
| `spi-in` | uint32 | yes | - | Inbound SPI, non-zero, different from `spi-out` |
| `replay-window` | int | no | 128 | Anti-replay window in packets |
| `rekey-interval` | duration | no | 8h | How often the reconcile loop calls `Rekey` |

### `wireguard` (non-FIPS builds only)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `key-ref` | string | yes | - | Key-store reference for this node's 32-byte private key |
| `peer-public-key` | string | yes | - | Peer's public key, base64 |
| `remote-port` | int | yes | - | Peer's UDP port |
| `listen-port` | int | no | kernel-chosen | Local UDP port |
| `persistent-keepalive` | duration | no | 25s | Persistent keepalive |

## UplinkConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | - | Referenced by `TunnelConfig.uplink` |
| `interface` | string | yes | - | WAN interface |
| `table` | int | yes | - | Routing table id, 100–252, unique per uplink |
| `gateway-v4` | string | one of | - | ISP IPv4 next hop |
| `gateway-v6` | string | one of | - | ISP IPv6 next hop |
| `addresses` | []string | yes | - | The uplink's own addresses (CIDR); traffic sourced from them uses the table |
| `priority` | int | no | 1000 | `ip rule` priority for the source rules; tunnel pins use `priority - 100` |

## Example: two uplinks, an ESP-protected tunnel per POP

```yaml
uplinks:
  - name: att
    interface: eth6
    table: 101
    gateway-v4: 99.12.246.38
    addresses: ["99.12.246.36/29"]
  - name: comcast
    interface: eth7
    table: 102
    gateway-v4: 96.65.171.22
    addresses: ["96.65.171.20/29"]

tunnels:
  - name: gre-mia-att
    type: gre
    transport: ipsec
    uplink: att
    local: "99.12.246.36"
    remote: "45.63.110.165"
    tunnel-ip: "10.255.0.1/30"
    ipsec:
      key-ref: kms://platform/tunnel/mia-att/out
      peer-key-ref: kms://platform/tunnel/mia-att/in
      spi-out: 0x1001
      spi-in: 0x1002
  - name: gre-atl-cmc
    type: gre
    transport: gre            # plain GRE until the relay is migrated
    uplink: comcast
    local: "96.65.171.20"
    remote: "66.42.90.190"
    tunnel-ip: "10.255.0.17/30"
```

## Example: iBGP via plain GRE to VPS (today's relay shape)

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

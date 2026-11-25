# DHCP Configuration Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `sdn.dhcp` configuration and where each daemon reads it.

## Overview

Two daemon configuration sections name DHCP, and **neither serves DHCP
today**:

- **platformd**: the `sdn.dhcp` section (minimal bind config). It only logs
  the zones the node would serve (`pkg/app/sdn.go:655`).
- **gatewayd**: the `dhcp:` section (`DHCPServiceConfig`,
  `pkg/sdn/gateway/types.go:717`). gatewayd refuses it at start as planned,
  not implemented (`pkg/sdn/gateway/handlers.go:80`).

## platformd: `sdn.dhcp`

```yaml
sdn:
  enabled: true
  dhcp:
    enabled: true
    interface: "eth0"
```

| Parameter | Type | Description |
|-----------|------|-------------|
| enabled | bool | Report the zones this node would serve |
| interface | string | Network interface to bind |

The zones it reports come from the platform IPAM system: each zone's pool is
derived from `sdn.environment` (DHCP range `.50` to the last usable address),
and explicit pools come from `sdn.ipam.pools`.

## gatewayd: `dhcp:`

The section parses, and gatewayd then refuses to start with it
(`ErrServiceUnavailable`: it needs an IPAM allocator gatewayd does not have).

```yaml
dhcp:
  enabled: true
  interface: "eth0"
  zone: "provisioning"          # resolve pool by zone
  # pool-start: "10.0.0.100"    # explicit range (overrides zone)
  # pool-end:   "10.0.0.200"
  lease-duration: 24h
```

| Parameter | Type | Description |
|-----------|------|-------------|
| enabled | bool | Enable the DHCP service |
| interface | string | Network interface to bind |
| zone | string | Zone name used to resolve the IPAM pool |
| pool-start / pool-end | string | Explicit address range (overrides zone) |
| lease-duration | duration | DHCP lease duration |

Precedence for pool selection (highest first): `pool-start`+`pool-end` →
`zone`. gatewayd's `pxe:` section is refused the same way
(`pkg/sdn/gateway/handlers.go:82`).

## Go Configuration API

The DHCP engine (`pkg/sdn/dhcp`) is configured programmatically by its
embedder with these types:

```go
type ServerConfig struct {
    Interfaces           []InterfaceConfig
    DefaultLeaseDuration time.Duration
    IPAMBackend          string            // "memory", "quicbaas", "dht"
    IPAMConfig           map[string]string // backend-specific settings
}

type InterfaceConfig struct {
    Name    string      // eth0, br0, ...
    Network string      // "public" or "private"
    Address netip.Addr  // server address on this interface
    PoolID  string      // IPAM pool ID
    Options DHCPOptions
}

type DHCPOptions struct {
    SubnetMask  net.IPMask
    Router      netip.Addr
    DNS         []netip.Addr
    DomainName  string
    LeaseTime   time.Duration
    RenewalTime time.Duration // T1
    RebindTime  time.Duration // T2
    NTPServers  []netip.Addr
    MTU         uint16
    Hostname    string
    NextServer   net.IP // PXE next-server (siaddr)
    BootFileName string // PXE boot file
}
```

```go
allocator := backends.NewMemoryBackend() // pkg/sdn/ipam/backends

server, err := dhcp.NewCoreDHCPServer(&dhcp.ServerConfig{
    Interfaces: []dhcp.InterfaceConfig{{
        Name:    "eth0",
        Network: dhcp.NetworkPrivate,
        Address: netip.MustParseAddr("192.0.2.1"),
        PoolID:  "internal-pool",
        Options: dhcp.DHCPOptions{
            Router:    netip.MustParseAddr("192.0.2.1"),
            DNS:       []netip.Addr{netip.MustParseAddr("8.8.8.8")},
            LeaseTime: 24 * time.Hour,
        },
    }},
    IPAMBackend: dhcp.IPAMBackendMemory,
}, allocator)
```

See [Plugins](plugins.md) for the IPAM and PXE plugin configuration
(architecture filters, TFTP root, boot files).

## Validation

- `NewCoreDHCPServer` validates the `ServerConfig` it is given.
- `ResolvePoolForZone` (`pkg/sdn/dhcp/zone_pool.go:77`) picks the pool: an
  explicit pool ID wins, otherwise the zone's pool, which must exist.

## See Also

- [README](README.md) — Service overview
- [Architecture](architecture.md) — Component design
- [Plugins](plugins.md) — IPAM and PXE plugins
- [IPAM Configuration](../ipam/configuration.md) — Pool definitions

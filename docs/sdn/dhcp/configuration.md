# DHCP Configuration Reference

> **Status: REFERENCE**
> The `sdn.dhcp` configuration and where each daemon reads it.

## Overview

The DHCP server is configured in two places, depending on which daemon
hosts it:

- **platformd**: the `sdn.dhcp` section (minimal bind config)
- **gateway node**: the `gateway.dhcp` service section (pool selection
  and lease settings)

Per the platform's explicit-config rule, the service starts only when
its config section is present with `enabled: true`.

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
| enabled | bool | Enable the DHCP server |
| interface | string | Network interface to bind |

Pool selection, options, and lease tracking come from the platform IPAM
system: each zone's pool is derived from `sdn.environment` (DHCP range `.50`
to the last usable address), and explicit pools come from `sdn.ipam.pools`.

## Gateway node: `gateway.dhcp`

```yaml
gateway:
  enabled: true
  dhcp:
    enabled: true
    interface: "eth0"
    zone: "provisioning"          # resolve pool by zone (preferred)
    # pool-start: "10.0.0.100"    # explicit range (overrides zone)
    # pool-end:   "10.0.0.200"
    lease-duration: 24h
```

| Parameter | Type | Description |
|-----------|------|-------------|
| enabled | bool | Enable the DHCP service |
| interface | string | Network interface to bind (required) |
| zone | string | Zone name used to resolve the IPAM pool |
| segment | string | Deprecated; provisioning subnet name (Zone takes precedence) |
| pool-start / pool-end | string | Explicit address range (overrides zone/segment) |
| lease-duration | duration | DHCP lease duration |

Precedence for pool selection (highest first):
`pool-start`+`pool-end` → `zone` → `segment`.

PXE boot is configured separately in the `gateway.pxe` service section.

## Go Configuration API

The DHCP engine (`pkg/sdn/dhcp`) is configured programmatically by the
daemon with these types:

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
}
```

```go
allocator := ipam.NewMemoryAllocator()

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

- `sdn.dhcp` / `gateway.dhcp` require `interface` when enabled.
- The referenced IPAM pool (by zone, segment, or explicit range) must
  exist; the gateway resolves it at service start.

## See Also

- [README](README.md) — Service overview
- [Architecture](architecture.md) — Component design
- [Plugins](plugins.md) — IPAM and PXE plugins
- [IPAM Configuration](../ipam/configuration.md) — Pool definitions

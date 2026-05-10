# GRE Tunnel Management

The `pkg/sdn/tunnel` package provides GRE, GRE6, and IPIP tunnel lifecycle management using Linux netlink. It is used by gatewayd to establish point-to-point tunnels to remote VPS nodes for iBGP transit peering.

## Architecture

The tunnel manager creates and manages Linux kernel tunnel interfaces via the vishvananda/netlink library. All operations are:

- **Idempotent**: `EnsureTunnel` is safe to call repeatedly with the same config
- **Thread-safe**: All methods are safe for concurrent use
- **Config-driven**: Tunnels are created from `TunnelConfig` structs (typically loaded from YAML)

## Supported Tunnel Types

| Type | Constant | Use Case |
|------|----------|----------|
| GRE | `gre` | IPv4 GRE tunnels to VPS nodes |
| GRE6 | `gre6` | IPv6 GRE tunnels |
| IPIP | `ipip` | IP-in-IP encapsulation |

## Usage

```go
mgr := tunnel.NewManager(logger)
defer mgr.Close()

err := mgr.EnsureTunnel(ctx, tunnel.TunnelConfig{
    Name:     "gre1",
    Type:     "gre",
    Local:    "99.12.246.36",
    Remote:   "45.63.110.165",
    TunnelIP: "10.255.0.1/30",
    MTU:      1400,
    TTL:      64,
})
```

## Integration with BGP

GRE tunnels provide the transport for iBGP sessions between gatewayd and remote VPS nodes. The tunnel IPs (e.g., 10.255.0.x/30) are used as BGP peer addresses in the `BGPConfig.Neighbors` list.

See [configuration.md](configuration.md) for config reference.

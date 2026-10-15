# DHCP API Reference

> **Status: REFERENCE**
> How the DHCP server is driven: configuration, not an API.

## Overview

The DHCP service is an **in-process component**: it runs inside the
daemon (platformd / gatewayd) and is driven entirely by the `sdn.dhcp`
YAML configuration. It does **not** currently expose a wire API — there
are no DHCP REST endpoints, gRPC/QUIC/MCP services, or
`platformctl sdn dhcp` CLI commands.

Lease allocation is backed by the platform IPAM system, so pool and
allocation state is observable through the IPAM surface:

- CLI: `platformctl sdn ipam pool list`, `platformctl sdn ipam allocations`
- API: see [IPAM API Reference](../ipam/api-reference.md)

## Go Service Interface

Embedders interact with the DHCP service through the `Server` interface
in `pkg/sdn/dhcp`:

```go
type Server interface {
    // Start starts the DHCP server on all configured interfaces.
    Start(ctx context.Context) error

    // Stop stops the DHCP server gracefully.
    Stop(ctx context.Context) error

    // Running returns true if the server is currently running.
    Running() bool

    // GetLease retrieves a lease by MAC address.
    GetLease(mac net.HardwareAddr) (*Lease, bool)

    // GetLeaseByIP retrieves a lease by IP address.
    GetLeaseByIP(ip netip.Addr) (*Lease, bool)

    // ListLeases returns all current leases.
    ListLeases() []*Lease

    // ReleaseLease releases a lease by MAC address.
    // Returns ErrLeaseNotFound if no lease exists for the MAC.
    ReleaseLease(mac net.HardwareAddr) error

    // Stats returns current server statistics.
    Stats() ServerStats
}
```

See `pkg/sdn/dhcp/types.go` for the `Lease`, `ServerStats`, and
configuration types, and [Configuration](configuration.md) for the YAML
reference.

## See Also

- [README](README.md) — Service overview and architecture
- [Configuration](configuration.md) — YAML configuration reference
- [Plugins](plugins.md) — IPAM and PXE plugin documentation
- [IPAM API Reference](../ipam/api-reference.md) — Pool/allocation APIs

# DHCP Service

Dynamic Host Configuration Protocol (DHCP) service for go-trusted-platform providing IP address allocation integrated with the platform IPAM system.

## Overview

The DHCP service implements a high-performance DHCP server using CoreDHCP as the underlying engine, with custom plugins for platform integration:

- Dynamic IP allocation from IPAM pools
- Multi-interface support for network segmentation
- PXE boot support for bare-metal provisioning
- Lock-free statistics collection
- Comprehensive lease management

## Status

| Component | Status | Description |
|-----------|--------|-------------|
| CoreDHCP Integration | Complete | Pure Go DHCP implementation |
| IPAM Plugin | Complete | IP allocation from IPAM pools |
| PXE Plugin | Complete | PXE boot with architecture detection |
| Lease Management | Complete | O(1) lookup by IP or MAC |
| Multi-Interface | Complete | Per-interface pool binding |
| Statistics Collection | Complete | Lock-free atomic counters |
| DHCPv4 | Complete | Full DHCPv4 support |
| DHCPv6 | Planned | Future DHCPv6 support |

## Architecture

The DHCP service follows a plugin-based architecture built on CoreDHCP:

```
                    ┌────────────────────────────────────────┐
                    │            CoreDHCP Server             │
                    │     (Multi-Interface Support)          │
                    └─────────────────┬──────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
    ┌─────────▼─────────┐   ┌─────────▼─────────┐   ┌─────────▼─────────┐
    │   Interface 1     │   │   Interface 2     │   │   Interface N     │
    │   (eth0/Pool-A)   │   │   (eth1/Pool-B)   │   │   (br0/Pool-N)    │
    └─────────┬─────────┘   └─────────┬─────────┘   └─────────┬─────────┘
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
    ┌─────────▼─────────┐   ┌─────────▼─────────┐   ┌─────────▼─────────┐
    │    IPAM Plugin    │   │    PXE Plugin     │   │  Stats Collector  │
    │  (IP Allocation)  │   │  (Boot Support)   │   │  (Lock-Free)      │
    └─────────┬─────────┘   └───────────────────┘   └───────────────────┘
              │
    ┌─────────▼─────────┐
    │    Lease Store    │
    │  (sync.Map-Based) │
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │   Platform IPAM   │
    │   (Pool Backend)  │
    └───────────────────┘
```

## Key Features

### IPAM Integration

- Allocates IP addresses from configured IPAM pools
- Supports multiple backends: memory, QuicBaaS, DHT
- Automatic lease tracking and renewal
- Pool exhaustion handling

### Multi-Interface Support

- Bind to multiple network interfaces
- Per-interface IPAM pool assignment
- Separate DHCP options per network
- Public and private network types

### PXE Boot Support

- Architecture-aware boot file selection
- UEFI and BIOS support
- iPXE chainloading
- TFTP server configuration

### High Performance

- Lock-free statistics using atomic operations
- O(1) lease lookup by IP or MAC address
- Concurrent-safe operations with sync.Map
- Efficient message handling

## Package Structure

```
pkg/sdn/dhcp/
├── types.go              # Server, Lease, DHCPOptions types
├── errors.go             # Typed error definitions
├── server.go             # Server interface and stats collector
├── coredhcp.go           # CoreDHCP server implementation
├── lease_manager.go      # LeaseStore for lease tracking
├── plugin_ipam.go        # IPAM plugin for IP allocation
└── plugin_pxe.go         # PXE plugin for boot support
```

## Quick Start

### Basic DHCP Server

```go
import (
    "context"
    "net/netip"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Create IPAM allocator
allocator := ipam.NewMemoryAllocator()

// Create server configuration
config := &dhcp.ServerConfig{
    Interfaces: []dhcp.InterfaceConfig{
        {
            Name:    "eth0",
            Network: dhcp.NetworkPrivate,
            Address: netip.MustParseAddr("192.168.1.1"),
            PoolID:  "internal-pool",
            Options: dhcp.DHCPOptions{
                SubnetMask: net.CIDRMask(24, 32),
                Router:     netip.MustParseAddr("192.168.1.1"),
                DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
                DomainName: "example.local",
                LeaseTime:  24 * time.Hour,
            },
        },
    },
    IPAMBackend: dhcp.IPAMBackendMemory,
}

// Create and start server
server, err := dhcp.NewCoreDHCPServer(config, allocator)
if err != nil {
    return err
}

ctx := context.Background()
if err := server.Start(ctx); err != nil {
    return err
}
defer server.Stop(ctx)
```

### PXE Boot Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"

// Create PXE plugin with architecture filters
pxe, err := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),  // TFTP server
    "pxelinux.0",                  // Default boot file
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchIntelX86:   "pxelinux.0",      // BIOS
        dhcp.PXEArchEFIX8664:   "shimx64.efi",     // UEFI x64
        dhcp.PXEArchARMUEFI64:  "shimaa64.efi",    // ARM64 UEFI
    }),
    dhcp.WithTFTPRoot("/var/lib/tftpboot"),
)
```

## DHCP Message Flow

```
Client                         Server
   │                              │
   │──────── DHCPDISCOVER ───────►│
   │                              │ Allocate IP from IPAM
   │◄─────── DHCPOFFER ──────────│
   │                              │
   │──────── DHCPREQUEST ────────►│
   │                              │ Confirm allocation
   │◄─────── DHCPACK ────────────│
   │                              │
   │     (Lease Active)           │
   │                              │
   │──────── DHCPREQUEST ────────►│ (Renewal at T1)
   │◄─────── DHCPACK ────────────│
   │                              │
   │──────── DHCPRELEASE ────────►│ (Optional)
   │                              │ Release IP to IPAM
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Component design and integration |
| [Configuration](configuration.md) | Configuration reference |
| [Plugins](plugins.md) | IPAM and PXE plugin documentation |
| [API Reference](api-reference.md) | Go service interface (no wire API today) |

## Integration Points

### IPAM Integration

The DHCP service integrates with the platform IPAM system for IP allocation:

- Allocate IPs from named pools
- Track lease state in both DHCP and IPAM
- Automatic release on lease expiration
- Support for specific IP requests

### SDN Integration

Works with the SDN subsystem for network provisioning:

- Provisioning VLAN support
- Port authentication awareness
- Device onboarding workflows

### Gateway Integration

Supports gateway edge mode for device onboarding:

- IPv6 allocation for new devices
- DHT bootstrap support
- Certificate enrollment coordination

## CLI Commands

There is currently no `platformctl sdn dhcp` command group. The DHCP
server is configured via the `sdn.dhcp` YAML section and runs inside
the daemon; lease and pool state is visible through the IPAM CLI:

```bash
# Pools backing DHCP allocation
platformctl sdn ipam pool list

# Current allocations
platformctl sdn ipam allocations
```

See [Configuration](configuration.md) and [SDN CLI Usage](../cli-usage.md).

## References

- [RFC 2131 - DHCP](https://datatracker.ietf.org/doc/html/rfc2131)
- [RFC 2132 - DHCP Options](https://datatracker.ietf.org/doc/html/rfc2132)
- [RFC 4578 - DHCP PXE Options](https://datatracker.ietf.org/doc/html/rfc4578)
- [CoreDHCP Project](https://github.com/coredhcp/coredhcp)

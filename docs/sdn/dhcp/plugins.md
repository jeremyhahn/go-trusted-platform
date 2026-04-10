# DHCP Plugins

## Overview

The DHCP service uses a plugin-based architecture built on CoreDHCP. This document covers the two platform-specific plugins: the IPAM Plugin for IP allocation and the PXE Plugin for network boot support.

## IPAM Plugin

The IPAM Plugin (`platform-ipam`) bridges CoreDHCP to the platform's IPAM system, providing dynamic IP allocation from configured pools.

### Plugin Name

```go
const PluginName = "platform-ipam"
```

### Features

- Allocate IPs from named IPAM pools
- Lease tracking with dual-index lookup (IP/MAC)
- Configurable DHCP options per interface
- Support for lease renewal and release
- Automatic lease state management

### Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                           IPAMPlugin                                       │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐   │
│  │                        Message Handlers                             │   │
│  │  (Map-based dispatch for O(1) routing)                              │   │
│  │                                                                      │   │
│  │  handlers = map[MessageType]MessageHandler {                         │   │
│  │      DISCOVER: handleDiscover,                                       │   │
│  │      REQUEST:  handleRequest,                                        │   │
│  │      RELEASE:  handleRelease,                                        │   │
│  │      DECLINE:  handleDecline,                                        │   │
│  │      INFORM:   handleInform,                                         │   │
│  │  }                                                                    │   │
│  └────────────────────────────────────────────────────────────────────┘   │
│                              │                                             │
│                              ▼                                             │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │
│  │   IPAM Allocator   │  │    Lease Store     │  │   DHCP Options     │  │
│  │                    │  │                    │  │                    │  │
│  │ - Allocate()       │  │ - Add()            │  │ - SubnetMask       │  │
│  │ - AllocateSpecific │  │ - GetByIP()        │  │ - Router           │  │
│  │ - Release()        │  │ - GetByMAC()       │  │ - DNS              │  │
│  │ - Renew()          │  │ - Renew()          │  │ - LeaseTime        │  │
│  │                    │  │ - SetState()       │  │ - DomainName       │  │
│  └────────────────────┘  └────────────────────┘  └────────────────────┘  │
│                                                                            │
└───────────────────────────────────────────────────────────────────────────┘
```

### Creating the Plugin

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"

// Create IPAM plugin
plugin, err := dhcp.NewIPAMPlugin(
    allocator,                    // ipam.Allocator
    "internal-pool",              // Pool ID
    dhcp.DHCPOptions{            // DHCP options
        SubnetMask: net.CIDRMask(24, 32),
        Router:     netip.MustParseAddr("192.168.1.1"),
        DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
        LeaseTime:  24 * time.Hour,
    },
    dhcp.WithLogger(logger),
    dhcp.WithLeaseStore(customLeaseStore),
    dhcp.WithDefaultLease(24 * time.Hour),
)
if err != nil {
    return err
}
defer plugin.Close()
```

### Plugin Options

| Option | Function | Description |
|--------|----------|-------------|
| Logger | `WithLogger(logger)` | Set structured logger |
| Lease Store | `WithLeaseStore(ls)` | Use custom lease store |
| Default Lease | `WithDefaultLease(d)` | Set default lease duration |

### Message Handlers

#### DHCPDISCOVER Handler

Handles client discovery requests by allocating an IP from the IPAM pool.

```go
func (p *IPAMPlugin) handleDiscover(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
```

**Flow:**
1. Extract client MAC address
2. Check for existing active lease
3. If lease exists and can be renewed, return OFFER with existing IP
4. Allocate new IP from IPAM pool
5. Create lease record in store
6. Build and return DHCPOFFER

**IPAM Allocation Request:**
```go
allocation, err := p.allocator.Allocate(ctx, &ipam.AllocationRequest{
    PoolID:        p.poolID,
    DeviceID:      mac.String(),
    Hostname:      req.HostName(),
    Metadata: map[string]string{
        "dhcp_client":  "true",
        "message_type": "discover",
    },
    LeaseDuration: p.defaultLease,
})
```

#### DHCPREQUEST Handler

Handles client requests to confirm or renew an IP allocation.

```go
func (p *IPAMPlugin) handleRequest(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
```

**Flow:**
1. Extract client MAC and requested IP
2. If no requested IP, return DHCPNAK
3. Check existing lease for this MAC
4. If lease matches, renew and return DHCPACK
5. Check if IP is leased to another MAC (conflict)
6. Allocate specific IP from IPAM
7. Create lease record
8. Return DHCPACK or DHCPNAK on failure

**Requested IP Extraction:**
```go
func (p *IPAMPlugin) getRequestedIP(req *dhcpv4.DHCPv4) netip.Addr {
    // Check option 50 (Requested IP Address)
    if requestedIPOpt := req.Options.Get(dhcpv4.OptionRequestedIPAddress); requestedIPOpt != nil {
        if ip, ok := netip.AddrFromSlice(requestedIPOpt); ok {
            return ip
        }
    }
    // Fall back to ciaddr
    if req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified() {
        if ip, ok := netip.AddrFromSlice(req.ClientIPAddr.To4()); ok {
            return ip
        }
    }
    return netip.Addr{}
}
```

#### DHCPRELEASE Handler

Handles client release of an IP address.

```go
func (p *IPAMPlugin) handleRelease(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
```

**Flow:**
1. Extract client MAC and IP
2. Verify lease exists and belongs to this MAC
3. Release IP back to IPAM pool
4. Update lease state to Released
5. Remove lease from store
6. Return nil (no response for RELEASE)

#### DHCPDECLINE Handler

Handles client notification of an address conflict.

```go
func (p *IPAMPlugin) handleDecline(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
```

**Flow:**
1. Extract declined IP from options
2. Mark lease as Declined
3. Remove lease from store
4. Release IP back to IPAM
5. Return nil (no response for DECLINE)

#### DHCPINFORM Handler

Handles client requests for configuration only (no IP allocation).

```go
func (p *IPAMPlugin) handleInform(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)
```

**Flow:**
1. Verify client has an IP (ciaddr)
2. Build DHCPACK with configuration options
3. Remove lease-related options (not applicable)
4. Return DHCPACK with DNS, domain, NTP, etc.

### DHCP Options

The plugin adds standard DHCP options to responses:

```go
func (p *IPAMPlugin) addCommonOptions(resp *dhcpv4.DHCPv4) {
    // Option 1: Subnet Mask
    if p.options.SubnetMask != nil {
        resp.UpdateOption(dhcpv4.OptSubnetMask(p.options.SubnetMask))
    }

    // Option 3: Router (Default Gateway)
    if p.options.Router.IsValid() {
        resp.UpdateOption(dhcpv4.OptRouter(p.options.Router.AsSlice()))
    }

    // Option 6: DNS Servers
    if len(p.options.DNS) > 0 {
        dnsServers := make([]net.IP, len(p.options.DNS))
        for i, dns := range p.options.DNS {
            dnsServers[i] = dns.AsSlice()
        }
        resp.UpdateOption(dhcpv4.OptDNS(dnsServers...))
    }

    // Option 15: Domain Name
    if p.options.DomainName != "" {
        resp.UpdateOption(dhcpv4.OptDomainName(p.options.DomainName))
    }

    // Option 42: NTP Servers
    if len(p.options.NTPServers) > 0 {
        ntpServers := make([]net.IP, len(p.options.NTPServers))
        for i, ntp := range p.options.NTPServers {
            ntpServers[i] = ntp.AsSlice()
        }
        resp.UpdateOption(dhcpv4.OptNTPServers(ntpServers...))
    }

    // Option 26: Interface MTU
    if p.options.MTU > 0 {
        resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU, []byte{
            byte(p.options.MTU >> 8),
            byte(p.options.MTU),
        }))
    }

    // Option 12: Hostname
    if p.options.Hostname != "" {
        resp.UpdateOption(dhcpv4.OptHostName(p.options.Hostname))
    }
}

func (p *IPAMPlugin) addLeaseOptions(resp *dhcpv4.DHCPv4) {
    // Option 51: IP Address Lease Time
    leaseTime := uint32(p.options.LeaseTime.Seconds())
    resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(leaseTime) * time.Second))

    // Option 58: Renewal (T1) Time
    renewalTime := uint32(p.options.RenewalTime.Seconds())
    renewalBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(renewalBytes, renewalTime)
    resp.UpdateOption(dhcpv4.OptGeneric(OptionRenewalTimeValue, renewalBytes))

    // Option 59: Rebinding (T2) Time
    rebindTime := uint32(p.options.RebindTime.Seconds())
    rebindBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(rebindBytes, rebindTime)
    resp.UpdateOption(dhcpv4.OptGeneric(OptionRebindingTimeValue, rebindBytes))
}
```

### Dynamic Option Updates

Options can be updated at runtime:

```go
// Get current options
opts := plugin.GetOptions()

// Update options
newOpts := opts
newOpts.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
if err := plugin.SetOptions(newOpts); err != nil {
    return err
}
```

### Plugin Lifecycle

```go
// Create plugin
plugin, err := dhcp.NewIPAMPlugin(allocator, poolID, options)
if err != nil {
    return err
}

// Use plugin (attached to server)
handler := plugin.Handler4()

// Get lease store for inspection
leaseStore := plugin.GetLeaseStore()

// Get pool ID
poolID := plugin.GetPoolID()

// Close plugin (releases resources)
err = plugin.Close()
```

## PXE Plugin

The PXE Plugin (`platform-pxe`) adds network boot support to DHCP responses for PXE clients.

### Plugin Name

```go
const PXEPluginName = "platform-pxe"
```

### Features

- Automatic PXE client detection
- Architecture-aware boot file selection
- Support for BIOS and UEFI clients
- Configurable TFTP server
- iPXE chainloading support

### Architecture Codes

| Code | Constant | Architecture |
|------|----------|--------------|
| 0 | `PXEArchIntelX86` | Intel x86 BIOS |
| 1 | `PXEArchNECPC98` | NEC/PC98 |
| 2 | `PXEArchEFIItanium` | EFI Itanium |
| 6 | `PXEArchEFIIA32` | EFI IA32 |
| 7 | `PXEArchEFIX8664` | EFI x86-64 (UEFI) |
| 9 | `PXEArchEFIBC` | EFI Byte Code |
| 10 | `PXEArchARMUEFI32` | ARM 32-bit UEFI |
| 11 | `PXEArchARMUEFI64` | ARM 64-bit UEFI |
| 15 | `PXEArchX8664HTTP` | x86-64 UEFI HTTP |
| 25 | `PXEArchRISCVUEFI32` | RISC-V 32-bit UEFI |
| 27 | `PXEArchRISCVUEFI64` | RISC-V 64-bit UEFI |

### Creating the Plugin

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"

// Create PXE plugin
pxe, err := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),  // TFTP server
    "pxelinux.0",                  // Default boot file
    dhcp.WithPXELogger(logger),
    dhcp.WithTFTPRoot("/var/lib/tftpboot"),
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchIntelX86:  "pxelinux.0",
        dhcp.PXEArchEFIX8664:  "shimx64.efi",
        dhcp.PXEArchARMUEFI64: "shimaa64.efi",
    }),
)
if err != nil {
    return err
}
defer pxe.Close()
```

### Plugin Options

| Option | Function | Description |
|--------|----------|-------------|
| Logger | `WithPXELogger(logger)` | Set structured logger |
| TFTP Root | `WithTFTPRoot(path)` | Set TFTP root directory |
| Architecture Filters | `WithArchitectureFilters(map)` | Set per-architecture boot files |

### PXE Client Detection

The plugin detects PXE clients using:

1. **Option 60 (Vendor Class Identifier)**: Must start with "PXEClient"
2. **Option 93 (Client System Architecture Type)**: Presence indicates PXE capability

```go
func (p *PXEPlugin) isPXEClient(req *dhcpv4.DHCPv4) bool {
    // Check vendor class identifier (option 60)
    vendorClass := req.Options.Get(dhcpv4.OptionClassIdentifier)
    if vendorClass != nil {
        vcString := string(vendorClass)
        if strings.HasPrefix(vcString, "PXEClient") {
            return true
        }
    }

    // Check for client system architecture (option 93)
    archOpt := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
    if archOpt != nil && len(archOpt) >= 2 {
        return true
    }

    return false
}
```

### Architecture Detection

```go
func (p *PXEPlugin) getClientArchitecture(req *dhcpv4.DHCPv4) uint16 {
    // Option 93: Client System Architecture Type (2 bytes, big-endian)
    archOpt := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
    if archOpt != nil && len(archOpt) >= 2 {
        return binary.BigEndian.Uint16(archOpt[:2])
    }

    // Default to x86 BIOS
    return PXEArchIntelX86
}
```

### Boot File Selection

```go
func (p *PXEPlugin) getBootFileForArch(arch uint16) string {
    p.mu.RLock()
    defer p.mu.RUnlock()

    // Check architecture filters
    if p.archFilters != nil {
        if bootFile, ok := p.archFilters[arch]; ok {
            return bootFile
        }
    }

    // Fall back to default boot file
    return p.bootFileName
}
```

### PXE Options Added

The plugin adds the following options to DHCP responses:

| Field/Option | Description |
|--------------|-------------|
| `ServerIPAddr` (siaddr) | TFTP server address |
| `BootFileName` | Boot file path |
| Option 66 | TFTP Server Name |
| Option 67 | Boot File Name |

```go
func (p *PXEPlugin) Handler4() handler.Handler4 {
    return func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
        if !p.isPXEClient(req) {
            return resp, false  // Continue chain
        }

        arch := p.getClientArchitecture(req)
        bootFile := p.getBootFileForArch(arch)

        // Set server fields
        resp.ServerIPAddr = p.nextServer
        resp.BootFileName = bootFile

        // Add DHCP options
        resp.UpdateOption(dhcpv4.OptTFTPServerName(p.nextServer.String()))
        resp.UpdateOption(dhcpv4.OptBootFileName(bootFile))

        return resp, false  // Continue chain
    }
}
```

### Dynamic Configuration

```go
// Update TFTP server
if err := pxe.SetNextServer(net.ParseIP("192.168.1.20")); err != nil {
    return err
}

// Update default boot file
if err := pxe.SetBootFileName("newboot.0"); err != nil {
    return err
}

// Add architecture filter
if err := pxe.SetArchitectureFilter(dhcp.PXEArchEFIX8664, "grubx64.efi"); err != nil {
    return err
}

// Remove architecture filter
pxe.RemoveArchitectureFilter(dhcp.PXEArchEFIIA32)

// Get current configuration
server := pxe.GetNextServer()
bootFile := pxe.GetBootFileName()
filters := pxe.GetArchitectureFilters()
tftpRoot := pxe.GetTFTPRoot()
```

### Common PXE Configurations

#### BIOS (Legacy) Boot

```go
pxe, _ := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),
    "pxelinux.0",
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchIntelX86: "pxelinux.0",
    }),
)
```

#### UEFI Boot with Secure Boot

```go
pxe, _ := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),
    "shimx64.efi",  // Shim for Secure Boot
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchEFIX8664:  "shimx64.efi",   // x64 Secure Boot
        dhcp.PXEArchEFIIA32:   "shimia32.efi",  // x86 Secure Boot
        dhcp.PXEArchARMUEFI64: "shimaa64.efi",  // ARM64 Secure Boot
    }),
)
```

#### iPXE Chainloading

```go
pxe, _ := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),
    "undionly.kpxe",  // iPXE for BIOS
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchIntelX86: "undionly.kpxe",  // BIOS iPXE
        dhcp.PXEArchEFIX8664: "ipxe.efi",       // UEFI iPXE
    }),
)
```

#### HTTP Boot (UEFI)

```go
pxe, _ := dhcp.NewPXEPlugin(
    net.ParseIP("192.168.1.10"),
    "http://boot.example.com/boot.efi",
    dhcp.WithArchitectureFilters(map[uint16]string{
        dhcp.PXEArchX8664HTTP: "http://boot.example.com/bootx64.efi",
        dhcp.PXEArchX8632HTTP: "http://boot.example.com/bootia32.efi",
    }),
)
```

### Plugin Lifecycle

```go
// Create plugin
pxe, err := dhcp.NewPXEPlugin(server, bootFile, options...)
if err != nil {
    return err
}

// Get handler for use with CoreDHCP
handler := pxe.Handler4()

// Check if closed
// Plugin operations will be no-ops after Close()

// Close plugin
err = pxe.Close()
// Returns ErrPluginClosed if already closed
```

## Plugin Chaining

Both plugins can be used together in a handler chain:

```
Request → IPAM Plugin → PXE Plugin → Response
           │              │
           │              └─ Add PXE options if PXE client
           │
           └─ Allocate IP, build base response
```

The PXE plugin is designed to be non-blocking (`return resp, false`) so it can be chained with other plugins. It only modifies responses for PXE clients and passes through all others unchanged.

## Error Handling

### IPAM Plugin Errors

| Error | Cause |
|-------|-------|
| `ErrAllocatorRequired` | Nil allocator provided |
| `ErrPoolIDRequired` | Empty pool ID |
| `ErrPluginClosed` | Operation on closed plugin |

### PXE Plugin Errors

| Error | Cause |
|-------|-------|
| `ErrInvalidNextServer` | Nil or unspecified server address |
| `ErrInvalidBootFile` | Empty boot file name |
| `ErrPluginClosed` | Operation on closed plugin |

## See Also

- [README](README.md) - Package overview
- [Architecture](architecture.md) - Component design
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - API overview

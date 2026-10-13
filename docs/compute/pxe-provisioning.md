# PXE Boot and Provisioning

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [`docs/ipxe/`](../ipxe/) (`pkg/ipxe`, whose engineering.md §9 lists this file's defects) and [`docs/sdn/`](../sdn/) for VLAN placement; the fixed VLANs 1/998/100+ below were retired by the reference network.

## Overview

The iPXE server (`pkg/ipxe`) provides network boot infrastructure for device provisioning. It implements DHCP, TFTP, and HTTP servers that work together to boot devices from the network into the trusted platform enrollment flow.

## Architecture

```
                              PXE Boot Flow
+--------+     +--------+     +--------+     +--------+     +--------+
| Device |---->| DHCP   |---->| TFTP   |---->| HTTP   |---->| Boot   |
| (PXE)  |     | Server |     | Server |     | Server |     | Kernel |
+--------+     +--------+     +--------+     +--------+     +--------+
    |              |              |              |              |
    |   DISCOVER   |              |              |              |
    |------------->|              |              |              |
    |   OFFER      |              |              |              |
    |<-------------|              |              |              |
    |   REQUEST    |              |              |              |
    |------------->|              |              |              |
    |   ACK + PXE  |              |              |              |
    |<-------------|              |              |              |
    |              |   GET ipxe.efi              |              |
    |----------------------------->|              |              |
    |              |   iPXE FW     |              |              |
    |<-----------------------------|              |              |
    |              |              |  GET boot.ipxe|              |
    |------------------------------------------>|              |
    |              |              |  iPXE Script  |              |
    |<------------------------------------------|              |
    |              |              |  GET kernel   |              |
    |------------------------------------------>|------------->|
```

## Components

### PXE Server

The main server coordinates DHCP, TFTP, and HTTP services:

```go
cfg := &ipxe.ServerConfig{
    Interface:      "eth0",
    HTTPPort:       8080,
    TFTPPort:       69,
    EnableDHCP:     true,
    DHCPInterface:  "eth0",
    DHCPRangeStart: "192.168.1.100",
    DHCPRangeEnd:   "192.168.1.200",
    DHCPSubnetMask: "255.255.255.0",
    DHCPGateway:    "192.168.1.1",
    DHCPDNS:        "192.168.1.1",
    DHCPLeaseTime:  time.Hour,
    BootFilename:   "ipxe.efi",
    BootEntries: []ipxe.BootEntry{
        {
            Name:        "alpine",
            Description: "Alpine Linux 3.20",
            ISOURL:      "https://example.com/alpine.iso",
            Kernel:      "https://example.com/vmlinuz-lts",
            Initrd:      "https://example.com/initramfs-lts",
            Args:        "console=ttyS0",
        },
    },
}

server, err := ipxe.NewServer(cfg, logger)
if err != nil {
    return err
}

// Start with signal handling
err = server.RunWithSignals(ctx)
```

### DHCP Server

Provides IP addresses and PXE boot parameters to clients:

```go
dhcpConfig := &ipxe.DHCPConfig{
    Interface:      "eth0",
    ServerIP:       net.ParseIP("192.168.1.10"),
    BroadcastIP:    net.ParseIP("192.168.1.255"),
    SubnetMask:     net.ParseIP("255.255.255.0"),
    RangeStart:     net.ParseIP("192.168.1.100"),
    RangeEnd:       net.ParseIP("192.168.1.200"),
    LeaseTime:      time.Hour,
    Router:         net.ParseIP("192.168.1.1"),
    DNSServers:     []net.IP{net.ParseIP("192.168.1.1")},
    TFTPServerName: "pxe.example.com",
    TFTPServerIP:   net.ParseIP("192.168.1.10"),
    BootFilename:   "ipxe.efi",
    IPXEScript:     "http://192.168.1.10:8080/boot.ipxe",
}

server, err := ipxe.NewDHCPServer(dhcpConfig, logger)
if err != nil {
    return err
}

err = server.Start(ctx)
```

#### PXE Client Detection

The DHCP server identifies PXE clients using:

| Option | Value | Client Type |
|--------|-------|-------------|
| Option 60 (Vendor Class) | `PXEClient:*` | Standard PXE |
| Option 77 (User Class) | `iPXE` | iPXE Client |
| Option 93 (Client Arch) | Present | PXE capable |

#### Client Architectures

| Code | Architecture |
|------|--------------|
| 0x0000 | BIOS x86 |
| 0x0006 | EFI x86 |
| 0x0007 | EFI x64 |
| 0x0009 | EFI BC |

### TFTP Server

Serves iPXE firmware to PXE clients:

```go
tftpServer := ipxe.NewTFTPServer(cfg, serverIP, logger)
err := tftpServer.Start(ctx)
```

#### Firmware Files

| Filename | Description | Source |
|----------|-------------|--------|
| `ipxe.efi` | 64-bit UEFI iPXE | boot.ipxe.org |
| `ipxe32.efi` | 32-bit UEFI iPXE | boot.ipxe.org |

Firmware is automatically downloaded and cached:
- User cache: `~/.cache/go-trusted-platform/firmware/`
- System cache: `/var/cache/go-trusted-platform/firmware/`

### HTTP Server

Serves iPXE scripts and boot files:

```go
httpServer := ipxe.NewHTTPServer(cfg, logger)
err := httpServer.Start(ctx)
```

#### Endpoints

| Path | Purpose |
|------|---------|
| `/boot.ipxe` | Initial boot script |
| `/menu.ipxe` | Boot menu with entries |
| `/boot/{name}.ipxe` | Per-entry boot scripts |
| `/files/{path}` | Local file serving |
| `/proxy/https/{url}` | HTTPS proxy for iPXE |
| `/health` | Health check |
| `/static/{path}` | Static files |

## iPXE Script Generation

### Boot Script (`/boot.ipxe`)

```bash
#!ipxe
echo Booting from PXE server...
chain menu.ipxe || shell
```

### Menu Script (`/menu.ipxe`)

Dynamic menu generated from configured boot entries:

```bash
#!ipxe
menu PXE Boot Menu
item --gap --             --------- Boot Options ---------
item alpine               Alpine Linux 3.20
item ubuntu               Ubuntu 24.04 LTS
item --gap --             --------- Utilities -----------
item shell                Drop to iPXE shell
item reboot               Reboot system
item exit                 Exit to BIOS

choose --timeout 30000 --default alpine selected || goto exit
goto ${selected}

:alpine
echo Booting Alpine Linux...
chain http://192.168.1.10:8080/boot/alpine.ipxe || goto failed
```

### Entry Script (`/boot/{name}.ipxe`)

Generated based on boot entry type:

#### Network Boot (ISO-based)

```bash
#!ipxe
echo Booting Alpine Linux 3.20...

set iso_url https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard.iso
set kernel_url http://192.168.1.10:8080/proxy/https/example.com/vmlinuz-lts
set initrd_url http://192.168.1.10:8080/proxy/https/example.com/initramfs-lts

echo Loading kernel...
kernel ${kernel_url} alpine_repo=http://... modloop=http://...
echo Loading initrd...
initrd ${initrd_url}

boot || goto failed
```

#### Direct Kernel Boot

```bash
#!ipxe
echo Booting Custom OS...

kernel http://192.168.1.10:8080/files/vmlinuz console=ttyS0
initrd http://192.168.1.10:8080/files/initrd.img
boot || goto failed
```

## HTTPS Proxy

iPXE does not support HTTPS. The HTTP server provides a proxy endpoint:

```
Original:  https://example.com/path/to/file
Proxied:   http://pxe-server:8080/proxy/https/example.com/path/to/file
```

The proxy:
- Fetches HTTPS resources on behalf of iPXE
- Handles TLS termination
- Supports large file transfers (5 minute timeout)

## VLAN Strategy

### Network Segmentation

| VLAN | Name | Purpose |
|------|------|---------|
| 1 | PXE | Initial PXE boot, DHCP/TFTP access |
| 998 | Provisioning | Post-boot enrollment, limited access |
| 100+ | Production | Full network access after enrollment |

### Boot Flow with VLANs

```
1. Device powers on in VLAN 1 (PXE)
   - DHCP request/response
   - TFTP firmware download
   - HTTP script/kernel download

2. Kernel boots, switches to VLAN 998 (Provisioning)
   - Limited network access
   - TPM initialization
   - Certificate enrollment (ACME)

3. Enrollment completes, moves to VLAN 100+ (Production)
   - Full network access per policy
   - Periodic re-attestation
```

### OVS Configuration

```bash
# Create bridge with VLANs
ovs-vsctl add-br br0

# PXE VLAN trunk port
ovs-vsctl add-port br0 eth0 tag=1

# Device port (initial PXE VLAN)
ovs-vsctl add-port br0 tap-device tag=1

# Transition to provisioning
ovs-vsctl set port tap-device tag=998

# Transition to production
ovs-vsctl set port tap-device tag=100
```

## Configuration

### ServerConfig

```go
type ServerConfig struct {
    // Network interface to bind to
    Interface string

    // HTTP server port (default: 8080)
    HTTPPort int

    // TFTP server port (default: 69)
    TFTPPort int

    // External URL for HTTP server (auto-detected if empty)
    ExternalURL string

    // Directory to serve local files from
    LocalFilesDir string

    // DHCP configuration
    EnableDHCP     bool
    DHCPInterface  string
    DHCPRangeStart string
    DHCPRangeEnd   string
    DHCPSubnetMask string
    DHCPGateway    string
    DHCPDNS        string
    DHCPLeaseTime  time.Duration
    DHCPServerIP   string

    // Boot configuration
    TFTPServerName string
    BootFilename   string      // Initial firmware (ipxe.efi)
    IPXEScript     string      // Script URL for iPXE clients
    BootEntries    []BootEntry // Available boot options
}
```

### BootEntry

```go
type BootEntry struct {
    Name        string // Menu identifier
    Description string // Display name
    ISOURL      string // ISO file URL
    Kernel      string // Kernel URL/path
    Initrd      string // Initrd URL/path
    Args        string // Kernel arguments
    AutoInstall string // Autoinstall config path
}
```

## Boot Flow: PXE to Authenticated

### Complete Provisioning Sequence

```
1. Device PXE Boot
   +------------------+
   | BIOS/UEFI        |
   | Network Boot     |
   +--------+---------+
            |
            v
2. DHCP Discovery
   +------------------+
   | Get IP + PXE     |
   | Options          |
   +--------+---------+
            |
            v
3. TFTP Download
   +------------------+
   | Download iPXE    |
   | Firmware         |
   +--------+---------+
            |
            v
4. iPXE Execution
   +------------------+
   | Chain to HTTP    |
   | Boot Script      |
   +--------+---------+
            |
            v
5. Kernel Boot
   +------------------+
   | Download Kernel  |
   | + Initrd         |
   +--------+---------+
            |
            v
6. OS Initialize
   +------------------+
   | TPM Init         |
   | Network Config   |
   +--------+---------+
            |
            v
7. Certificate Enrollment
   +------------------+
   | ACME Request     |
   | TPM Attestation  |
   +--------+---------+
            |
            v
8. Network Transition
   +------------------+
   | VLAN Change      |
   | Policy Apply     |
   +--------+---------+
            |
            v
9. Production Access
   +------------------+
   | Full Network     |
   | Ongoing Attest.  |
   +------------------+
```

## Error Handling

| Error | Description |
|-------|-------------|
| `ErrInvalidConfig` | Configuration validation failed |
| `ErrInvalidPort` | Port number out of range |
| `ErrInvalidInterface` | Network interface not found |
| `ErrInvalidIPRange` | DHCP IP range invalid |
| `ErrNoBootEntries` | No boot entries configured |
| `ErrInvalidBootEntry` | Boot entry missing required fields |
| `ErrNoServerIP` | Cannot determine server IP |
| `ErrNoAvailableIPs` | DHCP pool exhausted |
| `ErrFirmwareNotFound` | iPXE firmware not cached |

## Monitoring

### Health Check

```bash
curl http://pxe-server:8080/health
# {"status":"healthy"}
```

### Readiness Check

```go
server, _ := ipxe.NewServer(cfg, logger)
go server.Start(ctx)

// Wait for all services
err := server.WaitForReady(10 * time.Second)
```

### Logging

All servers log at structured levels:
- INFO: Service start/stop, successful boots
- DEBUG: DHCP packets, TFTP transfers
- WARN: Optional firmware unavailable
- ERROR: Service failures

## Security Considerations

1. **Network Isolation**: PXE VLAN should be isolated from production networks

2. **DHCP Security**: Run on trusted network segments only

3. **Firmware Integrity**: iPXE firmware downloaded from official sources

4. **HTTPS Proxy**: Only proxies HTTPS to HTTP, not arbitrary protocols

5. **Path Traversal**: Static/local file handlers validate paths

## Related Documentation

- [Network Authentication](network-auth.md)
- [Compute Architecture](architecture.md)
- [802.1X Network Attachment](802.1X-network-attachment.md)

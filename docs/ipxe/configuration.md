# iPXE Configuration Reference

## ServerConfig

Main configuration structure for the PXE server.

```go
type ServerConfig struct {
    Interface     string       // Network interface (empty = all)
    BindHost      string       // HTTP/TFTP bind address (empty = every interface)
    HTTPPort      int          // HTTP port (default: 8080)
    TFTPPort      int          // TFTP port (default: 69)
    ExternalURL   string       // External URL (auto-detected)
    LocalFilesDir string       // Directory for /files/* endpoint
    DHCP          DHCPConfig   // DHCP configuration
    BootEntries   []BootEntry  // Boot menu entries
}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Interface` | string | "" | Network interface PXE serves: the server IP is detected from it, and the DHCP socket is bound to it (`SO_BINDTODEVICE`) unless `DHCPInterface` is set. It does not choose the HTTP or TFTP address; `BindHost` does. |
| `BindHost` | string | "" (`DefaultBindHost`) | IP address the HTTP and TFTP servers bind. Empty is the unspecified address: every interface. Anything but an IP address fails validation with `ErrInvalidBindHost`. A specific address is also the server IP when `DHCPServerIP` is unset. See [Bind address](#bind-address). |
| `HTTPPort` | int | 8080 | HTTP server port for boot scripts and files. |
| `TFTPPort` | int | 69 | TFTP server port for iPXE firmware. |
| `ExternalURL` | string | auto | Base URL for boot scripts. Auto-detected from interface if empty. |
| `LocalFilesDir` | string | "" | Directory to serve via `/files/*` endpoint. |
| `DHCP` | DHCPConfig | - | DHCP server configuration. |
| `BootEntries` | []BootEntry | - | List of boot menu entries. |

## Bind address

Every listener address comes from configuration; none is hardcoded (#93).

| Listener | Binds | Set by |
|---|---|---|
| HTTP | `BindHost`:`HTTPPort` | `ServerConfig.BindHost`; pxeboot `--bind-host`; container `BOOTSTRAP_BIND_HOST`; bootstrap YAML `deployer.bootstrap_bind_host` |
| TFTP | `BindHost`:`TFTPPort` | as HTTP |
| DHCP | the unspecified address :`DHCPPort`, restricted to `DHCPInterface` (else `Interface`) by `SO_BINDTODEVICE` | the interface fields |

The precedence is the container's: the deployer's YAML key becomes the
`BOOTSTRAP_BIND_HOST` environment variable, the entrypoint turns a set
variable into `--bind-host`, and an unset one leaves the flag's default,
`DefaultBindHost` (empty, every interface).

**DHCP does not bind `BindHost`, deliberately.** A PXE client has no address
yet, so it broadcasts its DISCOVER and REQUEST to 255.255.255.255. Linux
delivers a datagram sent to the limited broadcast address only to a UDP
socket bound to the unspecified address; a socket bound to the server's
unicast address never sees it, and the DHCP server would never hear a client.
The socket therefore stays on the unspecified address, and `SO_BINDTODEVICE`
is what confines it to the provisioning segment. That scoping is by
interface, not by address, and needs `CAP_NET_RAW`.

## DHCPConfig

DHCP server configuration.

```go
type DHCPConfig struct {
    Enabled     bool   // Enable DHCP server
    Interface   string // DHCP interface (uses raw sockets if set)
    RangeStart  string // First IP in range
    RangeEnd    string // Last IP in range
    SubnetMask  string // Subnet mask
    Gateway     string // Default gateway
    DNS         string // DNS server
    LeaseTime   int    // Lease time in seconds
    ServerIP    string // Server IP (auto-detected)
}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | bool | true | Enable DHCP server. |
| `Interface` | string | "" | Interface for DHCP. When set, uses raw sockets for bridged network support. |
| `RangeStart` | string | "192.168.1.100" | Start of IP allocation range. |
| `RangeEnd` | string | "192.168.1.200" | End of IP allocation range. |
| `SubnetMask` | string | "255.255.255.0" | Network subnet mask. |
| `Gateway` | string | "192.168.1.1" | Default gateway for clients. |
| `DNS` | string | "8.8.8.8" | DNS server for clients. |
| `LeaseTime` | int | 3600 | IP lease duration in seconds. |
| `ServerIP` | string | auto | PXE server IP. Auto-detected from interface if empty. |

## BootEntry

Boot menu entry configuration.

```go
type BootEntry struct {
    Name        string // Entry identifier (alphanumeric, dashes)
    Description string // Human-readable description
    ISOURL      string // ISO URL (for network boot)
    Kernel      string // Kernel path or URL
    Initrd      string // Initrd path or URL
    Args        string // Kernel arguments
    AutoInstall string // Autoinstall config path
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Unique identifier for the boot entry. Used in URLs. |
| `Description` | string | Display name shown in boot menu. |
| `ISOURL` | string | URL to ISO for netboot distributions (Alpine). |
| `Kernel` | string | Path or URL to kernel (vmlinuz). |
| `Initrd` | string | Path or URL to initrd (initramfs). |
| `Args` | string | Kernel command line arguments. |
| `AutoInstall` | string | Path to autoinstall/preseed configuration. |

## Example Configurations

### Minimal Configuration

```go
config := ipxe.DefaultServerConfig()
config.BootEntries = []ipxe.BootEntry{
    {
        Name:        "alpine",
        Description: "Alpine Linux",
        Kernel:      "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/vmlinuz-lts",
        Initrd:      "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/initramfs-lts",
    },
}
```

### Isolated Test Network

```go
config := &ipxe.ServerConfig{
    Interface:     "pxe-br",
    BindHost:      "10.99.99.1",
    HTTPPort:      8080,
    TFTPPort:      69,
    ExternalURL:   "http://10.99.99.1:8080",
    LocalFilesDir: "/tmp/boot-files",
    DHCP: ipxe.DHCPConfig{
        Enabled:    true,
        Interface:  "pxe-br",
        RangeStart: "10.99.99.100",
        RangeEnd:   "10.99.99.200",
        SubnetMask: "255.255.255.0",
        Gateway:    "10.99.99.1",
        DNS:        "8.8.8.8",
        LeaseTime:  3600,
        ServerIP:   "10.99.99.1",
    },
    BootEntries: []ipxe.BootEntry{
        {
            Name:        "local-alpine",
            Description: "Local Alpine Install",
            Kernel:      "http://10.99.99.1:8080/files/vmlinuz-lts",
            Initrd:      "http://10.99.99.1:8080/files/initramfs-lts",
            Args:        "console=ttyS0,115200n8",
        },
    },
}
```

### Multiple Boot Entries

```go
config.BootEntries = []ipxe.BootEntry{
    {
        Name:        "alpine-standard",
        Description: "Alpine Linux 3.22 Standard",
        Kernel:      "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/vmlinuz-lts",
        Initrd:      "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/initramfs-lts",
        Args:        "alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.22/main modloop=https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/modloop-lts",
    },
    {
        Name:        "trusted-platform",
        Description: "Trusted Platform Installer",
        Kernel:      "http://10.99.99.1:8080/files/vmlinuz-lts",
        Initrd:      "http://10.99.99.1:8080/files/initramfs-lts",
        Args:        "console=ttyS0 autoinstall",
    },
}
```

## URL Handling

### HTTPS Proxy

iPXE doesn't support HTTPS. The HTTP server automatically proxies HTTPS URLs:

```
Original:  https://example.com/vmlinuz
Proxied:   http://server:8080/proxy/https/example.com/vmlinuz
```

This conversion happens automatically for:
- `Kernel` URLs
- `Initrd` URLs
- URLs in `Args` field

### Local Files

Files in `LocalFilesDir` are served at `/files/*`:

```
LocalFilesDir: /tmp/boot
File: /tmp/boot/vmlinuz-lts
URL:  http://server:8080/files/vmlinuz-lts
```

## Validation

Configuration is validated when creating a server:

```go
server, err := ipxe.NewServer(config, logger)
if err != nil {
    // Handle validation error
}
```

Validation checks:
- Port numbers in valid range (1-65535)
- `BindHost` is empty or an IP address (`ErrInvalidBindHost`)
- IP addresses are valid
- DHCP range is valid (start < end)
- Boot entries have required fields (Name, Kernel, Initrd)
- Interface exists (if specified)

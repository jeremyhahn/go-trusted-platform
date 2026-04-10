# iPXE Package

The `pkg/ipxe` package provides a complete PXE boot server implementation for network booting QEMU instances within the trusted platform test environment.

## Overview

The iPXE package combines three services into a single orchestrated server:

- **DHCP Server** - Assigns IP addresses and provides PXE boot options
- **TFTP Server** - Serves iPXE firmware to boot clients
- **HTTP Server** - Serves boot scripts, kernels, initrds, and local files

## Quick Start

### Programmatic Usage

```go
package main

import (
    "context"
    "net"

    "github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func main() {
    logger := logging.DefaultLogger()

    config := ipxe.DefaultServerConfig()
    config.Interface = "br0"
    config.DHCP.ServerIP = "10.99.99.1"
    config.DHCP.RangeStart = "10.99.99.100"
    config.DHCP.RangeEnd = "10.99.99.200"
    config.BootEntries = []ipxe.BootEntry{
        {
            Name:        "alpine",
            Description: "Alpine Linux",
            Kernel:      "http://10.99.99.1:8080/files/vmlinuz-lts",
            Initrd:      "http://10.99.99.1:8080/files/initramfs-lts",
            Args:        "console=ttyS0",
        },
    }

    server, err := ipxe.NewServer(config, logger)
    if err != nil {
        panic(err)
    }

    ctx := context.Background()
    server.Start(ctx)
}
```

### CLI Usage

```bash
# PXE boot from an ISO (extracts kernel/initrd automatically)
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso

# PXE boot with direct kernel/initrd URLs
sudo platformctl iso test pxe \
    --kernel http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/vmlinuz-lts \
    --initrd http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/initramfs-lts

# PXE boot with local files
sudo platformctl iso test pxe \
    --kernel /path/to/vmlinuz \
    --initrd /path/to/initramfs \
    --args "console=ttyS0 quiet"
```

## Documentation

- [Architecture](architecture.md) - Component design and data flow
- [Configuration](configuration.md) - Configuration reference
- [Testing](testing.md) - Test environment setup and usage

## Requirements

- Linux (raw sockets for DHCP on bridged networks)
- Root privileges (for network setup and privileged ports)
- QEMU with OVMF (for UEFI PXE boot)

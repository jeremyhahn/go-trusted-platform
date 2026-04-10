# iPXE Testing Guide

## CLI Test Command

The `platformctl iso test pxe` command provides a complete PXE boot test environment.

### Basic Usage

```bash
# Test with an ISO (extracts kernel/initrd automatically)
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso

# Test with direct URLs
sudo platformctl iso test pxe \
    --kernel https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/vmlinuz-lts \
    --initrd https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/initramfs-lts

# Test with local files
sudo platformctl iso test pxe \
    --kernel /path/to/vmlinuz \
    --initrd /path/to/initramfs
```

### Command Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--iso` | - | Path to ISO file (extracts boot files) |
| `--kernel` | - | Path or URL to kernel |
| `--initrd` | - | Path or URL to initrd |
| `--args` | - | Custom kernel arguments |
| `--memory` | 8192 | VM memory in MB |
| `--cpus` | (all) | Number of CPUs |
| `--work-dir` | work | Working directory |
| `--debug` | false | Enable debug output |
| `--secure-boot` | true | Enable UEFI Secure Boot |

### What It Does

1. Creates isolated bridge network (10.99.99.0/24)
2. Sets up NAT for internet access
3. Starts PXE server (DHCP, TFTP, HTTP)
4. Creates QEMU VM with TPM
5. Boots VM via PXE

## Programmatic Testing

### Using TestEnv

```go
package main

import (
    "context"
    "time"

    "github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

func main() {
    logger := logging.DefaultLogger()
    ctx := context.Background()

    // Create test environment config
    cfg := ipxe.DefaultTestEnvConfig()
    cfg.BootEntries = []ipxe.BootEntry{
        {
            Name:        "test",
            Description: "Test Boot",
            Kernel:      "http://10.99.99.1:8080/files/vmlinuz",
            Initrd:      "http://10.99.99.1:8080/files/initramfs",
        },
    }

    // Create and setup test environment
    env, err := ipxe.NewTestEnv(cfg, logger)
    if err != nil {
        panic(err)
    }

    // Setup network (requires root)
    if err := env.Setup(); err != nil {
        panic(err)
    }
    defer env.Cleanup()

    // Start PXE server
    go env.Start(ctx)
    time.Sleep(2 * time.Second) // Wait for server

    // Create QEMU VM
    qemuCfg := qemu.DefaultConfig()
    qemuCfg.TapDevice = env.TapName()
    qemuCfg.PXEEnabled = true
    qemuCfg.Memory = 2048

    vm, err := qemu.NewVM(qemuCfg, logger)
    if err != nil {
        panic(err)
    }

    // Boot via PXE
    vm.Start(ctx, string(qemu.BootModePXE))
}
```

### Isolated Network Setup

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/testenv"

// Create network config
netCfg := testenv.DefaultNetworkConfig()
// Bridge: pxe-br (10.99.99.1)
// TAP: tap-pxe
// DHCP: 10.99.99.100-200

// Create and setup
network := testenv.NewIsolatedNetwork(netCfg)
if err := network.Setup(); err != nil {
    panic(err)
}
defer network.Cleanup()

// Use network.TapName() for QEMU
```

### ISO Boot File Extraction

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"

// Extract boot files from ISO
extractDir, kernel, initrd, modloop, args, err := ipxe.ExtractBootFiles("/path/to/alpine.iso")
if err != nil {
    panic(err)
}
defer os.RemoveAll(extractDir)

// Use extracted files
fmt.Printf("Kernel: %s\n", kernel)
fmt.Printf("Initrd: %s\n", initrd)
fmt.Printf("Args: %s\n", args)
```

## Network Topology

```
┌───────────────────────────────────────────────┐
│              Test Environment                 │
│                                               │
│   ┌───────────────────────────────────────┐   │
│   │           Bridge: pxe-br              │   │
│   │           IP: 10.99.99.1/24           │   │
│   │                                       │   │
│   │   ┌─────────────┐   ┌─────────────┐   │   │
│   │   │ PXE Server  │   │ TAP Device  │   │   │
│   │   │             │   │ tap-pxe     │   │   │
│   │   │ DHCP :67    │   │      │      │   │   │
│   │   │ TFTP :69    │   │      │      │   │   │
│   │   │ HTTP :8080  │   │      ▼      │   │   │
│   │   └─────────────┘   │ ┌─────────┐ │   │   │
│   │                     │ │  QEMU   │ │   │   │
│   │                     │ │   VM    │ │   │   │
│   │                     │ └─────────┘ │   │   │
│   │                     └─────────────┘   │   │
│   └───────────────────────────────────────┘   │
│                       │                       │
│                 NAT (iptables)                │
│                       │                       │
│                    Internet                   │
└───────────────────────────────────────────────┘
```

## Debugging

### Enable Debug Logging

```bash
sudo platformctl iso test pxe --iso alpine.iso --debug
```

### Check Services

```bash
# DHCP traffic
sudo tcpdump -i pxe-br port 67 or port 68

# TFTP traffic
sudo tcpdump -i pxe-br port 69

# HTTP traffic
curl http://10.99.99.1:8080/health
curl http://10.99.99.1:8080/menu.ipxe
```

### Common Issues

**Permission Denied**
```
Error: test command requires root privileges
```
Solution: Run with `sudo`

**Bridge Already Exists**
```
Error: failed to create bridge: file exists
```
Solution: Clean up stale resources:
```bash
sudo ip link delete pxe-br
sudo ip link delete tap-pxe
```

**DHCP Not Working**
- Check bridge has IP: `ip addr show pxe-br`
- Check NAT rules: `sudo iptables -t nat -L`
- Enable IP forwarding: `echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`

**TFTP Timeout**
- Verify TFTP server running: `netstat -uln | grep 69`
- Check firmware downloaded: `ls ~/.cache/go-trusted-platform/firmware/`

## Unit Tests

Run the package tests:

```bash
# All tests
go test ./pkg/ipxe/...

# Specific test
go test ./pkg/ipxe/... -run TestHTTPServer

# With coverage
go test ./pkg/ipxe/... -cover
```

Note: Some tests require root for network operations and are skipped in CI.

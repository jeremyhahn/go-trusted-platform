# QEMU Package

The `qemu` package provides Go bindings for managing QEMU virtual machines with support for UEFI, Secure Boot, TPM, and advanced virtualization features.

## Features

- QEMU VM lifecycle management (create, start, stop, wait)
- UEFI firmware support (OVMF)
- Secure Boot with custom key enrollment
- TPM 2.0 integration (swtpm)
- KVM acceleration
- VirtIO devices for optimal performance
- Network configuration (user mode, bridged, none)
- Serial console and VNC support
- qcow2 disk image management
- NVRAM management for UEFI variables

## Installation

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

func main() {
    // Create configuration
    config := qemu.DefaultConfig()
    config.ISO = "alpine.iso"
    config.DiskPath = "vm.qcow2"
    config.DiskSize = "20G"
    config.Memory = 4096
    config.CPUs = 4
    config.SecureBoot = true

    // Create logger
    logger := logging.DefaultLogger()

    // Create VM instance
    vm, err := qemu.NewVM(config, logger)
    if err != nil {
        log.Fatal(err)
    }

    // Create disk image
    if err := vm.CreateDisk(); err != nil {
        log.Fatal(err)
    }

    // Start VM in install mode (boots from ISO)
    ctx := context.Background()
    if err := vm.Start(ctx, "install"); err != nil {
        log.Fatal(err)
    }

    // Wait for installation to complete
    if err := vm.Wait(); err != nil {
        log.Printf("VM exited: %v", err)
    }

    // Boot from disk
    if err := vm.Start(ctx, "boot"); err != nil {
        log.Fatal(err)
    }

    // Wait for VM to exit
    if err := vm.Wait(); err != nil {
        log.Printf("VM exited: %v", err)
    }
}
```

### Configuration

```go
// Create custom configuration
config := &qemu.Config{
    // Required fields
    DiskPath: "/path/to/vm.qcow2",
    DiskSize: "20G",
    Memory:   4096,  // MB
    CPUs:     4,
    WorkDir:  "work",

    // Optional fields
    ISO:           "/path/to/install.iso",
    SecureBoot:    true,
    EnableKVM:     true,
    SerialConsole: true,
    NoGraphic:     true,
    BootOrder:     "d",  // d = CD-ROM first
    NetworkMode:   "user",
    VNCDisplay:    0,  // 0 = disabled, >0 = VNC port

    // OVMF firmware paths
    OVMFCode:       "/usr/share/OVMF/OVMF_CODE_4M.fd",
    OVMFCodeSecure: "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    OVMFVars:       "/usr/share/OVMF/OVMF_VARS_4M.fd",

    // TPM socket path
    TPMSocket: "/path/to/swtpm.sock",
}

// Validate configuration
if err := config.Validate(); err != nil {
    log.Fatal(err)
}
```

### Guest architectures

`Config.Arch` selects an architecture profile (`arch.go`); everything the
command line shares (memory, network, QMP, serial, RNG) is built once and
the profile supplies the rest:

| | `x86_64` (default) | `aarch64` |
|---|---|---|
| binary | `qemu-system-x86_64` | `qemu-system-aarch64` |
| machine / CPU | `q35` (`smm=on` with Secure Boot) / `host` under KVM, `max` under TCG | `virt,gic-version=3` / `cortex-a72`; under KVM `virt,gic-version=host` / `host`, so a GICv2-only host such as the Raspberry Pi 4 boots |
| firmware | OVMF in two pflash drives, NVRAM copied from `OVMFVars` | `Firmware` (U-Boot `u-boot.bin`) as `-bios`; no NVRAM file |
| disk | AHCI (`ide-hd`), `qcow2` | `virtio-blk-pci`, `raw` |
| TPM front-end | `tpm-tis` | `tpm-tis-device` |
| boot modes | install (ISO on AHCI), boot, pxe | boot, pxe (install is refused: there is no aarch64 ISO) |
| KVM | `EnableKVM` on an amd64 host | `EnableKVM` on an arm64 host; elsewhere TCG |

KVM also needs `/dev/kvm` to open read-write. When `EnableKVM` is set but it
does not (no device, or no access), the guest runs TCG and one warning names
the reason. `Config.KVMProbe` replaces the probe in tests.

The x86_64 command line is pinned by `TestBuildQEMUCommand_X86Golden` to
what it was before the profiles existed. `DiskFormat` and `TPMDevice`
override the profile defaults. The aarch64 profile is how the Raspberry Pi
factory image is booted without the hardware
(`platformctl diskimage test boot`, `pkg/diskimage.Boot`):

```go
config := &qemu.Config{
    Arch:       qemu.ArchAArch64,
    Firmware:   "build/docker/uboot-builder/output/qemu_arm64/u-boot.bin",
    DiskPath:   "work/diskimage-test/disk.img",
    DiskFormat: qemu.DiskFormatRaw,
    DiskSize:   "4096M",
    Memory:     2048,
    CPUs:       4,
    WorkDir:    "work/diskimage-test",
    TPMSocket:  "work/diskimage-test/tpm/swtpm.sock",
    NoGraphic:  true,
    SerialLogFile: "work/diskimage-test/serial.log",
}
```

### The harness package

`pkg/qemu/harness` is what every emulated boot shares: `StartTPM` starts
(or resumes) the swtpm for a `Config` and points `TPMSocket` at the socket
it opened, `WaitForSerial` waits for a milestone in the serial transcript,
and `Console` drives an interactive session on `ConsoleSocketPath` (stop
U-Boot's autoboot, run `tpm2 info`). `platformctl iso test`,
`platformctl diskimage test boot` and the integration suites use it.

### Boot Modes

The VM supports two boot modes:

1. **Install Mode**: Boots from ISO for installation
   ```go
   err := vm.Start(ctx, "install")
   ```

2. **Boot Mode**: Boots from disk
   ```go
   err := vm.Start(ctx, "boot")
   ```

### Secure Boot

Enable Secure Boot and enroll custom keys:

```go
// Configure Secure Boot
config.SecureBoot = true
config.OVMFCodeSecure = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"

// Create enroller
enrollerConfig := &qemu.SecureBootEnrollerConfig{
    KeysDir:      "/path/to/secure-boot-keys",
    NVRAMDir:     config.WorkDir + "/nvram",
    OVMFVarsPath: config.OVMFVars,
}

enroller, err := qemu.NewSecureBootEnroller(enrollerConfig, logger)
if err != nil {
    log.Fatal(err)
}

// Enroll keys
if err := enroller.EnrollKeys(context.Background()); err != nil {
    log.Fatal(err)
}

// Validate enrollment
if err := enroller.ValidateEnrollment(context.Background()); err != nil {
    log.Fatal(err)
}
```

### TPM Integration

The package automatically detects and connects to a TPM socket if available:

```go
config.TPMSocket = "/path/to/tpm/swtpm.sock"

// VM will automatically connect to TPM if socket exists
vm, err := qemu.NewVM(config, logger)
```

### VM Lifecycle Management

```go
// Check if VM is running
if vm.IsRunning() {
    log.Println("VM is running")
}

// Get process ID
pid := vm.GetPID()
log.Printf("VM PID: %d", pid)

// Stop VM gracefully
if err := vm.Stop(); err != nil {
    log.Printf("Failed to stop VM: %v", err)
}

// Wait for VM to exit
if err := vm.Wait(); err != nil {
    log.Printf("VM exited with error: %v", err)
}
```

### Error Handling

The package defines standard errors:

```go
switch {
case errors.Is(err, qemu.ErrISONotFound):
    log.Println("ISO file not found")
case errors.Is(err, qemu.ErrDiskNotFound):
    log.Println("Disk file not found")
case errors.Is(err, qemu.ErrOVMFNotFound):
    log.Println("OVMF firmware not found")
case errors.Is(err, qemu.ErrTPMNotRunning):
    log.Println("TPM socket not available")
case errors.Is(err, qemu.ErrVMAlreadyRunning):
    log.Println("VM is already running")
case errors.Is(err, qemu.ErrVMNotRunning):
    log.Println("VM is not running")
case errors.Is(err, qemu.ErrInvalidMode):
    log.Println("Invalid boot mode")
}
```

## Testing

Run unit tests:

```bash
go test -v ./pkg/qemu/...
```

Run tests with coverage:

```bash
go test -v -coverprofile=coverage.out ./pkg/qemu/...
go tool cover -html=coverage.out
```

The unit tests do not need `qemu-img`. `CreateDisk` reaches it through a seam,
and the tests replace it with an in-memory fake. The tests that run the real
`qemu-img` are in `test/integration/vtpm/qemu_test.go`. They run in the
devcontainer with `make integration-test-vtpm`, and they fail if the binary is
missing.

## Requirements

- QEMU (qemu-system-x86_64)
- qemu-img (for disk creation)
- OVMF firmware files
- Optional: swtpm (for TPM support)

## Architecture

The package consists of:

- **qemu.go**: Core VM management
- **config.go**: Configuration structures
- **types.go**: Error definitions and boot modes
- **secureboot.go**: Secure Boot key enrollment
- **disk_test.go**: Disk and command building tests
- **qemu_test.go**: Core VM functionality tests
- **secureboot_test.go**: Secure Boot enrollment tests

## Best Practices

1. **Always validate configuration** before creating a VM
2. **Use context** for proper cancellation and timeouts
3. **Check VM state** before operations (IsRunning, GetPID)
4. **Handle errors** appropriately with type assertions
5. **Clean up resources** by stopping VMs when done
6. **Use KVM acceleration** when available for better performance
7. **Enable TPM** for secure boot and attestation use cases

## Examples

See the `examples/` directory for complete working examples:

- Basic VM creation and management
- Secure Boot configuration
- TPM integration
- Network configuration
- Custom firmware setup

## References

- [QEMU Documentation](https://www.qemu.org/documentation/)
- [OVMF/UEFI Firmware](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)
- [swtpm TPM Emulator](https://github.com/stefanberger/swtpm)
- [UEFI Secure Boot](https://wiki.ubuntu.com/UEFI/SecureBoot)

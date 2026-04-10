# Unified Kernel Image (UKI)

## Overview

A Unified Kernel Image (UKI) is a single EFI PE/COFF executable that bundles all components needed to boot a Linux system:

- Linux kernel (vmlinuz)
- Initial ramdisk (initramfs)
- Kernel command line
- OS release information
- Optional CPU microcode, splash screen, and device tree

UKIs simplify secure boot by consolidating all boot components into a single signed file. This eliminates the need for separate signature verification of kernel, initramfs, and command line, reducing the attack surface and simplifying key management.

### Benefits

| Benefit | Description |
|---------|-------------|
| **Single Signature** | One Authenticode signature protects all boot components |
| **Tamper Protection** | Command line is embedded and cannot be modified at boot |
| **Simplified Boot Chain** | Firmware loads one file instead of multiple components |
| **Measured Boot** | Single PCR measurement for entire boot payload |
| **Distribution** | Single file to deploy, sign, and manage |

## Features

| Feature | Description |
|---------|-------------|
| Native PE/COFF manipulation | Pure Go implementation, no external tools required |
| Multi-architecture support | x86_64, aarch64, arm, riscv64 |
| Section management | Add standard and custom PE sections |
| EFI stub integration | Uses kernel's built-in EFI stub (CONFIG_EFI_STUB) |
| SBAT support | Secure Boot Advanced Targeting metadata |
| Parser included | Extract and inspect UKI components |
| Authenticode compatible | Sign with `pkg/authenticode` for Secure Boot |

## UKI Structure

A UKI is a PE/COFF executable containing multiple sections:

```
+---------------------------+
|      DOS Header (MZ)      |
+---------------------------+
|        PE Signature       |
+---------------------------+
|       COFF Header         |
+---------------------------+
|     Optional Header       |
+---------------------------+
|    Section Headers        |
+---------------------------+
|                           |
|   .osrel    (OS release)  |  Optional
|                           |
+---------------------------+
|                           |
|  .cmdline   (kernel args) |  Required
|                           |
+---------------------------+
|                           |
|   .ucode    (microcode)   |  Optional
|                           |
+---------------------------+
|                           |
|   .splash   (boot image)  |  Optional
|                           |
+---------------------------+
|                           |
|   .linux    (kernel)      |  Required (base PE)
|                           |
+---------------------------+
|                           |
|   .initrd   (initramfs)   |  Required
|                           |
+---------------------------+
|                           |
|    .dtb     (device tree) |  Optional (ARM)
|                           |
+---------------------------+
|                           |
|    .sbat    (SBAT data)   |  Optional
|                           |
+---------------------------+
```

### Section Reference

| Section | Required | Description |
|---------|----------|-------------|
| `.linux` | Yes | Linux kernel image (vmlinuz) - serves as base PE |
| `.initrd` | Yes | Initial ramdisk (initramfs/initrd) |
| `.cmdline` | Yes | Kernel command line arguments |
| `.osrel` | No | OS release information (from /etc/os-release) |
| `.ucode` | No | CPU microcode (intel-ucode.img or amd-ucode.img) |
| `.splash` | No | Boot splash screen image |
| `.dtb` | No | Device tree blob (ARM/RISC-V systems) |
| `.sbat` | No | UEFI Secure Boot Advanced Targeting metadata |

## Building UKIs

### Using the Builder API

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/uki"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Create logger
logger := logging.NewLogger(logging.INFO)

// Create UKI builder
builder := uki.NewBuilder(logger)

// Create UKI from file paths
ukiConfig, err := uki.FromFiles(
    "/boot/vmlinuz-linux",
    "/boot/initramfs-linux.img",
    "root=/dev/sda2 ro quiet",
)
if err != nil {
    return err
}
defer ukiConfig.Close()

// Optional: Add OS release info
ukiConfig.OSRelease = `NAME="Trusted Platform"
VERSION="1.0"
ID=trusted-platform`

// Build UKI to file
err = builder.BuildFile(ukiConfig, "/boot/efi/EFI/Linux/linux.efi")
```

### Using io.Reader Interface

```go
// Create UKI with io.Reader interfaces for more flexibility
ukiConfig := &uki.UKI{
    Kernel:    kernelReader,
    Initramfs: initrdReader,
    Cmdline:   "root=UUID=xxx ro quiet splash",
    OSRelease: osReleaseContent,
}

// Validate configuration
if err := ukiConfig.Validate(); err != nil {
    return fmt.Errorf("invalid UKI config: %w", err)
}

// Build to io.Writer
err = builder.Build(ukiConfig, outputWriter)
```

### Adding Optional Components

```go
// Add CPU microcode
microcodeFile, _ := os.Open("/boot/intel-ucode.img")
defer microcodeFile.Close()
ukiConfig.Microcode = microcodeFile

// Add splash screen
splashFile, _ := os.Open("/usr/share/plymouth/splash.bmp")
defer splashFile.Close()
ukiConfig.Splash = splashFile

// Add SBAT metadata
ukiConfig.SBAT = `sbat,1,SBAT Version,sbat,1,https://example.com/sbat
trusted-platform,1,Trusted Platform,linux.efi,1,https://example.com`

// Add device tree (ARM systems)
dtbFile, _ := os.Open("/boot/dtbs/broadcom/bcm2711-rpi-4-b.dtb")
defer dtbFile.Close()
ukiConfig.DeviceTree = dtbFile
```

### Adding Custom Sections

```go
// Add custom sections before building
err = builder.AddSection(".vendor", []byte("Custom vendor data"))
if err != nil {
    return err
}

// Section names are limited to 8 characters (PE/COFF limitation)
err = builder.AddSection(".config", configData)
```

## Parsing Existing UKIs

### Parse UKI File

```go
// Create parser
parser := uki.NewParser(logger)

// Parse UKI from file
ukiConfig, err := parser.ParseFile("/boot/efi/EFI/Linux/linux.efi")
if err != nil {
    return err
}

// Access extracted components
fmt.Printf("Cmdline: %s\n", ukiConfig.Cmdline)
fmt.Printf("OS Release: %s\n", ukiConfig.OSRelease)

// Read kernel data
kernelData, _ := io.ReadAll(ukiConfig.Kernel)
fmt.Printf("Kernel size: %d bytes\n", len(kernelData))
```

### List Sections

```go
// List all sections in a UKI
file, _ := os.Open("/boot/efi/EFI/Linux/linux.efi")
defer file.Close()

sections, err := parser.ListSections(file)
if err != nil {
    return err
}

for _, name := range sections {
    fmt.Printf("Section: %s\n", name)
}
```

### Extract Specific Section

```go
// Extract a specific section by name
file, _ := os.Open("/boot/efi/EFI/Linux/linux.efi")
defer file.Close()

cmdlineData, err := parser.ExtractSection(file, ".cmdline")
if err != nil {
    return err
}

fmt.Printf("Cmdline: %s\n", string(cmdlineData))
```

## Multi-Architecture Support

The UKI package supports multiple CPU architectures:

| Architecture | Constant | EFI Stub Location |
|--------------|----------|-------------------|
| x86_64 | `uki.ArchX86_64` | `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` |
| AArch64 | `uki.ArchAArch64` | `/usr/lib/systemd/boot/efi/linuxaa64.efi.stub` |
| ARM | `uki.ArchARM` | `/usr/lib/systemd/boot/efi/linuxarm.efi.stub` |
| RISC-V 64 | `uki.ArchRISCV64` | `/usr/lib/systemd/boot/efi/linuxriscv64.efi.stub` |

### Setting Architecture

```go
builder := uki.NewBuilder(logger)

// Set target architecture (defaults to x86_64)
err := builder.SetArchitecture("aarch64")
if err != nil {
    return fmt.Errorf("unsupported architecture: %w", err)
}
```

### Using Custom EFI Stub

```go
// Override the default stub
stubFile, _ := os.Open("/path/to/custom.efi.stub")
defer stubFile.Close()

ukiConfig := &uki.UKI{
    Kernel:    kernelReader,
    Initramfs: initrdReader,
    Cmdline:   "root=/dev/sda2 ro",
    Stub:      stubFile, // Custom stub
}
```

Note: When `Stub` is nil, the builder uses the kernel itself as the base PE file since modern Linux kernels have a built-in EFI stub (CONFIG_EFI_STUB).

## Integration with Authenticode Signing

UKIs must be signed with Authenticode for Secure Boot. Use the `pkg/authenticode` package:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"

// Build unsigned UKI
err = builder.BuildFile(ukiConfig, "/tmp/linux-unsigned.efi")
if err != nil {
    return err
}

// Create Authenticode signer
signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      keyBackend,
    KeyAttributes: &types.KeyAttributes{CN: "secure-boot-db"},
    Certificate:   dbCert,
    Logger:        logger,
})
if err != nil {
    return err
}

// Sign the UKI
err = signer.SignFile("/tmp/linux-unsigned.efi", "/boot/efi/EFI/Linux/linux.efi")
if err != nil {
    return err
}

// Verify signature
err = signer.VerifyFile("/boot/efi/EFI/Linux/linux.efi")
```

### Complete Build and Sign Workflow

```go
func BuildSignedUKI(kernelPath, initrdPath, cmdline, outputPath string) error {
    logger := logging.NewLogger(logging.INFO)

    // 1. Create UKI
    ukiConfig, err := uki.FromFiles(kernelPath, initrdPath, cmdline)
    if err != nil {
        return err
    }
    defer ukiConfig.Close()

    // 2. Build unsigned UKI
    builder := uki.NewBuilder(logger)
    unsignedPath := outputPath + ".unsigned"

    if err := builder.BuildFile(ukiConfig, unsignedPath); err != nil {
        return err
    }
    defer os.Remove(unsignedPath)

    // 3. Sign with DB key
    signer, err := authenticode.NewSigner(signerOpts)
    if err != nil {
        return err
    }

    if err := signer.SignFile(unsignedPath, outputPath); err != nil {
        return err
    }

    return nil
}
```

## PE/COFF Implementation Details

The UKI package includes a native PE/COFF implementation:

- **Section Alignment**: 4KB (0x1000) for virtual addresses
- **File Alignment**: 512 bytes (0x200) for raw data
- **Section Characteristics**: Data sections use `IMAGE_SCN_CNT_INITIALIZED_DATA` without memory mapping flags
- **UKI Data Sections**: `.cmdline`, `.initrd`, etc. have `VirtualAddress=0` and are accessed by file offset only

This matches the behavior expected by the Linux kernel's EFI stub.

## Related Documentation

- [Secure Boot Implementation](secure-boot.md) - Automated Secure Boot with custom keys
- [UEFI Secure Boot](uefi-secure-boot.md) - UEFI Secure Boot concepts
- [Firmware Architecture](architecture.md) - Overall firmware architecture

## References

- [UAPI Group UKI Specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [systemd UKI Documentation](https://systemd.io/BOOT_LOADER_SPECIFICATION/)
- [PE/COFF Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

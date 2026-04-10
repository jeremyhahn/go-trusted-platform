# Automated Secure Boot Implementation

## Overview

The Trusted Platform includes **fully automated Secure Boot** support using custom keys. The implementation uses native Go code for all operations including NVRAM manipulation and Authenticode signing, eliminating dependencies on external tools.

## Features

- **Automatic key generation** - PK, KEK, and DB keys generated during build
- **Automatic key enrollment** - Keys enrolled into OVMF NVRAM using native Go
- **Automatic bootloader signing** - All EFI binaries signed with custom DB key
- **Secure Boot enabled by default** - No manual configuration required
- **Custom keys only** - No dependency on Microsoft or vendor keys
- **Native implementation** - No external Python or shell dependencies

## Architecture

### Key Hierarchy

```
Platform Key (PK)
  └─ Key Exchange Key (KEK)
      └─ Database Key (DB)
          └─ Signs: bootx64.efi, kernel, initramfs
```

### Build Flow

```
1. Build platform-initrd binary
2. Extract Alpine ISO
3. Generate Secure Boot keys (PK, KEK, DB)
4. Sign bootloader with DB key (native authenticode)
5. Customize initramfs with platform-initrd
6. Create OVMF NVRAM and enroll keys (native)
7. Build final ISO
```

## Key Components

### 1. Native NVRAM Manipulation

**Package**: `pkg/uefi`

Provides pure Go implementation of UEFI NVRAM operations:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"

// Open NVRAM file
nvram, err := uefi.OpenNVRAM("/path/to/OVMF_VARS.fd")

// Create signature lists from certificates
pkESL := uefi.NewSignatureListFromCert(pkCert.Raw, ownerGUID)
kekESL := uefi.NewSignatureListFromCert(kekCert.Raw, ownerGUID)
dbESL := uefi.NewSignatureListFromCert(dbCert.Raw, ownerGUID)

// Enroll keys
nvram.SetVariable("PK", uefi.EFIGlobalVariable, uefi.SecureBootAttributes, pkESL.Bytes())
nvram.SetVariable("KEK", uefi.EFIGlobalVariable, uefi.SecureBootAttributes, kekESL.Bytes())
nvram.SetVariable("db", uefi.EFIImageSecurityDatabase, uefi.SecureBootAttributes, dbESL.Bytes())

// Enable Secure Boot
nvram.SetVariable("SecureBoot", uefi.EFIGlobalVariable, attrs, []byte{0x01})
nvram.SetVariable("SetupMode", uefi.EFIGlobalVariable, attrs, []byte{0x00})

// Save
nvram.Save()
```

### 2. QEMU Secure Boot Enroller

**Package**: `pkg/qemu`

High-level API for Secure Boot enrollment:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/qemu"

enroller, err := qemu.NewSecureBootEnroller(&qemu.SecureBootEnrollerConfig{
    KeysDir:      "/path/to/keys",
    NVRAMDir:     "/path/to/nvram",
    OVMFVarsPath: "/usr/share/OVMF/OVMF_VARS_4M.fd",
}, logger)

// Enroll keys
err = enroller.EnrollKeys(ctx)

// Check status
status, err := enroller.GetEnrollmentStatus()
fmt.Printf("SecureBoot: %v, Keys enrolled: %v\n", status.SecureBootEnabled, status.KeysEnrolled)
```

### 3. Native Authenticode Signing

**Package**: `pkg/authenticode`

Signs PE/COFF files without external tools:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"

signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      keyBackend,
    KeyAttributes: &types.KeyAttributes{CN: "secure-boot"},
    Certificate:   cert,
    Logger:        logger,
})

// Sign a file
err = signer.SignFile("input.efi", "output.efi")

// Verify a signature
err = signer.VerifyFile("signed.efi")
```

## Usage

### Building ISO with Secure Boot

```bash
# Build ISO (Secure Boot enabled by default)
make iso-alpine

# Verify keys were generated
ls -la work/secure-boot-keys/

# Verify bootloader signature (using native verifier)
platformd authenticode verify --cert work/secure-boot-keys/DB.crt --input work/iso/efi/boot/bootx64.efi
```

### Testing in QEMU

```bash
# Test installation (Secure Boot enabled)
platformctl iso test install

# Test boot (Secure Boot enabled)
platformctl iso test boot
```

### Verifying Secure Boot Status

Using the native Go tooling:

```go
status, err := enroller.GetEnrollmentStatus()
// status.SecureBootEnabled - true if SecureBoot=1
// status.SetupMode - true if in setup mode
// status.HasPK, HasKEK, HasDB - key presence
// status.KeysEnrolled - all three keys present
```

## Key Files and Locations

### Generated Keys

```
work/secure-boot-keys/
├── PK.key          # Platform Key (private)
├── PK.crt          # Platform Key (certificate)
├── KEK.key         # Key Exchange Key (private)
├── KEK.crt         # Key Exchange Key (certificate)
├── DB.key          # Database Key (private)
└── DB.crt          # Database Key (certificate)
```

### OVMF NVRAM

```
work/nvram/
├── OVMF_VARS.fd           # NVRAM with enrolled keys
└── OVMF_VARS_ENROLLED.flag # Enrollment marker
```

### Signed Bootloader

```
work/iso/efi/boot/
└── bootx64.efi     # Signed bootloader
```

## Security Considerations

### Key Storage

**CRITICAL**: The private keys (*.key files) are the root of trust for your system.

- **Keep keys secure** - Store in encrypted storage
- **Back up keys** - Loss of keys means inability to update system
- **Restrict access** - Only authorized personnel should have access
- **Version control** - Do NOT commit keys to git

### Key Rotation

To rotate keys:

```bash
# Delete old keys
rm -rf work/secure-boot-keys
rm -f work/nvram/OVMF_VARS_ENROLLED.flag

# Rebuild (generates new keys)
make iso-alpine
```

## Boot Process

### With Secure Boot Enabled

1. **OVMF firmware** loads with Secure Boot enabled
2. **Firmware** verifies bootloader signature against enrolled DB key
3. **Bootloader** (bootx64.efi) loads if signature valid
4. **Bootloader** verifies kernel/initramfs signatures
5. **System** boots if all signatures valid

### Verification Chain

```
OVMF NVRAM (PK, KEK, DB)
    ↓ verifies
bootx64.efi (signed with DB)
    ↓ loads
vmlinuz-lts (signed with DB)
    ↓ loads
initramfs-lts (contains platform-initrd)
```

## Troubleshooting

### ISO won't boot

```bash
# Verify bootloader is signed
platformd authenticode verify --cert work/secure-boot-keys/DB.crt --input work/iso/efi/boot/bootx64.efi

# Check enrollment status programmatically
# status.SecureBootEnabled should be true
```

### "Access Denied" error

This means Secure Boot rejected the bootloader signature. Check:

1. Keys are enrolled in NVRAM
2. Bootloader is signed correctly
3. Signing used correct DB key
4. NVRAM uses enrolled keys, not default OVMF template

## Native Authenticode Signing

The Trusted Platform provides native Go-based Authenticode/PKCS#7 signing, eliminating
the dependency on external tools like `sbsigntool`.

### Using the CLI

```bash
# Sign a PE/COFF file (EFI binary, UKI, etc.)
platformd authenticode sign \
    --key /path/to/DB.key \
    --cert /path/to/DB.crt \
    --input unsigned.efi \
    --output signed.efi

# Verify an Authenticode signature
platformd authenticode verify \
    --cert /path/to/DB.crt \
    --input signed.efi
```

### Features

- **Full PKCS#7/Authenticode compliance** - Compatible with sbverify, osslsigncode
- **RSA and ECDSA support** - Works with both key types
- **Cryptographic verification** - Verifies RSA/ECDSA signatures, not just PE digests
- **No external dependencies** - Pure Go implementation
- **Hardware key support** - Can use TPM or PKCS#11 backed keys via XKMS

## Production Deployment

### Option 1: Custom Keys (Current Implementation)

**Pros**:
- Full control over signing chain
- No dependency on external CAs
- Free
- Pure Go implementation

**Cons**:
- Users must enroll keys manually on bare metal
- Not trusted by default on physical hardware

**Best for**: Controlled deployments, enterprise environments

### Option 2: Shim Bootloader

**Pros**:
- Signed by distro, trusted by most systems
- Chain-loads unsigned GRUB
- Works on physical hardware without key enrollment

**Cons**:
- Adds complexity
- Dependency on distro signing

**Best for**: General-purpose deployments

### Option 3: Microsoft Signing

**Pros**:
- Trusted by all UEFI systems
- Works everywhere without configuration

**Cons**:
- Costs money
- Requires Microsoft UEFI CA signing service
- Complex submission process

**Best for**: Commercial products, wide deployment

## Implementation Notes

The native Go implementation provides:

- **pkg/uefi** - UEFI NVRAM parsing and variable manipulation
- **pkg/qemu** - High-level Secure Boot enrollment for QEMU/OVMF
- **pkg/authenticode** - Authenticode/PKCS#7 signing and verification

No external dependencies required (no virt-fw-vars, sbsigntool, etc.)

## References

- [UEFI Secure Boot Specification](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html)
- [Microsoft Authenticode Specification](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)

## Summary

The automated Secure Boot implementation provides:

1. **Zero manual steps** - Fully automated key generation and enrollment
2. **Custom keys** - No dependency on Microsoft or vendor keys
3. **Production ready** - Proper key hierarchy and signing chain
4. **Tested** - Verified working in QEMU with OVMF
5. **Native implementation** - Pure Go, no external tool dependencies
6. **Documented** - Complete documentation and troubleshooting guide

**Status**: Secure Boot is fully functional with native Go implementation.

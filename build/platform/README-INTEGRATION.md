# Platform-initrd Integration Guide

Quick reference for building and deploying platform-initrd into Alpine ISO.

## Quick Start

### Build Static Binary
```bash
cd /home/jhahn/sources/go-trusted-platform
make -C build/platform build-static
```

**Output**: `/home/jhahn/sources/go-trusted-platform/platform-initrd-static`

### Copy to ISO Build Area
```bash
make -C build/platform copy-iso
```

**Locations**:
- ISO bin directory: `build/iso/alpine/amd64/work/iso/platform-initrd-bin/`
- ISO overlay: `build/iso/alpine/amd64/work/overlay/usr/bin/`

### Sign for Secure Boot (Optional)
```bash
make -C build/platform sign
```

**Requires**:
- `sbsign` command available
- Signing keys at `/etc/platform/sb-signing-key.pem` and `/etc/platform/sb-cert.pem`

### Complete Pipeline
```bash
make -C build/platform all
```

Builds static binary, copies to ISO areas, and displays summary.

---

## Files Modified

### 1. Autoinstall Script
**File**: `build/iso/alpine/amd64/scripts/install/autoinstall.sh.template`

**Changes**:
- Removed all tpm2-tools commands
- Removed LUKS setup (now in platform-initrd)
- Delegated to single `platform-initrd install` call
- Reduced from 2,277 to 129 lines

**Key Call**:
```bash
/usr/bin/platform-initrd install \
    --device "$INSTALL_DISK" \
    --automated \
    --fips="$FIPS" \
    --lockdown="$LOCKDOWN" \
    --tpm-autounseal="$TPM_AUTOUNSEAL" \
    --tpm-seal-pcr="$TPM_SEAL_PCR" \
    --luks-tpm-only="$LUKS_TPM_ONLY" \
    --fido2-luks="$FIDO2_LUKS" \
    --debug="$DEBUG"
```

### 2. Firstboot Sealing Service
**File**: `build/iso/alpine/amd64/scripts/install/tpm-firstboot-seal.sh`

**Changes**:
- OpenRC service wrapper around platform-initrd
- Simplified from 426 to 53 lines
- Delegates all logic to binary

**Key Call**:
```bash
/usr/bin/platform-initrd firstboot seal
```

### 3. Build System
**File**: `build/platform/Makefile`

**Targets**:
- `build-static`: Build static platform-initrd binary
- `copy-iso`: Copy to ISO build directories
- `sign`: Sign with Secure Boot keys
- `test`: Run platform-initrd tests
- `coverage`: Generate test coverage
- `all`: Complete build pipeline

---

## Architecture

### Installation Phase (autoinstall.sh)
```
ISO Boot
  ↓
autoinstall.sh
  ↓
platform-initrd install
  ├─ Partition disk (MBR + EFI)
  ├─ Format LUKS
  ├─ Create LVM volumes
  ├─ Create filesystems
  ├─ Install Alpine packages
  ├─ Configure dracut/UKI
  └─ Initial TPM sealing (non-PCR)
  ↓
Installed System
```

### First-boot Phase (tpm-firstboot-seal.sh)
```
System Boot
  ↓
tpm-firstboot-seal service
  ↓
platform-initrd firstboot seal
  ├─ Detect TPM type
  ├─ Create PCR-sealed objects
  ├─ Update LUKS keys
  └─ Set boot entry
  ↓
Reboot (sealed)
```

---

## Configuration Variables

These are set in the main Makefile and passed to autoinstall.sh:

```makefile
TPM_AUTOUNSEAL       # Enable TPM auto-unlock
TPM_SEAL_PCR         # PCR registers to seal
LUKS_TPM_ONLY        # Remove password keyslot
FIDO2_LUKS           # Enable FIDO2 support
DEBUG                # Enable debug output
LOCKDOWN             # Enable kernel lockdown
FIPS                 # Enable FIPS mode
```

---

## Validation

### Check Script Syntax
```bash
sh -n build/iso/alpine/amd64/scripts/install/autoinstall.sh.template
sh -n build/iso/alpine/amd64/scripts/install/tpm-firstboot-seal.sh
```

### Verify Makefile
```bash
make -f build/platform/Makefile help
```

### Test Binary
```bash
./platform-initrd-static --help
./platform-initrd-static install --help
./platform-initrd-static firstboot --help
```

---

## Troubleshooting

### Binary not found in ISO
```bash
# Check if binary exists
ls -la build/iso/alpine/amd64/work/overlay/usr/bin/platform-initrd

# Rebuild
make -C build/platform clean build-static copy-iso
```

### Autoinstall script fails
```bash
# Enable debug output
DEBUG=1 ./autoinstall.sh.template

# Check for platform-initrd availability
which platform-initrd
file platform-initrd-static
```

### Firstboot sealing fails
```bash
# Run manually with debug
/usr/bin/platform-initrd firstboot seal --debug

# Check seal flag
ls -la /boot/efi/platform-sealed.flag

# Check logs
journalctl -u tpm-firstboot-seal -n 50
```

---

## Dependencies

### Build-Time
- Go 1.18+ (for building platform-initrd)
- make
- Standard Unix utilities

### Runtime (in ISO)
- cryptsetup (LUKS)
- lvm2 (LVM)
- parted (partitioning)
- e2fsprogs (ext4)
- openssh (SSH access)
- sbsigntool (Secure Boot)

### Removed
- tpm2-tools (all commands)
- swtpm (software TPM)
- Manual TPM initialization scripts

---

## Build Targets

### Development
```bash
# Build dynamic-linked binary
make -C build/platform build

# Run tests
make -C build/platform test

# Generate coverage
make -C build/platform coverage
```

### Production
```bash
# Build static binary for distribution
make -C build/platform build-static

# Copy to ISO
make -C build/platform copy-iso

# Sign for Secure Boot
make -C build/platform sign

# Complete pipeline
make -C build/platform all
```

---

## Integration Checklist

- [ ] Build platform-initrd static binary
- [ ] Copy to ISO build area
- [ ] Verify scripts have valid syntax
- [ ] Test autoinstall in debug mode
- [ ] Test firstboot seal on target system
- [ ] Verify TPM sealing completes
- [ ] Test LUKS unlock with TPM key
- [ ] Test password fallback unlock
- [ ] Document configuration changes
- [ ] Update build system if needed

---

## Next Steps

1. **Build**: `make -C build/platform build-static`
2. **Deploy**: `make -C build/platform copy-iso`
3. **Test**: Boot ISO and verify installation completes
4. **Sign** (if needed): `make -C build/platform sign`
5. **Release**: Include platform-initrd-static in distribution

---

## Support

For issues or questions:
- Check the full integration report: `PLATFORM-INITRD-INTEGRATION.md`
- Review platform-initrd documentation: `docs/platform-initrd-architecture.md`
- Check service logs: `journalctl -u tpm-firstboot-seal`
- Enable debug mode: `DEBUG=1 ./autoinstall.sh.template`

# Platform-Initrd: Secure Boot Orchestration System

## Overview

Platform-initrd is a comprehensive boot-time orchestration system that provides secure disk encryption using TPM 2.0, FIDO2 hardware security keys, and LUKS2 full disk encryption. It replaces traditional bash scripts and external tools with a single, statically-linked Go binary designed for initramfs deployment.

## Key Features

- **TPM 2.0 Integration**: Automatic key sealing and unsealing with PCR policies
- **FIDO2 Support**: Hardware security key authentication for boot unlock
- **LUKS2 Management**: Full disk encryption with multiple unlock methods
- **Fallback Chain**: Graceful degradation from automated to manual unlock
- **Static Binary**: Single ~5MB binary with no external dependencies
- **Production Ready**: Comprehensive error handling and recovery modes

## Architecture

### Components

```
go-trusted-platform/
├── pkg/
│   ├── luks/          # LUKS/cryptsetup integration
│   ├── fido2/         # Offline FIDO2 CTAP2 protocol
│   ├── initrd/        # Boot orchestration
│   └── tpm2/          # TPM operations (existing)
├── cmd/
│   └── platform-initrd/  # Main binary
└── build/
    ├── platform/
    │   └── amd64-alpine/  # Alpine platform build system
    └── iso/
        └── alpine/        # ISO builder entry point
```

### Package Responsibilities

#### pkg/luks
- LUKS2 volume operations (format, open, close)
- Keyslot management
- Token management (TPM2, FIDO2, PKCS#11 metadata)
- Cryptsetup command wrapper

**Key Files:**
- `luks.go` - Handler interface
- `cryptsetup.go` - Implementation
- `keyslot.go` - Keyslot operations
- `token.go` - Token management

#### pkg/fido2
- FIDO2 CTAP2 protocol implementation
- USB HID device communication
- HMAC-secret extension for key derivation
- Credential enrollment and authentication

**Key Files:**
- `fido2.go` - Handler interface
- `device.go` - USB HID communication
- `ctap2.go` - CTAP2 protocol
- `hmac_secret.go` - Key derivation

#### pkg/initrd
- Boot mode detection (install, boot, recovery)
- Strategy pattern for unlock methods
- Install-time workflow (seal keys)
- Boot-time workflow (unseal, unlock)
- Recovery operations

**Key Files:**
- `initrd.go` - Manager interface
- `strategy.go` - Unlock strategy chain
- `install.go` - Installation workflow
- `boot.go` - Boot workflow
- `recovery.go` - Recovery workflow

#### cmd/platform-initrd
- Command-line interface
- Subcommands: install, boot, recovery, version
- Auto-detection mode
- Signal handling and cleanup

**Key Files:**
- `main.go` - Entry point
- `install.go` - Install command
- `boot.go` - Boot command
- `recovery.go` - Recovery command

## Boot Flow

### Install Mode

```
1. User boots ISO with autoinstall
2. Installer partitions disk and creates LUKS volume
3. platform-initrd install runs:
   ├── Provision TPM (create persistent SRK)
   ├── Generate LUKS keys
   ├── Seal keys to TPM (upgrade and PCR-sealed)
   ├── Enroll FIDO2 devices (optional)
   ├── Configure LUKS keyslots
   └── Save sealed objects to EFI partition
4. System reboots into first-boot
5. First-boot service reseals keys with current PCR values
6. System reboots into normal operation
```

### Boot Mode (Normal)

```
1. Kernel loads initramfs
2. platform-initrd boot runs:
   ├── Detect boot mode
   ├── Initialize platform (TPM, LUKS, FIDO2)
   ├── Build volume configuration
   └── Execute unlock strategy chain:
       ├── Try TPM PCR-sealed key (priority 1)
       ├── Try TPM upgrade key (priority 2)
       ├── Try FIDO2 hardware key (priority 3)
       └── Fallback to password prompt (priority 100)
3. First successful unlock wins
4. LUKS volume mounted
5. Switch root and continue boot
```

### Recovery Mode

```
1. Boot with recovery flag or press key during boot
2. platform-initrd recovery runs:
   ├── Display recovery menu
   ├── Options:
   │   ├── Unlock with password
   │   ├── Unlock with FIDO2
   │   ├── Reseal TPM keys (after kernel update)
   │   ├── Show keyslot info
   │   ├── Add recovery key
   │   ├── Remove keyslot
   │   └── Emergency shell
   └── Execute selected operation
3. Return to boot or drop to shell
```

## Unlock Strategies

### 1. TPM PCR-Sealed Strategy (Priority 1)

**Purpose**: Normal secure boot with tamper detection

**How it works:**
- Key sealed to TPM with PCR policy
- PCRs measure: firmware, bootloader, kernel, initrd
- Unseal only if PCRs match expected values
- Automatic unlock, no user interaction

**When it succeeds:**
- System booted normally
- No firmware/bootloader/kernel changes
- Secure Boot enabled
- TPM available

**When it fails:**
- Kernel updated
- Firmware changed
- Secure Boot disabled
- TPM tampered or unavailable

### 2. TPM Upgrade Strategy (Priority 2)

**Purpose**: Allow kernel updates without manual intervention

**How it works:**
- Key sealed to TPM without PCR policy
- Allows unlock even after kernel update
- After successful unlock, reseals with current PCRs
- One-time use: auto-deleted after reseal

**When it succeeds:**
- Kernel was updated
- PCR-sealed key failed
- TPM available

**When it fails:**
- Both keys corrupted
- TPM unavailable
- Manual intervention needed

### 3. FIDO2 Strategy (Priority 3)

**Purpose**: Hardware security key authentication

**How it works:**
- HMAC-secret extension for key derivation
- Credential ID + Salt → HMAC key
- Requires user presence (touch button)
- Multiple devices can be enrolled

**When it succeeds:**
- TPM keys failed
- FIDO2 device plugged in
- User pressed button

**When it fails:**
- No FIDO2 device
- Wrong device
- User didn't press button
- Timeout

### 4. Password Strategy (Priority 100)

**Purpose**: Ultimate fallback

**How it works:**
- Interactive password prompt
- Tests password against LUKS keyslot 0
- Manual entry required

**When it succeeds:**
- All automation failed
- User enters correct password

**When it fails:**
- Wrong password
- Keyslot corrupted

## Configuration

### Default Locations

```yaml
Device: /dev/sda2           # LUKS device
Name: cryptroot             # Mapping name
TPM: /dev/tpmrm0            # TPM device
EFI: /boot/efi              # EFI partition mount
Keyring: /var/lib/platform  # Keyring storage
```

### Configuration File

Location: `/etc/platform-initrd/config.yaml`

```yaml
boot:
  mode: auto                # auto, install, boot, recovery
  device: /dev/sda2
  name: cryptroot

tpm:
  device: /dev/tpmrm0
  pcrs: [0, 7, 9]          # PCRs to seal

fido2:
  enabled: true
  timeout: 30s
  retry: 3

luks:
  keyslots:
    0: password           # Keyslot assignments
    1: tpm-pcr
    2: tpm-upgrade
    3: fido2-primary
    4: fido2-backup
```

## Building

### Build Platform-Initrd Binary

```bash
# Dynamic build (for testing)
make build-initrd

# Static build (for initramfs)
make build-initrd-static

# ARM64 static build
make build-initrd-arm64-static

# Debug build
make build-initrd-debug
```

### Build Alpine ISO

```bash
# Build complete ISO with platform-initrd
make iso-alpine

# Or build directly from the ISO directory
cd build/iso/alpine
make iso-amd64

# Run integration tests
make test-alpine

# Clean build artifacts
make clean-alpine
```

## Testing

### Unit Tests

```bash
# Run all initrd-related tests
make test-initrd

# Test specific package
go test -v ./pkg/luks/...
go test -v ./pkg/fido2/...
go test -v ./pkg/initrd/...
```

### Integration Tests

```bash
# Run full integration test suite
cd build/iso/alpine/amd64
make test

# Test install workflow
make test-install

# Test boot workflow
make test-boot

# Test recovery workflow (if implemented)
make test-recovery
```

## Development

### Adding New Unlock Strategy

1. Create new strategy in `pkg/initrd/strategy_*.go`
2. Implement `UnlockStrategy` interface:
   ```go
   type UnlockStrategy interface {
       Name() string
       Priority() int
       CanUnlock(ctx context.Context, vol *VolumeConfig) (bool, error)
       Unlock(ctx context.Context, vol *VolumeConfig) error
       Install(ctx context.Context, vol *VolumeConfig) error
   }
   ```
3. Register in `initrd.NewManager()`
4. Add tests in `pkg/initrd/strategy_test.go`
5. Update documentation

### Adding New Architecture to Alpine

1. Create `build/iso/alpine/<arch>/`
2. Copy and adapt from `amd64/`
3. Update `build/iso/alpine/Makefile`
4. Add Makefile target to top-level Makefile
5. Test and document

### Adding New Distro

1. Create `build/iso/<distro>/`
2. Create architecture subdirectories (amd64/, arm64/)
3. Adapt build system for distro specifics
4. Update top-level Makefile
5. Test and document

## Troubleshooting

### TPM Key Unsealing Fails

**Symptoms**: PCR-sealed key fails to unseal

**Causes**:
- Kernel updated
- Firmware changed
- Secure Boot disabled

**Solution**:
1. Boot to recovery mode
2. Select "Reseal TPM keys"
3. Enter password to unlock
4. Keys resealed with current PCRs
5. Reboot

### FIDO2 Device Not Detected

**Symptoms**: FIDO2 strategy times out

**Causes**:
- Device not plugged in
- USB enumeration slow
- Wrong device

**Solution**:
1. Ensure device plugged in before boot
2. Wait for device to enumerate
3. Check dmesg for USB errors
4. Try different USB port

### All Unlock Methods Fail

**Symptoms**: Falls back to password prompt

**Causes**:
- TPM unavailable
- FIDO2 not enrolled
- System tampered

**Solution**:
1. Enter password at prompt
2. Boot to recovery mode
3. Check TPM with `tpm2_getcap properties-fixed`
4. Re-enroll FIDO2 if needed
5. Reseal TPM keys

## Security Considerations

### TPM Security

- SRK persists at handle 0x81000001
- Sealed objects stored on EFI partition (FAT32)
- EFI partition read-only at runtime
- PCR policy binds keys to firmware/boot state

### FIDO2 Security

- Credential random never leaves device
- Salt stored on disk (not secret)
- User presence required (touch)
- Multiple devices for redundancy

### LUKS Security

- LUKS2 only (no LUKS1 support)
- Argon2id PBKDF (memory-hard)
- Multiple keyslots for different methods
- Recovery key offline storage recommended

### Memory Security

- Secure memory wiping after use
- No key material in logs
- mlock for sensitive data
- No swap in initramfs

## Performance

### Boot Time Impact

- **Normal boot (TPM)**: < 100ms overhead
- **Upgrade boot (TPM)**: < 200ms overhead
- **FIDO2 boot**: 2-5s (user interaction)
- **Password boot**: Depends on user

### Binary Size

- Static binary: ~5MB
- Initramfs increase: ~5MB
- ISO size increase: ~5MB

## Future Enhancements

### Planned Features

- Network unlock (Tang/Clevis)
- Cloud KMS integration
- Bluetooth FIDO2 devices
- NFC support
- Secure Boot key rotation
- Remote attestation

### Architecture Extensibility

The strategy pattern allows adding new unlock methods without modifying core code. Potential additions:

- Smart card (PIV)
- Biometric authentication
- Time-based unlock
- Location-based unlock
- Multi-factor combinations

## References

### Documentation

- [Architecture](initrd-architecture.md) - Detailed design
- [Alpine Build Guide](../../build/iso/alpine/amd64/BUILD.md) - Build instructions

### Source Code

- pkg/luks - LUKS integration
- pkg/fido2 - FIDO2 implementation
- pkg/initrd - Boot orchestration
- cmd/platform-initrd - CLI implementation

### External Resources

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [LUKS Specification](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf)

## License

Part of the go-trusted-platform project.
See the main project LICENSE file for details.

## Contributing

See CONTRIBUTING.md in the main project repository.

## Support

For issues and questions:
- GitHub Issues: https://github.com/jeremyhahn/go-trusted-platform/issues
- Documentation: https://github.com/jeremyhahn/go-trusted-platform/tree/main/docs

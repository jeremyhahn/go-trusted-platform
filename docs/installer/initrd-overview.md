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
│   ├── initrd/        # Boot orchestration (SDK-aware)
│   ├── tpm/           # Host TPM operations
│   └── ...
├── cmd/
│   └── platform-initrd/  # Static initramfs binary
└── build/
    ├── platform/
    │   └── amd64-alpine/  # Alpine platform build system
    └── iso/
        └── alpine/        # ISO builder entry point
```

There is **no `pkg/fido2/`** in the platform repository. The Phase 6c
refactor deleted that package (~6,821 LOC) and routed every consumer
through the canonical xkms implementation. The initrd reaches the FIDO2
CTAP2 primitives through the quicbaas SDK type-alias re-export at
`github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2`.

### Build-time carve-out for the initramfs

`pkg/initrd/` and `cmd/platform-initrd/` are a **separate compilation
unit** that runs in early boot before networking, TLS trust, and the SDK
runtime are available. The initrd binary therefore cannot open a
quicbaas SDK connection. Two import rules apply:

1. The initrd MAY import `github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2`
   directly. The package is a thin **type-alias re-export** of the
   canonical xkms implementation; it carries no network or runtime
   state and is safe to link statically into the initramfs binary.
2. The initrd MUST NOT import `github.com/jeremyhahn/go-xkms/pkg/*`
   directly. The only blessed upstream path from the platform repo is
   the quicbaas SDK re-export.

The relevant import is visible in `pkg/initrd/strategy_fido2.go`:

```go
import (
    "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
    // ...
)
```

This is a **build-time carve-out**, not a runtime SDK exception.
Application code that runs under `platformd` or `platformctl` reaches
FIDO2 — device verbs and WebAuthn ceremony alike — only through
`quicbaas.SDK().Security().Auth().FIDO2()`, never via the re-export
directly.

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

#### FIDO2 (re-exported from go-xkms via the quicbaas SDK)

The initrd consumes the canonical xkms FIDO2 CTAP2 implementation via
`github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2`. The type aliases
exposed by that package include:

- `fido2.EnrollmentConfig` / `fido2.EnrollmentResult` — credential
  enrollment payloads used by `pkg/initrd/strategy_fido2.go`.
- `fido2.AuthenticationConfig` — slot-level credential metadata loaded
  during boot.
- `fido2.RelyingParty`, `fido2.User` — identifiers for the LUKS-root
  relying party.

The CTAP2 protocol, USB HID device communication, and HMAC-secret
derivation all live in go-xkms and are NOT duplicated in this
repository.

#### pkg/initrd
- Boot mode detection (install, boot, recovery)
- Strategy pattern for unlock methods
- Install-time workflow (seal keys)
- Boot-time workflow (unseal, unlock)
- Recovery operations

**Key Files:**
- `initrd.go` - Manager interface
- `strategy.go` - Unlock strategy chain
- `strategy_tpm_pcr.go` - PCR-sealed TPM strategy
- `strategy_tpm_upgrade.go` - Upgrade-resilient TPM strategy
- `strategy_fido2.go` - FIDO2 strategy (consumes the xkms re-export)
- `strategy_password.go` - Interactive password fallback
- `install.go` - Installation workflow
- `boot.go` - Boot workflow

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

## Kernel Update UKI Rebuild (Secure Boot)

On a node installed with Secure Boot (`secure-boot.enabled`), the bootloader is a
single signed Unified Kernel Image (UKI) at the UEFI removable-media path
`/boot/efi/EFI/BOOT/BOOTX64.EFI`. A kernel package change (`apk upgrade
linux-lts`) installs a new kernel + modules but does **not** rebuild or re-sign
that UKI — so without intervention the node would either boot a stale kernel or,
once the old kernel/modules are gone, fail to boot under enforced UEFI Secure
Boot + `CONFIG_MODULE_SIG_FORCE`.

To keep the node bootable, the installer drops a kernel-update hook onto the
target that runs the UKI rebuild verb on every kernel change.

### CLI verb

```bash
# Invoked automatically by the kernel hook for a specific kernel version
platformctl install uki-rebuild --kver 6.6.67-0-lts

# Rebuild for the newest kernel under /lib/modules
platformctl install uki-rebuild
```

`platformctl install uki-rebuild` runs **on the booted node**. It is a local
node-maintenance verb (not a daemon RPC), but it still reaches all crypto
through the SDK. Pipeline:

1. Resolve the kernel version (default: newest under `/lib/modules`) and its
   image under `/boot`.
2. Rebuild the UKI for that kernel with the **persisted** kernel cmdline
   (`/etc/kernel/cmdline`, written by the installer) via the same dracut UKI
   builder used at install time.
3. Resolve the Secure Boot **DB signer** with the same precedence the installer
   uses, and it **never generates a new DB key** (a fresh, unenrolled key would
   brick Secure Boot):
   - `resign-mode: local` — read the `file://` DB key from the encrypted root.
   - `resign-mode: remote` — hash-sign via `secureboot.NewKMSSigner` over the
     platform SDK client (IDevID mTLS); the private key never leaves the KMS.
4. Sign + **verify before swapping**: the rebuilt UKI must carry a valid
   Authenticode signature whose certificate is exactly the DB certificate, and a
   spot check confirms the freshly installed kernel modules are signed.
5. **Atomic, never-brick swap:** the rebuild builds + signs to a staging file
   (`BOOTX64.EFI.new`) on the ESP, then `rename(2)`s it over `BOOTX64.EFI` in a
   single atomic operation, preserving the previous image as `BOOTX64.EFI.prev`.
   On **any** failure the swap is aborted, the working UKI is left in place, and
   a non-zero exit is returned (which the hook logs) — the **old kernel still
   boots**. The existing UEFI NVRAM entry and removable-media fallback both
   point at `BOOTX64.EFI`, so the boot configuration needs no change; for manual
   recovery an operator can restore `BOOTX64.EFI.prev` from an EFI shell.

### On-target assets (installed only when `secure-boot.enabled`)

| Path | Role |
|------|------|
| `/etc/kernel/install.d/90-trusted-platform-uki.install` | kernel-install(8) plugin — runs `platformctl install uki-rebuild --kver "$KERNEL_VERSION"` on kernel `add`/`change`. |
| `/etc/apk/commit_hooks.d/90-trusted-platform-uki` | apk commit-hook bridge — Alpine's apk does not invoke kernel-install drop-ins, so this fires the rebuild after an `apk upgrade linux-*` transaction, gated on a newer kernel than the live UKI. |

Both hooks are minimal shell glue; all rebuild / sign / verify / atomic-swap
logic lives in the Go verb. They invoke `/usr/bin/platformctl` (the path the
installer places `platformctl` at on the target).

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
go test -v ./pkg/initrd/...
```

FIDO2 CTAP2 unit tests live in the canonical xkms repository
(`go-xkms/pkg/fido2`). The platform initrd's FIDO2 strategy test
(`pkg/initrd/strategy_fido2_test.go`) exercises the integration against
the SDK re-export only.

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
- pkg/initrd - Boot orchestration (FIDO2 strategy lives in `strategy_fido2.go`)
- cmd/platform-initrd - CLI implementation
- go-quicbaas `sdk/go/xkms/fido2` - canonical FIDO2 CTAP2 types (re-exported from go-xkms)

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

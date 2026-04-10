# platform-initrd Reference

`platform-initrd` is the minimal boot binary for initramfs operations. It handles TPM-sealed LUKS disk unlocking during the early boot phase.

**Note**: This binary is NOT user-facing. It is called automatically by dracut hooks and systemd services during the boot process.

## Synopsis

```
platform-initrd [command] [options]
```

## Binary Size

`platform-initrd` is optimized for initramfs use at ~22MB binary size.
Firstboot functionality has been moved to `platformctl firstboot` which runs after switch_root.

## Commands

### boot

Unlock encrypted root filesystem using TPM-sealed keys.

```bash
platform-initrd boot --device /dev/sda2
```

**Options:**
- `--device, -d`: LUKS device path (required)
- `--name, -n`: LUKS mapping name (default: cryptroot)
- `--timeout`: Unlock timeout in seconds (default: 30)
- `--pcrs`: PCR banks to verify (reads from config if not specified)
- `--fallback`: Enable fallback unlock methods (default: true)
- `--emergency`: Drop to emergency shell on failure
- `--tpm-path`: TPM device path (default: /dev/tpmrm0)
- `--efi-path`: EFI partition mount point (default: /boot/efi)
- `--xkms-dir`: XKMS storage directory
- `--fips`: Enable FIPS mode
- `--verbose, -v`: Enable verbose logging
- `--debug`: Enable debug logging

### recovery

Recovery mode for boot failures and manual unlocking.

```bash
platform-initrd recovery --device /dev/sda2
```

**Options:**
- `--device, -d`: LUKS device path (required)
- `--name, -n`: LUKS mapping name (default: cryptroot)
- `--reseal-pcrs`: Automatically reseal to current PCRs after unlock (default: true)
- `--fido2`: Enable FIDO2 authenticator unlock (default: true)
- `--interactive`: Interactive recovery menu
- `--tpm-path`: TPM device path (default: /dev/tpmrm0)
- `--efi-path`: EFI partition mount point (default: /boot/efi)
- `--fips`: Enable FIPS mode
- `--verbose, -v`: Enable verbose logging
- `--debug`: Enable debug logging

## Boot Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           BOOT SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │ 1. INITRD: platform-initrd boot --device /dev/sda2              │     │
│  │    Unlocks LUKS using TPM-sealed keys or fallback methods       │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                    │                                     │
│                                    ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │ 2. switch_root to real filesystem                               │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                    │                                     │
│                                    ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │ 3. FIRSTBOOT (one-time): platformctl firstboot                  │     │
│  │    Runs via systemd/openrc service on first boot only           │     │
│  │    - Provisions TPM (EK, SRK, IAK, IDevID)                      │     │
│  │    - Seals LUKS key to TPM with PCR policy                      │     │
│  │    - Enables automatic boot unlocking                           │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                    │                                     │
│                                    ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │ 4. platformd daemon starts (normal operation)                   │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## See Also

- [platformctl.md](platformctl.md) - CLI operations (install system, wipe, etc.)
- [platformd.md](platformd.md) - Platform daemon
- [../installer/README.md](../installer/README.md) - Installation architecture
- [../installer/UNLOCK_STRATEGIES.md](../installer/UNLOCK_STRATEGIES.md) - Unlock strategies

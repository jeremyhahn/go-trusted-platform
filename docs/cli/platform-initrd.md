# platform-initrd Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `platform-initrd` early-boot binary's commands and flags.

`platform-initrd` is the minimal boot binary for initramfs operations. It handles TPM-sealed LUKS disk unlocking during the early boot phase.

**Note**: This binary is NOT user-facing. It is called automatically by dracut hooks and systemd services during the boot process.

## Synopsis

```
platform-initrd [command] [options]
```

## Binary Size

`platform-initrd` is a static, stripped binary built with `make platform-initrd`
(about 94 MB on amd64).
Firstboot functionality has been moved to `platformctl firstboot` which runs after switch_root.

## Commands

### boot

Unlock encrypted root filesystem using TPM-sealed keys.

```bash
platform-initrd boot --device /dev/sda2
```

**Options:**
- `--device, -d`: LUKS device path (required unless `--diskless`)
- `--name, -n`: LUKS mapping name (default: cryptroot)
- `--diskless`: Mount the diskless dm-verity root described by the signed kernel command line instead of unlocking `--device`
- `--root-mount`: Root mount point for diskless boot (default: /sysroot)
- `--diskless-work-dir`: Tmpfs work directory for diskless root material (default: /run/platform/diskless-root)
- `--timeout`: Unlock timeout in seconds (default: 30)
- `--pcrs`: PCR banks to verify (reads from config if not specified)
- `--fallback`: Enable fallback unlock methods (default: true)
- `--emergency`: Drop to emergency shell on failure
- `--tpm-path`: TPM device path (default: /dev/tpmrm0)
- `--efi-path`: EFI partition mount point (default: /boot/efi)
- `--xkms-dir`: XKMS storage directory (default: /etc/trusted-platform/xkms)
- `--fips`: Recorded but not read; the kernel's FIPS mode selects the keyslot KDF ([FIPS mode](../fips/cli.md))
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
- `--reseal-pcrs`: Recorded but not read; recovery does not reseal the TPM-PCR key (default: true)
- `--fido2`: Enable FIDO2 authenticator unlock (default: true)
- `--interactive`: Interactive recovery menu
- `--tpm-path`: TPM device path (default: /dev/tpmrm0)
- `--efi-path`: EFI partition mount point (default: /boot/efi)
- `--xkms-dir`: XKMS storage directory (default: /etc/trusted-platform/xkms)
- `--fips`: Recorded but not read; the kernel's FIPS mode selects the keyslot KDF ([FIPS mode](../fips/cli.md))
- `--verbose, -v`: Enable verbose logging
- `--debug`: Enable debug logging

### version

Print the binary's version.

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

- [daemon/cli.md](../daemon/cli.md) - platformctl root verbs (wipe, etc.) and the platformd daemon
- [../installer/architecture.md](../installer/architecture.md) - Installation architecture
- [../installer/engineering.md](../installer/engineering.md) - Unlock strategies

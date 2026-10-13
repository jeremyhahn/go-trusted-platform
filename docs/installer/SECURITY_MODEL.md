# LUKS Key Security Model

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [engineering.md](engineering.md). The installer password is forensic protection only, and the first-boot seal files are `seal-platform.pub`/`.priv`.

This document describes the TPM-based security model for LUKS full-disk encryption in the Trusted Platform installer.

## Overview

The Trusted Platform uses TPM 2.0 to seal LUKS encryption keys with hardware-backed security policies. The system supports multiple unlock strategies with varying security levels, allowing flexibility while maintaining strong security guarantees.

## TPM Storage Root Keys (SRKs)

The platform uses two Storage Root Keys in the TPM:

| SRK | Handle | Policy | Purpose |
|-----|--------|--------|---------|
| **SSRK** (Shared SRK) | 0x81000001 | None | Temporary seals, upgrade path |
| **Platform KeyStore SRK** | 0x81000002 | PCR | Production seals, CA keys |

### SSRK (0x81000001)
- **No authentication policy** - can be accessed without PCR verification
- Used for temporary upgrade seals during kernel updates
- Seals under SSRK should be deleted immediately after use
- **Security risk if left around** - allows unsealing without verification

### Platform KeyStore SRK (0x81000002)
- **PCR policy** - requires platform PCR golden measurement to match expected value
- Used for all production seals (LUKS key, CA keys, etc.)
- Provides hardware-backed security for secrets

## LUKS Key Seal Types

| Seal Type | Parent SRK | PCR Policy | Files | Security Level |
|-----------|------------|------------|-------|----------------|
| **Platform (PCR)** | 0x81000002 | Yes (Platform PCR) | seal.pub, seal.priv | Highest |
| **Upgrade (None)** | 0x81000001 | No | seal-upgrade.pub, seal-upgrade.priv | Temporary |

### Platform Seals (seal.pub, seal.priv)
- **Primary unlock mechanism** for production use
- Sealed to Platform KeyStore SRK with PCR auth policy
- Requires Platform PCR extended with golden measurement
- Automatic unlock when PCRs match and platform is provisioned

### Upgrade Seals (seal-upgrade.pub, seal-upgrade.priv)
- **Temporary** - only exist during kernel upgrades
- Sealed to SSRK with NO policy at all
- **MUST be deleted immediately after use**
- Security risk if left on disk

## Security State Table

| State | Upgrade Seals | Platform Seals | Security |
|-------|---------------|----------------|----------|
| Install | Created | None | Temporary |
| First Boot | **DELETED** | Created | Secured |
| Normal Boot | None | Used | PCR policy |
| Pre-Upgrade | Created | Exists | Temporary |
| Post-Upgrade | **DELETED** | Updated | PCR policy |

## Unlock Strategy Priority

Strategies are tried in priority order (lower number = higher priority):

| Priority | Strategy | Condition | User Action |
|----------|----------|-----------|-------------|
| 0 | Firstboot-Seal | Plain key exists | None (automatic) |
| 1 | TPM-PCR | Platform seals exist | None (automatic) |
| 2 | TPM-Upgrade | Upgrade seals exist | None (automatic) |
| 100 | Password | Always available | Enter LUKS passphrase |

## Golden Measurement (Platform PCR)

The Platform KeyStore SRK's PCR policy requires the Platform PCR to contain the "golden measurement":

```
Golden Measurement = Hash(PCR0 || PCR7 || PCR9 || PCR10)
```

Where:
- **PCR 0**: BIOS/UEFI firmware measurements
- **PCR 7**: Secure Boot state
- **PCR 9**: Kernel command line
- **PCR 10**: IMA file measurements

This ensures the LUKS key can only be unsealed when the boot chain matches the expected state.

## Encrypted Installer Container

During installation, sensitive keys and platform configuration are stored in an encrypted LUKS container on the EFI partition, providing forensic protection against SSD spare block recovery.

### Installer Container Design

| Aspect | Implementation |
|--------|----------------|
| **Container** | `/boot/efi/tpm2/installer.luks` (100MB) |
| **Encryption** | LUKS2 with well-known password `installer` |
| **Contents** | luks-key.bin, recovery-key.txt, /etc/trusted-platform/config.yaml |
| **Lifecycle** | Created at install, used for provisioning, wiped at first boot |

### Why Encryption Works

The well-known password provides **forensic protection**, not access control:

1. **Encrypted data = high entropy** - looks like random data
2. **SSD spare blocks contain only encrypted fragments** - useless without LUKS header
3. **Secure wipe destroys LUKS header** - makes spare blocks irrecoverable
4. **TRIM releases SSD blocks** - controller marks them for garbage collection

### Recovery Key

A human-readable recovery key in dashed hex format is generated and written to `/root/luks-recovery.txt` after first boot. This provides an emergency unlock method when TPM sealing fails.

## Boot Flow Diagrams

### Installation

```
┌─────────────────────────────────────────────────────────────────┐
│                         INSTALLATION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Generate random 32-byte LUKS key                            │
│  2. Generate recovery key (dashed hex format)                   │
│  3. Add LUKS key to root partition (keyslot 1)                  │
│  4. Add recovery key to root partition (keyslot 2)              │
│  5. Create encrypted installer container:                       │
│     └── /boot/efi/tpm2/installer.luks                           │
│         ├── luks-key.bin (32-byte LUKS key)                     │
│         ├── recovery-key.txt (human-readable)                   │
│         └── /etc/trusted-platform/config.yaml                   │
│  6. Unmount and close installer container                       │
│  7. Reboot into first boot                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### First Boot (After Installation)

```
┌─────────────────────────────────────────────────────────────────┐
│                          FIRST BOOT                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Initramfs detects first boot (installer.luks exists)        │
│     └── Firstboot-Seal strategy activates                       │
│                                                                 │
│  2. Open installer container (password: "installer")            │
│     └── Mount read-write at /mnt/installer                      │
│                                                                 │
│  3. Read LUKS key and recovery key from installer               │
│     └── luks-key.bin, recovery-key.txt                          │
│                                                                 │
│  4. Provision platform INSIDE installer container               │
│     ├── Create SSRK (0x81000001) - no policy                    │
│     ├── Create Platform KeyStore SRK (0x81000002) - PCR policy  │
│     ├── Extend Platform PCR with golden measurement             │
│     └── All output encrypted (CA keys, platform state)          │
│                                                                 │
│  5. Create seals:                                               │
│     └── seal.pub, seal.priv (PCR policy) on EFI partition       │
│                                                                 │
│  6. Unlock LUKS with key (still in memory)                      │
│                                                                 │
│  7. Set markers for post-switch_root:                           │
│     ├── Copy installer contents to root filesystem              │
│     └── Write recovery key to /root/luks-recovery.txt           │
│                                                                 │
│  8. Kill root keyslot 0; PRESERVE installer.luks pending proof │
│                                                                 │
│  Next boot, TPM-PCR unlock (platform-initrd boot):              │
│  9. SECURE WIPE installer.luks (overwrite + TRIM)               │
│     └── Defeats forensic recovery from SSD spare blocks         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Normal Boot (Production)

```
┌─────────────────────────────────────────────────────────────────┐
│                         NORMAL BOOT                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Initramfs starts boot sequence                              │
│     └── No plain key, has Platform seals                        │
│                                                                 │
│  2. TPM-PCR strategy activates                                  │
│     └── Found seal.pub, seal.priv on EFI partition              │
│                                                                 │
│  3. Run: platformd --config /boot/efi/.../config.yaml extend    │
│     └── Extend PCR 23 with golden measurement                   │
│                                                                 │
│  4. Unseal LUKS key from Platform KeyStore                      │
│     └── PCR 23 must match (golden measurement)                  │
│                                                                 │
│  5. Unlock LUKS volume                                          │
│                                                                 │
│  6. Continue boot (switch_root)                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Kernel Upgrade Boot

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL UPGRADE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PRE-UPGRADE (before reboot):                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. Package manager installs new kernel                   │  │
│  │  2. Create upgrade seals on SSRK (no policy)              │  │
│  │     └── seal-upgrade.pub, seal-upgrade.priv               │  │
│  │  3. Reboot                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  FIRST BOOT WITH NEW KERNEL:                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. TPM-PCR fails (new kernel = different PCRs)           │  │
│  │  2. TPM-Upgrade activates                                 │  │
│  │     └── Unseal from SSRK (no policy check)                │  │
│  │  3. IMMEDIATELY DELETE upgrade seals                      │  │
│  │     └── Security: no unprotected seals on disk            │  │
│  │  4. Set reseal flag                                       │  │
│  │  5. Boot continues normally                               │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  POST-BOOT RE-SEAL:                                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. Platformd sees reseal flag                            │  │
│  │  2. Re-seal LUKS key with new PCR values                  │  │
│  │     └── Update seal.pub, seal.priv                        │  │
│  │  3. Clear reseal flag                                     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  NEXT BOOT: Normal boot (TPM-PCR with new PCR values)           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### TPM Configuration (config.yaml)

```yaml
tpm:
  device: /dev/tpmrm0

  # Shared SRK - NO policy, for upgrades
  ssrk:
    handle: 0x81000001

  # Platform KeyStore - PCR policy
  keystore:
    srk-handle: 0x81000002
    platform-policy: true          # Enable PCR policy

  # Golden measurement PCRs
  platform-pcr: 23
  platform-pcr-bank: sha256
  golden-pcrs: [0, 7, 9, 10]
```

## EFI Partition Layout

**Note:** EFI partition must be at least 200MB to accommodate the installer container.

### During Installation
```
/boot/efi/tpm2/
└── installer.luks     # Encrypted container (100MB) - LUKS key + recovery + config
```

### After First Boot
```
/boot/efi/tpm2/
├── seal.pub           # TPM-sealed LUKS key (public)
└── seal.priv          # TPM-sealed LUKS key (private)
```

**Note:** No sensitive data is ever written unencrypted to the EFI partition.

### Factory image (Raspberry Pi, `boot.firmware: uboot`)

The boot partition is the same ESP with the firmware beside it: the
Raspberry Pi firmware files (`start4.elf`, `fixup4.dat`, the board `.dtb`,
`overlays/`), `config.txt`, U-Boot as `kernel8.img`, and the signed UKI at
`EFI/BOOT/BOOTAA64.EFI`. `tpm2/installer.luks` is written by the build host
and wiped by the device's first boot exactly as above. The partition is
FAT32 type `0x0c` in an MBR because the Pi firmware reads nothing else; a
consequence is that U-Boot, which only treats an MBR partition of type
`0xEF` as the EFI system partition, cannot persist EFI variables to
`ubootefi.var` and says so at every boot ("Cannot persist EFI variables
without system partition"). Nothing in the boot chain depends on persisted
variables: PK/KEK/db are compiled into U-Boot and BootOrder is not used
(U-Boot's standard boot finds the UKI by path). See
[docs/factory-image/architecture.md](../factory-image/architecture.md) §6
for the trust boundaries of that chain.

## Security Considerations

### Forensic Protection via Encrypted Installer Container
The installer.luks container provides forensic protection:
- **Problem:** Plain files on SSD can be recovered from spare blocks via wear-leveling
- **Solution:** Encrypt with LUKS so spare blocks contain only encrypted fragments
- **Wipe:** Secure wipe destroys LUKS header + TRIM releases blocks
- **Result:** Forensic recovery yields only random-looking encrypted data

### Never Leave Upgrade Seals on Disk
Upgrade seals have NO policy protection. If left on disk, anyone with physical access can unseal the LUKS key. The system ALWAYS deletes upgrade seals immediately after use.

### PCR Policy Strength
The golden measurement binds secrets to:
- BIOS/UEFI firmware state
- Secure Boot configuration
- Kernel and initramfs
- IMA measurements

Any change to these components invalidates the seal, requiring password fallback or re-provisioning.

### Multi-Layer Protection
Production LUKS keys have multiple layers:
1. **TPM binding** - physically tied to this TPM chip
2. **PCR policy** - tied to specific boot chain state
3. **Recovery key** - human-readable backup in `/root/luks-recovery.txt`
4. **LUKS passphrase** - ultimate fallback (user-provided during install)

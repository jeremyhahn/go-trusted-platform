# Trusted Platform Installer

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [user.md](user.md). There is no `strategy_firstboot_seal.go` (`FirstbootSealStrategy` is in `pkg/firstboot/strategy.go`), no plaintext key on the EFI partition, and no PIN seals.

This directory contains documentation for the Trusted Platform installer and boot system.

## Documentation Index

| Document | Description |
|----------|-------------|
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | LUKS key security model, TPM sealing architecture |
| [UNLOCK_STRATEGIES.md](UNLOCK_STRATEGIES.md) | Initramfs unlock strategies and configuration |
| [initrd-overview.md](initrd-overview.md) | Platform-initrd secure boot orchestration overview |
| [initrd-architecture.md](initrd-architecture.md) | Detailed architecture design with code examples |
| [iso-building.md](iso-building.md) | Trusted Platform ISO building guide |
| [provisioning-client.md](provisioning-client.md) | Device provisioning client API documentation |
| [qemu-testing.md](qemu-testing.md) | QEMU/KVM testing and Secure Boot requirements |

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TRUSTED PLATFORM BOOT ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                           INSTALLATION                              │   │
│   │                                                                     │   │
│   │  1. Create partitions (EFI, LUKS, LVM)                              │   │
│   │  2. Format LUKS with passphrase                                     │   │
│   │  3. Generate random LUKS key                                        │   │
│   │  4. Add key to LUKS keyslot                                         │   │
│   │  5. Write plain key to EFI partition                                │   │
│   │  6. Create upgrade seals (temporary)                                │   │
│   │  7. Install OS and bootloader                                       │   │
│   │  8. Copy platform config to EFI                                     │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                            FIRST BOOT                               │   │
│   │                                                                     │   │
│   │  1. Initramfs detects plain key (first boot)                        │   │
│   │  2. Firstboot-Seal strategy activates                               │   │
│   │  3. Provision platform to tmpfs                                     │   │
│   │     ├── Create SSRK (0x81000001) - no policy                        │   │
│   │     ├── Create Platform SRK (0x81000002) - PCR+PIN                  │   │
│   │     └── Extend PCR 23 (golden measurement)                          │   │
│   │  4. Create seals:                                                   │   │
│   │     ├── Platform seals (PCR+PIN) - primary                          │   │
│   │     └── PIN seals (PIN only) - fallback                             │   │
│   │  5. DELETE plain key (secure)                                       │   │
│   │  6. DELETE upgrade seals (secure)                                   │   │
│   │  7. Unlock LUKS                                                     │   │
│   │  8. switch_root → copy tmpfs to /var/lib/trusted-platform           │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                           NORMAL BOOT                               │   │
│   │                                                                     │   │
│   │  1. Initramfs starts                                                │   │
│   │  2. TPM-PCR strategy activates                                      │   │
│   │  3. platformd extend (PCR 23)                                       │   │
│   │  4. Unseal from Platform KeyStore                                   │   │
│   │     ├── PCR 23 must match                                           │   │
│   │     └── Platform PIN required                                       │   │
│   │  5. Unlock LUKS                                                     │   │
│   │  6. switch_root → normal boot                                       │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             COMPONENT LAYERS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                          INITRAMFS LAYER                              │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │  │
│  │  │   dracut    │ │ platform-   │ │    LUKS     │ │     LVM     │      │  │
│  │  │   module    │ │   initrd    │ │   handler   │ │   activate  │      │  │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘      │  │
│  │         └────────────────┴───────────────┴──────────────┘             │  │
│  │                                  │                                    │  │
│  └──────────────────────────────────┼────────────────────────────────────┘  │
│                                     │                                       │
│  ┌──────────────────────────────────┼────────────────────────────────────┐  │
│  │                          STRATEGY LAYER                               │  │
│  │                                  ▼                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                       Strategy Chain                            │  │  │
│  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐        │  │  │
│  │  │  │ Firstboot │ │  TPM-PCR  │ │TPM-Upgrade│ │  TPM-PIN  │ ...    │  │  │
│  │  │  │   Seal    │ │           │ │           │ │           │        │  │  │
│  │  │  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘        │  │  │
│  │  │        └─────────────┴─────────────┴─────────────┘              │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                  │                                    │  │
│  └──────────────────────────────────┼────────────────────────────────────┘  │
│                                     │                                       │
│  ┌──────────────────────────────────┼────────────────────────────────────┐  │
│  │                            TPM LAYER                                  │  │
│  │                                  ▼                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                      go-xkms TPM2                           │  │  │
│  │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │  │  │
│  │  │  │     SSRK      │  │ Platform SRK  │  │   PCR Policy  │        │  │  │
│  │  │  │  0x81000001   │  │  0x81000002   │  │   (PCR 23)    │        │  │  │
│  │  │  │  (no policy)  │  │  (PCR + PIN)  │  │               │        │  │  │
│  │  │  └───────────────┘  └───────────────┘  └───────────────┘        │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                  │                                    │  │
│  └──────────────────────────────────┼────────────────────────────────────┘  │
│                                     │                                       │
│  ┌──────────────────────────────────┼────────────────────────────────────┐  │
│  │                          HARDWARE LAYER                               │  │
│  │                                  ▼                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                        TPM 2.0 Chip                             │  │  │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐             │  │  │
│  │  │  │  PCR 0  │  │  PCR 7  │  │  PCR 9  │  │ PCR 23  │  ...        │  │  │
│  │  │  │ (BIOS)  │  │(SecBoot)│  │ (cmdln) │  │(golden) │             │  │  │
│  │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘             │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Files

### Initramfs Code
- `pkg/initrd/initrd.go` - Main manager
- `pkg/initrd/strategy_firstboot_seal.go` - First boot sealing
- `pkg/initrd/strategy_tpm_pcr.go` - TPM PCR unlock
- `pkg/initrd/strategy_tpm_upgrade.go` - Kernel upgrade unlock
- `pkg/initrd/strategy_password.go` - Passphrase fallback

### Platform Code
- `pkg/platform/keychain.go` - Platform XKMS management
- `pkg/cli/commands/tpm/extend.go` - PCR extension command
- `pkg/cli/commands/tpm/provision.go` - Platform provisioning

### Installer Code
- `pkg/installer/installer.go` - Installation logic
- `pkg/iso/` - ISO building

### Configuration
- `configs/platform/standalone/*.yaml` - Platform configs (single source of truth for install + runtime)

## Quick Reference

### TPM Handles
| Handle | Name | Policy |
|--------|------|--------|
| 0x81000001 | SSRK | None |
| 0x81000002 | Platform SRK | PCR + PIN |

### EFI Files
| File | Purpose | Lifetime |
|------|---------|----------|
| installer.luks | Encrypted container (contains luks-key.bin) | First boot only (securely wiped) |
| seal-platform.pub/priv | Platform seals (PCR policy) | Permanent |
| seal-upgrade.pub/priv | Upgrade seals (no policy) | One boot |
| pcr-banks | PCR selection for sealing | Permanent |

**SECURITY:** The LUKS key is NEVER stored in plaintext on the EFI partition.
It only exists inside the encrypted installer.luks container which is securely wiped after firstboot.

### Unlock Priority
1. Keyfile (80) - First boot (from mounted installer.luks)
2. TPM-PCR (1) - Normal boot
3. TPM-Upgrade (2) - Kernel upgrade
4. Password (100) - Last resort

## Related Documentation

- [CLAUDE.md](../../CLAUDE.md) - Project conventions
- [iso-building.md](iso-building.md) - ISO building
- [SECURE-BOOT.md](../firmware/secure-boot.md) - Secure Boot integration
- [IMA](../ima/) - Linux Integrity Measurement Architecture (file integrity, PCR 10)

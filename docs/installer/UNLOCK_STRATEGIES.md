# LUKS Unlock Strategies

This document describes the unlock strategies available in the Trusted Platform initramfs.

## Strategy Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Strategy Chain                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Firstboot  │  │   TPM-PCR   │  │ TPM-Upgrade │              │
│  │  Priority 0 │  │  Priority 1 │  │  Priority 2 │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │    FIDO2    │  │  Password   │                               │
│  │  Priority 4 │  │ Priority 100│                               │
│  └──────┬──────┘  └──────┬──────┘                               │
│         │                │                                      │
│         └────────────────┘                                      │
│                │                                                │
│                ▼                                                │
│        [ LUKS Unlocked ]                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Strategy Summary

| Strategy | Priority | Trigger | User Action | Files |
|----------|----------|---------|-------------|-------|
| Firstboot-Seal | 0 | Installer exists | None | installer.luks |
| TPM-PCR | 1 | Platform seals exist | None | seal.pub, seal.priv |
| TPM-Upgrade | 2 | Upgrade seals exist | None | seal-upgrade.pub, seal-upgrade.priv |
| FIDO2 | 4 | FIDO2 configured | Touch key | N/A |
| Password | 100 | Always | Enter passphrase | N/A |

## Firstboot-Seal Strategy

**File:** `pkg/initrd/strategy_firstboot_seal.go`

### Purpose
Handles first boot after installation. Opens encrypted installer container, provisions platform inside it, seals keys to TPM.

### Trigger Condition
- Encrypted installer exists: `/boot/efi/tpm2/installer.luks`
- No sealed blobs exist

### Flow
1. Open encrypted installer container (password: `installer`)
2. Mount read-write at `/mnt/installer`
3. Read LUKS key and recovery key from installer
4. Provision platform INSIDE installer container (in-process)
   - Creates SSRK and Platform KeyStore SRK
   - Extends PCR 23 with golden measurement
   - All output stays encrypted (CA keys, platform state)
5. Create Platform seals (PCR policy) on EFI partition
6. Unlock LUKS with key (still in memory)
7. Set markers for post-switch_root:
   - Copy installer contents to root filesystem
   - Write recovery key to `/root/luks-recovery.txt`
8. Kill root keyslot 0 (the install-time passphrase); **preserve installer.luks**
   pending proof of the seal
9. **Next boot, on a `TPM-PCR` unlock: SECURE WIPE installer.luks** (overwrite
   + TRIM, from `platform-initrd boot` before `switch_root`)

### Security Notes
- All provisioning happens inside encrypted container - maximum security
- LUKS key never written unencrypted to EFI partition
- Installer container provides forensic protection (encrypted fragments in SSD spare blocks)
- Secure wipe destroys LUKS header making forensic recovery impossible
- Recovery key written to root filesystem (encrypted) after first boot

## TPM-PCR Strategy

**File:** `pkg/initrd/strategy_tpm_pcr.go`

### Purpose
Primary unlock strategy for production use. Uses Platform KeyStore SRK with PCR policy.

### Trigger Condition
- Platform seals exist: `seal.pub`, `seal.priv`
- TPM available

### Flow
1. Mount EFI partition
2. Extend PCR 23 with golden measurement (in-process)
3. Load sealed blobs from EFI
4. Unseal using Platform KeyStore SRK
   - Requires PCR 23 match
5. Unlock LUKS

### Security Features
- PCR policy ensures boot chain integrity
- Hardware-bound to TPM chip

### Failure Cases
- PCR mismatch (boot chain changed)
- TPM unavailable

## TPM-Upgrade Strategy

**File:** `pkg/initrd/strategy_tpm_upgrade.go`

### Purpose
Temporary unlock during kernel upgrades when PCRs change.

### Trigger Condition
- Upgrade seals exist: `seal-upgrade.pub`, `seal-upgrade.priv`
- TPM available

### Flow
1. Load upgrade seals from EFI
2. Unseal using SSRK (no policy check)
3. **IMMEDIATELY DELETE upgrade seals**
4. Set reseal flag for post-boot
5. Unlock LUKS

### Security Notes
- Upgrade seals have NO policy protection
- MUST be deleted immediately after use
- Only created right before kernel upgrade
- Never persist across multiple boots

### Creating Upgrade Seals
Before kernel upgrade:
```go
upgradeStrategy.CreateUpgradeSeal(luksKey)
```

## FIDO2 Strategy

**File:** `pkg/initrd/strategy_fido2.go`

### Purpose
Unlock using FIDO2 security key (YubiKey, etc.)

### Trigger Condition
- FIDO2 handler configured
- FIDO2 device available

### Flow
1. Detect FIDO2 device
2. Prompt user to touch key
3. Get FIDO2 credential
4. Derive or unseal LUKS key
5. Unlock LUKS

## Password Strategy

**File:** `pkg/initrd/strategy_password.go`

### Purpose
Ultimate fallback using LUKS passphrase.

### Trigger Condition
- Always available
- Lowest priority (100)

### Flow
1. Prompt user for LUKS passphrase
2. Unlock LUKS directly with passphrase

### User Prompt
```
Enter LUKS passphrase for /dev/sda2:
```

### Security Notes
- Not TPM-bound
- Full LUKS passphrase required
- Use only as last resort

## Configuration

### Enabling Strategies

In `initrd.Config.FallbackMethods`:

```yaml
fallback-methods:
  - tpm-pcr      # Primary TPM with PCR policy
  - tpm-upgrade  # Kernel upgrade path
  - fido2        # FIDO2 security key (optional)
  - password     # Ultimate fallback
```

### Strategy Priority

Strategies are tried in priority order. First successful unlock wins.

### Adding Custom Strategies

Implement the `UnlockStrategy` interface:

```go
type UnlockStrategy interface {
    Name() string
    Priority() int
    CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool
    Unlock(ctx context.Context, volume *luks.VolumeConfig) error
    Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error
}
```

Register in `pkg/initrd/initrd.go`:

```go
m.RegisterStrategy(NewMyCustomStrategy(m.platform, m.logger))
```

## EFI Partition Layout

**Note:** EFI partition must be at least 200MB to accommodate the installer container.

### During Installation
```
/boot/efi/
├── EFI/
│   └── BOOT/
│       └── BOOTX64.EFI
└── tpm2/
    └── installer.luks      # Encrypted container (100MB) - LUKS key + recovery + config
```

### After First Boot
```
/boot/efi/
├── EFI/
│   └── BOOT/
│       └── BOOTX64.EFI
└── tpm2/
    ├── seal.pub            # Platform seal public (PCR policy)
    ├── seal.priv           # Platform seal private (PCR policy)
    ├── pcr-banks           # PCR selection for seals
    └── .reseal-needed      # Re-seal flag (if kernel update pending)
```

**Note:** No sensitive data is ever written unencrypted to the EFI partition. The `installer.luks` container provides forensic protection during the install-to-firstboot window.

## Troubleshooting

### TPM-PCR Fails After BIOS Update
PCR values changed. Use Password strategy with LUKS passphrase, then re-seal after boot.

### Installer Still Exists After the Second Boot
`installer.luks` is expected after the first boot: it is wiped by the next
boot that unlocks with `TPM-PCR` (the serial log says `Seal confirmed by
TPM-PCR unlock`). If it still exists after that, the second boot unlocked some
other way (`Successfully unlocked with strategy: Keyfile` — the seal is not
working; fix that first) or the wipe failed (`WARNING seal confirmation`).
Manually wipe:
```bash
# Mount EFI
mount /boot/efi

# Secure wipe installer
dd if=/dev/urandom of=/boot/efi/tpm2/installer.luks bs=1M count=100
sync
rm /boot/efi/tpm2/installer.luks
fstrim /boot/efi   # Issue TRIM
```

### Lost Recovery Key
If `/root/luks-recovery.txt` doesn't exist after first boot:
- The LUKS passphrase from installation is still valid (keyslot 0)
- Boot with Password strategy and re-generate recovery key if needed

### No TPM Available
All TPM strategies fail. Use:
- FIDO2 if configured
- Recovery key from `/root/luks-recovery.txt`
- Password (LUKS passphrase) as last resort

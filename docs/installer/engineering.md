# Installer — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/installer/`, `pkg/initrd/`, `pkg/iso/`, `pkg/qemu/`, `cmd/platform-initrd` · Last verified: 2026-09-16
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was read out of the named file on 2026-08-18.

---

## 1. Package layout

`pkg/installer/` — the install orchestrator:

| File | Holds |
|---|---|
| `types.go` | `Config` and every sub-config; the `Installer`, `DiskManager`, `OSInstaller`, `UKIBuilder` interfaces; `DiskInfo` |
| `installer.go` | `NewInstaller`, `Install`, TPM clear, disk setup, UKI build/sign, `prepareLUKSKeyForTPM`, cleanup |
| `boot_firmware.go` | `InstallTarget` (disk\|image), `BootFirmwareType` (uefi\|uboot), `BootConfig`, the `bootFirmwares` dispatch map, `imageTargetSkips` |
| `arch.go` | `resolveBootTarget` — the per-architecture UKI file name, systemd stub path and dracut driver set (`x86_64`, `aarch64`) |
| `config.go` | `LoadConfig`, `SaveConfig`, `DefaultConfig` |
| `config_loader.go` | `LoadInstallConfig`, `MergeWithDefaults` |
| `config_generator.go` | `GenerateInstallConfig`, `WriteInstallConfig`, and the `*YAMLConfig` shapes |
| `profiles.go` | Built-in profiles, embedded from `pkg/installer/profiles/*.yaml` |
| `disk.go` | `NewDiskManager` — partitioning, LUKS, LVM, mount |
| `os.go`, `alpine.go`, `alpine/` | `NewOSInstaller`; Alpine base install, `APKManager`, `FIPSInstaller` |
| `uki.go`, `dracut_builder.go` | `NewUKIBuilderAdapter`, `NewDracutUKIBuilder` |
| `uki_rebuild.go`, `uki_rebuild_errors.go` | `UKIRebuilder` and its functional options |
| `remote_sign_client.go` | `RemoteSignContext`, `ErrRemoteSign` |
| `fido2_enroll.go`, `fido2_unlock.go` | `FIDO2Enrollment`, `FIDO2Unlock`, `DetectFIDO2Device`, `IsFIDO2Available` |
| `kernel_hook.go` | The post-kernel-upgrade UKI rebuild hook |
| `hardreset.go` | `HardReset` — SysRq-b warm reset |
| `hwoffload.go` | `CheckHWOffloadSupport` |
| `postinstall.go` | `PostInstallExecutor` |
| `errors.go`, `uki_rebuild_errors.go` | Typed errors |

`pkg/initrd/` — the boot-time unlock engine: `types.go`, `config.go`,
`initrd.go`, `strategy.go`, `strategy_keyfile.go`, `strategy_tpm_pcr.go`,
`strategy_tpm_upgrade.go`, `strategy_tpm_nopcr.go`, `strategy_fido2.go`,
`strategy_password.go`, `boot.go`, `install.go`, `recovery.go`, `partition.go`,
`multidrive.go`, `tpm_detect.go`, `errors.go`.

`pkg/iso/` — media production: `config.go`, `types.go`, `download.go`,
`extract.go`, `customize.go`, `customize_profile.go`, `build.go`,
`inject_modules.go`, `prefetch.go`, `profile_network.go`, `errors.go`, plus the
embedded `autoinstall.sh`. `PlatformISOConfig` carries the target
architecture (`alpine.architecture`, canonicalised by `SetDefaults`, rejected
by `Validate` with `UnsupportedArchitectureError` / `FIPSUnsupportedArchitectureError`)
and an `installer:` override block (`device`, `partition_table` gpt|mbr,
`kernel_package`, `extra_packages`, `hardware_manufacturer`,
`hardware_model`) that the generated `installer.Config` and the apk prefetch
honour; the ISO leaves every override empty. `Customizer.CustomizeAll` is
`checkPrerequisites` → exported `StageMedia` (the media-root half a disk
image builder reuses) → `customizeLiveISO` (initramfs and GRUB surgery).
Every bundled binary passes `validateTargetBinary`, which requires the ELF
machine of the configured architecture (`BinaryArchMismatchError`).

`pkg/qemu/` — the test harness: `config.go`, `types.go`, `qemu.go`,
`secureboot.go`, `monitor.go`, `snapshot.go`, `migration.go`, `ovs_network.go`.

`pkg/partition/` — the one place that knows how the kernel names partitions
(`Path(disk, n)`: `sda`→`sda2`, `nvme0n1`→`nvme0n1p2`, `mmcblk0`→`mmcblk0p2`,
`loop3`→`loop3p2`; `Parent`) and how the EFI system partition is found for a
root device (`FindESP`: the disk's first partition, then
`/dev/disk/by-label/EFI`, then `DefaultESPCandidates` — `vda1`, `sda1`,
`nvme0n1p1`, `mmcblk0p1`, `mmcblk1p1`). The installer's partition paths,
`FirstbootSealStrategy`, `TPMPCRStrategy` and `TPMUpgradeStrategy` all go
through it; there is no other probe list.

`cmd/platform-initrd` is a four-line `main` over `pkg/boot/commands`.

## 2. Exported surface — `pkg/installer`

```go
func NewInstaller(logger *logging.Logger, config *Config, opts ...InstallerOption) (Installer, error)
type InstallerOption func(*installer)
func WithRemoteSignContext(rsc *RemoteSignContext) InstallerOption
```

`Installer` has exactly two methods: `Install(ctx) error` and `Close() error`.
The concrete type is unexported — construct through `NewInstaller`.

```go
const DefaultESPUKIPath = "/boot/efi/EFI/BOOT/BOOTX64.EFI"
const DefaultESPBootDir = "/boot/efi/EFI/BOOT"
func ESPUKIPathFor(arch uki.Architecture) (string, error)
```

`OSConfig.Architecture` selects the boot artefacts. `""`, `x86_64` and the
GOARCH alias `amd64` resolve to `BOOTX64.EFI` and `linuxx64.efi.stub`;
`aarch64` / `arm64` resolve to `BOOTAA64.EFI` and `linuxaa64.efi.stub`
(`uki.BootFileName`, `uki.StubPath`). `NewInstaller` canonicalises the
configured spelling to the Alpine name (`aarch64`), which is also the apk
architecture directory, and `Config.Validate` rejects anything `pkg/uki`
does not model. `UKIRebuilder` defaults its live UKI path to the
architecture of the binary it runs in.

Interfaces the orchestrator composes (`types.go`):

| Interface | Constructor | Methods |
|---|---|---|
| `DiskManager` | `NewDiskManager(logger, *DiskConfig)` | `CreatePartitionTable`, `CreateEFIPartition`, `CreateRootPartition`, `SetupLUKS`, `CreateLVMPhysicalVolume`, `CreateLVMVolumeGroup`, `CreateLVMLogicalVolume`, `FormatFilesystem`, `Mount`, `Unmount`, `EnsureDeviceNode`, `Close` |
| `OSInstaller` | `NewOSInstaller(logger, *OSConfig)` | `InstallBase`, `ConfigureSystem`, `ConfigureNetwork`, `InstallKernel`, `SetRootPassword`, `EnableServices`, `InstallPackages`, `ExecutePostInstall`, `Name` |
| `UKIBuilder` | `NewUKIBuilderAdapter(logger)` / `NewDracutUKIBuilder(logger)` | `BuildUKI(ctx, *UKIConfig, io.Writer)` |

UKI rebuild after a kernel upgrade:

```go
func NewUKIRebuilder(logger *logging.Logger, config *Config, opts ...UKIRebuildOption) *UKIRebuilder
type RemoteSignerResolver func(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error)
```

Options: `WithUKIBuilder`, `WithRemoteSigner`, `WithAuthenticodeSigner`,
`WithESPUKIPath`, `WithModulesDir`, `WithBootDir`, `WithKernelCmdlinePath`.

Config helpers: `LoadConfig`, `SaveConfig`, `DefaultConfig`,
`LoadInstallConfig`, `MergeWithDefaults`, `GenerateInstallConfig`,
`WriteInstallConfig`, `ConfigToYAML`, `ConfigFromYAML`, `ValidateConfig`.

Profiles: `GetProfile`, `GetProfileWithDescription`, `ListProfiles`,
`ListProfilesWithDescriptions`, `ValidateProfileName`,
`GenerateConfigFromProfile`. Four names exist and no others —
`ProfileDev`, `ProfileProduction`, `ProfileProductionHS`, `ProfileFIPS`.

FIDO2: `NewFIDO2Enrollment(*FIDO2EnrollmentConfig)`, `DetectFIDO2Device`,
`IsFIDO2Available`, `NewFIDO2Unlock(luksDevice string, debug bool)`.

Other exported names: `HardReset`, `CheckHWOffloadSupport`,
`NewPostInstallExecutor`, `DefaultIMAMonitorPaths`,
`DefaultLUKSTPMHandle` (`0x81000001`), `InstallerPassword`
(`"forensic-protection-only"`), `RecoveryKeyStrategyDestroy`,
`RecoveryKeyStrategyEscrow`, `SecureBootResignModeRemote`,
`SecureBootResignModeLocal`.

## 3. Exported surface — `pkg/initrd`

```go
func NewManager(platform *Platform, logger *logging.Logger) (Manager, error)
func NewStrategyChain(logger *logging.Logger) *StrategyChain
func DefaultConfig() *Config
func MergeConfig(base, override *Config) *Config
```

`Manager`: `Initialize`, `DetectMode`, `Install`, `Boot`, `Recovery`,
`InteractiveRecovery`, `RegisterStrategy`, `UnlockVolumes`, `Close`.

`UnlockStrategy`: `Name() string`, `Priority() int`,
`CanUnlock(ctx, *luks.VolumeConfig) bool`, `Unlock(ctx, *luks.VolumeConfig) error`,
`Install(ctx, *luks.VolumeConfig, password []byte) error`.

`Platform` carries `TPM xkms.TrustedPlatformModule`, `LUKS luks.Handler`,
`FIDO2 fido2.Handler`, `XKMS *platform.XKMS`, `Backend xkms.TPMKeyBackend`,
`Config *Config`.

Strategy constructors: `NewKeyfileStrategy`, `NewTPMPCRStrategy`,
`NewTPMUpgradeStrategy`, `NewTPMNoPCRStrategy`, `NewFIDO2Strategy`,
`NewPasswordStrategy`. Also `NewDiskPreparer`, `NewMultiDriveManager`,
`NewTPMDetector`.

`BootMode` is `ModeInstall`, `ModeBoot`, `ModeRecovery`, `ModeMaintenance`.

## 4. Invariants

1. **Sealing never happens in the installer.** `NewInstaller` explicitly does
   *not* construct a TPM2 object when `EnableTPMSealing` is set — it only
   `os.Stat`s `/dev/tpmrm0` then `/dev/tpm0`, logs, and clears the flag if
   neither exists. Creating a TPM here would provision the EK and collide with
   firstboot.
2. **The TPM clear runs regardless of `EnableTPMSealing`, and its failure is
   non-fatal.** A VM without a TPM must still install. On `TPM_RC_LOCKOUT` the
   installer escalates to `ForceClear` (UEFI PPI) and calls `HardReset()`.
3. **The boot firmware is a seam, and the install target gates host-only steps.**
   After the UKI is signed, `Install` dispatches through `bootFirmwares`
   (`pkg/installer/boot_firmware.go`): `uefi` keeps `configureUEFIBoot` and
   `enforceSecureBoot` exactly as before, `uboot` writes the provisioned
   sentinel, copies the staged firmware tree onto the ESP root and enrols
   nothing (the PK/KEK/db are preseeded into U-Boot). A U-Boot staging
   failure is fatal, because there is no firmware fallback path that finds
   the UKI. `Config.Target = image` consults `imageTargetSkips`: the TPM clear,
   the `/dev/tpmrm0` presence check, FIDO2 auto-enrolment and `/proc/cmdline`
   propagation act on the build host and are skipped; everything the node
   needs on its first boot is still written.
4. **Every partition path and every UKI file name is derived, never spelled.**
   `pkg/partition.Path` produces `<disk>2` or `<disk>p2` as the kernel would
   (loop and MMC devices need the `p`), and the boot file under `EFI/BOOT` is
   `uki.BootFileName(arch)`; the completion gate (architecture.md §5, step 15) checks that name,
   so an aarch64 install is failed for a missing `BOOTAA64.EFI`, not passed
   for a stale `BOOTX64.EFI`. The ESP line in `/etc/fstab` is `LABEL=EFI
   /boot/efi vfat defaults 0 2` — the label `disk.go` writes with `mkfs.vfat
   -n EFI` — so the entry stays valid whatever device name the partition gets
   on the booted node (2026-09-16; it used to bake the installer's `/dev/sdX1`).
5. **Ordering inside `Install` is load-bearing.** The FIPS kernel must be
   installed *before* the UKI is built; `platform-initrd` must be in the dracut
   module *before* the UKI is built; the UKI must be signed *before* FIPS
   OpenSSL configuration, because FIPS mode breaks the signing path; Secure
   Boot enforcement must also precede it. Reordering these silently produces an
   unbootable or unsigned node.
6. **Post-install script failure is fatal; almost nothing else is.** Package
   install, network config, UEFI boot entry, Secure Boot enforcement, the
   kernel-update hook, the firstboot service, `prepareLUKSKeyForTPM` and FIDO2
   enrolment all log a warning and continue. `ExecutePostInstall` returns an
   error that aborts the install, because that script provisions operator
   access and a node that installs "successfully" without it is unreachable.
7. **Strategy priority is ascending — lower runs first.**
   `StrategyChain.sort()` orders by `Priority()` ascending and `Execute` takes
   the first strategy whose `CanUnlock` is true and whose `Unlock` succeeds.
   **The doc comment on `KeyfileStrategy.Priority()` says "higher = tried
   first" and is wrong**; 80 is tried *after* TPM-PCR (1), TPM-Upgrade (2) and
   FIDO2 (3), and before Password (100). The effective order is in §5.
8. **`Add` and `RegisterStrategy` ignore nil** so a minimal build can omit a
   strategy without a branch at the call site.
9. **`ExecuteInstall` is fail-fast**, unlike `Execute`: the first strategy whose
   `Install` fails aborts the whole chain.
10. **A bundle of PCR selection has three sources with a fixed precedence** in
   `pkg/boot/commands/boot.go`: the `--pcrs` flag, then
   `/boot/efi/tpm2/pcr-banks`, then `config.yaml` inside the mounted installer
   container. If all three fail the selection is left empty and
   `Config.Validate` rejects it with `ErrInvalidConfig`.
11. **`Config.Validate` (initrd) requires `RootDevice`, `XKMSPath` and a
   non-empty `PCRSelection`.** `DefaultConfig()` deliberately leaves
   `PCRSelection` nil so that an installer config that forgot to set it fails
   loudly rather than sealing against a wrong-but-plausible default.
12. **LUKS keyslots are fixed.** Slot 0 = installer passphrase, slot 1 = TPM
    key, slot 2 = recovery passphrase. `pkg/firstboot/strategy.go` defines
    `luksSlotTPMKey = 1` and `luksSlotRecovery = 2`; code that adds or removes
    slots must use them.
13. **`installer.luks` is wiped only once the seal is proven.** First boot
    never wipes it: the seal it just wrote has not unsealed anything yet.
    The next boot that unlocks the root with `TPM-PCR` while the container
    is still on the ESP wipes it from `platform-initrd boot`
    (`pkg/boot/commands/sealconfirm.go`, `securewipe.File`); a keyfile
    unlock or a failed seal preserves it so the retry has its key — which
    means a half-provisioned node is still holding its LUKS key on the ESP
    until then. Root keyslot 0 (the install-time passphrase) is killed the
    moment the sealed key is written (`killInstallerKeyslot`).
14. **PK is written last** during Secure Boot enforcement, and enforcement only
    proceeds if the signed UKI verifies against the db certificate and the
    firmware is in Setup Mode.
15. **A partition node is trusted only while it names the kernel's device.**
    `waitForDevice` and `EnsureDeviceNode` compare an existing node's
    major:minor with `/proc/partitions` (`refreshDeviceNode`) and recreate
    it when they differ. Every `blockdev --rereadpt` drops and re-adds the
    partitions, and a re-added partition gets a fresh extended minor while a
    reference to the old one lingers; devtmpfs follows, a static `/dev` (the
    factory-image assemble container's) does not, and a mount through the
    stale node fails with ENXIO. Names the kernel does not list
    (device-mapper names) are left alone.
16. **A failed image-target install releases what `setupDisk` opened; a
    failed live install does not.** `Install` names its error and a
    deferred `afterFailedInstall` consults `releaseOnFailure`
    (`pkg/installer/release.go`): for `Config.Target = image` it unmounts
    the chroot pseudo-filesystems, the ESP and `/mnt` (lazily when a regular
    unmount fails), removes the `vg0-root` mapping and closes the LUKS
    mapping, on its own 30-second context so a cancelled install still
    cleans up, and logs every step that did not complete as
    `ErrDiskRelease`. The install error is what `Install` returns; the
    release never replaces it. A live install keeps its mounts because the
    operator is on the node and the reboot clears them; an image build has
    no reboot, and a mapping or loop device left open on the build host
    blocks the next build until someone finds it by hand (2026-09-20).
17. **The kernel inside the UKI is signed when the boot firmware verifies
    it.** `bootFirmware.VerifiesEmbeddedKernel` is false for `uefi` and true
    for `uboot`; `buildUKI` calls `signEmbeddedKernel` before the PE builder
    wraps the kernel, and it Authenticode-signs the decompressed EFI-stub
    kernel in memory with the same DB key `signUKI` uses. systemd-stub hands
    that kernel to `LoadImage`; EDK2 firmware lets the stub install a
    Security-Arch override that trusts an image the stub already verified,
    U-Boot has no such protocol and authenticates the inner image against
    `db` (measured 2026-09-20: the UKI verified, the inner kernel did not,
    and the stub failed in `linux_exec` with a Security violation). The x86
    UKI keeps its unsigned inner kernel, so its bytes do not change.
18. **`WIN_CERTIFICATE.dwLength` is header + DER; the 8-byte padding is
    outside it.** `pkg/authenticode.embedSignature` writes what `sbsign`
    writes. A `dwLength` that covered the padding verified under OVMF and
    was rejected by U-Boot's mbedTLS PKCS#7 parser (length mismatch), whose
    untranslated error then crashed the firmware; the U-Boot builder
    carries a patch for the crash, the signer carries the convention.
19. **A platform-built kernel comes from the media and is verified first.**
    `OSConfig.KernelArtifactsDir` (YAML `os.kernel-artifacts-dir`) names a
    directory on the install media in the `virt-kernel-builder` layout
    (`vmlinuz-<flavor>`, `modules-<flavor>.tar.gz`, `kernel-version.txt`,
    `SHA256SUMS`); `InstallBase` then installs no kernel apk and
    `InstallKernel` runs `installMediaKernel` (`pkg/installer/mediakernel.go`):
    `SHA256SUMS` verified, kernel copied to `/boot/vmlinuz-<flavor>`, modules
    unpacked at the root, `depmod` for the release. The flavour is the
    configured `kernel-package`'s (`linux-virt` → `virt`), so the UKI
    builder's `vmlinuz-<flavor>` lookup (invariant 3's kernel flavour rule)
    and dracut's `/lib/modules/<release>` see a packaged kernel. Failures are
    `ErrMediaKernel` (`ErrorTypeOSInstall`). The QEMU virt stand-in of the
    Raspberry Pi image is the consumer ([factory-image architecture.md](../factory-image/architecture.md) §2).

## 5. Unlock strategy table — as the code registers it

`initrdManager.registerDefaultStrategies()` always registers
`KeyfileStrategy`, then registers one strategy per entry in
`Config.FallbackMethods`.

| Strategy | `Name()` | `Priority()` | Registered when | Source |
|---|---|---|---|---|
| TPM + PCR policy | `TPM-PCR` | **1** | `luks.UnlockTPMPCR` in `FallbackMethods` | `strategy_tpm_pcr.go` |
| TPM upgrade seal | `TPM-Upgrade` | **2** | `luks.UnlockTPMUpgrade` | `strategy_tpm_upgrade.go` |
| FIDO2 | `FIDO2` | **3** | `luks.UnlockFIDO2` **and** `Platform.FIDO2 != nil` | `strategy_fido2.go` |
| TPM without PCR | (see note) | **5** | **never — by the default registrar** | `strategy_tpm_nopcr.go` |
| Keyfile | `Keyfile` | **80** | always | `strategy_keyfile.go` |
| Password | `Password` | **100** | `luks.UnlockPassword` | `strategy_password.go` |

`DefaultConfig().FallbackMethods` is
`[UnlockTPMPCR, UnlockTPMUpgrade, UnlockFIDO2, UnlockPassword]`.

**`TPMNoPCRStrategy` is constructible but unreachable through
`registerDefaultStrategies`.** `luks.UnlockTPMNoPCR` exists as an
`UnlockMethod` constant, but the `switch` in `initrd.go` has no case for it, so
a config listing `tpm-nopcr` logs *"Unknown unlock method"* and registers
nothing. A caller that wants it must `RegisterStrategy(NewTPMNoPCRStrategy(...))`
directly.

**The first-boot strategy does not live in `pkg/initrd`.** `FirstbootSealStrategy`
(`Name() == "Firstboot-Seal"`, `Priority() == 0`) is defined in
`pkg/firstboot/strategy.go` and constructed with
`NewFirstbootSealStrategy(executor, luksHandler, logger)`. There is no
`pkg/initrd/strategy_firstboot_seal.go` — see §10.

## 6. Error semantics

`pkg/installer` uses a single wrapper type plus constructors:

```go
type InstallerError struct { Type ErrorType; Message string; Cause error }
```

`ErrorType` is one of `invalid_config`, `disk_operation`, `encryption`,
`os_install`, `uki_build`, `secure_boot`, `tpm`. Constructors:
`ErrInvalidConfig(msg)`, `ErrDiskOperation(msg, cause)`, `ErrEncryption`,
`ErrOSInstall`, `ErrUKIBuild`, `ErrSecureBoot`, `ErrTPM`. `Unwrap` is
implemented, so `errors.As(err, &installerErr)` and `errors.Is` on the cause
both work.

Structured errors: `ErrSecureBootConfig{Field, Reason}` from
`SecureBootConfig.Validate`; `ErrRemoteSign`; and the UKI rebuild set
`ErrKernelImageNotFound`, `ErrKernelCmdlineUnavailable`, `ErrNoKernelModules`,
`ErrModulesUnsigned`, `ErrUKIRebuildVerify`. Generic wrappers `MessageError`,
`WrappedError`, `CommandOutputError` exist in `pkg/installer`,
`pkg/installer/alpine`, `pkg/initrd`, `pkg/iso` and `pkg/cli/commands/iso`;
they are per-package types, not shared.

`pkg/initrd` sentinels (`errors.go` / `types.go`):
`ErrUnlockFailed`, `ErrNoStrategiesAvail`, `ErrInvalidMode`, `ErrInvalidConfig`,
`ErrVolumeNotConfigured`, `ErrInstallationFailed`, `ErrRecoveryFailed`,
`ErrStrategyNotAvailable`. `StrategyChain.Execute` returns
`&SentinelCauseError{Sentinel: ErrUnlockFailed, Cause: …}` when at least one
strategy tried and failed, and bare `ErrUnlockFailed` when none was eligible;
`ErrNoStrategiesAvail` when the chain is empty. `SentinelCauseError.Unwrap`
returns `[]error{Sentinel, Cause}`, so `errors.Is(err, ErrUnlockFailed)` matches
either way.

`pkg/cli/commands/iso` errors are typed per failure: `ErrDaemonConnectionRequired`,
`ErrInvalidArchitecture`, `ErrInvalidPlatformType`, `ErrISONotFound`,
`ErrDirectoryNotFound`, `ErrDirectoryAlreadyExists`, `ErrDownloadFailed`,
`ErrExtractionFailed`, `ErrCustomizationFailed`, `ErrBuildFailed`,
`ErrConfigValidationFailed`, `ErrProfileNotFound`, `ErrConfigParseError`,
`ErrVolumeLabelTooLong`, `ErrBootstrapClientCreate`, `ErrCABundleFetch`,
`ErrCABundleEmpty`, `ErrCABundleWrite`, `ErrOverridesWithoutTemplate`,
`ErrOverridesMergeFailed`, `PXEServerQEMUError`.

### Fail-closed paths

| Path | Behaviour |
|---|---|
| `ExecutePostInstall` fails | **Install aborts.** Operator access is not optional. |
| `SecureBootConfig.Validate` | Rejects a missing `db.key-uri`, a missing `pk`/`kek` URI when `enforce` is set, and any URI scheme that is not `kms://` or `file://`. Defaults `resign-mode` to `remote`. |
| `enforceSecureBoot` | Refuses to enrol unless the signed UKI verifies against the db cert **and** firmware is in Setup Mode. Fails open into "boots unsigned", never into "bricked". |
| `installer.luks` wipe | Deferred to the first `TPM-PCR` unlock (`platform-initrd boot`); skipped after a keyfile unlock or a failed seal, so the retry path survives. Fails **open** on purpose — and that is the residual risk in §6 of [architecture.md](architecture.md). |
| `initrd.Config.Validate` | Empty `PCRSelection` is `ErrInvalidConfig`. No default PCR set is ever assumed. |
| `StrategyChain.Execute` | Returns `ErrUnlockFailed` rather than falling through to an unencrypted boot. |
| `ExecuteInstall` | Aborts on the first strategy install failure. |

## 7. Configuration

Precedence for `platformctl install system`, highest first: **command-line flag
→ config file → built-in default.** `loadConfig` reads `--config`, else
`/etc/platformd/install.yaml`, else builds from flags; `applyFlagOverrides` then
re-applies only the flags cobra reports as `Changed`.

### `installer.Config` (YAML keys)

| Key | Type | Default (`DefaultConfig`) |
|---|---|---|
| `disk.device` | string | — (**required**) |
| `disk.partition-table` | `gpt` \| `mbr` | `gpt` |
| `disk.efi-partition-size` | int (MB) | `538` |
| `disk.root-filesystem` | `lvm` \| `ext4` | `lvm` |
| `disk.lvm-volume-group` | string | `vg0` |
| `disk.lvm-logical-volume` | string | `root` |
| `disk.encryption.version` | string | `luks2` |
| `disk.encryption.cipher` | string | `aes-xts-plain64` |
| `disk.encryption.key-size` | int (bits) | `512` |
| `disk.encryption.hash` | string | `sha256` |
| `disk.encryption.pbkdf` | string | **empty** — `fips.GetKDF()` auto-detects from `/proc/sys/crypto/fips_enabled` |
| `disk.encryption.mapped-name` | string | `cryptroot` |
| `disk.encryption.password` / `passphrase` | string, `secret:"true"` | — |
| `disk.encryption.tpm.enabled` | bool | — |
| `disk.encryption.tpm.handle` | uint32 | `DefaultLUKSTPMHandle` = `0x81000001` (SSRK) |
| `disk.encryption.tpm.seal-pcrs` | []uint | falls back to top-level `pcrs` |
| `disk.encryption.tpm.pcr-banks` | []string | falls back to the TPM config value |
| `disk.encryption.tpm.platform-policy` | bool | should be `false` — the initrd unseals before platformd creates the platform policy |
| `disk.encryption.tpm.factory-reset-on-firstboot` | bool | `false` in Go, `true` in reference templates |
| `disk.encryption.tpm.force-clear-via-ppi` | bool | `false` in Go, `true` in reference X10 templates |
| `disk.encryption.tpm.recovery-key-strategy` | `destroy` \| `escrow` | `escrow` (`ResolvedRecoveryKeyStrategy()`) |
| `disk.encryption.tpm.recovery-key.enabled` / `.method` | bool / string | `method` supports `autogen` only |
| `os.os` | `alpine` \| `debian` \| `fedora` \| `ubuntu` | `alpine` |
| `target` | `disk` \| `image` | `disk` — `image` is a loop-mounted disk image on a build host: the build host's TPM is not cleared, no FIDO2 key is probed, `/proc/cmdline` is not consulted, and sealing material is written for the node to seal on its own first boot |
| `boot.firmware` | `uefi` \| `uboot` | `uefi` — `uboot` copies `boot.firmware-stage-dir` (default `/media/cdrom/boot-firmware`) onto the ESP root and treats Secure Boot keys as preseeded in the U-Boot binary; no `efibootmgr`, no efivars |
| `boot.firmware-stage-dir` | string | `/media/cdrom/boot-firmware` |
| `os.architecture` | string | `x86_64` |
| `os.kernel-package` | string | `linux-lts` (the apk kernel; `linux-rpi` on a Raspberry Pi; ignored under FIPS) |
| `os.hostname` | string | `trusted-platform` |
| `os.fips` | bool | `false` |
| `os.lockdown` / `os.lockdown-mode` | bool / `integrity`\|`confidentiality` | `true` / `confidentiality` |
| `os.tpm-auto-upgrade-seal` | bool | `true` |
| `os.enable-fido2` | bool | `false` |
| `os.kernel-modules` | []string | — (needed on bare metal for `igb`, `ixgbe`, …) |
| `os.ima.*` | `IMAConfig` | policy `tcb`\|`appraise_tcb`\|`secure_boot`\|`critical_data`; appraise `off`\|`log`\|`enforce`\|`fix` |
| `secure-boot.enabled` / `.enforce` | bool | — |
| `secure-boot.resign-mode` | `remote` \| `local` | `remote` (applied by `Validate`) |
| `secure-boot.pk` / `.kek` / `.db` | `SecureBootKeyRef` | `key-uri` / `cert-uri` must be `kms://` or `file://` |
| `enable-tpm-sealing` | bool | `true` |
| `pcrs` | []uint | — |
| `enable-fido2-enrollment`, `fido2.*` | bool, `FIDO2Config` | `fido2.keyslot` documented default 3 |
| `environment` | string | `dev`\|`preprod`\|`prod`\|`test`; `test` makes platformd skip external checks |
| `hardware-manufacturer`, `hardware-model`, `hardware-part-number` | string | drive `quirks.ResolveIdentity` — the same identity the BMC clients match on, so the installed OS resolves the same entry |

`OSConfig.HardwareManufacturer` / `HardwareModel` / `HardwarePartNumber` are
`yaml:"-"` — they are propagated from the outer `Config` by `NewInstaller`,
not set in YAML. `Config.HardwareIdentity()` returns the three as a
`quirks.Identity`; `OSConfig.hardwareIdentity()` returns the same value after
propagation.

The three YAML keys are normally written by the bootstrap orchestrator, which
reads the identity off the node's `bmc.Client` during discovery — see
[`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md) for
the precedence chain and the hand-pinning escape hatch.

`app.App` carries the same three keys and `GetInstallerConfig` /
`SetInstallerConfig` copy them both ways. That is load-bearing, not
duplication: every on-disk config reaches the installer through
`loadUnifiedConfig`, which unmarshals the file into `App` and returns
`App.GetInstallerConfig()`. A field `App` does not carry is a field the
installer never sees, however faithfully the orchestrator wrote it.

### dnsmasq (`network.dnsmasq`)

`configureDNS` (alpine.go) takes one of three paths, in precedence order: the
dedicated `network.dnsmasq` block (`enabled: true`), the legacy
`network.dns.upstream-dns` string, else a plain `resolv.conf`. Both dnsmasq
paths install the package inside the chroot, enable the service in the
default runlevel, and point `resolv.conf` at `nameserver 127.0.0.1`.

`buildDNSMasqConf` renders `/etc/dnsmasq.conf`: `no-resolv`,
`listen-address=127.0.0.1`, `bind-interfaces`, `cache-size=1000`, one
`server=` line per `upstream-servers` entry, then — when `local-domain` is
set — `domain=<domain>` always, plus `local=/<domain>/` **only when no
upstream route governs the domain** (`dnsmasqZoneHasUpstreamRoute`): no
unscoped `server=` entry and no domain-scoped entry whose scope covers the
domain (suffix match, case-insensitive). Such a node is a purely local
resolver answering from `/etc/hosts`.

Wherever any route governs the zone, `local=` is omitted so the zone is
FORWARDED — including on the control plane, whose route targets its own
platformd zone at `127.0.0.1#9053`. `local=/<domain>/` makes dnsmasq
authoritative for the domain (answers from `/etc/hosts` only, never
forwarded — not even to a loopback upstream); emitting it unconditionally
blackholed the internal zone on every node forwarding to a remote control
plane — NXDOMAIN for `cp.<domain>` and a platformd FATAL at ACME
registration (issue #128). The forwarding shape needs no substitute
directive: the `server=` lines already route every zone, and templates that
pin the internal zone to a specific upstream use the domain-scoped
`/example.com/ip#port` entry form — a form `local=` defeats.

Upstream entries accept `ip`, `ip#port` (dnsmasq's separator), `host:port` /
`[v6]:port` (YAML shorthand), and `/domain/ip#port`. dnsmasq accepts only
`#` before the port and no IPv6 brackets, so the `:` shorthand and brackets
are normalized when the `server=` line is emitted
(`normalizeDNSMasqUpstream`). An entry that does not parse is written
verbatim — dnsmasq itself rejects the line at startup — and counts as
remote for the `local=` decision, so a malformed entry can never blackhole
the zone (`dnsmasqZoneServedLocally`, `dnsmasqUpstreamHost`).

### `initrd.Config`

Not a YAML surface. **`initrd.LoadConfig(path)` and `initrd.SaveConfig` are
stubs**: `LoadConfig` ignores its path and returns `DefaultConfig()`;
`SaveConfig` validates and returns nil without writing. The real configuration
arrives as flags from `pkg/boot/commands`. Defaults: `RootDevice`
`/dev/sda2`, `BootDevice` `/dev/sda1`, `XKMSPath`
`/var/lib/trusted-platform/xkms`, `PCRBanks` `["sha256"]`, `UnlockTimeout` 30 s,
`RetryCount` 3, `EnableAuditLog` true, `AuditLogPath`
`/var/log/initrd-unlock.log`. `Validate` raises `UnlockTimeout` to 30 and
`RetryCount` to 3 when non-positive.

### Environment variables

The installer packages read **no environment variables of their own**. The
`platformctl` persistent flags accept `PLATFORMCTL_CONFIG`,
`PLATFORMCTL_CONTEXT`, `PLATFORMCTL_TRANSPORT`, `PLATFORMCTL_SERVER`,
`PLATFORMCTL_SERVER_NAME`, `PLATFORMCTL_OUTPUT` and `NO_COLOR` — see
[cli.md](cli.md) §1.

## 8. Persistence and on-disk layout

Gateway-role nodes (`gateway.enabled: true` in the platform config) additionally
carry, laid down by the installer and firstboot (#66):

| Path | Written by | Purpose |
|---|---|---|
| `/usr/bin/gatewayd`, `/usr/sbin/gatewayd` → symlink | installer (`installGatewaydBinary`, from the ISO's `platformd-bin/`) | the edge daemon |
| `/etc/init.d/gatewayd` | firstboot (`installGatewaydService`) | OpenRC service, default runlevel, after `platformd` |
| `/etc/gatewayd/config.yaml` (0600) | firstboot (`renderGatewaydConfig`) | the `gateway:`, `proxy:`, `trust:`, `sdn:`, `control-plane:` sections of the platform config |
| `/etc/gatewayd/{client.pem,client-key.pem,cp-ca.pem}` | **operator** (not produced by the repo yet — #149, #431) | control-plane reporter mTLS identity; absent ⇒ reporter rendered disabled |

ESP layout, with the constants that name each file (`pkg/firstboot/types.go`,
`pkg/firstboot/strategy.go`):

| Path | Constant | Lifetime |
|---|---|---|
| `/boot/efi/EFI/BOOT/BOOTX64.EFI` (`BOOTAA64.EFI` on aarch64) | `uki.BootFileName(arch)` | permanent (the UKI) |
| `/boot/efi/tpm2/` | `EFITPMDir` | permanent |
| `/boot/efi/tpm2/installer.luks` | `EFIInstallerFile`, `strategyInstallerContainerFile` | first boot, then until the **first `TPM-PCR` unlock**, which securely wipes it |
| `/boot/efi/tpm2/seal-platform.pub` | `EFISealPlatformPub`, `strategySealPub` | permanent |
| `/boot/efi/tpm2/seal-platform.priv` | `EFISealPlatformPriv`, `strategySealPriv` | permanent |
| `/boot/efi/tpm2/seal-upgrade.pub` / `.priv` | `EFISealUpgradePub` / `Priv` | one boot — deleted immediately on use |
| `/boot/efi/tpm2/pcr-banks` | `EFIPCRBanks` | written minimally at install, overwritten authoritatively by firstboot |
| `/boot/efi/tpm2/pcr-seal-values.txt` | `EFIPCRValues` | permanent |
| `/boot/efi/tpm2/swtpm-state` | `EFISwtpmStateDir` | swtpm deployments only |
| `/boot/efi/tpm2/ppi-clear-attempted` | — | loop guard for `force-clear-via-ppi` |
| `/boot/efi/tpm2/network.conf` | — | written by `writeFirstbootNetworkConfig` at install; sourced by the dracut hook on first boot and by the firstboot service |

**`network.conf` contract.** A `key=value` file meant to be sourced by
POSIX sh. Keys: `INTERFACE`, `TYPE` (`static` or `dhcp`), and for static
interfaces `IPV4_ADDRESS` (the **bare** address, never with a CIDR suffix),
`IPV4_PREFIX` (0–32, derived by `firstbootStaticAddress` from the config's
CIDR suffix, else its dotted netmask, else 24), `IPV4_NETMASK` (as configured,
may be empty) and `IPV4_GATEWAY`; plus optional `DNS` (space-separated, quoted)
and `HOSTNAME`. The dracut hook's `platformd_static_cidr` (`pkg/iso/dracut_network.go`)
joins address and prefix exactly once, taking the prefix from `IPV4_PREFIX`,
then from any suffix on `IPV4_ADDRESS`, then from `IPV4_NETMASK`, then `/24`;
a malformed value falls through to the next source, so an older
`network.conf` that carried `IPV4_ADDRESS=a.b.c.d/24` still applies correctly.
The initramfs brings the address up as a serial-console diagnostic and to set
the hostname the IAK/IDevID certificates are named after; nothing in
`platform-initrd` needs the network, and ACME enrollment runs after
`switch_root` in the firstboot service.

Inside the container while it is mounted at `/mnt/installer`:
`luks-key.bin` (the only path `KeyfileStrategy` looks at),
`recovery-key.txt`, `etc/trusted-platform/config.yaml`.

Runtime files: `/run/platform-initrd-boot.log` (the boot breadcrumb trail),
`/run/platform/firstboot-handoff/recovery.key` (tmpfs, 0600, single-consumer),
`/run/initrd-install` and `/run/initrd-recovery` (mode markers read by
`DetectMode`).

**Compatibility rule.** The seal filenames and the keyslot indices are the
compatibility contract between an installed node and a future
`platform-initrd`. Renaming a seal file or moving a keyslot is a breaking change
to every already-installed machine and needs a migration path in the same PR.

## 9. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/installer/*_test.go` | Config validation and merge, profiles, Secure Boot URI validation, disk plumbing, UKI rebuild, FIDO2 detection, TPM clear paths |
| Unit | `pkg/initrd/*_test.go` | Strategy chain ordering, each strategy's `CanUnlock`, config merge, TPM detection, partitioning, multidrive |
| Unit | `pkg/iso/*_test.go` | Config defaults, customise steps, extract, prefetch, module injection, profile network generation |
| Unit | `pkg/qemu/*_test.go` | Argument construction, Secure Boot enrolment, monitor, snapshot, migration |
| Integration | `test/integration/ipxe/` and the `platformctl iso test` verbs | Real QEMU + real swtpm + real OVMF |

**Seams for fault injection**, all package-level `var`s or interfaces so a test
can substitute them without touching the host:

- `installer.tpmDeviceCandidates` — the `/dev/tpmrm0`, `/dev/tpm0` list.
- `installer.tpmModprobe` — the modprobe shell-out.
- `installer.tpmDeviceWaitTimeout` — the post-modprobe poll bound.
- `installer.remoteSignerResolver` via `WithRemoteSignContext` / `WithRemoteSigner`.
- `installer.UKIBuilder` via `WithUKIBuilder`; the authenticode signer via
  `WithAuthenticodeSigner`; every path via `WithESPUKIPath`, `WithModulesDir`,
  `WithBootDir`, `WithKernelCmdlinePath`.
- `initrd.Platform` — TPM, LUKS and FIDO2 are all interfaces.
- `PasswordStrategy.reader` is created lazily so constructing the chain never
  blocks on stdin.

**Parity gap.** `conventions/feature-docs.md` §4 requires every `cli.md` verb to
have a matching `CommandDefinition` in the integration parity suite. **No
`CommandDefinition` type exists in this repository** (grepped repo-wide,
2026-08-18), so the requirement is unmet repo-wide, not only here.

## 10. Corrections against the pre-convention documents

The code wins. Each row is a defect in the older file, recorded rather than
silently fixed, because those files are still linked from elsewhere.

| Claim | Where | Reality in code |
|---|---|---|
| `pkg/initrd/strategy_firstboot_seal.go` implements a "Firstboot-Seal" strategy | UNLOCK_STRATEGIES.md, README.md, initrd-architecture.md, and a stale comment in `pkg/installer/installer.go` | **No such file.** `FirstbootSealStrategy` lives in `pkg/firstboot/strategy.go`. |
| Installer container password is `installer` | SECURITY_MODEL.md | `installer.InstallerPassword` = `"forensic-protection-only"`. factory-reset.md is right. |
| Seal files are `seal.pub` / `seal.priv` | SECURITY_MODEL.md, UNLOCK_STRATEGIES.md | `seal-platform.pub` / `seal-platform.priv`. |
| FIDO2 strategy priority is 4 | UNLOCK_STRATEGIES.md | `3` (`strategy_fido2.go`). |
| The strategy set is Firstboot / TPM-PCR / TPM-Upgrade / FIDO2 / Password | UNLOCK_STRATEGIES.md | `Keyfile` (80) and `TPMNoPCR` (5) also exist; `Keyfile` is the strategy that actually carries the first boot inside `pkg/initrd`. |
| "Write plain key to EFI partition" during install | README.md §System Overview | Superseded. The key is only ever inside `installer.luks`; the same README says so five sections later. |
| Platform SRK policy is "PCR + PIN"; there are "PIN seals" | README.md, initrd-architecture.md | No PIN seal path exists in `pkg/initrd`. SECURITY_MODEL.md's "PCR policy" description is the accurate one. |
| `pkg/luks`, `pkg/fido2`, `pkg/initrd/strategies/` | initrd-architecture.md | The real paths are `pkg/storage/luks`, the `go-quicbaas/sdk/go/xkms/fido2` re-export, and `pkg/initrd/strategy_*.go`. `initrd-architecture.md` is an **aspirational design note that predates the implementation** — read it for intent, never for identifiers. |
| `--debug-sink` is an `iso create` CLI flag | (former) doc comment on `iso.PlatformConfig.DebugSink` | **The flag does not exist.** `DebugSink` is settable only through the ISO build config; the doc comment now says so. |

**Two things worth raising with the owner rather than documenting as settled:**

1. `pkg/iso/customize.go` unconditionally sets `platform_debug=1` on every
   ISO's kernel command line, so a published ISO ships with debug mode on.
   `platform_debug_sink=` is baked only when `Platform.DebugSink` is set;
   otherwise the install script derives the sink from the DHCP server. (The
   hard-coded fallback address it used to bake was removed in v0.2.0-alpha.)
2. `initrd.LoadConfig` / `SaveConfig` are stubs that neither read nor write.
   They are exported and look functional.

## 11. Observability

- **`/run/platform-initrd-boot.log`** is the boot breadcrumb file. `runBoot`
  writes numbered steps (`step01` … `step05`, `step04a`, `step04b`) to both
  stderr and this tmpfs file, so a pre-pivot hang can be located exactly. It is
  the first thing to read after a failed unlock.
- **Kernel console → serial.** `pkg/installer/installer.go` puts
  `earlyprintk=efi,keep`, `earlycon=…` and `console=tty0 console=ttyS0,…
  console=ttyS1,…` on the cmdline, so everything dracut and `platform-initrd`
  write to fd 1/2 reaches the BMC serial console. **Do not add a userspace
  tee** — see [architecture.md](architecture.md) §3.
- **Audit log.** `initrd.Config.EnableAuditLog` / `AuditLogPath` and the
  `AuditLog` / `UnlockAttempt` types record per-strategy outcome and duration.
  `pkg/boot/commands` sets the path to `/var/log/platformd/audit.log`;
  `initrd.DefaultConfig` uses `/var/log/initrd-unlock.log`.
- **Install log.** The autoinstall script uploads `/tmp/install.log` on every
  exit path to the forensic sink named by `platform_debug_sink=` on the kernel
  command line; the receiving end is the iPXE HTTP server's
  `PUT /installs/{hostname}/{filename}` ([`docs/ipxe/api.md`](../ipxe/api.md)).
- **Never log**: the LUKS key, the recovery passphrase, `--password`,
  `--root-password`, `--eab-hmac`, or the contents of `installer.luks`. The
  installer logs the first 8 bytes of a SHA-256 *of* the LUKS key as a
  correlation aid; that is the only key-derived value that may appear.

## 12. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [factory-reset.md](factory-reset.md) — `TPM2_Clear` and `recovery-key-strategy`
- [`docs/ipxe/`](../ipxe/) — network boot · [`docs/provisioning/`](../provisioning/) — device lifecycle
- [`docs/daemon/api.md`](../daemon/api.md) — the platform transport model

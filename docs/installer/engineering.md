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
| `diskless.go`, `nbd_target.go` | `checkBootModel`, the diskless root parameters; the `diskless-nbd` target (`useNBDTarget`, `checkNBDAttached`, `nbdCmdlineParams`, `espFstabSource`) |
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
| `OSInstaller` | `NewOSInstaller(logger, *OSConfig)` | `InstallBase`, `ConfigureSystem`, `ConfigureNetwork(ctx, root, *NetworkConfig, *netplan.Plan)`, `InstallKernel`, `SetRootPassword`, `EnableServices`, `InstallPackages`, `ExecutePostInstall`, `Name` |
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

Network (host addressing by role, §7): `NetworkConfig.Validate(*netplan.Plan)`,
`Config.Plan`, `HostRole` (`HostRoleGateway`, `HostRoleControlPlane`,
`HostRoleCompute`), `PlatformVRFConfig` (`EffectiveName`, `EffectiveTable`),
`DefaultPlatformVRFName`, `DefaultPlatformVRFTable`, `PlatformVRFDummy`,
`BondVLANConfig.Zone`; typed errors `ErrInvalidHostRole`,
`ErrForwardingNotAllowed`, `ErrNetworkPlanRequired`, `ErrAddressNotPermitted`,
`ErrDHCPNotPermitted`, `ErrFabricAddressRequired`, `ErrBondZoneVLAN`,
`ErrInvalidPlatformVRF`. `SubnetConfig`, `SubnetScope`, `SubnetRole`,
`DHCPScopeConfig` and the `NetworkConfig` subnet helpers are gone: numbering
comes from the plan only.

dnsmasq (§7): `BuildDNSMasqConf(*DNSMasqConfig) string` renders the
`/etc/dnsmasq.conf` the installer writes; it is exported for the installer
integration suite (§9).

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
    `ErrDiskRelease`. A LUKS mapping nothing has open
    (`luks2.ErrVolumeNotUnlocked`) is already released, not a failure. The install error is what `Install` returns; the
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
20. **A successful install closes the root LUKS mapping, retrying only while
    it is busy.** `closeInstalledLUKS` (`pkg/installer/release.go`) calls
    `luks2.Lock` up to three times. go-luks2 v0.2.0's `Lock` retries a busy
    target for about 3s itself before it returns `luks2.ErrMappingBusy`, so
    only that error earns another attempt, after a 1s and then a 2s backoff
    that a cancelled install interrupts. A name nothing has open
    (`luks2.ErrVolumeNotUnlocked`) is closed. Any other failure, or a mapping
    still busy after the last attempt, falls back to `devmapper.Remove`; a
    failure there is logged as data that may not be persisted and does not
    fail the install.

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

**`TPM-Upgrade` has a reader and no production writer.** It is registered by
default (`pkg/initrd/initrd.go:188-189`) and runs every boot: `CanUnlock`
mounts the ESP, finds no `tpm2/seal-upgrade.pub` / `.priv`, logs
*"TPM-Upgrade: No upgrade seal files found"* and declines
(`pkg/initrd/strategy_tpm_upgrade.go:108-118`). `Install` creates nothing
(`strategy_tpm_upgrade.go:287`), and `CreateUpgradeSeal`
(`strategy_tpm_upgrade.go:304`) is called only from its test. The firstboot
writer, `writeUpgradeSealedObjects` (`pkg/firstboot/executor.go:763-774`), is
reached only from `Executor.Run` (`executor.go:357`), which nothing calls:
`platformctl firstboot` builds an executor
(`pkg/cli/commands/firstboot/firstboot.go:156`) but unlocks through
`FirstbootSealStrategy` (`firstboot.go:171-189`), whose seal path writes the
platform seal only and deletes any upgrade seal
(`pkg/firstboot/strategy.go:1361`). Neither the kernel-update hook
(`pkg/installer/kernel_hook.go`, `uki_rebuild.go`) nor the
`tpm-firstboot-seal` OpenRC service re-seals: the service tests for
`seal-upgrade.*` (`pkg/installer/installer.go:3259`) that never exist, and the
`platformctl firstboot` it runs (`installer.go:3346`) declines once
`seal-platform.pub` exists (`pkg/firstboot/strategy.go:131-161`). So a kernel
or firmware change that moves the bound PCRs goes: `TPM-PCR` fails under the
platform policy (`strategy_tpm_pcr.go:239-246`), `TPM-Upgrade` declines,
`FIDO2` runs only if registered, `Keyfile` finds no `installer.luks`, and
`Password` prompts. After the passphrase, platformd detects the Platform SRK
policy drift (`pkg/app/app.go:1927-1934`) beside a present seal and returns
`ErrTPMSealPolicyDrift` (`pkg/app/tpm_seal_guard.go:214`,
`pkg/app/app.go:1970-1972`). The planned upgrade path is
[architecture.md](architecture.md) trust boundary 4.

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

`pkg/cli/commands/iso` errors are typed per failure: `ErrInvalidArchitecture`, `ErrInvalidPlatformType`, `ErrISONotFound`,
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
| `ConfigureNetwork` on a platform host | **Install aborts** when `network.role` is set: a platform host must not boot with its forwarding, host firewall or zone addressing in an unknown state. A host with no role keeps the old behaviour (network failure logged, install continues). |

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
| `disk.encryption.mapped-name` | string | `cryptroot` — `Validate` checks it with `luks2.ValidateMappingName` (`[A-Za-z0-9]` first, then `[A-Za-z0-9_.+-]`, at most 127 bytes) and refuses a bad name as `ErrorTypeInvalidConfig` before the disk is formatted, since `Unlock` would refuse it only after the wipe |
| `disk.encryption.password` / `passphrase` | string, `secret:"true"` | — |
| `disk.encryption.tpm.enabled` | bool | — |
| `disk.encryption.tpm.handle` | uint32 | `DefaultLUKSTPMHandle` = `0x81000001` (SSRK) |
| `disk.encryption.tpm.seal-pcrs` | []uint | falls back to top-level `pcrs`; recorded in `pcr-banks` only (`pkg/firstboot/strategy.go:1335`) and never applied to the seal, which uses the platform policy (`strategy.go:1302`) |
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
| `os.tpm-auto-upgrade-seal` | bool | `true` — written to `/etc/alpine-tpm.conf` as `TPM_AUTO_UPGRADE_SEAL` (`pkg/installer/alpine.go:601`), which nothing reads; no upgrade seal is created either way (§5) |
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

### Host addressing by role (`network.role`)

The reference network (`docs/architecture/reference-network.md`, handbook
`infra/network/docs/15`) gives each host an address only on the zones it uses,
forbids forwarding on everything but a gateway, and puts the host's one
platform-VRF address in a Linux VRF. `NetworkConfig.Validate(plan)` enforces
it; `plan` is the `netplan.Plan` of the node's environment, derived from the
platform config's `sdn.environment` and handed to the installer as
`Config.Plan` by `App.GetInstallerConfig` (`yaml:"-"`, never serialized).

| Key | Type | Meaning |
|---|---|---|
| `network.role` | `""` \| `gateway` \| `control-plane` \| `compute` | Empty: the host is not on a platform network (lab, image build) and none of the rules below apply. |
| `network.ip-forward` | bool | Forwarding on the installed host. Only `gateway` may set it (`ErrForwardingNotAllowed`). |
| `network.platform-vrf.address` | IPv4 `/32` | The host's platform-VRF address; must lie in the environment's platform-hosts range (`<base>.E.144.0/20`). |
| `network.platform-vrf.name` / `.table` | string / int | VRF device and routing table; default `vrf-platform` / `1000`. |
| `network.vlans[].zone` | zone name | A VLAN interface on a zone: the ID comes from the plan (`id` must be 0; both set is `ErrVLANZone`), the address must be inside the zone's subnet, and the role rules apply. A literal `id` without `zone` is allowed only on a host with no role (`ErrLiteralVLANWithRole`). Generation writes `vlan-raw-device` and `vlan-id`. |
| `network.bonds[].vlans[].zone` | zone name | The zone a bond address lives on. The VLAN ID comes from the plan; the address must be inside the zone's subnet (`ErrBondZoneVLAN`). Replaces the deleted `network.subnets` / `vlans[].subnet` indirection. |

The role → zones table (`roleZones`, `pkg/installer/network_role.go`):

| Role | Zones a host address may lie in |
|---|---|
| `control-plane` | fabric, hypervisor, storage, control-plane (control-plane nodes are hypervisors too) |
| `compute` | fabric, hypervisor, storage |
| `gateway` | exempt: gateways route and NAT by role |

For `control-plane` and `compute`, every static address — interfaces (IPv4 and
IPv6), bridges, bonds, VLAN interfaces and bond zone VLANs — must lie in one of
the role's zones; an address in another zone or in no zone is refused
(`ErrAddressNotPermitted`: no multi-homing). A fabric address, the VTEP, is
required (`ErrFabricAddressRequired`). DHCP on any interface, bridge, bond or
VLAN is refused (`ErrDHCPNotPermitted`): the address would land on
provisioning, the native VLAN. A role, a platform VRF or a bond zone VLAN with
no plan is `ErrNetworkPlanRequired`.

platformd runs the same check when it loads its config (`App.Init` →
`validateHostNetwork`), so a bad host network fails at load as
`ErrHostNetworkValidation`, not only at install.

Realisation (`alpine_hostnet.go`), all under the installed root:

| File | Written when | Content |
|---|---|---|
| `/etc/sysctl.d/60-platform-forwarding.conf` | any role | `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` = `1` for a gateway, `0` otherwise |
| `/etc/nftables.d/60-platform-hostfw.nft` | `control-plane`, `compute` | `table inet platform_hostfw` with a `forward` hook chain, `policy drop`: the host never forwards between its interfaces. The `nftables` package is installed and `/etc/runlevels/default/nftables` linked. A gateway gets no file: gatewayd's host filter owns it. |
| `/etc/network/interfaces` | no `network.interfaces` | The default `auto eth0` / `inet dhcp` stanza is written **only for a host with no role**: on a control-plane or compute node it would put a DHCP address on provisioning, and a gateway's eth0 is a WAN uplink gatewayd owns. |
| `/etc/network/interfaces` | `platform-vrf` set | `iface vrf-platform` with `vrf-table 1000`, and dummy `pvrf0` (`link-type dummy`, `vrf-member vrf-platform`) holding the `/32`. The platform overlay attaches to this VRF when the overlay service lands (#709). |
| `/etc/network/interfaces` | Linux bond with zone VLANs | `bond<N>.<VLAN>` stanzas with the plan's VLAN, and no per-zone `gateway` line: a host has one default route, not one per zone. OVS bonds still emit no Linux VLAN stanzas. |

### dnsmasq (`network.dnsmasq`)

`configureDNS` (alpine.go) takes one of three paths, in precedence order: the
dedicated `network.dnsmasq` block (`enabled: true`), the legacy
`network.dns.upstream-dns` string, else a plain `resolv.conf`. Both dnsmasq
paths install the package inside the chroot, enable the service in the
default runlevel, and point `resolv.conf` at `nameserver 127.0.0.1`.

`BuildDNSMasqConf` renders `/etc/dnsmasq.conf`: `no-resolv`,
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
| `/etc/init.d/gatewayd` | firstboot (`installGatewaydService`) | OpenRC service, default runlevel, after `platformd`; `start_pre` runs `modprobe jool` only when the config has `gateway.nat64.enabled: true` |
| apk `jool-modules-lts`, `jool-tools`, `jool-tools-openrc` | installer (`InstallPackages`, from `os.packages`: the gateway templates list them, and a gateway-role medium on the stock kernel adds them to its baked `configs/installer.yaml`) | the NAT64 translator gatewayd's `nat64:` section drives |
| `/etc/gatewayd/config.yaml` (0600) | firstboot (`renderGatewaydConfig`) | the `gateway:`, `proxy:`, `trust:`, `sdn:`, `control-plane:` sections of the platform config |
| `/etc/gatewayd/{client.pem,client-key.pem,cp-ca.pem}` | **operator** (not produced by the repo yet — #149, #431) | control-plane reporter mTLS identity; absent ⇒ reporter rendered disabled |

The Jool package list is `tpconfig.GatewaydPackages` (`pkg/config/gateway_role.go`,
#603); the shipped gateway templates carry it and a gateway-role ISO
prefetches it beside the stock `linux-lts` kernel (not in a FIPS, kernel-less
or non-lts ISO, where `jool-modules-lts` would pull in a second kernel).
The prefetch and the install take the list from one function,
`PreFetchConfig.installedPackages` (`pkg/iso/prefetch.go`), under that one
kernel condition: whenever the medium prefetches the Jool packages, the
`configs/installer.yaml` it bakes lists them in `os.packages`
(`applyInstallerOverrides`, `pkg/iso/customize.go`), once, after the
template's own entries. A gateway template on any other kernel still lists
them itself; the medium adds nothing then.
`jool-modules-lts` is built for one exact `linux-lts` release: upgrade the two
together. A kernel that outruns the module leaves `jool` unloadable, the init
script warns, and gatewayd refuses its `nat64:` section
(`ErrNAT64ModuleUnavailable`).

Nodes installed from media built with `--platform-apk-dir` carry the overlay's
IPsec packages (#709). `EnableServices` adds every service of its list whose
`/etc/init.d` script is installed (`openRCServices`, `pkg/installer/alpine.go`),
so on these nodes `xkms-p11-kit` and `charon` join the default runlevel and the
VICI socket exists after every boot. Both generated platformd scripts start
`after charon`, and platformd runs as root, the socket's default owner
([sdn engineering](../sdn/engineering.md) §9.6).

`os.services` (`OSConfig.Services`) names more services for the default
runlevel. They are appended after that list, under the same init-script rule.
The factory-image target sets it from `InstallerOverrides.ExtraServices`; the
Raspberry Pi target sets `pcscd`
([factory-image engineering](../factory-image/engineering.md)).

A medium that bundles a platform config (ISO, factory image, netboot set)
installs from the copy it bakes as `configs/installer.yaml`, through
`os.packages` and `os.services`. Staging appends to those lists what the medium carries for the
installed system: `PreFetchConfig.installedPackages` (`pkg/iso/prefetch.go`)
— the IPsec packages of `--platform-apk-dir`, a gateway's Jool packages and
`InstallerOverrides.ExtraPackages` — and `InstallerOverrides.ExtraServices`.
The template's own entries come first and keep their order, and nothing is
listed twice (`applyInstallerOverrides`, `pkg/iso/customize.go`). The
prefetch reads the same function, so what is fetched is what is installed.
A dynamic-config medium bakes no platform config: it installs the lists of
the config it fetches, and nothing is appended to them.

ESP layout, with the constants that name each file (`pkg/firstboot/types.go`,
`pkg/firstboot/strategy.go`):

| Path | Constant | Lifetime |
|---|---|---|
| `/boot/efi/EFI/BOOT/BOOTX64.EFI` (`BOOTAA64.EFI` on aarch64) | `uki.BootFileName(arch)` | permanent (the UKI) |
| `/boot/efi/tpm2/` | `EFITPMDir` | permanent |
| `/boot/efi/tpm2/installer.luks` | `EFIInstallerFile`, `strategyInstallerContainerFile` | first boot, then until the **first `TPM-PCR` unlock**, which securely wipes it |
| `/boot/efi/tpm2/seal-platform.pub` | `EFISealPlatformPub`, `strategySealPub` | permanent |
| `/boot/efi/tpm2/seal-platform.priv` | `EFISealPlatformPriv`, `strategySealPriv` | permanent |
| `/boot/efi/tpm2/seal-upgrade.pub` / `.priv` | `EFISealUpgradePub` / `Priv` | never written in production (§5); `TPM-Upgrade` would keep them after use (`pkg/initrd/strategy_tpm_upgrade.go:236-252`), and the first-boot seal and a `TPM-PCR` unlock delete them (`pkg/firstboot/strategy.go:1361`, `pkg/initrd/strategy_tpm_pcr.go:227`) |
| `/boot/efi/tpm2/pcr-banks` | `EFIPCRBanks` | written minimally at install, overwritten authoritatively by firstboot |
| `/boot/efi/tpm2/pcr-seal-values.txt` | `EFIPCRValues` | permanent |
| `/boot/efi/tpm2/swtpm-state` | `EFISwtpmStateDir` | swtpm deployments only |
| `/boot/efi/tpm2/ppi-clear-attempted` | — | loop guard for `force-clear-via-ppi` |
| `/boot/efi/tpm2/network.conf` | — | written by `writeFirstbootNetworkConfig` at install; parsed (never sourced) by the dracut hook on first boot and by the firstboot service |

**`network.conf` contract.** A `KEY=value` file the ESP holds, which anyone with
the disk can edit, so it is **parsed, never sourced**: `platformd_load_network_conf`
(`pkg/disklessroot/network_conf_shell.go`, shared by the dracut hook and the
firstboot service) splits each line at the first `=`, accepts only the keys
below, strips one pair of surrounding double quotes, and accepts a value only
if it is made of letters, digits and `. _ : / -` and spaces. Any other line (a
command, `$(...)`, a `;`, a backtick, `${...}`, an unknown key) is reported on
stderr, skipped and never executed or applied; the lines that pass still load.
Keys: `INTERFACE`, `TYPE` (`static` or `dhcp`), and for static
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

`buildUKI` omits dracut's `network` and `network-legacy` modules, so the
platformd module carries the network itself: `platformd_install_network`
(`pkg/iso/dracut_network.go`, run from `module-setup.sh`'s `install()`)
installs busybox `udhcpc`, the `default.script` that applies its lease
(`/usr/share/udhcpc/default.script`, with `/etc/udhcpc/udhcpc.conf`, both from
the busybox package of the root dracut runs in), and `ip`, `cut`, `chmod` and
`mv`, which that script runs; `ping` and `hostname` are optional. `udhcpc`
without its script obtains a lease and never puts the address or route on the
interface. A diskless node fetches its root over that network, and a
`diskless-nbd` node reaches its export over it, so when the embedded command
line selects either model (`platformd_boot_model`, or `platformd_nbd_node` for
`diskless-nbd`) a missing piece fails the dracut run, and the install, rather
than producing a node that cannot boot; a disk install only warns.

That initramfs is on the boot path of every model: `buildUKI` (`pkg/installer/installer.go`)
runs dracut, injects `platform-initrd`, and makes the result the UKI's
`.initrd`. Its `--omit` list stays `crypt network network-legacy nbd nfs` for
every boot model. dracut's `nbd` module runs `nbd-client` over dracut's own
network stack. A `diskless-nbd` node's `platform-initrd` attaches the export
itself (planned, [below](#attaching-before-the-install)), over the network the
platformd module brings up. What that node does need is the kernel's NBD block
driver. `dracutDrivers` (`pkg/installer/arch.go`) adds `nbd` to the
architecture's `--add-drivers` set for `diskless-nbd` only (`bootModelDrivers`),
and the other models' sets are unchanged (`TestDracutDriversByBootModel`).

A diskless node's root is shared by every node of the media set, so its own
`/etc/hostname`, `/etc/network/interfaces` and `/etc/resolv.conf` would
override the per-node `network.conf`. After mounting the overlay, and before
`switch_root`, `platformd_seed_node_settings` writes the node's hostname,
interface (static or DHCP) and resolver into the tmpfs upper layer, replacing
any symlink; the shared root is never written.

**`diskless-nbd` node side — install and boot of the installed UKI built, attach Planned (#689).** The NBD export server is built
(`pkg/bootstrap/nbd`, [bootstrap engineering](../bootstrap/engineering.md#nbd-export-server-pkgbootstrapnbd)).
So are four pieces of the node half: the `platform_nbd_server` reader
`nbd.ServerFromCmdline`
([kernel-cmdline §4](../reference/kernel-cmdline.md#nbd-root-parameter)), the
client configuration builder `nbd.NewClientConfig`, the negotiation
`nbd.Attach` (below), which meets the second to fourth points of this
contract, and the installer target `nbd` (the fifth point,
[below](#the-installer-target-nbd)). After the install, the boot server hands
the node the UKI from its export instead of the installer
([bootstrap engineering](../bootstrap/engineering.md#the-diskless-nbd-runtime-path)).
`platform-initrd` does not attach an export yet, so only the installer calls
`nbd.ServerFromCmdline`, and nothing calls the other two. The node half below is the
contract every slice meets:

- The boot server's NBD address comes from the **signed** UKI `.cmdline`,
  under the same rule as the diskless root parameters: nothing on the live
  command line can name the root. Built: the installer copies no live-line
  parameter into the UKI but the debug sink (`hostUKICmdlineParams`), so a
  live `platform_nbd_server` never reaches it.
- `platform-initrd` sends the client flag `NBD_FLAG_C_FIXED_NEWSTYLE`. Its
  first option is `NBD_OPT_STARTTLS`, and it requires TLS 1.3. It presents
  the IDevID certificate, whose key stays in the TPM. It verifies the server
  certificate against the platform CA carried in the image.
- It then sends `NBD_OPT_GO` with an empty export name, or its own IDevID
  identity.
- A refusal is final. These include `NBD_REP_ERR_TLS_REQD`,
  `NBD_REP_ERR_POLICY`, `NBD_REP_ERR_UNKNOWN`, a failed handshake, or a
  closed connection. The node never retries in plaintext and never asks for
  another export. The boot fails closed into the recovery path.
- The installer target `nbd` runs Phase A against the attached export instead
  of a local disk: it LUKS2-formats the export and installs onto it. The key
  is sealed to the node's TPM, as on a disk install. Built.

```go
func Attach(ctx context.Context, conn net.Conn, cfg nbd.ClientConfig) (*nbd.Export, error)
```

`ClientConfig` carries `Certificate` (the IDevID; its `PrivateKey` is the TPM
signer), `RootCAs` (the platform CA), `ServerName` and `HandshakeTimeout`
(default 30 s; a context deadline that comes sooner wins). A missing field is
`nbd.ErrInvalidConfig`, returned before anything is written. `Attach` sends
`NBD_FLAG_C_FIXED_NEWSTYLE` (and `NO_ZEROES` when the server offers it), then
`NBD_OPT_STARTTLS`, then a TLS 1.3-only handshake, then `NBD_OPT_GO` for the
empty export name, asking for `NBD_INFO_BLOCK_SIZE`. It returns `Export`: the
TLS connection, now in transmission, with the size, the transmission flags and
the block-size constraints. It owns `conn` and closes it on every error:

| Outcome | Typed error |
|---|---|
| any `NBD_REP_ERR_*` reply to `STARTTLS` or `GO` | `nbd.ErrServerRefused{Option, Reply}` |
| handshake failure, including a TLS alert the server sends after a TLS 1.3 handshake has completed (client certificate rejected) | `nbd.ErrTLSHandshake` |
| not fixed newstyle, bad magic, a reply to another option, an oversized or malformed reply, `GO` acknowledged without `NBD_INFO_EXPORT`, a closed connection, the timeout, a cancelled context | `nbd.ErrProtocol` |

```go
func NewClientConfig(ctx context.Context, server nbd.ServerAddr, anchor *trust.Anchor, idevid tls.Certificate) (nbd.ClientConfig, error)
```

`NewClientConfig` builds `Attach`'s configuration from the signed parameters.
`server` is the address `ServerFromCmdline` read; its host becomes
`ServerName`, so the boot server's certificate must carry it. `RootCAs` is the
platform anchor's CA pool. `HandshakeTimeout` is the default. `idevid` is a
parameter: it is the certificate the node's enrollment put in its TPM, and the
node enrols before its first attach (#883 Q2,
[below](#enrolling-before-the-attach)). `anchor` is a parameter too: no early-boot path reads a
CA bundle today. The image's bundle is on the root filesystem, which for this
model is the export itself. Nothing calls `NewClientConfig` yet.

| Input | Typed error |
|---|---|
| an address with no valid host or a zero port | `nbd.ErrCmdline` |
| no anchor | `nbd.ErrInvalidConfig` (`RootCAs`) |
| an anchor whose bundle is unreadable or holds no CA | `nbd.ErrTrustAnchor`, wrapping `trust.ErrAnchorUnavailable` or `trust.ErrAnchorEmpty` |
| an IDevID with no certificate or no key | `nbd.ErrInvalidConfig` (`Certificate`), from `ClientConfig.Validate` |

### The installer target `nbd`

`checkBootModel` (`pkg/installer/diskless.go`) is `Install`'s step 0. It
returns the model the live command line selects: `""` (disk), `diskless`, or
`diskless-nbd`, which it accepts only with exactly one well-formed
`platform_nbd_server` (`nbd.ServerFromCmdline`). Every other value is
`ErrorTypeBootModel`. For `diskless-nbd`, `Install` then enrols the node
([below](#enrolling-before-the-attach)) and, once it holds the IDevID, calls
`useNBDTarget` (`pkg/installer/nbd_target.go`). Both run before step 1.
`useNBDTarget` refuses with `ErrorTypeNBDTarget` wrapping
`*NBDTargetError{Device, Reason}`:

| Condition | `Reason` |
|---|---|
| no `disk.encryption` (the export's root is always LUKS2) | `a diskless-nbd root must be LUKS2-encrypted; …` |
| no `/sys/block/nbd0` (module not loaded) | `no such block device (…)` |
| no `/sys/block/nbd0/pid` (no client holds an export) | `not attached to an NBD export (no pid)` |
| `size` missing or not a decimal sector count | `size unreadable: …` / `size is not a number: …` |
| `size` is 0 | `attached export has size 0` |

Otherwise it sets `disk.device` to `/dev/nbd0` and `disk.partition-table` to
`gpt`, whatever the profile chose for a local disk (a Pi profile's is `mbr`, for
its firmware): the boot server reads the export's partition table itself
([below](#the-nbd-metadata-area)) and reads only GPT. The disk manager shares that
config, so the unchanged `setupDisk` partitions, LUKS2-formats, LVMs and
mounts the export exactly as it would a disk; nothing is copied per model. The
installer reads the attachment and never makes it: the export must be attached
before `platformctl install system` runs
([below](#attaching-before-the-install)).

Step 1, the TPM clear, does not run for this model (`nbdTargetSkips`,
`pkg/installer/boot_firmware.go`). The node attached its export with the IDevID
whose key the TPM holds, and a TPM2_Clear evicts it with every other owner and
endorsement object, so the node could never attach its root again. A
re-install therefore keeps whatever else the TPM holds.

The UKI's root parameters come from `nbdCmdlineParams`:
`platform_boot_model=diskless-nbd` and the signed `platform_nbd_server`, and
nothing else. `ukiRootCmdlineParams` returns them as they are, so the UKI
carries no `root=`, `rd.luks.*` or `rd.lvm.*`; the only live-line parameter
that reaches it is the debug sink (`hostUKICmdlineParams`).

### Enrolling before the attach

The installer enrols, then attaches (#883 Q2). The export admits a node only
by its IDevID, so a `diskless-nbd` node holds one before its first attach.
Every node except the first enrols the same way, on every architecture and
boot model: ACME `enroll-01` or `endorse-01`, whichever
`acme.client.enrollment.challenge` selects, through the go-quicbaas SDK's
`sdk/go/xkms/acme` client. That is the client `platformd` runs on a disk
node's first boot (`App.CompletePlatformIdentity`, `pkg/app/app.go`). There is
no second enrollment path, and the installer adds no enrollment code: it calls
the client through one seam (`pkg/installer/nbd_enrol.go`):

```go
type IdentityEnroller interface {
    EnrollIdentity(ctx context.Context) (*x509.Certificate, error)
}

func WithIdentityEnroller(e IdentityEnroller) InstallerOption
```

`enrollNBDIdentity` calls it once, before the TPM clear, before
`useNBDTarget` reads the attachment and before any disk is touched. A refusal
is `ErrorTypeEnrollment` wrapping `*EnrollmentError{Reason, Err}`, and the
install stops with no disk changed:

| Condition | `Reason` |
|---|---|
| no enroller was supplied | `no enrollment client is configured` |
| `EnrollIdentity` returned an error (kept as `Err`) | `enrollment failed` |
| `EnrollIdentity` returned no certificate | `enrollment returned no IDevID certificate` |

A refusal of the export after a successful enrollment stays
`ErrorTypeNBDTarget`, so the two failures are told apart.

The live environment does not supply an enroller yet (**Planned**), so a
`diskless-nbd` install is refused at this step. The enrollment client runs
inside `platformd`'s first-boot provisioning (`InitTPM`,
`ProvisionPlatform`, `CompletePlatformIdentity`). That provisioning needs the
TPM's PINs and writes the platform datastore, and on a `diskless-nbd` node
both belong on the export, which the node can attach only after it enrols.
Where the live environment keeps them until then is not decided.

### Attaching before the install

How the live environment reaches the installer on a `diskless-nbd` node:

| Step | Where |
|---|---|
| The media set's installer initramfs | `pkg/diskimage/netboot/build.go` (`installerInitramfs`) makes it from Alpine's with `Customizer.InstallerInitramfs` (`pkg/iso/customize.go`), which adds the autoinstall overlay and patches `init` |
| `init` starts the autoinstall | `patchInitScript`: when `/proc/cmdline` carries `alpine_start=autoinstall`, an inittab (`createAutoinstallOverlay`) runs `/root/run-autoinstall.sh` as `::sysinit:`, which runs `autoinstall.sh` |
| The live command line | the device script's kernel arguments: `alpine_start=autoinstall` from the media set (`pkg/bootstrap/container/mediaset.go`), plus `platform_boot_model=diskless-nbd` and `platform_nbd_server` from `nodeBootArgs` (`pkg/bootstrap/container/server.go`). iPXE passes them to the kernel; nothing signs them |
| The install | `autoinstall.sh` (`buildAutoinstallScript`) runs `platformctl install system --disk "$INSTALL_DISK"` |

On this model `nbd_install_target` (`nbdInstallTargetFunction`) sets
`INSTALL_DISK` to `/dev/nbd0`, and the local-disk scan does not run, so a node
with no local disk does not stop at "No suitable installation disk found". It
matches only the whole word `platform_boot_model=diskless-nbd`; every other
node scans its disks as before. The installer validates the rest of the line
(`checkBootModel`) and checks the attachment (`useNBDTarget`).

The attach itself is **Planned**. It runs in the live environment between
`nbd_install_target` and the install, through the code `platform-initrd` uses
(the media already carries the `platform-initrd` binary,
`CopyPlatformInitrdBinary`), and its failure ends the script through `error`
before `platformctl install system` runs. Until it exists, the installer's own
checks are the refusal: no enrollment is `ErrorTypeEnrollment` and no attached
`nbd0` is `ErrorTypeNBDTarget`, both before the TPM, a partition table or a
key is touched, and the failed install stays in the installer
([autoinstall](autoinstall.md#8-failure-paths)). Two things hold the attach
back, and both hold the `platform-initrd` attach back too:

1. **The handoff to the kernel.** `nbd.Attach` ends with a `crypto/tls`
   connection. The kernel `nbd` driver takes a socket it reads and writes in
   plaintext (`NBD_SET_SOCK`, or netlink `NBD_ATTR_SOCKETS`), and `crypto/tls`
   cannot hand its session keys to kernel TLS.
2. **The IDevID before the first install.** A node attaches only after
   enrollment, with the IDevID the bootstrap CA issued through the SDK (#883).
   The installer enrols first ([above](#enrolling-before-the-attach)), but the
   live environment does not supply its enrollment client yet.

### The command line under Secure Boot

An installed `diskless-nbd` node takes its root from the UKI's `.cmdline`, and
from nothing else:

| Link | Where |
|---|---|
| The UKI is systemd-stub plus `.linux`, `.initrd` and `.cmdline`; Secure Boot signs the whole image, sections included | `pkg/uki` (`builder.go`, `builder_objcopy.go`); the parser refuses a UKI with no `.cmdline` (`parser.go`) |
| The device script boots the installed UKI by URL with **no arguments** | `BootImageURL` (`pkg/ipxe/script_generator.go`), set by `deviceBootInfo` (`pkg/bootstrap/container/server.go`) |
| `platform-initrd` reads `/proc/cmdline`, which under Secure Boot is the signed `.cmdline`: systemd-stub ignores the load options | `pkg/boot/commands/boot.go`; `platform_nbd_server` is read only from it (`pkg/bootstrap/nbd/cmdline.go`) |
| The dracut module reads `root=` from the `/etc/kernel/cmdline` it embeds in the initramfs, not from `/proc/cmdline` | `pkg/iso/customize.go` (the platformd module's `module-setup.sh` and `platformd-root.sh`) |

Who refuses an unsigned command line is the **firmware**, not the server. The
bootstrap server streams the UKI as it is and checks no signature
(`pkg/bootstrap` has none). With Secure Boot on, the firmware refuses a UKI
the db does not sign, and systemd-stub refuses load options, so a changed
`.cmdline` does not boot. A Raspberry Pi always verifies: its U-Boot carries
the preseeded keys ([factory image](../factory-image/architecture.md#3-rejected-alternatives),
[`pxe-client --secure-boot`](../ipxe/cli.md)). On x86 Secure Boot is the
firmware's setting.

Two gaps remain, and neither is closed in code:

1. **Without Secure Boot** systemd-stub takes the load options over `.cmdline`,
   and anyone who can change the device script or the served UKI chooses the
   server and the boot model. Nothing refuses a `diskless-nbd` boot with
   Secure Boot off, and no document requires a check, so none is added here.
   The TLS handshake still authenticates the export server, and the sealed key
   still unseals only under the PCR policy.
2. **The live line is unsigned.** The installer copies `platform_nbd_server`
   from the live command line into the UKI it builds
   (`disklessCmdlineParams`, `pkg/installer/diskless.go`). The signature says
   who built the UKI; it does not prove the address was right. The attach's
   TLS server authentication is what proves that.

### The NBD metadata area

The sealed key blob and the PCR banks live **on the NBD
volume**, not on the node. The area is partition 1 of the export, the same
partition a disk install uses as its ESP, so every reader and writer of those
files works unchanged:

| | |
|---|---|
| Location | `/dev/nbd0p1`: GPT partition 1, from 1 MiB (`diskManager.CreateEFIPartition`, `pkg/installer/disk.go`) |
| Size | `disk.efi-partition-size` MiB, default 538; the LUKS2 root (`/dev/nbd0p2`) takes the rest |
| Format | FAT32 (`vfat`, label `EFI`), the [ESP layout](#8-persistence-and-on-disk-layout) above: the UKI under `EFI/BOOT/`, and `tpm2/pcr-banks`, `tpm2/installer.luks` (first boot), `tpm2/seal-platform.pub` / `.priv`, `tpm2/pcr-seal-values.txt` (no `tpm2/seal-upgrade.*` — nothing writes it, §5) |
| Mounted at | `/mnt/boot/efi` during Phase A; `/boot/efi` on the node, from fstab **by path** (`espFstabSource`), never `LABEL=EFI`, so a stray local partition with that label cannot receive the seal |

Writers: Phase A writes `tpm2/pcr-banks` and `tpm2/installer.luks` under
`/mnt/boot/efi/tpm2` (`prepareLUKSKeyForTPM`, `pkg/installer/installer.go`),
and the first-boot seal writes `seal-platform.*` under `/boot/efi/tpm2`
(`pkg/firstboot/types.go` `EFISealPlatformPub`/`Priv`). Readers: the unlock
strategies find the area with `partition.FindESP(root)`, which takes partition
1 beside the root device first (`/dev/nbd0p2` → `/dev/nbd0p1`) before any
`EFI` label, and read `tpm2/seal-platform.*` and `tpm2/pcr-banks` from it
(`pkg/initrd/strategy_tpm_pcr.go`). The boot server holds the area and the
LUKS2 ciphertext; neither is useful without the node's TPM.

The boot server reads one file from the area: the installed UKI, which it
serves the node at every boot after the install (see
[bootstrap engineering](../bootstrap/engineering.md#the-diskless-nbd-runtime-path)).
`nbd.OpenMetadataFile(volumeDir, identity, name)` (`pkg/bootstrap/nbd/metadata.go`)
reads it from `<volume_dir>/<identity>.img` without mounting or attaching
anything. It finds the GPT header at LBA 1 for 512-, 1024-, 2048- or
4096-byte sectors, checks the header and entry-array CRC32s, takes partition 1
only if it lies inside the volume, checks the FAT32 boot sector, reads the
first FAT whole (16 MiB at most), and follows cluster chains, refusing a free,
reserved or out-of-range cluster, a loop, or a chain shorter than the file.
Names match case-insensitively; long names are used only when their checksum
matches the 8.3 entry.

| Volume | Result |
|---|---|
| no `<identity>.img`, or one with no GPT and no MBR signature (blank, as the NBD server creates it) | `nbd.ErrNotInstalled` — the node has not been installed |
| partitioned, but not a readable area holding `name` | `nbd.ErrMetadataArea{Identity, Reason, Cause}` |
| an identity that is not a valid volume name | `nbd.ErrVolume` wrapping `fs.ErrInvalid` |

An install that stopped after partitioning leaves a volume that is
`ErrMetadataArea`. The boot server never reinstalls over it, because the
installer would format whatever the export holds. To reinstall, the operator
removes `<volume_dir>/<hostname>.img` while the node is off; the NBD server
creates a blank one at the next attach.

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
| Integration | `test/integration/installer/` (`make integration-test-installer`) | A real dnsmasq on the `BuildDNSMasqConf` output, for the control-plane (loopback upstream) and worker (remote upstream) shapes, forwards a query for a name in the internal zone to a stub upstream; the same config with `local=/<domain>/` added answers NXDOMAIN and never forwards it (the #128 blackhole, #131) |

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

The code wins. Each row is a defect in an older file, recorded rather than
silently fixed. SECURITY_MODEL.md, UNLOCK_STRATEGIES.md, initrd-overview.md,
initrd-architecture.md and README.md have since been deleted
([architecture.md §8](architecture.md#8-related)); their rows stay as the
record of what they claimed.

| Claim | Where | Reality in code |
|---|---|---|
| `pkg/initrd/strategy_firstboot_seal.go` implements a "Firstboot-Seal" strategy | UNLOCK_STRATEGIES.md, README.md, initrd-architecture.md, and a stale comment in `pkg/installer/installer.go` | **No such file.** `FirstbootSealStrategy` lives in `pkg/firstboot/strategy.go`. |
| Installer container password is `installer` | SECURITY_MODEL.md | `installer.InstallerPassword` = `"forensic-protection-only"`. factory-reset.md is right. |
| Seal files are `seal.pub` / `seal.priv` | SECURITY_MODEL.md, UNLOCK_STRATEGIES.md | `seal-platform.pub` / `seal-platform.priv`. |
| FIDO2 strategy priority is 4 | UNLOCK_STRATEGIES.md | `3` (`strategy_fido2.go`). |
| The strategy set is Firstboot / TPM-PCR / TPM-Upgrade / FIDO2 / Password, and `TPM-Upgrade` carries a kernel upgrade across | the pre-convention unlock-strategy notes | `Keyfile` (80) and `TPMNoPCR` (5) also exist; `Keyfile` is the strategy that actually carries the first boot inside `pkg/initrd`. `TPM-Upgrade` has no production writer and declines every boot ([§5](#5-unlock-strategy-table--as-the-code-registers-it)). |
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

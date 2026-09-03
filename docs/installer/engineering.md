# Installer — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/installer/`, `pkg/initrd/`, `pkg/iso/`, `pkg/qemu/`, `cmd/platform-initrd` · Last verified: 2026-08-18
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
embedded `autoinstall.sh`.

`pkg/qemu/` — the test harness: `config.go`, `types.go`, `qemu.go`,
`secureboot.go`, `monitor.go`, `snapshot.go`, `migration.go`, `ovs_network.go`.

`cmd/platform-initrd` is a four-line `main` over `pkg/boot/commands`.

## 2. Exported surface — `pkg/installer`

```go
func NewInstaller(logger *logging.Logger, config *Config, opts ...InstallerOption) (Installer, error)
type InstallerOption func(*installer)
func WithRemoteSignContext(rsc *RemoteSignContext) InstallerOption
```

`Installer` has exactly two methods: `Install(ctx) error` and `Close() error`.
The concrete type is unexported — construct through `NewInstaller`.

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
3. **Ordering inside `Install` is load-bearing.** The FIPS kernel must be
   installed *before* the UKI is built; `platform-initrd` must be in the dracut
   module *before* the UKI is built; the UKI must be signed *before* FIPS
   OpenSSL configuration, because FIPS mode breaks the signing path; Secure
   Boot enforcement must also precede it. Reordering these silently produces an
   unbootable or unsigned node.
4. **Post-install script failure is fatal; almost nothing else is.** Package
   install, network config, UEFI boot entry, Secure Boot enforcement, the
   kernel-update hook, the firstboot service, `prepareLUKSKeyForTPM` and FIDO2
   enrolment all log a warning and continue. `ExecutePostInstall` returns an
   error that aborts the install, because that script provisions operator
   access and a node that installs "successfully" without it is unreachable.
5. **Strategy priority is ascending — lower runs first.**
   `StrategyChain.sort()` orders by `Priority()` ascending and `Execute` takes
   the first strategy whose `CanUnlock` is true and whose `Unlock` succeeds.
   **The doc comment on `KeyfileStrategy.Priority()` says "higher = tried
   first" and is wrong**; 80 is tried *after* TPM-PCR (1), TPM-Upgrade (2) and
   FIDO2 (3), and before Password (100). The effective order is in §5.
6. **`Add` and `RegisterStrategy` ignore nil** so a minimal build can omit a
   strategy without a branch at the call site.
7. **`ExecuteInstall` is fail-fast**, unlike `Execute`: the first strategy whose
   `Install` fails aborts the whole chain.
8. **A bundle of PCR selection has three sources with a fixed precedence** in
   `pkg/boot/commands/boot.go`: the `--pcrs` flag, then
   `/boot/efi/tpm2/pcr-banks`, then `config.yaml` inside the mounted installer
   container. If all three fail the selection is left empty and
   `Config.Validate` rejects it with `ErrInvalidConfig`.
9. **`Config.Validate` (initrd) requires `RootDevice`, `XKMSPath` and a
   non-empty `PCRSelection`.** `DefaultConfig()` deliberately leaves
   `PCRSelection` nil so that an installer config that forgot to set it fails
   loudly rather than sealing against a wrong-but-plausible default.
10. **LUKS keyslots are fixed.** Slot 0 = installer passphrase, slot 1 = TPM
    key, slot 2 = recovery passphrase. `pkg/firstboot/strategy.go` defines
    `luksSlotTPMKey = 1` and `luksSlotRecovery = 2`; code that adds or removes
    slots must use them.
11. **`installer.luks` is wiped only if sealing succeeded.** On a failed seal
    the container is preserved so the boot can be retried — which means a
    half-provisioned node is still holding its LUKS key on the ESP.
12. **PK is written last** during Secure Boot enforcement, and enforcement only
    proceeds if the signed UKI verifies against the db certificate and the
    firmware is in Setup Mode.

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
| `installer.luks` wipe | Skipped when sealing failed, so the retry path survives. Fails **open** on purpose — and that is the residual risk in §6 of [architecture.md](architecture.md). |
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
| `os.architecture` | string | `x86_64` |
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

ESP layout, with the constants that name each file (`pkg/firstboot/types.go`,
`pkg/firstboot/strategy.go`):

| Path | Constant | Lifetime |
|---|---|---|
| `/boot/efi/EFI/BOOT/BOOTX64.EFI` | — | permanent (the UKI) |
| `/boot/efi/tpm2/` | `EFITPMDir` | permanent |
| `/boot/efi/tpm2/installer.luks` | `EFIInstallerFile`, `strategyInstallerContainerFile` | **first boot only**, then securely wiped |
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
| `--debug-sink` is an `iso create` CLI flag | doc comment on `iso.PlatformConfig.DebugSink` | **The flag does not exist** (grepped 2026-08-18). `DebugSink` is settable only through the ISO build config. |

**Two things worth raising with the owner rather than documenting as settled:**

1. `pkg/iso/customize.go` bakes a **hard-coded default forensic-sink address**
   into every ISO's kernel command line (`platform_debug_sink=`) when
   `Platform.DebugSink` is unset, and unconditionally sets `platform_debug=1`.
   A published ISO therefore ships a fixed internal endpoint and debug mode on
   by default. The address is deliberately not reproduced in this document.
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

# Factory Image — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/diskimage/` (`rpi`, `qemuvirt`, `uboot`, `runner`), `pkg/cli/commands/diskimage/`, `pkg/qemu` (aarch64 profile), `pkg/qemu/harness/`, `build/docker/uboot-builder/`, `build/docker/diskimage-builder/`, `test/integration/diskimage/` · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was read out of the named file on 2026-09-20.

---

## 1. Package layout

| File | Holds |
|---|---|
| `pkg/diskimage/target.go` | the `Target` interface, the `targets` dispatch map, `Targets`, `NewTarget` |
| `pkg/diskimage/config.go` | `BuildConfig` and its defaults (`DefaultTarget`, `DefaultSizeMB`, `DefaultContainerRuntime`, `DefaultBuilderImage`, `DefaultBuilderDir`, `DefaultUBootBuilderDir`, `MediaDirName`) |
| `pkg/diskimage/builder.go` | `Create`, `Result`, `Preflight`, the U-Boot lookup and the container invocation |
| `pkg/diskimage/assemble.go` | `Assemble`, `AssembleOptions`, `AssembleResult` — the in-container step |
| `pkg/diskimage/inspect.go` | `Inspect`, `Report`, `Partition`, `ParseMBR` |
| `pkg/diskimage/boot.go` | `Boot`, `BootOptions`, `BootResult`, `DefaultBootWorkDir`, `DefaultBootMemory` — the emulated boot (QEMU virt + swtpm) behind `diskimage test boot` and the integration suite |
| `pkg/diskimage/errors.go` | `UnknownTargetError`, `PreflightError`, `StageError`, `AssembleError`, `HostInstallerMissingError`, `LoopDeviceError`, `InspectError`, `BootError` |
| `pkg/diskimage/rpi/` | `Name`, `KernelPackage`, `DefaultModel`, `Model`, `Models`, `LookupModel`, `New`, `Target`, `ConfigTxt`; `apk.go` (apk extraction); `errors.go` |
| `pkg/diskimage/qemuvirt/` | `Name`, `KernelPackage`, `New`, `Target` |
| `pkg/diskimage/uboot/` | `Board`, `Boards`, `Manifest`, `Artifacts`, `Options`, `CacheKey`, `Build`, `ReadManifest`, `Locate`; `errors.go` |
| `pkg/diskimage/virtkernel/` | `Manifest`, `Artifacts`, `Options`, `CacheKey`, `Build`, `ReadManifest`, `Locate`, `DefaultVersion`/`DefaultTarballSHA256`/`DefaultLocalVersion`/`DefaultFlavor`; `ManifestError`, `InputError`, `BuildError` — the stand-in's kernel builder driver |
| `pkg/diskimage/artifacts/` | `VerifyChecksums`, `FileSHA256`, `AbsPath`, `ExtractTarGz`; `MissingError`, `ChecksumMismatchError`, `ExtractError` — what the U-Boot and kernel outputs share, and gzip-tar extraction (apks, Alpine netboot tarballs) |
| `pkg/diskimage/netboot/` | `Stage`, `StageFromImage` (the Pi TFTP tree); `Build`, `Config`, `Set`, `RaspberryPiSet`, `Result`, `CDROMDir`/`TFTPTreeDir`/`ARM64IPXEFile` (the netboot media build, see §6); `alpine.go` (pinned Alpine netboot tarballs); `BuildError`, `PrivateKeyMaterialError`, `UnpinnedReleaseError`, `MissingFileError` |
| `pkg/diskimage/diskimagetest/` | `WriteELF`, `Binaries`, `UBootOutput`, `VirtKernelOutput`, `PlatformConfig` — the build inputs every image-building package's tests lay out |
| `build/docker/virt-kernel-builder/` | `Dockerfile`, `Makefile`, `build-virt-kernel.sh`, `configs/virt.config`, `README.md` |
| `pkg/diskimage/runner/` | `Runner`, `Exec`, `CommandError` |
| `pkg/cli/commands/diskimage/` | `NewCommand`; `create.go`, `inspect.go`, `test.go` (`test boot`, `ErrInvalidPortForward`), `assemble.go`, `merge.go`, `errors.go` |
| `pkg/qemu/arch.go` | `Arch` (`ArchX86_64`, `ArchAArch64`), `DiskFormatQCOW2`/`DiskFormatRaw`, the `archProfiles` map; `Config.Arch`, `Firmware`, `DiskFormat`, `TPMDevice`; `ErrUnsupportedArch`, `ErrFirmwareMissing`, `ErrUnsupportedBootMode`. The x86_64 command line is pinned by `TestBuildQEMUCommand_X86Golden` |
| `pkg/qemu/harness/` | `TPM` (interface over `*swtpm.SWTPM`), `StartTPM`, `StopTPM`, `TPMState`; `WaitForSerial`, `WaitForSerialAfter`, `SerialSize`, `SerialContains`; `Console` (`DialConsole`, `Expect`, `Send`, `SendLine`, `Discard`, `Transcript`, `Close`); `TPMError`, `SerialError`, `SerialTimeoutError`, `ConsoleError`, `ConsoleTimeoutError`. Shared by `iso test`, `diskimage test boot` and the integration suites |
| `pkg/installer/release.go` | `releaseOnFailure`, `afterFailedInstall`, `releaseDisk`, `diskRelease`, `luksMappedName`; `ErrDiskRelease` (installer engineering.md invariant 16) |
| `pkg/authenticode/pe.go` | `embedSignature`: `WIN_CERTIFICATE.dwLength` is header + DER and the 8-byte padding stays outside it (what `sbsign` writes; mbedTLS rejects the alternative, see §10) |
| `configs/platform/templates/single-node/raspberrypi/rpi4/default.yaml` | the Raspberry Pi 4 template `create --target rpi` picks up (`raspberrypi/README.md` lists what differs from the x86 template) |
| `test/integration/diskimage/` | `suite_test.go` (inputs from `DISKIMAGE_IMAGE`, `DISKIMAGE_RPI_IMAGE`, `DISKIMAGE_UBOOT`, `DISKIMAGE_WORK_DIR`; `MissingInputError`), `image_test.go`, `uboot_test.go`, `firstboot_test.go`; `userspace/` (the arm64 container suite) |
| `pkg/installer/boot_firmware.go` | `InstallTarget`, `BootFirmwareType`, `BootConfig`, `bootFirmwares`, `imageTargetSkips` (contract in [installer engineering.md](../installer/engineering.md) §2, invariant 3) |
| `pkg/iso/types.go` | `InstallerOverrides` |
| `build/docker/uboot-builder/` | `Dockerfile`, `Makefile`, `build-uboot.sh`, `mkesl.py`, `configs/{common-efi.config,rpi_arm64-tpm.config,qemu_arm64-tpm.config,tpm-soft-spi.dts}`, `patches/0001-mbedtls-glue-return-errno-for-parse-failures.patch`, `README.md` — every file but the README is a cache-key input |
| `build/docker/trusted-platform/Dockerfile-alpine-swtpm-arm64` | arm64 Alpine + swtpm for the userspace suite; the platform binaries are bind-mounted from `bin/aarch64` |
| `build/docker/diskimage-builder/Dockerfile` | the arm64 Alpine assemble container (apk-tools, parted, dosfstools, e2fsprogs, lvm2, util-linux, kmod, cpio, xz, mkinitfs, squashfs-tools, cryptsetup — no platform binaries, no keys); it also runs `diskimage netboot-initfs` and `diskimage diskless-root`. One image per platform: `BuildConfig.builderImageFor(arch)` tags `<BuilderImage>:<arch>` — host arch for assemble, target arch for netboot-initfs and diskless-root — so no step can run another platform's image |
| `pkg/diskimage/netboot_initfs.go` | `GenerateNetbootInitfs` (in-container), `StagedMedia.BuildNetbootInitfs` (host side), `NetbootInitfsOptions`, `NetbootInitfs`, `NetbootInitfsFeatures` |
| `pkg/diskimage/diskless_root.go` | `GenerateDisklessRoot` (in-container), `StagedMedia.BuildDisklessRoot` (host side through `runner.Container`), `DisklessRootOptions`, `DisklessRoot`, `DisklessRootFSFile`, `DisklessVerityFile`, `DisklessRootHashFile` |
| `pkg/diskimage/diskless_secrets.go` | `refuseRootPrivateKeys`, the pre-`mksquashfs` walk that refuses a root carrying private key material, and its `DisklessRootPrivateKeyError` |
| `pkg/diskimage/diskless_credentials.go` | `lockRootAccounts` (locks usable shadow hashes before packing), `refuseRootCredentials` and its `DisklessRootCredentialError` |
| `pkg/diskimage/diskless_config.go` | `refuseRootConfigSecrets` (refuses an installed platform config holding a plaintext `secret:"true"` field, found by `bootstrap.PlaintextSecretFields` against `app.App`) and its `DisklessRootConfigSecretError` |
| `pkg/initrd/diskless_root.go` | the initramfs-side diskless root path: fetch squashfs plus dm-verity hash tree, open with the signed `platform_roothash=` and pinned verity parameters, mount read-only squashfs and tmpfs overlay |

## 2. Exported surface

```go
type Target interface {
    Name() string
    Architecture() uki.Architecture
    KernelPackage() string
    ExtraPackages() []string
    UBootBoard() uboot.Board
    InstallerOverrides() iso.InstallerOverrides
    StageBootFirmware(ctx context.Context, mediaDir, prefetchDir string, art uboot.Artifacts) error
    BuiltKernel() bool                                                                   // qemu-virt: true
    StageKernel(ctx context.Context, mediaDir string, kernel *virtkernel.Artifacts) error // kernel-artifacts/<flavor>
}
func Targets() []string                              // sorted: qemu-virt, rpi
func NewTarget(name, model string) (Target, error)   // UnknownTargetError

func Create(ctx context.Context, cfg *BuildConfig) (*Result, error)
func Assemble(ctx context.Context, opts AssembleOptions) (*AssembleResult, error)
func GenerateDisklessRoot(ctx context.Context, opts DisklessRootOptions) (*DisklessRoot, error)
func (s *StagedMedia) BuildDisklessRoot(ctx context.Context, outDir, manifestDir string, sourceDateEpoch int64, version string) (*DisklessRoot, error)
func Inspect(ctx context.Context, path string, run runner.Runner) (*Report, error)
func Boot(ctx context.Context, opts BootOptions) (*BootResult, error)
func Preflight(ctx context.Context, run runnerFunc, containerRuntime, arch string) error
func ParseMBR(sector []byte) ([]Partition, error)
```

`BuildConfig`: `ISO *iso.ISOBuildConfig` (required), `Target`, `Model`,
`SizeMB`, `Output`, `BinariesDir`, `ContainerRuntime`, `BuilderImage`,
`BuilderDir`, `UBootBuilderDir`, `UBootOutputDir`, `UBootDir` (prebuilt;
skips the U-Boot build), `UBootCacheVolume`, `VirtKernelBuilderDir`,
`VirtKernelOutputDir`, `VirtKernelDir` (prebuilt), `VirtKernelCacheVolume`,
`Runner`, `Logger`, `SkipPreflight`. `Result`: `Image`, `SHA256`,
`SizeBytes`, `MediaDir`, `UBoot`, `Kernel` (nil for a packaged kernel). `AssembleOptions`: `Config` (required), `Output` (required),
`SizeMB`, `Runner`, `Logger`. `AssembleResult`: `Image`, `SizeBytes`, `LoopDevice`.
`BootOptions`: `Image` (required), `InPlace`, `Firmware` (required),
`WorkDir`, `Memory`, `CPUs`, `SerialLog`, `ConsoleSocket`, `Expect` (needs
`SerialLog`), `PortForwards`, `Debug`, `Logger`, plus unexported seams for
the TPM and the VM that tests inject. `BootResult`: `Disk`, `TPMState`,
`SerialLog`, `Expected`. `Boot` builds a `qemu.Config{Arch: ArchAArch64,
Firmware, DiskFormat: raw, ...}`, starts the swtpm through
`harness.StartTPM`, starts the VM in boot mode and either waits for it to
power off or, with `Expect`, for the milestone in the transcript, then
stops it; the swtpm is stopped on every return.

`Report`: `Image`, `SizeBytes`, `Partitions`, `ESP` (p1 when its type is
`0x0c`/`0x0b`), `LUKS2` (p2 carries a LUKS version-2 header), `ESPFiles`,
`UKIPath`, `UKIMachine`, `UKISigned`, `InstallerLUKS`, `Provisioned`,
`ConfigTxt`; `String()` is what `inspect` prints.

`rpi`: `Name = "rpi"`, `KernelPackage = "linux-rpi"`, `DefaultModel =
"rpi4"`; models `rpi4` (`bcm2711-rpi-4-b.dtb`), `rpi400`
(`bcm2711-rpi-400.dtb`), `cm4` (`bcm2711-rpi-cm4.dtb`), `rpi3b+`
(`bcm2710-rpi-3-b-plus.dtb`), `rpi5` (`bcm2712-rpi-5-b.dtb`,
`Experimental: true`). `ConfigTxt(m)` yields `arm_64bit=1`, `enable_uart=1`,
`uart_2ndstage=1`, `dtoverlay=disable-bt`, `dtoverlay=tpm-soft-spi`,
`kernel=kernel8.img`.

`qemuvirt`: `Name = "qemu-virt"`, `KernelPackage = "linux-lts"`, board
`uboot.BoardQEMUArm64`; `StageBootFirmware` leaves the directory empty.

`uboot`: `BoardRPiArm64 = "rpi_arm64"`, `BoardQEMUArm64 = "qemu_arm64"`;
`DefaultVersion`, `DefaultTarballSHA256`, `DefaultOwnerGUID` pin the upstream
release and are held equal to `build/docker/uboot-builder/Makefile` by
`TestPinsMatchBuilderMakefile`. `Artifacts`: `Board`, `Dir`, `Binary`
(`u-boot.bin`), `Config` (`u-boot.config`), `OverlaysDir` (rpi only).
`Manifest` is `output/manifest.json` (`uboot_version`, `tarball_sha256`,
`cache_key`, `owner_guid`, `boards`, `measured_pcrs`, `built_at`).

## 3. Invariants

1. **The installer is the only thing that writes the image.** `Assemble`
   creates a sparse file, attaches it, sets `Config.Target = InstallTargetImage`,
   `Config.Boot.Firmware = BootFirmwareUBoot` (when unset) and
   `Config.Disk.Device` to the loop device, and calls
   `installer.NewInstaller(...).Install`. Partitioning, LUKS, the OS, the UKI
   and `installer.luks` are the installer's, unchanged.
2. **Host-only steps are skipped for the image target; sealing material is
   not.** With `Target == image` the installer skips `TPM2_Clear`, the
   `/dev/tpmrm0` presence check (it logs *Image target: TPM sealing material
   will be written for the node to seal on its first boot* instead of turning
   sealing off), FIDO2 auto-enrolment and `/proc/cmdline` propagation
   (`imageTargetSkips`). `installer.luks`, the seal PCR list and the platform
   config are written as for a disk install.
3. **The passphrase is random per image.** When `Disk.Encryption` is set and
   carries neither `Password` nor `Passphrase`, `Assemble` generates 32
   random bytes, hex-encoded, as the keyslot-0 passphrase. It is never logged
   or returned. Firstboot replaces it with the TPM-sealed key.
4. **The boot firmware seam is fail-closed.** `ubootFirmware.ConfigureBoot`
   writes the sentinel, then copies `boot.firmware-stage-dir` (default
   `/media/cdrom/boot-firmware`) onto the ESP root; a missing directory, a
   symlink or a non-regular file is fatal (`ErrBootFirmwareStage`). There is
   no firmware fallback that could find the UKI.
5. **The Pi target verifies its own output.** `StageBootFirmware` fails with
   `FirmwareMissingError` unless `kernel8.img`, `config.txt`, the model's
   DTB, `overlays/tpm-soft-spi.dtbo`, `overlays/disable-bt.dtbo`,
   `start4.elf` and `fixup4.dat` all exist after staging. Files come only
   from the prefetched apks and the verified U-Boot output, so the image is
   built offline from the packages the node has installed.
6. **Nothing unverified reaches the ESP.** `uboot.Locate` requires every
   board directory, checks every file against its `SHA256SUMS`
   (`ChecksumMismatchError` for a bad digest *or* a file with no entry), and
   requires `overlays/tpm-soft-spi.dtbo` for `rpi_arm64`.
7. **Diskless image boot fails closed.** The builder refuses a root without
   `/sbin/init` or `/usr/bin/platformd` (`DisklessRootContentError`), checked
   in the installed tree and again in the squashfs listing, before any verity
   tree is made. The root hash is published only inside the DB-signed
   manifest. `platform-initrd` accepts a diskless root only when the signed
   UKI's `platform_roothash=`, `platform_verity_salt=`, sizes and URLs are all
   present and valid; it fetches the squashfs and hash tree into bounded
   tmpfs, and opens dm-verity before any mount with a device-mapper table
   (`dmsetup create --readonly`) whose every parameter is pinned or signed —
   there is no superblock to read them from, and no cryptsetup in the
   initramfs. dm-verity checks each block as it is read, starting with the
   squashfs superblock at mount; one that does not hash up to the signed root
   panics the node (`panic_on_corruption`) rather than serve it.
8. **The cache key is one value in two implementations, over every input
   that shapes the binary.** `uboot.CacheKey` and `make cache-key` hash
   `uboot:<version>`, `owner:<GUID>` (the SignatureOwner written into every
   preseeded list), then the sha256 of each config input — the fragments,
   the overlay, the patch, and the builder itself (`Dockerfile`,
   `build-uboot.sh`, `mkesl.py`) — and each certificate, in a fixed order;
   `TestCacheKeyMatchesMakeCacheKey` runs `make -s cache-key` and compares,
   with and without an owner GUID, and `TestCacheKeyCoversTheBuilder` pins
   the builder files as inputs. `Build` skips the container when
   `manifest.json` carries the key, and rejects a manifest that does not
   carry it after a build (`ManifestError`). A fix to the build script or
   the ESL writer therefore misses the cache; before this (review finding
   on #680) it could stage an old `u-boot.bin` into a new image under a
   manifest reporting a matching key.
9. **The baked config makes the node self-describing.** `applyInstallerOverrides`
   (`pkg/iso/customize.go`) always writes `os.architecture`, and writes
   `os.kernel-package`, `disk.device`, `disk.partition-table`,
   `hardware-manufacturer`, `hardware-model`, `install-target` and
   `boot.firmware` when the target sets them. The node's own config therefore
   says `aarch64` / `uboot`, so `platformctl install uki-rebuild` on the
   node produces `BOOTAA64.EFI`.
10. **The loop device comes from `/dev/loop-control`**, not `losetup --find`:
   `allocateLoopDevice` issues `LOOP_CTL_GET_FREE` and creates `/dev/loopN`
   with `mknod` when the container's private `/dev` has no node for it
   (`LoopDeviceError` otherwise), then `losetup --partscan` attaches the
   image. Detach runs whether or not the install succeeded; a detach failure
   after a failed install is logged, not raised.
11. **The host's `/dev` is never bind-mounted into the container.** The
    installer's `mdev -s` resets the mode of every device node it walks;
    `TestCreateStagesMediaAndRunsTheContainer` fails if the `docker create` argv ever names a
    `/dev` path again. The private `/dev` is static, so the installer's
    partition-node refresh (installer engineering invariant 15) is what keeps
    `/dev/loopNp1` usable after the second partition-table re-read.
12. **The size floor is 2048 MB** (default 4096); `Create` and `Assemble`
    fail below it before touching anything.
13. **`Preflight` runs before any work** unless `SkipPreflight`: the runtime
    answers `version`; on a foreign architecture a short-lived privileged
    `alpine:3.22` container started through the runtime (so the answer is the
    runtime host's, not the caller's `/proc`) reads
    `/proc/sys/fs/binfmt_misc/qemu-<arch>` and it carries `F` in its
    `flags:`; native builds run no probe; `/sys/module/loop` and `/sys/module/dm_crypt` exist.
14. **The assemble container runs at the host platform** (`BuildConfig.HostArch`,
    default `runtime.GOARCH`), never the target's: qemu-user has no keyring
    syscalls, so go-luks2 cannot open the volume under emulation (#802). A
    foreign target runs the installer from `BuildConfig.HostInstallerBinary`
    (a host-architecture `platformctl-static`, copied to `/installer`; the CLI
    takes the one beside the running `platformctl`), and `Create` fails with
    `HostInstallerMissingError` when there is none. The target architecture
    reaches the installer through the baked config (`os.architecture`); the
    installer never derives it from its own GOARCH (the UKI builder is set to
    the install target). Native: partitioning, LUKS, mkfs, losetup. Emulated
    (binfmt, in the target chroot): apk, dracut, depmod.

## 4. Error semantics

All errors are typed; none is `fmt.Errorf`. Every wrapping type implements
`Unwrap`.

| Error | Package | Returned when |
|---|---|---|
| `UnknownTargetError{Target, Targets}` | `diskimage` | `--target` is not `rpi` or `qemu-virt` |
| `PreflightError{Check, Remedy}` | `diskimage` | a build-host requirement is unmet; `Remedy` names the fix (`make init`, `modprobe ...`) |
| `StageError{Step, Err}` | `diskimage` | configuration, Secure Boot keys, U-Boot, media staging or boot-firmware staging failed |
| `AssembleError{Step, Err}` | `diskimage` | the container step, the loop device or the install failed |
| `InspectError{Path, Reason, Err}` | `diskimage` | the image cannot be read, has no MBR, or its ESP cannot be listed |
| `UnknownModelError{Model, Models}`; `PackageMissingError{Package, Dir}`; `PackageError{Package, Err}`; `FirmwareMissingError{File}`; `StageError{Step, Err}` | `rpi` | unknown `--model`; a required apk not prefetched; a malformed apk; a required boot file not produced; the staging directory could not be laid out |
| `ArtifactMissingError{Path, Hint}`; `ChecksumMismatchError{Path, Reason}`; `ManifestError{Path, Err}` | `uboot` | `u-boot.bin`, `SHA256SUMS` or the overlay absent; a digest mismatch, a file with no entry or a malformed sums line; `manifest.json` unreadable, incomplete or carrying the wrong cache key |
| `InputError{Path, Err}`; `BuildError{Step, Err}` | `uboot` | a fragment, overlay source or certificate unreadable; the builder image build or run failed |
| `CommandError{Name, Args, Output, Err}` | `runner` | any external command exited non-zero; carries the combined output |
| `ErrBuildFailed{Reason}`, `ErrConfigRequired{}`, `ErrConfigLoadFailed{Path, Err}`, `ErrBinariesNotFound{Dir}` | `cli/commands/diskimage` | the CLI wrappers; `ErrBinariesNotFound` names `make rpi-binaries` |
| `ErrUnknownInstallTarget`, `ErrUnknownBootFirmware`, `ErrBootFirmwareStage` | `installer` | an unknown `install-target` / `boot.firmware` spelling; a failed firmware copy |

**Fail-closed paths**: preflight; the size floor; U-Boot checksum
verification; the required-firmware check; the boot-firmware copy (symlinks
and non-regular files refused); apk extraction (paths containing `..` are
dropped); the `losetup` result; and the installer's own completion gate,
which fails an aarch64 image whose `BOOTAA64.EFI` is missing or empty
([installer engineering.md](../installer/engineering.md) invariant 4).

## 5. Configuration

The build is driven by flags ([cli.md](cli.md)); there are no environment
variables and no config file of its own. Precedence: flag > `BuildConfig`
default > `iso.DefaultISOBuildConfig()`.

The platform config baked into the image is `--platform-config`
(auto-detected: `configs/platform/templates/single-node/raspberrypi/<model>/default.yaml`
when it exists — it does not ship yet — else
`configs/platform/templates/single-node/default.yaml`), deep-merged with
`--overrides`. The target's `InstallerOverrides` are then applied on top:

| Target | `disk.device` | `disk.partition-table` | `os.kernel-package` | `hardware-manufacturer` / `hardware-model` | `install-target` | `boot.firmware` |
|---|---|---|---|---|---|---|
| `rpi` | `/dev/mmcblk0` | `mbr` | `linux-rpi` | `Raspberry Pi` / the model description | `image` | `uboot` |
| `qemu-virt` | `/dev/vda` | `mbr` | `linux-virt` (from `kernel-artifacts/virt` on the media) | `Raspberry Pi` / `QEMU virt stand-in` | `image` | `uboot` |

The hardware manufacturer/model pair selects the `pkg/quirks` entry, and the
two differ in one thing: console order. The Pi's last `console=` is `tty1`,
so an operator at the HDMI port sees OpenRC and the firstboot seal; the
stand-in's is `ttyAMA0`, because it has no display and the serial transcript
is what the integration suite reads — with `tty1` last, everything after
`switch_root` is invisible there (measured 2026-09-21).

`os.architecture` is always `aarch64`. Both targets select the Raspberry Pi
quirk entry (`pkg/quirks`: `console=ttyAMA0,115200 console=tty1 rootwait
loglevel=7`, no earlycon), because the virt machine's PL011 is `ttyAMA0` too.
The `rpi` target adds `raspberrypi-bootloader` and
`raspberrypi-bootloader-common` to the prefetch.

`seal-pcrs` comes from the template (`[0, 7, 9]` in the single-node default).
On the Pi, PCR 0 is only U-Boot's version string, so `[0, 4, 7, 9]` — adding
the measured UKI — is the recommended value; set it with `--overrides` until
the Raspberry Pi template ships.

Makefile variables: `UBOOT_KEYS_DIR` (default `$HOME/.trusted-platform/secure-boot`;
must hold `PK.crt`, `KEK.crt`, `DB.crt`), `UBOOT_OUTPUT_DIR`, `DISKIMAGE_TARGET`,
`DISKIMAGE_MODEL`, `DISKIMAGE_SIZE_MB`, `DISKIMAGE_OUTPUT`, `DISKIMAGE_BUILDER_IMG`,
`DISKIMAGE_FLAGS`, `RPI_SDCARD`, `RPI_SDCARD_CONFIRM`; in the U-Boot builder,
`UBOOT_VERSION`, `UBOOT_SHA256`, `UBOOT_BOARDS`, `UBOOT_OWNER_GUID`, `KEYS_DIR`,
`OUTPUT_DIR`, `CACHE_VOLUME` (mirrored by `uboot.Options`; the docker volume
holding the upstream tarball).

### Builder containers never bind-mount the host

A bind mount is resolved by the container daemon on **its** filesystem. When the
build runs inside a CI job container the daemon is the host's and the checkout
is not on it: inputs arrive as an empty directory and outputs never reach the
checkout (this is how `make virt-kernel-build` failed with `missing builder
input /configs/virt.config`). Every builder container is therefore run the
same way, with data moved by `docker cp` and no `-v <host path>`:

- inputs are baked into the image (`COPY`) or copied into the created
  container before it starts;
- outputs are copied out of the container after it exited successfully; a
  failed build copies nothing out;
- the source-tarball cache is a **named docker volume** (`CACHE_VOLUME`, e.g.
  `trusted-platform-uboot-src`), which the daemon owns, not a host directory;
- the container is always removed, with its anonymous volumes.

`build/docker/run-builder.sh [-i HOST:CTR]... [-o CTR:HOST]... -- <docker create
args>` does this for every Makefile builder (iPXE, U-Boot, virt kernel, FIPS
kernel, OpenSSL FIPS provider, strongSwan); `runner.Container`
(`pkg/diskimage/runner`) does it for the Go callers (`uboot.Build`,
`virtkernel.Build`, the assemble and netboot-initfs containers, the FIPS
artifact containers in `pkg/iso`). It behaves identically on a developer host.
`diskimagetest.Runner` is a fake daemon with a private filesystem per
container; it rejects `run` and any host bind mount, so a regression fails the
unit tests.

## 6. Persistence and on-disk layout

- `<work-dir>/media/` — the staged media root (`apks-prefetch/aarch64/`,
  `platformd-bin/`, `configs/installer.yaml`, `boot-firmware/`, keys),
  copied into the assemble container at `/media/cdrom`; kept after the build.
- `<work-dir>/trusted-platform-<target>.img` unless `--output` is given.
- `build/docker/uboot-builder/output/{rpi_arm64,qemu_arm64}/` (`u-boot.bin`,
  `u-boot.config`, `SHA256SUMS`, `overlays/tpm-soft-spi.dtbo` for rpi) and
  `output/manifest.json`.
- The image: [architecture.md §2](architecture.md#the-image); the ESP is the
  installer's 538 MB default, the root takes the rest. No compatibility
  promise covers the media or U-Boot output layouts.

**Netboot media build** (`netboot.Build`, the container contract
`container.NetbootMedia`): the same media, staged once per media set and
served by the bootstrap container instead of written to a card.

- `media/<set>/cdrom/` — the set's install media (`diskimage.StageMedia` for
  its target, moved into place); `payload.list` over every file of it;
  `vmlinuz-<flavour>` (db-signed with the build's DB key — the KMS-held key
  for `kms://` references — when Secure Boot is on), `initramfs-<flavour>`,
  `modloop-<flavour>`: from the pinned Alpine netboot tarball for a target
  on a packaged kernel (the Pi set, Alpine's `rpi` flavour); for a target on
  a platform-built kernel (the virt set) that kernel, with the initramfs and
  modloop `diskimage netboot-initfs` generates for it in the arm64 builder
  container; `media-set.yaml`. A set with no diskimage target — `X86_64Set`,
  x86_64's default — stages the installer media alone
  (`iso.StageInstallMedia` with the x86 binaries: no U-Boot, no boot
  firmware, the machine's own UEFI) and boots Alpine's `lts` flavour.
  `DefaultSets` = `X86_64Set` + `RaspberryPiSet` + `ARM64VirtSet`.
  `Config.SetsToBuild` is the one answer to "which sets": the named `Sets`,
  else `DefaultSets`, less every set with no diskless image when `Diskless`
  is set. `platformctl diskimage netboot` passes no sets when `--sets` is
  absent and asks `SetsToBuild` before resolving per-set binaries, so a
  default `--diskless` build never needs the x86_64 binaries.
- Every set's `initramfs-<flavour>` is rewritten as the installer's
  (`iso.InstallMedia.InstallerInitramfs` → `Customizer.InstallerInitramfs`):
  the autoinstall overlay generated from the set's own media configuration,
  Alpine's `/init` patched to install it on `alpine_start=autoinstall` and to
  DHCP on every carrier-up NIC — the same `makeInstallerInitramfs` step the
  ISO's initramfs gets. A netboot initramfs already has the NIC drivers and
  udhcpc's script, so nothing else is added. An `/init` the patches cannot
  anchor to fails the build; the release's live initramfs is never served.
  The repack is zstd, root-owned.
- `rpi-tftp/` (the Pi set: `Stage` from the set's own packages and U-Boot)
  and `firmware/snponly-aarch64.efi` (the ipxe-builder's arm64 iPXE, verified
  against its `SHA256SUMS`, then db-signed).
- `http-boot/{boot.img,boot.sig,pubkey.bin}` when `Config.HTTPBoot` is set (the
  Pi's signed HTTP boot, below); indexed as `http_boot`.
- `netboot-media.yaml`, `SHA256SUMS` (relative paths, `sha256sum -c`
  format). `Build` loads the result back through `LoadNetbootMedia` and
  `LoadMediaSets`, so a build the container would refuse fails the build.
- A set is served over HTTP, so it is staged `NetworkServed`: only
  positively public Secure Boot artifacts, no key generation, and a config
  that would sign with media-staged keys is refused — the DB key belongs in
  the KMS (`resign-mode: remote`). `refusePrivateKeys` checks the result
  again (`PrivateKeyMaterialError`).
- Alpine tarballs are cached under `CacheDir` (default
  `<output>.cache/alpine`) and verified against the digests pinned in
  `alpine.go`; an unpinned Alpine release is an `UnpinnedReleaseError`.

**Signed HTTP boot** (`netboot.StageHTTPBoot`, `pkg/rpibootsig`,
`pkg/diskimage/fatimage`): the Pi's first stage over HTTP. The bootloader EEPROM
fetches `boot.img` and `boot.sig` from `HTTP_HOST`/`HTTP_PATH`; with
`SIGNED_BOOT=1` it runs the image only if `boot.sig` verifies against the public
key whose SHA-256 is in OTP.

- `boot.img` is `fatimage.Build` of the staged Pi tree: a FAT16 ramdisk,
  written in pure Go (no loop device, no `mkfs`), reproducible for a tree
  (a fixed FAT epoch). The writer uses lowercase 8.3 short names with NT case
  flags when a name fits, emits VFAT long-name entries only when needed, and
  the reader rejects malformed geometry, cluster cycles, and cross-linked
  directory chains before walking files.
- `boot.sig` is `rpibootsig.Sign`, byte-compatible with upstream's
  `rpi-eeprom-digest`: `<sha256 of boot.img>\nts: <epoch>\n[target-soc: 2711|2712\n]rsa2048: <hex>`,
  the signature RSA-2048 PKCS#1 v1.5 over SHA-256 of the image. `target-soc`
  is optional and omitted by default for `boot.img`; `platformctl diskimage
  netboot --target-soc 2711|2712` writes it explicitly for hardware validation.
  `--model` still selects the Pi tree to stage, and 3B+ has no EEPROM and is a
  `NoEEPROMError`. Golden tests pin the format against vectors made with
  upstream's script.
- `pubkey.bin` is the modulus (256 bytes) and exponent (8 bytes), both
  little-endian: `rpibootsig.KeyBlob`. Its SHA-256 (`KeyHash`) is the OTP
  customer key hash; `ParseKeyBlob` reads it back. Raspberry Pi's
  `rpi-eeprom-config --pubkey` takes the fleet certificate/public key as PEM,
  so operators export that PEM separately through `platformctl ca certificate`.
- **The private key never leaves the KMS.** The signer is
  `secureboot.NewKMSSigner` on the build's platform client: the KMS is sent the
  prehashed SHA-256 digest (`PreHashed=true`). `FleetKey` must be a `kms://`
  reference (`FleetKeyRefError`), an RSA-2048 key - the only size the
  bootloader verifies - and `rpibootsig.Sign` verifies its own signature before
  emitting it, so a KMS that signs with the wrong key or scheme fails the
  build. The same signer backs `platformctl diskimage rpi-eeprom-hsm`, whose
  stdout contract matches upstream `rpi-eeprom-digest -H` for signing the
  EEPROM config without exporting the private key. Signing the 2712 (Pi 5/CM5)
  first-stage `bootcode.bin` is not this flow and is unsupported until Phase 6
  hardware validation (#692).
- The build reads the staged files back (`VerifyHTTPBoot`: the key against its
  hash, the digest, the signature) before it
  returns, and `container.LoadNetbootMedia` refuses an index whose `http_boot`
  directory lacks any of the three files.
- Serving: the deployer owns `http-boot/` (it is cleared and replaced with the
  rest of the build) and the container serves it from the data directory at
  `/data/http-boot/`, so `HTTP_PATH` is `container.NetbootMedia.HTTPBootPath()`
  (`data/http-boot`). The HTTP server's read/write timeout is 30 s.
- The emulator side, `rpinetboot.HTTPBoot`, is the EEPROM's: fetch both
  files, require the public key to hash to the OTP value
  (`KeyHashMismatchError`), verify `boot.sig` over `boot.img`
  (`DigestMismatchError`, `SignatureError`, `MalformedError`), then mount the
  image (`RamdiskError`). A refusal is an `HTTPBootRefusedError`. It is
  exposed as `platformctl bootstrap probe rpi-http` ([bootstrap cli.md](../bootstrap/cli.md))
  and driven end to end by `test/integration/netboot/rpi_httpboot_test.go`,
  which signs with an in-process RSA key: the integration suite has no KMS
  service, and the KMS path is covered by the builder's unit tests against the
  platform-client fake.

What only hardware can confirm (OTP programming, signed EEPROM config,
explicit `target-soc` behaviour, the EEPROM FAT reader, `HTTP_HOST`/`HTTP_PORT`
syntax, the image size limit, HTTPS and a custom CA on the Pi 5 and CM5) is
listed in [user.md](user.md#what-hardware-must-still-confirm).

## 7. Test strategy

Four layers, cheapest first; each one is a `make` target and the
`rpi-image` job in `nightly.yml` runs the first three. That workflow has no
schedule since #852: dispatch it by hand (`workflow_dispatch`), and every
dispatch also runs the emulated first boot.

- **Unit** (`make test-diskimage`, `test-qemu`, `coverage-diskimage`,
  `bench-diskimage`; `make test` covers the rest): every external command
  goes through `runner.Runner` or a function seam, so no unit test touches a
  container runtime, a loop device, a TPM or QEMU. `Assemble` takes an
  injectable install function; `Boot` takes an injectable TPM starter and VM;
  `Inspect` runs against a synthetic MBR + LUKS2 header with a fake `mdir`;
  `pkg/qemu`'s x86_64 command line is a golden test and the aarch64 profile
  is asserted argument by argument; `pkg/qemu/harness` fakes the swtpm
  behind its `TPM` interface and drives `Console` against an in-process
  unix socket; the installer's release-on-failure and embedded-kernel signing
  run against recorders and a `authenticodetest.MinimalPE`. That package
  (`pkg/authenticode/authenticodetest`) is the one home for hand-built PE
  fixtures: `MinimalPE` for tests that sign, `SectionedPE(sections, padding)`
  for tests that rewrite the section table (`pkg/uki`). Do not add a local copy.
  `TestCacheKeyMatchesMakeCacheKey` runs `make -s cache-key` in the builder
  directory (needs `make`, no container).
- **Image layout** (`test/integration/diskimage/image_test.go`, part of
  `make integration-test-diskimage`): both images are inspected without
  booting — MBR types and boot flag, FAT32 ESP, LUKS2 root, the signed
  aarch64 UKI at `EFI/BOOT/BOOTAA64.EFI`, `tpm2/installer.luks` and
  `pcr-banks` present, no plaintext key on the ESP; the Raspberry Pi image
  additionally carries `config.txt`, `kernel8.img`, the firmware, the DTB
  and the `tpm-soft-spi` overlay.
- **U-Boot alone** (`uboot_test.go`): the qemu_arm64 U-Boot with a swtpm
  and an empty disk, driven at its prompt through `harness.Console`:
  `tpm2 info` finds the TIS device, `SecureBoot` reads `01`, `db` exists.
- **Emulated first boot** (`firstboot_test.go`, `make integration-test-diskimage`,
  30-60 minutes under TCG): `pkg/diskimage.Boot` boots the `qemu-virt`
  image and waits for the serial milestones in order — U-Boot's bootflow,
  the EFI stub measuring the initrd under Secure Boot, the kernel,
  platform-initrd in FIRSTBOOT mode, the keyfile unlock, the seal service
  sealing the LUKS key to the TPM with the PCR policy, and the login
  prompt (OpenRC's default runlevel, platformd included, finished) — then
  boots the same disk and TPM state a second time and expects `TPM-PCR`
  as attempt 1, with no fallback, and — the seal now proven — wipes
  `installer.luks` before `switch_root` (`Seal confirmed by TPM-PCR
  unlock`, [bootstrap architecture.md](../bootstrap/architecture.md)); a
  third boot then finds no installer container and unlocks with `TPM-PCR`
  again. The devcontainer
  runs it (`run-integration-tests.sh diskimage`, the parent package only —
  `userspace/` has its own target — with a 90-minute go test timeout).
- **arm64 userspace** (`test/integration/diskimage/userspace/`,
  `make integration-test-diskimage-userspace`, minutes): the aarch64
  platformd on musl inside an arm64 Alpine container against a swtpm —
  health (the CA and KMS components; a single node reports SDN unhealthy
  by design), `tpm info` (the swtpm, not the simulator), EK and SSRK at
  their handles, seal/unseal through the daemon (SSRK-parented with
  password auth), go-luks2 format + dm-crypt unlock on the target
  architecture. Two arrangements are forced by qemu-user: swtpm cannot
  bind a socket inside the emulated container, so the Makefile runs a
  host-native swtpm and bind-mounts its socket; and the fresh-TPM seal
  guard wants a vfat ESP at `/boot/efi`, so the suite loop-mounts one.
- **Hardware validation** on a Raspberry Pi is the operator step in
  [user.md](user.md); it has not been performed in this phase.

## 8. Observability

Log events (structured, through `logging.Logger`): `[DISKIMAGE] Secure Boot
keys` (`decision`, `dir`), `[DISKIMAGE] Image attached` (`image`, `loop`,
`size_mb`), `[DISKIMAGE] failed to detach the loop device after a failed
install`, `[UBOOT] Copied boot firmware onto the EFI partition` (`from`,
`to`), `[UBOOT] Secure Boot enforcement requested: the PK/KEK/db are
preseeded into the U-Boot binary; nothing to enroll`, and the installer's
`Image target: TPM sealing material will be written for the node to seal on
its first boot`. The installer's own `[DISK]`, `[TPM]` and UKI events apply
unchanged. There are no metrics and no audit records: this is a build-host
tool, not a daemon.

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every verb in [cli.md](cli.md) to
have a `CommandDefinition` in the integration parity suite. **This repository
defines no `CommandDefinition` type** (grepped repo-wide, 2026-09-16), so the
requirement is unmet repo-wide, not only here.

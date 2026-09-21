package installer

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// InstallTarget names what the installer writes to.
type InstallTarget string

const (
	// InstallTargetDisk is a disk of the node being installed: the live
	// installer runs on the target hardware, so the TPM can be cleared and
	// the host's own boot environment consulted.
	InstallTargetDisk InstallTarget = "disk"
	// InstallTargetImage is a loop-mounted disk image on a build host. The
	// host's TPM, FIDO2 devices and kernel command line belong to the
	// builder, not the node, and are left alone.
	InstallTargetImage InstallTarget = "image"
)

// BootFirmwareType names the firmware the installed system boots under.
type BootFirmwareType string

const (
	// BootFirmwareUEFI is a UEFI implementation with NVRAM boot entries and
	// Secure Boot key enrolment through efivarfs.
	BootFirmwareUEFI BootFirmwareType = "uefi"
	// BootFirmwareUBoot is U-Boot loaded by the Raspberry Pi firmware and
	// acting as the UEFI implementation: the boot files it needs are copied
	// onto the ESP root and its Secure Boot keys are preseeded in the binary.
	BootFirmwareUBoot BootFirmwareType = "uboot"
)

// BootConfig selects the boot firmware the installed system targets.
type BootConfig struct {
	// Firmware is uefi (default) or uboot.
	Firmware BootFirmwareType `yaml:"firmware,omitempty" json:"firmware,omitempty"`
	// FirmwareStageDir is the directory whose tree is copied onto the ESP
	// root for a U-Boot target: the U-Boot binary as kernel8.img,
	// config.txt, the Raspberry Pi firmware blobs, device trees and
	// overlays. Defaults to boot-firmware/ on the install media.
	FirmwareStageDir string `yaml:"firmware-stage-dir,omitempty" json:"firmware_stage_dir,omitempty"`
}

// defaultFirmwareStageDir is where the media generator stages a U-Boot
// target's boot files (pkg/iso, pkg/diskimage).
var defaultFirmwareStageDir = filepath.Join(isoMediaMount, "boot-firmware")

// validInstallTargets and validBootFirmwares are the accepted spellings.
var (
	validInstallTargets = map[InstallTarget]bool{"": true, InstallTargetDisk: true, InstallTargetImage: true}
	validBootFirmwares  = map[BootFirmwareType]bool{"": true, BootFirmwareUEFI: true, BootFirmwareUBoot: true}
)

// bootFirmware is what the install sequence asks of the target firmware
// after the UKI is signed: make the system discoverable at the next POST,
// and enforce Secure Boot where the firmware supports enrolment.
type bootFirmware interface {
	ConfigureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error
	EnforceSecureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error
	// VerifiesEmbeddedKernel reports whether the firmware authenticates
	// the kernel the UKI's stub loads from memory, so that kernel has to
	// carry its own Authenticode signature. systemd-stub hands the
	// embedded kernel to LoadImage; EDK2 firmware lets the stub install a
	// Security-Arch override that trusts it (the stub itself was verified),
	// U-Boot has no such protocol and verifies the inner image against db.
	VerifiesEmbeddedKernel() bool
}

// bootFirmwares dispatches a BootFirmwareType to its implementation.
var bootFirmwares = map[BootFirmwareType]bootFirmware{
	BootFirmwareUEFI:  uefiFirmware{},
	BootFirmwareUBoot: ubootFirmware{},
}

// espRootDir is the mounted EFI system partition of the target: the
// installer's mount point unless a test injected another root.
func (i *installer) espRootDir() string {
	if i.espRoot != "" {
		return i.espRoot
	}
	return filepath.Join(targetMountPoint, "boot", "efi")
}

// bootFirmwareType returns the configured firmware, uefi when unset.
func (i *installer) bootFirmwareType() BootFirmwareType {
	if i.config == nil || i.config.Boot == nil || i.config.Boot.Firmware == "" {
		return BootFirmwareUEFI
	}
	return i.config.Boot.Firmware
}

// bootFirmware resolves the implementation for the configured firmware.
func (i *installer) bootFirmware() (bootFirmware, error) {
	fw, ok := bootFirmwares[i.bootFirmwareType()]
	if !ok {
		return nil, ErrUnknownBootFirmware(string(i.bootFirmwareType()))
	}
	return fw, nil
}

// uefiFirmware is the historical path: startup.nsh, the provisioned
// sentinel, an efibootmgr NVRAM entry, the TRUSTED_PLATFORM EFI variable,
// and Secure Boot enrolment through efivarfs when the firmware is in Setup
// Mode.
type uefiFirmware struct{}

func (uefiFirmware) ConfigureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error {
	return i.configureUEFIBoot(ctx, diskInfo)
}

func (uefiFirmware) EnforceSecureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error {
	return i.enforceSecureBoot(ctx, diskInfo)
}

// VerifiesEmbeddedKernel is false: EDK2 honours systemd-stub's security
// override, and the x86 UKI keeps the unsigned inner kernel it always had.
func (uefiFirmware) VerifiesEmbeddedKernel() bool { return false }

// ubootFirmware targets U-Boot as loaded by the Raspberry Pi firmware. There
// is no NVRAM, no efivarfs and no efibootmgr: U-Boot's boot standard finds
// the UKI at EFI/BOOT/<arch loader> on the first FAT partition, so the
// firmware files only have to be present on the ESP root.
type ubootFirmware struct{}

func (ubootFirmware) ConfigureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error {
	espDir := i.espRootDir()
	if err := writeProvisionedSentinel(espDir); err != nil {
		return err
	}
	stageDir := defaultFirmwareStageDir
	if i.config.Boot != nil && i.config.Boot.FirmwareStageDir != "" {
		stageDir = i.config.Boot.FirmwareStageDir
	}
	info, err := os.Stat(stageDir)
	if err != nil {
		return ErrBootFirmwareStage("boot firmware staging directory "+stageDir+" is not readable", err)
	}
	if !info.IsDir() {
		return ErrBootFirmwareStage("boot firmware staging path "+stageDir+" is not a directory", nil)
	}
	if err := copyTree(stageDir, espDir); err != nil {
		return ErrBootFirmwareStage("copying the staged boot firmware onto the EFI partition", err)
	}
	i.logger.Info("[UBOOT] Copied boot firmware onto the EFI partition", "from", stageDir, "to", espDir)
	return nil
}

func (ubootFirmware) EnforceSecureBoot(ctx context.Context, i *installer, diskInfo *DiskInfo) error {
	if i.config.SecureBoot == nil || !i.config.SecureBoot.Enabled || !i.config.SecureBoot.Enforce {
		return nil
	}
	i.logger.Info("[UBOOT] Secure Boot enforcement requested: the PK/KEK/db are preseeded into the U-Boot binary; nothing to enroll")
	return nil
}

// VerifiesEmbeddedKernel is true: U-Boot authenticates every image
// LoadImage is given, including the kernel systemd-stub loads out of the
// UKI, and refuses an unsigned one with "Image not authenticated"
// (measured 2026-09-20 on qemu_arm64: the UKI verified, the inner kernel
// did not, and the stub failed in linux_exec with a Security violation).
func (ubootFirmware) VerifiesEmbeddedKernel() bool { return true }

// provisionedSentinelPath is the marker on the ESP that tells the firmware
// side of the platform (and a later re-install) the disk was provisioned by
// the Trusted Platform installer.
const (
	provisionedSentinelDir  = "EFI/TRUSTED_PLATFORM"
	provisionedSentinelFile = "PROVISIONED"
	provisionedSentinelBody = "TRUSTED_PLATFORM=1\n"
)

// writeProvisionedSentinel writes EFI/TRUSTED_PLATFORM/PROVISIONED under
// espDir.
func writeProvisionedSentinel(espDir string) error {
	sentinelDir := filepath.Join(espDir, provisionedSentinelDir)
	if err := os.MkdirAll(sentinelDir, 0755); err != nil {
		return &WrappedError{Msg: "create TRUSTED_PLATFORM sentinel dir", Err: err}
	}
	if err := os.WriteFile(filepath.Join(sentinelDir, provisionedSentinelFile), []byte(provisionedSentinelBody), 0644); err != nil {
		return &WrappedError{Msg: "write TRUSTED_PLATFORM sentinel", Err: err}
	}
	return nil
}

// copyTree copies every regular file under src to the same relative path
// under dst, creating directories as needed. Symlinks are refused: nothing
// staged for a FAT partition may be one.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0755)
		case d.Type()&fs.ModeSymlink != 0:
			return &MessageError{Msg: "refusing to stage symlink " + path + " onto the EFI partition"}
		case !d.Type().IsRegular():
			return &MessageError{Msg: "refusing to stage non-regular file " + path + " onto the EFI partition"}
		}
		return copyRegularFile(path, target)
	})
}

// copyRegularFile copies one file, replacing any existing destination.
func copyRegularFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// installStep names the parts of Install that depend on running on the node
// being installed rather than on a build host.
type installStep int

const (
	// stepClearTPM clears the TPM before provisioning.
	stepClearTPM installStep = iota
	// stepTPMDevicePresence turns TPM sealing off when no TPM device exists.
	stepTPMDevicePresence
	// stepFIDO2AutoEnroll enrols a FIDO2 key found on the host.
	stepFIDO2AutoEnroll
	// stepHostCmdlinePropagation copies debug parameters from /proc/cmdline.
	stepHostCmdlinePropagation
)

// imageTargetSkips lists the steps an image build must not perform: they
// would act on the build host's TPM, security keys and kernel command line
// instead of the node's. Sealing material is still written, because the
// node seals it on its own first boot.
var imageTargetSkips = map[installStep]bool{
	stepClearTPM:               true,
	stepTPMDevicePresence:      true,
	stepFIDO2AutoEnroll:        true,
	stepHostCmdlinePropagation: true,
}

// skip reports whether step is disabled for the configured install target.
func (i *installer) skip(step installStep) bool {
	return i.config != nil && i.config.Target == InstallTargetImage && imageTargetSkips[step]
}

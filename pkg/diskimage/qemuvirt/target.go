// Package qemuvirt is the emulated stand-in for the Raspberry Pi target: the
// same Alpine aarch64 install, EFI partition, U-Boot boot flow and first
// boot, on the QEMU virt machine with U-Boot supplied as -bios and a swtpm
// behind tpm-tis-device. Its kernel is the platform-built virt kernel
// (pkg/diskimage/virtkernel): Alpine's aarch64 kernels have no memory-mapped
// TIS driver and QEMU's virt machine offers no other TPM transport, so the
// stand-in boots Alpine's kernel version with that driver added. Nothing
// else differs, so the integration suite exercises the identical pipeline.
package qemuvirt

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/virtkernel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Name is the target name on the command line.
const Name = "qemu-virt"

// KernelPackage names the kernel flavour the built kernel is installed
// under (vmlinuz-virt, /lib/modules/<release>); no apk of that name is
// installed or prefetched.
const KernelPackage = "linux-virt"

// KernelArtifactsMediaDir is where StageKernel puts the built kernel,
// relative to the media root, and where the installer reads it from under
// /media/cdrom.
const KernelArtifactsMediaDir = "kernel-artifacts/" + virtkernel.DefaultFlavor

// Target builds the QEMU virt image.
type Target struct{}

// New returns the target.
func New() *Target { return &Target{} }

// Name implements diskimage.Target.
func (t *Target) Name() string { return Name }

// ModelName implements diskimage.Target: the one machine, QEMU's virt.
func (t *Target) ModelName() string { return "virt" }

// Architecture implements diskimage.Target.
func (t *Target) Architecture() uki.Architecture { return uki.ArchAArch64 }

// KernelPackage implements diskimage.Target.
func (t *Target) KernelPackage() string { return KernelPackage }

// ExtraPackages implements diskimage.Target: none.
func (t *Target) ExtraPackages() []string { return nil }

// UBootBoard implements diskimage.Target.
func (t *Target) UBootBoard() uboot.Board { return uboot.BoardQEMUArm64 }

// BuiltKernel implements diskimage.Target: the virt kernel.
func (t *Target) BuiltKernel() bool { return true }

// InstallerOverrides implements diskimage.Target. The disk is the virtio
// block device QEMU presents; the quirk entry is the Raspberry Pi one
// because the virt machine's PL011 is ttyAMA0 too; the kernel comes from
// the staged artifacts.
func (t *Target) InstallerOverrides() iso.InstallerOverrides {
	return iso.InstallerOverrides{
		Device:               "/dev/vda",
		PartitionTable:       "mbr",
		KernelPackage:        KernelPackage,
		KernelArtifactsDir:   "/media/cdrom/" + KernelArtifactsMediaDir,
		HardwareManufacturer: "Raspberry Pi",
		HardwareModel:        "QEMU virt stand-in",
		Target:               "image",
		BootFirmware:         "uboot",
	}
}

// StageBootFirmware implements diskimage.Target. U-Boot is passed to QEMU
// as -bios, so the boot partition needs no firmware files; the directory
// still exists because the installer's uboot firmware seam copies it.
func (t *Target) StageBootFirmware(ctx context.Context, mediaDir, prefetchDir string, art uboot.Artifacts) error {
	dest := filepath.Join(mediaDir, "boot-firmware")
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	return os.MkdirAll(dest, 0o755)
}

// StageKernel implements diskimage.Target: the verified artifact
// directory (kernel, modules, config, kernel-version.txt, SHA256SUMS) is
// copied whole so the installer verifies the same SHA256SUMS again.
func (t *Target) StageKernel(ctx context.Context, mediaDir string, kernel *virtkernel.Artifacts) error {
	if kernel == nil {
		return &StageError{Step: "staging the kernel", Err: errNoKernel}
	}
	dest := filepath.Join(mediaDir, KernelArtifactsMediaDir)
	if err := os.RemoveAll(dest); err != nil {
		return &StageError{Step: "clearing the kernel staging directory", Err: err}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return &StageError{Step: "creating the kernel staging directory", Err: err}
	}
	entries, err := os.ReadDir(kernel.Dir)
	if err != nil {
		return &StageError{Step: "reading the kernel artifacts", Err: err}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(kernel.Dir, e.Name()), filepath.Join(dest, e.Name())); err != nil {
			return &StageError{Step: "copying " + e.Name(), Err: err}
		}
	}
	return nil
}

// copyFile copies src to dst with mode 0644.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

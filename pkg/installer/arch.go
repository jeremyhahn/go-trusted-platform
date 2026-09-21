package installer

import (
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// bootTarget carries the artefact names that differ between CPU
// architectures: the UEFI removable-media boot file the unified kernel image
// is written to, the systemd stub it is built from, and the kernel drivers
// dracut packs into the initramfs.
type bootTarget struct {
	arch          uki.Architecture
	ukiFileName   string
	stubPath      string
	dracutDrivers string
}

// dracutDriversX86 is the initramfs driver set for x86_64 installs: the
// server-class NICs the installer's dracut network unlock hook needs, plus
// device-mapper and the FAT support the EFI partition requires.
const dracutDriversX86 = "igb ixgbe e1000e i40e ice mlx5_core bnxt_en dm_mod dm_crypt vfat fat nls_cp437 nls_iso8859_1"

// dracutDriversAArch64 is the initramfs driver set for aarch64 installs: the
// same device-mapper and FAT support, the TPM stack including the SPI
// transport a Raspberry Pi's discrete TPM sits on, the SD-card and
// on-board Ethernet drivers of the Pi, and the virtio drivers the QEMU
// virt machine used for emulated boots presents.
// dracutDriversAArch64 carries the SPI TPM stack the Raspberry Pi image
// boots with: the platform's tpm-soft-spi overlay describes the SLB9670 on
// a GPIO bit-banged bus, so the initramfs needs spi-gpio (and its
// spi-bitbang core) beside tpm_tis_spi, or the TPM does not exist when
// platform-initrd asks for it. spi-bcm2835 is the hardware controller for
// operators who use the kernel's own tpm-slb9670 overlay instead. Alpine's
// aarch64 kernels have no memory-mapped TIS driver (CONFIG_TCG_TIS unset),
// so tpm_tis is listed for kernels that carry it and is absent otherwise.
const dracutDriversAArch64 = "dm_mod dm_crypt vfat fat nls_cp437 nls_iso8859_1 tpm tpm_tis_core tpm_tis tpm_tis_spi spi-gpio spi-bitbang spi-bcm2835 mmc_block sdhci sdhci-iproc bcmgenet virtio_blk virtio_net virtio_mmio virtio_pci"

// dracutDriversByArch maps each installable architecture to its driver set.
var dracutDriversByArch = map[uki.Architecture]string{
	uki.ArchX86_64:  dracutDriversX86,
	uki.ArchAArch64: dracutDriversAArch64,
}

// x86BootTarget is the historical default every installer used before
// architectures were modelled. An installer constructed without going
// through NewInstaller (tests build the struct directly) behaves exactly as
// before by resolving to it; the literal names are pinned to pkg/uki by
// TestX86BootTargetMatchesUKI.
var x86BootTarget = bootTarget{
	arch:          uki.ArchX86_64,
	ukiFileName:   "BOOTX64.EFI",
	stubPath:      uki.DefaultStubPath,
	dracutDrivers: dracutDriversX86,
}

// resolveBootTarget derives the boot artefact names for an OSConfig
// architecture value ("" means x86_64; GOARCH aliases are accepted).
func resolveBootTarget(archName string) (bootTarget, error) {
	arch, err := uki.ParseArchitecture(archName)
	if err != nil {
		return bootTarget{}, ErrInvalidConfig("unsupported OS architecture " + archName)
	}
	drivers, ok := dracutDriversByArch[arch]
	if !ok {
		return bootTarget{}, ErrInvalidConfig("no initramfs driver set for architecture " + string(arch))
	}
	ukiName, err := uki.BootFileName(arch)
	if err != nil {
		return bootTarget{}, ErrInvalidConfig("no UEFI boot file name for architecture " + string(arch))
	}
	stub, err := uki.StubPath(arch)
	if err != nil {
		return bootTarget{}, ErrInvalidConfig("no EFI stub for architecture " + string(arch))
	}
	return bootTarget{arch: arch, ukiFileName: ukiName, stubPath: stub, dracutDrivers: drivers}, nil
}

// bootTarget returns the installer's resolved boot target, or the x86_64
// default for an installer that was not built by NewInstaller.
func (i *installer) bootTarget() bootTarget {
	if i.boot.arch == "" {
		return x86BootTarget
	}
	return i.boot
}

// ukiFileName is the file name under EFI/BOOT the unified kernel image is
// written to (BOOTX64.EFI, BOOTAA64.EFI, ...).
func (i *installer) ukiFileName() string {
	return i.bootTarget().ukiFileName
}

// espLoaderPath is the UEFI device-path form of the UKI location, as
// firmware boot entries and startup.nsh spell it.
func (i *installer) espLoaderPath() string {
	return `\EFI\BOOT\` + i.ukiFileName()
}

// ukiESPPath is the UKI location as the installed system sees it.
func (i *installer) ukiESPPath() string {
	return filepath.Join(DefaultESPBootDir, i.ukiFileName())
}

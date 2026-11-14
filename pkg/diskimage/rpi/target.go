// Package rpi is the Raspberry Pi target of the disk image builder: an
// Alpine aarch64 system on an SD card whose FAT boot partition carries the
// Raspberry Pi firmware, U-Boot as kernel8.img, the board device trees,
// the soft-SPI TPM overlay and the config.txt that ties them together. The
// EFI system partition and the U-Boot boot flow are what pkg/installer's
// uboot firmware seam expects; everything here only stages files.
package rpi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/virtkernel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Name is the target name on the command line.
const Name = "rpi"

// KernelPackage is the Alpine kernel built for the Raspberry Pi boards.
const KernelPackage = "linux-rpi"

// bootloaderPackages carry the GPU firmware the Pi loads before U-Boot:
// start*.elf and fixup*.dat, and bootcode.bin for the boards whose boot ROM
// still needs it.
var bootloaderPackages = []string{"raspberrypi-bootloader", "raspberrypi-bootloader-common"}

// tokenPackages are the smart-card stack every Pi carries so a YubiKey or a
// Nitrokey HSM answers PKCS#11 on the node: pcsc-lite's pcscd daemon and its
// OpenRC script, the USB CCID reader driver both tokens speak through, OpenSC
// (opensc-pkcs11.so, the Nitrokey HSM / SmartCard-HSM module) and Yubico's
// libykcs11.so (the YubiKey PIV module).
var tokenPackages = []string{"pcsc-lite", "pcsc-lite-openrc", "ccid", "opensc", "yubico-piv-tool-libs"}

// tokenServices are the OpenRC services of the token stack the installed Pi
// starts at boot: pcscd, whose init script pcsc-lite-openrc ships.
var tokenServices = []string{"pcscd"}

// Model describes one board.
type Model struct {
	// Name is the --model value.
	Name string
	// Description is the board's name: what the operator sees, and the
	// hardware-model the image's platform config carries.
	Description string
	// DTB is the device tree the firmware loads for the board.
	DTB string
	// Firmware is the GPU firmware the board loads from the boot partition
	// before U-Boot. Empty for the Pi 5, whose bootloader EEPROM reads
	// config.txt and loads kernel8.img itself.
	Firmware []string
	// Experimental marks boards mainline U-Boot only recently gained
	// (validation on hardware is still owed).
	Experimental bool
	// SoC is the target-soc of the board's bootloader EEPROM ("2711" or
	// "2712"), which fetches and verifies a signed boot.img over HTTP. Empty
	// for a board with a boot ROM and no EEPROM (the 3B+), which cannot.
	SoC string
}

// models is the supported board table, keyed by --model.
var models = map[string]Model{
	"rpi4":   {Name: "rpi4", Description: "Raspberry Pi 4 Model B", DTB: "bcm2711-rpi-4-b.dtb", Firmware: pi4Firmware, SoC: "2711"},
	"rpi400": {Name: "rpi400", Description: "Raspberry Pi 400", DTB: "bcm2711-rpi-400.dtb", Firmware: pi4Firmware, SoC: "2711"}, // lab-string-ok: Raspberry Pi model name, not a lab host
	"cm4":    {Name: "cm4", Description: "Raspberry Pi Compute Module 4", DTB: "bcm2711-rpi-cm4.dtb", Firmware: pi4Firmware, SoC: "2711"},
	"rpi3b+": {Name: "rpi3b+", Description: "Raspberry Pi 3 Model B+", DTB: "bcm2710-rpi-3-b-plus.dtb", Firmware: []string{"bootcode.bin", "start.elf", "fixup.dat"}},
	"rpi5":   {Name: "rpi5", Description: "Raspberry Pi 5", DTB: "bcm2712-rpi-5-b.dtb", Experimental: true, SoC: "2712"},
}

// pi4Firmware is what the BCM2711 boards' EEPROM loads before U-Boot.
var pi4Firmware = []string{"start4.elf", "fixup4.dat"}

// DefaultModel is used when --model is not given.
const DefaultModel = "rpi4"

// Models lists the supported model names, sorted.
func Models() []string {
	names := make([]string, 0, len(models))
	for name := range models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LookupModel resolves a --model value.
func LookupModel(name string) (Model, error) {
	if name == "" {
		name = DefaultModel
	}
	m, ok := models[name]
	if !ok {
		return Model{}, &UnknownModelError{Model: name, Models: Models()}
	}
	return m, nil
}

// Target builds the Raspberry Pi image for one model.
type Target struct {
	Model Model
}

// New returns the target for model ("" means DefaultModel).
func New(model string) (*Target, error) {
	m, err := LookupModel(model)
	if err != nil {
		return nil, err
	}
	return &Target{Model: m}, nil
}

// Name implements diskimage.Target.
func (t *Target) Name() string { return Name }

// ModelName implements diskimage.Target: the model's name, "rpi4" for a
// Raspberry Pi 4.
func (t *Target) ModelName() string { return t.Model.Name }

// Architecture implements diskimage.Target.
func (t *Target) Architecture() uki.Architecture { return uki.ArchAArch64 }

// KernelPackage implements diskimage.Target.
func (t *Target) KernelPackage() string { return KernelPackage }

// ExtraPackages implements diskimage.Target: the firmware packages the boot
// partition is populated from, then the smart-card token stack.
func (t *Target) ExtraPackages() []string {
	return slices.Concat(bootloaderPackages, tokenPackages)
}

// UBootBoard implements diskimage.Target.
func (t *Target) UBootBoard() uboot.Board { return uboot.BoardRPiArm64 }

// BuiltKernel implements diskimage.Target: the Pi boots Alpine's linux-rpi
// package, which carries the SPI TPM transport its hardware uses.
func (t *Target) BuiltKernel() bool { return false }

// StageKernel implements diskimage.Target: nothing to stage for a
// packaged kernel.
func (t *Target) StageKernel(context.Context, string, *virtkernel.Artifacts) error { return nil }

// InstallerOverrides implements diskimage.Target: an MBR SD card, the Pi
// kernel, U-Boot as the boot firmware, pcscd started at boot and the
// Raspberry Pi quirk entry.
func (t *Target) InstallerOverrides() iso.InstallerOverrides {
	return iso.InstallerOverrides{
		Device:               "/dev/mmcblk0",
		PartitionTable:       "mbr",
		KernelPackage:        KernelPackage,
		ExtraPackages:        t.ExtraPackages(),
		ExtraServices:        slices.Clone(tokenServices),
		HardwareManufacturer: "Raspberry Pi",
		HardwareModel:        t.Model.Description,
		Target:               "image",
		BootFirmware:         "uboot",
	}
}

// ConfigTxt is the boot configuration the Raspberry Pi firmware reads.
//
//   - arm_64bit=1: load a 64-bit kernel8.img
//   - enable_uart=1 / uart_2ndstage=1: the primary UART is the console and
//     the firmware itself logs to it
//   - dtoverlay=disable-bt: move Bluetooth off the PL011 so it is ttyAMA0
//   - dtoverlay=tpm-soft-spi: the SLB9670 on SPI0 CE1 as a GPIO-driven bus,
//     for U-Boot (soft_spi) and Linux (spi-gpio) alike
//   - kernel=kernel8.img: U-Boot, which then boots EFI/BOOT/BOOTAA64.EFI
func ConfigTxt(m Model) string {
	lines := []string{
		"# Trusted Platform Raspberry Pi boot configuration (generated by platformctl diskimage)",
		"# Board: " + m.Description,
		"arm_64bit=1",
		"enable_uart=1",
		"uart_2ndstage=1",
		"dtoverlay=disable-bt",
		"dtoverlay=tpm-soft-spi",
		"kernel=kernel8.img",
	}
	return strings.Join(lines, "\n") + "\n"
}

// requiredFirmware must exist on the boot partition for the target model to
// start U-Boot at all.
func requiredFirmware(m Model) []string {
	files := []string{"kernel8.img", "config.txt", m.DTB, "overlays/tpm-soft-spi.dtbo", "overlays/disable-bt.dtbo"}
	return append(files, m.Firmware...)
}

// StageBootFirmware implements diskimage.Target: it fills
// <mediaDir>/boot-firmware with everything the Pi firmware and U-Boot read
// from the FAT partition, taking U-Boot and the TPM overlay from the
// builder output and the GPU firmware and device trees from the prefetched
// apks (so the image is built offline, from the same packages the node
// has installed).
func (t *Target) StageBootFirmware(ctx context.Context, mediaDir, prefetchDir string, art uboot.Artifacts) error {
	return t.StageBootFirmwareInto(ctx, filepath.Join(mediaDir, "boot-firmware"), prefetchDir, art)
}

// StageBootFirmwareInto fills dest with the boot partition's firmware
// set — what StageBootFirmware puts under the media directory, and what
// a network boot server serves a Pi over TFTP (pkg/rpinetboot).
func (t *Target) StageBootFirmwareInto(ctx context.Context, dest, prefetchDir string, art uboot.Artifacts) error {
	if err := os.RemoveAll(dest); err != nil {
		return &StageError{Step: "clearing the boot-firmware staging directory", Err: err}
	}
	if err := os.MkdirAll(filepath.Join(dest, "overlays"), 0o755); err != nil {
		return &StageError{Step: "creating the boot-firmware staging directory", Err: err}
	}

	if err := copyFile(art.Binary, filepath.Join(dest, "kernel8.img")); err != nil {
		return &StageError{Step: "staging U-Boot as kernel8.img", Err: err}
	}
	if err := copyFile(filepath.Join(art.OverlaysDir, "tpm-soft-spi.dtbo"), filepath.Join(dest, "overlays", "tpm-soft-spi.dtbo")); err != nil {
		return &StageError{Step: "staging the TPM overlay", Err: err}
	}

	for _, pkg := range bootloaderPackages {
		apk, err := findAPK(prefetchDir, pkg)
		if err != nil {
			return err
		}
		if _, err := artifacts.ExtractTarGz(apk, "boot/", dest, func(string) bool { return true }); err != nil {
			return &PackageError{Package: apk, Err: err}
		}
	}
	kernelAPK, err := findAPK(prefetchDir, KernelPackage)
	if err != nil {
		return err
	}
	if _, err := artifacts.ExtractTarGz(kernelAPK, "boot/", dest, func(rel string) bool {
		// Every board DTB, so one image boots any supported model, plus the
		// overlay config.txt references. The kernel itself lives in the UKI.
		return (strings.HasPrefix(rel, "bcm27") && strings.HasSuffix(rel, ".dtb")) || rel == "overlays/disable-bt.dtbo"
	}); err != nil {
		return &PackageError{Package: kernelAPK, Err: err}
	}

	if err := os.WriteFile(filepath.Join(dest, "config.txt"), []byte(ConfigTxt(t.Model)), 0o644); err != nil {
		return &StageError{Step: "writing config.txt", Err: err}
	}

	for _, rel := range requiredFirmware(t.Model) {
		if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
			return &FirmwareMissingError{File: rel}
		}
	}
	return nil
}

// copyFile copies src to dst, replacing dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

package qemu

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Arch names the guest CPU architecture a VM emulates.
type Arch string

const (
	// ArchX86_64 is the default: the q35 machine with OVMF, the
	// architecture every platform ISO test has always run on.
	ArchX86_64 Arch = "x86_64"
	// ArchAArch64 is the virt machine booted through U-Boot supplied as
	// -bios, the way the Raspberry Pi factory image is exercised without
	// the hardware (pkg/diskimage/qemuvirt).
	ArchAArch64 Arch = "aarch64"
)

// Disk formats a VM disk can be in.
const (
	DiskFormatQCOW2 = "qcow2"
	DiskFormatRaw   = "raw"
)

// archProfile is everything in the QEMU command line that differs by
// guest architecture. buildQEMUCommand consults the profile for the
// machine, CPU, disk controller, display, firmware and TPM front-end and
// keeps the architecture-neutral parts (memory, network, QMP, serial,
// RNG) in one place. The x86_64 profile reproduces the pre-profile
// command line byte for byte; TestBuildQEMUCommand_X86Golden pins it.
type archProfile struct {
	// binary is the default QEMU binary.
	binary string
	// romDirs are the directories probed for -L when a custom binary is
	// used, so a custom build finds its ROM files; nil means never.
	romDirs []string
	// kvmHostArch is the GOARCH of a host that can KVM-accelerate this
	// guest. Any other host runs TCG whatever Config.EnableKVM says.
	kvmHostArch string
	// diskFormat is the default disk image format.
	diskFormat string
	// tpmDevice is the TPM front-end device.
	tpmDevice string
	// nvram reports whether the firmware keeps its variables in a pflash
	// NVRAM file the VM must initialise from a template.
	nvram func(c *Config) bool
	// machine returns the -machine value.
	machine func(c *Config, kvm bool) string
	// cpu returns the -cpu value.
	cpu func(c *Config, kvm bool) string
	// disk returns the root disk's drive and device arguments.
	disk func(c *Config, format, cache string) []string
	// boot returns the mode-specific boot arguments: boot order, the
	// install CD-ROM, the display device the firmware expects.
	boot func(c *Config, mode BootMode) ([]string, error)
	// firmware returns the firmware arguments.
	firmware func(c *Config) ([]string, error)
}

// archProfiles dispatches Config.Arch to its profile.
var archProfiles = map[Arch]archProfile{
	ArchX86_64: {
		binary:      "qemu-system-x86_64",
		romDirs:     []string{"/usr/share/seabios", "/usr/share/qemu", "/usr/share/qemu-kvm"},
		kvmHostArch: "amd64",
		diskFormat:  DiskFormatQCOW2,
		tpmDevice:   "tpm-tis",
		nvram:       func(*Config) bool { return true },
		machine:     x86Machine,
		cpu:         x86CPU,
		disk:        x86Disk,
		boot:        x86Boot,
		firmware:    x86Firmware,
	},
	ArchAArch64: {
		binary:      "qemu-system-aarch64",
		kvmHostArch: "arm64",
		diskFormat:  DiskFormatRaw,
		tpmDevice:   "tpm-tis-device",
		nvram:       aarch64UEFI,
		machine:     aarch64Machine,
		cpu:         aarch64CPU,
		disk:        aarch64Disk,
		boot:        aarch64Boot,
		firmware:    aarch64Firmware,
	},
}

// arch returns the configured architecture, x86_64 when unset.
func (c *Config) arch() Arch {
	return c.Arch.OrDefault()
}

// OrDefault returns a, or x86_64 when a is empty: the guest a Config without
// an Arch builds.
func (a Arch) OrDefault() Arch {
	if a == "" {
		return ArchX86_64
	}
	return a
}

// profile resolves the configured architecture's profile.
func (c *Config) profile() (archProfile, error) {
	p, ok := archProfiles[c.arch()]
	if !ok {
		return archProfile{}, &SentinelCauseError{Sentinel: ErrUnsupportedArch, Cause: &MessageError{Msg: string(c.Arch)}}
	}
	return p, nil
}

// qemuBinary returns the configured binary or the profile's default.
func (c *Config) qemuBinary(p archProfile) string {
	if c.QEMUBinary != "" {
		return c.QEMUBinary
	}
	return p.binary
}

// kvm reports whether the guest runs under KVM: the caller asked for it,
// the host can provide it for this guest architecture, and the KVM device
// opens read-write. Emulating a foreign architecture always runs TCG. When
// KVM was asked for but the device is unusable, the guest runs TCG and the
// error says why.
func (c *Config) kvm(p archProfile) (bool, error) {
	if !c.EnableKVM || c.hostArch() != p.kvmHostArch {
		return false, nil
	}
	probe := c.KVMProbe
	if probe == nil {
		probe = probeKVMDevice
	}
	if err := probe(); err != nil {
		return false, err
	}
	return true, nil
}

// kvmDevice is the KVM device QEMU opens for -enable-kvm.
const kvmDevice = "/dev/kvm"

// probeKVMDevice opens the KVM device read-write, as QEMU does, and closes
// it again. A host without the device, or a user without access to it,
// makes QEMU exit at once with "failed to initialize kvm".
func probeKVMDevice() error {
	return probeDeviceRW(kvmDevice)
}

// probeDeviceRW opens path read-write and closes it again.
func probeDeviceRW(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrKVMUnavailable, Cause: err}
	}
	return f.Close()
}

// hostArch is the GOARCH QEMU runs on: Config.HostArch, else the running
// binary's.
func (c *Config) hostArch() string {
	if c.HostArch != "" {
		return c.HostArch
	}
	return runtime.GOARCH
}

// diskFormat returns the configured disk format or the profile's default.
func (c *Config) diskFormat(p archProfile) string {
	if c.DiskFormat != "" {
		return c.DiskFormat
	}
	return p.diskFormat
}

// tpmDevice returns the configured TPM front-end or the profile's default.
func (c *Config) tpmDevice(p archProfile) string {
	if c.TPMDevice != "" {
		return c.TPMDevice
	}
	return p.tpmDevice
}

// x86Machine selects q35, with SMM only when Secure Boot needs it: SMM is
// required for a Secure Boot OVMF but can trip KVM emulation
// (cpu_asidx_from_attrs assertion failures) when it is not.
func x86Machine(c *Config, _ bool) string {
	if c.SecureBoot {
		return "q35,smm=on"
	}
	return "q35"
}

// x86CPU passes the host CPU through under KVM. TCG cannot take "host"
// (QEMU: "CPU model 'host' requires KVM or HVF"), so it emulates "max",
// every feature TCG supports.
func x86CPU(_ *Config, kvm bool) string {
	if kvm {
		return "host"
	}
	return "max"
}

// x86Disk attaches the disk through AHCI, not virtio: Ubuntu's OVMF has
// no VirtioBlkDxe driver, so it cannot read a virtio disk during UEFI boot
// discovery, while its AhciDxe reads SATA. install.yaml's device=/dev/sda
// is that SATA disk.
func x86Disk(c *Config, format, cache string) []string {
	return []string{
		"-drive", fmt.Sprintf("file=%s,if=none,format=%s,cache=%s,id=hd0", c.DiskPath, format, cache),
		"-device", "ahci,id=ahci0",
		"-device", "ide-hd,drive=hd0,bus=ahci0.0",
	}
}

// x86Boot returns the boot order and display device for a mode. OVMF
// expects a display device even in nographic mode, or boot may fail
// silently; the install CD-ROM goes on the AHCI controller so OVMF
// enumerates it beside the disk (a separate -cdrom IDE device may not
// appear in its boot order).
func x86Boot(c *Config, mode BootMode) ([]string, error) {
	switch mode {
	case BootModeInstall:
		args := []string{"-boot", "order=" + c.BootOrder}
		if c.ISO != "" {
			args = append(args,
				"-drive", fmt.Sprintf("file=%s,if=none,media=cdrom,readonly=on,id=cd0", c.ISO),
				"-device", "ide-cd,drive=cd0,bus=ahci0.1",
			)
		}
		return append(args, "-device", "VGA"), nil
	case BootModeBoot:
		return append([]string{"-boot", "menu=on,strict=off"}, x86Display(c)...), nil
	case BootModePXE:
		// n = network first; menu=on lets the user pick another device;
		// strict=off falls back to the other devices when PXE fails.
		return append([]string{"-boot", "order=n,menu=on,strict=off"}, x86Display(c)...), nil
	}
	return nil, ErrInvalidMode
}

// x86Display is the display device: plain VGA when headless, virtio-vga
// when a display is wanted.
func x86Display(c *Config) []string {
	if c.NoGraphic {
		return []string{"-device", "VGA"}
	}
	return []string{"-device", "virtio-vga"}
}

// x86Firmware is OVMF in two pflash drives: the code (the Secure Boot
// build when Secure Boot is on) and the NVRAM copied from the template.
// The same firmware must serve install and boot: mixing a non-secboot
// install with a secboot boot leaves NVRAM state that crashes QEMU. With
// Secure Boot the flash is marked secure so SMM protects it.
func x86Firmware(c *Config) ([]string, error) {
	args := pflashArgs(c)
	if c.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	return args, nil
}

// aarch64CPU is the host CPU under KVM and a Cortex-A72 (the Raspberry Pi
// 4's core) under TCG.
// aarch64Machine returns the virt machine with a GIC the accelerator can
// provide. Under KVM the interrupt controller is the host's own, and a
// Raspberry Pi 4's GIC-400 is GICv2 only, so a fixed gic-version=3 stops
// QEMU before the guest boots; gic-version=host takes whatever the host
// provides (QEMU docs/system/arm/virt.rst, "gic-version": "host: Use the
// same GIC version the host provides, when using KVM"). TCG emulates the
// GIC and cannot take "host", so it keeps a fixed GICv3.
func aarch64Machine(_ *Config, kvm bool) string {
	if kvm {
		return "virt,gic-version=host"
	}
	return "virt,gic-version=3"
}

func aarch64CPU(_ *Config, kvm bool) string {
	if kvm {
		return "host"
	}
	return "cortex-a72"
}

// aarch64Disk is a virtio-blk disk: the virt machine has no AHCI, U-Boot
// and the Alpine aarch64 kernel both drive virtio, and the image was
// installed against /dev/vda.
func aarch64Disk(c *Config, format, cache string) []string {
	return []string{
		"-drive", fmt.Sprintf("file=%s,if=none,format=%s,cache=%s,id=hd0", c.DiskPath, format, cache),
		"-device", "virtio-blk-pci,drive=hd0",
	}
}

// aarch64Boot: U-Boot's standard boot flow finds EFI/BOOT/BOOTAA64.EFI on
// the first FAT partition by itself, the virt machine ignores -boot, and
// no display device is needed. There is no aarch64 install ISO, so
// install mode is refused rather than silently booting the disk.
func aarch64Boot(_ *Config, mode BootMode) ([]string, error) {
	switch mode {
	case BootModeBoot, BootModePXE:
		return nil, nil
	case BootModeInstall:
		return nil, &SentinelCauseError{Sentinel: ErrUnsupportedBootMode, Cause: &MessageError{Msg: "aarch64 has no install ISO; boot a factory image instead"}}
	}
	return nil, ErrInvalidMode
}

// pflashArgs are the two UEFI pflash drives: the code read-only (the Secure
// Boot build when Secure Boot is on) and the per-instance NVRAM copied from
// the vars template.
func pflashArgs(c *Config) []string {
	return []string{
		"-drive", fmt.Sprintf("if=pflash,unit=0,format=raw,readonly=on,file=%s", c.GetOVMFCodePath()),
		"-drive", fmt.Sprintf("if=pflash,unit=1,format=raw,file=%s", c.GetNVRAMPath()),
	}
}

// aarch64UEFI reports whether an aarch64 guest boots UEFI (AAVMF) from
// pflash instead of U-Boot as -bios: the firmware code path is set and no
// -bios image is.
func aarch64UEFI(c *Config) bool {
	return c.Firmware == "" && c.OVMFCode != ""
}

// aarch64Firmware is AAVMF in two pflash drives when aarch64UEFI holds,
// otherwise U-Boot as -bios. The virt machine has no SMM, so the flash is
// never marked secure. U-Boot keeps its EFI variables in ubootefi.var on
// the ESP (EFI_VARIABLE_FILE_STORE), so it has no NVRAM file to initialise.
func aarch64Firmware(c *Config) ([]string, error) {
	if aarch64UEFI(c) {
		return pflashArgs(c), nil
	}
	if c.Firmware == "" {
		return nil, &SentinelCauseError{Sentinel: ErrFirmwareMissing, Cause: &MessageError{Msg: "Config.Firmware (u-boot.bin) is required for aarch64"}}
	}
	if _, err := os.Stat(c.Firmware); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFirmwareMissing, Cause: &MessageError{Msg: c.Firmware}}
	}
	return []string{"-bios", c.Firmware}, nil
}

// romDirArgs returns -L for the first ROM directory that holds the VGA
// BIOS, when the profile has ROM directories and a custom binary is in
// use; a custom build (the CanoKey QEMU) does not know where the
// distribution keeps them. The comparison is against the configured
// string, not the resolved binary: an empty QEMUBinary has always probed
// (DefaultConfig sets it explicitly), and the x86 golden test holds the
// command line to what it was.
func romDirArgs(c *Config, p archProfile) []string {
	if c.QEMUBinary == p.binary {
		return nil
	}
	for _, dir := range p.romDirs {
		if _, err := os.Stat(filepath.Join(dir, "vgabios-stdvga.bin")); err == nil {
			return []string{"-L", dir}
		}
	}
	return nil
}

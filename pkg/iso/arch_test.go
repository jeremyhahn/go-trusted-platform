package iso

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// writeMinimalELF writes a 64-bit little-endian ELF executable header with no
// program or section headers, which debug/elf accepts, for the given machine.
func writeMinimalELF(t *testing.T, dir, name string, machine elf.Machine) string {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(hdr[18:], uint16(machine))
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint16(hdr[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(hdr[54:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(hdr[58:], 64) // e_shentsize
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, hdr, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func validPlatformISOConfig() *PlatformISOConfig {
	return &PlatformISOConfig{
		Alpine:      AlpineConfig{Version: "3.22.2", Mirror: "http://example.com/alpine"},
		Directories: DirectoryConfig{Work: "work"},
		Platform:    PlatformConfig{Version: "1.0.0"},
		RootFS:      RootFSConfig{Type: "lvm"},
	}
}

func TestPlatformISOConfigArchitectureValidation(t *testing.T) {
	for _, arch := range []string{"", "x86_64", "amd64", "aarch64", "arm64"} {
		cfg := validPlatformISOConfig()
		cfg.Alpine.Architecture = arch
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected architecture %q: %v", arch, err)
		}
	}
	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "mips"
	var unsupported *UnsupportedArchitectureError
	if err := cfg.Validate(); !errors.As(err, &unsupported) || unsupported.Arch != "mips" {
		t.Errorf("Validate() error = %v, want *UnsupportedArchitectureError{mips}", err)
	}

	cfg = validPlatformISOConfig()
	cfg.Alpine.Architecture = "aarch64"
	cfg.Security.FIPS = true
	var fips *FIPSUnsupportedArchitectureError
	if err := cfg.Validate(); !errors.As(err, &fips) || fips.Arch != "aarch64" {
		t.Errorf("Validate() error = %v, want *FIPSUnsupportedArchitectureError{aarch64}", err)
	}
	cfg.Alpine.Architecture = "x86_64"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() rejected FIPS on x86_64: %v", err)
	}

	cfg = validPlatformISOConfig()
	cfg.Installer.PartitionTable = "apm"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "partition_table") {
		t.Errorf("Validate() accepted partition table apm: %v", err)
	}
	for _, table := range []string{"", "gpt", "mbr"} {
		cfg.Installer.PartitionTable = table
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected partition table %q: %v", table, err)
		}
	}
}

func TestPlatformISOConfigSetDefaultsCanonicalisesArchitecture(t *testing.T) {
	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "arm64"
	cfg.SetDefaults()
	if cfg.Alpine.Architecture != "aarch64" {
		t.Errorf("SetDefaults left architecture %q, want aarch64", cfg.Alpine.Architecture)
	}
	if cfg.architecture() != uki.ArchAArch64 {
		t.Errorf("architecture() = %q", cfg.architecture())
	}

	cfg = validPlatformISOConfig()
	cfg.SetDefaults()
	if cfg.Alpine.Architecture != "x86_64" || cfg.architecture() != uki.ArchX86_64 {
		t.Errorf("SetDefaults defaulted architecture to %q", cfg.Alpine.Architecture)
	}

	cfg = validPlatformISOConfig()
	cfg.Alpine.Architecture = "mips"
	cfg.SetDefaults()
	if cfg.Alpine.Architecture != "mips" {
		t.Errorf("SetDefaults rewrote an unknown architecture to %q; Validate must reject it instead", cfg.Alpine.Architecture)
	}
}

func TestValidateBinaryChecksMachine(t *testing.T) {
	dir := t.TempDir()
	arm := writeMinimalELF(t, dir, "platformd-arm64", elf.EM_AARCH64)
	x86 := writeMinimalELF(t, dir, "platformd-x86", elf.EM_X86_64)

	if err := validateBinary(arm, elf.EM_AARCH64); err != nil {
		t.Errorf("aarch64 binary rejected for aarch64: %v", err)
	}
	if err := validateBinary(x86, elf.EM_X86_64); err != nil {
		t.Errorf("x86_64 binary rejected for x86_64: %v", err)
	}
	var mismatch *BinaryArchMismatchError
	err := validateBinary(arm, elf.EM_X86_64)
	if !errors.As(err, &mismatch) || mismatch.Want != elf.EM_X86_64 || mismatch.Got != elf.EM_AARCH64 || mismatch.Path != arm {
		t.Fatalf("validateBinary(arm, x86_64) error = %v, want *BinaryArchMismatchError", err)
	}
	if !strings.Contains(err.Error(), "EM_AARCH64") || !strings.Contains(err.Error(), "EM_X86_64") {
		t.Errorf("error does not name both machines: %v", err)
	}
}

func TestValidateTargetBinaryFollowsConfiguredArchitecture(t *testing.T) {
	dir := t.TempDir()
	arm := writeMinimalELF(t, dir, "platformd-arm64", elf.EM_AARCH64)
	x86 := writeMinimalELF(t, dir, "platformd-x86", elf.EM_X86_64)

	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "aarch64"
	c := NewCustomizer(cfg, logging.DefaultLogger())
	if err := c.validateTargetBinary(arm); err != nil {
		t.Errorf("aarch64 media rejected an aarch64 binary: %v", err)
	}
	if err := c.validateTargetBinary(x86); err == nil {
		t.Error("aarch64 media accepted an x86_64 binary")
	}

	cfg = validPlatformISOConfig() // architecture unset: historical x86_64 behaviour
	c = NewCustomizer(cfg, logging.DefaultLogger())
	if err := c.validateTargetBinary(x86); err != nil {
		t.Errorf("default media rejected an x86_64 binary: %v", err)
	}
	if err := c.validateTargetBinary(arm); err == nil {
		t.Error("default media accepted an aarch64 binary")
	}

	cfg = validPlatformISOConfig()
	cfg.Alpine.Architecture = "arm" // parses, but no ELF machine is mapped for it
	c = NewCustomizer(cfg, logging.DefaultLogger())
	var unsupported *UnsupportedArchitectureError
	if err := c.validateTargetBinary(arm); !errors.As(err, &unsupported) {
		t.Errorf("validateTargetBinary for arm error = %v, want *UnsupportedArchitectureError", err)
	}
}

func TestBuildInstallerConfigAppliesInstallerOverrides(t *testing.T) {
	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "arm64"
	cfg.SetDefaults()
	cfg.Installer = InstallerOverrides{
		Device:               "/dev/mmcblk0",
		PartitionTable:       "mbr",
		KernelPackage:        "linux-rpi",
		ExtraPackages:        []string{"raspberrypi-bootloader"},
		HardwareManufacturer: "Raspberry Pi",
		HardwareModel:        "Raspberry Pi 4 Model B",
	}
	c := NewCustomizer(cfg, logging.DefaultLogger())
	got, err := c.buildInstallerConfig()
	if err != nil {
		t.Fatalf("buildInstallerConfig: %v", err)
	}
	if got.Disk.Device != "/dev/mmcblk0" || got.Disk.PartitionTable != installer.PartitionTableMBR {
		t.Errorf("disk = %+v", got.Disk)
	}
	if got.OS.Architecture != "aarch64" || got.OS.KernelPackage != "linux-rpi" {
		t.Errorf("os arch/kernel = %q/%q", got.OS.Architecture, got.OS.KernelPackage)
	}
	if len(got.OS.Packages) != 1 || got.OS.Packages[0] != "raspberrypi-bootloader" {
		t.Errorf("os packages = %v", got.OS.Packages)
	}
	if got.HardwareManufacturer != "Raspberry Pi" || got.HardwareModel != "Raspberry Pi 4 Model B" {
		t.Errorf("hardware identity = %q / %q", got.HardwareManufacturer, got.HardwareModel)
	}

	// Without overrides the x86_64 ISO defaults are byte-for-byte what they were.
	plain := validPlatformISOConfig()
	plain.SetDefaults()
	got, err = NewCustomizer(plain, logging.DefaultLogger()).buildInstallerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Disk.Device != "/dev/sda" || got.Disk.PartitionTable != installer.PartitionTableGPT ||
		got.OS.Architecture != "x86_64" || got.OS.KernelPackage != "" || len(got.OS.Packages) != 0 ||
		got.HardwareManufacturer != "" || got.HardwareModel != "" {
		t.Errorf("defaults changed: disk=%+v os=%+v hw=%q/%q", got.Disk, got.OS, got.HardwareManufacturer, got.HardwareModel)
	}
}

func TestBuildKernelCmdlineResolvesHardwareQuirk(t *testing.T) {
	plain := validPlatformISOConfig()
	plain.SetDefaults()
	defaultLine := NewCustomizer(plain, logging.DefaultLogger()).buildKernelCmdline()
	for _, p := range quirks.Default().KernelCmdline {
		if !strings.Contains(defaultLine, p) {
			t.Errorf("default cmdline %q lacks default quirk param %q", defaultLine, p)
		}
	}

	cfg := validPlatformISOConfig()
	cfg.SetDefaults()
	cfg.Installer.HardwareManufacturer = "Supermicro"
	c := NewCustomizer(cfg, logging.DefaultLogger())
	q := c.targetQuirk()
	if q.Key == "default" {
		t.Fatal("targetQuirk() resolved the default entry for Supermicro")
	}
	line := c.buildKernelCmdline()
	for _, p := range q.KernelCmdline {
		if !strings.Contains(line, p) {
			t.Errorf("cmdline %q lacks quirk param %q", line, p)
		}
	}

	// An unknown vendor resolves to the default entry, not an empty one.
	cfg.Installer.HardwareManufacturer = "No Such Vendor"
	if got := NewCustomizer(cfg, logging.DefaultLogger()).targetQuirk(); got.Key != "default" {
		t.Errorf("unknown vendor resolved to %q", got.Key)
	}
}

func TestPreFetchKernelPackage(t *testing.T) {
	base := &PreFetchConfig{Mirror: "http://example.com", Version: "3.22", Architecture: "x86_64"}
	if base.kernelPackage() != "linux-lts" {
		t.Errorf("kernelPackage() default = %q", base.kernelPackage())
	}
	pkgs := CollectRequiredPackages(base)
	if !contains(pkgs, "linux-lts") {
		t.Errorf("default package set lacks linux-lts: %v", pkgs)
	}

	rpi := &PreFetchConfig{Mirror: "http://example.com", Version: "3.22", Architecture: "aarch64", KernelPackage: "linux-rpi"}
	pkgs = CollectRequiredPackages(rpi)
	if !contains(pkgs, "linux-rpi") || contains(pkgs, "linux-lts") {
		t.Errorf("linux-rpi package set = %v", pkgs)
	}

	fips := &PreFetchConfig{Mirror: "http://example.com", Version: "3.22", Architecture: "x86_64", FIPS: true, KernelPackage: "linux-rpi"}
	if pkgs = CollectRequiredPackages(fips); contains(pkgs, "linux-rpi") || contains(pkgs, "linux-lts") {
		t.Errorf("FIPS package set must carry no stock kernel: %v", pkgs)
	}

	// A platform-built kernel on the media: the package is named for its
	// flavour but never prefetched; the firmware stubs still are.
	built := &PreFetchConfig{Mirror: "http://example.com", Version: "3.22", Architecture: "aarch64", KernelPackage: "linux-virt", SkipKernel: true}
	if pkgs = CollectRequiredPackages(built); contains(pkgs, "linux-virt") || contains(pkgs, "linux-lts") {
		t.Errorf("built-kernel package set must carry no kernel apk: %v", pkgs)
	} else if !contains(pkgs, "linux-firmware-none") {
		t.Errorf("built-kernel package set lacks the firmware stub: %v", pkgs)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestBuildPreFetchRepositoryUsesConfiguredArchitecture(t *testing.T) {
	// The builder is exercised through its config translation only: an
	// unreachable mirror fails before any network call is needed to prove
	// the architecture and kernel package reached PreFetchConfig.
	cfg := validPlatformISOConfig()
	cfg.Alpine.Architecture = "aarch64"
	cfg.Alpine.Mirror = "http://127.0.0.1:1/alpine"
	cfg.Directories.Work = t.TempDir()
	cfg.SetDefaults()
	cfg.Installer.KernelPackage = "linux-rpi"
	c := NewCustomizer(cfg, logging.DefaultLogger())
	err := c.BuildPreFetchRepository(context.Background())
	if err == nil {
		t.Fatal("BuildPreFetchRepository succeeded against an unreachable mirror")
	}
	if strings.Contains(err.Error(), "x86_64") {
		t.Errorf("aarch64 build reached for an x86_64 repository: %v", err)
	}
}

func TestStageMediaStagesWithoutLiveISOTooling(t *testing.T) {
	work := t.TempDir()
	cfg := validPlatformISOConfig()
	cfg.Directories.Work = work
	cfg.Platform.ConfigServerURL = "https://config.example.invalid" // dynamic config: nothing to embed
	cfg.Build.PreFetch = false
	cfg.SetDefaults()
	c := NewCustomizer(cfg, logging.DefaultLogger())
	if err := c.StageMedia(context.Background()); err != nil {
		t.Fatalf("StageMedia: %v", err)
	}
	for _, rel := range []string{
		filepath.Join("dracut-platformd", "90platformd", "module-setup.sh"),
		SecureBootKeysISODirName,
	} {
		if _, err := os.Stat(filepath.Join(cfg.Directories.ISO, rel)); err != nil {
			t.Errorf("StageMedia did not stage %s: %v", rel, err)
		}
	}
	// The live-ISO half needs an extracted Alpine ISO and must not have run.
	if _, err := os.Stat(filepath.Join(cfg.Directories.ISO, "boot", "grub", "grub.cfg")); err == nil {
		t.Error("StageMedia rewrote the GRUB configuration, which belongs to customizeLiveISO")
	}
}

func TestISOConfigValidateDerivesArchitecturePaths(t *testing.T) {
	cfg := DefaultISOConfig()
	cfg.Architecture = "arm64"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Architecture != "aarch64" || cfg.ISO != "alpine-standard-3.22.2-aarch64.iso" ||
		cfg.URL != "http://mirror.cs.odu.edu/alpine/v3.22/releases/aarch64/alpine-standard-3.22.2-aarch64.iso" {
		t.Errorf("derived arch=%q iso=%q url=%q", cfg.Architecture, cfg.ISO, cfg.URL)
	}

	cfg = DefaultISOConfig()
	cfg.Architecture = ""
	if err := cfg.Validate(); err != nil || cfg.ISO != "alpine-standard-3.22.2-x86_64.iso" {
		t.Errorf("empty architecture: iso=%q err=%v", cfg.ISO, err)
	}

	cfg = DefaultISOConfig()
	cfg.Architecture = "mips"
	var unsupported *UnsupportedArchitectureError
	if err := cfg.Validate(); !errors.As(err, &unsupported) {
		t.Errorf("Validate(mips) error = %v", err)
	}
}

func TestInstallerOverridesTargetAndBootFirmware(t *testing.T) {
	cfg := validPlatformISOConfig()
	cfg.SetDefaults()
	cfg.Installer.Target = "image"
	cfg.Installer.BootFirmware = "uboot"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := NewCustomizer(cfg, logging.DefaultLogger()).buildInstallerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != installer.InstallTargetImage || got.Boot == nil || got.Boot.Firmware != installer.BootFirmwareUBoot {
		t.Errorf("target/boot = %q/%+v", got.Target, got.Boot)
	}

	plain := validPlatformISOConfig()
	plain.SetDefaults()
	got, err = NewCustomizer(plain, logging.DefaultLogger()).buildInstallerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != "" || got.Boot != nil {
		t.Errorf("defaults changed: target=%q boot=%+v", got.Target, got.Boot)
	}

	for field, value := range map[string]string{"target": "usb", "boot_firmware": "coreboot"} {
		bad := validPlatformISOConfig()
		if field == "target" {
			bad.Installer.Target = value
		} else {
			bad.Installer.BootFirmware = value
		}
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("Validate() accepted %s=%q: %v", field, value, err)
		}
	}
}

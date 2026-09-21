package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidateTargetAndBootFirmware(t *testing.T) {
	base := func() *Config {
		return &Config{Disk: &DiskConfig{Device: "/dev/loop0"}, OS: &OSConfig{Architecture: "aarch64"}}
	}
	for _, target := range []InstallTarget{"", InstallTargetDisk, InstallTargetImage} {
		cfg := base()
		cfg.Target = target
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected target %q: %v", target, err)
		}
	}
	cfg := base()
	cfg.Target = "usb"
	var invalid *InstallerError
	if err := cfg.Validate(); !errors.As(err, &invalid) || invalid.Type != ErrorTypeInvalidConfig || !strings.Contains(err.Error(), "usb") {
		t.Errorf("Validate() error for target usb = %v", err)
	}
	for _, fw := range []BootFirmwareType{"", BootFirmwareUEFI, BootFirmwareUBoot} {
		cfg = base()
		cfg.Boot = &BootConfig{Firmware: fw}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected firmware %q: %v", fw, err)
		}
	}
	cfg = base()
	cfg.Boot = &BootConfig{Firmware: "coreboot"}
	if err := cfg.Validate(); !errors.As(err, &invalid) || !strings.Contains(err.Error(), "coreboot") {
		t.Errorf("Validate() error for firmware coreboot = %v", err)
	}
}

func TestBootFirmwareDispatch(t *testing.T) {
	inst := &installer{logger: createTestLogger()}
	if inst.bootFirmwareType() != BootFirmwareUEFI {
		t.Errorf("zero-value installer resolved firmware %q, want uefi", inst.bootFirmwareType())
	}
	fw, err := inst.bootFirmware()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fw.(uefiFirmware); !ok {
		t.Errorf("default firmware is %T, want uefiFirmware", fw)
	}

	inst.config = &Config{Boot: &BootConfig{Firmware: BootFirmwareUBoot}}
	fw, err = inst.bootFirmware()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fw.(ubootFirmware); !ok {
		t.Errorf("uboot firmware is %T", fw)
	}

	inst.config = &Config{Boot: &BootConfig{Firmware: "coreboot"}}
	if _, err := inst.bootFirmware(); err == nil {
		t.Error("bootFirmware() accepted an unknown firmware")
	}
}

func TestImageTargetSkips(t *testing.T) {
	disk := &installer{config: &Config{Target: InstallTargetDisk}}
	image := &installer{config: &Config{Target: InstallTargetImage}}
	zero := &installer{}
	for _, step := range []installStep{stepClearTPM, stepTPMDevicePresence, stepFIDO2AutoEnroll, stepHostCmdlinePropagation} {
		if disk.skip(step) || zero.skip(step) {
			t.Errorf("step %d skipped for a disk target", step)
		}
		if !image.skip(step) {
			t.Errorf("step %d not skipped for an image target", step)
		}
	}
}

// stageFirmware builds a fake staged boot-firmware tree.
func stageFirmware(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"kernel8.img":               "u-boot",
		"config.txt":                "arm_64bit=1\nkernel=kernel8.img\n",
		"bcm2711-rpi-4-b.dtb":       "dtb",
		"overlays/tpm-slb9670.dtbo": "dtbo",
		"overlays/disable-bt.dtbo":  "dtbo",
		"start4.elf":                "firmware",
	}
	for rel, body := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCopyTreeCopiesFilesAndRefusesSymlinks(t *testing.T) {
	src := stageFirmware(t)
	dst := t.TempDir()
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	for _, rel := range []string{"kernel8.img", "config.txt", "overlays/tpm-slb9670.dtbo", "start4.elf"} {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("%s not copied: %v", rel, err)
			continue
		}
		want, _ := os.ReadFile(filepath.Join(src, rel))
		if string(got) != string(want) {
			t.Errorf("%s content differs", rel)
		}
	}
	// Re-copy over an existing tree replaces files rather than failing.
	if err := os.WriteFile(filepath.Join(src, "config.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("second copyTree: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "config.txt")); string(got) != "changed" {
		t.Errorf("config.txt not replaced: %q", got)
	}

	if err := os.Symlink("kernel8.img", filepath.Join(src, "kernel.img")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, t.TempDir()); err == nil {
		t.Error("copyTree accepted a symlink")
	}
	if err := copyTree(filepath.Join(src, "does-not-exist"), t.TempDir()); err == nil {
		t.Error("copyTree accepted a missing source")
	}
}

func TestWriteProvisionedSentinel(t *testing.T) {
	esp := t.TempDir()
	if err := writeProvisionedSentinel(esp); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(esp, "EFI", "TRUSTED_PLATFORM", "PROVISIONED"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "TRUSTED_PLATFORM=1\n" {
		t.Errorf("sentinel = %q", got)
	}
	// An unwritable ESP is an error, not a warning.
	file := filepath.Join(esp, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeProvisionedSentinel(file); err == nil {
		t.Error("writeProvisionedSentinel succeeded under a regular file")
	}
}

func TestUBootConfigureBootStagesFirmware(t *testing.T) {
	stage := stageFirmware(t)
	esp := t.TempDir()
	inst := &installer{logger: createTestLogger(), espRoot: esp, config: &Config{
		Boot: &BootConfig{Firmware: BootFirmwareUBoot, FirmwareStageDir: stage},
	}}
	if err := (ubootFirmware{}).ConfigureBoot(context.Background(), inst, &DiskInfo{Device: "/dev/loop0"}); err != nil {
		t.Fatalf("ConfigureBoot: %v", err)
	}
	for _, rel := range []string{"kernel8.img", "config.txt", "overlays/tpm-slb9670.dtbo", "start4.elf", "EFI/TRUSTED_PLATFORM/PROVISIONED"} {
		if _, err := os.Stat(filepath.Join(esp, rel)); err != nil {
			t.Errorf("ESP lacks %s after ConfigureBoot: %v", rel, err)
		}
	}
	// Nothing UEFI-only was written: no startup.nsh, no NVRAM entry.
	if _, err := os.Stat(filepath.Join(esp, "startup.nsh")); err == nil {
		t.Error("U-Boot target wrote startup.nsh")
	}

	// A missing staging directory is a typed error naming the path.
	inst.config.Boot.FirmwareStageDir = filepath.Join(t.TempDir(), "absent")
	err := ubootFirmware{}.ConfigureBoot(context.Background(), inst, &DiskInfo{Device: "/dev/loop0"})
	var typed *InstallerError
	if !errors.As(err, &typed) {
		t.Fatalf("ConfigureBoot with a missing stage dir error = %v, want *InstallerError", err)
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error does not name the staging directory: %v", err)
	}

	// A file where the directory should be is refused too.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	inst.config.Boot.FirmwareStageDir = file
	if err := (ubootFirmware{}).ConfigureBoot(context.Background(), inst, nil); !errors.As(err, &typed) {
		t.Errorf("ConfigureBoot with a file stage path error = %v", err)
	}

	// The default staging directory is the install media's boot-firmware/.
	if defaultFirmwareStageDir != filepath.Join(isoMediaMount, "boot-firmware") {
		t.Errorf("defaultFirmwareStageDir = %q", defaultFirmwareStageDir)
	}
	if zero := (&installer{}).espRootDir(); zero != "/mnt/boot/efi" {
		t.Errorf("espRootDir() default = %q", zero)
	}
}

func TestUBootEnforceSecureBootIsANoOp(t *testing.T) {
	inst := &installer{logger: createTestLogger(), config: &Config{
		Boot:       &BootConfig{Firmware: BootFirmwareUBoot},
		SecureBoot: &SecureBootConfig{Enabled: true, Enforce: true},
	}}
	if err := (ubootFirmware{}).EnforceSecureBoot(context.Background(), inst, nil); err != nil {
		t.Errorf("EnforceSecureBoot = %v, want nil (keys are preseeded in U-Boot)", err)
	}
	inst.config.SecureBoot = nil
	if err := (ubootFirmware{}).EnforceSecureBoot(context.Background(), inst, nil); err != nil {
		t.Errorf("EnforceSecureBoot without Secure Boot = %v", err)
	}
}

func TestErrorConstructors(t *testing.T) {
	for _, err := range []error{ErrUnknownInstallTarget("usb"), ErrUnknownBootFirmware("coreboot"), ErrBootFirmwareStage("copy", os.ErrNotExist)} {
		var typed *InstallerError
		if !errors.As(err, &typed) {
			t.Errorf("%v is not an *InstallerError", err)
		}
	}
	if !errors.Is(ErrBootFirmwareStage("copy", os.ErrNotExist), os.ErrNotExist) {
		t.Error("ErrBootFirmwareStage does not unwrap its cause")
	}
}

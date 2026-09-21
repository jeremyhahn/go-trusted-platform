package installer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

func TestResolveBootTarget(t *testing.T) {
	tests := []struct {
		name    string
		arch    string
		uki     string
		stub    string
		drivers string
	}{
		{"empty defaults to x86_64", "", "BOOTX64.EFI", uki.DefaultStubPath, dracutDriversX86},
		{"x86_64", "x86_64", "BOOTX64.EFI", uki.DefaultStubPath, dracutDriversX86},
		{"amd64 alias", "amd64", "BOOTX64.EFI", uki.DefaultStubPath, dracutDriversX86},
		{"aarch64", "aarch64", "BOOTAA64.EFI", "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub", dracutDriversAArch64},
		{"arm64 alias", "arm64", "BOOTAA64.EFI", "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub", dracutDriversAArch64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bt, err := resolveBootTarget(tc.arch)
			if err != nil {
				t.Fatalf("resolveBootTarget(%q): %v", tc.arch, err)
			}
			if bt.ukiFileName != tc.uki || bt.stubPath != tc.stub || bt.dracutDrivers != tc.drivers {
				t.Errorf("resolveBootTarget(%q) = %+v", tc.arch, bt)
			}
		})
	}
}

func TestResolveBootTargetRejectsUnsupported(t *testing.T) {
	for _, arch := range []string{"mips", "x86", "ARM64", "riscv64", "arm"} {
		_, err := resolveBootTarget(arch)
		if err == nil {
			t.Errorf("resolveBootTarget(%q) accepted an architecture with no driver set", arch)
			continue
		}
		var invalid *InstallerError
		if !errors.As(err, &invalid) || invalid.Type != ErrorTypeInvalidConfig {
			t.Errorf("resolveBootTarget(%q) error %T = %v, want an invalid-config InstallerError", arch, err, err)
		}
	}
}

func TestX86BootTargetMatchesUKI(t *testing.T) {
	name, err := uki.BootFileName(uki.ArchX86_64)
	if err != nil || name != x86BootTarget.ukiFileName {
		t.Errorf("x86BootTarget.ukiFileName = %q, pkg/uki says %q (%v)", x86BootTarget.ukiFileName, name, err)
	}
	stub, err := uki.StubPath(uki.ArchX86_64)
	if err != nil || stub != x86BootTarget.stubPath {
		t.Errorf("x86BootTarget.stubPath = %q, pkg/uki says %q (%v)", x86BootTarget.stubPath, stub, err)
	}
	resolved, err := resolveBootTarget("")
	if err != nil || resolved != x86BootTarget {
		t.Errorf("resolveBootTarget(\"\") = %+v, want x86BootTarget", resolved)
	}
}

func TestInstallerBootTargetAccessors(t *testing.T) {
	// An installer built without NewInstaller keeps the historical names.
	zero := &installer{logger: createTestLogger()}
	if zero.ukiFileName() != "BOOTX64.EFI" || zero.espLoaderPath() != `\EFI\BOOT\BOOTX64.EFI` || zero.ukiESPPath() != DefaultESPUKIPath {
		t.Errorf("zero-value installer resolved %q %q %q", zero.ukiFileName(), zero.espLoaderPath(), zero.ukiESPPath())
	}
	arm, err := resolveBootTarget("aarch64")
	if err != nil {
		t.Fatal(err)
	}
	inst := &installer{logger: createTestLogger(), boot: arm}
	if inst.ukiFileName() != "BOOTAA64.EFI" {
		t.Errorf("ukiFileName = %q", inst.ukiFileName())
	}
	if inst.espLoaderPath() != `\EFI\BOOT\BOOTAA64.EFI` {
		t.Errorf("espLoaderPath = %q", inst.espLoaderPath())
	}
	if inst.ukiESPPath() != "/boot/efi/EFI/BOOT/BOOTAA64.EFI" {
		t.Errorf("ukiESPPath = %q", inst.ukiESPPath())
	}
	if !strings.Contains(inst.bootTarget().dracutDrivers, "tpm_tis_spi") {
		t.Errorf("aarch64 dracut drivers lack tpm_tis_spi: %q", inst.bootTarget().dracutDrivers)
	}
	if strings.Contains(zero.bootTarget().dracutDrivers, "tpm_tis_spi") {
		t.Errorf("x86_64 dracut drivers changed: %q", zero.bootTarget().dracutDrivers)
	}
}

func TestConfigValidateRejectsUnsupportedArchitecture(t *testing.T) {
	cfg := &Config{Disk: &DiskConfig{Device: "/dev/sda"}, OS: &OSConfig{Architecture: "mips"}}
	err := cfg.Validate()
	var invalid *InstallerError
	if !errors.As(err, &invalid) || invalid.Type != ErrorTypeInvalidConfig {
		t.Fatalf("Validate() error = %v, want an invalid-config InstallerError", err)
	}
	if !strings.Contains(err.Error(), "mips") {
		t.Errorf("error does not name the architecture: %v", err)
	}
	cfg.OS.Architecture = "aarch64"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() rejected aarch64: %v", err)
	}
}

func TestESPUKIPathFor(t *testing.T) {
	got, err := ESPUKIPathFor(uki.ArchAArch64)
	if err != nil || got != "/boot/efi/EFI/BOOT/BOOTAA64.EFI" {
		t.Errorf("ESPUKIPathFor(aarch64) = %q, %v", got, err)
	}
	got, err = ESPUKIPathFor(uki.ArchX86_64)
	if err != nil || got != DefaultESPUKIPath {
		t.Errorf("ESPUKIPathFor(x86_64) = %q, %v", got, err)
	}
	if _, err := ESPUKIPathFor(uki.Architecture("mips")); err == nil {
		t.Error("ESPUKIPathFor(mips) accepted an unknown architecture")
	}
	if host := hostESPUKIPath(); !strings.HasPrefix(host, DefaultESPBootDir+"/BOOT") {
		t.Errorf("hostESPUKIPath() = %q", host)
	}
}

func TestSyncUKIOnESPAtUsesArchitectureFileName(t *testing.T) {
	arm, err := resolveBootTarget("aarch64")
	if err != nil {
		t.Fatal(err)
	}
	inst := &installer{logger: createTestLogger(), boot: arm}
	root := t.TempDir()
	bootDir := filepath.Join(root, espBootDir)
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Only the x86 name present: an aarch64 install must fail the gate.
	if err := os.WriteFile(filepath.Join(bootDir, "BOOTX64.EFI"), []byte("uki"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := inst.syncUKIOnESPAt(root); err == nil {
		t.Fatal("completion gate passed without BOOTAA64.EFI")
	}
	if err := os.WriteFile(filepath.Join(bootDir, "BOOTAA64.EFI"), []byte("uki"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := inst.syncUKIOnESPAt(root); err != nil {
		t.Fatalf("completion gate failed with BOOTAA64.EFI present: %v", err)
	}
}

func TestAPKTriggerCarriesUKIPath(t *testing.T) {
	root := t.TempDir()
	path, err := writeKernelUpdateAPKTrigger(root, "/boot/efi/EFI/BOOT/BOOTAA64.EFI")
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "UKI=/boot/efi/EFI/BOOT/BOOTAA64.EFI\n") {
		t.Errorf("apk trigger does not gate on the aarch64 UKI:\n%s", content)
	}
	if strings.Contains(string(content), "%") {
		t.Errorf("apk trigger contains an unexpanded format verb:\n%s", content)
	}
}

func TestHostStubCandidatesStartWithHostStub(t *testing.T) {
	candidates := hostStubCandidates()
	want, err := uki.StubPath(uki.HostArchitecture())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) < 2 || candidates[0] != want {
		t.Errorf("hostStubCandidates() = %v, want first entry %q", candidates, want)
	}
}

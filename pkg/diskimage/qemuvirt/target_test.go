package qemuvirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/virtkernel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

func TestTargetContract(t *testing.T) {
	tgt := New()
	if tgt.Name() != "qemu-virt" || tgt.Architecture() != uki.ArchAArch64 || tgt.KernelPackage() != "linux-virt" || tgt.UBootBoard() != uboot.BoardQEMUArm64 || tgt.ExtraPackages() != nil {
		t.Errorf("contract = %s %s %s %s %v", tgt.Name(), tgt.Architecture(), tgt.KernelPackage(), tgt.UBootBoard(), tgt.ExtraPackages())
	}
	if !tgt.BuiltKernel() {
		t.Error("the virt stand-in boots the platform-built kernel")
	}
	ov := tgt.InstallerOverrides()
	if ov.Device != "/dev/vda" || ov.PartitionTable != "mbr" || ov.KernelPackage != "linux-virt" || ov.Target != "image" || ov.BootFirmware != "uboot" || ov.HardwareManufacturer != "Raspberry Pi" {
		t.Errorf("InstallerOverrides = %+v", ov)
	}
	if ov.KernelArtifactsDir != "/media/cdrom/kernel-artifacts/virt" {
		t.Errorf("KernelArtifactsDir = %s", ov.KernelArtifactsDir)
	}
}

func TestStageBootFirmwareCreatesEmptyDir(t *testing.T) {
	media := t.TempDir()
	dest := filepath.Join(media, "boot-firmware")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "stale"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().StageBootFirmware(context.Background(), media, t.TempDir(), uboot.Artifacts{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Errorf("boot-firmware dir = %v, %v; want empty", entries, err)
	}
	// An unwritable parent is an error.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().StageBootFirmware(context.Background(), file, "", uboot.Artifacts{}); err == nil {
		t.Error("StageBootFirmware under a file succeeded")
	}
}

// fakeKernel is a builder output directory with the files the installer reads.
func fakeKernel(t *testing.T) *virtkernel.Artifacts {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"vmlinuz-virt": "kernel", "modules-virt.tar.gz": "modules", "kernel-version.txt": "6.12.110-0-virt\n", "config-virt": "c", "SHA256SUMS": "s"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir-not-copied"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &virtkernel.Artifacts{Dir: dir, Flavor: "virt", Release: "6.12.110-0-virt", Kernel: filepath.Join(dir, "vmlinuz-virt"), Modules: filepath.Join(dir, "modules-virt.tar.gz")}
}

func TestStageKernelCopiesTheArtifactDirectory(t *testing.T) {
	media := t.TempDir()
	dest := filepath.Join(media, KernelArtifactsMediaDir)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "stale"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := New().StageKernel(context.Background(), media, fakeKernel(t)); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"vmlinuz-virt", "modules-virt.tar.gz", "kernel-version.txt", "config-virt", "SHA256SUMS"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("staged kernel lacks %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "stale")); !os.IsNotExist(err) {
		t.Error("a stale file survived the staging")
	}
	if _, err := os.Stat(filepath.Join(dest, "subdir-not-copied")); !os.IsNotExist(err) {
		t.Error("subdirectories are not part of the artifacts")
	}
}

func TestStageKernelFailures(t *testing.T) {
	var stage *StageError
	if err := New().StageKernel(context.Background(), t.TempDir(), nil); !errors.As(err, &stage) || !errors.Is(err, errNoKernel) {
		t.Errorf("nil kernel: %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().StageKernel(context.Background(), file, fakeKernel(t)); !errors.As(err, &stage) {
		t.Errorf("unwritable media: %v", err)
	}
	missing := &virtkernel.Artifacts{Dir: filepath.Join(t.TempDir(), "nope")}
	if err := New().StageKernel(context.Background(), t.TempDir(), missing); !errors.As(err, &stage) {
		t.Errorf("missing artifacts: %v", err)
	}
	if got := stage.Error(); got == "" {
		t.Error("empty error string")
	}
}

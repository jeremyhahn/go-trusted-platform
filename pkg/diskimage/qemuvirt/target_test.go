package qemuvirt

import (
	"context"
	"errors"
	"io/fs"
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
	cases := []struct {
		name     string
		setup    func(t *testing.T) (mediaDir string, kernel *virtkernel.Artifacts)
		wantStep string
		wantErr  error
	}{
		{
			name: "nil kernel",
			setup: func(t *testing.T) (string, *virtkernel.Artifacts) {
				return t.TempDir(), nil
			},
			wantStep: "staging the kernel",
			wantErr:  errNoKernel,
		},
		{
			name: "media dir is a file",
			setup: func(t *testing.T) (string, *virtkernel.Artifacts) {
				file := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(file, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return file, fakeKernel(t)
			},
			wantStep: "clearing the kernel staging directory",
		},
		{
			// RemoveAll treats a dangling parent as already gone, so the
			// failure surfaces when the staging directory is created.
			name: "staging parent is a dangling symlink",
			setup: func(t *testing.T) (string, *virtkernel.Artifacts) {
				media := t.TempDir()
				if err := os.Symlink(filepath.Join(media, "gone"), filepath.Join(media, "kernel-artifacts")); err != nil {
					t.Fatal(err)
				}
				return media, fakeKernel(t)
			},
			wantStep: "creating the kernel staging directory",
		},
		{
			name: "missing artifacts",
			setup: func(t *testing.T) (string, *virtkernel.Artifacts) {
				return t.TempDir(), &virtkernel.Artifacts{Dir: filepath.Join(t.TempDir(), "nope")}
			},
			wantStep: "reading the kernel artifacts",
			wantErr:  fs.ErrNotExist,
		},
		{
			// A dangling symlink among the artifacts must fail the stage,
			// never be skipped and leave an incomplete kernel on the media.
			name: "unreadable artifact",
			setup: func(t *testing.T) (string, *virtkernel.Artifacts) {
				kernel := fakeKernel(t)
				if err := os.Symlink(filepath.Join(kernel.Dir, "gone"), filepath.Join(kernel.Dir, "broken")); err != nil {
					t.Fatal(err)
				}
				return t.TempDir(), kernel
			},
			wantStep: "copying broken",
			wantErr:  fs.ErrNotExist,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mediaDir, kernel := tc.setup(t)
			err := New().StageKernel(context.Background(), mediaDir, kernel)
			var stage *StageError
			if !errors.As(err, &stage) {
				t.Fatalf("got %v, want *StageError", err)
			}
			if stage.Step != tc.wantStep {
				t.Errorf("Step = %q, want %q", stage.Step, tc.wantStep)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want it to wrap %v", err, tc.wantErr)
			}
			if stage.Error() == "" {
				t.Error("empty error string")
			}
		})
	}
}

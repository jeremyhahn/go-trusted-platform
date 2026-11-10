package diskimage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// cov964Blocker returns a regular file under t.TempDir(): any path below it
// cannot be created, so MkdirAll and OpenFile on such a path fail.
func cov964Blocker(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(path, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// cov964WriteFile writes data to a new file under t.TempDir().
func cov964WriteFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// cov964LinuxOnlyImage writes an MBR whose only partition is a Linux one, so
// the image has no EFI system partition.
func cov964LinuxOnlyImage(t *testing.T) string {
	t.Helper()
	mbr := make([]byte, 512)
	e := mbr[446:]
	e[4] = 0x83
	binary.LittleEndian.PutUint32(e[8:], 2048)
	binary.LittleEndian.PutUint32(e[12:], 4096)
	mbr[510], mbr[511] = 0x55, 0xaa
	return cov964WriteFile(t, "linux.img", mbr)
}

func TestCoverage964ExtractESPCopiesTheKeptFiles(t *testing.T) {
	image := writeImage(t, false)
	loader := minimalPE(0xAA64, true)
	esp := &mtoolsRunner{files: map[string][]byte{
		"EFI/BOOT/BOOTAA64.EFI": loader,
		"config.txt":            []byte("arm_64bit=1\n"),
	}}
	dest := t.TempDir()
	keep := func(name string) bool { return strings.HasPrefix(name, "EFI/") }

	copied, err := ExtractESP(context.Background(), image, dest, keep, esp.run)
	if err != nil {
		t.Fatalf("ExtractESP: %v", err)
	}
	if !reflect.DeepEqual(copied, []string{"EFI/BOOT/BOOTAA64.EFI"}) {
		t.Errorf("copied = %v", copied)
	}
	got, err := os.ReadFile(filepath.Join(dest, "EFI", "BOOT", "BOOTAA64.EFI"))
	if err != nil || !bytes.Equal(got, loader) {
		t.Errorf("extracted loader = %d bytes, %v", len(got), err)
	}
	if _, err := os.Stat(filepath.Join(dest, "config.txt")); !os.IsNotExist(err) {
		t.Errorf("a file the filter refused was copied: %v", err)
	}
	// Both mtools calls address partition 1 at its byte offset.
	for _, call := range esp.calls {
		if !strings.Contains(strings.Join(call, " "), image+"@@1048576") {
			t.Errorf("mtools call %v does not address the ESP offset", call)
		}
	}

	// A nil filter keeps every file, in sorted order.
	all, err := ExtractESP(context.Background(), image, t.TempDir(), nil, esp.run)
	if err != nil || !reflect.DeepEqual(all, []string{"EFI/BOOT/BOOTAA64.EFI", "config.txt"}) {
		t.Errorf("unfiltered copy = %v, %v", all, err)
	}
}

func TestCoverage964ExtractESPFailures(t *testing.T) {
	image := writeImage(t, false)
	files := map[string][]byte{"EFI/BOOT/BOOTAA64.EFI": minimalPE(0xAA64, false)}
	cases := []struct {
		name   string
		image  string
		dest   string
		runner *mtoolsRunner
		reason string
	}{
		{"missing image", filepath.Join(t.TempDir(), "absent.img"), t.TempDir(), &mtoolsRunner{}, "cannot open"},
		{"short image", cov964WriteFile(t, "short.img", make([]byte, 100)), t.TempDir(), &mtoolsRunner{}, "cannot read the MBR"},
		{"no MBR signature", cov964WriteFile(t, "blank.img", make([]byte, 512)), t.TempDir(), &mtoolsRunner{}, "signature"},
		{"no FAT partition", cov964LinuxOnlyImage(t), t.TempDir(), &mtoolsRunner{}, "no FAT partition 1"},
		{"mdir fails", image, t.TempDir(), &mtoolsRunner{files: files, fail: "mdir"}, "cannot list the EFI partition"},
		{"destination is a file", image, cov964Blocker(t), &mtoolsRunner{files: files}, "cannot create"},
		{"mcopy fails", image, t.TempDir(), &mtoolsRunner{files: files, fail: "mcopy"}, "cannot copy EFI/BOOT/BOOTAA64.EFI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copied, err := ExtractESP(context.Background(), tc.image, tc.dest, nil, tc.runner.run)
			var ierr *InspectError
			if !errors.As(err, &ierr) || ierr.Path != tc.image || !strings.Contains(ierr.Reason, tc.reason) {
				t.Fatalf("err = %v, want an InspectError with reason %q", err, tc.reason)
			}
			if copied != nil {
				t.Errorf("copied = %v on failure", copied)
			}
		})
	}
}

func TestCoverage964CreateRunsPreflightUnlessSkipped(t *testing.T) {
	t.Run("unknown target", func(t *testing.T) {
		rec := &diskimagetest.Runner{}
		cfg := buildConfigForTest(t, "nope", rec)
		cfg.SkipPreflight = false
		var unknown *UnknownTargetError
		if _, err := Create(context.Background(), cfg); !errors.As(err, &unknown) || unknown.Target != "nope" {
			t.Fatalf("err = %v", err)
		}
		if calls := rec.Joined(); len(calls) != 0 {
			t.Errorf("the runtime was called for an unknown target: %v", calls)
		}
	})
	t.Run("runtime unusable", func(t *testing.T) {
		rec := &diskimagetest.Runner{Fail: "version"}
		cfg := buildConfigForTest(t, "qemu-virt", rec)
		cfg.SkipPreflight = false
		var pre *PreflightError
		if _, err := Create(context.Background(), cfg); !errors.As(err, &pre) || !strings.HasSuffix(pre.Check, " is not usable") {
			t.Fatalf("err = %v", err)
		}
		if _, err := os.Stat(cfg.Output); !os.IsNotExist(err) {
			t.Errorf("an image was written after a failed preflight: %v", err)
		}
	})
}

func TestCoverage964StageHostInstaller(t *testing.T) {
	binary := writeHostInstaller(t)
	dir, cleanup, err := stageHostInstaller(binary)
	if err != nil {
		t.Fatalf("stageHostInstaller: %v", err)
	}
	staged := filepath.Join(dir, hostInstallerName)
	info, err := os.Stat(staged)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("staged installer = %v, %v", info, err)
	}
	if got, err := os.ReadFile(staged); err != nil || string(got) != "host-installer" {
		t.Errorf("staged content = %q, %v", got, err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s: %v", dir, err)
	}

	// A directory opens but cannot be read: the copy fails and nothing is returned.
	dir, cleanup, err = stageHostInstaller(t.TempDir())
	if err == nil || dir != "" || cleanup != nil {
		t.Errorf("directory as installer = %q, cleanup set %v, err %v", dir, cleanup != nil, err)
	}
}

func TestCoverage964AssembleDefaultsAndDetachAfterFailedInstall(t *testing.T) {
	t.Run("missing disk section", func(t *testing.T) {
		rec := &fakeRunner{loop: "/dev/loop4"}
		cfg := assembleConfig()
		cfg.Disk = nil
		var seen *installer.Config
		_, err := Assemble(context.Background(), AssembleOptions{
			Config: cfg, Output: filepath.Join(t.TempDir(), "img"), SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc,
			install: func(_ context.Context, _ *logging.Logger, c *installer.Config) error { seen = c; return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if seen.Disk == nil || seen.Disk.Device != "/dev/loop4" || seen.Disk.Encryption != nil {
			t.Errorf("disk = %+v", seen.Disk)
		}
	})
	t.Run("install and detach both fail", func(t *testing.T) {
		rec := &fakeRunner{loop: "/dev/loop5", failOn: "--detach"}
		installErr := errors.New("install boom")
		_, err := Assemble(context.Background(), AssembleOptions{
			Config: assembleConfig(), Output: filepath.Join(t.TempDir(), "img"), SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc,
			install: func(context.Context, *logging.Logger, *installer.Config) error { return installErr },
		})
		// The install failure is the one reported; the detach failure is only logged.
		var aerr *AssembleError
		if !errors.Is(err, installErr) || !errors.As(err, &aerr) || aerr.Step != "installing onto the image" {
			t.Errorf("err = %v", err)
		}
	})
}

func TestCoverage964CreateSparseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sparse.img")
	if err := createSparseFile(path, 1<<20); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 1<<20 {
		t.Errorf("sparse file = %v, %v", info, err)
	}
	if err := createSparseFile(path, -1); err == nil {
		t.Error("a negative size was accepted")
	}
}

func TestCoverage964AllocateLoopDeviceRejectsANonControlNode(t *testing.T) {
	// A regular file opens but is not /dev/loop-control: the ioctl fails.
	control := cov964WriteFile(t, "loop-control", nil)
	var lerr *LoopDeviceError
	if path, err := allocateLoopDevice(control); !errors.As(err, &lerr) || lerr.Op != "requesting a free loop device" || path != "" {
		t.Errorf("allocateLoopDevice = %q, %v", path, err)
	}
}

func TestCoverage964OutputDirectoryUnderAFile(t *testing.T) {
	blocked := filepath.Join(cov964Blocker(t), "out")
	var stage *StageError

	rec := &initfsRunner{}
	_, err := GenerateNetbootInitfs(context.Background(), NetbootInitfsOptions{
		Modules: modulesFile(t), Release: diskimagetest.VirtKernelRelease, Flavour: "virt", OutputDir: blocked, Root: t.TempDir(), Runner: rec.run,
	})
	if !errors.As(err, &stage) || stage.Step != "creating the output directory" {
		t.Errorf("GenerateNetbootInitfs err = %v", err)
	}

	staged, err := StageMedia(context.Background(), buildConfigForTest(t, "qemu-virt", &diskimagetest.Runner{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.BuildNetbootInitfs(context.Background(), blocked); !errors.As(err, &stage) || stage.Step != "creating the output directory" {
		t.Errorf("BuildNetbootInitfs err = %v", err)
	}
	key, cert := testDBKey(t)
	staged.SecureBoot = &iso.SecureBootMaterial{DBKey: key, DBCert: cert}
	if _, err := staged.BuildDisklessRoot(context.Background(), blocked, t.TempDir(), 0, "1"); !errors.As(err, &stage) || stage.Step != "creating the diskless root output directory" {
		t.Errorf("BuildDisklessRoot err = %v", err)
	}

	asm := &fakeAssemble{}
	opts := disklessOptions(t, newDisklessRunner(), asm)
	opts.WorkDir = blocked
	if _, err := GenerateDisklessRoot(context.Background(), opts); !errors.As(err, &stage) || stage.Step != "creating "+blocked {
		t.Errorf("GenerateDisklessRoot err = %v", err)
	}
	if asm.cfg != nil {
		t.Error("the image was assembled although the work directory could not be created")
	}
}

func TestCoverage964BuilderErrorMessages(t *testing.T) {
	cases := []struct {
		err  error
		want []string
	}{
		{&HostInstallerMissingError{HostArch: "amd64", TargetArch: "arm64"}, []string{"building a arm64 image on a amd64 host", "needs a amd64 platformctl-static"}},
		{&builderImageError{value: "builder:latest"}, []string{`--builder-image "builder:latest"`, "without a tag or digest"}},
	}
	for _, tc := range cases {
		msg := tc.err.Error()
		for _, want := range tc.want {
			if !strings.Contains(msg, want) {
				t.Errorf("%q lacks %q", msg, want)
			}
		}
	}
}

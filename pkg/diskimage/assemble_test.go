package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeRunner records argv and answers losetup.
type fakeRunner struct {
	calls  [][]string
	loop   string
	failOn string
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn != "" && strings.Contains(name+" "+strings.Join(args, " "), f.failOn) {
		return []byte("boom"), errors.New("exit 1")
	}
	return nil, nil
}

// alloc stands in for allocateLoopDevice.
func (f *fakeRunner) alloc() (string, error) {
	if f.failOn == "alloc" {
		return "", &LoopDeviceError{Op: "requesting a free loop device", Err: errors.New("no loop")}
	}
	return f.loop, nil
}

func assembleConfig() *installer.Config {
	return &installer.Config{
		Disk: &installer.DiskConfig{Device: "/dev/mmcblk0", PartitionTable: installer.PartitionTableMBR, Encryption: &installer.EncryptionConfig{Version: "luks2"}},
		OS:   &installer.OSConfig{Architecture: "aarch64", KernelPackage: "linux-rpi"},
	}
}

func TestAssembleAttachesInstallsAndDetaches(t *testing.T) {
	out := filepath.Join(t.TempDir(), "image.img")
	rec := &fakeRunner{loop: "/dev/loop7"}
	var seen *installer.Config
	res, err := Assemble(context.Background(), AssembleOptions{
		Config: assembleConfig(), Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc, Logger: logging.DefaultLogger(),
		install: func(_ context.Context, _ *logging.Logger, cfg *installer.Config) error { seen = cfg; return nil },
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if res.LoopDevice != "/dev/loop7" || res.Image != out || res.SizeBytes != 2048*1024*1024 {
		t.Errorf("result = %+v", res)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() != 2048*1024*1024 {
		t.Errorf("image size = %v, %v", info, err)
	}
	if seen == nil || seen.Disk.Device != "/dev/loop7" || seen.Target != installer.InstallTargetImage || seen.Boot == nil || seen.Boot.Firmware != installer.BootFirmwareUBoot {
		t.Errorf("installer config = %+v (boot %+v)", seen, seen.Boot)
	}
	if len(seen.Disk.Encryption.Password) != passphraseBytes*2 {
		t.Errorf("passphrase not generated: %q", seen.Disk.Encryption.Password)
	}
	if len(rec.calls) != 2 || strings.Join(rec.calls[0], " ") != "losetup --partscan /dev/loop7 "+out || strings.Join(rec.calls[1], " ") != "losetup --detach /dev/loop7" {
		t.Errorf("calls = %v", rec.calls)
	}

	// A caller-supplied passphrase is kept; an explicit firmware too.
	cfg := assembleConfig()
	cfg.Disk.Encryption.Password = "given"
	cfg.Boot = &installer.BootConfig{Firmware: installer.BootFirmwareUEFI}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: cfg, Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc,
		install: func(_ context.Context, _ *logging.Logger, c *installer.Config) error { seen = c; return nil }}); err != nil {
		t.Fatal(err)
	}
	if seen.Disk.Encryption.Password != "given" || seen.Boot.Firmware != installer.BootFirmwareUEFI {
		t.Errorf("caller values overwritten: %+v", seen.Disk.Encryption)
	}
}

func TestAssembleFailures(t *testing.T) {
	out := filepath.Join(t.TempDir(), "image.img")
	noop := func(context.Context, *logging.Logger, *installer.Config) error { return nil }
	var aerr *AssembleError

	if _, err := Assemble(context.Background(), AssembleOptions{Output: out, SizeMB: 2048}); !errors.As(err, &aerr) {
		t.Errorf("nil config error = %v", err)
	}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), SizeMB: 2048}); !errors.As(err, &aerr) {
		t.Errorf("no output error = %v", err)
	}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: out, SizeMB: 512}); !errors.As(err, &aerr) || !strings.Contains(err.Error(), "below the minimum") {
		t.Errorf("small size error = %v", err)
	}

	rec := &fakeRunner{loop: "/dev/loop1", failOn: "--partscan"}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc, install: noop}); !errors.As(err, &aerr) || aerr.Step != "attaching the image as a loop device" {
		t.Errorf("losetup failure error = %v", err)
	}
	rec = &fakeRunner{failOn: "alloc"}
	var lerr *LoopDeviceError
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc, install: noop}); !errors.As(err, &aerr) || aerr.Step != "allocating a loop device" || !errors.As(err, &lerr) {
		t.Errorf("loop allocation failure error = %v", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("losetup ran without a loop device: %v", rec.calls)
	}

	// An install failure still detaches, and reports the install error.
	rec = &fakeRunner{loop: "/dev/loop2"}
	installErr := errors.New("install boom")
	_, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc,
		install: func(context.Context, *logging.Logger, *installer.Config) error { return installErr }})
	if !errors.Is(err, installErr) || !errors.As(err, &aerr) || aerr.Step != "installing onto the image" {
		t.Errorf("install failure error = %v", err)
	}
	if len(rec.calls) != 2 || rec.calls[1][1] != "--detach" {
		t.Errorf("loop device not detached after a failed install: %v", rec.calls)
	}

	// A detach failure after a successful install is an error.
	rec = &fakeRunner{loop: "/dev/loop3", failOn: "--detach"}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: out, SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc, install: noop}); !errors.As(err, &aerr) || aerr.Step != "detaching the loop device" {
		t.Errorf("detach failure error = %v", err)
	}

	// An unwritable image path.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(context.Background(), AssembleOptions{Config: assembleConfig(), Output: filepath.Join(blocker, "x.img"), SizeMB: 2048, Runner: rec.run, allocateLoop: rec.alloc, install: noop}); !errors.As(err, &aerr) || aerr.Step != "creating the image file" {
		t.Errorf("unwritable image error = %v", err)
	}
}

func TestAllocateLoopDeviceErrors(t *testing.T) {
	var lerr *LoopDeviceError
	// No loop-control device at all.
	if _, err := allocateLoopDevice(filepath.Join(t.TempDir(), "missing")); !errors.As(err, &lerr) || !strings.HasPrefix(lerr.Op, "opening ") {
		t.Errorf("missing loop-control error = %v", err)
	}
	// A regular file answers the ioctl with ENOTTY.
	notControl := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notControl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := allocateLoopDevice(notControl); !errors.As(err, &lerr) || lerr.Op != "requesting a free loop device" {
		t.Errorf("non-device loop-control error = %v", err)
	}
	if !strings.Contains(lerr.Error(), "diskimage: loop device: requesting a free loop device") || lerr.Unwrap() == nil {
		t.Errorf("error text = %q", lerr.Error())
	}
}

func TestEnsureBlockNode(t *testing.T) {
	// An existing path is accepted as is.
	existing := filepath.Join(t.TempDir(), "loop9")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureBlockNode(existing, loopMajor, 9); err != nil {
		t.Errorf("existing node error = %v", err)
	}
	// A path under a regular file fails the stat with ENOTDIR.
	var lerr *LoopDeviceError
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureBlockNode(filepath.Join(blocker, "loop9"), loopMajor, 9); !errors.As(err, &lerr) || !strings.HasPrefix(lerr.Op, "checking ") {
		t.Errorf("unstattable node error = %v", err)
	}
	// A missing parent directory fails the mknod.
	if err := ensureBlockNode(filepath.Join(t.TempDir(), "missing", "loop9"), loopMajor, 9); !errors.As(err, &lerr) || !strings.HasPrefix(lerr.Op, "creating ") {
		t.Errorf("uncreatable node error = %v", err)
	}
}

func TestRandomPassphraseIsRandom(t *testing.T) {
	a, err := randomPassphrase()
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomPassphrase()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != passphraseBytes*2 {
		t.Errorf("passphrases %q %q", a, b)
	}
}

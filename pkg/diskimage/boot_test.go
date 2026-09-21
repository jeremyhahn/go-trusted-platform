package diskimage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// fakeBootTPM satisfies harness.TPM for the boot seam.
type fakeBootTPM struct{ stopped bool }

func (f *fakeBootTPM) IsInitialized() bool               { return true }
func (f *fakeBootTPM) Initialize(context.Context) error  { return nil }
func (f *fakeBootTPM) Start(context.Context) error       { return nil }
func (f *fakeBootTPM) WaitForSocket(time.Duration) error { return nil }
func (f *fakeBootTPM) SocketPath() string                { return "/tmp/fake/swtpm.sock" }
func (f *fakeBootTPM) StateDir() string                  { return "/tmp/fake" }
func (f *fakeBootTPM) PID() int                          { return 1 }
func (f *fakeBootTPM) Stop() error                       { f.stopped = true; return nil }

// fakeBootVM records the VM lifecycle and can write serial output when
// started, the way a guest would.
type fakeBootVM struct {
	cfg      *qemu.Config
	startErr error
	waitErr  error
	onStart  func()
	started  bool
	waited   bool
	stopped  bool
}

func (f *fakeBootVM) Start(context.Context, string) error {
	f.started = true
	if f.startErr != nil {
		return f.startErr
	}
	if f.onStart != nil {
		f.onStart()
	}
	return nil
}
func (f *fakeBootVM) Wait() error { f.waited = true; return f.waitErr }
func (f *fakeBootVM) Stop() error { f.stopped = true; return nil }

// bootFixture is an image (with a hole in it) and a firmware file.
type bootFixture struct {
	dir, image, firmware string
	tpm                  *fakeBootTPM
	vm                   *fakeBootVM
}

func newBootFixture(t *testing.T) *bootFixture {
	t.Helper()
	dir := t.TempDir()
	image := filepath.Join(dir, "image.img")
	data := make([]byte, 3*sparseChunk)
	copy(data, []byte("MBR"))
	copy(data[2*sparseChunk:], []byte("LUKS"))
	if err := os.WriteFile(image, data, 0o644); err != nil {
		t.Fatal(err)
	}
	firmware := filepath.Join(dir, "u-boot.bin")
	if err := os.WriteFile(firmware, []byte("uboot"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &bootFixture{dir: dir, image: image, firmware: firmware, tpm: &fakeBootTPM{}, vm: &fakeBootVM{}}
}

func (f *bootFixture) options() BootOptions {
	return BootOptions{
		Image:    f.image,
		Firmware: f.firmware,
		WorkDir:  filepath.Join(f.dir, "work"),
		Logger:   logging.DefaultLogger(),
		startTPM: func(_ context.Context, _ *logging.Logger, cfg *qemu.Config) (harness.TPM, harness.TPMState, error) {
			cfg.TPMSocket = f.tpm.SocketPath()
			return f.tpm, harness.TPMStatePreserved, nil
		},
		newVM: func(cfg *qemu.Config, _ *logging.Logger) (bootVM, error) {
			f.vm.cfg = cfg
			return f.vm, nil
		},
	}
}

func TestBoot_CopiesTheImageAndWaitsForPowerOff(t *testing.T) {
	f := newBootFixture(t)
	opts := f.options()
	opts.Memory = 1024
	opts.CPUs = 2
	opts.SerialLog = filepath.Join(f.dir, "serial.log")
	opts.PortForwards = []qemu.PortForward{{HostPort: 18443, GuestPort: 8443, Protocol: "tcp"}}

	result, err := Boot(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}

	if result.Disk != filepath.Join(opts.WorkDir, bootDiskName) {
		t.Errorf("disk = %s, want the working copy", result.Disk)
	}
	if result.TPMState != harness.TPMStatePreserved || result.Expected {
		t.Errorf("result = %+v", result)
	}
	if !f.vm.started || !f.vm.waited || f.vm.stopped {
		t.Errorf("vm lifecycle: started=%v waited=%v stopped=%v", f.vm.started, f.vm.waited, f.vm.stopped)
	}
	if !f.tpm.stopped {
		t.Error("the TPM must be stopped when Boot returns")
	}
	cfg := f.vm.cfg
	switch {
	case cfg.Arch != qemu.ArchAArch64:
		t.Errorf("arch = %s", cfg.Arch)
	case cfg.Firmware != f.firmware:
		t.Errorf("firmware = %s", cfg.Firmware)
	case cfg.DiskPath != result.Disk, cfg.DiskFormat != qemu.DiskFormatRaw:
		t.Errorf("disk = %s %s", cfg.DiskPath, cfg.DiskFormat)
	case cfg.DiskSize != "3M":
		t.Errorf("disk size = %s", cfg.DiskSize)
	case cfg.Memory != 1024, cfg.CPUs != 2:
		t.Errorf("memory/cpus = %d/%d", cfg.Memory, cfg.CPUs)
	case cfg.SerialLogFile != opts.SerialLog, cfg.SerialConsole:
		t.Errorf("serial = %q console=%v", cfg.SerialLogFile, cfg.SerialConsole)
	case cfg.NetworkMode != "user", len(cfg.PortForwards) != 1:
		t.Errorf("network = %s %v", cfg.NetworkMode, cfg.PortForwards)
	case cfg.TPMSocket != f.tpm.SocketPath():
		t.Errorf("tpm socket = %s", cfg.TPMSocket)
	case !cfg.NoGraphic, !cfg.EnableKVM:
		t.Errorf("graphics/kvm = %v/%v", cfg.NoGraphic, cfg.EnableKVM)
	}

	copied, err := os.ReadFile(result.Disk)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(f.image)
	if !bytes.Equal(copied, original) {
		t.Error("the working copy differs from the image")
	}
}

func TestBoot_DefaultsAndInteractiveConsole(t *testing.T) {
	f := newBootFixture(t)
	opts := f.options()
	opts.WorkDir = ""
	// Run from the fixture directory so the default work dir lands in it.
	wd, _ := os.Getwd()
	if err := os.Chdir(f.dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	result, err := Boot(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disk != filepath.Join(DefaultBootWorkDir, bootDiskName) {
		t.Errorf("disk = %s", result.Disk)
	}
	cfg := f.vm.cfg
	if cfg.Memory != DefaultBootMemory || cfg.CPUs < 1 || cfg.CPUs > 4 {
		t.Errorf("memory/cpus = %d/%d", cfg.Memory, cfg.CPUs)
	}
	if !cfg.SerialConsole || cfg.SerialLogFile != "" {
		t.Errorf("an empty SerialLog means an interactive console: %+v", cfg)
	}
}

func TestBoot_InPlaceBootsTheImageItself(t *testing.T) {
	f := newBootFixture(t)
	opts := f.options()
	opts.InPlace = true

	result, err := Boot(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disk != f.image {
		t.Errorf("disk = %s, want the image itself", result.Disk)
	}
	if _, err := os.Stat(filepath.Join(opts.WorkDir, bootDiskName)); !os.IsNotExist(err) {
		t.Error("no working copy may be made in place")
	}
}

func TestBoot_ExpectStopsTheVMWhenTheMilestoneAppears(t *testing.T) {
	f := newBootFixture(t)
	opts := f.options()
	opts.SerialLog = filepath.Join(f.dir, "serial.log")
	opts.Expect = "platformd ready"
	opts.ConsoleSocket = filepath.Join(f.dir, "console.sock")
	f.vm.onStart = func() {
		_ = os.WriteFile(opts.SerialLog, []byte("U-Boot\nBooting Linux\n[INIT] platformd ready\n"), 0o644)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := Boot(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Expected || !f.vm.stopped || f.vm.waited {
		t.Errorf("expected=%v stopped=%v waited=%v", result.Expected, f.vm.stopped, f.vm.waited)
	}
	if f.vm.cfg.ConsoleSocketPath != opts.ConsoleSocket {
		t.Errorf("console socket = %s", f.vm.cfg.ConsoleSocketPath)
	}
}

func TestBoot_ExpectTimesOut(t *testing.T) {
	f := newBootFixture(t)
	opts := f.options()
	opts.SerialLog = filepath.Join(f.dir, "serial.log")
	opts.Expect = "never printed"
	f.vm.onStart = func() { _ = os.WriteFile(opts.SerialLog, []byte("U-Boot\n"), 0o644) }
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	result, err := Boot(ctx, opts)

	var bootErr *BootError
	if !errors.As(err, &bootErr) {
		t.Fatalf("err = %v", err)
	}
	var timeout *harness.SerialTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want a serial timeout", err)
	}
	if result == nil || result.Expected || !f.vm.stopped {
		t.Errorf("result = %+v stopped=%v", result, f.vm.stopped)
	}
}

func TestBoot_ConfigurationErrors(t *testing.T) {
	f := newBootFixture(t)
	cases := map[string]func(*BootOptions){
		"no image":                  func(o *BootOptions) { o.Image = "" },
		"no firmware":               func(o *BootOptions) { o.Firmware = "" },
		"expect without serial log": func(o *BootOptions) { o.Expect = "x" },
		"missing image":             func(o *BootOptions) { o.Image = filepath.Join(f.dir, "nope.img") },
		"missing firmware":          func(o *BootOptions) { o.Firmware = filepath.Join(f.dir, "nope.bin") },
		"unwritable work dir":       func(o *BootOptions) { o.WorkDir = filepath.Join(f.image, "sub") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			opts := f.options()
			mutate(&opts)
			_, err := Boot(context.Background(), opts)
			var bootErr *BootError
			if !errors.As(err, &bootErr) {
				t.Fatalf("err = %v", err)
			}
			if f.vm.started {
				t.Error("the VM must not start on a configuration error")
			}
		})
	}
}

func TestBoot_TPMAndVMFailures(t *testing.T) {
	boom := errors.New("boom")
	t.Run("TPM start", func(t *testing.T) {
		f := newBootFixture(t)
		opts := f.options()
		opts.startTPM = func(context.Context, *logging.Logger, *qemu.Config) (harness.TPM, harness.TPMState, error) {
			return nil, "", boom
		}
		_, err := Boot(context.Background(), opts)
		if !errors.Is(err, boom) || f.vm.started {
			t.Errorf("err = %v started=%v", err, f.vm.started)
		}
	})
	t.Run("VM construction", func(t *testing.T) {
		f := newBootFixture(t)
		opts := f.options()
		opts.newVM = func(*qemu.Config, *logging.Logger) (bootVM, error) { return nil, boom }
		_, err := Boot(context.Background(), opts)
		if !errors.Is(err, boom) || !f.tpm.stopped {
			t.Errorf("err = %v tpmStopped=%v", err, f.tpm.stopped)
		}
	})
	t.Run("VM start", func(t *testing.T) {
		f := newBootFixture(t)
		f.vm.startErr = boom
		_, err := Boot(context.Background(), f.options())
		if !errors.Is(err, boom) || !f.tpm.stopped {
			t.Errorf("err = %v tpmStopped=%v", err, f.tpm.stopped)
		}
	})
	t.Run("VM exit", func(t *testing.T) {
		f := newBootFixture(t)
		f.vm.waitErr = boom
		result, err := Boot(context.Background(), f.options())
		if !errors.Is(err, boom) || result == nil {
			t.Errorf("err = %v result=%v", err, result)
		}
	})
}

func TestCopySparse(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.img")
	data := make([]byte, 4*sparseChunk+17)
	copy(data[sparseChunk:], []byte("data in the second chunk"))
	copy(data[4*sparseChunk:], []byte("tail"))
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.img")

	if err := copySparse(src, dst); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("copy differs from source")
	}
	if err := copySparse(filepath.Join(dir, "missing"), dst); err == nil {
		t.Error("a missing source must fail")
	}
	if err := copySparse(src, filepath.Join(dir, "no", "such", "dir")); err == nil {
		t.Error("an uncreatable destination must fail")
	}
}

func TestBootError(t *testing.T) {
	cause := errors.New("cause")
	err := &BootError{Step: "starting the VM", Err: cause}
	if err.Error() != "diskimage: boot: starting the VM: cause" || !errors.Is(err, cause) {
		t.Errorf("err = %v", err)
	}
}

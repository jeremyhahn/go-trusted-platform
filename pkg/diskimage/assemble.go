package diskimage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"golang.org/x/sys/unix"
)

// AssembleOptions drives Assemble, which runs inside the builder container.
type AssembleOptions struct {
	// Config is the installer configuration the media was built for; the
	// caller loaded it the way the live ISO does (platform config through
	// the app layer) or from a plain installer YAML.
	Config *installer.Config
	// Output is the image path; SizeMB its size.
	Output string
	SizeMB int
	// Runner runs losetup; nil means runner.Exec.
	Runner runner.Runner
	// Logger receives the installer's log; nil means the default logger.
	Logger *logging.Logger
	// install runs the installer; nil means pkg/installer. Tests inject it
	// so no unit test partitions anything.
	install func(ctx context.Context, logger *logging.Logger, cfg *installer.Config) error
	// allocateLoop returns the path of a free loop device whose node exists;
	// nil means allocateLoopDevice against /dev/loop-control.
	allocateLoop func() (string, error)
}

// loopControlPath is the loop-control device and loopMajor the loop block
// device major number.
const (
	loopControlPath = "/dev/loop-control"
	loopMajor       = 7
)

// allocateLoopDevice asks loop-control for a free loop device and makes sure
// its node exists. The assemble container runs with a private /dev, so a
// loop device the kernel creates after the container started has no node in
// it until this creates one.
func allocateLoopDevice(controlPath string) (string, error) {
	fd, err := unix.Open(controlPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", &LoopDeviceError{Op: "opening " + controlPath, Err: err}
	}
	defer unix.Close(fd)
	n, err := unix.IoctlRetInt(fd, unix.LOOP_CTL_GET_FREE)
	if err != nil {
		return "", &LoopDeviceError{Op: "requesting a free loop device", Err: err}
	}
	path := "/dev/loop" + strconv.Itoa(n)
	if err := ensureBlockNode(path, loopMajor, uint32(n)); err != nil {
		return "", err
	}
	return path, nil
}

// ensureBlockNode creates the block device node at path unless it exists.
func ensureBlockNode(path string, major, minor uint32) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return &LoopDeviceError{Op: "checking " + path, Err: err}
	}
	if err := unix.Mknod(path, unix.S_IFBLK|0o660, int(unix.Mkdev(major, minor))); err != nil {
		return &LoopDeviceError{Op: "creating " + path, Err: err}
	}
	return nil
}

// AssembleResult reports what Assemble did.
type AssembleResult struct {
	Image      string
	SizeBytes  int64
	LoopDevice string
}

// passphraseBytes is the length of the per-image LUKS keyslot-0 passphrase.
// Firstboot replaces it with the TPM-sealed key and removes the slot, so
// it only ever protects the image between the build and the first boot.
const passphraseBytes = 32

// Assemble lays a platform install onto a fresh sparse image: it takes a
// free loop device from loop-control, attaches the image to it, points the installer at it with the image
// target set, runs the installer (partitions, LUKS2, Alpine, UKI, the
// U-Boot boot files, installer.luks for first boot), and detaches. The
// image's LUKS passphrase is random per build.
func Assemble(ctx context.Context, opts AssembleOptions) (*AssembleResult, error) {
	if opts.Config == nil {
		return nil, &AssembleError{Step: "configuration", Err: &configError{"installer configuration is required"}}
	}
	if opts.Output == "" {
		return nil, &AssembleError{Step: "configuration", Err: &configError{"output path is required"}}
	}
	if opts.SizeMB < minimumSizeMB {
		return nil, &AssembleError{Step: "configuration", Err: &sizeError{opts.SizeMB}}
	}
	run := opts.Runner
	if run == nil {
		run = runner.Exec
	}
	logger := opts.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	install := opts.install
	if install == nil {
		install = runInstaller
	}
	allocateLoop := opts.allocateLoop
	if allocateLoop == nil {
		allocateLoop = func() (string, error) { return allocateLoopDevice(loopControlPath) }
	}

	cfg := opts.Config
	cfg.Target = installer.InstallTargetImage
	if cfg.Boot == nil {
		cfg.Boot = &installer.BootConfig{}
	}
	if cfg.Boot.Firmware == "" {
		cfg.Boot.Firmware = installer.BootFirmwareUBoot
	}
	if cfg.Disk == nil {
		cfg.Disk = &installer.DiskConfig{}
	}
	if cfg.Disk.Encryption != nil && cfg.Disk.Encryption.Password == "" && cfg.Disk.Encryption.Passphrase == "" {
		passphrase, err := randomPassphrase()
		if err != nil {
			return nil, &AssembleError{Step: "generating the image passphrase", Err: err}
		}
		cfg.Disk.Encryption.Password = passphrase
	}

	size := int64(opts.SizeMB) * 1024 * 1024
	if err := createSparseFile(opts.Output, size); err != nil {
		return nil, &AssembleError{Step: "creating the image file", Err: err}
	}

	loop, err := allocateLoop()
	if err != nil {
		return nil, &AssembleError{Step: "allocating a loop device", Err: err}
	}
	if _, err := run(ctx, "losetup", "--partscan", loop, opts.Output); err != nil {
		return nil, &AssembleError{Step: "attaching the image as a loop device", Err: err}
	}
	logger.Info("[DISKIMAGE] Image attached", "image", opts.Output, "loop", loop, "size_mb", opts.SizeMB)
	cfg.Disk.Device = loop

	installErr := install(ctx, logger, cfg)
	unix.Sync()
	if _, err := run(ctx, "losetup", "--detach", loop); err != nil {
		if installErr == nil {
			return nil, &AssembleError{Step: "detaching the loop device", Err: err}
		}
		logger.Warn("[DISKIMAGE] failed to detach the loop device after a failed install", "loop", loop, "error", err)
	}
	if installErr != nil {
		return nil, &AssembleError{Step: "installing onto the image", Err: installErr}
	}
	return &AssembleResult{Image: opts.Output, SizeBytes: size, LoopDevice: loop}, nil
}

// runInstaller is the production install seam.
func runInstaller(ctx context.Context, logger *logging.Logger, cfg *installer.Config) error {
	inst, err := installer.NewInstaller(logger, cfg)
	if err != nil {
		return err
	}
	defer inst.Close()
	return inst.Install(ctx)
}

// randomPassphrase returns a hex-encoded random passphrase.
func randomPassphrase() (string, error) {
	buf := make([]byte, passphraseBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// createSparseFile creates (or truncates) path at size bytes without
// writing data, so the image costs only what the installer touches.
func createSparseFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

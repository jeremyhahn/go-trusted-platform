package diskimage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// Defaults for BootOptions.
const (
	DefaultBootWorkDir = "work/diskimage-test"
	DefaultBootMemory  = 2048
	// bootDiskName is the working copy of the image under WorkDir.
	bootDiskName = "disk.img"
	// sparseChunk is the copy granularity of copySparse; a chunk that is
	// all zeros becomes a hole in the copy.
	sparseChunk = 1 << 20
)

// BootOptions drives Boot: a factory image booted on the QEMU virt machine
// through U-Boot, with a software TPM behind tpm-tis-device, the way the
// integration suite and `platformctl diskimage test boot` exercise the
// image without a Raspberry Pi.
type BootOptions struct {
	// Image is the raw factory image. It is copied into WorkDir before
	// boot unless InPlace is set, because the first boot changes it
	// (firstboot seals the LUKS key and wipes installer.luks).
	Image string
	// InPlace boots Image itself: the second boot of a sequence wants the
	// disk the first boot left.
	InPlace bool
	// Firmware is the qemu_arm64 u-boot.bin.
	Firmware string
	// WorkDir holds the TPM state (tpm/), the QMP and console sockets and
	// the working copy of the image. Reusing it across boots keeps the
	// TPM state, which is what lets the second boot unseal.
	WorkDir string
	// Memory (MB) and CPUs size the guest; zero means the defaults.
	Memory int
	CPUs   int
	// SerialLog captures the guest's serial console to a file. Empty
	// means the console is interactive on stdio.
	SerialLog string
	// ConsoleSocket, when set, also exposes the console on this unix
	// socket for a harness.Console session.
	ConsoleSocket string
	// Expect, when set, ends the boot as soon as this text appears in
	// SerialLog: the VM is stopped and Boot returns. It needs SerialLog.
	Expect string
	// PortForwards are user-mode network forwards (host port -> guest).
	PortForwards []qemu.PortForward
	// Debug enables QEMU and swtpm debug output.
	Debug bool
	// Logger receives progress; nil means the default logger.
	Logger *logging.Logger

	// startTPM and newVM are the harness and QEMU seams; nil means the
	// real ones. Tests inject fakes so no unit test starts a VM.
	startTPM func(ctx context.Context, logger *logging.Logger, cfg *qemu.Config) (harness.TPM, harness.TPMState, error)
	newVM    func(cfg *qemu.Config, logger *logging.Logger) (bootVM, error)
}

// bootVM is the part of *qemu.VM Boot drives.
type bootVM interface {
	Start(ctx context.Context, mode string) error
	Wait() error
	Stop() error
}

// BootResult reports what Boot did.
type BootResult struct {
	// Disk is the image that was booted (the working copy unless InPlace).
	Disk string
	// TPMState says whether the TPM state was fresh or resumed.
	TPMState harness.TPMState
	// SerialLog is the transcript path, when one was captured.
	SerialLog string
	// Expected is true when Expect was set and the text appeared.
	Expected bool
}

// Boot boots a factory image under emulation and returns when the guest
// powers off, when Expect appears in the serial transcript, or when ctx
// ends. The software TPM is started first and stopped on return.
func Boot(ctx context.Context, opts BootOptions) (*BootResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	startTPM := opts.startTPM
	if startTPM == nil {
		startTPM = harness.StartTPM
	}
	newVM := opts.newVM
	if newVM == nil {
		newVM = func(cfg *qemu.Config, logger *logging.Logger) (bootVM, error) { return qemu.NewVM(cfg, logger) }
	}

	if opts.Image == "" {
		return nil, &BootError{Step: "configuration", Err: &configError{"an image is required"}}
	}
	if opts.Firmware == "" {
		return nil, &BootError{Step: "configuration", Err: &configError{"the U-Boot firmware is required"}}
	}
	if opts.Expect != "" && opts.SerialLog == "" {
		return nil, &BootError{Step: "configuration", Err: &configError{"--expect needs a serial log to watch"}}
	}
	imageInfo, err := os.Stat(opts.Image)
	if err != nil {
		return nil, &BootError{Step: "opening the image", Err: err}
	}
	if _, err := os.Stat(opts.Firmware); err != nil {
		return nil, &BootError{Step: "opening the firmware", Err: err}
	}

	workDir := opts.WorkDir
	if workDir == "" {
		workDir = DefaultBootWorkDir
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, &BootError{Step: "creating the work directory", Err: err}
	}

	disk := opts.Image
	if !opts.InPlace {
		disk = filepath.Join(workDir, bootDiskName)
		logger.Info("[DISKIMAGE] Copying the image for this boot", "from", opts.Image, "to", disk)
		if err := copySparse(opts.Image, disk); err != nil {
			return nil, &BootError{Step: "copying the image", Err: err}
		}
	}

	memory := opts.Memory
	if memory == 0 {
		memory = DefaultBootMemory
	}
	cpus := opts.CPUs
	if cpus == 0 {
		cpus = min(runtime.NumCPU(), 4)
	}
	cfg := &qemu.Config{
		Arch:              qemu.ArchAArch64,
		Firmware:          opts.Firmware,
		DiskPath:          disk,
		DiskFormat:        qemu.DiskFormatRaw,
		DiskSize:          strconv.FormatInt(imageInfo.Size()>>20, 10) + "M",
		Memory:            memory,
		CPUs:              cpus,
		WorkDir:           workDir,
		EnableKVM:         true,
		NoGraphic:         true,
		SerialConsole:     opts.SerialLog == "",
		SerialLogFile:     opts.SerialLog,
		ConsoleSocketPath: opts.ConsoleSocket,
		NetworkMode:       "user",
		PortForwards:      opts.PortForwards,
		Debug:             opts.Debug,
	}

	tpm, tpmState, err := startTPM(ctx, logger, cfg)
	if err != nil {
		return nil, &BootError{Step: "starting the software TPM", Err: err}
	}
	defer harness.StopTPM(logger, tpm)
	logger.Info("[DISKIMAGE] Software TPM running", "state", string(tpmState), "socket", cfg.TPMSocket)

	vm, err := newVM(cfg, logger)
	if err != nil {
		return nil, &BootError{Step: "configuring the VM", Err: err}
	}
	if err := vm.Start(ctx, string(qemu.BootModeBoot)); err != nil {
		return nil, &BootError{Step: "starting the VM", Err: err}
	}
	result := &BootResult{Disk: disk, TPMState: tpmState, SerialLog: opts.SerialLog}

	if opts.Expect == "" {
		logger.Info("[DISKIMAGE] VM started; waiting for it to power off")
		if err := vm.Wait(); err != nil {
			return result, &BootError{Step: "running the VM", Err: err}
		}
		return result, nil
	}

	logger.Info("[DISKIMAGE] VM started; waiting for the milestone", "expect", opts.Expect)
	waitErr := harness.WaitForSerial(ctx, opts.SerialLog, opts.Expect)
	if err := vm.Stop(); err != nil {
		logger.Warn("[DISKIMAGE] failed to stop the VM", "error", err)
	}
	if waitErr != nil {
		return result, &BootError{Step: "waiting for " + strconv.Quote(opts.Expect), Err: waitErr}
	}
	result.Expected = true
	return result, nil
}

// copySparse copies src to dst, punching holes where src is all zeros,
// so a 4 GB image that holds a few hundred megabytes costs what it holds.
func copySparse(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	buf := make([]byte, sparseChunk)
	var offset int64
	for {
		n, err := io.ReadFull(in, buf)
		if n > 0 {
			chunk := buf[:n]
			if !allZero(chunk) {
				if _, err := out.WriteAt(chunk, offset); err != nil {
					_ = out.Close()
					return err
				}
			}
			offset += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			_ = out.Close()
			return err
		}
	}
	if err := out.Truncate(info.Size()); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

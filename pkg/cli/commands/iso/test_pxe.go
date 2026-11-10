// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package iso

import (
	"context"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

var (
	// PXE test flags
	pxeISO        string
	pxeKernel     string
	pxeInitrd     string
	pxeArgs       string
	pxeMemory     int
	pxeCPUs       int
	pxeWorkDir    string
	pxeDebug      bool
	pxeSecureBoot bool

	// Architecture-specific flags (test_pxe_arch.go).
	pxeArchitectureFlag string
	pxeUBoot            string
	pxeIPXE             string
	pxeKeysDir          string
	// Automation: capture the console to a file and stop at a milestone.
	pxeSerialLog string
	pxeExpect    string
	// The client's disk: what a network-booted installer installs to.
	pxeDisk     string
	pxeDiskSize string
)

// DefaultPXEDiskName is the client disk created under the work directory
// when --disk is not given.
const DefaultPXEDiskName = "pxe-client.qcow2"

// newTestPXECommand creates the pxe subcommand for PXE boot testing
func newTestPXECommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pxe",
		Short: "Test PXE boot in isolated network",
		Long: `Test PXE boot using an isolated network environment.

Creates an isolated 10.99.99.0/24 network with bridge, TAP device, and NAT.
Starts a PXE server (HTTP, TFTP, DHCP) and boots a VM via network boot.

The test environment provides complete isolation using:
  - Dedicated bridge network (pxe-br)
  - TAP device for VM (tap-pxe-client)
  - NAT for external connectivity
  - DHCP server on isolated network
  - HTTP server for iPXE scripts and boot files
  - TFTP server for initial PXE firmware

You can specify the boot files in two ways:
  1. Via ISO extraction (--iso): Extracts kernel/initrd from ISO
  2. Direct specification (--kernel, --initrd): Use specific files or URLs

Requirements:
  - Root privileges (required for network setup)
  - QEMU with KVM support
  - OVMF firmware
  - swtpm for TPM emulation

Examples:
  # Boot from ISO (extracts kernel/initrd automatically)
  sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso

  # Boot with direct kernel/initrd URLs
  sudo platformctl iso test pxe \
    --kernel http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/vmlinuz-lts \
    --initrd http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot/initramfs-lts

  # Boot with local kernel/initrd files
  sudo platformctl iso test pxe \
    --kernel /path/to/vmlinuz \
    --initrd /path/to/initramfs \
    --args "console=ttyS0"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestPXE(getFlags(), cmd, args)
		},
	}

	// Boot source flags
	cmd.Flags().StringVar(&pxeISO, "iso", "",
		"Path to ISO file (extracts kernel/initrd automatically)")
	cmd.Flags().StringVar(&pxeKernel, "kernel", "",
		"Path or URL to kernel (overrides ISO extraction)")
	cmd.Flags().StringVar(&pxeInitrd, "initrd", "",
		"Path or URL to initrd (overrides ISO extraction)")
	cmd.Flags().StringVar(&pxeArgs, "args", "",
		"Kernel boot arguments (default: auto-detected from ISO or Alpine defaults)")

	// VM resource flags
	cmd.Flags().IntVar(&pxeMemory, "memory", 4096,
		"RAM in MB")
	cmd.Flags().IntVar(&pxeCPUs, "cpus", runtime.NumCPU(),
		"Number of CPU cores")
	cmd.Flags().StringVar(&pxeWorkDir, "work-dir", "work-pxe",
		"Working directory for VM artifacts and PXE server files")
	cmd.Flags().BoolVar(&pxeDebug, "debug", false,
		"Enable debug output")
	cmd.Flags().BoolVar(&pxeSecureBoot, "secure-boot", false,
		"Enable UEFI Secure Boot")
	cmd.Flags().StringVar(&pxeArchitectureFlag, "architecture", "x86_64",
		"Guest architecture: x86_64 (OVMF) or aarch64 (U-Boot as -bios; the served iPXE and the kernel are signed with the db key)")
	cmd.Flags().StringVar(&pxeUBoot, "uboot", "",
		"aarch64: the qemu_arm64 u-boot.bin (default "+DefaultPXEUBoot+")")
	cmd.Flags().StringVar(&pxeIPXE, "ipxe", "",
		"aarch64: the platform-built arm64 iPXE served to the client (default: "+DefaultPXEIPXE+", from make ipxe-build)")
	cmd.Flags().StringVar(&pxeKeysDir, "keys-dir", "",
		"aarch64: directory holding DB.key and DB.crt, the Secure Boot db U-Boot was preseeded with (default "+DefaultPXEKeysDir+")")
	cmd.Flags().StringVar(&pxeDisk, "disk", "",
		"Client disk image (default: <work-dir>/"+DefaultPXEDiskName+", created when missing)")
	cmd.Flags().StringVar(&pxeDiskSize, "disk-size", "10G",
		"Size of the client disk when it is created")
	cmd.Flags().StringVar(&pxeSerialLog, "serial-log", "",
		"Capture the guest console to this file instead of stdio")
	cmd.Flags().StringVar(&pxeExpect, "expect", "",
		"Stop the VM as soon as this text appears in --serial-log (exit 0), or fail when the context ends first")

	return cmd
}

// runTestPXE executes the PXE boot test
func runTestPXE(commonFlags *cli.CommonFlags, cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if hostEUID() != 0 {
		return &MessageError{Msg: "pxe boot test requires root privileges for network setup: " +
			"please run with sudo: sudo platformctl iso test pxe"}
	}

	logger := createTestLogger(pxeDebug)
	ctx, cancel := createTestContext(0)
	defer cancel()

	printTestHeader("PXE Boot Test")

	// Determine boot entry from flags
	bootEntry, err := resolveBootEntry(logger)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve boot entry", Err: err}
	}
	arch, err := preparePXEArchitecture(ctx, logger)
	if err != nil {
		return err
	}
	if pxeExpect != "" && pxeSerialLog == "" {
		return &MessageError{Msg: "--expect needs --serial-log to watch"}
	}
	if err := os.MkdirAll(pxeWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create work directory", Err: err}
	}
	bootEntry, err = arch.localizeKernel(ctx, logger, bootEntry, pxeWorkDir)
	if err != nil {
		return &WrappedError{Msg: "failed to prepare the kernel for the guest", Err: err}
	}
	printInfo(fmt.Sprintf("Architecture: %s", arch.qemu))

	printInfo(fmt.Sprintf("Boot Entry: %s", bootEntry.Name))
	printInfo(fmt.Sprintf("Kernel: %s", bootEntry.Kernel))
	printInfo(fmt.Sprintf("Initrd: %s", bootEntry.Initrd))
	if bootEntry.Args != "" {
		printInfo(fmt.Sprintf("Args: %s", bootEntry.Args))
	}
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", pxeMemory, pxeCPUs))
	printInfo(fmt.Sprintf("Work Dir: %s", pxeWorkDir))

	// Create work directory
	if err := os.MkdirAll(pxeWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create work directory", Err: err}
	}

	// The isolated network and the PXE server on it are the package's own
	// test environment (ipxe.DefaultTestEnvConfig: pxe-br, 10.99.99.0/24,
	// leases .100-.200), so the bridge's subnet is the one the leases are
	// in. A hand-rolled copy here once put the bridge on a /28, and every
	// unicast reply to a leased client — the TFTP data — left through the
	// host's default route instead of the bridge.
	printInfo("Setting up isolated network environment...")
	envConfig := ipxe.DefaultTestEnvConfig()
	envConfig.LocalFilesDir = filepath.Join(pxeWorkDir, "pxe-files")
	envConfig.FirmwareSigner = arch.signer
	envConfig.FirmwareOverrides = arch.firmwareOverrides
	if err := os.MkdirAll(envConfig.LocalFilesDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create PXE files directory", Err: err}
	}
	// A local kernel or initrd is served from the files directory; the
	// boot script can only name URLs.
	filesURL := fmt.Sprintf("http://%s:%d/files", envConfig.ServerIP, envConfig.HTTPPort)
	bootEntry, err = publishBootFiles(bootEntry, envConfig.LocalFilesDir, filesURL)
	if err != nil {
		return err
	}
	envConfig.BootEntries = []ipxe.BootEntry{bootEntry}

	env, err := newPXETestEnv(envConfig, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create PXE test environment", Err: err}
	}
	if err := env.Setup(); err != nil {
		return &WrappedError{Msg: "failed to setup isolated network", Err: err}
	}
	defer func() {
		printInfo("Cleaning up isolated network...")
		if err := env.Cleanup(); err != nil {
			logger.Warnf("Failed to cleanup network: %v", err)
		}
		printSuccess("Network cleanup complete")
	}()

	printSuccess("Isolated network ready")
	printInfo(fmt.Sprintf("Bridge: %s", envConfig.BridgeName))
	printInfo(fmt.Sprintf("TAP Device: %s", env.TapName()))
	printInfo(fmt.Sprintf("Server IP: %s", env.ServerIP()))

	// Start the PXE server (HTTP, TFTP, DHCP) in the background; Start
	// returns only when the context ends or a listener fails.
	printInfo("Starting PXE server (HTTP, TFTP, DHCP)...")
	pxeCtx, pxeCancel := context.WithCancel(ctx)
	defer pxeCancel()

	pxeErrChan := make(chan error, 1)
	go func() {
		pxeErrChan <- env.Start(pxeCtx)
	}()

	// Wait for PXE server to be ready
	printInfo("Waiting for PXE server to be ready...")
	select {
	case <-env.Ready():
	case err := <-pxeErrChan:
		pxeCancel()
		return &WrappedError{Msg: "PXE server not ready", Err: err}
	case <-time.After(pxeServerReadyTimeout):
		pxeCancel()
		return &MessageError{Msg: "PXE server not ready after " + pxeServerReadyTimeout.String()}
	}
	printSuccess("PXE server ready")

	// Create QEMU configuration for PXE boot
	// The client has a disk — an empty one, so firmware falls through to
	// the network, and the installer the network delivers has a target.
	qemuConfig := &qemu.Config{
		DiskPath:      pxeDiskPath(),
		DiskSize:      pxeDiskSize,
		Memory:        pxeMemory,
		CPUs:          pxeCPUs,
		WorkDir:       pxeWorkDir,
		SecureBoot:    pxeSecureBoot,
		Debug:         pxeDebug,
		TapDevice:     env.TapName(),
		PXEEnabled:    true,
		EnableKVM:     true,
		SerialConsole: pxeSerialLog == "",
		SerialLogFile: pxeSerialLog,
		NoGraphic:     true,
		Arch:          arch.qemu,
		Firmware:      arch.firmware,
	}

	// Setup VM environment
	if err := setupTestVMEnvironment(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to setup VM environment", Err: err}
	}

	// Initialize and start TPM
	tpm, err := setupTestTPM(ctx, logger, qemuConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to setup TPM", Err: err}
	}
	defer stopTestTPM(logger, tpm)

	// Enroll Secure Boot keys if enabled
	// U-Boot carries the keys preseeded; enrolment is OVMF's need.
	if pxeSecureBoot && arch.qemu != qemu.ArchAArch64 {
		if err := enrollTestSecureBootKeys(ctx, logger, qemuConfig); err != nil {
			logger.Warnf("Failed to enroll Secure Boot keys: %v", err)
			logger.Warnf("Continuing without Secure Boot key enrollment")
		}
	}

	printSuccess("VM environment ready")

	// Start QEMU with PXE boot
	printInfo("Starting QEMU VM with PXE boot...")
	printInfo("The VM will boot from the network via PXE")
	printInfo("Press Ctrl+C to exit")

	if err := runQEMUPXE(ctx, logger, qemuConfig); err != nil {
		pxeCancel()
		// Check if PXE server failed
		select {
		case pxeErr := <-pxeErrChan:
			if pxeErr != nil {
				return &PXEServerQEMUError{PXEErr: pxeErr, QEMUErr: err}
			}
		default:
		}
		return &WrappedError{Msg: "QEMU PXE boot failed", Err: err}
	}

	// Stop PXE server gracefully
	printInfo("Stopping PXE server...")
	pxeCancel()
	if err := env.Stop(); err != nil {
		logger.Warnf("Failed to stop the PXE server: %v", err)
	}

	printSuccess("PXE boot test completed")
	return nil
}

// resolveBootEntry determines the boot entry from command flags
func resolveBootEntry(logger *logging.Logger) (ipxe.BootEntry, error) {
	// If kernel and initrd are explicitly provided, use them
	if pxeKernel != "" && pxeInitrd != "" {
		logger.Info("Using direct kernel and initrd specification")

		args := pxeArgs
		if args == "" {
			// Default Alpine kernel arguments
			args = "console=tty0 console=ttyS0,115200 modules=loop,squashfs,sd-mod,usb-storage quiet"
		}

		return ipxe.BootEntry{
			Name:        "custom",
			Description: "Custom PXE Boot",
			Kernel:      pxeKernel,
			Initrd:      pxeInitrd,
			Args:        args,
		}, nil
	}

	// If kernel is provided but not initrd (or vice versa), error
	if pxeKernel != "" || pxeInitrd != "" {
		return ipxe.BootEntry{}, &MessageError{Msg: "both --kernel and --initrd must be specified together"}
	}

	// Must provide ISO for extraction
	if pxeISO == "" {
		return ipxe.BootEntry{}, &MessageError{Msg: "must specify either --iso or (--kernel and --initrd)"}
	}

	// Extract kernel/initrd from ISO
	logger.Info("Extracting boot files from ISO", "iso", pxeISO)

	if _, err := os.Stat(pxeISO); os.IsNotExist(err) {
		return ipxe.BootEntry{}, &MessageError{Msg: fmt.Sprintf("ISO file not found: %s", pxeISO)}
	}

	// Create extraction directory
	extractDir := filepath.Join(pxeWorkDir, "iso-extract")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return ipxe.BootEntry{}, &WrappedError{Msg: "failed to create extraction directory", Err: err}
	}

	// Extract ISO using the iso package ExtractISO function
	// For simplicity, we'll use 7z directly here to avoid circular dependencies
	logger.Info("Extracting ISO contents", "destination", extractDir)

	if err := extractISOContents(pxeISO, extractDir); err != nil {
		return ipxe.BootEntry{}, &WrappedError{Msg: "failed to extract ISO", Err: err}
	}

	// Locate kernel and initrd in extracted files
	// Alpine ISOs typically have boot/vmlinuz-lts and boot/initramfs-lts
	kernelPath := filepath.Join(extractDir, "boot", "vmlinuz-lts")
	initrdPath := filepath.Join(extractDir, "boot", "initramfs-lts")

	if _, err := os.Stat(kernelPath); os.IsNotExist(err) {
		// Try alternative kernel names
		kernelPath = filepath.Join(extractDir, "boot", "vmlinuz")
		if _, err := os.Stat(kernelPath); os.IsNotExist(err) {
			return ipxe.BootEntry{}, &MessageError{Msg: "kernel not found in ISO (tried boot/vmlinuz-lts and boot/vmlinuz)"}
		}
	}

	if _, err := os.Stat(initrdPath); os.IsNotExist(err) {
		// Try alternative initrd names
		initrdPath = filepath.Join(extractDir, "boot", "initramfs")
		if _, err := os.Stat(initrdPath); os.IsNotExist(err) {
			return ipxe.BootEntry{}, &MessageError{Msg: "initrd not found in ISO (tried boot/initramfs-lts and boot/initramfs)"}
		}
	}

	logger.Info("Boot files extracted successfully",
		"kernel", kernelPath,
		"initrd", initrdPath)

	args := pxeArgs
	if args == "" {
		// Read kernel arguments from ISO if available
		argsPath := filepath.Join(extractDir, "boot", "cmdline.txt")
		if data, err := os.ReadFile(argsPath); err == nil {
			args = string(data)
			logger.Info("Using kernel arguments from ISO", "args", args)
		} else {
			// Default Alpine kernel arguments
			args = "console=tty0 console=ttyS0,115200 modules=loop,squashfs,sd-mod,usb-storage quiet"
			logger.Info("Using default kernel arguments", "args", args)
		}
	}

	return ipxe.BootEntry{
		Name:        "alpine-iso",
		Description: "Alpine Linux from ISO",
		Kernel:      "file://" + kernelPath,
		Initrd:      "file://" + initrdPath,
		Args:        args,
	}, nil
}

// extractISOContents extracts ISO contents using 7z
func extractISOContents(isoPath, destDir string) error {
	// Remove existing directory
	os.RemoveAll(destDir)

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}

	// Execute 7z extraction
	// Try different extraction methods
	extractors := []struct {
		command string
		args    []string
	}{
		{"7z", []string{"x", isoPath, "-o" + destDir}},
		{"bsdtar", []string{"-xf", isoPath, "-C", destDir}},
	}

	var lastErr error
	for _, ex := range extractors {
		cmd := exec.CommandContext(context.Background(), ex.command, ex.args...)
		if err := runHostCommand(cmd); err != nil {
			lastErr = err
			continue
		}
		// Success
		return nil
	}

	if lastErr != nil {
		return &WrappedError{Msg: "failed to extract ISO (tried 7z, bsdtar)", Err: lastErr}
	}

	return &MessageError{Msg: "no ISO extraction tools available (tried 7z, bsdtar)"}
}

// runQEMUPXE runs QEMU with PXE boot mode
func runQEMUPXE(ctx context.Context, logger *logging.Logger, config *qemu.Config) error {
	// Create QEMU VM
	vm, err := newQEMUVM(config, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create VM", Err: err}
	}

	// An absent disk is created empty; an existing one is kept (a second
	// run boots what the first installed).
	if err := vmCreateDisk(vm); err != nil {
		return &WrappedError{Msg: "preparing the client disk", Err: err}
	}

	// Start VM in PXE boot mode
	logger.Info("Starting QEMU in PXE boot mode...")
	if err := vmStart(vm, ctx, string(qemu.BootModePXE)); err != nil {
		return &WrappedError{Msg: "failed to start VM", Err: err}
	}

	if pxeExpect != "" {
		// Automated: the milestone in the serial log ends the run.
		logger.Info("VM started; waiting for the milestone", "expect", pxeExpect, "serial_log", pxeSerialLog)
		waitErr := harness.WaitForSerial(ctx, pxeSerialLog, pxeExpect)
		if err := vmStop(vm); err != nil {
			logger.Warnf("failed to stop the VM: %v", err)
		}
		if waitErr != nil {
			return &WrappedError{Msg: "waiting for " + strconv.Quote(pxeExpect), Err: waitErr}
		}
		logger.Info("Milestone reached", "expect", pxeExpect)
		return nil
	}

	// Wait for VM to complete
	logger.Info("VM started, waiting for PXE boot to complete (press Ctrl+C to exit)...")
	if err := vmWait(vm); err != nil {
		// PXE boot failures are not necessarily fatal
		// The VM may be waiting for user interaction
		logger.Warnf("VM execution completed with status: %v", err)
	}

	logger.Info("PXE boot session completed")
	return nil
}

// pxeDiskPath is --disk, or the default disk under the work directory.
func pxeDiskPath() string {
	if pxeDisk != "" {
		return pxeDisk
	}
	return filepath.Join(pxeWorkDir, DefaultPXEDiskName)
}

// publishBootFiles copies a boot entry's local (file://) kernel and initrd
// into filesDir, which the PXE server serves at filesURL, and rewrites the
// entry to fetch them from there. iPXE can only fetch URLs; a file:// entry
// would reach the script verbatim and fail on the client.
func publishBootFiles(entry ipxe.BootEntry, filesDir, filesURL string) (ipxe.BootEntry, error) {
	publish := func(ref string) (string, error) {
		if !strings.HasPrefix(ref, "file://") {
			return ref, nil
		}
		src := strings.TrimPrefix(ref, "file://")
		name := filepath.Base(src)
		if err := copyFile(src, filepath.Join(filesDir, name)); err != nil {
			return "", &WrappedError{Msg: "publishing " + src + " for the PXE client", Err: err}
		}
		return filesURL + "/" + name, nil
	}
	var err error
	if entry.Kernel, err = publish(entry.Kernel); err != nil {
		return entry, err
	}
	if entry.Initrd, err = publish(entry.Initrd); err != nil {
		return entry, err
	}
	return entry, nil
}

// copyFile copies src to dst, replacing dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

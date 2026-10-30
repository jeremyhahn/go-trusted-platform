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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// testFlags holds flags for the test commands
type testFlags struct {
	iso        string
	disk       string
	diskSize   string
	diskCache  string
	memory     int
	cpus       int
	workDir    string
	secureBoot bool
	debug      bool

	// FIDO2/CanoKey flags
	fido2Enable bool
	fido2Mode   string
	canoKeyFile string
	canoKeyPcap string
	u2fPassthru string

	// Custom QEMU binary for CanoKey support
	qemuBinary string

	// Network mode flag
	networkMode string

	// timeout bounds a headless run; zero waits until the guest powers off
	timeout time.Duration

	// expect is the boot milestone on the serial console that ends a
	// headless boot test; empty waits until the guest powers off
	expect string
}

// newTestCommand creates the test subcommand for ISO testing
func newTestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &testFlags{}

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test ISO images in QEMU",
		Long: `Test platform ISO images using QEMU with TPM support.

Provides subcommands for testing installation, first boot, and subsequent boots
of the platform ISO in a virtual machine environment with software TPM.`,
	}

	// testInstallCmd tests ISO installation
	testInstallCmd := &cobra.Command{
		Use:   "install",
		Short: "Test ISO installation",
		Long: `Test ISO installation in QEMU with TPM support.

Creates a new virtual disk and boots from the ISO to test the installation
process. The disk is preserved for subsequent boot tests.

Example:
  platformctl iso test install --iso trusted-platform-alpine.iso --disk alpine-installed.qcow2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestInstall(getFlags(), flags)
		},
	}

	// testFirstBootCmd tests first boot after installation
	testFirstBootCmd := &cobra.Command{
		Use:   "firstboot",
		Short: "Test first boot after installation",
		Long: `Test first boot after installation with TPM unlock.

Boots from the installed disk and tests the first boot sequence including
TPM-based disk encryption unlock. Requires a previously installed disk.

Example:
  platformctl iso test firstboot --disk alpine-installed.qcow2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestFirstBoot(getFlags(), flags, "First Boot Test")
		},
	}

	// testBootCmd tests normal boot
	testBootCmd := &cobra.Command{
		Use:   "boot",
		Short: "Test normal boot",
		Long: `Test normal boot from installed disk with TPM unlock.

Boots from the installed disk and tests the boot sequence including
TPM-based disk encryption unlock. Requires a previously installed disk.

With --expect, the test passes as soon as the milestone appears on the
serial console (an installed node never powers off by itself) and the VM
is stopped; it needs --timeout, which sends the console to a log.

Example:
  platformctl iso test boot --disk alpine-installed.qcow2
  platformctl iso test boot --disk alpine-installed.qcow2 --timeout 20m --expect 'login:'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestBoot(getFlags(), flags, "Normal Boot Test")
		},
	}

	// testAllCmd runs all tests sequentially
	testAllCmd := &cobra.Command{
		Use:   "all",
		Short: "Run all tests sequentially",
		Long: `Run all ISO tests sequentially.

Executes installation test followed by first boot and normal boot tests.
This provides a complete end-to-end test of the platform ISO.

Example:
  platformctl iso test all --iso trusted-platform-alpine.iso`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestAll(getFlags(), flags)
		},
	}

	// Add test subcommands
	cmd.AddCommand(testInstallCmd)
	cmd.AddCommand(testFirstBootCmd)
	cmd.AddCommand(testBootCmd)
	cmd.AddCommand(testAllCmd)
	cmd.AddCommand(createClientServerCommand(getFlags))
	cmd.AddCommand(newTestPXECommand(getFlags))

	// Common flags for all test commands
	for _, subcmd := range []*cobra.Command{testInstallCmd, testFirstBootCmd, testBootCmd, testAllCmd} {
		subcmd.Flags().StringVar(&flags.disk, "disk", "alpine-platform-installed.qcow2",
			"Path to qcow2 disk image")
		subcmd.Flags().StringVar(&flags.diskSize, "disk-size", "10G",
			"Disk size (e.g., 2G, 10G, 20G)")
		subcmd.Flags().StringVar(&flags.diskCache, "disk-cache", "",
			"QEMU disk cache mode: writethrough (default), writeback, none, unsafe, directsync. Nested-virt hosts should use unsafe or writeback")
		subcmd.Flags().IntVar(&flags.memory, "memory", 8192,
			"RAM in MB")
		subcmd.Flags().IntVar(&flags.cpus, "cpus", runtime.NumCPU(),
			"Number of CPU cores")
		subcmd.Flags().StringVar(&flags.workDir, "work-dir", "work",
			"Working directory for VM artifacts")
		subcmd.Flags().BoolVar(&flags.secureBoot, "secure-boot", true,
			"Enable UEFI Secure Boot")
		subcmd.Flags().BoolVar(&flags.debug, "debug", false,
			"Enable debug output")

		// FIDO2/CanoKey flags
		subcmd.Flags().BoolVar(&flags.fido2Enable, "fido2", false,
			"Enable FIDO2/CanoKey device emulation for LUKS unlock testing")
		subcmd.Flags().StringVar(&flags.fido2Mode, "fido2-mode", "canokey",
			"FIDO2 mode: 'canokey' (full FIDO2+HMAC-secret), 'u2f-emulated', or 'u2f-passthru'")
		subcmd.Flags().StringVar(&flags.canoKeyFile, "canokey-file", "",
			"CanoKey state file path (default: $workdir/canokey/canokey.state)")
		subcmd.Flags().StringVar(&flags.canoKeyPcap, "canokey-pcap", "",
			"CanoKey USB packet capture file for debugging")
		subcmd.Flags().StringVar(&flags.u2fPassthru, "u2f-device", "",
			"Host hidraw device for U2F passthrough (e.g., /dev/hidraw0)")
		subcmd.Flags().StringVar(&flags.qemuBinary, "qemu-binary", "",
			"Custom QEMU binary path (default: qemu-system-x86_64, use qemu-system-x86_64-canokey for CanoKey)")
		subcmd.Flags().StringVar(&flags.networkMode, "network", "",
			"Network mode: 'user' (NAT), 'bridge' (requires bridge helper), or 'none' (default: auto-detect)")
		subcmd.Flags().DurationVar(&flags.timeout, "timeout", 0,
			"Stop the VM and fail when the guest has not powered off within this duration, e.g. 45m (default: wait until it powers off)")
	}

	// ISO flag only for install and all commands
	// Default uses same convention as create: trusted-alpine-<version>-x86_64.iso
	// An installed node never powers off: a milestone ends its boot test
	for _, subcmd := range []*cobra.Command{testFirstBootCmd, testBootCmd} {
		subcmd.Flags().StringVar(&flags.expect, "expect", "",
			"Pass when this line appears on the serial console, then stop the VM, e.g. 'login:' (needs --timeout; default: wait until the guest powers off)")
	}

	testInstallCmd.Flags().StringVar(&flags.iso, "iso", "",
		"Path to ISO file (default: trusted-alpine-<version>-x86_64.iso)")

	testAllCmd.Flags().StringVar(&flags.iso, "iso", "",
		"Path to ISO file (default: trusted-alpine-<version>-x86_64.iso)")

	return cmd
}

// runTestInstall executes the installation test
func runTestInstall(commonFlags *cli.CommonFlags, flags *testFlags) error {
	// Validate flag values before ANY destructive setup (disk creation,
	// NVRAM reset) so bad input cannot mutate reusable VM state.
	if err := qemu.ValidateDiskCache(flags.diskCache); err != nil {
		return err
	}

	logger := createTestLogger(flags.debug)
	ctx, cancel := createTestContext(flags.timeout)
	defer cancel()

	printTestHeader("ISO Installation Test")

	// Auto-detect ISO if not specified (uses same convention as create command)
	if flags.iso == "" {
		flags.iso = resolveDefaultISO()
	}

	// Validate ISO exists
	if _, err := os.Stat(flags.iso); os.IsNotExist(err) {
		return ErrISONotFound{Path: flags.iso}
	}

	printInfo(fmt.Sprintf("ISO: %s", flags.iso))
	printInfo(fmt.Sprintf("Disk: %s (size: %s)", flags.disk, flags.diskSize))
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", flags.memory, flags.cpus))
	printInfo(fmt.Sprintf("Secure Boot: %v", flags.secureBoot))
	if flags.fido2Enable {
		printInfo(fmt.Sprintf("FIDO2: enabled (mode: %s)", flags.fido2Mode))
	}

	// Create QEMU configuration
	config := createTestQEMUConfig(flags)
	config.ISO = flags.iso

	// Setup VM environment
	if err := setupTestVMEnvironment(ctx, logger, config); err != nil {
		return &WrappedError{Msg: "failed to setup VM environment", Err: err}
	}

	// Reset NVRAM for fresh installation — stale boot entries from previous
	// runs prevent OVMF from discovering the CD-ROM as a boot device.
	if err := resetTestNVRAM(ctx, logger, config); err != nil {
		return &WrappedError{Msg: "failed to reset NVRAM", Err: err}
	}

	// Create disk image
	if err := createTestDiskImage(ctx, logger, flags.disk, flags.diskSize); err != nil {
		return &WrappedError{Msg: "failed to create disk image", Err: err}
	}

	// Initialize and start TPM
	tpm, err := setupTestTPM(ctx, logger, config)
	if err != nil {
		return &WrappedError{Msg: "failed to setup TPM", Err: err}
	}
	defer stopTestTPM(logger, tpm)

	// Enroll Secure Boot keys if enabled
	// This is required for ISO boot when Secure Boot is enabled
	if err := enrollTestSecureBootKeys(ctx, logger, config); err != nil {
		return &WrappedError{Msg: "failed to enroll Secure Boot keys", Err: err}
	}

	printSuccess("VM environment ready")

	// Start QEMU with installation boot
	printInfo("Starting QEMU for installation (this will open an interactive session)...")
	printInfo("Press Ctrl+C to exit when installation is complete")

	if err := runTestQEMUInstall(ctx, logger, config); err != nil {
		return testVMError(flags.timeout, "QEMU installation failed", err)
	}

	printSuccess("Installation test completed")
	return nil
}

// runTestFirstBoot executes the first boot test
func runTestFirstBoot(commonFlags *cli.CommonFlags, flags *testFlags, testName string) error {
	return runTestBootCommon(commonFlags, flags, testName)
}

// runTestBoot executes the normal boot test
func runTestBoot(commonFlags *cli.CommonFlags, flags *testFlags, testName string) error {
	return runTestBootCommon(commonFlags, flags, testName)
}

// runTestBootCommon is the common implementation for boot tests
func runTestBootCommon(commonFlags *cli.CommonFlags, flags *testFlags, testName string) error {
	// Validate flag values before any destructive setup (NVRAM reset).
	if flags.expect != "" && flags.timeout <= 0 {
		return &MessageError{Msg: "--expect needs --timeout: the milestone is read from the headless console log"}
	}
	if err := qemu.ValidateDiskCache(flags.diskCache); err != nil {
		return err
	}

	logger := createTestLogger(flags.debug)
	ctx, cancel := createTestContext(flags.timeout)
	defer cancel()

	printTestHeader(testName)

	// Validate disk exists
	if _, err := os.Stat(flags.disk); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("disk not found: %s. Run 'install' first", flags.disk)}
	}

	printInfo(fmt.Sprintf("Disk: %s", flags.disk))
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", flags.memory, flags.cpus))
	printInfo(fmt.Sprintf("Secure Boot: %v", flags.secureBoot))
	if flags.fido2Enable {
		printInfo(fmt.Sprintf("FIDO2: enabled (mode: %s)", flags.fido2Mode))
	}

	// Create QEMU configuration
	config := createTestQEMUConfig(flags)

	// A headless run (--timeout) has no terminal to show the console on:
	// it goes to a log in --work-dir, whose tail a failure reports.
	if flags.timeout > 0 {
		config.SerialConsole = false
		config.SerialLogFile = filepath.Join(flags.workDir, bootConsoleLogName)
		if err := resetConsoleLog(config.SerialLogFile); err != nil {
			return err
		}
		printInfo(fmt.Sprintf("Console log: %s", config.SerialLogFile))
	}

	// Setup VM environment
	if err := setupTestVMEnvironment(ctx, logger, config); err != nil {
		return &WrappedError{Msg: "failed to setup VM environment", Err: err}
	}

	// Initialize and start TPM
	tpm, err := setupTestTPM(ctx, logger, config)
	if err != nil {
		return &WrappedError{Msg: "failed to setup TPM", Err: err}
	}
	defer stopTestTPM(logger, tpm)

	// Enroll Secure Boot keys if enabled
	if err := enrollTestSecureBootKeys(ctx, logger, config); err != nil {
		return &WrappedError{Msg: "failed to enroll Secure Boot keys", Err: err}
	}

	printSuccess("VM environment ready")

	// Start QEMU with boot from disk
	printInfo("Starting QEMU for boot test (this will open an interactive session)...")
	printInfo("Press Ctrl+C to exit")

	started := time.Now()
	if err := runTestQEMUBoot(ctx, logger, config, flags.expect); err != nil {
		return bootError(flags.timeout, time.Since(started), config.SerialLogFile, err)
	}

	printSuccess("Boot test completed")
	return nil
}

// runTestAll executes all tests sequentially
func runTestAll(commonFlags *cli.CommonFlags, flags *testFlags) error {
	printTestHeader("Running All ISO Tests")

	// Auto-detect ISO if not specified (uses same convention as create command)
	if flags.iso == "" {
		flags.iso = resolveDefaultISO()
	}

	// Run installation test
	printInfo("Step 1/3: Installation Test")
	if err := runTestInstall(commonFlags, flags); err != nil {
		return &WrappedError{Msg: "installation test failed", Err: err}
	}

	printInfo("\nStep 2/3: First Boot Test")
	if err := runTestFirstBoot(commonFlags, flags, "First Boot Test"); err != nil {
		return &WrappedError{Msg: "first boot test failed", Err: err}
	}

	printInfo("\nStep 3/3: Normal Boot Test")
	if err := runTestBoot(commonFlags, flags, "Normal Boot Test"); err != nil {
		return &WrappedError{Msg: "normal boot test failed", Err: err}
	}

	printSuccess("\nAll tests completed successfully!")
	return nil
}

// Helper functions

// createTestQEMUConfig creates a QEMU configuration from command flags
func createTestQEMUConfig(flags *testFlags) *qemu.Config {
	config := defaultQEMUConfig()
	config.DiskPath = flags.disk
	config.DiskSize = flags.diskSize
	config.DiskCache = flags.diskCache
	config.Memory = flags.memory
	config.CPUs = flags.cpus
	config.WorkDir = flags.workDir
	config.SecureBoot = flags.secureBoot
	config.Debug = flags.debug
	// Always use serial console and no graphics for headless operation
	// The default config already has these set to true, so we keep them
	config.SerialConsole = true
	config.NoGraphic = true

	// Set network mode if specified (override auto-detection)
	if flags.networkMode != "" {
		config.NetworkMode = flags.networkMode
	}

	// Set custom QEMU binary if specified
	if flags.qemuBinary != "" {
		config.QEMUBinary = flags.qemuBinary
	}

	// Configure FIDO2/CanoKey if enabled
	if flags.fido2Enable {
		config.FIDO2 = &qemu.FIDO2Config{
			Enable:         true,
			Mode:           flags.fido2Mode,
			CanoKeyFile:    flags.canoKeyFile,
			CanoKeyPcap:    flags.canoKeyPcap,
			PassthruDevice: flags.u2fPassthru,
		}

		// Auto-select CanoKey QEMU binary if FIDO2 is enabled in canokey mode
		// and no custom binary is specified
		if flags.qemuBinary == "" && (flags.fido2Mode == "canokey" || flags.fido2Mode == "") {
			// Check if CanoKey-enabled QEMU is available
			if _, err := exec.LookPath("qemu-system-x86_64-canokey"); err == nil {
				config.QEMUBinary = "qemu-system-x86_64-canokey"
			}
		}
	}

	return config
}

// createTestLogger creates a logger instance
func createTestLogger(debug bool) *logging.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return logging.NewLogger(level, nil)
}

// createTestContext creates a context with cancellation support
func createTestContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		// A headless run (CI) has nobody to press Ctrl+C: the deadline
		// kills QEMU when the guest never powers off.
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, cleaning up...")
		cancel()
	}()

	return ctx, cancel
}

// setupTestVMEnvironment creates necessary directories and files
func setupTestVMEnvironment(ctx context.Context, logger *logging.Logger, config *qemu.Config) error {
	// Create work directory
	if err := os.MkdirAll(config.WorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create work directory", Err: err}
	}

	// Create NVRAM directory
	nvramDir := filepath.Join(config.WorkDir, "nvram")
	if err := os.MkdirAll(nvramDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create NVRAM directory", Err: err}
	}

	// Initialize NVRAM if needed. U-Boot (aarch64) keeps its EFI variables
	// on the ESP, so there is no NVRAM template to copy.
	nvramPath := config.GetNVRAMPath()
	if config.Arch == qemu.ArchAArch64 {
		logger.Infof("U-Boot firmware: no NVRAM to initialise")
	} else if _, err := os.Stat(nvramPath); os.IsNotExist(err) {
		logger.Infof("Initializing OVMF NVRAM from template...")
		if err := copyTestFile(config.OVMFVars, nvramPath); err != nil {
			return &WrappedError{Msg: "failed to initialize NVRAM", Err: err}
		}
	} else {
		logger.Infof("Using existing OVMF NVRAM")
	}

	// Create TPM directory
	tpmDir := filepath.Join(config.WorkDir, "tpm")
	if err := os.MkdirAll(tpmDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create TPM directory", Err: err}
	}

	return nil
}

// resetTestNVRAM removes existing NVRAM and creates a fresh copy from template.
// This ensures a clean UEFI boot order for fresh installations.
// The default UEFI firmware will boot from CD-ROM when no other boot entries exist.
func resetTestNVRAM(ctx context.Context, logger *logging.Logger, config *qemu.Config) error {
	nvramPath := config.GetNVRAMPath()
	nvramDir := filepath.Dir(nvramPath)

	// Create NVRAM directory if needed
	if err := os.MkdirAll(nvramDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create NVRAM directory", Err: err}
	}

	// Remove existing NVRAM to force fresh boot order
	if _, err := os.Stat(nvramPath); err == nil {
		logger.Infof("Resetting NVRAM for fresh installation: %s", nvramPath)
		if err := os.Remove(nvramPath); err != nil {
			return &WrappedError{Msg: "failed to remove existing NVRAM", Err: err}
		}
	}

	// Copy fresh NVRAM from template
	logger.Infof("Initializing OVMF NVRAM from template...")
	if err := copyTestFile(config.OVMFVars, nvramPath); err != nil {
		return &WrappedError{Msg: "failed to initialize NVRAM", Err: err}
	}

	return nil
}

// createTestDiskImage creates a new qcow2 disk image
func createTestDiskImage(ctx context.Context, logger *logging.Logger, diskPath, diskSize string) error {
	// Remove existing disk if present
	if _, err := os.Stat(diskPath); err == nil {
		logger.Infof("Removing existing disk: %s", diskPath)
		if err := os.Remove(diskPath); err != nil {
			return &WrappedError{Msg: "failed to remove existing disk", Err: err}
		}
	}

	logger.Infof("Creating disk image: %s (%s)", diskPath, diskSize)

	// Create new disk using qemu-img
	cmd := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", diskPath, diskSize)
	if err := runHostCommand(cmd); err != nil {
		return &WrappedError{Msg: "failed to create disk image", Err: err}
	}

	return nil
}

// setupTestTPM starts the software TPM through the shared harness and
// reports what it did; the harness owns the state-directory reuse that
// keeps PCR values and sealed data across the boots of one test sequence.
func setupTestTPM(ctx context.Context, logger *logging.Logger, config *qemu.Config) (harness.TPM, error) {
	tpm, state, err := startTPM(ctx, logger, config)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to setup TPM", Err: err}
	}
	switch state {
	case harness.TPMStateInitialized:
		printSuccess("Software TPM initialized")
	case harness.TPMStatePreserved:
		printSuccess("Software TPM state preserved")
	}
	printSuccess(fmt.Sprintf("Software TPM started (PID: %d)", tpm.PID()))
	return tpm, nil
}

// stopTestTPM gracefully stops the TPM daemon
func stopTestTPM(logger *logging.Logger, tpm harness.TPM) {
	stopTPM(logger, tpm)
}

// enrollTestSecureBootKeys enrolls Secure Boot keys into NVRAM for boot tests
func enrollTestSecureBootKeys(ctx context.Context, logger *logging.Logger, config *qemu.Config) error {
	if !config.SecureBoot {
		logger.Debug("Secure Boot disabled, skipping key enrollment")
		return nil
	}

	nvramDir := filepath.Join(config.WorkDir, "nvram")

	// Check multiple locations for Secure Boot keys
	// Keys may be in the main work dir or in the ISO build subdirectory
	keysDirCandidates := []string{
		filepath.Join(config.WorkDir, "secure-boot-keys"),
		filepath.Join(config.WorkDir, "iso-build", "secure-boot-keys"),
	}

	var keysDir string
	for _, candidate := range keysDirCandidates {
		if _, err := os.Stat(candidate); err == nil {
			keysDir = candidate
			break
		}
	}

	if keysDir == "" {
		logger.Warn("Secure Boot keys directory not found, skipping enrollment",
			"searched", keysDirCandidates)
		return nil
	}

	// Create SecureBootEnroller configuration
	enrollerConfig := &qemu.SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     nvramDir,
		OVMFVarsPath: config.OVMFVars,
		Debug:        config.Debug,
	}

	// Create enroller
	enroller, err := newSecureBootEnroller(enrollerConfig, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create Secure Boot enroller", Err: err}
	}

	// Check if keys are already enrolled to preserve existing NVRAM
	// (which may contain boot entries from installation)
	if enroller.IsEnrolled() {
		logger.Info("Secure Boot keys already enrolled, preserving existing NVRAM")
		return nil
	}

	// Enroll keys
	logger.Info("Enrolling Secure Boot keys into NVRAM...")
	if err := enroller.EnrollKeys(ctx); err != nil {
		return &WrappedError{Msg: "failed to enroll Secure Boot keys", Err: err}
	}

	printSuccess("Secure Boot keys enrolled successfully")
	return nil
}

// runTestQEMUInstall runs QEMU for installation
func runTestQEMUInstall(ctx context.Context, logger *logging.Logger, config *qemu.Config) error {
	// Create QEMU VM
	vm, err := newQEMUVM(config, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create VM", Err: err}
	}

	// Start VM in install mode
	logger.Info("Starting QEMU in installation mode...")
	if err := vmStart(vm, ctx, string(qemu.BootModeInstall)); err != nil {
		return &WrappedError{Msg: "failed to start VM", Err: err}
	}

	// Wait for VM to complete
	logger.Info("VM started, waiting for installation to complete (press Ctrl+C to exit)...")
	return installWaitResult(ctx, vmWait(vm), config.DiskPath, logger)
}

// installWaitResult decides whether an install VM that has exited
// installed the disk. A VM killed at the context deadline failed even
// when the disk already holds data: the install was cut off. Otherwise a
// non-zero exit is the reboot that ends the autoinstall (or Ctrl+C), and
// it counts as success when the disk exceeds 100 MB.
func installWaitResult(ctx context.Context, waitErr error, diskPath string, logger *logging.Logger) error {
	if err := vmDeadlineError(ctx); err != nil {
		return err
	}
	// The autoinstaller powers the guest off whether the install passed or
	// failed (its inittab ends with /sbin/poweroff -f), so a clean exit is
	// an install only when the disk was written, like a reboot.
	var size int64
	if info, err := os.Stat(diskPath); err == nil {
		size = info.Size()
	}
	written := size > minInstalledDiskSize
	if waitErr != nil {
		if written {
			logger.Info("Installation completed successfully (VM rebooted)")
			return nil
		}
		return &WrappedError{Msg: "VM execution failed", Err: waitErr}
	}
	if !written {
		return ErrInstallDiskNotWritten{Disk: diskPath, Size: size, MinSize: minInstalledDiskSize}
	}

	logger.Info("Installation completed successfully")
	return nil
}

// vmDeadlineError reports a VM wait that ended because the context's
// deadline passed, which means QEMU was killed with the guest still
// running.
func vmDeadlineError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &WrappedError{Msg: "the VM was still running at the deadline", Err: context.DeadlineExceeded}
	}
	return nil
}

// testVMError reports a failed VM test; a VM stopped because --timeout
// expired is ErrVMTimeout, naming the timeout.
func testVMError(timeout time.Duration, msg string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrVMTimeout{Timeout: timeout}
	}
	return &WrappedError{Msg: msg, Err: err}
}

// minInstalledDiskSize is the disk size above which a finished install VM
// counts as having installed: the empty qcow2 it starts from is far smaller.
const minInstalledDiskSize = 100 * 1024 * 1024

// bootConsoleLogName is the guest console log a headless boot test writes
// in --work-dir; bootConsoleTailLines is how much of it a failure reports.
const (
	bootConsoleLogName   = "boot-serial.log"
	bootConsoleTailLines = 60
)

// bootError reports a failed boot test with the tail of the guest console
// log, so the failure shows the last bootloader, kernel or init line. A run
// stopped because --timeout expired is ErrBootTimeout.
func bootError(timeout, elapsed time.Duration, consoleLog string, err error) error {
	tail := consoleTail(consoleLog, bootConsoleTailLines)
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrBootTimeout{Timeout: timeout, Elapsed: elapsed, ConsoleLog: consoleLog, ConsoleTail: tail}
	}
	return &ErrBootFailed{Err: err, ConsoleLog: consoleLog, ConsoleTail: tail}
}

// resetConsoleLog removes the console log an earlier boot test in the same
// work dir left, so neither its --expect milestone nor its tail is taken
// for this boot's before QEMU truncates the file.
func resetConsoleLog(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &WrappedError{Msg: "failed to remove the previous console log " + path, Err: err}
	}
	return nil
}

// consoleTail returns the last lines of the console log at path, or ""
// when there is no log, it cannot be read, or the guest wrote nothing.
func consoleTail(path string, lines int) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := strings.TrimRight(strings.ReplaceAll(string(data), "\r", ""), "\n")
	if text == "" {
		return ""
	}
	all := strings.Split(text, "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// runTestQEMUBoot runs QEMU for boot test
func runTestQEMUBoot(ctx context.Context, logger *logging.Logger, config *qemu.Config, expect string) error {
	// Create QEMU VM
	vm, err := newQEMUVM(config, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create VM", Err: err}
	}

	// Start VM in boot mode
	logger.Info("Starting QEMU in boot mode...")
	if err := vmStart(vm, ctx, string(qemu.BootModeBoot)); err != nil {
		return &WrappedError{Msg: "failed to start VM", Err: err}
	}

	if err := waitForBoot(ctx, logger, seamedVM{vm}, config.SerialLogFile, expect); err != nil {
		return err
	}

	logger.Info("Boot test completed successfully")
	return nil
}

// bootVM is the part of a running qemu.VM the boot wait drives.
type bootVM interface {
	Wait() error
	Stop() error
}

// waitForBoot ends the boot test. With expect set, the test passes when
// the milestone appears in the serial console log and the VM is then
// stopped: an installed node never powers off by itself. Without it, the
// test ends when the guest powers off. A run still going at the deadline
// is reported as such, so bootError names it ErrBootTimeout.
func waitForBoot(ctx context.Context, logger *logging.Logger, vm bootVM, serialLog, expect string) error {
	if expect == "" {
		logger.Info("VM started, waiting for boot to complete (press Ctrl+C to exit)...")
		waitErr := vm.Wait()
		if err := vmDeadlineError(ctx); err != nil {
			return err
		}
		if waitErr != nil {
			return &WrappedError{Msg: "VM execution failed", Err: waitErr}
		}
		return nil
	}

	logger.Info("VM started; waiting for the milestone", "expect", expect, "serial_log", serialLog)
	waitErr := harness.WaitForSerial(ctx, serialLog, expect)
	if err := vm.Stop(); err != nil {
		logger.Warn("failed to stop the VM", "error", err)
	}
	if waitErr == nil {
		logger.Info("Milestone reached", "expect", expect)
		return nil
	}
	if err := vmDeadlineError(ctx); err != nil {
		return err
	}
	return &WrappedError{Msg: "waiting for " + strconv.Quote(expect), Err: waitErr}
}

// copyTestFile copies a file from src to dst
func copyTestFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return &WrappedError{Msg: "failed to read source file", Err: err}
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return &WrappedError{Msg: "failed to write destination file", Err: err}
	}

	return nil
}

// resolveDefaultISO generates the default ISO path using the same convention as create command
// Format: trusted-alpine-<version>-x86_64.iso
func resolveDefaultISO() string {
	// Read version from VERSION file (same as create command)
	version := "dev"
	if data, err := os.ReadFile("VERSION"); err == nil {
		version = string(data)
		// Trim whitespace/newlines
		version = filepath.Clean(version)
		if idx := len(version) - 1; idx >= 0 && (version[idx] == '\n' || version[idx] == '\r') {
			version = version[:idx]
		}
		// Trim more carefully
		for len(version) > 0 && (version[len(version)-1] == '\n' || version[len(version)-1] == '\r' || version[len(version)-1] == ' ') {
			version = version[:len(version)-1]
		}
	}

	// Generate ISO name using same convention as create command
	isoName := fmt.Sprintf("trusted-alpine-%s-x86_64.iso", version)

	// Check if the ISO exists in current directory
	if _, err := os.Stat(isoName); err == nil {
		return isoName
	}

	// Check for FIPS variant
	fipsIsoName := fmt.Sprintf("trusted-alpine-%s-x86_64-fips.iso", version)
	if _, err := os.Stat(fipsIsoName); err == nil {
		return fipsIsoName
	}

	// Return standard name even if not found (will fail with informative error later)
	return isoName
}

// Output formatting functions

func printTestHeader(title string) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("========================================")
	color.New(color.FgCyan, color.Bold).Println(title)
	color.New(color.FgCyan, color.Bold).Println("========================================")
	fmt.Println()
}

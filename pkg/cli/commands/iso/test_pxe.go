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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
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
)

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

	return cmd
}

// runTestPXE executes the PXE boot test
func runTestPXE(commonFlags *cli.CommonFlags, cmd *cobra.Command, args []string) error {
	// Check for root privileges
	if os.Geteuid() != 0 {
		return &MessageError{Msg: "pxe boot test requires root privileges for network setup: " +
			"please run with sudo: sudo platformctl iso test pxe"}
	}

	logger := createTestLogger(pxeDebug)
	ctx, cancel := createTestContext()
	defer cancel()

	printTestHeader("PXE Boot Test")

	// Determine boot entry from flags
	bootEntry, err := resolveBootEntry(logger)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve boot entry", Err: err}
	}

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

	// Setup isolated network
	printInfo("Setting up isolated network environment...")
	netConfig := testenv.DefaultNetworkConfig()
	netConfig.BridgeName = "pxe-br"
	netConfig.ServerTapName = "tap-pxe-client"
	netConfig.ClientTapName = "tap-pxe-unused"
	netConfig.GatewayIP = net.ParseIP("10.99.99.1")
	netConfig.Domain = "pxe.test"

	network := testenv.NewIsolatedNetwork(netConfig)
	if err := network.Setup(); err != nil {
		return &WrappedError{Msg: "failed to setup isolated network", Err: err}
	}
	defer func() {
		printInfo("Cleaning up isolated network...")
		if err := network.Cleanup(); err != nil {
			logger.Warnf("Failed to cleanup network: %v", err)
		}
		printSuccess("Network cleanup complete")
	}()

	printSuccess("Isolated network ready")
	printInfo(fmt.Sprintf("Bridge: %s", netConfig.BridgeName))
	printInfo(fmt.Sprintf("TAP Device: %s", netConfig.ServerTapName))
	printInfo(fmt.Sprintf("Gateway IP: %s", netConfig.GatewayIP.String()))

	// Create PXE server configuration
	pxeLocalDir := filepath.Join(pxeWorkDir, "pxe-files")
	if err := os.MkdirAll(pxeLocalDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create PXE files directory", Err: err}
	}

	pxeConfig := &ipxe.ServerConfig{
		Interface:      netConfig.BridgeName,
		HTTPPort:       8080,
		TFTPPort:       69,
		ExternalURL:    fmt.Sprintf("http://%s:8080", netConfig.GatewayIP.String()),
		LocalFilesDir:  pxeLocalDir,
		EnableDHCP:     true,
		DHCPInterface:  netConfig.BridgeName,
		DHCPRangeStart: "10.99.99.100",
		DHCPRangeEnd:   "10.99.99.200",
		DHCPSubnetMask: "255.255.255.0",
		DHCPGateway:    netConfig.GatewayIP.String(),
		DHCPDNS:        "8.8.8.8",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPServerIP:   netConfig.GatewayIP.String(),
		TFTPServerName: "",
		BootFilename:   "ipxe.efi",
		IPXEScript:     fmt.Sprintf("http://%s:8080/boot.ipxe", netConfig.GatewayIP.String()),
		BootEntries:    []ipxe.BootEntry{bootEntry},
	}

	// Create and start PXE server
	printInfo("Starting PXE server (HTTP, TFTP, DHCP)...")
	pxeServer, err := ipxe.NewServer(pxeConfig, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create PXE server", Err: err}
	}

	// Start PXE server in background
	pxeCtx, pxeCancel := context.WithCancel(ctx)
	defer pxeCancel()

	pxeErrChan := make(chan error, 1)
	go func() {
		pxeErrChan <- pxeServer.Start(pxeCtx)
	}()

	// Wait for PXE server to be ready
	printInfo("Waiting for PXE server to be ready...")
	if err := pxeServer.WaitForReady(10 * time.Second); err != nil {
		pxeCancel()
		return &WrappedError{Msg: "PXE server not ready", Err: err}
	}
	printSuccess("PXE server ready")

	// Create QEMU configuration for PXE boot
	qemuConfig := &qemu.Config{
		DiskPath:      "", // No disk for pure PXE boot test
		Memory:        pxeMemory,
		CPUs:          pxeCPUs,
		WorkDir:       pxeWorkDir,
		SecureBoot:    pxeSecureBoot,
		Debug:         pxeDebug,
		TapDevice:     netConfig.ServerTapName,
		PXEEnabled:    true,
		EnableKVM:     true,
		SerialConsole: true,
		NoGraphic:     true,
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
	if pxeSecureBoot {
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
	pxeServer.Stop()

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
		if err := cmd.Run(); err != nil {
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
	vm, err := qemu.NewVM(config, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create VM", Err: err}
	}

	// Start VM in PXE boot mode
	logger.Info("Starting QEMU in PXE boot mode...")
	if err := vm.Start(ctx, string(qemu.BootModePXE)); err != nil {
		return &WrappedError{Msg: "failed to start VM", Err: err}
	}

	// Wait for VM to complete
	logger.Info("VM started, waiting for PXE boot to complete (press Ctrl+C to exit)...")
	if err := vm.Wait(); err != nil {
		// PXE boot failures are not necessarily fatal
		// The VM may be waiting for user interaction
		logger.Warnf("VM execution completed with status: %v", err)
	}

	logger.Info("PXE boot session completed")
	return nil
}

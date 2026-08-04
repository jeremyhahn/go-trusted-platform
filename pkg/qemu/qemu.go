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

package qemu

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Default timeout for QMP connection attempts
const defaultQMPTimeout = 5 * time.Second

// Default timeout for graceful shutdown via QMP before falling back to SIGTERM
const defaultGracefulShutdownTimeout = 30 * time.Second

// VM represents a QEMU virtual machine instance
type VM struct {
	config    *Config
	logger    *logging.Logger
	cmd       *exec.Cmd
	running   atomic.Bool
	mu        sync.Mutex
	stdoutBuf bytes.Buffer
	stderrBuf bytes.Buffer
	monitor   *Monitor
}

// NewVM creates a new QEMU VM instance
func NewVM(config *Config, logger *logging.Logger) (*VM, error) {
	if config == nil {
		return nil, &MessageError{Msg: "config is required"}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid configuration", Err: err}
	}

	return &VM{
		config: config,
		logger: logger,
	}, nil
}

// CreateDisk creates a qcow2 disk image
func (vm *VM) CreateDisk() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.logger.Infof("Creating disk image: %s (size: %s)", vm.config.DiskPath, vm.config.DiskSize)

	// Check if disk already exists
	if _, err := os.Stat(vm.config.DiskPath); err == nil {
		vm.logger.Warnf("Disk already exists: %s", vm.config.DiskPath)
		return nil
	}

	// Create disk directory if needed
	diskDir := filepath.Dir(vm.config.DiskPath)
	if err := os.MkdirAll(diskDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create disk directory", Err: err}
	}

	// Create qcow2 disk
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", vm.config.DiskPath, vm.config.DiskSize)
	if output, err := cmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to create disk", Err: err, Detail: ": " + string(output)}
	}

	vm.logger.Infof("Disk created successfully: %s", vm.config.DiskPath)
	return nil
}

// initializeNVRAM initializes the NVRAM file from the template
func (vm *VM) initializeNVRAM() error {
	nvramPath := vm.config.GetNVRAMPath()
	nvramDir := filepath.Dir(nvramPath)

	// Create NVRAM directory
	if err := os.MkdirAll(nvramDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create NVRAM directory", Err: err}
	}

	// Check if NVRAM already exists
	if _, err := os.Stat(nvramPath); err == nil {
		vm.logger.Debugf("Using existing NVRAM: %s", nvramPath)
		return nil
	}

	// Copy OVMF_VARS template to NVRAM location
	vm.logger.Infof("Initializing NVRAM from template: %s -> %s", vm.config.OVMFVars, nvramPath)

	input, err := os.ReadFile(vm.config.OVMFVars)
	if err != nil {
		return &WrappedError{Msg: "failed to read OVMF_VARS template", Err: err}
	}

	if err := os.WriteFile(nvramPath, input, 0644); err != nil {
		return &WrappedError{Msg: "failed to write NVRAM file", Err: err}
	}

	vm.logger.Infof("NVRAM initialized: %s", nvramPath)
	return nil
}

// buildQEMUCommand builds the QEMU command line
func (vm *VM) buildQEMUCommand(ctx context.Context, mode BootMode) (*exec.Cmd, error) {
	// Use background context if nil
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{}

	// When using custom QEMU binary, specify data directory for ROM files
	// This allows custom builds (like CanoKey QEMU) to find vgabios, etc.
	if vm.config.QEMUBinary != "qemu-system-x86_64" {
		// Check common locations for BIOS/ROM files
		biosLocations := []string{
			"/usr/share/seabios",  // Debian/Ubuntu
			"/usr/share/qemu",     // Some distributions
			"/usr/share/qemu-kvm", // RHEL/CentOS
		}
		for _, loc := range biosLocations {
			if _, err := os.Stat(filepath.Join(loc, "vgabios-stdvga.bin")); err == nil {
				args = append(args, "-L", loc)
				break
			}
		}
	}

	// Enable KVM acceleration
	if vm.config.EnableKVM {
		args = append(args, "-enable-kvm")
	}

	// Machine type - SMM (System Management Mode) is required for Secure Boot
	// but can cause KVM emulation issues (cpu_asidx_from_attrs assertion failures).
	// Only enable SMM when Secure Boot is explicitly needed.
	if vm.config.SecureBoot {
		args = append(args, "-machine", "q35,smm=on")
	} else {
		args = append(args, "-machine", "q35")
	}

	// CPU configuration
	args = append(args, "-cpu", "host")
	args = append(args, "-smp", fmt.Sprintf("cores=%d,threads=1", vm.config.CPUs))

	// Memory
	args = append(args, "-m", strconv.Itoa(vm.config.Memory))

	// Disk configuration — MUST be before boot mode switch so AHCI controller
	// exists before any bus references (e.g., ide-cd on ahci0.1 for ISO install).
	// CRITICAL: Use AHCI controller (not VirtIO) because Ubuntu 24.04's OVMF firmware
	// does not include VirtioBlkDxe driver — it cannot read VirtIO-attached disks during
	// UEFI boot discovery. AHCI/SATA works with OVMF's built-in AhciDxe driver.
	// The install.yaml uses device=/dev/sda which corresponds to SATA/AHCI.
	// cache=writethrough ensures all writes are immediately persisted to disk.
	args = append(args,
		"-drive", fmt.Sprintf("file=%s,if=none,format=qcow2,cache=writethrough,id=hd0", vm.config.DiskPath),
		"-device", "ahci,id=ahci0",
		"-device", "ide-hd,drive=hd0,bus=ahci0.0",
	)

	// Boot configuration based on mode
	switch mode {
	case BootModeInstall:
		// Boot from CD-ROM for installation
		args = append(args, "-boot", "order="+vm.config.BootOrder)
		if vm.config.ISO != "" {
			// Attach ISO to the AHCI controller so OVMF enumerates it alongside
			// the hard disk. Using -cdrom creates a separate IDE device that may
			// not appear in OVMF's boot order. AHCI CDROM is discoverable.
			args = append(args,
				"-drive", fmt.Sprintf("file=%s,if=none,media=cdrom,readonly=on,id=cd0", vm.config.ISO),
				"-device", "ide-cd,drive=cd0,bus=ahci0.1",
			)
		}
		// Always add VGA device for UEFI compatibility (needed even in nographic mode)
		args = append(args, "-device", "VGA")

	case BootModeBoot:
		// Boot from disk with menu
		args = append(args, "-boot", "menu=on,strict=off")
		// Always add VGA device for UEFI compatibility (needed even in nographic mode)
		// OVMF expects a display device; without it, boot may fail silently
		if vm.config.NoGraphic {
			args = append(args, "-device", "VGA")
		} else {
			// Use virtio-vga for better performance with graphics
			args = append(args, "-device", "virtio-vga")
		}

	case BootModePXE:
		// Boot from network via PXE
		// -boot n: Network boot (PXE)
		// menu=on: Enable boot menu to allow user to select boot device
		// strict=off: Allow fallback to other boot devices if PXE fails
		args = append(args, "-boot", "order=n,menu=on,strict=off")
		// Always add VGA device for UEFI compatibility (needed even in nographic mode)
		if vm.config.NoGraphic {
			args = append(args, "-device", "VGA")
		} else {
			// Use virtio-vga for better performance with graphics
			args = append(args, "-device", "virtio-vga")
		}
		vm.logger.Info("PXE boot mode enabled - VM will boot from network")
	}

	// Network configuration
	if vm.config.NetworkMode != "none" {
		// OVS networking takes precedence when enabled
		// OVS provides programmable SDN features like 802.1X policy enforcement
		// Standard Linux bridges are used by default for simpler deployments
		if vm.config.OVSEnabled() && vm.config.TapDevice == "" {
			// OVS mode - TAP device must be pre-created and attached to OVS bridge
			// Use OVSNetwork.Setup() before calling Start() to create the TAP
			vm.logger.Warnf("OVS enabled but no TAP device configured - use OVSNetwork.Setup() first or set TapDevice")
			// Fall through to standard bridge/user mode
		}

		// TapDevice takes precedence - direct TAP attachment for isolated test networks
		if vm.config.TapDevice != "" {
			// Direct TAP device attachment (for isolated test networks)
			// The TAP device must already exist and be attached to a bridge
			vm.logger.Infof("Using TAP device: %s", vm.config.TapDevice)

			// vnet_hdr=on enables virtio-net header support which is required when the TAP
			// device is created with VNET_HDR flag. This enables proper checksum offloading
			// between the guest virtio-net driver and the host TAP device.
			netdevArg := fmt.Sprintf("tap,id=net0,ifname=%s,script=no,downscript=no,vnet_hdr=on", vm.config.TapDevice)

			// Add MAC address if specified
			// csum=off,guest_csum=off disables checksum offloading in virtio-net which helps
			// avoid "connection reset by peer" issues when going through NAT. The guest will
			// compute checksums in software ensuring packets are valid after NAT translation.
			deviceArg := "virtio-net-pci,netdev=net0,csum=off,guest_csum=off"
			if vm.config.MACAddress != "" {
				deviceArg = fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s,csum=off,guest_csum=off", vm.config.MACAddress)
			}

			args = append(args,
				"-netdev", netdevArg,
				"-device", deviceArg,
			)
		} else {
			switch vm.config.NetworkMode {
			case "bridge":
				// Bridge networking - connect to host bridge using QEMU bridge helper
				// This provides DHCP access to the same network as the host
				bridgeName := vm.config.BridgeName
				if bridgeName == "" {
					bridgeName = DefaultBridgeName
				}

				// Verify bridge exists before attempting to use it
				if !BridgeExists(bridgeName) {
					vm.logger.Warnf("Bridge %s not found, falling back to user mode networking", bridgeName)
					args = append(args,
						"-netdev", "user,id=net0",
						"-device", "virtio-net-pci,netdev=net0",
					)
				} else {
					vm.logger.Infof("Using bridge networking: %s", bridgeName)
					// Use QEMU's bridge helper for tap device creation
					// This requires /etc/qemu/bridge.conf to allow the bridge
					netdevArg := fmt.Sprintf("bridge,id=net0,br=%s", bridgeName)

					// Find and specify bridge helper path explicitly
					// This is required when using custom QEMU binaries that may look
					// in different locations for the bridge helper
					bridgeHelperPath := findBridgeHelper()
					if bridgeHelperPath != "" {
						netdevArg = fmt.Sprintf("%s,helper=%s", netdevArg, bridgeHelperPath)
						vm.logger.Debugf("Using bridge helper: %s", bridgeHelperPath)
					}

					// Add MAC address if specified
					deviceArg := "virtio-net-pci,netdev=net0"
					if vm.config.MACAddress != "" {
						deviceArg = fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s", vm.config.MACAddress)
					}

					args = append(args,
						"-netdev", netdevArg,
						"-device", deviceArg,
					)
				}
			case "user":
				// User mode networking (NAT) - QEMU's built-in networking
				// Build netdev string with optional port forwarding
				netdevArg := "user,id=net0"

				// Add port forwarding rules if configured
				for _, pf := range vm.config.PortForwards {
					netdevArg += "," + pf.String()
					vm.logger.Debugf("Port forward: host:%d -> guest:%d (%s)",
						pf.HostPort, pf.GuestPort, pf.Protocol)
				}

				args = append(args,
					"-netdev", netdevArg,
					"-device", "virtio-net-pci,netdev=net0",
				)
			default:
				// Use the specified network mode directly (for custom configurations)
				args = append(args,
					"-netdev", fmt.Sprintf("%s,id=net0", vm.config.NetworkMode),
					"-device", "virtio-net-pci,netdev=net0",
				)
			}
		}
	}

	// OVMF firmware configuration
	// NOTE: We must use the same OVMF firmware for both install and boot to
	// ensure NVRAM compatibility. Using different firmware versions (e.g.,
	// non-secboot for install and secboot for boot) can cause NVRAM state
	// issues that lead to QEMU crashes (assertion failures in cpu_asidx_from_attrs).
	//
	// For Secure Boot support, the firmware type is determined by config.SecureBoot:
	// - When SecureBoot=true: uses OVMF_CODE_4M.secboot.fd (can enforce Secure Boot)
	// - When SecureBoot=false: uses OVMF_CODE_4M.fd (no Secure Boot enforcement)
	//
	// The secboot firmware CAN boot unsigned code when Secure Boot is not enforced
	// (i.e., when PK is not enrolled or Secure Boot is disabled in UEFI settings).
	ovmfCode := vm.config.GetOVMFCodePath()

	nvramPath := vm.config.GetNVRAMPath()

	args = append(args,
		"-drive", fmt.Sprintf("if=pflash,unit=0,format=raw,readonly=on,file=%s", ovmfCode),
		"-drive", fmt.Sprintf("if=pflash,unit=1,format=raw,file=%s", nvramPath),
	)

	// OVMF pflash configuration - only set secure=on when Secure Boot is enabled
	// The secure property enables SMM protection for the flash device
	if vm.config.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}

	// TPM configuration
	tpmSocket := vm.config.GetTPMSocketPath()
	if _, err := os.Stat(tpmSocket); err == nil {
		args = append(args,
			"-chardev", fmt.Sprintf("socket,id=chrtpm,path=%s", tpmSocket),
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
			"-device", "tpm-tis,tpmdev=tpm0",
		)
		vm.logger.Debugf("TPM enabled: %s", tpmSocket)
	} else {
		vm.logger.Warnf("TPM socket not found: %s", tpmSocket)
	}

	// FIDO2/CanoKey configuration
	fido2Args, err := vm.buildFIDO2Args()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to build FIDO2 args", Err: err}
	}
	args = append(args, fido2Args...)

	// Random number generator
	args = append(args,
		"-object", "rng-random,filename=/dev/urandom,id=rng0",
		"-device", "virtio-rng-pci,rng=rng0",
	)

	// QMP socket configuration for runtime control
	// This enables graceful shutdown, pause/resume, and status queries
	qmpSocketPath := vm.config.GetQMPSocketPath()
	args = append(args, "-qmp", fmt.Sprintf("unix:%s,server,wait=off", qmpSocketPath))
	vm.logger.Debugf("QMP socket enabled: %s", qmpSocketPath)

	// Serial console configuration.
	// Priority: ConsoleSocketPath (multi-viewer broker) > SerialLogFile > SerialConsole > none.
	// When a console socket is configured the guest serial port is exposed on a
	// unix-domain socket (server, non-blocking) so the console broker can attach;
	// when SerialLogFile is also set the transcript is mirrored to that file via
	// the chardev logfile option, satisfying both interactive console and durable
	// log capture from a single serial port.
	if consoleSock := vm.config.GetConsoleSocketPath(); consoleSock != "" {
		chardev := fmt.Sprintf("socket,id=console0,path=%s,server=on,wait=off", consoleSock)
		if vm.config.SerialLogFile != "" {
			chardev += fmt.Sprintf(",logfile=%s", vm.config.SerialLogFile)
		}
		args = append(args, "-chardev", chardev, "-serial", "chardev:console0")
	} else if vm.config.SerialLogFile != "" {
		args = append(args, "-serial", fmt.Sprintf("file:%s", vm.config.SerialLogFile))
	} else if vm.config.SerialConsole {
		args = append(args, "-serial", "stdio")
	}

	// Graphics
	if vm.config.NoGraphic {
		args = append(args, "-nographic")
	} else if vm.config.VNCDisplay > 0 {
		args = append(args, "-vnc", fmt.Sprintf(":%d", vm.config.VNCDisplay))
	}

	// Create command with context
	qemuBinary := vm.config.QEMUBinary
	if qemuBinary == "" {
		qemuBinary = "qemu-system-x86_64"
	}
	cmd := exec.CommandContext(ctx, qemuBinary, args...)

	// Clear LIBVIRT environment variables that can interfere with QEMU device allocation
	// Copy current environment and remove LIBVIRT-related vars
	env := os.Environ()
	cleanEnv := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "LIBVIRT_") {
			cleanEnv = append(cleanEnv, e)
		}
	}
	cmd.Env = cleanEnv

	// Note: We intentionally do NOT set Setpgid here as it can interfere with
	// TTY control and stdin/stdout/stderr handling when using -serial stdio

	if vm.config.Debug {
		vm.logger.Debugf("QEMU command: %s %v", qemuBinary, args)
	}

	return cmd, nil
}

// Start starts the VM
// mode can be: "install" (boot from ISO), "boot" (boot from disk), "pxe" (boot from network)
func (vm *VM) Start(ctx context.Context, mode string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Check if VM is already running
	if vm.running.Load() {
		return ErrVMAlreadyRunning
	}

	// Parse boot mode
	bootMode := BootMode(mode)
	if !bootMode.IsValid() {
		return ErrInvalidMode
	}

	// Validate mode-specific requirements
	switch bootMode {
	case BootModeInstall:
		if vm.config.ISO == "" {
			return &SentinelCauseError{Sentinel: ErrISONotFound, Cause: &MessageError{Msg: "ISO path is required for install mode"}}
		}
		if _, err := os.Stat(vm.config.ISO); err != nil {
			return &SentinelCauseError{Sentinel: ErrISONotFound, Cause: &MessageError{Msg: fmt.Sprintf("%s", vm.config.ISO)}}
		}
	case BootModeBoot:
		if _, err := os.Stat(vm.config.DiskPath); err != nil {
			return &SentinelCauseError{Sentinel: ErrDiskNotFound, Cause: &MessageError{Msg: fmt.Sprintf("%s", vm.config.DiskPath)}}
		}
	case BootModePXE:
		// PXE boot requires network configuration
		if vm.config.NetworkMode == "none" {
			return ErrPXENetworkRequired
		}
		// Log PXE server info if configured
		if vm.config.PXEServerIP != "" {
			vm.logger.Infof("PXE boot: server IP %s", vm.config.PXEServerIP)
		}
	}

	// Clean up any stale QMP socket from previous run
	qmpSocketPath := vm.config.GetQMPSocketPath()
	if err := os.Remove(qmpSocketPath); err != nil && !os.IsNotExist(err) {
		vm.logger.Warnf("Failed to remove stale QMP socket: %v", err)
	}

	// Initialize NVRAM
	if err := vm.initializeNVRAM(); err != nil {
		return &WrappedError{Msg: "failed to initialize NVRAM", Err: err}
	}

	// Build QEMU command
	cmd, err := vm.buildQEMUCommand(ctx, bootMode)
	if err != nil {
		return &WrappedError{Msg: "failed to build QEMU command", Err: err}
	}

	vm.cmd = cmd
	vm.logger.Infof("Starting VM in %s mode", mode)

	// Clear previous output buffers
	vm.stdoutBuf.Reset()
	vm.stderrBuf.Reset()

	// Configure stdout/stderr based on serial console setting
	// When using SerialLogFile, QEMU writes serial output to file, so we capture stdout/stderr for errors
	if vm.config.SerialLogFile != "" {
		// Serial goes to file, capture stdout/stderr for QEMU errors
		vm.cmd.Stdout = &vm.stdoutBuf
		vm.cmd.Stderr = &vm.stderrBuf
		vm.logger.Infof("Serial output will be written to: %s", vm.config.SerialLogFile)
	} else if vm.config.SerialConsole {
		// Pass stdin/stdout/stderr directly to parent process for interactive console
		vm.cmd.Stdin = os.Stdin
		vm.cmd.Stdout = os.Stdout
		vm.cmd.Stderr = os.Stderr
	} else {
		// Capture stdout and stderr for error reporting
		vm.cmd.Stdout = &vm.stdoutBuf
		vm.cmd.Stderr = &vm.stderrBuf
	}

	// Start QEMU process
	if err := vm.cmd.Start(); err != nil {
		// Log captured stderr if available
		if vm.stderrBuf.Len() > 0 {
			vm.logger.Errorf("QEMU stderr: %s", vm.stderrBuf.String())
		}
		if vm.stdoutBuf.Len() > 0 {
			vm.logger.Debugf("QEMU stdout: %s", vm.stdoutBuf.String())
		}
		return &SentinelCauseError{Sentinel: ErrQEMUFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}

	vm.running.Store(true)
	vm.logger.Infof("VM started (PID: %d)", vm.cmd.Process.Pid)

	// Bring up TAP device after QEMU opens it
	// QEMU with script=no,downscript=no doesn't run helper scripts to bring the TAP up
	// so we must do it ourselves after QEMU has opened the device
	if vm.config.TapDevice != "" {
		// Small delay to ensure QEMU has opened the TAP device
		time.Sleep(100 * time.Millisecond)
		if err := vm.bringTapUp(); err != nil {
			vm.logger.Warnf("Failed to bring up TAP device %s: %v", vm.config.TapDevice, err)
		} else {
			vm.logger.Infof("TAP device %s is UP", vm.config.TapDevice)
		}
	}

	return nil
}

// Wait waits for the VM to exit
func (vm *VM) Wait() error {
	vm.mu.Lock()
	cmd := vm.cmd
	vm.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return ErrVMNotRunning
	}

	vm.logger.Debug("Waiting for VM to exit...")

	err := cmd.Wait()
	vm.running.Store(false)

	// Close monitor connection if active
	vm.mu.Lock()
	if vm.monitor != nil {
		_ = vm.monitor.Close()
		vm.monitor = nil
	}
	vm.mu.Unlock()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			vm.logger.Debugf("VM exited with code: %d", exitErr.ExitCode())
		}
		// Log captured stderr and stdout for debugging
		if vm.stderrBuf.Len() > 0 {
			vm.logger.Errorf("QEMU stderr: %s", vm.stderrBuf.String())
		}
		if vm.stdoutBuf.Len() > 0 {
			vm.logger.Debugf("QEMU stdout: %s", vm.stdoutBuf.String())
		}
		return &SentinelCauseError{Sentinel: ErrQEMUFailed, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}

	vm.logger.Info("VM exited successfully")
	return nil
}

// bringTapUp brings up the TAP device using the ip command
// This is needed because QEMU with script=no doesn't bring up the TAP device
func (vm *VM) bringTapUp() error {
	cmd := exec.Command("ip", "link", "set", vm.config.TapDevice, "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &CommandOutputError{Msg: "failed to bring up TAP device", Err: err, Detail: ": " + string(output)}
	}
	return nil
}

// Stop stops the VM gracefully.
// It first attempts a graceful shutdown via QMP SystemPowerdown (ACPI power button),
// waiting up to the configured timeout. If QMP is not available or the graceful
// shutdown times out, it falls back to SIGTERM.
func (vm *VM) Stop() error {
	return vm.StopWithTimeout(defaultGracefulShutdownTimeout)
}

// StopWithTimeout stops the VM with a custom timeout for graceful shutdown.
// The timeout specifies how long to wait for the guest to respond to the
// ACPI power button event before falling back to SIGTERM.
func (vm *VM) StopWithTimeout(timeout time.Duration) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.cmd == nil || vm.cmd.Process == nil {
		vm.running.Store(false)
		return ErrVMNotRunning
	}

	pid := vm.cmd.Process.Pid
	vm.logger.Infof("Stopping VM (PID: %d)", pid)

	// Try graceful shutdown via QMP first
	if vm.monitor != nil && vm.monitor.IsConnected() {
		vm.logger.Info("Attempting graceful shutdown via QMP SystemPowerdown")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Send ACPI power button event
		if err := vm.monitor.SystemPowerdown(ctx); err != nil {
			vm.logger.Warnf("QMP SystemPowerdown failed: %v, falling back to SIGTERM", err)
		} else {
			// Wait for VM to shut down gracefully
			shutdownComplete := make(chan struct{})
			go func() {
				// Poll for process termination
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						// Check if process is still running
						if err := vm.cmd.Process.Signal(syscall.Signal(0)); err != nil {
							close(shutdownComplete)
							return
						}
					case <-ctx.Done():
						return
					}
				}
			}()

			select {
			case <-shutdownComplete:
				vm.logger.Info("VM shut down gracefully via ACPI")
				vm.running.Store(false)
				// Close monitor connection
				_ = vm.monitor.Close()
				vm.monitor = nil
				return nil
			case <-ctx.Done():
				vm.logger.Warnf("Graceful shutdown timed out after %v, falling back to SIGTERM", timeout)
			}
		}

		// Close monitor before sending signals
		_ = vm.monitor.Close()
		vm.monitor = nil
	}

	// Fall back to SIGTERM
	vm.logger.Info("Sending SIGTERM to VM process")
	if err := vm.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// If SIGTERM fails, force kill
		vm.logger.Warnf("SIGTERM failed, sending SIGKILL: %v", err)
		if killErr := vm.cmd.Process.Kill(); killErr != nil {
			return &WrappedError{Msg: "failed to kill VM process", Err: killErr}
		}
	}

	vm.running.Store(false)
	vm.logger.Info("VM stopped")

	return nil
}

// ForceStop immediately terminates the VM with SIGKILL.
// This should only be used when graceful shutdown is not possible.
func (vm *VM) ForceStop() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.cmd == nil || vm.cmd.Process == nil {
		vm.running.Store(false)
		return ErrVMNotRunning
	}

	vm.logger.Warnf("Force stopping VM (PID: %d) with SIGKILL", vm.cmd.Process.Pid)

	// Close monitor connection if active
	if vm.monitor != nil {
		_ = vm.monitor.Close()
		vm.monitor = nil
	}

	if err := vm.cmd.Process.Kill(); err != nil {
		return &WrappedError{Msg: "failed to kill VM process", Err: err}
	}

	vm.running.Store(false)
	vm.logger.Info("VM force stopped")

	return nil
}

// ConnectMonitor establishes a connection to the QMP socket.
// This should be called after the VM has started and the QMP socket is available.
// The connection enables runtime control via QMP commands.
func (vm *VM) ConnectMonitor(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.monitor != nil && vm.monitor.IsConnected() {
		return ErrMonitorAlreadyConnected{}
	}

	qmpSocketPath := vm.config.GetQMPSocketPath()
	vm.logger.Debugf("Connecting to QMP monitor at %s", qmpSocketPath)

	// Wait for QMP socket to be available with retries
	timeout := defaultQMPTimeout
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
	}

	socketReady := false
	startTime := time.Now()
	for time.Since(startTime) < timeout {
		if _, err := os.Stat(qmpSocketPath); err == nil {
			socketReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !socketReady {
		return ErrMonitorSocketNotFound{SocketPath: qmpSocketPath}
	}

	vm.logger.Debugf("QMP socket is available")

	// Create and connect the monitor
	monitor := NewMonitor(qmpSocketPath, defaultQMPTimeout, vm.logger)
	if err := monitor.Connect(ctx); err != nil {
		return err
	}

	vm.monitor = monitor
	vm.logger.Infof("Connected to QMP monitor (QEMU %s)", monitor.monitor.Version.String())

	return nil
}

// DisconnectMonitor closes the QMP monitor connection.
func (vm *VM) DisconnectMonitor() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.monitor == nil {
		return nil
	}

	err := vm.monitor.Close()
	vm.monitor = nil
	return err
}

// Monitor returns the QMP monitor instance for direct access to QMP commands.
// Returns nil if the monitor is not connected.
func (vm *VM) Monitor() *Monitor {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.monitor
}

// Pause pauses VM execution.
// Requires an active QMP monitor connection (call ConnectMonitor first).
func (vm *VM) Pause(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.monitor == nil || !vm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	return vm.monitor.Pause(ctx)
}

// Resume resumes VM execution after being paused.
// Requires an active QMP monitor connection (call ConnectMonitor first).
func (vm *VM) Resume(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.monitor == nil || !vm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	return vm.monitor.Resume(ctx)
}

// VMStatus queries the current status of the VM via QMP.
// Requires an active QMP monitor connection (call ConnectMonitor first).
func (vm *VM) VMStatus(ctx context.Context) (VMStatus, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return VMStatusUnknown, ErrVMNotRunning
	}

	if vm.monitor == nil || !vm.monitor.IsConnected() {
		return VMStatusUnknown, ErrMonitorNotConnected{}
	}

	return vm.monitor.Status(ctx)
}

// Reset performs a system reset of the VM via QMP.
// Requires an active QMP monitor connection (call ConnectMonitor first).
func (vm *VM) Reset(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running.Load() {
		return ErrVMNotRunning
	}

	if vm.monitor == nil || !vm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	return vm.monitor.SystemReset(ctx)
}

// IsRunning returns true if the VM is currently running
func (vm *VM) IsRunning() bool {
	return vm.running.Load()
}

// GetPID returns the process ID of the running VM, or 0 if not running
func (vm *VM) GetPID() int {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.cmd != nil && vm.cmd.Process != nil {
		return vm.cmd.Process.Pid
	}
	return 0
}

// GetConfig returns the VM configuration
func (vm *VM) GetConfig() *Config {
	return vm.config
}

// buildFIDO2Args builds QEMU arguments for FIDO2/CanoKey devices
func (vm *VM) buildFIDO2Args() ([]string, error) {
	if vm.config.FIDO2 == nil || !vm.config.FIDO2.Enable {
		return nil, nil
	}

	var args []string
	fido2 := vm.config.FIDO2

	switch fido2.Mode {
	case "canokey", "":
		// CanoKey mode - Full FIDO2 with HMAC-secret support (best for LUKS)
		// Requires libcanokey-qemu to be installed and QEMU built with --enable-canokey

		// Determine CanoKey state file path
		canoKeyFile := fido2.CanoKeyFile
		if canoKeyFile == "" {
			canoKeyDir := filepath.Join(vm.config.WorkDir, "canokey")
			if err := os.MkdirAll(canoKeyDir, 0755); err != nil {
				return nil, &WrappedError{Msg: "failed to create CanoKey directory", Err: err}
			}
			canoKeyFile = filepath.Join(canoKeyDir, "canokey.state")
		}

		// Build CanoKey device args
		deviceArg := fmt.Sprintf("canokey,file=%s", canoKeyFile)

		// Add optional pcap capture for debugging
		if fido2.CanoKeyPcap != "" {
			deviceArg = fmt.Sprintf("%s,pcap=%s", deviceArg, fido2.CanoKeyPcap)
		}

		// Enable USB controller and add CanoKey device
		args = append(args, "-usb", "-device", deviceArg)
		vm.logger.Infof("FIDO2 CanoKey enabled: %s", canoKeyFile)

	case "u2f-emulated":
		// U2F emulated mode - Software U2F emulation (U2F only, not full FIDO2)
		// Requires libu2f-emu library

		deviceArg := "u2f-emulated"
		if fido2.U2FDir != "" {
			// Use persistent U2F credentials from directory
			deviceArg = fmt.Sprintf("u2f-emulated,dir=%s", fido2.U2FDir)
		}
		// Note: If U2FDir is empty, uses ephemeral mode (auto-generated credentials)

		args = append(args, "-usb", "-device", deviceArg)
		vm.logger.Info("FIDO2 U2F emulated mode enabled")

	case "u2f-passthru":
		// U2F passthrough mode - Pass physical U2F/FIDO2 key to VM
		// Requires the physical key to be connected to the host

		deviceArg := "u2f-passthru"
		if fido2.PassthruDevice != "" {
			// Use specific hidraw device
			deviceArg = fmt.Sprintf("u2f-passthru,hidraw=%s", fido2.PassthruDevice)
		}
		// Note: If PassthruDevice is empty, QEMU auto-detects first U2F device

		args = append(args, "-usb", "-device", deviceArg)
		if fido2.PassthruDevice != "" {
			vm.logger.Infof("FIDO2 U2F passthrough enabled: %s", fido2.PassthruDevice)
		} else {
			vm.logger.Info("FIDO2 U2F passthrough enabled (auto-detect)")
		}

	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unknown FIDO2 mode: %s (valid: canokey, u2f-emulated, u2f-passthru)", fido2.Mode)}
	}

	return args, nil
}

// GetCanoKeyFilePath returns the CanoKey state file path
func (vm *VM) GetCanoKeyFilePath() string {
	if vm.config.FIDO2 == nil {
		return ""
	}
	if vm.config.FIDO2.CanoKeyFile != "" {
		return vm.config.FIDO2.CanoKeyFile
	}
	return filepath.Join(vm.config.WorkDir, "canokey", "canokey.state")
}

// StopExistingByTap stops any existing QEMU processes that use the specified TAP device.
// This is useful for cleaning up stale VMs before starting a new one.
// Returns nil if no processes were found or all were successfully terminated.
func StopExistingByTap(tapDevice string) error {
	if tapDevice == "" {
		return nil
	}

	// Find QEMU processes using this TAP device by searching for the ifname argument
	// The QEMU command line contains: -netdev tap,...,ifname=<tapDevice>,...
	cmd := exec.Command("pgrep", "-f", fmt.Sprintf("qemu.*ifname=%s", tapDevice))
	output, err := cmd.Output()
	if err != nil {
		// pgrep returns exit code 1 if no processes found - this is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return &WrappedError{Msg: "failed to find QEMU processes", Err: err}
	}

	// Parse PIDs and kill each process
	pids := strings.Fields(strings.TrimSpace(string(output)))
	for _, pidStr := range pids {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Send SIGTERM for graceful shutdown
		process, err := os.FindProcess(pid)
		if err != nil {
			continue
		}

		if err := process.Signal(syscall.SIGTERM); err != nil {
			// Process may have already exited
			continue
		}
	}

	// Wait a moment for processes to terminate
	time.Sleep(500 * time.Millisecond)

	// Check if any processes are still running and force kill them
	cmd = exec.Command("pgrep", "-f", fmt.Sprintf("qemu.*ifname=%s", tapDevice))
	if output, err = cmd.Output(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
		// Some processes are still running, send SIGKILL
		pids = strings.Fields(strings.TrimSpace(string(output)))
		for _, pidStr := range pids {
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}
			process, err := os.FindProcess(pid)
			if err != nil {
				continue
			}
			_ = process.Kill()
		}
		// Wait for processes to be reaped
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

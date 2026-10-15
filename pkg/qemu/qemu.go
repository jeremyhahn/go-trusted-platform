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
	"errors"
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

// How long Start waits for QEMU to create the TAP device before bringing it up
const tapOpenTimeout = 2 * time.Second

// How long StopExistingByTap waits for signalled processes to exit
const processExitTimeout = 500 * time.Millisecond

// How often the wait helpers re-check their condition
const pollInterval = 100 * time.Millisecond

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

	// runtimeDir is the socket directory this VM created and must remove.
	runtimeDir string
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

	p, err := vm.config.profile()
	if err != nil {
		return err
	}
	format := vm.config.diskFormat(p)
	cmd := exec.Command("qemu-img", "create", "-f", format, vm.config.DiskPath, vm.config.DiskSize)
	if output, err := cmd.CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to create disk", Err: err, Detail: ": " + string(output)}
	}

	vm.logger.Infof("Disk created successfully: %s", vm.config.DiskPath)
	return nil
}

// initializeNVRAM initializes the NVRAM file from the template. Firmware
// supplied as -bios (aarch64 U-Boot) keeps its variables on the ESP and
// has no NVRAM file, so there is nothing to initialise.
func (vm *VM) initializeNVRAM() error {
	p, err := vm.config.profile()
	if err != nil {
		return err
	}
	if !p.nvram(vm.config) {
		return nil
	}
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

// buildQEMUCommand builds the QEMU command line. The architecture profile
// (arch.go) supplies the machine, CPU, disk controller, boot/display,
// firmware and TPM front-end; everything else is common to every guest.
func (vm *VM) buildQEMUCommand(ctx context.Context, mode BootMode) (*exec.Cmd, error) {
	// Use background context if nil
	if ctx == nil {
		ctx = context.Background()
	}
	c := vm.config
	p, err := c.profile()
	if err != nil {
		return nil, err
	}

	// When using a custom QEMU binary, point it at the ROM files (vgabios
	// and friends) so a custom build (like the CanoKey QEMU) finds them.
	args := append([]string{}, romDirArgs(c, p)...)

	kvm := c.kvm(p)
	if kvm {
		args = append(args, "-enable-kvm")
	}

	args = append(args, "-machine", p.machine(c, kvm))
	args = append(args, "-cpu", p.cpu(c, kvm))
	args = append(args, "-smp", fmt.Sprintf("cores=%d,threads=1", c.CPUs))
	args = append(args, "-m", strconv.Itoa(c.Memory))

	// Disk configuration — MUST be before the boot arguments so the disk
	// controller exists before any bus references (the install CD-ROM on
	// ahci0.1). The cache mode defaults to writethrough (all writes
	// immediately persisted — bare-metal faithful); nested-virt hosts
	// override via Config.DiskCache because synchronous writes there can
	// exceed the guest's SCSI timeout and corrupt the install (#49).
	diskCache := c.DiskCache
	if diskCache == "" {
		diskCache = "writethrough"
	}
	args = append(args, p.disk(c, c.diskFormat(p), diskCache)...)

	bootArgs, err := p.boot(c, mode)
	if err != nil {
		return nil, err
	}
	args = append(args, bootArgs...)
	if mode == BootModePXE {
		vm.logger.Info("PXE boot mode enabled - VM will boot from network")
	}

	args = append(args, vm.networkArgs()...)

	firmwareArgs, err := p.firmware(c)
	if err != nil {
		return nil, err
	}
	args = append(args, firmwareArgs...)

	// TPM configuration
	tpmSocket := c.GetTPMSocketPath()
	if _, err := os.Stat(tpmSocket); err == nil {
		args = append(args,
			"-chardev", fmt.Sprintf("socket,id=chrtpm,path=%s", tpmSocket),
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
			"-device", c.tpmDevice(p)+",tpmdev=tpm0",
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
	qmpSocketPath := c.GetQMPSocketPath()
	args = append(args, "-qmp", fmt.Sprintf("unix:%s,server,wait=off", qmpSocketPath))
	vm.logger.Debugf("QMP socket enabled: %s", qmpSocketPath)

	// Serial console configuration.
	// Priority: ConsoleSocketPath (multi-viewer broker) > SerialLogFile > SerialConsole > none.
	// When a console socket is configured the guest serial port is exposed on a
	// unix-domain socket (server, non-blocking) so the console broker can attach;
	// when SerialLogFile is also set the transcript is mirrored to that file via
	// the chardev logfile option, satisfying both interactive console and durable
	// log capture from a single serial port.
	if consoleSock := c.GetConsoleSocketPath(); consoleSock != "" {
		chardev := fmt.Sprintf("socket,id=console0,path=%s,server=on,wait=off", consoleSock)
		if c.SerialLogFile != "" {
			chardev += fmt.Sprintf(",logfile=%s", c.SerialLogFile)
		}
		args = append(args, "-chardev", chardev, "-serial", "chardev:console0")
	} else if c.SerialLogFile != "" {
		args = append(args, "-serial", fmt.Sprintf("file:%s", c.SerialLogFile))
	} else if c.SerialConsole {
		args = append(args, "-serial", "stdio")
	}

	// Graphics
	if c.NoGraphic {
		args = append(args, "-nographic")
	} else if c.VNCDisplay > 0 {
		args = append(args, "-vnc", fmt.Sprintf(":%d", c.VNCDisplay))
	}

	qemuBinary := c.qemuBinary(p)
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

	if c.Debug {
		vm.logger.Debugf("QEMU command: %s %v", qemuBinary, args)
	}

	return cmd, nil
}

// networkArgs returns the -netdev/-device pair for the configured network
// mode. OVS networking takes precedence when enabled (programmable SDN
// features like 802.1X policy enforcement); a pre-created TAP device
// comes next (isolated test networks); then the plain modes.
func (vm *VM) networkArgs() []string {
	c := vm.config
	if c.NetworkMode == "none" {
		return nil
	}
	if c.OVSEnabled() && c.TapDevice == "" {
		// OVS mode - TAP device must be pre-created and attached to OVS bridge
		// Use OVSNetwork.Setup() before calling Start() to create the TAP
		vm.logger.Warnf("OVS enabled but no TAP device configured - use OVSNetwork.Setup() first or set TapDevice")
		// Fall through to standard bridge/user mode
	}

	if c.TapDevice != "" {
		// Direct TAP device attachment (for isolated test networks)
		// The TAP device must already exist and be attached to a bridge
		vm.logger.Infof("Using TAP device: %s", c.TapDevice)

		// vnet_hdr=on enables virtio-net header support which is required when the TAP
		// device is created with VNET_HDR flag. This enables proper checksum offloading
		// between the guest virtio-net driver and the host TAP device.
		netdevArg := fmt.Sprintf("tap,id=net0,ifname=%s,script=no,downscript=no,vnet_hdr=on", c.TapDevice)

		// csum=off,guest_csum=off disables checksum offloading in virtio-net which helps
		// avoid "connection reset by peer" issues when going through NAT. The guest will
		// compute checksums in software ensuring packets are valid after NAT translation.
		deviceArg := "virtio-net-pci,netdev=net0,csum=off,guest_csum=off"
		if c.MACAddress != "" {
			deviceArg = fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s,csum=off,guest_csum=off", c.MACAddress)
		}
		return []string{"-netdev", netdevArg, "-device", deviceArg}
	}

	switch c.NetworkMode {
	case "bridge":
		// Bridge networking - connect to host bridge using QEMU bridge helper
		// This provides DHCP access to the same network as the host
		bridgeName := c.BridgeName
		if bridgeName == "" {
			bridgeName = DefaultBridgeName
		}

		// Verify bridge exists before attempting to use it
		if !BridgeExists(bridgeName) {
			vm.logger.Warnf("Bridge %s not found, falling back to user mode networking", bridgeName)
			return []string{"-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0"}
		}
		vm.logger.Infof("Using bridge networking: %s", bridgeName)
		// Use QEMU's bridge helper for tap device creation
		// This requires /etc/qemu/bridge.conf to allow the bridge
		netdevArg := fmt.Sprintf("bridge,id=net0,br=%s", bridgeName)

		// Find and specify bridge helper path explicitly
		// This is required when using custom QEMU binaries that may look
		// in different locations for the bridge helper
		if bridgeHelperPath := findBridgeHelper(); bridgeHelperPath != "" {
			netdevArg = fmt.Sprintf("%s,helper=%s", netdevArg, bridgeHelperPath)
			vm.logger.Debugf("Using bridge helper: %s", bridgeHelperPath)
		}

		deviceArg := "virtio-net-pci,netdev=net0"
		if c.MACAddress != "" {
			deviceArg = fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s", c.MACAddress)
		}
		return []string{"-netdev", netdevArg, "-device", deviceArg}
	case "user":
		// User mode networking (NAT) - QEMU's built-in networking
		// Build netdev string with optional port forwarding
		netdevArg := "user,id=net0"
		for _, pf := range c.PortForwards {
			netdevArg += "," + pf.String()
			vm.logger.Debugf("Port forward: host:%d -> guest:%d (%s)",
				pf.HostPort, pf.GuestPort, pf.Protocol)
		}
		return []string{"-netdev", netdevArg, "-device", "virtio-net-pci,netdev=net0"}
	default:
		// Use the specified network mode directly (for custom configurations)
		return []string{"-netdev", fmt.Sprintf("%s,id=net0", c.NetworkMode), "-device", "virtio-net-pci,netdev=net0"}
	}
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
			return &SentinelCauseError{Sentinel: ErrISONotFound, Cause: &MessageError{Msg: vm.config.ISO}}
		}
	case BootModeBoot:
		if _, err := os.Stat(vm.config.DiskPath); err != nil {
			return &SentinelCauseError{Sentinel: ErrDiskNotFound, Cause: &MessageError{Msg: vm.config.DiskPath}}
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

	// Sockets live in a short per-run directory; it is released on every
	// path that does not leave QEMU running.
	if err := vm.createRuntimeDir(); err != nil {
		return err
	}
	started := false
	defer func() {
		if !started {
			vm.releaseRuntimeDir()
		}
	}()
	if err := vm.config.validateSocketPaths(); err != nil {
		return err
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
	switch {
	case vm.config.SerialLogFile != "":
		// Serial goes to file, capture stdout/stderr for QEMU errors
		vm.cmd.Stdout = &vm.stdoutBuf
		vm.cmd.Stderr = &vm.stderrBuf
		vm.logger.Infof("Serial output will be written to: %s", vm.config.SerialLogFile)
	case vm.config.SerialConsole:
		// Pass stdin/stdout/stderr directly to parent process for interactive console
		vm.cmd.Stdin = os.Stdin
		vm.cmd.Stdout = os.Stdout
		vm.cmd.Stderr = os.Stderr
	default:
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

	started = true
	vm.running.Store(true)
	vm.logger.Infof("VM started (PID: %d)", vm.cmd.Process.Pid)

	// Bring up TAP device after QEMU opens it
	// QEMU with script=no,downscript=no doesn't run helper scripts to bring the TAP up
	// so we must do it ourselves after QEMU has opened the device
	if vm.config.TapDevice != "" {
		// QEMU creates the TAP device when it opens it
		tapPath := filepath.Join(sysClassNet, vm.config.TapDevice)
		if !waitForPath(ctx, tapPath, tapOpenTimeout) {
			vm.logger.Warnf("TAP device %s did not appear within %s", vm.config.TapDevice, tapOpenTimeout)
		}
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
	vm.releaseRuntimeDir()
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
				vm.releaseRuntimeDir()
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
	vm.releaseRuntimeDir()
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
	vm.releaseRuntimeDir()
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

	if !waitForPath(ctx, qmpSocketPath, timeout) {
		if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
			return &WrappedError{Msg: "canceled waiting for QMP socket " + qmpSocketPath, Err: ctx.Err()}
		}
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

	pids, err := findQEMUByTap(tapDevice)
	if err != nil {
		return err
	}

	// Send SIGTERM for graceful shutdown and give the processes a moment to exit
	waitForProcessesExit(signalProcesses(pids, syscall.SIGTERM), processExitTimeout)

	// Force kill any process still running and wait for it to be reaped
	pids, err = findQEMUByTap(tapDevice)
	if err != nil {
		return err
	}
	waitForProcessesExit(signalProcesses(pids, syscall.SIGKILL), processExitTimeout)

	return nil
}

// findQEMUByTap returns the PIDs of the QEMU processes using tapDevice. The
// QEMU command line contains: -netdev tap,...,ifname=<tapDevice>,...
func findQEMUByTap(tapDevice string) ([]int, error) {
	cmd := exec.Command("pgrep", "-f", fmt.Sprintf("qemu.*ifname=%s", tapDevice))
	output, err := cmd.Output()
	if err != nil {
		// pgrep returns exit code 1 if no processes found - this is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, &WrappedError{Msg: "failed to find QEMU processes", Err: err}
	}

	var pids []int
	for _, pidStr := range strings.Fields(string(output)) {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// signalProcesses sends sig to each PID and returns the PIDs it reached. A
// process that has already exited is skipped.
func signalProcesses(pids []int, sig syscall.Signal) []int {
	var signalled []int
	for _, pid := range pids {
		if err := syscall.Kill(pid, sig); err != nil {
			continue
		}
		signalled = append(signalled, pid)
	}
	return signalled
}

// waitForProcessesExit waits up to timeout for every PID to exit and reports
// whether they all did.
func waitForProcessesExit(pids []int, timeout time.Duration) bool {
	return waitFor(context.Background(), timeout, func() bool {
		for _, pid := range pids {
			if !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
				return false
			}
		}
		return true
	})
}

// waitForPath waits up to timeout for path to exist and reports whether it
// does. A nil ctx never cancels the wait.
func waitForPath(ctx context.Context, path string, timeout time.Duration) bool {
	return waitFor(ctx, timeout, func() bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

// waitFor checks done every pollInterval until it returns true, the timeout
// elapses, or ctx is cancelled, and reports whether done returned true. A nil
// ctx never cancels the wait.
func waitFor(ctx context.Context, timeout time.Duration, done func() bool) bool {
	if ctx == nil {
		ctx = context.Background()
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if done() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}

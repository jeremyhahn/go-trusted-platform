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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// isTerminalFD checks if the given file descriptor is a terminal
func isTerminalFD(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

// hasInteractiveTTYCS returns true if stdin and stdout are both terminals
func hasInteractiveTTYCS() bool {
	return isTerminalFD(os.Stdin.Fd()) && isTerminalFD(os.Stdout.Fd())
}

// clientServerFlags holds all flags for the client-server test command
type clientServerFlags struct {
	iso               string
	serverDisk        string
	clientDisk        string
	serverWorkDir     string
	clientWorkDir     string
	diskSize          string
	diskCache         string
	memory            int
	cpus              int
	secureBoot        bool
	debug             bool
	skipInstall       bool
	serverOnly        bool
	clientOnly        bool
	fido2Enable       bool
	fido2Mode         string
	serverConfigPath  string
	clientConfigPath  string
	userNetwork       bool
	serverHostPort    int
	dnsHostPort       int
	useOVS            bool
	platformdBinary   string
	forceConsole      bool
	webUIPath         string
	serverProfile     string
	clientProfile     string
	dynamicNetwork    bool
	enableDHCP        bool
	serverTimeout     int    // Timeout in seconds for waiting for server to be ready (default: 600)
	bootstrapStrategy string // dane, noise, spki, embedded, auto
	bootstrapNoiseKey string // hex-encoded Noise static key
	bootstrapSPKIPin  string // hex-encoded SPKI SHA-256 pin
}

// ServerVMState holds the state of a running server VM for cleanup
type ServerVMState struct {
	VM  *qemu.VM
	TPM harness.TPM
}

// serverState holds the running server VM state for cleanup
var csServerState *ServerVMState

// csServerCABundlePath holds the path to the exported CA bundle from the server
var csServerCABundlePath string

// createClientServerCommand creates the client-server test subcommand
// This is called from test.go to add the command to the test command hierarchy
func createClientServerCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &clientServerFlags{}

	cmd := &cobra.Command{
		Use:   "client-server",
		Short: "Test client-server deployment with TPM enrollment",
		Long: `Test client-server deployment in an isolated network.

Creates two VMs in an isolated 10.99.99.0/28 network:
  - Server (10.99.99.2): DNS, CA, ACME server with enroll-01 challenge
  - Client (10.99.99.3): Enrolls with server via ACME to get IDevID certificate

The test validates end-to-end TPM enrollment workflow using the custom
enroll-01 ACME challenge. The client uses the server for DNS resolution.

Network Modes:
  - Bridge networking (default): Requires root for TAP/bridge setup.
    Both VMs get static IPs and can communicate directly.
  - OVS networking (--use-ovs): Uses Open vSwitch for SDN features.
    Provides programmable flows for 802.1X policy enforcement.
    Requires OVS to be installed and running.
  - User networking (--user-network): No root required.
    Uses QEMU's user-mode NAT with port forwarding.
    Only supports --server-only mode (single VM at a time).

Profile-Driven Configuration:
  - --server-profile: Use network config from a server device profile
  - --client-profile: Use network config from a client device profile
  - --dynamic-network: Enable profile-driven network phases
  - --enable-dhcp: Enable DHCP server for provisioning network

Requirements:
  - QEMU with KVM support
  - OVMF firmware
  - Root privileges (for bridge networking, not needed with --user-network)

Examples:
  # Run full client-server test (requires root)
  sudo platformctl iso test client-server --iso trusted-alpine-1.0.0-x86_64.iso

  # Skip installation (use existing disks)
  sudo platformctl iso test client-server --skip-install

  # Run server only (requires root)
  sudo platformctl iso test client-server --server-only

  # Run server only with user networking (NO ROOT required)
  platformctl iso test client-server --server-only --user-network

  # Run with OVS networking for SDN features
  sudo platformctl iso test client-server --use-ovs

  # Run client only (assumes server is running)
  sudo platformctl iso test client-server --client-only

  # Run with device profiles for dynamic network config
  sudo platformctl iso test client-server --use-ovs --dynamic-network \
    --server-profile profiles/server.yaml \
    --client-profile profiles/client.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientServerTest(getFlags(), flags)
		},
	}

	// Common flags
	cmd.Flags().StringVar(&flags.iso, "iso", "",
		"Path to ISO file (default: auto-detect from VERSION)")
	cmd.Flags().StringVar(&flags.serverDisk, "server-disk", "server-installed.qcow2",
		"Path to server qcow2 disk image")
	cmd.Flags().StringVar(&flags.clientDisk, "client-disk", "client-installed.qcow2",
		"Path to client qcow2 disk image")
	cmd.Flags().StringVar(&flags.serverWorkDir, "server-work-dir", "work-server",
		"Working directory for server VM artifacts")
	cmd.Flags().StringVar(&flags.clientWorkDir, "client-work-dir", "work-client",
		"Working directory for client VM artifacts")
	cmd.Flags().StringVar(&flags.diskSize, "disk-size", "10G",
		"Disk size for both VMs")
	cmd.Flags().StringVar(&flags.diskCache, "disk-cache", "",
		"QEMU disk cache mode for both VMs: writethrough (default), writeback, none, unsafe, directsync")
	cmd.Flags().IntVar(&flags.memory, "memory", 8192,
		"RAM in MB for each VM")

	// Use min(runtime.NumCPU(), 8) to avoid overwhelming VMs with too many cores
	// Most VMs don't need more than 8 cores and some guests may crash with very high core counts
	defaultCPUs := runtime.NumCPU()
	if defaultCPUs > 8 {
		defaultCPUs = 8
	}
	cmd.Flags().IntVar(&flags.cpus, "cpus", defaultCPUs,
		"Number of CPU cores for each VM (default: min(host cores, 8))")
	cmd.Flags().BoolVar(&flags.secureBoot, "secure-boot", false,
		"Enable UEFI Secure Boot (disabled by default due to KVM SMM emulation bugs)")
	cmd.Flags().BoolVar(&flags.debug, "debug", false,
		"Enable debug output")
	cmd.Flags().BoolVar(&flags.skipInstall, "skip-install", false,
		"Skip installation (use existing disks)")
	cmd.Flags().BoolVar(&flags.serverOnly, "server-only", false,
		"Run server VM only")
	cmd.Flags().BoolVar(&flags.clientOnly, "client-only", false,
		"Run client VM only (assumes server is running)")

	// FIDO2 flags
	cmd.Flags().BoolVar(&flags.fido2Enable, "fido2", false,
		"Enable FIDO2/CanoKey device emulation")
	cmd.Flags().StringVar(&flags.fido2Mode, "fido2-mode", "canokey",
		"FIDO2 mode: 'canokey', 'u2f-emulated', or 'u2f-passthru'")

	// Config template paths
	cmd.Flags().StringVar(&flags.serverConfigPath, "server-config", "",
		"Path to server platform config template (default: configs/platform/standalone/qemu.server.example.com.yaml)")
	cmd.Flags().StringVar(&flags.clientConfigPath, "client-config", "",
		"Path to client platform config template (default: configs/platform/standalone/qemu.client.example.com.yaml)")

	// User-mode networking flags (no root required)
	cmd.Flags().BoolVar(&flags.userNetwork, "user-network", false,
		"Use user-mode networking with port forwarding (no root required, --server-only only)")
	cmd.Flags().IntVar(&flags.serverHostPort, "server-host-port", 8443,
		"Host port to forward to guest HTTPS (8443) when using --user-network")
	cmd.Flags().IntVar(&flags.dnsHostPort, "dns-host-port", 8053,
		"Host port to forward to guest DNS (8053) when using --user-network")

	// OVS networking flag (SDN features)
	cmd.Flags().BoolVar(&flags.useOVS, "use-ovs", false,
		"Use Open vSwitch for SDN networking (requires OVS installed and running)")

	// Platformd binary override (useful for static builds)
	cmd.Flags().StringVar(&flags.platformdBinary, "platformd-binary", "",
		"Path to platformd binary for ISO building (default: current executable)")

	// WebUI path (public_html directory or tarball)
	cmd.Flags().StringVar(&flags.webUIPath, "webui", "",
		"Path to WebUI directory or tarball (public_html or public_html.tar.gz)")

	// Force console output (bypass TTY detection) - enabled by default
	cmd.Flags().BoolVar(&flags.forceConsole, "console", true,
		"Enable console output (default: true, use --console=false to disable)")

	// Profile-driven network configuration flags
	cmd.Flags().StringVar(&flags.serverProfile, "server-profile", "",
		"Path to server device profile YAML (enables profile-driven network config)")
	cmd.Flags().StringVar(&flags.clientProfile, "client-profile", "",
		"Path to client device profile YAML (enables profile-driven network config)")
	cmd.Flags().BoolVar(&flags.dynamicNetwork, "dynamic-network", false,
		"Use network configuration from device profiles instead of defaults")
	cmd.Flags().BoolVar(&flags.enableDHCP, "enable-dhcp", false,
		"Enable DHCP server in testenv for dynamic IP assignment")
	cmd.Flags().IntVar(&flags.serverTimeout, "server-timeout", 600,
		"Timeout in seconds for waiting for server to be ready (default: 600 = 10 minutes)")

	// Bootstrap trust strategy flags
	cmd.Flags().StringVar(&flags.bootstrapStrategy, "bootstrap-strategy", "dane",
		"Bootstrap strategy for CA bundle fetch (dane, noise, spki, embedded, auto)")
	cmd.Flags().StringVar(&flags.bootstrapNoiseKey, "bootstrap-noise-key", "",
		"Hex-encoded Noise_NK server static key for bootstrap")
	cmd.Flags().StringVar(&flags.bootstrapSPKIPin, "bootstrap-spki-pin", "",
		"Hex-encoded SPKI SHA-256 pin for bootstrap")

	return cmd
}

// loadCSDeviceProfile loads a device profile from a YAML file
func loadCSDeviceProfile(path string) (*deviceentities.DeviceProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read profile", Err: err}
	}

	var profile deviceentities.DeviceProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, &WrappedError{Msg: "failed to parse profile", Err: err}
	}

	return &profile, nil
}

// createCSLogger creates a logger instance for client-server tests
func createCSLogger(debug bool) *logging.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return logging.NewLogger(level, nil)
}

// runClientServerTest executes the client-server test
func runClientServerTest(commonFlags *cli.CommonFlags, flags *clientServerFlags) error {
	// Validate flag values before any destructive setup (disk creation,
	// NVRAM reset) in either the server or client leg.
	if err := qemu.ValidateDiskCache(flags.diskCache); err != nil {
		return err
	}

	printTestHeader("Client-Server Test")

	// User-mode networking only supports single VM (server-only)
	if flags.userNetwork && !flags.serverOnly {
		return &MessageError{Msg: "--user-network only supports --server-only mode (single VM testing)"}
	}

	// OVS and user-network are mutually exclusive
	if flags.useOVS && flags.userNetwork {
		return &MessageError{Msg: "--use-ovs and --user-network are mutually exclusive"}
	}

	// Check root privileges (not needed for user-mode networking)
	if !flags.userNetwork {
		if err := testenv.CheckRootPrivileges(); err != nil {
			return err
		}
	}

	// Check OVS availability if requested
	if flags.useOVS && !testenv.IsOVSAvailable() {
		return &MessageError{Msg: "OVS is not available (check if openvswitch is installed and running)"}
	}

	// Create logger
	logger := createCSLogger(flags.debug)

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, cleaning up...")
		cancel()
	}()

	// User-mode networking path (no root required)
	if flags.userNetwork {
		return runCSServerVMUserNetwork(ctx, logger, flags)
	}

	// Load device profiles if specified
	var serverProfile, clientProfile *deviceentities.DeviceProfile
	if flags.serverProfile != "" {
		var err error
		serverProfile, err = loadCSDeviceProfile(flags.serverProfile)
		if err != nil {
			return &WrappedError{Msg: "failed to load server profile", Err: err}
		}
		printInfo(fmt.Sprintf("Loaded server profile: %s", flags.serverProfile))
	}
	if flags.clientProfile != "" {
		var err error
		clientProfile, err = loadCSDeviceProfile(flags.clientProfile)
		if err != nil {
			return &WrappedError{Msg: "failed to load client profile", Err: err}
		}
		printInfo(fmt.Sprintf("Loaded client profile: %s", flags.clientProfile))
	}

	// Bridge networking path (requires root)
	// Create network configuration
	var netConfig *testenv.NetworkConfig
	if flags.dynamicNetwork && (serverProfile != nil || clientProfile != nil) {
		// Build network config from profiles
		builder := testenv.NewProfileNetworkBuilder(testenv.DefaultNetworkConfig())
		if serverProfile != nil {
			builder.WithServerProfile(serverProfile)
		}
		if clientProfile != nil {
			builder.WithClientProfile(clientProfile)
		}
		var err error
		netConfig, err = builder.Build()
		if err != nil {
			return &WrappedError{Msg: "failed to build network config from profiles", Err: err}
		}
		printInfo("Using profile-driven network configuration")
	} else {
		netConfig = testenv.DefaultNetworkConfig()
	}

	// Check if network already exists (for --client-only mode connecting to existing --server-only)
	networkExists := testenv.NetworkExists(netConfig)

	var network testenv.IsolatedNetwork
	if flags.clientOnly && networkExists {
		// Client-only mode with existing network - reuse it
		printInfo("Reusing existing network (server already running)...")
		if flags.useOVS {
			ovsNet, err := testenv.NewOVSIsolatedNetwork(netConfig, nil)
			if err != nil {
				return &WrappedError{Msg: "failed to create OVS network", Err: err}
			}
			network = ovsNet
		} else {
			network = testenv.NewIsolatedNetwork(netConfig)
		}
		// Ensure NAT/forwarding rules are in place (they may have been cleared)
		printInfo("Ensuring NAT rules are in place...")
		if err := network.EnsureRules(); err != nil {
			return &WrappedError{Msg: "failed to ensure network rules", Err: err}
		}
		// Don't cleanup on exit - server owns the network
	} else {
		// Clean up stale resources from previous runs
		printInfo("Cleaning up stale resources...")
		testenv.CleanupStaleResources(netConfig)

		// Setup isolated network
		if flags.useOVS {
			if flags.dynamicNetwork {
				printInfo("Setting up OVS isolated network with phase management...")
				ovsOpts := testenv.DefaultOVSNetworkOptions()
				// Configure VLANs for different phases if profiles specify them
				if serverProfile != nil {
					if prodNet := serverProfile.GetPostEnrollmentNetworkConfig(); prodNet != nil {
						ovsOpts.TrustedVLAN = prodNet.VLAN
					}
				}
				if clientProfile != nil {
					if provNet := clientProfile.GetEnrollmentNetworkConfig(); provNet != nil {
						ovsOpts.ProvisioningVLAN = provNet.VLAN
					}
				}
				ovsNet, err := testenv.NewOVSIsolatedNetwork(netConfig, ovsOpts)
				if err != nil {
					return &WrappedError{Msg: "failed to create OVS network", Err: err}
				}
				if err := ovsNet.Setup(); err != nil {
					return &WrappedError{Msg: "failed to setup OVS isolated network", Err: err}
				}
				// Set initial phases - server starts in production, client starts in provisioning
				if err := ovsNet.SetPhase(netConfig.ServerTapName, testenv.NetworkPhaseTrusted); err != nil {
					logger.Warnf("Failed to set server to production phase: %v", err)
				}
				if err := ovsNet.SetPhase(netConfig.ClientTapName, testenv.NetworkPhaseProvisioning); err != nil {
					logger.Warnf("Failed to set client to provisioning phase: %v", err)
				}
				network = ovsNet
				printInfo("Using OVS with dynamic network phases")
			} else {
				printInfo("Setting up OVS isolated network...")
				ovsNet, err := testenv.NewOVSIsolatedNetwork(netConfig, nil)
				if err != nil {
					return &WrappedError{Msg: "failed to create OVS network", Err: err}
				}
				if err := ovsNet.Setup(); err != nil {
					return &WrappedError{Msg: "failed to setup OVS isolated network", Err: err}
				}
				network = ovsNet
				printInfo("Using OVS for SDN networking")
			}
		} else {
			printInfo("Setting up isolated network...")
			linuxNet := testenv.NewIsolatedNetwork(netConfig)
			if err := linuxNet.Setup(); err != nil {
				return &WrappedError{Msg: "failed to setup isolated network", Err: err}
			}
			network = linuxNet
		}

		defer func() {
			// Only cleanup if we're not in client-only mode
			// (server-only mode owns the network and should clean up)
			if !flags.clientOnly {
				printInfo("Cleaning up network...")
				if err := network.Cleanup(); err != nil {
					logger.Warnf("Failed to cleanup network: %v", err)
				}
			}
		}()
	}

	printSuccess(fmt.Sprintf("Network ready: %s (gateway: %s)", netConfig.SubnetCIDR(), netConfig.GatewayIP))
	printInfo(fmt.Sprintf("Server: %s (%s)", netConfig.ServerIP, network.ServerTapName()))
	printInfo(fmt.Sprintf("Client: %s (%s)", netConfig.ClientIP, network.ClientTapName()))

	// Run server if needed
	if !flags.clientOnly {
		if err := runCSServerVM(ctx, logger, network, flags); err != nil {
			return &WrappedError{Msg: "server VM failed", Err: err}
		}
		// Ensure server VM is cleaned up when we're done (only if running in background)
		defer stopCSServerVM(logger)
	}

	// Run client if needed
	if !flags.serverOnly {
		if err := runCSClientVM(ctx, logger, network, flags); err != nil {
			return &WrappedError{Msg: "client VM failed", Err: err}
		}
	}

	printSuccess("Client-server test completed successfully!")
	return nil
}

// runCSServerVM handles the server VM lifecycle
// When serverOnly is true, it runs the server interactively.
// Otherwise, it starts the server in background mode and returns control.
func runCSServerVM(ctx context.Context, logger *logging.Logger, network testenv.IsolatedNetwork, flags *clientServerFlags) error {
	netConfig := network.Config()

	printTestHeader("Server VM")
	printInfo(fmt.Sprintf("Disk: %s (size: %s)", flags.serverDisk, flags.diskSize))
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", flags.memory, flags.cpus))
	printInfo(fmt.Sprintf("IP: %s", netConfig.ServerIP))

	// Create working directory
	if err := os.MkdirAll(flags.serverWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create server work directory", Err: err}
	}

	// Clean up any stale QEMU processes using the server TAP device
	if err := qemu.StopExistingByTap(network.ServerTapName()); err != nil {
		logger.Warnf("Failed to stop existing server QEMU processes: %v", err)
	}

	// Read platform config and apply test network overrides
	platformConfig, err := ReadServerPlatformConfig(flags.serverConfigPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read server platform config", Err: err}
	}
	platformConfig, err = ApplyNetworkConfig(platformConfig, netConfig, platformTypeServer, flags.debug)
	if err != nil {
		return &WrappedError{Msg: "failed to apply server network config", Err: err}
	}
	platformConfigPath := filepath.Join(flags.serverWorkDir, "platform.yaml")
	if err := WritePlatformConfig(platformConfig, platformConfigPath); err != nil {
		return &WrappedError{Msg: "failed to write server platform config", Err: err}
	}
	printInfo(fmt.Sprintf("Platform config: %s", platformConfigPath))

	// Create QEMU config
	qemuConfig := createCSQEMUConfig(flags.serverDisk, flags.serverWorkDir, network.ServerTapName(), netConfig.ServerMAC, flags)

	// Server ISO path
	serverISO := filepath.Join(flags.serverWorkDir, "server.iso")

	// Run installation if needed
	if !flags.skipInstall {
		printInfo("Building server ISO with static network configuration...")

		// Build custom ISO with server's installer config
		// PreFetch is enabled because the test runs in an isolated network
		// without internet access for downloading packages
		isoBuilderConfig := &ISOBuilderConfig{
			OutputPath:         serverISO,
			WorkDir:            filepath.Join(flags.serverWorkDir, "iso-build"),
			PlatformConfigPath: platformConfigPath,
			PlatformType:       "server",
			SecureBoot:         flags.secureBoot,
			EnableFIDO2:        flags.fido2Enable,
			Debug:              flags.debug,
			PlatformdBinary:    flags.platformdBinary,
			WebUIPath:          flags.webUIPath,
			PreFetch:           true,
		}
		if err := BuildCustomISO(ctx, logger, isoBuilderConfig); err != nil {
			return &WrappedError{Msg: "failed to build server ISO", Err: err}
		}
		printSuccess(fmt.Sprintf("Server ISO created: %s", serverISO))

		printInfo("Starting server installation...")

		// Create disk image
		if err := createTestDiskImage(ctx, logger, flags.serverDisk, flags.diskSize); err != nil {
			return &WrappedError{Msg: "failed to create server disk", Err: err}
		}

		// Reset NVRAM for fresh installation (ensures clean UEFI boot order)
		// This is critical for successful CD-ROM boot during installation
		if err := resetTestNVRAM(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "failed to reset NVRAM for installation", Err: err}
		}

		// Setup TPM
		tpm, err := setupTestTPM(ctx, logger, qemuConfig)
		if err != nil {
			return &WrappedError{Msg: "failed to setup server TPM", Err: err}
		}
		defer stopCSTPM(logger, tpm)

		// NOTE: Secure Boot keys are enrolled AFTER installation, not before.
		// The ISO bootloader is unsigned, so Secure Boot would reject it.
		// After installation, the UKI is signed with our keys, so we can
		// enable Secure Boot for the boot phase.

		// Set ISO for installation (use our custom server ISO)
		qemuConfig.ISO = serverISO

		// Check if we should use console output or file-based serial
		// Server uses console only in server-only mode (it's the foreground process)
		// In client-server mode, server runs in background so client can be foreground
		// forceConsole bypasses TTY detection (useful when running with sudo)
		useConsole := flags.serverOnly && (flags.forceConsole || hasInteractiveTTYCS())
		if !useConsole {
			qemuConfig.SerialConsole = false
			qemuConfig.SerialLogFile = filepath.Join(flags.serverWorkDir, "server-install-serial.log")
			logger.Infof("Using file-based serial output: %s", qemuConfig.SerialLogFile)
		} else {
			qemuConfig.SerialConsole = true
			logger.Info("Using console serial output for server install")
		}

		// Run installation
		if err := runTestQEMUInstall(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "server installation failed", Err: err}
		}

		printSuccess("Server installation completed")
	}

	// Boot server - run interactively if server-only mode, otherwise run in background
	printInfo("Starting server boot...")

	// Setup VM environment for boot
	if err := setupTestVMEnvironment(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to setup server VM environment for boot", Err: err}
	}

	// Setup TPM
	tpm, err := setupTestTPM(ctx, logger, qemuConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to setup server TPM for boot", Err: err}
	}

	// Enroll Secure Boot keys AFTER installation but BEFORE boot.
	// The installed UKI is signed with our keys, so Secure Boot can verify it.
	if err := enrollTestSecureBootKeys(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to enroll server Secure Boot keys", Err: err}
	}

	if flags.serverOnly {
		// Server-only mode: run interactively with serial console
		// forceConsole bypasses TTY detection (useful when running with sudo)
		defer stopTestTPM(logger, tpm)
		useConsole := flags.forceConsole || hasInteractiveTTYCS()
		if !useConsole {
			qemuConfig.SerialConsole = false
			qemuConfig.SerialLogFile = filepath.Join(flags.serverWorkDir, "server-boot-serial.log")
			logger.Infof("Using file-based serial output for server boot: %s", qemuConfig.SerialLogFile)
		} else {
			qemuConfig.SerialConsole = true
			logger.Info("Using console serial output for server boot")
		}
		if err := runTestQEMUBoot(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "server boot failed", Err: err}
		}
		printSuccess("Server VM completed")
	} else {
		// Client-server mode: start server in background, wait for it to be ready
		// Use file-based serial output for background operation (no TTY available)
		qemuConfig.SerialConsole = false
		qemuConfig.SerialLogFile = filepath.Join(flags.serverWorkDir, "server-serial.log")

		vm, err := qemu.NewVM(qemuConfig, logger)
		if err != nil {
			stopTestTPM(logger, tpm)
			return &WrappedError{Msg: "failed to create server VM", Err: err}
		}

		logger.Info("Starting server VM in background mode...")
		if err := vm.Start(ctx, string(qemu.BootModeBoot)); err != nil {
			stopTestTPM(logger, tpm)
			return &WrappedError{Msg: "failed to start server VM", Err: err}
		}

		printSuccess(fmt.Sprintf("Server VM started (PID: %d)", vm.GetPID()))

		// Store server state for cleanup
		csServerState = &ServerVMState{
			VM:  vm,
			TPM: tpm,
		}

		// Wait for server to be reachable
		// NOTE: The server performs firstboot provisioning which reboots the system,
		// so we need to allow enough time for:
		// 1. First boot and firstboot service execution
		// 2. Automatic reboot after TPM sealing
		// 3. Second boot and platformd service startup
		serverIPStr := netConfig.ServerIP.String()
		timeout := time.Duration(flags.serverTimeout) * time.Second
		printInfo(fmt.Sprintf("Waiting for server to be ready at %s (timeout: %v, may take several minutes due to firstboot provisioning)...", serverIPStr, timeout))
		if err := waitForCSServerReady(ctx, logger, serverIPStr, timeout); err != nil {
			// Cleanup on failure
			stopCSServerVM(logger)
			return &WrappedError{Msg: "server did not become ready", Err: err}
		}

		printSuccess("Server VM is ready")

		// Fetch CA bundle from server for embedding in client ISO
		printInfo("Fetching CA bundle from server for client ISO...")
		csServerCABundlePath = filepath.Join(flags.serverWorkDir, "ca-bundle.pem")
		if err := fetchCSCABundle(ctx, logger, serverIPStr, csServerCABundlePath, flags); err != nil {
			stopCSServerVM(logger)
			return &WrappedError{Msg: "failed to fetch CA bundle from server", Err: err}
		}
		printSuccess(fmt.Sprintf("CA bundle saved to: %s", csServerCABundlePath))
	}

	return nil
}

// stopCSServerVM stops the server VM and TPM
func stopCSServerVM(logger *logging.Logger) {
	if csServerState == nil {
		return
	}

	if csServerState.VM != nil && csServerState.VM.IsRunning() {
		logger.Info("Stopping server VM...")
		if err := csServerState.VM.Stop(); err != nil {
			logger.Warnf("Failed to stop server VM: %v", err)
		}
	}

	if csServerState.TPM != nil {
		stopTestTPM(logger, csServerState.TPM)
	}

	csServerState = nil
}

// waitForCSServerReady waits for the server to be reachable via ping and DNS
// The server may reboot during firstboot provisioning, so this function handles
// the server going down and coming back up.
func waitForCSServerReady(ctx context.Context, logger *logging.Logger, serverIP string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	pingReachable := false
	dnsReady := false
	httpsReady := false
	rebootDetected := false
	consecutivePingFailures := 0

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check ping reachability
		cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", serverIP)
		pingOK := cmd.Run() == nil

		if pingOK {
			consecutivePingFailures = 0
			if !pingReachable {
				logger.Infof("Server %s is reachable via ping", serverIP)
				pingReachable = true
			}
		} else {
			consecutivePingFailures++
			// If we had ping and now lost it, server is rebooting
			if pingReachable && consecutivePingFailures >= 3 {
				logger.Info("Server appears to be rebooting (ping lost), waiting for it to come back...")
				pingReachable = false
				dnsReady = false
				httpsReady = false
				rebootDetected = true
			}
		}

		// Check platformd service (only after ping succeeds)
		// NOTE: The platform's DNS runs on port 8053 (public) and 9053 (internal),
		// NOT port 53. ACME challenges use a custom resolver that explicitly
		// points to the platform's DNS server, so we don't need system-level DNS.
		// We check port 8053 to verify platformd is running.
		if pingReachable && !dnsReady {
			// Check if platformd's public DNS port (8053) is open
			portCmd := exec.CommandContext(ctx, "nc", "-z", "-w", "2", serverIP, "8053")
			port8053Open := portCmd.Run() == nil

			// Also check internal DNS port (9053)
			portCmd2 := exec.CommandContext(ctx, "nc", "-z", "-w", "2", serverIP, "9053")
			port9053Open := portCmd2.Run() == nil

			if !port8053Open && !port9053Open {
				logger.Debug("Platformd DNS ports (8053/9053) not open yet, waiting...")
			} else {
				// At least one DNS port is open, try a query on the internal port
				cmd := exec.CommandContext(ctx, "dig", "+short", "+timeout=2", "+tries=1",
					fmt.Sprintf("@%s", serverIP), "-p", "9053", "localhost", "A")
				output, err := cmd.CombinedOutput()
				// Even if the query returns empty, the port being open means platformd is running
				if port8053Open || port9053Open {
					logger.Infof("Server %s platformd DNS service is running (ports: 8053=%v, 9053=%v)",
						serverIP, port8053Open, port9053Open)
					dnsReady = true
				} else if err != nil {
					logger.Debug("DNS ports open but query failed", "error", err, "output", string(output))
				}
			}
		}

		// Check HTTPS port (8443) - webservice must be ready before we can fetch CA bundle
		if pingReachable && dnsReady && !httpsReady {
			portCmd := exec.CommandContext(ctx, "nc", "-z", "-w", "2", serverIP, "8443")
			port8443Open := portCmd.Run() == nil
			if port8443Open {
				logger.Infof("Server %s HTTPS service is running (port 8443)", serverIP)
				httpsReady = true
			} else {
				logger.Debug("HTTPS port (8443) not open yet, waiting...")
			}
		}

		// All checks passed
		if pingReachable && dnsReady && httpsReady {
			if rebootDetected {
				logger.Infof("Server %s is fully ready after reboot (ping + platformd)", serverIP)
			} else {
				logger.Infof("Server %s is fully ready (ping + platformd)", serverIP)
			}
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	if !pingReachable {
		return &MessageError{Msg: fmt.Sprintf("server %s did not become reachable via ping within %v", serverIP, timeout)}
	}
	if !dnsReady {
		return &MessageError{Msg: fmt.Sprintf("server %s platformd DNS service did not become ready within %v (ping OK but ports 8053/9053 not responding). "+
			"Check if platformd service is running on the server with: rc-service platformd status", serverIP, timeout)}
	}
	return &MessageError{Msg: fmt.Sprintf("server %s platformd HTTPS service did not become ready within %v (ping and DNS OK but port 8443 not responding). "+
		"Check if platformd is running on the server", serverIP, timeout)}
}

// checkCSPortsAvailable checks that the required ports are not already in use on localhost.
// This prevents false positives where an existing service is detected instead of the VM.
func checkCSPortsAvailable(ctx context.Context, logger *logging.Logger, flags *clientServerFlags) error {
	portsToCheck := []struct {
		port int
		name string
	}{
		{flags.serverHostPort, "HTTPS"},
		{flags.dnsHostPort, "DNS"},
		{9053, "Internal DNS"},
	}

	var conflicts []string
	for _, p := range portsToCheck {
		portCmd := exec.CommandContext(ctx, "nc", "-z", "-w", "1", "127.0.0.1", fmt.Sprintf("%d", p.port))
		if portCmd.Run() == nil {
			conflicts = append(conflicts, fmt.Sprintf("localhost:%d (%s)", p.port, p.name))
		}
	}

	if len(conflicts) > 0 {
		return &MessageError{Msg: fmt.Sprintf("ports already in use: %s. Stop conflicting services before running the test", strings.Join(conflicts, ", "))}
	}

	logger.Debug("All required ports are available")
	return nil
}

// waitForCSServerReadyUserNetwork waits for the server to be reachable via localhost port forwarding.
// This is used with user-mode networking where QEMU forwards ports to the host.
// The server may reboot during firstboot provisioning, so this function handles
// the server going down and coming back up.
func waitForCSServerReadyUserNetwork(ctx context.Context, logger *logging.Logger, flags *clientServerFlags, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	// Minimum boot time - don't check ports until VM has had time to boot
	// This prevents false positives from pre-existing listeners on the host
	minBootTime := 30 * time.Second
	bootStart := time.Now()

	logger.Infof("Waiting %v for VM to boot before checking ports...", minBootTime)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(minBootTime):
		logger.Debug("Minimum boot time elapsed, starting port checks...")
	}

	httpsReady := false
	statusVerified := false

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check HTTPS port (8443) on localhost via port forwarding
		if !httpsReady {
			portCmd := exec.CommandContext(ctx, "nc", "-z", "-w", "2", "127.0.0.1", fmt.Sprintf("%d", flags.serverHostPort))
			if portCmd.Run() == nil {
				logger.Infof("HTTPS port is open (localhost:%d)", flags.serverHostPort)
				httpsReady = true
			} else {
				elapsed := time.Since(bootStart)
				logger.Debugf("HTTPS port not open yet (elapsed: %v), waiting...", elapsed.Round(time.Second))
			}
		}

		// Verify platformd is actually responding with valid status
		if httpsReady && !statusVerified {
			if err := verifyCSPlatformdStatus(ctx, logger, flags); err != nil {
				logger.Debugf("Platformd status check failed: %v, retrying...", err)
			} else {
				statusVerified = true
			}
		}

		// All checks passed
		if httpsReady && statusVerified {
			elapsed := time.Since(bootStart)
			logger.Infof("Platformd is fully ready (boot time: %v)", elapsed.Round(time.Second))
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	if !httpsReady {
		return &MessageError{Msg: fmt.Sprintf("platformd HTTPS service did not become ready within %v (localhost:%d not responding). "+
			"Check server-boot-serial.log for details", timeout, flags.serverHostPort)}
	}
	return &MessageError{Msg: fmt.Sprintf("platformd status verification failed within %v. "+
		"Check server-boot-serial.log for details", timeout)}
}

// verifyCSPlatformdStatus calls the platformd /api/v1/status endpoint to verify it's running
// and the TPM is properly initialized.
func verifyCSPlatformdStatus(ctx context.Context, logger *logging.Logger, flags *clientServerFlags) error {
	url := fmt.Sprintf("https://127.0.0.1:%d/api/v1/status", flags.serverHostPort)

	// Build TLS transport using the fetched CA bundle if available.
	transport := &http.Transport{}
	if csServerCABundlePath != "" {
		bundlePEM, readErr := os.ReadFile(csServerCABundlePath)
		if readErr == nil && len(bundlePEM) > 0 {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(bundlePEM) {
				transport.TLSClientConfig = &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS13,
				}
				logger.Debug("Using fetched CA bundle for status verification TLS")
			}
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &WrappedError{Msg: "failed to create request", Err: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return &WrappedError{Msg: "failed to connect", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &MessageError{Msg: fmt.Sprintf("unexpected status code: %d", resp.StatusCode)}
	}

	// Read and log the response for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &WrappedError{Msg: "failed to read response", Err: err}
	}

	logger.Infof("Platformd status response received (%d bytes)", len(body))
	logger.Debugf("Status response: %s", string(body))

	// Verify the response contains expected TPM info
	if !strings.Contains(string(body), "tpm") && !strings.Contains(string(body), "TPM") {
		logger.Warn("Status response does not contain TPM info - provisioning may not be complete")
	}

	return nil
}

// csClientCABundlePath returns the CA bundle path for embedding in the client
// ISO. When the bootstrap strategy is "embedded", the bundle is embedded
// directly in the ISO. For all other strategies, the client fetches the bundle
// at runtime, so no embedding is needed.
func csClientCABundlePath(bundlePath string, flags *clientServerFlags) string {
	if flags.bootstrapStrategy == string(trust.StrategyEmbedded) || flags.bootstrapStrategy == "" {
		return bundlePath
	}
	return ""
}

// fetchCSCABundle fetches the CA certificate bundle from the server using the
// configured bootstrap strategy and saves it to the specified path. The DNS
// server address is resolved from the client platform config's dns.resolver
// section when available, falling back to serverIP with the default public
// DNS port.
func fetchCSCABundle(ctx context.Context, logger *logging.Logger, serverIP string, outputPath string, flags *clientServerFlags) error {
	strategy := trust.Strategy(flags.bootstrapStrategy)
	if flags.bootstrapStrategy == "" {
		strategy = trust.StrategyDANE
	}

	serverURL := fmt.Sprintf("https://%s:8443", serverIP)
	dnsServer := resolveBootstrapDNSServer(flags.clientConfigPath, serverIP)
	serverHostname := resolveServerHostname(flags.serverConfigPath)

	logger.Infof("Bootstrap DNS server resolved to: %s", dnsServer)
	if serverHostname != "" {
		logger.Infof("Bootstrap DANE hostname: %s", serverHostname)
	}

	scope := &trust.ScopeConfig{
		Strategies:       []trust.Strategy{strategy},
		ServerURL:        serverURL,
		Hostname:         serverHostname,
		BundlePath:       "/api/v1/ca/bootstrap",
		PerMethodTimeout: 15 * time.Second,
	}

	if dnsServer != "" {
		scope.DANE = &trust.DANEConfig{DNSServer: dnsServer}
	}

	if flags.bootstrapNoiseKey != "" {
		scope.Noise = &trust.NoiseConfig{
			ServerAddr:      fmt.Sprintf("%s:9999", serverIP),
			ServerStaticKey: flags.bootstrapNoiseKey,
		}
	}

	if flags.bootstrapSPKIPin != "" {
		scope.SPKI = &trust.SPKIConfig{
			Pin: flags.bootstrapSPKIPin,
		}
	}

	resolver, err := trust.NewResolver(&trust.Config{Default: scope}, logger)
	if err != nil {
		return ErrBootstrapClientCreate{Reason: err.Error()}
	}

	bundlePEM, err := resolver.CABundlePEM(ctx, trust.ClassDefault)
	if err != nil {
		return ErrCABundleFetch{Reason: err.Error()}
	}

	if len(bundlePEM) == 0 {
		return ErrCABundleEmpty{}
	}

	if err := trust.InstallToSystemTrust(bundlePEM, outputPath); err != nil {
		return ErrCABundleWrite{Path: outputPath, Reason: err.Error()}
	}

	logger.Infof("CA bundle fetched successfully: %s (%d bytes)", outputPath, len(bundlePEM))
	return nil
}

// runCSClientVM handles the client VM lifecycle
func runCSClientVM(ctx context.Context, logger *logging.Logger, network testenv.IsolatedNetwork, flags *clientServerFlags) error {
	netConfig := network.Config()

	printTestHeader("Client VM")
	printInfo(fmt.Sprintf("Disk: %s (size: %s)", flags.clientDisk, flags.diskSize))
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", flags.memory, flags.cpus))
	printInfo(fmt.Sprintf("IP: %s", netConfig.ClientIP))
	printInfo(fmt.Sprintf("DNS Server: %s", netConfig.ServerIP))

	// Create working directory
	if err := os.MkdirAll(flags.clientWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create client work directory", Err: err}
	}

	// Clean up any stale QEMU processes using the client TAP device
	if err := qemu.StopExistingByTap(network.ClientTapName()); err != nil {
		logger.Warnf("Failed to stop existing client QEMU processes: %v", err)
	}

	// Read platform config and apply test network overrides
	platformConfig, err := ReadClientPlatformConfig(flags.clientConfigPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read client platform config", Err: err}
	}
	platformConfig, err = ApplyNetworkConfig(platformConfig, netConfig, platformTypeClient, flags.debug)
	if err != nil {
		return &WrappedError{Msg: "failed to apply client network config", Err: err}
	}
	platformConfigPath := filepath.Join(flags.clientWorkDir, "platform.yaml")
	if err := WritePlatformConfig(platformConfig, platformConfigPath); err != nil {
		return &WrappedError{Msg: "failed to write client platform config", Err: err}
	}
	printInfo(fmt.Sprintf("Platform config: %s", platformConfigPath))

	// Fetch CA bundle from server if not already fetched (e.g., in --client-only mode)
	if csServerCABundlePath == "" {
		serverIPStr := netConfig.ServerIP.String()
		timeout := time.Duration(flags.serverTimeout) * time.Second

		// In --client-only mode, wait for server to be ready before fetching CA bundle
		printInfo(fmt.Sprintf("Waiting for server to be ready at %s (timeout: %v)...", serverIPStr, timeout))
		if err := waitForCSServerReady(ctx, logger, serverIPStr, timeout); err != nil {
			return &WrappedError{Msg: "server is not ready", Err: err}
		}
		printSuccess("Server is ready")

		printInfo("Fetching CA bundle from server...")
		csServerCABundlePath = filepath.Join(flags.clientWorkDir, "ca-bundle.pem")
		if err := fetchCSCABundle(ctx, logger, serverIPStr, csServerCABundlePath, flags); err != nil {
			return &WrappedError{Msg: "failed to fetch CA bundle from server", Err: err}
		}
		printSuccess(fmt.Sprintf("CA bundle saved to: %s", csServerCABundlePath))
	}

	// Create QEMU config
	qemuConfig := createCSQEMUConfig(flags.clientDisk, flags.clientWorkDir, network.ClientTapName(), netConfig.ClientMAC, flags)

	// Client ISO path
	clientISO := filepath.Join(flags.clientWorkDir, "client.iso")

	// Run installation if needed
	if !flags.skipInstall {
		printInfo("Building client ISO with static network configuration...")

		// Build custom ISO with client's installer config
		// PreFetch is enabled because the test runs in an isolated network
		isoBuilderConfig := &ISOBuilderConfig{
			OutputPath:         clientISO,
			WorkDir:            filepath.Join(flags.clientWorkDir, "iso-build"),
			PlatformConfigPath: platformConfigPath,
			PlatformType:       "client",
			SecureBoot:         flags.secureBoot,
			EnableFIDO2:        flags.fido2Enable,
			Debug:              flags.debug,
			PlatformdBinary:    flags.platformdBinary,
			CABundlePath:       csClientCABundlePath(csServerCABundlePath, flags),
			WebUIPath:          flags.webUIPath,
			PreFetch:           true,
		}
		if err := BuildCustomISO(ctx, logger, isoBuilderConfig); err != nil {
			return &WrappedError{Msg: "failed to build client ISO", Err: err}
		}
		printSuccess(fmt.Sprintf("Client ISO created: %s", clientISO))
		if csServerCABundlePath != "" {
			printInfo(fmt.Sprintf("CA bundle embedded from: %s", csServerCABundlePath))
		}

		printInfo("Starting client installation...")

		// Create disk image
		if err := createTestDiskImage(ctx, logger, flags.clientDisk, flags.diskSize); err != nil {
			return &WrappedError{Msg: "failed to create client disk", Err: err}
		}

		// Reset NVRAM for fresh installation (ensures clean UEFI boot order)
		// This is critical for successful CD-ROM boot during installation
		if err := resetTestNVRAM(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "failed to reset NVRAM for installation", Err: err}
		}

		// Setup TPM
		tpm, err := setupTestTPM(ctx, logger, qemuConfig)
		if err != nil {
			return &WrappedError{Msg: "failed to setup client TPM", Err: err}
		}
		defer stopCSTPM(logger, tpm)

		// NOTE: Secure Boot keys are enrolled AFTER installation, not before.
		// The ISO bootloader is unsigned, so Secure Boot would reject it.
		// After installation, the UKI is signed with our keys, so we can
		// enable Secure Boot for the boot phase.

		// Set ISO for installation (use our custom client ISO)
		qemuConfig.ISO = clientISO

		// Check if we should use console output or file-based serial
		// Client is always the foreground process (server runs in background in client-server mode)
		// forceConsole bypasses TTY detection (useful when running with sudo)
		useConsole := flags.forceConsole || hasInteractiveTTYCS()
		if !useConsole {
			qemuConfig.SerialConsole = false
			qemuConfig.SerialLogFile = filepath.Join(flags.clientWorkDir, "client-install-serial.log")
			logger.Infof("Using file-based serial output for client install: %s", qemuConfig.SerialLogFile)
		} else {
			qemuConfig.SerialConsole = true
			logger.Info("Using console serial output for client install")
		}

		// Run installation
		if err := runTestQEMUInstall(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "client installation failed", Err: err}
		}

		printSuccess("Client installation completed")
	}

	// Boot client
	printInfo("Starting client boot...")

	// Setup VM environment for boot
	if err := setupTestVMEnvironment(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to setup client VM environment for boot", Err: err}
	}

	// Setup TPM
	tpm, err := setupTestTPM(ctx, logger, qemuConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to setup client TPM for boot", Err: err}
	}
	defer stopTestTPM(logger, tpm)

	// Enroll Secure Boot keys AFTER installation but BEFORE boot.
	// The installed UKI is signed with our keys, so Secure Boot can verify it.
	if err := enrollTestSecureBootKeys(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to enroll client Secure Boot keys", Err: err}
	}

	// Check if we should use console output or file-based serial
	// Client is always the foreground process (server runs in background in client-server mode)
	// forceConsole bypasses TTY detection (useful when running with sudo)
	useConsole := flags.forceConsole || hasInteractiveTTYCS()
	if !useConsole {
		qemuConfig.SerialConsole = false
		qemuConfig.SerialLogFile = filepath.Join(flags.clientWorkDir, "client-boot-serial.log")
		logger.Infof("Using file-based serial output for client boot: %s", qemuConfig.SerialLogFile)
	} else {
		qemuConfig.SerialConsole = true
		logger.Info("Using console serial output for client boot")
	}

	// Run boot
	if err := runTestQEMUBoot(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "client boot failed", Err: err}
	}

	printSuccess("Client VM completed")
	return nil
}

// createCSQEMUConfig creates a QEMU config for client-server testing
func createCSQEMUConfig(diskPath, workDir, tapDevice, macAddress string, flags *clientServerFlags) *qemu.Config {
	config := qemu.DefaultConfig()
	config.DiskPath = diskPath
	config.DiskSize = flags.diskSize
	config.DiskCache = flags.diskCache
	config.Memory = flags.memory
	config.CPUs = flags.cpus
	config.WorkDir = workDir
	config.SecureBoot = flags.secureBoot
	config.Debug = flags.debug
	config.SerialConsole = true
	config.NoGraphic = true

	// Use TAP device for isolated network
	config.TapDevice = tapDevice
	config.MACAddress = macAddress

	// FIDO2 configuration
	if flags.fido2Enable {
		config.FIDO2 = &qemu.FIDO2Config{
			Enable: true,
			Mode:   flags.fido2Mode,
		}

		// Auto-select CanoKey QEMU binary if FIDO2 is enabled in canokey mode
		if flags.fido2Mode == "canokey" || flags.fido2Mode == "" {
			// Check if CanoKey-enabled QEMU is available
			if _, err := exec.LookPath("qemu-system-x86_64-canokey"); err == nil {
				config.QEMUBinary = "qemu-system-x86_64-canokey"
			}
		}
	}

	return config
}

// stopCSTPM is a helper to stop TPM in client-server context
func stopCSTPM(logger *logging.Logger, tpm harness.TPM) {
	if tpm == nil {
		return
	}
	logger.Info("Stopping software TPM...")
	if err := tpm.Stop(); err != nil {
		logger.Warnf("Failed to stop TPM: %v", err)
	}
}

// runCSServerVMUserNetwork runs the server VM with user-mode networking (no root required).
// This mode uses QEMU's NAT with port forwarding instead of TAP/bridge networking.
// Services are accessible on localhost via port forwarding.
func runCSServerVMUserNetwork(ctx context.Context, logger *logging.Logger, flags *clientServerFlags) error {
	printTestHeader("Server VM (User-Mode Networking)")
	printInfo(fmt.Sprintf("Disk: %s (size: %s)", flags.serverDisk, flags.diskSize))
	printInfo(fmt.Sprintf("Memory: %d MB, CPUs: %d", flags.memory, flags.cpus))
	printInfo("Network: user-mode NAT with port forwarding")
	printInfo(fmt.Sprintf("  HTTPS forwarding: localhost:%d -> guest:8443", flags.serverHostPort))
	printInfo(fmt.Sprintf("  DNS forwarding: localhost:%d -> guest:8053", flags.dnsHostPort))

	// Create working directory
	if err := os.MkdirAll(flags.serverWorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create server work directory", Err: err}
	}

	// Create QEMU config with user-mode networking
	qemuConfig := createCSUserNetworkQEMUConfig(flags.serverDisk, flags.serverWorkDir, flags)

	// Server ISO path
	serverISO := filepath.Join(flags.serverWorkDir, "server.iso")

	// Read platform config and apply DHCP network overrides for user-mode networking
	platformConfig, err := ReadServerPlatformConfig(flags.serverConfigPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read server platform config", Err: err}
	}
	platformConfig, err = ApplyNetworkConfig(platformConfig, nil, platformTypeDHCP, flags.debug)
	if err != nil {
		return &WrappedError{Msg: "failed to apply DHCP network config", Err: err}
	}
	platformConfigPath := filepath.Join(flags.serverWorkDir, "platform.yaml")
	if err := WritePlatformConfig(platformConfig, platformConfigPath); err != nil {
		return &WrappedError{Msg: "failed to write server platform config", Err: err}
	}
	printInfo(fmt.Sprintf("Platform config: %s", platformConfigPath))

	// Run installation if needed
	if !flags.skipInstall {
		printInfo("Building server ISO with DHCP network configuration...")

		// Build custom ISO with server's installer config
		// PreFetch is enabled because the test runs in an isolated network
		isoBuilderConfig := &ISOBuilderConfig{
			OutputPath:         serverISO,
			WorkDir:            filepath.Join(flags.serverWorkDir, "iso-build"),
			PlatformConfigPath: platformConfigPath,
			PlatformType:       "server",
			SecureBoot:         flags.secureBoot,
			EnableFIDO2:        flags.fido2Enable,
			Debug:              flags.debug,
			PlatformdBinary:    flags.platformdBinary,
			WebUIPath:          flags.webUIPath,
			PreFetch:           true,
		}
		if err := BuildCustomISO(ctx, logger, isoBuilderConfig); err != nil {
			return &WrappedError{Msg: "failed to build server ISO", Err: err}
		}
		printSuccess(fmt.Sprintf("Server ISO created: %s", serverISO))

		printInfo("Starting server installation...")

		// Create disk image
		if err := createTestDiskImage(ctx, logger, flags.serverDisk, flags.diskSize); err != nil {
			return &WrappedError{Msg: "failed to create server disk", Err: err}
		}

		// Reset NVRAM for fresh installation (ensures clean UEFI boot order)
		// This is critical for successful CD-ROM boot during installation
		if err := resetTestNVRAM(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "failed to reset NVRAM for installation", Err: err}
		}

		// Setup TPM
		tpm, err := setupTestTPM(ctx, logger, qemuConfig)
		if err != nil {
			return &WrappedError{Msg: "failed to setup server TPM", Err: err}
		}
		defer stopCSTPM(logger, tpm)

		// NOTE: Secure Boot keys are enrolled AFTER installation, not before.
		// The ISO bootloader is unsigned, so Secure Boot would reject it.
		// After installation, the UKI is signed with our keys, so we can
		// enable Secure Boot for the boot phase.

		// Set ISO for installation
		qemuConfig.ISO = serverISO

		// Run installation
		if err := runTestQEMUInstall(ctx, logger, qemuConfig); err != nil {
			return &WrappedError{Msg: "server installation failed", Err: err}
		}

		printSuccess("Server installation completed")
	}

	// Boot server in background mode
	// This is where firstboot runs: TPM sealing, platformd provisioning
	printInfo("Starting server boot (firstboot will run)...")

	// Check that required ports are not already in use (prevents false positive detection)
	if err := checkCSPortsAvailable(ctx, logger, flags); err != nil {
		return &WrappedError{Msg: "pre-flight check failed", Err: err}
	}

	// Setup VM environment for boot
	if err := setupTestVMEnvironment(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to setup server VM environment for boot", Err: err}
	}

	// Setup TPM
	tpm, err := setupTestTPM(ctx, logger, qemuConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to setup server TPM for boot", Err: err}
	}

	// Enroll Secure Boot keys AFTER installation but BEFORE boot.
	// The installed UKI is signed with our keys, so Secure Boot can verify it.
	if err := enrollTestSecureBootKeys(ctx, logger, qemuConfig); err != nil {
		return &WrappedError{Msg: "failed to enroll server Secure Boot keys", Err: err}
	}

	// Use file-based serial output for background operation
	qemuConfig.SerialConsole = false
	qemuConfig.SerialLogFile = filepath.Join(flags.serverWorkDir, "server-boot-serial.log")

	// Start VM in background mode
	vm, err := qemu.NewVM(qemuConfig, logger)
	if err != nil {
		stopTestTPM(logger, tpm)
		return &WrappedError{Msg: "failed to create server VM", Err: err}
	}

	logger.Info("Starting server VM in background mode...")
	if err := vm.Start(ctx, string(qemu.BootModeBoot)); err != nil {
		stopTestTPM(logger, tpm)
		return &WrappedError{Msg: "failed to start server VM", Err: err}
	}

	printSuccess(fmt.Sprintf("Server VM started (PID: %d)", vm.GetPID()))

	// Wait for platformd to be ready on localhost (via port forwarding)
	// Firstboot may reboot the system, so we need to allow time for:
	// 1. First boot and firstboot service execution
	// 2. Automatic reboot after TPM sealing
	// 3. Second boot and platformd service startup
	timeout := time.Duration(flags.serverTimeout) * time.Second
	printInfo(fmt.Sprintf("Waiting for platformd to be ready (timeout: %v, may take several minutes due to firstboot provisioning)...", timeout))
	if err := waitForCSServerReadyUserNetwork(ctx, logger, flags, timeout); err != nil {
		// Cleanup on failure
		logger.Warn("Server did not become ready, stopping VM...")
		vm.Stop()
		stopTestTPM(logger, tpm)
		return &WrappedError{Msg: "server did not become ready", Err: err}
	}

	printSuccess("Platform provisioning completed successfully!")
	printInfo(fmt.Sprintf("Serial log available at: %s", qemuConfig.SerialLogFile))

	// Stop the VM gracefully
	printInfo("Stopping server VM...")
	if err := vm.Stop(); err != nil {
		logger.Warnf("Failed to stop server VM: %v", err)
	}
	stopTestTPM(logger, tpm)

	printSuccess("Server VM completed - platform provisioning verified")
	return nil
}

// createCSUserNetworkQEMUConfig creates a QEMU config with user-mode networking and port forwarding
func createCSUserNetworkQEMUConfig(diskPath, workDir string, flags *clientServerFlags) *qemu.Config {
	config := qemu.DefaultConfig()
	config.DiskPath = diskPath
	config.DiskSize = flags.diskSize
	config.DiskCache = flags.diskCache
	config.Memory = flags.memory
	config.CPUs = flags.cpus
	config.WorkDir = workDir
	config.SecureBoot = flags.secureBoot
	config.Debug = flags.debug
	config.SerialConsole = true
	config.NoGraphic = true

	// Use user-mode networking with port forwarding
	config.NetworkMode = "user"
	config.TapDevice = "" // Clear any TAP device
	config.PortForwards = []qemu.PortForward{
		// Web service HTTP/HTTPS
		{HostPort: 8080, GuestPort: 8080, Protocol: "tcp"},
		{HostPort: flags.serverHostPort, GuestPort: 8443, Protocol: "tcp"},
		// DNS (both TCP and UDP)
		{HostPort: flags.dnsHostPort, GuestPort: 8053, Protocol: "tcp"},
		{HostPort: flags.dnsHostPort, GuestPort: 8053, Protocol: "udp"},
		// Internal DNS
		{HostPort: 9053, GuestPort: 9053, Protocol: "tcp"},
		{HostPort: 9053, GuestPort: 9053, Protocol: "udp"},
		// SSH for debugging
		{HostPort: 2222, GuestPort: 22, Protocol: "tcp"},
	}

	// FIDO2 configuration
	if flags.fido2Enable {
		config.FIDO2 = &qemu.FIDO2Config{
			Enable: true,
			Mode:   flags.fido2Mode,
		}

		// Auto-select CanoKey QEMU binary if FIDO2 is enabled in canokey mode
		if flags.fido2Mode == "canokey" || flags.fido2Mode == "" {
			// Check if CanoKey-enabled QEMU is available
			if _, err := exec.LookPath("qemu-system-x86_64-canokey"); err == nil {
				config.QEMUBinary = "qemu-system-x86_64-canokey"
			}
		}
	}

	return config
}

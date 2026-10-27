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

package install

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/installer/alpine" // Register Alpine FIPS installer
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// systemFlags contains flags for the system install command
type systemFlags struct {
	config             string
	os                 string
	osVersion          string
	disk               string
	efiSize            int
	partitionTable     string
	filesystem         string
	lvmVG              string
	lvmLV              string
	password           string
	rootPassword       string
	hostname           string
	mirror             string
	automated          bool
	fips               bool
	lockdown           bool
	lockdownMode       string
	tpmAutoUpgradeSeal bool
	platformdBinary    string
	verbose            bool
	debug              bool

	// Install-time remote Secure Boot DB signing (resign-mode: remote). These
	// mirror what `platformctl provision fetch-config` already accepts; the DB
	// private key never leaves the control plane. When provisionServerURL is
	// empty the remote signer is not wired and the installer falls through to
	// on-node key generation (airgap / local installs).
	provisionServerURL string
	eabKID             string
	eabHMAC            string
	ekSerial           string
	mac                string
	ekCertPath         string
	caBundle           string
}

// newSystemCommand creates the system subcommand for OS installation
func newSystemCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &systemFlags{}

	cmd := &cobra.Command{
		Use:   "system",
		Short: "Install complete operating system",
		Long: `System installation performs complete OS installation including:
  - Disk partitioning (GPT/MBR)
  - LUKS2 encryption setup
  - Base OS installation (Alpine, Debian, Fedora, Ubuntu)
  - System configuration (fstab, crypttab, network)
  - Kernel and initramfs installation
  - UKI (Unified Kernel Image) building
  - Optional Secure Boot signing
  - Optional TPM sealing

Configuration priority (highest to lowest):
  1. Command-line flags (override everything)
  2. Config file (default: /etc/platformd/install.yaml)
  3. Environment variables
  4. Hardcoded defaults

This command should only be run during initial system installation from live media.`,
		Example: `  # Install using config file
  platformctl install system --config /etc/platformd/install.yaml

  # Install Alpine Linux with encryption using flags
  platformctl install system --os alpine --disk /dev/sda --password "secret" --automated

  # Install with custom settings and config file overrides
  platformctl install system --config /etc/platformd/install.yaml --disk /dev/nvme0n1 --hostname myserver`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSystemInstall(cmd, flags, cmdFlags)
		},
	}

	// Add flags
	cmd.Flags().StringVar(&cmdFlags.config, "config", "", "Path to config file (default: /etc/platformd/install.yaml)")
	cmd.Flags().StringVar(&cmdFlags.os, "os", "alpine", "Operating system to install (alpine, debian, fedora, ubuntu)")
	cmd.Flags().StringVar(&cmdFlags.osVersion, "os-version", "", "OS version (default: latest stable)")
	cmd.Flags().StringVar(&cmdFlags.disk, "disk", "", "Target disk device (e.g., /dev/sda)")
	cmd.Flags().IntVar(&cmdFlags.efiSize, "efi-size", 538, "EFI partition size in MB")
	cmd.Flags().StringVar(&cmdFlags.partitionTable, "partition-table", "gpt", "Partition table type (gpt or mbr)")
	cmd.Flags().StringVar(&cmdFlags.filesystem, "filesystem", "lvm", "Root filesystem type (lvm or ext4)")
	cmd.Flags().StringVar(&cmdFlags.lvmVG, "lvm-vg", "vg0", "LVM volume group name (when using lvm)")
	cmd.Flags().StringVar(&cmdFlags.lvmLV, "lvm-lv", "root", "LVM logical volume name (when using lvm)")
	cmd.Flags().StringVar(&cmdFlags.password, "password", "", "LUKS encryption password")
	cmd.Flags().StringVar(&cmdFlags.rootPassword, "root-password", "", "Root user password (optional)")
	cmd.Flags().StringVar(&cmdFlags.hostname, "hostname", "trusted-platform", "System hostname")
	cmd.Flags().StringVar(&cmdFlags.mirror, "mirror", "", "Alpine mirror URL (default: https://dl-cdn.alpinelinux.org/alpine)")
	cmd.Flags().BoolVar(&cmdFlags.automated, "automated", false, "Automated mode - no interactive prompts")
	cmd.Flags().BoolVar(&cmdFlags.fips, "fips", false, "Enable FIPS mode")
	cmd.Flags().BoolVar(&cmdFlags.lockdown, "lockdown", true, "Enable kernel lockdown")
	cmd.Flags().StringVar(&cmdFlags.lockdownMode, "lockdown-mode", "confidentiality", "Kernel lockdown mode: integrity or confidentiality (default: confidentiality)")
	cmd.Flags().BoolVar(&cmdFlags.tpmAutoUpgradeSeal, "tpm-auto-upgrade-seal", true, "Enable automatic TPM resealing on kernel upgrade")
	cmd.Flags().StringVar(&cmdFlags.platformdBinary, "platformd-binary", "", "Path to platformd binary to install (optional)")
	cmd.Flags().BoolVarP(&cmdFlags.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&cmdFlags.debug, "debug", false, "Enable debug logging (implies verbose)")

	// Install-time remote Secure Boot DB signing (resign-mode: remote). When
	// --provision-server-url is set and secure-boot.resign-mode is remote, the
	// installer signs the UKI digest via the control plane's
	// /api/v1/provisioning/sign endpoint instead of generating a DB key on-node.
	cmd.Flags().StringVar(&cmdFlags.provisionServerURL, "provision-server-url", "", "Control-plane URL for remote Secure Boot DB signing (e.g. https://platform:8443)")
	cmd.Flags().StringVar(&cmdFlags.eabKID, "eab-kid", "", "EAB key ID for remote provisioning auth")
	cmd.Flags().StringVar(&cmdFlags.eabHMAC, "eab-hmac", "", "EAB HMAC for remote provisioning auth")
	cmd.Flags().StringVar(&cmdFlags.ekSerial, "ek-serial", "", "TPM EK serial presented for remote provisioning auth")
	cmd.Flags().StringVar(&cmdFlags.mac, "mac", "", "Booting NIC MAC presented for remote provisioning auth")
	cmd.Flags().StringVar(&cmdFlags.ekCertPath, "ek-cert", "", "Path to the TPM EK certificate (DER or PEM) for EK-bound profiles")
	cmd.Flags().StringVar(&cmdFlags.caBundle, "ca-bundle", "", "Path to the CA bundle (PEM) used to verify the control plane's TLS certificate")

	return cmd
}

// runSystemInstall executes the system installation command
func runSystemInstall(cmd *cobra.Command, _ *cli.CommonFlags, cmdFlags *systemFlags) error {
	// Initialize logger
	logger := getInstallLogger(cmdFlags.verbose, cmdFlags.debug)

	logger.Info("Starting system installation")

	// Load configuration
	config, platform, err := loadConfig(logger, cmd, cmdFlags)
	if err != nil {
		return ErrConfigLoadFailed{Path: cmdFlags.config, Err: err}
	}

	// Log where configuration was loaded from
	if cmdFlags.config != "" {
		logger.Info("Loaded configuration from file", "path", cmdFlags.config)
	} else if _, statErr := os.Stat("/etc/platformd/install.yaml"); statErr == nil {
		logger.Info("Loaded configuration from file", "path", "/etc/platformd/install.yaml")
	} else {
		logger.Info("Using configuration from command-line flags")
	}

	logger.Info("Installation configuration",
		"os", config.OS.OS,
		"disk", config.Disk.Device,
		"hostname", config.OS.Hostname)

	// Validate configuration
	if err := config.Validate(); err != nil {
		return ErrConfigValidationFailed{Err: err}
	}

	// Validate password for automated mode
	if cmdFlags.automated {
		if config.Disk.Encryption == nil || (config.Disk.Encryption.Password == "" && config.Disk.Encryption.Passphrase == "") {
			return ErrPasswordRequired{}
		}
	}

	// Create installer, wiring the install-time remote Secure Boot DB signer when
	// resign-mode remote and a provisioning context (CP URL + EAB/EK) is present.
	opts, err := remoteSignInstallerOptions(config, cmdFlags)
	if err != nil {
		return err
	}
	// A diskless-nbd install enrols through the platform's own client first.
	if enroller := identityEnroller(platform); enroller != nil {
		opts = append(opts, installer.WithIdentityEnroller(enroller))
	}
	inst, err := installer.NewInstaller(logger, config, opts...)
	if err != nil {
		return ErrInstallerCreationFailed{Err: err}
	}
	defer inst.Close()

	// Run installation
	ctx := context.Background()
	logger.Info("Running system installation")
	if err := inst.Install(ctx); err != nil {
		logger.Error(err, "message", "Installation failed")
		return ErrInstallationFailed{Err: err}
	}

	logger.Info("System installation completed successfully")

	fmt.Println("\nSystem installation completed successfully!")
	fmt.Println("\nNext steps:")
	fmt.Println("  1. The system has been installed with LUKS encryption")
	fmt.Println("  2. A Unified Kernel Image (UKI) has been created")
	fmt.Println("  3. Remove the installation media and reboot")
	fmt.Println("\nImportant: Remember your LUKS passphrase!")

	return nil
}

// getInstallLogger creates the appropriate logger for installation
func getInstallLogger(verbose, debug bool) *logging.Logger {
	level := slog.LevelWarn
	if debug {
		level = slog.LevelDebug
	} else if verbose {
		level = slog.LevelInfo
	}
	return logging.NewLogger(level, nil)
}

// loadConfig loads the configuration from file or creates from flags.
// Uses unified App config format (with seal-pcrs field).
func loadConfig(logger *logging.Logger, cmd *cobra.Command, cmdFlags *systemFlags) (*installer.Config, *app.App, error) {
	var config *installer.Config
	var platform *app.App
	var err error

	// Determine config file path
	configPath := cmdFlags.config
	if configPath == "" {
		configPath = "/etc/platformd/install.yaml"
	}

	// Try to load config file if it exists
	if _, statErr := os.Stat(configPath); statErr == nil {
		logger.Debug("Loading config from file", "path", configPath)

		platform, err = decodePlatformConfig(logger, configPath)
		if err != nil {
			return nil, nil, err
		}
		// Extract installer.Config from App, with the network plan of the
		// node's environment (sdn.environment).
		config, err = platform.GetInstallerConfig()
		if err != nil {
			return nil, nil, err
		}
	} else {
		// No config file, create from flags
		logger.Debug("Config file not found, creating from flags", "path", configPath)
		config = createConfigFromFlags(cmdFlags)
	}

	// Apply flag overrides to config
	applyFlagOverrides(logger, config, cmd, cmdFlags)

	return config, platform, nil
}

// loadUnifiedConfig loads config as a unified App config.
// Returns installer.Config extracted from App.
func loadUnifiedConfig(logger *logging.Logger, configPath string) (*installer.Config, error) {
	platform, err := decodePlatformConfig(logger, configPath)
	if err != nil {
		return nil, err
	}
	// Extract installer.Config from App, with the network plan of the
	// node's environment (sdn.environment).
	return platform.GetInstallerConfig()
}

// decodePlatformConfig reads the unified platform configuration (the App).
func decodePlatformConfig(logger *logging.Logger, configPath string) (*app.App, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	if err := app.CheckPlatformConfigYAML(data); err != nil {
		return nil, err
	}
	var appConfig app.App
	if err := config.DecodeYAML(data, &appConfig); err != nil {
		return nil, err
	}

	logger.Info("Loaded App config", "path", configPath, "seal-pcrs", appConfig.SealPCRs)
	return &appConfig, nil
}

// identityEnroller is the enrollment client a diskless-nbd install runs: the
// platform's own, App.EnrollIdentity, which platformd runs on a disk node's
// first boot. Without a platform configuration there is none, and the
// installer refuses a diskless-nbd install.
func identityEnroller(platform *app.App) installer.IdentityEnroller {
	if platform == nil {
		return nil
	}
	return platform
}

// createConfigFromFlags builds a config from current flag values
func createConfigFromFlags(cmdFlags *systemFlags) *installer.Config {
	// Determine partition table type
	var partTableType installer.PartitionTable
	switch cmdFlags.partitionTable {
	case "gpt":
		partTableType = installer.PartitionTableGPT
	case "mbr":
		partTableType = installer.PartitionTableMBR
	default:
		partTableType = installer.PartitionTableGPT
	}

	// Determine OS type
	var osType installer.OperatingSystem
	switch cmdFlags.os {
	case "alpine":
		osType = installer.OSAlpine
	case "debian":
		osType = installer.OSDebian
	case "fedora":
		osType = installer.OSFedora
	case "ubuntu":
		osType = installer.OSUbuntu
	default:
		osType = installer.OSAlpine
	}

	// Determine filesystem type
	var fsType installer.FilesystemType
	switch cmdFlags.filesystem {
	case "lvm":
		fsType = installer.FilesystemLVM
	case "ext4":
		fsType = installer.FilesystemExt4
	default:
		fsType = installer.FilesystemLVM
	}

	return &installer.Config{
		Disk: &installer.DiskConfig{
			Device:           cmdFlags.disk,
			PartitionTable:   partTableType,
			EFIPartitionSize: cmdFlags.efiSize,
			RootFilesystem:   fsType,
			LVMVolumeGroup:   cmdFlags.lvmVG,
			LVMLogicalVolume: cmdFlags.lvmLV,
			Encryption: &installer.EncryptionConfig{
				Cipher:     "aes-xts-plain64",
				KeySize:    512,
				Hash:       "sha256",
				PBKDF:      getPBKDFForFIPS(cmdFlags.fips),
				Password:   cmdFlags.password,
				Passphrase: cmdFlags.password,
				MappedName: "cryptroot",
			},
		},
		OS: &installer.OSConfig{
			OS:                 osType,
			Version:            cmdFlags.osVersion,
			Architecture:       "x86_64",
			RootPassword:       cmdFlags.rootPassword,
			Hostname:           cmdFlags.hostname,
			Mirror:             cmdFlags.mirror,
			FilesystemType:     fsType,
			FIPS:               cmdFlags.fips,
			Lockdown:           cmdFlags.lockdown,
			LockdownMode:       cmdFlags.lockdownMode,
			TPMAutoUpgradeSeal: cmdFlags.tpmAutoUpgradeSeal,
			PlatformdBinary:    cmdFlags.platformdBinary,
		},
		EnableTPMSealing: true,
		SecureBoot:       nil,
	}
}

// getPBKDFForFIPS returns the appropriate PBKDF algorithm based on FIPS mode
func getPBKDFForFIPS(fipsEnabled bool) string {
	if fipsEnabled {
		return "pbkdf2" // FIPS-approved
	}
	return "argon2id" // Default, more secure but not FIPS-approved
}

// applyFlagOverrides applies explicitly set command-line flags to the config
func applyFlagOverrides(logger *logging.Logger, config *installer.Config, cmd *cobra.Command, cmdFlags *systemFlags) {
	// Initialize nil sub-configs with sensible defaults to prevent nil pointer dereferences
	defaults := installer.DefaultConfig()
	if config.Disk == nil {
		config.Disk = defaults.Disk
	} else {
		// Apply defaults for zero-valued fields
		if config.Disk.PartitionTable == "" {
			config.Disk.PartitionTable = defaults.Disk.PartitionTable
		}
		if config.Disk.EFIPartitionSize == 0 {
			config.Disk.EFIPartitionSize = defaults.Disk.EFIPartitionSize
		}
		if config.Disk.RootFilesystem == "" {
			config.Disk.RootFilesystem = defaults.Disk.RootFilesystem
		}
		if config.Disk.LVMVolumeGroup == "" {
			config.Disk.LVMVolumeGroup = defaults.Disk.LVMVolumeGroup
		}
		if config.Disk.LVMLogicalVolume == "" {
			config.Disk.LVMLogicalVolume = defaults.Disk.LVMLogicalVolume
		}
		if config.Disk.Encryption == nil {
			config.Disk.Encryption = defaults.Disk.Encryption
		}
	}
	if config.OS == nil {
		config.OS = defaults.OS
	} else {
		if config.OS.Architecture == "" {
			config.OS.Architecture = defaults.OS.Architecture
		}
		if config.OS.Hostname == "" {
			config.OS.Hostname = defaults.OS.Hostname
		}
		if config.OS.FilesystemType == "" {
			// Sync with disk config if available, otherwise default to LVM
			if config.Disk != nil && config.Disk.RootFilesystem != "" {
				config.OS.FilesystemType = config.Disk.RootFilesystem
			} else {
				config.OS.FilesystemType = installer.FilesystemLVM
			}
		}
	}
	if config.Network == nil {
		config.Network = &installer.NetworkConfig{}
	}
	if !config.EnableTPMSealing {
		config.EnableTPMSealing = defaults.EnableTPMSealing
	}

	// Disk configuration overrides
	if cmd.Flags().Changed("disk") {
		logger.Debug("Overriding disk device from flag", "value", cmdFlags.disk)
		config.Disk.Device = cmdFlags.disk
	}

	if cmd.Flags().Changed("partition-table") {
		logger.Debug("Overriding partition table from flag", "value", cmdFlags.partitionTable)
		switch cmdFlags.partitionTable {
		case "gpt":
			config.Disk.PartitionTable = installer.PartitionTableGPT
		case "mbr":
			config.Disk.PartitionTable = installer.PartitionTableMBR
		}
	}

	if cmd.Flags().Changed("efi-size") {
		logger.Debug("Overriding EFI size from flag", "value", cmdFlags.efiSize)
		config.Disk.EFIPartitionSize = cmdFlags.efiSize
	}

	if cmd.Flags().Changed("filesystem") {
		logger.Debug("Overriding filesystem from flag", "value", cmdFlags.filesystem)
		switch cmdFlags.filesystem {
		case "lvm":
			config.Disk.RootFilesystem = installer.FilesystemLVM
			config.OS.FilesystemType = installer.FilesystemLVM
		case "ext4":
			config.Disk.RootFilesystem = installer.FilesystemExt4
			config.OS.FilesystemType = installer.FilesystemExt4
		}
	}

	if cmd.Flags().Changed("lvm-vg") {
		logger.Debug("Overriding LVM VG from flag", "value", cmdFlags.lvmVG)
		config.Disk.LVMVolumeGroup = cmdFlags.lvmVG
	}

	if cmd.Flags().Changed("lvm-lv") {
		logger.Debug("Overriding LVM LV from flag", "value", cmdFlags.lvmLV)
		config.Disk.LVMLogicalVolume = cmdFlags.lvmLV
	}

	if cmd.Flags().Changed("password") {
		logger.Debug("Overriding password from flag")
		if config.Disk.Encryption == nil {
			config.Disk.Encryption = &installer.EncryptionConfig{}
		}
		config.Disk.Encryption.Password = cmdFlags.password
		config.Disk.Encryption.Passphrase = cmdFlags.password
	}

	// OS configuration overrides
	if cmd.Flags().Changed("os") {
		logger.Debug("Overriding OS from flag", "value", cmdFlags.os)
		switch cmdFlags.os {
		case "alpine":
			config.OS.OS = installer.OSAlpine
		case "debian":
			config.OS.OS = installer.OSDebian
		case "fedora":
			config.OS.OS = installer.OSFedora
		case "ubuntu":
			config.OS.OS = installer.OSUbuntu
		}
	}

	if cmd.Flags().Changed("os-version") {
		logger.Debug("Overriding OS version from flag", "value", cmdFlags.osVersion)
		config.OS.Version = cmdFlags.osVersion
	}

	if cmd.Flags().Changed("hostname") {
		logger.Debug("Overriding hostname from flag", "value", cmdFlags.hostname)
		config.OS.Hostname = cmdFlags.hostname
	}

	if cmd.Flags().Changed("mirror") {
		logger.Debug("Overriding mirror from flag", "value", cmdFlags.mirror)
		config.OS.Mirror = cmdFlags.mirror
	}

	if cmd.Flags().Changed("root-password") {
		logger.Debug("Overriding root password from flag")
		config.OS.RootPassword = cmdFlags.rootPassword
	}

	if cmd.Flags().Changed("fips") {
		logger.Debug("Overriding FIPS from flag", "value", cmdFlags.fips)
		config.OS.FIPS = cmdFlags.fips
	}

	if cmd.Flags().Changed("lockdown") {
		logger.Debug("Overriding lockdown from flag", "value", cmdFlags.lockdown)
		config.OS.Lockdown = cmdFlags.lockdown
	}

	if cmd.Flags().Changed("lockdown-mode") {
		logger.Debug("Overriding lockdown mode from flag", "value", cmdFlags.lockdownMode)
		config.OS.LockdownMode = cmdFlags.lockdownMode
	}

	if cmd.Flags().Changed("tpm-auto-upgrade-seal") {
		logger.Debug("Overriding TPM auto upgrade seal from flag", "value", cmdFlags.tpmAutoUpgradeSeal)
		config.OS.TPMAutoUpgradeSeal = cmdFlags.tpmAutoUpgradeSeal
	}

	if cmd.Flags().Changed("platformd-binary") {
		logger.Debug("Overriding platformd binary from flag", "value", cmdFlags.platformdBinary)
		config.OS.PlatformdBinary = cmdFlags.platformdBinary
	}
}

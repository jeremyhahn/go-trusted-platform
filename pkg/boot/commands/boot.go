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

package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	bootconfig "github.com/jeremyhahn/go-trusted-platform/pkg/boot/config"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	// Installer container mount point during firstboot
	installerMountPoint = "/mnt/installer"
)

var (
	bootTimeout      int
	bootPCRs         []uint
	bootFallbackMode bool
	bootEmergency    bool
	bootDevice       string
	bootMappingName  string
	bootTPMPath      string
	bootEFIPath      string
	bootXKMSDir      string
	bootVerbose      bool
	bootDebug        bool
	bootFIPS         bool
)

// BootCmd provides the boot command for platform-initrd
var BootCmd = &cobra.Command{
	Use:   "boot",
	Short: "Boot mode - Unlock encrypted root filesystem",
	Long: `Boot mode performs normal boot operations including:
  - TPM initialization and verification
  - Encrypted volume unlock using PCR-sealed keys
  - Automatic fallback to upgrade keys if needed
  - Optional FIDO2 authentication
  - Emergency password fallback

This command is typically called automatically by the initramfs.`,
	Example: `  # Normal boot
  platform-initrd boot --device /dev/sda2

  # Boot with custom timeout
  platform-initrd boot --device /dev/sda2 --timeout 60

  # Boot with fallback enabled
  platform-initrd boot --device /dev/sda2 --fallback`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runBoot(cmd.Context())
	},
}

func init() {
	BootCmd.Flags().IntVar(&bootTimeout, "timeout", 30, "Unlock timeout in seconds")
	BootCmd.Flags().UintSliceVar(&bootPCRs, "pcrs", nil, "Expected PCR banks (reads from pcr-banks file if not specified)")
	BootCmd.Flags().BoolVar(&bootFallbackMode, "fallback", true, "Enable fallback unlock methods")
	BootCmd.Flags().BoolVar(&bootEmergency, "emergency", false, "Drop to emergency shell on failure")
	BootCmd.Flags().StringVarP(&bootDevice, "device", "d", "", "LUKS device path (e.g., /dev/sda2)")
	BootCmd.Flags().StringVarP(&bootMappingName, "name", "n", "cryptroot", "LUKS mapping name")
	BootCmd.Flags().StringVar(&bootTPMPath, "tpm-path", "/dev/tpmrm0", "TPM device path")
	BootCmd.Flags().StringVar(&bootEFIPath, "efi-path", "/boot/efi", "EFI partition mount point")
	BootCmd.Flags().StringVar(&bootXKMSDir, "xkms-dir", "/etc/trusted-platform/xkms", "XKMS storage directory")
	BootCmd.Flags().BoolVarP(&bootVerbose, "verbose", "v", false, "Enable verbose logging")
	BootCmd.Flags().BoolVar(&bootDebug, "debug", false, "Enable debug logging (implies verbose)")
	BootCmd.Flags().BoolVar(&bootFIPS, "fips", false, "Enable FIPS mode (use PBKDF2 instead of Argon2id)")

	BootCmd.MarkFlagRequired("device")
}

func runBoot(ctx context.Context) error {
	// breadcrumb prints to BOTH stderr (kernel/SOL console) and a tmpfs
	// log file so that any subsequent forensic dump can recover the exact
	// step where boot got stuck. The kernel console + this file are the
	// two channels we have for diagnosing pre-pivot hangs.
	bcFile, _ := os.OpenFile("/run/platform-initrd-boot.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	bc := func(format string, args ...any) {
		line := fmt.Sprintf("[BOOT] "+format+"\n", args...)
		os.Stderr.WriteString(line)
		if bcFile != nil {
			bcFile.WriteString(line)
			bcFile.Sync()
		}
	}
	if bcFile != nil {
		defer bcFile.Close()
	}
	bc("step01: runBoot entered, validating flags (device=%q mapping=%q)", bootDevice, bootMappingName)

	// Validate required flags
	if bootDevice == "" {
		bc("step01: ERROR --device flag is required")
		return &MessageError{Msg: "--device flag is required"}
	}

	bc("step02: InitializeLogger(mode=boot, verbose=%v, debug=%v)", bootVerbose, bootDebug)
	// Initialize logger
	logger, err := InitializeLogger("boot", bootVerbose, bootDebug)
	if err != nil {
		bc("step02: ERROR InitializeLogger: %v", err)
		return &WrappedError{Msg: "failed to initialize logger", Err: err}
	}
	bc("step02: logger ready")

	startTime := time.Now()
	logger.Info("Starting platform-initrd boot sequence",
		"device", bootDevice,
		"mapping", bootMappingName,
		"version", Version)

	bc("step03: tryMountInstaller(efiPath=%q)", bootEFIPath)
	// PRE-MOUNT: Try to mount installer.luks using go-luks2 BEFORE loading config
	// This is needed because:
	// 1. On first boot, pcr-banks file doesn't exist yet - config is in installer.luks
	// 2. CreateManager needs config from /mnt/installer/etc/trusted-platform/config.yaml
	// 3. If we don't mount here, CreateManager will fail with "no TPM configuration found"
	installerLoopDev, installerMounted := tryMountInstaller(bootEFIPath)
	bc("step03: tryMountInstaller returned mounted=%v loopDev=%q", installerMounted, installerLoopDev)
	if installerMounted {
		defer cleanupInstaller(installerLoopDev)
	}

	bc("step04: resolving PCR selection (cli pcrs=%v)", bootPCRs)
	// Load seal-pcrs from (in priority order):
	// 1. CLI flag (if explicitly provided)
	// 2. pcr-banks file on EFI (written by firstboot)
	// 3. Platform config.yaml (single source of truth)
	pcrSelection := bootPCRs
	if len(pcrSelection) == 0 {
		// Try pcr-banks file first (written by firstboot)
		pcrBanksPath := filepath.Join(bootEFIPath, "tpm2", "pcr-banks")
		bc("step04a: loadSealPCRsFromFile(%q)", pcrBanksPath)
		loadedPCRs, err := loadSealPCRsFromFile(pcrBanksPath)
		if err == nil {
			pcrSelection = loadedPCRs
			bc("step04a: loaded pcrs from pcr-banks file: %v", pcrSelection)
			logger.Info("Loaded seal-pcrs from pcr-banks", "pcrs", pcrSelection)
		} else {
			bc("step04a: pcr-banks file unavailable: %v", err)
			// Fall back to config.yaml
			logger.Debug("pcr-banks not found, loading from config.yaml", "error", err)
			bc("step04b: loadSealPCRsFromConfig()")
			configPCRs, configErr := loadSealPCRsFromConfig(logger)
			if configErr == nil {
				pcrSelection = configPCRs
				bc("step04b: loaded pcrs from config.yaml: %v", pcrSelection)
				logger.Info("Loaded seal-pcrs from config.yaml", "pcrs", pcrSelection)
			} else {
				bc("step04b: config.yaml pcr load failed: %v", configErr)
				logger.Warn("Failed to load seal-pcrs",
					"pcr_banks_error", err,
					"config_error", configErr)
				pcrSelection = []uint{}
			}
		}
	} else {
		bc("step04: using pcrs from CLI flag: %v", pcrSelection)
		logger.Info("Using seal-pcrs from CLI flag", "pcrs", pcrSelection)
	}

	bc("step05: building initrd Config (RootDevice=%q BootDevice=%q XKMSPath=%q)", bootDevice, bootEFIPath, bootXKMSDir)
	// Create initrd configuration
	config := &platforminitrd.Config{
		Mode:           platforminitrd.ModeBoot,
		RootDevice:     bootDevice,
		BootDevice:     bootEFIPath,
		XKMSPath:       bootXKMSDir,
		PCRBanks:       []string{"sha256"},
		PCRSelection:   pcrSelection,
		UnlockTimeout:  bootTimeout,
		RetryCount:     3,
		EnableAuditLog: true,
		AuditLogPath:   "/var/log/platformd/audit.log",
		FIPS:           bootFIPS,
	}

	// Configure fallback methods if enabled
	if bootFallbackMode {
		config.FallbackMethods = []storageluks.UnlockMethod{
			storageluks.UnlockTPMPCR,
			storageluks.UnlockTPMUpgrade,
			storageluks.UnlockFIDO2,
			storageluks.UnlockPassword,
		}
	}

	bc("step06: config.Validate()")
	if err := config.Validate(); err != nil {
		bc("step06: ERROR config.Validate: %v", err)
		return &WrappedError{Msg: "invalid configuration", Err: err}
	}
	bc("step06: config validated")

	bc("step07: CreateManager(tpmPath=%q)", bootTPMPath)
	// Create platform manager
	fmt.Fprintf(os.Stderr, "[BOOT] Creating platform manager\n")
	manager, err := CreateManager(ctx, logger, config, bootTPMPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] ERROR: Failed to create manager: %v\n", err)
		return handleBootFailure(ctx, err, bootEmergency)
	}
	fmt.Fprintf(os.Stderr, "[BOOT] Manager created successfully\n")
	defer manager.Close()

	// Initialize the platform
	fmt.Fprintf(os.Stderr, "[BOOT] Initializing platform components\n")
	if err := manager.Initialize(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] ERROR: Failed to initialize platform: %v\n", err)
		return handleBootFailure(ctx, err, bootEmergency)
	}
	fmt.Fprintf(os.Stderr, "[BOOT] Platform initialized successfully\n")

	// Run boot sequence
	fmt.Fprintf(os.Stderr, "[BOOT] Executing boot unlock sequence\n")
	if err := manager.Boot(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] ERROR: Boot unlock failed: %v\n", err)
		return handleBootFailure(ctx, err, bootEmergency)
	}

	duration := time.Since(startTime)
	logger.Info("Boot unlock completed successfully",
		"device", bootDevice,
		"mapping", bootMappingName,
		"duration", duration)

	fmt.Printf("Successfully unlocked %s as %s (%v)\n", bootDevice, bootMappingName, duration)

	return nil
}

// handleBootFailure handles boot failures with appropriate actions
func handleBootFailure(ctx context.Context, err error, emergency bool) error {
	if emergency {
		fmt.Fprintln(os.Stderr, "\n=== BOOT FAILURE - ENTERING EMERGENCY SHELL ===")
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr, "\nTroubleshooting steps:")
		fmt.Fprintln(os.Stderr, "  1. Check TPM status: tpm2_getcap properties-fixed")
		fmt.Fprintln(os.Stderr, "  2. Check device mapper: dmsetup ls")
		fmt.Fprintln(os.Stderr, "  3. Check logs: cat /var/log/platformd/boot.log")
		fmt.Fprintln(os.Stderr, "  4. Try recovery mode: platform-initrd recovery")
		fmt.Fprintln(os.Stderr, "\nStarting emergency shell...")

		return launchEmergencyShell(ctx)
	}

	return &WrappedError{Msg: "boot failed", Err: err}
}

// launchEmergencyShell spawns an emergency shell
func launchEmergencyShell(ctx context.Context) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	// Check if shell exists
	if _, err := os.Stat(shell); err != nil {
		return &WrappedError{Msg: "emergency shell not available", Err: err}
	}

	fmt.Fprintln(os.Stderr, "\nType 'exit' to continue boot or reboot the system.")

	// Launch shell
	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "emergency shell failed", Err: err}
	}

	return nil
}

// tryMountInstaller attempts to mount installer.luks using go-luks2
// Returns the loop device path and whether the installer was mounted
// If already mounted (by dracut hook) or doesn't exist, returns ("", false)
func tryMountInstaller(efiPath string) (string, bool) {
	fmt.Fprintf(os.Stderr, "[BOOT] tryMountInstaller: probe existing mount\n")
	// Check if installer is already mounted (by dracut hook)
	testFile := filepath.Join(installerMountPoint, "luks-key.bin")
	if _, err := os.Stat(testFile); err == nil {
		fmt.Fprintf(os.Stderr, "[BOOT] Installer already mounted at %s\n", installerMountPoint)
		return "", false
	}

	// Check if installer.luks exists
	installerPath := filepath.Join(efiPath, "tpm2", "installer.luks")
	fmt.Fprintf(os.Stderr, "[BOOT] tryMountInstaller: stat %s\n", installerPath)
	if _, err := os.Stat(installerPath); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] tryMountInstaller: installer.luks not present (%v) — not firstboot\n", err)
		// No installer.luks - not firstboot mode, or already completed
		return "", false
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Found installer.luks - attempting to mount using go-luks2\n")

	fmt.Fprintf(os.Stderr, "[BOOT] tryMountInstaller: SetupLoopDevice(%q)\n", installerPath)
	// Setup loop device for the installer file
	loopDev, err := luks2.SetupLoopDevice(installerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to setup loop device: %v\n", err)
		return "", false
	}
	fmt.Fprintf(os.Stderr, "[BOOT] Loop device created: %s\n", loopDev)
	fmt.Fprintf(os.Stderr, "[BOOT] tryMountInstaller: luks2.Unlock(installer)\n")

	// Unlock with well-known password using go-luks2
	if err := luks2.Unlock(loopDev, []byte(bootconfig.InstallerPassword), "installer"); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to unlock installer: %v\n", err)
		luks2.DetachLoopDevice(loopDev)
		return "", false
	}
	fmt.Fprintf(os.Stderr, "[BOOT] Installer unlocked successfully\n")

	// Get mapped device path
	installerDevPath, err := luks2.GetMappedDevicePath("installer")
	if err != nil {
		installerDevPath = "/dev/mapper/installer"
	}

	// Create mount point
	if err := os.MkdirAll(installerMountPoint, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to create mount point: %v\n", err)
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return "", false
	}

	// Mount read-write for provisioning (FirstbootSealStrategy needs write access)
	if err := syscall.Mount(installerDevPath, installerMountPoint, "ext4", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to mount installer: %v\n", err)
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return "", false
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Installer mounted at %s (using go-luks2)\n", installerMountPoint)
	return loopDev, true
}

// cleanupInstaller unmounts and closes the installer that we mounted
func cleanupInstaller(loopDev string) {
	fmt.Fprintf(os.Stderr, "[BOOT] Cleaning up installer mount\n")

	// Sync first
	syscall.Sync()

	// Unmount
	if err := syscall.Unmount(installerMountPoint, 0); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Normal unmount failed: %v, trying lazy\n", err)
		if err := syscall.Unmount(installerMountPoint, syscall.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Lazy unmount failed: %v\n", err)
		}
	}
	os.Remove(installerMountPoint)

	// Close LUKS
	if err := luks2.Lock("installer"); err != nil {
		fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to close LUKS: %v\n", err)
	}

	// Detach loop device
	if loopDev != "" {
		if err := luks2.DetachLoopDevice(loopDev); err != nil {
			fmt.Fprintf(os.Stderr, "[BOOT] WARNING: Failed to detach loop device: %v\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "[BOOT] Installer cleanup complete\n")
}

// loadSealPCRsFromFile loads the seal-pcrs from the pcr-banks file
// The pcr-banks file is written during firstboot with values from the installer config
// Format: seal-pcrs=0,7,9 (comma-separated PCR indices)
func loadSealPCRsFromFile(path string) ([]uint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read pcr-banks file", Err: err}
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, &MessageError{Msg: "pcr-banks file is empty"}
	}

	// Parse key=value format
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "seal-pcrs=") {
			pcrStr := strings.TrimPrefix(line, "seal-pcrs=")
			if pcrStr == "" {
				return nil, &MessageError{Msg: "seal-pcrs value is empty"}
			}

			var pcrs []uint
			for _, s := range strings.Split(pcrStr, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				var pcr uint
				if _, err := fmt.Sscanf(s, "%d", &pcr); err != nil {
					return nil, &WrappedError{Msg: fmt.Sprintf("invalid PCR value %q", s), Err: err}
				}
				pcrs = append(pcrs, pcr)
			}

			if len(pcrs) == 0 {
				return nil, &MessageError{Msg: "no valid PCRs found in seal-pcrs"}
			}
			return pcrs, nil
		}
	}

	return nil, &MessageError{Msg: "seal-pcrs not found in pcr-banks file"}
}

// loadSealPCRsFromConfig loads seal-pcrs from the platform config.yaml
// Single source of truth: app.App.SealPCRs field
// Only searches secure locations: encrypted installer.luks or encrypted root filesystem.
// installer.luks mirrors target filesystem structure for easy copy to / on switch_root.
func loadSealPCRsFromConfig(logger interface {
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}) ([]uint, error) {
	// Single source of truth paths (installer.luks mirrors target filesystem)
	configPaths := []string{
		filepath.Join(installerMountPoint, "etc", "trusted-platform", "config.yaml"),
		"/etc/trusted-platform/config.yaml",
	}

	for _, path := range configPaths {
		logger.Debug("Checking config path", "path", path)
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Debug("Cannot read config", "path", path, "error", err)
			continue
		}

		logger.Debug("Config file found", "path", path, "size", len(data))

		var cfg bootconfig.BootConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			logger.Warn("Failed to parse config", "path", path, "error", err)
			continue
		}

		logger.Debug("Config parsed", "path", path, "seal_pcrs", cfg.SealPCRs)

		if len(cfg.SealPCRs) > 0 {
			logger.Info("Loaded seal-pcrs from config", "path", path, "pcrs", cfg.SealPCRs)
			return cfg.SealPCRs, nil
		}

		// seal-pcrs field is empty - log the actual file content for debugging
		logger.Warn("Config file exists but seal-pcrs is empty/missing",
			"path", path,
			"parsed_seal_pcrs", cfg.SealPCRs,
			"file_size", len(data))
	}

	return nil, &MessageError{Msg: fmt.Sprintf("seal-pcrs not found in config.yaml. Add 'seal-pcrs: [7, 9]' to your config. Searched: %v", configPaths)}
}

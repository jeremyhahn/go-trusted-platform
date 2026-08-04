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

// Package firstboot provides CLI commands for first-boot TPM sealing operations.
// This command runs AFTER switch_root when the real filesystem is mounted,
// and seals LUKS keys to the TPM for subsequent automatic boot unlocking.
package firstboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	googleLogger "github.com/google/logger"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/firstboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	firstbootLuksDevice    string
	firstbootTPMAutoUnseal bool
	firstbootTPMOnly       bool
	firstbootSwtpmStateDir string
	firstbootEFIMountPoint string
	firstbootPCRSelection  []uint
	firstbootConfig        string
	firstbootFIPS          bool
	firstbootVerbose       bool
	firstbootDebug         bool
	firstbootPlatformDir   string
	firstbootConfigDir     string
	firstbootLogDir        string
	firstbootCADir         string
	firstbootTPMPath       string
	firstbootXKMSDir       string
)

// NewCommand creates the firstboot command for platformctl
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firstboot",
		Short: "First-boot TPM PCR sealing operations",
		Long: `Perform first-boot TPM PCR sealing after system installation.

This command runs after switch_root when the real filesystem is mounted.
It reads the LUKS key from the installer container (or plain file for legacy)
and seals it to the TPM with PCR policy for secure automatic boot unlocking.

The command performs:
  - Platform TPM provisioning (EK, SRK, IAK, IDevID)
  - LUKS key extraction from encrypted installer container
  - TPM sealing with PCR policy for boot integrity verification
  - Cleanup of plain key files for security
  - Installation and enablement of platformd service

After firstboot completes successfully, the system can boot automatically
with TPM-sealed LUKS keys that verify boot integrity via PCR values.

This command is typically called by a systemd service or OpenRC init script
after the first boot following installation.`,
		Example: `  # Run firstboot with automatic LUKS device detection
  platformctl firstboot

  # Run firstboot with explicit LUKS device
  platformctl firstboot --luks-device /dev/sda2

  # Run firstboot with TPM-only mode (removes password keyslot)
  platformctl firstboot --luks-device /dev/sda2 --tpm-only

  # Run firstboot with custom PCR selection
  platformctl firstboot --pcrs 0,1,2,3,7`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirstboot(cmd.Context())
		},
	}

	// Flags
	cmd.Flags().StringVar(&firstbootLuksDevice, "luks-device", "", "LUKS device path (auto-detect if not specified)")
	cmd.Flags().BoolVar(&firstbootTPMAutoUnseal, "tpm-auto-unseal", true, "Enable TPM auto-unseal (seal key to TPM)")
	cmd.Flags().BoolVar(&firstbootTPMOnly, "tpm-only", false, "Remove password keyslot after sealing (TPM-only unlock)")
	cmd.Flags().StringVar(&firstbootSwtpmStateDir, "swtpm-state-dir", "/var/lib/swtpm", "swtpm state directory for software TPM")
	cmd.Flags().StringVar(&firstbootEFIMountPoint, "efi-mount", "/boot/efi", "EFI partition mount point")
	cmd.Flags().UintSliceVar(&firstbootPCRSelection, "pcrs", nil, "PCR registers to seal against (reads from config if not specified)")
	cmd.Flags().StringVar(&firstbootConfig, "config", "", "Platform configuration file")
	cmd.Flags().BoolVar(&firstbootFIPS, "fips", false, "Enable FIPS mode")
	cmd.Flags().BoolVarP(&firstbootVerbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&firstbootDebug, "debug", false, "Enable debug logging")
	cmd.Flags().StringVar(&firstbootPlatformDir, "platform-dir", "/var/lib/trusted-platform", "Platform data directory")
	cmd.Flags().StringVar(&firstbootConfigDir, "config-dir", "/etc/trusted-platform", "Configuration directory")
	cmd.Flags().StringVar(&firstbootLogDir, "log-dir", "/var/log/trusted-platform", "Log directory")
	cmd.Flags().StringVar(&firstbootCADir, "ca-dir", "", "CA data directory (defaults to platform-dir/ca)")
	cmd.Flags().StringVar(&firstbootTPMPath, "tpm-path", "/dev/tpmrm0", "TPM device path")
	cmd.Flags().StringVar(&firstbootXKMSDir, "xkms-dir", "/etc/trusted-platform/xkms", "XKMS storage directory")

	return cmd
}

func runFirstboot(ctx context.Context) error {
	fmt.Println("Starting firstboot TPM sealing workflow...")

	// Initialize logger
	logger := initializeLogger(firstbootVerbose, firstbootDebug)

	startTime := time.Now()
	logger.Info("Starting platformctl firstboot",
		"tpm_path", firstbootTPMPath,
		"efi_mount", firstbootEFIMountPoint)

	// Build firstboot configuration
	config := firstboot.DefaultConfig()
	config.LuksDevice = firstbootLuksDevice
	config.TPMAutoUnseal = firstbootTPMAutoUnseal
	config.LuksTPMOnly = firstbootTPMOnly
	config.SwtpmStateDir = firstbootSwtpmStateDir
	config.EFIMountPoint = firstbootEFIMountPoint
	config.Debug = firstbootDebug

	// Handle PCR selection - try command line first, then config file
	if len(firstbootPCRSelection) > 0 {
		config.PCRSelection = firstbootPCRSelection
		logger.Info("Using PCRs from command line", "pcrs", config.PCRSelection)
	} else {
		// Try to load PCRs from config file
		pcrs, err := loadPCRsFromConfig(logger)
		if err != nil {
			logger.Warn("Failed to load PCRs from config", "error", err)
		} else if len(pcrs) > 0 {
			config.PCRSelection = pcrs
			logger.Info("Loaded PCRs from config", "pcrs", config.PCRSelection)
		}
	}

	if len(config.PCRSelection) == 0 {
		return &MessageError{Msg: "no PCR selection provided - use --pcrs flag or configure seal-pcrs in config.yaml"}
	}

	// Create the firstboot executor
	executor, err := firstboot.NewExecutor(ctx, config, logger)
	if err != nil {
		return &WrappedError{Msg: "failed to create firstboot executor", Err: err}
	}
	defer executor.Close()

	// Initialize LUKS handler for the strategy
	luksConfig := storageluks.DefaultConfig()
	googleLog := googleLogger.Init("luks", false, false, os.Stdout)

	luksHandler, err := storageluks.NewCryptsetupHandler(luksConfig, googleLog)
	if err != nil {
		return &WrappedError{Msg: "failed to initialize LUKS handler", Err: err}
	}

	// Create and run the firstboot seal strategy
	strategy := firstboot.NewFirstbootSealStrategy(executor, luksHandler, logger)

	// Check if firstboot is needed
	volume := &storageluks.VolumeConfig{
		DevicePath:   firstbootLuksDevice,
		MappingName:  "cryptroot",
		PCRSelection: config.PCRSelection,
		PCRBanks:     []string{"sha256"},
	}

	if !strategy.CanUnlock(ctx, volume) {
		logger.Info("Firstboot sealing not needed (already sealed or no installer data)")
		fmt.Println("Firstboot sealing not needed - system already configured")
		return nil
	}

	// Run the firstboot workflow
	logger.Info("Running firstboot TPM sealing...")
	if err := strategy.Unlock(ctx, volume); err != nil {
		// SECURITY: ErrSealingFallbackUsed means LUKS was unlocked with a
		// plain key (so the system can boot to a recovery shell) but the
		// TPM sealing did NOT complete. The pcr-banks file was not
		// written and platformd will fail at startup with TPM_RC_POLICY_FAIL.
		// Surface this as a non-zero exit so the OpenRC tpm-firstboot-seal
		// service knows NOT to mark itself "started" and re-runs us on
		// the next boot. The previous behaviour swallowed this failure
		// and reported "completed successfully" while platformd silently
		// crashed at boot — that's the bug that masked the real failure
		// during the lab-node-2 deployment debug session (2026-04-07).
		if errors.Is(err, firstboot.ErrSealingFallbackUsed) {
			elapsed := time.Since(startTime)
			logger.Errorf("FIRSTBOOT INCOMPLETE: sealing fallback used: duration=%s error=%v",
				elapsed, err)
			fmt.Fprintf(os.Stderr,
				"FIRSTBOOT INCOMPLETE after %s — TPM sealing did not complete.\n"+
					"LUKS is unlocked via plain key, but pcr-banks was NOT written and\n"+
					"platformd will fail at startup with TPM_RC_POLICY_FAIL.\n"+
					"Most common cause: stale TPM owner-hierarchy auth from a previous\n"+
					"failed run. Try `platformctl tpm clear --force --confirm` (PPI clear,\n"+
					"requires reboot) then re-run firstboot.\n",
				elapsed)
			return err
		}
		return &WrappedError{Msg: "firstboot failed", Err: err}
	}

	elapsed := time.Since(startTime)
	logger.Info("Firstboot completed successfully", "duration", elapsed)
	fmt.Printf("Firstboot completed successfully in %s\n", elapsed)

	return nil
}

// loadPCRsFromConfig attempts to load PCR selection from config file
func loadPCRsFromConfig(logger *logging.Logger) ([]uint, error) {
	configPaths := []string{
		firstbootConfig,
		filepath.Join(firstbootConfigDir, "config.yaml"),
		"/etc/trusted-platform/config.yaml",
		"/boot/efi/tpm2/install-config.yaml",
	}

	var configPath string
	for _, path := range configPaths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		return nil, &MessageError{Msg: "no config file found"}
	}

	v := viper.New()
	v.SetConfigFile(configPath)

	if err := v.ReadInConfig(); err != nil {
		return nil, &WrappedError{Msg: "failed to read config", Err: err}
	}

	// Try seal-pcrs at root level
	if v.IsSet("seal-pcrs") {
		return convertToUintSlice(v.GetIntSlice("seal-pcrs")), nil
	}

	// Try tpm.seal-pcrs
	if v.IsSet("tpm.seal-pcrs") {
		return convertToUintSlice(v.GetIntSlice("tpm.seal-pcrs")), nil
	}

	// Try installer.seal-pcrs
	if v.IsSet("installer.seal-pcrs") {
		return convertToUintSlice(v.GetIntSlice("installer.seal-pcrs")), nil
	}

	return nil, &MessageError{Msg: "seal-pcrs not found in config"}
}

// convertToUintSlice converts int slice to uint slice
func convertToUintSlice(ints []int) []uint {
	result := make([]uint, len(ints))
	for i, v := range ints {
		result[i] = uint(v)
	}
	return result
}

// initializeLogger creates a logger for firstboot
func initializeLogger(verbose, debug bool) *logging.Logger {
	var level slog.Level
	if debug {
		level = slog.LevelDebug
	} else if verbose {
		level = slog.LevelInfo
	} else {
		level = slog.LevelWarn
	}
	return logging.NewLogger(level, nil)
}

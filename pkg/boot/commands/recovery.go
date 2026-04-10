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
	"time"

	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/spf13/cobra"
)

var (
	recoveryResealPCRs  bool
	recoveryFIDO2       bool
	recoveryInteractive bool
	recoveryDevice      string
	recoveryMappingName string
	recoveryTPMPath     string
	recoveryEFIPath     string
	recoveryXKMSDir     string
	recoveryVerbose     bool
	recoveryDebug       bool
	recoveryFIPS        bool
)

// RecoveryCmd provides the recovery command for platform-initrd
var RecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Recovery mode - Unlock with fallback and reseal keys",
	Long: `Recovery mode provides disaster recovery capabilities including:
  - Manual unlock with password or FIDO2
  - PCR reseal after kernel updates
  - Key slot management and recovery
  - System integrity verification
  - Emergency key rotation

This command is used when automatic unlock fails or after system changes.`,
	Example: `  # Enter recovery mode
  platform-initrd recovery --device /dev/sda2

  # Recovery with automatic reseal
  platform-initrd recovery --device /dev/sda2 --reseal-pcrs

  # Interactive recovery mode
  platform-initrd recovery --device /dev/sda2 --interactive`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRecovery(cmd.Context())
	},
}

func init() {
	RecoveryCmd.Flags().BoolVar(&recoveryResealPCRs, "reseal-pcrs", true, "Automatically reseal to current PCRs after unlock")
	RecoveryCmd.Flags().BoolVar(&recoveryFIDO2, "fido2", true, "Enable FIDO2 authenticator unlock")
	RecoveryCmd.Flags().BoolVar(&recoveryInteractive, "interactive", false, "Interactive recovery menu")
	RecoveryCmd.Flags().StringVarP(&recoveryDevice, "device", "d", "", "LUKS device path (e.g., /dev/sda2)")
	RecoveryCmd.Flags().StringVarP(&recoveryMappingName, "name", "n", "cryptroot", "LUKS mapping name")
	RecoveryCmd.Flags().StringVar(&recoveryTPMPath, "tpm-path", "/dev/tpmrm0", "TPM device path")
	RecoveryCmd.Flags().StringVar(&recoveryEFIPath, "efi-path", "/boot/efi", "EFI partition mount point")
	RecoveryCmd.Flags().StringVar(&recoveryXKMSDir, "xkms-dir", "/etc/trusted-platform/xkms", "XKMS storage directory")
	RecoveryCmd.Flags().BoolVarP(&recoveryVerbose, "verbose", "v", false, "Enable verbose logging")
	RecoveryCmd.Flags().BoolVar(&recoveryDebug, "debug", false, "Enable debug logging (implies verbose)")
	RecoveryCmd.Flags().BoolVar(&recoveryFIPS, "fips", false, "Enable FIPS mode (use PBKDF2 instead of Argon2id)")

	RecoveryCmd.MarkFlagRequired("device")
}

func runRecovery(ctx context.Context) error {
	// Validate required flags
	if recoveryDevice == "" {
		return fmt.Errorf("--device flag is required")
	}

	// Initialize logger
	logger, err := InitializeLogger("recovery", recoveryVerbose, recoveryDebug)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	startTime := time.Now()
	logger.Info("Starting platform-initrd recovery mode",
		"device", recoveryDevice,
		"mapping", recoveryMappingName,
		"version", Version)

	// Show recovery banner
	fmt.Println("=== Platform-Initrd Recovery Mode ===")
	fmt.Println()
	fmt.Println("This mode allows you to recover access to your encrypted system.")
	fmt.Println()

	// Create initrd configuration
	config := &platforminitrd.Config{
		Mode:           platforminitrd.ModeRecovery,
		RootDevice:     recoveryDevice,
		BootDevice:     recoveryEFIPath,
		XKMSPath:       recoveryXKMSDir,
		PCRBanks:       []string{"sha256"},
		PCRSelection:   []uint{0, 1, 2, 3, 7},
		UnlockTimeout:  300, // Longer timeout for recovery
		RetryCount:     5,
		EnableAuditLog: true,
		AuditLogPath:   "/var/log/platformd/audit.log",
		FIPS:           recoveryFIPS,
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create platform manager
	manager, err := CreateManager(ctx, logger, config, recoveryTPMPath)
	if err != nil {
		logger.Error(fmt.Errorf("failed to create manager: %w", err))
		return fmt.Errorf("failed to create manager: %w", err)
	}
	defer manager.Close()

	// Initialize the platform
	logger.Info("Initializing platform components")
	if err := manager.Initialize(ctx); err != nil {
		logger.Error(fmt.Errorf("failed to initialize platform: %w", err))
		return fmt.Errorf("failed to initialize platform: %w", err)
	}

	// Show interactive menu if requested
	if recoveryInteractive {
		logger.Info("Starting interactive recovery mode")
		if err := manager.InteractiveRecovery(ctx); err != nil {
			logger.Error(fmt.Errorf("interactive recovery failed: %w", err))
			return fmt.Errorf("interactive recovery failed: %w", err)
		}
		return nil
	}

	// Run recovery sequence
	logger.Info("Executing recovery unlock sequence")
	if err := manager.Recovery(ctx); err != nil {
		logger.Error(fmt.Errorf("recovery unlock failed: %w", err))
		return fmt.Errorf("recovery failed: %w", err)
	}

	duration := time.Since(startTime)
	logger.Info("Recovery completed successfully",
		"device", recoveryDevice,
		"mapping", recoveryMappingName,
		"duration", duration)

	fmt.Printf("\nRecovery completed successfully (%v)\n", duration)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Verify system integrity")
	fmt.Println("  2. Check logs: /var/log/platformd/recovery.log")
	fmt.Println("  3. Reboot to test automatic unlock")

	return nil
}

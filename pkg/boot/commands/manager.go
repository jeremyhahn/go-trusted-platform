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
	"log/slog"
	"os"
	"strings"
	"time"

	googleLogger "github.com/google/logger"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"gopkg.in/yaml.v3"
)

// PlatformConfig represents the platform configuration file structure
// This is a minimal subset of the full platformd config used for TPM initialization
type PlatformConfig struct {
	TPM *xkmssdk.TPMConfig `yaml:"tpm"`
}

// srkHandleHex safely formats a PlatformSRK handle as hex, returning "none"
// if the config is nil (e.g., config YAML lacks platform-srk section).
func srkHandleHex(srk *xkmssdk.PlatformSRKConfig) string {
	if srk == nil {
		return "none"
	}
	return fmt.Sprintf("0x%08x", srk.SRKHandle)
}

// ssrkHandleHex safely formats an SSRK handle as hex, returning "none"
// if the config is nil.
func ssrkHandleHex(srk *xkmssdk.SRKConfig) string {
	if srk == nil {
		return "none"
	}
	return fmt.Sprintf("0x%08x", srk.Handle)
}

// CreateManager creates a new initrd manager with all components initialized
func CreateManager(ctx context.Context, logger *logging.Logger, config *platforminitrd.Config, tpmDevicePath string) (platforminitrd.Manager, error) {
	// 1. Initialize TPM2 module
	tpmDevice := tpmDevicePath

	// Debug: Log input parameter
	logger.Info("createManager: input tpmDevicePath", "path", tpmDevicePath)

	// If no explicit TPM path was provided, try to detect it
	if tpmDevice == "" || tpmDevice == "/dev/tpmrm0" {
		if tpmPath := os.Getenv("TPM2TOOLS_TCTI"); tpmPath != "" {
			// Support TPM2TOOLS_TCTI environment variable
			// Common formats:
			//   - device:/dev/tpm0        (standard device)
			//   - swtpm:host=localhost,port=2321  (software TPM)
			//   - /dev/tpmrm0             (direct device path)

			logger.Info("createManager: TPM2TOOLS_TCTI detected", "tcti", tpmPath)

			// Parse the TCTI format
			if after, found := strings.CutPrefix(tpmPath, "device:"); found {
				// Strip "device:" prefix - use the device path directly
				logger.Info("createManager: Stripped 'device:' prefix", "result", after)
				tpmDevice = after
			} else if strings.HasPrefix(tpmPath, "swtpm:") {
				// Keep swtpm format as-is for socket-based TPM
				logger.Info("createManager: Using swtpm format as-is")
				tpmDevice = tpmPath
			} else {
				// Assume it's a direct device path
				logger.Info("createManager: Using TPM2TOOLS_TCTI as direct path")
				tpmDevice = tpmPath
			}
		} else if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			logger.Info("createManager: No TPM2TOOLS_TCTI, found /dev/tpmrm0")
			tpmDevice = "/dev/tpmrm0"
		} else if _, err := os.Stat("/dev/tpm0"); err == nil {
			logger.Info("createManager: No TPM2TOOLS_TCTI, found /dev/tpm0")
			tpmDevice = "/dev/tpm0"
		} else {
			return nil, fmt.Errorf("no TPM device found at /dev/tpmrm0 or /dev/tpm0")
		}
	} else {
		logger.Info("createManager: Using explicit tpmDevice", "device", tpmDevice)
	}

	logger.Info("createManager: Final TPM device path", "device", tpmDevice)

	// Load TPM configuration from available sources
	// Priority order:
	// 1. pcr-banks file on EFI (BOOT mode - contains platform config)
	// 2. Config file in installer mount (FIRSTBOOT mode)
	// 3. Config file on root (after decryption)
	// NO FALLBACK TO DEFAULTS - we must have explicit config
	var loadedTPMConfig *xkmssdk.TPMConfig

	// FIRST: Try pcr-banks file on EFI (for BOOT mode after firstboot)
	// This file contains platform config written during firstboot sealing
	pcrBanksPath := "/boot/efi/tpm2/pcr-banks"
	if pcrBanksConfig := parsePCRBanksConfig(pcrBanksPath, logger); pcrBanksConfig != nil {
		loadedTPMConfig = pcrBanksConfig
		logger.Info("Loaded TPM config from pcr-banks",
			"path", pcrBanksPath,
			"platform_pcr", loadedTPMConfig.PlatformPCR,
			"keystore_srk_handle", srkHandleHex(loadedTPMConfig.PlatformSRK))
	}

	// SECOND: Try config files (for FIRSTBOOT mode with installer, or after decryption)
	if loadedTPMConfig == nil {
		configPaths := []string{
			"/mnt/installer/etc/trusted-platform/config.yaml", // Installer mount (firstboot)
			"/etc/trusted-platform/config.yaml",               // Encrypted root (after decryption)
			"/etc/trusted-platform/platformd.yaml",
			"/boot/efi/configs/platformd.yaml",
			"/media/cdrom/configs/platformd.yaml",
		}

		for _, configPath := range configPaths {
			if data, err := os.ReadFile(configPath); err == nil {
				var platformCfg PlatformConfig
				if err := yaml.Unmarshal(data, &platformCfg); err == nil && platformCfg.TPM != nil {
					loadedTPMConfig = platformCfg.TPM
					logger.Info("Loaded platform config from file",
						"path", configPath,
						"platform_pcr", loadedTPMConfig.PlatformPCR,
						"keystore_srk_handle", srkHandleHex(loadedTPMConfig.PlatformSRK))
					break
				}
			}
		}
	}

	// NO FALLBACK - config MUST exist
	if loadedTPMConfig == nil {
		return nil, fmt.Errorf("FATAL: no TPM configuration found. Required: pcr-banks at /boot/efi/tpm2/pcr-banks OR config at /mnt/installer/etc/trusted-platform/config.yaml (firstboot) OR /etc/trusted-platform/config.yaml (after decryption). Installation is broken - reinstall required")
	}

	// Use loaded config with device path override
	tpmConfig := loadedTPMConfig
	tpmConfig.Device = tpmDevice
	tpmConfig.UseSimulator = false
	tpmConfig.UseEntropy = false
	tpmConfig.FileIntegrity = []string{}
	logger.Info("Using TPM config",
		"platform_pcr", tpmConfig.PlatformPCR,
		"platform_pcr_bank", tpmConfig.PlatformPCRBank,
		"keystore_srk_handle", srkHandleHex(tpmConfig.PlatformSRK),
		"ssrk_handle", ssrkHandleHex(tpmConfig.SSRK))

	xkmsLogger := slog.Default()
	tpmParams := &xkmssdk.TPMParams{
		Config:       tpmConfig,
		Logger:       xkmsLogger,
		DebugSecrets: false,
		Backend:      nil, // Will be created by TPM2
		BlobStore:    nil, // Optional
		CertStore:    nil, // Optional
		SignerStore:  nil, // Optional
	}

	// Retry TPM initialization with delays to allow TPM to fully initialize
	// In initramfs environment, TPM device may exist but not be ready yet
	var tpmModule xkmssdk.TrustedPlatformModule
	var err error
	maxRetries := 5
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		tpmModule, err = xkmssdk.NewTPM2(tpmParams)
		if err == nil || err == xkmssdk.ErrTPMNotInitialized {
			// Success! The TPM is open.
			// ErrNotInitialized just means it hasn't been provisioned yet,
			// which is fine - we'll handle that gracefully during boot
			if err == xkmssdk.ErrTPMNotInitialized {
				logger.Info("TPM opened successfully (not yet provisioned)", "attempt", i+1)
			} else {
				logger.Info("TPM initialized successfully", "attempt", i+1)
			}
			break
		}

		if i < maxRetries-1 {
			logger.Warn("TPM initialization failed, retrying",
				"attempt", i+1,
				"max_retries", maxRetries,
				"error", err,
				"retry_delay", retryDelay)
			time.Sleep(retryDelay)
		}
	}

	// Only fail if we couldn't open the TPM at all (not including ErrNotInitialized)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		return nil, fmt.Errorf("failed to initialize TPM2 after %d attempts: %w", maxRetries, err)
	}

	// 2. Initialize LUKS handler
	luksConfig := storageluks.DefaultConfig()

	// Convert logging.Logger to google/logger for LUKS
	googleLog := googleLogger.Init("luks", false, false, os.Stdout)
	defer googleLog.Close()

	luksHandler, err := storageluks.NewCryptsetupHandler(luksConfig, googleLog)
	if err != nil {
		tpmModule.Close()
		return nil, fmt.Errorf("failed to initialize LUKS handler: %w", err)
	}

	// 3. Create minimal KeyBackend for TPM unsealing
	// The TPM needs a KeyBackend to read sealed keys from disk
	// We only need the file backend, not the full XKMS infrastructure
	storageBackend, err := xkmssdk.NewFileStorageBackend(config.XKMSPath)
	if err != nil {
		tpmModule.Close()
		return nil, fmt.Errorf("failed to create file storage backend: %w", err)
	}
	backendInstance := xkmssdk.NewFileBackend(xkmsLogger, storageBackend)

	// 4. Create Platform Bundle (minimal dependencies for boot)
	// No XKMS, no FIDO2 - just TPM + LUKS + backend for unsealing
	platformBundle := &platforminitrd.Platform{
		TPM:     tpmModule,
		LUKS:    luksHandler,
		FIDO2:   nil,             // Not needed for boot
		XKMS:    nil,             // Not needed for boot
		Backend: backendInstance, // Direct backend access for TPM unsealing
		Config:  config,
	}

	// 6. Create Manager
	manager, err := platforminitrd.NewManager(platformBundle, logger)
	if err != nil {
		tpmModule.Close()
		return nil, fmt.Errorf("failed to create initrd manager: %w", err)
	}

	return manager, nil
}

// InitializeLogger creates and configures the logger
func InitializeLogger(mode string, verbose, debug bool) (*logging.Logger, error) {
	var level slog.Level
	if debug {
		level = slog.LevelDebug
	} else if verbose {
		level = slog.LevelInfo
	} else {
		level = slog.LevelWarn
	}

	// In boot, install, and firstboot modes (early environment), ONLY use stderr to avoid blocking
	// File logging can block and prevents output on serial console during installation
	// Use plain text format for better readability in the initrd environment
	if mode == "boot" || mode == "install" || mode == "firstboot" {
		return logging.NewLogger(level, nil), nil // true = use text format
	}

	// For other modes (recovery, etc.), use file logging with JSON format
	// Create log directory
	logDir := "/var/log/platformd"
	os.MkdirAll(logDir, 0755)

	// Create log file
	logFile, err := os.OpenFile(
		fmt.Sprintf("%s/%s.log", logDir, mode),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		// Fallback to stdout only with text format
		return logging.NewLogger(level, nil), nil
	}

	return logging.NewLogger(level, logFile), nil
}

// parsePCRBanksConfig parses the pcr-banks file from EFI partition
// All values MUST come from the installer config (single source of truth)
// NO hardcoded defaults - if required values are missing, returns nil
//
// Required format (key=value per line):
//
//	seal-pcrs=0,1,2,3,7
//	platform-pcr=23
//	platform-pcr-bank=sha256
//	golden-pcrs=0,7,9,10
//	keystore-srk-handle=0x81000002
//	ssrk-handle=0x81000001
//
// Returns nil if file doesn't exist or is missing required values
func parsePCRBanksConfig(path string, logger *logging.Logger) *xkmssdk.TPMConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	// Must be key=value format - old format is no longer supported
	if !strings.Contains(content, "=") {
		logger.Warn("pcr-banks file is in old format - reinstall required")
		return nil
	}

	// Parse key=value format
	values := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse required values - NO defaults
	var platformPCR uint
	if platformPCRStr, ok := values["platform-pcr"]; ok {
		if _, err := fmt.Sscanf(platformPCRStr, "%d", &platformPCR); err != nil {
			logger.Warn("pcr-banks: invalid platform-pcr value", "value", platformPCRStr)
			return nil
		}
	} else {
		logger.Warn("pcr-banks: missing required platform-pcr")
		return nil
	}

	platformPCRBank, ok := values["platform-pcr-bank"]
	if !ok || platformPCRBank == "" {
		logger.Warn("pcr-banks: missing required platform-pcr-bank")
		return nil
	}

	var keystoreSRKHandle uint32
	if handleStr, ok := values["keystore-srk-handle"]; ok {
		if _, err := fmt.Sscanf(handleStr, "0x%x", &keystoreSRKHandle); err != nil {
			if _, err := fmt.Sscanf(handleStr, "%d", &keystoreSRKHandle); err != nil {
				logger.Warn("pcr-banks: invalid keystore-srk-handle", "value", handleStr)
				return nil
			}
		}
	} else {
		logger.Warn("pcr-banks: missing required keystore-srk-handle")
		return nil
	}

	var ssrkHandle uint32
	if handleStr, ok := values["ssrk-handle"]; ok {
		if _, err := fmt.Sscanf(handleStr, "0x%x", &ssrkHandle); err != nil {
			if _, err := fmt.Sscanf(handleStr, "%d", &ssrkHandle); err != nil {
				logger.Warn("pcr-banks: invalid ssrk-handle", "value", handleStr)
				return nil
			}
		}
	} else {
		logger.Warn("pcr-banks: missing required ssrk-handle")
		return nil
	}

	// Parse golden-pcrs (can be empty, meaning no PCR-based golden measurement)
	var goldenPCRs []uint
	if goldenPCRsStr, ok := values["golden-pcrs"]; ok && goldenPCRsStr != "" {
		for _, pcrStr := range strings.Split(goldenPCRsStr, ",") {
			pcrStr = strings.TrimSpace(pcrStr)
			if pcrStr == "" {
				continue
			}
			var pcr uint
			if _, err := fmt.Sscanf(pcrStr, "%d", &pcr); err == nil {
				goldenPCRs = append(goldenPCRs, pcr)
			}
		}
	}

	logger.Info("Parsed pcr-banks from installer config",
		"platform_pcr", platformPCR,
		"platform_pcr_bank", platformPCRBank,
		"golden_pcrs", goldenPCRs,
		"keystore_srk_handle", fmt.Sprintf("0x%08x", keystoreSRKHandle),
		"ssrk_handle", fmt.Sprintf("0x%08x", ssrkHandle))

	// Create TPM config with values from pcr-banks (which came from installer config)
	defaultCfg := xkmssdk.DefaultTPMConfig
	return &xkmssdk.TPMConfig{
		Hash:            defaultCfg.Hash,
		EK:              defaultCfg.EK,
		IAK:             defaultCfg.IAK,
		IDevID:          defaultCfg.IDevID,
		PlatformPCR:     platformPCR,
		PlatformPCRBank: platformPCRBank,
		GoldenPCRs:      goldenPCRs,
		PlatformSRK: &xkmssdk.PlatformSRKConfig{
			SRKHandle:      keystoreSRKHandle,
			PlatformPolicy: true,
		},
		SSRK: &xkmssdk.SRKConfig{
			Handle: ssrkHandle,
		},
	}
}

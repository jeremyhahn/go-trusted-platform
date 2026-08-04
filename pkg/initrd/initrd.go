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

package initrd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// initrdManager implements the Manager interface
type initrdManager struct {
	platform *Platform
	chain    *StrategyChain
	logger   *logging.Logger
}

// NewManager creates a new initrd manager
func NewManager(platform *Platform, logger *logging.Logger) (Manager, error) {
	if platform == nil {
		return nil, &MessageError{Msg: "platform is required"}
	}

	if logger == nil {
		return nil, &MessageError{Msg: "logger is required"}
	}

	if err := platform.Config.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid platform config", Err: err}
	}

	manager := &initrdManager{
		platform: platform,
		chain:    NewStrategyChain(logger),
		logger:   logger,
	}

	// Register default strategies based on configuration
	manager.registerDefaultStrategies()

	logger.Info("NewManager: About to return manager")
	return manager, nil
}

// Initialize prepares the boot environment
func (m *initrdManager) Initialize(ctx context.Context) error {
	m.logger.Info("Initializing boot environment")

	// Validate configuration
	if err := m.platform.Config.Validate(); err != nil {
		return &WrappedError{Msg: "invalid configuration", Err: err}
	}

	// Check that required devices exist
	if err := m.validateDevices(); err != nil {
		return &WrappedError{Msg: "device validation failed", Err: err}
	}

	m.logger.Info("Boot environment initialized")
	return nil
}

// DetectMode determines the current boot mode
func (m *initrdManager) DetectMode(ctx context.Context) (BootMode, error) {
	m.logger.Info("Detecting boot mode")

	// Check if mode is explicitly set in config
	if m.platform.Config.Mode != 0 {
		m.logger.Info("Using configured mode", "mode", m.platform.Config.Mode)
		return m.platform.Config.Mode, nil
	}

	// Auto-detect mode based on environment
	// Check for install flag
	if _, err := os.Stat("/run/initrd-install"); err == nil {
		m.logger.Info("Detected mode: install")
		return ModeInstall, nil
	}

	// Check for recovery flag
	if _, err := os.Stat("/run/initrd-recovery"); err == nil {
		m.logger.Info("Detected mode: recovery")
		return ModeRecovery, nil
	}

	// Check kernel command line for mode hints
	mode, err := m.detectModeFromCmdline()
	if err == nil && mode != ModeBoot {
		return mode, nil
	}

	// Default to normal boot
	m.logger.Info("Detected mode: boot")
	return ModeBoot, nil
}

// RegisterStrategy registers an unlock strategy.
// Nil strategies are ignored to support conditional compilation (minimal builds).
func (m *initrdManager) RegisterStrategy(strategy UnlockStrategy) {
	if strategy == nil {
		return
	}
	m.logger.Info("Registering unlock strategy",
		"name", strategy.Name(),
		"priority", strategy.Priority())
	m.chain.Add(strategy)
}

// UnlockVolumes attempts to unlock all configured volumes
func (m *initrdManager) UnlockVolumes(ctx context.Context) error {
	m.logger.Info("Unlocking volumes")

	volume, err := m.buildVolumeConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build volume config", Err: err}
	}

	err = m.chain.Execute(ctx, volume)
	if err != nil {
		return &WrappedError{Msg: "failed to unlock volumes", Err: err}
	}

	m.logger.Info("All volumes unlocked successfully")
	return nil
}

// Close cleans up resources
func (m *initrdManager) Close() error {
	m.logger.Info("Closing initrd manager")

	// Close TPM
	if m.platform.TPM != nil {
		if err := m.platform.TPM.Close(); err != nil {
			m.logger.Error(err, "context", "Failed to close TPM")
		}
	}

	// Close FIDO2 handler if present
	if m.platform.FIDO2 != nil {
		if err := m.platform.FIDO2.Close(); err != nil {
			m.logger.Error(err, "context", "Failed to close FIDO2 handler")
		}
	}

	return nil
}

// registerDefaultStrategies registers the default unlock strategies
func (m *initrdManager) registerDefaultStrategies() {
	m.logger.Info("Registering default unlock strategies")

	// Register Keyfile strategy for first boot unlock (before TPM provisioning)
	// This strategy activates when the encrypted installer container is mounted
	// at /mnt/installer and contains luks-key.bin. After firstboot runs
	// (platformctl firstboot), the container is securely wiped and TPM-based
	// strategies take over.
	// SECURITY: The LUKS key is NEVER stored in plaintext on the EFI partition
	m.RegisterStrategy(NewKeyfileStrategy(m.platform, m.logger))

	// Register strategies based on configured fallback methods
	for _, method := range m.platform.Config.FallbackMethods {
		switch method {
		case luks.UnlockTPMPCR:
			m.RegisterStrategy(NewTPMPCRStrategy(m.platform, m.logger))
		case luks.UnlockTPMUpgrade:
			m.RegisterStrategy(NewTPMUpgradeStrategy(m.platform, m.logger))
		case luks.UnlockFIDO2:
			if m.platform.FIDO2 != nil {
				m.RegisterStrategy(NewFIDO2Strategy(m.platform, m.logger))
			} else {
				m.logger.Warn("FIDO2 method configured but handler not available")
			}
		case luks.UnlockPassword:
			m.RegisterStrategy(NewPasswordStrategy(m.platform, m.logger))
		default:
			m.logger.Warn("Unknown unlock method", "method", method)
		}
	}

	m.logger.Info("Registered unlock strategies", "count", m.chain.Count())
}

// validateDevices checks that required devices exist
func (m *initrdManager) validateDevices() error {
	// Check root device
	if _, err := os.Stat(m.platform.Config.RootDevice); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("root device %s not found", m.platform.Config.RootDevice), Err: err}
	}

	// Check boot device if configured
	if m.platform.Config.BootDevice != "" {
		if _, err := os.Stat(m.platform.Config.BootDevice); err != nil {
			m.logger.Warn("Boot device not found",
				"device", m.platform.Config.BootDevice,
				"error", err)
		}
	}

	return nil
}

// detectModeFromCmdline attempts to detect mode from kernel command line
func (m *initrdManager) detectModeFromCmdline() (BootMode, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ModeBoot, err
	}

	cmdlineStr := string(cmdline)

	// Check for mode hints in command line
	if strings.Contains(cmdlineStr, "initrd.mode=install") {
		return ModeInstall, nil
	}
	if strings.Contains(cmdlineStr, "initrd.mode=recovery") {
		return ModeRecovery, nil
	}
	if strings.Contains(cmdlineStr, "initrd.mode=maintenance") {
		return ModeMaintenance, nil
	}

	return ModeBoot, nil
}

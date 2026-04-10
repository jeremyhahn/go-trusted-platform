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
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// DefaultConfig returns a default initrd configuration
// NOTE: PCRSelection is nil - MUST be set from installer config (single source of truth)
// Validation will fail if PCRSelection is not explicitly provided
func DefaultConfig() *Config {
	return &Config{
		Mode:       ModeInstall,
		RootDevice: "/dev/sda2",
		BootDevice: "/dev/sda1",
		XKMSPath:   "/var/lib/trusted-platform/xkms",
		PCRBanks:   []string{"sha256"},
		// PCRSelection must come from installer config - no hardcoded defaults
		PCRSelection:        nil,
		UpgradePCRSelection: nil,
		UnlockTimeout:       30,
		FallbackMethods: []luks.UnlockMethod{
			luks.UnlockTPMPCR,
			luks.UnlockTPMUpgrade,
			luks.UnlockFIDO2,
			luks.UnlockPassword,
		},
		RetryCount:     3,
		EnableAuditLog: true,
		AuditLogPath:   "/var/log/initrd-unlock.log",
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	// In a real implementation, this would load from a YAML/JSON file
	// For now, return default config
	return DefaultConfig(), nil
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	// In a real implementation, this would save to a YAML/JSON file
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

// MergeConfig merges two configurations, with override taking precedence
func MergeConfig(base, override *Config) *Config {
	result := *base

	if override.Mode != 0 {
		result.Mode = override.Mode
	}
	if override.RootDevice != "" {
		result.RootDevice = override.RootDevice
	}
	if override.BootDevice != "" {
		result.BootDevice = override.BootDevice
	}
	if override.XKMSPath != "" {
		result.XKMSPath = override.XKMSPath
	}
	if len(override.PCRBanks) > 0 {
		result.PCRBanks = override.PCRBanks
	}
	if len(override.PCRSelection) > 0 {
		result.PCRSelection = override.PCRSelection
	}
	if len(override.UpgradePCRSelection) > 0 {
		result.UpgradePCRSelection = override.UpgradePCRSelection
	}
	if override.UnlockTimeout > 0 {
		result.UnlockTimeout = override.UnlockTimeout
	}
	if len(override.FallbackMethods) > 0 {
		result.FallbackMethods = override.FallbackMethods
	}
	if override.RetryCount > 0 {
		result.RetryCount = override.RetryCount
	}
	if override.AuditLogPath != "" {
		result.AuditLogPath = override.AuditLogPath
	}

	return &result
}

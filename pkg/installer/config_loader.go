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

package installer

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadInstallConfig loads and parses a YAML installation configuration file
func LoadInstallConfig(path string) (*Config, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read config file", Err: err}
	}

	// Expand environment variables in YAML content
	expanded := os.ExpandEnv(string(data))

	// Parse YAML
	var yamlConfig InstallConfig
	if err := yaml.Unmarshal([]byte(expanded), &yamlConfig); err != nil {
		return nil, &WrappedError{Msg: "failed to parse YAML config", Err: err}
	}

	// Validate version
	if yamlConfig.Version != ConfigVersion {
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported config version: %s (expected %s)", yamlConfig.Version, ConfigVersion)}
	}

	// Convert to internal Config structure
	config := &Config{
		Debug: false, // Set to false by default, can be overridden
	}

	// Convert disk configuration
	config.Disk = &DiskConfig{
		Device:           yamlConfig.Disk.Device,
		PartitionTable:   PartitionTable(yamlConfig.Disk.PartitionTable),
		EFIPartitionSize: yamlConfig.Disk.EFISize,
		RootFilesystem:   FilesystemType(yamlConfig.Disk.Filesystem),
	}

	// Set defaults for disk config
	if config.Disk.PartitionTable == "" {
		config.Disk.PartitionTable = PartitionTableGPT
	}
	if config.Disk.EFIPartitionSize == 0 {
		config.Disk.EFIPartitionSize = 538
	}
	if config.Disk.RootFilesystem == "" {
		config.Disk.RootFilesystem = FilesystemLVM
	}

	// Convert LVM configuration
	if yamlConfig.Disk.LVM != nil {
		config.Disk.LVMVolumeGroup = yamlConfig.Disk.LVM.VolumeGroup
		config.Disk.LVMLogicalVolume = yamlConfig.Disk.LVM.LogicalVolume
	} else if config.Disk.RootFilesystem == FilesystemLVM {
		// Set defaults if using LVM but no LVM config specified
		config.Disk.LVMVolumeGroup = "vg0"
		config.Disk.LVMLogicalVolume = "root"
	}

	// Convert encryption configuration
	if yamlConfig.Disk.Encryption != nil && yamlConfig.Disk.Encryption.Enabled {
		config.Disk.Encryption = &EncryptionConfig{
			Version:    "luks2",
			Cipher:     yamlConfig.Disk.Encryption.Cipher,
			KeySize:    yamlConfig.Disk.Encryption.KeySize,
			Hash:       yamlConfig.Disk.Encryption.Hash,
			PBKDF:      yamlConfig.Disk.Encryption.PBKDF,
			Password:   yamlConfig.Disk.Encryption.Password,
			Passphrase: yamlConfig.Disk.Encryption.Password,
			MappedName: yamlConfig.Disk.Encryption.MappedName,
		}

		// Set encryption defaults
		if config.Disk.Encryption.Cipher == "" {
			config.Disk.Encryption.Cipher = "aes-xts-plain64"
		}
		if config.Disk.Encryption.KeySize == 0 {
			config.Disk.Encryption.KeySize = 512
		}
		if config.Disk.Encryption.Hash == "" {
			config.Disk.Encryption.Hash = "sha256"
		}
		// PBKDF intentionally not defaulted - fips.GetKDF() in disk.go auto-detects
		// the appropriate KDF based on /proc/sys/crypto/fips_enabled
		if config.Disk.Encryption.MappedName == "" {
			config.Disk.Encryption.MappedName = "cryptroot"
		}
	}

	// Convert OS configuration
	config.OS = &OSConfig{
		OS:                 OperatingSystem(yamlConfig.OS.Name),
		Version:            yamlConfig.OS.Version,
		Architecture:       yamlConfig.OS.Architecture,
		Hostname:           yamlConfig.OS.Hostname,
		Mirror:             yamlConfig.OS.Mirror,
		RootPassword:       yamlConfig.OS.RootPassword,
		FilesystemType:     FilesystemType(yamlConfig.OS.FilesystemType),
		FIPS:               yamlConfig.OS.FIPS,
		Lockdown:           yamlConfig.OS.Lockdown,
		LockdownMode:       yamlConfig.OS.LockdownMode,
		TPMAutoUpgradeSeal: yamlConfig.OS.TPMAutoUpgradeSeal,
		PlatformdBinary:    yamlConfig.OS.PlatformdBinary,
		WebUIInstallPath:   yamlConfig.OS.WebUIInstallPath,
		Packages:           yamlConfig.OS.Packages,
		EnableFIDO2:        yamlConfig.OS.EnableFIDO2,
	}

	// Set OS defaults
	if config.OS.Architecture == "" {
		config.OS.Architecture = "x86_64"
	}
	if config.OS.Hostname == "" {
		config.OS.Hostname = "trusted-platform"
	}
	if config.OS.FilesystemType == "" {
		config.OS.FilesystemType = FilesystemLVM
	}
	if config.OS.Lockdown && config.OS.LockdownMode == "" {
		config.OS.LockdownMode = "confidentiality"
	}

	// Convert security configuration
	config.EnableTPMSealing = yamlConfig.Security.TPM.Enabled
	config.PCRs = yamlConfig.Security.TPM.SealPCRs

	// Set default PCRs if TPM enabled but no PCRs specified
	if config.EnableTPMSealing && len(config.PCRs) == 0 {
		config.PCRs = SealPCRsDefault()
	}

	// Set SecureBoot if enabled, carrying the full parsed shape (URIs + key
	// store types) through so the installer can resolve the DB/PK/KEK keys.
	if yamlConfig.Security.SecureBoot.Enabled {
		sb := SecureBootConfig(yamlConfig.Security.SecureBoot)
		sb.Enabled = true
		config.SecureBoot = &sb
	}

	// Expand XKMS references in sensitive fields
	if err := expandXKMSReferences(config); err != nil {
		return nil, &WrappedError{Msg: "failed to expand XKMS references", Err: err}
	}

	// Validate the loaded configuration
	if err := config.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid configuration", Err: err}
	}

	return config, nil
}

// expandXKMSReferences expands xkms:// references in configuration
// Format: xkms://path/to/secret
func expandXKMSReferences(config *Config) error {
	// Check disk encryption password
	if config.Disk != nil && config.Disk.Encryption != nil {
		if strings.HasPrefix(config.Disk.Encryption.Password, "xkms://") {
			path := strings.TrimPrefix(config.Disk.Encryption.Password, "xkms://")
			value, err := readFromXKMS(path)
			if err != nil {
				return &WrappedError{Msg: "failed to read disk encryption password from XKMS", Err: err}
			}
			config.Disk.Encryption.Password = value
			config.Disk.Encryption.Passphrase = value
		}
	}

	// Check OS root password
	if config.OS != nil {
		if strings.HasPrefix(config.OS.RootPassword, "xkms://") {
			path := strings.TrimPrefix(config.OS.RootPassword, "xkms://")
			value, err := readFromXKMS(path)
			if err != nil {
				return &WrappedError{Msg: "failed to read root password from XKMS", Err: err}
			}
			config.OS.RootPassword = value
		}
	}

	return nil
}

// readFromXKMS reads a secret from XKMS
// This is a placeholder implementation that reads from filesystem
// In production, this could integrate with system XKMS, vault, etc.
func readFromXKMS(path string) (string, error) {
	// For now, treat xkms:// as a file path
	// Future enhancement: integrate with actual XKMS systems
	data, err := os.ReadFile(path)
	if err != nil {
		return "", &WrappedError{Msg: "failed to read XKMS file", Err: err}
	}
	return strings.TrimSpace(string(data)), nil
}

// MergeWithDefaults merges a config with default values
func MergeWithDefaults(config *Config, defaults *Config) *Config {
	if config == nil {
		return defaults
	}
	if defaults == nil {
		return config
	}

	merged := &Config{
		Debug:            config.Debug || defaults.Debug,
		EnableTPMSealing: config.EnableTPMSealing || defaults.EnableTPMSealing,
	}

	// Merge disk config
	if config.Disk != nil {
		merged.Disk = config.Disk
	} else if defaults.Disk != nil {
		merged.Disk = defaults.Disk
	}

	// Merge OS config
	if config.OS != nil {
		merged.OS = config.OS
	} else if defaults.OS != nil {
		merged.OS = defaults.OS
	}

	// Merge UKI config
	if config.UKI != nil {
		merged.UKI = config.UKI
	} else if defaults.UKI != nil {
		merged.UKI = defaults.UKI
	}

	// Merge SecureBoot config
	if config.SecureBoot != nil {
		merged.SecureBoot = config.SecureBoot
	} else if defaults.SecureBoot != nil {
		merged.SecureBoot = defaults.SecureBoot
	}

	// Merge PCRs
	if len(config.PCRs) > 0 {
		merged.PCRs = config.PCRs
	} else if len(defaults.PCRs) > 0 {
		merged.PCRs = defaults.PCRs
	}

	return merged
}

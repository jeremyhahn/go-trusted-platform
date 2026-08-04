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
	"os"

	"gopkg.in/yaml.v2"
)

// LoadConfig loads installer configuration from a YAML file
// Note: This does NOT validate the config, as flag overrides may be applied after loading.
// Call config.Validate() after applying any flag overrides.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read config file", Err: err}
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, &WrappedError{Msg: "failed to parse config file", Err: err}
	}

	// Initialize nil pointers to prevent nil pointer dereferences when applying overrides
	if config.Disk == nil {
		config.Disk = &DiskConfig{}
	}
	if config.Disk.Encryption == nil {
		config.Disk.Encryption = &EncryptionConfig{}
	}
	if config.OS == nil {
		config.OS = &OSConfig{}
	}

	return &config, nil
}

// SaveConfig saves installer configuration to a YAML file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal config", Err: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return &WrappedError{Msg: "failed to write config file", Err: err}
	}

	return nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Disk: &DiskConfig{
			PartitionTable:   PartitionTableGPT,
			EFIPartitionSize: 538,
			RootFilesystem:   FilesystemLVM,
			LVMVolumeGroup:   "vg0",
			LVMLogicalVolume: "root",
			Encryption: &EncryptionConfig{
				Version: "luks2",
				Cipher:  "aes-xts-plain64",
				KeySize: 512,
				Hash:    "sha256",
				// PBKDF intentionally empty - fips.GetKDF() auto-detects from /proc/sys/crypto/fips_enabled
				MappedName: "cryptroot",
			},
		},
		OS: &OSConfig{
			OS:                 OSAlpine,
			Architecture:       "x86_64",
			Hostname:           "trusted-platform",
			FilesystemType:     FilesystemLVM,
			Lockdown:           true,
			LockdownMode:       "confidentiality",
			TPMAutoUpgradeSeal: true,
		},
		EnableTPMSealing: true,
	}
}

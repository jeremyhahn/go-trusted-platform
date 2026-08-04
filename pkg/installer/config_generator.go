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

	"gopkg.in/yaml.v3"
)

// ConfigVersion represents the config file format version
const ConfigVersion = "1.0"

// InstallConfig represents the YAML configuration structure
type InstallConfig struct {
	Version  string             `yaml:"version"`
	Disk     DiskYAMLConfig     `yaml:"disk"`
	OS       OSYAMLConfig       `yaml:"os"`
	Security SecurityYAMLConfig `yaml:"security"`
}

// DiskYAMLConfig represents disk configuration in YAML format
type DiskYAMLConfig struct {
	Device         string                `yaml:"device"`
	PartitionTable string                `yaml:"partition_table"`
	EFISize        int                   `yaml:"efi_size"`
	Filesystem     string                `yaml:"filesystem"`
	LVM            *LVMYAMLConfig        `yaml:"lvm,omitempty"`
	Encryption     *EncryptionYAMLConfig `yaml:"encryption,omitempty"`
}

// LVMYAMLConfig represents LVM configuration in YAML format
type LVMYAMLConfig struct {
	VolumeGroup   string `yaml:"volume_group"`
	LogicalVolume string `yaml:"logical_volume"`
}

// EncryptionYAMLConfig represents encryption configuration in YAML format
type EncryptionYAMLConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Cipher     string `yaml:"cipher"`
	KeySize    int    `yaml:"key_size"`
	Hash       string `yaml:"hash"`
	PBKDF      string `yaml:"pbkdf"`
	Password   string `yaml:"password" secret:"true"`
	MappedName string `yaml:"mapped_name"`
}

// OSYAMLConfig represents OS configuration in YAML format
type OSYAMLConfig struct {
	Name               string   `yaml:"name"`
	Version            string   `yaml:"version"`
	Architecture       string   `yaml:"architecture"`
	Hostname           string   `yaml:"hostname"`
	Mirror             string   `yaml:"mirror"`
	RootPassword       string   `yaml:"root_password" secret:"true"`
	FilesystemType     string   `yaml:"filesystem_type"`
	FIPS               bool     `yaml:"fips"`
	Lockdown           bool     `yaml:"lockdown"`
	LockdownMode       string   `yaml:"lockdown_mode,omitempty"`
	TPMAutoUpgradeSeal bool     `yaml:"tpm_auto_upgrade_seal"`
	PlatformdBinary    string   `yaml:"platformd_binary,omitempty"`
	WebUIInstallPath   string   `yaml:"webui_install_path,omitempty"`
	Packages           []string `yaml:"packages,omitempty"`
	EnableFIDO2        bool     `yaml:"enable-fido2,omitempty"`
}

// SecurityYAMLConfig represents security configuration in YAML format
type SecurityYAMLConfig struct {
	TPM        TPMYAMLConfig        `yaml:"tpm"`
	SecureBoot SecureBootYAMLConfig `yaml:"secure_boot"`
}

// TPMYAMLConfig represents TPM configuration in YAML format
type TPMYAMLConfig struct {
	Enabled  bool   `yaml:"enabled"`
	SealPCRs []uint `yaml:"seal_pcrs,omitempty"`
}

// SecureBootYAMLConfig is the autoinstall YAML view of Secure Boot config. It
// is a direct alias of SecureBootConfig so the generated autoinstall YAML
// round-trips the full PK/KEK/DB shape (enabled, enforce, resign-mode, URIs).
type SecureBootYAMLConfig = SecureBootConfig

// GenerateInstallConfig converts an installer.Config to YAML format
func GenerateInstallConfig(buildConfig *Config) ([]byte, error) {
	if buildConfig == nil {
		return nil, &MessageError{Msg: "config cannot be nil"}
	}

	if err := buildConfig.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid config", Err: err}
	}

	yamlConfig := &InstallConfig{
		Version: ConfigVersion,
	}

	// Convert disk configuration
	if buildConfig.Disk != nil {
		yamlConfig.Disk = DiskYAMLConfig{
			Device:         buildConfig.Disk.Device,
			PartitionTable: string(buildConfig.Disk.PartitionTable),
			EFISize:        buildConfig.Disk.EFIPartitionSize,
			Filesystem:     string(buildConfig.Disk.RootFilesystem),
		}

		// Set defaults
		if yamlConfig.Disk.PartitionTable == "" {
			yamlConfig.Disk.PartitionTable = string(PartitionTableGPT)
		}
		if yamlConfig.Disk.EFISize == 0 {
			yamlConfig.Disk.EFISize = 538
		}
		if yamlConfig.Disk.Filesystem == "" {
			yamlConfig.Disk.Filesystem = string(FilesystemLVM)
		}

		// Add LVM config if filesystem is LVM
		if buildConfig.Disk.RootFilesystem == FilesystemLVM {
			lvmVG := buildConfig.Disk.LVMVolumeGroup
			if lvmVG == "" {
				lvmVG = "vg0"
			}
			lvmLV := buildConfig.Disk.LVMLogicalVolume
			if lvmLV == "" {
				lvmLV = "root"
			}
			yamlConfig.Disk.LVM = &LVMYAMLConfig{
				VolumeGroup:   lvmVG,
				LogicalVolume: lvmLV,
			}
		}

		// Add encryption config
		if buildConfig.Disk.Encryption != nil {
			enc := buildConfig.Disk.Encryption
			yamlConfig.Disk.Encryption = &EncryptionYAMLConfig{
				Enabled:    true,
				Cipher:     enc.Cipher,
				KeySize:    enc.KeySize,
				Hash:       enc.Hash,
				PBKDF:      enc.PBKDF,
				Password:   enc.Password,
				MappedName: enc.MappedName,
			}
			// Set defaults
			if yamlConfig.Disk.Encryption.Cipher == "" {
				yamlConfig.Disk.Encryption.Cipher = "aes-xts-plain64"
			}
			if yamlConfig.Disk.Encryption.KeySize == 0 {
				yamlConfig.Disk.Encryption.KeySize = 512
			}
			if yamlConfig.Disk.Encryption.Hash == "" {
				yamlConfig.Disk.Encryption.Hash = "sha256"
			}
			// PBKDF is intentionally not defaulted here - fips.GetKDF() in disk.go
			// will auto-detect the appropriate KDF based on /proc/sys/crypto/fips_enabled
			if yamlConfig.Disk.Encryption.MappedName == "" {
				yamlConfig.Disk.Encryption.MappedName = "cryptroot"
			}
		}
	}

	// Convert OS configuration
	if buildConfig.OS != nil {
		yamlConfig.OS = OSYAMLConfig{
			Name:               string(buildConfig.OS.OS),
			Version:            buildConfig.OS.Version,
			Architecture:       buildConfig.OS.Architecture,
			Hostname:           buildConfig.OS.Hostname,
			Mirror:             buildConfig.OS.Mirror,
			RootPassword:       buildConfig.OS.RootPassword,
			FilesystemType:     string(buildConfig.OS.FilesystemType),
			FIPS:               buildConfig.OS.FIPS,
			Lockdown:           buildConfig.OS.Lockdown,
			LockdownMode:       buildConfig.OS.LockdownMode,
			TPMAutoUpgradeSeal: buildConfig.OS.TPMAutoUpgradeSeal,
			PlatformdBinary:    buildConfig.OS.PlatformdBinary,
			Packages:           buildConfig.OS.Packages,
			EnableFIDO2:        buildConfig.OS.EnableFIDO2,
		}

		// Set defaults
		if yamlConfig.OS.Architecture == "" {
			yamlConfig.OS.Architecture = "x86_64"
		}
		if yamlConfig.OS.Hostname == "" {
			yamlConfig.OS.Hostname = "trusted-platform"
		}
		if yamlConfig.OS.FilesystemType == "" {
			yamlConfig.OS.FilesystemType = string(FilesystemLVM)
		}
		if yamlConfig.OS.Lockdown && yamlConfig.OS.LockdownMode == "" {
			yamlConfig.OS.LockdownMode = "confidentiality"
		}
	}

	// Convert security configuration
	yamlConfig.Security = SecurityYAMLConfig{
		TPM: TPMYAMLConfig{
			Enabled:  buildConfig.EnableTPMSealing,
			SealPCRs: buildConfig.PCRs,
		},
	}
	// Carry the full Secure Boot shape into the autoinstall YAML when
	// configured; a nil pointer leaves SecureBoot zero-valued (Enabled=false).
	if buildConfig.SecureBoot != nil {
		yamlConfig.Security.SecureBoot = *buildConfig.SecureBoot
	}

	// Set default PCRs if TPM is enabled but no PCRs specified
	if yamlConfig.Security.TPM.Enabled && len(yamlConfig.Security.TPM.SealPCRs) == 0 {
		yamlConfig.Security.TPM.SealPCRs = []uint{0, 7, 9}
	}

	// Marshal to YAML
	data, err := yaml.Marshal(yamlConfig)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal config to YAML", Err: err}
	}

	return data, nil
}

// WriteInstallConfig writes a configuration to a YAML file
func WriteInstallConfig(config *Config, path string) error {
	data, err := GenerateInstallConfig(config)
	if err != nil {
		return &WrappedError{Msg: "failed to generate config", Err: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return &WrappedError{Msg: "failed to write config file", Err: err}
	}

	return nil
}

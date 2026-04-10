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
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/dev.yaml
var devProfileData []byte

//go:embed profiles/production.yaml
var productionProfileData []byte

//go:embed profiles/production-hs.yaml
var productionHSProfileData []byte

//go:embed profiles/fips.yaml
var fipsProfileData []byte

// ProfileName represents a built-in configuration profile
type ProfileName string

const (
	ProfileDev          ProfileName = "dev"
	ProfileProduction   ProfileName = "production"
	ProfileProductionHS ProfileName = "production-hs"
	ProfileFIPS         ProfileName = "fips"
)

// Profile represents a configuration profile with metadata
type Profile struct {
	Name        ProfileName
	Description string
	Config      *Config
}

// ProfileInfo contains basic profile information for listing
type ProfileInfo struct {
	Name        string
	Description string
}

// builtInProfiles maps profile names to their embedded YAML data
var builtInProfiles = map[ProfileName][]byte{
	ProfileDev:          devProfileData,
	ProfileProduction:   productionProfileData,
	ProfileProductionHS: productionHSProfileData,
	ProfileFIPS:         fipsProfileData,
}

// profileDescriptions provides human-readable descriptions for each profile
var profileDescriptions = map[ProfileName]string{
	ProfileDev:          "Development profile with debug enabled and relaxed security",
	ProfileProduction:   "Production profile with balanced security and integrity mode lockdown",
	ProfileProductionHS: "High security profile with FIPS, confidentiality lockdown, and extensive PCR sealing",
	ProfileFIPS:         "FIPS 140-3 compliant profile with FIPS mode and integrity lockdown",
}

// GetProfile loads and returns a named configuration profile
func GetProfile(name string) (*Config, error) {
	profileName := ProfileName(strings.ToLower(name))

	// Check if profile exists
	profileData, exists := builtInProfiles[profileName]
	if !exists {
		return nil, fmt.Errorf("unknown profile: %s (available: %s)", name, strings.Join(ListProfiles(), ", "))
	}

	// Parse the embedded YAML
	var yamlConfig InstallConfig
	if err := yaml.Unmarshal(profileData, &yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to parse profile %s: %w", name, err)
	}

	// Convert YAML to internal Config structure using the same logic as LoadInstallConfig
	config := &Config{
		Debug: false,
	}

	// Enable debug for dev profile
	if profileName == ProfileDev {
		config.Debug = true
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
		config.PCRs = []uint{0, 7, 9}
	}

	// Set SecureBoot if enabled
	if yamlConfig.Security.SecureBoot.Enabled {
		config.SecureBoot = &SecureBootConfig{
			// Paths will be auto-detected during installation
		}
	}

	return config, nil
}

// GetProfileWithDescription loads a profile and returns it with metadata
func GetProfileWithDescription(name string) (*Profile, error) {
	config, err := GetProfile(name)
	if err != nil {
		return nil, err
	}

	profileName := ProfileName(strings.ToLower(name))
	return &Profile{
		Name:        profileName,
		Description: profileDescriptions[profileName],
		Config:      config,
	}, nil
}

// ListProfiles returns a list of available profile names
func ListProfiles() []string {
	// Return in consistent order
	return []string{
		string(ProfileDev),
		string(ProfileProduction),
		string(ProfileFIPS),
		string(ProfileProductionHS),
	}
}

// ListProfilesWithDescriptions returns all profiles with their descriptions
func ListProfilesWithDescriptions() []ProfileInfo {
	profiles := make([]ProfileInfo, 0, len(builtInProfiles))
	// Iterate in consistent order
	for _, name := range ListProfiles() {
		profileName := ProfileName(name)
		if desc, exists := profileDescriptions[profileName]; exists {
			profiles = append(profiles, ProfileInfo{
				Name:        name,
				Description: desc,
			})
		}
	}
	return profiles
}

// ValidateProfileName checks if a profile name is valid
func ValidateProfileName(name string) error {
	profileName := ProfileName(strings.ToLower(name))
	if _, exists := builtInProfiles[profileName]; !exists {
		return fmt.Errorf("invalid profile name: %s (available: %s)", name, strings.Join(ListProfiles(), ", "))
	}
	return nil
}

// GenerateConfigFromProfile generates a new config based on a profile with overrides
func GenerateConfigFromProfile(profileName string, overrides map[string]string) (*Config, error) {
	config, err := GetProfile(profileName)
	if err != nil {
		return nil, err
	}

	// Apply overrides
	for key, value := range overrides {
		switch strings.ToLower(key) {
		case "hostname":
			if config.OS != nil {
				config.OS.Hostname = value
			}
		case "device":
			if config.Disk != nil {
				config.Disk.Device = value
			}
		case "password":
			if config.Disk != nil && config.Disk.Encryption != nil {
				config.Disk.Encryption.Password = value
				config.Disk.Encryption.Passphrase = value
			}
		case "root_password", "rootpassword":
			if config.OS != nil {
				config.OS.RootPassword = value
			}
		}
	}

	return config, nil
}

// ConfigToYAML converts a Config to YAML format
func ConfigToYAML(config *Config) (string, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config to YAML: %w", err)
	}
	return string(data), nil
}

// ConfigFromYAML parses a Config from YAML format
func ConfigFromYAML(data []byte) (*Config, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}
	return &config, nil
}

// ValidateConfig validates an installation configuration
func ValidateConfig(config *Config) error {
	return config.Validate()
}

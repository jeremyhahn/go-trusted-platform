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
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGetProfile(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		expectError bool
	}{
		{
			name:        "get dev profile",
			profileName: "dev",
			expectError: false,
		},
		{
			name:        "get production profile",
			profileName: "production",
			expectError: false,
		},
		{
			name:        "get production-hs profile",
			profileName: "production-hs",
			expectError: false,
		},
		{
			name:        "get fips profile",
			profileName: "fips",
			expectError: false,
		},
		{
			name:        "get non-existent profile",
			profileName: "non-existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := GetProfile(tt.profileName)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for profile %s, got nil", tt.profileName)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error getting profile %s: %v", tt.profileName, err)
			}

			if config == nil {
				t.Fatal("expected non-nil config")
			}

			// Verify basic configuration
			if config.Disk == nil {
				t.Error("expected disk config")
			}

			if config.OS == nil {
				t.Error("expected OS config")
			}
		})
	}
}

func TestGetProfileWithDescription(t *testing.T) {
	profile, err := GetProfileWithDescription("dev")
	if err != nil {
		t.Fatalf("failed to get profile with description: %v", err)
	}

	if profile.Name != ProfileDev {
		t.Errorf("expected profile name %s, got %s", ProfileDev, profile.Name)
	}

	if profile.Description == "" {
		t.Error("profile description should not be empty")
	}

	if profile.Config == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestListProfiles(t *testing.T) {
	profiles := ListProfiles()

	if len(profiles) == 0 {
		t.Fatal("expected at least one profile")
	}

	expectedProfiles := map[string]bool{
		"dev":           false,
		"production":    false,
		"production-hs": false,
		"fips":          false,
	}

	for _, profileName := range profiles {
		if _, exists := expectedProfiles[profileName]; exists {
			expectedProfiles[profileName] = true
		}
	}

	for name, found := range expectedProfiles {
		if !found {
			t.Errorf("expected profile %s not found in list", name)
		}
	}
}

func TestListProfilesWithDescriptions(t *testing.T) {
	profiles := ListProfilesWithDescriptions()

	if len(profiles) == 0 {
		t.Fatal("expected at least one profile")
	}

	for _, profile := range profiles {
		if profile.Description == "" {
			t.Errorf("profile %s has empty description", profile.Name)
		}
	}
}

func TestValidateProfileName(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		expectError bool
	}{
		{
			name:        "valid dev profile",
			profileName: "dev",
			expectError: false,
		},
		{
			name:        "valid production profile",
			profileName: "production",
			expectError: false,
		},
		{
			name:        "invalid profile",
			profileName: "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.profileName)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
					RootFilesystem: FilesystemLVM,
				},
				OS: &OSConfig{
					OS:       OSAlpine,
					Version:  "3.22",
					Hostname: "test",
				},
			},
			expectError: false,
		},
		{
			name: "missing disk config",
			config: &Config{
				OS: &OSConfig{
					OS:       OSAlpine,
					Version:  "3.22",
					Hostname: "test",
				},
			},
			expectError: true,
		},
		{
			name: "missing OS config",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
			},
			expectError: true,
		},
		{
			name: "missing disk device",
			config: &Config{
				Disk: &DiskConfig{
					PartitionTable: PartitionTableGPT,
				},
				OS: &OSConfig{
					OS:       OSAlpine,
					Version:  "3.22",
					Hostname: "test",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigToYAML(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			RootFilesystem: FilesystemLVM,
		},
		OS: &OSConfig{
			OS:       OSAlpine,
			Version:  "3.22",
			Hostname: "test-host",
		},
	}

	yamlStr, err := ConfigToYAML(config)
	if err != nil {
		t.Fatalf("failed to convert config to YAML: %v", err)
	}

	if yamlStr == "" {
		t.Error("expected non-empty YAML string")
	}

	// Verify we can parse it back
	var parsed Config
	if err := yaml.Unmarshal([]byte(yamlStr), &parsed); err != nil {
		t.Fatalf("failed to parse generated YAML: %v", err)
	}

	if parsed.OS.Hostname != "test-host" {
		t.Errorf("expected hostname test-host, got %s", parsed.OS.Hostname)
	}
}

func TestConfigFromYAML(t *testing.T) {
	yamlData := `
disk:
  device: /dev/sda
  partitiontable: gpt
  efipartitionsize: 538
  rootfilesystem: lvm
  lvmvolumegroup: test-vg
  lvmlogicalvolume: test-lv
os:
  os: alpine
  version: "3.22"
  architecture: x86_64
  hostname: test-host
  mirror: http://dl-cdn.alpinelinux.org/alpine
  packages:
    - alpine-base
    - linux-lts
  rootpassword: test123
  filesystemtype: lvm
  fips: false
  lockdown: false
`

	config, err := ConfigFromYAML([]byte(yamlData))
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	if config.Disk == nil {
		t.Fatal("expected disk config")
	}

	if config.Disk.Device != "/dev/sda" {
		t.Errorf("expected device /dev/sda, got %s", config.Disk.Device)
	}

	if config.OS == nil {
		t.Fatal("expected OS config")
	}

	if config.OS.Hostname != "test-host" {
		t.Errorf("expected hostname test-host, got %s", config.OS.Hostname)
	}

	if len(config.OS.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(config.OS.Packages))
	}
}

func TestConfigFromYAMLInvalid(t *testing.T) {
	invalidYAML := `
this is not: valid: yaml:
  - broken
    structure
`

	_, err := ConfigFromYAML([]byte(invalidYAML))
	if err == nil {
		t.Error("expected error parsing invalid YAML")
	}
}

func TestGenerateConfigFromProfile(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		overrides   map[string]string
		expectError bool
		validate    func(*testing.T, *Config)
	}{
		{
			name:        "generate from dev profile without overrides",
			profileName: "dev",
			overrides:   nil,
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Device != "/dev/sda" {
					t.Errorf("expected device /dev/sda, got %s", cfg.Disk.Device)
				}
			},
		},
		{
			name:        "generate with device override",
			profileName: "production",
			overrides: map[string]string{
				"device": "/dev/nvme0n1",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Device != "/dev/nvme0n1" {
					t.Errorf("expected device /dev/nvme0n1, got %s", cfg.Disk.Device)
				}
			},
		},
		{
			name:        "generate with hostname override",
			profileName: "fips",
			overrides: map[string]string{
				"hostname": "my-custom-host",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.OS.Hostname != "my-custom-host" {
					t.Errorf("expected hostname my-custom-host, got %s", cfg.OS.Hostname)
				}
			},
		},
		{
			name:        "generate with password override",
			profileName: "dev",
			overrides: map[string]string{
				"password": "super-secret",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Encryption == nil {
					t.Fatal("expected encryption config")
				}
				if cfg.Disk.Encryption.Password != "super-secret" {
					t.Errorf("expected password super-secret, got %s", cfg.Disk.Encryption.Password)
				}
			},
		},
		{
			name:        "generate from non-existent profile",
			profileName: "non-existent",
			overrides:   nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := GenerateConfigFromProfile(tt.profileName, tt.overrides)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if config == nil {
				t.Fatal("expected non-nil config")
			}

			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestProfileConfigValidation(t *testing.T) {
	// Test that all built-in profiles can be loaded
	profileNames := []string{"dev", "production", "production-hs", "fips"}

	for _, name := range profileNames {
		t.Run("load_"+name, func(t *testing.T) {
			config, err := GetProfile(name)
			if err != nil {
				t.Fatalf("failed to get profile %s: %v", name, err)
			}

			if config == nil {
				t.Fatal("expected non-nil config")
			}

			// Verify basic structure
			if config.Disk == nil {
				t.Error("expected disk config")
			}

			if config.OS == nil {
				t.Error("expected OS config")
			}
		})
	}
}

func TestProfileYAMLRoundTrip(t *testing.T) {
	// Test that we can convert a profile to YAML and back without data loss
	config, err := GetProfile("dev")
	if err != nil {
		t.Fatalf("failed to get dev profile: %v", err)
	}

	// Convert to YAML
	yamlStr, err := ConfigToYAML(config)
	if err != nil {
		t.Fatalf("failed to convert to YAML: %v", err)
	}

	// Parse back
	parsed, err := ConfigFromYAML([]byte(yamlStr))
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	// Verify key fields
	if parsed.OS.Hostname != config.OS.Hostname {
		t.Errorf("hostname mismatch: expected %s, got %s",
			config.OS.Hostname, parsed.OS.Hostname)
	}

	if parsed.Disk.Device != config.Disk.Device {
		t.Errorf("device mismatch: expected %s, got %s",
			config.Disk.Device, parsed.Disk.Device)
	}
}

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
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantErr     bool
		validate    func(*testing.T, *Config)
	}{
		{
			name: "valid config",
			yamlContent: `
disk:
  device: /dev/sda
  partition-table: gpt
  efi-partition-size: 538
  root-filesystem: lvm
  lvm-volume-group: vg0
  lvm-logical-volume: root
  encryption:
    cipher: aes-xts-plain64
    key-size: 512
    hash: sha256
    pbkdf: argon2id
    password: test123
    mapped-name: cryptroot

os:
  os: alpine
  version: "3.19"
  architecture: x86_64
  hostname: test-host
  mirror: https://dl-cdn.alpinelinux.org/alpine
  filesystem-type: lvm
  fips: false
  lockdown: true
  lockdown-mode: confidentiality
  tpm-auto-upgrade-seal: true

enable-tpm-sealing: true
debug: false
`,
			wantErr: false,
			validate: func(t *testing.T, c *Config) {
				if c.Disk.Device != "/dev/sda" {
					t.Errorf("Expected disk device /dev/sda, got %s", c.Disk.Device)
				}
				if c.Disk.PartitionTable != PartitionTableGPT {
					t.Errorf("Expected partition table gpt, got %s", c.Disk.PartitionTable)
				}
				if c.Disk.EFIPartitionSize != 538 {
					t.Errorf("Expected EFI size 538, got %d", c.Disk.EFIPartitionSize)
				}
				if c.Disk.RootFilesystem != FilesystemLVM {
					t.Errorf("Expected root filesystem lvm, got %s", c.Disk.RootFilesystem)
				}
				if c.Disk.Encryption.Password != "test123" {
					t.Errorf("Expected password test123, got %s", c.Disk.Encryption.Password)
				}
				if c.OS.OS != OSAlpine {
					t.Errorf("Expected OS alpine, got %s", c.OS.OS)
				}
				if c.OS.Hostname != "test-host" {
					t.Errorf("Expected hostname test-host, got %s", c.OS.Hostname)
				}
				if !c.EnableTPMSealing {
					t.Error("Expected TPM sealing to be enabled")
				}
			},
		},
		{
			name: "minimal config",
			yamlContent: `
disk:
  device: /dev/vda
  partition-table: gpt
  encryption:
    password: secret

os:
  os: debian
  hostname: minimal
`,
			wantErr: false,
			validate: func(t *testing.T, c *Config) {
				if c.Disk.Device != "/dev/vda" {
					t.Errorf("Expected disk device /dev/vda, got %s", c.Disk.Device)
				}
				if c.OS.OS != OSDebian {
					t.Errorf("Expected OS debian, got %s", c.OS.OS)
				}
			},
		},
		{
			name: "invalid yaml",
			yamlContent: `
disk:
  device: /dev/sda
  invalid: [unclosed
`,
			wantErr: true,
			validate: func(t *testing.T, c *Config) {
				// Should not be called
			},
		},
		{
			name: "missing required fields",
			yamlContent: `
os:
  os: alpine
`,
			// LoadConfig doesn't validate required fields - it just parses YAML
			// Validation happens when the config is used by the installer
			wantErr: false,
			validate: func(t *testing.T, c *Config) {
				// Should have OS set, disk should be initialized to empty
				if c.OS.OS != OSAlpine {
					t.Errorf("Expected OS alpine, got %s", c.OS.OS)
				}
				if c.Disk == nil {
					t.Error("Disk should be initialized (not nil)")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			if err := os.WriteFile(configPath, []byte(tt.yamlContent), 0600); err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			// Load config
			config, err := LoadConfig(configPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && config != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a test config
	config := &Config{
		Disk: &DiskConfig{
			Device:           "/dev/sda",
			PartitionTable:   PartitionTableGPT,
			EFIPartitionSize: 538,
			RootFilesystem:   FilesystemLVM,
			LVMVolumeGroup:   "vg0",
			LVMLogicalVolume: "root",
			Encryption: &EncryptionConfig{
				Cipher:     "aes-xts-plain64",
				KeySize:    512,
				Hash:       "sha256",
				PBKDF:      "argon2id",
				Password:   "test123",
				MappedName: "cryptroot",
			},
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			Architecture: "x86_64",
			Hostname:     "test-host",
			Lockdown:     true,
			LockdownMode: "confidentiality",
		},
		EnableTPMSealing: true,
	}

	// Save config
	if err := SaveConfig(config, configPath); err != nil {
		t.Fatalf("SaveConfig() failed: %v", err)
	}

	// Load it back
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	// Verify
	if loaded.Disk.Device != config.Disk.Device {
		t.Errorf("Device mismatch: got %s, want %s", loaded.Disk.Device, config.Disk.Device)
	}
	if loaded.OS.Hostname != config.OS.Hostname {
		t.Errorf("Hostname mismatch: got %s, want %s", loaded.OS.Hostname, config.OS.Hostname)
	}
	if loaded.EnableTPMSealing != config.EnableTPMSealing {
		t.Errorf("EnableTPMSealing mismatch: got %v, want %v", loaded.EnableTPMSealing, config.EnableTPMSealing)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if config.Disk == nil {
		t.Fatal("DefaultConfig() Disk is nil")
	}

	if config.OS == nil {
		t.Fatal("DefaultConfig() OS is nil")
	}

	if config.Disk.PartitionTable != PartitionTableGPT {
		t.Errorf("Expected default partition table GPT, got %s", config.Disk.PartitionTable)
	}

	if config.Disk.RootFilesystem != FilesystemLVM {
		t.Errorf("Expected default filesystem LVM, got %s", config.Disk.RootFilesystem)
	}

	if config.OS.OS != OSAlpine {
		t.Errorf("Expected default OS Alpine, got %s", config.OS.OS)
	}

	if !config.EnableTPMSealing {
		t.Error("Expected TPM sealing enabled by default")
	}
}

func TestSaveConfig_InvalidPath(t *testing.T) {
	config := DefaultConfig()
	err := SaveConfig(config, "/nonexistent/directory/config.yaml")
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "full config",
			config: &Config{
				Disk: &DiskConfig{
					Device:           "/dev/nvme0n1",
					PartitionTable:   PartitionTableGPT,
					EFIPartitionSize: 1024,
					RootFilesystem:   FilesystemExt4,
					Encryption: &EncryptionConfig{
						Version:    "luks2",
						Cipher:     "aes-xts-plain64",
						KeySize:    512,
						Hash:       "sha512",
						PBKDF:      "argon2id",
						Password:   "secure123",
						MappedName: "encrypted",
					},
				},
				OS: &OSConfig{
					OS:                 OSUbuntu,
					Version:            "22.04",
					Architecture:       "x86_64",
					Hostname:           "ubuntu-server",
					Mirror:             "http://archive.ubuntu.com/ubuntu",
					FilesystemType:     FilesystemExt4,
					FIPS:               true,
					Lockdown:           true,
					LockdownMode:       "integrity",
					TPMAutoUpgradeSeal: false,
					RootPassword:       "rootpass",
				},
				EnableTPMSealing: true,
				PCRs:             []uint{0, 1, 2, 7},
				Debug:            true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save
			if err := SaveConfig(tt.config, configPath); err != nil {
				t.Fatalf("SaveConfig() failed: %v", err)
			}

			// Load
			loaded, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("LoadConfig() failed: %v", err)
			}

			// Compare
			if loaded.Disk.Device != tt.config.Disk.Device {
				t.Errorf("Device: got %s, want %s", loaded.Disk.Device, tt.config.Disk.Device)
			}
			if loaded.Disk.EFIPartitionSize != tt.config.Disk.EFIPartitionSize {
				t.Errorf("EFIPartitionSize: got %d, want %d", loaded.Disk.EFIPartitionSize, tt.config.Disk.EFIPartitionSize)
			}
			if loaded.OS.OS != tt.config.OS.OS {
				t.Errorf("OS: got %s, want %s", loaded.OS.OS, tt.config.OS.OS)
			}
			if loaded.OS.FIPS != tt.config.OS.FIPS {
				t.Errorf("FIPS: got %v, want %v", loaded.OS.FIPS, tt.config.OS.FIPS)
			}
			if loaded.Debug != tt.config.Debug {
				t.Errorf("Debug: got %v, want %v", loaded.Debug, tt.config.Debug)
			}
			if len(loaded.PCRs) != len(tt.config.PCRs) {
				t.Errorf("PCRs length: got %d, want %d", len(loaded.PCRs), len(tt.config.PCRs))
			}
		})
	}
}

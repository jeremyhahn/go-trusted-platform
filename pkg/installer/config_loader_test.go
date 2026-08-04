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

func TestLoadInstallConfig(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		yaml     string
		wantErr  bool
		validate func(*testing.T, *Config)
	}{
		{
			name: "valid minimal config",
			yaml: `version: "1.0"
disk:
  device: /dev/sda
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
os:
  name: alpine
  version: "3.22.2"
  architecture: x86_64
  hostname: test-host
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: testpass
  filesystem_type: lvm
  fips: false
  lockdown: false
  tpm_auto_upgrade_seal: false
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Device != "/dev/sda" {
					t.Errorf("device = %s, want /dev/sda", cfg.Disk.Device)
				}
				if cfg.OS.Hostname != "test-host" {
					t.Errorf("hostname = %s, want test-host", cfg.OS.Hostname)
				}
			},
		},
		{
			name: "config with encryption",
			yaml: `version: "1.0"
disk:
  device: /dev/vda
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
  encryption:
    enabled: true
    cipher: aes-xts-plain64
    key_size: 512
    hash: sha256
    pbkdf: argon2id
    password: secret123
    mapped_name: cryptroot
os:
  name: alpine
  version: "3.22.2"
  architecture: x86_64
  hostname: encrypted-host
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: rootpass
  filesystem_type: lvm
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Encryption == nil {
					t.Fatal("encryption is nil")
				}
				if cfg.Disk.Encryption.Password != "secret123" {
					t.Errorf("password = %s, want secret123", cfg.Disk.Encryption.Password)
				}
			},
		},
		{
			name: "config with TPM and PCRs",
			yaml: `version: "1.0"
disk:
  device: /dev/sda
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
os:
  name: alpine
  version: "3.22.2"
  architecture: x86_64
  hostname: tpm-host
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: rootpass
  filesystem_type: lvm
security:
  tpm:
    enabled: true
    seal_pcrs: [0, 7, 9, 11]
  secure_boot:
    enabled: true
    db:
      key-uri: kms://platform/secureboot/db
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.EnableTPMSealing {
					t.Error("TPM sealing not enabled")
				}
				expectedPCRs := []uint{0, 7, 9, 11}
				if len(cfg.PCRs) != len(expectedPCRs) {
					t.Errorf("len(PCRs) = %d, want %d", len(cfg.PCRs), len(expectedPCRs))
				}
				if cfg.SecureBoot == nil {
					t.Error("SecureBoot is nil")
				}
			},
		},
		{
			name: "config with environment variables",
			yaml: `version: "1.0"
disk:
  device: /dev/sda
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
  encryption:
    enabled: true
    password: "${TEST_PASSWORD}"
os:
  name: alpine
  version: "3.22.2"
  architecture: x86_64
  hostname: "${TEST_HOSTNAME}"
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: "${TEST_ROOT_PASSWORD}"
  filesystem_type: lvm
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				// Set environment variables
				t.Setenv("TEST_PASSWORD", "envpass123")
				t.Setenv("TEST_HOSTNAME", "envhost")
				t.Setenv("TEST_ROOT_PASSWORD", "envrootpass")

				// Note: Environment variables should already be expanded during load
				if cfg.Disk.Encryption == nil {
					t.Fatal("encryption is nil")
				}
				// Variables are expanded at parse time, so they should be empty here
				// This test validates the structure is correct
			},
		},
		{
			name: "invalid version",
			yaml: `version: "2.0"
disk:
  device: /dev/sda
os:
  name: alpine
  version: "3.22.2"
`,
			wantErr: true,
		},
		{
			name:    "invalid YAML",
			yaml:    `this is not: valid: yaml: syntax`,
			wantErr: true,
		},
		{
			name: "missing required fields",
			yaml: `version: "1.0"
disk:
  partition_table: gpt
os:
  name: alpine
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test config to temp file
			configPath := filepath.Join(tmpDir, tt.name+".yaml")
			if err := os.WriteFile(configPath, []byte(tt.yaml), 0600); err != nil {
				t.Fatalf("failed to write test config: %v", err)
			}

			cfg, err := LoadInstallConfig(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadInstallConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestLoadInstallConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	yaml := `version: "1.0"
disk:
  device: /dev/sda
os:
  name: alpine
  version: "3.22.2"
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadInstallConfig(configPath)
	if err != nil {
		t.Fatalf("LoadInstallConfig() failed: %v", err)
	}

	// Check defaults
	if cfg.Disk.PartitionTable != PartitionTableGPT {
		t.Errorf("partition_table = %s, want gpt", cfg.Disk.PartitionTable)
	}
	if cfg.Disk.EFIPartitionSize != 538 {
		t.Errorf("efi_partition_size = %d, want 538", cfg.Disk.EFIPartitionSize)
	}
	if cfg.Disk.RootFilesystem != FilesystemLVM {
		t.Errorf("root_filesystem = %s, want lvm", cfg.Disk.RootFilesystem)
	}
	if cfg.OS.Architecture != "x86_64" {
		t.Errorf("architecture = %s, want x86_64", cfg.OS.Architecture)
	}
	if cfg.OS.Hostname != "trusted-platform" {
		t.Errorf("hostname = %s, want trusted-platform", cfg.OS.Hostname)
	}
}

func TestLoadInstallConfigWithEnvVars(t *testing.T) {
	tmpDir := t.TempDir()

	// Set environment variables
	t.Setenv("TEST_DEVICE", "/dev/vdb")
	t.Setenv("TEST_HOSTNAME", "myhost")
	t.Setenv("TEST_PASSWORD", "mypass123")

	yaml := `version: "1.0"
disk:
  device: ${TEST_DEVICE}
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
  encryption:
    enabled: true
    password: ${TEST_PASSWORD}
os:
  name: alpine
  version: "3.22.2"
  hostname: ${TEST_HOSTNAME}
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: rootpass
  filesystem_type: lvm
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadInstallConfig(configPath)
	if err != nil {
		t.Fatalf("LoadInstallConfig() failed: %v", err)
	}

	// Check environment variables were expanded
	if cfg.Disk.Device != "/dev/vdb" {
		t.Errorf("device = %s, want /dev/vdb", cfg.Disk.Device)
	}
	if cfg.OS.Hostname != "myhost" {
		t.Errorf("hostname = %s, want myhost", cfg.OS.Hostname)
	}
	if cfg.Disk.Encryption.Password != "mypass123" {
		t.Errorf("password = %s, want mypass123", cfg.Disk.Encryption.Password)
	}
}

func TestMergeWithDefaults(t *testing.T) {
	defaults := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			Hostname: "default-host",
		},
		EnableTPMSealing: true,
		PCRs:             []uint{0, 7},
		Debug:            false,
	}

	tests := []struct {
		name     string
		config   *Config
		validate func(*testing.T, *Config)
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Device != "/dev/sda" {
					t.Errorf("device = %s, want /dev/sda", cfg.Disk.Device)
				}
			},
		},
		{
			name: "config overrides defaults",
			config: &Config{
				Disk: &DiskConfig{
					Device: "/dev/vda",
				},
				OS: &OSConfig{
					Hostname: "custom-host",
				},
			},
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Disk.Device != "/dev/vda" {
					t.Errorf("device = %s, want /dev/vda", cfg.Disk.Device)
				}
				if cfg.OS.Hostname != "custom-host" {
					t.Errorf("hostname = %s, want custom-host", cfg.OS.Hostname)
				}
			},
		},
		{
			name: "partial override",
			config: &Config{
				OS: &OSConfig{
					Hostname: "partial-host",
				},
			},
			validate: func(t *testing.T, cfg *Config) {
				// Disk should come from defaults
				if cfg.Disk.Device != "/dev/sda" {
					t.Errorf("device = %s, want /dev/sda", cfg.Disk.Device)
				}
				// OS should be from config
				if cfg.OS.Hostname != "partial-host" {
					t.Errorf("hostname = %s, want partial-host", cfg.OS.Hostname)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged := MergeWithDefaults(tt.config, defaults)
			if merged == nil {
				t.Fatal("merged config is nil")
			}
			tt.validate(t, merged)
		})
	}
}

func TestLoadInstallConfigFileNotFound(t *testing.T) {
	_, err := LoadInstallConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestExpandXKMSReferences(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a XKMS file
	xkmsFile := filepath.Join(tmpDir, "secret.key")
	if err := os.WriteFile(xkmsFile, []byte("secret-value"), 0600); err != nil {
		t.Fatalf("failed to write XKMS file: %v", err)
	}

	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			Encryption: &EncryptionConfig{
				Password: "xkms://" + xkmsFile,
			},
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			Version:      "3.22.2",
			RootPassword: "xkms://" + xkmsFile,
		},
	}

	err := expandXKMSReferences(config)
	if err != nil {
		t.Fatalf("expandXKMSReferences() failed: %v", err)
	}

	// Check values were expanded
	if config.Disk.Encryption.Password != "secret-value" {
		t.Errorf("password = %s, want secret-value", config.Disk.Encryption.Password)
	}
	if config.OS.RootPassword != "secret-value" {
		t.Errorf("root_password = %s, want secret-value", config.OS.RootPassword)
	}
}

func TestExpandXKMSReferencesError(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			Encryption: &EncryptionConfig{
				Password: "xkms:///nonexistent/file",
			},
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22.2",
		},
	}

	err := expandXKMSReferences(config)
	if err == nil {
		t.Error("expected error for nonexistent XKMS file, got nil")
	}
}

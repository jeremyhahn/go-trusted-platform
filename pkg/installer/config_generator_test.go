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

	"gopkg.in/yaml.v3"
)

func TestGenerateInstallConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		wantErr  bool
		validate func(*testing.T, []byte)
	}{
		{
			name: "minimal valid config",
			config: &Config{
				Disk: &DiskConfig{
					Device: "/dev/sda",
				},
				OS: &OSConfig{
					OS:      OSAlpine,
					Version: "3.22.2",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, data []byte) {
				var cfg InstallConfig
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to unmarshal generated YAML: %v", err)
				}
				if cfg.Version != ConfigVersion {
					t.Errorf("version = %s, want %s", cfg.Version, ConfigVersion)
				}
				if cfg.Disk.Device != "/dev/sda" {
					t.Errorf("disk.device = %s, want /dev/sda", cfg.Disk.Device)
				}
			},
		},
		{
			name: "config with encryption",
			config: &Config{
				Disk: &DiskConfig{
					Device:           "/dev/vda",
					PartitionTable:   PartitionTableGPT,
					EFIPartitionSize: 538,
					RootFilesystem:   FilesystemLVM,
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
					OS:      OSAlpine,
					Version: "3.22.2",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, data []byte) {
				var cfg InstallConfig
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if cfg.Disk.Encryption == nil {
					t.Fatal("encryption config is nil")
				}
				if !cfg.Disk.Encryption.Enabled {
					t.Error("encryption not enabled")
				}
				if cfg.Disk.Encryption.Password != "test123" {
					t.Errorf("password = %s, want test123", cfg.Disk.Encryption.Password)
				}
			},
		},
		{
			name: "config with LVM",
			config: &Config{
				Disk: &DiskConfig{
					Device:           "/dev/sda",
					RootFilesystem:   FilesystemLVM,
					LVMVolumeGroup:   "vg0",
					LVMLogicalVolume: "root",
				},
				OS: &OSConfig{
					OS:      OSAlpine,
					Version: "3.22.2",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, data []byte) {
				var cfg InstallConfig
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if cfg.Disk.LVM == nil {
					t.Fatal("LVM config is nil")
				}
				if cfg.Disk.LVM.VolumeGroup != "vg0" {
					t.Errorf("volume_group = %s, want vg0", cfg.Disk.LVM.VolumeGroup)
				}
			},
		},
		{
			name: "config with security settings",
			config: &Config{
				Disk: &DiskConfig{
					Device: "/dev/sda",
				},
				OS: &OSConfig{
					OS:           OSAlpine,
					Version:      "3.22.2",
					FIPS:         true,
					Lockdown:     true,
					LockdownMode: "confidentiality",
				},
				EnableTPMSealing: true,
				PCRs:             []uint{0, 7, 9},
				SecureBoot: &SecureBootConfig{
					Enabled:    true,
					ResignMode: SecureBootResignModeRemote,
					DB: SecureBootKeyRef{
						KeyURI:  "kms://platform/secureboot/db",
						CertURI: "kms://platform/secureboot/db-cert",
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, data []byte) {
				var cfg InstallConfig
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if !cfg.OS.FIPS {
					t.Error("FIPS not enabled")
				}
				if !cfg.OS.Lockdown {
					t.Error("lockdown not enabled")
				}
				if !cfg.Security.TPM.Enabled {
					t.Error("TPM not enabled")
				}
				if !cfg.Security.SecureBoot.Enabled {
					t.Error("SecureBoot not enabled")
				}
			},
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid config - no disk",
			config: &Config{
				OS: &OSConfig{
					OS:      OSAlpine,
					Version: "3.22.2",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateInstallConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateInstallConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

func TestWriteInstallConfig(t *testing.T) {
	tmpDir := t.TempDir()

	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22.2",
		},
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "write to valid path",
			path:    filepath.Join(tmpDir, "config.yaml"),
			wantErr: false,
		},
		{
			name:    "write to invalid path",
			path:    "/invalid/path/config.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteInstallConfig(config, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteInstallConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify file was written
				if _, err := os.Stat(tt.path); os.IsNotExist(err) {
					t.Error("config file was not created")
				}
				// Verify file permissions
				info, err := os.Stat(tt.path)
				if err != nil {
					t.Fatalf("failed to stat file: %v", err)
				}
				if info.Mode().Perm() != 0600 {
					t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
				}
			}
		})
	}
}

func TestGenerateInstallConfigDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			// No partition table, EFI size, or filesystem specified
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22.2",
			// No architecture or hostname specified
		},
	}

	data, err := GenerateInstallConfig(config)
	if err != nil {
		t.Fatalf("GenerateInstallConfig() failed: %v", err)
	}

	var cfg InstallConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Check defaults were applied
	if cfg.Disk.PartitionTable != string(PartitionTableGPT) {
		t.Errorf("partition_table = %s, want gpt", cfg.Disk.PartitionTable)
	}
	if cfg.Disk.EFISize != 538 {
		t.Errorf("efi_size = %d, want 538", cfg.Disk.EFISize)
	}
	if cfg.Disk.Filesystem != string(FilesystemLVM) {
		t.Errorf("filesystem = %s, want lvm", cfg.Disk.Filesystem)
	}
	if cfg.OS.Architecture != "x86_64" {
		t.Errorf("architecture = %s, want x86_64", cfg.OS.Architecture)
	}
	if cfg.OS.Hostname != "trusted-platform" {
		t.Errorf("hostname = %s, want trusted-platform", cfg.OS.Hostname)
	}
}

func TestGenerateInstallConfigEncryptionDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			Encryption: &EncryptionConfig{
				Password: "test123",
				// No cipher, keysize, hash, or PBKDF specified
			},
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22.2",
		},
	}

	data, err := GenerateInstallConfig(config)
	if err != nil {
		t.Fatalf("GenerateInstallConfig() failed: %v", err)
	}

	var cfg InstallConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	enc := cfg.Disk.Encryption
	if enc == nil {
		t.Fatal("encryption config is nil")
	}

	// Check encryption defaults
	if enc.Cipher != "aes-xts-plain64" {
		t.Errorf("cipher = %s, want aes-xts-plain64", enc.Cipher)
	}
	if enc.KeySize != 512 {
		t.Errorf("key_size = %d, want 512", enc.KeySize)
	}
	if enc.Hash != "sha256" {
		t.Errorf("hash = %s, want sha256", enc.Hash)
	}
	// PBKDF is intentionally not set in config - it's determined at runtime
	// based on FIPS mode by fips.GetKDF() in disk.go
	// Empty PBKDF means the runtime will select argon2id (non-FIPS) or pbkdf2 (FIPS)
	if enc.PBKDF != "" {
		t.Errorf("pbkdf = %s, want empty (runtime determined)", enc.PBKDF)
	}
	if enc.MappedName != "cryptroot" {
		t.Errorf("mapped_name = %s, want cryptroot", enc.MappedName)
	}
}

func TestGenerateInstallConfigTPMDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22.2",
		},
		EnableTPMSealing: true,
		// No PCRs specified
	}

	data, err := GenerateInstallConfig(config)
	if err != nil {
		t.Fatalf("GenerateInstallConfig() failed: %v", err)
	}

	var cfg InstallConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !cfg.Security.TPM.Enabled {
		t.Error("TPM not enabled")
	}

	// Check default PCRs
	expectedPCRs := []uint{0, 7, 9}
	if len(cfg.Security.TPM.SealPCRs) != len(expectedPCRs) {
		t.Errorf("len(seal_pcrs) = %d, want %d", len(cfg.Security.TPM.SealPCRs), len(expectedPCRs))
	}
	for i, pcr := range expectedPCRs {
		if cfg.Security.TPM.SealPCRs[i] != pcr {
			t.Errorf("seal_pcrs[%d] = %d, want %d", i, cfg.Security.TPM.SealPCRs[i], pcr)
		}
	}
}

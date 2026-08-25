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

package iso

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewCustomizer(t *testing.T) {
	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: "/tmp/test-overlay",
		},
	}

	customizer := NewCustomizer(config, nil)
	if customizer == nil {
		t.Fatal("NewCustomizer returned nil")
	}

	if customizer.config != config {
		t.Error("Config not set correctly")
	}

	if customizer.overlayDir != config.Directories.Overlay {
		t.Error("Overlay directory not set correctly")
	}

	if customizer.logger == nil {
		t.Error("Logger should be initialized with default")
	}
}

func TestGenerateInstallConfig(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		config         *PlatformISOConfig
		wantErr        bool
		validateConfig func(*testing.T, *installer.Config)
	}{
		{
			name: "basic LVM configuration",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.example.com/alpine",
				},
				Directories: DirectoryConfig{
					Overlay: tmpDir,
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				Security: SecurityConfig{
					SecureBoot: false,
					Lockdown:   false,
					FIPS:       false,
					TPM: TPMConfig{
						AutoUnseal: false,
						SealPCR:    "0,7,9",
					},
				},
				LUKS: LUKSConfig{
					Enabled: true,
					TPMOnly: false,
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *installer.Config) {
				if cfg.Disk.RootFilesystem != installer.FilesystemLVM {
					t.Errorf("Expected LVM filesystem, got %v", cfg.Disk.RootFilesystem)
				}
				if cfg.Disk.LVMVolumeGroup != "vg0" {
					t.Errorf("Expected vg0, got %s", cfg.Disk.LVMVolumeGroup)
				}
				if cfg.Disk.Encryption == nil {
					t.Error("Expected encryption config, got nil")
				}
				if cfg.OS.OS != installer.OSAlpine {
					t.Errorf("Expected Alpine OS, got %v", cfg.OS.OS)
				}
			},
		},
		{
			name: "ext4 with Secure Boot",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.example.com/alpine",
				},
				Directories: DirectoryConfig{
					Overlay: tmpDir,
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				Security: SecurityConfig{
					SecureBoot:   true,
					Lockdown:     true,
					LockdownMode: "confidentiality",
					FIPS:         false,
					TPM: TPMConfig{
						AutoUnseal: true,
						SealPCR:    "0,1,2,3,7",
					},
				},
				LUKS: LUKSConfig{
					Enabled: true,
					TPMOnly: true,
				},
				RootFS: RootFSConfig{
					Type: "ext4",
				},
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *installer.Config) {
				if cfg.Disk.RootFilesystem != installer.FilesystemExt4 {
					t.Errorf("Expected ext4 filesystem, got %v", cfg.Disk.RootFilesystem)
				}
				if cfg.SecureBoot == nil {
					t.Error("Expected Secure Boot config, got nil")
				}
				if !cfg.OS.Lockdown {
					t.Error("Expected lockdown enabled")
				}
				if cfg.OS.LockdownMode != "confidentiality" {
					t.Errorf("Expected confidentiality mode, got %s", cfg.OS.LockdownMode)
				}
				if !cfg.EnableTPMSealing {
					t.Error("Expected TPM sealing enabled")
				}
			},
		},
		{
			name: "FIPS mode",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.example.com/alpine",
				},
				Directories: DirectoryConfig{
					Overlay: tmpDir,
				},
				Platform: PlatformConfig{
					Version: "1.4.0-fips",
				},
				Security: SecurityConfig{
					SecureBoot: false,
					Lockdown:   false,
					FIPS:       true,
					TPM: TPMConfig{
						AutoUnseal: false,
					},
				},
				LUKS: LUKSConfig{
					Enabled: false,
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *installer.Config) {
				if !cfg.OS.FIPS {
					t.Error("Expected FIPS mode enabled")
				}
				if cfg.Disk.Encryption != nil {
					t.Error("Expected no encryption config")
				}
			},
		},
		{
			name: "invalid filesystem type",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.example.com/alpine",
				},
				Directories: DirectoryConfig{
					Overlay: tmpDir,
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "btrfs", // Invalid
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh overlay directory for each test
			testOverlay := filepath.Join(tmpDir, tt.name)
			tt.config.Directories.Overlay = testOverlay

			customizer := NewCustomizer(tt.config, logging.DefaultLogger())

			err := customizer.GenerateInstallConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateInstallConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify files were created
			configDir := filepath.Join(testOverlay, "etc", "platformd")
			installConfigPath := filepath.Join(configDir, "install.yaml")
			initrdConfigPath := filepath.Join(configDir, "initrd.yaml")

			if _, err := os.Stat(installConfigPath); err != nil {
				t.Errorf("Install config file not created: %v", err)
			}

			if _, err := os.Stat(initrdConfigPath); err != nil {
				t.Errorf("Initrd config file not created: %v", err)
			}

			// Read and validate installer config
			data, err := os.ReadFile(installConfigPath)
			if err != nil {
				t.Fatalf("Failed to read installer config: %v", err)
			}

			var installConfig installer.Config
			if err := yaml.Unmarshal(data, &installConfig); err != nil {
				t.Fatalf("Failed to unmarshal installer config: %v", err)
			}

			if tt.validateConfig != nil {
				tt.validateConfig(t, &installConfig)
			}
		})
	}
}

func TestBuildInstallerConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *PlatformISOConfig
		wantErr bool
		check   func(*testing.T, *installer.Config)
	}{
		{
			name: "LVM with LUKS",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://example.com",
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				LUKS: LUKSConfig{
					Enabled: true,
				},
				Security: SecurityConfig{
					TPM: TPMConfig{
						SealPCR: "0,7,9",
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, cfg *installer.Config) {
				if cfg.Disk.RootFilesystem != installer.FilesystemLVM {
					t.Error("Expected LVM filesystem")
				}
				if cfg.Disk.Encryption == nil {
					t.Error("Expected encryption config")
				}
				if cfg.Disk.Encryption.Version != "luks2" {
					t.Error("Expected LUKS2")
				}
			},
		},
		{
			name: "ext4 without LUKS",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://example.com",
				},
				RootFS: RootFSConfig{
					Type: "ext4",
				},
				LUKS: LUKSConfig{
					Enabled: false,
				},
			},
			wantErr: false,
			check: func(t *testing.T, cfg *installer.Config) {
				if cfg.Disk.RootFilesystem != installer.FilesystemExt4 {
					t.Error("Expected ext4 filesystem")
				}
				if cfg.Disk.Encryption != nil {
					t.Error("Expected no encryption config")
				}
			},
		},
		{
			name: "invalid filesystem",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://example.com",
				},
				RootFS: RootFSConfig{
					Type: "xfs",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customizer := NewCustomizer(tt.config, nil)

			cfg, err := customizer.buildInstallerConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("buildInstallerConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestBuildInitrdConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *PlatformISOConfig
		check  func(*testing.T, *initrd.Config)
	}{
		{
			name: "TPM with password fallback",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					TPM: TPMConfig{
						AutoUnseal: true,
						SealPCR:    "0,1,2,3,7",
					},
				},
				LUKS: LUKSConfig{
					Enabled: true,
					TPMOnly: false,
				},
			},
			check: func(t *testing.T, cfg *initrd.Config) {
				if cfg.Mode != initrd.ModeInstall {
					t.Error("Expected install mode")
				}
				if len(cfg.FallbackMethods) < 2 {
					t.Error("Expected at least 2 fallback methods")
				}
				if len(cfg.PCRSelection) == 0 {
					t.Error("Expected PCR selection")
				}
			},
		},
		{
			name: "TPM only (no password)",
			config: &PlatformISOConfig{
				Security: SecurityConfig{
					TPM: TPMConfig{
						AutoUnseal: true,
						SealPCR:    "0,7",
					},
				},
				LUKS: LUKSConfig{
					Enabled: true,
					TPMOnly: true,
				},
			},
			check: func(t *testing.T, cfg *initrd.Config) {
				hasPassword := false
				for _, method := range cfg.FallbackMethods {
					if method == luks.UnlockPassword {
						hasPassword = true
					}
				}
				if hasPassword {
					t.Error("Expected no password fallback")
				}
			},
		},
		{
			name: "no LUKS",
			config: &PlatformISOConfig{
				LUKS: LUKSConfig{
					Enabled: false,
				},
			},
			check: func(t *testing.T, cfg *initrd.Config) {
				if len(cfg.FallbackMethods) != 0 {
					t.Error("Expected no fallback methods")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customizer := NewCustomizer(tt.config, nil)

			cfg := customizer.buildInitrdConfig()
			if cfg == nil {
				t.Fatal("buildInitrdConfig returned nil")
			}

			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestBuildKernelCmdline(t *testing.T) {
	tests := []struct {
		name   string
		config *PlatformISOConfig
		want   []string // Expected strings to be present in cmdline
	}{
		{
			name: "basic LVM with LUKS",
			config: &PlatformISOConfig{
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				LUKS: LUKSConfig{
					Enabled: true,
				},
			},
			want: []string{"root=/dev/mapper/cryptroot", "rd.luks.name=cryptroot", "rd.lvm=1"},
		},
		{
			name: "ext4 without LUKS",
			config: &PlatformISOConfig{
				RootFS: RootFSConfig{
					Type: "ext4",
				},
				LUKS: LUKSConfig{
					Enabled: false,
				},
			},
			want: []string{"root=/dev/mapper/cryptroot", "rootfstype=ext4"},
		},
		{
			name: "with lockdown and FIPS",
			config: &PlatformISOConfig{
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				Security: SecurityConfig{
					Lockdown:     true,
					LockdownMode: "integrity",
					FIPS:         true,
				},
			},
			want: []string{"lockdown=integrity", "fips=1"},
		},
		{
			name: "lockdown default mode",
			config: &PlatformISOConfig{
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				Security: SecurityConfig{
					Lockdown: true,
				},
			},
			want: []string{"lockdown=confidentiality"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customizer := NewCustomizer(tt.config, nil)

			cmdline := customizer.buildKernelCmdline()
			if cmdline == "" {
				t.Error("buildKernelCmdline returned empty string")
			}

			for _, expected := range tt.want {
				if !strings.Contains(cmdline, expected) {
					t.Errorf("Expected cmdline to contain %q, got: %s", expected, cmdline)
				}
			}
		})
	}
}

func TestParsePCRSelection(t *testing.T) {
	tests := []struct {
		name      string
		selection string
		want      []uint
		wantErr   bool
	}{
		{
			name:      "valid single PCR",
			selection: "7",
			want:      []uint{7},
			wantErr:   false,
		},
		{
			name:      "valid multiple PCRs",
			selection: "0,7,9",
			want:      []uint{0, 7, 9},
			wantErr:   false,
		},
		{
			name:      "valid with spaces",
			selection: "0, 1, 2, 3",
			want:      []uint{0, 1, 2, 3},
			wantErr:   false,
		},
		{
			name:      "empty string",
			selection: "",
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "invalid character",
			selection: "0,7,a",
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "out of range",
			selection: "0,7,24",
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "negative number",
			selection: "0,7,-1",
			want:      nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePCRSelection(tt.selection)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePCRSelection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parsePCRSelection() got %v PCRs, want %v", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("parsePCRSelection() got[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestWriteConfigs(t *testing.T) {
	tmpDir := t.TempDir()

	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://example.com",
		},
		Directories: DirectoryConfig{
			Overlay: tmpDir,
		},
		RootFS: RootFSConfig{
			Type: "lvm",
		},
		LUKS: LUKSConfig{
			Enabled: true,
		},
		Security: SecurityConfig{
			TPM: TPMConfig{
				SealPCR: "0,7",
			},
		},
	}

	customizer := NewCustomizer(config, nil)

	// Test installer config write
	installConfig, err := customizer.buildInstallerConfig()
	if err != nil {
		t.Fatalf("buildInstallerConfig failed: %v", err)
	}

	installPath := filepath.Join(tmpDir, "install.yaml")
	if err := customizer.writeInstallerConfig(installConfig, installPath); err != nil {
		t.Errorf("writeInstallerConfig failed: %v", err)
	}

	// Verify file exists and is valid YAML
	data, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("Failed to read installer config: %v", err)
	}

	var readConfig installer.Config
	if err := yaml.Unmarshal(data, &readConfig); err != nil {
		t.Errorf("Failed to unmarshal installer config: %v", err)
	}

	// Test initrd config write
	initrdConfig := customizer.buildInitrdConfig()

	initrdPath := filepath.Join(tmpDir, "initrd.yaml")
	if err := customizer.writeInitrdConfig(initrdConfig, initrdPath); err != nil {
		t.Errorf("writeInitrdConfig failed: %v", err)
	}

	// Verify file exists and is valid YAML
	data, err = os.ReadFile(initrdPath)
	if err != nil {
		t.Fatalf("Failed to read initrd config: %v", err)
	}

	var readInitrdConfig initrd.Config
	if err := yaml.Unmarshal(data, &readInitrdConfig); err != nil {
		t.Errorf("Failed to unmarshal initrd config: %v", err)
	}
}

// TestCopySecureBootKeys_AutoGenerate tests that Secure Boot keys are automatically
// generated when they don't exist, regardless of the SecureBoot config flag.
func TestCopySecureBootKeys_AutoGenerate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create minimal directory structure
	isoDir := filepath.Join(tmpDir, "iso")
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		t.Fatalf("Failed to create ISO directory: %v", err)
	}

	// Configure with keys directory that doesn't exist
	keysDir := filepath.Join(tmpDir, "new-secure-boot-keys")

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work: tmpDir,
			ISO:  isoDir,
			Keys: keysDir,
		},
		Security: SecurityConfig{
			SecureBoot: false, // Even when false, keys should be generated
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()
	if err := customizer.CopySecureBootKeys(ctx); err != nil {
		t.Fatalf("CopySecureBootKeys failed: %v", err)
	}

	// Verify keys were generated in keys directory
	dbKey := filepath.Join(keysDir, "DB.key")
	dbCert := filepath.Join(keysDir, "DB.crt")

	if _, err := os.Stat(dbKey); os.IsNotExist(err) {
		t.Error("DB.key was not generated")
	}
	if _, err := os.Stat(dbCert); os.IsNotExist(err) {
		t.Error("DB.crt was not generated")
	}

	// Verify keys were copied to ISO directory
	isoKeysDir := filepath.Join(isoDir, "secure-boot-keys")
	isoDbKey := filepath.Join(isoKeysDir, "DB.key")
	isoDbCert := filepath.Join(isoKeysDir, "DB.crt")

	if _, err := os.Stat(isoDbKey); os.IsNotExist(err) {
		t.Error("DB.key was not copied to ISO")
	}
	if _, err := os.Stat(isoDbCert); os.IsNotExist(err) {
		t.Error("DB.crt was not copied to ISO")
	}
}

// TestCopySecureBootKeys_ExistingKeys tests that existing keys are used
// and copied to the ISO without regeneration.
func TestCopySecureBootKeys_ExistingKeys(t *testing.T) {
	tmpDir := t.TempDir()

	// Create keys directory with pre-existing keys
	keysDir := filepath.Join(tmpDir, "existing-keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("Failed to create keys directory: %v", err)
	}

	// A REAL matched pair: the staging gate validates the staged DB
	// material exactly as the installer's signing path will (parseable
	// key + certificate, matching public keys), so placeholder bytes
	// would correctly fail the build (round-11 review).
	testKeyContent, testCertContent := genTestSigningPairPEM(t)

	if err := os.WriteFile(filepath.Join(keysDir, "DB.key"), testKeyContent, 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "DB.crt"), testCertContent, 0644); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	// Create ISO directory
	isoDir := filepath.Join(tmpDir, "iso")
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		t.Fatalf("Failed to create ISO directory: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work: tmpDir,
			ISO:  isoDir,
			Keys: keysDir,
		},
		Security: SecurityConfig{
			SecureBoot: true,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()
	if err := customizer.CopySecureBootKeys(ctx); err != nil {
		t.Fatalf("CopySecureBootKeys failed: %v", err)
	}

	// Verify original keys still contain original content (not regenerated)
	keyData, err := os.ReadFile(filepath.Join(keysDir, "DB.key"))
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if string(keyData) != string(testKeyContent) {
		t.Error("Key file was modified (regenerated) when it should have been preserved")
	}

	// Verify keys were copied to ISO directory
	isoKeysDir := filepath.Join(isoDir, "secure-boot-keys")
	isoKeyData, err := os.ReadFile(filepath.Join(isoKeysDir, "DB.key"))
	if err != nil {
		t.Fatalf("Failed to read copied key file: %v", err)
	}
	if string(isoKeyData) != string(testKeyContent) {
		t.Error("Copied key content does not match original")
	}
}

// TestCopySecureBootKeys_DefaultKeysDir tests that the default keys directory
// is used when Keys config is empty.
func TestCopySecureBootKeys_DefaultKeysDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ISO directory
	isoDir := filepath.Join(tmpDir, "iso")
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		t.Fatalf("Failed to create ISO directory: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work: tmpDir,
			ISO:  isoDir,
			Keys: "", // Empty - should use default
		},
		Security: SecurityConfig{
			SecureBoot: false,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()
	if err := customizer.CopySecureBootKeys(ctx); err != nil {
		t.Fatalf("CopySecureBootKeys failed: %v", err)
	}

	// Verify keys directory was set to default
	expectedKeysDir := filepath.Join(tmpDir, "secure-boot-keys")
	if config.Directories.Keys != expectedKeysDir {
		t.Errorf("Expected keys directory to be set to %s, got %s", expectedKeysDir, config.Directories.Keys)
	}

	// Verify keys were generated in default location
	if _, err := os.Stat(filepath.Join(expectedKeysDir, "DB.key")); os.IsNotExist(err) {
		t.Error("DB.key was not generated in default keys directory")
	}

	// Verify keys were copied to ISO
	isoKeysDir := filepath.Join(isoDir, "secure-boot-keys")
	if _, err := os.Stat(filepath.Join(isoKeysDir, "DB.key")); os.IsNotExist(err) {
		t.Error("DB.key was not copied to ISO directory")
	}
}

// TestEnsureSecureBootKeysExist_NewKeys tests key generation when no keys exist.
func TestEnsureSecureBootKeysExist_NewKeys(t *testing.T) {
	tmpDir := t.TempDir()

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work: tmpDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	keysDir := filepath.Join(tmpDir, "test-keys")
	ctx := context.Background()
	if err := customizer.ensureSecureBootKeysExist(ctx, keysDir); err != nil {
		t.Fatalf("ensureSecureBootKeysExist failed: %v", err)
	}

	// Verify all key files were generated
	requiredFiles := []string{"PK.key", "PK.crt", "KEK.key", "KEK.crt", "DB.key", "DB.crt"}
	for _, file := range requiredFiles {
		path := filepath.Join(keysDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Required file %s was not generated", file)
		}
	}
}

// TestEnsureSecureBootKeysExist_ExistingKeys tests that existing keys are not overwritten.
func TestEnsureSecureBootKeysExist_ExistingKeys(t *testing.T) {
	tmpDir := t.TempDir()

	// Create keys directory with existing keys
	keysDir := filepath.Join(tmpDir, "existing-keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("Failed to create keys directory: %v", err)
	}

	// Create minimal existing key/cert
	testContent := []byte("ORIGINAL CONTENT")
	if err := os.WriteFile(filepath.Join(keysDir, "DB.key"), testContent, 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "DB.crt"), testContent, 0644); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work: tmpDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()
	if err := customizer.ensureSecureBootKeysExist(ctx, keysDir); err != nil {
		t.Fatalf("ensureSecureBootKeysExist failed: %v", err)
	}

	// Verify original content was preserved
	keyData, err := os.ReadFile(filepath.Join(keysDir, "DB.key"))
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if string(keyData) != string(testContent) {
		t.Error("Key file was modified when it should have been preserved")
	}
}

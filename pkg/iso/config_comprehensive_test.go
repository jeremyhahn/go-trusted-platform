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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestPlatformISOConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create dummy files for validation
	platformdBinary := filepath.Join(tmpDir, "platformd")
	os.WriteFile(platformdBinary, []byte("#!/bin/sh\necho platformd"), 0755)

	platformConfig := filepath.Join(tmpDir, "platform.yaml")
	os.WriteFile(platformConfig, []byte("version: 1.4.0\n"), 0644)

	tests := []struct {
		name    string
		config  *PlatformISOConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://dl-cdn.alpinelinux.org/alpine",
				},
				Platform: PlatformConfig{
					Version:         "1.4.0",
					PlatformdBinary: platformdBinary,
					ConfigFile:      platformConfig,
				},
				Directories: DirectoryConfig{
					Work:    tmpDir,
					ISO:     filepath.Join(tmpDir, "iso"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
			},
			wantErr: false,
		},
		{
			name: "missing Alpine version",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Mirror: "http://example.com",
				},
			},
			wantErr: true,
			errMsg:  "alpine version",
		},
		{
			name: "invalid root filesystem type",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://example.com",
				},
				Directories: DirectoryConfig{
					Work: "/tmp/work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "btrfs",
				},
			},
			wantErr: true,
			errMsg:  "root_fs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAlpineConfigFields(t *testing.T) {
	config := AlpineConfig{
		Version: "3.22.2",
		Mirror:  "http://dl-cdn.alpinelinux.org/alpine",
		ISO:     "alpine-standard-3.22.2-x86_64.iso",
		URL:     "http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-standard-3.22.2-x86_64.iso",
	}

	assert.Equal(t, "3.22.2", config.Version)
	assert.NotEmpty(t, config.Mirror)
}

func TestDirectoryConfigStructure(t *testing.T) {
	tmpDir := t.TempDir()

	config := DirectoryConfig{
		Work:    tmpDir,
		ISO:     filepath.Join(tmpDir, "iso"),
		Overlay: filepath.Join(tmpDir, "overlay"),
		Keys:    filepath.Join(tmpDir, "keys"),
	}

	assert.NotEmpty(t, config.Work)
	assert.NotEmpty(t, config.ISO)
	assert.NotEmpty(t, config.Overlay)
}

func TestSecurityConfigStructure(t *testing.T) {
	config := SecurityConfig{
		SecureBoot: true,
		Lockdown:   true,
		FIPS:       false,
		TPM: TPMConfig{
			AutoUnseal:      true,
			SealPCR:         "0,1,2,3,7",
			AutoUpgradeSeal: true,
		},
	}

	assert.True(t, config.SecureBoot)
	assert.True(t, config.Lockdown)
	assert.True(t, config.TPM.AutoUnseal)
}

func TestLUKSConfigStructure(t *testing.T) {
	tests := []struct {
		name   string
		config LUKSConfig
		check  func(*testing.T, LUKSConfig)
	}{
		{
			name: "LUKS enabled with password",
			config: LUKSConfig{
				Enabled: true,
				TPMOnly: false,
			},
			check: func(t *testing.T, cfg LUKSConfig) {
				assert.True(t, cfg.Enabled)
				assert.False(t, cfg.TPMOnly)
			},
		},
		{
			name: "TPM-only LUKS",
			config: LUKSConfig{
				Enabled: true,
				TPMOnly: true,
			},
			check: func(t *testing.T, cfg LUKSConfig) {
				assert.True(t, cfg.Enabled)
				assert.True(t, cfg.TPMOnly)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.check != nil {
				tt.check(t, tt.config)
			}
		})
	}
}

func TestRootFSConfigTypes(t *testing.T) {
	tests := []struct {
		name   string
		fsType string
	}{
		{
			name:   "lvm filesystem",
			fsType: "lvm",
		},
		{
			name:   "ext4 filesystem",
			fsType: "ext4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := RootFSConfig{
				Type: tt.fsType,
			}
			assert.Equal(t, tt.fsType, config.Type)
		})
	}
}

func TestISOBuildConfigLoadSave(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		setupFile   func() string
		wantErr     bool
		checkResult func(*testing.T, *ISOBuildConfig)
	}{
		{
			name: "valid config file",
			setupFile: func() string {
				configPath := filepath.Join(tmpDir, "valid-config.yaml")
				config := &ISOBuildConfig{
					AlpineVersion: "3.22.2",
					AlpineMirror:  "http://example.com",
					Architecture:  "x86_64",
					RootFS:        "lvm",
					WorkDir:       "/tmp/work",
				}
				data, _ := yaml.Marshal(config)
				os.WriteFile(configPath, data, 0644)
				return configPath
			},
			wantErr: false,
			checkResult: func(t *testing.T, cfg *ISOBuildConfig) {
				assert.Equal(t, "3.22.2", cfg.AlpineVersion)
				assert.Equal(t, "lvm", cfg.RootFS)
			},
		},
		{
			name: "nonexistent file",
			setupFile: func() string {
				return "/nonexistent/config.yaml"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := tt.setupFile()

			config, err := LoadISOBuildConfig(configPath)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				if tt.checkResult != nil {
					tt.checkResult(t, config)
				}
			}
		})
	}
}

func TestSaveLoadConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	original := &ISOBuildConfig{
		AlpineVersion: "3.22.2",
		AlpineMirror:  "http://dl-cdn.alpinelinux.org/alpine",
		Architecture:  "x86_64",
		RootFS:        "lvm",
		WorkDir:       "/tmp/work",
		SecureBoot:    true,
	}

	configPath := filepath.Join(tmpDir, "config.yaml")
	err := SaveISOBuildConfig(original, configPath)
	require.NoError(t, err)

	loaded, err := LoadISOBuildConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, original.AlpineVersion, loaded.AlpineVersion)
	assert.Equal(t, original.RootFS, loaded.RootFS)
	assert.Equal(t, original.SecureBoot, loaded.SecureBoot)
}

func TestPlatformISOConfigSetDefaults(t *testing.T) {
	config := &PlatformISOConfig{}
	config.SetDefaults()

	assert.NotEmpty(t, config.Directories.Work)
	assert.NotEmpty(t, config.Directories.ISO)
	assert.NotEmpty(t, config.Directories.Overlay)
}

func TestPlatformTypeValidation(t *testing.T) {
	tests := []struct {
		name    string
		ptype   PlatformType
		isValid bool
	}{
		{
			name:    "server type",
			ptype:   PlatformTypeServer,
			isValid: true,
		},
		{
			name:    "client type",
			ptype:   PlatformTypeClient,
			isValid: true,
		},
		{
			name:    "invalid type",
			ptype:   PlatformType("invalid"),
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isValid, tt.ptype.IsValid())
			assert.Equal(t, string(tt.ptype), tt.ptype.String())
		})
	}
}

func TestBuildOptionsStructure(t *testing.T) {
	options := BuildOptions{
		Debug:        true,
		QEMUDisk:     "/tmp/qemu.qcow2",
		QEMUDiskSize: "20G",
	}

	assert.True(t, options.Debug)
	assert.Equal(t, "/tmp/qemu.qcow2", options.QEMUDisk)
	assert.Equal(t, "20G", options.QEMUDiskSize)
}

func TestOutputConfigStructure(t *testing.T) {
	output := OutputConfig{
		ISO:       "output.iso",
		Directory: "/tmp/output",
		Checksum:  true,
	}

	assert.Equal(t, "output.iso", output.ISO)
	assert.Equal(t, "/tmp/output", output.Directory)
	assert.True(t, output.Checksum)
}

func TestFIPSConfigStructure(t *testing.T) {
	fips := FIPSConfig{
		ContainerRuntime: "docker",
		OpenSSLContainer: "openssl-fips-provider-builder",
		KernelContainer:  "fips-kernel-builder",
	}

	assert.Equal(t, "docker", fips.ContainerRuntime)
	assert.NotEmpty(t, fips.OpenSSLContainer)
	assert.NotEmpty(t, fips.KernelContainer)
}

func TestTPMConfigStructure(t *testing.T) {
	tpm := TPMConfig{
		AutoUnseal:      true,
		SealPCR:         "0,1,2,3,7",
		Device:          "/dev/tpm0",
		AutoUpgradeSeal: true,
	}

	assert.True(t, tpm.AutoUnseal)
	assert.Equal(t, "0,1,2,3,7", tpm.SealPCR)
	assert.Equal(t, "/dev/tpm0", tpm.Device)
}

func TestPlatformConfigFields(t *testing.T) {
	tmpDir := t.TempDir()

	validBinary := filepath.Join(tmpDir, "platformd")
	os.WriteFile(validBinary, []byte("#!/bin/sh\n"), 0755)

	config := PlatformConfig{
		Version:         "1.4.0",
		PlatformdBinary: validBinary,
		PlatformType:    PlatformTypeServer,
	}

	assert.Equal(t, "1.4.0", config.Version)
	assert.Equal(t, validBinary, config.PlatformdBinary)
	assert.True(t, config.PlatformType.IsValid())
}

func TestSecurityConfigDefaults(t *testing.T) {
	config := SecurityConfig{}

	// By default, all security features should be disabled
	assert.False(t, config.SecureBoot)
	assert.False(t, config.Lockdown)
	assert.False(t, config.FIPS)
	assert.False(t, config.TPM.AutoUnseal)
}

func TestPlatformISOConfigYAMLSerialization(t *testing.T) {
	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://example.com",
		},
		Directories: DirectoryConfig{
			Work: "/tmp/work",
		},
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
	}

	data, err := yaml.Marshal(config)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	yamlStr := string(data)
	assert.Contains(t, yamlStr, "alpine:")
	assert.Contains(t, yamlStr, "version: 3.22.2")
	assert.Contains(t, yamlStr, "platform:")
}

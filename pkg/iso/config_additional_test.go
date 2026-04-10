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

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestISOBuildConfig_ApplyOverrides(t *testing.T) {
	tests := []struct {
		name       string
		buildCfg   *ISOBuildConfig
		installCfg *installer.Config
		verify     func(*testing.T, *installer.Config)
	}{
		{
			name: "override_version",
			buildCfg: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
			},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					Version: "3.18.0",
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, "3.19.0", cfg.OS.Version)
			},
		},
		{
			name: "override_mirror",
			buildCfg: &ISOBuildConfig{
				AlpineMirror: "https://mirror.example.com",
			},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					Mirror: "https://old.example.com",
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, "https://mirror.example.com", cfg.OS.Mirror)
			},
		},
		{
			name: "override_architecture",
			buildCfg: &ISOBuildConfig{
				Architecture: "aarch64",
			},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					Architecture: "x86_64",
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, "aarch64", cfg.OS.Architecture)
			},
		},
		{
			name: "override_packages",
			buildCfg: &ISOBuildConfig{
				Packages: []string{"pkg1", "pkg2"},
			},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					Packages: []string{"old-pkg"},
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, []string{"pkg1", "pkg2"}, cfg.OS.Packages)
			},
		},
		{
			name: "override_platformd_binary",
			buildCfg: &ISOBuildConfig{
				PlatformdBinary: "/custom/platformd",
			},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					PlatformdBinary: "/old/platformd",
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, "/custom/platformd", cfg.OS.PlatformdBinary)
			},
		},
		{
			name: "override_debug_mode",
			buildCfg: &ISOBuildConfig{
				Debug: true,
			},
			installCfg: &installer.Config{
				Debug: false,
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.True(t, cfg.Debug)
			},
		},
		{
			name:     "no_overrides",
			buildCfg: &ISOBuildConfig{},
			installCfg: &installer.Config{
				OS: &installer.OSConfig{
					Version: "3.18.0",
					Mirror:  "https://example.com",
				},
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				assert.Equal(t, "3.18.0", cfg.OS.Version)
				assert.Equal(t, "https://example.com", cfg.OS.Mirror)
			},
		},
		{
			name: "nil_os_config",
			buildCfg: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
			},
			installCfg: &installer.Config{
				OS: nil,
			},
			verify: func(t *testing.T, cfg *installer.Config) {
				// Should not panic
				assert.Nil(t, cfg.OS)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.buildCfg.applyOverrides(tt.installCfg)
			tt.verify(t, tt.installCfg)
		})
	}
}

func TestISOBuildConfig_GetInstallConfig_WithProfile(t *testing.T) {
	buildCfg := &ISOBuildConfig{
		Profile: "dev",
	}

	cfg, err := buildCfg.GetInstallConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestISOBuildConfig_GetInstallConfig_WithProvidedConfigFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create a temporary installer config file
	configFile := filepath.Join(tempDir, "installer.yaml")
	testConfig := &installer.Config{
		Debug: true,
		OS: &installer.OSConfig{
			Version: "3.18.0",
		},
	}
	require.NoError(t, installer.SaveConfig(testConfig, configFile))

	buildCfg := &ISOBuildConfig{}

	cfg, err := buildCfg.GetInstallConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestISOBuildConfig_GetInstallConfig_Generated(t *testing.T) {
	buildCfg := &ISOBuildConfig{
		AlpineVersion: "3.19.0",
		AlpineMirror:  "https://mirror.example.com",
		Architecture:  "x86_64",
		WorkDir:       "/tmp/work",
	}

	cfg, err := buildCfg.GetInstallConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.OS)
}

func TestISOBuildConfig_GetInstallConfig_InvalidProfile(t *testing.T) {
	buildCfg := &ISOBuildConfig{
		Profile: "nonexistent-profile",
	}

	_, err := buildCfg.GetInstallConfig()
	assert.Error(t, err)
}

func TestISOBuildConfig_GenerateInstallConfig(t *testing.T) {
	buildCfg := &ISOBuildConfig{
		AlpineVersion: "3.19.0",
		AlpineMirror:  "https://mirror.example.com",
		Architecture:  "x86_64",
		WorkDir:       "/tmp/work",
		Packages:      []string{"pkg1", "pkg2"},
	}

	cfg := buildCfg.generateInstallConfig()
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.OS)
	assert.Equal(t, "3.19.0", cfg.OS.Version)
	assert.Equal(t, "https://mirror.example.com", cfg.OS.Mirror)
	assert.Equal(t, "x86_64", cfg.OS.Architecture)
	assert.Equal(t, []string{"pkg1", "pkg2"}, cfg.OS.Packages)
}

func TestISOBuildConfig_ResolveWorkDir_CreateNew(t *testing.T) {
	tempBase := t.TempDir()
	workDir := filepath.Join(tempBase, "new-work-dir")

	buildCfg := &ISOBuildConfig{
		WorkDir: workDir,
	}

	resolvedDir, err := buildCfg.ResolveWorkDir()
	require.NoError(t, err)
	assert.Equal(t, workDir, resolvedDir)

	// Verify directory was created
	info, err := os.Stat(workDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestISOBuildConfig_ResolveWorkDir_ExistingDir(t *testing.T) {
	tempBase := t.TempDir()
	workDir := filepath.Join(tempBase, "existing-work-dir")
	require.NoError(t, os.MkdirAll(workDir, 0755))

	buildCfg := &ISOBuildConfig{
		WorkDir: workDir,
	}

	resolvedDir, err := buildCfg.ResolveWorkDir()
	require.NoError(t, err)
	assert.Equal(t, workDir, resolvedDir)
}

func TestISOBuildConfig_ResolveWorkDir_DefaultLocation(t *testing.T) {
	buildCfg := &ISOBuildConfig{}

	resolvedDir, err := buildCfg.ResolveWorkDir()
	require.NoError(t, err)
	assert.NotEmpty(t, resolvedDir)
}

func TestISOBuildConfig_ResolveBinaries_ProvidedPaths(t *testing.T) {
	tempDir := t.TempDir()

	platformdPath := filepath.Join(tempDir, "platformd")
	require.NoError(t, os.WriteFile(platformdPath, []byte("#!/bin/bash"), 0755))

	buildCfg := &ISOBuildConfig{
		PlatformdBinary: platformdPath,
	}

	err := buildCfg.ResolveBinaries()
	require.NoError(t, err)
	assert.Equal(t, platformdPath, buildCfg.PlatformdBinary)
}

func TestISOBuildConfig_ResolveBinaries_NotFound(t *testing.T) {
	buildCfg := &ISOBuildConfig{
		PlatformdBinary: "/nonexistent/platformd",
	}

	err := buildCfg.ResolveBinaries()
	assert.Error(t, err)
}

func TestISOBuildConfig_Validate_CompleteConfig(t *testing.T) {
	buildCfg := DefaultISOBuildConfig()
	buildCfg.WorkDir = t.TempDir()

	err := buildCfg.Validate()
	assert.NoError(t, err)
}

func TestISOBuildConfig_Validate_AllFields(t *testing.T) {
	tests := []struct {
		name    string
		config  *ISOBuildConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_with_profile",
			config: &ISOBuildConfig{
				Profile:       "dev",
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
			},
			wantErr: false,
		},
		{
			name: "invalid_with_both_config_and_profile",
			config: &ISOBuildConfig{
				Profile:       "dev",
				ConfigFile:    "/tmp/config.yaml",
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
			},
			wantErr: true,
			errMsg:  "only one of",
		},
		{
			name: "invalid_root_filesystem",
			config: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
				RootFS:        "invalid-fs",
			},
			wantErr: true,
			errMsg:  "must be",
		},
		{
			name: "valid_lockdown_modes",
			config: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
				Lockdown:      true,
				LockdownMode:  "confidentiality",
			},
			wantErr: false,
		},
		{
			name: "invalid_lockdown_mode",
			config: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
				Lockdown:      true,
				LockdownMode:  "invalid-mode",
			},
			wantErr: true,
			errMsg:  "lockdown-mode must be",
		},
		{
			name: "valid_after_install_actions",
			config: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
				AfterInstall:  "reboot",
			},
			wantErr: false,
		},
		{
			name: "invalid_after_install_action",
			config: &ISOBuildConfig{
				AlpineVersion: "3.19.0",
				AlpineMirror:  "https://mirror.example.com",
				Architecture:  "x86_64",
				WorkDir:       "/tmp/work",
				AfterInstall:  "invalid-action",
			},
			wantErr: true,
			errMsg:  "after-install must be",
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

func TestDownloadConfig_Validate_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		config  *DownloadConfig
		wantErr bool
	}{
		{
			name: "valid_minimal",
			config: &DownloadConfig{
				Version:      "3.19.0",
				Mirror:       "https://mirror.example.com",
				Architecture: "x86_64",
				OutputDir:    "/tmp/output",
			},
			wantErr: false,
		},
		{
			name: "empty_version",
			config: &DownloadConfig{
				Version: "",
				Mirror:  "https://mirror.example.com",
			},
			wantErr: true,
		},
		{
			name: "empty_mirror",
			config: &DownloadConfig{
				Version: "3.19.0",
				Mirror:  "",
			},
			wantErr: true,
		},
		{
			name: "invalid_arch",
			config: &DownloadConfig{
				Version:      "3.19.0",
				Mirror:       "https://mirror.example.com",
				Architecture: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCustomizeConfig_Validate_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	platformdBinary := filepath.Join(tempDir, "platformd")
	require.NoError(t, os.WriteFile(platformdBinary, []byte("#!/bin/bash"), 0755))

	workDir := filepath.Join(tempDir, "work")
	require.NoError(t, os.MkdirAll(workDir, 0755))

	tests := []struct {
		name    string
		config  *CustomizeConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_config",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: platformdBinary,
				WorkDir:         workDir,
			},
			wantErr: false,
		},
		{
			name: "missing_iso_dir",
			config: &CustomizeConfig{
				ISODir:          "",
				PlatformdBinary: platformdBinary,
				WorkDir:         workDir,
			},
			wantErr: true,
			errMsg:  "iso directory is required",
		},
		{
			name: "missing_platformd",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: "",
				WorkDir:         workDir,
			},
			wantErr: true,
			errMsg:  "platformd binary is required",
		},
		{
			name: "missing_work_dir",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: platformdBinary,
				WorkDir:         "",
			},
			wantErr: true,
			errMsg:  "work directory is required",
		},
		{
			name: "iso_dir_not_found",
			config: &CustomizeConfig{
				ISODir:          "/nonexistent/iso",
				PlatformdBinary: platformdBinary,
				WorkDir:         workDir,
			},
			wantErr: true,
			errMsg:  "iso directory not found",
		},
		{
			name: "platformd_not_found",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: "/nonexistent/platformd",
				WorkDir:         workDir,
			},
			wantErr: true,
			errMsg:  "platformd binary not found",
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

func TestLoadISOBuildConfig_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.yaml")

	// Write invalid YAML
	require.NoError(t, os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644))

	_, err := LoadISOBuildConfig(configPath)
	assert.Error(t, err)
}

func TestSaveISOBuildConfig_InvalidPath(t *testing.T) {
	cfg := DefaultISOBuildConfig()

	err := SaveISOBuildConfig(cfg, "/invalid/path/that/does/not/exist/config.yaml")
	assert.Error(t, err)
}

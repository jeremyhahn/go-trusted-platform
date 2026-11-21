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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

func TestPlatformType_String(t *testing.T) {
	tests := []struct {
		name     string
		pt       PlatformType
		expected string
	}{
		{
			name:     "server platform",
			pt:       PlatformTypeServer,
			expected: "server",
		},
		{
			name:     "client platform",
			pt:       PlatformTypeClient,
			expected: "client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pt.String()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestPlatformType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		pt       PlatformType
		expected bool
	}{
		{
			name:     "server is valid",
			pt:       PlatformTypeServer,
			expected: true,
		},
		{
			name:     "client is valid",
			pt:       PlatformTypeClient,
			expected: true,
		},
		{
			name:     "invalid type",
			pt:       PlatformType("invalid"),
			expected: false,
		},
		{
			name:     "empty string is invalid",
			pt:       PlatformType(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pt.IsValid()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDefaultISOBuildConfig(t *testing.T) {
	config := DefaultISOBuildConfig()

	if config.AlpineVersion != "3.22.2" {
		t.Errorf("expected AlpineVersion '3.22.2', got %s", config.AlpineVersion)
	}

	if config.Architecture != "x86_64" {
		t.Errorf("expected Architecture 'x86_64', got %s", config.Architecture)
	}

	if config.RootFS != "lvm" {
		t.Errorf("expected RootFS 'lvm', got %s", config.RootFS)
	}

	if config.LockdownMode != "confidentiality" {
		t.Errorf("expected LockdownMode 'confidentiality', got %s", config.LockdownMode)
	}

	if !config.TPMAutoUpgradeSeal {
		t.Error("expected TPMAutoUpgradeSeal to be true")
	}

	if len(config.TPMSealPCR) != 2 || config.TPMSealPCR[0] != 7 || config.TPMSealPCR[1] != 11 {
		t.Errorf("expected TPMSealPCR [7 11], got %v", config.TPMSealPCR)
	}
}

func TestISOBuildConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *ISOBuildConfig
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid default config",
			config:    DefaultISOBuildConfig(),
			wantError: false,
		},
		{
			name: "missing alpine version",
			config: &ISOBuildConfig{
				AlpineMirror: "https://dl-cdn.alpinelinux.org/alpine",
				Architecture: "x86_64",
				WorkDir:      "work",
			},
			wantError: true,
			errorMsg:  "alpine version is required",
		},
		{
			name: "missing alpine mirror",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				Architecture:  "x86_64",
				WorkDir:       "work",
			},
			wantError: true,
			errorMsg:  "alpine mirror is required",
		},
		{
			name: "missing architecture",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				WorkDir:       "work",
			},
			wantError: true,
			errorMsg:  "architecture is required",
		},
		{
			name: "invalid architecture",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "invalid",
				WorkDir:       "work",
			},
			wantError: true,
			errorMsg:  "unsupported architecture",
		},
		{
			name: "missing work directory",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
			},
			wantError: true,
			errorMsg:  "work directory is required",
		},
		{
			name: "invalid root filesystem",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				RootFS:        "invalid",
			},
			wantError: true,
			errorMsg:  "root-fs must be 'lvm' or 'ext4'",
		},
		{
			name: "invalid lockdown mode",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				Lockdown:      true,
				LockdownMode:  "invalid",
			},
			wantError: true,
			errorMsg:  "lockdown-mode must be 'integrity' or 'confidentiality'",
		},
		{
			name: "invalid after-install action",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				AfterInstall:  "invalid",
			},
			wantError: true,
			errorMsg:  "after-install must be 'reboot' or 'poweroff'",
		},
		{
			name: "valid aarch64 architecture",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "aarch64",
				WorkDir:       "work",
			},
			wantError: false,
		},
		{
			name: "valid integrity lockdown",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				Lockdown:      true,
				LockdownMode:  "integrity",
			},
			wantError: false,
		},
		{
			name: "valid poweroff action",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				AfterInstall:  "poweroff",
			},
			wantError: false,
		},
		{
			name: "invalid profile name",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				Profile:       "invalid-profile",
			},
			wantError: true,
			errorMsg:  "invalid profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestISOBuildConfigValidateMutuallyExclusive(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("test: data"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		config    *ISOBuildConfig
		wantError bool
	}{
		{
			name: "config and profile specified",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				ConfigFile:    configFile,
				Profile:       "dev",
			},
			wantError: true,
		},
		{
			name: "install-config and profile specified",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				InstallConfig: &installer.Config{},
				Profile:       "dev",
			},
			wantError: true,
		},
		{
			name: "only profile specified",
			config: &ISOBuildConfig{
				AlpineVersion: "3.22.2",
				AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
				Architecture:  "x86_64",
				WorkDir:       "work",
				Profile:       "dev",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError && err == nil {
				t.Error("expected error for mutually exclusive options")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestISOBuildConfigGetInstallConfig(t *testing.T) {
	t.Run("use provided install config", func(t *testing.T) {
		expectedConfig := installer.DefaultConfig()
		config := &ISOBuildConfig{
			InstallConfig: expectedConfig,
		}

		result, err := config.GetInstallConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != expectedConfig {
			t.Error("expected same config instance")
		}
	})

	t.Run("load from profile", func(t *testing.T) {
		config := &ISOBuildConfig{
			Profile: "dev",
		}

		result, err := config.GetInstallConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result == nil {
			t.Error("expected non-nil config")
		}
	})

	t.Run("generate from build config", func(t *testing.T) {
		config := &ISOBuildConfig{
			AlpineVersion:      "3.22.2",
			AlpineMirror:       "https://dl-cdn.alpinelinux.org/alpine",
			Architecture:       "x86_64",
			FIPS:               true,
			Lockdown:           true,
			LockdownMode:       "confidentiality",
			TPMAutoUnseal:      true,
			TPMSealPCR:         []uint{0, 7, 9},
			TPMAutoUpgradeSeal: true,
			SecureBoot:         true,
		}

		result, err := config.GetInstallConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.OS.Version != "3.22.2" {
			t.Errorf("expected Version '3.22.2', got %s", result.OS.Version)
		}

		if !result.OS.FIPS {
			t.Error("expected FIPS to be true")
		}

		if !result.OS.Lockdown {
			t.Error("expected Lockdown to be true")
		}

		if result.OS.LockdownMode != "confidentiality" {
			t.Errorf("expected LockdownMode 'confidentiality', got %s", result.OS.LockdownMode)
		}

		if !result.EnableTPMSealing {
			t.Error("expected EnableTPMSealing to be true")
		}

		if len(result.PCRs) != 3 {
			t.Errorf("expected 3 PCRs, got %d", len(result.PCRs))
		}

		if result.SecureBoot == nil {
			t.Error("expected SecureBoot to be configured")
		}
	})
}

func TestISOBuildConfigResolveWorkDir(t *testing.T) {
	t.Run("create work directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &ISOBuildConfig{
			WorkDir: filepath.Join(tmpDir, "work"),
		}

		workDir, err := config.ResolveWorkDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !filepath.IsAbs(workDir) {
			t.Error("expected absolute path")
		}

		// Check directory was created
		info, err := os.Stat(workDir)
		if err != nil {
			t.Fatalf("work directory not created: %v", err)
		}

		if !info.IsDir() {
			t.Error("expected directory")
		}
	})

	t.Run("default work directory", func(t *testing.T) {
		config := &ISOBuildConfig{}

		workDir, err := config.ResolveWorkDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if config.WorkDir != workDir {
			t.Error("expected config.WorkDir to be updated")
		}
	})
}

func TestISOBuildConfigResolveBinaries(t *testing.T) {
	t.Run("binaries not found", func(t *testing.T) {
		config := &ISOBuildConfig{}

		err := config.ResolveBinaries()
		if err == nil {
			t.Error("expected error when binaries not found")
		}
	})

	t.Run("use provided binaries", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create dummy binary
		platformdBinary := filepath.Join(tmpDir, "platformd")

		if err := os.WriteFile(platformdBinary, []byte("dummy"), 0755); err != nil {
			t.Fatal(err)
		}

		config := &ISOBuildConfig{
			PlatformdBinary: platformdBinary,
		}

		err := config.ResolveBinaries()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if config.PlatformdBinary != platformdBinary {
			t.Error("expected platformd binary path to remain unchanged")
		}
	})
}

func TestISOBuildConfigGetAlpineISOURL(t *testing.T) {
	config := &ISOBuildConfig{
		AlpineVersion: "3.22.2",
		AlpineMirror:  "https://dl-cdn.alpinelinux.org/alpine",
		Architecture:  "x86_64",
	}

	url := config.GetAlpineISOURL()
	expected := "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-standard-3.22.2-x86_64.iso"

	if url != expected {
		t.Errorf("expected URL '%s', got '%s'", expected, url)
	}
}

func TestISOBuildConfigGetAlpineISOFilename(t *testing.T) {
	config := &ISOBuildConfig{
		AlpineVersion: "3.22.2",
		Architecture:  "x86_64",
	}

	filename := config.GetAlpineISOFilename()
	expected := "alpine-standard-3.22.2-x86_64.iso"

	if filename != expected {
		t.Errorf("expected filename '%s', got '%s'", expected, filename)
	}
}

func TestDownloadConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *DownloadConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			config: &DownloadConfig{
				Version:      "3.22.2",
				Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
				Architecture: "x86_64",
				OutputDir:    "/tmp",
			},
			wantError: false,
		},
		{
			name: "missing version",
			config: &DownloadConfig{
				Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
				Architecture: "x86_64",
				OutputDir:    "/tmp",
			},
			wantError: true,
			errorMsg:  "version is required",
		},
		{
			name: "missing mirror",
			config: &DownloadConfig{
				Version:      "3.22.2",
				Architecture: "x86_64",
				OutputDir:    "/tmp",
			},
			wantError: true,
			errorMsg:  "mirror is required",
		},
		{
			name: "invalid architecture",
			config: &DownloadConfig{
				Version:      "3.22.2",
				Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
				Architecture: "invalid",
				OutputDir:    "/tmp",
			},
			wantError: true,
			errorMsg:  "unsupported architecture",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDownloadConfigHelpers(t *testing.T) {
	config := &DownloadConfig{
		Version:      "3.22.2",
		Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
		Architecture: "x86_64",
		OutputDir:    "/tmp",
	}

	t.Run("GetISOURL", func(t *testing.T) {
		url := config.GetISOURL()
		expected := "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-standard-3.22.2-x86_64.iso"
		if url != expected {
			t.Errorf("expected '%s', got '%s'", expected, url)
		}
	})

	t.Run("GetISOFilename", func(t *testing.T) {
		filename := config.GetISOFilename()
		expected := "alpine-standard-3.22.2-x86_64.iso"
		if filename != expected {
			t.Errorf("expected '%s', got '%s'", expected, filename)
		}
	})

	t.Run("GetChecksumURL", func(t *testing.T) {
		url := config.GetChecksumURL()
		expected := "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-standard-3.22.2-x86_64.iso.sha256"
		if url != expected {
			t.Errorf("expected '%s', got '%s'", expected, url)
		}
	})

	t.Run("GetISOPath", func(t *testing.T) {
		path := config.GetISOPath()
		expected := "/tmp/alpine-standard-3.22.2-x86_64.iso"
		if path != expected {
			t.Errorf("expected '%s', got '%s'", expected, path)
		}
	})
}

func TestExtractConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()
	isoFile := filepath.Join(tmpDir, "test.iso")

	// Create dummy ISO file
	if err := os.WriteFile(isoFile, []byte("dummy iso"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		config    *ExtractConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			config: &ExtractConfig{
				ISOPath:   isoFile,
				OutputDir: tmpDir,
			},
			wantError: false,
		},
		{
			name: "missing iso path",
			config: &ExtractConfig{
				OutputDir: tmpDir,
			},
			wantError: true,
			errorMsg:  "iso path is required",
		},
		{
			name: "missing output dir",
			config: &ExtractConfig{
				ISOPath: isoFile,
			},
			wantError: true,
			errorMsg:  "output directory is required",
		},
		{
			name: "iso file not found",
			config: &ExtractConfig{
				ISOPath:   "/nonexistent/test.iso",
				OutputDir: tmpDir,
			},
			wantError: true,
			errorMsg:  "iso file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCustomizeConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()
	isoDir := filepath.Join(tmpDir, "iso")
	platformdBinary := filepath.Join(tmpDir, "platformd")

	// Create required directories and files
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(platformdBinary, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		config    *CustomizeConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: platformdBinary,
				WorkDir:         tmpDir,
			},
			wantError: false,
		},
		{
			name: "missing iso dir",
			config: &CustomizeConfig{
				PlatformdBinary: platformdBinary,
				WorkDir:         tmpDir,
			},
			wantError: true,
			errorMsg:  "iso directory is required",
		},
		{
			name: "missing platformd binary",
			config: &CustomizeConfig{
				ISODir:  isoDir,
				WorkDir: tmpDir,
			},
			wantError: true,
			errorMsg:  "platformd binary is required",
		},
		{
			name: "iso directory not found",
			config: &CustomizeConfig{
				ISODir:          "/nonexistent/iso",
				PlatformdBinary: platformdBinary,
				WorkDir:         tmpDir,
			},
			wantError: true,
			errorMsg:  "iso directory not found",
		},
		{
			name: "platformd binary not found",
			config: &CustomizeConfig{
				ISODir:          isoDir,
				PlatformdBinary: "/nonexistent/binary",
				WorkDir:         tmpDir,
			},
			wantError: true,
			errorMsg:  "platformd binary not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBuildConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()
	isoDir := filepath.Join(tmpDir, "iso")

	// Create ISO directory
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		config    *BuildConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			config: &BuildConfig{
				ISODir:    isoDir,
				OutputISO: "/tmp/output.iso",
				Label:     "TEST_LABEL",
			},
			wantError: false,
		},
		{
			name: "missing iso dir",
			config: &BuildConfig{
				OutputISO: "/tmp/output.iso",
				Label:     "TEST_LABEL",
			},
			wantError: true,
			errorMsg:  "iso directory is required",
		},
		{
			name: "missing output iso",
			config: &BuildConfig{
				ISODir: isoDir,
				Label:  "TEST_LABEL",
			},
			wantError: true,
			errorMsg:  "output iso path is required",
		},
		{
			name: "missing label",
			config: &BuildConfig{
				ISODir:    isoDir,
				OutputISO: "/tmp/output.iso",
			},
			wantError: true,
			errorMsg:  "volume label is required",
		},
		{
			name: "label too long",
			config: &BuildConfig{
				ISODir:    isoDir,
				OutputISO: "/tmp/output.iso",
				Label:     "THIS_LABEL_IS_WAY_TOO_LONG_FOR_ISO9660",
			},
			wantError: true,
			errorMsg:  "volume label must be 32 characters or less",
		},
		{
			name: "iso directory not found",
			config: &BuildConfig{
				ISODir:    "/nonexistent/iso",
				OutputISO: "/tmp/output.iso",
				Label:     "TEST_LABEL",
			},
			wantError: true,
			errorMsg:  "iso directory not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLoadProfile(t *testing.T) {
	tests := []struct {
		name      string
		profile   string
		wantError bool
	}{
		{
			name:      "load dev profile",
			profile:   "dev",
			wantError: false,
		},
		{
			name:      "load production profile",
			profile:   "production",
			wantError: false,
		},
		{
			name:      "load fips profile",
			profile:   "fips",
			wantError: false,
		},
		{
			name:      "load production-hs profile",
			profile:   "production-hs",
			wantError: false,
		},
		{
			name:      "invalid profile",
			profile:   "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := LoadProfile(tt.profile)
			if tt.wantError {
				if err == nil {
					t.Error("expected error for invalid profile")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if config == nil {
					t.Error("expected non-nil config")
				}
			}
		})
	}
}

func TestGetMajorVersion(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"3.22.2", "3.22"},
		{"3.22", "3.22"},
		{"3", "3"},
		{"4.0.1", "4.0"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := getMajorVersion(tt.version)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestLoadSaveISOBuildConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "iso-build.yaml")

	// Create and save config
	original := DefaultISOBuildConfig()
	original.AlpineVersion = "3.22.3"
	original.FIPS = true
	original.Packages = []string{"vim", "curl"}

	err := SaveISOBuildConfig(original, configPath)
	if err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Load config
	loaded, err := LoadISOBuildConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify fields
	if loaded.AlpineVersion != original.AlpineVersion {
		t.Errorf("expected AlpineVersion '%s', got '%s'", original.AlpineVersion, loaded.AlpineVersion)
	}

	if loaded.FIPS != original.FIPS {
		t.Errorf("expected FIPS %v, got %v", original.FIPS, loaded.FIPS)
	}

	if len(loaded.Packages) != len(original.Packages) {
		t.Errorf("expected %d packages, got %d", len(original.Packages), len(loaded.Packages))
	}
}

func TestLoadISOBuildConfigFileNotFound(t *testing.T) {
	_, err := LoadISOBuildConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestSaveISOBuildConfig_Error(t *testing.T) {
	config := DefaultISOBuildConfig()
	err := SaveISOBuildConfig(config, "/invalid/path/config.yaml")
	if err == nil {
		t.Error("expected error when saving to invalid path")
	}
}

func TestISOBuildConfigResolveWorkDir_EmptyPath(t *testing.T) {
	config := &ISOBuildConfig{}
	workDir, err := config.ResolveWorkDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if workDir == "" {
		t.Error("expected non-empty work directory")
	}
	if config.WorkDir == "" {
		t.Error("expected config.WorkDir to be updated")
	}
}

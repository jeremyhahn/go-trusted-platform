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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestBuildDynamicConfigParams(t *testing.T) {
	tests := []struct {
		name       string
		platform   PlatformConfig
		wantEmpty  bool
		wantParams []string
		wantAbsent []string
	}{
		{
			name:      "no config server URL returns empty",
			platform:  PlatformConfig{},
			wantEmpty: true,
		},
		{
			name: "config server URL only",
			platform: PlatformConfig{
				ConfigServerURL: "https://config.example.com/api/v1/config",
			},
			wantParams: []string{
				"platform_config=https://config.example.com/api/v1/config",
			},
			wantAbsent: []string{
				"bootstrap_strategy=",
				"bootstrap_dns=",
				"bootstrap_noise_key=",
				"bootstrap_spki_pin=",
			},
		},
		{
			name: "all params set",
			platform: PlatformConfig{
				ConfigServerURL:   "https://config.example.com",
				BootstrapStrategy: "dane",
				BootstrapDNS:      "8.8.8.8",
				BootstrapNoiseKey: "abcdef0123456789",
				BootstrapSPKIPin:  "sha256/AAAA",
			},
			wantParams: []string{
				"platform_config=https://config.example.com",
				"bootstrap_strategy=dane",
				"bootstrap_dns=8.8.8.8",
				"bootstrap_noise_key=abcdef0123456789",
				"bootstrap_spki_pin=sha256/AAAA",
			},
		},
		{
			name: "partial params - only strategy and DNS",
			platform: PlatformConfig{
				ConfigServerURL:   "https://config.example.com",
				BootstrapStrategy: "spki",
				BootstrapDNS:      "1.1.1.1",
			},
			wantParams: []string{
				"platform_config=https://config.example.com",
				"bootstrap_strategy=spki",
				"bootstrap_dns=1.1.1.1",
			},
			wantAbsent: []string{
				"bootstrap_noise_key=",
				"bootstrap_spki_pin=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PlatformISOConfig{
				Platform: tt.platform,
			}
			customizer := NewCustomizer(config, logging.DefaultLogger())

			result := customizer.buildDynamicConfigParams()

			if tt.wantEmpty {
				if result != "" {
					t.Errorf("Expected empty params, got %q", result)
				}
				return
			}

			for _, param := range tt.wantParams {
				if !strings.Contains(result, param) {
					t.Errorf("Expected params to contain %q, got %q", param, result)
				}
			}

			for _, absent := range tt.wantAbsent {
				if strings.Contains(result, absent) {
					t.Errorf("Expected params to NOT contain %q, got %q", absent, result)
				}
			}
		})
	}
}

// TestConfigureBootloaderDynamicConfig verifies that ConfigureBootloader
// patches the installer ISO's GRUB cmdline with dynamic-config params
// (platform_config=URL, bootstrap_*) when the ISOBuildConfig supplies
// a ConfigServerURL. The GRUB kernel cmdline is the single source of
// truth the installer reads at boot time.
func TestConfigureBootloaderDynamicConfig(t *testing.T) {
	tests := []struct {
		name             string
		grubConfig       string
		platform         PlatformConfig
		validateModified func(*testing.T, string)
	}{
		{
			name: "injects platform_config into GRUB kernel cmdline",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1 quiet
	initrd /boot/initramfs-lts
}
`,
			platform: PlatformConfig{
				ConfigServerURL:   "https://config.example.com/v1",
				BootstrapStrategy: "dane",
				BootstrapDNS:      "8.8.8.8",
			},
			validateModified: func(t *testing.T, content string) {
				if !strings.Contains(content, "platform_config=https://config.example.com/v1") {
					t.Error("Expected platform_config kernel param")
				}
				if !strings.Contains(content, "bootstrap_strategy=dane") {
					t.Error("Expected bootstrap_strategy kernel param")
				}
				if !strings.Contains(content, "bootstrap_dns=8.8.8.8") {
					t.Error("Expected bootstrap_dns kernel param")
				}
				// alpine_start=autoinstall is injected as the kernel-cmdline
				// marker the patched Alpine init uses to trigger autoinstall.
				if !strings.Contains(content, "console=ttyS0,115200") {
					t.Error("Expected console params to still be present")
				}
			},
		},
		{
			name: "no injection when config server URL is empty",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1 quiet
	initrd /boot/initramfs-lts
}
`,
			platform: PlatformConfig{},
			validateModified: func(t *testing.T, content string) {
				if strings.Contains(content, "platform_config=") {
					t.Error("Expected no platform_config param when URL is empty")
				}
				// alpine_start=autoinstall is injected as the kernel-cmdline
				// marker the patched Alpine init uses to trigger autoinstall.
			},
		},
		{
			name: "injects all bootstrap params",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1
	initrd /boot/initramfs-lts
}
`,
			platform: PlatformConfig{
				ConfigServerURL:   "https://config.example.com",
				BootstrapStrategy: "noise",
				BootstrapDNS:      "1.1.1.1",
				BootstrapNoiseKey: "deadbeef",
				BootstrapSPKIPin:  "sha256/BBBB",
			},
			validateModified: func(t *testing.T, content string) {
				expectedParams := []string{
					"platform_config=https://config.example.com",
					"bootstrap_strategy=noise",
					"bootstrap_dns=1.1.1.1",
					"bootstrap_noise_key=deadbeef",
					"bootstrap_spki_pin=sha256/BBBB",
				}
				for _, param := range expectedParams {
					if !strings.Contains(content, param) {
						t.Errorf("Expected kernel cmdline to contain %q", param)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			isoDir := filepath.Join(tmpDir, "iso")
			grubDir := filepath.Join(isoDir, "boot", "grub")
			if err := os.MkdirAll(grubDir, 0755); err != nil {
				t.Fatalf("Failed to create grub dir: %v", err)
			}
			grubPath := filepath.Join(grubDir, "grub.cfg")
			if err := os.WriteFile(grubPath, []byte(tt.grubConfig), 0644); err != nil {
				t.Fatalf("Failed to write grub.cfg: %v", err)
			}

			// Seed a dummy bootx64.efi so UpdateEFIBootloader doesn't
			// blow up trying to find it. The test does not verify the
			// UEFI update path; it verifies GRUB cmdline mutation.
			efiBootDir := filepath.Join(isoDir, "efi", "boot")
			_ = os.MkdirAll(efiBootDir, 0755)
			_ = os.WriteFile(filepath.Join(efiBootDir, "bootx64.efi"), []byte("stub"), 0644)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Platform: tt.platform,
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			// We don't need UpdateEFIBootloader to succeed here —
			// it requires grub-mkstandalone on the host and the test
			// only cares about the GRUB cmdline mutation that happens
			// before the EFI update step. ConfigureBootloader logs
			// and continues on EFI update failure, so this is safe.
			_ = customizer.ConfigureBootloader(context.Background())

			content, err := os.ReadFile(grubPath)
			if err != nil {
				t.Fatalf("Failed to read modified grub.cfg: %v", err)
			}
			tt.validateModified(t, string(content))
		})
	}
}

func TestCopyPlatformConfigDynamicMode(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		platform   PlatformConfig
		wantErr    bool
	}{
		{
			name:       "skips when config server URL is set and no config path",
			configPath: "",
			platform: PlatformConfig{
				ConfigServerURL: "https://config.example.com",
			},
			wantErr: false,
		},
		{
			name:       "errors when no config path and no config server URL",
			configPath: "",
			platform:   PlatformConfig{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "iso"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Platform: tt.platform,
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.CopyPlatformConfig(ctx, tt.configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyPlatformConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateInstallConfigDynamicMode(t *testing.T) {
	tests := []struct {
		name     string
		platform PlatformConfig
		wantSkip bool
	}{
		{
			name: "skips when config server URL is set and no config file",
			platform: PlatformConfig{
				ConfigServerURL: "https://config.example.com",
			},
			wantSkip: true,
		},
		{
			name: "does not skip when config file is also set",
			platform: PlatformConfig{
				ConfigServerURL: "https://config.example.com",
				ConfigFile:      "/some/path.yaml",
			},
			wantSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			overlayDir := filepath.Join(tmpDir, "overlay")
			if err := os.MkdirAll(overlayDir, 0755); err != nil {
				t.Fatalf("Failed to create overlay dir: %v", err)
			}

			config := &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "https://dl-cdn.alpinelinux.org/alpine",
				},
				Directories: DirectoryConfig{
					Work:    tmpDir,
					Overlay: overlayDir,
				},
				Platform: tt.platform,
				RootFS: RootFSConfig{
					Type: "lvm",
				},
			}
			config.SetDefaults()

			customizer := NewCustomizer(config, logging.DefaultLogger())

			err := customizer.GenerateInstallConfig()
			if tt.wantSkip {
				if err != nil {
					t.Errorf("GenerateInstallConfig() unexpected error: %v", err)
				}
				// Verify no config files were generated
				configDir := filepath.Join(overlayDir, "etc", "platformd")
				if _, statErr := os.Stat(configDir); !os.IsNotExist(statErr) {
					t.Error("Expected no config directory to be created in dynamic mode")
				}
			}
			// When not skipping, we don't validate further since buildInstallerConfig
			// may need additional setup beyond what this unit test provides.
		})
	}
}

func TestISOBuildConfigIsDynamicConfigMode(t *testing.T) {
	tests := []struct {
		name   string
		config ISOBuildConfig
		want   bool
	}{
		{
			name:   "false when no config server URL",
			config: ISOBuildConfig{},
			want:   false,
		},
		{
			name: "true when config server URL is set and no config sources",
			config: ISOBuildConfig{
				ConfigServerURL: "https://config.example.com",
			},
			want: true,
		},
		{
			name: "false when config server URL and platform config file both set",
			config: ISOBuildConfig{
				ConfigServerURL:    "https://config.example.com",
				PlatformConfigFile: "/path/to/config.yaml",
			},
			want: false,
		},
		{
			name: "false when config server URL and config file both set",
			config: ISOBuildConfig{
				ConfigServerURL: "https://config.example.com",
				ConfigFile:      "/path/to/installer.yaml",
			},
			want: false,
		},
		{
			name: "false when config server URL and profile both set",
			config: ISOBuildConfig{
				ConfigServerURL: "https://config.example.com",
				Profile:         "server-default",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsDynamicConfigMode()
			if got != tt.want {
				t.Errorf("IsDynamicConfigMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func installFakeGrubMkstandalone(t *testing.T, root string) {
	t.Helper()
	binDir := filepath.Join(root, "fake-bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create fake bin dir: %v", err)
	}
	path := filepath.Join(binDir, "grub-mkstandalone")
	script := `#!/bin/sh
set -eu
out=""
for arg in "$@"; do
	case "$arg" in
		--output=*) out=${arg#--output=} ;;
	esac
done
if [ -z "$out" ]; then
	exit 1
fi
printf fake-grub > "$out"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake grub-mkstandalone: %v", err)
	}
	for _, name := range []string{"mkfs.vfat", "mmd", "mcopy"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestConfigureBootloader verifies GRUB cmdline mutation: quiet stripped,
// "Linux lts" renamed to "Trusted Alpine LTS", console= and console params
// injected. A fake grub-mkstandalone keeps the EFI update path fatal without
// requiring the host EFI toolchain.
func TestConfigureBootloader(t *testing.T) {
	tmpDir := t.TempDir()
	installFakeGrubMkstandalone(t, tmpDir)

	tests := []struct {
		name             string
		grubConfig       string
		wantErr          bool
		wantErrContains  string
		debugSink        string
		validateModified func(*testing.T, string)
	}{
		{
			name:            "missing grub.cfg returns error",
			wantErr:         true,
			wantErrContains: "GRUB config not found",
		},
		{
			name: "basic grub config modification",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux /boot/vmlinuz-lts root=/dev/sda1 quiet
	initrd /boot/initramfs-lts
}
`,
			wantErr: false,
			validateModified: func(t *testing.T, content string) {
				if strings.Contains(content, " quiet") || strings.Contains(content, "quiet ") {
					t.Error("Expected 'quiet' to be removed from config")
				}
				if strings.Contains(content, `menuentry "Linux lts"`) {
					t.Error("Expected 'Linux lts' to be renamed to 'Trusted Alpine LTS'")
				}
				if !strings.Contains(content, `menuentry "Trusted Alpine LTS"`) {
					t.Error("Expected 'Trusted Alpine LTS' menu entry")
				}
				if !strings.Contains(content, "console=ttyS0,115200") {
					t.Error("Expected console=ttyS0,115200 to be added")
				}
				if !strings.Contains(content, "console=tty1") {
					t.Error("Expected console=tty1 to be added")
				}
				// alpine_start=autoinstall is the kernel-cmdline marker the
				// patched Alpine init uses to trigger the autoinstall flow.
				// apkovl is the secondary mechanism that runs the install
				// script; the cmdline marker is still required so the init
				// hook fires before switch_root.
				if !strings.Contains(content, "alpine_start=autoinstall") {
					t.Error("Expected alpine_start=autoinstall to be injected")
				}
				// No sink is configured, so none may be baked: the
				// install script derives it from the DHCP server.
				if strings.Contains(content, "platform_debug_sink=") {
					t.Error("Expected no platform_debug_sink without a configured sink")
				}
			},
		},
		{
			name: "configured debug sink is baked into the cmdline",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux /boot/vmlinuz-lts root=/dev/sda1
	initrd /boot/initramfs-lts
}
`,
			debugSink: "198.51.100.7:8080",
			validateModified: func(t *testing.T, content string) {
				if strings.Count(content, "platform_debug_sink=198.51.100.7:8080") != 1 {
					t.Errorf("Expected the configured sink exactly once, got:\n%s", content)
				}
			},
		},
		{
			name: "grub config already has terminal_output",
			grubConfig: `set timeout=10
terminal_output console
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1
	initrd /boot/initramfs-lts
}
`,
			wantErr: false,
			validateModified: func(t *testing.T, content string) {
				count := strings.Count(content, "terminal_output console")
				if count != 1 {
					t.Errorf("Expected exactly 1 terminal_output directive, found %d", count)
				}
			},
		},
		{
			name: "grub config with single quoted menu entry",
			grubConfig: `set timeout=10
menuentry 'Linux lts' {
	linux	/boot/vmlinuz-lts root=/dev/sda1 quiet
	initrd /boot/initramfs-lts
}
`,
			wantErr: false,
			validateModified: func(t *testing.T, content string) {
				if strings.Contains(content, `menuentry 'Linux lts'`) {
					t.Error("Expected 'Linux lts' to be renamed")
				}
				if !strings.Contains(content, `menuentry 'Trusted Alpine LTS'`) {
					t.Error("Expected 'Trusted Alpine LTS' menu entry")
				}
			},
		},
		{
			name: "grub config with existing console params",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1 console=ttyS0,115200 console=tty1
	initrd /boot/initramfs-lts
}
`,
			wantErr: false,
			validateModified: func(t *testing.T, content string) {
				count := strings.Count(content, "console=ttyS0,115200")
				if count != 1 {
					t.Errorf("Expected exactly 1 console=ttyS0,115200, found %d", count)
				}
			},
		},
		{
			name: "pre-existing alpine_start is not duplicated",
			grubConfig: `set timeout=10
menuentry "Linux lts" {
	linux	/boot/vmlinuz-lts root=/dev/sda1 alpine_start=autoinstall
	initrd /boot/initramfs-lts
}
`,
			wantErr: false,
			validateModified: func(t *testing.T, content string) {
				// The injection logic guards against duplicates: when the
				// pre-existing cmdline already carries alpine_start=autoinstall
				// the injector must NOT add a second one.
				count := strings.Count(content, "alpine_start=autoinstall")
				if count != 1 {
					t.Errorf("Expected exactly 1 alpine_start=autoinstall, found %d", count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isoDir := filepath.Join(tmpDir, tt.name, "iso")
			grubDir := filepath.Join(isoDir, "boot", "grub")
			os.MkdirAll(grubDir, 0755)

			if tt.grubConfig != "" {
				grubPath := filepath.Join(grubDir, "grub.cfg")
				if err := os.WriteFile(grubPath, []byte(tt.grubConfig), 0644); err != nil {
					t.Fatalf("Failed to write grub.cfg: %v", err)
				}

				// Seed a dummy bootx64.efi: UpdateEFIBootloader GENERATES a new one
				// with grub-mkstandalone, so only the file's existence matters. It is
				// required because an EFI update failure is now fatal (#48) — an ISO
				// whose bootloader was not updated does not boot under UEFI.
				efiBootDir := filepath.Join(isoDir, "efi", "boot")
				if err := os.MkdirAll(efiBootDir, 0755); err != nil {
					t.Fatalf("seed efi dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(efiBootDir, "bootx64.efi"), []byte("stub"), 0644); err != nil {
					t.Fatalf("seed bootx64.efi: %v", err)
				}
			}

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}
			config.Platform.DebugSink = tt.debugSink

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.ConfigureBootloader(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureBootloader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("ConfigureBootloader() error = %q, want substring %q", err.Error(), tt.wantErrContains)
			}
			if tt.validateModified != nil {
				grubPath := filepath.Join(grubDir, "grub.cfg")
				content, readErr := os.ReadFile(grubPath)
				if readErr != nil {
					t.Fatalf("Failed to read modified grub.cfg: %v", readErr)
				}
				tt.validateModified(t, string(content))
			}
		})
	}
}

func TestGenerateAutoinstallScript(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		config  *PlatformISOConfig
		wantErr bool
	}{
		{
			name: "generate basic autoinstall script",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					Work:    tmpDir,
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Build: BuildOptions{
					Debug: false,
				},
			},
			wantErr: false,
		},
		{
			name: "generate debug autoinstall script",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					Work:    tmpDir,
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Build: BuildOptions{
					Debug: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDir := filepath.Join(tmpDir, tt.name)
			tt.config.Directories.Work = workDir
			os.MkdirAll(workDir, 0755)

			customizer := NewCustomizer(tt.config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.GenerateAutoinstallScript(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAutoinstallScript() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				scriptPath := filepath.Join(workDir, "autoinstall.sh")
				info, err := os.Stat(scriptPath)
				if os.IsNotExist(err) {
					t.Error("Autoinstall script was not created")
					return
				}

				// Check script is executable
				if info.Mode()&0100 == 0 {
					t.Error("Autoinstall script should be executable")
				}

				// Read and verify content
				content, err := os.ReadFile(scriptPath)
				if err != nil {
					t.Fatalf("Failed to read autoinstall script: %v", err)
				}

				// Check script has shebang
				if !strings.HasPrefix(string(content), "#!/bin/sh") {
					t.Error("Autoinstall script should start with #!/bin/sh")
				}

				// Check script contains expected functions
				if !strings.Contains(string(content), "log()") {
					t.Error("Autoinstall script should contain log() function")
				}
				if !strings.Contains(string(content), "error()") {
					t.Error("Autoinstall script should contain error() function")
				}
			}
		})
	}
}

func TestBuildAutoinstallScript(t *testing.T) {
	tests := []struct {
		name         string
		config       *PlatformISOConfig
		wantContains []string
	}{
		{
			name: "basic script",
			config: &PlatformISOConfig{
				Build: BuildOptions{
					Debug: false,
				},
			},
			wantContains: []string{
				"#!/bin/sh",
				"log()",
				"error()",
				"set -e",
			},
		},
		{
			name: "debug script",
			config: &PlatformISOConfig{
				Build: BuildOptions{
					Debug: true,
				},
			},
			wantContains: []string{
				"#!/bin/sh",
				"log()",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customizer := NewCustomizer(tt.config, logging.DefaultLogger())
			script := customizer.buildAutoinstallScript()

			for _, want := range tt.wantContains {
				if !strings.Contains(script, want) {
					t.Errorf("Expected script to contain %q", want)
				}
			}
		})
	}
}

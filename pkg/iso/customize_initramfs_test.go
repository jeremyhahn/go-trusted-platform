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
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestFindInitramfs(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		setup   func(isoDir string) error
		wantErr bool
	}{
		{
			name: "initramfs-lts found",
			setup: func(isoDir string) error {
				bootDir := filepath.Join(isoDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "initramfs-lts"), []byte("initramfs data"), 0644)
			},
			wantErr: false,
		},
		{
			name: "initrd found",
			setup: func(isoDir string) error {
				bootDir := filepath.Join(isoDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "initrd.img"), []byte("initrd data"), 0644)
			},
			wantErr: false,
		},
		{
			name: "no initramfs found",
			setup: func(isoDir string) error {
				bootDir := filepath.Join(isoDir, "boot")
				return os.MkdirAll(bootDir, 0755)
			},
			wantErr: true,
		},
		{
			name: "boot directory does not exist",
			setup: func(isoDir string) error {
				return nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isoDir := filepath.Join(tmpDir, tt.name)
			os.MkdirAll(isoDir, 0755)

			if tt.setup != nil {
				if err := tt.setup(isoDir); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			path, err := customizer.findInitramfs()

			if (err != nil) != tt.wantErr {
				t.Errorf("findInitramfs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && path == "" {
				t.Error("findInitramfs() returned empty path")
			}
		})
	}
}

func TestCreateDracutModuleExtended(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "create dracut module with full verification",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initramfsDir := filepath.Join(tmpDir, tt.name)
			os.MkdirAll(initramfsDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			err := customizer.createDracutModule(initramfsDir)

			if (err != nil) != tt.wantErr {
				t.Errorf("createDracutModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify module directory was created
				moduleDir := filepath.Join(initramfsDir, "usr", "lib", "dracut", "modules.d", "90platformd")
				if _, err := os.Stat(moduleDir); os.IsNotExist(err) {
					t.Error("Module directory was not created")
				}

				// Verify module-setup.sh was created
				moduleSetup := filepath.Join(moduleDir, "module-setup.sh")
				if _, err := os.Stat(moduleSetup); os.IsNotExist(err) {
					t.Error("module-setup.sh was not created")
				}

				// Verify module-setup.sh is executable
				info, _ := os.Stat(moduleSetup)
				if info.Mode()&0100 == 0 {
					t.Error("module-setup.sh should be executable")
				}

				// Verify content has expected functions
				content, _ := os.ReadFile(moduleSetup)
				if !strings.Contains(string(content), "check()") {
					t.Error("module-setup.sh should contain check() function")
				}
				if !strings.Contains(string(content), "depends()") {
					t.Error("module-setup.sh should contain depends() function")
				}
				if !strings.Contains(string(content), "install()") {
					t.Error("module-setup.sh should contain install() function")
				}

				// Verify platform-initrd-boot.sh was created
				wrapperScript := filepath.Join(moduleDir, "platform-initrd-boot.sh")
				if _, err := os.Stat(wrapperScript); os.IsNotExist(err) {
					t.Error("platform-initrd-boot.sh was not created")
				}
			}
		})
	}
}

// apkovlEntry holds metadata about a tar entry for test verification.
type apkovlEntry struct {
	mode       int64
	content    string
	linkTarget string
	isDir      bool
}

// extractApkovlEntries reads an apkovl tar.gz and returns a map of entries.
func extractApkovlEntries(t *testing.T, path string) map[string]apkovlEntry {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open apkovl: %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	entries := make(map[string]apkovlEntry)

	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}

		entry := apkovlEntry{
			mode:       hdr.Mode,
			linkTarget: hdr.Linkname,
			isDir:      hdr.Typeflag == tar.TypeDir,
		}

		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			buf := make([]byte, hdr.Size)
			if _, readErr := tr.Read(buf); readErr != nil && readErr.Error() != "EOF" {
				t.Logf("warning: partial read for %s: %v", hdr.Name, readErr)
			}
			entry.content = string(buf)
		}

		entries[hdr.Name] = entry
	}

	return entries
}

func TestCopyDracutModule(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "copy dracut module successfully",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isoDir := filepath.Join(tmpDir, tt.name, "iso")
			os.MkdirAll(isoDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())

			err := customizer.CopyDracutModule(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyDracutModule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify dracut module directory was created
				moduleDir := filepath.Join(isoDir, "dracut-platformd", "90platformd")
				if _, err := os.Stat(moduleDir); os.IsNotExist(err) {
					t.Error("Dracut module directory was not created")
				}

				// Verify module-setup.sh was created
				moduleSetup := filepath.Join(moduleDir, "module-setup.sh")
				if _, err := os.Stat(moduleSetup); os.IsNotExist(err) {
					t.Error("module-setup.sh was not created")
				}

				// Verify module-setup.sh content
				content, _ := os.ReadFile(moduleSetup)
				if !strings.Contains(string(content), "check()") {
					t.Error("module-setup.sh should contain check() function")
				}
				// platform-initrd is a static Go binary; the module-setup
				// uses inst_simple instead of inst_binary because dracut's
				// inst_binary runs ldd and fails on static binaries.
				if !strings.Contains(string(content), "inst_simple /usr/bin/platform-initrd /usr/bin/platform-initrd") {
					t.Error("module-setup.sh should install platform-initrd binary via inst_simple")
				}

				// Verify platformd-unlock.sh was created
				unlockScript := filepath.Join(moduleDir, "platformd-unlock.sh")
				if _, err := os.Stat(unlockScript); os.IsNotExist(err) {
					t.Error("platformd-unlock.sh was not created")
				}

				// Verify unlock script content
				unlockContent, _ := os.ReadFile(unlockScript)
				if !strings.Contains(string(unlockContent), "platformd") {
					t.Error("platformd-unlock.sh should reference platformd")
				}
			}
		})
	}
}

func TestCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		setup   func(workDir string) error
		wantErr bool
	}{
		{
			name: "cleanup removes temp directories",
			setup: func(workDir string) error {
				// Create directories that should be cleaned up
				initramfsTmp := filepath.Join(workDir, "initramfs-tmp")
				verifyDir := filepath.Join(workDir, "verify-initramfs")
				if err := os.MkdirAll(initramfsTmp, 0755); err != nil {
					return err
				}
				if err := os.MkdirAll(verifyDir, 0755); err != nil {
					return err
				}
				// Add some files to verify cleanup
				os.WriteFile(filepath.Join(initramfsTmp, "test.txt"), []byte("test"), 0644)
				os.WriteFile(filepath.Join(verifyDir, "test.txt"), []byte("test"), 0644)
				return nil
			},
			wantErr: false,
		},
		{
			name: "cleanup succeeds when directories dont exist",
			setup: func(workDir string) error {
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDir := filepath.Join(tmpDir, tt.name, "work")
			os.MkdirAll(workDir, 0755)

			if tt.setup != nil {
				if err := tt.setup(workDir); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					Work:    workDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			err := customizer.cleanup()

			if (err != nil) != tt.wantErr {
				t.Errorf("cleanup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify directories were removed
				initramfsTmp := filepath.Join(workDir, "initramfs-tmp")
				verifyDir := filepath.Join(workDir, "verify-initramfs")

				if _, err := os.Stat(initramfsTmp); !os.IsNotExist(err) {
					t.Error("initramfs-tmp directory should have been removed")
				}
				if _, err := os.Stat(verifyDir); !os.IsNotExist(err) {
					t.Error("verify-initramfs directory should have been removed")
				}
			}
		})
	}
}

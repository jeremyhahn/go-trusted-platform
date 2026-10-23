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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestCheckPrerequisites(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		config  *PlatformISOConfig
		setup   func() error
		wantErr bool
	}{
		{
			name: "ISO directory not found",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "nonexistent-iso"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
			},
			wantErr: true,
		},
		{
			name: "valid ISO directory without platformd",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "valid-iso"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
			},
			setup: func() error {
				return os.MkdirAll(filepath.Join(tmpDir, "valid-iso"), 0755)
			},
			wantErr: false,
		},
		{
			name: "platformd binary not found",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "iso-with-platformd"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Platform: PlatformConfig{
					PlatformdBinary: filepath.Join(tmpDir, "nonexistent-platformd"),
				},
			},
			setup: func() error {
				return os.MkdirAll(filepath.Join(tmpDir, "iso-with-platformd"), 0755)
			},
			wantErr: true,
		},
		{
			name: "valid config with existing platformd",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "iso-valid-platformd"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				Platform: PlatformConfig{
					PlatformdBinary: filepath.Join(tmpDir, "mock-platformd"),
				},
			},
			setup: func() error {
				if err := os.MkdirAll(filepath.Join(tmpDir, "iso-valid-platformd"), 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(tmpDir, "mock-platformd"), []byte("mock binary"), 0755)
			},
			wantErr: false,
		},
		{
			name: "secure boot enabled without keys",
			config: &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     filepath.Join(tmpDir, "iso-secureboot"),
					Overlay: filepath.Join(tmpDir, "overlay"),
					Keys:    filepath.Join(tmpDir, "nonexistent-keys"),
				},
				Security: SecurityConfig{
					SecureBoot: true,
				},
			},
			setup: func() error {
				return os.MkdirAll(filepath.Join(tmpDir, "iso-secureboot"), 0755)
			},
			wantErr: false, // Just warns, doesn't fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			customizer := NewCustomizer(tt.config, logging.DefaultLogger())
			err := customizer.checkPrerequisites()

			if (err != nil) != tt.wantErr {
				t.Errorf("checkPrerequisites() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCopyWebUI(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		webUIPath string
		setup     func() error
		wantErr   bool
	}{
		{
			name:      "webUI path not found",
			webUIPath: filepath.Join(tmpDir, "nonexistent-webui"),
			wantErr:   true,
		},
		{
			name:      "webUI as directory",
			webUIPath: filepath.Join(tmpDir, "webui-dir"),
			setup: func() error {
				webUIDir := filepath.Join(tmpDir, "webui-dir")
				if err := os.MkdirAll(webUIDir, 0755); err != nil {
					return err
				}
				// Create some files in the webui directory
				if err := os.WriteFile(filepath.Join(webUIDir, "index.html"), []byte("<html>Test</html>"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(webUIDir, "app.js"), []byte("console.log('test')"), 0644)
			},
			wantErr: false,
		},
		{
			name:      "webUI as tarball",
			webUIPath: filepath.Join(tmpDir, "webui.tar.gz"),
			setup: func() error {
				// Create a mock tarball file
				return os.WriteFile(filepath.Join(tmpDir, "webui.tar.gz"), []byte("mock tarball content"), 0644)
			},
			wantErr: false,
		},
		{
			name:      "webUI as tgz tarball",
			webUIPath: filepath.Join(tmpDir, "webui.tgz"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "webui.tgz"), []byte("mock tarball content"), 0644)
			},
			wantErr: false,
		},
		{
			name:      "invalid webUI path type",
			webUIPath: filepath.Join(tmpDir, "webui.txt"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "webui.txt"), []byte("invalid type"), 0644)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			isoDir := filepath.Join(tmpDir, tt.name, "iso")
			os.MkdirAll(isoDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: filepath.Join(tmpDir, tt.name, "overlay"),
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.CopyWebUI(ctx, tt.webUIPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyWebUI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && err == nil {
				// Verify the webUI was copied
				info, _ := os.Stat(tt.webUIPath)
				if info.IsDir() {
					// Check webui directory was created in ISO
					webuiDest := filepath.Join(isoDir, "webui")
					if _, err := os.Stat(webuiDest); os.IsNotExist(err) {
						t.Error("webui directory was not created in ISO")
					}
				} else {
					// Check tarball was copied
					tarballDest := filepath.Join(isoDir, "webui.tar.gz")
					if _, err := os.Stat(tarballDest); os.IsNotExist(err) {
						t.Error("webui tarball was not copied to ISO")
					}
				}
			}
		})
	}
}

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
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestValidateBinary(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		setup    func() string
		wantErr  bool
		errMatch string
	}{
		{
			name: "binary not found",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent")
			},
			wantErr:  true,
			errMatch: "binary not found",
		},
		{
			name: "not a regular file - directory",
			setup: func() string {
				dir := filepath.Join(tmpDir, "testdir")
				os.MkdirAll(dir, 0755)
				return dir
			},
			wantErr:  true,
			errMatch: "not a regular file",
		},
		{
			name: "not a valid ELF binary - text file",
			setup: func() string {
				path := filepath.Join(tmpDir, "textfile")
				os.WriteFile(path, []byte("not an ELF binary"), 0755)
				return path
			},
			wantErr:  true,
			errMatch: "not a valid ELF binary",
		},
		{
			name: "empty file",
			setup: func() string {
				path := filepath.Join(tmpDir, "emptyfile")
				os.WriteFile(path, []byte{}, 0755)
				return path
			},
			wantErr:  true,
			errMatch: "not a valid ELF binary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			err := validateBinary(path, elf.EM_X86_64)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMatch != "" {
				if err == nil || !containsString(err.Error(), tt.errMatch) {
					t.Errorf("validateBinary() error = %v, want error containing %q", err, tt.errMatch)
				}
			}
		})
	}
}

func TestCopyPlatformBinary(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		binaryPath string
		setup      func() error
		wantErr    bool
	}{
		{
			name:       "binary not found",
			binaryPath: filepath.Join(tmpDir, "nonexistent-binary"),
			wantErr:    true,
		},
		{
			name:       "invalid binary - text file",
			binaryPath: filepath.Join(tmpDir, "invalid-binary"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "invalid-binary"), []byte("not a binary"), 0755)
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
			overlayDir := filepath.Join(tmpDir, tt.name, "overlay")
			os.MkdirAll(isoDir, 0755)
			os.MkdirAll(overlayDir, 0755)

			config := &PlatformISOConfig{
				Directories: DirectoryConfig{
					ISO:     isoDir,
					Overlay: overlayDir,
				},
			}

			customizer := NewCustomizer(config, logging.DefaultLogger())
			ctx := context.Background()

			err := customizer.CopyPlatformBinary(ctx, tt.binaryPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyPlatformBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCopyPlatformdBinary(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		binaryPath string
		setup      func() error
		wantErr    bool
	}{
		{
			name:       "binary not found",
			binaryPath: filepath.Join(tmpDir, "nonexistent-platformd"),
			wantErr:    true,
		},
		{
			name:       "invalid binary format",
			binaryPath: filepath.Join(tmpDir, "invalid-platformd"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "invalid-platformd"), []byte("#!/bin/sh\necho test"), 0755)
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

			err := customizer.CopyPlatformdBinary(ctx, tt.binaryPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyPlatformdBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCopyObjcopyBinary(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		binaryPath string
		setup      func() error
		wantErr    bool
	}{
		{
			name:       "binary not found",
			binaryPath: filepath.Join(tmpDir, "nonexistent-objcopy"),
			wantErr:    true,
		},
		{
			name:       "valid file exists",
			binaryPath: filepath.Join(tmpDir, "mock-objcopy"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "mock-objcopy"), []byte("#!/bin/sh\necho objcopy"), 0755)
			},
			wantErr: false,
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

			err := customizer.copyObjcopyBinary(ctx, tt.binaryPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("copyObjcopyBinary() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify file was copied if no error
			if !tt.wantErr && err == nil {
				destPath := filepath.Join(isoDir, "platformd-bin", "objcopy")
				if _, err := os.Stat(destPath); os.IsNotExist(err) {
					t.Error("objcopy binary was not copied to destination")
				}

				// Check symlink was created
				symlinkPath := filepath.Join(isoDir, "platformd-bin", "llvm-objcopy")
				if _, err := os.Lstat(symlinkPath); os.IsNotExist(err) {
					t.Error("llvm-objcopy symlink was not created")
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

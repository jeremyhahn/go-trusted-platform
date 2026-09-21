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

	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBinary_NotFound(t *testing.T) {
	err := validateBinary("/nonexistent/binary", elf.EM_X86_64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary not found")
}

func TestValidateBinary_NotRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	err := validateBinary(tmpDir, elf.EM_X86_64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

func TestValidateBinary_NotELF(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBinary := filepath.Join(tmpDir, "not-elf")
	require.NoError(t, os.WriteFile(fakeBinary, []byte("this is not an ELF binary"), 0755))

	err := validateBinary(fakeBinary, elf.EM_X86_64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid ELF binary")
}

func TestValidatePlatformdBinaryName_Coverage(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid platformd binary",
			path:    "/usr/bin/platformd",
			wantErr: false,
		},
		{
			name:    "platformd with prefix",
			path:    "/usr/bin/my-platformd",
			wantErr: false,
		},
		{
			name:    "platformctl is rejected",
			path:    "/usr/bin/platformctl",
			wantErr: true,
			errMsg:  "platformctl",
		},
		{
			name:    "unrelated binary is rejected",
			path:    "/usr/bin/nginx",
			wantErr: true,
			errMsg:  "does not appear to be platformd",
		},
		{
			name:    "case insensitive check for platformctl",
			path:    "/usr/bin/PlatformCtl",
			wantErr: true,
			errMsg:  "platformctl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlatformdBinaryName(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCustomizer_Cleanup(t *testing.T) {
	t.Run("cleanup removes temp directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create the directories that cleanup should remove
		initramfsTmpDir := filepath.Join(tmpDir, "initramfs-tmp")
		verifyDir := filepath.Join(tmpDir, "verify-initramfs")
		require.NoError(t, os.MkdirAll(initramfsTmpDir, 0755))
		require.NoError(t, os.MkdirAll(verifyDir, 0755))

		// Put some files in them
		require.NoError(t, os.WriteFile(filepath.Join(initramfsTmpDir, "temp.txt"), []byte("temp"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(verifyDir, "verify.txt"), []byte("verify"), 0644))

		config := &PlatformISOConfig{
			Directories: DirectoryConfig{
				Work:    tmpDir,
				Overlay: filepath.Join(tmpDir, "overlay"),
			},
		}

		c := NewCustomizer(config, nil)
		err := c.cleanup()
		require.NoError(t, err)

		// Verify directories were removed
		_, err = os.Stat(initramfsTmpDir)
		assert.True(t, os.IsNotExist(err), "initramfs-tmp should be removed")

		_, err = os.Stat(verifyDir)
		assert.True(t, os.IsNotExist(err), "verify-initramfs should be removed")
	})

	t.Run("cleanup succeeds when directories do not exist", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &PlatformISOConfig{
			Directories: DirectoryConfig{
				Work:    tmpDir,
				Overlay: filepath.Join(tmpDir, "overlay"),
			},
		}

		c := NewCustomizer(config, nil)
		err := c.cleanup()
		assert.NoError(t, err)
	})
}

func TestCustomizer_WriteInstallerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
			Work:    tmpDir,
		},
		RootFS: RootFSConfig{
			Type: "lvm",
		},
	}

	c := NewCustomizer(config, logging.DefaultLogger())

	t.Run("write to valid path", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "test-config.yaml")
		installConfig := &installer.Config{
			Debug: true,
		}

		err := c.writeInstallerConfig(installConfig, configPath)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("write to invalid path", func(t *testing.T) {
		installConfig := &installer.Config{}
		err := c.writeInstallerConfig(installConfig, "/nonexistent/dir/config.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write config file")
	})
}

func TestCustomizer_WriteInitrdConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
			Work:    tmpDir,
		},
	}

	c := NewCustomizer(config, logging.DefaultLogger())

	t.Run("write to valid path", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "initrd-config.yaml")
		initrdConfig := &initrd.Config{
			RootDevice: "/dev/sda2",
		}

		err := c.writeInitrdConfig(initrdConfig, configPath)
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("write to invalid path", func(t *testing.T) {
		initrdConfig := &initrd.Config{}
		err := c.writeInitrdConfig(initrdConfig, "/nonexistent/dir/config.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write config file")
	})
}

func TestCustomizer_CopyPlatformctlBinary_EmptyPath(t *testing.T) {
	tmpDir := t.TempDir()

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			ISO:     filepath.Join(tmpDir, "iso"),
			Overlay: filepath.Join(tmpDir, "overlay"),
		},
	}

	c := NewCustomizer(config, nil)
	ctx := context.Background()

	err := c.CopyPlatformctlBinary(ctx, "")
	assert.NoError(t, err)
}

func TestCustomizer_CopyPlatformctlBinary_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			ISO:     filepath.Join(tmpDir, "iso"),
			Overlay: filepath.Join(tmpDir, "overlay"),
		},
	}

	c := NewCustomizer(config, nil)
	ctx := context.Background()

	err := c.CopyPlatformctlBinary(ctx, "/nonexistent/platformctl")
	assert.NoError(t, err)
}

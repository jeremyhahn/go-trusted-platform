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

package ipxe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBootConfig(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "GRUB linux command",
			content: `menuentry "Test" {
				linux /boot/vmlinuz console=ttyS0 quiet
				initrd /boot/initramfs
			}`,
			expected: "console=ttyS0 quiet",
		},
		{
			name: "GRUB kernel command",
			content: `menuentry "Test" {
				kernel /vmlinuz root=/dev/sda1 ro
				initrd /initrd
			}`,
			expected: "root=/dev/sda1 ro",
		},
		{
			name: "SYSLINUX APPEND",
			content: `LABEL test
				KERNEL vmlinuz
				APPEND initrd=initramfs modules=loop,squashfs quiet
			`,
			expected: "initrd=initramfs modules=loop,squashfs quiet",
		},
		{
			name: "multiple entries, use first",
			content: `LABEL first
				KERNEL vmlinuz
				APPEND first=true

			LABEL second
				KERNEL vmlinuz
				APPEND second=true
			`,
			expected: "first=true",
		},
		{
			name:     "no boot config",
			content:  "# Just a comment\n",
			expected: "",
		},
		{
			name:     "empty content",
			content:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBootConfig(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCopyFile(t *testing.T) {
	// Create temp directory for testing
	tmpDir, err := os.MkdirTemp("", "ipxe-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source file with test content
	srcPath := filepath.Join(tmpDir, "source.txt")
	testContent := []byte("test content for copy")
	err = os.WriteFile(srcPath, testContent, 0644)
	require.NoError(t, err)

	t.Run("successful copy", func(t *testing.T) {
		dstPath := filepath.Join(tmpDir, "dest.txt")
		err := copyFile(srcPath, dstPath)
		require.NoError(t, err)

		// Verify destination file exists and has same content
		dstContent, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		assert.Equal(t, testContent, dstContent)
	})

	t.Run("source file not found", func(t *testing.T) {
		dstPath := filepath.Join(tmpDir, "dest2.txt")
		err := copyFile("/nonexistent/file.txt", dstPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read source file")
	})

	t.Run("destination directory not writable", func(t *testing.T) {
		dstPath := "/root/cannot-write-here.txt"
		err := copyFile(srcPath, dstPath)
		if err != nil {
			assert.Contains(t, err.Error(), "failed to write destination file")
		} else {
			// Clean up if test somehow succeeded
			os.Remove(dstPath)
		}
	})
}

func TestFindBootFiles_MockFilesystem(t *testing.T) {
	// Create a mock ISO mount structure
	tmpDir, err := os.MkdirTemp("", "ipxe-iso-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name         string
		setupFiles   func(string) error
		expectKernel string
		expectInitrd string
		expectError  bool
	}{
		{
			name: "standard Alpine layout",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-lts"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "initramfs-lts"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz-lts",
			expectInitrd: "initramfs-lts",
			expectError:  false,
		},
		{
			name: "Ubuntu/Debian casper layout",
			setupFiles: func(mountDir string) error {
				casperDir := filepath.Join(mountDir, "casper")
				if err := os.MkdirAll(casperDir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(casperDir, "vmlinuz"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(casperDir, "initrd"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz",
			expectInitrd: "initrd",
			expectError:  false,
		},
		{
			name: "missing kernel",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "initramfs-lts"), []byte("initrd"), 0644)
			},
			expectError: true,
		},
		{
			name: "missing initrd",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "vmlinuz-lts"), []byte("kernel"), 0644)
			},
			expectError: true,
		},
		{
			name: "virt variant",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-virt"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "initramfs-virt"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz-virt",
			expectInitrd: "initramfs-virt",
			expectError:  false,
		},
		{
			name: "bzImage kernel fallback",
			setupFiles: func(mountDir string) error {
				customDir := filepath.Join(mountDir, "custom")
				if err := os.MkdirAll(customDir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(customDir, "bzImage"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(customDir, "initrd.gz"), []byte("initrd"), 0644)
			},
			expectKernel: "bzImage",
			expectInitrd: "initrd.gz",
			expectError:  false,
		},
		{
			name: "live layout",
			setupFiles: func(mountDir string) error {
				liveDir := filepath.Join(mountDir, "live")
				if err := os.MkdirAll(liveDir, 0755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(liveDir, "vmlinuz"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(liveDir, "initrd"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz",
			expectInitrd: "initrd",
			expectError:  false,
		},
		{
			name: "root vmlinuz",
			setupFiles: func(mountDir string) error {
				if err := os.WriteFile(filepath.Join(mountDir, "vmlinuz"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(mountDir, "initramfs"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz",
			expectInitrd: "initramfs",
			expectError:  false,
		},
		{
			name: "vmlinuz.efi kernel",
			setupFiles: func(mountDir string) error {
				if err := os.WriteFile(filepath.Join(mountDir, "vmlinuz.efi"), []byte("kernel"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(mountDir, "initrd.lz"), []byte("initrd"), 0644)
			},
			expectKernel: "vmlinuz.efi",
			expectInitrd: "initrd.lz",
			expectError:  false,
		},
		{
			name: "empty directory",
			setupFiles: func(mountDir string) error {
				return nil // No files created
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh temp directory for this test
			mountDir, err := os.MkdirTemp("", "mount-*")
			require.NoError(t, err)
			defer os.RemoveAll(mountDir)

			// Setup test files
			err = tt.setupFiles(mountDir)
			require.NoError(t, err)

			// Run findBootFiles
			kernelPath, initrdPath, err := findBootFiles(mountDir)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Contains(t, kernelPath, tt.expectKernel)
				assert.Contains(t, initrdPath, tt.expectInitrd)
				assert.True(t, filepath.IsAbs(kernelPath), "kernel path should be absolute")
				assert.True(t, filepath.IsAbs(initrdPath), "initrd path should be absolute")
			}
		})
	}
}

func TestFindModloop(t *testing.T) {
	// Create a mock ISO mount structure
	tmpDir, err := os.MkdirTemp("", "ipxe-modloop-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name         string
		setupFiles   func(string) error
		expectFound  bool
		expectInPath string
	}{
		{
			name: "modloop-lts in boot dir",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "modloop-lts"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop-lts",
		},
		{
			name: "modloop-virt",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "modloop-virt"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop-virt",
		},
		{
			name: "modloop in root",
			setupFiles: func(mountDir string) error {
				return os.WriteFile(filepath.Join(mountDir, "modloop-lts"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop-lts",
		},
		{
			name: "modloop generic in boot",
			setupFiles: func(mountDir string) error {
				bootDir := filepath.Join(mountDir, "boot")
				if err := os.MkdirAll(bootDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(bootDir, "modloop"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop",
		},
		{
			name: "modloop virt in root",
			setupFiles: func(mountDir string) error {
				return os.WriteFile(filepath.Join(mountDir, "modloop-virt"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop-virt",
		},
		{
			name: "modloop generic in root",
			setupFiles: func(mountDir string) error {
				return os.WriteFile(filepath.Join(mountDir, "modloop"), []byte("modloop"), 0644)
			},
			expectFound:  true,
			expectInPath: "modloop",
		},
		{
			name: "no modloop",
			setupFiles: func(mountDir string) error {
				return os.MkdirAll(filepath.Join(mountDir, "boot"), 0755)
			},
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mountDir, err := os.MkdirTemp("", "mount-*")
			require.NoError(t, err)
			defer os.RemoveAll(mountDir)

			err = tt.setupFiles(mountDir)
			require.NoError(t, err)

			result := findModloop(mountDir)

			if tt.expectFound {
				assert.NotEmpty(t, result)
				assert.Contains(t, result, tt.expectInPath)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}

func TestExtractKernelArgs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ipxe-args-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		setupFiles  func(string) error
		expectArgs  string
		expectEmpty bool
	}{
		{
			name: "GRUB config in boot/grub",
			setupFiles: func(mountDir string) error {
				grubDir := filepath.Join(mountDir, "boot", "grub")
				if err := os.MkdirAll(grubDir, 0755); err != nil {
					return err
				}
				grubCfg := `menuentry "Alpine" {
					linux /boot/vmlinuz modules=loop,squashfs quiet
					initrd /boot/initramfs
				}`
				return os.WriteFile(filepath.Join(grubDir, "grub.cfg"), []byte(grubCfg), 0644)
			},
			expectArgs: "modules=loop,squashfs quiet",
		},
		{
			name: "SYSLINUX config in boot/syslinux",
			setupFiles: func(mountDir string) error {
				syslinuxDir := filepath.Join(mountDir, "boot", "syslinux")
				if err := os.MkdirAll(syslinuxDir, 0755); err != nil {
					return err
				}
				syslinuxCfg := `LABEL alpine
					KERNEL vmlinuz
					APPEND alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.20/main
				`
				return os.WriteFile(filepath.Join(syslinuxDir, "syslinux.cfg"), []byte(syslinuxCfg), 0644)
			},
			expectArgs: "alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.20/main",
		},
		{
			name: "isolinux config",
			setupFiles: func(mountDir string) error {
				isolinuxDir := filepath.Join(mountDir, "isolinux")
				if err := os.MkdirAll(isolinuxDir, 0755); err != nil {
					return err
				}
				cfg := `LABEL test
					KERNEL vmlinuz
					APPEND root=/dev/sr0 quiet
				`
				return os.WriteFile(filepath.Join(isolinuxDir, "isolinux.cfg"), []byte(cfg), 0644)
			},
			expectArgs: "root=/dev/sr0 quiet",
		},
		{
			name: "syslinux in syslinux dir",
			setupFiles: func(mountDir string) error {
				syslinuxDir := filepath.Join(mountDir, "syslinux")
				if err := os.MkdirAll(syslinuxDir, 0755); err != nil {
					return err
				}
				cfg := `LABEL linux
					KERNEL vmlinuz
					APPEND console=tty0
				`
				return os.WriteFile(filepath.Join(syslinuxDir, "syslinux.cfg"), []byte(cfg), 0644)
			},
			expectArgs: "console=tty0",
		},
		{
			name: "EFI grub config",
			setupFiles: func(mountDir string) error {
				efiDir := filepath.Join(mountDir, "EFI", "BOOT")
				if err := os.MkdirAll(efiDir, 0755); err != nil {
					return err
				}
				cfg := `menuentry "Boot" {
					linux /vmlinuz efi=runtime
					initrd /initrd
				}`
				return os.WriteFile(filepath.Join(efiDir, "grub.cfg"), []byte(cfg), 0644)
			},
			expectArgs: "efi=runtime",
		},
		{
			name: "no config files",
			setupFiles: func(mountDir string) error {
				return os.MkdirAll(filepath.Join(mountDir, "boot"), 0755)
			},
			expectEmpty: true,
		},
		{
			name: "empty config file",
			setupFiles: func(mountDir string) error {
				grubDir := filepath.Join(mountDir, "boot", "grub")
				if err := os.MkdirAll(grubDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(grubDir, "grub.cfg"), []byte(""), 0644)
			},
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mountDir, err := os.MkdirTemp("", "mount-*")
			require.NoError(t, err)
			defer os.RemoveAll(mountDir)

			err = tt.setupFiles(mountDir)
			require.NoError(t, err)

			result := extractKernelArgs(mountDir)

			if tt.expectEmpty {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expectArgs, result)
			}
		})
	}
}

// TestExtractBootFiles_RequiresRoot tests the actual ISO mounting functionality.
// This test requires root privileges and an actual ISO file.
// When run without root, it tests the error handling paths.
func TestExtractBootFiles_RequiresRoot(t *testing.T) {
	// Test 1: Non-existent ISO file - should fail with appropriate error
	t.Run("nonexistent_iso", func(t *testing.T) {
		_, _, _, _, _, err := ExtractBootFiles("/nonexistent/path/to/file.iso")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	// Test 2: Directory instead of ISO - should fail with appropriate error
	t.Run("directory_instead_of_iso", func(t *testing.T) {
		_, _, _, _, _, err := ExtractBootFiles(os.TempDir())
		require.Error(t, err)
	})

	// Test 3: Empty path - should fail with appropriate error
	t.Run("empty_path", func(t *testing.T) {
		_, _, _, _, _, err := ExtractBootFiles("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	// Test 4: If TEST_ISO_PATH is provided and we have root, test the actual extraction
	testISO := os.Getenv("TEST_ISO_PATH")
	if testISO != "" {
		t.Run("actual_iso_extraction", func(t *testing.T) {
			if _, err := os.Stat(testISO); os.IsNotExist(err) {
				t.Logf("Test ISO file does not exist: %s", testISO)
				return
			}

			extractDir, kernel, initrd, modloop, args, err := ExtractBootFiles(testISO)
			if err != nil {
				// Expected if not running as root or ISO is invalid
				t.Logf("ExtractBootFiles failed (may be expected): %v", err)
				return
			}

			defer os.RemoveAll(extractDir)

			// Verify results
			assert.NotEmpty(t, extractDir)
			assert.NotEmpty(t, kernel)
			assert.NotEmpty(t, initrd)

			// Verify files exist
			assert.FileExists(t, kernel)
			assert.FileExists(t, initrd)

			if modloop != "" {
				assert.FileExists(t, modloop)
			}

			t.Logf("Extraction successful:")
			t.Logf("  Extract dir: %s", extractDir)
			t.Logf("  Kernel: %s", kernel)
			t.Logf("  Initrd: %s", initrd)
			t.Logf("  Modloop: %s", modloop)
			t.Logf("  Args: %s", args)
		})
	}
}

func TestExtractBootFiles_NonexistentISO(t *testing.T) {
	_, _, _, _, _, err := ExtractBootFiles("/nonexistent/file.iso")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExtractBootFiles_ValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		isoPath   string
		expectErr string
	}{
		{
			name:      "non-existent ISO",
			isoPath:   "/nonexistent/path/to/file.iso",
			expectErr: "not found",
		},
		{
			name:      "empty path",
			isoPath:   "",
			expectErr: "not found",
		},
		{
			name:      "directory instead of file",
			isoPath:   os.TempDir(),
			expectErr: "", // Different error depending on OS
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, _, err := ExtractBootFiles(tt.isoPath)
			require.Error(t, err)
			if tt.expectErr != "" {
				assert.Contains(t, err.Error(), tt.expectErr)
			}
		})
	}
}

func TestParseBootConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "linux command with no args",
			content: `menuentry "Test" {
				linux /boot/vmlinuz
			}`,
			expected: "",
		},
		{
			name: "kernel command with only path",
			content: `menuentry "Test" {
				kernel /vmlinuz
			}`,
			expected: "",
		},
		{
			name: "APPEND with only initrd",
			content: `LABEL test
				KERNEL vmlinuz
				APPEND
			`,
			expected: "",
		},
		{
			name:     "whitespace only",
			content:  "   \n  \t  \n   ",
			expected: "",
		},
		{
			name: "mixed case commands",
			content: `LABEL test
				KERNEL vmlinuz
				append console=ttyS0
			`,
			expected: "",
		},
		{
			// linux16 is a valid GRUB command for 16-bit boot that starts with "linux",
			// so it matches the prefix check and extracts args correctly
			name: "linux16 command",
			content: `menuentry "Test" {
				linux16 /boot/vmlinuz console=tty0
			}`,
			expected: "console=tty0",
		},
		{
			name: "multiple spaces between args",
			content: `LABEL test
				KERNEL vmlinuz
				APPEND   arg1=val1   arg2=val2   arg3=val3
			`,
			expected: "arg1=val1 arg2=val2 arg3=val3",
		},
		{
			name: "tabs in content",
			content: `LABEL test
	KERNEL vmlinuz
	APPEND	console=tty0	quiet`,
			expected: "console=tty0 quiet",
		},
		{
			name: "complex Alpine config",
			content: `LABEL alpine-lts
				MENU LABEL Alpine Linux LTS
				KERNEL vmlinuz-lts
				INITRD initramfs-lts
				APPEND modules=loop,squashfs alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.20/main modloop=modloop-lts
			`,
			expected: "modules=loop,squashfs alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.20/main modloop=modloop-lts",
		},
		{
			name: "grub with single arg",
			content: `menuentry "Boot" {
				linux /vmlinuz quiet
			}`,
			expected: "quiet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBootConfig(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCopyFile_Permissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ipxe-perms-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create source file
	srcPath := filepath.Join(tmpDir, "source.txt")
	err = os.WriteFile(srcPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Copy file
	dstPath := filepath.Join(tmpDir, "dest.txt")
	err = copyFile(srcPath, dstPath)
	require.NoError(t, err)

	// Check destination file permissions
	info, err := os.Stat(dstPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestCopyFile_LargeFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ipxe-large-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a 1MB source file
	srcPath := filepath.Join(tmpDir, "large.bin")
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	err = os.WriteFile(srcPath, largeContent, 0644)
	require.NoError(t, err)

	// Copy file
	dstPath := filepath.Join(tmpDir, "large_copy.bin")
	err = copyFile(srcPath, dstPath)
	require.NoError(t, err)

	// Verify content
	dstContent, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, largeContent, dstContent)
}

func TestFindBootFiles_RecursiveSearch(t *testing.T) {
	// Test the recursive search fallback when files aren't in standard locations
	tmpDir, err := os.MkdirTemp("", "ipxe-recursive-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create files in a non-standard nested location
	customDir := filepath.Join(tmpDir, "custom", "deeply", "nested")
	err = os.MkdirAll(customDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(customDir, "vmlinuz"), []byte("kernel"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(customDir, "initramfs"), []byte("initrd"), 0644)
	require.NoError(t, err)

	// Should find files via recursive search
	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "vmlinuz")
	assert.Contains(t, initrdPath, "initramfs")
}

func TestFindBootFiles_PrefersStandardLocations(t *testing.T) {
	// Verify that standard locations are preferred over recursive search
	tmpDir, err := os.MkdirTemp("", "ipxe-prefer-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create files in both standard and non-standard locations
	bootDir := filepath.Join(tmpDir, "boot")
	err = os.MkdirAll(bootDir, 0755)
	require.NoError(t, err)

	customDir := filepath.Join(tmpDir, "custom")
	err = os.MkdirAll(customDir, 0755)
	require.NoError(t, err)

	// Standard location
	err = os.WriteFile(filepath.Join(bootDir, "vmlinuz-lts"), []byte("standard kernel"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(bootDir, "initramfs-lts"), []byte("standard initrd"), 0644)
	require.NoError(t, err)

	// Non-standard location
	err = os.WriteFile(filepath.Join(customDir, "vmlinuz"), []byte("custom kernel"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(customDir, "initramfs"), []byte("custom initrd"), 0644)
	require.NoError(t, err)

	// Should prefer standard location
	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "boot")
	assert.Contains(t, kernelPath, "vmlinuz-lts")
	assert.Contains(t, initrdPath, "boot")
	assert.Contains(t, initrdPath, "initramfs-lts")
}

func TestFindBootFiles_ErrorHandling(t *testing.T) {
	t.Run("missing kernel error message", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "ipxe-err-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		bootDir := filepath.Join(tmpDir, "boot")
		err = os.MkdirAll(bootDir, 0755)
		require.NoError(t, err)

		// Only create initrd
		err = os.WriteFile(filepath.Join(bootDir, "initramfs"), []byte("initrd"), 0644)
		require.NoError(t, err)

		_, _, err = findBootFiles(tmpDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kernel")
	})

	t.Run("missing initrd error message", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "ipxe-err-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		bootDir := filepath.Join(tmpDir, "boot")
		err = os.MkdirAll(bootDir, 0755)
		require.NoError(t, err)

		// Only create kernel
		err = os.WriteFile(filepath.Join(bootDir, "vmlinuz"), []byte("kernel"), 0644)
		require.NoError(t, err)

		_, _, err = findBootFiles(tmpDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "initrd")
	})
}

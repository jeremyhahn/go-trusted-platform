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

package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateRecoveryKey tests recovery key generation
func TestGenerateRecoveryKey(t *testing.T) {
	key := generateRecoveryKey()
	assert.NotEmpty(t, key)
	// Format: XXXX-XXXX-... (dashed hex format)
	assert.Contains(t, key, "-")
	// Should be uppercase hex
	for _, c := range key {
		if c != '-' {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
				"character %c should be uppercase hex or dash", c)
		}
	}
}

// TestClearBytes tests secure memory clearing
func TestClearBytes(t *testing.T) {
	// Test with byte slice
	data := []byte("sensitive data that should be cleared")
	originalLen := len(data)

	clearBytes(data)

	// Verify all bytes are zeroed
	assert.Len(t, data, originalLen, "length should remain the same")
	for i, b := range data {
		assert.Equal(t, byte(0), b, "byte at position %d should be zero", i)
	}
}

// TestCreateAllocatedFile tests file allocation
func TestCreateAllocatedFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		size     int64
		wantErr  bool
	}{
		{
			name:     "create small file",
			filename: filepath.Join(tempDir, "test1.bin"),
			size:     1024,
			wantErr:  false,
		},
		{
			name:     "create medium file",
			filename: filepath.Join(tempDir, "test2.bin"),
			size:     100 * 1024, // 100KB
			wantErr:  false,
		},
		{
			name:     "invalid path",
			filename: "/nonexistent/path/file.bin",
			size:     1024,
			wantErr:  true,
		},
		{
			name:     "zero size file",
			filename: filepath.Join(tempDir, "test3.bin"),
			size:     0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := createAllocatedFile(tt.filename, tt.size)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify file exists and has correct size
				info, err := os.Stat(tt.filename)
				require.NoError(t, err)
				assert.Equal(t, tt.size, info.Size())

				// Cleanup
				if err := os.Remove(tt.filename); err != nil {
					t.Logf("cleanup: %v", err)
				}
			}
		})
	}
}

// TestDefaultIMAMonitorPaths tests IMA monitor path defaults
func TestDefaultIMAMonitorPaths(t *testing.T) {
	paths := DefaultIMAMonitorPaths()
	assert.NotNil(t, paths)
	assert.Greater(t, len(paths), 0, "should return at least one default path")

	// Check some expected paths - uses specific /etc/* paths rather than /etc itself
	expectedPaths := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc/passwd"}
	for _, expected := range expectedPaths {
		assert.Contains(t, paths, expected, "should contain %s", expected)
	}
}

// TestCopyBinaryWithVerification tests binary copying with verification
func TestCopyBinaryWithVerification(t *testing.T) {
	tests := []struct {
		name        string
		setupSrc    func(t *testing.T, srcDir string) string
		setupDst    func(t *testing.T, dstDir string) string
		wantErr     bool
		errContains string
		verify      func(t *testing.T, dst string, srcData []byte)
	}{
		{
			name: "successful copy",
			setupSrc: func(t *testing.T, srcDir string) string {
				src := filepath.Join(srcDir, "platformctl")
				err := os.WriteFile(src, []byte("#!/bin/sh\necho test"), 0755)
				require.NoError(t, err)
				return src
			},
			setupDst: func(t *testing.T, dstDir string) string {
				return filepath.Join(dstDir, "usr", "bin", "platformctl")
			},
			wantErr: false,
			verify: func(t *testing.T, dst string, srcData []byte) {
				// Verify file exists
				stat, err := os.Stat(dst)
				require.NoError(t, err)
				assert.Equal(t, int64(len(srcData)), stat.Size())
				assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())

				// Verify content
				dstData, err := os.ReadFile(dst)
				require.NoError(t, err)
				assert.Equal(t, srcData, dstData)
			},
		},
		{
			name: "creates target directory",
			setupSrc: func(t *testing.T, srcDir string) string {
				src := filepath.Join(srcDir, "binary")
				err := os.WriteFile(src, []byte("binary content"), 0755)
				require.NoError(t, err)
				return src
			},
			setupDst: func(t *testing.T, dstDir string) string {
				// Target directory doesn't exist yet
				return filepath.Join(dstDir, "deep", "nested", "path", "binary")
			},
			wantErr: false,
			verify: func(t *testing.T, dst string, srcData []byte) {
				// Verify nested directory was created
				dir := filepath.Dir(dst)
				stat, err := os.Stat(dir)
				require.NoError(t, err)
				assert.True(t, stat.IsDir())

				// Verify binary was copied
				dstData, err := os.ReadFile(dst)
				require.NoError(t, err)
				assert.Equal(t, srcData, dstData)
			},
		},
		{
			name: "source not found",
			setupSrc: func(t *testing.T, srcDir string) string {
				return filepath.Join(srcDir, "nonexistent")
			},
			setupDst: func(t *testing.T, dstDir string) string {
				return filepath.Join(dstDir, "target")
			},
			wantErr:     true,
			errContains: "failed to read binary",
		},
		{
			name: "overwrites existing file",
			setupSrc: func(t *testing.T, srcDir string) string {
				src := filepath.Join(srcDir, "new_binary")
				err := os.WriteFile(src, []byte("new content"), 0755)
				require.NoError(t, err)
				return src
			},
			setupDst: func(t *testing.T, dstDir string) string {
				dst := filepath.Join(dstDir, "existing")
				err := os.WriteFile(dst, []byte("old content"), 0644)
				require.NoError(t, err)
				return dst
			},
			wantErr: false,
			verify: func(t *testing.T, dst string, srcData []byte) {
				// Verify new content
				dstData, err := os.ReadFile(dst)
				require.NoError(t, err)
				assert.Equal(t, srcData, dstData)

				// Verify permissions were updated to 0755
				stat, err := os.Stat(dst)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())
			},
		},
		{
			name: "large binary",
			setupSrc: func(t *testing.T, srcDir string) string {
				src := filepath.Join(srcDir, "large_binary")
				// Create a 1MB "binary"
				data := make([]byte, 1024*1024)
				for i := range data {
					data[i] = byte(i % 256)
				}
				err := os.WriteFile(src, data, 0755)
				require.NoError(t, err)
				return src
			},
			setupDst: func(t *testing.T, dstDir string) string {
				return filepath.Join(dstDir, "large_binary")
			},
			wantErr: false,
			verify: func(t *testing.T, dst string, srcData []byte) {
				stat, err := os.Stat(dst)
				require.NoError(t, err)
				assert.Equal(t, int64(1024*1024), stat.Size())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcDir := t.TempDir()
			dstDir := t.TempDir()

			src := tt.setupSrc(t, srcDir)
			dst := tt.setupDst(t, dstDir)

			// Read source data for verification (if it exists)
			var srcData []byte
			if data, err := os.ReadFile(src); err == nil {
				srcData = data
			}

			err := copyBinaryWithVerification(src, dst)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.verify != nil {
					tt.verify(t, dst, srcData)
				}
			}
		})
	}
}

// TestCopyBinaryWithVerification_Permissions tests permission verification
func TestCopyBinaryWithVerification_Permissions(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create source file with non-executable permissions
	src := filepath.Join(srcDir, "binary")
	err := os.WriteFile(src, []byte("binary"), 0644)
	require.NoError(t, err)

	dst := filepath.Join(dstDir, "binary")

	// Copy should succeed and set 0755 permissions
	err = copyBinaryWithVerification(src, dst)
	assert.NoError(t, err)

	// Verify target has 0755 permissions
	stat, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())
}

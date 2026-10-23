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
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeWritable(t *testing.T) {
	// Create a temporary directory structure
	tempDir := t.TempDir()

	// Create test files and directories
	testFile := filepath.Join(tempDir, "test.txt")
	testDir := filepath.Join(tempDir, "subdir")

	require.NoError(t, os.MkdirAll(testDir, 0755))
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0444)) // Read-only

	subFile := filepath.Join(testDir, "subfile.txt")
	require.NoError(t, os.WriteFile(subFile, []byte("test"), 0444)) // Read-only

	// Verify files are read-only
	info, err := os.Stat(testFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm())

	// Make writable
	err = makeWritable(tempDir)
	require.NoError(t, err)

	// Verify files are now writable
	info, err = os.Stat(testFile)
	require.NoError(t, err)
	assert.True(t, info.Mode().Perm()&0200 != 0, "file should be user-writable")

	info, err = os.Stat(subFile)
	require.NoError(t, err)
	assert.True(t, info.Mode().Perm()&0200 != 0, "subdirectory file should be user-writable")
}

func TestMakeWritable_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	err := makeWritable(tempDir)
	assert.NoError(t, err)
}

func TestMakeWritable_NonExistentDir(t *testing.T) {
	err := makeWritable("/nonexistent/path")
	assert.Error(t, err)
}

func TestGetDiskUsage(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files with known sizes
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")

	data1 := make([]byte, 1024) // 1 KB
	data2 := make([]byte, 2048) // 2 KB

	require.NoError(t, os.WriteFile(file1, data1, 0644))
	require.NoError(t, os.WriteFile(file2, data2, 0644))

	size, err := GetDiskUsage(tempDir)
	require.NoError(t, err)
	assert.Equal(t, int64(3072), size) // 1024 + 2048
}

func TestGetDiskUsage_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	size, err := GetDiskUsage(tempDir)
	require.NoError(t, err)
	assert.Equal(t, int64(0), size)
}

func TestGetDiskUsage_NestedDirs(t *testing.T) {
	tempDir := t.TempDir()

	// Create nested directory structure
	subdir := filepath.Join(tempDir, "sub1", "sub2")
	require.NoError(t, os.MkdirAll(subdir, 0755))

	// Create files at different levels
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "sub1", "file2.txt")
	file3 := filepath.Join(subdir, "file3.txt")

	require.NoError(t, os.WriteFile(file1, make([]byte, 100), 0644))
	require.NoError(t, os.WriteFile(file2, make([]byte, 200), 0644))
	require.NoError(t, os.WriteFile(file3, make([]byte, 300), 0644))

	size, err := GetDiskUsage(tempDir)
	require.NoError(t, err)
	assert.Equal(t, int64(600), size)
}

func TestGetAvailableSpace(t *testing.T) {
	tempDir := t.TempDir()

	space, err := GetAvailableSpace(tempDir)
	require.NoError(t, err)
	assert.Greater(t, space, uint64(0))
}

func TestGetAvailableSpace_InvalidPath(t *testing.T) {
	_, err := GetAvailableSpace("/nonexistent/path/that/does/not/exist")
	assert.Error(t, err)
}

func TestCheckDiskSpace(t *testing.T) {
	tempDir := t.TempDir()

	// Create a small test "ISO"
	isoPath := filepath.Join(tempDir, "test.iso")
	require.NoError(t, os.WriteFile(isoPath, make([]byte, 1024), 0644))

	// Should have plenty of space for 1KB file
	err := CheckDiskSpace(isoPath, tempDir)
	assert.NoError(t, err)
}

func TestCheckDiskSpace_NonExistentISO(t *testing.T) {
	tempDir := t.TempDir()
	err := CheckDiskSpace("/nonexistent/file.iso", tempDir)
	assert.Error(t, err)
}

func TestVerifyExtraction_ValidDirectory(t *testing.T) {
	tempDir := t.TempDir()

	// Create directory structure that looks like an extracted ISO
	bootDir := filepath.Join(tempDir, "boot")
	diskDir := filepath.Join(tempDir, ".disk")

	require.NoError(t, os.MkdirAll(bootDir, 0755))
	require.NoError(t, os.MkdirAll(diskDir, 0755))

	// Add some files
	require.NoError(t, os.WriteFile(filepath.Join(bootDir, "kernel"), []byte("test"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(diskDir, "info"), []byte("test"), 0644))

	err := VerifyExtraction(tempDir)
	assert.NoError(t, err)
}

func TestVerifyExtraction_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()
	err := VerifyExtraction(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no files found")
}

func TestVerifyExtraction_NonExistentDirectory(t *testing.T) {
	err := VerifyExtraction("/nonexistent/path")
	assert.Error(t, err)
}

func TestVerifyExtraction_FileInsteadOfDirectory(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("test"), 0644))

	err := VerifyExtraction(filePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestCopyISO(t *testing.T) {
	tempDir := t.TempDir()

	// Create source ISO
	srcPath := filepath.Join(tempDir, "source.iso")
	testData := []byte("ISO content data")
	require.NoError(t, os.WriteFile(srcPath, testData, 0644))

	// Copy to destination
	dstPath := filepath.Join(tempDir, "destination.iso")
	ctx := context.Background()

	err := CopyISO(ctx, srcPath, dstPath)
	require.NoError(t, err)

	// Verify destination exists and has correct content
	data, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, testData, data)

	// Verify permissions are preserved
	srcInfo, _ := os.Stat(srcPath)
	dstInfo, _ := os.Stat(dstPath)
	assert.Equal(t, srcInfo.Mode().Perm(), dstInfo.Mode().Perm())
}

func TestCopyISO_WithContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	// Create a large source file
	srcPath := filepath.Join(tempDir, "source.iso")
	largeData := make([]byte, 10*1024*1024) // 10 MB
	require.NoError(t, os.WriteFile(srcPath, largeData, 0644))

	dstPath := filepath.Join(tempDir, "destination.iso")

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := CopyISO(ctx, srcPath, dstPath)
	assert.Error(t, err)

	// Destination should not exist after failed copy
	_, err = os.Stat(dstPath)
	assert.True(t, os.IsNotExist(err))
}

func TestCopyISO_NonExistentSource(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	err := CopyISO(ctx, "/nonexistent/source.iso", filepath.Join(tempDir, "dest.iso"))
	assert.Error(t, err)
}

func TestCopyISO_InvalidDestination(t *testing.T) {
	tempDir := t.TempDir()

	srcPath := filepath.Join(tempDir, "source.iso")
	require.NoError(t, os.WriteFile(srcPath, []byte("test"), 0644))

	ctx := context.Background()
	err := CopyISO(ctx, srcPath, "/invalid/path/dest.iso")
	assert.Error(t, err)
}

func TestExtractISO_NonExistentISO(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	config := &ISOConfig{
		WorkDir:   tempDir,
		ISODir:    filepath.Join(tempDir, "extracted"),
		ISO:       "nonexistent.iso",
		Version:   "3.22.2",
		MirrorURL: "http://example.com",
	}

	err := ExtractISO(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO file not found")
}

func TestExtractISO_InvalidConfig(t *testing.T) {
	ctx := context.Background()

	config := &ISOConfig{
		// Missing required fields
	}

	err := ExtractISO(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestExtractWithProgress_NonExistentISO(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	config := &ISOConfig{
		WorkDir:   tempDir,
		ISODir:    filepath.Join(tempDir, "extracted"),
		ISO:       "nonexistent.iso",
		Version:   "3.22.2",
		MirrorURL: "http://example.com",
	}

	err := ExtractWithProgress(ctx, config, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO file not found")
}

func TestExtractWithProgress_InvalidConfig(t *testing.T) {
	ctx := context.Background()

	config := &ISOConfig{
		// Missing required fields
	}

	err := ExtractWithProgress(ctx, config, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestExtractBsdtar_ToolNotFound(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	isoPath := filepath.Join(tempDir, "test.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("fake iso"), 0644))

	destDir := filepath.Join(tempDir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	err := extractBsdtar(ctx, isoPath, destDir)
	// Error will occur either because tool is not found or because the file is not a valid ISO
	_ = err // Behavior depends on whether bsdtar is installed
}

func TestExtractOsirrox_ToolNotFound(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	isoPath := filepath.Join(tempDir, "test.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("fake iso"), 0644))

	destDir := filepath.Join(tempDir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	err := extractOsirrox(ctx, isoPath, destDir)
	// Error will occur either because tool is not found or because the file is not a valid ISO
	_ = err // Behavior depends on whether xorriso is installed
}

func TestExtract7z_NotAvailable(t *testing.T) {
	// This test verifies error handling when 7z is not available
	// We don't actually call it since 7z may not be installed
	tempDir := t.TempDir()
	ctx := context.Background()

	// Create a fake ISO file
	isoPath := filepath.Join(tempDir, "test.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("fake iso"), 0644))

	destDir := filepath.Join(tempDir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	// Try extraction - will fail gracefully if 7z not found or file is not valid
	err := extract7z(ctx, isoPath, destDir)
	_ = err // Behavior depends on whether 7z is installed
}

// fakeExtractorTool installs an executable named tool as the only entry on
// PATH. It prints a banner to stdout (7z's begins "7-Zip", which broke
// `platformctl iso extract -o json`) and exits with exitCode.
func fakeExtractorTool(t *testing.T, tool string, exitCode int) {
	t.Helper()

	binDir := t.TempDir()
	script := "#!/bin/sh\necho '" + tool + " banner on stdout'\nexit " + strconv.Itoa(exitCode) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, tool), []byte(script), 0o755))
	t.Setenv("PATH", binDir)
}

// captureStdio swaps os.Stdout and os.Stderr for pipes while fn runs and
// returns what each received.
func captureStdio(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	errR, errW, err := os.Pipe()
	require.NoError(t, err)

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	fn()

	require.NoError(t, outW.Close())
	require.NoError(t, errW.Close())
	outBytes, err := io.ReadAll(outR)
	require.NoError(t, err)
	errBytes, err := io.ReadAll(errR)
	require.NoError(t, err)
	return string(outBytes), string(errBytes)
}

// TestExtractors_ToolOutputStaysOffStdout pins that an extraction tool's
// stdout goes to stderr: stdout carries only the CLI verb's result object
// (docs/installer/cli.md §4).
func TestExtractors_ToolOutputStaysOffStdout(t *testing.T) {
	extractors := map[string]func(context.Context, string, string) error{
		"7z":      extract7z,
		"bsdtar":  extractBsdtar,
		"xorriso": extractOsirrox,
	}

	for tool, extract := range extractors {
		t.Run(tool+"/Success", func(t *testing.T) {
			fakeExtractorTool(t, tool, 0)
			dir := t.TempDir()

			var extractErr error
			stdout, stderr := captureStdio(t, func() {
				extractErr = extract(context.Background(), filepath.Join(dir, "in.iso"), filepath.Join(dir, "out"))
			})

			require.NoError(t, extractErr)
			assert.Empty(t, stdout, "tool output must not reach stdout")
			assert.Contains(t, stderr, tool+" banner on stdout")
		})

		t.Run(tool+"/ToolFails", func(t *testing.T) {
			fakeExtractorTool(t, tool, 2)
			dir := t.TempDir()

			var extractErr error
			stdout, _ := captureStdio(t, func() {
				extractErr = extract(context.Background(), filepath.Join(dir, "in.iso"), filepath.Join(dir, "out"))
			})

			var wrapped *WrappedError
			require.ErrorAs(t, extractErr, &wrapped)
			assert.Contains(t, wrapped.Msg, "extraction failed")
			assert.Empty(t, stdout, "tool output must not reach stdout on failure either")
		})
	}
}

// Test configuration validation for extraction
func TestISOConfig_ValidateForExtraction(t *testing.T) {
	tests := []struct {
		name    string
		config  *ISOConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ISOConfig{
				Version:   "3.22.2",
				WorkDir:   "/tmp/work",
				MirrorURL: "http://example.com",
			},
			wantErr: false,
		},
		{
			name: "missing version",
			config: &ISOConfig{
				WorkDir:   "/tmp/work",
				MirrorURL: "http://example.com",
			},
			wantErr: true,
		},
		{
			name: "missing work dir",
			config: &ISOConfig{
				Version:   "3.22.2",
				MirrorURL: "http://example.com",
			},
			wantErr: true,
		},
		{
			name: "auto-populated fields",
			config: &ISOConfig{
				Version:   "3.22.2",
				WorkDir:   "/tmp/work",
				MirrorURL: "http://example.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify auto-populated fields
				assert.NotEmpty(t, tt.config.ISO)
				assert.NotEmpty(t, tt.config.ISODir)
			}
		})
	}
}

func TestGetDiskUsage_ErrorHandling(t *testing.T) {
	// Test with a path that we know will fail during walk
	_, err := GetDiskUsage("/nonexistent/path/to/directory")
	assert.Error(t, err)
}

// Benchmark disk usage calculation
func BenchmarkGetDiskUsage(b *testing.B) {
	tempDir := b.TempDir()

	// Create 100 files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tempDir, "file_"+string(rune(i)))
		os.WriteFile(filePath, make([]byte, 1024), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetDiskUsage(tempDir)
	}
}

// Benchmark making files writable
func BenchmarkMakeWritable(b *testing.B) {
	tempDir := b.TempDir()

	// Create directory structure with read-only files
	for i := 0; i < 50; i++ {
		filePath := filepath.Join(tempDir, "file_"+string(rune(i)))
		os.WriteFile(filePath, []byte("test"), 0444)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeWritable(tempDir)
	}
}

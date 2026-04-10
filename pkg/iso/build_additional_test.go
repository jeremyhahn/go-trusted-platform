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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile_Success(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := filepath.Join(tempDir, "source.txt")
	dstFile := filepath.Join(tempDir, "dest.txt")

	testData := []byte("test content")
	require.NoError(t, os.WriteFile(srcFile, testData, 0644))

	err := copyFile(srcFile, dstFile)
	require.NoError(t, err)

	// Verify content
	data, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, testData, data)
}

func TestCopyFile_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := "/nonexistent/source.txt"
	dstFile := filepath.Join(tempDir, "dest.txt")

	err := copyFile(srcFile, dstFile)
	assert.Error(t, err)
}

func TestCopyFile_DestinationError(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := filepath.Join(tempDir, "source.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte("test"), 0644))

	// Try to write to invalid destination
	dstFile := "/invalid/path/dest.txt"

	err := copyFile(srcFile, dstFile)
	assert.Error(t, err)
}

func TestCopyDir_Success(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "source")
	dstDir := filepath.Join(tempDir, "dest")

	// Create source directory structure
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("content2"), 0644))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify files were copied
	data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("content1"), data1)

	data2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("content2"), data2)
}

func TestCopyDir_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := "/nonexistent/source"
	dstDir := filepath.Join(tempDir, "dest")

	err := copyDir(srcDir, dstDir)
	assert.Error(t, err)
}

func TestCopyDir_NestedDirectories(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "source")
	dstDir := filepath.Join(tempDir, "dest")

	// Create deeply nested structure
	deepDir := filepath.Join(srcDir, "level1", "level2", "level3")
	require.NoError(t, os.MkdirAll(deepDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep content"), 0644))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify deep file exists
	data, err := os.ReadFile(filepath.Join(dstDir, "level1", "level2", "level3", "deep.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("deep content"), data)
}

func TestCopyDir_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "empty_source")
	dstDir := filepath.Join(tempDir, "empty_dest")

	require.NoError(t, os.MkdirAll(srcDir, 0755))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify destination exists
	info, err := os.Stat(dstDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestFileExists_True(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "exists.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	assert.True(t, fileExists(testFile))
}

func TestFileExists_False(t *testing.T) {
	assert.False(t, fileExists("/nonexistent/file.txt"))
}

func TestIsDir_True(t *testing.T) {
	tempDir := t.TempDir()
	assert.True(t, isDir(tempDir))
}

func TestIsDir_False_File(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	assert.False(t, isDir(testFile))
}

func TestIsDir_False_NotExist(t *testing.T) {
	assert.False(t, isDir("/nonexistent/directory"))
}

func TestBuildISO_ValidateConfigError(t *testing.T) {
	builder := NewBuilder(nil)

	// Invalid config - nil
	err := builder.BuildISO(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is required")
}

func TestBuildISO_ISODirNotFound(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    "/nonexistent/iso/dir",
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err)
}

func TestBuildISO_PrepareISOContentsWithFIPSKernel(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create a fake FIPS kernel directory
	fipsKernelDir := filepath.Join(tempDir, "work", "fips-kernel")
	require.NoError(t, os.MkdirAll(fipsKernelDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "vmlinuz-fips"), []byte("fake kernel"), 0644))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   filepath.Join(tempDir, "work"),
	}

	// This will fail at xorriso step, but we're testing the FIPS kernel copy
	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err) // Expected to fail at xorriso

	// Verify FIPS data directory was created
	fipsDataDir := filepath.Join(isoDir, ".fips-data")
	assert.True(t, isDir(fipsDataDir))
}

func TestBuildISO_PrepareISOContentsWithUKI(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create a fake UKI directory
	ukiDir := filepath.Join(tempDir, "work", "host-uki")
	require.NoError(t, os.MkdirAll(ukiDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(ukiDir, "BOOTX64.EFI"), []byte("fake uki"), 0644))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   filepath.Join(tempDir, "work"),
	}

	// This will fail at xorriso step, but we're testing the UKI copy
	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err) // Expected to fail at xorriso

	// Verify UKI data directory was created
	ukiDataDir := filepath.Join(isoDir, ".signed-uki")
	assert.True(t, isDir(ukiDataDir))
}

func TestCopySecureBootKeys_Success(t *testing.T) {
	tempDir := t.TempDir()

	// Create source keys directory
	keysDir := filepath.Join(tempDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "PK.auth"), []byte("pk"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "KEK.auth"), []byte("kek"), 0644))

	// Create ISO directory
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		KeysDir: keysDir,
	}

	err := builder.copySecureBootKeys(config)
	require.NoError(t, err)

	// Verify keys were copied
	dstKeys := filepath.Join(isoDir, "keys")
	assert.True(t, fileExists(filepath.Join(dstKeys, "PK.auth")))
	assert.True(t, fileExists(filepath.Join(dstKeys, "KEK.auth")))
}

func TestCopySecureBootKeys_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		KeysDir: "/nonexistent/keys",
	}

	err := builder.copySecureBootKeys(config)
	assert.Error(t, err)
}

func TestRunXorriso_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	builder := NewBuilder(nil)
	err := builder.runXorriso(ctx, config)
	assert.Error(t, err)
}

func TestPrepareISOContents_NoWorkDir(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   "", // No work directory
	}

	builder := NewBuilder(nil)
	err := builder.prepareISOContents(config)
	require.NoError(t, err) // Should succeed with no-op
}

func TestValidateConfig_LongVolumeID(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "THIS_VOLUME_ID_IS_WAY_TOO_LONG_AND_EXCEEDS_32_CHARACTERS",
	}

	err := builder.validateConfig(config)
	require.NoError(t, err)

	// Volume ID should be truncated to 32 characters
	assert.Len(t, config.VolumeID, 32)
}

func TestValidateConfig_EmptyVolumeID(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "",
	}

	err := builder.validateConfig(config)
	require.NoError(t, err)

	// Should have default label
	assert.Equal(t, "ALPINE_BOOT", config.VolumeID)
}

func TestValidateConfig_MissingISODir(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO directory is required")
}

func TestValidateConfig_MissingOutputISO(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:   isoDir,
		VolumeID: "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output ISO path is required")
}

func TestValidateConfig_ISODirNotFound(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    "/nonexistent/iso",
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO directory not found")
}

func TestPrepareISOContents_FIPSKernelCopyError(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create FIPS kernel dir with a file we can't copy (read-only directory for destination)
	fipsKernelDir := filepath.Join(tempDir, "work", "fips-kernel")
	require.NoError(t, os.MkdirAll(fipsKernelDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "vmlinuz-fips"), []byte("kernel"), 0644))

	// Make ISO dir read-only to cause copy failure
	fipsDataDir := filepath.Join(isoDir, ".fips-data")
	require.NoError(t, os.MkdirAll(fipsDataDir, 0444)) // Read-only

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		WorkDir: filepath.Join(tempDir, "work"),
	}

	// Should not fail, just log warnings
	err := builder.prepareISOContents(config)
	assert.NoError(t, err)

	// Restore permissions for cleanup
	os.Chmod(fipsDataDir, 0755)
}

// Benchmark tests
func BenchmarkCopyFile(b *testing.B) {
	tempDir := b.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	testData := make([]byte, 1024*1024) // 1MB
	os.WriteFile(srcFile, testData, 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstFile := filepath.Join(tempDir, "dest_"+string(rune(i))+".txt")
		copyFile(srcFile, dstFile)
	}
}

func BenchmarkCopyDir(b *testing.B) {
	tempDir := b.TempDir()
	srcDir := filepath.Join(tempDir, "source")
	os.MkdirAll(srcDir, 0755)

	// Create some files
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(srcDir, "file_"+string(rune(i))+".txt")
		os.WriteFile(filePath, []byte("content"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstDir := filepath.Join(tempDir, "dest_"+string(rune(i)))
		copyDir(srcDir, dstDir)
	}
}

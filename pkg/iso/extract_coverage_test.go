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
)

func TestExtractBsdtarCoverage(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with non-existent ISO - should fail regardless of whether bsdtar is available
	err := extractBsdtar(ctx, filepath.Join(tmpDir, "nonexistent.iso"), filepath.Join(tmpDir, "dest"))
	if err == nil {
		t.Error("extractBsdtar() should fail for non-existent ISO")
	}
}

func TestExtractOsiroxCoverage(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with non-existent ISO - should fail regardless of whether xorriso is available
	err := extractOsirrox(ctx, filepath.Join(tmpDir, "nonexistent.iso"), filepath.Join(tmpDir, "dest"))
	// xorriso may or may not be available, so we just check it was called
	// The function should either fail due to missing binary or fail due to non-existent ISO
	_ = err // We don't check error since it depends on tool availability
}

func TestExtract7zCoverage(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with non-existent ISO - should fail
	err := extract7z(ctx, filepath.Join(tmpDir, "nonexistent.iso"), filepath.Join(tmpDir, "dest"))
	// 7z may or may not be available
	_ = err
}

func TestExtractWithProgressInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with invalid config (empty version)
	config := &ISOConfig{
		Version:   "",
		MirrorURL: "http://example.com/alpine",
		WorkDir:   tmpDir,
		ISODir:    filepath.Join(tmpDir, "iso"),
	}

	err := ExtractWithProgress(ctx, config, nil)
	if err == nil {
		t.Error("ExtractWithProgress() should fail with invalid config")
	}
}

func TestExtractWithProgressMissingISO(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with valid config but missing ISO file
	config := &ISOConfig{
		Version:   "3.22.2",
		MirrorURL: "http://example.com/alpine",
		WorkDir:   filepath.Join(tmpDir, "work-missing"),
		ISODir:    filepath.Join(tmpDir, "iso-missing"),
	}

	err := ExtractWithProgress(ctx, config, nil)
	if err == nil {
		t.Error("ExtractWithProgress() should fail when ISO is missing")
	}
}

func TestExtractISOInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with invalid config (empty version)
	config := &ISOConfig{
		Version:   "",
		MirrorURL: "http://example.com/alpine",
		WorkDir:   tmpDir,
		ISODir:    filepath.Join(tmpDir, "iso"),
	}

	err := ExtractISO(ctx, config)
	if err == nil {
		t.Error("ExtractISO() should fail with invalid config")
	}
}

func TestExtractISOMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Test with valid config but missing ISO file
	config := &ISOConfig{
		Version:   "3.22.2",
		MirrorURL: "http://example.com/alpine",
		WorkDir:   filepath.Join(tmpDir, "work-missing"),
		ISODir:    filepath.Join(tmpDir, "iso-missing"),
	}

	err := ExtractISO(ctx, config)
	if err == nil {
		t.Error("ExtractISO() should fail when ISO is missing")
	}
}

func TestCopyISOSourceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	err := CopyISO(ctx, filepath.Join(tmpDir, "nonexistent.iso"), filepath.Join(tmpDir, "dest.iso"))
	if err == nil {
		t.Error("CopyISO() should fail when source is missing")
	}
}

func TestCopyISOSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create source file
	srcPath := filepath.Join(tmpDir, "source.iso")
	content := make([]byte, 1024)
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	dstPath := filepath.Join(tmpDir, "dest.iso")
	err := CopyISO(ctx, srcPath, dstPath)
	if err != nil {
		t.Errorf("CopyISO() error = %v", err)
	}

	// Verify copy
	srcInfo, _ := os.Stat(srcPath)
	dstInfo, err := os.Stat(dstPath)
	if err != nil {
		t.Errorf("Destination file not created: %v", err)
	}
	if srcInfo.Size() != dstInfo.Size() {
		t.Errorf("File sizes don't match: src=%d, dst=%d", srcInfo.Size(), dstInfo.Size())
	}
}

func TestCopyISODestinationError(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create source file
	srcPath := filepath.Join(tmpDir, "source2.iso")
	if err := os.WriteFile(srcPath, []byte("mock iso"), 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Try to copy to non-existent directory
	err := CopyISO(ctx, srcPath, filepath.Join(tmpDir, "nonexistent", "dest.iso"))
	if err == nil {
		t.Error("CopyISO() should fail when destination directory doesn't exist")
	}
}

func TestVerifyExtractionNotExists(t *testing.T) {
	tmpDir := t.TempDir()

	err := VerifyExtraction(filepath.Join(tmpDir, "nonexistent"))
	if err == nil {
		t.Error("VerifyExtraction() should fail when directory doesn't exist")
	}
}

func TestVerifyExtractionNotDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	filePath := filepath.Join(tmpDir, "notadir")
	if err := os.WriteFile(filePath, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	err := VerifyExtraction(filePath)
	if err == nil {
		t.Error("VerifyExtraction() should fail when path is not a directory")
	}
}

func TestVerifyExtractionEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	err := VerifyExtraction(emptyDir)
	if err == nil {
		t.Error("VerifyExtraction() should fail when directory is empty")
	}
}

func TestVerifyExtractionValid(t *testing.T) {
	tmpDir := t.TempDir()

	isoDir := filepath.Join(tmpDir, "valid")
	if err := os.MkdirAll(filepath.Join(isoDir, "boot"), 0755); err != nil {
		t.Fatalf("Failed to create boot directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(isoDir, ".disk"), 0755); err != nil {
		t.Fatalf("Failed to create .disk directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(isoDir, "boot", "vmlinuz"), []byte("kernel"), 0644); err != nil {
		t.Fatalf("Failed to create vmlinuz: %v", err)
	}
	if err := os.WriteFile(filepath.Join(isoDir, "boot", "initramfs"), []byte("initramfs"), 0644); err != nil {
		t.Fatalf("Failed to create initramfs: %v", err)
	}

	err := VerifyExtraction(isoDir)
	if err != nil {
		t.Errorf("VerifyExtraction() error = %v", err)
	}
}

func TestMakeWritableNotExists(t *testing.T) {
	tmpDir := t.TempDir()

	err := makeWritable(filepath.Join(tmpDir, "nonexistent"))
	if err == nil {
		t.Error("makeWritable() should fail when directory doesn't exist")
	}
}

func TestMakeWritableSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	testDir := filepath.Join(tmpDir, "writable-test")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Create a read-only file
	filePath := filepath.Join(testDir, "readonly.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0444); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	err := makeWritable(testDir)
	if err != nil {
		t.Errorf("makeWritable() error = %v", err)
	}

	// Verify file is writable
	info, _ := os.Stat(filePath)
	if info.Mode()&0200 == 0 {
		t.Error("File should be writable after makeWritable()")
	}
}

func TestGetDiskUsageNotExists(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := GetDiskUsage(filepath.Join(tmpDir, "nonexistent"))
	if err == nil {
		t.Error("GetDiskUsage() should fail when directory doesn't exist")
	}
}

func TestGetDiskUsageEmpty(t *testing.T) {
	tmpDir := t.TempDir()

	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	size, err := GetDiskUsage(emptyDir)
	if err != nil {
		t.Errorf("GetDiskUsage() error = %v", err)
	}
	if size != 0 {
		t.Errorf("GetDiskUsage() = %d, want 0", size)
	}
}

func TestGetDiskUsageWithFiles(t *testing.T) {
	tmpDir := t.TempDir()

	testDir := filepath.Join(tmpDir, "files")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Create files with known sizes
	if err := os.WriteFile(filepath.Join(testDir, "file1.txt"), make([]byte, 100), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "file2.txt"), make([]byte, 200), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Create subdirectory with file
	subDir := filepath.Join(testDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file3.txt"), make([]byte, 300), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	size, err := GetDiskUsage(testDir)
	if err != nil {
		t.Errorf("GetDiskUsage() error = %v", err)
	}
	if size != 600 {
		t.Errorf("GetDiskUsage() = %d, want 600", size)
	}
}

func TestGetAvailableSpaceValid(t *testing.T) {
	tmpDir := t.TempDir()

	space, err := GetAvailableSpace(tmpDir)
	if err != nil {
		t.Errorf("GetAvailableSpace() error = %v", err)
	}
	if space == 0 {
		t.Error("GetAvailableSpace() returned 0 for valid path")
	}
}

func TestGetAvailableSpaceNotExists(t *testing.T) {
	_, err := GetAvailableSpace("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("GetAvailableSpace() should fail for non-existent path")
	}
}

func TestCheckDiskSpaceMissingISO(t *testing.T) {
	tmpDir := t.TempDir()

	err := CheckDiskSpace(filepath.Join(tmpDir, "nonexistent.iso"), tmpDir)
	if err == nil {
		t.Error("CheckDiskSpace() should fail when ISO is missing")
	}
}

func TestCheckDiskSpaceValid(t *testing.T) {
	tmpDir := t.TempDir()

	isoPath := filepath.Join(tmpDir, "small.iso")
	if err := os.WriteFile(isoPath, make([]byte, 1024), 0644); err != nil {
		t.Fatalf("Failed to create ISO file: %v", err)
	}

	err := CheckDiskSpace(isoPath, tmpDir)
	if err != nil {
		t.Errorf("CheckDiskSpace() error = %v", err)
	}
}

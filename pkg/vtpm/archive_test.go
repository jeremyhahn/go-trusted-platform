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

package vtpm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewArchiver(t *testing.T) {
	config := &Config{BaseDir: "/tmp/vtpm"}

	// Test with logger
	archiver := NewArchiver(config, nil)
	if archiver == nil {
		t.Fatal("NewArchiver returned nil")
	}
	if archiver.config != config {
		t.Error("NewArchiver did not set config correctly")
	}
	if archiver.logger == nil {
		t.Error("NewArchiver should create default logger when nil")
	}
}

func TestNewArchiver_WithLogger(t *testing.T) {
	config := &Config{BaseDir: "/tmp/vtpm"}
	logger := logging.DefaultLogger()

	archiver := NewArchiver(config, logger)
	if archiver == nil {
		t.Fatal("NewArchiver returned nil")
	}
	if archiver.logger != logger {
		t.Error("NewArchiver should use provided logger")
	}
}

func TestArchiver_Export(t *testing.T) {
	// Create temp directory for bundle
	tmpDir := t.TempDir()
	bundleID := "test-bundle"
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)

	// Create bundle directory structure
	if err := os.MkdirAll(filepath.Join(bundlePath, "tpm"), 0700); err != nil {
		t.Fatalf("Failed to create bundle directory: %v", err)
	}

	// Create manifest
	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		Hostname:  "test.example.com",
		CreatedAt: time.Now(),
		Checksums: map[string]string{},
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifestData, 0600); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	// Create a test TPM state file
	if err := os.WriteFile(filepath.Join(bundlePath, "tpm", "tpm2-00.permall"), []byte("test-tpm-state"), 0600); err != nil {
		t.Fatalf("Failed to write TPM state: %v", err)
	}

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	// Export to buffer
	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, bundleID, &buf)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify the archive contains expected files
	gzr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	foundManifest := false
	foundTPMState := false
	foundTPMDir := false

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar header: %v", err)
		}

		if filepath.Base(header.Name) == "manifest.json" {
			foundManifest = true
		}
		if filepath.Base(header.Name) == "tpm2-00.permall" {
			foundTPMState = true
		}
		if strings.HasSuffix(header.Name, "/tpm/") {
			foundTPMDir = true
		}
	}

	if !foundManifest {
		t.Error("Archive should contain manifest.json")
	}
	if !foundTPMState {
		t.Error("Archive should contain tpm2-00.permall")
	}
	if !foundTPMDir {
		t.Error("Archive should contain tpm directory")
	}
}

func TestArchiver_Export_WithSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()
	bundleID := "export-subdirs"
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)

	// Create nested directory structure
	os.MkdirAll(filepath.Join(bundlePath, "tpm"), 0700)
	os.MkdirAll(filepath.Join(bundlePath, "ovmf"), 0700)
	os.MkdirAll(filepath.Join(bundlePath, "secure-boot-keys"), 0700)

	// Create files
	os.WriteFile(filepath.Join(bundlePath, "manifest.json"), []byte("{}"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "tpm", "state.bin"), []byte("tpm"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "ovmf", "VARS.fd"), []byte("ovmf"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "PK.key"), []byte("pk"), 0600)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, bundleID, &buf)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify all files are in archive
	gzr, _ := gzip.NewReader(&buf)
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	fileCount := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		fileCount++
	}

	// Should have directories and files
	if fileCount < 7 {
		t.Errorf("Expected at least 7 entries in archive, got %d", fileCount)
	}
}

func TestArchiver_Export_BundleNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, "nonexistent-bundle", &buf)

	if err == nil {
		t.Error("Export should fail for nonexistent bundle")
	}

	if _, ok := err.(ErrBundleNotFound); !ok {
		t.Errorf("Expected ErrBundleNotFound, got %T", err)
	}
}

func TestArchiver_ValidateArchive(t *testing.T) {
	// Create a valid archive in memory
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Create manifest
	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        "test-bundle",
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)

	// Write manifest to archive
	header := &tar.Header{
		Name: "vtpm-bundle-test-bundle/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}
	if _, err := tw.Write(manifestData); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	tw.Close()
	gzw.Close()

	// Validate the archive
	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	validatedManifest, err := archiver.ValidateArchive(ctx, &buf)
	if err != nil {
		t.Fatalf("ValidateArchive failed: %v", err)
	}

	if validatedManifest.ID != "test-bundle" {
		t.Errorf("Manifest ID = %v, want test-bundle", validatedManifest.ID)
	}
}

func TestArchiver_ValidateArchive_NoManifest(t *testing.T) {
	// Create an archive without manifest
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Write a random file
	header := &tar.Header{
		Name: "vtpm-bundle-test/somefile.txt",
		Mode: 0600,
		Size: 4,
	}
	tw.WriteHeader(header)
	tw.Write([]byte("test"))

	tw.Close()
	gzw.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ValidateArchive(ctx, &buf)
	if err == nil {
		t.Error("ValidateArchive should fail without manifest")
	}

	if _, ok := err.(ErrInvalidManifest); !ok {
		t.Errorf("Expected ErrInvalidManifest, got %T", err)
	}
}

func TestArchiver_ValidateArchive_InvalidGzip(t *testing.T) {
	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	// Invalid gzip data
	buf := bytes.NewReader([]byte("not gzip data"))
	ctx := context.Background()
	_, err := archiver.ValidateArchive(ctx, buf)
	if err == nil {
		t.Error("ValidateArchive should fail for invalid gzip")
	}

	// Verify error type
	var archiveErr ErrArchiveOperationFailed
	if !errors.As(err, &archiveErr) {
		t.Errorf("Expected ErrArchiveOperationFailed, got %T", err)
	}
}

func TestArchiver_ValidateArchive_InvalidManifestJSON(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	invalidJSON := []byte("{invalid json")
	header := &tar.Header{
		Name: "vtpm-bundle-test/manifest.json",
		Mode: 0600,
		Size: int64(len(invalidJSON)),
	}
	tw.WriteHeader(header)
	tw.Write(invalidJSON)

	tw.Close()
	gzw.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ValidateArchive(ctx, &buf)
	if err == nil {
		t.Error("ValidateArchive should fail for invalid JSON")
	}

	var invalidManifest ErrInvalidManifest
	if !errors.As(err, &invalidManifest) {
		t.Errorf("Expected ErrInvalidManifest, got %T", err)
	}
}

func TestArchiver_Import(t *testing.T) {
	// Create a valid archive in memory
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	bundleID := "import-test-bundle"
	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		Hostname:          "imported.example.com",
		CreatedAt:         time.Now(),
		SecureBootEnabled: false,
	}
	manifestData, _ := json.Marshal(manifest)

	header := &tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	}
	tw.WriteHeader(header)
	tw.Write(manifestData)

	tw.Close()
	gzw.Close()

	// Import the archive
	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	bundle, err := archiver.Import(ctx, &buf)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	if bundle.ID != bundleID {
		t.Errorf("Bundle ID = %v, want %v", bundle.ID, bundleID)
	}

	if bundle.Manifest.Hostname != "imported.example.com" {
		t.Errorf("Bundle hostname = %v, want imported.example.com", bundle.Manifest.Hostname)
	}

	// Verify bundle struct fields
	if bundle.TPMState == nil {
		t.Error("TPMState should not be nil")
	}
	if bundle.OVMFState == nil {
		t.Error("OVMFState should not be nil")
	}
}

func TestArchiver_Import_InvalidGzip(t *testing.T) {
	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.Import(ctx, bytes.NewReader([]byte("not gzip")))
	if err == nil {
		t.Error("Import should fail for invalid gzip")
	}
}

func TestArchiver_Import_InvalidManifest(t *testing.T) {
	// Create archive with invalid manifest JSON
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	invalidJSON := []byte("{invalid json")
	header := &tar.Header{
		Name: "vtpm-bundle-test/manifest.json",
		Mode: 0600,
		Size: int64(len(invalidJSON)),
	}
	tw.WriteHeader(header)
	tw.Write(invalidJSON)

	tw.Close()
	gzw.Close()

	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.Import(ctx, &buf)
	if err == nil {
		t.Error("Import should fail for invalid manifest JSON")
	}
}

func TestArchiver_Import_NoManifest(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Write a file that's not manifest.json
	header := &tar.Header{
		Name: "vtpm-bundle-test/other.txt",
		Mode: 0600,
		Size: 4,
	}
	tw.WriteHeader(header)
	tw.Write([]byte("test"))

	tw.Close()
	gzw.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.Import(ctx, &buf)
	if err == nil {
		t.Error("Import should fail without manifest")
	}
}

func TestArchiver_Import_BundleAlreadyExists(t *testing.T) {
	bundleID := "existing-bundle"

	// Create archive
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)

	header := &tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	}
	tw.WriteHeader(header)
	tw.Write(manifestData)

	tw.Close()
	gzw.Close()

	// Create existing bundle directory
	tmpDir := t.TempDir()
	existingPath := filepath.Join(tmpDir, "bundles", bundleID)
	os.MkdirAll(existingPath, 0700)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.Import(ctx, &buf)
	if err == nil {
		t.Error("Import should fail when bundle already exists")
	}

	if _, ok := err.(ErrBundleAlreadyExists); !ok {
		t.Errorf("Expected ErrBundleAlreadyExists, got %T: %v", err, err)
	}
}

func TestArchiver_ImportFromFile(t *testing.T) {
	bundleID := "file-import-test"

	// Create archive file
	archivePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Failed to create archive file: %v", err)
	}

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		Hostname:          "file-import.example.com",
		CreatedAt:         time.Now(),
		SecureBootEnabled: true,
	}
	manifestData, _ := json.Marshal(manifest)

	// Add manifest
	header := &tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	}
	tw.WriteHeader(header)
	tw.Write(manifestData)

	// Add TPM directory
	tw.WriteHeader(&tar.Header{
		Name:     "vtpm-bundle-" + bundleID + "/tpm/",
		Mode:     0700,
		Typeflag: tar.TypeDir,
	})

	// Add TPM state file
	tpmState := []byte("test-tpm-state")
	tw.WriteHeader(&tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/tpm/tpm2-00.permall",
		Mode: 0600,
		Size: int64(len(tpmState)),
	})
	tw.Write(tpmState)

	// Add secure boot keys directory
	tw.WriteHeader(&tar.Header{
		Name:     "vtpm-bundle-" + bundleID + "/secure-boot-keys/",
		Mode:     0700,
		Typeflag: tar.TypeDir,
	})

	tw.Close()
	gzw.Close()
	f.Close()

	// Import from file
	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	bundle, err := archiver.ImportFromFile(ctx, archivePath)
	if err != nil {
		t.Fatalf("ImportFromFile failed: %v", err)
	}

	if bundle.ID != bundleID {
		t.Errorf("Bundle ID = %v, want %v", bundle.ID, bundleID)
	}

	// Verify secure boot keys are set for secure boot enabled bundles
	if bundle.SecureBootKeys == nil {
		t.Error("SecureBootKeys should be set for secure boot enabled bundle")
	}

	// Verify files were extracted
	manifestPath := filepath.Join(tmpDir, "bundles", bundleID, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Error("Manifest file should exist after import")
	}

	tpmStatePath := filepath.Join(tmpDir, "bundles", bundleID, "tpm", "tpm2-00.permall")
	if _, err := os.Stat(tpmStatePath); os.IsNotExist(err) {
		t.Error("TPM state file should exist after import")
	}
}

func TestArchiver_ImportFromFile_NotFound(t *testing.T) {
	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ImportFromFile(ctx, "/nonexistent/path/archive.tar.gz")
	if err == nil {
		t.Error("ImportFromFile should fail for nonexistent file")
	}
}

func TestArchiver_ImportFromFile_InvalidGzip(t *testing.T) {
	// Create invalid archive file
	archivePath := filepath.Join(t.TempDir(), "invalid.tar.gz")
	os.WriteFile(archivePath, []byte("not gzip data"), 0644)

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ImportFromFile(ctx, archivePath)
	if err == nil {
		t.Error("ImportFromFile should fail for invalid gzip")
	}
}

func TestArchiver_ImportFromFile_NoManifest(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "no-manifest.tar.gz")
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	// Write a file that's not manifest
	header := &tar.Header{
		Name: "vtpm-bundle-test/other.txt",
		Mode: 0600,
		Size: 4,
	}
	tw.WriteHeader(header)
	tw.Write([]byte("test"))

	tw.Close()
	gzw.Close()
	f.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ImportFromFile(ctx, archivePath)
	if err == nil {
		t.Error("ImportFromFile should fail without manifest")
	}
}

func TestArchiver_ImportFromFile_BundleAlreadyExists(t *testing.T) {
	bundleID := "existing-file-bundle"

	archivePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)

	tw.WriteHeader(&tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	})
	tw.Write(manifestData)

	tw.Close()
	gzw.Close()
	f.Close()

	// Create existing bundle
	tmpDir := t.TempDir()
	os.MkdirAll(filepath.Join(tmpDir, "bundles", bundleID), 0700)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ImportFromFile(ctx, archivePath)
	if err == nil {
		t.Error("ImportFromFile should fail when bundle exists")
	}

	var existsErr ErrBundleAlreadyExists
	if !errors.As(err, &existsErr) {
		t.Errorf("Expected ErrBundleAlreadyExists, got %T", err)
	}
}

func TestArchiver_ImportFromFile_WithOVMFAndSecureBootFiles(t *testing.T) {
	bundleID := "full-bundle"

	archivePath := filepath.Join(t.TempDir(), "full-bundle.tar.gz")
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		CreatedAt:         time.Now(),
		SecureBootEnabled: true,
	}
	manifestData, _ := json.Marshal(manifest)

	// Add all files
	files := []struct {
		name    string
		content string
		isDir   bool
	}{
		{"vtpm-bundle-" + bundleID + "/manifest.json", string(manifestData), false},
		{"vtpm-bundle-" + bundleID + "/tpm/", "", true},
		{"vtpm-bundle-" + bundleID + "/tpm/tpm2-00.permall", "tpm-state", false},
		{"vtpm-bundle-" + bundleID + "/ovmf/", "", true},
		{"vtpm-bundle-" + bundleID + "/ovmf/OVMF_VARS.fd", "ovmf-vars", false},
		{"vtpm-bundle-" + bundleID + "/secure-boot-keys/", "", true},
		{"vtpm-bundle-" + bundleID + "/secure-boot-keys/PK.key", "pk-key", false},
		{"vtpm-bundle-" + bundleID + "/secure-boot-keys/PK.crt", "pk-crt", false},
	}

	for _, file := range files {
		if file.isDir {
			tw.WriteHeader(&tar.Header{
				Name:     file.name,
				Mode:     0700,
				Typeflag: tar.TypeDir,
			})
		} else {
			tw.WriteHeader(&tar.Header{
				Name: file.name,
				Mode: 0600,
				Size: int64(len(file.content)),
			})
			tw.Write([]byte(file.content))
		}
	}

	tw.Close()
	gzw.Close()
	f.Close()

	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	bundle, err := archiver.ImportFromFile(ctx, archivePath)
	if err != nil {
		t.Fatalf("ImportFromFile failed: %v", err)
	}

	// Verify all paths are set correctly
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)

	if bundle.TPMState.StateDir != filepath.Join(bundlePath, "tpm") {
		t.Errorf("TPMState.StateDir incorrect")
	}
	if bundle.OVMFState.NVRAMFile != filepath.Join(bundlePath, "ovmf", "OVMF_VARS.fd") {
		t.Errorf("OVMFState.NVRAMFile incorrect")
	}
	if bundle.SecureBootKeys.PKKey != filepath.Join(bundlePath, "secure-boot-keys", "PK.key") {
		t.Errorf("SecureBootKeys.PKKey incorrect")
	}
}

func TestArchiver_Export_EmptyBundle(t *testing.T) {
	tmpDir := t.TempDir()
	bundleID := "empty-bundle"
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)
	os.MkdirAll(bundlePath, 0700)

	// Only manifest, no other files
	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)
	os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifestData, 0600)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, bundleID, &buf)
	if err != nil {
		t.Fatalf("Export should succeed for minimal bundle: %v", err)
	}

	// Verify archive is valid
	gzr, _ := gzip.NewReader(&buf)
	tr := tar.NewReader(gzr)

	foundFiles := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		foundFiles++
	}

	if foundFiles < 2 {
		t.Errorf("Archive should have at least 2 entries (dir and manifest)")
	}
}

func TestArchiver_ImportFromFile_InvalidManifestJSON(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "invalid-manifest.tar.gz")
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	invalidJSON := []byte("{invalid json")
	tw.WriteHeader(&tar.Header{
		Name: "vtpm-bundle-test/manifest.json",
		Mode: 0600,
		Size: int64(len(invalidJSON)),
	})
	tw.Write(invalidJSON)

	tw.Close()
	gzw.Close()
	f.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ImportFromFile(ctx, archivePath)
	if err == nil {
		t.Error("ImportFromFile should fail for invalid manifest JSON")
	}
}

// =============================================================================
// Additional Archive Tests for Coverage
// =============================================================================

func TestArchiver_Export_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	bundleID := "large-file-bundle"
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)
	os.MkdirAll(filepath.Join(bundlePath, "tpm"), 0700)

	// Create a larger file (1MB)
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	os.WriteFile(filepath.Join(bundlePath, "tpm", "large.bin"), largeContent, 0600)

	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)
	os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifestData, 0600)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, bundleID, &buf)
	if err != nil {
		t.Fatalf("Export failed for large file: %v", err)
	}

	// Verify buffer has content
	if buf.Len() == 0 {
		t.Error("Export should produce non-empty archive")
	}
}

func TestArchiver_ValidateArchive_EmptyArchive(t *testing.T) {
	// Create empty gzip
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	tw.Close()
	gzw.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	_, err := archiver.ValidateArchive(ctx, &buf)
	if err == nil {
		t.Error("ValidateArchive should fail for empty archive")
	}
}

func TestArchiver_ImportFromFile_RegularFiles(t *testing.T) {
	bundleID := "regular-files"

	archivePath := filepath.Join(t.TempDir(), "regular.tar.gz")
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        bundleID,
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)

	// Add multiple regular files
	files := []struct {
		name    string
		content []byte
	}{
		{"vtpm-bundle-" + bundleID + "/manifest.json", manifestData},
		{"vtpm-bundle-" + bundleID + "/tpm/state.bin", []byte("tpm-state")},
		{"vtpm-bundle-" + bundleID + "/ovmf/vars.fd", []byte("ovmf-vars")},
	}

	for _, file := range files {
		tw.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: 0600,
			Size: int64(len(file.content)),
		})
		tw.Write(file.content)
	}

	tw.Close()
	gzw.Close()
	f.Close()

	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	bundle, err := archiver.ImportFromFile(ctx, archivePath)
	if err != nil {
		t.Fatalf("ImportFromFile failed: %v", err)
	}

	if bundle.ID != bundleID {
		t.Errorf("Bundle ID = %v, want %v", bundle.ID, bundleID)
	}
}

func TestArchiver_Export_WithSecureBootKeys(t *testing.T) {
	tmpDir := t.TempDir()
	bundleID := "sb-export"
	bundlePath := filepath.Join(tmpDir, "bundles", bundleID)
	os.MkdirAll(filepath.Join(bundlePath, "tpm"), 0700)
	os.MkdirAll(filepath.Join(bundlePath, "ovmf"), 0700)
	os.MkdirAll(filepath.Join(bundlePath, "secure-boot-keys"), 0700)

	// Create secure boot keys
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "PK.key"), []byte("pk"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "PK.crt"), []byte("pk-crt"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "KEK.key"), []byte("kek"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "KEK.crt"), []byte("kek-crt"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "DB.key"), []byte("db"), 0600)
	os.WriteFile(filepath.Join(bundlePath, "secure-boot-keys", "DB.crt"), []byte("db-crt"), 0600)

	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		CreatedAt:         time.Now(),
		SecureBootEnabled: true,
	}
	manifestData, _ := json.Marshal(manifest)
	os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifestData, 0600)

	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	var buf bytes.Buffer
	ctx := context.Background()
	err := archiver.Export(ctx, bundleID, &buf)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify secure boot keys are in archive
	gzr, _ := gzip.NewReader(&buf)
	tr := tar.NewReader(gzr)

	sbKeyCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if strings.Contains(header.Name, "secure-boot-keys") && !strings.HasSuffix(header.Name, "/") {
			sbKeyCount++
		}
	}

	if sbKeyCount != 6 {
		t.Errorf("Expected 6 secure boot key files, got %d", sbKeyCount)
	}
}

func TestArchiver_ValidateArchive_ManifestInDirectory(t *testing.T) {
	// Test that manifest in a directory path is found
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        "nested-manifest",
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
	}
	manifestData, _ := json.Marshal(manifest)

	// Create directory entry first
	tw.WriteHeader(&tar.Header{
		Name:     "vtpm-bundle-nested-manifest/",
		Mode:     0700,
		Typeflag: tar.TypeDir,
	})

	// Add manifest file
	tw.WriteHeader(&tar.Header{
		Name: "vtpm-bundle-nested-manifest/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	})
	tw.Write(manifestData)

	tw.Close()
	gzw.Close()

	config := &Config{BaseDir: t.TempDir()}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	validatedManifest, err := archiver.ValidateArchive(ctx, &buf)
	if err != nil {
		t.Fatalf("ValidateArchive failed: %v", err)
	}

	if validatedManifest.ID != "nested-manifest" {
		t.Errorf("Manifest ID = %v, want nested-manifest", validatedManifest.ID)
	}
}

func TestArchiver_Import_WithSecureBootEnabled(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	bundleID := "sb-import-test"
	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		Hostname:          "sb-host.example.com",
		CreatedAt:         time.Now(),
		SecureBootEnabled: true,
	}
	manifestData, _ := json.Marshal(manifest)

	tw.WriteHeader(&tar.Header{
		Name: "vtpm-bundle-" + bundleID + "/manifest.json",
		Mode: 0600,
		Size: int64(len(manifestData)),
	})
	tw.Write(manifestData)

	tw.Close()
	gzw.Close()

	tmpDir := t.TempDir()
	config := &Config{BaseDir: tmpDir}
	archiver := NewArchiver(config, nil)

	ctx := context.Background()
	bundle, err := archiver.Import(ctx, &buf)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	if bundle.Manifest.SecureBootEnabled != true {
		t.Error("SecureBootEnabled should be true")
	}
}

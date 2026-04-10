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

// TestCopyNetworkSetupFilesSuccess verifies successful copying of network setup files
func TestCopyNetworkSetupFilesSuccess(t *testing.T) {
	// Create temporary directories
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	// Create configs directory structure
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs directory: %v", err)
	}

	// Create mock network setup script
	scriptPath := filepath.Join(configsDir, "trusted-platform-network.sh")
	scriptContent := `#!/bin/bash
# Test script
echo "Network setup"
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Create mock service file
	servicePath := filepath.Join(configsDir, "trusted-platform-network.service")
	serviceContent := `[Unit]
Description=Test Service
[Service]
Type=oneshot
ExecStart=/bin/true
`
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		t.Fatalf("Failed to create test service: %v", err)
	}

	// Create config with overlay directory
	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())

	// Execute CopyNetworkSetupFiles
	ctx := context.Background()
	err := customizer.CopyNetworkSetupFiles(ctx)
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles failed: %v", err)
	}

	// Verify script was copied to correct location
	expectedScriptDest := filepath.Join(overlayDir, "usr", "local", "bin", "trusted-platform-network.sh")
	if _, err := os.Stat(expectedScriptDest); os.IsNotExist(err) {
		t.Errorf("Script not copied to expected location: %s", expectedScriptDest)
	}

	// Verify script permissions
	scriptInfo, err := os.Stat(expectedScriptDest)
	if err != nil {
		t.Fatalf("Failed to stat script: %v", err)
	}
	if scriptInfo.Mode()&0755 == 0 {
		t.Errorf("Script does not have executable permissions: %o", scriptInfo.Mode())
	}

	// Verify service was copied to correct location
	expectedServiceDest := filepath.Join(overlayDir, "lib", "systemd", "system", "trusted-platform-network.service")
	if _, err := os.Stat(expectedServiceDest); os.IsNotExist(err) {
		t.Errorf("Service not copied to expected location: %s", expectedServiceDest)
	}

	// Verify service permissions
	serviceInfo, err := os.Stat(expectedServiceDest)
	if err != nil {
		t.Fatalf("Failed to stat service: %v", err)
	}
	if serviceInfo.Mode()&0644 == 0 {
		t.Errorf("Service does not have correct permissions: %o", serviceInfo.Mode())
	}

	// Verify content was copied correctly
	copiedScriptContent, err := os.ReadFile(expectedScriptDest)
	if err != nil {
		t.Fatalf("Failed to read copied script: %v", err)
	}
	if string(copiedScriptContent) != scriptContent {
		t.Errorf("Script content mismatch after copy")
	}

	copiedServiceContent, err := os.ReadFile(expectedServiceDest)
	if err != nil {
		t.Fatalf("Failed to read copied service: %v", err)
	}
	if string(copiedServiceContent) != serviceContent {
		t.Errorf("Service content mismatch after copy")
	}
}

// TestCopyNetworkSetupFilesMissingScript verifies graceful handling when script is missing
func TestCopyNetworkSetupFilesMissingScript(t *testing.T) {
	// Create temporary directories (without creating the files)
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs directory: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())

	// Execute CopyNetworkSetupFiles with missing files
	ctx := context.Background()
	err := customizer.CopyNetworkSetupFiles(ctx)

	// Should not fail, just warn and return nil
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles should not fail on missing files: %v", err)
	}
}

// TestCopyNetworkSetupFilesEmptyConfigsDir verifies handling of missing configs directory
func TestCopyNetworkSetupFilesEmptyConfigsDir(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	nonExistentConfigsDir := filepath.Join(tmpDir, "nonexistent", "configs", "os")

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: nonExistentConfigsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())

	ctx := context.Background()
	err := customizer.CopyNetworkSetupFiles(ctx)

	// Should return nil (graceful handling)
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles should handle missing configs dir gracefully: %v", err)
	}
}

// TestCopyNetworkSetupFilesOverlayCreation verifies overlay directory creation
func TestCopyNetworkSetupFilesOverlayCreation(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	// Create configs directory structure
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs directory: %v", err)
	}

	// Create network files
	scriptPath := filepath.Join(configsDir, "trusted-platform-network.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create script: %v", err)
	}

	servicePath := filepath.Join(configsDir, "trusted-platform-network.service")
	if err := os.WriteFile(servicePath, []byte("[Unit]\nDescription=Test"), 0644); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Verify overlay directory doesn't exist yet
	if _, err := os.Stat(overlayDir); err == nil {
		t.Fatalf("Overlay directory should not exist yet")
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())
	ctx := context.Background()
	err := customizer.CopyNetworkSetupFiles(ctx)
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles failed: %v", err)
	}

	// Verify overlay directory and subdirectories were created
	expectedDirs := []string{
		overlayDir,
		filepath.Join(overlayDir, "usr"),
		filepath.Join(overlayDir, "usr", "local"),
		filepath.Join(overlayDir, "usr", "local", "bin"),
		filepath.Join(overlayDir, "lib"),
		filepath.Join(overlayDir, "lib", "systemd"),
		filepath.Join(overlayDir, "lib", "systemd", "system"),
	}

	for _, dir := range expectedDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Required directory not created: %s", dir)
		}
	}
}

// TestCopyNetworkSetupFilesFallbackToDefaultConfigsDir verifies fallback behavior
func TestCopyNetworkSetupFilesFallbackToDefaultConfigsDir(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	// Don't set ConfigsDir, should fallback to "configs/os"
	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: "", // Empty, will use fallback
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())
	ctx := context.Background()

	// This should not fail, just warn and return nil (files don't exist in current test environment)
	err := customizer.CopyNetworkSetupFiles(ctx)
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles should handle fallback gracefully: %v", err)
	}
}

// TestCopyNetworkSetupFilesFileWriteFailure simulates write failure
func TestCopyNetworkSetupFilesFileWriteFailure(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay", "readonly")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	// Create configs directory with files
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs directory: %v", err)
	}

	scriptPath := filepath.Join(configsDir, "trusted-platform-network.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create script: %v", err)
	}

	servicePath := filepath.Join(configsDir, "trusted-platform-network.service")
	if err := os.WriteFile(servicePath, []byte("[Unit]\nDescription=Test"), 0644); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Create the parent directory so the path is valid up to the overlay level
	if err := os.MkdirAll(filepath.Dir(overlayDir), 0755); err != nil {
		t.Fatalf("Failed to create parent directory: %v", err)
	}
	// Place a regular file where the overlay directory is expected.
	// os.MkdirAll will fail when it tries to create subdirectories
	// under a regular file, regardless of user privileges (including root).
	if err := os.WriteFile(overlayDir, []byte("blocker"), 0644); err != nil {
		t.Fatalf("Failed to create blocker file: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())
	ctx := context.Background()

	// Should fail because overlayDir is a regular file, not a directory,
	// so os.MkdirAll cannot create subdirectories under it
	err := customizer.CopyNetworkSetupFiles(ctx)
	if err == nil {
		t.Fatal("CopyNetworkSetupFiles should fail when cannot create directories")
	}
}

// TestCopyNetworkSetupFilesPermissions verifies file permissions are set correctly
func TestCopyNetworkSetupFilesPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs directory: %v", err)
	}

	// Create script with wrong permissions initially
	scriptPath := filepath.Join(configsDir, "trusted-platform-network.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho test"), 0644); err != nil {
		t.Fatalf("Failed to create script: %v", err)
	}

	servicePath := filepath.Join(configsDir, "trusted-platform-network.service")
	if err := os.WriteFile(servicePath, []byte("[Unit]\nDescription=Test"), 0755); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	customizer := NewCustomizer(config, logging.DefaultLogger())
	ctx := context.Background()

	err := customizer.CopyNetworkSetupFiles(ctx)
	if err != nil {
		t.Fatalf("CopyNetworkSetupFiles failed: %v", err)
	}

	// Verify script is executable (0755)
	scriptDest := filepath.Join(overlayDir, "usr", "local", "bin", "trusted-platform-network.sh")
	scriptInfo, err := os.Stat(scriptDest)
	if err != nil {
		t.Fatalf("Failed to stat script: %v", err)
	}
	expectedScriptMode := os.FileMode(0755)
	if scriptInfo.Mode().Perm() != expectedScriptMode {
		t.Errorf("Script permissions incorrect: got %o, want %o", scriptInfo.Mode().Perm(), expectedScriptMode)
	}

	// Verify service is readable (0644)
	serviceDest := filepath.Join(overlayDir, "lib", "systemd", "system", "trusted-platform-network.service")
	serviceInfo, err := os.Stat(serviceDest)
	if err != nil {
		t.Fatalf("Failed to stat service: %v", err)
	}
	expectedServiceMode := os.FileMode(0644)
	if serviceInfo.Mode().Perm() != expectedServiceMode {
		t.Errorf("Service permissions incorrect: got %o, want %o", serviceInfo.Mode().Perm(), expectedServiceMode)
	}
}

// BenchmarkCopyNetworkSetupFiles benchmarks the network setup file copy operation
func BenchmarkCopyNetworkSetupFiles(b *testing.B) {
	tmpDir := b.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	configsDir := filepath.Join(tmpDir, "configs", "os")

	if err := os.MkdirAll(configsDir, 0755); err != nil {
		b.Fatalf("Failed to create configs directory: %v", err)
	}

	// Create network files
	scriptPath := filepath.Join(configsDir, "trusted-platform-network.sh")
	largeScriptContent := `#!/bin/bash
# Large test script for benchmarking
set -euo pipefail

log() {
    local level="$1"
    shift
    local message="$*"
    echo "[${level}] ${message}"
}

check_prerequisites() {
    log "INFO" "Checking prerequisites"
    for cmd in curl jq systemctl; do
        command -v "$cmd" > /dev/null || return 1
    done
}

main() {
    log "INFO" "Starting network setup"
    check_prerequisites
    log "INFO" "Setup complete"
}

main "$@"
`
	if err := os.WriteFile(scriptPath, []byte(largeScriptContent), 0755); err != nil {
		b.Fatalf("Failed to create script: %v", err)
	}

	servicePath := filepath.Join(configsDir, "trusted-platform-network.service")
	serviceContent := `[Unit]
Description=Test Service
After=network.target
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/test.sh
[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		b.Fatalf("Failed to create service: %v", err)
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay:    overlayDir,
			ConfigsDir: configsDir,
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create new overlay directory for each iteration
		iterOverlayDir := filepath.Join(tmpDir, "overlay", string(rune(i)))
		config.Directories.Overlay = iterOverlayDir

		customizer := NewCustomizer(config, logging.DefaultLogger())
		ctx := context.Background()

		if err := customizer.CopyNetworkSetupFiles(ctx); err != nil {
			b.Fatalf("CopyNetworkSetupFiles failed: %v", err)
		}
	}
}

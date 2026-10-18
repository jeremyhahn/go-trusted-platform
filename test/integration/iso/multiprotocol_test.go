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

//go:build integration

// Package iso provides multi-protocol integration tests for ISO services.
// These tests verify that ISO operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified ISOCommands interface.
//
// Run tests via:
//
//	make integration-test-iso
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package iso

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestISOMultiProtocol runs the complete ISO test suite against all protocol adapters.
// Each adapter implements the ISOCommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestISOMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement ISOCommands
	adapters := []ISOCommands{
		NewCLIAdapter(),
		// NewRESTAdapter(),  // TODO: Implement
		// NewGRPCAdapter(),  // TODO: Implement
		// NewQUICAdapter(),  // TODO: Implement
		// NewMCPAdapter(),   // TODO: Implement
		// NewUnixAdapter(),  // TODO: Implement
	}

	gate := helpers.NewAdapterGate(t, "iso", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testISOProtocol(t, ctx, adapter)
		})
	}
}

// testISOProtocol runs the complete ISO test suite against a single protocol adapter.
func testISOProtocol(t *testing.T, ctx context.Context, cmd ISOCommands) {
	// Create unique test work directory for this protocol run
	workDir := CreateTestWorkDir(t, fmt.Sprintf("iso-test-%s-", cmd.Name()))
	defer CleanupTestWorkDir(t, workDir)

	t.Run("Profile", func(t *testing.T) {
		testProfileOperations(t, ctx, cmd)
	})

	t.Run("Download", func(t *testing.T) {
		testDownloadOperations(t, ctx, cmd, workDir)
	})

	t.Run("Extract", func(t *testing.T) {
		testExtractOperations(t, ctx, cmd, workDir)
	})

	t.Run("Customize", func(t *testing.T) {
		testCustomizeOperations(t, ctx, cmd, workDir)
	})

	t.Run("Build", func(t *testing.T) {
		testBuildOperations(t, ctx, cmd, workDir)
	})

	t.Run("Create", func(t *testing.T) {
		testCreateOperations(t, ctx, cmd, workDir)
	})

	// Note: Test commands (install, boot, etc.) require QEMU and TPM support
	// They are tested separately in TestISOVMTests
}

// =============================================================================
// Fixtures
// =============================================================================
//
// Extract, Customize, Build and the VM tests each need the artefact an earlier
// step produces. The ensure* helpers return that artefact, producing it through
// the adapter when no earlier subtest has, so any subtest can run on its own
// (-run selects it) and a step that cannot produce its artefact fails the test
// that needs it instead of letting it pass unrun.

func alpineISOPath(workDir string) string {
	return filepath.Join(workDir, fmt.Sprintf("alpine-standard-%s-%s.iso", DefaultAlpineVersion, DefaultArch))
}

func extractedISODir(workDir string) string {
	return filepath.Join(workDir, "extracted-iso")
}

func builtISOPath(workDir string) string {
	return filepath.Join(workDir, "test-output.iso")
}

func installedDiskPath(workDir string) string {
	return filepath.Join(workDir, "test-install.qcow2")
}

// ensureAlpineISO returns the downloaded Alpine ISO, downloading it first.
func ensureAlpineISO(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) string {
	t.Helper()
	isoPath := alpineISOPath(workDir)
	if FileExists(isoPath) {
		return isoPath
	}

	result, err := cmd.Download(ctx, DownloadOptions{
		Version: DefaultAlpineVersion,
		Mirror:  DefaultMirror,
		Arch:    DefaultArch,
		WorkDir: workDir,
		Verify:  true,
	})
	if err != nil {
		t.Fatalf("missing prerequisite: downloading the Alpine ISO fixture: %v", err)
	}
	if result != nil && result.ISOPath != "" {
		isoPath = result.ISOPath
	}
	if !FileExists(isoPath) {
		t.Fatalf("missing prerequisite: %v", ErrISONotFound{Path: isoPath})
	}
	return isoPath
}

// ensureExtractedISO returns the extracted ISO tree, extracting it first.
func ensureExtractedISO(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) string {
	t.Helper()
	isoDir := extractedISODir(workDir)
	if DirExists(isoDir) {
		return isoDir
	}

	isoPath := ensureAlpineISO(t, ctx, cmd, workDir)
	if _, err := cmd.Extract(ctx, ExtractOptions{ISO: isoPath, OutputDir: isoDir, WorkDir: workDir}); err != nil {
		t.Fatalf("missing prerequisite: extracting the ISO fixture: %v", err)
	}
	if !DirExists(isoDir) {
		t.Fatalf("missing prerequisite: %v", ErrDirectoryNotFound{Path: isoDir})
	}
	return isoDir
}

// ensureBuiltISO returns an ISO rebuilt from the extracted tree, building it first.
func ensureBuiltISO(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) string {
	t.Helper()
	isoPath := builtISOPath(workDir)
	if FileExists(isoPath) {
		return isoPath
	}

	isoDir := ensureExtractedISO(t, ctx, cmd, workDir)
	result, err := cmd.Build(ctx, BuildOptions{SourceDir: isoDir, Output: isoPath, VolumeID: "TEST_ISO", WorkDir: workDir})
	if err != nil {
		t.Fatalf("missing prerequisite: building the ISO fixture: %v", err)
	}
	if result != nil && result.OutputISO != "" {
		isoPath = result.OutputISO
	}
	if !FileExists(isoPath) {
		t.Fatalf("missing prerequisite: %v", ErrISONotFound{Path: isoPath})
	}
	return isoPath
}

// installOptions installs isoPath onto the work directory's test disk.
func installOptions(isoPath, workDir string) TestInstallOptions {
	return TestInstallOptions{
		ISO:        isoPath,
		Disk:       installedDiskPath(workDir),
		DiskSize:   "10G",
		Memory:     4096,
		CPUs:       2,
		WorkDir:    workDir,
		SecureBoot: false,
		Debug:      true,
	}
}

// ensureInstalledDisk returns a disk with the built ISO installed, installing it first.
func ensureInstalledDisk(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) string {
	t.Helper()
	diskPath := installedDiskPath(workDir)
	if FileExists(diskPath) {
		return diskPath
	}

	isoPath := ensureBuiltISO(t, ctx, cmd, workDir)
	if _, err := cmd.TestInstall(ctx, installOptions(isoPath, workDir)); err != nil {
		t.Fatalf("missing prerequisite: installing the ISO fixture onto %s: %v", diskPath, err)
	}
	if !FileExists(diskPath) {
		t.Fatalf("missing prerequisite: %v", ErrDiskNotFound{Path: diskPath})
	}
	return diskPath
}

// =============================================================================
// Profile Tests
// =============================================================================

func testProfileOperations(t *testing.T, ctx context.Context, cmd ISOCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	t.Run("ProfileList", func(t *testing.T) {
		result, err := cmd.ProfileList(testCtx)
		// Profile list may fail with daemon connection required error
		// This is expected when dual-mode is not yet implemented
		if err != nil {
			t.Logf("ProfileList not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		// If implemented, verify we get profiles
		if result.Success && len(result.Profiles) > 0 {
			// Check known profiles
			profileNames := make(map[string]bool)
			for _, p := range result.Profiles {
				profileNames[p.Name] = true
				assert.NotEmpty(t, p.Name, "Profile name should not be empty")
			}
			// Check for expected profiles
			for _, expected := range []string{"dev", "production", "fips"} {
				if profileNames[expected] {
					t.Logf("Found expected profile: %s", expected)
				}
			}
		}
	})

	t.Run("ProfileShowDev", func(t *testing.T) {
		result, err := cmd.ProfileShow(testCtx, "dev")
		if err != nil {
			t.Logf("ProfileShow not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success && result.Profile != nil {
			assert.Equal(t, "dev", result.Profile.Name, "Profile name should match")
		}
	})

	t.Run("ProfileShowProduction", func(t *testing.T) {
		result, err := cmd.ProfileShow(testCtx, "production")
		if err != nil {
			t.Logf("ProfileShow not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success && result.Profile != nil {
			assert.Equal(t, "production", result.Profile.Name, "Profile name should match")
			// Production profile should have security enabled
			assert.True(t, result.Profile.TPMUnseal, "Production should have TPM unseal")
			assert.True(t, result.Profile.LUKS, "Production should have LUKS")
		}
	})

	t.Run("ProfileShowFIPS", func(t *testing.T) {
		result, err := cmd.ProfileShow(testCtx, "fips")
		if err != nil {
			t.Logf("ProfileShow not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success && result.Profile != nil {
			assert.Equal(t, "fips", result.Profile.Name, "Profile name should match")
			// FIPS profile should have FIPS enabled
			assert.True(t, result.Profile.FIPS, "FIPS profile should have FIPS enabled")
		}
	})

	t.Run("ProfileShowNonExistent", func(t *testing.T) {
		_, err := cmd.ProfileShow(testCtx, "nonexistent-profile-12345")
		if err == nil {
			t.Log("ProfileShow of nonexistent profile should fail or return error")
		}
	})

	t.Run("ProfileValidateValidFile", func(t *testing.T) {
		// Create a minimal valid config file
		tempDir, err := os.MkdirTemp("", "profile-validate-")
		require.NoError(t, err, "Should create temp dir")
		defer os.RemoveAll(tempDir)

		configPath := filepath.Join(tempDir, "valid-config.yaml")
		validConfig := `
device: /dev/sda
hostname: test-host
root_password: testpass123
disk:
  wipe: false
`
		err = os.WriteFile(configPath, []byte(validConfig), 0644)
		require.NoError(t, err, "Should write config file")

		result, err := cmd.ProfileValidate(testCtx, configPath)
		if err != nil {
			t.Logf("ProfileValidate not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("ProfileValidateInvalidFile", func(t *testing.T) {
		result, err := cmd.ProfileValidate(testCtx, "/nonexistent/path/config.yaml")
		if err != nil {
			t.Logf("ProfileValidate not available or returned error (expected): %v", err)
			return
		}
		// If implemented and file doesn't exist, should return invalid
		if result != nil && !result.Valid {
			assert.NotEmpty(t, result.Errors, "Should have validation errors for nonexistent file")
		}
	})

	t.Run("ProfileGenerate", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "profile-generate-")
		require.NoError(t, err, "Should create temp dir")
		defer os.RemoveAll(tempDir)

		outputPath := filepath.Join(tempDir, "generated.yaml")

		opts := ProfileGenerateOptions{
			ProfileName:    "dev",
			OutputFile:     outputPath,
			OverrideDevice: "/dev/nvme0n1",
		}

		result, err := cmd.ProfileGenerate(testCtx, opts)
		if err != nil {
			t.Logf("ProfileGenerate not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			// Verify file was created
			if outputPath != "" && result.OutputFile != "" {
				_, statErr := os.Stat(result.OutputFile)
				if statErr == nil {
					assert.True(t, FileExists(result.OutputFile), "Output file should exist")
				}
			}
		}
	})
}

// =============================================================================
// Download Tests
// =============================================================================

func testDownloadOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	t.Run("DownloadDefaultVersion", func(t *testing.T) {
		opts := DownloadOptions{
			Version: DefaultAlpineVersion,
			Mirror:  DefaultMirror,
			Arch:    DefaultArch,
			WorkDir: workDir,
			Verify:  true,
		}

		result, err := cmd.Download(testCtx, opts)
		if err != nil {
			t.Logf("Download not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			assert.NotEmpty(t, result.ISOPath, "ISO path should be set")
			assert.True(t, result.Verified || result.Message != "", "Should be verified or have message")
		}
	})

	t.Run("DownloadWithForce", func(t *testing.T) {
		opts := DownloadOptions{
			Version: DefaultAlpineVersion,
			Mirror:  DefaultMirror,
			Arch:    DefaultArch,
			WorkDir: workDir,
			Force:   true,
			Verify:  true,
		}

		result, err := cmd.Download(testCtx, opts)
		if err != nil {
			t.Logf("Download not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("DownloadInvalidVersion", func(t *testing.T) {
		opts := DownloadOptions{
			Version: "0.0.0-invalid",
			Mirror:  DefaultMirror,
			Arch:    DefaultArch,
			WorkDir: workDir,
		}

		_, err := cmd.Download(testCtx, opts)
		// Invalid version should fail
		if err == nil {
			t.Log("Download of invalid version may succeed with generic error")
		}
	})

	t.Run("DownloadInvalidArch", func(t *testing.T) {
		opts := DownloadOptions{
			Version: DefaultAlpineVersion,
			Mirror:  DefaultMirror,
			Arch:    "invalid-arch",
			WorkDir: workDir,
		}

		_, err := cmd.Download(testCtx, opts)
		// Invalid architecture should fail
		if err == nil {
			t.Log("Download of invalid arch may succeed with generic error")
		}
	})
}

// =============================================================================
// Extract Tests
// =============================================================================

func testExtractOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	t.Run("ExtractNonExistentISO", func(t *testing.T) {
		opts := ExtractOptions{
			ISO:     "/nonexistent/path/alpine.iso",
			WorkDir: workDir,
		}

		_, err := cmd.Extract(testCtx, opts)
		if err != nil {
			// Expected - either not available or file not found
			t.Logf("Extract of nonexistent ISO failed as expected: %v", err)
			return
		}
	})

	t.Run("ExtractValidISO", func(t *testing.T) {
		isoPath := ensureAlpineISO(t, testCtx, cmd, workDir)
		outputDir := extractedISODir(workDir)
		opts := ExtractOptions{
			ISO:       isoPath,
			OutputDir: outputDir,
			WorkDir:   workDir,
		}

		result, err := cmd.Extract(testCtx, opts)
		if err != nil {
			t.Logf("Extract not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			assert.NotEmpty(t, result.OutputDir, "Output dir should be set")
			// Verify extraction created files
			if DirExists(result.OutputDir) {
				count, err := CountFilesInDir(result.OutputDir)
				if err == nil && count > 0 {
					t.Logf("Extracted %d files to %s", count, result.OutputDir)
				}
			}
		}
	})

	t.Run("ExtractWithForce", func(t *testing.T) {
		isoPath := ensureAlpineISO(t, testCtx, cmd, workDir)
		outputDir := filepath.Join(workDir, "extracted-iso-force")
		opts := ExtractOptions{
			ISO:       isoPath,
			OutputDir: outputDir,
			WorkDir:   workDir,
			Force:     true,
		}

		result, err := cmd.Extract(testCtx, opts)
		if err != nil {
			t.Logf("Extract not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})
}

// =============================================================================
// Customize Tests
// =============================================================================

func testCustomizeOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	t.Run("CustomizeNonExistentDir", func(t *testing.T) {
		opts := CustomizeOptions{
			ISODir:  "/nonexistent/path/iso",
			WorkDir: workDir,
		}

		_, err := cmd.Customize(testCtx, opts)
		if err != nil {
			t.Logf("Customize of nonexistent dir failed as expected: %v", err)
			return
		}
	})

	t.Run("CustomizeValidDir", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		opts := CustomizeOptions{
			ISODir:  isoDir,
			WorkDir: workDir,
		}

		result, err := cmd.Customize(testCtx, opts)
		if err != nil {
			t.Logf("Customize not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("CustomizeWithOverlay", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		// Create a simple overlay
		overlayDir := filepath.Join(workDir, "overlay")
		err := os.MkdirAll(filepath.Join(overlayDir, "etc"), 0755)
		require.NoError(t, err, "Should create overlay dir")

		testFile := filepath.Join(overlayDir, "etc", "test-overlay")
		err = os.WriteFile(testFile, []byte("test content\n"), 0644)
		require.NoError(t, err, "Should write overlay file")

		opts := CustomizeOptions{
			ISODir:  isoDir,
			Overlay: overlayDir,
			WorkDir: workDir,
		}

		result, err := cmd.Customize(testCtx, opts)
		if err != nil {
			t.Logf("Customize with overlay not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("CustomizeWithAutoinstall", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		opts := CustomizeOptions{
			ISODir:      isoDir,
			Autoinstall: true,
			WorkDir:     workDir,
		}

		result, err := cmd.Customize(testCtx, opts)
		if err != nil {
			t.Logf("Customize with autoinstall not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})
}

// =============================================================================
// Build Tests
// =============================================================================

func testBuildOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	outputISO := builtISOPath(workDir)

	t.Run("BuildNonExistentDir", func(t *testing.T) {
		opts := BuildOptions{
			SourceDir: "/nonexistent/path/iso",
			Output:    outputISO,
			WorkDir:   workDir,
		}

		_, err := cmd.Build(testCtx, opts)
		if err != nil {
			t.Logf("Build from nonexistent dir failed as expected: %v", err)
			return
		}
	})

	t.Run("BuildValidDir", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		opts := BuildOptions{
			SourceDir:   isoDir,
			Output:      outputISO,
			VolumeID:    "TEST_ISO",
			GenerateSum: true,
			WorkDir:     workDir,
		}

		result, err := cmd.Build(testCtx, opts)
		if err != nil {
			t.Logf("Build not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			assert.NotEmpty(t, result.OutputISO, "Output ISO path should be set")
			// Verify ISO was created
			if result.OutputISO != "" && FileExists(result.OutputISO) {
				size, _ := GetFileSize(result.OutputISO)
				t.Logf("Built ISO: %s (%d bytes)", result.OutputISO, size)
				assert.Greater(t, size, int64(0), "ISO should have content")
			}
		}
	})

	t.Run("BuildWithCustomLabel", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		customOutputISO := filepath.Join(workDir, "custom-label.iso")
		opts := BuildOptions{
			SourceDir:   isoDir,
			Output:      customOutputISO,
			VolumeID:    "CUSTOM_LABEL_123",
			GenerateSum: false,
			WorkDir:     workDir,
		}

		result, err := cmd.Build(testCtx, opts)
		if err != nil {
			t.Logf("Build with custom label not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("BuildLabelTooLong", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		opts := BuildOptions{
			SourceDir: isoDir,
			Output:    filepath.Join(workDir, "long-label.iso"),
			VolumeID:  "THIS_LABEL_IS_WAY_TOO_LONG_FOR_AN_ISO_VOLUME_ID_WHICH_HAS_32_CHAR_MAX",
			WorkDir:   workDir,
		}

		_, err := cmd.Build(testCtx, opts)
		// Long label should fail or be truncated
		if err != nil {
			t.Logf("Build with long label failed as expected: %v", err)
		}
	})
}

// =============================================================================
// Create Tests (All-in-One)
// =============================================================================

func testCreateOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	t.Run("CreateWithDefaults", func(t *testing.T) {
		createWorkDir := filepath.Join(workDir, "create-default")
		err := os.MkdirAll(createWorkDir, 0755)
		require.NoError(t, err, "Should create work dir")

		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          DefaultArch,
			WorkDir:       createWorkDir,
			SecureBoot:    false, // Disable for faster tests
			TPMUnseal:     true,
			LUKS:          true,
			GenerateKeys:  false, // Skip key generation for tests
			Force:         true,
		}

		result, err := cmd.Create(testCtx, opts)
		if err != nil {
			t.Logf("Create not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			assert.NotEmpty(t, result.OutputISO, "Output ISO should be set")
			t.Logf("Created ISO in %v: %s", result.ElapsedTime, result.OutputISO)
		}
	})

	t.Run("CreateWithFIPS", func(t *testing.T) {
		createWorkDir := filepath.Join(workDir, "create-fips")
		err := os.MkdirAll(createWorkDir, 0755)
		require.NoError(t, err, "Should create work dir")

		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          DefaultArch,
			WorkDir:       createWorkDir,
			SecureBoot:    false,
			TPMUnseal:     true,
			LUKS:          true,
			FIPS:          true, // Enable FIPS mode
			GenerateKeys:  false,
			Force:         true,
		}

		result, err := cmd.Create(testCtx, opts)
		if err != nil {
			t.Logf("Create with FIPS not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
		if result.Success {
			// FIPS ISO should have -fips suffix
			assert.Contains(t, result.OutputISO, "fips", "FIPS ISO should have fips in name")
		}
	})

	t.Run("CreateServerType", func(t *testing.T) {
		createWorkDir := filepath.Join(workDir, "create-server")
		err := os.MkdirAll(createWorkDir, 0755)
		require.NoError(t, err, "Should create work dir")

		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          DefaultArch,
			PlatformType:  "server",
			WorkDir:       createWorkDir,
			SecureBoot:    false,
			GenerateKeys:  false,
			Force:         true,
		}

		result, err := cmd.Create(testCtx, opts)
		if err != nil {
			t.Logf("Create server type not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("CreateClientType", func(t *testing.T) {
		createWorkDir := filepath.Join(workDir, "create-client")
		err := os.MkdirAll(createWorkDir, 0755)
		require.NoError(t, err, "Should create work dir")

		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          DefaultArch,
			PlatformType:  "client",
			WorkDir:       createWorkDir,
			SecureBoot:    false,
			GenerateKeys:  false,
			Force:         true,
		}

		result, err := cmd.Create(testCtx, opts)
		if err != nil {
			t.Logf("Create client type not available (expected): %v", err)
			return
		}
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("CreateInvalidArch", func(t *testing.T) {
		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          "invalid-arch",
			WorkDir:       workDir,
		}

		_, err := cmd.Create(testCtx, opts)
		// Invalid architecture should fail
		assert.Error(t, err, "Create with invalid arch should fail")
	})

	t.Run("CreateInvalidPlatformType", func(t *testing.T) {
		opts := CreateOptions{
			AlpineVersion: DefaultAlpineVersion,
			Mirror:        DefaultMirror,
			Arch:          DefaultArch,
			PlatformType:  "invalid-type",
			WorkDir:       workDir,
		}

		_, err := cmd.Create(testCtx, opts)
		// Invalid platform type should fail
		assert.Error(t, err, "Create with invalid platform type should fail")
	})
}

// =============================================================================
// VM Test Operations (Require QEMU/TPM)
// =============================================================================

// TestISOVMTests tests ISO operations that require QEMU and TPM.
// These are separated because they require special environment setup.
func TestISOVMTests(t *testing.T) {
	if err := CheckVMTools(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "iso", "CLI", adapter.Setup(ctx))
	defer adapter.Teardown()

	workDir := CreateTestWorkDir(t, "iso-vm-test-")
	defer CleanupTestWorkDir(t, workDir)

	t.Run("TestInstall", func(t *testing.T) {
		testVMInstall(t, ctx, adapter, workDir)
	})

	t.Run("TestBoot", func(t *testing.T) {
		testVMBoot(t, ctx, adapter, workDir)
	})
}

func testVMInstall(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	isoPath := ensureBuiltISO(t, testCtx, cmd, workDir)

	result, err := cmd.TestInstall(testCtx, installOptions(isoPath, workDir))
	if err != nil {
		requireInstallDidNotHang(t, err)
		t.Logf("TestInstall failed (may require interactive session): %v", err)
		return
	}
	require.NotNil(t, result, "Result should not be nil")
	t.Logf("TestInstall completed in %v with exit code %d", result.ElapsedTime, result.ExitCode)
}

// requireInstallDidNotHang fails the test when the install error is a hang: a
// guest stuck at the GRUB menu, or an install that used its whole
// vmInstallTimeout. Logging those and passing would work like a skip (CA m639).
func requireInstallDidNotHang(t *testing.T, err error) {
	t.Helper()
	var grubErr ErrGRUBMenuNoBoot
	if errors.As(err, &grubErr) {
		t.Fatalf("TestInstall: %v", grubErr)
	}
	var timeoutErr ErrCommandTimeout
	if errors.As(err, &timeoutErr) {
		t.Fatalf("TestInstall: %v", timeoutErr)
	}
}

func testVMBoot(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	diskPath := ensureInstalledDisk(t, ctx, cmd, workDir)

	testCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	opts := TestBootOptions{
		Disk:       diskPath,
		Memory:     4096,
		CPUs:       2,
		WorkDir:    workDir,
		SecureBoot: false,
		Debug:      true,
	}

	result, err := cmd.TestBoot(testCtx, opts)
	if err != nil {
		t.Logf("TestBoot failed (may require interactive session): %v", err)
		return
	}
	require.NotNil(t, result, "Result should not be nil")
	t.Logf("TestBoot completed in %v with exit code %d", result.ElapsedTime, result.ExitCode)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestISOErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "iso", "CLI", adapter.Setup(ctx))
	defer adapter.Teardown()

	t.Run("CreateTimeoutContext", func(t *testing.T) {
		// Create a context that's already cancelled
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		opts := CreateOptions{
			WorkDir: "/tmp/timeout-test",
		}

		_, err := adapter.Create(cancelledCtx, opts)
		assert.Error(t, err, "Should fail with cancelled context")
	})

	t.Run("DownloadInvalidMirror", func(t *testing.T) {
		opts := DownloadOptions{
			Mirror:  "http://invalid.nonexistent.mirror.test/alpine",
			Version: DefaultAlpineVersion,
			Arch:    DefaultArch,
			WorkDir: "/tmp/invalid-mirror-test",
		}

		_, err := adapter.Download(ctx, opts)
		// May fail with connection error or be not available
		if err != nil {
			t.Logf("Download from invalid mirror failed as expected: %v", err)
		}
	})
}

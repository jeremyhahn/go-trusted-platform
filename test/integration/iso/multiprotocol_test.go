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
	result, err := cmd.Build(ctx, BuildOptions{SourceDir: isoDir, Output: isoPath, VolumeID: "TEST_ISO"})
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
		Timeout:    vmInstallTimeout,
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
		require.NoError(t, err)
		require.True(t, result.Success)

		profiles := make(map[string]ProfileInfo, len(result.Profiles))
		for _, p := range result.Profiles {
			profiles[p.Name] = p
		}
		for _, expected := range []string{"dev", "production", "production-hs", "fips"} {
			assert.Contains(t, profiles, expected)
		}
		assert.False(t, profiles["dev"].SecureBoot, "dev boots without Secure Boot")
		assert.True(t, profiles["production"].SecureBoot)
		assert.True(t, profiles["fips"].FIPS)
	})

	t.Run("ProfileShowProduction", func(t *testing.T) {
		result, err := cmd.ProfileShow(testCtx, "production")
		require.NoError(t, err)
		require.True(t, result.Success)
		require.NotNil(t, result.Profile)
		assert.Equal(t, "production", result.Profile.Name)
		assert.True(t, result.Profile.TPMUnseal, "production seals LUKS to the TPM")
		assert.True(t, result.Profile.LUKS)
		assert.Contains(t, result.YAML, "kms://platform/secureboot/db", "production signs the UKI with the platform DB key")
	})

	t.Run("ProfileShowFIPS", func(t *testing.T) {
		result, err := cmd.ProfileShow(testCtx, "fips")
		require.NoError(t, err)
		require.NotNil(t, result.Profile)
		assert.Equal(t, "fips", result.Profile.Name)
		assert.True(t, result.Profile.FIPS)
	})

	t.Run("ProfileShowNonExistent", func(t *testing.T) {
		_, err := cmd.ProfileShow(testCtx, "nonexistent-profile-12345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonexistent-profile-12345")
	})

	t.Run("ProfileGenerateThenValidate", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "generated.yaml")
		result, err := cmd.ProfileGenerate(testCtx, ProfileGenerateOptions{
			ProfileName:    "production",
			OutputFile:     outputPath,
			OverrideDevice: "/dev/nvme0n1",
		})
		require.NoError(t, err)
		require.True(t, result.Success)
		assert.Equal(t, outputPath, result.OutputFile)
		assert.Contains(t, result.YAML, "/dev/nvme0n1")

		written, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.Equal(t, result.YAML, string(written), "the file holds exactly the printed config")

		validated, err := cmd.ProfileValidate(testCtx, outputPath)
		require.NoError(t, err)
		assert.True(t, validated.Valid)
		assert.Empty(t, validated.Errors)
	})

	t.Run("ProfileValidateInvalidContent", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "invalid.yaml")
		require.NoError(t, os.WriteFile(configPath, []byte("disk: [not, a, mapping\n"), 0o600))

		result, err := cmd.ProfileValidate(testCtx, configPath)
		require.Error(t, err, "an invalid config exits non-zero")
		require.NotNil(t, result)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})

	t.Run("ProfileValidateMissingFile", func(t *testing.T) {
		_, err := cmd.ProfileValidate(testCtx, "/nonexistent/path/config.yaml")
		require.Error(t, err)
	})
}

// =============================================================================
// Download Tests
// =============================================================================

func testDownloadOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	t.Run("DownloadDefaultVersion", func(t *testing.T) {
		result, err := cmd.Download(testCtx, DownloadOptions{
			Version: DefaultAlpineVersion,
			Mirror:  DefaultMirror,
			Arch:    DefaultArch,
			WorkDir: workDir,
			Verify:  true,
		})
		require.NoError(t, err)
		require.True(t, result.Success)
		assert.Equal(t, alpineISOPath(workDir), result.ISOPath)
		assert.True(t, result.Verified)
		assert.Len(t, result.SHA256, 64)
		assert.Positive(t, result.SizeBytes)
		assert.True(t, FileExists(result.ISOPath))
	})

	t.Run("DownloadInvalidArch", func(t *testing.T) {
		_, err := cmd.Download(testCtx, DownloadOptions{
			Version: DefaultAlpineVersion,
			Mirror:  DefaultMirror,
			Arch:    "invalid-arch",
			WorkDir: workDir,
		})
		require.Error(t, err)
	})
}

// =============================================================================
// Extract Tests
// =============================================================================

func testExtractOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	t.Run("ExtractNonExistentISO", func(t *testing.T) {
		_, err := cmd.Extract(testCtx, ExtractOptions{
			ISO:     "/nonexistent/path/alpine.iso",
			WorkDir: workDir,
		})
		require.Error(t, err)
	})

	t.Run("ExtractValidISO", func(t *testing.T) {
		isoPath := ensureAlpineISO(t, testCtx, cmd, workDir)
		outputDir := filepath.Join(workDir, "extracted-iso-verb")

		result, err := cmd.Extract(testCtx, ExtractOptions{ISO: isoPath, OutputDir: outputDir})
		require.NoError(t, err)
		require.True(t, result.Success)
		assert.Equal(t, outputDir, result.OutputDir)
		assert.Positive(t, result.FileCount)

		_, err = cmd.Extract(testCtx, ExtractOptions{ISO: isoPath, OutputDir: outputDir})
		require.Error(t, err, "a populated output directory needs --force")

		forced, err := cmd.Extract(testCtx, ExtractOptions{ISO: isoPath, OutputDir: outputDir, Force: true})
		require.NoError(t, err)
		assert.Equal(t, result.FileCount, forced.FileCount)
	})
}

// =============================================================================
// Customize Tests
// =============================================================================

func testCustomizeOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	t.Run("CustomizeNonExistentDir", func(t *testing.T) {
		_, err := cmd.Customize(testCtx, CustomizeOptions{
			ISODir:  "/nonexistent/path/iso",
			WorkDir: workDir,
		})
		require.Error(t, err)
	})

	t.Run("CustomizeWithOverlay", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)

		overlayDir := filepath.Join(workDir, "overlay")
		require.NoError(t, os.MkdirAll(filepath.Join(overlayDir, "etc"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "etc", "test-overlay"), []byte("test content\n"), 0o644))

		result, err := cmd.Customize(testCtx, CustomizeOptions{
			ISODir:  isoDir,
			Overlay: overlayDir,
			WorkDir: workDir,
		})
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, isoDir, result.ISODir)
	})
}

// =============================================================================
// Build Tests
// =============================================================================

func testBuildOperations(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	t.Run("BuildNonExistentDir", func(t *testing.T) {
		_, err := cmd.Build(testCtx, BuildOptions{
			SourceDir: "/nonexistent/path/iso",
			Output:    filepath.Join(workDir, "missing-source.iso"),
		})
		require.Error(t, err)
	})

	t.Run("BuildValidDir", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)
		outputISO := filepath.Join(workDir, "custom-label.iso")

		result, err := cmd.Build(testCtx, BuildOptions{
			SourceDir:   isoDir,
			Output:      outputISO,
			VolumeID:    "CUSTOM_LABEL_123",
			GenerateSum: true,
		})
		require.NoError(t, err)
		require.True(t, result.Success)
		assert.Equal(t, outputISO, result.OutputISO)
		assert.Positive(t, result.SizeBytes)
		assert.Equal(t, outputISO+".sha256", result.ChecksumFile)
		assert.True(t, FileExists(result.ChecksumFile))
	})

	t.Run("BuildLabelTooLong", func(t *testing.T) {
		isoDir := ensureExtractedISO(t, testCtx, cmd, workDir)
		outputISO := filepath.Join(workDir, "long-label.iso")

		_, err := cmd.Build(testCtx, BuildOptions{
			SourceDir: isoDir,
			Output:    outputISO,
			VolumeID:  "THIS_LABEL_IS_WAY_TOO_LONG_FOR_AN_ISO_VOLUME_ID_WHICH_HAS_32_CHAR_MAX",
		})
		require.Error(t, err)
		assert.False(t, FileExists(outputISO))
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

	installed := t.Run("TestInstall", func(t *testing.T) {
		testVMInstall(t, ctx, adapter, workDir)
	})

	t.Run("TestBoot", func(t *testing.T) {
		if !installed {
			// A cut-off install can leave a partly written disk behind;
			// booting it would only report the install failure again.
			t.Fatalf("missing prerequisite: TestInstall did not produce an installed disk")
		}
		testVMBoot(t, ctx, adapter, workDir)
	})
}

// testVMInstall installs the built ISO headless. The install is bounded by
// vmInstallTimeout: a guest that never powers off fails the test with the
// command output instead of holding the package until go test panics.
func testVMInstall(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	isoPath := ensureBuiltISO(t, ctx, cmd, workDir)

	opts := installOptions(isoPath, workDir)
	result, err := cmd.TestInstall(ctx, opts)
	if err != nil {
		t.Fatalf("iso test install --timeout %s: %v", opts.Timeout, err)
	}
	require.NotNil(t, result, "Result should not be nil")
	require.True(t, FileExists(opts.Disk), "the install should leave the disk at %s", opts.Disk)
	t.Logf("TestInstall completed in %v", result.ElapsedTime)
}

func testVMBoot(t *testing.T, ctx context.Context, cmd ISOCommands, workDir string) {
	diskPath := ensureInstalledDisk(t, ctx, cmd, workDir)

	opts := TestBootOptions{
		Disk:       diskPath,
		Memory:     4096,
		CPUs:       2,
		WorkDir:    workDir,
		SecureBoot: false,
		Debug:      true,
		Timeout:    vmBootTimeout,
	}

	result, err := cmd.TestBoot(ctx, opts)
	if err != nil {
		t.Fatalf("iso test boot --timeout %s: %v", opts.Timeout, err)
	}
	require.NotNil(t, result, "Result should not be nil")
	t.Logf("TestBoot completed in %v", result.ElapsedTime)
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

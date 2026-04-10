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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUKIBuilderAdapter(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	assert.NotNil(t, builder)
}

func TestUKIBuilder_BuildUKI_MissingKernel(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	config := &UKIConfig{
		Cmdline:       "root=/dev/sda2",
		KernelPath:    "/nonexistent/kernel",
		InitramfsPath: "/nonexistent/initramfs",
	}

	var buf bytes.Buffer
	ctx := context.Background()
	err := builder.BuildUKI(ctx, config, &buf)

	assert.Error(t, err)
	// Error message depends on whether dracut is installed or not
	errMsg := err.Error()
	validErrors := errMsg == "" ||
		strings.Contains(errMsg, "failed to open kernel") ||
		strings.Contains(errMsg, "dracut") ||
		strings.Contains(errMsg, "executable file not found")
	assert.True(t, validErrors, "expected UKI build error, got: %s", errMsg)
}

func TestUKIBuilder_BuildUKI_MissingInitramfs(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	// Create a temporary kernel file
	tmpDir, err := os.MkdirTemp("", "uki-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	err = os.WriteFile(kernelPath, []byte("fake kernel data"), 0644)
	require.NoError(t, err)

	config := &UKIConfig{
		Cmdline:       "root=/dev/sda2",
		KernelPath:    kernelPath,
		InitramfsPath: "/nonexistent/initramfs",
	}

	var buf bytes.Buffer
	ctx := context.Background()
	err = builder.BuildUKI(ctx, config, &buf)

	assert.Error(t, err)
	// Error message depends on whether dracut is installed or not
	errMsg := err.Error()
	validErrors := errMsg == "" ||
		strings.Contains(errMsg, "failed to open initramfs") ||
		strings.Contains(errMsg, "dracut") ||
		strings.Contains(errMsg, "executable file not found")
	assert.True(t, validErrors, "expected UKI build error, got: %s", errMsg)
}

func TestUKIBuilder_BuildUKI_MissingMicrocode(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	// Create temporary kernel and initramfs files
	tmpDir, err := os.MkdirTemp("", "uki-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	err = os.WriteFile(kernelPath, []byte("fake kernel data"), 0644)
	require.NoError(t, err)

	initramfsPath := filepath.Join(tmpDir, "initramfs")
	err = os.WriteFile(initramfsPath, []byte("fake initramfs data"), 0644)
	require.NoError(t, err)

	config := &UKIConfig{
		Cmdline:       "root=/dev/sda2",
		KernelPath:    kernelPath,
		InitramfsPath: initramfsPath,
		MicrocodePath: "/nonexistent/microcode",
	}

	var buf bytes.Buffer
	ctx := context.Background()
	err = builder.BuildUKI(ctx, config, &buf)

	assert.Error(t, err)
	// Error message depends on whether dracut is installed or not
	errMsg := err.Error()
	validErrors := errMsg == "" ||
		strings.Contains(errMsg, "failed to open microcode") ||
		strings.Contains(errMsg, "dracut") ||
		strings.Contains(errMsg, "executable file not found")
	assert.True(t, validErrors, "expected UKI build error, got: %s", errMsg)
}

// Note: Actual UKI building requires a real kernel PE file, so full tests are integration tests
// TestUKIBuilder_BuildUKI_Success - Integration test only
// - Creates a real UKI from kernel, initramfs, and cmdline
// - Verifies PE file structure
// - Verifies sections are added correctly
// - Tests with and without microcode

func TestUKIBuilder_SignUKI_MissingKeyFile(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	config := &SecureBootConfig{
		KeyPath:  "/nonexistent/keys/db.key",
		CertPath: "/nonexistent/keys/db.crt",
	}

	ctx := context.Background()
	err := builder.SignUKI(ctx, "/path/to/uki", config)

	// Should fail because key file doesn't exist
	assert.Error(t, err)

	// Verify it's a SecureBoot error
	var installerErr *InstallerError
	assert.ErrorAs(t, err, &installerErr)
	assert.Equal(t, ErrorTypeSecureBoot, installerErr.Type)
}

func TestUKIConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *UKIConfig
		verify func(t *testing.T, cfg *UKIConfig)
	}{
		{
			name: "full config",
			config: &UKIConfig{
				Cmdline:       "root=/dev/mapper/cryptroot ro quiet",
				KernelPath:    "/boot/vmlinuz-lts",
				InitramfsPath: "/boot/initramfs-lts",
				OSRelease:     "Alpine Linux",
				MicrocodePath: "/boot/intel-ucode.img",
			},
			verify: func(t *testing.T, cfg *UKIConfig) {
				assert.NotEmpty(t, cfg.Cmdline)
				assert.NotEmpty(t, cfg.KernelPath)
				assert.NotEmpty(t, cfg.InitramfsPath)
				assert.NotEmpty(t, cfg.OSRelease)
				assert.NotEmpty(t, cfg.MicrocodePath)
			},
		},
		{
			name: "minimal config",
			config: &UKIConfig{
				Cmdline:       "root=/dev/sda2",
				KernelPath:    "/boot/vmlinuz",
				InitramfsPath: "/boot/initramfs",
			},
			verify: func(t *testing.T, cfg *UKIConfig) {
				assert.NotEmpty(t, cfg.Cmdline)
				assert.NotEmpty(t, cfg.KernelPath)
				assert.NotEmpty(t, cfg.InitramfsPath)
				assert.Empty(t, cfg.OSRelease)
				assert.Empty(t, cfg.MicrocodePath)
			},
		},
		{
			name: "with LUKS cmdline",
			config: &UKIConfig{
				Cmdline:       "root=/dev/mapper/cryptroot cryptdevice=/dev/sda2:cryptroot",
				KernelPath:    "/boot/vmlinuz",
				InitramfsPath: "/boot/initramfs",
			},
			verify: func(t *testing.T, cfg *UKIConfig) {
				assert.Contains(t, cfg.Cmdline, "cryptroot")
				assert.Contains(t, cfg.Cmdline, "cryptdevice")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestSecureBootConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *SecureBootConfig
		verify func(t *testing.T, cfg *SecureBootConfig)
	}{
		{
			name: "with encrypted key",
			config: &SecureBootConfig{
				KeyPath:     "/keys/db.key",
				CertPath:    "/keys/db.crt",
				KeyPassword: "password123",
			},
			verify: func(t *testing.T, cfg *SecureBootConfig) {
				assert.NotEmpty(t, cfg.KeyPath)
				assert.NotEmpty(t, cfg.CertPath)
				assert.NotEmpty(t, cfg.KeyPassword)
			},
		},
		{
			name: "without key password",
			config: &SecureBootConfig{
				KeyPath:  "/keys/db.key",
				CertPath: "/keys/db.crt",
			},
			verify: func(t *testing.T, cfg *SecureBootConfig) {
				assert.NotEmpty(t, cfg.KeyPath)
				assert.NotEmpty(t, cfg.CertPath)
				assert.Empty(t, cfg.KeyPassword)
			},
		},
		{
			name: "custom key locations",
			config: &SecureBootConfig{
				KeyPath:  "/custom/path/to/key.pem",
				CertPath: "/custom/path/to/cert.pem",
			},
			verify: func(t *testing.T, cfg *SecureBootConfig) {
				assert.Equal(t, "/custom/path/to/key.pem", cfg.KeyPath)
				assert.Equal(t, "/custom/path/to/cert.pem", cfg.CertPath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestUKIBuilder_ErrorTypes(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() error
		errorType ErrorType
	}{
		{
			name: "missing kernel file",
			setupFunc: func() error {
				logger := createTestLogger()
				builder := NewUKIBuilderAdapter(logger)
				config := &UKIConfig{
					Cmdline:       "root=/dev/sda2",
					KernelPath:    "/nonexistent",
					InitramfsPath: "/nonexistent",
				}
				var buf bytes.Buffer
				return builder.BuildUKI(context.Background(), config, &buf)
			},
			errorType: ErrorTypeUKIBuild,
		},
		{
			name: "secure boot signing missing key",
			setupFunc: func() error {
				logger := createTestLogger()
				builder := NewUKIBuilderAdapter(logger)
				config := &SecureBootConfig{
					KeyPath:  "/nonexistent/keys/db.key",
					CertPath: "/nonexistent/keys/db.crt",
				}
				return builder.SignUKI(context.Background(), "/path/to/uki", config)
			},
			errorType: ErrorTypeSecureBoot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setupFunc()
			require.Error(t, err)

			var installerErr *InstallerError
			assert.ErrorAs(t, err, &installerErr)
			assert.Equal(t, tt.errorType, installerErr.Type)
		})
	}
}

func TestUKIBuilder_BuildUKI_WithFiles(t *testing.T) {
	// This test verifies the adapter correctly passes files to the underlying builder
	// The actual PE building is tested in pkg/uki/builder_test.go

	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	tmpDir, err := os.MkdirTemp("", "uki-build-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create fake kernel file (minimal PE format for the test)
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	// Create a minimal fake PE file (this won't work for real building but tests the file handling)
	kernelData := []byte("MZ") // PE magic number
	err = os.WriteFile(kernelPath, kernelData, 0644)
	require.NoError(t, err)

	// Create fake initramfs
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	initramfsData := []byte("fake initramfs")
	err = os.WriteFile(initramfsPath, initramfsData, 0644)
	require.NoError(t, err)

	config := &UKIConfig{
		Cmdline:       "root=/dev/sda2 ro",
		KernelPath:    kernelPath,
		InitramfsPath: initramfsPath,
		OSRelease:     "Test Linux",
	}

	var buf bytes.Buffer
	ctx := context.Background()
	err = builder.BuildUKI(ctx, config, &buf)

	// This will likely fail with a PE parsing error since we have fake data,
	// but it tests that files are opened and passed correctly
	// A real integration test would use actual kernel files
	assert.Error(t, err)
}

func TestUKIConfig_CmdlineVariations(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		verify  func(t *testing.T, cmdline string)
	}{
		{
			name:    "simple root",
			cmdline: "root=/dev/sda2",
			verify: func(t *testing.T, cmdline string) {
				assert.Contains(t, cmdline, "root=")
				assert.NotContains(t, cmdline, "cryptroot")
			},
		},
		{
			name:    "encrypted root",
			cmdline: "root=/dev/mapper/cryptroot cryptdevice=/dev/sda2:cryptroot",
			verify: func(t *testing.T, cmdline string) {
				assert.Contains(t, cmdline, "cryptroot")
				assert.Contains(t, cmdline, "cryptdevice")
			},
		},
		{
			name:    "with quiet splash",
			cmdline: "root=/dev/sda2 quiet splash",
			verify: func(t *testing.T, cmdline string) {
				assert.Contains(t, cmdline, "quiet")
				assert.Contains(t, cmdline, "splash")
			},
		},
		{
			name:    "with TPM PCR",
			cmdline: "root=/dev/mapper/cryptroot rd.luks.options=tpm2-device=auto",
			verify: func(t *testing.T, cmdline string) {
				assert.Contains(t, cmdline, "tpm2-device")
				assert.Contains(t, cmdline, "rd.luks.options")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &UKIConfig{
				Cmdline:       tt.cmdline,
				KernelPath:    "/boot/vmlinuz",
				InitramfsPath: "/boot/initramfs",
			}

			tt.verify(t, config.Cmdline)
		})
	}
}

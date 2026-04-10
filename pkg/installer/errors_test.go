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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInstallerError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *InstallerError
		expected string
	}{
		{
			name: "error with cause",
			err: &InstallerError{
				Type:    ErrorTypeDiskOperation,
				Message: "failed to create partition",
				Cause:   errors.New("device not found"),
			},
			expected: "disk_operation: failed to create partition: device not found",
		},
		{
			name: "error without cause",
			err: &InstallerError{
				Type:    ErrorTypeInvalidConfig,
				Message: "device is required",
			},
			expected: "invalid_config: device is required",
		},
		{
			name: "encryption error with cause",
			err: &InstallerError{
				Type:    ErrorTypeEncryption,
				Message: "LUKS format failed",
				Cause:   errors.New("cryptsetup not found"),
			},
			expected: "encryption: LUKS format failed: cryptsetup not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInstallerError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      *InstallerError
		expected error
	}{
		{
			name: "unwrap with cause",
			err: &InstallerError{
				Type:    ErrorTypeDiskOperation,
				Message: "test message",
				Cause:   errors.New("underlying error"),
			},
			expected: errors.New("underlying error"),
		},
		{
			name: "unwrap without cause",
			err: &InstallerError{
				Type:    ErrorTypeInvalidConfig,
				Message: "test message",
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Unwrap()
			if tt.expected != nil {
				assert.EqualError(t, result, tt.expected.Error())
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestErrInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "missing device",
			message:  "disk device is required",
			expected: "invalid_config: disk device is required",
		},
		{
			name:     "missing OS config",
			message:  "OS configuration is required",
			expected: "invalid_config: OS configuration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidConfig(tt.message)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			// Verify it's an InstallerError
			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeInvalidConfig, installerErr.Type)
			assert.Nil(t, installerErr.Cause)
		})
	}
}

func TestErrDiskOperation(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "partition creation failed",
			message:  "failed to create partition",
			cause:    errors.New("device busy"),
			expected: "disk_operation: failed to create partition: device busy",
		},
		{
			name:     "mount failed",
			message:  "failed to mount filesystem",
			cause:    errors.New("invalid argument"),
			expected: "disk_operation: failed to mount filesystem: invalid argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDiskOperation(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			// Verify error type and unwrapping
			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeDiskOperation, installerErr.Type)
			assert.True(t, errors.Is(err, tt.cause))
		})
	}
}

func TestErrEncryption(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "LUKS format failed",
			message:  "failed to format LUKS",
			cause:    errors.New("cryptsetup error"),
			expected: "encryption: failed to format LUKS: cryptsetup error",
		},
		{
			name:     "LUKS open failed",
			message:  "failed to open LUKS container",
			cause:    errors.New("invalid passphrase"),
			expected: "encryption: failed to open LUKS container: invalid passphrase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrEncryption(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeEncryption, installerErr.Type)
		})
	}
}

func TestErrOSInstall(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "base install failed",
			message:  "failed to install base system",
			cause:    errors.New("download failed"),
			expected: "os_install: failed to install base system: download failed",
		},
		{
			name:     "package install failed",
			message:  "failed to install package",
			cause:    errors.New("package not found"),
			expected: "os_install: failed to install package: package not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrOSInstall(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeOSInstall, installerErr.Type)
		})
	}
}

func TestErrUKIBuild(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "kernel not found",
			message:  "failed to open kernel",
			cause:    errors.New("file not found"),
			expected: "uki_build: failed to open kernel: file not found",
		},
		{
			name:     "build failed",
			message:  "failed to build UKI",
			cause:    errors.New("invalid PE format"),
			expected: "uki_build: failed to build UKI: invalid PE format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrUKIBuild(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeUKIBuild, installerErr.Type)
		})
	}
}

func TestErrSecureBoot(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "signing failed",
			message:  "failed to sign UKI",
			cause:    errors.New("key not found"),
			expected: "secure_boot: failed to sign UKI: key not found",
		},
		{
			name:     "not implemented",
			message:  "Secure Boot signing not yet implemented",
			cause:    nil,
			expected: "secure_boot: Secure Boot signing not yet implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrSecureBoot(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeSecureBoot, installerErr.Type)
		})
	}
}

func TestErrTPM(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "sealing failed",
			message:  "failed to seal to TPM",
			cause:    errors.New("TPM not available"),
			expected: "tpm: failed to seal to TPM: TPM not available",
		},
		{
			name:     "PCR read failed",
			message:  "failed to read PCRs",
			cause:    errors.New("TPM error"),
			expected: "tpm: failed to read PCRs: TPM error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrTPM(tt.message, tt.cause)
			assert.Error(t, err)
			assert.Equal(t, tt.expected, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Equal(t, ErrorTypeTPM, installerErr.Type)
		})
	}
}

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		errType  ErrorType
		expected string
	}{
		{
			name:     "invalid config",
			errType:  ErrorTypeInvalidConfig,
			expected: "invalid_config",
		},
		{
			name:     "disk operation",
			errType:  ErrorTypeDiskOperation,
			expected: "disk_operation",
		},
		{
			name:     "encryption",
			errType:  ErrorTypeEncryption,
			expected: "encryption",
		},
		{
			name:     "os install",
			errType:  ErrorTypeOSInstall,
			expected: "os_install",
		},
		{
			name:     "uki build",
			errType:  ErrorTypeUKIBuild,
			expected: "uki_build",
		},
		{
			name:     "secure boot",
			errType:  ErrorTypeSecureBoot,
			expected: "secure_boot",
		},
		{
			name:     "tpm",
			errType:  ErrorTypeTPM,
			expected: "tpm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.errType))
		})
	}
}

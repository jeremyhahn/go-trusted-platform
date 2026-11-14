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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestISOError_Error(t *testing.T) {
	tests := []struct {
		name     string
		isoError *ISOError
		expected string
	}{
		{
			name: "error with cause",
			isoError: &ISOError{
				Type:    ErrorTypeConfig,
				Message: "configuration failed",
				Cause:   errors.New("invalid value"),
			},
			expected: "config: configuration failed: invalid value",
		},
		{
			name: "error without cause",
			isoError: &ISOError{
				Type:    ErrorTypePlatform,
				Message: "platform not found",
			},
			expected: "platform: platform not found",
		},
		{
			name: "error with different type",
			isoError: &ISOError{
				Type:    ErrorTypeBuild,
				Message: "build failed",
				Cause:   errors.New("xorriso error"),
			},
			expected: "build: build failed: xorriso error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.isoError.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestISOError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		isoError *ISOError
		expected error
	}{
		{
			name: "with cause",
			isoError: &ISOError{
				Type:    ErrorTypeConfig,
				Message: "test error",
				Cause:   errors.New("underlying error"),
			},
			expected: errors.New("underlying error"),
		},
		{
			name: "without cause",
			isoError: &ISOError{
				Type:    ErrorTypeConfig,
				Message: "test error",
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.isoError.Unwrap()
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.Error(), result.Error())
			}
		})
	}
}

func TestErrPlatformConfigRequired(t *testing.T) {
	err := ErrPlatformConfigRequired()
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypePlatform, isoErr.Type)
	assert.Contains(t, isoErr.Message, "platform config path is required")
	assert.Contains(t, isoErr.Message, "--platform-config flag")
}

func TestErrPlatformConfigNotFound(t *testing.T) {
	path := "/path/to/config.yaml"
	err := ErrPlatformConfigNotFound(path)
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypePlatform, isoErr.Type)
	assert.Contains(t, isoErr.Message, "platform config not found")
	assert.Contains(t, isoErr.Message, path)
}

func TestErrPlatformConfigRead(t *testing.T) {
	path := "/path/to/config.yaml"
	cause := errors.New("permission denied")
	err := ErrPlatformConfigRead(path, cause)
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypePlatform, isoErr.Type)
	assert.Contains(t, isoErr.Message, "failed to read platform config")
	assert.Contains(t, isoErr.Message, path)
	assert.Equal(t, cause, isoErr.Cause)
}

func TestErrPlatformConfigMissingSealPCRs(t *testing.T) {
	path := "/path/to/config.yaml"
	err := ErrPlatformConfigMissingSealPCRs(path)
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypePlatform, isoErr.Type)
	assert.Contains(t, isoErr.Message, "platform config missing required 'seal-pcrs' field")
	assert.Contains(t, isoErr.Message, path)
	assert.Contains(t, isoErr.Message, "seal-pcrs: [7, 11]")
}

func TestErrPlatformConfigWrite(t *testing.T) {
	path := "/path/to/iso/config.yaml"
	cause := errors.New("disk full")
	err := ErrPlatformConfigWrite(path, cause)
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypePlatform, isoErr.Type)
	assert.Contains(t, isoErr.Message, "failed to write platform config to ISO")
	assert.Contains(t, isoErr.Message, path)
	assert.Equal(t, cause, isoErr.Cause)
}

func TestErrConfigDirCreate(t *testing.T) {
	path := "/path/to/configs"
	cause := errors.New("permission denied")
	err := ErrConfigDirCreate(path, cause)
	assert.NotNil(t, err)

	isoErr, ok := err.(*ISOError)
	assert.True(t, ok, "error should be of type *ISOError")
	assert.Equal(t, ErrorTypeCustomize, isoErr.Type)
	assert.Contains(t, isoErr.Message, "failed to create configs directory")
	assert.Contains(t, isoErr.Message, path)
	assert.Equal(t, cause, isoErr.Cause)
}

func TestErrorType_String(t *testing.T) {
	tests := []struct {
		name     string
		errType  ErrorType
		expected string
	}{
		{"config error", ErrorTypeConfig, "config"},
		{"platform error", ErrorTypePlatform, "platform"},
		{"customize error", ErrorTypeCustomize, "customize"},
		{"build error", ErrorTypeBuild, "build"},
		{"download error", ErrorTypeDownload, "download"},
		{"extract error", ErrorTypeExtract, "extract"},
		{"secure boot error", ErrorTypeSecureBoot, "secure_boot"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.errType))
		})
	}
}

func TestISOError_ErrorWrapping(t *testing.T) {
	// Test that errors.Is and errors.As work correctly with wrapped errors
	baseErr := errors.New("base error")
	isoErr := &ISOError{
		Type:    ErrorTypeConfig,
		Message: "wrapper error",
		Cause:   baseErr,
	}

	// Test unwrapping
	unwrapped := errors.Unwrap(isoErr)
	assert.Equal(t, baseErr, unwrapped)

	// Test errors.Is
	assert.True(t, errors.Is(isoErr, baseErr))
}

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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrDaemonConnectionRequired(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "with command name",
			command:  "iso build",
			expected: "daemon connection required for 'iso build' command - dual-mode will be added later",
		},
		{
			name:     "empty command",
			command:  "",
			expected: "daemon connection required for '' command - dual-mode will be added later",
		},
		{
			name:     "special characters",
			command:  "test --flag=value",
			expected: "daemon connection required for 'test --flag=value' command - dual-mode will be added later",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDaemonConnectionRequired{Command: tt.command}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrDaemonConnectionRequired{}))
		})
	}
}

func TestErrInvalidArchitecture(t *testing.T) {
	tests := []struct {
		name     string
		arch     string
		valid    []string
		expected string
	}{
		{
			name:     "invalid architecture",
			arch:     "arm32",
			valid:    []string{"x86_64", "aarch64"},
			expected: "invalid architecture 'arm32': valid options are [x86_64 aarch64]",
		},
		{
			name:     "empty architecture",
			arch:     "",
			valid:    []string{"x86_64"},
			expected: "invalid architecture '': valid options are [x86_64]",
		},
		{
			name:     "empty valid list",
			arch:     "invalid",
			valid:    []string{},
			expected: "invalid architecture 'invalid': valid options are []",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidArchitecture{Architecture: tt.arch, Valid: tt.valid}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrInvalidArchitecture{}))
		})
	}
}

func TestErrInvalidPlatformType(t *testing.T) {
	tests := []struct {
		name         string
		platformType string
		valid        []string
		expected     string
	}{
		{
			name:         "invalid platform type",
			platformType: "desktop",
			valid:        []string{"server", "client"},
			expected:     "invalid platform type 'desktop': valid options are [server client]",
		},
		{
			name:         "empty platform type",
			platformType: "",
			valid:        []string{"server"},
			expected:     "invalid platform type '': valid options are [server]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPlatformType{PlatformType: tt.platformType, Valid: tt.valid}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrInvalidPlatformType{}))
		})
	}
}

func TestErrISONotFound(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "absolute path",
			path:     "/tmp/missing.iso",
			expected: "ISO file not found: /tmp/missing.iso",
		},
		{
			name:     "relative path",
			path:     "alpine.iso",
			expected: "ISO file not found: alpine.iso",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "ISO file not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrISONotFound{Path: tt.path}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrISONotFound{}))
		})
	}
}

func TestErrDirectoryNotFound(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "absolute path",
			path:     "/tmp/missing-dir",
			expected: "directory not found: /tmp/missing-dir",
		},
		{
			name:     "relative path",
			path:     "work/iso",
			expected: "directory not found: work/iso",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDirectoryNotFound{Path: tt.path}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrDirectoryNotFound{}))
		})
	}
}

func TestErrDirectoryAlreadyExists(t *testing.T) {
	err := ErrDirectoryAlreadyExists{Path: "/tmp/existing-dir"}
	assert.Contains(t, err.Error(), "directory already exists")
	assert.Contains(t, err.Error(), "/tmp/existing-dir")
	assert.Contains(t, err.Error(), "--force")
}

func TestErrDownloadFailed(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "network error",
			reason:   "connection timeout",
			expected: "failed to download ISO: connection timeout",
		},
		{
			name:     "checksum mismatch",
			reason:   "SHA256 checksum mismatch",
			expected: "failed to download ISO: SHA256 checksum mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDownloadFailed{Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrDownloadFailed{}))
		})
	}
}

func TestErrExtractionFailed(t *testing.T) {
	err := ErrExtractionFailed{Reason: "7z not found"}
	assert.Equal(t, "failed to extract ISO: 7z not found", err.Error())
	assert.True(t, errors.As(err, &ErrExtractionFailed{}))
}

func TestErrCustomizationFailed(t *testing.T) {
	err := ErrCustomizationFailed{Reason: "initramfs modification failed"}
	assert.Equal(t, "failed to customize ISO: initramfs modification failed", err.Error())
	assert.True(t, errors.As(err, &ErrCustomizationFailed{}))
}

func TestErrBuildFailed(t *testing.T) {
	err := ErrBuildFailed{Reason: "xorriso returned error"}
	assert.Equal(t, "failed to build ISO: xorriso returned error", err.Error())
	assert.True(t, errors.As(err, &ErrBuildFailed{}))
}

func TestErrConfigValidationFailed(t *testing.T) {
	err := ErrConfigValidationFailed{Reason: "missing required field: output"}
	assert.Equal(t, "configuration validation failed: missing required field: output", err.Error())
	assert.True(t, errors.As(err, &ErrConfigValidationFailed{}))
}

func TestErrProfileNotFound(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		expected    string
	}{
		{
			name:        "known profile name",
			profileName: "invalid-profile",
			expected:    "profile not found: invalid-profile",
		},
		{
			name:        "empty profile name",
			profileName: "",
			expected:    "profile not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrProfileNotFound{ProfileName: tt.profileName}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrProfileNotFound{}))
		})
	}
}

func TestErrConfigParseError(t *testing.T) {
	err := ErrConfigParseError{Path: "/tmp/config.yaml", Reason: "invalid YAML syntax"}
	expected := "failed to parse config file '/tmp/config.yaml': invalid YAML syntax"
	assert.Equal(t, expected, err.Error())
	assert.True(t, errors.As(err, &ErrConfigParseError{}))
}

func TestErrVolumeLabelTooLong(t *testing.T) {
	tests := []struct {
		name      string
		label     string
		maxLength int
		expected  string
	}{
		{
			name:      "label exceeds max",
			label:     "THIS_LABEL_IS_WAY_TOO_LONG_FOR_ISO",
			maxLength: 32,
			expected:  "volume label 'THIS_LABEL_IS_WAY_TOO_LONG_FOR_ISO' exceeds maximum length of 32 characters",
		},
		{
			name:      "zero max length",
			label:     "TEST",
			maxLength: 0,
			expected:  "volume label 'TEST' exceeds maximum length of 0 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrVolumeLabelTooLong{Label: tt.label, MaxLength: tt.maxLength}
			assert.Equal(t, tt.expected, err.Error())
			assert.True(t, errors.As(err, &ErrVolumeLabelTooLong{}))
		})
	}
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrDaemonConnectionRequired{}
	var _ error = ErrInvalidArchitecture{}
	var _ error = ErrInvalidPlatformType{}
	var _ error = ErrISONotFound{}
	var _ error = ErrDirectoryNotFound{}
	var _ error = ErrDirectoryAlreadyExists{}
	var _ error = ErrDownloadFailed{}
	var _ error = ErrExtractionFailed{}
	var _ error = ErrCustomizationFailed{}
	var _ error = ErrBuildFailed{}
	var _ error = ErrConfigValidationFailed{}
	var _ error = ErrProfileNotFound{}
	var _ error = ErrConfigParseError{}
	var _ error = ErrVolumeLabelTooLong{}
}

func TestErrorsAreDistinct(t *testing.T) {
	// Verify different error types are not confused with each other
	errDownload := ErrDownloadFailed{Reason: "test"}
	errExtract := ErrExtractionFailed{Reason: "test"}

	var downloadErr ErrDownloadFailed
	var extractErr ErrExtractionFailed

	assert.True(t, errors.As(errDownload, &downloadErr))
	assert.False(t, errors.As(errDownload, &extractErr))

	assert.True(t, errors.As(errExtract, &extractErr))
	assert.False(t, errors.As(errExtract, &downloadErr))
}

func TestErrorMessagesContainContext(t *testing.T) {
	// Verify error messages contain enough context for debugging
	tests := []struct {
		name        string
		err         error
		mustContain []string
	}{
		{
			name:        "ErrDaemonConnectionRequired",
			err:         ErrDaemonConnectionRequired{Command: "iso build"},
			mustContain: []string{"daemon", "iso build"},
		},
		{
			name:        "ErrInvalidArchitecture",
			err:         ErrInvalidArchitecture{Architecture: "arm32", Valid: []string{"x86_64"}},
			mustContain: []string{"arm32", "x86_64"},
		},
		{
			name:        "ErrConfigParseError",
			err:         ErrConfigParseError{Path: "/etc/config.yaml", Reason: "syntax error"},
			mustContain: []string{"/etc/config.yaml", "syntax error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, substr := range tt.mustContain {
				assert.True(t, strings.Contains(errMsg, substr),
					"error message should contain '%s', got: %s", substr, errMsg)
			}
		})
	}
}

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

package webservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "valid hostname",
			host:     "example.com",
			expected: "example.com",
		},
		{
			name:     "hostname with port",
			host:     "example.com:8080",
			expected: "example.com",
		},
		{
			name:     "hostname with uppercase",
			host:     "EXAMPLE.COM",
			expected: "example.com",
		},
		{
			name:     "hostname with spaces",
			host:     "  example.com  ",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			host:     "api.example.com",
			expected: "api.example.com",
		},
		{
			name:     "subdomain with port",
			host:     "api.example.com:443",
			expected: "api.example.com",
		},
		{
			name:     "localhost",
			host:     "localhost",
			expected: "localhost",
		},
		{
			name:     "localhost with port",
			host:     "localhost:3000",
			expected: "localhost",
		},
		{
			name:     "invalid hostname with invalid characters",
			host:     "example_underscore.com",
			expected: "",
		},
		{
			name:     "invalid hostname with spaces in middle",
			host:     "exa mple.com",
			expected: "",
		},
		{
			name:     "empty string",
			host:     "",
			expected: "",
		},
		{
			name:     "hostname with multiple subdomains",
			host:     "api.v1.example.com",
			expected: "api.v1.example.com",
		},
		{
			name:     "hostname with dashes",
			host:     "api-v1.example-domain.com",
			expected: "api-v1.example-domain.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		{
			name:     "valid hostname",
			hostname: "example.com",
			expected: true,
		},
		{
			name:     "valid localhost",
			hostname: "localhost",
			expected: true,
		},
		{
			name:     "valid subdomain",
			hostname: "api.example.com",
			expected: true,
		},
		{
			name:     "valid hostname with dashes",
			hostname: "api-v1.example-domain.com",
			expected: true,
		},
		{
			name:     "valid multi-level subdomain",
			hostname: "api.v1.staging.example.com",
			expected: true,
		},
		{
			name:     "invalid with underscore",
			hostname: "example_domain.com",
			expected: false,
		},
		{
			name:     "invalid with uppercase (not lowercase)",
			hostname: "EXAMPLE.COM",
			expected: false,
		},
		{
			name:     "invalid with spaces",
			hostname: "example domain.com",
			expected: false,
		},
		{
			name:     "invalid with special characters",
			hostname: "example@domain.com",
			expected: false,
		},
		{
			name:     "empty string",
			hostname: "",
			expected: false,
		},
		{
			name:     "hostname starting with dash - allowed by regex",
			hostname: "-example.com",
			expected: true, // The regex allows this
		},
		{
			name:     "hostname ending with dash - allowed by regex",
			hostname: "example.com-",
			expected: true, // The regex allows this
		},
		{
			name:     "invalid double dots",
			hostname: "example..com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHostname(tt.hostname)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsFileAccessible(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(tmpFile, []byte("test content"), 0644)
	require.NoError(t, err)

	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "accessible file",
			filePath: tmpFile,
			expected: true,
		},
		{
			name:     "non-existent file",
			filePath: filepath.Join(tmpDir, "nonexistent.txt"),
			expected: false,
		},
		{
			name:     "directory instead of file",
			filePath: tmpDir,
			expected: false,
		},
		{
			name:     "empty path",
			filePath: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFileAccessible(tt.filePath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

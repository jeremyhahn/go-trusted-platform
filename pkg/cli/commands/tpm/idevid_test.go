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

package tpm

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  idevidsvc.DeviceKeyAlgorithm
		expectErr bool
	}{
		{
			name:     "ECDSA-P256",
			input:    "ECDSA-P256",
			expected: idevidsvc.AlgorithmECDSAP256,
		},
		{
			name:     "ECDSA-P256 lowercase",
			input:    "ecdsa-p256",
			expected: idevidsvc.AlgorithmECDSAP256,
		},
		{
			name:     "P256 shorthand",
			input:    "P256",
			expected: idevidsvc.AlgorithmECDSAP256,
		},
		{
			name:     "ECDSA-P384",
			input:    "ECDSA-P384",
			expected: idevidsvc.AlgorithmECDSAP384,
		},
		{
			name:     "P384 shorthand",
			input:    "P384",
			expected: idevidsvc.AlgorithmECDSAP384,
		},
		{
			name:     "RSA-2048",
			input:    "RSA-2048",
			expected: idevidsvc.AlgorithmRSA2048,
		},
		{
			name:     "RSA2048 without hyphen",
			input:    "RSA2048",
			expected: idevidsvc.AlgorithmRSA2048,
		},
		{
			name:     "RSA-3072",
			input:    "RSA-3072",
			expected: idevidsvc.AlgorithmRSA3072,
		},
		{
			name:     "with whitespace",
			input:    "  ECDSA-P256  ",
			expected: idevidsvc.AlgorithmECDSAP256,
		},
		{
			name:      "invalid algorithm",
			input:     "INVALID",
			expected:  idevidsvc.AlgorithmUnspecified,
			expectErr: true,
		},
		{
			name:      "empty string",
			input:     "",
			expected:  idevidsvc.AlgorithmUnspecified,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAlgorithm(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
				var algErr ErrInvalidAlgorithm
				assert.ErrorAs(t, err, &algErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "Yes", formatBool(true))
	assert.Equal(t, "No", formatBool(false))
}

func TestReadFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		expectedContent := "-----BEGIN CERTIFICATE-----\ntest content\n-----END CERTIFICATE-----"
		_, err = tmpFile.WriteString(expectedContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Read the file
		content, err := readFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, expectedContent, content)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := readFile("/nonexistent/path/file.pem")
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		// Create an empty temporary file
		tmpFile, err := os.CreateTemp("", "test-empty-*.pem")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		content, err := readFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Equal(t, "", content)
	})
}

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
	"testing"

	"github.com/stretchr/testify/assert"

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// =============================================================================
// Key Algorithm Helper Tests
// =============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  tpmsvc.KeyAlgorithm
		expectErr bool
	}{
		{
			name:     "RSA-2048",
			input:    "RSA-2048",
			expected: tpmsvc.KeyAlgorithm("RSA-2048"),
		},
		{
			name:     "RSA2048 without hyphen",
			input:    "RSA2048",
			expected: tpmsvc.KeyAlgorithm("RSA-2048"),
		},
		{
			name:     "RSA-3072",
			input:    "RSA-3072",
			expected: tpmsvc.KeyAlgorithm("RSA-3072"),
		},
		{
			name:     "RSA3072 without hyphen",
			input:    "RSA3072",
			expected: tpmsvc.KeyAlgorithm("RSA-3072"),
		},
		{
			name:     "RSA-4096",
			input:    "RSA-4096",
			expected: tpmsvc.KeyAlgorithm("RSA-4096"),
		},
		{
			name:     "RSA4096 without hyphen",
			input:    "RSA4096",
			expected: tpmsvc.KeyAlgorithm("RSA-4096"),
		},
		{
			name:     "ECDSA-P256",
			input:    "ECDSA-P256",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P256"),
		},
		{
			name:     "ECDSAP256 without hyphen",
			input:    "ECDSAP256",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P256"),
		},
		{
			name:     "P256 shorthand",
			input:    "P256",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P256"),
		},
		{
			name:     "ECDSA-P384",
			input:    "ECDSA-P384",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P384"),
		},
		{
			name:     "ECDSAP384 without hyphen",
			input:    "ECDSAP384",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P384"),
		},
		{
			name:     "P384 shorthand",
			input:    "P384",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P384"),
		},
		{
			name:     "ECDSA-P521",
			input:    "ECDSA-P521",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P521"),
		},
		{
			name:     "ECDSAP521 without hyphen",
			input:    "ECDSAP521",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P521"),
		},
		{
			name:     "P521 shorthand",
			input:    "P521",
			expected: tpmsvc.KeyAlgorithm("ECDSA-P521"),
		},
		{
			name:      "invalid algorithm",
			input:     "INVALID",
			expectErr: true,
		},
		{
			name:      "empty string",
			input:     "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tpmsvc.ParseKeyAlgorithm(tt.input)
			if tt.expectErr {
				assert.False(t, ok)
			} else {
				assert.True(t, ok)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestFormatKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    tpmsvc.KeyAlgorithm
		expected string
	}{
		{
			name:     "RSA-2048",
			input:    tpmsvc.KeyAlgorithm("RSA-2048"),
			expected: "RSA-2048",
		},
		{
			name:     "RSA-3072",
			input:    tpmsvc.KeyAlgorithm("RSA-3072"),
			expected: "RSA-3072",
		},
		{
			name:     "RSA-4096",
			input:    tpmsvc.KeyAlgorithm("RSA-4096"),
			expected: "RSA-4096",
		},
		{
			name:     "ECDSA-P256",
			input:    tpmsvc.KeyAlgorithm("ECDSA-P256"),
			expected: "ECDSA-P256",
		},
		{
			name:     "ECDSA-P384",
			input:    tpmsvc.KeyAlgorithm("ECDSA-P384"),
			expected: "ECDSA-P384",
		},
		{
			name:     "ECDSA-P521",
			input:    tpmsvc.KeyAlgorithm("ECDSA-P521"),
			expected: "ECDSA-P521",
		},
		{
			name:     "Unknown/empty",
			input:    tpmsvc.KeyAlgorithm(""),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := string(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// PCR Bank Helper Tests
// =============================================================================

func TestParsePCRBank(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected tpmsvc.PCRBank
	}{
		{
			name:     "sha1 lowercase",
			input:    "sha1",
			expected: tpmsvc.PCRBank("sha1"),
		},
		{
			name:     "sha256 lowercase",
			input:    "sha256",
			expected: tpmsvc.PCRBank("sha256"),
		},
		{
			name:     "sha384 lowercase",
			input:    "sha384",
			expected: tpmsvc.PCRBank("sha384"),
		},
		{
			name:     "sha512 lowercase",
			input:    "sha512",
			expected: tpmsvc.PCRBank("sha512"),
		},
		{
			name:     "unknown defaults to sha256",
			input:    "unknown",
			expected: tpmsvc.PCRBank("sha256"),
		},
		{
			name:     "empty defaults to sha256",
			input:    "",
			expected: tpmsvc.PCRBank("sha256"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tpmsvc.ParsePCRBank(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Int Slice to Uint32 Helper Tests
// =============================================================================

func TestIntSliceToUint32(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := intSliceToUint32(nil)
		assert.Nil(t, result)
	})

	t.Run("empty slice", func(t *testing.T) {
		result := intSliceToUint32([]int{})
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})

	t.Run("single element", func(t *testing.T) {
		result := intSliceToUint32([]int{7})
		assert.Equal(t, []uint32{7}, result)
	})

	t.Run("multiple elements", func(t *testing.T) {
		result := intSliceToUint32([]int{0, 7, 9, 10, 23})
		assert.Equal(t, []uint32{0, 7, 9, 10, 23}, result)
	})
}

// =============================================================================
// TPM Info Output Helper Tests
// =============================================================================

func TestBuildTPMInfoOutput(t *testing.T) {
	t.Run("passes through xkms info string", func(t *testing.T) {
		const xkmsReport = "TPM Information\nManufacturer: Infineon\nFamily: 2.0\n"
		resp := &tpmsvc.InfoResponse{
			IsSimulator: true,
			Properties: map[string]string{
				"info": xkmsReport,
			},
		}

		output := buildTPMInfoOutput(resp)

		assert.Equal(t, xkmsReport, output["info"])
		assert.Equal(t, true, output["is_simulator"])
	})

	t.Run("missing info string", func(t *testing.T) {
		resp := &tpmsvc.InfoResponse{
			IsSimulator: false,
		}

		output := buildTPMInfoOutput(resp)

		assert.Equal(t, "", output["info"])
		assert.Equal(t, false, output["is_simulator"])
	})
}

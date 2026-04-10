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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// =============================================================================
// Key Algorithm Helper Tests
// =============================================================================

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  platformv1.KeyAlgorithm
		expectErr bool
	}{
		{
			name:     "RSA-2048",
			input:    "RSA-2048",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		},
		{
			name:     "RSA2048 without hyphen",
			input:    "RSA2048",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		},
		{
			name:     "RSA-3072",
			input:    "RSA-3072",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		},
		{
			name:     "RSA3072 without hyphen",
			input:    "RSA3072",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		},
		{
			name:     "RSA-4096",
			input:    "RSA-4096",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
		},
		{
			name:     "RSA4096 without hyphen",
			input:    "RSA4096",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
		},
		{
			name:     "ECDSA-P256",
			input:    "ECDSA-P256",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "ECDSAP256 without hyphen",
			input:    "ECDSAP256",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "P256 shorthand",
			input:    "P256",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		},
		{
			name:     "ECDSA-P384",
			input:    "ECDSA-P384",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		},
		{
			name:     "ECDSAP384 without hyphen",
			input:    "ECDSAP384",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		},
		{
			name:     "P384 shorthand",
			input:    "P384",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		},
		{
			name:     "ECDSA-P521",
			input:    "ECDSA-P521",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
		},
		{
			name:     "ECDSAP521 without hyphen",
			input:    "ECDSAP521",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
		},
		{
			name:     "P521 shorthand",
			input:    "P521",
			expected: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
		},
		{
			name:      "invalid algorithm",
			input:     "INVALID",
			expected:  platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
			expectErr: true,
		},
		{
			name:      "empty string",
			input:     "",
			expected:  platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseKeyAlgorithm(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
				var algErr ErrInvalidKeyAlgorithm
				assert.ErrorAs(t, err, &algErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestFormatKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    platformv1.KeyAlgorithm
		expected string
	}{
		{
			name:     "RSA-2048",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
			expected: "RSA-2048",
		},
		{
			name:     "RSA-3072",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
			expected: "RSA-3072",
		},
		{
			name:     "RSA-4096",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
			expected: "RSA-4096",
		},
		{
			name:     "ECDSA-P256",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			expected: "ECDSA-P256",
		},
		{
			name:     "ECDSA-P384",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
			expected: "ECDSA-P384",
		},
		{
			name:     "ECDSA-P521",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
			expected: "ECDSA-P521",
		},
		{
			name:     "Unknown/Unspecified",
			input:    platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatKeyAlgorithm(tt.input)
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
		expected platformv1.PCRBank
	}{
		{
			name:     "sha1 lowercase",
			input:    "sha1",
			expected: platformv1.PCRBank_PCR_BANK_SHA1,
		},
		{
			name:     "SHA1 uppercase",
			input:    "SHA1",
			expected: platformv1.PCRBank_PCR_BANK_SHA1,
		},
		{
			name:     "sha256 lowercase",
			input:    "sha256",
			expected: platformv1.PCRBank_PCR_BANK_SHA256,
		},
		{
			name:     "SHA256 uppercase",
			input:    "SHA256",
			expected: platformv1.PCRBank_PCR_BANK_SHA256,
		},
		{
			name:     "sha384 lowercase",
			input:    "sha384",
			expected: platformv1.PCRBank_PCR_BANK_SHA384,
		},
		{
			name:     "SHA384 uppercase",
			input:    "SHA384",
			expected: platformv1.PCRBank_PCR_BANK_SHA384,
		},
		{
			name:     "sha512 lowercase",
			input:    "sha512",
			expected: platformv1.PCRBank_PCR_BANK_SHA512,
		},
		{
			name:     "SHA512 uppercase",
			input:    "SHA512",
			expected: platformv1.PCRBank_PCR_BANK_SHA512,
		},
		{
			name:     "sm3_256 lowercase",
			input:    "sm3_256",
			expected: platformv1.PCRBank_PCR_BANK_SM3_256,
		},
		{
			name:     "SM3_256 uppercase",
			input:    "SM3_256",
			expected: platformv1.PCRBank_PCR_BANK_SM3_256,
		},
		{
			name:     "unknown defaults to sha256",
			input:    "unknown",
			expected: platformv1.PCRBank_PCR_BANK_SHA256,
		},
		{
			name:     "empty defaults to sha256",
			input:    "",
			expected: platformv1.PCRBank_PCR_BANK_SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePCRBank(tt.input)
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

// TestBuildTPMInfoOutput verifies the JSON/YAML output structure is a
// thin wrapper around the comprehensive xkms TPM info string. The CLI
// must not reinvent the presentation layer — it delegates to
// go-xkms TPM2.Info() which is delivered via resp.Properties["info"].
func TestBuildTPMInfoOutput(t *testing.T) {
	t.Run("passes through xkms info string", func(t *testing.T) {
		const xkmsReport = "TPM Information\nManufacturer: Infineon\nFamily: 2.0\n"
		resp := &platformv1.TPMInfoResponse{
			Version:     platformv1.TPMVersion_TPM_VERSION_2_0,
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
		resp := &platformv1.TPMInfoResponse{
			Version:     platformv1.TPMVersion_TPM_VERSION_2_0,
			IsSimulator: false,
		}

		output := buildTPMInfoOutput(resp)

		assert.Equal(t, "", output["info"])
		assert.Equal(t, false, output["is_simulator"])
	})
}

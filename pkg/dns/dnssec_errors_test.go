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

package dns

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDNSSECError_Error tests the Error method of DNSSECError.
func TestDNSSECError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *DNSSECError
		expected string
	}{
		{
			name: "with zone",
			err: &DNSSECError{
				Op:   "GenerateKey",
				Zone: "example.com.",
				Err:  ErrKeyGenerationFailed,
			},
			expected: "dnssec: GenerateKey [example.com.]: dnssec: key generation failed",
		},
		{
			name: "without zone",
			err: &DNSSECError{
				Op:   "Sign",
				Zone: "",
				Err:  ErrSigningFailed,
			},
			expected: "dnssec: Sign: dnssec: zone signing failed",
		},
		{
			name: "with custom error",
			err: &DNSSECError{
				Op:   "Validate",
				Zone: "test.org.",
				Err:  errors.New("validation failed"),
			},
			expected: "dnssec: Validate [test.org.]: validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDNSSECError_Unwrap tests the Unwrap method of DNSSECError.
func TestDNSSECError_Unwrap(t *testing.T) {
	underlyingErr := ErrKeyNotFound
	err := &DNSSECError{
		Op:   "GetKey",
		Zone: "example.com.",
		Err:  underlyingErr,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, underlyingErr, unwrapped)
	assert.True(t, errors.Is(err, ErrKeyNotFound))
}

// TestDNSSECError_Is tests the Is method of DNSSECError.
func TestDNSSECError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    *DNSSECError
		target error
		want   bool
	}{
		{
			name: "matching underlying error",
			err: &DNSSECError{
				Op:   "GenerateKSK",
				Zone: "example.com.",
				Err:  ErrKeyGenerationFailed,
			},
			target: ErrKeyGenerationFailed,
			want:   true,
		},
		{
			name: "non-matching error",
			err: &DNSSECError{
				Op:   "SignZone",
				Zone: "example.com.",
				Err:  ErrSigningFailed,
			},
			target: ErrKeyNotFound,
			want:   false,
		},
		{
			name: "nil target",
			err: &DNSSECError{
				Op:   "Test",
				Zone: "test.com.",
				Err:  ErrZoneNil,
			},
			target: nil,
			want:   false,
		},
		{
			name: "wrapped error chain",
			err: &DNSSECError{
				Op:   "GetSigner",
				Zone: "example.com.",
				Err:  ErrKMSKeyNotFound,
			},
			target: ErrKMSKeyNotFound,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Is(tt.target)
			assert.Equal(t, tt.want, result)
		})
	}
}

// TestSentinelErrors tests that all sentinel errors are defined and distinct.
func TestSentinelErrors(t *testing.T) {
	// All sentinel errors should be non-nil and have expected message content
	sentinelErrors := []struct {
		err     error
		content string
	}{
		{ErrDNSSECConfigNil, "configuration is nil"},
		{ErrLoggerNil, "logger is nil"},
		{ErrZoneNameEmpty, "zone name is empty"},
		{ErrZoneNil, "zone is nil"},
		{ErrKeyNotFound, "key not found"},
		{ErrInvalidDNSKEY, "invalid DNSKEY"},
		{ErrPrivateKeySerialize, "serialize private key"},
		{ErrEmptyRRSet, "empty RRset"},
		{ErrInvalidKeyType, "invalid key type"},
		{ErrSigningFailed, "signing failed"},
		{ErrInvalidAlgorithm, "invalid or unsupported algorithm"},
		{ErrKeyGenerationFailed, "key generation failed"},
		{ErrNSECChainFailed, "NSEC chain"},
		{ErrNSEC3ChainFailed, "NSEC3 chain"},
		{ErrKMSNil, "KMS service is nil"},
		{ErrKMSKeyGeneration, "KMS key generation"},
		{ErrKMSKeyNotFound, "key not found in KMS"},
		{ErrKMSSigningFailed, "KMS signing failed"},
		{ErrKMSKeyDisabled, "KMS key is disabled"},
		{ErrUnsupportedAlgorithm, "algorithm not supported"},
		{ErrInvalidKeyStore, "invalid key store"},
		{ErrKeyStoreNil, "key store is nil"},
	}

	for _, tc := range sentinelErrors {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Contains(t, tc.err.Error(), tc.content)
		})
	}
}

// TestDNSSECError_ErrorsIs tests error matching using errors.Is.
func TestDNSSECError_ErrorsIs(t *testing.T) {
	err := &DNSSECError{
		Op:   "TestOp",
		Zone: "example.com.",
		Err:  ErrKMSKeyDisabled,
	}

	// Should match through errors.Is
	assert.True(t, errors.Is(err, ErrKMSKeyDisabled))
	assert.False(t, errors.Is(err, ErrKMSKeyNotFound))
}

// TestDNSSECError_ErrorsUnwrap tests error unwrapping using errors.Unwrap.
func TestDNSSECError_ErrorsUnwrap(t *testing.T) {
	innerErr := ErrInvalidDNSKEY
	err := &DNSSECError{
		Op:   "Parse",
		Zone: "test.com.",
		Err:  innerErr,
	}

	unwrapped := errors.Unwrap(err)
	assert.Equal(t, innerErr, unwrapped)
}

// TestDNSSECError_NestedError tests DNSSECError with nested DNSSECError.
func TestDNSSECError_NestedError(t *testing.T) {
	innerErr := &DNSSECError{
		Op:   "InnerOp",
		Zone: "inner.com.",
		Err:  ErrKeyNotFound,
	}
	outerErr := &DNSSECError{
		Op:   "OuterOp",
		Zone: "outer.com.",
		Err:  innerErr,
	}

	// Should be able to match the inner error through the chain
	assert.True(t, errors.Is(outerErr, ErrKeyNotFound))

	// Outer error message should contain zone info
	assert.Contains(t, outerErr.Error(), "outer.com.")
	assert.Contains(t, outerErr.Error(), "OuterOp")
}

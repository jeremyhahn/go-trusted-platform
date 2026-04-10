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

package attestation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrAttestationRequired(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAttestationRequired
		expected string
	}{
		{
			name:     "with zone",
			err:      ErrAttestationRequired{Zone: "example.com."},
			expected: "attestation required for zone example.com.",
		},
		{
			name:     "without zone",
			err:      ErrAttestationRequired{},
			expected: "attestation is required for this zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrAttestationExpired(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAttestationExpired
		expected string
	}{
		{
			name:     "with device and expiry",
			err:      ErrAttestationExpired{DeviceID: "device-123", ExpiredAt: "2025-01-01T00:00:00Z"},
			expected: "attestation token for device device-123 expired at 2025-01-01T00:00:00Z",
		},
		{
			name:     "without device",
			err:      ErrAttestationExpired{},
			expected: "attestation token has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrAttestationTooOld(t *testing.T) {
	err := ErrAttestationTooOld{Age: "10m", MaxAge: "5m"}
	assert.Equal(t, "attestation evidence age 10m exceeds maximum 5m", err.Error())
}

func TestErrPCRMismatch(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrPCRMismatch
		expected string
	}{
		{
			name:     "with policy",
			err:      ErrPCRMismatch{Policy: "standard-boot"},
			expected: "PCR values do not match policy standard-boot",
		},
		{
			name:     "without policy",
			err:      ErrPCRMismatch{},
			expected: "PCR values do not match the required policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrEKNotAuthorized(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrEKNotAuthorized
		expected string
	}{
		{
			name:     "with fingerprint and reason",
			err:      ErrEKNotAuthorized{EKFingerprint: "sha256:abc", Reason: "CA not trusted"},
			expected: "endorsement key sha256:abc not authorized: CA not trusted",
		},
		{
			name:     "with fingerprint only",
			err:      ErrEKNotAuthorized{EKFingerprint: "sha256:abc"},
			expected: "endorsement key sha256:abc is not authorized",
		},
		{
			name:     "empty",
			err:      ErrEKNotAuthorized{},
			expected: "endorsement key certificate is not authorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrOperationNotAllowed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrOperationNotAllowed
		expected string
	}{
		{
			name:     "with operation and allowed list",
			err:      ErrOperationNotAllowed{Operation: "TXT", AllowedOperations: []string{"A", "AAAA"}},
			expected: "operation TXT not allowed, permitted: [A AAAA]",
		},
		{
			name:     "with operation only",
			err:      ErrOperationNotAllowed{Operation: "TXT"},
			expected: "operation TXT not allowed by attestation token",
		},
		{
			name:     "empty",
			err:      ErrOperationNotAllowed{},
			expected: "operation not allowed by attestation token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrZoneNotAllowed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrZoneNotAllowed
		expected string
	}{
		{
			name:     "with zone and allowed list",
			err:      ErrZoneNotAllowed{Zone: "other.com.", AllowedZones: []string{"example.com.", "test.com."}},
			expected: "zone other.com. not allowed, permitted: [example.com. test.com.]",
		},
		{
			name:     "with zone only",
			err:      ErrZoneNotAllowed{Zone: "other.com."},
			expected: "zone other.com. not allowed by attestation token",
		},
		{
			name:     "empty",
			err:      ErrZoneNotAllowed{},
			expected: "zone not allowed by attestation token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidToken(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidToken
		expected string
	}{
		{
			name:     "with reason and cause",
			err:      ErrInvalidToken{Reason: "malformed signature", Err: errors.New("base64 decode failed")},
			expected: "invalid attestation token: malformed signature: base64 decode failed",
		},
		{
			name:     "with reason only",
			err:      ErrInvalidToken{Reason: "malformed signature"},
			expected: "invalid attestation token: malformed signature",
		},
		{
			name:     "empty",
			err:      ErrInvalidToken{},
			expected: "invalid attestation token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidToken_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrInvalidToken{Reason: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))

	errNoCause := ErrInvalidToken{Reason: "test"}
	assert.Nil(t, errNoCause.Unwrap())
}

func TestErrServiceUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrServiceUnavailable
		expected string
	}{
		{
			name:     "with reason and cause",
			err:      ErrServiceUnavailable{Reason: "connection refused", Err: errors.New("dial tcp: connection refused")},
			expected: "attestation service unavailable: connection refused: dial tcp: connection refused",
		},
		{
			name:     "with reason only",
			err:      ErrServiceUnavailable{Reason: "connection refused"},
			expected: "attestation service unavailable: connection refused",
		},
		{
			name:     "empty",
			err:      ErrServiceUnavailable{},
			expected: "attestation service is unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrServiceUnavailable_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrServiceUnavailable{Reason: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))

	errNoCause := ErrServiceUnavailable{Reason: "test"}
	assert.Nil(t, errNoCause.Unwrap())
}

func TestErrInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidConfig
		expected string
	}{
		{
			name:     "with field",
			err:      ErrInvalidConfig{Field: "max_age", Reason: "must be positive"},
			expected: "invalid attestation config: field max_age: must be positive",
		},
		{
			name:     "without field",
			err:      ErrInvalidConfig{Reason: "configuration is incomplete"},
			expected: "invalid attestation config: configuration is incomplete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrVerificationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrVerificationFailed
		expected string
	}{
		{
			name:     "with all fields",
			err:      ErrVerificationFailed{Step: "signature_check", Reason: "invalid signature", Err: errors.New("crypto error")},
			expected: "attestation verification failed at step signature_check: invalid signature: crypto error",
		},
		{
			name:     "with step and reason",
			err:      ErrVerificationFailed{Step: "signature_check", Reason: "invalid signature"},
			expected: "attestation verification failed at step signature_check: invalid signature",
		},
		{
			name:     "with step only",
			err:      ErrVerificationFailed{Step: "signature_check"},
			expected: "attestation verification failed at step signature_check",
		},
		{
			name:     "with reason only",
			err:      ErrVerificationFailed{Reason: "invalid signature"},
			expected: "attestation verification failed: invalid signature",
		},
		{
			name:     "empty",
			err:      ErrVerificationFailed{},
			expected: "attestation verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrVerificationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrVerificationFailed{Step: "test", Err: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))

	errNoCause := ErrVerificationFailed{Step: "test"}
	assert.Nil(t, errNoCause.Unwrap())
}

func TestErrorsImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrAttestationRequired{}
	var _ error = ErrAttestationExpired{}
	var _ error = ErrAttestationTooOld{}
	var _ error = ErrPCRMismatch{}
	var _ error = ErrEKNotAuthorized{}
	var _ error = ErrOperationNotAllowed{}
	var _ error = ErrZoneNotAllowed{}
	var _ error = ErrInvalidToken{}
	var _ error = ErrServiceUnavailable{}
	var _ error = ErrInvalidConfig{}
	var _ error = ErrVerificationFailed{}
}

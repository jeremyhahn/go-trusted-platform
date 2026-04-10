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

package auth

import (
	"errors"
	"testing"
)

func TestErrAuthenticationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAuthenticationFailed
		expected string
	}{
		{
			name:     "empty reason",
			err:      ErrAuthenticationFailed{},
			expected: "auth: authentication failed",
		},
		{
			name:     "with reason",
			err:      ErrAuthenticationFailed{Reason: "invalid credentials"},
			expected: "auth: authentication failed: invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrCertificateInvalid(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateInvalid
		expected string
	}{
		{
			name:     "empty reason",
			err:      ErrCertificateInvalid{},
			expected: "auth: certificate invalid",
		},
		{
			name:     "with reason",
			err:      ErrCertificateInvalid{Reason: "signature verification failed"},
			expected: "auth: certificate invalid: signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrCertificateExpired(t *testing.T) {
	err := ErrCertificateExpired{}
	expected := "auth: certificate expired"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrCertificateRevoked(t *testing.T) {
	err := ErrCertificateRevoked{}
	expected := "auth: certificate revoked"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrChainValidationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrChainValidationFailed
		expected string
	}{
		{
			name:     "nil cause",
			err:      ErrChainValidationFailed{},
			expected: "auth: certificate chain validation failed",
		},
		{
			name:     "with cause",
			err:      ErrChainValidationFailed{Cause: errors.New("unknown issuer")},
			expected: "auth: certificate chain validation failed: unknown issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrChainValidationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrChainValidationFailed{Cause: cause}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Verify errors.Is works
	if !errors.Is(err, cause) {
		t.Error("errors.Is should return true for wrapped error")
	}
}

func TestErrIdentityNotFound(t *testing.T) {
	err := ErrIdentityNotFound{}
	expected := "auth: identity not found in certificate"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrTenantNotFound(t *testing.T) {
	err := ErrTenantNotFound{}
	expected := "auth: tenant not found in certificate"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrTPMAttestationFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTPMAttestationFailed
		expected string
	}{
		{
			name:     "empty reason",
			err:      ErrTPMAttestationFailed{},
			expected: "auth: TPM attestation failed",
		},
		{
			name:     "with reason",
			err:      ErrTPMAttestationFailed{Reason: "quote verification failed"},
			expected: "auth: TPM attestation failed: quote verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrNilCertificate(t *testing.T) {
	err := ErrNilCertificate{}
	expected := "auth: nil certificate provided"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrNilLogger(t *testing.T) {
	err := ErrNilLogger{}
	expected := "auth: nil logger provided"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrNilCA(t *testing.T) {
	err := ErrNilCA{}
	expected := "auth: nil certificate authority provided"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrMissingTrustedRoots(t *testing.T) {
	err := ErrMissingTrustedRoots{}
	expected := "auth: no trusted roots configured"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrRevocationCheckFailed(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrRevocationCheckFailed
		expected string
	}{
		{
			name:     "empty reason",
			err:      ErrRevocationCheckFailed{},
			expected: "auth: revocation check failed",
		},
		{
			name:     "with reason",
			err:      ErrRevocationCheckFailed{Reason: "CRL download failed"},
			expected: "auth: revocation check failed: CRL download failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidKeyUsage(t *testing.T) {
	err := ErrInvalidKeyUsage{
		Expected: "DigitalSignature",
		Actual:   "KeyEncipherment",
	}
	expected := "auth: invalid key usage: expected DigitalSignature, got KeyEncipherment"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrInvalidExtKeyUsage(t *testing.T) {
	err := ErrInvalidExtKeyUsage{Expected: "ClientAuth"}
	expected := "auth: missing extended key usage: ClientAuth"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

// TestErrorsImplementErrorInterface verifies all error types implement error interface.
func TestErrorsImplementErrorInterface(t *testing.T) {
	errorTypes := []error{
		ErrAuthenticationFailed{},
		ErrCertificateInvalid{},
		ErrCertificateExpired{},
		ErrCertificateRevoked{},
		ErrChainValidationFailed{},
		ErrIdentityNotFound{},
		ErrTenantNotFound{},
		ErrTPMAttestationFailed{},
		ErrNilCertificate{},
		ErrNilLogger{},
		ErrNilCA{},
		ErrMissingTrustedRoots{},
		ErrRevocationCheckFailed{},
		ErrInvalidKeyUsage{},
		ErrInvalidExtKeyUsage{},
	}

	for _, err := range errorTypes {
		if err.Error() == "" {
			t.Errorf("Error() should not return empty string for %T", err)
		}
	}
}

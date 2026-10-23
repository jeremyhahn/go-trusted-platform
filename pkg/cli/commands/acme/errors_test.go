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

package acme

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrDaemonConnectionRequired verifies ErrDaemonConnectionRequired error
func TestErrACMEDaemonCallMissing(t *testing.T) {
	testCases := []struct {
		name     string
		err      ErrACMEDaemonCallMissing
		expected string
	}{
		{
			name:     "register",
			err:      ErrACMEDaemonCallMissing{Command: "register", Section: "§7.3 newAccount"},
			expected: "acme register: platformd has no ACME call for RFC 8555 §7.3 newAccount (SDK gap)",
		},
		{
			name:     "rotate-key",
			err:      ErrACMEDaemonCallMissing{Command: "rotate-key", Section: "§7.3.5 key change"},
			expected: "acme rotate-key: platformd has no ACME call for RFC 8555 §7.3.5 key change (SDK gap)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

// TestErrDaemonConnectionRequired_ErrorsAs verifies errors.As works
func TestErrACMEDaemonCallMissing_ErrorsIs(t *testing.T) {
	var err error = ErrACMEDaemonCallMissing{Command: "renew", Section: "§7.4 order and finalize"}

	assert.True(t, errors.Is(err, ErrACMEDaemonCallMissing{Command: "renew", Section: "§7.4 order and finalize"}))
	assert.False(t, errors.Is(err, ErrACMEDaemonCallMissing{Command: "download", Section: "§7.4.2 certificate download"}),
		"a gap for another verb must not match")

	var targetErr ErrACMEDaemonCallMissing
	require.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "renew", targetErr.Command)
}

// TestValidationErrors verifies the input-validation errors name the bad value
func TestValidationErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		contains []string
	}{
		{name: "missing email", err: ErrMissingEmail{}, contains: []string{"--email"}},
		{name: "invalid email", err: ErrInvalidEmail{Email: "bad"}, contains: []string{`"bad"`}},
		{name: "invalid authz", err: ErrInvalidAuthorizationType{Type: "x"}, contains: []string{`"x"`, "permanent-identifier"}},
		{name: "invalid challenge", err: ErrInvalidChallengeType{Type: "y"}, contains: []string{`"y"`, "device-attest-01"}},
		{name: "invalid URL", err: ErrInvalidCertificateURL{URL: "http://z"}, contains: []string{`"http://z"`, "https"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.contains {
				assert.Contains(t, tc.err.Error(), want)
			}
			assert.False(t, errors.Is(tc.err, ErrACMEDaemonCallMissing{}), "a validation error is not the gap")
		})
	}
}

// TestErrRegisterAccountFailed verifies ErrRegisterAccountFailed error
func TestErrRegisterAccountFailed(t *testing.T) {
	testCases := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "network error",
			reason:   "network unreachable",
			expected: "failed to register ACME account: network unreachable",
		},
		{
			name:     "invalid email",
			reason:   "invalid email format",
			expected: "failed to register ACME account: invalid email format",
		},
		{
			name:     "server error",
			reason:   "internal server error",
			expected: "failed to register ACME account: internal server error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrRegisterAccountFailed{Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())

			// Verify error interface implementation
			var e error = err
			assert.NotNil(t, e)
		})
	}
}

// TestErrRegisterAccountFailed_ErrorsAs verifies errors.As works
func TestErrRegisterAccountFailed_ErrorsAs(t *testing.T) {
	err := ErrRegisterAccountFailed{Reason: "test reason"}

	var targetErr ErrRegisterAccountFailed
	assert.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "test reason", targetErr.Reason)
}

// TestErrRenewCertificateFailed verifies ErrRenewCertificateFailed error
func TestErrRenewCertificateFailed(t *testing.T) {
	testCases := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "challenge failed",
			reason:   "DNS challenge verification failed",
			expected: "failed to renew certificate: DNS challenge verification failed",
		},
		{
			name:     "expired authorization",
			reason:   "authorization expired",
			expected: "failed to renew certificate: authorization expired",
		},
		{
			name:     "invalid CSR",
			reason:   "CSR validation error",
			expected: "failed to renew certificate: CSR validation error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrRenewCertificateFailed{Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())

			// Verify error interface implementation
			var e error = err
			assert.NotNil(t, e)
		})
	}
}

// TestErrRenewCertificateFailed_ErrorsAs verifies errors.As works
func TestErrRenewCertificateFailed_ErrorsAs(t *testing.T) {
	err := ErrRenewCertificateFailed{Reason: "test reason"}

	var targetErr ErrRenewCertificateFailed
	assert.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "test reason", targetErr.Reason)
}

// TestErrDownloadCertificateFailed verifies ErrDownloadCertificateFailed error
func TestErrDownloadCertificateFailed(t *testing.T) {
	testCases := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "not found",
			reason:   "certificate not found",
			expected: "failed to download certificate: certificate not found",
		},
		{
			name:     "network error",
			reason:   "connection timeout",
			expected: "failed to download certificate: connection timeout",
		},
		{
			name:     "unauthorized",
			reason:   "unauthorized access",
			expected: "failed to download certificate: unauthorized access",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrDownloadCertificateFailed{Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())

			// Verify error interface implementation
			var e error = err
			assert.NotNil(t, e)
		})
	}
}

// TestErrDownloadCertificateFailed_ErrorsAs verifies errors.As works
func TestErrDownloadCertificateFailed_ErrorsAs(t *testing.T) {
	err := ErrDownloadCertificateFailed{Reason: "test reason"}

	var targetErr ErrDownloadCertificateFailed
	assert.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "test reason", targetErr.Reason)
}

// TestErrRotateKeyFailed verifies ErrRotateKeyFailed error
func TestErrRotateKeyFailed(t *testing.T) {
	testCases := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "key generation failed",
			reason:   "failed to generate new key",
			expected: "failed to rotate account key: failed to generate new key",
		},
		{
			name:     "rollover rejected",
			reason:   "server rejected rollover request",
			expected: "failed to rotate account key: server rejected rollover request",
		},
		{
			name:     "signature error",
			reason:   "invalid signature",
			expected: "failed to rotate account key: invalid signature",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrRotateKeyFailed{Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())

			// Verify error interface implementation
			var e error = err
			assert.NotNil(t, e)
		})
	}
}

// TestErrRotateKeyFailed_ErrorsAs verifies errors.As works
func TestErrRotateKeyFailed_ErrorsAs(t *testing.T) {
	err := ErrRotateKeyFailed{Reason: "test reason"}

	var targetErr ErrRotateKeyFailed
	assert.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "test reason", targetErr.Reason)
}

// TestErrMissingCertificateURL verifies ErrMissingCertificateURL error
func TestErrMissingCertificateURL(t *testing.T) {
	err := ErrMissingCertificateURL{}
	assert.Equal(t, "certificate URL is required", err.Error())

	// Verify error interface implementation
	var e error = err
	assert.NotNil(t, e)
}

// TestErrMissingCertificateURL_ErrorsAs verifies errors.As works
func TestErrMissingCertificateURL_ErrorsAs(t *testing.T) {
	err := ErrMissingCertificateURL{}

	var targetErr ErrMissingCertificateURL
	assert.True(t, errors.As(err, &targetErr))
}

// TestErrMissingAuthorizationValue verifies ErrMissingAuthorizationValue error
func TestErrMissingAuthorizationValue(t *testing.T) {
	err := ErrMissingAuthorizationValue{}
	assert.Equal(t, "could not determine authorization value; specify --cn or --sans-dns/--sans-ip", err.Error())

	// Verify error interface implementation
	var e error = err
	assert.NotNil(t, e)
}

// TestErrMissingAuthorizationValue_ErrorsAs verifies errors.As works
func TestErrMissingAuthorizationValue_ErrorsAs(t *testing.T) {
	err := ErrMissingAuthorizationValue{}

	var targetErr ErrMissingAuthorizationValue
	assert.True(t, errors.As(err, &targetErr))
}

// TestErrIPAuthorizationRequiresIP verifies ErrIPAuthorizationRequiresIP error
func TestErrIPAuthorizationRequiresIP(t *testing.T) {
	err := ErrIPAuthorizationRequiresIP{}
	assert.Equal(t, "IP authorization requires --sans-ip", err.Error())

	// Verify error interface implementation
	var e error = err
	assert.NotNil(t, e)
}

// TestErrIPAuthorizationRequiresIP_ErrorsAs verifies errors.As works
func TestErrIPAuthorizationRequiresIP_ErrorsAs(t *testing.T) {
	err := ErrIPAuthorizationRequiresIP{}

	var targetErr ErrIPAuthorizationRequiresIP
	assert.True(t, errors.As(err, &targetErr))
}

// TestErrMissingSubjectField verifies ErrMissingSubjectField error
func TestErrMissingSubjectField(t *testing.T) {
	testCases := []struct {
		name     string
		field    string
		expected string
	}{
		{
			name:     "missing common name",
			field:    "common name (CN)",
			expected: "missing required subject field: common name (CN)",
		},
		{
			name:     "missing organization",
			field:    "organization",
			expected: "missing required subject field: organization",
		},
		{
			name:     "missing country",
			field:    "country",
			expected: "missing required subject field: country",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrMissingSubjectField{Field: tc.field}
			assert.Equal(t, tc.expected, err.Error())

			// Verify error interface implementation
			var e error = err
			assert.NotNil(t, e)
		})
	}
}

// TestErrMissingSubjectField_ErrorsAs verifies errors.As works
func TestErrMissingSubjectField_ErrorsAs(t *testing.T) {
	err := ErrMissingSubjectField{Field: "test field"}

	var targetErr ErrMissingSubjectField
	assert.True(t, errors.As(err, &targetErr))
	assert.Equal(t, "test field", targetErr.Field)
}

// TestAllErrorTypes_ImplementErrorInterface verifies all error types implement error
func TestAllErrorTypes_ImplementErrorInterface(t *testing.T) {
	// This test ensures all custom error types properly implement the error interface
	var _ error = ErrACMEDaemonCallMissing{}
	var _ error = ErrMissingEmail{}
	var _ error = ErrInvalidEmail{}
	var _ error = ErrInvalidAuthorizationType{}
	var _ error = ErrInvalidChallengeType{}
	var _ error = ErrInvalidCertificateURL{}
	var _ error = ErrRegisterAccountFailed{}
	var _ error = ErrRenewCertificateFailed{}
	var _ error = ErrDownloadCertificateFailed{}
	var _ error = ErrRotateKeyFailed{}
	var _ error = ErrMissingCertificateURL{}
	var _ error = ErrMissingAuthorizationValue{}
	var _ error = ErrIPAuthorizationRequiresIP{}
	var _ error = ErrMissingSubjectField{}

	// If we get here without compile errors, all types implement error
	assert.True(t, true)
}

// TestErrorMessages_AreDescriptive verifies error messages are user-friendly
func TestErrorMessages_AreDescriptive(t *testing.T) {
	// Verify error messages contain helpful information
	err1 := ErrACMEDaemonCallMissing{Command: "register", Section: "§7.3 newAccount"}
	assert.Contains(t, err1.Error(), "platformd")
	assert.Contains(t, err1.Error(), "register")
	assert.Contains(t, err1.Error(), "RFC 8555 §7.3")

	err2 := ErrMissingAuthorizationValue{}
	assert.Contains(t, err2.Error(), "--cn")
	assert.Contains(t, err2.Error(), "--sans-dns")
	assert.Contains(t, err2.Error(), "--sans-ip")

	err3 := ErrIPAuthorizationRequiresIP{}
	assert.Contains(t, err3.Error(), "--sans-ip")
}

// TestErrorTypes_AreDistinct verifies error types are distinguishable
func TestErrorTypes_AreDistinct(t *testing.T) {
	errors := []error{
		ErrACMEDaemonCallMissing{Command: "test", Section: "test"},
		ErrMissingEmail{},
		ErrInvalidEmail{Email: "test"},
		ErrInvalidAuthorizationType{Type: "test"},
		ErrInvalidChallengeType{Type: "test"},
		ErrInvalidCertificateURL{URL: "test"},
		ErrRegisterAccountFailed{Reason: "test"},
		ErrRenewCertificateFailed{Reason: "test"},
		ErrDownloadCertificateFailed{Reason: "test"},
		ErrRotateKeyFailed{Reason: "test"},
		ErrMissingCertificateURL{},
		ErrMissingAuthorizationValue{},
		ErrIPAuthorizationRequiresIP{},
		ErrMissingSubjectField{Field: "test"},
	}

	// Verify all error messages are unique
	messages := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		assert.False(t, messages[msg], "duplicate error message: %s", msg)
		messages[msg] = true
	}
}

// TestErrDaemonConnectionRequired_EmptyCommand verifies behavior with empty command
func TestErrACMEDaemonCallMissing_EmptyFields(t *testing.T) {
	err := ErrACMEDaemonCallMissing{}
	assert.Equal(t, "acme : platformd has no ACME call for RFC 8555  (SDK gap)", err.Error())
}

// TestErrMissingSubjectField_EmptyField verifies behavior with empty field
func TestErrMissingSubjectField_EmptyField(t *testing.T) {
	err := ErrMissingSubjectField{Field: ""}
	assert.Equal(t, "missing required subject field: ", err.Error())
}

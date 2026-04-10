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

//go:build codec_msgpack

package quic

import (
	"errors"
	"strings"
	"testing"
)

func TestErrInvalidConfigError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      ErrInvalidConfig
		expected string
	}{
		{
			name:     "field and reason",
			err:      ErrInvalidConfig{Field: "ListenAddr", Reason: "cannot be empty"},
			expected: "invalid configuration: ListenAddr: cannot be empty",
		},
		{
			name:     "empty field",
			err:      ErrInvalidConfig{Field: "", Reason: "some reason"},
			expected: "invalid configuration: : some reason",
		},
		{
			name:     "empty reason",
			err:      ErrInvalidConfig{Field: "SomeField", Reason: ""},
			expected: "invalid configuration: SomeField: ",
		},
		{
			name:     "both empty",
			err:      ErrInvalidConfig{Field: "", Reason: ""},
			expected: "invalid configuration: : ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestErrProtocolError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      ErrProtocol
		expected string
	}{
		{
			name:     "status OK",
			err:      ErrProtocol{Status: StatusOK, Message: "success"},
			expected: "protocol error (status 0x00): success",
		},
		{
			name:     "status not found",
			err:      ErrProtocol{Status: StatusNotFound, Message: "resource not found"},
			expected: "protocol error (status 0x02): resource not found",
		},
		{
			name:     "status unauthorized",
			err:      ErrProtocol{Status: StatusUnauthorized, Message: "invalid token"},
			expected: "protocol error (status 0x03): invalid token",
		},
		{
			name:     "status internal error",
			err:      ErrProtocol{Status: StatusInternalError, Message: "server error"},
			expected: "protocol error (status 0x04): server error",
		},
		{
			name:     "empty message",
			err:      ErrProtocol{Status: StatusTimeout, Message: ""},
			expected: "protocol error (status 0x05): ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestStatusError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      byte
		message     string
		expectNil   bool
		expectError string
	}{
		{
			name:      "status OK returns nil",
			status:    StatusOK,
			message:   "success",
			expectNil: true,
		},
		{
			name:        "status not found",
			status:      StatusNotFound,
			message:     "resource not found",
			expectNil:   false,
			expectError: "protocol error (status 0x02): resource not found",
		},
		{
			name:        "status unauthorized",
			status:      StatusUnauthorized,
			message:     "auth failed",
			expectNil:   false,
			expectError: "protocol error (status 0x03): auth failed",
		},
		{
			name:        "status internal error",
			status:      StatusInternalError,
			message:     "internal",
			expectNil:   false,
			expectError: "protocol error (status 0x04): internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := StatusError(tt.status, tt.message)

			if tt.expectNil {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}

				if err.Error() != tt.expectError {
					t.Errorf("expected '%s', got '%s'", tt.expectError, err.Error())
				}

				// Verify it's an ErrProtocol
				var protoErr *ErrProtocol
				if !errors.As(err, &protoErr) {
					t.Errorf("expected error to be *ErrProtocol, got %T", err)
				}
			}
		})
	}
}

func TestErrorToStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{
			name:           "nil error returns StatusOK",
			err:            nil,
			expectedStatus: StatusOK,
		},
		{
			name:           "ErrProtocol preserves status",
			err:            &ErrProtocol{Status: StatusNotFound, Message: "not found"},
			expectedStatus: StatusNotFound,
		},
		{
			name:           "ErrNilRequest returns StatusInvalidRequest",
			err:            ErrNilRequest,
			expectedStatus: StatusInvalidRequest,
		},
		{
			name:           "ErrNilResponse returns StatusInvalidRequest",
			err:            ErrNilResponse,
			expectedStatus: StatusInvalidRequest,
		},
		{
			name:           "ErrPayloadTooLarge returns StatusInvalidArgument",
			err:            ErrPayloadTooLarge,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrTokenTooLarge returns StatusInvalidArgument",
			err:            ErrTokenTooLarge,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrClientClosed returns StatusUnavailable",
			err:            ErrClientClosed,
			expectedStatus: StatusUnavailable,
		},
		{
			name:           "ErrServerNotRunning returns StatusUnavailable",
			err:            ErrServerNotRunning,
			expectedStatus: StatusUnavailable,
		},
		{
			name:           "unknown error returns StatusInternalError",
			err:            errors.New("some unknown error"),
			expectedStatus: StatusInternalError,
		},
		{
			name:           "ErrCANotInitialized returns StatusUnavailable",
			err:            ErrCANotInitialized,
			expectedStatus: StatusUnavailable,
		},
		{
			name:           "ErrCACertStoreUnavailable returns StatusUnavailable",
			err:            ErrCACertStoreUnavailable,
			expectedStatus: StatusUnavailable,
		},
		{
			name:           "ErrCAMissingCommonName returns StatusInvalidArgument",
			err:            ErrCAMissingCommonName,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrCAMissingSerial returns StatusInvalidArgument",
			err:            ErrCAMissingSerial,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrCAMissingCertificate returns StatusInvalidArgument",
			err:            ErrCAMissingCertificate,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrCAInvalidPEM returns StatusInvalidArgument",
			err:            ErrCAInvalidPEM,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrCAInvalidExtendDays returns StatusInvalidArgument",
			err:            ErrCAInvalidExtendDays,
			expectedStatus: StatusInvalidArgument,
		},
		{
			name:           "ErrCACRLNotSupported returns StatusNotImplemented",
			err:            ErrCACRLNotSupported,
			expectedStatus: StatusNotImplemented,
		},
		{
			name:           "ErrCABundleNotFound returns StatusNotFound",
			err:            ErrCABundleNotFound,
			expectedStatus: StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status := ErrorToStatus(tt.err)
			if status != tt.expectedStatus {
				t.Errorf("expected status 0x%02X, got 0x%02X", tt.expectedStatus, status)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrProtocol with StatusNotFound",
			err:      &ErrProtocol{Status: StatusNotFound, Message: "not found"},
			expected: true,
		},
		{
			name:     "ErrProtocol with other status",
			err:      &ErrProtocol{Status: StatusUnauthorized, Message: "auth failed"},
			expected: false,
		},
		{
			name:     "non-protocol error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "wrapped ErrProtocol with StatusNotFound",
			err:      &ErrProtocol{Status: StatusNotFound, Message: "wrapped"},
			expected: true,
		},
		{
			name:     "ErrCACertNotFound",
			err:      ErrCACertNotFound{Serial: "12345"},
			expected: true,
		},
		{
			name:     "ErrCABundleNotFound",
			err:      ErrCABundleNotFound,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsNotFound(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrProtocol with StatusUnauthorized",
			err:      &ErrProtocol{Status: StatusUnauthorized, Message: "auth failed"},
			expected: true,
		},
		{
			name:     "ErrProtocol with other status",
			err:      &ErrProtocol{Status: StatusNotFound, Message: "not found"},
			expected: false,
		},
		{
			name:     "non-protocol error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsUnauthorized(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsUnavailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrProtocol with StatusUnavailable",
			err:      &ErrProtocol{Status: StatusUnavailable, Message: "unavailable"},
			expected: true,
		},
		{
			name:     "ErrServerNotRunning",
			err:      ErrServerNotRunning,
			expected: true,
		},
		{
			name:     "ErrClientClosed",
			err:      ErrClientClosed,
			expected: true,
		},
		{
			name:     "ErrCANotInitialized",
			err:      ErrCANotInitialized,
			expected: true,
		},
		{
			name:     "ErrCACertStoreUnavailable",
			err:      ErrCACertStoreUnavailable,
			expected: true,
		},
		{
			name:     "ErrProtocol with other status",
			err:      &ErrProtocol{Status: StatusNotFound, Message: "not found"},
			expected: false,
		},
		{
			name:     "non-protocol error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsUnavailable(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()
	// Verify sentinel errors are properly defined
	sentinelErrors := []struct {
		name string
		err  error
	}{
		{"ErrServerNotRunning", ErrServerNotRunning},
		{"ErrServerRunning", ErrServerRunning},
		{"ErrClientClosed", ErrClientClosed},
		{"ErrConnectionFailed", ErrConnectionFailed},
		{"ErrStreamFailed", ErrStreamFailed},
		{"ErrPayloadTooLarge", ErrPayloadTooLarge},
		{"ErrTokenTooLarge", ErrTokenTooLarge},
		{"ErrNilRequest", ErrNilRequest},
		{"ErrNilResponse", ErrNilResponse},
	}

	for _, tt := range sentinelErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}

			if tt.err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", tt.name)
			}
		})
	}
}

func TestSentinelErrorMessages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err            error
		expectedSubstr string
	}{
		{ErrServerNotRunning, "not running"},
		{ErrServerRunning, "already running"},
		{ErrClientClosed, "closed"},
		{ErrConnectionFailed, "connection failed"},
		{ErrStreamFailed, "stream"},
		{ErrPayloadTooLarge, "payload"},
		{ErrTokenTooLarge, "token"},
		{ErrNilRequest, "request"},
		{ErrNilResponse, "response"},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(strings.ToLower(tt.err.Error()), tt.expectedSubstr) {
				t.Errorf("expected error message to contain '%s', got '%s'", tt.expectedSubstr, tt.err.Error())
			}
		})
	}
}

func TestErrorToStatusWithWrappedErrors(t *testing.T) {
	t.Parallel()
	// Test that ErrorToStatus works with wrapped protocol errors
	wrapped := &ErrProtocol{Status: StatusNotFound, Message: "wrapped error"}

	status := ErrorToStatus(wrapped)
	if status != StatusNotFound {
		t.Errorf("expected StatusNotFound (0x02), got 0x%02X", status)
	}
}

func TestErrInvalidConfigImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = ErrInvalidConfig{}
}

func TestErrProtocolImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = &ErrProtocol{}
}

func TestErrCAInvalidAlgorithmError(t *testing.T) {
	t.Parallel()
	err := ErrCAInvalidAlgorithm{Algorithm: "UNKNOWN"}
	expected := "invalid key algorithm: UNKNOWN"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCACertNotFoundError(t *testing.T) {
	t.Parallel()
	err := ErrCACertNotFound{Serial: "12345"}
	expected := "certificate not found: 12345"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCAEncodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("encoding error")
	err := ErrCAEncodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to encode payload: encoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestErrCADecodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("decoding error")
	err := ErrCADecodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to decode payload: decoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCAIssueFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("issue error")
	err := ErrCAIssueFailed{Cause: cause}

	// Test Error()
	expected := "failed to issue certificate: issue error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCARevokeFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("revoke error")
	err := ErrCARevokeFailed{Cause: cause}

	// Test Error()
	expected := "failed to revoke certificate: revoke error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCARenewFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("renew error")
	err := ErrCARenewFailed{Cause: cause}

	// Test Error()
	expected := "failed to renew certificate: renew error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCAParseFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("parse error")
	err := ErrCAParseFailed{Cause: cause}

	// Test Error()
	expected := "failed to parse certificate: parse error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCACRLFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("CRL error")
	err := ErrCACRLFailed{Cause: cause}

	// Test Error()
	expected := "failed to generate CRL: CRL error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCACRLParseFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("CRL parse error")
	err := ErrCACRLParseFailed{Cause: cause}

	// Test Error()
	expected := "failed to parse CRL: CRL parse error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestErrCABundleFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("bundle error")
	err := ErrCABundleFailed{Cause: cause}

	// Test Error()
	expected := "failed to get CA bundle: bundle error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}
}

func TestIsCAError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrCANotInitialized",
			err:      ErrCANotInitialized,
			expected: true,
		},
		{
			name:     "ErrCAMissingCommonName",
			err:      ErrCAMissingCommonName,
			expected: true,
		},
		{
			name:     "ErrCAMissingSerial",
			err:      ErrCAMissingSerial,
			expected: true,
		},
		{
			name:     "ErrCAMissingCertificate",
			err:      ErrCAMissingCertificate,
			expected: true,
		},
		{
			name:     "ErrCAInvalidPEM",
			err:      ErrCAInvalidPEM,
			expected: true,
		},
		{
			name:     "ErrCAInvalidExtendDays",
			err:      ErrCAInvalidExtendDays,
			expected: true,
		},
		{
			name:     "ErrCACRLNotSupported",
			err:      ErrCACRLNotSupported,
			expected: true,
		},
		{
			name:     "ErrCABundleNotFound",
			err:      ErrCABundleNotFound,
			expected: true,
		},
		{
			name:     "ErrCACertStoreUnavailable",
			err:      ErrCACertStoreUnavailable,
			expected: true,
		},
		{
			name:     "ErrCAInvalidAlgorithm",
			err:      ErrCAInvalidAlgorithm{Algorithm: "UNKNOWN"},
			expected: true,
		},
		{
			name:     "ErrCACertNotFound",
			err:      ErrCACertNotFound{Serial: "12345"},
			expected: true,
		},
		{
			name:     "ErrCAEncodingFailed",
			err:      ErrCAEncodingFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCADecodingFailed",
			err:      ErrCADecodingFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCAIssueFailed",
			err:      ErrCAIssueFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCARevokeFailed",
			err:      ErrCARevokeFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCARenewFailed",
			err:      ErrCARenewFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCAParseFailed",
			err:      ErrCAParseFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCACRLFailed",
			err:      ErrCACRLFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCACRLParseFailed",
			err:      ErrCACRLParseFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "ErrCABundleFailed",
			err:      ErrCABundleFailed{Cause: errors.New("test")},
			expected: true,
		},
		{
			name:     "Non-CA error",
			err:      errors.New("not a CA error"),
			expected: false,
		},
		{
			name:     "ErrServerNotRunning",
			err:      ErrServerNotRunning,
			expected: false,
		},
		{
			name:     "ErrProtocol",
			err:      &ErrProtocol{Status: StatusNotFound, Message: "test"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsCAError(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for error: %v", tt.expected, result, tt.err)
			}
		})
	}
}

func TestCASentinelErrors(t *testing.T) {
	t.Parallel()
	// Verify CA sentinel errors are properly defined
	caErrors := []struct {
		name string
		err  error
	}{
		{"ErrCANotInitialized", ErrCANotInitialized},
		{"ErrCAMissingCommonName", ErrCAMissingCommonName},
		{"ErrCAMissingSerial", ErrCAMissingSerial},
		{"ErrCAMissingCertificate", ErrCAMissingCertificate},
		{"ErrCAInvalidPEM", ErrCAInvalidPEM},
		{"ErrCAInvalidExtendDays", ErrCAInvalidExtendDays},
		{"ErrCACRLNotSupported", ErrCACRLNotSupported},
		{"ErrCABundleNotFound", ErrCABundleNotFound},
		{"ErrCACertStoreUnavailable", ErrCACertStoreUnavailable},
	}

	for _, tt := range caErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}

			if tt.err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", tt.name)
			}
		})
	}
}

func TestWrappedErrorTypes(t *testing.T) {
	t.Parallel()
	// Verify all wrapped error types implement error interface
	var _ error = ErrCAEncodingFailed{}
	var _ error = ErrCADecodingFailed{}
	var _ error = ErrCAIssueFailed{}
	var _ error = ErrCARevokeFailed{}
	var _ error = ErrCARenewFailed{}
	var _ error = ErrCAParseFailed{}
	var _ error = ErrCACRLFailed{}
	var _ error = ErrCACRLParseFailed{}
	var _ error = ErrCABundleFailed{}
	var _ error = ErrCAInvalidAlgorithm{}
	var _ error = ErrCACertNotFound{}
}

func TestErrorChaining(t *testing.T) {
	t.Parallel()
	// Test error chaining with nested errors
	rootCause := errors.New("root cause")
	parseErr := ErrCAParseFailed{Cause: rootCause}
	issueErr := ErrCAIssueFailed{Cause: parseErr}

	// Verify we can unwrap the chain
	unwrapped := issueErr.Unwrap()
	if _, ok := unwrapped.(ErrCAParseFailed); !ok {
		t.Errorf("expected ErrCAParseFailed, got %T", unwrapped)
	}

	// Verify errors.Is works through chain
	if !errors.Is(issueErr, rootCause) {
		t.Error("expected errors.Is to find root cause through chain")
	}
}

func TestErrTLSConfigGenerationError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      ErrTLSConfigGeneration
		expected string
	}{
		{
			name: "with wrapped error",
			err: ErrTLSConfigGeneration{
				Reason: "failed to generate key",
				Err:    errors.New("key generation failed"),
			},
			expected: "TLS config generation failed: failed to generate key: key generation failed",
		},
		{
			name: "without wrapped error",
			err: ErrTLSConfigGeneration{
				Reason: "invalid certificate",
				Err:    nil,
			},
			expected: "TLS config generation failed: invalid certificate",
		},
		{
			name: "empty reason with error",
			err: ErrTLSConfigGeneration{
				Reason: "",
				Err:    errors.New("some error"),
			},
			expected: "TLS config generation failed: : some error",
		},
		{
			name: "both empty",
			err: ErrTLSConfigGeneration{
				Reason: "",
				Err:    nil,
			},
			expected: "TLS config generation failed: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestErrTLSConfigGenerationUnwrap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		err          ErrTLSConfigGeneration
		expectUnwrap error
	}{
		{
			name: "with wrapped error",
			err: ErrTLSConfigGeneration{
				Reason: "test",
				Err:    errors.New("wrapped error"),
			},
			expectUnwrap: errors.New("wrapped error"),
		},
		{
			name: "without wrapped error",
			err: ErrTLSConfigGeneration{
				Reason: "test",
				Err:    nil,
			},
			expectUnwrap: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			unwrapped := tt.err.Unwrap()
			if tt.expectUnwrap == nil {
				if unwrapped != nil {
					t.Errorf("expected nil, got %v", unwrapped)
				}
			} else {
				if unwrapped == nil {
					t.Errorf("expected %v, got nil", tt.expectUnwrap)
				} else if unwrapped.Error() != tt.expectUnwrap.Error() {
					t.Errorf("expected '%s', got '%s'", tt.expectUnwrap.Error(), unwrapped.Error())
				}
			}
		})
	}
}

func TestErrTLSConfigGenerationErrorsIs(t *testing.T) {
	t.Parallel()
	cause := errors.New("root cause")
	err := ErrTLSConfigGeneration{
		Reason: "test",
		Err:    cause,
	}

	// Test that errors.Is works with the unwrapped error
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the root cause")
	}
}

func TestErrTLSConfigGenerationImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = ErrTLSConfigGeneration{}
}

// =============================================================================
// Gateway Error Tests
// =============================================================================

func TestErrGatewayEncodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("encoding error")
	err := ErrGatewayEncodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to encode gateway payload: encoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestErrGatewayDecodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("decoding error")
	err := ErrGatewayDecodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to decode gateway payload: decoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestErrGatewayOperationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("operation error")
	err := ErrGatewayOperationFailed{Operation: "CreateGateway", Cause: cause}

	// Test Error()
	expected := "gateway operation CreateGateway failed: operation error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestGatewayErrorTypes(t *testing.T) {
	t.Parallel()
	// Verify all gateway error types implement error interface
	var _ error = ErrGatewayEncodingFailed{}
	var _ error = ErrGatewayDecodingFailed{}
	var _ error = ErrGatewayOperationFailed{}
}

func TestGatewayErrorChaining(t *testing.T) {
	t.Parallel()
	// Test error chaining with nested gateway errors
	rootCause := errors.New("root cause")
	decodingErr := ErrGatewayDecodingFailed{Cause: rootCause}
	opErr := ErrGatewayOperationFailed{Operation: "ProcessRequest", Cause: decodingErr}

	// Verify we can unwrap the chain
	unwrapped := opErr.Unwrap()
	if _, ok := unwrapped.(ErrGatewayDecodingFailed); !ok {
		t.Errorf("expected ErrGatewayDecodingFailed, got %T", unwrapped)
	}

	// Verify errors.Is works through chain
	if !errors.Is(opErr, rootCause) {
		t.Error("expected errors.Is to find root cause through chain")
	}
}

// =============================================================================
// Overlay Error Tests
// =============================================================================

func TestErrOverlayEncodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("encoding error")
	err := ErrOverlayEncodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to encode overlay payload: encoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestErrOverlayDecodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("decoding error")
	err := ErrOverlayDecodingFailed{Cause: cause}

	// Test Error()
	expected := "failed to decode overlay payload: decoding error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestErrOverlayOperationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("operation error")
	err := ErrOverlayOperationFailed{Operation: "CreateOverlay", Cause: cause}

	// Test Error()
	expected := "overlay operation CreateOverlay failed: operation error"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestOverlayErrorTypes(t *testing.T) {
	t.Parallel()
	// Verify all overlay error types implement error interface
	var _ error = ErrOverlayEncodingFailed{}
	var _ error = ErrOverlayDecodingFailed{}
	var _ error = ErrOverlayOperationFailed{}
}

func TestOverlayErrorChaining(t *testing.T) {
	t.Parallel()
	// Test error chaining with nested overlay errors
	rootCause := errors.New("root cause")
	decodingErr := ErrOverlayDecodingFailed{Cause: rootCause}
	opErr := ErrOverlayOperationFailed{Operation: "ProcessRequest", Cause: decodingErr}

	// Verify we can unwrap the chain
	unwrapped := opErr.Unwrap()
	if _, ok := unwrapped.(ErrOverlayDecodingFailed); !ok {
		t.Errorf("expected ErrOverlayDecodingFailed, got %T", unwrapped)
	}

	// Verify errors.Is works through chain
	if !errors.Is(opErr, rootCause) {
		t.Error("expected errors.Is to find root cause through chain")
	}
}

// =============================================================================
// IAM Error Tests
// =============================================================================

func TestErrIAMUserNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMUserNotFound{}

	// Test Error()
	expected := "user not found"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMUserNotFound{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMRoleNotFound{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMUserNotFound{}) {
		t.Error("expected errors.Is to find ErrIAMUserNotFound")
	}
}

func TestErrIAMRoleNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleNotFound{}

	// Test Error()
	expected := "role not found"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMRoleNotFound{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMUserNotFound{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMRoleNotFound{}) {
		t.Error("expected errors.Is to find ErrIAMRoleNotFound")
	}
}

func TestErrIAMGroupNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMGroupNotFound{}

	// Test Error()
	expected := "group not found"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMGroupNotFound{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMUserNotFound{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMGroupNotFound{}) {
		t.Error("expected errors.Is to find ErrIAMGroupNotFound")
	}
}

func TestErrIAMUserAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMUserAlreadyExists{}

	// Test Error()
	expected := "user already exists"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMUserAlreadyExists{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMRoleAlreadyExists{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMUserAlreadyExists{}) {
		t.Error("expected errors.Is to find ErrIAMUserAlreadyExists")
	}
}

func TestErrIAMRoleAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleAlreadyExists{}

	// Test Error()
	expected := "role already exists"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMRoleAlreadyExists{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMUserAlreadyExists{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMRoleAlreadyExists{}) {
		t.Error("expected errors.Is to find ErrIAMRoleAlreadyExists")
	}
}

func TestErrIAMGroupAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMGroupAlreadyExists{}

	// Test Error()
	expected := "group already exists"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMGroupAlreadyExists{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMUserAlreadyExists{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMGroupAlreadyExists{}) {
		t.Error("expected errors.Is to find ErrIAMGroupAlreadyExists")
	}
}

func TestErrIAMPermissionDenied(t *testing.T) {
	t.Parallel()
	err := ErrIAMPermissionDenied{}

	// Test Error()
	expected := "permission denied"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMPermissionDenied{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMUserNotFound{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMPermissionDenied{}) {
		t.Error("expected errors.Is to find ErrIAMPermissionDenied")
	}
}

func TestErrIAMTokenExpired(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenExpired{}

	// Test Error()
	expected := "token expired"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMTokenExpired{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMTokenInvalid{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMTokenExpired{}) {
		t.Error("expected errors.Is to find ErrIAMTokenExpired")
	}
}

func TestErrIAMTokenInvalid(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenInvalid{}

	// Test Error()
	expected := "token invalid"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Is() - same type
	if !err.Is(ErrIAMTokenInvalid{}) {
		t.Error("expected Is() to return true for same type")
	}

	// Test Is() - different type
	if err.Is(ErrIAMTokenExpired{}) {
		t.Error("expected Is() to return false for different type")
	}

	// Test errors.Is with same type
	if !errors.Is(err, ErrIAMTokenInvalid{}) {
		t.Error("expected errors.Is to find ErrIAMTokenInvalid")
	}
}

func TestErrIAMTokenVerificationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("verification failed")
	err := ErrIAMTokenVerificationFailed{Cause: cause}

	// Test Error()
	expected := "token verification failed: verification failed"
	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test Unwrap()
	if err.Unwrap() != cause {
		t.Errorf("expected unwrapped error to be the cause")
	}

	// Verify errors.Is works through Unwrap
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the cause")
	}
}

func TestIAMErrorTypesInterface(t *testing.T) {
	t.Parallel()
	// Verify all IAM error types implement error interface
	var _ error = ErrIAMUserNotFound{}
	var _ error = ErrIAMRoleNotFound{}
	var _ error = ErrIAMGroupNotFound{}
	var _ error = ErrIAMUserAlreadyExists{}
	var _ error = ErrIAMRoleAlreadyExists{}
	var _ error = ErrIAMGroupAlreadyExists{}
	var _ error = ErrIAMPermissionDenied{}
	var _ error = ErrIAMTokenExpired{}
	var _ error = ErrIAMTokenInvalid{}
	var _ error = ErrIAMTokenVerificationFailed{}
}

func TestIAMErrorIsMethodsWithNonMatchingTypes(t *testing.T) {
	t.Parallel()
	// Test that Is() returns false for non-matching error types
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "UserNotFound vs generic error",
			err:    ErrIAMUserNotFound{},
			target: errors.New("some error"),
		},
		{
			name:   "RoleNotFound vs generic error",
			err:    ErrIAMRoleNotFound{},
			target: errors.New("some error"),
		},
		{
			name:   "GroupNotFound vs generic error",
			err:    ErrIAMGroupNotFound{},
			target: errors.New("some error"),
		},
		{
			name:   "UserAlreadyExists vs generic error",
			err:    ErrIAMUserAlreadyExists{},
			target: errors.New("some error"),
		},
		{
			name:   "RoleAlreadyExists vs generic error",
			err:    ErrIAMRoleAlreadyExists{},
			target: errors.New("some error"),
		},
		{
			name:   "GroupAlreadyExists vs generic error",
			err:    ErrIAMGroupAlreadyExists{},
			target: errors.New("some error"),
		},
		{
			name:   "PermissionDenied vs generic error",
			err:    ErrIAMPermissionDenied{},
			target: errors.New("some error"),
		},
		{
			name:   "TokenExpired vs generic error",
			err:    ErrIAMTokenExpired{},
			target: errors.New("some error"),
		},
		{
			name:   "TokenInvalid vs generic error",
			err:    ErrIAMTokenInvalid{},
			target: errors.New("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Use type assertion to call Is() method
			switch e := tt.err.(type) {
			case ErrIAMUserNotFound:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMRoleNotFound:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMGroupNotFound:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMUserAlreadyExists:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMRoleAlreadyExists:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMGroupAlreadyExists:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMPermissionDenied:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMTokenExpired:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			case ErrIAMTokenInvalid:
				if e.Is(tt.target) {
					t.Error("expected Is() to return false for non-matching type")
				}
			}
		})
	}
}

// =============================================================================
// KMS Error Tests
// =============================================================================

func TestErrKMSBatchSizeExceeded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      ErrKMSBatchSizeExceeded
		expected string
	}{
		{
			name:     "typical values",
			err:      ErrKMSBatchSizeExceeded{Count: 150, MaxCount: 100},
			expected: "batch size 150 exceeds maximum allowed 100",
		},
		{
			name:     "zero values",
			err:      ErrKMSBatchSizeExceeded{Count: 0, MaxCount: 0},
			expected: "batch size 0 exceeds maximum allowed 0",
		},
		{
			name:     "large values",
			err:      ErrKMSBatchSizeExceeded{Count: 10000, MaxCount: 1000},
			expected: "batch size 10000 exceeds maximum allowed 1000",
		},
		{
			name:     "boundary case",
			err:      ErrKMSBatchSizeExceeded{Count: 101, MaxCount: 100},
			expected: "batch size 101 exceeds maximum allowed 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestKMSBatchErrorTypeInterface(t *testing.T) {
	t.Parallel()
	// Verify KMS error types implement error interface
	var _ error = ErrKMSBatchSizeExceeded{}
}

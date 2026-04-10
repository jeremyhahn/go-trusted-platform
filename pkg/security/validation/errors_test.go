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

package validation

import (
	"testing"
)

func TestErrValidationFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrValidationFailed
		expected string
	}{
		{
			name:     "no errors",
			err:      ErrValidationFailed{},
			expected: "validation failed",
		},
		{
			name: "single error",
			err: ErrValidationFailed{
				Errors: []ValidationError{
					{Field: "email", Message: "is required"},
				},
			},
			expected: "validation failed: email: is required",
		},
		{
			name: "multiple errors",
			err: ErrValidationFailed{
				Errors: []ValidationError{
					{Field: "email", Message: "is required"},
					{Field: "password", Message: "too short"},
				},
			},
			expected: "validation failed: email: is required; password: too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name:     "with field",
			err:      ValidationError{Field: "email", Message: "is required"},
			expected: "email: is required",
		},
		{
			name:     "without field",
			err:      ValidationError{Message: "validation failed"},
			expected: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrFieldRequired_Error(t *testing.T) {
	err := ErrFieldRequired{Field: "username"}
	expected := "field username is required"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrFieldTooLong_Error(t *testing.T) {
	err := ErrFieldTooLong{Field: "name", MaxLength: 100, Actual: 150}
	expected := "field name exceeds maximum length: 150 > 100"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrFieldTooShort_Error(t *testing.T) {
	err := ErrFieldTooShort{Field: "password", MinLength: 8, Actual: 5}
	expected := "field password is below minimum length: 5 < 8"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidFormat_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidFormat
		expected string
	}{
		{
			name:     "with actual",
			err:      ErrInvalidFormat{Field: "date", Expected: "YYYY-MM-DD", Actual: "2024/01/01"},
			expected: "field date has invalid format: expected YYYY-MM-DD, got 2024/01/01",
		},
		{
			name:     "without actual",
			err:      ErrInvalidFormat{Field: "date", Expected: "YYYY-MM-DD"},
			expected: "field date has invalid format: expected YYYY-MM-DD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidValue_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidValue
		expected string
	}{
		{
			name:     "with allowed values",
			err:      ErrInvalidValue{Field: "status", Value: "unknown", Allowed: []string{"active", "inactive"}},
			expected: "field status has invalid value: unknown, allowed values: [active inactive]",
		},
		{
			name:     "with reason",
			err:      ErrInvalidValue{Field: "age", Value: -5, Reason: "must be positive"},
			expected: "field age has invalid value: -5 (must be positive)",
		},
		{
			name:     "simple",
			err:      ErrInvalidValue{Field: "count", Value: "abc"},
			expected: "field count has invalid value: abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrPathTraversal_Error(t *testing.T) {
	err := ErrPathTraversal{Path: "../../../etc/passwd"}
	expected := "path traversal detected: ../../../etc/passwd"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrDangerousContent_Error(t *testing.T) {
	err := ErrDangerousContent{Field: "comment", Type: "script", Content: "<script>"}
	expected := "dangerous script content detected in field comment"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrOutOfRange_Error(t *testing.T) {
	err := ErrOutOfRange{Field: "age", Min: 0, Max: 120, Value: 150}
	expected := "field age value 150 is out of range [0, 120]"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidPattern_Error(t *testing.T) {
	err := ErrInvalidPattern{Field: "zipcode", Pattern: "^\\d{5}$", Value: "123"}
	expected := "field zipcode value does not match pattern ^\\d{5}$"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidEmail_Error(t *testing.T) {
	err := ErrInvalidEmail{Email: "not-an-email"}
	expected := "invalid email address: not-an-email"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidURL_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidURL
		expected string
	}{
		{
			name:     "with reason",
			err:      ErrInvalidURL{URL: "not-a-url", Reason: "missing scheme"},
			expected: "invalid URL: not-a-url (missing scheme)",
		},
		{
			name:     "without reason",
			err:      ErrInvalidURL{URL: "not-a-url"},
			expected: "invalid URL: not-a-url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidIP_Error(t *testing.T) {
	err := ErrInvalidIP{IP: "not-an-ip"}
	expected := "invalid IP address: not-an-ip"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrSQLInjection_Error(t *testing.T) {
	err := ErrSQLInjection{Field: "query", Pattern: "'; DROP TABLE"}
	expected := "potential SQL injection detected in field query"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrXSSDetected_Error(t *testing.T) {
	err := ErrXSSDetected{Field: "comment"}
	expected := "potential XSS content detected in field comment"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

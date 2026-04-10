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

func TestValidatorFunc_Validate(t *testing.T) {
	// Test with a simple validator function
	alwaysValid := ValidatorFunc(func(value any) error {
		return nil
	})

	err := alwaysValid.Validate("test")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Test with error-returning function
	alwaysInvalid := ValidatorFunc(func(value any) error {
		return ErrFieldRequired{Field: "test"}
	})

	err = alwaysInvalid.Validate("test")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestValidationResult_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		result   ValidationResult
		expected bool
	}{
		{
			name:     "valid result",
			result:   ValidationResult{Valid: true, Errors: nil},
			expected: true,
		},
		{
			name:     "invalid result with errors",
			result:   ValidationResult{Valid: false, Errors: []ValidationError{{Field: "test"}}},
			expected: false,
		},
		{
			name:     "result with empty errors slice",
			result:   ValidationResult{Valid: false, Errors: []ValidationError{}},
			expected: true, // IsValid checks len(Errors) == 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestValidationResult_Error(t *testing.T) {
	tests := []struct {
		name     string
		result   ValidationResult
		expected string
	}{
		{
			name:     "no errors",
			result:   ValidationResult{},
			expected: "",
		},
		{
			name: "with errors",
			result: ValidationResult{
				Errors: []ValidationError{
					{Field: "email", Message: "is required"},
				},
			},
			expected: "email: is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.Error(); got != tt.expected {
				t.Errorf("Error() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestValidationResult_AddError(t *testing.T) {
	result := NewValidResult()

	if !result.Valid {
		t.Error("new valid result should be valid")
	}

	result.AddError(ValidationError{Field: "test", Message: "error"})

	if result.Valid {
		t.Error("result should be invalid after adding error")
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors length = %d, expected 1", len(result.Errors))
	}
}

func TestValidationResult_Merge(t *testing.T) {
	result1 := NewValidResult()
	result2 := NewInvalidResult(
		ValidationError{Field: "field1", Message: "error1"},
		ValidationError{Field: "field2", Message: "error2"},
	)

	result1.Merge(result2)

	if result1.Valid {
		t.Error("merged result should be invalid")
	}
	if len(result1.Errors) != 2 {
		t.Errorf("Errors length = %d, expected 2", len(result1.Errors))
	}
}

func TestNewValidResult(t *testing.T) {
	result := NewValidResult()

	if !result.Valid {
		t.Error("new valid result should be valid")
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors length = %d, expected 0", len(result.Errors))
	}
}

func TestNewInvalidResult(t *testing.T) {
	result := NewInvalidResult(
		ValidationError{Field: "test", Message: "error"},
	)

	if result.Valid {
		t.Error("new invalid result should be invalid")
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors length = %d, expected 1", len(result.Errors))
	}
}

func TestDefaultSanitizerOptions(t *testing.T) {
	options := DefaultSanitizerOptions()

	if !options.TrimSpace {
		t.Error("TrimSpace should be true")
	}
	if !options.StripHTML {
		t.Error("StripHTML should be true")
	}
	if !options.EscapeHTML {
		t.Error("EscapeHTML should be true")
	}
	if !options.StripNullBytes {
		t.Error("StripNullBytes should be true")
	}
	if !options.NormalizeNewlines {
		t.Error("NormalizeNewlines should be true")
	}
}

func TestDefaultPathSanitizerOptions(t *testing.T) {
	options := DefaultPathSanitizerOptions()

	if options.AllowAbsolute {
		t.Error("AllowAbsolute should be false")
	}
	if options.MaxDepth != 10 {
		t.Errorf("MaxDepth = %d, expected 10", options.MaxDepth)
	}
	if options.AllowDotFiles {
		t.Error("AllowDotFiles should be false")
	}
	if len(options.DisallowedExtensions) == 0 {
		t.Error("DisallowedExtensions should not be empty")
	}
}

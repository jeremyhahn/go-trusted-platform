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

package fips

import (
	"errors"
	"testing"
)

func TestErrorDefinitions(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		shouldBeError bool
	}{
		{
			name:          "ErrUnsupportedOS",
			err:           ErrUnsupportedOS,
			expectedMsg:   "unsupported operating system for FIPS installation",
			shouldBeError: true,
		},
		{
			name:          "ErrNotImplemented",
			err:           ErrNotImplemented,
			expectedMsg:   "FIPS installer not implemented for this OS",
			shouldBeError: true,
		},
		{
			name:          "ErrVerificationFailed",
			err:           ErrVerificationFailed,
			expectedMsg:   "FIPS verification failed",
			shouldBeError: true,
		},
		{
			name:          "ErrKernelNotFound",
			err:           ErrKernelNotFound,
			expectedMsg:   "FIPS kernel not found",
			shouldBeError: true,
		},
		{
			name:          "ErrOpenSSLNotConfigured",
			err:           ErrOpenSSLNotConfigured,
			expectedMsg:   "OpenSSL not configured for FIPS mode",
			shouldBeError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil && tt.shouldBeError {
				t.Error("error is nil but should be defined")
			}

			if tt.err != nil {
				if tt.err.Error() != tt.expectedMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.expectedMsg, tt.err.Error())
				}
			}
		})
	}
}

func TestErrorEquality(t *testing.T) {
	// Test that error constants are properly comparable with errors.Is
	tests := []struct {
		name     string
		err      error
		target   error
		shouldBe bool
	}{
		{
			name:     "ErrUnsupportedOS is itself",
			err:      ErrUnsupportedOS,
			target:   ErrUnsupportedOS,
			shouldBe: true,
		},
		{
			name:     "ErrNotImplemented is itself",
			err:      ErrNotImplemented,
			target:   ErrNotImplemented,
			shouldBe: true,
		},
		{
			name:     "ErrVerificationFailed is itself",
			err:      ErrVerificationFailed,
			target:   ErrVerificationFailed,
			shouldBe: true,
		},
		{
			name:     "ErrKernelNotFound is itself",
			err:      ErrKernelNotFound,
			target:   ErrKernelNotFound,
			shouldBe: true,
		},
		{
			name:     "ErrOpenSSLNotConfigured is itself",
			err:      ErrOpenSSLNotConfigured,
			target:   ErrOpenSSLNotConfigured,
			shouldBe: true,
		},
		{
			name:     "ErrUnsupportedOS is not ErrNotImplemented",
			err:      ErrUnsupportedOS,
			target:   ErrNotImplemented,
			shouldBe: false,
		},
		{
			name:     "ErrVerificationFailed is not ErrKernelNotFound",
			err:      ErrVerificationFailed,
			target:   ErrKernelNotFound,
			shouldBe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errors.Is(tt.err, tt.target)
			if result != tt.shouldBe {
				t.Errorf("errors.Is(%v, %v) = %v, expected %v", tt.err, tt.target, result, tt.shouldBe)
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that wrapped errors can be unwrapped properly
	baseErr := ErrVerificationFailed
	wrappedErr := errors.New("additional context: " + baseErr.Error())

	if errors.Is(wrappedErr, baseErr) {
		t.Error("string concatenation should not make errors.Is work")
	}

	// Properly wrapped error
	properlyWrappedErr := errors.Join(baseErr, errors.New("additional context"))
	if !errors.Is(properlyWrappedErr, baseErr) {
		t.Error("errors.Join should make errors.Is work")
	}
}

func TestErrorTypeAssertions(t *testing.T) {
	// Verify all errors are standard error types
	var _ = ErrUnsupportedOS
	var _ = ErrNotImplemented
	var _ = ErrVerificationFailed
	var _ = ErrKernelNotFound
	var _ = ErrOpenSSLNotConfigured
}

func TestErrorNilChecks(t *testing.T) {
	// Ensure error constants are not nil
	errors := []error{
		ErrUnsupportedOS,
		ErrNotImplemented,
		ErrVerificationFailed,
		ErrKernelNotFound,
		ErrOpenSSLNotConfigured,
	}

	for i, err := range errors {
		if err == nil {
			t.Errorf("error at index %d is nil", i)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	// Ensure error messages are non-empty and descriptive
	tests := []struct {
		err    error
		minLen int
	}{
		{ErrUnsupportedOS, 10},
		{ErrNotImplemented, 10},
		{ErrVerificationFailed, 10},
		{ErrKernelNotFound, 10},
		{ErrOpenSSLNotConfigured, 10},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			msg := tt.err.Error()
			if len(msg) < tt.minLen {
				t.Errorf("error message too short: '%s' (length %d, expected at least %d)",
					msg, len(msg), tt.minLen)
			}
			if msg == "" {
				t.Error("error message is empty")
			}
		})
	}
}

func TestErrorUniqueness(t *testing.T) {
	// Ensure all error messages are unique
	errors := map[string]error{
		"ErrUnsupportedOS":        ErrUnsupportedOS,
		"ErrNotImplemented":       ErrNotImplemented,
		"ErrVerificationFailed":   ErrVerificationFailed,
		"ErrKernelNotFound":       ErrKernelNotFound,
		"ErrOpenSSLNotConfigured": ErrOpenSSLNotConfigured,
	}

	seen := make(map[string]string)
	for name, err := range errors {
		msg := err.Error()
		if existingName, exists := seen[msg]; exists {
			t.Errorf("duplicate error message: %s and %s both have message '%s'",
				name, existingName, msg)
		}
		seen[msg] = name
	}
}

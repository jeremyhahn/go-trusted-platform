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

package prompt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPromptWriteError_Error(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		err      error
		expected string
	}{
		{
			name:     "simple error",
			message:  "Enter password",
			err:      errors.New("write failed"),
			expected: "failed to write prompt message 'Enter password': write failed",
		},
		{
			name:     "empty message",
			message:  "",
			err:      errors.New("io error"),
			expected: "failed to write prompt message '': io error",
		},
		{
			name:     "complex error",
			message:  "Security PIN",
			err:      errors.New("connection reset by peer"),
			expected: "failed to write prompt message 'Security PIN': connection reset by peer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PromptWriteError{
				Message: tt.message,
				Err:     tt.err,
			}

			assert.Equal(t, tt.expected, e.Error(), "Error message should match expected format")
		})
	}
}

func TestPromptWriteError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	e := &PromptWriteError{
		Message: "test",
		Err:     originalErr,
	}

	unwrapped := e.Unwrap()

	assert.Equal(t, originalErr, unwrapped, "Unwrap should return the original error")
	assert.True(t, errors.Is(e, originalErr), "errors.Is should work with wrapped error")
}

func TestPromptWriteError_ErrorsAs(t *testing.T) {
	originalErr := errors.New("write error")
	e := &PromptWriteError{
		Message: "Enter value",
		Err:     originalErr,
	}

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(e, &promptWriteErr), "errors.As should match PromptWriteError")
	assert.Equal(t, "Enter value", promptWriteErr.Message, "Message should be accessible after As")
}

func TestPromptReadError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "EOF error",
			err:      errors.New("EOF"),
			expected: "failed to read prompt input: EOF",
		},
		{
			name:     "timeout error",
			err:      errors.New("read timeout"),
			expected: "failed to read prompt input: read timeout",
		},
		{
			name:     "closed pipe error",
			err:      errors.New("pipe closed"),
			expected: "failed to read prompt input: pipe closed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PromptReadError{
				Err: tt.err,
			}

			assert.Equal(t, tt.expected, e.Error(), "Error message should match expected format")
		})
	}
}

func TestPromptReadError_Unwrap(t *testing.T) {
	originalErr := errors.New("original read error")
	e := &PromptReadError{
		Err: originalErr,
	}

	unwrapped := e.Unwrap()

	assert.Equal(t, originalErr, unwrapped, "Unwrap should return the original error")
	assert.True(t, errors.Is(e, originalErr), "errors.Is should work with wrapped error")
}

func TestPromptReadError_ErrorsAs(t *testing.T) {
	originalErr := errors.New("read error")
	e := &PromptReadError{
		Err: originalErr,
	}

	var promptReadErr *PromptReadError
	assert.True(t, errors.As(e, &promptReadErr), "errors.As should match PromptReadError")
	assert.Equal(t, originalErr, promptReadErr.Err, "Err should be accessible after As")
}

func TestPasswordReadError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "terminal error",
			err:      errors.New("not a terminal"),
			expected: "failed to read password: not a terminal",
		},
		{
			name:     "interrupted error",
			err:      errors.New("interrupted system call"),
			expected: "failed to read password: interrupted system call",
		},
		{
			name:     "permission error",
			err:      errors.New("permission denied"),
			expected: "failed to read password: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PasswordReadError{
				Err: tt.err,
			}

			assert.Equal(t, tt.expected, e.Error(), "Error message should match expected format")
		})
	}
}

func TestPasswordReadError_Unwrap(t *testing.T) {
	originalErr := errors.New("original password error")
	e := &PasswordReadError{
		Err: originalErr,
	}

	unwrapped := e.Unwrap()

	assert.Equal(t, originalErr, unwrapped, "Unwrap should return the original error")
	assert.True(t, errors.Is(e, originalErr), "errors.Is should work with wrapped error")
}

func TestPasswordReadError_ErrorsAs(t *testing.T) {
	originalErr := errors.New("password read error")
	e := &PasswordReadError{
		Err: originalErr,
	}

	var pwReadErr *PasswordReadError
	assert.True(t, errors.As(e, &pwReadErr), "errors.As should match PasswordReadError")
	assert.Equal(t, originalErr, pwReadErr.Err, "Err should be accessible after As")
}

func TestErrorTypes_ImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = &PromptWriteError{}
	var _ error = &PromptReadError{}
	var _ error = &PasswordReadError{}
}

func TestErrorChaining(t *testing.T) {
	// Test that errors can be chained properly
	rootErr := errors.New("root cause")
	readErr := &PromptReadError{Err: rootErr}
	writeErr := &PromptWriteError{Message: "wrapper", Err: readErr}

	// Should be able to find rootErr
	assert.True(t, errors.Is(writeErr, rootErr), "Should find root error in chain")

	// Should be able to find readErr
	var foundReadErr *PromptReadError
	assert.True(t, errors.As(writeErr, &foundReadErr), "Should find PromptReadError in chain")
}

func TestPromptWriteError_NilError(t *testing.T) {
	e := &PromptWriteError{
		Message: "test",
		Err:     nil,
	}

	// Should not panic with nil error
	assert.Contains(t, e.Error(), "test", "Should contain message even with nil error")
	assert.Nil(t, e.Unwrap(), "Unwrap should return nil for nil error")
}

func TestPromptReadError_NilError(t *testing.T) {
	e := &PromptReadError{
		Err: nil,
	}

	// Should not panic with nil error
	assert.NotPanics(t, func() {
		_ = e.Error()
	}, "Error() should not panic with nil error")
	assert.Nil(t, e.Unwrap(), "Unwrap should return nil for nil error")
}

func TestPasswordReadError_NilError(t *testing.T) {
	e := &PasswordReadError{
		Err: nil,
	}

	// Should not panic with nil error
	assert.NotPanics(t, func() {
		_ = e.Error()
	}, "Error() should not panic with nil error")
	assert.Nil(t, e.Unwrap(), "Unwrap should return nil for nil error")
}

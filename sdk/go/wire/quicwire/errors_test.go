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

package quicwire

import (
	"errors"
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

func TestErrInvalidConfigImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = ErrInvalidConfig{}
}

func TestErrProtocolImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = &ErrProtocol{}
}

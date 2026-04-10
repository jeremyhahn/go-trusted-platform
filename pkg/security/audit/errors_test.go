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

package audit

import (
	"errors"
	"testing"
)

func TestErrAuditLogFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrAuditLogFailed
		expected string
	}{
		{
			name:     "with reason and error",
			err:      ErrAuditLogFailed{Reason: "write failed", Err: errors.New("disk full")},
			expected: "audit log failed: write failed: disk full",
		},
		{
			name:     "with reason only",
			err:      ErrAuditLogFailed{Reason: "buffer overflow"},
			expected: "audit log failed: buffer overflow",
		},
		{
			name:     "empty reason",
			err:      ErrAuditLogFailed{Reason: ""},
			expected: "audit log failed: ",
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

func TestErrAuditLogFailed_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	err := ErrAuditLogFailed{Reason: "test", Err: inner}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() = %v, expected %v", unwrapped, inner)
	}

	errNoInner := ErrAuditLogFailed{Reason: "test"}
	if unwrapped := errNoInner.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap() = %v, expected nil", unwrapped)
	}
}

func TestErrInvalidEvent_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidEvent
		expected string
	}{
		{
			name:     "missing field",
			err:      ErrInvalidEvent{Field: "Actor", Reason: "cannot be empty"},
			expected: "invalid audit event: field Actor: cannot be empty",
		},
		{
			name:     "invalid format",
			err:      ErrInvalidEvent{Field: "Timestamp", Reason: "must be after epoch"},
			expected: "invalid audit event: field Timestamp: must be after epoch",
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

func TestErrQueryFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrQueryFailed
		expected string
	}{
		{
			name:     "with error",
			err:      ErrQueryFailed{Reason: "database error", Err: errors.New("connection timeout")},
			expected: "audit query failed: database error: connection timeout",
		},
		{
			name:     "without error",
			err:      ErrQueryFailed{Reason: "invalid filter"},
			expected: "audit query failed: invalid filter",
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

func TestErrQueryFailed_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	err := ErrQueryFailed{Reason: "test", Err: inner}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() = %v, expected %v", unwrapped, inner)
	}
}

func TestErrLoggerClosed_Error(t *testing.T) {
	err := ErrLoggerClosed{}
	expected := "audit logger has been closed"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrBufferFull_Error(t *testing.T) {
	err := ErrBufferFull{Size: 1000}
	expected := "audit buffer full, size: 1000"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrPersistenceFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrPersistenceFailed
		expected string
	}{
		{
			name:     "with error",
			err:      ErrPersistenceFailed{EventID: "evt-123", Err: errors.New("write error")},
			expected: "audit persistence failed for event evt-123: write error",
		},
		{
			name:     "without error",
			err:      ErrPersistenceFailed{EventID: "evt-456"},
			expected: "audit persistence failed for event evt-456",
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

func TestErrPersistenceFailed_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	err := ErrPersistenceFailed{EventID: "test", Err: inner}

	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("Unwrap() = %v, expected %v", unwrapped, inner)
	}
}

func TestErrInvalidFilter_Error(t *testing.T) {
	err := ErrInvalidFilter{Field: "StartTime", Reason: "must be before EndTime"}
	expected := "invalid audit filter: field StartTime: must be before EndTime"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrContextCanceled_Error(t *testing.T) {
	err := ErrContextCanceled{Operation: "query"}
	expected := "audit operation canceled: query"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "BufferSize", Reason: "must be positive"}
	expected := "invalid audit config: field BufferSize: must be positive"

	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, expected %q", got, expected)
	}
}

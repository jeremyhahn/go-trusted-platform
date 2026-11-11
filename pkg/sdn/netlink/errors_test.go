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

package netlink

import (
	"errors"
	"strings"
	"testing"
)

func TestNetlinkError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *NetlinkError
		expected string
	}{
		{
			name: "error without cause",
			err: &NetlinkError{
				Type:    ErrorTypeInvalidName,
				Message: "test message",
			},
			expected: "invalid_name: test message",
		},
		{
			name: "error with cause",
			err: &NetlinkError{
				Type:    ErrorTypeCreateFailed,
				Message: "test message",
				Cause:   errors.New("underlying error"),
			},
			expected: "create_failed: test message: underlying error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNetlinkError_Unwrap(t *testing.T) {
	tests := []struct {
		name string
		err  *NetlinkError
		want error
	}{
		{
			name: "with cause",
			err: &NetlinkError{
				Type:    ErrorTypeCreateFailed,
				Message: "test",
				Cause:   errors.New("cause error"),
			},
			want: errors.New("cause error"),
		},
		{
			name: "without cause",
			err: &NetlinkError{
				Type:    ErrorTypeInvalidName,
				Message: "test",
				Cause:   nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := tt.err.Unwrap()
			if tt.want == nil {
				if unwrapped != nil {
					t.Errorf("Unwrap() = %v, want nil", unwrapped)
				}
			} else {
				if unwrapped == nil {
					t.Errorf("Unwrap() = nil, want %v", tt.want)
				} else if unwrapped.Error() != tt.want.Error() {
					t.Errorf("Unwrap() = %v, want %v", unwrapped, tt.want)
				}
			}
		})
	}
}

func TestErrInvalidName(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		wantContains  string
	}{
		{
			name:          "empty name",
			interfaceName: "",
			wantContains:  "invalid interface name",
		},
		{
			name:          "long name",
			interfaceName: "verylonginterfacename",
			wantContains:  "invalid interface name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidName(tt.interfaceName)
			if err == nil {
				t.Fatal("ErrInvalidName() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypeInvalidName {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeInvalidName)
			}

			if !strings.Contains(err.Error(), tt.wantContains) {
				t.Errorf("Error message %q does not contain %q", err.Error(), tt.wantContains)
			}
		})
	}
}

func TestErrNotFound(t *testing.T) {
	name := "test0"
	err := ErrNotFound(name)

	if err == nil {
		t.Fatal("ErrNotFound() returned nil")
	}

	var netlinkErr *NetlinkError
	if !errors.As(err, &netlinkErr) {
		t.Fatal("error is not a NetlinkError")
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}

	if !strings.Contains(err.Error(), name) {
		t.Errorf("Error message %q does not contain interface name %q", err.Error(), name)
	}
}

func TestErrAlreadyExists(t *testing.T) {
	name := "test0"
	err := ErrAlreadyExists(name)

	if err == nil {
		t.Fatal("ErrAlreadyExists() returned nil")
	}

	var netlinkErr *NetlinkError
	if !errors.As(err, &netlinkErr) {
		t.Fatal("error is not a NetlinkError")
	}

	if netlinkErr.Type != ErrorTypeAlreadyExists {
		t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeAlreadyExists)
	}

	if !strings.Contains(err.Error(), name) {
		t.Errorf("Error message %q does not contain interface name %q", err.Error(), name)
	}
}

func TestErrCreateFailed(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		cause         error
	}{
		{
			name:          "with cause",
			interfaceName: "test0",
			cause:         errors.New("underlying error"),
		},
		{
			name:          "nil cause",
			interfaceName: "test1",
			cause:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrCreateFailed(tt.interfaceName, tt.cause)

			if err == nil {
				t.Fatal("ErrCreateFailed() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypeCreateFailed {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeCreateFailed)
			}

			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Error("error does not wrap the cause")
				}
			}

			if !strings.Contains(err.Error(), tt.interfaceName) {
				t.Errorf("Error message %q does not contain interface name %q", err.Error(), tt.interfaceName)
			}
		})
	}
}

func TestErrDeleteFailed(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		cause         error
	}{
		{
			name:          "with cause",
			interfaceName: "test0",
			cause:         errors.New("underlying error"),
		},
		{
			name:          "nil cause",
			interfaceName: "test1",
			cause:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDeleteFailed(tt.interfaceName, tt.cause)

			if err == nil {
				t.Fatal("ErrDeleteFailed() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypeDeleteFailed {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeDeleteFailed)
			}

			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Error("error does not wrap the cause")
				}
			}
		})
	}
}

func TestErrSetupFailed(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		message       string
		cause         error
	}{
		{
			name:          "with cause",
			interfaceName: "test0",
			message:       "set MTU",
			cause:         errors.New("underlying error"),
		},
		{
			name:          "nil cause",
			interfaceName: "test1",
			message:       "configure",
			cause:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrSetupFailed(tt.interfaceName, tt.message, tt.cause)

			if err == nil {
				t.Fatal("ErrSetupFailed() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypeSetupFailed {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeSetupFailed)
			}

			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Error("error does not wrap the cause")
				}
			}

			if !strings.Contains(err.Error(), tt.message) {
				t.Errorf("Error message %q does not contain %q", err.Error(), tt.message)
			}
		})
	}
}

func TestErrStateFailed(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		state         string
		cause         error
	}{
		{
			name:          "with cause",
			interfaceName: "test0",
			state:         "up",
			cause:         errors.New("underlying error"),
		},
		{
			name:          "nil cause",
			interfaceName: "test1",
			state:         "down",
			cause:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrStateFailed(tt.interfaceName, tt.state, tt.cause)

			if err == nil {
				t.Fatal("ErrStateFailed() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypeStateFailed {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypeStateFailed)
			}

			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Error("error does not wrap the cause")
				}
			}

			if !strings.Contains(err.Error(), tt.state) {
				t.Errorf("Error message %q does not contain state %q", err.Error(), tt.state)
			}
		})
	}
}

func TestErrPermission(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		cause     error
	}{
		{
			name:      "with cause",
			operation: "create TAP",
			cause:     errors.New("permission denied"),
		},
		{
			name:      "nil cause",
			operation: "delete link",
			cause:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrPermission(tt.operation, tt.cause)

			if err == nil {
				t.Fatal("ErrPermission() returned nil")
			}

			var netlinkErr *NetlinkError
			if !errors.As(err, &netlinkErr) {
				t.Fatal("error is not a NetlinkError")
			}

			if netlinkErr.Type != ErrorTypePermission {
				t.Errorf("Type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
			}

			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Error("error does not wrap the cause")
				}
			}

			if !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
				t.Errorf("Error message %q does not mention CAP_NET_ADMIN", err.Error())
			}

			if !strings.Contains(err.Error(), tt.operation) {
				t.Errorf("Error message %q does not mention operation %q", err.Error(), tt.operation)
			}
		})
	}
}

// Test all error type constants

// Test error wrapping and unwrapping
func TestNetlinkError_Wrapping(t *testing.T) {
	innerErr := errors.New("inner error")
	middleErr := ErrSetupFailed("test0", "middle", innerErr)
	outerErr := &NetlinkError{
		Type:    ErrorTypeCreateFailed,
		Message: "outer error",
		Cause:   middleErr,
	}

	// Test that we can unwrap to the inner error
	if !errors.Is(outerErr, innerErr) {
		t.Error("outer error should wrap inner error")
	}

	// Test direct unwrap
	unwrapped := outerErr.Unwrap()
	if unwrapped != middleErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, middleErr)
	}
}

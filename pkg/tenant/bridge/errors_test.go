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

package bridge

import (
	"errors"
	"testing"
)

func TestErrBridgeExists_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeExists
		expected string
	}{
		{
			name:     "simple bridge name",
			err:      ErrBridgeExists{Name: "br-tenant-test"},
			expected: "bridge already exists: br-tenant-test",
		},
		{
			name:     "empty bridge name",
			err:      ErrBridgeExists{Name: ""},
			expected: "bridge already exists: ",
		},
		{
			name:     "special characters in name",
			err:      ErrBridgeExists{Name: "br-tenant-test-123"},
			expected: "bridge already exists: br-tenant-test-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrBridgeExists.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrBridgeNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeNotFound
		expected string
	}{
		{
			name:     "simple bridge name",
			err:      ErrBridgeNotFound{Name: "br-tenant-test"},
			expected: "bridge not found: br-tenant-test",
		},
		{
			name:     "empty bridge name",
			err:      ErrBridgeNotFound{Name: ""},
			expected: "bridge not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrBridgeNotFound.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrBridgeCreateFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeCreateFailed
		expected string
	}{
		{
			name:     "with underlying error",
			err:      ErrBridgeCreateFailed{Name: "br-test", Err: errors.New("connection refused")},
			expected: "failed to create bridge br-test: connection refused",
		},
		{
			name:     "with nil error",
			err:      ErrBridgeCreateFailed{Name: "br-test", Err: nil},
			expected: "failed to create bridge br-test: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrBridgeCreateFailed.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrBridgeCreateFailed_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	err := ErrBridgeCreateFailed{Name: "br-test", Err: underlyingErr}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ErrBridgeCreateFailed.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}

	// Test with errors.Is
	if !errors.Is(err, underlyingErr) {
		t.Error("errors.Is should find underlying error")
	}
}

func TestErrBridgeDeleteFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeDeleteFailed
		expected string
	}{
		{
			name:     "with underlying error",
			err:      ErrBridgeDeleteFailed{Name: "br-test", Err: errors.New("bridge in use")},
			expected: "failed to delete bridge br-test: bridge in use",
		},
		{
			name:     "with nil error",
			err:      ErrBridgeDeleteFailed{Name: "br-test", Err: nil},
			expected: "failed to delete bridge br-test: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrBridgeDeleteFailed.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrBridgeDeleteFailed_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	err := ErrBridgeDeleteFailed{Name: "br-test", Err: underlyingErr}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ErrBridgeDeleteFailed.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}

	// Test with errors.Is
	if !errors.Is(err, underlyingErr) {
		t.Error("errors.Is should find underlying error")
	}
}

func TestErrFlowInstallFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrFlowInstallFailed
		expected string
	}{
		{
			name:     "with underlying error",
			err:      ErrFlowInstallFailed{Bridge: "br-test", Err: errors.New("table overflow")},
			expected: "failed to install flows on bridge br-test: table overflow",
		},
		{
			name:     "with nil error",
			err:      ErrFlowInstallFailed{Bridge: "br-test", Err: nil},
			expected: "failed to install flows on bridge br-test: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrFlowInstallFailed.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrFlowInstallFailed_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	err := ErrFlowInstallFailed{Bridge: "br-test", Err: underlyingErr}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ErrFlowInstallFailed.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}
}

func TestErrOVSConnectionFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrOVSConnectionFailed
		expected string
	}{
		{
			name:     "with underlying error",
			err:      ErrOVSConnectionFailed{Err: errors.New("socket not found")},
			expected: "OVS connection failed: socket not found",
		},
		{
			name:     "with nil error",
			err:      ErrOVSConnectionFailed{Err: nil},
			expected: "OVS connection failed: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrOVSConnectionFailed.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrOVSConnectionFailed_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	err := ErrOVSConnectionFailed{Err: underlyingErr}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ErrOVSConnectionFailed.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}
}

func TestErrInvalidBridgeName_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidBridgeName
		expected string
	}{
		{
			name:     "empty name",
			err:      ErrInvalidBridgeName{Name: "", Reason: "name cannot be empty"},
			expected: "invalid bridge name \"\": name cannot be empty",
		},
		{
			name:     "too long name",
			err:      ErrInvalidBridgeName{Name: "very-long-name", Reason: "name exceeds maximum length"},
			expected: "invalid bridge name \"very-long-name\": name exceeds maximum length",
		},
		{
			name:     "invalid characters",
			err:      ErrInvalidBridgeName{Name: "br@test", Reason: "contains invalid characters"},
			expected: "invalid bridge name \"br@test\": contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrInvalidBridgeName.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrTenantNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTenantNotFound
		expected string
	}{
		{
			name:     "uuid tenant id",
			err:      ErrTenantNotFound{TenantID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "tenant not found: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "empty tenant id",
			err:      ErrTenantNotFound{TenantID: ""},
			expected: "tenant not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrTenantNotFound.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrInvalidVLANRange_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidVLANRange
		expected string
	}{
		{
			name:     "start greater than end",
			err:      ErrInvalidVLANRange{Start: 200, End: 100, Reason: "start must be less than or equal to end"},
			expected: "invalid VLAN range 200-100: start must be less than or equal to end",
		},
		{
			name:     "zero start",
			err:      ErrInvalidVLANRange{Start: 0, End: 100, Reason: "VLAN IDs must be 1-4094"},
			expected: "invalid VLAN range 0-100: VLAN IDs must be 1-4094",
		},
		{
			name:     "exceeds maximum",
			err:      ErrInvalidVLANRange{Start: 100, End: 5000, Reason: "VLAN ID exceeds maximum 4094"},
			expected: "invalid VLAN range 100-5000: VLAN ID exceeds maximum 4094",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrInvalidVLANRange.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrFlowDeleteFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrFlowDeleteFailed
		expected string
	}{
		{
			name:     "with underlying error",
			err:      ErrFlowDeleteFailed{Bridge: "br-test", Err: errors.New("flow not found")},
			expected: "failed to delete flows on bridge br-test: flow not found",
		},
		{
			name:     "with nil error",
			err:      ErrFlowDeleteFailed{Bridge: "br-test", Err: nil},
			expected: "failed to delete flows on bridge br-test: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrFlowDeleteFailed.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrFlowDeleteFailed_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	err := ErrFlowDeleteFailed{Bridge: "br-test", Err: underlyingErr}

	unwrapped := err.Unwrap()
	if unwrapped != underlyingErr {
		t.Errorf("ErrFlowDeleteFailed.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}
}

func TestErrBridgeStatusError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeStatusError
		expected string
	}{
		{
			name:     "error status",
			err:      ErrBridgeStatusError{Name: "br-test", Status: StatusError},
			expected: "bridge br-test is in error state: error",
		},
		{
			name:     "deleting status",
			err:      ErrBridgeStatusError{Name: "br-test", Status: StatusDeleting},
			expected: "bridge br-test is in error state: deleting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrBridgeStatusError.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestErrOperationInProgress_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrOperationInProgress
		expected string
	}{
		{
			name:     "create operation",
			err:      ErrOperationInProgress{TenantID: "tenant-123", Operation: "create"},
			expected: "operation create already in progress for tenant tenant-123",
		},
		{
			name:     "delete operation",
			err:      ErrOperationInProgress{TenantID: "tenant-456", Operation: "delete"},
			expected: "operation delete already in progress for tenant tenant-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("ErrOperationInProgress.Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test that all error types implement the error interface
func TestErrorTypes_ImplementErrorInterface(t *testing.T) {
	var _ error = ErrBridgeExists{}
	var _ error = ErrBridgeNotFound{}
	var _ error = ErrBridgeCreateFailed{}
	var _ error = ErrBridgeDeleteFailed{}
	var _ error = ErrFlowInstallFailed{}
	var _ error = ErrOVSConnectionFailed{}
	var _ error = ErrInvalidBridgeName{}
	var _ error = ErrTenantNotFound{}
	var _ error = ErrInvalidVLANRange{}
	var _ error = ErrFlowDeleteFailed{}
	var _ error = ErrBridgeStatusError{}
	var _ error = ErrOperationInProgress{}
}

// Test error type assertions
func TestErrorTypes_TypeAssertion(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "ErrBridgeExists", err: ErrBridgeExists{Name: "test"}},
		{name: "ErrBridgeNotFound", err: ErrBridgeNotFound{Name: "test"}},
		{name: "ErrBridgeCreateFailed", err: ErrBridgeCreateFailed{Name: "test", Err: errors.New("test")}},
		{name: "ErrBridgeDeleteFailed", err: ErrBridgeDeleteFailed{Name: "test", Err: errors.New("test")}},
		{name: "ErrFlowInstallFailed", err: ErrFlowInstallFailed{Bridge: "test", Err: errors.New("test")}},
		{name: "ErrOVSConnectionFailed", err: ErrOVSConnectionFailed{Err: errors.New("test")}},
		{name: "ErrInvalidBridgeName", err: ErrInvalidBridgeName{Name: "test", Reason: "test"}},
		{name: "ErrTenantNotFound", err: ErrTenantNotFound{TenantID: "test"}},
		{name: "ErrInvalidVLANRange", err: ErrInvalidVLANRange{Start: 1, End: 2, Reason: "test"}},
		{name: "ErrFlowDeleteFailed", err: ErrFlowDeleteFailed{Bridge: "test", Err: errors.New("test")}},
		{name: "ErrBridgeStatusError", err: ErrBridgeStatusError{Name: "test", Status: StatusError}},
		{name: "ErrOperationInProgress", err: ErrOperationInProgress{TenantID: "test", Operation: "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify error message is not empty
			if tt.err.Error() == "" {
				t.Errorf("%s.Error() returned empty string", tt.name)
			}
		})
	}
}

// Test error wrapping chain
func TestErrorWrapping_Chain(t *testing.T) {
	baseErr := errors.New("base error")
	createErr := ErrBridgeCreateFailed{Name: "br-test", Err: baseErr}

	// Verify the chain works correctly
	if !errors.Is(createErr, baseErr) {
		t.Error("errors.Is should find base error in chain")
	}

	// Verify unwrap returns correct error
	var unwrapped error = createErr
	for {
		u, ok := unwrapped.(interface{ Unwrap() error })
		if !ok {
			break
		}
		unwrapped = u.Unwrap()
	}

	if unwrapped != baseErr {
		t.Errorf("unwrap chain should end at base error, got %v", unwrapped)
	}
}

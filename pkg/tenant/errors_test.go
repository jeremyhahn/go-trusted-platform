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

package tenant

import (
	"errors"
	"testing"
)

func TestErrTenantExists_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTenantExists
		expected string
	}{
		{
			name:     "with tenant name",
			err:      ErrTenantExists{Name: "test-tenant"},
			expected: "tenant already exists: test-tenant",
		},
		{
			name:     "with empty name",
			err:      ErrTenantExists{Name: ""},
			expected: "tenant already exists: ",
		},
		{
			name:     "with special characters",
			err:      ErrTenantExists{Name: "tenant-123_special"},
			expected: "tenant already exists: tenant-123_special",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrTenantExists.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrTenantExists_ImplementsError(t *testing.T) {
	var _ error = ErrTenantExists{}
}

func TestErrTenantNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTenantNotFound
		expected string
	}{
		{
			name:     "with ID only",
			err:      ErrTenantNotFound{ID: "tenant-id-123"},
			expected: "tenant not found: id=tenant-id-123",
		},
		{
			name:     "with name only",
			err:      ErrTenantNotFound{Name: "test-tenant"},
			expected: "tenant not found: name=test-tenant",
		},
		{
			name:     "with both ID and name - ID takes precedence",
			err:      ErrTenantNotFound{ID: "id-123", Name: "tenant-name"},
			expected: "tenant not found: id=id-123",
		},
		{
			name:     "with empty ID falls back to name",
			err:      ErrTenantNotFound{ID: "", Name: "fallback-tenant"},
			expected: "tenant not found: name=fallback-tenant",
		},
		{
			name:     "with both empty",
			err:      ErrTenantNotFound{ID: "", Name: ""},
			expected: "tenant not found: name=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrTenantNotFound.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrTenantNotFound_ImplementsError(t *testing.T) {
	var _ error = ErrTenantNotFound{}
}

func TestErrInvalidRequest_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidRequest
		expected string
	}{
		{
			name:     "with reason",
			err:      ErrInvalidRequest{Reason: "tenant name is required"},
			expected: "invalid request: tenant name is required",
		},
		{
			name:     "with empty reason",
			err:      ErrInvalidRequest{Reason: ""},
			expected: "invalid request: ",
		},
		{
			name:     "with detailed reason",
			err:      ErrInvalidRequest{Reason: "VLAN range must be between 1 and 4094"},
			expected: "invalid request: VLAN range must be between 1 and 4094",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrInvalidRequest.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidRequest_ImplementsError(t *testing.T) {
	var _ error = ErrInvalidRequest{}
}

func TestErrInvalidState_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidState
		expected string
	}{
		{
			name:     "with created state",
			err:      ErrInvalidState{Current: StateCreated},
			expected: "invalid tenant state: created",
		},
		{
			name:     "with active state",
			err:      ErrInvalidState{Current: StateActive},
			expected: "invalid tenant state: active",
		},
		{
			name:     "with deleted state",
			err:      ErrInvalidState{Current: StateDeleted},
			expected: "invalid tenant state: deleted",
		},
		{
			name:     "with unknown state",
			err:      ErrInvalidState{Current: State("unknown")},
			expected: "invalid tenant state: unknown",
		},
		{
			name:     "with empty state",
			err:      ErrInvalidState{Current: State("")},
			expected: "invalid tenant state: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrInvalidState.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidState_ImplementsError(t *testing.T) {
	var _ error = ErrInvalidState{}
}

func TestErrInvalidTransition_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidTransition
		expected string
	}{
		{
			name:     "created to deleted directly",
			err:      ErrInvalidTransition{From: StateCreated, To: StateDeleted},
			expected: "invalid state transition: created -> deleted",
		},
		{
			name:     "active to created",
			err:      ErrInvalidTransition{From: StateActive, To: StateCreated},
			expected: "invalid state transition: active -> created",
		},
		{
			name:     "deleted to active",
			err:      ErrInvalidTransition{From: StateDeleted, To: StateActive},
			expected: "invalid state transition: deleted -> active",
		},
		{
			name:     "suspended to created",
			err:      ErrInvalidTransition{From: StateSuspended, To: StateCreated},
			expected: "invalid state transition: suspended -> created",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrInvalidTransition.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidTransition_ImplementsError(t *testing.T) {
	var _ error = ErrInvalidTransition{}
}

func TestErrStorageFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrStorageFailed
		expected string
	}{
		{
			name:     "with operation and wrapped error",
			err:      ErrStorageFailed{Operation: "create", Err: errors.New("connection refused")},
			expected: "storage operation failed: create: connection refused",
		},
		{
			name:     "with delete operation",
			err:      ErrStorageFailed{Operation: "delete", Err: errors.New("not found")},
			expected: "storage operation failed: delete: not found",
		},
		{
			name:     "with nil error",
			err:      ErrStorageFailed{Operation: "update", Err: nil},
			expected: "storage operation failed: update: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrStorageFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrStorageFailed_Unwrap(t *testing.T) {
	wrappedErr := errors.New("underlying error")
	err := ErrStorageFailed{Operation: "read", Err: wrappedErr}

	unwrapped := err.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("ErrStorageFailed.Unwrap() = %v, want %v", unwrapped, wrappedErr)
	}
}

func TestErrStorageFailed_UnwrapNil(t *testing.T) {
	err := ErrStorageFailed{Operation: "read", Err: nil}

	unwrapped := err.Unwrap()
	if unwrapped != nil {
		t.Errorf("ErrStorageFailed.Unwrap() = %v, want nil", unwrapped)
	}
}

func TestErrStorageFailed_ErrorsIs(t *testing.T) {
	wrappedErr := errors.New("underlying error")
	err := ErrStorageFailed{Operation: "read", Err: wrappedErr}

	if !errors.Is(err, wrappedErr) {
		t.Error("errors.Is should return true for wrapped error")
	}
}

func TestErrStorageFailed_ImplementsError(t *testing.T) {
	var _ error = ErrStorageFailed{}
}

func TestErrBridgeOperationFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrBridgeOperationFailed
		expected string
	}{
		{
			name:     "with bridge create operation",
			err:      ErrBridgeOperationFailed{Bridge: "br-tenant-1", Operation: "create", Err: errors.New("already exists")},
			expected: "bridge operation failed: create on br-tenant-1: already exists",
		},
		{
			name:     "with bridge delete operation",
			err:      ErrBridgeOperationFailed{Bridge: "br-test", Operation: "delete", Err: errors.New("in use")},
			expected: "bridge operation failed: delete on br-test: in use",
		},
		{
			name:     "with nil error",
			err:      ErrBridgeOperationFailed{Bridge: "br-nil", Operation: "configure", Err: nil},
			expected: "bridge operation failed: configure on br-nil: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrBridgeOperationFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrBridgeOperationFailed_Unwrap(t *testing.T) {
	wrappedErr := errors.New("bridge error")
	err := ErrBridgeOperationFailed{Bridge: "br-test", Operation: "create", Err: wrappedErr}

	unwrapped := err.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("ErrBridgeOperationFailed.Unwrap() = %v, want %v", unwrapped, wrappedErr)
	}
}

func TestErrBridgeOperationFailed_ImplementsError(t *testing.T) {
	var _ error = ErrBridgeOperationFailed{}
}

func TestErrVLANAllocationFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrVLANAllocationFailed
		expected string
	}{
		{
			name:     "with tenant ID and error",
			err:      ErrVLANAllocationFailed{TenantID: "tenant-123", Err: errors.New("no VLANs available")},
			expected: "VLAN allocation failed for tenant tenant-123: no VLANs available",
		},
		{
			name:     "with empty tenant ID",
			err:      ErrVLANAllocationFailed{TenantID: "", Err: errors.New("range exhausted")},
			expected: "VLAN allocation failed for tenant : range exhausted",
		},
		{
			name:     "with nil error",
			err:      ErrVLANAllocationFailed{TenantID: "tenant-456", Err: nil},
			expected: "VLAN allocation failed for tenant tenant-456: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrVLANAllocationFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrVLANAllocationFailed_Unwrap(t *testing.T) {
	wrappedErr := errors.New("vlan error")
	err := ErrVLANAllocationFailed{TenantID: "tenant-123", Err: wrappedErr}

	unwrapped := err.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("ErrVLANAllocationFailed.Unwrap() = %v, want %v", unwrapped, wrappedErr)
	}
}

func TestErrVLANAllocationFailed_ImplementsError(t *testing.T) {
	var _ error = ErrVLANAllocationFailed{}
}

func TestErrQuotaExceeded_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrQuotaExceeded
		expected string
	}{
		{
			name:     "VM quota exceeded",
			err:      ErrQuotaExceeded{TenantID: "tenant-1", Resource: "VMs", Requested: 5, Available: 2},
			expected: "quota exceeded for tenant tenant-1: resource=VMs, requested=5, available=2",
		},
		{
			name:     "memory quota exceeded",
			err:      ErrQuotaExceeded{TenantID: "tenant-2", Resource: "memory", Requested: 8192, Available: 1024},
			expected: "quota exceeded for tenant tenant-2: resource=memory, requested=8192, available=1024",
		},
		{
			name:     "zero available",
			err:      ErrQuotaExceeded{TenantID: "tenant-3", Resource: "disk", Requested: 100, Available: 0},
			expected: "quota exceeded for tenant tenant-3: resource=disk, requested=100, available=0",
		},
		{
			name:     "negative available (edge case)",
			err:      ErrQuotaExceeded{TenantID: "tenant-4", Resource: "vcpus", Requested: 10, Available: -5},
			expected: "quota exceeded for tenant tenant-4: resource=vcpus, requested=10, available=-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrQuotaExceeded.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrQuotaExceeded_ImplementsError(t *testing.T) {
	var _ error = ErrQuotaExceeded{}
}

func TestErrResourceLimitReached_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrResourceLimitReached
		expected string
	}{
		{
			name:     "VM limit reached",
			err:      ErrResourceLimitReached{TenantID: "tenant-1", Resource: "VMs", Limit: 10},
			expected: "resource limit reached for tenant tenant-1: resource=VMs, limit=10",
		},
		{
			name:     "container limit reached",
			err:      ErrResourceLimitReached{TenantID: "tenant-2", Resource: "containers", Limit: 50},
			expected: "resource limit reached for tenant tenant-2: resource=containers, limit=50",
		},
		{
			name:     "zero limit",
			err:      ErrResourceLimitReached{TenantID: "tenant-3", Resource: "bridges", Limit: 0},
			expected: "resource limit reached for tenant tenant-3: resource=bridges, limit=0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrResourceLimitReached.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrResourceLimitReached_ImplementsError(t *testing.T) {
	var _ error = ErrResourceLimitReached{}
}

func TestErrInvalidVLANRange_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidVLANRange
		expected string
	}{
		{
			name:     "end less than start",
			err:      ErrInvalidVLANRange{Start: 200, End: 100, Reason: "end VLAN must be greater than or equal to start VLAN"},
			expected: "invalid VLAN range 200-100: end VLAN must be greater than or equal to start VLAN",
		},
		{
			name:     "start out of range",
			err:      ErrInvalidVLANRange{Start: 0, End: 100, Reason: "start VLAN must be between 1 and 4094"},
			expected: "invalid VLAN range 0-100: start VLAN must be between 1 and 4094",
		},
		{
			name:     "end out of range",
			err:      ErrInvalidVLANRange{Start: 100, End: 5000, Reason: "end VLAN must be between 1 and 4094"},
			expected: "invalid VLAN range 100-5000: end VLAN must be between 1 and 4094",
		},
		{
			name:     "boundary values",
			err:      ErrInvalidVLANRange{Start: 1, End: 4094, Reason: "test reason"},
			expected: "invalid VLAN range 1-4094: test reason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrInvalidVLANRange.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidVLANRange_ImplementsError(t *testing.T) {
	var _ error = ErrInvalidVLANRange{}
}

func TestErrDEKOperationFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDEKOperationFailed
		expected string
	}{
		{
			name:     "create operation failed",
			err:      ErrDEKOperationFailed{TenantID: "tenant-1", Operation: "create", Err: errors.New("TPM not available")},
			expected: "DEK operation failed for tenant tenant-1: create: TPM not available",
		},
		{
			name:     "rotate operation failed",
			err:      ErrDEKOperationFailed{TenantID: "tenant-2", Operation: "rotate", Err: errors.New("key sealed")},
			expected: "DEK operation failed for tenant tenant-2: rotate: key sealed",
		},
		{
			name:     "nil error",
			err:      ErrDEKOperationFailed{TenantID: "tenant-3", Operation: "delete", Err: nil},
			expected: "DEK operation failed for tenant tenant-3: delete: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrDEKOperationFailed.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrDEKOperationFailed_Unwrap(t *testing.T) {
	wrappedErr := errors.New("dek error")
	err := ErrDEKOperationFailed{TenantID: "tenant-123", Operation: "create", Err: wrappedErr}

	unwrapped := err.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("ErrDEKOperationFailed.Unwrap() = %v, want %v", unwrapped, wrappedErr)
	}
}

func TestErrDEKOperationFailed_ImplementsError(t *testing.T) {
	var _ error = ErrDEKOperationFailed{}
}

func TestErrConfigValidation_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrConfigValidation
		expected string
	}{
		{
			name:     "field validation",
			err:      ErrConfigValidation{Field: "DefaultVLANRangeStart", Reason: "must be between 1 and 4094"},
			expected: "configuration validation failed: DefaultVLANRangeStart: must be between 1 and 4094",
		},
		{
			name:     "empty field",
			err:      ErrConfigValidation{Field: "BridgePrefix", Reason: "must not be empty"},
			expected: "configuration validation failed: BridgePrefix: must not be empty",
		},
		{
			name:     "nested field",
			err:      ErrConfigValidation{Field: "DefaultComputeQuota.MaxVMs", Reason: "must be non-negative"},
			expected: "configuration validation failed: DefaultComputeQuota.MaxVMs: must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ErrConfigValidation.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrConfigValidation_ImplementsError(t *testing.T) {
	var _ error = ErrConfigValidation{}
}

func TestAllErrorsImplementError(t *testing.T) {
	// Ensure all error types implement the error interface
	errs := []error{
		ErrTenantExists{Name: "test"},
		ErrTenantNotFound{ID: "test"},
		ErrInvalidRequest{Reason: "test"},
		ErrInvalidState{Current: StateActive},
		ErrInvalidTransition{From: StateCreated, To: StateDeleted},
		ErrStorageFailed{Operation: "test", Err: nil},
		ErrBridgeOperationFailed{Bridge: "test", Operation: "test", Err: nil},
		ErrVLANAllocationFailed{TenantID: "test", Err: nil},
		ErrQuotaExceeded{TenantID: "test", Resource: "test", Requested: 1, Available: 0},
		ErrResourceLimitReached{TenantID: "test", Resource: "test", Limit: 1},
		ErrInvalidVLANRange{Start: 1, End: 10, Reason: "test"},
		ErrDEKOperationFailed{TenantID: "test", Operation: "test", Err: nil},
		ErrConfigValidation{Field: "test", Reason: "test"},
	}

	for i, err := range errs {
		if err == nil {
			t.Errorf("error at index %d is nil", i)
		}
		if err.Error() == "" {
			t.Errorf("error at index %d has empty message", i)
		}
	}
}

func TestErrorUniqueness(t *testing.T) {
	// Test that different error types with same data produce different messages
	err1 := ErrTenantExists{Name: "test"}
	err2 := ErrTenantNotFound{Name: "test"}

	if err1.Error() == err2.Error() {
		t.Error("ErrTenantExists and ErrTenantNotFound should have different messages")
	}
}

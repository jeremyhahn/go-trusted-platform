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

package quota

import (
	"errors"
	"testing"
)

func TestErrQuotaExceeded_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrQuotaExceeded
		expected string
	}{
		{
			name: "vms_exceeded",
			err: ErrQuotaExceeded{
				TenantID:  "tenant-123",
				Resource:  ResourceVMs,
				Requested: 10,
				Available: 5,
			},
			expected: "quota: exceeded for tenant tenant-123 resource vms: requested 10, available 5",
		},
		{
			name: "memory_exceeded",
			err: ErrQuotaExceeded{
				TenantID:  "tenant-456",
				Resource:  ResourceMemory,
				Requested: 8192,
				Available: 4096,
			},
			expected: "quota: exceeded for tenant tenant-456 resource memory: requested 8192, available 4096",
		},
		{
			name: "zero_available",
			err: ErrQuotaExceeded{
				TenantID:  "tenant-789",
				Resource:  ResourceDisk,
				Requested: 100,
				Available: 0,
			},
			expected: "quota: exceeded for tenant tenant-789 resource disk: requested 100, available 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrReservationNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrReservationNotFound
		expected string
	}{
		{
			name:     "uuid_id",
			err:      ErrReservationNotFound{ID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "quota: reservation not found: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "simple_id",
			err:      ErrReservationNotFound{ID: "res-123"},
			expected: "quota: reservation not found: res-123",
		},
		{
			name:     "empty_id",
			err:      ErrReservationNotFound{ID: ""},
			expected: "quota: reservation not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrReservationExpired_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrReservationExpired
		expected string
	}{
		{
			name:     "uuid_id",
			err:      ErrReservationExpired{ID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "quota: reservation expired: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "simple_id",
			err:      ErrReservationExpired{ID: "res-456"},
			expected: "quota: reservation expired: res-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrInvalidResource_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidResource
		expected string
	}{
		{
			name:     "unknown_resource",
			err:      ErrInvalidResource{Resource: ResourceType("unknown")},
			expected: "quota: invalid resource type: unknown",
		},
		{
			name:     "empty_resource",
			err:      ErrInvalidResource{Resource: ResourceType("")},
			expected: "quota: invalid resource type: ",
		},
		{
			name:     "custom_resource",
			err:      ErrInvalidResource{Resource: ResourceType("custom-type")},
			expected: "quota: invalid resource type: custom-type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrStoreFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrStoreFailed
		expected string
	}{
		{
			name: "with_wrapped_error",
			err: ErrStoreFailed{
				Operation: "GetQuota",
				Err:       errors.New("connection refused"),
			},
			expected: "quota: store operation GetQuota failed: connection refused",
		},
		{
			name: "without_wrapped_error",
			err: ErrStoreFailed{
				Operation: "UpdateUsage",
				Err:       nil,
			},
			expected: "quota: store operation UpdateUsage failed",
		},
		{
			name: "complex_error",
			err: ErrStoreFailed{
				Operation: "SyncAll",
				Err:       errors.New("timeout after 30s"),
			},
			expected: "quota: store operation SyncAll failed: timeout after 30s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrStoreFailed_Unwrap(t *testing.T) {
	tests := []struct {
		name        string
		err         ErrStoreFailed
		expectNil   bool
		expectedMsg string
	}{
		{
			name: "unwrap_returns_wrapped_error",
			err: ErrStoreFailed{
				Operation: "GetQuota",
				Err:       errors.New("database error"),
			},
			expectNil:   false,
			expectedMsg: "database error",
		},
		{
			name: "unwrap_returns_nil_when_no_wrapped_error",
			err: ErrStoreFailed{
				Operation: "GetQuota",
				Err:       nil,
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := tt.err.Unwrap()
			if tt.expectNil {
				if unwrapped != nil {
					t.Errorf("Unwrap() = %v, expected nil", unwrapped)
				}
			} else {
				if unwrapped == nil {
					t.Error("Unwrap() = nil, expected non-nil")
				} else if unwrapped.Error() != tt.expectedMsg {
					t.Errorf("Unwrap().Error() = %q, expected %q", unwrapped.Error(), tt.expectedMsg)
				}
			}
		})
	}
}

func TestErrStoreFailed_ErrorsIs(t *testing.T) {
	innerErr := errors.New("connection refused")
	storeErr := ErrStoreFailed{Operation: "GetQuota", Err: innerErr}

	if !errors.Is(storeErr, innerErr) {
		t.Error("errors.Is should return true for wrapped error")
	}
}

func TestErrTenantNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTenantNotFound
		expected string
	}{
		{
			name:     "uuid_tenant",
			err:      ErrTenantNotFound{TenantID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "quota: tenant not found: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "simple_tenant",
			err:      ErrTenantNotFound{TenantID: "tenant-abc"},
			expected: "quota: tenant not found: tenant-abc",
		},
		{
			name:     "empty_tenant",
			err:      ErrTenantNotFound{TenantID: ""},
			expected: "quota: tenant not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrInvalidAmount_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidAmount
		expected string
	}{
		{
			name: "negative_amount",
			err: ErrInvalidAmount{
				Resource: ResourceVMs,
				Amount:   -5,
			},
			expected: "quota: invalid amount -5 for resource vms",
		},
		{
			name: "zero_amount_when_positive_required",
			err: ErrInvalidAmount{
				Resource: ResourceMemory,
				Amount:   0,
			},
			expected: "quota: invalid amount 0 for resource memory",
		},
		{
			name: "large_negative",
			err: ErrInvalidAmount{
				Resource: ResourceDisk,
				Amount:   -1000000,
			},
			expected: "quota: invalid amount -1000000 for resource disk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrNilStore_Error(t *testing.T) {
	err := ErrNilStore{}
	expected := "quota: store is nil"
	if err.Error() != expected {
		t.Errorf("Error() = %q, expected %q", err.Error(), expected)
	}
}

func TestErrNilLogger_Error(t *testing.T) {
	err := ErrNilLogger{}
	expected := "quota: logger is nil"
	if err.Error() != expected {
		t.Errorf("Error() = %q, expected %q", err.Error(), expected)
	}
}

func TestErrReservationAlreadyCommitted_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrReservationAlreadyCommitted
		expected string
	}{
		{
			name:     "uuid_id",
			err:      ErrReservationAlreadyCommitted{ID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "quota: reservation already committed: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "simple_id",
			err:      ErrReservationAlreadyCommitted{ID: "res-789"},
			expected: "quota: reservation already committed: res-789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestErrorTypeAssertions(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		checkFunc func(error) bool
	}{
		{
			name: "quota_exceeded_type_assertion",
			err:  ErrQuotaExceeded{TenantID: "t1", Resource: ResourceVMs, Requested: 10, Available: 5},
			checkFunc: func(e error) bool {
				var target ErrQuotaExceeded
				return errors.As(e, &target)
			},
		},
		{
			name: "reservation_not_found_type_assertion",
			err:  ErrReservationNotFound{ID: "r1"},
			checkFunc: func(e error) bool {
				var target ErrReservationNotFound
				return errors.As(e, &target)
			},
		},
		{
			name: "reservation_expired_type_assertion",
			err:  ErrReservationExpired{ID: "r1"},
			checkFunc: func(e error) bool {
				var target ErrReservationExpired
				return errors.As(e, &target)
			},
		},
		{
			name: "invalid_resource_type_assertion",
			err:  ErrInvalidResource{Resource: ResourceType("bad")},
			checkFunc: func(e error) bool {
				var target ErrInvalidResource
				return errors.As(e, &target)
			},
		},
		{
			name: "store_failed_type_assertion",
			err:  ErrStoreFailed{Operation: "op", Err: errors.New("inner")},
			checkFunc: func(e error) bool {
				var target ErrStoreFailed
				return errors.As(e, &target)
			},
		},
		{
			name: "tenant_not_found_type_assertion",
			err:  ErrTenantNotFound{TenantID: "t1"},
			checkFunc: func(e error) bool {
				var target ErrTenantNotFound
				return errors.As(e, &target)
			},
		},
		{
			name: "invalid_amount_type_assertion",
			err:  ErrInvalidAmount{Resource: ResourceVMs, Amount: -1},
			checkFunc: func(e error) bool {
				var target ErrInvalidAmount
				return errors.As(e, &target)
			},
		},
		{
			name: "nil_store_type_assertion",
			err:  ErrNilStore{},
			checkFunc: func(e error) bool {
				var target ErrNilStore
				return errors.As(e, &target)
			},
		},
		{
			name: "nil_logger_type_assertion",
			err:  ErrNilLogger{},
			checkFunc: func(e error) bool {
				var target ErrNilLogger
				return errors.As(e, &target)
			},
		},
		{
			name: "reservation_already_committed_type_assertion",
			err:  ErrReservationAlreadyCommitted{ID: "r1"},
			checkFunc: func(e error) bool {
				var target ErrReservationAlreadyCommitted
				return errors.As(e, &target)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.checkFunc(tt.err) {
				t.Error("type assertion failed")
			}
		})
	}
}

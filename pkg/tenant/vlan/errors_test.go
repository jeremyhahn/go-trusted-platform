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

package vlan

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrVLANRangeExhausted_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrVLANRangeExhausted
		expected string
	}{
		{
			name:     "standard range",
			err:      &ErrVLANRangeExhausted{Start: 100, End: 4000},
			expected: "VLAN range exhausted: no available range in 100-4000",
		},
		{
			name:     "min values",
			err:      &ErrVLANRangeExhausted{Start: 1, End: 1},
			expected: "VLAN range exhausted: no available range in 1-1",
		},
		{
			name:     "max values",
			err:      &ErrVLANRangeExhausted{Start: 4094, End: 4094},
			expected: "VLAN range exhausted: no available range in 4094-4094",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrVLANInUse_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrVLANInUse
		expected string
	}{
		{
			name:     "standard usage",
			err:      &ErrVLANInUse{VLAN: 100, TenantID: "tenant-1"},
			expected: "VLAN 100 is already in use by tenant tenant-1",
		},
		{
			name:     "min vlan",
			err:      &ErrVLANInUse{VLAN: 1, TenantID: "test"},
			expected: "VLAN 1 is already in use by tenant test",
		},
		{
			name:     "max vlan",
			err:      &ErrVLANInUse{VLAN: 4094, TenantID: "prod"},
			expected: "VLAN 4094 is already in use by tenant prod",
		},
		{
			name:     "empty tenant id",
			err:      &ErrVLANInUse{VLAN: 500, TenantID: ""},
			expected: "VLAN 500 is already in use by tenant ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrVLANOutOfRange_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrVLANOutOfRange
		expected string
	}{
		{
			name:     "below range",
			err:      &ErrVLANOutOfRange{VLAN: 0, Min: 1, Max: 4094},
			expected: "VLAN 0 is outside valid range 1-4094",
		},
		{
			name:     "above range",
			err:      &ErrVLANOutOfRange{VLAN: 4095, Min: 1, Max: 4094},
			expected: "VLAN 4095 is outside valid range 1-4094",
		},
		{
			name:     "custom range",
			err:      &ErrVLANOutOfRange{VLAN: 50, Min: 100, Max: 200},
			expected: "VLAN 50 is outside valid range 100-200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidVLANRange_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrInvalidVLANRange
		expected string
	}{
		{
			name:     "start exceeds end",
			err:      &ErrInvalidVLANRange{Start: 200, End: 100, Reason: "start exceeds end"},
			expected: "invalid VLAN range 200-100: start exceeds end",
		},
		{
			name:     "below minimum",
			err:      &ErrInvalidVLANRange{Start: 0, End: 100, Reason: "start below minimum"},
			expected: "invalid VLAN range 0-100: start below minimum",
		},
		{
			name:     "above maximum",
			err:      &ErrInvalidVLANRange{Start: 100, End: 5000, Reason: "end exceeds maximum"},
			expected: "invalid VLAN range 100-5000: end exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrVLANRangeOverlap_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrVLANRangeOverlap
		expected string
	}{
		{
			name: "standard overlap",
			err: &ErrVLANRangeOverlap{
				Existing:  Range{Start: 100, End: 200},
				Requested: Range{Start: 150, End: 250},
			},
			expected: "VLAN range 150-250 overlaps with existing allocation 100-200",
		},
		{
			name: "exact overlap",
			err: &ErrVLANRangeOverlap{
				Existing:  Range{Start: 100, End: 200},
				Requested: Range{Start: 100, End: 200},
			},
			expected: "VLAN range 100-200 overlaps with existing allocation 100-200",
		},
		{
			name: "single vlan overlap",
			err: &ErrVLANRangeOverlap{
				Existing:  Range{Start: 100, End: 100},
				Requested: Range{Start: 100, End: 100},
			},
			expected: "VLAN range 100-100 overlaps with existing allocation 100-100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrTenantVLANNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrTenantVLANNotFound
		expected string
	}{
		{
			name:     "standard tenant",
			err:      &ErrTenantVLANNotFound{TenantID: "tenant-123"},
			expected: "no VLAN allocation found for tenant tenant-123",
		},
		{
			name:     "uuid tenant",
			err:      &ErrTenantVLANNotFound{TenantID: "550e8400-e29b-41d4-a716-446655440000"},
			expected: "no VLAN allocation found for tenant 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "empty tenant",
			err:      &ErrTenantVLANNotFound{TenantID: ""},
			expected: "no VLAN allocation found for tenant ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrStoreFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrStoreFailed
		expected string
	}{
		{
			name:     "save operation",
			err:      &ErrStoreFailed{Operation: "SaveAllocation", Err: errors.New("connection refused")},
			expected: "store operation SaveAllocation failed: connection refused",
		},
		{
			name:     "get operation",
			err:      &ErrStoreFailed{Operation: "GetAllocation", Err: errors.New("not found")},
			expected: "store operation GetAllocation failed: not found",
		},
		{
			name:     "delete operation",
			err:      &ErrStoreFailed{Operation: "DeleteAllocation", Err: errors.New("timeout")},
			expected: "store operation DeleteAllocation failed: timeout",
		},
		{
			name:     "nil underlying error",
			err:      &ErrStoreFailed{Operation: "ListAllocations", Err: nil},
			expected: "store operation ListAllocations failed: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrStoreFailed_Unwrap(t *testing.T) {
	t.Run("unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &ErrStoreFailed{Operation: "test", Err: underlying}

		got := err.Unwrap()
		if got != underlying {
			t.Errorf("Unwrap() = %v, want %v", got, underlying)
		}
	})

	t.Run("unwrap returns nil for nil error", func(t *testing.T) {
		err := &ErrStoreFailed{Operation: "test", Err: nil}

		got := err.Unwrap()
		if got != nil {
			t.Errorf("Unwrap() = %v, want nil", got)
		}
	})

	t.Run("errors.Is works with wrapped error", func(t *testing.T) {
		underlying := fmt.Errorf("wrapped: %w", errors.New("base error"))
		err := &ErrStoreFailed{Operation: "test", Err: underlying}

		if !errors.Is(err, underlying) {
			t.Error("errors.Is should find underlying error")
		}
	})

	t.Run("errors.Unwrap chain", func(t *testing.T) {
		baseErr := errors.New("base")
		wrapErr := fmt.Errorf("wrap: %w", baseErr)
		storeErr := &ErrStoreFailed{Operation: "test", Err: wrapErr}

		// First unwrap gets the wrapped error
		unwrapped := errors.Unwrap(storeErr)
		if unwrapped != wrapErr {
			t.Errorf("first unwrap = %v, want %v", unwrapped, wrapErr)
		}

		// Second unwrap gets the base error
		unwrapped2 := errors.Unwrap(unwrapped)
		if unwrapped2 != baseErr {
			t.Errorf("second unwrap = %v, want %v", unwrapped2, baseErr)
		}
	})
}

func TestErrNilStore_Error(t *testing.T) {
	t.Run("returns correct message", func(t *testing.T) {
		err := &ErrNilStore{}
		expected := "store cannot be nil"
		got := err.Error()
		if got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
	})
}

func TestErrNilConfig_Error(t *testing.T) {
	t.Run("returns correct message", func(t *testing.T) {
		err := &ErrNilConfig{}
		expected := "configuration cannot be nil"
		got := err.Error()
		if got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
	})
}

func TestErrEmptyTenantID_Error(t *testing.T) {
	t.Run("returns correct message", func(t *testing.T) {
		err := &ErrEmptyTenantID{}
		expected := "tenant ID cannot be empty"
		got := err.Error()
		if got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
	})
}

func TestErrTenantAlreadyAllocated_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrTenantAlreadyAllocated
		expected string
	}{
		{
			name:     "standard allocation",
			err:      &ErrTenantAlreadyAllocated{TenantID: "tenant-1", Range: Range{Start: 100, End: 199}},
			expected: "tenant tenant-1 already has VLAN allocation 100-199",
		},
		{
			name:     "single vlan allocation",
			err:      &ErrTenantAlreadyAllocated{TenantID: "tenant-2", Range: Range{Start: 500, End: 500}},
			expected: "tenant tenant-2 already has VLAN allocation 500-500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidRangeSize_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrInvalidRangeSize
		expected string
	}{
		{
			name:     "standard case",
			err:      &ErrInvalidRangeSize{Requested: 1000, Available: 500},
			expected: "requested range size 1000 exceeds available space 500",
		},
		{
			name:     "edge case",
			err:      &ErrInvalidRangeSize{Requested: 4094, Available: 0},
			expected: "requested range size 4094 exceeds available space 0",
		},
		{
			name:     "one more than available",
			err:      &ErrInvalidRangeSize{Requested: 101, Available: 100},
			expected: "requested range size 101 exceeds available space 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	// Ensure all error types implement the error interface
	var _ error = &ErrVLANRangeExhausted{}
	var _ error = &ErrVLANInUse{}
	var _ error = &ErrVLANOutOfRange{}
	var _ error = &ErrInvalidVLANRange{}
	var _ error = &ErrVLANRangeOverlap{}
	var _ error = &ErrTenantVLANNotFound{}
	var _ error = &ErrStoreFailed{}
	var _ error = &ErrNilStore{}
	var _ error = &ErrNilConfig{}
	var _ error = &ErrEmptyTenantID{}
	var _ error = &ErrTenantAlreadyAllocated{}
	var _ error = &ErrInvalidRangeSize{}
}

func TestErrorTypeAssertions(t *testing.T) {
	t.Run("ErrVLANRangeExhausted type assertion", func(t *testing.T) {
		var err error = &ErrVLANRangeExhausted{Start: 100, End: 200}
		if _, ok := err.(*ErrVLANRangeExhausted); !ok {
			t.Error("type assertion failed for ErrVLANRangeExhausted")
		}
	})

	t.Run("ErrVLANInUse type assertion", func(t *testing.T) {
		var err error = &ErrVLANInUse{VLAN: 100, TenantID: "test"}
		if _, ok := err.(*ErrVLANInUse); !ok {
			t.Error("type assertion failed for ErrVLANInUse")
		}
	})

	t.Run("ErrStoreFailed type assertion and access fields", func(t *testing.T) {
		underlying := errors.New("test error")
		var err error = &ErrStoreFailed{Operation: "Save", Err: underlying}

		storeErr, ok := err.(*ErrStoreFailed)
		if !ok {
			t.Fatal("type assertion failed for ErrStoreFailed")
		}
		if storeErr.Operation != "Save" {
			t.Errorf("Operation = %q, want %q", storeErr.Operation, "Save")
		}
		if storeErr.Err != underlying {
			t.Error("Err field mismatch")
		}
	})

	t.Run("ErrVLANRangeOverlap access fields", func(t *testing.T) {
		var err error = &ErrVLANRangeOverlap{
			Existing:  Range{Start: 100, End: 200},
			Requested: Range{Start: 150, End: 250},
		}

		overlapErr, ok := err.(*ErrVLANRangeOverlap)
		if !ok {
			t.Fatal("type assertion failed for ErrVLANRangeOverlap")
		}
		if overlapErr.Existing.Start != 100 || overlapErr.Existing.End != 200 {
			t.Errorf("Existing = %v, want {100, 200}", overlapErr.Existing)
		}
		if overlapErr.Requested.Start != 150 || overlapErr.Requested.End != 250 {
			t.Errorf("Requested = %v, want {150, 250}", overlapErr.Requested)
		}
	})
}

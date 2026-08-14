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
	"context"
	"testing"
	"time"
)

func TestRange_Contains(t *testing.T) {
	tests := []struct {
		name     string
		r        Range
		vlan     uint16
		expected bool
	}{
		{
			name:     "contains start",
			r:        Range{Start: 100, End: 200},
			vlan:     100,
			expected: true,
		},
		{
			name:     "contains end",
			r:        Range{Start: 100, End: 200},
			vlan:     200,
			expected: true,
		},
		{
			name:     "contains middle",
			r:        Range{Start: 100, End: 200},
			vlan:     150,
			expected: true,
		},
		{
			name:     "below range",
			r:        Range{Start: 100, End: 200},
			vlan:     99,
			expected: false,
		},
		{
			name:     "above range",
			r:        Range{Start: 100, End: 200},
			vlan:     201,
			expected: false,
		},
		{
			name:     "single vlan range",
			r:        Range{Start: 100, End: 100},
			vlan:     100,
			expected: true,
		},
		{
			name:     "single vlan range miss",
			r:        Range{Start: 100, End: 100},
			vlan:     101,
			expected: false,
		},
		{
			name:     "min VLAN boundary",
			r:        Range{Start: MinVLANID, End: 100},
			vlan:     MinVLANID,
			expected: true,
		},
		{
			name:     "max VLAN boundary",
			r:        Range{Start: 4000, End: MaxVLANID},
			vlan:     MaxVLANID,
			expected: true,
		},
		{
			name:     "zero VLAN",
			r:        Range{Start: 1, End: 100},
			vlan:     0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.Contains(tt.vlan)
			if got != tt.expected {
				t.Errorf("Contains(%d) = %v, want %v", tt.vlan, got, tt.expected)
			}
		})
	}
}

func TestRange_Size(t *testing.T) {
	tests := []struct {
		name     string
		r        Range
		expected int
	}{
		{
			name:     "standard range",
			r:        Range{Start: 100, End: 199},
			expected: 100,
		},
		{
			name:     "single vlan",
			r:        Range{Start: 100, End: 100},
			expected: 1,
		},
		{
			name:     "full range",
			r:        Range{Start: MinVLANID, End: MaxVLANID},
			expected: int(MaxVLANID - MinVLANID + 1),
		},
		{
			name:     "inverted range returns zero",
			r:        Range{Start: 200, End: 100},
			expected: 0,
		},
		{
			name:     "two vlans",
			r:        Range{Start: 100, End: 101},
			expected: 2,
		},
		{
			name:     "default allocation size",
			r:        Range{Start: 100, End: 199},
			expected: int(DefaultRangeSize),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.Size()
			if got != tt.expected {
				t.Errorf("Size() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestRange_Validate(t *testing.T) {
	tests := []struct {
		name        string
		r           Range
		expectError bool
		errorType   interface{}
	}{
		{
			name:        "valid range",
			r:           Range{Start: 100, End: 200},
			expectError: false,
		},
		{
			name:        "valid single vlan",
			r:           Range{Start: 100, End: 100},
			expectError: false,
		},
		{
			name:        "valid full range",
			r:           Range{Start: MinVLANID, End: MaxVLANID},
			expectError: false,
		},
		{
			name:        "start below minimum",
			r:           Range{Start: 0, End: 100},
			expectError: true,
			errorType:   &ErrInvalidVLANRange{},
		},
		{
			name:        "end above maximum",
			r:           Range{Start: 100, End: 4095},
			expectError: true,
			errorType:   &ErrInvalidVLANRange{},
		},
		{
			name:        "start exceeds end",
			r:           Range{Start: 200, End: 100},
			expectError: true,
			errorType:   &ErrInvalidVLANRange{},
		},
		{
			name:        "both below minimum",
			r:           Range{Start: 0, End: 0},
			expectError: true,
			errorType:   &ErrInvalidVLANRange{},
		},
		{
			name:        "both above maximum",
			r:           Range{Start: 5000, End: 6000},
			expectError: true,
			errorType:   &ErrInvalidVLANRange{},
		},
		{
			name:        "boundary minimum",
			r:           Range{Start: MinVLANID, End: MinVLANID},
			expectError: false,
		},
		{
			name:        "boundary maximum",
			r:           Range{Start: MaxVLANID, End: MaxVLANID},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorType != nil {
					// Type assertion to check error type
					if _, want := tt.errorType.(*ErrInvalidVLANRange); want {
						if _, ok := err.(*ErrInvalidVLANRange); !ok {
							t.Errorf("expected ErrInvalidVLANRange, got %T", err)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRange_Overlaps(t *testing.T) {
	tests := []struct {
		name     string
		r        Range
		other    Range
		expected bool
	}{
		{
			name:     "no overlap before",
			r:        Range{Start: 100, End: 199},
			other:    Range{Start: 200, End: 299},
			expected: false,
		},
		{
			name:     "no overlap after",
			r:        Range{Start: 200, End: 299},
			other:    Range{Start: 100, End: 199},
			expected: false,
		},
		{
			name:     "partial overlap start",
			r:        Range{Start: 100, End: 199},
			other:    Range{Start: 150, End: 250},
			expected: true,
		},
		{
			name:     "partial overlap end",
			r:        Range{Start: 150, End: 250},
			other:    Range{Start: 100, End: 199},
			expected: true,
		},
		{
			name:     "exact overlap",
			r:        Range{Start: 100, End: 199},
			other:    Range{Start: 100, End: 199},
			expected: true,
		},
		{
			name:     "contained range",
			r:        Range{Start: 100, End: 300},
			other:    Range{Start: 150, End: 250},
			expected: true,
		},
		{
			name:     "containing range",
			r:        Range{Start: 150, End: 250},
			other:    Range{Start: 100, End: 300},
			expected: true,
		},
		{
			name:     "single vlan overlap",
			r:        Range{Start: 100, End: 100},
			other:    Range{Start: 100, End: 100},
			expected: true,
		},
		{
			name:     "boundary touch start",
			r:        Range{Start: 100, End: 199},
			other:    Range{Start: 199, End: 299},
			expected: true,
		},
		{
			name:     "boundary touch end",
			r:        Range{Start: 199, End: 299},
			other:    Range{Start: 100, End: 199},
			expected: true,
		},
		{
			name:     "one apart no overlap",
			r:        Range{Start: 100, End: 198},
			other:    Range{Start: 199, End: 299},
			expected: false,
		},
		{
			name:     "symmetric test",
			r:        Range{Start: 100, End: 200},
			other:    Range{Start: 150, End: 250},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.Overlaps(tt.other)
			if got != tt.expected {
				t.Errorf("Overlaps(%v) = %v, want %v", tt.other, got, tt.expected)
			}
			// Verify symmetry
			gotReverse := tt.other.Overlaps(tt.r)
			if gotReverse != tt.expected {
				t.Errorf("Overlaps reverse(%v) = %v, want %v", tt.r, gotReverse, tt.expected)
			}
		})
	}
}

func TestRange_String(t *testing.T) {
	tests := []struct {
		name     string
		r        Range
		expected string
	}{
		{
			name:     "standard range",
			r:        Range{Start: 100, End: 199},
			expected: "100-199",
		},
		{
			name:     "single vlan",
			r:        Range{Start: 100, End: 100},
			expected: "100-100",
		},
		{
			name:     "full range",
			r:        Range{Start: MinVLANID, End: MaxVLANID},
			expected: "1-4094",
		},
		{
			name:     "zero values",
			r:        Range{Start: 0, End: 0},
			expected: "0-0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRange_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		r        Range
		expected bool
	}{
		{
			name:     "non-empty range",
			r:        Range{Start: 100, End: 199},
			expected: false,
		},
		{
			name:     "single vlan non-empty",
			r:        Range{Start: 100, End: 100},
			expected: false,
		},
		{
			name:     "empty inverted range",
			r:        Range{Start: 200, End: 100},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.IsEmpty()
			if got != tt.expected {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAllocation_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		alloc    *Allocation
		expected bool
	}{
		{
			name: "valid allocation",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: 100, End: 199},
				AllocatedAt: time.Now(),
			},
			expected: true,
		},
		{
			name:     "nil allocation",
			alloc:    nil,
			expected: false,
		},
		{
			name: "empty tenant id",
			alloc: &Allocation{
				TenantID:    "",
				Range:       Range{Start: 100, End: 199},
				AllocatedAt: time.Now(),
			},
			expected: false,
		},
		{
			name: "invalid range - start below min",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: 0, End: 100},
				AllocatedAt: time.Now(),
			},
			expected: false,
		},
		{
			name: "invalid range - end above max",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: 100, End: 5000},
				AllocatedAt: time.Now(),
			},
			expected: false,
		},
		{
			name: "invalid range - start exceeds end",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: 200, End: 100},
				AllocatedAt: time.Now(),
			},
			expected: false,
		},
		{
			name: "valid single vlan allocation",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: 100, End: 100},
				AllocatedAt: time.Now(),
			},
			expected: true,
		},
		{
			name: "valid boundary allocation min",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: MinVLANID, End: MinVLANID},
				AllocatedAt: time.Now(),
			},
			expected: true,
		},
		{
			name: "valid boundary allocation max",
			alloc: &Allocation{
				TenantID:    "tenant-1",
				Range:       Range{Start: MaxVLANID, End: MaxVLANID},
				AllocatedAt: time.Now(),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.alloc.IsValid()
			if got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAllocation_Contains(t *testing.T) {
	tests := []struct {
		name     string
		alloc    *Allocation
		vlan     uint16
		expected bool
	}{
		{
			name: "contains vlan",
			alloc: &Allocation{
				TenantID: "tenant-1",
				Range:    Range{Start: 100, End: 199},
			},
			vlan:     150,
			expected: true,
		},
		{
			name: "contains start",
			alloc: &Allocation{
				TenantID: "tenant-1",
				Range:    Range{Start: 100, End: 199},
			},
			vlan:     100,
			expected: true,
		},
		{
			name: "contains end",
			alloc: &Allocation{
				TenantID: "tenant-1",
				Range:    Range{Start: 100, End: 199},
			},
			vlan:     199,
			expected: true,
		},
		{
			name: "does not contain below",
			alloc: &Allocation{
				TenantID: "tenant-1",
				Range:    Range{Start: 100, End: 199},
			},
			vlan:     99,
			expected: false,
		},
		{
			name: "does not contain above",
			alloc: &Allocation{
				TenantID: "tenant-1",
				Range:    Range{Start: 100, End: 199},
			},
			vlan:     200,
			expected: false,
		},
		{
			name:     "nil allocation",
			alloc:    nil,
			vlan:     100,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.alloc.Contains(tt.vlan)
			if got != tt.expected {
				t.Errorf("Contains(%d) = %v, want %v", tt.vlan, got, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *Config
		expectError bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   4000,
				DefaultRangeSize: 100,
			},
			expectError: false,
		},
		{
			name: "valid minimal config",
			cfg: &Config{
				GlobalRangeStart: MinVLANID,
				GlobalRangeEnd:   MaxVLANID,
				DefaultRangeSize: 1,
			},
			expectError: false,
		},
		{
			name: "start below minimum",
			cfg: &Config{
				GlobalRangeStart: 0,
				GlobalRangeEnd:   4000,
				DefaultRangeSize: 100,
			},
			expectError: true,
		},
		{
			name: "end above maximum",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   5000,
				DefaultRangeSize: 100,
			},
			expectError: true,
		},
		{
			name: "start exceeds end",
			cfg: &Config{
				GlobalRangeStart: 4000,
				GlobalRangeEnd:   100,
				DefaultRangeSize: 100,
			},
			expectError: true,
		},
		{
			name: "zero default range size",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   4000,
				DefaultRangeSize: 0,
			},
			expectError: true,
		},
		{
			name: "default size exceeds global range",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   199,
				DefaultRangeSize: 200,
			},
			expectError: true,
		},
		{
			name: "default size equals global range",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   199,
				DefaultRangeSize: 100,
			},
			expectError: false,
		},
		{
			name: "single vlan global range with size 1",
			cfg: &Config{
				GlobalRangeStart: 100,
				GlobalRangeEnd:   100,
				DefaultRangeSize: 1,
			},
			expectError: false,
		},
		{
			name: "full range config",
			cfg: &Config{
				GlobalRangeStart: MinVLANID,
				GlobalRangeEnd:   MaxVLANID,
				DefaultRangeSize: DefaultRangeSize,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Run("returns non-nil config", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg == nil {
			t.Fatal("DefaultConfig() returned nil")
		}
	})

	t.Run("has expected values", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.GlobalRangeStart != 100 {
			t.Errorf("GlobalRangeStart = %d, want 100", cfg.GlobalRangeStart)
		}
		if cfg.GlobalRangeEnd != 4000 {
			t.Errorf("GlobalRangeEnd = %d, want 4000", cfg.GlobalRangeEnd)
		}
		if cfg.DefaultRangeSize != DefaultRangeSize {
			t.Errorf("DefaultRangeSize = %d, want %d", cfg.DefaultRangeSize, DefaultRangeSize)
		}
	})

	t.Run("default config validates", func(t *testing.T) {
		cfg := DefaultConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("DefaultConfig() validation failed: %v", err)
		}
	})
}

func TestConstants(t *testing.T) {
	t.Run("MinVLANID is 1", func(t *testing.T) {
		if MinVLANID != 1 {
			t.Errorf("MinVLANID = %d, want 1", MinVLANID)
		}
	})

	t.Run("MaxVLANID is 4094", func(t *testing.T) {
		if MaxVLANID != 4094 {
			t.Errorf("MaxVLANID = %d, want 4094", MaxVLANID)
		}
	})

	t.Run("DefaultRangeSize is 100", func(t *testing.T) {
		if DefaultRangeSize != 100 {
			t.Errorf("DefaultRangeSize = %d, want 100", DefaultRangeSize)
		}
	})
}

func TestStoreInterface(t *testing.T) {
	// Compile-time check that Store interface has the expected methods
	var _ Store = (*mockStoreForInterfaceTest)(nil)
}

// mockStoreForInterfaceTest is a minimal implementation to verify Store interface
type mockStoreForInterfaceTest struct{}

func (m *mockStoreForInterfaceTest) GetAllocation(_ context.Context, _ string) (*Allocation, error) {
	return nil, nil
}
func (m *mockStoreForInterfaceTest) SaveAllocation(_ context.Context, _ *Allocation) error {
	return nil
}
func (m *mockStoreForInterfaceTest) DeleteAllocation(_ context.Context, _ string) error {
	return nil
}
func (m *mockStoreForInterfaceTest) ListAllocations(_ context.Context) ([]*Allocation, error) {
	return nil, nil
}

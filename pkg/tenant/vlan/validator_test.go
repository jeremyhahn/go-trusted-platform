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
)

func setupValidatorTest(t *testing.T) (*Validator, *Allocator, *mockVLANStore) {
	t.Helper()
	store := newMockStore()
	cfg := DefaultConfig()
	alloc, err := NewAllocator(store, cfg, nil)
	if err != nil {
		t.Fatalf("failed to create allocator: %v", err)
	}
	validator := NewValidator(alloc, nil)
	return validator, alloc, store
}

func TestNewValidator(t *testing.T) {
	t.Run("creates validator with allocator", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		v := NewValidator(alloc, nil)
		if v == nil {
			t.Fatal("NewValidator returned nil")
		}
		if v.allocator != alloc {
			t.Error("validator allocator mismatch")
		}
	})

	t.Run("uses default logger when nil", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		v := NewValidator(alloc, nil)
		if v.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestValidator_ValidateTenantVLAN(t *testing.T) {
	t.Run("accepts valid VLAN in tenant range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidateTenantVLAN(ctx, "tenant-1", 150)
		if err != nil {
			t.Errorf("ValidateTenantVLAN failed: %v", err)
		}
	})

	t.Run("accepts VLAN at range start", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidateTenantVLAN(ctx, "tenant-1", 100)
		if err != nil {
			t.Errorf("ValidateTenantVLAN failed: %v", err)
		}
	})

	t.Run("accepts VLAN at range end", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidateTenantVLAN(ctx, "tenant-1", 199)
		if err != nil {
			t.Errorf("ValidateTenantVLAN failed: %v", err)
		}
	})

	t.Run("rejects empty tenant ID", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateTenantVLAN(context.Background(), "", 100)
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("rejects VLAN below minimum", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateTenantVLAN(context.Background(), "tenant-1", 0)
		if err == nil {
			t.Fatal("expected error for VLAN 0")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("rejects VLAN above maximum", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateTenantVLAN(context.Background(), "tenant-1", 4095)
		if err == nil {
			t.Fatal("expected error for VLAN 4095")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("rejects VLAN for tenant without allocation", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateTenantVLAN(context.Background(), "no-allocation", 100)
		if err == nil {
			t.Fatal("expected error for tenant without allocation")
		}
	})

	t.Run("rejects VLAN outside tenant range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidateTenantVLAN(ctx, "tenant-1", 200)
		if err == nil {
			t.Fatal("expected error for VLAN outside tenant range")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("rejects VLAN belonging to another tenant", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 200-299

		err := v.ValidateTenantVLAN(ctx, "tenant-1", 250)
		if err == nil {
			t.Fatal("expected error for VLAN belonging to another tenant")
		}
		if vlanInUse, ok := err.(*ErrVLANInUse); ok {
			if vlanInUse.TenantID != "tenant-2" {
				t.Errorf("expected owner tenant-2, got %s", vlanInUse.TenantID)
			}
		}
	})

	t.Run("handles VLAN boundary 1", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: MinVLANID,
			GlobalRangeEnd:   MaxVLANID,
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)
		v := NewValidator(alloc, nil)
		ctx := context.Background()

		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: MinVLANID, End: 100}); allocErr != nil {
			t.Fatalf("AllocateSpecific failed: %v", allocErr)
		}

		err := v.ValidateTenantVLAN(ctx, "tenant-1", MinVLANID)
		if err != nil {
			t.Errorf("ValidateTenantVLAN at MinVLANID failed: %v", err)
		}
	})

	t.Run("handles VLAN boundary 4094", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: MinVLANID,
			GlobalRangeEnd:   MaxVLANID,
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)
		v := NewValidator(alloc, nil)
		ctx := context.Background()

		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 4000, End: MaxVLANID}); allocErr != nil {
			t.Fatalf("AllocateSpecific failed: %v", allocErr)
		}

		err := v.ValidateTenantVLAN(ctx, "tenant-1", MaxVLANID)
		if err != nil {
			t.Errorf("ValidateTenantVLAN at MaxVLANID failed: %v", err)
		}
	})
}

func TestValidator_ValidatePortVLAN(t *testing.T) {
	t.Run("accepts valid port VLAN", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidatePortVLAN(ctx, "tenant-1", 150)
		if err != nil {
			t.Errorf("ValidatePortVLAN failed: %v", err)
		}
	})

	t.Run("rejects empty tenant ID", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidatePortVLAN(context.Background(), "", 100)
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("rejects invalid VLAN", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidatePortVLAN(context.Background(), "tenant-1", 0)
		if err == nil {
			t.Fatal("expected error for invalid VLAN")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}

		err = v.ValidatePortVLAN(context.Background(), "tenant-1", 4095)
		if err == nil {
			t.Fatal("expected error for invalid VLAN 4095")
		}
	})

	t.Run("rejects port VLAN for tenant without allocation", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidatePortVLAN(context.Background(), "no-allocation", 100)
		if err == nil {
			t.Fatal("expected error for tenant without allocation")
		}
	})

	t.Run("rejects port VLAN outside tenant range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.ValidatePortVLAN(ctx, "tenant-1", 300)
		if err == nil {
			t.Fatal("expected error for VLAN outside tenant range")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})
}

func TestValidator_ValidateRange(t *testing.T) {
	t.Run("accepts valid range within global bounds", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.ValidateRange(ctx, Range{Start: 500, End: 599})
		if err != nil {
			t.Errorf("ValidateRange failed: %v", err)
		}
	})

	t.Run("rejects invalid range start > end", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.ValidateRange(ctx, Range{Start: 200, End: 100})
		if err == nil {
			t.Fatal("expected error for invalid range")
		}
		if _, ok := err.(*ErrInvalidVLANRange); !ok {
			t.Errorf("expected ErrInvalidVLANRange, got %T", err)
		}
	})

	t.Run("rejects range start below global range", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		// Default config has global range 100-4000
		err := v.ValidateRange(ctx, Range{Start: 50, End: 150})
		if err == nil {
			t.Fatal("expected error for range below global")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("rejects range end above global range", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		// Default config has global range 100-4000
		err := v.ValidateRange(ctx, Range{Start: 3900, End: 4050})
		if err == nil {
			t.Fatal("expected error for range above global")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("rejects range below minimum VLAN", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.ValidateRange(ctx, Range{Start: 0, End: 100})
		if err == nil {
			t.Fatal("expected error for range below minimum")
		}
	})

	t.Run("rejects range above maximum VLAN", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.ValidateRange(ctx, Range{Start: 100, End: 5000})
		if err == nil {
			t.Fatal("expected error for range above maximum")
		}
	})

	t.Run("accepts range at global boundaries", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		// Global range is 100-4000
		err := v.ValidateRange(ctx, Range{Start: 100, End: 4000})
		if err != nil {
			t.Errorf("ValidateRange at global boundaries failed: %v", err)
		}
	})
}

func TestValidator_CheckOverlap(t *testing.T) {
	t.Run("no overlap with empty allocations", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.CheckOverlap(ctx, "", Range{Start: 100, End: 199})
		if err != nil {
			t.Errorf("CheckOverlap failed: %v", err)
		}
	})

	t.Run("no overlap with non-overlapping allocation", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.CheckOverlap(ctx, "", Range{Start: 300, End: 399})
		if err != nil {
			t.Errorf("CheckOverlap failed: %v", err)
		}
	})

	t.Run("detects overlap with existing allocation", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		err := v.CheckOverlap(ctx, "", Range{Start: 150, End: 249})
		if err == nil {
			t.Fatal("expected overlap error")
		}
		if _, ok := err.(*ErrVLANRangeOverlap); !ok {
			t.Errorf("expected ErrVLANRangeOverlap, got %T", err)
		}
	})

	t.Run("excludes own tenant from overlap check", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		// When expanding tenant-1's range, exclude their current allocation
		err := v.CheckOverlap(ctx, "tenant-1", Range{Start: 100, End: 299})
		if err != nil {
			t.Errorf("CheckOverlap should exclude own tenant: %v", err)
		}
	})

	t.Run("detects overlap with other tenant when expanding", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 200-299

		// tenant-1 expanding would overlap with tenant-2
		err := v.CheckOverlap(ctx, "tenant-1", Range{Start: 100, End: 250})
		if err == nil {
			t.Fatal("expected overlap error with other tenant")
		}
	})

	t.Run("rejects invalid range", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		err := v.CheckOverlap(ctx, "", Range{Start: 200, End: 100})
		if err == nil {
			t.Fatal("expected error for invalid range")
		}
	})

	t.Run("handles multiple allocations", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 200-299
		if _, allocErr := alloc.Allocate(ctx, "tenant-3", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 300-399

		// No overlap
		err := v.CheckOverlap(ctx, "", Range{Start: 500, End: 599})
		if err != nil {
			t.Errorf("CheckOverlap failed: %v", err)
		}

		// Overlap with tenant-2
		err = v.CheckOverlap(ctx, "", Range{Start: 250, End: 350})
		if err == nil {
			t.Fatal("expected overlap error")
		}
	})
}

func TestValidator_IsVLANAvailable(t *testing.T) {
	t.Run("available VLAN", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		if !v.IsVLANAvailable(ctx, 500) {
			t.Error("VLAN 500 should be available")
		}
	})

	t.Run("unavailable VLAN", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		if v.IsVLANAvailable(ctx, 150) {
			t.Error("VLAN 150 should not be available")
		}
	})

	t.Run("invalid VLAN returns false", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		if v.IsVLANAvailable(ctx, 0) {
			t.Error("VLAN 0 should not be available")
		}
		if v.IsVLANAvailable(ctx, 4095) {
			t.Error("VLAN 4095 should not be available")
		}
	})

	t.Run("boundary VLANs", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: MinVLANID,
			GlobalRangeEnd:   MaxVLANID,
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)
		v := NewValidator(alloc, nil)
		ctx := context.Background()

		if !v.IsVLANAvailable(ctx, MinVLANID) {
			t.Errorf("MinVLANID (%d) should be available", MinVLANID)
		}
		if !v.IsVLANAvailable(ctx, MaxVLANID) {
			t.Errorf("MaxVLANID (%d) should be available", MaxVLANID)
		}
	})
}

func TestValidator_IsRangeAvailable(t *testing.T) {
	t.Run("available range", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)
		ctx := context.Background()

		if !v.IsRangeAvailable(ctx, Range{Start: 500, End: 599}) {
			t.Error("range should be available")
		}
	})

	t.Run("unavailable range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		if v.IsRangeAvailable(ctx, Range{Start: 150, End: 249}) {
			t.Error("range should not be available")
		}
	})

	t.Run("partial overlap", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		if v.IsRangeAvailable(ctx, Range{Start: 199, End: 299}) {
			t.Error("range with partial overlap should not be available")
		}
	})
}

func TestValidator_GetTenantForVLAN(t *testing.T) {
	t.Run("returns tenant for allocated VLAN", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		tenant, err := v.GetTenantForVLAN(ctx, 150)
		if err != nil {
			t.Fatalf("GetTenantForVLAN failed: %v", err)
		}
		if tenant != "tenant-1" {
			t.Errorf("tenant = %s, want tenant-1", tenant)
		}
	})

	t.Run("returns empty for unallocated VLAN", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		tenant, err := v.GetTenantForVLAN(ctx, 500)
		if err != nil {
			t.Fatalf("GetTenantForVLAN failed: %v", err)
		}
		if tenant != "" {
			t.Errorf("tenant = %s, want empty", tenant)
		}
	})

	t.Run("returns error for invalid VLAN", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		_, err := v.GetTenantForVLAN(context.Background(), 0)
		if err == nil {
			t.Error("expected error for invalid VLAN")
		}
	})
}

func TestValidator_ValidateVLANBoundary(t *testing.T) {
	t.Run("accepts VLANs within tenant range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		vlans := []uint16{100, 150, 199}
		err := v.ValidateVLANBoundary(ctx, "tenant-1", vlans)
		if err != nil {
			t.Errorf("ValidateVLANBoundary failed: %v", err)
		}
	})

	t.Run("rejects empty tenant ID", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateVLANBoundary(context.Background(), "", []uint16{100})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("rejects tenant without allocation", func(t *testing.T) {
		v, _, _ := setupValidatorTest(t)

		err := v.ValidateVLANBoundary(context.Background(), "no-allocation", []uint16{100})
		if err == nil {
			t.Fatal("expected error for tenant without allocation")
		}
	})

	t.Run("rejects VLAN outside tenant range", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199

		vlans := []uint16{100, 300, 199} // 300 is outside
		err := v.ValidateVLANBoundary(ctx, "tenant-1", vlans)
		if err == nil {
			t.Fatal("expected error for VLAN outside range")
		}
	})

	t.Run("detects VLAN belonging to another tenant", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 100-199
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		} // 200-299

		vlans := []uint16{100, 250} // 250 belongs to tenant-2
		err := v.ValidateVLANBoundary(ctx, "tenant-1", vlans)
		if err == nil {
			t.Fatal("expected error for VLAN belonging to another tenant")
		}
		if vlanInUse, ok := err.(*ErrVLANInUse); ok {
			if vlanInUse.TenantID != "tenant-2" {
				t.Errorf("expected owner tenant-2, got %s", vlanInUse.TenantID)
			}
		}
	})

	t.Run("accepts empty VLAN list", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		}

		err := v.ValidateVLANBoundary(ctx, "tenant-1", []uint16{})
		if err != nil {
			t.Errorf("ValidateVLANBoundary with empty list failed: %v", err)
		}
	})

	t.Run("handles nil VLAN list", func(t *testing.T) {
		v, alloc, _ := setupValidatorTest(t)
		ctx := context.Background()

		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate failed: %v", allocErr)
		}

		err := v.ValidateVLANBoundary(ctx, "tenant-1", nil)
		if err != nil {
			t.Errorf("ValidateVLANBoundary with nil list failed: %v", err)
		}
	})
}

func TestValidator_EdgeCases(t *testing.T) {
	t.Run("validate at VLAN boundaries 1 and 4094", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: MinVLANID,
			GlobalRangeEnd:   MaxVLANID,
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)
		v := NewValidator(alloc, nil)
		ctx := context.Background()

		// Allocate at boundaries
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-min", Range{Start: MinVLANID, End: 100}); allocErr != nil {
			t.Fatalf("AllocateSpecific failed: %v", allocErr)
		}
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-max", Range{Start: 4000, End: MaxVLANID}); allocErr != nil {
			t.Fatalf("AllocateSpecific failed: %v", allocErr)
		}

		// Validate at boundaries
		err := v.ValidateTenantVLAN(ctx, "tenant-min", MinVLANID)
		if err != nil {
			t.Errorf("validation at MinVLANID failed: %v", err)
		}

		err = v.ValidateTenantVLAN(ctx, "tenant-max", MaxVLANID)
		if err != nil {
			t.Errorf("validation at MaxVLANID failed: %v", err)
		}
	})

	t.Run("single VLAN allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   4000,
			DefaultRangeSize: 1,
		}
		alloc, _ := NewAllocator(store, cfg, nil)
		v := NewValidator(alloc, nil)
		ctx := context.Background()

		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 500, End: 500}); allocErr != nil {
			t.Fatalf("AllocateSpecific failed: %v", allocErr)
		}

		// Only VLAN 500 should be valid
		if err := v.ValidateTenantVLAN(ctx, "tenant-1", 500); err != nil {
			t.Errorf("single VLAN validation failed: %v", err)
		}

		if err := v.ValidateTenantVLAN(ctx, "tenant-1", 499); err == nil {
			t.Error("expected error for VLAN 499")
		}

		if err := v.ValidateTenantVLAN(ctx, "tenant-1", 501); err == nil {
			t.Error("expected error for VLAN 501")
		}
	})
}

func BenchmarkValidator_ValidateTenantVLAN(b *testing.B) {
	store := newMockStore()
	cfg := DefaultConfig()
	alloc, _ := NewAllocator(store, cfg, nil)
	v := NewValidator(alloc, nil)
	ctx := context.Background()

	if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
		b.Fatalf("Allocate setup failed: %v", allocErr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.ValidateTenantVLAN(ctx, "tenant-1", 150); err != nil {
			b.Errorf("ValidateTenantVLAN failed: %v", err)
		}
	}
}

func BenchmarkValidator_CheckOverlap(b *testing.B) {
	store := newMockStore()
	cfg := DefaultConfig()
	alloc, _ := NewAllocator(store, cfg, nil)
	v := NewValidator(alloc, nil)
	ctx := context.Background()

	// Create many allocations
	for i := 0; i < 20; i++ {
		if _, allocErr := alloc.Allocate(ctx, "tenant-"+string(rune('A'+i)), 100); allocErr != nil {
			b.Fatalf("Allocate setup failed: %v", allocErr)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.CheckOverlap(ctx, "", Range{Start: 3000, End: 3099}); err != nil {
			b.Errorf("CheckOverlap failed: %v", err)
		}
	}
}

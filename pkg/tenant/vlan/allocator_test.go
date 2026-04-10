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
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// mockVLANStore implements the Store interface for testing
type mockVLANStore struct {
	allocations map[string]*Allocation
	mu          sync.RWMutex

	// Error injection for testing error paths
	getError    error
	saveError   error
	deleteError error
	listError   error
}

func newMockStore() *mockVLANStore {
	return &mockVLANStore{
		allocations: make(map[string]*Allocation),
	}
}

func (m *mockVLANStore) GetAllocation(_ context.Context, tenantID string) (*Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getError != nil {
		return nil, m.getError
	}

	alloc, ok := m.allocations[tenantID]
	if !ok {
		return nil, nil
	}
	return alloc, nil
}

func (m *mockVLANStore) SaveAllocation(_ context.Context, alloc *Allocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.saveError != nil {
		return m.saveError
	}

	m.allocations[alloc.TenantID] = alloc
	return nil
}

func (m *mockVLANStore) DeleteAllocation(_ context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteError != nil {
		return m.deleteError
	}

	delete(m.allocations, tenantID)
	return nil
}

func (m *mockVLANStore) ListAllocations(_ context.Context) ([]*Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listError != nil {
		return nil, m.listError
	}

	result := make([]*Allocation, 0, len(m.allocations))
	for _, alloc := range m.allocations {
		result = append(result, alloc)
	}
	return result, nil
}

func (m *mockVLANStore) setGetError(err error)    { m.getError = err }
func (m *mockVLANStore) setSaveError(err error)   { m.saveError = err }
func (m *mockVLANStore) setDeleteError(err error) { m.deleteError = err }
func (m *mockVLANStore) setListError(err error)   { m.listError = err }

func (m *mockVLANStore) clearErrors() {
	m.getError = nil
	m.saveError = nil
	m.deleteError = nil
	m.listError = nil
}

func TestNewAllocator(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		logger := slog.Default()

		alloc, err := NewAllocator(store, cfg, logger)
		if err != nil {
			t.Fatalf("NewAllocator failed: %v", err)
		}
		if alloc == nil {
			t.Fatal("NewAllocator returned nil")
		}
		if alloc.GetGlobalRange().Start != cfg.GlobalRangeStart {
			t.Errorf("GlobalRangeStart = %d, want %d", alloc.GetGlobalRange().Start, cfg.GlobalRangeStart)
		}
		if alloc.GetGlobalRange().End != cfg.GlobalRangeEnd {
			t.Errorf("GlobalRangeEnd = %d, want %d", alloc.GetGlobalRange().End, cfg.GlobalRangeEnd)
		}
		if alloc.GetDefaultRangeSize() != cfg.DefaultRangeSize {
			t.Errorf("DefaultRangeSize = %d, want %d", alloc.GetDefaultRangeSize(), cfg.DefaultRangeSize)
		}
	})

	t.Run("nil store", func(t *testing.T) {
		cfg := DefaultConfig()
		_, err := NewAllocator(nil, cfg, nil)
		if err == nil {
			t.Fatal("expected error for nil store")
		}
		if _, ok := err.(*ErrNilStore); !ok {
			t.Errorf("expected ErrNilStore, got %T", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		store := newMockStore()
		_, err := NewAllocator(store, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		if _, ok := err.(*ErrNilConfig); !ok {
			t.Errorf("expected ErrNilConfig, got %T", err)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 0, // Invalid
			GlobalRangeEnd:   4000,
			DefaultRangeSize: 100,
		}
		_, err := NewAllocator(store, cfg, nil)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, err := NewAllocator(store, cfg, nil)
		if err != nil {
			t.Fatalf("NewAllocator failed: %v", err)
		}
		if alloc.logger == nil {
			t.Error("logger should not be nil")
		}
	})

	t.Run("loads existing allocations", func(t *testing.T) {
		store := newMockStore()
		store.allocations["tenant-1"] = &Allocation{
			TenantID:    "tenant-1",
			Range:       Range{Start: 100, End: 199},
			AllocatedAt: time.Now(),
		}

		cfg := DefaultConfig()
		alloc, err := NewAllocator(store, cfg, nil)
		if err != nil {
			t.Fatalf("NewAllocator failed: %v", err)
		}

		// Verify allocation was loaded
		got, err := alloc.Get(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if got.Range.Start != 100 || got.Range.End != 199 {
			t.Errorf("loaded allocation range = %v, want 100-199", got.Range)
		}
	})

	t.Run("store list error during init", func(t *testing.T) {
		store := newMockStore()
		store.setListError(errors.New("list failed"))
		cfg := DefaultConfig()

		_, err := NewAllocator(store, cfg, nil)
		if err == nil {
			t.Fatal("expected error when store fails")
		}
	})
}

func TestAllocator_Allocate(t *testing.T) {
	t.Run("allocate with default size", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		result, err := alloc.Allocate(ctx, "tenant-1", 0)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
		if result.TenantID != "tenant-1" {
			t.Errorf("TenantID = %s, want tenant-1", result.TenantID)
		}
		if result.Range.Size() != int(DefaultRangeSize) {
			t.Errorf("Range size = %d, want %d", result.Range.Size(), DefaultRangeSize)
		}
		if result.Range.Start != cfg.GlobalRangeStart {
			t.Errorf("Range start = %d, want %d", result.Range.Start, cfg.GlobalRangeStart)
		}
	})

	t.Run("allocate with custom size", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		result, err := alloc.Allocate(ctx, "tenant-1", 50)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
		if result.Range.Size() != 50 {
			t.Errorf("Range size = %d, want 50", result.Range.Size())
		}
	})

	t.Run("allocate assigns unique ranges", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		r1, _ := alloc.Allocate(ctx, "tenant-1", 100)
		r2, _ := alloc.Allocate(ctx, "tenant-2", 100)
		r3, _ := alloc.Allocate(ctx, "tenant-3", 100)

		// Verify non-overlapping
		if r1.Range.Overlaps(r2.Range) {
			t.Errorf("tenant-1 (%v) overlaps tenant-2 (%v)", r1.Range, r2.Range)
		}
		if r2.Range.Overlaps(r3.Range) {
			t.Errorf("tenant-2 (%v) overlaps tenant-3 (%v)", r2.Range, r3.Range)
		}
		if r1.Range.Overlaps(r3.Range) {
			t.Errorf("tenant-1 (%v) overlaps tenant-3 (%v)", r1.Range, r3.Range)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.Allocate(context.Background(), "", 100)
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("tenant already allocated", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, err := alloc.Allocate(ctx, "tenant-1", 100); err != nil {
			t.Fatalf("Allocate setup failed: %v", err)
		}
		_, err := alloc.Allocate(ctx, "tenant-1", 100)
		if err == nil {
			t.Fatal("expected error for already allocated tenant")
		}
		if _, ok := err.(*ErrTenantAlreadyAllocated); !ok {
			t.Errorf("expected ErrTenantAlreadyAllocated, got %T", err)
		}
	})

	t.Run("range exhausted", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   199, // Only 100 VLANs
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		_, err := alloc.Allocate(ctx, "tenant-2", 100)
		if err == nil {
			t.Fatal("expected error when range exhausted")
		}
		if _, ok := err.(*ErrVLANRangeExhausted); !ok {
			t.Errorf("expected ErrVLANRangeExhausted, got %T", err)
		}
	})

	t.Run("store save error", func(t *testing.T) {
		store := newMockStore()
		store.setSaveError(errors.New("save failed"))
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.Allocate(context.Background(), "tenant-1", 100)
		if err == nil {
			t.Fatal("expected error when store fails")
		}
		if _, ok := err.(*ErrStoreFailed); !ok {
			t.Errorf("expected ErrStoreFailed, got %T", err)
		}
	})

	t.Run("requested size larger than remaining", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   249, // 150 VLANs
			DefaultRangeSize: 50,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil { // Uses 100-199
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		_, err := alloc.Allocate(ctx, "tenant-2", 100)
		if err == nil {
			t.Fatal("expected error when requested size > remaining")
		}
	})
}

func TestAllocator_AllocateSpecific(t *testing.T) {
	t.Run("allocate specific range", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		requested := Range{Start: 200, End: 299}
		result, err := alloc.AllocateSpecific(ctx, "tenant-1", requested)
		if err != nil {
			t.Fatalf("AllocateSpecific failed: %v", err)
		}
		if result.Range != requested {
			t.Errorf("Range = %v, want %v", result.Range, requested)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.AllocateSpecific(context.Background(), "", Range{Start: 100, End: 199})
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.AllocateSpecific(context.Background(), "tenant-1", Range{Start: 200, End: 100})
		if err == nil {
			t.Fatal("expected error for invalid range")
		}
		if _, ok := err.(*ErrInvalidVLANRange); !ok {
			t.Errorf("expected ErrInvalidVLANRange, got %T", err)
		}
	})

	t.Run("range outside global bounds", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig() // 100-4000
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.AllocateSpecific(context.Background(), "tenant-1", Range{Start: 50, End: 149})
		if err == nil {
			t.Fatal("expected error for range outside global bounds")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("tenant already allocated", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 100, End: 199}); allocErr != nil {
			t.Fatalf("AllocateSpecific setup failed: %v", allocErr)
		}
		_, err := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 300, End: 399})
		if err == nil {
			t.Fatal("expected error for already allocated tenant")
		}
		if _, ok := err.(*ErrTenantAlreadyAllocated); !ok {
			t.Errorf("expected ErrTenantAlreadyAllocated, got %T", err)
		}
	})

	t.Run("range overlaps existing", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 100, End: 199}); allocErr != nil {
			t.Fatalf("AllocateSpecific setup failed: %v", allocErr)
		}
		_, err := alloc.AllocateSpecific(ctx, "tenant-2", Range{Start: 150, End: 249})
		if err == nil {
			t.Fatal("expected error for overlapping range")
		}
		if _, ok := err.(*ErrVLANRangeOverlap); !ok {
			t.Errorf("expected ErrVLANRangeOverlap, got %T", err)
		}
	})

	t.Run("store save error", func(t *testing.T) {
		store := newMockStore()
		store.setSaveError(errors.New("save failed"))
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.AllocateSpecific(context.Background(), "tenant-1", Range{Start: 100, End: 199})
		if err == nil {
			t.Fatal("expected error when store fails")
		}
		if _, ok := err.(*ErrStoreFailed); !ok {
			t.Errorf("expected ErrStoreFailed, got %T", err)
		}
	})

	t.Run("range end outside global bounds", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig() // 100-4000
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.AllocateSpecific(context.Background(), "tenant-1", Range{Start: 3900, End: 4050})
		if err == nil {
			t.Fatal("expected error for range end outside global bounds")
		}
	})
}

func TestAllocator_Release(t *testing.T) {
	t.Run("release existing allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		err := alloc.Release(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("Release failed: %v", err)
		}

		// Verify tenant no longer has allocation
		_, err = alloc.Get(ctx, "tenant-1")
		if err == nil {
			t.Error("expected error getting released allocation")
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		err := alloc.Release(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("release non-existent allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		err := alloc.Release(context.Background(), "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent tenant")
		}
		if _, ok := err.(*ErrTenantVLANNotFound); !ok {
			t.Errorf("expected ErrTenantVLANNotFound, got %T", err)
		}
	})

	t.Run("store delete error", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		store.setDeleteError(errors.New("delete failed"))

		err := alloc.Release(ctx, "tenant-1")
		if err == nil {
			t.Fatal("expected error when store fails")
		}
		if _, ok := err.(*ErrStoreFailed); !ok {
			t.Errorf("expected ErrStoreFailed, got %T", err)
		}
	})

	t.Run("released range becomes available", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   299, // Only 200 VLANs
			DefaultRangeSize: 100,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		result, _ := alloc.Allocate(ctx, "tenant-1", 100)
		originalRange := result.Range
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		// Release tenant-1
		if releaseErr := alloc.Release(ctx, "tenant-1"); releaseErr != nil {
			t.Fatalf("Release setup failed: %v", releaseErr)
		}

		// Allocate new tenant should get released range
		result, err := alloc.Allocate(ctx, "tenant-3", 100)
		if err != nil {
			t.Fatalf("Allocate after release failed: %v", err)
		}
		if result.Range != originalRange {
			t.Errorf("new allocation should use released range, got %v, want %v", result.Range, originalRange)
		}
	})
}

func TestAllocator_Get(t *testing.T) {
	t.Run("get existing allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		original, _ := alloc.Allocate(ctx, "tenant-1", 100)
		got, err := alloc.Get(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if got.TenantID != original.TenantID {
			t.Errorf("TenantID = %s, want %s", got.TenantID, original.TenantID)
		}
		if got.Range != original.Range {
			t.Errorf("Range = %v, want %v", got.Range, original.Range)
		}
	})

	t.Run("empty tenant ID", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty tenant ID")
		}
		if _, ok := err.(*ErrEmptyTenantID); !ok {
			t.Errorf("expected ErrEmptyTenantID, got %T", err)
		}
	})

	t.Run("get non-existent allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.Get(context.Background(), "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent tenant")
		}
		if _, ok := err.(*ErrTenantVLANNotFound); !ok {
			t.Errorf("expected ErrTenantVLANNotFound, got %T", err)
		}
	})

	t.Run("get loads from store if not in cache", func(t *testing.T) {
		store := newMockStore()
		// Pre-populate store directly
		store.allocations["tenant-1"] = &Allocation{
			TenantID:    "tenant-1",
			Range:       Range{Start: 500, End: 599},
			AllocatedAt: time.Now(),
		}
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		// Should be loaded during init, but let's verify Get works
		got, err := alloc.Get(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if got.Range.Start != 500 || got.Range.End != 599 {
			t.Errorf("Range = %v, want 500-599", got.Range)
		}
	})

	t.Run("store get error", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		// Clear the in-memory cache by creating a new allocation then releasing
		// Actually, we need to test when it's not in cache - set up store error after init
		store.setGetError(errors.New("get failed"))

		// Add allocation directly to store after init but not to allocator cache
		// This simulates the case where Get needs to fetch from store
		// Since allocator loads on init, we need another approach

		// Actually, let's test the error path directly by having an allocation
		// that's only in store (added after allocator init)
		store.clearErrors()
		store.allocations["tenant-2"] = &Allocation{
			TenantID:    "tenant-2",
			Range:       Range{Start: 600, End: 699},
			AllocatedAt: time.Now(),
		}

		// Now set error before Get
		store.setGetError(errors.New("get failed"))

		// Allocator doesn't have tenant-2 in cache, so it will try store
		// This should fail with store error
		_, err := alloc.Get(context.Background(), "tenant-2")
		if err == nil {
			t.Fatal("expected error when store fails")
		}
	})
}

func TestAllocator_GetByVLAN(t *testing.T) {
	t.Run("find tenant by VLAN", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil { // 100-199
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		tenantID, err := alloc.GetByVLAN(ctx, 150)
		if err != nil {
			t.Fatalf("GetByVLAN failed: %v", err)
		}
		if tenantID != "tenant-1" {
			t.Errorf("TenantID = %s, want tenant-1", tenantID)
		}
	})

	t.Run("VLAN not allocated", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil { // 100-199
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		tenantID, err := alloc.GetByVLAN(ctx, 300)
		if err != nil {
			t.Fatalf("GetByVLAN failed: %v", err)
		}
		if tenantID != "" {
			t.Errorf("TenantID = %s, want empty", tenantID)
		}
	})

	t.Run("VLAN out of valid range", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.GetByVLAN(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error for VLAN 0")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}

		_, err = alloc.GetByVLAN(context.Background(), 4095)
		if err == nil {
			t.Fatal("expected error for VLAN 4095")
		}
	})

	t.Run("VLAN outside global range", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   200,
			DefaultRangeSize: 50,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		_, err := alloc.GetByVLAN(context.Background(), 50)
		if err == nil {
			t.Fatal("expected error for VLAN outside global range")
		}
		if _, ok := err.(*ErrVLANOutOfRange); !ok {
			t.Errorf("expected ErrVLANOutOfRange, got %T", err)
		}
	})

	t.Run("find at boundary VLANs", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 100, End: 199}); allocErr != nil {
			t.Fatalf("AllocateSpecific setup failed: %v", allocErr)
		}

		// Test boundary VLANs
		tid, err := alloc.GetByVLAN(ctx, 100)
		if err != nil || tid != "tenant-1" {
			t.Errorf("GetByVLAN(100) = (%s, %v), want (tenant-1, nil)", tid, err)
		}

		tid, err = alloc.GetByVLAN(ctx, 199)
		if err != nil || tid != "tenant-1" {
			t.Errorf("GetByVLAN(199) = (%s, %v), want (tenant-1, nil)", tid, err)
		}
	})
}

func TestAllocator_IsAvailable(t *testing.T) {
	t.Run("available range", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if !alloc.IsAvailable(ctx, Range{Start: 500, End: 599}) {
			t.Error("range should be available")
		}
	})

	t.Run("unavailable range partial overlap", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil { // 100-199
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		if alloc.IsAvailable(ctx, Range{Start: 150, End: 249}) {
			t.Error("range should not be available (overlaps)")
		}
	})

	t.Run("unavailable range full overlap", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil { // 100-199
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		if alloc.IsAvailable(ctx, Range{Start: 100, End: 199}) {
			t.Error("range should not be available")
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if alloc.IsAvailable(ctx, Range{Start: 200, End: 100}) {
			t.Error("invalid range should not be available")
		}
	})

	t.Run("range outside global bounds", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig() // 100-4000
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if alloc.IsAvailable(ctx, Range{Start: 50, End: 99}) {
			t.Error("range outside global bounds should not be available")
		}
	})
}

func TestAllocator_ListAllocations(t *testing.T) {
	t.Run("list empty", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		list, err := alloc.ListAllocations(context.Background())
		if err != nil {
			t.Fatalf("ListAllocations failed: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("expected empty list, got %d items", len(list))
		}
	})

	t.Run("list with allocations", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if _, allocErr := alloc.Allocate(ctx, "tenant-3", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		list, err := alloc.ListAllocations(ctx)
		if err != nil {
			t.Fatalf("ListAllocations failed: %v", err)
		}
		if len(list) != 3 {
			t.Errorf("expected 3 allocations, got %d", len(list))
		}

		// Verify all tenants are present
		found := make(map[string]bool)
		for _, a := range list {
			found[a.TenantID] = true
		}
		for _, tid := range []string{"tenant-1", "tenant-2", "tenant-3"} {
			if !found[tid] {
				t.Errorf("tenant %s not found in list", tid)
			}
		}
	})
}

func TestAllocator_Reload(t *testing.T) {
	t.Run("reload refreshes state", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		// Directly modify store (simulating external change)
		store.allocations["tenant-2"] = &Allocation{
			TenantID:    "tenant-2",
			Range:       Range{Start: 500, End: 599},
			AllocatedAt: time.Now(),
		}

		// Reload should pick up tenant-2
		err := alloc.Reload(ctx)
		if err != nil {
			t.Fatalf("Reload failed: %v", err)
		}

		got, err := alloc.Get(ctx, "tenant-2")
		if err != nil {
			t.Fatalf("Get after reload failed: %v", err)
		}
		if got.Range.Start != 500 {
			t.Errorf("Range.Start = %d, want 500", got.Range.Start)
		}
	})

	t.Run("reload clears old state", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		// Remove from store
		delete(store.allocations, "tenant-1")

		// Reload should remove tenant-1
		if reloadErr := alloc.Reload(ctx); reloadErr != nil {
			t.Fatalf("Reload failed: %v", reloadErr)
		}

		_, err := alloc.Get(ctx, "tenant-1")
		if err == nil {
			t.Error("expected error for removed tenant")
		}
	})

	t.Run("reload with store error", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		store.setListError(errors.New("list failed"))
		err := alloc.Reload(context.Background())
		if err == nil {
			t.Fatal("expected error when store fails")
		}
	})

	t.Run("reload skips nil and empty allocations", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()

		// Add some invalid entries
		store.allocations[""] = &Allocation{
			TenantID: "",
			Range:    Range{Start: 100, End: 199},
		}
		store.allocations["valid"] = &Allocation{
			TenantID: "valid",
			Range:    Range{Start: 200, End: 299},
		}

		alloc, _ := NewAllocator(store, cfg, nil)

		// Should only have 1 valid allocation
		if alloc.GetAllocationCount() != 1 {
			t.Errorf("allocation count = %d, want 1", alloc.GetAllocationCount())
		}
	})
}

func TestAllocator_GetGlobalRange(t *testing.T) {
	store := newMockStore()
	cfg := &Config{
		GlobalRangeStart: 500,
		GlobalRangeEnd:   2000,
		DefaultRangeSize: 50,
	}
	alloc, _ := NewAllocator(store, cfg, nil)

	r := alloc.GetGlobalRange()
	if r.Start != 500 || r.End != 2000 {
		t.Errorf("GetGlobalRange() = %v, want {500, 2000}", r)
	}
}

func TestAllocator_GetDefaultRangeSize(t *testing.T) {
	store := newMockStore()
	cfg := &Config{
		GlobalRangeStart: 100,
		GlobalRangeEnd:   4000,
		DefaultRangeSize: 75,
	}
	alloc, _ := NewAllocator(store, cfg, nil)

	if size := alloc.GetDefaultRangeSize(); size != 75 {
		t.Errorf("GetDefaultRangeSize() = %d, want 75", size)
	}
}

func TestAllocator_GetAvailableCapacity(t *testing.T) {
	t.Run("full capacity initially", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   199, // 100 VLANs
			DefaultRangeSize: 50,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		if cap := alloc.GetAvailableCapacity(); cap != 100 {
			t.Errorf("GetAvailableCapacity() = %d, want 100", cap)
		}
	})

	t.Run("reduced after allocation", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   199, // 100 VLANs
			DefaultRangeSize: 50,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		if _, allocErr := alloc.Allocate(context.Background(), "tenant-1", 30); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		if cap := alloc.GetAvailableCapacity(); cap != 70 {
			t.Errorf("GetAvailableCapacity() = %d, want 70", cap)
		}
	})
}

func TestAllocator_GetAllocationCount(t *testing.T) {
	t.Run("zero initially", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		if count := alloc.GetAllocationCount(); count != 0 {
			t.Errorf("GetAllocationCount() = %d, want 0", count)
		}
	})

	t.Run("increases with allocations", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		if count := alloc.GetAllocationCount(); count != 2 {
			t.Errorf("GetAllocationCount() = %d, want 2", count)
		}
	})

	t.Run("decreases with release", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if _, allocErr := alloc.Allocate(ctx, "tenant-2", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if releaseErr := alloc.Release(ctx, "tenant-1"); releaseErr != nil {
			t.Fatalf("Release setup failed: %v", releaseErr)
		}

		if count := alloc.GetAllocationCount(); count != 1 {
			t.Errorf("GetAllocationCount() = %d, want 1", count)
		}
	})
}

func TestAllocator_ConcurrentAllocations(t *testing.T) {
	t.Run("concurrent allocate different tenants", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   4000,
			DefaultRangeSize: 10,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		var wg sync.WaitGroup
		concurrency := 50
		errors := make(chan error, concurrency)

		wg.Add(concurrency)
		for i := 0; i < concurrency; i++ {
			go func(idx int) {
				defer wg.Done()
				tenantID := "tenant-" + string(rune('A'+idx))
				_, err := alloc.Allocate(context.Background(), tenantID, 10)
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Errorf("concurrent allocation error: %v", err)
		}

		// Verify all allocations are unique
		list, _ := alloc.ListAllocations(context.Background())
		if len(list) != concurrency {
			t.Errorf("expected %d allocations, got %d", concurrency, len(list))
		}

		// Check for overlaps
		for i := 0; i < len(list); i++ {
			for j := i + 1; j < len(list); j++ {
				if list[i].Range.Overlaps(list[j].Range) {
					t.Errorf("overlapping ranges: %s=%v, %s=%v",
						list[i].TenantID, list[i].Range,
						list[j].TenantID, list[j].Range)
				}
			}
		}
	})

	t.Run("concurrent allocate and release", func(t *testing.T) {
		store := newMockStore()
		cfg := &Config{
			GlobalRangeStart: 100,
			GlobalRangeEnd:   500,
			DefaultRangeSize: 10,
		}
		alloc, _ := NewAllocator(store, cfg, nil)

		var wg sync.WaitGroup
		ctx := context.Background()

		// Pre-allocate some tenants
		for i := 0; i < 10; i++ {
			if _, allocErr := alloc.Allocate(ctx, "pre-tenant-"+string(rune('0'+i)), 10); allocErr != nil {
				t.Fatalf("Allocate setup failed: %v", allocErr)
			}
		}

		// Concurrent operations
		wg.Add(20)

		// Allocators
		for i := 0; i < 10; i++ {
			go func(idx int) {
				defer wg.Done()
				tenantID := "new-tenant-" + string(rune('A'+idx))
				if _, allocErr := alloc.Allocate(ctx, tenantID, 10); allocErr != nil {
					t.Errorf("Allocate setup failed: %v", allocErr)
				}
			}(i)
		}

		// Releasers
		for i := 0; i < 10; i++ {
			go func(idx int) {
				defer wg.Done()
				tenantID := "pre-tenant-" + string(rune('0'+idx))
				if releaseErr := alloc.Release(ctx, tenantID); releaseErr != nil {
					t.Errorf("Release setup failed: %v", releaseErr)
				}
			}(i)
		}

		wg.Wait()

		// Basic sanity check
		count := alloc.GetAllocationCount()
		if count < 0 || count > 20 {
			t.Errorf("unexpected allocation count: %d", count)
		}
	})

	t.Run("concurrent reads", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
			t.Fatalf("Allocate setup failed: %v", allocErr)
		}

		var wg sync.WaitGroup
		concurrency := 100

		wg.Add(concurrency)
		for i := 0; i < concurrency; i++ {
			go func() {
				defer wg.Done()
				if _, getErr := alloc.Get(ctx, "tenant-1"); getErr != nil {
					t.Errorf("Get failed: %v", getErr)
				}
				if _, vlanErr := alloc.GetByVLAN(ctx, 150); vlanErr != nil {
					t.Errorf("GetByVLAN failed: %v", vlanErr)
				}
				alloc.IsAvailable(ctx, Range{Start: 500, End: 599})
				if _, listErr := alloc.ListAllocations(ctx); listErr != nil {
					t.Errorf("ListAllocations failed: %v", listErr)
				}
			}()
		}

		wg.Wait()
	})
}

func TestAllocator_PreventOverlap(t *testing.T) {
	t.Run("prevent overlap between automatic allocations", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		allocations := make([]*Allocation, 0, 10)

		for i := 0; i < 10; i++ {
			a, err := alloc.Allocate(ctx, "tenant-"+string(rune('0'+i)), 100)
			if err != nil {
				t.Fatalf("allocation %d failed: %v", i, err)
			}
			allocations = append(allocations, a)
		}

		// Verify no overlaps
		for i := 0; i < len(allocations); i++ {
			for j := i + 1; j < len(allocations); j++ {
				if allocations[i].Range.Overlaps(allocations[j].Range) {
					t.Errorf("overlap detected: %s=%v, %s=%v",
						allocations[i].TenantID, allocations[i].Range,
						allocations[j].TenantID, allocations[j].Range)
				}
			}
		}
	})

	t.Run("prevent overlap between specific allocations", func(t *testing.T) {
		store := newMockStore()
		cfg := DefaultConfig()
		alloc, _ := NewAllocator(store, cfg, nil)

		ctx := context.Background()
		if _, allocErr := alloc.AllocateSpecific(ctx, "tenant-1", Range{Start: 100, End: 199}); allocErr != nil {
			t.Fatalf("AllocateSpecific setup failed: %v", allocErr)
		}

		// Try overlapping range
		_, err := alloc.AllocateSpecific(ctx, "tenant-2", Range{Start: 150, End: 249})
		if err == nil {
			t.Fatal("expected overlap error")
		}
		if _, ok := err.(*ErrVLANRangeOverlap); !ok {
			t.Errorf("expected ErrVLANRangeOverlap, got %T", err)
		}
	})
}

func BenchmarkAllocator_Allocate(b *testing.B) {
	store := newMockStore()
	cfg := &Config{
		GlobalRangeStart: 1,
		GlobalRangeEnd:   MaxVLANID,
		DefaultRangeSize: 10,
	}
	alloc, _ := NewAllocator(store, cfg, nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tenantID := "tenant-" + string(rune('A'+i%100))
		if _, allocErr := alloc.Allocate(ctx, tenantID, 10); allocErr != nil {
			b.Fatalf("Allocate setup failed: %v", allocErr)
		}
		if releaseErr := alloc.Release(ctx, tenantID); releaseErr != nil {
			b.Fatalf("Release setup failed: %v", releaseErr)
		}
	}
}

func BenchmarkAllocator_Get(b *testing.B) {
	store := newMockStore()
	cfg := DefaultConfig()
	alloc, _ := NewAllocator(store, cfg, nil)
	ctx := context.Background()

	if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
		b.Fatalf("Allocate setup failed: %v", allocErr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, getErr := alloc.Get(ctx, "tenant-1"); getErr != nil {
			b.Errorf("Get failed: %v", getErr)
		}
	}
}

func BenchmarkAllocator_GetByVLAN(b *testing.B) {
	store := newMockStore()
	cfg := DefaultConfig()
	alloc, _ := NewAllocator(store, cfg, nil)
	ctx := context.Background()

	if _, allocErr := alloc.Allocate(ctx, "tenant-1", 100); allocErr != nil {
		b.Fatalf("Allocate setup failed: %v", allocErr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, vlanErr := alloc.GetByVLAN(ctx, 150); vlanErr != nil {
			b.Errorf("GetByVLAN failed: %v", vlanErr)
		}
	}
}

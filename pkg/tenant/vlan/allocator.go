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
	"log/slog"
	"sync"
	"time"
)

// Allocator manages VLAN range allocation for tenants
type Allocator struct {
	store  Store
	logger *slog.Logger

	// Configuration
	globalRange Range  // e.g., 100-4000
	rangeSize   uint16 // Default size per tenant, e.g., 100

	// In-memory tracking
	mu        sync.RWMutex
	allocated map[string]Range // tenantID -> range
	usedVLANs *bitset          // Quick lookup of used VLANs
}

// NewAllocator creates a new VLAN allocator with the specified configuration
func NewAllocator(store Store, cfg *Config, logger *slog.Logger) (*Allocator, error) {
	if store == nil {
		return nil, &ErrNilStore{}
	}
	if cfg == nil {
		return nil, &ErrNilConfig{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	a := &Allocator{
		store:  store,
		logger: logger,
		globalRange: Range{
			Start: cfg.GlobalRangeStart,
			End:   cfg.GlobalRangeEnd,
		},
		rangeSize: cfg.DefaultRangeSize,
		allocated: make(map[string]Range),
		usedVLANs: newBitset(int(MaxVLANID) + 1),
	}

	// Load existing allocations from store
	if err := a.Reload(context.Background()); err != nil {
		return nil, err
	}

	return a, nil
}

// Allocate assigns a VLAN range to a tenant
// If requestedSize is 0, the default range size is used
func (a *Allocator) Allocate(ctx context.Context, tenantID string, requestedSize uint16) (*Allocation, error) {
	if tenantID == "" {
		return nil, &ErrEmptyTenantID{}
	}

	size := requestedSize
	if size == 0 {
		size = a.rangeSize
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if tenant already has an allocation
	if existing, ok := a.allocated[tenantID]; ok {
		return nil, &ErrTenantAlreadyAllocated{
			TenantID: tenantID,
			Range:    existing,
		}
	}

	// Find an available range
	start, found := a.usedVLANs.FindClearRange(a.globalRange.Start, a.globalRange.End, size)
	if !found {
		return nil, &ErrVLANRangeExhausted{
			Start: a.globalRange.Start,
			End:   a.globalRange.End,
		}
	}

	allocRange := Range{
		Start: start,
		End:   start + size - 1,
	}

	// Validate the range is within global bounds
	if allocRange.End > a.globalRange.End {
		return nil, &ErrVLANRangeExhausted{
			Start: a.globalRange.Start,
			End:   a.globalRange.End,
		}
	}

	alloc := &Allocation{
		TenantID:    tenantID,
		Range:       allocRange,
		AllocatedAt: time.Now().UTC(),
	}

	// Persist to store
	if err := a.store.SaveAllocation(ctx, alloc); err != nil {
		return nil, &ErrStoreFailed{
			Operation: "SaveAllocation",
			Err:       err,
		}
	}

	// Update in-memory state
	a.allocated[tenantID] = allocRange
	a.usedVLANs.SetRange(allocRange.Start, allocRange.End)

	a.logger.Info("allocated VLAN range",
		slog.String("tenant_id", tenantID),
		slog.String("range", allocRange.String()),
	)

	return alloc, nil
}

// AllocateSpecific assigns a specific VLAN range to a tenant
func (a *Allocator) AllocateSpecific(ctx context.Context, tenantID string, requested Range) (*Allocation, error) {
	if tenantID == "" {
		return nil, &ErrEmptyTenantID{}
	}

	if err := requested.Validate(); err != nil {
		return nil, err
	}

	// Check requested range is within global bounds
	if requested.Start < a.globalRange.Start || requested.End > a.globalRange.End {
		return nil, &ErrVLANOutOfRange{
			VLAN: requested.Start,
			Min:  a.globalRange.Start,
			Max:  a.globalRange.End,
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if tenant already has an allocation
	if existing, ok := a.allocated[tenantID]; ok {
		return nil, &ErrTenantAlreadyAllocated{
			TenantID: tenantID,
			Range:    existing,
		}
	}

	// Check for overlap with existing allocations
	for tid, existingRange := range a.allocated {
		if requested.Overlaps(existingRange) {
			return nil, &ErrVLANRangeOverlap{
				Existing:  existingRange,
				Requested: requested,
			}
		}
		// Also check via bitset for any partial overlaps
		_ = tid // Using tid in future logging if needed
	}

	// Verify the range is actually available in the bitset
	if !a.usedVLANs.TestRangeClear(requested.Start, requested.End) {
		// Find which allocation owns the overlapping VLAN
		for tid, existingRange := range a.allocated {
			if requested.Overlaps(existingRange) {
				return nil, &ErrVLANRangeOverlap{
					Existing:  existingRange,
					Requested: requested,
				}
			}
			_ = tid
		}
		// If we can't find the owner, return a generic overlap error
		return nil, &ErrVLANRangeOverlap{
			Existing:  Range{}, // Unknown
			Requested: requested,
		}
	}

	alloc := &Allocation{
		TenantID:    tenantID,
		Range:       requested,
		AllocatedAt: time.Now().UTC(),
	}

	// Persist to store
	if err := a.store.SaveAllocation(ctx, alloc); err != nil {
		return nil, &ErrStoreFailed{
			Operation: "SaveAllocation",
			Err:       err,
		}
	}

	// Update in-memory state
	a.allocated[tenantID] = requested
	a.usedVLANs.SetRange(requested.Start, requested.End)

	a.logger.Info("allocated specific VLAN range",
		slog.String("tenant_id", tenantID),
		slog.String("range", requested.String()),
	)

	return alloc, nil
}

// Release frees a tenant's VLAN allocation
func (a *Allocator) Release(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return &ErrEmptyTenantID{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if tenant has an allocation
	allocRange, ok := a.allocated[tenantID]
	if !ok {
		return &ErrTenantVLANNotFound{TenantID: tenantID}
	}

	// Delete from store
	if err := a.store.DeleteAllocation(ctx, tenantID); err != nil {
		return &ErrStoreFailed{
			Operation: "DeleteAllocation",
			Err:       err,
		}
	}

	// Update in-memory state
	delete(a.allocated, tenantID)
	a.usedVLANs.ClearRange(allocRange.Start, allocRange.End)

	a.logger.Info("released VLAN range",
		slog.String("tenant_id", tenantID),
		slog.String("range", allocRange.String()),
	)

	return nil
}

// Get returns a tenant's current allocation
func (a *Allocator) Get(ctx context.Context, tenantID string) (*Allocation, error) {
	if tenantID == "" {
		return nil, &ErrEmptyTenantID{}
	}

	a.mu.RLock()
	allocRange, ok := a.allocated[tenantID]
	a.mu.RUnlock()

	if ok {
		// Return from cache
		return &Allocation{
			TenantID: tenantID,
			Range:    allocRange,
		}, nil
	}

	// Try to load from store
	alloc, err := a.store.GetAllocation(ctx, tenantID)
	if err != nil {
		return nil, &ErrStoreFailed{
			Operation: "GetAllocation",
			Err:       err,
		}
	}
	if alloc == nil {
		return nil, &ErrTenantVLANNotFound{TenantID: tenantID}
	}

	// Update cache
	a.mu.Lock()
	a.allocated[tenantID] = alloc.Range
	a.usedVLANs.SetRange(alloc.Range.Start, alloc.Range.End)
	a.mu.Unlock()

	return alloc, nil
}

// GetByVLAN finds which tenant owns a VLAN
// Returns the tenant ID if found, or empty string with an error if not found
func (a *Allocator) GetByVLAN(ctx context.Context, vlan uint16) (string, error) {
	// Validate VLAN is in valid range
	if vlan < MinVLANID || vlan > MaxVLANID {
		return "", &ErrVLANOutOfRange{
			VLAN: vlan,
			Min:  MinVLANID,
			Max:  MaxVLANID,
		}
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check if VLAN is within global range
	if vlan < a.globalRange.Start || vlan > a.globalRange.End {
		return "", &ErrVLANOutOfRange{
			VLAN: vlan,
			Min:  a.globalRange.Start,
			Max:  a.globalRange.End,
		}
	}

	// Quick check if VLAN is allocated at all
	if !a.usedVLANs.Test(vlan) {
		return "", nil // Not allocated
	}

	// Find the owning tenant
	for tenantID, allocRange := range a.allocated {
		if allocRange.Contains(vlan) {
			return tenantID, nil
		}
	}

	// Should not reach here if state is consistent
	return "", nil
}

// IsAvailable checks if a VLAN range is available
func (a *Allocator) IsAvailable(ctx context.Context, r Range) bool {
	if err := r.Validate(); err != nil {
		return false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check if range is within global bounds
	if r.Start < a.globalRange.Start || r.End > a.globalRange.End {
		return false
	}

	// Check if all VLANs in range are clear
	return a.usedVLANs.TestRangeClear(r.Start, r.End)
}

// ListAllocations returns all VLAN allocations
func (a *Allocator) ListAllocations(ctx context.Context) ([]*Allocation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	allocations := make([]*Allocation, 0, len(a.allocated))
	for tenantID, allocRange := range a.allocated {
		allocations = append(allocations, &Allocation{
			TenantID: tenantID,
			Range:    allocRange,
		})
	}

	return allocations, nil
}

// Reload refreshes in-memory state from store
func (a *Allocator) Reload(ctx context.Context) error {
	allocations, err := a.store.ListAllocations(ctx)
	if err != nil {
		return &ErrStoreFailed{
			Operation: "ListAllocations",
			Err:       err,
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Reset in-memory state
	a.allocated = make(map[string]Range)
	a.usedVLANs.Reset()

	// Rebuild from store
	for _, alloc := range allocations {
		if alloc == nil || alloc.TenantID == "" {
			continue
		}
		a.allocated[alloc.TenantID] = alloc.Range
		a.usedVLANs.SetRange(alloc.Range.Start, alloc.Range.End)
	}

	a.logger.Info("reloaded VLAN allocations",
		slog.Int("count", len(a.allocated)),
	)

	return nil
}

// GetGlobalRange returns the configured global VLAN range
func (a *Allocator) GetGlobalRange() Range {
	return a.globalRange
}

// GetDefaultRangeSize returns the default allocation size
func (a *Allocator) GetDefaultRangeSize() uint16 {
	return a.rangeSize
}

// GetAvailableCapacity returns the number of unallocated VLANs
func (a *Allocator) GetAvailableCapacity() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	globalSize := int(a.globalRange.End-a.globalRange.Start) + 1
	usedInRange := a.usedVLANs.CountSetInRange(a.globalRange.Start, a.globalRange.End)
	return globalSize - usedInRange
}

// GetAllocationCount returns the number of active allocations
func (a *Allocator) GetAllocationCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.allocated)
}

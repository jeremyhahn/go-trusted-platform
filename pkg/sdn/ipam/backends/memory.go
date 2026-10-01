// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

// Package backends provides IPAM allocator backend implementations.
package backends

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// Compile-time interface checks
var (
	_ ipam.Allocator            = (*MemoryBackend)(nil)
	_ ipam.BatchAllocator       = (*MemoryBackend)(nil)
	_ ipam.ReservationAllocator = (*MemoryBackend)(nil)
)

// MemoryBackendConfig holds configuration for the memory backend.
type MemoryBackendConfig struct {
	// Logger is the logger instance for the backend.
	Logger *slog.Logger
}

// MemoryBackend implements ipam.Allocator using in-memory storage.
// It is safe for concurrent use and designed for testing and single-node development.
type MemoryBackend struct {
	mu          sync.RWMutex
	pools       map[string]*ipam.Pool           // poolID -> Pool
	poolsByName map[string]string               // name -> poolID
	poolsByCIDR map[netip.Prefix]string         // CIDR -> poolID
	allocations map[netip.Addr]*ipam.Allocation // IP -> Allocation
	bitmaps     map[string]*ipam.Bitmap         // poolID -> Bitmap

	logger *slog.Logger
	closed atomic.Bool
}

// NewMemoryBackend creates a new in-memory IPAM backend.
func NewMemoryBackend(opts ...ipam.AllocatorOption) *MemoryBackend {
	logger := slog.Default()

	return &MemoryBackend{
		pools:       make(map[string]*ipam.Pool),
		poolsByName: make(map[string]string),
		poolsByCIDR: make(map[netip.Prefix]string),
		allocations: make(map[netip.Addr]*ipam.Allocation),
		bitmaps:     make(map[string]*ipam.Bitmap),
		logger:      logger,
	}
}

// NewMemoryBackendWithConfig creates a new in-memory IPAM backend with config.
func NewMemoryBackendWithConfig(config *MemoryBackendConfig) *MemoryBackend {
	logger := slog.Default()
	if config != nil && config.Logger != nil {
		logger = config.Logger
	}

	return &MemoryBackend{
		pools:       make(map[string]*ipam.Pool),
		poolsByName: make(map[string]string),
		poolsByCIDR: make(map[netip.Prefix]string),
		allocations: make(map[netip.Addr]*ipam.Allocation),
		bitmaps:     make(map[string]*ipam.Bitmap),
		logger:      logger,
	}
}

// Pool Management

// CreatePool creates a new IP address pool.
func (m *MemoryBackend) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	if err := m.validatePool(pool); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicates
	if _, exists := m.pools[pool.ID]; exists {
		return ipam.ErrPoolAlreadyExists
	}
	if _, exists := m.poolsByName[pool.Name]; exists {
		return ipam.ErrPoolNameExists
	}
	if _, exists := m.poolsByCIDR[pool.CIDR]; exists {
		return ipam.ErrPoolAlreadyExists
	}

	// Check for CIDR overlaps
	for existingCIDR := range m.poolsByCIDR {
		if ipam.CIDROverlaps(pool.CIDR, existingCIDR) {
			return ipam.ErrPoolCIDROverlaps
		}
	}

	// Size the pool by what is actually allocatable (usable less reserved).
	pool.TotalIPs = pool.AllocatableIPs()
	pool.AvailableIPs = pool.TotalIPs
	pool.AllocatedIPs = 0
	pool.CreatedAt = time.Now()
	pool.UpdatedAt = pool.CreatedAt

	// The bitmap covers every usable address, indexed by usable position;
	// reserved addresses are skipped by the window rules, never set.
	m.bitmaps[pool.ID] = ipam.NewBitmap(ipam.CalculatePoolSize(pool.CIDR))

	// Store pool (clone to prevent external modification)
	m.pools[pool.ID] = pool.Clone()
	m.poolsByName[pool.Name] = pool.ID
	m.poolsByCIDR[pool.CIDR] = pool.ID

	m.logger.Debug("pool created",
		slog.String("pool_id", pool.ID),
		slog.String("name", pool.Name),
		slog.String("cidr", pool.CIDR.String()),
		slog.Uint64("total_ips", pool.TotalIPs))

	return nil
}

// GetPool retrieves a pool by its ID.
func (m *MemoryBackend) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	return pool.Clone(), nil
}

// GetPoolByName retrieves a pool by its name.
func (m *MemoryBackend) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	poolID, exists := m.poolsByName[name]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	return pool.Clone(), nil
}

// GetPoolByCIDR retrieves a pool by its CIDR.
func (m *MemoryBackend) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	poolID, exists := m.poolsByCIDR[cidr]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	return pool.Clone(), nil
}

// ListPools returns all pools.
func (m *MemoryBackend) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pools := make([]*ipam.Pool, 0, len(m.pools))
	for _, pool := range m.pools {
		pools = append(pools, pool.Clone())
	}

	return pools, nil
}

// ListPoolsByZone returns all pools whose Zone matches the given zone string.
// An empty zone returns all pools (equivalent to ListPools).
func (m *MemoryBackend) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}
	if zone == "" {
		return m.ListPools(ctx)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var pools []*ipam.Pool
	for _, pool := range m.pools {
		if pool.Zone == zone {
			pools = append(pools, pool.Clone())
		}
	}

	return pools, nil
}

// UpdatePool updates an existing pool's configuration.
func (m *MemoryBackend) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.pools[pool.ID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	// CIDR cannot be changed after creation
	if pool.CIDR != existing.CIDR {
		return &ipam.ErrPoolOperationFailed{
			PoolID:    pool.ID,
			Operation: "update",
			Cause:     ipam.ErrInvalidCIDR,
		}
	}

	// Validate before touching any index, so a refused update leaves the
	// backend exactly as it was.
	if err := m.validatePool(pool); err != nil {
		return err
	}

	// Check for name conflicts
	if pool.Name != existing.Name {
		if existingID, nameExists := m.poolsByName[pool.Name]; nameExists && existingID != pool.ID {
			return ipam.ErrPoolNameExists
		}
		// Update name index
		delete(m.poolsByName, existing.Name)
		m.poolsByName[pool.Name] = pool.ID
	}

	// Preserve allocation counters; the size follows the (possibly changed)
	// reserved prefixes.
	pool.AllocatedIPs = existing.AllocatedIPs
	pool.TotalIPs = pool.AllocatableIPs()
	pool.AvailableIPs = 0
	if pool.TotalIPs > pool.AllocatedIPs {
		pool.AvailableIPs = pool.TotalIPs - pool.AllocatedIPs
	}
	pool.CreatedAt = existing.CreatedAt
	pool.UpdatedAt = time.Now()

	m.pools[pool.ID] = pool.Clone()

	m.logger.Debug("pool updated",
		slog.String("pool_id", pool.ID),
		slog.String("name", pool.Name))

	return nil
}

// DeletePool removes a pool and all its allocations.
func (m *MemoryBackend) DeletePool(ctx context.Context, poolID string) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	// Check for active allocations
	activeCount := 0
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID && alloc.Status == ipam.AllocationStatusActive {
			activeCount++
		}
	}
	if activeCount > 0 {
		return ipam.ErrPoolHasAllocations
	}

	// Remove all allocations for this pool
	for ip, alloc := range m.allocations {
		if alloc.PoolID == poolID {
			delete(m.allocations, ip)
		}
	}

	// Remove pool
	delete(m.pools, poolID)
	delete(m.poolsByName, pool.Name)
	delete(m.poolsByCIDR, pool.CIDR)
	delete(m.bitmaps, poolID)

	m.logger.Debug("pool deleted",
		slog.String("pool_id", poolID),
		slog.String("name", pool.Name))

	return nil
}

// GetPoolStats returns statistics about a pool.
func (m *MemoryBackend) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	stats := &ipam.PoolStats{
		PoolID:       poolID,
		TotalIPs:     pool.TotalIPs,
		AllocatedIPs: pool.AllocatedIPs,
		AvailableIPs: pool.AvailableIPs,
	}

	// Count expired and reserved allocations
	for _, alloc := range m.allocations {
		if alloc.PoolID != poolID {
			continue
		}
		switch alloc.Status {
		case ipam.AllocationStatusExpired:
			stats.ExpiredIPs++
		case ipam.AllocationStatusReserved:
			stats.ReservedIPs++
		}
	}

	stats.CalculateUtilization()

	return stats, nil
}

// Allocation Operations

// Allocate allocates the next available IP from the specified pool.
func (m *MemoryBackend) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Get pool
	pool, exists := m.pools[req.PoolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	// Get bitmap
	bitmap := m.bitmaps[req.PoolID]

	// Find the next free, unreserved address in the dynamic window. The
	// bitmap is indexed by usable position: offset minus the skipped
	// network address.
	shift := ipam.AdjustOffsetForUsable(pool.CIDR, 0)
	ip, offset, err := pool.NextDynamic(func(from uint64) (uint64, bool) {
		idx, found := bitmap.NextClear(from - shift)
		return idx + shift, found
	})
	if err != nil {
		return nil, err
	}

	// Mark as allocated in bitmap
	bitmap.Set(offset - shift)

	// Create allocation
	alloc := m.createAllocation(req, pool, ip)

	// Store allocation
	m.allocations[ip] = alloc

	// Update pool stats
	pool.AllocatedIPs++
	pool.AvailableIPs--
	pool.UpdatedAt = time.Now()

	m.logger.Debug("IP allocated",
		slog.String("pool_id", req.PoolID),
		slog.String("ip", ip.String()),
		slog.String("device_id", req.DeviceID))

	return alloc.Clone(), nil
}

// AllocateSpecific allocates a specific IP address from a pool.
func (m *MemoryBackend) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if !req.RequestedIP.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Get pool
	pool, exists := m.pools[req.PoolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	// The address must be in the pool, usable, and not reserved.
	if err := pool.CheckSpecific(req.RequestedIP); err != nil {
		return nil, err
	}

	// Check if already allocated
	if existingAlloc, exists := m.allocations[req.RequestedIP]; exists {
		if existingAlloc.Status == ipam.AllocationStatusActive {
			return nil, &ipam.ErrIPConflict{
				IP:       req.RequestedIP,
				DeviceID: existingAlloc.DeviceID,
			}
		}
		// Remove expired/released allocation
		delete(m.allocations, req.RequestedIP)
	}

	// Get bitmap and calculate offset
	bitmap := m.bitmaps[req.PoolID]
	offset, err := ipam.IPToOffset(pool.CIDR, req.RequestedIP)
	if err != nil {
		return nil, err
	}

	// Adjust offset for bitmap (remove network address adjustment)
	bitmapOffset := offset
	if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
		bitmapOffset = offset - 1
	}

	// Check if already set in bitmap
	if bitmap.IsSet(bitmapOffset) {
		return nil, ipam.ErrIPAlreadyAllocated
	}

	// Mark as allocated
	bitmap.Set(bitmapOffset)

	// Create allocation
	alloc := m.createAllocation(req, pool, req.RequestedIP)

	// Store allocation
	m.allocations[req.RequestedIP] = alloc

	// Update pool stats
	pool.AllocatedIPs++
	pool.AvailableIPs--
	pool.UpdatedAt = time.Now()

	m.logger.Debug("specific IP allocated",
		slog.String("pool_id", req.PoolID),
		slog.String("ip", req.RequestedIP.String()),
		slog.String("device_id", req.DeviceID))

	return alloc.Clone(), nil
}

// Release releases an allocated IP address back to the pool.
func (m *MemoryBackend) Release(ctx context.Context, ip netip.Addr) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	alloc, exists := m.allocations[ip]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	if alloc.Status == ipam.AllocationStatusReleased {
		return ipam.ErrAllocationReleased
	}

	pool, exists := m.pools[alloc.PoolID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	// Calculate bitmap offset
	offset, err := ipam.IPToOffset(pool.CIDR, ip)
	if err != nil {
		return err
	}

	// Adjust offset for bitmap
	bitmapOffset := offset
	if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
		bitmapOffset = offset - 1
	}

	// Clear bitmap
	bitmap := m.bitmaps[alloc.PoolID]
	bitmap.Clear(bitmapOffset)

	// Update allocation status
	alloc.Status = ipam.AllocationStatusReleased
	alloc.ReleasedAt = time.Now()

	// Update pool stats (only if it was active)
	if alloc.Status != ipam.AllocationStatusExpired {
		pool.AllocatedIPs--
		pool.AvailableIPs++
		pool.UpdatedAt = time.Now()
	}

	m.logger.Debug("IP released",
		slog.String("ip", ip.String()),
		slog.String("device_id", alloc.DeviceID))

	return nil
}

// ReleaseByDeviceID releases all allocations for a device.
func (m *MemoryBackend) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	if err := m.checkClosed(); err != nil {
		return 0, err
	}

	if deviceID == "" {
		return 0, ipam.ErrDeviceIDRequired
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var released int
	for ip, alloc := range m.allocations {
		if alloc.DeviceID != deviceID {
			continue
		}
		if alloc.Status != ipam.AllocationStatusActive {
			continue
		}

		pool, exists := m.pools[alloc.PoolID]
		if !exists {
			continue
		}

		// Calculate bitmap offset
		offset, err := ipam.IPToOffset(pool.CIDR, ip)
		if err != nil {
			continue
		}

		// Adjust offset for bitmap
		bitmapOffset := offset
		if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
			bitmapOffset = offset - 1
		}

		// Clear bitmap
		bitmap := m.bitmaps[alloc.PoolID]
		bitmap.Clear(bitmapOffset)

		// Update allocation status
		alloc.Status = ipam.AllocationStatusReleased
		alloc.ReleasedAt = time.Now()

		// Update pool stats
		pool.AllocatedIPs--
		pool.AvailableIPs++
		pool.UpdatedAt = time.Now()

		released++
	}

	m.logger.Debug("released allocations by device",
		slog.String("device_id", deviceID),
		slog.Int("count", released))

	return released, nil
}

// Lease Management

// Renew extends the lease of an allocation.
func (m *MemoryBackend) Renew(ctx context.Context, ip netip.Addr) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	alloc, exists := m.allocations[ip]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	if alloc.Status == ipam.AllocationStatusExpired {
		return ipam.ErrAllocationExpired
	}

	if alloc.Status == ipam.AllocationStatusReleased {
		return ipam.ErrAllocationReleased
	}

	pool, exists := m.pools[alloc.PoolID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	now := time.Now()
	alloc.LastSeen = now

	// Extend lease if applicable
	if !alloc.ExpiresAt.IsZero() {
		if pool.DefaultLeaseDuration > 0 {
			alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
		}
	}

	m.logger.Debug("lease renewed",
		slog.String("ip", ip.String()),
		slog.String("device_id", alloc.DeviceID))

	return nil
}

// GetAllocation retrieves an allocation by IP address.
func (m *MemoryBackend) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	if !ip.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	alloc, exists := m.allocations[ip]
	if !exists {
		return nil, ipam.ErrAllocationNotFound
	}

	return alloc.Clone(), nil
}

// GetAllocationsByDevice retrieves all allocations for a device.
func (m *MemoryBackend) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	if deviceID == "" {
		return nil, ipam.ErrDeviceIDRequired
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var allocations []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.DeviceID == deviceID {
			allocations = append(allocations, alloc.Clone())
		}
	}

	return allocations, nil
}

// GetAllocationsByPool retrieves all allocations in a pool.
func (m *MemoryBackend) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.pools[poolID]; !exists {
		return nil, ipam.ErrPoolNotFound
	}

	var allocations []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID {
			allocations = append(allocations, alloc.Clone())
		}
	}

	return allocations, nil
}

// Expiration Management

// ExpireInactive marks inactive allocations as expired and returns them.
func (m *MemoryBackend) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	if pool.InactivityTimeout == 0 {
		return nil, nil // No timeout configured
	}

	threshold := time.Now().Add(-pool.InactivityTimeout)
	var expired []*ipam.Allocation

	for ip, alloc := range m.allocations {
		if alloc.PoolID != poolID {
			continue
		}
		if alloc.Status != ipam.AllocationStatusActive {
			continue
		}
		if alloc.LastSeen.Before(threshold) {
			// Mark as expired
			alloc.Status = ipam.AllocationStatusExpired
			alloc.ReleasedAt = time.Now()
			expired = append(expired, alloc.Clone())

			// Clear bitmap
			offset, err := ipam.IPToOffset(pool.CIDR, ip)
			if err != nil {
				continue
			}

			// Adjust offset for bitmap
			bitmapOffset := offset
			if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
				bitmapOffset = offset - 1
			}

			m.bitmaps[poolID].Clear(bitmapOffset)

			// Update pool stats
			pool.AllocatedIPs--
			pool.AvailableIPs++
		}
	}

	if len(expired) > 0 {
		pool.UpdatedAt = time.Now()
		m.logger.Debug("expired inactive allocations",
			slog.String("pool_id", poolID),
			slog.Int("count", len(expired)))
	}

	return expired, nil
}

// Batch Operations (BatchAllocator interface)

// AllocateBatch allocates multiple IPs in a single operation.
func (m *MemoryBackend) AllocateBatch(ctx context.Context, reqs []*ipam.AllocationRequest) ([]*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	allocations := make([]*ipam.Allocation, 0, len(reqs))
	for _, req := range reqs {
		alloc, err := m.Allocate(ctx, req)
		if err != nil {
			// Return partial results with error
			return allocations, &ipam.ErrAllocationFailed{
				PoolID: req.PoolID,
				Reason: "batch allocation partial failure",
				Cause:  err,
			}
		}
		allocations = append(allocations, alloc)
	}

	return allocations, nil
}

// ReleaseBatch releases multiple IPs in a single operation.
func (m *MemoryBackend) ReleaseBatch(ctx context.Context, ips []netip.Addr) (int, error) {
	if err := m.checkClosed(); err != nil {
		return 0, err
	}

	var released int
	var lastErr error
	for _, ip := range ips {
		if err := m.Release(ctx, ip); err != nil {
			lastErr = err
			continue
		}
		released++
	}

	return released, lastErr
}

// Reservation Operations (ReservationAllocator interface)

// Reserve marks an IP as reserved, preventing automatic allocation.
func (m *MemoryBackend) Reserve(ctx context.Context, poolID string, ip netip.Addr, description string) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[poolID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	if err := pool.CheckSpecific(ip); err != nil {
		return err
	}

	// Check if already allocated or reserved
	if existingAlloc, exists := m.allocations[ip]; exists {
		if existingAlloc.Status == ipam.AllocationStatusActive ||
			existingAlloc.Status == ipam.AllocationStatusReserved {
			return ipam.ErrIPAlreadyAllocated
		}
	}

	// Calculate bitmap offset
	offset, err := ipam.IPToOffset(pool.CIDR, ip)
	if err != nil {
		return err
	}

	// Adjust offset for bitmap
	bitmapOffset := offset
	if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
		bitmapOffset = offset - 1
	}

	// Mark as reserved in bitmap
	bitmap := m.bitmaps[poolID]
	bitmap.Set(bitmapOffset)

	// Create reservation
	now := time.Now()
	alloc := &ipam.Allocation{
		ID:          generateID(),
		PoolID:      poolID,
		IP:          ip,
		DeviceID:    "reserved",
		Description: description,
		AllocatedAt: now,
		LastSeen:    now,
		Status:      ipam.AllocationStatusReserved,
	}

	m.allocations[ip] = alloc

	// Update pool stats
	pool.AllocatedIPs++
	pool.AvailableIPs--
	pool.UpdatedAt = now

	m.logger.Debug("IP reserved",
		slog.String("pool_id", poolID),
		slog.String("ip", ip.String()))

	return nil
}

// Unreserve removes a reservation, making the IP available for allocation.
func (m *MemoryBackend) Unreserve(ctx context.Context, ip netip.Addr) error {
	if err := m.checkClosed(); err != nil {
		return err
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	alloc, exists := m.allocations[ip]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	if alloc.Status != ipam.AllocationStatusReserved {
		return &ipam.ErrInvalidAllocationStatus{
			Current: alloc.Status,
			Desired: ipam.AllocationStatusReleased,
			Reason:  "can only unreserve reserved allocations",
		}
	}

	pool, exists := m.pools[alloc.PoolID]
	if !exists {
		return ipam.ErrPoolNotFound
	}

	// Calculate bitmap offset
	offset, err := ipam.IPToOffset(pool.CIDR, ip)
	if err != nil {
		return err
	}

	// Adjust offset for bitmap
	bitmapOffset := offset
	if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
		bitmapOffset = offset - 1
	}

	// Clear bitmap
	bitmap := m.bitmaps[alloc.PoolID]
	bitmap.Clear(bitmapOffset)

	// Remove allocation
	delete(m.allocations, ip)

	// Update pool stats
	pool.AllocatedIPs--
	pool.AvailableIPs++
	pool.UpdatedAt = time.Now()

	m.logger.Debug("IP unreserved",
		slog.String("pool_id", alloc.PoolID),
		slog.String("ip", ip.String()))

	return nil
}

// ListReservations returns all reserved IPs in a pool.
func (m *MemoryBackend) ListReservations(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if err := m.checkClosed(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.pools[poolID]; !exists {
		return nil, ipam.ErrPoolNotFound
	}

	var reservations []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID && alloc.Status == ipam.AllocationStatusReserved {
			reservations = append(reservations, alloc.Clone())
		}
	}

	return reservations, nil
}

// Health and Lifecycle

// Ping checks if the allocator backend is available.
func (m *MemoryBackend) Ping(ctx context.Context) error {
	return m.checkClosed()
}

// Close releases resources held by the allocator.
func (m *MemoryBackend) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		m.mu.Lock()
		defer m.mu.Unlock()

		// Clear all maps
		m.pools = nil
		m.poolsByName = nil
		m.poolsByCIDR = nil
		m.allocations = nil
		m.bitmaps = nil

		m.logger.Debug("memory backend closed")
		return nil
	}
	return ipam.ErrBackendUnavailable
}

// Helper functions

func (m *MemoryBackend) checkClosed() error {
	if m.closed.Load() {
		return ipam.ErrBackendUnavailable
	}
	return nil
}

func (m *MemoryBackend) validatePool(pool *ipam.Pool) error {
	if pool.ID == "" {
		return ipam.ErrInvalidPoolID
	}
	if pool.Name == "" {
		return ipam.ErrInvalidPoolName
	}
	if !pool.CIDR.IsValid() {
		return ipam.ErrInvalidCIDR
	}
	// Validate gateway if specified
	if pool.Gateway.IsValid() && !pool.CIDR.Contains(pool.Gateway) {
		return ipam.ErrInvalidGateway
	}
	return ipam.NewPoolManager().ValidatePool(pool)
}

func (m *MemoryBackend) createAllocation(req *ipam.AllocationRequest, pool *ipam.Pool, ip netip.Addr) *ipam.Allocation {
	now := time.Now()
	alloc := &ipam.Allocation{
		ID:          generateID(),
		PoolID:      req.PoolID,
		Zone:        pool.Zone,
		IP:          ip,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		Description: req.Description,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
		AllocatedAt: now,
		LastSeen:    now,
		Status:      ipam.AllocationStatusActive,
	}

	// Set expiration if lease duration specified
	if req.LeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(req.LeaseDuration)
	} else if pool.DefaultLeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
	}

	return alloc
}

func generateID() string {
	return uuid.New().String()
}

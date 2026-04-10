//go:build !platform_p2p

// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

// Package backends provides storage backend implementations for IPAM.
// This file implements the QuicBaaS backend for strongly consistent IP allocation.
package backends

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

const (
	// Entity type prefixes for QuicBaaS storage
	entityTypePool       = "ipam_pool"
	entityTypeAllocation = "ipam_allocation"
	entityTypeIndex      = "ipam_index"

	// Index field names

	// Default configuration
	defaultMaxRetries       = 10
	defaultRequestTimeout   = 30 * time.Second
	defaultInactivityPeriod = 720 * time.Hour // 30 days
)

// QuicBaaSClient defines the interface required from a QuicBaaS client.
// This interface allows for dependency injection and mocking in tests.
type QuicBaaSClient interface {
	// IsStarted returns true if the client is connected and ready.
	IsStarted() bool

	// Put stores a value with the given entity type and ID.
	Put(ctx context.Context, entityType string, id uint64, data []byte) error

	// Get retrieves a value by entity type and ID.
	// Returns (data, found, error).
	Get(ctx context.Context, entityType string, id uint64) ([]byte, bool, error)

	// Delete removes an entity by type and ID.
	Delete(ctx context.Context, entityType string, id uint64) error

	// List retrieves entities with pagination.
	List(ctx context.Context, entityType string, pageSize uint64, pageToken string) ([]*service.Entity, string, error)

	// Query searches for entities using secondary indexes.
	Query(ctx context.Context, entityType, indexField string, value []byte) ([]*service.Entity, error)
}

// QuicBaaSBackend implements ipam.Allocator using QuicBaaS for storage.
// It provides strongly consistent IP allocation using QuicBaaS's Raft-based
// consensus protocol. The backend stores allocations directly rather than
// using bitmaps, providing better persistence and recovery characteristics.
type QuicBaaSBackend struct {
	client     QuicBaaSClient
	logger     *slog.Logger
	maxRetries int
	closed     atomic.Bool
}

// QuicBaaSBackendConfig holds configuration for the QuicBaaS backend.
type QuicBaaSBackendConfig struct {
	// MaxRetries is the maximum number of retry attempts for concurrent operations.
	MaxRetries int
	// Logger is the logger instance for the backend.
	Logger *slog.Logger
}

// NewQuicBaaSBackend creates a new QuicBaaS-backed IPAM allocator.
// The provided client must be started before use.
func NewQuicBaaSBackend(client QuicBaaSClient, config *QuicBaaSBackendConfig) (*QuicBaaSBackend, error) {
	if client == nil {
		return nil, ipam.ErrBackendUnavailable
	}

	if config == nil {
		config = &QuicBaaSBackendConfig{}
	}

	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &QuicBaaSBackend{
		client:     client,
		logger:     logger.With(slog.String("component", "ipam-quicbaas")),
		maxRetries: maxRetries,
	}, nil
}

// Pool Management

// CreatePool creates a new IP address pool.
func (d *QuicBaaSBackend) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if pool == nil {
		return ipam.ErrInvalidPoolID
	}

	if pool.ID == "" {
		return ipam.ErrInvalidPoolID
	}

	if pool.Name == "" {
		return ipam.ErrInvalidPoolName
	}

	if !pool.CIDR.IsValid() {
		return ipam.ErrInvalidCIDR
	}

	// Check if pool already exists
	poolID := stringToID(pool.ID)
	existing, found, err := d.client.Get(ctx, entityTypePool, poolID)
	if err != nil {
		return &ipam.ErrStorageOperation{Operation: "get", Key: pool.ID, Cause: err}
	}
	if found && len(existing) > 0 {
		return ipam.ErrPoolAlreadyExists
	}

	// Check for name conflict
	if err := d.checkPoolNameConflict(ctx, pool.Name, pool.ID); err != nil {
		return err
	}

	// Check for CIDR overlap
	if err := d.checkCIDROverlap(ctx, pool.CIDR, pool.ID); err != nil {
		return err
	}

	// Initialize pool statistics
	pool.TotalIPs = ipam.CalculatePoolSize(pool.CIDR)
	pool.AvailableIPs = pool.TotalIPs
	pool.AllocatedIPs = 0

	now := time.Now()
	pool.CreatedAt = now
	pool.UpdatedAt = now

	// Serialize pool
	data, err := json.Marshal(pool)
	if err != nil {
		return &ipam.ErrSerialization{EntityType: "pool", Operation: "marshal", Cause: err}
	}

	// Store pool
	if err := d.client.Put(ctx, entityTypePool, poolID, data); err != nil {
		return &ipam.ErrStorageOperation{Operation: "put", Key: pool.ID, Cause: err}
	}

	// Store name index
	nameIndexID := stringToID("name:" + pool.Name)
	if err := d.client.Put(ctx, entityTypeIndex, nameIndexID, []byte(pool.ID)); err != nil {
		d.logger.Warn("failed to store name index", slog.String("pool", pool.ID), slog.Any("error", err))
	}

	// Store CIDR index
	cidrIndexID := stringToID("cidr:" + pool.CIDR.String())
	if err := d.client.Put(ctx, entityTypeIndex, cidrIndexID, []byte(pool.ID)); err != nil {
		d.logger.Warn("failed to store CIDR index", slog.String("pool", pool.ID), slog.Any("error", err))
	}

	d.logger.Info("pool created",
		slog.String("id", pool.ID),
		slog.String("name", pool.Name),
		slog.String("cidr", pool.CIDR.String()),
		slog.Uint64("total_ips", pool.TotalIPs))

	return nil
}

// GetPool retrieves a pool by ID.
func (d *QuicBaaSBackend) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if poolID == "" {
		return nil, ipam.ErrInvalidPoolID
	}

	id := stringToID(poolID)
	data, found, err := d.client.Get(ctx, entityTypePool, id)
	if err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "get", Key: poolID, Cause: err}
	}
	if !found {
		return nil, ipam.ErrPoolNotFound
	}

	var pool ipam.Pool
	if err := json.Unmarshal(data, &pool); err != nil {
		return nil, &ipam.ErrSerialization{EntityType: "pool", Operation: "unmarshal", Cause: err}
	}

	return &pool, nil
}

// GetPoolByName retrieves a pool by name.
func (d *QuicBaaSBackend) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if name == "" {
		return nil, ipam.ErrInvalidPoolName
	}

	// Look up pool ID from name index
	nameIndexID := stringToID("name:" + name)
	data, found, err := d.client.Get(ctx, entityTypeIndex, nameIndexID)
	if err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "get", Key: "name:" + name, Cause: err}
	}
	if !found {
		return nil, ipam.ErrPoolNotFound
	}

	poolID := string(data)
	return d.GetPool(ctx, poolID)
}

// GetPoolByCIDR retrieves a pool by CIDR.
func (d *QuicBaaSBackend) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if !cidr.IsValid() {
		return nil, ipam.ErrInvalidCIDR
	}

	// Look up pool ID from CIDR index
	cidrIndexID := stringToID("cidr:" + cidr.String())
	data, found, err := d.client.Get(ctx, entityTypeIndex, cidrIndexID)
	if err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "get", Key: "cidr:" + cidr.String(), Cause: err}
	}
	if !found {
		return nil, ipam.ErrPoolNotFound
	}

	poolID := string(data)
	return d.GetPool(ctx, poolID)
}

// ListPools returns all pools.
func (d *QuicBaaSBackend) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	var pools []*ipam.Pool
	var pageToken string

	for {
		entities, nextToken, err := d.client.List(ctx, entityTypePool, 100, pageToken)
		if err != nil {
			return nil, &ipam.ErrStorageOperation{Operation: "list", Key: entityTypePool, Cause: err}
		}

		for _, entity := range entities {
			var pool ipam.Pool
			if err := json.Unmarshal(entity.Data, &pool); err != nil {
				d.logger.Warn("failed to unmarshal pool", slog.Uint64("id", entity.ID), slog.Any("error", err))
				continue
			}
			pools = append(pools, &pool)
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return pools, nil
}

// UpdatePool updates an existing pool.
func (d *QuicBaaSBackend) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if pool == nil || pool.ID == "" {
		return ipam.ErrInvalidPoolID
	}

	// Verify pool exists
	existing, err := d.GetPool(ctx, pool.ID)
	if err != nil {
		return err
	}

	// Check for name conflict if name changed
	if pool.Name != existing.Name {
		if err := d.checkPoolNameConflict(ctx, pool.Name, pool.ID); err != nil {
			return err
		}

		// Update name index
		oldNameIndexID := stringToID("name:" + existing.Name)
		d.client.Delete(ctx, entityTypeIndex, oldNameIndexID)

		newNameIndexID := stringToID("name:" + pool.Name)
		d.client.Put(ctx, entityTypeIndex, newNameIndexID, []byte(pool.ID))
	}

	pool.UpdatedAt = time.Now()

	data, err := json.Marshal(pool)
	if err != nil {
		return &ipam.ErrSerialization{EntityType: "pool", Operation: "marshal", Cause: err}
	}

	poolID := stringToID(pool.ID)
	if err := d.client.Put(ctx, entityTypePool, poolID, data); err != nil {
		return &ipam.ErrStorageOperation{Operation: "put", Key: pool.ID, Cause: err}
	}

	return nil
}

// DeletePool deletes a pool and all its allocations.
func (d *QuicBaaSBackend) DeletePool(ctx context.Context, poolID string) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if poolID == "" {
		return ipam.ErrInvalidPoolID
	}

	// Get pool to check for allocations
	pool, err := d.GetPool(ctx, poolID)
	if err != nil {
		return err
	}

	// Check for active allocations
	allocations, err := d.GetAllocationsByPool(ctx, poolID)
	if err != nil {
		return err
	}

	activeCount := 0
	for _, alloc := range allocations {
		if alloc.Status == ipam.AllocationStatusActive {
			activeCount++
		}
	}

	if activeCount > 0 {
		return ipam.ErrPoolHasAllocations
	}

	// Delete all allocations
	for _, alloc := range allocations {
		allocID := stringToID(alloc.IP.String())
		d.client.Delete(ctx, entityTypeAllocation, allocID)
	}

	// Delete indexes
	nameIndexID := stringToID("name:" + pool.Name)
	d.client.Delete(ctx, entityTypeIndex, nameIndexID)

	cidrIndexID := stringToID("cidr:" + pool.CIDR.String())
	d.client.Delete(ctx, entityTypeIndex, cidrIndexID)

	// Delete pool
	id := stringToID(poolID)
	if err := d.client.Delete(ctx, entityTypePool, id); err != nil {
		return &ipam.ErrStorageOperation{Operation: "delete", Key: poolID, Cause: err}
	}

	d.logger.Info("pool deleted", slog.String("id", poolID))
	return nil
}

// GetPoolStats returns statistics for a pool.
func (d *QuicBaaSBackend) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	pool, err := d.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	allocations, err := d.GetAllocationsByPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	stats := &ipam.PoolStats{
		PoolID:   poolID,
		TotalIPs: pool.TotalIPs,
	}

	for _, alloc := range allocations {
		switch alloc.Status {
		case ipam.AllocationStatusActive:
			if alloc.IsExpired() {
				stats.ExpiredIPs++
			} else {
				stats.AllocatedIPs++
			}
		case ipam.AllocationStatusExpired:
			stats.ExpiredIPs++
		case ipam.AllocationStatusReserved:
			stats.ReservedIPs++
		}
	}

	stats.AvailableIPs = pool.TotalIPs - stats.AllocatedIPs - stats.ExpiredIPs - stats.ReservedIPs
	stats.CalculateUtilization()

	return stats, nil
}

// IP Allocation

// Allocate allocates the next available IP address from a pool.
func (d *QuicBaaSBackend) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if req == nil {
		return nil, ipam.ErrPoolIDRequired
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Get pool
	pool, err := d.GetPool(ctx, req.PoolID)
	if err != nil {
		return nil, err
	}

	// Get existing allocations to find available IPs
	allocations, err := d.GetAllocationsByPool(ctx, req.PoolID)
	if err != nil {
		return nil, err
	}

	// Build set of allocated IPs
	allocatedIPs := make(map[netip.Addr]bool)
	for _, alloc := range allocations {
		if alloc.Status == ipam.AllocationStatusActive || alloc.Status == ipam.AllocationStatusReserved {
			allocatedIPs[alloc.IP] = true
		}
	}

	// Find next available IP
	poolSize := ipam.CalculatePoolSize(pool.CIDR)

	// Start offset at 1 to skip network address for IPv4
	startOffset := uint64(0)
	if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
		startOffset = 1
	}

	var allocatedIP netip.Addr
	for offset := startOffset; offset < poolSize+startOffset; offset++ {
		ip, err := ipam.OffsetToIP(pool.CIDR, offset)
		if err != nil {
			continue
		}

		// Skip network/broadcast addresses
		if ipam.IsNetworkOrBroadcast(pool.CIDR, ip) {
			continue
		}

		// Check if already allocated
		if !allocatedIPs[ip] {
			allocatedIP = ip
			break
		}
	}

	if !allocatedIP.IsValid() {
		return nil, ipam.ErrPoolExhausted
	}

	// Create allocation record
	now := time.Now()
	alloc := &ipam.Allocation{
		ID:          uuid.New().String(),
		PoolID:      req.PoolID,
		IP:          allocatedIP,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		Description: req.Description,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
		AllocatedAt: now,
		LastSeen:    now,
		Status:      ipam.AllocationStatusActive,
	}

	// Set expiration
	if req.LeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(req.LeaseDuration)
	} else if pool.DefaultLeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
	}

	// Store allocation
	allocData, err := json.Marshal(alloc)
	if err != nil {
		return nil, &ipam.ErrSerialization{EntityType: "allocation", Operation: "marshal", Cause: err}
	}

	allocID := stringToID(allocatedIP.String())
	if err := d.client.Put(ctx, entityTypeAllocation, allocID, allocData); err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "put", Key: allocatedIP.String(), Cause: err}
	}

	// Update pool stats
	pool.AllocatedIPs++
	pool.AvailableIPs--
	pool.UpdatedAt = now
	d.UpdatePool(ctx, pool)

	d.logger.Info("IP allocated",
		slog.String("ip", allocatedIP.String()),
		slog.String("pool", req.PoolID),
		slog.String("device", req.DeviceID))

	return alloc, nil
}

// AllocateSpecific allocates a specific IP address from a pool.
func (d *QuicBaaSBackend) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if req == nil {
		return nil, ipam.ErrPoolIDRequired
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if !req.RequestedIP.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	// Get pool
	pool, err := d.GetPool(ctx, req.PoolID)
	if err != nil {
		return nil, err
	}

	// Verify IP is in pool
	if !pool.CIDR.Contains(req.RequestedIP) {
		return nil, ipam.ErrIPNotInPool
	}

	// Check if network or broadcast address
	if ipam.IsNetworkOrBroadcast(pool.CIDR, req.RequestedIP) {
		return nil, ipam.ErrNetworkAddress
	}

	// Check if already allocated
	existing, err := d.GetAllocation(ctx, req.RequestedIP)
	if err == nil && existing != nil && existing.Status == ipam.AllocationStatusActive {
		return nil, &ipam.ErrIPConflict{IP: req.RequestedIP, DeviceID: existing.DeviceID}
	}

	// Create allocation record
	now := time.Now()
	alloc := &ipam.Allocation{
		ID:          uuid.New().String(),
		PoolID:      req.PoolID,
		IP:          req.RequestedIP,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		Description: req.Description,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
		AllocatedAt: now,
		LastSeen:    now,
		Status:      ipam.AllocationStatusActive,
	}

	if req.LeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(req.LeaseDuration)
	} else if pool.DefaultLeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
	}

	// Store allocation
	allocData, err := json.Marshal(alloc)
	if err != nil {
		return nil, &ipam.ErrSerialization{EntityType: "allocation", Operation: "marshal", Cause: err}
	}

	allocID := stringToID(req.RequestedIP.String())
	if err := d.client.Put(ctx, entityTypeAllocation, allocID, allocData); err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "put", Key: req.RequestedIP.String(), Cause: err}
	}

	// Update pool stats
	pool.AllocatedIPs++
	pool.AvailableIPs--
	pool.UpdatedAt = now
	d.UpdatePool(ctx, pool)

	d.logger.Info("specific IP allocated",
		slog.String("ip", req.RequestedIP.String()),
		slog.String("pool", req.PoolID),
		slog.String("device", req.DeviceID))

	return alloc, nil
}

// Release releases an IP allocation.
func (d *QuicBaaSBackend) Release(ctx context.Context, ip netip.Addr) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	// Get allocation
	alloc, err := d.GetAllocation(ctx, ip)
	if err != nil {
		return err
	}

	if alloc.Status == ipam.AllocationStatusReleased {
		return ipam.ErrAllocationReleased
	}

	// Get pool
	pool, err := d.GetPool(ctx, alloc.PoolID)
	if err != nil {
		return err
	}

	// Update allocation status
	alloc.Status = ipam.AllocationStatusReleased
	alloc.ReleasedAt = time.Now()

	allocData, err := json.Marshal(alloc)
	if err != nil {
		return &ipam.ErrSerialization{EntityType: "allocation", Operation: "marshal", Cause: err}
	}

	allocID := stringToID(ip.String())
	if err := d.client.Put(ctx, entityTypeAllocation, allocID, allocData); err != nil {
		return &ipam.ErrStorageOperation{Operation: "put", Key: ip.String(), Cause: err}
	}

	// Update pool stats
	pool.AllocatedIPs--
	pool.AvailableIPs++
	pool.UpdatedAt = time.Now()
	d.UpdatePool(ctx, pool)

	d.logger.Info("IP released",
		slog.String("ip", ip.String()),
		slog.String("pool", alloc.PoolID),
		slog.String("device", alloc.DeviceID))

	return nil
}

// ReleaseByDeviceID releases all allocations for a device.
func (d *QuicBaaSBackend) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	if d.closed.Load() {
		return 0, ipam.ErrBackendUnavailable
	}

	if deviceID == "" {
		return 0, ipam.ErrDeviceIDRequired
	}

	allocations, err := d.GetAllocationsByDevice(ctx, deviceID)
	if err != nil {
		return 0, err
	}

	released := 0
	for _, alloc := range allocations {
		if alloc.Status == ipam.AllocationStatusActive {
			if err := d.Release(ctx, alloc.IP); err != nil {
				d.logger.Warn("failed to release allocation",
					slog.String("ip", alloc.IP.String()),
					slog.Any("error", err))
				continue
			}
			released++
		}
	}

	return released, nil
}

// Renew renews an IP allocation lease.
func (d *QuicBaaSBackend) Renew(ctx context.Context, ip netip.Addr) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	alloc, err := d.GetAllocation(ctx, ip)
	if err != nil {
		return err
	}

	if alloc.Status != ipam.AllocationStatusActive {
		return ipam.ErrAllocationReleased
	}

	if alloc.IsExpired() {
		return ipam.ErrAllocationExpired
	}

	// Get pool for default lease duration
	pool, err := d.GetPool(ctx, alloc.PoolID)
	if err != nil {
		return err
	}

	now := time.Now()
	alloc.LastSeen = now

	// Extend expiration if lease duration is set
	if pool.DefaultLeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
	}

	allocData, err := json.Marshal(alloc)
	if err != nil {
		return &ipam.ErrSerialization{EntityType: "allocation", Operation: "marshal", Cause: err}
	}

	allocID := stringToID(ip.String())
	if err := d.client.Put(ctx, entityTypeAllocation, allocID, allocData); err != nil {
		return &ipam.ErrStorageOperation{Operation: "put", Key: ip.String(), Cause: err}
	}

	return nil
}

// GetAllocation retrieves an allocation by IP.
func (d *QuicBaaSBackend) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if !ip.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	allocID := stringToID(ip.String())
	data, found, err := d.client.Get(ctx, entityTypeAllocation, allocID)
	if err != nil {
		return nil, &ipam.ErrStorageOperation{Operation: "get", Key: ip.String(), Cause: err}
	}
	if !found {
		return nil, ipam.ErrAllocationNotFound
	}

	var alloc ipam.Allocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return nil, &ipam.ErrSerialization{EntityType: "allocation", Operation: "unmarshal", Cause: err}
	}

	return &alloc, nil
}

// GetAllocationsByDevice retrieves all allocations for a device.
func (d *QuicBaaSBackend) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if deviceID == "" {
		return nil, ipam.ErrDeviceIDRequired
	}

	// List all allocations and filter by device
	var allocations []*ipam.Allocation
	var pageToken string

	for {
		entities, nextToken, err := d.client.List(ctx, entityTypeAllocation, 100, pageToken)
		if err != nil {
			return nil, &ipam.ErrStorageOperation{Operation: "list", Key: entityTypeAllocation, Cause: err}
		}

		for _, entity := range entities {
			var alloc ipam.Allocation
			if err := json.Unmarshal(entity.Data, &alloc); err != nil {
				continue
			}
			if alloc.DeviceID == deviceID {
				allocations = append(allocations, &alloc)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return allocations, nil
}

// GetAllocationsByPool retrieves all allocations for a pool.
func (d *QuicBaaSBackend) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	if poolID == "" {
		return nil, ipam.ErrInvalidPoolID
	}

	var allocations []*ipam.Allocation
	var pageToken string

	for {
		entities, nextToken, err := d.client.List(ctx, entityTypeAllocation, 100, pageToken)
		if err != nil {
			return nil, &ipam.ErrStorageOperation{Operation: "list", Key: entityTypeAllocation, Cause: err}
		}

		for _, entity := range entities {
			var alloc ipam.Allocation
			if err := json.Unmarshal(entity.Data, &alloc); err != nil {
				continue
			}
			if alloc.PoolID == poolID {
				allocations = append(allocations, &alloc)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return allocations, nil
}

// ExpireInactive marks inactive allocations as expired.
func (d *QuicBaaSBackend) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if d.closed.Load() {
		return nil, ipam.ErrBackendUnavailable
	}

	pool, err := d.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	allocations, err := d.GetAllocationsByPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	inactivityTimeout := pool.InactivityTimeout
	if inactivityTimeout == 0 {
		inactivityTimeout = defaultInactivityPeriod
	}

	now := time.Now()
	var expired []*ipam.Allocation
	expiredCount := 0

	for _, alloc := range allocations {
		if alloc.Status != ipam.AllocationStatusActive {
			continue
		}

		// Check if expired based on last seen time
		if now.Sub(alloc.LastSeen) > inactivityTimeout {
			alloc.Status = ipam.AllocationStatusExpired

			allocData, err := json.Marshal(alloc)
			if err != nil {
				continue
			}

			allocID := stringToID(alloc.IP.String())
			if err := d.client.Put(ctx, entityTypeAllocation, allocID, allocData); err != nil {
				continue
			}

			expired = append(expired, alloc)
			expiredCount++
		}
	}

	// Update pool stats
	if expiredCount > 0 {
		pool.AllocatedIPs -= uint64(expiredCount)
		pool.AvailableIPs += uint64(expiredCount)
		pool.UpdatedAt = now
		d.UpdatePool(ctx, pool)
	}

	return expired, nil
}

// Health

// Ping checks if the backend is healthy.
func (d *QuicBaaSBackend) Ping(ctx context.Context) error {
	if d.closed.Load() {
		return ipam.ErrBackendUnavailable
	}

	if !d.client.IsStarted() {
		return ipam.ErrBackendUnavailable
	}

	return nil
}

// Close closes the backend.
func (d *QuicBaaSBackend) Close() error {
	d.closed.Store(true)
	return nil
}

// Helper functions

// checkPoolNameConflict checks if a pool name already exists.
func (d *QuicBaaSBackend) checkPoolNameConflict(ctx context.Context, name, excludePoolID string) error {
	nameIndexID := stringToID("name:" + name)
	data, found, err := d.client.Get(ctx, entityTypeIndex, nameIndexID)
	if err != nil {
		return &ipam.ErrStorageOperation{Operation: "get", Key: "name:" + name, Cause: err}
	}
	if found && string(data) != excludePoolID {
		return ipam.ErrPoolNameExists
	}
	return nil
}

// checkCIDROverlap checks if a CIDR overlaps with existing pools.
func (d *QuicBaaSBackend) checkCIDROverlap(ctx context.Context, cidr netip.Prefix, excludePoolID string) error {
	pools, err := d.ListPools(ctx)
	if err != nil {
		return err
	}

	for _, pool := range pools {
		if pool.ID == excludePoolID {
			continue
		}
		if cidr.Overlaps(pool.CIDR) {
			return ipam.ErrPoolCIDROverlaps
		}
	}

	return nil
}

// stringToID converts a string to a uint64 ID using FNV-1a hashing.
func stringToID(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// Compile-time interface verification
var _ ipam.Allocator = (*QuicBaaSBackend)(nil)

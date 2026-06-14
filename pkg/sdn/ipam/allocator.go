// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"context"
	"log/slog"
	"net/netip"
)

// Allocator is the main interface for IP address management operations.
// Implementations must be safe for concurrent use.
type Allocator interface {
	// Pool management

	// CreatePool creates a new IP address pool.
	// Returns ErrPoolAlreadyExists if a pool with the same ID exists.
	// Returns ErrPoolNameExists if a pool with the same name exists.
	// Returns ErrPoolCIDROverlaps if the CIDR overlaps with an existing pool.
	CreatePool(ctx context.Context, pool *Pool) error

	// GetPool retrieves a pool by its ID.
	// Returns ErrPoolNotFound if the pool does not exist.
	GetPool(ctx context.Context, poolID string) (*Pool, error)

	// GetPoolByName retrieves a pool by its name.
	// Returns ErrPoolNotFound if no pool with that name exists.
	GetPoolByName(ctx context.Context, name string) (*Pool, error)

	// GetPoolByCIDR retrieves a pool by its CIDR.
	// Returns ErrPoolNotFound if no pool with that CIDR exists.
	GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*Pool, error)

	// ListPools returns all pools.
	ListPools(ctx context.Context) ([]*Pool, error)

	// ListPoolsByZone returns all pools whose Zone field matches zone.
	// An empty zone string returns all pools (equivalent to ListPools).
	ListPoolsByZone(ctx context.Context, zone string) ([]*Pool, error)

	// UpdatePool updates an existing pool's configuration.
	// Returns ErrPoolNotFound if the pool does not exist.
	// Note: CIDR cannot be changed after pool creation.
	UpdatePool(ctx context.Context, pool *Pool) error

	// DeletePool removes a pool and all its allocations.
	// Returns ErrPoolNotFound if the pool does not exist.
	// Returns ErrPoolHasAllocations if force is false and active allocations exist.
	DeletePool(ctx context.Context, poolID string) error

	// GetPoolStats returns statistics about a pool.
	// Returns ErrPoolNotFound if the pool does not exist.
	GetPoolStats(ctx context.Context, poolID string) (*PoolStats, error)

	// Allocation operations

	// Allocate allocates the next available IP from the specified pool.
	// Returns ErrPoolNotFound if the pool does not exist.
	// Returns ErrPoolExhausted if no IPs are available.
	// Returns ErrDeviceIDRequired if the device ID is empty.
	Allocate(ctx context.Context, req *AllocationRequest) (*Allocation, error)

	// AllocateSpecific allocates a specific IP address from a pool.
	// Returns ErrPoolNotFound if the pool does not exist.
	// Returns ErrIPNotInPool if the IP is not within the pool's CIDR.
	// Returns ErrIPAlreadyAllocated if the IP is already allocated.
	// Returns ErrNetworkAddress if the IP is a network address.
	// Returns ErrBroadcastAddress if the IP is a broadcast address.
	AllocateSpecific(ctx context.Context, req *AllocationRequest) (*Allocation, error)

	// Release releases an allocated IP address back to the pool.
	// Returns ErrAllocationNotFound if the allocation does not exist.
	Release(ctx context.Context, ip netip.Addr) error

	// ReleaseByDeviceID releases all allocations for a device.
	// Returns the number of allocations released.
	ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error)

	// Lease management

	// Renew extends the lease of an allocation.
	// Returns ErrAllocationNotFound if the allocation does not exist.
	// Returns ErrAllocationExpired if the allocation has already expired.
	Renew(ctx context.Context, ip netip.Addr) error

	// GetAllocation retrieves an allocation by IP address.
	// Returns ErrAllocationNotFound if no allocation exists for the IP.
	GetAllocation(ctx context.Context, ip netip.Addr) (*Allocation, error)

	// GetAllocationsByDevice retrieves all allocations for a device.
	GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*Allocation, error)

	// GetAllocationsByPool retrieves all allocations in a pool.
	// Returns ErrPoolNotFound if the pool does not exist.
	GetAllocationsByPool(ctx context.Context, poolID string) ([]*Allocation, error)

	// Expiration management

	// ExpireInactive marks inactive allocations as expired and returns them.
	// An allocation is inactive if LastSeen is older than the pool's InactivityTimeout.
	// Returns ErrPoolNotFound if the pool does not exist.
	ExpireInactive(ctx context.Context, poolID string) ([]*Allocation, error)

	// Health and lifecycle

	// Ping checks if the allocator backend is available.
	Ping(ctx context.Context) error

	// Close releases resources held by the allocator.
	Close() error
}

// AllocatorOption configures an allocator implementation.
type AllocatorOption func(*allocatorOptions)

type allocatorOptions struct {
	logger *slog.Logger
}

// WithLogger sets the logger for the allocator.
func WithLogger(logger *slog.Logger) AllocatorOption {
	return func(o *allocatorOptions) {
		o.logger = logger
	}
}

// AllocatorFactory creates allocators based on configuration.
type AllocatorFactory interface {
	// Create creates a new allocator with the given options.
	Create(opts ...AllocatorOption) (Allocator, error)
}

// AllocationIterator provides iteration over allocations.
type AllocationIterator interface {
	// Next advances to the next allocation.
	// Returns false when there are no more allocations.
	Next() bool

	// Allocation returns the current allocation.
	// Returns nil if Next() returned false or was never called.
	Allocation() *Allocation

	// Err returns any error that occurred during iteration.
	Err() error

	// Close releases resources held by the iterator.
	Close() error
}

// PoolIterator provides iteration over pools.
type PoolIterator interface {
	// Next advances to the next pool.
	// Returns false when there are no more pools.
	Next() bool

	// Pool returns the current pool.
	// Returns nil if Next() returned false or was never called.
	Pool() *Pool

	// Err returns any error that occurred during iteration.
	Err() error

	// Close releases resources held by the iterator.
	Close() error
}

// BatchAllocator provides batch allocation operations for efficiency.
type BatchAllocator interface {
	Allocator

	// AllocateBatch allocates multiple IPs in a single operation.
	// Returns the allocations that were successful.
	// If any allocation fails, partial results may be returned with an error.
	AllocateBatch(ctx context.Context, reqs []*AllocationRequest) ([]*Allocation, error)

	// ReleaseBatch releases multiple IPs in a single operation.
	// Returns the number of successful releases.
	ReleaseBatch(ctx context.Context, ips []netip.Addr) (int, error)
}

// ReservationAllocator provides IP reservation capabilities.
type ReservationAllocator interface {
	Allocator

	// Reserve marks an IP as reserved, preventing automatic allocation.
	// Returns ErrIPAlreadyAllocated if the IP is already allocated.
	Reserve(ctx context.Context, poolID string, ip netip.Addr, description string) error

	// Unreserve removes a reservation, making the IP available for allocation.
	// Returns ErrAllocationNotFound if the IP is not reserved.
	Unreserve(ctx context.Context, ip netip.Addr) error

	// ListReservations returns all reserved IPs in a pool.
	ListReservations(ctx context.Context, poolID string) ([]*Allocation, error)
}

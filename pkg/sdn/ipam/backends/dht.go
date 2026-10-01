//go:build platform_p2p

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

// Package backends provides IPAM allocator implementations for different
// storage backends including DHT for distributed P2P environments.
package backends

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/p2p"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	dht "github.com/libp2p/go-libp2p-kad-dht"
)

// DHT key namespaces for IPAM data.
const (
	dhtPoolPrefix       = "/ipam/pool/"
	dhtAllocationPrefix = "/ipam/alloc/"
	dhtDevicePrefix     = "/ipam/device/"
)

// Timing constants for DHT operations.
const (
	// claimTimeout is how long to wait for DHT propagation when verifying claims.
	claimTimeout = 5 * time.Second

	// claimPropagationDelay is a brief delay before verifying a claim.
	claimPropagationDelay = 100 * time.Millisecond

	// maxAllocationRetries is the maximum number of random IP attempts.
	maxAllocationRetries = 50

	// dhtOperationTimeout is the default timeout for DHT operations.
	dhtOperationTimeout = 10 * time.Second
)

// DHTBackend implements ipam.Allocator using libp2p's Kademlia DHT for
// decentralized IP allocation. It uses a claim-based approach for eventual
// consistency: generate candidate IP, claim in DHT, verify claim.
type DHTBackend struct {
	node   *p2p.Node
	dht    *dht.IpfsDHT
	peerID string
	logger *slog.Logger

	// Local cache for pools (DHT is slow for metadata lookups)
	poolCache sync.Map // map[string]*ipam.Pool

	// Local index for name lookups
	poolNameIndex sync.Map // map[string]string (name -> poolID)

	// Local index for CIDR lookups
	poolCIDRIndex sync.Map // map[string]string (CIDR string -> poolID)
}

// Ensure DHTBackend implements ipam.Allocator.
var _ ipam.Allocator = (*DHTBackend)(nil)

// NewDHTBackend creates a new DHT-backed IPAM allocator.
func NewDHTBackend(node *p2p.Node, opts ...ipam.AllocatorOption) (*DHTBackend, error) {
	if node == nil {
		return nil, &ErrDHTBackendInit{Reason: "p2p node is required"}
	}

	kadDHT := node.DHT()
	if kadDHT == nil {
		return nil, &ErrDHTBackendInit{Reason: "p2p node DHT is not initialized"}
	}

	peerID := node.PeerID()
	if peerID == "" {
		return nil, &ErrDHTBackendInit{Reason: "p2p node has no peer ID"}
	}

	return &DHTBackend{
		node:   node,
		dht:    kadDHT,
		peerID: peerID.String(),
		logger: slog.Default().With(slog.String("component", "ipam-dht")),
	}, nil
}

// Pool Management
// Note: Pool metadata is stored in DHT and cached locally for performance.

// CreatePool creates a new IP address pool.
func (d *DHTBackend) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	if pool == nil {
		return ipam.ErrInvalidPoolID
	}
	if pool.ID == "" {
		return ipam.ErrInvalidPoolID
	}
	if pool.Name == "" {
		return ipam.ErrInvalidPoolName
	}
	if err := ipam.NewPoolManager().ValidatePool(pool); err != nil {
		return err
	}

	// Check if pool already exists
	if _, loaded := d.poolCache.Load(pool.ID); loaded {
		return ipam.ErrPoolAlreadyExists
	}

	// Check name uniqueness
	if _, loaded := d.poolNameIndex.Load(pool.Name); loaded {
		return ipam.ErrPoolNameExists
	}

	// Check CIDR uniqueness
	if _, loaded := d.poolCIDRIndex.Load(pool.CIDR.String()); loaded {
		return ipam.ErrPoolCIDROverlaps
	}

	// Initialize pool stats: what is actually allocatable.
	pool.TotalIPs = pool.AllocatableIPs()
	pool.AvailableIPs = pool.TotalIPs
	pool.AllocatedIPs = 0

	now := time.Now()
	pool.CreatedAt = now
	pool.UpdatedAt = now

	// Store in DHT
	key := dhtPoolPrefix + pool.ID
	data, err := json.Marshal(pool)
	if err != nil {
		return &ipam.ErrPoolOperationFailed{PoolID: pool.ID, Operation: "create", Cause: err}
	}

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	if err := d.dht.PutValue(opCtx, key, data); err != nil {
		return &ipam.ErrPoolOperationFailed{PoolID: pool.ID, Operation: "create", Cause: err}
	}

	// Update local caches
	d.poolCache.Store(pool.ID, pool.Clone())
	d.poolNameIndex.Store(pool.Name, pool.ID)
	d.poolCIDRIndex.Store(pool.CIDR.String(), pool.ID)

	d.logger.Info("pool created",
		slog.String("pool_id", pool.ID),
		slog.String("cidr", pool.CIDR.String()),
		slog.Uint64("total_ips", pool.TotalIPs))

	return nil
}

// GetPool retrieves a pool by its ID.
func (d *DHTBackend) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	if poolID == "" {
		return nil, ipam.ErrInvalidPoolID
	}

	// Check local cache first
	if cached, ok := d.poolCache.Load(poolID); ok {
		return cached.(*ipam.Pool).Clone(), nil
	}

	// Try DHT
	if d.dht == nil {
		return nil, ipam.ErrPoolNotFound
	}
	key := dhtPoolPrefix + poolID

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	data, err := d.dht.GetValue(opCtx, key)
	if err != nil {
		return nil, ipam.ErrPoolNotFound
	}

	pool := &ipam.Pool{}
	if err := json.Unmarshal(data, pool); err != nil {
		return nil, &ipam.ErrPoolOperationFailed{PoolID: poolID, Operation: "get", Cause: err}
	}

	// Cache locally
	d.poolCache.Store(poolID, pool.Clone())
	d.poolNameIndex.Store(pool.Name, pool.ID)
	d.poolCIDRIndex.Store(pool.CIDR.String(), pool.ID)

	return pool, nil
}

// GetPoolByName retrieves a pool by its name.
func (d *DHTBackend) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	if name == "" {
		return nil, ipam.ErrInvalidPoolName
	}

	// Check local index
	if poolID, ok := d.poolNameIndex.Load(name); ok {
		return d.GetPool(ctx, poolID.(string))
	}

	// Not in local cache - would need to scan DHT which is expensive
	// For now, return not found. A full implementation would need a name index in DHT.
	return nil, ipam.ErrPoolNotFound
}

// GetPoolByCIDR retrieves a pool by its CIDR.
func (d *DHTBackend) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	if !cidr.IsValid() {
		return nil, ipam.ErrInvalidCIDR
	}

	// Check local index
	if poolID, ok := d.poolCIDRIndex.Load(cidr.String()); ok {
		return d.GetPool(ctx, poolID.(string))
	}

	return nil, ipam.ErrPoolNotFound
}

// ListPools returns all pools.
func (d *DHTBackend) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	var pools []*ipam.Pool

	d.poolCache.Range(func(key, value any) bool {
		pool := value.(*ipam.Pool)
		pools = append(pools, pool.Clone())
		return true
	})

	return pools, nil
}

// ListPoolsByZone returns all pools whose Zone field matches zone.
// An empty zone returns all pools (equivalent to ListPools).
func (d *DHTBackend) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	if zone == "" {
		return d.ListPools(ctx)
	}
	var filtered []*ipam.Pool
	d.poolCache.Range(func(key, value any) bool {
		pool := value.(*ipam.Pool)
		if pool.Zone == zone {
			filtered = append(filtered, pool.Clone())
		}
		return true
	})
	return filtered, nil
}

// UpdatePool updates an existing pool's configuration.
func (d *DHTBackend) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	if pool == nil || pool.ID == "" {
		return ipam.ErrInvalidPoolID
	}

	existing, err := d.GetPool(ctx, pool.ID)
	if err != nil {
		return err
	}

	// CIDR cannot be changed
	if pool.CIDR != existing.CIDR {
		return &ipam.ErrPoolOperationFailed{
			PoolID:    pool.ID,
			Operation: "update",
			Cause:     &MessageError{Msg: "CIDR cannot be changed after pool creation"},
		}
	}

	// Validate and check the name before changing anything, so a refused
	// update leaves the index and the store exactly as they were.
	if err := ipam.NewPoolManager().ValidatePool(pool); err != nil {
		return err
	}
	renamed := pool.Name != existing.Name
	if renamed {
		if _, loaded := d.poolNameIndex.Load(pool.Name); loaded {
			return ipam.ErrPoolNameExists
		}
	}

	pool.UpdatedAt = time.Now()
	pool.CreatedAt = existing.CreatedAt
	pool.AllocatedIPs = existing.AllocatedIPs
	// The size follows the (possibly changed) reserved prefixes.
	pool.TotalIPs = pool.AllocatableIPs()
	pool.AvailableIPs = 0
	if pool.TotalIPs > pool.AllocatedIPs {
		pool.AvailableIPs = pool.TotalIPs - pool.AllocatedIPs
	}

	// Store in DHT
	key := dhtPoolPrefix + pool.ID
	data, err := json.Marshal(pool)
	if err != nil {
		return &ipam.ErrPoolOperationFailed{PoolID: pool.ID, Operation: "update", Cause: err}
	}

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	if err := d.dht.PutValue(opCtx, key, data); err != nil {
		return &ipam.ErrPoolOperationFailed{PoolID: pool.ID, Operation: "update", Cause: err}
	}

	if renamed {
		d.poolNameIndex.Delete(existing.Name)
		d.poolNameIndex.Store(pool.Name, pool.ID)
	}
	d.poolCache.Store(pool.ID, pool.Clone())

	return nil
}

// DeletePool removes a pool.
func (d *DHTBackend) DeletePool(ctx context.Context, poolID string) error {
	if poolID == "" {
		return ipam.ErrInvalidPoolID
	}

	pool, err := d.GetPool(ctx, poolID)
	if err != nil {
		return err
	}

	// Check for active allocations
	if pool.AllocatedIPs > 0 {
		return ipam.ErrPoolHasAllocations
	}

	// Remove from local caches
	d.poolCache.Delete(poolID)
	d.poolNameIndex.Delete(pool.Name)
	d.poolCIDRIndex.Delete(pool.CIDR.String())

	// Note: DHT does not support deletion directly.
	// The entry will eventually expire from DHT.
	d.logger.Info("pool deleted",
		slog.String("pool_id", poolID))

	return nil
}

// GetPoolStats returns statistics about a pool.
func (d *DHTBackend) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	pool, err := d.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	stats := &ipam.PoolStats{
		PoolID:       poolID,
		TotalIPs:     pool.TotalIPs,
		AllocatedIPs: pool.AllocatedIPs,
		AvailableIPs: pool.AvailableIPs,
	}
	stats.CalculateUtilization()

	return stats, nil
}

// Allocation Operations - Claim-based with random IP selection

// Allocate allocates the next available IP from a pool using random selection.
func (d *DHTBackend) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	pool, err := d.GetPool(ctx, req.PoolID)
	if err != nil {
		return nil, err
	}

	// Try random addresses of the dynamic window until one succeeds.
	for attempt := 0; attempt < maxAllocationRetries; attempt++ {
		ip, err := pool.RandomDynamic()
		var reserved *ipam.ErrIPReserved
		if errors.As(err, &reserved) {
			continue
		}
		if errors.Is(err, ipam.ErrPoolExhausted) {
			return nil, err
		}
		if err != nil {
			return nil, &ipam.ErrAllocationFailed{PoolID: req.PoolID, Reason: "failed to generate random IP", Cause: err}
		}

		// Skip network and broadcast addresses
		if isNetworkOrBroadcast(pool.CIDR, ip) {
			continue
		}

		// Try to claim this IP
		alloc, err := d.tryClaim(ctx, pool, ip, req)
		if err == nil {
			return alloc, nil
		}

		if err != ipam.ErrIPAlreadyAllocated {
			return nil, err
		}

		// IP taken, try another
		d.logger.Debug("IP already claimed, retrying",
			slog.String("ip", ip.String()),
			slog.Int("attempt", attempt))
	}

	return nil, &ipam.ErrAllocationFailed{
		PoolID: req.PoolID,
		Reason: "max retries exceeded, pool may be exhausted",
	}
}

// AllocateSpecific allocates a specific IP address from a pool.
func (d *DHTBackend) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	if !req.RequestedIP.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	pool, err := d.GetPool(ctx, req.PoolID)
	if err != nil {
		return nil, err
	}

	// The address must be in the pool, usable, and not reserved.
	if err := pool.CheckSpecific(req.RequestedIP); err != nil {
		return nil, err
	}

	return d.tryClaim(ctx, pool, req.RequestedIP, req)
}

// tryClaim attempts to claim an IP address in the DHT.
func (d *DHTBackend) tryClaim(ctx context.Context, pool *ipam.Pool, ip netip.Addr, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	key := d.allocationKey(ip)

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	// Check if already allocated
	existing, err := d.dht.GetValue(opCtx, key)
	if err == nil && len(existing) > 0 {
		var existingAlloc ipam.Allocation
		if err := json.Unmarshal(existing, &existingAlloc); err == nil {
			if existingAlloc.Status == ipam.AllocationStatusActive {
				return nil, ipam.ErrIPAlreadyAllocated
			}
		}
	}

	// Create allocation
	now := time.Now()
	alloc := &ipam.Allocation{
		ID:          d.generateAllocationID(ip),
		PoolID:      pool.ID,
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

	// Set expiration
	if req.LeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(req.LeaseDuration)
	} else if pool.DefaultLeaseDuration > 0 {
		alloc.ExpiresAt = now.Add(pool.DefaultLeaseDuration)
	}

	// Claim in DHT
	data, err := json.Marshal(alloc)
	if err != nil {
		return nil, &ipam.ErrAllocationFailed{PoolID: pool.ID, Reason: "marshal failed", Cause: err}
	}

	if err := d.dht.PutValue(opCtx, key, data); err != nil {
		return nil, &ipam.ErrAllocationFailed{PoolID: pool.ID, Reason: "DHT put failed", Cause: err}
	}

	// Store device index
	deviceKey := d.deviceKey(req.DeviceID, ip)
	if err := d.dht.PutValue(opCtx, deviceKey, data); err != nil {
		d.logger.Warn("failed to store device index",
			slog.String("device_id", req.DeviceID),
			slog.Any("error", err))
	}

	// Brief wait for DHT propagation
	select {
	case <-time.After(claimPropagationDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Verify claim (DHT is eventually consistent)
	verifyCtx, verifyCancel := context.WithTimeout(ctx, claimTimeout)
	defer verifyCancel()

	verified, err := d.dht.GetValue(verifyCtx, key)
	if err != nil {
		return nil, &ipam.ErrAllocationFailed{PoolID: pool.ID, Reason: "verification failed", Cause: err}
	}

	var verifiedAlloc ipam.Allocation
	if err := json.Unmarshal(verified, &verifiedAlloc); err != nil {
		return nil, &ipam.ErrAllocationFailed{PoolID: pool.ID, Reason: "verification unmarshal failed", Cause: err}
	}

	// Check if our claim won
	if verifiedAlloc.DeviceID != req.DeviceID {
		return nil, ipam.ErrIPAlreadyAllocated
	}

	// Update pool stats (best effort, may be stale in distributed system)
	d.updatePoolStats(ctx, pool.ID, 1)

	d.logger.Info("IP allocated via DHT",
		slog.String("ip", ip.String()),
		slog.String("device", req.DeviceID),
		slog.String("pool", pool.ID))

	return alloc, nil
}

// Release releases an allocated IP address back to the pool.
func (d *DHTBackend) Release(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	key := d.allocationKey(ip)

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	// Get existing allocation
	data, err := d.dht.GetValue(opCtx, key)
	if err != nil {
		return ipam.ErrAllocationNotFound
	}

	var alloc ipam.Allocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return &ipam.ErrAllocationFailed{PoolID: "", Reason: "unmarshal failed", Cause: err}
	}

	// Mark as released
	alloc.Status = ipam.AllocationStatusReleased
	alloc.ReleasedAt = time.Now()

	// Update in DHT
	data, err = json.Marshal(alloc)
	if err != nil {
		return &ipam.ErrAllocationFailed{PoolID: alloc.PoolID, Reason: "marshal failed", Cause: err}
	}

	if err := d.dht.PutValue(opCtx, key, data); err != nil {
		return &ipam.ErrAllocationFailed{PoolID: alloc.PoolID, Reason: "DHT put failed", Cause: err}
	}

	// Update pool stats
	d.updatePoolStats(ctx, alloc.PoolID, -1)

	d.logger.Info("IP released via DHT",
		slog.String("ip", ip.String()),
		slog.String("device", alloc.DeviceID))

	return nil
}

// ReleaseByDeviceID releases all allocations for a device.
func (d *DHTBackend) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	if deviceID == "" {
		return 0, ipam.ErrDeviceIDRequired
	}

	allocs, err := d.GetAllocationsByDevice(ctx, deviceID)
	if err != nil {
		return 0, err
	}

	released := 0
	for _, alloc := range allocs {
		if err := d.Release(ctx, alloc.IP); err == nil {
			released++
		}
	}

	return released, nil
}

// Renew extends the lease of an allocation.
func (d *DHTBackend) Renew(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return ipam.ErrInvalidIP
	}

	key := d.allocationKey(ip)

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	data, err := d.dht.GetValue(opCtx, key)
	if err != nil {
		return ipam.ErrAllocationNotFound
	}

	var alloc ipam.Allocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return &ipam.ErrAllocationFailed{PoolID: "", Reason: "unmarshal failed", Cause: err}
	}

	if alloc.Status != ipam.AllocationStatusActive {
		return ipam.ErrAllocationReleased
	}

	if alloc.IsExpired() {
		return ipam.ErrAllocationExpired
	}

	// Update last seen
	alloc.LastSeen = time.Now()

	data, err = json.Marshal(alloc)
	if err != nil {
		return &ipam.ErrAllocationFailed{PoolID: alloc.PoolID, Reason: "marshal failed", Cause: err}
	}

	return d.dht.PutValue(opCtx, key, data)
}

// GetAllocation retrieves an allocation by IP address.
func (d *DHTBackend) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if !ip.IsValid() {
		return nil, ipam.ErrInvalidIP
	}

	key := d.allocationKey(ip)

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	data, err := d.dht.GetValue(opCtx, key)
	if err != nil {
		return nil, ipam.ErrAllocationNotFound
	}

	var alloc ipam.Allocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return nil, &ipam.ErrAllocationFailed{PoolID: "", Reason: "unmarshal failed", Cause: err}
	}

	return &alloc, nil
}

// GetAllocationsByDevice retrieves all allocations for a device.
func (d *DHTBackend) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	if deviceID == "" {
		return nil, ipam.ErrDeviceIDRequired
	}

	// Note: This is a simplified implementation. A full implementation would
	// need to maintain a device -> allocations index in DHT or use a separate
	// data store for efficient device lookups.
	// For now, we return empty as scanning DHT is not practical.
	return []*ipam.Allocation{}, nil
}

// GetAllocationsByPool retrieves all allocations in a pool.
func (d *DHTBackend) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if poolID == "" {
		return nil, ipam.ErrInvalidPoolID
	}

	_, err := d.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	// Note: Similar to GetAllocationsByDevice, scanning DHT is not practical.
	// A full implementation would need an index or separate data store.
	return []*ipam.Allocation{}, nil
}

// ExpireInactive marks inactive allocations as expired.
func (d *DHTBackend) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	if poolID == "" {
		return nil, ipam.ErrInvalidPoolID
	}

	_, err := d.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}

	// Note: Expiration in a distributed DHT system is complex.
	// Each node would need to track its own allocations and expire them.
	// For now, return empty as this requires more sophisticated distributed coordination.
	return []*ipam.Allocation{}, nil
}

// Ping checks if the allocator backend is available.
func (d *DHTBackend) Ping(ctx context.Context) error {
	if d.node == nil {
		return ipam.ErrBackendUnavailable
	}

	if !d.node.IsRunning() {
		return ipam.ErrBackendUnavailable
	}

	opCtx, cancel := context.WithTimeout(ctx, dhtOperationTimeout)
	defer cancel()

	// Check DHT is responsive by getting closest peers
	_, err := d.dht.GetClosestPeers(opCtx, "ipam-health-check")
	if err != nil {
		return ipam.ErrBackendUnavailable
	}

	return nil
}

// Close releases resources held by the allocator.
func (d *DHTBackend) Close() error {
	// Node lifecycle is managed externally
	return nil
}

// Helper methods

// allocationKey returns the DHT key for an IP allocation.
func (d *DHTBackend) allocationKey(ip netip.Addr) string {
	return dhtAllocationPrefix + ip.String()
}

// deviceKey returns the DHT key for a device's allocation.
func (d *DHTBackend) deviceKey(deviceID string, ip netip.Addr) string {
	return dhtDevicePrefix + deviceID + "/" + ip.String()
}

// generateAllocationID generates a unique allocation ID.
func (d *DHTBackend) generateAllocationID(ip netip.Addr) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", d.peerID, ip.String(), time.Now().UnixNano())))
	return fmt.Sprintf("%x", h[:8])
}

// updatePoolStats updates the pool statistics in the cache.
func (d *DHTBackend) updatePoolStats(ctx context.Context, poolID string, delta int64) {
	if cached, ok := d.poolCache.Load(poolID); ok {
		pool := cached.(*ipam.Pool)
		if delta > 0 {
			pool.AllocatedIPs += uint64(delta)
			if pool.AvailableIPs >= uint64(delta) {
				pool.AvailableIPs -= uint64(delta)
			}
		} else {
			if pool.AllocatedIPs >= uint64(-delta) {
				pool.AllocatedIPs -= uint64(-delta)
			}
			pool.AvailableIPs += uint64(-delta)
		}
		pool.UpdatedAt = time.Now()
		d.poolCache.Store(poolID, pool)
	}
}

// Utility functions for IP address calculations

// calculatePoolSize calculates the number of usable IPs in a CIDR block.
func calculatePoolSize(cidr netip.Prefix) uint64 {
	bits := cidr.Bits()
	if cidr.Addr().Is4() {
		// IPv4
		if bits >= 32 {
			return 1
		}
		hostBits := 32 - bits
		if hostBits > 30 {
			hostBits = 30 // Cap at /2 to avoid overflow
		}
		size := uint64(1) << hostBits
		// Subtract network and broadcast addresses for non-/31 and non-/32
		if bits < 31 {
			return size - 2
		}
		return size
	}

	// IPv6
	if bits >= 128 {
		return 1
	}
	hostBits := 128 - bits
	if hostBits > 63 {
		hostBits = 63 // Cap to avoid uint64 overflow
	}
	return uint64(1) << hostBits
}

// randomIPInCIDR generates a random IP address within a CIDR block.
func randomIPInCIDR(cidr netip.Prefix) (netip.Addr, error) {
	bits := cidr.Bits()
	addr := cidr.Addr()

	if addr.Is4() {
		return randomIPv4InCIDR(cidr, bits)
	}
	return randomIPv6InCIDR(cidr, bits)
}

// randomIPv4InCIDR generates a random IPv4 address within a CIDR block.
func randomIPv4InCIDR(cidr netip.Prefix, bits int) (netip.Addr, error) {
	hostBits := 32 - bits
	if hostBits == 0 {
		return cidr.Addr(), nil
	}

	// Generate random host portion
	maxHost := uint32(1)<<hostBits - 1
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return netip.Addr{}, err
	}

	hostPart := binary.BigEndian.Uint32(randBytes) & maxHost

	// Combine network and host portions
	addrBytes := cidr.Addr().As4()
	networkPart := binary.BigEndian.Uint32(addrBytes[:])
	networkMask := ^((uint32(1) << hostBits) - 1)
	result := (networkPart & networkMask) | hostPart

	var resultBytes [4]byte
	binary.BigEndian.PutUint32(resultBytes[:], result)

	return netip.AddrFrom4(resultBytes), nil
}

// randomIPv6InCIDR generates a random IPv6 address within a CIDR block.
func randomIPv6InCIDR(cidr netip.Prefix, bits int) (netip.Addr, error) {
	hostBits := 128 - bits
	if hostBits == 0 {
		return cidr.Addr(), nil
	}

	baseAddr := cidr.Addr().As16()
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return netip.Addr{}, err
	}

	// Create result by combining network portion with random host portion
	var result [16]byte
	copy(result[:], baseAddr[:])

	// Apply random bits to the host portion
	fullBytes := hostBits / 8
	partialBits := hostBits % 8

	// Fill full bytes from the end
	for i := 0; i < fullBytes && i < 16; i++ {
		result[15-i] = randBytes[15-i]
	}

	// Handle partial byte
	if partialBits > 0 && fullBytes < 16 {
		byteIndex := 15 - fullBytes
		mask := byte((1 << partialBits) - 1)
		result[byteIndex] = (result[byteIndex] & ^mask) | (randBytes[byteIndex] & mask)
	}

	return netip.AddrFrom16(result), nil
}

// isNetworkOrBroadcast returns true if the IP is a network or broadcast address.
func isNetworkOrBroadcast(cidr netip.Prefix, ip netip.Addr) bool {
	return isNetworkAddress(cidr, ip) || isBroadcastAddress(cidr, ip)
}

// isNetworkAddress returns true if the IP is the network address.
func isNetworkAddress(cidr netip.Prefix, ip netip.Addr) bool {
	// /31 and /32 have no network address (RFC 3021)
	bits := cidr.Bits()
	if bits >= 31 {
		return false
	}

	// For IPv6, there's no traditional network address concept
	if ip.Is6() {
		return false
	}
	return ip == cidr.Masked().Addr()
}

// isBroadcastAddress returns true if the IP is the broadcast address.
func isBroadcastAddress(cidr netip.Prefix, ip netip.Addr) bool {
	// IPv6 doesn't have broadcast addresses
	if ip.Is6() {
		return false
	}

	bits := cidr.Bits()
	if bits >= 31 {
		return false // /31 and /32 have no broadcast
	}

	// Calculate broadcast address
	networkAddr := cidr.Masked().Addr().As4()
	hostBits := 32 - bits
	hostMask := uint32((1 << hostBits) - 1)

	networkInt := binary.BigEndian.Uint32(networkAddr[:])
	broadcastInt := networkInt | hostMask

	ipBytes := ip.As4()
	ipInt := binary.BigEndian.Uint32(ipBytes[:])
	return ipInt == broadcastInt
}

// CalculatePoolSize is exported for use by other packages.
func CalculatePoolSize(cidr netip.Prefix) uint64 {
	return calculatePoolSize(cidr)
}

// RandomIPInCIDR is exported for use by other packages.
func RandomIPInCIDR(cidr netip.Prefix) (netip.Addr, error) {
	return randomIPInCIDR(cidr)
}

// IsNetworkOrBroadcast is exported for use by other packages.
func IsNetworkOrBroadcast(cidr netip.Prefix, ip netip.Addr) bool {
	return isNetworkOrBroadcast(cidr, ip)
}

// CalculateBroadcastAddress calculates the broadcast address for an IPv4 CIDR.
func CalculateBroadcastAddress(cidr netip.Prefix) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, ipam.ErrInvalidCIDR
	}
	if cidr.Addr().Is6() {
		return netip.Addr{}, &MessageError{Msg: "IPv6 does not have broadcast addresses"}
	}

	bits := cidr.Bits()
	if bits >= 31 {
		return netip.Addr{}, &MessageError{Msg: "/31 and /32 networks have no broadcast address"}
	}

	networkAddr := cidr.Masked().Addr().As4()
	hostBits := 32 - bits
	hostMask := uint32((1 << hostBits) - 1)

	networkInt := binary.BigEndian.Uint32(networkAddr[:])
	broadcastInt := networkInt | hostMask

	var broadcastBytes [4]byte
	binary.BigEndian.PutUint32(broadcastBytes[:], broadcastInt)

	return netip.AddrFrom4(broadcastBytes), nil
}

// ipToBigInt converts an IP address to a big.Int.
func ipToBigInt(ip netip.Addr) *big.Int {
	if ip.Is4() {
		ipBytes := ip.As4()
		return new(big.Int).SetBytes(ipBytes[:])
	}
	ipBytes := ip.As16()
	return new(big.Int).SetBytes(ipBytes[:])
}

// bigIntToIPv4 converts a big.Int to an IPv4 address.
func bigIntToIPv4(n *big.Int) netip.Addr {
	bytes := n.Bytes()
	var addr [4]byte
	// Right-align the bytes
	offset := 4 - len(bytes)
	if offset < 0 {
		offset = 0
		bytes = bytes[len(bytes)-4:]
	}
	copy(addr[offset:], bytes)
	return netip.AddrFrom4(addr)
}

// bigIntToIPv6 converts a big.Int to an IPv6 address.
func bigIntToIPv6(n *big.Int) netip.Addr {
	bytes := n.Bytes()
	var addr [16]byte
	// Right-align the bytes
	offset := 16 - len(bytes)
	if offset < 0 {
		offset = 0
		bytes = bytes[len(bytes)-16:]
	}
	copy(addr[offset:], bytes)
	return netip.AddrFrom16(addr)
}

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
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Tracker monitors real-time resource usage with atomic operations.
type Tracker struct {
	store  QuotaStore
	logger *slog.Logger

	// cache holds in-memory usage per tenant.
	// Key is tenantID, value is *usageCache.
	cache sync.Map

	// syncInterval is the interval at which to sync usage to storage.
	syncInterval time.Duration
}

// usageCache holds atomic counters for tenant resource usage.
type usageCache struct {
	vms           atomic.Int64
	containers    atomic.Int64
	vcpus         atomic.Int64
	memoryMB      atomic.Int64
	diskGB        atomic.Int64
	bridges       atomic.Int64
	ports         atomic.Int64
	bandwidthMbps atomic.Int64
	volumes       atomic.Int64
	snapshots     atomic.Int64

	lastSync atomic.Value // time.Time
}

// newUsageCache creates a new usage cache initialized from existing usage.
func newUsageCache(usage *TenantUsage) *usageCache {
	c := &usageCache{}
	c.lastSync.Store(time.Now())

	if usage != nil {
		c.vms.Store(usage.VMs)
		c.containers.Store(usage.Containers)
		c.vcpus.Store(usage.VCPUs)
		c.memoryMB.Store(usage.MemoryMB)
		c.diskGB.Store(usage.DiskGB)
		c.bridges.Store(usage.Bridges)
		c.ports.Store(usage.Ports)
		c.bandwidthMbps.Store(usage.BandwidthMbps)
		c.volumes.Store(usage.Volumes)
		c.snapshots.Store(usage.Snapshots)
	}

	return c
}

// get returns the counter for a specific resource type.
func (c *usageCache) get(resource ResourceType) int64 {
	switch resource {
	case ResourceVMs:
		return c.vms.Load()
	case ResourceContainers:
		return c.containers.Load()
	case ResourceVCPUs:
		return c.vcpus.Load()
	case ResourceMemory:
		return c.memoryMB.Load()
	case ResourceDisk:
		return c.diskGB.Load()
	case ResourceBridges:
		return c.bridges.Load()
	case ResourcePorts:
		return c.ports.Load()
	case ResourceBandwidth:
		return c.bandwidthMbps.Load()
	case ResourceVolumes:
		return c.volumes.Load()
	case ResourceSnapshots:
		return c.snapshots.Load()
	default:
		return 0
	}
}

// add atomically adds to a resource counter, returning the new value.
func (c *usageCache) add(resource ResourceType, delta int64) int64 {
	switch resource {
	case ResourceVMs:
		return c.vms.Add(delta)
	case ResourceContainers:
		return c.containers.Add(delta)
	case ResourceVCPUs:
		return c.vcpus.Add(delta)
	case ResourceMemory:
		return c.memoryMB.Add(delta)
	case ResourceDisk:
		return c.diskGB.Add(delta)
	case ResourceBridges:
		return c.bridges.Add(delta)
	case ResourcePorts:
		return c.ports.Add(delta)
	case ResourceBandwidth:
		return c.bandwidthMbps.Add(delta)
	case ResourceVolumes:
		return c.volumes.Add(delta)
	case ResourceSnapshots:
		return c.snapshots.Add(delta)
	default:
		return 0
	}
}

// set atomically sets a resource counter value.
func (c *usageCache) set(resource ResourceType, value int64) {
	switch resource {
	case ResourceVMs:
		c.vms.Store(value)
	case ResourceContainers:
		c.containers.Store(value)
	case ResourceVCPUs:
		c.vcpus.Store(value)
	case ResourceMemory:
		c.memoryMB.Store(value)
	case ResourceDisk:
		c.diskGB.Store(value)
	case ResourceBridges:
		c.bridges.Store(value)
	case ResourcePorts:
		c.ports.Store(value)
	case ResourceBandwidth:
		c.bandwidthMbps.Store(value)
	case ResourceVolumes:
		c.volumes.Store(value)
	case ResourceSnapshots:
		c.snapshots.Store(value)
	}
}

// toTenantUsage converts the cache to a TenantUsage struct.
func (c *usageCache) toTenantUsage(tenantID string) *TenantUsage {
	lastSync, _ := c.lastSync.Load().(time.Time)
	return &TenantUsage{
		TenantID:      tenantID,
		VMs:           c.vms.Load(),
		Containers:    c.containers.Load(),
		VCPUs:         c.vcpus.Load(),
		MemoryMB:      c.memoryMB.Load(),
		DiskGB:        c.diskGB.Load(),
		Bridges:       c.bridges.Load(),
		Ports:         c.ports.Load(),
		BandwidthMbps: c.bandwidthMbps.Load(),
		Volumes:       c.volumes.Load(),
		Snapshots:     c.snapshots.Load(),
		Timestamp:     lastSync,
	}
}

// TrackerOption is a functional option for configuring the Tracker.
type TrackerOption func(*Tracker)

// WithSyncInterval sets the sync interval for the tracker.
func WithSyncInterval(interval time.Duration) TrackerOption {
	return func(t *Tracker) {
		t.syncInterval = interval
	}
}

// NewTracker creates a new usage tracker.
func NewTracker(store QuotaStore, logger *slog.Logger, opts ...TrackerOption) (*Tracker, error) {
	if store == nil {
		return nil, ErrNilStore{}
	}
	if logger == nil {
		return nil, ErrNilLogger{}
	}

	t := &Tracker{
		store:        store,
		logger:       logger,
		syncInterval: time.Minute,
	}

	for _, opt := range opts {
		opt(t)
	}

	return t, nil
}

// getOrCreateCache gets or creates a usage cache for a tenant.
func (t *Tracker) getOrCreateCache(ctx context.Context, tenantID string) (*usageCache, error) {
	if value, ok := t.cache.Load(tenantID); ok {
		return value.(*usageCache), nil
	}

	// Load from store.
	usage, err := t.store.GetUsage(ctx, tenantID)
	if err != nil {
		return nil, ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	cache := newUsageCache(usage)
	actual, _ := t.cache.LoadOrStore(tenantID, cache)
	return actual.(*usageCache), nil
}

// Increment adds to resource usage.
func (t *Tracker) Increment(ctx context.Context, tenantID string, resource ResourceType, amount int64) error {
	if !resource.IsValid() {
		return ErrInvalidResource{Resource: resource}
	}
	if amount < 0 {
		return ErrInvalidAmount{Resource: resource, Amount: amount}
	}

	cache, err := t.getOrCreateCache(ctx, tenantID)
	if err != nil {
		return err
	}

	newValue := cache.add(resource, amount)

	t.logger.Debug("usage incremented",
		slog.String("tenant_id", tenantID),
		slog.String("resource", string(resource)),
		slog.Int64("amount", amount),
		slog.Int64("new_value", newValue),
	)

	return nil
}

// Decrement subtracts from resource usage.
func (t *Tracker) Decrement(ctx context.Context, tenantID string, resource ResourceType, amount int64) error {
	if !resource.IsValid() {
		return ErrInvalidResource{Resource: resource}
	}
	if amount < 0 {
		return ErrInvalidAmount{Resource: resource, Amount: amount}
	}

	cache, err := t.getOrCreateCache(ctx, tenantID)
	if err != nil {
		return err
	}

	// Ensure we don't go below zero.
	for {
		current := cache.get(resource)
		newValue := current - amount
		if newValue < 0 {
			newValue = 0
		}

		// Use compare-and-swap for safe decrement.
		switch resource {
		case ResourceVMs:
			if cache.vms.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceContainers:
			if cache.containers.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceVCPUs:
			if cache.vcpus.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceMemory:
			if cache.memoryMB.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceDisk:
			if cache.diskGB.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceBridges:
			if cache.bridges.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourcePorts:
			if cache.ports.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceBandwidth:
			if cache.bandwidthMbps.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceVolumes:
			if cache.volumes.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		case ResourceSnapshots:
			if cache.snapshots.CompareAndSwap(current, newValue) {
				t.logger.Debug("usage decremented",
					slog.String("tenant_id", tenantID),
					slog.String("resource", string(resource)),
					slog.Int64("amount", amount),
					slog.Int64("new_value", newValue),
				)
				return nil
			}
		default:
			return ErrInvalidResource{Resource: resource}
		}
		// CAS failed, retry.
	}
}

// GetUsage returns current usage for a resource.
func (t *Tracker) GetUsage(ctx context.Context, tenantID string, resource ResourceType) (int64, error) {
	if !resource.IsValid() {
		return 0, ErrInvalidResource{Resource: resource}
	}

	cache, err := t.getOrCreateCache(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	return cache.get(resource), nil
}

// GetAllUsage returns all usage for a tenant.
func (t *Tracker) GetAllUsage(ctx context.Context, tenantID string) (*TenantUsage, error) {
	cache, err := t.getOrCreateCache(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return cache.toTenantUsage(tenantID), nil
}

// Sync persists in-memory usage to store.
func (t *Tracker) Sync(ctx context.Context, tenantID string) error {
	value, ok := t.cache.Load(tenantID)
	if !ok {
		return nil // Nothing to sync.
	}

	cache := value.(*usageCache)
	usage := cache.toTenantUsage(tenantID)
	usage.Timestamp = time.Now()

	if err := t.store.UpdateUsage(ctx, tenantID, usage); err != nil {
		return ErrStoreFailed{Operation: "UpdateUsage", Err: err}
	}

	cache.lastSync.Store(time.Now())

	t.logger.Debug("usage synced to store",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// SyncAll persists all tenant usage to store.
func (t *Tracker) SyncAll(ctx context.Context) error {
	var syncErrors []error

	t.cache.Range(func(key, value any) bool {
		tenantID := key.(string)
		if err := t.Sync(ctx, tenantID); err != nil {
			syncErrors = append(syncErrors, err)
			t.logger.Error("failed to sync tenant usage",
				slog.String("tenant_id", tenantID),
				slog.Any("error", err),
			)
		}
		return true
	})

	if len(syncErrors) > 0 {
		return ErrStoreFailed{
			Operation: "SyncAll",
			Err:       syncErrors[0],
		}
	}

	return nil
}

// LoadFromStore loads usage from the store into cache for a tenant.
func (t *Tracker) LoadFromStore(ctx context.Context, tenantID string) error {
	usage, err := t.store.GetUsage(ctx, tenantID)
	if err != nil {
		return ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	cache := newUsageCache(usage)
	t.cache.Store(tenantID, cache)

	t.logger.Debug("usage loaded from store",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// Set directly sets the usage for a resource.
func (t *Tracker) Set(ctx context.Context, tenantID string, resource ResourceType, value int64) error {
	if !resource.IsValid() {
		return ErrInvalidResource{Resource: resource}
	}
	if value < 0 {
		return ErrInvalidAmount{Resource: resource, Amount: value}
	}

	cache, err := t.getOrCreateCache(ctx, tenantID)
	if err != nil {
		return err
	}

	cache.set(resource, value)

	t.logger.Debug("usage set",
		slog.String("tenant_id", tenantID),
		slog.String("resource", string(resource)),
		slog.Int64("value", value),
	)

	return nil
}

// Invalidate removes a tenant's cache, forcing reload on next access.
func (t *Tracker) Invalidate(tenantID string) {
	t.cache.Delete(tenantID)

	t.logger.Debug("usage cache invalidated",
		slog.String("tenant_id", tenantID),
	)
}

// InvalidateAll removes all cached data.
func (t *Tracker) InvalidateAll() {
	t.cache.Range(func(key, _ any) bool {
		t.cache.Delete(key)
		return true
	})

	t.logger.Debug("all usage caches invalidated")
}

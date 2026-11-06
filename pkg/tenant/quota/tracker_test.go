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
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNewTracker_Valid(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v, expected nil", err)
	}
	if tracker == nil {
		t.Fatal("NewTracker() returned nil tracker")
	}
	if tracker.syncInterval != time.Minute {
		t.Errorf("syncInterval = %v, expected %v", tracker.syncInterval, time.Minute)
	}
}

func TestNewTracker_NilStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewTracker(nil, logger)
	if err == nil {
		t.Fatal("NewTracker() with nil store should return error")
	}

	var nilStoreErr ErrNilStore
	if !errors.As(err, &nilStoreErr) {
		t.Errorf("error type = %T, expected ErrNilStore", err)
	}
}

func TestNewTracker_NilLogger(t *testing.T) {
	store := newMockQuotaStore()

	_, err := NewTracker(store, nil)
	if err == nil {
		t.Fatal("NewTracker() with nil logger should return error")
	}

	var nilLoggerErr ErrNilLogger
	if !errors.As(err, &nilLoggerErr) {
		t.Errorf("error type = %T, expected ErrNilLogger", err)
	}
}

func TestNewTracker_WithSyncInterval(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	customInterval := 30 * time.Second

	tracker, err := NewTracker(store, logger, WithSyncInterval(customInterval))
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}
	if tracker.syncInterval != customInterval {
		t.Errorf("syncInterval = %v, expected %v", tracker.syncInterval, customInterval)
	}
}

func TestTracker_Increment_IncreasesUsage(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Increment from zero
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 5 {
		t.Errorf("usage = %d, expected 5", usage)
	}

	// Increment again
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	usage, err = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 8 {
		t.Errorf("usage = %d, expected 8", usage)
	}
}

func TestTracker_Increment_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Increment(ctx, "tenant-1", ResourceType("invalid"), 1)
	if err == nil {
		t.Fatal("Increment() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestTracker_Increment_NegativeAmount(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, -5)
	if err == nil {
		t.Fatal("Increment() with negative amount should return error")
	}

	var amountErr ErrInvalidAmount
	if !errors.As(err, &amountErr) {
		t.Errorf("error type = %T, expected ErrInvalidAmount", err)
	}
}

func TestTracker_Increment_StoreError(t *testing.T) {
	store := newMockQuotaStore()
	store.usageError = errors.New("store error")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 1)
	if err == nil {
		t.Fatal("Increment() with store error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestTracker_Decrement_DecreasesUsage(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      10,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	err = tracker.Decrement(ctx, "tenant-1", ResourceVMs, 3)
	if err != nil {
		t.Fatalf("Decrement() error = %v", err)
	}

	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 7 {
		t.Errorf("usage = %d, expected 7", usage)
	}
}

func TestTracker_Decrement_DoesNotGoBelowZero(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      3,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	err = tracker.Decrement(ctx, "tenant-1", ResourceVMs, 10)
	if err != nil {
		t.Fatalf("Decrement() error = %v", err)
	}

	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 0 {
		t.Errorf("usage = %d, expected 0 (should not go below zero)", usage)
	}
}

func TestTracker_Decrement_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Decrement(ctx, "tenant-1", ResourceType("invalid"), 1)
	if err == nil {
		t.Fatal("Decrement() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestTracker_Decrement_NegativeAmount(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Decrement(ctx, "tenant-1", ResourceVMs, -5)
	if err == nil {
		t.Fatal("Decrement() with negative amount should return error")
	}

	var amountErr ErrInvalidAmount
	if !errors.As(err, &amountErr) {
		t.Errorf("error type = %T, expected ErrInvalidAmount", err)
	}
}

func TestTracker_Decrement_AllResourceTypes(t *testing.T) {
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceDisk, ResourceVolumes, ResourceSnapshots,
	}

	for _, resource := range resources {
		t.Run(string(resource), func(t *testing.T) {
			store := newMockQuotaStore()
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

			tracker, err := NewTracker(store, logger)
			if err != nil {
				t.Fatalf("NewTracker() error = %v", err)
			}

			ctx := context.Background()

			// Increment first
			err = tracker.Increment(ctx, "tenant-1", resource, 10)
			if err != nil {
				t.Fatalf("Increment(%s) error = %v", resource, err)
			}

			// Then decrement
			err = tracker.Decrement(ctx, "tenant-1", resource, 3)
			if err != nil {
				t.Fatalf("Decrement(%s) error = %v", resource, err)
			}

			usage, err := tracker.GetUsage(ctx, "tenant-1", resource)
			if err != nil {
				t.Fatalf("GetUsage(%s) error = %v", resource, err)
			}
			if usage != 7 {
				t.Errorf("usage = %d, expected 7", usage)
			}
		})
	}
}

func TestTracker_GetUsage_ReturnsCorrectValue(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      5,
		MemoryMB: 8192,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	vms, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage(VMs) error = %v", err)
	}
	if vms != 5 {
		t.Errorf("VMs usage = %d, expected 5", vms)
	}

	memory, err := tracker.GetUsage(ctx, "tenant-1", ResourceMemory)
	if err != nil {
		t.Fatalf("GetUsage(Memory) error = %v", err)
	}
	if memory != 8192 {
		t.Errorf("Memory usage = %d, expected 8192", memory)
	}
}

func TestTracker_GetUsage_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	_, err = tracker.GetUsage(ctx, "tenant-1", ResourceType("invalid"))
	if err == nil {
		t.Fatal("GetUsage() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestTracker_GetAllUsage_ReturnsAllResources(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID:      "tenant-1",
		VMs:           5,
		Containers:    10,
		VCPUs:         16,
		MemoryMB:      32768,
		DiskGB:        500,
		Bridges:       2,
		Ports:         50,
		BandwidthMbps: 500,
		Volumes:       25,
		Snapshots:     50,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	usage, err := tracker.GetAllUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetAllUsage() error = %v", err)
	}

	if usage.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, expected %q", usage.TenantID, "tenant-1")
	}
	if usage.VMs != 5 {
		t.Errorf("VMs = %d, expected 5", usage.VMs)
	}
	if usage.Containers != 10 {
		t.Errorf("Containers = %d, expected 10", usage.Containers)
	}
	if usage.VCPUs != 16 {
		t.Errorf("VCPUs = %d, expected 16", usage.VCPUs)
	}
	if usage.MemoryMB != 32768 {
		t.Errorf("MemoryMB = %d, expected 32768", usage.MemoryMB)
	}
	if usage.DiskGB != 500 {
		t.Errorf("DiskGB = %d, expected 500", usage.DiskGB)
	}
	if usage.Bridges != 2 {
		t.Errorf("Bridges = %d, expected 2", usage.Bridges)
	}
	if usage.Ports != 50 {
		t.Errorf("Ports = %d, expected 50", usage.Ports)
	}
	if usage.BandwidthMbps != 500 {
		t.Errorf("BandwidthMbps = %d, expected 500", usage.BandwidthMbps)
	}
	if usage.Volumes != 25 {
		t.Errorf("Volumes = %d, expected 25", usage.Volumes)
	}
	if usage.Snapshots != 50 {
		t.Errorf("Snapshots = %d, expected 50", usage.Snapshots)
	}
}

func TestTracker_GetAllUsage_NewTenant(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	usage, err := tracker.GetAllUsage(ctx, "new-tenant")
	if err != nil {
		t.Fatalf("GetAllUsage() error = %v", err)
	}

	// All values should be zero for new tenant
	if usage.VMs != 0 || usage.Containers != 0 || usage.VCPUs != 0 {
		t.Error("New tenant should have zero usage")
	}
}

func TestTracker_Sync_PersistsToStore(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Modify usage in memory
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	err = tracker.Increment(ctx, "tenant-1", ResourceContainers, 10)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	// Sync to store
	err = tracker.Sync(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Verify store was updated
	usage, err := store.GetUsage(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage.VMs != 5 {
		t.Errorf("store VMs = %d, expected 5", usage.VMs)
	}
	if usage.Containers != 10 {
		t.Errorf("store Containers = %d, expected 10", usage.Containers)
	}
}

func TestTracker_Sync_NothingToSync(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Sync tenant with no cache entry
	err = tracker.Sync(ctx, "nonexistent")
	if err != nil {
		t.Errorf("Sync() with no cache entry should return nil, got: %v", err)
	}
}

func TestTracker_Sync_StoreError(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Create cache entry
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	// Set error before sync
	store.updateErr = errors.New("database write failed")

	err = tracker.Sync(ctx, "tenant-1")
	if err == nil {
		t.Fatal("Sync() with store error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestTracker_SyncAll(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Create usage for multiple tenants
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}
	err = tracker.Increment(ctx, "tenant-2", ResourceContainers, 10)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	// Sync all
	err = tracker.SyncAll(ctx)
	if err != nil {
		t.Fatalf("SyncAll() error = %v", err)
	}

	// Verify both tenants synced
	usage1, _ := store.GetUsage(ctx, "tenant-1")
	usage2, _ := store.GetUsage(ctx, "tenant-2")

	if usage1.VMs != 5 {
		t.Errorf("tenant-1 VMs = %d, expected 5", usage1.VMs)
	}
	if usage2.Containers != 10 {
		t.Errorf("tenant-2 Containers = %d, expected 10", usage2.Containers)
	}
}

func TestTracker_SyncAll_PartialError(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Create usage for tenant
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	// Set error
	store.updateErr = errors.New("database error")

	err = tracker.SyncAll(ctx)
	if err == nil {
		t.Fatal("SyncAll() with error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestTracker_LoadFromStore(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID:   "tenant-1",
		VMs:        10,
		Containers: 20,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Explicitly load from store
	err = tracker.LoadFromStore(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("LoadFromStore() error = %v", err)
	}

	// Verify data was loaded
	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 10 {
		t.Errorf("VMs = %d, expected 10", usage)
	}
}

func TestTracker_LoadFromStore_Error(t *testing.T) {
	store := newMockQuotaStore()
	store.usageError = errors.New("store error")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.LoadFromStore(ctx, "tenant-1")
	if err == nil {
		t.Fatal("LoadFromStore() with error should return error")
	}

	var storeErr ErrStoreFailed
	if !errors.As(err, &storeErr) {
		t.Errorf("error type = %T, expected ErrStoreFailed", err)
	}
}

func TestTracker_Set_DirectlySetValue(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	err = tracker.Set(ctx, "tenant-1", ResourceVMs, 42)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != 42 {
		t.Errorf("usage = %d, expected 42", usage)
	}
}

func TestTracker_Set_InvalidResource(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Set(ctx, "tenant-1", ResourceType("invalid"), 10)
	if err == nil {
		t.Fatal("Set() with invalid resource should return error")
	}

	var invalidErr ErrInvalidResource
	if !errors.As(err, &invalidErr) {
		t.Errorf("error type = %T, expected ErrInvalidResource", err)
	}
}

func TestTracker_Set_NegativeValue(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	err = tracker.Set(ctx, "tenant-1", ResourceVMs, -5)
	if err == nil {
		t.Fatal("Set() with negative value should return error")
	}

	var amountErr ErrInvalidAmount
	if !errors.As(err, &amountErr) {
		t.Errorf("error type = %T, expected ErrInvalidAmount", err)
	}
}

func TestTracker_Invalidate_ClearsCache(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{
		TenantID: "tenant-1",
		VMs:      10,
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Load cache
	_, _ = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)

	// Modify in-memory
	err = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	if err != nil {
		t.Fatalf("Increment() error = %v", err)
	}

	// Verify in-memory value
	usage, _ := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if usage != 15 {
		t.Errorf("usage before invalidate = %d, expected 15", usage)
	}

	// Invalidate cache
	tracker.Invalidate("tenant-1")

	// Next access should reload from store
	usage, _ = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if usage != 10 {
		t.Errorf("usage after invalidate = %d, expected 10 (from store)", usage)
	}
}

func TestTracker_InvalidateAll(t *testing.T) {
	store := newMockQuotaStore()
	store.setUsage("tenant-1", &TenantUsage{TenantID: "tenant-1", VMs: 10})
	store.setUsage("tenant-2", &TenantUsage{TenantID: "tenant-2", VMs: 20})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Load caches and modify
	_ = tracker.Increment(ctx, "tenant-1", ResourceVMs, 5)
	_ = tracker.Increment(ctx, "tenant-2", ResourceVMs, 5)

	// Invalidate all
	tracker.InvalidateAll()

	// Verify caches are reloaded from store
	usage1, _ := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	usage2, _ := tracker.GetUsage(ctx, "tenant-2", ResourceVMs)

	if usage1 != 10 {
		t.Errorf("tenant-1 usage = %d, expected 10 (from store)", usage1)
	}
	if usage2 != 20 {
		t.Errorf("tenant-2 usage = %d, expected 20 (from store)", usage2)
	}
}

func TestTracker_ConcurrentIncrement(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	numGoroutines := 100
	incrementsPerGoroutine := 100

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				_ = tracker.Increment(ctx, "tenant-1", ResourceVMs, 1)
			}
		}()
	}

	wg.Wait()

	expected := int64(numGoroutines * incrementsPerGoroutine)
	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != expected {
		t.Errorf("usage = %d, expected %d", usage, expected)
	}
}

func TestTracker_ConcurrentDecrement(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Start with high value
	initialValue := int64(10000)
	err = tracker.Set(ctx, "tenant-1", ResourceVMs, initialValue)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	numGoroutines := 100
	decrementsPerGoroutine := 100

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < decrementsPerGoroutine; j++ {
				_ = tracker.Decrement(ctx, "tenant-1", ResourceVMs, 1)
			}
		}()
	}

	wg.Wait()

	expected := initialValue - int64(numGoroutines*decrementsPerGoroutine)
	usage, err := tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
	if usage != expected {
		t.Errorf("usage = %d, expected %d", usage, expected)
	}
}

func TestTracker_ConcurrentMixedOperations(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	numGoroutines := 50
	operationsPerGoroutine := 50

	var wg sync.WaitGroup

	// Half increment, half decrement
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				if idx%2 == 0 {
					_ = tracker.Increment(ctx, "tenant-1", ResourceVMs, 1)
				} else {
					_ = tracker.Decrement(ctx, "tenant-1", ResourceVMs, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	// Should not error - just verify no data race
	_, err = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
}

func TestTracker_ConcurrentMultipleTenants(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()
	numTenants := 10
	numGoroutinesPerTenant := 10
	incrementsPerGoroutine := 100

	var wg sync.WaitGroup

	for tenantIdx := 0; tenantIdx < numTenants; tenantIdx++ {
		tenantID := "tenant-" + string(rune('A'+tenantIdx))
		for goroutineIdx := 0; goroutineIdx < numGoroutinesPerTenant; goroutineIdx++ {
			wg.Add(1)
			go func(tid string) {
				defer wg.Done()
				for j := 0; j < incrementsPerGoroutine; j++ {
					_ = tracker.Increment(ctx, tid, ResourceVMs, 1)
				}
			}(tenantID)
		}
	}

	wg.Wait()

	// Verify each tenant's usage
	expected := int64(numGoroutinesPerTenant * incrementsPerGoroutine)
	for tenantIdx := 0; tenantIdx < numTenants; tenantIdx++ {
		tenantID := "tenant-" + string(rune('A'+tenantIdx))
		usage, err := tracker.GetUsage(ctx, tenantID, ResourceVMs)
		if err != nil {
			t.Errorf("GetUsage(%s) error = %v", tenantID, err)
			continue
		}
		if usage != expected {
			t.Errorf("%s usage = %d, expected %d", tenantID, usage, expected)
		}
	}
}

func TestTracker_ConcurrentSyncAndModify(t *testing.T) {
	store := newMockQuotaStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker, err := NewTracker(store, logger)
	if err != nil {
		t.Fatalf("NewTracker() error = %v", err)
	}

	ctx := context.Background()

	// Initialize
	_ = tracker.Set(ctx, "tenant-1", ResourceVMs, 100)

	var wg sync.WaitGroup

	// Goroutine 1: Continuously increment
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = tracker.Increment(ctx, "tenant-1", ResourceVMs, 1)
		}
	}()

	// Goroutine 2: Continuously sync
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_ = tracker.Sync(ctx, "tenant-1")
		}
	}()

	// Goroutine 3: Continuously read
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, _ = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
		}
	}()

	wg.Wait()

	// Just verify no panic/error - data race detector will catch issues
	_, err = tracker.GetUsage(ctx, "tenant-1", ResourceVMs)
	if err != nil {
		t.Fatalf("GetUsage() error = %v", err)
	}
}

func TestUsageCache_ToTenantUsage(t *testing.T) {
	usage := &TenantUsage{
		TenantID:      "tenant-1",
		VMs:           5,
		Containers:    10,
		VCPUs:         16,
		MemoryMB:      32768,
		DiskGB:        500,
		Bridges:       2,
		Ports:         50,
		BandwidthMbps: 500,
		Volumes:       25,
		Snapshots:     50,
	}

	cache := newUsageCache(usage)
	result := cache.toTenantUsage("tenant-1")

	if result.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, expected %q", result.TenantID, "tenant-1")
	}
	if result.VMs != 5 {
		t.Errorf("VMs = %d, expected 5", result.VMs)
	}
	if result.Containers != 10 {
		t.Errorf("Containers = %d, expected 10", result.Containers)
	}
	if result.VCPUs != 16 {
		t.Errorf("VCPUs = %d, expected 16", result.VCPUs)
	}
	if result.MemoryMB != 32768 {
		t.Errorf("MemoryMB = %d, expected 32768", result.MemoryMB)
	}
	if result.DiskGB != 500 {
		t.Errorf("DiskGB = %d, expected 500", result.DiskGB)
	}
	if result.Bridges != 2 {
		t.Errorf("Bridges = %d, expected 2", result.Bridges)
	}
	if result.Ports != 50 {
		t.Errorf("Ports = %d, expected 50", result.Ports)
	}
	if result.BandwidthMbps != 500 {
		t.Errorf("BandwidthMbps = %d, expected 500", result.BandwidthMbps)
	}
	if result.Volumes != 25 {
		t.Errorf("Volumes = %d, expected 25", result.Volumes)
	}
	if result.Snapshots != 50 {
		t.Errorf("Snapshots = %d, expected 50", result.Snapshots)
	}
}

func TestUsageCache_NewFromNil(t *testing.T) {
	cache := newUsageCache(nil)

	// All values should be zero
	if cache.get(ResourceVMs) != 0 {
		t.Errorf("VMs = %d, expected 0", cache.get(ResourceVMs))
	}
	if cache.get(ResourceContainers) != 0 {
		t.Errorf("Containers = %d, expected 0", cache.get(ResourceContainers))
	}
}

func TestUsageCache_GetUnknownResource(t *testing.T) {
	cache := newUsageCache(nil)
	result := cache.get(ResourceType("unknown"))
	if result != 0 {
		t.Errorf("get(unknown) = %d, expected 0", result)
	}
}

func TestUsageCache_AddUnknownResource(t *testing.T) {
	cache := newUsageCache(nil)
	result := cache.add(ResourceType("unknown"), 5)
	if result != 0 {
		t.Errorf("add(unknown) = %d, expected 0", result)
	}
}

func TestUsageCache_SetAllResources(t *testing.T) {
	cache := newUsageCache(nil)
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceDisk, ResourceVolumes, ResourceSnapshots,
	}

	for i, resource := range resources {
		value := int64((i + 1) * 10)
		cache.set(resource, value)
		if got := cache.get(resource); got != value {
			t.Errorf("get(%s) = %d after set, expected %d", resource, got, value)
		}
	}
}

func TestUsageCache_SetUnknownResource(t *testing.T) {
	cache := newUsageCache(nil)
	// Should not panic
	cache.set(ResourceType("unknown"), 100)
}

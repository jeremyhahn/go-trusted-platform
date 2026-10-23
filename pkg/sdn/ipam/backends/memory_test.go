// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package backends

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

func TestMemoryBackend_CreatePool(t *testing.T) {
	t.Parallel()

	t.Run("creates pool successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}

		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}

		// Verify pool was created
		retrieved, err := backend.GetPool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("GetPool failed: %v", err)
		}
		if retrieved.Name != "test-pool" {
			t.Errorf("expected name %q, got %q", "test-pool", retrieved.Name)
		}
		// /24 has 256 addresses - 2 (network + broadcast) = 254 usable
		if retrieved.TotalIPs != 254 {
			t.Errorf("expected TotalIPs %d, got %d", 254, retrieved.TotalIPs)
		}
		if retrieved.AvailableIPs != 254 {
			t.Errorf("expected AvailableIPs %d, got %d", 254, retrieved.AvailableIPs)
		}
	})

	t.Run("returns error for duplicate pool ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		pool2 := &ipam.Pool{
			ID:   "pool-1",
			Name: "different-name",
			CIDR: netip.MustParsePrefix("10.1.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool2)
		if !errors.Is(err, ipam.ErrPoolAlreadyExists) {
			t.Errorf("expected ErrPoolAlreadyExists, got %v", err)
		}
	})

	t.Run("returns error for duplicate pool name", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		pool2 := &ipam.Pool{
			ID:   "pool-2",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.1.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool2)
		if !errors.Is(err, ipam.ErrPoolNameExists) {
			t.Errorf("expected ErrPoolNameExists, got %v", err)
		}
	})

	t.Run("returns error for overlapping CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool-1",
			CIDR: netip.MustParsePrefix("10.0.0.0/16"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Overlapping subnet
		pool2 := &ipam.Pool{
			ID:   "pool-2",
			Name: "test-pool-2",
			CIDR: netip.MustParsePrefix("10.0.1.0/24"),
		}
		err := backend.CreatePool(ctx, pool2)
		if !errors.Is(err, ipam.ErrPoolCIDROverlaps) {
			t.Errorf("expected ErrPoolCIDROverlaps, got %v", err)
		}
	})

	t.Run("returns error for invalid pool ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrInvalidPoolID) {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("returns error for invalid pool name", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrInvalidPoolName) {
			t.Errorf("expected ErrInvalidPoolName, got %v", err)
		}
	})

	t.Run("returns error for invalid CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.Prefix{}, // Invalid
		}
		err := backend.CreatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrInvalidCIDR) {
			t.Errorf("expected ErrInvalidCIDR, got %v", err)
		}
	})

	t.Run("returns error for gateway outside CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:      "pool-1",
			Name:    "test-pool",
			CIDR:    netip.MustParsePrefix("10.0.0.0/24"),
			Gateway: netip.MustParseAddr("10.0.1.1"), // Outside CIDR
		}
		err := backend.CreatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrInvalidGateway) {
			t.Errorf("expected ErrInvalidGateway, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for duplicate CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		cidr := netip.MustParsePrefix("10.0.0.0/24")
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool-1",
			CIDR: cidr,
		}
		_ = backend.CreatePool(ctx, pool)

		// Same CIDR
		pool2 := &ipam.Pool{
			ID:   "pool-2",
			Name: "test-pool-2",
			CIDR: cidr,
		}
		err := backend.CreatePool(ctx, pool2)
		if !errors.Is(err, ipam.ErrPoolAlreadyExists) {
			t.Errorf("expected ErrPoolAlreadyExists, got %v", err)
		}
	})
}

func TestMemoryBackend_GetPool(t *testing.T) {
	t.Parallel()

	t.Run("retrieves pool by ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		retrieved, err := backend.GetPool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("GetPool failed: %v", err)
		}
		if retrieved.ID != "pool-1" {
			t.Errorf("expected ID %q, got %q", "pool-1", retrieved.ID)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetPool(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetPool(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_GetPoolByName(t *testing.T) {
	t.Parallel()

	t.Run("retrieves pool by name", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		retrieved, err := backend.GetPoolByName(ctx, "test-pool")
		if err != nil {
			t.Fatalf("GetPoolByName failed: %v", err)
		}
		if retrieved.Name != "test-pool" {
			t.Errorf("expected name %q, got %q", "test-pool", retrieved.Name)
		}
	})

	t.Run("returns error for non-existent name", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetPoolByName(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetPoolByName(ctx, "test-pool")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_GetPoolByCIDR(t *testing.T) {
	t.Parallel()

	t.Run("retrieves pool by CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		cidr := netip.MustParsePrefix("10.0.0.0/24")
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: cidr,
		}
		_ = backend.CreatePool(ctx, pool)

		retrieved, err := backend.GetPoolByCIDR(ctx, cidr)
		if err != nil {
			t.Fatalf("GetPoolByCIDR failed: %v", err)
		}
		if retrieved.CIDR != cidr {
			t.Errorf("expected CIDR %v, got %v", cidr, retrieved.CIDR)
		}
	})

	t.Run("returns error for non-existent CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetPoolByCIDR(ctx, netip.MustParsePrefix("10.1.0.0/24"))
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetPoolByCIDR(ctx, netip.MustParsePrefix("10.0.0.0/24"))
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_ListPools(t *testing.T) {
	t.Parallel()

	t.Run("lists all pools", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		for i := 0; i < 3; i++ {
			pool := &ipam.Pool{
				ID:   "pool-" + string(rune('1'+i)),
				Name: "test-pool-" + string(rune('1'+i)),
				CIDR: netip.MustParsePrefix("10." + string(rune('0'+i)) + ".0.0/24"),
			}
			_ = backend.CreatePool(ctx, pool)
		}

		pools, err := backend.ListPools(ctx)
		if err != nil {
			t.Fatalf("ListPools failed: %v", err)
		}
		if len(pools) != 3 {
			t.Errorf("expected 3 pools, got %d", len(pools))
		}
	})

	t.Run("returns empty list when no pools exist", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pools, err := backend.ListPools(ctx)
		if err != nil {
			t.Fatalf("ListPools failed: %v", err)
		}
		if len(pools) != 0 {
			t.Errorf("expected 0 pools, got %d", len(pools))
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.ListPools(ctx)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_UpdatePool(t *testing.T) {
	t.Parallel()

	t.Run("updates pool successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:          "pool-1",
			Name:        "test-pool",
			CIDR:        netip.MustParsePrefix("10.0.0.0/24"),
			Description: "original",
		}
		_ = backend.CreatePool(ctx, pool)

		pool.Description = "updated"
		pool.Name = "updated-pool"
		err := backend.UpdatePool(ctx, pool)
		if err != nil {
			t.Fatalf("UpdatePool failed: %v", err)
		}

		retrieved, _ := backend.GetPool(ctx, "pool-1")
		if retrieved.Description != "updated" {
			t.Errorf("expected description %q, got %q", "updated", retrieved.Description)
		}
		if retrieved.Name != "updated-pool" {
			t.Errorf("expected name %q, got %q", "updated-pool", retrieved.Name)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "non-existent",
			Name: "test",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.UpdatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when changing CIDR", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		pool.CIDR = netip.MustParsePrefix("10.1.0.0/24")
		err := backend.UpdatePool(ctx, pool)
		if err == nil {
			t.Error("expected error when changing CIDR")
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.UpdatePool(ctx, pool)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for name conflict with different pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool1 := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool-1",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool1)

		pool2 := &ipam.Pool{
			ID:   "pool-2",
			Name: "test-pool-2",
			CIDR: netip.MustParsePrefix("10.1.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool2)

		// Try to update pool2 to use pool1's name
		pool2.Name = "test-pool-1"
		err := backend.UpdatePool(ctx, pool2)
		if !errors.Is(err, ipam.ErrPoolNameExists) {
			t.Errorf("expected ErrPoolNameExists, got %v", err)
		}
	})
}

func TestMemoryBackend_DeletePool(t *testing.T) {
	t.Parallel()

	t.Run("deletes empty pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		err := backend.DeletePool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("DeletePool failed: %v", err)
		}

		_, err = backend.GetPool(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.DeletePool(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error for pool with active allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Create an allocation
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, _ = backend.Allocate(ctx, req)

		err := backend.DeletePool(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrPoolHasAllocations) {
			t.Errorf("expected ErrPoolHasAllocations, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.DeletePool(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("deletes pool with released allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Create and release an allocation
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)
		_ = backend.Release(ctx, alloc.IP)

		// Should succeed since allocation is released
		err := backend.DeletePool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("DeletePool failed: %v", err)
		}
	})
}

func TestMemoryBackend_Allocate(t *testing.T) {
	t.Parallel()

	t.Run("allocates IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
			Hostname: "test-host",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		// First usable IP should be 10.0.0.1 (skipping network address)
		expected := netip.MustParseAddr("10.0.0.1")
		if alloc.IP != expected {
			t.Errorf("expected IP %v, got %v", expected, alloc.IP)
		}
		if alloc.DeviceID != "device-1" {
			t.Errorf("expected device ID %q, got %q", "device-1", alloc.DeviceID)
		}
		if alloc.Hostname != "test-host" {
			t.Errorf("expected hostname %q, got %q", "test-host", alloc.Hostname)
		}
		if alloc.Status != ipam.AllocationStatusActive {
			t.Errorf("expected status %v, got %v", ipam.AllocationStatusActive, alloc.Status)
		}
	})

	t.Run("allocates sequential IPs", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/28"), // 14 usable IPs
		}
		_ = backend.CreatePool(ctx, pool)

		expectedIPs := []string{
			"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
		}

		for i, expectedIP := range expectedIPs {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			alloc, err := backend.Allocate(ctx, req)
			if err != nil {
				t.Fatalf("Allocate %d failed: %v", i, err)
			}
			if alloc.IP.String() != expectedIP {
				t.Errorf("allocation %d: expected IP %s, got %s", i, expectedIP, alloc.IP.String())
			}
		}
	})

	t.Run("returns error when pool is exhausted", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		// /30 has 2 usable IPs
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/30"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Allocate all IPs
		for i := 0; i < 2; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			_, _ = backend.Allocate(ctx, req)
		}

		// Try to allocate one more
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-extra",
		}
		_, err := backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrPoolExhausted) {
			t.Errorf("expected ErrPoolExhausted, got %v", err)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		req := &ipam.AllocationRequest{
			PoolID:   "non-existent",
			DeviceID: "device-1",
		}
		_, err := backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error for missing device ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "",
		}
		_, err := backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrDeviceIDRequired) {
			t.Errorf("expected ErrDeviceIDRequired, got %v", err)
		}
	})

	t.Run("sets lease expiration from pool default", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                   "pool-1",
			Name:                 "test-pool",
			CIDR:                 netip.MustParsePrefix("10.0.0.0/24"),
			DefaultLeaseDuration: 1 * time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		if alloc.ExpiresAt.IsZero() {
			t.Error("expected ExpiresAt to be set")
		}
		if time.Until(alloc.ExpiresAt) > 1*time.Hour {
			t.Error("ExpiresAt is too far in the future")
		}
	})

	t.Run("sets lease expiration from request", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                   "pool-1",
			Name:                 "test-pool",
			CIDR:                 netip.MustParsePrefix("10.0.0.0/24"),
			DefaultLeaseDuration: 1 * time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:        "pool-1",
			DeviceID:      "device-1",
			LeaseDuration: 30 * time.Minute,
		}
		alloc, _ := backend.Allocate(ctx, req)

		if time.Until(alloc.ExpiresAt) > 30*time.Minute {
			t.Error("ExpiresAt should use request lease duration")
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, err := backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_AllocateSpecific(t *testing.T) {
	t.Parallel()

	t.Run("allocates specific IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		specificIP := netip.MustParseAddr("10.0.0.100")
		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: specificIP,
		}
		alloc, err := backend.AllocateSpecific(ctx, req)
		if err != nil {
			t.Fatalf("AllocateSpecific failed: %v", err)
		}
		if alloc.IP != specificIP {
			t.Errorf("expected IP %v, got %v", specificIP, alloc.IP)
		}
	})

	t.Run("returns error for IP already allocated", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		specificIP := netip.MustParseAddr("10.0.0.100")
		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: specificIP,
		}
		_, _ = backend.AllocateSpecific(ctx, req)

		// Try to allocate same IP
		req2 := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-2",
			RequestedIP: specificIP,
		}
		_, err := backend.AllocateSpecific(ctx, req2)
		var conflictErr *ipam.ErrIPConflict
		if !errors.As(err, &conflictErr) {
			t.Errorf("expected ErrIPConflict, got %v", err)
		}
	})

	t.Run("returns error for IP outside pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: netip.MustParseAddr("10.1.0.1"), // Outside pool
		}
		_, err := backend.AllocateSpecific(ctx, req)
		if !errors.Is(err, ipam.ErrIPNotInPool) {
			t.Errorf("expected ErrIPNotInPool, got %v", err)
		}
	})

	t.Run("returns error for network address", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: netip.MustParseAddr("10.0.0.0"), // Network address
		}
		_, err := backend.AllocateSpecific(ctx, req)
		if !errors.Is(err, ipam.ErrNetworkAddress) {
			t.Errorf("expected ErrNetworkAddress, got %v", err)
		}
	})

	t.Run("returns error for broadcast address", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: netip.MustParseAddr("10.0.0.255"), // Broadcast address
		}
		_, err := backend.AllocateSpecific(ctx, req)
		if !errors.Is(err, ipam.ErrBroadcastAddress) {
			t.Errorf("expected ErrBroadcastAddress, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: netip.Addr{}, // Invalid
		}
		_, err := backend.AllocateSpecific(ctx, req)
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: netip.MustParseAddr("10.0.0.100"),
		}
		_, err := backend.AllocateSpecific(ctx, req)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("reallocates released IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		specificIP := netip.MustParseAddr("10.0.0.100")
		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: specificIP,
		}
		alloc, _ := backend.AllocateSpecific(ctx, req)
		_ = backend.Release(ctx, alloc.IP)

		// Now reallocate the same IP
		req2 := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-2",
			RequestedIP: specificIP,
		}
		alloc2, err := backend.AllocateSpecific(ctx, req2)
		if err != nil {
			t.Fatalf("AllocateSpecific failed: %v", err)
		}
		if alloc2.IP != specificIP {
			t.Errorf("expected IP %v, got %v", specificIP, alloc2.IP)
		}
	})
}

func TestMemoryBackend_Release(t *testing.T) {
	t.Parallel()

	t.Run("releases IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		err := backend.Release(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("Release failed: %v", err)
		}

		// Verify allocation status
		releasedAlloc, _ := backend.GetAllocation(ctx, alloc.IP)
		if releasedAlloc.Status != ipam.AllocationStatusReleased {
			t.Errorf("expected status %v, got %v", ipam.AllocationStatusReleased, releasedAlloc.Status)
		}
	})

	t.Run("released IP can be reallocated", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)
		releasedIP := alloc.IP

		_ = backend.Release(ctx, releasedIP)

		// Allocate again - should get the same IP (first available)
		req2 := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-2",
		}
		newAlloc, err := backend.Allocate(ctx, req2)
		if err != nil {
			t.Fatalf("Reallocate failed: %v", err)
		}
		if newAlloc.IP != releasedIP {
			t.Errorf("expected released IP %v to be reallocated, got %v", releasedIP, newAlloc.IP)
		}
	})

	t.Run("returns error for non-existent allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Release(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Release(ctx, netip.Addr{})
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.Release(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for already released allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)
		_ = backend.Release(ctx, alloc.IP)

		// Try to release again
		err := backend.Release(ctx, alloc.IP)
		if !errors.Is(err, ipam.ErrAllocationReleased) {
			t.Errorf("expected ErrAllocationReleased, got %v", err)
		}
	})
}

func TestMemoryBackend_ReleaseByDeviceID(t *testing.T) {
	t.Parallel()

	t.Run("releases all device allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Allocate multiple IPs for same device
		for i := 0; i < 3; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-1",
			}
			_, _ = backend.Allocate(ctx, req)
		}

		// Allocate for different device
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-2",
		}
		_, _ = backend.Allocate(ctx, req)

		released, err := backend.ReleaseByDeviceID(ctx, "device-1")
		if err != nil {
			t.Fatalf("ReleaseByDeviceID failed: %v", err)
		}
		if released != 3 {
			t.Errorf("expected 3 released, got %d", released)
		}

		// Verify device-2's allocation is still active
		allocs, _ := backend.GetAllocationsByDevice(ctx, "device-2")
		if len(allocs) != 1 {
			t.Errorf("expected 1 allocation for device-2, got %d", len(allocs))
		}
		if allocs[0].Status != ipam.AllocationStatusActive {
			t.Errorf("device-2 allocation should still be active")
		}
	})

	t.Run("returns error for empty device ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.ReleaseByDeviceID(ctx, "")
		if !errors.Is(err, ipam.ErrDeviceIDRequired) {
			t.Errorf("expected ErrDeviceIDRequired, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.ReleaseByDeviceID(ctx, "device-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns zero for non-existent device", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		released, err := backend.ReleaseByDeviceID(ctx, "non-existent-device")
		if err != nil {
			t.Fatalf("ReleaseByDeviceID failed: %v", err)
		}
		if released != 0 {
			t.Errorf("expected 0 released, got %d", released)
		}
	})
}

func TestMemoryBackend_Renew(t *testing.T) {
	t.Parallel()

	t.Run("renews lease successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                   "pool-1",
			Name:                 "test-pool",
			CIDR:                 netip.MustParsePrefix("10.0.0.0/24"),
			DefaultLeaseDuration: 1 * time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		require.NoError(t, err)
		require.Equal(t, clock.Now(), alloc.LastSeen)

		clock.Advance(10 * time.Minute)

		err = backend.Renew(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("Renew failed: %v", err)
		}

		renewed, _ := backend.GetAllocation(ctx, alloc.IP)
		assert.Equal(t, clock.Now(), renewed.LastSeen, "renewal must stamp LastSeen with the current time")
		assert.Equal(t, clock.Now().Add(time.Hour), renewed.ExpiresAt, "renewal must extend the lease from the current time")
	})

	t.Run("returns error for expired allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
			InactivityTimeout: time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		require.NoError(t, err)

		clock.Advance(time.Hour + time.Nanosecond)

		expired, err := backend.ExpireInactive(ctx, "pool-1")
		require.NoError(t, err)
		require.Len(t, expired, 1)

		err = backend.Renew(ctx, alloc.IP)
		if !errors.Is(err, ipam.ErrAllocationExpired) {
			t.Errorf("expected ErrAllocationExpired, got %v", err)
		}
	})

	t.Run("returns error for released allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)
		_ = backend.Release(ctx, alloc.IP)

		err := backend.Renew(ctx, alloc.IP)
		if !errors.Is(err, ipam.ErrAllocationReleased) {
			t.Errorf("expected ErrAllocationReleased, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.Renew(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Renew(ctx, netip.Addr{})
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("returns error for non-existent allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Renew(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("renews allocation without lease duration", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
			// No DefaultLeaseDuration
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		err := backend.Renew(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("Renew failed: %v", err)
		}
	})
}

func TestMemoryBackend_GetAllocation(t *testing.T) {
	t.Parallel()

	t.Run("retrieves allocation by IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		retrieved, err := backend.GetAllocation(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("GetAllocation failed: %v", err)
		}
		if retrieved.DeviceID != "device-1" {
			t.Errorf("expected device ID %q, got %q", "device-1", retrieved.DeviceID)
		}
	})

	t.Run("returns error for non-existent allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetAllocation(ctx, netip.Addr{})
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})
}

func TestMemoryBackend_GetAllocationsByDevice(t *testing.T) {
	t.Parallel()

	t.Run("retrieves device allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Allocate for device-1
		for i := 0; i < 3; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-1",
			}
			_, _ = backend.Allocate(ctx, req)
		}

		// Allocate for device-2
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-2",
		}
		_, _ = backend.Allocate(ctx, req)

		allocs, err := backend.GetAllocationsByDevice(ctx, "device-1")
		if err != nil {
			t.Fatalf("GetAllocationsByDevice failed: %v", err)
		}
		if len(allocs) != 3 {
			t.Errorf("expected 3 allocations, got %d", len(allocs))
		}
	})

	t.Run("returns error for empty device ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetAllocationsByDevice(ctx, "")
		if !errors.Is(err, ipam.ErrDeviceIDRequired) {
			t.Errorf("expected ErrDeviceIDRequired, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetAllocationsByDevice(ctx, "device-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_GetAllocationsByPool(t *testing.T) {
	t.Parallel()

	t.Run("retrieves pool allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		for i := 0; i < 5; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			_, _ = backend.Allocate(ctx, req)
		}

		allocs, err := backend.GetAllocationsByPool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("GetAllocationsByPool failed: %v", err)
		}
		if len(allocs) != 5 {
			t.Errorf("expected 5 allocations, got %d", len(allocs))
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetAllocationsByPool(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetAllocationsByPool(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_ExpireInactive(t *testing.T) {
	t.Parallel()

	t.Run("expires inactive allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
			InactivityTimeout: time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		require.NoError(t, err)

		clock.Advance(time.Hour + time.Nanosecond)

		expired, err := backend.ExpireInactive(ctx, "pool-1")
		if err != nil {
			t.Fatalf("ExpireInactive failed: %v", err)
		}
		if len(expired) != 1 {
			t.Errorf("expected 1 expired allocation, got %d", len(expired))
		}

		// Verify allocation is expired
		retrievedAlloc, _ := backend.GetAllocation(ctx, alloc.IP)
		if retrievedAlloc.Status != ipam.AllocationStatusExpired {
			t.Errorf("expected status %v, got %v", ipam.AllocationStatusExpired, retrievedAlloc.Status)
		}
		assert.Equal(t, clock.Now(), retrievedAlloc.ReleasedAt)
	})

	t.Run("does not expire an allocation idle for exactly the timeout", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
			InactivityTimeout: time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, _ = backend.Allocate(ctx, req)

		// The timeout is exclusive: an allocation last seen exactly one
		// timeout ago is still active.
		clock.Advance(time.Hour)

		expired, err := backend.ExpireInactive(ctx, "pool-1")
		if err != nil {
			t.Fatalf("ExpireInactive failed: %v", err)
		}
		if len(expired) != 0 {
			t.Errorf("expected 0 expired allocations, got %d", len(expired))
		}
	})

	t.Run("renewal restarts the inactivity window", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
			InactivityTimeout: time.Hour,
		}))
		alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "device-1"})
		require.NoError(t, err)

		clock.Advance(45 * time.Minute)
		require.NoError(t, backend.Renew(ctx, alloc.IP))
		clock.Advance(45 * time.Minute)

		expired, err := backend.ExpireInactive(ctx, "pool-1")
		require.NoError(t, err)
		assert.Empty(t, expired, "90 minutes after allocation but 45 after renewal is inside the window")
	})

	t.Run("returns nil when no timeout configured", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
			InactivityTimeout: 0, // No timeout
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, _ = backend.Allocate(ctx, req)

		expired, err := backend.ExpireInactive(ctx, "pool-1")
		if err != nil {
			t.Fatalf("ExpireInactive failed: %v", err)
		}
		if expired != nil {
			t.Errorf("expected nil, got %v", expired)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.ExpireInactive(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.ExpireInactive(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_GetPoolStats(t *testing.T) {
	t.Parallel()

	t.Run("returns accurate stats", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/28"), // 14 usable IPs
		}
		_ = backend.CreatePool(ctx, pool)

		// Allocate 5 IPs
		for i := 0; i < 5; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			_, _ = backend.Allocate(ctx, req)
		}

		stats, err := backend.GetPoolStats(ctx, "pool-1")
		if err != nil {
			t.Fatalf("GetPoolStats failed: %v", err)
		}

		if stats.TotalIPs != 14 {
			t.Errorf("expected TotalIPs %d, got %d", 14, stats.TotalIPs)
		}
		if stats.AllocatedIPs != 5 {
			t.Errorf("expected AllocatedIPs %d, got %d", 5, stats.AllocatedIPs)
		}
		if stats.AvailableIPs != 9 {
			t.Errorf("expected AvailableIPs %d, got %d", 9, stats.AvailableIPs)
		}
		// Utilization should be ~35.7%
		if stats.UtilizationPct < 35 || stats.UtilizationPct > 36 {
			t.Errorf("expected UtilizationPct ~35.7, got %f", stats.UtilizationPct)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.GetPoolStats(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.GetPoolStats(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("counts expired and reserved allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		pool := &ipam.Pool{
			ID:                "pool-1",
			Name:              "test-pool",
			CIDR:              netip.MustParsePrefix("10.0.0.0/28"),
			InactivityTimeout: time.Hour,
		}
		_ = backend.CreatePool(ctx, pool)

		// Create a reservation
		_ = backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.1"), "gateway")

		// Create and expire an allocation
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, err := backend.Allocate(ctx, req)
		require.NoError(t, err)

		clock.Advance(time.Hour + time.Nanosecond)
		_, err = backend.ExpireInactive(ctx, "pool-1")
		require.NoError(t, err)

		stats, err := backend.GetPoolStats(ctx, "pool-1")
		if err != nil {
			t.Fatalf("GetPoolStats failed: %v", err)
		}

		if stats.ReservedIPs != 1 {
			t.Errorf("expected ReservedIPs %d, got %d", 1, stats.ReservedIPs)
		}
		if stats.ExpiredIPs != 1 {
			t.Errorf("expected ExpiredIPs %d, got %d", 1, stats.ExpiredIPs)
		}
	})
}

func TestMemoryBackend_Reserve(t *testing.T) {
	t.Parallel()

	t.Run("reserves IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		err := backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.1"), "gateway")
		if err != nil {
			t.Fatalf("Reserve failed: %v", err)
		}

		// Verify reservation
		alloc, _ := backend.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1"))
		if alloc.Status != ipam.AllocationStatusReserved {
			t.Errorf("expected status %v, got %v", ipam.AllocationStatusReserved, alloc.Status)
		}
	})

	t.Run("prevents allocation of reserved IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Reserve first usable IP
		_ = backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.1"), "gateway")

		// Try to allocate - should get next available
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
		// Should skip reserved IP and allocate 10.0.0.2
		if alloc.IP.String() != "10.0.0.2" {
			t.Errorf("expected IP 10.0.0.2, got %s", alloc.IP.String())
		}
	})

	t.Run("returns error for already allocated IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		err := backend.Reserve(ctx, "pool-1", alloc.IP, "test")
		if !errors.Is(err, ipam.ErrIPAlreadyAllocated) {
			t.Errorf("expected ErrIPAlreadyAllocated, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.1"), "gateway")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		err := backend.Reserve(ctx, "pool-1", netip.Addr{}, "gateway")
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Reserve(ctx, "non-existent", netip.MustParseAddr("10.0.0.1"), "gateway")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("returns error for IP not in pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		err := backend.Reserve(ctx, "pool-1", netip.MustParseAddr("192.168.1.1"), "gateway")
		if !errors.Is(err, ipam.ErrIPNotInPool) {
			t.Errorf("expected ErrIPNotInPool, got %v", err)
		}
	})
}

func TestMemoryBackend_Unreserve(t *testing.T) {
	t.Parallel()

	t.Run("unreserves IP successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		ip := netip.MustParseAddr("10.0.0.1")
		_ = backend.Reserve(ctx, "pool-1", ip, "gateway")

		err := backend.Unreserve(ctx, ip)
		if err != nil {
			t.Fatalf("Unreserve failed: %v", err)
		}

		// Verify allocation is removed
		_, err = backend.GetAllocation(ctx, ip)
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("returns error for non-reserved allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, _ := backend.Allocate(ctx, req)

		err := backend.Unreserve(ctx, alloc.IP)
		var statusErr *ipam.ErrInvalidAllocationStatus
		if !errors.As(err, &statusErr) {
			t.Errorf("expected ErrInvalidAllocationStatus, got %v", err)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.Unreserve(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Unreserve(ctx, netip.Addr{})
		if !errors.Is(err, ipam.ErrInvalidIP) {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("returns error for non-existent allocation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Unreserve(ctx, netip.MustParseAddr("10.0.0.1"))
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})
}

func TestMemoryBackend_ListReservations(t *testing.T) {
	t.Parallel()

	t.Run("lists all reservations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Create reservations
		_ = backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.1"), "gateway")
		_ = backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.2"), "dns1")
		_ = backend.Reserve(ctx, "pool-1", netip.MustParseAddr("10.0.0.3"), "dns2")

		// Create regular allocation
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		_, _ = backend.Allocate(ctx, req)

		reservations, err := backend.ListReservations(ctx, "pool-1")
		if err != nil {
			t.Fatalf("ListReservations failed: %v", err)
		}
		if len(reservations) != 3 {
			t.Errorf("expected 3 reservations, got %d", len(reservations))
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		_, err := backend.ListReservations(ctx, "pool-1")
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns error for non-existent pool", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		_, err := backend.ListReservations(ctx, "non-existent")
		if !errors.Is(err, ipam.ErrPoolNotFound) {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})
}

func TestMemoryBackend_BatchAllocate(t *testing.T) {
	t.Parallel()

	t.Run("allocates batch successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		reqs := make([]*ipam.AllocationRequest, 5)
		for i := range reqs {
			reqs[i] = &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
		}

		allocations, err := backend.AllocateBatch(ctx, reqs)
		if err != nil {
			t.Fatalf("AllocateBatch failed: %v", err)
		}
		if len(allocations) != 5 {
			t.Errorf("expected 5 allocations, got %d", len(allocations))
		}
	})

	t.Run("returns partial results on error", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/30"), // Only 2 usable IPs
		}
		_ = backend.CreatePool(ctx, pool)

		reqs := make([]*ipam.AllocationRequest, 5)
		for i := range reqs {
			reqs[i] = &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
		}

		allocations, err := backend.AllocateBatch(ctx, reqs)
		if err == nil {
			t.Error("expected error for exhausted pool")
		}
		if len(allocations) != 2 {
			t.Errorf("expected 2 partial allocations, got %d", len(allocations))
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		reqs := []*ipam.AllocationRequest{
			{PoolID: "pool-1", DeviceID: "device-1"},
		}
		_, err := backend.AllocateBatch(ctx, reqs)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_ReleaseBatch(t *testing.T) {
	t.Parallel()

	t.Run("releases batch successfully", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		var ips []netip.Addr
		for i := 0; i < 5; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			alloc, _ := backend.Allocate(ctx, req)
			ips = append(ips, alloc.IP)
		}

		released, err := backend.ReleaseBatch(ctx, ips)
		if err != nil {
			t.Fatalf("ReleaseBatch failed: %v", err)
		}
		if released != 5 {
			t.Errorf("expected 5 released, got %d", released)
		}
	})

	t.Run("returns error when backend is closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		ips := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
		_, err := backend.ReleaseBatch(ctx, ips)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("returns partial release count with some errors", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Allocate some IPs
		var allocatedIPs []netip.Addr
		for i := 0; i < 3; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			alloc, _ := backend.Allocate(ctx, req)
			allocatedIPs = append(allocatedIPs, alloc.IP)
		}

		// Add some non-existent IPs to the batch
		ips := append(allocatedIPs, netip.MustParseAddr("10.0.0.200"), netip.MustParseAddr("10.0.0.201"))

		released, err := backend.ReleaseBatch(ctx, ips)
		// Should return error for the non-existent IPs
		if err == nil {
			t.Error("expected error for non-existent IPs")
		}
		// But should still release the valid ones
		if released != 3 {
			t.Errorf("expected 3 released, got %d", released)
		}
	})
}

func TestMemoryBackend_Ping(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when open", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		err := backend.Ping(ctx)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		backend.Close()

		err := backend.Ping(ctx)
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestMemoryBackend_Close(t *testing.T) {
	t.Parallel()

	t.Run("closes successfully", func(t *testing.T) {
		t.Parallel()
		backend := NewMemoryBackend()

		err := backend.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Second close should return error
		err = backend.Close()
		if !errors.Is(err, ipam.ErrBackendUnavailable) {
			t.Errorf("expected ErrBackendUnavailable on second close, got %v", err)
		}
	})
}

func TestMemoryBackend_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent allocations", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/20"), // 4094 usable IPs
		}
		_ = backend.CreatePool(ctx, pool)

		const goroutines = 100
		const allocsPerGoroutine = 10

		var wg sync.WaitGroup
		wg.Add(goroutines)

		allocatedIPs := make(chan netip.Addr, goroutines*allocsPerGoroutine)
		errChan := make(chan error, goroutines*allocsPerGoroutine)

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < allocsPerGoroutine; j++ {
					req := &ipam.AllocationRequest{
						PoolID:   "pool-1",
						DeviceID: "device-" + string(rune('0'+id)),
					}
					alloc, err := backend.Allocate(ctx, req)
					if err != nil {
						errChan <- err
						return
					}
					allocatedIPs <- alloc.IP
				}
			}(i)
		}

		wg.Wait()
		close(allocatedIPs)
		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Errorf("allocation error: %v", err)
		}

		// Verify all IPs are unique
		seen := make(map[netip.Addr]bool)
		for ip := range allocatedIPs {
			if seen[ip] {
				t.Errorf("duplicate IP allocated: %v", ip)
			}
			seen[ip] = true
		}

		expectedCount := goroutines * allocsPerGoroutine
		if len(seen) != expectedCount {
			t.Errorf("expected %d unique IPs, got %d", expectedCount, len(seen))
		}
	})

	t.Run("handles concurrent allocate and release", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		_ = backend.CreatePool(ctx, pool)

		const iterations = 100
		var wg sync.WaitGroup
		wg.Add(iterations * 2)

		// Allocators
		for i := 0; i < iterations; i++ {
			go func(id int) {
				defer wg.Done()
				req := &ipam.AllocationRequest{
					PoolID:   "pool-1",
					DeviceID: "device-" + string(rune('0'+id)),
				}
				alloc, err := backend.Allocate(ctx, req)
				if err != nil {
					return // Pool might be exhausted
				}
				// Immediately release
				_ = backend.Release(ctx, alloc.IP)
			}(i)
		}

		// Releasers (may fail if nothing to release)
		for i := 0; i < iterations; i++ {
			go func() {
				defer wg.Done()
				allocs, err := backend.GetAllocationsByPool(ctx, "pool-1")
				if err != nil || len(allocs) == 0 {
					return
				}
				_ = backend.Release(ctx, allocs[0].IP)
			}()
		}

		wg.Wait()
		// No crash = success
	})
}

func TestMemoryBackend_IPv6(t *testing.T) {
	t.Parallel()

	t.Run("allocates IPv6 addresses", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool-v6",
			CIDR: netip.MustParsePrefix("2001:db8::/120"), // 256 IPs
		}
		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}

		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}

		if !alloc.IP.Is6() {
			t.Errorf("expected IPv6 address, got %v", alloc.IP)
		}
		if !pool.CIDR.Contains(alloc.IP) {
			t.Errorf("allocated IP %v not in CIDR %v", alloc.IP, pool.CIDR)
		}
	})

	t.Run("allocates specific IPv6 address", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool-v6",
			CIDR: netip.MustParsePrefix("2001:db8::/120"),
		}
		_ = backend.CreatePool(ctx, pool)

		// Use 0x50 (80 in decimal) which is well within the /120 range (0-255)
		specificIP := netip.MustParseAddr("2001:db8::50")
		req := &ipam.AllocationRequest{
			PoolID:      "pool-1",
			DeviceID:    "device-1",
			RequestedIP: specificIP,
		}
		alloc, err := backend.AllocateSpecific(ctx, req)
		if err != nil {
			t.Fatalf("AllocateSpecific failed: %v", err)
		}
		if alloc.IP != specificIP {
			t.Errorf("expected IP %v, got %v", specificIP, alloc.IP)
		}
	})
}

func TestMemoryBackend_Slash31Network(t *testing.T) {
	t.Parallel()

	t.Run("handles /31 point-to-point network", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		// Per RFC 3021, /31 networks have 2 usable IPs
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "p2p-link",
			CIDR: netip.MustParsePrefix("10.0.0.0/31"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}

		// Should have 2 usable IPs
		retrieved, _ := backend.GetPool(ctx, "pool-1")
		if retrieved.TotalIPs != 2 {
			t.Errorf("expected TotalIPs 2 for /31, got %d", retrieved.TotalIPs)
		}

		// Allocate both IPs
		for i := 0; i < 2; i++ {
			req := &ipam.AllocationRequest{
				PoolID:   "pool-1",
				DeviceID: "device-" + string(rune('0'+i)),
			}
			_, err := backend.Allocate(ctx, req)
			if err != nil {
				t.Fatalf("Allocate %d failed: %v", i, err)
			}
		}

		// Third allocation should fail
		req := &ipam.AllocationRequest{
			PoolID:   "pool-1",
			DeviceID: "device-extra",
		}
		_, err = backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrPoolExhausted) {
			t.Errorf("expected ErrPoolExhausted, got %v", err)
		}
	})
}

func TestMemoryBackend_Slash32Network(t *testing.T) {
	t.Parallel()

	t.Run("handles /32 single host", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		backend := NewMemoryBackend()
		defer backend.Close()

		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "single-host",
			CIDR: netip.MustParsePrefix("10.0.0.1/32"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}

		// Should have 1 usable IP
		retrieved, _ := backend.GetPool(ctx, "pool-1")
		if retrieved.TotalIPs != 1 {
			t.Errorf("expected TotalIPs 1 for /32, got %d", retrieved.TotalIPs)
		}
	})
}

func TestNewMemoryBackendWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("creates backend with nil config", func(t *testing.T) {
		t.Parallel()
		backend := NewMemoryBackendWithConfig(nil)
		defer backend.Close()

		if backend == nil {
			t.Fatal("expected non-nil backend")
		}

		// Should work normally
		ctx := context.Background()
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}
	})

	t.Run("creates backend with custom logger", func(t *testing.T) {
		t.Parallel()
		logger := slog.Default()
		config := &MemoryBackendConfig{
			Logger: logger,
		}
		backend := NewMemoryBackendWithConfig(config)
		defer backend.Close()

		if backend == nil {
			t.Fatal("expected non-nil backend")
		}

		// Should work normally
		ctx := context.Background()
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}
	})

	t.Run("creates backend with nil logger in config", func(t *testing.T) {
		t.Parallel()
		config := &MemoryBackendConfig{
			Logger: nil,
		}
		backend := NewMemoryBackendWithConfig(config)
		defer backend.Close()

		if backend == nil {
			t.Fatal("expected non-nil backend")
		}
	})

	t.Run("stamps pools from the configured clock", func(t *testing.T) {
		t.Parallel()
		clock := newManualClock()
		backend := newClockedMemoryBackend(clock)
		defer backend.Close()

		ctx := context.Background()
		require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}))
		got, err := backend.GetPool(ctx, "pool-1")
		require.NoError(t, err)
		assert.Equal(t, clock.Now(), got.CreatedAt)
	})

	t.Run("falls back to the wall clock when no clock is configured", func(t *testing.T) {
		t.Parallel()
		backend := NewMemoryBackendWithConfig(&MemoryBackendConfig{Clock: nil})
		defer backend.Close()

		ctx := context.Background()
		before := time.Now()
		require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}))
		got, err := backend.GetPool(ctx, "pool-1")
		require.NoError(t, err)
		assert.False(t, got.CreatedAt.Before(before), "a nil Clock must fall back to time.Now")
	})
}

// TestMemoryBackend_ReleaseAfterExpiryCountsTheAddressOnce is the #730
// regression: ExpireInactive already returns the address to the pool, so a
// later Release must record the release without counting it free again.
// Before the fix AllocatedIPs, a uint64, wrapped to 2^64-1.
func TestMemoryBackend_ReleaseAfterExpiryCountsTheAddressOnce(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
		ID:                "pool-1",
		Name:              "expiry-pool",
		CIDR:              netip.MustParsePrefix("10.0.0.0/24"),
		InactivityTimeout: time.Hour,
	}))
	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "device-1"})
	require.NoError(t, err)

	// Backdate the stored allocation past the inactivity timeout rather than
	// waiting it out.
	backend.mu.Lock()
	backend.allocations[alloc.IP].LastSeen = time.Time{}
	backend.mu.Unlock()

	expired, err := backend.ExpireInactive(ctx, "pool-1")
	require.NoError(t, err)
	require.Len(t, expired, 1)

	require.NoError(t, backend.Release(ctx, alloc.IP))

	stats, err := backend.GetPoolStats(ctx, "pool-1")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), stats.AllocatedIPs, "the expired address must not be counted free a second time")
	assert.Equal(t, stats.TotalIPs, stats.AvailableIPs)

	got, err := backend.GetAllocation(ctx, alloc.IP)
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusReleased, got.Status)
}

// TestMemoryBackend_ReleaseActiveFreesTheAddress covers the ordinary path the
// guard must keep: an active allocation's release returns its address.
func TestMemoryBackend_ReleaseActiveFreesTheAddress(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
		ID: "pool-1", Name: "active-pool", CIDR: netip.MustParsePrefix("10.0.1.0/30"),
	}))
	first, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "a"})
	require.NoError(t, err)
	_, err = backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "b"})
	require.NoError(t, err)

	// A /30 holds two usable addresses: the pool is full until one is released.
	_, err = backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "c"})
	require.ErrorIs(t, err, ipam.ErrPoolExhausted)

	require.NoError(t, backend.Release(ctx, first.IP))
	again, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-1", DeviceID: "c"})
	require.NoError(t, err)
	assert.Equal(t, first.IP, again.IP, "the released address is allocatable again")
	require.ErrorIs(t, backend.Release(ctx, netip.MustParseAddr("10.0.1.3")), ipam.ErrAllocationNotFound)
}

//go:build !platform_p2p

// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package backends

import (
	"context"
	"testing"

	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// ─────────────────────────────────────────────────────────────────────────────
// Memory backend — Zone field round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestMemoryBackend_PoolZoneRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	pool := &ipam.Pool{
		ID:   "zone-pool",
		Name: "zone-pool",
		CIDR: netip.MustParsePrefix("10.50.0.0/24"),
		Zone: "control-plane",
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	got, err := backend.GetPool(ctx, "zone-pool")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if got.Zone != "control-plane" {
		t.Errorf("Pool.Zone round-trip: want %q, got %q", "control-plane", got.Zone)
	}
}

func TestMemoryBackend_AllocationZoneStampedFromPool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	pool := &ipam.Pool{
		ID:   "stamp-pool",
		Name: "stamp-pool",
		CIDR: netip.MustParsePrefix("10.51.0.0/24"),
		Zone: "provisioning",
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   "stamp-pool",
		DeviceID: "dev-01",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if alloc.Zone != "provisioning" {
		t.Errorf("Allocation.Zone: want %q, got %q", "provisioning", alloc.Zone)
	}
}

func TestMemoryBackend_AllocationSpecificZoneStampedFromPool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	pool := &ipam.Pool{
		ID:   "specific-zone-pool",
		Name: "specific-zone-pool",
		CIDR: netip.MustParsePrefix("10.52.0.0/24"),
		Zone: "management",
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	alloc, err := backend.AllocateSpecific(ctx, &ipam.AllocationRequest{
		PoolID:      "specific-zone-pool",
		DeviceID:    "dev-02",
		RequestedIP: netip.MustParseAddr("10.52.0.5"),
	})
	if err != nil {
		t.Fatalf("AllocateSpecific: %v", err)
	}

	if alloc.Zone != "management" {
		t.Errorf("Allocation.Zone (AllocateSpecific): want %q, got %q", "management", alloc.Zone)
	}
}

func TestMemoryBackend_ListPoolsByZone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := NewMemoryBackend()
	t.Cleanup(func() { backend.Close() })

	pools := []struct {
		id   string
		cidr string
		zone string
	}{
		{"pool-a", "10.60.0.0/24", "control-plane"},
		{"pool-b", "10.61.0.0/24", "provisioning"},
		{"pool-c", "10.62.0.0/24", "control-plane"},
		{"pool-d", "10.63.0.0/24", ""},
	}

	for _, p := range pools {
		if err := backend.CreatePool(ctx, &ipam.Pool{
			ID:   p.id,
			Name: p.id,
			CIDR: netip.MustParsePrefix(p.cidr),
			Zone: p.zone,
		}); err != nil {
			t.Fatalf("CreatePool %s: %v", p.id, err)
		}
	}

	t.Run("filter by trusted", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "control-plane")
		if err != nil {
			t.Fatalf("ListPoolsByZone: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 trusted pools, got %d", len(result))
		}
	})

	t.Run("filter by provisioning", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "provisioning")
		if err != nil {
			t.Fatalf("ListPoolsByZone: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("expected 1 provisioning pool, got %d", len(result))
		}
	})

	t.Run("empty zone returns all", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "")
		if err != nil {
			t.Fatalf("ListPoolsByZone(empty): %v", err)
		}
		if len(result) != 4 {
			t.Errorf("expected 4 pools for empty zone filter, got %d", len(result))
		}
	})

	t.Run("no match returns empty slice", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "quarantine")
		if err != nil {
			t.Fatalf("ListPoolsByZone(quarantine): %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 quarantine pools, got %d", len(result))
		}
	})
}

func TestMemoryBackend_PoolZoneEmptyWhenNotSet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	pool := &ipam.Pool{
		ID:   "no-zone",
		Name: "no-zone",
		CIDR: netip.MustParsePrefix("10.70.0.0/24"),
		// Zone intentionally omitted
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	got, err := backend.GetPool(ctx, "no-zone")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if got.Zone != "" {
		t.Errorf("Pool.Zone should be empty when not set, got %q", got.Zone)
	}

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   "no-zone",
		DeviceID: "dev-x",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if alloc.Zone != "" {
		t.Errorf("Allocation.Zone should be empty for zoneless pool, got %q", alloc.Zone)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// QuicBaaS backend — Zone field round-trip (using mock client)
// ─────────────────────────────────────────────────────────────────────────────

func TestQuicBaaSBackend_PoolZoneRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("NewQuicBaaSBackend: %v", err)
	}

	pool := &ipam.Pool{
		ID:   "qb-zone-pool",
		Name: "qb-zone-pool",
		CIDR: netip.MustParsePrefix("172.16.10.0/24"),
		Zone: "storage",
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	got, err := backend.GetPool(ctx, "qb-zone-pool")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if got.Zone != "storage" {
		t.Errorf("Pool.Zone round-trip (quicbaas): want %q, got %q", "storage", got.Zone)
	}
}

func TestQuicBaaSBackend_AllocationZoneStampedFromPool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("NewQuicBaaSBackend: %v", err)
	}

	pool := &ipam.Pool{
		ID:   "qb-stamp-pool",
		Name: "qb-stamp-pool",
		CIDR: netip.MustParsePrefix("172.16.20.0/24"),
		Zone: "tenant",
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   "qb-stamp-pool",
		DeviceID: "qb-dev-01",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if alloc.Zone != "tenant" {
		t.Errorf("Allocation.Zone (quicbaas): want %q, got %q", "tenant", alloc.Zone)
	}
}

func TestQuicBaaSBackend_ListPoolsByZone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("NewQuicBaaSBackend: %v", err)
	}

	for _, p := range []struct {
		id   string
		cidr string
		zone string
	}{
		{"qb-trusted-1", "172.16.100.0/24", "control-plane"},
		{"qb-trusted-2", "172.16.101.0/24", "control-plane"},
		{"qb-prov-1", "172.16.102.0/24", "provisioning"},
	} {
		if err := backend.CreatePool(ctx, &ipam.Pool{
			ID:   p.id,
			Name: p.id,
			CIDR: netip.MustParsePrefix(p.cidr),
			Zone: p.zone,
		}); err != nil {
			t.Fatalf("CreatePool %s: %v", p.id, err)
		}
	}

	t.Run("filter trusted", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "control-plane")
		if err != nil {
			t.Fatalf("ListPoolsByZone: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("want 2 trusted pools, got %d", len(result))
		}
	})

	t.Run("empty zone returns all", func(t *testing.T) {
		t.Parallel()
		result, err := backend.ListPoolsByZone(ctx, "")
		if err != nil {
			t.Fatalf("ListPoolsByZone(empty): %v", err)
		}
		if len(result) != 3 {
			t.Errorf("want 3 pools for empty filter, got %d", len(result))
		}
	})
}

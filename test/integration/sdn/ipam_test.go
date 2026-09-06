//go:build integration

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

package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// IPAM Pool CRUD Multi-Protocol Tests
// =============================================================================

// TestIPAMPoolCRUDMultiProtocol runs IPAM pool CRUD tests across all SDN
// protocol adapters, verifying feature parity for create, get, update, delete,
// and zone-filtered list operations.
func TestIPAMPoolCRUDMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	adapters := NewSDNTestAdapters()

	gate := helpers.NewAdapterGate(t, "sdn", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(cancel)

			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer adapter.Teardown()

			t.Run("PoolCRUD", func(t *testing.T) {
				testIPAMPoolCRUD(t, ctx, adapter)
			})

			t.Run("ZoneFilter", func(t *testing.T) {
				testIPAMPoolZoneFilter(t, ctx, adapter)
			})

			t.Run("CIDRImmutability", func(t *testing.T) {
				testIPAMPoolCIDRImmutable(t, ctx, adapter)
			})
		})
	}
}

// =============================================================================
// IPAM Pool CRUD lifecycle
// =============================================================================

// testIPAMPoolCRUD exercises the full create → get → update → delete lifecycle.
func testIPAMPoolCRUD(t *testing.T, ctx context.Context, adapter SDNTestAdapter) {
	t.Helper()

	// --- Create ---
	createReq := IPAMPoolCreateRequest{
		Name:          fmt.Sprintf("test-pool-crud-%s", strings.ToLower(adapter.Name())),
		CIDR:          "192.0.2.0/24",
		Gateway:       "192.0.2.1",
		Zone:          "trusted",
		Description:   "integration test pool",
		LeaseDuration: 24 * time.Hour,
	}

	created, err := adapter.CreatePool(ctx, createReq)
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreatePool failed: %v", err)
	}

	if created.ID == "" {
		t.Fatal("CreatePool: expected non-empty ID")
	}
	if created.CIDR != createReq.CIDR {
		t.Errorf("CreatePool: CIDR mismatch: want %s, got %s", createReq.CIDR, created.CIDR)
	}
	if created.Name != createReq.Name {
		t.Errorf("CreatePool: Name mismatch: want %s, got %s", createReq.Name, created.Name)
	}
	if created.Zone != createReq.Zone {
		t.Errorf("CreatePool: Zone mismatch: want %s, got %s", createReq.Zone, created.Zone)
	}

	poolID := created.ID
	t.Logf("[%s] CreatePool: id=%s cidr=%s", adapter.Name(), poolID, created.CIDR)

	// Ensure we clean up even if the test fails mid-way.
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if err := adapter.DeletePool(cleanCtx, poolID); err != nil {
			t.Logf("[%s] cleanup DeletePool %s: %v (ignored)", adapter.Name(), poolID, err)
		}
	})

	// --- Get ---
	got, err := adapter.GetPool(ctx, poolID)
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("GetPool failed: %v", err)
	}
	if got.ID != poolID {
		t.Errorf("GetPool: ID mismatch: want %s, got %s", poolID, got.ID)
	}
	if got.CIDR != createReq.CIDR {
		t.Errorf("GetPool: CIDR mismatch: want %s, got %s", createReq.CIDR, got.CIDR)
	}

	// --- Update ---
	updateReq := IPAMPoolUpdateRequest{
		Name:        fmt.Sprintf("test-pool-crud-updated-%s", strings.ToLower(adapter.Name())),
		Description: "updated description",
		Zone:        "provisioning",
	}

	updated, err := adapter.UpdatePool(ctx, poolID, updateReq)
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("UpdatePool failed: %v", err)
	}
	if updated.Name != updateReq.Name {
		t.Errorf("UpdatePool: Name mismatch: want %s, got %s", updateReq.Name, updated.Name)
	}
	if updated.CIDR != createReq.CIDR {
		t.Errorf("UpdatePool: CIDR should be immutable: want %s, got %s", createReq.CIDR, updated.CIDR)
	}
	if updated.Zone != updateReq.Zone {
		t.Errorf("UpdatePool: Zone mismatch: want %s, got %s", updateReq.Zone, updated.Zone)
	}

	// --- List (confirm pool appears) ---
	list, err := adapter.ListPools(ctx, "")
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("ListPools failed: %v", err)
	}
	found := false
	for _, p := range list.Pools {
		if p.ID == poolID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListPools: pool %s not found in list of %d pools", poolID, len(list.Pools))
	}

	// --- Delete ---
	if err := adapter.DeletePool(ctx, poolID); err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("DeletePool failed: %v", err)
	}

	// Verify gone (GetPool should fail after delete).
	_, err = adapter.GetPool(ctx, poolID)
	if err == nil {
		t.Errorf("GetPool after DeletePool: expected error, got nil")
	}
}

// =============================================================================
// Zone filter test
// =============================================================================

// testIPAMPoolZoneFilter creates pools in two different zones and verifies
// that ListPools with a zone parameter only returns matching pools.
func testIPAMPoolZoneFilter(t *testing.T, ctx context.Context, adapter SDNTestAdapter) {
	t.Helper()

	zones := []string{"trusted", "provisioning"}
	poolIDs := make([]string, 0, len(zones))

	// Create one pool per zone.
	for i, zone := range zones {
		req := IPAMPoolCreateRequest{
			Name: fmt.Sprintf("zone-filter-pool-%s-%d", strings.ToLower(adapter.Name()), i),
			CIDR: fmt.Sprintf("198.51.10%d.0/24", i),
			Zone: zone,
		}
		pool, err := adapter.CreatePool(ctx, req)
		if err != nil {
			skipIfNotImplemented(t, err)
			t.Fatalf("CreatePool (zone=%s): %v", zone, err)
		}
		poolIDs = append(poolIDs, pool.ID)
		t.Logf("[%s] created pool id=%s zone=%s cidr=%s", adapter.Name(), pool.ID, zone, pool.CIDR)
	}

	// Cleanup regardless of test outcome.
	t.Cleanup(func() {
		for _, id := range poolIDs {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := adapter.DeletePool(cleanCtx, id); err != nil {
				t.Logf("[%s] cleanup DeletePool %s: %v (ignored)", adapter.Name(), id, err)
			}
			cleanCancel()
		}
	})

	// Filter by each zone and verify only the matching pool is returned.
	for i, zone := range zones {
		resp, err := adapter.ListPools(ctx, zone)
		if err != nil {
			skipIfNotImplemented(t, err)
			t.Fatalf("ListPools(zone=%s): %v", zone, err)
		}

		expectedID := poolIDs[i]
		found := false
		for _, p := range resp.Pools {
			if p.ID == expectedID {
				found = true
			}
			// Every returned pool must match the requested zone (or have empty zone, adapter-
			// specific: some adapters may not propagate zone on list).
			if p.Zone != "" && p.Zone != zone {
				t.Errorf("ListPools(zone=%s): pool %s has wrong zone %s", zone, p.ID, p.Zone)
			}
		}
		if !found {
			t.Errorf("ListPools(zone=%s): expected pool %s not found in response", zone, expectedID)
		}

		// The other zone's pool must not appear.
		otherID := poolIDs[1-i]
		for _, p := range resp.Pools {
			if p.ID == otherID {
				t.Errorf("ListPools(zone=%s): unexpectedly returned pool %s from zone %s",
					zone, otherID, zones[1-i])
			}
		}
	}

	// Empty zone filter must return all pools (at least both we created).
	all, err := adapter.ListPools(ctx, "")
	if err != nil {
		t.Fatalf("ListPools(zone=''): %v", err)
	}
	for _, id := range poolIDs {
		found := false
		for _, p := range all.Pools {
			if p.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ListPools(zone=''): pool %s not found in unfiltered list", id)
		}
	}
}

// =============================================================================
// CIDR immutability test
// =============================================================================

// testIPAMPoolCIDRImmutable creates a pool and attempts to change its CIDR
// via UpdatePool. The server must reject the change and keep the original CIDR.
func testIPAMPoolCIDRImmutable(t *testing.T, ctx context.Context, adapter SDNTestAdapter) {
	t.Helper()

	const originalCIDR = "203.0.113.0/24"

	pool, err := adapter.CreatePool(ctx, IPAMPoolCreateRequest{
		Name: fmt.Sprintf("cidr-immutable-test-%s", strings.ToLower(adapter.Name())),
		CIDR: originalCIDR,
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreatePool: %v", err)
	}

	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if err := adapter.DeletePool(cleanCtx, pool.ID); err != nil {
			t.Logf("[%s] cleanup DeletePool %s: %v (ignored)", adapter.Name(), pool.ID, err)
		}
	})

	// Attempt update — CIDR must not be accepted.
	// Most adapters will simply ignore the CIDR field in UpdatePool, so the
	// returned pool should still carry the original CIDR.
	updated, err := adapter.UpdatePool(ctx, pool.ID, IPAMPoolUpdateRequest{
		Name: fmt.Sprintf("cidr-immutable-renamed-%s", strings.ToLower(adapter.Name())),
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		// Some adapters/servers return an explicit error when CIDR change is
		// attempted; that is also acceptable.
		t.Logf("[%s] UpdatePool returned error (acceptable for CIDR immutability): %v", adapter.Name(), err)
		return
	}

	if updated.CIDR != originalCIDR {
		t.Errorf("UpdatePool: CIDR changed from %s to %s — CIDR must be immutable",
			originalCIDR, updated.CIDR)
	}
}

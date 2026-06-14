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

package dhcp_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// newTestAllocator creates an in-memory allocator pre-seeded with pools.
func newTestAllocator(t *testing.T, pools ...ipam.Pool) ipam.Allocator {
	t.Helper()
	alloc := backends.NewMemoryBackend()
	ctx := context.Background()
	for i := range pools {
		if err := alloc.CreatePool(ctx, &pools[i]); err != nil {
			t.Fatalf("seed pool %q: %v", pools[i].Name, err)
		}
	}
	return alloc
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvePoolForZone — explicit binding (highest precedence)
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvePoolForZone_Explicit_TakesPrecedence(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t,
		ipam.Pool{
			ID:   "prov-pool",
			Name: "prov-pool",
			CIDR: netip.MustParsePrefix("172.16.201.0/24"),
			Zone: "provisioning",
		},
	)

	// Explicit pool ID set; zone also set — explicit must win.
	poolID, res, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "prov-pool", "provisioning", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poolID != "prov-pool" {
		t.Errorf("want poolID %q, got %q", "prov-pool", poolID)
	}
	if res != dhcp.PoolResolutionExplicit {
		t.Errorf("want PoolResolutionExplicit, got %v", res)
	}
}

func TestResolvePoolForZone_Explicit_NoAllocatorNeeded(t *testing.T) {
	t.Parallel()

	// Even with a nil allocator, explicit must return without panic.
	poolID, res, err := dhcp.ResolvePoolForZone(context.Background(), nil, "direct-pool", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poolID != "direct-pool" {
		t.Errorf("want %q, got %q", "direct-pool", poolID)
	}
	if res != dhcp.PoolResolutionExplicit {
		t.Errorf("want PoolResolutionExplicit, got %v", res)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvePoolForZone — zone-derived selection
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvePoolForZone_ZoneDerived_SingleMatch(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t,
		ipam.Pool{
			ID:   "prov-pool",
			Name: "prov-pool",
			CIDR: netip.MustParsePrefix("172.16.201.0/24"),
			Zone: "provisioning",
		},
		ipam.Pool{
			ID:   "trusted-pool",
			Name: "trusted-pool",
			CIDR: netip.MustParsePrefix("198.18.0.0/24"),
			Zone: "trusted",
		},
	)

	poolID, res, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "provisioning", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poolID != "prov-pool" {
		t.Errorf("want %q, got %q", "prov-pool", poolID)
	}
	if res != dhcp.PoolResolutionZone {
		t.Errorf("want PoolResolutionZone, got %v", res)
	}
}

func TestResolvePoolForZone_ZoneDerived_NoMatch_ReturnsErrNoPoolForZone(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t)

	_, _, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "storage", "")
	var target dhcp.ErrNoPoolForZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrNoPoolForZone, got %T: %v", err, err)
	}
	if target.Zone != "storage" {
		t.Errorf("want Zone %q in error, got %q", "storage", target.Zone)
	}
}

func TestResolvePoolForZone_ZoneDerived_MultipleMatches_ReturnsErrAmbiguousZonePool(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t,
		ipam.Pool{
			ID:   "prov-a",
			Name: "prov-a",
			CIDR: netip.MustParsePrefix("172.16.201.0/25"),
			Zone: "provisioning",
		},
		ipam.Pool{
			ID:   "prov-b",
			Name: "prov-b",
			CIDR: netip.MustParsePrefix("172.16.201.128/25"),
			Zone: "provisioning",
		},
	)

	_, _, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "provisioning", "")
	var target dhcp.ErrAmbiguousZonePool
	if !errors.As(err, &target) {
		t.Errorf("want ErrAmbiguousZonePool, got %T: %v", err, err)
	}
	if target.Count != 2 {
		t.Errorf("want Count 2, got %d", target.Count)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvePoolForZone — segment legacy fallback
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvePoolForZone_Segment_Fallback(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t,
		ipam.Pool{
			ID:   "provisioning",
			Name: "provisioning",
			CIDR: netip.MustParsePrefix("172.16.201.0/24"),
			Zone: "provisioning",
		},
	)

	// No explicit pool, no zone — falls back to segment name.
	poolID, res, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "", "provisioning")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poolID != "provisioning" {
		t.Errorf("want %q, got %q", "provisioning", poolID)
	}
	if res != dhcp.PoolResolutionSegment {
		t.Errorf("want PoolResolutionSegment, got %v", res)
	}
}

func TestResolvePoolForZone_Segment_NotFound_ReturnsError(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t)

	_, _, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing segment pool, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvePoolForZone — nothing provided
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvePoolForZone_NothingProvided_ReturnsErrPoolIDRequired(t *testing.T) {
	t.Parallel()

	alloc := newTestAllocator(t)

	_, _, err := dhcp.ResolvePoolForZone(context.Background(), alloc, "", "", "")
	if !errors.Is(err, dhcp.ErrPoolIDRequired) {
		t.Errorf("want ErrPoolIDRequired, got %T: %v", err, err)
	}
}

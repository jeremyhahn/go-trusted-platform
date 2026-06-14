//go:build !platform_p2p

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

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	sdnzone "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// newSDNTestApp builds the minimal App needed for initIPAMPools tests.
func newSDNTestApp(t *testing.T, ipamCfg *sdn.IPAMConfig) *App {
	t.Helper()
	app := &App{
		Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
		SDNConfig: &sdn.Config{
			Enabled: true,
			IPAM:    ipamCfg,
		},
	}
	return app
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend dispatch
// ─────────────────────────────────────────────────────────────────────────────

func TestInitIPAMPools_MemoryDefault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		// Backend intentionally empty → should default to memory.
		Pools: []sdn.PoolConfig{
			{Name: "default-pool", CIDR: netip.MustParsePrefix("10.0.0.0/24"), Zone: "trusted"},
		},
	})

	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}

	if app.ipamAllocator == nil {
		t.Fatal("ipamAllocator must be set after initIPAMPools")
	}

	pool, err := app.ipamAllocator.GetPoolByName(ctx, "default-pool")
	if err != nil {
		t.Fatalf("GetPoolByName: %v", err)
	}
	if pool.Zone != "trusted" {
		t.Errorf("Pool.Zone: want %q, got %q", "trusted", pool.Zone)
	}
}

func TestInitIPAMPools_ExplicitMemoryBackend(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		Pools: []sdn.PoolConfig{
			{Name: "mem-pool", CIDR: netip.MustParsePrefix("10.1.0.0/24")},
		},
	})

	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}

	if app.ipamAllocator == nil {
		t.Fatal("ipamAllocator must be set")
	}
}

func TestInitIPAMPools_UnknownBackend(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "redis",
	})

	err := app.initIPAMPools(ctx)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
	var target sdn.ErrIPAMBackendUnknown
	if !errors.As(err, &target) {
		t.Errorf("want ErrIPAMBackendUnknown, got %T: %v", err, err)
	}
	if target.Backend != "redis" {
		t.Errorf("Backend field: want %q, got %q", "redis", target.Backend)
	}
}

func TestInitIPAMPools_DHTBackendWithoutP2P(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "dht",
	})

	err := app.initIPAMPools(ctx)
	if err == nil {
		t.Fatal("expected error for dht backend without p2p, got nil")
	}
	var target sdn.ErrIPAMBackendP2PRequired
	if !errors.As(err, &target) {
		t.Errorf("want ErrIPAMBackendP2PRequired, got %T: %v", err, err)
	}
}

func TestInitIPAMPools_QuicBaaSBackendWithoutClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// App has no daoFactory → QuicBaaSSDKClient() returns nil.
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "quicbaas",
	})

	err := app.initIPAMPools(ctx)
	if err == nil {
		t.Fatal("expected error for quicbaas backend without client, got nil")
	}
	var target sdn.ErrIPAMBackendUnconfigured
	if !errors.As(err, &target) {
		t.Errorf("want ErrIPAMBackendUnconfigured, got %T: %v", err, err)
	}
	if target.Backend != "quicbaas" {
		t.Errorf("Backend field: want %q, got %q", "quicbaas", target.Backend)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Seeding semantics
// ─────────────────────────────────────────────────────────────────────────────

// TestInitIPAMPools_SeedCreateIfMissing verifies that pools that don't exist
// in the backend are created with the correct zone.
func TestInitIPAMPools_SeedCreateIfMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		Pools: []sdn.PoolConfig{
			{Name: "new-pool", CIDR: netip.MustParsePrefix("10.2.0.0/24"), Zone: "provisioning"},
		},
	})

	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}

	pool, err := app.ipamAllocator.GetPoolByName(ctx, "new-pool")
	if err != nil {
		t.Fatalf("GetPoolByName: %v", err)
	}
	if pool.Zone != "provisioning" {
		t.Errorf("Pool.Zone: want %q, got %q", "provisioning", pool.Zone)
	}
}

// TestInitIPAMPools_SeedIdempotent verifies that calling initIPAMPools twice
// does not fail and does not mutate or recreate the pre-existing pool.
func TestInitIPAMPools_SeedIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		Pools: []sdn.PoolConfig{
			{Name: "idem-pool", CIDR: netip.MustParsePrefix("10.3.0.0/24"), Zone: "trusted"},
		},
	})

	// First run: create pool.
	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("first initIPAMPools: %v", err)
	}

	// Allocate an IP so we can detect if the pool was recreated (which would
	// wipe the allocation).
	alloc, err := app.ipamAllocator.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   "idem-pool",
		DeviceID: "probe-device",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	allocatedIP := alloc.IP

	// Preserve the existing backend and override the factory to simulate a
	// persistent backend that survives restart (so the second run sees the
	// existing pool).
	existingAllocator := app.ipamAllocator
	app.ipamAllocator = nil

	original := ipamBackendFactory["memory"]
	defer func() { ipamBackendFactory["memory"] = original }()

	ipamBackendFactory["memory"] = func(ctx context.Context, a *App) (ipam.Allocator, error) {
		return existingAllocator, nil
	}

	// Second run: must be a no-op for the existing pool.
	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("second initIPAMPools: %v", err)
	}

	// The allocation from the first run must still be present.
	retrieved, err := app.ipamAllocator.GetAllocation(ctx, allocatedIP)
	if err != nil {
		t.Fatalf("GetAllocation after second init: %v", err)
	}
	if retrieved.IP != allocatedIP {
		t.Errorf("allocation IP changed after re-seed: want %v, got %v", allocatedIP, retrieved.IP)
	}
}

// TestInitIPAMPools_ExistingPoolNotOverwritten verifies that an existing pool
// in the backend is not modified when the seed config is run again.
func TestInitIPAMPools_ExistingPoolNotOverwritten(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Build a pre-seeded backend with a pool that has a different zone than
	// the config — the seed must NOT overwrite it.
	existingBackend := backends.NewMemoryBackend()
	if err := existingBackend.CreatePool(ctx, &ipam.Pool{
		ID:   "pre-existing",
		Name: "pre-existing",
		CIDR: netip.MustParsePrefix("10.4.0.0/24"),
		Zone: "management", // set by a previous runtime create
	}); err != nil {
		t.Fatalf("pre-seed CreatePool: %v", err)
	}

	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		// Config says zone=trusted but the runtime pool already exists with zone=management.
		Pools: []sdn.PoolConfig{
			{Name: "pre-existing", CIDR: netip.MustParsePrefix("10.4.0.0/24"), Zone: "trusted"},
		},
	})

	// Override factory to return the pre-seeded backend.
	original := ipamBackendFactory["memory"]
	defer func() { ipamBackendFactory["memory"] = original }()
	ipamBackendFactory["memory"] = func(ctx context.Context, a *App) (ipam.Allocator, error) {
		return existingBackend, nil
	}

	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}

	pool, err := app.ipamAllocator.GetPoolByName(ctx, "pre-existing")
	if err != nil {
		t.Fatalf("GetPoolByName: %v", err)
	}
	// The zone must remain "management" (runtime value), not "trusted" (config).
	if pool.Zone != "management" {
		t.Errorf("existing pool Zone was modified: want %q, got %q", "management", pool.Zone)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone derivation from subnets (deriveSDNFromSubnets)
// ─────────────────────────────────────────────────────────────────────────────

// TestDeriveSDNFromSubnets_ZonePropagatedToPool verifies that the zone derived
// from the subnet name is written to the PoolConfig.Zone field.
func TestDeriveSDNFromSubnets_ZonePropagatedToPool(t *testing.T) {
	t.Parallel()

	cases := []struct {
		subnetName string
		wantZone   sdnzone.Zone
	}{
		{"production", sdnzone.ZoneTrusted},
		{"provisioning", sdnzone.ZoneProvisioning},
		{"quarantine", sdnzone.ZoneQuarantine},
		{"storage", sdnzone.ZoneStorage},
		{"management", sdnzone.ZoneManagement},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.subnetName, func(t *testing.T) {
			t.Parallel()

			app := &App{
				Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
				SDNConfig: &sdn.Config{
					Enabled: true,
				},
				NetworkConfig: &installer.NetworkConfig{
					Subnets: []installer.SubnetConfig{
						{
							Name:   tc.subnetName,
							CIDR:   "10.100.0.0/24",
							Scope:  installer.SubnetScopeInternal,
							VLANID: 100,
						},
					},
				},
			}

			app.deriveSDNFromSubnets()

			if app.SDNConfig.IPAM == nil {
				t.Fatal("IPAM config must be populated by deriveSDNFromSubnets")
			}
			if len(app.SDNConfig.IPAM.Pools) != 1 {
				t.Fatalf("expected 1 pool, got %d", len(app.SDNConfig.IPAM.Pools))
			}

			got := app.SDNConfig.IPAM.Pools[0].Zone
			if got != string(tc.wantZone) {
				t.Errorf("PoolConfig.Zone for %q: want %q, got %q", tc.subnetName, tc.wantZone, got)
			}
		})
	}
}

// TestDeriveSDNFromSubnets_ExplicitPoolWins verifies that an explicit pool
// config entry takes precedence over the auto-derived one.
func TestDeriveSDNFromSubnets_ExplicitPoolWins(t *testing.T) {
	t.Parallel()

	app := &App{
		Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
		SDNConfig: &sdn.Config{
			Enabled: true,
			IPAM: &sdn.IPAMConfig{
				Pools: []sdn.PoolConfig{
					// Explicit entry for "provisioning" subnet.
					{Name: "provisioning", CIDR: netip.MustParsePrefix("10.200.0.0/24"), Zone: "management"},
				},
			},
		},
		NetworkConfig: &installer.NetworkConfig{
			Subnets: []installer.SubnetConfig{
				{
					Name:   "provisioning",
					CIDR:   "10.100.0.0/24", // different CIDR — explicit wins
					Scope:  installer.SubnetScopeInternal,
					VLANID: 100,
				},
			},
		},
	}

	app.deriveSDNFromSubnets()

	// There should still be only 1 pool (the explicit one was not replaced).
	if len(app.SDNConfig.IPAM.Pools) != 1 {
		t.Fatalf("expected 1 pool (explicit wins), got %d", len(app.SDNConfig.IPAM.Pools))
	}

	pool := app.SDNConfig.IPAM.Pools[0]
	if pool.CIDR.String() != "10.200.0.0/24" {
		t.Errorf("explicit pool CIDR should not be replaced: got %q", pool.CIDR)
	}
	if pool.Zone != "management" {
		t.Errorf("explicit pool Zone should not be replaced: got %q", pool.Zone)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Type round-trips
// ─────────────────────────────────────────────────────────────────────────────

func TestPool_ZoneClone(t *testing.T) {
	t.Parallel()

	p := &ipam.Pool{
		ID:   "test",
		Name: "test",
		CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		Zone: "management",
	}
	clone := p.Clone()
	if clone.Zone != "management" {
		t.Errorf("Clone() did not preserve Zone: got %q", clone.Zone)
	}
}

func TestAllocation_ZoneClone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := backends.NewMemoryBackend()
	defer b.Close()

	if err := b.CreatePool(ctx, &ipam.Pool{
		ID:   "z-pool",
		Name: "z-pool",
		CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		Zone: "quarantine",
	}); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	alloc, err := b.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   "z-pool",
		DeviceID: "d",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	clone := alloc.Clone()
	if clone.Zone != "quarantine" {
		t.Errorf("Clone() did not preserve Zone: got %q", clone.Zone)
	}
}

func TestAllocationRequest_ZoneClone(t *testing.T) {
	t.Parallel()

	req := &ipam.AllocationRequest{
		PoolID:   "p",
		DeviceID: "d",
		Zone:     "trusted",
	}
	clone := req.Clone()
	if clone.Zone != "trusted" {
		t.Errorf("AllocationRequest.Clone() did not preserve Zone: got %q", clone.Zone)
	}
}

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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	sdnzone "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// newSDNTestApp builds the minimal App needed for initIPAMPools tests: an
// environment-4 SDN section, validated so its plan exists.
func newSDNTestApp(t *testing.T, ipamCfg *sdn.IPAMConfig) *App {
	t.Helper()
	app := &App{
		Logger: logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
		SDNConfig: &sdn.Config{
			Enabled:     true,
			Environment: &netplan.Environment{ID: 4},
			IPAM:        ipamCfg,
		},
	}
	if err := app.SDNConfig.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
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
			{Name: "public", CIDR: netip.MustParsePrefix("203.0.113.0/24")},
		},
	})

	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}
	if app.ipamAllocator == nil {
		t.Fatal("ipamAllocator must be set after initIPAMPools")
	}
	if _, err := app.ipamAllocator.GetPoolByName(ctx, "public"); err != nil {
		t.Fatalf("explicit pool: %v", err)
	}
}

// TestInitIPAMPools_NoIPAMSectionUsesMemory seeds the plan on a controller
// without an ipam section.
func TestInitIPAMPools_NoIPAMSectionUsesMemory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, nil)
	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}
	if _, err := app.ipamAllocator.GetPoolByName(ctx, "control-plane"); err != nil {
		t.Fatalf("plan pool: %v", err)
	}
}

func TestInitIPAMPools_UnknownBackend(t *testing.T) {
	t.Parallel()

	app := newSDNTestApp(t, &sdn.IPAMConfig{Backend: "redis"})
	err := app.initIPAMPools(context.Background())
	var target sdn.ErrIPAMBackendUnknown
	if !errors.As(err, &target) || target.Backend != "redis" {
		t.Fatalf("want ErrIPAMBackendUnknown{redis}, got %v", err)
	}
}

func TestInitIPAMPools_DHTBackendWithoutP2P(t *testing.T) {
	t.Parallel()

	app := newSDNTestApp(t, &sdn.IPAMConfig{Backend: "dht"})
	if err := app.initIPAMPools(context.Background()); !errors.As(err, new(sdn.ErrIPAMBackendP2PRequired)) {
		t.Fatalf("want ErrIPAMBackendP2PRequired, got %v", err)
	}
}

func TestInitIPAMPools_QuicBaaSBackendWithoutClient(t *testing.T) {
	t.Parallel()

	// App has no daoFactory → QuicBaaSSDKClient() returns nil.
	app := newSDNTestApp(t, &sdn.IPAMConfig{Backend: "quicbaas"})
	err := app.initIPAMPools(context.Background())
	var target sdn.ErrIPAMBackendUnconfigured
	if !errors.As(err, &target) || target.Backend != "quicbaas" {
		t.Fatalf("want ErrIPAMBackendUnconfigured{quicbaas}, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Seeding semantics
// ─────────────────────────────────────────────────────────────────────────────

// TestInitIPAMPools_SeedsThePlan creates one pool per zone (gateway reserved,
// DHCP range from .50) and the IPAM ranges, and leaves the tenant default
// range unseeded.
func TestInitIPAMPools_SeedsThePlan(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, nil)
	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}

	prov, err := app.ipamAllocator.GetPoolByName(ctx, "provisioning")
	if err != nil {
		t.Fatalf("provisioning pool: %v", err)
	}
	if prov.CIDR.String() != "192.0.2.0/24" || prov.Zone != "provisioning" || prov.Gateway.String() != "192.0.2.1" {
		t.Errorf("provisioning pool = %+v", prov)
	}
	if prov.RangeStart.String() != "192.0.2.50" || prov.RangeEnd.String() != "192.0.2.254" {
		t.Errorf("provisioning range = %s-%s", prov.RangeStart, prov.RangeEnd)
	}
	if len(prov.Reserved) != 1 || prov.Reserved[0].String() != "192.0.2.1/32" {
		t.Errorf("provisioning reserved = %v", prov.Reserved)
	}

	tun, err := app.ipamAllocator.GetPoolByName(ctx, "tunnel-p2p")
	if err != nil {
		t.Fatalf("tunnel pool: %v", err)
	}
	if len(tun.Reserved) != 1 || tun.Reserved[0].String() != "10.4.128.0/31" {
		t.Errorf("tunnel reserved = %v", tun.Reserved)
	}
	if _, err := app.ipamAllocator.GetPoolByName(ctx, "tenant-default"); err == nil {
		t.Error("the tenant default range is carved, never seeded as one pool")
	}
}

// TestIPAMSeedPools_NeedsPlan refuses to seed without a plan.
func TestIPAMSeedPools_NeedsPlan(t *testing.T) {
	t.Parallel()

	app := &App{
		Logger:    logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, io.Discard),
		SDNConfig: &sdn.Config{Enabled: true},
	}
	if _, err := app.ipamSeedPools(); !errors.As(err, new(sdn.ErrEnvironmentRequired)) {
		t.Fatalf("want ErrEnvironmentRequired, got %v", err)
	}
	if err := app.seedIPAMPools(context.Background(), backends.NewMemoryBackend()); err == nil {
		t.Fatal("seeding without a plan must fail")
	}
}

// TestInitIPAMPools_ExplicitPoolReservesGateway seeds an explicit pool with
// its zone, range, lease and the gateway reserved.
func TestInitIPAMPools_ExplicitPoolReservesGateway(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		Pools: []sdn.PoolConfig{{
			Name:       "lab",
			CIDR:       netip.MustParsePrefix("198.51.100.0/24"),
			Gateway:    netip.MustParseAddr("198.51.100.1"),
			Zone:       "storage",
			RangeStart: netip.MustParseAddr("198.51.100.100"),
			RangeEnd:   netip.MustParseAddr("198.51.100.200"),
		}},
	})
	if err := app.initIPAMPools(ctx); err != nil {
		t.Fatalf("initIPAMPools: %v", err)
	}
	pool, err := app.ipamAllocator.GetPoolByName(ctx, "lab")
	if err != nil {
		t.Fatalf("GetPoolByName: %v", err)
	}
	if pool.Zone != "storage" || pool.RangeStart.String() != "198.51.100.100" {
		t.Errorf("pool = %+v", pool)
	}
	if len(pool.Reserved) != 1 || pool.Reserved[0].String() != "198.51.100.1/32" {
		t.Errorf("reserved = %v", pool.Reserved)
	}
}

// TestInitIPAMPools_SeedIdempotent verifies that seeding twice does not fail
// and does not mutate or recreate the pre-existing pool.
func TestInitIPAMPools_SeedIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app := newSDNTestApp(t, &sdn.IPAMConfig{
		Backend: "memory",
		Pools: []sdn.PoolConfig{
			{Name: "idem-pool", CIDR: netip.MustParsePrefix("203.0.113.0/24")},
		},
	})

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

	// Re-seed the SAME allocator, which is what a restart against a persistent
	// backend does: the pool already exists, so the seed must be a no-op.
	// Seeding is exercised directly rather than by substituting a constructor
	// in ipamBackendFactory — that map is read by every concurrent
	// initIPAMPools caller and writing it from a test is a data race (#37).
	existingAllocator := app.ipamAllocator
	if err := app.seedIPAMPools(ctx, existingAllocator); err != nil {
		t.Fatalf("second seedIPAMPools: %v", err)
	}

	retrieved, err := existingAllocator.GetAllocation(ctx, alloc.IP)
	if err != nil {
		t.Fatalf("GetAllocation after second init: %v", err)
	}
	if retrieved.IP != alloc.IP {
		t.Errorf("allocation IP changed after re-seed: want %v, got %v", alloc.IP, retrieved.IP)
	}
}

// TestInitIPAMPools_ExistingPoolNotOverwritten verifies that an existing pool
// in the backend is not modified when the seed runs again.
func TestInitIPAMPools_ExistingPoolNotOverwritten(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	existingBackend := backends.NewMemoryBackend()
	if err := existingBackend.CreatePool(ctx, &ipam.Pool{
		ID:         "control-plane",
		Name:       "control-plane",
		CIDR:       netip.MustParsePrefix("10.4.6.0/24"),
		Gateway:    netip.MustParseAddr("10.4.6.1"),
		Reserved:   []netip.Prefix{netip.MustParsePrefix("10.4.6.1/32")},
		RangeStart: netip.MustParseAddr("10.4.6.50"),
		RangeEnd:   netip.MustParseAddr("10.4.6.254"),
		Zone:       "management", // set by a previous runtime write
	}); err != nil {
		t.Fatalf("pre-seed CreatePool: %v", err)
	}

	app := newSDNTestApp(t, nil)
	if err := app.seedIPAMPools(ctx, existingBackend); err != nil {
		t.Fatalf("seedIPAMPools: %v", err)
	}

	pool, err := existingBackend.GetPoolByName(ctx, "control-plane")
	if err != nil {
		t.Fatalf("GetPoolByName: %v", err)
	}
	if pool.Zone != "management" {
		t.Errorf("existing pool Zone was modified: want %q, got %q", "management", pool.Zone)
	}
}

// TestSeedIPAMPools_RefusesDrift refuses a stored pool that has a plan
// pool's name but another prefix (a pool from an earlier network model)
// instead of silently keeping it.
func TestSeedIPAMPools_RefusesDrift(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := backends.NewMemoryBackend()
	if err := backend.CreatePool(ctx, &ipam.Pool{
		ID: "provisioning", Name: "provisioning", CIDR: netip.MustParsePrefix("172.16.201.0/24"),
	}); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	app := newSDNTestApp(t, nil)
	err := app.seedIPAMPools(ctx, backend)
	var target ErrSDNIPAMPoolDrift
	if !errors.As(err, &target) || target.Pool != "provisioning" {
		t.Fatalf("want ErrSDNIPAMPoolDrift{provisioning}, got %v", err)
	}
	for _, want := range []string{"172.16.201.0/24", "192.0.2.0/24", "re-bootstrap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

// TestSeedIPAMPools_CreateFailure surfaces a backend refusal as
// ErrSDNIPAMPoolCreate.
func TestSeedIPAMPools_CreateFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := backends.NewMemoryBackend()
	// An overlapping pool under another name makes CreatePool refuse.
	if err := backend.CreatePool(ctx, &ipam.Pool{ID: "squatter", Name: "squatter", CIDR: netip.MustParsePrefix("10.4.0.0/16")}); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	app := newSDNTestApp(t, nil)
	var target ErrSDNIPAMPoolCreate
	if err := app.seedIPAMPools(ctx, backend); !errors.As(err, &target) {
		t.Fatalf("want ErrSDNIPAMPoolCreate, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DHCP zones
// ─────────────────────────────────────────────────────────────────────────────

// TestDHCPZones serves only zones whose policy lists dhcp and on which the
// host holds an address.
func TestDHCPZones(t *testing.T) {
	t.Parallel()

	app := newSDNTestApp(t, nil)
	app.NetworkConfig = &installer.NetworkConfig{Bonds: []installer.BondConfig{{
		Name: "bond0",
		VLANs: []installer.BondVLANConfig{
			{Zone: "control-plane", IPv4Address: "10.4.6.10/24"},
		},
	}}}
	if got := app.dhcpZones(); len(got) != 0 {
		t.Fatalf("a reference control-plane node serves no DHCP, got %v", got)
	}

	app.NetworkConfig.Bonds[0].VLANs = append(app.NetworkConfig.Bonds[0].VLANs,
		installer.BondVLANConfig{Zone: "provisioning", IPv4Address: "192.0.2.2/24"},
		installer.BondVLANConfig{Zone: "storage", IPv4Address: "10.4.7.2/24"},
		installer.BondVLANConfig{Zone: "quarantine"}, // no address held
	)
	got := app.dhcpZones()
	if len(got) != 1 || got[0] != sdnzone.ZoneProvisioning {
		t.Fatalf("dhcp zones = %v, want [provisioning]", got)
	}
}

// TestLogDHCPStatus warns when dhcp is enabled but nothing qualifies.
func TestLogDHCPStatus(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	app := newSDNTestApp(t, nil)
	app.Logger = logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, &buf)
	app.SDNConfig.DHCP = &sdn.DHCPConfig{Enabled: true, Interface: "zone405"}
	app.logDHCPStatus()
	if !strings.Contains(buf.String(), "serves no DHCP") {
		t.Fatalf("log %q", buf.String())
	}

	buf.Reset()
	app.NetworkConfig = &installer.NetworkConfig{Bonds: []installer.BondConfig{{
		VLANs: []installer.BondVLANConfig{{Zone: "quarantine", IPv4Address: "10.4.4.2/24"}},
	}}}
	app.logDHCPStatus()
	if !strings.Contains(buf.String(), `"zone":"quarantine"`) {
		t.Fatalf("log %q", buf.String())
	}

	buf.Reset()
	app.SDNConfig.DHCP.Enabled = false
	app.logDHCPStatus()
	if buf.Len() != 0 {
		t.Fatalf("disabled dhcp logs nothing, got %q", buf.String())
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
		Zone:     "storage",
	}
	clone := req.Clone()
	if clone.Zone != "storage" {
		t.Errorf("AllocationRequest.Clone() did not preserve Zone: got %q", clone.Zone)
	}
}

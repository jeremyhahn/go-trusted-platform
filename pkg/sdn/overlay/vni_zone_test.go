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

package overlay

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vlan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// newStartedController creates a running overlay controller for zone VNI tests.
func newStartedController(t *testing.T) *Controller {
	t.Helper()
	cfg := &Config{
		NodeID:            "test-node-zone",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		UnderlayMTU:       9000,
		VXLANPort:         4789,
		BridgeName:        "br-overlay",
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Stop(context.Background())
	})
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// VNIConfig — Zone field parsing
// ─────────────────────────────────────────────────────────────────────────────

func TestVNIConfig_ZoneField_Preserved(t *testing.T) {
	t.Parallel()

	cfg := &VNIConfig{
		VNI:  1001,
		VLAN: 201,
		Zone: string(zone.ZoneProvisioning),
	}
	if cfg.Zone != string(zone.ZoneProvisioning) {
		t.Errorf("want Zone %q, got %q", zone.ZoneProvisioning, cfg.Zone)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AddVNI — explicit VNI always wins over zone-derived
// ─────────────────────────────────────────────────────────────────────────────

func TestAddVNI_ExplicitVNI_NoZoneDerivation(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	ctx := context.Background()

	err := c.AddVNI(ctx, &VNIConfig{
		VNI:  999999,
		VLAN: 200,
		Zone: string(zone.ZoneTenant), // would derive 1000+200 but explicit overrides
	})
	if err != nil {
		t.Fatalf("AddVNI with explicit VNI: %v", err)
	}

	info, err := c.GetVNI(ctx, 999999)
	if err != nil {
		t.Fatalf("GetVNI: %v", err)
	}
	if info.VNI != 999999 {
		t.Errorf("want VNI 999999, got %d", info.VNI)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AddVNI — zone-derived: tenant zone uses TenantBase
// ─────────────────────────────────────────────────────────────────────────────

func TestAddVNI_TenantZone_VLANOffset_UsesTenantBase(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	ctx := context.Background()

	// VNI zero + tenant zone + VLAN 5 → TenantBase + 5 = 1005
	cfg := &VNIConfig{
		VLAN: 5,
		Zone: string(zone.ZoneTenant),
	}
	if err := c.AddVNI(ctx, cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}

	expectedVNI := uint32(vlan.TenantBase) + 5
	info, err := c.GetVNI(ctx, expectedVNI)
	if err != nil {
		t.Fatalf("GetVNI(%d): %v", expectedVNI, err)
	}
	if info.VNI != expectedVNI {
		t.Errorf("want VNI %d, got %d", expectedVNI, info.VNI)
	}
}

func TestAddVNI_TenantZone_NoVLAN_SequentialAllocation(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	ctx := context.Background()

	// VNI zero, VLAN zero, tenant zone → TenantBase + count + 1
	cfg := &VNIConfig{
		Zone: string(zone.ZoneTenant),
	}
	if err := c.AddVNI(ctx, cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}

	// Must have allocated VNI >= TenantBase+1.
	vnis, err := c.ListVNIs(ctx)
	if err != nil {
		t.Fatalf("ListVNIs: %v", err)
	}
	if len(vnis) == 0 {
		t.Fatal("expected at least one VNI after AddVNI")
	}
	got := vnis[0].VNI
	if got < uint32(vlan.TenantBase)+1 {
		t.Errorf("tenant VNI should be >= %d, got %d", uint32(vlan.TenantBase)+1, got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AddVNI — zone-derived: non-tenant zone uses VNIBase
// ─────────────────────────────────────────────────────────────────────────────

func TestAddVNI_TrustedZone_VLANOffset_UsesVNIBase(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	ctx := context.Background()

	// VNI zero + trusted zone + VLAN 200 → VNIBase + 200
	cfg := &VNIConfig{
		VLAN: 200,
		Zone: string(zone.ZoneTrusted),
	}
	if err := c.AddVNI(ctx, cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}

	expectedVNI := DefaultVNIBase + 200
	info, err := c.GetVNI(ctx, expectedVNI)
	if err != nil {
		t.Fatalf("GetVNI(%d): %v", expectedVNI, err)
	}
	if info.VNI != expectedVNI {
		t.Errorf("want VNI %d, got %d", expectedVNI, info.VNI)
	}
}

func TestAddVNI_ProvisioningZone_VLANOffset_UsesVNIBase(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	ctx := context.Background()

	cfg := &VNIConfig{
		VLAN: 201,
		Zone: string(zone.ZoneProvisioning),
	}
	if err := c.AddVNI(ctx, cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}

	expectedVNI := DefaultVNIBase + 201
	info, err := c.GetVNI(ctx, expectedVNI)
	if err != nil {
		t.Fatalf("GetVNI(%d): %v", expectedVNI, err)
	}
	if info.VNI != expectedVNI {
		t.Errorf("want VNI %d, got %d", expectedVNI, info.VNI)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AddVNI — nil and invalid inputs
// ─────────────────────────────────────────────────────────────────────────────

func TestAddVNI_NilConfig_ReturnsErrVNINotFound(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	err := c.AddVNI(context.Background(), nil)
	if err != ErrVNINotFound {
		t.Errorf("want ErrVNINotFound, got %v", err)
	}
}

func TestAddVNI_ZeroVNI_NoZone_ReturnsValidationError(t *testing.T) {
	t.Parallel()

	c := newStartedController(t)
	// VNI 0 and no zone — Validate() on a VNI < MinVNI (1).
	err := c.AddVNI(context.Background(), &VNIConfig{VNI: 0})
	if err == nil {
		t.Fatal("VNI=0 with no zone must return an error (VNI out of range)")
	}
}

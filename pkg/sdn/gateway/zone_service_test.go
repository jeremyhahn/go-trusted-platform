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

package gateway

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ─────────────────────────────────────────────────────────────────────────────
// DHCPServiceConfig — Zone field
// ─────────────────────────────────────────────────────────────────────────────

func TestDHCPServiceConfig_ZoneField_Preserved(t *testing.T) {
	t.Parallel()

	cfg := &DHCPServiceConfig{
		Enabled:   true,
		Interface: "eth0",
		Zone:      "provisioning",
	}
	if cfg.Zone != "provisioning" {
		t.Errorf("want zone %q, got %q", "provisioning", cfg.Zone)
	}
}

func TestDHCPServiceConfig_SegmentField_StillWorks(t *testing.T) {
	t.Parallel()

	cfg := &DHCPServiceConfig{
		Enabled:   true,
		Interface: "eth0",
		Segment:   "provisioning",
	}
	if cfg.Segment != "provisioning" {
		t.Errorf("want segment %q, got %q", "provisioning", cfg.Segment)
	}
}

func TestDHCPServiceConfig_Validate_EnabledWithInterface_NoError(t *testing.T) {
	t.Parallel()

	cfg := &DHCPServiceConfig{
		Enabled:   true,
		Interface: "eth0",
		Zone:      "provisioning",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid DHCPServiceConfig must pass, got: %v", err)
	}
}

func TestDHCPServiceConfig_Validate_EnabledWithZoneNoInterface_ReturnsError(t *testing.T) {
	t.Parallel()

	cfg := &DHCPServiceConfig{
		Enabled: true,
		Zone:    "provisioning",
		// Interface is empty — must fail
	}
	if err := cfg.Validate(); err == nil {
		t.Error("enabled DHCP with no interface must fail validation")
	}
}

func TestDHCPServiceConfig_Validate_Disabled_NoError(t *testing.T) {
	t.Parallel()

	cfg := &DHCPServiceConfig{
		Enabled: false,
		// Interface and Zone absent — disabled config skips validation.
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled DHCPServiceConfig must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TransitServiceConfig
// ─────────────────────────────────────────────────────────────────────────────

func TestTransitServiceConfig_Validate_Enabled_NoError(t *testing.T) {
	t.Parallel()

	cfg := &TransitServiceConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Errorf("enabled TransitServiceConfig must pass, got: %v", err)
	}
}

func TestTransitServiceConfig_Validate_Disabled_NoError(t *testing.T) {
	t.Parallel()

	cfg := &TransitServiceConfig{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled TransitServiceConfig must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ManagementVPNServiceConfig
// ─────────────────────────────────────────────────────────────────────────────

func TestManagementVPNServiceConfig_Validate_Enabled_NoError(t *testing.T) {
	t.Parallel()

	cfg := &ManagementVPNServiceConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Errorf("enabled ManagementVPNServiceConfig must pass, got: %v", err)
	}
}

func TestManagementVPNServiceConfig_Validate_Disabled_NoError(t *testing.T) {
	t.Parallel()

	cfg := &ManagementVPNServiceConfig{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled ManagementVPNServiceConfig must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GatewayConfig — Transit and ManagementVPN service blocks
// ─────────────────────────────────────────────────────────────────────────────

func TestGatewayConfig_HasEnabledServices_TransitEnabled(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		Enabled: true,
		ID:      "gw-01",
		Transit: &TransitServiceConfig{Enabled: true},
	}
	if !cfg.HasEnabledServices() {
		t.Error("GatewayConfig with enabled Transit must report HasEnabledServices = true")
	}
}

func TestGatewayConfig_HasEnabledServices_ManagementVPNEnabled(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-01",
		ManagementVPN: &ManagementVPNServiceConfig{Enabled: true},
	}
	if !cfg.HasEnabledServices() {
		t.Error("GatewayConfig with enabled ManagementVPN must report HasEnabledServices = true")
	}
}

func TestGatewayConfig_HasEnabledServices_BothDisabled_ReturnsFalse(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-01",
		Transit:       &TransitServiceConfig{Enabled: false},
		ManagementVPN: &ManagementVPNServiceConfig{Enabled: false},
	}
	if cfg.HasEnabledServices() {
		t.Error("GatewayConfig with all services disabled must report HasEnabledServices = false")
	}
}

func TestGatewayConfig_Validate_WithTransitAndManagementVPN_NoError(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-01",
		Transit:       &TransitServiceConfig{Enabled: true},
		ManagementVPN: &ManagementVPNServiceConfig{Enabled: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("GatewayConfig with transit+management_vpn must pass, got: %v", err)
	}
}

func TestGatewayConfig_Validate_Disabled_SkipsServiceValidation(t *testing.T) {
	t.Parallel()

	// A disabled gateway skips all service validation.
	cfg := &GatewayConfig{
		Enabled: false,
		// ID absent — normally required but gate is disabled.
		Transit:       &TransitServiceConfig{Enabled: true},
		ManagementVPN: &ManagementVPNServiceConfig{Enabled: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled gateway must skip validation, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneService
// ─────────────────────────────────────────────────────────────────────────────

// testZoneService creates a ZoneService seeded with a minimal valid set of zones.
func testZoneService(t *testing.T) ZoneService {
	t.Helper()
	resolved := []zone.ZoneConfig{
		{Name: "trusted", Isolate: false},
		{Name: "public", InternetIngress: true},
		{Name: "provisioning", LifecycleRole: zone.LifecycleRoleProvisioning},
		{Name: "quarantine", LifecycleRole: zone.LifecycleRoleQuarantine},
	}
	svc, err := NewZoneService(resolved, map[string]zone.Zone{"corp-lan": "trusted"})
	if err != nil {
		t.Fatalf("NewZoneService: %v", err)
	}
	return svc
}

func TestNewZoneService_SeedsResolvedZones(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	recs, err := svc.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// The 4 explicit seeds override their built-in counterparts; Resolve
	// merges in the remaining built-ins (storage, tenant, management) = 7.
	if len(recs) != 7 {
		t.Errorf("expected 7 resolved zones (4 overrides + 3 built-ins), got %d", len(recs))
	}
}

func TestZoneService_Create_Success(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	cfg := zone.ZoneConfig{Name: "dmz", InternetIngress: true}
	rec, restartRequired, err := svc.Create(ctx, cfg)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.Config.Name != "dmz" {
		t.Errorf("expected zone name dmz, got %q", rec.Config.Name)
	}
	// A brand-new zone never requires restart.
	if restartRequired {
		t.Error("new zone should not require restart")
	}

	recs, _ := svc.List(ctx, "")
	if len(recs) != 8 {
		t.Errorf("expected 8 zones after create (7 resolved + dmz), got %d", len(recs))
	}
}

func TestZoneService_Create_DuplicateName_ReturnsError(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	_, _, err := svc.Create(ctx, zone.ZoneConfig{Name: "trusted"})
	if err == nil {
		t.Fatal("expected ErrZoneAlreadyExists, got nil")
	}
	if _, ok := err.(ErrZoneAlreadyExists); !ok {
		t.Errorf("expected ErrZoneAlreadyExists, got %T: %v", err, err)
	}
}

func TestZoneService_Update_Success_PolicyChange_ReturnsRestartRequired(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	// Changing Isolate triggers restartRequired.
	updatedCfg := zone.ZoneConfig{Name: "trusted", Isolate: true}
	rec, restartRequired, err := svc.Update(ctx, "trusted", updatedCfg)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rec.Config.Name != "trusted" {
		t.Errorf("unexpected zone name %q", rec.Config.Name)
	}
	if !restartRequired {
		t.Error("policy change must return restartRequired=true")
	}
}

func TestZoneService_Update_NotFound_ReturnsError(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	_, _, err := svc.Update(ctx, "nonexistent", zone.ZoneConfig{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected ErrZoneNotFound, got nil")
	}
	if _, ok := err.(ErrZoneNotFound); !ok {
		t.Errorf("expected ErrZoneNotFound, got %T: %v", err, err)
	}
}

func TestZoneService_Delete_Success(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	// First create a zone so we can delete it without breaking lifecycle roles.
	_, _, err := svc.Create(ctx, zone.ZoneConfig{Name: "scratch", Isolate: true})
	if err != nil {
		t.Fatalf("Create scratch: %v", err)
	}

	restartRequired, err := svc.Delete(ctx, "scratch")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Zone had Isolate=true so policy fields were set → restart required.
	if !restartRequired {
		t.Error("deleting an isolated zone must return restartRequired=true")
	}

	recs, _ := svc.List(ctx, "")
	for _, r := range recs {
		if r.Config.Name == "scratch" {
			t.Error("deleted zone still present in list")
		}
	}
}

func TestZoneService_Delete_NotFound_ReturnsError(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	_, err := svc.Delete(ctx, "ghost")
	if err == nil {
		t.Fatal("expected ErrZoneNotFound, got nil")
	}
	if _, ok := err.(ErrZoneNotFound); !ok {
		t.Errorf("expected ErrZoneNotFound, got %T: %v", err, err)
	}
}

func TestZoneService_List_FilterByLifecycleRole(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	recs, err := svc.List(ctx, zone.LifecycleRoleProvisioning)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 provisioning zone, got %d", len(recs))
	}
	if recs[0].Config.Name != "provisioning" {
		t.Errorf("expected zone 'provisioning', got %q", recs[0].Config.Name)
	}
}

func TestZoneService_AssignNetwork_Success(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	restartRequired, err := svc.AssignNetwork(ctx, "corp-lan", "public")
	if err != nil {
		t.Fatalf("AssignNetwork: %v", err)
	}
	// Reassigning always requires a flow rebuild.
	if !restartRequired {
		t.Error("network zone assignment must return restartRequired=true")
	}
}

func TestZoneService_AssignNetwork_UnknownZone_ReturnsError(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)
	ctx := context.Background()

	_, err := svc.AssignNetwork(ctx, "corp-lan", "phantom-zone")
	if err == nil {
		t.Fatal("expected ErrZoneNotFound, got nil")
	}
	if _, ok := err.(ErrZoneNotFound); !ok {
		t.Errorf("expected ErrZoneNotFound, got %T: %v", err, err)
	}
}

func TestZoneService_ZoneIndex_ReturnsSnapshot(t *testing.T) {
	t.Parallel()
	svc := testZoneService(t)

	idx := svc.ZoneIndex()
	if len(idx) != 7 {
		t.Errorf("expected 7 zones in index, got %d", len(idx))
	}
	if _, ok := idx["trusted"]; !ok {
		t.Error("index missing 'trusted' zone")
	}
}

func TestZoneService_ErrorTypes_ErrorStrings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{ErrZoneNotFound{Name: "x"}, `zone: zone "x" not found`},
		{ErrZoneAlreadyExists{Name: "y"}, `zone: zone "y" already exists`},
		{ErrNetworkNotFound{Name: "n"}, `zone: network "n" not found`},
		{ErrZoneValidation{Cause: ErrZoneNotFound{Name: "z"}}, `zone: validation failed: zone: zone "z" not found`},
	}
	for _, tc := range cases {
		if tc.err.Error() != tc.want {
			t.Errorf("Error() = %q, want %q", tc.err.Error(), tc.want)
		}
	}
}

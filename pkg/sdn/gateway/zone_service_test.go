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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
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

	if err := validVPNServiceConfig().Validate(); err != nil {
		t.Errorf("enabled ManagementVPNServiceConfig must pass, got: %v", err)
	}
}

// TestManagementVPNServiceConfig_Validate_EnabledNeedsPoolAndZones: an
// enabled VPN is checked against the core's own rules, defaults applied.
func TestManagementVPNServiceConfig_Validate_EnabledNeedsPoolAndZones(t *testing.T) {
	t.Parallel()

	err := (&ManagementVPNServiceConfig{Enabled: true}).Validate()
	var invalid *vpn.ErrInvalidConfig
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, "pool", invalid.Field)
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
		ID:      "edge-01",
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
		ID:            "edge-01",
		ManagementVPN: validVPNServiceConfig(),
	}
	if !cfg.HasEnabledServices() {
		t.Error("GatewayConfig with enabled ManagementVPN must report HasEnabledServices = true")
	}
}

func TestGatewayConfig_HasEnabledServices_BothDisabled_ReturnsFalse(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "edge-01",
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
		ID:            "edge-01",
		Transit:       &TransitServiceConfig{Enabled: true},
		ManagementVPN: validVPNServiceConfig(),
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
		ManagementVPN: validVPNServiceConfig(),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled gateway must skip validation, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneService
// ─────────────────────────────────────────────────────────────────────────────

// labZone is an owner-defined zone at offset 9 on the hypervisor trunk.
func labZone() zone.ZoneConfig {
	return zone.ZoneConfig{
		Name:        "lab",
		Offset:      9,
		PortClasses: []zone.PortClass{zone.PortClassHypervisor},
		Isolate:     true,
	}
}

// newEnvZoneService returns a zone service in environment 4 whose audit log
// is captured in the returned buffer.
func newEnvZoneService(t *testing.T, seed []zone.ZoneConfig) (*zoneService, *bytes.Buffer) {
	t.Helper()
	svc, err := NewZoneService(seed, &netplan.Environment{ID: 4})
	require.NoError(t, err)
	zs := svc.(*zoneService)
	var buf bytes.Buffer
	zs.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return zs, &buf
}

func zoneNames(recs []*ZoneRecord) []zone.Zone {
	out := make([]zone.Zone, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Config.Name)
	}
	return out
}

// TestNewZoneService_Builtins seeds the nine built-ins in offset order
// without an environment (no numbering).
func TestNewZoneService_Builtins(t *testing.T) {
	svc, err := NewZoneService(nil, nil)
	require.NoError(t, err)
	recs, err := svc.List(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []zone.Zone{
		zone.ZoneTransit, zone.ZoneFabric, zone.ZoneManagement, zone.ZoneHypervisor,
		zone.ZoneQuarantine, zone.ZoneProvisioning, zone.ZoneControlPlane, zone.ZoneStorage, zone.ZoneBackup,
	}, zoneNames(recs))
	for _, r := range recs {
		assert.Nil(t, r.Numbering, "no environment, no numbering")
		assert.False(t, r.CreatedAt.IsZero())
	}
}

// TestNewZoneService_SeedErrors refuses an invalid seed and a seed the
// environment cannot number.
func TestNewZoneService_SeedErrors(t *testing.T) {
	_, err := NewZoneService([]zone.ZoneConfig{{Name: "trusted", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassGateway}}}, nil)
	var verr ErrZoneValidation
	require.True(t, errors.As(err, &verr), "got %v", err)
	var reserved zone.ErrReservedZoneName
	assert.True(t, errors.As(err, &reserved))

	_, err = NewZoneService(nil, &netplan.Environment{ID: 41})
	require.True(t, errors.As(err, &verr), "got %v", err)
}

// TestNewZoneService_SeedWithResolvedSet accepts an already-resolved set
// (what sdn.Config.ResolvedZones returns) and keeps the owner zone.
func TestNewZoneService_SeedWithResolvedSet(t *testing.T) {
	resolved, err := zone.Resolve([]zone.ZoneConfig{labZone()})
	require.NoError(t, err)
	svc, _ := newEnvZoneService(t, resolved)
	recs, err := svc.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, recs, 10)
	assert.Equal(t, zone.Zone("lab"), recs[9].Config.Name)
	require.NotNil(t, recs[9].Numbering)
	assert.Equal(t, uint16(409), recs[9].Numbering.VLAN)
}

// TestZoneService_Create adds an owner zone with its numbering and reports
// a restart.
func TestZoneService_Create(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	rec, restart, err := svc.Create(context.Background(), labZone())
	require.NoError(t, err)
	assert.True(t, restart, "the plan is derived at startup")
	assert.Equal(t, zone.Zone("lab"), rec.Config.Name)
	require.NotNil(t, rec.Numbering)
	assert.Equal(t, "10.4.9.0/24", rec.Numbering.Subnet4.String())
	assert.Equal(t, rec.CreatedAt, rec.UpdatedAt)

	idx := svc.ZoneIndex()
	assert.Contains(t, idx, zone.Zone("lab"))
}

// TestZoneService_Create_Errors covers every refusal on create.
func TestZoneService_Create_Errors(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	ctx := context.Background()

	_, _, err := svc.Create(ctx, zone.ZoneConfig{Name: zone.ZoneStorage})
	var exists ErrZoneAlreadyExists
	require.True(t, errors.As(err, &exists), "built-ins always exist")

	omitted := labZone()
	omitted.Omit = true
	_, _, err = svc.Create(ctx, omitted)
	var verr ErrZoneValidation
	require.True(t, errors.As(err, &verr))

	tests := []struct {
		name string
		cfg  zone.ZoneConfig
		want any
	}{
		{"offset outside 9-99", zone.ZoneConfig{Name: "lab", Offset: 3, PortClasses: []zone.PortClass{zone.PortClassGateway}}, &zone.ErrOwnerZoneOffset{}},
		{"management-only class", zone.ZoneConfig{Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassBMC}}, &zone.ErrOwnerZonePortClass{}},
		{"overlay kind", zone.ZoneConfig{Name: "tenant", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassGateway}}, &zone.ErrReservedZoneName{}},
		{"unaudited path to control-plane", func() zone.ZoneConfig {
			c := labZone()
			c.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane}}
			return c
		}(), &zone.ErrPrivilegedAccessRequired{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Create(ctx, tc.cfg)
			require.True(t, errors.As(err, &verr), "got %v", err)
			assert.True(t, errors.As(err, tc.want), "got %v", err)
		})
	}

	block40, err := NewZoneService(nil, &netplan.Environment{ID: 40})
	require.NoError(t, err)
	high := labZone()
	high.Offset = 95
	_, _, err = block40.Create(ctx, high)
	var vlanErr netplan.ErrVLANOutOfRange
	require.True(t, errors.As(err, &vlanErr), "numbering collisions are refused: got %v", err)

	_, _, err = svc.Create(ctx, labZone())
	require.NoError(t, err)
	dup := labZone()
	dup.Name = "lab2"
	_, _, err = svc.Create(ctx, dup)
	var offErr zone.ErrDuplicateOffset
	require.True(t, errors.As(err, &offErr), "got %v", err)
	_, _, err = svc.Create(ctx, labZone())
	require.True(t, errors.As(err, &exists))
}

// TestZoneService_Create_AuditsPrivilegedPath writes an audit record for a
// path into control-plane opened by an override.
func TestZoneService_Create_AuditsPrivilegedPath(t *testing.T) {
	svc, buf := newEnvZoneService(t, nil)
	cfg := labZone()
	cfg.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"dns"}}}
	cfg.PrivilegedAccess = &zone.PrivilegedAccess{Reason: "lab resolver", ApprovedBy: "owner"}
	_, _, err := svc.Create(context.Background(), cfg)
	require.NoError(t, err)

	var found bool
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(line, &rec))
		if rec["to"] == "control-plane" {
			found = true
			assert.Equal(t, true, rec["audit"])
			assert.Equal(t, "lab resolver", rec["reason"])
			assert.Equal(t, "owner", rec["approved_by"])
			assert.Equal(t, "AU-2,AC-4", rec["compliance"])
		}
	}
	assert.True(t, found, "privileged path audit record: %s", buf.String())
}

// TestZoneService_Update tunes a built-in (identity kept) and replaces an
// owner zone.
func TestZoneService_Update(t *testing.T) {
	svc, _ := newEnvZoneService(t, []zone.ZoneConfig{labZone()})
	ctx := context.Background()

	rec, restart, err := svc.Update(ctx, zone.ZoneStorage, zone.ZoneConfig{Isolate: true, Services: []string{"nvme-tcp"}})
	require.NoError(t, err)
	assert.True(t, restart)
	assert.Equal(t, zone.OffsetStorage, rec.Config.Offset)
	assert.Equal(t, []string{"nvme-tcp"}, rec.Config.Services)
	assert.Equal(t, uint16(407), rec.Numbering.VLAN)

	moved := labZone()
	moved.Offset = 20
	rec, _, err = svc.Update(ctx, "lab", moved)
	require.NoError(t, err)
	assert.Equal(t, uint16(420), rec.Numbering.VLAN)
	assert.False(t, rec.UpdatedAt.Before(rec.CreatedAt))
}

// TestZoneService_Update_Errors covers every refusal on update.
func TestZoneService_Update_Errors(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	ctx := context.Background()

	_, _, err := svc.Update(ctx, "nowhere", zone.ZoneConfig{})
	var nf ErrZoneNotFound
	require.True(t, errors.As(err, &nf))

	var verr ErrZoneValidation
	_, _, err = svc.Update(ctx, zone.ZoneStorage, zone.ZoneConfig{Name: zone.ZoneBackup})
	require.True(t, errors.As(err, &verr), "renaming is refused")

	_, _, err = svc.Update(ctx, zone.ZoneStorage, zone.ZoneConfig{Offset: 30})
	var ident zone.ErrBuiltinIdentity
	require.True(t, errors.As(err, &ident), "a built-in cannot be renumbered: got %v", err)

	_, _, err = svc.Update(ctx, zone.ZoneBackup, zone.ZoneConfig{Omit: true})
	require.True(t, errors.As(err, &verr), "omission goes through Delete")

	before, err := svc.List(ctx, "")
	require.NoError(t, err)
	_, _, err = svc.Update(ctx, zone.ZoneStorage, zone.ZoneConfig{Offset: 30})
	require.Error(t, err)
	after, err := svc.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, zoneNames(before), zoneNames(after), "a refused mutation changes nothing")
}

// TestZoneService_Delete removes an owner zone and omits an optional
// built-in; required built-ins and unknown zones are refused.
func TestZoneService_Delete(t *testing.T) {
	tuned := zone.ZoneConfig{Name: zone.ZoneStorage, Isolate: true}
	svc, _ := newEnvZoneService(t, []zone.ZoneConfig{tuned, labZone()})
	ctx := context.Background()

	restart, err := svc.Delete(ctx, "lab")
	require.NoError(t, err)
	assert.True(t, restart)

	restart, err = svc.Delete(ctx, zone.ZoneBackup)
	require.NoError(t, err)
	assert.True(t, restart)
	recs, err := svc.List(ctx, "")
	require.NoError(t, err)
	assert.NotContains(t, zoneNames(recs), zone.ZoneBackup)
	assert.NotContains(t, zoneNames(recs), zone.Zone("lab"))
	assert.Contains(t, zoneNames(recs), zone.ZoneStorage, "other operator entries survive a delete")

	_, err = svc.Delete(ctx, zone.ZoneFabric)
	var verr ErrZoneValidation
	require.True(t, errors.As(err, &verr))
	var req zone.ErrOmitRequired
	assert.True(t, errors.As(err, &req))

	_, err = svc.Delete(ctx, "nowhere")
	var nf ErrZoneNotFound
	require.True(t, errors.As(err, &nf))
}

// TestZoneService_List_FilterByLifecycleRole returns only the holder of a
// lifecycle role.
func TestZoneService_List_FilterByLifecycleRole(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	recs, err := svc.List(context.Background(), zone.LifecycleRoleQuarantine)
	require.NoError(t, err)
	assert.Equal(t, []zone.Zone{zone.ZoneQuarantine}, zoneNames(recs))
}

// TestZoneService_SnapshotsAreDetached verifies callers cannot mutate the
// service through returned records or the index.
func TestZoneService_SnapshotsAreDetached(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	ctx := context.Background()
	recs, err := svc.List(ctx, "")
	require.NoError(t, err)
	recs[1].Config.AllowTo[0].Services[0] = "mutated"
	idx := svc.ZoneIndex()
	idx[zone.ZoneFabric].AllowTo[0].Services[0] = "mutated"

	again, err := svc.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, "vxlan", again[1].Config.AllowTo[0].Services[0])
}

// TestZoneView_RoundTrip converts a record to its JSON view and the spec
// back to a config.
func TestZoneView_RoundTrip(t *testing.T) {
	svc, _ := newEnvZoneService(t, nil)
	cfg := labZone()
	cfg.InternetIngress = false
	cfg.IsolateFrom = []zone.Zone{zone.ZoneStorage}
	cfg.Services = []string{"ssh"}
	cfg.AllowTo = []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"dns"}}}
	cfg.PrivilegedAccess = &zone.PrivilegedAccess{Reason: "r", ApprovedBy: "owner"}
	rec, restart, err := svc.Create(context.Background(), cfg)
	require.NoError(t, err)

	view := rec.View(restart)
	assert.True(t, view.RestartRequired)
	require.NotNil(t, view.Numbering)
	assert.Equal(t, ZoneNumberingView{VLAN: 409, Subnet4: "10.4.9.0/24", Gateway: "10.4.9.1"}, *view.Numbering)

	raw, err := json.Marshal(view)
	require.NoError(t, err)
	var back ZoneView
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, cfg, back.Config(""))
	assert.Equal(t, zone.Zone("other"), back.Config("other").Name, "the path name wins")

	var nilRec *ZoneRecord
	assert.Nil(t, nilRec.NumberingView())
	assert.Nil(t, (&ZoneRecord{}).NumberingView())
	assert.WithinDuration(t, time.Now(), view.CreatedAt, time.Minute)
}

// TestZoneNumberingView_IPv6 includes the IPv6 subnet when the environment
// has a ULA.
func TestZoneNumberingView_IPv6(t *testing.T) {
	ula, err := netip.ParsePrefix("fd12:3456:789a::/48")
	require.NoError(t, err)
	svc, err := NewZoneService(nil, &netplan.Environment{ID: 4, ULA: ula})
	require.NoError(t, err)
	recs, err := svc.List(context.Background(), zone.LifecycleRoleProvisioning)
	require.NoError(t, err)
	assert.Equal(t, "fd12:3456:789a:405::/64", recs[0].NumberingView().Subnet6)
}

// TestZoneService_ErrorStrings checks each error names the zone.
func TestZoneService_ErrorStrings(t *testing.T) {
	assert.Contains(t, ErrZoneNotFound{Name: "lab"}.Error(), `"lab"`)
	assert.Contains(t, ErrZoneAlreadyExists{Name: "lab"}.Error(), `"lab"`)
	cause := zone.ErrEmptyZoneName{}
	verr := ErrZoneValidation{Cause: cause}
	assert.Contains(t, verr.Error(), cause.Error())
	assert.Equal(t, cause, verr.Unwrap())
}

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

package compute

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// placementPlan is the environment-4 reference plan.
func placementPlan(t *testing.T) *netplan.Plan {
	t.Helper()
	p, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	if err != nil {
		t.Fatalf("netplan.New: %v", err)
	}
	return p
}

// fakeOVSPort is an OVSPortController that records what it is asked to do.
type fakeOVSPort struct {
	vlans []int64
	flows int
}

func (f *fakeOVSPort) InstallFlow(string, int, string, string) error { f.flows++; return nil }
func (f *fakeOVSPort) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	f.flows += len(rules)
	return nil
}
func (f *fakeOVSPort) DeleteFlow(string, string) error                  { return nil }
func (f *fakeOVSPort) DeleteFlowsByPort(string, string) error           { return nil }
func (f *fakeOVSPort) ListFlows(string) ([]string, error)               { return nil, nil }
func (f *fakeOVSPort) GetOFPort(context.Context, string) (int32, error) { return 1, nil }
func (f *fakeOVSPort) SetPortState(context.Context, string, ovs.PortState) error {
	return nil
}
func (f *fakeOVSPort) SetPortVLAN(_ context.Context, _ string, v int64) error {
	f.vlans = append(f.vlans, v)
	return nil
}
func (f *fakeOVSPort) SetPortTrunk(context.Context, string, []uint16, uint16) error { return nil }

// TestPlaceVNIC_ProfileZone places a vNIC on the profile's zone with the
// plan's VLAN.
func TestPlaceVNIC_ProfileZone(t *testing.T) {
	placement, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile: &entities.DeviceProfile{Zone: string(zone.ZoneStorage)},
		Plan:    placementPlan(t),
		PortID:  "tap0",
	})
	if err != nil {
		t.Fatalf("PlaceVNIC: %v", err)
	}
	if placement.NetworkName != "storage" || placement.Zone != zone.ZoneStorage || placement.VLAN != 407 {
		t.Errorf("placement = %+v, want storage/407", placement)
	}
}

// TestPlaceVNIC_NoDefaultZone refuses a profile without a zone: there is no
// fallback zone.
func TestPlaceVNIC_NoDefaultZone(t *testing.T) {
	_, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile: &entities.DeviceProfile{Name: "vm"},
		Plan:    placementPlan(t),
		PortID:  "tap1",
	})
	var target ErrProfileZoneRequired
	if !errors.As(err, &target) || target.Profile != "vm" {
		t.Fatalf("want ErrProfileZoneRequired, got %v", err)
	}
	if target.Error() == "" {
		t.Error("empty message")
	}
}

// TestPlaceVNIC_UnknownZone refuses a zone the plan does not hold.
func TestPlaceVNIC_UnknownZone(t *testing.T) {
	_, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile: &entities.DeviceProfile{Zone: "lab"},
		Plan:    placementPlan(t),
		PortID:  "tap2",
	})
	var noNet ErrNoNetworkInZone
	if !errors.As(err, &noNet) || noNet.Zone != "lab" {
		t.Fatalf("want ErrNoNetworkInZone{lab}, got %v", err)
	}
	if noNet.Error() == "" {
		t.Error("empty message")
	}
}

// TestPlaceVNIC_InvalidInput covers nil config, profile, plan and port.
func TestPlaceVNIC_InvalidInput(t *testing.T) {
	plan := placementPlan(t)
	profile := &entities.DeviceProfile{Zone: string(zone.ZoneStorage)}
	cases := map[string]*PlaceVNICConfig{
		"nil config": nil,
		"nil plan":   {Profile: profile, PortID: "tap"},
		"empty port": {Profile: profile, Plan: plan},
	}
	for name, cfg := range cases {
		if _, err := PlaceVNIC(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{Plan: plan, PortID: "tap"}); !errors.Is(err, ErrInvalidProfile) {
		t.Errorf("nil profile: want ErrInvalidProfile, got %v", err)
	}
}

// TestPlaceVNIC_ZoneFlowManager tags the port through the flow manager.
func TestPlaceVNIC_ZoneFlowManager(t *testing.T) {
	plan := placementPlan(t)
	ovsPort := &fakeOVSPort{}
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName: "br-int", FlowController: ovsPort, PortController: ovsPort, Plan: plan,
	})
	if err != nil {
		t.Fatalf("NewZoneFlowManager: %v", err)
	}
	placement, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile:         &entities.DeviceProfile{Zone: string(zone.ZoneBackup)},
		Plan:            plan,
		ZoneFlowManager: zfm,
		PortID:          "tap3",
	})
	if err != nil {
		t.Fatalf("PlaceVNIC: %v", err)
	}
	if placement.VLAN != 408 || len(ovsPort.vlans) != 1 || ovsPort.vlans[0] != 408 {
		t.Errorf("placement %+v, port VLANs %v; want 408", placement, ovsPort.vlans)
	}
	if ovsPort.flows == 0 {
		t.Error("no zone flows installed; the vNIC is tagged but not isolated")
	}
}

// TestPlaceVNIC_PolicyEngine applies a port policy carrying the zone VLAN
// when no flow manager is configured.
func TestPlaceVNIC_PolicyEngine(t *testing.T) {
	engine, err := policy.NewEngine(policy.Config{BridgeName: "br-int", FlowController: &fakeOVSPort{}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	_, err = PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile:      &entities.DeviceProfile{Zone: string(zone.ZoneStorage)},
		Plan:         placementPlan(t),
		PolicyEngine: engine,
		PortID:       "tap4",
		TenantID:     "tenant-a",
	})
	if err != nil {
		t.Fatalf("PlaceVNIC: %v", err)
	}
	got, err := engine.GetPolicy("tap4")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.VLAN != 407 || got.Zone != zone.ZoneStorage || got.TenantID != "tenant-a" {
		t.Errorf("policy = %+v", got)
	}
}

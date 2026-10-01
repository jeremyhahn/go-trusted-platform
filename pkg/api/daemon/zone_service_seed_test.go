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

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestZoneServiceSeed_ConfiguredZonesReachTheService seeds the zone service
// with the configured owner zone and environment.
func TestZoneServiceSeed_ConfiguredZonesReachTheService(t *testing.T) {
	a := &app.App{SDNConfig: &sdn.Config{
		Enabled:     true,
		Environment: &netplan.Environment{ID: 4},
		Zones: []zone.ZoneConfig{{
			Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true,
		}},
	}}
	seed, env := zoneServiceSeed(a)
	if env == nil || env.ID != 4 || len(seed) != 1 {
		t.Fatalf("seed %v env %v", seed, env)
	}
	svc, err := gateway.NewZoneService(seed, env)
	if err != nil {
		t.Fatalf("NewZoneService: %v", err)
	}
	recs, err := svc.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Config.Name == "lab" {
			found = true
		}
	}
	if !found {
		t.Fatal("the configured owner zone must reach the zone service")
	}
}

// TestZoneServiceSeed_DisabledOrAbsent yields no seed.
func TestZoneServiceSeed_DisabledOrAbsent(t *testing.T) {
	for _, a := range []*app.App{nil, {}, {SDNConfig: &sdn.Config{Enabled: false, Environment: &netplan.Environment{ID: 4}}}} {
		if seed, env := zoneServiceSeed(a); seed != nil || env != nil {
			t.Fatalf("want nil seed, got %v %v", seed, env)
		}
	}
}

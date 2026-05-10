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

package firewall

import "testing"

func testZones() []Zone {
	return []Zone{
		{
			Name:       "wan",
			Interfaces: []string{"eth0", "eth1"},
			Policy:     "deny",
		},
		{
			Name:       "lan",
			Interfaces: []string{"bond0.200"},
			Policy:     "allow",
		},
		{
			Name:       "dmz",
			Interfaces: []string{"bond0.201"},
			Policy:     "deny",
		},
	}
}

func TestZoneResolver_ZoneForInterface(t *testing.T) {
	zr := NewZoneResolver(testZones())

	tests := []struct {
		iface    string
		wantZone string
		wantOK   bool
	}{
		{"eth0", "wan", true},
		{"eth1", "wan", true},
		{"bond0.200", "lan", true},
		{"bond0.201", "dmz", true},
		{"unknown0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.iface, func(t *testing.T) {
			zone, ok := zr.ZoneForInterface(tt.iface)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if zone != tt.wantZone {
				t.Errorf("zone: got %q, want %q", zone, tt.wantZone)
			}
		})
	}
}

func TestZoneResolver_Zone(t *testing.T) {
	zr := NewZoneResolver(testZones())

	t.Run("existing zone", func(t *testing.T) {
		z, ok := zr.Zone("lan")
		if !ok {
			t.Fatal("expected to find lan zone")
		}
		if z.Name != "lan" {
			t.Errorf("name: got %q, want %q", z.Name, "lan")
		}
	})

	t.Run("missing zone", func(t *testing.T) {
		_, ok := zr.Zone("nonexistent")
		if ok {
			t.Error("expected zone lookup to fail")
		}
	})
}

func TestZoneResolver_PolicyForZone(t *testing.T) {
	zr := NewZoneResolver(testZones())

	tests := []struct {
		zone string
		want Action
	}{
		{"wan", ActionDeny},
		{"lan", ActionAllow},
		{"dmz", ActionDeny},
		{"nonexistent", ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := zr.PolicyForZone(tt.zone)
			if got != tt.want {
				t.Errorf("policy: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewZoneResolver_Empty(t *testing.T) {
	zr := NewZoneResolver(nil)
	_, ok := zr.ZoneForInterface("eth0")
	if ok {
		t.Error("expected no zones for nil input")
	}
}

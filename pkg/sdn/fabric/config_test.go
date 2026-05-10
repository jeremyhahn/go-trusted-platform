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

package fabric

import (
	"errors"
	"testing"
)

func TestFabricConfig_Validate_Valid(t *testing.T) {
	cfg := validFabricConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %s", err)
	}
}

func TestFabricConfig_Validate_DefaultsToVLANMode(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Mode = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %s", err)
	}
	if cfg.Mode != ModeVLAN {
		t.Fatalf("expected mode %q, got %q", ModeVLAN, cfg.Mode)
	}
}

func TestFabricConfig_Validate_NilConfig(t *testing.T) {
	var cfg *FabricConfig
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	var nilErr ErrNilConfig
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected ErrNilConfig, got %T: %s", err, err)
	}
}

func TestFabricConfig_Validate_InvalidMode(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Mode = "invalid"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	var invErr ErrInvalidFabricConfig
	if !errors.As(err, &invErr) {
		t.Fatalf("expected ErrInvalidFabricConfig, got %T: %s", err, err)
	}
}

func TestFabricConfig_Validate_EVPNModeWithoutConfig(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Mode = ModeEVPN
	cfg.EVPN = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for EVPN mode without config")
	}
}

func TestFabricConfig_Validate_EVPNModeWithConfig(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Mode = ModeEVPN
	cfg.EVPN = &EVPNConfig{
		VNIBase:           100000,
		AnycastGatewayMAC: "00:00:5e:00:01:01",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid EVPN config, got error: %s", err)
	}
}

func TestFabricConfig_Validate_NoSwitches(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Switches = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty switches")
	}
}

func TestFabricConfig_Validate_DuplicateSwitchID(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Switches = append(cfg.Switches, SwitchConfig{
		ID: "nexus-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.2",
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate switch ID")
	}
}

func TestFabricConfig_Validate_NoSegments(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Segments = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty segments")
	}
}

func TestFabricConfig_Validate_DuplicateSegmentName(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Segments = append(cfg.Segments, SegmentConfig{
		Name: "production", VLAN: 201,
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate segment name")
	}
}

func TestFabricConfig_Validate_DuplicateVLAN(t *testing.T) {
	cfg := validFabricConfig()
	cfg.Segments = append(cfg.Segments, SegmentConfig{
		Name: "duplicate-vlan", VLAN: 200,
	})
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate VLAN")
	}
	var dupErr ErrDuplicateVLAN
	if !errors.As(err, &dupErr) {
		t.Fatalf("expected ErrDuplicateVLAN, got %T: %s", err, err)
	}
}

func TestSwitchConfig_Validate_MissingID(t *testing.T) {
	sc := SwitchConfig{Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"}
	err := sc.Validate()
	if err == nil {
		t.Fatal("expected error for missing switch ID")
	}
}

func TestSwitchConfig_Validate_MissingVendor(t *testing.T) {
	sc := SwitchConfig{ID: "sw-01", MgmtIP: "10.0.0.1"}
	err := sc.Validate()
	if err == nil {
		t.Fatal("expected error for missing vendor")
	}
}

func TestSwitchConfig_Validate_MissingMgmtIP(t *testing.T) {
	sc := SwitchConfig{ID: "sw-01", Vendor: "cisco-nexus"}
	err := sc.Validate()
	if err == nil {
		t.Fatal("expected error for missing mgmt-ip")
	}
}

func TestSwitchConfig_Validate_Valid(t *testing.T) {
	sc := SwitchConfig{ID: "sw-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"}
	if err := sc.Validate(); err != nil {
		t.Fatalf("expected valid, got: %s", err)
	}
}

func TestSegmentConfig_Validate_MissingName(t *testing.T) {
	sc := SegmentConfig{VLAN: 200}
	err := sc.Validate()
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestSegmentConfig_Validate_InvalidVLAN(t *testing.T) {
	tests := []struct {
		name string
		vlan uint16
	}{
		{"zero vlan", 0},
		{"vlan too high", 4095},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := SegmentConfig{Name: "test", VLAN: tt.vlan}
			err := sc.Validate()
			if err == nil {
				t.Fatal("expected error for invalid VLAN")
			}
		})
	}
}

func TestSegmentConfig_Validate_InvalidRole(t *testing.T) {
	sc := SegmentConfig{Name: "test", VLAN: 200, Role: "bogus"}
	err := sc.Validate()
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestSegmentConfig_Validate_Valid(t *testing.T) {
	sc := SegmentConfig{Name: "test", VLAN: 200, Role: RoleProvisioning}
	if err := sc.Validate(); err != nil {
		t.Fatalf("expected valid, got: %s", err)
	}
}

func TestLAGConfig_Validate_MissingID(t *testing.T) {
	lc := LAGConfig{
		Members:       []PortRef{{SwitchID: "sw-01", Port: "Eth1/1"}},
		PortChannelID: 10,
	}
	err := lc.Validate()
	if err == nil {
		t.Fatal("expected error for missing LAG ID")
	}
}

func TestLAGConfig_Validate_NoMembers(t *testing.T) {
	lc := LAGConfig{ID: "lag-01", PortChannelID: 10}
	err := lc.Validate()
	if err == nil {
		t.Fatal("expected error for empty members")
	}
}

func TestLAGConfig_Validate_NoPortChannelID(t *testing.T) {
	lc := LAGConfig{
		ID:      "lag-01",
		Members: []PortRef{{SwitchID: "sw-01", Port: "Eth1/1"}},
	}
	err := lc.Validate()
	if err == nil {
		t.Fatal("expected error for missing port-channel-id")
	}
}

func TestLAGConfig_Validate_Valid(t *testing.T) {
	lc := LAGConfig{
		ID:            "lag-01",
		Members:       []PortRef{{SwitchID: "sw-01", Port: "Eth1/1"}},
		PortChannelID: 10,
	}
	if err := lc.Validate(); err != nil {
		t.Fatalf("expected valid, got: %s", err)
	}
}

func TestPeerConfig_Validate_MissingSwitchA(t *testing.T) {
	ids := map[string]struct{}{"sw-01": {}, "sw-02": {}}
	pc := PeerConfig{SwitchB: "sw-02", PeerLinkPorts: []string{"Eth1/47"}}
	err := pc.Validate(ids)
	if err == nil {
		t.Fatal("expected error for missing switch-a")
	}
}

func TestPeerConfig_Validate_UnknownSwitch(t *testing.T) {
	ids := map[string]struct{}{"sw-01": {}}
	pc := PeerConfig{SwitchA: "sw-01", SwitchB: "sw-99", PeerLinkPorts: []string{"Eth1/47"}}
	err := pc.Validate(ids)
	if err == nil {
		t.Fatal("expected error for unknown switch")
	}
	var unknownErr ErrUnknownSwitch
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected ErrUnknownSwitch, got %T: %s", err, err)
	}
}

func TestPeerConfig_Validate_NoPeerLinkPorts(t *testing.T) {
	ids := map[string]struct{}{"sw-01": {}, "sw-02": {}}
	pc := PeerConfig{SwitchA: "sw-01", SwitchB: "sw-02"}
	err := pc.Validate(ids)
	if err == nil {
		t.Fatal("expected error for missing peer-link ports")
	}
}

func TestPeerConfig_Validate_Valid(t *testing.T) {
	ids := map[string]struct{}{"sw-01": {}, "sw-02": {}}
	pc := PeerConfig{SwitchA: "sw-01", SwitchB: "sw-02", PeerLinkPorts: []string{"Eth1/47"}}
	if err := pc.Validate(ids); err != nil {
		t.Fatalf("expected valid, got: %s", err)
	}
}

func TestPortRef_Validate_MissingSwitchID(t *testing.T) {
	pr := PortRef{Port: "Eth1/1"}
	err := pr.Validate()
	if err == nil {
		t.Fatal("expected error for missing switch-id")
	}
	var invErr ErrInvalidPortRef
	if !errors.As(err, &invErr) {
		t.Fatalf("expected ErrInvalidPortRef, got %T: %s", err, err)
	}
}

func TestPortRef_Validate_MissingPort(t *testing.T) {
	pr := PortRef{SwitchID: "sw-01"}
	err := pr.Validate()
	if err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestPortRef_Validate_Valid(t *testing.T) {
	pr := PortRef{SwitchID: "sw-01", Port: "Eth1/1"}
	if err := pr.Validate(); err != nil {
		t.Fatalf("expected valid, got: %s", err)
	}
}

// validFabricConfig returns a minimal valid FabricConfig for testing.
func validFabricConfig() *FabricConfig {
	return &FabricConfig{
		Mode: ModeVLAN,
		Switches: []SwitchConfig{
			{ID: "nexus-01", Vendor: "cisco-nexus", MgmtIP: "10.0.0.1"},
		},
		Segments: []SegmentConfig{
			{Name: "production", VLAN: 200, CIDR: "10.200.0.0/24"},
		},
	}
}

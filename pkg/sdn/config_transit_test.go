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

package sdn_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vlan"
)

// ─────────────────────────────────────────────────────────────────────────────
// TransitConfig.Validate
// ─────────────────────────────────────────────────────────────────────────────

func TestTransitConfig_NilConfig_NoError(t *testing.T) {
	t.Parallel()

	var tc *sdn.TransitConfig
	if err := tc.Validate(); err != nil {
		t.Errorf("nil TransitConfig must pass, got: %v", err)
	}
}

func TestTransitConfig_ZeroVLAN_NoError(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{} // VLAN 0 = use default
	if err := tc.Validate(); err != nil {
		t.Errorf("zero VLAN must pass (defaults to %d), got: %v", vlan.DefaultTransit, err)
	}
}

func TestTransitConfig_ValidVLAN_NoError(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{VLAN: vlan.DefaultTransit, P2P: "172.16.0.0/24"}
	if err := tc.Validate(); err != nil {
		t.Errorf("valid transit config must pass, got: %v", err)
	}
}

func TestTransitConfig_InvalidVLAN_ReturnsErrInvalidTransitVLAN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vlan uint16
	}{
		{"VLAN 0 is zero (valid, means default)", 0}, // 0 is valid (skips validate)
		{"VLAN 4095 out of range", 4095},
		{"VLAN 4096 out of range", 4096},
		{"VLAN 65535 max uint16", 65535},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := &sdn.TransitConfig{VLAN: tt.vlan}
			err := tc.Validate()
			if tt.vlan == 0 {
				// Zero means "use default" — no error.
				if err != nil {
					t.Errorf("VLAN 0 must pass, got: %v", err)
				}
				return
			}
			var target sdn.ErrInvalidTransitVLAN
			if !errors.As(err, &target) {
				t.Errorf("want ErrInvalidTransitVLAN, got %T: %v", err, err)
			}
			if target.VLAN != tt.vlan {
				t.Errorf("want VLAN %d in error, got %d", tt.vlan, target.VLAN)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TransitConfig.EffectiveVLAN / EffectiveP2P
// ─────────────────────────────────────────────────────────────────────────────

func TestTransitConfig_EffectiveVLAN_DefaultWhenZero(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{VLAN: 0}
	if got := tc.EffectiveVLAN(); got != vlan.DefaultTransit {
		t.Errorf("want DefaultTransit %d, got %d", vlan.DefaultTransit, got)
	}
}

func TestTransitConfig_EffectiveVLAN_NilConfig(t *testing.T) {
	t.Parallel()

	var tc *sdn.TransitConfig
	if got := tc.EffectiveVLAN(); got != vlan.DefaultTransit {
		t.Errorf("nil config: want DefaultTransit %d, got %d", vlan.DefaultTransit, got)
	}
}

func TestTransitConfig_EffectiveVLAN_ExplicitValue(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{VLAN: 20}
	if got := tc.EffectiveVLAN(); got != 20 {
		t.Errorf("want 20, got %d", got)
	}
}

func TestTransitConfig_EffectiveP2P_DefaultWhenEmpty(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{}
	const wantDefault = "172.16.0.0/24"
	if got := tc.EffectiveP2P(); got != wantDefault {
		t.Errorf("want %q, got %q", wantDefault, got)
	}
}

func TestTransitConfig_EffectiveP2P_ExplicitValue(t *testing.T) {
	t.Parallel()

	tc := &sdn.TransitConfig{P2P: "10.0.0.0/30"}
	if got := tc.EffectiveP2P(); got != "10.0.0.0/30" {
		t.Errorf("want %q, got %q", "10.0.0.0/30", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sdn.Config.Validate with Transit block
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_TransitBlock_Valid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Transit = &sdn.TransitConfig{VLAN: vlan.DefaultTransit, P2P: "172.16.0.0/24"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid transit block must pass, got: %v", err)
	}
}

func TestValidate_TransitBlock_InvalidVLAN_ReturnsError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Transit = &sdn.TransitConfig{VLAN: 4095} // out of range
	err := c.Validate()
	var target sdn.ErrInvalidTransitVLAN
	if !errors.As(err, &target) {
		t.Errorf("want ErrInvalidTransitVLAN, got %T: %v", err, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ManagementVPNConfig validation
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_ManagementVPN_ValidAllowTo(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: true,
		Type:    "wireguard",
		AllowTo: []string{"management"},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid management_vpn must pass, got: %v", err)
	}
}

func TestValidate_ManagementVPN_Disabled_SkipsZoneCheck(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: false,
		AllowTo: []string{"nonexistent-zone"}, // would fail if validated
	}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled management_vpn must skip zone check, got: %v", err)
	}
}

func TestValidate_ManagementVPN_UnknownZone_ReturnsError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: true,
		Type:    "wireguard",
		AllowTo: []string{"nonexistent-zone"},
	}
	err := c.Validate()
	var target sdn.ErrManagementVPNUnknownZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrManagementVPNUnknownZone, got %T: %v", err, err)
	}
	if target.Zone != "nonexistent-zone" {
		t.Errorf("want Zone %q in error, got %q", "nonexistent-zone", target.Zone)
	}
}

func TestValidate_ManagementVPN_MultipleZones_AllValid(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: true,
		AllowTo: []string{"management", "trusted"},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("management_vpn with valid multi-zone allow_to must pass, got: %v", err)
	}
}

func TestValidate_ManagementVPN_MultipleZones_OneInvalid_ReturnsError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: true,
		AllowTo: []string{"management", "bogus-zone"},
	}
	err := c.Validate()
	var target sdn.ErrManagementVPNUnknownZone
	if !errors.As(err, &target) {
		t.Errorf("want ErrManagementVPNUnknownZone, got %T: %v", err, err)
	}
}

func TestValidate_ManagementVPN_EmptyAllowTo_NoError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{
		Enabled: true,
		AllowTo: nil, // no restrictions specified — valid
	}
	if err := c.Validate(); err != nil {
		t.Errorf("empty allow_to must pass, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Services block (ZoneServiceConfig) — schema round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestValidate_ServicesBlock_NoError(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Services = map[string]sdn.ZoneServiceConfig{
		"provisioning": {
			ACMEServer: "172.16.201.10",
			DNSServer:  "172.16.201.1",
			DHCPRange:  "172.16.201.100-172.16.201.200",
		},
		"quarantine": {
			RemediationServer: "172.16.202.10",
			DNSServer:         "172.16.202.1",
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("services block must pass validation, got: %v", err)
	}
}

func TestValidate_ServicesBlock_LookupByZone(t *testing.T) {
	t.Parallel()

	c := minValidConfig()
	c.Services = map[string]sdn.ZoneServiceConfig{
		"provisioning": {
			ACMEServer: "172.16.201.10",
			DNSServer:  "172.16.201.1",
			DHCPRange:  "172.16.201.100-172.16.201.200",
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	svc, ok := c.Services["provisioning"]
	if !ok {
		t.Fatal("provisioning service config not found")
	}
	if svc.ACMEServer != "172.16.201.10" {
		t.Errorf("want ACMEServer %q, got %q", "172.16.201.10", svc.ACMEServer)
	}
	if svc.DHCPRange != "172.16.201.100-172.16.201.200" {
		t.Errorf("want DHCPRange %q, got %q", "172.16.201.100-172.16.201.200", svc.DHCPRange)
	}
}

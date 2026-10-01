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

package nexus

import "testing"

func TestParseShowVLAN_Found(t *testing.T) {
	output := `VLAN Name                             Status    Ports
---- -------------------------------- --------- -------
200  production                       active    Eth1/1, Eth1/2
201  provisioning                     active    Eth1/3
`
	info, found := parseShowVLAN(output, 200)
	if !found {
		t.Fatal("expected VLAN 200 to be found")
	}
	if info.ID != 200 {
		t.Fatalf("expected ID 200, got %d", info.ID)
	}
	if info.Name != "production" {
		t.Fatalf("expected name %q, got %q", "production", info.Name)
	}
	if info.Status != "active" {
		t.Fatalf("expected status %q, got %q", "active", info.Status)
	}
}

func TestParseShowVLAN_NotFound(t *testing.T) {
	output := `VLAN Name                             Status    Ports
---- -------------------------------- --------- -------
100  default                          active    Eth1/1
`
	_, found := parseShowVLAN(output, 200)
	if found {
		t.Fatal("expected VLAN 200 to not be found")
	}
}

func TestParseShowVLAN_EmptyOutput(t *testing.T) {
	_, found := parseShowVLAN("", 200)
	if found {
		t.Fatal("expected not found for empty output")
	}
}

func TestParseShowVLAN_ErrorMessage(t *testing.T) {
	output := "VLAN 200 not found in current VLAN database"
	_, found := parseShowVLAN(output, 200)
	if found {
		t.Fatal("expected not found for error message output")
	}
}

func TestParseShowPortChannelSummary_Found(t *testing.T) {
	output := `Group Port-channel Protocol    Member Ports
10    Po10(SU)     LACP        Eth1/1(P)    Eth1/2(P)
20    Po20(SD)     LACP        Eth1/3(D)
`
	if !parseShowPortChannelSummary(output, 10) {
		t.Fatal("expected port-channel 10 to be found")
	}
}

func TestParseShowPortChannelSummary_NotFound(t *testing.T) {
	output := `Group Port-channel Protocol    Member Ports
20    Po20(SD)     LACP        Eth1/3(D)
`
	if parseShowPortChannelSummary(output, 10) {
		t.Fatal("expected port-channel 10 to not be found")
	}
}

func TestParseShowPortChannelSummary_EmptyOutput(t *testing.T) {
	if parseShowPortChannelSummary("", 10) {
		t.Fatal("expected not found for empty output")
	}
}

func TestContainsError_True(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"error keyword", "Error: invalid command"},
		{"invalid keyword", "Invalid interface"},
		{"percent prefix", "% Unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !containsError(tt.output) {
				t.Fatalf("expected containsError=true for %q", tt.output)
			}
		})
	}
}

func TestContainsError_False(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"normal output", "VLAN 200 production active"},
		{"empty output", ""},
		{"version output", "Cisco NX-OS Software"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if containsError(tt.output) {
				t.Fatalf("expected containsError=false for %q", tt.output)
			}
		})
	}
}

// TestParseInterfaceConfig reads a trunk with a range, an "add" line, the
// native VLAN, MTU and shutdown.
func TestParseInterfaceConfig(t *testing.T) {
	out := `interface Ethernet1/25
  switchport mode trunk
  switchport trunk native vlan 405
  switchport trunk allowed vlan 403-405
  switchport trunk allowed vlan add 401
  mtu 9216
  shutdown
`
	cfg := parseInterfaceConfig(out)
	if cfg.mode != "trunk" || cfg.native != 405 || cfg.mtu != 9216 || !cfg.shutdown {
		t.Fatalf("unexpected %+v", cfg)
	}
	want := []uint16{401, 403, 404, 405}
	if len(cfg.allowed) != len(want) {
		t.Fatalf("allowed %v, want %v", cfg.allowed, want)
	}
	for i := range want {
		if cfg.allowed[i] != want[i] {
			t.Fatalf("allowed %v, want %v", cfg.allowed, want)
		}
	}

	access := parseInterfaceConfig("  switchport mode access\n  switchport access vlan 402\n  no shutdown\n")
	if access.mode != "access" || access.accessVLAN != 402 || access.shutdown {
		t.Fatalf("unexpected %+v", access)
	}
}

// TestParseInterfaceConfig_Garbage ignores values it cannot parse.
func TestParseInterfaceConfig_Garbage(t *testing.T) {
	cfg := parseInterfaceConfig("  switchport access vlan x\n  mtu big\n  switchport trunk allowed vlan 9-3,abc\n")
	if cfg.accessVLAN != 0 || cfg.mtu != 0 || len(cfg.allowed) != 0 {
		t.Fatalf("unexpected %+v", cfg)
	}
	if empty := parseInterfaceConfig(""); empty.mode != "" {
		t.Fatalf("unexpected %+v", empty)
	}
}

// TestParseInterfaceConfig_DefaultModeAndRouted reads a port with no mode
// line (NX-OS omits the default) as access, and "no switchport" as routed.
func TestParseInterfaceConfig_DefaultModeAndRouted(t *testing.T) {
	cfg := parseInterfaceConfig("interface Ethernet1/41\n  switchport access vlan 402\n  mtu 9216\n")
	if cfg.mode != "access" || cfg.accessVLAN != 402 {
		t.Fatalf("default mode: got mode %q vlan %d, want access 402", cfg.mode, cfg.accessVLAN)
	}
	routed := parseInterfaceConfig("interface Ethernet1/1\n  no switchport\n")
	if routed.mode != modeRouted {
		t.Fatalf("routed port: got mode %q, want %q", routed.mode, modeRouted)
	}
}

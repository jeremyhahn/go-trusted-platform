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

func TestParseShowNVEVNI_Found(t *testing.T) {
	output := `Interface VNI      Multicast-group   State
nve1      100200   225.1.1.1         Up
nve1      100201   225.1.1.2         Up
`
	if !parseShowNVEVNI(output, 100200) {
		t.Fatal("expected VNI 100200 to be found")
	}
}

func TestParseShowNVEVNI_NotFound(t *testing.T) {
	output := `Interface VNI      Multicast-group   State
nve1      100100   225.1.1.1         Up
`
	if parseShowNVEVNI(output, 100200) {
		t.Fatal("expected VNI 100200 to not be found")
	}
}

func TestParseShowNVEVNI_EmptyOutput(t *testing.T) {
	if parseShowNVEVNI("", 100200) {
		t.Fatal("expected not found for empty output")
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

func TestParseShowRunningInterface_Found(t *testing.T) {
	output := `interface Ethernet1/5
  switchport
  switchport mode access
  switchport access vlan 200
  no shutdown
`
	vlan := parseShowRunningInterface(output)
	if vlan != 200 {
		t.Fatalf("expected VLAN 200, got %d", vlan)
	}
}

func TestParseShowRunningInterface_NotFound(t *testing.T) {
	output := `interface Ethernet1/5
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 200,201
`
	vlan := parseShowRunningInterface(output)
	if vlan != 0 {
		t.Fatalf("expected VLAN 0, got %d", vlan)
	}
}

func TestParseShowRunningInterface_EmptyOutput(t *testing.T) {
	vlan := parseShowRunningInterface("")
	if vlan != 0 {
		t.Fatalf("expected VLAN 0, got %d", vlan)
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

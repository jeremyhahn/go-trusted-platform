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

import (
	"strings"
	"testing"
)

func TestShowVLANCommand(t *testing.T) {
	cmd := showVLANCommand(200)
	if cmd != "show vlan id 200" {
		t.Fatalf("expected %q, got %q", "show vlan id 200", cmd)
	}
}

func TestCreateVLANCommands(t *testing.T) {
	cmds := createVLANCommands(200, "production")
	if len(cmds) < 3 {
		t.Fatalf("expected at least 3 commands, got %d", len(cmds))
	}
	if cmds[0] != "configure terminal" {
		t.Fatalf("expected first command %q, got %q", "configure terminal", cmds[0])
	}
	if cmds[1] != "vlan 200" {
		t.Fatalf("expected %q, got %q", "vlan 200", cmds[1])
	}
	foundName := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "name production") {
			foundName = true
			break
		}
	}
	if !foundName {
		t.Fatal("expected name command in VLAN creation")
	}
	if cmds[len(cmds)-1] != "end" {
		t.Fatalf("expected last command %q, got %q", "end", cmds[len(cmds)-1])
	}
}

func TestCreateVLANCommands_NoName(t *testing.T) {
	cmds := createVLANCommands(200, "")
	for _, cmd := range cmds {
		if strings.Contains(cmd, "name") {
			t.Fatal("should not include name command when name is empty")
		}
	}
}

func TestCreateVNICommands(t *testing.T) {
	cmds := createVNICommands(100200, 200)
	foundNVE := false
	foundMember := false
	for _, cmd := range cmds {
		if cmd == "interface nve1" {
			foundNVE = true
		}
		if strings.Contains(cmd, "member vni 100200 associate-vlan 200") {
			foundMember = true
		}
	}
	if !foundNVE {
		t.Fatal("expected interface nve1 command")
	}
	if !foundMember {
		t.Fatal("expected member vni command")
	}
}

func TestCreateLAGCommands_WithVPC(t *testing.T) {
	cmds := createLAGCommands(10, []string{"Eth1/1", "Eth1/2"}, "active", true)

	foundPC := false
	foundVPC := false
	foundMember := 0
	for _, cmd := range cmds {
		if strings.Contains(cmd, "interface port-channel10") {
			foundPC = true
		}
		if strings.Contains(cmd, "vpc 10") {
			foundVPC = true
		}
		if strings.Contains(cmd, "channel-group 10 mode active") {
			foundMember++
		}
	}
	if !foundPC {
		t.Fatal("expected port-channel interface command")
	}
	if !foundVPC {
		t.Fatal("expected vpc command for MC-LAG")
	}
	if foundMember != 2 {
		t.Fatalf("expected 2 channel-group commands, got %d", foundMember)
	}
}

func TestCreateLAGCommands_WithoutVPC(t *testing.T) {
	cmds := createLAGCommands(10, []string{"Eth1/1"}, "", false)

	for _, cmd := range cmds {
		if strings.Contains(cmd, "vpc") {
			t.Fatal("should not include vpc command when not MC-LAG")
		}
	}
}

func TestSetPortAccessCommands(t *testing.T) {
	cmds := setPortAccessCommands("Eth1/5", 200)

	foundInterface := false
	foundAccess := false
	foundVLAN := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "interface Eth1/5") {
			foundInterface = true
		}
		if strings.Contains(cmd, "switchport mode access") {
			foundAccess = true
		}
		if strings.Contains(cmd, "switchport access vlan 200") {
			foundVLAN = true
		}
	}
	if !foundInterface {
		t.Fatal("expected interface command")
	}
	if !foundAccess {
		t.Fatal("expected switchport mode access command")
	}
	if !foundVLAN {
		t.Fatal("expected switchport access vlan command")
	}
}

func TestSetPortTrunkCommands(t *testing.T) {
	cmds := setPortTrunkCommands("Eth1/5", []uint16{200, 201}, 200)

	foundTrunk := false
	foundAllowed := false
	foundNative := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "switchport mode trunk") {
			foundTrunk = true
		}
		if strings.Contains(cmd, "switchport trunk allowed vlan 200,201") {
			foundAllowed = true
		}
		if strings.Contains(cmd, "switchport trunk native vlan 200") {
			foundNative = true
		}
	}
	if !foundTrunk {
		t.Fatal("expected switchport mode trunk command")
	}
	if !foundAllowed {
		t.Fatal("expected switchport trunk allowed vlan command")
	}
	if !foundNative {
		t.Fatal("expected switchport trunk native vlan command")
	}
}

func TestSetPortTrunkCommands_NoNative(t *testing.T) {
	cmds := setPortTrunkCommands("Eth1/5", []uint16{200}, 0)

	for _, cmd := range cmds {
		if strings.Contains(cmd, "native") {
			t.Fatal("should not include native vlan when zero")
		}
	}
}

func TestJoinUint16s(t *testing.T) {
	result := joinUint16s([]uint16{200, 201, 203}, ",")
	if result != "200,201,203" {
		t.Fatalf("expected %q, got %q", "200,201,203", result)
	}
}

func TestJoinUint16s_Empty(t *testing.T) {
	result := joinUint16s(nil, ",")
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestShowRunningInterfaceCommand(t *testing.T) {
	cmd := showRunningInterfaceCommand("Eth1/5")
	if cmd != "show running-config interface Eth1/5" {
		t.Fatalf("expected %q, got %q", "show running-config interface Eth1/5", cmd)
	}
}

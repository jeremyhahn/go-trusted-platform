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

// TestSetPortCommands checks the access, trunk and shutdown command sets,
// including the MTU and the native-VLAN reset.
func TestSetPortCommands(t *testing.T) {
	access := strings.Join(setPortAccessCommands("Eth1/41", 402, 9216), "\n")
	for _, want := range []string{"interface Eth1/41", "switchport mode access", "switchport access vlan 402", "mtu 9216", "no shutdown"} {
		if !strings.Contains(access, want) {
			t.Fatalf("access: missing %q in %s", want, access)
		}
	}
	if strings.Contains(strings.Join(setPortAccessCommands("Eth1/41", 402, 0), "\n"), "mtu") {
		t.Fatal("mtu 0 must leave the MTU alone")
	}

	trunk := strings.Join(setPortTrunkCommands("Eth1/25", []uint16{401, 405}, 405, 9216), "\n")
	for _, want := range []string{"switchport mode trunk", "switchport trunk allowed vlan 401,405", "switchport trunk native vlan 405", "mtu 9216"} {
		if !strings.Contains(trunk, want) {
			t.Fatalf("trunk: missing %q in %s", want, trunk)
		}
	}
	bare := strings.Join(setPortTrunkCommands("Eth1/25", nil, 0, 0), "\n")
	for _, want := range []string{"switchport trunk allowed vlan none", "no switchport trunk native vlan"} {
		if !strings.Contains(bare, want) {
			t.Fatalf("trunk: missing %q in %s", want, bare)
		}
	}

	if !strings.Contains(strings.Join(disablePortCommands("Eth1/25"), "\n"), "  shutdown") {
		t.Fatal("expected shutdown")
	}
}

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

package mcp

import (
	"testing"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
)

// TestFormatPortStatus_NativeVLAN carries a trunk's native VLAN to MCP
// clients, leaves it out when there is none, and maps nil to nil.
func TestFormatPortStatus_NativeVLAN(t *testing.T) {
	trunk := formatPortStatus(&switchmgmt.PortStatus{
		Port: "Eth1/25", Mode: switchmgmt.PortModeTrunk, TrunkVLANs: []uint16{401, 405}, NativeVLAN: 405,
	})
	if trunk["native_vlan"] != uint16(405) {
		t.Fatalf("native_vlan = %v, want 405", trunk["native_vlan"])
	}
	access := formatPortStatus(&switchmgmt.PortStatus{Port: "Eth1/41", Mode: switchmgmt.PortModeAccess, AccessVLAN: 402})
	if _, ok := access["native_vlan"]; ok {
		t.Fatal("an access port must not report a native VLAN")
	}
	if formatPortStatus(nil) != nil {
		t.Fatal("formatPortStatus(nil) must be nil")
	}
}

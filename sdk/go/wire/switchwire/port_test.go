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

package switchwire

import (
	"encoding/json"
	"testing"
)

// TestPortStatus_JSONFieldNames pins the port status wire names and the
// omitempty fields; the switch REST handlers and the SDK client share them.
func TestPortStatus_JSONFieldNames(t *testing.T) {
	data, err := json.Marshal(PortStatus{Port: "Eth1/1", Mode: PortModeAccess, AccessVLAN: 100, Enabled: true})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"port":"Eth1/1","mode":"access","access_vlan":100,"enabled":true,"link_up":false}`
	if string(data) != want {
		t.Errorf("port status = %s, want %s", data, want)
	}
}

func TestPortStatus_DecodesTrunkPort(t *testing.T) {
	var ps PortStatus
	err := json.Unmarshal([]byte(`{"port":"Eth1/2","mode":"trunk","trunk_vlans":[100,200],"native_vlan":1,"link_up":true}`), &ps)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ps.Mode != PortModeTrunk || len(ps.TrunkVLANs) != 2 || ps.NativeVLAN != 1 || !ps.LinkUp {
		t.Errorf("decoded = %+v, want the trunk port", ps)
	}
}

func TestPortStatus_RejectsOutOfRangeVLAN(t *testing.T) {
	var ps PortStatus
	if err := json.Unmarshal([]byte(`{"access_vlan":70000}`), &ps); err == nil {
		t.Error("Unmarshal accepted VLAN 70000, want a uint16 range error")
	}
}

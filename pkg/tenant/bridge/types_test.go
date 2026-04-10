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

package bridge

import (
	"testing"
	"time"
)

func TestBridgeStatus_Constants(t *testing.T) {
	tests := []struct {
		status   BridgeStatus
		expected string
	}{
		{StatusPending, "pending"},
		{StatusActive, "active"},
		{StatusError, "error"},
		{StatusDeleting, "deleting"},
		{StatusSuspended, "suspended"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("BridgeStatus = %q, want %q", string(tt.status), tt.expected)
			}
		})
	}
}

func TestVLANRange_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		vr       VLANRange
		expected bool
	}{
		{
			name:     "valid range 1-100",
			vr:       VLANRange{Start: 1, End: 100},
			expected: true,
		},
		{
			name:     "valid single VLAN",
			vr:       VLANRange{Start: 100, End: 100},
			expected: true,
		},
		{
			name:     "valid max range",
			vr:       VLANRange{Start: 1, End: 4094},
			expected: true,
		},
		{
			name:     "valid max single VLAN",
			vr:       VLANRange{Start: 4094, End: 4094},
			expected: true,
		},
		{
			name:     "invalid zero start",
			vr:       VLANRange{Start: 0, End: 100},
			expected: false,
		},
		{
			name:     "invalid zero end",
			vr:       VLANRange{Start: 1, End: 0},
			expected: false,
		},
		{
			name:     "invalid both zero",
			vr:       VLANRange{Start: 0, End: 0},
			expected: false,
		},
		{
			name:     "invalid start greater than end",
			vr:       VLANRange{Start: 200, End: 100},
			expected: false,
		},
		{
			name:     "invalid end exceeds max",
			vr:       VLANRange{Start: 1, End: 4095},
			expected: false,
		},
		{
			name:     "invalid both exceed max",
			vr:       VLANRange{Start: 5000, End: 6000},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vr.IsValid()
			if result != tt.expected {
				t.Errorf("VLANRange{%d, %d}.IsValid() = %v, want %v",
					tt.vr.Start, tt.vr.End, result, tt.expected)
			}
		})
	}
}

func TestVLANRange_Contains(t *testing.T) {
	vr := VLANRange{Start: 100, End: 200}

	tests := []struct {
		name     string
		vlan     uint16
		expected bool
	}{
		{
			name:     "at start",
			vlan:     100,
			expected: true,
		},
		{
			name:     "at end",
			vlan:     200,
			expected: true,
		},
		{
			name:     "in middle",
			vlan:     150,
			expected: true,
		},
		{
			name:     "below range",
			vlan:     99,
			expected: false,
		},
		{
			name:     "above range",
			vlan:     201,
			expected: false,
		},
		{
			name:     "zero",
			vlan:     0,
			expected: false,
		},
		{
			name:     "max VLAN",
			vlan:     4094,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vr.Contains(tt.vlan)
			if result != tt.expected {
				t.Errorf("VLANRange{%d, %d}.Contains(%d) = %v, want %v",
					vr.Start, vr.End, tt.vlan, result, tt.expected)
			}
		})
	}
}

func TestVLANRange_Size(t *testing.T) {
	tests := []struct {
		name     string
		vr       VLANRange
		expected int
	}{
		{
			name:     "single VLAN",
			vr:       VLANRange{Start: 100, End: 100},
			expected: 1,
		},
		{
			name:     "small range",
			vr:       VLANRange{Start: 100, End: 110},
			expected: 11,
		},
		{
			name:     "full range",
			vr:       VLANRange{Start: 1, End: 4094},
			expected: 4094,
		},
		{
			name:     "invalid range returns 0",
			vr:       VLANRange{Start: 0, End: 100},
			expected: 0,
		},
		{
			name:     "start greater than end returns 0",
			vr:       VLANRange{Start: 200, End: 100},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vr.Size()
			if result != tt.expected {
				t.Errorf("VLANRange{%d, %d}.Size() = %d, want %d",
					tt.vr.Start, tt.vr.End, result, tt.expected)
			}
		})
	}
}

func TestTenantBridge_Fields(t *testing.T) {
	now := time.Now()
	bridge := TenantBridge{
		Name:         "br-tenant-test",
		TenantID:     "tenant-123",
		TenantName:   "test-tenant",
		Datapath:     "system",
		VLANRange:    VLANRange{Start: 100, End: 200},
		CreatedAt:    now,
		UpdatedAt:    now,
		Status:       StatusActive,
		PortCount:    5,
		FlowCount:    10,
		UUID:         "abc-123",
		ErrorMessage: "",
	}

	if bridge.Name != "br-tenant-test" {
		t.Errorf("Name = %q, want %q", bridge.Name, "br-tenant-test")
	}
	if bridge.TenantID != "tenant-123" {
		t.Errorf("TenantID = %q, want %q", bridge.TenantID, "tenant-123")
	}
	if bridge.TenantName != "test-tenant" {
		t.Errorf("TenantName = %q, want %q", bridge.TenantName, "test-tenant")
	}
	if bridge.Datapath != "system" {
		t.Errorf("Datapath = %q, want %q", bridge.Datapath, "system")
	}
	if bridge.VLANRange.Start != 100 || bridge.VLANRange.End != 200 {
		t.Errorf("VLANRange = %v, want {100, 200}", bridge.VLANRange)
	}
	if bridge.Status != StatusActive {
		t.Errorf("Status = %q, want %q", bridge.Status, StatusActive)
	}
	if bridge.PortCount != 5 {
		t.Errorf("PortCount = %d, want %d", bridge.PortCount, 5)
	}
	if bridge.FlowCount != 10 {
		t.Errorf("FlowCount = %d, want %d", bridge.FlowCount, 10)
	}
	if bridge.UUID != "abc-123" {
		t.Errorf("UUID = %q, want %q", bridge.UUID, "abc-123")
	}
}

func TestBridgeInfo_Fields(t *testing.T) {
	info := BridgeInfo{
		Name:         "br-test",
		UUID:         "uuid-123",
		DatapathType: "system",
		Ports:        []string{"port1", "port2"},
		Status:       map[string]string{"state": "active"},
	}

	if info.Name != "br-test" {
		t.Errorf("Name = %q, want %q", info.Name, "br-test")
	}
	if info.UUID != "uuid-123" {
		t.Errorf("UUID = %q, want %q", info.UUID, "uuid-123")
	}
	if info.DatapathType != "system" {
		t.Errorf("DatapathType = %q, want %q", info.DatapathType, "system")
	}
	if len(info.Ports) != 2 {
		t.Errorf("len(Ports) = %d, want %d", len(info.Ports), 2)
	}
	if info.Status["state"] != "active" {
		t.Errorf("Status['state'] = %q, want %q", info.Status["state"], "active")
	}
}

func TestBridgeOptions_Functional(t *testing.T) {
	t.Run("WithDatapathType", func(t *testing.T) {
		opts := &bridgeOptions{}
		WithDatapathType("netdev")(opts)
		if opts.datapathType != "netdev" {
			t.Errorf("datapathType = %q, want %q", opts.datapathType, "netdev")
		}
	})

	t.Run("WithFailMode", func(t *testing.T) {
		opts := &bridgeOptions{}
		WithFailMode("standalone")(opts)
		if opts.failMode != "standalone" {
			t.Errorf("failMode = %q, want %q", opts.failMode, "standalone")
		}
	})

	t.Run("WithProtocols", func(t *testing.T) {
		opts := &bridgeOptions{}
		protocols := []string{"OpenFlow13", "OpenFlow15"}
		WithProtocols(protocols)(opts)
		if len(opts.protocols) != 2 {
			t.Errorf("len(protocols) = %d, want %d", len(opts.protocols), 2)
		}
		if opts.protocols[0] != "OpenFlow13" {
			t.Errorf("protocols[0] = %q, want %q", opts.protocols[0], "OpenFlow13")
		}
	})

	t.Run("WithExternalIDs", func(t *testing.T) {
		opts := &bridgeOptions{}
		ids := map[string]string{"key": "value"}
		WithExternalIDs(ids)(opts)
		if opts.externalIDs["key"] != "value" {
			t.Errorf("externalIDs['key'] = %q, want %q", opts.externalIDs["key"], "value")
		}
	})

	t.Run("WithOtherConfig", func(t *testing.T) {
		opts := &bridgeOptions{}
		config := map[string]string{"option": "enabled"}
		WithOtherConfig(config)(opts)
		if opts.otherConfig["option"] != "enabled" {
			t.Errorf("otherConfig['option'] = %q, want %q", opts.otherConfig["option"], "enabled")
		}
	})
}

func TestFlowMatch_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		match    FlowMatch
		expected bool
	}{
		{
			name:     "empty match",
			match:    FlowMatch{},
			expected: true,
		},
		{
			name: "with InPort",
			match: FlowMatch{
				InPort: ptrUint32(1),
			},
			expected: false,
		},
		{
			name: "with VLAN",
			match: FlowMatch{
				VLAN: ptrUint16(100),
			},
			expected: false,
		},
		{
			name: "with EthSrc",
			match: FlowMatch{
				EthSrc: ptrString("00:11:22:33:44:55"),
			},
			expected: false,
		},
		{
			name: "with EthDst",
			match: FlowMatch{
				EthDst: ptrString("ff:ff:ff:ff:ff:ff"),
			},
			expected: false,
		},
		{
			name: "with EthType",
			match: FlowMatch{
				EthType: ptrUint16(0x0800),
			},
			expected: false,
		},
		{
			name: "with IPProto",
			match: FlowMatch{
				IPProto: ptrUint8(6),
			},
			expected: false,
		},
		{
			name: "with IPv4Src",
			match: FlowMatch{
				IPv4Src: ptrString("192.168.1.1"),
			},
			expected: false,
		},
		{
			name: "with IPv4Dst",
			match: FlowMatch{
				IPv4Dst: ptrString("10.0.0.1"),
			},
			expected: false,
		},
		{
			name: "with TCPSrc",
			match: FlowMatch{
				TCPSrc: ptrUint16(80),
			},
			expected: false,
		},
		{
			name: "with TCPDst",
			match: FlowMatch{
				TCPDst: ptrUint16(443),
			},
			expected: false,
		},
		{
			name: "with UDPSrc",
			match: FlowMatch{
				UDPSrc: ptrUint16(53),
			},
			expected: false,
		},
		{
			name: "with UDPDst",
			match: FlowMatch{
				UDPDst: ptrUint16(67),
			},
			expected: false,
		},
		{
			name: "with multiple fields",
			match: FlowMatch{
				VLAN:    ptrUint16(100),
				EthType: ptrUint16(0x0800),
				IPProto: ptrUint8(6),
				TCPDst:  ptrUint16(80),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.match.IsEmpty()
			if result != tt.expected {
				t.Errorf("FlowMatch.IsEmpty() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFlow_Fields(t *testing.T) {
	vlan := uint16(100)
	flow := Flow{
		Table:    TableIngress,
		Priority: PriorityBase,
		Match: FlowMatch{
			VLAN: &vlan,
		},
		Actions: []Action{
			{Type: ActionGotoTable, Table: TableVLANValidation},
		},
		Cookie:      CookieBaseFlow,
		IdleTimeout: 0,
		HardTimeout: 0,
	}

	if flow.Table != TableIngress {
		t.Errorf("Table = %d, want %d", flow.Table, TableIngress)
	}
	if flow.Priority != PriorityBase {
		t.Errorf("Priority = %d, want %d", flow.Priority, PriorityBase)
	}
	if *flow.Match.VLAN != 100 {
		t.Errorf("Match.VLAN = %d, want %d", *flow.Match.VLAN, 100)
	}
	if len(flow.Actions) != 1 {
		t.Errorf("len(Actions) = %d, want %d", len(flow.Actions), 1)
	}
	if flow.Cookie != CookieBaseFlow {
		t.Errorf("Cookie = %x, want %x", flow.Cookie, CookieBaseFlow)
	}
}

func TestAction_Fields(t *testing.T) {
	tests := []struct {
		name   string
		action Action
	}{
		{
			name: "output action",
			action: Action{
				Type: ActionOutput,
				Port: 1,
			},
		},
		{
			name: "drop action",
			action: Action{
				Type: ActionDrop,
			},
		},
		{
			name: "set VLAN action",
			action: Action{
				Type: ActionSetVLAN,
				VLAN: 100,
			},
		},
		{
			name: "goto table action",
			action: Action{
				Type:  ActionGotoTable,
				Table: 1,
			},
		},
		{
			name: "set field action",
			action: Action{
				Type:  ActionSetField,
				Field: "eth_dst",
				Value: "00:11:22:33:44:55",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify action type is set
			if tt.action.Type == "" {
				t.Error("Action.Type should not be empty")
			}
		})
	}
}

func TestActionType_Constants(t *testing.T) {
	tests := []struct {
		action   ActionType
		expected string
	}{
		{ActionOutput, "output"},
		{ActionDrop, "drop"},
		{ActionSetVLAN, "set_vlan"},
		{ActionPopVLAN, "pop_vlan"},
		{ActionPushVLAN, "push_vlan"},
		{ActionGotoTable, "goto_table"},
		{ActionSetField, "set_field"},
		{ActionNormal, "normal"},
		{ActionFlood, "flood"},
		{ActionController, "controller"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("ActionType = %q, want %q", string(tt.action), tt.expected)
			}
		})
	}
}

func TestPortConstants(t *testing.T) {
	tests := []struct {
		name     string
		port     uint32
		expected uint32
	}{
		{"PortMax", PortMax, 0xffffff00},
		{"PortInPort", PortInPort, 0xfffffff8},
		{"PortTable", PortTable, 0xfffffff9},
		{"PortNormal", PortNormal, 0xfffffffa},
		{"PortFlood", PortFlood, 0xfffffffb},
		{"PortAll", PortAll, 0xfffffffc},
		{"PortController", PortController, 0xfffffffd},
		{"PortLocal", PortLocal, 0xfffffffe},
		{"PortAny", PortAny, 0xffffffff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.port != tt.expected {
				t.Errorf("%s = %x, want %x", tt.name, tt.port, tt.expected)
			}
		})
	}
}

func TestEthTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		ethType  uint16
		expected uint16
	}{
		{"EthTypeIPv4", EthTypeIPv4, 0x0800},
		{"EthTypeARP", EthTypeARP, 0x0806},
		{"EthTypeVLAN", EthTypeVLAN, 0x8100},
		{"EthTypeIPv6", EthTypeIPv6, 0x86DD},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ethType != tt.expected {
				t.Errorf("%s = %x, want %x", tt.name, tt.ethType, tt.expected)
			}
		})
	}
}

func TestIPProtoConstants(t *testing.T) {
	tests := []struct {
		name     string
		proto    uint8
		expected uint8
	}{
		{"IPProtoICMP", IPProtoICMP, 1},
		{"IPProtoTCP", IPProtoTCP, 6},
		{"IPProtoUDP", IPProtoUDP, 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proto != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.proto, tt.expected)
			}
		})
	}
}

func TestTableConstants(t *testing.T) {
	tests := []struct {
		name     string
		table    uint8
		expected uint8
	}{
		{"TableIngress", TableIngress, 0},
		{"TableVLANValidation", TableVLANValidation, 1},
		{"TableForwarding", TableForwarding, 2},
		{"TableEgress", TableEgress, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.table != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.table, tt.expected)
			}
		})
	}
}

func TestLifecycleEvent_Constants(t *testing.T) {
	tests := []struct {
		event    LifecycleEvent
		expected string
	}{
		{EventCreate, "create"},
		{EventActivate, "activate"},
		{EventSuspend, "suspend"},
		{EventResume, "resume"},
		{EventDelete, "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.event) != tt.expected {
				t.Errorf("LifecycleEvent = %q, want %q", string(tt.event), tt.expected)
			}
		})
	}
}

// Helper functions for creating pointers
func ptrUint8(v uint8) *uint8    { return &v }
func ptrUint16(v uint16) *uint16 { return &v }
func ptrUint32(v uint32) *uint32 { return &v }
func ptrString(v string) *string { return &v }

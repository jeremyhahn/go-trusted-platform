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

package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBridgeState_EntityID(t *testing.T) {
	bridge := &BridgeState{ID: "br-test-123"}
	entityID := bridge.EntityID()

	// Same ID should produce same hash
	bridge2 := &BridgeState{ID: "br-test-123"}
	assert.Equal(t, entityID, bridge2.EntityID())

	// Different ID should produce different hash
	bridge3 := &BridgeState{ID: "br-different"}
	assert.NotEqual(t, entityID, bridge3.EntityID())
}

func TestBridgeState_SetEntityID(t *testing.T) {
	bridge := &BridgeState{ID: "br-test"}
	originalID := bridge.EntityID()

	// SetEntityID is a no-op, entity ID is derived from bridge ID
	bridge.SetEntityID(12345)

	assert.Equal(t, originalID, bridge.EntityID())
}

func TestPortState_EntityID(t *testing.T) {
	port := &PortState{ID: "port-test-123"}
	entityID := port.EntityID()

	// Same ID should produce same hash
	port2 := &PortState{ID: "port-test-123"}
	assert.Equal(t, entityID, port2.EntityID())

	// Different ID should produce different hash
	port3 := &PortState{ID: "port-different"}
	assert.NotEqual(t, entityID, port3.EntityID())
}

func TestPortState_SetEntityID(t *testing.T) {
	port := &PortState{ID: "port-test"}
	originalID := port.EntityID()

	// SetEntityID is a no-op, entity ID is derived from port ID
	port.SetEntityID(12345)

	assert.Equal(t, originalID, port.EntityID())
}

func TestFlowState_EntityID(t *testing.T) {
	flow := &FlowState{ID: "flow-test-123"}
	entityID := flow.EntityID()

	// Same ID should produce same hash
	flow2 := &FlowState{ID: "flow-test-123"}
	assert.Equal(t, entityID, flow2.EntityID())

	// Different ID should produce different hash
	flow3 := &FlowState{ID: "flow-different"}
	assert.NotEqual(t, entityID, flow3.EntityID())
}

func TestFlowState_SetEntityID(t *testing.T) {
	flow := &FlowState{ID: "flow-test"}
	originalID := flow.EntityID()

	// SetEntityID is a no-op, entity ID is derived from flow ID
	flow.SetEntityID(12345)

	assert.Equal(t, originalID, flow.EntityID())
}

func TestVLANState_EntityID(t *testing.T) {
	vlan := &VLANState{ID: 100}
	entityID := vlan.EntityID()

	// VLAN ID is used directly as entity ID
	assert.Equal(t, uint64(100), entityID)

	// Different ID should produce different entity ID
	vlan2 := &VLANState{ID: 200}
	assert.Equal(t, uint64(200), vlan2.EntityID())
}

func TestVLANState_SetEntityID(t *testing.T) {
	vlan := &VLANState{ID: 100}

	// SetEntityID is a no-op, entity ID is the VLAN ID
	vlan.SetEntityID(12345)

	// ID should remain unchanged
	assert.Equal(t, uint64(100), vlan.EntityID())
}

func TestHashString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect uint64
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "simple string",
			input: "test",
		},
		{
			name:  "bridge id",
			input: "br-test-123",
		},
		{
			name:  "uuid style",
			input: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := hashString(tt.input)
			hash2 := hashString(tt.input)

			// Same input should produce same hash
			assert.Equal(t, hash1, hash2)

			// Different inputs should produce different hashes (most of the time)
			if tt.input != "" {
				hash3 := hashString(tt.input + "x")
				assert.NotEqual(t, hash1, hash3)
			}
		})
	}
}

func TestHashString_Uniqueness(t *testing.T) {
	// Verify different strings produce different hashes
	hashes := make(map[uint64]string)
	testInputs := []string{
		"br-1", "br-2", "br-3",
		"port-1", "port-2", "port-3",
		"flow-1", "flow-2", "flow-3",
		"test", "Test", "TEST",
		"abc", "def", "ghi",
	}

	for _, input := range testInputs {
		hash := hashString(input)
		if existing, found := hashes[hash]; found && existing != input {
			t.Errorf("Hash collision: %s and %s both produce %d", input, existing, hash)
		}
		hashes[hash] = input
	}
}

func TestFlowMatch_Fields(t *testing.T) {
	inPort := uint32(1)
	ethType := uint16(0x0800)
	vlanVid := uint16(100)
	vlanPcp := uint8(3)
	ipProto := uint8(6)
	tcpSrc := uint16(80)
	tcpDst := uint16(443)
	udpSrc := uint16(53)
	udpDst := uint16(53)
	icmpType := uint8(8)
	icmpCode := uint8(0)
	arpOp := uint16(1)

	match := &FlowMatch{
		InPort:   &inPort,
		EthSrc:   "00:11:22:33:44:55",
		EthDst:   "66:77:88:99:aa:bb",
		EthType:  &ethType,
		VLANVid:  &vlanVid,
		VLANPcp:  &vlanPcp,
		IPv4Src:  "192.168.1.0/24",
		IPv4Dst:  "10.0.0.0/8",
		IPProto:  &ipProto,
		TCPSrc:   &tcpSrc,
		TCPDst:   &tcpDst,
		UDPSrc:   &udpSrc,
		UDPDst:   &udpDst,
		ICMPType: &icmpType,
		ICMPCode: &icmpCode,
		ARPOp:    &arpOp,
		ARPSpa:   "192.168.1.1",
		ARPTpa:   "192.168.1.2",
	}

	assert.Equal(t, uint32(1), *match.InPort)
	assert.Equal(t, "00:11:22:33:44:55", match.EthSrc)
	assert.Equal(t, "66:77:88:99:aa:bb", match.EthDst)
	assert.Equal(t, uint16(0x0800), *match.EthType)
	assert.Equal(t, uint16(100), *match.VLANVid)
	assert.Equal(t, uint8(3), *match.VLANPcp)
	assert.Equal(t, "192.168.1.0/24", match.IPv4Src)
	assert.Equal(t, "10.0.0.0/8", match.IPv4Dst)
	assert.Equal(t, uint8(6), *match.IPProto)
	assert.Equal(t, uint16(80), *match.TCPSrc)
	assert.Equal(t, uint16(443), *match.TCPDst)
	assert.Equal(t, uint16(53), *match.UDPSrc)
	assert.Equal(t, uint16(53), *match.UDPDst)
	assert.Equal(t, uint8(8), *match.ICMPType)
	assert.Equal(t, uint8(0), *match.ICMPCode)
	assert.Equal(t, uint16(1), *match.ARPOp)
	assert.Equal(t, "192.168.1.1", match.ARPSpa)
	assert.Equal(t, "192.168.1.2", match.ARPTpa)
}

func TestFlowAction_AllTypes(t *testing.T) {
	tests := []struct {
		name       string
		actionType FlowActionType
	}{
		{name: "output", actionType: ActionOutput},
		{name: "drop", actionType: ActionDrop},
		{name: "normal", actionType: ActionNormal},
		{name: "flood", actionType: ActionFlood},
		{name: "all", actionType: ActionAll},
		{name: "controller", actionType: ActionController},
		{name: "local", actionType: ActionLocal},
		{name: "in_port", actionType: ActionInPort},
		{name: "set_vlan", actionType: ActionSetVLAN},
		{name: "strip_vlan", actionType: ActionStripVLAN},
		{name: "set_vlan_pcp", actionType: ActionSetVLANPcp},
		{name: "set_eth_src", actionType: ActionSetEthSrc},
		{name: "set_eth_dst", actionType: ActionSetEthDst},
		{name: "set_ipv4_src", actionType: ActionSetIPv4Src},
		{name: "set_ipv4_dst", actionType: ActionSetIPv4Dst},
		{name: "set_tcp_src", actionType: ActionSetTCPSrc},
		{name: "set_tcp_dst", actionType: ActionSetTCPDst},
		{name: "set_udp_src", actionType: ActionSetUDPSrc},
		{name: "set_udp_dst", actionType: ActionSetUDPDst},
		{name: "goto_table", actionType: ActionGotoTable},
		{name: "group", actionType: ActionGroup},
		{name: "meter", actionType: ActionMeter},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := &FlowAction{Type: tt.actionType}
			assert.Equal(t, tt.actionType, action.Type)
		})
	}
}

func TestFlowAction_WithParameters(t *testing.T) {
	port := uint32(1)
	vlanVid := uint16(100)
	vlanPcp := uint8(3)
	l4Port := uint16(80)
	table := uint8(1)
	groupID := uint32(10)
	meterID := uint32(20)

	action := &FlowAction{
		Type:    ActionOutput,
		Port:    &port,
		VLANVid: &vlanVid,
		VLANPcp: &vlanPcp,
		MAC:     "00:11:22:33:44:55",
		IPv4:    "192.168.1.1",
		L4Port:  &l4Port,
		Table:   &table,
		GroupID: &groupID,
		MeterID: &meterID,
	}

	assert.Equal(t, ActionOutput, action.Type)
	assert.Equal(t, uint32(1), *action.Port)
	assert.Equal(t, uint16(100), *action.VLANVid)
	assert.Equal(t, uint8(3), *action.VLANPcp)
	assert.Equal(t, "00:11:22:33:44:55", action.MAC)
	assert.Equal(t, "192.168.1.1", action.IPv4)
	assert.Equal(t, uint16(80), *action.L4Port)
	assert.Equal(t, uint8(1), *action.Table)
	assert.Equal(t, uint32(10), *action.GroupID)
	assert.Equal(t, uint32(20), *action.MeterID)
}

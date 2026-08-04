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

package daemon

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helper Functions Tests - ovsBridgeToPb
// These functions have 0% coverage and need direct testing
// =============================================================================

func TestSDNService_ovsBridgeToPb(t *testing.T) {
	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}

	t.Run("full bridge conversion", func(t *testing.T) {
		ovsBridge := &ovs.Bridge{
			UUID:         "uuid-bridge-1",
			Name:         "br0",
			DatapathType: "system",
			Ports:        []string{"port1", "port2"},
			FailMode:     "standalone",
			STP:          true,
			RSTP:         false,
			ExternalIDs:  map[string]string{"external-id-1": "value1"},
			OtherConfig:  map[string]string{"config-key": "config-value"},
		}

		result := svc.ovsBridgeToPb(ovsBridge)

		require.NotNil(t, result)
		assert.Equal(t, "uuid-bridge-1", result.Id)
		require.NotNil(t, result.Config)
		assert.Equal(t, "br0", result.Config.Name)
		assert.Equal(t, platformv1.BridgeType_BRIDGE_TYPE_OVS, result.Config.Type)
		assert.Equal(t, "uuid-bridge-1", result.Config.DatapathId)
		assert.True(t, result.Config.StpEnabled)
		assert.Equal(t, "value1", result.Config.Labels["external-id-1"])
		assert.Equal(t, "config-value", result.Config.Options["config-key"])
		assert.Equal(t, platformv1.BridgeStatus_BRIDGE_STATUS_UP, result.Status)
		assert.NotNil(t, result.CreatedAt)
		assert.NotNil(t, result.UpdatedAt)
	})

	t.Run("bridge with empty maps", func(t *testing.T) {
		ovsBridge := &ovs.Bridge{
			UUID:        "uuid-bridge-2",
			Name:        "br1",
			STP:         false,
			ExternalIDs: nil,
			OtherConfig: nil,
		}

		result := svc.ovsBridgeToPb(ovsBridge)

		require.NotNil(t, result)
		assert.Equal(t, "uuid-bridge-2", result.Id)
		assert.Equal(t, "br1", result.Config.Name)
		assert.False(t, result.Config.StpEnabled)
		// nil maps should result in nil in proto
		assert.Nil(t, result.Config.Labels)
		assert.Nil(t, result.Config.Options)
	})

	t.Run("bridge with multiple external IDs", func(t *testing.T) {
		ovsBridge := &ovs.Bridge{
			UUID: "uuid-bridge-3",
			Name: "br2",
			ExternalIDs: map[string]string{
				"id1": "val1",
				"id2": "val2",
				"id3": "val3",
			},
			OtherConfig: map[string]string{
				"opt1": "optval1",
				"opt2": "optval2",
			},
		}

		result := svc.ovsBridgeToPb(ovsBridge)

		require.NotNil(t, result)
		assert.Len(t, result.Config.Labels, 3)
		assert.Len(t, result.Config.Options, 2)
	})

	t.Run("bridge with RSTP enabled", func(t *testing.T) {
		ovsBridge := &ovs.Bridge{
			UUID: "uuid-bridge-4",
			Name: "br3",
			STP:  false,
			RSTP: true,
		}

		result := svc.ovsBridgeToPb(ovsBridge)

		require.NotNil(t, result)
		// Config.StpEnabled reflects the STP field, not RSTP
		assert.False(t, result.Config.StpEnabled)
	})

	t.Run("bridge with empty name and UUID", func(t *testing.T) {
		ovsBridge := &ovs.Bridge{
			UUID: "",
			Name: "",
		}

		result := svc.ovsBridgeToPb(ovsBridge)

		require.NotNil(t, result)
		assert.Equal(t, "", result.Id)
		assert.Equal(t, "", result.Config.Name)
		assert.Equal(t, "", result.Config.DatapathId)
	})
}

// =============================================================================
// Helper Functions Tests - ovsPortToPb
// =============================================================================

func TestSDNService_ovsPortToPb(t *testing.T) {
	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}

	t.Run("full port conversion", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID:        "uuid-port-1",
			Name:        "port0",
			Interfaces:  []string{"iface1", "iface2"},
			Tag:         100,
			Trunks:      []int64{200, 300},
			VLANMode:    "access",
			ExternalIDs: map[string]string{"port-id": "value1"},
			OtherConfig: map[string]string{"config-key": "config-value"},
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-1")

		require.NotNil(t, result)
		assert.Equal(t, "uuid-port-1", result.Id)
		assert.Equal(t, "bridge-id-1", result.BridgeId)
		require.NotNil(t, result.Config)
		assert.Equal(t, "port0", result.Config.Name)
		assert.Equal(t, platformv1.PortType_PORT_TYPE_INTERNAL, result.Config.Type)
		assert.Equal(t, uint32(100), result.Config.Vlan)
		assert.Equal(t, "value1", result.Config.Labels["port-id"])
		assert.Equal(t, platformv1.PortStatus_PORT_STATUS_UP, result.Status)
		assert.NotNil(t, result.CreatedAt)
		assert.NotNil(t, result.UpdatedAt)
	})

	t.Run("port with no VLAN tag", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID:        "uuid-port-2",
			Name:        "port1",
			Tag:         0,
			ExternalIDs: nil,
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-2")

		require.NotNil(t, result)
		assert.Equal(t, "uuid-port-2", result.Id)
		assert.Equal(t, uint32(0), result.Config.Vlan)
	})

	t.Run("port with empty bridge ID", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID: "uuid-port-3",
			Name: "port2",
		}

		result := svc.ovsPortToPb(ovsPort, "")

		require.NotNil(t, result)
		assert.Equal(t, "", result.BridgeId)
	})

	t.Run("port with multiple labels", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID: "uuid-port-4",
			Name: "port3",
			Tag:  50,
			ExternalIDs: map[string]string{
				"label1": "value1",
				"label2": "value2",
				"label3": "value3",
			},
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-3")

		require.NotNil(t, result)
		assert.Len(t, result.Config.Labels, 3)
		assert.Equal(t, "value1", result.Config.Labels["label1"])
		assert.Equal(t, "value2", result.Config.Labels["label2"])
		assert.Equal(t, "value3", result.Config.Labels["label3"])
	})

	t.Run("port with high VLAN tag", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID: "uuid-port-5",
			Name: "port4",
			Tag:  4095, // Max VLAN ID
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-4")

		require.NotNil(t, result)
		assert.Equal(t, uint32(4095), result.Config.Vlan)
	})

	t.Run("port with empty name and UUID", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID: "",
			Name: "",
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-5")

		require.NotNil(t, result)
		assert.Equal(t, "", result.Id)
		assert.Equal(t, "", result.Config.Name)
	})

	t.Run("port with trunk ports", func(t *testing.T) {
		ovsPort := &ovs.Port{
			UUID:     "uuid-port-6",
			Name:     "trunk-port",
			VLANMode: "trunk",
			Trunks:   []int64{100, 200, 300, 400},
		}

		result := svc.ovsPortToPb(ovsPort, "bridge-id-6")

		require.NotNil(t, result)
		// The current implementation sets Type to PORT_TYPE_INTERNAL regardless
		assert.Equal(t, platformv1.PortType_PORT_TYPE_INTERNAL, result.Config.Type)
	})
}

// =============================================================================
// Helper Functions Tests - ovsFlowToPb
// =============================================================================

func TestSDNService_ovsFlowToPb(t *testing.T) {
	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}

	t.Run("full flow conversion", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Table:       0,
			Priority:    100,
			Match:       "in_port=1,dl_vlan=100",
			Actions:     "output:2",
			Cookie:      "0x1234",
			Duration:    3600,
			PacketCount: 1000,
			ByteCount:   500000,
		}

		result := svc.ovsFlowToPb(ovsFlow, "bridge-id-1")

		require.NotNil(t, result)
		assert.Equal(t, "flow-0x1234", result.Id)
		require.NotNil(t, result.Config)
		assert.Equal(t, "bridge-id-1", result.Config.BridgeId)
		assert.NotNil(t, result.CreatedAt)
	})

	t.Run("flow with empty cookie", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Table:    1,
			Priority: 50,
			Match:    "in_port=3",
			Actions:  "drop",
			Cookie:   "",
		}

		result := svc.ovsFlowToPb(ovsFlow, "bridge-id-2")

		require.NotNil(t, result)
		assert.Equal(t, "flow-", result.Id)
		assert.Equal(t, "bridge-id-2", result.Config.BridgeId)
	})

	t.Run("flow with special cookie characters", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Table:       2,
			Priority:    200,
			Cookie:      "0xabcdef123456",
			PacketCount: 999999,
			ByteCount:   888888888,
		}

		result := svc.ovsFlowToPb(ovsFlow, "bridge-id-3")

		require.NotNil(t, result)
		assert.Equal(t, "flow-0xabcdef123456", result.Id)
	})

	t.Run("flow with empty bridge ID", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Cookie: "test-cookie",
		}

		result := svc.ovsFlowToPb(ovsFlow, "")

		require.NotNil(t, result)
		assert.Equal(t, "", result.Config.BridgeId)
	})

	t.Run("flow with high priority", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Table:    0,
			Priority: 65535, // Max OpenFlow priority
			Cookie:   "high-priority",
		}

		result := svc.ovsFlowToPb(ovsFlow, "bridge-id-4")

		require.NotNil(t, result)
		assert.Equal(t, "flow-high-priority", result.Id)
	})

	t.Run("flow with large counters", func(t *testing.T) {
		ovsFlow := &ovs.Flow{
			Cookie:      "large-counters",
			PacketCount: 9223372036854775807, // Max int64
			ByteCount:   9223372036854775807,
		}

		result := svc.ovsFlowToPb(ovsFlow, "bridge-id-5")

		require.NotNil(t, result)
		assert.Equal(t, "flow-large-counters", result.Id)
	})

	t.Run("flow with all empty fields", func(t *testing.T) {
		ovsFlow := &ovs.Flow{}

		result := svc.ovsFlowToPb(ovsFlow, "")

		require.NotNil(t, result)
		assert.Equal(t, "flow-", result.Id)
		assert.Equal(t, "", result.Config.BridgeId)
	})
}

// =============================================================================
// pbToOvsFlowMod Tests - Complete coverage for all match and action types
// =============================================================================

func TestSDNService_pbToOvsFlowMod_Extended(t *testing.T) {
	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}

	t.Run("config with empty match struct", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
			Match:    &platformv1.FlowMatch{}, // Empty match
			Actions:  []*platformv1.FlowAction{},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, 100, flowMod.Priority)
		assert.Empty(t, flowMod.Match) // Should be empty
	})

	t.Run("config with partial match fields", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 200,
			Match: &platformv1.FlowMatch{
				InPort: "1", // Only in_port set
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, "in_port=1", flowMod.Match)
	})

	t.Run("config with only VlanId in match", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 150,
			Match: &platformv1.FlowMatch{
				VlanId: 100,
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Contains(t, flowMod.Match, "dl_vlan=100")
	})

	t.Run("config with only EthSrc in match", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Match: &platformv1.FlowMatch{
				EthSrc: "00:11:22:33:44:55",
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Contains(t, flowMod.Match, "dl_src=00:11:22:33:44:55")
	})

	t.Run("config with only EthDst in match", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Match: &platformv1.FlowMatch{
				EthDst: "66:77:88:99:aa:bb",
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Contains(t, flowMod.Match, "dl_dst=66:77:88:99:aa:bb")
	})

	t.Run("config with empty actions", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Actions:  []*platformv1.FlowAction{},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Empty(t, flowMod.Actions)
	})

	t.Run("config with single OUTPUT action", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Actions: []*platformv1.FlowAction{
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
					Port: "3",
				},
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, "output:3", flowMod.Actions)
	})

	t.Run("config with single DROP action", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Actions: []*platformv1.FlowAction{
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_DROP,
				},
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, "drop", flowMod.Actions)
	})

	t.Run("config with SET_VLAN action", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Actions: []*platformv1.FlowAction{
				{
					Type:   platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
					VlanId: 200,
				},
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, "mod_vlan_vid:200", flowMod.Actions)
	})

	t.Run("config with STRIP_VLAN action", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Actions: []*platformv1.FlowAction{
				{
					Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
				},
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, "strip_vlan", flowMod.Actions)
	})

	t.Run("config with multiple tables", func(t *testing.T) {
		testCases := []struct {
			table    platformv1.FlowTable
			expected int
		}{
			{platformv1.FlowTable_FLOW_TABLE_0, int(platformv1.FlowTable_FLOW_TABLE_0)},
			{platformv1.FlowTable_FLOW_TABLE_1, int(platformv1.FlowTable_FLOW_TABLE_1)},
			{platformv1.FlowTable_FLOW_TABLE_2, int(platformv1.FlowTable_FLOW_TABLE_2)},
		}

		for _, tc := range testCases {
			config := &platformv1.FlowConfig{
				BridgeId: "br0",
				Table:    tc.table,
			}

			flowMod := svc.pbToOvsFlowMod(config)

			require.NotNil(t, flowMod)
			assert.Equal(t, tc.expected, flowMod.Table)
		}
	})

	t.Run("config with all match fields", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 500,
			Match: &platformv1.FlowMatch{
				InPort: "1",
				VlanId: 100,
				EthSrc: "00:11:22:33:44:55",
				EthDst: "66:77:88:99:aa:bb",
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Contains(t, flowMod.Match, "in_port=1")
		assert.Contains(t, flowMod.Match, "dl_vlan=100")
		assert.Contains(t, flowMod.Match, "dl_src=00:11:22:33:44:55")
		assert.Contains(t, flowMod.Match, "dl_dst=66:77:88:99:aa:bb")
	})

	t.Run("config with all action types", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
				{Type: platformv1.FlowActionType_FLOW_ACTION_DROP},
				{Type: platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, VlanId: 100},
				{Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
			},
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Contains(t, flowMod.Actions, "output:2")
		assert.Contains(t, flowMod.Actions, "drop")
		assert.Contains(t, flowMod.Actions, "mod_vlan_vid:100")
		assert.Contains(t, flowMod.Actions, "strip_vlan")
	})

	t.Run("config with high priority", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 65535, // Max OpenFlow priority
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Equal(t, 65535, flowMod.Priority)
	})

	t.Run("config with nil actions slice", func(t *testing.T) {
		config := &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Actions:  nil,
		}

		flowMod := svc.pbToOvsFlowMod(config)

		require.NotNil(t, flowMod)
		assert.Empty(t, flowMod.Actions)
	})
}

// =============================================================================
// Resource Tracking Structure Tests
// =============================================================================

func TestSDNService_ResourceStructures(t *testing.T) {
	t.Run("bridgeResource fields", func(t *testing.T) {
		now := time.Now()
		br := &bridgeResource{
			id:         "test-id",
			name:       "test-bridge",
			bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
			createdAt:  now,
		}

		assert.Equal(t, "test-id", br.id)
		assert.Equal(t, "test-bridge", br.name)
		assert.Equal(t, platformv1.BridgeType_BRIDGE_TYPE_OVS, br.bridgeType)
		assert.Equal(t, now, br.createdAt)
	})

	t.Run("portResource fields", func(t *testing.T) {
		now := time.Now()
		pr := &portResource{
			id:        "port-id",
			name:      "port-name",
			bridgeID:  "bridge-id",
			portType:  platformv1.PortType_PORT_TYPE_TAP,
			createdAt: now,
		}

		assert.Equal(t, "port-id", pr.id)
		assert.Equal(t, "port-name", pr.name)
		assert.Equal(t, "bridge-id", pr.bridgeID)
		assert.Equal(t, platformv1.PortType_PORT_TYPE_TAP, pr.portType)
		assert.Equal(t, now, pr.createdAt)
	})

	t.Run("tapResource fields", func(t *testing.T) {
		now := time.Now()
		tr := &tapResource{
			name:      "tap-name",
			createdAt: now,
		}

		assert.Equal(t, "tap-name", tr.name)
		assert.Equal(t, now, tr.createdAt)
	})

	t.Run("vlanResource fields", func(t *testing.T) {
		now := time.Now()
		vr := &vlanResource{
			id:        "vlan-id",
			vlanID:    100,
			bridgeID:  "bridge-id",
			name:      "vlan-name",
			ports:     []string{"port1", "port2"},
			createdAt: now,
		}

		assert.Equal(t, "vlan-id", vr.id)
		assert.Equal(t, uint32(100), vr.vlanID)
		assert.Equal(t, "bridge-id", vr.bridgeID)
		assert.Equal(t, "vlan-name", vr.name)
		assert.ElementsMatch(t, []string{"port1", "port2"}, vr.ports)
		assert.Equal(t, now, vr.createdAt)
	})

	t.Run("portAuthResource fields", func(t *testing.T) {
		authTime := time.Now()
		expireTime := authTime.Add(24 * time.Hour)
		par := &portAuthResource{
			portID:          "port-id",
			bridgeID:        "bridge-id",
			certificateCN:   "test.example.com",
			certificate:     []byte("cert-data"),
			authenticatedAt: authTime,
			expiresAt:       expireTime,
			authorizedVLANs: []uint32{100, 200, 300},
		}

		assert.Equal(t, "port-id", par.portID)
		assert.Equal(t, "bridge-id", par.bridgeID)
		assert.Equal(t, "test.example.com", par.certificateCN)
		assert.Equal(t, []byte("cert-data"), par.certificate)
		assert.Equal(t, authTime, par.authenticatedAt)
		assert.Equal(t, expireTime, par.expiresAt)
		assert.ElementsMatch(t, []uint32{100, 200, 300}, par.authorizedVLANs)
	})
}

// =============================================================================
// SDNService Map Initialization Tests
// =============================================================================

func TestSDNService_MapInitialization(t *testing.T) {
	t.Run("empty service has initialized maps", func(t *testing.T) {
		svc := &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		}

		assert.NotNil(t, svc.bridges)
		assert.NotNil(t, svc.ports)
		assert.NotNil(t, svc.taps)
		assert.NotNil(t, svc.vlans)
		assert.NotNil(t, svc.portAuths)
		assert.Len(t, svc.bridges, 0)
		assert.Len(t, svc.ports, 0)
		assert.Len(t, svc.taps, 0)
		assert.Len(t, svc.vlans, 0)
		assert.Len(t, svc.portAuths, 0)
	})

	t.Run("service can store and retrieve resources", func(t *testing.T) {
		svc := &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		}

		// Add resources
		svc.bridges["br0"] = &bridgeResource{id: "id1", name: "br0"}
		svc.ports["port0"] = &portResource{id: "id2", name: "port0"}
		svc.taps["tap0"] = &tapResource{name: "tap0"}
		svc.vlans["br0:100"] = &vlanResource{id: "id3", vlanID: 100}
		svc.portAuths["br0:port0"] = &portAuthResource{portID: "port0"}

		// Verify
		assert.Len(t, svc.bridges, 1)
		assert.Len(t, svc.ports, 1)
		assert.Len(t, svc.taps, 1)
		assert.Len(t, svc.vlans, 1)
		assert.Len(t, svc.portAuths, 1)

		// Retrieve
		assert.Equal(t, "id1", svc.bridges["br0"].id)
		assert.Equal(t, "id2", svc.ports["port0"].id)
		assert.Equal(t, "tap0", svc.taps["tap0"].name)
		assert.Equal(t, "id3", svc.vlans["br0:100"].id)
		assert.Equal(t, "port0", svc.portAuths["br0:port0"].portID)
	})
}

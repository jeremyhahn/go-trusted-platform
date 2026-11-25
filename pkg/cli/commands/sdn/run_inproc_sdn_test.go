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

package sdn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestRunBridge_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("CreateBridge", &platformv1.CreateBridgeResponse{Bridge: &platformv1.Bridge{Id: "uuid-1", Config: &platformv1.BridgeConfig{Name: "br-lab"}}})
	rec.respond("GetBridge", &platformv1.GetBridgeResponse{Bridge: &platformv1.Bridge{Id: "uuid-1", Config: &platformv1.BridgeConfig{Name: "br-lab"}}})
	rec.respond("ListBridges", &platformv1.ListBridgesResponse{Bridges: []*platformv1.Bridge{{Id: "uuid-1", Config: &platformv1.BridgeConfig{Name: "br-lab"}}}})

	t.Run("create", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			return runBridgeCreate(flags, "bridge-7", "br-lab", "ovs", "lab bridge", "0000aa", "secure", true, true, 9000)
		})
		require.NoError(t, err)
		assert.Contains(t, out, "br-lab")

		cfg := rec.request(t, "CreateBridge").(*platformv1.CreateBridgeRequest).GetConfig()
		assert.Equal(t, "br-lab", cfg.GetName())
		assert.Equal(t, "0000aa", cfg.GetDatapathId())
		assert.True(t, cfg.GetStpEnabled())
		assert.Equal(t, uint32(9000), cfg.GetMtu())
		assert.Equal(t, map[string]string{"fail_mode": "secure", "rstp_enable": "true", "description": "lab bridge"}, cfg.GetOptions())
		assert.Equal(t, "bridge-7", cfg.GetLabels()["bridge_id"])
	})

	t.Run("create without options", func(t *testing.T) {
		_, err := captureStdout(t, func() error {
			return runBridgeCreate(flags, "bridge-8", "br-min", "ovs", "", "", "", false, false, 0)
		})
		require.NoError(t, err)
		cfg := rec.request(t, "CreateBridge").(*platformv1.CreateBridgeRequest).GetConfig()
		assert.Empty(t, cfg.GetOptions())
		assert.False(t, cfg.GetStpEnabled())
	})

	t.Run("get", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runBridgeGet(flags, "uuid-1") })
		require.NoError(t, err)
		assert.Contains(t, out, "br-lab")
		assert.Equal(t, "uuid-1", rec.request(t, "GetBridge").(*platformv1.GetBridgeRequest).GetId())
	})

	t.Run("list filters by type and status", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runBridgeList(flags, "ovs", "up", 25, "") })
		require.NoError(t, err)
		assert.Contains(t, out, "br-lab")
		req := rec.request(t, "ListBridges").(*platformv1.ListBridgesRequest)
		assert.Equal(t, map[string]string{"type": "ovs", "status": "up"}, req.GetSelector().GetMatchLabels())
	})

	t.Run("list without filters sends no selector", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runBridgeList(flags, "", "", 25, "") })
		require.NoError(t, err)
		assert.Nil(t, rec.request(t, "ListBridges").(*platformv1.ListBridgesRequest).GetSelector())
	})

	t.Run("delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runBridgeDelete(flags, "uuid-1", true, false, false) })
		require.NoError(t, err)
		assert.JSONEq(t, `{"bridge_id":"uuid-1","deleted":true}`, out)
		req := rec.request(t, "DeleteBridge").(*platformv1.DeleteBridgeRequest)
		assert.Equal(t, "uuid-1", req.GetId())
		assert.True(t, req.GetForce())
	})
}

func TestRunFlow_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("AddFlow", &platformv1.AddFlowResponse{Flow: &platformv1.Flow{Id: "flow-9"}})
	rec.respond("ListFlows", &platformv1.ListFlowsResponse{Flows: []*platformv1.Flow{{Id: "flow-9"}}})

	t.Run("add builds match and actions", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			return runFlowAdd(flags, "br0", "flow-9", 1, 200, 3, "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb",
				0x0800, "10.0.0.1", "10.0.0.2", []string{"output"}, 4)
		})
		require.NoError(t, err)
		assert.Contains(t, out, "flow-9")

		cfg := rec.request(t, "AddFlow").(*platformv1.AddFlowRequest).GetConfig()
		assert.Equal(t, "br0", cfg.GetBridgeId())
		assert.Equal(t, uint32(200), cfg.GetPriority())
		assert.Equal(t, "flow-9", cfg.GetMetadata()["flow_id"])
		m := cfg.GetMatch()
		assert.Equal(t, "3", m.GetInPort())
		assert.Equal(t, "aa:aa:aa:aa:aa:aa", m.GetEthSrc())
		assert.Equal(t, "bb:bb:bb:bb:bb:bb", m.GetEthDst())
		assert.Equal(t, uint32(0x0800), m.GetEthType())
		assert.Equal(t, "10.0.0.1", m.GetIpSrc())
		assert.Equal(t, "10.0.0.2", m.GetIpDst())
		require.Len(t, cfg.GetActions(), 1)
		assert.Equal(t, platformv1.FlowActionType_FLOW_ACTION_OUTPUT, cfg.GetActions()[0].GetType())
		assert.Equal(t, "4", cfg.GetActions()[0].GetPort())
	})

	t.Run("add with an empty match", func(t *testing.T) {
		_, err := captureStdout(t, func() error {
			return runFlowAdd(flags, "br0", "flow-10", 0, 100, 0, "", "", 0, "", "", []string{"drop"}, 0)
		})
		require.NoError(t, err)
		cfg := rec.request(t, "AddFlow").(*platformv1.AddFlowRequest).GetConfig()
		assert.Empty(t, cfg.GetMatch().GetInPort())
		assert.Empty(t, cfg.GetActions()[0].GetPort())
	})

	t.Run("add rejects an unknown action before calling the server", func(t *testing.T) {
		before := len(rec.requests)
		err := runFlowAdd(flags, "br0", "flow-11", 0, 100, 0, "", "", 0, "", "", []string{"teleport"}, 0)
		var target ErrInvalidFlowActionType
		require.ErrorAs(t, err, &target)
		assert.Equal(t, "teleport", target.Type)
		assert.Len(t, rec.requests, before)
	})

	t.Run("delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runFlowDelete(flags, "br0", "flow-9") })
		require.NoError(t, err)
		assert.JSONEq(t, `{"bridge_id":"br0","flow_id":"flow-9","deleted":true}`, out)
		req := rec.request(t, "DeleteFlow").(*platformv1.DeleteFlowRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.Equal(t, "flow-9", req.GetFlowId())
	})

	t.Run("list a table", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runFlowList(flags, "br0", 1, 50, "") })
		require.NoError(t, err)
		assert.Contains(t, out, "flow-9")
		req := rec.request(t, "ListFlows").(*platformv1.ListFlowsRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.NotEqual(t, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED, req.GetTable())
	})

	t.Run("list every table", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runFlowList(flags, "br0", -1, 50, "") })
		require.NoError(t, err)
		assert.Equal(t, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED, rec.request(t, "ListFlows").(*platformv1.ListFlowsRequest).GetTable())
	})
}

func TestRunPort_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("AddPort", &platformv1.AddPortResponse{Port: &platformv1.Port{Id: "port-1", Config: &platformv1.PortConfig{Name: "eth1"}}})
	rec.respond("GetPort", &platformv1.GetPortResponse{Port: &platformv1.Port{Id: "port-1", Config: &platformv1.PortConfig{Name: "eth1"}}})
	rec.respond("GetPortStats", &platformv1.GetPortStatsResponse{Stats: &platformv1.PortStats{PacketsReceived: 42}})

	t.Run("add", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			return runPortAdd(flags, "br0", "port-1", "eth1", "internal", 100, "enp1s0", "02:00:00:00:00:01", 1500, "up")
		})
		require.NoError(t, err)
		assert.Contains(t, out, "eth1")

		req := rec.request(t, "AddPort").(*platformv1.AddPortRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		cfg := req.GetConfig()
		assert.Equal(t, "eth1", cfg.GetName())
		assert.Equal(t, uint32(100), cfg.GetVlan())
		assert.Equal(t, "02:00:00:00:00:01", cfg.GetMacAddress())
		assert.Equal(t, uint32(1500), cfg.GetMtu())
		assert.Equal(t, map[string]string{"interface": "enp1s0", "admin_state": "up"}, cfg.GetOptions())
		assert.Equal(t, "port-1", cfg.GetLabels()["port_id"])
	})

	t.Run("delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runPortDelete(flags, "br0", "eth1") })
		require.NoError(t, err)
		assert.JSONEq(t, `{"bridge_id":"br0","port_id":"eth1","deleted":true}`, out)
		req := rec.request(t, "DeletePort").(*platformv1.DeletePortRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.Equal(t, "eth1", req.GetPortId())
	})

	t.Run("state", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runPortGetState(flags, "br0", "eth1") })
		require.NoError(t, err)
		assert.Contains(t, out, "port-1")
		req := rec.request(t, "GetPort").(*platformv1.GetPortRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.Equal(t, "eth1", req.GetPortId())
	})

	t.Run("stats", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runPortGetStats(flags, "br0", "eth1") })
		require.NoError(t, err)
		assert.Contains(t, out, "42")
		req := rec.request(t, "GetPortStats").(*platformv1.GetPortStatsRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.Equal(t, "eth1", req.GetPortId())
	})
}

func TestRunVLAN_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("CreateVLAN", &platformv1.CreateVLANResponse{Vlan: &platformv1.VLAN{Id: "vlan-100", Config: &platformv1.VLANConfig{VlanId: 100, Name: "v100"}}})
	rec.respond("ListVLANs", &platformv1.ListVLANsResponse{Vlans: []*platformv1.VLAN{{Id: "vlan-100", Config: &platformv1.VLANConfig{VlanId: 100, Name: "v100"}}}})

	t.Run("create on the first bridge", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runVLANCreate(flags, 100, "v100", "lab", []string{"br0", "br1"}) })
		require.NoError(t, err)
		assert.Contains(t, out, "v100")
		cfg := rec.request(t, "CreateVLAN").(*platformv1.CreateVLANRequest).GetConfig()
		assert.Equal(t, uint32(100), cfg.GetVlanId())
		assert.Equal(t, "v100", cfg.GetName())
		assert.Equal(t, "br0", cfg.GetBridgeId())
		assert.Equal(t, "lab", cfg.GetLabels()["description"])
	})

	t.Run("create without bridges or description", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runVLANCreate(flags, 200, "v200", "", nil) })
		require.NoError(t, err)
		cfg := rec.request(t, "CreateVLAN").(*platformv1.CreateVLANRequest).GetConfig()
		assert.Empty(t, cfg.GetBridgeId())
		assert.Empty(t, cfg.GetLabels())
	})

	t.Run("delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runVLANDelete(flags, "br0", 100) })
		require.NoError(t, err)
		assert.JSONEq(t, `{"vlan_id":100,"deleted":true}`, out)
		req := rec.request(t, "DeleteVLAN").(*platformv1.DeleteVLANRequest)
		assert.Equal(t, "br0", req.GetBridgeId())
		assert.Equal(t, uint32(100), req.GetVlanId())
	})

	t.Run("list", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runVLANList(flags, "br0", 10, "") })
		require.NoError(t, err)
		assert.Contains(t, out, "v100")
		assert.Equal(t, "br0", rec.request(t, "ListVLANs").(*platformv1.ListVLANsRequest).GetBridgeId())
	})
}

func TestRunPolicy_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("ApplyPolicy", &platformv1.ApplyPolicyResponse{Policy: &platformv1.Policy{Id: "pol-1", Config: &platformv1.PolicyConfig{Name: "deny-all"}}})
	rec.respond("GetPolicy", &platformv1.GetPolicyResponse{Policy: &platformv1.Policy{Id: "pol-1", Config: &platformv1.PolicyConfig{Name: "deny-all"}}})
	rec.respond("ListPolicies", &platformv1.ListPoliciesResponse{Policies: []*platformv1.Policy{{Id: "pol-1", Config: &platformv1.PolicyConfig{Name: "deny-all"}}}})

	t.Run("apply targets the bridge", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			return runPolicyApply(flags, "pol-1", "deny-all", "acl", "drop everything", "br0", 10, true)
		})
		require.NoError(t, err)
		assert.Contains(t, out, "deny-all")

		req := rec.request(t, "ApplyPolicy").(*platformv1.ApplyPolicyRequest)
		assert.Equal(t, "pol-1", req.GetPolicyId())
		cfg := req.GetConfig()
		assert.Equal(t, "deny-all", cfg.GetName())
		assert.Equal(t, "drop everything", cfg.GetDescription())
		assert.Equal(t, int32(10), cfg.GetPriority())
		assert.True(t, cfg.GetEnabled())
		require.Len(t, cfg.GetTargets(), 1)
		assert.Equal(t, "br0", cfg.GetTargets()[0].GetId())
		assert.Equal(t, platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, cfg.GetTargets()[0].GetType())
	})

	t.Run("get", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runPolicyGet(flags, "pol-1") })
		require.NoError(t, err)
		assert.Contains(t, out, "deny-all")
		assert.Equal(t, "pol-1", rec.request(t, "GetPolicy").(*platformv1.GetPolicyRequest).GetPolicyId())
	})

	t.Run("list", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runPolicyList(flags, "acl", "br0", 10, "") })
		require.NoError(t, err)
		assert.Contains(t, out, "deny-all")
		req := rec.request(t, "ListPolicies").(*platformv1.ListPoliciesRequest)
		assert.Equal(t, "acl", req.GetType())
		assert.Equal(t, "br0", req.GetTargetId())
	})
}

// TestRunPolicyApply_InvalidTypeBeforeDialing is the regression test for
// policy apply validating --type only after connecting: without a reachable
// daemon the user saw a connection error instead of the bad type.
func TestRunPolicyApply_InvalidTypeBeforeDialing(t *testing.T) {
	err := runPolicyApply(&cli.CommonFlags{}, "p1", "p1", "teleport", "", "br0", 1, true)
	assert.Equal(t, ErrInvalidPolicyType{Type: "teleport"}, err)
}

func TestRunZone_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	zone := &platformv1.NetworkZone{Config: &platformv1.NetworkZoneConfig{Name: "lab"}}
	rec.respond("CreateNetworkZone", &platformv1.CreateNetworkZoneResponse{Zone: zone})
	rec.respond("UpdateNetworkZone", &platformv1.UpdateNetworkZoneResponse{Zone: zone})
	rec.respond("ListNetworkZones", &platformv1.ListNetworkZonesResponse{Zones: []*platformv1.NetworkZone{zone}})

	t.Run("list", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runZoneList(flags, "provisioning") })
		require.NoError(t, err)
		assert.Contains(t, out, "lab")
		assert.Equal(t, "provisioning", rec.request(t, "ListNetworkZones").(*platformv1.ListNetworkZonesRequest).GetLifecycleRole())
	})

	t.Run("create", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runZoneCreate(flags, &zoneFlags{name: "lab", offset: 9}) })
		require.NoError(t, err)
		assert.Contains(t, out, "lab")
		assert.Equal(t, "lab", rec.request(t, "CreateNetworkZone").(*platformv1.CreateNetworkZoneRequest).GetConfig().GetName())
	})

	t.Run("update", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runZoneUpdate(flags, &zoneFlags{name: "lab", isolate: true}) })
		require.NoError(t, err)
		assert.Contains(t, out, "lab")
		assert.Equal(t, "lab", rec.request(t, "UpdateNetworkZone").(*platformv1.UpdateNetworkZoneRequest).GetName())
	})

	t.Run("delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runZoneDelete(flags, "lab") })
		require.NoError(t, err)
		assert.Equal(t, "Network zone \"lab\" deleted successfully.\n", out)
		assert.Equal(t, "lab", rec.request(t, "DeleteNetworkZone").(*platformv1.DeleteNetworkZoneRequest).GetName())
	})

	t.Run("delete that needs a restart", func(t *testing.T) {
		rec.respond("DeleteNetworkZone", &platformv1.DeleteNetworkZoneResponse{RestartRequired: true})
		out, err := captureStdout(t, func() error { return runZoneDelete(flags, "lab") })
		require.NoError(t, err)
		assert.Equal(t, "Network zone \"lab\" deleted. Daemon restart required to re-derive the network plan.\n", out)
	})
}

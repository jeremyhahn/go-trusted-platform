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
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newSDNParityFixture returns an SDN service holding bridge br0 and port eth0
// on an in-memory OVS fake, and the MCP tool registry in front of it. The MCP
// tools and the gRPC methods are driven against the same service, so any
// difference between them is a request-mapping difference.
func newSDNParityFixture(t *testing.T) (*SDNService, *ConfigurableMockOVSClient, *mcp.ToolRegistry) {
	t.Helper()

	mockOVS := NewConfigurableMockOVSClient()
	sdnService := createMCPTestSDNService(mockOVS)
	sdnService.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	sdnService.ports["eth0"] = &portResource{id: "eth0-uuid", name: "eth0", bridgeID: "br0-uuid"}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})
	return sdnService, mockOVS, mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// captureFlowMods records every flow the service hands to the OVS fake.
func captureFlowMods(mockOVS *ConfigurableMockOVSClient) *[]ovs.FlowMod {
	var mods []ovs.FlowMod
	mockOVS.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		mods = append(mods, *flow)
		return nil
	})
	return &mods
}

// mcpJSON renders a value the way an MCP tool result renders it.
func mcpJSON(t *testing.T, v interface{}) interface{} {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out interface{}
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// TestSDNMCPAddFlowCarriesFlowBody is the regression for the faked
// sdn_add_flow: it read a "flow" argument its schema never declared, so the
// match and actions were dropped and every MCP flow reached the switch as an
// empty rule while the tool answered success.
func TestSDNMCPAddFlowCarriesFlowBody(t *testing.T) {
	_, mockOVS, registry := newSDNParityFixture(t)
	mods := captureFlowMods(mockOVS)

	result, err := registry.ExecuteTool(context.Background(), "sdn_add_flow", map[string]interface{}{
		"bridge_name": "br0",
		"priority":    float64(100),
		"match":       map[string]interface{}{"in_port": "1"},
		"actions": []interface{}{
			map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"},
		},
	})
	require.NoError(t, err)

	require.Len(t, *mods, 1, "the flow must reach the switch")
	assert.Equal(t, "in_port=1", (*mods)[0].Match)
	assert.Equal(t, "output:2", (*mods)[0].Actions)
	assert.Equal(t, 100, (*mods)[0].Priority)

	flow, ok := result.(map[string]interface{})["flow"].(*platformv1.Flow)
	require.True(t, ok, "sdn_add_flow must return the added flow")
	assert.NotEmpty(t, flow.GetId())
	assert.Equal(t, "1", flow.GetConfig().GetMatch().GetInPort())
}

func TestSDNMCPAddFlowRefusesUndecodableBody(t *testing.T) {
	tests := map[string]map[string]interface{}{
		"unknown match field": {"match": map[string]interface{}{"in_prot": "1"}},
		"unknown action type": {"actions": []interface{}{map[string]interface{}{"type": "FLOW_ACTION_TELEPORT"}}},
		"wrong field type":    {"priority": "high"},
		"unknown argument":    {"mtch": map[string]interface{}{"in_port": "1"}},
		"flow wrapper":        {"flow": map[string]interface{}{"priority": 100}},
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, mockOVS, registry := newSDNParityFixture(t)

			args := map[string]interface{}{"bridge_name": "br0"}
			for k, v := range body {
				args[k] = v
			}
			_, err := registry.ExecuteTool(context.Background(), "sdn_add_flow", args)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Zero(t, mockOVS.GetCallCount("AddFlow"), "an undecodable flow must never reach the switch")
		})
	}
}

// TestSDNMCPAddFlowMatchesGRPC sends one flow through both transports and
// checks that the switch receives the same rule and both answer the same flow.
func TestSDNMCPAddFlowMatchesGRPC(t *testing.T) {
	sdnService, mockOVS, registry := newSDNParityFixture(t)
	mods := captureFlowMods(mockOVS)
	ctx := context.Background()

	grpcConfig := &platformv1.FlowConfig{
		BridgeId: "br0",
		Priority: 200,
		Match:    &platformv1.FlowMatch{InPort: "3", VlanId: 10},
		Actions: []*platformv1.FlowAction{
			{Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
			{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "4"},
		},
	}
	grpcResp, err := sdnService.AddFlow(ctx, &platformv1.AddFlowRequest{Config: grpcConfig})
	require.NoError(t, err)

	mcpResult, err := registry.ExecuteTool(ctx, "sdn_add_flow", map[string]interface{}{
		"bridge_name": "br0",
		"priority":    float64(200),
		"match":       map[string]interface{}{"in_port": "3", "vlan_id": float64(10)},
		"actions": []interface{}{
			map[string]interface{}{"type": "FLOW_ACTION_STRIP_VLAN"},
			map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "4"},
		},
	})
	require.NoError(t, err)

	require.Len(t, *mods, 2)
	grpcMod, mcpMod := (*mods)[0], (*mods)[1]
	grpcMod.Cookie, mcpMod.Cookie = "", ""
	assert.Equal(t, grpcMod, mcpMod, "both transports must install the same rule")

	mcpFlow := mcpResult.(map[string]interface{})["flow"].(*platformv1.Flow)
	assert.True(t, proto.Equal(grpcResp.GetFlow().GetConfig(), mcpFlow.GetConfig()),
		"flow config: grpc %v, mcp %v", grpcResp.GetFlow().GetConfig(), mcpFlow.GetConfig())
}

// TestSDNMCPSuccessMatchesGRPC checks that each read and write tool answers
// what its gRPC twin answers on the same service.
func TestSDNMCPSuccessMatchesGRPC(t *testing.T) {
	ctx := context.Background()

	t.Run("list_flows", func(t *testing.T) {
		sdnService, mockOVS, registry := newSDNParityFixture(t)
		mockOVS.OnListFlows(func(context.Context, string) ([]*ovs.Flow, error) {
			return []*ovs.Flow{{Cookie: "0x10", Priority: 5, Match: "in_port=1", Actions: "drop"}}, nil
		})

		grpcResp, err := sdnService.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: "br0"})
		require.NoError(t, err)
		mcpResult, err := registry.ExecuteTool(ctx, "sdn_list_flows", map[string]interface{}{"bridge_name": "br0"})
		require.NoError(t, err)

		mcpFlows := mcpResult.(map[string]interface{})["flows"].([]interface{})
		require.Len(t, mcpFlows, len(grpcResp.GetFlows()))
		for i, f := range grpcResp.GetFlows() {
			// Each call stamps its own read time; everything else must match.
			mcpFlow := mcpFlows[i].(*platformv1.Flow)
			f.CreatedAt, mcpFlow.CreatedAt = nil, nil
			assert.True(t, proto.Equal(f, mcpFlow), "flow %d: grpc %v, mcp %v", i, f, mcpFlow)
		}
	})

	t.Run("flush_flows", func(t *testing.T) {
		sdnService, mockOVS, registry := newSDNParityFixture(t)
		mockOVS.OnListFlows(func(context.Context, string) ([]*ovs.Flow, error) {
			return []*ovs.Flow{{Cookie: "0x1"}, {Cookie: "0x2"}}, nil
		})

		grpcResp, err := sdnService.FlushFlows(ctx, &platformv1.FlushFlowsRequest{BridgeId: "br0"})
		require.NoError(t, err)
		mcpResult, err := registry.ExecuteTool(ctx, "sdn_flush_flows", map[string]interface{}{"bridge_name": "br0"})
		require.NoError(t, err)

		assert.Equal(t, grpcResp.GetDeletedCount(), mcpResult.(map[string]interface{})["deleted_count"])
	})

	t.Run("get_flow_stats", func(t *testing.T) {
		sdnService, _, registry := newSDNParityFixture(t)
		flowID := ovs.FlowID(0x2a)

		grpcResp, err := sdnService.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: flowID})
		require.NoError(t, err)
		mcpResult, err := registry.ExecuteTool(ctx, "sdn_get_flow_stats", map[string]interface{}{
			"bridge_name": "br0",
			"flow_id":     flowID,
		})
		require.NoError(t, err)

		assert.Equal(t, mcpJSON(t, grpcResp.GetStats()), mcpResult)
	})

	t.Run("create_and_list_vlans", func(t *testing.T) {
		grpcService, _, _ := newSDNParityFixture(t)
		mcpService, _, registry := newSDNParityFixture(t)

		grpcResp, err := grpcService.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
			Config: &platformv1.VLANConfig{BridgeId: "br0", VlanId: 100, Name: "vlan100"},
		})
		require.NoError(t, err)
		mcpResult, err := registry.ExecuteTool(ctx, "sdn_create_vlan", map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     float64(100),
			"name":        "vlan100",
		})
		require.NoError(t, err)

		mcpVLAN := mcpResult.(map[string]interface{})["vlan"].(*platformv1.VLAN)
		assert.Equal(t, grpcResp.GetVlan().GetId(), mcpVLAN.GetId())
		assert.True(t, proto.Equal(grpcResp.GetVlan().GetConfig(), mcpVLAN.GetConfig()))

		grpcList, err := grpcService.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: "br0"})
		require.NoError(t, err)
		mcpList, err := registry.ExecuteTool(ctx, "sdn_list_vlans", map[string]interface{}{"bridge_name": "br0"})
		require.NoError(t, err)
		mcpVLANs := mcpList.(map[string]interface{})["vlans"].([]interface{})
		require.Len(t, mcpVLANs, len(grpcList.GetVlans()))
		for i, v := range grpcList.GetVlans() {
			assert.Equal(t, v.GetId(), mcpVLANs[i].(*platformv1.VLAN).GetId())
		}

		_, err = grpcService.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 100})
		require.NoError(t, err)
		_, err = registry.ExecuteTool(ctx, "sdn_delete_vlan", map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     float64(100),
		})
		require.NoError(t, err)
		assert.Empty(t, mcpService.vlans, "sdn_delete_vlan must remove the VLAN")
	})

	t.Run("get_port_stats", func(t *testing.T) {
		sdnService, _, registry := newSDNParityFixture(t)

		grpcResp, err := sdnService.GetPortStats(ctx, &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "eth0"})
		require.NoError(t, err)
		mcpResult, err := registry.ExecuteTool(ctx, "sdn_get_port_stats", map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		})
		require.NoError(t, err)

		assert.Equal(t, mcpJSON(t, grpcResp.GetStats()), mcpResult)
	})
}

// TestSDNMCPErrorsMatchGRPC checks that each tool fails with the error class
// of its gRPC twin, for an unknown object and for invalid input.
func TestSDNMCPErrorsMatchGRPC(t *testing.T) {
	type grpcCall func(ctx context.Context, s *SDNService) error

	tests := []struct {
		name string
		tool string
		args map[string]interface{}
		grpc grpcCall
		want codes.Code
	}{
		{
			name: "add_flow unknown bridge", tool: "sdn_add_flow",
			args: map[string]interface{}{"bridge_name": "nope"},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.AddFlow(ctx, &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "nope"}})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "add_flow empty bridge", tool: "sdn_add_flow",
			args: map[string]interface{}{"bridge_name": ""},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.AddFlow(ctx, &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{}})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "delete_flow unknown bridge", tool: "sdn_delete_flow",
			args: map[string]interface{}{"bridge_name": "nope", "flow_id": ovs.FlowID(1)},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "nope", FlowId: ovs.FlowID(1)})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "delete_flow empty flow id", tool: "sdn_delete_flow",
			args: map[string]interface{}{"bridge_name": "br0", "flow_id": ""},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "br0"})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "list_flows unknown bridge", tool: "sdn_list_flows",
			args: map[string]interface{}{"bridge_name": "nope"},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: "nope"})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "flush_flows empty bridge", tool: "sdn_flush_flows",
			args: map[string]interface{}{"bridge_name": ""},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.FlushFlows(ctx, &platformv1.FlushFlowsRequest{})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "flush_flows unknown bridge", tool: "sdn_flush_flows",
			args: map[string]interface{}{"bridge_name": "nope"},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.FlushFlows(ctx, &platformv1.FlushFlowsRequest{BridgeId: "nope"})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "get_flow_stats unknown bridge", tool: "sdn_get_flow_stats",
			args: map[string]interface{}{"bridge_name": "nope", "flow_id": ovs.FlowID(1)},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: "nope", FlowId: ovs.FlowID(1)})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "get_flow_stats malformed flow id", tool: "sdn_get_flow_stats",
			args: map[string]interface{}{"bridge_name": "br0", "flow_id": "not-a-flow"},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "not-a-flow"})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "create_vlan unknown bridge", tool: "sdn_create_vlan",
			args: map[string]interface{}{"bridge_name": "nope", "vlan_id": float64(100)},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
					Config: &platformv1.VLANConfig{BridgeId: "nope", VlanId: 100},
				})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "create_vlan out of range", tool: "sdn_create_vlan",
			args: map[string]interface{}{"bridge_name": "br0", "vlan_id": float64(4096)},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
					Config: &platformv1.VLANConfig{BridgeId: "br0", VlanId: 4096},
				})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "delete_vlan unknown vlan", tool: "sdn_delete_vlan",
			args: map[string]interface{}{"bridge_name": "br0", "vlan_id": float64(200)},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 200})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "list_vlans empty bridge", tool: "sdn_list_vlans",
			args: map[string]interface{}{"bridge_name": ""},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.ListVLANs(ctx, &platformv1.ListVLANsRequest{})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "get_port_stats unknown port", tool: "sdn_get_port_stats",
			args: map[string]interface{}{"bridge_name": "br0", "port_name": "nope"},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.GetPortStats(ctx, &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "nope"})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "get_port_stats empty port", tool: "sdn_get_port_stats",
			args: map[string]interface{}{"bridge_name": "br0", "port_name": ""},
			grpc: func(ctx context.Context, s *SDNService) error {
				_, err := s.GetPortStats(ctx, &platformv1.GetPortStatsRequest{BridgeId: "br0"})
				return err
			},
			want: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdnService, _, registry := newSDNParityFixture(t)
			ctx := context.Background()

			grpcErr := tt.grpc(ctx, sdnService)
			_, mcpErr := registry.ExecuteTool(ctx, tt.tool, tt.args)

			require.Error(t, grpcErr)
			require.Error(t, mcpErr)
			assert.Equal(t, tt.want, status.Code(grpcErr), "gRPC: %v", grpcErr)
			assert.Equal(t, status.Code(grpcErr), status.Code(mcpErr), "MCP: %v", mcpErr)
		})
	}
}

// TestSDNMCPHasNoTenantScope records that SDN objects carry no tenant on
// either transport: a caller bound to tenant B lists and removes the VLAN a
// tenant A caller created, on gRPC exactly as on MCP. Tenancy is an open
// question for the SDN service, not something the MCP layer may invent.
func TestSDNMCPHasNoTenantScope(t *testing.T) {
	sdnService, _, registry := newSDNParityFixture(t)
	tenantA := grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-a"})
	tenantB := grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-b"})

	_, err := sdnService.CreateVLAN(tenantA, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{BridgeId: "br0", VlanId: 300, Name: "tenant-a"},
	})
	require.NoError(t, err)

	grpcList, err := sdnService.ListVLANs(tenantB, &platformv1.ListVLANsRequest{BridgeId: "br0"})
	require.NoError(t, err)
	assert.Len(t, grpcList.GetVlans(), 1, "gRPC shows tenant A's VLAN to tenant B")

	mcpList, err := registry.ExecuteTool(tenantB, "sdn_list_vlans", map[string]interface{}{"bridge_name": "br0"})
	require.NoError(t, err)
	assert.Len(t, mcpList.(map[string]interface{})["vlans"], 1, "MCP shows tenant A's VLAN to tenant B")

	_, err = registry.ExecuteTool(tenantB, "sdn_delete_vlan", map[string]interface{}{
		"bridge_name": "br0",
		"vlan_id":     float64(300),
	})
	require.NoError(t, err)
	assert.Empty(t, sdnService.vlans, "tenant B removed tenant A's VLAN")
}

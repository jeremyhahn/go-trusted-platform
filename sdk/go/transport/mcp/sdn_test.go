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
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestSDNMCP_CLIMethodsMapped pins the tool behind every SDNService method
// the platformctl sdn commands call, so none falls back to Unimplemented.
func TestSDNMCP_CLIMethodsMapped(t *testing.T) {
	want := map[string]string{
		platformv1.SDNService_CreateBridge_FullMethodName:      "sdn_create_bridge",
		platformv1.SDNService_DeleteBridge_FullMethodName:      "sdn_delete_bridge",
		platformv1.SDNService_GetBridge_FullMethodName:         "sdn_list_bridges",
		platformv1.SDNService_ListBridges_FullMethodName:       "sdn_list_bridges",
		platformv1.SDNService_AddPort_FullMethodName:           "sdn_add_port",
		platformv1.SDNService_DeletePort_FullMethodName:        "sdn_delete_port",
		platformv1.SDNService_GetPort_FullMethodName:           "sdn_get_port_state",
		platformv1.SDNService_SetPortState_FullMethodName:      "sdn_set_port_state",
		platformv1.SDNService_GetPortStats_FullMethodName:      "sdn_get_port_stats",
		platformv1.SDNService_AddFlow_FullMethodName:           "sdn_add_flow",
		platformv1.SDNService_DeleteFlow_FullMethodName:        "sdn_delete_flow",
		platformv1.SDNService_ListFlows_FullMethodName:         "sdn_list_flows",
		platformv1.SDNService_FlushFlows_FullMethodName:        "sdn_flush_flows",
		platformv1.SDNService_CreateVLAN_FullMethodName:        "sdn_create_vlan",
		platformv1.SDNService_DeleteVLAN_FullMethodName:        "sdn_delete_vlan",
		platformv1.SDNService_ListVLANs_FullMethodName:         "sdn_list_vlans",
		platformv1.SDNService_ApplyPolicy_FullMethodName:       "sdn_apply_policy",
		platformv1.SDNService_GetPolicy_FullMethodName:         "sdn_get_policy",
		platformv1.SDNService_ListPolicies_FullMethodName:      "sdn_list_policies",
		platformv1.SDNService_ListNetworkZones_FullMethodName:  "gateway_zone_list",
		platformv1.SDNService_CreateNetworkZone_FullMethodName: "gateway_zone_create",
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: "gateway_zone_update",
		platformv1.SDNService_DeleteNetworkZone_FullMethodName: "gateway_zone_delete",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s maps to %q, want %q", method, got, tool)
		}
	}
}

func TestSDNMCP_SetPortState_RoundTrip(t *testing.T) {
	reply := &platformv1.SetPortStateResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"sdn_set_port_state": map[string]interface{}{
			"success": true,
			"port":    map[string]interface{}{"id": "eth1", "bridge_id": "br0"},
		},
	}, platformv1.SDNService_SetPortState_FullMethodName, &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "eth1", AdminState: "down",
		IngressRate: 1 << 60, IngressBurst: 2, EgressRate: 3, EgressBurst: 4,
	}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	args := calls[0].Arguments
	if calls[0].Name != "sdn_set_port_state" || args["bridge_name"] != "br0" ||
		args["port_name"] != "eth1" || args["state"] != "down" {
		t.Errorf("call = %+v", calls[0])
	}
	// A uint64 rate past 2^53 survives as a decimal string.
	if args["ingress_rate"] != "1152921504606846976" || args["ingress_burst"] != "2" ||
		args["egress_rate"] != "3" || args["egress_burst"] != "4" {
		t.Errorf("rates = %+v", args)
	}
	if reply.GetPort().GetId() != "eth1" || reply.GetPort().GetBridgeId() != "br0" {
		t.Errorf("port = %+v", reply.GetPort())
	}
}

func TestSDNMCP_SetPortState_WrongRequestType(t *testing.T) {
	calls, err := invokePhase35(t, nil, platformv1.SDNService_SetPortState_FullMethodName,
		&platformv1.GetPortRequest{}, &platformv1.SetPortStateResponse{})
	requireCode(t, err, codes.InvalidArgument)
	if len(calls) != 0 {
		t.Errorf("a refused request reached the tool: %+v", calls)
	}
}

func TestSDNMCP_GetPort_PlacesBarePort(t *testing.T) {
	reply := &platformv1.GetPortResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"sdn_get_port_state": map[string]interface{}{"id": "eth1", "status": 1},
	}, platformv1.SDNService_GetPort_FullMethodName,
		&platformv1.GetPortRequest{BridgeId: "br0", PortId: "eth1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["bridge_name"] != "br0" || calls[0].Arguments["port_name"] != "eth1" {
		t.Errorf("call = %+v", calls[0])
	}
	if reply.GetPort().GetId() != "eth1" || reply.GetPort().GetStatus() != platformv1.PortStatus(1) {
		t.Errorf("port = %+v", reply.GetPort())
	}
}

func TestSDNMCP_GetPortStats_PlacesBareStats(t *testing.T) {
	reply := &platformv1.GetPortStatsResponse{}
	_, err := invokePhase35(t, map[string]interface{}{
		"sdn_get_port_stats": map[string]interface{}{"packets_received": 7},
	}, platformv1.SDNService_GetPortStats_FullMethodName,
		&platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "eth1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if reply.GetStats().GetPacketsReceived() != 7 {
		t.Errorf("stats = %+v", reply.GetStats())
	}
}

func TestSDNMCP_GetBridge(t *testing.T) {
	const br0UUID, br1UUID = "6f1c2a40-0000-4000-8000-000000000000", "9b7e3d51-0000-4000-8000-000000000001"
	results := map[string]interface{}{
		"sdn_list_bridges": map[string]interface{}{"bridges": []interface{}{
			map[string]interface{}{"id": br0UUID, "config": map[string]interface{}{"name": "br0"}},
			map[string]interface{}{"id": br1UUID, "config": map[string]interface{}{"name": "br1"}},
		}},
	}

	found := []struct {
		name, id, wantUUID, wantName string
	}{
		{"by UUID", br0UUID, br0UUID, "br0"},
		{"by name", "br1", br1UUID, "br1"},
	}
	for _, tt := range found {
		t.Run(tt.name, func(t *testing.T) {
			reply := &platformv1.GetBridgeResponse{}
			_, err := invokePhase35(t, results, platformv1.SDNService_GetBridge_FullMethodName,
				&platformv1.GetBridgeRequest{Id: tt.id}, reply)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if reply.GetBridge().GetId() != tt.wantUUID || reply.GetBridge().GetConfig().GetName() != tt.wantName {
				t.Errorf("bridge = %+v", reply.GetBridge())
			}
		})
	}

	t.Run("not found", func(t *testing.T) {
		_, err := invokePhase35(t, results, platformv1.SDNService_GetBridge_FullMethodName,
			&platformv1.GetBridgeRequest{Id: "br9"}, &platformv1.GetBridgeResponse{})
		requireCode(t, err, codes.NotFound)
	})
}

// TestSDNMCP_ArgsReachTool checks each builder sends the tool's argument
// names, mapping the gRPC bridge and port IDs to bridge_name and port_name.
func TestSDNMCP_ArgsReachTool(t *testing.T) {
	tests := []struct {
		name   string
		method string
		req    interface{}
		want   map[string]interface{}
	}{
		{
			name:   "create bridge",
			method: platformv1.SDNService_CreateBridge_FullMethodName,
			req: &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
				Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS, Labels: map[string]string{"a": "b"},
			}},
			want: map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "delete bridge",
			method: platformv1.SDNService_DeleteBridge_FullMethodName,
			req:    &platformv1.DeleteBridgeRequest{Id: "br0"},
			want:   map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "add port",
			method: platformv1.SDNService_AddPort_FullMethodName,
			req: &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{
				Name: "eth1", Type: platformv1.PortType_PORT_TYPE_INTERNAL,
			}},
			want: map[string]interface{}{"bridge_name": "br0", "port_name": "eth1", "port_type": "internal"},
		},
		{
			name:   "delete port",
			method: platformv1.SDNService_DeletePort_FullMethodName,
			req:    &platformv1.DeletePortRequest{BridgeId: "br0", PortId: "eth1"},
			want:   map[string]interface{}{"bridge_name": "br0", "port_name": "eth1"},
		},
		{
			name:   "add flow",
			method: platformv1.SDNService_AddFlow_FullMethodName,
			req:    &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "br0"}},
			want:   map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "delete flow",
			method: platformv1.SDNService_DeleteFlow_FullMethodName,
			req:    &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "f1"},
			want:   map[string]interface{}{"bridge_name": "br0", "flow_id": "f1"},
		},
		{
			name:   "list flows",
			method: platformv1.SDNService_ListFlows_FullMethodName,
			req:    &platformv1.ListFlowsRequest{BridgeId: "br0"},
			want:   map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "flush flows",
			method: platformv1.SDNService_FlushFlows_FullMethodName,
			req:    &platformv1.FlushFlowsRequest{BridgeId: "br0"},
			want:   map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "create vlan",
			method: platformv1.SDNService_CreateVLAN_FullMethodName,
			req: &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{
				BridgeId: "br0", VlanId: 42, Name: "lab",
			}},
			want: map[string]interface{}{"bridge_name": "br0", "vlan_id": float64(42), "name": "lab"},
		},
		{
			name:   "delete vlan",
			method: platformv1.SDNService_DeleteVLAN_FullMethodName,
			req:    &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 42},
			want:   map[string]interface{}{"bridge_name": "br0", "vlan_id": float64(42)},
		},
		{
			name:   "list vlans",
			method: platformv1.SDNService_ListVLANs_FullMethodName,
			req:    &platformv1.ListVLANsRequest{BridgeId: "br0"},
			want:   map[string]interface{}{"bridge_name": "br0"},
		},
		{
			name:   "list policies",
			method: platformv1.SDNService_ListPolicies_FullMethodName,
			req:    &platformv1.ListPoliciesRequest{Type: "acl", TargetId: "br0"},
			want:   map[string]interface{}{"type": "acl", "target_id": "br0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{}, tt.method, tt.req, nil)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			got := calls[0].Arguments
			if len(got) != len(tt.want) {
				t.Errorf("arguments = %+v, want %+v", got, tt.want)
			}
			for key, value := range tt.want {
				if got[key] != value {
					t.Errorf("%s = %v, want %v", key, got[key], value)
				}
			}
		})
	}
}

// TestSDNMCP_AddFlowCarriesFlowBody checks that a flow's table, match,
// actions and timeouts reach sdn_add_flow under their proto names. Until #304
// the tool dropped them, so the SDK refused any flow that had them.
func TestSDNMCP_AddFlowCarriesFlowBody(t *testing.T) {
	req := &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{
		BridgeId:    "br0",
		Table:       platformv1.FlowTable_FLOW_TABLE_1,
		Priority:    100,
		Match:       &platformv1.FlowMatch{InPort: "1"},
		Actions:     []*platformv1.FlowAction{{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"}},
		IdleTimeout: 30,
	}}

	calls, err := invokePhase35(t, map[string]interface{}{}, platformv1.SDNService_AddFlow_FullMethodName, req, nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	want := map[string]interface{}{
		"bridge_name":  "br0",
		"table":        "FLOW_TABLE_1",
		"priority":     float64(100),
		"match":        map[string]interface{}{"in_port": "1"},
		"actions":      []interface{}{map[string]interface{}{"type": "FLOW_ACTION_OUTPUT", "port": "2"}},
		"idle_timeout": float64(30),
	}
	if got := calls[0].Arguments; !reflect.DeepEqual(got, want) {
		t.Errorf("arguments = %#v, want %#v", got, want)
	}
}

// TestSDNMCP_RefusesUncarriedFields checks a request field the tool has no
// argument for fails InvalidArgument, naming the field, before any call.
func TestSDNMCP_RefusesUncarriedFields(t *testing.T) {
	tests := []struct {
		name   string
		method string
		req    interface{}
		field  string
	}{
		{
			name:   "linux bridge",
			method: platformv1.SDNService_CreateBridge_FullMethodName,
			req: &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
				Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_LINUX,
			}},
			field: "config.type",
		},
		{
			name:   "bridge mtu",
			method: platformv1.SDNService_CreateBridge_FullMethodName,
			req:    &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br0", Mtu: 9000}},
			field:  "config.mtu",
		},
		{
			name:   "forced bridge delete",
			method: platformv1.SDNService_DeleteBridge_FullMethodName,
			req:    &platformv1.DeleteBridgeRequest{Id: "br0", Force: true},
			field:  "force",
		},
		{
			name:   "bridge selector",
			method: platformv1.SDNService_ListBridges_FullMethodName,
			req:    &platformv1.ListBridgesRequest{Selector: &platformv1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}},
			field:  "selector",
		},
		{
			name:   "port vlan",
			method: platformv1.SDNService_AddPort_FullMethodName,
			req: &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{
				Name: "eth1", Vlan: 10, Mtu: 1500,
			}},
			field: "config.mtu",
		},
		{
			name:   "flow table filter",
			method: platformv1.SDNService_ListFlows_FullMethodName,
			req:    &platformv1.ListFlowsRequest{BridgeId: "br0", Table: 1},
			field:  "table",
		},
		{
			name:   "flush one table",
			method: platformv1.SDNService_FlushFlows_FullMethodName,
			req:    &platformv1.FlushFlowsRequest{BridgeId: "br0", Table: 1},
			field:  "table",
		},
		{
			name:   "vlan ports",
			method: platformv1.SDNService_CreateVLAN_FullMethodName,
			req: &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{
				BridgeId: "br0", VlanId: 42, Ports: []string{"eth1"},
			}},
			field: "config.ports",
		},
		{
			name:   "vlan selector",
			method: platformv1.SDNService_ListVLANs_FullMethodName,
			req:    &platformv1.ListVLANsRequest{BridgeId: "br0", Selector: &platformv1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}},
			field:  "selector",
		},
		{
			name:   "policy pagination",
			method: platformv1.SDNService_ListPolicies_FullMethodName,
			req:    &platformv1.ListPoliciesRequest{Pagination: &platformv1.PaginationRequest{PageSize: 5}},
			field:  "pagination",
		},
		{
			name:   "zone omit",
			method: platformv1.SDNService_CreateNetworkZone_FullMethodName,
			req:    &platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{Name: "lab", Omit: true}},
			field:  "config.omit",
		},
		{
			name:   "zone rename",
			method: platformv1.SDNService_UpdateNetworkZone_FullMethodName,
			req: &platformv1.UpdateNetworkZoneRequest{
				Name: "lab", Config: &platformv1.NetworkZoneConfig{Name: "other"},
			},
			field: "config.name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{}, tt.method, tt.req, nil)
			requireCode(t, err, codes.InvalidArgument)
			want := ErrFieldNotSupported{Method: tt.method, Field: tt.field}.Error()
			if status.Convert(err).Message() != want {
				t.Errorf("message = %q, want %q", status.Convert(err).Message(), want)
			}
			if len(calls) != 0 {
				t.Errorf("a refused request reached the tool: %+v", calls)
			}
		})
	}
}

// TestSDNMCP_BuildersRejectWrongRequestType covers every SDN builder's
// type check, which keeps a mis-routed message from being sent half-read.
func TestSDNMCP_BuildersRejectWrongRequestType(t *testing.T) {
	for _, method := range []string{
		platformv1.SDNService_CreateBridge_FullMethodName,
		platformv1.SDNService_DeleteBridge_FullMethodName,
		platformv1.SDNService_GetBridge_FullMethodName,
		platformv1.SDNService_ListBridges_FullMethodName,
		platformv1.SDNService_AddPort_FullMethodName,
		platformv1.SDNService_DeletePort_FullMethodName,
		platformv1.SDNService_GetPort_FullMethodName,
		platformv1.SDNService_SetPortState_FullMethodName,
		platformv1.SDNService_GetPortStats_FullMethodName,
		platformv1.SDNService_AddFlow_FullMethodName,
		platformv1.SDNService_DeleteFlow_FullMethodName,
		platformv1.SDNService_ListFlows_FullMethodName,
		platformv1.SDNService_FlushFlows_FullMethodName,
		platformv1.SDNService_CreateVLAN_FullMethodName,
		platformv1.SDNService_DeleteVLAN_FullMethodName,
		platformv1.SDNService_ListVLANs_FullMethodName,
		platformv1.SDNService_ApplyPolicy_FullMethodName,
		platformv1.SDNService_ListPolicies_FullMethodName,
		platformv1.SDNService_CreateNetworkZone_FullMethodName,
		platformv1.SDNService_UpdateNetworkZone_FullMethodName,
	} {
		_, err := mcpArgBuilders[method](&platformv1.PaginationRequest{})
		if !errors.Is(err, ErrUnexpectedArgsType{Method: method}) {
			t.Errorf("%s: err = %v, want ErrUnexpectedArgsType", method, err)
		}
	}
}

// TestSDNMCP_DecodersRejectWrongReplyType covers every SDN decoder's type
// check; through Invoke the mismatch is Internal.
func TestSDNMCP_DecodersRejectWrongReplyType(t *testing.T) {
	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.SDNService_GetPort_FullMethodName:           decodeSDNGetPortResult,
		platformv1.SDNService_GetPortStats_FullMethodName:      decodeSDNGetPortStatsResult,
		platformv1.SDNService_ApplyPolicy_FullMethodName:       mcpReplyDecoders[platformv1.SDNService_ApplyPolicy_FullMethodName],
		platformv1.SDNService_GetPolicy_FullMethodName:         mcpReplyDecoders[platformv1.SDNService_GetPolicy_FullMethodName],
		platformv1.SDNService_ListPolicies_FullMethodName:      mcpReplyDecoders[platformv1.SDNService_ListPolicies_FullMethodName],
		platformv1.SDNService_ListNetworkZones_FullMethodName:  decodeSDNListNetworkZonesResult,
		platformv1.SDNService_CreateNetworkZone_FullMethodName: decodeSDNCreateNetworkZoneResult,
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: decodeSDNUpdateNetworkZoneResult,
	} {
		err := decode(map[string]interface{}{}, &platformv1.PaginationRequest{})
		if !errors.Is(err, ErrUnexpectedReplyType{Method: method}) {
			t.Errorf("%s: err = %v, want ErrUnexpectedReplyType", method, err)
		}
	}

	const method = platformv1.SDNService_GetBridge_FullMethodName
	if err := decodeSDNGetBridgeResult(&platformv1.PaginationRequest{}, nil, &platformv1.GetBridgeResponse{}); !errors.Is(err, ErrUnexpectedArgsType{Method: method}) {
		t.Errorf("GetBridge args: err = %v", err)
	}
	if err := decodeSDNGetBridgeResult(&platformv1.GetBridgeRequest{}, nil, &platformv1.PaginationRequest{}); !errors.Is(err, ErrUnexpectedReplyType{Method: method}) {
		t.Errorf("GetBridge reply: err = %v", err)
	}

	_, err := invokePhase35(t, map[string]interface{}{"sdn_get_port_state": map[string]interface{}{}},
		platformv1.SDNService_GetPort_FullMethodName, &platformv1.GetPortRequest{}, &platformv1.PaginationRequest{})
	requireCode(t, err, codes.Internal)
}

func TestSDNMCP_DecodersRejectMalformedResult(t *testing.T) {
	for _, method := range []string{
		platformv1.SDNService_GetPort_FullMethodName,
		platformv1.SDNService_GetPortStats_FullMethodName,
	} {
		reply := map[string]interface{}{
			platformv1.SDNService_GetPort_FullMethodName:      &platformv1.GetPortResponse{},
			platformv1.SDNService_GetPortStats_FullMethodName: &platformv1.GetPortStatsResponse{},
		}[method]
		if err := mcpReplyDecoders[method]("not an object", reply); err == nil {
			t.Errorf("%s decoded a string result", method)
		}
	}
	if err := decodeSDNGetBridgeResult(&platformv1.GetBridgeRequest{}, "not an object", &platformv1.GetBridgeResponse{}); err == nil {
		t.Error("GetBridge decoded a string result")
	}
}

func TestDecodeStatus(t *testing.T) {
	if err := decodeStatus(nil); err != nil {
		t.Errorf("decodeStatus(nil) = %v", err)
	}
	requireCode(t, decodeStatus(ErrBridgeNotFound{ID: "br0"}), codes.NotFound)
	requireCode(t, decodeStatus(ErrUnexpectedReplyType{Method: "m"}), codes.Internal)
}

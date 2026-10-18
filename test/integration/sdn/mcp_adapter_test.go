//go:build integration

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
	"encoding/json"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// decodeAsMCPServer decodes sdn_add_flow arguments the way platformd's MCP
// provider does: every argument except bridge_name is the FlowConfig body,
// re-encoded as JSON and decoded by protojson, which refuses unknown fields
// and unknown enum names.
func decodeAsMCPServer(t *testing.T, args map[string]interface{}) *platformv1.FlowConfig {
	t.Helper()
	flow := make(map[string]interface{}, len(args))
	for field, value := range args {
		if field != "bridge_name" {
			flow[field] = value
		}
	}
	body, err := json.Marshal(flow)
	if err != nil {
		t.Fatalf("marshal flow body: %v", err)
	}
	config := &platformv1.FlowConfig{}
	if err := protojson.Unmarshal(body, config); err != nil {
		t.Fatalf("server would refuse the flow body %s: %v", body, err)
	}
	return config
}

func TestMCPSDNFlowAddArgsDecodeAsFlowConfig(t *testing.T) {
	tests := map[string]FlowAddOptions{
		"default drop flow": DefaultFlowOptions("br-flow", "flow1"),
		"match and several actions": {
			BridgeID:    "br-flow",
			Table:       1,
			Priority:    200,
			IdleTimeout: 30,
			HardTimeout: 60,
			Match: FlowMatch{
				InPort: 3, DlType: 0x0800, DlVLAN: 10,
				DlSrc: "02:00:00:00:00:01", NwDst: "10.0.0.2", NwProto: 6, TpDst: 443,
			},
			Actions: []FlowAction{
				{Type: "strip_vlan"},
				{Type: "set_field", Field: "eth_dst", Value: "02:00:00:00:00:02"},
				{Type: "goto_table", TableID: 2},
				{Type: "output", Port: 4},
			},
		},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			args, err := mcpSDNFlowAddArgs(opts)
			if err != nil {
				t.Fatalf("mcpSDNFlowAddArgs: %v", err)
			}
			if got := args["bridge_name"]; got != opts.BridgeID {
				t.Errorf("bridge_name = %v, want %q", got, opts.BridgeID)
			}

			got := decodeAsMCPServer(t, args)
			want := flowConfigToProto(opts)
			want.BridgeId = ""
			if !proto.Equal(got, want) {
				t.Errorf("server decodes %v, want the FlowConfig the gRPC adapter sends %v", got, want)
			}
		})
	}
}

func TestMCPSDNFlowAddArgsUseToolArgumentNames(t *testing.T) {
	args, err := mcpSDNFlowAddArgs(DefaultFlowOptions("br-flow", "flow1"))
	if err != nil {
		t.Fatalf("mcpSDNFlowAddArgs: %v", err)
	}
	// The tool takes the flow flat beside bridge_name; a "flow" wrapper and
	// a bridge_id argument are not part of its schema.
	for _, refused := range []string{"flow", "bridge_id"} {
		if _, ok := args[refused]; ok {
			t.Errorf("args carry %q, which sdn_add_flow does not take: %v", refused, args)
		}
	}
	actions, ok := args["actions"].([]interface{})
	if !ok || len(actions) != 1 {
		t.Fatalf("actions = %#v, want one FlowAction object", args["actions"])
	}
	action, ok := actions[0].(map[string]interface{})
	if !ok || action["type"] != "FLOW_ACTION_DROP" {
		t.Errorf("action = %#v, want type FLOW_ACTION_DROP", actions[0])
	}
}

func TestMCPSDNFlowAddResponseCarriesServerFlowID(t *testing.T) {
	body := []byte(`{"success":true,"flow":{"id":"flow-0x2a","config":{"priority":100}}}`)
	var resp mcpSDNFlowAddResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode sdn_add_flow result: %v", err)
	}
	if resp.Flow.ID != "flow-0x2a" {
		t.Errorf("flow ID = %q, want the server-assigned flow-0x2a", resp.Flow.ID)
	}
}

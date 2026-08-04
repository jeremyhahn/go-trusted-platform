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

//go:build codec_msgpack

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the SDN surface
// between the platform SDK client and the daemon. The canonical contract is
// the platform.v1 protobuf messages themselves: the SDK QUIC transport adapter
// hands the generated pb request struct straight to the payload codec and the
// daemon decodes into the SAME pb type (and vice versa for responses). Every
// message is round-tripped through the codec (encode SDK-side shape -> decode
// daemon-side shape) and compared with proto.Equal so a codec or field-shape
// regression on either side fails here first. These are the twelve SDN
// operations the SDK QUIC adapter maps (grpcMethodToOpcodeMap); before the
// pb-wire fix the daemon decoded flat structs whose Go field names did not
// match the pb Go field names, silently dropping every request field
// (CreateBridge Config.Name, AddPort BridgeId/Config.Name, AddFlow Config.*,
// SetPortState BridgeId/PortId/AdminState, ...).

func roundTripSDNWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quic.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quic.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

func TestQUICSDNWireCompatBridge(t *testing.T) {
	roundTripSDNWire(t,
		&platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
			Name:       "br0",
			Type:       platformv1.BridgeType_BRIDGE_TYPE_OVS,
			StpEnabled: true,
			Mtu:        1500,
			Labels:     map[string]string{"role": "trunk"},
			Options:    map[string]string{"fail_mode": "secure"},
		}},
		&platformv1.CreateBridgeRequest{})
	roundTripSDNWire(t,
		&platformv1.CreateBridgeResponse{
			Status: &platformv1.Status{Success: true, Message: "bridge created successfully"},
			Bridge: &platformv1.Bridge{Id: "uuid-br0", Config: &platformv1.BridgeConfig{Name: "br0"}},
		},
		&platformv1.CreateBridgeResponse{})

	roundTripSDNWire(t,
		&platformv1.DeleteBridgeRequest{Id: "br0", Force: true},
		&platformv1.DeleteBridgeRequest{})
	roundTripSDNWire(t,
		&platformv1.GetBridgeRequest{Id: "br0"},
		&platformv1.GetBridgeRequest{})
	roundTripSDNWire(t,
		&platformv1.GetBridgeResponse{Bridge: &platformv1.Bridge{Id: "uuid-br0", Config: &platformv1.BridgeConfig{Name: "br0"}}},
		&platformv1.GetBridgeResponse{})
	roundTripSDNWire(t,
		&platformv1.ListBridgesRequest{Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 25}},
		&platformv1.ListBridgesRequest{})
	roundTripSDNWire(t,
		&platformv1.ListBridgesResponse{Bridges: []*platformv1.Bridge{
			{Id: "uuid-br0", Config: &platformv1.BridgeConfig{Name: "br0"}},
		}},
		&platformv1.ListBridgesResponse{})
}

func TestQUICSDNWireCompatPort(t *testing.T) {
	roundTripSDNWire(t,
		&platformv1.AddPortRequest{
			BridgeId: "br0",
			Config:   &platformv1.PortConfig{Name: "eth0", Vlan: 100},
		},
		&platformv1.AddPortRequest{})
	roundTripSDNWire(t,
		&platformv1.AddPortResponse{
			Status: &platformv1.Status{Success: true},
			Port:   &platformv1.Port{Id: "uuid-eth0", Config: &platformv1.PortConfig{Name: "eth0"}},
		},
		&platformv1.AddPortResponse{})

	roundTripSDNWire(t,
		&platformv1.DeletePortRequest{BridgeId: "br0", PortId: "eth0"},
		&platformv1.DeletePortRequest{})
	roundTripSDNWire(t,
		&platformv1.GetPortRequest{BridgeId: "br0", PortId: "eth0"},
		&platformv1.GetPortRequest{})
	roundTripSDNWire(t,
		&platformv1.GetPortResponse{Port: &platformv1.Port{Id: "uuid-eth0", Config: &platformv1.PortConfig{Name: "eth0"}}},
		&platformv1.GetPortResponse{})
	roundTripSDNWire(t,
		&platformv1.ListPortsRequest{BridgeId: "br0"},
		&platformv1.ListPortsRequest{})
	roundTripSDNWire(t,
		&platformv1.ListPortsResponse{Ports: []*platformv1.Port{
			{Id: "uuid-eth0", Config: &platformv1.PortConfig{Name: "eth0"}},
		}},
		&platformv1.ListPortsResponse{})

	roundTripSDNWire(t,
		&platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "eth0", AdminState: "up"},
		&platformv1.SetPortStateRequest{})
	roundTripSDNWire(t,
		&platformv1.SetPortStateResponse{
			Status: &platformv1.Status{Success: true},
			Port:   &platformv1.Port{Id: "uuid-eth0"},
		},
		&platformv1.SetPortStateResponse{})
}

func TestQUICSDNWireCompatFlow(t *testing.T) {
	roundTripSDNWire(t,
		&platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
		}},
		&platformv1.AddFlowRequest{})
	roundTripSDNWire(t,
		&platformv1.AddFlowResponse{
			Status: &platformv1.Status{Success: true},
			Flow:   &platformv1.Flow{Id: "flow-1"},
		},
		&platformv1.AddFlowResponse{})

	roundTripSDNWire(t,
		&platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "flow-1"},
		&platformv1.DeleteFlowRequest{})
	roundTripSDNWire(t,
		&platformv1.ListFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable_FLOW_TABLE_0},
		&platformv1.ListFlowsRequest{})
	roundTripSDNWire(t,
		&platformv1.ListFlowsResponse{Flows: []*platformv1.Flow{{Id: "flow-1"}}},
		&platformv1.ListFlowsResponse{})
}

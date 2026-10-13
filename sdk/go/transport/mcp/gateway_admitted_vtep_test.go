// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

func admittedVTEP(vtep string) *platformv1.GatewayAdmittedVTEP {
	return &platformv1.GatewayAdmittedVTEP{
		Vtep: vtep, DeviceId: 42, HostId: "host-42", Serial: "SN42", Hostname: "edge-42",
		AllocationId: "alloc-42", BaselineSource: "signed", ProfileId: 9,
		VerdictAt: timestamppb.New(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)),
	}
}

// asToolResult renders v the way the daemon's MCP server does: encoding/json
// over the value its tool returned, decoded by the client as generic JSON.
func asToolResult(t *testing.T, v interface{}) interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal tool result: %v", err)
	}
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}
	return out
}

func sdkGatewayOverMCP(t *testing.T, tool string, result interface{}, calls *[]toolCall) *sdkgateway.Client {
	t.Helper()
	a := provisioningTestServer(t, map[string]interface{}{tool: asToolResult(t, result)}, calls)
	return sdkgateway.NewClientFromGRPC(platformv1.NewGatewayServiceClient(a.Connection()))
}

// The SDK's admitted-VTEP reads used to fail with Unimplemented over MCP:
// neither method had a tool. The single-VTEP tool answers the bare record,
// so a generic decode into the reply would also have left it empty.
func TestGatewayAdmittedVTEP_SDKOverMCP(t *testing.T) {
	var calls []toolCall
	client := sdkGatewayOverMCP(t, "gateway_admitted_vtep", admittedVTEP("198.51.100.10"), &calls)

	got, err := client.GetAdmittedVTEP(context.Background(), "gw-01", "198.51.100.10")
	if err != nil {
		t.Fatalf("GetAdmittedVTEP: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "gateway_admitted_vtep" {
		t.Fatalf("calls = %+v, want a single gateway_admitted_vtep", calls)
	}
	wantArgs := map[string]interface{}{"gateway_id": "gw-01", "vtep": "198.51.100.10"}
	if !reflect.DeepEqual(calls[0].Arguments, wantArgs) {
		t.Fatalf("tool arguments = %v, want %v", calls[0].Arguments, wantArgs)
	}
	if !proto.Equal(got, admittedVTEP("198.51.100.10")) {
		t.Fatalf("reply = %v, want %v", got, admittedVTEP("198.51.100.10"))
	}
}

func TestListGatewayAdmittedVTEPs_SDKOverMCP(t *testing.T) {
	var calls []toolCall
	client := sdkGatewayOverMCP(t, "gateway_admitted_vteps", map[string]interface{}{
		"vteps": []interface{}{admittedVTEP("198.51.100.10"), &platformv1.GatewayAdmittedVTEP{Vtep: "198.51.100.11"}},
		"count": 2,
	}, &calls)

	got, err := client.ListAdmittedVTEPs(context.Background(), "gw-01")
	if err != nil {
		t.Fatalf("ListAdmittedVTEPs: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "gateway_admitted_vteps" {
		t.Fatalf("calls = %+v, want a single gateway_admitted_vteps", calls)
	}
	if calls[0].Arguments["gateway_id"] != "gw-01" {
		t.Fatalf("tool arguments = %v, want gateway_id gw-01", calls[0].Arguments)
	}
	if len(got) != 2 || !proto.Equal(got[0], admittedVTEP("198.51.100.10")) || got[1].GetVtep() != "198.51.100.11" {
		t.Fatalf("reply = %v", got)
	}
}

func TestGatewayAdmittedVTEP_MCPDecodeRejectsWrongReplyType(t *testing.T) {
	err := decodeGatewayAdmittedVTEPResult(map[string]interface{}{"vtep": "198.51.100.10"},
		&platformv1.ListGatewayAdmittedVTEPsResponse{})
	if _, ok := err.(ErrUnexpectedReplyType); !ok {
		t.Fatalf("err = %v, want ErrUnexpectedReplyType", err)
	}
}

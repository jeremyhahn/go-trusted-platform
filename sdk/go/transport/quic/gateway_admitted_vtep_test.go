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

//go:build codec_msgpack

package quic

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

var verdictAt = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func admittedWire(vtep string) *quicapi.GatewayAdmittedVTEPInfo {
	return &quicapi.GatewayAdmittedVTEPInfo{
		VTEP: vtep, DeviceID: 42, HostID: "host-42", Serial: "SN42", Hostname: "edge-42",
		AllocationID: "alloc-42", BaselineSource: "signed", ProfileID: 9, VerdictAt: verdictAt.Unix(),
	}
}

func admittedPB(vtep string) *platformv1.GatewayAdmittedVTEP {
	return &platformv1.GatewayAdmittedVTEP{
		Vtep: vtep, DeviceId: 42, HostId: "host-42", Serial: "SN42", Hostname: "edge-42",
		AllocationId: "alloc-42", BaselineSource: "signed", ProfileId: 9, VerdictAt: timestamppb.New(verdictAt),
	}
}

// sdkGatewayOverQUIC is the SDK gateway client a CLI caller gets for
// --protocol quic, wired to a sender that answers like the daemon.
func sdkGatewayOverQUIC(t *testing.T, wireResp interface{}) (*sdkgateway.Client, *recordingSender) {
	t.Helper()
	respPayload, err := quicapi.EncodePayload(wireResp)
	if err != nil {
		t.Fatalf("encode daemon response: %v", err)
	}
	sender := &recordingSender{respPayload: respPayload}
	conn := newConnWithSender(t, sender)
	return sdkgateway.NewClientFromGRPC(platformv1.NewGatewayServiceClient(conn)), sender
}

// The SDK's admitted-VTEP reads used to fail with Unimplemented over QUIC:
// neither method had an opcode. A by-name decode would also have dropped
// every field whose wire and pb names differ, and the verdict time.
func TestGatewayAdmittedVTEP_SDKOverQUIC(t *testing.T) {
	client, sender := sdkGatewayOverQUIC(t, &quicapi.GatewayAdmittedVTEPResponse{VTEP: admittedWire("198.51.100.10")})

	got, err := client.GetAdmittedVTEP(context.Background(), "gw-01", "198.51.100.10")
	if err != nil {
		t.Fatalf("GetAdmittedVTEP: %v", err)
	}
	if sender.rawOpcode != quicapi.OpGatewayCategory || sender.rawPayload[0] != quicapi.OpGatewayAdmittedVTEP {
		t.Fatalf("sent opcode 0x%02X sub 0x%02X, want the gateway category and OpGatewayAdmittedVTEP",
			sender.rawOpcode, sender.rawPayload[0])
	}
	var req quicapi.GatewayAdmittedVTEPRequest
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &req); err != nil {
		t.Fatalf("daemon-side decode: %v", err)
	}
	if req.GatewayID != "gw-01" || req.VTEP != "198.51.100.10" {
		t.Fatalf("the daemon must see the gateway and VTEP the caller named, got %+v", req)
	}
	if !proto.Equal(got, admittedPB("198.51.100.10")) {
		t.Fatalf("reply = %v, want %v", got, admittedPB("198.51.100.10"))
	}
}

func TestListGatewayAdmittedVTEPs_SDKOverQUIC(t *testing.T) {
	client, sender := sdkGatewayOverQUIC(t, &quicapi.GatewayListAdmittedVTEPsResponse{
		VTEPs: []*quicapi.GatewayAdmittedVTEPInfo{admittedWire("198.51.100.10"), {VTEP: "198.51.100.11"}},
		Count: 2,
	})

	got, err := client.ListAdmittedVTEPs(context.Background(), "gw-01")
	if err != nil {
		t.Fatalf("ListAdmittedVTEPs: %v", err)
	}
	if sender.rawPayload[0] != quicapi.OpGatewayListAdmittedVTEPs {
		t.Fatalf("sub-opcode 0x%02X, want OpGatewayListAdmittedVTEPs", sender.rawPayload[0])
	}
	var req quicapi.GatewayListAdmittedVTEPsRequest
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &req); err != nil {
		t.Fatalf("daemon-side decode: %v", err)
	}
	if req.GatewayID != "gw-01" {
		t.Fatalf("the daemon must see the gateway the caller named, got %+v", req)
	}
	if len(got) != 2 || !proto.Equal(got[0], admittedPB("198.51.100.10")) {
		t.Fatalf("reply = %v", got)
	}
	if got[1].GetVerdictAt() != nil {
		t.Fatal("a VTEP with no verdict time must carry none, not the epoch")
	}
}

func TestGatewayAdmittedVTEP_QUICRefusesMistypedMessages(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)
	err := conn.Invoke(context.Background(), platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName,
		&platformv1.ListGatewayAdmittedVTEPsRequest{}, &platformv1.GetGatewayAdmittedVTEPResponse{})
	if status.Code(err) != codes.Internal || sender.rawCalls != 0 {
		t.Fatalf("a mistyped request must fail before the wire: code %v, sends %d", status.Code(err), sender.rawCalls)
	}

	conn = newConnWithSender(t, &recordingSender{respPayload: []byte{0xC1}})
	err = conn.Invoke(context.Background(), platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName,
		&platformv1.ListGatewayAdmittedVTEPsRequest{}, &platformv1.ListGatewayAdmittedVTEPsResponse{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a malformed response must be Internal, got %v", err)
	}
}

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
	"context"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var gatewayBGPMethods = map[string]string{
	platformv1.GatewayService_GetBGPStatus_FullMethodName:          "gateway_bgp_status",
	platformv1.GatewayService_ListBGPPeers_FullMethodName:          "gateway_bgp_peers",
	platformv1.GatewayService_AnnouncePrefix_FullMethodName:        "gateway_bgp_announce",
	platformv1.GatewayService_WithdrawPrefix_FullMethodName:        "gateway_bgp_withdraw",
	platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: "gateway_bgp_prefixes",
}

func TestGatewayBGPMCP_EveryMethodHasToolBuilderAndDecoder(t *testing.T) {
	for method, tool := range gatewayBGPMethods {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
		if _, has := mcpArgBuilders[method]; !has {
			t.Errorf("%s missing argument builder", method)
		}
		if _, has := mcpReplyDecoders[method]; !has {
			t.Errorf("%s missing reply decoder", method)
		}
	}
}

func TestGatewayBGPMCP_ReadVerbs(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"gateway_bgp_status": map[string]interface{}{
			"local_asn": float64(65001), "router_id": "10.0.0.1", "peer_count": float64(3),
			"established_peers": float64(2), "prefixes_announced": float64(5), "running": true,
		},
		"gateway_bgp_peers": map[string]interface{}{"peers": []interface{}{
			map[string]interface{}{
				"address": "10.0.0.2", "asn": float64(65002), "state": "established", "description": "upstream",
				"prefixes_received": float64(7), "prefixes_sent": float64(4), "established_at": gatewayTestTime,
			},
			map[string]interface{}{"address": "10.0.0.3", "asn": float64(65003), "state": "active"},
		}},
		"gateway_bgp_prefixes": map[string]interface{}{"prefixes": []interface{}{
			map[string]interface{}{"prefix": "203.0.113.0/24", "next_hop": "10.0.0.1", "announced_at": gatewayTestTime},
		}},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	statusResp := &platformv1.GetBGPStatusResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_GetBGPStatus_FullMethodName,
		&platformv1.GetBGPStatusRequest{}, statusResp); err != nil {
		t.Fatalf("GetBGPStatus: %v", err)
	}
	s := statusResp.GetStatus()
	if s.GetLocalAsn() != 65001 || s.GetRouterId() != "10.0.0.1" || s.GetPeerCount() != 3 ||
		s.GetEstablishedPeers() != 2 || s.GetPrefixesAnnounced() != 5 || !s.GetRunning() {
		t.Errorf("status = %+v", s)
	}

	peersResp := &platformv1.ListBGPPeersResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_ListBGPPeers_FullMethodName,
		&platformv1.ListBGPPeersRequest{}, peersResp); err != nil {
		t.Fatalf("ListBGPPeers: %v", err)
	}
	peers := peersResp.GetPeers()
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	up := peers[0]
	if up.GetAddress() != "10.0.0.2" || up.GetAsn() != 65002 || up.GetState() != "established" ||
		up.GetDescription() != "upstream" || up.GetPrefixesReceived() != 7 || up.GetPrefixesSent() != 4 {
		t.Errorf("peer = %+v", up)
	}
	if up.GetUptime().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Errorf("established = %v, want %s", up.GetUptime(), gatewayTestTime)
	}
	if peers[1].GetUptime() != nil {
		t.Errorf("a peer that is not established has uptime %v, want none", peers[1].GetUptime())
	}

	prefixesResp := &platformv1.ListAnnouncedPrefixesResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName,
		&platformv1.ListAnnouncedPrefixesRequest{}, prefixesResp); err != nil {
		t.Fatalf("ListAnnouncedPrefixes: %v", err)
	}
	prefixes := prefixesResp.GetPrefixes()
	if len(prefixes) != 1 || prefixes[0].GetPrefix() != "203.0.113.0/24" || prefixes[0].GetNextHop() != "10.0.0.1" ||
		prefixes[0].GetAnnouncedAt().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Errorf("prefixes = %+v", prefixes)
	}

	for i, call := range calls {
		if len(call.Arguments) != 0 {
			t.Errorf("call %d (%s) sent arguments %v, want none", i, call.Name, call.Arguments)
		}
	}
}

func TestGatewayBGPMCP_AnnounceAndWithdraw(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"gateway_bgp_announce": map[string]interface{}{"success": true},
		"gateway_bgp_withdraw": map[string]interface{}{"success": true},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	announceResp := &platformv1.AnnouncePrefixResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_AnnouncePrefix_FullMethodName,
		&platformv1.AnnouncePrefixRequest{Prefix: "203.0.113.0/24", NextHop: "10.0.0.1"}, announceResp); err != nil {
		t.Fatalf("AnnouncePrefix: %v", err)
	}
	withdrawResp := &platformv1.WithdrawPrefixResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_WithdrawPrefix_FullMethodName,
		&platformv1.WithdrawPrefixRequest{Prefix: "203.0.113.0/24"}, withdrawResp); err != nil {
		t.Fatalf("WithdrawPrefix: %v", err)
	}

	if len(calls) != 2 || calls[0].Name != "gateway_bgp_announce" || calls[1].Name != "gateway_bgp_withdraw" {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Arguments["prefix"] != "203.0.113.0/24" || calls[0].Arguments["next_hop"] != "10.0.0.1" {
		t.Errorf("announce sent %v, want the prefix and next hop", calls[0].Arguments)
	}
	if calls[1].Arguments["prefix"] != "203.0.113.0/24" {
		t.Errorf("withdraw sent %v, want the prefix", calls[1].Arguments)
	}
	if !announceResp.GetStatus().GetSuccess() || !withdrawResp.GetStatus().GetSuccess() {
		t.Errorf("replies = %+v / %+v, want success", announceResp, withdrawResp)
	}
}

func TestGatewayBGPMCP_BuildersRefuseTheWrongRequestType(t *testing.T) {
	for method := range gatewayBGPMethods {
		var wrongType ErrUnexpectedArgsType
		if _, err := mcpArgBuilders[method](&platformv1.GetNAT64StatusRequest{}); !errors.As(err, &wrongType) ||
			wrongType.Method != method {
			t.Errorf("%s: wrong request gave %v, want ErrUnexpectedArgsType naming the method", method, err)
		}
	}
}

func TestGatewayBGPMCP_DecodersRefuseTheWrongReplyAndMalformedResults(t *testing.T) {
	replies := map[string]interface{}{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:          &platformv1.GetBGPStatusResponse{},
		platformv1.GatewayService_ListBGPPeers_FullMethodName:          &platformv1.ListBGPPeersResponse{},
		platformv1.GatewayService_AnnouncePrefix_FullMethodName:        &platformv1.AnnouncePrefixResponse{},
		platformv1.GatewayService_WithdrawPrefix_FullMethodName:        &platformv1.WithdrawPrefixResponse{},
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: &platformv1.ListAnnouncedPrefixesResponse{},
	}
	for method, reply := range replies {
		decode := mcpReplyDecoders[method]

		var wrongType ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{}, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &wrongType) ||
			wrongType.Method != method {
			t.Errorf("%s: wrong reply gave %v, want ErrUnexpectedReplyType naming the method", method, err)
		}
		var unmarshal ErrUnmarshalFailed
		if err := decode("not an object", reply); !errors.As(err, &unmarshal) {
			t.Errorf("%s: wrong shape gave %v, want ErrUnmarshalFailed", method, err)
		}
		var marshal ErrMarshalFailed
		if err := decode(make(chan int), reply); !errors.As(err, &marshal) {
			t.Errorf("%s: unencodable result gave %v, want ErrMarshalFailed", method, err)
		}
	}
}

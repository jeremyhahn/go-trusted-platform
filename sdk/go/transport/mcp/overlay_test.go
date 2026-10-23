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
	"slices"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var overlayMethods = map[string]string{
	platformv1.OverlayService_GetOverlayStatus_FullMethodName: "overlay_status",
	platformv1.OverlayService_ListVTEPs_FullMethodName:        "overlay_vtep_list",
	platformv1.OverlayService_GetVTEP_FullMethodName:          "overlay_vtep_get",
	platformv1.OverlayService_ListVNIs_FullMethodName:         "overlay_vni_list",
	platformv1.OverlayService_CreateVNI_FullMethodName:        "overlay_vni_create",
	platformv1.OverlayService_DeleteVNI_FullMethodName:        "overlay_vni_delete",
	platformv1.OverlayService_ListTunnels_FullMethodName:      "overlay_tunnel_list",
	platformv1.OverlayService_GetTunnelStats_FullMethodName:   "overlay_tunnel_stats",
	platformv1.OverlayService_ListRemoteMACs_FullMethodName:   "overlay_mac_list",
	platformv1.OverlayService_ForgetMAC_FullMethodName:        "overlay_mac_forget",
}

func TestOverlayMCP_EveryMethodHasToolBuilderAndDecoder(t *testing.T) {
	for method, tool := range overlayMethods {
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

func TestOverlayMCP_StatusAndVTEPs(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"overlay_status": map[string]interface{}{
			"node_id": "node-1", "vtep_ip": "10.0.0.1", "controller_state": "running", "healthy": true,
			"underlay_mtu": float64(1500), "vxlan_port": float64(4789), "vni_count": float64(2),
			"vtep_count": float64(3), "remote_mac_count": float64(9), "tunnel_count": float64(4),
			"uptime_seconds": float64(60),
		},
		"overlay_vtep_list": map[string]interface{}{"vteps": []interface{}{
			map[string]interface{}{"node_id": "node-2", "ip": "10.0.0.2", "healthy": true, "last_seen": gatewayTestTime},
			map[string]interface{}{"node_id": "node-3", "ip": "10.0.0.3", "healthy": false, "last_seen": ""},
		}},
		"overlay_vtep_get": map[string]interface{}{
			"node_id": "node-2", "ip": "10.0.0.2", "healthy": true, "last_seen": gatewayTestTime,
			"vnis": []interface{}{float64(100), float64(200)}, "mac_count": float64(5),
			"bytes_sent": float64(1024), "bytes_recv": float64(2048),
		},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	statusResp := &platformv1.GetOverlayStatusResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_GetOverlayStatus_FullMethodName,
		&platformv1.GetOverlayStatusRequest{}, statusResp); err != nil {
		t.Fatalf("GetOverlayStatus: %v", err)
	}
	s := statusResp.GetStatus()
	if s.GetNodeId() != "node-1" || s.GetVtepIp() != "10.0.0.1" || !s.GetHealthy() || s.GetUnderlayMtu() != 1500 ||
		s.GetVxlanPort() != 4789 || s.GetVniCount() != 2 || s.GetVtepCount() != 3 ||
		s.GetRemoteMacCount() != 9 || s.GetTunnelCount() != 4 {
		t.Errorf("status = %+v", s)
	}

	listResp := &platformv1.ListVTEPsResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_ListVTEPs_FullMethodName,
		&platformv1.ListVTEPsRequest{}, listResp); err != nil {
		t.Fatalf("ListVTEPs: %v", err)
	}
	vteps := listResp.GetVteps()
	if len(vteps) != 2 || vteps[0].GetNodeId() != "node-2" || vteps[0].GetIp() != "10.0.0.2" || !vteps[0].GetHealthy() ||
		vteps[0].GetLastSeen().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Fatalf("vteps = %+v", vteps)
	}
	if vteps[1].GetHealthy() || vteps[1].GetLastSeen() != nil {
		t.Errorf("a VTEP never seen = %+v, want unhealthy with no last-seen time", vteps[1])
	}

	getResp := &platformv1.GetVTEPResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_GetVTEP_FullMethodName,
		&platformv1.GetVTEPRequest{NodeId: "node-2"}, getResp); err != nil {
		t.Fatalf("GetVTEP: %v", err)
	}
	v := getResp.GetVtep()
	if v.GetNodeId() != "node-2" || !slices.Equal(v.GetVnis(), []uint32{100, 200}) || v.GetMacCount() != 5 ||
		v.GetBytesSent() != 1024 || v.GetBytesRecv() != 2048 {
		t.Errorf("vtep = %+v", v)
	}

	if len(calls) != 3 || len(calls[0].Arguments) != 0 || len(calls[1].Arguments) != 0 ||
		calls[2].Arguments["node_id"] != "node-2" {
		t.Errorf("calls = %+v, want no arguments for status and list, the node ID for get", calls)
	}
}

func TestOverlayMCP_VNILifecycle(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"overlay_vni_create": map[string]interface{}{
			"vni": float64(1000100), "vlan": float64(100), "tunnel_count": float64(0),
			"mac_count": float64(0), "imet_advertised": false, "created_at": gatewayTestTime,
		},
		"overlay_vni_list": map[string]interface{}{"vnis": []interface{}{
			map[string]interface{}{"vni": float64(1000100), "vlan": float64(100), "mac_count": float64(3), "created_at": ""},
		}},
		"overlay_vni_delete": map[string]interface{}{"success": true},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	createResp := &platformv1.CreateVNIResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_CreateVNI_FullMethodName,
		&platformv1.CreateVNIRequest{Config: &platformv1.VNIConfig{Vni: 1000100, Vlan: 100, Name: "prod"}}, createResp); err != nil {
		t.Fatalf("CreateVNI: %v", err)
	}
	created := createResp.GetVni()
	if !createResp.GetStatus().GetSuccess() || created.GetId() != "vni-1000100" || created.GetConfig().GetVni() != 1000100 ||
		created.GetConfig().GetVlan() != 100 || created.GetCreatedAt().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Errorf("create = %+v", createResp)
	}

	listResp := &platformv1.ListVNIsResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_ListVNIs_FullMethodName,
		&platformv1.ListVNIsRequest{}, listResp); err != nil {
		t.Fatalf("ListVNIs: %v", err)
	}
	vnis := listResp.GetVnis()
	if len(vnis) != 1 || vnis[0].GetMacCount() != 3 || vnis[0].GetCreatedAt() != nil {
		t.Errorf("vnis = %+v, want one VNI with its MAC count and no creation time", vnis)
	}

	deleteResp := &platformv1.DeleteVNIResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_DeleteVNI_FullMethodName,
		&platformv1.DeleteVNIRequest{Vni: 1000100}, deleteResp); err != nil {
		t.Fatalf("DeleteVNI: %v", err)
	}
	if !deleteResp.GetStatus().GetSuccess() {
		t.Errorf("delete = %+v, want success", deleteResp)
	}

	if len(calls) != 3 {
		t.Fatalf("calls = %+v", calls)
	}
	create := calls[0].Arguments
	if create["vni"] != float64(1000100) || create["vlan"] != float64(100) || create["name"] != "prod" {
		t.Errorf("create sent %v, want the VNI, VLAN and name", create)
	}
	if calls[2].Arguments["vni"] != float64(1000100) {
		t.Errorf("delete sent %v, want the VNI", calls[2].Arguments)
	}
}

func TestOverlayMCP_TunnelsAndMACs(t *testing.T) {
	var calls []toolCall
	tunnel := map[string]interface{}{
		"id": "t-1", "local_vtep": "10.0.0.1", "remote_vtep": "10.0.0.2", "vni": float64(100),
		"port": "vxlan-1", "state": "up", "bytes_sent": float64(1024), "bytes_recv": float64(2048),
	}
	a := provisioningTestServer(t, map[string]interface{}{
		"overlay_tunnel_list":  map[string]interface{}{"tunnels": []interface{}{tunnel}},
		"overlay_tunnel_stats": map[string]interface{}{"tunnel": tunnel},
		"overlay_mac_list": map[string]interface{}{"macs": []interface{}{
			map[string]interface{}{
				"mac": "aa:bb:cc:dd:ee:ff", "ip": "", "vni": float64(100), "remote_vtep": "10.0.0.2",
				"source": "evpn", "learned_at": gatewayTestTime, "expires_at": "",
			},
		}},
		"overlay_mac_forget": map[string]interface{}{"success": true},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	listResp := &platformv1.ListTunnelsResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_ListTunnels_FullMethodName,
		&platformv1.ListTunnelsRequest{Vni: 100}, listResp); err != nil {
		t.Fatalf("ListTunnels: %v", err)
	}
	statsResp := &platformv1.GetTunnelStatsResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_GetTunnelStats_FullMethodName,
		&platformv1.GetTunnelStatsRequest{RemoteVtep: "10.0.0.2", Vni: 100}, statsResp); err != nil {
		t.Fatalf("GetTunnelStats: %v", err)
	}
	if len(listResp.GetTunnels()) != 1 {
		t.Fatalf("tunnels = %+v, want one", listResp.GetTunnels())
	}
	for _, tun := range []*platformv1.TunnelInfo{listResp.GetTunnels()[0], statsResp.GetTunnel()} {
		if tun.GetLocalVtep() != "10.0.0.1" || tun.GetRemoteVtep() != "10.0.0.2" || tun.GetVni() != 100 ||
			tun.GetState() != "up" || tun.GetBytesTx() != 1024 || tun.GetBytesRx() != 2048 {
			t.Errorf("tunnel = %+v", tun)
		}
	}

	macsResp := &platformv1.ListRemoteMACsResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_ListRemoteMACs_FullMethodName,
		&platformv1.ListRemoteMACsRequest{Vni: 100}, macsResp); err != nil {
		t.Fatalf("ListRemoteMACs: %v", err)
	}
	macs := macsResp.GetMacs()
	if len(macs) != 1 || macs[0].GetMac() != "aa:bb:cc:dd:ee:ff" || macs[0].GetVni() != 100 ||
		macs[0].GetRemoteVtep() != "10.0.0.2" || macs[0].GetLearnedAt().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Errorf("macs = %+v", macs)
	}

	forgetResp := &platformv1.ForgetMACResponse{}
	if err := conn.Invoke(ctx, platformv1.OverlayService_ForgetMAC_FullMethodName,
		&platformv1.ForgetMACRequest{Mac: "aa:bb:cc:dd:ee:ff", Vni: 100}, forgetResp); err != nil {
		t.Fatalf("ForgetMAC: %v", err)
	}
	if !forgetResp.GetStatus().GetSuccess() {
		t.Errorf("forget = %+v, want success", forgetResp)
	}

	if len(calls) != 4 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Arguments["vni"] != float64(100) {
		t.Errorf("tunnel list sent %v, want the VNI filter", calls[0].Arguments)
	}
	if calls[1].Arguments["remote_vtep"] != "10.0.0.2" || calls[1].Arguments["vni"] != float64(100) {
		t.Errorf("tunnel stats sent %v, want the remote VTEP and VNI", calls[1].Arguments)
	}
	if calls[2].Arguments["vni"] != float64(100) {
		t.Errorf("MAC list sent %v, want the VNI filter", calls[2].Arguments)
	}
	if calls[3].Arguments["mac"] != "aa:bb:cc:dd:ee:ff" || calls[3].Arguments["vni"] != float64(100) {
		t.Errorf("forget sent %v, want the MAC and VNI", calls[3].Arguments)
	}
}

func TestOverlayMCP_MalformedTimeFailsTheCall(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"overlay_vtep_get": map[string]interface{}{"node_id": "node-2", "last_seen": "yesterday"},
	}, &calls)
	err := a.Connection().Invoke(context.Background(), platformv1.OverlayService_GetVTEP_FullMethodName,
		&platformv1.GetVTEPRequest{NodeId: "node-2"}, &platformv1.GetVTEPResponse{})
	if err == nil {
		t.Fatal("GetVTEP accepted a last-seen time that is not RFC 3339")
	}
}

func TestOverlayMCP_BuildersRefuseTheWrongRequestType(t *testing.T) {
	for method := range overlayMethods {
		var wrongType ErrUnexpectedArgsType
		if _, err := mcpArgBuilders[method](&platformv1.GetNAT64StatusRequest{}); !errors.As(err, &wrongType) ||
			wrongType.Method != method {
			t.Errorf("%s: wrong request gave %v, want ErrUnexpectedArgsType naming the method", method, err)
		}
	}
}

func TestOverlayMCP_DecodersRefuseTheWrongReplyAndMalformedResults(t *testing.T) {
	replies := map[string]interface{}{
		platformv1.OverlayService_GetOverlayStatus_FullMethodName: &platformv1.GetOverlayStatusResponse{},
		platformv1.OverlayService_ListVTEPs_FullMethodName:        &platformv1.ListVTEPsResponse{},
		platformv1.OverlayService_GetVTEP_FullMethodName:          &platformv1.GetVTEPResponse{},
		platformv1.OverlayService_ListVNIs_FullMethodName:         &platformv1.ListVNIsResponse{},
		platformv1.OverlayService_CreateVNI_FullMethodName:        &platformv1.CreateVNIResponse{},
		platformv1.OverlayService_DeleteVNI_FullMethodName:        &platformv1.DeleteVNIResponse{},
		platformv1.OverlayService_ListTunnels_FullMethodName:      &platformv1.ListTunnelsResponse{},
		platformv1.OverlayService_GetTunnelStats_FullMethodName:   &platformv1.GetTunnelStatsResponse{},
		platformv1.OverlayService_ListRemoteMACs_FullMethodName:   &platformv1.ListRemoteMACsResponse{},
		platformv1.OverlayService_ForgetMAC_FullMethodName:        &platformv1.ForgetMACResponse{},
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

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

package quic

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// overlayCallRecorder invokes method against a sender that answers with
// wireReply, and checks the request rode the overlay category.
func overlayCallRecorder(t *testing.T, method string, args, reply interface{}, wireReply interface{}) *recordingSender {
	t.Helper()
	encoded, err := quicwire.EncodePayload(wireReply)
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}
	sender := &recordingSender{respPayload: encoded}
	if err := newConnWithSender(t, sender).Invoke(context.Background(), method, args, reply); err != nil {
		t.Fatalf("Invoke(%s) = %v", method, err)
	}
	if sender.rawOpcode != quicwire.OpOverlayCategory {
		t.Fatalf("opcode = 0x%02X, want the overlay category 0x%02X", sender.rawOpcode, quicwire.OpOverlayCategory)
	}
	return sender
}

// decodeOverlayRequest decodes the body the adapter sent after the
// sub-opcode, checking the sub-opcode first.
func decodeOverlayRequest(t *testing.T, sender *recordingSender, sub byte, into interface{}) {
	t.Helper()
	if len(sender.rawPayload) == 0 || sender.rawPayload[0] != sub {
		t.Fatalf("payload = %x, want sub-opcode 0x%02X first", sender.rawPayload, sub)
	}
	if err := quicwire.DecodePayload(sender.rawPayload[1:], into); err != nil {
		t.Fatalf("DecodePayload(request) = %v", err)
	}
}

func TestOverlayRouting_EveryMethodReachesItsSubOpcode(t *testing.T) {
	methods := []string{
		platformv1.OverlayService_ListVTEPs_FullMethodName,
		platformv1.OverlayService_GetVTEP_FullMethodName,
		platformv1.OverlayService_CreateVNI_FullMethodName,
		platformv1.OverlayService_DeleteVNI_FullMethodName,
		platformv1.OverlayService_ListVNIs_FullMethodName,
		platformv1.OverlayService_ListTunnels_FullMethodName,
		platformv1.OverlayService_GetTunnelStats_FullMethodName,
		platformv1.OverlayService_ListRemoteMACs_FullMethodName,
		platformv1.OverlayService_ForgetMAC_FullMethodName,
		platformv1.OverlayService_GetOverlayStatus_FullMethodName,
	}
	for _, method := range methods {
		if grpcMethodToOpcodeMap[method] != quicwire.OpOverlayCategory {
			t.Fatalf("%s opcode = 0x%02X, want the overlay category", method, grpcMethodToOpcodeMap[method])
		}
		if categorySubOpcodeMap[method] != overlaySubOpcodes[method] || overlaySubOpcodes[method] == 0 {
			t.Fatalf("%s has no overlay sub-opcode", method)
		}
		_, empty := categoryEmptyBodyMethods[method]
		if empty != (method == platformv1.OverlayService_GetOverlayStatus_FullMethodName) {
			t.Fatalf("%s empty-bodied = %v, want only GetOverlayStatus without a body", method, empty)
		}
	}
	if _, ok := categoryOpcodes[quicwire.OpOverlayCategory]; !ok {
		t.Fatal("the overlay category is not a category opcode")
	}
}

func TestInvoke_GetOverlayStatus_SendsNoBodyAndDecodesTheStatus(t *testing.T) {
	reply := &platformv1.GetOverlayStatusResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_GetOverlayStatus_FullMethodName,
		&platformv1.GetOverlayStatusRequest{}, reply,
		&quicwire.OverlayStatusResponse{Status: &quicwire.OverlayStatusInfo{
			NodeID: "node-1", LocalVTEP: "10.0.0.1", VXLANPort: 4789, MTU: 1500,
			VTEPCount: 3, VNICount: 2, TunnelCount: 4, MACCount: 9, HealthStatus: "healthy",
		}})

	if len(sender.rawPayload) != 1 || sender.rawPayload[0] != quicwire.OpOverlayStatus {
		t.Fatalf("payload = %x, want only the status sub-opcode", sender.rawPayload)
	}
	s := reply.GetStatus()
	if s.GetNodeId() != "node-1" || s.GetVtepIp() != "10.0.0.1" || s.GetVxlanPort() != 4789 ||
		s.GetUnderlayMtu() != 1500 || s.GetVtepCount() != 3 || s.GetVniCount() != 2 ||
		s.GetTunnelCount() != 4 || s.GetRemoteMacCount() != 9 || !s.GetHealthy() {
		t.Fatalf("status = %+v, want the served values", s)
	}
}

func TestInvoke_GetVTEP_SendsTheNodeIDAndDecodesTheVTEP(t *testing.T) {
	lastSeen := time.Date(2026, 10, 13, 12, 0, 0, 500, time.UTC)
	reply := &platformv1.GetVTEPResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_GetVTEP_FullMethodName,
		&platformv1.GetVTEPRequest{NodeId: "node-2"}, reply,
		&quicwire.OverlayGetVTEPResponse{VTEP: &quicwire.VTEPInfo{
			ID: "node-2", IPAddress: "10.0.0.2", Status: "healthy",
			VNIs: []uint32{100, 200}, LastSeen: lastSeen.UnixNano(),
		}})

	var req quicwire.OverlayGetVTEPRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayGetVTEP, &req)
	if req.ID != "node-2" {
		t.Fatalf("request ID = %q, want node-2", req.ID)
	}
	v := reply.GetVtep()
	if v.GetNodeId() != "node-2" || v.GetIp() != "10.0.0.2" || !v.GetHealthy() ||
		!slices.Equal(v.GetVnis(), []uint32{100, 200}) || !v.GetLastSeen().AsTime().Equal(lastSeen) {
		t.Fatalf("vtep = %+v, want the served values", v)
	}
}

func TestInvoke_CreateVNI_SendsTheConfigAndDecodesTheVNI(t *testing.T) {
	reply := &platformv1.CreateVNIResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_CreateVNI_FullMethodName,
		&platformv1.CreateVNIRequest{Config: &platformv1.VNIConfig{
			Vni: 1000100, Vlan: 100, Name: "prod", Labels: map[string]string{"env": "prod"},
		}}, reply,
		&quicwire.OverlayCreateVNIResponse{VNI: &quicwire.VNIInfo{
			VNI: 1000100, VLAN: 100, Name: "prod", MACCount: 2, CreatedAt: 1700000000,
		}})

	var req quicwire.OverlayCreateVNIRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayCreateVNI, &req)
	if req.VNI != 1000100 || req.VLAN != 100 || req.Name != "prod" || req.Labels["env"] != "prod" {
		t.Fatalf("request = %+v, want the config fields", req)
	}
	if !reply.GetStatus().GetSuccess() {
		t.Fatal("status is not successful")
	}
	vni := reply.GetVni()
	if vni.GetId() != "vni-1000100" || vni.GetConfig().GetVni() != 1000100 || vni.GetConfig().GetVlan() != 100 ||
		vni.GetConfig().GetName() != "prod" || vni.GetMacCount() != 2 || vni.GetCreatedAt().GetSeconds() != 1700000000 {
		t.Fatalf("vni = %+v, want the served VNI named as gRPC names it", vni)
	}
}

func TestInvoke_CreateVNI_WithoutConfigSendsZeroValues(t *testing.T) {
	sender := overlayCallRecorder(t, platformv1.OverlayService_CreateVNI_FullMethodName,
		&platformv1.CreateVNIRequest{}, &platformv1.CreateVNIResponse{},
		&quicwire.OverlayCreateVNIResponse{})

	var req quicwire.OverlayCreateVNIRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayCreateVNI, &req)
	if req.VNI != 0 || req.VLAN != 0 {
		t.Fatalf("request = %+v, want zero values for the daemon to refuse", req)
	}
}

func TestInvoke_DeleteVNI_SendsTheVNIAndReportsSuccess(t *testing.T) {
	reply := &platformv1.DeleteVNIResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_DeleteVNI_FullMethodName,
		&platformv1.DeleteVNIRequest{Vni: 300}, reply,
		&quicwire.OverlayDeleteVNIResponse{VNI: 300, Success: true})

	var req quicwire.OverlayDeleteVNIRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayDeleteVNI, &req)
	if req.VNI != 300 || !reply.GetStatus().GetSuccess() {
		t.Fatalf("request VNI = %d, success = %v; want 300 and true", req.VNI, reply.GetStatus().GetSuccess())
	}
}

func TestInvoke_GetTunnelStats_SendsTheSelectorAndDecodesTheTunnel(t *testing.T) {
	reply := &platformv1.GetTunnelStatsResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_GetTunnelStats_FullMethodName,
		&platformv1.GetTunnelStatsRequest{RemoteVtep: "10.0.0.3", Vni: 100}, reply,
		&quicwire.OverlayTunnelStatsResponse{Tunnel: &quicwire.TunnelInfo{
			LocalVTEP: "10.0.0.1", RemoteVTEP: "10.0.0.3", VNI: 100, Status: "up",
			TxBytes: 1024, RxBytes: -1,
		}})

	var req quicwire.OverlayTunnelStatsRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayTunnelStats, &req)
	if req.RemoteVTEP != "10.0.0.3" || req.VNI != 100 {
		t.Fatalf("request = %+v, want the remote VTEP and VNI", req)
	}
	tun := reply.GetTunnel()
	if tun.GetLocalVtep() != "10.0.0.1" || tun.GetRemoteVtep() != "10.0.0.3" || tun.GetVni() != 100 ||
		tun.GetState() != "up" || tun.GetBytesTx() != 1024 || tun.GetBytesRx() != 0 {
		t.Fatalf("tunnel = %+v, want the served values with a negative counter as zero", tun)
	}
}

func TestInvoke_ForgetMAC_SendsTheMACAndReportsSuccess(t *testing.T) {
	reply := &platformv1.ForgetMACResponse{}
	sender := overlayCallRecorder(t, platformv1.OverlayService_ForgetMAC_FullMethodName,
		&platformv1.ForgetMACRequest{Mac: "aa:bb:cc:dd:ee:ff", Vni: 100}, reply,
		&quicwire.OverlayForgetMACResponse{Success: true})

	var req quicwire.OverlayForgetMACRequest
	decodeOverlayRequest(t, sender, quicwire.OpOverlayForgetMAC, &req)
	if req.MAC != "aa:bb:cc:dd:ee:ff" || req.VNI != 100 || !reply.GetStatus().GetSuccess() {
		t.Fatalf("request = %+v, success = %v; want the MAC, VNI and success", req, reply.GetStatus().GetSuccess())
	}
}

func TestInvoke_OverlayTransportFailureIsReturned(t *testing.T) {
	sender := &recordingSender{sendRequestErr: errors.New("connection reset")}
	err := newConnWithSender(t, sender).Invoke(context.Background(), platformv1.OverlayService_DeleteVNI_FullMethodName,
		&platformv1.DeleteVNIRequest{Vni: 1}, &platformv1.DeleteVNIResponse{})
	if err == nil {
		t.Fatal("Invoke succeeded over a failed transport")
	}
}

func TestOverlayRequestEncoders_AcceptTheirOwnTypeAndRefuseOthers(t *testing.T) {
	requests := map[string]proto.Message{
		platformv1.OverlayService_GetVTEP_FullMethodName:        &platformv1.GetVTEPRequest{},
		platformv1.OverlayService_CreateVNI_FullMethodName:      &platformv1.CreateVNIRequest{},
		platformv1.OverlayService_DeleteVNI_FullMethodName:      &platformv1.DeleteVNIRequest{},
		platformv1.OverlayService_GetTunnelStats_FullMethodName: &platformv1.GetTunnelStatsRequest{},
		platformv1.OverlayService_ForgetMAC_FullMethodName:      &platformv1.ForgetMACRequest{},
	}
	for method, req := range requests {
		encode, ok := categoryRequestEncoders[method]
		if !ok {
			t.Fatalf("%s has no request encoder", method)
		}
		if _, err := encode(req); err != nil {
			t.Fatalf("%s encode of its own request = %v", method, err)
		}
		var wrongType ErrInvalidArgsType
		if _, err := encode(&platformv1.GetNAT64StatusRequest{}); !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Fatalf("%s encode of the wrong request = %v, want ErrInvalidArgsType naming the method", method, err)
		}
	}
}

func TestOverlayReplyDecoders_Refusals(t *testing.T) {
	replies := map[string]proto.Message{
		platformv1.OverlayService_GetOverlayStatus_FullMethodName: &platformv1.GetOverlayStatusResponse{},
		platformv1.OverlayService_GetVTEP_FullMethodName:          &platformv1.GetVTEPResponse{},
		platformv1.OverlayService_CreateVNI_FullMethodName:        &platformv1.CreateVNIResponse{},
		platformv1.OverlayService_DeleteVNI_FullMethodName:        &platformv1.DeleteVNIResponse{},
		platformv1.OverlayService_GetTunnelStats_FullMethodName:   &platformv1.GetTunnelStatsResponse{},
		platformv1.OverlayService_ForgetMAC_FullMethodName:        &platformv1.ForgetMACResponse{},
	}
	for method, reply := range replies {
		decode, ok := categoryResponseDecoders[method]
		if !ok {
			t.Fatalf("%s has no reply decoder", method)
		}
		var wrongType ErrInvalidReplyType
		if err := decode(nil, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Fatalf("%s decode into the wrong reply = %v, want ErrInvalidReplyType naming the method", method, err)
		}
		var undecodable ErrDecodingFailed
		if err := decode([]byte{0xc1}, reply); !errors.As(err, &undecodable) {
			t.Fatalf("%s decode of garbage = %v, want ErrDecodingFailed", method, err)
		}
	}
}

func TestOverlayPagers_RefuseTheWrongTypes(t *testing.T) {
	cases := map[string]struct {
		request proto.Message
		reply   proto.Message
	}{
		platformv1.OverlayService_ListVTEPs_FullMethodName: {
			&platformv1.ListVTEPsRequest{}, &platformv1.ListVTEPsResponse{}},
		platformv1.OverlayService_ListVNIs_FullMethodName: {
			&platformv1.ListVNIsRequest{}, &platformv1.ListVNIsResponse{}},
		platformv1.OverlayService_ListTunnels_FullMethodName: {
			&platformv1.ListTunnelsRequest{}, &platformv1.ListTunnelsResponse{}},
		platformv1.OverlayService_ListRemoteMACs_FullMethodName: {
			&platformv1.ListRemoteMACsRequest{}, &platformv1.ListRemoteMACsResponse{}},
	}
	for method, tc := range cases {
		pager, ok := categoryPagers[method]
		if !ok {
			t.Fatalf("%s is not paged", method)
		}
		if _, err := pager.request(tc.request, 7); err != nil {
			t.Fatalf("%s request of its own type = %v", method, err)
		}
		var wrongArgs ErrInvalidArgsType
		if _, err := pager.request(&platformv1.GetNAT64StatusRequest{}, 0); !errors.As(err, &wrongArgs) || wrongArgs.Method != method {
			t.Fatalf("%s request of the wrong type = %v, want ErrInvalidArgsType naming the method", method, err)
		}
		var wrongReply ErrInvalidReplyType
		if _, err := pager.decode(nil, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &wrongReply) || wrongReply.Method != method {
			t.Fatalf("%s decode into the wrong reply = %v, want ErrInvalidReplyType naming the method", method, err)
		}
		var undecodable ErrDecodingFailed
		if _, err := pager.decode([]byte{0xc1}, tc.reply); !errors.As(err, &undecodable) {
			t.Fatalf("%s decode of garbage = %v, want ErrDecodingFailed", method, err)
		}
	}
}

// overlayPagingDaemon serves n entries of whichever overlay list it is
// asked for, at most pageCap per reply, and records each request's offset
// and VNI filter. Entry i is named strconv.Itoa(i).
type overlayPagingDaemon struct {
	recordingSender
	n       int32
	pageCap int32
	offsets []int32
	vnis    []uint32
}

func (d *overlayPagingDaemon) SendRequest(_ context.Context, _ byte, payload []byte) (*quicwire.Response, error) {
	var req quicwire.OverlayListMACsRequest
	if err := quicwire.DecodePayload(payload[1:], &req); err != nil {
		return nil, err
	}
	d.offsets = append(d.offsets, req.Offset)
	d.vnis = append(d.vnis, req.VNI)
	start := min(req.Offset, d.n)
	end := min(start+min(req.Limit, d.pageCap), d.n)
	var reply interface{}
	switch payload[0] {
	case quicwire.OpOverlayListVTEPs:
		page := &quicwire.OverlayListVTEPsResponse{Total: d.n}
		for i := start; i < end; i++ {
			page.VTEPs = append(page.VTEPs, &quicwire.VTEPInfo{ID: strconv.Itoa(int(i))})
		}
		reply = page
	case quicwire.OpOverlayListVNIs:
		page := &quicwire.OverlayListVNIsResponse{Total: d.n}
		for i := start; i < end; i++ {
			page.VNIs = append(page.VNIs, &quicwire.VNIInfo{VNI: uint32(i), Name: strconv.Itoa(int(i))})
		}
		reply = page
	case quicwire.OpOverlayListTunns:
		page := &quicwire.OverlayListTunnelsResponse{Total: d.n}
		for i := start; i < end; i++ {
			page.Tunnels = append(page.Tunnels, &quicwire.TunnelInfo{RemoteVTEP: strconv.Itoa(int(i))})
		}
		reply = page
	default:
		page := &quicwire.OverlayListMACsResponse{Total: d.n}
		for i := start; i < end; i++ {
			page.MACs = append(page.MACs, &quicwire.MACEntry{MAC: strconv.Itoa(int(i))})
		}
		reply = page
	}
	encoded, err := quicwire.EncodePayload(reply)
	if err != nil {
		return nil, err
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: encoded}, nil
}

func (d *overlayPagingDaemon) conn() *quicClientConn {
	a := &Adapter{client: &quicwire.Client{}}
	a.connected.Store(true)
	return &quicClientConn{adapter: a, sender: d}
}

func TestInvoke_OverlayListsPageThroughEveryEntry(t *testing.T) {
	const entries = 2500
	lists := []struct {
		method  string
		request proto.Message
		reply   proto.Message
		vni     uint32
		names   func(proto.Message) []string
	}{
		{
			method:  platformv1.OverlayService_ListVTEPs_FullMethodName,
			request: &platformv1.ListVTEPsRequest{},
			reply:   &platformv1.ListVTEPsResponse{},
			names: func(m proto.Message) []string {
				var names []string
				for _, v := range m.(*platformv1.ListVTEPsResponse).GetVteps() {
					names = append(names, v.GetNodeId())
				}
				return names
			},
		},
		{
			method:  platformv1.OverlayService_ListVNIs_FullMethodName,
			request: &platformv1.ListVNIsRequest{},
			reply:   &platformv1.ListVNIsResponse{},
			names: func(m proto.Message) []string {
				var names []string
				for _, v := range m.(*platformv1.ListVNIsResponse).GetVnis() {
					names = append(names, v.GetConfig().GetName())
				}
				return names
			},
		},
		{
			method:  platformv1.OverlayService_ListTunnels_FullMethodName,
			request: &platformv1.ListTunnelsRequest{Vni: 100},
			reply:   &platformv1.ListTunnelsResponse{},
			vni:     100,
			names: func(m proto.Message) []string {
				var names []string
				for _, v := range m.(*platformv1.ListTunnelsResponse).GetTunnels() {
					names = append(names, v.GetRemoteVtep())
				}
				return names
			},
		},
		{
			method:  platformv1.OverlayService_ListRemoteMACs_FullMethodName,
			request: &platformv1.ListRemoteMACsRequest{Vni: 200},
			reply:   &platformv1.ListRemoteMACsResponse{},
			vni:     200,
			names: func(m proto.Message) []string {
				var names []string
				for _, v := range m.(*platformv1.ListRemoteMACsResponse).GetMacs() {
					names = append(names, v.GetMac())
				}
				return names
			},
		},
	}
	for _, list := range lists {
		t.Run(list.method, func(t *testing.T) {
			daemon := &overlayPagingDaemon{n: entries, pageCap: 1000}
			if err := daemon.conn().Invoke(context.Background(), list.method, list.request, list.reply); err != nil {
				t.Fatalf("Invoke = %v", err)
			}
			names := list.names(list.reply)
			if len(names) != entries {
				t.Fatalf("entries = %d, want all %d", len(names), entries)
			}
			for i, name := range names {
				if name != strconv.Itoa(i) {
					t.Fatalf("entry %d = %q, want the daemon's order", i, name)
				}
			}
			if !slices.Equal(daemon.offsets, []int32{0, 1000, 2000}) {
				t.Fatalf("offsets = %v, want one request per page", daemon.offsets)
			}
			for _, vni := range daemon.vnis {
				if vni != list.vni {
					t.Fatalf("VNI filter = %d, want %d on every page", vni, list.vni)
				}
			}
		})
	}
}

func TestInvoke_OverlayListWrongRequestTypeSendsNothing(t *testing.T) {
	daemon := &overlayPagingDaemon{n: 10, pageCap: 1000}
	err := daemon.conn().Invoke(context.Background(), platformv1.OverlayService_ListVNIs_FullMethodName,
		&platformv1.GetNAT64StatusRequest{}, &platformv1.ListVNIsResponse{})
	if status.Code(err) != codes.InvalidArgument || len(daemon.offsets) != 0 {
		t.Fatalf("err = %v after %d requests, want InvalidArgument before any", err, len(daemon.offsets))
	}
}

func TestOverlayWireConversions_NilAndZeroValues(t *testing.T) {
	if overlayStatusFromWire(nil) != nil || vtepFromWire(nil) != nil ||
		vniFromWire(nil) != nil || tunnelFromWire(nil) != nil {
		t.Fatal("a nil wire value must convert to nil")
	}
	if unixNanoTimestamp(0) != nil {
		t.Fatal("a zero moment must convert to no timestamp")
	}
	if wireBytes(-5) != 0 || wireBytes(7) != 7 {
		t.Fatal("wireBytes must floor negatives at zero and keep the rest")
	}
	if vniFromWire(&quicwire.VNIInfo{}).GetId() != "vni-0" {
		t.Fatal("VNI 0 must be named vni-0, as gRPC names it")
	}
	if vtepFromWire(&quicwire.VTEPInfo{Status: "degraded"}).GetHealthy() {
		t.Fatal("a degraded VTEP must not be healthy")
	}
}

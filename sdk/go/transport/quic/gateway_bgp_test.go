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

package quic

import (
	"context"
	"errors"
	"math"
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

func TestInvoke_GetBGPStatus_SendsNoBodyAndDecodesTheServedStatus(t *testing.T) {
	reply := &platformv1.GetBGPStatusResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_GetBGPStatus_FullMethodName,
		&platformv1.GetBGPStatusRequest{}, reply,
		&quicwire.GatewayBGPStatusResponse{Status: &quicwire.BGPStatusInfo{
			Enabled: true, RouterID: "10.0.0.1", LocalAS: 65001,
			PeerCount: 3, EstablishedCount: 2, PrefixesSent: 5,
		}})

	if len(sender.rawPayload) != 1 || sender.rawPayload[0] != quicwire.OpGatewayBGPStatus {
		t.Fatalf("payload = %x, want only the BGP status sub-opcode", sender.rawPayload)
	}
	s := reply.GetStatus()
	if !s.GetRunning() || s.GetRouterId() != "10.0.0.1" || s.GetLocalAsn() != 65001 ||
		s.GetPeerCount() != 3 || s.GetEstablishedPeers() != 2 || s.GetPrefixesAnnounced() != 5 {
		t.Fatalf("status = %+v, want the served values", s)
	}
}

func TestInvoke_ListBGPPeers_DecodesPeersAndTheEstablishedMoment(t *testing.T) {
	reply := &platformv1.ListBGPPeersResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_ListBGPPeers_FullMethodName,
		&platformv1.ListBGPPeersRequest{}, reply,
		&quicwire.GatewayBGPPeersResponse{Peers: []*quicwire.BGPPeerInfo{
			{Address: "10.0.0.2", RemoteAS: 65002, State: "established", Description: "upstream",
				PrefixesReceived: 7, PrefixesSent: 4, Uptime: 60},
			nil,
			{Address: "10.0.0.3", RemoteAS: 65003, State: "active"},
		}})

	var sent quicwire.GatewayBGPPeersRequest
	decodeSent(t, sender, quicwire.OpGatewayBGPPeers, &sent)
	if sent.Limit != gatewayListPageSize || sent.Offset != 0 {
		t.Fatalf("request = %+v, want the first page of %d", sent, gatewayListPageSize)
	}
	if sender.rawCalls != 1 {
		t.Fatalf("requests = %d, want 1: a reply without a total is the whole list", sender.rawCalls)
	}
	peers := reply.GetPeers()
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2 (the nil wire entry dropped)", len(peers))
	}
	up := peers[0]
	if up.GetAddress() != "10.0.0.2" || up.GetAsn() != 65002 || up.GetState() != "established" ||
		up.GetDescription() != "upstream" || up.GetPrefixesReceived() != 7 || up.GetPrefixesSent() != 4 {
		t.Fatalf("peer = %+v, want the served values", up)
	}
	if up.GetUptime() == nil {
		t.Fatal("an established peer decoded without its established time")
	}
	if peers[1].GetUptime() != nil {
		t.Fatalf("a peer that is not established has uptime %v, want none", peers[1].GetUptime())
	}
}

func TestInvoke_AnnouncePrefix_SendsTheServerShape(t *testing.T) {
	reply := &platformv1.AnnouncePrefixResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_AnnouncePrefix_FullMethodName,
		&platformv1.AnnouncePrefixRequest{Prefix: "203.0.113.0/24", NextHop: "10.0.0.1"}, reply,
		&quicwire.GatewayAnnouncePrefixResponse{Prefix: "203.0.113.0/24", Success: true})

	var sent quicwire.GatewayAnnouncePrefixRequest
	decodeSent(t, sender, quicwire.OpGatewayAnnouncePrefix, &sent)
	if sent.Prefix != "203.0.113.0/24" || sent.NextHop != "10.0.0.1" {
		t.Fatalf("sent = %+v, want the prefix and next hop", sent)
	}
	if !reply.GetStatus().GetSuccess() {
		t.Fatalf("status = %+v, want success", reply.GetStatus())
	}
}

func TestInvoke_WithdrawPrefix_SendsTheServerShape(t *testing.T) {
	reply := &platformv1.WithdrawPrefixResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_WithdrawPrefix_FullMethodName,
		&platformv1.WithdrawPrefixRequest{Prefix: "203.0.113.0/24"}, reply,
		&quicwire.GatewayWithdrawPrefixResponse{Prefix: "203.0.113.0/24", Success: true})

	var sent quicwire.GatewayWithdrawPrefixRequest
	decodeSent(t, sender, quicwire.OpGatewayWithdrawPrefix, &sent)
	if sent.Prefix != "203.0.113.0/24" {
		t.Fatalf("sent = %+v, want the prefix", sent)
	}
	if !reply.GetStatus().GetSuccess() {
		t.Fatalf("status = %+v, want success", reply.GetStatus())
	}
}

func TestInvoke_ListAnnouncedPrefixes_DecodesThePrefixes(t *testing.T) {
	announced := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reply := &platformv1.ListAnnouncedPrefixesResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName,
		&platformv1.ListAnnouncedPrefixesRequest{}, reply,
		&quicwire.GatewayListPrefixesResponse{Prefixes: []*quicwire.PrefixInfo{
			{Prefix: "203.0.113.0/24", NextHop: "10.0.0.1", AnnouncedAt: announced.Unix()},
			nil,
			{Prefix: "198.51.100.0/24"},
		}})

	var sent quicwire.GatewayListPrefixesRequest
	decodeSent(t, sender, quicwire.OpGatewayListPrefixes, &sent)
	if sent.Limit != gatewayListPageSize || sent.Offset != 0 {
		t.Fatalf("request = %+v, want the first page of %d", sent, gatewayListPageSize)
	}
	prefixes := reply.GetPrefixes()
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %d, want 2 (the nil wire entry dropped)", len(prefixes))
	}
	if prefixes[0].GetPrefix() != "203.0.113.0/24" || prefixes[0].GetNextHop() != "10.0.0.1" ||
		!prefixes[0].GetAnnouncedAt().AsTime().Equal(announced) {
		t.Fatalf("prefix = %+v, want the served values", prefixes[0])
	}
	if prefixes[1].GetAnnouncedAt() != nil {
		t.Fatalf("an unknown announce time decoded as %v, want none", prefixes[1].GetAnnouncedAt())
	}
}

func TestGatewayBGPRequestEncoders_AcceptTheirOwnTypeAndRefuseOthers(t *testing.T) {
	requests := map[string]proto.Message{
		platformv1.GatewayService_AnnouncePrefix_FullMethodName: &platformv1.AnnouncePrefixRequest{},
		platformv1.GatewayService_WithdrawPrefix_FullMethodName: &platformv1.WithdrawPrefixRequest{},
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

func TestGatewayBGPReplyDecoders_Refusals(t *testing.T) {
	replies := map[string]proto.Message{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:   &platformv1.GetBGPStatusResponse{},
		platformv1.GatewayService_AnnouncePrefix_FullMethodName: &platformv1.AnnouncePrefixResponse{},
		platformv1.GatewayService_WithdrawPrefix_FullMethodName: &platformv1.WithdrawPrefixResponse{},
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

func TestGatewayBGPRouting_EveryMethodReachesItsSubOpcode(t *testing.T) {
	want := map[string]byte{
		platformv1.GatewayService_GetBGPStatus_FullMethodName:          quicwire.OpGatewayBGPStatus,
		platformv1.GatewayService_ListBGPPeers_FullMethodName:          quicwire.OpGatewayBGPPeers,
		platformv1.GatewayService_AnnouncePrefix_FullMethodName:        quicwire.OpGatewayAnnouncePrefix,
		platformv1.GatewayService_WithdrawPrefix_FullMethodName:        quicwire.OpGatewayWithdrawPrefix,
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: quicwire.OpGatewayListPrefixes,
	}
	for method, sub := range want {
		if grpcMethodToOpcodeMap[method] != quicwire.OpGatewayCategory {
			t.Errorf("%s opcode = 0x%02X, want the gateway category", method, grpcMethodToOpcodeMap[method])
		}
		if categorySubOpcodeMap[method] != sub {
			t.Errorf("%s sub-opcode = 0x%02X, want 0x%02X", method, categorySubOpcodeMap[method], sub)
		}
	}
}

func TestBGPWireConversions_NilAndEdgeValues(t *testing.T) {
	if bgpStatusFromWire(nil) != nil {
		t.Fatal("a reply without a status must decode as a nil status")
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	peer := bgpPeerFromWire(&quicwire.BGPPeerInfo{Address: "10.0.0.2", Uptime: 90}, now)
	if want := now.Add(-90 * time.Second); !peer.GetUptime().AsTime().Equal(want) {
		t.Fatalf("established = %v, want %v (now less the wire uptime)", peer.GetUptime().AsTime(), want)
	}
	if got := wireCount32(-1); got != 0 {
		t.Fatalf("wireCount32(-1) = %d, want 0", got)
	}
	if got := wireCount32(math.MaxUint32 + 1); got != math.MaxUint32 {
		t.Fatalf("wireCount32(MaxUint32+1) = %d, want it saturated", got)
	}
	if got := wireCount32(42); got != 42 {
		t.Fatalf("wireCount32(42) = %d, want 42", got)
	}
}

// pagingDaemon serves n BGP peers and n announced prefixes the way the
// daemon's gateway handler pages them: from the requested offset, at most
// pageCap entries a reply, with the total it holds. Both list requests share
// the {limit, offset} shape, so one decode reads either.
type pagingDaemon struct {
	recordingSender
	n         int32
	total     int32
	pageCap   int32
	garbageAt int
	offsets   []int32
}

func newPagingDaemon(n, pageCap int32) *pagingDaemon {
	return &pagingDaemon{n: n, total: n, pageCap: pageCap}
}

func (d *pagingDaemon) SendRequest(_ context.Context, _ byte, payload []byte) (*quicwire.Response, error) {
	var req quicwire.GatewayBGPPeersRequest
	if err := quicwire.DecodePayload(payload[1:], &req); err != nil {
		return nil, err
	}
	d.offsets = append(d.offsets, req.Offset)
	if len(d.offsets) == d.garbageAt {
		return &quicwire.Response{Status: quicwire.StatusOK, Payload: []byte{0xc1}}, nil
	}
	start := min(req.Offset, d.n)
	end := min(start+min(req.Limit, d.pageCap), d.n)
	var reply interface{}
	if payload[0] == quicwire.OpGatewayBGPPeers {
		peers := make([]*quicwire.BGPPeerInfo, 0, end-start)
		for i := start; i < end; i++ {
			peers = append(peers, &quicwire.BGPPeerInfo{Address: strconv.Itoa(int(i))})
		}
		reply = &quicwire.GatewayBGPPeersResponse{Peers: peers, Count: end - start, Total: d.total}
	} else {
		prefixes := make([]*quicwire.PrefixInfo, 0, end-start)
		for i := start; i < end; i++ {
			prefixes = append(prefixes, &quicwire.PrefixInfo{Prefix: strconv.Itoa(int(i))})
		}
		reply = &quicwire.GatewayListPrefixesResponse{Prefixes: prefixes, Count: end - start, Total: d.total}
	}
	encoded, err := quicwire.EncodePayload(reply)
	if err != nil {
		return nil, err
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: encoded}, nil
}

func (d *pagingDaemon) conn() *quicClientConn {
	a := &Adapter{client: &quicwire.Client{}}
	a.connected.Store(true)
	return &quicClientConn{adapter: a, sender: d}
}

// wantOffsets is the offsets a client paging n entries by pageSize asks for.
func wantOffsets(n, pageSize int32) []int32 {
	offsets := []int32{0}
	for next := pageSize; next < n; next += pageSize {
		offsets = append(offsets, next)
	}
	return offsets
}

// TestInvoke_BGPListsPageThroughEveryEntry proves both lists return every
// entry, in order, past the daemon's default page of 100 and its cap of
// 1000, and past a daemon that serves smaller pages than the SDK asks for.
func TestInvoke_BGPListsPageThroughEveryEntry(t *testing.T) {
	const entries = 2500
	for _, pageCap := range []int32{100, 1000} {
		t.Run("peers/cap"+strconv.Itoa(int(pageCap)), func(t *testing.T) {
			daemon := newPagingDaemon(entries, pageCap)
			reply := &platformv1.ListBGPPeersResponse{}
			if err := daemon.conn().Invoke(context.Background(), platformv1.GatewayService_ListBGPPeers_FullMethodName,
				&platformv1.ListBGPPeersRequest{}, reply); err != nil {
				t.Fatalf("Invoke = %v", err)
			}
			if len(reply.GetPeers()) != entries {
				t.Fatalf("peers = %d, want all %d", len(reply.GetPeers()), entries)
			}
			for i, peer := range reply.GetPeers() {
				if peer.GetAddress() != strconv.Itoa(i) {
					t.Fatalf("peer %d = %q, want the daemon's order", i, peer.GetAddress())
				}
			}
			if !slices.Equal(daemon.offsets, wantOffsets(entries, pageCap)) {
				t.Fatalf("offsets = %v, want %v", daemon.offsets, wantOffsets(entries, pageCap))
			}
		})
		t.Run("prefixes/cap"+strconv.Itoa(int(pageCap)), func(t *testing.T) {
			daemon := newPagingDaemon(entries, pageCap)
			reply := &platformv1.ListAnnouncedPrefixesResponse{}
			if err := daemon.conn().Invoke(context.Background(), platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName,
				&platformv1.ListAnnouncedPrefixesRequest{}, reply); err != nil {
				t.Fatalf("Invoke = %v", err)
			}
			if len(reply.GetPrefixes()) != entries {
				t.Fatalf("prefixes = %d, want all %d", len(reply.GetPrefixes()), entries)
			}
			for i, prefix := range reply.GetPrefixes() {
				if prefix.GetPrefix() != strconv.Itoa(i) {
					t.Fatalf("prefix %d = %q, want the daemon's order", i, prefix.GetPrefix())
				}
			}
			if !slices.Equal(daemon.offsets, wantOffsets(entries, pageCap)) {
				t.Fatalf("offsets = %v, want %v", daemon.offsets, wantOffsets(entries, pageCap))
			}
		})
	}
}

// TestInvoke_BGPListPagingFailures proves a refused request never reaches the
// wire, a page the client cannot decode fails the whole call rather than
// returning a partial list, and a total the daemon cannot fill ends paging.
func TestInvoke_BGPListPagingFailures(t *testing.T) {
	t.Run("wrong request type", func(t *testing.T) {
		daemon := newPagingDaemon(10, 1000)
		err := daemon.conn().Invoke(context.Background(), platformv1.GatewayService_ListBGPPeers_FullMethodName,
			&platformv1.GetNAT64StatusRequest{}, &platformv1.ListBGPPeersResponse{})
		if status.Code(err) != codes.InvalidArgument || len(daemon.offsets) != 0 {
			t.Fatalf("err = %v after %d requests, want InvalidArgument before any", err, len(daemon.offsets))
		}
	})
	t.Run("undecodable second page", func(t *testing.T) {
		daemon := newPagingDaemon(250, 100)
		daemon.garbageAt = 2
		err := daemon.conn().Invoke(context.Background(), platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName,
			&platformv1.ListAnnouncedPrefixesRequest{}, &platformv1.ListAnnouncedPrefixesResponse{})
		if status.Code(err) != codes.Internal {
			t.Fatalf("err = %v, want Internal for the undecodable page", err)
		}
		if len(daemon.offsets) != 2 {
			t.Fatalf("requests = %d, want paging to stop at the bad page", len(daemon.offsets))
		}
	})
	t.Run("total the daemon cannot fill", func(t *testing.T) {
		daemon := newPagingDaemon(5, 1000)
		daemon.total = math.MaxInt32
		reply := &platformv1.ListBGPPeersResponse{}
		if err := daemon.conn().Invoke(context.Background(), platformv1.GatewayService_ListBGPPeers_FullMethodName,
			&platformv1.ListBGPPeersRequest{}, reply); err != nil {
			t.Fatalf("Invoke = %v", err)
		}
		if len(reply.GetPeers()) != 5 || !slices.Equal(daemon.offsets, []int32{0, 5}) {
			t.Fatalf("peers = %d after offsets %v, want 5 and paging to stop at the empty page",
				len(reply.GetPeers()), daemon.offsets)
		}
	})
}

func TestGatewayBGPPagers_RefuseTheWrongTypes(t *testing.T) {
	cases := map[string]struct {
		request proto.Message
		reply   proto.Message
	}{
		platformv1.GatewayService_ListBGPPeers_FullMethodName: {
			&platformv1.ListBGPPeersRequest{}, &platformv1.ListBGPPeersResponse{}},
		platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName: {
			&platformv1.ListAnnouncedPrefixesRequest{}, &platformv1.ListAnnouncedPrefixesResponse{}},
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

func TestPageCount_CapsAtTheWireMaximum(t *testing.T) {
	if got := pageCount(1000); got != 1000 {
		t.Fatalf("pageCount(1000) = %d, want 1000", got)
	}
	if got := pageCount(math.MaxInt); got != math.MaxInt32 {
		t.Fatalf("pageCount(MaxInt) = %d, want the cap %d", got, int32(math.MaxInt32))
	}
}

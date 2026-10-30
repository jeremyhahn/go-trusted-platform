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
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	ipamBackends "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// fakeGatewayBGPController answers with fixed data, or err when set, and
// records the last announce and withdraw it was asked for.
type fakeGatewayBGPController struct {
	status    *platformv1.BGPStatus
	peers     []*platformv1.BGPPeer
	prefixes  []*platformv1.AnnouncedPrefix
	err       error
	announced *platformv1.AnnouncePrefixRequest
	withdrawn *platformv1.WithdrawPrefixRequest
}

func (f *fakeGatewayBGPController) GetBGPStatus(context.Context, *platformv1.GetBGPStatusRequest) (*platformv1.GetBGPStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetBGPStatusResponse{Status: f.status}, nil
}

func (f *fakeGatewayBGPController) ListBGPPeers(context.Context, *platformv1.ListBGPPeersRequest) (*platformv1.ListBGPPeersResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListBGPPeersResponse{Peers: f.peers}, nil
}

func (f *fakeGatewayBGPController) AnnouncePrefix(_ context.Context, req *platformv1.AnnouncePrefixRequest) (*platformv1.AnnouncePrefixResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.announced = req
	return &platformv1.AnnouncePrefixResponse{}, nil
}

func (f *fakeGatewayBGPController) WithdrawPrefix(_ context.Context, req *platformv1.WithdrawPrefixRequest) (*platformv1.WithdrawPrefixResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.withdrawn = req
	return &platformv1.WithdrawPrefixResponse{}, nil
}

func (f *fakeGatewayBGPController) ListAnnouncedPrefixes(context.Context, *platformv1.ListAnnouncedPrefixesRequest) (*platformv1.ListAnnouncedPrefixesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListAnnouncedPrefixesResponse{Prefixes: f.prefixes}, nil
}

var bgpTestAnnouncedAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newFakeGatewayBGPController() *fakeGatewayBGPController {
	return &fakeGatewayBGPController{
		status: &platformv1.BGPStatus{
			LocalAsn: 65001, RouterId: "192.0.2.1", PeerCount: 2,
			EstablishedPeers: 1, PrefixesAnnounced: 3, Running: true,
		},
		peers: []*platformv1.BGPPeer{{
			Address: "192.0.2.2", Asn: 65002, State: "Established", Description: "upstream",
			PrefixesReceived: 4, PrefixesSent: 3,
			Uptime: timestamppb.New(time.Now().Add(-90 * time.Second)),
		}},
		prefixes: []*platformv1.AnnouncedPrefix{{
			Prefix: "203.0.113.0/24", NextHop: "192.0.2.1",
			AnnouncedAt: timestamppb.New(bgpTestAnnouncedAt),
		}},
	}
}

var errBGPTestBackend = grpcstatus.Error(codes.Internal, "speaker failed")

// =============================================================================
// QUIC adapter
// =============================================================================

func TestGatewayBGPQUICAdapter_Works(t *testing.T) {
	ctx := context.Background()
	fake := newFakeGatewayBGPController()
	a := gatewayBGPQUICAdapter{controller: fake}

	st, err := a.BGPStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, &quic.BGPStatusInfo{
		Enabled: true, RouterID: "192.0.2.1", LocalAS: 65001,
		PeerCount: 2, EstablishedCount: 1, PrefixesSent: 3,
	}, st)

	peers, err := a.ListBGPPeers(ctx)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, "192.0.2.2", peers[0].Address)
	assert.Equal(t, uint32(65002), peers[0].RemoteAS)
	assert.Equal(t, "Established", peers[0].State)
	assert.Equal(t, 4, peers[0].PrefixesReceived)
	assert.InDelta(t, 90, peers[0].Uptime, 2)

	require.NoError(t, a.AnnouncePrefix(ctx, "198.51.100.0/24", &quic.AnnouncePrefixOptions{NextHop: "192.0.2.1"}))
	assert.Equal(t, "198.51.100.0/24", fake.announced.GetPrefix())
	assert.Equal(t, "192.0.2.1", fake.announced.GetNextHop())

	require.NoError(t, a.WithdrawPrefix(ctx, "198.51.100.0/24"))
	assert.Equal(t, "198.51.100.0/24", fake.withdrawn.GetPrefix())

	prefixes, err := a.ListPrefixes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []*quic.PrefixInfo{{
		Prefix: "203.0.113.0/24", NextHop: "192.0.2.1", Status: "announced",
		AnnouncedAt: bgpTestAnnouncedAt.Unix(),
	}}, prefixes)
}

func TestGatewayBGPQUICAdapter_AnnounceNilOptionsLetsSpeakerChooseNextHop(t *testing.T) {
	fake := newFakeGatewayBGPController()
	a := gatewayBGPQUICAdapter{controller: fake}

	require.NoError(t, a.AnnouncePrefix(context.Background(), "198.51.100.0/24", nil))
	assert.Equal(t, "198.51.100.0/24", fake.announced.GetPrefix())
	assert.Empty(t, fake.announced.GetNextHop())
}

func TestGatewayBGPQUICAdapter_AnnounceRefusesUnsupportedAttributes(t *testing.T) {
	cases := []struct {
		attribute string
		opts      *quic.AnnouncePrefixOptions
	}{
		{"local_pref", &quic.AnnouncePrefixOptions{LocalPref: 200}},
		{"med", &quic.AnnouncePrefixOptions{MED: 10}},
		{"communities", &quic.AnnouncePrefixOptions{Communities: []string{"65001:100"}}},
		{"labels", &quic.AnnouncePrefixOptions{Labels: map[string]string{"k": "v"}}},
	}
	for _, c := range cases {
		t.Run(c.attribute, func(t *testing.T) {
			fake := newFakeGatewayBGPController()
			a := gatewayBGPQUICAdapter{controller: fake}

			err := a.AnnouncePrefix(context.Background(), "198.51.100.0/24", c.opts)
			assert.Equal(t, ErrBGPAttributeUnsupported{Attribute: c.attribute}, err)
			assert.Nil(t, fake.announced, "a refused announce must not reach the speaker")
		})
	}
}

func TestGatewayBGPQUICAdapter_NilControllerNotConfigured(t *testing.T) {
	ctx := context.Background()
	a := gatewayBGPQUICAdapter{}

	_, err := a.BGPStatus(ctx)
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	_, err = a.ListBGPPeers(ctx)
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	assert.ErrorIs(t, a.AnnouncePrefix(ctx, "198.51.100.0/24", nil), errGatewayFeatureNotConfigured)
	assert.ErrorIs(t, a.WithdrawPrefix(ctx, "198.51.100.0/24"), errGatewayFeatureNotConfigured)
	_, err = a.ListPrefixes(ctx)
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
}

func TestGatewayBGPQUICAdapter_ControllerErrorPassesThrough(t *testing.T) {
	ctx := context.Background()
	a := gatewayBGPQUICAdapter{controller: &fakeGatewayBGPController{err: errBGPTestBackend}}

	_, err := a.BGPStatus(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	_, err = a.ListBGPPeers(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	assert.Equal(t, errBGPTestBackend, a.AnnouncePrefix(ctx, "198.51.100.0/24", nil))
	assert.Equal(t, errBGPTestBackend, a.WithdrawPrefix(ctx, "198.51.100.0/24"))
	_, err = a.ListPrefixes(ctx)
	assert.Equal(t, errBGPTestBackend, err)
}

// =============================================================================
// Converters
// =============================================================================

func TestBGPConverters_NilStaysNil(t *testing.T) {
	assert.Nil(t, protoBGPStatusToQUIC(nil))
	assert.Nil(t, protoBGPPeerToQUIC(nil, time.Now()))
	assert.Nil(t, protoAnnouncedPrefixToQUIC(nil))
	assert.Nil(t, newBGPStatusView(nil))
	assert.Nil(t, newBGPPeerView(nil))
	assert.Nil(t, newAnnouncedPrefixView(nil))
}

func TestBGPConverters_MissingTimestampsStayZero(t *testing.T) {
	peer := &platformv1.BGPPeer{Address: "192.0.2.2", State: "Idle"}
	prefix := &platformv1.AnnouncedPrefix{Prefix: "203.0.113.0/24"}

	assert.Zero(t, protoBGPPeerToQUIC(peer, time.Now()).Uptime)
	assert.Zero(t, protoAnnouncedPrefixToQUIC(prefix).AnnouncedAt)
	assert.Nil(t, newBGPPeerView(peer).EstablishedAt)
	assert.Nil(t, newAnnouncedPrefixView(prefix).AnnouncedAt)
}

func TestProtoBGPPeerToQUIC_UptimeIsAgeAtNow(t *testing.T) {
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	peer := &platformv1.BGPPeer{Uptime: timestamppb.New(now.Add(-5 * time.Minute))}

	assert.Equal(t, int64(300), protoBGPPeerToQUIC(peer, now).Uptime)
}

// =============================================================================
// MCP tools
// =============================================================================

func TestGatewayBGPTools_Works(t *testing.T) {
	ctx := context.Background()
	fake := newFakeGatewayBGPController()
	var tools gatewayBGPTools
	tools.SetGatewayBGPController(fake)

	st, err := tools.GatewayBGPStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, &bgpStatusView{
		LocalASN: 65001, RouterID: "192.0.2.1", PeerCount: 2,
		EstablishedPeers: 1, PrefixesAnnounced: 3, Running: true,
	}, st)

	peers, err := tools.GatewayBGPPeers(ctx)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	peer := peers[0].(*bgpPeerView)
	assert.Equal(t, "192.0.2.2", peer.Address)
	require.NotNil(t, peer.EstablishedAt)
	assert.Equal(t, fake.peers[0].GetUptime().AsTime(), *peer.EstablishedAt)

	require.NoError(t, tools.GatewayBGPAnnounce(ctx, "198.51.100.0/24", "192.0.2.1"))
	assert.Equal(t, "198.51.100.0/24", fake.announced.GetPrefix())
	assert.Equal(t, "192.0.2.1", fake.announced.GetNextHop())

	require.NoError(t, tools.GatewayBGPWithdraw(ctx, "198.51.100.0/24"))
	assert.Equal(t, "198.51.100.0/24", fake.withdrawn.GetPrefix())

	prefixes, err := tools.GatewayBGPPrefixes(ctx)
	require.NoError(t, err)
	announcedAt := bgpTestAnnouncedAt
	assert.Equal(t, []interface{}{&announcedPrefixView{
		Prefix: "203.0.113.0/24", NextHop: "192.0.2.1", AnnouncedAt: &announcedAt,
	}}, prefixes)
}

func TestGatewayBGPTools_NilControllerServiceNotAvailable(t *testing.T) {
	ctx := context.Background()
	var tools gatewayBGPTools
	want := ErrServiceNotAvailable{Service: "gateway"}

	_, err := tools.GatewayBGPStatus(ctx)
	assert.Equal(t, want, err)
	_, err = tools.GatewayBGPPeers(ctx)
	assert.Equal(t, want, err)
	assert.Equal(t, want, tools.GatewayBGPAnnounce(ctx, "198.51.100.0/24", ""))
	assert.Equal(t, want, tools.GatewayBGPWithdraw(ctx, "198.51.100.0/24"))
	_, err = tools.GatewayBGPPrefixes(ctx)
	assert.Equal(t, want, err)
}

func TestGatewayBGPTools_ControllerErrorPassesThrough(t *testing.T) {
	ctx := context.Background()
	tools := gatewayBGPTools{controller: &fakeGatewayBGPController{err: errBGPTestBackend}}

	_, err := tools.GatewayBGPStatus(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	_, err = tools.GatewayBGPPeers(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	assert.Equal(t, errBGPTestBackend, tools.GatewayBGPAnnounce(ctx, "198.51.100.0/24", ""))
	assert.Equal(t, errBGPTestBackend, tools.GatewayBGPWithdraw(ctx, "198.51.100.0/24"))
	_, err = tools.GatewayBGPPrefixes(ctx)
	assert.Equal(t, errBGPTestBackend, err)
}

// =============================================================================
// REST service
// =============================================================================

func TestGatewayRESTService_BGPWorks(t *testing.T) {
	ctx := context.Background()
	fake := newFakeGatewayBGPController()
	svc := newGatewayRESTService(nil, nil)
	svc.SetGatewayBGPController(fake)

	st, err := svc.GetBGPStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, &rest.BGPStatusResponse{
		LocalASN: 65001, RouterID: "192.0.2.1", PeerCount: 2,
		EstablishedPeers: 1, PrefixesAnnounced: 3, Running: true,
	}, st)

	peers, err := svc.ListBGPPeers(ctx)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, "192.0.2.2", peers[0].Address)
	assert.Equal(t, fake.peers[0].GetUptime().AsTime(), peers[0].Uptime)

	require.NoError(t, svc.AnnouncePrefix(ctx, "198.51.100.0/24", "192.0.2.1"))
	assert.Equal(t, "198.51.100.0/24", fake.announced.GetPrefix())
	require.NoError(t, svc.WithdrawPrefix(ctx, "198.51.100.0/24"))
	assert.Equal(t, "198.51.100.0/24", fake.withdrawn.GetPrefix())

	prefixes, err := svc.ListAnnouncedPrefixes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []rest.AnnouncedPrefixResponse{{
		Prefix: "203.0.113.0/24", NextHop: "192.0.2.1", AnnouncedAt: bgpTestAnnouncedAt,
	}}, prefixes)
}

func TestGatewayRESTService_BGPStatusWithoutStatusIsNotNil(t *testing.T) {
	svc := newGatewayRESTService(nil, nil)
	svc.SetGatewayBGPController(&fakeGatewayBGPController{})

	st, err := svc.GetBGPStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &rest.BGPStatusResponse{}, st, "the handler stamps the result, so it must never be nil")
}

func TestGatewayRESTService_BGPNotConfigured(t *testing.T) {
	want := rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}
	cases := map[string]GatewayBGPController{
		"no controller": nil,
		"no speaker":    NewGatewayService(),
	}
	for name, controller := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			svc := newGatewayRESTService(nil, nil)
			if controller != nil {
				svc.SetGatewayBGPController(controller)
			}

			_, err := svc.GetBGPStatus(ctx)
			assert.Equal(t, want, err)
			_, err = svc.ListBGPPeers(ctx)
			assert.Equal(t, want, err)
			assert.Equal(t, want, svc.AnnouncePrefix(ctx, "198.51.100.0/24", ""))
			assert.Equal(t, want, svc.WithdrawPrefix(ctx, "198.51.100.0/24"))
			_, err = svc.ListAnnouncedPrefixes(ctx)
			assert.Equal(t, want, err)
		})
	}
}

func TestGatewayRESTService_BGPInvalidInput(t *testing.T) {
	ctx := context.Background()
	svc := newGatewayRESTService(nil, nil)
	svc.SetGatewayBGPController(NewGatewayService())

	assert.Equal(t, rest.ErrInvalidPrefix{Prefix: "not-a-prefix"}, svc.AnnouncePrefix(ctx, "not-a-prefix", ""))
	assert.Equal(t, rest.ErrInvalidIPAddress{IP: "not-an-ip"}, svc.AnnouncePrefix(ctx, "198.51.100.0/24", "not-an-ip"))
	assert.Equal(t, rest.ErrInvalidPrefix{Prefix: "not-a-prefix"}, svc.WithdrawPrefix(ctx, "not-a-prefix"))
}

func TestGatewayRESTService_BGPBackendErrorPassesThrough(t *testing.T) {
	ctx := context.Background()
	svc := newGatewayRESTService(nil, nil)
	svc.SetGatewayBGPController(&fakeGatewayBGPController{err: errBGPTestBackend})

	_, err := svc.GetBGPStatus(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	_, err = svc.ListBGPPeers(ctx)
	assert.Equal(t, errBGPTestBackend, err)
	assert.Equal(t, errBGPTestBackend, svc.AnnouncePrefix(ctx, "198.51.100.0/24", ""))
	assert.Equal(t, errBGPTestBackend, svc.WithdrawPrefix(ctx, "198.51.100.0/24"))
	_, err = svc.ListAnnouncedPrefixes(ctx)
	assert.Equal(t, errBGPTestBackend, err)
}

func TestGatewayBGPRESTError(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		nextHop string
		err     error
		want    error
	}{
		{"unavailable is not configured", "", "", grpcstatus.Error(codes.Unavailable, "down"),
			rest.ErrGatewayFeatureNotConfigured{Feature: "bgp"}},
		{"bad prefix", "x", "", grpcstatus.Error(codes.InvalidArgument, "bad"),
			rest.ErrInvalidPrefix{Prefix: "x"}},
		{"bad next hop", "198.51.100.0/24", "y", grpcstatus.Error(codes.InvalidArgument, "bad"),
			rest.ErrInvalidIPAddress{IP: "y"}},
		{"good next hop blames the prefix", "x", "192.0.2.1", grpcstatus.Error(codes.InvalidArgument, "bad"),
			rest.ErrInvalidPrefix{Prefix: "x"}},
		{"other codes pass through", "", "", errBGPTestBackend, errBGPTestBackend},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, gatewayBGPRESTError(c.prefix, c.nextHop, c.err))
		})
	}
}

func TestErrBGPAttributeUnsupported(t *testing.T) {
	err := ErrBGPAttributeUnsupported{Attribute: "med"}

	assert.Equal(t, "BGP path attribute not supported on announce: med", err.Error())
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
}

func TestRESTServer_SetGatewayBGPService(t *testing.T) {
	t.Run("nil is ignored", func(t *testing.T) {
		s := newTestRESTServerForPhase35(t)
		s.SetGatewayBGPService(nil)
		assert.Nil(t, s.gatewayService)
	})
	t.Run("wires the BGP routes", func(t *testing.T) {
		s := newTestRESTServerForPhase35(t)
		s.SetGatewayBGPService(newFakeGatewayBGPController())

		code, body := doJSON(t, s, http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var st rest.BGPStatusResponse
		require.NoError(t, json.Unmarshal(body, &st))
		assert.Equal(t, uint32(65001), st.LocalASN)
	})
}

// =============================================================================
// Transport parity
// =============================================================================

// bgpParityTransports drives one GatewayService through every transport
// binding the daemon wires: gRPC (which Unix and the embedded SDK share),
// QUIC over the wire handler, REST over the daemon router, and MCP through
// the production provider.
type bgpParityTransports struct {
	grpc *GatewayService
	quic *QUICServiceHandler
	rest *RESTServer
	mcp  *MCPServiceProvider
}

func newBGPParityTransports(t *testing.T, speaker BGPSpeakerInterface) bgpParityTransports {
	t.Helper()
	svc := NewGatewayService()
	if speaker != nil {
		svc.SetBGPSpeaker(speaker)
	}
	logger := logging.DefaultLogger()
	adapter := newFullGatewayQUICAdapter(ipamBackends.NewMemoryBackend(), nil, nil, nil, svc, nil)
	restServer := newTestRESTServerForPhase35(t)
	restServer.SetGatewayBGPService(svc)
	return bgpParityTransports{
		grpc: svc,
		quic: newTestQUICServiceHandler(logger, WithQUICGatewayHandler(quic.NewGatewayHandler(logger, adapter))),
		rest: restServer,
		mcp:  NewMCPServiceProvider(&MCPServiceProviderConfig{GatewayBGP: svc}),
	}
}

func bgpQUICCall(t *testing.T, h *QUICServiceHandler, subOpcode byte, body interface{}) *quicwire.Response {
	t.Helper()
	encoded, err := quicwire.EncodePayload(body)
	require.NoError(t, err)
	payload := append([]byte{subOpcode}, encoded...)
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: 0x2F, Payload: payload})
	require.NotNil(t, resp)
	return resp
}

func TestGatewayBGP_TransportParity(t *testing.T) {
	ctx := context.Background()
	speaker := newMockBGPSpeaker()
	speaker.peers[0].Uptime = time.Hour
	speaker.paths[bgp.AFamilyIPv4Unicast] = []bgp.Path{{
		Family:  bgp.AFamilyIPv4Unicast,
		Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
		NextHop: netip.MustParseAddr("192.0.2.1"),
		Age:     bgpTestAnnouncedAt,
	}}
	tr := newBGPParityTransports(t, speaker)
	const prefix = "198.51.100.0/24"

	t.Run("gRPC", func(t *testing.T) {
		st, err := tr.grpc.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint32(65001), st.GetStatus().GetLocalAsn())
		assert.Equal(t, "10.0.0.1", st.GetStatus().GetRouterId())

		peers, err := tr.grpc.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
		require.NoError(t, err)
		require.Len(t, peers.GetPeers(), 1)
		assert.Equal(t, "10.0.0.2", peers.GetPeers()[0].GetAddress())
		assert.WithinDuration(t, time.Now().Add(-time.Hour), peers.GetPeers()[0].GetUptime().AsTime(), 2*time.Second)

		_, err = tr.grpc.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{Prefix: prefix})
		require.NoError(t, err)
		_, err = tr.grpc.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
		require.NoError(t, err)

		prefixes, err := tr.grpc.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
		require.NoError(t, err)
		require.Len(t, prefixes.GetPrefixes(), 1)
		assert.Equal(t, "203.0.113.0/24", prefixes.GetPrefixes()[0].GetPrefix())
		assert.Equal(t, "192.0.2.1", prefixes.GetPrefixes()[0].GetNextHop())
	})

	t.Run("QUIC", func(t *testing.T) {
		resp := bgpQUICCall(t, tr.quic, quicwire.OpGatewayBGPStatus, struct{}{})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		var st quic.GatewayBGPStatusResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &st))
		assert.Equal(t, uint32(65001), st.Status.LocalAS)
		assert.Equal(t, "10.0.0.1", st.Status.RouterID)

		resp = bgpQUICCall(t, tr.quic, quicwire.OpGatewayBGPPeers, struct{}{})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		var peers quic.GatewayBGPPeersResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &peers))
		require.Len(t, peers.Peers, 1)
		assert.Equal(t, "10.0.0.2", peers.Peers[0].Address)
		assert.InDelta(t, 3600, peers.Peers[0].Uptime, 2)

		resp = bgpQUICCall(t, tr.quic, quicwire.OpGatewayAnnouncePrefix, quic.GatewayAnnouncePrefixRequest{Prefix: prefix})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		resp = bgpQUICCall(t, tr.quic, quicwire.OpGatewayWithdrawPrefix, quic.GatewayWithdrawPrefixRequest{Prefix: prefix})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

		resp = bgpQUICCall(t, tr.quic, quicwire.OpGatewayListPrefixes, quic.GatewayListPrefixesRequest{})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		var prefixes quic.GatewayListPrefixesResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &prefixes))
		require.Len(t, prefixes.Prefixes, 1)
		assert.Equal(t, "203.0.113.0/24", prefixes.Prefixes[0].Prefix)
		assert.Equal(t, bgpTestAnnouncedAt.Unix(), prefixes.Prefixes[0].AnnouncedAt)
	})

	t.Run("REST", func(t *testing.T) {
		code, body := doJSON(t, tr.rest, http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var st rest.BGPStatusResponse
		require.NoError(t, json.Unmarshal(body, &st))
		assert.Equal(t, uint32(65001), st.LocalASN)
		assert.Equal(t, "10.0.0.1", st.RouterID)

		code, body = doJSON(t, tr.rest, http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var peers rest.BGPPeerListResponse
		require.NoError(t, json.Unmarshal(body, &peers))
		require.Len(t, peers.Peers, 1)
		assert.Equal(t, "10.0.0.2", peers.Peers[0].Address)
		assert.WithinDuration(t, time.Now().Add(-time.Hour), peers.Peers[0].Uptime, 2*time.Second)

		code, body = doJSON(t, tr.rest, http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", rest.AnnouncePrefixRequest{Prefix: prefix})
		require.Equal(t, http.StatusCreated, code, string(body))
		code, body = doJSON(t, tr.rest, http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/"+url.PathEscape(prefix), nil)
		require.Equal(t, http.StatusOK, code, string(body))

		code, body = doJSON(t, tr.rest, http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var prefixes rest.AnnouncedPrefixListResponse
		require.NoError(t, json.Unmarshal(body, &prefixes))
		require.Len(t, prefixes.Prefixes, 1)
		assert.Equal(t, "203.0.113.0/24", prefixes.Prefixes[0].Prefix)
		assert.True(t, bgpTestAnnouncedAt.Equal(prefixes.Prefixes[0].AnnouncedAt))
	})

	t.Run("MCP", func(t *testing.T) {
		st, err := tr.mcp.GatewayBGPStatus(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint32(65001), st.(*bgpStatusView).LocalASN)
		assert.Equal(t, "10.0.0.1", st.(*bgpStatusView).RouterID)

		peers, err := tr.mcp.GatewayBGPPeers(ctx)
		require.NoError(t, err)
		require.Len(t, peers, 1)
		peer := peers[0].(*bgpPeerView)
		assert.Equal(t, "10.0.0.2", peer.Address)
		require.NotNil(t, peer.EstablishedAt)
		assert.WithinDuration(t, time.Now().Add(-time.Hour), *peer.EstablishedAt, 2*time.Second)

		require.NoError(t, tr.mcp.GatewayBGPAnnounce(ctx, prefix, ""))
		require.NoError(t, tr.mcp.GatewayBGPWithdraw(ctx, prefix))

		prefixes, err := tr.mcp.GatewayBGPPrefixes(ctx)
		require.NoError(t, err)
		require.Len(t, prefixes, 1)
		assert.Equal(t, "203.0.113.0/24", prefixes[0].(*announcedPrefixView).Prefix)
	})
}

// TestGatewayBGP_QUICClientReceivesEveryPeerAndPrefix proves the SDK's QUIC
// client returns the same whole lists gRPC does when the gateway holds more
// peers and announced prefixes than the daemon serves in one reply: the
// call travels a loopback QUIC listener into the real gateway handler.
func TestGatewayBGP_QUICClientReceivesEveryPeerAndPrefix(t *testing.T) {
	const entries = 2500
	speaker := newMockBGPSpeaker()
	speaker.peers = make([]bgp.PeerInfo, entries)
	paths := make([]bgp.Path, entries)
	for i := range entries {
		network := netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0})
		speaker.peers[i] = bgp.PeerInfo{Address: network.Next(), ASN: uint32(64512 + i), State: bgp.PeerStateEstablished}
		paths[i] = bgp.Path{Family: bgp.AFamilyIPv4Unicast, Prefix: netip.PrefixFrom(network, 24),
			NextHop: netip.MustParseAddr("192.0.2.1"), Age: bgpTestAnnouncedAt}
	}
	speaker.paths[bgp.AFamilyIPv4Unicast] = paths
	svc := NewGatewayService()
	svc.SetBGPSpeaker(speaker)
	logger := logging.DefaultLogger()
	bundle := operatorTLSBundle(t)
	handler := newTestQUICServiceHandler(logger, mtlsQUICAuth(t, bundle), WithQUICGatewayHandler(
		quic.NewGatewayHandler(logger, newFullGatewayQUICAdapter(ipamBackends.NewMemoryBackend(), nil, nil, nil, svc, nil))))
	conn := newPhase35QUICClient(t, handler, bundle).Connection()
	ctx := context.Background()

	wantPeers, err := svc.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
	require.NoError(t, err)
	gotPeers := &platformv1.ListBGPPeersResponse{}
	require.NoError(t, conn.Invoke(ctx, platformv1.GatewayService_ListBGPPeers_FullMethodName,
		&platformv1.ListBGPPeersRequest{}, gotPeers))
	require.Len(t, gotPeers.GetPeers(), entries)
	for i, peer := range gotPeers.GetPeers() {
		require.Equal(t, wantPeers.GetPeers()[i].GetAddress(), peer.GetAddress(), "peer %d", i)
	}

	wantPrefixes, err := svc.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
	require.NoError(t, err)
	gotPrefixes := &platformv1.ListAnnouncedPrefixesResponse{}
	require.NoError(t, conn.Invoke(ctx, platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName,
		&platformv1.ListAnnouncedPrefixesRequest{}, gotPrefixes))
	require.Len(t, gotPrefixes.GetPrefixes(), entries)
	for i, prefix := range gotPrefixes.GetPrefixes() {
		require.Equal(t, wantPrefixes.GetPrefixes()[i].GetPrefix(), prefix.GetPrefix(), "prefix %d", i)
	}
}

func TestGatewayBGP_TransportParityNotConfigured(t *testing.T) {
	ctx := context.Background()
	tr := newBGPParityTransports(t, nil)
	const prefix = "198.51.100.0/24"

	t.Run("gRPC", func(t *testing.T) {
		calls := map[string]func() error{
			"status": func() error {
				_, err := tr.grpc.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})
				return err
			},
			"peers": func() error {
				_, err := tr.grpc.ListBGPPeers(ctx, &platformv1.ListBGPPeersRequest{})
				return err
			},
			"announce": func() error {
				_, err := tr.grpc.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{Prefix: prefix})
				return err
			},
			"withdraw": func() error {
				_, err := tr.grpc.WithdrawPrefix(ctx, &platformv1.WithdrawPrefixRequest{Prefix: prefix})
				return err
			},
			"prefixes": func() error {
				_, err := tr.grpc.ListAnnouncedPrefixes(ctx, &platformv1.ListAnnouncedPrefixesRequest{})
				return err
			},
		}
		for name, call := range calls {
			assert.Equal(t, codes.Unavailable, grpcstatus.Code(call()), name)
		}
	})

	t.Run("QUIC", func(t *testing.T) {
		calls := map[string]*quicwire.Response{
			"status":   bgpQUICCall(t, tr.quic, quicwire.OpGatewayBGPStatus, struct{}{}),
			"peers":    bgpQUICCall(t, tr.quic, quicwire.OpGatewayBGPPeers, struct{}{}),
			"announce": bgpQUICCall(t, tr.quic, quicwire.OpGatewayAnnouncePrefix, quic.GatewayAnnouncePrefixRequest{Prefix: prefix}),
			"withdraw": bgpQUICCall(t, tr.quic, quicwire.OpGatewayWithdrawPrefix, quic.GatewayWithdrawPrefixRequest{Prefix: prefix}),
			"prefixes": bgpQUICCall(t, tr.quic, quicwire.OpGatewayListPrefixes, quic.GatewayListPrefixesRequest{}),
		}
		for name, resp := range calls {
			assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "%s: %s", name, resp.Payload)
		}
	})

	t.Run("REST", func(t *testing.T) {
		calls := []struct {
			method, path string
			body         interface{}
		}{
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/status", nil},
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", nil},
			{http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", rest.AnnouncePrefixRequest{Prefix: prefix}},
			{http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/" + url.PathEscape(prefix), nil},
			{http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", nil},
		}
		for _, c := range calls {
			code, body := doJSON(t, tr.rest, c.method, c.path, c.body)
			assert.Equal(t, http.StatusServiceUnavailable, code, "%s %s: %s", c.method, c.path, body)
		}
	})

	t.Run("MCP", func(t *testing.T) {
		calls := map[string]func() error{
			"status":   func() error { _, err := tr.mcp.GatewayBGPStatus(ctx); return err },
			"peers":    func() error { _, err := tr.mcp.GatewayBGPPeers(ctx); return err },
			"announce": func() error { return tr.mcp.GatewayBGPAnnounce(ctx, prefix, "") },
			"withdraw": func() error { return tr.mcp.GatewayBGPWithdraw(ctx, prefix) },
			"prefixes": func() error { _, err := tr.mcp.GatewayBGPPrefixes(ctx); return err },
		}
		for name, call := range calls {
			err := call()
			assert.Equal(t, codes.Unavailable, grpcstatus.Code(err), name)
		}
	})
}

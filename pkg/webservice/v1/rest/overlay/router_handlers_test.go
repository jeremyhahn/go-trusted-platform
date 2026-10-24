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

package overlay

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingOverlayServer records the request each handler built and answers
// with the canned response for that method, or err when it is set.
type recordingOverlayServer struct {
	platformv1.UnimplementedOverlayServiceServer
	got proto.Message
	err error
}

var (
	seenAt = timestamppb.New(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC))

	cannedStatus = &platformv1.GetOverlayStatusResponse{Status: &platformv1.OverlayStatus{
		NodeId: "node-01", VtepIp: "10.0.0.1", VtepCount: 3, VniCount: 2,
		TunnelCount: 4, RemoteMacCount: 9, Healthy: true, VxlanPort: 4789, UnderlayMtu: 9000,
	}}
	cannedVTEP = &platformv1.VTEPInfo{
		NodeId: "node-02", Ip: "10.0.0.2", Healthy: true, LastSeen: seenAt,
		Vnis: []uint32{1000100, 1000200}, MacCount: 5, BytesSent: 1 << 40, BytesRecv: 42,
	}
	cannedVNI = &platformv1.VNI{
		Id: "vni-1000100", MacCount: 5, CreatedAt: seenAt,
		Config: &platformv1.VNIConfig{Vni: 1000100, Vlan: 100},
	}
	cannedTunnel = &platformv1.TunnelInfo{
		LocalVtep: "10.0.0.1", RemoteVtep: "10.0.0.2", Vni: 1000100,
		State: "up", BytesTx: 7, BytesRx: 8,
	}
	cannedMAC = &platformv1.RemoteMACEntry{
		Mac: "02:00:00:00:00:01", Vni: 1000100, RemoteVtep: "10.0.0.2", LearnedAt: seenAt,
	}
	okStatus = &platformv1.Status{Success: true}
)

func (s *recordingOverlayServer) answer(req, resp proto.Message) (proto.Message, error) {
	s.got = req
	if s.err != nil {
		return nil, s.err
	}
	return resp, nil
}

func (s *recordingOverlayServer) GetOverlayStatus(_ context.Context, r *platformv1.GetOverlayStatusRequest) (*platformv1.GetOverlayStatusResponse, error) {
	resp, err := s.answer(r, cannedStatus)
	return asResp[*platformv1.GetOverlayStatusResponse](resp), err
}

func (s *recordingOverlayServer) ListVTEPs(_ context.Context, r *platformv1.ListVTEPsRequest) (*platformv1.ListVTEPsResponse, error) {
	resp, err := s.answer(r, &platformv1.ListVTEPsResponse{Vteps: []*platformv1.VTEPInfo{cannedVTEP}})
	return asResp[*platformv1.ListVTEPsResponse](resp), err
}

func (s *recordingOverlayServer) GetVTEP(_ context.Context, r *platformv1.GetVTEPRequest) (*platformv1.GetVTEPResponse, error) {
	resp, err := s.answer(r, &platformv1.GetVTEPResponse{Vtep: cannedVTEP})
	return asResp[*platformv1.GetVTEPResponse](resp), err
}

func (s *recordingOverlayServer) ListVNIs(_ context.Context, r *platformv1.ListVNIsRequest) (*platformv1.ListVNIsResponse, error) {
	resp, err := s.answer(r, &platformv1.ListVNIsResponse{Vnis: []*platformv1.VNI{cannedVNI}})
	return asResp[*platformv1.ListVNIsResponse](resp), err
}

func (s *recordingOverlayServer) CreateVNI(_ context.Context, r *platformv1.CreateVNIRequest) (*platformv1.CreateVNIResponse, error) {
	resp, err := s.answer(r, &platformv1.CreateVNIResponse{Status: okStatus, Vni: cannedVNI})
	return asResp[*platformv1.CreateVNIResponse](resp), err
}

func (s *recordingOverlayServer) DeleteVNI(_ context.Context, r *platformv1.DeleteVNIRequest) (*platformv1.DeleteVNIResponse, error) {
	resp, err := s.answer(r, &platformv1.DeleteVNIResponse{Status: okStatus})
	return asResp[*platformv1.DeleteVNIResponse](resp), err
}

func (s *recordingOverlayServer) ListTunnels(_ context.Context, r *platformv1.ListTunnelsRequest) (*platformv1.ListTunnelsResponse, error) {
	resp, err := s.answer(r, &platformv1.ListTunnelsResponse{Tunnels: []*platformv1.TunnelInfo{cannedTunnel}})
	return asResp[*platformv1.ListTunnelsResponse](resp), err
}

func (s *recordingOverlayServer) GetTunnelStats(_ context.Context, r *platformv1.GetTunnelStatsRequest) (*platformv1.GetTunnelStatsResponse, error) {
	resp, err := s.answer(r, &platformv1.GetTunnelStatsResponse{Tunnel: cannedTunnel})
	return asResp[*platformv1.GetTunnelStatsResponse](resp), err
}

func (s *recordingOverlayServer) ListRemoteMACs(_ context.Context, r *platformv1.ListRemoteMACsRequest) (*platformv1.ListRemoteMACsResponse, error) {
	resp, err := s.answer(r, &platformv1.ListRemoteMACsResponse{Macs: []*platformv1.RemoteMACEntry{cannedMAC}})
	return asResp[*platformv1.ListRemoteMACsResponse](resp), err
}

func (s *recordingOverlayServer) ForgetMAC(_ context.Context, r *platformv1.ForgetMACRequest) (*platformv1.ForgetMACResponse, error) {
	resp, err := s.answer(r, &platformv1.ForgetMACResponse{Status: okStatus})
	return asResp[*platformv1.ForgetMACResponse](resp), err
}

// asResp narrows a canned response to its concrete type; nil stays nil.
func asResp[T proto.Message](m proto.Message) T {
	var zero T
	if m == nil {
		return zero
	}
	return m.(T)
}

// overlayCall is one SDK call through the REST transport: the request the
// server must receive and the response the caller must get back.
type overlayCall struct {
	name     string
	call     func(context.Context, platformv1.OverlayServiceClient) (proto.Message, error)
	wantReq  proto.Message
	wantResp proto.Message
}

func overlayCalls() []overlayCall {
	return []overlayCall{
		{
			name: "GetOverlayStatus",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})
			},
			wantReq:  &platformv1.GetOverlayStatusRequest{},
			wantResp: cannedStatus,
		},
		{
			name: "ListVTEPs",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})
			},
			wantReq:  &platformv1.ListVTEPsRequest{},
			wantResp: &platformv1.ListVTEPsResponse{Vteps: []*platformv1.VTEPInfo{cannedVTEP}},
		},
		{
			name: "GetVTEP",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.GetVTEP(ctx, &platformv1.GetVTEPRequest{NodeId: "node-02"})
			},
			wantReq:  &platformv1.GetVTEPRequest{NodeId: "node-02"},
			wantResp: &platformv1.GetVTEPResponse{Vtep: cannedVTEP},
		},
		{
			name: "ListVNIs",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.ListVNIs(ctx, &platformv1.ListVNIsRequest{})
			},
			wantReq:  &platformv1.ListVNIsRequest{},
			wantResp: &platformv1.ListVNIsResponse{Vnis: []*platformv1.VNI{cannedVNI}},
		},
		{
			name: "CreateVNI",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.CreateVNI(ctx, &platformv1.CreateVNIRequest{Config: &platformv1.VNIConfig{
					Vni: 1000100, Vlan: 100, Name: "tenant-a", Labels: map[string]string{"env": "lab"},
				}})
			},
			wantReq: &platformv1.CreateVNIRequest{Config: &platformv1.VNIConfig{
				Vni: 1000100, Vlan: 100, Name: "tenant-a", Labels: map[string]string{"env": "lab"},
			}},
			wantResp: &platformv1.CreateVNIResponse{Status: okStatus, Vni: cannedVNI},
		},
		{
			name: "DeleteVNI",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{Vni: 1000100})
			},
			wantReq:  &platformv1.DeleteVNIRequest{Vni: 1000100},
			wantResp: &platformv1.DeleteVNIResponse{Status: okStatus},
		},
		{
			name: "ListTunnels",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.ListTunnels(ctx, &platformv1.ListTunnelsRequest{Vni: 1000100})
			},
			wantReq:  &platformv1.ListTunnelsRequest{Vni: 1000100},
			wantResp: &platformv1.ListTunnelsResponse{Tunnels: []*platformv1.TunnelInfo{cannedTunnel}},
		},
		{
			name: "GetTunnelStats",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.GetTunnelStats(ctx, &platformv1.GetTunnelStatsRequest{RemoteVtep: "10.0.0.2", Vni: 1000100})
			},
			wantReq:  &platformv1.GetTunnelStatsRequest{RemoteVtep: "10.0.0.2", Vni: 1000100},
			wantResp: &platformv1.GetTunnelStatsResponse{Tunnel: cannedTunnel},
		},
		{
			name: "ListRemoteMACs",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{Vni: 1000100})
			},
			wantReq:  &platformv1.ListRemoteMACsRequest{Vni: 1000100},
			wantResp: &platformv1.ListRemoteMACsResponse{Macs: []*platformv1.RemoteMACEntry{cannedMAC}},
		},
		{
			name: "ForgetMAC",
			call: func(ctx context.Context, c platformv1.OverlayServiceClient) (proto.Message, error) {
				return c.ForgetMAC(ctx, &platformv1.ForgetMACRequest{Mac: "02:00:00:00:00:01", Vni: 1000100})
			},
			wantReq:  &platformv1.ForgetMACRequest{Mac: "02:00:00:00:00:01", Vni: 1000100},
			wantResp: &platformv1.ForgetMACResponse{Status: okStatus},
		},
	}
}

// TestSDKREST_EveryMethodRoundTrips: each SDK call reaches its handler with
// every request field intact and returns the server's response unchanged.
// The filters of ListTunnels, GetTunnelStats and ListRemoteMACs travel in the
// query string; before this test they went in a GET body the router never
// read, so the server saw no VNI and no remote VTEP.
func TestSDKREST_EveryMethodRoundTrips(t *testing.T) {
	for _, tc := range overlayCalls() {
		t.Run(tc.name, func(t *testing.T) {
			srv := &recordingOverlayServer{}
			_, client := serveOverlay(t, srv)

			resp, err := tc.call(context.Background(), client)

			require.NoError(t, err)
			require.NotNil(t, srv.got, "the request reached no handler")
			assert.True(t, proto.Equal(tc.wantReq, srv.got), "server got %v, want %v", srv.got, tc.wantReq)
			assert.True(t, proto.Equal(tc.wantResp, resp), "caller got %v, want %v", resp, tc.wantResp)
		})
	}
}

// TestSDKREST_ServerErrorKeepsItsCode: a gRPC status from the server comes
// back to the SDK caller with the same code on every method.
func TestSDKREST_ServerErrorKeepsItsCode(t *testing.T) {
	serverErrs := []codes.Code{codes.NotFound, codes.InvalidArgument, codes.Unavailable}
	for _, tc := range overlayCalls() {
		for _, code := range serverErrs {
			t.Run(tc.name+"/"+code.String(), func(t *testing.T) {
				srv := &recordingOverlayServer{err: status.Error(code, "overlay refused")}
				_, client := serveOverlay(t, srv)

				_, err := tc.call(context.Background(), client)

				require.Error(t, err)
				assert.Equal(t, code, status.Code(err))
				assert.NotNil(t, srv.got, "the error did not come from the handler")
			})
		}
	}
}

// TestOverlayRouter_BadInputIsRefusedBeforeTheServer: a malformed query
// parameter or body is a 400 and never reaches the server.
func TestOverlayRouter_BadInputIsRefusedBeforeTheServer(t *testing.T) {
	cases := []struct {
		name, method, path, body string
	}{
		{"ListTunnels non-numeric vni", http.MethodGet, "/api/v1/overlay/tunnels?vni=abc", ""},
		{"GetTunnelStats negative vni", http.MethodGet, "/api/v1/overlay/tunnels/stats?remote_vtep=10.0.0.2&vni=-1", ""},
		{"ListRemoteMACs vni overflows uint32", http.MethodGet, "/api/v1/overlay/macs?vni=4294967296", ""},
		{"ForgetMAC non-numeric vni", http.MethodDelete, "/api/v1/overlay/macs?mac=02:00:00:00:00:01&vni=x", ""},
		{"DeleteVNI overflows uint32", http.MethodDelete, "/api/v1/overlay/vnis/4294967296", ""},
		{"CreateVNI malformed JSON", http.MethodPost, "/api/v1/overlay/vnis", `{"config":`},
		{"CreateVNI unknown field type", http.MethodPost, "/api/v1/overlay/vnis", `{"config":{"vni":"many"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &recordingOverlayServer{}
			server, _ := serveOverlay(t, srv)

			code := doRaw(t, server.Client(), tc.method, server.URL+tc.path, tc.body)

			assert.Equal(t, http.StatusBadRequest, code)
			assert.Nil(t, srv.got, "bad input reached the server")
		})
	}
}

// TestOverlayRouter_CreateVNIAnswers201: creation is 201 Created, not 200.
func TestOverlayRouter_CreateVNIAnswers201(t *testing.T) {
	srv := &recordingOverlayServer{}
	server, _ := serveOverlay(t, srv)

	code := doRaw(t, server.Client(), http.MethodPost, server.URL+"/api/v1/overlay/vnis",
		`{"config":{"vni":1000100,"vlan":100}}`)

	assert.Equal(t, http.StatusCreated, code)
	assert.True(t, proto.Equal(&platformv1.CreateVNIRequest{
		Config: &platformv1.VNIConfig{Vni: 1000100, Vlan: 100},
	}, srv.got), "server got %v", srv.got)
}

// TestOverlayRouter_FiltersAreOptional: an absent filter reaches the server
// as zero, which the server reads as "every VNI".
func TestOverlayRouter_FiltersAreOptional(t *testing.T) {
	cases := []struct {
		path string
		want proto.Message
	}{
		{"/api/v1/overlay/tunnels", &platformv1.ListTunnelsRequest{}},
		{"/api/v1/overlay/macs", &platformv1.ListRemoteMACsRequest{}},
		{"/api/v1/overlay/tunnels/stats", &platformv1.GetTunnelStatsRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			srv := &recordingOverlayServer{}
			server, _ := serveOverlay(t, srv)

			code := doRaw(t, server.Client(), http.MethodGet, server.URL+tc.path, "")

			assert.Equal(t, http.StatusOK, code)
			assert.True(t, proto.Equal(tc.want, srv.got), "server got %v, want %v", srv.got, tc.want)
		})
	}
}

// doRaw sends one request without the SDK and returns the HTTP status.
func doRaw(t *testing.T, client *http.Client, method, url, body string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode
}

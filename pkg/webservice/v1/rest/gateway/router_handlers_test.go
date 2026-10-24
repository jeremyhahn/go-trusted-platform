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

package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errFakeReplyType reports a test case whose canned reply does not match
// the RPC it was routed to, so a mis-wired route fails the test instead
// of answering with an empty message.
type errFakeReplyType struct{}

func (errFakeReplyType) Error() string {
	return "fake gateway service: reply type does not match the RPC"
}

// fakeGatewayService records the request each RPC received and answers
// with a canned reply or error.
type fakeGatewayService struct {
	platformv1.UnimplementedGatewayServiceServer

	reply   proto.Message
	err     error
	lastReq proto.Message
}

func answer[T proto.Message](f *fakeGatewayService, req proto.Message) (T, error) {
	f.lastReq = req
	var zero T
	if f.err != nil {
		return zero, f.err
	}
	reply, ok := f.reply.(T)
	if !ok {
		return zero, errFakeReplyType{}
	}
	return reply, nil
}

func (f *fakeGatewayService) GetGatewayStatus(_ context.Context, req *platformv1.GetGatewayStatusRequest) (*platformv1.GetGatewayStatusResponse, error) {
	return answer[*platformv1.GetGatewayStatusResponse](f, req)
}

func (f *fakeGatewayService) SetGatewayMode(_ context.Context, req *platformv1.SetGatewayModeRequest) (*platformv1.SetGatewayModeResponse, error) {
	return answer[*platformv1.SetGatewayModeResponse](f, req)
}

func (f *fakeGatewayService) GetBGPStatus(_ context.Context, req *platformv1.GetBGPStatusRequest) (*platformv1.GetBGPStatusResponse, error) {
	return answer[*platformv1.GetBGPStatusResponse](f, req)
}

func (f *fakeGatewayService) ListBGPPeers(_ context.Context, req *platformv1.ListBGPPeersRequest) (*platformv1.ListBGPPeersResponse, error) {
	return answer[*platformv1.ListBGPPeersResponse](f, req)
}

func (f *fakeGatewayService) ListAnnouncedPrefixes(_ context.Context, req *platformv1.ListAnnouncedPrefixesRequest) (*platformv1.ListAnnouncedPrefixesResponse, error) {
	return answer[*platformv1.ListAnnouncedPrefixesResponse](f, req)
}

func (f *fakeGatewayService) AnnouncePrefix(_ context.Context, req *platformv1.AnnouncePrefixRequest) (*platformv1.AnnouncePrefixResponse, error) {
	return answer[*platformv1.AnnouncePrefixResponse](f, req)
}

func (f *fakeGatewayService) WithdrawPrefix(_ context.Context, req *platformv1.WithdrawPrefixRequest) (*platformv1.WithdrawPrefixResponse, error) {
	return answer[*platformv1.WithdrawPrefixResponse](f, req)
}

func (f *fakeGatewayService) ListIPAMPools(_ context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
	return answer[*platformv1.ListIPAMPoolsResponse](f, req)
}

func (f *fakeGatewayService) ListAllocations(_ context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
	return answer[*platformv1.ListAllocationsResponse](f, req)
}

func (f *fakeGatewayService) AllocateIP(_ context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
	return answer[*platformv1.AllocateIPResponse](f, req)
}

func (f *fakeGatewayService) ReleaseIP(_ context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
	return answer[*platformv1.ReleaseIPResponse](f, req)
}

// gatewayRouteCase is one GatewayRouter route: the HTTP request, the
// RPC request it must forward, the reply the service gives and the
// status the route answers with.
type gatewayRouteCase struct {
	name     string
	method   string
	path     string
	body     string
	wantReq  proto.Message
	reply    proto.Message
	wantCode int
}

func gatewayRouteCases() []gatewayRouteCase {
	return []gatewayRouteCase{
		{
			name: "get status", method: http.MethodGet, path: "/api/v1/gateway/status",
			wantReq: &platformv1.GetGatewayStatusRequest{},
			reply: &platformv1.GetGatewayStatusResponse{Status: &platformv1.GatewayStatus{
				Id: "gw-1", NodeId: "node-01", Modes: 3, Tier: "datacenter",
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "set mode", method: http.MethodPost, path: "/api/v1/gateway/mode", body: `{"modes":5}`,
			wantReq: &platformv1.SetGatewayModeRequest{Modes: 5},
			reply: &platformv1.SetGatewayModeResponse{
				Status:        &platformv1.Status{Success: true, Message: "mode set"},
				GatewayStatus: &platformv1.GatewayStatus{Id: "gw-1", Modes: 5},
			},
			wantCode: http.StatusOK,
		},
		{
			name: "get bgp status", method: http.MethodGet, path: "/api/v1/gateway/bgp/status",
			wantReq: &platformv1.GetBGPStatusRequest{},
			reply: &platformv1.GetBGPStatusResponse{Status: &platformv1.BGPStatus{
				LocalAsn: 64512, RouterId: "10.0.0.1", PeerCount: 2, EstablishedPeers: 1, Running: true,
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "list bgp peers", method: http.MethodGet, path: "/api/v1/gateway/bgp/peers",
			wantReq: &platformv1.ListBGPPeersRequest{},
			reply: &platformv1.ListBGPPeersResponse{Peers: []*platformv1.BGPPeer{
				{Address: "10.0.0.2", Asn: 64513, State: "established", PrefixesReceived: 4},
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "list announced prefixes", method: http.MethodGet, path: "/api/v1/gateway/bgp/prefixes",
			wantReq: &platformv1.ListAnnouncedPrefixesRequest{},
			reply: &platformv1.ListAnnouncedPrefixesResponse{Prefixes: []*platformv1.AnnouncedPrefix{
				{Prefix: "203.0.113.0/24", NextHop: "10.0.0.1"},
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "announce prefix", method: http.MethodPost, path: "/api/v1/gateway/bgp/prefixes",
			body:     `{"prefix":"203.0.113.0/24","next_hop":"10.0.0.1"}`,
			wantReq:  &platformv1.AnnouncePrefixRequest{Prefix: "203.0.113.0/24", NextHop: "10.0.0.1"},
			reply:    &platformv1.AnnouncePrefixResponse{Status: &platformv1.Status{Success: true, Message: "announced"}},
			wantCode: http.StatusCreated,
		},
		{
			name: "withdraw prefix", method: http.MethodDelete, path: "/api/v1/gateway/bgp/prefixes?prefix=203.0.113.0%2F24",
			wantReq:  &platformv1.WithdrawPrefixRequest{Prefix: "203.0.113.0/24"},
			reply:    &platformv1.WithdrawPrefixResponse{Status: &platformv1.Status{Success: true, Message: "withdrawn"}},
			wantCode: http.StatusOK,
		},
		{
			name: "list ipam pools", method: http.MethodGet, path: "/api/v1/gateway/ipam/pools",
			wantReq: &platformv1.ListIPAMPoolsRequest{},
			reply: &platformv1.ListIPAMPoolsResponse{Pools: []*platformv1.IPAMPool{
				{Id: "prod-v4", Name: "prod-v4", Cidr: "10.0.0.0/24", Total: 254},
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "list allocations", method: http.MethodGet, path: "/api/v1/gateway/ipam/allocations",
			wantReq: &platformv1.ListAllocationsRequest{},
			reply: &platformv1.ListAllocationsResponse{Allocations: []*platformv1.IPAllocation{
				{Ip: "10.0.0.10", PoolId: "prod-v4", Hostname: "node-03", Status: "active"},
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "allocate ip", method: http.MethodPost, path: "/api/v1/gateway/ipam/allocations",
			body:    `{"pool_id":"prod-v4","hostname":"node-04"}`,
			wantReq: &platformv1.AllocateIPRequest{PoolId: "prod-v4", Hostname: "node-04"},
			reply: &platformv1.AllocateIPResponse{Allocation: &platformv1.IPAllocation{
				Ip: "10.0.0.11", PoolId: "prod-v4", Hostname: "node-04", Status: "active",
			}},
			wantCode: http.StatusCreated,
		},
		{
			name: "release ip", method: http.MethodDelete, path: "/api/v1/gateway/ipam/allocations?ip=10.0.0.11",
			wantReq:  &platformv1.ReleaseIPRequest{Ip: "10.0.0.11"},
			reply:    &platformv1.ReleaseIPResponse{Status: &platformv1.Status{Success: true, Message: "released"}},
			wantCode: http.StatusOK,
		},
	}
}

func newGatewayTestRouter(svc platformv1.GatewayServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	NewGatewayRouter(logger, svc, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

func serveGatewayCase(router http.Handler, tc gatewayRouteCase, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, reader))
	return rec
}

func TestGatewayRouter_ForwardsEachRouteToTheService(t *testing.T) {
	for _, tc := range gatewayRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{reply: tc.reply}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if !proto.Equal(svc.lastReq, tc.wantReq) {
				t.Fatalf("forwarded request = %v, want %v", svc.lastReq, tc.wantReq)
			}
			env := decodeIPAMEnvelope(t, rec)
			if !env.Success || env.Code != tc.wantCode {
				t.Fatalf("envelope = {code:%d success:%v}, want {code:%d success:true}", env.Code, env.Success, tc.wantCode)
			}
			got := tc.reply.ProtoReflect().New().Interface()
			if err := protojson.Unmarshal(env.Payload, got); err != nil {
				t.Fatalf("decode payload: %v (payload=%s)", err, env.Payload)
			}
			if !proto.Equal(got, tc.reply) {
				t.Fatalf("payload = %v, want %v", got, tc.reply)
			}
		})
	}
}

func TestGatewayRouter_ServiceErrorsReachTheCaller(t *testing.T) {
	for _, tc := range gatewayRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{err: status.Error(codes.NotFound, "gateway resource not found")}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq == nil {
				t.Fatal("the service was never called")
			}
			if env := decodeIPAMEnvelope(t, rec); env.Success {
				t.Fatalf("envelope reports success for a failed call: %+v", env)
			}
		})
	}
}

func TestGatewayRouter_MalformedBodyAnswers400(t *testing.T) {
	for _, tc := range gatewayRouteCases() {
		if tc.body == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{reply: tc.reply}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "{not json")

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("a malformed body reached the service: %v", svc.lastReq)
			}
		})
	}
}

func TestGatewayRouter_NilServerAnswers503OnEveryRoute(t *testing.T) {
	router := newGatewayTestRouter(nil)
	for _, tc := range gatewayRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveGatewayCase(router, tc, tc.body)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "gateway service is not available") {
				t.Fatalf("body does not name the missing service: %s", rec.Body.String())
			}
		})
	}
}

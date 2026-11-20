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
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func (f *fakeGatewayService) AddVIP(_ context.Context, req *platformv1.AddVIPRequest) (*platformv1.AddVIPResponse, error) {
	return answer[*platformv1.AddVIPResponse](f, req)
}

func (f *fakeGatewayService) RemoveVIP(_ context.Context, req *platformv1.RemoveVIPRequest) (*platformv1.RemoveVIPResponse, error) {
	return answer[*platformv1.RemoveVIPResponse](f, req)
}

func (f *fakeGatewayService) GetVIP(_ context.Context, req *platformv1.GetVIPRequest) (*platformv1.GetVIPResponse, error) {
	return answer[*platformv1.GetVIPResponse](f, req)
}

func (f *fakeGatewayService) ListVIPs(_ context.Context, req *platformv1.ListVIPsRequest) (*platformv1.ListVIPsResponse, error) {
	return answer[*platformv1.ListVIPsResponse](f, req)
}

func (f *fakeGatewayService) SetVIPBackends(_ context.Context, req *platformv1.SetVIPBackendsRequest) (*platformv1.SetVIPBackendsResponse, error) {
	return answer[*platformv1.SetVIPBackendsResponse](f, req)
}

func (f *fakeGatewayService) GetLBStatus(_ context.Context, req *platformv1.GetLBStatusRequest) (*platformv1.GetLBStatusResponse, error) {
	return answer[*platformv1.GetLBStatusResponse](f, req)
}

func (f *fakeGatewayService) GetNAT64Status(_ context.Context, req *platformv1.GetNAT64StatusRequest) (*platformv1.GetNAT64StatusResponse, error) {
	return answer[*platformv1.GetNAT64StatusResponse](f, req)
}

func (f *fakeGatewayService) GetPerfFlows(_ context.Context, req *platformv1.GetPerfFlowsRequest) (*platformv1.GetPerfFlowsResponse, error) {
	return answer[*platformv1.GetPerfFlowsResponse](f, req)
}

func (f *fakeGatewayService) GetPerfDatapath(_ context.Context, req *platformv1.GetPerfDatapathRequest) (*platformv1.GetPerfDatapathResponse, error) {
	return answer[*platformv1.GetPerfDatapathResponse](f, req)
}

func (f *fakeGatewayService) GetPerfConntrack(_ context.Context, req *platformv1.GetPerfConntrackRequest) (*platformv1.GetPerfConntrackResponse, error) {
	return answer[*platformv1.GetPerfConntrackResponse](f, req)
}

func testVIP() *platformv1.VIPConfig {
	return &platformv1.VIPConfig{
		Address: "198.51.100.10", Port: 443, Protocol: "tcp", Algorithm: "hash",
		Backends: []*platformv1.VIPBackend{{Address: "10.0.0.21", Port: 8443, Weight: 1}},
	}
}

func testVIPStatus() *platformv1.VIPStatus {
	return &platformv1.VIPStatus{
		Vip: testVIP(), CtZone: 7, GroupId: 11,
		Backends: []*platformv1.VIPBackendStatus{{
			Backend: &platformv1.VIPBackend{Address: "10.0.0.21", Port: 8443, Weight: 1}, Healthy: true,
		}},
	}
}

// gatewayLBRouteCases are the load balancer, NAT64 and performance routes,
// served at the daemon's /api/v1/sdn/gateway paths so one SDK path reaches
// either server.
func gatewayLBRouteCases() []gatewayRouteCase {
	zone := uint32(7)
	return []gatewayRouteCase{
		{
			name: "add vip", method: http.MethodPost, path: "/api/v1/sdn/gateway/lb/vips",
			body: `{"vip":{"address":"198.51.100.10","port":443,"protocol":"tcp","algorithm":"hash",` +
				`"backends":[{"address":"10.0.0.21","port":8443,"weight":1}]}}`,
			wantReq:  &platformv1.AddVIPRequest{Vip: testVIP()},
			reply:    &platformv1.AddVIPResponse{Status: &platformv1.Status{Success: true}, Vip: testVIPStatus()},
			wantCode: http.StatusCreated,
		},
		{
			name: "list vips", method: http.MethodGet, path: "/api/v1/sdn/gateway/lb/vips",
			wantReq:  &platformv1.ListVIPsRequest{},
			reply:    &platformv1.ListVIPsResponse{Vips: []*platformv1.VIPStatus{testVIPStatus()}},
			wantCode: http.StatusOK,
		},
		{
			name: "get vip", method: http.MethodGet, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/443",
			wantReq:  &platformv1.GetVIPRequest{Protocol: "tcp", Address: "198.51.100.10", Port: 443},
			reply:    &platformv1.GetVIPResponse{Vip: testVIPStatus()},
			wantCode: http.StatusOK,
		},
		{
			name: "remove vip", method: http.MethodDelete, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/443",
			wantReq:  &platformv1.RemoveVIPRequest{Protocol: "tcp", Address: "198.51.100.10", Port: 443},
			reply:    &platformv1.RemoveVIPResponse{Status: &platformv1.Status{Success: true}},
			wantCode: http.StatusOK,
		},
		{
			name: "set vip backends", method: http.MethodPut, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/443/backends",
			body: `{"backends":[{"address":"10.0.0.22","port":8443,"weight":2}]}`,
			wantReq: &platformv1.SetVIPBackendsRequest{
				Protocol: "tcp", Address: "198.51.100.10", Port: 443,
				Backends: []*platformv1.VIPBackend{{Address: "10.0.0.22", Port: 8443, Weight: 2}},
			},
			reply:    &platformv1.SetVIPBackendsResponse{Status: &platformv1.Status{Success: true}, Vip: testVIPStatus()},
			wantCode: http.StatusOK,
		},
		{
			name: "get lb status", method: http.MethodGet, path: "/api/v1/sdn/gateway/lb/status",
			wantReq: &platformv1.GetLBStatusRequest{},
			reply: &platformv1.GetLBStatusResponse{Status: &platformv1.LBStatus{
				Active: true, VipCount: 1, HealthyBackends: 1, TotalBackends: 1,
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "get nat64 status", method: http.MethodGet, path: "/api/v1/sdn/gateway/nat64/status",
			wantReq: &platformv1.GetNAT64StatusRequest{},
			reply: &platformv1.GetNAT64StatusResponse{Status: &platformv1.NAT64Status{
				Active: true, InstancePresent: true, Prefix: "64:ff9b::/96", Instance: "gtp", Sessions: 3,
			}},
			wantCode: http.StatusOK,
		},
		{
			name: "perf flows", method: http.MethodPost, path: "/api/v1/sdn/gateway/perf/flows",
			body:    `{"count":100,"batch":true,"bridge":"br-int"}`,
			wantReq: &platformv1.GetPerfFlowsRequest{Count: 100, Batch: true, Bridge: "br-int"},
			reply: &platformv1.GetPerfFlowsResponse{
				Installed: 100, DurationNs: 2_000_000, FlowsPerSecond: 50000, Batched: true, Bridge: "br-int",
			},
			wantCode: http.StatusOK,
		},
		{
			name: "perf datapath", method: http.MethodGet, path: "/api/v1/sdn/gateway/perf/datapath?bridge=br-int",
			wantReq: &platformv1.GetPerfDatapathRequest{Bridge: "br-int"},
			reply: &platformv1.GetPerfDatapathResponse{
				Hits: 10, Misses: 2, DatapathType: "system", Bridge: "br-int",
			},
			wantCode: http.StatusOK,
		},
		{
			name: "perf conntrack", method: http.MethodGet, path: "/api/v1/sdn/gateway/perf/conntrack",
			wantReq:  &platformv1.GetPerfConntrackRequest{},
			reply:    &platformv1.GetPerfConntrackResponse{TotalEntries: 4, PerZone: map[uint32]uint64{7: 4}},
			wantCode: http.StatusOK,
		},
		{
			name: "perf conntrack one zone", method: http.MethodGet, path: "/api/v1/sdn/gateway/perf/conntrack?zone=7",
			wantReq:  &platformv1.GetPerfConntrackRequest{Zone: &zone},
			reply:    &platformv1.GetPerfConntrackResponse{TotalEntries: 4, PerZone: map[uint32]uint64{7: 4}},
			wantCode: http.StatusOK,
		},
	}
}

func TestGatewayRouter_LBRoutesForwardToTheService(t *testing.T) {
	for _, tc := range gatewayLBRouteCases() {
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

func TestGatewayRouter_LBServiceErrorsReachTheCaller(t *testing.T) {
	for _, tc := range gatewayLBRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{err: status.Error(codes.NotFound, "vip not found")}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq == nil {
				t.Fatal("the service was never called")
			}
		})
	}
}

func TestGatewayRouter_LBMalformedBodyAnswers400(t *testing.T) {
	for _, tc := range gatewayLBRouteCases() {
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

func TestGatewayRouter_LBBadPathOrQueryAnswers400(t *testing.T) {
	cases := []gatewayRouteCase{
		{name: "port zero", method: http.MethodGet, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/0"},
		{name: "port too large", method: http.MethodDelete, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/65536"},
		{name: "port not a number", method: http.MethodPut, path: "/api/v1/sdn/gateway/lb/vips/tcp/198.51.100.10/https/backends", body: `{"backends":[]}`},
		{name: "zone not a number", method: http.MethodGet, path: "/api/v1/sdn/gateway/perf/conntrack?zone=seven"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("an invalid request reached the service: %v", svc.lastReq)
			}
		})
	}
}

func TestGatewayRouter_LBNilServerAnswers503(t *testing.T) {
	router := newGatewayTestRouter(nil)
	for _, tc := range gatewayLBRouteCases() {
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

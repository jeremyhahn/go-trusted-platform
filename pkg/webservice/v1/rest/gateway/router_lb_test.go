// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// Commercial licenses are also available.
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

func (f *fakeGatewayService) GetVIP(_ context.Context, req *platformv1.GetVIPRequest) (*platformv1.GetVIPResponse, error) {
	return answer[*platformv1.GetVIPResponse](f, req)
}

func (f *fakeGatewayService) ListVIPs(_ context.Context, req *platformv1.ListVIPsRequest) (*platformv1.ListVIPsResponse, error) {
	return answer[*platformv1.ListVIPsResponse](f, req)
}

func (f *fakeGatewayService) GetLBStatus(_ context.Context, req *platformv1.GetLBStatusRequest) (*platformv1.GetLBStatusResponse, error) {
	return answer[*platformv1.GetLBStatusResponse](f, req)
}

func lbTestVIPStatus() *platformv1.VIPStatus {
	backend := &platformv1.VIPBackend{Address: "10.0.1.1", Port: 8443, Weight: 1}
	return &platformv1.VIPStatus{
		Vip: &platformv1.VIPConfig{
			Address:   "10.0.0.5",
			Port:      443,
			Protocol:  "tcp",
			Algorithm: "hash",
			Backends:  []*platformv1.VIPBackend{backend},
		},
		CtZone:   7,
		GroupId:  3,
		Backends: []*platformv1.VIPBackendStatus{{Backend: backend, Healthy: true}},
	}
}

// lbRouteCases lists the load-balancer read routes the webservice serves
// under /api/v1/gateway/lb.
func lbRouteCases() []gatewayRouteCase {
	return []gatewayRouteCase{
		{
			name:     "list vips",
			method:   http.MethodGet,
			path:     "/api/v1/gateway/lb/vips",
			wantReq:  &platformv1.ListVIPsRequest{},
			reply:    &platformv1.ListVIPsResponse{Vips: []*platformv1.VIPStatus{lbTestVIPStatus()}},
			wantCode: http.StatusOK,
		},
		{
			name:     "get vip",
			method:   http.MethodGet,
			path:     "/api/v1/gateway/lb/vips/tcp/10.0.0.5/443",
			wantReq:  &platformv1.GetVIPRequest{Protocol: "tcp", Address: "10.0.0.5", Port: 443},
			reply:    &platformv1.GetVIPResponse{Vip: lbTestVIPStatus()},
			wantCode: http.StatusOK,
		},
		{
			name:     "get vip ipv6",
			method:   http.MethodGet,
			path:     "/api/v1/gateway/lb/vips/udp/fd00::5/53",
			wantReq:  &platformv1.GetVIPRequest{Protocol: "udp", Address: "fd00::5", Port: 53},
			reply:    &platformv1.GetVIPResponse{Vip: lbTestVIPStatus()},
			wantCode: http.StatusOK,
		},
		{
			name:    "lb status",
			method:  http.MethodGet,
			path:    "/api/v1/gateway/lb/status",
			wantReq: &platformv1.GetLBStatusRequest{},
			reply: &platformv1.GetLBStatusResponse{Status: &platformv1.LBStatus{
				Active: true, VipCount: 1, HealthyBackends: 1, TotalBackends: 2,
			}},
			wantCode: http.StatusOK,
		},
	}
}

func TestGatewayRouter_LBReadsForwardToTheService(t *testing.T) {
	for _, tc := range lbRouteCases() {
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
			if tc.name == "list vips" {
				raw := strings.ReplaceAll(string(env.Payload), " ", "")
				for _, want := range []string{`"ctZone":7`, `"groupId":3`} {
					if !strings.Contains(raw, want) {
						t.Fatalf("payload lacks camelCase %s: %s", want, env.Payload)
					}
				}
			}
		})
	}
}

func TestGatewayRouter_LBReadErrorsReachTheCaller(t *testing.T) {
	errs := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"not found", status.Error(codes.NotFound, "vip not found"), http.StatusNotFound},
		{"unavailable", status.Error(codes.Unavailable, "load balancer not configured"), http.StatusServiceUnavailable},
	}
	for _, tc := range lbRouteCases() {
		for _, e := range errs {
			t.Run(tc.name+"/"+e.name, func(t *testing.T) {
				svc := &fakeGatewayService{err: e.err}
				rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)

				if rec.Code != e.wantCode {
					t.Fatalf("status = %d, want %d (body=%s)", rec.Code, e.wantCode, rec.Body.String())
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
}

func TestGatewayRouter_LBBadPortAnswers400(t *testing.T) {
	for _, path := range []string{
		"/api/v1/gateway/lb/vips/tcp/10.0.0.5/notaport",
		"/api/v1/gateway/lb/vips/tcp/10.0.0.5/70000",
	} {
		t.Run(path, func(t *testing.T) {
			svc := &fakeGatewayService{reply: &platformv1.GetVIPResponse{}}
			tc := gatewayRouteCase{method: http.MethodGet, path: path}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("the service was called with %v for a bad port", svc.lastReq)
			}
		})
	}
}

func TestGatewayRouter_LBNilServerAnswers503(t *testing.T) {
	router := newGatewayTestRouter(nil)
	for _, tc := range lbRouteCases() {
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

// TestGatewayRouter_LBHasNoWriteRoutes pins that this slice serves only the
// reads; the next slice adds AddVIP, RemoveVIP and SetVIPBackends and
// removes this guard.
func TestGatewayRouter_LBHasNoWriteRoutes(t *testing.T) {
	for _, tc := range []gatewayRouteCase{
		{name: "add vip", method: http.MethodPost, path: "/api/v1/gateway/lb/vips", body: `{"vip":{}}`},
		{name: "remove vip", method: http.MethodDelete, path: "/api/v1/gateway/lb/vips/tcp/10.0.0.5/443"},
		{name: "set backends", method: http.MethodPut, path: "/api/v1/gateway/lb/vips/tcp/10.0.0.5/443/backends", body: `{"backends":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{reply: &platformv1.GetVIPResponse{}}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 404 or 405 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("the service was called with %v", svc.lastReq)
			}
		})
	}
}

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

func (f *fakeGatewayService) AddVIP(_ context.Context, req *platformv1.AddVIPRequest) (*platformv1.AddVIPResponse, error) {
	return answer[*platformv1.AddVIPResponse](f, req)
}

func (f *fakeGatewayService) RemoveVIP(_ context.Context, req *platformv1.RemoveVIPRequest) (*platformv1.RemoveVIPResponse, error) {
	return answer[*platformv1.RemoveVIPResponse](f, req)
}

func (f *fakeGatewayService) SetVIPBackends(_ context.Context, req *platformv1.SetVIPBackendsRequest) (*platformv1.SetVIPBackendsResponse, error) {
	return answer[*platformv1.SetVIPBackendsResponse](f, req)
}

func lbWriteTestVIPStatus() *platformv1.VIPStatus {
	return &platformv1.VIPStatus{
		Vip: &platformv1.VIPConfig{
			Address:  "192.0.2.10",
			Port:     443,
			Protocol: "tcp",
			Backends: []*platformv1.VIPBackend{{Address: "192.0.2.21", Port: 8443}},
		},
		CtZone:  7,
		GroupId: 3,
		Backends: []*platformv1.VIPBackendStatus{
			{Backend: &platformv1.VIPBackend{Address: "192.0.2.21", Port: 8443}, Healthy: true},
		},
	}
}

// lbWriteRouteCases is one case per load-balancer write route.
func lbWriteRouteCases() []gatewayRouteCase {
	return []gatewayRouteCase{
		{
			name:   "add vip",
			method: http.MethodPost,
			path:   "/api/v1/gateway/lb/vips",
			body:   `{"vip":{"address":"192.0.2.10","port":443,"protocol":"tcp","backends":[{"address":"192.0.2.21","port":8443}]}}`,
			wantReq: &platformv1.AddVIPRequest{Vip: &platformv1.VIPConfig{
				Address:  "192.0.2.10",
				Port:     443,
				Protocol: "tcp",
				Backends: []*platformv1.VIPBackend{{Address: "192.0.2.21", Port: 8443}},
			}},
			reply:    &platformv1.AddVIPResponse{Vip: lbWriteTestVIPStatus()},
			wantCode: http.StatusCreated,
		},
		{
			name:     "remove vip",
			method:   http.MethodDelete,
			path:     "/api/v1/gateway/lb/vips/tcp/192.0.2.10/443",
			wantReq:  &platformv1.RemoveVIPRequest{Protocol: "tcp", Address: "192.0.2.10", Port: 443},
			reply:    &platformv1.RemoveVIPResponse{},
			wantCode: http.StatusOK,
		},
		{
			name:   "set vip backends",
			method: http.MethodPut,
			path:   "/api/v1/gateway/lb/vips/tcp/192.0.2.10/443/backends",
			body:   `{"protocol":"udp","address":"192.0.2.99","port":1,"backends":[{"address":"192.0.2.22","port":8443,"weight":2}]}`,
			wantReq: &platformv1.SetVIPBackendsRequest{
				Protocol: "tcp",
				Address:  "192.0.2.10",
				Port:     443,
				Backends: []*platformv1.VIPBackend{{Address: "192.0.2.22", Port: 8443, Weight: 2}},
			},
			reply:    &platformv1.SetVIPBackendsResponse{Vip: lbWriteTestVIPStatus()},
			wantCode: http.StatusOK,
		},
	}
}

func TestGatewayRouter_LBWritesForwardToTheService(t *testing.T) {
	for _, tc := range lbWriteRouteCases() {
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

func TestGatewayRouter_LBWriteErrorsReachTheCaller(t *testing.T) {
	errs := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "lb: bad vip"), http.StatusBadRequest},
		{"not found", status.Error(codes.NotFound, "vip not found"), http.StatusNotFound},
		{"already exists", status.Error(codes.AlreadyExists, "vip exists"), http.StatusConflict},
	}
	for _, tc := range lbWriteRouteCases() {
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

func TestGatewayRouter_LBWriteBadInputAnswers400(t *testing.T) {
	for _, tc := range []gatewayRouteCase{
		{name: "add vip bad body", method: http.MethodPost, path: "/api/v1/gateway/lb/vips", body: `{"vip":"x"}`},
		{name: "remove vip port out of range", method: http.MethodDelete, path: "/api/v1/gateway/lb/vips/tcp/192.0.2.10/70000"},
		{name: "set backends bad port", method: http.MethodPut, path: "/api/v1/gateway/lb/vips/tcp/192.0.2.10/abc/backends", body: `{"backends":[]}`},
		{name: "set backends bad body", method: http.MethodPut, path: "/api/v1/gateway/lb/vips/tcp/192.0.2.10/443/backends", body: `{"backends":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeGatewayService{reply: &platformv1.AddVIPResponse{}}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("the service was called with %v", svc.lastReq)
			}
		})
	}
}

func TestGatewayRouter_LBWriteNilServerAnswers503(t *testing.T) {
	router := newGatewayTestRouter(nil)
	for _, tc := range lbWriteRouteCases() {
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

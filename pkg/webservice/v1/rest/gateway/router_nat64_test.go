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

func (f *fakeGatewayService) GetNAT64Status(_ context.Context, req *platformv1.GetNAT64StatusRequest) (*platformv1.GetNAT64StatusResponse, error) {
	return answer[*platformv1.GetNAT64StatusResponse](f, req)
}

// nat64RouteCase is the webservice read of the NAT64 translator status
// (#2052). The daemon keeps /api/v1/sdn/gateway/nat64; the webservice
// serves the same operation under /api/v1/gateway/nat64 in protojson.
func nat64RouteCase() gatewayRouteCase {
	return gatewayRouteCase{
		name:    "nat64 status",
		method:  http.MethodGet,
		path:    "/api/v1/gateway/nat64/status",
		wantReq: &platformv1.GetNAT64StatusRequest{},
		reply: &platformv1.GetNAT64StatusResponse{Status: &platformv1.NAT64Status{
			Active:          true,
			InstancePresent: true,
			Prefix:          "64:ff9b::/96",
			Instance:        "tp-nat64",
			Sessions:        12,
			Pool4Used:       3,
			ModuleVersion:   "4.1.10",
			FlowCount:       2,
		}},
		wantCode: http.StatusOK,
	}
}

func TestGatewayRouter_NAT64StatusForwardsToTheService(t *testing.T) {
	tc := nat64RouteCase()
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
	got := &platformv1.GetNAT64StatusResponse{}
	if err := protojson.Unmarshal(env.Payload, got); err != nil {
		t.Fatalf("decode payload: %v (payload=%s)", err, env.Payload)
	}
	if !proto.Equal(got, tc.reply) {
		t.Fatalf("payload = %v, want %v", got, tc.reply)
	}
	raw := strings.ReplaceAll(string(env.Payload), " ", "")
	for _, want := range []string{`"instancePresent":true`, `"pool4Used":"3"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("payload lacks camelCase %s: %s", want, env.Payload)
		}
	}
}

func TestGatewayRouter_NAT64StatusErrorsReachTheCaller(t *testing.T) {
	tc := nat64RouteCase()
	for _, e := range []struct {
		name     string
		err      error
		wantCode int
	}{
		{"unavailable", status.Error(codes.Unavailable, "nat64 translator not configured"), http.StatusServiceUnavailable},
		{"failed precondition", status.Error(codes.FailedPrecondition, "nat64 translator module unavailable"), http.StatusConflict},
	} {
		t.Run(e.name, func(t *testing.T) {
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

func TestGatewayRouter_NAT64StatusNilServerAnswers503(t *testing.T) {
	tc := nat64RouteCase()
	rec := serveGatewayCase(newGatewayTestRouter(nil), tc, tc.body)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "gateway service is not available") {
		t.Fatalf("body does not name the missing service: %s", rec.Body.String())
	}
}

func TestGatewayRouter_NAT64StatusIsReadOnly(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			tc := gatewayRouteCase{name: "nat64 " + method, method: method, path: "/api/v1/gateway/nat64/status"}
			svc := &fakeGatewayService{reply: &platformv1.GetNAT64StatusResponse{}}
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

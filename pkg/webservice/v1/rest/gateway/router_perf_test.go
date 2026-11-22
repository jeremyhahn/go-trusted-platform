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

func (f *fakeGatewayService) GetPerfFlows(_ context.Context, req *platformv1.GetPerfFlowsRequest) (*platformv1.GetPerfFlowsResponse, error) {
	return answer[*platformv1.GetPerfFlowsResponse](f, req)
}

const perfFlowsPath = "/api/v1/gateway/perf/flows"

func TestGatewayRouter_PerfFlowsForwardsTheBody(t *testing.T) {
	reply := &platformv1.GetPerfFlowsResponse{
		Installed: 1000, DurationNs: 2500000, FlowsPerSecond: 400000, Batched: true, Bridge: "br-int",
	}
	svc := &fakeGatewayService{reply: reply}
	tc := gatewayRouteCase{method: http.MethodPost, path: perfFlowsPath}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, `{"count":1000,"batch":true}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	want := &platformv1.GetPerfFlowsRequest{Count: 1000, Batch: true}
	if !proto.Equal(svc.lastReq, want) {
		t.Fatalf("forwarded request = %v, want %v", svc.lastReq, want)
	}
	env := decodeIPAMEnvelope(t, rec)
	if !env.Success || env.Code != http.StatusOK {
		t.Fatalf("envelope = {code:%d success:%v}, want {code:200 success:true}", env.Code, env.Success)
	}
	got := &platformv1.GetPerfFlowsResponse{}
	if err := protojson.Unmarshal(env.Payload, got); err != nil {
		t.Fatalf("decode payload: %v (payload=%s)", err, env.Payload)
	}
	if !proto.Equal(got, reply) {
		t.Fatalf("payload = %v, want %v", got, reply)
	}
	raw := strings.ReplaceAll(string(env.Payload), " ", "")
	for _, s := range []string{`"flowsPerSecond"`, `"durationNs":"2500000"`} {
		if !strings.Contains(raw, s) {
			t.Fatalf("payload lacks %s: %s", s, env.Payload)
		}
	}
}

func TestGatewayRouter_PerfFlowsEmptyBodyUsesTheServiceDefault(t *testing.T) {
	svc := &fakeGatewayService{reply: &platformv1.GetPerfFlowsResponse{Installed: 1000}}
	tc := gatewayRouteCase{method: http.MethodPost, path: perfFlowsPath}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !proto.Equal(svc.lastReq, &platformv1.GetPerfFlowsRequest{}) {
		t.Fatalf("forwarded request = %v, want an empty request", svc.lastReq)
	}
}

func TestGatewayRouter_PerfFlowsErrorsReachTheCaller(t *testing.T) {
	for _, e := range []struct {
		name     string
		err      error
		wantCode int
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "count exceeds 100000"), http.StatusBadRequest},
		{"not found", status.Error(codes.NotFound, "bridge not found"), http.StatusNotFound},
		{"unavailable", status.Error(codes.Unavailable, "perf service not configured"), http.StatusServiceUnavailable},
	} {
		t.Run(e.name, func(t *testing.T) {
			svc := &fakeGatewayService{err: e.err}
			tc := gatewayRouteCase{method: http.MethodPost, path: perfFlowsPath}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, `{"count":1000}`)

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

func TestGatewayRouter_PerfFlowsBadJSONAnswers400(t *testing.T) {
	svc := &fakeGatewayService{reply: &platformv1.GetPerfFlowsResponse{}}
	tc := gatewayRouteCase{method: http.MethodPost, path: perfFlowsPath}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, `{"count":"many"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if svc.lastReq != nil {
		t.Fatalf("the service was called with %v for a bad body", svc.lastReq)
	}
}

// TestGatewayRouter_PerfFlowsIsNotAGet pins that the benchmark, which
// installs and removes switch flows, is never reachable by a GET.
func TestGatewayRouter_PerfFlowsIsNotAGet(t *testing.T) {
	svc := &fakeGatewayService{reply: &platformv1.GetPerfFlowsResponse{}}
	tc := gatewayRouteCase{method: http.MethodGet, path: perfFlowsPath}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 404 or 405 (body=%s)", rec.Code, rec.Body.String())
	}
	if svc.lastReq != nil {
		t.Fatalf("the service was called with %v", svc.lastReq)
	}
}

func TestGatewayRouter_PerfFlowsNilServerAnswers503(t *testing.T) {
	tc := gatewayRouteCase{method: http.MethodPost, path: perfFlowsPath}
	rec := serveGatewayCase(newGatewayTestRouter(nil), tc, `{"count":1000}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "gateway service is not available") {
		t.Fatalf("body does not name the missing service: %s", rec.Body.String())
	}
}

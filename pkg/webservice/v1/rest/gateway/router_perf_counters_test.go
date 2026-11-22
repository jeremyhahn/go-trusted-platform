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

func (f *fakeGatewayService) GetPerfDatapath(_ context.Context, req *platformv1.GetPerfDatapathRequest) (*platformv1.GetPerfDatapathResponse, error) {
	return answer[*platformv1.GetPerfDatapathResponse](f, req)
}

func (f *fakeGatewayService) GetPerfConntrack(_ context.Context, req *platformv1.GetPerfConntrackRequest) (*platformv1.GetPerfConntrackResponse, error) {
	return answer[*platformv1.GetPerfConntrackResponse](f, req)
}

const (
	perfDatapathPath  = "/api/v1/gateway/perf/datapath"
	perfConntrackPath = "/api/v1/gateway/perf/conntrack"
)

func TestGatewayRouter_PerfDatapathForwardsTheBridge(t *testing.T) {
	reply := &platformv1.GetPerfDatapathResponse{
		Hits: 10, Misses: 2, Lost: 0, OffloadedFlowCount: 4, HwOffloadEnabled: true, DatapathType: "system", Bridge: "br-int",
	}
	svc := &fakeGatewayService{reply: reply}
	tc := gatewayRouteCase{method: http.MethodGet, path: perfDatapathPath + "?bridge=br-int"}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	want := &platformv1.GetPerfDatapathRequest{Bridge: "br-int"}
	if !proto.Equal(svc.lastReq, want) {
		t.Fatalf("forwarded request = %v, want %v", svc.lastReq, want)
	}
	env := decodeIPAMEnvelope(t, rec)
	if !env.Success || env.Code != http.StatusOK {
		t.Fatalf("envelope = {code:%d success:%v}, want {code:200 success:true}", env.Code, env.Success)
	}
	got := &platformv1.GetPerfDatapathResponse{}
	if err := protojson.Unmarshal(env.Payload, got); err != nil {
		t.Fatalf("decode payload: %v (payload=%s)", err, env.Payload)
	}
	if !proto.Equal(got, reply) {
		t.Fatalf("payload = %v, want %v", got, reply)
	}
	raw := strings.ReplaceAll(string(env.Payload), " ", "")
	for _, s := range []string{`"hits":"10"`, `"hwOffloadEnabled":true`} {
		if !strings.Contains(raw, s) {
			t.Fatalf("payload lacks %s: %s", s, env.Payload)
		}
	}

	t.Run("no bridge", func(t *testing.T) {
		svc := &fakeGatewayService{reply: &platformv1.GetPerfDatapathResponse{}}
		tc := gatewayRouteCase{method: http.MethodGet, path: perfDatapathPath}
		rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		if !proto.Equal(svc.lastReq, &platformv1.GetPerfDatapathRequest{}) {
			t.Fatalf("forwarded request = %v, want an empty request", svc.lastReq)
		}
	})
}

func TestGatewayRouter_PerfConntrackForwardsTheZone(t *testing.T) {
	reply := &platformv1.GetPerfConntrackResponse{TotalEntries: 42, PerZone: map[uint32]uint64{7: 12, 0: 30}}
	svc := &fakeGatewayService{reply: reply}
	tc := gatewayRouteCase{method: http.MethodGet, path: perfConntrackPath + "?zone=7"}
	rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	zone := uint32(7)
	want := &platformv1.GetPerfConntrackRequest{Zone: &zone}
	if !proto.Equal(svc.lastReq, want) {
		t.Fatalf("forwarded request = %v, want %v", svc.lastReq, want)
	}
	env := decodeIPAMEnvelope(t, rec)
	if !env.Success || env.Code != http.StatusOK {
		t.Fatalf("envelope = {code:%d success:%v}, want {code:200 success:true}", env.Code, env.Success)
	}
	got := &platformv1.GetPerfConntrackResponse{}
	if err := protojson.Unmarshal(env.Payload, got); err != nil {
		t.Fatalf("decode payload: %v (payload=%s)", err, env.Payload)
	}
	if !proto.Equal(got, reply) {
		t.Fatalf("payload = %v, want %v", got, reply)
	}
	raw := strings.ReplaceAll(string(env.Payload), " ", "")
	if !strings.Contains(raw, `"totalEntries":"42"`) {
		t.Fatalf("payload lacks totalEntries as a string: %s", env.Payload)
	}

	t.Run("no zone", func(t *testing.T) {
		svc := &fakeGatewayService{reply: &platformv1.GetPerfConntrackResponse{}}
		tc := gatewayRouteCase{method: http.MethodGet, path: perfConntrackPath}
		rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		req, ok := svc.lastReq.(*platformv1.GetPerfConntrackRequest)
		if !ok {
			t.Fatalf("forwarded request = %v, want a GetPerfConntrackRequest", svc.lastReq)
		}
		if req.Zone != nil {
			t.Fatalf("forwarded zone = %d, want none (every zone)", *req.Zone)
		}
	})
}

func TestGatewayRouter_PerfConntrackBadZoneAnswers400(t *testing.T) {
	for _, q := range []string{"seven", "4294967296"} {
		t.Run(q, func(t *testing.T) {
			svc := &fakeGatewayService{reply: &platformv1.GetPerfConntrackResponse{}}
			tc := gatewayRouteCase{method: http.MethodGet, path: perfConntrackPath + "?zone=" + q}
			rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if svc.lastReq != nil {
				t.Fatalf("the service was called with %v for a bad zone", svc.lastReq)
			}
		})
	}
}

func TestGatewayRouter_PerfCountersErrorsReachTheCaller(t *testing.T) {
	for _, path := range []string{perfDatapathPath, perfConntrackPath} {
		for _, e := range []struct {
			name     string
			err      error
			wantCode int
		}{
			{"not found", status.Error(codes.NotFound, "bridge not found"), http.StatusNotFound},
			{"unavailable", status.Error(codes.Unavailable, "perf service not configured"), http.StatusServiceUnavailable},
		} {
			t.Run(path+" "+e.name, func(t *testing.T) {
				svc := &fakeGatewayService{err: e.err}
				tc := gatewayRouteCase{method: http.MethodGet, path: path}
				rec := serveGatewayCase(newGatewayTestRouter(svc), tc, "")

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

func TestGatewayRouter_PerfCountersNilServerAnswers503(t *testing.T) {
	for _, path := range []string{perfDatapathPath, perfConntrackPath} {
		t.Run(path, func(t *testing.T) {
			tc := gatewayRouteCase{method: http.MethodGet, path: path}
			rec := serveGatewayCase(newGatewayTestRouter(nil), tc, "")

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "gateway service is not available") {
				t.Fatalf("body does not name the missing service: %s", rec.Body.String())
			}
		})
	}
}

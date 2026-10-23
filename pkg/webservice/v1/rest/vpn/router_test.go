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

package vpn

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer answers every VPNService call with err, or with an empty
// reply, and records the request it was given.
type recordingServer struct {
	platformv1.UnimplementedVPNServiceServer
	err  error
	last proto.Message
}

func (s *recordingServer) EnrolPeer(_ context.Context, req *platformv1.EnrolVPNPeerRequest) (*platformv1.EnrolVPNPeerResponse, error) {
	s.last = req
	return &platformv1.EnrolVPNPeerResponse{Peer: req.GetPeer()}, s.err
}

func (s *recordingServer) ListPeers(_ context.Context, req *platformv1.ListVPNPeersRequest) (*platformv1.ListVPNPeersResponse, error) {
	s.last = req
	return &platformv1.ListVPNPeersResponse{}, s.err
}

func (s *recordingServer) RevokePeer(_ context.Context, req *platformv1.RevokeVPNPeerRequest) (*platformv1.RevokeVPNPeerResponse, error) {
	s.last = req
	return &platformv1.RevokeVPNPeerResponse{}, s.err
}

func (s *recordingServer) GetStatus(_ context.Context, req *platformv1.GetVPNStatusRequest) (*platformv1.GetVPNStatusResponse, error) {
	s.last = req
	return &platformv1.GetVPNStatusResponse{}, s.err
}

func (s *recordingServer) GetPosturePolicy(_ context.Context, req *platformv1.GetVPNPosturePolicyRequest) (*platformv1.GetVPNPosturePolicyResponse, error) {
	s.last = req
	return &platformv1.GetVPNPosturePolicyResponse{}, s.err
}

func (s *recordingServer) SetPosturePolicy(_ context.Context, req *platformv1.SetVPNPosturePolicyRequest) (*platformv1.SetVPNPosturePolicyResponse, error) {
	s.last = req
	return &platformv1.SetVPNPosturePolicyResponse{Policy: req.GetPolicy()}, s.err
}

func (s *recordingServer) DeletePosturePolicy(_ context.Context, req *platformv1.DeleteVPNPosturePolicyRequest) (*platformv1.DeleteVPNPosturePolicyResponse, error) {
	s.last = req
	return &platformv1.DeleteVPNPosturePolicyResponse{}, s.err
}

func (s *recordingServer) ListPosturePolicies(_ context.Context, req *platformv1.ListVPNPosturePoliciesRequest) (*platformv1.ListVPNPosturePoliciesResponse, error) {
	s.last = req
	return &platformv1.ListVPNPosturePoliciesResponse{}, s.err
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

// mountRouter mounts the VPN routes under /api/v1.
func mountRouter(server platformv1.VPNServiceServer) *mux.Router {
	router := mux.NewRouter()
	NewVPNRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

// envelope is the standard webservice response wrapper.
type envelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

func serve(router *mux.Router, verb, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(verb, path, strings.NewReader(body)))
	return rec
}

// vpnProbe is one route, the scope it requires, the HTTP status it answers
// with, and the request the service must receive.
type vpnProbe struct {
	name  string
	verb  string
	path  string
	body  string
	scope string
	code  int
	want  proto.Message
}

var vpnProbes = []vpnProbe{
	{
		name: "enrol peer", scope: scopeWrite, verb: http.MethodPost, path: "/api/v1/vpn/peers",
		body: `{"tenant_id":"acme","device_id":"laptop-1","zones":["management"]}`,
		code: http.StatusCreated,
		want: &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}}},
	},
	{
		name: "list peers", scope: scopeRead, verb: http.MethodGet, path: "/api/v1/vpn/peers?tenant_id=acme",
		code: http.StatusOK,
		want: &platformv1.ListVPNPeersRequest{TenantId: "acme"},
	},
	{
		name: "revoke peer", scope: scopeWrite, verb: http.MethodDelete, path: "/api/v1/vpn/peers/laptop-1?tenant_id=acme",
		code: http.StatusOK,
		want: &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"},
	},
	{
		name: "status", scope: scopeRead, verb: http.MethodGet, path: "/api/v1/vpn/status?gateway_id=gw-1",
		code: http.StatusOK,
		want: &platformv1.GetVPNStatusRequest{GatewayId: "gw-1"},
	},
	{
		name: "list posture policies", scope: scopeAdmin, verb: http.MethodGet, path: "/api/v1/vpn/posture-policies?tenant_id=acme",
		code: http.StatusOK,
		want: &platformv1.ListVPNPosturePoliciesRequest{TenantId: "acme"},
	},
	{
		name: "get posture policy", scope: scopeAdmin, verb: http.MethodGet, path: "/api/v1/vpn/posture-policies/corp?tenant_id=acme",
		code: http.StatusOK,
		want: &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
	},
	{
		name: "set posture policy", scope: scopeAdmin, verb: http.MethodPut, path: "/api/v1/vpn/posture-policies/corp",
		body: `{"tenant_id":"acme","module":"package vpn.posture"}`,
		code: http.StatusOK,
		want: &platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package vpn.posture"}},
	},
	{
		name: "delete posture policy", scope: scopeAdmin, verb: http.MethodDelete, path: "/api/v1/vpn/posture-policies/corp?tenant_id=acme",
		code: http.StatusOK,
		want: &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
	},
}

func TestVPNRouterServesEveryOperation(t *testing.T) {
	if len(platformv1.VPNService_ServiceDesc.Methods) != len(vpnProbes) {
		t.Fatalf("VPNService has %d methods, the test probes %d", len(platformv1.VPNService_ServiceDesc.Methods), len(vpnProbes))
	}
	for _, probe := range vpnProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != probe.code {
				t.Fatalf("code = %d, want %d, body %s", rec.Code, probe.code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if !body.Success {
				t.Fatalf("envelope = %+v", body)
			}
			if !proto.Equal(server.last, probe.want) {
				t.Fatalf("service got %v, want %v", server.last, probe.want)
			}
		})
	}
}

// TestVPNRouterMapsServiceRefusals checks that a refused call reaches the
// client as the matching HTTP status on every route.
func TestVPNRouterMapsServiceRefusals(t *testing.T) {
	refusals := map[codes.Code]int{
		codes.PermissionDenied: http.StatusForbidden,
		codes.NotFound:         http.StatusNotFound,
		codes.InvalidArgument:  http.StatusBadRequest,
		codes.Aborted:          http.StatusConflict,
		codes.Unavailable:      http.StatusServiceUnavailable,
	}
	for code, want := range refusals {
		for _, probe := range vpnProbes {
			server := &recordingServer{err: status.Error(code, "refused")}
			rec := serve(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != want {
				t.Errorf("%s refused with %s: code = %d, want %d", probe.name, code, rec.Code, want)
			}
		}
	}
}

func TestVPNRouterWithoutAServiceIsUnavailable(t *testing.T) {
	for _, probe := range vpnProbes {
		rec := serve(mountRouter(nil), probe.verb, probe.path, probe.body)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: code = %d, want 503", probe.name, rec.Code)
		}
	}
}

func TestVPNRouterRefusesBadBodies(t *testing.T) {
	cases := []struct {
		name string
		verb string
		path string
		body string
	}{
		{"enrol with malformed JSON", http.MethodPost, "/api/v1/vpn/peers", `{"device_id":`},
		{"set with malformed JSON", http.MethodPut, "/api/v1/vpn/posture-policies/corp", `{"module":`},
		{"set naming another policy", http.MethodPut, "/api/v1/vpn/posture-policies/corp", `{"name":"other"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mountRouter(server), tc.verb, tc.path, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400, body %s", rec.Code, rec.Body)
			}
			if server.last != nil {
				t.Fatalf("the service was called with %v", server.last)
			}
		})
	}
}

// grantingAuthorizer lets a request through only when the route asks for
// the one scope it grants.
type grantingAuthorizer struct {
	granted string
}

func (a grantingAuthorizer) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TestVPNRouterRequiresEachRouteScope checks that every route asks for its
// own scope: the right one reaches the service, any other is refused before
// the service is called.
func TestVPNRouterRequiresEachRouteScope(t *testing.T) {
	for _, probe := range vpnProbes {
		for _, granted := range []string{scopeRead, scopeWrite, scopeAdmin} {
			server := &recordingServer{}
			vpnRouter := NewVPNRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil))
			vpnRouter.SetScopeAuthorizer(grantingAuthorizer{granted: granted})
			router := mux.NewRouter()
			vpnRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

			rec := serve(router, probe.verb, probe.path, probe.body)
			if granted == probe.scope {
				if rec.Code != probe.code {
					t.Errorf("%s with %s: code = %d, want %d", probe.name, granted, rec.Code, probe.code)
				}
				continue
			}
			if rec.Code != http.StatusForbidden || server.last != nil {
				t.Errorf("%s with %s: code = %d, service called = %v; want 403 and no call",
					probe.name, granted, rec.Code, server.last != nil)
			}
		}
	}
}

func TestErrPolicyNameMismatchNamesBothPolicies(t *testing.T) {
	msg := (&ErrPolicyNameMismatch{Path: "corp", Body: "other"}).Error()
	if !strings.Contains(msg, "corp") || !strings.Contains(msg, "other") {
		t.Fatalf("Error() = %q, want both names", msg)
	}
}

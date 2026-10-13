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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeVPNServer records the last request and returns a configured error.
type fakeVPNServer struct {
	platformv1.UnimplementedVPNServiceServer
	last proto.Message
	err  error
}

func (f *fakeVPNServer) EnrolPeer(_ context.Context, req *platformv1.EnrolVPNPeerRequest) (*platformv1.EnrolVPNPeerResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.EnrolVPNPeerResponse{Peer: req.GetPeer()}, nil
}

func (f *fakeVPNServer) ListPeers(_ context.Context, req *platformv1.ListVPNPeersRequest) (*platformv1.ListVPNPeersResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListVPNPeersResponse{Peers: []*platformv1.VPNPeer{{TenantId: req.GetTenantId(), DeviceId: "laptop-1"}}}, nil
}

func (f *fakeVPNServer) RevokePeer(_ context.Context, req *platformv1.RevokeVPNPeerRequest) (*platformv1.RevokeVPNPeerResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.RevokeVPNPeerResponse{}, nil
}

func (f *fakeVPNServer) GetStatus(_ context.Context, req *platformv1.GetVPNStatusRequest) (*platformv1.GetVPNStatusResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetVPNStatusResponse{Gateways: []*platformv1.VPNGatewayStatus{{GatewayId: "gw-1", Reporting: true}}}, nil
}

func (f *fakeVPNServer) GetPosturePolicy(_ context.Context, req *platformv1.GetVPNPosturePolicyRequest) (*platformv1.GetVPNPosturePolicyResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetVPNPosturePolicyResponse{Policy: &platformv1.VPNPosturePolicy{TenantId: req.GetTenantId(), Name: req.GetName()}}, nil
}

func (f *fakeVPNServer) SetPosturePolicy(_ context.Context, req *platformv1.SetVPNPosturePolicyRequest) (*platformv1.SetVPNPosturePolicyResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.SetVPNPosturePolicyResponse{Policy: req.GetPolicy()}, nil
}

func (f *fakeVPNServer) DeletePosturePolicy(_ context.Context, req *platformv1.DeleteVPNPosturePolicyRequest) (*platformv1.DeleteVPNPosturePolicyResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteVPNPosturePolicyResponse{}, nil
}

func (f *fakeVPNServer) ListPosturePolicies(_ context.Context, req *platformv1.ListVPNPosturePoliciesRequest) (*platformv1.ListVPNPosturePoliciesResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListVPNPosturePoliciesResponse{}, nil
}

// serveVPN runs one request through a router carrying the VPN routes.
func serveVPN(server platformv1.VPNServiceServer, method, target, body string) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	NewVPNHandlers(server, operatorGuard(), nil).RegisterRoutes(router)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, operatorRequest(method, target, strings.NewReader(body)))
	return recorder
}

func TestVPNHandlers_RouteEveryOperationToTheServer(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		body   string
		code   int
		want   proto.Message
	}{
		{
			name: "enrol", method: http.MethodPost, target: "/api/v1/vpn/peers",
			body: `{"tenantId":"acme","deviceId":"laptop-1","zones":["management"]}`, code: http.StatusCreated,
			want: &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}}},
		},
		{
			name: "list peers", method: http.MethodGet, target: "/api/v1/vpn/peers?tenant_id=acme", code: http.StatusOK,
			want: &platformv1.ListVPNPeersRequest{TenantId: "acme"},
		},
		{
			name: "revoke", method: http.MethodDelete, target: "/api/v1/vpn/peers/laptop-1?tenant_id=acme", code: http.StatusOK,
			want: &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"},
		},
		{
			name: "status", method: http.MethodGet, target: "/api/v1/vpn/status?gateway_id=gw-1", code: http.StatusOK,
			want: &platformv1.GetVPNStatusRequest{GatewayId: "gw-1"},
		},
		{
			name: "list policies", method: http.MethodGet, target: "/api/v1/vpn/posture-policies?tenant_id=acme", code: http.StatusOK,
			want: &platformv1.ListVPNPosturePoliciesRequest{TenantId: "acme"},
		},
		{
			name: "get policy", method: http.MethodGet, target: "/api/v1/vpn/posture-policies/corp?tenant_id=acme", code: http.StatusOK,
			want: &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
		},
		{
			name: "set policy", method: http.MethodPut, target: "/api/v1/vpn/posture-policies/corp",
			body: `{"tenantId":"acme","module":"package vpn.posture"}`, code: http.StatusOK,
			want: &platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package vpn.posture"}},
		},
		{
			name: "delete policy", method: http.MethodDelete, target: "/api/v1/vpn/posture-policies/corp?tenant_id=acme", code: http.StatusOK,
			want: &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &fakeVPNServer{}
			recorder := serveVPN(server, tc.method, tc.target, tc.body)

			require.Equal(t, tc.code, recorder.Code, recorder.Body.String())
			assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
			assert.True(t, proto.Equal(tc.want, server.last), "request = %v, want %v", server.last, tc.want)
		})
	}
}

func TestVPNHandlers_MapServiceErrorsToHTTPStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{status.Error(codes.InvalidArgument, "tenant_id: required"), http.StatusBadRequest},
		{status.Error(codes.NotFound, "no such peer"), http.StatusNotFound},
		{status.Error(codes.Aborted, "key collision"), http.StatusConflict},
		{status.Error(codes.Unavailable, "store down"), http.StatusServiceUnavailable},
		{status.Error(codes.Internal, "unexpected"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		recorder := serveVPN(&fakeVPNServer{err: tc.err}, http.MethodGet, "/api/v1/vpn/peers", "")

		assert.Equal(t, tc.want, recorder.Code, "%v", tc.err)
		var body ErrorResponse
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		assert.Equal(t, tc.want, body.Code)
		assert.NotEmpty(t, body.Error)
	}
}

func TestVPNHandlers_RefuseBadBodies(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "malformed JSON", method: http.MethodPost, target: "/api/v1/vpn/peers", body: `{"tenantId":`},
		{name: "unknown field", method: http.MethodPost, target: "/api/v1/vpn/peers", body: `{"tenant":"acme"}`},
		{name: "name mismatch", method: http.MethodPut, target: "/api/v1/vpn/posture-policies/corp", body: `{"tenantId":"acme","name":"other"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &fakeVPNServer{}
			recorder := serveVPN(server, tc.method, tc.target, tc.body)

			assert.Equal(t, http.StatusBadRequest, recorder.Code)
			assert.Nil(t, server.last, "a refused body must not reach the service")
		})
	}
}

func TestVPNHandlers_WithoutServerEveryRouteIsUnavailable(t *testing.T) {
	routes := [][2]string{
		{http.MethodPost, "/api/v1/vpn/peers"},
		{http.MethodGet, "/api/v1/vpn/peers"},
		{http.MethodDelete, "/api/v1/vpn/peers/laptop-1"},
		{http.MethodGet, "/api/v1/vpn/status"},
		{http.MethodGet, "/api/v1/vpn/posture-policies"},
		{http.MethodGet, "/api/v1/vpn/posture-policies/corp"},
		{http.MethodPut, "/api/v1/vpn/posture-policies/corp"},
		{http.MethodDelete, "/api/v1/vpn/posture-policies/corp"},
	}
	for _, route := range routes {
		recorder := serveVPN(nil, route[0], route[1], "{}")
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "%s %s", route[0], route[1])
	}
}

func TestVPNHandlerErrors(t *testing.T) {
	assert.Contains(t, ErrVPNUnavailable{}.Error(), "not configured")

	cause := &json.SyntaxError{}
	invalid := ErrVPNInvalidRequestBody{Cause: cause}
	assert.Contains(t, invalid.Error(), "invalid vpn request body")
	assert.ErrorIs(t, invalid, cause)

	assert.Contains(t, ErrVPNNameMismatch{Path: "corp", Body: "other"}.Error(), "does not match")
}

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// recordingSDN is an SDNService that records the request each RPC received
// and answers err, so a test sees exactly what the REST binding decoded.
type recordingSDN struct {
	platformv1.UnimplementedSDNServiceServer
	rpc string
	req proto.Message
	err error
}

func (s *recordingSDN) record(rpc string, req proto.Message) error {
	s.rpc, s.req = rpc, req
	return s.err
}

func (s *recordingSDN) CreateBridge(_ context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	return &platformv1.CreateBridgeResponse{}, s.record("CreateBridge", req)
}

func (s *recordingSDN) ListBridges(_ context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	return &platformv1.ListBridgesResponse{}, s.record("ListBridges", req)
}

func (s *recordingSDN) GetBridge(_ context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	return &platformv1.GetBridgeResponse{}, s.record("GetBridge", req)
}

func (s *recordingSDN) DeleteBridge(_ context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	return &platformv1.DeleteBridgeResponse{}, s.record("DeleteBridge", req)
}

func (s *recordingSDN) AddPort(_ context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	return &platformv1.AddPortResponse{}, s.record("AddPort", req)
}

func (s *recordingSDN) ListPorts(_ context.Context, req *platformv1.ListPortsRequest) (*platformv1.ListPortsResponse, error) {
	return &platformv1.ListPortsResponse{}, s.record("ListPorts", req)
}

func (s *recordingSDN) DeletePort(_ context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	return &platformv1.DeletePortResponse{}, s.record("DeletePort", req)
}

func (s *recordingSDN) GetPort(_ context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	return &platformv1.GetPortResponse{}, s.record("GetPort", req)
}

// SetPortState answers the port it set, so a test can read the response's
// wire shape.
func (s *recordingSDN) SetPortState(_ context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
	port := &platformv1.Port{
		Id:       req.GetPortId(),
		BridgeId: req.GetBridgeId(),
		Status:   platformv1.PortStatus_PORT_STATUS_DOWN,
	}
	return &platformv1.SetPortStateResponse{Port: port}, s.record("SetPortState", req)
}

func (s *recordingSDN) GetPortStats(_ context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	return &platformv1.GetPortStatsResponse{}, s.record("GetPortStats", req)
}

func (s *recordingSDN) AuthenticatePort(_ context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
	return &platformv1.AuthenticatePortResponse{}, s.record("AuthenticatePort", req)
}

func (s *recordingSDN) RevokePortAuth(_ context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
	return &platformv1.RevokePortAuthResponse{}, s.record("RevokePortAuth", req)
}

func (s *recordingSDN) AddFlow(_ context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	return &platformv1.AddFlowResponse{}, s.record("AddFlow", req)
}

func (s *recordingSDN) ListFlows(_ context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	return &platformv1.ListFlowsResponse{}, s.record("ListFlows", req)
}

func (s *recordingSDN) DeleteFlow(_ context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	return &platformv1.DeleteFlowResponse{}, s.record("DeleteFlow", req)
}

func (s *recordingSDN) CreateVLAN(_ context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	return &platformv1.CreateVLANResponse{}, s.record("CreateVLAN", req)
}

func (s *recordingSDN) ListVLANs(_ context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	return &platformv1.ListVLANsResponse{}, s.record("ListVLANs", req)
}

func (s *recordingSDN) DeleteVLAN(_ context.Context, req *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	return &platformv1.DeleteVLANResponse{}, s.record("DeleteVLAN", req)
}

func (s *recordingSDN) ApplyPolicy(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	return &platformv1.ApplyPolicyResponse{}, s.record("ApplyPolicy", req)
}

func (s *recordingSDN) ListPolicies(_ context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error) {
	return &platformv1.ListPoliciesResponse{}, s.record("ListPolicies", req)
}

func (s *recordingSDN) GetPolicy(_ context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error) {
	return &platformv1.GetPolicyResponse{}, s.record("GetPolicy", req)
}

func (s *recordingSDN) DeletePolicy(_ context.Context, req *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error) {
	return &platformv1.DeletePolicyResponse{}, s.record("DeletePolicy", req)
}

// sdnRouter registers the SDN routes over svc. A nil svc is passed as a nil
// interface.
func sdnRouter(svc *recordingSDN) *mux.Router {
	var server platformv1.SDNServiceServer
	if svc != nil {
		server = svc
	}
	router := mux.NewRouter()
	NewSDNHandlers(server, slog.Default()).RegisterRoutes(router)
	return router
}

// sdnRoute is one SDNService route: the request a caller sends and the RPC
// request the binding must decode it into.
type sdnRoute struct {
	method string
	path   string
	body   string
	rpc    string
	want   proto.Message
}

// sdnRoutes is the daemon's SDNService route table, as the SDK's REST
// transport (sdk/go/transport/rest/sdn.go) addresses it.
var sdnRoutes = []sdnRoute{
	{http.MethodPost, "/api/v1/sdn/bridges", `{"config":{"name":"br0","mtu":9000}}`, "CreateBridge",
		&platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br0", Mtu: 9000}}},
	{http.MethodGet, "/api/v1/sdn/bridges", "", "ListBridges", &platformv1.ListBridgesRequest{}},
	{http.MethodGet, "/api/v1/sdn/bridges/br0", "", "GetBridge", &platformv1.GetBridgeRequest{Id: "br0"}},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0?force=true", "", "DeleteBridge",
		&platformv1.DeleteBridgeRequest{Id: "br0", Force: true}},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/ports", `{"config":{"name":"eth0","vlan":10}}`, "AddPort",
		&platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{Name: "eth0", Vlan: 10}}},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports", "", "ListPorts", &platformv1.ListPortsRequest{BridgeId: "br0"}},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/eth0", "", "DeletePort",
		&platformv1.DeletePortRequest{BridgeId: "br0", PortId: "eth0"}},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports/eth0/state", "", "GetPort",
		&platformv1.GetPortRequest{BridgeId: "br0", PortId: "eth0"}},
	{http.MethodPut, "/api/v1/sdn/bridges/br0/ports/eth0/state",
		`{"adminState":"down","ingressRate":"10","ingressBurst":"1","egressRate":"20","egressBurst":"2"}`, "SetPortState",
		&platformv1.SetPortStateRequest{
			BridgeId: "br0", PortId: "eth0", AdminState: "down",
			IngressRate: 10, IngressBurst: 1, EgressRate: 20, EgressBurst: 2,
		}},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports/eth0/stats", "", "GetPortStats",
		&platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "eth0"}},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/ports/eth0/auth", `{"certificate":"AQI=","format":"DER"}`, "AuthenticatePort",
		&platformv1.AuthenticatePortRequest{BridgeId: "br0", PortId: "eth0", Certificate: []byte{1, 2}, Format: "DER"}},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/eth0/auth", "", "RevokePortAuth",
		&platformv1.RevokePortAuthRequest{BridgeId: "br0", PortId: "eth0"}},
	{http.MethodPost, "/api/v1/sdn/flows", `{"config":{"bridgeId":"br0","priority":100}}`, "AddFlow",
		&platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "br0", Priority: 100}}},
	{http.MethodGet, "/api/v1/sdn/flows?bridge_id=br0", "", "ListFlows", &platformv1.ListFlowsRequest{BridgeId: "br0"}},
	{http.MethodDelete, "/api/v1/sdn/flows", `{"bridgeId":"br0","flowId":"flow-1"}`, "DeleteFlow",
		&platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "flow-1"}},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/flows", "", "ListFlows", &platformv1.ListFlowsRequest{BridgeId: "br0"}},
	{http.MethodPost, "/api/v1/sdn/vlans", `{"config":{"vlanId":100,"bridgeId":"br0"}}`, "CreateVLAN",
		&platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{VlanId: 100, BridgeId: "br0"}}},
	{http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", "", "ListVLANs", &platformv1.ListVLANsRequest{BridgeId: "br0"}},
	{http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", "", "DeleteVLAN",
		&platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 100}},
	{http.MethodPost, "/api/v1/sdn/policies", `{"policyId":"p1","config":{"name":"web","type":"POLICY_TYPE_ACL"}}`, "ApplyPolicy",
		&platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: &platformv1.PolicyConfig{Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_ACL}}},
	{http.MethodGet, "/api/v1/sdn/policies?target_id=br0", "", "ListPolicies", &platformv1.ListPoliciesRequest{TargetId: "br0"}},
	{http.MethodGet, "/api/v1/sdn/policies/p1", "", "GetPolicy", &platformv1.GetPolicyRequest{PolicyId: "p1"}},
	{http.MethodDelete, "/api/v1/sdn/policies/p1", "", "DeletePolicy", &platformv1.DeletePolicyRequest{PolicyId: "p1"}},
}

func TestSDNHandlers_RoutesDecodeTheProtoRequest(t *testing.T) {
	t.Parallel()
	for _, route := range sdnRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			t.Parallel()
			svc := &recordingSDN{}

			rec := sdnServe(sdnRouter(svc), route.method, route.path, route.body)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, route.rpc, svc.rpc)
			assert.True(t, proto.Equal(route.want, svc.req), "got %v", svc.req)
		})
	}
}

func TestSDNHandlers_ResponseIsProtoJSON(t *testing.T) {
	t.Parallel()
	rec := sdnServe(sdnRouter(&recordingSDN{}), http.MethodPut,
		"/api/v1/sdn/bridges/br0/ports/eth0/state", `{"adminState":"down"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp platformv1.SetPortStateResponse
	require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "br0", resp.GetPort().GetBridgeId())
	assert.Equal(t, platformv1.PortStatus_PORT_STATUS_DOWN, resp.GetPort().GetStatus())

	var raw map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Contains(t, raw["port"], "bridgeId", "fields are lowerCamelCase, as protojson writes them")
}

func TestSDNHandlers_MapsServiceStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), http.StatusBadRequest},
		{"not found", status.Error(codes.NotFound, "missing"), http.StatusNotFound},
		{"already exists", status.Error(codes.AlreadyExists, "taken"), http.StatusConflict},
		{"failed precondition", status.Error(codes.FailedPrecondition, "busy"), http.StatusConflict},
		{"unavailable", status.Error(codes.Unavailable, "down"), http.StatusServiceUnavailable},
		{"internal", status.Error(codes.Internal, "boom"), http.StatusInternalServerError},
		{"untyped", ErrSDNServiceNotAvailable{}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &recordingSDN{err: tc.err}

			rec := sdnServe(sdnRouter(svc), http.MethodPut,
				"/api/v1/sdn/bridges/br0/ports/eth9/state", `{"adminState":"up"}`)

			assert.Equal(t, tc.want, rec.Code)
			assert.Equal(t, "SetPortState", svc.rpc)
		})
	}
}

func TestSDNHandlers_RefusesWhatTheBindingCannotDecode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"malformed body", http.MethodPost, "/api/v1/sdn/vlans", "not json"},
		{"unknown body field", http.MethodPut, "/api/v1/sdn/bridges/br0/ports/eth0/state", `{"adminState":"down","state":"down"}`},
		{"unknown query parameter", http.MethodGet, "/api/v1/sdn/vlans?bogus=1", ""},
		{"vlan id that is not a number", http.MethodDelete, "/api/v1/sdn/vlans/abc?bridge_id=br0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &recordingSDN{}

			rec := sdnServe(sdnRouter(svc), tc.method, tc.path, tc.body)

			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Empty(t, svc.rpc, "a refused request never reaches the service")
		})
	}
}

func TestSDNHandlers_NilServiceAnswers503(t *testing.T) {
	t.Parallel()
	router := sdnRouter(nil)
	for _, route := range sdnRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			t.Parallel()

			rec := sdnServe(router, route.method, route.path, route.body)

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

// The old daemon-only routes are gone: the SDK never addressed them and no
// RPC backs the topology view.
func TestSDNHandlers_RetiredRoutesAreNotServed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/sdn/topology"},
		{http.MethodDelete, "/api/v1/sdn/flows/flow-1"},
		{http.MethodPost, "/api/v1/sdn/bridges/br0/flows"},
		{http.MethodDelete, "/api/v1/sdn/bridges/br0/flows/flow-1"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			t.Parallel()
			svc := &recordingSDN{}

			rec := sdnServe(sdnRouter(svc), tc.method, tc.path, "{}")

			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code)
			assert.Empty(t, svc.rpc)
		})
	}
}

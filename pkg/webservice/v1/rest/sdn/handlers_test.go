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

package sdn

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// scriptedSDNServer records the request a handler hands the SDN service and
// answers with resp, or with err when it is set.
type scriptedSDNServer struct {
	platformv1.UnimplementedSDNServiceServer
	got  proto.Message
	resp proto.Message
	err  error
}

func answer[T proto.Message](s *scriptedSDNServer, req proto.Message) (T, error) {
	s.got = req
	var zero T
	if s.err != nil {
		return zero, s.err
	}
	if resp, ok := s.resp.(T); ok {
		return resp, nil
	}
	return zero, nil
}

func (s *scriptedSDNServer) CreateBridge(_ context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	return answer[*platformv1.CreateBridgeResponse](s, req)
}

func (s *scriptedSDNServer) ListBridges(_ context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	return answer[*platformv1.ListBridgesResponse](s, req)
}

func (s *scriptedSDNServer) GetBridge(_ context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	return answer[*platformv1.GetBridgeResponse](s, req)
}

func (s *scriptedSDNServer) DeleteBridge(_ context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	return answer[*platformv1.DeleteBridgeResponse](s, req)
}

func (s *scriptedSDNServer) AddPort(_ context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	return answer[*platformv1.AddPortResponse](s, req)
}

func (s *scriptedSDNServer) ListPorts(_ context.Context, req *platformv1.ListPortsRequest) (*platformv1.ListPortsResponse, error) {
	return answer[*platformv1.ListPortsResponse](s, req)
}

func (s *scriptedSDNServer) DeletePort(_ context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	return answer[*platformv1.DeletePortResponse](s, req)
}

func (s *scriptedSDNServer) GetPort(_ context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	return answer[*platformv1.GetPortResponse](s, req)
}

func (s *scriptedSDNServer) SetPortState(_ context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
	return answer[*platformv1.SetPortStateResponse](s, req)
}

func (s *scriptedSDNServer) GetPortStats(_ context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	return answer[*platformv1.GetPortStatsResponse](s, req)
}

func (s *scriptedSDNServer) AuthenticatePort(_ context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
	return answer[*platformv1.AuthenticatePortResponse](s, req)
}

func (s *scriptedSDNServer) RevokePortAuth(_ context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
	return answer[*platformv1.RevokePortAuthResponse](s, req)
}

func (s *scriptedSDNServer) AddFlow(_ context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	return answer[*platformv1.AddFlowResponse](s, req)
}

func (s *scriptedSDNServer) DeleteFlow(_ context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	return answer[*platformv1.DeleteFlowResponse](s, req)
}

func (s *scriptedSDNServer) ListFlows(_ context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	return answer[*platformv1.ListFlowsResponse](s, req)
}

func (s *scriptedSDNServer) ApplyPolicy(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	return answer[*platformv1.ApplyPolicyResponse](s, req)
}

func (s *scriptedSDNServer) ListPolicies(_ context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error) {
	return answer[*platformv1.ListPoliciesResponse](s, req)
}

func (s *scriptedSDNServer) GetPolicy(_ context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error) {
	return answer[*platformv1.GetPolicyResponse](s, req)
}

func (s *scriptedSDNServer) CreateVLAN(_ context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	return answer[*platformv1.CreateVLANResponse](s, req)
}

func (s *scriptedSDNServer) ListVLANs(_ context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	return answer[*platformv1.ListVLANsResponse](s, req)
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// newTestRouter mounts the SDN routes under /api/v1 on server, with the
// production response writer so the envelope is the one clients read.
func newTestRouter(server platformv1.SDNServiceServer) *mux.Router {
	logger := newTestLogger()
	root := mux.NewRouter()
	NewSDNRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// serve sends one request through the SDN routes.
func serve(server platformv1.SDNServiceServer, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newTestRouter(server).ServeHTTP(rec, req)
	return rec
}

// payload decodes the envelope's payload into msg with protojson, the way
// the SDK REST transport does.
func payload(t *testing.T, rec *httptest.ResponseRecorder, msg proto.Message) {
	t.Helper()
	var envelope struct {
		Success bool            `json:"success"`
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope), rec.Body.String())
	require.True(t, envelope.Success, rec.Body.String())
	require.NoError(t, protojson.Unmarshal(envelope.Payload, msg), string(envelope.Payload))
}

func testBridge() *platformv1.Bridge {
	return &platformv1.Bridge{
		Id:     "br0",
		Config: &platformv1.BridgeConfig{Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS, Mtu: 1500},
		Status: platformv1.BridgeStatus_BRIDGE_STATUS_UP,
	}
}

func testPort() *platformv1.Port {
	return &platformv1.Port{
		Id:       "port0",
		BridgeId: "br0",
		Config:   &platformv1.PortConfig{Name: "port0", Type: platformv1.PortType_PORT_TYPE_INTERNAL, Vlan: 10},
		Status:   platformv1.PortStatus_PORT_STATUS_UP,
	}
}

func testFlowConfig() *platformv1.FlowConfig {
	return &platformv1.FlowConfig{
		BridgeId: "br0",
		Priority: 100,
		Match:    &platformv1.FlowMatch{InPort: "1", VlanId: 10},
		Actions:  []*platformv1.FlowAction{{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"}},
	}
}

func testPolicy() *platformv1.Policy {
	return &platformv1.Policy{
		Id:     "p1",
		Config: &platformv1.PolicyConfig{Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS, Enabled: true},
		Status: platformv1.PolicyStatus_POLICY_STATUS_ACTIVE,
	}
}

func testVLAN() *platformv1.VLAN {
	return &platformv1.VLAN{Id: "br0-20", Config: &platformv1.VLANConfig{VlanId: 20, Name: "lab", BridgeId: "br0"}}
}

// TestRoutesDecodeTheProtoRequest: every route hands the service the proto
// request its JSON body, path and query make, and answers the proto
// response in the envelope.
func TestRoutesDecodeTheProtoRequest(t *testing.T) {
	ok := &platformv1.Status{Success: true}
	tests := []struct {
		name   string
		method string
		target string
		body   string
		status int
		want   proto.Message
		resp   proto.Message
		reply  proto.Message
	}{
		{
			name: "CreateBridge", method: http.MethodPost, target: "/api/v1/sdn/bridges",
			body: `{"config":{"name":"br0","type":"BRIDGE_TYPE_OVS","stpEnabled":true,"mtu":1500}}`,
			want: &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
				Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS, StpEnabled: true, Mtu: 1500}},
			resp: &platformv1.CreateBridgeResponse{Status: ok, Bridge: testBridge()}, reply: &platformv1.CreateBridgeResponse{},
		},
		{
			name: "ListBridges", method: http.MethodGet, target: "/api/v1/sdn/bridges",
			body:  `{"pagination":{"page":2,"pageSize":10}}`,
			want:  &platformv1.ListBridgesRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10}},
			resp:  &platformv1.ListBridgesResponse{Bridges: []*platformv1.Bridge{testBridge()}},
			reply: &platformv1.ListBridgesResponse{},
		},
		{
			name: "GetBridge", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0",
			want: &platformv1.GetBridgeRequest{Id: "br0"},
			resp: &platformv1.GetBridgeResponse{Bridge: testBridge()}, reply: &platformv1.GetBridgeResponse{},
		},
		{
			name: "DeleteBridge", method: http.MethodDelete, target: "/api/v1/sdn/bridges/br0",
			want: &platformv1.DeleteBridgeRequest{Id: "br0"},
			resp: &platformv1.DeleteBridgeResponse{Status: ok}, reply: &platformv1.DeleteBridgeResponse{},
		},
		{
			name: "AddPort", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/ports",
			body: `{"bridgeId":"ignored","config":{"name":"port0","type":"PORT_TYPE_INTERNAL","vlan":10,"trunkVlans":[20,30]}}`,
			want: &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{
				Name: "port0", Type: platformv1.PortType_PORT_TYPE_INTERNAL, Vlan: 10, TrunkVlans: []uint32{20, 30}}},
			resp: &platformv1.AddPortResponse{Status: ok, Port: testPort()}, reply: &platformv1.AddPortResponse{},
		},
		{
			name: "ListPorts", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/ports",
			want:  &platformv1.ListPortsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListPortsResponse{Ports: []*platformv1.Port{testPort()}},
			reply: &platformv1.ListPortsResponse{},
		},
		{
			name: "DeletePort", method: http.MethodDelete, target: "/api/v1/sdn/bridges/br0/ports/port0",
			want: &platformv1.DeletePortRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.DeletePortResponse{Status: ok}, reply: &platformv1.DeletePortResponse{},
		},
		{
			name: "GetPortState", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/ports/port0/state",
			want: &platformv1.GetPortRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.GetPortResponse{Port: testPort()}, reply: &platformv1.GetPortResponse{},
		},
		{
			name: "SetPortState", method: http.MethodPut, target: "/api/v1/sdn/bridges/br0/ports/port0/state",
			body: `{"adminState":"down","ingressRate":"1000","ingressBurst":"100"}`,
			want: &platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "port0", AdminState: "down",
				IngressRate: 1000, IngressBurst: 100},
			resp: &platformv1.SetPortStateResponse{Status: ok, Port: testPort()}, reply: &platformv1.SetPortStateResponse{},
		},
		{
			name: "GetPortStats", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/ports/port0/stats",
			want:  &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "port0"},
			resp:  &platformv1.GetPortStatsResponse{Stats: &platformv1.PortStats{PacketsReceived: 7, BytesSent: 512}},
			reply: &platformv1.GetPortStatsResponse{},
		},
		{
			name: "AuthenticatePort", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/ports/port0/auth",
			body: `{"certificate":"Y2VydA==","format":"PEM"}`,
			want: &platformv1.AuthenticatePortRequest{BridgeId: "br0", PortId: "port0", Certificate: []byte("cert"), Format: "PEM"},
			resp: &platformv1.AuthenticatePortResponse{Status: ok,
				Auth: &platformv1.PortAuth{Authenticated: true, CertificateCn: "device-1", AuthorizedVlans: []uint32{10}}},
			reply: &platformv1.AuthenticatePortResponse{},
		},
		{
			name: "RevokePortAuth", method: http.MethodDelete, target: "/api/v1/sdn/bridges/br0/ports/port0/auth",
			want: &platformv1.RevokePortAuthRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.RevokePortAuthResponse{Status: ok}, reply: &platformv1.RevokePortAuthResponse{},
		},
		{
			name: "AddFlow", method: http.MethodPost, target: "/api/v1/sdn/flows",
			body: `{"config":{"bridgeId":"br0","priority":100,"match":{"inPort":"1","vlanId":10},` +
				`"actions":[{"type":"FLOW_ACTION_OUTPUT","port":"2"}]}}`,
			want:  &platformv1.AddFlowRequest{Config: testFlowConfig()},
			resp:  &platformv1.AddFlowResponse{Status: ok, Flow: &platformv1.Flow{Id: "0x1", Config: testFlowConfig()}},
			reply: &platformv1.AddFlowResponse{},
		},
		{
			name: "AddFlowOnTheBridgePath", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/flows",
			body: `{"config":{"bridgeId":"ignored","priority":100,"match":{"inPort":"1","vlanId":10},` +
				`"actions":[{"type":"FLOW_ACTION_OUTPUT","port":"2"}]}}`,
			want:  &platformv1.AddFlowRequest{Config: testFlowConfig()},
			resp:  &platformv1.AddFlowResponse{Status: ok},
			reply: &platformv1.AddFlowResponse{},
		},
		{
			name: "DeleteFlow", method: http.MethodDelete, target: "/api/v1/sdn/flows",
			body: `{"bridgeId":"br0","flowId":"0x1"}`,
			want: &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "0x1"},
			resp: &platformv1.DeleteFlowResponse{Status: ok}, reply: &platformv1.DeleteFlowResponse{},
		},
		{
			name: "ListFlowsByQuery", method: http.MethodGet, target: "/api/v1/sdn/flows?bridge_id=br0",
			want:  &platformv1.ListFlowsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListFlowsResponse{Flows: []*platformv1.Flow{{Id: "0x1", Config: testFlowConfig()}}},
			reply: &platformv1.ListFlowsResponse{},
		},
		{
			name: "ListFlowsFromTheBody", method: http.MethodGet, target: "/api/v1/sdn/flows",
			body:  `{"bridgeId":"br0"}`,
			want:  &platformv1.ListFlowsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListFlowsResponse{},
			reply: &platformv1.ListFlowsResponse{},
		},
		{
			name: "ListFlowsOnTheBridgePath", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/flows?bridge_id=ignored",
			want:  &platformv1.ListFlowsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListFlowsResponse{},
			reply: &platformv1.ListFlowsResponse{},
		},
		{
			name: "ApplyPolicy", method: http.MethodPost, target: "/api/v1/sdn/policies", status: http.StatusCreated,
			body: `{"policyId":"p1","config":{"name":"web","type":"POLICY_TYPE_QOS","enabled":true}}`,
			want: &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: &platformv1.PolicyConfig{
				Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS, Enabled: true}},
			resp: &platformv1.ApplyPolicyResponse{Status: ok, Policy: testPolicy()}, reply: &platformv1.ApplyPolicyResponse{},
		},
		{
			name: "ListPolicies", method: http.MethodGet, target: "/api/v1/sdn/policies",
			body:  `{"type":"qos","targetId":"eth1"}`,
			want:  &platformv1.ListPoliciesRequest{Type: "qos", TargetId: "eth1"},
			resp:  &platformv1.ListPoliciesResponse{Policies: []*platformv1.Policy{testPolicy()}},
			reply: &platformv1.ListPoliciesResponse{},
		},
		{
			name: "GetPolicy", method: http.MethodGet, target: "/api/v1/sdn/policies/p1",
			want: &platformv1.GetPolicyRequest{PolicyId: "p1"},
			resp: &platformv1.GetPolicyResponse{Policy: testPolicy()}, reply: &platformv1.GetPolicyResponse{},
		},
		{
			name: "CreateVLAN", method: http.MethodPost, target: "/api/v1/sdn/vlans",
			body: `{"config":{"vlanId":20,"name":"lab","bridgeId":"br0"}}`,
			want: &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{VlanId: 20, Name: "lab", BridgeId: "br0"}},
			resp: &platformv1.CreateVLANResponse{Status: ok, Vlan: testVLAN()}, reply: &platformv1.CreateVLANResponse{},
		},
		{
			name: "CreateVLANOnTheBridgePath", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/vlans",
			body: `{"config":{"vlanId":20,"name":"lab"}}`,
			want: &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{VlanId: 20, Name: "lab", BridgeId: "br0"}},
			resp: &platformv1.CreateVLANResponse{Status: ok, Vlan: testVLAN()}, reply: &platformv1.CreateVLANResponse{},
		},
		{
			name: "ListVLANsByQuery", method: http.MethodGet, target: "/api/v1/sdn/vlans?bridge_id=br0",
			want:  &platformv1.ListVLANsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListVLANsResponse{Vlans: []*platformv1.VLAN{testVLAN()}},
			reply: &platformv1.ListVLANsResponse{},
		},
		{
			name: "ListVLANsOnTheBridgePath", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/vlans",
			want:  &platformv1.ListVLANsRequest{BridgeId: "br0"},
			resp:  &platformv1.ListVLANsResponse{},
			reply: &platformv1.ListVLANsResponse{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedSDNServer{resp: tc.resp}
			rec := serve(server, tc.method, tc.target, tc.body)

			want := tc.status
			if want == 0 {
				want = http.StatusOK
			}
			require.Equal(t, want, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, server.got), "request = %v, want %v", server.got, tc.want)
			payload(t, rec, tc.reply)
			assert.True(t, proto.Equal(tc.resp, tc.reply), "reply = %v, want %v", tc.reply, tc.resp)
		})
	}
}

// TestBridgeReplyIsTheProtoJSONShape: the payload carries the proto JSON
// names and enum names and emits unpopulated fields, not the retired flat
// REST shape (name, type "ovs", created_at at the top of the bridge).
func TestBridgeReplyIsTheProtoJSONShape(t *testing.T) {
	server := &scriptedSDNServer{resp: &platformv1.GetBridgeResponse{Bridge: testBridge()}}
	rec := serve(server, http.MethodGet, "/api/v1/sdn/bridges/br0", "")

	require.Equal(t, http.StatusOK, rec.Code)
	var envelope struct {
		Payload struct {
			Bridge map[string]json.RawMessage `json:"bridge"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	bridge := envelope.Payload.Bridge
	assert.JSONEq(t, `"BRIDGE_STATUS_UP"`, string(bridge["status"]))
	assert.Contains(t, bridge, "ports", "unpopulated fields are emitted")
	assert.NotContains(t, bridge, "name")
	assert.NotContains(t, bridge, "created_at")
	var config map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(bridge["config"], &config))
	assert.JSONEq(t, `"BRIDGE_TYPE_OVS"`, string(config["type"]))
	assert.Contains(t, config, "stpEnabled")
}

// TestServiceErrorsMapToHTTP: a gRPC status from the service is the HTTP
// status the other proto-shaped routes answer.
func TestServiceErrorsMapToHTTP(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"InvalidArgument", status.Error(codes.InvalidArgument, "bridge id or name is required"), http.StatusBadRequest},
		{"FailedPrecondition", status.Error(codes.FailedPrecondition, "port authentication is not enforced"), http.StatusConflict},
		{"NotFound", status.Error(codes.NotFound, "bridge not found"), http.StatusNotFound},
		{"AlreadyExists", status.Error(codes.AlreadyExists, "bridge exists"), http.StatusConflict},
		{"Internal", status.Error(codes.Internal, "ovs failed"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(&scriptedSDNServer{err: tc.err}, http.MethodGet, "/api/v1/sdn/bridges/br0", "")
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

// The service refuses port authentication with FailedPrecondition while the
// switch does not enforce it (#304); REST answers 409, the platform's status
// for that class (#665), not 500.
func TestPortAuth_RefusalIsConflict(t *testing.T) {
	refusals := map[string]policy.ErrPortAuthNotEnforced{
		http.MethodPost:   {Operation: "AuthenticatePort"},
		http.MethodDelete: {Operation: "RevokePortAuth"},
	}
	for method, refusal := range refusals {
		t.Run(method, func(t *testing.T) {
			rec := serve(&scriptedSDNServer{err: refusal}, method, "/api/v1/sdn/bridges/br0/ports/port0/auth", "{}")

			assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
			var answer restwire.WebServiceResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
			assert.Equal(t, refusal.Error(), answer.Error, "the refusal's own message reaches the caller")
		})
	}
}

// everyRoute is one request to each bridge, port, flow, policy and VLAN
// route.
var everyRoute = []struct{ method, target string }{
	{http.MethodPost, "/api/v1/sdn/bridges"},
	{http.MethodGet, "/api/v1/sdn/bridges"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0"},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0"},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/ports"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports"},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/state"},
	{http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/stats"},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/ports/port0/auth"},
	{http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0/auth"},
	{http.MethodPost, "/api/v1/sdn/flows"},
	{http.MethodDelete, "/api/v1/sdn/flows"},
	{http.MethodGet, "/api/v1/sdn/flows"},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/flows"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/flows"},
	{http.MethodPost, "/api/v1/sdn/policies"},
	{http.MethodGet, "/api/v1/sdn/policies"},
	{http.MethodGet, "/api/v1/sdn/policies/p1"},
	{http.MethodPost, "/api/v1/sdn/vlans"},
	{http.MethodGet, "/api/v1/sdn/vlans"},
	{http.MethodPost, "/api/v1/sdn/bridges/br0/vlans"},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/vlans"},
}

// TestNoServerIsServiceUnavailable: every route answers 503 when the SDN
// service is not wired.
func TestNoServerIsServiceUnavailable(t *testing.T) {
	for _, route := range everyRoute {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			rec := serve(nil, route.method, route.target, "")
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		})
	}
}

// TestEveryRouteWritesTheServiceError: each route answers a service error
// with its status, not a payload.
func TestEveryRouteWritesTheServiceError(t *testing.T) {
	for _, route := range everyRoute {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			server := &scriptedSDNServer{err: status.Error(codes.NotFound, "bridge not found")}
			rec := serve(server, route.method, route.target, "")
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.NotNil(t, server.got, "the route did not reach the service")
		})
	}
}

// TestBadBodyIsBadRequest: a body the route cannot decode as its proto
// request is a typed 400 and never reaches the service.
func TestBadBodyIsBadRequest(t *testing.T) {
	tests := []struct {
		name, method, target, body string
	}{
		{"BodyIsNotJSON", http.MethodPost, "/api/v1/sdn/bridges", `{"config":`},
		{"ConfigIsNotAnObject", http.MethodPost, "/api/v1/sdn/bridges", `{"config":"br0"}`},
		{"PortVLANIsNotANumber", http.MethodPost, "/api/v1/sdn/bridges/br0/ports", `{"config":{"vlan":"ten"}}`},
		{"PortStateRateIsNotANumber", http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state", `{"ingressRate":"fast"}`},
		{"CertificateIsNotBase64", http.MethodPost, "/api/v1/sdn/bridges/br0/ports/port0/auth", `{"certificate":"not base64!"}`},
		{"FlowActionsIsNotAList", http.MethodPost, "/api/v1/sdn/flows", `{"config":{"actions":{"type":"FLOW_ACTION_DROP"}}}`},
		{"DeleteFlowIsNotJSON", http.MethodDelete, "/api/v1/sdn/flows", `[`},
		{"ListFlowsIsNotJSON", http.MethodGet, "/api/v1/sdn/flows", `[`},
		{"PolicyRulesIsNotAList", http.MethodPost, "/api/v1/sdn/policies", `{"config":{"rules":"all"}}`},
		{"VLANIDIsNotANumber", http.MethodPost, "/api/v1/sdn/vlans", `{"config":{"vlanId":"twenty"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedSDNServer{}
			rec := serve(server, tc.method, tc.target, tc.body)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "invalid request body", "the 400 is the typed decode error")
			assert.Nil(t, server.got, "the service was called")
		})
	}
}

// TestPathBridgeNeedsAConfig: a bridge-scoped AddFlow or CreateVLAN without
// a config reaches the service unchanged, which refuses it.
func TestPathBridgeNeedsAConfig(t *testing.T) {
	for _, target := range []string{"/api/v1/sdn/bridges/br0/flows", "/api/v1/sdn/bridges/br0/vlans"} {
		t.Run(target, func(t *testing.T) {
			server := &scriptedSDNServer{err: status.Error(codes.InvalidArgument, "config is required")}
			rec := serve(server, http.MethodPost, target, `{}`)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.NotNil(t, server.got, "the route did not reach the service")
			config := server.got.ProtoReflect().Descriptor().Fields().ByName("config")
			assert.False(t, server.got.ProtoReflect().Has(config), "the route invented a config")
		})
	}
}

// TestEnvelopeIsTheRestWireShape: the reply decodes as the shared envelope.
func TestEnvelopeIsTheRestWireShape(t *testing.T) {
	server := &scriptedSDNServer{resp: &platformv1.DeleteBridgeResponse{Status: &platformv1.Status{Success: true}}}
	rec := serve(server, http.MethodDelete, "/api/v1/sdn/bridges/br0", "")

	var envelope restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.True(t, envelope.Success)
	assert.Equal(t, http.StatusOK, envelope.Code)
}

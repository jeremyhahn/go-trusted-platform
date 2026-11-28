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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectSDNSDK returns an SDK SDN client connected through the REST adapter
// to the SDN router served by connectSDNConn.
func connectSDNSDK(t *testing.T, server platformv1.SDNServiceServer) platformv1.SDNServiceClient {
	t.Helper()
	return platformv1.NewSDNServiceClient(connectSDNConn(t, server))
}

// connectSDNConn serves the SDN router over TLS in-process and returns the
// SDK REST adapter's connection to it.
func connectSDNConn(t *testing.T, server platformv1.SDNServiceServer) grpc.ClientConnInterface {
	t.Helper()

	logger := newTestLogger()
	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewSDNRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return adapter.Connection()
}

func testPolicyConfig() *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS, Priority: 5, Enabled: true,
		Rules: []*platformv1.PolicyRule{{
			RuleId: "r1",
			Match:  &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/8", VlanId: 20},
			Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, ActionValue: "1mbit",
		}},
		Targets: []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, Id: "eth1"}},
	}
}

// TestSDKRESTRoundTrip: an SDK call over REST reaches the service as the
// request the caller built, and the caller reads the reply the service
// built.
func TestSDKRESTRoundTrip(t *testing.T) {
	ok := &platformv1.Status{Success: true, Message: "done"}
	policy := &platformv1.Policy{Id: "p1", Config: testPolicyConfig(),
		Status: platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, HitCount: 3}
	ctx := context.Background()
	port := testPort()
	flow := &platformv1.Flow{Id: "0x1", Config: testFlowConfig()}
	tests := []struct {
		name string
		req  proto.Message
		resp proto.Message
	}{
		{
			name: "CreateBridge",
			req: &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
				Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS, Controllers: []string{"tcp:10.0.0.1:6653"}}},
			resp: &platformv1.CreateBridgeResponse{Status: ok, Bridge: testBridge()},
		},
		{
			name: "ListBridges",
			req:  &platformv1.ListBridgesRequest{Pagination: &platformv1.PaginationRequest{PageSize: 10}},
			resp: &platformv1.ListBridgesResponse{Bridges: []*platformv1.Bridge{testBridge()}},
		},
		{name: "GetBridge", req: &platformv1.GetBridgeRequest{Id: "br0"},
			resp: &platformv1.GetBridgeResponse{Bridge: testBridge()}},
		{name: "DeleteBridge", req: &platformv1.DeleteBridgeRequest{Id: "br0"},
			resp: &platformv1.DeleteBridgeResponse{Status: ok}},
		{
			name: "AddPort",
			req:  &platformv1.AddPortRequest{BridgeId: "br0", Config: port.GetConfig()},
			resp: &platformv1.AddPortResponse{Status: ok, Port: port},
		},
		{name: "ListPorts", req: &platformv1.ListPortsRequest{BridgeId: "br0"},
			resp: &platformv1.ListPortsResponse{Ports: []*platformv1.Port{port}}},
		{name: "DeletePort", req: &platformv1.DeletePortRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.DeletePortResponse{Status: ok}},
		{name: "GetPort", req: &platformv1.GetPortRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.GetPortResponse{Port: port}},
		{
			name: "SetPortState",
			req: &platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "port0", AdminState: "down",
				IngressRate: 1 << 40, EgressBurst: 64},
			resp: &platformv1.SetPortStateResponse{Status: ok, Port: port},
		},
		{
			name: "GetPortStats",
			req:  &platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.GetPortStatsResponse{Stats: &platformv1.PortStats{PacketsReceived: 1 << 40, Dropped: 2}},
		},
		{
			name: "AuthenticatePort",
			req: &platformv1.AuthenticatePortRequest{BridgeId: "br0", PortId: "port0",
				Certificate: []byte("-----BEGIN CERTIFICATE-----"), Format: "PEM"},
			resp: &platformv1.AuthenticatePortResponse{Status: ok, Auth: &platformv1.PortAuth{
				Authenticated: true, CertificateCn: "device-1", Certificate: []byte("der"), AuthorizedVlans: []uint32{10}}},
		},
		{name: "RevokePortAuth", req: &platformv1.RevokePortAuthRequest{BridgeId: "br0", PortId: "port0"},
			resp: &platformv1.RevokePortAuthResponse{Status: ok}},
		{name: "AddFlow", req: &platformv1.AddFlowRequest{Config: testFlowConfig()},
			resp: &platformv1.AddFlowResponse{Status: ok, Flow: flow}},
		{name: "DeleteFlow", req: &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "0x1"},
			resp: &platformv1.DeleteFlowResponse{Status: ok}},
		{name: "ListFlows", req: &platformv1.ListFlowsRequest{BridgeId: "br0"},
			resp: &platformv1.ListFlowsResponse{Flows: []*platformv1.Flow{flow}}},
		{
			name: "ApplyPolicy",
			req:  &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: testPolicyConfig()},
			resp: &platformv1.ApplyPolicyResponse{Status: ok, Policy: policy},
		},
		{name: "ListPolicies", req: &platformv1.ListPoliciesRequest{Type: "qos", TargetId: "eth1"},
			resp: &platformv1.ListPoliciesResponse{Policies: []*platformv1.Policy{policy}}},
		{name: "GetPolicy", req: &platformv1.GetPolicyRequest{PolicyId: "p1"},
			resp: &platformv1.GetPolicyResponse{Policy: policy}},
		{name: "CreateVLAN", req: &platformv1.CreateVLANRequest{Config: testVLAN().GetConfig()},
			resp: &platformv1.CreateVLANResponse{Status: ok, Vlan: testVLAN()}},
		{name: "ListVLANs", req: &platformv1.ListVLANsRequest{BridgeId: "br0"},
			resp: &platformv1.ListVLANsResponse{Vlans: []*platformv1.VLAN{testVLAN()}}},
		{name: "DeleteVLAN", req: &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 20},
			resp: &platformv1.DeleteVLANResponse{Status: ok}},
		{name: "DeletePolicy", req: &platformv1.DeletePolicyRequest{PolicyId: "p1"},
			resp: &platformv1.DeletePolicyResponse{Status: ok}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedSDNServer{resp: tc.resp}
			got := tc.resp.ProtoReflect().New().Interface()
			err := connectSDNConn(t, server).Invoke(ctx, "/"+platformv1.SDNService_ServiceDesc.ServiceName+"/"+tc.name, tc.req, got)
			require.NoError(t, err)
			assert.True(t, proto.Equal(tc.req, server.got), "request = %v, want %v", server.got, tc.req)
			assert.True(t, proto.Equal(tc.resp, got), "reply = %v, want %v", got, tc.resp)
		})
	}
}

func TestSDKRESTServiceRefusalIsInvalidArgument(t *testing.T) {
	server := &scriptedSDNServer{err: status.Error(codes.InvalidArgument, "policy name is required")}
	client := connectSDNSDK(t, server)

	_, err := client.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{}})

	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}

// zoneSDNServer answers the four network zone methods with scripted
// replies and records the request each one received.
type zoneSDNServer struct {
	platformv1.UnimplementedSDNServiceServer
	zone *platformv1.NetworkZone
	got  proto.Message
}

func (s *zoneSDNServer) CreateNetworkZone(_ context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error) {
	s.got = req
	return &platformv1.CreateNetworkZoneResponse{Zone: s.zone}, nil
}

func (s *zoneSDNServer) ListNetworkZones(_ context.Context, req *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error) {
	s.got = req
	return &platformv1.ListNetworkZonesResponse{Zones: []*platformv1.NetworkZone{s.zone}}, nil
}

func (s *zoneSDNServer) UpdateNetworkZone(_ context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.UpdateNetworkZoneResponse, error) {
	s.got = req
	return &platformv1.UpdateNetworkZoneResponse{Zone: s.zone}, nil
}

func (s *zoneSDNServer) DeleteNetworkZone(_ context.Context, req *platformv1.DeleteNetworkZoneRequest) (*platformv1.DeleteNetworkZoneResponse, error) {
	s.got = req
	return &platformv1.DeleteNetworkZoneResponse{RestartRequired: true}, nil
}

// TestSDKRESTZoneRoundTrip drives the four zone methods through the SDK
// REST transport against the real webservice zone routes: the zone
// config, numbering, timestamps and restart_required survive both ways.
func TestSDKRESTZoneRoundTrip(t *testing.T) {
	ctx := context.Background()
	cfg := &platformv1.NetworkZoneConfig{
		Name: "lab", Offset: 12, PortClasses: []string{"hypervisor"}, Isolate: true,
		IsolateFrom: []string{"dmz"}, Services: []string{"ntp"},
		AllowTo:          []*platformv1.NetworkZonePath{{Zone: "edge", Services: []string{"dns"}}},
		PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{Reason: "audit", ApprovedBy: "owner"},
	}
	stamp := timestamppb.New(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC))
	zone := &platformv1.NetworkZone{
		Config: cfg, CreatedAt: stamp, UpdatedAt: stamp, RestartRequired: true,
		Numbering: &platformv1.NetworkZoneNumbering{Vlan: 112, Subnet4: "10.0.12.0/24", Gateway: "10.0.12.1"},
	}
	server := &zoneSDNServer{zone: zone}
	client := connectSDNSDK(t, server)

	created, err := client.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: cfg})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.CreateNetworkZoneRequest{Config: cfg}, server.got), "request = %v", server.got)
	assert.True(t, proto.Equal(zone, created.GetZone()), "zone = %v, want %v", created.GetZone(), zone)

	listed, err := client.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{LifecycleRole: "quarantine"})
	require.NoError(t, err)
	assert.Equal(t, "quarantine", server.got.(*platformv1.ListNetworkZonesRequest).GetLifecycleRole())
	require.Len(t, listed.GetZones(), 1)
	assert.True(t, proto.Equal(zone, listed.GetZones()[0]), "zone = %v", listed.GetZones()[0])

	updated, err := client.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: cfg})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: cfg}, server.got), "request = %v", server.got)
	assert.True(t, proto.Equal(zone, updated.GetZone()), "zone = %v", updated.GetZone())

	deleted, err := client.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{Name: "lab"})
	require.NoError(t, err)
	assert.Equal(t, "lab", server.got.(*platformv1.DeleteNetworkZoneRequest).GetName())
	assert.True(t, deleted.GetRestartRequired())
	assert.True(t, deleted.GetStatus().GetSuccess())
}

// TestSDKRESTZoneOmitMutatesNothing proves an Omit=true Create or Update is
// refused with InvalidArgument and never reaches the zone service, so no zone
// is created or replaced for a field the REST document cannot carry.
func TestSDKRESTZoneOmitMutatesNothing(t *testing.T) {
	ctx := context.Background()
	cfg := &platformv1.NetworkZoneConfig{Name: "lab", Offset: 12, Omit: true}
	server := &zoneSDNServer{zone: &platformv1.NetworkZone{Config: cfg}}
	client := connectSDNSDK(t, server)

	_, err := client.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: cfg})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "create err = %v", err)
	assert.Nil(t, server.got, "create reached the zone service: %v", server.got)

	_, err = client.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: "lab", Config: cfg})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "update err = %v", err)
	assert.Nil(t, server.got, "update reached the zone service: %v", server.got)
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sentRequest is what the test server saw of one SDK request.
type sentRequest struct {
	method, path, query string
	body                map[string]interface{}
}

// sdnOverREST returns an SDN client whose REST transport talks to a server
// that records the request and answers with payload in the platform envelope.
func sdnOverREST(t *testing.T, payload string) (platformv1.SDNServiceClient, *sentRequest) {
	t.Helper()
	sent := &sentRequest{}
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		sent.method, sent.path, sent.query = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		raw, err := io.ReadAll(r.Body)
		if err != nil || (len(raw) > 0 && json.Unmarshal(raw, &sent.body) != nil) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"success":true,"payload":` + payload + `}`))
	})
	return platformv1.NewSDNServiceClient(a.Connection()), sent
}

// sdnPortJSON is a Port as the server's protojson writes it.
const sdnPortJSON = `{"id":"7f3c","bridgeId":"br-int","config":{"name":"eth0","type":"PORT_TYPE_TAP","vlan":10},` +
	`"status":"PORT_STATUS_UP","createdAt":"2026-10-26T08:00:00Z"}`

// TestSDN_SDKOverREST_EveryCallReachesItsRoute: each SDN call reaches the
// route the webservice serves, with the bridge and port in the path, the
// VLAN filter in the query, and the rest of the proto request as the
// protojson body.
func TestSDN_SDKOverREST_EveryCallReachesItsRoute(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		call   func(platformv1.SDNServiceClient) error
		method string
		path   string
		query  string
		body   map[string]interface{}
	}{
		{
			name: "CreateBridge",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.CreateBridge(ctx, &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{
					Name: "br-int", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS, StpEnabled: true}})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/bridges",
			body: map[string]interface{}{"config": map[string]interface{}{
				"name": "br-int", "type": "BRIDGE_TYPE_OVS", "stpEnabled": true}},
		},
		{
			name: "ListBridges",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ListBridges(ctx, &platformv1.ListBridgesRequest{
					Pagination: &platformv1.PaginationRequest{PageSize: 10}})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/bridges",
			body: map[string]interface{}{"pagination": map[string]interface{}{"pageSize": float64(10)}},
		},
		{
			name: "GetBridge",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.GetBridge(ctx, &platformv1.GetBridgeRequest{Id: "br-int"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/bridges/br-int",
		},
		{
			name: "DeleteBridge",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{Id: "br-int"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/sdn/bridges/br-int",
		},
		{
			name: "AddPort",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.AddPort(ctx, &platformv1.AddPortRequest{BridgeId: "br-int", Config: &platformv1.PortConfig{
					Name: "eth0", Type: platformv1.PortType_PORT_TYPE_TAP, TrunkVlans: []uint32{20}}})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/bridges/br-int/ports",
			body: map[string]interface{}{"config": map[string]interface{}{
				"name": "eth0", "type": "PORT_TYPE_TAP", "trunkVlans": []interface{}{float64(20)}}},
		},
		{
			name: "ListPorts",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ListPorts(ctx, &platformv1.ListPortsRequest{BridgeId: "br-int"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/bridges/br-int/ports",
		},
		{
			name: "DeletePort",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.DeletePort(ctx, &platformv1.DeletePortRequest{BridgeId: "br-int", PortId: "eth0"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/sdn/bridges/br-int/ports/eth0",
		},
		{
			name: "GetPort",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.GetPort(ctx, &platformv1.GetPortRequest{BridgeId: "br-int", PortId: "eth0"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/bridges/br-int/ports/eth0/state",
		},
		{
			name: "SetPortState",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.SetPortState(ctx, &platformv1.SetPortStateRequest{
					BridgeId: "br-int", PortId: "eth0", AdminState: "down", IngressRate: 10_000})
				return err
			},
			method: http.MethodPut, path: "/api/v1/sdn/bridges/br-int/ports/eth0/state",
			body: map[string]interface{}{"adminState": "down", "ingressRate": "10000"},
		},
		{
			name: "GetPortStats",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.GetPortStats(ctx, &platformv1.GetPortStatsRequest{BridgeId: "br-int", PortId: "eth0"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/bridges/br-int/ports/eth0/stats",
		},
		{
			name: "AuthenticatePort",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.AuthenticatePort(ctx, &platformv1.AuthenticatePortRequest{
					BridgeId: "br-int", PortId: "eth0", Certificate: []byte("cert"), Format: "PEM"})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/bridges/br-int/ports/eth0/auth",
			body: map[string]interface{}{"certificate": "Y2VydA==", "format": "PEM"},
		},
		{
			name: "RevokePortAuth",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{BridgeId: "br-int", PortId: "eth0"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/sdn/bridges/br-int/ports/eth0/auth",
		},
		{
			name: "AddFlow",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.AddFlow(ctx, &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{
					BridgeId: "br-int", Priority: 100,
					Actions: []*platformv1.FlowAction{{Type: platformv1.FlowActionType_FLOW_ACTION_DROP}}}})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/flows",
			body: map[string]interface{}{"config": map[string]interface{}{
				"bridgeId": "br-int", "priority": float64(100),
				"actions": []interface{}{map[string]interface{}{"type": "FLOW_ACTION_DROP"}}}},
		},
		{
			name: "DeleteFlow",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "br-int", FlowId: "0x1"})
				return err
			},
			method: http.MethodDelete, path: "/api/v1/sdn/flows",
			body: map[string]interface{}{"bridgeId": "br-int", "flowId": "0x1"},
		},
		{
			name: "ListFlows",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: "br-int"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/flows",
			body: map[string]interface{}{"bridgeId": "br-int"},
		},
		{
			name: "ApplyPolicy",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: &platformv1.PolicyConfig{
					Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS}})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/policies",
			body: map[string]interface{}{"policyId": "p1",
				"config": map[string]interface{}{"name": "web", "type": "POLICY_TYPE_QOS"}},
		},
		{
			name: "ListPolicies",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ListPolicies(ctx, &platformv1.ListPoliciesRequest{TargetId: "eth1"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/policies",
			body: map[string]interface{}{"targetId": "eth1"},
		},
		{
			name: "GetPolicy",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/policies/p1",
		},
		{
			name: "CreateVLAN",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.CreateVLAN(ctx, &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{
					VlanId: 20, Name: "lab", BridgeId: "br-int"}})
				return err
			},
			method: http.MethodPost, path: "/api/v1/sdn/vlans",
			body: map[string]interface{}{"config": map[string]interface{}{
				"vlanId": float64(20), "name": "lab", "bridgeId": "br-int"}},
		},
		{
			name: "ListVLANs",
			call: func(c platformv1.SDNServiceClient) error {
				_, err := c.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: "br-int"})
				return err
			},
			method: http.MethodGet, path: "/api/v1/sdn/vlans", query: "bridge_id=br-int",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := sdnOverREST(t, `{}`)
			if err := tc.call(client); err != nil {
				t.Fatalf("%s over REST: %v", tc.name, err)
			}
			if sent.method != tc.method || sent.path != tc.path || sent.query != tc.query {
				t.Errorf("sent %s %s?%s, want %s %s?%s", sent.method, sent.path, sent.query, tc.method, tc.path, tc.query)
			}
			wantJSON, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal want: %v", err)
			}
			if len(tc.body) == 0 {
				wantJSON = []byte(`{}`)
			}
			gotJSON, err := json.Marshal(sent.body)
			if err != nil {
				t.Fatalf("marshal got: %v", err)
			}
			if len(sent.body) == 0 {
				gotJSON = []byte(`{}`)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("body = %s, want %s: path and query fields travel only in the URL", gotJSON, wantJSON)
			}
		})
	}
}

// TestSDN_SDKOverREST_RepliesAreTheProto: the server's protojson reply is
// the gRPC reply, with no translation.
func TestSDN_SDKOverREST_RepliesAreTheProto(t *testing.T) {
	client, _ := sdnOverREST(t, `{"status":{"success":true,"message":"port added"},"port":`+sdnPortJSON+`}`)
	resp, err := client.AddPort(context.Background(), &platformv1.AddPortRequest{
		BridgeId: "br-int", Config: &platformv1.PortConfig{Name: "eth0"}})
	if err != nil {
		t.Fatalf("AddPort over REST: %v", err)
	}
	want := &platformv1.Port{}
	if err := protojson.Unmarshal([]byte(sdnPortJSON), want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if !proto.Equal(resp.GetPort(), want) || resp.GetStatus().GetMessage() != "port added" {
		t.Errorf("reply = %v, want port %v", resp, want)
	}

	client, _ = sdnOverREST(t, `{"status":{"success":true},"auth":{"authenticated":true,`+
		`"certificateCn":"device-1","certificate":"Y2VydA==","authorizedVlans":[10,20]}}`)
	auth, err := client.AuthenticatePort(context.Background(), &platformv1.AuthenticatePortRequest{
		BridgeId: "br-int", PortId: "eth0"})
	if err != nil {
		t.Fatalf("AuthenticatePort over REST: %v", err)
	}
	if !auth.GetAuth().GetAuthenticated() || string(auth.GetAuth().GetCertificate()) != "cert" ||
		len(auth.GetAuth().GetAuthorizedVlans()) != 2 {
		t.Errorf("auth = %v", auth.GetAuth())
	}
}

// TestSDN_SDKOverREST_RefusesARequestTheRouteCannotCarry: a request whose
// path identifier is unset is refused before anything is sent.
func TestSDN_SDKOverREST_RefusesARequestTheRouteCannotCarry(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(platformv1.SDNServiceClient) error
	}{
		{"GetBridge without id", func(c platformv1.SDNServiceClient) error {
			_, err := c.GetBridge(ctx, &platformv1.GetBridgeRequest{})
			return err
		}},
		{"DeleteBridge without id", func(c platformv1.SDNServiceClient) error {
			_, err := c.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{})
			return err
		}},
		{"AddPort without bridge", func(c platformv1.SDNServiceClient) error {
			_, err := c.AddPort(ctx, &platformv1.AddPortRequest{Config: &platformv1.PortConfig{Name: "eth0"}})
			return err
		}},
		{"SetPortState without port", func(c platformv1.SDNServiceClient) error {
			_, err := c.SetPortState(ctx, &platformv1.SetPortStateRequest{BridgeId: "br-int", AdminState: "up"})
			return err
		}},
		{"GetPortStats without bridge", func(c platformv1.SDNServiceClient) error {
			_, err := c.GetPortStats(ctx, &platformv1.GetPortStatsRequest{PortId: "eth0"})
			return err
		}},
		{"RevokePortAuth without port", func(c platformv1.SDNServiceClient) error {
			_, err := c.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{BridgeId: "br-int"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, sent := sdnOverREST(t, `{}`)
			err := tc.call(client)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
			}
			if sent.path != "" {
				t.Errorf("the refused request reached the server: %s %s", sent.method, sent.path)
			}
		})
	}
}

// TestSDNBodyEncoder_SendsProtoJSON: the body is the proto JSON mapping, so
// enums, bytes and 64-bit integers reach the server as protojson spells
// them.
func TestSDNBodyEncoder_SendsProtoJSON(t *testing.T) {
	request := &platformv1.SetPortStateRequest{AdminState: "up", EgressRate: 1 << 40}
	encode := restRequestEncoders[platformv1.SDNService_SetPortState_FullMethodName]
	body, err := encode(request)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw, ok := body.(json.RawMessage)
	if !ok {
		t.Fatalf("body = %T, want json.RawMessage", body)
	}
	decoded := &platformv1.SetPortStateRequest{}
	if err := protojson.Unmarshal(raw, decoded); err != nil || !proto.Equal(decoded, request) {
		t.Errorf("body %s decodes to %v (err %v), want %v", raw, decoded, err, request)
	}
}

// TestSDNBodyEncoder_RefusesABodyThatIsNotTheRequest: an SDN method's
// encoder sends only that method's request message.
func TestSDNBodyEncoder_RefusesABodyThatIsNotTheRequest(t *testing.T) {
	encode := restRequestEncoders[platformv1.SDNService_AddPort_FullMethodName]
	for name, body := range map[string]interface{}{
		"not a proto":     map[string]string{},
		"another request": &platformv1.DeletePortRequest{BridgeId: "br-int"},
		"no body":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := encode(body)
			var want ErrUnexpectedRequestType
			if !errors.As(err, &want) || want.Method != platformv1.SDNService_AddPort_FullMethodName {
				t.Fatalf("err = %v, want ErrUnexpectedRequestType for AddPort", err)
			}
		})
	}
}

// TestSDNZoneMethodsKeepTheirEncoding: the network-zone methods are not
// given the protojson encoder, since the zone routes keep the REST zone
// document.
func TestSDNZoneMethodsKeepTheirEncoding(t *testing.T) {
	for _, method := range []string{
		platformv1.SDNService_CreateNetworkZone_FullMethodName,
		platformv1.SDNService_UpdateNetworkZone_FullMethodName,
		platformv1.SDNService_DeleteNetworkZone_FullMethodName,
		platformv1.SDNService_ListNetworkZones_FullMethodName,
	} {
		if _, ok := restRequestEncoders[method]; ok {
			t.Errorf("%s has a protojson encoder", method)
		}
	}
	if _, ok := restRequestEncoders[platformv1.SDNService_CreateBridge_FullMethodName]; !ok {
		t.Error("CreateBridge has no protojson encoder")
	}
}

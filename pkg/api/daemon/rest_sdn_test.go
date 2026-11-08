// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// sdnRESTCallers are the callers the SDN REST tests authenticate as.
var sdnRESTCallers = iamRESTTokens{
	"sdn-operator": {Subject: "sdn-operator", TenantID: iamRESTTenantA, Scopes: []string{"sdn:read", "sdn:write", "sdn:delete"}},
	"sdn-reader":   {Subject: "sdn-reader", TenantID: iamRESTTenantA, Scopes: []string{"sdn:read"}},
	"dns-reader":   {Subject: "dns-reader", TenantID: iamRESTTenantA, Scopes: []string{"dns:read"}},
}

// sdnRESTGuard authenticates the sdnRESTCallers.
func sdnRESTGuard() *restapi.ScopeGuard {
	return restapi.NewScopeGuard(sdnRESTCallers, nil, nil)
}

// newRESTServerWithSDN wires a test SDN service holding bridge br0 into a
// REST server, the way the daemon does at startup.
func newRESTServerWithSDN(t *testing.T) (*RESTServer, *SDNService) {
	t.Helper()
	svc := newTestSDNService(NewConfigurableMockOVSClient())
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	server := newTestRESTServerForPhase35(t)
	require.NoError(t, server.SetSDNService(svc, sdnRESTGuard()))
	return server, svc
}

// doSDNJSON sends a JSON request as the sdn-operator caller and returns the
// status code and body.
func doSDNJSON(t *testing.T, s *RESTServer, method, path string, body interface{}) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sdn-operator")
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

// decodeREST decodes a protojson response body the SDN routes wrote.
func decodeREST(t *testing.T, body []byte, msg proto.Message) {
	t.Helper()
	require.NoError(t, protojson.Unmarshal(body, msg), string(body))
}

func listRESTVLANs(t *testing.T, server *RESTServer) []*platformv1.VLAN {
	t.Helper()
	code, body := doSDNJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	var resp platformv1.ListVLANsResponse
	decodeREST(t, body, &resp)
	return resp.GetVlans()
}

func vlanBody(config map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"config": config}
}

func TestRESTServer_SetSDNService_SharesVLANState(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)
	ctx := context.Background()

	code, body := doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		vlanBody(map[string]interface{}{"vlanId": 100, "name": "tenant-a", "bridgeId": "br0"}))
	require.Equal(t, http.StatusOK, code, string(body))
	var created platformv1.CreateVLANResponse
	decodeREST(t, body, &created)
	assert.Equal(t, uint32(100), created.GetVlan().GetConfig().GetVlanId())

	grpcList, err := svc.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: "br0"})
	require.NoError(t, err)
	require.Len(t, grpcList.GetVlans(), 1, "a VLAN created over REST is visible over gRPC")
	assert.Equal(t, uint32(100), grpcList.GetVlans()[0].GetConfig().GetVlanId())

	_, err = svc.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{VlanId: 200, BridgeId: "br0"},
	})
	require.NoError(t, err)
	assert.Len(t, listRESTVLANs(t, server), 2, "a VLAN created over gRPC is visible over REST")

	code, body = doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		vlanBody(map[string]interface{}{"vlanId": 100, "bridgeId": "br0"}))
	assert.Equal(t, http.StatusConflict, code, string(body))

	code, body = doSDNJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	remaining := listRESTVLANs(t, server)
	require.Len(t, remaining, 1)
	assert.Equal(t, uint32(200), remaining[0].GetConfig().GetVlanId())

	code, body = doSDNJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestRESTServer_SetSDNService_RejectsWhatGRPCRejects(t *testing.T) {
	server, _ := newRESTServerWithSDN(t)

	cases := []struct {
		name   string
		config map[string]interface{}
		want   int
	}{
		{"VLAN ID zero", map[string]interface{}{"vlanId": 0, "bridgeId": "br0"}, http.StatusBadRequest},
		{"VLAN ID above 4095", map[string]interface{}{"vlanId": 4096, "bridgeId": "br0"}, http.StatusBadRequest},
		{"missing bridge", map[string]interface{}{"vlanId": 10}, http.StatusBadRequest},
		{"unknown bridge", map[string]interface{}{"vlanId": 10, "bridgeId": "br-missing"}, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans", vlanBody(tc.config))
			assert.Equal(t, tc.want, code, string(body))
		})
	}

	assert.Empty(t, listRESTVLANs(t, server))
}

func TestRESTServer_SetSDNService_SharesPolicyState(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)
	ctx := context.Background()

	code, body := doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/policies", map[string]interface{}{
		"config": map[string]interface{}{
			"name":    "web",
			"type":    "POLICY_TYPE_ACL",
			"rules":   []map[string]interface{}{{"action": "POLICY_RULE_ACTION_DENY", "match": map[string]interface{}{"protocol": "tcp", "destinationPort": 22}}},
			"targets": []map[string]interface{}{{"type": "POLICY_TARGET_TYPE_BRIDGE", "id": "br0"}},
		},
	})
	require.Equal(t, http.StatusOK, code, string(body))
	var created platformv1.ApplyPolicyResponse
	decodeREST(t, body, &created)
	policyID := created.GetPolicy().GetId()
	require.NotEmpty(t, policyID)

	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: policyID})
	require.NoError(t, err, "a policy applied over REST is visible over gRPC")
	assert.Equal(t, platformv1.PolicyType_POLICY_TYPE_ACL, got.GetPolicy().GetConfig().GetType())
	require.Len(t, got.GetPolicy().GetConfig().GetRules(), 1)
	rule := got.GetPolicy().GetConfig().GetRules()[0]
	assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY, rule.GetAction())
	assert.Equal(t, uint32(22), rule.GetMatch().GetDestinationPort())

	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{Name: "db"}})
	require.NoError(t, err)
	code, body = doSDNJSON(t, server, http.MethodGet, "/api/v1/sdn/policies/db", nil)
	require.Equal(t, http.StatusOK, code, "a policy applied over gRPC is visible over REST: %s", body)
	code, body = doSDNJSON(t, server, http.MethodGet, "/api/v1/sdn/policies?type=acl", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	var listed platformv1.ListPoliciesResponse
	decodeREST(t, body, &listed)
	require.Len(t, listed.GetPolicies(), 1, "the type filter reaches the service")
	assert.Equal(t, "web", listed.GetPolicies()[0].GetConfig().GetName())

	code, body = doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/policies",
		map[string]interface{}{"config": map[string]interface{}{"name": "web"}})
	assert.Equal(t, http.StatusConflict, code, string(body))
	code, body = doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/policies",
		map[string]interface{}{"config": map[string]interface{}{"type": "POLICY_TYPE_ACL"}})
	assert.Equal(t, http.StatusBadRequest, code, "a nameless policy is rejected as gRPC rejects it: %s", body)

	code, body = doSDNJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+policyID, nil)
	require.Equal(t, http.StatusOK, code, string(body))
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: policyID})
	assert.Equal(t, codes.NotFound, status.Code(err), "a policy deleted over REST is gone over gRPC")

	code, body = doSDNJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+policyID, nil)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestRESTServer_SetSDNService_NilServiceAnswers503(t *testing.T) {
	server := newTestRESTServerForPhase35(t)
	require.NoError(t, server.SetSDNService(nil, sdnRESTGuard()))

	code, _ := doSDNJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		vlanBody(map[string]interface{}{"vlanId": 100, "bridgeId": "br0"}))
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doSDNJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doSDNJSON(t, server, http.MethodGet, "/api/v1/sdn/policies", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)
}

// sdnRouteScopes is every route SetSDNService mounts, with a concrete path
// and the scope the gRPC catalog gives its SDNService rpc.
var sdnRouteScopes = []struct{ method, route, path, scope string }{
	{http.MethodPost, "/api/v1/sdn/bridges", "/api/v1/sdn/bridges", "sdn:write"},                                                      // CreateBridge
	{http.MethodGet, "/api/v1/sdn/bridges", "/api/v1/sdn/bridges", "sdn:read"},                                                        // ListBridges
	{http.MethodGet, "/api/v1/sdn/bridges/{id}", "/api/v1/sdn/bridges/br0", "sdn:read"},                                               // GetBridge
	{http.MethodDelete, "/api/v1/sdn/bridges/{id}", "/api/v1/sdn/bridges/br0", "sdn:delete"},                                          // DeleteBridge
	{http.MethodPost, "/api/v1/sdn/bridges/{bridge_id}/ports", "/api/v1/sdn/bridges/br0/ports", "sdn:write"},                          // AddPort
	{http.MethodGet, "/api/v1/sdn/bridges/{bridge_id}/ports", "/api/v1/sdn/bridges/br0/ports", "sdn:read"},                            // ListPorts
	{http.MethodDelete, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}", "/api/v1/sdn/bridges/br0/ports/p1", "sdn:delete"},          // DeletePort
	{http.MethodGet, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/state", "/api/v1/sdn/bridges/br0/ports/p1/state", "sdn:read"},   // GetPort
	{http.MethodPut, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/state", "/api/v1/sdn/bridges/br0/ports/p1/state", "sdn:write"},  // SetPortState
	{http.MethodGet, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/stats", "/api/v1/sdn/bridges/br0/ports/p1/stats", "sdn:read"},   // GetPortStats
	{http.MethodPost, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth", "/api/v1/sdn/bridges/br0/ports/p1/auth", "sdn:write"},   // AuthenticatePort
	{http.MethodDelete, "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth", "/api/v1/sdn/bridges/br0/ports/p1/auth", "sdn:write"}, // RevokePortAuth
	{http.MethodPost, "/api/v1/sdn/flows", "/api/v1/sdn/flows", "sdn:write"},                                                          // AddFlow
	{http.MethodGet, "/api/v1/sdn/flows", "/api/v1/sdn/flows", "sdn:read"},                                                            // ListFlows
	{http.MethodDelete, "/api/v1/sdn/flows", "/api/v1/sdn/flows", "sdn:delete"},                                                       // DeleteFlow
	{http.MethodGet, "/api/v1/sdn/bridges/{bridge_id}/flows", "/api/v1/sdn/bridges/br0/flows", "sdn:read"},                            // ListFlows
	{http.MethodPost, "/api/v1/sdn/vlans", "/api/v1/sdn/vlans", "sdn:write"},                                                          // CreateVLAN
	{http.MethodGet, "/api/v1/sdn/vlans", "/api/v1/sdn/vlans", "sdn:read"},                                                            // ListVLANs
	{http.MethodDelete, "/api/v1/sdn/vlans/{vlan_id}", "/api/v1/sdn/vlans/100", "sdn:delete"},                                         // DeleteVLAN
	{http.MethodPost, "/api/v1/sdn/policies", "/api/v1/sdn/policies", "sdn:write"},                                                    // ApplyPolicy
	{http.MethodGet, "/api/v1/sdn/policies", "/api/v1/sdn/policies", "sdn:read"},                                                      // ListPolicies
	{http.MethodGet, "/api/v1/sdn/policies/{policy_id}", "/api/v1/sdn/policies/web", "sdn:read"},                                      // GetPolicy
	{http.MethodDelete, "/api/v1/sdn/policies/{policy_id}", "/api/v1/sdn/policies/web", "sdn:delete"},                                 // DeletePolicy
	{http.MethodPost, "/api/v1/sdn/zones", "/api/v1/sdn/zones", "sdn:write"},                                                          // CreateNetworkZone
	{http.MethodGet, "/api/v1/sdn/zones", "/api/v1/sdn/zones", "sdn:read"},                                                            // ListNetworkZones
	{http.MethodPut, "/api/v1/sdn/zones/{name}", "/api/v1/sdn/zones/dmz", "sdn:write"},                                                // UpdateNetworkZone
	{http.MethodDelete, "/api/v1/sdn/zones/{name}", "/api/v1/sdn/zones/dmz", "sdn:delete"},                                            // DeleteNetworkZone
}

func TestSetSDNService_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	err := s.SetSDNService(newTestSDNService(NewConfigurableMockOVSClient()), nil)
	var unavailable ErrSDNRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "no REST scope guard", unavailable.Reason)
	assert.Nil(t, s.sdnHandlers)
	assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/sdn/vlans", "sdn-operator").Code,
		"a refused mount serves no SDN route")
}

func TestSDNREST_EveryRouteNeedsItsScope(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetSDNService(newTestSDNService(NewConfigurableMockOVSClient()), sdnRESTGuard()))
	for _, tc := range sdnRouteScopes {
		name := tc.method + " " + tc.route
		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)
		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)
		recorder = serveIAM(s, tc.method, tc.path, "sdn-operator")
		assertReachedHandler(t, recorder, name, recorder.Body.String())
	}
}

func TestSetZoneService_ZoneRoutesNeedTheSDNScope(t *testing.T) {
	zones, err := gateway.NewZoneService(nil, nil)
	require.NoError(t, err)
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetSDNService(newTestSDNService(NewConfigurableMockOVSClient()), sdnRESTGuard()))
	s.SetZoneService(zones)

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/sdn/zones", "").Code)
	recorder := serveIAM(s, http.MethodGet, "/api/v1/sdn/zones", "dns-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "sdn:read")
	recorder = serveIAM(s, http.MethodGet, "/api/v1/sdn/zones", "sdn-operator")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
}

func TestSetZoneService_WithoutTheSDNScopeGuardMountsNothing(t *testing.T) {
	zones, err := gateway.NewZoneService(nil, nil)
	require.NoError(t, err)
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	s.SetZoneService(zones)

	assert.Nil(t, s.sdnHandlers)
	assert.Empty(t, s.ownedRoutes)
	assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/sdn/zones", "sdn-operator").Code)
}

func TestSDNREST_ReaderCannotWriteOrDelete(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)

	recorder := serveIAM(server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", "sdn-reader")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	recorder = serveIAM(server, http.MethodPost, "/api/v1/sdn/vlans", "sdn-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "sdn:write")

	recorder = serveIAM(server, http.MethodDelete, "/api/v1/sdn/bridges/br0", "sdn-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "sdn:delete")
	assert.Contains(t, svc.bridges, "br0", "a refused delete never reaches the service")
}

func TestSDNRouteScope(t *testing.T) {
	for _, tc := range sdnRouteScopes {
		scope, err := sdnRouteScope(tc.method, tc.route)
		require.NoError(t, err, "%s %s", tc.method, tc.route)
		assert.Equal(t, tc.scope, scope, "%s %s", tc.method, tc.route)
	}
	_, err := sdnRouteScope(http.MethodOptions, "/api/v1/sdn/bridges")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "sdn:*", forbidden.Scope)
}

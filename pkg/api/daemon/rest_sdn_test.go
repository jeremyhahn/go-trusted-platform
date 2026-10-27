// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// newRESTServerWithSDN wires a test SDN service holding bridge br0 into a
// REST server, the way the daemon does at startup.
func newRESTServerWithSDN(t *testing.T) (*RESTServer, *SDNService) {
	t.Helper()
	svc := newTestSDNService(NewConfigurableMockOVSClient())
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	server := newTestRESTServerForPhase35(t)
	server.SetSDNService(svc)
	return server, svc
}

// decodeREST decodes a protojson response body the SDN routes wrote.
func decodeREST(t *testing.T, body []byte, msg proto.Message) {
	t.Helper()
	require.NoError(t, protojson.Unmarshal(body, msg), string(body))
}

func listRESTVLANs(t *testing.T, server *RESTServer) []*platformv1.VLAN {
	t.Helper()
	code, body := doJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
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

	code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
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

	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		vlanBody(map[string]interface{}{"vlanId": 100, "bridgeId": "br0"}))
	assert.Equal(t, http.StatusConflict, code, string(body))

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	remaining := listRESTVLANs(t, server)
	require.Len(t, remaining, 1)
	assert.Equal(t, uint32(200), remaining[0].GetConfig().GetVlanId())

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
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
			code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans", vlanBody(tc.config))
			assert.Equal(t, tc.want, code, string(body))
		})
	}

	assert.Empty(t, listRESTVLANs(t, server))
}

func TestRESTServer_SetSDNService_SharesPolicyState(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)
	ctx := context.Background()

	code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies", map[string]interface{}{
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
	code, body = doJSON(t, server, http.MethodGet, "/api/v1/sdn/policies/db", nil)
	require.Equal(t, http.StatusOK, code, "a policy applied over gRPC is visible over REST: %s", body)
	code, body = doJSON(t, server, http.MethodGet, "/api/v1/sdn/policies?type=acl", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	var listed platformv1.ListPoliciesResponse
	decodeREST(t, body, &listed)
	require.Len(t, listed.GetPolicies(), 1, "the type filter reaches the service")
	assert.Equal(t, "web", listed.GetPolicies()[0].GetConfig().GetName())

	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies",
		map[string]interface{}{"config": map[string]interface{}{"name": "web"}})
	assert.Equal(t, http.StatusConflict, code, string(body))
	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies",
		map[string]interface{}{"config": map[string]interface{}{"type": "POLICY_TYPE_ACL"}})
	assert.Equal(t, http.StatusBadRequest, code, "a nameless policy is rejected as gRPC rejects it: %s", body)

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+policyID, nil)
	require.Equal(t, http.StatusOK, code, string(body))
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: policyID})
	assert.Equal(t, codes.NotFound, status.Code(err), "a policy deleted over REST is gone over gRPC")

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+policyID, nil)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestRESTServer_SetSDNService_NilServiceAnswers503(t *testing.T) {
	server := newTestRESTServerForPhase35(t)
	server.SetSDNService(nil)

	code, _ := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		vlanBody(map[string]interface{}{"vlanId": 100, "bridgeId": "br0"}))
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doJSON(t, server, http.MethodGet, "/api/v1/sdn/policies", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)
}

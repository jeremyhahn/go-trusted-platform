// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func listRESTVLANs(t *testing.T, server *RESTServer) restapi.VLANListResponse {
	t.Helper()
	code, body := doJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	var resp restapi.VLANListResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp
}

func TestRESTServer_SetSDNService_SharesVLANState(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)
	ctx := context.Background()

	code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		map[string]interface{}{"vlan_id": 100, "name": "tenant-a", "bridge_id": "br0"})
	require.Equal(t, http.StatusCreated, code, string(body))

	grpcList, err := svc.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: "br0"})
	require.NoError(t, err)
	require.Len(t, grpcList.GetVlans(), 1, "a VLAN created over REST is visible over gRPC")
	assert.Equal(t, uint32(100), grpcList.GetVlans()[0].GetConfig().GetVlanId())

	_, err = svc.CreateVLAN(ctx, &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{VlanId: 200, BridgeId: "br0"},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, listRESTVLANs(t, server).Count, "a VLAN created over gRPC is visible over REST")

	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		map[string]interface{}{"vlan_id": 100, "bridge_id": "br0"})
	assert.Equal(t, http.StatusConflict, code, string(body))

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	remaining := listRESTVLANs(t, server)
	require.Equal(t, 1, remaining.Count)
	assert.Equal(t, uint32(200), remaining.VLANs[0].VLANID)

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/vlans/100?bridge_id=br0", nil)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestRESTServer_SetSDNService_RejectsWhatGRPCRejects(t *testing.T) {
	server, _ := newRESTServerWithSDN(t)

	cases := []struct {
		name string
		body map[string]interface{}
		want int
	}{
		{"VLAN ID zero", map[string]interface{}{"vlan_id": 0, "bridge_id": "br0"}, http.StatusBadRequest},
		{"VLAN ID above 4095", map[string]interface{}{"vlan_id": 4096, "bridge_id": "br0"}, http.StatusBadRequest},
		{"missing bridge", map[string]interface{}{"vlan_id": 10}, http.StatusBadRequest},
		{"unknown bridge", map[string]interface{}{"vlan_id": 10, "bridge_id": "br-missing"}, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans", tc.body)
			assert.Equal(t, tc.want, code, string(body))
		})
	}

	assert.Equal(t, 0, listRESTVLANs(t, server).Count)
}

func TestRESTServer_SetSDNService_SharesPolicyState(t *testing.T) {
	server, svc := newRESTServerWithSDN(t)
	ctx := context.Background()

	code, body := doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies", map[string]interface{}{
		"name":    "web",
		"type":    "acl",
		"rules":   []map[string]interface{}{{"action": "deny", "protocol": "tcp", "destination_port": 22}},
		"targets": []map[string]interface{}{{"type": "bridge", "id": "br0"}},
	})
	require.Equal(t, http.StatusCreated, code, string(body))
	var created restapi.PolicyResponse
	require.NoError(t, json.Unmarshal(body, &created))

	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: created.ID})
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
	var listed restapi.SDNPolicyListResponse
	require.NoError(t, json.Unmarshal(body, &listed))
	require.Equal(t, 1, listed.Count, "the type filter reaches the service")
	assert.Equal(t, "web", listed.Policies[0].Name)

	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies", map[string]interface{}{"name": "web"})
	assert.Equal(t, http.StatusConflict, code, string(body))
	code, body = doJSON(t, server, http.MethodPost, "/api/v1/sdn/policies", map[string]interface{}{"type": "acl"})
	assert.Equal(t, http.StatusBadRequest, code, "a nameless policy is rejected as gRPC rejects it: %s", body)

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+created.ID, nil)
	require.Equal(t, http.StatusOK, code, string(body))
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: created.ID})
	assert.Equal(t, codes.NotFound, status.Code(err), "a policy deleted over REST is gone over gRPC")

	code, body = doJSON(t, server, http.MethodDelete, "/api/v1/sdn/policies/"+created.ID, nil)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestRESTServer_SetSDNService_NilServiceAnswers503(t *testing.T) {
	server := newTestRESTServerForPhase35(t)
	server.SetSDNService(nil)

	code, _ := doJSON(t, server, http.MethodPost, "/api/v1/sdn/vlans",
		map[string]interface{}{"vlan_id": 100, "bridge_id": "br0"})
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doJSON(t, server, http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)

	code, _ = doJSON(t, server, http.MethodGet, "/api/v1/sdn/policies", nil)
	assert.Equal(t, http.StatusServiceUnavailable, code)
}

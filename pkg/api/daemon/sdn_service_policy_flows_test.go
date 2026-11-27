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

package daemon

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newPolicyFlowsService(t *testing.T) (*SDNService, *ConfigurableMockOVSClient) {
	t.Helper()
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}
	return svc, mockClient
}

func applyACLPolicy(t *testing.T, svc *SDNService) string {
	t.Helper()
	resp, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{
		Name:     "web",
		Type:     platformv1.PolicyType_POLICY_TYPE_ACL,
		Priority: 100,
		Rules: []*platformv1.PolicyRule{
			{RuleId: "r1", Priority: 100, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW},
			{RuleId: "r2", Priority: 90, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY},
		},
		Targets: []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br0"}},
	}})
	require.NoError(t, err)
	return resp.GetPolicy().GetId()
}

func TestSDNServiceUnit_FlushFlowsRejectsTable(t *testing.T) {
	svc, m := newPolicyFlowsService(t)
	_, err := svc.FlushFlows(context.Background(), &platformv1.FlushFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable_FLOW_TABLE_1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Zero(t, m.GetCallCount("ListFlows"))
	assert.Zero(t, m.GetCallCount("DeleteAllFlows"))

	resp, err := svc.FlushFlows(context.Background(), &platformv1.FlushFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED})
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, 1, m.GetCallCount("DeleteAllFlows"))
}

func TestSDNServiceUnit_ListPoliciesTypeFilterAcceptsEnumName(t *testing.T) {
	svc, _ := newPolicyFlowsService(t)
	id := applyACLPolicy(t, svc)
	for _, typ := range []string{"POLICY_TYPE_ACL", "acl"} {
		list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{Type: typ})
		require.NoError(t, err)
		require.Len(t, list.GetPolicies(), 1, typ)
		assert.Equal(t, id, list.GetPolicies()[0].GetId())
	}
	list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{Type: "POLICY_TYPE_QOS"})
	require.NoError(t, err)
	assert.Empty(t, list.GetPolicies())
}

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

// The constraint matches quic_sdn_handlers_test.go, which defines the
// MockOVSClientInterface and newTestSDNServiceWithMock helpers used here.

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newEnforcePolicyFixture returns a service whose OVS mock holds one bridge,
// br0, with no flows installed.
func newEnforcePolicyFixture(t *testing.T) (*SDNService, *MockOVSClientInterface) {
	t.Helper()
	mockOVS := NewMockOVSClientInterface()
	mockOVS.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	return newTestSDNServiceWithMock(t, mockOVS), mockOVS
}

func enforcePolicyConfig(enabled bool, targets ...*platformv1.PolicyTarget) *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name:     "web",
		Priority: 100,
		Enabled:  enabled,
		Rules: []*platformv1.PolicyRule{
			{RuleId: "r1", Priority: 100, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW},
		},
		Targets: targets,
	}
}

func bridgeTarget(id string) *platformv1.PolicyTarget {
	return &platformv1.PolicyTarget{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: id}
}

func requireNoFlows(t *testing.T, mockOVS *MockOVSClientInterface, bridge string) {
	t.Helper()
	flows, err := mockOVS.ListFlows(context.Background(), bridge)
	require.NoError(t, err)
	assert.Empty(t, flows)
}

// TestSDNService_ApplyPolicy_RefusesNonBridgeTarget checks a non-bridge target
// fails the whole call before any flow is installed on the bridge targets.
func TestSDNService_ApplyPolicy_RefusesNonBridgeTarget(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		Config: enforcePolicyConfig(true,
			bridgeTarget("br0"),
			&platformv1.PolicyTarget{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, Id: "p1"},
		),
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	requireNoFlows(t, mockOVS, "br0")

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	assert.Empty(t, svc.policies)
}

// TestSDNService_ApplyPolicy_RefusesUnresolvedBridge checks a bridge ID that
// resolves to no bridge is reported NotFound and nothing is installed.
func TestSDNService_ApplyPolicy_RefusesUnresolvedBridge(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		Config: enforcePolicyConfig(true, bridgeTarget("br0"), bridgeTarget("missing")),
	})
	assert.Equal(t, codes.NotFound, status.Code(err))
	requireNoFlows(t, mockOVS, "br0")

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	assert.Empty(t, svc.policies)
}

// TestSDNService_ApplyPolicy_DisabledInstallsNothing checks a disabled policy
// is stored with status "disabled" and installs no flows.
func TestSDNService_ApplyPolicy_DisabledInstallsNothing(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)

	resp, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		Config: enforcePolicyConfig(false, bridgeTarget("br0")),
	})
	require.NoError(t, err)
	requireNoFlows(t, mockOVS, "br0")

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	stored, ok := svc.policies[resp.GetPolicy().GetId()]
	require.True(t, ok)
	assert.False(t, stored.enabled)
	assert.Equal(t, "inactive", stored.status)
	assert.Empty(t, stored.flows)
}

// TestSDNService_ApplyPolicy_EnabledInstallsFlows checks an enabled policy on a
// resolved bridge installs one flow per rule and is stored "active".
func TestSDNService_ApplyPolicy_EnabledInstallsFlows(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)

	resp, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)

	flows, err := mockOVS.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	assert.Len(t, flows, 1)

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	stored, ok := svc.policies[resp.GetPolicy().GetId()]
	require.True(t, ok)
	assert.Equal(t, "active", stored.status)
}

// sshDenyConfig is a deny policy whose one rule matches TCP port 22.
func sshDenyConfig(name string, enabled bool) *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name:     name,
		Priority: 200,
		Enabled:  enabled,
		Rules: []*platformv1.PolicyRule{{
			RuleId:   "ssh",
			Priority: 200,
			Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match:    &platformv1.PolicyRuleMatch{Protocol: "6", DestinationPort: 22},
		}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}
}

// Deleting a disabled policy that shares a rule match with an active
// policy leaves the active policy's flows on the bridge (#1951 (b)).
func TestSDNService_DeletePolicy_KeepsOtherPolicysFlows(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("deny-ssh", true)})
	require.NoError(t, err)
	draft, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("draft-ssh", false)})
	require.NoError(t, err)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: draft.GetPolicy().GetId()})
	require.NoError(t, err)

	flows, err := mockOVS.ListFlows(ctx, "br0")
	require.NoError(t, err)
	assert.Len(t, flows, 1, "the active deny policy's flow must survive")
}

// Re-applying an enabled policy with enabled=false removes the flows the
// earlier apply installed (#1951 (c)).
func TestSDNService_ApplyPolicy_DisableRemovesInstalledFlows(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)
	ctx := context.Background()

	resp, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("deny-ssh", true)})
	require.NoError(t, err)
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: resp.GetPolicy().GetId(),
		Config:   sshDenyConfig("deny-ssh", false),
	})
	require.NoError(t, err)
	requireNoFlows(t, mockOVS, "br0")
}

// A catch-all rule (no match fields) is removed by DeletePolicy (#1951 (d)).
func TestSDNService_DeletePolicy_RemovesCatchAllRule(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)
	ctx := context.Background()

	resp, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: enforcePolicyConfig(true, bridgeTarget("br0"))})
	require.NoError(t, err)
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: resp.GetPolicy().GetId()})
	require.NoError(t, err)
	requireNoFlows(t, mockOVS, "br0")
}

// A failed flow removal fails DeletePolicy and keeps the record.
func TestSDNService_DeletePolicy_FlowRemovalFailureKeepsPolicy(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)
	ctx := context.Background()

	resp, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("deny-ssh", true)})
	require.NoError(t, err)
	mockOVS.deleteFlowsByCookieErr = errors.New("ovs unavailable")

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: resp.GetPolicy().GetId()})
	assert.Equal(t, codes.Internal, status.Code(err))

	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: resp.GetPolicy().GetId()})
	require.NoError(t, err)
}

// A disabled policy reports POLICY_STATUS_INACTIVE (#1951 (f)).
func TestSDNService_GetPolicy_DisabledIsInactive(t *testing.T) {
	svc, _ := newEnforcePolicyFixture(t)
	ctx := context.Background()

	resp, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("draft-ssh", false)})
	require.NoError(t, err)
	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: resp.GetPolicy().GetId()})
	require.NoError(t, err)
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, got.GetPolicy().GetStatus())
}

// A failed flow install fails ApplyPolicy and leaves no flows behind.
func TestSDNService_ApplyPolicy_AddFlowFailureInstallsNothing(t *testing.T) {
	svc, mockOVS := newEnforcePolicyFixture(t)
	mockOVS.addFlowErr = errors.New("ovs unavailable")

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: sshDenyConfig("deny-ssh", true)})
	assert.Equal(t, codes.Internal, status.Code(err))
	requireNoFlows(t, mockOVS, "br0")

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	assert.Empty(t, svc.policies)
}

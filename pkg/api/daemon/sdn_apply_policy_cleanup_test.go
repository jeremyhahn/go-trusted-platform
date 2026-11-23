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

// The constraint matches sdn_apply_policy_enforce_test.go, whose fixtures
// (replacingOVS, twoRulePolicyConfig, getPolicy) are used here.

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// bridgeFailOVS is a replacingOVS whose strict deletes fail on the bridges
// listed in failDelete, so a withdrawal or rollback can fail on one bridge
// only.
type bridgeFailOVS struct {
	*replacingOVS

	failDelete map[string]bool
}

func (f *bridgeFailOVS) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if f.failDelete[bridgeName] {
		return errInjectedOVS
	}
	return f.replacingOVS.DeleteFlowStrict(ctx, bridgeName, flow)
}

func newBridgeFailFixture(t *testing.T) (*SDNService, *bridgeFailOVS) {
	t.Helper()
	fake := &bridgeFailOVS{
		replacingOVS: &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()},
		failDelete:   map[string]bool{},
	}
	fake.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	fake.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-br1", Name: "br1"})
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	return svc, fake
}

// failStaleWithdrawal applies p1 on br0, then reapplies it on br1 while
// deletes on br0 fail: the br0 flows stay installed and the reapply returns
// Internal with the record marked ERROR.
func failStaleWithdrawal(t *testing.T, svc *SDNService, fake *bridgeFailOVS) *platformv1.PolicyConfig {
	t.Helper()
	ctx := context.Background()
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	require.Len(t, fake.matches(t, "br0"), 2)

	fake.failDelete["br0"] = true
	cfg := twoRulePolicyConfig()
	cfg.Targets = []*platformv1.PolicyTarget{bridgeTarget("br1")}
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ERROR, getPolicy(t, svc, "p1").GetStatus())
	require.Len(t, fake.matches(t, "br0"), 2)
	require.Len(t, fake.matches(t, "br1"), 2)
	return cfg
}

func TestSDNService_ApplyPolicy_FailedStaleWithdrawalKeepsOldBridgeFlows(t *testing.T) {
	svc, fake := newBridgeFailFixture(t)
	cfg := failStaleWithdrawal(t, svc, fake)

	delete(fake.failDelete, "br0")
	cfg.Enabled = false
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Empty(t, fake.matches(t, "br1"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, getPolicy(t, svc, "p1").GetStatus())
}

func TestSDNService_DeletePolicy_AfterFailedStaleWithdrawalRemovesOldBridgeFlows(t *testing.T) {
	svc, fake := newBridgeFailFixture(t)
	failStaleWithdrawal(t, svc, fake)

	delete(fake.failDelete, "br0")
	ctx := context.Background()
	_, err := svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Empty(t, fake.matches(t, "br1"))
	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSDNService_ApplyPolicy_FailedRollbackKeepsAttemptedFlows(t *testing.T) {
	svc, fake := newBridgeFailFixture(t)
	ctx := context.Background()
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	// The first br1 flow is installed, the second fails, and the rollback
	// cannot delete either from br1.
	fake.failAddOn = fake.addCalls + 2
	fake.failDelete["br1"] = true
	cfg := twoRulePolicyConfig()
	cfg.Targets = []*platformv1.PolicyTarget{bridgeTarget("br1")}
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
	require.Equal(t, codes.Internal, status.Code(err))
	require.NotEmpty(t, fake.matches(t, "br1"))

	delete(fake.failDelete, "br1")
	fake.failAddOn = 0
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Empty(t, fake.matches(t, "br1"))
}

func TestSDNService_DeletePolicy_PriorDisabledRecordCleansFailedAttempt(t *testing.T) {
	svc, fake := newBridgeFailFixture(t)
	ctx := context.Background()
	disabled := twoRulePolicyConfig()
	disabled.Enabled = false
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: disabled})
	require.NoError(t, err)

	fake.failAddOn = fake.addCalls + 2
	fake.failDelete["br0"] = true
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ERROR, getPolicy(t, svc, "p1").GetStatus())
	require.NotEmpty(t, fake.matches(t, "br0"))

	delete(fake.failDelete, "br0")
	fake.failAddOn = 0
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
}

func TestSDNService_ApplyPolicy_PendingFlowsBlockConflictingPolicy(t *testing.T) {
	svc, fake := newBridgeFailFixture(t)
	failStaleWithdrawal(t, svc, fake)

	// p1's record now targets br1, but its br0 flows are still installed.
	other := &platformv1.PolicyConfig{
		Name:     "other",
		Priority: 100,
		Enabled:  true,
		Rules: []*platformv1.PolicyRule{
			{RuleId: "x", Priority: 200, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}},
		},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "other", Config: other})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

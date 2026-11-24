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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ownerOVS models a switch whose strict delete honours the cookie, as the
// native client restricts a strict delete to the exact cookie when one is
// set, while OFPFC_ADD replaces a same-entry flow regardless of cookie.
type ownerOVS struct {
	*replacingOVS

	calls         int          // AddFlow calls so far
	failOn        map[int]bool // 1-based AddFlow calls that fail without writing
	rejectActions string       // AddFlow of a flow with these actions fails without writing
	hideStats     bool         // GetFlowStats returns nothing
}

func (o *ownerOVS) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	o.calls++
	if o.failOn[o.calls] || (o.rejectActions != "" && flow.Actions == o.rejectActions) {
		return errInjectedOVS
	}
	return o.replacingOVS.AddFlow(ctx, bridgeName, flow)
}

func (o *ownerOVS) DeleteFlowStrict(_ context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if o.deleteErr != nil {
		return o.deleteErr
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.flows[bridgeName] = o.removeLocked(bridgeName, func(fl *ovs.Flow) bool {
		if fl.Table != flow.Table || fl.Priority != flow.Priority || fl.Match != flow.Match {
			return false
		}
		return flow.Cookie == "" || fl.Cookie == flow.Cookie
	})
	return nil
}

func (o *ownerOVS) GetFlowStats(ctx context.Context, bridgeName string, _ string) ([]*ovs.Flow, error) {
	if o.hideStats {
		return []*ovs.Flow{}, nil
	}
	return o.ListFlows(ctx, bridgeName)
}

func newOwnerOVSFixture(t *testing.T) (*SDNService, *ownerOVS) {
	t.Helper()
	inner := &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}
	inner.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	inner.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-br1", Name: "br1"})
	fake := &ownerOVS{replacingOVS: inner}
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	return svc, fake
}

// seedAPIFlow installs a flow as SDNService.AddFlow would (an API cookie)
// at the entry a DENY rule with this priority and source occupies, and
// returns its cookie.
func seedAPIFlow(t *testing.T, fake *ownerOVS, svc *SDNService, bridge string, priority int32, sourceIP string) string {
	t.Helper()
	mod, err := svc.policyRuleToFlowMod(&platformv1.PolicyRule{
		Priority: priority,
		Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
		Match:    &platformv1.PolicyRuleMatch{SourceIp: sourceIP},
	}, 0)
	require.NoError(t, err)
	cookie, err := ovs.NewAPIFlowCookie()
	require.NoError(t, err)
	cookieStr := fmt.Sprintf("0x%x", cookie)
	require.NoError(t, fake.replacingOVS.AddFlow(context.Background(), bridge, &ovs.FlowMod{
		Table:    0,
		Priority: int(priority),
		Match:    mod.Match,
		Actions:  "output:2",
		Cookie:   cookieStr,
	}))
	return cookieStr
}

func requireOnlyFlow(t *testing.T, fake *ownerOVS, bridge, cookie, actions string) {
	t.Helper()
	flows, err := fake.ListFlows(context.Background(), bridge)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, cookie, flows[0].Cookie)
	assert.Equal(t, actions, flows[0].Actions)
}

func TestPolicyFlowCookie_OwnedAndStable(t *testing.T) {
	assert.Equal(t, policyFlowCookie("p1"), policyFlowCookie("p1"))
	assert.NotEqual(t, policyFlowCookie("p1"), policyFlowCookie("p2"))
	assert.Equal(t, policyFlowCookieOwner, policyFlowCookie("p1")&^(1<<48-1))
	assert.NotEqual(t, ovs.APIFlowCookieOwner, policyFlowCookieOwner)
	assert.NotEqual(t, uint64(0xF1BE), policyFlowCookieOwner>>48)
}

func TestSDNService_ApplyPolicy_FlowsCarryThePolicyCookie(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	require.Len(t, flows, 2)
	want := fmt.Sprintf("0x%x", policyFlowCookie("p1"))
	for _, fl := range flows {
		assert.Equal(t, want, fl.Cookie, "flow %q", fl.Match)
	}

	// The policy's own flows are not foreign occupants of their entries.
	_, err = svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
}

func TestSDNService_ApplyPolicy_ExistingAPIFlowIsRefused(t *testing.T) {
	svc, fake := newOwnerOVSFixture(t)
	cookie := seedAPIFlow(t, fake, svc, "br0", 300, "192.0.2.30")

	config := &platformv1.PolicyConfig{
		Name:    "web",
		Enabled: true,
		Rules: []*platformv1.PolicyRule{
			{RuleId: "deny-c", Priority: 300, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.30"}},
		},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: config})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)
	assert.Equal(t, 0, fake.calls)
	requireOnlyFlow(t, fake, "br0", cookie, "output:2")
}

// A switch-rejected policy add must not take an API flow at the same entry
// with it: the pre-check refuses the entry when it sees the flow, and when
// it cannot, the rollback's cookie-restricted strict delete spares it.
func TestSDNService_ApplyPolicy_RejectedAddSparesExistingAPIFlow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hideStats bool
		want      codes.Code
	}{
		{name: "visible", hideStats: false, want: codes.FailedPrecondition},
		{name: "hidden", hideStats: true, want: codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, fake := newOwnerOVSFixture(t)
			cookie := seedAPIFlow(t, fake, svc, "br0", 300, "192.0.2.30")
			fake.hideStats = tc.hideStats
			fake.rejectActions = "output:4294967295"

			config := &platformv1.PolicyConfig{
				Name:    "web",
				Enabled: true,
				Rules: []*platformv1.PolicyRule{
					{RuleId: "redirect-c", Priority: 300, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_REDIRECT,
						ActionValue: "4294967295", Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.30"}},
				},
				Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
			}
			_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: config})
			assert.Equal(t, tc.want, status.Code(err), "err = %v", err)
			requireOnlyFlow(t, fake, "br0", cookie, "output:2")
		})
	}
}

// A failed restore of one prior flow must not stop the others: later rules,
// on the same bridge and on another, are still re-added.
func TestSDNService_ApplyPolicy_RestoreTriesEveryPriorFlow(t *testing.T) {
	svc, fake := newOwnerOVSFixture(t)
	config := twoRulePolicyConfig()
	config.Targets = []*platformv1.PolicyTarget{bridgeTarget("br0"), bridgeTarget("br1")}

	// AddFlow calls 1-4: br0 deny-a, br0 deny-b, br1 deny-a, br1 deny-b.
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: config})
	require.NoError(t, err)
	require.Equal(t, 4, fake.calls)
	priorBr0 := fake.matches(t, "br0")
	priorBr1 := fake.matches(t, "br1")
	require.Len(t, priorBr0, 2)
	require.Len(t, priorBr1, 2)

	// Install calls 5-8 fail on br1 deny-b; rollback deletes all four;
	// restore call 9 (br0 deny-a) fails, calls 10-12 must still run.
	fake.failOn = map[int]bool{8: true, 9: true}
	_, err = svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: config})
	assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)
	assert.Equal(t, 12, fake.calls)
	assert.Equal(t, []string{priorBr0[1]}, fake.matches(t, "br0"))
	assert.ElementsMatch(t, priorBr1, fake.matches(t, "br1"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ERROR, getPolicy(t, svc, "p1").GetStatus())
}

// A pre-check that cannot read the installed flows writes nothing.
func TestSDNService_ApplyPolicy_FlowStatsFailureIsUnavailable(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	fake.getFlowStatsErr = errInjectedOVS

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	assert.Equal(t, codes.Unavailable, status.Code(err), "err = %v", err)
	assert.Equal(t, 0, fake.addCalls)
	assert.Empty(t, fake.matches(t, "br0"))
	_, err = svc.GetPolicy(context.Background(), &platformv1.GetPolicyRequest{PolicyId: "p1"})
	assert.Error(t, err, "a refused policy is not stored")
}

// seedLegacyPolicyFlow installs on bridge the flow twoRulePolicyConfig's
// deny-a rule installs, with the given cookie and actions.
func seedLegacyPolicyFlow(t *testing.T, fake *replacingOVS, svc *SDNService, bridge, cookie, actions string) *ovs.FlowMod {
	t.Helper()
	mod, err := svc.policyRuleToFlowMod(twoRulePolicyConfig().GetRules()[0], twoRulePolicyConfig().GetPriority())
	require.NoError(t, err)
	if actions == "" {
		actions = mod.Actions
	}
	seed := &ovs.FlowMod{Table: mod.Table, Priority: mod.Priority, Match: mod.Match, Actions: actions, Cookie: cookie}
	require.NoError(t, fake.AddFlow(context.Background(), bridge, seed))
	return seed
}

func TestSDNService_ApplyPolicy_AdoptsALegacyCookieZeroPolicyFlow(t *testing.T) {
	for _, cookie := range []string{"", "0x0"} {
		t.Run("cookie="+cookie, func(t *testing.T) {
			svc, fake := newReplacingOVSFixture(t)
			seed := seedLegacyPolicyFlow(t, fake, svc, "br0", cookie, "")

			_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
			require.NoError(t, err)

			flows, err := fake.ListFlows(context.Background(), "br0")
			require.NoError(t, err)
			want := fmt.Sprintf("0x%x", policyFlowCookie("p1"))
			adopted := false
			for _, fl := range flows {
				assert.Equal(t, want, fl.Cookie, "flow %s", fl.Match)
				if fl.Match == seed.Match && fl.Priority == seed.Priority {
					adopted = true
				}
			}
			assert.True(t, adopted, "the legacy flow's entry carries the policy flow")

			_, err = svc.DeletePolicy(context.Background(), &platformv1.DeletePolicyRequest{PolicyId: "p1"})
			require.NoError(t, err)
			assert.Empty(t, fake.matches(t, "br0"))
		})
	}
}

func TestSDNService_ApplyPolicy_LegacyZeroCookieFlowWithOtherActionsIsStillRefused(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	seed := seedLegacyPolicyFlow(t, fake, svc, "br0", "0x0", "output:2")

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)

	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, seed.Match, flows[0].Match)
	assert.Equal(t, "0x0", flows[0].Cookie)
	assert.Equal(t, "output:2", flows[0].Actions)
}

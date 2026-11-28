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
	assert.Equal(t, policyFlowCookie("p1", 0), policyFlowCookie("p1", 0))
	assert.NotEqual(t, policyFlowCookie("p1", 0), policyFlowCookie("p2", 0))
	assert.Equal(t, policyFlowCookieOwner, policyFlowCookie("p1", 0)&^(1<<48-1))
	assert.NotEqual(t, ovs.APIFlowCookieOwner, policyFlowCookieOwner)
	assert.NotEqual(t, uint64(0xF1BE), policyFlowCookieOwner>>48)

	// Each rule of a policy has its own cookie, and both belong to the policy.
	rule0, rule1 := policyFlowCookie("p1", 0), policyFlowCookie("p1", 1)
	assert.NotEqual(t, rule0, rule1)
	assert.True(t, samePolicyCookie(fmt.Sprintf("0x%x", rule0), fmt.Sprintf("0x%x", rule1)))
}

// Two rules on one entry would install one switch flow (OFPFC_ADD keeps the
// later) while the record keeps the first rule's cookie, so a strict delete
// would miss the flow: ApplyPolicy refuses them before any install.
func TestSDNService_ApplyPolicy_RefusesDuplicateEntryRules(t *testing.T) {
	svc, fake := newOwnerOVSFixture(t)

	config := &platformv1.PolicyConfig{
		Name:     "dup",
		Priority: 100,
		Enabled:  true,
		Rules: []*platformv1.PolicyRule{
			// The /32 and the bare address encode the same entry.
			{RuleId: "deny-a", Priority: 200, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}},
			{RuleId: "allow-a", Priority: 200, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10/32"}},
		},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: config})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "deny-a")
	assert.Contains(t, err.Error(), "allow-a")

	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	assert.Empty(t, flows, "no flow is installed for a refused policy")
	assert.Zero(t, fake.calls, "no AddFlow is attempted")
}

// Policy IDs whose truncated hashes match would share every flow cookie, so
// ListFlows and GetFlowStats could not tell their flows apart: the second
// policy is refused before any install.
func TestSDNService_ApplyPolicy_RefusesCookieHashCollision(t *testing.T) {
	const first, second = "0518cd1c11c51ee791e80b24", "60a173ed4966add101d89b26"
	require.Equal(t, policyFlowCookie(first, 0), policyFlowCookie(second, 0), "the two IDs collide")

	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: first, Config: &platformv1.PolicyConfig{
		Name: "first", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.NoError(t, err)

	_, err = svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: second, Config: &platformv1.PolicyConfig{
		Name: "second", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-b", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.20"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, err.Error(), first)

	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1, "the switch holds only the first policy's flow")
	assert.Equal(t, fmt.Sprintf("0x%x", policyFlowCookie(first, 0)), flows[0].Cookie)
}

// After a daemon restart the policy map is empty, so the collision check
// has no record of the first policy; its surviving flow under the same
// truncated hash must still not be taken as the second policy's own.
func TestSDNService_ApplyPolicy_RestartKeepsCookieCollisionProtection(t *testing.T) {
	const first, second = "0518cd1c11c51ee791e80b24", "60a173ed4966add101d89b26"
	require.Equal(t, policyFlowCookie(first, 0), policyFlowCookie(second, 0), "the two IDs collide")
	ctx := context.Background()

	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: first, Config: &platformv1.PolicyConfig{
		Name: "first", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.NoError(t, err)
	flows, err := fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	firstActions := flows[0].Actions

	// The restarted daemon: same switch, empty policy map.
	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: second, Config: &platformv1.PolicyConfig{
		Name: "second", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "allow-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	flows, err = fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1, "the switch keeps only the first policy's flow")
	assert.Equal(t, fmt.Sprintf("0x%x", policyFlowCookie(first, 0)), flows[0].Cookie)
	assert.Equal(t, firstActions, flows[0].Actions, "the deny rule is not replaced")
}

// TestSDNService_ApplyPolicy_RestartRefusesSurvivingSameHashFlowAtAnotherEntry:
// after a restart the policy map is empty, so a surviving flow under the
// same truncated hash at another entry must still refuse the colliding
// policy, or both would share one flow ID and stats.
func TestSDNService_ApplyPolicy_RestartRefusesSurvivingSameHashFlowAtAnotherEntry(t *testing.T) {
	const first, second = "0518cd1c11c51ee791e80b24", "60a173ed4966add101d89b26"
	require.Equal(t, policyFlowCookie(first, 0), policyFlowCookie(second, 0), "the two IDs collide")
	ctx := context.Background()

	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: first, Config: &platformv1.PolicyConfig{
		Name: "first", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.NoError(t, err)

	// The restarted daemon: same switch, empty policy map.
	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: second, Config: &platformv1.PolicyConfig{
		Name: "second", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-b", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.20"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	flows, err := fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1, "the switch keeps only the first policy's flow")
	assert.Equal(t, fmt.Sprintf("0x%x", policyFlowCookie(first, 0)), flows[0].Cookie)
}

// An unchanged reapply after a restart still replaces the policy's own flows.
func TestSDNService_ApplyPolicy_RestartReapplyOfUnchangedPolicyStillWorks(t *testing.T) {
	ctx := context.Background()
	svc, fake := newReplacingOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	flows, err := fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 2)
	cookies := map[string]bool{}
	for _, fl := range flows {
		cookies[fl.Cookie] = true
	}
	assert.Equal(t, twoRuleP1Cookies(), cookies)
}

// bareListOVS models the native client's ListFlows, which reports cookies, tables and priorities but neither Match nor Actions; GetFlowStats (via ownerOVS) still reports them.
type bareListOVS struct{ *ownerOVS }

func (b *bareListOVS) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	flows, err := b.ownerOVS.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, err
	}
	out := make([]*ovs.Flow, 0, len(flows))
	for _, fl := range flows {
		if fl == nil {
			continue
		}
		c := *fl
		c.Match, c.Actions = "", ""
		out = append(out, &c)
	}
	return out, nil
}

// The native ListFlows omits matches, so the restart reapply of an
// unchanged policy must read its surviving flows' entries from flow stats,
// or every own flow looks like one at another entry.
func TestSDNService_ApplyPolicy_RestartReapplyReadsFlowMatches(t *testing.T) {
	ctx := context.Background()
	_, owner := newOwnerOVSFixture(t)
	fake := &bareListOVS{ownerOVS: owner}
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	flows, err := owner.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 2)
	cookies := map[string]bool{}
	for _, fl := range flows {
		cookies[fl.Cookie] = true
	}
	assert.Equal(t, twoRuleP1Cookies(), cookies)
}

// A disabled record installs nothing, so after a restart it is no proof
// that a surviving flow under its truncated hash is its own; enabling it
// must not replace the colliding policy's deny flow.
func TestSDNService_ApplyPolicy_RestartDisabledRecordDoesNotOwnSurvivingFlow(t *testing.T) {
	const first, second = "0518cd1c11c51ee791e80b24", "60a173ed4966add101d89b26"
	require.Equal(t, policyFlowCookie(first, 0), policyFlowCookie(second, 0), "the two IDs collide")
	ctx := context.Background()

	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: first, Config: &platformv1.PolicyConfig{
		Name: "first", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.NoError(t, err)
	flows, err := fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	firstActions := flows[0].Actions

	// The restarted daemon: same switch, empty policy map.
	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	secondConfig := func(enabled bool) *platformv1.PolicyConfig {
		return &platformv1.PolicyConfig{
			Name: "second", Priority: 100, Enabled: enabled,
			Rules: []*platformv1.PolicyRule{{RuleId: "allow-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
			Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
		}
	}
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: second, Config: secondConfig(false)})
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: second, Config: secondConfig(true)})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	flows, err = fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1, "the switch keeps only the first policy's flow")
	assert.Equal(t, fmt.Sprintf("0x%x", policyFlowCookie(first, 0)), flows[0].Cookie)
	assert.Equal(t, firstActions, flows[0].Actions, "the deny rule is not replaced")
}

// TestSDNService_ApplyPolicy_RestartSameActionCollisionIsRefused: after a
// restart a colliding ID whose rule has the same entry and actions must not
// adopt the first policy's flow, because deleting or changing it would remove
// or rewrite that rule (Codex #1955 round 15). The bridge's claim keeps the
// full ID across the restart.
func TestSDNService_ApplyPolicy_RestartSameActionCollisionIsRefused(t *testing.T) {
	const first, second = "0518cd1c11c51ee791e80b24", "60a173ed4966add101d89b26"
	require.Equal(t, policyFlowCookie(first, 0), policyFlowCookie(second, 0), "the two IDs collide")
	ctx := context.Background()

	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: first, Config: &platformv1.PolicyConfig{
		Name: "first", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-a", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.NoError(t, err)
	flows, err := fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	firstActions := flows[0].Actions

	// The restarted daemon: same switch, empty policy map.
	svc2, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	_, err = svc2.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: second, Config: &platformv1.PolicyConfig{
		Name: "second", Priority: 100, Enabled: true,
		Rules: []*platformv1.PolicyRule{{RuleId: "deny-b", Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}}},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, err.Error(), first, "the claim names the full owner")

	_, err = svc2.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: second})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	flows, err = fake.ListFlows(ctx, "br0")
	require.NoError(t, err)
	require.Len(t, flows, 1, "the switch keeps the first policy's flow")
	assert.Equal(t, fmt.Sprintf("0x%x", policyFlowCookie(first, 0)), flows[0].Cookie)
	assert.Equal(t, firstActions, flows[0].Actions, "the deny rule is not removed or rewritten")
}

// TestSDNService_ApplyPolicy_ClaimsItsCookieHashOnTheBridge: an enabled apply
// records the full policy ID under its cookie hash in the bridge's
// external_ids.
func TestSDNService_ApplyPolicy_ClaimsItsCookieHashOnTheBridge(t *testing.T) {
	ctx := context.Background()
	svc, fake := newOwnerOVSFixture(t)
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)

	ids, err := fake.GetBridgeExternalIDs(ctx, "br0")
	require.NoError(t, err)
	key := fmt.Sprintf("gtp-policy-cookie-%08x", policyFlowCookie("p1", 0)>>16&(1<<32-1))
	assert.Equal(t, "p1", ids[key])
}

// twoRuleP1Cookies is the set of flow cookies policy p1 with
// twoRulePolicyConfig installs: one cookie per rule, as hex strings.
func twoRuleP1Cookies() map[string]bool {
	return map[string]bool{
		fmt.Sprintf("0x%x", policyFlowCookie("p1", 0)): true,
		fmt.Sprintf("0x%x", policyFlowCookie("p1", 1)): true,
	}
}

func TestSDNService_ApplyPolicy_FlowsCarryThePolicyCookie(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	require.Len(t, flows, 2)
	p1 := fmt.Sprintf("0x%x", policyFlowCookie("p1", 0))
	cookies := map[string]bool{}
	for _, fl := range flows {
		assert.True(t, samePolicyCookie(p1, fl.Cookie), "flow %q cookie %s is a p1 policy cookie", fl.Match, fl.Cookie)
		cookies[fl.Cookie] = true
	}
	assert.Equal(t, twoRuleP1Cookies(), cookies, "each rule's flow carries its own rule cookie")

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
			p1 := fmt.Sprintf("0x%x", policyFlowCookie("p1", 0))
			cookies := map[string]bool{}
			adopted := false
			for _, fl := range flows {
				assert.True(t, samePolicyCookie(p1, fl.Cookie), "flow %s cookie %s is a p1 policy cookie", fl.Match, fl.Cookie)
				cookies[fl.Cookie] = true
				if fl.Match == seed.Match && fl.Priority == seed.Priority {
					adopted = true
				}
			}
			assert.Equal(t, twoRuleP1Cookies(), cookies, "each rule's flow carries its own rule cookie")
			assert.True(t, adopted, "the legacy flow's entry carries the policy flow")

			_, err = svc.DeletePolicy(context.Background(), &platformv1.DeletePolicyRequest{PolicyId: "p1"})
			require.NoError(t, err)
			assert.Empty(t, fake.matches(t, "br0"))
		})
	}
}

// A failed apply that adopted a cookie-zero legacy flow restores it: the
// legacy rule was enforcing before the apply, and no prior record holds it.
func TestSDNService_ApplyPolicy_RollbackRestoresAdoptedLegacyFlow(t *testing.T) {
	svc, fake := newOwnerOVSFixture(t)
	seed := seedLegacyPolicyFlow(t, fake.replacingOVS, svc, "br0", "0x0", "")
	fake.failOn = map[int]bool{2: true}

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.Equal(t, codes.Internal, status.Code(err), "err: %v", err)

	requireOnlyFlow(t, fake, "br0", seed.Cookie, seed.Actions)
	flows, err := fake.ListFlows(context.Background(), "br0")
	require.NoError(t, err)
	assert.Equal(t, seed.Match, flows[0].Match)
	assert.Equal(t, seed.Priority, flows[0].Priority)
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

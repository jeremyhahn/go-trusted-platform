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

// errFlowInstall is the fault the OVS fake returns for a flow it refuses.
var errFlowInstall = errors.New("test: flow not installed")

// newPolicyFlowFixture builds an SDN service on the OVS fake with bridge br0
// and records every flow the service installs.
func newPolicyFlowFixture(t *testing.T) (*SDNService, *ConfigurableMockOVSClient, *[]ovs.FlowMod) {
	t.Helper()
	mock := NewConfigurableMockOVSClient()
	svc, err := NewSDNService("", WithOVSClient(mock))
	require.NoError(t, err)
	svc.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	var mods []ovs.FlowMod
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		mods = append(mods, *flow)
		return nil
	})
	return svc, mock, &mods
}

func denyPolicy(name string, rules ...*platformv1.PolicyRule) *platformv1.ApplyPolicyRequest {
	return &platformv1.ApplyPolicyRequest{
		Config: &platformv1.PolicyConfig{
			Name:     name,
			Priority: 100,
			Enabled:  true,
			Rules:    rules,
			Targets: []*platformv1.PolicyTarget{{
				Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE,
				Id:   "br0",
			}},
		},
	}
}

func denyRule(id string, match *platformv1.PolicyRuleMatch) *platformv1.PolicyRule {
	return &platformv1.PolicyRule{
		RuleId: id,
		Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
		Match:  match,
	}
}

// TestSDNService_ApplyPolicy_ProtocolMatchesTheFlowGrammar checks that each
// policy protocol reaches OVS as a match the flow grammar parses: a named
// protocol as its shorthand, a protocol number behind "ip", and an IP match
// without a protocol behind "ip". A protocol the grammar cannot carry is
// refused before any flow is installed.
func TestSDNService_ApplyPolicy_ProtocolMatchesTheFlowGrammar(t *testing.T) {
	tests := []struct {
		name  string
		match *platformv1.PolicyRuleMatch
		want  string
	}{
		{"tcp port", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}, "tcp,tp_dst=22"},
		{"udp upper case", &platformv1.PolicyRuleMatch{Protocol: "UDP"}, "udp"},
		{"icmp source", &platformv1.PolicyRuleMatch{Protocol: "icmp", SourceIp: "10.0.0.0/8"}, "icmp,nw_src=10.0.0.0/8"},
		{"protocol number", &platformv1.PolicyRuleMatch{Protocol: "47"}, "ip,nw_proto=47"},
		{"no protocol", &platformv1.PolicyRuleMatch{DestinationIp: "10.1.0.0/16"}, "ip,nw_dst=10.1.0.0/16"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mods := newPolicyFlowFixture(t)
			_, err := svc.ApplyPolicy(context.Background(), denyPolicy("p", denyRule("r1", tt.match)))
			require.NoError(t, err)
			require.Len(t, *mods, 1)
			assert.Equal(t, tt.want, (*mods)[0].Match)
			assert.Equal(t, "drop", (*mods)[0].Actions)
		})
	}

	for _, proto := range []string{"gre-ish", "300"} {
		t.Run("refuses "+proto, func(t *testing.T) {
			svc, mock, _ := newPolicyFlowFixture(t)
			_, err := svc.ApplyPolicy(context.Background(),
				denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: proto})))
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Zero(t, mock.GetCallCount("AddFlow"), "a refused rule must never reach the switch")
			list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{})
			require.NoError(t, err)
			assert.Empty(t, list.GetPolicies())
		})
	}
}

// TestSDNService_ApplyPolicy_FailsWhenAFlowIsNotInstalled checks that a flow
// the switch refuses fails the apply with codes.Internal, removes the flows
// the same call installed, and records no policy.
func TestSDNService_ApplyPolicy_FailsWhenAFlowIsNotInstalled(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	var installed []ovs.FlowMod
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		if len(installed) == 1 {
			return errFlowInstall
		}
		installed = append(installed, *flow)
		return nil
	})

	_, err := svc.ApplyPolicy(context.Background(), denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))

	deletes := mock.GetCalls("DeleteFlowStrict")
	require.Len(t, deletes, 1, "the first rule's flow must be removed")
	require.Len(t, installed, 1)
	removed, ok := deletes[0].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, installed[0].Match, removed.Match)

	list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetPolicies(), "a failed apply must record no policy")
}

// bridgeTargets returns BRIDGE policy targets with the given IDs.
func bridgeTargets(ids ...string) []*platformv1.PolicyTarget {
	targets := make([]*platformv1.PolicyTarget, len(ids))
	for i, id := range ids {
		targets[i] = &platformv1.PolicyTarget{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: id}
	}
	return targets
}

// assertPolicyRefusedOnUnknownBridge applies a deny policy to the given
// targets and checks it is refused with NotFound, installs no flow and
// records no policy (#2022 Codex P1).
func assertPolicyRefusedOnUnknownBridge(t *testing.T, targets ...string) {
	t.Helper()
	svc, mock, mods := newPolicyFlowFixture(t)
	req := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	req.Config.Targets = bridgeTargets(targets...)

	_, err := svc.ApplyPolicy(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, *mods, "a policy on an unknown bridge must install no flow")
	assert.Zero(t, mock.GetCallCount("AddFlow"))

	list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetPolicies(), "a refused apply must record no policy")
}

// TestSDNService_ApplyPolicy_RefusesAnUnknownBridgeTarget checks that a
// policy whose targets mix a known and an unknown bridge is refused before
// any flow reaches the known one, so it is never reported active while only
// partly enforced.
func TestSDNService_ApplyPolicy_RefusesAnUnknownBridgeTarget(t *testing.T) {
	assertPolicyRefusedOnUnknownBridge(t, "br0", "br-missing")
}

// TestSDNService_ApplyPolicy_RefusesASingleUnknownBridgeTarget checks that a
// policy on one mistyped bridge is refused, not recorded active with no flow.
func TestSDNService_ApplyPolicy_RefusesASingleUnknownBridgeTarget(t *testing.T) {
	assertPolicyRefusedOnUnknownBridge(t, "br-missing")
}

// A failed update of an existing policy must leave the old policy enforced:
// the update's AddFlow replaced the old flow (same table, priority and
// match), so deleting it on rollback must be followed by re-installing the
// old policy's flows (#2021 Codex P1).
func TestSDNService_ApplyPolicy_FailedUpdateRestoresTheActivePolicy(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	ctx := context.Background()

	first := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(ctx, first)
	require.NoError(t, err)

	var adds []ovs.FlowMod
	calls := 0
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		calls++
		if calls == 2 {
			return errFlowInstall
		}
		adds = append(adds, *flow)
		return nil
	})

	update := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	)
	update.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(ctx, update)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))

	require.GreaterOrEqual(t, len(adds), 2, "the old policy's flow must be re-installed after the rollback")
	last := adds[len(adds)-1]
	assert.Equal(t, "tcp,tp_dst=22", last.Match)
	assert.Equal(t, "drop", last.Actions)

	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "pol-1"})
	require.NoError(t, err)
	rules := got.GetPolicy().GetConfig().GetRules()
	require.Len(t, rules, 1, "the failed update must not replace the recorded policy")
	assert.Equal(t, "r1", rules[0].GetRuleId())
}

// A new policy whose rule shares another policy's table, priority and match
// replaces that policy's switch entry. When a later rule of the new policy
// fails, the rollback deletes the entry, so the other policy's flow must be
// put back (Codex P1, PR #2021).
func TestSDNService_ApplyPolicy_FailedApplyRestoresAnotherPolicysFlow(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	ctx := context.Background()

	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)

	var adds []ovs.FlowMod
	calls := 0
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		calls++
		if calls == 2 {
			return errFlowInstall
		}
		adds = append(adds, *flow)
		return nil
	})

	b := denyPolicy("b",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	)
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.Error(t, err)

	require.GreaterOrEqual(t, len(adds), 2, "policy a's overwritten flow must be re-installed after the rollback")
	last := adds[len(adds)-1]
	assert.Equal(t, "tcp,tp_dst=22", last.Match)
	assert.Equal(t, "drop", last.Actions)

	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "pol-a"})
	require.NoError(t, err)
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, got.GetPolicy().GetStatus())
}

// A protocol number and its name parse to the same switch entry, so the
// rollback must restore policy a's deny even when b spells it differently.
func TestSDNService_ApplyPolicy_FailedApplyRestoresAFlowSpelledDifferently(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	ctx := context.Background()

	var aMatch string
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		aMatch = flow.Match
		return nil
	})
	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "6", DestinationPort: 22}))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)
	require.NotEmpty(t, aMatch)

	var adds []ovs.FlowMod
	calls := 0
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		calls++
		if calls == 2 {
			return errFlowInstall
		}
		adds = append(adds, *flow)
		return nil
	})

	b := denyPolicy("b",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	)
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.Error(t, err)

	require.GreaterOrEqual(t, len(adds), 2, "policy a's deny must be re-installed although b spells the protocol differently")
	last := adds[len(adds)-1]
	assert.Equal(t, aMatch, last.Match)
	assert.Equal(t, "drop", last.Actions)
}

// TestSDNService_ApplyPolicy_FailedApplyRestoresAFlowWithAnotherHostPrefix
// checks that a source prefix spelled with host bits (10.0.0.1/24) keys the
// same switch entry as its network form (10.0.0.0/24), which is what the
// OpenFlow encoder writes: a failed apply that overwrote it restores it.
func TestSDNService_ApplyPolicy_FailedApplyRestoresAFlowWithAnotherHostPrefix(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	ctx := context.Background()

	var aMatch string
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		aMatch = flow.Match
		return nil
	})
	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/24"}))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)
	require.NotEmpty(t, aMatch)

	var adds []ovs.FlowMod
	calls := 0
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		calls++
		if calls == 2 {
			return errFlowInstall
		}
		adds = append(adds, *flow)
		return nil
	})
	b := denyPolicy("b",
		denyRule("r1", &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.1/24"}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	)
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.Error(t, err)

	require.GreaterOrEqual(t, len(adds), 2, "policy a's deny must be re-installed although b spells the prefix with host bits")
	last := adds[len(adds)-1]
	assert.Equal(t, aMatch, last.Match)
	assert.Equal(t, "drop", last.Actions)
}

func TestNormalizeFlowMatch_PrefixesKeyByTheirNetwork(t *testing.T) {
	assert.Equal(t, normalizeFlowMatch("ip,nw_src=10.0.0.0/24"), normalizeFlowMatch("ip,nw_src=10.0.0.1/24"))
	assert.Equal(t, normalizeFlowMatch("ip,nw_dst=192.168.1.0/24"), normalizeFlowMatch("ip,nw_dst=192.168.1.7/24"))
	assert.NotEqual(t, normalizeFlowMatch("ip,nw_src=10.0.0.0/24"), normalizeFlowMatch("ip,nw_src=10.0.1.0/24"))
}

// TestSDNService_DeletePolicy_UsesTheSameMatch checks that deleting a policy
// removes flows by the match its apply installed.
func TestSDNService_DeletePolicy_UsesTheSameMatch(t *testing.T) {
	svc, mock, mods := newPolicyFlowFixture(t)
	resp, err := svc.ApplyPolicy(context.Background(), denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22, VlanId: 10})))
	require.NoError(t, err)
	require.Len(t, *mods, 1)

	_, err = svc.DeletePolicy(context.Background(), &platformv1.DeletePolicyRequest{PolicyId: resp.GetPolicy().GetId()})
	require.NoError(t, err)

	deletes := mock.GetCalls("DeleteFlow")
	require.Len(t, deletes, 1)
	assert.Equal(t, (*mods)[0].Match, deletes[0].Args[1])
}

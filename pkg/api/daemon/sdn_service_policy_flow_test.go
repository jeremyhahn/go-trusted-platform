package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
	// The first rule's flow, and the second's: its AddFlow error does not
	// prove the switch refused it (#2021 Codex r1).
	require.Len(t, deletes, 2, "every attempted flow must be removed")
	require.Len(t, installed, 1)
	removed, ok := deletes[0].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, installed[0].Match, removed.Match)
	uncertain, ok := deletes[1].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, "udp,tp_dst=53", uncertain.Match)

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

func allowRule(id string, match *platformv1.PolicyRuleMatch) *platformv1.PolicyRule {
	return &platformv1.PolicyRule{
		RuleId: id,
		Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
		Match:  match,
	}
}

// An AddFlow error does not prove the switch refused the flow: the
// flow-mod is written before its barrier is awaited, so a barrier timeout
// can come after installation. The rollback must remove the uncertain flow
// and put back the entry it may have replaced, even when the request
// context is already cancelled (#2021 Codex r1).
func TestSDNService_ApplyPolicy_FailedApplyRemovesTheUncertainFlow(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)

	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(context.Background(), a)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var adds []ovs.FlowMod
	var cancelledAdds int
	calls := 0
	mock.OnAddFlow(func(callCtx context.Context, _ string, flow *ovs.FlowMod) error {
		calls++
		if callCtx.Err() != nil {
			cancelledAdds++
			return callCtx.Err()
		}
		adds = append(adds, *flow)
		if calls == 1 {
			// Installed, then the barrier times out and the caller goes away.
			cancel()
			return errFlowInstall
		}
		return nil
	})

	b := denyPolicy("b", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.Error(t, err)

	deletes := mock.GetCalls("DeleteFlowStrict")
	require.NotEmpty(t, deletes, "the flow whose AddFlow failed must be removed")
	deleted, ok := deletes[0].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, "tcp,tp_dst=22", deleted.Match)

	assert.Zero(t, cancelledAdds, "the rollback must not use the cancelled request context")
	require.GreaterOrEqual(t, len(adds), 2, "policy a's overwritten flow must be re-installed")
	last := adds[len(adds)-1]
	assert.Equal(t, "tcp,tp_dst=22", last.Match)
	assert.Equal(t, "drop", last.Actions)
}

// Two policies with the same match and priority: the later one's entry is
// the effective one. A failed apply that overwrote it must leave the later
// policy's entry installed, whatever the map order (#2021 Codex r1).
func TestSDNService_ApplyPolicy_FailedApplyRestoresTheEffectiveOverlappingEntry(t *testing.T) {
	for i := 0; i < 50; i++ {
		svc, mock, _ := newPolicyFlowFixture(t)
		ctx := context.Background()

		a := denyPolicy("a", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
		a.PolicyId = "pol-a"
		_, err := svc.ApplyPolicy(ctx, a)
		require.NoError(t, err)
		b := denyPolicy("b", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
		b.PolicyId = "pol-b"
		_, err = svc.ApplyPolicy(ctx, b)
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

		c := denyPolicy("c",
			allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
			denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
		)
		c.PolicyId = "pol-c"
		_, err = svc.ApplyPolicy(ctx, c)
		require.Error(t, err)

		var effective *ovs.FlowMod
		for j := range adds {
			if adds[j].Match == "tcp,tp_dst=22" {
				effective = &adds[j]
			}
		}
		require.NotNil(t, effective, "run %d: an overwritten entry must be re-installed", i)
		require.Equal(t, "drop", effective.Actions, "run %d: policy b's deny was the effective entry", i)
	}
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

// TestNormalizeFlowMatch_BareAddressesKeyByTheEncodedForm checks that a bare
// address keys by the IPv4 form the OpenFlow encoder writes, so an
// IPv4-mapped IPv6 spelling is the same switch entry as the IPv4 address.
func TestNormalizeFlowMatch_BareAddressesKeyByTheEncodedForm(t *testing.T) {
	assert.Equal(t, normalizeFlowMatch("ip,nw_src=::ffff:192.0.2.1"), normalizeFlowMatch("ip,nw_src=192.0.2.1"))
	assert.Equal(t, normalizeFlowMatch("ip,nw_dst=::ffff:192.0.2.1"), normalizeFlowMatch("ip,nw_dst=192.0.2.1"))
	assert.NotEqual(t, normalizeFlowMatch("ip,nw_src=192.0.2.1"), normalizeFlowMatch("ip,nw_src=192.0.2.2"))
}

// TestSDNService_ApplyPolicy_FailedApplyRestoresAFlowWithAMappedAddress
// checks that a source address spelled as an IPv4-mapped IPv6 address
// (::ffff:192.0.2.1) keys the same switch entry as its IPv4 form, which is
// what the OpenFlow encoder writes: a failed apply that overwrote it restores
// it (#2021 Codex r3).
func TestSDNService_ApplyPolicy_FailedApplyRestoresAFlowWithAMappedAddress(t *testing.T) {
	svc, mock, _ := newPolicyFlowFixture(t)
	ctx := context.Background()

	var aMatch string
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		aMatch = flow.Match
		return nil
	})
	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.1"}))
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
		denyRule("r1", &platformv1.PolicyRuleMatch{SourceIp: "::ffff:192.0.2.1"}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "udp", DestinationPort: 53}),
	)
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.Error(t, err)

	require.GreaterOrEqual(t, len(adds), 2, "policy a's deny must be re-installed although b spells the address as IPv4-mapped IPv6")
	last := adds[len(adds)-1]
	assert.Equal(t, aMatch, last.Match)
	assert.Equal(t, "drop", last.Actions)
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

	assert.Empty(t, mock.GetCalls("DeleteFlow"), "a non-strict delete reaches other policies' entries")
	deletes := mock.GetCalls("DeleteFlowStrict")
	require.Len(t, deletes, 1)
	flow, ok := deletes[0].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, (*mods)[0].Match, flow.Match)
	assert.Equal(t, (*mods)[0].Priority, flow.Priority)
}

// switchModelClient models the switch's flow table on top of the mock: an
// AddFlow writes the entry (before its hook runs, as a flow-mod is written
// before its barrier is awaited) and a DeleteFlowStrict removes it.
type switchModelClient struct {
	*ConfigurableMockOVSClient

	mu         sync.Mutex
	entries    map[string]string // match -> actions
	deletes    []string
	addHook    func(flow *ovs.FlowMod) error
	deleteHook func(flow *ovs.FlowMod) error
	listed     []*ovs.Flow // entries other owners installed, as ListFlows reports them
}

// ListFlows reports the entries other owners installed (listed); the model
// keys its own entries by match alone, so it does not list them.
func (c *switchModelClient) ListFlows(_ context.Context, _ string) ([]*ovs.Flow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*ovs.Flow, 0, len(c.listed))
	for _, f := range c.listed {
		cp := *f
		out = append(out, &cp)
	}
	return out, nil
}

func newSwitchModelSDNService(t *testing.T) (*SDNService, *switchModelClient) {
	t.Helper()
	sw := &switchModelClient{ConfigurableMockOVSClient: NewConfigurableMockOVSClient(), entries: map[string]string{}}
	svc, err := NewSDNService("", WithOVSClient(sw))
	require.NoError(t, err)
	svc.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	return svc, sw
}

func (c *switchModelClient) AddFlow(_ context.Context, _ string, flow *ovs.FlowMod) error {
	c.mu.Lock()
	c.entries[flow.Match] = flow.Actions
	hook := c.addHook
	c.mu.Unlock()
	if hook != nil {
		return hook(flow)
	}
	return nil
}

func (c *switchModelClient) DeleteFlowStrict(_ context.Context, _ string, flow *ovs.FlowMod) error {
	c.mu.Lock()
	hook := c.deleteHook
	c.deletes = append(c.deletes, flow.Match)
	c.mu.Unlock()
	if hook != nil {
		if err := hook(flow); err != nil {
			return err
		}
	}
	c.mu.Lock()
	delete(c.entries, flow.Match)
	c.mu.Unlock()
	return nil
}

func (c *switchModelClient) entry(match string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.entries[match]
	return a, ok
}

func (c *switchModelClient) deleted() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.deletes...)
}

// Apply A installs an entry and then fails while apply B installs the same
// entry and has not yet published its policy: A's rollback must not leave B
// reporting success without its flow on the switch.
func TestSDNService_ApplyPolicy_ConcurrentRollbackKeepsTheOtherApplysFlow(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	aInstalled := make(chan struct{})
	bInstalled := make(chan struct{})
	rolledBack := make(chan struct{})
	var aOnce, bOnce, rbOnce sync.Once
	sw.addHook = func(flow *ovs.FlowMod) error {
		if flow.Actions == "drop" { // apply A
			aOnce.Do(func() { close(aInstalled) })
			// A's barrier is slow: B gets to install the same entry meanwhile
			// if nothing serializes the two applies.
			select {
			case <-bInstalled:
			case <-time.After(300 * time.Millisecond):
			}
			return errFlowInstall
		}
		// Apply B: installed, its barrier returns only after A rolled back.
		bOnce.Do(func() { close(bInstalled) })
		select {
		case <-rolledBack:
		case <-time.After(2 * time.Second):
		}
		return nil
	}
	sw.deleteHook = func(*ovs.FlowMod) error {
		rbOnce.Do(func() { close(rolledBack) })
		return nil
	}

	a := denyPolicy("a", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	a.PolicyId = "pol-a"
	b := denyPolicy("b", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	b.PolicyId = "pol-b"

	aErr := make(chan error, 1)
	go func() {
		_, err := svc.ApplyPolicy(context.Background(), a)
		aErr <- err
	}()
	select {
	case <-aInstalled:
	case <-time.After(5 * time.Second):
		t.Fatal("apply A never installed its flow")
	}
	bErr := make(chan error, 1)
	go func() {
		_, err := svc.ApplyPolicy(context.Background(), b)
		bErr <- err
	}()

	require.Error(t, <-aErr)
	require.NoError(t, <-bErr)

	actions, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok, "B reported success, so its flow must be on the switch")
	assert.NotEqual(t, "drop", actions)
}

// A replacement whose rules no longer cover an entry the old policy installed
// would leave that flow on the switch with no owner: it is refused before any
// switch write, and the recorded policy is unchanged.
func TestSDNService_ApplyPolicy_ReplacementRemovesTheDroppedEntry(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	first := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}),
	)
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(context.Background(), first)
	require.NoError(t, err)
	_, ok := sw.entry("tcp")
	require.True(t, ok)

	sw.mu.Lock()
	sw.deletes = nil
	sw.mu.Unlock()

	added := denyRule("r3", &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/8"})
	second := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		added,
	)
	second.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(context.Background(), second)
	require.NoError(t, err, "a replacement that drops an entry is applied, not refused")

	_, ok = sw.entry("tcp")
	assert.False(t, ok, "the dropped entry must be removed from the switch")
	assert.Contains(t, sw.deleted(), "tcp")
	assert.NotContains(t, sw.deleted(), "tcp,tp_dst=22", "a kept entry must not be deleted")
	_, ok = sw.entry("tcp,tp_dst=22")
	assert.True(t, ok)

	addedMod, err := svc.policyRuleToFlowMod(added, second.GetConfig().GetPriority())
	require.NoError(t, err)
	_, ok = sw.entry(addedMod.Match)
	assert.True(t, ok, "the new entry %q must be installed", addedMod.Match)

	svc.mu.RLock()
	recorded := svc.policies["pol-1"]
	svc.mu.RUnlock()
	require.NotNil(t, recorded)
	require.Len(t, recorded.rules, 2)
	assert.Equal(t, "r3", recorded.rules[1].GetRuleId(), "the recorded policy must be the new version")
}

func TestSDNService_ApplyPolicy_ReplacementKeepsAnEntryAnotherPolicyOwns(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	first := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}),
	)
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(context.Background(), first)
	require.NoError(t, err)

	other := denyPolicy("q", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp"}))
	other.PolicyId = "pol-2"
	_, err = svc.ApplyPolicy(context.Background(), other)
	require.NoError(t, err)

	sw.mu.Lock()
	sw.deletes = nil
	sw.mu.Unlock()

	second := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	second.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(context.Background(), second)
	require.NoError(t, err)

	_, ok := sw.entry("tcp")
	assert.True(t, ok, "an entry another policy owns must stay installed")
	assert.NotContains(t, sw.deleted(), "tcp")
}

func TestSDNService_ApplyPolicy_FailedObsoleteDeleteIsStrandedAndRetried(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	first := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}),
	)
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(context.Background(), first)
	require.NoError(t, err)

	errDelete := errors.New("test: delete refused")
	failed := false
	sw.mu.Lock()
	sw.deleteHook = func(flow *ovs.FlowMod) error {
		if flow.Match == "tcp" && !failed {
			failed = true
			return errDelete
		}
		return nil
	}
	sw.mu.Unlock()

	second := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	second.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(context.Background(), second)
	require.NoError(t, err, "a failed removal of an obsolete entry does not fail the replacement")
	require.True(t, failed)

	_, ok := sw.entry("tcp")
	require.True(t, ok, "the model keeps the entry the delete failed on")
	droppedMod, err := svc.policyRuleToFlowMod(allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}), first.GetConfig().GetPriority())
	require.NoError(t, err)
	_, stranded := svc.strandedFlows[newFlowEntryKey("br0", droppedMod)]
	assert.True(t, stranded, "the entry the delete failed on must be recorded as stranded")

	// The next apply on the bridge removes the stranded entry.
	sw.mu.Lock()
	sw.deletes = nil
	sw.mu.Unlock()
	y := denyPolicy("y", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}))
	_, err = svc.ApplyPolicy(context.Background(), y)
	require.NoError(t, err)
	assert.Contains(t, sw.deleted(), "tcp", "the stranded entry must be removed by the next apply")
	_, ok = sw.entry("tcp")
	assert.False(t, ok)
	assert.Empty(t, svc.strandedFlows)
}

// A replacement that keeps every entry the old policy installed (here the
// action changes on the same match and a rule is added) still applies.
func TestSDNService_ApplyPolicy_ReplacementKeepingEveryEntrySucceeds(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	first := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(context.Background(), first)
	require.NoError(t, err)

	second := denyPolicy("p",
		allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443}),
	)
	second.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(context.Background(), second)
	require.NoError(t, err)

	actions, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok)
	assert.NotEqual(t, "drop", actions)
	actions, ok = sw.entry("tcp,tp_dst=443")
	require.True(t, ok)
	assert.Equal(t, "drop", actions)
}

// A raw AddFlow issued while a policy apply is failing must not land between
// the apply's installs and its rollback: policy flows carry no cookie, so the
// rollback would remove or overwrite the raw flow on the same match.
func TestSDNService_AddFlow_WaitsForAFailingPolicyApplysRollback(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	var evMu sync.Mutex
	var events []string
	logEvent := func(e string) {
		evMu.Lock()
		events = append(events, e)
		evMu.Unlock()
	}

	policyMid := make(chan struct{})
	rawAdded := make(chan struct{})
	var midOnce, rawOnce sync.Once
	sw.addHook = func(flow *ovs.FlowMod) error {
		if flow.Cookie != "" {
			logEvent("raw")
			rawOnce.Do(func() { close(rawAdded) })
			return nil
		}
		if flow.Match == "tcp,tp_dst=443" { // r2: the apply fails here
			midOnce.Do(func() { close(policyMid) })
			select {
			case <-rawAdded:
			case <-time.After(300 * time.Millisecond):
			}
			return errFlowInstall
		}
		return nil
	}
	sw.deleteHook = func(*ovs.FlowMod) error {
		logEvent("delete")
		return nil
	}

	pol := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		denyRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443}),
	)
	applyErr := make(chan error, 1)
	go func() {
		_, err := svc.ApplyPolicy(context.Background(), pol)
		applyErr <- err
	}()
	select {
	case <-policyMid:
	case <-time.After(5 * time.Second):
		t.Fatal("the apply never reached its second rule")
	}

	addErr := make(chan error, 1)
	go func() {
		_, err := svc.AddFlow(context.Background(), &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{
			BridgeId: "br0",
			Priority: 100,
			Match:    &platformv1.FlowMatch{TcpDst: 22},
		}})
		addErr <- err
	}()

	require.Error(t, <-applyErr)
	require.NoError(t, <-addErr)

	evMu.Lock()
	defer evMu.Unlock()
	rawAt, lastDelete := -1, -1
	for i, e := range events {
		switch e {
		case "raw":
			rawAt = i
		case "delete":
			lastDelete = i
		}
	}
	require.NotEqual(t, -1, rawAt, "the raw flow was never added: %v", events)
	require.NotEqual(t, -1, lastDelete, "the failed apply never rolled back: %v", events)
	assert.Greater(t, rawAt, lastDelete, "the raw add must come after the rollback: %v", events)
}

// A rollback delete that fails is an error of the apply, and the entry it
// left behind stays tracked: the next apply removes it.
func TestSDNService_ApplyPolicy_FailedRollbackDeleteIsReportedAndRetried(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	errDelete := errors.New("test: delete refused")
	sw.addHook = func(*ovs.FlowMod) error { return errFlowInstall }
	sw.deleteHook = func(*ovs.FlowMod) error { return errDelete }

	x := denyPolicy("x", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	_, err := svc.ApplyPolicy(context.Background(), x)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rollback")
	assert.Contains(t, err.Error(), errDelete.Error())
	_, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok, "the model keeps the entry the delete failed on")

	// The switch recovers: the next apply removes the stranded entry.
	sw.mu.Lock()
	sw.addHook = nil
	sw.deleteHook = nil
	sw.deletes = nil
	sw.mu.Unlock()
	y := denyPolicy("y", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}))
	_, err = svc.ApplyPolicy(context.Background(), y)
	require.NoError(t, err)
	assert.Contains(t, sw.deleted(), "tcp,tp_dst=22", "the stranded entry must be removed by the next apply")
	_, ok = sw.entry("tcp,tp_dst=22")
	assert.False(t, ok)

	// Once removed it is no longer tracked: a third apply deletes nothing.
	sw.mu.Lock()
	sw.deletes = nil
	sw.mu.Unlock()
	z := denyPolicy("z", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443}))
	_, err = svc.ApplyPolicy(context.Background(), z)
	require.NoError(t, err)
	assert.Empty(t, sw.deleted())
}

// A failed update whose rollback delete also fails still puts the old deny
// back (an OpenFlow ADD replaces the same-match entry), or reports the old
// policy as erroneous: never a permissive flow under an ACTIVE deny (#2021 Codex).
func TestSDNService_ApplyPolicy_FailedRollbackDeleteRestoresTheOldDeny(t *testing.T) {
	svc, client := newSwitchModelSDNService(t)
	ctx := context.Background()

	web := &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}
	deny := denyRule("r1", web)
	denyReq := denyPolicy("deny-web", deny)
	denyReq.PolicyId = "p1"
	if _, err := svc.ApplyPolicy(ctx, denyReq); err != nil {
		t.Fatalf("apply deny: %v", err)
	}
	denyFlow, err := svc.policyRuleToFlowMod(deny, 100)
	if err != nil {
		t.Fatalf("translate deny: %v", err)
	}
	denyActions, ok := client.entry(denyFlow.Match)
	if !ok {
		t.Fatalf("deny flow %q not installed", denyFlow.Match)
	}

	allow := allowRule("r1", web)
	broken := allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443})
	brokenFlow, err := svc.policyRuleToFlowMod(broken, 100)
	if err != nil {
		t.Fatalf("translate broken: %v", err)
	}
	client.mu.Lock()
	client.addHook = func(flow *ovs.FlowMod) error {
		if flow.Match == brokenFlow.Match {
			return errFlowInstall
		}
		return nil
	}
	client.deleteHook = func(*ovs.FlowMod) error { return errFlowInstall }
	client.mu.Unlock()

	update := denyPolicy("deny-web", allow, broken)
	update.PolicyId = "p1"
	if _, err := svc.ApplyPolicy(ctx, update); err == nil {
		t.Fatal("apply with a refused flow succeeded")
	}

	got, ok := client.entry(denyFlow.Match)
	restored := ok && got == denyActions
	svc.mu.RLock()
	state := svc.policies["p1"].status
	svc.mu.RUnlock()
	if !restored && state == "active" {
		t.Fatalf("entry %q = %q (present %v) with policy p1 still active; want the deny %q back or p1 in error", denyFlow.Match, got, ok, denyActions)
	}
	if !restored {
		t.Fatalf("deny entry %q not restored: %q", denyFlow.Match, got)
	}
}

// A policy flow the switch rejected is not deleted by the rollback: a
// non-policy entry with the same table, priority and match (the gateway's
// ingress pipeline at table 0, priority 0) survives (#2021 Codex).
func TestSDNService_ApplyPolicy_RejectedFlowRollbackKeepsAForeignEntry(t *testing.T) {
	svc, client := newSwitchModelSDNService(t)
	ctx := context.Background()

	wildcard := allowRule("any", nil)
	flow, err := svc.policyRuleToFlowMod(wildcard, 0)
	if err != nil {
		t.Fatalf("translate wildcard: %v", err)
	}
	client.mu.Lock()
	client.entries[flow.Match] = "foreign:pipeline"
	// The gateway pipeline's own entry, unknown to the policy service.
	client.listed = []*ovs.Flow{{Table: flow.Table, Priority: flow.Priority, Match: flow.Match, Actions: "foreign:pipeline"}}
	client.addHook = func(*ovs.FlowMod) error { return ovs.ErrInvalidFlow }
	client.mu.Unlock()

	wild := denyPolicy("wild", wildcard)
	wild.Config.Priority = 0
	if _, err := svc.ApplyPolicy(ctx, wild); err == nil {
		t.Fatal("apply with a rejected flow succeeded")
	}
	if got, ok := client.entry(flow.Match); !ok || got != "foreign:pipeline" {
		t.Fatalf("foreign entry %q = %q (present %v), want it kept; deletes %v", flow.Match, got, ok, client.deleted())
	}
}

// A target ApplyPolicy cannot install flows on is refused before any flow is
// installed, and no policy is recorded: a non-bridge target, or a bridge
// target that resolves to no bridge (#2022 R12-1).
func TestSDNService_ApplyPolicy_RefusesTargetsItCannotApply(t *testing.T) {
	bridge := func(id string) *platformv1.PolicyTarget {
		return &platformv1.PolicyTarget{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: id}
	}
	cases := []struct {
		name    string
		targets []*platformv1.PolicyTarget
		want    codes.Code
	}{
		{"non-bridge target", []*platformv1.PolicyTarget{{
			Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE + 1,
			Id:   "br0",
		}}, codes.InvalidArgument},
		{"missing bridge", []*platformv1.PolicyTarget{bridge("br-missing")}, codes.NotFound},
		{"known and missing bridge", []*platformv1.PolicyTarget{bridge("br0"), bridge("br-missing")}, codes.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, mods := newPolicyFlowFixture(t)
			req := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
			req.PolicyId = "policy-refused"
			req.Config.Targets = tc.targets

			_, err := svc.ApplyPolicy(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(err), "%v", err)
			assert.Empty(t, *mods, "no flow may be installed for a refused target")

			_, err = svc.GetPolicy(context.Background(), &platformv1.GetPolicyRequest{PolicyId: req.PolicyId})
			assert.Error(t, err, "a refused apply records no policy")
			list, err := svc.ListPolicies(context.Background(), &platformv1.ListPoliciesRequest{})
			require.NoError(t, err)
			assert.Empty(t, list.GetPolicies(), "a refused apply records no policy")
		})
	}
}

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

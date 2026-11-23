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
// is stored with status "inactive" and installs no flows.
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
	assert.Empty(t, stored.flowIDs)
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

// errInjectedOVS is the failure replacingOVS returns when told to fail.
var errInjectedOVS = errors.New("injected OVS failure")

// replacingOVS models the OpenFlow semantics ApplyPolicy depends on: AddFlow
// sends OFPFC_ADD, which replaces an installed flow with the same table,
// priority and match, and a delete removes every flow it matches. The shared
// mock appends on AddFlow and removes nothing on delete, which hides both.
type replacingOVS struct {
	*MockOVSClientInterface

	addCalls  int   // AddFlow calls so far
	failAddOn int   // the 1-based AddFlow call that fails; 0 never
	deleteErr error // returned by DeleteFlow and DeleteFlowStrict when set
}

func newReplacingOVSFixture(t *testing.T) (*SDNService, *replacingOVS) {
	t.Helper()
	fake := &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}
	fake.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	return svc, fake
}

func (f *replacingOVS) AddFlow(_ context.Context, bridgeName string, flow *ovs.FlowMod) error {
	f.addCalls++
	if f.failAddOn > 0 && f.addCalls == f.failAddOn {
		return errInjectedOVS
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.removeLocked(bridgeName, func(fl *ovs.Flow) bool {
		return fl.Table == flow.Table && fl.Priority == flow.Priority && fl.Match == flow.Match
	})
	f.flows[bridgeName] = append(kept, &ovs.Flow{
		Table:    flow.Table,
		Priority: flow.Priority,
		Match:    flow.Match,
		Actions:  flow.Actions,
		Cookie:   flow.Cookie,
	})
	return nil
}

func (f *replacingOVS) DeleteFlow(_ context.Context, bridgeName string, match string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flows[bridgeName] = f.removeLocked(bridgeName, func(fl *ovs.Flow) bool { return fl.Match == match })
	return nil
}

func (f *replacingOVS) DeleteFlowStrict(_ context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flows[bridgeName] = f.removeLocked(bridgeName, func(fl *ovs.Flow) bool {
		return fl.Table == flow.Table && fl.Priority == flow.Priority && fl.Match == flow.Match
	})
	return nil
}

// removeLocked returns the bridge's flows without those drop selects; the
// caller holds f.mu.
func (f *replacingOVS) removeLocked(bridgeName string, drop func(*ovs.Flow) bool) []*ovs.Flow {
	kept := make([]*ovs.Flow, 0, len(f.flows[bridgeName]))
	for _, fl := range f.flows[bridgeName] {
		if !drop(fl) {
			kept = append(kept, fl)
		}
	}
	return kept
}

func (f *replacingOVS) matches(t *testing.T, bridgeName string) []string {
	t.Helper()
	flows, err := f.ListFlows(context.Background(), bridgeName)
	require.NoError(t, err)
	out := make([]string, 0, len(flows))
	for _, fl := range flows {
		out = append(out, fl.Match)
	}
	return out
}

// twoRulePolicyConfig is an enabled policy on br0 whose two rules have
// distinct matches.
func twoRulePolicyConfig() *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name:     "web",
		Priority: 100,
		Enabled:  true,
		Rules: []*platformv1.PolicyRule{
			{RuleId: "deny-a", Priority: 200, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.10"}},
			{RuleId: "deny-b", Priority: 200, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
				Match: &platformv1.PolicyRuleMatch{SourceIp: "192.0.2.20"}},
		},
		Targets: []*platformv1.PolicyTarget{bridgeTarget("br0")},
	}
}

func getPolicy(t *testing.T, svc *SDNService, id string) *platformv1.Policy {
	t.Helper()
	resp, err := svc.GetPolicy(context.Background(), &platformv1.GetPolicyRequest{PolicyId: id})
	require.NoError(t, err)
	return resp.GetPolicy()
}

// TestSDNService_ApplyPolicy_DisableRemovesInstalledFlows checks reapplying a
// policy with enabled=false removes the flows its enabled apply installed.
func TestSDNService_ApplyPolicy_DisableRemovesInstalledFlows(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)
	require.Len(t, fake.matches(t, "br0"), 1)

	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(false, bridgeTarget("br0")),
	})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))

	got := getPolicy(t, svc, "p1")
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, got.GetStatus())
	assert.False(t, got.GetConfig().GetEnabled())
}

// TestSDNService_ApplyPolicy_FailedDisableReportsError checks a disable whose
// flow removal fails returns Internal and never reports the policy inactive
// while its flows stay installed.
func TestSDNService_ApplyPolicy_FailedDisableReportsError(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)

	fake.deleteErr = errInjectedOVS
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(false, bridgeTarget("br0")),
	})
	assert.Equal(t, codes.Internal, status.Code(err))

	got := getPolicy(t, svc, "p1")
	assert.NotEqual(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, got.GetStatus())
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ERROR, got.GetStatus())
	assert.Len(t, fake.matches(t, "br0"), 1)
}

// TestSDNService_ApplyPolicy_FailedReapplyRestoresReplacedFlows checks a
// reapply that fails part way leaves the prior policy's flows installed, even
// though OFPFC_ADD already replaced a same-match prior flow.
func TestSDNService_ApplyPolicy_FailedReapplyRestoresReplacedFlows(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	prior := fake.matches(t, "br0")
	require.ElementsMatch(t, []string{"nw_src=192.0.2.10", "nw_src=192.0.2.20"}, prior)

	fake.failAddOn = fake.addCalls + 2
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	assert.Equal(t, codes.Internal, status.Code(err))

	assert.ElementsMatch(t, prior, fake.matches(t, "br0"))
	got := getPolicy(t, svc, "p1")
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, got.GetStatus())
	require.Len(t, got.GetConfig().GetRules(), 2)
	assert.Equal(t, "deny-a", got.GetConfig().GetRules()[0].GetRuleId())
	assert.Equal(t, "deny-b", got.GetConfig().GetRules()[1].GetRuleId())
}

// TestSDNService_ApplyPolicy_AddFlowFailureIsNotStored checks a new policy
// whose flow install fails returns Internal, stores nothing and leaves no flow.
func TestSDNService_ApplyPolicy_AddFlowFailureIsNotStored(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	fake.failAddOn = 1

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Empty(t, fake.matches(t, "br0"))

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	assert.Empty(t, svc.policies)
}

// A second policy installing the same (bridge, table, priority, match) as an
// enabled one would replace its flow, and withdrawing either would delete
// the other's: it is refused, and the first keeps its flow (#2234).
func TestSDNService_ApplyPolicy_RefusesFlowKeyOwnedByAnotherPolicy(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)

	cfg2 := enforcePolicyConfig(true, bridgeTarget("br0"))
	cfg2.Name = "web2"
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p2", Config: cfg2})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)
	assert.Contains(t, status.Convert(err).Message(), "p1")

	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p2"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	require.Len(t, fake.matches(t, "br0"), 1)

	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(false, bridgeTarget("br0")),
	})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
}

// A disable withdraws from the bridges the flows were installed on, not
// from a fresh lookup of the targets, which may fail or be empty (#2234).
func TestSDNService_ApplyPolicy_DisableUsesInstalledBridges(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)
	require.Len(t, fake.matches(t, "br0"), 1)

	fake.listBridgesErr = errInjectedOVS
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(false),
	})
	require.NoError(t, err)
	fake.listBridgesErr = nil
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, getPolicy(t, svc, "p1").GetStatus())
}

// A bridge lookup that fails is not a confirmed absence: Unavailable, and
// nothing is stored (#2234).
func TestSDNService_ApplyPolicy_BridgeLookupFailureIsUnavailable(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	fake.listBridgesErr = errInjectedOVS

	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	assert.Equal(t, codes.Unavailable, status.Code(err), "err = %v", err)

	svc.mu.RLock()
	defer svc.mu.RUnlock()
	assert.Empty(t, svc.policies)
}

// gatedOVS blocks AddFlow, after the flow is in place, while gate is set,
// so a test can run a second call in the middle of the first.
type gatedOVS struct {
	*replacingOVS

	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (g *gatedOVS) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	err := g.replacingOVS.AddFlow(ctx, bridgeName, flow)
	if g.gate != nil {
		g.once.Do(func() { close(g.entered) })
		<-g.gate
	}
	return err
}

// A disable that arrives while an enabled reapply is installing must not
// leave an active record without its flow, or the reverse (#2234).
func TestSDNService_ApplyPolicy_SerializesReapplyAndDisable(t *testing.T) {
	inner := &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}
	inner.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	fake := &gatedOVS{replacingOVS: inner, entered: make(chan struct{})}
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
	})
	require.NoError(t, err)

	fake.gate = make(chan struct{})
	var errA, errB error
	aDone := make(chan struct{})
	bDone := make(chan struct{})
	go func() {
		defer close(aDone)
		_, errA = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
			PolicyId: "p1", Config: enforcePolicyConfig(true, bridgeTarget("br0")),
		})
	}()
	<-fake.entered
	go func() {
		defer close(bDone)
		_, errB = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
			PolicyId: "p1", Config: enforcePolicyConfig(false, bridgeTarget("br0")),
		})
	}()
	select {
	case <-bDone:
	case <-time.After(200 * time.Millisecond):
	}
	close(fake.gate)
	<-aDone
	<-bDone
	require.NoError(t, errA)
	require.NoError(t, errB)

	flows := fake.matches(t, "br0")
	switch got := getPolicy(t, svc, "p1").GetStatus(); got {
	case platformv1.PolicyStatus_POLICY_STATUS_ACTIVE:
		assert.Len(t, flows, 1, "active policy without its flow")
	case platformv1.PolicyStatus_POLICY_STATUS_INACTIVE:
		assert.Empty(t, flows, "inactive policy with flows left")
	default:
		t.Fatalf("status = %v", got)
	}
}

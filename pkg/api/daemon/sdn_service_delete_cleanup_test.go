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
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newDeleteCleanupSDNService(t *testing.T, mock *ConfigurableMockOVSClient) *SDNService {
	t.Helper()
	mock.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{{UUID: "uuid-br0", Name: "br0"}}, nil
	})
	svc, err := NewSDNService("", WithOVSClient(mock))
	require.NoError(t, err)
	return svc
}

func vlanPolicyConfig(name string, vlan uint32) *platformv1.PolicyConfig {
	return &platformv1.PolicyConfig{
		Name:     name,
		Priority: 100,
		Enabled:  true,
		Rules: []*platformv1.PolicyRule{{
			RuleId:   "r1",
			Priority: 100,
			Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			Match: &platformv1.PolicyRuleMatch{
				SourceIp: "192.0.2.0/24",
				VlanId:   vlan,
			},
		}},
		Targets: []*platformv1.PolicyTarget{
			{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br0"},
		},
	}
}

func TestSDNService_DeletePolicy_RemovesOnlyItsOwnFlows(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	var mu sync.Mutex
	var added []*ovs.FlowMod
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		mu.Lock()
		defer mu.Unlock()
		added = append(added, flow)
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	require.NoError(t, err)
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "b", Config: vlanPolicyConfig("pb", 20)})
	require.NoError(t, err)

	require.Len(t, added, 2)
	cookieA, cookieB := added[0].Cookie, added[1].Cookie
	require.NotEmpty(t, cookieA)
	require.NotEmpty(t, cookieB)
	require.NotEqual(t, cookieA, cookieB)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)

	assert.Empty(t, mock.GetCalls("DeleteFlow"))
	assert.Empty(t, mock.GetCalls("DeleteFlowsByCookie"))
	calls := mock.GetCalls("DeleteFlowStrict")
	require.Len(t, calls, 1)
	assert.Equal(t, "br0", calls[0].Args[0])
	removed, ok := calls[0].Args[1].(*ovs.FlowMod)
	require.True(t, ok)
	assert.Equal(t, cookieA, removed.Cookie)
	assert.Equal(t, added[0].Match, removed.Match)

	list, err := svc.ListPolicies(ctx, &platformv1.ListPoliciesRequest{})
	require.NoError(t, err)
	var ids []string
	for _, p := range list.GetPolicies() {
		ids = append(ids, p.GetId())
	}
	assert.Equal(t, []string{"b"}, ids)
}

func ovsCookieString(c uint64) string {
	return fmt.Sprintf("0x%x", c)
}

// TestSDNService_DeleteFlow_RefusesAPolicyOwnedFlow pins the #1955 Codex
// round-6 P1: every rule of a policy shares one cookie on a bridge, so
// ListFlows shows one ID for all of them. DeleteFlow on that ID must not
// delete the policy's rules behind its back; the policy is the unit, and
// only DeletePolicy removes them.
func TestSDNService_DeleteFlow_RefusesAPolicyOwnedFlow(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	var mu sync.Mutex
	var added []*ovs.FlowMod
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		mu.Lock()
		defer mu.Unlock()
		added = append(added, flow)
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	cfg := vlanPolicyConfig("pa", 10)
	cfg.Rules = append(cfg.Rules, &platformv1.PolicyRule{
		RuleId:   "r2",
		Priority: 90,
		Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
		Match: &platformv1.PolicyRuleMatch{
			SourceIp: "198.51.100.0/24",
			VlanId:   10,
		},
	})
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: cfg})
	require.NoError(t, err)

	require.Len(t, added, 2)
	require.NotEmpty(t, added[0].Cookie)
	require.Equal(t, added[0].Cookie, added[1].Cookie)
	flowID := ovs.FlowIDPrefix + added[0].Cookie

	_, err = svc.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: flowID})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, mock.GetCalls("DeleteFlowsByCookie"))

	got, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "a"})
	require.NoError(t, err)
	require.NotNil(t, got)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)
	assert.Empty(t, mock.GetCalls("DeleteFlowsByCookie"))
	calls := mock.GetCalls("DeleteFlowStrict")
	require.Len(t, calls, 2)
	for i, call := range calls {
		assert.Equal(t, "br0", call.Args[0])
		removed, ok := call.Args[1].(*ovs.FlowMod)
		require.True(t, ok)
		assert.Equal(t, added[i].Cookie, removed.Cookie)
	}
}

func TestSDNService_DeletePolicy_CleanupErrorKeepsPolicy(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	require.NoError(t, err)

	mock.OnDeleteFlowStrict(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		return errors.New("switch unreachable")
	})
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	svc.mu.RLock()
	_, kept := svc.policies["a"]
	svc.mu.RUnlock()
	assert.True(t, kept, "policy record must survive a failed cleanup")

	mock.OnDeleteFlowStrict(nil)
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)
	svc.mu.RLock()
	_, kept = svc.policies["a"]
	svc.mu.RUnlock()
	assert.False(t, kept)
}

func seedVLAN(svc *SDNService) {
	svc.mu.Lock()
	svc.vlans["br0:100"] = &vlanResource{vlanID: 100, ports: []string{"p1", "p2"}}
	svc.mu.Unlock()
}

func TestSDNService_DeleteVLAN_PortClearErrorKeepsVLAN(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	mock.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		if portName == "p2" {
			return errors.New("switch unreachable")
		}
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	seedVLAN(svc)

	_, err := svc.DeleteVLAN(context.Background(), &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 100})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))

	svc.mu.RLock()
	res, kept := svc.vlans["br0:100"]
	svc.mu.RUnlock()
	require.True(t, kept, "VLAN record must survive a failed port clear")
	assert.Equal(t, []string{"p2"}, res.ports)
}

func TestSDNService_DeleteVLAN_MissingPortCountsAsCleared(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	mock.OnSetPortVLAN(func(ctx context.Context, portName string, tag int64) error {
		if portName == "p2" {
			return ovs.ErrPortNotFound
		}
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	seedVLAN(svc)

	_, err := svc.DeleteVLAN(context.Background(), &platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 100})
	require.NoError(t, err)

	svc.mu.RLock()
	_, kept := svc.vlans["br0:100"]
	svc.mu.RUnlock()
	assert.False(t, kept)
}

// A reapply whose rule changed must keep the policy's cookie: the flows
// of the first apply stay on the switch under it, and DeletePolicy only
// knows the cookie in the record.
func TestSDNService_DeletePolicy_RemovesFlowsOfEveryApply(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	var mu sync.Mutex
	var added []*ovs.FlowMod
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		mu.Lock()
		defer mu.Unlock()
		added = append(added, flow)
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	require.NoError(t, err)
	changed := vlanPolicyConfig("pa", 10)
	changed.Rules[0].Match.SourceIp = "198.51.100.0/24"
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: changed})
	require.NoError(t, err)

	require.Len(t, added, 2)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)

	// The reapply withdraws the first apply's flow, DeletePolicy the
	// second's: between them each installed flow gets its strict delete.
	deleted := make(map[string]bool)
	for _, call := range mock.GetCalls("DeleteFlowStrict") {
		assert.Equal(t, "br0", call.Args[0])
		flow, ok := call.Args[1].(*ovs.FlowMod)
		require.True(t, ok)
		deleted[flow.Match+"|"+flow.Cookie] = true
	}
	for _, flow := range added {
		assert.True(t, deleted[flow.Match+"|"+flow.Cookie], "flow %q cookie %s was never removed", flow.Match, flow.Cookie)
	}
	assert.Empty(t, mock.GetCalls("DeleteFlowsByCookie"))
}

// A bridge that no longer exists took its flows with it: DeletePolicy
// counts it as cleared. Any other switch error keeps the record.
func TestSDNService_DeletePolicy_DeletedBridgeCountsAsCleared(t *testing.T) {
	cases := []struct {
		name       string
		bridgeGone bool
	}{
		{name: "bridge gone", bridgeGone: true},
		{name: "bridge present", bridgeGone: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewConfigurableMockOVSClient()
			svc := newDeleteCleanupSDNService(t, mock)
			ctx := context.Background()

			_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
			require.NoError(t, err)

			mock.OnDeleteFlowStrict(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
				return errors.New("failed to connect OpenFlow client")
			})
			if tc.bridgeGone {
				mock.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
					return nil, nil
				})
			} else {
				mock.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
					return []*ovs.Bridge{{UUID: "uuid-br0", Name: "br0"}}, nil
				})
			}

			_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
			svc.mu.RLock()
			_, kept := svc.policies["a"]
			svc.mu.RUnlock()
			if tc.bridgeGone {
				require.NoError(t, err)
				assert.False(t, kept)
				return
			}
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.True(t, kept, "policy record must survive a failed cleanup on a live bridge")
		})
	}
}

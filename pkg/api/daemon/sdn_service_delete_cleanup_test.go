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

	svc.mu.RLock()
	wantCookie := svc.policies["a"].flowCookies["br0"]
	svc.mu.RUnlock()
	require.NotZero(t, wantCookie)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)

	assert.Empty(t, mock.GetCalls("DeleteFlow"))
	calls := mock.GetCalls("DeleteFlowsByCookie")
	require.Len(t, calls, 1)
	assert.Equal(t, "br0", calls[0].Args[0])
	assert.Equal(t, wantCookie, calls[0].Args[1])
	assert.Equal(t, ^uint64(0), calls[0].Args[2])
	assert.Equal(t, cookieA, ovsCookieString(wantCookie))

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

func TestSDNService_DeletePolicy_CleanupErrorKeepsPolicy(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	require.NoError(t, err)

	mock.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
		return errors.New("switch unreachable")
	})
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	svc.mu.RLock()
	_, kept := svc.policies["a"]
	svc.mu.RUnlock()
	assert.True(t, kept, "policy record must survive a failed cleanup")

	mock.OnDeleteFlowsByCookie(nil)
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

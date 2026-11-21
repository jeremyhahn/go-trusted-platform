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
	assert.Equal(t, "disabled", stored.status)
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

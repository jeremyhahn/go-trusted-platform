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

// TestSDNService_ApplyPolicy_GeneratedIDsAreUnique pins the random policy and
// flow IDs: timestamp IDs collided when two were minted within the clock's
// resolution, as one rule installed on two bridges in a single call does (#284).
func TestSDNService_ApplyPolicy_GeneratedIDsAreUnique(t *testing.T) {
	mockOVS := NewMockOVSClientInterface()
	mockOVS.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	mockOVS.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-br1", Name: "br1"})
	svc := newTestSDNServiceWithMock(t, mockOVS)
	ctx := context.Background()

	config := func(name string) *platformv1.PolicyConfig {
		return &platformv1.PolicyConfig{
			Name:     name,
			Priority: 100,
			Rules: []*platformv1.PolicyRule{
				{RuleId: "r1", Priority: 100, Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW},
			},
			Targets: []*platformv1.PolicyTarget{
				{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br0"},
				{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br1"},
			},
		}
	}

	first, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: config("web")})
	require.NoError(t, err)
	second, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: config("db")})
	require.NoError(t, err)

	firstID := first.GetPolicy().GetId()
	assert.Regexp(t, `^policy-[0-9a-f-]{36}$`, firstID)
	assert.NotEqual(t, firstID, second.GetPolicy().GetId())

	svc.mu.RLock()
	flowIDs := svc.policies[firstID].flowIDs
	svc.mu.RUnlock()
	require.Len(t, flowIDs, 2)
	assert.NotEqual(t, flowIDs[0], flowIDs[1])
}

// TestSDNService_ApplyPolicy_KeepsCallerPolicyID checks a caller-supplied ID
// is used verbatim and a missing config is rejected before any ID is minted.
func TestSDNService_ApplyPolicy_KeepsCallerPolicyID(t *testing.T) {
	svc := newTestSDNServiceWithMock(t, NewMockOVSClientInterface())
	ctx := context.Background()

	resp, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{
		PolicyId: "policy-fixed",
		Config:   &platformv1.PolicyConfig{Name: "web"},
	})
	require.NoError(t, err)
	assert.Equal(t, "policy-fixed", resp.GetPolicy().GetId())

	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "policy-other"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

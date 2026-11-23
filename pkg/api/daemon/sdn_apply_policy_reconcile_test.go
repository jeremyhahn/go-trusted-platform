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

// The constraint matches sdn_apply_policy_enforce_test.go, whose fixtures
// (replacingOVS, twoRulePolicyConfig, getPolicy) are used here.

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deleting a disabled policy must not touch the switch: it installed no
// flows, and a match-based delete would remove an enabled policy's flow
// with the same match (#2234).
func TestSDNService_DeletePolicy_DisabledPolicyKeepsEnabledPolicyFlows(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pa", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	before := fake.matches(t, "br0")
	require.Len(t, before, 2)

	cfgB := twoRulePolicyConfig()
	cfgB.Name = "web-disabled"
	cfgB.Enabled = false
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pb", Config: cfgB})
	require.NoError(t, err)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "pb"})
	require.NoError(t, err)

	assert.ElementsMatch(t, before, fake.matches(t, "br0"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, getPolicy(t, svc, "pa").GetStatus())
}

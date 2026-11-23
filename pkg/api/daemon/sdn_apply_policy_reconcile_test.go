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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// writeThenFailOVS installs the flow of AddFlow call failOn and then
// returns an error, as a barrier that times out after the write would: the
// caller cannot tell whether that flow is on the switch.
type writeThenFailOVS struct {
	*replacingOVS

	calls  int
	failOn int // the 1-based AddFlow call that installs and then fails
}

func (w *writeThenFailOVS) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	w.calls++
	if err := w.replacingOVS.AddFlow(ctx, bridgeName, flow); err != nil {
		return err
	}
	if w.calls == w.failOn {
		return errInjectedOVS
	}
	return nil
}

func newWriteThenFailFixture(t *testing.T) (*SDNService, *writeThenFailOVS) {
	t.Helper()
	inner := &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}
	inner.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	fake := &writeThenFailOVS{replacingOVS: inner}
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)
	return svc, fake
}

// The flow whose AddFlow failed may be installed: the rollback removes it
// too, and keeps a record to clean up with when the rollback fails (#2234).
func TestSDNService_ApplyPolicy_FailedAddRollsBackTheFailingFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("new policy", func(t *testing.T) {
		svc, fake := newWriteThenFailFixture(t)
		fake.failOn = 2

		_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
		assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)
		assert.Empty(t, fake.matches(t, "br0"))
		_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("reapply restores the prior flows", func(t *testing.T) {
		svc, fake := newWriteThenFailFixture(t)
		_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
		require.NoError(t, err)
		prior := fake.matches(t, "br0")
		require.Len(t, prior, 2)

		cfg := twoRulePolicyConfig()
		cfg.Rules[0].Match.SourceIp = "192.0.2.30"
		cfg.Rules[1].Match.SourceIp = "192.0.2.40"
		fake.failOn = fake.calls + 2
		_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
		assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)

		assert.ElementsMatch(t, prior, fake.matches(t, "br0"))
		assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, getPolicy(t, svc, "p1").GetStatus())
	})

	t.Run("failed rollback keeps an error record to clean up with", func(t *testing.T) {
		svc, fake := newWriteThenFailFixture(t)
		fake.failOn = 2
		fake.deleteErr = errInjectedOVS

		_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
		assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)
		require.Len(t, fake.matches(t, "br0"), 2)
		assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ERROR, getPolicy(t, svc, "p1").GetStatus())

		fake.deleteErr = nil
		_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p1"})
		require.NoError(t, err)
		assert.Empty(t, fake.matches(t, "br0"))
	})
}

// An enabled reapply that moves a policy to another bridge withdraws its
// flows from the old one, so a later disable leaves no flow behind (#2234).
func TestSDNService_ApplyPolicy_ReapplyWithdrawsOldBridgeFlows(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	fake.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-br1", Name: "br1"})
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	require.Len(t, fake.matches(t, "br0"), 2)

	cfg := twoRulePolicyConfig()
	cfg.Targets = []*platformv1.PolicyTarget{bridgeTarget("br1")}
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Len(t, fake.matches(t, "br1"), 2)

	cfg.Enabled = false
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
	require.NoError(t, err)
	assert.Empty(t, fake.matches(t, "br0"))
	assert.Empty(t, fake.matches(t, "br1"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_INACTIVE, getPolicy(t, svc, "p1").GetStatus())
}

// OpenFlow priorities are 16-bit: an effective priority outside 0..65535
// would be truncated on the wire, so it is refused before any flow is
// installed (#2234).
func TestSDNService_ApplyPolicy_PriorityOutsideOpenFlowRangeIsRefused(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*platformv1.PolicyConfig){
		"rule above 65535": func(c *platformv1.PolicyConfig) { c.Rules[1].Priority = 65536 + 200 },
		"rule below 0":     func(c *platformv1.PolicyConfig) { c.Rules[1].Priority = -1 },
		"policy above 65535": func(c *platformv1.PolicyConfig) {
			c.Priority = 70000
			c.Rules[1].Priority = 0
		},
		"policy below 0": func(c *platformv1.PolicyConfig) {
			c.Priority = -5
			c.Rules[1].Priority = 0
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			svc, fake := newReplacingOVSFixture(t)
			cfg := twoRulePolicyConfig()
			mutate(cfg)

			_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: cfg})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
			assert.Empty(t, fake.matches(t, "br0"))
			_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
			assert.Equal(t, codes.NotFound, status.Code(err))
		})
	}
}

// Two policies whose effective priorities are equal on the wire occupy the
// same flow entry and conflict, whichever field the priority came from
// (#2234).
func TestSDNService_ApplyPolicy_ConflictKeyUsesWirePriority(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	cfgA := twoRulePolicyConfig()
	cfgA.Rules[0].Priority = 100
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pa", Config: cfgA})
	require.NoError(t, err)
	before := fake.matches(t, "br0")

	cfgB := twoRulePolicyConfig()
	cfgB.Name = "web-b"
	cfgB.Priority = 100
	cfgB.Rules = cfgB.Rules[:1]
	cfgB.Rules[0].Priority = 0
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pb", Config: cfgB})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)
	assert.ElementsMatch(t, before, fake.matches(t, "br0"))
}

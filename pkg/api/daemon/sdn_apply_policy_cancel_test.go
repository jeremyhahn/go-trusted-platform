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

// A /0 source matches every source: it is the same switch entry as a rule
// with no source, so reapplying from one to the other leaves nothing stale
// to strictly delete (that delete would remove the replacement) (#2234).
func TestStalePolicyFlows_ZeroPrefixIsTheOmittedSource(t *testing.T) {
	old := []policyFlow{{bridge: "br0", ruleID: "r1", mod: &ovs.FlowMod{
		Table: 0, Priority: 200, Match: "tcp,nw_src=0.0.0.0/0,tp_dst=443", Actions: "drop",
	}}}
	current := []policyFlow{{bridge: "br0", ruleID: "r1", mod: &ovs.FlowMod{
		Table: 0, Priority: 200, Match: "tcp,tp_dst=443", Actions: "drop",
	}}}
	assert.Empty(t, stalePolicyFlows(old, current))
}

// A second policy whose rule omits the source conflicts with an enabled
// policy whose rule has a /0 source: both are one switch entry (#2234).
func TestSDNService_ApplyPolicy_ZeroPrefixConflictsWithOmittedSource(t *testing.T) {
	svc, fake := newReplacingOVSFixture(t)
	ctx := context.Background()

	cfgA := twoRulePolicyConfig()
	cfgA.Rules = cfgA.Rules[:1]
	cfgA.Rules[0].Priority = 100
	cfgA.Rules[0].Match = &platformv1.PolicyRuleMatch{Protocol: "tcp", SourceIp: "0.0.0.0/0", DestinationPort: 443}
	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pa", Config: cfgA})
	require.NoError(t, err)
	before := fake.matches(t, "br0")

	cfgB := twoRulePolicyConfig()
	cfgB.Name = "web-b"
	cfgB.Rules = cfgB.Rules[:1]
	cfgB.Rules[0].Priority = 100
	cfgB.Rules[0].Match = &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 443}
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "pb", Config: cfgB})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "err = %v", err)
	assert.ElementsMatch(t, before, fake.matches(t, "br0"))
}

// cancelAfterWriteOVS writes each flow change and only then reports the
// context's error, as the native OpenFlow client does: it sends before it
// selects ctx.Done. On the cancelOn-th AddFlow it cancels the request.
type cancelAfterWriteOVS struct {
	*replacingOVS

	calls    int
	cancelOn int
	cancel   context.CancelFunc
}

func (c *cancelAfterWriteOVS) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	c.calls++
	if err := c.replacingOVS.AddFlow(ctx, bridgeName, flow); err != nil {
		return err
	}
	if c.cancelOn > 0 && c.calls == c.cancelOn && c.cancel != nil {
		c.cancel()
	}
	return ctx.Err()
}

func (c *cancelAfterWriteOVS) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if err := c.replacingOVS.DeleteFlowStrict(ctx, bridgeName, flow); err != nil {
		return err
	}
	return ctx.Err()
}

// A reapply canceled after its flows were written must still roll back to
// every prior flow: the rollback runs on a context the cancel does not
// reach (#2234).
func TestSDNService_ApplyPolicy_CanceledReapplyRestoresEveryPriorFlow(t *testing.T) {
	inner := &replacingOVS{MockOVSClientInterface: NewMockOVSClientInterface()}
	inner.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-br0", Name: "br0"})
	fake := &cancelAfterWriteOVS{replacingOVS: inner}
	svc, err := NewSDNService("", WithOVSClient(fake))
	require.NoError(t, err)

	_, err = svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	require.NoError(t, err)
	prior := fake.matches(t, "br0")
	require.Len(t, prior, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.cancel = cancel
	fake.cancelOn = fake.calls + 2
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: twoRulePolicyConfig()})
	assert.Equal(t, codes.Internal, status.Code(err), "err = %v", err)

	assert.ElementsMatch(t, prior, fake.matches(t, "br0"))
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, getPolicy(t, svc, "p1").GetStatus())
}

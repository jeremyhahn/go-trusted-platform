package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// looseDeleteSwitch adds OpenFlow's non-strict delete to the switch model:
// OFPFC_DELETE removes every entry whose match carries all the given fields,
// whatever its priority.
type looseDeleteSwitch struct {
	*switchModelClient
}

func (c *looseDeleteSwitch) DeleteFlow(_ context.Context, _ string, match string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := strings.Split(match, ",")
	for m := range c.entries {
		have := map[string]bool{}
		for _, f := range strings.Split(m, ",") {
			have[f] = true
		}
		all := true
		for _, f := range want {
			if f != "" && !have[f] {
				all = false
				break
			}
		}
		if all {
			delete(c.entries, m)
		}
	}
	return nil
}

func newLooseDeleteSDNService(t *testing.T) (*SDNService, *looseDeleteSwitch) {
	t.Helper()
	sw := &looseDeleteSwitch{switchModelClient: &switchModelClient{
		ConfigurableMockOVSClient: NewConfigurableMockOVSClient(),
		entries:                   map[string]string{},
	}}
	svc, err := NewSDNService("", WithOVSClient(sw))
	require.NoError(t, err)
	svc.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	return svc, sw
}

func policyStatus(svc *SDNService, id string) string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if p, ok := svc.policies[id]; ok {
		return p.status
	}
	return ""
}

// Deleting a priority-100 policy matching TCP must not remove a separate
// priority-200 deny matching TCP port 22 (#2021 Codex).
func TestSDNService_DeletePolicy_KeepsAnotherPolicysOverlappingFlow(t *testing.T) {
	svc, sw := newLooseDeleteSDNService(t)
	ctx := context.Background()

	a := denyPolicy("a", allowRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp"}))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)

	b := denyPolicy("b", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	b.PolicyId = "pol-b"
	b.Config.Priority = 200
	_, err = svc.ApplyPolicy(ctx, b)
	require.NoError(t, err)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "pol-a"})
	require.NoError(t, err)

	_, ok := sw.entry("tcp")
	require.False(t, ok, "the deleted policy's flow must be removed")
	actions, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok, "the priority-200 deny must stay installed")
	require.Equal(t, "drop", actions)
	require.Equal(t, "active", policyStatus(svc, "pol-b"))
}

// Two policies with the same entry: deleting the one in force puts the
// surviving policy's flow back (#2021 Codex).
func TestSDNService_DeletePolicy_RestoresASurvivingPolicysSameEntry(t *testing.T) {
	svc, sw := newLooseDeleteSDNService(t)
	ctx := context.Background()
	ssh := &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}

	a := denyPolicy("a", denyRule("r1", ssh))
	a.PolicyId = "pol-a"
	_, err := svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)
	b := denyPolicy("b", allowRule("r1", ssh))
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.NoError(t, err)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "pol-b"})
	require.NoError(t, err)

	actions, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok, "the surviving policy's entry must be on the switch")
	require.Equal(t, "drop", actions)
	require.Equal(t, "active", policyStatus(svc, "pol-a"))
}

// unconfirmedDeleteSwitch removes the entry on a strict delete and then
// fails, as a delete whose barrier times out after the switch applied it.
type unconfirmedDeleteSwitch struct {
	*looseDeleteSwitch
}

func (c *unconfirmedDeleteSwitch) DeleteFlowStrict(ctx context.Context, bridge string, flow *ovs.FlowMod) error {
	if err := c.looseDeleteSwitch.DeleteFlowStrict(ctx, bridge, flow); err != nil {
		return err
	}
	return errors.New("barrier: confirmation timed out")
}

// A strict delete that removed the shared entry but failed to confirm must
// still restore the surviving policy's flow, and the deleted policy stays
// recorded with an error returned (#2021 Codex).
func TestSDNService_DeletePolicy_RestoresSurvivorWhenTheDeleteConfirmationFails(t *testing.T) {
	_, loose := newLooseDeleteSDNService(t)
	sw := &unconfirmedDeleteSwitch{looseDeleteSwitch: loose}
	svc, err := NewSDNService("", WithOVSClient(sw))
	require.NoError(t, err)
	svc.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	ctx := context.Background()
	ssh := &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}

	a := denyPolicy("a", denyRule("r1", ssh))
	a.PolicyId = "pol-a"
	_, err = svc.ApplyPolicy(ctx, a)
	require.NoError(t, err)
	b := denyPolicy("b", allowRule("r1", ssh))
	b.PolicyId = "pol-b"
	_, err = svc.ApplyPolicy(ctx, b)
	require.NoError(t, err)

	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "pol-b"})
	require.Error(t, err, "an unconfirmed delete must not report success")

	actions, ok := sw.entry("tcp,tp_dst=22")
	require.True(t, ok, "the surviving policy's entry must be back on the switch")
	require.Equal(t, "drop", actions)
	require.Equal(t, "active", policyStatus(svc, "pol-a"))
	require.NotEmpty(t, policyStatus(svc, "pol-b"), "a policy whose delete failed stays recorded")
}

// VLAN 4097 encodes as VLAN 1 on the wire: it is refused before any switch
// write (#2021 Codex).
func TestSDNService_ApplyPolicy_RefusesAnOutOfRangeVLAN(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)
	var writes int
	sw.addHook = func(*ovs.FlowMod) error { writes++; return nil }

	for _, vid := range []uint32{4096, 4097} {
		req := denyPolicy("v", allowRule("r1", &platformv1.PolicyRuleMatch{VlanId: vid}))
		_, err := svc.ApplyPolicy(context.Background(), req)
		require.Error(t, err, "vlan %d", vid)
		require.Equal(t, codes.InvalidArgument, status.Code(err), "vlan %d", vid)
	}
	require.Zero(t, writes)
	require.Empty(t, sw.deleted())
	require.Empty(t, sw.entries)

	ok := denyPolicy("v", allowRule("r1", &platformv1.PolicyRuleMatch{VlanId: 4095}))
	_, err := svc.ApplyPolicy(context.Background(), ok)
	require.NoError(t, err)
}

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

// sharedEntryPolicies returns pol-a (DENY on tcp) and pol-b (ALLOW on the
// same tcp entry plus a DENY on tcp,tp_dst=22), and pol-b's replacement
// that keeps only its tcp,tp_dst=22 rule.
func sharedEntryPolicies() (a, b, bReplaced *platformv1.ApplyPolicyRequest) {
	shared := &platformv1.PolicyRuleMatch{Protocol: "tcp"}
	ssh := &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}
	a = denyPolicy("a", denyRule("r1", shared))
	a.PolicyId = "pol-a"
	b = denyPolicy("b", allowRule("r1", shared), denyRule("r2", ssh))
	b.PolicyId = "pol-b"
	bReplaced = denyPolicy("b", denyRule("r2", ssh))
	bReplaced.PolicyId = "pol-b"
	return a, b, bReplaced
}

// A replacement that drops an entry another policy still owns puts that
// policy's flow back: the dropped policy's action must not stay in force
// (Codex round 6, PR #2021).
func TestSDNService_ApplyPolicy_ReplacementRestoresTheSurvivingPolicysAction(t *testing.T) {
	shared := &platformv1.PolicyRuleMatch{Protocol: "tcp"}

	t.Run("survivor applied first", func(t *testing.T) {
		svc, sw := newSwitchModelSDNService(t)
		a, b, bReplaced := sharedEntryPolicies()
		aMod, err := svc.policyRuleToFlowMod(denyRule("r1", shared), 100)
		require.NoError(t, err)
		bMod, err := svc.policyRuleToFlowMod(allowRule("r1", shared), 100)
		require.NoError(t, err)
		require.NotEqual(t, aMod.Actions, bMod.Actions)

		_, err = svc.ApplyPolicy(context.Background(), a)
		require.NoError(t, err)
		_, err = svc.ApplyPolicy(context.Background(), b)
		require.NoError(t, err)
		actions, ok := sw.entry(aMod.Match)
		require.True(t, ok)
		require.Equal(t, bMod.Actions, actions, "the later policy's flow is in force")

		_, err = svc.ApplyPolicy(context.Background(), bReplaced)
		require.NoError(t, err)
		actions, ok = sw.entry(aMod.Match)
		require.True(t, ok, "pol-a still owns the entry")
		assert.Equal(t, aMod.Actions, actions, "pol-a's action must be back, not pol-b's dropped ALLOW")
	})

	t.Run("survivor applied last", func(t *testing.T) {
		svc, sw := newSwitchModelSDNService(t)
		a, b, bReplaced := sharedEntryPolicies()
		aMod, err := svc.policyRuleToFlowMod(denyRule("r1", shared), 100)
		require.NoError(t, err)

		_, err = svc.ApplyPolicy(context.Background(), b)
		require.NoError(t, err)
		_, err = svc.ApplyPolicy(context.Background(), a)
		require.NoError(t, err)

		_, err = svc.ApplyPolicy(context.Background(), bReplaced)
		require.NoError(t, err)
		actions, ok := sw.entry(aMod.Match)
		require.True(t, ok)
		assert.Equal(t, aMod.Actions, actions, "pol-a's action stays in force")
	})
}

// A replacement whose obsolete entry cannot be removed is not acknowledged:
// the apply returns Internal naming the entry, the new version is recorded
// as "error", and the entry stays queued for the next apply.
func TestSDNService_ApplyPolicy_FailedObsoleteDeleteFailsTheReplacement(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)

	first := denyPolicy("p",
		denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}),
		allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}),
	)
	first.PolicyId = "pol-1"
	_, err := svc.ApplyPolicy(context.Background(), first)
	require.NoError(t, err)

	errDelete := errors.New("test: delete refused")
	failed := false
	sw.mu.Lock()
	sw.deleteHook = func(flow *ovs.FlowMod) error {
		if flow.Match == "tcp" && !failed {
			failed = true
			return errDelete
		}
		return nil
	}
	sw.mu.Unlock()

	second := denyPolicy("p", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 22}))
	second.PolicyId = "pol-1"
	_, err = svc.ApplyPolicy(context.Background(), second)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err), "%v", err)
	assert.Contains(t, err.Error(), `"tcp"`, "the error names the entry left installed")
	require.True(t, failed)

	svc.mu.RLock()
	recorded := svc.policies["pol-1"]
	svc.mu.RUnlock()
	require.NotNil(t, recorded)
	require.Len(t, recorded.rules, 1, "the recorded policy is the new version")
	assert.Equal(t, "error", recorded.status)

	droppedMod, err := svc.policyRuleToFlowMod(allowRule("r2", &platformv1.PolicyRuleMatch{Protocol: "tcp"}), 100)
	require.NoError(t, err)
	svc.applyMu.Lock()
	_, stranded := svc.strandedFlows[newFlowEntryKey("br0", droppedMod)]
	svc.applyMu.Unlock()
	require.True(t, stranded, "the entry the delete failed on stays queued")

	y := denyPolicy("y", denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp", DestinationPort: 80}))
	_, err = svc.ApplyPolicy(context.Background(), y)
	require.NoError(t, err)
	_, ok := sw.entry("tcp")
	assert.False(t, ok, "the next apply removes the stranded entry")
	svc.applyMu.Lock()
	defer svc.applyMu.Unlock()
	assert.Empty(t, svc.strandedFlows)
}

// A replacement that drops a shared entry and cannot put the surviving
// policy's flow back is not acknowledged: Internal, the survivor is marked
// "error" and its entry is queued for restore.
func TestSDNService_ApplyPolicy_FailedSurvivorRestoreFailsTheReplacement(t *testing.T) {
	svc, sw := newSwitchModelSDNService(t)
	a, b, bReplaced := sharedEntryPolicies()
	aMod, err := svc.policyRuleToFlowMod(denyRule("r1", &platformv1.PolicyRuleMatch{Protocol: "tcp"}), 100)
	require.NoError(t, err)

	_, err = svc.ApplyPolicy(context.Background(), a)
	require.NoError(t, err)
	_, err = svc.ApplyPolicy(context.Background(), b)
	require.NoError(t, err)

	errRestore := errors.New("test: restore refused")
	sw.mu.Lock()
	sw.addHook = func(flow *ovs.FlowMod) error {
		if flow.Match == aMod.Match && flow.Actions == aMod.Actions {
			return errRestore
		}
		return nil
	}
	sw.mu.Unlock()

	_, err = svc.ApplyPolicy(context.Background(), bReplaced)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err), "%v", err)

	sw.mu.Lock()
	sw.addHook = nil
	sw.mu.Unlock()

	svc.mu.RLock()
	aStatus := svc.policies["pol-a"].status
	svc.mu.RUnlock()
	assert.Equal(t, "error", aStatus)
	svc.applyMu.Lock()
	defer svc.applyMu.Unlock()
	assert.True(t, svc.unrestoredFlows[newFlowEntryKey("br0", aMod)], "pol-a's entry is queued for restore")
}

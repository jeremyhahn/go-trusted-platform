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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// raceBound caps how long a hook waits for the other caller. With the
// serialized service the other caller is blocked, so the wait always runs
// out; it only bounds the fixed code's run time.
const raceBound = 500 * time.Millisecond

// fakeSwitch models the part of OVS these tests need: an AddFlow with the
// same bridge, match and priority as an installed rule replaces that rule's
// cookie, and DeleteFlowsByCookie removes the rules carrying the cookie.
type fakeSwitch struct {
	mu    sync.Mutex
	rules map[string]uint64
}

func newFakeSwitch(mock *ConfigurableMockOVSClient) *fakeSwitch {
	fs := &fakeSwitch{rules: make(map[string]uint64)}
	mock.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
		fs.deleteByCookie(bridgeName, cookie)
		return nil
	})
	mock.OnDeleteFlowStrict(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		fs.deleteStrict(bridgeName, flow)
		return nil
	})
	return fs
}

// deleteStrict removes the entry at the flow's match and priority when it
// carries the flow's cookie, as a cookie-restricted strict delete does.
func (fs *fakeSwitch) deleteStrict(bridgeName string, flow *ovs.FlowMod) {
	cookie, err := strconv.ParseUint(strings.TrimPrefix(flow.Cookie, "0x"), 16, 64)
	if err != nil {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	key := bridgeName + "|" + flow.Match + "|" + strconv.Itoa(flow.Priority)
	if c, ok := fs.rules[key]; ok && c == cookie {
		delete(fs.rules, key)
	}
}

// recordedCookies returns the cookies of every flow the policy's record
// may have on the switch; ok is false when the policy is not recorded.
func recordedCookies(svc *SDNService, policyID string) (map[uint64]bool, bool) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	p, ok := svc.policies[policyID]
	if !ok {
		return nil, false
	}
	out := make(map[uint64]bool)
	for _, flow := range svc.recordFlows(*p) {
		if c, err := strconv.ParseUint(strings.TrimPrefix(flow.mod.Cookie, "0x"), 16, 64); err == nil {
			out[c] = true
		}
	}
	return out, true
}

func (fs *fakeSwitch) add(t *testing.T, bridgeName string, flow *ovs.FlowMod) {
	cookie, err := strconv.ParseUint(strings.TrimPrefix(flow.Cookie, "0x"), 16, 64)
	if err != nil {
		t.Errorf("flow cookie %q: %v", flow.Cookie, err)
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.rules[bridgeName+"|"+flow.Match+"|"+strconv.Itoa(flow.Priority)] = cookie
}

func (fs *fakeSwitch) deleteByCookie(bridgeName string, cookie uint64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for key, c := range fs.rules {
		if c == cookie && strings.HasPrefix(key, bridgeName+"|") {
			delete(fs.rules, key)
		}
	}
}

func (fs *fakeSwitch) snapshot() map[string]uint64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make(map[string]uint64, len(fs.rules))
	for k, v := range fs.rules {
		out[k] = v
	}
	return out
}

// waitBounded waits for ch to close, at most raceBound.
func waitBounded(ch <-chan struct{}) {
	select {
	case <-ch:
	case <-time.After(raceBound):
	}
}

func TestSDNService_ApplyPolicy_ConcurrentFirstAppliesKeepOneCookie(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	fs := newFakeSwitch(mock)
	firstReturn := make(chan struct{})
	var closeFirst sync.Once
	var addCalls atomic.Int32
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		fs.add(t, bridgeName, flow)
		if addCalls.Add(1) == 1 {
			// The first caller has installed its rule; let the other caller
			// replace it and publish before this one publishes.
			waitBounded(firstReturn)
		}
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
			closeFirst.Do(func() { close(firstReturn) })
		}(i)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	rules := fs.snapshot()
	require.Len(t, rules, 1)
	recorded, listed := recordedCookies(svc, "a")
	require.True(t, listed)
	for key, cookie := range rules {
		assert.True(t, recorded[cookie], "recorded cookies must hold the surviving rule %s cookie %s", key, ovsCookieString(cookie))
	}

	_, err := svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "a"})
	require.NoError(t, err)
	assert.Empty(t, fs.snapshot(), "a successful delete must leave no flow of the policy installed")
}

// raceReapplyWithDelete applies policy "a" on br0, then runs a reapply on br0
// and br1 concurrently with a DeletePolicy by deleteKey, and checks that the
// switch and the record agree afterwards.
func raceReapplyWithDelete(t *testing.T, deleteKey string) {
	t.Helper()
	mock := NewConfigurableMockOVSClient()
	fs := newFakeSwitch(mock)
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		fs.add(t, bridgeName, flow)
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	mock.OnListBridges(func(ctx context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{{UUID: "uuid-br0", Name: "br0"}, {UUID: "uuid-br1", Name: "br1"}}, nil
	})
	ctx := context.Background()

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	require.NoError(t, err)

	deleteStarted := make(chan struct{})
	reapplyReturned := make(chan struct{})
	var startOnce sync.Once
	var reapplyWaited atomic.Bool
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		if reapplyWaited.CompareAndSwap(false, true) {
			// Let the delete snapshot the policy's cookies first.
			waitBounded(deleteStarted)
		}
		fs.add(t, bridgeName, flow)
		return nil
	})
	mock.OnDeleteFlowStrict(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		startOnce.Do(func() { close(deleteStarted) })
		// Let the reapply publish before this delete drops the record.
		waitBounded(reapplyReturned)
		fs.deleteStrict(bridgeName, flow)
		return nil
	})

	reapply := vlanPolicyConfig("pa", 10)
	reapply.Targets = append(reapply.Targets, &platformv1.PolicyTarget{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br1"})

	var wg sync.WaitGroup
	var applyErr, deleteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(reapplyReturned)
		_, applyErr = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: reapply})
	}()
	go func() {
		defer wg.Done()
		_, deleteErr = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: deleteKey})
	}()
	wg.Wait()
	require.NoError(t, applyErr)
	require.NoError(t, deleteErr)

	rules := fs.snapshot()
	recorded, listed := recordedCookies(svc, "a")
	if !listed {
		assert.Empty(t, rules, "the policy is gone, so no flow of it may stay installed")
		return
	}
	for key, cookie := range rules {
		assert.True(t, recorded[cookie], "rule %s carries cookie %s, which the policy record does not hold", key, ovsCookieString(cookie))
	}
}

func TestSDNService_DeletePolicy_RacingReapplyLeavesNoOrphanFlow(t *testing.T) {
	raceReapplyWithDelete(t, "a")
}

func TestSDNService_DeletePolicy_ByNameSerializesWithApplyByID(t *testing.T) {
	raceReapplyWithDelete(t, "pa")
}

func TestSDNService_ApplyPolicy_ConcurrentSameNameOneWins(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	fs := newFakeSwitch(mock)
	firstReturn := make(chan struct{})
	var closeFirst sync.Once
	var addCalls atomic.Int32
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		fs.add(t, bridgeName, flow)
		if addCalls.Add(1) == 1 {
			// Hold the first caller between its name check and its record
			// until the other caller has returned.
			waitBounded(firstReturn)
		}
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	ids := []string{"a", "b"}
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			_, errs[i] = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: id, Config: vlanPolicyConfig("pa", 10)})
			closeFirst.Do(func() { close(firstReturn) })
		}(i, id)
	}
	wg.Wait()

	var ok, exists int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case status.Code(err) == codes.AlreadyExists:
			exists++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, ok, "exactly one apply of the name must succeed")
	assert.Equal(t, 1, exists, "the other apply must fail with AlreadyExists")

	resp, err := svc.ListPolicies(ctx, &platformv1.ListPoliciesRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.GetPolicies(), 1)
}

// A DeleteFlow racing a first ApplyPolicy, between its flow installs and
// the publication of its record, must not strip the policy's flows: it
// waits for the apply, then refuses the policy's flow (#1955).
func TestSDNService_DeleteFlow_WaitsForPolicyApply(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	fs := newFakeSwitch(mock)
	installed := make(chan string, 1)
	release := make(chan struct{})
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		fs.add(t, bridgeName, flow)
		select {
		case installed <- flow.Cookie:
		default:
		}
		// Hold the apply after its install, before it publishes.
		waitBounded(release)
		return nil
	})
	svc := newDeleteCleanupSDNService(t, mock)
	ctx := context.Background()

	applyDone := make(chan struct{})
	var applyErr error
	go func() {
		defer close(applyDone)
		_, applyErr = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "a", Config: vlanPolicyConfig("pa", 10)})
	}()

	var cookie string
	select {
	case cookie = <-installed:
	case <-time.After(raceBound):
		close(release)
		t.Fatal("the apply installed no flow")
	}
	// The ID ListFlows hands out for the installed flow.
	flowID := ovs.FlowIDPrefix + cookie

	deleteDone := make(chan struct{})
	var deleteErr error
	go func() {
		defer close(deleteDone)
		_, deleteErr = svc.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: flowID})
	}()
	// Give an unserialized DeleteFlow the time to finish first.
	select {
	case <-deleteDone:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	waitBounded(applyDone)
	waitBounded(deleteDone)

	require.NoError(t, applyErr)
	require.Error(t, deleteErr)
	assert.Equal(t, codes.FailedPrecondition, status.Code(deleteErr))
	assert.Len(t, fs.snapshot(), 1, "the policy's flow must stay installed")
}

// Each rule of a policy gets its own flow ID, and GetFlowStats on it
// returns that rule's counters, not another rule's (#1955).
func TestSDNService_GetFlowStats_TwoRuleFlowsKeepTheirOwnCounters(t *testing.T) {
	mock := NewConfigurableMockOVSClient()
	var mu sync.Mutex
	var installed []*ovs.Flow
	packets := func(priority int) int64 {
		if priority == 100 {
			return 11
		}
		return 22
	}
	mock.OnAddFlow(func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
		mu.Lock()
		defer mu.Unlock()
		f := &ovs.Flow{Cookie: flow.Cookie, Table: flow.Table, Priority: flow.Priority, Match: flow.Match, Actions: flow.Actions}
		f.PacketCount = packets(flow.Priority)
		installed = append(installed, f)
		return nil
	})
	mock.OnListFlows(func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]*ovs.Flow(nil), installed...), nil
	})
	mock.OnGetFlowStats(func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
		rest, ok := strings.CutPrefix(match, "cookie=")
		if !ok {
			// The apply's occupancy read: nothing else holds the entries.
			return nil, nil
		}
		want, _, _ := strings.Cut(rest, "/")
		mu.Lock()
		defer mu.Unlock()
		var out []*ovs.Flow
		for _, f := range installed {
			if f.Cookie == want {
				out = append(out, f)
			}
		}
		return out, nil
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

	list, err := svc.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: "br0"})
	require.NoError(t, err)
	require.Len(t, list.GetFlows(), 2)
	assert.NotEqual(t, list.GetFlows()[0].GetId(), list.GetFlows()[1].GetId(), "each rule needs its own flow ID")
	for _, flow := range list.GetFlows() {
		stats, err := svc.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: flow.GetId()})
		require.NoError(t, err)
		priority := int(flow.GetConfig().GetPriority())
		assert.Equal(t, uint64(packets(priority)), stats.GetStats().GetPacketCount(), "flow %s (priority %d) returned another rule's counters", flow.GetId(), priority)
	}
}

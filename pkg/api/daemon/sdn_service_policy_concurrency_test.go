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
	return fs
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
	svc.mu.RLock()
	recorded := svc.policies["a"].flowCookies["br0"]
	svc.mu.RUnlock()
	for key, cookie := range rules {
		assert.Equal(t, ovsCookieString(cookie), ovsCookieString(recorded), "recorded cookie must match the surviving rule %s", key)
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
	mock.OnDeleteFlowsByCookie(func(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
		startOnce.Do(func() { close(deleteStarted) })
		// Let the reapply publish before this delete drops the record.
		waitBounded(reapplyReturned)
		fs.deleteByCookie(bridgeName, cookie)
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
	svc.mu.RLock()
	p, listed := svc.policies["a"]
	recorded := make(map[uint64]bool)
	if listed {
		for _, c := range p.flowCookies {
			recorded[c] = true
		}
	}
	svc.mu.RUnlock()
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

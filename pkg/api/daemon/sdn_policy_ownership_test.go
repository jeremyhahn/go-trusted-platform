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
	"strconv"
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

// Policy flow ownership (#1951, ruling 1170): a failed re-apply keeps the old
// flows, a partial install keeps every attempted cookie owned, policy
// mutations are serialized, and a policy on a deleted bridge can be deleted.

func newOwnershipFixture(t *testing.T) (*SDNService, *ConfigurableMockOVSClient) {
	t.Helper()
	mock := NewConfigurableMockOVSClient()
	mock.OnListBridges(func(context.Context) ([]*ovs.Bridge, error) {
		return []*ovs.Bridge{{UUID: "uuid-br0", Name: "br0"}}, nil
	})
	svc, err := NewSDNService("", WithOVSClient(mock))
	require.NoError(t, err)
	return svc, mock
}

func ownershipConfig(rules int, enabled bool) *platformv1.PolicyConfig {
	cfg := &platformv1.PolicyConfig{
		Name:     "own",
		Priority: 100,
		Enabled:  enabled,
		Targets:  []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE, Id: "br0"}},
	}
	for i := 0; i < rules; i++ {
		cfg.Rules = append(cfg.Rules, &platformv1.PolicyRule{
			RuleId:   fmt.Sprintf("r%d", i),
			Priority: 100,
			Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
		})
	}
	return cfg
}

func flowCookie(t *testing.T, flow *ovs.FlowMod) uint64 {
	t.Helper()
	c, err := strconv.ParseUint(flow.Cookie, 0, 64)
	require.NoError(t, err)
	return c
}

func deletedCookies(mock *ConfigurableMockOVSClient) []uint64 {
	var out []uint64
	for _, c := range mock.GetCalls("DeleteFlowsByCookie") {
		out = append(out, c.Args[1].(uint64))
	}
	return out
}

func policyCookies(svc *SDNService, id string) ([]uint64, *policyResource) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	p, ok := svc.policies[id]
	if !ok {
		return nil, nil
	}
	var out []uint64
	for _, f := range p.flows {
		out = append(out, f.cookie)
	}
	return out, p
}

func TestApplyPolicy_FailedUpdateKeepsOldFlows(t *testing.T) {
	svc, mock := newOwnershipFixture(t)
	ctx := context.Background()

	var mu sync.Mutex
	var added []uint64
	failSecond := false
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		mu.Lock()
		defer mu.Unlock()
		added = append(added, flowCookie(t, flow))
		if failSecond && len(added) == 3 {
			return errors.New("barrier failed")
		}
		return nil
	})

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: ownershipConfig(1, true)})
	require.NoError(t, err)
	oldCookies, _ := policyCookies(svc, "p1")
	require.Len(t, oldCookies, 1)
	cookieA := oldCookies[0]

	mu.Lock()
	failSecond = true
	mu.Unlock()
	_, err = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p1", Config: ownershipConfig(2, true)})
	assert.Equal(t, codes.Internal, status.Code(err))

	deleted := deletedCookies(mock)
	assert.NotContains(t, deleted, cookieA, "a failed update must not remove the old flows")
	require.Len(t, added, 3)
	assert.Contains(t, deleted, added[1], "the first new flow is removed")

	got, p := policyCookies(svc, "p1")
	require.NotNil(t, p)
	assert.Equal(t, []uint64{cookieA}, got)
	assert.Len(t, p.rules, 1, "the record is still the first version")
	assert.True(t, p.enabled)

	_, err = svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "p1"})
	require.NoError(t, err)
}

func TestApplyPolicy_PartialInstallKeepsResidualCookies(t *testing.T) {
	svc, mock := newOwnershipFixture(t)
	ctx := context.Background()

	var added []uint64
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		added = append(added, flowCookie(t, flow))
		if len(added) == 2 {
			return errors.New("barrier failed")
		}
		return nil
	})
	var deleteFails atomic.Bool
	deleteFails.Store(true)
	mock.OnDeleteFlowsByCookie(func(context.Context, string, uint64, uint64) error {
		if deleteFails.Load() {
			return errors.New("ovs unavailable")
		}
		return nil
	})

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p2", Config: ownershipConfig(2, true)})
	assert.Equal(t, codes.Internal, status.Code(err))

	got, p := policyCookies(svc, "p2")
	require.NotNil(t, p, "the leftover flows must stay owned by a record")
	assert.False(t, p.enabled)
	assert.Equal(t, "failed", p.status)
	require.Len(t, added, 2)
	assert.ElementsMatch(t, added, got, "both attempted cookies, the failed one included")

	deleteFails.Store(false)
	before := len(mock.GetCalls("DeleteFlowsByCookie"))
	_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p2"})
	require.NoError(t, err)
	assert.ElementsMatch(t, added, deletedCookies(mock)[before:])
	_, p = policyCookies(svc, "p2")
	assert.Nil(t, p)
}

func TestPolicyMutations_DeleteAndReapplySerialized(t *testing.T) {
	svc, mock := newOwnershipFixture(t)
	ctx := context.Background()

	var mu sync.Mutex
	var added []uint64
	var released atomic.Bool
	var addedWhileDeleting atomic.Bool
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		mu.Lock()
		added = append(added, flowCookie(t, flow))
		mu.Unlock()
		return nil
	})

	_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p3", Config: ownershipConfig(1, true)})
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	var deleteCalls atomic.Int32
	mock.OnDeleteFlowsByCookie(func(context.Context, string, uint64, uint64) error {
		if deleteCalls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	mock.OnAddFlow(func(_ context.Context, _ string, flow *ovs.FlowMod) error {
		if !released.Load() {
			addedWhileDeleting.Store(true)
		}
		mu.Lock()
		added = append(added, flowCookie(t, flow))
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	var deleteErr, applyErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, deleteErr = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p3"})
	}()
	<-entered
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, applyErr = svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p3", Config: ownershipConfig(1, true)})
	}()
	time.Sleep(50 * time.Millisecond)
	released.Store(true)
	close(release)
	wg.Wait()

	require.NoError(t, deleteErr)
	require.NoError(t, applyErr)
	assert.False(t, addedWhileDeleting.Load(), "the re-apply installed flows while the delete was in flight")

	owned, _ := policyCookies(svc, "p3")
	deleted := deletedCookies(mock)
	mu.Lock()
	defer mu.Unlock()
	for _, c := range added {
		assert.True(t, containsCookie(deleted, c) || containsCookie(owned, c), "cookie %#x is installed with no owner", c)
	}
}

func containsCookie(list []uint64, c uint64) bool {
	for _, v := range list {
		if v == c {
			return true
		}
	}
	return false
}

func TestDeletePolicy_MissingBridgeTreatsFlowsRemoved(t *testing.T) {
	cases := []struct {
		name      string
		bridgeErr error
		wantCode  codes.Code
		wantKept  bool
	}{
		{name: "bridge gone", bridgeErr: fmt.Errorf("lookup: %w", ovs.ErrBridgeNotFound), wantCode: codes.OK},
		{name: "other error", bridgeErr: errors.New("ovsdb unavailable"), wantCode: codes.Internal, wantKept: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, mock := newOwnershipFixture(t)
			ctx := context.Background()
			_, err := svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{PolicyId: "p4", Config: ownershipConfig(2, true)})
			require.NoError(t, err)

			mock.OnDeleteFlowsByCookie(func(context.Context, string, uint64, uint64) error {
				return errors.New("no such bridge")
			})
			mock.OnGetBridge(func(context.Context, string) (*ovs.Bridge, error) {
				return nil, tc.bridgeErr
			})

			_, err = svc.DeletePolicy(ctx, &platformv1.DeletePolicyRequest{PolicyId: "p4"})
			assert.Equal(t, tc.wantCode, status.Code(err))
			_, p := policyCookies(svc, "p4")
			assert.Equal(t, tc.wantKept, p != nil)
		})
	}
}

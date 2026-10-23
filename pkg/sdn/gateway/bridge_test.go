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

package gateway

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// testBridge is one fake OVS bridge that successive runtimes program, as
// successive datapath processes program one kernel bridge: what a killed
// process installed is still there when the next one starts (#557). Flows
// follow add-flow semantics, keyed by table, priority and match, and groups
// refuse what OVS refuses, so a reconcile that only works on an empty bridge
// fails here.
type testBridge struct {
	ovs.ClientInterface

	mu          sync.Mutex
	flows       map[testFlowKey]testFlow
	groups      map[uint32]openflow.GroupDesc
	failMode    string
	externalIDs map[string]string
}

type testFlowKey struct {
	table    int
	priority int
	match    string
}

type testFlow struct {
	actions string
	cookie  uint64
}

// errTestBridge is a request the fake bridge refuses, as OVS would.
type errTestBridge struct {
	Op     string
	Detail string
}

func (e *errTestBridge) Error() string { return "test bridge: " + e.Op + ": " + e.Detail }

func newTestBridge() *testBridge {
	return &testBridge{
		flows:       make(map[testFlowKey]testFlow),
		groups:      make(map[uint32]openflow.GroupDesc),
		externalIDs: make(map[string]string),
	}
}

// testController programs a testBridge through the policy flow controller
// the gateway's zone flows use; its methods are kept off testBridge because
// two of them share a name with the OVS client's.
type testController struct {
	b *testBridge
}

func (c *testController) InstallFlow(_ string, priority int, match string, actions string) error {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flows[testFlowKey{priority: priority, match: match}] = testFlow{actions: actions}
	return nil
}

// InstallFlows installs the batch whole or not at all, as one OpenFlow
// transaction does.
func (c *testController) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	b := c.b
	cookies := make([]uint64, len(rules))
	for i, rule := range rules {
		if rule.Cookie == "" {
			continue
		}
		cookie, err := strconv.ParseUint(rule.Cookie, 0, 64)
		if err != nil {
			return &errTestBridge{Op: "add-flow", Detail: "cookie " + strconv.Quote(rule.Cookie) + " is not a number"}
		}
		cookies[i] = cookie
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, rule := range rules {
		b.flows[testFlowKey{table: rule.Table, priority: rule.Priority, match: rule.Match}] =
			testFlow{actions: rule.Actions, cookie: cookies[i]}
	}
	return nil
}

func (c *testController) DeleteFlow(_ string, match string) error {
	b := c.b
	b.deleteFlows(func(k testFlowKey, _ testFlow) bool { return k.match == match })
	return nil
}

func (c *testController) DeleteFlowsByPort(_ string, portID string) error {
	b := c.b
	b.deleteFlows(func(k testFlowKey, _ testFlow) bool {
		return slices.Contains(strings.Split(k.match, ","), "in_port="+portID)
	})
	return nil
}

func (c *testController) ListFlows(_ string) ([]string, error) {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.flows))
	for k, f := range b.flows {
		out = append(out, fmt.Sprintf("cookie=0x%x, table=%d, priority=%d,%s actions=%s", f.cookie, k.table, k.priority, k.match, f.actions))
	}
	slices.Sort(out)
	return out, nil
}

// GetFlowStats answers the two dumps the gateway makes: every flow, and the
// flows under a cookie and mask (the generation sweep).
func (b *testBridge) GetFlowStats(_ context.Context, _ string, match string) ([]*ovs.Flow, error) {
	var cookie, mask uint64
	if match != "" {
		if _, err := fmt.Sscanf(match, "cookie=0x%x/0x%x", &cookie, &mask); err != nil {
			return nil, &errTestBridge{Op: "dump-flows", Detail: "unsupported match " + strconv.Quote(match)}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*ovs.Flow
	for k, f := range b.flows {
		if f.cookie&mask == cookie&mask {
			out = append(out, &ovs.Flow{
				Table: k.table, Priority: k.priority, Match: k.match,
				Actions: f.actions, Cookie: fmt.Sprintf("0x%x", f.cookie),
			})
		}
	}
	return out, nil
}

func (b *testBridge) DeleteFlowStrict(_ context.Context, _ string, flow *ovs.FlowMod) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.flows, testFlowKey{table: flow.Table, priority: flow.Priority, match: flow.Match})
	return nil
}

func (b *testBridge) DeleteFlowsByCookie(_ context.Context, _ string, cookie, cookieMask uint64) error {
	b.deleteFlows(func(_ testFlowKey, f testFlow) bool { return f.cookie&cookieMask == cookie&cookieMask })
	return nil
}

func (b *testBridge) deleteFlows(drop func(testFlowKey, testFlow) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, f := range b.flows {
		if drop(k, f) {
			delete(b.flows, k)
		}
	}
}

func (b *testBridge) GetOFPort(context.Context, string) (int32, error) { return 7, nil }

func (b *testBridge) GetInterface(_ context.Context, name string) (*ovs.Interface, error) {
	return &ovs.Interface{Name: name, OFPort: 7, MAC: "02:00:00:00:00:07"}, nil
}

func (b *testBridge) GetBridge(_ context.Context, name string) (*ovs.Bridge, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &ovs.Bridge{Name: name, FailMode: b.failMode, ExternalIDs: copyIDs(b.externalIDs)}, nil
}

func (b *testBridge) SetBridgeFailMode(_ context.Context, _ string, failMode string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failMode = failMode
	return nil
}

func (b *testBridge) SetBridgeExternalIDs(_ context.Context, _ string, ids map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range ids {
		b.externalIDs[k] = v
	}
	return nil
}

func (b *testBridge) GetBridgeExternalIDs(context.Context, string) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return copyIDs(b.externalIDs), nil
}

// AddGroup refuses an ID the bridge already holds, as OVS does with
// OFPGMFC_GROUP_EXISTS.
func (b *testBridge) AddGroup(_ context.Context, _ string, group *openflow.GroupMod) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.groups[group.GroupID]; ok {
		return &errTestBridge{Op: "add-group", Detail: "group " + strconv.FormatUint(uint64(group.GroupID), 10) + " exists"}
	}
	b.groups[group.GroupID] = openflow.GroupDesc{Type: group.Type, GroupID: group.GroupID, Buckets: group.Buckets}
	return nil
}

// ModifyGroup refuses an ID the bridge does not hold, as OVS does with
// OFPGMFC_UNKNOWN_GROUP.
func (b *testBridge) ModifyGroup(_ context.Context, _ string, group *openflow.GroupMod) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.groups[group.GroupID]; !ok {
		return &errTestBridge{Op: "mod-group", Detail: "group " + strconv.FormatUint(uint64(group.GroupID), 10) + " is unknown"}
	}
	b.groups[group.GroupID] = openflow.GroupDesc{Type: group.Type, GroupID: group.GroupID, Buckets: group.Buckets}
	return nil
}

func (b *testBridge) DeleteGroup(_ context.Context, _ string, groupID uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if groupID == openflow.OFPGAll {
		clear(b.groups)
		return nil
	}
	delete(b.groups, groupID)
	return nil
}

func (b *testBridge) GetGroupDesc(context.Context, string) ([]openflow.GroupDesc, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]openflow.GroupDesc, 0, len(b.groups))
	for _, g := range b.groups {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, c openflow.GroupDesc) int { return cmp.Compare(a.GroupID, c.GroupID) })
	return out, nil
}

// State is what the bridge holds with each flow generation left out: every
// flow by table, priority, match, actions and cookie owner, then every group
// ID, sorted. Two processes that programmed the same configuration leave the
// same State whatever generations they drew.
func (b *testBridge) State() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.flows)+len(b.groups))
	for k, f := range b.flows {
		out = append(out, fmt.Sprintf("flow owner=0x%x table=%d priority=%d %s actions=%s",
			f.cookie&ovs.OwnerCookieMask, k.table, k.priority, k.match, f.actions))
	}
	for id := range b.groups {
		out = append(out, "group "+strconv.FormatUint(uint64(id), 10))
	}
	slices.Sort(out)
	return out
}

// Generations returns, per cookie owner, the distinct generation-stamped
// cookies on the bridge. A reconciled bridge has exactly one per owner.
func (b *testBridge) Generations() map[uint64][]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[uint64][]uint64)
	for _, f := range b.flows {
		owner := f.cookie & ovs.OwnerCookieMask
		if owner == 0 || f.cookie == owner || slices.Contains(out[owner], f.cookie) {
			continue
		}
		out[owner] = append(out[owner], f.cookie)
	}
	return out
}

func TestTestBridge_ReinstallingAFlowReplacesItsActionsAndCookie(t *testing.T) {
	b := newTestBridge()
	require.NoError(t, (&testController{b: b}).InstallFlows("br", []zoneflows.FlowRule{{Table: 1, Priority: 10, Match: "ip", Actions: "drop", Cookie: "0xf1be000100000001"}}))
	require.NoError(t, (&testController{b: b}).InstallFlows("br", []zoneflows.FlowRule{{Table: 1, Priority: 10, Match: "ip", Actions: "normal", Cookie: "0xf1be000100000002"}}))

	assert.Equal(t, []string{"flow owner=0xf1be000100000000 table=1 priority=10 ip actions=normal"}, b.State())
	assert.Equal(t, map[uint64][]uint64{0xf1be000100000000: {0xf1be000100000002}}, b.Generations())

	flows, err := b.GetFlowStats(context.Background(), "br", "cookie=0xf1be000100000000/0xffffffff00000000")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, "0xf1be000100000002", flows[0].Cookie)
}

func TestTestBridge_RefusesWhatOVSRefuses(t *testing.T) {
	b := newTestBridge()
	ctx := context.Background()
	var refused *errTestBridge

	err := (&testController{b: b}).InstallFlows("br", []zoneflows.FlowRule{
		{Priority: 1, Match: "arp", Actions: "normal"},
		{Priority: 2, Match: "ip", Actions: "drop", Cookie: "not-a-cookie"},
	})
	require.ErrorAs(t, err, &refused)
	assert.Empty(t, b.State(), "a refused batch installs nothing")

	_, err = b.GetFlowStats(ctx, "br", "table=3")
	require.ErrorAs(t, err, &refused)

	require.NoError(t, b.AddGroup(ctx, "br", &openflow.GroupMod{GroupID: 5}))
	require.ErrorAs(t, b.AddGroup(ctx, "br", &openflow.GroupMod{GroupID: 5}), &refused)
	require.ErrorAs(t, b.ModifyGroup(ctx, "br", &openflow.GroupMod{GroupID: 6}), &refused)
	assert.Equal(t, []string{"group 5"}, b.State())
}

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

package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

func attUplink() UplinkConfig {
	return UplinkConfig{Name: "att", Interface: "eth6", Table: 101, GatewayV4: "99.12.246.38", GatewayV6: "2001:db8::1",
		Addresses: []string{"99.12.246.36/29", "2001:db8::36/64"}}
}

func uplinkMock() *mockNetlinkOps {
	mock := newMockNetlinkOps()
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	mock.links["eth7"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth7", Index: 7}}
	return mock
}

func TestUplinkConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*UplinkConfig)
		reason string
	}{
		"no name":       {func(c *UplinkConfig) { c.Name = "" }, "name is required"},
		"no interface":  {func(c *UplinkConfig) { c.Interface = "" }, "interface is required"},
		"table low":     {func(c *UplinkConfig) { c.Table = 5 }, "table must be 100-252"},
		"table high":    {func(c *UplinkConfig) { c.Table = 253 }, "table must be 100-252"},
		"no gateway":    {func(c *UplinkConfig) { c.GatewayV4, c.GatewayV6 = "", "" }, "gateway-v4 or gateway-v6"},
		"bad v4":        {func(c *UplinkConfig) { c.GatewayV4 = "2001:db8::1" }, "not an IPv4"},
		"bad v6":        {func(c *UplinkConfig) { c.GatewayV6 = "10.0.0.1" }, "not an IPv6"},
		"no addresses":  {func(c *UplinkConfig) { c.Addresses = nil }, "at least one address"},
		"bad address":   {func(c *UplinkConfig) { c.Addresses = []string{"nope"} }, "not valid CIDR"},
		"negative prio": {func(c *UplinkConfig) { c.Priority = -1 }, "priority"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := attUplink()
			c.mutate(&cfg)
			err := cfg.Validate()
			var invalid *ErrInvalidUplinkConfig
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Contains(t, err.Error(), c.reason)
		})
	}
	ok := attUplink()
	require.NoError(t, ok.Validate())
	assert.Equal(t, DefaultUplinkRulePriority, ok.effectivePriority())
}

func TestUplinkManager_EnsureUplink(t *testing.T) {
	mock := uplinkMock()
	u := newUplinkManagerWithOps(testLogger(), mock)
	cfg := attUplink()
	require.NoError(t, u.EnsureUplink(context.Background(), cfg))
	assert.True(t, u.Has("att"))
	assert.False(t, u.Has("comcast"))

	require.Len(t, mock.routes, 2, "a v4 and a v6 default in table 101")
	for _, r := range mock.routes {
		assert.Equal(t, 101, r.Table)
		assert.Equal(t, 6, r.LinkIndex)
	}
	require.Len(t, mock.rules, 2, "one source rule per address")
	assert.Equal(t, vnl.FAMILY_V4, mock.rules[0].Family)
	assert.Equal(t, "99.12.246.36/32", mock.rules[0].Src.String())
	assert.Equal(t, vnl.FAMILY_V6, mock.rules[1].Family)
	assert.Equal(t, DefaultUplinkRulePriority, mock.rules[0].Priority)

	// Idempotent
	require.NoError(t, u.EnsureUplink(context.Background(), cfg))
	assert.Len(t, mock.rules, 2)

	// Rules already present in the kernel (from a previous run) are not duplicated.
	u2 := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, u2.EnsureUplink(context.Background(), cfg))
	assert.Len(t, mock.rules, 2, "existing kernel rules are adopted, not duplicated")

	// Changed config is re-installed.
	changed := cfg
	changed.Table = 102
	require.NoError(t, u.EnsureUplink(context.Background(), changed))
	for _, r := range mock.routes {
		assert.Equal(t, 102, r.Table)
	}

	require.NoError(t, u.RemoveUplink(context.Background(), "att"))
	assert.False(t, u.Has("att"))
	assert.Empty(t, mock.routes)
	var nf *ErrUplinkNotFound
	require.True(t, errors.As(u.RemoveUplink(context.Background(), "att"), &nf))
}

func TestUplinkManager_Errors(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		u := newUplinkManagerWithOps(testLogger(), uplinkMock())
		var invalid *ErrInvalidUplinkConfig
		require.True(t, errors.As(u.EnsureUplink(context.Background(), UplinkConfig{}), &invalid))
	})
	t.Run("unknown interface", func(t *testing.T) {
		u := newUplinkManagerWithOps(testLogger(), newMockNetlinkOps())
		err := u.EnsureUplink(context.Background(), attUplink())
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(err, &op), "got %v", err)
		assert.Contains(t, err.Error(), "eth6")
	})
	t.Run("route install fails", func(t *testing.T) {
		mock := uplinkMock()
		mock.routeReplaceFn = func(*vnl.Route) error { return errors.New("ENETUNREACH") }
		u := newUplinkManagerWithOps(testLogger(), mock)
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(u.EnsureUplink(context.Background(), attUplink()), &op))
		assert.False(t, u.Has("att"))
	})
	t.Run("rule install fails rolls back", func(t *testing.T) {
		mock := uplinkMock()
		n := 0
		mock.ruleAddFn = func(r *vnl.Rule) error {
			n++
			if n == 2 {
				return errors.New("EINVAL")
			}
			mock.mu.Lock()
			mock.rules = append(mock.rules, *r)
			mock.mu.Unlock()
			return nil
		}
		u := newUplinkManagerWithOps(testLogger(), mock)
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(u.EnsureUplink(context.Background(), attUplink()), &op))
		assert.Empty(t, mock.rules, "the first rule is removed again")
		assert.Empty(t, mock.routes, "the default routes are rolled back with the rules (#583 review)")
		assert.False(t, u.Has("att"))
	})
	t.Run("rule list fails", func(t *testing.T) {
		mock := uplinkMock()
		mock.ruleListFn = func(int) ([]vnl.Rule, error) { return nil, errors.New("EPERM") }
		u := newUplinkManagerWithOps(testLogger(), mock)
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(u.EnsureUplink(context.Background(), attUplink()), &op))
	})
}

func TestUplinkManager_BindTunnel(t *testing.T) {
	mock := uplinkMock()
	u := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, u.EnsureUplink(context.Background(), attUplink()))
	before := len(mock.rules)

	require.NoError(t, u.BindTunnel(context.Background(), "att", "gre-mia", "99.12.246.36", "45.63.110.165"))
	require.Len(t, mock.rules, before+1)
	pin := mock.rules[before]
	assert.Equal(t, DefaultUplinkRulePriority-tunnelRuleOffset, pin.Priority)
	assert.Equal(t, 101, pin.Table)
	assert.Equal(t, "45.63.110.165/32", pin.Dst.String())

	// Binding twice is a no-op.
	require.NoError(t, u.BindTunnel(context.Background(), "att", "gre-mia", "99.12.246.36", "45.63.110.165"))
	assert.Len(t, mock.rules, before+1)

	require.NoError(t, u.UnbindTunnel(context.Background(), "att", "gre-mia"))
	assert.Len(t, mock.rules, before)
	require.NoError(t, u.UnbindTunnel(context.Background(), "att", "gre-mia"), "unbinding an unbound tunnel is a no-op")

	t.Run("unknown uplink", func(t *testing.T) {
		var nf *ErrUplinkNotFound
		require.True(t, errors.As(u.BindTunnel(context.Background(), "comcast", "t", "1.1.1.1", "2.2.2.2"), &nf))
		// Unbinding from an uplink that no longer exists is a no-op: the
		// binding left with the uplink (#583 review).
		require.NoError(t, u.UnbindTunnel(context.Background(), "comcast", "t"))
	})
	t.Run("bad endpoints", func(t *testing.T) {
		var invalid *ErrInvalidUplinkConfig
		require.True(t, errors.As(u.BindTunnel(context.Background(), "att", "t", "nope", "2.2.2.2"), &invalid))
	})
	t.Run("rule add fails", func(t *testing.T) {
		mock.ruleAddFn = func(*vnl.Rule) error { return errors.New("EINVAL") }
		defer func() { mock.ruleAddFn = nil }()
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(u.BindTunnel(context.Background(), "att", "t2", "99.12.246.36", "66.42.90.190"), &op))
	})
	t.Run("rule del fails", func(t *testing.T) {
		require.NoError(t, u.BindTunnel(context.Background(), "att", "t3", "99.12.246.36", "66.42.90.190"))
		mock.ruleDelFn = func(*vnl.Rule) error { return errors.New("EPERM") }
		defer func() { mock.ruleDelFn = nil }()
		var op *ErrUplinkOperationFailed
		require.True(t, errors.As(u.UnbindTunnel(context.Background(), "att", "t3"), &op))
	})
	t.Run("low priority is clamped", func(t *testing.T) {
		low := attUplink()
		low.Name, low.Table, low.Priority = "low", 150, 10
		require.NoError(t, u.EnsureUplink(context.Background(), low))
		require.NoError(t, u.BindTunnel(context.Background(), "low", "t4", "99.12.246.36", "66.42.90.190"))
		assert.Equal(t, 1, mock.rules[len(mock.rules)-1].Priority)
	})
}

func TestUplinkManager_Close(t *testing.T) {
	mock := uplinkMock()
	u := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, u.EnsureUplink(context.Background(), attUplink()))
	comcast := UplinkConfig{Name: "comcast", Interface: "eth7", Table: 102, GatewayV4: "96.65.171.22", Addresses: []string{"96.65.171.20/29"}}
	require.NoError(t, u.EnsureUplink(context.Background(), comcast))
	require.NoError(t, u.BindTunnel(context.Background(), "comcast", "gre-atl", "96.65.171.20", "66.42.90.190"))
	require.NoError(t, u.Close())
	assert.Empty(t, mock.routes)
	assert.Empty(t, mock.rules)

	mock.routeDelFn = func(*vnl.Route) error { return errors.New("ESRCH") }
	require.NoError(t, u.EnsureUplink(context.Background(), comcast))
	assert.Error(t, u.Close(), "a route that would not delete is reported")
}

func TestRuleAndConfigEquality(t *testing.T) {
	a, b := attUplink(), attUplink()
	assert.True(t, uplinkConfigEqual(a, b))
	b.Addresses = []string{"99.12.246.36/29"}
	assert.False(t, uplinkConfigEqual(a, b))
	b = attUplink()
	b.Addresses[0] = "99.12.246.37/29"
	assert.False(t, uplinkConfigEqual(a, b))
	assert.True(t, ipnetEqual(nil, nil))
	assert.False(t, ipnetEqual(nil, hostNet([]byte{1, 2, 3, 4})))
	assert.Equal(t, vnl.FAMILY_V6, family(hostNet(mustIP("2001:db8::1")).IP))
	assert.Equal(t, "2001:db8::1/128", hostNet(mustIP("2001:db8::1")).String())
}

func mustIP(s string) net.IP { return net.ParseIP(s) }

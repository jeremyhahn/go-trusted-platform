// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

// The observability fields on TunnelStatus (#594) come from the manager's own
// record of the tunnel: the transport it programmed, the uplink pin it holds,
// and when it last rotated key material.

func TestManager_Status_ReportsTransportUplinkAndBinding(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	up := newUplinkManagerWithOps(testLogger(), mock)
	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.6", Addresses: []string{"198.51.100.4/29"},
	}))
	m := newManagerWithOps(testLogger(), mock, WithUplinks(up))

	pinned := TunnelConfig{Name: "gre-pri", Type: TunnelTypeGRE, Uplink: "isp-a", Local: "198.51.100.4", Remote: "198.51.100.100", TunnelIP: "10.255.0.1/30"}
	require.NoError(t, m.EnsureTunnel(context.Background(), pinned))
	plain := TunnelConfig{Name: "gre-alt", Type: TunnelTypeGRE, Local: "198.51.100.4", Remote: "192.0.2.100", TunnelIP: "10.255.0.5/30"}
	require.NoError(t, m.EnsureTunnel(context.Background(), plain))

	st, err := m.Status(context.Background(), "gre-pri")
	require.NoError(t, err)
	assert.Equal(t, TransportGRE, st.Transport)
	assert.Equal(t, "isp-a", st.Uplink)
	assert.True(t, st.Bound, "a tunnel naming an uplink is pinned to it")
	assert.Zero(t, st.RekeyInterval, "gre carries no key material")
	assert.True(t, st.LastRekey.IsZero())

	st, err = m.Status(context.Background(), "gre-alt")
	require.NoError(t, err)
	assert.Empty(t, st.Uplink)
	assert.False(t, st.Bound, "a tunnel naming no uplink routes through the main table")
}

func TestManager_Status_ReportsRekey(t *testing.T) {
	mock := newMockNetlinkOps()
	cfg := ipsecConfig()
	keys := keysFor(cfg)
	m := newManagerWithOps(testLogger(), mock, WithKeyProvider(keys))
	rotated := time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)
	m.clock = func() time.Time { return rotated }
	require.NoError(t, m.EnsureTunnel(context.Background(), cfg))

	before, err := m.Status(context.Background(), cfg.Name)
	require.NoError(t, err)
	assert.Equal(t, TransportIPsec, before.Transport)
	assert.Equal(t, cfg.IPsec.EffectiveRekeyInterval(), before.RekeyInterval)
	assert.True(t, before.LastRekey.IsZero(), "no rotation has happened yet")

	require.NoError(t, m.Rekey(context.Background(), cfg.Name))
	after, err := m.Status(context.Background(), cfg.Name)
	require.NoError(t, err)
	assert.Equal(t, rotated, after.LastRekey)

	t.Run("a failed rekey does not advance the timestamp", func(t *testing.T) {
		m.clock = func() time.Time { return rotated.Add(time.Hour) }
		mock.xfrmStateUpdateFn = func(*vnl.XfrmState) error { return errors.New("ESRCH") }
		defer func() { mock.xfrmStateUpdateFn = nil }()
		var rk *ErrRekeyFailed
		require.True(t, errors.As(m.Rekey(context.Background(), cfg.Name), &rk))
		st, err := m.Status(context.Background(), cfg.Name)
		require.NoError(t, err)
		assert.Equal(t, rotated, st.LastRekey)
	})
}

func TestTunnelConfig_RekeyInterval(t *testing.T) {
	assert.Zero(t, (&TunnelConfig{}).rekeyInterval(), "gre has no key material")
	assert.Equal(t, DefaultRekeyInterval, (&TunnelConfig{Transport: TransportIPsec}).rekeyInterval())
	assert.Equal(t, time.Hour, (&TunnelConfig{Transport: TransportIPsec, IPsec: &IPsecConfig{RekeyInterval: time.Hour}}).rekeyInterval())
	assert.Equal(t, DefaultRekeyInterval, (&TunnelConfig{Transport: TransportWireGuard}).rekeyInterval())
}

func TestUplinkManager_List(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.links["eth6"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth6", Index: 6}}
	mock.links["eth7"] = &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "eth7", Index: 7}}
	up := newUplinkManagerWithOps(testLogger(), mock)

	assert.Empty(t, up.List(), "nothing programmed, nothing reported")

	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-b", Interface: "eth7", Table: 102, GatewayV4: "203.0.113.1", GatewayV6: "2001:db8:2::1",
		Addresses: []string{"203.0.113.10/29", "2001:db8:2::10/64"},
	}))
	require.NoError(t, up.EnsureUplink(context.Background(), UplinkConfig{
		Name: "isp-a", Interface: "eth6", Table: 101, GatewayV4: "198.51.100.6", Addresses: []string{"198.51.100.4/29"}, Priority: 900,
	}))
	require.NoError(t, up.BindTunnel(context.Background(), "isp-a", "gre-pri", "198.51.100.4", "198.51.100.100"))
	require.NoError(t, up.BindTunnel(context.Background(), "isp-a", "gre-alt", "198.51.100.4", "192.0.2.100"))

	list := up.List()
	require.Len(t, list, 2)
	assert.Equal(t, "isp-a", list[0].Name, "sorted by name")
	assert.Equal(t, "eth6", list[0].Interface)
	assert.Equal(t, 101, list[0].Table)
	assert.Equal(t, "198.51.100.6", list[0].GatewayV4)
	assert.Equal(t, 900, list[0].Priority)
	assert.Equal(t, 1, list[0].RuleCount)
	assert.Equal(t, []string{"gre-alt", "gre-pri"}, list[0].Tunnels, "bound tunnels sorted by name")

	assert.Equal(t, "isp-b", list[1].Name)
	assert.Equal(t, DefaultUplinkRulePriority, list[1].Priority)
	assert.Equal(t, 2, list[1].RuleCount, "one source rule per address")
	assert.Empty(t, list[1].Tunnels)

	t.Run("the report is a copy", func(t *testing.T) {
		list[0].Addresses[0] = "mutated"
		assert.Equal(t, "198.51.100.4/29", up.List()[0].Addresses[0])
	})

	t.Run("unbinding and removal are reflected", func(t *testing.T) {
		require.NoError(t, up.UnbindTunnel(context.Background(), "isp-a", "gre-pri"))
		assert.Equal(t, []string{"gre-alt"}, up.List()[0].Tunnels)
		require.NoError(t, up.RemoveUplink(context.Background(), "isp-b"))
		assert.Len(t, up.List(), 1)
	})
}
